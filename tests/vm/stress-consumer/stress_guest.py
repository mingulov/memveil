#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stress-pair guest flow: baseline then candidate in one boot.

Runs as root inside the virtme-ng guest. Re-verifies the exact
consumer and object bytes from the input manifest before
attaching, then runs two legs (baseline pair, candidate pair)
with fresh maps and owned fixture state per leg. Each leg runs
identity controls, a 200-op quiet phase, and a 2000-op paced
phase overlapped with one 128 MiB direct-read leg per vCPU
while bpftrace counts the attach points and block stats prove
the load flowed.

Dmesg logs are phase-local (cleared before every phase) and
bpftrace stays up through the final release, so no phase
inherits another's lines and the held mapping's release is
counted. Every export carries a sha256 sidecar.

Exit 0 means the choreography completed (the host judges every
leg from the exports and never trusts guest verdicts); exit 1
means guest-side infrastructure or a control failed and the
host must judge the run failed.

Every step writes flushed start/result markers to the shared
export as it runs and checkpoints completed phases there, so
a hang or a forced termination still leaves the last marker,
partial outputs, and every finished phase host-side. Every
guest operation carries an explicit timeout; nothing runs
unbounded.

Two modes: "full" runs baseline then candidate through
controls, the quiet phase, and the paced overlap phase;
"q3" runs the candidate then the baseline through controls
and the quiet phase only (no flood disk, no bpftrace).
"""

import concurrent.futures
import contextlib
import hashlib
import json
import os
import re
import select
import shutil
import signal
import subprocess
import sys
import time

LC_SITES = ("mv_map_result:swiotlb_tbl_map_single,"
            "mv_unmap:__swiotlb_tbl_unmap_single")
CP_SITES = ("mv_sync_device:__swiotlb_sync_single_for_device,"
            "mv_sync_cpu:__swiotlb_sync_single_for_cpu,"
            "mv_bounce:swiotlb_bounce,"
            "mv_bounce_exit:swiotlb_bounce")
LC_SIZES = (512, 1024, 2048, 4096)

# The only guest release this flow admits, enforced before
# any fixture setup and re-checked by the host judge.
EXPECT_RELEASE = "7.0.14-070014-generic"

# Every guest operation is bounded; nothing runs unbounded.
# insmod covers the 2000-op paced oracle (~20 s paced plus
# scheduling slack); dd covers one 128 MiB direct read.
TIMEOUT_MODPROBE = 120
TIMEOUT_INSMOD = 600
TIMEOUT_RMMOD = 120
TIMEOUT_DD = 300
TIMEOUT_DMESG = 30
TIMEOUT_CLEANUP = 120
# Post-kill reap, then the pipe drain. A stray holder may
# delay forensics by this long, never stall the verdict.
TIMEOUT_REAP = 5
TIMEOUT_DRAIN = 5
# SIGINT grace for the overlap tracer: the counts print
# on SIGINT, then SIGKILL plus the reap above applies.
TIMEOUT_TRACER = 30

# Readiness stdout without an ack past this is a flood, not
# a slow attach.
READY_BUFFER_CAP = 1048576


class StepTimeout(Exception):
    """One bounded guest operation outlived its timeout."""

    def __init__(self, step, timeout, out, err):
        super().__init__("%s timed out after %ds" % (step, timeout))
        self.step = step
        self.timeout = timeout
        self.out = out or ""
        self.err = err or ""


def fail(msg):
    """Abort the guest flow; the host judges this failed."""
    print("stress-guest: FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)


def _pipe_text(blob):
    """Decode captured pipe bytes, lossy-but-total.

    Undecodable bytes surface as U+FFFD; they never
    raise past a verdict the pipes still inform.
    """
    if blob is None:
        blob = b""
    return blob.decode("utf-8", "replace").replace(
        "\r\n", "\n").replace("\r", "\n")


def sh(args, timeout=TIMEOUT_DMESG, **kw):
    """Run one guest command, bounded, partials preserved.

    Bounded end to end: the command gets `timeout`, then
    SIGKILL plus a bounded reap, then a bounded output
    collection, so the whole call stays within timeout +
    reap + drain. Nothing here waits on the child
    unconditionally (contrast subprocess.run, which reaps
    with wait(None) after the kill and can hang past any
    timeout). A child still unreaped past the reap
    deadline, or pipes a stray holder keeps open, delays
    forensics but never the verdict: StepTimeout carries
    whatever partials were readable, with the collection
    state noted on the diagnostic stream.
    """
    proc = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, **kw)
    try:
        raw_out, raw_err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        pass
    else:
        return subprocess.CompletedProcess(
            args, proc.returncode, _pipe_text(raw_out),
            _pipe_text(raw_err))
    try:
        proc.kill()
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=TIMEOUT_REAP)
    except subprocess.TimeoutExpired:
        pass
    try:
        raw_out, raw_err = proc.communicate(
            timeout=TIMEOUT_DRAIN)
    except subprocess.TimeoutExpired as partial:
        out = _pipe_text(partial.output)
        err = _pipe_text(partial.stderr)
        cut = True
    else:
        out = _pipe_text(raw_out)
        err = _pipe_text(raw_err)
        cut = False
    if proc.poll() is None:
        err += ("\n[stress-guest: child unreaped after "
                "%ds; showing partial output]\n"
                % TIMEOUT_REAP)
    elif cut:
        err += ("\n[stress-guest: output truncated after "
                "%ds post-kill drain]\n" % TIMEOUT_DRAIN)
    raise StepTimeout(" ".join(args), timeout, out, err)


def drain_bounded(proc, seconds):
    """Drain a reaped-or-dying proc's stdout, bounded.

    Returns (text, truncated): everything readable before
    EOF or the deadline, plus whether the deadline cut the
    drain short (a stray holder kept the pipe open). EOF
    before the deadline means complete, whatever the size.
    The pipe is closed; later readers see .closed.
    """
    if proc.stdout is None:
        return "", False
    fd = proc.stdout.fileno()
    os.set_blocking(fd, False)
    chunks = []
    truncated = False
    try:
        end = time.monotonic() + seconds
        while True:
            remaining = end - time.monotonic()
            if remaining <= 0:
                truncated = True
                break
            ready, _, _ = select.select([proc.stdout], [], [],
                                        min(remaining, 0.5))
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            if chunk == b"":
                break
            chunks.append(chunk)
    finally:
        try:
            os.set_blocking(fd, True)
        except OSError:
            pass
        try:
            proc.stdout.close()
        except (OSError, ValueError):
            pass
    return b"".join(chunks).decode("utf-8", "replace"), truncated


def check_identity(identity, ko_digest, oracle, expect_release):
    """Refuse a guest whose identity or oracle bytes drifted.

    Mirrors the collector-SIGKILL identity gate: the booted
    release and the live BTF bytes must equal the pinned
    expectations, and the oracle module about to load must
    equal the manifest-bound digest. Pair and consumer
    bytes are enforced separately by input verification.
    Raises ValueError; the gate maps it to the guest abort.
    """
    if oracle.get("ko_sha256") is None \
            or oracle.get("btf_sha256") is None:
        raise ValueError("run manifest lacks oracle identity pins")
    if identity.get("release") != expect_release:
        raise ValueError("guest booted release %r, expected %r"
                         % (identity.get("release"), expect_release))
    if identity.get("btf_sha256") != oracle.get("btf_sha256"):
        raise ValueError("guest live BTF differs from the pinned bytes")
    if ko_digest != oracle.get("ko_sha256"):
        raise ValueError("guest oracle module drift")


def export_names_for_mode(mode):
    """Exact export inventory per mode; the host judges this."""
    # progress.log rides along: the marker choreography is
    # judged evidence, and the final export covers it with a
    # sidecar like every other name.
    names = ["identity.json", "input-verify.json", "progress.log"]
    legs = ("c9", "baseline") if mode == "q3" else ("baseline", "c9")
    for leg in legs:
        names += ["%s-controls.json" % leg, "%s-c0a-lc.txt" % leg,
                  "%s-c0b-lc.txt" % leg, "%s-c0-oracle.log" % leg,
                  "%s-p1-lc.txt" % leg, "%s-p1-cp.txt" % leg,
                  "%s-p1-oracle.log" % leg]
        if mode != "q3":
            names += ["%s-p2-lc.txt" % leg, "%s-p2-cp.txt" % leg,
                      "%s-p2-oracle.log" % leg,
                      "%s-bpftrace.txt" % leg,
                      "%s-bpftrace.stderr" % leg,
                      "%s-dd.json" % leg, "%s-window.json" % leg,
                      "%s-blockstats.json" % leg]
    return names


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def scsi_disks():
    disks = set()
    for name in os.listdir("/sys/block"):
        if name.startswith("sd"):
            disks.add(name)
    return disks


def block_stat(short):
    """Whole-disk counters proving DMA flowed (no addresses)."""
    with open(os.path.join("/sys/block", short, "stat")) as handle:
        vals = [int(x) for x in handle.read().split()]
    return {"read_ios": vals[0], "read_sectors": vals[2],
            "write_ios": vals[4], "write_sectors": vals[6]}


def dd_flood_leg(dev, size_mb):
    """One concurrent flood leg with overlap timestamps."""
    count = size_mb * 16
    start = mono_ns()
    rd = sh(["dd", "if=%s" % dev, "of=/dev/null", "bs=64k",
             "count=%d" % count, "iflag=direct"],
            timeout=TIMEOUT_DD)
    finish = mono_ns()
    if rd.returncode != 0:
        fail("dd flood leg failed: %s" % rd.stderr.strip()[-200:])
    copied = re.search(r"(\d+) bytes .* copied", rd.stderr)
    if copied is None or int(copied.group(1)) != count * 65536:
        fail("dd flood leg short: %s" % rd.stderr.strip()[-200:])
    return {"bytes": int(copied.group(1)),
            "seconds": (finish - start) / 1e9,
            "start_ns": start, "finish_ns": finish}


class Gate:
    """One boot's owned guest state for both legs."""

    def __init__(self, work, export, args):
        # Identity before anything else: no fixture setup,
        # no bytes executed, until the release is exact.
        if os.uname().release != EXPECT_RELEASE:
            fail("guest booted release %r, expected %r"
                 % (os.uname().release, EXPECT_RELEASE))
        if args.expect_release not in ("", EXPECT_RELEASE):
            fail("conflicting --expect-release %r" % args.expect_release)
        self.work = work
        self.export_dir = export
        self.consume = args.consumer
        self.ko = args.ko
        self.ko_sha = args.ko_sha
        self.mode = args.mode
        self.pairs = {
            "baseline": {"lc": args.baseline_lc, "cp": args.baseline_cp,
                         "lc_sha": args.baseline_lc_sha,
                         "cp_sha": args.baseline_cp_sha},
            "c9": {"lc": args.c9_lc, "cp": args.c9_cp,
                   "lc_sha": args.c9_lc_sha, "cp_sha": args.c9_cp_sha},
        }
        self.consumer_sha = args.consumer_sha
        # Entry marker before the manifest read: a stall
        # there must still leave one marker host-side. The
        # release gate above still fires first, so refusal
        # order is unchanged.
        os.makedirs(work, exist_ok=True)
        os.makedirs(export, exist_ok=True)
        self.marker("exec", "start", {"mode": self.mode})
        try:
            with open(args.manifest) as handle:
                self.manifest = json.load(handle)
        except (OSError, ValueError) as exc:
            fail("cannot read run manifest: %s" % exc)
        self.consumers = []
        self.transients = []
        self.oracle_loaded = False
        if os.geteuid() != 0:
            fail("guest flow requires root")
        if os.path.exists("/sys/module/memveil_dma_oracle"):
            fail("oracle module already exists; no ownership")
        if os.path.exists("/sys/module/scsi_debug"):
            fail("scsi_debug already exists; no fixture ownership")
        with open("/proc/cmdline") as handle:
            if "swiotlb=force" not in handle.read():
                fail("guest lacks swiotlb=force")
        self.marker("boot", "ok", {"release": EXPECT_RELEASE,
                                   "mode": self.mode})
        self.verify_inputs()
        self.write_json("identity.json", self.identity())
        try:
            check_identity(
                json.loads(open(os.path.join(
                    self.work, "identity.json")).read()),
                self.checked["ko"],
                self.manifest.get("oracle", {}), EXPECT_RELEASE)
        except ValueError as exc:
            fail(str(exc))
        self.checkpoint(["identity.json", "input-verify.json"])

    def verify_inputs(self):
        """Re-hash every byte this guest will execute or load."""
        checked = {}
        for label, path, want in [
                ("consumer", self.consume, self.consumer_sha),
                ("baseline-lc", self.pairs["baseline"]["lc"],
                 self.pairs["baseline"]["lc_sha"]),
                ("baseline-cp", self.pairs["baseline"]["cp"],
                 self.pairs["baseline"]["cp_sha"]),
                ("c9-lc", self.pairs["c9"]["lc"], self.pairs["c9"]["lc_sha"]),
                ("c9-cp", self.pairs["c9"]["cp"], self.pairs["c9"]["cp_sha"])]:
            if not os.path.isfile(path):
                fail("missing %s: %s" % (label, path))
            got = sha_file(path)
            if got != want:
                fail("%s digest mismatch: want %s... got %s..."
                     % (label, want[:16], got[:16]))
            checked[label] = got
        manifest = self.manifest
        pairs = manifest.get("pairs", {})
        for name, channel in [("baseline", "lc"), ("baseline", "cp"),
                              ("c9", "lc"), ("c9", "cp")]:
            entry = pairs.get(name, {}).get(channel, {})
            label = "%s-%s" % (name, "lc" if channel == "lc" else "cp")
            if entry.get("sha256") != checked[label]:
                fail("manifest drift for %s" % label)
        want_consumer = manifest.get("consumer", {}).get("binary_sha256")
        if want_consumer != checked["consumer"]:
            fail("manifest drift for consumer")
        if not os.path.isfile(self.ko):
            fail("missing oracle module: %s" % self.ko)
        checked["ko"] = sha_file(self.ko)
        if checked["ko"] != self.ko_sha:
            fail("oracle module digest mismatch: want %s... got %s..."
                 % (self.ko_sha[:16], checked["ko"][:16]))
        oracle = manifest.get("oracle", {})
        if checked["ko"] != oracle.get("ko_sha256"):
            fail("oracle module not the manifest-bound bytes")
        self.checked = checked
        self.write_json("input-verify.json", {
            "digests": checked,
            "manifest_schema": manifest.get("schema"),
            "runner_commit": manifest.get("runner_commit"),
        })
        self.marker("input-verify", "ok",
                    {"digests": sorted(checked.keys())})

    def identity(self):
        release = os.uname().release
        with open("/proc/cmdline") as handle:
            cmdline = handle.read().strip()
        with open("/sys/kernel/btf/vmlinux", "rb") as handle:
            btf = hashlib.sha256(handle.read()).hexdigest()
        return {"release": release, "cmdline": cmdline,
                "btf_sha256": btf, "digests": self.checked}

    def write_json(self, name, doc):
        dst = os.path.join(self.work, name)
        with open(dst, "w") as handle:
            handle.write(json.dumps(doc, indent=1, sort_keys=True) + "\n")
        return dst

    def export(self, names):
        """Copy work files to the export with sha256 sidecars."""
        for name in names:
            src = os.path.join(self.work, name)
            if not os.path.isfile(src):
                fail("missing export %s" % name)
            dst = os.path.join(self.export_dir, name)
            shutil.copyfile(src, dst)
            with open(dst + ".sha256", "w") as handle:
                handle.write("%s  %s\n" % (sha_file(dst), name))

    def marker(self, step, status, detail=None):
        """Append a flushed step marker, mirrored to the export.

        The mirror never raises: a failed export write is
        noted on stderr, and the end-of-run inventory still
        enforces what the host may judge.
        """
        record = {"ts_ns": mono_ns(), "step": step,
                  "status": status}
        if detail is not None:
            record["detail"] = detail
        line = json.dumps(record, sort_keys=True) + "\n"
        try:
            with open(os.path.join(self.work, "progress.log"),
                      "a") as handle:
                handle.write(line)
                handle.flush()
                os.fsync(handle.fileno())
        except OSError as exc:
            print("stress-guest: progress write failed: %s" % exc,
                  file=sys.stderr)
            return
        try:
            shutil.copyfile(os.path.join(self.work, "progress.log"),
                            os.path.join(self.export_dir,
                                         "progress.log"))
        except OSError as exc:
            print("stress-guest: progress mirror failed: %s" % exc,
                  file=sys.stderr)

    def checkpoint(self, names):
        """Export finished files now, not only at the end."""
        self.export(names)
        self.marker("checkpoint", "ok", {"files": list(names)})

    @contextlib.contextmanager
    def step(self, name):
        """Mark one step's start and result around its body."""
        self.marker(name, "start")
        try:
            yield
        except StepTimeout as exc:
            partial = "%s-timeout.txt" % re.sub(r"[^a-z0-9]+", "-",
                                                name)
            with open(os.path.join(self.work, partial), "w") as handle:
                handle.write("step: %s\ntimeout: %ds\n"
                             % (exc.step, exc.timeout))
                handle.write("--- stdout ---\n%s\n" % exc.out[-4000:])
                handle.write("--- stderr ---\n%s\n" % exc.err[-4000:])
            self.marker(name, "timeout",
                        {"after_s": exc.timeout, "partial": partial})
            try:
                self.export([partial])
            except SystemExit:
                pass
            fail("%s timed out after %ds" % (exc.step, exc.timeout))
        except SystemExit:
            self.marker(name, "fail")
            raise
        except BaseException as exc:
            self.marker(name, "error",
                        {"reason": str(exc)[:300]})
            raise
        else:
            self.marker(name, "ok")

    def abort(self, reason):
        """Reap owned processes and leave an abort record.

        Every wait here is bounded: the terminate grace
        and the post-kill reap share one 10 s budget, and
        each tail drain has its own deadline. Tails reach
        the shared export with sidecars and are listed in
        the abort record; a cut-short drain is marked
        truncated, never silently dropped. A dying proc
        still drains: the pipe is the evidence, and the
        drain is bounded whether or not EOF arrives.
        """
        for proc in list(self.consumers) + list(self.transients):
            if proc.poll() is None:
                proc.terminate()
        end = time.monotonic() + 10
        for proc in list(self.consumers) + list(self.transients):
            if proc.poll() is None:
                try:
                    proc.wait(timeout=max(0, end - time.monotonic()))
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=max(
                            0, end - time.monotonic()))
                    except subprocess.TimeoutExpired:
                        pass
        tails = []
        for index, proc in enumerate(self.consumers):
            if proc.stdout is None or proc.stdout.closed:
                continue
            # Reap a zombie opportunistically; never blocks.
            proc.poll()
            try:
                rest, truncated = drain_bounded(proc, TIMEOUT_DRAIN)
            except (OSError, ValueError):
                continue
            # The readiness prefix is preserved consumer
            # output too: a diagnostic consumed before a
            # readiness failure still exports its tail,
            # even when the post-kill drain reads empty.
            prefix = getattr(proc, "gate_prefix", "")
            if rest or truncated or prefix:
                if truncated:
                    rest += ("\n[stress-guest: tail truncated "
                             "after %ds]\n" % TIMEOUT_DRAIN)
                name = "abort-consumer-%d.txt" % index
                with open(os.path.join(self.work, name),
                          "w") as handle:
                    handle.write(getattr(proc, "gate_prefix", "")
                                 + rest)
                tails.append(name)
        if self.oracle_loaded:
            try:
                inner = sh(["rmmod", "memveil_dma_oracle"],
                           timeout=TIMEOUT_CLEANUP)
                self.marker("abort-rmmod", "ok" if inner.returncode == 0
                            else "fail",
                            {"exit": inner.returncode})
            except StepTimeout as exc:
                self.marker("abort-rmmod", "timeout",
                            {"out": exc.out[-500:],
                             "err": exc.err[-500:]})
            except OSError as exc:
                self.marker("abort-rmmod", "error",
                            {"reason": str(exc)[:200]})
            self.oracle_loaded = False
        # Recount at the end, after the opportunistic
        # reaps above: only a genuinely live proc reports
        # unreaped, never a kill that landed on an
        # exhausted budget and died a millisecond later.
        unreaped = sum(
            1 for proc in list(self.consumers) + list(self.transients)
            if proc.poll() is None)
        self.write_json("abort.json", {"reason": reason,
                                       "mode": self.mode,
                                       "tails": tails,
                                       "unreaped": unreaped})
        for name in ["abort.json", "progress.log"] + tails:
            try:
                self.export([name])
            except SystemExit:
                pass

    def start_consumer(self, obj, ring, sites, seconds, out,
                       expect_family, expect_sha):
        """Start one consumer; return the Popen handle."""
        if os.path.exists(out):
            fail("consumer out exists: %s" % out)
        proc = subprocess.Popen(
            [self.consume, "--expect-family", expect_family,
             "--expect-sha256", expect_sha, obj, ring, sites,
             str(seconds), out],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True)
        proc.gate_ring = ring
        self.consumers.append(proc)
        return proc

    def wait_ready(self, procs, timeout=30):
        """Consume acknowledgements emitted only after attach+arm.

        Reads are non-blocking under a hard deadline: select
        may signal a partial line, and a blocking readline
        would then wait past the deadline (or forever) for
        the rest. Only a complete newline-terminated line
        naming this consumer's own ring accepts; a
        newline-less prefix or another ring's ack never
        does, even once fully buffered.
        """
        for proc in procs:
            if getattr(proc, "gate_ring", None) is None:
                fail("consumer without an expected ring "
                     "cannot acknowledge")
        end = time.monotonic() + timeout
        buffers = {}
        for proc in procs:
            buffers[id(proc)] = b""
            os.set_blocking(proc.stdout.fileno(), False)
        try:
            pending = list(procs)
            while pending:
                if time.monotonic() >= end:
                    fail("consumer attachment acknowledgements "
                         "timed out")
                for proc in list(pending):
                    if proc.poll() is not None:
                        fail("consumer exited before readiness")
                    ready, _, _ = select.select([proc.stdout], [],
                                                [], 0.1)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(proc.stdout.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if chunk == b"":
                        fail("consumer closed stdout before readiness")
                    buf = buffers[id(proc)] + chunk
                    if len(buf) > READY_BUFFER_CAP:
                        fail("consumer flooded stdout without readiness")
                    buffers[id(proc)] = buf
                    want = ("ready ring=%s"
                            % proc.gate_ring).encode()
                    # Every element but the last is a complete
                    # newline-terminated line; the trailing
                    # fragment is not evidence yet.
                    if want not in buf.split(b"\n")[:-1]:
                        continue
                    proc.gate_ready = True
                    proc.gate_prefix = buf.decode("utf-8", "replace")
                    pending.remove(proc)
        finally:
            for proc in procs:
                # Save-then-timeout: a readiness failure
                # must not discard the bytes already
                # consumed (often the one diagnostic
                # explaining the failure); the abort tail
                # exports them. Acked consumers already
                # carry the same prefix, untouched.
                if not getattr(proc, "gate_prefix", ""):
                    buf = buffers.get(id(proc), b"")
                    if buf:
                        proc.gate_prefix = buf.decode(
                            "utf-8", "replace")
                try:
                    os.set_blocking(proc.stdout.fileno(), True)
                except OSError:
                    pass

    def wait_consumer(self, proc, tag, timeout=180):
        """Wait for one consumer; fail unless it exits 0.

        The child gets `timeout`, then SIGKILL plus a
        bounded reap; the pipe then drains under its own
        deadline, so a stray holder delays forensics but
        never the verdict. Drained output is preserved; a
        cut-short drain fails closed as truncated, even
        when the child itself already exited.
        """
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=TIMEOUT_REAP)
            except subprocess.TimeoutExpired:
                pass
        out, truncated = drain_bounded(proc, TIMEOUT_DRAIN)
        seen = getattr(proc, "gate_prefix", "") + (out or "")
        if proc.returncode is None:
            fail("%s: consumer unreaped after kill; partial: %s"
                 % (tag, seen[-500:]))
        if truncated:
            fail("%s: consumer output truncated after %ds; "
                 "stray pipe holder? partial: %s"
                 % (tag, TIMEOUT_DRAIN, seen[-500:]))
        if proc.returncode != 0:
            fail("%s: consumer exit %d: %s"
                 % (tag, proc.returncode, seen[-500:]))
        if not getattr(proc, "gate_ready", False):
            ring = getattr(proc, "gate_ring", None)
            if ring is not None:
                want = "ready ring=%s\n" % ring
            else:
                want = "ready ring="
            if want not in seen:
                fail("%s: consumer never ready" % tag)
        return out

    def stop_tracer(self, proc):
        """Stop the overlap tracer, failing closed if stuck.

        SIGINT first (the counts print on SIGINT), a
        bounded wait, then SIGKILL plus a bounded reap.
        A tracer unreaped on both waits is left owned
        for the abort backstop and fails here: no
        checkpoint may cover a phase whose tracer never
        reported. The tracer state lands in the progress
        markers, mirrored to the export like the rest.
        """
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=TIMEOUT_TRACER)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=TIMEOUT_REAP)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is not None:
            return
        self.marker("bpftrace", "unreaped",
                    {"sigint_wait_s": TIMEOUT_TRACER,
                     "reap_wait_s": TIMEOUT_REAP})
        fail("bpftrace unreaped after SIGINT and SIGKILL; "
             "phase-2 outputs withheld")

    def clear_dmesg(self):
        inner = sh(["dmesg", "-C"])
        if inner.returncode != 0:
            fail("dmesg -C failed: %s" % inner.stderr.strip())

    def oracle_log(self, name):
        """Snapshot phase-local mv-oracle: lines into work/<name>."""
        dst = os.path.join(self.work, name)
        inner = sh(["dmesg"])
        if inner.returncode != 0:
            fail("dmesg failed")
        with open(dst, "w") as handle:
            for line in inner.stdout.split("\n"):
                if "mv-oracle:" in line:
                    handle.write(line + "\n")
        return dst

    def insmod(self, params):
        start = mono_ns()
        inner = sh(["insmod", self.ko, "mv_oracle_arm=1"] + params,
                   timeout=TIMEOUT_INSMOD)
        finish = mono_ns()
        if inner.returncode != 0:
            fail("insmod failed: %s" % inner.stderr.strip())
        self.oracle_loaded = True
        return {"start_ns": start, "finish_ns": finish}

    def rmmod(self):
        inner = sh(["rmmod", "memveil_dma_oracle"],
                   timeout=TIMEOUT_RMMOD)
        if inner.returncode != 0:
            fail("rmmod failed: %s" % inner.stderr.strip())
        self.oracle_loaded = False


def parse_lc_file(path):
    """Minimal lc-line scan for the control assertions."""
    maps = []
    unmaps = []
    with open(path) as handle:
        for line in handle:
            if line.startswith("summary "):
                break
            fields = dict(token.split("=", 1) for token in
                          line.split()[1:])
            rec = {key: int(fields[key]) for key in
                   ("kind", "ok", "size", "gen")}
            if rec["kind"] == 1:
                maps.append(rec)
            elif rec["kind"] == 2:
                unmaps.append(rec)
    return maps, unmaps


def run_controls(gate, name, pair, family):
    """Identity controls before the quiet phase (Q3).

    Consumer A attaches, two scripted ops run (op 0 releases
    normally, op 1 stays held), A exits; consumer B attaches
    fresh and the held mapping releases under it. Asserts the
    post-attach known generation resolved (op 0 map+release
    share a nonzero gen under A) and the held-across-attach
    release kept gen 0 under B (B never saw the map, so any
    known gen there would be fabricated).
    """
    tag = "%s-controls" % name
    with gate.step(tag):
        gate.clear_dmesg()
        first = os.path.join(gate.work, "%s-c0a-lc.txt" % name)
        proc_a = gate.start_consumer(pair["lc"], "mv_lifecycle",
                                     LC_SITES, 8, first, family,
                                     pair["lc_sha"])
        gate.wait_ready([proc_a])
        gate.insmod(["mv_oracle_ops=2"])
        gate.wait_consumer(proc_a, tag + "-a", timeout=60)
        maps, unmaps = parse_lc_file(first)
        op0_maps = [m for m in maps
                    if m["size"] == LC_SIZES[0] and m["gen"] != 0]
        if not op0_maps:
            fail("%s: no post-attach known map for op 0" % tag)
        gen0 = op0_maps[0]["gen"]
        if not any(u["gen"] == gen0 for u in unmaps):
            fail("%s: op 0 release lost gen %d" % (tag, gen0))
        held = [m for m in maps if m["size"] == LC_SIZES[1]]
        held_gen = held[0]["gen"] if held else 0
        second = os.path.join(gate.work, "%s-c0b-lc.txt" % name)
        proc_b = gate.start_consumer(pair["lc"], "mv_lifecycle",
                                     LC_SITES, 20, second, family,
                                     pair["lc_sha"])
        gate.wait_ready([proc_b])
        gate.rmmod()
        gate.wait_consumer(proc_b, tag + "-b", timeout=60)
        _, unmaps_b = parse_lc_file(second)
        held_releases = [u for u in unmaps_b
                         if u["size"] == LC_SIZES[1]]
        if not any(u["gen"] == 0 for u in held_releases):
            fail("%s: held-across-attach release not gen 0" % tag)
        if held_gen != 0 and any(u["gen"] == held_gen for u in unmaps_b):
            fail("%s: held gen %d leaked across attach" % (tag, held_gen))
        gate.oracle_log("%s-c0-oracle.log" % name)
        gate.write_json("%s-controls.json" % name, {
            "op0_gen": gen0, "held_gen_first": held_gen,
            "held_releases": len(held_releases),
        })
    gate.checkpoint(["%s-controls.json" % name,
                     "%s-c0a-lc.txt" % name,
                     "%s-c0b-lc.txt" % name,
                     "%s-c0-oracle.log" % name])


def run_phase1(gate, name, pair, family):
    """200 scripted oracle ops alone (exact host expectations)."""
    with gate.step("%s-quiet" % name):
        gate.clear_dmesg()
        lc = os.path.join(gate.work, "%s-p1-lc.txt" % name)
        cp = os.path.join(gate.work, "%s-p1-cp.txt" % name)
        plc = gate.start_consumer(pair["lc"], "mv_lifecycle",
                                  LC_SITES, 120, lc, family,
                                  pair["lc_sha"])
        pcp = gate.start_consumer(pair["cp"], "mv_copies",
                                  CP_SITES, 120, cp, family,
                                  pair["cp_sha"])
        gate.wait_ready([plc, pcp])
        gate.insmod(["mv_oracle_ops=200"])
        time.sleep(5)
        gate.rmmod()
        gate.wait_consumer(plc, "%s-p1-lc" % name)
        gate.wait_consumer(pcp, "%s-p1-cp" % name)
        gate.oracle_log("%s-p1-oracle.log" % name)
    gate.checkpoint(["%s-p1-lc.txt" % name,
                     "%s-p1-cp.txt" % name,
                     "%s-p1-oracle.log" % name])


def run_phase2(gate, name, pair, family, disk, short):
    """2000 paced ops overlapped with the per-vCPU flood legs."""
    with gate.step("%s-overlap" % name):
        ncpu = os.cpu_count() or 0
        gate.clear_dmesg()
        lc = os.path.join(gate.work, "%s-p2-lc.txt" % name)
        cp = os.path.join(gate.work, "%s-p2-cp.txt" % name)
        plc = gate.start_consumer(pair["lc"], "mv_lifecycle",
                                  LC_SITES, 300, lc, family,
                                  pair["lc_sha"])
        pcp = gate.start_consumer(pair["cp"], "mv_copies",
                                  CP_SITES, 300, cp, family,
                                  pair["cp_sha"])
        gate.wait_ready([plc, pcp])
        bpf_out = open(os.path.join(gate.work, "%s-bpftrace.txt" % name),
                       "w")
        bpf_err = open(os.path.join(gate.work, "%s-bpftrace.stderr" % name),
                       "w")
        bprog = ("fentry:swiotlb_tbl_map_single "
                 "{ @maps = count(); } "
                 "fentry:__swiotlb_tbl_unmap_single "
                 "{ @unmaps = count(); } "
                 "fentry:swiotlb_bounce { @bounces = count(); }")
        bpf = subprocess.Popen(
            ["bpftrace", "-q", "-e", bprog],
            stdout=bpf_out, stderr=bpf_err, start_new_session=True)
        gate.transients.append(bpf)
        time.sleep(3)
        if bpf.poll() is not None:
            bpf_out.close()
            bpf_err.close()
            fail("bpftrace exited early; attach points unavailable?")
        stats0 = block_stat(short)
        # Legs first: insmod blocks for its paced ops, so the flood
        # is already in flight when oracle traffic starts.
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=ncpu) as pool:
            futs = {pool.submit(dd_flood_leg, disk, 128): i
                    for i in range(ncpu)}
            window = gate.insmod(["mv_oracle_ops=2000",
                                  "mv_oracle_delay_ms=10"])
            legs = {}
            # Bounded transitively: each worker runs exactly
            # one sh() (bounded by its own kill, reap, and
            # drain), so every future resolves; the bound
            # lives in sh, where the kill happens, because a
            # result() deadline could not stop the thread
            # the pool join still waits for.
            for fut in concurrent.futures.as_completed(futs):
                legs["cpu%d" % futs[fut]] = fut.result()
        stats1 = block_stat(short)
        # The tracer stays up through the final release: the held
        # mapping's unmap must be counted, not cut off.
        gate.rmmod()
        # Fail-closed: an unreaped tracer raises before
        # the checkpoint below may cover this phase.
        gate.stop_tracer(bpf)
        gate.transients.remove(bpf)
        bpf_out.close()
        bpf_err.close()
        if stats1["read_ios"] <= stats0["read_ios"]:
            fail("flood produced no block reads")
        gate.wait_consumer(plc, "%s-p2-lc" % name, timeout=300)
        gate.wait_consumer(pcp, "%s-p2-cp" % name, timeout=300)
        gate.oracle_log("%s-p2-oracle.log" % name)
        gate.write_json("%s-dd.json" % name, legs)
        gate.write_json("%s-window.json" % name, window)
        gate.write_json("%s-blockstats.json" % name,
                        {"before": stats0, "after": stats1})
    gate.checkpoint(["%s-p2-lc.txt" % name, "%s-p2-cp.txt" % name,
                     "%s-p2-oracle.log" % name,
                     "%s-bpftrace.txt" % name,
                     "%s-bpftrace.stderr" % name,
                     "%s-dd.json" % name, "%s-window.json" % name,
                     "%s-blockstats.json" % name])


def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("work")
    parser.add_argument("export")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--consumer", required=True)
    parser.add_argument("--consumer-sha", required=True)
    parser.add_argument("--ko", required=True)
    parser.add_argument("--ko-sha", required=True)
    parser.add_argument("--mode", default="full",
                        choices=("full", "q3"))
    parser.add_argument("--expect-release", default="")
    parser.add_argument("--baseline-lc", required=True)
    parser.add_argument("--baseline-cp", required=True)
    parser.add_argument("--baseline-lc-sha", required=True)
    parser.add_argument("--baseline-cp-sha", required=True)
    parser.add_argument("--c9-lc", required=True)
    parser.add_argument("--c9-cp", required=True)
    parser.add_argument("--c9-lc-sha", required=True)
    parser.add_argument("--c9-cp-sha", required=True)
    args = parser.parse_args(argv)
    gate = Gate(args.work, args.export, args)
    try:
        run_flow(gate)
    except SystemExit:
        gate.abort("guest exit")
        raise
    except BaseException as exc:
        gate.abort("guest error: %s" % str(exc)[:300])
        raise


def run_flow(gate):
    """One boot's legs for the requested mode."""
    ncpu = os.cpu_count() or 0
    if ncpu < 2:
        fail("stress gate needs 2+ vCPUs, have %d" % ncpu)
    if gate.mode == "q3":
        # Adapter gate: candidate first, then baseline;
        # controls plus the quiet phase only.
        run_controls(gate, "c9", gate.pairs["c9"], "aya")
        run_phase1(gate, "c9", gate.pairs["c9"], "aya")
        run_controls(gate, "baseline", gate.pairs["baseline"], "c")
        run_phase1(gate, "baseline", gate.pairs["baseline"], "c")
    else:
        if shutil.which("bpftrace") is None:
            fail("bpftrace not available")
        with gate.step("fixture-setup"):
            disk, short = fixture_disk(gate)
        try:
            # Baseline first, then the candidate; every leg loads
            # fresh objects (fresh maps), owns a phase-local dmesg,
            # and leaves the oracle unloaded behind it.
            run_controls(gate, "baseline", gate.pairs["baseline"], "c")
            run_phase1(gate, "baseline", gate.pairs["baseline"], "c")
            run_phase2(gate, "baseline", gate.pairs["baseline"], "c",
                       disk, short)
            run_controls(gate, "c9", gate.pairs["c9"], "aya")
            run_phase1(gate, "c9", gate.pairs["c9"], "aya")
            run_phase2(gate, "c9", gate.pairs["c9"], "aya",
                       disk, short)
        finally:
            with gate.step("fixture-cleanup"):
                inner = sh(["rmmod", "scsi_debug"],
                           timeout=TIMEOUT_CLEANUP)
                if inner.returncode != 0:
                    fail("scsi_debug cleanup failed: %s"
                         % inner.stderr.strip())
    gate.export(export_names_for_mode(gate.mode))
    print("stress-guest: legs exported (mode %s)" % gate.mode)


def fixture_disk(gate):
    """Load scsi_debug and identify the owned disk, bounded."""
    before_disks = scsi_disks()
    inner = sh(["modprobe", "scsi_debug", "dev_size_mb=256"],
               timeout=TIMEOUT_MODPROBE)
    if inner.returncode != 0:
        fail("scsi_debug failed: %s" % inner.stderr.strip())
    gate.marker("modprobe", "ok")
    disk = None
    for _ in range(30):
        extra = scsi_disks() - before_disks
        if extra:
            disk = "/dev/%s" % sorted(extra)[0]
            break
        time.sleep(0.5)
    if disk is None:
        fail("scsi_debug disk never appeared")
    short = disk.rsplit("/", 1)[1]
    with open(os.path.join("/sys/block", short, "device", "model")) as handle:
        if "scsi_debug" not in handle.read():
            fail("new stress disk is not owned scsi_debug")
    gate.marker("fixture-disk", "ok", {"disk": short})
    return disk, short


if __name__ == "__main__":
    main(sys.argv[1:])
