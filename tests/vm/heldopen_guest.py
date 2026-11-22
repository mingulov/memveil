#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Held-open guest flow: the L6 live leg on the battery shape.

Runs as root inside the virtme-ng guest. The host stages
the full inputs doc in the shared export dir and passes
only its filename via --inputs; this flow hashes those
exact bytes first and refuses unless the run manifest
binds the same digest. It then re-verifies the exact
consumer, object, and oracle-fixture bytes from the
run manifest before attaching, then runs the held-open
choreography: one scripted window with the last mapping
held open across the hold boundary and released exactly
once on unload.

Exit 0 means the choreography completed (the host judges
from the exports and never trusts guest verdicts); exit 1
means guest-side infrastructure failed and the host must
judge the run failed. Every export carries a sha256
sidecar. No DMA addresses ever cross: consumer files hold
decoded facts only.
"""

import hashlib
import json
import os
import select
import shutil
import subprocess
import sys
import time

LC_SITES = ("mv_map_result:swiotlb_tbl_map_single,"
            "mv_unmap:__swiotlb_tbl_unmap_single")
CP_SITES = ("mv_sync_device:__swiotlb_sync_single_for_device,"
            "mv_sync_cpu:__swiotlb_sync_single_for_cpu,"
            "mv_bounce:swiotlb_bounce,"
            "mv_bounce_exit:swiotlb_bounce")

# The only guest release this flow admits, enforced before
# any fixture setup and re-checked by the host judge.
EXPECT_RELEASE = "7.0.14-070014-generic"

# Every guest operation is bounded; nothing runs unbounded.
TIMEOUT_INSMOD = 600
TIMEOUT_RMMOD = 120
TIMEOUT_DMESG = 30

# Readiness stdout without an ack past this is a flood, not
# a slow attach.
READY_BUFFER_CAP = 1048576

CASE = "heldopen"

# Guest-inputs doc schema, owned by this flow: the host
# stages the full inputs doc in the shared export dir and
# the guest command line carries only the pointer filename.
# The guest hashes the exact bytes first and refuses
# unless the run manifest binds the same digest.
GUEST_INPUTS_SCHEMA = "memveil-heldopen-guest-inputs/1"


def export_names_for_case(case):
    """Exact export inventory; the host judges this."""
    if case != CASE:
        raise ValueError("bad case %r" % (case,))
    return ["identity.json", "input-verify.json",
            "cmp-lc.txt", "cmp-cp.txt", "cmp-oracle.log"]


def fail(msg):
    """Abort the guest flow; the host judges this failed."""
    print("heldopen-guest: FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)


def parse_guest_inputs(export_dir, name):
    """Read the staged inputs doc; return (fields, observed_sha).

    Runs before anything else in the guest: the pointer
    must be a bare filename resolved against the export
    dir, the exact bytes are hashed first, and the run
    manifest named inside must bind the same filename and
    digest. Raises ValueError; the caller maps it to the
    guest abort.
    """
    if not name or not isinstance(name, str) \
            or os.path.basename(name) != name \
            or name in (".", "..") \
            or os.path.isabs(name):
        raise ValueError(
            "inputs pointer must be a bare filename, "
            "got %r" % (name,))
    path = os.path.join(export_dir, name)
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except OSError as exc:
        raise ValueError("cannot read guest inputs %r: %s"
                         % (name, exc))
    observed = hashlib.sha256(blob).hexdigest()
    try:
        doc = json.loads(blob.decode("utf-8"))
    except ValueError as exc:
        raise ValueError("guest inputs %r are not JSON: %s"
                         % (name, exc))
    if not isinstance(doc, dict):
        raise ValueError("guest inputs %r are not a mapping"
                         % (name,))
    if doc.get("schema") != GUEST_INPUTS_SCHEMA:
        raise ValueError("guest inputs schema %r"
                         % (doc.get("schema"),))
    case = doc.get("case")
    if case != CASE:
        raise ValueError("bad case %r" % (case,))
    manifest_path = doc.get("manifest")
    if not manifest_path or not isinstance(
            manifest_path, str):
        raise ValueError("guest inputs lack a run manifest")
    try:
        with open(manifest_path) as handle:
            manifest = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read run manifest: %s"
                         % exc)
    staged = manifest.get("guest_inputs", {})
    entry = staged.get(case, {}) if isinstance(
        staged, dict) else {}
    if not isinstance(entry, dict) \
            or not entry.get("sha256"):
        raise ValueError("run manifest lacks a "
                         "guest-inputs binding for %s"
                         % case)
    if entry.get("file") != name:
        raise ValueError("guest inputs file %r is not the "
                         "bound doc for %s" % (name, case))
    if entry.get("sha256") != observed:
        raise ValueError(
            "guest inputs bytes differ from the manifest "
            "binding for %s: observed %s... bound %s..."
            % (case, observed[:16],
               str(entry.get("sha256"))[:16]))
    fields = {"case": case, "manifest": manifest_path}
    for key in ("consumer", "ko", "lc", "cp"):
        section = doc.get(key, {})
        if not isinstance(section, dict) \
                or not isinstance(
                    section.get("path"), str) \
                or not section.get("path") \
                or not isinstance(
                    section.get("sha256"), str) \
                or not section.get("sha256"):
            raise ValueError("guest inputs lack %s "
                             "path/digest" % key)
        fields[key] = section["path"]
        fields[key + "_sha"] = section["sha256"]
    if not isinstance(doc.get("expect_release"), str):
        raise ValueError(
            "guest inputs lack an expect-release")
    fields["expect_release"] = doc["expect_release"]
    return fields, observed


def sh(args, timeout=TIMEOUT_DMESG, **kw):
    """Run one guest command, bounded."""
    try:
        return subprocess.run(args, capture_output=True,
                              text=True, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        fail("guest command timed out after %ds: %s"
             % (timeout, args[0]))


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check_identity(identity, ko_digest, oracle):
    """Refuse a guest whose identity or oracle bytes drifted.

    The booted release and the live BTF bytes must equal
    the pinned expectations, and the oracle module about
    to load must equal the manifest-bound digest. Raises
    ValueError; the gate maps it to the guest abort.
    """
    if oracle.get("ko_sha256") is None \
            or oracle.get("btf_sha256") is None:
        raise ValueError("run manifest lacks oracle identity pins")
    if identity.get("release") != EXPECT_RELEASE:
        raise ValueError("guest booted release %r, expected %r"
                         % (identity.get("release"),
                            EXPECT_RELEASE))
    if identity.get("btf_sha256") != oracle.get("btf_sha256"):
        raise ValueError("guest live BTF differs from the pinned bytes")
    if ko_digest != oracle.get("ko_sha256"):
        raise ValueError("guest oracle module drift")


class Gate:
    """One held-open run: paths, checks, consumer control."""

    def __init__(self, work, export, args):
        # Identity before anything else: no fixture setup,
        # no bytes executed, until the release is exact.
        if os.uname().release != EXPECT_RELEASE:
            fail("guest booted release %r, expected %r"
                 % (os.uname().release, EXPECT_RELEASE))
        if args.expect_release not in ("", EXPECT_RELEASE):
            fail("conflicting --expect-release %r"
                 % args.expect_release)
        if args.case != CASE:
            fail("bad case %r" % (args.case,))
        self.case = args.case
        self.work = work
        self.export_dir = export
        self.consume = args.consumer
        self.consumer_sha = args.consumer_sha
        self.ko = args.ko
        self.ko_sha = args.ko_sha
        self.lc_obj = args.lc
        self.lc_sha = args.lc_sha
        self.cp_obj = args.cp
        self.cp_sha = args.cp_sha
        self.guest_inputs_file = args.guest_inputs_file
        self.guest_inputs_sha = args.guest_inputs_sha
        try:
            with open(args.manifest) as handle:
                self.manifest = json.load(handle)
        except (OSError, ValueError) as exc:
            fail("cannot read run manifest: %s" % exc)
        self.consumers = []
        self.oracle_loaded = False
        if os.geteuid() != 0:
            fail("guest flow requires root")
        os.makedirs(work, exist_ok=True)
        os.makedirs(export, exist_ok=True)
        if os.path.exists("/sys/module/memveil_dma_oracle"):
            fail("oracle module already exists; no ownership")
        with open("/proc/cmdline") as handle:
            if "swiotlb=force" not in handle.read():
                fail("guest lacks swiotlb=force")
        self.verify_inputs()
        self.write_json("identity.json", self.identity())
        try:
            with open(os.path.join(self.work,
                                   "identity.json")) as handle:
                identity = json.load(handle)
            check_identity(identity, self.checked["ko"],
                           self.manifest.get("oracle", {}))
        except ValueError as exc:
            fail(str(exc))

    def verify_inputs(self):
        """Re-hash every byte this guest will execute or load.

        The consumer plus the sealed lifecycle/copy pair
        and the oracle fixture: a digest mismatch or a
        manifest drift refuses before any attach.
        """
        checked = {}
        wanted = [("consumer", self.consume,
                   self.consumer_sha),
                  ("lc", self.lc_obj, self.lc_sha),
                  ("cp", self.cp_obj, self.cp_sha)]
        for label, path, want in wanted:
            if not path or not os.path.isfile(path):
                fail("missing %s: %s" % (label, path))
            got = sha_file(path)
            if got != want:
                fail("%s digest mismatch: want %s... got %s..."
                     % (label, want[:16], got[:16]))
            checked[label] = got
        manifest = self.manifest
        objects = manifest.get("objects", {})
        for channel in ("lc", "cp"):
            if objects.get(channel, {}).get("sha256") \
                    != checked[channel]:
                fail("manifest drift for %s" % channel)
        if manifest.get("consumer", {}).get("binary_sha256") \
                != checked["consumer"]:
            fail("manifest drift for consumer")
        if not os.path.isfile(self.ko):
            fail("missing oracle module: %s" % self.ko)
        checked["ko"] = sha_file(self.ko)
        if checked["ko"] != self.ko_sha:
            fail("oracle module digest mismatch: want %s... "
                 "got %s..."
                 % (self.ko_sha[:16], checked["ko"][:16]))
        oracle = manifest.get("oracle", {})
        if checked["ko"] != oracle.get("ko_sha256"):
            fail("oracle module not the manifest-bound bytes")
        self.checked = checked
        self.write_json("input-verify.json", {
            "case": self.case,
            "digests": checked,
            "guest_inputs_file": self.guest_inputs_file,
            "guest_inputs_sha256": self.guest_inputs_sha,
            "manifest_schema": manifest.get("schema"),
            "runner_commit": manifest.get("runner_commit"),
        })

    def identity(self):
        release = os.uname().release
        with open("/proc/cmdline") as handle:
            cmdline = handle.read().strip()
        with open("/sys/kernel/btf/vmlinux", "rb") as handle:
            btf = hashlib.sha256(handle.read()).hexdigest()
        return {"release": release, "cmdline": cmdline,
                "btf_sha256": btf, "digests": self.checked}

    def start_consumer(self, obj, ring, sites, seconds, out,
                       expect_sha):
        """Start one consumer; return the Popen handle."""
        if os.path.exists(out):
            fail("consumer out exists: %s" % out)
        proc = subprocess.Popen(
            [self.consume, "--expect-family", "aya",
             "--expect-sha256", expect_sha, obj, ring,
             sites, str(seconds), out],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True)
        self.consumers.append(proc)
        return proc

    def wait_ready(self, procs, timeout=30):
        """Consume acknowledgements emitted only after attach+arm.

        Reads are non-blocking under a hard deadline: select
        may signal a partial line, and a blocking readline
        would then wait past the deadline (or forever) for
        the rest. Only a full "ready ring=" line accepts.
        """
        end = time.monotonic() + timeout
        buffers = {}
        for proc in procs:
            buffers[id(proc)] = b""
            os.set_blocking(proc.stdout.fileno(), False)
        try:
            pending = list(procs)
            while pending:
                if time.monotonic() >= end:
                    fail("consumer attachment "
                         "acknowledgements timed out")
                for proc in list(pending):
                    if proc.poll() is not None:
                        fail("consumer exited before readiness")
                    ready, _, _ = select.select(
                        [proc.stdout], [], [], 0.1)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(proc.stdout.fileno(),
                                        65536)
                    except BlockingIOError:
                        continue
                    if chunk == b"":
                        fail("consumer closed stdout before "
                             "readiness")
                    buf = buffers[id(proc)] + chunk
                    if len(buf) > READY_BUFFER_CAP:
                        fail("consumer flooded stdout without "
                             "readiness")
                    buffers[id(proc)] = buf
                    for line in buf.split(b"\n"):
                        if line.startswith(b"ready ring="):
                            break
                    else:
                        continue
                    proc.gate_ready = True
                    proc.gate_prefix = buf.decode(
                        "utf-8", "replace")
                    pending.remove(proc)
        finally:
            for proc in procs:
                try:
                    os.set_blocking(proc.stdout.fileno(),
                                    True)
                except OSError:
                    pass

    def wait_consumer(self, proc, tag, timeout=180):
        """Wait for one consumer; fail unless it exits 0."""
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            fail("%s: consumer did not exit" % tag)
        seen = getattr(proc, "gate_prefix", "") + (out or "")
        if proc.returncode != 0:
            fail("%s: consumer exit %d: %s"
                 % (tag, proc.returncode, seen[-500:]))
        if not getattr(proc, "gate_ready", False) \
                and "ready ring=" not in seen:
            fail("%s: consumer never ready" % tag)
        return out

    def clear_dmesg(self):
        r = sh(["dmesg", "-C"])
        if r.returncode != 0:
            fail("dmesg -C failed: %s" % r.stderr.strip())

    def oracle_log(self, name):
        """Snapshot mv-oracle: lines into work/<name>."""
        dst = os.path.join(self.work, name)
        r = sh(["dmesg"])
        if r.returncode != 0:
            fail("dmesg failed")
        with open(dst, "w") as handle:
            for line in r.stdout.split("\n"):
                if "mv-oracle:" in line:
                    handle.write(line + "\n")
        return dst

    def insmod(self, params):
        r = sh(["insmod", self.ko, "mv_oracle_arm=1"] + params,
               timeout=TIMEOUT_INSMOD)
        if r.returncode != 0:
            fail("insmod failed: %s" % r.stderr.strip())
        self.oracle_loaded = True
        return r

    def rmmod(self):
        r = sh(["rmmod", "memveil_dma_oracle"],
               timeout=TIMEOUT_RMMOD)
        if r.returncode != 0:
            fail("rmmod failed: %s" % r.stderr.strip())
        self.oracle_loaded = False
        return r

    def export(self, names):
        """Copy work files to the export with sha256 sidecars."""
        for name in names:
            src = os.path.join(self.work, name)
            if not os.path.isfile(src):
                fail("missing export %s" % name)
            dst = os.path.join(self.export_dir, name)
            shutil.copyfile(src, dst)
            with open(dst + ".sha256", "w") as handle:
                handle.write("%s  %s\n" % (sha_file(dst),
                                           name))

    def write_json(self, name, doc):
        dst = os.path.join(self.work, name)
        with open(dst, "w") as handle:
            handle.write(json.dumps(doc, indent=1,
                                    sort_keys=True) + "\n")
        return dst


def run_heldopen(gate):
    """One held-open window under the sealed pair.

    Step-identical to the retired oracle comparison
    window (tests/vm/guest_lifecycle.py run_oracle): two
    25 s consumers, attach acknowledgements, insmod with
    a 100 ms op delay, a 5 s hold with the last mapping
    open across the boundary, unload releasing it exactly
    once, then the oracle-log snapshot and exports. The
    consumer runs with its real CLI (digest-pinned, no
    bridge) and the oracle bytes are the fixture.
    """
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "cmp-lc.txt")
    cp = os.path.join(gate.work, "cmp-cp.txt")
    plc = gate.start_consumer(gate.lc_obj, "mv_lifecycle",
                              LC_SITES, 25, lc,
                              gate.lc_sha)
    pcp = gate.start_consumer(gate.cp_obj, "mv_copies",
                              CP_SITES, 25, cp,
                              gate.cp_sha)
    gate.wait_ready([plc, pcp])
    gate.insmod(["mv_oracle_delay_ms=100"])
    time.sleep(5)
    gate.rmmod()
    gate.wait_consumer(plc, "heldopen-cmp-lc")
    gate.wait_consumer(pcp, "heldopen-cmp-cp")
    gate.oracle_log("cmp-oracle.log")
    gate.export(export_names_for_case("heldopen"))
    print("heldopen-guest: heldopen exported")


def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("work")
    parser.add_argument("export")
    parser.add_argument("--inputs", required=True,
                        help="staged inputs doc filename "
                             "(a bare name resolved "
                             "against the export dir)")
    args = parser.parse_args(argv)
    try:
        fields, observed = parse_guest_inputs(
            args.export, args.inputs)
    except ValueError as exc:
        fail(str(exc))
    fields["guest_inputs_file"] = args.inputs
    fields["guest_inputs_sha"] = observed
    gate = Gate(args.work, args.export,
                argparse.Namespace(**fields))
    try:
        run_heldopen(gate)
    finally:
        for proc in gate.consumers:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        if gate.oracle_loaded:
            sh(["rmmod", "memveil_dma_oracle"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
