#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Scenario-battery guest flow: one case per boot.

Runs as root inside the virtme-ng guest. Re-verifies the
exact consumer, object, binary, profile, and oracle bytes
from the run manifest before attaching, then runs one
battery case: the consumer legs (matrix/copy/canonical/
saturation/stop/skipsync) drive the test-only Rust consumer
with digest-pinned C9 objects, while the record legs
(faults/record3) run the sealed C9 record directly with
the bound reference profile and no bridge.

Exit 0 means the choreography completed (the host judges
every case from the exports and never trusts guest
verdicts); exit 1 means guest-side infrastructure failed
and the host must judge the run failed. Every export
carries a sha256 sidecar. No DMA addresses ever cross:
consumer files hold decoded facts only.
"""

import hashlib
import json
import os
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

CASES = ("matrix", "copy", "canonical-c", "canonical-e",
         "saturation", "stop", "faults", "record3",
         "skipsync")
FAULT_CAPTURES = ("f3a", "f3b", "f5a", "f5b", "f5c", "f6")


def export_names_for_case(case):
    """Exact export inventory per case; the host judges this."""
    names = ["identity.json", "input-verify.json"]
    if case == "matrix":
        for delay_ms in (1000, 100, 10):
            tag = "s%d" % delay_ms
            names += ["%s-lc.txt" % tag, "%s-cp.txt" % tag,
                      "%s-oracle.log" % tag]
    elif case == "copy":
        names += ["a-lc.txt", "a-cp.txt", "a-oracle.log",
                  "b-lc.txt", "b-cp.txt", "b-oracle.log"]
    elif case == "canonical-c":
        names += ["c-lc.txt", "c-cp.txt", "c-oracle.log"]
    elif case == "canonical-e":
        names += ["e-lc.txt", "e-cp.txt", "e-oracle.log"]
    elif case == "saturation":
        names += ["flood-lc.txt", "flood-cp.txt",
                  "flood-oracle.log"]
    elif case == "stop":
        for cycle in range(5):
            tag = "c%d" % cycle
            names += ["%s-lc.txt" % tag, "%s-oracle.log" % tag]
            if cycle != 1:
                names.insert(len(names) - 1,
                             "%s-cp.txt" % tag)
        names.append("ledger.json")
    elif case == "faults":
        names += ["profile.json", "faults.json",
                  "f4-oracle.log", "f3b-report.json",
                  "f3a-cut-oracle.log", "f3b-cut-oracle.log"]
        for tag in FAULT_CAPTURES:
            names += ["%s-record.json" % tag,
                      "%s-session.json" % tag,
                      "%s-events.ndjson" % tag,
                      "%s-oracle.log" % tag]
    elif case == "record3":
        names += ["profile.json", "record.json",
                  "cap-session.json", "cap-events.ndjson",
                  "r3-oracle.log"]
    elif case == "skipsync":
        names += ["w-lc.txt", "w-cp.txt", "w-oracle.log"]
    else:
        raise ValueError("bad case %r" % (case,))
    return names


def fail(msg):
    """Abort the guest flow; the host judges this failed."""
    print("battery-guest: FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)


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


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


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


def find_pcnet():
    """Return the pcnet32-driven interface name, else fail."""
    for iface in sorted(os.listdir("/sys/class/net")):
        drv = os.path.join("/sys/class/net", iface, "device",
                           "driver")
        try:
            if os.readlink(drv).endswith("pcnet32"):
                return iface
        except OSError:
            continue
    fail("no pcnet32 NIC found")


def configure_net(iface):
    r = sh(["sysctl", "-w",
            "net.ipv6.conf.%s.disable_ipv6=1" % iface])
    if r.returncode != 0:
        fail("ipv6 disable failed: %s" % r.stderr.strip())
    r = sh(["ip", "link", "set", iface, "up"])
    if r.returncode != 0:
        fail("ip link up failed: %s" % r.stderr.strip())
    r = sh(["ip", "addr", "add", "10.0.3.15/24", "dev",
            iface])
    if r.returncode != 0 and "exists" not in r.stderr:
        fail("ip addr failed: %s" % r.stderr.strip())
    r = sh(["ping", "-c", "1", "-W", "3", "10.0.3.2"])
    if r.returncode != 0:
        fail("gateway ping failed: %s" % r.stdout.strip())


class Gate:
    """One case run: paths, checks, consumer control."""

    def __init__(self, work, export, args):
        # Identity before anything else: no fixture setup,
        # no bytes executed, until the release is exact.
        if os.uname().release != EXPECT_RELEASE:
            fail("guest booted release %r, expected %r"
                 % (os.uname().release, EXPECT_RELEASE))
        if args.expect_release not in ("", EXPECT_RELEASE):
            fail("conflicting --expect-release %r"
                 % args.expect_release)
        if args.case not in CASES:
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
        self.attempt_obj = args.attempt
        self.attempt_sha = args.attempt_sha
        self.binary = args.binary
        self.binary_sha = args.binary_sha
        self.profile = args.profile
        self.profile_sha = args.profile_sha
        self.profiles_dir = args.profiles_dir
        self.test_lc = args.test_lc
        self.test_cp = args.test_cp
        self.test_lc_sha = args.test_lc_sha
        self.test_cp_sha = args.test_cp_sha
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

        Only the inputs this case runs are required: the
        record legs never execute the consumer, the
        saturation case never loads the sealed pair, and
        only the record legs load the binary, the attempt
        object, and the profile. An unbound saturation
        pair therefore cannot block the other cases.
        """
        checked = {}
        if self.case in ("faults", "record3"):
            wanted = [("lc", self.lc_obj, self.lc_sha),
                      ("cp", self.cp_obj, self.cp_sha),
                      ("attempt", self.attempt_obj,
                       self.attempt_sha),
                      ("binary", self.binary, self.binary_sha),
                      ("profile", self.profile,
                       self.profile_sha)]
        elif self.case == "saturation":
            wanted = [("consumer", self.consume,
                       self.consumer_sha),
                      ("test-lc", self.test_lc,
                       self.test_lc_sha),
                      ("test-cp", self.test_cp,
                       self.test_cp_sha)]
        else:
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
        if self.case == "saturation":
            test_objects = manifest.get("test_objects", {})
            if not test_objects.get("bound"):
                fail("saturation test objects unbound in "
                     "the run manifest")
            for channel, label in (("lc", "test-lc"),
                                   ("cp", "test-cp")):
                entry = test_objects.get(channel, {})
                if entry.get("sha256") != checked[label]:
                    fail("manifest drift for %s" % label)
        else:
            for channel in ("lc", "cp"):
                if objects.get(channel, {}).get("sha256") \
                        != checked[channel]:
                    fail("manifest drift for %s" % channel)
        if "consumer" in checked and manifest.get(
                "consumer", {}).get("binary_sha256") \
                != checked["consumer"]:
            fail("manifest drift for consumer")
        if self.case in ("faults", "record3"):
            if objects.get("attempt", {}).get("sha256") \
                    != checked["attempt"]:
                fail("manifest drift for attempt")
            if manifest.get("binary", {}).get("sha256") \
                    != checked["binary"]:
                fail("manifest drift for binary")
            if manifest.get("profile", {}).get("sha256") \
                    != checked["profile"]:
                fail("manifest drift for profile")
            profiles_manifest = os.path.join(
                self.profiles_dir, "manifest.txt")
            try:
                listed = open(profiles_manifest).read().split()
            except OSError:
                fail("profiles dir lacks a manifest")
            if os.path.basename(self.profile) not in listed:
                fail("bound profile not listed by its "
                     "profiles dir")
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

    def bpf_inventory(self):
        """Checked JSON object counts; failed queries cannot mean empty."""
        inventory = {}
        for kind, key in (("prog", "progs"),
                          ("map", "maps")):
            r = sh(["bpftool", "-j", kind, "show"])
            if r.returncode != 0:
                raise ValueError("bpftool inventory failed: "
                                 + kind)
            objects = json.loads(r.stdout)
            if not isinstance(objects, list) or any(
                    not isinstance(o, dict) or
                    type(o.get("id")) is not int
                    for o in objects):
                raise ValueError("malformed bpftool inventory: "
                                 + kind)
            inventory[key] = len(objects)
        return inventory

    def settled_inventory(self, before, timeout=30):
        """Poll BPF counts back to baseline; return (now, waited_s).

        The kernel frees map IDs deferred, so one immediate
        sample after process exit races reclamation and
        reports phantom residue. Poll until the counts equal
        the baseline or the timeout expires; the caller
        records both so a real leak still fails with
        evidence.
        """
        start = time.monotonic()
        while True:
            now = self.bpf_inventory()
            waited = round(time.monotonic() - start, 3)
            if now == before or waited >= timeout:
                return now, waited
            time.sleep(0.5)


def run_window(gate, tag, params, window):
    """One scripted window under the sealed pair; tag-named files."""
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "%s-lc.txt" % tag)
    cp = os.path.join(gate.work, "%s-cp.txt" % tag)
    plc = gate.start_consumer(gate.lc_obj, "mv_lifecycle",
                              LC_SITES, window, lc,
                              gate.lc_sha)
    pcp = gate.start_consumer(gate.cp_obj, "mv_copies",
                              CP_SITES, window, cp,
                              gate.cp_sha)
    gate.wait_ready([plc, pcp])
    gate.insmod(params)
    time.sleep(5)
    gate.rmmod()
    gate.wait_consumer(plc, "%s-%s-lc" % (gate.case, tag))
    gate.wait_consumer(pcp, "%s-%s-cp" % (gate.case, tag))
    gate.oracle_log("%s-oracle.log" % tag)


def run_matrix(gate):
    """Stepped rates: 1, 10, 100 maps/s over scripted traffic."""
    gate.write_json("identity.json", gate.identity())
    for delay_ms, window in ((1000, 20), (100, 16), (10, 16)):
        run_window(gate, "s%d" % delay_ms,
                   ["mv_oracle_delay_ms=%d" % delay_ms],
                   window)
    gate.export(export_names_for_case("matrix"))
    print("battery-guest: matrix exported")


def run_copy(gate):
    """Copy semantics: standard window plus fail-probe window."""
    gate.write_json("identity.json", gate.identity())
    run_window(gate, "a", [], 22)
    run_window(gate, "b", ["mv_oracle_fail_op=2"], 22)
    gate.export(export_names_for_case("copy"))
    print("battery-guest: copy exported")


def run_canonical(gate, tag, scenario):
    """One fixed canonical window (oracle 0.4.0 scenario)."""
    gate.write_json("identity.json", gate.identity())
    run_window(gate, tag,
               ["mv_oracle_witness=1",
                "mv_oracle_delay_ms=100",
                "mv_oracle_scenario=%d" % scenario],
               25)
    gate.export(export_names_for_case(gate.case))
    print("battery-guest: %s exported" % gate.case)


def run_saturation(gate):
    """Small-ring flood: exact loss accounting under STOP.

    Both consumers stop before the 300-op flood, both rings
    actually lose records, and each ring reconciles after
    resume and drain. Flood accounting credits only the
    separately hashed 4 KiB test objects this case binds.
    """
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "flood-lc.txt")
    cp = os.path.join(gate.work, "flood-cp.txt")
    plc = gate.start_consumer(gate.test_lc, "mv_lifecycle",
                              LC_SITES, 40, lc,
                              gate.test_lc_sha)
    pcp = gate.start_consumer(gate.test_cp, "mv_copies",
                              CP_SITES, 40, cp,
                              gate.test_cp_sha)
    gate.wait_ready([plc, pcp])
    os.kill(plc.pid, signal.SIGSTOP)
    os.kill(pcp.pid, signal.SIGSTOP)
    gate.insmod(["mv_oracle_ops=300"])
    time.sleep(3)
    os.kill(plc.pid, signal.SIGCONT)
    os.kill(pcp.pid, signal.SIGCONT)
    time.sleep(2)
    gate.rmmod()
    gate.wait_consumer(plc, "saturation-lc")
    gate.wait_consumer(pcp, "saturation-cp")
    gate.oracle_log("flood-oracle.log")
    gate.export(export_names_for_case("saturation"))
    print("battery-guest: saturation exported")


def run_stop(gate):
    """Stop races: signals, victim, quiet window, short window."""
    gate.write_json("identity.json", gate.identity())
    ledger = []
    for cycle in range(5):
        tag = "c%d" % cycle
        gate.clear_dmesg()
        lc = os.path.join(gate.work, "%s-lc.txt" % tag)
        cp = os.path.join(gate.work, "%s-cp.txt" % tag)
        row = {"cycle": cycle}
        if cycle == 2:
            # Quiet window: traffic first, consumers after.
            gate.insmod([])
            time.sleep(2)
            gate.rmmod()
            gate.clear_dmesg()
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 10,
                lc, gate.lc_sha)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 10, cp,
                gate.cp_sha)
            gate.wait_ready([plc, pcp])
            gate.wait_consumer(plc, "stop-%s-lc" % tag)
            gate.wait_consumer(pcp, "stop-%s-cp" % tag)
            row["mode"] = "quiet"
            row["lc_exit"] = 0
            row["cp_exit"] = 0
        elif cycle == 4:
            # Short window over slow traffic: detach mid-run.
            # The 6 s window covers the 3 s script with margin
            # but ends long before the exit release.
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 6,
                lc, gate.lc_sha)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 6, cp,
                gate.cp_sha)
            gate.wait_ready([plc, pcp])
            gate.insmod(["mv_oracle_delay_ms=1000"])
            gate.wait_consumer(plc, "stop-%s-lc" % tag,
                               timeout=60)
            gate.wait_consumer(pcp, "stop-%s-cp" % tag,
                               timeout=60)
            time.sleep(6)
            gate.rmmod()
            row["mode"] = "short"
            row["lc_exit"] = 0
            row["cp_exit"] = 0
        else:
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 20,
                lc, gate.lc_sha)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 20, cp,
                gate.cp_sha)
            gate.wait_ready([plc, pcp])
            gate.insmod([])
            time.sleep(1)
            if cycle in (0, 3):
                targets = (plc, pcp) if cycle == 0 else (plc,)
                for proc in targets:
                    os.kill(proc.pid, signal.SIGSTOP)
                time.sleep(2)
                for proc in targets:
                    os.kill(proc.pid, signal.SIGCONT)
                row["mode"] = "stop-both" if cycle == 0 \
                    else "stop-lc"
            else:
                alive = pcp.poll() is None
                if not alive:
                    fail("victim exited before SIGTERM")
                row["victim_alive"] = alive
                row["victim_signal"] = signal.SIGTERM
                row["victim_signal_ns"] = mono_ns()
                pcp.send_signal(signal.SIGTERM)
                try:
                    victim_rc = pcp.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    pcp.kill()
                    fail("stop victim ignored SIGTERM")
                row["mode"] = "term-cp"
                row["victim_rc"] = victim_rc
                row["victim_file"] = os.path.exists(cp)
                if row["victim_alive"] is not True or \
                        victim_rc != -signal.SIGTERM:
                    fail("victim was not alive or did not "
                         "terminate by SIGTERM")
                # The consumer writes its file once at the
                # end of its window; SIGTERM lands while it
                # polls, so a dead victim leaves no file at
                # all, summary or otherwise.
                if os.path.exists(cp):
                    fail("stop victim left a file")
            time.sleep(4)
            gate.rmmod()
            gate.wait_consumer(plc, "stop-%s-lc" % tag)
            if cycle != 1:
                gate.wait_consumer(pcp, "stop-%s-cp" % tag)
            row["lc_exit"] = 0
            row["cp_exit"] = 0 if cycle != 1 \
                else row["victim_rc"]
        gate.oracle_log("%s-oracle.log" % tag)
        ledger.append(row)
    gate.write_json("ledger.json", ledger)
    gate.export(export_names_for_case("stop"))
    print("battery-guest: stop exported")


def run_skipsync(gate):
    """Directed skip-sync window with bounce readback."""
    gate.write_json("identity.json", gate.identity())
    run_window(gate, "w",
               ["mv_oracle_witness=1",
                "mv_oracle_delay_ms=100"],
               25)
    gate.export(export_names_for_case("skipsync"))
    print("battery-guest: skipsync exported")


def record_argv(gate, duration, caps, cap):
    """Record argv for the sealed C9 binary.

    The statically linked loader runs without --bridge;
    explicit object paths win verbatim over the embedded
    bytes, and the bound reference profile admits the
    channels through live-interface verification.
    """
    return [gate.binary, "record",
            "--duration", str(duration),
            "--output", cap,
            "--object", gate.attempt_obj,
            "--lc-object", gate.lc_obj,
            "--cp-object", gate.cp_obj,
            "--profile", gate.profile,
            "--profiles-dir", gate.profiles_dir,
            "--capability", ",".join(caps)]


def await_record_ready(rec, work, errname="record.stderr"):
    """Wait for the record readiness line; fail with stderr tail."""
    def tail():
        try:
            with open(os.path.join(work, errname),
                      "rb") as handle:
                return handle.read()[-500:].decode(
                    "utf-8", "replace")
        except OSError:
            return ""
    ready = None
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        r, _, _ = select.select([rec.stdout], [], [], 1.0)
        if r:
            line = rec.stdout.readline()
            if line and "ready session=" in line:
                ready = line.strip()
                break
        if rec.poll() is not None:
            break
    if ready is None:
        try:
            rec.kill()
        except OSError:
            pass
        fail("record never reached readiness: " + tail())
    return ready, tail


def export_profile(gate):
    """Export the bound profile bytes for the host receipt."""
    shutil.copyfile(gate.profile,
                    os.path.join(gate.work, "profile.json"))


def run_record3(gate):
    """Three-channel product record over nested oracle traffic.

    Runs the sealed C9 record with attempt, lifecycle, and
    copy channels against scenario 1 (nested 4096+1024)
    under the bound reference profile, then exports the
    capture plus the oracle log for host-side comparison.
    """
    gate.write_json("identity.json", gate.identity())
    export_profile(gate)
    gate.clear_dmesg()
    cap = os.path.join(gate.work, "cap")
    rec = subprocess.Popen(
        record_argv(gate, 30,
                    ("attempt-trace", "mapping-lifecycle",
                     "copy-actual"),
                    cap),
        stdout=subprocess.PIPE,
        stderr=open(os.path.join(gate.work, "record.stderr"),
                    "wb"),
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    ready, tail = await_record_ready(rec, gate.work)
    gate.insmod(["mv_oracle_witness=1",
                 "mv_oracle_delay_ms=100",
                 "mv_oracle_scenario=1"])
    time.sleep(8)
    gate.rmmod()
    try:
        rc = rec.wait(timeout=120)
    except subprocess.TimeoutExpired:
        rec.kill()
        rec.wait()
        fail("record did not exit: " + tail())
    gate.write_json("record.json", {"exit": rc, "ready": ready})
    gate.oracle_log("r3-oracle.log")
    for name in ("session.json", "events.ndjson"):
        src = os.path.join(cap, name)
        if not os.path.isfile(src):
            fail("capture lacks %s" % name)
        shutil.copyfile(
            src, os.path.join(gate.work, "cap-" + name))
    gate.export(export_names_for_case("record3"))
    print("battery-guest: record3 exported record_exit=%d "
          "stderr_tail=%r" % (rc, tail()))


def run_faults(gate):
    """Multi-channel faults: rollback, teardown, busy, race.

    Seven scenarios in one boot: truncated lc/cp objects
    must refuse with exit 3 and zero BPF residue; SIGTERM
    mid-capture (1ch and 3ch) must stop bounded with a
    signal end reason, with a cut oracle snapshot proving
    the flood was mid-flight; a full output filesystem
    must fail honestly without a masquerading session;
    paced and burst 300-op floods compare 1ch against 3ch
    capture; background flood during attach must not leak
    pre-window records. The faults.json ledger carries
    every scenario's exit, stderr tail, BPF inventory pair,
    and the seconds waited for kernel-deferred map IDs to
    settle.
    """
    gate.write_json("identity.json", gate.identity())
    export_profile(gate)
    ledger = []

    def trunc(src, tag):
        with open(src, "rb") as handle:
            head = handle.read(4096)
        dst = os.path.join(gate.work, "bad-%s.o" % tag)
        with open(dst, "wb") as handle:
            handle.write(head)
        return dst

    def run_refused(tag, lc_obj, cp_obj):
        before = gate.bpf_inventory()
        cap = os.path.join(gate.work, "%s-cap" % tag)
        argv = record_argv(
            gate, 10,
            ("attempt-trace", "mapping-lifecycle",
             "copy-actual"),
            cap)
        argv[argv.index("--lc-object") + 1] = lc_obj
        argv[argv.index("--cp-object") + 1] = cp_obj
        try:
            r = sh(argv, timeout=60)
        except SystemExit:
            fail("%s: refused run hung" % tag)
        after, settle = gate.settled_inventory(before)
        ledger.append({
            "scenario": tag, "exit": r.returncode,
            "stderr": r.stderr.strip()[-512:],
            "progs_before": before["progs"],
            "progs_after": after["progs"],
            "maps_before": before["maps"],
            "maps_after": after["maps"],
            "settle_s": settle,
            "cap": os.path.isfile(
                os.path.join(cap, "session.json")),
        })

    run_refused("f1", trunc(gate.lc_obj, "lc"), gate.cp_obj)
    run_refused("f2", gate.lc_obj, trunc(gate.cp_obj, "cp"))

    def start_record(tag, duration, caps, output=None):
        cap = output or os.path.join(gate.work,
                                     "%s-cap" % tag)
        rec = subprocess.Popen(
            record_argv(gate, duration, caps, cap),
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(
                gate.work, "%s-record.stderr" % tag), "wb"),
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        ready, _ = await_record_ready(
            rec, gate.work, "%s-record.stderr" % tag)
        return rec, cap, ready

    def finish_capture(tag, rec, cap, ready):
        try:
            rc = rec.wait(timeout=240)
        except subprocess.TimeoutExpired:
            rec.kill()
            rec.wait()
            fail("%s: record did not exit" % tag)
        gate.write_json("%s-record.json" % tag,
                        {"exit": rc, "ready": ready})
        for name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
            if not os.path.isfile(src):
                fail("%s: capture lacks %s" % (tag, name))
            shutil.copyfile(
                src, os.path.join(gate.work,
                                  "%s-%s" % (tag, name)))

    def record_ledger(tag, rec, before, extra=None):
        after, settle = gate.settled_inventory(before)
        row = {
            "scenario": tag, "exit": rec.returncode,
            "stderr": "",
            "progs_before": before["progs"],
            "progs_after": after["progs"],
            "maps_before": before["maps"],
            "maps_after": after["maps"],
            "settle_s": settle,
            "cap": True,
        }
        if extra:
            row.update(extra)
        ledger.append(row)

    for tag, caps in (("f3a", ("attempt-trace",)),
                      ("f3b", ("attempt-trace",
                               "mapping-lifecycle",
                               "copy-actual"))):
        before = gate.bpf_inventory()
        gate.clear_dmesg()
        rec, cap, ready = start_record(tag, 90, caps)
        window = [mono_ns()]
        # insmod runs the 300-op flood synchronously (~30s),
        # so background it: SIGTERM must land mid-flood, and
        # the cut snapshot below must precede flood completion.
        flood = subprocess.Popen(
            ["insmod", gate.ko, "mv_oracle_arm=1",
             "mv_oracle_ops=300", "mv_oracle_delay_ms=100"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, start_new_session=True)
        gate.consumers.append(flood)
        time.sleep(10)
        window.append(mono_ns())
        rec.terminate()
        try:
            rc = rec.wait(timeout=60)
        except subprocess.TimeoutExpired:
            rec.kill()
            rec.wait()
            fail("%s: SIGTERM did not stop record" % tag)
        gate.oracle_log("%s-cut-oracle.log" % tag)
        try:
            _, err = flood.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            flood.kill()
            flood.communicate()
            fail("%s: oracle flood hung" % tag)
        gate.consumers.remove(flood)
        if flood.returncode != 0:
            fail("%s: insmod failed: %s"
                 % (tag, err.strip()[-300:]))
        gate.oracle_loaded = True
        gate.rmmod()
        gate.oracle_log("%s-oracle.log" % tag)
        gate.write_json("%s-record.json" % tag,
                        {"exit": rc, "ready": ready})
        for name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
            if not os.path.isfile(src):
                fail("%s: capture lacks %s" % (tag, name))
            shutil.copyfile(
                src, os.path.join(gate.work,
                                  "%s-%s" % (tag, name)))
        record_ledger(tag, rec, before, {"window": window})

    rep = sh([gate.binary, "report", "--format", "json",
              os.path.join(gate.work, "f3b-cap")])
    with open(os.path.join(gate.work, "f3b-report.json"),
              "w") as handle:
        handle.write(rep.stdout)
    try:
        with open(os.path.join(gate.work,
                               "f3b-report.json")) as handle:
            json.load(handle)
    except ValueError:
        fail("signal-cut report emitted invalid JSON")
    ledger.append({
        "scenario": "f3b-report", "exit": rep.returncode,
        "stderr": rep.stderr.strip()[-512:],
        "progs_before": 0, "progs_after": 0,
        "maps_before": 0, "maps_after": 0,
        "settle_s": 0,
        "cap": True,
    })

    mnt = os.path.join(gate.work, "full")
    os.makedirs(mnt)
    r = sh(["mount", "-t", "tmpfs", "-o", "size=64k",
            "memveil-full", mnt])
    if r.returncode != 0:
        fail("tmpfs mount failed: %s" % r.stderr.strip())
    try:
        with open(os.path.join(mnt, "filler"), "wb") as handle:
            handle.write(b"x" * 57344)
        before = gate.bpf_inventory()
        gate.clear_dmesg()
        cap = os.path.join(mnt, "cap")
        rec = subprocess.Popen(
            record_argv(gate, 30,
                        ("attempt-trace",
                         "mapping-lifecycle", "copy-actual"),
                        cap),
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(gate.work,
                                     "f4-record.stderr"),
                        "wb"),
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        ready, _ = await_record_ready(
            rec, gate.work, "f4-record.stderr")
        gate.insmod(["mv_oracle_witness=1",
                     "mv_oracle_delay_ms=100",
                     "mv_oracle_scenario=1"])
        time.sleep(8)
        gate.rmmod()
        try:
            rc = rec.wait(timeout=120)
        except subprocess.TimeoutExpired:
            rec.kill()
            rec.wait()
            fail("f4: record did not exit")
        gate.oracle_log("f4-oracle.log")
        with open(os.path.join(gate.work, "f4-record.stderr"),
                  "rb") as handle:
            err = handle.read()[-512:].decode("utf-8",
                                              "replace")
        after, settle = gate.settled_inventory(before)
        ledger.append({
            "scenario": "f4", "exit": rc, "stderr": err,
            "progs_before": before["progs"],
            "progs_after": after["progs"],
            "maps_before": before["maps"],
            "maps_after": after["maps"],
            "settle_s": settle,
            "cap": os.path.isfile(
                os.path.join(cap, "session.json")),
            "events_kept": os.path.isfile(
                os.path.join(cap, "events.ndjson")),
            "ready": ready,
        })
    finally:
        r = sh(["umount", mnt])
        if r.returncode != 0:
            fail("tmpfs umount failed: %s" % r.stderr.strip())

    floods = (("f5a", ("attempt-trace",),
               ["mv_oracle_ops=300",
                "mv_oracle_delay_ms=100"],
               45),
              ("f5b", ("attempt-trace", "mapping-lifecycle",
                       "copy-actual"),
               ["mv_oracle_ops=300",
                "mv_oracle_delay_ms=100"],
               45),
              ("f5c", ("attempt-trace", "mapping-lifecycle",
                       "copy-actual"),
               ["mv_oracle_ops=300"], 10))
    for tag, caps, params, wait_s in floods:
        before = gate.bpf_inventory()
        gate.clear_dmesg()
        rec, cap, ready = start_record(tag, 120, caps)
        window = [mono_ns()]
        gate.insmod(params)
        time.sleep(wait_s)
        gate.rmmod()
        window.append(mono_ns())
        gate.oracle_log("%s-oracle.log" % tag)
        finish_capture(tag, rec, cap, ready)
        record_ledger(tag, rec, before, {"window": window})

    iface = find_pcnet()
    configure_net(iface)
    before = gate.bpf_inventory()
    gate.clear_dmesg()
    flood = subprocess.Popen(
        ["ping", "-f", "-c", "5000", "-q", "10.0.3.2"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        rec, cap, ready = start_record(
            "f6", 60,
            ("attempt-trace", "mapping-lifecycle",
             "copy-actual"))
    finally:
        flood.terminate()
        try:
            flood.wait(timeout=30)
        except subprocess.TimeoutExpired:
            flood.kill()
            flood.wait()
    time.sleep(2)
    window = [mono_ns()]
    gate.insmod(["mv_oracle_witness=1",
                 "mv_oracle_delay_ms=100",
                 "mv_oracle_scenario=1"])
    time.sleep(8)
    gate.rmmod()
    window.append(mono_ns())
    gate.oracle_log("f6-oracle.log")
    finish_capture("f6", rec, cap, ready)
    record_ledger("f6", rec, before, {"window": window})

    gate.write_json("faults.json", ledger)
    gate.export(export_names_for_case("faults"))
    print("battery-guest: faults exported")


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
    parser.add_argument("--lc", required=True)
    parser.add_argument("--lc-sha", required=True)
    parser.add_argument("--cp", required=True)
    parser.add_argument("--cp-sha", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--attempt-sha", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--binary-sha", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--profile-sha", required=True)
    parser.add_argument("--profiles-dir", required=True)
    parser.add_argument("--test-lc", default="")
    parser.add_argument("--test-cp", default="")
    parser.add_argument("--test-lc-sha", default="")
    parser.add_argument("--test-cp-sha", default="")
    parser.add_argument("--case", required=True)
    parser.add_argument("--expect-release", default="")
    args = parser.parse_args(argv)
    gate = Gate(args.work, args.export, args)
    try:
        if gate.case == "matrix":
            run_matrix(gate)
        elif gate.case == "copy":
            run_copy(gate)
        elif gate.case == "canonical-c":
            run_canonical(gate, "c", 3)
        elif gate.case == "canonical-e":
            run_canonical(gate, "e", 4)
        elif gate.case == "saturation":
            run_saturation(gate)
        elif gate.case == "stop":
            run_stop(gate)
        elif gate.case == "faults":
            run_faults(gate)
        elif gate.case == "record3":
            run_record3(gate)
        elif gate.case == "skipsync":
            run_skipsync(gate)
        else:
            fail("bad case %r" % (gate.case,))
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
