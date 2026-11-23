#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lifecycle VM gate guest flow: traffic, capture, export.

Runs as root inside the virtme-ng guest (one boot per gate
subcommand). Subcommands: matrix | copy | realio | stop |
saturation | cleanup | perf | oracle. Every refusal aborts
FAIL (exit 1), never skip: armed gates fail loudly.

Exports carry .sha256 sidecars; the exact inventory is
checked host-side. No DMA addresses ever cross: consumer
files hold decoded facts only.
"""
import errno
import hashlib
import json
import os
import re
import shutil
import signal
import select
import uuid
import subprocess
import sys
import time

LC_SITES = ("mv_map_result:swiotlb_tbl_map_single,"
            "mv_unmap:__swiotlb_tbl_unmap_single")
CP_SITES = ("mv_sync_device:__swiotlb_sync_single_for_device,"
            "mv_sync_cpu:__swiotlb_sync_single_for_cpu,"
            "mv_bounce:swiotlb_bounce,"
            "mv_bounce_exit:swiotlb_bounce")

# Pre-readiness finalization reserve the record writer
# fallocates before signaling readiness, mirrored from
# the product's src/capture/writer.rs
# FINALIZE_RESERVE_BYTES (EventWriter::prepare refuses
# pre-readiness with ENOSPC when the output filesystem
# cannot grant it). The f4 staging derives its size from
# this, never from a bare number; the host pins
# re-check the mirror against the product source.
FINALIZE_RESERVE_BYTES = 17 * 1024 * 1024

# f4 capture headroom past the reserve: the staging
# files plus the baseline line and the few events a
# slow guest persists between the ready line and the
# post-readiness fill. 1 MiB is orders past the modeled
# ~68 KiB need and noise against the 6 GiB guest.
F4_HEADROOM_BYTES = 1024 * 1024

# Exit the record binary reports for a cannot-start
# refusal (product: src/capture/collector.rs
# EXIT_REFUSAL): a pre-readiness death with this exit
# is a classified refusal; any other pre-readiness
# death is unexpected.
EXIT_REFUSAL = 3


def fail(msg):
    print(f"guest_lifecycle: FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def sha_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1048576), b""):
            h.update(chunk)
    return h.hexdigest()


def mono_ns():
    return time.clock_gettime_ns(time.CLOCK_MONOTONIC)


def remove_scsi_debug(short, sysfs="/sys", poll_rounds=50,
                      poll_gap=0.1, unload_rounds=10,
                      unload_gap=0.5):
    """Delete the owned scsi_debug disk, then unload the module.

    sysfs device deletion completes asynchronously in the
    guest: poll until the block node is gone (bounded), then
    retry the unload a few times. A device that never leaves
    or an unload that never succeeds still fails loudly with
    its cause instead of hanging the gate.
    """
    try:
        with open(os.path.join(sysfs, "block", short, "device",
                               "delete"), "w") as fh:
            fh.write("1")
    except OSError as exc:
        fail("scsi_debug delete failed for %s: %s" % (short, exc))
    node = os.path.join(sysfs, "block", short)
    for _ in range(poll_rounds):
        if not os.path.exists(node):
            break
        time.sleep(poll_gap)
    else:
        fail("scsi_debug disk %s still present after delete"
             % short)
    last = ""
    for _ in range(unload_rounds):
        r = sh(["rmmod", "scsi_debug"])
        if r.returncode == 0:
            return
        last = r.stderr.strip()
        time.sleep(unload_gap)
    fail("scsi_debug rmmod failed: %s" % last)


def validate_victim(alive, rc):
    if alive is not True or rc != -signal.SIGTERM:
        raise ValueError("victim was not alive or did not terminate by SIGTERM")


def dmesg_after_marker(text, marker):
    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if marker in line]
    if len(hits) != 1:
        raise ValueError("dmesg boundary missing/duplicated; wrap or corruption")
    return lines[hits[0] + 1:]


def load_guest_candidate(repo):
    """Verified candidate for this guest, or None in dev.

    The propagated MV_CANDIDATE_DIGEST must match the
    manifest bytes; any mismatch refuses here, before the
    guest touches hardware or starts work.
    """
    sys.path.insert(0, os.path.join(repo, "tests"))
    from support.candidate_input import load
    return load()


def guest_bpf_objects(repo, candidate=None):
    """Lifecycle/copy BPF objects: verified Aya or dev tree.

    Candidate mode resolves the verified Aya objects under
    the verified root; the candidate carries no bridge.
    """
    if candidate is not None:
        return {"lc_obj": str(candidate.path(
                    "bpf/swiotlb_lifecycle.bpf.o")),
                "cp_obj": str(candidate.path(
                    "bpf/swiotlb_copy.bpf.o"))}
    return {"lc_obj": os.path.join(
                repo, "build", "bpf", "swiotlb_lifecycle.bpf.o"),
            "cp_obj": os.path.join(
                repo, "build", "bpf", "swiotlb_copy.bpf.o")}


def guest_bridge_input(repo, sub, candidate):
    """Bridge-path input for guest setup.

    The bundle leg loads no bridge, so its sealed run pins
    the candidate runtime member the sealed engine loads
    instead of the dev bridge fixture; every other leg
    keeps the dev bridge its consumers load.
    """
    if sub == "bundle" and candidate is not None:
        return str(candidate.path(
            "lib/memveil/libgcc_s.so.1"))
    return os.path.join(
        repo, "build", "deps", "lmb", "lib", "libbpf_mojo.so.1")


def topwalk_product_paths(repo, candidate=None):
    """(memveil, attempt object) for a topwalk leg.

    Candidate mode resolves the verified packaged bytes
    under the verified root; dev resolves the build tree.
    """
    if candidate is not None:
        return (str(candidate.path("bin/memveil")),
                str(candidate.path(
                    "bpf/swiotlb_attempt.bpf.o")))
    return (os.path.join(repo, "build", "memveil"),
            os.path.join(
                repo, "build", "bpf", "swiotlb_attempt.bpf.o"))


def topwalk_replay_binary(repo):
    """(replay binary, selection-or-None) for host top replay.

    Candidate inputs select the verified packaged bytes via
    load()/binary(); without them the dev tree binary runs.
    """
    sys.path.insert(0, os.path.join(repo, "tests"))
    from support.candidate_input import binary, load
    development = os.path.join(repo, "build", "memveil")
    selected = load()
    if selected is None:
        return development, None
    return binary(development), selected


def assert_topwalk_memveil_binding(ledger, selected):
    """Refuse unless walk.json names the verified binary.

    A selected candidate pins bin/memveil bytes; the guest
    records the executed binary's sha in walk.json, so a
    mismatch proves the leg ran foreign bytes. Dev runs
    (no selection) record without asserting.
    """
    if selected is None:
        return
    pinned = selected.manifest["files"]["bin/memveil"]
    if ledger.get("memveil_sha") != pinned:
        raise ValueError(
            "walk.json memveil_sha differs from the verified "
            "candidate binary")


# Sealed faults binding: the only guest release, oracle
# bytes, live BTF, and profile the faults flow admits.
# The host re-hashes every pin against its source before
# boot; this guest re-hashes the bytes it actually loads
# before use, so only the exact qualified guest reaches
# the first scenario.
FAULTS_RELEASE = "7.0.14-070014-generic"
FAULTS_KO_SHA256 = "923c708278a8dc0ad96a897bb2d3ed75ef35a521" \
    "428a87fdb07d58d30cd58cfc"
FAULTS_BTF_SHA256 = "ec3aa895be1da974a3116c24cd31adccc5e49fef" \
    "1b4b089dc588aa9e32419a05"
FAULTS_PROFILE_MEMBER = \
    "profiles/linux-x86_64-7.0-reference.json"
FAULTS_KO_FIXTURE = ("tests", "vm", "fixtures", "ko",
                     "memveil_dma_oracle-7.0.14-070014-generic.ko")


class Gate:
    """One subcommand run: paths, checks, consumer control."""

    def __init__(self, sub, work, export, repo):
        self.candidate = load_guest_candidate(repo)
        self.sub = sub
        self.work = work
        self.export_dir = export
        self.repo = repo
        # The bundle and faults legs run the packaged
        # record directly, never the dev consumer, so they
        # carry no consumer prerequisite.
        self.consume = None if sub in ("bundle", "faults") \
            else os.path.join(repo, "build", "vm", "mv_consume")
        # The faults leg loads through the statically linked
        # record loader, so it carries no bridge prerequisite
        # either; every other leg keeps its bridge input.
        self.bridge = None if sub == "faults" \
            else guest_bridge_input(repo, sub, self.candidate)
        self.lc_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_lifecycle.bpf.o")
        self.cp_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_copy.bpf.o")
        self.lc_test_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_lifecycle-test.bpf.o")
        if self.candidate is not None:
            resolved = guest_bpf_objects(repo, self.candidate)
            self.lc_obj = resolved["lc_obj"]
            self.cp_obj = resolved["cp_obj"]
        self.consumers = []
        self.oracle_loaded = False
        self.cp_test_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_copy-test.bpf.o")
        # The faults leg loads the reviewed pinned-guest
        # fixture, never a host-built module; every other leg
        # keeps its built module path.
        self.ko = os.path.join(repo, *FAULTS_KO_FIXTURE) \
            if sub == "faults" else os.path.join(
                repo, "build", "vm", "oracle",
                "memveil_dma_oracle.ko")
        if os.geteuid() != 0:
            fail("guest flow requires root")
        os.makedirs(work, exist_ok=True)
        os.makedirs(export, exist_ok=True)
        required = [path for path in
                    (self.consume, self.bridge, self.lc_obj,
                     self.cp_obj, self.ko)
                    if path is not None]
        for path in required:
            if not os.path.isfile(path):
                fail(f"missing {path}")
        if os.path.exists("/sys/module/memveil_dma_oracle"):
            fail("oracle module already exists; no ownership")
        with open("/proc/cmdline") as fh:
            if "swiotlb=force" not in fh.read():
                fail("guest lacks swiotlb=force")
        if sub == "faults":
            self._faults_preflight()

    def _faults_preflight(self):
        """Bind the sealed faults inputs before any guest work.

        The candidate carries the verified record binary,
        the three channel objects, and the guest-matched
        profile; without it the leg fails closed instead of
        running dev-tree bytes. The oracle fixture is
        re-hashed here and the release plus live BTF pinned,
        so only the exact qualified guest reaches the first
        scenario.
        """
        if self.candidate is None:
            fail("faults needs the verified candidate inputs")
        if os.uname().release != FAULTS_RELEASE:
            fail("guest booted release %r, expected %r"
                 % (os.uname().release, FAULTS_RELEASE))
        self.faults_bin = str(self.candidate.path("bin/memveil"))
        self.faults_attempt = str(self.candidate.path(
            "bpf/swiotlb_attempt.bpf.o"))
        self.faults_profile = str(self.candidate.path(
            FAULTS_PROFILE_MEMBER))
        profiles_dir = self.candidate.path(
            "profiles/manifest.txt").parent
        try:
            listed = profiles_dir.joinpath(
                "manifest.txt").read_text().split()
        except OSError:
            fail("sealed profiles manifest unreadable")
        if os.path.basename(self.faults_profile) not in listed:
            fail("bound profile not listed by its sealed manifest")
        self.faults_profiles_dir = str(profiles_dir)
        if sha_file(self.ko) != FAULTS_KO_SHA256:
            fail("faults oracle bytes differ from the fixture")
        try:
            with open("/sys/kernel/btf/vmlinux", "rb") as handle:
                btf = hashlib.sha256(handle.read()).hexdigest()
        except OSError as exc:
            fail("faults live BTF unreadable: %s" % exc)
        if btf != FAULTS_BTF_SHA256:
            fail("faults live BTF differs from the pinned bytes")

    def identity(self):
        release = os.uname().release
        with open("/proc/cmdline") as fh:
            cmdline = fh.read().strip()
        if self.sub == "faults":
            with open("/sys/kernel/btf/vmlinux", "rb") as fh:
                btf = hashlib.sha256(fh.read()).hexdigest()
            return {"release": release, "cmdline": cmdline,
                    "btf_sha256": btf,
                    "digests": {
                        "binary": sha_file(self.faults_bin),
                        "attempt": sha_file(self.faults_attempt),
                        "lc": sha_file(self.lc_obj),
                        "cp": sha_file(self.cp_obj),
                        "profile": sha_file(self.faults_profile),
                        "ko": sha_file(self.ko)}}
        from lifecycle_env import module_build_identity
        config_btf = module_build_identity()
        doc = {"release": release, "swiotlb_force": "swiotlb=force" in cmdline,
               "config_sha": config_btf["config_sha"], "btf_sha": config_btf["btf_sha"],
               "bridge_sha": sha_file(self.bridge)}
        if self.consume is not None:
            doc["consume_sha"] = sha_file(self.consume)
        doc.update({
                "lc_sha": sha_file(self.lc_test_obj if self.sub == "saturation" else self.lc_obj),
                "cp_sha": sha_file(self.cp_test_obj if self.sub == "saturation" else self.cp_obj),
                "ko_sha": sha_file(self.ko)})
        return doc

    def start_consumer(self, obj, ring, sites, seconds, out):
        """Start one consumer; return the Popen handle."""
        if os.path.exists(out):
            fail(f"consumer out exists: {out}")
        proc = subprocess.Popen(
            [self.consume, "--bridge", self.bridge, obj, ring,
             sites, str(seconds), out],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, start_new_session=True)
        self.consumers.append(proc)
        return proc

    def wait_ready(self, progs, timeout=30):
        """Consume acknowledgements emitted only after all sites attach.

        Loaded program inventory alone cannot prove attachment.
        """
        end = time.monotonic() + timeout
        pending = [p for p in self.consumers if not getattr(p, "gate_ready", False)]
        while pending and time.monotonic() < end:
            for proc in list(pending):
                if proc.poll() is not None:
                    fail("consumer exited before readiness")
                ready, _, _ = select.select([proc.stdout], [], [], 0.1)
                if ready:
                    line = proc.stdout.readline()
                    if line.startswith("ready ring="):
                        proc.gate_ready = True
                        pending.remove(proc)
            if not pending:
                return
        fail(f"consumer attachment acknowledgements timed out: {progs}")

    def clear_dmesg(self):
        r = sh(["dmesg", "-C"])
        if r.returncode != 0:
            fail(f"dmesg -C failed: {r.stderr.strip()}")

    def oracle_log(self, name):
        """Snapshot mv-oracle: lines into work/<name>."""
        dst = os.path.join(self.work, name)
        r = sh(["dmesg"])
        if r.returncode != 0:
            fail("dmesg failed")
        with open(dst, "w") as fh:
            for line in r.stdout.split("\n"):
                if "mv-oracle:" in line:
                    fh.write(line + "\n")
        return dst

    def insmod(self, params):
        args = ["insmod", self.ko, "mv_oracle_arm=1"] + params
        r = sh(args)
        if r.returncode != 0:
            fail(f"insmod failed: {r.stderr.strip()}")
        self.oracle_loaded = True
        return r

    def rmmod(self):
        r = sh(["rmmod", "memveil_dma_oracle"])
        if r.returncode != 0:
            fail(f"rmmod failed: {r.stderr.strip()}")
        self.oracle_loaded = False
        return r

    def wait_consumer(self, proc, tag, timeout=180):
        """Wait for one consumer; fail unless it exits 0."""
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            fail(f"{tag}: consumer did not exit")
        if proc.returncode != 0:
            fail(f"{tag}: consumer exit {proc.returncode}: {out[-500:]}")
        if not getattr(proc, "gate_ready", False) and "ready ring=" not in out:
            fail(f"{tag}: consumer never ready")
        return out

    def export(self, names):
        """Copy work files to the export with sha256 sidecars."""
        for name in names:
            src = os.path.join(self.work, name)
            if not os.path.isfile(src):
                fail(f"missing export {name}")
            dst = os.path.join(self.export_dir, f"{self.sub}-{name}")
            shutil.copyfile(src, dst)
            with open(dst + ".sha256", "w") as fh:
                fh.write(f"{sha_file(dst)}  {self.sub}-{name}\n")

    def write_json(self, name, doc):
        dst = os.path.join(self.work, name)
        with open(dst, "w") as fh:
            json.dump(doc, fh, indent=1, sort_keys=True)
            fh.write("\n")
        return dst

    def io_tlb_used(self):
        with open("/sys/kernel/debug/swiotlb/io_tlb_used") as fh:
            return int(fh.read().strip())

    def io_tlb_samples(self, count=5, gap=1.0):
        """Repeated used-slab samples; the minimum is the floor.

        Background guest DMA can hold transient mappings at any
        single instant, so one sample proves nothing; the
        minimum over a quiet window is the owned baseline.
        """
        out = []
        for _ in range(count):
            out.append(self.io_tlb_used())
            time.sleep(gap)
        return out

    def bpf_inventory(self):
        """Checked JSON object counts; failed queries cannot mean empty."""
        inventory = {}
        for kind, key in (("prog", "progs"), ("map", "maps")):
            r = sh(["bpftool", "-j", kind, "show"])
            if r.returncode != 0:
                raise ValueError("bpftool inventory failed: " + kind)
            objects = json.loads(r.stdout)
            if not isinstance(objects, list) or any(not isinstance(o, dict) or
                    type(o.get("id")) is not int for o in objects):
                raise ValueError("malformed bpftool inventory: " + kind)
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


def run_matrix(gate):
    """Stepped rates: 1, 10, 100 maps/s over scripted traffic."""
    gate.write_json("identity.json", gate.identity())
    names = ["identity.json"]
    for delay_ms, window in ((1000, 20), (100, 16), (10, 16)):
        tag = f"s{delay_ms}"
        gate.clear_dmesg()
        lc = os.path.join(gate.work, f"{tag}-lc.txt")
        cp = os.path.join(gate.work, f"{tag}-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, window, lc)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, window, cp)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        gate.insmod([f"mv_oracle_delay_ms={delay_ms}"])
        time.sleep(5)
        gate.rmmod()
        gate.wait_consumer(plc, f"matrix-{tag}-lc")
        gate.wait_consumer(pcp, f"matrix-{tag}-cp")
        gate.oracle_log(f"{tag}-oracle.log")
        names += [f"{tag}-lc.txt", f"{tag}-cp.txt",
                  f"{tag}-oracle.log"]
    gate.export(names)
    print("guest_lifecycle: matrix exported")


def run_copy(gate):
    """Copy semantics: standard window plus fail-probe window."""
    gate.write_json("identity.json", gate.identity())
    names = ["identity.json"]
    for tag, params in (("a", []), ("b", ["mv_oracle_fail_op=2"])):
        gate.clear_dmesg()
        lc = os.path.join(gate.work, f"{tag}-lc.txt")
        cp = os.path.join(gate.work, f"{tag}-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, 22, lc)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, 22, cp)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        gate.insmod(params)
        time.sleep(5)
        gate.rmmod()
        gate.wait_consumer(plc, f"copy-{tag}-lc")
        gate.wait_consumer(pcp, f"copy-{tag}-cp")
        gate.oracle_log(f"{tag}-oracle.log")
        names += [f"{tag}-lc.txt", f"{tag}-cp.txt",
                  f"{tag}-oracle.log"]
    gate.export(names)
    print("guest_lifecycle: copy exported")


def find_pcnet():
    """Return the pcnet32-driven interface name, else fail."""
    for iface in sorted(os.listdir("/sys/class/net")):
        drv = os.path.join("/sys/class/net", iface, "device", "driver")
        try:
            if os.readlink(drv).endswith("pcnet32"):
                return iface
        except OSError:
            continue
    fail("no pcnet32 NIC found")


def configure_net(iface):
    r = sh(["sysctl", "-w",
            f"net.ipv6.conf.{iface}.disable_ipv6=1"])
    if r.returncode != 0:
        fail(f"ipv6 disable failed: {r.stderr.strip()}")
    r = sh(["ip", "link", "set", iface, "up"])
    if r.returncode != 0:
        fail(f"ip link up failed: {r.stderr.strip()}")
    r = sh(["ip", "addr", "add", "10.0.3.15/24", "dev", iface])
    if r.returncode != 0 and "exists" not in r.stderr:
        fail(f"ip addr failed: {r.stderr.strip()}")
    r = sh(["ping", "-c", "1", "-W", "3", "10.0.3.2"])
    if r.returncode != 0:
        fail(f"gateway ping failed: {r.stdout.strip()}")


def scsi_disks():
    """Set of /dev/sd? block nodes currently present."""
    return {n for n in os.listdir("/dev")
            if re.fullmatch(r"sd[a-z]", n)}


def run_realio(gate):
    """Real block + vnet I/O through the swiotlb path."""
    iface = find_pcnet()
    configure_net(iface)
    gate.write_json("identity.json",
                    dict(gate.identity(), iface=iface))
    before_disks = scsi_disks()
    used_before = gate.io_tlb_samples()
    lc = os.path.join(gate.work, "io-lc.txt")
    cp = os.path.join(gate.work, "io-cp.txt")
    plc = gate.start_consumer(
        gate.lc_obj, "mv_lifecycle", LC_SITES, 90, lc)
    pcp = gate.start_consumer(
        gate.cp_obj, "mv_copies", CP_SITES, 90, cp)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
    workload = {"iface": iface, "used_before": used_before}
    workload["start_ns"] = mono_ns()
    ping = sh(["timeout", "60", "ping", "-A", "-c", "2000",
               "-q", "10.0.3.2"])
    if ping.returncode != 0:
        fail(f"ping workload failed: {ping.stderr.strip()[-300:]}")
    sent = re.search(r"(\d+) packets transmitted", ping.stdout)
    rcvd = re.search(r"(\d+) received", ping.stdout)
    workload["ping_tx"] = int(sent.group(1)) if sent else None
    workload["ping_rx"] = int(rcvd.group(1)) if rcvd else None
    if os.path.exists("/sys/module/scsi_debug"):
        fail("scsi_debug already exists; no fixture ownership")
    r = sh(["modprobe", "scsi_debug", "dev_size_mb=64"])
    if r.returncode != 0:
        fail(f"scsi_debug failed: {r.stderr.strip()}")
    new = None
    for _ in range(30):
        extra = scsi_disks() - before_disks
        if extra:
            new = sorted(extra)[0]
            break
        time.sleep(0.5)
    if new is None:
        fail("scsi_debug disk never appeared")
    dev = f"/dev/{new}"
    model = os.path.join("/sys/block", new, "device", "model")
    try:
        with open(model) as fh:
            if "scsi_debug" not in fh.read():
                fail(f"{dev} is not the scsi_debug disk")
    except OSError:
        fail(f"{dev} has no model file")
    workload["disk"] = dev
    rd = sh(["dd", f"if={dev}", "of=/dev/null", "bs=64k",
             "count=256", "iflag=direct"])
    if rd.returncode != 0:
        fail(f"disk read failed: {rd.stderr.strip()[-200:]}")
    wr = sh(["dd", "if=/dev/zero", f"of={dev}", "bs=64k",
             "count=256", "oflag=direct"])
    if wr.returncode != 0:
        fail(f"disk write failed: {wr.stderr.strip()[-200:]}")
    workload["disk_bytes"] = 2 * 256 * 65536
    remove_scsi_debug(new)
    workload["end_ns"] = mono_ns()
    gate.wait_consumer(plc, "realio-lc")
    gate.wait_consumer(pcp, "realio-cp")
    workload["detach_ns"] = mono_ns()
    time.sleep(5)
    workload["used_after"] = gate.io_tlb_samples()
    gate.write_json("workload.json", workload)
    gate.export(["identity.json", "io-lc.txt", "io-cp.txt",
                 "workload.json"])
    print("guest_lifecycle: realio exported")


def run_stop(gate):
    """Stop races: signals, victim, quiet window, short window."""
    gate.write_json("identity.json", gate.identity())
    names = ["identity.json"]
    ledger = []
    for cycle in range(5):
        tag = f"c{cycle}"
        gate.clear_dmesg()
        lc = os.path.join(gate.work, f"{tag}-lc.txt")
        cp = os.path.join(gate.work, f"{tag}-cp.txt")
        row = {"cycle": cycle}
        if cycle == 2:
            # Quiet window: traffic first, consumers after.
            gate.insmod([])
            time.sleep(2)
            gate.rmmod()
            gate.clear_dmesg()
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 10, lc)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 10, cp)
            gate.wait_ready(("mv_map_result", "mv_bounce"))
            gate.wait_consumer(plc, f"stop-{tag}-lc")
            gate.wait_consumer(pcp, f"stop-{tag}-cp")
            row["mode"] = "quiet"
            row["lc_exit"] = 0
            row["cp_exit"] = 0
        elif cycle == 4:
            # Short window over slow traffic: detach mid-run.
            # The 6 s window covers the 3 s script with margin
            # but ends long before the exit release.
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 6, lc)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 6, cp)
            gate.wait_ready(("mv_map_result", "mv_bounce"))
            gate.insmod(["mv_oracle_delay_ms=1000"])
            gate.wait_consumer(plc, f"stop-{tag}-lc", timeout=60)
            gate.wait_consumer(pcp, f"stop-{tag}-cp", timeout=60)
            time.sleep(6)
            gate.rmmod()
            row["mode"] = "short"
            row["lc_exit"] = 0
            row["cp_exit"] = 0
        else:
            plc = gate.start_consumer(
                gate.lc_obj, "mv_lifecycle", LC_SITES, 20, lc)
            pcp = gate.start_consumer(
                gate.cp_obj, "mv_copies", CP_SITES, 20, cp)
            gate.wait_ready(("mv_map_result", "mv_bounce"))
            gate.insmod([])
            time.sleep(1)
            if cycle in (0, 3):
                targets = (plc, pcp) if cycle == 0 else (plc,)
                for proc in targets:
                    os.kill(proc.pid, signal.SIGSTOP)
                time.sleep(2)
                for proc in targets:
                    os.kill(proc.pid, signal.SIGCONT)
                row["mode"] = "stop-both" if cycle == 0 else "stop-lc"
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
                validate_victim(alive, victim_rc)
                if os.path.exists(cp):
                    with open(cp) as fh:
                        body = fh.read()
                    if "\nsummary " in body or body.startswith(
                            "summary "):
                        fail("stop victim left a summary")
            time.sleep(4)
            gate.rmmod()
            gate.wait_consumer(plc, f"stop-{tag}-lc")
            if cycle != 1:
                gate.wait_consumer(pcp, f"stop-{tag}-cp")
            row["lc_exit"] = 0
            row["cp_exit"] = 0 if cycle != 1 else row["victim_rc"]
        gate.oracle_log(f"{tag}-oracle.log")
        if cycle == 1 and not os.path.exists(cp):
            names += [f"{tag}-lc.txt", f"{tag}-oracle.log"]
        else:
            names += [f"{tag}-lc.txt", f"{tag}-cp.txt",
                      f"{tag}-oracle.log"]
        ledger.append(row)
    gate.write_json("ledger.json", ledger)
    names.append("ledger.json")
    gate.export(names)
    print("guest_lifecycle: stop exported")


def run_saturation(gate):
    """Small-ring flood: exact loss accounting under STOP."""
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "flood-lc.txt")
    cp = os.path.join(gate.work, "flood-cp.txt")
    plc = gate.start_consumer(
        gate.lc_test_obj, "mv_lifecycle", LC_SITES, 40, lc)
    pcp = gate.start_consumer(
        gate.cp_test_obj, "mv_copies", CP_SITES, 40, cp)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
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
    gate.export(["identity.json", "flood-lc.txt", "flood-cp.txt",
                 "flood-oracle.log"])
    print("guest_lifecycle: saturation exported")


def run_cleanup(gate):
    """100 start/stop/error cycles against a resource baseline."""
    gate.write_json("identity.json", gate.identity())
    baseline = {
        "bpf": gate.bpf_inventory(),
        "io_tlb_used": gate.io_tlb_samples(),
        "files": sorted(os.listdir(gate.work)),
    }
    marker = "memveil-cleanup-" + uuid.uuid4().hex
    with open("/dev/kmsg", "w") as fh:
        fh.write("<6>" + marker + "\n")
    before = sh(["dmesg"])
    if before.returncode != 0:
        fail("dmesg unavailable before cleanup")
    dmesg_after_marker(before.stdout, marker)
    ledger = []
    for cycle in range(100):
        row = {"cycle": cycle}
        lc = os.path.join(gate.work, f"w{cycle}-lc.txt")
        cp = os.path.join(gate.work, f"w{cycle}-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, 2, lc)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, 2, cp)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        if cycle % 5 == 0:
            gate.insmod([])
            gate.rmmod()
            row["traffic"] = True
        else:
            time.sleep(0.2)
            row["traffic"] = False
        gate.wait_consumer(plc, f"cleanup-w{cycle}-lc")
        gate.wait_consumer(pcp, f"cleanup-w{cycle}-cp")
        from consume import parse_consume_file, check_conservation
        row["health"] = {}
        for ring, path in (("lc", lc), ("cp", cp)):
            events, summary = parse_consume_file(path)
            bad = check_conservation(events, summary, f"cleanup-{cycle}-{ring}")
            if summary["cnt_fail"]:
                bad.append("unexpected cleanup detail loss")
            if bad:
                fail("; ".join(bad))
            row["health"][ring] = summary
        os.remove(lc)
        os.remove(cp)
        error = cycle % 7
        if error == 1:
            r = sh(["insmod", gate.ko])
            row["error"] = {"case": "insmod-unarmed", "rc": r.returncode}
            if r.returncode == 0:
                gate.rmmod()
                fail("unarmed insmod unexpectedly loaded")
        elif error == 3:
            r = sh([gate.consume, "--bridge", gate.bridge,
                    "/nonexistent.bpf.o", "mv_lifecycle",
                    LC_SITES, "2",
                    os.path.join(gate.work, "err.txt")])
            row["error"] = {"case": "bad-object", "rc": r.returncode}
            if r.returncode == 0:
                fail("bad-object consumer exited 0")
        elif error == 5:
            r = sh([gate.consume, "--bridge", gate.bridge,
                    gate.lc_obj, "mv_bogus", LC_SITES, "2",
                    os.path.join(gate.work, "err.txt")])
            row["error"] = {"case": "bad-ring", "rc": r.returncode}
            if r.returncode == 0:
                fail("bad-ring consumer exited 0")
        else:
            row["error"] = {"case": "none", "rc": 0}
        ledger.append(row)
    after_bpf, after_settle = gate.settled_inventory(
        baseline["bpf"])
    after = {
        "bpf": after_bpf,
        "io_tlb_used": gate.io_tlb_samples(),
        "files": sorted(os.listdir(gate.work)),
    }
    after_log = sh(["dmesg"])
    if after_log.returncode != 0:
        fail("dmesg unavailable after cleanup")
    fresh_dmesg = dmesg_after_marker(after_log.stdout, marker)
    suspicious = [line for line in fresh_dmesg
                  if re.search(r"warn|bug|oops|error", line,
                               re.IGNORECASE)
                  and "mv-oracle:" not in line]
    gate.write_json("ledger.json", ledger)
    gate.write_json("inventory.json", {
        "baseline": baseline, "after": after,
        "bpf_settle_s": after_settle,
        "dmesg_marker_present": True,
        "suspicious": len(suspicious),
    })
    gate.export(["identity.json", "ledger.json", "inventory.json"])
    print("guest_lifecycle: cleanup exported")


def ping_leg(gateway, count):
    """One ping leg: (tx, rx, seconds, p99_ms or None).

    A flood run measures throughput; flood mode prints no
    per-packet times, so a paced run supplies the p99 sample.
    """
    start = mono_ns()
    proc = sh(["timeout", "120", "ping", "-A", "-c",
               str(count), "-q", gateway])
    elapsed = (mono_ns() - start) / 1e9
    if proc.returncode != 0:
        fail(f"ping flood failed: {proc.stderr.strip()[-300:]}")
    sent = re.search(r"(\d+) packets transmitted", proc.stdout)
    rcvd = re.search(r"(\d+) received", proc.stdout)
    samp = sh(["timeout", "120", "ping", "-i", "0.01", "-c",
               "500", gateway])
    if samp.returncode != 0:
        fail(f"ping sample failed: {samp.stderr.strip()[-300:]}")
    rtts = [float(v) for v in
            re.findall(r"time=([\d.]+) ms", samp.stdout)]
    p99 = None
    sample_tx = re.search(r"(\d+) packets transmitted", samp.stdout)
    sample_rx = re.search(r"(\d+) received", samp.stdout)
    sample = dict(sample_tx=int(sample_tx.group(1)) if sample_tx else None,
                  sample_rx=int(sample_rx.group(1)) if sample_rx else None,
                  sample_count=len(rtts))
    if rtts:
        ordered = sorted(rtts)
        p99 = ordered[max(0, (99 * len(ordered) - 1) // 100)]
    return (int(sent.group(1)) if sent else None,
            int(rcvd.group(1)) if rcvd else None,
            elapsed, p99, sample)


def dd_leg(dev, size_mb=32):
    """One dd leg: (bytes, seconds)."""
    count = size_mb * 16
    start = mono_ns()
    rd = sh(["dd", f"if={dev}", "of=/dev/null", "bs=64k",
             f"count={count}", "iflag=direct"])
    elapsed = (mono_ns() - start) / 1e9
    if rd.returncode != 0:
        fail(f"dd leg failed: {rd.stderr.strip()[-200:]}")
    copied = re.search(r"(\d+) bytes .* copied", rd.stderr)
    if copied is None or int(copied.group(1)) != count * 65536:
        fail("dd leg did not complete independently counted bytes")
    return int(copied.group(1)), elapsed


def dd_flood_leg(dev, size_mb):
    """One concurrent flood leg: {bytes, seconds} or FAIL."""
    count = size_mb * 16
    start = mono_ns()
    rd = sh(["dd", f"if={dev}", "of=/dev/null", "bs=64k",
             f"count={count}", "iflag=direct"])
    elapsed = (mono_ns() - start) / 1e9
    if rd.returncode != 0:
        fail(f"dd flood leg failed: {rd.stderr.strip()[-200:]}")
    copied = re.search(r"(\d+) bytes .* copied", rd.stderr)
    if copied is None or int(copied.group(1)) != count * 65536:
        fail("dd flood leg short: %s" % rd.stderr.strip()[-200:])
    return {"bytes": int(copied.group(1)), "seconds": elapsed}


def block_stat(short):
    """Whole-disk counters proving DMA flowed (no addresses)."""
    with open(os.path.join("/sys/block", short, "stat")) as fh:
        vals = [int(x) for x in fh.read().split()]
    return {"read_ios": vals[0], "read_sectors": vals[2],
            "write_ios": vals[4], "write_sectors": vals[6]}


def run_perf(gate):
    """Paired off/observed workload legs: ping + dd."""
    iface = find_pcnet()
    configure_net(iface)
    gate.write_json("identity.json",
                    dict(gate.identity(), iface=iface))
    before_disks = scsi_disks()
    if os.path.exists("/sys/module/scsi_debug"):
        fail("scsi_debug already exists; no fixture ownership")
    r = sh(["modprobe", "scsi_debug", "dev_size_mb=64"])
    if r.returncode != 0:
        fail(f"scsi_debug failed: {r.stderr.strip()}")
    disk = None
    for _ in range(30):
        extra = scsi_disks() - before_disks
        if extra:
            disk = f"/dev/{sorted(extra)[0]}"
            break
        time.sleep(0.5)
    if disk is None:
        fail("scsi_debug disk never appeared")
    short = disk.rsplit("/", 1)[1]
    with open(os.path.join("/sys/block", short, "device", "model")) as fh:
        if "scsi_debug" not in fh.read():
            fail("new perf disk is not owned scsi_debug")
    names = ["identity.json"]
    pairs = []
    # Six pairs for five valid: validate-first may exclude one.
    for pair in range(6):
        legs = []
        for mode in ("off", "observed"):
            leg = {"pair": pair, "mode": mode}
            if mode == "observed":
                lc = os.path.join(gate.work, f"p{pair}-lc.txt")
                cp = os.path.join(gate.work, f"p{pair}-cp.txt")
                plc = gate.start_consumer(
                    gate.lc_obj, "mv_lifecycle", LC_SITES, 60, lc)
                pcp = gate.start_consumer(
                    gate.cp_obj, "mv_copies", CP_SITES, 60, cp)
                gate.wait_ready(("mv_map_result", "mv_bounce"))
                leg["attach_ns"] = mono_ns()
            tx, rx, secs, p99, sample = ping_leg("10.0.3.2", 1000)
            leg["ping"] = {"tx": tx, "rx": rx, "seconds": secs,
                           "p99_ms": p99, **sample}
            nbytes, dsecs = dd_leg(disk)
            leg["dd"] = {"bytes": nbytes, "seconds": dsecs}
            leg["end_ns"] = mono_ns()
            if mode == "observed":
                gate.wait_consumer(plc, f"perf-p{pair}-lc")
                gate.wait_consumer(pcp, f"perf-p{pair}-cp")
                leg["detach_ns"] = mono_ns()
                names += [f"p{pair}-lc.txt", f"p{pair}-cp.txt"]
            legs.append(leg)
        pairs.append(legs)
    short = disk.rsplit("/", 1)[1]
    remove_scsi_debug(short)
    gate.write_json("pairs.json", pairs)
    names.append("pairs.json")
    gate.export(names)
    print("guest_lifecycle: perf exported")


def run_oracle(gate):
    """Single scripted window for the ledger comparison."""
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    lc = os.path.join(gate.work, "cmp-lc.txt")
    cp = os.path.join(gate.work, "cmp-cp.txt")
    plc = gate.start_consumer(
        gate.lc_obj, "mv_lifecycle", LC_SITES, 25, lc)
    pcp = gate.start_consumer(
        gate.cp_obj, "mv_copies", CP_SITES, 25, cp)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
    gate.insmod(["mv_oracle_delay_ms=100"])
    time.sleep(5)
    gate.rmmod()
    gate.wait_consumer(plc, "oracle-lc")
    gate.wait_consumer(pcp, "oracle-cp")
    gate.oracle_log("cmp-oracle.log")
    gate.export(["identity.json", "cmp-lc.txt", "cmp-cp.txt",
                 "cmp-oracle.log"])
    print("guest_lifecycle: oracle exported")


def run_witness(gate):
    """Executed-copy witness plus inner/outer fail windows.

    Window w runs the standard script with bounce readback
    and device-write simulation; window f adds the fail
    probe with an unclamped inner-health retry. Both keep
    the standard DMA call sequence, so probe multisets stay
    comparable to the laboratory baselines.
    """
    gate.write_json("identity.json", gate.identity())
    names = ["identity.json"]
    cases = (("w", ["mv_oracle_witness=1",
                    "mv_oracle_delay_ms=100"]),
             ("f", ["mv_oracle_witness=1",
                    "mv_oracle_delay_ms=100",
                    "mv_oracle_fail_op=2",
                    "mv_oracle_inner_probe=1"]))
    for tag, params in cases:
        gate.clear_dmesg()
        lc = os.path.join(gate.work, f"{tag}-lc.txt")
        cp = os.path.join(gate.work, f"{tag}-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, 25, lc)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, 25, cp)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        gate.insmod(params)
        time.sleep(5)
        gate.rmmod()
        gate.wait_consumer(plc, f"witness-{tag}-lc")
        gate.wait_consumer(pcp, f"witness-{tag}-cp")
        gate.oracle_log(f"{tag}-oracle.log")
        names += [f"{tag}-lc.txt", f"{tag}-cp.txt",
                  f"{tag}-oracle.log"]
    gate.export(names)
    print("guest_lifecycle: witness exported")


def run_canonical(gate):
    """Fixed canonical lifecycle/copy windows (oracle 0.4.0).

    One window per scenario: nested overlapping mappings,
    request-only sync, clamped over-sync, early-return sync
    after unmap, and sequential reuse. Every window runs
    with bounce readback; the host test compares against
    the frozen canonical spec.
    """
    gate.write_json("identity.json", gate.identity())
    names = ["identity.json"]
    cases = (
        ("n", ["mv_oracle_witness=1", "mv_oracle_delay_ms=100",
              "mv_oracle_scenario=1"]),
        ("s", ["mv_oracle_witness=1", "mv_oracle_delay_ms=100",
              "mv_oracle_scenario=2"]),
        ("c", ["mv_oracle_witness=1", "mv_oracle_delay_ms=100",
              "mv_oracle_scenario=3"]),
        ("e", ["mv_oracle_witness=1", "mv_oracle_delay_ms=100",
              "mv_oracle_scenario=4"]),
        ("r", ["mv_oracle_witness=1", "mv_oracle_delay_ms=100",
              "mv_oracle_scenario=5"]),
    )
    for tag, params in cases:
        gate.clear_dmesg()
        lc = os.path.join(gate.work, f"{tag}-lc.txt")
        cp = os.path.join(gate.work, f"{tag}-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, 25, lc)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, 25, cp)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        gate.insmod(params)
        time.sleep(5)
        gate.rmmod()
        gate.wait_consumer(plc, f"canonical-{tag}-lc")
        gate.wait_consumer(pcp, f"canonical-{tag}-cp")
        gate.oracle_log(f"{tag}-oracle.log")
        names += [f"{tag}-lc.txt", f"{tag}-cp.txt",
                  f"{tag}-oracle.log"]
    gate.export(names)
    print("guest_lifecycle: canonical exported")


def run_record3(gate):
    """Three-channel product record over nested oracle traffic.

    Runs the real `memveil record` with attempt, lifecycle,
    and copy channels against scenario 1 (nested 4096+1024)
    using the host-minted ephemeral test profile, then
    exports the capture plus the oracle log for host-side
    comparison.
    """
    memveil = os.path.join(gate.repo, "build", "memveil")
    attempt_obj = os.path.join(
        gate.repo, "build", "bpf", "swiotlb_attempt.bpf.o")
    profile = os.path.join(
        gate.repo, "build", "vm", "record3-profile.json")
    for path in (memveil, attempt_obj, profile):
        if not os.path.isfile(path):
            fail(f"missing {path}")
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    cap = os.path.join(gate.work, "cap")
    rec = subprocess.Popen(
        [memveil, "record",
         "--duration", "30",
         "--output", cap,
         "--object", attempt_obj,
         "--lc-object", gate.lc_obj,
         "--cp-object", gate.cp_obj,
         "--bridge", gate.bridge,
         "--profile", profile,
         "--capability",
         "attempt-trace,mapping-lifecycle,copy-actual"],
        stdout=subprocess.PIPE,
        stderr=open(os.path.join(gate.work, "record.stderr"),
                    "wb"),
        text=True,
        bufsize=1,
        start_new_session=True,
    )
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
    def record_tail():
        try:
            with open(os.path.join(gate.work, "record.stderr"),
                      "rb") as fh:
                return fh.read()[-500:].decode(
                    "utf-8", "replace")
        except OSError:
            return ""
    if ready is None:
        try:
            rec.kill()
        except OSError:
            pass
        fail("record never reached readiness: "
             + record_tail())
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
        fail("record did not exit: " + record_tail())
    gate.write_json("record.json", {"exit": rc, "ready": ready})
    gate.oracle_log("r3-oracle.log")
    for name in ("session.json", "events.ndjson"):
        src = os.path.join(cap, name)
        if not os.path.isfile(src):
            fail(f"capture lacks {name}")
        shutil.copyfile(
            src, os.path.join(gate.work, "cap-" + name))
    gate.export(["identity.json", "record.json",
                 "cap-session.json", "cap-events.ndjson",
                 "r3-oracle.log"])
    print(f"guest_lifecycle: record3 exported record_exit={rc} "
          f"stderr_tail={record_tail()!r}")


def verify_extracted_bundle(root):
    """Check the extracted tree against its own MANIFEST.json."""
    manifest_path = os.path.join(root, "MANIFEST.json")
    with open(manifest_path) as fh:
        manifest = json.load(fh)
    files = manifest["files"]
    seen = set()
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            full = os.path.join(dirpath, name)
            if os.path.islink(full):
                fail(f"bundle symlink not allowed: {full}")
            rel = os.path.relpath(full, root)
            if rel == "MANIFEST.json":
                continue
            seen.add(rel)
    if seen != set(files):
        fail(f"bundle file set drift: "
             f"{sorted(seen ^ set(files))[:8]}")
    for rel, want in files.items():
        if sha_file(os.path.join(root, rel)) != want:
            fail(f"bundle hash mismatch: {rel}")
    return manifest


def await_record_ready(rec, work, errname="record.stderr",
                       allow_refusal=False):
    """Wait for the record readiness line; classify early death.

    Returns (ready, tail) on the ready line. A
    pre-readiness death with the refusal exit returns
    (None, tail) only with allow_refusal; any other
    pre-readiness death (wrong exit, signal, timeout)
    fails loudly, as does a refusal where readiness was
    staged. Callers that staged readiness keep the
    default and never silently ledger a refusal.
    """
    def tail():
        try:
            with open(os.path.join(work, errname),
                      "rb") as fh:
                return fh.read()[-500:].decode("utf-8", "replace")
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
    if ready is not None:
        return ready, tail
    rc = rec.poll()
    if rc is None:
        try:
            rec.kill()
        except OSError:
            pass
        fail("record never reached readiness: " + tail())
    if rc == EXIT_REFUSAL:
        if allow_refusal:
            return None, tail
        fail("record refused pre-readiness, readiness "
             "staged: " + tail())
    if rc < 0:
        fail(f"record died pre-readiness (signal {-rc}): {tail()}")
    fail(f"record died pre-readiness (exit {rc}): {tail()}")


def drain_done_line(rec):
    """Last non-empty stdout line past the ready line.

    Record prints exactly one stdout summary at exit,
    so past the consumed ready line the remainder
    holds only that run verdict (plus blank padding,
    if any). Empty when record printed nothing past
    readiness; the host judge refuses the empty line.
    """
    done = ""
    for line in rec.stdout.read().splitlines():
        if line.strip():
            done = line.strip()
    return done


def f4_fs_bytes():
    """f4 output filesystem size: reserve plus headroom."""
    return FINALIZE_RESERVE_BYTES + F4_HEADROOM_BYTES


def f4_admits_start(fs_bytes):
    """True when a filesystem admits the f4 reserve plus headroom."""
    return fs_bytes >= f4_fs_bytes()


def fill_to_full(path):
    """Grow a filler file until its filesystem reports full.

    Unbuffered 4 KiB writes so each ENOSPC surfaces at
    the failing write rather than at close, leaving
    under a page free. ENOSPC anywhere (open, write,
    close) means the postcondition already holds and
    returns quietly; any other errno, or a zero-byte
    write without error, fails loudly: a filler that
    stops any other way proves nothing about fullness.
    """
    chunk = b"x" * 4096
    try:
        with open(path, "ab", buffering=0) as handle:
            while True:
                if handle.write(chunk) == 0:
                    fail("filler wrote zero bytes "
                         "without error")
    except OSError as exc:
        if exc.errno != errno.ENOSPC:
            fail(f"filler failed: {exc}")


def _read_int_file(path):
    with open(path) as fh:
        return int(fh.read().strip())


def run_topwalk(gate):
    """Live top walkthrough: ordinary disk I/O under live capture.

    Runs the real `memveil top --output` with attempt,
    lifecycle, and copy channels against the selected gate
    profile while ordinary direct-I/O disk traffic flows
    through the swiotlb path, then exports the live blocks
    plus the retained capture for host-side replay
    comparison. An independent debugfs witness brackets the
    run; BPF inventory must settle back to baseline.
    """
    memveil, attempt_obj = topwalk_product_paths(
        gate.repo, gate.candidate)
    profile = os.path.join(
        gate.repo, "build", "vm", "gate-profile.json")
    for path in (memveil, attempt_obj, profile):
        if not os.path.isfile(path):
            fail(f"missing {path}")
    gate.write_json("identity.json", gate.identity())
    before = gate.bpf_inventory()
    witness = {"nslabs": _read_int_file(
        "/sys/kernel/debug/swiotlb/io_tlb_nslabs")}
    witness["used_before"] = gate.io_tlb_samples(count=3, gap=1.0)
    before_disks = scsi_disks()
    if os.path.exists("/sys/module/scsi_debug"):
        fail("scsi_debug already exists; no fixture ownership")
    r = sh(["modprobe", "scsi_debug", "dev_size_mb=64"])
    if r.returncode != 0:
        fail(f"scsi_debug failed: {r.stderr.strip()}")
    new = None
    for _ in range(30):
        extra = scsi_disks() - before_disks
        if extra:
            new = sorted(extra)[0]
            break
        time.sleep(0.5)
    if new is None:
        fail("scsi_debug disk never appeared")
    dev = f"/dev/{new}"
    model = os.path.join("/sys/block", new, "device", "model")
    try:
        with open(model) as fh:
            if "scsi_debug" not in fh.read():
                fail(f"{dev} is not the scsi_debug disk")
    except OSError:
        fail(f"{dev} has no model file")
    stat_path = os.path.join("/sys/block", new, "stat")
    with open(stat_path) as fh:
        stat_before = fh.read().split()
    workload = {"disk": dev}
    cap = os.path.join(gate.work, "cap")
    live_txt = os.path.join(gate.work, "live.txt")
    live_err = os.path.join(gate.work, "live.err")
    env = dict(os.environ, LMB_NATIVE_LIB=gate.bridge)
    writer = subprocess.Popen(
        ["timeout", "60", "bash", "-c",
         f"while true; do dd if=/dev/zero of={dev} bs=64k "
         f"count=256 oflag=direct 2>/dev/null; done"],
        start_new_session=True)
    workload["start_ns"] = mono_ns()
    proc = subprocess.Popen(
        [memveil, "top",
         "--output", cap,
         "--object", attempt_obj,
         "--lc-object", gate.lc_obj,
         "--cp-object", gate.cp_obj,
         "--bridge", gate.bridge,
         "--profile", profile,
         "--capability",
         "attempt-trace,mapping-lifecycle,copy-actual",
         "--duration", "15",
         "--interval", "1s"],
        stdout=open(live_txt, "w"),
        stderr=open(live_err, "w"),
        env=env,
        start_new_session=True)
    try:
        rc = proc.wait(timeout=180)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        fail("live top did not exit")
    workload["end_ns"] = mono_ns()
    workload["writer_alive"] = writer.poll() is None
    with open(stat_path) as fh:
        stat_after = fh.read().split()
    workload["stat_before"] = stat_before
    workload["stat_after"] = stat_after
    try:
        writer.terminate()
        writer.wait(timeout=30)
    except subprocess.TimeoutExpired:
        writer.kill()
        writer.wait()
        fail("workload writer ignored SIGTERM")
    remove_scsi_debug(new)
    witness["used_after"] = gate.io_tlb_samples(count=3, gap=1.0)
    witness["nslabs_after"] = _read_int_file(
        "/sys/kernel/debug/swiotlb/io_tlb_nslabs")
    after, waited = gate.settled_inventory(before)
    session_path = os.path.join(cap, "session.json")
    events_path = os.path.join(cap, "events.ndjson")
    for path in (session_path, events_path):
        if not os.path.isfile(path):
            fail(f"capture lacks {os.path.basename(path)}")
    with open(session_path) as fh:
        session = json.load(fh)
    caps = session.get("capabilities", {})
    gate.write_json("walk.json", {
        "memveil_rc": rc,
        "memveil_sha": sha_file(memveil),
        "attempt_sha": sha_file(attempt_obj),
        "profile_sha": sha_file(profile),
        "profile_ids": {
            key: caps.get(key, {}).get("profile_id", "")
            for key in ("bounce_attempts", "mapping_lifecycle",
                        "copy_bytes", "pool_stats")
        },
        "end_reason": session.get("capture", {}).get(
            "end_reason", ""),
        "bpf_before": before,
        "bpf_after": after,
        "settled_waited_s": waited,
        "witness": witness,
        "workload": workload,
        "live_stdout_sha": sha_file(live_txt),
        "live_stderr_sha": sha_file(live_err),
    })
    shutil.copyfile(
        session_path, os.path.join(gate.work, "cap-session.json"))
    shutil.copyfile(
        events_path, os.path.join(gate.work, "cap-events.ndjson"))
    gate.export(["identity.json", "walk.json", "live.txt",
                 "live.err", "cap-session.json",
                 "cap-events.ndjson"])
    print(f"guest_lifecycle: topwalk exported top_exit={rc}")


BUNDLE_VERSION = "0.2.0"


def bundle_run_inputs(repo, candidate):
    """Execution inputs for the bundle leg.

    Dev (candidate None): the dist tarball plus the extract
    root name. Sealed: the binary, BPF objects, and runtime
    member under the verified root; the dev tree is never
    consulted, so a missing sealed member raises instead of
    falling back to dev objects.
    """
    if candidate is None:
        return {
            "mode": "dev",
            "tarball": os.path.join(
                repo, "dist",
                "memveil-%s.tar.gz" % BUNDLE_VERSION),
            "root_name": "memveil-" + BUNDLE_VERSION,
        }
    return {
        "mode": "sealed",
        "tarball": str(candidate.bundle),
        "tarball_name": candidate.bundle.name,
        "tarball_sha": sha_file(str(candidate.bundle)),
        "root": str(candidate.root),
        "bin": str(candidate.path("bin/memveil")),
        "attempt": str(candidate.path(
            "bpf/swiotlb_attempt.bpf.o")),
        "lc": str(candidate.path(
            "bpf/swiotlb_lifecycle.bpf.o")),
        "cp": str(candidate.path(
            "bpf/swiotlb_copy.bpf.o")),
        "libgcc": str(candidate.path(
            "lib/memveil/libgcc_s.so.1")),
        "manifest_sha":
            candidate.manifest["bundle_manifest_sha256"],
        "files": dict(candidate.manifest["files"]),
        "files_verified": len(candidate.manifest["files"]),
    }


def bundle_record_argv(bundle_bin, objects, profile, cap):
    """Record argv for the bundle leg.

    The statically linked loader runs without --bridge; the
    bundle carries no bridge library in either mode.
    """
    return [bundle_bin, "record",
            "--duration", "150",
            "--output", cap,
            "--object", objects["attempt"],
            "--lc-object", objects["lc"],
            "--cp-object", objects["cp"],
            "--profile", profile,
            "--capability",
            "attempt-trace,mapping-lifecycle,copy-actual"]


def run_bundle(gate):
    """Shipped bundle, three phases, extracted-binary report.

    Dev: extracts dist/memveil-0.2.0.tar.gz, verifies every
    file against MANIFEST.json (no symlinks, exact set, exact
    hashes), and proves the shipped BPF copies equal the
    build. Sealed: serves the verified candidate root
    directly (already verified at load; the manifest bytes
    are re-pinned here) with no dev-tree consultation. Both
    modes run the bundle record with all three channels
    through oracle-exact, outer-failure, and block+vnet phases
    in one capture. The extracted report renders the capture;
    bundle.json retains phases, hashes, and the console tail.
    """
    profile = os.path.join(
        gate.repo, "build", "vm", "record3-profile.json")
    run = bundle_run_inputs(gate.repo, gate.candidate)
    if run["mode"] == "sealed":
        tarball = run["tarball"]
        for path in (tarball, profile):
            if not os.path.isfile(path):
                fail(f"missing {path}")
        root = run["root"]
        if sha_file(os.path.join(
                root, "MANIFEST.json")) != run["manifest_sha"]:
            fail("sealed bundle manifest differs")
        tarball_name = run["tarball_name"]
        tarball_sha = run["tarball_sha"]
        manifest_sha = run["manifest_sha"]
        files_verified = run["files_verified"]
        bundle_bin = run["bin"]
        bundle_objs = {
            "attempt": run["attempt"],
            "lc": run["lc"],
            "cp": run["cp"],
        }
        libgcc = run["libgcc"]
    else:
        tarball = run["tarball"]
        for path in (tarball, profile):
            if not os.path.isfile(path):
                fail(f"missing {path}")
        extract = os.path.join(gate.work, "extract")
        os.makedirs(extract)
        r = sh(["tar", "xzf", tarball, "-C", extract])
        if r.returncode != 0:
            fail("bundle extract failed: "
                 f"{r.stderr.strip()[-200:]}")
        root = os.path.join(extract, run["root_name"])
        manifest = verify_extracted_bundle(root)
        bundle_bin = os.path.join(root, "bin", "memveil")
        bundle_objs = {
            "attempt": os.path.join(root, "bpf",
                                    "swiotlb_attempt.bpf.o"),
            "lc": os.path.join(root, "bpf",
                               "swiotlb_lifecycle.bpf.o"),
            "cp": os.path.join(root, "bpf",
                               "swiotlb_copy.bpf.o"),
        }
        libgcc = os.path.join(root, "lib", "memveil",
                              "libgcc_s.so.1")
        if not os.path.isfile(libgcc):
            fail(f"missing {libgcc}")
        build_objs = {
            "attempt": os.path.join(
                gate.repo, "build", "bpf",
                "swiotlb_attempt.bpf.o"),
            "lc": gate.lc_obj,
            "cp": gate.cp_obj,
        }
        for key in ("attempt", "lc", "cp"):
            if sha_file(bundle_objs[key]) != sha_file(
                    build_objs[key]):
                fail(f"bundle {key} object differs from build")
        tarball_name = os.path.basename(tarball)
        tarball_sha = sha_file(tarball)
        manifest_sha = sha_file(os.path.join(
            root, "MANIFEST.json"))
        files_verified = len(manifest["files"])
    gate.write_json("identity.json", gate.identity())
    iface = find_pcnet()
    configure_net(iface)
    gate.write_json("identity.json",
                    dict(gate.identity(), iface=iface))
    before_disks = scsi_disks()
    used_before = gate.io_tlb_samples()
    cap = os.path.join(gate.work, "cap")
    rec = subprocess.Popen(
        bundle_record_argv(
            bundle_bin, bundle_objs, profile, cap),
        stdout=subprocess.PIPE,
        stderr=open(os.path.join(gate.work, "record.stderr"),
                    "wb"),
        text=True,
        bufsize=1,
        start_new_session=True,
    )
    ready, tail = await_record_ready(rec, gate.work)
    phases = {}
    gate.clear_dmesg()
    phases["oracle"] = [mono_ns()]
    gate.insmod(["mv_oracle_witness=1",
                 "mv_oracle_delay_ms=100",
                 "mv_oracle_scenario=1"])
    time.sleep(8)
    gate.rmmod()
    time.sleep(2)
    phases["oracle"].append(mono_ns())
    gate.oracle_log("o-oracle.log")
    gate.clear_dmesg()
    phases["fail"] = [mono_ns()]
    gate.insmod(["mv_oracle_witness=1",
                 "mv_oracle_delay_ms=100",
                 "mv_oracle_fail_op=2",
                 "mv_oracle_inner_probe=1"])
    time.sleep(10)
    gate.rmmod()
    time.sleep(2)
    phases["fail"].append(mono_ns())
    gate.oracle_log("f-oracle.log")
    workload = {"iface": iface, "used_before": used_before}
    phases["io"] = [mono_ns()]
    workload["start_ns"] = phases["io"][0]
    # Low-rate I/O: the F2-6 bar is exact low-rate comparison,
    # not flood absorption (burst overrun is F2-7's subject).
    ping = sh(["timeout", "60", "ping", "-A", "-c", "200",
               "-q", "10.0.3.2"])
    if ping.returncode != 0:
        fail(f"ping workload failed: {ping.stderr.strip()[-300:]}")
    sent = re.search(r"(\d+) packets transmitted", ping.stdout)
    rcvd = re.search(r"(\d+) received", ping.stdout)
    workload["ping_tx"] = int(sent.group(1)) if sent else None
    workload["ping_rx"] = int(rcvd.group(1)) if rcvd else None
    if os.path.exists("/sys/module/scsi_debug"):
        fail("scsi_debug already exists; no fixture ownership")
    r = sh(["modprobe", "scsi_debug", "dev_size_mb=64"])
    if r.returncode != 0:
        fail(f"scsi_debug failed: {r.stderr.strip()}")
    new = None
    for _ in range(30):
        extra = scsi_disks() - before_disks
        if extra:
            new = sorted(extra)[0]
            break
        time.sleep(0.5)
    if new is None:
        fail("scsi_debug disk never appeared")
    dev = f"/dev/{new}"
    model = os.path.join("/sys/block", new, "device", "model")
    try:
        with open(model) as fh:
            if "scsi_debug" not in fh.read():
                fail(f"{dev} is not the scsi_debug disk")
    except OSError:
        fail(f"{dev} has no model file")
    workload["disk"] = dev
    rd = sh(["dd", f"if={dev}", "of=/dev/null", "bs=64k",
             "count=8", "iflag=direct"])
    if rd.returncode != 0:
        fail(f"disk read failed: {rd.stderr.strip()[-200:]}")
    wr = sh(["dd", "if=/dev/zero", f"of={dev}", "bs=64k",
             "count=8", "oflag=direct"])
    if wr.returncode != 0:
        fail(f"disk write failed: {wr.stderr.strip()[-200:]}")
    workload["disk_bytes"] = 2 * 8 * 65536
    remove_scsi_debug(new)
    workload["end_ns"] = mono_ns()
    phases["io"].append(workload["end_ns"])
    try:
        rc = rec.wait(timeout=180)
    except subprocess.TimeoutExpired:
        rec.kill()
        rec.wait()
        fail("record did not exit: " + tail())
    workload["detach_ns"] = mono_ns()
    time.sleep(2)
    workload["used_after"] = gate.io_tlb_samples()
    gate.write_json("record.json", {"exit": rc, "ready": ready})
    gate.write_json("workload.json", workload)
    rep = sh([bundle_bin, "report", "--format", "json", cap])
    report_path = os.path.join(gate.work, "report.json")
    with open(report_path, "w") as fh:
        fh.write(rep.stdout)
    try:
        with open(report_path) as fh:
            json.load(fh)
    except ValueError:
        fail("extracted report emitted invalid JSON")
    for name in ("session.json", "events.ndjson"):
        src = os.path.join(cap, name)
        if not os.path.isfile(src):
            fail(f"capture lacks {name}")
        shutil.copyfile(
            src, os.path.join(gate.work, "cap-" + name))
    gate.write_json("bundle.json", {
        "tarball": tarball_name,
        "tarball_sha": tarball_sha,
        "manifest_sha": manifest_sha,
        "files_verified": files_verified,
        "verified": True,
        "bin_sha": sha_file(bundle_bin),
        "attempt_sha": sha_file(bundle_objs["attempt"]),
        "lc_sha": sha_file(bundle_objs["lc"]),
        "cp_sha": sha_file(bundle_objs["cp"]),
        "libgcc_sha": sha_file(libgcc),
        "report_exit": rep.returncode,
        "phases": phases,
        "console_tail": (ready + "\n" + tail())[-2048:],
    })
    gate.export(["identity.json", "record.json",
                 "cap-session.json", "cap-events.ndjson",
                 "o-oracle.log", "f-oracle.log",
                 "workload.json", "bundle.json", "report.json"])
    print(f"guest_lifecycle: bundle exported record_exit={rc} "
          f"report_exit={rep.returncode}")


def run_faults(gate):
    """Multi-channel faults: rollback, teardown, busy, race.

    Seven scenarios in one boot: truncated lc/cp objects must
    refuse with exit 3 and zero BPF residue; SIGTERM mid-capture
    (1ch and 3ch) must stop bounded with a signal end reason,
    with a cut oracle snapshot proving the flood was mid-flight;
    a full output filesystem must publish an honest error
    session; paced and burst 300-op floods compare
    1ch against 3ch capture; background flood during attach must
    not leak pre-window records. The faults.json ledger carries
    every scenario's exit, stderr tail, BPF inventory pair, and
    the seconds waited for kernel-deferred map IDs to settle.
    """
    # Sealed inputs, bound and re-hashed by the faults
    # preflight: the verified record binary, the attempt
    # object, and the guest-matched profile. The lifecycle
    # and copy objects ride on the gate (sealed there too).
    memveil = gate.faults_bin
    attempt_obj = gate.faults_attempt
    profile = gate.faults_profile
    profiles_dir = gate.faults_profiles_dir
    gate.write_json("identity.json", gate.identity())
    shutil.copyfile(profile,
                    os.path.join(gate.work, "profile.json"))
    ledger = []
    names = ["identity.json", "profile.json"]

    def trunc(src, tag):
        with open(src, "rb") as fh:
            head = fh.read(4096)
        dst = os.path.join(gate.work, f"bad-{tag}.o")
        with open(dst, "wb") as fh:
            fh.write(head)
        return dst

    def run_refused(tag, lc_obj, cp_obj):
        before = gate.bpf_inventory()
        cap = os.path.join(gate.work, f"{tag}-cap")
        try:
            r = sh([memveil, "record",
                    "--duration", "10",
                    "--output", cap,
                    "--object", attempt_obj,
                    "--lc-object", lc_obj,
                    "--cp-object", cp_obj,
                    "--profile", profile,
                    "--profiles-dir", profiles_dir,
                    "--capability",
                    "attempt-trace,mapping-lifecycle,copy-actual"],
                   timeout=60)
        except subprocess.TimeoutExpired:
            fail(f"{tag}: refused run hung")
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
        cap = output or os.path.join(gate.work, f"{tag}-cap")
        args = [memveil, "record",
                "--duration", str(duration),
                "--output", cap,
                "--object", attempt_obj,
                "--profile", profile,
                "--profiles-dir", profiles_dir]
        if caps != ("attempt-trace",):
            args += ["--lc-object", gate.lc_obj,
                     "--cp-object", gate.cp_obj,
                     "--capability", ",".join(caps)]
        rec = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(
                gate.work, f"{tag}-record.stderr"), "wb"),
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        ready, _ = await_record_ready(
            rec, gate.work, f"{tag}-record.stderr")
        return rec, cap, ready

    def finish_capture(tag, rec, cap, ready):
        try:
            rc = rec.wait(timeout=240)
        except subprocess.TimeoutExpired:
            rec.kill()
            rec.wait()
            fail(f"{tag}: record did not exit")
        gate.write_json(f"{tag}-record.json",
                        {"exit": rc, "ready": ready})
        for name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
            if not os.path.isfile(src):
                fail(f"{tag}: capture lacks {name}")
            shutil.copyfile(
                src, os.path.join(gate.work, f"{tag}-{name}"))

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
                      ("f3b", ("attempt-trace", "mapping-lifecycle",
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
            fail(f"{tag}: SIGTERM did not stop record")
        gate.oracle_log(f"{tag}-cut-oracle.log")
        try:
            _, err = flood.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            flood.kill()
            flood.communicate()
            fail(f"{tag}: oracle flood hung")
        gate.consumers.remove(flood)
        if flood.returncode != 0:
            fail(f"{tag}: insmod failed: {err.strip()[-300:]}")
        gate.oracle_loaded = True
        gate.rmmod()
        gate.oracle_log(f"{tag}-oracle.log")
        gate.write_json(f"{tag}-record.json",
                        {"exit": rc, "ready": ready})
        for name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
            if not os.path.isfile(src):
                fail(f"{tag}: capture lacks {name}")
            shutil.copyfile(
                src, os.path.join(gate.work, f"{tag}-{name}"))
        record_ledger(tag, rec, before, {"window": window})
        names += [f"{tag}-record.json", f"{tag}-session.json",
                  f"{tag}-events.ndjson", f"{tag}-oracle.log",
                  f"{tag}-cut-oracle.log"]

    rep = sh([memveil, "report", "--format", "json",
              os.path.join(gate.work, "f3b-cap")])
    with open(os.path.join(gate.work, "f3b-report.json"),
              "w") as fh:
        fh.write(rep.stdout)
    try:
        with open(os.path.join(gate.work, "f3b-report.json")) as fh:
            json.load(fh)
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
    names.append("f3b-report.json")

    # f4: mid-capture fullness. The filesystem admits
    # the writer's pre-readiness reserve plus headroom,
    # and the filler grows only AFTER the ready line
    # proves the reserve landed and capture started:
    # ENOSPC must strike mid-capture (honest exit 1,
    # events kept), never pre-readiness (exit 3
    # refusal, no capture). The ready line is
    # program-order proof: the product prints it after
    # the reserve fallocate, attach, and baseline
    # append, and the fill below runs strictly after
    # this call returns that line.
    mnt = os.path.join(gate.work, "full")
    os.makedirs(mnt)
    r = sh(["mount", "-t", "tmpfs", "-o",
            f"size={f4_fs_bytes() // 1024}k",
            "memveil-full", mnt])
    if r.returncode != 0:
        fail(f"tmpfs mount failed: {r.stderr.strip()}")
    try:
        before = gate.bpf_inventory()
        gate.clear_dmesg()
        cap = os.path.join(mnt, "cap")
        rec = subprocess.Popen(
            [memveil, "record",
             "--duration", "30",
             "--output", cap,
             "--object", attempt_obj,
             "--lc-object", gate.lc_obj,
             "--cp-object", gate.cp_obj,
             "--profile", profile,
             "--profiles-dir", profiles_dir,
             "--capability",
             "attempt-trace,mapping-lifecycle,copy-actual"],
            stdout=subprocess.PIPE,
            stderr=open(os.path.join(gate.work,
                                     "f4-record.stderr"), "wb"),
            text=True,
            bufsize=1,
            start_new_session=True,
        )
        ready, _ = await_record_ready(
            rec, gate.work, "f4-record.stderr",
            allow_refusal=False)
        fill_to_full(os.path.join(mnt, "filler"))
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
        done = drain_done_line(rec)
        gate.oracle_log("f4-oracle.log")
        with open(os.path.join(gate.work, "f4-record.stderr"),
                  "rb") as fh:
            err = fh.read()[-512:].decode("utf-8", "replace")
        after, settle = gate.settled_inventory(before)
        for name in ("session.json", "events.ndjson"):
            src = os.path.join(cap, name)
            if not os.path.isfile(src):
                fail(f"f4: capture lacks {name}")
            shutil.copyfile(
                src, os.path.join(gate.work, "f4-" + name))
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
            "done": done,
        })
        names += ["f4-oracle.log", "f4-session.json",
                  "f4-events.ndjson"]
    finally:
        r = sh(["umount", mnt])
        if r.returncode != 0:
            fail(f"tmpfs umount failed: {r.stderr.strip()}")

    floods = (("f5a", ("attempt-trace",),
               ["mv_oracle_ops=300", "mv_oracle_delay_ms=100"],
               45),
              ("f5b", ("attempt-trace", "mapping-lifecycle",
                      "copy-actual"),
               ["mv_oracle_ops=300", "mv_oracle_delay_ms=100"],
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
        gate.oracle_log(f"{tag}-oracle.log")
        finish_capture(tag, rec, cap, ready)
        record_ledger(tag, rec, before, {"window": window})
        names += [f"{tag}-record.json", f"{tag}-session.json",
                  f"{tag}-events.ndjson", f"{tag}-oracle.log"]

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
    names += ["f6-record.json", "f6-session.json",
              "f6-events.ndjson", "f6-oracle.log"]

    gate.write_json("faults.json", ledger)
    names.append("faults.json")
    gate.export(names)
    print("guest_lifecycle: faults exported")


def run_overhead(gate):
    """Live-overhead campaign; implementation in overhead_guest."""
    from overhead_guest import run_overhead as impl
    return impl(gate)


def run_overhead_probe(gate):
    """Live-overhead fail-fast probe; see overhead_guest."""
    from overhead_guest import run_overhead_probe as impl
    return impl(gate)


def run_races(gate):
    """Concurrent map/unmap flood: pairing honesty under reuse.

    Phase 1 runs scripted oracle ops alone (exact host-side
    expectations). Phase 2 overlaps paced oracle ops with one
    direct-read dd leg per vCPU on an owned scsi_debug disk
    while bpftrace counts the attach points and block stats
    prove the load flowed. Needs 2+ vCPUs: single-CPU guests
    cannot race the generation table.
    """
    import concurrent.futures

    ncpu = os.cpu_count() or 0
    if ncpu < 2:
        fail("races gate needs 2+ vCPUs, have %d" % ncpu)
    if shutil.which("bpftrace") is None:
        fail("bpftrace not available")
    gate.write_json("identity.json", gate.identity())
    gate.clear_dmesg()
    lc1 = os.path.join(gate.work, "p1-lc.txt")
    cp1 = os.path.join(gate.work, "p1-cp.txt")
    plc = gate.start_consumer(
        gate.lc_obj, "mv_lifecycle", LC_SITES, 120, lc1)
    pcp = gate.start_consumer(
        gate.cp_obj, "mv_copies", CP_SITES, 120, cp1)
    gate.wait_ready(("mv_map_result", "mv_bounce"))
    gate.insmod(["mv_oracle_ops=200"])
    time.sleep(5)
    gate.rmmod()
    gate.wait_consumer(plc, "races-p1-lc")
    gate.wait_consumer(pcp, "races-p1-cp")
    gate.oracle_log("p1-oracle.log")
    before_disks = scsi_disks()
    if os.path.exists("/sys/module/scsi_debug"):
        fail("scsi_debug already exists; no fixture ownership")
    r = sh(["modprobe", "scsi_debug", "dev_size_mb=256"])
    if r.returncode != 0:
        fail("scsi_debug failed: %s" % r.stderr.strip())
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
    with open(os.path.join("/sys/block", short, "device",
                           "model")) as fh:
        if "scsi_debug" not in fh.read():
            fail("new races disk is not owned scsi_debug")
    try:
        lc2 = os.path.join(gate.work, "p2-lc.txt")
        cp2 = os.path.join(gate.work, "p2-cp.txt")
        plc = gate.start_consumer(
            gate.lc_obj, "mv_lifecycle", LC_SITES, 300, lc2)
        pcp = gate.start_consumer(
            gate.cp_obj, "mv_copies", CP_SITES, 300, cp2)
        gate.wait_ready(("mv_map_result", "mv_bounce"))
        bpf_out = open(os.path.join(gate.work, "bpftrace.txt"),
                       "w")
        bpf_err = open(os.path.join(gate.work, "bpftrace.stderr"),
                       "w")
        bprog = ("fentry:swiotlb_tbl_map_single "
                 "{ @maps = count(); } "
                 "fentry:__swiotlb_tbl_unmap_single "
                 "{ @unmaps = count(); } "
                 "fentry:swiotlb_bounce { @bounces = count(); }")
        bpf = subprocess.Popen(
            ["bpftrace", "-q", "-e", bprog],
            stdout=bpf_out, stderr=bpf_err,
            start_new_session=True)
        time.sleep(3)
        if bpf.poll() is not None:
            bpf_out.close()
            bpf_err.close()
            fail("bpftrace exited early; attach points unavailable?")
        stats0 = block_stat(short)
        # Legs first: insmod blocks for its paced ops, so the
        # flood is already in flight when oracle traffic starts.
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=ncpu) as pool:
            futs = {pool.submit(dd_flood_leg, disk, 128): i
                    for i in range(ncpu)}
            gate.insmod(["mv_oracle_ops=2000",
                         "mv_oracle_delay_ms=10"])
            legs = {}
            for fut in concurrent.futures.as_completed(futs):
                legs["cpu%d" % futs[fut]] = fut.result()
        stats1 = block_stat(short)
        bpf.send_signal(signal.SIGINT)
        try:
            bpf.wait(timeout=30)
        except subprocess.TimeoutExpired:
            bpf.kill()
            bpf.wait()
        bpf_out.close()
        bpf_err.close()
        if stats1["read_ios"] <= stats0["read_ios"]:
            fail("flood produced no block reads")
        gate.rmmod()
        gate.wait_consumer(plc, "races-p2-lc", timeout=300)
        gate.wait_consumer(pcp, "races-p2-cp", timeout=300)
        gate.oracle_log("p2-oracle.log")
        gate.write_json("dd.json", legs)
        gate.write_json("blockstats.json",
                        {"before": stats0, "after": stats1})
    finally:
        remove_scsi_debug(short)
    gate.export(["identity.json", "p1-lc.txt", "p1-cp.txt",
                 "p1-oracle.log", "p2-lc.txt", "p2-cp.txt",
                 "p2-oracle.log", "bpftrace.txt",
                 "bpftrace.stderr", "dd.json",
                 "blockstats.json"])
    print("guest_lifecycle: races exported")


SUBS = {
    "matrix": run_matrix,
    "races": run_races,
    "copy": run_copy,
    "realio": run_realio,
    "stop": run_stop,
    "saturation": run_saturation,
    "cleanup": run_cleanup,
    "perf": run_perf,
    "oracle": run_oracle,
    "witness": run_witness,
    "canonical": run_canonical,
    "record3": run_record3,
    "topwalk": run_topwalk,
    "bundle": run_bundle,
    "faults": run_faults,
    "overhead": run_overhead,
    "overhead-probe": run_overhead_probe,
}


def main():
    if len(sys.argv) != 5:
        print("usage: guest_lifecycle.py SUB WORK EXPORT REPO",
              file=sys.stderr)
        return 2
    sub, work, export, repo = sys.argv[1:5]
    if sub not in SUBS:
        fail(f"bad subcommand {sub}")
    gate = Gate(sub, work, export, repo)
    try:
        SUBS[sub](gate)
    finally:
        # Only handles launched by this guest are owned here.
        for proc in gate.consumers:
            if proc.poll() is None:
                proc.kill()
                proc.communicate()
        if gate.oracle_loaded:
            sh(["rmmod", "memveil_dma_oracle"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
