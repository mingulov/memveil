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
            "mv_bounce:swiotlb_bounce")


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


def validate_victim(alive, rc):
    if alive is not True or rc != -signal.SIGTERM:
        raise ValueError("victim was not alive or did not terminate by SIGTERM")


def dmesg_after_marker(text, marker):
    lines = text.splitlines()
    hits = [i for i, line in enumerate(lines) if marker in line]
    if len(hits) != 1:
        raise ValueError("dmesg boundary missing/duplicated; wrap or corruption")
    return lines[hits[0] + 1:]


class Gate:
    """One subcommand run: paths, checks, consumer control."""

    def __init__(self, sub, work, export, repo):
        self.sub = sub
        self.work = work
        self.export_dir = export
        self.repo = repo
        self.consume = os.path.join(repo, "build", "vm", "mv_consume")
        self.bridge = os.path.join(
            repo, "build", "deps", "lmb", "lib", "libbpf_mojo.so.1")
        self.lc_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_lifecycle.bpf.o")
        self.cp_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_copy.bpf.o")
        self.lc_test_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_lifecycle-test.bpf.o")
        self.consumers = []
        self.oracle_loaded = False
        self.cp_test_obj = os.path.join(
            repo, "build", "bpf", "swiotlb_copy-test.bpf.o")
        self.ko = os.path.join(
            repo, "build", "vm", "oracle", "memveil_dma_oracle.ko")
        if os.geteuid() != 0:
            fail("guest flow requires root")
        os.makedirs(work, exist_ok=True)
        os.makedirs(export, exist_ok=True)
        for path in (self.consume, self.bridge, self.lc_obj,
                     self.cp_obj, self.ko):
            if not os.path.isfile(path):
                fail(f"missing {path}")
        if os.path.exists("/sys/module/memveil_dma_oracle"):
            fail("oracle module already exists; no ownership")
        with open("/proc/cmdline") as fh:
            if "swiotlb=force" not in fh.read():
                fail("guest lacks swiotlb=force")

    def identity(self):
        release = os.uname().release
        with open("/proc/cmdline") as fh:
            cmdline = fh.read().strip()
        from lifecycle_env import module_build_identity
        config_btf = module_build_identity()
        return {"release": release, "swiotlb_force": "swiotlb=force" in cmdline,
                "config_sha": config_btf["config_sha"], "btf_sha": config_btf["btf_sha"],
                "bridge_sha": sha_file(self.bridge),
                "consume_sha": sha_file(self.consume),
                "lc_sha": sha_file(self.lc_test_obj if self.sub == "saturation" else self.lc_obj),
                "cp_sha": sha_file(self.cp_test_obj if self.sub == "saturation" else self.cp_obj),
                "ko_sha": sha_file(self.ko)}

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
    with open(os.path.join("/sys/block", new, "device",
                           "delete"), "w") as fh:
        fh.write("1")
    r = sh(["rmmod", "scsi_debug"])
    if r.returncode != 0:
        fail(f"scsi_debug rmmod failed: {r.stderr.strip()}")
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
    with open(os.path.join("/sys/block", short, "device",
                           "delete"), "w") as fh:
        fh.write("1")
    r = sh(["rmmod", "scsi_debug"])
    if r.returncode != 0:
        fail(f"scsi_debug rmmod failed: {r.stderr.strip()}")
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


def await_record_ready(rec, work, errname="record.stderr"):
    """Wait for the record readiness line; fail with stderr tail."""
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
    if ready is None:
        try:
            rec.kill()
        except OSError:
            pass
        fail("record never reached readiness: " + tail())
    return ready, tail


def run_bundle(gate):
    """Shipped bundle, three phases, extracted-binary report.

    Extracts dist/memveil-0.1.0.tar.gz, verifies every file
    against MANIFEST.json (no symlinks, exact set, exact
    hashes), and runs the extracted record with all three
    channels through oracle-exact, outer-failure, and
    block+vnet phases in one capture. The extracted report
    renders the capture; bundle.json retains phases, hashes,
    and the console tail.
    """
    tarball = os.path.join(gate.repo, "dist",
                           "memveil-0.1.0.tar.gz")
    profile = os.path.join(
        gate.repo, "build", "vm", "record3-profile.json")
    for path in (tarball, profile):
        if not os.path.isfile(path):
            fail(f"missing {path}")
    gate.write_json("identity.json", gate.identity())
    extract = os.path.join(gate.work, "extract")
    os.makedirs(extract)
    r = sh(["tar", "xzf", tarball, "-C", extract])
    if r.returncode != 0:
        fail(f"bundle extract failed: {r.stderr.strip()[-200:]}")
    root = os.path.join(extract, "memveil-0.1.0")
    manifest = verify_extracted_bundle(root)
    bundle_bin = os.path.join(root, "bin", "memveil")
    bundle_bridge = os.path.join(root, "lib", "libbpf_mojo.so.1")
    bundle_objs = {
        "attempt": os.path.join(root, "bpf",
                                "swiotlb_attempt.bpf.o"),
        "lc": os.path.join(root, "bpf",
                           "swiotlb_lifecycle.bpf.o"),
        "cp": os.path.join(root, "bpf", "swiotlb_copy.bpf.o"),
    }
    build_objs = {
        "attempt": os.path.join(
            gate.repo, "build", "bpf", "swiotlb_attempt.bpf.o"),
        "lc": gate.lc_obj,
        "cp": gate.cp_obj,
    }
    for key in ("attempt", "lc", "cp"):
        if sha_file(bundle_objs[key]) != sha_file(
                build_objs[key]):
            fail(f"bundle {key} object differs from build")
    iface = find_pcnet()
    configure_net(iface)
    gate.write_json("identity.json",
                    dict(gate.identity(), iface=iface))
    before_disks = scsi_disks()
    used_before = gate.io_tlb_samples()
    cap = os.path.join(gate.work, "cap")
    rec = subprocess.Popen(
        [bundle_bin, "record",
         "--duration", "150",
         "--output", cap,
         "--object", bundle_objs["attempt"],
         "--lc-object", bundle_objs["lc"],
         "--cp-object", bundle_objs["cp"],
         "--bridge", bundle_bridge,
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
    # not flood absorption (burst overrun under the rotating
    # poll quantum is F2-7's sparse-channel-busy subject).
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
    with open(os.path.join("/sys/block", new, "device",
                           "delete"), "w") as fh:
        fh.write("1")
    r = sh(["rmmod", "scsi_debug"])
    if r.returncode != 0:
        fail(f"scsi_debug rmmod failed: {r.stderr.strip()}")
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
        "tarball": "memveil-0.1.0.tar.gz",
        "tarball_sha": sha_file(tarball),
        "manifest_sha": sha_file(
            os.path.join(root, "MANIFEST.json")),
        "files_verified": len(manifest["files"]),
        "verified": True,
        "bin_sha": sha_file(bundle_bin),
        "attempt_sha": sha_file(bundle_objs["attempt"]),
        "lc_sha": sha_file(bundle_objs["lc"]),
        "cp_sha": sha_file(bundle_objs["cp"]),
        "bridge_sha": sha_file(bundle_bridge),
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
    a full output filesystem must fail honestly without a
    masquerading session; paced and burst 300-op floods compare
    1ch against 3ch capture; background flood during attach must
    not leak pre-window records. The faults.json ledger carries
    every scenario's exit, stderr tail, BPF inventory pair, and
    the seconds waited for kernel-deferred map IDs to settle.
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
    ledger = []
    names = ["identity.json"]

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
                    "--bridge", gate.bridge,
                    "--profile", profile,
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
                "--bridge", gate.bridge,
                "--profile", profile]
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

    mnt = os.path.join(gate.work, "full")
    os.makedirs(mnt)
    r = sh(["mount", "-t", "tmpfs", "-o", "size=64k",
            "memveil-full", mnt])
    if r.returncode != 0:
        fail(f"tmpfs mount failed: {r.stderr.strip()}")
    try:
        with open(os.path.join(mnt, "filler"), "wb") as fh:
            fh.write(b"x" * 57344)
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
             "--bridge", gate.bridge,
             "--profile", profile,
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
                  "rb") as fh:
            err = fh.read()[-512:].decode("utf-8", "replace")
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
        names.append("f4-oracle.log")
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


SUBS = {
    "matrix": run_matrix,
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
    "bundle": run_bundle,
    "faults": run_faults,
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
