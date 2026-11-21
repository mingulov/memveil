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
"""

import concurrent.futures
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


def fail(msg):
    """Abort the guest flow; the host judges this failed."""
    print("stress-guest: FAIL: %s" % msg, file=sys.stderr)
    sys.exit(1)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


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
             "count=%d" % count, "iflag=direct"])
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
        self.work = work
        self.export_dir = export
        self.consume = args.consumer
        self.ko = args.ko
        self.pairs = {
            "baseline": {"lc": args.baseline_lc, "cp": args.baseline_cp,
                         "lc_sha": args.baseline_lc_sha,
                         "cp_sha": args.baseline_cp_sha},
            "c9": {"lc": args.c9_lc, "cp": args.c9_cp,
                   "lc_sha": args.c9_lc_sha, "cp_sha": args.c9_cp_sha},
        }
        self.consumer_sha = args.consumer_sha
        self.manifest = json.loads(open(args.manifest).read())
        self.consumers = []
        self.oracle_loaded = False
        if os.geteuid() != 0:
            fail("guest flow requires root")
        os.makedirs(work, exist_ok=True)
        os.makedirs(export, exist_ok=True)
        if os.path.exists("/sys/module/memveil_dma_oracle"):
            fail("oracle module already exists; no ownership")
        if os.path.exists("/sys/module/scsi_debug"):
            fail("scsi_debug already exists; no fixture ownership")
        with open("/proc/cmdline") as handle:
            if "swiotlb=force" not in handle.read():
                fail("guest lacks swiotlb=force")
        self.verify_inputs()

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
        self.checked = checked
        self.write_json("input-verify.json", {
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
        self.consumers.append(proc)
        return proc

    def wait_ready(self, procs, timeout=30):
        """Consume acknowledgements emitted only after attach+arm."""
        end = time.monotonic() + timeout
        pending = list(procs)
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
        fail("consumer attachment acknowledgements timed out")

    def wait_consumer(self, proc, tag, timeout=180):
        """Wait for one consumer; fail unless it exits 0."""
        try:
            out, _ = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            fail("%s: consumer did not exit" % tag)
        if proc.returncode != 0:
            fail("%s: consumer exit %d: %s"
                 % (tag, proc.returncode, out[-500:]))
        if not getattr(proc, "gate_ready", False) and "ready ring=" not in out:
            fail("%s: consumer never ready" % tag)
        return out

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
        inner = sh(["insmod", self.ko, "mv_oracle_arm=1"] + params)
        finish = mono_ns()
        if inner.returncode != 0:
            fail("insmod failed: %s" % inner.stderr.strip())
        self.oracle_loaded = True
        return {"start_ns": start, "finish_ns": finish}

    def rmmod(self):
        inner = sh(["rmmod", "memveil_dma_oracle"])
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
    gate.clear_dmesg()
    first = os.path.join(gate.work, "%s-c0a-lc.txt" % name)
    proc_a = gate.start_consumer(pair["lc"], "mv_lifecycle",
                                 LC_SITES, 8, first, family,
                                 pair["lc_sha"])
    gate.wait_ready([proc_a])
    gate.insmod(["mv_oracle_ops=2"])
    gate.wait_consumer(proc_a, tag + "-a", timeout=60)
    maps, unmaps = parse_lc_file(first)
    op0_maps = [m for m in maps if m["size"] == LC_SIZES[0] and m["gen"] != 0]
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
    held_releases = [u for u in unmaps_b if u["size"] == LC_SIZES[1]]
    if not any(u["gen"] == 0 for u in held_releases):
        fail("%s: held-across-attach release not gen 0" % tag)
    if held_gen != 0 and any(u["gen"] == held_gen for u in unmaps_b):
        fail("%s: held gen %d leaked across attach" % (tag, held_gen))
    gate.oracle_log("%s-c0-oracle.log" % name)
    gate.write_json("%s-controls.json" % name, {
        "op0_gen": gen0, "held_gen_first": held_gen,
        "held_releases": len(held_releases),
    })


def run_phase1(gate, name, pair, family):
    """200 scripted oracle ops alone (exact host expectations)."""
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


def run_phase2(gate, name, pair, family, disk, short):
    """2000 paced ops overlapped with the per-vCPU flood legs."""
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
    bpf_out = open(os.path.join(gate.work, "%s-bpftrace.txt" % name), "w")
    bpf_err = open(os.path.join(gate.work, "%s-bpftrace.stderr" % name), "w")
    bprog = ("fentry:swiotlb_tbl_map_single "
             "{ @maps = count(); } "
             "fentry:__swiotlb_tbl_unmap_single "
             "{ @unmaps = count(); } "
             "fentry:swiotlb_bounce { @bounces = count(); }")
    bpf = subprocess.Popen(
        ["bpftrace", "-q", "-e", bprog],
        stdout=bpf_out, stderr=bpf_err, start_new_session=True)
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
        for fut in concurrent.futures.as_completed(futs):
            legs["cpu%d" % futs[fut]] = fut.result()
    stats1 = block_stat(short)
    # The tracer stays up through the final release: the held
    # mapping's unmap must be counted, not cut off.
    gate.rmmod()
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
    gate.wait_consumer(plc, "%s-p2-lc" % name, timeout=300)
    gate.wait_consumer(pcp, "%s-p2-cp" % name, timeout=300)
    gate.oracle_log("%s-p2-oracle.log" % name)
    gate.write_json("%s-dd.json" % name, legs)
    gate.write_json("%s-window.json" % name, window)
    gate.write_json("%s-blockstats.json" % name,
                    {"before": stats0, "after": stats1})


def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("work")
    parser.add_argument("export")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--consumer", required=True)
    parser.add_argument("--consumer-sha", required=True)
    parser.add_argument("--ko", required=True)
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
    ncpu = os.cpu_count() or 0
    if ncpu < 2:
        fail("stress gate needs 2+ vCPUs, have %d" % ncpu)
    if shutil.which("bpftrace") is None:
        fail("bpftrace not available")
    gate.write_json("identity.json", gate.identity())
    before_disks = scsi_disks()
    inner = sh(["modprobe", "scsi_debug", "dev_size_mb=256"])
    if inner.returncode != 0:
        fail("scsi_debug failed: %s" % inner.stderr.strip())
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
        run_phase2(gate, "c9", gate.pairs["c9"], "aya", disk, short)
    finally:
        inner = sh(["rmmod", "scsi_debug"])
        if inner.returncode != 0:
            fail("scsi_debug cleanup failed: %s" % inner.stderr.strip())
    names = ["identity.json", "input-verify.json"]
    for leg in ("baseline", "c9"):
        names += ["%s-controls.json" % leg, "%s-c0a-lc.txt" % leg,
                  "%s-c0b-lc.txt" % leg, "%s-c0-oracle.log" % leg,
                  "%s-p1-lc.txt" % leg, "%s-p1-cp.txt" % leg,
                  "%s-p1-oracle.log" % leg, "%s-p2-lc.txt" % leg,
                  "%s-p2-cp.txt" % leg, "%s-p2-oracle.log" % leg,
                  "%s-bpftrace.txt" % leg, "%s-bpftrace.stderr" % leg,
                  "%s-dd.json" % leg, "%s-window.json" % leg,
                  "%s-blockstats.json" % leg]
    gate.export(names)
    print("stress-guest: both legs exported")


if __name__ == "__main__":
    main(sys.argv[1:])
