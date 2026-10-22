#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kernel matrix guest flow: doctor, oracle, workload, record, report.

Runs as root inside the virtme-ng guest (one boot per kernel).
Reads /tmp/export/job.json written by tools/kernel-matrix, writes
all evidence to /tmp/mv then copies to /tmp/export. Every refusal
aborts FAIL (exit 1), never skip: the host decides pass/fail from
the exported files.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

TR = "/sys/kernel/tracing"
EVT = TR + "/events/swiotlb/swiotlb_bounced"
FILTER_FUNCS = "/sys/kernel/tracing/available_filter_functions"

WANT_FUNCS = {
    "map": "swiotlb_tbl_map_single",
    "unmap": "__swiotlb_tbl_unmap_single",
    "copy": "swiotlb_bounce",
    "syncc": "__swiotlb_sync_single_for_cpu",
    "syncd": "__swiotlb_sync_single_for_device",
}

BPF_OBJECTS = (("attempt", "swiotlb_attempt.bpf.o"),
               ("lifecycle", "swiotlb_lifecycle.bpf.o"),
               ("copy", "swiotlb_copy.bpf.o"))

_OUT = "/tmp/mv"
_EXPORT = "/tmp/export"
_KM = None


def copy_out():
    try:
        out, export = _OUT, _EXPORT
        if not os.path.isdir(out) or not os.path.isdir(export):
            return
        for name in sorted(os.listdir(out)):
            src = os.path.join(out, name)
            dst = os.path.join(export, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                try:
                    shutil.copy2(src, dst)
                except OSError:
                    pass
        # Exported copies read world-wide; /tmp/mv keeps strict modes.
        proc = subprocess.run(["chmod", "-R", "a+rX", export],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            print("guest: chmod export failed: %s"
                  % (proc.stderr or "").strip(), file=sys.stderr)
    except Exception:
        pass


def fail(msg):
    print("guest: FAIL: %s" % msg, file=sys.stderr)
    try:
        Path(_OUT, "FAIL.txt").write_text(msg + "\n")
    except OSError:
        pass
    if _KM is not None:
        export_dmesg(_KM, _OUT, fatal=False)
    copy_out()
    sys.exit(1)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True, **kw)


def write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(data)


def find_nvme():
    proc = sh(["lsblk", "-ndo", "NAME,TYPE"])
    if proc.returncode != 0:
        return None
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].startswith("nvme") \
                and parts[1] == "disk":
            return "/dev/" + parts[0]
    return None


def detect_hooks():
    present = {}
    present["tp"] = os.path.isdir(EVT)
    try:
        funcs = Path(FILTER_FUNCS).read_text().splitlines()
    except OSError:
        funcs = None
    for key, func in WANT_FUNCS.items():
        if funcs is None:
            present[key] = False
        else:
            present[key] = func in funcs
    omitted = [key for key, ok in present.items() if not ok]
    return present, omitted


def first_line(proc):
    for line in (proc.stdout or "").splitlines():
        if line.strip():
            return line.strip()
    return ""


def record_artifacts(km, out, mv, mode):
    bpf = {}
    if mode == "deb":
        roots = ["/usr/lib/memveil"]
    else:
        roots = [os.path.join(os.path.dirname(mv), "..", "lib",
                              "memveil"),
                 os.path.dirname(mv)]
    for key, name in BPF_OBJECTS:
        found = None
        for root in roots:
            cand = os.path.join(root, name)
            if os.path.isfile(cand):
                found = cand
                break
        if not found:
            fail("bpf object missing: %s" % name)
        bpf[key] = km.sha_file(found)
    dpkg_version = ""
    if mode == "deb":
        proc = sh(["dpkg-query", "-W", "-f=${Version}", "memveil"])
        dpkg_version = (proc.stdout or "").strip()
        if proc.returncode != 0 or not dpkg_version:
            fail("dpkg-query for memveil failed")
    bpftrace = sh(["bpftrace", "--version"])
    bpftool = sh(["bpftool", "--version"])
    if not first_line(bpftrace) or not first_line(bpftool):
        fail("bpftrace or bpftool version unreadable")
    write(os.path.join(out, "artifacts.json"), json.dumps(
        {"mode": mode, "binary": {"path": mv,
                                 "sha256": km.sha_file(mv)},
         "dpkg_version": dpkg_version, "bpf": bpf,
         "bpftrace": first_line(bpftrace),
         "bpftool": first_line(bpftool)},
        indent=2, sort_keys=True) + "\n")


def mark_dmesg(km):
    try:
        with open("/dev/kmsg", "w") as handle:
            handle.write("<6>" + km.DMESG_MARKER + "\n")
    except OSError as exc:
        fail("cannot mark dmesg: %s" % exc)


def export_dmesg(km, out, fatal=True):
    try:
        proc = sh(["dmesg"])
        if proc.returncode != 0:
            raise OSError("dmesg unavailable")
        raw = proc.stdout or ""
        write(os.path.join(out, "dmesg.txt"), km.redact_dmesg(raw))
        present, count = km.scan_dmesg(raw, km.DMESG_MARKER)
        write(os.path.join(out, "dmesg_scan.json"), json.dumps(
            {"marker": km.DMESG_MARKER, "marker_present": present,
             "suspicious": count}, indent=2, sort_keys=True) + "\n")
    except Exception:
        if fatal:
            fail("dmesg unavailable")


def snapshot_progs(out, idx):
    stamp = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    proc = sh(["bpftool", "prog", "show", "--json"], timeout=60)
    if proc.returncode != 0:
        fail("bpftool snapshot %d failed" % idx)
    write(os.path.join(out, "progs%d.json" % idx),
          proc.stdout or "")
    return stamp


def wait_ready(out, proc, timeout_s=120):
    path = os.path.join(out, "record.out")
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        try:
            if "ready session=" in Path(path).read_text():
                return True
        except OSError:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.2)
    return None


def run_dd(dev, dd_count):
    return sh(["dd", "if=" + dev, "of=/dev/null", "bs=1M",
               "count=%d" % dd_count, "iflag=direct",
               "status=none"], timeout=300)


def run(argv):
    export, repo = argv[1], argv[2]
    global _OUT, _EXPORT
    _EXPORT = export
    job_path = os.path.join(export, "job.json")
    try:
        job = json.loads(Path(job_path).read_text())
    except (OSError, ValueError) as exc:
        fail("unreadable job.json: %s" % exc)
    out = "/tmp/mv"
    _OUT = out
    shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    admitted = job.get("admitted", [])
    duration = int(job.get("duration", 60))
    dd_count = int(job.get("dd_count", 128))
    deb = job.get("deb")
    bundle = job.get("bundle")
    sys.path.insert(0, os.path.join(repo, "tests", "vm"))
    try:
        import kernel_matrix as km
    except ImportError as exc:
        fail("cannot import kernel_matrix: %s" % exc)
    global _KM
    _KM = km
    mv = None
    mode = None
    if deb:
        proc = sh(["dpkg", "-i", deb])
        write(os.path.join(out, "dpkg.out"),
              (proc.stdout or "") + (proc.stderr or ""))
        write(os.path.join(out, "dpkg.exit"), str(proc.returncode))
        if proc.returncode != 0:
            fail("dpkg -i failed exit %d" % proc.returncode)
        mv = shutil.which("memveil") or "/usr/bin/memveil"
        mode = "deb"
    elif bundle:
        mv = bundle
        mode = "bundle"
    else:
        fail("job needs deb or bundle")
    if not mv or not os.path.isfile(mv):
        fail("memveil binary missing: %r" % mv)
    record_artifacts(km, out, mv, mode)
    release = os.uname().release
    write(os.path.join(out, "uname.txt"),
          release + "\n" + Path("/proc/cmdline").read_text())
    try:
        mods = os.readlink("/lib/modules/" + release)
        mods_path = os.path.join("/lib/modules", release, mods) \
            if not os.path.isabs(mods) else mods
    except OSError:
        mods_path = "/lib/modules/" + release
    if not os.path.isdir(mods_path):
        fail("guest modules dir missing: %s" % mods_path)
    write(os.path.join(out, "mods.txt"),
          release + "\n" + mods_path + "\n")
    subprocess.run(["mount", "-t", "debugfs", "none",
                    "/sys/kernel/debug"],
                   capture_output=True)
    proc = sh([mv, "doctor", "--json"])
    write(os.path.join(out, "doctor.json"), proc.stdout or "")
    write(os.path.join(out, "doctor.stderr"), proc.stderr or "")
    write(os.path.join(out, "doctor.exit"), str(proc.returncode))
    present, omitted = detect_hooks()
    write(os.path.join(out, "hooks.json"),
          json.dumps({"present": present, "omitted": omitted},
                     indent=2, sort_keys=True) + "\n")
    refused = [cap for cap in km.CAPS if cap not in admitted]
    # Mark before the refusal probes so their dmesg output is
    # scanned; the oracle automount notice matches no pattern.
    mark_dmesg(km)
    for cap in refused:
        dest = os.path.join(out, "cap-" + cap)
        proc = sh([mv, "record", "--output", dest,
                   "--duration", "5", "--capability",
                   km.refusal_probe_caps(cap)], timeout=120)
        write(os.path.join(out, "record-cap-%s.out" % cap),
              (proc.stdout or "") + (proc.stderr or ""))
        write(os.path.join(out, "record-cap-%s.exit" % cap),
              str(proc.returncode))
        write(os.path.join(out, "record-cap-%s.exists" % cap),
              "yes" if os.path.exists(dest) else "no")
    if refused:
        dest = os.path.join(out, "cap-combined")
        proc = sh([mv, "record", "--output", dest,
                   "--duration", "5", "--capability",
                   ",".join(km.CAPS)], timeout=120)
        write(os.path.join(out, "record-combined.out"),
              (proc.stdout or "") + (proc.stderr or ""))
        write(os.path.join(out, "record-combined.exit"),
              str(proc.returncode))
        write(os.path.join(out, "record-combined.exists"),
              "yes" if os.path.exists(dest) else "no")
    if not admitted:
        export_dmesg(km, out)
        print("guest: refused flow done")
        return 0
    caps = ",".join(admitted)
    dev = find_nvme()
    write(os.path.join(out, "dev.txt"), (dev or "none") + "\n")
    if not dev:
        fail("no nvme disk found")
    need = []
    if "attempt-trace" in admitted:
        need.append("tp")
    if "mapping-lifecycle" in admitted:
        need.extend(["map", "unmap"])
    if "copy-actual" in admitted:
        need.extend(["copy", "syncc", "syncd"])
    keep = [p for p in need if p not in omitted]
    if not keep:
        fail("no oracle probes for admitted caps %s (omitted %s)"
             % (admitted, omitted))
    omit_for_oracle = [p for p in ("tp", "map", "unmap", "copy",
                                   "syncc", "syncd") if p not in keep]
    prog = km.build_oracle_program(omitted=omit_for_oracle)
    write(os.path.join(out, "oracle.bt"), prog)
    write(os.path.join(out, "oracle.keep"),
          ",".join(keep) + "\n")
    oracle_out = open(os.path.join(out, "oracle.txt"), "w")
    oracle_err = open(os.path.join(out, "oracle.stderr"), "w")
    opid = subprocess.Popen(["bpftrace", "-q", "-e", prog],
                            stdout=oracle_out, stderr=oracle_err,
                            start_new_session=True)
    time.sleep(3)
    if opid.poll() is not None:
        oracle_out.close()
        oracle_err.close()
        fail("oracle exited early (missing hook not omitted?)")
    times = {}
    times[0] = snapshot_progs(out, 0)
    cap = os.path.join(out, "cap")
    record_out = open(os.path.join(out, "record.out"), "w")
    record_err = open(os.path.join(out, "record.stderr"), "w")
    rpid = subprocess.Popen([mv, "record", "--output", cap,
                             "--duration", str(duration),
                             "--capability", caps],
                            stdout=record_out, stderr=record_err,
                            start_new_session=True)
    ready = wait_ready(out, rpid)
    if ready is None:
        rpid.terminate()
        try:
            rpid.wait(timeout=10)
        except subprocess.TimeoutExpired:
            rpid.kill()
            rpid.wait()
        write(os.path.join(out, "record.exit"),
              str(rpid.returncode))
        opid.send_signal(signal.SIGINT)
        fail("record not ready in 120s")
    if ready is False:
        write(os.path.join(out, "record.exit"),
              str(rpid.returncode))
        opid.send_signal(signal.SIGINT)
        fail("record exited %d before ready; see record.stderr"
             % (rpid.returncode,))
    times[1] = snapshot_progs(out, 1)
    # Settle before the workload so edge samples bracket cleanly.
    time.sleep(4)
    base = os.path.basename(dev)
    if not base or ".." in base or "/" in base:
        fail("unexpected block device %r" % dev)
    try:
        stat_before = km.parse_blockstat(
            Path("/sys/block", base, "stat").read_text())
    except (OSError, ValueError) as exc:
        opid.send_signal(signal.SIGINT)
        rpid.terminate()
        fail("block stat unreadable: %s" % exc)
    workload_lines = []
    for i in (1, 2):
        start = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        workload_lines.append("dd%d start %d" % (i, start))
        proc = run_dd(dev, dd_count)
        end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        workload_lines.append("dd%d end %d rc=%d"
                              % (i, end, proc.returncode))
        if proc.returncode != 0:
            opid.send_signal(signal.SIGINT)
            rpid.terminate()
            fail("dd%d failed" % i)
        time.sleep(2)
    procs = []
    par_start = []
    for _ in range(4):
        par_start.append(
            time.clock_gettime_ns(time.CLOCK_MONOTONIC))
        procs.append(subprocess.Popen(
            ["dd", "if=" + dev, "of=/dev/null", "bs=1M",
             "count=%d" % dd_count, "iflag=direct",
             "status=none"]))
    for i, proc in enumerate(procs):
        proc.wait(timeout=300)
        end = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
        workload_lines.append("par%d start %d" % (i, par_start[i]))
        workload_lines.append("par%d end %d rc=%d"
                              % (i, end, proc.returncode))
        if proc.returncode != 0:
            opid.send_signal(signal.SIGINT)
            rpid.terminate()
            fail("parallel dd%d failed" % i)
    write(os.path.join(out, "workload.txt"),
          "\n".join(workload_lines) + "\n")
    try:
        stat_after = km.parse_blockstat(
            Path("/sys/block", base, "stat").read_text())
    except (OSError, ValueError) as exc:
        opid.send_signal(signal.SIGINT)
        rpid.terminate()
        fail("block stat unreadable: %s" % exc)
    write(os.path.join(out, "blockstat.json"), json.dumps(
        {"dev": base, "before": stat_before, "after": stat_after},
        indent=2, sort_keys=True) + "\n")
    times[2] = snapshot_progs(out, 2)
    try:
        rpid.wait(timeout=duration + 120)
    except subprocess.TimeoutExpired:
        rpid.kill()
        rpid.wait()
        write(os.path.join(out, "record.exit"),
              str(rpid.returncode))
        opid.send_signal(signal.SIGINT)
        fail("record did not exit")
    record_out.close()
    record_err.close()
    write(os.path.join(out, "record.exit"), str(rpid.returncode))
    times[3] = snapshot_progs(out, 3)
    write(os.path.join(out, "progs_times.json"),
          json.dumps({str(k): v for k, v in sorted(times.items())},
                     indent=2, sort_keys=True) + "\n")
    time.sleep(2)
    opid.send_signal(signal.SIGINT)
    try:
        opid.wait(timeout=30)
    except subprocess.TimeoutExpired:
        opid.kill()
        fail("oracle did not stop")
    oracle_out.close()
    oracle_err.close()
    proc = sh([mv, "report", "--max-events-bytes", "4294967296", cap],
              timeout=120)
    write(os.path.join(out, "report.out"), proc.stdout or "")
    write(os.path.join(out, "report.stderr"), proc.stderr or "")
    write(os.path.join(out, "report.exit"), str(proc.returncode))
    proc = sh([mv, "report", "--format", "json",
               "--max-events-bytes", "4294967296", cap], timeout=120)
    write(os.path.join(out, "report.json"), proc.stdout or "")
    write(os.path.join(out, "report-json.stderr"), proc.stderr or "")
    write(os.path.join(out, "report-json.exit"), str(proc.returncode))
    export_dmesg(km, out)
    print("guest: admitted flow done caps=%s" % caps)
    return 0


def main():
    if len(sys.argv) != 3:
        print("usage: kernel_matrix_guest.py EXPORT REPO",
              file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        fail("guest requires root")
    try:
        return run(sys.argv)
    except subprocess.TimeoutExpired as exc:
        fail("timed out: %s" % exc)
    finally:
        copy_out()


if __name__ == "__main__":
    sys.exit(main())
