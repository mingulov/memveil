#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Kernel matrix guest flow: doctor, oracle, workload, record, report.

Runs as root inside the virtme-ng guest (one boot per kernel).
Reads /tmp/export/job.json written by tools/kernel-matrix, writes
all evidence to /tmp/mv then copies to /tmp/export. Every refusal
aborts FAIL (exit 1), never skip: the host decides pass/fail from
the exported files.
"""

import gzip
import hashlib
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


def quiesce_udev(sh, write, out, polls=10):
    """Settle udev then shut its daemon down before measuring."""
    settle = sh(["udevadm", "settle", "--timeout=60"])
    log = "$ udevadm settle --timeout=60\n%s%s" % (
        settle.stdout or "", settle.stderr or "")
    write(os.path.join(out, "udev.out"), log)
    write(os.path.join(out, "udev.exit"),
          str(settle.returncode))
    if settle.returncode != 0:
        fail("udevadm settle failed exit %d"
             % settle.returncode)
    stop = sh(["udevadm", "control", "--exit"])
    log += "$ udevadm control --exit\n%s%s" % (
        stop.stdout or "", stop.stderr or "")
    write(os.path.join(out, "udev.out"), log)
    write(os.path.join(out, "udev.exit"),
          str(stop.returncode))
    if stop.returncode != 0:
        fail("udevadm control failed exit %d"
             % stop.returncode)
    for _ in range(polls):
        daemon = sh(["pgrep", "-x", "systemd-udevd"])
        workers = sh(["pgrep", "udev"])
        if daemon.returncode != 0 \
                and workers.returncode != 0:
            write(os.path.join(out, "udev.out"),
                  log + "$ pgrep -x systemd-udevd\ndaemon "
                  "and workers gone\n")
            write(os.path.join(out, "udev.exit"), "0")
            return
        time.sleep(1)
    listing = sh(["pgrep", "-a", "udev"])
    write(os.path.join(out, "udev.out"),
          log + "$ pgrep -a udev\n%s"
          % (listing.stdout or ""))
    write(os.path.join(out, "udev.exit"), "1")
    fail("systemd-udevd still running after control --exit")


def write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(data)


def find_nvme_by_serial(serial, root="/sys/block"):
    """NVMe device node with one serial, or None."""
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return None
    for name in names:
        if not name.startswith("nvme"):
            continue
        try:
            with open(os.path.join(root, name, "device",
                                   "serial")) as handle:
                if handle.read().strip() == serial:
                    return "/dev/" + name
        except OSError:
            continue
    return None


HIST_EVENT = TR + "/events/swiotlb/swiotlb_bounced"


def select_oracle_mode(btf_present, keep):
    """Full oracle, or count-only when BTF is absent for tp."""
    if btf_present:
        return "full"
    if set(keep) == {"tp"}:
        return "countonly"
    raise ValueError("BTF absent but non-tp probes needed: %s"
                     % sorted(keep))


def hist_install(event_dir):
    """Enable a key=size hist trigger, raising OSError."""
    Path(event_dir, "trigger").write_text("hist:key=size\n")
    Path(event_dir, "enable").write_text("1\n")


def hist_snapshot(event_dir):
    """Current hist text, raising OSError."""
    return Path(event_dir, "hist").read_text()


def hist_remove(event_dir):
    """Best-effort trigger removal, never raises."""
    try:
        Path(event_dir, "trigger").write_text(
            "!hist:key=size\n")
    except OSError:
        pass
    try:
        Path(event_dir, "enable").write_text("0\n")
    except OSError:
        pass


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


def wait_ready(rec_out, proc, timeout_s=120):
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        try:
            if "ready session=" in Path(rec_out).read_text():
                return True
        except OSError:
            pass
        if proc.poll() is not None:
            return False
        time.sleep(0.2)
    return None


def read_stat(km, base, write):
    try:
        text = Path("/sys/block", base, "stat").read_text()
    except OSError as exc:
        fail("block stat unreadable: %s" % exc)
    try:
        if write:
            return km.parse_blockstat_write(text)
        return km.parse_blockstat(text)
    except ValueError as exc:
        fail("block stat unreadable: %s" % exc)


def check_base(dev):
    base = os.path.basename(dev or "")
    if not base or ".." in base or "/" in base:
        fail("unexpected block device %r" % dev)
    return base


def run_phase(load, mode, tag, dev, count, offset,
              dest):
    args = [sys.executable, load, mode, "--phase", tag,
            "--dev", dev, "--count", str(count),
            "--offset", str(offset)]
    with open(dest, "a") as handle:
        proc = subprocess.run(args, stdout=handle,
                              stderr=subprocess.PIPE,
                              text=True, timeout=600)
    if proc.returncode != 0:
        fail("%s failed: %s" % (tag, (proc.stderr or "")
                                .strip()[:200]))


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
    try:
        with gzip.open("/proc/config.gz", "rb") as handle:
            raw = handle.read()
        write(os.path.join(out, "configid.txt"),
              hashlib.sha256(raw).hexdigest() + "\n")
    except OSError:
        write(os.path.join(out, "configid.txt"), "absent\n")
    except Exception:
        write(os.path.join(out, "configid.txt"),
              "unreadable\n")
    try:
        write(os.path.join(out, "version.txt"),
              Path("/proc/version").read_text())
    except OSError as exc:
        fail("cannot read /proc/version: %s" % exc)
    try:
        write(os.path.join(out, "lockdown.txt"),
              Path("/sys/kernel/security/lockdown")
              .read_text())
    except OSError:
        write(os.path.join(out, "lockdown.txt"), "absent\n")
    subprocess.run(["mount", "-t", "debugfs", "none",
                    "/sys/kernel/debug"],
                   capture_output=True)
    proc = sh([mv, "doctor", "--json", "--capability", "all"])
    write(os.path.join(out, "doctor-passive.json"),
          proc.stdout or "")
    write(os.path.join(out, "doctor-passive.stderr"),
          proc.stderr or "")
    write(os.path.join(out, "doctor-passive.exit"),
          str(proc.returncode))
    proc = sh([mv, "doctor", "--json", "--capability", "all",
               "--load-check"])
    write(os.path.join(out, "doctor.json"), proc.stdout or "")
    write(os.path.join(out, "doctor.stderr"), proc.stderr or "")
    write(os.path.join(out, "doctor.exit"), str(proc.returncode))
    sev = "/sys/devices/system/cpu/sev"
    if not os.path.exists(sev):
        write(os.path.join(out, "sev-sysfs.txt"), "absent")
    else:
        try:
            names = sorted(os.listdir(sev))
        except OSError as exc:
            write(os.path.join(out, "sev-sysfs.txt"),
                  "unreadable: %s" % exc)
        else:
            write(os.path.join(out, "sev-sysfs.txt"),
                  "\n".join(names) + ("\n" if names else ""))
    present, omitted = detect_hooks()
    btf_present = os.path.isfile("/sys/kernel/btf/vmlinux")
    write(os.path.join(out, "hooks.json"),
          json.dumps({"present": present, "omitted": omitted,
                      "btf": btf_present},
                     indent=2, sort_keys=True) + "\n")
    refused = [cap for cap in km.CAPS if cap not in admitted]
    # Mark before refusal probes so their dmesg is scanned.
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
    load = os.path.join(repo, "tests", "vm",
                        "kernel_matrix_load.py")
    data_serial = job.get("data_serial", "mv0")
    scratch_serial = job.get("scratch_serial", "mv1")
    dev = find_nvme_by_serial(data_serial)
    scratch = find_nvme_by_serial(scratch_serial)
    write(os.path.join(out, "dev.txt"),
          (dev or "none") + "\n" + (scratch or "none")
          + "\n")
    if not dev:
        fail("no nvme disk with serial %s" % data_serial)
    if not scratch:
        fail("no scratch disk with serial %s"
             % scratch_serial)
    quiesce_udev(sh, write, out)
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
    try:
        oracle_mode = select_oracle_mode(btf_present, keep)
    except ValueError as exc:
        fail(str(exc))
    prog = km.build_oracle_program(
        omitted=omit_for_oracle,
        count_only=(oracle_mode == "countonly"))
    write(os.path.join(out, "oracle.bt"), prog)
    write(os.path.join(out, "oracle.keep"),
          ",".join(keep) + "\n")
    write(os.path.join(out, "oracle.mode"),
          oracle_mode + "\n")
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
    hist_status = None
    if oracle_mode == "countonly":
        try:
            hist_install(HIST_EVENT)
            hist_status = "ok"
        except OSError as exc:
            hist_status = "unsupported: %s" % exc
        write(os.path.join(out, "hist.status"),
              hist_status + "\n")
    times = {}
    times[0] = snapshot_progs(out, 0)
    cap = os.path.join(out, "cap")
    record_out = open(os.path.join(out, "record.out"), "w")
    record_err = open(os.path.join(out, "record.stderr"), "w")
    rpid = subprocess.Popen(km.record_argv(mv, cap, duration,
                                             caps, None),
                            stdout=record_out, stderr=record_err,
                            start_new_session=True)
    ready = wait_ready(os.path.join(out, "record.out"), rpid)
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
    base = check_base(dev)
    scratch_base = check_base(scratch)
    data_before = read_stat(km, base, False)
    data_write_before = read_stat(km, base, True)
    scratch_before = read_stat(km, scratch_base, True)
    scratch_read_before = read_stat(km, scratch_base, False)
    if hist_status == "ok":
        try:
            write(os.path.join(out, "hist_before.txt"),
                  hist_snapshot(HIST_EVENT))
        except OSError as exc:
            fail("hist snapshot before phases failed: %s" % exc)
    workload_path = os.path.join(out, "workload.txt")
    open(workload_path, "w").close()
    run_phase(load, "read", "read0", dev, dd_count, 0,
              workload_path)
    run_phase(load, "read", "read512", dev, dd_count,
              512, workload_path)
    run_phase(load, "write", "write512", scratch, 64, 512,
              workload_path)
    readers = []
    handles = []
    for i in range(km.WORKLOAD_GROUPS):
        dest = os.path.join(out, "workload-r%d.txt" % i)
        handle = open(dest, "w")
        handles.append(handle)
        readers.append(subprocess.Popen(
            [sys.executable, load, "read", "--phase",
             "readers-%d" % i, "--dev", dev, "--count",
             str(dd_count), "--offset", "0"],
            stdout=handle,
            stderr=subprocess.PIPE, text=True))
    for i, proc in enumerate(readers):
        _, err = proc.communicate(timeout=600)
        handles[i].close()
        if proc.returncode != 0:
            fail("readers-%d failed: %s"
                 % (i, (err or "").strip()[:200]))
        with open(workload_path, "a") as handle:
            handle.write(Path(
                os.path.join(out,
                             "workload-r%d.txt" % i))
                .read_text())
    data_after = read_stat(km, base, False)
    data_write_after = read_stat(km, base, True)
    scratch_after = read_stat(km, scratch_base, True)
    scratch_read_after = read_stat(km, scratch_base, False)
    write(os.path.join(out, "blockstat.json"), json.dumps(
        {"data": {"dev": base, "read_before": data_before,
                  "read_after": data_after,
                  "write_before": data_write_before,
                  "write_after": data_write_after},
         "scratch": {"dev": scratch_base,
                     "write_before": scratch_before,
                     "write_after": scratch_after,
                     "read_before": scratch_read_before,
                     "read_after": scratch_read_after}},
        indent=2, sort_keys=True) + "\n")
    if hist_status == "ok":
        try:
            write(os.path.join(out, "hist_after.txt"),
                  hist_snapshot(HIST_EVENT))
        except OSError as exc:
            fail("hist snapshot after phases failed: %s" % exc)
        hist_remove(HIST_EVENT)
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
    # Settle two edge gaps before the busy loader starts.
    assert km.BUSY_SETTLE_NS >= 2 * km.MAX_EDGE_GAP_NS
    time.sleep(km.BUSY_SETTLE_NS / 10 ** 9)
    busy_dir = os.path.join(out, "busy")
    os.makedirs(busy_dir, exist_ok=True)
    busy_out = open(os.path.join(busy_dir, "busy.out"), "w")
    busy_err = open(os.path.join(busy_dir, "busy.stderr"), "w")
    bpid = subprocess.Popen(
        [sys.executable, load, "busy", "--phase", "busy",
         "--dev", dev, "--readers", "4"],
        stdout=busy_out, stderr=busy_err,
        start_new_session=True)
    time.sleep(2)
    if bpid.poll() is not None:
        busy_out.close()
        busy_err.close()
        fail("busy loader exited early")
    busy_times = {}
    busy_times[0] = snapshot_progs(busy_dir, 0)
    busy_cap = os.path.join(busy_dir, "cap")
    busy_rec_out = open(os.path.join(busy_dir,
                                     "record.out"), "w")
    busy_rec_err = open(os.path.join(busy_dir,
                                     "record.stderr"), "w")
    spawn_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    qpid = subprocess.Popen(km.record_argv(
        mv, busy_cap, 300, caps, km.BUSY_MAX_EVENTS_BYTES),
        stdout=busy_rec_out, stderr=busy_rec_err,
        start_new_session=True)
    ready = wait_ready(os.path.join(busy_dir, "record.out"),
                       qpid)
    if ready is None:
        qpid.terminate()
        bpid.send_signal(signal.SIGTERM)
        fail("busy record not ready in 120s")
    if ready is False:
        write(os.path.join(busy_dir, "record.exit"),
              str(qpid.returncode))
        bpid.send_signal(signal.SIGTERM)
        fail("busy record exited %d before ready"
             % (qpid.returncode,))
    ready_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    time.sleep(20)
    busy_times[1] = snapshot_progs(busy_dir, 1)
    stop_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    qpid.send_signal(signal.SIGINT)
    try:
        qpid.wait(timeout=120)
    except subprocess.TimeoutExpired:
        qpid.kill()
        qpid.wait()
        bpid.send_signal(signal.SIGTERM)
        fail("busy record did not stop on SIGINT")
    exit_ns = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    busy_times[2] = snapshot_progs(busy_dir, 2)
    write(os.path.join(busy_dir, "progs_times.json"),
          json.dumps({str(k): v
                      for k, v in sorted(busy_times.items())},
                     indent=2, sort_keys=True) + "\n")
    busy_rec_out.close()
    busy_rec_err.close()
    write(os.path.join(busy_dir, "record.exit"),
          str(qpid.returncode))
    bpid.send_signal(signal.SIGTERM)
    try:
        bpid.wait(timeout=60)
    except subprocess.TimeoutExpired:
        bpid.kill()
        bpid.wait()
        fail("busy loader did not stop on SIGTERM")
    busy_out.close()
    busy_err.close()
    if bpid.returncode != 0:
        fail("busy loader exited %d" % bpid.returncode)
    write(os.path.join(busy_dir, "times.json"), json.dumps(
        {"spawn_ns": spawn_ns, "ready_ns": ready_ns,
         "stop_ns": stop_ns, "exit_ns": exit_ns},
        indent=2, sort_keys=True) + "\n")
    try:
        reason = km.session_end_reason(
            Path(busy_cap, "session.json").read_text())
    except (OSError, ValueError) as exc:
        reason = "unknown (%s)" % exc
    write(os.path.join(busy_dir, "end_reason.txt"),
          reason + "\n")
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
    proc = sh([mv, "report", "--max-events-bytes", "4294967296",
               busy_cap], timeout=120)
    write(os.path.join(busy_dir, "report.out"),
          proc.stdout or "")
    write(os.path.join(busy_dir, "report.stderr"),
          proc.stderr or "")
    write(os.path.join(busy_dir, "report.exit"),
          str(proc.returncode))
    proc = sh([mv, "report", "--format", "json",
               "--max-events-bytes", "4294967296", busy_cap],
              timeout=120)
    write(os.path.join(busy_dir, "report.json"),
          proc.stdout or "")
    write(os.path.join(busy_dir, "report-json.stderr"),
          proc.stderr or "")
    write(os.path.join(busy_dir, "report-json.exit"),
          str(proc.returncode))
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
