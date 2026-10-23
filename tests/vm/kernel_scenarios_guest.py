#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detection scenario guest flow: twelve scenarios, one boot.

Runs as root inside the virtme-ng guest. Reads
/tmp/export/job.json written by tools/kernel-matrix, writes
all evidence to /tmp/mv then copies to /tmp/export. Every
scenario runs its setup, precondition proof, passive
doctor, load-check doctor, record, teardown, and teardown
proof; the host judges pass/fail. Only a broken guest
environment aborts FAIL (exit 1): the guest never retries
a failed command and never falls back, except the memcg
scenario's second calibrated run.
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SCN_ORDER = (
    "base",
    "neg-renamed",
    "neg-layout",
    "neg-shift",
    "neg-argcnt",
    "nonroot",
    "nocaps",
    "ftrace-off",
    "tracefs-unmounted",
    "btf-empty",
    "btf-truncated",
    "memcg",
)

NEG_FILES = {
    "neg-renamed": "renamed_field",
    "neg-layout": "widened_layout",
    "neg-shift": "wrong_shift",
    "neg-argcnt": "wrong_argcnt",
}

WORKLOAD_SCENARIOS = ("base", "neg-layout", "neg-shift",
                      "neg-argcnt")
REPORT_SCENARIOS = ("neg-layout", "neg-shift", "neg-argcnt")

ALL_CAPS = "attempt-trace,mapping-lifecycle,copy-actual"

BPF_OBJECTS = (("attempt", "swiotlb_attempt.bpf.o"),
               ("lifecycle", "swiotlb_lifecycle.bpf.o"),
               ("copy", "swiotlb_copy.bpf.o"))

TRACEFS_DEBUG = "/sys/kernel/debug/tracing"
TRACEFS_SYS = "/sys/kernel/tracing"
BTF_PATH = "/sys/kernel/btf/vmlinux"
FTRACE_ENABLED = "/proc/sys/kernel/ftrace_enabled"
CGROUP = "/sys/fs/cgroup"
MC_GROUP = "mvt_small"

_OUT = "/tmp/mv"
_EXPORT = "/tmp/export"


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
    copy_out()
    sys.exit(1)


def sh(args, **kw):
    return subprocess.run(args, capture_output=True, text=True,
                          **kw)


def write(path, data):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(data)


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


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def record_artifacts(km, out, mv, mode):
    if mode == "deb":
        roots = ["/usr/lib/memveil"]
    else:
        roots = [os.path.join(os.path.dirname(mv), "..", "lib",
                              "memveil"),
                 os.path.dirname(mv)]
    bpf = {}
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
        proc = sh(["dpkg-query", "-W", "-f=${Version}",
                   "memveil"])
        dpkg_version = (proc.stdout or "").strip()
        if proc.returncode != 0 or not dpkg_version:
            fail("dpkg-query for memveil failed")
    write(os.path.join(out, "artifacts.json"), json.dumps(
        {"mode": mode, "binary": {"path": mv,
                                 "sha256": km.sha_file(mv)},
         "dpkg_version": dpkg_version, "bpf": bpf},
        indent=2, sort_keys=True) + "\n")


def doctor_argv(mv, load_check, cp_object=None):
    argv = [mv, "doctor", "--json", "--capability", "all"]
    if load_check:
        argv.append("--load-check")
    if cp_object:
        argv += ["--cp-object", cp_object]
    return argv


def record_argv(mv, dest, duration, cp_object=None):
    argv = [mv, "record", "--output", dest, "--duration",
           str(duration), "--capability", ALL_CAPS]
    if cp_object:
        argv += ["--cp-object", cp_object]
    return argv


def wrap_nonroot(argv):
    return ["setpriv", "--reuid=65534", "--regid=65534",
            "--clear-groups"] + argv


def wrap_nocaps(argv):
    return ["capsh",
            "--drop=cap_sys_admin,cap_bpf,cap_perfmon",
            "--"] + argv


def wrap_cgroup(group, argv):
    return ["sh", "-c",
            "echo $$ > %s/%s/cgroup.procs; exec \"$@\""
            % (CGROUP, group), "sh"] + argv


def run_doctor(sdir, mv, name, load_check, cp_object,
               wrap):
    proc = sh(wrap(doctor_argv(mv, load_check, cp_object)),
              timeout=180)
    write(os.path.join(sdir, name + ".json"),
          proc.stdout or "")
    write(os.path.join(sdir, name + ".stderr"),
          proc.stderr or "")
    write(os.path.join(sdir, name + ".exit"),
          str(proc.returncode))


def run_record(sdir, mv, cap, duration, cp_object, wrap,
               with_workload, load, dev):
    rec_stdout = open(os.path.join(sdir, "record.stdout"),
                      "w")
    rec_stderr = open(os.path.join(sdir, "record.stderr"),
                      "w")
    proc = subprocess.Popen(
        wrap(record_argv(mv, cap, duration, cp_object)),
        stdout=rec_stdout, stderr=rec_stderr,
        start_new_session=True)
    if with_workload:
        ready = wait_ready(os.path.join(sdir,
                                        "record.stdout"),
                           proc)
        if ready is True:
            wout = open(os.path.join(sdir, "workload.out"),
                        "w")
            wproc = subprocess.run(
                [sys.executable, load, "read", "--phase",
                 "scn", "--dev", dev, "--count", "64",
                 "--offset", "0"],
                stdout=wout, stderr=subprocess.PIPE,
                text=True, timeout=300)
            wout.close()
            write(os.path.join(sdir, "workload.exit"),
                  str(wproc.returncode))
        else:
            write(os.path.join(sdir, "workload.out"), "")
            write(os.path.join(sdir, "workload.exit"),
                  "skipped")
    try:
        proc.wait(timeout=duration + 180)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
    rec_stdout.close()
    rec_stderr.close()
    try:
        combined = Path(sdir, "record.stdout").read_text() \
            + Path(sdir, "record.stderr").read_text()
    except OSError:
        combined = ""
    write(os.path.join(sdir, "record.out"), combined)
    write(os.path.join(sdir, "record.exit"),
          str(proc.returncode))
    write(os.path.join(sdir, "record.exists"),
          "yes" if os.path.exists(cap) else "no")


def run_reports(sdir, mv, cap):
    if os.path.isdir(cap):
        proc = sh([mv, "report", "--format", "json",
                   "--max-events-bytes", "4294967296", cap],
                  timeout=300)
        write(os.path.join(sdir, "report.json"),
              proc.stdout or "")
        write(os.path.join(sdir, "report-json.stderr"),
              proc.stderr or "")
        write(os.path.join(sdir, "report-json.exit"),
              str(proc.returncode))
        proc = sh([mv, "report", "--max-events-bytes",
                   "4294967296", cap], timeout=300)
        write(os.path.join(sdir, "report.txt"),
              proc.stdout or "")
        write(os.path.join(sdir, "report-txt.stderr"),
              proc.stderr or "")
        write(os.path.join(sdir, "report-txt.exit"),
              str(proc.returncode))
    else:
        for name in ("report.json", "report.txt"):
            write(os.path.join(sdir, name), "")


def teardown_proof(sdir, mv):
    proc = sh(doctor_argv(mv, False), timeout=180)
    try:
        verdict = json.loads(proc.stdout or "").get(
            "verdict")
    except ValueError:
        verdict = None
    proof = {"verdict": verdict}
    write(os.path.join(sdir, "teardown.json"),
          json.dumps(proof, indent=2, sort_keys=True) + "\n")


def note_teardown(sdir, key, value):
    path = os.path.join(sdir, "teardown.json")
    try:
        proof = json.loads(Path(path).read_text())
    except (OSError, ValueError):
        proof = {}
    proof[key] = value
    write(path, json.dumps(proof, indent=2, sort_keys=True)
          + "\n")


def scenario_base(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    run_doctor(sdir, mv, "doctor-passive", False, None,
               ctx["plain"])
    try:
        verdict = json.loads(
            Path(sdir, "doctor-passive.json")
            .read_text()).get("verdict")
    except (OSError, ValueError):
        verdict = None
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"verdict": verdict}, indent=2,
                     sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-load", True, None,
               ctx["plain"])
    run_record(sdir, mv, os.path.join(sdir, "cap"), 10,
               None, ctx["plain"], True, ctx["load"],
               ctx["dev"])
    teardown_proof(sdir, mv)


def scenario_negative(ctx, name):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    cp_object = ctx["negs"][NEG_FILES[name]]
    try:
        digest = sha_file(cp_object)
    except OSError:
        digest = None
    run_doctor(sdir, mv, "doctor-passive", False,
               cp_object, ctx["plain"])
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"object_sha": digest}, indent=2,
                     sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-load", True, cp_object,
               ctx["plain"])
    with_workload = name in WORKLOAD_SCENARIOS
    run_record(sdir, mv, os.path.join(sdir, "cap"),
               10 if with_workload else 5, cp_object,
               ctx["plain"], with_workload, ctx["load"],
               ctx["dev"])
    if name in REPORT_SCENARIOS:
        run_reports(sdir, mv, os.path.join(sdir, "cap"))
    teardown_proof(sdir, mv)


_NONROOT_PROBE = (
    "import json,os;"
    "uid=os.geteuid();"
    "root='none';readable=None;"
    "d=os.path.join('/sys/kernel/debug/tracing','events');"
    "s=os.path.join('/sys/kernel/tracing','events');"
    "t=None;"
    "t=[p for p in (d,s) if os.path.exists(os.path.dirname(p))];"
    "t=t[0] if t else None;"
    "root={'%s':'debug','%s':'sys'}.get(os.path.dirname(t),'none') if t else 'none';"
    "readable=os.access(t,os.R_OK) if t else None;"
    "print(json.dumps({'uid':uid,'root':root,'events_readable':readable}))"
    % (TRACEFS_DEBUG, TRACEFS_SYS))


def scenario_nonroot(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    nobody_dir = os.path.join(sdir, "nobody-out")
    os.makedirs(nobody_dir, exist_ok=True)
    try:
        os.chown(nobody_dir, 65534, 65534)
    except OSError as exc:
        fail("chown nobody-out failed: %s" % exc)
    probe = sh(wrap_nonroot([sys.executable, "-c",
                             _NONROOT_PROBE]),
               timeout=60)
    try:
        pre = json.loads((probe.stdout or "").strip())
    except ValueError:
        pre = {"uid": None, "root": None,
               "events_readable": None,
               "probe_exit": str(probe.returncode),
               "probe_err": (probe.stderr or "")[:200]}
    else:
        pre["probe_exit"] = str(probe.returncode)
    write(os.path.join(sdir, "precondition.json"),
          json.dumps(pre, indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               wrap_nonroot)
    run_doctor(sdir, mv, "doctor-load", True, None,
               wrap_nonroot)
    run_record(sdir, mv,
               os.path.join(nobody_dir, "rec"), 5, None,
               wrap_nonroot, False, ctx["load"], ctx["dev"])
    teardown_proof(sdir, mv)


_NOCAPS_PROBE = (
    "for line in open('/proc/self/status'):"
    " fields=line.split();"
    " print(fields[1]) if fields and fields[0]=='CapEff:' else None")


def scenario_nocaps(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    probe = sh(wrap_nocaps([sys.executable, "-c",
                            _NOCAPS_PROBE]),
               timeout=60)
    capeff = (probe.stdout or "").strip().splitlines()
    pre = {"capeff": capeff[0] if capeff else None,
           "probe_exit": str(probe.returncode)}
    write(os.path.join(sdir, "precondition.json"),
          json.dumps(pre, indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               wrap_nocaps)
    run_doctor(sdir, mv, "doctor-load", True, None,
               wrap_nocaps)
    run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
               None, wrap_nocaps, False, ctx["load"],
               ctx["dev"])
    teardown_proof(sdir, mv)


def scenario_ftrace_off(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    try:
        orig = Path(FTRACE_ENABLED).read_text().strip()
    except OSError:
        orig = None
    try:
        Path(FTRACE_ENABLED).write_text("0\n")
        now = Path(FTRACE_ENABLED).read_text().strip()
    except OSError:
        now = None
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"ftrace_enabled": now, "orig": orig},
                     indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               ctx["plain"])
    run_doctor(sdir, mv, "doctor-load", True, None,
               ctx["plain"])
    run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
               None, ctx["plain"], False, ctx["load"],
               ctx["dev"])
    restored = None
    if orig is not None:
        try:
            Path(FTRACE_ENABLED).write_text(orig + "\n")
            restored = Path(FTRACE_ENABLED).read_text() \
                .strip()
        except OSError:
            restored = None
    teardown_proof(sdir, mv)
    note_teardown(sdir, "ftrace_enabled", restored)


def _trace_mounts():
    found = []
    try:
        text = Path("/proc/mounts").read_text()
    except OSError:
        return None, []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] in (
                "tracefs", "debugfs"):
            found.append({"fstype": fields[2],
                          "point": fields[1]})
    return text, found


def scenario_tracefs_unmounted(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    _, found = _trace_mounts()
    write(os.path.join(sdir, "mounts.before.json"),
          json.dumps(found, indent=2, sort_keys=True) + "\n")
    umount_log = []
    for entry in sorted(found,
                        key=lambda e: e["point"],
                        reverse=True):
        proc = sh(["umount", entry["point"]], timeout=60)
        umount_log.append({"point": entry["point"],
                           "exit": str(proc.returncode),
                           "err": (proc.stderr or "")[:200]})
    text, _ = _trace_mounts()
    events_present = os.path.exists(os.path.join(
        TRACEFS_SYS, "events")) or os.path.exists(
            os.path.join(TRACEFS_DEBUG, "events"))
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"mounts": text or "",
                      "events_present": events_present,
                      "umount": umount_log},
                     indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               ctx["plain"])
    run_doctor(sdir, mv, "doctor-load", True, None,
               ctx["plain"])
    run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
               None, ctx["plain"], False, ctx["load"],
               ctx["dev"])
    mount_log = []
    for entry in sorted(found,
                        key=lambda e: e["point"]):
        proc = sh(["mount", "-t", entry["fstype"], "none",
                   entry["point"]], timeout=60)
        mount_log.append({"point": entry["point"],
                          "exit": str(proc.returncode),
                          "err": (proc.stderr or "")[:200]})
    teardown_proof(sdir, mv)
    note_teardown(sdir, "mount", mount_log)


def _btf_orig():
    try:
        with open(BTF_PATH, "rb") as handle:
            raw = handle.read()
        return raw, sha_file(BTF_PATH)
    except OSError:
        return None, None


def _btf_size():
    try:
        return os.path.getsize(BTF_PATH)
    except OSError:
        return None


def _btf_head_equal(want):
    try:
        with open(BTF_PATH, "rb") as handle:
            return handle.read(len(want)) == want
    except OSError:
        return False


def scenario_btf_empty(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    raw, orig_sha = _btf_orig()
    empty_path = "/tmp/mv-btf-empty"
    bind_err = None
    if raw is None:
        bind_err = "original btf unreadable"
    else:
        try:
            Path(empty_path).write_text("")
            proc = sh(["mount", "--bind", empty_path,
                       BTF_PATH], timeout=60)
            if proc.returncode != 0:
                bind_err = (proc.stderr or "")[:200]
        except OSError as exc:
            bind_err = str(exc)[:200]
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"size": _btf_size(),
                      "bind_err": bind_err},
                     indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               ctx["plain"])
    run_doctor(sdir, mv, "doctor-load", True, None,
               ctx["plain"])
    run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
               None, ctx["plain"], False, ctx["load"],
               ctx["dev"])
    sh(["umount", BTF_PATH], timeout=60)
    _, restored_sha = _btf_orig()
    teardown_proof(sdir, mv)
    note_teardown(sdir, "btf_restored",
                  restored_sha == orig_sha)


def scenario_btf_truncated(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    raw, orig_sha = _btf_orig()
    half_path = "/tmp/mv-btf-half"
    bind_err = None
    half = None
    if raw is None:
        bind_err = "original btf unreadable"
    else:
        half = raw[:len(raw) // 2]
        try:
            Path(half_path).write_bytes(half)
            proc = sh(["mount", "--bind", half_path,
                       BTF_PATH], timeout=60)
            if proc.returncode != 0:
                bind_err = (proc.stderr or "")[:200]
        except OSError as exc:
            bind_err = str(exc)[:200]
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"size": _btf_size(),
                      "orig_size": len(raw)
                      if raw is not None else None,
                      "head_equal": _btf_head_equal(half)
                      if half is not None else False,
                      "bind_err": bind_err},
                     indent=2, sort_keys=True) + "\n")
    run_doctor(sdir, mv, "doctor-passive", False, None,
               ctx["plain"])
    run_doctor(sdir, mv, "doctor-load", True, None,
               ctx["plain"])
    run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
               None, ctx["plain"], False, ctx["load"],
               ctx["dev"])
    sh(["umount", BTF_PATH], timeout=60)
    _, restored_sha = _btf_orig()
    teardown_proof(sdir, mv)
    note_teardown(sdir, "btf_restored",
                  restored_sha == orig_sha)


def _cg_path(group, leaf):
    return os.path.join(CGROUP, group, leaf)


def _cg_setup(group):
    try:
        os.makedirs(os.path.join(CGROUP, group),
                    exist_ok=True)
        ctl = Path(CGROUP, "cgroup.subtree_control") \
            .read_text()
        if "memory" not in ctl.split():
            Path(CGROUP, "cgroup.subtree_control") \
                .write_text("+memory")
        return None
    except OSError as exc:
        return str(exc)[:200]


def _cg_rm(group):
    try:
        os.rmdir(os.path.join(CGROUP, group))
    except OSError:
        pass


def _cg_peak(group):
    try:
        return int(Path(_cg_path(group, "memory.peak"))
                   .read_text().strip())
    except (OSError, ValueError):
        return None


def _cg_oom(group):
    try:
        for line in Path(_cg_path(group, "memory.events")) \
                .read_text().splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0] == \
                    "oom_kill":
                return int(fields[1])
    except (OSError, ValueError):
        pass
    return None


def scenario_memcg(ctx):
    sdir = ctx["sdir"]
    mv = ctx["mv"]
    attempts = []
    chosen = None
    try:
        controllers = Path(CGROUP,
                           "cgroup.controllers").read_text()
    except OSError:
        controllers = ""
    if "memory" not in controllers.split():
        write(os.path.join(sdir, "precondition.json"),
              json.dumps({"attempt": None,
                          "error": "no memory controller"},
                         indent=2, sort_keys=True) + "\n")
        write(os.path.join(sdir, "memcg.json"),
              json.dumps({"attempts": [], "chosen": None,
                          "status": "fail"},
                         indent=2, sort_keys=True) + "\n")
        run_doctor(sdir, mv, "doctor-passive", False, None,
                   ctx["plain"])
        run_doctor(sdir, mv, "doctor-load", True, None,
                   ctx["plain"])
        run_record(sdir, mv, os.path.join(sdir, "cap"), 5,
                   None, ctx["plain"], False, ctx["load"],
                   ctx["dev"])
        teardown_proof(sdir, mv)
        return
    for num in range(2):
        attempt = _memcg_attempt(ctx, sdir, num)
        attempts.append(attempt)
        if attempt.get("setup_err") is not None:
            break
        if attempt.get("invalid") is None:
            chosen = num
            break
    if chosen is None and len(attempts) == 2 and all(
            a.get("setup_err") is None
            and a.get("invalid") is not None
            for a in attempts):
        status = "not_proven"
    elif chosen is None:
        status = "fail"
    else:
        status = "ok"
    write(os.path.join(sdir, "memcg.json"),
          json.dumps({"attempts": attempts,
                      "chosen": chosen, "status": status},
                     indent=2, sort_keys=True) + "\n")
    if chosen is None:
        picked = attempts[0]
    else:
        picked = attempts[chosen]
    write(os.path.join(sdir, "precondition.json"),
          json.dumps({"attempt": picked}, indent=2,
                     sort_keys=True) + "\n")
    attdir = os.path.join(sdir, "att%d" % (
        chosen if chosen is not None else 0))
    for name in ("doctor-passive.json",
                 "doctor-passive.stderr",
                 "doctor-passive.exit", "doctor-load.json",
                 "doctor-load.stderr", "doctor-load.exit",
                 "record.out", "record.stdout",
                 "record.stderr", "record.exit",
                 "record.exists"):
        try:
            shutil.copy2(os.path.join(attdir, name),
                         os.path.join(sdir, name))
        except OSError:
            write(os.path.join(sdir, name), "")
    _cg_rm(MC_GROUP)
    teardown_proof(sdir, mv)


def _memcg_calibrate(ctx, num):
    mv = ctx["mv"]
    groups = ["mvt_cal%d_%d" % (num, i) for i in range(3)]
    for group in groups:
        err = _cg_setup(group)
        if err is not None:
            return None, err
    sh(wrap_cgroup(groups[0],
                   doctor_argv(mv, False)), timeout=180)
    p0 = _cg_peak(groups[0])
    sh(wrap_cgroup(groups[1],
                   doctor_argv(mv, True)), timeout=180)
    p1 = _cg_peak(groups[1])
    tmp = os.path.join(ctx["sdir"], "cal-rec-%d" % num)
    sh(wrap_cgroup(groups[2],
                   [mv, "record", "--output", tmp,
                    "--duration", "1", "--capability",
                    "copy-actual"]), timeout=180)
    r0 = _cg_peak(groups[2])
    for group in groups:
        _cg_rm(group)
    if p0 is None or p1 is None or r0 is None:
        return None, "peak unreadable"
    return {"p0": p0, "p1": p1, "r0": r0}, None


def _memcg_attempt(ctx, sdir, num):
    mv = ctx["mv"]
    attdir = os.path.join(sdir, "att%d" % num)
    os.makedirs(attdir, exist_ok=True)
    cal, err = _memcg_calibrate(ctx, num)
    if err is not None:
        return {"setup_err": err}
    limit = (max(cal["p0"], cal["r0"]) + cal["p1"]) // 2
    err = _cg_setup(MC_GROUP)
    if err is not None:
        return dict(cal, limit=limit, setup_err=err)
    try:
        Path(_cg_path(MC_GROUP, "memory.max")) \
            .write_text(str(limit))
        mem_max = Path(_cg_path(MC_GROUP, "memory.max")) \
            .read_text().strip()
        probe = sh(wrap_cgroup(
            MC_GROUP,
            [sys.executable, "-c",
             "print(open('/proc/self/cgroup').read())"]),
            timeout=60)
        cgroup = probe.stdout or ""
    except OSError as exc:
        return dict(cal, limit=limit,
                    setup_err=str(exc)[:200])
    oom_before = _cg_oom(MC_GROUP)
    wrap = lambda argv: wrap_cgroup(MC_GROUP, argv)
    run_doctor(attdir, mv, "doctor-passive", False, None,
               wrap)
    run_doctor(attdir, mv, "doctor-load", True, None, wrap)
    run_record(attdir, mv, os.path.join(attdir, "cap"), 5,
               None, wrap, False, ctx["load"], ctx["dev"])
    oom_after = _cg_oom(MC_GROUP)
    exits = []
    for leaf in ("doctor-passive.exit", "doctor-load.exit",
                 "record.exit"):
        try:
            exits.append(Path(attdir, leaf).read_text()
                         .strip())
        except OSError:
            exits.append(None)
    attempt = dict(cal, limit=limit, cgroup=cgroup,
                   memory_max=mem_max, oom_before=oom_before,
                   oom_after=oom_after, exits=exits)
    invalid = None
    if oom_before is not None and oom_after is not None \
            and oom_after - oom_before > 0:
        invalid = "oom_kill delta %d" % (
            oom_after - oom_before,)
    for exit_text in exits:
        if (exit_text or "").startswith("-"):
            invalid = "signal exit %s" % exit_text
    if invalid is not None:
        attempt["invalid"] = invalid
    return attempt


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
    for tool in ("setpriv", "capsh", "sysctl", "mount",
                 "umount"):
        if shutil.which(tool) is None:
            fail("guest tool missing: %s" % tool)
    deb = job.get("deb")
    bundle = job.get("bundle")
    sys.path.insert(0, os.path.join(repo, "tests", "vm"))
    try:
        import kernel_matrix as km
    except ImportError as exc:
        fail("cannot import kernel_matrix: %s" % exc)
    mv = None
    mode = None
    if deb:
        proc = sh(["dpkg", "-i", deb])
        write(os.path.join(out, "dpkg.out"),
              (proc.stdout or "") + (proc.stderr or ""))
        write(os.path.join(out, "dpkg.exit"),
              str(proc.returncode))
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
    write(os.path.join(out, "uname.txt"),
          os.uname().release + "\n"
          + Path("/proc/cmdline").read_text())
    subprocess.run(["mount", "-t", "debugfs", "none",
                    "/sys/kernel/debug"],
                   capture_output=True)
    negs = {}
    for name, sha in (job.get("negatives") or {}).items():
        path = os.path.join(export, "neg",
                            "swiotlb_copy-%s.bpf.o" % name)
        if not os.path.isfile(path):
            fail("negative object missing: %s" % name)
        if sha_file(path) != sha:
            fail("negative object sha mismatch: %s" % name)
        negs[name] = path
    for name in NEG_FILES.values():
        if name not in negs:
            fail("job lacks negative %s" % name)
    data_serial = job.get("data_serial", "mv0")
    dev = find_nvme_by_serial(data_serial)
    write(os.path.join(out, "dev.txt"),
          (dev or "none") + "\n")
    if not dev:
        fail("no nvme disk with serial %s" % data_serial)
    load = os.path.join(repo, "tests", "vm",
                        "kernel_matrix_load.py")
    if not os.path.isfile(load):
        fail("workload missing: %s" % load)
    ctx = {"mv": mv, "load": load, "dev": dev, "negs": negs,
           "plain": lambda argv: argv, "sdir": None}
    runners = {"base": scenario_base,
               "neg-renamed": lambda c: scenario_negative(
                   c, "neg-renamed"),
               "neg-layout": lambda c: scenario_negative(
                   c, "neg-layout"),
               "neg-shift": lambda c: scenario_negative(
                   c, "neg-shift"),
               "neg-argcnt": lambda c: scenario_negative(
                   c, "neg-argcnt"),
               "nonroot": scenario_nonroot,
               "nocaps": scenario_nocaps,
               "ftrace-off": scenario_ftrace_off,
               "tracefs-unmounted":
               scenario_tracefs_unmounted,
               "btf-empty": scenario_btf_empty,
               "btf-truncated": scenario_btf_truncated,
               "memcg": scenario_memcg}
    for name in SCN_ORDER:
        sdir = os.path.join(out, "scn-" + name)
        os.makedirs(sdir, exist_ok=True)
        ctx["sdir"] = sdir
        try:
            runners[name](ctx)
        except subprocess.TimeoutExpired as exc:
            write(os.path.join(sdir, "TIMEOUT.txt"),
                  "timed out: %s\n" % exc)
        print("guest: scenario %s done" % name)
    print("guest: scenarios done")
    return 0


def main():
    if len(sys.argv) != 3:
        print("usage: kernel_scenarios_guest.py EXPORT REPO",
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