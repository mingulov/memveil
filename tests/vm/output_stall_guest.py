#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Output-stall guest flow: live record against a full stdout pipe.

Runs as root inside the virtme-ng guest (one boot per run).
Stalls the binary under test on its own full stdout pipe
through output_stall_core.run_stall, with an owned pcnet
ping stimulus during the window and bpftool attach proof
at readiness and at blocked entry. Writes every export to
/tmp/mv, then copies to /tmp/export with sha256 sidecars.

Exit 0 means the choreography completed (verdict.json
carries PASS/FAIL); exit 1 means guest-side infrastructure
failed and the host must judge the run failed. The host
re-derives the verdict from the exported observations and
never trusts verdict.json alone.
"""

import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import output_stall_core as core

_OUT = "/tmp/mv"
_PEER = "10.0.3.2"


def write(path, data):
    with open(path, "w") as handle:
        handle.write(data)


def copy_out(out, export):
    try:
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


def fail(out, export, msg):
    print("guest: FAIL: %s" % msg, file=sys.stderr)
    try:
        Path(out).mkdir(parents=True, exist_ok=True)
        Path(out, "FAIL.txt").write_text(msg + "\n")
    except OSError:
        pass
    copy_out(out, export)
    sys.exit(1)


def first_line(proc):
    if proc.returncode != 0 or not proc.stdout:
        return ""
    lines = proc.stdout.splitlines()
    return lines[0] if lines else ""


def bpf_progs(bpftool):
    """Loaded program id set + names, or an error note."""
    try:
        proc = subprocess.run([bpftool, "prog", "show", "--json"],
                              capture_output=True, text=True,
                              timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": "bpftool failed: %s" % (exc,)}
    if proc.returncode != 0:
        return {"error": "bpftool exit %d" % proc.returncode}
    try:
        doc = json.loads(proc.stdout or "[]")
    except ValueError:
        return {"error": "bpftool output unparsable"}
    ids = set()
    names = []
    for row in doc:
        try:
            ids.add(int(row.get("id")))
            names.append(str(row.get("name", "")))
        except (TypeError, ValueError):
            continue
    return {"ids": sorted(ids), "names": sorted(names)}


def parse_args(argv):
    args = {"work": "", "export": "", "binary": "",
            "profiles_dir": "", "duration": "15",
            "capability": "attempt-trace", "bpftrace": "",
            "bpftool": "", "stimulus": True}
    if len(argv) < 3:
        return None
    args["work"] = argv[0]
    args["export"] = argv[1]
    i = 2
    while i < len(argv):
        token = argv[i]
        if token == "--no-stimulus":
            args["stimulus"] = False
            i += 1
        elif token in ("--binary", "--profiles-dir",
                       "--duration", "--capability",
                       "--bpftrace", "--bpftool") \
                and i + 1 < len(argv):
            args[token[2:].replace("-", "_")] = argv[i + 1]
            i += 2
        else:
            return None
    if not args["work"] or not args["export"] \
            or not args["binary"]:
        return None
    return args


def main(argv):
    # Guest-only: never attach the binary under test to the
    # host by an accidental direct run. The host runner sets
    # this marker in the --exec environment.
    if os.environ.get("MEMVEIL_VM_OUTPUT_STALL_GUEST") != "1":
        sys.stderr.write("output_stall_guest: guest-only entry "
                         "point (refusing host run)\n")
        return 2
    args = parse_args(argv)
    out = _OUT
    export = argv[1] if len(argv) >= 2 else "/tmp/export"
    if args is None:
        fail(out, export, "bad guest args: %r" % (argv,))
    work = args["work"]
    export = args["export"]
    try:
        duration = float(args["duration"])
    except ValueError:
        fail(out, export, "bad duration %r"
             % (args["duration"],))
    binary = args["binary"]
    if not os.path.isfile(binary) \
            or not os.access(binary, os.X_OK):
        fail(out, export, "binary under test unusable: %s"
             % binary)
    try:
        Path(out).mkdir(parents=True, exist_ok=True)
        Path(work).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        fail(out, export, "work dirs failed: %s" % (exc,))
    write(os.path.join(out, "job.json"), json.dumps(
        {"binary": binary, "duration": duration,
         "capability": args["capability"],
         "profiles_dir": args["profiles_dir"],
         "stimulus": args["stimulus"]},
        indent=2, sort_keys=True) + "\n")

    # Artifact + guest identity (absolute host-resolved tool
    # paths: vng passes no PATH into the guest).
    uname = subprocess.run(["uname", "-r"], capture_output=True,
                           text=True)
    bpftrace_v = ""
    bpftool_v = ""
    if args["bpftrace"]:
        bpftrace_v = first_line(subprocess.run(
            [args["bpftrace"], "--version"],
            capture_output=True, text=True, timeout=30))
    if args["bpftool"]:
        bpftool_v = first_line(subprocess.run(
            [args["bpftool"], "--version"],
            capture_output=True, text=True, timeout=30))
    artifacts = {
        "binary": {"path": binary,
                   "sha256": core.sha_file(binary)},
        "guest_release": (uname.stdout or "").strip(),
        "btf_present": os.path.exists(
            "/sys/kernel/btf/vmlinux"),
        "bpftrace": bpftrace_v, "bpftool": bpftool_v,
        "bpftrace_path": args["bpftrace"],
        "bpftool_path": args["bpftool"],
    }
    write(os.path.join(out, "artifacts.json"),
          json.dumps(artifacts, indent=2, sort_keys=True)
          + "\n")

    bpftool = args["bpftool"] or "bpftool"
    progs_before = bpf_progs(bpftool)
    if "error" in progs_before:
        fail(out, export, "attach baseline failed: %s"
             % progs_before["error"])
    observations = {"progs_before": progs_before,
                    "progs_ready": None,
                    "progs_blocked": None}

    def observe(phase, obs):
        snap = bpf_progs(bpftool)
        if "error" in snap:
            fail(out, export, "attach proof failed at %s: %s"
                 % (phase, snap["error"]))
        observations["progs_" + phase] = snap

    stimulus = None
    stimulus_log = os.path.join(work, "stimulus.log")
    if args["stimulus"]:
        flood = ["timeout", str(int(duration + 60)),
                 "ping", "-f", "-c", "3000", _PEER]
        try:
            log_handle = open(stimulus_log, "wb")
        except OSError as exc:
            fail(out, export, "stimulus log failed: %s" % (exc,))
        try:
            stimulus = subprocess.Popen(
                flood, stdout=log_handle, stderr=log_handle,
                stdin=subprocess.DEVNULL, close_fds=True,
                start_new_session=True)
        finally:
            log_handle.close()
        write(os.path.join(out, "stimulus.cmd"),
              shlex.join(flood) + "\n")
    else:
        Path(stimulus_log).write_bytes(b"stimulus disabled\n")

    record_argv = [binary, "record", "--output",
                   os.path.join(work, "cap"), "--duration",
                   str(int(duration)), "--capability",
                   args["capability"]]
    if args["profiles_dir"]:
        record_argv += ["--profiles-dir", args["profiles_dir"]]
    try:
        obs = core.run_stall(
            record_argv, work,
            ready_timeout=120.0,
            block_timeout=duration + 90.0,
            hold_seconds=5.0, hold_samples=10,
            stderr_path=os.path.join(work, "record.stderr"),
            observe=observe)
    except Exception as exc:
        fail(out, export, "stall choreography failed: %s" % (exc,))

    if stimulus is not None:
        try:
            stimulus.wait(timeout=90)
        except subprocess.TimeoutExpired:
            try:
                stimulus.kill()
            except OSError:
                pass
            stimulus.wait(timeout=30)
    try:
        with open(stimulus_log, "rb") as handle:
            stimulus_tail = handle.read()[-2000:].decode(
                "utf-8", "replace")
    except OSError:
        stimulus_tail = ""

    # Capture verification + readback through the same binary.
    cap_dir = obs["cap_dir"]
    capture = core.verify_capture(cap_dir)
    cleanup = core.verify_cleanup(cap_dir)
    judged = core.judge_stall(obs, require_growth=False)
    report = {"exit": None, "stdout_sha256": "",
              "stdout_bytes": 0, "stdout_head": "",
              "stderr_head": ""}
    try:
        proc = subprocess.run([binary, "report", cap_dir],
                              capture_output=True, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as exc:
        fail(out, export, "report readback failed: %s" % (exc,))
    report["exit"] = proc.returncode
    report["stdout_sha256"] = core.sha_bytes(proc.stdout or b"")
    report["stdout_bytes"] = len(proc.stdout or b"")
    try:
        report["stdout_head"] = (proc.stdout or b"")[:500].decode(
            "utf-8", "replace")
        report["stderr_head"] = (proc.stderr or b"")[:500].decode(
            "utf-8", "replace")
    except ValueError:
        pass

    before_ids = set(
        observations["progs_before"].get("ids", []))
    ready_ids = set((observations["progs_ready"] or {}).get(
        "ids", []))
    blocked_ids = set(
        (observations["progs_blocked"] or {}).get("ids", []))
    new_ids = sorted((ready_ids | blocked_ids) - before_ids)
    names = ((observations["progs_ready"] or {}).get(
        "names", [])
        + (observations["progs_blocked"] or {}).get(
            "names", []))
    attach = {"before_ids": sorted(before_ids),
              "ready_ids": sorted(ready_ids),
              "blocked_ids": sorted(blocked_ids),
              "new_ids": new_ids, "names": sorted(set(names)),
              "ok": bool(new_ids) or any(
                  "swiotlb" in n or "memveil" in n
                  for n in names)}
    reasons = list(judged["reasons"])
    if not capture["ok"]:
        reasons.append("capture cross-check failed: %s"
                       % ("; ".join(capture["reasons"]),))
    if not cleanup["ok"]:
        reasons.append("owned cleanup failed: %s"
                       % ("; ".join(cleanup["reasons"]),))
    if not attach["ok"]:
        reasons.append("no independent attach proof")
    if report["exit"] != 0 or not report["stdout_bytes"]:
        reasons.append("report readback failed (exit %s)"
                       % (report["exit"],))
    verdict = {"verdict": "PASS" if not reasons else "FAIL",
               "reasons": reasons}

    exports = {
        "verdict.json": verdict,
        "stall.json": {"observations": obs, "judge": judged},
        "capture.json": capture,
        "cleanup.json": cleanup,
        "attach.json": attach,
        "artifacts.json": artifacts,
        "report.json": report,
        "stimulus.json": {
            "enabled": args["stimulus"],
            "exit": stimulus.returncode
            if stimulus is not None else None,
            "tail": stimulus_tail,
        },
    }
    for name, doc in exports.items():
        write(os.path.join(out, name),
              json.dumps(doc, indent=2, sort_keys=True,
                         default=str) + "\n")
    write(os.path.join(out, "record.stdout"),
          obs["ready_line"] + "\n" + obs["done_line"] + "\n"
          if obs["ready_ok"] and obs["done_ok"]
          else (obs["ready_line"] + "\n"
                if obs["ready_line"] else ""))
    try:
        with open(os.path.join(work, "record.stderr"),
                  "rb") as handle:
            err_raw = handle.read()
    except OSError:
        err_raw = b""
    try:
        Path(out, "record.stderr").write_bytes(err_raw)
    except OSError:
        fail(out, export, "record.stderr export failed")
    try:
        shutil.copy2(stimulus_log,
                     os.path.join(out, "stimulus.log"))
    except OSError:
        fail(out, export, "stimulus log export failed")
    for name in sorted(os.listdir(out)):
        if name.endswith(".sha256") or name == "FAIL.txt":
            continue
        path = os.path.join(out, name)
        if os.path.isfile(path):
            digest = core.sha_file(path)
            write(path + ".sha256", digest + "  " + name + "\n")
    copy_out(out, export)
    print("guest: output-stall %s" % verdict["verdict"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
