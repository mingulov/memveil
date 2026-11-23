#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Output-stall gate: prove a live collector blocks on a full pipe.

Unarmed (default) the runner self-tests offline: the full
stall choreography against a record-shaped stand-in
producer, a live closed-fd EPIPE control proving the judge
tells EPIPE apart from backpressure, and synthetic judge
cases for every FAIL reason. No boot, no privileges.

Armed (MEMVEIL_VM_OUTPUT_STALL=1 with --binary/--out) the
runner boots one guest, stalls the binary under test on
its own full stdout pipe, and re-derives the verdict
host-side from the exported observations. Standalone:
`python3 tests/vm/test_output_stall.py [--self-test]`.
"""

import fcntl
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import output_stall_core as core

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "output_stall_guest.py"
ARM_ENV = "MEMVEIL_VM_OUTPUT_STALL"

# The export inventory is single-sourced from
# output_stall_core.expected_exports (shared with the guest
# producer); this module never lists export names itself.


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check(name, cond, detail=""):
    print("%s %s %s" % ("ok" if cond else "FAIL", name,
                        detail if not cond else ""))
    return bool(cond)


# -- Unarmed self-test --------------------------------------------

def self_test_live_stall(tmp):
    """Full choreography vs the stand-in; every check must pass."""
    parent = os.path.join(tmp, "stall")
    os.mkdir(parent)
    argv = [sys.executable, str(REPO / "tests" / "vm"
                               / "output_stall_core.py"),
           "standin", "--output",
           os.path.join(parent, "cap"), "--duration", "3",
           "--events", "200"]
    obs = core.run_stall(argv, parent, ready_timeout=30.0,
                         block_timeout=60.0, hold_seconds=2.0,
                         hold_samples=5,
                         stderr_path=os.path.join(
                             parent, "record.stderr"))
    judged = core.judge_stall(obs, require_growth=True)
    capture = core.verify_capture(obs["cap_dir"])
    cleanup = core.verify_cleanup(obs["cap_dir"])
    ok = True
    ok = check("stall-judge", judged["verdict"] == "PASS",
               "; ".join(judged["reasons"])) and ok
    ok = check("stall-growth",
               (obs["size_at_blocked"] or 0)
               > (obs["size_at_ready"] or 0)) and ok
    ok = check("stall-wchan",
               len(obs["hold"]) == 5
               and all(s["wchan"] in core.PIPE_WCHANS
                       for s in obs["hold"])
               and all(s["alive"] for s in obs["hold"])) and ok
    ok = check("stall-capture", capture["ok"],
               "; ".join(capture["reasons"])) and ok
    ok = check("stall-cleanup", cleanup["ok"],
               "; ".join(cleanup["reasons"])) and ok
    ok = check("stall-exit", obs["exit_code"] == 0) and ok
    return ok


def self_test_epipe_control(tmp):
    """Closed read end: EPIPE shape, and the judge refuses it."""
    parent = os.path.join(tmp, "epipe")
    os.mkdir(parent)
    cap = os.path.join(parent, "cap")
    argv = [sys.executable, str(REPO / "tests" / "vm"
                               / "output_stall_core.py"),
           "standin", "--output", cap, "--duration", "1",
           "--events", "10"]
    rfd, wfd = os.pipe()
    os.close(rfd)  # The control: no reader, ever.
    err_path = os.path.join(parent, "record.stderr")
    with open(err_path, "wb") as err_handle:
        child = subprocess.Popen(argv, stdout=wfd,
                                 stderr=err_handle,
                                 stdin=subprocess.DEVNULL,
                                 close_fds=True,
                                 start_new_session=True)
    os.close(wfd)
    try:
        exit_code = child.wait(timeout=30)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=15)
        return check("epipe-exit", False, "stand-in hung")
    with open(err_path, "rb") as handle:
        stderr_text = handle.read().decode("utf-8", "replace")
    ok = True
    ok = check("epipe-exit", exit_code == 1,
               "exit %s" % (exit_code,)) and ok
    ok = check("epipe-marker",
               "cannot write stdout" in stderr_text) and ok
    # The same observations through the judge must FAIL as
    # EPIPE, never pass as a stall.
    judged = core.judge_stall(
        {"ready_ok": False, "filler_bytes": 0,
         "hold_stable": False, "hold": [],
         "session_while_blocked": False,
         "filler_intact": False, "done_ok": False,
         "tail_after_done": 0, "exit_code": exit_code,
         "stderr_tail": stderr_text[-2000:],
         "epipe_markers": True})
    ok = check("epipe-judged",
               judged["verdict"] == "FAIL"
               and any("EPIPE" in r
                       for r in judged["reasons"]),
               "; ".join(judged["reasons"])) and ok
    return ok


def self_test_judge_cases():
    """Every FAIL reason fires on its own synthetic trigger."""
    base = {"ready_ok": True, "filler_bytes": 65536,
            "hold_stable": True,
            "hold": [{"alive": True, "wchan": "pipe_write"}],
            "session_while_blocked": True,
            "filler_intact": True, "done_ok": True,
            "tail_after_done": 0, "exit_code": 0,
            "stderr_tail": "", "epipe_markers": False,
            "size_at_ready": 10, "size_at_blocked": 20}
    cases = [
        ("ready", {"ready_ok": False}, "readiness"),
        ("fill", {"filler_bytes": 0}, "full"),
        ("hold", {"hold_stable": False, "hold": [],
                  "exit_code": None}, "blocked hold"),
        ("early-exit", {"hold_stable": False, "hold": [],
                        "exit_code": 2, "done_ok": False},
         "never fired"),
        ("session", {"session_while_blocked": False},
         "durable"),
        ("filler", {"filler_intact": False}, "filler"),
        ("done", {"done_ok": False}, "summary"),
        ("tail", {"tail_after_done": 3}, "extra"),
        ("exit", {"exit_code": 1}, "exit 1"),
        ("stderr", {"stderr_tail": "x cannot write stdout\n"},
         "EPIPE"),
        ("growth", {"size_at_blocked": 10}, "grow"),
    ]
    ok = True
    sanity = core.judge_stall(dict(base), require_growth=True)
    ok = check("judge-sanity",
               sanity["verdict"] == "PASS",
               "; ".join(sanity["reasons"])) and ok
    for name, delta, want in cases:
        obs = dict(base)
        obs.update(delta)
        judged = core.judge_stall(obs, require_growth=True)
        hit = judged["verdict"] == "FAIL" and any(
            want in r for r in judged["reasons"])
        ok = check("judge-%s" % name, hit,
                   "; ".join(judged["reasons"])) and ok
    return ok


def self_test_capture_cases(tmp):
    """Capture/cleanup verifiers accept good trees, refuse bad ones."""
    parent = os.path.join(tmp, "capture")
    os.mkdir(parent)
    good = os.path.join(parent, "good")
    os.mkdir(good)
    raw = b'{"seq": 0}\n{"seq": 1}\n'
    with open(os.path.join(good, "events.ndjson"), "wb") as fh:
        fh.write(raw)
    session = {"capture": {"integrity": {
        "events_sha256": hashlib.sha256(raw).hexdigest(),
        "line_count": "2",
        "events_bytes": str(len(raw))}}}
    with open(os.path.join(good, "session.json"), "w") as fh:
        fh.write(json.dumps(session))
    ok = True
    ok = check("capture-good",
               core.verify_capture(good)["ok"]) and ok
    ok = check("cleanup-good",
               core.verify_cleanup(good)["ok"]) and ok
    bad = os.path.join(parent, "bad")
    shutil.copytree(good, bad)
    with open(os.path.join(bad, "events.ndjson"), "ab") as fh:
        fh.write(b"corrupt\n")
    Path(os.path.join(bad, "checkpoint.json")).write_text("{}")
    bad_cap = core.verify_capture(bad)
    bad_clean = core.verify_cleanup(bad)
    ok = check("capture-corrupt", not bad_cap["ok"]
               and not bad_cap["sha_match"]) and ok
    ok = check("cleanup-leftover", not bad_clean["ok"]
               and "checkpoint.json"
               in bad_clean["leftovers"]) and ok
    missing = os.path.join(parent, "missing")
    os.mkdir(missing)
    ok = check("capture-missing",
               not core.verify_capture(missing)["ok"]) and ok
    return ok


def run_self_test(work=None):
    print("output-stall self-test (unarmed, offline)")
    tmp = work or tempfile.mkdtemp(prefix="vmgate-outstall-")
    os.makedirs(tmp, exist_ok=True)
    keep = work is not None
    ok = True
    try:
        ok = self_test_live_stall(tmp) and ok
        ok = self_test_epipe_control(tmp) and ok
        ok = self_test_judge_cases() and ok
        ok = self_test_capture_cases(tmp) and ok
        ok = self_test_boot_guards(tmp) and ok
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print("output-stall self-test: %s"
          % ("PASS" if ok else "FAIL"))
    return ok


def self_test_boot_guards(tmp):
    """Boot assembly refuses shell rewrites before spawning."""
    from types import SimpleNamespace
    from unittest import mock
    ok = True

    def make_args(kver):
        return SimpleNamespace(
            duration=15, capability="attempt-trace",
            profiles_dir="", no_stimulus=False, kver=kver,
            timeout=900, binary_sha256="ab" * 32)

    flight = {"prefix": ["vng"], "harness": {}}
    for num, evil in enumerate(("v7.0.14 x", "v7.0.14;touch x",
                                "v7.0.14$(touch x)", "../evil")):
        with mock.patch("vm_process.run_owned_guest") as spawned:
            try:
                armed_boot(make_args(evil), "/tmp/x/memveil",
                           flight)
                ok = check("boot-kver-%d" % num, False,
                           "accepted %r" % evil) and ok
            except ValueError:
                ok = check("boot-kver-%d" % num,
                           spawned.call_count == 0,
                           "spawned") and ok
    hostile = os.path.join(tmp, 't"mp')
    os.mkdir(hostile)
    with mock.patch("vm_process.run_owned_guest") as spawned, \
         mock.patch.dict(os.environ, {"TMPDIR": hostile}), \
         mock.patch.object(tempfile, "tempdir", None):
        try:
            armed_boot(make_args("v7.0.14"), "/tmp/x/memveil",
                       flight)
            ok = check("boot-tmpdir", False, "accepted") and ok
        except ValueError:
            ok = check("boot-tmpdir", spawned.call_count == 0,
                       "spawned") and ok
    with mock.patch("vm_process.run_owned_guest") as spawned:
        spawned.side_effect = ValueError("sentinel-reached-boot")
        try:
            armed_boot(make_args("v7.0.14"), "/tmp/x/memveil",
                       flight)
            ok = check("boot-honest", False,
                       "no sentinel") and ok
        except ValueError as exc:
            ok = check("boot-honest",
                       str(exc) == "sentinel-reached-boot"
                       and spawned.call_count == 1,
                       str(exc)) and ok
    return ok


# -- Armed run ----------------------------------------------------

def armed_preflight():
    """Resolve vng + harness versions; armed failures are fatal."""
    from test_attempt_capture import find_vng, gate_prefix
    from harness_env import check_harness_versions
    vng = find_vng()
    if not vng:
        print("FAIL vm-output-stall: armed but vng missing")
        return None
    try:
        harness = check_harness_versions(vng)
    except ValueError as exc:
        print("FAIL vm-output-stall: armed but %s" % (exc,))
        return None
    try:
        prefix, _env = gate_prefix()
    except Exception as exc:  # pytest.skip/fail raise here
        print("FAIL vm-output-stall: armed but %s" % (exc,))
        return None
    return {"vng": vng, "harness": harness, "prefix": prefix}


def verify_exports(export, stimulus_enabled=True):
    """Exact inventory + sidecar check; returns {ok, files, reasons}.

    The expected set comes from the canonical inventory shared
    with the guest producer; stimulus.cmd is expected only
    with stimulus on. Unknown, missing, or sidecar-tampered
    files still refuse.
    """
    result = {"ok": False, "files": {}, "reasons": []}
    names = core.expected_exports(stimulus_enabled)
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        result["reasons"].append("export unreadable: %s" % (exc,))
        return result
    want = set(names) | \
        {"%s.sha256" % n for n in names}
    if have != want:
        result["reasons"].append(
            "export inventory drift: %s"
            % sorted(have ^ want))
        return result
    for name in names:
        path = export / name
        sidecar = export / ("%s.sha256" % name)
        try:
            digest = sha_file(path)
            text = sidecar.read_text().strip()
        except OSError as exc:
            result["reasons"].append(
                "%s unreadable: %s" % (name, exc))
            return result
        if text != "%s  %s" % (digest, name):
            result["reasons"].append(
                "%s sidecar mismatch" % name)
            return result
        result["files"][name] = path
    result["ok"] = True
    return result


def armed_run(args):
    if not args.binary or not args.binary_sha256 \
            or not args.out:
        print("FAIL vm-output-stall: armed needs --binary, "
              "--binary-sha256, --out")
        return 1
    binary = os.path.abspath(args.binary)
    if not os.path.isfile(binary):
        print("FAIL vm-output-stall: binary missing: %s"
              % binary)
        return 1
    if sha_file(binary) != args.binary_sha256:
        print("FAIL vm-output-stall: binary digest mismatch")
        return 1
    flight = armed_preflight()
    if flight is None:
        return 1
    lock_dir = REPO / "build" / "vm"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("FAIL vm-output-stall: lock dir failed: %s"
              % (exc,))
        return 1
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        print("FAIL vm-output-stall: VM suite lease already "
              "owned; one live executor at a time")
        return 1
    try:
        return armed_boot(args, binary, flight)
    finally:
        lease.close()


def armed_boot(args, binary, flight):
    from vm_process import run_owned_guest
    from capture_durability import check_shell_inert_path
    from kernel_matrix import validate_vng_token
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-outstall-"))
    export = tmp / "export"
    export.mkdir()
    # The export reaches the launcher command raw, so its
    # spelling is gated before the boot is assembled.
    check_shell_inert_path(export, "export path")
    work = "/tmp/vmgate-work"
    bpftrace = shutil.which("bpftrace") or ""
    bpftool = shutil.which("bpftool") or ""
    guest_argv = ["env", "MEMVEIL_VM_OUTPUT_STALL_GUEST=1",
                  sys.executable, str(GUEST), work,
                  "/tmp/export", "--binary", binary,
                  "--duration", str(args.duration),
                  "--capability", args.capability,
                  "--bpftrace", bpftrace, "--bpftool", bpftool]
    if args.profiles_dir:
        guest_argv += ["--profiles-dir",
                       os.path.abspath(args.profiles_dir)]
    if args.no_stimulus:
        guest_argv += ["--no-stimulus"]
    run = ["--run"]
    if args.kver:
        # An empty selector keeps the bare-host --run shape;
        # anything else must be a plain release token.
        validate_vng_token(args.kver, "kernel selector")
        run += [args.kver]
    cmd = flight["prefix"] + run + [
        "-m", "6G",
        "--append", "swiotlb=force",
        "--disable-microvm",
        "--network", "user",
        "--qemu-opts=-cpu host",
        "--qemu-opts=-device pcnet,netdev=pcnet0"
        " -netdev user,id=pcnet0,net=10.0.3.0/24",
        "--rwdir=/tmp/export=%s" % (export,),
        "--exec", shlex.join(guest_argv),
    ]
    (tmp / "boot.json").write_text(json.dumps(
        {"cmd": cmd, "binary": binary,
         "binary_sha256": args.binary_sha256,
         "harness": flight["harness"]},
        indent=2, sort_keys=True) + "\n")
    try:
        proc = run_owned_guest(cmd, timeout=args.timeout)
    except subprocess.TimeoutExpired:
        print("FAIL vm-output-stall: guest timed out; "
              "artifacts kept at %s" % (tmp,))
        return 1
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        print("FAIL vm-output-stall: guest exit %d; "
              "artifacts kept at %s"
              % (proc.returncode, tmp))
        return 1
    stimulus_on = not args.no_stimulus
    verified = verify_exports(export, stimulus_on)
    if not verified["ok"]:
        print("FAIL vm-output-stall: %s; artifacts kept at %s"
              % ("; ".join(verified["reasons"]), tmp))
        return 1
    try:
        stall = json.loads(
            verified["files"]["stall.json"].read_text())
        guest_verdict = json.loads(
            verified["files"]["verdict.json"].read_text())
    except ValueError as exc:
        print("FAIL vm-output-stall: exports unparsable (%s); "
              "artifacts kept at %s" % (exc, tmp))
        return 1
    # Host re-derivation: the verdict is recomputed here
    # from the exported observations, never trusted blindly.
    obs = stall.get("observations", {})
    rejudged = core.judge_stall(obs, require_growth=False)
    capture = json.loads(
        verified["files"]["capture.json"].read_text())
    cleanup = json.loads(
        verified["files"]["cleanup.json"].read_text())
    attach = json.loads(
        verified["files"]["attach.json"].read_text())
    report = json.loads(
        verified["files"]["report.json"].read_text())
    reasons = list(rejudged["reasons"])
    if not capture.get("ok"):
        reasons.append("capture cross-check failed")
    if not cleanup.get("ok"):
        reasons.append("owned cleanup failed")
    if not attach.get("ok"):
        reasons.append("no independent attach proof")
    if report.get("exit") != 0 \
            or not report.get("stdout_bytes"):
        reasons.append("report readback failed")
    host_verdict = "PASS" if not reasons else "FAIL"
    if guest_verdict.get("verdict") != host_verdict:
        reasons.append("host re-derivation disagrees with "
                       "guest verdict %r"
                       % (guest_verdict.get("verdict"),))
        host_verdict = "FAIL"
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        for name in core.expected_exports(stimulus_on):
            shutil.copy2(verified["files"][name], out / name)
            shutil.copy2(export / ("%s.sha256" % name),
                         out / ("%s.sha256" % name))
        for name in ("boot.json", "guest.stdout",
                     "guest.stderr", "guest.exit"):
            shutil.copy2(tmp / name, out / ("host-%s" % name))
        (out / "host-verdict.json").write_text(json.dumps(
            {"verdict": host_verdict, "reasons": reasons,
             "rejudged": rejudged,
             "guest_verdict": guest_verdict.get("verdict"),
             "binary_sha256": args.binary_sha256},
            indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        print("FAIL vm-output-stall: receipt failed (%s); "
              "artifacts kept at %s" % (exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-output-stall: guest tmp kept at %s" % (tmp,))
    if host_verdict != "PASS":
        print("FAIL vm-output-stall: %s" % ("; ".join(reasons),))
        return 1
    print("ok vm-output-stall PASS (%s)" % (out,))
    print("ok vm-output-stall filler=%s drain-intact=%s "
          "hold=%d exit=%s events=%s"
          % (obs.get("filler_bytes"),
             obs.get("filler_intact"), len(obs.get("hold", [])),
             obs.get("exit_code"),
             capture.get("events_lines")))
    return 0


# -- pytest entry points ------------------------------------------

def test_self_test_unarmed(tmp_path):
    assert run_self_test(work=str(tmp_path / "self"))


def _write_export_shape(export, names):
    """Build a well-formed export dir: names + valid sidecars."""
    export.mkdir(parents=True, exist_ok=True)
    for name in names:
        path = export / name
        path.write_bytes(b"pinned-%s\n" % name.encode())
        (export / ("%s.sha256" % name)).write_text(
            "%s  %s\n" % (sha_file(path), name))


def test_verify_exports_matches_armed_guest_shape(tmp_path):
    """The gate accepts the REAL armed export shape (stimulus on).

    Literal pin of every data file output_stall_guest.py writes
    to its out dir with stimulus on (job.json, artifacts.json,
    the verdict/stall/capture/cleanup/attach/report/
    stimulus.json dict, record.stdout, record.stderr,
    stimulus.log, plus stimulus.cmd written next to the flood
    launch); the whole dir is then copied out with sidecars.
    The unarmed self-test never ran this gate, so the missing
    stimulus.cmd entry hid until the armed run refused with
    "export inventory drift". The gate derives its expectation
    from output_stall_core.expected_exports, so this literal
    pin locks that definition too: any drift either way
    refuses the pinned shape. Extra, missing, and
    sidecar-tampered exports must still refuse.
    """
    armed_shape = ("verdict.json", "stall.json", "capture.json",
                   "cleanup.json", "attach.json",
                   "artifacts.json", "report.json",
                   "stimulus.json", "record.stdout",
                   "record.stderr", "stimulus.log", "job.json",
                   "stimulus.cmd")
    off_shape = tuple(n for n in armed_shape
                      if n != "stimulus.cmd")
    # The armed shape passes (this refused pre-fix with the
    # exact armed "export inventory drift" failure).
    export = tmp_path / "export"
    _write_export_shape(export, armed_shape)
    verified = verify_exports(export)
    assert verified["ok"], verified["reasons"]
    assert sorted(verified["files"]) == sorted(armed_shape)
    # Stimulus-off runs export the 12-file shape, in both
    # directions: accepted with the flag off, refused with it
    # on (missing stimulus.cmd), and the 13-file shape is
    # refused with the flag off (extra stimulus.cmd).
    off = tmp_path / "off"
    _write_export_shape(off, off_shape)
    assert verify_exports(off, False)["ok"]
    refused = verify_exports(off)
    assert not refused["ok"] and any(
        "stimulus.cmd" in r for r in refused["reasons"])
    refused = verify_exports(export, False)
    assert not refused["ok"] and any(
        "stimulus.cmd" in r for r in refused["reasons"])
    # Unknown/extra files still refuse.
    extra = tmp_path / "extra"
    _write_export_shape(extra, armed_shape + ("evil.json",))
    refused = verify_exports(extra)
    assert not refused["ok"] and any(
        "drift" in r for r in refused["reasons"])
    # Missing files still refuse.
    missing = tmp_path / "missing"
    _write_export_shape(missing, off_shape)
    (missing / "job.json").unlink()
    (missing / "job.json.sha256").unlink()
    refused = verify_exports(missing, False)
    assert not refused["ok"] and any(
        "drift" in r for r in refused["reasons"])
    # Sidecar tamper still refuses.
    tampered = tmp_path / "tampered"
    _write_export_shape(tampered, armed_shape)
    (tampered / "job.json").write_bytes(b"tampered\n")
    refused = verify_exports(tampered)
    assert not refused["ok"] and any(
        "sidecar mismatch" in r for r in refused["reasons"])


def test_armed_output_stall():
    import pytest
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip("output-stall armed run needs MEMVEIL_VM_OUTPUT_STALL=1")

    class Args:
        pass
    args = Args()
    args.binary = os.environ.get("MV_OUTPUT_STALL_BINARY", "")
    args.binary_sha256 = os.environ.get(
        "MV_OUTPUT_STALL_BINARY_SHA256", "")
    args.out = os.environ.get(
        "MV_OUTPUT_STALL_OUT",
        str(REPO / "build" / "vm" / "output-stall"))
    args.duration = int(os.environ.get(
        "MV_OUTPUT_STALL_DURATION", "15"))
    args.capability = os.environ.get(
        "MV_OUTPUT_STALL_CAPABILITY", "attempt-trace")
    args.profiles_dir = os.environ.get(
        "MV_OUTPUT_STALL_PROFILES_DIR", "")
    args.kver = os.environ.get("MV_OUTPUT_STALL_KVER", "")
    args.timeout = int(os.environ.get(
        "MV_OUTPUT_STALL_TIMEOUT", "900"))
    args.no_stimulus = os.environ.get(
        "MV_OUTPUT_STALL_NO_STIMULUS", "0") == "1"
    args.keep = True
    assert armed_run(args) == 0


def parse_cli(argv):
    import argparse
    parser = argparse.ArgumentParser(
        description="Output-stall gate: unarmed self-test by "
        "default; armed guest run with %s=1." % ARM_ENV)
    parser.add_argument("--self-test", action="store_true",
                        help="run the offline self-test")
    parser.add_argument("--binary", default="",
                        help="binary under test (armed)")
    parser.add_argument("--binary-sha256", default="",
                        help="expected binary digest (armed)")
    parser.add_argument("--out", default="",
                        help="receipt dir (armed)")
    parser.add_argument("--duration", type=int, default=15,
                        help="record window seconds (armed)")
    parser.add_argument("--capability", default="attempt-trace")
    parser.add_argument("--profiles-dir", default="")
    parser.add_argument("--kver", default="",
                        help="vng kernel selector, else host")
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--no-stimulus", action="store_true")
    parser.add_argument("--keep", action="store_true")
    return parser.parse_args(argv)


def main(argv):
    args = parse_cli(argv)
    if os.environ.get(ARM_ENV) == "1" and not args.self_test:
        return armed_run(args)
    return 0 if run_self_test() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
