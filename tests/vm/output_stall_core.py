#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shared output-stall choreography for the blocked-output gate.

A collector whose only stdout traffic is one readiness line plus
one final summary line cannot be backpressured mid-stream on
stdout: the stall lands on the final summary write. This module
drives that stall honestly: it observes readiness first (the
collector is live and attached), then fills the stdout pipe
itself until the kernel refuses more bytes, proves the
collector blocks in that full pipe (alive, no exit, pipe_write
wait channel, final session already durable on disk), and only
then drains the pipe and judges the capture.

Blocking on a full pipe with an open reader is structurally
distinct from a closed-fd EPIPE: no read end ever closes here,
so a write cannot fail with EPIPE; it can only block. The
judge still checks the EPIPE markers (early exit, "cannot
write stdout" on stderr, missing summary) so a run where the
fault never fired cannot pass as a stall.

Both the host-side unarmed self-test (against the stand-in
producer below) and the guest-side armed run (against the
real record binary) use this module, so the choreography,
the judging bar, and the capture/cleanup checks are one
implementation. Linux-only (/proc wait-channel proof).
"""

import errno
import fcntl
import hashlib
import json
import os
import re
import select
import signal
import subprocess
import sys
import time

# Record stdout grammar, shared with the export validator
# (tests/vm/export_validation.py): exactly one readiness line
# plus exactly one final summary line.
READY_RE = re.compile(r"ready session=[A-Za-z0-9_.-]+ start_ns=\d+$")
DONE_RE = re.compile(
    r"record: end=(duration|signal) outcome=finalized exit=0$")

# Wait channels that prove a sleep inside a pipe write.
# Older kernels report pipe_write (sometimes pipe_w); current
# kernels sleep in anon_pipe_write (observed on 7.2.13, whose
# /proc/PID/stack top frame is anon_pipe_write+...).
PIPE_WCHANS = ("pipe_write", "pipe_w", "anon_pipe_write")

# Deterministic filler: the drain must reproduce these exact
# bytes ahead of the summary line (FIFO order).
FILLER_UNIT = b"OUTPUT-STALL-FILLER:"
FILLER_CHUNK = FILLER_UNIT * (65536 // len(FILLER_UNIT))

# Files a normally finalized capture must not leave behind.
FINALIZE_LEFT_OVERS = ("checkpoint.json", ".finalization-reserve",
                       "session.finalizing")

# Canonical output-stall export inventory, shared by the guest
# producer (output_stall_guest.py) and the host gate
# (test_output_stall.py) so the two cannot drift apart. The
# guest writes exactly expected_exports(stimulus) data files
# into its out dir (plus one .sha256 sidecar each) and the
# host refuses anything else. stimulus.cmd exists only with
# stimulus on: the guest writes it next to the flood launch.
EXPORT_ALWAYS = ("verdict.json", "stall.json", "capture.json",
                 "cleanup.json", "attach.json",
                 "artifacts.json", "report.json",
                 "stimulus.json", "record.stdout",
                 "record.stderr", "stimulus.log", "job.json")
EXPORT_STIMULUS_ONLY = ("stimulus.cmd",)


def expected_exports(stimulus_enabled=True):
    """Export data-file names for one stimulus mode, in order."""
    if stimulus_enabled:
        return EXPORT_ALWAYS + EXPORT_STIMULUS_ONLY
    return tuple(EXPORT_ALWAYS)


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_line_exact(rfd, timeout_s):
    """Read one newline-terminated line, byte-exact, with a deadline.

    Returns the line without the newline, or None on timeout
    or EOF before any byte. Unbuffered: never consumes past
    the newline, so the pipe fill measurement stays exact.
    """
    end = time.monotonic() + timeout_s
    line = bytearray()
    while True:
        remain = end - time.monotonic()
        if remain <= 0:
            return None
        ready, _, _ = select.select([rfd], [], [], remain)
        if not ready:
            return None
        try:
            byte = os.read(rfd, 1)
        except OSError:
            return None
        if not byte:
            return None
        if byte == b"\n":
            return bytes(line)
        line += byte


def fill_pipe_to_full(wfd):
    """Write filler until the kernel reports the pipe full.

    Returns (byte_count, sha256). A positive count with the
    kernel refusing more is the proof the pipe is full; the
    caller holds the read end open throughout, so a later
    producer write can block but never fail with EPIPE.
    """
    flags = fcntl.fcntl(wfd, fcntl.F_GETFL)
    fcntl.fcntl(wfd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
    total = 0
    digest = hashlib.sha256()
    try:
        while True:
            try:
                nwritten = os.write(wfd, FILLER_CHUNK)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno == errno.EAGAIN:
                    break
                raise
            if nwritten <= 0:
                break
            total += nwritten
            digest.update(FILLER_CHUNK[:nwritten])
    finally:
        fcntl.fcntl(wfd, fcntl.F_SETFL, flags)
    return total, digest.hexdigest()


def sample_process(pid):
    """One /proc sample: alive, state, wait channel, pipe stack."""
    sample = {"alive": False, "state": "", "wchan": "",
              "stack_pipe_write": False, "stack_readable": False}
    try:
        with open("/proc/%d/stat" % pid, "rb") as handle:
            stat = handle.read()
    except OSError:
        return sample
    sample["alive"] = True
    try:
        after = stat.rsplit(b") ", 1)[1]
        sample["state"] = after.split()[0].decode("ascii", "replace")
    except (IndexError, ValueError):
        pass
    try:
        with open("/proc/%d/wchan" % pid, "rb") as handle:
            wchan = handle.read().decode("ascii", "replace").strip()
        sample["wchan"] = "" if wchan == "0" else wchan
    except OSError:
        pass
    try:
        with open("/proc/%d/stack" % pid, "rb") as handle:
            stack = handle.read().decode("ascii", "replace")
        sample["stack_readable"] = True
        sample["stack_pipe_write"] = "pipe_write" in stack
    except OSError:
        pass
    return sample


def session_finalized(cap_dir):
    """True when session.json exists with a usable integrity block."""
    path = os.path.join(cap_dir, "session.json")
    try:
        with open(path, "rb") as handle:
            doc = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError):
        return False
    integrity = ((doc.get("capture") or {}).get("integrity")
                 if isinstance(doc, dict) else None)
    return (isinstance(integrity, dict)
            and isinstance(integrity.get("events_sha256"), str)
            and len(integrity["events_sha256"]) == 64)


def events_size(cap_dir):
    try:
        return os.path.getsize(os.path.join(cap_dir, "events.ndjson"))
    except OSError:
        return None


def run_stall(producer_argv, cap_parent, cap_name="cap",
              ready_timeout=120.0, block_timeout=120.0,
              hold_seconds=5.0, hold_samples=10,
              drain_timeout=60.0, stderr_path=None,
              observe=None):
    """Stall one producer on its own full stdout pipe.

    producer_argv runs a record-shaped producer: one
    readiness line on stdout, a capture tree under
    cap_parent/cap_name, one summary line on stdout, then
    exit. observe(phase, obs), when given, runs at "ready"
    and "blocked" (guest attach proof hooks).
    Returns a JSON-serializable observations dict; never
    raises for producer behavior (infra failures raise).
    """
    cap_dir = os.path.join(cap_parent, cap_name)
    if stderr_path is None:
        stderr_path = os.path.join(cap_parent, "record.stderr")
    obs = {"cap_dir": cap_dir, "ready_line": "",
           "ready_ok": False, "filler_bytes": 0,
           "filler_sha256": "", "size_at_ready": None,
           "size_at_blocked": None, "blocked_entry_s": None,
           "hold": [], "hold_stable": False,
           "session_while_blocked": False,
           "drained_filler_sha256": "", "filler_intact": False,
           "done_line": "", "done_ok": False,
           "tail_after_done": 0, "exit_code": None,
           "stderr_path": stderr_path or "",
           "stderr_tail": "", "epipe_markers": False}
    rfd, wfd = os.pipe()
    err_handle = open(stderr_path, "wb")
    child = None
    t0 = time.monotonic()
    try:
        child = subprocess.Popen(
            producer_argv, stdout=wfd, stderr=err_handle,
            stdin=subprocess.DEVNULL, close_fds=True,
            start_new_session=True)
        ready = read_line_exact(rfd, ready_timeout)
        if ready is None:
            obs["exit_code"] = child.poll()
            obs["stderr_tail"] = read_stderr_tail(
                stderr_path, err_handle)
            obs["epipe_markers"] = obs["exit_code"] == 1 and \
                "cannot write stdout" in obs["stderr_tail"]
            return obs
        try:
            obs["ready_line"] = ready.decode("utf-8")
        except ValueError:
            return obs
        obs["ready_ok"] = bool(READY_RE.match(obs["ready_line"]))
        if not obs["ready_ok"]:
            return obs
        obs["size_at_ready"] = events_size(cap_dir)
        if observe is not None:
            observe("ready", obs)
        # The read end stays open from here until the drain
        # completes: the pipe is full, so the summary write
        # must block. Nothing here can produce EPIPE.
        total, digest = fill_pipe_to_full(wfd)
        obs["filler_bytes"] = total
        obs["filler_sha256"] = digest
        if total <= 0:
            return obs
        deadline = time.monotonic() + block_timeout
        while time.monotonic() < deadline:
            sample = sample_process(child.pid)
            if not sample["alive"]:
                obs["exit_code"] = child.poll()
                obs["stderr_tail"] = read_stderr_tail(
                    stderr_path, err_handle)
                return obs
            if session_finalized(cap_dir) and \
                    sample["wchan"] in PIPE_WCHANS:
                break
            time.sleep(0.2)
        else:
            return obs
        obs["blocked_entry_s"] = time.monotonic() - t0
        obs["size_at_blocked"] = events_size(cap_dir)
        obs["session_while_blocked"] = True
        if observe is not None:
            observe("blocked", obs)
        interval = hold_seconds / max(hold_samples, 1)
        for _ in range(hold_samples):
            time.sleep(interval)
            sample = sample_process(child.pid)
            obs["hold"].append(sample)
            if not sample["alive"]:
                obs["exit_code"] = child.poll()
                obs["stderr_tail"] = read_stderr_tail(
                    stderr_path, err_handle)
                return obs
        obs["hold_stable"] = bool(obs["hold"]) and all(
            s["wchan"] in PIPE_WCHANS for s in obs["hold"])
        drained = bytearray()
        done = None
        end = time.monotonic() + drain_timeout
        while time.monotonic() < end:
            remain = end - time.monotonic()
            ready_fds, _, _ = select.select([rfd], [], [],
                                            max(remain, 0))
            if not ready_fds:
                break
            chunk = os.read(rfd, 65536)
            if not chunk:
                break
            drained += chunk
            if b"\n" in drained[total:]:
                break
        filler_part = bytes(drained[:total])
        rest = bytes(drained[total:])
        expect = hashlib.sha256()
        remaining = total
        while remaining > 0:
            piece = FILLER_CHUNK[:min(len(FILLER_CHUNK),
                                      remaining)]
            expect.update(piece)
            remaining -= len(piece)
        obs["drained_filler_sha256"] = sha_bytes(filler_part)
        obs["filler_intact"] = (
            len(filler_part) == total
            and obs["drained_filler_sha256"] == expect.hexdigest())
        if b"\n" in rest:
            done, _, tail = rest.partition(b"\n")
            try:
                obs["done_line"] = done.decode("utf-8")
            except ValueError:
                obs["done_line"] = ""
            obs["done_ok"] = bool(DONE_RE.match(obs["done_line"]))
            obs["tail_after_done"] = len(tail)
        os.close(wfd)
        wfd = None
        try:
            obs["exit_code"] = child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            obs["exit_code"] = None
            return obs
        while True:
            ready_fds, _, _ = select.select([rfd], [], [], 5)
            if not ready_fds:
                break
            chunk = os.read(rfd, 65536)
            if not chunk:
                break
            obs["tail_after_done"] += len(chunk)
        obs["stderr_tail"] = read_stderr_tail(stderr_path,
                                              err_handle)
        obs["epipe_markers"] = obs["exit_code"] == 1 and \
            "cannot write stdout" in obs["stderr_tail"]
        return obs
    finally:
        for fd in (rfd, wfd):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if err_handle is not None:
            try:
                err_handle.close()
            except OSError:
                pass
        if child is not None and child.poll() is None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            try:
                child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                pass


def read_stderr_tail(stderr_path, err_handle):
    if err_handle is not None:
        try:
            err_handle.flush()
        except OSError:
            pass
    if not stderr_path:
        return ""
    try:
        with open(stderr_path, "rb") as handle:
            data = handle.read()
    except OSError:
        return ""
    try:
        text = data.decode("utf-8", "replace")
    except ValueError:
        return ""
    return text[-2000:]


def judge_stall(obs, require_growth=False):
    """Judge stalled-run observations. Returns {verdict, reasons, checks}.

    PASS needs every check: readiness observed, a provably
    full pipe, a stable blocked hold with the final session
    already durable, an intact drain with the exact summary,
    a clean finalized exit, and (optionally) capture growth
    across the stall. Anything else FAILs with the concrete
    reason, including the EPIPE shape (early exit 1 with the
    stdout marker) so a fault that never fired cannot pass.
    """
    checks = {}
    reasons = []
    checks["ready_ok"] = bool(obs.get("ready_ok"))
    if not checks["ready_ok"]:
        reasons.append("no readiness line before the stall")
    checks["filler_positive"] = \
        (obs.get("filler_bytes") or 0) > 0
    if not checks["filler_positive"]:
        reasons.append("pipe never proven full")
    checks["hold_stable"] = bool(obs.get("hold_stable")) and \
        len(obs.get("hold") or []) > 0
    if not checks["hold_stable"]:
        if obs.get("exit_code") is not None and \
                not obs.get("done_ok"):
            reasons.append(
                "collector exited before backpressure "
                "(exit %s): fault never fired"
                % (obs.get("exit_code"),))
        else:
            reasons.append("no stable blocked hold on the pipe")
    checks["session_while_blocked"] = \
        bool(obs.get("session_while_blocked"))
    if not checks["session_while_blocked"]:
        reasons.append("final session not durable while blocked")
    checks["filler_intact"] = bool(obs.get("filler_intact"))
    if not checks["filler_intact"]:
        reasons.append("drained filler does not match what filled")
    checks["done_ok"] = bool(obs.get("done_ok"))
    if not checks["done_ok"]:
        reasons.append("exact summary line missing after drain")
    checks["tail_empty"] = (obs.get("tail_after_done") or 0) == 0
    if not checks["tail_empty"]:
        reasons.append("extra stdout bytes past the summary")
    checks["exit_ok"] = obs.get("exit_code") == 0
    if not checks["exit_ok"]:
        reasons.append("exit %s instead of 0"
                       % (obs.get("exit_code"),))
    checks["stderr_clean"] = \
        "cannot write stdout" not in (obs.get("stderr_tail") or "")
    if not checks["stderr_clean"]:
        reasons.append("EPIPE marker on stderr: closed-fd shape, "
                       "not a stall")
    if obs.get("epipe_markers"):
        reasons.append("EPIPE shape (exit 1, stdout marker): "
                       "read end closed, no backpressure proven")
        checks["exit_ok"] = False
    if require_growth:
        before = obs.get("size_at_ready")
        after = obs.get("size_at_blocked")
        checks["growth_ok"] = (
            isinstance(before, int) and isinstance(after, int)
            and after > before)
        if not checks["growth_ok"]:
            reasons.append("capture did not grow across the stall")
    verdict = "PASS" if all(checks.values()) else "FAIL"
    return {"verdict": verdict, "reasons": reasons,
            "checks": checks}


def verify_capture(cap_dir):
    """Hash/count the capture and cross-check session integrity."""
    result = {"cap_dir": cap_dir, "events_present": False,
              "events_bytes": 0, "events_lines": 0,
              "events_sha256": "", "session_present": False,
              "sha_match": False, "lines_match": False,
              "bytes_match": False, "ok": False, "reasons": []}
    events_path = os.path.join(cap_dir, "events.ndjson")
    try:
        with open(events_path, "rb") as handle:
            raw = handle.read()
    except OSError:
        result["reasons"].append("events.ndjson unreadable")
        return result
    result["events_present"] = True
    result["events_bytes"] = len(raw)
    result["events_lines"] = raw.count(b"\n")
    result["events_sha256"] = sha_bytes(raw)
    session_path = os.path.join(cap_dir, "session.json")
    try:
        with open(session_path, "rb") as handle:
            doc = json.loads(handle.read().decode("utf-8"))
    except (OSError, ValueError):
        result["reasons"].append("session.json unreadable")
        return result
    result["session_present"] = True
    integrity = ((doc.get("capture") or {}).get("integrity")
                 if isinstance(doc, dict) else None)
    if not isinstance(integrity, dict):
        result["reasons"].append("session lacks integrity block")
        return result
    result["sha_match"] = \
        integrity.get("events_sha256") == result["events_sha256"]
    result["lines_match"] = \
        integrity.get("line_count") == str(result["events_lines"])
    result["bytes_match"] = \
        integrity.get("events_bytes") == str(result["events_bytes"])
    if not result["sha_match"]:
        result["reasons"].append("events sha256 mismatch")
    if not result["lines_match"]:
        result["reasons"].append("line count mismatch")
    if not result["bytes_match"]:
        result["reasons"].append("byte count mismatch")
    result["ok"] = result["sha_match"] and result["lines_match"] \
        and result["bytes_match"]
    return result


def verify_cleanup(cap_dir):
    """Confirm finalization leftovers are gone and the lock is free."""
    result = {"cap_dir": cap_dir, "leftovers": [],
              "lock_free": False, "ok": False,
              "reasons": []}
    for name in FINALIZE_LEFT_OVERS:
        if os.path.lexists(os.path.join(cap_dir, name)):
            result["leftovers"].append(name)
    if result["leftovers"]:
        result["reasons"].append(
            "finalization leftovers: %s"
            % ",".join(sorted(result["leftovers"])))
    try:
        dir_fd = os.open(cap_dir, os.O_DIRECTORY)
    except OSError:
        result["reasons"].append("capture dir unopenable")
        return result
    try:
        import fcntl as fcntl_mod
        fcntl_mod.flock(dir_fd,
                        fcntl_mod.LOCK_EX | fcntl_mod.LOCK_NB)
        result["lock_free"] = True
        fcntl_mod.flock(dir_fd, fcntl_mod.LOCK_UN)
    except (OSError, BlockingIOError):
        result["reasons"].append("capture dir still locked")
    finally:
        os.close(dir_fd)
    result["ok"] = not result["leftovers"] and result["lock_free"]
    return result


# -- Stand-in producer (unarmed self-test only) ---------------------

STANDIN_SESSION = "standin-1"


def standin_write(text):
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        # Loud EPIPE mimic (exit 1 + stderr marker, the
        # record shape). _exit: a normal return would flush
        # stdout again at shutdown and mask the exit code.
        try:
            sys.stderr.write("standin: cannot write stdout\n")
            sys.stderr.flush()
        except OSError:
            pass
        os._exit(1)


def run_standin(argv):
    """Mimic record's stdout + capture protocol for harness logic tests.

    Not product behavior: fixed line shapes, a small logic-only
    reserve (not the product 17 MiB), and an EPIPE mimic on
    stdout failure. The armed run proves the real binary.
    """
    output = ""
    duration = 3.0
    events = 200
    line_bytes = 128
    i = 0
    while i < len(argv):
        token = argv[i]
        if token == "--output" and i + 1 < len(argv):
            output = argv[i + 1]
            i += 2
        elif token == "--duration" and i + 1 < len(argv):
            duration = float(argv[i + 1])
            i += 2
        elif token == "--events" and i + 1 < len(argv):
            events = int(argv[i + 1])
            i += 2
        elif token == "--line-bytes" and i + 1 < len(argv):
            line_bytes = int(argv[i + 1])
            i += 2
        else:
            sys.stderr.write("standin: bad arg %r\n" % (token,))
            return 2
    if not output or events < 0 or duration < 0 \
            or line_bytes < 16:
        sys.stderr.write("standin: bad args\n")
        return 2
    try:
        os.mkdir(output, 0o700)
    except FileExistsError:
        sys.stderr.write("standin: output exists\n")
        return 1
    except OSError as exc:
        sys.stderr.write("standin: mkdir failed: %s\n" % (exc,))
        return 1
    dir_fd = os.open(output, os.O_DIRECTORY)
    try:
        fcntl.flock(dir_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        sys.stderr.write("standin: lock unavailable\n")
        os.close(dir_fd)
        return 1
    try:
        # Record order: writer + reserve exist before the
        # readiness line (reserve allocated pre-readiness,
        # events created at writer setup, ready at attach).
        reserve_path = os.path.join(output,
                                    ".finalization-reserve")
        with open(reserve_path, "wb") as reserve:
            reserve.write(b"r" * 1048576)
            reserve.flush()
            os.fsync(reserve.fileno())
        events_path = os.path.join(output, "events.ndjson")
        with open(events_path, "wb") as handle:
            handle.flush()
            os.fsync(handle.fileno())
        standin_write("ready session=%s start_ns=1\n"
                      % (STANDIN_SESSION,))
        gap = (duration / events) if events else 0
        written = 0
        with open(events_path, "wb") as handle:
            for seq in range(events):
                body = '{"seq": %d, "pad": "' % (seq,)
                pad_len = line_bytes - len(body) - 3
                line = (body + "p" * pad_len + '"}\n').encode()
                handle.write(line)
                written += len(line)
                if seq == events // 2:
                    with open(os.path.join(
                            output, "checkpoint.json"),
                            "w") as point:
                        point.write('{"checkpoint": true}\n')
                if gap:
                    time.sleep(gap)
            handle.flush()
            os.fsync(handle.fileno())
        for name in ("checkpoint.json", ".finalization-reserve"):
            try:
                os.unlink(os.path.join(output, name))
            except OSError:
                pass
        session = {
            "schema_version": "0.1.4",
            "capture": {
                "integrity": {
                    "events_sha256": sha_file(events_path),
                    "line_count": str(events),
                    "events_bytes": str(written),
                },
            },
        }
        with open(os.path.join(output, "session.json"),
                  "w") as handle:
            handle.write(json.dumps(session, sort_keys=True)
                         + "\n")
        standin_write("record: end=duration outcome=finalized "
                      "exit=0\n")
        return 0
    finally:
        try:
            fcntl.flock(dir_fd, fcntl.LOCK_UN)
        except OSError:
            pass
        os.close(dir_fd)


def main(argv):
    if len(argv) >= 2 and argv[1] == "standin":
        return run_standin(argv[2:])
    sys.stderr.write("usage: output_stall_core.py standin "
                     "--output DIR [--duration SEC] "
                     "[--events N] [--line-bytes B]\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
