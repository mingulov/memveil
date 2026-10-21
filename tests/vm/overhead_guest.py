#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Live-overhead guest flow: fixed workloads under collector modes.

Runs as root inside the virtme-ng guest (one boot per
subcommand), sharing the host rootfs so repo paths resolve
identically. Subcommands (wired in guest_lifecycle.py):
``overhead`` runs the full campaign, ``overhead-probe``
runs one summary leg plus one attached-idle leg as a
fail-fast environment check.

Frozen protocol (verbatim in the campaign report):
seed 20261016; 5 rounds; per round each observed mode
(attached-idle, summary, detail, undersized-buffer) pairs
with its own matched off leg (40 legs, 20 unique pairs, no
measurement reused). Order per round shuffles with an
explicit LCG (a=6364136223846793005, c=1442695040888963407,
m=2**64; Fisher-Yates j=rng%(i+1)); the host reproduces the
same schedule from the seed. Network: pcnet iface to
10.0.3.2, flood ``ping -A -c 1000`` plus paced
``ping -i 0.01 -c 6300`` (p50/p95/p99 from the full
sample). Block: owned scsi_debug dev_size_mb=64, measured
``dd bs=64k count=512 iflag=direct`` (exactly 33554432
bytes). Warmup per leg (~11 s): ``ping -i 0.01 -c 1100``
plus ``dd bs=64k count=256 iflag=direct``. The paced
interval floors bound every leg: warmup lasts at least
10 s and the measured workload at least 60 s. Collector:
product ``record --duration 120``, attached before warmup
starts and SIGTERM'd after the workload (attached-idle
adds SIGSTOP between readiness and the workload, SIGCONT
before SIGTERM), or lab consumers on the 4 KiB test rings
(120 s natural window, likewise covering the workload).

Per-leg facts only; validity is decided host-side. A leg
that cannot run records its error and the campaign
continues; fixture or ownership failures abort loudly.
Exports carry .sha256 sidecars; no DMA addresses cross.
"""

import json
import os
import re
import shutil
import signal
import select
import subprocess
import sys
import time

from guest_lifecycle import (CP_SITES, LC_SITES, await_record_ready,
                             configure_net, fail, find_pcnet, mono_ns,
                             remove_scsi_debug, scsi_disks, sh, sha_file)

SEED = 20261016
LCG_A = 6364136223846793005
LCG_C = 1442695040888963407
LCG_M = 2 ** 64
ROUNDS = 5
OBSERVED_MODES = ("attached-idle", "summary", "detail",
                  "undersized-buffer")
GATEWAY = "10.0.3.2"
FLOOD_COUNT = 1000
SAMPLE_COUNT = 6300
WARMUP_PING_COUNT = 1100
DD_COUNT = 512
DD_BS = 65536
DD_BYTES = DD_COUNT * DD_BS
WARMUP_DD_COUNT = 256
RECORD_DURATION = 120
LAB_WINDOW = 120
READY_TIMEOUT = 60
TERM_TIMEOUT = 60
# Required measurement windows, enforced host-side per leg.
# The paced ping intervals floor the durations: 1100 warmup
# packets at 10 ms span at least 10 s and 6300 measured
# packets at least 60 s. The upper bounds only catch
# pathological runs; healthy legs sit near the floors.
WARMUP_MIN_S = 10.0
MEASURED_MIN_S = 60.0
WARMUP_MAX_S = 180.0
MEASURED_MAX_S = 300.0
# The warmup seconds field and its timestamp endpoints come
# from the same monotonic clock microseconds apart, so a leg
# whose field disagrees by more than this slack carries
# contradictory durations and is invalid.
WINDOW_SLACK_S = 1.0
SETTLE_PER_LEG = 10
SETTLE_GLOBAL = 30


# Exported leg diagnostics carry allowlisted codes plus
# integer facts only; raw tool stderr, exception text,
# addresses, and command lines stay guest-local (console).
LEG_ERROR_CODES = frozenset((
    "ping-flood-failed", "ping-flood-unparseable",
    "ping-sample-failed", "empty-rtt-sample",
    "dd-failed", "dd-unparseable",
    "collector-reaped", "collector-timeout",
    "bpftool-missing", "bpftool-failed",
    "bpftool-unparseable", "bpftool-malformed",
    "bpftool-entry-malformed",
    "lab-exited-early", "lab-attach-timeout",
    "lab-never-ready", "lab-exit",
    "missing-memveil", "missing-attempt-obj",
    "missing-lc-obj", "missing-cp-obj",
    "missing-bridge", "missing-profile",
    "record-not-ready", "sigterm-failed",
    "record-would-not-die", "unknown-mode",
    "bpf-unsettled", "unexpected",
))
LEG_FACT_KEYS = frozenset((
    "rc", "errno", "lc", "cp", "progs_rc", "maps_rc",
    "before_progs", "before_maps",
    "after_progs", "after_maps",
))


class LegError(Exception):
    """One leg failed; the campaign records it and continues.

    Only the code plus integer facts cross into exports, via
    export(); detail stays guest-local (console only, never
    retained) so it may name raw stderr and paths.
    """

    def __init__(self, code, facts=None, detail=""):
        if code not in LEG_ERROR_CODES:
            raise ValueError(
                "unknown leg error code %r" % (code,))
        self.code = code
        self.facts = dict(facts or {})
        for key, val in self.facts.items():
            if key not in LEG_FACT_KEYS or \
                    type(val) is not int:
                raise ValueError(
                    "invalid leg error fact %r" % (key,))
        self.detail = detail or code
        super().__init__(self.detail)

    def export(self):
        parts = [self.code] + [
            "%s=%d" % (key, self.facts[key])
            for key in sorted(self.facts)]
        return " ".join(parts)


def build_schedule(seed=SEED):
    """The 40-leg execution order: [(round, mode, pair)].

    Pure function of the seed with a pinned LCG, so the host
    reproduces it byte-identically on any interpreter. Each
    round holds every observed mode paired with its own off
    leg; both the mode order and the within-pair order
    shuffle. Pair identities come from construction, never
    from adjacency.
    """
    state = seed % LCG_M

    def rng_next():
        nonlocal state
        state = (LCG_A * state + LCG_C) % LCG_M
        return state

    def shuffle(items):
        items = list(items)
        for i in range(len(items) - 1, 0, -1):
            j = rng_next() % (i + 1)
            items[i], items[j] = items[j], items[i]
        return items

    schedule = []
    for rnd in range(ROUNDS):
        for mode in shuffle(OBSERVED_MODES):
            pair = "r%d-%s" % (rnd, mode)
            legs = [(rnd, "off", pair), (rnd, mode, pair)]
            if rng_next() % 2:
                legs.reverse()
            schedule.extend(legs)
    return schedule


def percentiles(rtts):
    """p50/p95/p99 by the frozen nearest-rank rule."""
    ordered = sorted(rtts)
    n = len(ordered)
    out = {}
    for p in (50, 95, 99):
        out[p] = ordered[max(0, (p * n - 1) // 100)]
    return out


def ping_flood(gateway):
    """Flood leg: (tx, rx, seconds)."""
    start = mono_ns()
    proc = sh(["timeout", "120", "ping", "-A", "-c",
               str(FLOOD_COUNT), "-q", gateway])
    elapsed = (mono_ns() - start) / 1e9
    if proc.returncode != 0:
        raise LegError(
            "ping-flood-failed", {"rc": proc.returncode},
            detail="ping flood failed rc=%d: %s"
            % (proc.returncode,
               proc.stderr.strip()[-300:]))
    sent = re.search(r"(\d+) packets transmitted", proc.stdout)
    rcvd = re.search(r"(\d+) received", proc.stdout)
    if sent is None or rcvd is None:
        raise LegError("ping-flood-unparseable",
                       detail="ping flood output unparseable")
    return int(sent.group(1)), int(rcvd.group(1)), elapsed


def ping_sample(gateway):
    """Paced leg: full RTT list plus independent counters."""
    proc = sh(["timeout", "180", "ping", "-i", "0.01", "-c",
               str(SAMPLE_COUNT), gateway])
    if proc.returncode != 0:
        raise LegError(
            "ping-sample-failed", {"rc": proc.returncode},
            detail="ping sample failed rc=%d: %s"
            % (proc.returncode,
               proc.stderr.strip()[-300:]))
    rtts = [float(v) for v in
            re.findall(r"time=([\d.]+) ms", proc.stdout)]
    sent = re.search(r"(\d+) packets transmitted", proc.stdout)
    rcvd = re.search(r"(\d+) received", proc.stdout)
    return {
        "rtts": rtts,
        "sample_tx": int(sent.group(1)) if sent else None,
        "sample_rx": int(rcvd.group(1)) if rcvd else None,
        "sample_count": len(rtts),
    }


def dd_run(dev, count):
    """One direct-I/O read: (bytes, seconds)."""
    start = mono_ns()
    proc = sh(["dd", f"if={dev}", "of=/dev/null", "bs=64k",
               f"count={count}", "iflag=direct"])
    elapsed = (mono_ns() - start) / 1e9
    if proc.returncode != 0:
        raise LegError(
            "dd-failed", {"rc": proc.returncode},
            detail="dd failed rc=%d: %s"
            % (proc.returncode,
               proc.stderr.strip()[-200:]))
    copied = re.search(r"(\d+) bytes .* copied", proc.stderr)
    if copied is None:
        raise LegError("dd-unparseable",
                       detail="dd output unparseable")
    return int(copied.group(1)), elapsed


def run_warmup(gateway, dev):
    """Fixed warmup traffic; returns (seconds, ok, detail)."""
    start = mono_ns()
    try:
        proc = sh(["timeout", "120", "ping", "-i", "0.01", "-c",
                   str(WARMUP_PING_COUNT), gateway])
        if proc.returncode != 0:
            return (mono_ns() - start) / 1e9, False, \
                "warmup ping rc=%d" % proc.returncode
        nbytes, _ = dd_run(dev, WARMUP_DD_COUNT)
        if nbytes != WARMUP_DD_COUNT * DD_BS:
            return (mono_ns() - start) / 1e9, False, \
                "warmup dd bytes=%d" % nbytes
    except LegError as exc:
        if exc.code == "dd-failed":
            detail = "warmup dd rc=%d" % exc.facts["rc"]
        else:
            detail = "warmup dd unparseable"
        return (mono_ns() - start) / 1e9, False, detail
    return (mono_ns() - start) / 1e9, True, "ok"


def spawn(args, stdout_pipe=True, stderr_path=None):
    """Start a collector without reaping it here."""
    err = open(stderr_path, "wb") if stderr_path else None
    try:
        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE if stdout_pipe else None,
            stderr=err,
            text=True,
            bufsize=1,
            start_new_session=True,
        )
    finally:
        if err is not None:
            err.close()
    return proc


def reap(proc, timeout):
    """Reap exactly one child, returning (exit, rusage).

    Uses wait4 so per-process CPU and peak RSS survive;
    Popen.wait would discard the rusage. The caller must drop
    the handle from any shared consumer list afterwards.
    """
    deadline = time.monotonic() + timeout
    while True:
        try:
            pid, status, rusage = os.wait4(
                proc.pid, os.WNOHANG)
        except ChildProcessError:
            raise LegError("collector-reaped",
                           detail="collector already reaped")
        if pid != 0:
            break
        if time.monotonic() >= deadline:
            raise TimeoutError("collector did not exit")
        time.sleep(0.05)
    if os.WIFEXITED(status):
        exit_code = os.WEXITSTATUS(status)
    elif os.WIFSIGNALED(status):
        exit_code = -os.WTERMSIG(status)
    else:
        exit_code = -99
    proc.returncode = exit_code
    rest = ""
    if proc.stdout is not None:
        try:
            rest = proc.stdout.read()
        except OSError:
            rest = ""
    return exit_code, rusage, rest or ""


def bpf_mem_snapshot():
    """(prog_ids, map_ids, mem_by_kind) or raise LegError."""
    try:
        progs = sh(["bpftool", "-j", "prog", "show"])
        maps = sh(["bpftool", "-j", "map", "show"])
    except OSError as exc:
        errno = exc.errno if type(exc.errno) is int else -1
        raise LegError("bpftool-missing", {"errno": errno},
                       detail="bpftool missing: %s" % exc)
    if progs.returncode != 0 or maps.returncode != 0:
        raise LegError(
            "bpftool-failed",
            {"progs_rc": progs.returncode,
             "maps_rc": maps.returncode},
            detail="bpftool inventory failed")
    try:
        prog_list = json.loads(progs.stdout)
        map_list = json.loads(maps.stdout)
    except ValueError:
        raise LegError("bpftool-unparseable",
                       detail="bpftool output unparseable")
    if not isinstance(prog_list, list) or \
            not isinstance(map_list, list):
        raise LegError("bpftool-malformed",
                       detail="bpftool output malformed")
    prog_ids = set()
    map_ids = set()
    mem = {}
    for entry, ids, kind in ((prog_list, prog_ids, "prog"),
                            (map_list, map_ids, "map")):
        for obj in entry:
            if not isinstance(obj, dict) or \
                    type(obj.get("id")) is not int:
                raise LegError("bpftool-entry-malformed",
                               detail="bpftool entry malformed")
            ids.add(obj["id"])
            mem[(kind, obj["id"])] = obj.get("bytes_memlock")
    return prog_ids, map_ids, mem


def owned_memlock(before, after):
    """Sum bytes_memlock over new IDs; (bytes|None, reason)."""
    b_prog, b_map, _ = before
    a_prog, a_map, a_mem = after
    owned = [("prog", i) for i in sorted(a_prog - b_prog)]
    owned += [("map", i) for i in sorted(a_map - b_map)]
    total = 0
    for key in owned:
        val = a_mem.get(key)
        if type(val) is not int:
            return None, "bytes_memlock missing for %s %d" % key
        total += val
    return total, "owned %d progs %d maps" % (
        len(a_prog - b_prog), len(a_map - b_map))


def wait_lab_ready(procs, timeout=READY_TIMEOUT):
    """Readiness lines that prove attachment; LegError, never fail."""
    end = time.monotonic() + timeout
    pending = list(procs)
    while pending and time.monotonic() < end:
        for proc in list(pending):
            if proc.poll() is not None:
                raise LegError(
                    "lab-exited-early",
                    detail="lab consumer exited before ready")
            ready, _, _ = select.select([proc.stdout], [], [], 0.1)
            if ready:
                line = proc.stdout.readline()
                if line.startswith("ready ring="):
                    proc.gate_ready = True
                    pending.remove(proc)
        if not pending:
            return
    raise LegError("lab-attach-timeout",
                       detail="lab consumer attachment timed out")


def start_product(ctx, gate, tag, capabilities):
    """Start product record; (proc, ready, capdir, errpath)."""
    capdir = os.path.join(gate.work, "cap-" + tag)
    errpath = os.path.join(gate.work, tag + "-record.stderr")
    for code, path in (
            ("missing-memveil", ctx["memveil"]),
            ("missing-attempt-obj", ctx["attempt_obj"]),
            ("missing-profile", ctx["profile"]),
            ("missing-lc-obj", ctx["lc_obj"]),
            ("missing-cp-obj", ctx["cp_obj"]),
            ("missing-bridge", ctx["bridge"])):
        if not os.path.isfile(path):
            raise LegError(code, detail="missing %s" % path)
    proc = spawn(
        [ctx["memveil"], "record",
         "--duration", str(RECORD_DURATION),
         "--output", capdir,
         "--object", ctx["attempt_obj"],
         "--lc-object", ctx["lc_obj"],
         "--cp-object", ctx["cp_obj"],
         "--bridge", ctx["bridge"],
         "--profile", ctx["profile"],
         "--capability", ",".join(capabilities)],
        stderr_path=errpath,
    )
    try:
        ready, _tail = await_record_ready(
            proc, gate.work, errname=tag + "-record.stderr")
    except SystemExit as exc:
        try:
            reap(proc, 10)
        except (LegError, TimeoutError):
            try:
                proc.kill()
            except OSError:
                pass
        raise LegError("record-not-ready",
                       detail="record never reached readiness: %s"
                       % exc.code)
    return proc, ready, capdir, errpath


def stop_product(proc, timeout=TERM_TIMEOUT):
    """SIGTERM then reap; SIGKILL fallback. (exit, rusage, rest, killed)."""
    term_ns = mono_ns()
    try:
        os.kill(proc.pid, signal.SIGTERM)
    except OSError as exc:
        errno = exc.errno if type(exc.errno) is int else -1
        raise LegError("sigterm-failed", {"errno": errno},
                       detail="SIGTERM failed: %s" % exc)
    try:
        exit_code, rusage, rest = reap(proc, timeout)
        return exit_code, rusage, rest, term_ns, False
    except TimeoutError:
        pass
    try:
        proc.kill()
    except OSError:
        pass
    try:
        exit_code, rusage, rest = reap(proc, 10)
    except (LegError, TimeoutError) as exc:
        raise LegError("record-would-not-die",
                       detail="record would not die: %s" % exc)
    return exit_code, rusage, rest, term_ns, True


def stderr_text(path, limit=512):
    """Raw tail for the guest console only; never exported."""
    try:
        with open(path, "rb") as fh:
            return fh.read()[-limit:].decode("utf-8", "replace")
    except OSError:
        return ""


def stderr_summary(path):
    """Allowlisted record-stderr summary for exports.

    Counts only: raw addresses and command text stay
    guest-local. The caller prints the raw tail to the guest
    console for debugging.
    """
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return "record-stderr unreadable"
    return "record-stderr bytes=%d lines=%d" % (
        len(data), data.count(b"\n"))


def rusage_dict(rusage):
    return {
        "utime_s": rusage.ru_utime,
        "stime_s": rusage.ru_stime,
        "maxrss_kb": rusage.ru_maxrss,
    }


def run_workload(gateway, dev):
    """Warmup plus measured ping/dd; returns the workload doc."""
    warmup_start = mono_ns()
    warmup_s, warmup_ok, warmup_detail = run_warmup(gateway, dev)
    measured_start = mono_ns()
    flood_tx, flood_rx, flood_s = ping_flood(gateway)
    sample = ping_sample(gateway)
    dd_bytes, dd_s = dd_run(dev, DD_COUNT)
    end_ns = mono_ns()
    if not sample["rtts"]:
        raise LegError("empty-rtt-sample",
                       detail="empty paced RTT sample")
    pct = percentiles(sample["rtts"])
    return {
        "window": {
            "warmup_start_ns": warmup_start,
            "measured_start_ns": measured_start,
            "end_ns": end_ns,
        },
        "warmup": {"seconds": warmup_s, "ok": warmup_ok,
                   "detail": warmup_detail},
        "ping": {
            "tx": flood_tx, "rx": flood_rx, "seconds": flood_s,
            "rtts": sample["rtts"],
            "sample_tx": sample["sample_tx"],
            "sample_rx": sample["sample_rx"],
            "sample_count": sample["sample_count"],
            "p50_ms": pct[50], "p95_ms": pct[95],
            "p99_ms": pct[99],
        },
        "dd": {"bytes": dd_bytes, "seconds": dd_s},
    }


def kill_quietly(proc):
    try:
        if proc.poll() is None:
            proc.kill()
    except OSError:
        pass
    try:
        reap(proc, 10)
    except (LegError, TimeoutError, ChildProcessError, OSError):
        pass


def _record_leg_error(leg, coded):
    """Export the code; print code plus detail guest-locally."""
    leg["error"] = coded.export()
    print("leg %s error: %s (%s)"
          % (leg["tag"], coded.export(), coded.detail),
          file=sys.stderr)
    return leg


def run_one_leg(ctx, gate, seq, rnd, mode, pair, tag):
    """Run one leg; always returns a leg doc, never raises."""
    leg = {"seq": seq, "round": rnd, "mode": mode, "pair": pair,
           "tag": tag, "files": [], "error": ""}
    try:
        return _run_one_leg(ctx, gate, leg)
    except LegError as exc:
        return _record_leg_error(leg, exc)
    except TimeoutError as exc:
        return _record_leg_error(
            leg, LegError("collector-timeout",
                          detail=str(exc)))
    except Exception as exc:  # noqa: BLE001 (evidence, not silence)
        return _record_leg_error(
            leg, LegError("unexpected",
                          detail="%r" % (exc,)))


def _run_one_leg(ctx, gate, leg):
    mode = leg["mode"]
    tag = leg["tag"]
    bpf_before = gate.bpf_inventory()
    try:
        mem_before = bpf_mem_snapshot()
    except LegError as exc:
        mem_before = None
        mem_error = exc.export()
    else:
        mem_error = ""
    io_before = gate.io_tlb_samples(count=3, gap=0.2)
    collector = {"kind": "none"}
    procs = []
    try:
        if mode == "off":
            pass
        elif mode in ("summary", "detail", "attached-idle"):
            caps = ["attempt-trace"] if mode == "summary" else \
                ["attempt-trace", "mapping-lifecycle", "copy-actual"]
            proc, ready, capdir, errpath = start_product(
                ctx, gate, tag, caps)
            procs.append(proc)
            attach_ns = mono_ns()
            try:
                mem_after = bpf_mem_snapshot()
            except LegError as exc:
                mem_after = None
                mem_error = mem_error or exc.export()
            if mem_before is not None and mem_after is not None:
                mem_bytes, mem_reason = owned_memlock(
                    mem_before, mem_after)
            else:
                mem_bytes, mem_reason = None, \
                    mem_error or "no mem snapshot"
            stopped = False
            if mode == "attached-idle":
                os.kill(proc.pid, signal.SIGSTOP)
                stopped = True
            workload = run_workload(ctx["gateway"], ctx["dev"])
            if mode == "attached-idle":
                os.kill(proc.pid, signal.SIGCONT)
            exit_code, rusage, _rest, term_ns, killed = \
                stop_product(proc)
            procs.remove(proc)
            detach_ns = mono_ns()
            names = []
            session = os.path.join(capdir, "session.json")
            events = os.path.join(capdir, "events.ndjson")
            if os.path.isfile(session) and os.path.isfile(events):
                for src, dst in (
                        (session, tag + "-session.json"),
                        (events, tag + "-events.ndjson")):
                    shutil.copyfile(
                        src, os.path.join(gate.work, dst))
                    names.append(dst)
            cap_bytes = sum(
                os.path.getsize(os.path.join(gate.work, n))
                for n in names)
            collector = {
                "kind": "product",
                "capabilities": caps,
                "exit": exit_code,
                "ready": ready,
                "stopped": stopped,
                "killed": killed,
                **rusage_dict(rusage),
                "attach_ns": attach_ns,
                "detach_ns": detach_ns,
                "term_ns": term_ns,
                "stderr_tail": stderr_summary(errpath)
                if exit_code != 4 else "",
                "capture_bytes": cap_bytes,
            }
            if exit_code != 4:
                print("leg %s record exit=%d stderr: %r"
                      % (tag, exit_code,
                         stderr_text(errpath)),
                      file=sys.stderr)
            leg["files"] = names
            leg["bpf_mem"] = {"owned_memlock_bytes": mem_bytes,
                              "reason": mem_reason}
        elif mode == "undersized-buffer":
            lc_path = os.path.join(gate.work, tag + "-lc.txt")
            cp_path = os.path.join(gate.work, tag + "-cp.txt")
            plc = gate.start_consumer(
                ctx["lc_test_obj"], "mv_lifecycle", LC_SITES,
                LAB_WINDOW, lc_path)
            pcp = gate.start_consumer(
                ctx["cp_test_obj"], "mv_copies", CP_SITES,
                LAB_WINDOW, cp_path)
            procs.extend((plc, pcp))
            wait_lab_ready((plc, pcp))
            attach_ns = mono_ns()
            try:
                mem_after = bpf_mem_snapshot()
            except LegError as exc:
                mem_after = None
                mem_error = mem_error or exc.export()
            if mem_before is not None and mem_after is not None:
                mem_bytes, mem_reason = owned_memlock(
                    mem_before, mem_after)
            else:
                mem_bytes, mem_reason = None, \
                    mem_error or "no mem snapshot"
            workload = run_workload(ctx["gateway"], ctx["dev"])
            lc_exit, lc_ru, lc_rest = reap(plc, LAB_WINDOW + 60)
            cp_exit, cp_ru, cp_rest = reap(pcp, LAB_WINDOW + 60)
            for proc, rest in ((plc, lc_rest), (pcp, cp_rest)):
                if proc in gate.consumers:
                    gate.consumers.remove(proc)
                if not getattr(proc, "gate_ready", False) and \
                        "ready ring=" not in rest:
                    raise LegError("lab-never-ready",
                                   detail="lab consumer never ready")
            procs.clear()
            detach_ns = mono_ns()
            if lc_exit != 0 or cp_exit != 0:
                raise LegError(
                    "lab-exit",
                    {"lc": lc_exit, "cp": cp_exit},
                    detail="lab consumer exit lc=%d cp=%d"
                    % (lc_exit, cp_exit))
            cap_bytes = os.path.getsize(lc_path) + \
                os.path.getsize(cp_path)
            collector = {
                "kind": "lab",
                "rings": ["mv_lifecycle", "mv_copies"],
                "lc": {"exit": lc_exit, **rusage_dict(lc_ru)},
                "cp": {"exit": cp_exit, **rusage_dict(cp_ru)},
                "attach_ns": attach_ns,
                "detach_ns": detach_ns,
                "capture_bytes": cap_bytes,
            }
            leg["files"] = [tag + "-lc.txt", tag + "-cp.txt"]
            leg["bpf_mem"] = {"owned_memlock_bytes": mem_bytes,
                              "reason": mem_reason}
        else:
            raise LegError("unknown-mode",
                           detail="unknown mode %r" % (mode,))
        if mode == "off":
            workload = run_workload(ctx["gateway"], ctx["dev"])
            leg["bpf_mem"] = {"owned_memlock_bytes": 0,
                              "reason": "no collector"}
    finally:
        for proc in list(procs):
            kill_quietly(proc)
            if proc in gate.consumers:
                gate.consumers.remove(proc)
    leg["workload"] = workload
    leg["collector"] = collector
    io_after = gate.io_tlb_samples(count=3, gap=0.2)
    bpf_after, waited = gate.settled_inventory(
        bpf_before, timeout=SETTLE_PER_LEG)
    leg["bpf"] = {"before": bpf_before, "after": bpf_after,
                  "settled_waited_s": waited,
                  "settled": bpf_after == bpf_before}
    leg["io_tlb"] = {"before": io_before, "after": io_after}
    if not leg["bpf"]["settled"]:
        return _record_leg_error(leg, LegError(
            "bpf-unsettled",
            {"before_progs": bpf_before["progs"],
             "before_maps": bpf_before["maps"],
             "after_progs": bpf_after["progs"],
             "after_maps": bpf_after["maps"]},
            detail="BPF inventory did not settle: %r -> %r"
            % (bpf_before, bpf_after)))
    return leg


def profile_id(path):
    with open(path) as handle:
        return json.load(handle)["profile_id"]


def build_ctx(gate, iface, dev):
    """Fixed collector paths plus the owned workload endpoints."""
    repo = gate.repo
    return {
        "memveil": os.path.join(repo, "build", "memveil"),
        "attempt_obj": os.path.join(
            repo, "build", "bpf", "swiotlb_attempt.bpf.o"),
        "lc_obj": gate.lc_obj,
        "cp_obj": gate.cp_obj,
        "lc_test_obj": gate.lc_test_obj,
        "cp_test_obj": gate.cp_test_obj,
        "bridge": gate.bridge,
        "profile": os.path.join(repo, "build", "vm",
                                "gate-profile.json"),
        "gateway": GATEWAY,
        "iface": iface,
        "dev": dev,
    }


def record_artifacts(ctx):
    """Hash every collector input once per guest."""
    return {
        "memveil_sha": sha_file(ctx["memveil"]),
        "attempt_sha": sha_file(ctx["attempt_obj"]),
        "lc_sha": sha_file(ctx["lc_obj"]),
        "cp_sha": sha_file(ctx["cp_obj"]),
        "lc_test_sha": sha_file(ctx["lc_test_obj"]),
        "cp_test_sha": sha_file(ctx["cp_test_obj"]),
        "bridge_sha": sha_file(ctx["bridge"]),
        "profile_sha": sha_file(ctx["profile"]),
        "profile_id": profile_id(ctx["profile"]),
    }


def workload_spec():
    """The frozen workload parameters, echoed for the record."""
    return {
        "gateway": GATEWAY,
        "flood_count": FLOOD_COUNT,
        "sample_count": SAMPLE_COUNT,
        "warmup_ping_count": WARMUP_PING_COUNT,
        "dd_count": DD_COUNT,
        "dd_bytes": DD_BYTES,
        "warmup_dd_count": WARMUP_DD_COUNT,
        "record_duration_s": RECORD_DURATION,
        "lab_window_s": LAB_WINDOW,
        "seed": SEED,
        "rounds": ROUNDS,
    }


def setup_fixture(gate):
    """Owned network iface plus owned scsi_debug disk; (iface, dev)."""
    iface = find_pcnet()
    configure_net(iface)
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
            fail("new overhead disk is not owned scsi_debug")
    return iface, disk


def read_nslabs():
    with open("/sys/kernel/debug/swiotlb/io_tlb_nslabs") as fh:
        return int(fh.read().strip())


def run_overhead(gate):
    """Full campaign: 40 legs, 20 unique pairs, one guest."""
    gate.write_json("identity.json", gate.identity())
    iface, dev = setup_fixture(gate)
    ctx = build_ctx(gate, iface, dev)
    for key in ("memveil", "attempt_obj", "lc_obj", "cp_obj",
                "lc_test_obj", "cp_test_obj", "bridge", "profile"):
        if not os.path.isfile(ctx[key]):
            fail("missing %s" % ctx[key])
    fixture = {
        "iface": iface,
        "disk": dev,
        "nslabs": read_nslabs(),
        "bpf_boot": gate.bpf_inventory(),
        "io_tlb_boot": gate.io_tlb_samples(count=3, gap=0.2),
    }
    schedule = build_schedule()
    legs = []
    names = ["identity.json"]
    for seq, (rnd, mode, pair) in enumerate(schedule):
        tag = "l%02d" % seq
        leg = run_one_leg(ctx, gate, seq, rnd, mode, pair, tag)
        legs.append(leg)
        names.extend(leg["files"])
    short = dev.rsplit("/", 1)[1]
    remove_scsi_debug(short)
    bpf_end, waited = gate.settled_inventory(
        fixture["bpf_boot"], timeout=SETTLE_GLOBAL)
    doc = {
        "schema": "memveil-overhead-legs/1",
        "seed": SEED,
        "rounds": ROUNDS,
        "schedule": [[rnd, mode, pair]
                     for rnd, mode, pair in schedule],
        "artifacts": record_artifacts(ctx),
        "workload": workload_spec(),
        "fixture": fixture,
        "legs": legs,
        "epilogue": {
            "bpf_end": bpf_end,
            "settled_waited_s": waited,
            "settled": bpf_end == fixture["bpf_boot"],
        },
    }
    gate.write_json("legs.json", doc)
    names.append("legs.json")
    gate.export(names)
    print("guest overhead: exported %d legs" % len(legs))
    if not doc["epilogue"]["settled"]:
        fail("BPF inventory did not settle globally: %r -> %r"
             % (fixture["bpf_boot"], bpf_end))


def run_overhead_probe(gate):
    """Fail-fast check: one summary leg plus one idle leg."""
    gate.write_json("identity.json", gate.identity())
    iface, dev = setup_fixture(gate)
    ctx = build_ctx(gate, iface, dev)
    for key in ("memveil", "attempt_obj", "lc_obj", "cp_obj",
                "bridge", "profile"):
        if not os.path.isfile(ctx[key]):
            fail("missing %s" % ctx[key])
    fixture = {
        "iface": iface,
        "disk": dev,
        "nslabs": read_nslabs(),
        "bpf_boot": gate.bpf_inventory(),
        "io_tlb_boot": gate.io_tlb_samples(count=3, gap=0.2),
    }
    legs = [
        run_one_leg(ctx, gate, 0, 0, "summary",
                    "probe-summary", "p0"),
        run_one_leg(ctx, gate, 1, 0, "attached-idle",
                    "probe-idle", "p1"),
    ]
    short = dev.rsplit("/", 1)[1]
    remove_scsi_debug(short)
    bpf_end, waited = gate.settled_inventory(
        fixture["bpf_boot"], timeout=SETTLE_GLOBAL)
    doc = {
        "schema": "memveil-overhead-probe/1",
        "seed": SEED,
        "artifacts": record_artifacts(ctx),
        "workload": workload_spec(),
        "fixture": fixture,
        "legs": legs,
        "epilogue": {
            "bpf_end": bpf_end,
            "settled_waited_s": waited,
            "settled": bpf_end == fixture["bpf_boot"],
        },
    }
    gate.write_json("probe.json", doc)
    names = ["identity.json", "probe.json"]
    for leg in legs:
        names.extend(leg["files"])
    gate.export(names)
    print("guest overhead: probe exported")
    if not doc["epilogue"]["settled"]:
        fail("probe BPF inventory did not settle globally")
