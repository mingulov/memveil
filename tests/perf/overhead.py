#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Live-overhead gate: product collector cost under fixed workloads.

One fail-fast probe boot (summary plus attached-idle legs)
then one 40-leg campaign boot (5 rounds, every observed mode
paired with its own matched off leg, seeded order). Proves
only the tested artifact and environment; an unarmed lane
skips without booting.

Requires MEMVEIL_VM_PERF=1 with qualified probes. The
summary-mode targets (<= 5% throughput decrease, <= 10% p99
increase) apply to the documented reference workload only;
detail, attached-idle, and undersized-buffer results print
as measured ratios without invented thresholds. A summary
ratio outside the targets is a declared LIMITATION, never a
silent pass. Peak userspace RSS carries its own <= 256 MiB
reference target per leg, BPF memory reports separately.

Scope note: off legs are bare controls; summary legs run
product record with attempt-trace only; detail legs run all
three product channels; attached-idle legs hold a
three-channel product record SIGSTOP'd across the measured
window; undersized-buffer legs drain the 4 KiB lab rings.
Lab legs reuse the qualified saturation pieces and never
stand in for product channels. Every leg carries at least
10 s of warmup and a 60 s measured workload inside the
collector window; legs outside the required windows, or
whose collector misses workload coverage, are invalid.
records/s is the whole-collector persisted rate (entire
capture over attach-to-detach wall). RSS prints both the
per-process peak and the aggregate bound per leg.
"""

import hashlib
import json
import math
import os
import re
import shutil
import statistics
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "tests", "vm"))

from compare import assess, compare
from overhead_guest import (DD_BYTES, FLOOD_COUNT, MEASURED_MAX_S,
                            MEASURED_MIN_S, ROUNDS, SAMPLE_COUNT, SEED,
                            WARMUP_MAX_S, WARMUP_MIN_S,
                            WINDOW_SLACK_S, build_schedule)
from export_validation import (strict_json, validate_overhead_legs,
                               validate_overhead_probe,
                               validate_lifecycle_exports)
from consume import check_conservation, parse_consume_file
from evidence_retention import (VerifiedExports, expected_from_verified,
                                retain_failure, snapshot_exports)
from vm_boot import cleanup, run_guest

MODES = ("attached-idle", "summary", "detail", "undersized-buffer")
CAPS = {
    "summary": ["attempt-trace"],
    "attached-idle": ["attempt-trace", "mapping-lifecycle",
                      "copy-actual"],
    "detail": ["attempt-trace", "mapping-lifecycle", "copy-actual"],
}
CHANNELS = {
    "summary": ("bounce_attempts",),
    "attached-idle": ("bounce_attempts", "mapping_lifecycle",
                      "copy_bytes"),
    "detail": ("bounce_attempts", "mapping_lifecycle", "copy_bytes"),
}
RSS_MIB = 256


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL perf-overhead: armed but {what} missing")
        return False
    return True


def armed_preflight():
    ok = need(os.path.join(REPO, "build", "memveil"), "binary")
    for name in ("swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
                 "swiotlb_copy.bpf.o",
                 "swiotlb_lifecycle-test.bpf.o",
                 "swiotlb_copy-test.bpf.o"):
        ok = need(os.path.join(REPO, "build", "bpf", name),
                  "object " + name) and ok
    ok = need(os.path.join(REPO, "build", "vm", "mv_consume"),
              "consumer") and ok
    ok = need(os.path.join(
        REPO, "profiles",
        "linux-x86_64-7.0.0-34-generic.json"), "narrow profile") and ok
    if not shutil.which("vng"):
        print("FAIL perf-overhead: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL perf-overhead: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL perf-overhead: armed but /dev/kvm missing")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL perf-overhead: armed but no passwordless sudo")
        return False
    return ok


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_campaign(tmp, sub, ledger_name, validate_ledger):
    """Two-phase snapshot: ledger first, then its declared files.

    The ledger (legs.json/probe.json) is hashed against its
    sidecar first; the remaining names derive from the
    verified ledger bytes, and the live inventory must match
    exactly (no more, no fewer) before those bytes snapshot.
    """
    export = tmp / "export"
    got, verified = snapshot_exports(
        tmp, sub, ["identity.json", ledger_name])
    ledger = strict_json(got[ledger_name].read_text())
    validate_ledger(ledger)
    names = ["identity.json", ledger_name]
    for leg in ledger["legs"]:
        names.extend(leg["files"])
    want = {f"{sub}-{n}" for n in names}
    want |= {f"{sub}-{n}.sha256" for n in names}
    have = {p.name for p in export.iterdir()}
    if have != want:
        raise ValueError(
            "export inventory drift: %r" % (have ^ want,))
    rest = [n for n in names
            if n not in ("identity.json", ledger_name)]
    got2, verified2 = snapshot_exports(tmp, sub, rest)
    got.update(got2)
    verified.update(verified2)
    validate_lifecycle_exports(got, sub)
    from lifecycle_env import ORACLE_KO, module_build_identity
    expected = module_build_identity()
    identity = json.loads(got["identity.json"].read_text())
    for key in ("release", "config_sha", "btf_sha"):
        if identity[key] != expected[key]:
            raise ValueError(
                "guest kernel identity drift: " + key)
    for key, path in (
            ("consume_sha", os.path.join(
                REPO, "build", "vm", "mv_consume")),
            ("lc_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_lifecycle.bpf.o")),
            ("cp_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_copy.bpf.o")),
            ("bridge_sha", os.path.join(
                REPO, "build", "deps", "lmb", "lib",
                "libbpf_mojo.so.1")),
            ("ko_sha", ORACLE_KO)):
        if identity[key] != sha_file(path):
            raise ValueError("guest artifact mismatch: " + key)
    artifacts = ledger["artifacts"]
    for key, path in (
            ("memveil_sha", os.path.join(REPO, "build", "memveil")),
            ("attempt_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_attempt.bpf.o")),
            ("lc_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_lifecycle.bpf.o")),
            ("cp_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_copy.bpf.o")),
            ("lc_test_sha", os.path.join(
                REPO, "build", "bpf",
                "swiotlb_lifecycle-test.bpf.o")),
            ("cp_test_sha", os.path.join(
                REPO, "build", "bpf", "swiotlb_copy-test.bpf.o")),
            ("bridge_sha", os.path.join(
                REPO, "build", "deps", "lmb", "lib",
                "libbpf_mojo.so.1")),
            ("profile_sha", os.path.join(
                REPO, "profiles",
                "linux-x86_64-7.0.0-34-generic.json"))):
        if artifacts[key] != sha_file(path):
            raise ValueError("campaign input mismatch: " + key)
    return VerifiedExports(got, verified), ledger


def recompute_percentiles(rtts):
    """Nearest-rank p50/p95/p99, the frozen guest rule."""
    ordered = sorted(rtts)
    n = len(ordered)
    return {p: ordered[max(0, (p * n - 1) // 100)]
            for p in (50, 95, 99)}


def product_facts(got, leg, profile_id):
    """Session binding plus capture facts for a product leg."""
    tag = leg["tag"]
    session = strict_json(
        got[tag + "-session.json"].read_text())
    match = re.search(r"ready session=(\S+)",
                      leg["collector"]["ready"])
    if not match or match.group(1) != session["session_id"]:
        return None, "ready/session identity mismatch"
    caps = session.get("capabilities", {})
    for channel in CHANNELS[leg["mode"]]:
        if channel not in caps:
            return None, "session lacks " + channel
        if caps[channel].get("profile_id") != profile_id:
            return None, "session profile drift: " + channel
    events_path = got[tag + "-events.ndjson"]
    kinds = {}
    gens_mapped = set()
    gens_unmapped = set()
    seen_mapped = set()
    peak = 0
    depth = 0
    reordered = False
    total = 0
    with open(events_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            total += 1
            event = strict_json(line)
            kind = event.get("kind")
            kinds[kind] = kinds.get(kind, 0) + 1
            data = event.get("data", {})
            if kind == "map_result" and data.get("success") is True:
                gen = data.get("mapping_id")
                if gen:
                    gens_mapped.add(gen)
                    seen_mapped.add(gen)
                    depth += 1
                    peak = max(peak, depth)
            elif kind == "unmap":
                gen = data.get("mapping_id")
                if gen:
                    gens_unmapped.add(gen)
                    if gen in seen_mapped:
                        depth -= 1
                    else:
                        reordered = True
    completed = len(gens_mapped & gens_unmapped)
    detail = session.get("quality", {}).get("detail", {})
    loss_count = detail.get("loss_count")
    try:
        loss_count = int(loss_count) \
            if loss_count is not None else None
    except (TypeError, ValueError):
        return None, "unparseable detail loss_count"
    reason = detail.get("reason", "")
    fails = {}
    for key in ("submit_fail", "malformed", "dropped",
                "size_omitted", "duration_omitted",
                "signal_omitted", "rejected", "write_failed"):
        hit = re.search(r"%s=\((\d+)\)" % key, reason or "")
        fails[key] = int(hit.group(1)) if hit else None
    finalized = session.get("capture", {}).get("finalized")
    if finalized is not True:
        return None, "capture not finalized"
    return {
        "events_total": total,
        "kinds": kinds,
        "completed_lifetimes": completed,
        "peak_open": None if reordered else peak,
        "occupancy_reordered": reordered,
        "loss_count": loss_count,
        "loss_breakdown": fails,
    }, ""


def lab_facts(got, leg):
    """Conservation plus loss facts for a lab leg."""
    tag = leg["tag"]
    facts = {"events_total": 0, "cnt_fail": 0}
    for ring in ("lc", "cp"):
        events, summary = parse_consume_file(
            str(got[tag + "-" + ring + ".txt"]))
        bad = check_conservation(events, summary,
                                 tag + "-" + ring)
        if bad:
            return None, "; ".join(bad)
        facts["events_total"] += len(events)
        facts["cnt_fail"] += summary["cnt_fail"]
    return facts, ""


def leg_runs(leg, got, profile_id):
    """Validity-first leg verdict plus comparison runs.

    Returns (ping_run, dd_run, metrics, notes). Invalid legs
    carry their reason in both runs; metrics is None then.
    """
    mode = leg["mode"]
    bad = []
    if leg["error"]:
        bad.append("guest: " + leg["error"])
    workload = leg.get("workload")
    collector = leg.get("collector")
    if workload is None or collector is None:
        bad.append("leg lacks workload/collector facts")
    else:
        if workload["warmup"]["ok"] is not True:
            bad.append("warmup failed: %s"
                       % workload["warmup"]["detail"])
        ping = workload["ping"]
        if ping["tx"] != FLOOD_COUNT or \
                ping["rx"] != FLOOD_COUNT:
            bad.append("ping flood %r/%r"
                       % (ping["tx"], ping["rx"]))
        if ping["seconds"] is None or ping["seconds"] <= 0:
            bad.append("ping time %r" % (ping["seconds"],))
        for key in ("sample_tx", "sample_rx", "sample_count"):
            if ping[key] != SAMPLE_COUNT:
                bad.append("incomplete latency sample")
                break
        if len(ping["rtts"]) != SAMPLE_COUNT:
            bad.append("RTT list length %d"
                       % len(ping["rtts"]))
        elif not bad:
            want = recompute_percentiles(ping["rtts"])
            for pct, key in ((50, "p50_ms"), (95, "p95_ms"),
                             (99, "p99_ms")):
                if ping[key] != want[pct]:
                    bad.append("percentile mismatch " + key)
                    break
        dd = workload["dd"]
        if dd["bytes"] != DD_BYTES:
            bad.append("dd bytes %r" % (dd["bytes"],))
        if dd["seconds"] is None or dd["seconds"] <= 0:
            bad.append("dd time %r" % (dd["seconds"],))
        window = workload["window"]
        measured_s = (window["end_ns"]
                      - window["measured_start_ns"]) / 1e9
        warmup_s = (window["measured_start_ns"]
                    - window["warmup_start_ns"]) / 1e9
        if warmup_s < WARMUP_MIN_S:
            bad.append("warmup window %.2fs below %.0fs minimum"
                       % (warmup_s, WARMUP_MIN_S))
        elif warmup_s > WARMUP_MAX_S:
            bad.append("warmup window %.2fs exceeds %.0fs bound"
                       % (warmup_s, WARMUP_MAX_S))
        if abs(workload["warmup"]["seconds"]
               - warmup_s) > WINDOW_SLACK_S:
            bad.append("warmup window seconds field %.2fs "
                       "contradicts %.2fs endpoints"
                       % (workload["warmup"]["seconds"],
                          warmup_s))
        if measured_s < MEASURED_MIN_S:
            bad.append("measured window %.2fs below %.0fs minimum"
                       % (measured_s, MEASURED_MIN_S))
        elif measured_s > MEASURED_MAX_S:
            bad.append("measured window %.2fs exceeds %.0fs bound"
                       % (measured_s, MEASURED_MAX_S))
        if not bad:
            ping_run = {
                "throughput": ping["rx"] / ping["seconds"]
                if ping["seconds"] else None,
                "p50": ping["p50_ms"], "p95": ping["p95_ms"],
                "p99": ping["p99_ms"],
            }
            dd_run = {
                "throughput": dd["bytes"] / dd["seconds"]
                if dd["seconds"] else None,
            }
        kind = collector.get("kind")
        want_kind = {"off": "none"}.get(mode, "product")
        if mode == "undersized-buffer":
            want_kind = "lab"
        if kind != want_kind:
            bad.append("collector kind %r" % (kind,))
        if not leg.get("bpf", {}).get("settled", False):
            bad.append("BPF inventory did not settle")
    if bad:
        reason = "; ".join(bad)
        empty = {"valid": False, "counts_ok": False,
                 "invalid_reason": reason, "throughput": None,
                 "p50": None, "p95": None, "p99": None}
        return empty, dict(empty), None, reason
    facts = None
    if mode in CAPS:
        if collector["capabilities"] != CAPS[mode]:
            reason = "capabilities %r" % (
                collector["capabilities"],)
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if collector["exit"] != 4:
            reason = "record exit %r" % (collector["exit"],)
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if collector["killed"]:
            reason = "record SIGKILL fallback fired"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if collector["stopped"] != (mode == "attached-idle"):
            reason = "stopped flag %r" % (
                collector["stopped"],)
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if collector["attach_ns"] > \
                workload["window"]["warmup_start_ns"]:
            reason = "record attached after workload start"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if workload["window"]["end_ns"] >= collector["term_ns"]:
            reason = "workload overflowed record life"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if sorted(leg["files"]) != sorted(
                [leg["tag"] + "-session.json",
                 leg["tag"] + "-events.ndjson"]):
            reason = "product leg files %r" % (leg["files"],)
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        try:
            facts, why = product_facts(got, leg, profile_id)
        except (ValueError, KeyError, OSError) as exc:
            facts, why = None, "capture facts: %s" % exc
        if facts is None:
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": why, "throughput": None,
                     "p50": None, "p95": None, "p99": None}
            return empty, dict(empty), None, why
        cpu_s = collector["utime_s"] + collector["stime_s"]
        wall_s = (collector["detach_ns"]
                  - collector["attach_ns"]) / 1e9
    elif mode == "undersized-buffer":
        if collector["lc"]["exit"] != 0 or \
                collector["cp"]["exit"] != 0:
            reason = "lab exit lc=%r cp=%r" % (
                collector["lc"]["exit"],
                collector["cp"]["exit"])
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if collector["attach_ns"] > \
                workload["window"]["warmup_start_ns"]:
            reason = "lab consumers attached after workload start"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if workload["window"]["end_ns"] >= \
                collector["detach_ns"]:
            reason = "workload overflowed lab window"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        if sorted(leg["files"]) != sorted(
                [leg["tag"] + "-lc.txt",
                 leg["tag"] + "-cp.txt"]):
            reason = "lab leg files %r" % (leg["files"],)
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        try:
            facts, why = lab_facts(got, leg)
        except (ValueError, KeyError, OSError) as exc:
            facts, why = None, "lab facts: %s" % exc
        if facts is None:
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": why, "throughput": None,
                     "p50": None, "p95": None, "p99": None}
            return empty, dict(empty), None, why
        cpu_s = collector["lc"]["utime_s"] + \
            collector["lc"]["stime_s"] + \
            collector["cp"]["utime_s"] + collector["cp"]["stime_s"]
        wall_s = (collector["detach_ns"]
                  - collector["attach_ns"]) / 1e9
    else:
        if leg["files"]:
            reason = "off leg carries files"
            empty = {"valid": False, "counts_ok": False,
                     "invalid_reason": reason,
                     "throughput": None, "p50": None,
                     "p95": None, "p99": None}
            return empty, dict(empty), None, reason
        cpu_s = 0.0
        wall_s = measured_s
    ping_run = {"valid": True, "counts_ok": True,
                "invalid_reason": "", **ping_run}
    dd_run = {"valid": True, "counts_ok": True,
              "invalid_reason": "",
              "throughput": dd_run["throughput"]}
    if mode in CAPS:
        per_process_kb = collector["maxrss_kb"]
        aggregate_kb = collector["maxrss_kb"]
    elif mode == "undersized-buffer":
        per_process_kb = max(collector["lc"]["maxrss_kb"],
                             collector["cp"]["maxrss_kb"])
        # Summed per-process peaks: the two consumers run
        # concurrently, so the sum is a conservative bound on
        # their combined peak, not a sampled aggregate.
        aggregate_kb = collector["lc"]["maxrss_kb"] + \
            collector["cp"]["maxrss_kb"]
    else:
        per_process_kb = 0
        aggregate_kb = 0
    metrics = {
        "measured_s": measured_s,
        "warmup_s": warmup_s,
        "ping_throughput": ping_run["throughput"],
        "p50_ms": ping_run["p50"],
        "p95_ms": ping_run["p95"],
        "p99_ms": ping_run["p99"],
        "dd_throughput": dd_run["throughput"],
        "cpu_s": cpu_s,
        "cpu_wall_pct": 100.0 * cpu_s / wall_s if wall_s else None,
        "maxrss_kb": per_process_kb,
        "aggregate_rss_kb": aggregate_kb,
        "bpf_memlock": leg["bpf_mem"]["owned_memlock_bytes"],
        "capture_bytes": collector.get("capture_bytes", 0),
        "facts": facts,
    }
    snapshots = [got[name] for name in leg["files"]]
    metrics["snapshot_bytes"] = sum(
        p.stat().st_size for p in snapshots)
    if facts is not None and mode != "off":
        # Whole-collector rate: events_total spans the entire
        # capture, so its denominator is the whole collector
        # wall (attach to detach), never the measured window.
        collector_wall_s = (collector["detach_ns"]
                            - collector["attach_ns"]) / 1e9
        metrics["collector_wall_s"] = collector_wall_s
        metrics["records_per_s"] = \
            facts["events_total"] / collector_wall_s \
            if collector_wall_s > 0 else None
    else:
        metrics["collector_wall_s"] = None
        metrics["records_per_s"] = None
    return ping_run, dd_run, metrics, ""


def pair_ratios(bases, observed, field):
    """Per-pair observed/baseline ratios; None when unusable."""
    ratios = []
    for base, obs in zip(bases, observed):
        a = base.get(field)
        b = obs.get(field)
        if type(a) not in (int, float) or \
                type(b) not in (int, float) or \
                not math.isfinite(a) or not math.isfinite(b) or \
                a <= 0 or b <= 0:
            ratios.append(None)
        else:
            ratios.append(b / a)
    return ratios


def fmt(value, digits=3):
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return "%.*f" % (digits, value)
    return str(value)


def report_mode(mode, pairs, got, profile_id):
    """Compare one mode against matched off legs; verdict lines.

    pairs: [(off_leg, obs_leg)] in round order. Returns
    (qualified, lines, rows) where rows carry per-pair facts
    for the metric tables.
    """
    lines = []
    rows = []
    ping_base, ping_obs, dd_base, dd_obs = [], [], [], []
    for off_leg, obs_leg in pairs:
        for leg, pings, dds in ((off_leg, ping_base, dd_base),
                                (obs_leg, ping_obs, dd_obs)):
            ping_run, dd_run, metrics, _ = leg_runs(
                leg, got, profile_id)
            pings.append(ping_run)
            dds.append(dd_run)
            rows.append((leg["pair"], leg["mode"], leg["tag"],
                         ping_run, dd_run, metrics))
    ping_verdict = compare("ping-" + mode, ping_base, ping_obs,
                           fields=("throughput", "p50", "p95",
                                   "p99"))
    dd_verdict = compare("dd-" + mode, dd_base, dd_obs,
                         fields=("throughput",))
    lines.append("perf-overhead: %s pairs=%d excluded=%d" % (
        mode, ping_verdict["pairs"],
        len(ping_verdict["excluded"])
        + len(dd_verdict["excluded"])))
    for line in ping_verdict["excluded"] + dd_verdict["excluded"]:
        lines.append("perf-overhead: excluded %s %s"
                     % (mode, line))
    for verdict in (ping_verdict, dd_verdict):
        fields = verdict.get("fields", {})
        for field, stats in sorted(fields.items()):
            if not stats.get("qualified"):
                lines.append(
                    "perf-overhead: %s %s: UNQUALIFIED "
                    "(samples=%d)" % (mode, field,
                                      stats.get("samples", 0)))
                continue
            ratios = pair_ratios(
                ping_base if verdict is ping_verdict
                else dd_base,
                ping_obs if verdict is ping_verdict else dd_obs,
                field)
            lines.append(
                "perf-overhead: %s %s: median=%s min=%s "
                "max=%s ratios=[%s]" % (
                    mode, field,
                    fmt(stats["median"]), fmt(stats["min"]),
                    fmt(stats["max"]),
                    ",".join(fmt(r) for r in ratios)))
    qualified = ping_verdict["qualified"] and \
        dd_verdict["qualified"]
    if mode == "summary":
        for verdict in (ping_verdict, dd_verdict):
            status, note = assess(verdict)
            lines.append("perf-overhead: summary %s target %s: %s"
                         % (verdict["workload"].split("-", 1)[0],
                            status, note))
    else:
        state = "MEASURED" if qualified else "UNQUALIFIED"
        lines.append("perf-overhead: %s %s (ratios as-is, no "
                     "thresholds)" % (mode, state))
    return qualified, lines, rows


def report_metrics(rows):
    """Per-leg metric table lines plus per-mode aggregates.

    rec_s is the whole-collector persisted rate (entire
    capture over attach-to-detach wall). rss_MiB is the
    per-process peak; aggr_MiB is the aggregate bound (for
    two-consumer lab legs the summed per-process peaks, a
    conservative bound, not a sampled aggregate).
    """
    lines = ["perf-overhead: leg mode/pair/tag "
             "ping_thr p99 dd_thr cpu_s cpu% rss_MiB aggr_MiB "
             "bpf_mem rec_s bytes lifetimes"]
    by_mode = {}
    for pair, mode, tag, ping_run, dd_run, metrics in rows:
        if metrics is None:
            lines.append("perf-overhead: leg %s %s %s INVALID %s"
                         % (mode, pair, tag,
                            ping_run["invalid_reason"][:120]))
            continue
        facts = metrics["facts"] or {}
        lifetimes = facts.get("completed_lifetimes", "n/a")
        rss = metrics["maxrss_kb"] / 1024 \
            if metrics["maxrss_kb"] else 0.0
        aggr = metrics["aggregate_rss_kb"] / 1024 \
            if metrics["aggregate_rss_kb"] else 0.0
        lines.append(
            "perf-overhead: leg %s %s %s %s %s %s %s %s %s %s "
            "%s %s %s %s" % (
                mode, pair, tag,
                fmt(metrics["ping_throughput"], 1),
                fmt(metrics["p99_ms"]),
                fmt(metrics["dd_throughput"], 1),
                fmt(metrics["cpu_s"]), fmt(metrics["cpu_wall_pct"],
                                           1),
                fmt(rss, 1), fmt(aggr, 1),
                fmt(metrics["bpf_memlock"]),
                fmt(metrics["records_per_s"], 1),
                fmt(metrics["snapshot_bytes"]),
                fmt(lifetimes)))
        by_mode.setdefault(mode, []).append(metrics)
    for mode in sorted(by_mode):
        legs = by_mode[mode]
        rss = [m["maxrss_kb"] / 1024 for m in legs
               if m["maxrss_kb"]]
        aggr = [m["aggregate_rss_kb"] / 1024 for m in legs
                if m["aggregate_rss_kb"]]
        worst = max(rss) if rss else 0.0
        worst_aggr = max(aggr) if aggr else 0.0
        state = "PASS" if worst_aggr <= RSS_MIB else "FAIL"
        lines.append(
            "perf-overhead: rss %s: %s worst-per-process=%.1fMiB "
            "worst-aggregate=%.1fMiB n=%d (target<=%dMiB)" % (
                mode, state, worst, worst_aggr, len(aggr),
                RSS_MIB))
        mems = [m["bpf_memlock"] for m in legs
                if m["bpf_memlock"] is not None]
        if mems:
            lines.append(
                "perf-overhead: bpfmem %s: median=%d min=%d "
                "max=%d n=%d" % (
                    mode, statistics.median(mems), min(mems),
                    max(mems), len(mems)))
        else:
            lines.append("perf-overhead: bpfmem %s: NOT RUN "
                         "(no samples)" % mode)
    return lines


def check_epilogue(ledger):
    if ledger["epilogue"]["settled"] is not True:
        return "global BPF inventory did not settle"
    return ""


def run_probe():
    tmp = None
    try:
        tmp, proc = run_guest("overhead-probe", timeout=900,
                              network=True)
        if proc.returncode != 0:
            print("FAIL perf-overhead: probe guest failed: %s"
                  % proc.stderr[-2000:])
            retain_failure(tmp, "overhead-probe")
            print(f"gate artifacts kept at {tmp}")
            return 1
        try:
            got, ledger = snapshot_campaign(
                tmp, "overhead-probe", "probe.json",
                validate_overhead_probe)
        except (ValueError, AssertionError) as exc:
            print("FAIL perf-overhead: probe exports: %s" % exc)
            retain_failure(tmp, "overhead-probe")
            print(f"gate artifacts kept at {tmp}")
            return 1
        expected = expected_from_verified(got, "overhead-probe")
        profile_id = ledger["artifacts"]["profile_id"]
        bad = []
        for leg in ledger["legs"]:
            ping_run, dd_run, metrics, _ = leg_runs(
                leg, got, profile_id)
            if metrics is None:
                bad.append("%s %s: %s" % (
                    leg["mode"], leg["tag"],
                    ping_run["invalid_reason"]))
            elif metrics["bpf_memlock"] is None:
                bad.append("%s %s: no BPF memlock sample"
                           % (leg["mode"], leg["tag"]))
        epilogue = check_epilogue(ledger)
        if epilogue:
            bad.append(epilogue)
        if bad:
            print("FAIL perf-overhead: probe legs:")
            for line in bad:
                print("  " + line)
            retain_failure(tmp, "overhead-probe")
            print(f"gate artifacts kept at {tmp}")
            return 1
        print("perf-overhead: probe PASS: summary + "
              "attached-idle legs valid with BPF memlock")
        cleanup(tmp, "overhead-probe", expected=expected)
        return 0
    except Exception as exc:
        print(f"FAIL perf-overhead: probe: {exc}")
        retain_failure(tmp, "overhead-probe")
        print(f"gate artifacts kept at {tmp}")
        return 1


def run_flow():
    tmp = None
    try:
        tmp, proc = run_guest("overhead", timeout=7200,
                              network=True)
        if proc.returncode != 0:
            print("FAIL perf-overhead: guest failed: %s"
                  % proc.stderr[-2000:])
            retain_failure(tmp, "overhead")
            print(f"gate artifacts kept at {tmp}")
            return 1
        try:
            got, ledger = snapshot_campaign(
                tmp, "overhead", "legs.json",
                validate_overhead_legs)
        except (ValueError, AssertionError) as exc:
            print("FAIL perf-overhead: exports: %s" % exc)
            retain_failure(tmp, "overhead")
            print(f"gate artifacts kept at {tmp}")
            return 1
        expected = expected_from_verified(got, "overhead")
        profile_id = ledger["artifacts"]["profile_id"]
        by_pair = {}
        for leg in ledger["legs"]:
            by_pair.setdefault(leg["pair"], {})[leg["mode"]] = leg
        all_rows = []
        failures = []
        limits = []
        for mode in MODES:
            pairs = []
            for rnd in range(ROUNDS):
                pair_id = "r%d-%s" % (rnd, mode)
                members = by_pair.get(pair_id, {})
                if set(members) != {"off", mode}:
                    failures.append(
                        "%s: pair %s members %r"
                        % (mode, pair_id, sorted(members)))
                    continue
                pairs.append((members["off"], members[mode]))
            qualified, lines, rows = report_mode(
                mode, pairs, got, profile_id)
            all_rows.extend(rows)
            for line in lines:
                print(line)
            if not qualified:
                failures.append("%s: UNQUALIFIED "
                                "(fewer than five valid pairs)"
                                % mode)
            for line in lines:
                if " target FAIL: " in line:
                    limits.append(line.split("perf-overhead: "
                                             )[1])
                elif " target UNQUALIFIED: " in line:
                    failures.append(line.split("perf-overhead: "
                                               )[1])
        for line in report_metrics(all_rows):
            print(line)
        epilogue = check_epilogue(ledger)
        if epilogue:
            failures.append(epilogue)
        if failures:
            print("FAIL perf-overhead:")
            for line in failures:
                print("  " + line)
            retain_failure(tmp, "overhead")
            print(f"gate artifacts kept at {tmp}")
            return 1
        if limits:
            for line in limits:
                print("perf-overhead: LIMITATION: " + line)
        print("perf-overhead: PASS: 20 unique pairs measured; "
              "summary targets assessed, others as-is")
    except Exception as exc:
        print(f"FAIL perf-overhead: {exc}")
        retain_failure(tmp, "overhead")
        print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp, "overhead", expected=expected)
        return 0


def main():
    if os.environ.get("MEMVEIL_VM_PERF", "0") != "1":
        print("perf-overhead: SKIP: needs MEMVEIL_VM_PERF=1 "
              "with qualified probes")
        return 77
    if not armed_preflight():
        return 1
    code = run_probe()
    if code != 0:
        return code
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())
