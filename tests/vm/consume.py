#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Host-side parsing and comparison for the lifecycle VM gates.

Parses mv_consume output files (lc/cp event lines plus the
summary line) and mv-oracle: dmesg logs, checks counter
conservation, and compares consumed probe records against the
independent oracle-module ground truth. Every comparison
returns a sorted mismatch list, empty on agreement; the gates
treat any mismatch as a failure.

The scripted-traffic expectations replicate the oracle module
rules (tests/kernel/memveil_dma_oracle.c) and the
kernel-source-backed swiotlb call chains, never MemVeil
reducer math.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from oracle_ledger import OracleLedger, bucket_of, bucket_upper_edge
from oracle_ledger import nearest_rank

LC_SIZES = (512, 1024, 2048, 4096)

LC_LINE = re.compile(
    r"^lc kind=(\d+) ok=(\d+) skip=(\d+) dir=(\d+)"
    r" seq=(\d+) ktime=(\d+) size=(\d+)$"
)
CP_LINE = re.compile(
    r"^cp kind=(\d+) todev=(\d+) known=(\d+) clamp=(\d+)"
    r" ezero=(\d+) dir=(\d+) reason=(\d+)"
    r" seq=(\d+) ktime=(\d+) req=(\d+) eff=(\d+)$"
)
SUMMARY_LINE = re.compile(
    r"^summary observed=(\d+) badframe=(\d+) badrec=(\d+)"
    r" cnt_obs=(\d+) cnt_obsb=(\d+) cnt_emit=(\d+)"
    r" cnt_emitb=(\d+) cnt_fail=(\d+) cnt_flags=(\d+)"
    r" rx=(\d+) dlv=(\d+) mal=(\d+) drop=(\d+)$"
)

ORACLE_LINE = re.compile(r"mv-oracle: (.*)$")
ORACLE_ATTEMPT = re.compile(r"^op=(\d+) attempt requested=(\d+) forced=(\d+)$")
ORACLE_OUTCOME = re.compile(
    r"^op=(\d+) outcome=(success|failure)"
    r"(?: mapping=(\d+) mapped=(\d+)| rc=(-\d+|-EIO))?$"
)
ORACLE_SYNC = re.compile(r"^op=(\d+) mapping=(\d+) sync dir=(\d+) len=(\d+)$")
ORACLE_RELEASE = re.compile(r"^mapping=(\d+) release lifetime_ns=(\d+)$")
ORACLE_COMPLETE = re.compile(r"^script complete ops=(\d+)$")


def parse_consume_file(path):
    """Parse one consumer file into (events, summary).

    Every event line must match the lc/cp grammar exactly;
    exactly one summary line must close the file. Raises
    ValueError naming file and line on any defect.
    """
    events = []
    summary = None
    with open(path) as handle:
        lines = handle.read().split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    for lineno, line in enumerate(lines, 1):
        if line.startswith("summary "):
            if summary is not None:
                raise ValueError("%s:%d: second summary" % (path, lineno))
            match = SUMMARY_LINE.match(line)
            if not match:
                raise ValueError(
                    "%s:%d: malformed summary" % (path, lineno))
            summary = {
                "observed": int(match.group(1)),
                "badframe": int(match.group(2)),
                "badrec": int(match.group(3)),
                "cnt_obs": int(match.group(4)),
                "cnt_obsb": int(match.group(5)),
                "cnt_emit": int(match.group(6)),
                "cnt_emitb": int(match.group(7)),
                "cnt_fail": int(match.group(8)),
                "cnt_flags": int(match.group(9)),
                "rx": int(match.group(10)),
                "dlv": int(match.group(11)),
                "mal": int(match.group(12)),
                "drop": int(match.group(13)),
            }
            continue
        if summary is not None:
            raise ValueError(
                "%s:%d: event after summary" % (path, lineno))
        match = LC_LINE.match(line)
        if match:
            events.append({
                "ring": "lc",
                "kind": int(match.group(1)),
                "ok": int(match.group(2)),
                "skip": int(match.group(3)),
                "dir": int(match.group(4)),
                "seq": int(match.group(5)),
                "ktime": int(match.group(6)),
                "size": int(match.group(7)),
            })
            continue
        match = CP_LINE.match(line)
        if match:
            events.append({
                "ring": "cp",
                "kind": int(match.group(1)),
                "todev": int(match.group(2)),
                "known": int(match.group(3)),
                "clamp": int(match.group(4)),
                "ezero": int(match.group(5)),
                "dir": int(match.group(6)),
                "reason": int(match.group(7)),
                "seq": int(match.group(8)),
                "ktime": int(match.group(9)),
                "req": int(match.group(10)),
                "eff": int(match.group(11)),
            })
            continue
        raise ValueError(
            "%s:%d: malformed line" % (path, lineno))
    if summary is None:
        raise ValueError("%s: missing summary" % path)
    return events, summary


def check_conservation(events, summary, tag):
    """Check one window's counter conservation laws.

    Returns a sorted mismatch list. Laws: delivered lines equal
    the observed count; observed equals emitted plus submit
    failures while the epoch is clean; emitted bytes equal the
    delivered byte sum exactly; any flag bit invalidates the
    epoch; bridge delivery is exact (received equals delivered,
    nothing malformed or dropped).
    """
    bad = []
    size_key = "size" if events and events[0]["ring"] == "lc" else "req"
    if not events:
        size_key = "req"
    if summary["observed"] != len(events):
        bad.append("%s: observed %d != %d lines"
                   % (tag, summary["observed"], len(events)))
    if summary["cnt_flags"] != 0:
        bad.append("%s: epoch invalid flags=%d"
                   % (tag, summary["cnt_flags"]))
    if summary["cnt_obs"] != summary["cnt_emit"] + summary["cnt_fail"]:
        bad.append("%s: obs %d != emit %d + fail %d"
                   % (tag, summary["cnt_obs"], summary["cnt_emit"],
                      summary["cnt_fail"]))
    if summary["cnt_fail"] == 0:
        if summary["cnt_obsb"] != summary["cnt_emitb"]:
            bad.append("%s: byte aggregates diverge without loss"
                       % tag)
    elif summary["cnt_obsb"] < summary["cnt_emitb"]:
        bad.append("%s: emitted bytes exceed observed" % tag)
    delivered_bytes = sum(e[size_key] for e in events)
    if delivered_bytes != summary["cnt_emitb"]:
        bad.append("%s: delivered bytes %d != emitted %d"
                   % (tag, delivered_bytes, summary["cnt_emitb"]))
    seqs = [e["seq"] for e in events]
    if len(set(seqs)) != len(seqs):
        bad.append("%s: duplicate seq" % tag)
    if seqs != sorted(seqs):
        bad.append("%s: seq out of order" % tag)
    if seqs:
        if seqs[0] != 0:
            bad.append("%s: first seq %d != 0" % (tag, seqs[0]))
        if seqs[-1] + 1 != summary["cnt_obs"]:
            bad.append("%s: max seq %d vs observed %d"
                       % (tag, seqs[-1], summary["cnt_obs"]))
    if summary["rx"] != summary["dlv"]:
        bad.append("%s: bridge rx %d != dlv %d"
                   % (tag, summary["rx"], summary["dlv"]))
    if summary["mal"] != 0 or summary["drop"] != 0:
        bad.append("%s: bridge mal=%d drop=%d"
                   % (tag, summary["mal"], summary["drop"]))
    if summary["badframe"] != 0 or summary["badrec"] != 0:
        bad.append("%s: badframe=%d badrec=%d"
                   % (tag, summary["badframe"], summary["badrec"]))
    return sorted(bad)


def parse_oracle_log(path):
    """Parse an mv-oracle: dmesg log into traffic facts.

    Returns (ops, releases, complete_ops) where ops maps op
    index to its attempt/outcome/sync facts and releases maps
    mapping index to lifetime_ns. Raises ValueError on unknown
    line shapes (besides the known held-open/exit/mask notes).
    """
    ops = {}
    releases = {}

    def op_entry(i):
        return ops.setdefault(i, {"syncs": []})

    complete_ops = None
    with open(path) as handle:
        for raw in handle:
            match = ORACLE_LINE.search(raw)
            if not match:
                continue
            body = match.group(1).strip()
            hit = ORACLE_ATTEMPT.match(body)
            if hit:
                entry = op_entry(int(hit.group(1)))
                entry["requested"] = int(hit.group(2))
                entry["forced"] = int(hit.group(3))
                continue
            hit = ORACLE_OUTCOME.match(body)
            if hit:
                entry = op_entry(int(hit.group(1)))
                entry["success"] = hit.group(2) == "success"
                if entry["success"]:
                    entry["mapping"] = int(hit.group(3))
                    entry["mapped"] = int(hit.group(4))
                elif hit.group(5) == "-EIO":
                    entry["rc"] = -5
                else:
                    entry["rc"] = int(hit.group(5))
                continue
            hit = ORACLE_SYNC.match(body)
            if hit:
                entry = op_entry(int(hit.group(1)))
                entry["syncs"].append(
                    {"dir": int(hit.group(3)), "len": int(hit.group(4))})
                continue
            hit = ORACLE_RELEASE.match(body)
            if hit:
                releases[int(hit.group(1))] = int(hit.group(2))
                continue
            hit = ORACLE_COMPLETE.match(body)
            if hit:
                complete_ops = int(hit.group(1))
                continue
            if re.match(r"^op=\d+ mapping=\d+ (held-open|exit-release)$",
                        body):
                continue
            if re.match(r"^op=\d+ fail-probe (mask|map) rc=-?\d+$", body):
                continue
            if body in ("unloaded",):
                continue
            if body == "refusing to load without mv_oracle_arm=1":
                continue
            raise ValueError("unknown oracle line: %s" % body)
    return ops, releases, complete_ops


def scripted_expectation(ops, fail_op=-1):
    """Expected probe multisets for one scripted module run.

    Replicates the module script rules: sizes cycle
    512/1024/2048/4096, directions alternate TO/FROM, op 1
    syncs twice, the last successful op stays held until exit.
    Every map (even the fail-probe's inner success) carries a
    map-time TO bounce; sync_for_device bounces only for TO;
    release bounces only for FROM. Returns multisets as sorted
    lists of tuples.
    """
    maps = []
    unmaps = []
    syncs_dev = []
    syncs_cpu = []
    bounces = []
    for i in range(ops):
        size = LC_SIZES[i % len(LC_SIZES)]
        direction = 2 if i % 2 else 1
        failed = (i == fail_op)
        maps.append((size, direction, 1))
        # Map-time bounce always runs TO_DEVICE (the hook call
        # hardcodes the direction), whatever the mapping dir.
        bounces.append((1, size, 1))
        if failed:
            unmaps.append((size, direction, 1))
            continue
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            syncs_dev.append((size, direction))
            if direction == 1:
                bounces.append((1, size, direction))
        syncs_cpu.append((size, direction))
        if direction == 2:
            bounces.append((0, size, direction))
        unmaps.append((size, direction, 1))
    return {
        "maps": sorted(maps),
        "unmaps": sorted(unmaps),
        "syncs_dev": sorted(syncs_dev),
        "syncs_cpu": sorted(syncs_cpu),
        "bounces": sorted(bounces),
    }


def consumed_multisets(lc_events, cp_events):
    """Multisets of consumed probe records, same shapes."""
    maps = sorted(
        (e["size"], e["dir"], e["ok"]) for e in lc_events
        if e["kind"] == 1)
    unmaps = sorted(
        (e["size"], e["dir"], e["skip"]) for e in lc_events
        if e["kind"] == 2)
    syncs_dev = sorted(
        (e["req"], e["dir"]) for e in cp_events
        if e["kind"] == 1 and e["todev"] == 1)
    syncs_cpu = sorted(
        (e["req"], e["dir"]) for e in cp_events
        if e["kind"] == 1 and e["todev"] == 0)
    bounces = sorted(
        (e["todev"], e["req"], e["dir"]) for e in cp_events
        if e["kind"] == 2)
    return {
        "maps": maps,
        "unmaps": unmaps,
        "syncs_dev": syncs_dev,
        "syncs_cpu": syncs_cpu,
        "bounces": bounces,
    }


def compare_scripted(lc_events, cp_events, ops, fail_op, tag):
    """Compare consumed records against the scripted rules.

    Checks multiset equality per record class, strict flag
    rules (maps ok, unmaps skip-sync, syncs carry no bytes,
    every bounce known with effective equal to requested),
    and the stray-record rule (no record outside the five
    scripted classes). Returns a sorted mismatch list.
    """
    bad = []
    want = scripted_expectation(ops, fail_op)
    got = consumed_multisets(lc_events, cp_events)
    for key in ("maps", "unmaps", "syncs_dev", "syncs_cpu",
                "bounces"):
        if got[key] != want[key]:
            bad.append("%s: %s multiset differs: got %d want %d"
                       % (tag, key, len(got[key]), len(want[key])))
            for item in sorted(set(got[key]) ^ set(want[key])):
                bad.append("%s: %s drift %r" % (tag, key, item))
    for e in lc_events:
        if e["kind"] not in (1, 2):
            bad.append("%s: stray lc kind %d" % (tag, e["kind"]))
        elif e["kind"] == 1 and (e["ok"], e["skip"]) != (1, 0):
            bad.append("%s: map flags ok=%d skip=%d"
                       % (tag, e["ok"], e["skip"]))
        elif e["kind"] == 2 and (e["ok"], e["skip"]) != (1, 1):
            bad.append("%s: unmap flags ok=%d skip=%d"
                       % (tag, e["ok"], e["skip"]))
    for e in cp_events:
        if e["kind"] == 1:
            if (e["known"], e["reason"], e["eff"]) != (0, 4, 0):
                bad.append("%s: sync carries bytes %r" % (tag, e))
            if (e["clamp"], e["ezero"]) != (0, 0):
                bad.append("%s: sync flags %r" % (tag, e))
        elif e["kind"] == 2:
            if (e["known"], e["reason"]) != (1, 0):
                bad.append("%s: bounce unknown %r" % (tag, e))
            if e["eff"] != e["req"]:
                bad.append("%s: bounce eff %d != req %d"
                           % (tag, e["eff"], e["req"]))
            if (e["clamp"], e["ezero"]) != (0, 0):
                bad.append("%s: bounce flags %r" % (tag, e))
            want_todev = 1 if e["dir"] == 1 else 0
            if e["todev"] != want_todev:
                bad.append("%s: bounce dir/todev %r" % (tag, e))
        else:
            bad.append("%s: stray cp kind %d" % (tag, e["kind"]))
    return sorted(bad)


def check_oracle_script(ops_log, releases, complete_ops, ops,
                        fail_op, tag):
    """Check the module log ran the scripted sequence.

    Every op attempted once with the cycled size, outcomes
    success except the fail-probe, sync counts exact, every
    successful mapping released exactly once. Returns a sorted
    mismatch list.
    """
    bad = []
    if complete_ops != ops:
        bad.append("%s: script complete ops=%r want %d"
                   % (tag, complete_ops, ops))
    if sorted(ops_log) != list(range(ops)):
        bad.append("%s: op coverage %r" % (tag, sorted(ops_log)))
        return sorted(bad)
    for i in range(ops):
        entry = ops_log[i]
        want_size = LC_SIZES[i % len(LC_SIZES)]
        if entry.get("requested") != want_size:
            bad.append("%s: op %d requested %r want %d"
                       % (tag, i, entry.get("requested"), want_size))
        if entry.get("forced") != 0:
            bad.append("%s: op %d forced" % (tag, i))
        if i == fail_op:
            if "success" not in entry:
                bad.append("%s: fail op %d has no outcome"
                           % (tag, i))
            elif entry.get("success") is not False:
                bad.append("%s: fail op %d unexpectedly succeeded"
                           % (tag, i))
            if entry.get("syncs"):
                bad.append("%s: fail op %d synced" % (tag, i))
            continue
        if entry.get("success") is not True:
            bad.append("%s: op %d outcome %r"
                       % (tag, i, entry.get("success")))
            continue
        if entry.get("mapping") != i or entry.get("mapped") != want_size:
            bad.append("%s: op %d mapping %r" % (tag, i, entry))
        want_syncs = 2 if i == 1 else 1
        want_dir = 2 if i % 2 else 1
        syncs = entry.get("syncs", [])
        if len(syncs) != want_syncs:
            bad.append("%s: op %d %d syncs want %d"
                       % (tag, i, len(syncs), want_syncs))
        for sync in syncs:
            if sync != {"dir": want_dir, "len": want_size}:
                bad.append("%s: op %d sync %r" % (tag, i, sync))
    want_released = sorted(i for i in range(ops) if i != fail_op)
    if sorted(releases) != want_released:
        bad.append("%s: released %r want %r"
                   % (tag, sorted(releases), want_released))
    return sorted(bad)


def replay_oracle_ledger(ops_log, releases):
    """Replay oracle facts into an independent OracleLedger.

    Attempts/outcomes/releases come straight from the module
    log; executed copies derive by the source-backed rule
    (map-time TO bounce per success, sync_for_device bounce
    per TO sync, release bounce per FROM mapping). The
    ledger never sees probe output.
    """
    ledger = OracleLedger()
    for i in sorted(ops_log):
        entry = ops_log[i]
        ledger.record_attempt(i, "dev-1", entry["requested"],
                              entry["forced"])
        if entry.get("success") is True:
            size = entry["mapped"]
            ledger.record_outcome(i, True, mapping=i,
                                  mapped_bytes=size)
            ledger.record_copy(i, "original_to_bounce", size,
                               mapping=i)
            direction = (entry["syncs"][0]["dir"]
                         if entry["syncs"] else None)
            for sync in entry["syncs"]:
                if sync["dir"] == 1:
                    ledger.record_copy(i, "original_to_bounce",
                                       sync["len"], mapping=i)
            if direction == 2:
                ledger.record_copy(i, "bounce_to_original", size,
                                   mapping=i)
        else:
            ledger.record_outcome(i, False,
                                  return_code=entry.get("rc"))
    for mapping in sorted(releases):
        ledger.record_release(mapping, releases[mapping])
    ledger.seal()
    return ledger


def _live_event(session_id, seq, ts_ns, kind, hook, profile_id,
                data):
    return {
        "schema_version": "0.1.0",
        "session_id": session_id,
        "seq": str(seq),
        "ts_ns": str(ts_ns),
        "kind": kind,
        "source": {"hook": hook, "backend": "tracing",
                   "profile_id": profile_id,
                   "measurement": "observed",
                   "correlation": "direct"},
        "data": data,
    }


def translate_session(lc_events, cp_events, ops_log, out_dir,
                      session_id, profile_id):
    """Translate one scripted window into a live session dir.

    Pairing is by request size, which the scripted traffic
    keeps unique per op; anything ambiguous fails loudly
    instead of guessing. The caller must verify counter
    conservation first: the session claims complete detail.
    Returns the (probe_lifetimes, ordinals) pairing record.
    """
    sizes = {}
    for i, entry in ops_log.items():
        if entry.get("success") is not True:
            raise ValueError("op %d did not succeed" % i)
        size = entry["requested"]
        if size in sizes:
            raise ValueError("size %d repeats, pairing lost"
                             % size)
        sizes[size] = i
    op_of = {}
    map_ktime = {}
    for event in lc_events:
        if event["kind"] != 1:
            continue
        if event["size"] not in sizes:
            raise ValueError("unpaired map size %d"
                             % event["size"])
        op_of[event["size"]] = sizes[event["size"]]
        map_ktime[event["size"]] = event["ktime"]
    staged = []
    for event in lc_events:
        op = op_of.get(event["size"])
        if op is None:
            raise ValueError("unpaired lifecycle size %d"
                             % event["size"])
        if event["kind"] == 1:
            staged.append((event["ktime"], 0, _live_event(
                session_id, 0, event["ktime"], "map_result",
                "swiotlb:swiotlb_tbl_map_single", profile_id,
                {"operation_id": "op-%d" % op, "success": True,
                 "mapping_id": "map-%d" % op,
                 "return_code": None,
                 "mapped_bytes": str(event["size"])})))
        else:
            staged.append((event["ktime"], 0, _live_event(
                session_id, 0, event["ktime"], "unmap",
                "swiotlb:__swiotlb_tbl_unmap_single", profile_id,
                {"mapping_id": "map-%d" % op})))
    for event in cp_events:
        op = op_of.get(event["req"])
        if op is None:
            raise ValueError("unpaired copy size %d"
                             % event["req"])
        if event["kind"] == 1:
            staged.append((event["ktime"], 0, _live_event(
                session_id, 0, event["ktime"], "sync_request",
                "swiotlb:__swiotlb_sync_single", profile_id,
                {"operation_id": "op-%d" % op,
                 "mapping_id": "map-%d" % op, "offset": "0",
                 "length": str(event["req"])})))
        else:
            staged.append((event["ktime"], 0, _live_event(
                session_id, 0, event["ktime"], "copy",
                "swiotlb:swiotlb_bounce", profile_id,
                {"operation_id": "op-%d" % op,
                 "mapping_id": "map-%d" % op,
                 "direction": ("original_to_bounce"
                               if event["todev"] == 1
                               else "bounce_to_original"),
                 "bytes": str(event["eff"])})))
    for i, entry in sorted(ops_log.items()):
        size = entry["requested"]
        staged.append((map_ktime[size] - 1, -1, _live_event(
            session_id, 0, map_ktime[size] - 1, "bounce_attempt",
            "swiotlb:swiotlb_bounced", profile_id,
            {"device_id": "dev-1",
             "requested_bytes": str(size), "forced": False,
             "operation_id": "op-%d" % i})))
    staged.sort(key=lambda item: (item[0], item[1]))
    events = []
    for seq, (_, _, event) in enumerate(staged, 1):
        event["seq"] = str(seq)
        events.append(event)
    start = min(e["ktime"] for e in lc_events + cp_events) - 1
    end = max(e["ktime"] for e in lc_events + cp_events) + 1
    session = {
        "schema_version": "0.1.0",
        "session_id": session_id,
        "synthetic": False,
        "product": {"name": "memveil", "version": "0.1.0",
                    "build": None},
        "environment": {"mode": "unknown",
                        "detection": "unverified",
                        "asserted_mode": None,
                        "attestation": "not_performed",
                        "evidence": []},
        "capture": {"mode": "live",
                    "window": {"start_ns": str(start),
                               "end_ns": str(end)},
                    "filters": {"device": None},
                    "finalized": True, "end_reason": "duration"},
        "device_catalog": {"devices": [
            {"device_id": "dev-1", "name": "memveil-oracle",
             "driver": "platform-test",
             "identity_status": "resolved"}]},
        "baseline": {"complete": False,
                     "region_observations": []},
        "capabilities": {},
        "quality": {
            "detail": {"status": "complete_for_scope",
                       "loss_count": "0",
                       "scope": "live scripted window",
                       "reason": "Gate-verified conservation."},
            "aggregate": {"status": "unavailable",
                          "loss_count": None,
                          "scope": "counter snapshots",
                          "reason": "No counter snapshots."},
            "correlation": {"status": "complete_for_scope",
                            "loss_count": "0",
                            "scope": "size-paired live events",
                            "reason": "Unique sizes pair."},
            "baseline": {"status": "not_applicable",
                         "loss_count": None,
                         "scope": "lifecycle metrics",
                         "reason": "No baseline needed."},
            "terminal": {"status": "complete_for_scope",
                         "loss_count": "0",
                         "scope": "gate finalization",
                         "reason": "Gate finalized."}},
    }
    for cap, hook in (
            ("bounce_attempts", "swiotlb:swiotlb_bounced"),
            ("mapping_lifecycle",
             "swiotlb:swiotlb_tbl_map_single"),
            ("copy_bytes", "swiotlb:swiotlb_bounce"),
            ("sync_requests",
             "swiotlb:__swiotlb_sync_single")):
        session["capabilities"][cap] = {
            "status": "verified",
            "reason": "Live gate observation.",
            "hooks": [hook], "profile_id": profile_id}
    for cap in ("conversion_results", "region_state",
                "pool_stats", "task_context"):
        session["capabilities"][cap] = {
            "status": "unavailable",
            "reason": "No source in this session.",
            "hooks": [], "profile_id": None}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "session.json"), "w") as fh:
        json.dump(session, fh, indent=1, sort_keys=True)
        fh.write("\n")
    with open(os.path.join(out_dir, "events.ndjson"), "w") as fh:
        for event in events:
            json.dump(event, fh, sort_keys=True)
            fh.write("\n")
    probe_lifetimes = {}
    for event in lc_events:
        op = op_of[event["size"]]
        slot = probe_lifetimes.setdefault(op, {})
        if event["kind"] == 1:
            slot["map"] = event["ktime"]
        else:
            slot["unmap"] = event["ktime"]
    return probe_lifetimes


def compare_live(report, ledger):
    """Compare a live report against the oracle ledger.

    Allocation, copy, live/open, and completed-count rules
    match compare() exactly. Lifetimes differ by
    construction: the module measures map-entry to
    unmap-exit (including its own printk latency) while the
    probes stamp the inner call, so the probe interval sits
    strictly inside the module interval and the two
    observers may straddle a histogram boundary. The gate
    asserts that ordering per mapping (exact) and lifts it
    to the mean and p50/p99 edges (bucketing is monotone),
    instead of exact cross-observer equality. Returns
    mismatches.
    """
    from oracle_ledger import compare
    bad = [m for m in compare(report, ledger)
           if not (m.startswith("lifetime_mean_ns")
                   or m.startswith("lifetime_p50_ns")
                   or m.startswith("lifetime_p99_ns"))]
    metrics = {}
    for m in report["metrics"]:
        dims = m["dimensions"]
        if dims["device_id"] is None and dims["pool_id"] is None:
            metrics[m["name"]] = m
    want_durs = ledger.expected_lifetimes()
    if want_durs:
        mean = metrics.get("lifetime_mean_ns")
        if mean is None or mean["value"] is None:
            bad.append("missing metric lifetime_mean_ns")
        elif int(mean["value"]) > sum(want_durs) // len(want_durs):
            bad.append("lifetime_mean_ns %s exceeds ledger %d"
                       % (mean["value"],
                          sum(want_durs) // len(want_durs)))
        for frac, name in ((50, "lifetime_p50_ns"),
                           (99, "lifetime_p99_ns")):
            got = metrics.get(name)
            if got is None or got["value"] is None:
                bad.append("missing metric " + name)
                continue
            rank = nearest_rank(frac, 100, len(want_durs))
            truth = sorted(want_durs)[rank - 1]
            edge = bucket_upper_edge(bucket_of(truth))
            if int(got["value"]) > edge:
                bad.append("%s %s exceeds ledger edge %d"
                           % (name, got["value"], edge))
    return sorted(bad)


def check_lifetime_ordering(probe_lifetimes, releases, tag):
    """Probe intervals sit inside module intervals, per mapping."""
    bad = []
    for op, slot in sorted(probe_lifetimes.items()):
        if "map" not in slot or "unmap" not in slot:
            bad.append("%s: op %d unpaired probe ends" % (tag, op))
            continue
        probe_dur = slot["unmap"] - slot["map"]
        module_dur = releases.get(op)
        if module_dur is None:
            bad.append("%s: op %d never released" % (tag, op))
            continue
        if probe_dur < 0:
            bad.append("%s: op %d negative probe life" % (tag, op))
        if probe_dur > module_dur:
            bad.append("%s: op %d probe %d exceeds module %d"
                       % (tag, op, probe_dur, module_dur))
    return sorted(bad)
