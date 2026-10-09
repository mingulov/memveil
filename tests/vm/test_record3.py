#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Shipped three-channel record against oracle scenario 1.

Boots the guest, runs the real `memveil record` with the
attempt plus lifecycle plus copy channels under a minted
test profile, drives oracle 0.4.0 scenario 1 (nested
4096+1024 maps, cpu syncs, witnessed copies, paired
unmaps), and compares the shipped capture against the
frozen canonical scenario-1 expectations. Address-blind
throughout: mapping identity travels on wire generations.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import parse_oracle_log
from lifecycle_env import (BRIDGE, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from test_attempt_capture import evidence
from vm_boot import cleanup, run_guest, verify_exports

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ATTEMPT_PROBE = os.path.join(
    REPO, "build", "bpf", "swiotlb_attempt.bpf.o")
SPEC = os.path.join(REPO, "tests", "vm", "fixtures",
                    "canonical-expectations.json")


def _mint_profile():
    out = os.path.join(REPO, "build", "vm",
                       "record3-profile.json")
    proc = subprocess.run(
        [sys.executable,
         os.path.join(REPO, "tests", "vm",
                      "mint_record3_profile.py"),
         "--out", out],
        capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, proc.stderr[-2000:]
    with open(out) as handle:
        profile = json.load(handle)
    assert profile["schema_version"] == "0.1.1", profile
    assert {hook["function"] for hook in profile["hooks"]
            if hook["kind"] == "tracing"} == {
        "swiotlb_tbl_map_single",
        "__swiotlb_tbl_unmap_single",
        "__swiotlb_sync_single_for_device",
        "__swiotlb_sync_single_for_cpu",
        "swiotlb_bounce"}, profile
    return profile


def _events(path):
    with open(path) as handle:
        return [json.loads(line) for line in handle
                if line.strip()]


def check_capture_session(events, session, record, tag,
                          span_lo, span_hi, profile_id,
                          paired=True, end_reason="duration",
                          strict_loss=True):
    """Session-wide record admission, quality, and ordering.

    paired=True expects the designed v2 split (correlation
    honestly partial); single-channel captures without
    lifecycle refs pass paired=False (correlation not
    applicable: attempt counting has nothing to correlate).
    """
    bad = []
    if record["exit"] != 4:
        bad.append("%s: record exit %r != 4 (bounded)"
                   % (tag, record["exit"]))
    if session["capture"]["finalized"] is not True:
        bad.append("%s: capture not finalized" % tag)
    decision = evidence(session, "profile.decision")
    if decision != ("candidate %s: "
                    "bindings hold (profile unvalidated)"
                    % profile_id):
        bad.append("%s: profile decision %r" % (tag, decision))
    if session["capture"].get("end_reason") != end_reason:
        bad.append("%s: end_reason %r want %r"
                   % (tag, session["capture"].get("end_reason"),
                      end_reason))
    window = session["capture"]["window"]
    span = int(window["end_ns"]) - int(window["start_ns"])
    if not span_lo <= span <= span_hi:
        bad.append("%s: window span %d ns outside [%d, %d]"
                   % (tag, span, span_lo, span_hi))
    for channel in ("detail", "aggregate"):
        quality = session["quality"][channel]
        if strict_loss:
            if quality["status"] != "complete_for_scope":
                bad.append("%s: %s quality %r"
                           % (tag, channel, quality))
            if quality["loss_count"] != "0":
                bad.append("%s: %s loss %r"
                           % (tag, channel,
                              quality["loss_count"]))
        elif quality["status"] not in (
                "complete_for_scope", "partial"):
            bad.append("%s: %s quality %r"
                       % (tag, channel, quality))
    corr = session["quality"]["correlation"]
    if paired:
        if corr["status"] != "partial":
            bad.append("%s: correlation quality %r" % (tag, corr))
        for phrase in ("copy without pending operation",
                       "sync references unknown mapping"):
            if phrase not in corr["reason"]:
                bad.append("%s: correlation reason %r"
                           % (tag, corr["reason"]))
    elif corr["status"] != "not_applicable":
        bad.append("%s: 1ch correlation quality %r" % (tag, corr))
    elif "needs no cross-event correlation" not in corr["reason"]:
        bad.append("%s: 1ch correlation reason %r"
                   % (tag, corr["reason"]))
    if session["quality"]["terminal"]["status"] != "partial":
        bad.append("%s: terminal quality %r"
                   % (tag, session["quality"]["terminal"]))
    seqs = [int(e["seq"]) for e in events]
    if seqs != sorted(seqs) or len(set(seqs)) != len(seqs):
        bad.append("%s: event seq not ordered unique" % tag)
    sids = {e["session_id"] for e in events}
    if sids != {session["session_id"]}:
        bad.append("%s: session ids %r" % (tag, sids))
    return bad


def check_lifetimes(maps, unmaps, tag, exact):
    """Generation-paired release order; lifetimes never negative."""
    bad = []
    born = {}
    for event in maps:
        gen = event["data"]["wire_generation"]
        if gen is None:
            continue
        born.setdefault(gen, int(event["ts_ns"]))
    for event in unmaps:
        gen = event["data"]["wire_generation"]
        if gen not in born:
            bad.append("%s: unmap without map gen %r"
                       % (tag, gen))
        elif int(event["ts_ns"]) < born[gen]:
            bad.append("%s: negative lifetime gen %r" % (tag, gen))
    if exact and sorted(
            e["data"]["wire_generation"] for e in unmaps
            ) != sorted(born):
        bad.append("%s: unmap gens differ from map gens" % tag)
    return bad


def check_oracle_slice(events, tag):
    """Exact scenario-1 multisets plus generation pairing."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    attempts = kinds.get("bounce_attempt", [])
    if len(maps) != 2:
        bad.append("%s: want 2 map_result, got %d"
                   % (tag, len(maps)))
    if len(unmaps) != 2:
        bad.append("%s: want 2 unmap, got %d"
                   % (tag, len(unmaps)))
    if len(syncs) != 2:
        bad.append("%s: want 2 sync_request, got %d"
                   % (tag, len(syncs)))
    if len(copies) != 2:
        bad.append("%s: want 2 copy, got %d"
                   % (tag, len(copies)))
    if len(attempts) != 2:
        bad.append("%s: want 2 bounce_attempt, got %d"
                   % (tag, len(attempts)))
    if sorted(e["data"]["mapped_bytes"] for e in maps
              ) != ["1024", "4096"]:
        bad.append("%s: map sizes %r"
                   % (tag, [e["data"].get("mapped_bytes")
                            for e in maps]))
    if [e["data"]["success"] for e in maps] != [True, True]:
        bad.append("%s: map success %r" % (tag, maps))
    gens = [e["data"]["wire_generation"] for e in maps]
    if any(g in (None, "0") for g in gens):
        bad.append("%s: map gen unassigned %r" % (tag, gens))
    if len(set(gens)) != 2:
        bad.append("%s: maps share gen %r" % (tag, gens))
    bad += check_lifetimes(maps, unmaps, tag, True)
    if sorted(e["data"]["length"] for e in syncs
              ) != ["1024", "4096"]:
        bad.append("%s: sync lengths %r" % (tag, syncs))
    for e in syncs:
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
    if sorted(e["data"]["bytes"] for e in copies
              ) != ["1024", "4096"]:
        bad.append("%s: copy bytes %r" % (tag, copies))
    for e in copies:
        if e["data"]["direction"] != "original_to_bounce":
            bad.append("%s: copy dir %r" % (tag, e))
    return bad


def check_record3_capture(events, session, record, tag):
    """Session checks plus whole-capture scenario-1 multisets."""
    bad = check_capture_session(
        events, session, record, tag,
        20_000_000_000, 45_000_000_000, "record3-ephemeral")
    bad += check_oracle_slice(events, tag)
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    ends = {}
    for snap in kinds.get("counter_snapshot", []):
        ends.setdefault(snap["data"]["counter_id"], []).append(
            snap["data"]["value"])
    if sorted(ends.get("swiotlb.bounce_attempts", [])) != [
            "0", "2"]:
        bad.append("%s: attempt counter %r" % (tag, ends))
    if sorted(ends.get("swiotlb.requested_bytes", [])) != [
            "0", "5120"]:
        bad.append("%s: bytes counter %r" % (tag, ends))
    pools = kinds.get("pool_sample", [])
    if len(pools) != 2:
        bad.append("%s: want 2 pool_sample, got %d"
                   % (tag, len(pools)))
    elif pools[-1]["data"]["used_bytes"] != pools[0][
            "data"]["used_bytes"]:
        bad.append("%s: pool not drained to baseline %r"
                   % (tag, pools))
    return sorted(bad)


def test_record3_three_channel_capture():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE,
                          ATTEMPT_PROBE, BRIDGE)
    ensure_oracle_module()
    _mint_profile()
    with open(SPEC) as handle:
        frozen = json.load(handle)
    assert frozen["frozen_for_module"] == "0.4.0", frozen
    tmp, proc = run_guest("record3", timeout=900)
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(
            tmp, "record3",
            ["identity.json", "record.json",
             "cap-session.json", "cap-events.ndjson",
             "r3-oracle.log"])
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        record = json.loads(got["record.json"].read_text())
        session = json.loads(
            got["cap-session.json"].read_text())
        events = _events(got["cap-events.ndjson"])
        ops_log, releases, complete = parse_oracle_log(
            str(got["r3-oracle.log"]))
        assert complete, "oracle scenario 1 incomplete"
        assert len(ops_log) == 2, ops_log
        assert sorted(entry["requested"] for entry in
                      ops_log.values()) == [1024, 4096], ops_log
        bad = check_record3_capture(events, session,
                                    record, "r3")
        assert not bad, "\n".join(bad)
        witnessed = frozen["n"]["witnessed_total"]
        eff = sum(int(e["data"]["bytes"]) for e in events
                  if e["kind"] == "copy")
        assert eff == witnessed, (eff, witnessed)
        print("r3: 2 maps + 2 syncs + 2 copies + "
              "%d attempts, eff=%d ok"
              % (sum(1 for e in events
                     if e["kind"] == "bounce_attempt"),
                 eff))
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
