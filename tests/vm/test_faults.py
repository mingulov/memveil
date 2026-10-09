#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""F2-7: multi-channel faults through shipped record.

Seven scenarios in one guest: truncated lc/cp objects refuse
with exit 3 and zero BPF residue; SIGTERM mid-capture (1ch and
3ch) stops bounded with a signal end reason; a full output
filesystem fails honestly without a masquerading session;
paced 300-op floods compare 1ch against 3ch capture exactly;
a burst flood reconciles recorded plus omitted against the
scripted prediction; background flood during attach leaves no
pre-window records. Helper tests do not substitute: every
scenario drives the real binary, real attach, and real rings.
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import parse_oracle_log, scripted_expectation
from lifecycle_env import (BRIDGE, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module,
                           require_lifecycle_env)
from test_bundle import check_report
from test_record3 import (ATTEMPT_PROBE, _events, _mint_profile,
                          check_capture_session, check_lifetimes,
                          check_oracle_slice)
from vm_boot import cleanup, run_guest, verify_exports

CAPTURES = ("f3a", "f3b", "f5a", "f5b", "f5c", "f6")
FLOOD_OPS = 300


def _slice(events, window):
    return [e for e in events
            if window[0] <= int(e["ts_ns"]) <= window[1]]


def _detail(events):
    return [e for e in events if e["kind"] in (
        "bounce_attempt", "map_result", "unmap",
        "sync_request", "copy")]


def check_flood_slice(events, want, tag):
    """Exact scripted-flood multisets plus generation pairing."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    syncs = kinds.get("sync_request", [])
    copies = kinds.get("copy", [])
    attempts = kinds.get("bounce_attempt", [])
    if len(maps) != len(want["maps"]):
        bad.append("%s: want %d maps, got %d"
                   % (tag, len(want["maps"]), len(maps)))
    if len(unmaps) != len(want["unmaps"]):
        bad.append("%s: want %d unmaps, got %d"
                   % (tag, len(want["unmaps"]), len(unmaps)))
    want_syncs = want["syncs_dev"] + want["syncs_cpu"]
    if len(syncs) != len(want_syncs):
        bad.append("%s: want %d syncs, got %d"
                   % (tag, len(want_syncs), len(syncs)))
    if len(copies) != len(want["bounces"]):
        bad.append("%s: want %d copies, got %d"
                   % (tag, len(want["bounces"]), len(copies)))
    if len(attempts) != len(want["maps"]):
        bad.append("%s: want %d attempts, got %d"
                   % (tag, len(want["maps"]), len(attempts)))
    if sorted(int(e["data"]["mapped_bytes"]) for e in maps
              ) != sorted(s for s, _, _ in want["maps"]):
        bad.append("%s: map sizes drift" % tag)
    if any(not e["data"]["success"] for e in maps):
        bad.append("%s: map failure in flood" % tag)
    gens = [e["data"]["wire_generation"] for e in maps]
    if any(g in (None, "0") for g in gens):
        bad.append("%s: map gen unassigned" % tag)
    if len(set(gens)) != len(maps):
        bad.append("%s: maps share gen" % tag)
    bad += check_lifetimes(maps, unmaps, tag, True)
    if sorted(int(e["data"]["length"]) for e in syncs
              ) != sorted(req for req, _ in want_syncs):
        bad.append("%s: sync lengths drift" % tag)
    for e in syncs:
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
            break
    want_todev = sorted(req for todev, req, _ in
                        want["bounces"] if todev == 1)
    want_tocpu = sorted(req for todev, req, _ in
                        want["bounces"] if todev == 0)
    got_todev = sorted(int(e["data"]["bytes"]) for e in copies
                       if e["data"]["direction"]
                       == "original_to_bounce")
    got_tocpu = sorted(int(e["data"]["bytes"]) for e in copies
                       if e["data"]["direction"]
                       == "bounce_to_original")
    if got_todev != want_todev:
        bad.append("%s: to-device copies drift" % tag)
    if got_tocpu != want_tocpu:
        bad.append("%s: to-cpu copies drift" % tag)
    if sorted(int(e["data"]["requested_bytes"])
              for e in attempts
              ) != sorted(s for s, _, _ in want["maps"]):
        bad.append("%s: attempt bytes drift" % tag)
    return bad


def check_cut_slice(events, ops_logged, tag):
    """Signal-cut prefix: strict subset, sane pairing."""
    bad = []
    kinds = {}
    for event in events:
        kinds.setdefault(event["kind"], []).append(event)
    attempts = kinds.get("bounce_attempt", [])
    if not 0 < len(attempts) <= ops_logged:
        bad.append("%s: attempts %d vs %d logged"
                   % (tag, len(attempts), ops_logged))
    maps = kinds.get("map_result", [])
    unmaps = kinds.get("unmap", [])
    if maps and not 0 < len(maps) <= ops_logged:
        bad.append("%s: maps %d vs %d logged"
                   % (tag, len(maps), ops_logged))
    bad += check_lifetimes(maps, unmaps, tag, False)
    for e in kinds.get("sync_request", []):
        if (e["data"]["offset_known"],
                e["data"]["offset"]) != (False, None):
            bad.append("%s: sync offset %r" % (tag, e))
            break
    return bad


def test_faults_multi_channel():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE,
                          ATTEMPT_PROBE, BRIDGE)
    ensure_oracle_module()
    _mint_profile()
    want = scripted_expectation(FLOOD_OPS, -1)
    tmp, proc = run_guest("faults", timeout=1200, network=True)
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        names = ["identity.json", "faults.json",
                 "f4-oracle.log", "f3b-report.json",
                 "f3a-cut-oracle.log", "f3b-cut-oracle.log"]
        for tag in CAPTURES:
            names += [f"{tag}-record.json", f"{tag}-session.json",
                      f"{tag}-events.ndjson", f"{tag}-oracle.log"]
        got = verify_exports(tmp, "faults", names)
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        ledger = {row["scenario"]: row for row in
                  json.loads(got["faults.json"].read_text())}
        for tag, row in sorted(ledger.items()):
            assert row["settle_s"] < 30, (tag, row)
            if tag == "f3b-report":
                continue
            assert row["progs_after"] == row["progs_before"], \
                (tag, row)
            assert row["maps_after"] == row["maps_before"], \
                (tag, row)
        for tag in ("f1", "f2"):
            row = ledger[tag]
            assert row["exit"] == 3, row
            assert row["cap"] is False, row
            assert row["stderr"], row
            print("ft-%s refused: %s" % (tag, row["stderr"]))
        row = ledger["f4"]
        assert row["exit"] == 1, row
        assert row["cap"] is False, row
        assert row["events_kept"] is True, row
        assert row["stderr"], row
        f4_ops, _, _ = parse_oracle_log(
            str(got["f4-oracle.log"]))
        assert len(f4_ops) == 2, f4_ops
        caps = {}
        for tag in CAPTURES:
            record = json.loads(
                got[f"{tag}-record.json"].read_text())
            session = json.loads(
                got[f"{tag}-session.json"].read_text())
            events = _events(got[f"{tag}-events.ndjson"])
            ops, _, _ = parse_oracle_log(
                str(got[f"{tag}-oracle.log"]))
            caps[tag] = (record, session, events, ops)
        bad = []
        for tag in ("f3a", "f3b"):
            record, session, events, ops = caps[tag]
            window = ledger[tag]["window"]
            rest = "3ch" if tag == "f3b" else "1ch"
            cut, _, _ = parse_oracle_log(
                str(got[f"{tag}-cut-oracle.log"]))
            assert len(ops) == FLOOD_OPS, (tag, len(ops))
            assert 0 < len(cut) < FLOOD_OPS, \
                (tag, len(cut))
            bad += check_capture_session(
                events, session, record, "ft-" + tag,
                5_000_000_000, 30_000_000_000,
                "record3-ephemeral", tag == "f3b", "signal",
                False)
            bad += check_cut_slice(_slice(events, window),
                                   len(cut), "ft-" + tag)
            print("ft-%s (%s signal cut): %d/%d ops at cut" % (
                tag, rest, len(cut), len(ops)))
        report = json.loads(got["f3b-report.json"].read_text())
        assert ledger["f3b-report"]["exit"] == 4, ledger
        bad += check_report(
            report, caps["f3b"][2],
            {"report_exit": ledger["f3b-report"]["exit"]},
            "ft-f3b-r", False)
        for tag in ("f5a", "f5b"):
            record, session, events, ops = caps[tag]
            window = ledger[tag]["window"]
            assert len(ops) == FLOOD_OPS, (tag, len(ops))
            bad += check_capture_session(
                events, session, record, "ft-" + tag,
                100_000_000_000, 150_000_000_000,
                "record3-ephemeral", tag == "f5b")
            sl = _slice(events, window)
            kinds = {e["kind"] for e in sl}
            if tag == "f5a":
                assert not (kinds & {"map_result", "unmap",
                                     "sync_request", "copy"}), \
                    (tag, kinds)
                got_sizes = sorted(
                    int(e["data"]["requested_bytes"]) for e in sl
                    if e["kind"] == "bounce_attempt")
                assert got_sizes == sorted(
                    s for s, _, _ in want["maps"]), tag
            else:
                bad += check_flood_slice(sl, want, "ft-" + tag)
        a_sizes = sorted(
            int(e["data"]["requested_bytes"]) for e in _slice(
                caps["f5a"][2], ledger["f5a"]["window"])
            if e["kind"] == "bounce_attempt")
        b_sizes = sorted(
            int(e["data"]["requested_bytes"]) for e in _slice(
                caps["f5b"][2], ledger["f5b"]["window"])
            if e["kind"] == "bounce_attempt")
        assert a_sizes == b_sizes, "1ch/3ch attempt drift"
        print("ft-f5: 1ch/3ch attempt streams identical, "
              "%d floods exact" % len(a_sizes))
        record, session, events, ops = caps["f5c"]
        window = ledger["f5c"]["window"]
        assert len(ops) == FLOOD_OPS, len(ops)
        bad += check_capture_session(
            events, session, record, "ft-f5c",
            100_000_000_000, 150_000_000_000,
            "record3-ephemeral", True, "duration", False)
        sl = _slice(events, window)
        kinds = {}
        for event in sl:
            kinds.setdefault(event["kind"], []).append(event)
        predicted = (len(want["maps"]) + len(want["unmaps"])
                     + len(want["syncs_dev"])
                     + len(want["syncs_cpu"])
                     + len(want["bounces"])
                     + len(want["maps"]))
        loss = int(session["quality"]["detail"]["loss_count"])
        buckets = dict(re.findall(
            r"([a-z_]+)=\((\d+)\)",
            session["quality"]["detail"]["reason"]))
        assert buckets, session["quality"]["detail"]["reason"]
        for key, value in buckets.items():
            if key != "duration_omitted":
                assert value == "0", (key, buckets)
        assert buckets.get("duration_omitted", "0") == str(
            loss), buckets
        ambient = [e for e in _detail(events)
                   if not window[0] <= int(e["ts_ns"])
                   <= window[1]]
        total = len(_detail(events)) + loss
        assert total == predicted + len(ambient), (
            len(_detail(events)), loss, predicted,
            len(ambient))
        if len(kinds.get("map_result", [])) > len(want["maps"]):
            bad.append("ft-f5c: maps exceed prediction")
        if len(kinds.get("copy", [])) > len(want["bounces"]):
            bad.append("ft-f5c: copies exceed prediction")
        bad += check_lifetimes(kinds.get("map_result", []),
                               kinds.get("unmap", []),
                               "ft-f5c", False)
        print("ft-f5c: burst %d recorded + %d omitted == "
              "predicted + ambient" % (
                  len(_detail(events)), loss))
        record, session, events, ops = caps["f6"]
        window = ledger["f6"]["window"]
        assert len(ops) == 2, ops
        assert sorted(e["requested"] for e in ops.values()
                      ) == [1024, 4096], ops
        bad += check_capture_session(
            events, session, record, "ft-f6",
            40_000_000_000, 90_000_000_000,
            "record3-ephemeral")
        start = int(session["capture"]["window"]["start_ns"])
        early = [e for e in _detail(events)
                 if int(e["ts_ns"]) < start]
        assert not early, "pre-window records: %r" % early[:3]
        bad += check_oracle_slice(_slice(events, window),
                                  "ft-f6")
        ambient = [e for e in _detail(events)
                   if not window[0] <= int(e["ts_ns"])
                   <= window[1]]
        bad += check_lifetimes(
            [e for e in events if e["kind"] == "map_result"],
            [e for e in ambient if e["kind"] == "unmap"],
            "ft-f6-amb", False)
        print("ft-f6: attach race clean, oracle slice exact, "
              "%d ambient" % len(ambient))
        assert not bad, "\n".join(bad)
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
