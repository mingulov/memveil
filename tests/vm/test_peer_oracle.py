#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""L11 peer leg: offline oracle tests plus the armed live leg.

Offline: the characterisation tests prove the oracle
reader, pairing, and judge against recorded tracefs oracle
bytes plus synthetic edge traces. The live leg runs only
when explicitly armed (``MEMVEIL_VM_PEER=1`` with sealed C9
inputs); anything else skips fast without booting. An
armed leg with missing pieces fails instead of skipping.

Battery adoption contract: this module is case ``peer``
(``peer_oracle.CASE_ID``); the case-selectable battery
runner adopts it by id with a full-machine network boot.
"""

import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import peer_oracle
from peer_oracle import OracleError

REPO = Path(__file__).resolve().parent.parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures" \
    / "peer-oracle"
GUEST_FLOW = REPO / "tests" / "vm" / "peer_oracle_guest.py"
LOCK = REPO / "tests" / "vm" / "kernels.lock.json"

# Recorded oracle bytes; the tests refuse silently edited
# fixtures by pinning these digests.
STEP3_SHA = "b9751b2264b739ab58932058ba010bffb9476fcc7577" \
    "7552a1b9fffc846a1edd"
STEP5_SHA = "7545c89f084ba51d9fee0436affa7c5a774fc24c776c" \
    "67b0936ac5d0e7e9bbec"

BDF = "0000:00:0c.0"
OTHER_BDF = "0000:00:0d.0"
PROBE_BRACKET = {"pre": "L11-PHASE5-PRE",
                 "down": "L11-PHASE5-DOWN",
                 "up": "L11-PHASE5-UP",
                 "post": "L11-PHASE5-POST",
                 "end": "L11-PHASE5-END"}
PROFILE = "linux-x86_64-7.0-reference"


def fixture_text(name):
    return (FIXTURES / name).read_text()


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def ts_str(sec, us):
    return "%d.%06d" % (sec, us)


def ev_line(task, cpu, sec, us, event, body):
    return "%s [%s] ...1. %s: %s: %s" % (
        task, cpu, ts_str(sec, us), event, body)


def map_body(dev=BDF, direction="TO_DEVICE", addr="bbcdb000",
             size=98, phys="1034258c2", attrs=""):
    return "%s dir=%s dma_addr=%s size=%d phys_addr=%s attrs=%s" \
        % (dev, direction, addr, size, phys, attrs)


def unmap_body(dev=BDF, direction="TO_DEVICE", addr="bbcdb000",
               size=98, attrs=""):
    return "%s dir=%s dma_addr=%s size=%d attrs=%s" \
        % (dev, direction, addr, size, attrs)


def mark_line(task, cpu, sec, us, text):
    return ev_line(task, cpu, sec, us, "tracing_mark_write",
                   text)


def dump(entries):
    """Full ``trace`` dump text with an exact entries header."""
    head = ["# tracer: nop", "#",
            "# entries-in-buffer/entries-written: %d/%d   #P:2"
            % (len(entries), len(entries)),
            "#",
            "#                                _-----=> irqs-off",
            "#           TASK-PID     CPU#  TIMESTAMP  FUNCTION",
            "#              | |         |       |         |"]
    return "\n".join(head + entries) + "\n"


def window_doc(rows, counts, drops=None, entries=None,
               markers=0, extra=None):
    """Valid window export block around opaque rows."""
    drops = {"cpu0": 0, "cpu1": 0} if drops is None else drops
    if entries is None:
        entries = len(rows) + markers
    doc = {"entries_in_buffer": entries,
           "entries_written": entries,
           "markers": markers,
           "drops_before": dict(drops),
           "drops_after": dict(drops),
           "events": rows}
    doc.update(counts)
    if extra:
        doc.update(extra)
    return doc


def traffic_rows(pairs):
    """Opaque traffic rows for ``[(size, dir)]`` pairs."""
    rows = []
    line = 14
    for index, (size, direction) in enumerate(pairs):
        key = "k%04d" % (index + 1,)
        rows.append({"line": line, "ts_us": 1000000 + index * 20,
                     "cpu": "000", "kind": "map", "key": key,
                     "dir": direction, "size": size})
        rows.append({"line": line + 1,
                     "ts_us": 1000010 + index * 20,
                     "cpu": "000", "kind": "unmap", "key": key,
                     "dir": direction, "size": size})
        line += 2
    return rows


def peer_doc(traffic, bracket):
    """Valid ``peer.json`` around two window blocks."""
    jam = "0" * 64
    return {
        "schema": peer_oracle.PEER_SCHEMA,
        "case": peer_oracle.CASE_ID,
        "guest": {"release": "7.0.14-070014-generic",
                  "swiotlb_force": True, "btf_sha": jam,
                  "iface": "eth1", "pci": BDF,
                  "dma_mask_bits": 32,
                  "addr": "10.0.3.15/24",
                  "link_up_at_end": True,
                  "trace_root": "/sys/kernel/tracing",
                  "trace_clock": "[local] global counter"},
        "oracle": {"events": ["dma_map_phys",
                              "dma_unmap_phys"],
                   "event_ids": {"dma_map_phys": 381,
                                 "dma_unmap_phys": 380},
                   "format_sha": {"dma_map_phys": jam,
                                  "dma_unmap_phys": jam},
                   "format_tokens_ok": True,
                   "buffer_kb": 4096},
        "c9": {"binary_sha": jam, "profile": PROFILE,
               "caps": "attempt-trace,mapping-lifecycle,"
                       "copy-actual",
               "duration_s": 60, "record_exit": 0,
               "ready_session": "cap-1-1",
               "ready_start_ns": 10000000000,
               "window_clock": peer_oracle.MONO_CLOCK,
               "mono_open_ns": 11000000000,
               "mono_close_ns": 12000000000},
        "workload": {"ping_tx": 500, "ping_rx": 500,
                     "nic_tx_before": 2, "nic_tx_after": 502,
                     "nic_rx_before": 2, "nic_rx_after": 502},
        "traffic": traffic,
        "bracket": bracket,
    }


def bracket_fixture_rows():
    """Bracket rows: pre 1/1, teardown orphan, post pair + held."""
    return [
        {"line": 14, "ts_us": 1000000, "cpu": "000",
         "kind": "map", "key": "k0001", "dir": "TO_DEVICE",
         "size": 98},
        {"line": 15, "ts_us": 1000010, "cpu": "000",
         "kind": "unmap", "key": "k0001", "dir": "TO_DEVICE",
         "size": 98},
        {"line": 17, "ts_us": 2000000, "cpu": "001",
         "kind": "unmap", "key": "k0002",
         "dir": "FROM_DEVICE", "size": 1544},
        {"line": 19, "ts_us": 3000000, "cpu": "001",
         "kind": "map", "key": "k0003", "dir": "TO_DEVICE",
         "size": 98},
        {"line": 20, "ts_us": 3000010, "cpu": "001",
         "kind": "unmap", "key": "k0003", "dir": "TO_DEVICE",
         "size": 98},
        {"line": 21, "ts_us": 3000020, "cpu": "001",
         "kind": "map", "key": "k0004",
         "dir": "FROM_DEVICE", "size": 1544},
    ]


def bracket_fixture_doc():
    rows = bracket_fixture_rows()
    counts = {"maps": 3, "unmaps": 3, "pairs": 2,
              "orphans": 1, "still_open": 1,
              "mismatches": 0, "order_violations": 0,
              "other_device": 0}
    extra = {"marker_lines": {"pre": 13, "down": 16, "up": 18,
                              "post": 22, "end": 23},
             "pre_existing": 1, "held_open": 1}
    return window_doc(rows, counts, markers=5, extra=extra)


def traffic_fixture_doc(pairs=((98, "TO_DEVICE"),)):
    rows = traffic_rows(pairs)
    count = len(pairs)
    counts = {"maps": count, "unmaps": count, "pairs": count,
              "orphans": 0, "still_open": 0,
              "mismatches": 0, "order_violations": 0,
              "other_device": 0}
    return window_doc(rows, counts, markers=2)


def c9_fold(maps_by_size, unmaps, copies, events=0,
            profile=PROFILE, session="cap-1-1", attempts=0):
    """Hand-built ``parse_c9_stream``-shaped fold."""
    by_dir = Counter()
    bytes_by_dir = Counter()
    for direction, count, total in copies:
        by_dir[direction] += count
        bytes_by_dir[direction] += total
    kinds = Counter({"map_result": sum(maps_by_size.values())})
    if attempts:
        kinds["bounce_attempt"] = attempts
    return {"maps_by_size": Counter(maps_by_size),
            "copies_by_dir": by_dir,
            "copy_bytes_by_dir": bytes_by_dir,
            "unmaps": unmaps, "attempts": attempts,
            "profiles": {profile},
            "sessions": {session},
            "kinds": kinds,
            "events": events
            or (sum(maps_by_size.values()) + attempts)}


def live_summary(session="cap-1-1", start=10000000000,
                 end=60000000000):
    return {"id": session, "synthetic": False,
            "start": start, "end": end,
            "finalized": True, "end_reason": "duration"}


def zero_loss():
    return {"total": 0,
            "buckets": {name: 0
                        for name in peer_oracle.LOSS_BUCKETS}}


def test_fixture_hashes_pinned():
    assert sha_text(fixture_text("step3-trace.txt")) == STEP3_SHA
    assert sha_text(fixture_text("step5-trace.txt")) == STEP5_SHA


def test_recorded_step3_pairs_500_exact():
    window = peer_oracle.read_trace_window(
        fixture_text("step3-trace.txt"), BDF)
    assert len(window["records"]) == 1000
    assert window["header"] == {"in_buffer": 1002,
                                "written": 1002}
    assert dict(window["other_device"]) == {}
    assert window["other_events"] == []
    assert peer_oracle.check_ordering(window["records"]) == []
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"] == {"maps": 500, "unmaps": 500,
                                 "pairs": 500, "orphans": 0,
                                 "still_open": 0,
                                 "mismatches": 0}
    bad, _ = peer_oracle.judge_window(
        "step3", window,
        ["L11-PHASE3-BEGIN", "L11-PHASE3-END"])
    assert bad == []
    rows = peer_oracle.export_rows(window["records"])
    assert len(rows) == 1000
    violations, derived = peer_oracle.reverify_rows(rows)
    assert violations == []
    assert derived == pairing["counts"]
    assert "dma_addr" not in json.dumps(rows)
    assert "phys_addr" not in json.dumps(rows)


def test_recorded_step5_bracket_matches_probe():
    window = peer_oracle.read_trace_window(
        fixture_text("step5-trace.txt"), BDF)
    assert len(window["records"]) == 146
    assert window["header"] == {"in_buffer": 151,
                                "written": 151}
    assert peer_oracle.check_ordering(window["records"]) == []
    bad, phases = peer_oracle.split_bracket(
        window["records"], window["markers"], PROBE_BRACKET)
    assert bad == []
    kinds = {name: (sum(1 for row in rows
                        if row["event"] == "dma_map_phys"),
                    sum(1 for row in rows
                        if row["event"] == "dma_unmap_phys"))
             for name, rows in phases.items()}
    assert kinds == {"pre": (20, 20), "teardown": (0, 32),
                     "post": (53, 21)}
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"]["pairs"] == 41
    assert pairing["counts"]["orphans"] == 32
    assert pairing["counts"]["still_open"] == 32
    assert pairing["counts"]["mismatches"] == 0
    bad, classified = peer_oracle.classify_bracket(
        pairing, phases, True, True)
    assert bad == []
    assert classified == {"pre_existing": 32, "held_open": 32}


def test_parse_map_unmap_marker_shapes():
    kind, record = peer_oracle.parse_trace_line(
        "ping-188 [000] D..3. 1.643363: dma_map_phys: "
        "0000:00:0c.0 dir=TO_DEVICE dma_addr=bbcdb000 size=98 "
        "phys_addr=1034258c2 attrs=", 12)
    assert kind == "map"
    assert record["device"] == BDF
    assert record["dir"] == "TO_DEVICE"
    assert record["dma_addr"] == "bbcdb000"
    assert record["size"] == 98
    assert record["phys_addr"] == "1034258c2"
    assert record["ts_us"] == 1643363
    assert record["cpu"] == "000"
    kind, record = peer_oracle.parse_trace_line(
        "ping-188 [000] d.s2. 1.643471: dma_unmap_phys: "
        "0000:00:0c.0 dir=TO_DEVICE dma_addr=bbcdb000 size=98 "
        "attrs=", 13)
    assert kind == "unmap"
    assert "phys_addr" not in record
    assert record["ts_us"] == 1643471
    kind, record = peer_oracle.parse_trace_line(
        "python3-178 [001] ...1. 1.639620: tracing_mark_write: "
        "L11-PHASE3-BEGIN", 11)
    assert kind == "marker"
    assert record["marker"] == "L11-PHASE3-BEGIN"
    kind, _ = peer_oracle.parse_trace_line(
        "# entries-in-buffer/entries-written: 1/1   #P:2", 3)
    assert kind == "comment"
    kind, record = peer_oracle.parse_trace_line(
        "ping-1 [000] ...1. 2.000000: dma_map_sg: 0000:00:0c.0 "
        "dir=TO_DEVICE ents=2", 20)
    assert kind == "other"
    assert record["event"] == "dma_map_sg"


def test_parse_rejects_malformed_dma_lines():
    bad_lines = [
        # No BDF device token.
        "ping-1 [000] D..3. 1.000000: dma_map_phys: "
        "dir=TO_DEVICE dma_addr=aa size=8 phys_addr=bb attrs=",
        # Unknown direction.
        "ping-1 [000] D..3. 1.000000: dma_map_phys: "
        "0000:00:0c.0 dir=SIDEWAYS dma_addr=aa size=8 "
        "phys_addr=bb attrs=",
        # Non-numeric size.
        "ping-1 [000] D..3. 1.000000: dma_map_phys: "
        "0000:00:0c.0 dir=TO_DEVICE dma_addr=aa size=many "
        "phys_addr=bb attrs=",
        # Map without phys_addr.
        "ping-1 [000] D..3. 1.000000: dma_map_phys: "
        "0000:00:0c.0 dir=TO_DEVICE dma_addr=aa size=8 attrs=",
        # Not a trace line at all.
        "this is not a trace line",
    ]
    for line in bad_lines:
        with pytest.raises(OracleError):
            peer_oracle.parse_trace_line(line, 99)


def test_reordered_events_fail_closed():
    first = ev_line("ping-1", "000", 2, 100, "dma_map_phys",
                    map_body(addr="aa00"))
    second = ev_line("ping-1", "000", 1, 900, "dma_unmap_phys",
                     unmap_body(addr="aa00"))
    text = dump([mark_line("t-1", "000", 0, 900, "BEGIN"),
                 first, second,
                 mark_line("t-1", "000", 3, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    assert peer_oracle.check_ordering(window["records"]) != []
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("order violation" in finding for finding in bad)


def test_timestamp_tie_pairs_with_zero_lifetime():
    body = ev_line("ping-1", "000", 5, 0, "dma_map_phys",
                   map_body(addr="aa00"))
    free = ev_line("ping-1", "000", 5, 0, "dma_unmap_phys",
                   unmap_body(addr="aa00"))
    text = dump([mark_line("t-1", "000", 4, 0, "BEGIN"), body,
                 free, mark_line("t-1", "000", 6, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    assert peer_oracle.check_ordering(window["records"]) == []
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"]["pairs"] == 1
    assert pairing["pairs"][0]["lifetime_us"] == 0


def test_device_filter_is_exact_not_substring():
    # The owned BDF embedded where a substring probe would
    # match, but the positional device token names another
    # device: exact matching must attribute it elsewhere.
    other = ev_line("ping-1", "000", 1, 0, "dma_map_phys",
                    map_body(dev=OTHER_BDF, addr="aa00",
                             attrs=BDF))
    text = dump([mark_line("t-1", "000", 0, 0, "BEGIN"), other,
                 mark_line("t-1", "000", 2, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    assert window["records"] == []
    assert window["other_device"]["map"] == 1


def test_size_and_dir_mismatch_fail_closed():
    body = ev_line("ping-1", "000", 1, 0, "dma_map_phys",
                   map_body(addr="aa00", size=98,
                            direction="TO_DEVICE"))
    free = ev_line("ping-1", "000", 1, 10, "dma_unmap_phys",
                   unmap_body(addr="aa00", size=64,
                              direction="FROM_DEVICE"))
    text = dump([mark_line("t-1", "000", 0, 0, "BEGIN"), body,
                 free, mark_line("t-1", "000", 2, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"]["mismatches"] == 1
    assert pairing["counts"]["pairs"] == 0
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("mismatches" in finding for finding in bad)


def test_orphan_and_still_open_reported():
    lonely_free = ev_line("ping-1", "000", 1, 0,
                          "dma_unmap_phys",
                          unmap_body(addr="aa00"))
    lonely_map = ev_line("ping-1", "000", 1, 10, "dma_map_phys",
                         map_body(addr="bb00"))
    text = dump([mark_line("t-1", "000", 0, 0, "BEGIN"),
                 lonely_free, lonely_map,
                 mark_line("t-1", "000", 2, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"]["orphans"] == 1
    assert pairing["counts"]["still_open"] == 1
    assert pairing["counts"]["pairs"] == 0


def test_fifo_pops_earliest_open_map():
    first = ev_line("ping-1", "000", 1, 0, "dma_map_phys",
                    map_body(addr="aa00"))
    second = ev_line("ping-1", "000", 1, 5, "dma_map_phys",
                     map_body(addr="aa00"))
    free = ev_line("ping-1", "000", 1, 10, "dma_unmap_phys",
                   unmap_body(addr="aa00"))
    text = dump([mark_line("t-1", "000", 0, 0, "BEGIN"), first,
                 second, free,
                 mark_line("t-1", "000", 2, 0, "END")])
    window = peer_oracle.read_trace_window(text, BDF)
    pairing = peer_oracle.pair_fifo(window["records"])
    assert pairing["counts"]["pairs"] == 1
    assert pairing["pairs"][0]["lifetime_us"] == 10
    assert pairing["counts"]["still_open"] == 1


def test_window_hygiene_findings():
    good_map = ev_line("ping-1", "000", 1, 0, "dma_map_phys",
                       map_body(addr="aa00"))
    good_free = ev_line("ping-1", "000", 1, 10,
                        "dma_unmap_phys", unmap_body(addr="aa00"))
    begin = mark_line("t-1", "000", 0, 0, "BEGIN")
    end = mark_line("t-1", "000", 2, 0, "END")
    # Duplicate marker.
    text = dump([begin, begin, good_map, good_free, end])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("appears 2 times" in finding for finding in bad)
    # Missing marker.
    text = dump([begin, good_map, good_free])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("appears 0 times" in finding for finding in bad)
    # Truncated dump (header claims more than parsed).
    text = dump([begin, good_map, good_free, end]).replace(
        "4/4", "9/9")
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("truncated" in finding for finding in bad)
    # Buffer overwrite.
    text = dump([begin, good_map, good_free, end]).replace(
        "4/4", "3/4")
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("overwrite" in finding for finding in bad)
    # Unexpected event kind in the window.
    sibling = ev_line("ping-1", "000", 1, 5, "dma_map_sg",
                      "%s dir=TO_DEVICE ents=2" % (BDF,))
    text = dump([begin, good_map, sibling, good_free, end])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("unexpected dma_map_sg" in finding
               for finding in bad)
    # Event outside the markers.
    text = dump([good_map, begin, good_free, end])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("outside markers" in finding for finding in bad)
    # Other-device DMA breaks the quiet-guest proof.
    alien = ev_line("k-1", "001", 1, 5, "dma_map_phys",
                    map_body(dev=OTHER_BDF, addr="cc00"))
    text = dump([begin, good_map, alien, good_free, end])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("other devices" in finding for finding in bad)
    # A dump without the entries header fails closed.
    headless = "\n".join(
        line for line in dump([begin, end]).splitlines()
        if "entries-in-buffer" not in line) + "\n"
    window = peer_oracle.read_trace_window(headless, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("missing entries header" in finding
               for finding in bad)
    # A foreign marker is not silently ignored.
    alien_mark = mark_line("t-1", "000", 1, 5, "INTRUDER")
    text = dump([begin, good_map, alien_mark, good_free, end])
    window = peer_oracle.read_trace_window(text, BDF)
    bad, _ = peer_oracle.judge_window("w", window,
                                      ["BEGIN", "END"])
    assert any("foreign marker INTRUDER" in finding
               for finding in bad)


def test_bracket_attribution_edges():
    names = {"pre": "PRE", "down": "DOWN", "up": "UP",
             "post": "POST", "end": "END"}
    pre_map = ev_line("p-1", "000", 1, 0, "dma_map_phys",
                      map_body(addr="aa00"))
    down_free = ev_line("p-1", "000", 2, 0, "dma_unmap_phys",
                        unmap_body(addr="ee00", size=1544,
                                   direction="FROM_DEVICE"))
    post_map = ev_line("p-1", "000", 3, 0, "dma_map_phys",
                       map_body(addr="bb00", size=1544,
                                direction="FROM_DEVICE"))
    entries = [mark_line("t-1", "000", 0, 0, "PRE"), pre_map,
               mark_line("t-1", "000", 1, 50, "DOWN"), down_free,
               mark_line("t-1", "000", 2, 50, "UP"), post_map,
               mark_line("t-1", "000", 4, 0, "POST"),
               mark_line("t-1", "000", 5, 0, "END")]
    window = peer_oracle.read_trace_window(dump(entries), BDF)
    bad, phases = peer_oracle.split_bracket(
        window["records"], window["markers"], names)
    assert bad == []
    pairing = peer_oracle.pair_fifo(window["records"])
    # Pre-phase map still open at END: unattributed.
    bad, _ = peer_oracle.classify_bracket(pairing, phases,
                                          True, True)
    assert any("still-open" in finding for finding in bad)
    # Teardown orphan with oracle loss: not pre-existing.
    bad, _ = peer_oracle.classify_bracket(pairing, phases,
                                          False, True)
    assert any("orphan" in finding for finding in bad)
    # Held ring with the interface down: unattributed.
    held = [row for row in pairing["still_open"]]
    assert held
    bad, _ = peer_oracle.classify_bracket(
        {"orphans": [], "still_open": [post_map_record()]},
        {"teardown": [], "post": [post_map_record()]},
        True, False)
    assert any("still-open" in finding for finding in bad)
    # Orphans in pre/post phases never count as pre-existing.
    pre_free = {"line": 9, "event": "dma_unmap_phys"}
    post_free = {"line": 40, "event": "dma_unmap_phys"}
    bad, _ = peer_oracle.classify_bracket(
        {"orphans": [pre_free, post_free], "still_open": []},
        {"teardown": [{"line": 20}],
         "post": [{"line": 40}], "pre": [{"line": 9}]},
        True, True)
    assert len(bad) == 2 and all("orphan" in finding
                                 for finding in bad)


def post_map_record():
    return {"line": 30, "event": "dma_map_phys"}


def test_drops_judge():
    window = {"drops_before": {"cpu0": 0, "cpu1": 0},
              "drops_after": {"cpu0": 0, "cpu1": 1}}
    bad = peer_oracle.judge_drops("w", window)
    assert len(bad) == 1 and "oracle loss" in bad[0]
    window = {"drops_before": {"cpu0": 0},
              "drops_after": {"cpu0": 0, "cpu1": 0}}
    bad = peer_oracle.judge_drops("w", window)
    assert any("CPU set moved" in finding for finding in bad)
    window = {"drops_before": {"cpu0": 3, "cpu1": 0},
              "drops_after": {"cpu0": 3, "cpu1": 0}}
    assert peer_oracle.judge_drops("w", window) == []


def test_reverify_catches_guest_host_drift():
    traffic = traffic_fixture_doc(((98, "TO_DEVICE"),))
    tampered = copy.deepcopy(traffic)
    tampered["pairs"] = 2
    bad, _ = peer_oracle.judge_traffic_reverify(tampered)
    assert any("reverify pairs" in finding for finding in bad)
    orphaned = copy.deepcopy(traffic)
    orphaned["events"] = [row for row in orphaned["events"]
                          if row["kind"] == "unmap"]
    orphaned.update({"maps": 0, "unmaps": 1, "pairs": 0,
                     "orphans": 1, "still_open": 0,
                     "entries_in_buffer": 3,
                     "entries_written": 3})
    bad, _ = peer_oracle.judge_traffic_reverify(orphaned)
    assert any("orphans: 1" in finding for finding in bad)


def loss_detail(total, buckets=None, head=None):
    if buckets is None:
        buckets = {name: 0
                   for name in peer_oracle.LOSS_BUCKETS}
    inner = " ".join("%s=(%d)" % (name, buckets[name])
                     for name in peer_oracle.LOSS_BUCKETS)
    return {"status": "partial" if total else "complete_for_scope",
            "loss_count": str(total),
            "scope": "synthetic",
            "reason": "detail loss %d (%s)" % (
                total if head is None else head, inner)}


def test_declared_loss_audits_buckets():
    parsed = peer_oracle.parse_declared_loss(loss_detail(0))
    assert parsed["total"] == 0
    buckets = {name: 0 for name in peer_oracle.LOSS_BUCKETS}
    buckets["recursion_missed"] = 462
    parsed = peer_oracle.parse_declared_loss(
        loss_detail(462, buckets))
    assert parsed["total"] == 462
    assert parsed["buckets"]["recursion_missed"] == 462
    # Head disagrees with loss_count.
    with pytest.raises(OracleError):
        peer_oracle.parse_declared_loss(loss_detail(462, head=1))
    # Buckets do not sum to the head.
    short = {name: 0 for name in peer_oracle.LOSS_BUCKETS}
    with pytest.raises(OracleError):
        peer_oracle.parse_declared_loss(loss_detail(5, short))
    # A bucket missing from the enumeration.
    Dropped = {name: 0 for name in peer_oracle.LOSS_BUCKETS
               if name != "dropped"}
    inner = " ".join("%s=(%d)" % (name, Dropped[name])
                     for name in sorted(Dropped))
    with pytest.raises(OracleError):
        peer_oracle.parse_declared_loss(
            {"status": "partial", "loss_count": "0",
             "scope": "synthetic",
             "reason": "Detail loss 0 (%s)" % (inner,)})
    # Free-form reason.
    with pytest.raises(OracleError):
        peer_oracle.parse_declared_loss(
            {"status": "partial", "loss_count": "3",
             "scope": "synthetic", "reason": "some loss happened"})


def test_declared_loss_ignores_channel_suffix():
    buckets = {name: 0 for name in peer_oracle.LOSS_BUCKETS}
    buckets["recursion_missed"] = 462
    doc = loss_detail(462, buckets)
    doc["reason"] += "; channels attempt:(submit_fail=0 " \
        "malformed=0 dropped=0) lifecycle:(submit_fail=0 " \
        "malformed=0 dropped=0) copy:(submit_fail=0 " \
        "malformed=0 dropped=0)"
    parsed = peer_oracle.parse_declared_loss(doc)
    assert parsed["total"] == 462
    # A hostile suffix cannot inflate the audit: only the
    # pooled group counts, so this parses to zero.
    hostile = loss_detail(0)
    hostile["reason"] += "; dropped=(5)"
    parsed = peer_oracle.parse_declared_loss(hostile)
    assert parsed["total"] == 0
    garbage = loss_detail(0)
    garbage["reason"] += " plus extra words"
    with pytest.raises(OracleError):
        peer_oracle.parse_declared_loss(garbage)


def test_agreement_charges_gaps_to_declared_only():
    proven = Counter({98: 500, 1544: 20})
    exact = c9_fold({98: 500, 1544: 20}, 520,
                    [("original_to_bounce", 500, 49000)])
    bad, report = peer_oracle.agree_oracle_c9(
        proven, exact, zero_loss())
    assert bad == []
    assert report["gap"] == 0
    # Extra product records (other phases/devices) never fail.
    extra = c9_fold({98: 900, 1544: 44}, 1000,
                    [("original_to_bounce", 900, 90000)])
    bad, _ = peer_oracle.agree_oracle_c9(proven, extra,
                                         zero_loss())
    assert bad == []
    # A gap within declared loss passes, charged.
    short = c9_fold({98: 499, 1544: 20}, 520,
                    [("original_to_bounce", 499, 48902)])
    declared = {"total": 1,
                "buckets": dict(zero_loss()["buckets"])}
    bad, report = peer_oracle.agree_oracle_c9(proven, short,
                                              declared)
    assert bad == []
    assert report["gap"] == 1
    # The same gap beyond declared loss fails.
    bad, _ = peer_oracle.agree_oracle_c9(proven, short,
                                         zero_loss())
    assert any("exceeds declared loss" in finding
               for finding in bad)
    # No bounce bytes at all fails even with exact maps.
    quiet = c9_fold({98: 500, 1544: 20}, 520, [])
    bad, _ = peer_oracle.agree_oracle_c9(proven, quiet,
                                         zero_loss())
    assert any("bounce coverage" in finding for finding in bad)
    # FROM_DEVICE pairs need bounce_to_original cover.
    bad = peer_oracle.agree_bounce_dirs(
        {"TO_DEVICE", "FROM_DEVICE"}, exact)
    assert any("FROM_DEVICE" in finding for finding in bad)
    # Zero-byte copies do not cover bounce either.
    zero = c9_fold({98: 500, 1544: 20}, 520,
                   [("original_to_bounce", 500, 0)])
    bad, _ = peer_oracle.agree_oracle_c9(proven, zero,
                                         zero_loss())
    assert any("bounce coverage" in finding for finding in bad)
    both = c9_fold({98: 500, 1544: 20}, 520,
                   [("original_to_bounce", 500, 49000),
                    ("bounce_to_original", 20, 30880)])
    assert peer_oracle.agree_bounce_dirs(
        {"TO_DEVICE", "FROM_DEVICE"}, both) == []


def test_validate_peer_doc_accepts_fixture_shape():
    doc = peer_doc(traffic_fixture_doc(
        ((98, "TO_DEVICE"), (1544, "FROM_DEVICE"))),
        bracket_fixture_doc())
    assert peer_oracle.validate_peer_doc(doc) is doc
    text = json.dumps(doc, sort_keys=True)
    assert "dma_addr" not in text
    assert "phys_addr" not in text


def test_validate_peer_doc_rejects_mutations():
    good = peer_doc(traffic_fixture_doc(), bracket_fixture_doc())
    cases = []
    bad = copy.deepcopy(good)
    bad["schema"] = "memveil-peer-oracle/2"
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["guest"]["swiotlb_force"] = False
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["guest"]["pci"] = "00:0c.0"
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["guest"]["dma_mask_bits"] = 64
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["guest"]["extra"] = 1
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["oracle"]["events"] = ["dma_map_phys"]
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["c9"]["record_exit"] = 1
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["c9"]["mono_open_ns"] = bad["c9"]["mono_close_ns"] + 1
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["workload"]["nic_rx_after"] = 1
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["traffic"]["events"] = list(
        reversed(bad["traffic"]["events"]))
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["traffic"]["events"][0]["key"] = "opaque?"
    cases.append(bad)
    bad = copy.deepcopy(good)
    del bad["bracket"]["marker_lines"]
    cases.append(bad)
    bad = copy.deepcopy(good)
    bad["traffic"]["drops_after"] = {}
    cases.append(bad)
    for index, case in enumerate(cases):
        with pytest.raises(ValueError):
            peer_oracle.validate_peer_doc(case)
    with pytest.raises(ValueError):
        peer_oracle.strict_json('{"a": 1, "a": 2}')
    with pytest.raises(ValueError):
        peer_oracle.validate_peer_exports({"peer.json": None})


CAPABILITIES_8 = ("bounce_attempts", "mapping_lifecycle",
                  "copy_bytes", "sync_requests",
                  "conversion_results", "region_state",
                  "pool_stats", "task_context")
INTEGRITY_KINDS = ("bounce_attempt", "map_result", "unmap",
                   "copy", "sync_request", "transition_result",
                   "pool_sample", "gap", "marker",
                   "counter_snapshot")


def c9_event(seq, ts, kind, data, session="synth-peer-1",
             hook="tracing", backend="tracing",
             measurement="observed", correlation="direct"):
    return {"schema_version": "0.1.1", "session_id": session,
            "seq": str(seq), "ts_ns": str(ts), "kind": kind,
            "source": {"hook": hook, "backend": backend,
                       "profile_id": PROFILE,
                       "measurement": measurement,
                       "correlation": correlation},
            "data": data}


def c9_fixture_events(session="synth-peer-1", base=11000000000):
    return [
        c9_event(0, base, "bounce_attempt",
                 {"device_id": "d000001",
                  "requested_bytes": "98", "forced": True,
                  "operation_id": "op0"},
                 session, "swiotlb:swiotlb_bounced",
                 "tracepoint"),
        c9_event(1, base + 1, "map_result",
                 {"operation_id": "lc-0", "success": True,
                  "mapping_id": "gen-1", "return_code": None,
                  "mapped_bytes": "98", "wire_generation": "1",
                  "wire_identity": "known"},
                 session, "fexit:swiotlb_tbl_map_single"),
        c9_event(2, base + 2, "copy",
                 {"operation_id": "lc-0", "mapping_id": None,
                  "direction": "original_to_bounce",
                  "bytes": "98"},
                 session, "fentry:swiotlb_bounce",
                 "tracing", "observed", "unpaired"),
        c9_event(3, base + 3, "unmap",
                 {"mapping_id": "gen-1", "wire_generation": "1",
                  "wire_identity": "known"},
                 session,
                 "fentry:__swiotlb_tbl_unmap_single"),
        c9_event(4, base + 4, "map_result",
                 {"operation_id": "lc-1", "success": True,
                  "mapping_id": "gen-2", "return_code": None,
                  "mapped_bytes": "1544",
                  "wire_generation": "2",
                  "wire_identity": "known"},
                 session, "fexit:swiotlb_tbl_map_single"),
        c9_event(5, base + 5, "copy",
                 {"operation_id": "lc-1", "mapping_id": None,
                  "direction": "bounce_to_original",
                  "bytes": "1544"},
                 session, "fentry:swiotlb_bounce",
                 "tracing", "observed", "unpaired"),
        c9_event(6, base + 6, "unmap",
                 {"mapping_id": "gen-2", "wire_generation": "2",
                  "wire_identity": "known"},
                 session,
                 "fentry:__swiotlb_tbl_unmap_single"),
    ]


def c9_fixture_session(events_text, start=10000000000,
                       end=60000000000,
                       session="synth-peer-1", detail=None):
    raw = events_text.encode("utf-8")
    kinds = Counter(json.loads(line)["kind"]
                    for line in events_text.splitlines())
    if detail is None:
        detail = {"status": "complete_for_scope",
                  "loss_count": "0",
                  "scope": "synthetic peer fixture",
                  "reason": "detail loss 0 (%s)" % (
                      " ".join("%s=(0)" % (name,)
                               for name in
                               peer_oracle.LOSS_BUCKETS),)}
    channel = {"status": "complete_for_scope",
               "loss_count": "0", "scope": "synthetic",
               "reason": "synthetic"}
    return {
        "schema_version": "0.1.4", "session_id": session,
        "synthetic": True,
        "product": {"name": "memveil", "version": "0.1.1"},
        "environment": {"mode": "none",
                        "detection": "kernel_reported",
                        "attestation": "not_performed",
                        "evidence": []},
        "capture": {"mode": "synthetic",
                    "window": {"start_ns": str(start),
                               "end_ns": str(end)},
                    "filters": {}, "finalized": True,
                    "end_reason": "duration",
                    "integrity": {
                        "algorithm": "sha256",
                        "events_bytes": str(len(raw)),
                        "line_count": str(len(
                            events_text.splitlines())),
                        "first_seq": "0",
                        "last_seq": str(len(
                            events_text.splitlines()) - 1),
                        "events_sha256": hashlib.sha256(
                            raw).hexdigest(),
                        "kinds": {kind: str(kinds.get(kind, 0))
                                  for kind in
                                  INTEGRITY_KINDS}}},
        "device_catalog": {"devices": [
            {"device_id": "d000001", "name": "pcnet",
             "identity_status": "resolved",
             "driver": "pcnet32"}]},
        "baseline": {"complete": True,
                     "region_observations": []},
        "capabilities": {name: {"status": "verified",
                                "reason": "synthetic",
                                "hooks": []}
                         for name in CAPABILITIES_8},
        "quality": {"detail": detail, "aggregate": channel,
                    "correlation": channel,
                    "baseline": channel, "terminal": channel},
        "stop": {"outcome": "complete", "reason": "",
                 "budget_ms": "5000", "elapsed_ms": "1",
                 "admission_closed": True,
                 "quiescence_observed": True,
                 "writers_settled": "1",
                 "in_flight_at_close": "0",
                 "late_submits_drained": "0",
                 "drained_records": "0",
                 "busy_at_drain": False,
                 "counters_valid": True,
                 "open_mappings": "0"},
    }


def write_c9_fixture(tmp_path, session="synth-peer-1"):
    events = c9_fixture_events(session)
    text = "\n".join(json.dumps(event, sort_keys=True)
                     for event in events) + "\n"
    session_doc = c9_fixture_session(text, session=session)
    session_path = tmp_path / "cap-session.json"
    events_path = tmp_path / "cap-events.ndjson"
    session_path.write_text(json.dumps(session_doc,
                                       sort_keys=True) + "\n")
    events_path.write_text(text)
    return session_path, events_path


def test_c9_fixture_passes_schema_validator(tmp_path):
    validator = peer_oracle.load_schema_validator()
    session_path, events_path = write_c9_fixture(tmp_path)
    summary, fold, declared, _ = \
        peer_oracle.validate_c9_capture(
            validator, session_path, events_path)
    assert summary["id"] == "synth-peer-1"
    assert summary["synthetic"] is True
    assert fold["maps_by_size"] == Counter({98: 1, 1544: 1})
    assert fold["unmaps"] == 2
    assert fold["attempts"] == 1
    assert fold["kinds"]["bounce_attempt"] == 1
    assert fold["copy_bytes_by_dir"] == Counter(
        {"original_to_bounce": 98,
         "bounce_to_original": 1544})
    assert fold["profiles"] == {PROFILE}
    assert declared["total"] == 0


def test_c9_tamper_fails_validation(tmp_path):
    validator = peer_oracle.load_schema_validator()
    session_path, events_path = write_c9_fixture(tmp_path)
    lines = events_path.read_text().splitlines()
    tampered = json.loads(lines[1])
    tampered["data"]["mapped_bytes"] = "99"
    lines[1] = json.dumps(tampered, sort_keys=True)
    events_path.write_text("\n".join(lines) + "\n")
    with pytest.raises(Exception):
        peer_oracle.validate_c9_capture(
            validator, session_path, events_path)


def test_wiring_chain_blocks_only_on_provenance(tmp_path):
    """End-to-end offline: validator to judge, one finding."""
    validator = peer_oracle.load_schema_validator()
    session_path, events_path = write_c9_fixture(tmp_path)
    summary, fold, declared, _ = \
        peer_oracle.validate_c9_capture(
            validator, session_path, events_path)
    doc = peer_doc(traffic_fixture_doc(
        ((98, "TO_DEVICE"), (1544, "FROM_DEVICE"))),
        bracket_fixture_doc())
    doc["c9"]["ready_session"] = "synth-peer-1"
    peer_oracle.validate_peer_doc(doc)
    verdict, findings, agreement = peer_oracle.judge_peer_leg(
        doc, fold, summary, declared)
    assert verdict is False
    assert findings == ["C9 capture is not live"]
    assert agreement["gap"] == 0
    assert agreement["attempt_events"] == 1


def test_judge_pass_on_clean_leg():
    doc = peer_doc(traffic_fixture_doc(
        ((98, "TO_DEVICE"), (1544, "FROM_DEVICE"))),
        bracket_fixture_doc())
    fold = c9_fold({98: 1, 1544: 1}, 2,
                   [("original_to_bounce", 1, 98),
                    ("bounce_to_original", 1, 1544)],
                   events=10, attempts=3)
    verdict, findings, agreement = peer_oracle.judge_peer_leg(
        doc, fold, live_summary(), zero_loss())
    assert (verdict, findings) == (True, [])
    assert agreement["gap"] == 0
    assert agreement["copy_bytes"] == 1642
    assert agreement["attempt_events"] == 3


def test_judge_failure_classes():
    base_fold = c9_fold({98: 1}, 1,
                        [("original_to_bounce", 1, 98)],
                        events=4)
    cases = [
        ({"workload": {"ping_rx": 0}}, {}, {},
         "peer traffic"),
        ({"workload": {"nic_rx_after": 2}}, {}, {},
         "NIC corroboration"),
        ({"c9": {"mono_open_ns": 1}}, {}, {},
         "escapes C9 window"),
        ({"traffic": {"pairs": 0}}, {}, {},
         "traffic pairs"),
    ]
    for overlay, fold_overlay, sum_overlay, needle in cases:
        doc = peer_doc(traffic_fixture_doc(),
                       bracket_fixture_doc())
        for section, changes in overlay.items():
            doc[section].update(changes)
        fold = copy.deepcopy(base_fold)
        fold.update(fold_overlay)
        summary = live_summary()
        summary.update(sum_overlay)
        verdict, findings, _ = peer_oracle.judge_peer_leg(
            doc, fold, summary, zero_loss())
        assert verdict is False
        assert any(needle in finding for finding in findings), \
            (needle, findings)
    # C9-side failure classes.
    doc = peer_doc(traffic_fixture_doc(), bracket_fixture_doc())
    summary = live_summary()
    summary["synthetic"] = True
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, base_fold, summary, zero_loss())
    assert findings == ["C9 capture is not live"]
    summary = live_summary()
    summary["finalized"] = False
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, base_fold, summary, zero_loss())
    assert findings == ["C9 capture not finalized"]
    summary = live_summary()
    summary["end_reason"] = "signal"
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, base_fold, summary, zero_loss())
    assert any("end_reason" in finding for finding in findings)
    fold = copy.deepcopy(base_fold)
    fold["profiles"] = {"a", "b"}
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, fold, live_summary(), zero_loss())
    assert any("profiles" in finding for finding in findings)
    fold = copy.deepcopy(base_fold)
    fold["maps_by_size"] = Counter()
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, fold, live_summary(), zero_loss())
    assert any("exceeds declared loss" in finding
               for finding in findings)
    # Bracket marker disorder at top level.
    doc = peer_doc(traffic_fixture_doc(), bracket_fixture_doc())
    doc["bracket"]["marker_lines"]["end"] = 1
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, base_fold, live_summary(), zero_loss())
    assert any("out of order" in finding for finding in findings)
    # Dropped oracle events at top level.
    doc = peer_doc(traffic_fixture_doc(), bracket_fixture_doc())
    doc["traffic"]["drops_after"] = {"cpu0": 1, "cpu1": 0}
    _, findings, _ = peer_oracle.judge_peer_leg(
        doc, base_fold, live_summary(), zero_loss())
    assert any("oracle loss" in finding for finding in findings)


def test_receipt_binds_leg_inputs():
    doc = peer_doc(traffic_fixture_doc(
        ((98, "TO_DEVICE"), (1544, "FROM_DEVICE"))),
        bracket_fixture_doc())
    fold = c9_fold({98: 1, 1544: 1}, 2,
                   [("original_to_bounce", 1, 98),
                    ("bounce_to_original", 1, 1544)],
                   events=9, attempts=2)
    verdict, findings, agreement = peer_oracle.judge_peer_leg(
        doc, fold, live_summary(), zero_loss())
    harness = {"commit": "abc123", "dirty": False,
               "c9_binary_sha": "1" * 64,
               "c9_seal": {"manifest_sha": "2" * 64,
                           "bundle_sha": "3" * 64}}
    exports = {"peer.json": "4" * 64,
               "cap-session.json": "5" * 64,
               "cap-events.ndjson": "6" * 64,
               "record.out": "7" * 64,
               "record.stderr": "8" * 64}
    receipt = peer_oracle.emit_receipt(
        doc, fold, live_summary(), zero_loss(), agreement,
        verdict, findings, harness, exports)
    assert receipt["schema"] == peer_oracle.RECEIPT_SCHEMA
    assert receipt["leg"] == "L11"
    assert receipt["verdict"] == "PASS"
    assert receipt["harness"]["commit"] == "abc123"
    assert receipt["harness"]["c9_seal"]["bundle_sha"] == \
        "3" * 64
    assert receipt["c9"]["profile_id"] == [PROFILE]
    assert receipt["c9"]["declared_loss"] == 0
    assert receipt["c9"]["attempt_events"] == 2
    assert receipt["exports"]["record.stderr"] == "8" * 64
    assert receipt["guest"]["pci"] == BDF
    assert receipt["oracle"]["traffic_pairs"] == 2
    assert receipt["oracle"]["bracket_pre_existing"] == 1
    assert receipt["workload"]["ping_tx"] == 500
    assert receipt["exports"] == exports
    failed = peer_oracle.emit_receipt(
        doc, fold, live_summary(), zero_loss(), agreement,
        False, ["x"], harness, exports)
    assert failed["verdict"] == "FAIL"
    assert failed["findings"] == ["x"]


def write_export_tree(tmp_path, peer_text, cap_session="{}",
                      cap_events="",
                      record_out="ready session=cap-1-1 "
                                 "start_ns=10000000000\n",
                      record_stderr=""):
    export = tmp_path / "export"
    export.mkdir()
    for name, body in (("peer-peer.json", peer_text),
                       ("peer-cap-session.json", cap_session),
                       ("peer-cap-events.ndjson", cap_events),
                       ("peer-record.out", record_out),
                       ("peer-record.stderr", record_stderr)):
        path = export / name
        path.write_text(body)
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        (export / (name + ".sha256")).write_text(
            "%s  %s\n" % (digest, name))


def test_verify_peer_exports_roundtrip(tmp_path):
    doc = peer_doc(traffic_fixture_doc(), bracket_fixture_doc())
    text = json.dumps(doc, sort_keys=True)
    write_export_tree(tmp_path, text)
    got = peer_oracle.verify_peer_exports(
        tmp_path, "peer", peer_oracle.EXPORT_NAMES)
    assert set(got) == set(peer_oracle.EXPORT_NAMES)
    assert set(got.verified_hashes) == {
        "peer-peer.json", "peer-cap-session.json",
        "peer-cap-events.ndjson", "peer-record.out",
        "peer-record.stderr"}
    # A swapped sidecar fails the snapshot.
    sidecar = tmp_path / "export" / "peer-peer.json.sha256"
    sidecar.write_text("%s  peer-peer.json\n" % ("0" * 64,))
    with pytest.raises(AssertionError):
        peer_oracle.verify_peer_exports(
            tmp_path, "peer", peer_oracle.EXPORT_NAMES)


def test_guest_hidden_prefixes(tmp_path):
    assert guest_hidden("/tmp/bundle.tar.gz")
    assert guest_hidden("/tmp")
    assert guest_hidden("/dev/null")
    assert not guest_hidden("/tmpx/bundle.tar.gz")
    assert not guest_hidden(str(REPO / "bundle.tar.gz"))
    link = tmp_path / "linked-manifest.json"
    link.symlink_to("/tmp/real-manifest.json")
    assert guest_hidden(str(link))


def test_resolve_peer_kernel_from_lock():
    version, release, digest = peer_oracle.resolve_peer_kernel(
        LOCK)
    assert version == "v7.0.14"
    assert release == "7.0.14-070014-generic"
    assert digest == "3d3d50d77364ff616ddeae0508c68f74501afdee9" \
        "679682ce3bf59edba5b4aca"
    with pytest.raises(OracleError):
        peer_oracle.resolve_peer_kernel(LOCK, row_id="9.9")


def test_guest_argv_parsing():
    import peer_oracle_guest as guest
    args = guest.parse_argv(["/tmp/work", "/tmp/export",
                             "--release",
                             "7.0.14-070014-generic",
                             "--pci", BDF])
    assert args.pings == 500
    assert args.duration == 60
    assert args.addr == "10.0.3.15/24"
    assert args.caps == "attempt-trace,mapping-lifecycle," \
        "copy-actual"
    override = guest.parse_argv(
        ["/tmp/work", "/tmp/export", "--release",
         "7.0.14-070014-generic", "--pci", BDF, "--caps",
         "attempt-trace,mapping-lifecycle"])
    assert override.caps == "attempt-trace,mapping-lifecycle"
    with pytest.raises(SystemExit):
        guest.parse_argv(["/tmp/work", "/tmp/export",
                          "--release", "7.0.14-070014-generic",
                          "--pci", "not-a-bdf"])
    with pytest.raises(SystemExit):
        guest.parse_argv(["/tmp/work", "/tmp/export",
                          "--release", "7.0.14-070014-generic",
                          "--pci", BDF, "--pings", "0"])


def test_record_argv_carries_attempt_trace():
    import peer_oracle_guest as guest
    args = guest.parse_argv(["/tmp/work", "/tmp/export",
                             "--release",
                             "7.0.14-070014-generic",
                             "--pci", BDF])
    argv = guest.record_argv("/opt/c9/bin/memveil", args,
                            "/tmp/work/cap")
    assert argv == ["/opt/c9/bin/memveil", "record",
                   "--output", "/tmp/work/cap",
                   "--duration", "60", "--capability",
                   "attempt-trace,mapping-lifecycle,"
                   "copy-actual"]
    caps = argv[argv.index("--capability") + 1].split(",")
    assert "attempt-trace" in caps


def test_attempts_excluded_from_bounced_subset():
    proven = Counter({98: 1})
    # Attempts present alongside exact lifecycle cover:
    # PASS, count reported through.
    exact = c9_fold({98: 1}, 1,
                    [("original_to_bounce", 1, 98)],
                    attempts=50)
    bad, report = peer_oracle.agree_oracle_c9(
        proven, exact, zero_loss())
    assert bad == []
    assert report["gap"] == 0
    assert report["attempt_events"] == 50
    # Attempts never cover a lifecycle gap: one proven
    # lifetime with no lifecycle records fails even with
    # attempt records present.
    attempt_only = c9_fold({}, 0, [], attempts=5)
    bad, report = peer_oracle.agree_oracle_c9(
        proven, attempt_only, zero_loss())
    assert any("exceeds declared loss" in finding
               for finding in bad)
    assert report["gap"] == 2
    assert report["attempt_events"] == 5
    # The same gap charged to declared loss clears the
    # gap finding (bounce coverage still correctly
    # missing: an attempt-only capture observed no
    # copies).
    declared = {"total": 2,
                "buckets": dict(zero_loss()["buckets"])}
    bad, report = peer_oracle.agree_oracle_c9(
        proven, attempt_only, declared)
    assert bad == ["no exercised bounce coverage in C9 "
                   "copies"]
    assert report["gap"] == 2


def test_fold_counts_attempt_channel_explicitly(tmp_path):
    _, events_path = write_c9_fixture(tmp_path)
    lines = events_path.read_text().splitlines()
    lines.append(json.dumps(c9_event(
        7, 11000000007, "bounce_attempt",
        {"device_id": "d000001",
         "requested_bytes": "1544", "forced": True,
         "operation_id": "op1"},
        "synth-peer-1", "swiotlb:swiotlb_bounced",
        "tracepoint"), sort_keys=True))
    fold = peer_oracle.parse_c9_stream(lines)
    assert fold["attempts"] == 2
    assert fold["kinds"]["bounce_attempt"] == 2
    assert fold["maps_by_size"] == Counter({98: 1, 1544: 1})
    assert fold["unmaps"] == 2
    assert fold["events"] == 8


def test_guest_exports_record_logs(tmp_path):
    import peer_oracle_guest as guest
    work = tmp_path / "work"
    export = tmp_path / "export"
    work.mkdir()
    (work / "record.out").write_text(
        "ready session=cap-1-1 start_ns=5\n")
    refused = "memveil record: attempt-trace is required\n"
    (work / "record.stderr").write_text(refused)
    guest.export_record_logs(str(work), str(export))
    for name, body in (("peer-record.out",
                       "ready session=cap-1-1 start_ns=5\n"),
                      ("peer-record.stderr", refused)):
        path = export / name
        assert path.read_text() == body
        sidecar = export / (name + ".sha256")
        assert sidecar.read_text() == \
            "%s  %s\n" % (sha_text(body), name)
    # Missing sources skip quietly, never raise.
    guest.export_record_logs(str(tmp_path / "nowhere"),
                             str(tmp_path / "export2"))
    assert list((tmp_path / "export2").iterdir()) == []
    guest.export_record_logs(None, None)


def test_record_logs_survive_dead_guest(tmp_path):
    # Mocked dead guest: only the record logs reached the
    # rwdir before the guest died; no peer.json, no judge.
    export = tmp_path / "export"
    export.mkdir()
    refused = "memveil record: attempt-trace is required\n"
    (export / "peer-record.stderr").write_text(refused)
    digest = hashlib.sha256(refused.encode("utf-8")).hexdigest()
    (export / "peer-record.stderr.sha256").write_text(
        "%s  peer-record.stderr\n" % (digest,))
    note = peer_oracle.read_record_logs(export)
    assert note["schema"] == \
        peer_oracle.RECORD_LOG_NOTE_SCHEMA
    assert note["status"] == "present"
    entry = note["logs"]["record.stderr"]
    assert entry["present"] is True
    assert entry["sha256"] == digest
    assert entry["verified"] is True
    assert entry["error"] is None
    assert "attempt-trace is required" in entry["tail"]
    assert note["logs"]["record.out"]["present"] is False
    lines = peer_oracle.format_record_log_note(note)
    assert any(digest in line for line in lines)
    assert any("attempt-trace is required" in line
               for line in lines)
    assert any("record.out: absent" in line for line in lines)


def test_record_logs_absent_marker(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    note = peer_oracle.read_record_logs(export)
    assert note["status"] == "absent"
    for name in peer_oracle.RECORD_LOGS:
        assert note["logs"][name]["present"] is False
    lines = peer_oracle.format_record_log_note(note)
    assert lines[0] == "peer: record logs: absent"
    assert any("record.stderr: absent" in line
               for line in lines)
    note = peer_oracle.read_record_logs(None)
    assert note["status"] == "no-run-dir"
    lines = peer_oracle.format_record_log_note(note)
    assert lines[0] == "peer: record logs: no-run-dir"


def test_record_logs_sidecar_problems_reported(tmp_path):
    export = tmp_path / "export"
    export.mkdir()
    (export / "peer-record.stderr").write_text("boom\n")
    (export / "peer-record.stderr.sha256").write_text(
        "%s  peer-record.stderr\n" % ("0" * 64,))
    (export / "peer-record.out").write_text("ready\n")
    note = peer_oracle.read_record_logs(export)
    assert note["status"] == "present"
    assert note["logs"]["record.stderr"]["verified"] is False
    assert note["logs"]["record.stderr"]["error"] == \
        "hash mismatch"
    assert note["logs"]["record.out"]["error"] == \
        "missing sidecar"
    lines = peer_oracle.format_record_log_note(note)
    assert any("hash mismatch" in line for line in lines)
    assert any("missing sidecar" in line for line in lines)


def test_record_log_note_stash(tmp_path):
    note = peer_oracle.read_record_logs(None)
    path = stash_record_log_note(tmp_path, note)
    assert path == tmp_path / "record-logs.json"
    saved = json.loads(path.read_text())
    assert saved["status"] == "no-run-dir"
    assert saved["schema"] == \
        peer_oracle.RECORD_LOG_NOTE_SCHEMA
    # Never raises, even without a run dir.
    assert stash_record_log_note(None, note) is None


GUEST_HIDDEN_PREFIXES = ("/tmp/", "/dev/", "/proc/", "/sys/")


def guest_hidden(path):
    """True when a host path is namespaced away in-guest."""
    resolved = os.path.realpath(path)
    return resolved == "/tmp" or resolved.startswith(
        GUEST_HIDDEN_PREFIXES)


def resolve_sealed_c9():
    """Sealed C9 binary, seal digests, and guest env triple.

    Fails closed without qualification inputs, and when the
    tarball or manifest lives under a guest-namespaced
    prefix (/tmp is a private overlay in-guest): the guest
    re-verifies the same files, so they must be visible
    there.
    """
    sys.path.insert(0, str(REPO / "tests"))
    from support.candidate_input import load
    try:
        selected = load(required=True)
    except ValueError as exc:
        pytest.fail("peer leg needs sealed C9 inputs: %s"
                    % (exc,))
    manifest = str(selected.manifest_path)
    bundle = str(selected.bundle)
    for path in (manifest, bundle):
        if guest_hidden(path):
            pytest.fail("sealed input not guest-visible: %s"
                        % (path,))
    binary = str(selected.path("bin/memveil"))
    seal = {"manifest_sha": peer_oracle.sha_file(manifest),
            "bundle_sha": peer_oracle.sha_file(bundle),
            "manifest_digest": selected.digest}
    env = {"manifest": manifest, "bundle": bundle,
           "digest": selected.digest}
    return binary, seal, env


def harness_identity():
    """Repo HEAD plus dirty flag for the receipt."""
    head = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True, text=True)
    if head.returncode != 0:
        pytest.fail("harness commit unreadable")
    dirty = subprocess.run(
        ["git", "-C", str(REPO), "status", "--porcelain"],
        capture_output=True, text=True)
    return {"commit": head.stdout.strip(),
            "dirty": bool(dirty.stdout.strip())}


def stash_record_log_note(tmp, note):
    """Write the record-log note into the run dir.

    Best-effort forensics copy for failure paths: the
    note (present digests or the explicit absent marker)
    stays with the run dir next to harness.json. Never
    raises; returns the path or None.
    """
    if tmp is None:
        return None
    try:
        path = Path(tmp) / "record-logs.json"
        path.write_text(json.dumps(note, indent=1,
                                   sort_keys=True) + "\n")
        return path
    except (OSError, ValueError, TypeError):
        return None


def run_peer_guest(kver, release, pci, cand_env):
    """Boot the pinned guest and run the peer guest flow."""
    import fcntl
    import shlex
    from test_attempt_capture import gate_prefix
    from vm_process import run_owned_guest
    prefix, _ = gate_prefix()
    lock_dir = REPO / "build" / "vm"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise ValueError("VM suite lease already owned")
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-peer-"))
    export = tmp / "export"
    export.mkdir()
    (tmp / "kernel.txt").write_text(
        "%s %s\n" % (kver, release))
    guest = shlex.join(
        ["env",
         "MV_CANDIDATE_MANIFEST=" + cand_env["manifest"],
         "MV_BUNDLE_TARBALL=" + cand_env["bundle"],
         "MV_CANDIDATE_DIGEST=" + cand_env["digest"],
         "python3", str(GUEST_FLOW), "/tmp/vmgate-work",
         "/tmp/export", "--release", release, "--pci", pci])
    cmd = prefix + [
        "--run", kver, "-m", "6G",
        "--append", "swiotlb=force",
        "--disable-microvm",
        "--network", "user",
        "--qemu-opts=-cpu host",
        "--qemu-opts=-device pcnet,netdev=pcnet0"
        " -netdev user,id=pcnet0,net=10.0.3.0/24",
        "--rwdir=/tmp/export=%s" % (export,),
        "--exec", guest,
    ]
    (tmp / "harness.json").write_text(json.dumps(
        {"vng": prefix[-1], "kver": kver, "pci": pci},
        sort_keys=True) + "\n")
    try:
        proc = run_owned_guest(cmd,
                               timeout=peer_oracle.CASE_TIMEOUT)
    finally:
        lease.close()
    return tmp, proc


def test_peer_leg():
    """Armed L11 live leg (exclusive VM lease slot).

    Boots the pinned guest with the owned pcnet NIC on the
    lease peer path (no host bridge changes), runs the
    tracefs oracle around peer traffic plus the down/up
    bracket under a sealed C9 capture, and judges the full
    leg. Executor duties (lease idle check, warm vng cache
    with no downloads) follow the standard live procedure.
    """
    if os.environ.get(peer_oracle.PEER_ENV) != "1":
        pytest.skip("peer leg needs MEMVEIL_VM_PEER=1")
    peer_oracle.require_peer_env()
    from evidence_retention import expected_from_verified, \
        retain_failure
    from test_attempt_capture import cleanup
    try:
        kver, release, vmlinuz = peer_oracle.resolve_peer_kernel(
            LOCK)
    except OracleError as exc:
        pytest.fail("peer kernel pin: %s" % (exc,))
    print("peer: guest %s release %s vmlinuz %s"
          % (kver, release, vmlinuz[:16]))
    pci = os.environ.get("MEMVEIL_PEER_PCI", BDF)
    if not peer_oracle.BDF_RE.fullmatch(pci):
        pytest.fail("bad MEMVEIL_PEER_PCI %r" % (pci,))
    binary, seal, cand_env = resolve_sealed_c9()
    tmp = None
    try:
        tmp, proc = run_peer_guest(kver, release, pci, cand_env)
        assert proc.returncode == 0, \
            "guest failed: %s" % (proc.stderr[-2000:],)
        got = peer_oracle.verify_peer_exports(
            tmp, "peer", peer_oracle.EXPORT_NAMES)
        print("peer: record logs verified out=%s stderr=%s"
              % (got.verified_hashes["peer-record.out"],
                 got.verified_hashes["peer-record.stderr"]))
        expected = expected_from_verified(got, "peer")
        peer = peer_oracle.validate_peer_exports(got)
        validator = peer_oracle.load_schema_validator()
        summary, fold, declared, _ = \
            peer_oracle.validate_c9_capture(
                validator, got["cap-session.json"],
                got["cap-events.ndjson"])
        verdict, findings, agreement = \
            peer_oracle.judge_peer_leg(peer, fold, summary,
                                       declared)
        harness = harness_identity()
        harness["c9_binary_sha"] = peer_oracle.sha_file(binary)
        harness["c9_seal"] = seal
        receipt = peer_oracle.emit_receipt(
            peer, fold, summary, declared, agreement, verdict,
            findings, harness,
            {name: got.verified_hashes["peer-" + name]
             for name in peer_oracle.EXPORT_NAMES})
        (tmp / "receipt.json").write_text(
            json.dumps(receipt, indent=1, sort_keys=True)
            + "\n")
        assert verdict, "\n".join(findings)
        print("peer: %d traffic pairs + bracket %d/%d agree "
              "with %s (gap %d/%d)"
              % (peer["traffic"]["pairs"],
                 peer["bracket"]["pre_existing"],
                 peer["bracket"]["held_open"],
                 summary["id"], agreement["gap"],
                 declared["total"]))
    except Exception:
        try:
            export = Path(tmp) / "export" \
                if tmp is not None else None
            note = peer_oracle.read_record_logs(export)
            for line in peer_oracle.format_record_log_note(
                    note):
                print(line)
            stash_record_log_note(tmp, note)
        except Exception as exc:
            print("peer: record-log surface failed: %s"
                  % (exc,))
        retain_failure(tmp, "peer")
        print("gate artifacts kept at %s" % (tmp,))
        raise
    else:
        cleanup(tmp, "peer", expected=expected)
