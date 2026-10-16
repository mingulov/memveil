# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the live-overhead validation and comparison."""

import copy
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))), "vm"))

import overhead
from overhead_guest import (DD_BYTES, DD_COUNT, FLOOD_COUNT, LAB_WINDOW,
                            RECORD_DURATION, ROUNDS, SAMPLE_COUNT, SEED,
                            WARMUP_DD_COUNT, WARMUP_PING_COUNT,
                            build_schedule)
from export_validation import (validate_overhead_legs,
                               validate_overhead_probe)

PROFILE = "linux-x86_64-7.0.0-34-generic"
CAPS = {
    "summary": ["attempt-trace"],
    "attached-idle": ["attempt-trace", "mapping-lifecycle",
                      "copy-actual"],
    "detail": ["attempt-trace", "mapping-lifecycle", "copy-actual"],
}


def rtts():
    return [round(0.5 + i * 0.0002, 3)
            for i in range(SAMPLE_COUNT)]


WARMUP_START_NS = 2000
MEASURED_START_NS = WARMUP_START_NS + 11000000000
END_NS = MEASURED_START_NS + 64000000000


def workload(ping_s=2.0, dd_s=1.0):
    sample = rtts()
    pct = overhead.recompute_percentiles(sample)
    return {
        "window": {"warmup_start_ns": WARMUP_START_NS,
                   "measured_start_ns": MEASURED_START_NS,
                   "end_ns": END_NS},
        "warmup": {"seconds": 11.0, "ok": True, "detail": "ok"},
        "ping": {"tx": FLOOD_COUNT, "rx": FLOOD_COUNT,
                 "seconds": ping_s,
                 "rtts": sample, "sample_tx": SAMPLE_COUNT,
                 "sample_rx": SAMPLE_COUNT,
                 "sample_count": SAMPLE_COUNT,
                 "p50_ms": pct[50], "p95_ms": pct[95],
                 "p99_ms": pct[99]},
        "dd": {"bytes": DD_BYTES, "seconds": dd_s},
    }


def collector(mode):
    if mode == "off":
        return {"kind": "none"}
    attach_ns = WARMUP_START_NS - 1000
    detach_ns = END_NS + 2000000000
    if mode == "undersized-buffer":
        side = {"exit": 0, "utime_s": 1.0, "stime_s": 0.5,
                "maxrss_kb": 10000}
        return {"kind": "lab", "rings": ["mv_lifecycle",
                                         "mv_copies"],
                "lc": dict(side), "cp": dict(side),
                "attach_ns": attach_ns, "detach_ns": detach_ns,
                "capture_bytes": 100}
    return {"kind": "product", "capabilities": CAPS[mode],
            "exit": 4, "ready": "ready session=sess-%s" % mode,
            "stopped": mode == "attached-idle", "killed": False,
            "utime_s": 1.5, "stime_s": 0.5,
            "maxrss_kb": 123456, "attach_ns": attach_ns,
            "detach_ns": detach_ns, "term_ns": END_NS + 1000000000,
            "stderr_tail": "", "capture_bytes": 100}


def leg(mode, seq=0, rnd=0, pair="r0-summary", tag="l00"):
    files = []
    if mode in CAPS:
        files = [tag + "-session.json", tag + "-events.ndjson"]
    elif mode == "undersized-buffer":
        files = [tag + "-lc.txt", tag + "-cp.txt"]
    return {"seq": seq, "round": rnd, "mode": mode, "pair": pair,
            "tag": tag, "files": files, "error": "",
            "workload": workload(),
            "collector": collector(mode),
            "bpf": {"before": {"progs": 0, "maps": 0},
                    "after": {"progs": 0, "maps": 0},
                    "settled_waited_s": 0.1, "settled": True},
            "bpf_mem": {"owned_memlock_bytes": 1000,
                        "reason": "owned 1 progs 1 maps"},
            "io_tlb": {"before": [1, 1, 1], "after": [1, 1, 1]}}


def ledger(legs=None):
    if legs is None:
        legs = []
        for seq, (rnd, mode, pair) in enumerate(
                build_schedule(SEED)):
            legs.append(leg(mode, seq, rnd, pair,
                            "l%02d" % seq))
    return {
        "schema": "memveil-overhead-legs/1",
        "seed": SEED,
        "rounds": 5,
        "schedule": [[rnd, mode, pair]
                     for rnd, mode, pair in build_schedule(SEED)],
        "artifacts": {
            "memveil_sha": "0" * 64, "attempt_sha": "1" * 64,
            "lc_sha": "2" * 64, "cp_sha": "3" * 64,
            "lc_test_sha": "4" * 64, "cp_test_sha": "5" * 64,
            "bridge_sha": "6" * 64, "profile_sha": "7" * 64,
            "profile_id": PROFILE,
        },
        "workload": {"gateway": "10.0.3.2",
                     "flood_count": FLOOD_COUNT,
                     "sample_count": SAMPLE_COUNT,
                     "warmup_ping_count": WARMUP_PING_COUNT,
                     "dd_count": DD_COUNT,
                     "dd_bytes": DD_BYTES,
                     "warmup_dd_count": WARMUP_DD_COUNT,
                     "record_duration_s": RECORD_DURATION,
                     "lab_window_s": LAB_WINDOW, "seed": SEED,
                     "rounds": ROUNDS},
        "fixture": {"iface": "enp0s1", "disk": "/dev/sdb",
                    "nslabs": 1024,
                    "bpf_boot": {"progs": 0, "maps": 0},
                    "io_tlb_boot": [1, 1, 1]},
        "legs": legs,
        "epilogue": {"bpf_end": {"progs": 0, "maps": 0},
                     "settled_waited_s": 0.2, "settled": True},
    }


def session_doc(mode, session_id):
    caps = {}
    channels = ("bounce_attempts",) if mode == "summary" else (
        "bounce_attempts", "mapping_lifecycle", "copy_bytes")
    for channel in channels:
        caps[channel] = {"profile_id": PROFILE}
    return {"session_id": session_id, "capabilities": caps,
            "quality": {"detail": {
                "loss_count": "0",
                "reason": "submit_fail=(0) malformed=(0) "
                          "dropped=(0) size_omitted=(0) "
                          "duration_omitted=(0) "
                          "signal_omitted=(0) rejected=(0) "
                          "write_failed=(0)"}},
            "capture": {"finalized": True}}


def event_line(kind, data):
    return json.dumps({"kind": kind, "data": data})


LC_FILE = (
    "lc kind=1 ok=1 skip=0 dir=1 seq=0 ktime=100 size=512 gen=7\n"
    "lc kind=1 ok=1 skip=0 dir=1 seq=1 ktime=101 size=512 gen=8\n"
    "summary observed=2 badframe=0 badrec=0 cnt_obs=2 "
    "cnt_obsb=1024 cnt_emit=2 cnt_emitb=1024 cnt_fail=0 "
    "cnt_flags=0 rx=2 dlv=2 mal=0 drop=0\n"
)
CP_FILE = (
    "cp kind=2 todev=1 known=1 clamp=0 ezero=0 dir=1 reason=0 "
    "seq=0 ktime=100 req=512 eff=512\n"
    "summary observed=1 badframe=0 badrec=0 cnt_obs=1 "
    "cnt_obsb=512 cnt_emit=1 cnt_emitb=512 cnt_fail=0 "
    "cnt_flags=0 rx=1 dlv=1 mal=0 drop=0\n"
)


def write_product_files(tmp_path, tag, mode):
    (tmp_path / (tag + "-session.json")).write_text(
        json.dumps(session_doc(mode, "sess-" + mode)))
    (tmp_path / (tag + "-events.ndjson")).write_text(
        event_line("map_result",
                   {"success": True, "mapping_id": "gen-1"})
        + "\n"
        + event_line("unmap", {"mapping_id": "gen-1"}) + "\n")
    return {tag + "-session.json": tmp_path / (
        tag + "-session.json"),
        tag + "-events.ndjson": tmp_path / (
            tag + "-events.ndjson")}


def write_lab_files(tmp_path, tag):
    (tmp_path / (tag + "-lc.txt")).write_text(LC_FILE)
    (tmp_path / (tag + "-cp.txt")).write_text(CP_FILE)
    return {tag + "-lc.txt": tmp_path / (tag + "-lc.txt"),
            tag + "-cp.txt": tmp_path / (tag + "-cp.txt")}


def test_schedule_shape():
    first = build_schedule()
    assert first == build_schedule(SEED)
    assert len(first) == 40
    pairs = {}
    for rnd, mode, pair in first:
        pairs.setdefault(pair, []).append(mode)
    assert len(pairs) == 20
    for pair, modes in pairs.items():
        assert set(modes) == {"off", pair.split("-", 1)[1]}


def test_schedule_within_pair_adjacent():
    sched = build_schedule()
    for index in range(0, 40, 2):
        assert sched[index][2] == sched[index + 1][2]
        assert sched[index][0] == sched[index + 1][0]


def test_legs_validate_clean():
    validate_overhead_legs(ledger())


def test_legs_refuse_seed_drift():
    doc = ledger()
    doc["seed"] = 1
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_dropped_leg():
    doc = ledger()
    doc["legs"].pop()
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_swapped_pair():
    doc = ledger()
    doc["legs"][0]["pair"] = doc["legs"][2]["pair"]
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_bad_mode():
    doc = ledger()
    doc["legs"][0]["mode"] = "turbo"
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_schedule_drift():
    doc = ledger()
    doc["schedule"][0][1] = "summary"
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_extra_key():
    doc = ledger()
    doc["legs"][0]["smuggled"] = 1
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_accept_error_leg():
    doc = ledger()
    doc["legs"][0] = {"seq": 0, "round": 0,
                      "mode": doc["legs"][0]["mode"],
                      "pair": doc["legs"][0]["pair"],
                      "tag": "l00", "files": [],
                      "error": "guest: ping flood failed"}
    validate_overhead_legs(doc)


def test_legs_refuse_clean_leg_missing_facts():
    doc = ledger()
    del doc["legs"][0]["workload"]
    with pytest.raises(ValueError):
        validate_overhead_legs(doc)


def test_legs_refuse_1ns_endpoint_warmup():
    doc = ledger()
    window = doc["legs"][0]["workload"]["window"]
    window["warmup_start_ns"] = \
        window["measured_start_ns"] - 1
    with pytest.raises(ValueError, match="warmup window"):
        validate_overhead_legs(doc)


def test_legs_refuse_contradictory_warmup_seconds():
    doc = ledger()
    doc["legs"][0]["workload"]["warmup"]["seconds"] = 1.5
    with pytest.raises(ValueError, match="contradicts"):
        validate_overhead_legs(doc)


def test_probe_validate_clean():
    doc = ledger()
    probe = {key: doc[key] for key in
             ("seed", "artifacts", "workload", "fixture",
              "epilogue")}
    probe["schema"] = "memveil-overhead-probe/1"
    first = leg("summary", 0, 0, "probe-summary", "p0")
    second = leg("attached-idle", 1, 0, "probe-idle", "p1")
    probe["legs"] = [first, second]
    validate_overhead_probe(probe)


def test_probe_refuses_campaign_fields():
    doc = ledger()
    probe = {key: doc[key] for key in
             ("seed", "artifacts", "workload", "fixture",
              "epilogue", "rounds", "schedule")}
    probe["schema"] = "memveil-overhead-probe/1"
    probe["legs"] = [leg("summary", 0, 0, "probe-summary",
                         "p0"),
                     leg("attached-idle", 1, 0, "probe-idle",
                         "p1")]
    with pytest.raises(ValueError):
        validate_overhead_probe(probe)


def test_off_leg_valid():
    ping, dd, metrics, _ = overhead.leg_runs(
        leg("off", 0, 0, "r0-summary", "l00"), {}, PROFILE)
    assert ping["valid"] and dd["valid"]
    assert metrics["cpu_s"] == 0.0
    assert metrics["records_per_s"] is None


def test_summary_leg_valid(tmp_path):
    row = leg("summary", 0, 0, "r0-summary", "l00")
    got = write_product_files(tmp_path, "l00", "summary")
    ping, dd, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert ping["valid"] and dd["valid"]
    assert metrics["facts"]["completed_lifetimes"] == 1
    assert metrics["facts"]["peak_open"] == 1
    assert metrics["facts"]["loss_count"] == 0
    wall_s = (row["collector"]["detach_ns"]
              - row["collector"]["attach_ns"]) / 1e9
    assert metrics["collector_wall_s"] == wall_s
    assert metrics["records_per_s"] == \
        metrics["facts"]["events_total"] / wall_s
    assert metrics["aggregate_rss_kb"] == \
        metrics["maxrss_kb"] == 123456


def test_lab_leg_valid(tmp_path):
    got = write_lab_files(tmp_path, "l00")
    ping, dd, metrics, _ = overhead.leg_runs(
        leg("undersized-buffer", 0, 0, "r0-undersized-buffer",
            "l00"), got, PROFILE)
    assert ping["valid"] and dd["valid"]
    assert metrics["facts"]["events_total"] == 3
    assert metrics["facts"]["cnt_fail"] == 0


def test_leg_rejects_bad_flood():
    row = leg("off")
    row["workload"]["ping"]["rx"] = 999
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "999" in ping["invalid_reason"]


def test_leg_rejects_short_sample():
    row = leg("off")
    row["workload"]["ping"]["sample_count"] = SAMPLE_COUNT - 1
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None


def test_leg_rejects_dd_bytes():
    row = leg("off")
    row["workload"]["dd"]["bytes"] = 1
    _, dd, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "dd bytes" in dd["invalid_reason"]


def test_leg_rejects_percentile_drift():
    row = leg("off")
    row["workload"]["ping"]["p99_ms"] += 1.0
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "percentile" in ping[
        "invalid_reason"]


def test_leg_rejects_record_exit(tmp_path):
    got = write_product_files(tmp_path, "l00", "summary")
    row = leg("summary")
    row["collector"]["exit"] = 1
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "exit" in ping["invalid_reason"]


def test_leg_rejects_missing_stop_flag(tmp_path):
    got = write_product_files(tmp_path, "l00", "attached-idle")
    row = leg("attached-idle")
    row["collector"]["stopped"] = False
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "stopped" in ping[
        "invalid_reason"]


def test_leg_rejects_session_mismatch(tmp_path):
    got = write_product_files(tmp_path, "l00", "summary")
    (tmp_path / "l00-session.json").write_text(json.dumps(
        session_doc("summary", "sess-other")))
    row = leg("summary")
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "identity" in ping[
        "invalid_reason"]


def test_leg_rejects_profile_drift(tmp_path):
    got = write_product_files(tmp_path, "l00", "summary")
    doc = session_doc("summary", "sess-summary")
    doc["capabilities"]["bounce_attempts"]["profile_id"] = "x"
    (tmp_path / "l00-session.json").write_text(json.dumps(doc))
    row = leg("summary")
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "profile" in ping[
        "invalid_reason"]


def test_leg_rejects_lab_conservation_break(tmp_path):
    got = write_lab_files(tmp_path, "l00")
    (tmp_path / "l00-lc.txt").write_text(
        LC_FILE.replace("cnt_emit=2", "cnt_emit=9"))
    row = leg("undersized-buffer")
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None


def test_leg_rejects_unsettled_bpf():
    row = leg("off")
    row["bpf"]["settled"] = False
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "settle" in ping["invalid_reason"]


def test_leg_rejects_1ns_measured_window():
    row = leg("off")
    window = row["workload"]["window"]
    window["end_ns"] = window["measured_start_ns"] + 1
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "measured window" in ping[
        "invalid_reason"]


def test_leg_rejects_short_measured_window():
    row = leg("off")
    window = row["workload"]["window"]
    window["end_ns"] = window["measured_start_ns"] + 6200000000
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "below 60s minimum" in ping[
        "invalid_reason"]


def test_leg_rejects_short_endpoint_warmup():
    row = leg("off")
    window = row["workload"]["window"]
    window["warmup_start_ns"] = \
        window["measured_start_ns"] - 9500000000
    row["workload"]["warmup"]["seconds"] = 9.5
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "below 10s minimum" in ping[
        "invalid_reason"]


def test_leg_rejects_1ns_endpoint_warmup():
    row = leg("off")
    window = row["workload"]["window"]
    window["warmup_start_ns"] = \
        window["measured_start_ns"] - 1
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None
    assert "below 10s minimum" in ping["invalid_reason"]
    assert "contradicts" in ping["invalid_reason"]


def test_leg_rejects_contradictory_warmup_seconds():
    row = leg("off")
    row["workload"]["warmup"]["seconds"] = 9.5
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "contradicts" in ping[
        "invalid_reason"]


def test_leg_rejects_excessive_measured_window():
    row = leg("off")
    window = row["workload"]["window"]
    window["end_ns"] = window["measured_start_ns"] + 400000000000
    ping, _, metrics, _ = overhead.leg_runs(row, {}, PROFILE)
    assert metrics is None and "exceeds" in ping[
        "invalid_reason"]


def test_leg_rejects_attach_after_workload_start(tmp_path):
    got = write_product_files(tmp_path, "l00", "summary")
    row = leg("summary")
    row["collector"]["attach_ns"] = \
        row["workload"]["window"]["measured_start_ns"]
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "attached after workload" in ping[
        "invalid_reason"]


def test_leg_rejects_attach_after_workload_end(tmp_path):
    got = write_product_files(tmp_path, "l00", "summary")
    row = leg("summary")
    window = row["workload"]["window"]
    row["collector"]["attach_ns"] = window["end_ns"] + 1000
    row["collector"]["term_ns"] = window["end_ns"] + 2000
    row["collector"]["detach_ns"] = window["end_ns"] + 3000
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "attached after workload" in ping[
        "invalid_reason"]


def test_leg_rejects_lab_attach_after_workload_start(tmp_path):
    got = write_lab_files(tmp_path, "l00")
    row = leg("undersized-buffer")
    row["collector"]["attach_ns"] = \
        row["workload"]["window"]["measured_start_ns"]
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert metrics is None and "attached after workload" in ping[
        "invalid_reason"]


def test_rate_uses_collector_wall_not_measured(tmp_path):
    row = leg("summary", 0, 0, "r0-summary", "l00")
    got = write_product_files(tmp_path, "l00", "summary")
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert ping["valid"]
    wall_s = (row["collector"]["detach_ns"]
              - row["collector"]["attach_ns"]) / 1e9
    assert wall_s != metrics["measured_s"]
    assert metrics["records_per_s"] == \
        metrics["facts"]["events_total"] / wall_s
    assert metrics["records_per_s"] != \
        metrics["facts"]["events_total"] / metrics["measured_s"]


def test_lab_rss_reports_per_process_and_aggregate(tmp_path):
    got = write_lab_files(tmp_path, "l00")
    row = leg("undersized-buffer")
    row["collector"]["lc"]["maxrss_kb"] = 49336
    row["collector"]["cp"]["maxrss_kb"] = 49336
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert ping["valid"]
    assert metrics["maxrss_kb"] == 49336
    assert metrics["aggregate_rss_kb"] == 98672


def test_report_metrics_labels_rss_bounds(tmp_path):
    doc_rows = []
    got = {}
    got.update(write_product_files(tmp_path, "l00", "summary"))
    got.update(write_lab_files(tmp_path, "l01"))
    for row in (leg("off", 0, 0, "r0-summary", "l00"),
                leg("summary", 1, 0, "r0-summary", "l00"),
                leg("undersized-buffer", 2, 0,
                    "r0-undersized-buffer", "l01")):
        ping_run, dd_run, metrics, _ = overhead.leg_runs(
            row, got, PROFILE)
        doc_rows.append((row["pair"], row["mode"], row["tag"],
                         ping_run, dd_run, metrics))
    lines = overhead.report_metrics(doc_rows)
    assert any("rss_MiB aggr_MiB" in line for line in lines)
    lab_line = [line for line in lines
                if line.startswith("perf-overhead: rss "
                                   "undersized-buffer:")][0]
    assert "worst-per-process=9.8MiB" in lab_line
    assert "worst-aggregate=19.5MiB" in lab_line


def test_facts_reorder_loses_peak(tmp_path):
    got = write_product_files(tmp_path, "l00", "detail")
    (tmp_path / "l00-events.ndjson").write_text(
        event_line("unmap", {"mapping_id": "gen-9"}) + "\n")
    row = leg("detail")
    ping, _, metrics, _ = overhead.leg_runs(
        row, got, PROFILE)
    assert ping["valid"]
    assert metrics["facts"]["peak_open"] is None
    assert metrics["facts"]["occupancy_reordered"] is True
    assert metrics["facts"]["completed_lifetimes"] == 0


def campaign_got(tmp_path, doc):
    """Write every declared leg file; return the got mapping."""
    got = {}
    for row in doc["legs"]:
        tag = row["tag"]
        mode = row["mode"]
        if mode in CAPS:
            got.update(write_product_files(tmp_path, tag, mode))
        elif mode == "undersized-buffer":
            got.update(write_lab_files(tmp_path, tag))
    return got


def test_report_mode_summary_pass(tmp_path, capsys):
    doc = ledger()
    got = campaign_got(tmp_path, doc)
    pairs = []
    for rnd in range(5):
        members = {row["mode"]: row for row in doc["legs"]
                   if row["pair"] == "r%d-summary" % rnd}
        pairs.append((members["off"], members["summary"]))
    qualified, lines, rows = overhead.report_mode(
        "summary", pairs, got, PROFILE)
    assert qualified
    assert any("target PASS" in line for line in lines)
    assert len(rows) == 10


def test_report_mode_summary_breach_is_fail(tmp_path):
    doc = ledger()
    got = campaign_got(tmp_path, doc)
    pairs = []
    for rnd in range(5):
        members = {row["mode"]: row for row in doc["legs"]
                   if row["pair"] == "r%d-summary" % rnd}
        members["summary"]["workload"]["ping"]["seconds"] = 4.0
        pairs.append((members["off"], members["summary"]))
    qualified, lines, _ = overhead.report_mode(
        "summary", pairs, got, PROFILE)
    assert qualified
    assert any("target FAIL" in line for line in lines)


def test_report_mode_other_is_measured(tmp_path):
    doc = ledger()
    got = campaign_got(tmp_path, doc)
    pairs = []
    for rnd in range(5):
        members = {row["mode"]: row for row in doc["legs"]
                   if row["pair"] == "r%d-detail" % rnd}
        pairs.append((members["off"], members["detail"]))
    qualified, lines, _ = overhead.report_mode(
        "detail", pairs, got, PROFILE)
    assert qualified
    assert any("MEASURED" in line for line in lines)
    assert not any("target" in line for line in lines)


def test_report_mode_few_valid_is_unqualified(tmp_path):
    doc = ledger()
    got = campaign_got(tmp_path, doc)
    pairs = []
    for rnd in range(5):
        members = {row["mode"]: row for row in doc["legs"]
                   if row["pair"] == "r%d-detail" % rnd}
        if rnd < 2:
            members["detail"]["error"] = "guest: boom"
            del members["detail"]["workload"]
            del members["detail"]["collector"]
        pairs.append((members["off"], members["detail"]))
    qualified, lines, _ = overhead.report_mode(
        "detail", pairs, got, PROFILE)
    assert not qualified
    assert any("UNQUALIFIED" in line for line in lines)


def flow_fixture(monkeypatch, tmp_path, doc, got):
    from types import SimpleNamespace
    cleaned = []
    monkeypatch.setattr(
        overhead, "run_guest",
        lambda *a, **k: (tmp_path,
                         SimpleNamespace(returncode=0,
                                         stderr="")))
    monkeypatch.setattr(
        overhead, "snapshot_campaign", lambda *a, **k: (got, doc))
    monkeypatch.setattr(overhead, "expected_from_verified",
                        lambda *a, **k: {})
    monkeypatch.setattr(
        overhead, "cleanup",
        lambda path, *a, **k: cleaned.append(path))
    monkeypatch.setattr(overhead, "retain_failure",
                        lambda *a, **k: None)
    return cleaned


def test_flow_healthy_pass(tmp_path, monkeypatch, capsys):
    doc = ledger()
    got = campaign_got(tmp_path, doc)
    cleaned = flow_fixture(monkeypatch, tmp_path, doc, got)
    assert overhead.run_flow() == 0
    assert cleaned == [tmp_path]
    out = capsys.readouterr().out
    assert "PASS: 20 unique pairs" in out
    assert "LIMITATION" not in out


def test_flow_breach_is_limitation(tmp_path, monkeypatch, capsys):
    doc = ledger()
    for row in doc["legs"]:
        if row["mode"] == "summary":
            row["workload"]["ping"]["seconds"] = 4.0
    got = campaign_got(tmp_path, doc)
    cleaned = flow_fixture(monkeypatch, tmp_path, doc, got)
    assert overhead.run_flow() == 0
    assert cleaned == [tmp_path]
    out = capsys.readouterr().out
    assert "LIMITATION: summary ping target FAIL" in out


def test_flow_unqualified_fails(tmp_path, monkeypatch, capsys):
    doc = ledger()
    for row in doc["legs"]:
        if row["mode"] == "detail":
            row["error"] = "guest: boom"
            del row["workload"]
            del row["collector"]
    got = campaign_got(tmp_path, doc)
    cleaned = flow_fixture(monkeypatch, tmp_path, doc, got)
    assert overhead.run_flow() == 1
    assert not cleaned
    assert "FAIL perf-overhead" in capsys.readouterr().out


def probe_doc():
    doc = ledger([])
    probe = {key: doc[key] for key in
             ("seed", "artifacts", "workload", "fixture",
              "epilogue")}
    probe["schema"] = "memveil-overhead-probe/1"
    probe["legs"] = [leg("summary", 0, 0, "probe-summary", "p0"),
                     leg("attached-idle", 1, 0, "probe-idle",
                         "p1")]
    return probe


def test_probe_healthy_pass(tmp_path, monkeypatch, capsys):
    doc = probe_doc()
    got = campaign_got(tmp_path, doc)
    cleaned = flow_fixture(monkeypatch, tmp_path, doc, got)
    assert overhead.run_probe() == 0
    assert cleaned == [tmp_path]
    assert "probe PASS" in capsys.readouterr().out


def test_probe_bad_leg_fails(tmp_path, monkeypatch, capsys):
    doc = probe_doc()
    doc["legs"][0]["collector"]["exit"] = 1
    got = campaign_got(tmp_path, doc)
    cleaned = flow_fixture(monkeypatch, tmp_path, doc, got)
    assert overhead.run_probe() == 1
    assert not cleaned
    assert "FAIL perf-overhead" in capsys.readouterr().out


def test_main_unarmed_skips(monkeypatch):
    monkeypatch.setenv("MEMVEIL_VM_PERF", "0")
    assert overhead.main() == 77
