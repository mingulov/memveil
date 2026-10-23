#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detection scenario offline tests: table, predicates, row assembly.

No boot, no network, no privileged reads. Every case runs from
controlled fixture bytes.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_scenarios as ks


def _doc(caps, mode="load-check", verdict="ready"):
    return {"mode": mode, "verdict": verdict,
            "guest": {"tech": "ordinary", "signals": [],
                      "conflict": ""},
            "capabilities": [
                {"id": cap, "status": status,
                 "reason_code": code, "reason": reason}
                for cap, status, code, reason in caps]}


def _verified(cap):
    return "%s: live interfaces verified (profile unvalidated)" % cap


def _load_all_available():
    return _doc([(cap, "available", "available", _verified(cap))
                 for cap in ks.CAPS])


def _passive_all_unchecked():
    return _doc([(cap, "available-load-unchecked", "available",
                  _verified(cap)) for cap in ks.CAPS],
                mode="passive", verdict="ready-load-unchecked")


def _ev(name="base"):
    ev = {"passive": {"text": json.dumps(
                _passive_all_unchecked()), "exit": "0"},
            "load": {"text": json.dumps(
                _load_all_available()), "exit": "0"},
            "record": {"out": "ready session=mvt0\n", "exit": "4",
                       "exists": "yes"},
            "passive_schema": True, "load_schema": True,
            "precondition": {"verdict": "ready-load-unchecked"},
            "teardown": {"verdict": "ready-load-unchecked"},
            "base_verdict": "ready-load-unchecked",
            "capture": None, "memcg": None,
            "job_negatives": {}}
    if name == "base":
        ev["capture"] = {
            "events_text": _events(maps=5, copies=2),
            "session_text": json.dumps(_session()),
            "validate_rc": 0}
    return ev


def _check(rec, name):
    for check in rec["checks"]:
        if check["name"] == name:
            return check
    raise AssertionError("missing check " + name)


def _admitted_entry():
    return {
        "id": "7.0",
        "release": "7.0.14-070014-generic",
        "expected": {
            cap: {"verdict": "admitted",
                  "reason_class": "live-verified"}
            for cap in ks.CAPS},
    }


def test_scenarios_refuse_non_admitted_row():
    assert ks.scenarios_row_admitted(_admitted_entry())
    for cls in ("lockdown", "btf-absent", "floor-6.0"):
        entry = _admitted_entry()
        entry["expected"]["attempt-trace"] = {
            "verdict": "refused", "reason_class": cls}
        assert not ks.scenarios_row_admitted(entry)
    entry = _admitted_entry()
    entry["expected"]["mapping-lifecycle"] = {
        "verdict": "refused", "reason_class": "floor-6.11"}
    assert not ks.scenarios_row_admitted(entry)


def test_expectation_table_complete():
    assert tuple(ks.SCENARIOS) == ks.SCENARIO_ORDER
    fails = ks.check_expectation_table()
    assert not fails
    for name in ks.SCENARIO_ORDER:
        spec = ks.SCENARIOS[name]
        assert set(spec["exits"]) <= {"0", "3", "4"}
        assert len(spec["exits"]) == 3


def test_scenario_precondition_missing_fails():
    ev = _ev("base")
    ev["precondition"] = None
    rec = ks.evaluate_scenario("base", ev)
    assert not rec["ok"]
    assert not _check(rec, "precondition")["ok"]


def test_scenario_teardown_not_restored_fails():
    ev = _ev("base")
    ev["teardown"] = {"verdict": "unavailable"}
    rec = ks.evaluate_scenario("base", ev)
    assert not rec["ok"]
    assert not _check(rec, "teardown")["ok"]
    first = ks.evaluate_scenario("base", _ev("base"))
    assert first["ok"]
    later = ks.evaluate_scenario("base", _ev("base"))
    assert later["ok"]
    out = ks.evaluate_run([("base", first),
                           ("neg-renamed", rec),
                           ("neg-layout", later)])
    assert out[0]["status"] == "ok"
    assert out[1]["status"] == "fail"
    assert out[2]["status"] == "fail"
    assert any(c["name"] == "control" and not c["ok"]
               for c in out[2]["checks"])


def _refused_docs(code, status="unavailable"):
    reason = "refused for %s" % code
    load = _doc([(cap, status, code, reason)
                 for cap in ks.CAPS],
                mode="load-check", verdict="unavailable")
    return load


def test_record_code_matches_first_refused_cap():
    load = _doc([
        ("attempt-trace", "available", "available",
         _verified("attempt-trace")),
        ("mapping-lifecycle", "unavailable", "layout-missing",
         "live check failed"),
        ("copy-actual", "unavailable", "hook-ambiguous",
         "live check failed"),
    ], mode="load-check", verdict="unavailable")
    assert ks.first_refused_code(load) == "layout-missing"
    passive = _doc([
        ("attempt-trace", "available-load-unchecked",
         "available", _verified("attempt-trace")),
        ("mapping-lifecycle", "unavailable", "layout-missing",
         "live check failed"),
        ("copy-actual", "unavailable", "hook-ambiguous",
         "live check failed"),
    ], mode="passive", verdict="unavailable")
    out = "memveil record: live check failed\n" \
        "memveil record: code: layout-missing\n"
    ok, detail = ks.check_agreement(
        "nonroot", passive, load, out)
    assert ok, detail
    out = "memveil record: live check failed\n" \
        "memveil record: code: hook-ambiguous\n"
    ok, _ = ks.check_agreement("nonroot", passive, load, out)
    assert not ok


def test_passive_load_pairs():
    load = _doc([(cap, "unavailable", "load-eperm",
                  "load EPERM: needs CAP_BPF")
                 for cap in ks.CAPS],
                mode="load-check", verdict="unavailable")
    passive = _doc([(cap, "unavailable", "no-bpf-privilege",
                     "CapEff lacks BPF")
                    for cap in ks.CAPS],
                   mode="passive", verdict="unavailable")
    out = "memveil record: load: ch0 op=2 EPERM\n" \
        "memveil record: code: load-eperm\n"
    ok, detail = ks.check_agreement(
        "nocaps", passive, load, out)
    assert ok, detail
    ok, _ = ks.check_agreement("nonroot", passive, load, out)
    assert not ok
    denied = _doc([(cap, "unknown", "tracefs-denied",
                    "tracefs denied (privilege)")
                   for cap in ks.CAPS],
                  mode="passive", verdict="unavailable")
    ok, _ = ks.check_agreement("nocaps", denied, load, out)
    assert not ok
    mem_load = _doc([(cap, "unavailable", "load-enomem",
                      "load ENOMEM")
                     for cap in ks.CAPS],
                    mode="load-check", verdict="unavailable")
    mem_passive = _passive_all_unchecked()
    mem_passive["verdict"] = "unavailable"
    mem_out = "memveil record: load: ch0 op=2 ENOMEM\n" \
        "memveil record: code: load-enomem\n"
    ok, detail = ks.check_agreement(
        "memcg", mem_passive, mem_load, mem_out)
    assert ok, detail
    ok, _ = ks.check_agreement(
        "nocaps", mem_passive, mem_load, mem_out)
    assert not ok


def _session(cause="LAYOUT", unknown_key="copy.unknown_layout",
             unknown_count="3", maps="5", copies="0",
             obj_sha="a" * 64, loss_count="3",
             detail_status="partial"):
    return {
        "capture": {"window": {"start_ns": "1000",
                               "end_ns": "2000"}},
        "capabilities": {
            "copy_bytes": {"status": "partial",
                           "reason": "capture elapsed, %s copy "
                                     "events persisted" % copies}},
        "quality": {"detail": {"status": detail_status,
                               "loss_count": loss_count,
                               "reason": "detail loss %s "
                                         "(submit_fail=(0) "
                                         "malformed=(0) "
                                         "dropped=(0) "
                                         "recursion_missed=(0) "
                                         "size_omitted=(0) "
                                         "duration_omitted=(0) "
                                         "signal_omitted=(0) "
                                         "rejected=(%s) "
                                         "write_failed=(0)); first "
                                         "unknown copy: %s"
                                         % (loss_count, loss_count,
                                            cause)}},
        "environment": {"evidence": [
            {"type": "provenance",
             "source": "cp.object.sha256",
             "interpretation": obj_sha},
            {"type": "provenance", "source": unknown_key,
             "interpretation": unknown_count}]},
    }


def _events(maps=5, copies=0, attempts=9):
    lines = []
    for _ in range(attempts):
        lines.append(json.dumps({"kind": "bounce_attempt",
                                 "seq": "1"}))
    for _ in range(maps):
        lines.append(json.dumps({"kind": "map_result",
                                 "seq": "2"}))
    for _ in range(copies):
        lines.append(json.dumps({"kind": "copy", "seq": "3"}))
    return "\n".join(lines) + "\n" if lines else ""


def _report(value=None, measurement="unavailable"):
    return {"metrics": [
        {"name": "copy_original_to_bounce_bytes",
         "value": value, "measurement": measurement},
        {"name": "copy_bounce_to_original_bytes",
         "value": value, "measurement": measurement}]}


def _cap(cause="LAYOUT", unknown_key="copy.unknown_layout",
         copies=0, obj_sha="a" * 64, value=None,
         measurement="unavailable", maps=5,
         report_text=None, workload_out=None,
         workload_exit="0", validate_rc=0):
    if report_text is None:
        report_text = "metrics (2):\n" \
            "  copy_original_to_bounce_bytes = unavailable " \
            "bytes [unavailable]\n" \
            "  copy_bounce_to_original_bytes = unavailable " \
            "bytes [unavailable]\n"
    if workload_out is None:
        workload_out = "phase scn start_ns 1100 end_ns 1900 " \
            "bytes 67108864 ios 64\nbuf scn mod4096=0\n"
    return {"events_text": _events(maps=maps, copies=copies),
            "session_text": json.dumps(
                _session(cause=cause, unknown_key=unknown_key,
                         obj_sha=obj_sha)),
            "report_json_text": json.dumps(_report(
                value=value, measurement=measurement)),
            "report_text": report_text,
            "workload_out": workload_out,
            "workload_exit": workload_exit,
            "validate_rc": validate_rc,
            "object_sha": obj_sha}


def test_negative_capture_copy_record_fails():
    cap = _cap(copies=1)
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok
    cap = _cap(copies=0)
    ok, detail = ks.check_capture("neg-layout", cap)
    assert ok, detail


def test_negative_capture_complete_fails():
    session = _session()
    session["capabilities"]["copy_bytes"]["status"] = \
        "complete"
    cap = _cap()
    cap["session_text"] = json.dumps(session)
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok


def test_negative_capture_effective_zero_fails():
    cap = _cap(value="0", measurement="derived")
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok
    cap = _cap(report_text="metrics (1):\n"
               "  copy_original_to_bounce_bytes = 0 bytes "
               "[derived]\n")
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok
    cap = _cap(report_text="metrics (0):\nnotes:\n"
               "7 copy bytes lack device attribution and appear "
               "in global totals only.\n")
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok


def test_negative_capture_zero_unknown_fails():
    session = _session(unknown_count="0")
    cap = _cap()
    cap["session_text"] = json.dumps(session)
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok
    session = _session()
    session["environment"]["evidence"] = [
        item for item in
        session["environment"]["evidence"]
        if item["source"] != "copy.unknown_layout"]
    cap = _cap()
    cap["session_text"] = json.dumps(session)
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok


def test_negative_capture_no_maps_fails():
    cap = _cap(maps=0)
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok
    cap = _cap(workload_out="", workload_exit="1")
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok


def test_negative_capture_object_sha_mismatch_fails():
    cap = _cap()
    cap["object_sha"] = "b" * 64
    ok, _ = ks.check_capture("neg-layout", cap)
    assert not ok


def _memcg_ev(oom_delta=0, record_exit="3", status="ok",
              p0=20000000, p1=60000000, r0=25000000):
    limit = (max(p0, r0) + p1) // 2
    attempt = {"cgroup": "0::/mvt_small\n",
               "memory_max": str(limit),
               "p0": p0, "p1": p1, "r0": r0, "limit": limit,
               "oom_before": 10, "oom_after": 10 + oom_delta,
               "exits": ["0", "3", record_exit]}
    ev = _ev("memcg")
    passive = _passive_all_unchecked()
    passive["prechecks"] = [
        {"id": "privilege", "state": "pass", "code": ""},
        {"id": "memcg", "state": "unknown",
         "code": "memcg-headroom",
         "reason": "cgroup mvt_small fits 10000000 of "
                   "50000000 map bytes"}]
    ev["passive"] = {"text": json.dumps(passive),
                     "exit": "0"}
    ev["memcg"] = {"attempts": [attempt], "chosen": 0,
                   "status": status}
    ev["precondition"] = {"attempt": attempt}
    reason = "load ENOMEM: memcg or memlock limit"
    ev["load"] = {"text": json.dumps(_doc(
        [(cap, "unavailable", "load-enomem", reason)
         for cap in ks.CAPS],
        mode="load-check", verdict="unavailable")),
        "exit": "3"}
    ev["record"] = {"out": "memveil record: %s\n"
                           "memveil record: code: load-enomem\n"
                           % reason,
                    "exit": record_exit, "exists": "no"}
    return ev


def test_memcg_oom_kill_invalid():
    ev = _memcg_ev(oom_delta=1)
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]


def test_memcg_calibration_too_small_fails():
    ev = _memcg_ev(p0=50000000, p1=55000000)
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]
    assert not _check(rec, "precondition")["ok"]


def test_memcg_record_peak_over_limit_fails():
    ev = _memcg_ev()
    attempt = ev["memcg"]["attempts"][0]
    attempt["r0"] = attempt["limit"] + 1
    ev["precondition"] = {"attempt": attempt}
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]
    assert not _check(rec, "precondition")["ok"]


def test_memcg_ok_path():
    ev = _memcg_ev()
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)


def test_memcg_not_proven_needs_two_invalid():
    ev = _memcg_ev()
    attempt = ev["memcg"]["attempts"][0]
    attempt["oom_after"] = attempt["oom_before"] + 1
    ev["memcg"]["attempts"] = [dict(attempt),
                               dict(attempt)]
    ev["memcg"]["chosen"] = None
    ev["memcg"]["status"] = "not_proven"
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["status"] == "not_proven"
    assert not rec["ok"]
    ev["memcg"]["attempts"] = [dict(attempt)]
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["status"] == "fail"


def test_scenario_exit_mismatch_fails():
    ev = _ev("base")
    ev["passive"]["exit"] = "3"
    rec = ks.evaluate_scenario("base", ev)
    assert not rec["ok"]
    assert not _check(rec, "doctor_passive_exit")["ok"]
    ev = _memcg_ev()
    ev["passive"]["exit"] = "3"
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]
    assert not _check(rec, "doctor_passive_exit")["ok"]
