#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detection scenario offline tests: table, predicates, row assembly.

No boot, no network, no privileged reads. Every case runs from
controlled fixture bytes.
"""

import ast
import gzip
import hashlib
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_scenarios as ks
import kernel_scenarios_guest as scguest


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


def test_nocaps_precondition_needs_zero():
    ok, _ = ks.check_precondition(
        "nocaps", {"capeff": "0", "probe_exit": "0"})
    assert ok
    ok, _ = ks.check_precondition(
        "nocaps", {"capeff": "0000000000000000",
                   "probe_exit": "0"})
    assert ok
    for capeff in ("1", "1ffffffffff", "xyz", None):
        ok, _ = ks.check_precondition(
            "nocaps", {"capeff": capeff, "probe_exit": "0"})
        assert not ok


def _nocaps_ev(capeff, probe_exit="0"):
    ev = _ev("nocaps")
    ev["precondition"] = {"capeff": capeff,
                          "probe_exit": probe_exit}
    return ev


def test_nocaps_capeff_nonzero_not_proven():
    rec = ks.evaluate_scenario(
        "nocaps", _nocaps_ev("1ffffffffff"))
    assert not rec["ok"]
    assert rec["status"] == "not_proven"
    assert _check(rec, "precondition")["ok"]
    for name in ("doctor_passive", "doctor_passive_exit",
                 "doctor_load", "doctor_load_exit",
                 "record", "agreement", "capture",
                 "teardown"):
        check = _check(rec, name)
        assert check["skipped"], name


def test_nocaps_broken_evidence_fails():
    rec = ks.evaluate_scenario("nocaps", _nocaps_ev("xyz"))
    assert not rec["ok"]
    assert rec["status"] == "fail"
    rec = ks.evaluate_scenario(
        "nocaps", _nocaps_ev("0", probe_exit="1"))
    assert not rec["ok"]
    assert rec["status"] == "fail"


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
    limit = ks.memcg_limit(p0, r0, p1)
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


def _memcg_mixed_load():
    reason = "load ENOMEM: memcg or memlock limit"
    caps = [("attempt-trace", "available", "available",
             "attempt-trace: live interfaces verified")]
    for cap in ks.CAPS[1:]:
        caps.append((cap, "unavailable", "load-enomem",
                     reason))
    return _doc(caps, mode="load-check",
                verdict="unavailable")


def test_memcg_load_mixed_passes():
    ev = _memcg_ev()
    ev["load"] = {"text": json.dumps(_memcg_mixed_load()),
                  "exit": "3"}
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["ok"], json.dumps(rec["checks"], indent=1)


def test_memcg_load_false_ready_fails():
    # Load-check admits all while record refuses in the
    # same cgroup: a false ready, never not_proven.
    ev = _memcg_ev()
    ev["load"] = {"text": json.dumps(
        _load_all_available()), "exit": "0"}
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]
    assert rec["status"] == "fail"
    assert not _check(rec, "doctor_load")["ok"]
    assert not _check(rec, "doctor_load_exit")["ok"]


def test_memcg_load_exit_zero_with_refusal_fails():
    ev = _memcg_ev()
    ev["load"]["exit"] = "0"
    rec = ks.evaluate_scenario("memcg", ev)
    assert not rec["ok"]
    assert rec["status"] == "fail"


def test_memcg_unrefused_not_proven():
    ev = _memcg_ev()
    attempt = ev["memcg"]["attempts"][0]
    attempt["exits"] = ["0", "3", "4"]
    ev["memcg"]["attempts"] = [dict(attempt),
                               dict(attempt)]
    ev["memcg"]["chosen"] = None
    ev["memcg"]["status"] = "not_proven"
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["status"] == "not_proven"
    assert not rec["ok"]
    ok, _ = ks._memcg_not_proven(ev["memcg"])
    assert ok


def test_memcg_refused_voids_not_proven():
    ev = _memcg_ev()
    attempt = ev["memcg"]["attempts"][0]
    ev["memcg"]["attempts"] = [dict(attempt),
                               dict(attempt)]
    ev["memcg"]["chosen"] = None
    ev["memcg"]["status"] = "not_proven"
    rec = ks.evaluate_scenario("memcg", ev)
    assert rec["status"] == "fail"


def test_memcg_passive_precheck_gone():
    assert "passive_precheck" not in ks.SCENARIOS["memcg"]


def test_memcg_limit_page_aligned():
    assert ks.memcg_limit(20000000, 25000000, 60000000) \
        == 42496000
    assert ks.memcg_limit(20000000, 25000000,
                          60000000) % 4096 == 0
    # The live 97 MB shape rounds down to the page.
    assert ks.memcg_limit(64987136, 20738048,
                          129699840) == 97341440
    ev = _memcg_ev()
    attempt = ev["memcg"]["attempts"][0]
    raw = (max(attempt["p0"], attempt["r0"])
           + attempt["p1"]) // 2
    assert raw != attempt["limit"]
    attempt["limit"] = raw
    attempt["memory_max"] = str(raw)
    ok, detail = ks._memcg_attempt_ok(
        {"attempt": attempt})
    assert ok is None, detail


def test_scenarios_verdict_not_proven_never_passes():
    ok, detail = ks.scenarios_verdict(
        [{"name": "base", "status": "ok"},
         {"name": "memcg", "status": "not_proven"}])
    assert not ok
    assert "not_proven=1" in detail
    ok, _ = ks.scenarios_verdict(
        [{"name": "base", "status": "ok"}])
    assert ok
    ok, _ = ks.scenarios_verdict(
        [{"name": "base", "status": "fail"}])
    assert not ok


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


# Strict-leg binding: the guest runs record under
# --strict on exactly the finalizing legs below, where
# the session verdict is never complete so strict record
# exits 4; the eight refusal legs exit 3 with no capture
# and no flag. Harness 208ae75 never passes the flag, so
# these tests fail there (proven in a base worktree) and
# pass on the fixed harness. A live run binds its own
# harness commit, candidate manifest, runtime versions,
# and fresh run id through harness.json and the row
# receipts at run time.
STRICT_LEGS = ("base", "neg-layout", "neg-shift",
               "neg-argcnt")

_GUEST_MV = "/usr/bin/memveil"


def test_record_strict_matches_finalize_table():
    assert tuple(scguest.SCN_ORDER) == ks.SCENARIO_ORDER
    strict = []
    for name in ks.SCENARIO_ORDER:
        spec = ks.SCENARIOS[name]
        cp_object = None
        if name.startswith("neg-"):
            cp_object = "/tmp/neg-%s.bpf.o" % name
        argv = scguest.record_argv(
            _GUEST_MV, "cap", 10, cp_object,
            strict=scguest.record_strict(name))
        if "finalize" in spec["record"]:
            strict.append(name)
            assert "--strict" in argv, name
            assert spec["exits"][2] == "4", name
        else:
            assert "--strict" not in argv, name
            assert spec["exits"][2] == "3", name
        assert ("--strict" in argv) == spec["workload"], \
            name
    assert tuple(strict) == STRICT_LEGS


class _Completed:
    def __init__(self, stdout="", returncode=0):
        self.stdout = stdout
        self.stderr = ""
        self.returncode = returncode


def _fake_sh(argv, **kw):
    if argv[1:2] == ["doctor"]:
        return _Completed(json.dumps({"verdict": "ready"}))
    return _Completed("")


def _popen_factory(seen, returncode=4):
    class FakePopen:
        def __init__(self, argv, **kw):
            seen.append(list(argv))
            self.returncode = returncode

        def poll(self):
            return 0

        def wait(self, timeout=None):
            return self.returncode

    return FakePopen


class _SubprocessStub:
    TimeoutExpired = subprocess.TimeoutExpired

    def __init__(self, popen):
        self.Popen = popen
        self.run = subprocess.run


def _dispatch_record_argv(monkeypatch, tmp_path, name):
    """Record argv from the real guest leg, stubbed spawn."""
    seen = []
    monkeypatch.setattr(scguest, "sh", _fake_sh)
    monkeypatch.setattr(
        scguest, "subprocess",
        _SubprocessStub(_popen_factory(seen)))
    sdir = tmp_path / ("scn-" + name)
    sdir.mkdir()
    ctx = {"mv": _GUEST_MV, "load": "load",
           "dev": "/dev/x", "negs": {},
           "plain": lambda argv: argv, "sdir": str(sdir)}
    if name == "base":
        scguest.scenario_base(ctx)
    else:
        neg = tmp_path / ("neg-" + name + ".bpf.o")
        neg.write_bytes(b"negative-object")
        ctx["negs"] = {scguest.NEG_FILES[name]: str(neg)}
        scguest.scenario_negative(ctx, name)
    assert len(seen) == 1, (name, seen)
    return seen[0]


def test_finalizing_dispatch_carries_strict(monkeypatch,
                                            tmp_path):
    argv = _dispatch_record_argv(monkeypatch, tmp_path,
                                "base")
    assert argv[:2] == [_GUEST_MV, "record"]
    assert "--strict" in argv
    assert argv[argv.index("--duration") + 1] == "10"
    for name in ("neg-layout", "neg-shift", "neg-argcnt"):
        argv = _dispatch_record_argv(monkeypatch, tmp_path,
                                    name)
        assert "--strict" in argv, name
        assert "--cp-object" in argv, name
        assert argv[argv.index("--duration") + 1] == "10", \
            name
    argv = _dispatch_record_argv(monkeypatch, tmp_path,
                                "neg-renamed")
    assert "--strict" not in argv
    assert "--cp-object" in argv
    assert argv[argv.index("--duration") + 1] == "5"


def test_run_record_sites_route_through_record_strict():
    path = os.path.join(os.path.dirname(scguest.__file__),
                        "kernel_scenarios_guest.py")
    with open(path) as handle:
        tree = ast.parse(handle.read())
    literals = []
    shared = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not isinstance(node.func, ast.Name):
            continue
        if node.func.id != "run_record":
            continue
        strict_kw = [kw for kw in node.keywords
                     if kw.arg == "strict"]
        assert len(strict_kw) == 1
        value = strict_kw[0].value
        assert isinstance(value, ast.Call)
        assert isinstance(value.func, ast.Name)
        assert value.func.id == "record_strict"
        assert len(value.args) == 1
        arg = value.args[0]
        if isinstance(arg, ast.Constant):
            literals.append(arg.value)
        elif isinstance(arg, ast.Name) and arg.id == "name":
            # The shared negative dispatcher, executed
            # for all four names by the dispatch test.
            shared += 1
        else:
            raise AssertionError(ast.dump(value))
    assert shared == 1
    assert sorted(literals) == sorted(
        ("base", "nonroot", "nocaps", "ftrace-off",
         "tracefs-unmounted", "btf-empty", "btf-truncated",
         "memcg", "memcg"))


def test_record_argv_default_mode_control():
    plain = scguest.record_argv(_GUEST_MV, "cap", 10)
    assert plain == [_GUEST_MV, "record", "--output", "cap",
                     "--duration", "10", "--capability",
                     scguest.ALL_CAPS]
    assert scguest.record_argv(
        _GUEST_MV, "cap", 10,
        strict=True) == plain + ["--strict"]
    ok, _ = ks.check_record_finalized(
        {"exit": "0", "exists": "yes"}, "0")
    assert ok


def test_scenario_hook_probes_match_matrix_guest():
    import kernel_matrix_guest as mguest
    assert scguest.WANT_FUNCS == mguest.WANT_FUNCS
    assert scguest.HOOK_EVT == mguest.EVT
    assert scguest.HOOK_FILTER_FUNCS == mguest.FILTER_FUNCS
    assert scguest.BTF_PATH == "/sys/kernel/btf/vmlinux"


def test_scenario_detect_hooks(monkeypatch, tmp_path):
    hook = tmp_path / "swiotlb_bounced"
    hook.mkdir()
    funcs = tmp_path / "available_filter_functions"
    funcs.write_text("swiotlb_bounce\nsome_other\n")
    monkeypatch.setattr(scguest, "HOOK_EVT", str(hook))
    monkeypatch.setattr(scguest, "HOOK_FILTER_FUNCS",
                        str(funcs))
    present, omitted = scguest.detect_hooks()
    assert present == {"tp": True, "map": False,
                       "unmap": False, "copy": True,
                       "syncc": False, "syncd": False}
    assert sorted(omitted) == ["map", "syncc", "syncd",
                               "unmap"]
    monkeypatch.setattr(scguest, "HOOK_EVT",
                        str(tmp_path / "missing"))
    monkeypatch.setattr(scguest, "HOOK_FILTER_FUNCS",
                        str(tmp_path / "missing-funcs"))
    present, omitted = scguest.detect_hooks()
    assert set(present) == {"tp", "map", "unmap", "copy",
                            "syncc", "syncd"}
    assert not any(present.values())
    assert sorted(omitted) == sorted(present)


def test_scenario_write_btf_sha(tmp_path):
    src = tmp_path / "vmlinux"
    src.write_bytes(b"btf-bytes")
    out = tmp_path / "out"
    out.mkdir()
    scguest.write_btf_sha(str(out), str(src))
    assert (out / "btf-sha.txt").read_text() == \
        hashlib.sha256(b"btf-bytes").hexdigest() + "\n"
    scguest.write_btf_sha(str(out),
                          str(tmp_path / "missing"))
    assert (out / "btf-sha.txt").read_text() == "absent\n"


class _StubUname:
    release = "6.6.160-test"


def _identity_tree(tmp_path):
    sysfs = tmp_path / "sysfs"
    hook = sysfs / "swiotlb_bounced"
    hook.mkdir(parents=True)
    (sysfs / "available_filter_functions").write_text(
        "swiotlb_tbl_map_single\n"
        "__swiotlb_tbl_unmap_single\n"
        "swiotlb_bounce\n"
        "__swiotlb_sync_single_for_cpu\n"
        "__swiotlb_sync_single_for_device\n")
    mods = tmp_path / "modules" / _StubUname.release
    mods.mkdir(parents=True)
    (tmp_path / "cmdline").write_text("virtme chance\n")
    with gzip.open(tmp_path / "config.gz", "wb") as handle:
        handle.write(b"CONFIG_TEST=y\n")
    (tmp_path / "version").write_text("Linux version test\n")
    (tmp_path / "lockdown").write_text("[none] test\n")
    (tmp_path / "vmlinux").write_bytes(b"btf-bytes")
    return sysfs


def _patch_identity(monkeypatch, tmp_path):
    sysfs = _identity_tree(tmp_path)
    monkeypatch.setattr(os, "uname", lambda: _StubUname())
    monkeypatch.setattr(scguest, "HOOK_EVT",
                        str(sysfs / "swiotlb_bounced"))
    monkeypatch.setattr(scguest, "HOOK_FILTER_FUNCS",
                        str(sysfs / "available_filter_functions"))
    monkeypatch.setattr(scguest, "CMDLINE_PATH",
                        str(tmp_path / "cmdline"))
    monkeypatch.setattr(scguest, "CONFIG_GZ_PATH",
                        str(tmp_path / "config.gz"))
    monkeypatch.setattr(scguest, "VERSION_PATH",
                        str(tmp_path / "version"))
    monkeypatch.setattr(scguest, "LOCKDOWN_PATH",
                        str(tmp_path / "lockdown"))
    monkeypatch.setattr(scguest, "MODULES_ROOT",
                        str(tmp_path / "modules"))
    monkeypatch.setattr(scguest, "BTF_PATH",
                        str(tmp_path / "vmlinux"))


def test_record_guest_identity_writes_matrix_set(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    scguest.record_guest_identity(str(out))
    assert (out / "uname.txt").read_text() == \
        "6.6.160-test\nvirtme chance\n"
    assert (out / "mods.txt").read_text() == \
        "6.6.160-test\n%s\n" % (
            tmp_path / "modules" / "6.6.160-test")
    with gzip.open(tmp_path / "config.gz", "rb") as handle:
        want_config = hashlib.sha256(handle.read()).hexdigest()
    assert (out / "configid.txt").read_text() == \
        want_config + "\n"
    assert (out / "btf-sha.txt").read_text() == \
        hashlib.sha256(b"btf-bytes").hexdigest() + "\n"
    assert (out / "version.txt").read_text() == \
        "Linux version test\n"
    assert (out / "lockdown.txt").read_text() == "[none] test\n"
    hooks = json.loads((out / "hooks.json").read_text())
    assert set(hooks) == {"present", "omitted", "btf"}
    assert hooks["present"] == {"tp": True, "map": True,
                                "unmap": True, "copy": True,
                                "syncc": True, "syncd": True}
    assert hooks["omitted"] == []
    assert hooks["btf"] is True


def test_record_guest_identity_resolves_module_symlink(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    target = tmp_path / "real-mods"
    target.mkdir()
    link = tmp_path / "modules" / _StubUname.release
    link.rmdir()
    link.symlink_to(target)
    out = tmp_path / "out"
    out.mkdir()
    scguest.record_guest_identity(str(out))
    assert (out / "mods.txt").read_text() == \
        "6.6.160-test\n%s\n" % target
    link.unlink()
    link.symlink_to("../real-mods")
    out2 = tmp_path / "out2"
    out2.mkdir()
    scguest.record_guest_identity(str(out2))
    assert (out2 / "mods.txt").read_text() == \
        "6.6.160-test\n%s\n" % (
            tmp_path / "modules" / "6.6.160-test"
            / "../real-mods")


def test_record_guest_identity_absent_sentinels(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    monkeypatch.setattr(scguest, "CONFIG_GZ_PATH",
                        str(tmp_path / "no-config"))
    monkeypatch.setattr(scguest, "LOCKDOWN_PATH",
                        str(tmp_path / "no-lockdown"))
    monkeypatch.setattr(scguest, "BTF_PATH",
                        str(tmp_path / "no-btf"))
    out = tmp_path / "out"
    out.mkdir()
    scguest.record_guest_identity(str(out))
    assert (out / "configid.txt").read_text() == "absent\n"
    assert (out / "lockdown.txt").read_text() == "absent\n"
    assert (out / "btf-sha.txt").read_text() == "absent\n"
    hooks = json.loads((out / "hooks.json").read_text())
    assert hooks["btf"] is False


def test_record_guest_identity_truncated_config_unreadable(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    (tmp_path / "config.gz").write_bytes(b"\x1f\x8b\x08\x00")
    out = tmp_path / "out"
    out.mkdir()
    scguest.record_guest_identity(str(out))
    assert (out / "configid.txt").read_text() == \
        "unreadable\n"


def _patch_fail_paths(monkeypatch, tmp_path, out):
    monkeypatch.setattr(scguest, "_OUT", str(out))
    monkeypatch.setattr(scguest, "_EXPORT",
                        str(tmp_path / "no-export"))


def test_record_guest_identity_missing_modules_fails(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    monkeypatch.setattr(scguest, "MODULES_ROOT",
                        str(tmp_path / "no-modules"))
    out = tmp_path / "out"
    out.mkdir()
    _patch_fail_paths(monkeypatch, tmp_path, out)
    with pytest.raises(SystemExit):
        scguest.record_guest_identity(str(out))


def test_record_guest_identity_unreadable_version_fails(
        monkeypatch, tmp_path):
    _patch_identity(monkeypatch, tmp_path)
    monkeypatch.setattr(scguest, "VERSION_PATH",
                        str(tmp_path / "no-version"))
    out = tmp_path / "out"
    out.mkdir()
    _patch_fail_paths(monkeypatch, tmp_path, out)
    with pytest.raises(SystemExit):
        scguest.record_guest_identity(str(out))
