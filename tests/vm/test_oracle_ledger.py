#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle ledger tests: guest-free comparison checks.

The ledger is written only against raw driver calls and the
comparison only against finished JSON reports, so every case
below runs without a guest. Guest runs reuse the same compare()
entry point over module-collected ledgers.
"""

import json
import os
import subprocess
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import replay_oracle_witness_ledger
from oracle_ledger import OracleLedger, bucket_of, compare

REPO = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(REPO, "build", "memveil")


def _report_for(fixture):
    if not os.path.isfile(BIN):
        pytest.skip("missing build/memveil (run tools/build first)")
    out = subprocess.run(
        [BIN, "report", "--format", "json",
         os.path.join(REPO, "tests", "fixtures", fixture)],
        capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


def _nested_ledger():
    ledger = OracleLedger()
    ledger.record_attempt("op-1", "dev-1", 4096, True)
    ledger.record_copy("op-1", "original_to_bounce", 4096)
    ledger.record_outcome("op-1", True, mapping="map-1",
                          mapped_bytes=4096)
    ledger.record_copy("op-1", "original_to_bounce", 1024,
                       mapping="map-1")
    ledger.record_release("map-1", duration_ns=1000000000)
    ledger.seal()
    return ledger


def test_nested_matches_report():
    assert compare(_report_for("lifecycle/lifecycle-nested"),
                   _nested_ledger()) == []


def test_copy_before_failure_matches():
    report = _report_for("lifecycle/copy-before-failure")
    ledger = OracleLedger()
    ledger.record_attempt("op-1", "dev-1", 4096, True)
    ledger.record_copy("op-1", "original_to_bounce", 4096)
    ledger.record_outcome("op-1", False, return_code=-12)
    ledger.seal()
    assert compare(report, ledger) == []


def test_tampered_copy_detected():
    report = _report_for("lifecycle/lifecycle-nested")
    for metric in report["metrics"]:
        if (metric["name"] == "copy_original_to_bounce_bytes"
                and metric["dimensions"]["device_id"] is None):
            metric["value"] = str(int(metric["value"]) + 1)
    bad = compare(report, _nested_ledger())
    assert len(bad) == 1
    assert "copy_original_to_bounce_bytes" in bad[0]


def test_wrong_lifetime_detected():
    report = _report_for("lifecycle/lifecycle-nested")
    for metric in report["metrics"]:
        if metric["name"] == "lifetime_mean_ns":
            metric["value"] = "999999999"
    bad = compare(report, _nested_ledger())
    assert any("lifetime_mean_ns" in item for item in bad)


def test_quantile_edges_exact():
    # Durations [1,2,3,4]: p50 edge 3, p99 edge 7.
    assert bucket_of(2) == 2
    report = _report_for("lifecycle/lifecycle-nested")
    got = {m["name"]: m["value"] for m in report["metrics"]
           if m["dimensions"]["device_id"] is None
           and m["dimensions"]["pool_id"] is None}
    assert got["lifetime_p50_ns"] == "1073741823"
    assert got["lifetime_p99_ns"] == "1073741823"


def test_pool_pressure_matches():
    report = _report_for("pools/pressure")
    ledger = OracleLedger()
    ledger.record_attempt("op-1", "dev-1", 512, False)
    for _ in range(3):
        ledger.record_pool("pool-0", 900, 1000, "bytes")
    ledger.seal()
    assert compare(report, ledger) == []


def test_missing_pressure_detected():
    report = _report_for("pools/pressure")
    report["findings"] = []
    for metric in report["metrics"]:
        if metric["name"] == "pool_pressure_samples":
            metric["value"] = "1"
    ledger = OracleLedger()
    for _ in range(3):
        ledger.record_pool("pool-0", 900, 1000, "bytes")
    ledger.seal()
    bad = compare(report, ledger)
    assert any("pressured" in item for item in bad)
    assert any("POOL_PRESSURE" in item for item in bad)


def test_sealed_ledger_rejects_appends():
    ledger = OracleLedger()
    ledger.seal()
    with pytest.raises(ValueError):
        ledger.record_attempt("op", "dev", 1, False)


def test_compare_files_roundtrip():
    report = _report_for("lifecycle/lifecycle-nested")
    ledger = _nested_ledger()
    with tempfile.TemporaryDirectory() as tmp:
        report_path = os.path.join(tmp, "report.json")
        ledger_path = os.path.join(tmp, "ledger.json")
        with open(report_path, "w") as handle:
            json.dump(report, handle)
        with open(ledger_path, "w") as handle:
            json.dump({"entries": [
                dict(kind=e["kind"],
                     **{k: v for k, v in e.items() if k != "kind"})
                for e in ledger.entries]}, handle)
        from oracle_ledger import compare_files
        assert compare_files(report_path, ledger_path) == []


def _failed_entry():
    return {
        "requested": 2048,
        "forced": False,
        "success": False,
        "rc": -5,
        "inner": {"health": "healthy", "retry": "success",
                  "rc": None},
        "witness": [{"mapping": 2, "copy": "inner-map",
                     "copied": 2048, "verified": 2048}],
    }


def _kinds(ledger, kind, key, value):
    return [e for e in ledger.entries
            if e["kind"] == kind and e.get(key) == value]


def test_failed_op_keeps_retry_identity_separate():
    ledger = replay_oracle_witness_ledger({2: _failed_entry()},
                                          {})
    assert _kinds(ledger, "outcome", "op", 2)[0]["success"] is False
    assert _kinds(ledger, "allocation", "op", 2) == []
    assert _kinds(ledger, "release", "mapping", 2) == []
    assert _kinds(ledger, "copy", "op", 2) == []
    inner = _kinds(ledger, "allocation", "op", "2:inner")
    assert len(inner) == 1 and inner[0]["mapped_bytes"] == 2048
    copies = _kinds(ledger, "copy", "op", "2:inner")
    assert len(copies) == 1 and copies[0]["witnessed"] == 2048
    releases = _kinds(ledger, "release", "mapping", "2:inner")
    assert len(releases) == 1
    assert releases[0]["duration_ns"] is None
    assert ledger.expected_witnessed_copies() == {
        "original_to_bounce": 2048, "bounce_to_original": 0}


def test_failed_op_rejects_misplaced_witness():
    entry = _failed_entry()
    entry["witness"] = [{"mapping": 2, "copy": "map",
                         "copied": 2048, "verified": 2048}]
    with pytest.raises(ValueError):
        replay_oracle_witness_ledger({2: entry}, {})


def test_success_op_rejects_inner_map_witness():
    entry = {"requested": 512, "forced": False, "success": True,
             "mapped": 512,
             "witness": [{"mapping": 0, "copy": "map",
                          "copied": 512, "verified": 512},
                         {"mapping": 0, "copy": "inner-map",
                          "copied": 512, "verified": 512}]}
    with pytest.raises(ValueError):
        replay_oracle_witness_ledger({0: entry}, {0: 10})
