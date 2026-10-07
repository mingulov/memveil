# SPDX-License-Identifier: GPL-3.0-or-later

"""Diagnosis engine tests: evidence-linked findings.

Findings reference the quality and metrics they explain and never
duplicate codes the report already carries. Pool pressure needs
three consecutive qualifying samples; the long-lived policy is
informational, disabled by default, and never a leak verdict.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.diagnostics import (
    DiagnosisEngine,
    DiagnosticPolicy,
)
from memveil.model.metric import Finding, Metric
from memveil.model.report import Report


def _report() -> Report:
    var r = Report()
    r.session_id = String("d1")
    r.synthetic = True
    r.window_start_ns = UInt64(0)
    r.window_end_ns = UInt64(1000)
    r.q_detail.status = String("complete_for_scope")
    r.q_detail.scope = String("sc")
    r.q_detail.reason = String("rs")
    r.q_aggregate.status = String("complete_for_scope")
    r.q_aggregate.scope = String("sc")
    r.q_aggregate.reason = String("rs")
    r.q_correlation.status = String("not_applicable")
    r.q_correlation.scope = String("sc")
    r.q_correlation.reason = String("rs")
    r.q_baseline.status = String("not_applicable")
    r.q_baseline.scope = String("sc")
    r.q_baseline.reason = String("rs")
    r.q_terminal.status = String("complete_for_scope")
    r.q_terminal.scope = String("sc")
    r.q_terminal.reason = String("rs")
    return r^


def _metric(name: String, value: UInt64, pool: String) -> Metric:
    var m = Metric()
    m.name = name
    m.has_value = True
    m.value = value
    m.unit = String("count")
    m.measurement = String("observed")
    m.coverage = String("complete_for_scope")
    if pool != "":
        m.has_pool_id = True
        m.pool_id = pool
    m.scope = String("window [0,1000)")
    return m^


def _codes(findings: List[Finding], code: String) -> Int:
    var n = 0
    for i in range(len(findings)):
        if findings[i].code == code:
            n += 1
    return n


def test_healthy_empty_scope() raises:
    var eng = DiagnosisEngine()
    var out = eng.evaluate(_report(), DiagnosticPolicy())
    assert_equal(len(out), 0)


def test_unavailable_probe() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.q_detail.status = String("unavailable")
    r.q_detail.reason = String("tracepoint missing")
    r.q_detail.evidence_refs.append(String("hook:swiotlb_bounced"))
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(len(out), 1)
    assert_equal(out[0].code, String("PROBE_UNAVAILABLE"))
    assert_equal(out[0].severity, String("warning"))
    assert_equal(len(out[0].evidence_refs), 1)


def test_unpaired_lifecycle() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.metrics.append(
        _metric(String("unpaired_lifecycle_events"), UInt64(2), String(""))
    )
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(len(out), 1)
    assert_equal(out[0].code, String("UNPAIRED_LIFECYCLE"))
    assert_equal(out[0].severity, String("warning"))


def test_correlation_loss_alone_yields_no_lifecycle_finding() raises:
    # Optional correlation loss without observed unpaired
    # lifecycle events must not invent a lifecycle finding: an
    # attempts-only capture with producer-claimed correlation
    # loss keeps its sufficient-evidence verdict.
    var eng = DiagnosisEngine()
    var r = _report()
    r.q_correlation.status = String("partial")
    r.q_correlation.has_loss_count = True
    r.q_correlation.loss_count = UInt64(2)
    r.q_correlation.reason = String("optional correlation loss")
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(_codes(out, String("UNPAIRED_LIFECYCLE")), 0)


def test_no_duplicate_codes() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.q_detail.status = String("unavailable")
    r.q_detail.reason = String("gone")
    var f = Finding()
    f.code = String("PROBE_UNAVAILABLE")
    f.severity = String("warning")
    f.explanation = String("already reported")
    f.scope = String("sc")
    r.findings.append(f^)
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(len(out), 0)


def test_long_lived_disabled_by_default() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.metrics.append(_metric("oldest_open_mapping_age_ns", UInt64(900), ""))
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(_codes(out, "LONG_LIVED_ALLOCATION"), 0)


def test_long_lived_threshold() raises:
    var eng = DiagnosisEngine()
    var p = DiagnosticPolicy()
    p.has_long_lived_after = True
    p.long_lived_after_ns = UInt64(500)
    var r = _report()
    r.metrics.append(_metric("oldest_open_mapping_age_ns", UInt64(900), ""))
    var out = eng.evaluate(r^, p)
    assert_equal(_codes(out, "LONG_LIVED_ALLOCATION"), 1)
    assert_equal(out[0].severity, String("informational"))
    var r2 = _report()
    r2.metrics.append(_metric("oldest_open_mapping_age_ns", UInt64(100), ""))
    var out2 = eng.evaluate(r2^, p)
    assert_equal(_codes(out2, "LONG_LIVED_ALLOCATION"), 0)


def test_pool_pressure() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.metrics.append(_metric("pool_pressure_samples", UInt64(3), "p1"))
    r.metrics.append(_metric("pool_pressure_samples", UInt64(2), "p2"))
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(_codes(out, "POOL_PRESSURE"), 1)
    assert_equal(out[0].severity, String("warning"))
    assert_true(out[0].scope.find("p1") != -1)


def test_conversion_failures() raises:
    var eng = DiagnosisEngine()
    var r = _report()
    r.metrics.append(_metric("conversion_failures", UInt64(1), ""))
    var out = eng.evaluate(r^, DiagnosticPolicy())
    assert_equal(_codes(out, "CONVERSION_FAILED"), 1)


def test_requested_scope_missing() raises:
    var eng = DiagnosisEngine()
    var p = DiagnosticPolicy()
    p.requested.append(String("lifecycle"))
    var out = eng.evaluate(_report(), p)
    assert_equal(_codes(out, "PROBE_UNAVAILABLE"), 1)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_healthy_empty_scope]()
    suite.test[test_unavailable_probe]()
    suite.test[test_unpaired_lifecycle]()
    suite.test[test_correlation_loss_alone_yields_no_lifecycle_finding]()
    suite.test[test_no_duplicate_codes]()
    suite.test[test_long_lived_disabled_by_default]()
    suite.test[test_long_lived_threshold]()
    suite.test[test_pool_pressure]()
    suite.test[test_conversion_failures]()
    suite.test[test_requested_scope_missing]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
