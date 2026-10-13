# SPDX-License-Identifier: GPL-3.0-or-later

"""Capacity unit tests: N/N+1 for every bounded store.

Each registry refuses past its budget with an explicit quality
change and a visible limitation note; nothing is silently
evicted and no refusal corrupts unrelated state. Small
parametric instances prove the refusal logic, and
production-ceiling cases prove the exact contract numbers
(pending 65536, active 65536, devices 4096, report rows 4096).
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.diagnostics import (
    DiagnosisEngine,
    DiagnosticPolicy,
)
from memveil.analysis.engine import (
    MAX_REPORT_METRICS,
    budget_rows,
    finalize_limitations,
    truncate_rows,
)
from memveil.analysis.mappings import MappingTracker
from memveil.analysis.pools import PoolTracker
from memveil.capture.correlation import CorrelationRegistry
from memveil.model.event import Event
from memveil.model.identity import (
    ACTIVE_MAX,
    DEVICE_MAX_ID,
    PENDING_MAX,
)
from memveil.model.metric import Metric
from memveil.model.report import Report


def _base(kind: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(1000) + seq
    ev.kind = kind
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def _attempt(op: String, device: String, seq: UInt64) -> Event:
    var ev = _base("bounce_attempt", seq)
    ev.bounce.device_id = device
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _map(op: String, mapping: String, seq: UInt64) -> Event:
    var ev = _base("map_result", seq)
    ev.map_result.operation_id = op
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = mapping
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    return ev^


def _unmap(mapping: String, seq: UInt64) -> Event:
    var ev = _base("unmap", seq)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _pool(pool: String, seq: UInt64) -> Event:
    var ev = _base("pool_sample", seq)
    ev.pool.pool_id = pool
    ev.pool.has_used = True
    ev.pool.used_bytes = UInt64(900)
    ev.pool.has_capacity = True
    ev.pool.capacity_bytes = UInt64(1000)
    ev.pool.unit = String("bytes")
    return ev^


def _report() -> Report:
    var r = Report()
    r.session_id = String("d1")
    r.synthetic = True
    r.window_start_ns = UInt64(0)
    r.window_end_ns = UInt64(1000)
    r.q_detail.status = String("unavailable")
    r.q_detail.scope = String("sc")
    r.q_detail.reason = String("tracepoint missing")
    r.q_detail.evidence_refs.append(String("hook:swiotlb_bounced"))
    r.q_aggregate.status = String("partial")
    r.q_aggregate.scope = String("sc")
    r.q_aggregate.reason = String("detail loss")
    r.q_correlation.status = String("partial")
    r.q_correlation.scope = String("sc")
    r.q_correlation.reason = String("unpaired")
    r.q_baseline.status = String("not_applicable")
    r.q_baseline.scope = String("sc")
    r.q_baseline.reason = String("rs")
    r.q_terminal.status = String("partial")
    r.q_terminal.scope = String("sc")
    r.q_terminal.reason = String("stop partial")
    return r^


def test_pending_ceiling() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    for i in range(PENDING_MAX):
        var out = reg.normalize(
            _attempt("op" + String(i), "d1", UInt64(i + 1)), "ring"
        )
        assert_true(out.source_correlation == "direct")
    var over = reg.normalize(
        _attempt("op-over", "d1", UInt64(PENDING_MAX + 1)), "ring"
    )
    assert_true(over.source_correlation == "unpaired")
    assert_equal(reg.health().status, String("partial"))


def test_active_ceiling_at_production_bound() raises:
    var reg = CorrelationRegistry[131072, 65536, 8, 16384, 4096]()
    reg.admit_hook("h", "iova")
    for i in range(ACTIVE_MAX):
        _ = reg.normalize(
            _attempt("a" + String(i), "d1", UInt64(2 * i + 1)), "ring"
        )
        var ok = reg.normalize(
            _map("a" + String(i), "m" + String(i), UInt64(2 * i + 2)),
            "ring",
        )
        assert_true(ok.source_correlation == "direct")
    assert_equal(reg.active_count(), ACTIVE_MAX)
    _ = reg.normalize(
        _attempt("a-over", "d1", UInt64(2 * ACTIVE_MAX + 1)), "ring"
    )
    var over = reg.normalize(
        _map("a-over", "m-over", UInt64(2 * ACTIVE_MAX + 2)), "ring"
    )
    assert_true(over.source_correlation == "unpaired")
    assert_equal(reg.active_count(), ACTIVE_MAX)


def test_device_ceiling() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    for i in range(DEVICE_MAX_ID):
        var out = reg.normalize(
            _attempt("dop" + String(i), "dev" + String(i), UInt64(i + 1)),
            "ring",
        )
        assert_true(out.source_correlation == "direct")
    var over = reg.normalize(
        _attempt("dop-over", "dev-over", UInt64(DEVICE_MAX_ID + 1)),
        "ring",
    )
    assert_true(over.source_correlation == "unpaired")


def test_retired_churn_stays_bounded() raises:
    var reg = CorrelationRegistry[65536, 4, 8, 4, 4096]()
    reg.admit_hook("h", "iova")
    for i in range(20):
        _ = reg.normalize(
            _attempt("cop" + String(i), "d1", UInt64(3 * i + 1)), "ring"
        )
        _ = reg.normalize(
            _map("cop" + String(i), "cm" + String(i), UInt64(3 * i + 2)),
            "ring",
        )
        var rel = reg.normalize(
            _unmap("cm" + String(i), UInt64(3 * i + 3)), "ring"
        )
        assert_true(rel.source_correlation == "direct")
    assert_equal(reg.active_count(), 0)
    # The first tombstone cycled out of the 4-ring: repeating
    # its release stays unpaired instead of borrowing certainty
    # from forgotten evidence.
    var again = reg.normalize(_unmap("cm0", UInt64(61)), "ring")
    assert_true(again.source_correlation == "unpaired")


def test_mapping_tracker_op_refusal_visible() raises:
    var t = MappingTracker[16, 2, 4096]()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_attempt("op2", "d1", UInt64(2)))
    t.consume(_attempt("op3", "d1", UInt64(3)))
    var notes = t.limitations()
    assert_true(len(notes) > 0)
    # The refusal degrades nothing else: rows still render.
    var rows = t.metrics("window [0,1000)")
    assert_true(len(rows) > 0)


def test_mapping_tracker_active_refusal_withholds_live() raises:
    var t = MappingTracker[1, 16, 4096]()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", "m1", UInt64(2)))
    t.consume(_attempt("op2", "d1", UInt64(3)))
    t.consume(_map("op2", "m2", UInt64(4)))
    var notes = t.limitations()
    assert_true(len(notes) > 0)
    var rows = t.metrics("window [0,1000)")
    var found = False
    for i in range(len(rows)):
        if rows[i].name == "live_observed_allocation_bytes":
            found = True
            assert_true(not rows[i].has_value)
    assert_true(found)


def test_pool_table_refusal_visible() raises:
    var t = PoolTracker[2]()
    t.consume(_pool("p1", UInt64(1)))
    t.consume(_pool("p2", UInt64(2)))
    t.consume(_pool("p3", UInt64(3)))
    var notes = t.limitations()
    assert_true(len(notes) > 0)
    assert_true(t.sees_pools())


def test_report_row_truncation_exact() raises:
    assert_equal(MAX_REPORT_METRICS, 4096)
    var rows = List[Metric]()
    for i in range(4097):
        var m = Metric()
        m.name = String("m" + String(i))
        rows.append(m)
    var cut = truncate_rows(rows, MAX_REPORT_METRICS)
    assert_equal(len(cut.rows), 4096)
    assert_equal(cut.withheld, 1)
    assert_equal(cut.rows[0].name, String("m0"))
    var exact = truncate_rows(cut.rows, MAX_REPORT_METRICS)
    assert_equal(len(exact.rows), 4096)
    assert_equal(exact.withheld, 0)


def test_findings_bounded() raises:
    var eng = DiagnosisEngine()
    var out = eng.evaluate(_report(), DiagnosticPolicy())
    assert_true(len(out) <= 8)


def _row(name: String, device: String, pool: String) -> Metric:
    var m = Metric()
    m.name = name
    m.has_value = True
    m.value = UInt64(1)
    if device != "":
        m.has_device_id = True
        m.device_id = device
    if pool != "":
        m.has_pool_id = True
        m.pool_id = pool
    return m^


def _names(rows: List[Metric]) -> List[String]:
    var out = List[String]()
    for i in range(len(rows)):
        out.append(rows[i].name)
    return out^


def test_budget_keeps_mandatory_first() raises:
    # Device detail floods the budget; global and per-pool
    # evidence rows still win it in merge order.
    var rows = List[Metric]()
    for i in range(10):
        rows.append(_row(String("dev") + String(i), String("d"), String("")))
    rows.append(_row(String("global-a"), String(""), String("")))
    rows.append(_row(String("pool-p"), String(""), String("p1")))
    rows.append(_row(String("global-b"), String(""), String("")))
    var cut = budget_rows(rows, 5)
    assert_equal(len(cut.rows), 5)
    assert_equal(cut.withheld, 8)
    var names = _names(cut.rows)
    assert_equal(names[0], String("global-a"))
    assert_equal(names[1], String("pool-p"))
    assert_equal(names[2], String("global-b"))
    assert_equal(names[3], String("dev0"))
    assert_equal(names[4], String("dev1"))


def test_budget_under_budget_keeps_order() raises:
    var rows = List[Metric]()
    rows.append(_row(String("dev0"), String("d0"), String("")))
    rows.append(_row(String("global"), String(""), String("")))
    rows.append(_row(String("dev1"), String("d1"), String("")))
    var cut = budget_rows(rows, 4096)
    assert_equal(len(cut.rows), 3)
    assert_equal(cut.withheld, 0)
    var names = _names(cut.rows)
    assert_equal(names[0], String("dev0"))
    assert_equal(names[1], String("global"))
    assert_equal(names[2], String("dev1"))


def test_budget_degenerate_mandatory_overflow() raises:
    # Mandatory rows alone exceed the budget: the first
    # budget mandatory rows win in merge order.
    var rows = List[Metric]()
    for i in range(6):
        rows.append(_row(String("g") + String(i), String(""), String("")))
    var cut = budget_rows(rows, 4)
    assert_equal(len(cut.rows), 4)
    assert_equal(cut.withheld, 2)
    assert_equal(cut.rows[0].name, String("g0"))
    assert_equal(cut.rows[3].name, String("g3"))


def test_budget_boundaries() raises:
    var none = List[Metric]()
    var empty = budget_rows(none, 5)
    assert_equal(len(empty.rows), 0)
    assert_equal(empty.withheld, 0)
    var rows = List[Metric]()
    rows.append(_row(String("dev0"), String("d0"), String("")))
    rows.append(_row(String("global"), String(""), String("")))
    # Exact budget keeps merge order, never reorders.
    var exact = budget_rows(rows, 2)
    assert_equal(len(exact.rows), 2)
    assert_equal(exact.withheld, 0)
    assert_equal(exact.rows[0].name, String("dev0"))
    assert_equal(exact.rows[1].name, String("global"))
    var zero = budget_rows(rows, 0)
    assert_equal(len(zero.rows), 0)
    assert_equal(zero.withheld, 2)
    var neg = budget_rows(rows, -3)
    assert_equal(len(neg.rows), 0)
    assert_equal(neg.withheld, 2)


def test_budget_all_device_keeps_prefix() raises:
    var rows = List[Metric]()
    for i in range(6):
        rows.append(
            _row(String("dev") + String(i), String("d"), String(""))
        )
    var cut = budget_rows(rows, 4)
    assert_equal(len(cut.rows), 4)
    assert_equal(cut.withheld, 2)
    assert_equal(cut.rows[0].name, String("dev0"))
    assert_equal(cut.rows[3].name, String("dev3"))


def _notes(n: Int) -> List[String]:
    var out = List[String]()
    for i in range(n):
        out.append(String("note") + String(i))
    return out^


def test_finalize_limitations_keeps_row_disclosure() raises:
    # Both ceilings at once: 300 tracker notes plus withheld
    # rows still disclose the row omission in the last slot.
    var capped = finalize_limitations(_notes(300), 17)
    assert_equal(len(capped), 256)
    assert_equal(capped[0], String("note0"))
    assert_equal(capped[253], String("note253"))
    assert_true(
        capped[254].find(String("further limitations withheld")) != -1
    )
    assert_equal(
        capped[255],
        String("17 metric rows withheld (4096-row report budget)."),
    )


def test_finalize_limitations_without_rows() raises:
    var same = finalize_limitations(_notes(10), 0)
    assert_equal(len(same), 10)
    assert_equal(same[9], String("note9"))
    var capped = finalize_limitations(_notes(300), 0)
    assert_equal(len(capped), 256)
    assert_equal(capped[254], String("note254"))
    assert_true(
        capped[255].find(String("further limitations withheld")) != -1
    )
    var edge = finalize_limitations(_notes(255), 5)
    assert_equal(len(edge), 256)
    assert_equal(edge[254], String("note254"))
    assert_equal(
        edge[255],
        String("5 metric rows withheld (4096-row report budget)."),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_pending_ceiling]()
    suite.test[test_active_ceiling_at_production_bound]()
    suite.test[test_device_ceiling]()
    suite.test[test_retired_churn_stays_bounded]()
    suite.test[test_mapping_tracker_op_refusal_visible]()
    suite.test[test_mapping_tracker_active_refusal_withholds_live]()
    suite.test[test_pool_table_refusal_visible]()
    suite.test[test_report_row_truncation_exact]()
    suite.test[test_budget_keeps_mandatory_first]()
    suite.test[test_budget_under_budget_keeps_order]()
    suite.test[test_budget_degenerate_mandatory_overflow]()
    suite.test[test_budget_boundaries]()
    suite.test[test_budget_all_device_keeps_prefix]()
    suite.test[test_finalize_limitations_keeps_row_disclosure]()
    suite.test[test_finalize_limitations_without_rows]()
    suite.test[test_findings_bounded]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
