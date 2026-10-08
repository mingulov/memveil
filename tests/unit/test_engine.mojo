# SPDX-License-Identifier: GPL-3.0-or-later

"""Composed analyzer tests: attempts plus lifecycle plus pools.

The engine feeds one event stream to every tracker and merges
their rows into one report. Attempts-only captures keep exactly
their old rows; lifecycle and pool rows appear only with
observed evidence. Snapshot shares the finish reducers with no
destructive finalization, and the merged row set never exceeds
the 4096-row external budget.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.engine import (
    Analyzer,
    truncate_note,
    truncate_rows,
)
from memveil.model.event import Event
from memveil.model.metric import Metric
from memveil.model.session import Session


def _session() -> Session:
    var s = Session()
    s.session_id = String("eng")
    s.synthetic = True
    s.product_version = String("0.0.0")
    s.env_mode = String("unknown")
    s.env_detection = String("unverified")
    s.env_attestation = String("not_performed")
    s.capture_mode = String("replay")
    s.window_start_ns = UInt64(0)
    s.window_end_ns = UInt64(2300000000)
    s.finalized = True
    s.q_detail.status = String("complete_for_scope")
    s.q_detail.has_loss_count = True
    s.q_detail.loss_count = UInt64(0)
    s.q_detail.scope = String("sc")
    s.q_detail.reason = String("rs")
    s.q_aggregate.status = String("complete_for_scope")
    s.q_aggregate.has_loss_count = True
    s.q_aggregate.loss_count = UInt64(0)
    s.q_aggregate.scope = String("sc")
    s.q_aggregate.reason = String("rs")
    s.q_correlation.status = String("complete_for_scope")
    s.q_correlation.has_loss_count = True
    s.q_correlation.loss_count = UInt64(0)
    s.q_correlation.scope = String("sc")
    s.q_correlation.reason = String("rs")
    s.q_baseline.status = String("not_applicable")
    s.q_baseline.scope = String("sc")
    s.q_baseline.reason = String("rs")
    s.q_terminal.status = String("complete_for_scope")
    s.q_terminal.scope = String("sc")
    s.q_terminal.reason = String("rs")
    return s^


def _base(kind: String, seq: UInt64, ts: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("eng")
    ev.seq = seq
    ev.ts_ns = ts
    ev.kind = kind
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def _attempt(op: String, seq: UInt64) -> Event:
    var ev = _base("bounce_attempt", seq, UInt64(500))
    ev.bounce.device_id = String("d1")
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _map(op: String, mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _base("map_result", seq, ts)
    ev.map_result.operation_id = op
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = mapping
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    return ev^


def _copy(op: String, n: UInt64, seq: UInt64) -> Event:
    var ev = _base("copy", seq, UInt64(600) + seq)
    ev.copy.operation_id = op
    ev.copy.direction = String("original_to_bounce")
    ev.copy.bytes = n
    return ev^


def _unmap(mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _base("unmap", seq, ts)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _pool(pool: String, used: UInt64, cap: UInt64, seq: UInt64) -> Event:
    var ev = _base("pool_sample", seq, UInt64(700) + seq)
    ev.pool.pool_id = pool
    ev.pool.has_used = True
    ev.pool.used_bytes = used
    ev.pool.has_capacity = True
    ev.pool.capacity_bytes = cap
    ev.pool.unit = String("bytes")
    return ev^


def _region_session() -> Session:
    var s = _session()
    s.cap_conversion_results.status = String("verified")
    s.cap_conversion_results.reason = String("test")
    s.cap_region_state.status = String("verified")
    s.cap_region_state.reason = String("test")
    s.baseline_complete = True
    return s^


def _transition(
    region: String, state: String, seq: UInt64
) -> Event:
    var ev = _base("transition_result", seq, UInt64(800) + seq)
    ev.transition.region_id = region
    ev.transition.requested_state = state
    ev.transition.success = True
    ev.transition.has_return_code = True
    ev.transition.return_code = Int64(0)
    ev.transition.offset = UInt64(0)
    ev.transition.length = UInt64(8192)
    ev.transition.has_address_space = True
    ev.transition.address_space = String("guest_physical")
    ev.transition.has_resolution = True
    ev.transition.resolution = String("resolved")
    return ev^


def _gap(channel: String, seq: UInt64) -> Event:
    var ev = _base("gap", seq, UInt64(900))
    ev.gap.channel = channel
    ev.gap.has_lost_count = True
    ev.gap.lost_count = UInt64(2)
    ev.gap.reason = String("test gap")
    ev.gap.window_start_ns = UInt64(0)
    ev.gap.window_end_ns = UInt64(900)
    return ev^


def _count(rows: List[Metric], name: String) -> Int:
    var n = 0
    for i in range(len(rows)):
        if rows[i].name == name:
            n += 1
    return n


def _names(rows: List[Metric], want: String) -> Bool:
    for i in range(len(rows)):
        if rows[i].name == want:
            return True
    return False


def _find(rows: List[Metric], name: String) raises -> Metric:
    for i in range(len(rows)):
        var m = rows[i]
        if m.name == name and not m.has_device_id and not m.has_pool_id:
            return m
    raise Error("metric not found: " + name)


def _find_pool(
    rows: List[Metric], name: String, pool: String
) raises -> Metric:
    for i in range(len(rows)):
        var m = rows[i]
        if m.name == name and m.has_pool_id and m.pool_id == pool:
            return m
    raise Error("pool metric not found: " + name)


def _feed_nested(mut a: Analyzer) raises:
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_copy("op1", UInt64(4096), UInt64(2)))
    a.consume(_map("op1", "m1", UInt64(1300000000), UInt64(3)))
    a.consume(_unmap("m1", UInt64(2300000000), UInt64(4)))


def test_merged_rows() raises:
    var a = Analyzer(_session())
    _feed_nested(a)
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(_find(rep.metrics, "bounce_attempts").value, UInt64(1))
    assert_equal(
        _find(rep.metrics, "successful_allocations").value, UInt64(1)
    )
    assert_equal(
        _find(rep.metrics, "copy_original_to_bounce_bytes").value,
        UInt64(4096),
    )
    assert_equal(_find(rep.metrics, "live_observed_allocation_bytes").value, UInt64(0))
    # No pool source: pool placeholders stay unavailable.
    var pool = _find(rep.metrics, "pool_used_bytes")
    assert_true(not pool.has_value)


def test_pool_rows_gated() raises:
    var a = Analyzer(_session())
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(2)))
    var rep = a.finish(UInt64(2300000000), False)
    assert_true(_names(rep.metrics, "pool_used_bytes"))
    # No lifecycle source: the attempts placeholders stay null
    # and no tracker rows appear.
    var alloc = _find(rep.metrics, "successful_allocations")
    assert_true(not alloc.has_value)
    var cp = _find(rep.metrics, "copy_original_to_bounce_bytes")
    assert_true(not cp.has_value)


def test_attempts_only_unchanged() raises:
    var a = Analyzer(_session())
    a.consume(_attempt("op1", UInt64(1)))
    var rep = a.finish(UInt64(2300000000), False)
    # Placeholders stay unavailable; no valued tracker rows appear.
    var alloc = _find(rep.metrics, "successful_allocations")
    assert_true(not alloc.has_value)
    var pool = _find(rep.metrics, "pool_used_bytes")
    assert_true(not pool.has_value)
    var cp = _find(rep.metrics, "copy_original_to_bounce_bytes")
    assert_true(not cp.has_value)
    var live = _find(rep.metrics, "live_observed_allocation_bytes")
    assert_true(not live.has_value)
    var found = False
    for i in range(len(rep.limitations)):
        if rep.limitations[i].find("reduces bounce attempts") != -1:
            found = True
    assert_true(found)


def test_snapshot_finish_equivalence() raises:
    var a = Analyzer(_session())
    _feed_nested(a)
    var snap = a.snapshot(UInt64(2300000000), False)
    var fin = a.finish(UInt64(2300000000), False)
    assert_equal(len(snap.metrics), len(fin.metrics))
    for i in range(len(snap.metrics)):
        assert_equal(snap.metrics[i].name, fin.metrics[i].name)
        assert_equal(snap.metrics[i].has_value, fin.metrics[i].has_value)
        if snap.metrics[i].has_value:
            assert_equal(snap.metrics[i].value, fin.metrics[i].value)


def test_snapshot_narrowed_ok_finish_strict() raises:
    var a = Analyzer(_session())
    a.consume(_attempt("op1", UInt64(1)))
    var snap = a.snapshot(UInt64(1000000000), False)
    assert_equal(snap.window_end_ns, UInt64(1000000000))
    var raised = False
    try:
        _ = a.finish(UInt64(1000000000), False)
    except:
        raised = True
    assert_true(raised)


def test_unpaired_degrades_correlation() raises:
    var a = Analyzer(_session())
    var ev = _map("op1", "m1", UInt64(100), UInt64(1))
    ev.source_correlation = String("unpaired")
    a.consume(ev^)
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(rep.q_correlation.status, String("partial"))


def test_unpaired_events_emit_metric() raises:
    var a = Analyzer(_session())
    var ev = _map("op1", "m1", UInt64(100), UInt64(1))
    ev.source_correlation = String("unpaired")
    a.consume(ev^)
    var rep = a.finish(UInt64(2300000000), False)
    var row = _find(rep.metrics, "unpaired_lifecycle_events")
    assert_true(row.has_value)
    assert_equal(row.value, UInt64(1))
    assert_equal(row.unit, String("count"))


def test_paired_events_emit_no_unpaired_metric() raises:
    var a = Analyzer(_session())
    _feed_nested(a)
    var rep = a.finish(UInt64(2300000000), False)
    assert_true(not _names(rep.metrics, "unpaired_lifecycle_events"))


def test_region_rows_merged() raises:
    var a = Analyzer(_region_session())
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_transition("r1", "shared", UInt64(2)))
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(
        _find(rep.metrics, "conversion_requests").value, UInt64(1)
    )
    assert_equal(
        _find(rep.metrics, "known_shared_region_bytes").value,
        UInt64(8192),
    )
    assert_equal(
        _count(rep.metrics, "conversion_request_bytes"), 1
    )
    assert_equal(
        _count(rep.metrics, "known_shared_region_bytes"), 1
    )
    var snap = a.snapshot(UInt64(2300000000), False)
    assert_equal(
        _find(snap.metrics, "known_shared_region_bytes").value,
        UInt64(8192),
    )


def test_region_rows_absent_without_source() raises:
    var a = Analyzer(_session())
    a.consume(_attempt("op1", UInt64(1)))
    var rep = a.finish(UInt64(2300000000), False)
    var conv = _find(rep.metrics, "conversion_request_bytes")
    assert_true(not conv.has_value)
    var shared = _find(rep.metrics, "known_shared_region_bytes")
    assert_true(not shared.has_value)


def test_partial_tail_downgrades_stateful_metrics() raises:
    var a = Analyzer(_region_session())
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_map("op1", "m1", UInt64(1300000000), UInt64(2)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(3)))
    a.consume(_transition("r1", "shared", UInt64(4)))
    var rep = a.finish(UInt64(2300000000), True)
    # A partial tail may hide a release, so the live mapping gauge
    # is withheld (null/unavailable), not a degraded number: unknown
    # is not zero. Cumulative counters keep values with partial
    # coverage. Latest observed pool samples keep their values;
    # region current state is withheld because a transition may be missing.
    var live = _find(rep.metrics, "live_observed_allocation_bytes")
    assert_true(not live.has_value)
    assert_equal(live.coverage, String("unavailable"))
    assert_equal(
        _find(rep.metrics, "successful_allocations").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rep.metrics, "successful_allocations").confidence,
        String("high"),
    )
    assert_equal(
        _find_pool(rep.metrics, "pool_used_bytes", "p1").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rep.metrics, "known_shared_region_bytes").coverage,
        String("unavailable"),
    )


def test_detail_gap_downgrades_pool_and_region() raises:
    var a = Analyzer(_region_session())
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(2)))
    a.consume(_transition("r1", "shared", UInt64(3)))
    a.consume(_gap("detail", UInt64(4)))
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(
        _find_pool(rep.metrics, "pool_used_bytes", "p1").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rep.metrics, "conversion_requests").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rep.metrics, "known_shared_region_bytes").coverage,
        String("unavailable"),
    )


def test_baseline_gap_downgrades_region_unions_only() raises:
    var a = Analyzer(_region_session())
    a.consume(_attempt("op1", UInt64(1)))
    a.consume(_transition("r1", "shared", UInt64(2)))
    a.consume(_gap("baseline", UInt64(3)))
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(
        _find(rep.metrics, "known_shared_region_bytes").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rep.metrics, "conversion_requests").coverage,
        String("complete_for_scope"),
    )


def test_post_gap_pool_run_survives_snapshots() raises:
    var a = Analyzer(_session())
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(1)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(2)))
    a.consume(_gap("detail", UInt64(3)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(4)))
    var before = a.snapshot(UInt64(2300000000), False)
    assert_equal(_find_pool(before.metrics, "pool_pressure_samples", "p1").value, UInt64(1))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(5)))
    a.consume(_pool("p1", UInt64(900), UInt64(1000), UInt64(6)))
    var after = a.finish(UInt64(2300000000), False)
    assert_equal(_find_pool(after.metrics, "pool_pressure_samples", "p1").value, UInt64(3))


def test_sustained_churn_stable() raises:
    var a = Analyzer(_session())
    var seq = UInt64(1)
    for i in range(300):
        var op = String("op") + String(i)
        var mapping = String("m") + String(i)
        a.consume(_attempt(op, seq))
        seq += 1
        a.consume(
            _map(op, mapping, UInt64(1000) + UInt64(i), seq)
        )
        seq += 1
        a.consume(
            _unmap(mapping, UInt64(2000) + UInt64(i), seq)
        )
        seq += 1
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(
        _find(rep.metrics, "successful_allocations").value,
        UInt64(300),
    )
    assert_equal(
        _find(rep.metrics, "completed_lifetime_count").value,
        UInt64(300),
    )
    assert_equal(
        _find(rep.metrics, "live_observed_allocation_bytes").value,
        UInt64(0),
    )
    assert_equal(
        _find(rep.metrics, "open_mappings").value, UInt64(0)
    )
    assert_equal(
        _find(rep.metrics, "completed_lifetime_count").coverage,
        String("complete_for_scope"),
    )


def test_limitations_capped_at_schema_budget() raises:
    var a = Analyzer(_session())
    a.consume(_attempt("op1", UInt64(1)))
    for i in range(300):
        var pool = String("p") + String(i)
        var ev = _base(
            "pool_sample", UInt64(10) + UInt64(i), UInt64(700)
        )
        ev.pool.pool_id = pool
        ev.pool.has_used = True
        ev.pool.used_bytes = UInt64(1)
        ev.pool.has_capacity = True
        ev.pool.capacity_bytes = UInt64(100)
        ev.pool.unit = String("slots")
        a.consume(ev^)
    var rep = a.finish(UInt64(2300000000), False)
    assert_equal(len(rep.limitations), 256)
    var last = rep.limitations[len(rep.limitations) - 1]
    assert_true(last.find("withheld") != -1)
    for i in range(len(rep.limitations)):
        assert_true(rep.limitations[i].count_codepoints() <= 1024)
        assert_true(len(rep.limitations[i].as_bytes()) > 0)


def test_truncate_note() raises:
    var short = truncate_note(String("fine"))
    assert_equal(short, String("fine"))
    var long = String("")
    for _ in range(1100):
        long += "x"
    var cut = truncate_note(long)
    assert_equal(cut.count_codepoints(), 1024)
    var wide = String("")
    for _ in range(1100):
        wide += "é"
    var cut_wide = truncate_note(wide)
    assert_equal(cut_wide.count_codepoints(), 1024)


def test_truncate_rows() raises:
    var rows = List[Metric]()
    for i in range(5):
        var m = Metric()
        m.name = String("m") + String(i)
        m.has_value = True
        m.value = UInt64(i)
        rows.append(m^)
    var kept = truncate_rows(rows, 3)
    assert_equal(len(kept.rows), 3)
    assert_equal(kept.withheld, 2)
    assert_equal(kept.rows[0].name, String("m0"))
    var all = truncate_rows(rows, 5)
    assert_equal(len(all.rows), 5)
    assert_equal(all.withheld, 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_merged_rows]()
    suite.test[test_pool_rows_gated]()
    suite.test[test_attempts_only_unchanged]()
    suite.test[test_snapshot_finish_equivalence]()
    suite.test[test_snapshot_narrowed_ok_finish_strict]()
    suite.test[test_unpaired_degrades_correlation]()
    suite.test[test_unpaired_events_emit_metric]()
    suite.test[test_paired_events_emit_no_unpaired_metric]()
    suite.test[test_region_rows_merged]()
    suite.test[test_region_rows_absent_without_source]()
    suite.test[test_partial_tail_downgrades_stateful_metrics]()
    suite.test[test_detail_gap_downgrades_pool_and_region]()
    suite.test[test_baseline_gap_downgrades_region_unions_only]()
    suite.test[test_post_gap_pool_run_survives_snapshots]()
    suite.test[test_sustained_churn_stable]()
    suite.test[test_limitations_capped_at_schema_budget]()
    suite.test[test_truncate_note]()
    suite.test[test_truncate_rows]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
