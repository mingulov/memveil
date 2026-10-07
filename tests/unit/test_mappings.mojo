# SPDX-License-Identifier: GPL-3.0-or-later

"""Mapping tracker unit tests: copies, lifetimes, live bytes.

Independently authored expectations: allocations count successes
only, a sync request alone copies nothing, copies survive a later
outer failure, open mappings never become completed samples, and
any lost release or exhaustion invalidates live totals instead of
quietly lowering them.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.mappings import MappingTracker
from memveil.model.event import Event
from memveil.model.metric import Metric


def u64max() -> UInt64:
    return ~UInt64(0)


def _base(kind: String, seq: UInt64, ts: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = ts
    ev.kind = kind
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def _attempt(op: String, device: String, seq: UInt64) -> Event:
    var ev = _base("bounce_attempt", seq, UInt64(1000) + seq)
    ev.bounce.device_id = device
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _map(
    op: String, ok: Bool, mapping: String, mapped: UInt64,
    ts: UInt64, seq: UInt64,
) -> Event:
    var ev = _base("map_result", seq, ts)
    ev.map_result.operation_id = op
    ev.map_result.success = ok
    if mapping != "":
        ev.map_result.has_mapping_id = True
        ev.map_result.mapping_id = mapping
    if ok:
        ev.map_result.has_mapped_bytes = True
        ev.map_result.mapped_bytes = mapped
    else:
        ev.map_result.has_return_code = True
        ev.map_result.return_code = Int64(-12)
    return ev^


def _copy(
    op: String, mapping: String, direction: String, n: UInt64,
    seq: UInt64,
) -> Event:
    var ev = _base("copy", seq, UInt64(2000) + seq)
    ev.copy.operation_id = op
    if mapping != "":
        ev.copy.has_mapping_id = True
        ev.copy.mapping_id = mapping
    ev.copy.direction = direction
    ev.copy.bytes = n
    return ev^


def _sync(
    op: String, mapping: String, length: UInt64, seq: UInt64
) -> Event:
    var ev = _base("sync_request", seq, UInt64(3000) + seq)
    ev.sync.operation_id = op
    ev.sync.has_mapping_id = True
    ev.sync.mapping_id = mapping
    ev.sync.offset = UInt64(0)
    ev.sync.length = length
    return ev^


def _unmap(mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _base("unmap", seq, ts)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _gap(seq: UInt64) -> Event:
    var ev = _base("gap", seq, UInt64(4000) + seq)
    ev.gap.channel = String("detail")
    ev.gap.has_lost_count = True
    ev.gap.lost_count = UInt64(2)
    ev.gap.reason = String("test drop")
    return ev^


def _find(
    metrics: List[Metric], name: String, device: String
) raises -> Metric:
    for i in range(len(metrics)):
        var m = metrics[i]
        if m.name != name:
            continue
        if device == "" and not m.has_device_id:
            return m
        if device != "" and m.has_device_id and m.device_id == device:
            return m
    raise Error("metric not found: " + name)


def _global(metrics: List[Metric], name: String) raises -> Metric:
    return _find(metrics, name, "")


def test_lifecycle_nested() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_copy("op1", "", "original_to_bounce", UInt64(4096), UInt64(2)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(1300000000), UInt64(3)))
    t.consume(_sync("op1", "m1", UInt64(1024), UInt64(4)))
    t.consume(_copy("op1", "m1", "original_to_bounce", UInt64(1024), UInt64(5)))
    t.consume(_unmap("m1", UInt64(2300000000), UInt64(6)))
    var rows = t.metrics("window [0,2300000000)")
    assert_true(t.sees_lifecycle())
    assert_equal(_global(rows, "successful_allocations").value, UInt64(1))
    assert_equal(
        _global(rows, "copy_original_to_bounce_bytes").value,
        UInt64(5120),
    )
    assert_equal(_global(rows, "live_observed_allocation_bytes").value, UInt64(0))
    assert_equal(
        _global(rows, "completed_lifetime_count").value, UInt64(1)
    )
    var mean = _global(rows, "lifetime_mean_ns")
    assert_equal(mean.value, UInt64(1000000000))
    assert_true(mean.has_sample_count)
    assert_equal(mean.sample_count, UInt64(1))
    assert_equal(_global(rows, "sync_requests").value, UInt64(1))
    # 1e9 ns sits in [2^29, 2^30-1]: estimated edge 2^30-1.
    assert_equal(
        _global(rows, "lifetime_p50_ns").value, UInt64(1073741823)
    )
    assert_equal(
        _global(rows, "lifetime_p50_ns").measurement, String("estimated")
    )


def test_copy_before_failure() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_copy("op1", "", "original_to_bounce", UInt64(4096), UInt64(2)))
    t.consume(_map("op1", False, "", UInt64(0), UInt64(100), UInt64(3)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "successful_allocations").value, UInt64(0))
    assert_equal(_global(rows, "failed_allocations").value, UInt64(1))
    assert_equal(
        _global(rows, "copy_original_to_bounce_bytes").value,
        UInt64(4096),
    )
    assert_true(
        not _global(rows, "completed_lifetime_count").has_value
    )


def test_request_is_not_copy() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_sync("op1", "m1", UInt64(1024), UInt64(3)))
    t.consume(_unmap("m1", UInt64(200), UInt64(4)))
    var rows = t.metrics("window [0,1000)")
    # No copy events: the copy metric stays unavailable, and the
    # sync request is counted separately without adding bytes.
    var cp = _global(rows, "copy_original_to_bounce_bytes")
    assert_true(not cp.has_value)
    assert_equal(cp.measurement, String("unavailable"))
    assert_equal(_global(rows, "sync_requests").value, UInt64(1))


def test_orphan_release_invalidates_live() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_unmap("ghost", UInt64(200), UInt64(3)))
    var rows = t.metrics("window [0,1000)")
    var live = _global(rows, "live_observed_allocation_bytes")
    assert_true(not live.has_value)
    assert_equal(live.measurement, String("unavailable"))


def test_producer_loss_invalidates_live_keeps_aggregates() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    # Producer-reported detail loss may hide a release, exactly like
    # an observed gap: live state is withheld, aggregates keep their
    # values with partial coverage.
    t.note_detail_loss()
    var rows = t.metrics("window [0,1000)")
    var live = _global(rows, "live_observed_allocation_bytes")
    assert_true(not live.has_value)
    assert_equal(live.measurement, String("unavailable"))
    var opened = _global(rows, "open_mappings")
    assert_true(not opened.has_value)
    var allocs = _global(rows, "successful_allocations")
    assert_equal(allocs.value, UInt64(1))
    assert_equal(allocs.coverage, String("partial"))
    assert_equal(_global(rows, "mapped_bytes_total").value, UInt64(4096))


def test_peak_and_byte_time() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_attempt("op2", "d1", UInt64(2)))
    # m1: 4096 bytes over [100ms, 300ms); m2: 8192 bytes over
    # [200ms, horizon). Live bytes: 4096, then 12288, then 8192.
    t.consume(
        _map("op1", True, "m1", UInt64(4096), UInt64(100000000), UInt64(3))
    )
    t.consume(
        _map("op2", True, "m2", UInt64(8192), UInt64(200000000), UInt64(4))
    )
    t.consume(_unmap("m1", UInt64(300000000), UInt64(5)))
    var rows = t.metrics_horizon(
        "window [0,1000000000)", UInt64(1000000000)
    )
    assert_equal(
        _global(rows, "peak_live_observed_allocation_bytes").value,
        UInt64(12288),
    )
    # 4096*100ms + 12288*100ms + 8192*700ms, in byte-microseconds.
    assert_equal(
        _global(rows, "allocation_byte_microseconds").value,
        UInt64(7372800000),
    )


def test_peak_and_byte_time_withheld_when_live_invalid() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(
        _map("op1", True, "m1", UInt64(4096), UInt64(100000000), UInt64(2))
    )
    t.note_detail_loss()
    var rows = t.metrics_horizon(
        "window [0,1000000000)", UInt64(1000000000)
    )
    var peak = _global(rows, "peak_live_observed_allocation_bytes")
    assert_true(not peak.has_value)
    assert_equal(peak.measurement, String("unavailable"))
    var bt = _global(rows, "allocation_byte_microseconds")
    assert_true(not bt.has_value)
    assert_equal(bt.measurement, String("unavailable"))


def test_byte_time_withheld_without_horizon_while_open() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(
        _map("op1", True, "m1", UInt64(4096), UInt64(100000000), UInt64(2))
    )
    # No horizon: the open mapping's contribution is unprovable,
    # so completed-only would undercount and the row is withheld.
    var rows = t.metrics("window [0,1000)")
    var bt = _global(rows, "allocation_byte_microseconds")
    assert_true(not bt.has_value)
    var rows2 = t.metrics_horizon(
        "window [0,1000000000)", UInt64(1000000000)
    )
    assert_equal(
        _global(rows2, "allocation_byte_microseconds").value,
        UInt64(3686400000),
    )


def test_lifetime_p95() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_unmap("m1", UInt64(300), UInt64(3)))
    var rows = t.metrics("window [0,1000)")
    # One completed lifetime: every percentile lands in its bucket.
    assert_equal(
        _global(rows, "lifetime_p95_ns").value,
        _global(rows, "lifetime_p50_ns").value,
    )
    var t2 = MappingTracker()
    t2.consume(_attempt("op1", "d1", UInt64(1)))
    t2.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    var rows2 = t2.metrics("window [0,1000)")
    var p95 = _global(rows2, "lifetime_p95_ns")
    assert_true(not p95.has_value)


def test_detail_gap_invalidates_live() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_gap(UInt64(3)))
    t.consume(_unmap("m1", UInt64(200), UInt64(4)))
    var rows = t.metrics("window [0,1000)")
    assert_true(not _global(rows, "live_observed_allocation_bytes").has_value)
    var mean = _global(rows, "lifetime_mean_ns")
    assert_equal(mean.coverage, String("partial"))


def test_duplicate_result_refused() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_map("op1", True, "m2", UInt64(4096), UInt64(110), UInt64(3)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "successful_allocations").value, UInt64(1))
    assert_true(not _global(rows, "live_observed_allocation_bytes").has_value)


def test_reused_generation_two_samples() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(512), UInt64(100), UInt64(2)))
    t.consume(_unmap("m1", UInt64(150), UInt64(3)))
    t.consume(_attempt("op2", "d1", UInt64(4)))
    t.consume(_map("op2", True, "m2", UInt64(512), UInt64(200), UInt64(5)))
    t.consume(_unmap("m2", UInt64(260), UInt64(6)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "successful_allocations").value, UInt64(2))
    assert_equal(
        _global(rows, "completed_lifetime_count").value, UInt64(2)
    )
    assert_equal(_global(rows, "lifetime_mean_ns").value, UInt64(55))
    assert_equal(_global(rows, "lifetime_min_ns").value, UInt64(50))
    assert_equal(_global(rows, "lifetime_max_ns").value, UInt64(60))


def test_oldest_open_age() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    t.consume(_attempt("op2", "d1", UInt64(3)))
    t.consume(_map("op2", True, "m2", UInt64(8), UInt64(700), UInt64(4)))
    # Horizon 1000: oldest open maps at 100, age 900.
    var rows = t.metrics_horizon("window [0,1000)", UInt64(1000))
    assert_equal(
        _global(rows, "oldest_open_mapping_age_ns").value, UInt64(900)
    )
    var closed = MappingTracker()
    closed.consume(_attempt("op1", "d1", UInt64(1)))
    closed.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    closed.consume(_unmap("m1", UInt64(200), UInt64(3)))
    var norows = closed.metrics_horizon("window [0,1000)", UInt64(1000))
    assert_true(
        not _global(norows, "oldest_open_mapping_age_ns").has_value
    )


def test_open_at_end_censored() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "open_mappings").value, UInt64(1))
    assert_equal(_global(rows, "live_observed_allocation_bytes").value, UInt64(4096))
    # No releases observed: the completed count stays null rather
    # than claiming an empty observation.
    var count = _global(rows, "completed_lifetime_count")
    assert_true(not count.has_value)
    var mean = _global(rows, "lifetime_mean_ns")
    assert_true(not mean.has_value)
    assert_true(mean.notes != "")


def test_mapped_bytes_overflow_withheld() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", u64max(), UInt64(100), UInt64(2)))
    t.consume(_attempt("op2", "d1", UInt64(3)))
    t.consume(_map("op2", True, "m2", UInt64(1), UInt64(110), UInt64(4)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "successful_allocations").value, UInt64(2))
    assert_true(not _global(rows, "mapped_bytes_total").has_value)


def test_reversed_timestamps_uncertain() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(500), UInt64(2)))
    t.consume(_unmap("m1", UInt64(100), UInt64(3)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "live_observed_allocation_bytes").value, UInt64(0))
    assert_equal(
        _global(rows, "completed_lifetime_count").value, UInt64(0)
    )
    assert_true(not _global(rows, "lifetime_mean_ns").has_value)


def test_unpaired_map_excluded() raises:
    var t = MappingTracker()
    var ev = _map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(1))
    ev.source_correlation = String("unpaired")
    t.consume(ev^)
    var rows = t.metrics("window [0,1000)")
    assert_equal(_global(rows, "successful_allocations").value, UInt64(0))
    # No copy events at all: null with an unavailable marker, and
    # the unpaired exclusion is told by the degraded allocations.
    var cp = _global(rows, "copy_original_to_bounce_bytes")
    assert_true(not cp.has_value)
    assert_equal(
        _global(rows, "successful_allocations").coverage,
        String("partial"),
    )


def test_unpaired_unmap_invalidates_live() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(4096), UInt64(100), UInt64(2)))
    var ev = _unmap("m1", UInt64(200), UInt64(3))
    ev.source_correlation = String("unpaired")
    t.consume(ev^)
    var rows = t.metrics("window [0,1000)")
    assert_true(not _global(rows, "live_observed_allocation_bytes").has_value)


def test_active_budget() raises:
    var t = MappingTracker[1]()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(8), UInt64(100), UInt64(2)))
    t.consume(_attempt("op2", "d1", UInt64(3)))
    t.consume(_map("op2", True, "m2", UInt64(8), UInt64(110), UInt64(4)))
    var rows = t.metrics("window [0,1000)")
    # Both successes were observed, so both count; only the live
    # state the refused mapping would join is withheld.
    assert_equal(_global(rows, "successful_allocations").value, UInt64(2))
    assert_true(not _global(rows, "live_observed_allocation_bytes").has_value)


def test_resolved_history_bounded() raises:
    var t = MappingTracker[16, 16, 16, 4, 16]()
    var seq = UInt64(1)
    for i in range(6):
        var op = String("op") + String(i)
        var mapping = String("m") + String(i)
        t.consume(_attempt(op, "d1", seq))
        seq += 1
        t.consume(
            _map(
                op, True, mapping, UInt64(4096),
                UInt64(1000) + UInt64(i), seq,
            )
        )
        seq += 1
    # Six ops through a four-deep history: two evicted, totals
    # degrade with a visible note.
    var rows = t.metrics_horizon(
        String("window [0,2000)"), UInt64(2000)
    )
    assert_equal(
        _global(rows, "successful_allocations").value, UInt64(6)
    )
    assert_equal(
        _global(rows, "successful_allocations").coverage,
        String("partial"),
    )
    var noted = False
    for i in range(len(t.limitations())):
        if t.limitations()[i].find("history exceeded") != -1:
            noted = True
    assert_true(noted)
    # The evicted op is no longer recognized: resubmission is
    # accepted as new, with uncertainty preserved via partial
    # coverage rather than a duplicate verdict.
    t.consume(
        _map("op0", True, "m9", UInt64(4096), UInt64(5000), seq)
    )
    var rows2 = t.metrics_horizon(
        String("window [0,6000)"), UInt64(6000)
    )
    assert_equal(
        _global(rows2, "successful_allocations").value, UInt64(7)
    )
    assert_true(
        _global(rows2, "live_observed_allocation_bytes").has_value
    )


def test_retired_history_bounded() raises:
    var t = MappingTracker[16, 16, 16, 16, 4]()
    var seq = UInt64(1)
    for i in range(6):
        var op = String("op") + String(i)
        var mapping = String("m") + String(i)
        t.consume(_attempt(op, "d1", seq))
        seq += 1
        t.consume(
            _map(
                op, True, mapping, UInt64(4096),
                UInt64(1000) + UInt64(i), seq,
            )
        )
        seq += 1
        t.consume(
            _unmap(mapping, UInt64(1500) + UInt64(i), seq)
        )
        seq += 1
    # Six retirements through a four-deep history: two evicted.
    var rows = t.metrics_horizon(
        String("window [0,2000)"), UInt64(2000)
    )
    assert_equal(
        _global(rows, "completed_lifetime_count").value, UInt64(6)
    )
    assert_equal(
        _global(rows, "completed_lifetime_count").coverage,
        String("partial"),
    )
    var noted = False
    for i in range(len(t.limitations())):
        if t.limitations()[i].find("history exceeded") != -1:
            noted = True
    assert_true(noted)
    # The evicted retired id is no longer recognized: reuse is
    # accepted as a fresh mapping, never a duplicate verdict.
    t.consume(_attempt("op9", "d1", seq))
    seq += 1
    t.consume(
        _map("op9", True, "m0", UInt64(4096), UInt64(5000), seq)
    )
    var rows2 = t.metrics_horizon(
        String("window [0,6000)"), UInt64(6000)
    )
    assert_true(
        _global(rows2, "live_observed_allocation_bytes").has_value
    )
    assert_equal(
        _global(rows2, "live_observed_allocation_bytes").value,
        UInt64(4096),
    )


def test_per_device_rows() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(_map("op1", True, "m1", UInt64(100), UInt64(100), UInt64(2)))
    t.consume(_attempt("op2", "d2", UInt64(3)))
    t.consume(_map("op2", True, "m2", UInt64(300), UInt64(110), UInt64(4)))
    t.consume(_copy("op2", "m2", "bounce_to_original", UInt64(40), UInt64(5)))
    var rows = t.metrics("window [0,1000)")
    assert_equal(
        _find(rows, "successful_allocations", "d1").value, UInt64(1)
    )
    assert_equal(
        _find(rows, "mapped_bytes_total", "d2").value, UInt64(300)
    )
    assert_equal(
        _find(rows, "copy_bounce_to_original_bytes", "d2").value,
        UInt64(40),
    )
    assert_equal(
        _global(rows, "copy_bounce_to_original_bytes").value,
        UInt64(40),
    )


def _feed_prefix(mut t: MappingTracker) raises:
    t.consume(_attempt("op1", "d1", UInt64(1)))
    t.consume(
        _copy("op1", "", "original_to_bounce", UInt64(4096), UInt64(2))
    )


def test_snapshot_replay_equivalence() raises:
    # Snapshotting mid-stream must not change the final result:
    # metrics() shares the finish reducers with no destructive
    # finalization.
    var snapshotted = MappingTracker()
    _feed_prefix(snapshotted)
    var mid = snapshotted.metrics("window [0,1300000000)")
    assert_equal(
        _global(mid, "copy_original_to_bounce_bytes").value,
        UInt64(4096),
    )
    snapshotted.consume(
        _map("op1", True, "m1", UInt64(4096), UInt64(1300000000), UInt64(3))
    )
    var direct = MappingTracker()
    _feed_prefix(direct)
    direct.consume(
        _map("op1", True, "m1", UInt64(4096), UInt64(1300000000), UInt64(3))
    )
    var a = snapshotted.metrics("window [0,2300000000)")
    var b = direct.metrics("window [0,2300000000)")
    assert_equal(len(a), len(b))
    for i in range(len(a)):
        assert_equal(a[i].name, b[i].name)
        assert_equal(a[i].has_value, b[i].has_value)
        if a[i].has_value:
            assert_equal(a[i].value, b[i].value)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_lifecycle_nested]()
    suite.test[test_copy_before_failure]()
    suite.test[test_request_is_not_copy]()
    suite.test[test_orphan_release_invalidates_live]()
    suite.test[test_producer_loss_invalidates_live_keeps_aggregates]()
    suite.test[test_peak_and_byte_time]()
    suite.test[test_peak_and_byte_time_withheld_when_live_invalid]()
    suite.test[test_byte_time_withheld_without_horizon_while_open]()
    suite.test[test_lifetime_p95]()
    suite.test[test_detail_gap_invalidates_live]()
    suite.test[test_duplicate_result_refused]()
    suite.test[test_reused_generation_two_samples]()
    suite.test[test_oldest_open_age]()
    suite.test[test_open_at_end_censored]()
    suite.test[test_mapped_bytes_overflow_withheld]()
    suite.test[test_reversed_timestamps_uncertain]()
    suite.test[test_unpaired_map_excluded]()
    suite.test[test_unpaired_unmap_invalidates_live]()
    suite.test[test_active_budget]()
    suite.test[test_resolved_history_bounded]()
    suite.test[test_retired_history_bounded]()
    suite.test[test_per_device_rows]()
    suite.test[test_snapshot_replay_equivalence]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
