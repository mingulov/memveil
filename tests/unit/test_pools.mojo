# SPDX-License-Identifier: GPL-3.0-or-later

"""Pool unit tests: sampler conversion and pressure inputs.

The sampler converts allocator units to bytes only with a
verified size and checked arithmetic; read failures yield
unavailable samples, never zero. The tracker applies the
90%-for-three-consecutive-valid-samples rule with
contemporaneous denominators: a missing sample, unknown
capacity, or changed pool generation resets the streak.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.pools import PoolTracker
from memveil.capture.pools import (
    POOL_SWIOTLB_ALLOCATOR,
    check_field_admitted,
    normalize_pool_sample,
    read_pool_counters,
    slots_to_bytes,
)
from memveil.model.event import Event
from memveil.model.metric import Metric
from memveil.platform.reader import open_evidence_reader


def u64max() -> UInt64:
    return ~UInt64(0)


def _admitted() -> List[String]:
    var out = List[String]()
    out.append(String("used_slots"))
    out.append(String("capacity_slots"))
    return out^


def test_field_allowlist() raises:
    check_field_admitted("used_slots", _admitted())
    var raised = False
    try:
        check_field_admitted("free_list_head", _admitted())
    except:
        raised = True
    assert_true(raised)


def test_slots_to_bytes() raises:
    assert_equal(
        slots_to_bytes(UInt64(900), UInt64(512), True), UInt64(460800)
    )
    var raised = False
    try:
        _ = slots_to_bytes(u64max(), UInt64(2), True)
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        _ = slots_to_bytes(UInt64(9), UInt64(512), False)
    except:
        raised = True
    assert_true(raised)


def test_normalize_sample() raises:
    var full = normalize_pool_sample(
        "pool0", True, UInt64(900), True, UInt64(1000), UInt64(1),
        True, "debugfs", POOL_SWIOTLB_ALLOCATOR, True, UInt64(950),
        String(""),
    )
    assert_true(full.has_used_bytes)
    assert_equal(full.used_bytes, UInt64(900))
    assert_true(full.has_capacity_bytes)
    assert_equal(full.capacity_bytes, UInt64(1000))
    assert_equal(full.unit, String("bytes"))
    assert_equal(full.allocator, POOL_SWIOTLB_ALLOCATOR)
    assert_true(full.has_unit_bytes)
    assert_equal(full.unit_bytes, UInt64(1))
    assert_true(full.has_hiwater_bytes)
    assert_equal(full.hiwater_bytes, UInt64(950))
    assert_equal(full.reason, String(""))
    var nocap = normalize_pool_sample(
        "pool0", True, UInt64(900), False, UInt64(0), UInt64(1),
        True, "debugfs", POOL_SWIOTLB_ALLOCATOR, False, UInt64(0),
        String("denied"),
    )
    assert_true(nocap.has_used_bytes)
    assert_true(not nocap.has_capacity_bytes)
    assert_true(nocap.notes != "")
    assert_equal(nocap.reason, String("denied"))
    assert_true(not nocap.has_hiwater_bytes)
    var raised = False
    try:
        _ = normalize_pool_sample(
            "pool0", True, UInt64(900), True, UInt64(1000),
            UInt64(1), True, "debugfs", POOL_SWIOTLB_ALLOCATOR,
            False, UInt64(0), String("bogus"),
        )
    except:
        raised = True
    assert_true(raised)


def test_read_counters_ok() raises:
    var reader = open_evidence_reader(
        String("tests/fixtures/pools/debugfs-ok")
    )
    var got = read_pool_counters(reader)
    assert_true(got.has_used)
    assert_equal(got.used_slots, UInt64(12))
    assert_true(got.has_cap)
    assert_equal(got.cap_slots, UInt64(32768))
    assert_true(got.has_hiwater)
    assert_equal(got.hiwater_slots, UInt64(64))
    assert_equal(got.reason, String(""))


def test_read_counters_denied() raises:
    var reader = open_evidence_reader(
        String("tests/fixtures/pools/debugfs-denied")
    )
    var got = read_pool_counters(reader)
    assert_true(not got.has_used)
    assert_true(got.has_cap)
    assert_true(not got.has_hiwater)
    assert_equal(got.reason, String("denied"))


def test_read_counters_absent() raises:
    var reader = open_evidence_reader(
        String("tests/fixtures/pools/debugfs-absent")
    )
    var got = read_pool_counters(reader)
    assert_true(not got.has_used)
    assert_true(not got.has_cap)
    assert_true(not got.has_hiwater)
    assert_equal(got.reason, String("absent"))


def test_read_counters_bad() raises:
    var reader = open_evidence_reader(
        String("tests/fixtures/pools/debugfs-bad")
    )
    var got = read_pool_counters(reader)
    assert_true(not got.has_used)
    assert_true(got.has_cap)
    assert_equal(got.reason, String("unparseable"))


def _sample(
    pool: String,
    has_used: Bool,
    used: UInt64,
    has_cap: Bool,
    cap: UInt64,
    unit: String,
    seq: UInt64,
) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(1000) + seq
    ev.kind = String("pool_sample")
    ev.source_hook = String("pool_sampler")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.pool.pool_id = pool
    ev.pool.has_used = has_used
    ev.pool.used_bytes = used
    ev.pool.has_capacity = has_cap
    ev.pool.capacity_bytes = cap
    ev.pool.unit = unit
    return ev^


def _find(metrics: List[Metric], name: String, pool: String) raises -> Metric:
    for i in range(len(metrics)):
        var m = metrics[i]
        if m.name != name:
            continue
        if m.has_pool_id and m.pool_id == pool:
            return m
    raise Error("metric not found: " + name)


def test_pressure_vector() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    assert_equal(len(t.pressured_pools()), 0)
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(3)))
    var hot = t.pressured_pools()
    assert_equal(len(hot), 1)
    assert_equal(hot[0], String("p1"))
    var rows = t.metrics("window [0,2000)")
    assert_equal(
        _find(rows, "pool_pressure_samples", "p1").value, UInt64(3)
    )
    assert_equal(
        _find(rows, "pool_used_bytes", "p1").confidence,
        String("high"),
    )


def test_below_threshold_no_pressure() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(899), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(3)))
    assert_equal(len(t.pressured_pools()), 0)


def test_missing_sample_resets() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    t.consume(_sample("p1", False, UInt64(0), True, UInt64(1000), String("bytes"), UInt64(3)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(4)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(5)))
    assert_equal(len(t.pressured_pools()), 0)
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(6)))
    assert_equal(len(t.pressured_pools()), 1)


def test_contemporaneous_capacity() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(1800), True, UInt64(2000), String("bytes"), UInt64(2)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(3)))
    assert_equal(len(t.pressured_pools()), 1)


def test_generation_scoped_ids() raises:
    # Two pool ids for successive generations of one source name
    # keep independent streaks.
    var t = PoolTracker()
    t.consume(_sample("p1g1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1g1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    t.consume(_sample("p1g2", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(3)))
    assert_equal(len(t.pressured_pools()), 0)
    assert_equal(t.streak_of("p1g1"), 2)
    assert_equal(t.streak_of("p1g2"), 1)


def test_zero_capacity_invalid() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(0), True, UInt64(0), String("bytes"), UInt64(1)))
    var rows = t.metrics("window [0,2000)")
    var cap = _find(rows, "pool_capacity_bytes", "p1")
    assert_true(not cap.has_value)
    assert_equal(t.streak_of("p1"), 0)


def test_unknown_unit_invalid() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("slots"), UInt64(1)))
    assert_equal(t.streak_of("p1"), 0)
    assert_true(len(t.limitations()) > 0)


def test_pool_budget() raises:
    var t = PoolTracker[1]()
    t.consume(_sample("p1", True, UInt64(1), True, UInt64(100), String("bytes"), UInt64(1)))
    t.consume(_sample("p2", True, UInt64(1), True, UInt64(100), String("bytes"), UInt64(2)))
    assert_equal(t.streak_of("p1"), 0)
    var refused = False
    try:
        _ = t.streak_of("p2")
    except:
        refused = True
    assert_true(refused)
    assert_true(len(t.limitations()) > 0)


def test_latest_values() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(100), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(200), True, UInt64(1000), String("bytes"), UInt64(2)))
    var rows = t.metrics("window [0,2000)")
    assert_equal(_find(rows, "pool_used_bytes", "p1").value, UInt64(200))
    assert_equal(
        _find(rows, "pool_capacity_bytes", "p1").value, UInt64(1000)
    )


def test_hiwater_gauge() raises:
    var t = PoolTracker()
    var first = _sample("p1", True, UInt64(100), True, UInt64(1000), String("bytes"), UInt64(1))
    first.pool.has_hiwater = True
    first.pool.hiwater_bytes = UInt64(400)
    t.consume(first)
    var rows = t.metrics("window [0,2000)")
    var h = _find(rows, "pool_hiwater_bytes", "p1")
    assert_true(h.has_value)
    assert_equal(h.value, UInt64(400))
    assert_equal(h.unit, String("bytes"))
    assert_equal(h.confidence, String("high"))
    # Latest wins; a sample without hiwater keeps the old mark.
    t.consume(_sample("p1", True, UInt64(100), True, UInt64(1000), String("bytes"), UInt64(2)))
    rows = t.metrics("window [0,2000)")
    assert_equal(
        _find(rows, "pool_hiwater_bytes", "p1").value, UInt64(400)
    )
    var second = _sample("p1", True, UInt64(100), True, UInt64(1000), String("bytes"), UInt64(3))
    second.pool.has_hiwater = True
    second.pool.hiwater_bytes = UInt64(500)
    t.consume(second)
    rows = t.metrics("window [0,2000)")
    assert_equal(
        _find(rows, "pool_hiwater_bytes", "p1").value, UInt64(500)
    )


def _gap(channel: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(3000) + seq
    ev.kind = String("gap")
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.gap.channel = channel
    ev.gap.has_lost_count = True
    ev.gap.lost_count = UInt64(2)
    ev.gap.reason = String("test gap")
    ev.gap.window_start_ns = UInt64(0)
    ev.gap.window_end_ns = UInt64(3000)
    return ev^


def test_detail_gap_degrades_gauges() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_gap("detail", UInt64(2)))
    var rows = t.metrics("window [0,2000)")
    assert_equal(
        _find(rows, "pool_used_bytes", "p1").coverage, String("partial")
    )
    assert_equal(
        _find(rows, "pool_capacity_bytes", "p1").coverage,
        String("partial"),
    )
    assert_equal(
        _find(rows, "pool_pressure_samples", "p1").coverage,
        String("partial"),
    )


def test_partial_sample_keeps_known_half() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), False, UInt64(0), String("bytes"), UInt64(1)))
    t.consume(_sample("p2", False, UInt64(0), True, UInt64(1000), String("bytes"), UInt64(2)))
    var rows = t.metrics("window [0,2000)")
    var used = _find(rows, "pool_used_bytes", "p1")
    assert_true(used.has_value)
    assert_equal(used.value, UInt64(900))
    var nocap = _find(rows, "pool_capacity_bytes", "p1")
    assert_true(not nocap.has_value)
    var cap = _find(rows, "pool_capacity_bytes", "p2")
    assert_true(cap.has_value)
    assert_equal(cap.value, UInt64(1000))
    var noused = _find(rows, "pool_used_bytes", "p2")
    assert_true(not noused.has_value)


def test_partial_sample_resets_streak() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    assert_equal(t.streak_of("p1"), 2)
    # The known half still lands, but pressure needs both halves.
    t.consume(_sample("p1", True, UInt64(950), False, UInt64(0), String("bytes"), UInt64(3)))
    assert_equal(t.streak_of("p1"), 0)
    var rows = t.metrics("window [0,2000)")
    assert_equal(_find(rows, "pool_used_bytes", "p1").value, UInt64(950))


def test_unrelated_gap_keeps_gauges_complete() raises:
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_gap("aggregate", UInt64(2)))
    var rows = t.metrics("window [0,2000)")
    assert_equal(
        _find(rows, "pool_used_bytes", "p1").coverage,
        String("complete_for_scope"),
    )


def test_detail_gap_resets_streak() raises:
    # Streaks never cross a detail gap: a hidden sample may
    # sit below the threshold.
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    assert_equal(t.streak_of("p1"), 2)
    t.consume(_gap("detail", UInt64(3)))
    assert_equal(t.streak_of("p1"), 0)
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(4)))
    assert_equal(t.streak_of("p1"), 1)
    assert_equal(len(t.pressured_pools()), 0)


def test_threshold_floor_division() raises:
    # 90% of 1001 is 900.9: the floor-division threshold is
    # 901, so 900 does not qualify but 901 does.
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1001), String("bytes"), UInt64(1)))
    assert_equal(t.streak_of("p1"), 0)
    t.consume(_sample("p1", True, UInt64(901), True, UInt64(1001), String("bytes"), UInt64(2)))
    assert_equal(t.streak_of("p1"), 1)


def test_over_capacity_counts() raises:
    # Usage at or above the threshold qualifies, even past
    # nominal capacity: over-capacity is pressure, not a
    # reset.
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(1100), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(1100), True, UInt64(1000), String("bytes"), UInt64(2)))
    t.consume(_sample("p1", True, UInt64(1100), True, UInt64(1000), String("bytes"), UInt64(3)))
    assert_equal(len(t.pressured_pools()), 1)


def test_aggregate_gap_keeps_streak() raises:
    # Only the sample stream's own channel breaks streaks:
    # an aggregate gap leaves the streak and gauges alone.
    var t = PoolTracker()
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(1)))
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(2)))
    t.consume(_gap("aggregate", UInt64(3)))
    assert_equal(t.streak_of("p1"), 2)
    t.consume(_sample("p1", True, UInt64(900), True, UInt64(1000), String("bytes"), UInt64(4)))
    assert_equal(len(t.pressured_pools()), 1)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_field_allowlist]()
    suite.test[test_slots_to_bytes]()
    suite.test[test_normalize_sample]()
    suite.test[test_read_counters_ok]()
    suite.test[test_read_counters_denied]()
    suite.test[test_read_counters_absent]()
    suite.test[test_read_counters_bad]()
    suite.test[test_pressure_vector]()
    suite.test[test_below_threshold_no_pressure]()
    suite.test[test_missing_sample_resets]()
    suite.test[test_contemporaneous_capacity]()
    suite.test[test_generation_scoped_ids]()
    suite.test[test_zero_capacity_invalid]()
    suite.test[test_unknown_unit_invalid]()
    suite.test[test_pool_budget]()
    suite.test[test_latest_values]()
    suite.test[test_hiwater_gauge]()
    suite.test[test_detail_gap_degrades_gauges]()
    suite.test[test_unrelated_gap_keeps_gauges_complete]()
    suite.test[test_partial_sample_keeps_known_half]()
    suite.test[test_partial_sample_resets_streak]()
    suite.test[test_detail_gap_resets_streak]()
    suite.test[test_threshold_floor_division]()
    suite.test[test_over_capacity_counts]()
    suite.test[test_aggregate_gap_keeps_streak]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
