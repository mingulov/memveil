# SPDX-License-Identifier: GPL-3.0-or-later

"""Lifetime statistics tests: the contract histogram vector.

Completed durations [1,2,3,4] ns must yield count 4, floor mean 2,
estimated p50 3, and estimated p99 7. Open, uncertain, and refused
mappings never join the sample set.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.mappings import MappingTracker
from memveil.model.event import Event
from memveil.model.metric import Metric


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


def _attempt(op: String, seq: UInt64) -> Event:
    var ev = _base("bounce_attempt", seq, seq)
    ev.bounce.device_id = String("d1")
    ev.bounce.requested_bytes = UInt64(8)
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
    ev.map_result.mapped_bytes = UInt64(8)
    return ev^


def _unmap(mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _base("unmap", seq, ts)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _cycle(
    mut t: MappingTracker, op: String, mapping: String, dur: UInt64,
    base: UInt64,
) raises:
    t.consume(_attempt(op, base))
    t.consume(_map(op, mapping, UInt64(1000000), base + UInt64(1)))
    t.consume(_unmap(mapping, UInt64(1000000) + dur, base + UInt64(2)))


def _find(metrics: List[Metric], name: String) raises -> Metric:
    for i in range(len(metrics)):
        var m = metrics[i]
        if m.name == name and not m.has_device_id:
            return m
    raise Error("metric not found: " + name)


def test_histogram_vector() raises:
    var t = MappingTracker()
    _cycle(t, "op1", "m1", UInt64(1), UInt64(1))
    _cycle(t, "op2", "m2", UInt64(2), UInt64(10))
    _cycle(t, "op3", "m3", UInt64(3), UInt64(20))
    _cycle(t, "op4", "m4", UInt64(4), UInt64(30))
    var rows = t.metrics("window [0,2000000)")
    var count = _find(rows, "completed_lifetime_count")
    assert_equal(count.value, UInt64(4))
    assert_true(count.has_sample_count)
    assert_equal(count.sample_count, UInt64(4))
    var mean = _find(rows, "lifetime_mean_ns")
    assert_equal(mean.value, UInt64(2))
    assert_equal(mean.aggregation, String("mean"))
    assert_equal(mean.sample_count, UInt64(4))
    # Rank ceil(50*4/100)=2 lands on value 2 in [2,3]: edge 3.
    var p50 = _find(rows, "lifetime_p50_ns")
    assert_equal(p50.value, UInt64(3))
    assert_equal(p50.measurement, String("estimated"))
    # Rank ceil(99*4/100)=4 lands on value 4 in [4,7]: edge 7.
    var p99 = _find(rows, "lifetime_p99_ns")
    assert_equal(p99.value, UInt64(7))
    assert_equal(p99.measurement, String("estimated"))
    assert_equal(_find(rows, "lifetime_min_ns").value, UInt64(1))
    assert_equal(_find(rows, "lifetime_max_ns").value, UInt64(4))


def test_open_excluded_from_samples() raises:
    var t = MappingTracker()
    _cycle(t, "op1", "m1", UInt64(10), UInt64(1))
    t.consume(_attempt("op2", UInt64(10)))
    t.consume(_map("op2", "m2", UInt64(1000000), UInt64(11)))
    var rows = t.metrics("window [0,2000000)")
    assert_equal(
        _find(rows, "completed_lifetime_count").value, UInt64(1)
    )
    assert_equal(_find(rows, "lifetime_mean_ns").value, UInt64(10))
    assert_equal(_find(rows, "open_mappings").value, UInt64(1))


def test_uncertain_excluded_from_samples() raises:
    var t = MappingTracker()
    _cycle(t, "op1", "m1", UInt64(10), UInt64(1))
    t.consume(_attempt("op2", UInt64(10)))
    t.consume(_map("op2", "m2", UInt64(9000000), UInt64(11)))
    t.consume(_unmap("m2", UInt64(100), UInt64(12)))
    var rows = t.metrics("window [0,10000000)")
    assert_equal(
        _find(rows, "completed_lifetime_count").value, UInt64(1)
    )
    assert_equal(_find(rows, "lifetime_mean_ns").value, UInt64(10))
    assert_equal(
        _find(rows, "lifetime_mean_ns").coverage, String("partial")
    )


def test_empty_lifetimes_unavailable() raises:
    var t = MappingTracker()
    t.consume(_attempt("op1", UInt64(1)))
    var rows = t.metrics("window [0,1000)")
    var count = _find(rows, "completed_lifetime_count")
    assert_true(not count.has_value)
    assert_equal(count.measurement, String("unavailable"))
    var mean = _find(rows, "lifetime_mean_ns")
    assert_true(not mean.has_value)
    assert_equal(mean.measurement, String("unavailable"))
    assert_true(mean.notes != "")


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_histogram_vector]()
    suite.test[test_open_excluded_from_samples]()
    suite.test[test_uncertain_excluded_from_samples]()
    suite.test[test_empty_lifetimes_unavailable]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
