# SPDX-License-Identifier: GPL-3.0-or-later

"""Region tracker unit tests: intervals, uncertainty, budgets.

Independently authored expectations from the frozen product
contracts: overlapping shared requests union (12288, then 8192
after partial reprivatization), a failed conversion without
rollback proof leaves its interval unknown while the untouched
remainder stays known, ordinary-kernel no-op success records
the request without any state transition, unresolved or
identity-only ranges never form a physical union, mapping
events never mutate region state, and budgets refuse with a
visible limitation instead of merging distinct states.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.regions import RegionTracker
from memveil.model.event import Event
from memveil.model.metric import Metric
from memveil.model.regions import (
    RegionObservation,
    RegionReference,
    check_region_resolution,
    check_region_space,
    check_region_span,
    check_region_state,
)


def u64max() -> UInt64:
    return ~UInt64(0)


def _transition(
    region: String,
    state: String,
    ok: Bool,
    offset: UInt64,
    length: UInt64,
    seq: UInt64,
) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(1000) + seq
    ev.kind = String("transition_result")
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.transition.region_id = region
    ev.transition.requested_state = state
    ev.transition.success = ok
    ev.transition.has_return_code = True
    if ok:
        ev.transition.return_code = Int64(0)
    else:
        ev.transition.return_code = Int64(-5)
    ev.transition.offset = offset
    ev.transition.length = length
    ev.transition.has_address_space = True
    ev.transition.address_space = String("guest_physical")
    ev.transition.has_resolution = True
    ev.transition.resolution = String("resolved")
    return ev^


def _unresolved(
    region: String, state: String, seq: UInt64
) -> Event:
    var ev = _transition(
        region, state, True, UInt64(0), UInt64(8192), seq
    )
    ev.transition.has_address_space = True
    ev.transition.address_space = String("identity_only")
    ev.transition.has_resolution = True
    ev.transition.resolution = String("unresolved")
    return ev^


def _map(op: String, mapping: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(2000) + seq
    ev.kind = String("map_result")
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.map_result.operation_id = op
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = mapping
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    return ev^


def _unmap(mapping: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(3000) + seq
    ev.kind = String("unmap")
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _obs(
    region: String,
    state: String,
    offset: UInt64,
    length: UInt64,
) -> RegionObservation:
    var o = RegionObservation()
    o.region_id = region
    o.state = state
    o.offset = offset
    o.length = length
    o.address_space = String("guest_physical")
    o.provenance = String("test-baseline")
    return o^


def _find(metrics: List[Metric], name: String) raises -> Metric:
    for i in range(len(metrics)):
        if metrics[i].name == name:
            return metrics[i].copy()
    raise Error("missing metric " + name)


def test_reference_key() raises:
    var a = RegionReference()
    a.namespace = String("guest_physical")
    a.resolution = String("physical_span")
    a.identity = String("r1")
    a.offset = UInt64(0)
    a.length = UInt64(8192)
    a.generation = 1
    var b = a.copy()
    b.generation = 2
    var c = a.copy()
    c.namespace = String("kernel_virtual")
    assert_equal(a.key(), a.key())
    assert_true(a.key() != b.key())
    assert_true(a.key() != c.key())


def test_region_checks() raises:
    check_region_state(String("shared"))
    check_region_state(String("private"))
    check_region_state(String("unknown"))
    check_region_space(String("guest_physical"))
    check_region_space(String("kernel_virtual"))
    check_region_space(String("iova"))
    check_region_space(String("identity_only"))
    check_region_resolution(String("physical_span"))
    check_region_resolution(String("identity_only"))
    check_region_resolution(String("unavailable"))
    assert_equal(
        check_region_span(UInt64(4096), UInt64(4096)), UInt64(8192)
    )
    var bad = 0
    try:
        check_region_state(String("encrypted"))
    except:
        bad += 1
    try:
        check_region_space(String("gphys"))
    except:
        bad += 1
    try:
        check_region_resolution(String("resolved"))
    except:
        bad += 1
    try:
        _ = check_region_span(u64max(), UInt64(1))
    except:
        bad += 1
    assert_equal(bad, 4)


def test_region_union_shared() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(4096),
        UInt64(8192), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_true(t.sees_regions())
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(12288),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )
    assert_equal(
        _find(rows, String("conversion_request_bytes")).value,
        UInt64(16384),
    )
    t.consume(_transition(
        String("r1"), String("private"), True, UInt64(4096),
        UInt64(4096), UInt64(3),
    ))
    rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )
    assert_equal(
        _find(rows, String("known_private_region_bytes")).value,
        UInt64(4096),
    )


def test_conversion_uncertain() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("private"), False, UInt64(0),
        UInt64(4096), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("unknown_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )
    # Evidence classes: state interpretation is medium,
    # request counting is high, independent of coverage.
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).confidence,
        String("medium"),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).confidence,
        String("high"),
    )
    assert_equal(
        _find(rows, String("conversion_failures")).value, UInt64(1)
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )


def test_ordinary_noop() raises:
    var t = RegionTracker(False, True)
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    assert_true(t.sees_regions())
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(1)
    )
    assert_equal(
        _find(rows, String("conversion_request_bytes")).value,
        UInt64(8192),
    )
    var shared = _find(rows, String("known_shared_region_bytes"))
    assert_true(not shared.has_value)
    assert_equal(shared.measurement, String("unavailable"))


def test_unresolved_never_physical() raises:
    var t = RegionTracker()
    t.consume(_unresolved(String("r1"), String("shared"), UInt64(1)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(1)
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(0),
    )
    # The request counts, but its state effect is opaque, so the
    # zero union is partial, never authoritative.
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )
    var noted = False
    for i in range(len(t.limitations())):
        if t.limitations()[i].find("no usable state") != -1:
            noted = True
    assert_true(noted)


def test_mapping_events_ignored() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    t.consume(_map(String("op-9"), String("map-9"), UInt64(2)))
    t.consume(_unmap(String("map-9"), UInt64(3)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(1)
    )


def test_unknown_at_start() raises:
    var t = RegionTracker(True, False)
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(1)
    )
    var shared = _find(rows, String("known_shared_region_bytes"))
    assert_true(not shared.has_value)
    assert_equal(shared.measurement, String("unavailable"))


def test_baseline_seed() raises:
    var t = RegionTracker()
    var obs = List[RegionObservation]()
    obs.append(_obs(String("r1"), String("shared"), UInt64(0), UInt64(8192)))
    t.seed_baseline(obs)
    assert_true(t.sees_regions())
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )
    # Baseline seeds state, never conversion counts: without a
    # transition source the counters stay unavailable, not zero.
    var req = _find(rows, String("conversion_requests"))
    assert_true(not req.has_value)
    assert_equal(req.measurement, String("unavailable"))
    var fail = _find(rows, String("conversion_failures"))
    assert_true(not fail.has_value)
    var reqb = _find(rows, String("conversion_request_bytes"))
    assert_true(not reqb.has_value)


def test_baseline_unknown_preserved() raises:
    var t = RegionTracker()
    var obs = List[RegionObservation]()
    obs.append(_obs(String("r1"), String("unknown"), UInt64(0), UInt64(4096)))
    t.seed_baseline(obs)
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("unknown_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(0),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )


def test_repeated_conversion() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("private"), True, UInt64(0),
        UInt64(4096), UInt64(2),
    ))
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(3),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("known_private_region_bytes")).value,
        UInt64(0),
    )


def test_independent_regions() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    ))
    t.consume(_transition(
        String("r2"), String("private"), True, UInt64(0),
        UInt64(4096), UInt64(2),
    ))
    var g2 = _obs(String("r1"), String("private"), UInt64(0), UInt64(1024))
    g2.generation = 2
    var obs = List[RegionObservation]()
    obs.append(g2)
    t.seed_baseline(obs)
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("known_private_region_bytes")).value,
        UInt64(5120),
    )


def test_disjoint_intervals() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(8192),
        UInt64(4096), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )


def test_zero_length_request() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(4096),
        UInt64(0), UInt64(1),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(1)
    )
    assert_equal(
        _find(rows, String("conversion_request_bytes")).value,
        UInt64(0),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(0),
    )


def test_request_bytes_overflow() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        u64max(), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(1), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )
    var rb = _find(rows, String("conversion_request_bytes"))
    assert_true(not rb.has_value)
    assert_equal(rb.measurement, String("unavailable"))


def test_contradictory_namespace() raises:
    var t = RegionTracker()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    ))
    var kv = _transition(
        String("r1"), String("private"), True, UInt64(0),
        UInt64(8192), UInt64(2),
    )
    kv.transition.address_space = String("kernel_virtual")
    t.consume(kv)
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )
    assert_equal(
        _find(rows, String("known_private_region_bytes")).value,
        UInt64(0),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )
    assert_true(len(t.limitations()) > 0)


def test_region_budget() raises:
    var t = RegionTracker[REGION_N=1]()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    ))
    t.consume(_transition(
        String("r2"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(4096),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )
    assert_true(len(t.limitations()) > 0)


def test_segment_budget() raises:
    var t = RegionTracker[SEG_N=1]()
    t.consume(_transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    ))
    t.consume(_transition(
        String("r1"), String("private"), True, UInt64(0),
        UInt64(1024), UInt64(2),
    ))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(0),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).value, UInt64(2)
    )
    assert_true(len(t.limitations()) > 0)


def test_namespace_isolation() raises:
    var t = RegionTracker()
    var kv = _transition(
        String("r9"), String("shared"), True, UInt64(0),
        UInt64(8192), UInt64(1),
    )
    kv.transition.address_space = String("kernel_virtual")
    t.consume(kv)
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(0),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("complete_for_scope"),
    )


def test_empty_world() raises:
    var t = RegionTracker()
    assert_true(not t.sees_regions())
    var obs = List[RegionObservation]()
    t.seed_baseline(obs)
    assert_true(not t.sees_regions())


def test_generation_lineage_isolated() raises:
    var t = RegionTracker()
    var obs = List[RegionObservation]()
    var g1 = _obs(String("r1"), String("shared"), UInt64(0), UInt64(8192))
    g1.generation = 1
    var g2 = _obs(String("r1"), String("private"), UInt64(0), UInt64(8192))
    g2.generation = 2
    obs.append(g1^)
    obs.append(g2^)
    t.seed_baseline(obs)
    var tr = _transition(
        String("r1"), String("shared"), True, UInt64(0),
        UInt64(4096), UInt64(1),
    )
    tr.transition.generation = 2
    t.consume(tr^)
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(12288),
    )
    assert_equal(
        _find(rows, String("known_private_region_bytes")).value,
        UInt64(4096),
    )


def _gap(channel: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(4000) + seq
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
    ev.gap.window_end_ns = UInt64(4000)
    return ev^


def test_detail_gap_degrades_counts_and_unions() raises:
    var t = RegionTracker()
    t.consume(
        _transition(
            String("r1"), String("shared"), True, UInt64(0),
            UInt64(8192), UInt64(1),
        )
    )
    t.consume(_gap("detail", UInt64(2)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).coverage,
        String("partial"),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )


def test_baseline_gap_degrades_unions_only() raises:
    var t = RegionTracker()
    t.consume(
        _transition(
            String("r1"), String("shared"), True, UInt64(0),
            UInt64(8192), UInt64(1),
        )
    )
    t.consume(_gap("baseline", UInt64(2)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )
    assert_equal(
        _find(rows, String("conversion_requests")).coverage,
        String("complete_for_scope"),
    )


def test_opaque_transition_degrades_known_unions() raises:
    var t = RegionTracker()
    t.consume(
        _transition(
            String("r1"), String("shared"), True, UInt64(0),
            UInt64(8192), UInt64(1),
        )
    )
    t.consume(_unresolved(String("r1"), String("private"), UInt64(2)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).value,
        UInt64(8192),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("partial"),
    )


def test_unrelated_gap_keeps_regions_complete() raises:
    var t = RegionTracker()
    t.consume(
        _transition(
            String("r1"), String("shared"), True, UInt64(0),
            UInt64(8192), UInt64(1),
        )
    )
    t.consume(_gap("aggregate", UInt64(2)))
    var rows = t.metrics(String("window [0,2000)"))
    assert_equal(
        _find(rows, String("conversion_requests")).coverage,
        String("complete_for_scope"),
    )
    assert_equal(
        _find(rows, String("known_shared_region_bytes")).coverage,
        String("complete_for_scope"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_reference_key]()
    suite.test[test_region_checks]()
    suite.test[test_region_union_shared]()
    suite.test[test_conversion_uncertain]()
    suite.test[test_ordinary_noop]()
    suite.test[test_unresolved_never_physical]()
    suite.test[test_mapping_events_ignored]()
    suite.test[test_unknown_at_start]()
    suite.test[test_baseline_seed]()
    suite.test[test_baseline_unknown_preserved]()
    suite.test[test_repeated_conversion]()
    suite.test[test_independent_regions]()
    suite.test[test_disjoint_intervals]()
    suite.test[test_zero_length_request]()
    suite.test[test_request_bytes_overflow]()
    suite.test[test_contradictory_namespace]()
    suite.test[test_region_budget]()
    suite.test[test_segment_budget]()
    suite.test[test_namespace_isolation]()
    suite.test[test_empty_world]()
    suite.test[test_generation_lineage_isolated]()
    suite.test[test_opaque_transition_degrades_known_unions]()
    suite.test[test_detail_gap_degrades_counts_and_unions]()
    suite.test[test_baseline_gap_degrades_unions_only]()
    suite.test[test_unrelated_gap_keeps_regions_complete]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
