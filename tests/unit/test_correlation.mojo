# SPDX-License-Identifier: GPL-3.0-or-later

"""Correlation unit tests: pairing, generations, bounded registries.

The registry proves relationships without raw addresses or hidden
collector state: operation identity precedes mapping success,
namespaces never merge, observer context never becomes origin, and
every store refuses past its budget with an explicit quality
change instead of silent eviction.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.correlation import CorrelationRegistry, budgets
from memveil.model.event import Event
from memveil.model.validate import format_u64
from memveil.model.identity import (
    ACTIVE_MAX,
    DEVICE_MAX_ID,
    NESTED_MAX,
    PENDING_MAX,
    RETIRED_MAX,
)


def _base(kind: String, hook: String, seq: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("s1")
    ev.seq = seq
    ev.ts_ns = UInt64(1000) + seq
    ev.kind = kind
    ev.source_hook = hook
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def _attempt(op: String, device: String, hook: String, seq: UInt64) -> Event:
    var ev = _base("bounce_attempt", hook, seq)
    ev.bounce.device_id = device
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _map(
    op: String, ok: Bool, mapping: String, hook: String, seq: UInt64
) -> Event:
    var ev = _base("map_result", hook, seq)
    ev.map_result.operation_id = op
    ev.map_result.success = ok
    if mapping != "":
        ev.map_result.has_mapping_id = True
        ev.map_result.mapping_id = mapping
    if ok:
        ev.map_result.has_mapped_bytes = True
        ev.map_result.mapped_bytes = UInt64(4096)
    else:
        ev.map_result.has_return_code = True
        ev.map_result.return_code = Int64(-12)
    return ev^


def _copy(
    op: String, mapping: String, hook: String, seq: UInt64
) -> Event:
    var ev = _base("copy", hook, seq)
    ev.copy.operation_id = op
    if mapping != "":
        ev.copy.has_mapping_id = True
        ev.copy.mapping_id = mapping
    ev.copy.direction = String("original_to_bounce")
    ev.copy.bytes = UInt64(1024)
    return ev^


def _sync(op: String, mapping: String, hook: String, seq: UInt64) -> Event:
    var ev = _base("sync_request", hook, seq)
    ev.sync.operation_id = op
    if mapping != "":
        ev.sync.has_mapping_id = True
        ev.sync.mapping_id = mapping
    ev.sync.has_offset = True
    ev.sync.offset = UInt64(0)
    ev.sync.length = UInt64(1024)
    return ev^


def _unmap(mapping: String, hook: String, seq: UInt64) -> Event:
    var ev = _base("unmap", hook, seq)
    if mapping != "":
        ev.unmap.has_mapping_id = True
        ev.unmap.mapping_id = mapping
    return ev^


def _paired(ev: Event) -> Bool:
    return ev.source_correlation == "direct"


def test_attempt_opens_pending() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    var out = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    assert_true(_paired(out))
    assert_equal(reg.health().status, String("complete_for_scope"))


def test_map_requires_pending() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    var out = reg.normalize(
        _map("ghost", True, "m1", "h", UInt64(1)), "ring"
    )
    assert_true(not _paired(out))
    assert_equal(reg.health().status, String("partial"))


def test_map_success_creates_mapping() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    var out = reg.normalize(
        _map("op1", True, "m1", "h", UInt64(2)), "ring"
    )
    assert_true(_paired(out))
    assert_equal(reg.generation_of("d1", "iova", "m1"), UInt64(1))
    assert_equal(reg.active_count(), 1)


def test_same_address_new_generation() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(2)), "ring")
    var rel = reg.normalize(_unmap("m1", "h", UInt64(3)), "ring")
    assert_true(_paired(rel))
    _ = reg.normalize(_attempt("op2", "d1", "h", UInt64(4)), "ring")
    var second = reg.normalize(
        _map("op2", True, "m2", "h", UInt64(5)), "ring"
    )
    assert_true(_paired(second))
    var g1 = reg.generation_of("d1", "iova", "m1")
    var g2 = reg.generation_of("d1", "iova", "m2")
    assert_true(g1 != g2)
    assert_equal(g2, UInt64(2))


def test_cross_namespace_no_merge() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hk", "kvirt")
    reg.admit_hook("hg", "gphys")
    _ = reg.normalize(_attempt("op1", "d1", "hk", UInt64(1)), "ring")
    _ = reg.normalize(_attempt("op2", "d1", "hg", UInt64(2)), "ring")
    var a = reg.normalize(
        _map("op1", True, "tok", "hk", UInt64(3)), "ring"
    )
    var b = reg.normalize(
        _map("op2", True, "tok", "hg", UInt64(4)), "ring"
    )
    assert_true(_paired(a))
    assert_true(_paired(b))
    assert_equal(reg.active_count(), 2)
    var rel = reg.normalize(_unmap("tok", "hk", UInt64(5)), "ring")
    assert_true(_paired(rel))
    assert_equal(reg.active_count(), 1)
    var still = reg.normalize(
        _sync("op2", "tok", "hg", UInt64(6)), "ring"
    )
    assert_true(_paired(still))


def test_interior_sync_matches_live_generation() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(2)), "ring")
    var live = reg.normalize(
        _sync("op1", "m1", "h", UInt64(3)), "ring"
    )
    assert_true(_paired(live))
    _ = reg.normalize(_unmap("m1", "h", UInt64(4)), "ring")
    var stale = reg.normalize(
        _sync("op1", "m1", "h", UInt64(5)), "ring"
    )
    assert_true(not _paired(stale))


def test_nested_copy_before_result() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    var nested = reg.normalize(
        _copy("op1", "", "h", UInt64(2)), "ring"
    )
    assert_true(_paired(nested))
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(3)), "ring")
    var direct = reg.normalize(
        _copy("op1", "m1", "h", UInt64(4)), "ring"
    )
    assert_true(_paired(direct))


def test_nesting_budget() raises:
    var reg = CorrelationRegistry[65536, 65536, 1, 16384, 4096]()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    var first = reg.normalize(
        _copy("op1", "", "h", UInt64(2)), "ring"
    )
    assert_true(_paired(first))
    var second = reg.normalize(
        _copy("op1", "", "h", UInt64(3)), "ring"
    )
    assert_true(not _paired(second))
    assert_equal(reg.health().status, String("partial"))


def test_copy_preserved_when_map_fails() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    var cp = reg.normalize(
        _copy("op1", "", "h", UInt64(2)), "ring"
    )
    assert_true(_paired(cp))
    var fail = reg.normalize(
        _map("op1", False, "", "h", UInt64(3)), "ring"
    )
    assert_true(_paired(fail))
    assert_equal(reg.active_count(), 0)


def test_copy_after_failure_unpaired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", False, "", "h", UInt64(2)), "ring")
    var late = reg.normalize(
        _copy("op1", "", "h", UInt64(3)), "ring"
    )
    assert_true(not _paired(late))


def test_interrupt_context_not_origin() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    var a = _attempt("op1", "d1", "h", UInt64(1))
    a.has_observer = True
    a.has_pid = True
    a.pid = Int64(11)
    _ = reg.normalize(a^, "ring")
    var m = _map("op1", True, "m1", "h", UInt64(2))
    m.has_observer = True
    m.has_pid = True
    m.pid = Int64(99)
    var out = reg.normalize(m^, "ring")
    assert_true(_paired(out))


def test_duplicate_result_unpaired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(2)), "ring")
    var dup = reg.normalize(
        _map("op1", True, "m2", "h", UInt64(3)), "ring"
    )
    assert_true(not _paired(dup))


def test_unmap_unknown_unpaired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    var out = reg.normalize(_unmap("ghost", "h", UInt64(1)), "ring")
    assert_true(not _paired(out))


def test_retired_eviction_uncertain() raises:
    var reg = CorrelationRegistry[65536, 65536, 8, 1, 4096]()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(2)), "ring")
    _ = reg.normalize(_unmap("m1", "h", UInt64(3)), "ring")
    _ = reg.normalize(_attempt("op2", "d1", "h", UInt64(4)), "ring")
    _ = reg.normalize(_map("op2", True, "m2", "h", UInt64(5)), "ring")
    _ = reg.normalize(_unmap("m2", "h", UInt64(6)), "ring")
    # m1's tombstone is evicted; the repeat release stays unpaired
    # instead of borrowing certainty from forgotten evidence.
    var again = reg.normalize(_unmap("m1", "h", UInt64(7)), "ring")
    assert_true(not _paired(again))


def test_pending_exhaustion() raises:
    var reg = CorrelationRegistry[1, 65536, 8, 16384, 4096]()
    reg.admit_hook("h", "iova")
    var first = reg.normalize(
        _attempt("op1", "d1", "h", UInt64(1)), "ring"
    )
    assert_true(_paired(first))
    var second = reg.normalize(
        _attempt("op2", "d1", "h", UInt64(2)), "ring"
    )
    assert_true(not _paired(second))
    assert_equal(reg.health().status, String("partial"))


def test_device_exhaustion() raises:
    var reg = CorrelationRegistry[65536, 65536, 8, 16384, 1]()
    reg.admit_hook("h", "iova")
    var first = reg.normalize(
        _attempt("op1", "d1", "h", UInt64(1)), "ring"
    )
    assert_true(_paired(first))
    var second = reg.normalize(
        _attempt("op2", "d2", "h", UInt64(2)), "ring"
    )
    assert_true(not _paired(second))


def test_active_exhaustion() raises:
    var reg = CorrelationRegistry[65536, 1, 8, 16384, 4096]()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    _ = reg.normalize(_map("op1", True, "m1", "h", UInt64(2)), "ring")
    _ = reg.normalize(_attempt("op2", "d1", "h", UInt64(3)), "ring")
    var over = reg.normalize(
        _map("op2", True, "m2", "h", UInt64(4)), "ring"
    )
    assert_true(not _paired(over))


def test_hook_not_admitted() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    var out = reg.normalize(
        _attempt("op1", "d1", "other", UInt64(1)), "ring"
    )
    assert_true(not _paired(out))


def test_default_budgets() raises:
    var b = budgets()
    assert_equal(b.pending, PENDING_MAX)
    assert_equal(b.active, ACTIVE_MAX)
    assert_equal(b.nested, NESTED_MAX)
    assert_equal(b.retired, RETIRED_MAX)
    assert_equal(b.devices, DEVICE_MAX_ID)


def test_malformed_raises() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("h", "iova")
    _ = reg.normalize(_attempt("op1", "d1", "h", UInt64(1)), "ring")
    var bad = _map("op1", True, "", "h", UInt64(2))
    var raised = False
    try:
        _ = reg.normalize(bad^, "ring")
    except:
        raised = True
    assert_true(raised)


def test_non_lifecycle_passthrough() raises:
    var reg = CorrelationRegistry()
    var ev = _base("gap", "any", UInt64(1))
    ev.gap.channel = String("detail")
    ev.gap.reason = String("test")
    var out = reg.normalize(ev^, "ring")
    assert_equal(out.kind, String("gap"))
    assert_equal(reg.health().status, String("complete_for_scope"))


def _wire_map(
    op: String, gen: UInt64, hook: String, seq: UInt64
) -> Event:
    var ev = _base("map_result", hook, seq)
    ev.map_result.operation_id = op
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = String("gen-") + format_u64(gen)
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    ev.map_result.has_wire_generation = True
    ev.map_result.wire_generation = gen
    ev.map_result.has_wire_identity = True
    ev.map_result.wire_identity = String("known")
    return ev^


def _wire_unmap(gen: UInt64, hook: String, seq: UInt64) -> Event:
    var ev = _base("unmap", hook, seq)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = String("gen-") + format_u64(gen)
    ev.unmap.has_wire_generation = True
    ev.unmap.wire_generation = gen
    ev.unmap.has_wire_identity = True
    ev.unmap.wire_identity = String("known")
    return ev^


def test_wire_map_pairs_without_pending() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    reg.admit_hook("hu", "tlb-phys")
    var out = reg.normalize(
        _wire_map("lc-1", UInt64(41), "hm", UInt64(1)), "ring"
    )
    assert_true(_paired(out))
    assert_equal(
        reg.generation_of("unattributed", "tlb-phys", "gen-41"),
        UInt64(41),
    )
    var rel = reg.normalize(
        _wire_unmap(UInt64(41), "hu", UInt64(2)), "ring"
    )
    assert_true(_paired(rel))
    assert_equal(reg.active_count(), 0)
    assert_equal(reg.health().status, String("complete_for_scope"))


def test_wire_reuse_pairs_independently() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    reg.admit_hook("hu", "tlb-phys")
    _ = reg.normalize(
        _wire_map("lc-1", UInt64(41), "hm", UInt64(1)), "ring"
    )
    _ = reg.normalize(
        _wire_unmap(UInt64(41), "hu", UInt64(2)), "ring"
    )
    _ = reg.normalize(
        _wire_map("lc-3", UInt64(42), "hm", UInt64(3)), "ring"
    )
    var rel = reg.normalize(
        _wire_unmap(UInt64(42), "hu", UInt64(4)), "ring"
    )
    assert_true(_paired(rel))
    assert_equal(reg.health().status, String("complete_for_scope"))


def test_wire_double_map_unpaired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    _ = reg.normalize(
        _wire_map("lc-1", UInt64(7), "hm", UInt64(1)), "ring"
    )
    var out = reg.normalize(
        _wire_map("lc-2", UInt64(7), "hm", UInt64(2)), "ring"
    )
    assert_true(not _paired(out))
    assert_true(
        reg.health().reason.find(String("mapping already live")) != -1
    )


def test_wire_double_unmap_retired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    reg.admit_hook("hu", "tlb-phys")
    _ = reg.normalize(
        _wire_map("lc-1", UInt64(7), "hm", UInt64(1)), "ring"
    )
    _ = reg.normalize(
        _wire_unmap(UInt64(7), "hu", UInt64(2)), "ring"
    )
    var out = reg.normalize(
        _wire_unmap(UInt64(7), "hu", UInt64(3)), "ring"
    )
    assert_true(not _paired(out))
    assert_true(
        reg.health().reason.find(String("release of retired mapping"))
        != -1
    )


def test_wire_unassigned_never_pairs() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    var ev = _base("map_result", "hm", UInt64(1))
    ev.map_result.operation_id = String("lc-1")
    ev.map_result.success = True
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    ev.map_result.has_wire_generation = True
    ev.map_result.wire_generation = UInt64(0)
    ev.map_result.has_wire_identity = True
    ev.map_result.wire_identity = String("unassigned")
    var out = reg.normalize(ev^, "ring")
    assert_true(not _paired(out))
    assert_true(
        reg.health().reason.find(String("unassigned mapping identity"))
        != -1
    )
    assert_equal(reg.active_count(), 0)


def test_wire_miss_never_pairs() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hu", "tlb-phys")
    var ev = _base("unmap", "hu", UInt64(1))
    ev.unmap.has_wire_generation = True
    ev.unmap.wire_generation = UInt64(0)
    ev.unmap.has_wire_identity = True
    ev.unmap.wire_identity = String("miss")
    var out = reg.normalize(ev^, "ring")
    assert_true(not _paired(out))
    assert_true(
        reg.health().reason.find(String("release of unknown mapping"))
        != -1
    )


def test_wire_failed_map_unpaired() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    var ev = _base("map_result", "hm", UInt64(1))
    ev.map_result.operation_id = String("lc-1")
    ev.map_result.success = False
    ev.map_result.has_wire_generation = True
    ev.map_result.wire_generation = UInt64(0)
    var out = reg.normalize(ev^, "ring")
    assert_true(not _paired(out))
    assert_true(
        reg.health().reason.find(String("failure carries no mapping"))
        != -1
    )


def test_wire_token_mismatch_raises() raises:
    var reg = CorrelationRegistry()
    reg.admit_hook("hm", "tlb-phys")
    var ev = _wire_map("lc-1", UInt64(7), "hm", UInt64(1))
    ev.map_result.mapping_id = String("gen-9")
    var raised = False
    try:
        _ = reg.normalize(ev^, "ring")
    except:
        raised = True
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_attempt_opens_pending]()
    suite.test[test_map_requires_pending]()
    suite.test[test_map_success_creates_mapping]()
    suite.test[test_same_address_new_generation]()
    suite.test[test_cross_namespace_no_merge]()
    suite.test[test_interior_sync_matches_live_generation]()
    suite.test[test_nested_copy_before_result]()
    suite.test[test_nesting_budget]()
    suite.test[test_copy_preserved_when_map_fails]()
    suite.test[test_copy_after_failure_unpaired]()
    suite.test[test_interrupt_context_not_origin]()
    suite.test[test_duplicate_result_unpaired]()
    suite.test[test_unmap_unknown_unpaired]()
    suite.test[test_retired_eviction_uncertain]()
    suite.test[test_pending_exhaustion]()
    suite.test[test_device_exhaustion]()
    suite.test[test_active_exhaustion]()
    suite.test[test_hook_not_admitted]()
    suite.test[test_default_budgets]()
    suite.test[test_malformed_raises]()
    suite.test[test_non_lifecycle_passthrough]()
    suite.test[test_wire_map_pairs_without_pending]()
    suite.test[test_wire_reuse_pairs_independently]()
    suite.test[test_wire_double_map_unpaired]()
    suite.test[test_wire_double_unmap_retired]()
    suite.test[test_wire_unassigned_never_pairs]()
    suite.test[test_wire_miss_never_pairs]()
    suite.test[test_wire_failed_map_unpaired]()
    suite.test[test_wire_token_mismatch_raises]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
