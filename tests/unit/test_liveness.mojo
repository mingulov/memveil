# SPDX-License-Identifier: GPL-3.0-or-later

"""Hook liveness unit tests: windowed one-sided equations.

Independently authored expectations: a dead copy, lifecycle,
or unmap hook fires hooks_silent over its equation; orphan
copies fire the reverse equation; skip-sync unmaps never
count; known loss absorbs a deficit exactly; unknown loss or
a saturated counter turns the verdict unverified; guard-edge
excess never fires; pre-attach records stay out of the
windows; copy without lifecycle is unverified, never silent.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.liveness import (
    LIVENESS_BUCKETS,
    LIVENESS_BUCKET_NS,
    LIVENESS_GUARD_NS,
    LivenessLoss,
    LivenessTally,
    evaluate_liveness,
    sat_add_u64,
)


def _tally() -> LivenessTally:
    return LivenessTally(UInt64(1000000000), UInt64(3000000000))


def _loss(lc: UInt64, cp: UInt64) -> LivenessLoss:
    return LivenessLoss(lc, cp, True, True)


def _loss_split(
    lc: UInt64, cp: UInt64, known_lc: Bool, known_cp: Bool
) -> LivenessLoss:
    return LivenessLoss(lc, cp, known_lc, known_cp)


def _td() -> UInt64:
    return UInt64(10000000000)


def test_dead_copy_hook_fires() raises:
    var tally = _tally()
    for _ in range(100):
        tally.note_map(UInt64(4000000000), True)
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("map->copy"))
    assert_equal(v.detail, String("100 > 0"))


def test_dead_lifecycle_hook_fires() raises:
    var tally = _tally()
    for _ in range(50):
        tally.note_attempt(UInt64(4000000000))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("attempt->map"))
    assert_equal(v.detail, String("50 > 0"))


def test_dead_unmap_path_fires() raises:
    var tally = _tally()
    for _ in range(40):
        tally.note_unmap(UInt64(4000000000), UInt16(2), False)
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("unmap->copy"))
    assert_equal(v.detail, String("40 > 0"))


def test_orphan_copies_fire_reverse() raises:
    var tally = _tally()
    for _ in range(30):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("copy->map"))
    assert_equal(v.detail, String("30 > 0"))


def test_skip_sync_unmaps_excluded() raises:
    # Skip-sync unmaps never enter the unmap cause count: every equation stays unexercised instead of firing.
    var tally = _tally()
    for _ in range(40):
        tally.note_unmap(UInt64(4000000000), UInt16(2), True)
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("not_exercised"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_loss_absorbs_deficit() raises:
    var tally = _tally()
    for _ in range(100):
        tally.note_map(UInt64(4000000000), True)
    for _ in range(90):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    var ok = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(10))
    )
    assert_equal(ok.state, String("verified"))
    assert_equal(ok.equation, String(""))
    assert_equal(ok.detail, String(""))
    var bad = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(9))
    )
    assert_equal(bad.state, String("hooks_silent"))
    assert_equal(bad.equation, String("map->copy"))
    assert_equal(bad.detail, String("100 > 99"))


def test_unknown_loss_unverified() raises:
    var tally = _tally()
    for _ in range(100):
        tally.note_map(UInt64(4000000000), True)
    for _ in range(90):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    var v = evaluate_liveness(
        tally,
        _td(),
        True,
        True,
        True,
        LivenessLoss(UInt64(0), UInt64(10), False, False),
    )
    assert_equal(v.state, String("unverified"))
    assert_equal(v.equation, String("map->copy"))
    assert_equal(v.detail, String("100 vs 100"))


def test_channel_rollup_forward_only() raises:
    # Maps in F with copies outside R verify the copy channel alone.
    var tally = _tally()
    for _ in range(50):
        tally.note_map(UInt64(4000000000), True)
    for _ in range(50):
        tally.note_copy(UInt64(2000000000), UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("verified"))
    assert_equal(v.lc, String("not_exercised"))
    assert_equal(v.cp, String("verified"))


def test_channel_rollup_silent_copy() raises:
    # Maps with no copies silence only the copy channel.
    var tally = _tally()
    for _ in range(50):
        tally.note_map(UInt64(4000000000), True)
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("map->copy"))
    assert_equal(v.lc, String("not_exercised"))
    assert_equal(v.cp, String("hooks_silent"))


def test_loss_known_per_channel() raises:
    # Lifecycle known with copy unknown: E1 verifies while E2f stays out.
    var tally = _tally()
    for _ in range(50):
        tally.note_attempt(UInt64(4000000000))
    for _ in range(50):
        tally.note_map(UInt64(4000000000), True)
    var v = evaluate_liveness(
        tally,
        _td(),
        True,
        True,
        True,
        _loss_split(UInt64(0), UInt64(0), True, False),
    )
    assert_equal(v.state, String("unverified"))
    assert_equal(v.equation, String("map->copy"))
    assert_equal(v.detail, String("50 vs 0"))


def test_edge_excess_inside_guard_never_fires() raises:
    # Copies before R and inside the detach guard carry no reverse-equation weight: nothing fires.
    var tally = _tally()
    for _ in range(1000):
        tally.note_copy(UInt64(2000000000), UInt16(1))
    for _ in range(1000):
        tally.note_copy(UInt64(9500000000), UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("not_exercised"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_records_before_attach_ignored() raises:
    # Scripted ktimes near 1001 precede attach: every window stays empty.
    var tally = _tally()
    for i in range(10):
        var ts = UInt64(1001) + UInt64(i)
        tally.note_attempt(ts)
        tally.note_map(ts, True)
        tally.note_copy(ts, UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("not_exercised"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_copy_without_lifecycle_unverified() raises:
    var tally = _tally()
    for _ in range(30):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, False, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("unverified"))
    assert_equal(v.equation, String("copy liveness needs lifecycle"))
    assert_equal(v.detail, String(""))


def test_copy_only_empty_unverified() raises:
    # Zero records prove no hook fired; the run stays unverified.
    var tally = _tally()
    var v = evaluate_liveness(
        tally, _td(), True, False, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("unverified"))
    assert_equal(v.equation, String("copy liveness needs lifecycle"))
    assert_equal(v.detail, String(""))


def test_copy_only_syncs_without_copies_silent() raises:
    # Syncs with no copies prove the bounce hook dead, no lifecycle needed.
    var tally = _tally()
    for _ in range(30):
        tally.note_sync(UInt64(4000000000), True, UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, False, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("map->copy"))
    assert_equal(v.detail, String("30 > 0"))


def test_copy_only_cpu_syncs_without_copies_silent() raises:
    # The sync-for-cpu forward term fires the same way on its own.
    var tally = _tally()
    for _ in range(20):
        tally.note_sync(UInt64(4000000000), False, UInt16(2))
    var v = evaluate_liveness(
        tally, _td(), True, False, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("unmap->copy"))
    assert_equal(v.detail, String("20 > 0"))


def test_omitted_records_counted_as_loss() raises:
    # Drain- and latch-omitted records arrive inside the loss terms and absorb the deficit exactly.
    var tally = _tally()
    for _ in range(100):
        tally.note_map(UInt64(4000000000), True)
    for _ in range(60):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(40))
    )
    assert_equal(v.state, String("verified"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_short_run_not_exercised() raises:
    # t_d - GUARD <= t_r empties R: the reverse equations stay out while E1/E2f still evaluate over F.
    var tally = _tally()
    for _ in range(5):
        tally.note_attempt(UInt64(2000000000))
    for _ in range(10):
        tally.note_map(UInt64(2000000000), True)
    for _ in range(10):
        tally.note_copy(UInt64(2000000000), UInt16(1))
    var v = evaluate_liveness(
        tally,
        UInt64(3500000000),
        True,
        True,
        True,
        _loss(UInt64(0), UInt64(0)),
    )
    assert_equal(v.state, String("verified"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_bucket_boundary_conservative() raises:
    # The bucket straddling t_d - GUARD stays out of F: 100 maps with no copies would fire if it counted.
    var tally = _tally()
    for _ in range(100):
        tally.note_map(UInt64(9050000000), True)
    var v = evaluate_liveness(
        tally,
        UInt64(10100000000),
        True,
        True,
        True,
        _loss(UInt64(0), UInt64(0)),
    )
    assert_equal(v.state, String("not_exercised"))
    assert_equal(v.equation, String(""))
    assert_equal(v.detail, String(""))


def test_counter_saturation_unverified() raises:
    var exact = sat_add_u64(UInt64(5), UInt64(6))
    assert_equal(exact[0], UInt64(11))
    assert_true(not exact[1])
    var capped = sat_add_u64(~UInt64(0), UInt64(1))
    assert_equal(capped[0], ~UInt64(0))
    assert_true(capped[1])
    var tally = _tally()
    for _ in range(50):
        tally.note_attempt(UInt64(4000000000))
    tally.all.saturated = True
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("unverified"))
    assert_equal(v.equation, String("attempt->map"))
    assert_equal(v.detail, String("50 vs 0"))


def test_precedence_silent_over_unverified() raises:
    # E1 fires on exact counters while E2r stays unverified on a saturated reverse window: silence wins.
    var tally = _tally()
    for _ in range(50):
        tally.note_attempt(UInt64(4000000000))
    for _ in range(30):
        tally.note_copy(UInt64(4000000000), UInt16(1))
    tally.win_r.saturated = True
    var v = evaluate_liveness(
        tally, _td(), True, True, True, _loss(UInt64(0), UInt64(0))
    )
    assert_equal(v.state, String("hooks_silent"))
    assert_equal(v.equation, String("attempt->map"))
    assert_equal(v.detail, String("50 > 0"))


def test_liveness_constants() raises:
    assert_equal(LIVENESS_GUARD_NS, UInt64(1000000000))
    assert_equal(LIVENESS_BUCKET_NS, UInt64(250000000))
    assert_equal(LIVENESS_BUCKETS, 8)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_dead_copy_hook_fires]()
    suite.test[test_dead_lifecycle_hook_fires]()
    suite.test[test_dead_unmap_path_fires]()
    suite.test[test_orphan_copies_fire_reverse]()
    suite.test[test_skip_sync_unmaps_excluded]()
    suite.test[test_loss_absorbs_deficit]()
    suite.test[test_unknown_loss_unverified]()
    suite.test[test_loss_known_per_channel]()
    suite.test[test_channel_rollup_forward_only]()
    suite.test[test_channel_rollup_silent_copy]()
    suite.test[test_edge_excess_inside_guard_never_fires]()
    suite.test[test_records_before_attach_ignored]()
    suite.test[test_copy_without_lifecycle_unverified]()
    suite.test[test_copy_only_empty_unverified]()
    suite.test[test_copy_only_syncs_without_copies_silent]()
    suite.test[test_copy_only_cpu_syncs_without_copies_silent]()
    suite.test[test_omitted_records_counted_as_loss]()
    suite.test[test_short_run_not_exercised]()
    suite.test[test_bucket_boundary_conservative]()
    suite.test[test_counter_saturation_unverified]()
    suite.test[test_precedence_silent_over_unverified]()
    suite.test[test_liveness_constants]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
