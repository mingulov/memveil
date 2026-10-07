# SPDX-License-Identifier: GPL-3.0-or-later

"""Stop-protocol unit tests: explicit terminal evidence.

The stop controller closes admission, settles admitted writer
activity, drains to a proved transport boundary, samples
counters, and finalizes. Every path yields either proved
complete evidence or explicit partial evidence within the stop
budget; a quiet ring alone never proves completion, and open
logical mappings never block callback quiescence.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.stop import (
    STOP_BUDGET_MS,
    StopController,
    StopError,
)


def test_clean_stop_completes() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    ctl.observe_quiescence()
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("complete"))
    assert_equal(ev.stop_budget_ms, STOP_BUDGET_MS)
    assert_true(ev.counters_valid)


def test_writer_between_admission_and_count_settles() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var w = ctl.writer_begin()
    assert_true(w)
    ctl.close_admission()
    ctl.writer_settle()
    ctl.observe_quiescence()
    ctl.drain(1, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("complete"))
    assert_equal(ev.writers_settled, 1)


def test_admission_after_close_refused() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    var w = ctl.writer_begin()
    assert_true(not w)
    ctl.observe_quiescence()
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("complete"))


def test_stop_during_reserve_drains_late_submit() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var w = ctl.writer_begin()
    assert_true(w)
    ctl.writer_reserve()
    ctl.close_admission()
    ctl.writer_submit()
    ctl.writer_settle()
    ctl.observe_quiescence()
    ctl.drain(1, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("complete"))
    assert_equal(ev.late_submits_drained, 1)


def test_delayed_submit_past_drain_bound_partial() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var w = ctl.writer_begin()
    assert_true(w)
    ctl.writer_reserve()
    ctl.close_admission()
    # The writer never submits: quiescence is unproven, so the
    # drain cannot cover its record and the stop stays partial.
    var settled = ctl.try_quiescence()
    assert_true(not settled)
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("partial"))
    assert_true(ev.reason != "")


def test_missing_writer_decrement_partial() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var w = ctl.writer_begin()
    assert_true(w)
    ctl.close_admission()
    var settled = ctl.try_quiescence()
    assert_true(not settled)
    var ev = ctl.finalize(1)
    assert_equal(ev.outcome, String("partial"))
    assert_equal(ev.in_flight_at_close, 1)


def test_failed_final_snapshot_partial() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    ctl.observe_quiescence()
    ctl.drain(0, False)
    ctl.sample_counters(False)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("partial"))
    assert_true(not ev.counters_valid)


def test_busy_record_retried_then_partial() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    ctl.observe_quiescence()
    ctl.drain(0, True)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("partial"))
    assert_true(ev.busy_at_drain)


def test_quiet_ring_without_quiescence_never_complete() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var w = ctl.writer_begin()
    assert_true(w)
    ctl.close_admission()
    # Zero drained records with a writer still in flight proves
    # nothing: finalizing without observed quiescence is partial.
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(0)
    assert_equal(ev.outcome, String("partial"))


def test_open_mappings_do_not_block_quiescence() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    ctl.observe_quiescence()
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize(7)
    assert_equal(ev.outcome, String("complete"))
    assert_equal(ev.open_mappings, 7)


def test_budget_exhaustion_partial() raises:
    var ctl = StopController()
    ctl.mark_ready()
    ctl.close_admission()
    var ev = ctl.finalize_over_budget(STOP_BUDGET_MS + 1, 0)
    assert_equal(ev.outcome, String("partial"))
    assert_equal(ev.elapsed_ms, STOP_BUDGET_MS + 1)
    assert_equal(ev.stop_budget_ms, STOP_BUDGET_MS)


def test_finalize_requires_close() raises:
    var ctl = StopController()
    ctl.mark_ready()
    var raised = False
    try:
        _ = ctl.finalize(0)
    except:
        raised = True
    assert_true(raised)


def test_close_requires_ready() raises:
    var ctl = StopController()
    var raised = False
    try:
        ctl.close_admission()
    except:
        raised = True
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_clean_stop_completes]()
    suite.test[test_writer_between_admission_and_count_settles]()
    suite.test[test_admission_after_close_refused]()
    suite.test[test_stop_during_reserve_drains_late_submit]()
    suite.test[test_delayed_submit_past_drain_bound_partial]()
    suite.test[test_missing_writer_decrement_partial]()
    suite.test[test_failed_final_snapshot_partial]()
    suite.test[test_busy_record_retried_then_partial]()
    suite.test[test_quiet_ring_without_quiescence_never_complete]()
    suite.test[test_open_mappings_do_not_block_quiescence]()
    suite.test[test_budget_exhaustion_partial]()
    suite.test[test_finalize_requires_close]()
    suite.test[test_close_requires_ready]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
