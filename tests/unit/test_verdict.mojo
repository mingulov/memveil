# SPDX-License-Identifier: GPL-3.0-or-later

"""Verdict unit tests: measurement verdict from agreed counters plus loss.

The verdict core takes counters agreement, per-leg loss knowledge,
and delivered counts, and yields one of complete, partial_known_loss,
or partial_unknown_loss with a loss ratio in basis points. The ratio
is exact when every leg is known and a lower bound otherwise.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.model.report import (
    Verdict,
    incomplete_finding_severity,
    verdict_for_counts,
    verdict_for_session,
)
from memveil.model.session import (
    Session,
    StopState,
    quiescence_only_spillover,
    terminal_loss_leg,
)


def test_verdict_complete_clean() raises:
    var v = verdict_for_counts(True, True, UInt64(0), False, False, True, UInt64(0), UInt64(100))
    assert_equal(v.name, String("complete"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_known_loss_ratio() raises:
    var v = verdict_for_counts(True, True, UInt64(5), True, False, True, UInt64(0), UInt64(95))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 500)


def test_verdict_unknown_detail_lower_bound() raises:
    var v = verdict_for_counts(True, False, UInt64(0), True, False, True, UInt64(0), UInt64(100))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_unknown_terminal() raises:
    var v = verdict_for_counts(True, True, UInt64(0), False, True, False, UInt64(0), UInt64(100))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_counters_disagree() raises:
    var v = verdict_for_counts(False, True, UInt64(0), False, False, True, UInt64(0), UInt64(100))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_quiescence_spillover_known() raises:
    # Terminal partial but loss bounded (spillover verified): the
    # capture was degraded, so not complete, yet the loss is known.
    var v = verdict_for_counts(True, True, UInt64(0), False, True, True, UInt64(0), UInt64(100))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_vacuous_zero_zero() raises:
    var v = verdict_for_counts(True, True, UInt64(0), False, False, True, UInt64(0), UInt64(0))
    assert_equal(v.name, String("complete"))
    assert_equal(v.loss_ratio_bps, 0)


def test_verdict_ratio_truncates() raises:
    var v = verdict_for_counts(True, True, UInt64(1), True, False, True, UInt64(0), UInt64(2))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 3333)


def test_verdict_terminal_known_loss() raises:
    var v = verdict_for_counts(True, True, UInt64(0), False, True, True, UInt64(3), UInt64(97))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 300)


def test_verdict_disagree_keeps_lower_bound() raises:
    # Counters disagree, but 5 known detail losses over 95 delivered
    # still bound the ratio from below.
    var v = verdict_for_counts(False, True, UInt64(5), True, False, True, UInt64(0), UInt64(95))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 500)


def test_verdict_struct_defaults() raises:
    var v = Verdict()
    assert_equal(v.name, String(""))
    assert_equal(v.loss_ratio_bps, 0)
    assert_true(v.loss_ratio_bps >= 0)


def quiescence_stop() -> StopState:
    var s = StopState()
    s.outcome = String("partial")
    s.reason = String("quiescence unproven")
    s.budget_ms = UInt64(5000)
    s.elapsed_ms = UInt64(100)
    s.admission_closed = True
    s.quiescence_observed = False
    s.writers_settled = UInt64(0)
    s.in_flight_at_close = UInt64(3)
    s.late_submits_drained = UInt64(3)
    s.drained_records = UInt64(10)
    s.drain_completed = True
    s.submit_after_drain = False
    s.busy_at_drain = False
    s.counters_valid = True
    s.open_mappings = UInt64(0)
    return s^


def test_terminal_complete_proved() raises:
    var s = StopState()
    s.outcome = String("complete")
    var leg = terminal_loss_leg(String("complete_for_scope"), s)
    assert_equal(leg[0], False)
    assert_equal(leg[1], True)
    assert_equal(leg[2], UInt64(0))


def test_terminal_complete_contradicted() raises:
    # A bare complete label with no proving stop evidence stays unknown.
    var leg = terminal_loss_leg(String("complete_for_scope"), StopState())
    assert_equal(leg[0], False)
    assert_equal(leg[1], False)
    assert_equal(leg[2], UInt64(0))


def test_terminal_quiescence_only() raises:
    var leg = terminal_loss_leg(String("partial"), quiescence_stop())
    assert_equal(leg[0], True)
    assert_equal(leg[1], True)
    assert_equal(leg[2], UInt64(0))


def test_terminal_quiescence_busy() raises:
    var s = quiescence_stop()
    s.busy_at_drain = True
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_spillover_short() raises:
    var s = quiescence_stop()
    s.late_submits_drained = UInt64(2)
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_counters_bad() raises:
    var s = quiescence_stop()
    s.counters_valid = False
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_late_submit() raises:
    var s = quiescence_stop()
    s.submit_after_drain = True
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_drain_missing() raises:
    var s = quiescence_stop()
    s.drain_completed = False
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_admission_open() raises:
    var s = quiescence_stop()
    s.admission_closed = False
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_observed_other_cause() raises:
    var s = quiescence_stop()
    s.quiescence_observed = True
    s.reason = String("drain missing")
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_quiescence_over_budget() raises:
    var s = quiescence_stop()
    s.elapsed_ms = UInt64(6000)
    var leg = terminal_loss_leg(String("partial"), s)
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_terminal_partial_default_stop() raises:
    # Fixtures and pre-0.1.3 sessions carry no stop proof: unknown.
    var leg = terminal_loss_leg(String("partial"), StopState())
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)
    assert_equal(leg[2], UInt64(0))


def test_terminal_unavailable() raises:
    var leg = terminal_loss_leg(String("unavailable"), quiescence_stop())
    assert_equal(leg[0], True)
    assert_equal(leg[1], False)


def test_quiescence_predicate_direct() raises:
    assert_true(quiescence_only_spillover(quiescence_stop()))
    assert_true(not quiescence_only_spillover(StopState()))


def test_severity_bounded_zero_loss() raises:
    assert_equal(
        incomplete_finding_severity(String("partial_known_loss"), 0),
        String("informational"),
    )


def test_severity_known_loss_stays_warning() raises:
    assert_equal(
        incomplete_finding_severity(String("partial_known_loss"), 500),
        String("warning"),
    )


def test_severity_unknown_stays_warning() raises:
    assert_equal(
        incomplete_finding_severity(String("partial_unknown_loss"), 0),
        String("warning"),
    )


def test_severity_complete_stays_warning() raises:
    # A complete verdict with a finding means correlation-only
    # causes; attribution gaps stay warning until classified.
    assert_equal(
        incomplete_finding_severity(String("complete"), 0),
        String("warning"),
    )


def test_severity_unset_stays_warning() raises:
    assert_equal(
        incomplete_finding_severity(String(""), 0), String("warning")
    )


def test_verdict_partial_detail_zero_loss() raises:
    # Gaps observed but zero lost: bounded, yet not complete.
    var v = verdict_for_counts(True, True, UInt64(0), True, False, True, UInt64(0), UInt64(100))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def clean_session() -> Session:
    var s = Session()
    s.q_detail.status = String("complete_for_scope")
    s.q_detail.has_loss_count = True
    s.q_detail.loss_count = UInt64(0)
    s.q_terminal.status = String("complete_for_scope")
    s.stop.outcome = String("complete")
    return s^


def test_session_verdict_complete() raises:
    var v = verdict_for_session(clean_session(), UInt64(50))
    assert_equal(v.name, String("complete"))
    assert_equal(v.loss_ratio_bps, 0)


def test_session_verdict_producer_loss() raises:
    var s = clean_session()
    s.q_detail.status = String("partial")
    s.q_detail.loss_count = UInt64(5)
    var v = verdict_for_session(s, UInt64(95))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 500)


def test_session_verdict_no_stop_proof() raises:
    var s = clean_session()
    s.stop.outcome = String("partial")
    var v = verdict_for_session(s, UInt64(50))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_session_verdict_unknown_detail() raises:
    var s = clean_session()
    s.q_detail.status = String("partial")
    s.q_detail.has_loss_count = False
    var v = verdict_for_session(s, UInt64(10))
    assert_equal(v.name, String("partial_unknown_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def test_session_verdict_quiescence_only() raises:
    var s = clean_session()
    s.q_terminal.status = String("partial")
    s.stop = quiescence_stop()
    var v = verdict_for_session(s, UInt64(100))
    assert_equal(v.name, String("partial_known_loss"))
    assert_equal(v.loss_ratio_bps, 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_verdict_complete_clean]()
    suite.test[test_verdict_known_loss_ratio]()
    suite.test[test_verdict_unknown_detail_lower_bound]()
    suite.test[test_verdict_unknown_terminal]()
    suite.test[test_verdict_counters_disagree]()
    suite.test[test_verdict_quiescence_spillover_known]()
    suite.test[test_verdict_vacuous_zero_zero]()
    suite.test[test_verdict_ratio_truncates]()
    suite.test[test_verdict_terminal_known_loss]()
    suite.test[test_verdict_disagree_keeps_lower_bound]()
    suite.test[test_verdict_struct_defaults]()
    suite.test[test_terminal_complete_proved]()
    suite.test[test_terminal_complete_contradicted]()
    suite.test[test_terminal_quiescence_only]()
    suite.test[test_terminal_quiescence_busy]()
    suite.test[test_terminal_quiescence_spillover_short]()
    suite.test[test_terminal_quiescence_counters_bad]()
    suite.test[test_terminal_quiescence_late_submit]()
    suite.test[test_terminal_quiescence_drain_missing]()
    suite.test[test_terminal_quiescence_admission_open]()
    suite.test[test_terminal_quiescence_observed_other_cause]()
    suite.test[test_terminal_quiescence_over_budget]()
    suite.test[test_terminal_partial_default_stop]()
    suite.test[test_terminal_unavailable]()
    suite.test[test_quiescence_predicate_direct]()
    suite.test[test_verdict_partial_detail_zero_loss]()
    suite.test[test_session_verdict_complete]()
    suite.test[test_session_verdict_producer_loss]()
    suite.test[test_session_verdict_no_stop_proof]()
    suite.test[test_session_verdict_unknown_detail]()
    suite.test[test_session_verdict_quiescence_only]()
    suite.test[test_severity_bounded_zero_loss]()
    suite.test[test_severity_known_loss_stays_warning]()
    suite.test[test_severity_unknown_stays_warning]()
    suite.test[test_severity_complete_stays_warning]()
    suite.test[test_severity_unset_stays_warning]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
