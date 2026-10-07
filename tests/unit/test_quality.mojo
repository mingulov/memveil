# SPDX-License-Identifier: GPL-3.0-or-later

"""Loss-channel unit tests: the detail/aggregate quality matrix.

Detail events and counter deltas are alternative measurements,
never additive totals: intact counters survive detail loss,
intact detail survives a counter reset, a missing release
withholds live totals without inventing a leak, and unknown
loss stays null with a reason instead of a reassuring zero.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.attempts import AttemptAnalyzer
from memveil.analysis.mappings import MappingTracker
from memveil.capture.reader import default_limits, read_capture
from memveil.model.metric import Metric
from memveil.model.report import Report


def analyze(dir: String) raises -> Report:
    var r = read_capture(dir, False, default_limits())
    var a = AttemptAnalyzer(r.session)
    while r.has_more():
        a.consume(r.next_event())
    return a.finish(r.session.window_end_ns, r.partial)


def map_metrics(dir: String) raises -> List[Metric]:
    var r = read_capture(dir, False, default_limits())
    var t = MappingTracker()
    while r.has_more():
        t.consume(r.next_event())
    return t.metrics("window [0,2500000000)")


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


def test_counters_survive_detail_loss() raises:
    var rep = analyze(
        String("tests/fixtures/reader/quality-detail-counters")
    )
    assert_equal(rep.q_detail.status, "partial")
    assert_true(rep.q_detail.has_loss_count)
    assert_equal(rep.q_detail.loss_count, UInt64(2))
    var detail = _global(rep.metrics, String("bounce_attempts"))
    assert_equal(detail.value, UInt64(2))
    assert_equal(detail.coverage, "partial")
    var agg = _global(rep.metrics, String("counter_bounce_attempts"))
    assert_true(agg.has_value)
    assert_equal(agg.value, UInt64(3))
    assert_equal(agg.measurement, "derived")
    assert_equal(rep.q_aggregate.status, "complete_for_scope")


def test_detail_survives_counter_reset() raises:
    var rep = analyze(
        String("tests/fixtures/reader/quality-reset-detail-ok")
    )
    assert_equal(rep.q_detail.status, "complete_for_scope")
    var detail = _global(rep.metrics, String("bounce_attempts"))
    assert_equal(detail.value, UInt64(2))
    assert_equal(detail.coverage, "complete_for_scope")
    assert_equal(rep.q_aggregate.status, "partial")
    var found = False
    for i in range(len(rep.metrics)):
        if rep.metrics[i].name == "counter_bounce_attempts":
            found = True
    assert_true(not found)


def test_unknown_loss_stays_null_with_reason() raises:
    var rep = analyze(
        String("tests/fixtures/reader/detail-gap-unknown")
    )
    assert_equal(rep.q_detail.status, "partial")
    assert_true(not rep.q_detail.has_loss_count)
    var attempts = _global(rep.metrics, String("bounce_attempts"))
    assert_equal(attempts.value, UInt64(1))
    assert_equal(attempts.coverage, "partial")
    assert_equal(
        rep.limitations[len(rep.limitations) - 1],
        "Detail loss: 1 gap event (unknown lost);"
        " attempt counts are lower bounds.",
    )


def test_open_mapping_censored_not_leaked() raises:
    var rows = map_metrics(
        String("tests/fixtures/lifecycle/open-at-end")
    )
    var live = _global(rows, String("live_observed_allocation_bytes"))
    assert_true(live.has_value)
    assert_equal(live.value, UInt64(4096))
    var count = _global(rows, String("completed_lifetime_count"))
    assert_true(not count.has_value)


def test_gap_with_open_mapping_withholds_live() raises:
    var rows = map_metrics(
        String("tests/fixtures/lifecycle/quality-gap-open")
    )
    var live = _global(rows, String("live_observed_allocation_bytes"))
    assert_true(not live.has_value)
    var count = _global(rows, String("completed_lifetime_count"))
    assert_true(not count.has_value)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_counters_survive_detail_loss]()
    suite.test[test_detail_survives_counter_reset]()
    suite.test[test_unknown_loss_stays_null_with_reason]()
    suite.test[test_open_mapping_censored_not_leaked]()
    suite.test[test_gap_with_open_mapping_withholds_live]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
