# SPDX-License-Identifier: GPL-3.0-or-later

"""Attempt-analyzer unit tests: the A05 reducer over real captures.

The attempts/valid-* fixtures pin golden agreement on counts and
flags; the reader/* captures pin counter, loss, limit, and
finalization behavior.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.attempts import AttemptAnalyzer
from memveil.capture.normalize import device_id_for
from memveil.capture.reader import default_limits, read_capture
from memveil.model.event import Event
from memveil.model.metric import Finding, Metric
from memveil.model.report import ENGINE_VERSION, Report
from memveil.model.session import Session
from memveil.model.validate import checked_add, format_u64


def analyze(dir: String, allow: Bool) raises -> Report:
    var r = read_capture(dir, allow, default_limits())
    var a = AttemptAnalyzer(r.session)
    while r.has_more():
        a.consume(r.next_event())
    return a.finish(r.session.window_end_ns, r.partial)


def metric_by_name(report: Report, name: String, device: String) raises -> Metric:
    for i in range(len(report.metrics)):
        var m = report.metrics[i]
        if m.name != name:
            continue
        if device == "":
            if not m.has_device_id:
                return m^
        elif m.has_device_id and m.device_id == device:
            return m^
    raise Error("metric not found: " + name + " [" + device + "]")


def test_format_u64() raises:
    assert_equal(format_u64(UInt64(0)), "0")
    assert_equal(format_u64(UInt64(42)), "42")
    assert_equal(
        format_u64(UInt64(0xFFFFFFFFFFFFFFFF)), "18446744073709551615"
    )


def test_checked_add() raises:
    assert_equal(checked_add(UInt64(1), UInt64(2)), UInt64(3))
    assert_equal(
        checked_add(UInt64(0xFFFFFFFFFFFFFFFF), UInt64(0)),
        UInt64(0xFFFFFFFFFFFFFFFF),
    )
    var raised = False
    try:
        _ = checked_add(UInt64(0xFFFFFFFFFFFFFFFF), UInt64(1))
    except:
        raised = True
    assert_true(raised)


def test_reducer_attempts_fixture() raises:
    var rep = analyze(String("tests/fixtures/attempts"), False)
    assert_equal(rep.session_id, "attempts-3-session")
    assert_true(rep.synthetic)
    assert_equal(rep.engine_version, "memveil-0.1.0")
    assert_equal(ENGINE_VERSION, "memveil-0.1.0")
    assert_equal(len(rep.metrics), 14)
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_true(attempts.has_value)
    assert_equal(attempts.value, UInt64(3))
    assert_equal(attempts.unit, "count")
    assert_equal(attempts.measurement, "observed")
    assert_equal(attempts.coverage, "complete_for_scope")
    assert_equal(
        attempts.scope,
        "window [1000000000,4000000000), all devices, detail channel",
    )
    assert_equal(
        attempts.notes, "3 detail events; no counter snapshots to compare."
    )
    var dev = metric_by_name(rep, String("bounce_attempts"), String("dev-1"))
    assert_equal(dev.value, UInt64(3))
    assert_equal(dev.notes, "All 3 attempts observed device dev-1.")
    var bytes_all = metric_by_name(
        rep, String("requested_bounce_bytes"), String("")
    )
    assert_equal(bytes_all.value, UInt64(9216))
    assert_equal(
        bytes_all.notes,
        "4096 + 4096 + 1024 requested bytes across 3 attempts;"
        " allocation outcomes are unavailable in this fixture.",
    )
    var bytes_dev = metric_by_name(
        rep, String("requested_bounce_bytes"), String("dev-1")
    )
    assert_equal(bytes_dev.value, UInt64(9216))
    assert_equal(
        bytes_dev.notes, "4096 + 4096 + 1024 requested bytes on device dev-1."
    )
    var names = List[String]()
    names.append(String("successful_allocations"))
    names.append(String("copy_original_to_bounce_bytes"))
    names.append(String("copy_bounce_to_original_bytes"))
    names.append(String("live_observed_allocation_bytes"))
    names.append(String("observed_mapping_lifetime_ns"))
    names.append(String("conversion_request_bytes"))
    names.append(String("known_shared_region_bytes"))
    names.append(String("pool_used_bytes"))
    names.append(String("pool_capacity_bytes"))
    for name in names:
        var m = metric_by_name(rep, name, String(""))
        assert_true(not m.has_value)
        assert_equal(m.measurement, "unavailable")
        assert_equal(m.coverage, "unavailable")
    assert_equal(rep.q_detail.status, "complete_for_scope")
    assert_true(rep.q_detail.has_loss_count)
    assert_equal(rep.q_detail.loss_count, UInt64(0))
    assert_equal(rep.q_detail.scope, "3 bounce_attempt events")
    assert_equal(rep.q_detail.reason, "Authored fixture: no loss.")
    assert_equal(rep.q_aggregate.status, "unavailable")
    assert_equal(rep.q_correlation.status, "complete_for_scope")
    assert_equal(rep.q_baseline.status, "not_applicable")
    assert_equal(rep.q_terminal.status, "complete_for_scope")
    assert_equal(len(rep.findings), 0)
    assert_equal(len(rep.limitations), 3)
    assert_equal(
        rep.limitations[0],
        "Synthetic fixture: every value is authored test data;"
        " no guest was booted and no hook attached.",
    )
    assert_equal(
        rep.limitations[1],
        "This analyzer reduces bounce attempts and counter deltas only;"
        " lifecycle, copy, sync, conversion, region, pool, and task-context"
        " metrics are unavailable.",
    )
    assert_equal(
        rep.limitations[2],
        "No counter snapshots: attempt totals rest on the detail"
        " channel alone.",
    )


def test_reducer_device_dimensions() raises:
    var rep = analyze(String("tests/fixtures/reader/multidev"), False)
    var all_m = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(all_m.value, UInt64(3))
    var d1 = metric_by_name(rep, String("bounce_attempts"), String("dev-1"))
    var d2 = metric_by_name(rep, String("bounce_attempts"), String("dev-2"))
    assert_equal(d1.value, UInt64(2))
    assert_equal(d2.value, UInt64(1))
    assert_equal(d1.value + d2.value, all_m.value)
    assert_equal(d1.notes, "2 attempts observed device dev-1.")
    var b1 = metric_by_name(
        rep, String("requested_bounce_bytes"), String("dev-1")
    )
    var b2 = metric_by_name(
        rep, String("requested_bounce_bytes"), String("dev-2")
    )
    assert_equal(b1.value, UInt64(5120))
    assert_equal(b2.value, UInt64(2048))
    assert_equal(b1.notes, "4096 + 1024 requested bytes on device dev-1.")
    var seen_dev1 = -1
    var seen_dev2 = -1
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        if m.name == "bounce_attempts" and m.has_device_id:
            if m.device_id == "dev-1":
                seen_dev1 = i
            elif m.device_id == "dev-2":
                seen_dev2 = i
    assert_true(seen_dev1 >= 0)
    assert_true(seen_dev2 >= 0)
    assert_true(seen_dev1 < seen_dev2)


def aggregate_metric(rep: Report, name: String) raises -> Metric:
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        if m.name == name and m.scope.find(String("readings [")) == 0:
            return m^
    raise Error("aggregate metric not found: " + name)


def test_counter_deltas() raises:
    var rep = analyze(String("tests/fixtures/reader/counters"), False)
    var detail = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(detail.value, UInt64(3))
    var detail_bytes = metric_by_name(
        rep, String("requested_bounce_bytes"), String("")
    )
    assert_equal(detail_bytes.value, UInt64(9216))
    var agg = aggregate_metric(rep, String("counter_bounce_attempts"))
    assert_true(agg.has_value)
    assert_equal(agg.value, UInt64(3))
    assert_equal(agg.unit, "count")
    assert_equal(agg.measurement, "derived")
    assert_equal(agg.coverage, "complete_for_scope")
    assert_equal(agg.aggregation, "counter")
    assert_equal(
        agg.notes,
        "Counter delta 10 -> 13 (swiotlb.bounce_attempts);"
        " detail events counted separately (never added).",
    )
    var agg_bytes = aggregate_metric(
        rep, String("counter_requested_bounce_bytes")
    )
    assert_equal(agg_bytes.value, UInt64(9216))
    assert_equal(agg_bytes.unit, "bytes")
    assert_equal(agg_bytes.measurement, "derived")
    assert_equal(rep.q_aggregate.status, "complete_for_scope")
    for i in range(len(rep.limitations)):
        assert_true(rep.limitations[i] != (
            "No counter snapshots: attempt totals rest on the detail"
            " channel alone."
        ))


def test_counter_unusable() raises:
    var epoch = analyze(
        String("tests/fixtures/reader/counters-epoch"), False
    )
    assert_equal(len(epoch.metrics), 12)
    assert_equal(
        epoch.limitations[len(epoch.limitations) - 1],
        "Counter swiotlb.bounce_attempts (all devices): epoch changed"
        " 3 -> 4; no delta computed.",
    )
    var single = analyze(
        String("tests/fixtures/reader/counters-single"), False
    )
    assert_equal(
        single.limitations[len(single.limitations) - 1],
        "Counter swiotlb.bounce_attempts (all devices): single snapshot;"
        " no pair for a delta.",
    )
    var decrease = analyze(
        String("tests/fixtures/reader/counters-decrease"), False
    )
    assert_equal(
        decrease.limitations[len(decrease.limitations) - 1],
        "Counter swiotlb.bounce_attempts (all devices): value decreased"
        " 13 -> 10 within epoch 3; no delta computed.",
    )
    var scope = analyze(
        String("tests/fixtures/reader/counters-scope"), False
    )
    assert_equal(
        scope.limitations[len(scope.limitations) - 2],
        "Counter swiotlb.bounce_attempts (device dev-1): single snapshot;"
        " no pair for a delta.",
    )
    assert_equal(
        scope.limitations[len(scope.limitations) - 1],
        "Counter swiotlb.bounce_attempts (device dev-2): single snapshot;"
        " no pair for a delta.",
    )
    assert_equal(epoch.q_aggregate.status, "partial")


def test_counter_unknown_id() raises:
    var rep = analyze(
        String("tests/fixtures/reader/counters-unknown"), False
    )
    assert_equal(len(rep.metrics), 12)
    assert_equal(rep.q_aggregate.status, "partial")
    assert_equal(
        rep.limitations[len(rep.limitations) - 1],
        "Counter vendor.mystery (all devices): unknown counter id;"
        " no metric mapping.",
    )
    var found = False
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        if m.name == "counter_vendor.mystery":
            found = True
    assert_true(not found)


def test_counter_same_scope_collapse() raises:
    var rep = analyze(
        String("tests/fixtures/reader/counters-collapse"), False
    )
    var agg = aggregate_metric(rep, String("counter_bounce_attempts"))
    assert_equal(agg.value, UInt64(3))
    assert_equal(agg.measurement, "derived")
    assert_equal(len(rep.metrics), 13)
    assert_equal(
        rep.limitations[len(rep.limitations) - 1],
        "Additional swiotlb.bounce_attempts group (all devices, profile"
        " synthetic-attempts-2) excluded from metrics; one row per name"
        " and dimensions.",
    )


def test_detail_loss() raises:
    var rep = analyze(String("tests/fixtures/reader/detail-gap"), False)
    assert_equal(rep.q_detail.status, "partial")
    assert_true(rep.q_detail.has_loss_count)
    assert_equal(rep.q_detail.loss_count, UInt64(2))
    assert_equal(rep.q_detail.scope, "2 bounce_attempt events, 1 detail gap")
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(attempts.value, UInt64(2))
    assert_equal(attempts.coverage, "partial")
    assert_equal(len(rep.findings), 1)
    assert_equal(rep.findings[0].code, "CAPTURE_INCOMPLETE")
    assert_equal(rep.findings[0].severity, "warning")
    assert_equal(
        rep.limitations[len(rep.limitations) - 1],
        "Detail loss: 1 gap event (2 lost); attempt counts are lower bounds.",
    )
    var unknown = analyze(
        String("tests/fixtures/reader/detail-gap-unknown"), False
    )
    assert_equal(unknown.q_detail.status, "partial")
    assert_true(not unknown.q_detail.has_loss_count)
    assert_equal(
        unknown.limitations[len(unknown.limitations) - 1],
        "Detail loss: 1 gap event (unknown lost);"
        " attempt counts are lower bounds.",
    )


def test_partial_and_unfinalized() raises:
    var r = read_capture(
        String("tests/fixtures/reader/partial-tail"), True, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    while r.has_more():
        a.consume(r.next_event())
    var rep = a.finish(r.session.window_end_ns, r.partial)
    assert_true(r.partial)
    assert_equal(rep.q_terminal.status, "partial")
    assert_true(not rep.q_terminal.has_loss_count)
    assert_equal(len(rep.findings), 1)
    assert_equal(rep.findings[0].code, "CAPTURE_INCOMPLETE")
    var clean = analyze(String("tests/fixtures/attempts"), False)
    assert_equal(clean.q_terminal.status, "complete_for_scope")
    var r2 = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var forced = AttemptAnalyzer(r2.session)
    var rep_forced = forced.finish(UInt64(4000000000), True)
    assert_equal(rep_forced.q_terminal.status, "partial")
    var unfin = analyze(String("tests/fixtures/reader/unfinalized"), False)
    assert_equal(unfin.q_terminal.status, "partial")
    assert_equal(len(unfin.findings), 1)


def test_empty_capture() raises:
    var rep = analyze(String("tests/fixtures/reader/empty-events"), False)
    assert_equal(len(rep.metrics), 12)
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_true(attempts.has_value)
    assert_equal(attempts.value, UInt64(0))
    assert_equal(attempts.coverage, "complete_for_scope")
    assert_equal(
        attempts.notes, "0 detail events; no counter snapshots to compare."
    )
    assert_equal(len(rep.findings), 0)


def test_requested_bytes_overflow() raises:
    # The reader rejects overflowing streams, so the analyzer's own
    # overflow guard is fed synthetic events directly here.
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    for _ in range(2):
        var ev = Event()
        ev.kind = String("bounce_attempt")
        ev.bounce.device_id = String("dev-1")
        ev.bounce.requested_bytes = UInt64(0xFFFFFFFFFFFFFFFF)
        a.consume(ev)
    var rep = a.finish(r.session.window_end_ns, False)
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(attempts.value, UInt64(2))
    var bytes_all = metric_by_name(
        rep, String("requested_bounce_bytes"), String("")
    )
    assert_true(not bytes_all.has_value)
    assert_equal(bytes_all.measurement, "unavailable")
    assert_equal(
        rep.limitations[len(rep.limitations) - 1],
        "Requested-byte total exceeds u64 range; values withheld.",
    )


def bounce_event(device: String, op: String, req: UInt64) -> Event:
    var ev = Event()
    ev.kind = String("bounce_attempt")
    ev.bounce.device_id = device
    ev.bounce.operation_id = op
    ev.bounce.requested_bytes = req
    return ev^


def snapshot_event(
    counter: String,
    device: String,
    profile: String,
    epoch: UInt64,
    value: UInt64,
) -> Event:
    var ev = Event()
    ev.kind = String("counter_snapshot")
    ev.snapshot.counter_id = counter
    ev.snapshot.has_scope_device = True
    ev.snapshot.scope_device_id = device
    ev.snapshot.scope_profile_id = profile
    ev.snapshot.epoch = epoch
    ev.snapshot.value = value
    ev.snapshot.unit = String("count")
    return ev^


def has_limitation(rep: Report, needle: String) -> Bool:
    for i in range(len(rep.limitations)):
        if rep.limitations[i].find(needle) != -1:
            return True
    return False


def test_tail_metric_count_pinned() raises:
    var rep = analyze(String("tests/fixtures/attempts"), False)
    assert_equal(len(rep.metrics), 14)
    var names = List[String]()
    names.append(String("successful_allocations"))
    names.append(String("copy_original_to_bounce_bytes"))
    names.append(String("copy_bounce_to_original_bytes"))
    names.append(String("live_observed_allocation_bytes"))
    names.append(String("observed_mapping_lifetime_ns"))
    names.append(String("conversion_request_bytes"))
    names.append(String("known_shared_region_bytes"))
    names.append(String("pool_used_bytes"))
    names.append(String("pool_capacity_bytes"))
    for i in range(9):
        assert_equal(rep.metrics[4 + i].name, names[i])


def test_device_admission_bound() raises:
    # Metric-budget contract: the analyzer never raises
    # past the device budget. Per-device detail rows are
    # withheld with a limitation note (counter-row
    # precedent) so every 4096-device capture replays with
    # exact globals. 2041 devices keep full detail and
    # both aggregate rows; the rest keep exact global
    # accounting without per-device rows.
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    for i in range(2041):
        a.consume(bounce_event(String("dev-") + String(i), String("op-") + String(i), UInt64(8)))
    var rep = a.finish(r.session.window_end_ns, False)
    assert_equal(len(rep.metrics), 2 + 2 * 2041 + 10)
    assert_true(not has_limitation(rep, String("lack detail rows")))
    var b = AttemptAnalyzer(r.session)
    for i in range(2042):
        b.consume(bounce_event(String("dev-") + String(i), String("op-") + String(i), UInt64(8)))
    var rep2 = b.finish(r.session.window_end_ns, False)
    assert_true(
        has_limitation(rep2, String("1 device lacks detail rows"))
    )
    var all_m = metric_by_name(rep2, String("bounce_attempts"), String(""))
    assert_equal(all_m.value, UInt64(2042))
    assert_true(len(rep2.metrics) <= 4096)


def test_counter_budget_withheld() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    for i in range(2041):
        a.consume(bounce_event(String("dev-") + String(i), String("op-") + String(i), UInt64(8)))
    for g in range(4):
        var dev = String("dev-") + String(g + 1)
        a.consume(
            snapshot_event(
                String("swiotlb.bounce_attempts"), dev,
                String("p"), UInt64(3), UInt64(10),
            )
        )
        a.consume(
            snapshot_event(
                String("swiotlb.bounce_attempts"), dev,
                String("p"), UInt64(3), UInt64(13),
            )
        )
    var rep = a.finish(r.session.window_end_ns, False)
    assert_equal(len(rep.metrics), 4096)
    assert_true(
        has_limitation(
            rep, String("2 counter deltas withheld: metric budget exhausted.")
        )
    )
    assert_true(not has_limitation(rep, String("lack detail rows")))


def test_counter_groups_ignored() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    for i in range(4097):
        a.consume(
            snapshot_event(
                String("vendor.flood-") + String(i), String("dev-1"),
                String("p"), UInt64(3), UInt64(10),
            )
        )
    var rep = a.finish(r.session.window_end_ns, False)
    assert_equal(len(rep.limitations), 256)
    assert_true(
        has_limitation(
            rep, String("1 counter reading ignored: admission bound reached.")
        )
    )
    assert_true(
        has_limitation(rep, String("further limitations withheld."))
    )
    assert_equal(rep.q_aggregate.status, "partial")
    assert_true(not rep.q_aggregate.has_loss_count)
    assert_true(
        rep.q_aggregate.reason.find(String("admission bound reached.")) != -1
    )


def gap_event(
    channel: String,
    lost: UInt64,
    ws: UInt64,
    we: UInt64,
) -> Event:
    var ev = Event()
    ev.kind = String("gap")
    ev.gap.channel = channel
    ev.gap.has_lost_count = True
    ev.gap.lost_count = lost
    ev.gap.window_start_ns = ws
    ev.gap.window_end_ns = we
    return ev^


def test_f8_terminal_gap() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f8-terminal-gap"), False
    )
    assert_equal(rep.q_terminal.status, "partial")
    assert_true(not rep.q_terminal.has_loss_count)
    assert_equal(len(rep.findings), 1)
    assert_true(
        rep.findings[0].explanation.find(String("terminal gap observed"))
        != -1
    )


def test_f8_aggregate_gap() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f8-aggregate-gap"), False
    )
    assert_equal(rep.q_aggregate.status, "partial")
    assert_true(rep.q_aggregate.has_loss_count)
    assert_equal(rep.q_aggregate.loss_count, UInt64(7))


def test_f8_detail_producer_loss() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f8-detail-producer-loss"), False
    )
    assert_equal(rep.q_detail.status, "complete_for_scope")
    assert_true(rep.q_detail.has_loss_count)
    assert_equal(rep.q_detail.loss_count, UInt64(9))
    assert_true(rep.q_detail.reason.find(String("(loss 9)")) != -1)


def test_f8_partial_detail() raises:
    var rep = analyze(
        String("tests/fixtures/reader/partial-tail"), True
    )
    assert_equal(rep.q_detail.status, "partial")
    assert_true(not rep.q_detail.has_loss_count)
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(attempts.coverage, "partial")
    assert_true(attempts.notes.find(String("truncated tail excluded")) != -1)


def test_f8_gap_overlap() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    a.consume(gap_event(String("detail"), UInt64(5), UInt64(10), UInt64(20)))
    a.consume(gap_event(String("detail"), UInt64(7), UInt64(15), UInt64(25)))
    var rep = a.finish(r.session.window_end_ns, False)
    assert_equal(rep.q_detail.status, "partial")
    assert_true(not rep.q_detail.has_loss_count)
    assert_true(
        rep.q_detail.reason.find(String("Loss total unknown")) != -1
    )
    var b = AttemptAnalyzer(r.session)
    b.consume(gap_event(String("detail"), UInt64(5), UInt64(10), UInt64(20)))
    b.consume(gap_event(String("detail"), UInt64(7), UInt64(20), UInt64(30)))
    var rep2 = b.finish(r.session.window_end_ns, False)
    assert_true(rep2.q_detail.has_loss_count)
    assert_equal(rep2.q_detail.loss_count, UInt64(12))


def test_f9_mismatch() raises:
    var rep = analyze(String("tests/fixtures/reader/f9-mismatch"), False)
    assert_true(rep.counter_disagreement)
    assert_equal(len(rep.findings), 1)
    assert_true(
        rep.findings[0].explanation.find(
            String("counter cross-check disagrees")
        )
        != -1
    )
    assert_true(
        rep.findings[0].explanation.find(String("detail 3 vs counter delta 8"))
        != -1
    )
    var row = metric_by_name(
        rep, String("counter_bounce_attempts"), String("")
    )
    assert_equal(
        row.scope,
        "readings [1050000000,1350000000), all devices, aggregate channel",
    )
    assert_equal(row.coverage, "complete_for_scope")


def test_f9_agree() raises:
    var rep = analyze(String("tests/fixtures/reader/f9-agree"), False)
    assert_true(not rep.counter_disagreement)
    assert_equal(len(rep.findings), 0)


def test_f9_inconclusive() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f9-inconclusive-scope"), False
    )
    assert_true(not rep.counter_disagreement)
    assert_true(
        has_limitation(
            rep, String("1 counter comparison inconclusive;")
        )
    )
    var rep2 = analyze(
        String("tests/fixtures/reader/f9-inconclusive-loss"), False
    )
    assert_true(not rep2.counter_disagreement)
    assert_equal(rep2.q_detail.status, "partial")
    assert_true(
        has_limitation(
            rep2, String("1 counter comparison inconclusive;")
        )
    )


def test_f9_unit_mismatch() raises:
    var rep = analyze(String("tests/fixtures/reader/f9-unit"), False)
    assert_true(not rep.counter_disagreement)
    assert_true(
        has_limitation(
            rep,
            String(
                "unit mismatch: expected count, observed bytes;"
                " no delta computed"
            ),
        )
    )
    var found = False
    for i in range(len(rep.metrics)):
        if rep.metrics[i].name == "counter_bounce_attempts":
            found = True
    assert_true(not found)


def test_f9_partial_detail_coverage() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f9-partial-detail"), False
    )
    var row = metric_by_name(
        rep, String("counter_bounce_attempts"), String("")
    )
    assert_equal(row.coverage, "partial")


def test_f9_device_and_source() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    var b1 = bounce_event(String("dev-1"), String("op-1"), UInt64(8))
    b1.ts_ns = UInt64(1100000000)
    b1.source_measurement = String("observed")
    a.consume(b1)
    var s1 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-1"),
        String("p"), UInt64(3), UInt64(0),
    )
    s1.ts_ns = UInt64(1050000000)
    s1.source_measurement = String("observed")
    a.consume(s1)
    var s2 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-1"),
        String("p"), UInt64(3), UInt64(9),
    )
    s2.ts_ns = UInt64(1350000000)
    s2.source_measurement = String("observed")
    a.consume(s2)
    var rep = a.finish(r.session.window_end_ns, False)
    assert_true(rep.counter_disagreement)
    assert_true(
        rep.findings[0].explanation.find(String("(device dev-1)")) != -1
    )
    var c = AttemptAnalyzer(r.session)
    var b2 = bounce_event(String("dev-1"), String("op-1"), UInt64(8))
    b2.ts_ns = UInt64(1100000000)
    b2.source_measurement = String("estimated")
    c.consume(b2)
    var s3 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-1"),
        String("p"), UInt64(3), UInt64(0),
    )
    s3.ts_ns = UInt64(1050000000)
    s3.source_measurement = String("observed")
    c.consume(s3)
    var s4 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-1"),
        String("p"), UInt64(3), UInt64(9),
    )
    s4.ts_ns = UInt64(1350000000)
    s4.source_measurement = String("observed")
    c.consume(s4)
    var rep2 = c.finish(r.session.window_end_ns, False)
    assert_true(not rep2.counter_disagreement)
    assert_true(
        has_limitation(
            rep2, String("1 counter comparison inconclusive;")
        )
    )


def test_f13_literal_filter_scope() raises:
    var rep = analyze(String("tests/fixtures/reader/literal-filter"), False)
    var row = metric_by_name(
        rep, String("bounce_attempts"), String("")
    )
    assert_true(
        row.scope.find(String("recorded devices (filter: testdev0)"))
        != -1
    )
    assert_true(row.scope.find(String("all devices")) == -1)
    var plain = analyze(String("tests/fixtures/attempts"), False)
    var prow = metric_by_name(
        plain, String("bounce_attempts"), String("")
    )
    assert_true(prow.scope.find(String("all devices")) != -1)


def test_f9_profile_split() raises:
    var rep = analyze(String("tests/fixtures/reader/f9-profile-change"), False)
    assert_true(not rep.counter_disagreement)
    assert_equal(len(rep.findings), 0)
    var singles = 0
    for i in range(len(rep.limitations)):
        if rep.limitations[i].find(String("single snapshot")) != -1:
            singles += 1
    assert_equal(singles, 2)
    assert_equal(rep.q_aggregate.status, "partial")


def test_f9_filtered_global() raises:
    var rep = analyze(String("tests/fixtures/reader/f9-filtered-global"), False)
    assert_true(not rep.counter_disagreement)
    assert_equal(len(rep.findings), 0)
    assert_true(
        has_limitation(
            rep, String("1 counter comparison inconclusive;")
        )
    )
    var row = metric_by_name(
        rep, String("counter_bounce_attempts"), String("")
    )
    assert_true(row.scope.find(String("all devices")) != -1)
    assert_true(row.scope.find(String("filter:")) == -1)
    var head = metric_by_name(
        rep, String("bounce_attempts"), String("")
    )
    assert_true(head.scope.find(String("filter: testdev0")) != -1)


def test_f9_device_needs_span() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var a = AttemptAnalyzer(r.session)
    var b1 = bounce_event(String("dev-1"), String("op-1"), UInt64(8))
    b1.ts_ns = UInt64(1100000000)
    b1.source_measurement = String("observed")
    a.consume(b1)
    var s1 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-2"),
        String("p"), UInt64(3), UInt64(0),
    )
    s1.ts_ns = UInt64(1050000000)
    s1.source_measurement = String("observed")
    a.consume(s1)
    var s2 = snapshot_event(
        String("swiotlb.bounce_attempts"), String("dev-2"),
        String("p"), UInt64(3), UInt64(9),
    )
    s2.ts_ns = UInt64(1350000000)
    s2.source_measurement = String("observed")
    a.consume(s2)
    var rep = a.finish(r.session.window_end_ns, False)
    assert_true(not rep.counter_disagreement)
    assert_true(
        has_limitation(
            rep, String("1 counter comparison inconclusive;")
        )
    )


def test_f8_corr_baseline_gaps() raises:
    var rep = analyze(
        String("tests/fixtures/reader/f8-correlation-gap"), False
    )
    assert_equal(rep.q_correlation.status, "partial")
    assert_true(not rep.q_correlation.has_loss_count)
    var rep2 = analyze(
        String("tests/fixtures/reader/f8-baseline-gap"), False
    )
    assert_equal(rep2.q_baseline.status, "partial")
    assert_true(not rep2.q_baseline.has_loss_count)


def test_detail_unavailable_observed_zero() raises:
    var rep = analyze(
        String("tests/fixtures/reader/unavailable-detail"), False
    )
    assert_equal(rep.q_detail.status, "unavailable")
    var attempts = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_true(attempts.has_value)
    assert_equal(attempts.value, UInt64(0))
    assert_equal(attempts.measurement, "observed")
    assert_equal(attempts.coverage, "unavailable")
    assert_equal(
        attempts.notes,
        "0 detail events observed; producer status unavailable:"
        " zero is unconfirmed.",
    )
    var bytes_all = metric_by_name(
        rep, String("requested_bounce_bytes"), String("")
    )
    assert_true(bytes_all.has_value)
    assert_equal(bytes_all.value, UInt64(0))
    assert_equal(bytes_all.coverage, "unavailable")


def test_finish_horizon() raises:
    var r = read_capture(
        String("tests/fixtures/attempts"), False, default_limits()
    )
    var bad = List[UInt64]()
    bad.append(UInt64(999))
    bad.append(UInt64(4000000001))
    bad.append(UInt64(2500000000))
    bad.append(UInt64(1000000000))
    for i in range(len(bad)):
        var raised = False
        try:
            var a = AttemptAnalyzer(r.session)
            _ = a.finish(bad[i], False)
        except:
            raised = True
        assert_true(raised)
    var ok = AttemptAnalyzer(r.session)
    var rep = ok.finish(UInt64(4000000000), False)
    assert_equal(rep.window_end_ns, UInt64(4000000000))


def _many_device_report(ndevs: Int) raises -> Report:
    """Reduce one single-event attempt per device id."""
    var s = Session()
    s.session_id = String("many-devices")
    s.synthetic = False
    s.product_version = String("0.0.0")
    s.env_mode = String("unknown")
    s.env_detection = String("unverified")
    s.env_attestation = String("not_performed")
    s.capture_mode = String("live")
    s.window_start_ns = UInt64(0)
    s.window_end_ns = UInt64(1000000000)
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
    s.q_correlation.status = String("not_applicable")
    s.q_correlation.scope = String("sc")
    s.q_correlation.reason = String("rs")
    s.q_baseline.status = String("not_applicable")
    s.q_baseline.scope = String("sc")
    s.q_baseline.reason = String("rs")
    s.q_terminal.status = String("partial")
    s.q_terminal.scope = String("sc")
    s.q_terminal.reason = String("rs")
    var a = AttemptAnalyzer(s)
    for pair in range(2):
        var counter = String("swiotlb.bounce_attempts")
        var unit = String("count")
        var total = UInt64(ndevs)
        if pair == 1:
            counter = String("swiotlb.requested_bytes")
            unit = String("bytes")
            total = UInt64(ndevs) * UInt64(8)
        for end in range(2):
            var snap = Event()
            snap.kind = String("counter_snapshot")
            snap.source_measurement = String("observed")
            snap.snapshot.counter_id = counter
            snap.snapshot.has_scope_device = False
            snap.snapshot.scope_profile_id = String("p")
            snap.snapshot.epoch = UInt64(0)
            snap.snapshot.unit = unit
            if end == 0:
                snap.ts_ns = UInt64(0)
                snap.snapshot.value = UInt64(0)
            else:
                snap.ts_ns = UInt64(999999999)
                snap.snapshot.value = total
            a.consume(snap)
    for d in range(ndevs):
        var ev = Event()
        ev.session_id = String("many-devices")
        ev.seq = UInt64(d)
        ev.ts_ns = UInt64(d + 1)
        ev.kind = String("bounce_attempt")
        ev.source_hook = String("h")
        ev.source_backend = String("tracepoint")
        ev.source_profile_id = String("p")
        ev.source_measurement = String("observed")
        ev.source_correlation = String("direct")
        ev.bounce.device_id = device_id_for(d + 1)
        ev.bounce.requested_bytes = UInt64(8)
        ev.bounce.forced = False
        ev.bounce.operation_id = (
            String("op") + format_u64(UInt64(d))
        )
        a.consume(ev)
    return a.finish(UInt64(1000000000), False)


def test_many_devices_2041_clean() raises:
    var rep = _many_device_report(2041)
    assert_true(not has_limitation(rep, String("lack detail rows")))
    var all_m = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(all_m.value, UInt64(2041))
    var last = metric_by_name(
        rep, String("bounce_attempts"), String("d002041")
    )
    assert_equal(last.value, UInt64(1))
    var cnt = metric_by_name(
        rep, String("counter_bounce_attempts"), String("")
    )
    assert_equal(cnt.value, UInt64(2041))
    var byt = metric_by_name(
        rep, String("counter_requested_bounce_bytes"), String("")
    )
    assert_equal(byt.value, UInt64(2041) * UInt64(8))
    assert_true(not rep.counter_disagreement)
    assert_true(len(rep.metrics) <= 4096)


def test_many_devices_2042_withheld() raises:
    var rep = _many_device_report(2042)
    assert_true(
        has_limitation(rep, String("1 device lacks detail rows"))
    )
    var all_m = metric_by_name(rep, String("bounce_attempts"), String(""))
    assert_equal(all_m.value, UInt64(2042))
    var cnt = metric_by_name(
        rep, String("counter_bounce_attempts"), String("")
    )
    assert_equal(cnt.value, UInt64(2042))
    var byt = metric_by_name(
        rep, String("counter_requested_bounce_bytes"), String("")
    )
    assert_equal(byt.value, UInt64(2042) * UInt64(8))
    assert_true(not rep.counter_disagreement)
    assert_true(len(rep.metrics) <= 4096)
    var found = False
    for i in range(len(rep.metrics)):
        if rep.metrics[i].has_device_id:
            if rep.metrics[i].device_id == String("d002042"):
                found = True
    assert_true(not found)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_format_u64]()
    suite.test[test_checked_add]()
    suite.test[test_reducer_attempts_fixture]()
    suite.test[test_reducer_device_dimensions]()
    suite.test[test_counter_deltas]()
    suite.test[test_counter_unusable]()
    suite.test[test_counter_unknown_id]()
    suite.test[test_counter_same_scope_collapse]()
    suite.test[test_detail_loss]()
    suite.test[test_partial_and_unfinalized]()
    suite.test[test_empty_capture]()
    suite.test[test_requested_bytes_overflow]()
    suite.test[test_tail_metric_count_pinned]()
    suite.test[test_device_admission_bound]()
    suite.test[test_counter_budget_withheld]()
    suite.test[test_counter_groups_ignored]()
    suite.test[test_f8_terminal_gap]()
    suite.test[test_f8_aggregate_gap]()
    suite.test[test_f8_detail_producer_loss]()
    suite.test[test_f8_partial_detail]()
    suite.test[test_f8_gap_overlap]()
    suite.test[test_f8_corr_baseline_gaps]()
    suite.test[test_f9_mismatch]()
    suite.test[test_f9_agree]()
    suite.test[test_f9_inconclusive]()
    suite.test[test_f9_unit_mismatch]()
    suite.test[test_f9_partial_detail_coverage]()
    suite.test[test_f9_device_and_source]()
    suite.test[test_f9_profile_split]()
    suite.test[test_f9_filtered_global]()
    suite.test[test_f9_device_needs_span]()
    suite.test[test_f13_literal_filter_scope]()
    suite.test[test_detail_unavailable_observed_zero]()
    suite.test[test_finish_horizon]()
    suite.test[test_many_devices_2041_clean]()
    suite.test[test_many_devices_2042_withheld]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
