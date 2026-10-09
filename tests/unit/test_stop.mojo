# SPDX-License-Identifier: GPL-3.0-or-later

"""Stop-protocol unit tests: explicit terminal evidence.

The stop controller closes admission, settles admitted writer
activity, drains to a proved transport boundary, samples
counters, and finalizes. Every path yields either proved
complete evidence or explicit partial evidence within the stop
budget; a quiet ring alone never proves completion, and open
logical mappings never block callback quiescence.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
    snap_ok,
    stats_ok,
)
from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    PollOut,
)
from memveil.capture.stop import (
    STOP_BUDGET_MS,
    StopController,
    StopError,
)
from memveil.model.session import Session, parse_session
from memveil.platform.outcome import OpOut
from memveil.platform.reader import read_host_file


def _stop_mkdtemp() raises -> String:
    var template = String("/tmp/memveil-stop-XXXXXX")
    var buf = List[UInt8]()
    for b in template.as_bytes():
        buf.append(b)
    buf.append(UInt8(0))
    var p = external_call["mkdtemp", UInt64](Span(buf).unsafe_ptr())
    if p == UInt64(0):
        raise Error("mkdtemp failed")
    var raw = List[UInt8]()
    for i in range(len(buf)):
        if buf[i] == UInt8(0):
            break
        raw.append(buf[i])
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("mkdtemp gave non-UTF8")


def _stop_timeout() -> PollOut:
    return PollOut(String("timeout"), List[UInt8](), UInt32(0), String(""))


def _stop_batch() -> PollOut:
    # The close-out drain discards payloads without
    # decoding, so any frame bytes drain-count.
    var frame = List[UInt8]()
    for _ in range(64):
        frame.append(UInt8(0))
    return PollOut(String("batch"), frame^, UInt32(0), String(""))


def _stop_zeros(mut kernel: ScriptKernel, nstats: Int, nsnaps: Int):
    var zstats = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    for _ in range(nstats):
        kernel.add_stats(zstats.copy())
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(nsnaps):
        kernel.add_snap(zsnap.copy())


def _stop_session(cap: String) raises -> Session:
    var raw = read_host_file(
        cap + String("/session.json"), String("session"), 8388608
    )
    return parse_session(raw^)


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


def test_failed_admission_close_partial() raises:
    # A failed admission close finalizes partial with its
    # own reason, not as unproven quiescence.
    var ctl = StopController()
    ctl.mark_ready()
    ctl.fail_close()
    ctl.drain(0, False)
    ctl.sample_counters(True)
    var ev = ctl.finalize_over_budget(10, 0)
    assert_equal(ev.outcome, String("partial"))
    assert_equal(ev.reason, String("admission close failed"))
    assert_true(not ev.admission_closed)


def test_closeout_records_stop_evidence() raises:
    # A scripted full run records exact terminal stop
    # evidence: admission closed, quiescence unproven (no
    # kernel protocol observes it), three drained batches,
    # valid end counters, exit 4.
    var tmp = _stop_mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(0)
    cfg.max_events_bytes = 134217728
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("stop-evidence-probe")
    cfg.pid = 4242
    var kernel = ScriptKernel()
    kernel.add_poll(_stop_batch(), 3)
    kernel.add_poll(_stop_timeout(), 300)
    # Stats order: startup, two drain reads, drain
    # snapshot, confirm final. The final carries the
    # three drained batches (received = delivered, none
    # staged) so loss closure holds.
    _stop_zeros(kernel, 4, 4)
    kernel.add_stats(
        stats_ok(
            UInt64(3), UInt64(3), UInt64(0), UInt64(0), UInt64(0)
        )
    )
    _stop_zeros(kernel, 3, 0)
    var clock = ScriptClock()
    clock.add(UInt64(1000000000))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(cfg^)
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, 4)
    assert_equal(result.end_reason, String("duration"))
    var parsed = False
    var s = Session()
    try:
        s = _stop_session(tmp + String("/cap"))
        parsed = True
    except:
        parsed = False
    assert_true(parsed)
    assert_equal(s.stop.outcome, String("partial"))
    assert_equal(s.stop.reason, String("quiescence unproven"))
    assert_equal(s.stop.budget_ms, UInt64(5000))
    assert_true(s.stop.elapsed_ms <= UInt64(5000))
    assert_true(s.stop.admission_closed)
    assert_true(not s.stop.quiescence_observed)
    assert_equal(s.stop.writers_settled, UInt64(0))
    assert_equal(s.stop.in_flight_at_close, UInt64(0))
    assert_equal(s.stop.late_submits_drained, UInt64(0))
    assert_equal(s.stop.drained_records, UInt64(3))
    assert_true(not s.stop.busy_at_drain)
    assert_true(s.stop.counters_valid)
    assert_equal(s.stop.open_mappings, UInt64(0))


def test_closeout_detach_failure_partial() raises:
    # A failed detach finalizes partial with the admission
    # reason; the close is not claimed.
    var tmp = _stop_mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(0)
    cfg.max_events_bytes = 134217728
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("stop-detach-probe")
    cfg.pid = 4242
    var kernel = ScriptKernel()
    kernel.detach_out = OpOut(False, String("boom"))
    kernel.add_poll(_stop_timeout(), 300)
    _stop_zeros(kernel, 8, 4)
    var clock = ScriptClock()
    clock.add(UInt64(1000000000))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(cfg^)
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, 4)
    var parsed = False
    var s = Session()
    try:
        s = _stop_session(tmp + String("/cap"))
        parsed = True
    except:
        parsed = False
    assert_true(parsed)
    assert_equal(s.stop.outcome, String("partial"))
    assert_equal(s.stop.reason, String("admission close failed"))
    assert_true(not s.stop.admission_closed)


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
    suite.test[test_failed_admission_close_partial]()
    suite.test[test_closeout_records_stop_evidence]()
    suite.test[test_closeout_detach_failure_partial]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
