# SPDX-License-Identifier: GPL-3.0-or-later

"""Top unit tests: durations, arguments, refresh boundaries, live sink.

Durations share the capture options' checked rules (strict
decimal, refused overflow) with s/m/h units. Refresh
boundaries split the capture window into interval horizons;
the final snapshot always covers the whole window. The live
refresh sink prints numbered diagnosed blocks and refuses
loudly when stdout is broken; the live session template
carries provisional unclaimed values the tee stamps.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.engine import Analyzer
from memveil.cli.durations import parse_duration_ns
from memveil.cli.top import (
    BoundaryCursor,
    StdoutSink,
    TopOptions,
    WaitSlices,
    _diagnose,
    _finish_live,
    _live_template,
    _snapshot_block,
    _wait_interval,
    parse_top_args,
)
from memveil.model.event import Event
from memveil.model.report import Report
from memveil.model.session import DeviceEntry, Session
from memveil.model.validate import format_u64
from memveil.platform.clock import MonoClock
from memveil.platform.reader import read_host_file
from memveil.platform.signal import LiveSignalSource
from memveil.render.filter import device_filter_resolves
from memveil.render.render import render


def test_duration_units() raises:
    assert_equal(parse_duration_ns("1s"), UInt64(1000000000))
    assert_equal(parse_duration_ns("2m"), UInt64(120000000000))
    assert_equal(parse_duration_ns("1h"), UInt64(3600000000000))
    assert_equal(parse_duration_ns("5"), UInt64(5000000000))


def test_duration_rejects() raises:
    for bad in range(6):
        var text = String("0s")
        if bad == 1:
            text = String("01s")
        elif bad == 2:
            text = String("1x")
        elif bad == 3:
            text = String("")
        elif bad == 4:
            text = String("99999999999999999999h")
        elif bad == 5:
            text = String("18446744073709551615s")
        var raised = False
        try:
            _ = parse_duration_ns(text)
        except:
            raised = True
        assert_true(raised)


def _args(first: String, second: String) -> List[String]:
    var out = List[String]()
    if first != "":
        out.append(first)
    if second != "":
        out.append(second)
    return out^


def test_top_defaults() raises:
    var args = _args("capdir", "")
    var opts = parse_top_args(args)
    assert_equal(opts.interval_ns, UInt64(1000000000))
    assert_true(not opts.has_device)
    assert_true(not opts.has_long_lived_after)
    assert_equal(opts.dir, String("capdir"))


def test_top_flags() raises:
    var args = List[String]()
    args.append(String("--interval"))
    args.append(String("2s"))
    args.append(String("--device"))
    args.append(String("d000001"))
    args.append(String("--long-lived-after"))
    args.append(String("1m"))
    args.append(String("capdir"))
    var opts = parse_top_args(args)
    assert_equal(opts.interval_ns, UInt64(2000000000))
    assert_true(opts.has_device)
    assert_equal(opts.device, String("d000001"))
    assert_true(opts.has_long_lived_after)
    assert_equal(opts.long_lived_after_ns, UInt64(60000000000))


def test_top_arg_errors() raises:
    var raised = False
    try:
        var empty = List[String]()
        _ = parse_top_args(empty)
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        var args = List[String]()
        args.append(String("--interval"))
        args.append(String("nope"))
        args.append(String("capdir"))
        _ = parse_top_args(args)
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        var args = List[String]()
        args.append(String("--nope"))
        args.append(String("capdir"))
        _ = parse_top_args(args)
    except:
        raised = True
    assert_true(raised)


def test_boundaries() raises:
    var cur = BoundaryCursor(
        UInt64(0), UInt64(2300000000), UInt64(1000000000)
    )
    assert_true(not cur.has_due(UInt64(999999999)))
    assert_true(cur.has_due(UInt64(1000000000)))
    assert_equal(cur.pop(), UInt64(1000000000))
    assert_true(not cur.has_due(UInt64(1999999999)))
    assert_true(cur.has_due(UInt64(2000000000)))
    assert_equal(cur.pop(), UInt64(2000000000))
    assert_true(not cur.has_due(~UInt64(0)))
    var none = BoundaryCursor(
        UInt64(500), UInt64(500), UInt64(1000000000)
    )
    assert_true(not none.has_due(~UInt64(0)))
    var short = BoundaryCursor(
        UInt64(0), UInt64(999), UInt64(1000000000)
    )
    assert_true(not short.has_due(~UInt64(0)))
    var zero = BoundaryCursor(
        UInt64(0), UInt64(2300000000), UInt64(0)
    )
    assert_true(not zero.has_due(~UInt64(0)))


def _raise_self(signo: Int):
    _ = external_call["raise", Int32](Int32(signo))


def test_wait_slices_bounded() raises:
    var parts = WaitSlices(250)
    assert_true(parts.has_more())
    assert_equal(parts.take(), 100)
    assert_true(parts.has_more())
    assert_equal(parts.take(), 100)
    assert_true(parts.has_more())
    assert_equal(parts.take(), 50)
    assert_true(not parts.has_more())
    assert_true(not WaitSlices(0).has_more())
    assert_true(not WaitSlices(-5).has_more())
    var hour = WaitSlices(3600000)
    var count = 0
    var total = 0
    while hour.has_more():
        var s = hour.take()
        assert_true(s <= 100)
        count += 1
        total += s
    assert_equal(count, 36000)
    assert_equal(total, 3600000)


def test_wait_slices_stream_huge() raises:
    # A trillion-ms wait would materialize ten billion slices
    # as a list; the cursor yields them one at a time with
    # constant memory, so this completes at all.
    var big = WaitSlices(1000000000000)
    assert_true(big.has_more())
    assert_equal(big.take(), 100)
    assert_equal(big.take(), 100)
    assert_equal(big.take(), 100)
    assert_true(big.has_more())


def test_wait_interval_polls_before_sleep() raises:
    var clock = MonoClock()
    var src = LiveSignalSource()
    var setup = src.setup()
    assert_true(setup.ok)
    # A signal already pending when the wait starts returns at
    # once instead of sleeping first: an hour-long wait with a
    # pending stop returns "pending", never after an hour.
    _raise_self(2)
    var got = _wait_interval(clock, src, 3600000)
    assert_equal(got.state, String("pending"))
    src.teardown()


def test_wait_interval_quiet_waits_full() raises:
    var clock = MonoClock()
    var src = LiveSignalSource()
    var setup = src.setup()
    assert_true(setup.ok)
    var got = _wait_interval(clock, src, 0)
    assert_equal(got.state, String("none"))
    src.teardown()


def test_cursor_streams_long_window() raises:
    # A full-range window at unit interval would materialize 2^64
    # horizons as a list; the cursor yields them one at a time
    # with constant memory, so this completes at all.
    var cur = BoundaryCursor(
        UInt64(0), ~UInt64(0), UInt64(1)
    )
    assert_true(not cur.has_due(UInt64(0)))
    assert_true(cur.has_due(UInt64(1)))
    assert_equal(cur.pop(), UInt64(1))
    assert_equal(cur.pop(), UInt64(2))
    assert_equal(cur.pop(), UInt64(3))
    assert_true(cur.has_due(UInt64(4)))


comptime _O_WRONLY = 1
comptime _O_CREAT = 64
comptime _O_TRUNC = 512
comptime _AT_FDCWD = -100


def _cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    out.append(UInt8(0))
    return out^


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-top-XXXXXX")
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


def _redirect_fd(fd: Int32, path: String) raises -> Int32:
    """Redirect fd to path; return the saved descriptor."""
    var saved = external_call["dup", Int32](fd)
    if saved < Int32(0):
        raise Error("dup failed")
    var pname = _cstr(path)
    var opened = external_call["openat", Int32](
        Int32(_AT_FDCWD),
        Span(pname).unsafe_ptr(),
        Int32(_O_WRONLY | _O_CREAT | _O_TRUNC),
        UInt32(420),
    )
    if opened < Int32(0):
        _ = external_call["close", Int32](saved)
        raise Error("openat failed")
    var moved = external_call["dup2", Int32](opened, fd)
    _ = external_call["close", Int32](opened)
    if moved < Int32(0):
        _ = external_call["dup2", Int32](saved, fd)
        _ = external_call["close", Int32](saved)
        raise Error("dup2 failed")
    return saved


def _restore_fd(fd: Int32, saved: Int32):
    _ = external_call["dup2", Int32](saved, fd)
    _ = external_call["close", Int32](saved)


def _redirect_stdout(path: String) raises -> Int32:
    """Redirect fd 1 to path; return the saved descriptor."""
    return _redirect_fd(Int32(1), path)


def _restore_stdout(saved: Int32):
    _restore_fd(Int32(1), saved)


def _redirect_stderr(path: String) raises -> Int32:
    """Redirect fd 2 to path; return the saved descriptor."""
    return _redirect_fd(Int32(2), path)


def _restore_stderr(saved: Int32):
    _restore_fd(Int32(2), saved)


def _sink_attempt(op: String, seq: UInt64, ts: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("sinkprobe")
    ev.seq = seq
    ev.ts_ns = ts
    ev.kind = String("bounce_attempt")
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    ev.bounce.device_id = String("d1")
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _sink_report(horizon: UInt64) raises -> Report:
    """Fold the two-attempt probe stream; snapshot at horizon."""
    var s = _live_template()
    s.window_start_ns = UInt64(100)
    s.window_end_ns = ~UInt64(0)
    var a = Analyzer(s)
    var e0 = _sink_attempt("op1", UInt64(0), UInt64(100))
    var e1 = _sink_attempt("op2", UInt64(1), UInt64(200))
    a.consume(e0)
    a.consume(e1)
    var rep = a.snapshot(horizon, False)
    return rep^


def _sink_report_dev(horizon: UInt64) raises -> Report:
    """Fold attempts on two devices; snapshot at horizon."""
    var s = _live_template()
    s.window_start_ns = UInt64(100)
    s.window_end_ns = ~UInt64(0)
    var a = Analyzer(s)
    var e0 = _sink_attempt("op1", UInt64(0), UInt64(100))
    var e1 = _sink_attempt("op2", UInt64(1), UInt64(200))
    e1.bounce.device_id = String("d2")
    a.consume(e0)
    a.consume(e1)
    var rep = a.snapshot(horizon, False)
    return rep^


def _sink_text(data: List[UInt8]) raises -> String:
    try:
        return String(from_utf8=Span(data))
    except:
        raise Error("sink bytes not UTF-8")


def _block_want(seq: Int, horizon: UInt64, filt: String) raises -> String:
    """Oracle block: diagnosed render plus the numbered header."""
    var oracle = _sink_report(horizon)
    _diagnose(oracle, False, UInt64(0))
    var text = render(oracle, String("text"), filt)
    var want = (
        String("--- refresh ")
        + String(seq)
        + String(" @ ")
        + format_u64(horizon)
        + String(" ns ---\n")
        + text
    )
    var raw = text.as_bytes()
    if len(raw) == 0 or raw[len(raw) - 1] != UInt8(0x0A):
        want += String("\n")
    return want^


def test_sink_emits_numbered_block() raises:
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var opts = TopOptions()
    var sink = StdoutSink(opts)
    var rep = _sink_report(UInt64(200))
    var want = _block_want(1, UInt64(200), String(""))
    var saved = _redirect_stdout(out)
    var ok = sink.emit(rep^, UInt64(200))
    _restore_stdout(saved)
    assert_true(ok)
    var raw = read_host_file(out, String("out"), 1048576)
    assert_equal(_sink_text(raw), want)


def test_sink_device_filter_displays() raises:
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var opts = TopOptions()
    opts.has_device = True
    opts.device = String("d1")
    var sink = StdoutSink(opts)
    var rep = _sink_report(UInt64(200))
    var want = _block_want(1, UInt64(200), String("d1"))
    var saved = _redirect_stdout(out)
    var ok = sink.emit(rep^, UInt64(200))
    _restore_stdout(saved)
    assert_true(ok)
    var raw = read_host_file(out, String("out"), 1048576)
    assert_equal(_sink_text(raw), want)


def test_sink_seq_increments() raises:
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var opts = TopOptions()
    var sink = StdoutSink(opts)
    var first = _sink_report(UInt64(100))
    var second = _sink_report(UInt64(200))
    var want = _block_want(1, UInt64(100), String(""))
    want += _block_want(2, UInt64(200), String(""))
    var saved = _redirect_stdout(out)
    var ok0 = sink.emit(first^, UInt64(100))
    var ok1 = sink.emit(second^, UInt64(200))
    _restore_stdout(saved)
    assert_true(ok0)
    assert_true(ok1)
    var raw = read_host_file(out, String("out"), 1048576)
    assert_equal(_sink_text(raw), want)


def test_sink_filter_matches_replay_render() raises:
    # The live sink and the replay block printer share the
    # diagnose-plus-render path: the same analyzer state
    # with --device renders byte-identical blocks.
    var scratch = _mkdtemp()
    var live_out = scratch + String("/live.txt")
    var replay_out = scratch + String("/replay.txt")
    var opts = TopOptions()
    opts.has_device = True
    opts.device = String("d1")
    var sink = StdoutSink(opts)
    var rep = _sink_report_dev(UInt64(200))
    var saved = _redirect_stdout(live_out)
    var ok = sink.emit(rep^, UInt64(200))
    _restore_stdout(saved)
    assert_true(ok)
    var s = _live_template()
    s.window_start_ns = UInt64(100)
    s.window_end_ns = ~UInt64(0)
    var a = Analyzer(s)
    var e0 = _sink_attempt("op1", UInt64(0), UInt64(100))
    var e1 = _sink_attempt("op2", UInt64(1), UInt64(200))
    e1.bounce.device_id = String("d2")
    a.consume(e0)
    a.consume(e1)
    var saved2 = _redirect_stdout(replay_out)
    var rc = _snapshot_block(a, opts, UInt64(200), 1)
    _restore_stdout(saved2)
    assert_equal(rc, 0)
    var live_raw = read_host_file(live_out, String("live"), 1048576)
    var replay_raw = read_host_file(
        replay_out, String("replay"), 1048576
    )
    assert_equal(_sink_text(live_raw), _sink_text(replay_raw))


def _live_prefix_report() raises -> Report:
    """One attempt folded under the stamped live template."""
    var s = _live_template()
    s.window_start_ns = UInt64(100)
    s.window_end_ns = ~UInt64(0)
    var a = Analyzer(s)
    var e0 = _sink_attempt("op1", UInt64(0), UInt64(100))
    a.consume(e0)
    var rep = a.snapshot(UInt64(200), False)
    return rep^


def test_live_refresh_header_lines() raises:
    # A live prefix block names its honest bounds: live
    # marker, window, exact duration, unknown mode, and
    # unavailable kernel/profile/scope provenance.
    var text = render(_live_prefix_report(), String("text"), String(""))
    var want_text = List[String]()
    want_text.append(String("(live, engine "))
    want_text.append(String("window: [100,200)"))
    want_text.append(String("duration: 0.000000100 s (100 ns)"))
    want_text.append(
        String(
            "environment: mode=unknown detection=unverified"
            " attestation=not_performed evidence=0"
        )
    )
    want_text.append(
        String(
            "recorded kernel.release:"
            " unavailable (no captured provenance)"
        )
    )
    want_text.append(
        String(
            "recorded profile.decision:"
            " unavailable (no captured provenance)"
        )
    )
    want_text.append(
        String(
            "recorded measurement_scope:"
            " unavailable (no captured provenance)"
        )
    )
    for i in range(len(want_text)):
        assert_true(text.find(want_text[i]) != -1)
    var md = render(
        _live_prefix_report(), String("markdown"), String("")
    )
    var want_md = List[String]()
    want_md.append(String("- synthetic: no"))
    want_md.append(String("- window: [100,200)"))
    want_md.append(String("- duration: 0.000000100 s (100 ns)"))
    want_md.append(
        String(
            "- environment: mode=unknown detection=unverified"
            " attestation=not_performed evidence=0"
        )
    )
    want_md.append(
        String(
            "- recorded kernel.release:"
            " unavailable (no captured provenance)"
        )
    )
    want_md.append(
        String(
            "- recorded profile.decision:"
            " unavailable (no captured provenance)"
        )
    )
    want_md.append(
        String(
            "- recorded measurement\\_scope:"
            " unavailable (no captured provenance)"
        )
    )
    for i in range(len(want_md)):
        assert_true(md.find(want_md[i]) != -1)


def test_sink_full_stdout_refuses() raises:
    var opts = TopOptions()
    var sink = StdoutSink(opts)
    var rep = _sink_report(UInt64(200))
    var saved = external_call["dup", Int32](Int32(1))
    assert_true(saved >= Int32(0))
    var pname = _cstr(String("/dev/full"))
    var full = external_call["openat", Int32](
        Int32(_AT_FDCWD),
        Span(pname).unsafe_ptr(),
        Int32(_O_WRONLY),
        UInt32(0),
    )
    assert_true(full >= Int32(0))
    var moved = external_call["dup2", Int32](full, Int32(1))
    assert_true(moved >= Int32(0))
    _ = external_call["close", Int32](full)
    var ok = sink.emit(rep^, UInt64(200))
    _restore_stdout(saved)
    assert_true(not ok)


def test_live_template_provisional() raises:
    var s = _live_template()
    assert_equal(s.capture_mode, String("live"))
    assert_true(not s.synthetic)
    assert_true(not s.finalized)
    assert_true(not s.has_filter_device)
    assert_true(not s.baseline_complete)
    assert_equal(s.baseline_region_count, 0)
    assert_equal(len(s.baseline_regions), 0)
    assert_equal(s.window_start_ns, UInt64(0))
    assert_equal(s.window_end_ns, ~UInt64(0))
    # Provisional producer shape: scope-complete with
    # explicitly unknown loss. Correlation and baseline
    # surface verbatim when their streams show no gaps, so
    # their wording is user-visible in every prefix.
    assert_equal(s.q_detail.status, String("complete_for_scope"))
    assert_true(not s.q_detail.has_loss_count)
    assert_equal(s.q_detail.scope, String("live prefix"))
    assert_equal(
        s.q_detail.reason,
        String("provisional: producer loss unknown until finalize"),
    )
    assert_equal(s.q_aggregate.status, String("complete_for_scope"))
    assert_true(not s.q_aggregate.has_loss_count)
    assert_equal(s.q_aggregate.scope, String("live prefix"))
    assert_equal(
        s.q_aggregate.reason,
        String("provisional: producer loss unknown until finalize"),
    )
    assert_equal(s.q_correlation.status, String("complete_for_scope"))
    assert_true(not s.q_correlation.has_loss_count)
    assert_equal(s.q_correlation.scope, String("live prefix"))
    assert_equal(
        s.q_correlation.reason,
        String("provisional: producer loss unknown until finalize"),
    )
    assert_equal(s.q_baseline.status, String("not_applicable"))
    assert_equal(s.q_baseline.scope, String("attempt metrics"))
    assert_equal(
        s.q_baseline.reason,
        String("Attempt metrics need no baseline."),
    )
    assert_equal(s.q_terminal.status, String("complete_for_scope"))
    assert_true(not s.q_terminal.has_loss_count)
    assert_equal(s.q_terminal.scope, String("live prefix"))
    assert_equal(
        s.q_terminal.reason,
        String("provisional: producer loss unknown until finalize"),
    )
    assert_equal(s.product_name, String("memveil"))
    assert_true(len(s.product_version.as_bytes()) > 0)


def test_sink_warns_once_for_unknown_device() raises:
    # A filter matching no catalog device warns on
    # stderr exactly once; both blocks still print.
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var err = scratch + String("/err.txt")
    var opts = TopOptions()
    opts.has_device = True
    opts.device = String("nope")
    var sink = StdoutSink(opts)
    var rep0 = _sink_report_dev(UInt64(300))
    var rep1 = _sink_report_dev(UInt64(400))
    var saved_out = _redirect_stdout(out)
    var saved_err = _redirect_stderr(err)
    var r0 = sink.emit(rep0^, UInt64(300))
    var r1 = sink.emit(rep1^, UInt64(400))
    _restore_stdout(saved_out)
    _restore_stderr(saved_err)
    assert_true(r0)
    assert_true(r1)
    var text = _sink_text(read_host_file(out, String("out"), 1048576))
    assert_true(text.startswith(String("--- refresh 1 @ ")))
    var diag = _sink_text(read_host_file(err, String("err"), 1048576))
    assert_equal(
        diag,
        String(
            "memveil top: --device 'nope' matches no known device\n"
        ),
    )


def test_sink_known_device_filter_is_quiet() raises:
    # A resolving filter never warns.
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var err = scratch + String("/err.txt")
    var opts = TopOptions()
    opts.has_device = True
    opts.device = String("d2")
    var sink = StdoutSink(opts)
    var rep = _sink_report_dev(UInt64(300))
    var saved_out = _redirect_stdout(out)
    var saved_err = _redirect_stderr(err)
    var ok = sink.emit(rep^, UInt64(300))
    _restore_stdout(saved_out)
    _restore_stderr(saved_err)
    assert_true(ok)
    var diag = _sink_text(read_host_file(err, String("err"), 1048576))
    assert_equal(diag, String(""))


def test_filter_resolves_catalog_id_and_name() raises:
    # Catalog ids and names resolve even with no rows;
    # unknown filters do not.
    var rep = Report()
    var dev = DeviceEntry()
    dev.device_id = String("d9")
    dev.name = String("disk9")
    rep.devices.append(dev)
    assert_true(device_filter_resolves(rep, String("")))
    assert_true(device_filter_resolves(rep, String("d9")))
    assert_true(device_filter_resolves(rep, String("disk9")))
    assert_true(not device_filter_resolves(rep, String("nope")))


def test_filter_resolves_observed_metric_id() raises:
    # A metric device id resolves without a catalog
    # entry; other ids do not.
    var rep = _sink_report_dev(UInt64(300))
    assert_true(device_filter_resolves(rep, String("d1")))
    assert_true(device_filter_resolves(rep, String("d2")))
    assert_true(not device_filter_resolves(rep, String("nope")))


def test_finish_live_forwards_byte_budget() raises:
    # The final live replay covers the collection budget,
    # not just the replay cap: a capture inside the live
    # budget but past a smaller replay cap still finishes
    # with a final block.
    var dir = String("tests/fixtures/attempts")
    var events = read_host_file(
        dir + String("/events.ndjson"), String("events"), 1048576
    )
    var size = len(events)
    assert_true(size > 64)
    var opts = TopOptions()
    opts.max_events_bytes = size // 2
    opts.live.max_events_bytes = size * 2
    var scratch = _mkdtemp()
    var out = scratch + String("/out.txt")
    var saved = _redirect_stdout(out)
    var rc = _finish_live(dir, opts, 0)
    _restore_stdout(saved)
    assert_equal(rc, 0)
    var text = _sink_text(read_host_file(out, String("out"), 1048576))
    assert_true(text.startswith(String("--- refresh 1 @ ")))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_duration_units]()
    suite.test[test_duration_rejects]()
    suite.test[test_top_defaults]()
    suite.test[test_top_flags]()
    suite.test[test_top_arg_errors]()
    suite.test[test_boundaries]()
    suite.test[test_cursor_streams_long_window]()
    suite.test[test_wait_slices_bounded]()
    suite.test[test_wait_slices_stream_huge]()
    suite.test[test_wait_interval_polls_before_sleep]()
    suite.test[test_wait_interval_quiet_waits_full]()
    suite.test[test_sink_emits_numbered_block]()
    suite.test[test_sink_device_filter_displays]()
    suite.test[test_sink_seq_increments]()
    suite.test[test_sink_filter_matches_replay_render]()
    suite.test[test_live_refresh_header_lines]()
    suite.test[test_sink_full_stdout_refuses]()
    suite.test[test_live_template_provisional]()
    suite.test[test_finish_live_forwards_byte_budget]()
    suite.test[test_sink_warns_once_for_unknown_device]()
    suite.test[test_sink_known_device_filter_is_quiet]()
    suite.test[test_filter_resolves_catalog_id_and_name]()
    suite.test[test_filter_resolves_observed_metric_id]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
