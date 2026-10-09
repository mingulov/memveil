# SPDX-License-Identifier: GPL-3.0-or-later

"""Top: periodic summaries over a capture directory or live.

Top replays the capture's events through the shared composed
analyzer and prints one text summary per refresh: at each
interval boundary of capture time plus a final full-window
report. The final block renders the same rows and findings as
``report`` with the same policy, so replay-prefix equivalence
holds by construction.

With --output, top observes the live system instead: the
collector retains the capture while a tee writer folds the
same bytes into the shared analyzer and prints event-time
refreshes under a provisional session (producer loss
explicitly unknown until finalize). The final block replays
the retained capture, so the final live answer equals a
replay of that capture by construction.

Refresh membership follows consumption order, not timestamp
order: a refresh at horizon H covers the events consumed so
far, and a disordered event with a timestamp below an
already-printed horizon is folded into the final summary
only. Printed refreshes are never revised, so under
disordered input a horizon may exclude an event its
timestamp names.

The device option is a display filter over per-device rows
(exact device id or catalog name); analysis always covers
the whole capture. Summaries are line-oriented plain text with escaped
fields, safe for non-TTY pipes. Between refreshes top waits
the interval in wall time, polling for stops first and every
100 ms; a pending SIGINT/SIGTERM finishes the remaining
stream quietly, prints the final summary, and exits with the
final report's code.
"""

from memveil.analysis.diagnostics import diagnose_report
from memveil.analysis.engine import Analyzer
from memveil.capture.reader import (
    DEFAULT_MAX_EVENTS_BYTES,
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_SESSION_BYTES,
    CaptureReader,
    ReaderLimits,
    read_capture,
)
from memveil.capture.tee import RefreshSink, TeeWriter
from memveil.cli.doctor import resolve_profiles_dir
from memveil.cli.durations import parse_duration_ns
from memveil.cli.record import (
    EXIT_ERROR,
    EXIT_REFUSAL,
    RecordOptions,
    parse_record_args,
    run_collector_with,
)
from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    MAX_RENDERED_BYTES,
    CliError,
    check_rendered_size,
    exit_for_report,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.model.event import Event
from memveil.model.report import ENGINE_VERSION, Report
from memveil.model.session import Session
from memveil.model.validate import format_u64
from memveil.platform.stdout import write_stdout
from memveil.platform.clock import MonoClock
from memveil.platform.signal import LiveSignalSource, SignalOut
from memveil.render.render import render

comptime DEFAULT_INTERVAL_NS = UInt64(1000000000)


struct TopOptions:
    """Parsed top arguments."""

    var interval_ns: UInt64
    var has_device: Bool
    var device: String
    var has_long_lived_after: Bool
    var long_lived_after_ns: UInt64
    var dir: String
    var max_line_bytes: Int
    var max_session_bytes: Int
    var max_events_bytes: Int
    var has_output: Bool
    var live: RecordOptions

    def __init__(out self):
        self.interval_ns = DEFAULT_INTERVAL_NS
        self.has_device = False
        self.device = String("")
        self.has_long_lived_after = False
        self.long_lived_after_ns = UInt64(0)
        self.dir = String("")
        self.max_line_bytes = DEFAULT_MAX_LINE_BYTES
        self.max_session_bytes = DEFAULT_MAX_SESSION_BYTES
        self.max_events_bytes = DEFAULT_MAX_EVENTS_BYTES
        self.has_output = False
        self.live = RecordOptions()


def top_usage() -> String:
    """Usage text for the top verb."""
    return (
        "usage: memveil top [--interval DURATION] [--device NAME]\n"
        "       [--long-lived-after DURATION] [--max-line-bytes N]\n"
        "       [--max-session-bytes N] [--max-events-bytes N] DIR\n"
        "   or: memveil top --output DIR --object PATH\n"
        "       [--duration SEC] [--max-events-bytes N]\n"
        "       [--bridge PATH] [--profile ID|PATH]\n"
        "       [--capability IDS] [--lc-object PATH] [--cp-object PATH]\n"
        "       [--interval DURATION] [--device NAME]\n"
        "       [--long-lived-after DURATION]\n"
        "\n"
        "Replay the capture in DIR, printing one text summary per\n"
        "interval of capture time plus a final full-window report.\n"
        "With --output, observe the live system instead, retaining\n"
        "the capture in DIR while printing the same summaries.\n"
        "Refreshes cover events in consumption order; a disordered\n"
        "event below a printed horizon reaches the final summary\n"
        "only, never a revised refresh.\n"
        "Diagnostics go to stderr.\n"
        "\n"
        "  --interval DURATION\n"
        "                    wall sleep between refreshes, default 1s.\n"
        "  --device NAME     show only this device's per-device rows\n"
        "                    (exact device id or catalog name);\n"
        "                    analysis still covers the whole capture.\n"
        "  --long-lived-after DURATION\n"
        "                    enable the informational long-lived\n"
        "                    finding past this open age.\n"
        "\n"
        "DURATION is a decimal count with optional unit s, m, or h\n"
        "(bare digits mean seconds); zero and overflow are refused.\n"
        "\n"
        "Exit 0 for sufficient evidence, 4 for a usable but materially\n"
        "incomplete report, 2 for invalid input or usage. Live mode\n"
        "adds 3 for unavailable collection and 1 for errors.\n"
    )


struct BoundaryCursor:
    """Incremental interval horizons strictly inside (start, end).

    A long window at a small interval names far more horizons
    than memory could hold as a list, so the cursor yields them
    one at a time with constant state: peek with has_due, take
    with pop. The sequence matches materializing every
    start+k*interval below end, stopping before u64 overflow.
    """

    var _next: UInt64
    var _end: UInt64
    var _interval: UInt64
    var _done: Bool

    def __init__(
        out self,
        start_ns: UInt64,
        end_ns: UInt64,
        interval_ns: UInt64,
    ):
        self._next = UInt64(0)
        self._end = end_ns
        self._interval = interval_ns
        self._done = True
        if interval_ns == UInt64(0) or end_ns <= start_ns:
            return
        var b = start_ns + interval_ns
        if b < start_ns:
            return
        if b >= end_ns:
            return
        self._next = b
        self._done = False

    def has_due(self, ts: UInt64) -> Bool:
        """True when the next horizon is due at ts."""
        return not self._done and ts >= self._next

    def pop(mut self) -> UInt64:
        """Take the next horizon and advance; call only when due."""
        var h = self._next
        if h > ~UInt64(0) - self._interval:
            self._done = True
        else:
            var b = h + self._interval
            if b >= self._end:
                self._done = True
            else:
                self._next = b
        return h


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def _is_live_flag(tok: String) -> Bool:
    """True for record-flow flags, parsed by the shared parser."""
    return (
        tok == "--output"
        or tok == "--object"
        or tok == "--bridge"
        or tok == "--profile"
        or tok == "--capability"
        or tok == "--lc-object"
        or tok == "--cp-object"
        or tok == "--duration"
        or tok == "--max-events-bytes"
    )


def _parse_limit(text: String, what: String, cap: Int) raises CliError -> Int:
    """Strict decimal limit: 1..cap, no leading zeros."""
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 10:
        raise CliError(what + " needs a decimal value")
    if raw[0] < UInt8(0x31) or raw[0] > UInt8(0x39):
        raise CliError(what + " needs a decimal value")
    var v = 0
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise CliError(what + " needs a decimal value")
        v = v * 10 + (Int(b) - 0x30)
    if v > cap:
        raise CliError(what + " above cap")
    return v


def _parse_duration_opt(text: String, what: String) raises CliError -> UInt64:
    try:
        return parse_duration_ns(text)
    except e:
        raise CliError(what + " " + String(e))


def parse_top_args(args: List[String]) raises CliError -> TopOptions:
    """Parse top arguments without the leading verb."""
    var opts = TopOptions()
    var live_args = List[String]()
    var stashed_max_events = String("")
    var has_stash = False
    var i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--interval":
            if i + 1 >= len(args):
                raise CliError("--interval needs a value")
            opts.interval_ns = _parse_duration_opt(
                args[i + 1], "--interval"
            )
            i += 2
        elif tok == "--device":
            if i + 1 >= len(args):
                raise CliError("--device needs a value")
            if args[i + 1] == "":
                raise CliError("--device needs a value")
            opts.has_device = True
            opts.device = args[i + 1]
            i += 2
        elif tok == "--long-lived-after":
            if i + 1 >= len(args):
                raise CliError("--long-lived-after needs a value")
            opts.has_long_lived_after = True
            opts.long_lived_after_ns = _parse_duration_opt(
                args[i + 1], "--long-lived-after"
            )
            i += 2
        elif tok == "--max-line-bytes":
            if i + 1 >= len(args):
                raise CliError("--max-line-bytes needs a value")
            opts.max_line_bytes = _parse_limit(
                args[i + 1], "--max-line-bytes", 65536
            )
            i += 2
        elif tok == "--max-session-bytes":
            if i + 1 >= len(args):
                raise CliError("--max-session-bytes needs a value")
            opts.max_session_bytes = _parse_limit(
                args[i + 1], "--max-session-bytes", 16777216
            )
            i += 2
        elif tok == "--max-events-bytes":
            if i + 1 >= len(args):
                raise CliError("--max-events-bytes needs a value")
            stashed_max_events = args[i + 1]
            has_stash = True
            i += 2
        elif _is_live_flag(tok):
            if tok == "--output":
                opts.has_output = True
            live_args.append(tok)
            if i + 1 < len(args):
                live_args.append(args[i + 1])
                i += 2
            else:
                i += 1
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            if opts.dir != "":
                raise CliError("too many arguments")
            opts.dir = tok
            i += 1
    if opts.dir != "" and opts.has_output:
        raise CliError("cannot combine replay DIR with live --output")
    if opts.dir == "" and not opts.has_output:
        raise CliError("missing capture directory")
    if not opts.has_output and len(live_args) > 0:
        raise CliError("live options need --output DIR")
    if opts.has_output:
        if has_stash:
            live_args.append(String("--max-events-bytes"))
            live_args.append(stashed_max_events)
        opts.live = parse_record_args(live_args)
    elif has_stash:
        opts.max_events_bytes = _parse_limit(
            stashed_max_events, "--max-events-bytes", 4294967296
        )
    return opts^


def _top_failed(prefix: String, detail: String) raises -> Int:
    write_stderr(prefix + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID


def _print_block(text: String, seq: Int, horizon_ns: UInt64) raises:
    """Print one refresh block.

    Every byte goes through the checked stdout writer: a short
    write or error reports on stderr and raises, so a blocked
    stdout fails the run instead of printing success.
    """
    var head = String("--- refresh ")
    head += String(seq)
    head += String(" @ ")
    head += format_u64(horizon_ns)
    head += String(" ns ---\n")
    try:
        write_stdout(head)
        write_stdout(text)
        var raw = text.as_bytes()
        if len(raw) == 0 or raw[len(raw) - 1] != UInt8(0x0A):
            write_stdout("\n")
    except:
        write_stderr("memveil top: cannot write stdout\n")
        raise Error("cannot write stdout")


def _diagnose(
    mut rep: Report, has_long_lived_after: Bool, long_lived_after_ns: UInt64
):
    diagnose_report(rep, has_long_lived_after, long_lived_after_ns)


def _emit_report(
    var rep: Report,
    filt: String,
    has_long_lived_after: Bool,
    long_lived_after_ns: UInt64,
    seq: Int,
    horizon_ns: UInt64,
) raises -> Int:
    """Diagnose, render, and print one refresh block.

    Shared by replay refreshes and the live sink: one
    policy for every printed block. Render and stdout
    failures raise; an oversized block is a clean refusal.
    """
    _diagnose(rep, has_long_lived_after, long_lived_after_ns)
    var text = render(rep, String("text"), filt)
    try:
        check_rendered_size(text, MAX_RENDERED_BYTES)
    except e:
        return _top_failed("memveil top: ", e.message)
    _print_block(text, seq, horizon_ns)
    return 0


def _snapshot_block(
    mut analyzer: Analyzer,
    opts: TopOptions,
    horizon_ns: UInt64,
    seq: Int,
) raises -> Int:
    """Render and print one refresh."""
    var rep = analyzer.snapshot(horizon_ns, False)
    var filt = String("")
    if opts.has_device:
        filt = opts.device
    return _emit_report(
        rep^,
        filt,
        opts.has_long_lived_after,
        opts.long_lived_after_ns,
        seq,
        horizon_ns,
    )


struct StdoutSink(RefreshSink):
    """RefreshSink that prints numbered diagnosed text blocks.

    Block numbering starts at one and rises per accepted
    refresh. A refused emission still consumes its number,
    but refusals fail the run, so the gap never prints.
    """

    var _has_device: Bool
    var _device: String
    var _has_long_lived_after: Bool
    var _long_lived_after_ns: UInt64
    var _seq: Int

    def __init__(out self, opts: TopOptions):
        self._has_device = opts.has_device
        self._device = opts.device.copy()
        self._has_long_lived_after = opts.has_long_lived_after
        self._long_lived_after_ns = opts.long_lived_after_ns
        self._seq = 0

    def emit(mut self, var rep: Report, horizon_ns: UInt64) -> Bool:
        self._seq += 1
        var filt = String("")
        if self._has_device:
            filt = self._device
        var rc: Int
        try:
            rc = _emit_report(
                rep^,
                filt,
                self._has_long_lived_after,
                self._long_lived_after_ns,
                self._seq,
                horizon_ns,
            )
        except:
            return False
        return rc == 0


def _live_template() -> Session:
    """Provisional live session: unclaimed values the tee stamps.

    Real collection, nothing finalized, no capture filter
    (live records every device; --device stays a display
    filter), no baseline (the collector attests none
    either). Producer channels are scope-complete with
    explicitly unknown loss: correlation and baseline
    surface verbatim when their streams show no gaps, and
    the merge rebuilds every other scope and reason, so
    the provisional wording below is user-visible in
    every prefix and must stay honest. Region and
    conversion caps stay unadmitted, matching the
    collector, which attests no region source; revisit
    when conversion collection lands.
    """
    var s = Session()
    s.session_id = String("")
    s.synthetic = False
    s.product_name = String("memveil")
    s.product_version = String(ENGINE_VERSION)
    s.env_mode = String("unknown")
    s.env_detection = String("unverified")
    s.env_attestation = String("not_performed")
    s.capture_mode = String("live")
    s.window_start_ns = UInt64(0)
    s.window_end_ns = ~UInt64(0)
    s.finalized = False
    s.q_detail.status = String("complete_for_scope")
    s.q_detail.has_loss_count = False
    s.q_detail.scope = String("live prefix")
    s.q_detail.reason = String(
        "provisional: producer loss unknown until finalize"
    )
    s.q_aggregate.status = String("complete_for_scope")
    s.q_aggregate.has_loss_count = False
    s.q_aggregate.scope = String("live prefix")
    s.q_aggregate.reason = String(
        "provisional: producer loss unknown until finalize"
    )
    s.q_correlation.status = String("complete_for_scope")
    s.q_correlation.has_loss_count = False
    s.q_correlation.scope = String("live prefix")
    s.q_correlation.reason = String(
        "provisional: producer loss unknown until finalize"
    )
    s.q_baseline.status = String("not_applicable")
    s.q_baseline.scope = String("attempt metrics")
    s.q_baseline.reason = String("Attempt metrics need no baseline.")
    s.q_terminal.status = String("complete_for_scope")
    s.q_terminal.has_loss_count = False
    s.q_terminal.scope = String("live prefix")
    s.q_terminal.reason = String(
        "provisional: producer loss unknown until finalize"
    )
    return s^


def _finish_live(
    dir: String, opts: TopOptions, shown: Int
) raises -> Int:
    """Replay the retained capture as the final live block.

    Prefix numbering continues: the final block is refresh
    shown + 1 over the finalized session, so the final
    live answer equals a replay of the retained capture
    by construction.
    """
    var reader: CaptureReader
    try:
        reader = read_capture(
            dir,
            False,
            ReaderLimits(
                opts.max_session_bytes,
                opts.max_line_bytes,
                opts.max_events_bytes,
            ),
        )
    except e:
        return _top_failed(
            "memveil top: cannot read capture: ", e.message
        )
    var analyzer = Analyzer(reader.session)
    return _finish_after_signal(reader, analyzer, opts, shown)


def run_top_live(opts: TopOptions) raises -> Int:
    """Observe the live system; return the process exit code.

    Admission and collection reuse the record flow through
    a tee writer that prints event-time refreshes; the
    final block replays the retained capture, so the final
    live answer always equals a replay of that capture.
    Refusals name their reason on stderr and create
    nothing; printed prefixes stand when the run fails.
    """
    var profiles_dir: String
    try:
        profiles_dir = resolve_profiles_dir()
    except e:
        try:
            write_stderr(
                "memveil top: cannot resolve profiles location: "
                + sanitize_diagnostic(e.message)
                + String("\n")
            )
        except:
            pass
        return EXIT_REFUSAL
    var template = _live_template()
    var sink = StdoutSink(opts)
    var writer = TeeWriter[StdoutSink](
        template, opts.interval_ns, sink^
    )
    var result = run_collector_with(
        String(""), profiles_dir, opts.live, writer
    )
    if result.exit_code == EXIT_ERROR or result.exit_code == EXIT_REFUSAL:
        try:
            write_stderr(
                String("memveil top: ")
                + sanitize_diagnostic(result.diagnostic)
                + String("\n")
            )
        except:
            pass
        return result.exit_code
    return _finish_live(
        opts.live.output, opts, writer.emission_count()
    )


def run_top(args: List[String]) raises -> Int:
    """Run the top verb; return the process exit code.

    args excludes the program name and the top word. Summaries
    go to stdout and nothing else does; every diagnostic goes
    to stderr. Only a broken standard error raises.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(top_usage())
            except:
                write_stderr("memveil top: cannot write stdout\n")
                return EXIT_INTERNAL
            return EXIT_OK
        i += 1
    var opts: TopOptions
    try:
        opts = parse_top_args(args)
    except e:
        return _top_failed("memveil top: ", e.message)
    if opts.has_output:
        return run_top_live(opts^)
    var reader: CaptureReader
    try:
        reader = read_capture(
            opts.dir,
            False,
            ReaderLimits(
                opts.max_session_bytes,
                opts.max_line_bytes,
                opts.max_events_bytes,
            ),
        )
    except e:
        return _top_failed(
            "memveil top: cannot read capture: ", e.message
        )
    var signal = LiveSignalSource()
    var armed = signal.setup()
    if not armed.ok:
        try:
            write_stderr(
                "memveil top: cannot arm signals: "
                + sanitize_diagnostic(armed.message)
                + "\n"
            )
        except:
            pass
        return EXIT_INTERNAL
    var analyzer = Analyzer(reader.session)
    var clock = MonoClock()
    var cursor = BoundaryCursor(
        reader.session.window_start_ns,
        reader.session.window_end_ns,
        opts.interval_ns,
    )
    var seq = 0
    var code = _drain(
        reader, analyzer, opts, signal, clock, cursor, seq
    )
    signal.teardown()
    return code


comptime _WAIT_SLICE_MS = 100


struct WaitSlices:
    """One-at-a-time ≤100 ms slices for a refresh wait.

    A huge interval names far more slices than memory could
    hold as a list, so the cursor yields them one at a time
    with constant state: check with has_more, take with take.
    The sequence matches splitting the total into 100 ms
    slices with a short final slice.
    """

    var _left: Int

    def __init__(out self, total_ms: Int):
        self._left = total_ms
        if self._left < 0:
            self._left = 0

    def has_more(self) -> Bool:
        """True while an untaken slice remains."""
        return self._left > 0

    def take(mut self) -> Int:
        """Take the next slice; call only when due."""
        var s = self._left
        if s > _WAIT_SLICE_MS:
            s = _WAIT_SLICE_MS
        self._left -= s
        return s


def _wait_interval(
    mut clock: MonoClock, mut signal: LiveSignalSource, total_ms: Int
) -> SignalOut:
    """Poll-first interruptible wait; returns the last state.

    The first poll runs before any sleep, then each slice
    sleeps and re-polls, so a stop lands within about one
    slice no matter how long the interval is.
    """
    var got = signal.check()
    if got.state != "none":
        return got^
    var slices = WaitSlices(total_ms)
    while slices.has_more():
        clock.sleep_ms(slices.take())
        got = signal.check()
        if got.state != "none":
            return got^
    return got^


def _signal_failed(message: String) raises -> Int:
    """Report a signal-check failure; always exits internal."""
    try:
        write_stderr(
            "memveil top: signal check failed: "
            + sanitize_diagnostic(message)
            + "\n"
        )
    except:
        pass
    return EXIT_INTERNAL


def _drain(
    mut reader: CaptureReader,
    mut analyzer: Analyzer,
    opts: TopOptions,
    mut signal: LiveSignalSource,
    mut clock: MonoClock,
    mut cursor: BoundaryCursor,
    mut seq: Int,
) raises -> Int:
    """Stream events, refreshing at each boundary, then finish."""
    while True:
        var more: Bool
        try:
            more = reader.has_more()
        except e:
            return _top_failed(
                "memveil top: cannot read capture: ", e.message
            )
        if not more:
            break
        var ev: Event
        try:
            ev = reader.next_event()
        except e:
            return _top_failed(
                "memveil top: cannot read capture: ", e.message
            )
        var ts = ev.ts_ns
        # Every boundary the event crosses renders BEFORE the
        # event is consumed: a refresh at horizon H covers
        # [start, H), so the crossing event belongs to the next
        # refresh, never the one it triggers. Boundaries only
        # advance, so a nonmonotonic event below an already
        # rendered horizon renders nothing further.
        #
        # A stop observed mid-refresh only latches a flag: the
        # signalfd record is consumed by the wait's polls, but
        # the crossing event still folds first so the final
        # summary covers every pulled event.
        var stopped = False
        var wait_ms = Int(opts.interval_ns // UInt64(1000000))
        while cursor.has_due(ts) and not stopped:
            var horizon = cursor.pop()
            seq += 1
            var rc = _snapshot_block(
                analyzer, opts, horizon, seq
            )
            if rc != 0:
                return rc
            var wait = _wait_interval(clock, signal, wait_ms)
            if wait.state == "error":
                return _signal_failed(wait.message)
            stopped = wait.state != "none"
        try:
            analyzer.consume(ev^)
        except e:
            return _top_failed(
                "memveil top: cannot reduce capture: ", String(e)
            )
        if stopped:
            return _finish_after_signal(
                reader, analyzer, opts, seq
            )
        var outcome = _poll_signal(
            reader, analyzer, opts, signal, seq
        )
        if outcome >= 0:
            return outcome
    seq += 1
    var rep: Report
    try:
        rep = analyzer.finish(reader.session.window_end_ns, False)
    except e:
        return _top_failed("memveil top: ", String(e))
    _diagnose(rep, opts.has_long_lived_after, opts.long_lived_after_ns)
    var filt = String("")
    if opts.has_device:
        filt = opts.device
    var text: String
    try:
        text = render(rep, String("text"), filt)
    except e:
        write_stderr(
            "memveil top: internal error: cannot render report\n"
        )
        return EXIT_INTERNAL
    try:
        check_rendered_size(text, MAX_RENDERED_BYTES)
    except e:
        return _top_failed("memveil top: ", e.message)
    _print_block(text, seq, reader.session.window_end_ns)
    return exit_for_report(rep)


def _poll_signal(
    mut reader: CaptureReader,
    mut analyzer: Analyzer,
    opts: TopOptions,
    mut signal: LiveSignalSource,
    seq: Int,
) raises -> Int:
    """Handle a pending stop signal; -1 means keep going."""
    var got = signal.check()
    if got.state == "none":
        return -1
    if got.state == "error":
        return _signal_failed(got.message)
    return _finish_after_signal(reader, analyzer, opts, seq)


def _finish_after_signal(
    mut reader: CaptureReader,
    mut analyzer: Analyzer,
    opts: TopOptions,
    seq: Int,
) raises -> Int:
    """Drain the rest quietly, print the final summary and code."""
    while True:
        var more: Bool
        try:
            more = reader.has_more()
        except e:
            return _top_failed(
                "memveil top: cannot read capture: ", e.message
            )
        if not more:
            break
        var ev: Event
        try:
            ev = reader.next_event()
        except e:
            return _top_failed(
                "memveil top: cannot read capture: ", e.message
            )
        try:
            analyzer.consume(ev^)
        except e:
            return _top_failed(
                "memveil top: cannot reduce capture: ", String(e)
            )
    var rep: Report
    try:
        rep = analyzer.finish(reader.session.window_end_ns, False)
    except e:
        return _top_failed("memveil top: ", String(e))
    _diagnose(rep, opts.has_long_lived_after, opts.long_lived_after_ns)
    var filt = String("")
    if opts.has_device:
        filt = opts.device
    var text: String
    try:
        text = render(rep, String("text"), filt)
    except e:
        write_stderr(
            "memveil top: internal error: cannot render report\n"
        )
        return EXIT_INTERNAL
    _print_block(text, seq + 1, reader.session.window_end_ns)
    return exit_for_report(rep)
