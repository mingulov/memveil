# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline report command: read one capture, reduce, render, exit.

The report verb wires the reader, the attempt analyzer, and the
renderers into one offline pipeline. It never collects: no kernel,
device, or native-bridge import is needed to use it.

Exit codes are exact: 0 means the evidence suffices for the
requested scope, 4 means the report is usable but materially
incomplete (unfinalized capture, detail loss, or a detail/counter
disagreement), and 2 means invalid input or usage. A rendering
failure on an accepted report is an internal error and exits 1.
"""

from memveil.analysis.attempts import AttemptAnalyzer
from memveil.capture.reader import (
    DEFAULT_MAX_EVENTS_BYTES,
    DEFAULT_MAX_LINE_BYTES,
    DEFAULT_MAX_SESSION_BYTES,
    CaptureReader,
    ReaderLimits,
    read_capture,
)
from memveil.model.event import Event
from memveil.model.report import Report
from memveil.render.render import render
from memveil.render.text import escape_text

comptime EXIT_OK = 0
comptime EXIT_INTERNAL = 1
comptime EXIT_INVALID = 2
comptime EXIT_INCOMPLETE = 4
comptime MAX_RENDERED_BYTES = 16777216


def check_rendered_size(text: String, limit: Int) raises CliError:
    """Refuse to print a report larger than limit bytes."""
    if text.byte_length() > limit:
        raise CliError("report exceeds size limit")


@fieldwise_init
struct CliError(Copyable, Writable):
    """One command-line usage failure."""

    var message: String


struct ReportOptions:
    """Parsed report arguments."""

    var format: String
    var allow_partial: Bool
    var dir: String
    var max_line_bytes: Int
    var max_session_bytes: Int
    var max_events_bytes: Int

    def __init__(out self):
        self.format = String("text")
        self.allow_partial = False
        self.dir = String("")
        self.max_line_bytes = DEFAULT_MAX_LINE_BYTES
        self.max_session_bytes = DEFAULT_MAX_SESSION_BYTES
        self.max_events_bytes = DEFAULT_MAX_EVENTS_BYTES


def report_usage() -> String:
    """Usage text for the report verb."""
    return (
        "usage: memveil report [--format text|json|markdown]"
        " [--allow-partial]\n"
        "       [--max-line-bytes N] [--max-session-bytes N]\n"
        "       [--max-events-bytes N] DIR\n"
        "\n"
        "Read the capture in DIR, reduce its events to attempt metrics,\n"
        "and print one report on stdout. Diagnostics go to stderr.\n"
        "Counts always cover the whole capture window.\n"
        "\n"
        "  --format NAME     text (default), json, or markdown.\n"
        "  --allow-partial   drop a truncated final record and report\n"
        "                    the loss instead of failing.\n"
        "  --max-line-bytes N\n"
        "                    per-record cap, at most 65536.\n"
        "  --max-session-bytes N\n"
        "                    session file cap, at most 16777216.\n"
        "  --max-events-bytes N\n"
        "                    total work cap, at most 4294967296.\n"
        "\n"
        "Exit 0 for sufficient evidence, 4 for a usable but materially\n"
        "incomplete report, 2 for invalid input or usage.\n"
    )


def sanitize_diagnostic(frag: String) raises -> String:
    """Escape one untrusted fragment for a single-line diagnostic.

    Newlines, tabs, and returns become literal backslash sequences
    and other C0 bytes and DEL become U+FFFD, so hostile capture or
    argument bytes can neither split log lines nor smuggle terminal
    sequences into stderr. Printable text passes through untouched.
    """
    return escape_text(frag)


def neutralize_controls(text: String) raises -> String:
    """Strip control bytes from stderr text, keeping newlines.

    Backstop for fixed multi-line diagnostics such as usage: C0
    bytes other than newline and DEL become U+FFFD while newlines
    survive, so the layout of trusted text is preserved.
    """
    var raw = text.as_bytes()
    var out = List[UInt8]()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x0A):
            out.append(b)
        elif b < UInt8(0x20) or b == UInt8(0x7F):
            out.append(UInt8(0xEF))
            out.append(UInt8(0xBF))
            out.append(UInt8(0xBD))
        else:
            out.append(b)
    return String(from_utf8=Span(out))


def write_stderr(text: String) raises:
    """Append text to standard error.

    Append mode preserves prior diagnostics when stderr is
    redirected to a file; write mode would truncate them. Control
    bytes are neutralized at this boundary so no present or future
    diagnostic can emit raw terminal sequences.
    """
    var err = open("/dev/stderr", "a")
    err.write(neutralize_controls(text))
    err.close()


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def _parse_limit(text: String, what: String, cap: Int) raises CliError -> Int:
    """Strict decimal limit: 1..cap, no leading zeros."""
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 10:
        raise CliError(what + " needs a decimal value")
    if raw[0] < UInt8(0x31) or raw[0] > UInt8(0x39):
        raise CliError(what + " needs a decimal value")
    # Ten digits fit Int with room; the cap check below decides.
    var v = 0
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise CliError(what + " needs a decimal value")
        v = v * 10 + (Int(b) - 0x30)
    if v > cap:
        raise CliError(what + " above cap")
    return v


def parse_report_args(args: List[String]) raises CliError -> ReportOptions:
    """Parse report arguments without the leading verb."""
    var opts = ReportOptions()
    var i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--format":
            if i + 1 >= len(args):
                raise CliError("--format needs a value")
            var v = args[i + 1]
            if v != "text" and v != "json" and v != "markdown":
                raise CliError("unknown format: " + v)
            opts.format = v
            i += 2
        elif tok == "--allow-partial":
            opts.allow_partial = True
            i += 1
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
            opts.max_events_bytes = _parse_limit(
                args[i + 1], "--max-events-bytes", 4294967296
            )
            i += 2
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            if opts.dir != "":
                raise CliError("too many arguments")
            opts.dir = tok
            i += 1
    if opts.dir == "":
        raise CliError("missing capture directory")
    return opts^


def exit_for_report(rep: Report) -> Int:
    """Map report quality to the process exit code.

    A report that never settled (terminal unsettled), lost detail
    events, disagrees with its counter cross-check, or withholds a
    headline attempt metric is usable but materially incomplete.
    Aggregate-only gaps leave the detail counts standing, so they
    keep the sufficient-evidence exit. Correlation and baseline
    quality render for audit but never gate the exit: attempt
    counting needs no cross-event correlation, so an unrequested or
    gapped correlation channel cannot make sufficient attempt
    evidence insufficient.
    """
    if rep.q_terminal.status != "complete_for_scope":
        return EXIT_INCOMPLETE
    if rep.q_detail.status == "partial":
        return EXIT_INCOMPLETE
    if rep.q_detail.status == "unavailable":
        return EXIT_INCOMPLETE
    if rep.counter_disagreement:
        return EXIT_INCOMPLETE
    var i = 0
    while i < len(rep.metrics):
        var m = rep.metrics[i]
        if not m.has_device_id and not m.has_pool_id:
            if not m.has_value and (
                m.name == "bounce_attempts"
                or m.name == "requested_bounce_bytes"
            ):
                return EXIT_INCOMPLETE
        i += 1
    return EXIT_OK


def _report_failed(prefix: String, detail: String) raises -> Int:
    write_stderr(prefix + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID


def run_report(args: List[String]) raises -> Int:
    """Run the report verb; return the process exit code.

    args excludes the program name and the report word. The rendered
    report goes to stdout and nothing else does; every diagnostic
    goes to stderr. Only a broken standard error raises.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            print(report_usage(), end="")
            return EXIT_OK
        i += 1
    var opts: ReportOptions
    try:
        opts = parse_report_args(args)
    except e:
        return _report_failed("memveil report: ", e.message)
    var reader: CaptureReader
    try:
        reader = read_capture(
            opts.dir,
            opts.allow_partial,
            ReaderLimits(
                opts.max_session_bytes,
                opts.max_line_bytes,
                opts.max_events_bytes,
            ),
        )
    except e:
        return _report_failed(
            "memveil report: cannot read capture: ", e.message
        )
    var analyzer = AttemptAnalyzer(reader.session)
    while True:
        var more: Bool
        try:
            more = reader.has_more()
        except e:
            return _report_failed(
                "memveil report: cannot read capture: ", e.message
            )
        if not more:
            break
        var ev: Event
        try:
            ev = reader.next_event()
        except e:
            return _report_failed(
                "memveil report: cannot read capture: ", e.message
            )
        try:
            analyzer.consume(ev^)
        except e:
            return _report_failed(
                "memveil report: cannot reduce capture: ", String(e)
            )
    var rep: Report
    try:
        rep = analyzer.finish(reader.session.window_end_ns, reader.partial)
    except e:
        return _report_failed("memveil report: ", String(e))
    var text: String
    try:
        text = render(rep, opts.format)
    except e:
        write_stderr(
            "memveil report: internal error: cannot render report\n"
        )
        return EXIT_INTERNAL
    try:
        check_rendered_size(text, MAX_RENDERED_BYTES)
    except e:
        return _report_failed("memveil report: ", e.message)
    print(text, end="")
    var raw = text.as_bytes()
    if len(raw) == 0 or raw[len(raw) - 1] != UInt8(0x0A):
        print()
    return exit_for_report(rep)
