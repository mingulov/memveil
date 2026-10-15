# SPDX-License-Identifier: GPL-3.0-or-later

"""memveil record: admitted attempt capture, optional channels.

``run_record`` implements ``record --duration SEC --max-events-bytes
N --output DIR [--object PATH] [--bridge PATH] [--profile ID]
[--capability IDS] [--lc-object PATH] [--cp-object PATH]`` against
the live host. ``run_record_with`` is the same flow against an
explicit evidence root and profiles directory, so tests drive
fixtures through the identical code path. Admission and
collection run through the shared collection service; this
module owns only record argument parsing, usage, dispatch, and
rendering.

Exit codes: 4 = finalized (NORMAL including zero-event runs,
signal stops, and known-loss runs); 3 = cannot start
(diagnostic, no residual directory); 2 = usage (fixable via
argv); 1 = error or unfinalizable. Only a broken standard
error raises.
"""

from memveil.capture.collector import (
    EXIT_ERROR,
    EXIT_INVALID,
    EXIT_REFUSAL,
)
from memveil.capture.live import LiveWriter
from memveil.capture.run import (
    RecordOptions,
    repair_warning_for,
    run_collector_with,
)
from memveil.cli.doctor import resolve_profiles_dir
from memveil.cli.report import (
    EXIT_OK,
    CliError,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.platform.stdout import write_stdout

def record_usage() -> String:
    """Usage text for the record verb."""
    return (
        "usage: memveil record --output DIR [--object PATH]\n"
        "       [--duration SEC] [--max-events-bytes N]\n"
        "       [--bridge PATH] [--profile ID|PATH]\n"
        "       [--profiles-dir DIR] [--capability IDS]\n"
        "       [--lc-object PATH] [--cp-object PATH]\n"
        "\n"
        "Capture swiotlb bounce attempts into DIR. SEC defaults\n"
        "to 60; N defaults to 1073741824 (1 GiB) and must lie\n"
        "in 131072..4294967296. Without --bridge, the native\n"
        "bridge is discovered: LMB_NATIVE_LIB when unprivileged,\n"
        "then beside the executable, then the system path.\n"
        "Without --object, --lc-object, or --cp-object, each\n"
        "BPF object is discovered beside the executable or\n"
        "under the system directory, else the run refuses.\n"
        "Without --profile, the first validated profile passing\n"
        "full identity binding wins, then the first reference\n"
        "profile whose receipt verifies, else the first covering\n"
        "profile runs partial; an explicit --profile that fails\n"
        "binding refuses. Diagnostics go to stderr.\n"
        "\n"
        "--capability selects extra channels as a comma-separated\n"
        "list without spaces (default: attempt-trace, which is\n"
        "always required). mapping-lifecycle uses --lc-object\n"
        "and copy-actual uses --cp-object when given, else the\n"
        "discovered object for that channel; the winning profile\n"
        "must declare each requested capability supported and\n"
        "bind the matching object bytes, else the run refuses\n"
        "naming the capability. Extra channels never run\n"
        "partial: without full narrow binding the run refuses.\n"
        "\n"
        "Exit 4 for a finalized capture (including zero-event\n"
        "and signal stops), 3 when the run cannot start, 2 on\n"
        "usage errors, 1 on error or unfinalizable output.\n"
    )


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def _parse_decimal_u64(text: String) raises CliError -> UInt64:
    """Strict decimal: no leading zeros, 1..2^64-1."""
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 20:
        raise CliError("bad decimal: " + text)
    if raw[0] < UInt8(0x31) or raw[0] > UInt8(0x39):
        raise CliError("bad decimal: " + text)
    var v = UInt64(0)
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise CliError("bad decimal: " + text)
        var d = UInt64(Int(b) - 0x30)
        if v > (UInt64(0xFFFFFFFFFFFFFFFF) - d) // UInt64(10):
            raise CliError("bad decimal: " + text)
        v = v * UInt64(10) + d
    return v


def parse_record_args(args: List[String]) raises CliError -> RecordOptions:
    """Parse record arguments without the leading verb."""
    var opts = RecordOptions()
    var i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--duration":
            if i + 1 >= len(args):
                raise CliError("--duration needs a value")
            opts.duration_s = _parse_decimal_u64(args[i + 1])
            i += 2
        elif tok == "--max-events-bytes":
            if i + 1 >= len(args):
                raise CliError("--max-events-bytes needs a value")
            var v = _parse_decimal_u64(args[i + 1])
            if v > UInt64(0x7FFFFFFFFFFFFFFF):
                raise CliError("--max-events-bytes too large")
            opts.max_events_bytes = Int(v)
            i += 2
        elif tok == "--output":
            if i + 1 >= len(args):
                raise CliError("--output needs a value")
            if args[i + 1] == "":
                raise CliError("--output needs a value")
            opts.output = args[i + 1]
            i += 2
        elif tok == "--object":
            if i + 1 >= len(args):
                raise CliError("--object needs a value")
            if args[i + 1] == "":
                raise CliError("--object needs a value")
            opts.object = args[i + 1]
            i += 2
        elif tok == "--bridge":
            if i + 1 >= len(args):
                raise CliError("--bridge needs a value")
            if args[i + 1] == "":
                raise CliError("--bridge needs a value")
            opts.bridge = args[i + 1]
            opts.has_bridge = True
            i += 2
        elif tok == "--profile":
            if i + 1 >= len(args):
                raise CliError("--profile needs a value")
            if args[i + 1] == "":
                raise CliError("--profile needs a value")
            opts.profile = args[i + 1]
            opts.has_profile = True
            i += 2
        elif tok == "--profiles-dir":
            if i + 1 >= len(args):
                raise CliError("--profiles-dir needs a value")
            if args[i + 1] == "":
                raise CliError("--profiles-dir needs a value")
            opts.profiles_dir = args[i + 1]
            opts.has_profiles_dir = True
            i += 2
        elif tok == "--lc-object":
            if i + 1 >= len(args):
                raise CliError("--lc-object needs a value")
            if args[i + 1] == "":
                raise CliError("--lc-object needs a value")
            opts.lc_object = args[i + 1]
            i += 2
        elif tok == "--cp-object":
            if i + 1 >= len(args):
                raise CliError("--cp-object needs a value")
            if args[i + 1] == "":
                raise CliError("--cp-object needs a value")
            opts.cp_object = args[i + 1]
            i += 2
        elif tok == "--capability":
            if i + 1 >= len(args):
                raise CliError("--capability needs a value")
            if args[i + 1] == "":
                raise CliError("--capability needs a value")
            opts.capabilities = args[i + 1]
            i += 2
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            raise CliError("unexpected argument: " + tok)
    if opts.output == "":
        raise CliError("missing --output")
    return opts^


def _record_failed(detail: String) raises -> Int:
    """Report one cannot-start failure; return EXIT_REFUSAL."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_REFUSAL


def _record_misused(detail: String) raises -> Int:
    """Report one usage failure; return EXIT_INVALID."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID


def run_record_with(
    root: String, profiles_dir: String, opts: RecordOptions
) raises -> Int:
    """Run the record flow against explicit roots; return exit code.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. Absent bridge
    and object paths are discovered (explicit user input
    wins verbatim and is never root-joined). Refusals print
    one diagnostic and exit 3 before any BPF or output
    resource exists.
    """
    var writer = LiveWriter()
    var result = run_collector_with(
        root, profiles_dir, opts, writer
    )
    if result.outcome == String("finalized"):
        # A published capture lands root-owned under sudo;
        # hand it to the invoking user. Warn-only: the
        # capture stands whatever ownership repair does.
        var repair_line = repair_warning_for(opts.output, writer)
        if repair_line != String(""):
            try:
                write_stderr(repair_line)
            except:
                pass
    if result.exit_code == EXIT_ERROR or result.exit_code == EXIT_REFUSAL:
        try:
            write_stderr(
                String("memveil record: ")
                + sanitize_diagnostic(result.diagnostic)
                + String("\n")
            )
        except:
            pass
    if result.end_reason == String(""):
        return result.exit_code
    var done = String(
        t"record: end={result.end_reason} outcome={result.outcome} exit={result.exit_code}"
    )
    try:
        write_stdout(done + String("\n"))
    except:
        try:
            write_stderr("memveil record: cannot write stdout\n")
        except:
            pass
        return EXIT_ERROR
    return result.exit_code


def run_record(args: List[String]) raises -> Int:
    """Run the record verb; return the process exit code.

    args excludes the program name and the record word.
    Profiles resolve from the kernel-resolved binary path,
    never from argv[0] or the working directory.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(record_usage())
            except:
                try:
                    write_stderr("memveil record: cannot write stdout\n")
                except:
                    pass
                return EXIT_ERROR
            return EXIT_OK
        i += 1
    var opts: RecordOptions
    try:
        opts = parse_record_args(args)
    except e:
        return _record_misused(e.message)
    var profiles_dir = opts.profiles_dir
    if not opts.has_profiles_dir:
        try:
            profiles_dir = resolve_profiles_dir()
        except e:
            return _record_failed(
                String("cannot resolve profiles location: ") + e.message
            )
    return run_record_with(String(""), profiles_dir, opts^)
