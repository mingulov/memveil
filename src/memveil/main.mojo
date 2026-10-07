# SPDX-License-Identifier: GPL-3.0-or-later

"""MemVeil command line: capture, offline inspection, passive doctor."""

from std.sys import argv, exit

from memveil.capture.collector import EXIT_REFUSAL
from memveil.cli.doctor import run_doctor
from memveil.cli.record import run_record
from memveil.platform.signal import ensure_inherited_signal_block
from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    run_report,
    write_stderr,
)
from memveil.cli.top import run_top
from memveil.model.report import ENGINE_VERSION
from memveil.platform.stdout import write_stdout


def top_usage() -> String:
    """Usage text for the memveil program."""
    return (
        "usage: memveil <record|report|top|doctor|help|version> [args]\n"
        "\n"
        "Attempt capture, offline inspection, passive host check. Verbs:\n"
        "  record    capture swiotlb bounce attempts into a directory.\n"
        "  report    read one capture and print attempt metrics.\n"
        "  top       replay one capture with periodic summaries.\n"
        "  doctor    inspect the host passively and print capability.\n"
        "  help      print this text.\n"
        "  version   print the engine version.\n"
        "\n"
        "Run 'memveil record --help' for record options.\n"
        "Run 'memveil report --help' for report options.\n"
        "Run 'memveil top --help' for top options.\n"
        "Run 'memveil doctor --help' for doctor options.\n"
    )


def _stdout_failed() raises:
    """Report a top-level stdout failure; exit 1."""
    try:
        write_stderr(String("memveil: cannot write stdout\n"))
    except:
        pass
    exit(EXIT_INTERNAL)


def main() raises:
    var args = argv()
    if len(args) < 2:
        write_stderr(top_usage())
        exit(EXIT_INVALID)
    var verb = args[1]
    if verb == "help" or verb == "--help" or verb == "-h":
        try:
            write_stdout(top_usage())
        except:
            _stdout_failed()
        exit(EXIT_OK)
    if verb == "version" or verb == "--version":
        try:
            write_stdout(ENGINE_VERSION + String("\n"))
        except:
            _stdout_failed()
        exit(EXIT_OK)
    if (
        verb != "report"
        and verb != "doctor"
        and verb != "record"
        and verb != "top"
    ):
        write_stderr(top_usage())
        exit(EXIT_INVALID)
    var rest = List[String]()
    var i = 2
    while i < len(args):
        rest.append(args[i])
        i += 1
    if verb == "record" or verb == "top":
        # Both signal-driven verbs need every runtime thread to
        # inherit blocked stop signals; otherwise a SIGINT lands
        # in a worker and never reaches signalfd.
        var full = List[String]()
        var k = 0
        while k < len(args):
            full.append(args[k])
            k += 1
        var note = ensure_inherited_signal_block(full)
        if note != String(""):
            write_stderr(
                String("memveil ") + verb + String(": ") + note + String("\n")
            )
            exit(EXIT_REFUSAL)
    var code: Int
    try:
        if verb == "doctor":
            code = run_doctor(rest^)
        elif verb == "record":
            code = run_record(rest^)
        elif verb == "top":
            code = run_top(rest^)
        else:
            code = run_report(rest^)
    except:
        code = EXIT_INTERNAL
    exit(code)
