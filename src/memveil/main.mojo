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
from memveil.model.report import ENGINE_VERSION


def top_usage() -> String:
    """Usage text for the memveil program."""
    return (
        "usage: memveil <record|report|doctor|help|version> [args]\n"
        "\n"
        "Attempt capture, offline inspection, passive host check. Verbs:\n"
        "  record    capture swiotlb bounce attempts into a directory.\n"
        "  report    read one capture and print attempt metrics.\n"
        "  doctor    inspect the host passively and print capability.\n"
        "  help      print this text.\n"
        "  version   print the engine version.\n"
        "\n"
        "Run 'memveil record --help' for record options.\n"
        "Run 'memveil report --help' for report options.\n"
        "Run 'memveil doctor --help' for doctor options.\n"
    )


def main() raises:
    var args = argv()
    if len(args) < 2:
        write_stderr(top_usage())
        exit(EXIT_INVALID)
    var verb = args[1]
    if verb == "help" or verb == "--help" or verb == "-h":
        print(top_usage(), end="")
        exit(EXIT_OK)
    if verb == "version" or verb == "--version":
        print(ENGINE_VERSION)
        exit(EXIT_OK)
    if verb != "report" and verb != "doctor" and verb != "record":
        write_stderr(top_usage())
        exit(EXIT_INVALID)
    var rest = List[String]()
    var i = 2
    while i < len(args):
        rest.append(args[i])
        i += 1
    if verb == "record":
        var full = List[String]()
        var k = 0
        while k < len(args):
            full.append(args[k])
            k += 1
        var note = ensure_inherited_signal_block(full)
        if note != String(""):
            write_stderr(
                String("memveil record: ") + note + String("\n")
            )
            exit(EXIT_REFUSAL)
    var code: Int
    try:
        if verb == "doctor":
            code = run_doctor(rest^)
        elif verb == "record":
            code = run_record(rest^)
        else:
            code = run_report(rest^)
    except:
        code = EXIT_INTERNAL
    exit(code)
