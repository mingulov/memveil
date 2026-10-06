"""MemVeil command line: offline capture inspection."""

from std.sys import argv, exit

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
        "usage: memveil <report|help|version> [args]\n"
        "\n"
        "Offline capture inspection. Verbs:\n"
        "  report    read one capture and print attempt metrics.\n"
        "  help      print this text.\n"
        "  version   print the engine version.\n"
        "\n"
        "Run 'memveil report --help' for report options.\n"
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
    if verb != "report":
        write_stderr(top_usage())
        exit(EXIT_INVALID)
    var rest = List[String]()
    var i = 2
    while i < len(args):
        rest.append(args[i])
        i += 1
    var code: Int
    try:
        code = run_report(rest^)
    except:
        code = EXIT_INTERNAL
    exit(code)
