# SPDX-License-Identifier: GPL-3.0-or-later

"""Fixture mint probe: run bind-profile against the qualify fixture."""

from std.sys import argv, exit

from memveil.cli.bind import BindOptions, run_bind_with

comptime _HOST = "tests/fixtures/qualify/host"
comptime _PDIR = "tests/fixtures/qualify/profiles"
comptime _OBJ = "tests/fixtures/elf/ok.o"


def main() raises:
    var args = argv()
    if len(args) < 2:
        exit(2)
    var opts = BindOptions()
    opts.output = args[len(args) - 1]
    opts.object = String(_OBJ)
    var code = run_bind_with(
        String(_HOST), String(""), String(_PDIR), opts
    )
    exit(code)
