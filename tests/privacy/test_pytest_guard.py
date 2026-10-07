#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Pytest precondition guards: loud failure when pytest is missing.

Drives the pytest-gated suites with a PATH whose python3 always
fails, and requires exit 1 with a 'pytest not importable'
diagnostic naming the suite. Covers the unarmed lanes that
reach the guard without fixtures (oracle-ledger,
profile-semantics, perf-workload); the armed vm-* lanes share
the identical guard idiom. Exits nonzero on the first failure.
"""

import os
import stat
import subprocess
import sys
import tempfile

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)

SUITES = ("oracle-ledger", "profile-semantics", "perf-workload")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def main():
    with tempfile.TemporaryDirectory() as shimdir:
        shim = os.path.join(shimdir, "python3")
        with open(shim, "w", encoding="utf-8") as handle:
            handle.write("#!/bin/sh\nexit 1\n")
        os.chmod(shim, os.stat(shim).st_mode | stat.S_IXUSR)
        env = dict(os.environ)
        env["PATH"] = shimdir + os.pathsep + env.get("PATH", "")
        for suite in SUITES:
            proc = subprocess.run(
                [os.path.join(REPO, "tools", "test"), suite],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                env=env)
            check("%s-exit-1" % suite, proc.returncode == 1,
                  "exit %d" % proc.returncode)
            check("%s-says-not-importable" % suite,
                  b"pytest not importable" in proc.stdout)


if __name__ == "__main__":
    main()
