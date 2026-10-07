#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stdout-error checks: blocked/closed stdout must fail loudly.

Drives the built memveil binary with stdout to /dev/full: every
verb that renders to stdout must exit 1 with a stderr reason
instead of reporting success for bytes nobody received. Also
covers closed-stdout (EPIPE-style) delivery. Exits nonzero on
the first failure.
"""

import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
ATTEMPTS = os.path.join(REPO, "tests", "fixtures", "attempts")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def full(argv):
    with open("/dev/full", "wb") as sink:
        return subprocess.run([BIN] + argv, stdout=sink,
                              stderr=subprocess.PIPE)


def main():
    if not os.path.isfile(BIN):
        print("FAIL stdout-errors: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)

    p = full(["report", ATTEMPTS])
    check("report-full", p.returncode == 1, "exit %d" % p.returncode)
    check("report-full-stderr", p.stderr != b"")

    p = full(["report", "--format", "json", ATTEMPTS])
    check("report-json-full", p.returncode == 1,
          "exit %d" % p.returncode)

    p = full(["top", ATTEMPTS])
    check("top-full", p.returncode == 1, "exit %d" % p.returncode)
    check("top-full-stderr", p.stderr != b"")

    p = full(["doctor"])
    check("doctor-full", p.returncode == 1, "exit %d" % p.returncode)

    p = full(["version"])
    check("version-full", p.returncode == 1, "exit %d" % p.returncode)

    p = full(["help"])
    check("help-full", p.returncode == 1, "exit %d" % p.returncode)

    r, w = os.pipe()
    os.close(r)
    child = subprocess.Popen([BIN, "report", ATTEMPTS], stdout=w,
                             stderr=subprocess.PIPE)
    os.close(w)
    _, _ = child.communicate()
    # SIGPIPE death (-13) or a loud exit 1 both count: the run
    # must not report success for bytes nobody received.
    check("report-closed-pipe", child.returncode != 0,
          "exit %d" % child.returncode)


if __name__ == "__main__":
    main()
