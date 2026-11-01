#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Adversarial CLI checks: compat exits, accepted versions, partial edges.

Drives the built memveil binary: unknown schema major and
unsupported event kinds exit 2 with empty stdout; the
accepted frozen versions read green (session 0.1.3 plus
event 0.1.2 with both true-only copy markers); a truncated
final record exits 2 without the flag and 4 with it; a
corrupt tail is never repaired, even with the flag. Exits
nonzero on the first failure.
"""

import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
READER = os.path.join(REPO, "tests", "fixtures", "reader")


def run(args):
    return subprocess.run([BIN] + args, capture_output=True, text=True)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def main():
    if not os.path.isfile(BIN):
        print("FAIL adversarial-cli: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)

    subprocess.run([sys.executable, os.path.join(TESTS, "cli", "test_capture_integrity.py")], check=True)

    p = run(["report", os.path.join(READER, "compat-major")])
    check("major-exit", p.returncode == 2, "exit %d" % p.returncode)
    check("major-stdout", p.stdout == "")
    check("major-stderr", p.stderr != "")

    p = run(["report", os.path.join(READER, "badkind")])
    check("kind-exit", p.returncode == 2, "exit %d" % p.returncode)
    check("kind-stdout", p.stdout == "")
    check("kind-stderr", p.stderr != "")

    p = run(["report", os.path.join(READER, "ev012")])
    check("ev012-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("ev012-stdout", p.stdout != "")

    p = run(["report", os.path.join(READER, "complete-stop")])
    check("sess013-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("sess013-stdout", p.stdout != "")

    p = run(["report",
             os.path.join(READER, "f2-dangling-split-copy-ok")])
    check("sess012-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("sess012-stdout", p.stdout != "")

    p = run(["report", os.path.join(READER, "counters-single")])
    check("sess011-exit", p.returncode == 0, "exit %d" % p.returncode)
    check("sess011-stdout", p.stdout != "")

    p = run(["report", os.path.join(READER, "partial-tail")])
    check("tail-strict", p.returncode == 2, "exit %d" % p.returncode)
    check("tail-strict-stdout", p.stdout == "")

    p = run(["report", "--allow-partial",
             os.path.join(READER, "partial-tail")])
    check("tail-partial", p.returncode == 0, "exit %d" % p.returncode)
    check("tail-partial-stdout", p.stdout != "")

    p = run(["report", "--strict", "--allow-partial",
             os.path.join(READER, "partial-tail")])
    check("tail-partial-strict", p.returncode == 4,
          "exit %d" % p.returncode)
    check("tail-partial-strict-stdout", p.stdout != "")

    p = run(["report", "--allow-partial",
             os.path.join(READER, "corrupt-tail")])
    check("tail-corrupt", p.returncode == 2, "exit %d" % p.returncode)
    check("tail-corrupt-stdout", p.stdout == "")

    p = run(["report", "--allow-partial",
             os.path.join(READER, "interior-corrupt")])
    check("interior", p.returncode == 2, "exit %d" % p.returncode)
    check("interior-stdout", p.stdout == "")


if __name__ == "__main__":
    main()
