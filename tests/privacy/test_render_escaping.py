#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render-escaping checks: hostile metadata keeps its structure.

Replays the escape and canary captures through every
renderer: markdown tables stay rectangular within each
block, text device lines stay one-per-device, JSON
round-trips, and repeated runs are byte-identical. Exits
nonzero on the first failure.
"""

import json
import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")
READER = os.path.join(REPO, "tests", "fixtures", "reader")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def run(args):
    return subprocess.run([BIN] + args, capture_output=True)


def structural_pipes(line):
    # Escaped pipes (\|) are cell content, not structure; fold
    # escaped backslashes first so \\| counts as one literal.
    folded = line.replace("\\\\", "\x00").replace("\\|", "\x00")
    return folded.count("|")


def tables_rectangular(md):
    block = []
    for line in md.split("\n"):
        if line.startswith("|"):
            block.append(structural_pipes(line))
        else:
            if len(set(block)) > 1:
                return False
            block = []
    return len(set(block)) <= 1


def main():
    if not os.path.isfile(BIN):
        print("FAIL render-escaping: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    for cap in ("escape", "privacy-canary"):
        path = os.path.join(READER, cap)
        p = run(["report", "--format", "markdown", path])
        check("%s-md-exit" % cap, p.returncode == 0)
        md = p.stdout.decode("utf-8")
        check("%s-md-rect" % cap, tables_rectangular(md))
        check("%s-md-no-raw-esc" % cap, "\x1b" not in md)

        p = run(["report", "--format", "text", path])
        check("%s-text-exit" % cap, p.returncode == 0)
        text = p.stdout.decode("utf-8")
        devs = [ln for ln in text.split("\n") if ln.startswith("  dev-")]
        check("%s-text-devlines" % cap, len(devs) == 1,
              "%d lines" % len(devs))
        check("%s-text-no-raw-esc" % cap, "\x1b" not in text)

        p = run(["report", "--format", "json", path])
        check("%s-json-exit" % cap, p.returncode == 0)
        doc = json.loads(p.stdout.decode("utf-8"))
        check("%s-json-doc" % cap, isinstance(doc, dict))
        again = run(["report", "--format", "json", path])
        check("%s-json-stable" % cap, again.stdout == p.stdout)

        p = run(["top", path])
        check("%s-top-exit" % cap, p.returncode == 0)
        check("%s-top-no-raw-esc" % cap, b"\x1b" not in p.stdout)


if __name__ == "__main__":
    main()
