#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Examples gate: the worked example reproduces its README.

Runs the built binary over examples/real-capture in all three
formats and asserts the numbers the example README promises
(exit 4, 30 bounce attempts, zero detail loss, lifecycle/copy/
conversion/region rows unavailable). Fails when the example or
its documentation drifts from the product.
"""

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
BIN = os.path.join(ROOT, "build", "memveil")
EXAMPLE = os.path.join(ROOT, "examples", "real-capture")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def report(fmt):
    proc = subprocess.run(
        [BIN, "report", "--format", fmt, EXAMPLE],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc


def main():
    if not os.path.isfile(BIN):
        print("FAIL examples: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    readme = open(os.path.join(EXAMPLE, "README.md")).read()
    check("readme-states-exit", "exit 4" in readme)
    check("readme-states-count", "bounce_attempts = 30" in readme)

    proc = report("text")
    check("text-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    check("text-count", "bounce_attempts = 30" in proc.stdout)
    check("text-detail-loss",
          "detail: complete_for_scope loss=0" in proc.stdout)
    for row in ("successful_allocations = unavailable",
                "copy_original_to_bounce_bytes = unavailable",
                "conversion_request_bytes = unavailable",
                "known_shared_region_bytes = unavailable"):
        check("text-%s" % row.split(" ")[0], row in proc.stdout)
    check("text-terminal-partial",
          "terminal: partial" in proc.stdout)

    proc = report("json")
    check("json-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    try:
        doc = json.loads(proc.stdout)
    except ValueError as err:
        print("FAIL json-parses %s" % err)
        sys.exit(1)
    check("json-parses", True)
    attempts = [m for m in doc["metrics"]
                if m["name"] == "bounce_attempts"
                and (m.get("dimensions") or {}).get("device_id") is None]
    check("json-count", len(attempts) == 1
          and attempts[0]["value"] == "30",
          json.dumps(attempts)[:160])
    check("json-terminal-partial",
          doc["quality"]["terminal"]["status"] == "partial")

    proc = report("markdown")
    check("markdown-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    check("markdown-count", "bounce\\_attempts" in proc.stdout
          and "| 30 |" in proc.stdout)

    print("examples: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
