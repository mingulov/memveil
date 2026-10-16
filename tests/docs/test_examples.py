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
EXAMPLE3 = os.path.join(ROOT, "examples", "lifecycle-copy")


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def report(fmt, cap=None):
    proc = subprocess.run(
        [BIN, "report", "--format", fmt, cap or EXAMPLE],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return proc


def check_three_channel():
    check("3ch-readme-exists",
          os.path.isfile(os.path.join(EXAMPLE3, "README.md")))
    readme = open(os.path.join(EXAMPLE3, "README.md")).read()
    check("3ch-readme-exit", "exit 4" in readme)
    for token in ("bounce_attempts = 208",
                  "copy_original_to_bounce_bytes = 35002",
                  "copy_bounce_to_original_bytes = 24784",
                  "completed_lifetime_count = 208"):
        check("3ch-readme-%s" % token.split(" ")[0], token in readme)
    for name in ("oracle-phase.log", "fail-phase.log"):
        path = os.path.join(EXAMPLE3, name)
        check("3ch-oracle-%s" % name,
              os.path.isfile(path)
              and "mv-oracle:" in open(path).read())

    proc = report("text", EXAMPLE3)
    check("3ch-text-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    for row in ("bounce_attempts = 208",
                "copy_original_to_bounce_bytes = 35002",
                "copy_bounce_to_original_bytes = 24784",
                "completed_lifetime_count = 208",
                "detail: complete_for_scope loss=0",
                "terminal: partial",
                "correlation: partial"):
        check("3ch-text-%s" % row.split(" ")[0].replace(":", ""),
              row in proc.stdout)

    proc = report("json", EXAMPLE3)
    check("3ch-json-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    try:
        doc = json.loads(proc.stdout)
    except ValueError as err:
        print("FAIL 3ch-json-parses %s" % err)
        sys.exit(1)
    check("3ch-json-parses", True)
    want = {"bounce_attempts": "208",
            "copy_original_to_bounce_bytes": "35002",
            "copy_bounce_to_original_bytes": "24784",
            "completed_lifetime_count": "208"}
    for name, value in sorted(want.items()):
        got = [m for m in doc["metrics"]
               if m["name"] == name
               and (m.get("dimensions") or {}).get("device_id") is None]
        check("3ch-json-%s" % name, len(got) == 1
              and got[0]["value"] == value,
              json.dumps(got)[:160])
    check("3ch-json-terminal-partial",
          doc["quality"]["terminal"]["status"] == "partial")
    incomplete = [f for f in doc["findings"]
                  if f["code"] == "CAPTURE_INCOMPLETE"]
    check("3ch-json-incomplete-finding", len(incomplete) == 1
          and bool(incomplete[0]["evidence_refs"]))

    proc = report("markdown", EXAMPLE3)
    check("3ch-markdown-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    check("3ch-markdown-count", "bounce\\_attempts" in proc.stdout
          and "| 208 |" in proc.stdout)
    check("3ch-markdown-copy", "copy\\_original\\_to\\_bounce\\_bytes"
          in proc.stdout and "| 35002 |" in proc.stdout)

    proc = subprocess.run(
        [BIN, "top", "--interval", "60s", EXAMPLE3],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    check("3ch-top-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    check("3ch-top-count", "bounce_attempts = 208" in proc.stdout)


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

    incomplete = [f for f in doc["findings"] if f["code"] == "CAPTURE_INCOMPLETE"]
    check("json-incomplete-finding", len(incomplete) == 1
          and bool(incomplete[0]["evidence_refs"]))

    proc = report("markdown")
    check("markdown-exit", proc.returncode == 4,
          "exit %d: %s" % (proc.returncode, proc.stderr.strip()))
    check("markdown-count", "bounce\\_attempts" in proc.stdout
          and "| 30 |" in proc.stdout)

    check_three_channel()

    print("examples: all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
