#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mixed-workload soak: repeated replay cycles with RSS watch.

Replays a 50,000-record capture in all formats plus top for
MEMVEIL_SOAK_MINUTES (default 30), sampling wall time and
child peak RSS per cycle. Every cycle must exit stable with
exact counts; peak RSS must stay within the 256 MiB envelope
with no cycle failure. A passing soak earns no always-on
service claim. Exits nonzero on the first failure.
"""

import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
import time

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from replay import SIZES, generate  # noqa: E402

BIN = os.path.join(REPO, "build", "memveil")
COUNT = 50000


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def metric(doc, name):
    for m in doc.get("metrics", []):
        if m["name"] == name and "device_id" not in m:
            return m
    raise KeyError(name)


def main():
    if not os.path.isfile(BIN):
        print("FAIL soak: missing %s (run tools/build first)" % BIN)
        sys.exit(1)
    minutes = float(os.environ.get("MEMVEIL_SOAK_MINUTES", "30"))
    deadline = time.monotonic() + minutes * 60
    tmp = tempfile.mkdtemp(prefix="mvsoak")
    try:
        want = generate(os.path.join(tmp, "cap"), "soak-50k", COUNT)
        cycles = 0
        peak = 0
        walls = []
        while time.monotonic() < deadline:
            for fmt in ("text", "markdown", "json"):
                start = time.monotonic()
                p = subprocess.run(
                    [BIN, "report", "--format", fmt,
                     os.path.join(tmp, "cap")], capture_output=True)
                walls.append(time.monotonic() - start)
                if p.returncode != 0:
                    check("soak-exit", False,
                          "cycle %d fmt %s exit %d"
                          % (cycles, fmt, p.returncode))
                text = p.stdout.decode("utf-8")
                if fmt == "json":
                    doc = json.loads(text)
                    if (metric(doc, "bounce_attempts")["value"]
                            != str(COUNT)):
                        check("soak-count", False,
                              "cycle %d" % cycles)
                    if (metric(doc, "requested_bounce_bytes")["value"]
                            != str(want)):
                        check("soak-bytes", False,
                              "cycle %d" % cycles)
                    detail = None
                    for channel in doc.get("quality", {}).values():
                        if "bounce_attempt events" in str(
                                channel.get("scope", "")):
                            detail = channel
                    if (detail is None
                            or detail.get("status")
                            != "complete_for_scope"
                            or str(detail.get("loss_count")) != "0"):
                        check("soak-quality", False,
                              "cycle %d" % cycles)
                elif fmt == "text":
                    if not re.search(
                            r"^  bounce_attempts = %d count "
                            % COUNT, text, re.M):
                        check("soak-text-count", False,
                              "cycle %d" % cycles)
                    if not re.search(
                            r"^  requested_bounce_bytes = %d bytes "
                            % want, text, re.M):
                        check("soak-text-bytes", False,
                              "cycle %d" % cycles)
                elif fmt == "markdown":
                    if not re.search(
                            r"^\| bounce\\_attempts \| all \| %d \|"
                            % COUNT, text, re.M):
                        check("soak-md-count", False,
                              "cycle %d" % cycles)
                    if not re.search(
                            r"^\| requested\\_bounce\\_bytes \| all \| "
                            r"%d \|" % want, text, re.M):
                        check("soak-md-bytes", False,
                              "cycle %d" % cycles)
            # One 60 s refresh block: the soak watches replay
            # cost, not the 1 s wall pacing of default top.
            p = subprocess.run([BIN, "top", "--interval", "60s",
                                os.path.join(tmp, "cap")],
                               capture_output=True)
            if p.returncode != 0:
                check("soak-top", False, "cycle %d exit %d"
                      % (cycles, p.returncode))
            # The final summary renders the same rows as the
            # text report, so the exact count must appear.
            if not re.search(
                    r"^  bounce_attempts = %d count " % COUNT,
                    p.stdout.decode("utf-8"), re.M):
                check("soak-top-count", False,
                      "cycle %d" % cycles)
            peak = resource.getrusage(
                resource.RUSAGE_CHILDREN).ru_maxrss
            cycles += 1
        check("soak-cycles", cycles > 0)
        check("soak-rss", peak <= 256 * 1024, "%d KiB" % peak)
        print("soak: %d cycles in %.1f min, peak %d KiB, "
              "max cycle %.1fs"
              % (cycles, minutes, peak, max(walls) if walls else 0))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
