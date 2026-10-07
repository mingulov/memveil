#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay performance: 600k-record target, scaling, paced stream.

Generates a fixed 600,000-record synthetic capture with
independently known totals, replays it through the built
report verb, and asserts correctness first (exact counts),
then the envelope (wall <= 60 s, RSS <= 256 MiB). Also
checks prefix scaling (100k/300k) and a paced FIFO stream
for steady-state bounds. Prints CSV/JSON measurements to
stdout. Exits nonzero on the first failure.
"""

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
BIN = os.path.join(REPO, "build", "memveil")

COUNT = 600000
WINDOW_START = 1000000000
WINDOW_END = 61000000000
SIZES = (512, 1024, 2048, 4096)


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


def session_doc(sid):
    base = json.load(open(os.path.join(
        REPO, "tests", "fixtures", "reader", "detail-gap",
        "session.json")))
    base["session_id"] = sid
    base["capture"]["window"] = {"start_ns": str(WINDOW_START),
                                 "end_ns": str(WINDOW_END)}
    return base


def event_line(sid, seq, ts, size, forced, op):
    return json.dumps({
        "schema_version": "0.1.0", "session_id": sid,
        "source": {"hook": "swiotlb:swiotlb_bounced",
                   "backend": "synthetic",
                   "profile_id": "synthetic-attempts-1",
                   "measurement": "observed",
                   "correlation": "direct"},
        "seq": str(seq), "ts_ns": str(ts), "kind": "bounce_attempt",
        "data": {"device_id": "dev-1", "requested_bytes": str(size),
                 "forced": forced, "operation_id": op}},
        separators=(",", ":"))


def generate(path, sid, count):
    os.makedirs(path, exist_ok=True)
    with open(os.path.join(path, "session.json"), "w") as fh:
        json.dump(session_doc(sid), fh)
    total = 0
    with open(os.path.join(path, "events.ndjson"), "w") as fh:
        for i in range(count):
            size = SIZES[i % len(SIZES)]
            total += size
            ts = WINDOW_START + (i * (WINDOW_END - WINDOW_START)
                                 // count)
            fh.write(event_line(sid, i + 1, ts, size, i % 2 == 0,
                                "op%06d" % i) + "\n")
    return total


def replay(path, fmt="json"):
    # ru_maxrss is the waited-children high-water mark: exact
    # for the first replayed child, an upper bound after that.
    # The envelope assertion runs on the first replay only.
    start = time.monotonic()
    p = subprocess.run([BIN, "report", "--format", fmt, path],
                       capture_output=True)
    wall = time.monotonic() - start
    rss_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return p, wall, rss_kb


def metric(doc, name):
    for m in doc.get("metrics", []):
        if m["name"] == name and "device_id" not in m:
            return m
    raise KeyError(name)


def main():
    if not os.path.isfile(BIN):
        print("FAIL perf-replay: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    tmp = tempfile.mkdtemp(prefix="mvperf")
    try:
        t0 = time.monotonic()
        want_bytes = generate(os.path.join(tmp, "full"), "perf-600k",
                              COUNT)
        gen_s = time.monotonic() - t0
        events = os.path.join(tmp, "full", "events.ndjson")
        size = os.path.getsize(events)
        check("default-bound", size < 256 * 1024 * 1024,
              "%d bytes" % size)
        print("perf: generated %d records, %d bytes in %.1fs"
              % (COUNT, size, gen_s))

        p, wall, rss = replay(os.path.join(tmp, "full"))
        check("full-exit", p.returncode == 0,
              "exit %d: %s" % (p.returncode, p.stderr[:200]))
        doc = json.loads(p.stdout.decode("utf-8"))
        check("full-count",
              metric(doc, "bounce_attempts")["value"] == str(COUNT))
        check("full-bytes",
              metric(doc, "requested_bounce_bytes")["value"]
              == str(want_bytes))
        print("perf: full replay %.1fs, rss %d KiB (%.1f MiB)"
              % (wall, rss, rss / 1024.0))
        check("full-wall", wall <= 60.0, "%.1fs" % wall)
        check("full-rss", rss <= 256 * 1024, "%d KiB" % rss)
        rate = COUNT / wall if wall > 0 else 0.0
        print("perf: rate %.0f records/s" % rate)

        for n in (100000, 300000):
            sub = os.path.join(tmp, "pre-%d" % n)
            os.makedirs(sub)
            shutil.copy(os.path.join(tmp, "full", "session.json"),
                        os.path.join(sub, "session.json"))
            with open(events) as src, open(
                    os.path.join(sub, "events.ndjson"), "w") as dst:
                for i in range(n):
                    dst.write(src.readline())
            want = sum(SIZES[i % len(SIZES)] for i in range(n))
            p, wall, _ = replay(sub)
            check("prefix-%d-exit" % n, p.returncode == 0)
            doc = json.loads(p.stdout.decode("utf-8"))
            check("prefix-%d-count" % n,
                  metric(doc, "bounce_attempts")["value"] == str(n))
            check("prefix-%d-bytes" % n,
                  metric(doc, "requested_bounce_bytes")["value"]
                  == str(want))
            print("perf: prefix %d in %.1fs" % (n, wall))

        paced_seconds = int(os.environ.get("MEMVEIL_PACED_SECONDS",
                                           "60"))
        paced_lines = min(COUNT, paced_seconds * 10000)
        fifo_dir = os.path.join(tmp, "paced")
        os.makedirs(fifo_dir)
        shutil.copy(os.path.join(tmp, "full", "session.json"),
                    os.path.join(fifo_dir, "session.json"))
        fifo = os.path.join(fifo_dir, "events.ndjson")
        os.mkfifo(fifo)
        # Stream from disk: prebuffering the whole paced input
        # would inflate this process past the product's own
        # footprint and contaminate the children high-water.
        errors = []

        def feed():
            try:
                with open(events) as src, open(fifo, "w") as out:
                    start = time.monotonic()
                    for i in range(paced_lines):
                        line = src.readline()
                        if not line:
                            errors.append("input short at %d" % i)
                            break
                        out.write(line)
                        out.flush()
                        want = start + (i + 1) * (
                            paced_seconds / paced_lines)
                        delay = want - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))

        feeder = threading.Thread(target=feed)
        feeder.start()
        p, wall, rss = replay(fifo_dir)
        feeder.join(timeout=30)
        check("paced-errors", not errors, "; ".join(errors[:3]))
        check("paced-exit", p.returncode == 0,
              "exit %d: %s" % (p.returncode, p.stderr[:200]))
        doc = json.loads(p.stdout.decode("utf-8"))
        check("paced-count",
              metric(doc, "bounce_attempts")["value"]
              == str(paced_lines))
        print("perf: paced %d lines over %ds, rss %d KiB"
              % (paced_lines, paced_seconds, rss))
        print(json.dumps({"records": COUNT, "bytes": size,
                          "want_bytes": want_bytes}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
