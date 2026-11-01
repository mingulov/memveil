#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Replay performance: 600k-record target, scaling, paced stream.

Generates a fixed 600,000-record synthetic capture with
independently known totals, replays it through the built
report verb, and asserts correctness first (exact counts),
then the envelope (wall <= 60 s, RSS <= 256 MiB). Also
checks prefix scaling (100k/300k) and paced regular-file reads
for steady-state bounds. Prints CSV/JSON measurements to
stdout. Exits nonzero on the first failure.
"""

import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
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
        "schema_version": "0.1.1", "session_id": sid,
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


def generate_sealed(path, sid, count):
    """Generate a separate zero-based integrity case using hashlib as oracle."""
    os.mkdir(path)
    digest = hashlib.sha256()
    size = 0
    total = 0
    with open(os.path.join(path, "events.ndjson"), "xb") as stream:
        for i in range(count):
            requested = SIZES[i % len(SIZES)]
            total += requested
            timestamp = WINDOW_START + i * (WINDOW_END - WINDOW_START) // count
            line = (event_line(sid, i, timestamp, requested, i % 2 == 0,
                               "op%06d" % i) + "\n").encode()
            stream.write(line)
            digest.update(line)
            size += len(line)
    doc = session_doc(sid)
    doc["schema_version"] = "0.1.4"
    kinds = dict.fromkeys(("bounce_attempt", "map_result", "unmap", "copy",
                           "sync_request", "transition_result", "pool_sample",
                           "gap", "marker", "counter_snapshot"), "0")
    kinds["bounce_attempt"] = str(count)
    doc["capture"]["integrity"] = {
        "algorithm": "sha256", "events_bytes": str(size),
        "line_count": str(count), "first_seq": "0", "last_seq": str(count - 1),
        "events_sha256": digest.hexdigest(), "kinds": kinds}
    with open(os.path.join(path, "session.json"), "x") as stream:
        json.dump(doc, stream)
    return total, size


def replay(path, fmt="json", env=None):
    # ru_maxrss is the waited-children high-water mark: exact
    # for the first replayed child, an upper bound after that.
    # The envelope assertion runs on the first replay only.
    start = time.monotonic()
    p = subprocess.run([BIN, "report", "--format", fmt, path],
                       capture_output=True, env=env)
    wall = time.monotonic() - start
    rss_kb = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    return p, wall, rss_kb


def metric(doc, name):
    for m in doc.get("metrics", []):
        if m["name"] == name and "device_id" not in m:
            return m
    raise KeyError(name)


def paced_errors(receipt, source_stat, count, size, duration_ns, wall):
    errors = []
    for key, expected in [('lines', count), ('bytes', size), ('eof', True), ('error', 0),
                          ('device', source_stat.st_dev), ('inode', source_stat.st_ino)]:
        if receipt.get(key) != expected:
            errors.append(key + ' differs from independent input')
    if not 0 < receipt.get('max_request_bytes', 0) <= 65536:
        errors.append('read request exceeded bounded buffer or was absent')
    if receipt.get('calls', 0) < (size + 65535) // 65536 + 1:
        errors.append('real read/EOF calls were not reached')
    if receipt.get('elapsed_ns', 0) < duration_ns or wall * 1000000000 < duration_ns:
        errors.append('paced duration was not reached')
    return errors


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
        # Sanitizer instrumentation slows CPU-bound replay
        # several-fold (up to ~7x observed); the sanitize lane
        # proves completion and memory safety, not wall
        # performance (plain-lane budgets are the perf
        # qualification). Uniform lane factor; a hang fails.
        wall_budget = 60.0 * (10.0 if os.environ.get("LMB_SANITIZE")
                              == "1" else 1.0)
        check("full-wall", wall <= wall_budget, "%.1fs" % wall)
        # ASan redzones roughly triple replay RSS; footprint
        # qualification stays on the plain lane (same x10 lane
        # multiplier as the runner's rss_mult precedent).
        rss_budget = 256 * 1024 * (10 if os.environ.get("LMB_SANITIZE")
                                   == "1" else 1)
        check("full-rss", rss <= rss_budget, "%d KiB" % rss)
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
        check("paced-positive-duration", paced_seconds > 0 and paced_lines > 0)
        paced_dir = os.path.join(tmp, "paced")
        os.makedirs(paced_dir)
        shutil.copy(os.path.join(tmp, "full", "session.json"), paced_dir)
        paced_file = os.path.join(paced_dir, "events.ndjson")
        with open(events, 'rb') as src, open(paced_file, 'xb') as dst:
            for _ in range(paced_lines):
                line = src.readline()
                if not line:
                    check("paced-source-line", False)
                dst.write(line)
        adapter = os.path.join(REPO, 'build', 'perf', 'paced_reads.so')
        os.makedirs(os.path.dirname(adapter), exist_ok=True)
        subprocess.run(['clang', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                        '-shared', '-fPIC', os.path.join(TESTS, 'perf', 'paced_reads.c'),
                        '-o', adapter], check=True)
        subprocess.run([sys.executable, os.path.join(TESTS, 'perf', 'test_paced_reads.py')], check=True)
        receipt_path = os.path.join(tmp, 'paced-reads.json')
        env = dict(os.environ, MEMVEIL_PACED_FILE=paced_file, MEMVEIL_PACED_RECEIPT=receipt_path,
                   MEMVEIL_PACED_LINES=str(paced_lines), MEMVEIL_PACED_NS=str(paced_seconds * 1000000000))
        env['LD_PRELOAD'] = adapter + (':' + env['LD_PRELOAD'] if env.get('LD_PRELOAD') else '')
        p, wall, rss = replay(paced_dir, env=env)
        receipt = json.load(open(receipt_path)) if os.path.isfile(receipt_path) else {}
        errors = paced_errors(receipt, os.stat(paced_file), paced_lines, os.path.getsize(paced_file),
                              paced_seconds * 1000000000, wall)
        check("paced-errors", not errors, "; ".join(errors[:3]))
        check("paced-exit", p.returncode == 0,
              "exit %d: %s" % (p.returncode, p.stderr[:200]))
        doc = json.loads(p.stdout.decode("utf-8"))
        check("paced-count", metric(doc, "bounce_attempts")["value"] == str(paced_lines))
        check("paced-bytes", metric(doc, "requested_bounce_bytes")["value"] ==
              str(sum(SIZES[i % len(SIZES)] for i in range(paced_lines))))
        check("paced-rss", rss <= rss_budget, "%d KiB" % rss)
        print("perf: paced %d lines over %ds, rss %d KiB" % (paced_lines, paced_seconds, rss))
        print('perf: actual paced reads ' + json.dumps(receipt, sort_keys=True))
        sealed = os.path.join(tmp, "sealed")
        sealed_total, sealed_size = generate_sealed(sealed, "sealed-600k", COUNT)
        p, wall, rss = replay(sealed)
        check("sealed-exit", p.returncode == 0, p.stderr[:200])
        doc = json.loads(p.stdout)
        check("sealed-count", metric(doc, "bounce_attempts")["value"] == str(COUNT))
        check("sealed-bytes", metric(doc, "requested_bounce_bytes")["value"] == str(sealed_total))
        check("sealed-integrity", doc["integrity"] == {
            "status": "verified", "verified_bytes": str(sealed_size),
            "verified_events": str(COUNT)})
        check("sealed-wall", wall <= wall_budget, "%.1fs" % wall)
        check("sealed-rss", rss <= rss_budget, "%d KiB" % rss)
        print("perf: sealed replay %.1fs, rss %d KiB (upper bound)" % (wall, rss))
        print(json.dumps({"records": COUNT, "bytes": size,
                          "want_bytes": want_bytes}))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
