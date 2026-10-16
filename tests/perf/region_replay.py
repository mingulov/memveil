#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Region scaling replay: fragmented-region stress with oracle equality.

Generates mixed attempt/mapping/fragmented-region captures with
known unions and lifetimes, replays each scale step through the
built report verb, and asserts correctness first (exact counts
and oracle unions), then the declared envelope below.

Workload (declared before measurement):
  STEPS: big-region hole counts, doubling, up to the admitted
    65,536-segment ceiling (final step saturates it).
  Big region "big": one shared span [0, k*8192), then k private
    holes [i*8192, i*8192+4096). Final: k shared plus k private
    segments; shared and private unions are k*4096 each.
  Hot region "hot": HOT_TOGGLES alternating shared/private
    conversions over [0,4096), applied after the big region is
    fully built, so every hot update meets the full fragmented
    state. Final: one segment.
  Partial region "part": shared [0,8192), then a failed private
    [0,4096) without rollback proof: unknown [0,4096) plus
    shared [4096,8192). Final: two segments.
  Background: MAP_OPS attempt/map pairs with FIFO unmaps at a
    controlled peak of PEAK_OPEN open mappings; every mapping
    opens and closes exactly once on dev-1.
  Active-ceiling step: one further capture with a small
    fragmented region but MAP_OPS_CEILING mappings peaking at
    PEAK_CEILING simultaneously open lifetimes, one slot
    under the admitted ACTIVE_MAX ceiling, proving the
    active-mapping envelope with exact counts.
Envelope (replay targets from docs/performance.md):
  wall <= 60 s per scale replay, benchmark peak RSS <= 256 MiB,
  exact output equality at every step. Throughput is reported
  per step next to the documented 10,000 records/s replay
  target for context.
"""

import bisect
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

# Declared workload: doubling hole counts up to the admitted
# segment ceiling (2*32766+3 = 65535 of 65536 segments).
STEPS = (1024, 2048, 4096, 8192, 16384, 32766)
HOT_TOGGLES = 4096
MAP_OPS = 4096
PEAK_OPEN = 1024
# Active-ceiling step: small region, mappings driven to one
# slot under the admitted ACTIVE_MAX ceiling (65535 live).
CEILING_HOLES = 64
MAP_OPS_CEILING = 66000
PEAK_CEILING = 65535
MAP_BYTES = 4096
HOLE_STRIDE = 8192
HOLE_BYTES = 4096

# Admitted product limits (docs/resource-limits.md).
SEGMENTS_MAX = 65536
REGION_MAX = 4096
ACTIVE_MAX = 65536

# Declared envelope (docs/performance.md replay targets).
WALL_BUDGET_S = 60.0
RSS_BUDGET_KIB = 256 * 1024
RATE_TARGET = 10000

WINDOW_START = 1000000000
TS_STEP = 1000000

U64MAX = (1 << 64) - 1


def check(name, cond, detail=""):
    if not cond:
        print("FAIL %s %s" % (name, detail))
        sys.exit(1)
    print("ok %s" % name)


class Lineage:
    """One lineage of disjoint merged half-open intervals."""

    def __init__(self):
        self._starts = []
        self._ends = []
        self._states = []

    def assign(self, start, end, state):
        if start >= end:
            return
        starts, ends, states = self._starts, self._ends, self._states
        first = bisect.bisect_right(ends, start)
        last = bisect.bisect_left(starts, end) - 1
        repl_s, repl_e, repl_t = [], [], []
        if first <= last:
            if starts[first] < start:
                repl_s.append(starts[first])
                repl_e.append(start)
                repl_t.append(states[first])
        repl_s.append(start)
        repl_e.append(end)
        repl_t.append(state)
        if first <= last:
            if ends[last] > end:
                repl_s.append(end)
                repl_e.append(ends[last])
                repl_t.append(states[last])
        if first <= last:
            del starts[first:last + 1]
            del ends[first:last + 1]
            del states[first:last + 1]
        # Merge with the predecessor and inside the splice.
        if first > 0 and states[first - 1] == repl_t[0] and \
                ends[first - 1] == repl_s[0]:
            repl_s[0] = starts[first - 1]
            del starts[first - 1]
            del ends[first - 1]
            del states[first - 1]
            first -= 1
        merged_s = [repl_s[0]]
        merged_e = [repl_e[0]]
        merged_t = [repl_t[0]]
        for s, e, t in zip(repl_s[1:], repl_e[1:], repl_t[1:]):
            if merged_t[-1] == t and merged_e[-1] == s:
                merged_e[-1] = e
            else:
                merged_s.append(s)
                merged_e.append(e)
                merged_t.append(t)
        if first < len(starts) and merged_t[-1] == states[first] and \
                merged_e[-1] == starts[first]:
            merged_e[-1] = ends[first]
            del starts[first]
            del ends[first]
            del states[first]
        starts[first:first] = merged_s
        ends[first:first] = merged_e
        states[first:first] = merged_t

    def unions(self):
        out = {"shared": 0, "private": 0, "unknown": 0}
        for s, e, t in zip(self._starts, self._ends, self._states):
            out[t] += e - s
        return out

    def segments(self):
        return len(self._starts)


class IntervalOracle:
    """Independent region interval model for small instances."""

    def __init__(self):
        self._lineages = {}
        self.requests = 0
        self.failures = 0
        self.request_bytes = 0
        self.bytes_overflow = False

    def apply(self, region, state, success, offset, length):
        if offset + length > U64MAX:
            raise ValueError("oracle: span overflows")
        self.requests += 1
        if not success:
            self.failures += 1
        if self.request_bytes + length > U64MAX:
            self.bytes_overflow = True
        else:
            self.request_bytes += length
        lineage = self._lineages.setdefault(region, Lineage())
        if success:
            lineage.assign(offset, offset + length, state)
        else:
            lineage.assign(offset, offset + length, "unknown")

    def unions(self):
        out = {"shared": 0, "private": 0, "unknown": 0}
        for lineage in self._lineages.values():
            for key, val in lineage.unions().items():
                out[key] += val
        return out

    def segments(self):
        return sum(lg.segments() for lg in
                   self._lineages.values())

    def lineages(self):
        return len(self._lineages)


# Frozen lifetime-histogram boundary table, transcribed from the
# documented contract: bucket 0 holds exactly 0, and each later
# bucket ends at the next all-ones boundary. Entry i is the
# inclusive upper edge reported for any duration at or below it.
# Deliberately literal: expected edges come from this table plus
# binary search, not from re-implementing product bucket math.
_LIFETIME_BUCKET_EDGES = (
    0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095,
    8191, 16383, 32767, 65535, 131071, 262143, 524287, 1048575,
    2097151, 4194303, 8388607, 16777215, 33554431, 67108863,
    134217727, 268435455, 536870911, 1073741823, 2147483647,
    4294967295, 8589934591, 17179869183, 34359738367, 68719476735,
    137438953471, 274877906943, 549755813887, 1099511627775,
    2199023255551, 4398046511103, 8796093022207, 17592186044415,
    35184372088831, 70368744177663, 140737488355327, 281474976710655,
    562949953421311, 1125899906842623, 2251799813685247,
    4503599627370495, 9007199254740991, 18014398509481983,
    36028797018963967, 72057594037927935, 144115188075855871,
    288230376151711743, 576460752303423487, 1152921504606846975,
    2305843009213693951, 4611686018427387903, 9223372036854775807,
    18446744073709551615,
)


def _lifetime_edge_for_duration(value):
    """Inclusive upper edge for one duration via the frozen table."""
    if value < 0 or value > U64MAX:
        raise ValueError("lifetime out of range")
    return _LIFETIME_BUCKET_EDGES[
        bisect.bisect_left(_LIFETIME_BUCKET_EDGES, value)]


def _lifetime_rank(num, den, count):
    """Nearest rank ceil(num*count/den) with unbounded integers."""
    if den <= 0 or num <= 0 or num > den or count <= 0:
        raise ValueError("bad percentile input")
    return (num * count + den - 1) // den


class LifetimeOracle:
    """Independent timestamp-based mapping lifetime model.

    Records map timestamps and release timestamps from the
    capture, then derives completed durations, final open
    state, and peak occupancy by a chronological sweep with
    releases ordered before maps at equal timestamps.
    """

    def __init__(self):
        self._open = {}
        self._durations = []
        self._sweep = []
        self.live_bytes = 0
        self.peak_bytes = 0
        self.peak_open = 0

    def note_map(self, mapping, ts, nbytes):
        if mapping in self._open:
            raise ValueError("oracle: duplicate map")
        self._open[mapping] = (ts, nbytes)
        self._sweep.append((ts, 1, mapping, nbytes))

    def note_unmap(self, mapping, ts):
        if mapping not in self._open:
            raise ValueError("oracle: orphan release")
        map_ts, nbytes = self._open.pop(mapping)
        if ts < map_ts:
            raise ValueError("oracle: reversed lifetime")
        self._durations.append(ts - map_ts)
        self._sweep.append((ts, 0, mapping, nbytes))

    def finalize(self):
        live = {}
        live_bytes = 0
        peak = 0
        peak_open = 0
        for _, order, mapping, nbytes in sorted(self._sweep):
            if order == 0:
                live_bytes -= live.pop(mapping)
            else:
                live[mapping] = nbytes
                live_bytes += nbytes
                if live_bytes > peak:
                    peak = live_bytes
                if len(live) > peak_open:
                    peak_open = len(live)
        self.live_bytes = live_bytes
        self.peak_bytes = peak
        self.peak_open = peak_open

    @property
    def completed(self):
        return len(self._durations)

    @property
    def open_count(self):
        return len(self._open)

    @property
    def mean_ns(self):
        return sum(self._durations) // len(self._durations)

    @property
    def min_ns(self):
        return min(self._durations)

    @property
    def max_ns(self):
        return max(self._durations)

    def _edge(self, num, den):
        ordered = sorted(self._durations)
        rank = _lifetime_rank(num, den, len(ordered))
        return _lifetime_edge_for_duration(ordered[rank - 1])

    @property
    def p50_edge(self):
        return self._edge(50, 100)

    @property
    def p95_edge(self):
        return self._edge(95, 100)

    @property
    def p99_edge(self):
        return self._edge(99, 100)


def lifetime_oracle_from_capture(path):
    """Rebuild lifetime facts from capture timestamps only."""
    oracle = LifetimeOracle()
    with open(os.path.join(path, "events.ndjson")) as fh:
        for line in fh:
            ev = json.loads(line)
            if ev["kind"] == "map_result":
                if ev["data"]["success"]:
                    oracle.note_map(
                        ev["data"]["mapping_id"],
                        int(ev["ts_ns"]),
                        int(ev["data"]["mapped_bytes"]))
            elif ev["kind"] == "unmap":
                oracle.note_unmap(
                    ev["data"]["mapping_id"], int(ev["ts_ns"]))
    oracle.finalize()
    return oracle


def check_oracle_on_frozen_fixtures():
    """Prove the oracle against pinned contract expectations."""
    cases = (
        ("region-union",
         {"shared": 8192, "private": 4096, "unknown": 0,
          "requests": 3, "failures": 0}),
        ("conversion-uncertain",
         {"shared": 4096, "private": 0, "unknown": 4096,
          "requests": 2, "failures": 1}),
    )
    for fixture, want in cases:
        path = os.path.join(REPO, "tests", "fixtures", "regions",
                            fixture, "events.ndjson")
        oracle = IntervalOracle()
        with open(path) as fh:
            for line in fh:
                ev = json.loads(line)
                if ev["kind"] != "transition_result":
                    continue
                data = ev["data"]
                oracle.apply(ev["data"]["region_id"],
                             data["requested_state"],
                             data["success"],
                             int(data["offset"]),
                             int(data["length"]))
        got = oracle.unions()
        got["requests"] = oracle.requests
        got["failures"] = oracle.failures
        check("oracle-%s" % fixture, got == want,
              "got %r want %r" % (got, want))


def session_doc(sid, event_count):
    base = json.load(open(os.path.join(
        REPO, "tests", "fixtures", "regions", "region-union",
        "session.json")))
    base["session_id"] = sid
    base["capture"]["window"] = {
        "start_ns": str(WINDOW_START),
        "end_ns": str(WINDOW_START + (event_count + 100) * TS_STEP)}
    base["capabilities"]["bounce_attempts"] = {
        "status": "verified",
        "reason": "Benchmark session: synthetic region-scaling load.",
        "hooks": ["swiotlb:swiotlb_bounced"],
        "profile_id": "synthetic-lifecycle-1"}
    base["capabilities"]["mapping_lifecycle"] = {
        "status": "verified",
        "reason": "Benchmark session: synthetic region-scaling load.",
        "hooks": ["synthetic:map_result"],
        "profile_id": "synthetic-lifecycle-1"}
    for cap in ("conversion_results", "region_state"):
        base["capabilities"][cap] = {
            "status": "verified",
            "reason": "Benchmark session: synthetic region-scaling load.",
            "hooks": ["synthetic:transition"],
            "profile_id": "synthetic-regions-1"}
    base["quality"]["detail"]["scope"] = "%d benchmark events" % event_count
    base["quality"]["detail"]["reason"] = "Benchmark session: no loss."
    base["quality"]["correlation"]["scope"] = \
        "correlated benchmark events"
    base["quality"]["correlation"]["reason"] = \
        "Benchmark session: every relationship pairs."
    base["quality"]["baseline"]["reason"] = \
        "Benchmark session: known-empty initial state."
    base["quality"]["terminal"]["reason"] = "Benchmark session: finalized."
    return base


def attempt_line(sid, seq, ts, op, i):
    return json.dumps({
        "schema_version": "0.1.1", "session_id": sid,
        "source": {"hook": "swiotlb:swiotlb_bounced",
                   "backend": "synthetic",
                   "profile_id": "synthetic-lifecycle-1",
                   "measurement": "observed",
                   "correlation": "direct"},
        "seq": str(seq), "ts_ns": str(ts), "kind": "bounce_attempt",
        "data": {"device_id": "dev-1",
                 "requested_bytes": str(MAP_BYTES),
                 "forced": i % 2 == 0, "operation_id": op}},
        separators=(",", ":"))


def map_line(sid, seq, ts, op, mapping):
    return json.dumps({
        "schema_version": "0.1.1", "session_id": sid,
        "source": {"hook": "synthetic:map_result",
                   "backend": "synthetic",
                   "profile_id": "synthetic-lifecycle-1",
                   "measurement": "observed",
                   "correlation": "direct"},
        "seq": str(seq), "ts_ns": str(ts), "kind": "map_result",
        "data": {"operation_id": op, "success": True,
                 "mapping_id": mapping, "return_code": None,
                 "mapped_bytes": str(MAP_BYTES),
                 "wire_generation": None, "wire_identity": None}},
        separators=(",", ":"))


def unmap_line(sid, seq, ts, mapping):
    return json.dumps({
        "schema_version": "0.1.1", "session_id": sid,
        "source": {"hook": "synthetic:map_result",
                   "backend": "synthetic",
                   "profile_id": "synthetic-lifecycle-1",
                   "measurement": "observed",
                   "correlation": "direct"},
        "seq": str(seq), "ts_ns": str(ts), "kind": "unmap",
        "data": {"mapping_id": mapping, "wire_generation": None,
                 "wire_identity": None}},
        separators=(",", ":"))


def transition_line(sid, seq, ts, region, state, success, offset,
                    length):
    return json.dumps({
        "schema_version": "0.1.1", "session_id": sid,
        "source": {"hook": "synthetic:transition",
                   "backend": "synthetic",
                   "profile_id": "synthetic-regions-1",
                   "measurement": "observed",
                   "correlation": "direct"},
        "seq": str(seq), "ts_ns": str(ts), "kind": "transition_result",
        "data": {"region_id": region, "requested_state": state,
                 "success": success,
                 "return_code": 0 if success else -5,
                 "offset": str(offset), "length": str(length),
                 "address_space": "guest_physical",
                 "resolution": "resolved"}},
        separators=(",", ":"))


def generate(path, sid, holes, map_ops=MAP_OPS,
             peak_open_limit=PEAK_OPEN):
    """Write one mixed capture; return known facts for the oracle."""
    os.makedirs(path, exist_ok=True)
    transitions = []
    lines = []
    seq = 0
    peak_open = 0
    open_now = 0
    for i in range(map_ops):
        if i >= peak_open_limit:
            seq += 1
            lines.append(unmap_line(
                sid, seq, WINDOW_START + seq * TS_STEP,
                "map-%06d" % (i - peak_open_limit)))
            open_now -= 1
        seq += 1
        lines.append(attempt_line(
            sid, seq, WINDOW_START + seq * TS_STEP,
            "op-%06d" % i, i))
        seq += 1
        lines.append(map_line(
            sid, seq, WINDOW_START + seq * TS_STEP,
            "op-%06d" % i, "map-%06d" % i))
        open_now += 1
        peak_open = max(peak_open, open_now)
    span = holes * HOLE_STRIDE
    seq += 1
    lines.append(transition_line(
        sid, seq, WINDOW_START + seq * TS_STEP,
        "big", "shared", True, 0, span))
    transitions.append(("big", "shared", True, 0, span))
    for i in range(holes):
        seq += 1
        lines.append(transition_line(
            sid, seq, WINDOW_START + seq * TS_STEP,
            "big", "private", True, i * HOLE_STRIDE, HOLE_BYTES))
        transitions.append(("big", "private", True,
                            i * HOLE_STRIDE, HOLE_BYTES))
    seq += 1
    lines.append(transition_line(
        sid, seq, WINDOW_START + seq * TS_STEP,
        "part", "shared", True, 0, 8192))
    transitions.append(("part", "shared", True, 0, 8192))
    seq += 1
    lines.append(transition_line(
        sid, seq, WINDOW_START + seq * TS_STEP,
        "part", "private", False, 0, 4096))
    transitions.append(("part", "private", False, 0, 4096))
    for i in range(HOT_TOGGLES):
        state = "shared" if i % 2 == 0 else "private"
        seq += 1
        lines.append(transition_line(
            sid, seq, WINDOW_START + seq * TS_STEP,
            "hot", state, True, 0, 4096))
        transitions.append(("hot", state, True, 0, 4096))
    for i in range(map_ops - peak_open_limit, map_ops):
        seq += 1
        lines.append(unmap_line(
            sid, seq, WINDOW_START + seq * TS_STEP,
            "map-%06d" % i))
        open_now -= 1
    with open(os.path.join(path, "session.json"), "w") as fh:
        json.dump(session_doc(sid, len(lines)), fh)
    with open(os.path.join(path, "events.ndjson"), "w") as fh:
        for line in lines:
            fh.write(line + "\n")
    assert open_now == 0, "benchmark: mapping leak %d" % open_now
    span = holes * HOLE_STRIDE
    closed = {
        "requests": 1 + holes + 2 + HOT_TOGGLES,
        "failures": 1,
        "request_bytes": span + holes * HOLE_BYTES + 8192 + 4096
        + HOT_TOGGLES * 4096,
        "shared": holes * HOLE_BYTES + 4096,
        "private": holes * HOLE_BYTES + 4096,
        "unknown": 4096,
        "segments": 2 * holes + 3,
        "lineages": 3,
        "bounce": map_ops,
        "bounce_bytes": map_ops * MAP_BYTES,
        "allocations": map_ops,
        "mapped_bytes": map_ops * MAP_BYTES,
        "peak_open": peak_open,
        "events": len(lines),
    }
    return transitions, closed


def child_usage():
    ru = resource.getrusage(resource.RUSAGE_CHILDREN)
    return ru.ru_utime + ru.ru_stime, ru.ru_maxrss


def replay(path):
    cpu_before, _ = child_usage()
    start = time.monotonic()
    p = subprocess.run([BIN, "report", "--format", "json", path],
                       capture_output=True)
    wall = time.monotonic() - start
    cpu_after, rss_kb = child_usage()
    return p, wall, cpu_after - cpu_before, rss_kb


def gmetric(doc, name):
    for m in doc.get("metrics", []):
        if m["name"] == name and \
                m["dimensions"]["device_id"] is None:
            return m
    raise KeyError(name)


def dmetric(doc, name, device):
    for m in doc.get("metrics", []):
        if m["name"] == name and \
                m["dimensions"].get("device_id") == device:
            return m
    raise KeyError("%s[%s]" % (name, device))


def main():
    if not os.path.isfile(BIN):
        print("FAIL region-replay: missing %s (run tools/build first)"
              % BIN)
        sys.exit(1)
    check_oracle_on_frozen_fixtures()
    tmp = tempfile.mkdtemp(prefix="mvregion")
    peak_rss = 0
    specs = [("holes-%d" % holes, "region-scale-%d" % holes,
              holes, MAP_OPS, PEAK_OPEN) for holes in STEPS]
    specs.append(("active-ceiling", "region-active-ceiling",
                  CEILING_HOLES, MAP_OPS_CEILING, PEAK_CEILING))
    try:
        for tag, sid, holes, map_ops, peak_want in specs:
            path = os.path.join(tmp, tag)
            t0 = time.monotonic()
            transitions, closed = generate(
                path, sid, holes, map_ops, peak_want)
            gen_s = time.monotonic() - t0
            oracle = IntervalOracle()
            for region, state, ok, off, ln in transitions:
                oracle.apply(region, state, ok, off, ln)
            unions = oracle.unions()
            check("%s-oracle-segments" % tag,
                  oracle.segments() == closed["segments"] and
                  oracle.segments() <= SEGMENTS_MAX,
                  "%d" % oracle.segments())
            check("%s-oracle-lineages" % tag,
                  oracle.lineages() == closed["lineages"] and
                  oracle.lineages() <= REGION_MAX)
            check("%s-oracle-unions" % tag,
                  unions["shared"] == closed["shared"] and
                  unions["private"] == closed["private"] and
                  unions["unknown"] == closed["unknown"],
                  "%r" % (unions,))
            check("%s-oracle-counts" % tag,
                  oracle.requests == closed["requests"] and
                  oracle.failures == closed["failures"] and
                  oracle.request_bytes == closed["request_bytes"] and
                  not oracle.bytes_overflow)
            check("%s-peak-open" % tag,
                  closed["peak_open"] == peak_want and
                  peak_want <= ACTIVE_MAX,
                  "%d" % closed["peak_open"])
            life = lifetime_oracle_from_capture(path)
            check("%s-lifetime-oracle-count" % tag,
                  life.completed == map_ops,
                  "%d" % life.completed)
            check("%s-lifetime-oracle-open" % tag,
                  life.open_count == 0 and
                  life.live_bytes == 0,
                  "open %d live %d"
                  % (life.open_count, life.live_bytes))
            check("%s-lifetime-oracle-peak" % tag,
                  life.peak_bytes == peak_want * MAP_BYTES and
                  life.peak_open == peak_want,
                  "%d" % life.peak_bytes)
            size = os.path.getsize(
                os.path.join(path, "events.ndjson"))
            check("%s-input-cap" % tag, size < 256 * 1024 * 1024,
                  "%d bytes" % size)
            print("region: %s: %d events, %d bytes in %.1fs"
                  % (tag, closed["events"], size, gen_s))
            p, wall, cpu, rss = replay(path)
            peak_rss = max(peak_rss, rss)
            # Exit 4: the designed unknown interval keeps the
            # state unions partial, output still complete.
            check("%s-exit" % tag, p.returncode == 4,
                  "exit %d: %s" % (p.returncode, p.stderr[:200]))
            doc = json.loads(p.stdout.decode("utf-8"))
            check("%s-bounce" % tag,
                  gmetric(doc, "bounce_attempts")["value"]
                  == str(closed["bounce"]))
            check("%s-bounce-bytes" % tag,
                  gmetric(doc, "requested_bounce_bytes")["value"]
                  == str(closed["bounce_bytes"]))
            check("%s-requests" % tag,
                  gmetric(doc, "conversion_requests")["value"]
                  == str(closed["requests"]))
            check("%s-failures" % tag,
                  gmetric(doc, "conversion_failures")["value"]
                  == str(closed["failures"]))
            check("%s-request-bytes" % tag,
                  gmetric(doc, "conversion_request_bytes")["value"]
                  == str(closed["request_bytes"]))
            check("%s-shared" % tag,
                  gmetric(doc, "known_shared_region_bytes")["value"]
                  == str(closed["shared"]))
            check("%s-private" % tag,
                  gmetric(doc, "known_private_region_bytes")["value"]
                  == str(closed["private"]))
            check("%s-unknown" % tag,
                  gmetric(doc, "unknown_region_bytes")["value"]
                  == str(closed["unknown"]))
            check("%s-union-coverage" % tag,
                  gmetric(doc, "known_shared_region_bytes")
                  ["coverage"] == "partial" and
                  gmetric(doc, "known_private_region_bytes")
                  ["coverage"] == "partial" and
                  gmetric(doc, "unknown_region_bytes")
                  ["coverage"] == "partial")
            check("%s-allocations" % tag,
                  dmetric(doc, "successful_allocations", "dev-1")
                  ["value"] == str(closed["allocations"]))
            check("%s-mapped" % tag,
                  dmetric(doc, "mapped_bytes_total", "dev-1")
                  ["value"] == str(closed["mapped_bytes"]))
            check("%s-completed-lifetimes" % tag,
                  gmetric(doc, "completed_lifetime_count")["value"]
                  == str(life.completed) and
                  life.completed == map_ops)
            check("%s-open" % tag,
                  gmetric(doc, "open_mappings")["value"] == "0" and
                  life.open_count == 0)
            check("%s-live" % tag,
                  gmetric(doc, "live_observed_allocation_bytes")
                  ["value"] == "0" and life.live_bytes == 0)
            check("%s-peak-live" % tag,
                  gmetric(doc, "peak_live_observed_allocation_bytes")
                  ["value"] == str(life.peak_bytes) and
                  life.peak_bytes == peak_want * MAP_BYTES)
            check("%s-lifetime-mean" % tag,
                  gmetric(doc, "lifetime_mean_ns")["value"]
                  == str(life.mean_ns))
            check("%s-lifetime-min" % tag,
                  gmetric(doc, "lifetime_min_ns")["value"]
                  == str(life.min_ns))
            check("%s-lifetime-max" % tag,
                  gmetric(doc, "lifetime_max_ns")["value"]
                  == str(life.max_ns))
            check("%s-lifetime-p50" % tag,
                  gmetric(doc, "lifetime_p50_ns")["value"]
                  == str(life.p50_edge))
            check("%s-lifetime-p95" % tag,
                  gmetric(doc, "lifetime_p95_ns")["value"]
                  == str(life.p95_edge))
            check("%s-lifetime-p99" % tag,
                  gmetric(doc, "lifetime_p99_ns")["value"]
                  == str(life.p99_edge))
            check("%s-no-budget-refusal" % tag,
                  not any("interval budget exceeded" in lim or
                          "region table exhausted" in lim or
                          "token reused" in lim or
                          "Active mapping table exhausted" in lim
                          for lim in doc.get("limitations", [])),
                  "%r" % (doc.get("limitations", []),))
            rate = closed["events"] / wall if wall > 0 else 0.0
            print("region: %s: wall %.1fs cpu %.1fs rss %d KiB "
                  "(%.1f MiB) rate %.0f records/s (target %d)"
                  % (tag, wall, cpu, rss, rss / 1024.0, rate,
                     RATE_TARGET))
            check("%s-wall" % tag, wall <= WALL_BUDGET_S,
                  "%.1fs over %.0fs" % (wall, WALL_BUDGET_S))
        check("peak-rss", peak_rss <= RSS_BUDGET_KIB,
              "%d KiB over %d KiB" % (peak_rss, RSS_BUDGET_KIB))
        print("region: peak rss %d KiB (%.1f MiB)"
              % (peak_rss, peak_rss / 1024.0))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
