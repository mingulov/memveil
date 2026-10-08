#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent owned-DMA oracle ledger.

The ledger records raw driver calls (map attempts, outcomes,
copies, releases, allocator samples) as the test kernel module
performs them. It never imports reducer code and never applies
reducer math: expectations come from direct counting over the
raw entries, and lifetime quantiles are checked as exact
bucket membership of the true nearest rank.

compare() matches a finished JSON report against the sealed
ledger and returns a sorted list of mismatch strings, empty on
agreement. The harness treats any mismatch as a gate failure.
"""

import json

BUCKETS = 65


def bucket_of(value):
    """Frozen 65-bucket histogram bucket for one duration."""
    if value == 0:
        return 0
    width = 0
    rest = value
    while rest > 0:
        width += 1
        rest >>= 1
    return width


def bucket_upper_edge(bucket):
    """Inclusive upper edge of one histogram bucket."""
    if bucket <= 0:
        return 0
    if bucket >= 64:
        return (1 << 64) - 1
    return (1 << bucket) - 1


def nearest_rank(num, den, count):
    """ceil(num*count/den) with unbounded integers."""
    if den <= 0 or num <= 0 or num > den or count <= 0:
        raise ValueError("bad percentile input")
    return (num * count + den - 1) // den


class OracleLedger:
    """Raw owned-DMA ground truth. Append-only until seal()."""

    def __init__(self):
        self._entries = []
        self._sealed = False

    def _add(self, kind, **fields):
        if self._sealed:
            raise ValueError("ledger sealed")
        entry = {"kind": kind}
        entry.update(fields)
        self._entries.append(entry)

    def record_attempt(self, op, device, requested, forced):
        self._add("attempt", op=op, device=device,
                 requested=requested, forced=bool(forced))

    def record_outcome(self, op, success, mapping=None,
                       mapped_bytes=None, return_code=None):
        self._add("outcome", op=op, success=bool(success),
                 mapping=mapping, mapped_bytes=mapped_bytes,
                 return_code=return_code)

    def record_allocation(self, op, success, mapping=None, mapped_bytes=None):
        """Explicit inner allocation; distinct from outer operation outcome."""
        self._add("allocation", op=op, success=success,
                  mapping=mapping, mapped_bytes=mapped_bytes)

    def _allocation_kind(self):
        return "allocation" if any(e["kind"] == "allocation" for e in self._entries) else "outcome"

    def record_copy(self, op, direction, nbytes, mapping=None,
                  witnessed=None):
        """A copy with optional executed-byte witness.

        witnessed=None keeps the legacy asserted-bytes shape;
        an integer names independently verified executed bytes
        (bounce readback or device-write simulation), which must
        never exceed nbytes.
        """
        if witnessed is not None and witnessed > nbytes:
            raise ValueError("witnessed bytes exceed asserted bytes")
        self._add("copy", op=op, mapping=mapping,
                 direction=direction, nbytes=nbytes,
                 witnessed=witnessed)

    def record_release(self, mapping, duration_ns=None):
        self._add("release", mapping=mapping,
                 duration_ns=duration_ns)

    def record_pool(self, pool, used, capacity, unit):
        self._add("pool", pool=pool, used=used,
                 capacity=capacity, unit=unit)

    def seal(self):
        self._sealed = True

    @property
    def entries(self):
        return list(self._entries)

    def expected_allocations(self):
        return sum(1 for e in self._entries
                   if e["kind"] == self._allocation_kind() and e["success"])

    def expected_failures(self):
        return sum(1 for e in self._entries
                   if e["kind"] == self._allocation_kind() and not e["success"])

    def expected_mapped_bytes(self):
        return sum(e["mapped_bytes"] for e in self._entries
                   if e["kind"] == self._allocation_kind() and e["success"])

    def expected_copies(self):
        totals = {"original_to_bounce": 0, "bounce_to_original": 0}
        for e in self._entries:
            if e["kind"] == "copy":
                totals[e["direction"]] += e["nbytes"]
        return totals

    def expected_witnessed_copies(self):
        """Witnessed executed bytes, or None when any copy lacks one.

        A single unwitnessed copy voids the witnessed totals:
        mixed ledgers must not present partial witness sums as
        executed-copy ground truth.
        """
        totals = {"original_to_bounce": 0, "bounce_to_original": 0}
        for e in self._entries:
            if e["kind"] != "copy":
                continue
            if e.get("witnessed") is None:
                return None
            totals[e["direction"]] += e["witnessed"]
        return totals

    def expected_lifetimes(self):
        return sorted(e["duration_ns"] for e in self._entries
                      if e["kind"] == "release"
                      and e["duration_ns"] is not None)

    def expected_live_bytes(self):
        live = {}
        for e in self._entries:
            if e["kind"] == self._allocation_kind() and e["success"]:
                live[e["mapping"]] = e["mapped_bytes"]
            elif e["kind"] == "release":
                live.pop(e["mapping"], None)
        return sum(live.values()), len(live)

    def pressure_streaks(self):
        """Pools with three consecutive qualifying samples."""
        streak = {}
        for e in self._entries:
            if e["kind"] != "pool":
                continue
            pool = e["pool"]
            ok = (e["unit"] == "bytes" and e["used"] is not None
                  and e["capacity"] is not None and e["capacity"] > 0
                  and e["used"] >= e["capacity"] - e["capacity"] // 10)
            streak[pool] = streak.get(pool, 0) + 1 if ok else 0
        return streak

    def expected_pressure(self):
        return sorted(p for p, n in self.pressure_streaks().items() if n >= 3)


def _global_metrics(report):
    found = {}
    for m in report["metrics"]:
        dims = m["dimensions"]
        if dims["device_id"] is None and dims["pool_id"] is None:
            if m["name"] in found:
                raise ValueError("duplicate global metric " + m["name"])
            found[m["name"]] = m
    return found


def _pressure_streaks(report):
    streaks = {}
    for m in report["metrics"]:
        if m["name"] != "pool_pressure_samples":
            continue
        pool = m["dimensions"]["pool_id"]
        if pool is not None and m["value"] is not None:
            if pool in streaks:
                raise ValueError("duplicate pool pressure metric")
            streaks[pool] = int(m["value"])
    return streaks


def _finding_codes(report):
    return [f["code"] for f in report["findings"]]


def compare(report, ledger):
    """Match a report dict against a sealed ledger.

    Returns a sorted mismatch list, empty on agreement.
    """
    bad = []
    metrics = _global_metrics(report)

    def valued(name):
        m = metrics.get(name)
        if m is None:
            bad.append("missing metric " + name)
            return None
        if m["value"] is None:
            bad.append("null metric " + name)
            return None
        return int(m["value"])

    def expect_null(name, must_exist=True):
        # Names without an attempts placeholder (open_mappings,
        # completed_lifetime_count, ...) may be absent entirely
        # when their scope never appears; they must only never
        # be valued without a ledger source.
        m = metrics.get(name)
        if m is None:
            if must_exist:
                bad.append("missing metric " + name)
        elif m["value"] is not None:
            bad.append("valued metric %s without ledger source" % name)

    kinds = set(e["kind"] for e in ledger.entries)
    for name, truth in (("bounce_attempts", sum(e["kind"] == "attempt" for e in ledger.entries)),
                        ("requested_bounce_bytes", sum(e["requested"] for e in ledger.entries if e["kind"] == "attempt"))):
        if "attempt" in kinds:
            got = valued(name)
            if got is not None and got != truth:
                bad.append("%s %d != ledger %d" % (name, got, truth))
        else:
            expect_null(name, must_exist=False)
    if "outcome" in kinds or "allocation" in kinds:
        got = valued("failed_allocations")
        if got is not None and got != ledger.expected_failures():
            bad.append("failed_allocations %d != ledger %d" % (got, ledger.expected_failures()))
        mapped = valued("mapped_bytes_total")
        if mapped is not None and mapped != ledger.expected_mapped_bytes():
            bad.append("mapped_bytes_total %d != ledger %d" % (mapped, ledger.expected_mapped_bytes()))
        alloc = valued("successful_allocations")
        if alloc is not None and alloc != ledger.expected_allocations():
            bad.append("successful_allocations %d != ledger %d"
                       % (alloc, ledger.expected_allocations()))
    else:
        expect_null("successful_allocations")
        expect_null("failed_allocations", must_exist=False)
    copies = ledger.expected_copies()
    if "copy" in kinds:
        o2b = valued("copy_original_to_bounce_bytes")
        if o2b is not None and o2b != copies["original_to_bounce"]:
            bad.append("copy_original_to_bounce_bytes %d != ledger %d"
                       % (o2b, copies["original_to_bounce"]))
        b2o = valued("copy_bounce_to_original_bytes")
        if b2o is not None and b2o != copies["bounce_to_original"]:
            bad.append("copy_bounce_to_original_bytes %d != ledger %d"
                       % (b2o, copies["bounce_to_original"]))
    else:
        expect_null("copy_original_to_bounce_bytes")
        expect_null("copy_bounce_to_original_bytes")

    live_bytes, live_open = ledger.expected_live_bytes()
    if "outcome" in kinds or "allocation" in kinds or "release" in kinds:
        live = valued("live_observed_allocation_bytes")
        if live is not None and live != live_bytes:
            bad.append("live_observed_allocation_bytes %d != ledger %d"
                       % (live, live_bytes))
        opened = valued("open_mappings")
        if opened is not None and opened != live_open:
            bad.append("open_mappings %d != ledger %d"
                       % (opened, live_open))
    else:
        expect_null("live_observed_allocation_bytes")
        expect_null("open_mappings", must_exist=False)

    want_durs = ledger.expected_lifetimes()
    if want_durs:
        count = valued("completed_lifetime_count")
        if count is not None and count != len(want_durs):
            bad.append("completed_lifetime_count %d != ledger %d"
                       % (count, len(want_durs)))
    else:
        expect_null("completed_lifetime_count", must_exist=False)
    if want_durs:
        mean = valued("lifetime_mean_ns")
        if mean is not None and mean != sum(want_durs) // len(want_durs):
            bad.append("lifetime_mean_ns %d != ledger %d"
                       % (mean, sum(want_durs) // len(want_durs)))
        for name, truth in (("lifetime_min_ns", min(want_durs)), ("lifetime_max_ns", max(want_durs))):
            got = valued(name)
            if got is not None and got != truth:
                bad.append("%s %d != ledger %d" % (name, got, truth))
        for frac, name in ((50, "lifetime_p50_ns"), (95, "lifetime_p95_ns"),
                           (99, "lifetime_p99_ns")):
            got = valued(name)
            if got is None:
                continue
            rank = nearest_rank(frac, 100, len(want_durs))
            truth = sorted(want_durs)[rank - 1]
            edge = bucket_upper_edge(bucket_of(truth))
            if got != edge:
                bad.append("%s %d != ledger edge %d"
                           % (name, got, edge))

    if not want_durs:
        for name in ("lifetime_mean_ns", "lifetime_min_ns", "lifetime_max_ns", "lifetime_p50_ns", "lifetime_p95_ns", "lifetime_p99_ns"):
            expect_null(name, must_exist=False)
    streaks = _pressure_streaks(report)
    expected = ledger.pressure_streaks()
    if streaks != expected:
        bad.append("pool pressure streaks differ from ledger (pressured subjects included)")
    subjects = []
    for finding in report["findings"]:
        if finding["code"] == "POOL_PRESSURE":
            refs = [r[5:] for r in finding.get("evidence_refs", []) if r.startswith("pool:")]
            if len(refs) != 1:
                bad.append("POOL_PRESSURE finding has no unique pool subject")
            subjects.extend(refs)
    if sorted(subjects) != ledger.expected_pressure():
        bad.append("POOL_PRESSURE subjects differ from ledger")
    return sorted(bad)


def compare_witnessed(report, ledger):
    """Match a report against witnessed executed bytes only.

    Fails when any ledger copy lacks an executed-byte witness
    or when a witness covers fewer bytes than asserted; on a
    fully witnessed ledger this is compare() with the totals
    additionally proven executed.
    """
    bad = []
    for e in ledger.entries:
        if e["kind"] != "copy":
            continue
        if e.get("witnessed") is None:
            bad.append("unwitnessed copy op=%r" % (e.get("op"),))
        elif e["witnessed"] != e["nbytes"]:
            bad.append("copy op=%r witnessed %d of %d bytes"
                       % (e.get("op"), e["witnessed"],
                          e["nbytes"]))
    if bad:
        return sorted(bad)
    if ledger.expected_witnessed_copies() is None:
        return ["no witnessed copy totals"]
    return compare(report, ledger)


def compare_files(report_path, ledger_path):
    """Compare a report JSON file against a ledger JSON file."""
    with open(report_path) as handle:
        report = json.load(handle)
    with open(ledger_path) as handle:
        raw = json.load(handle)
    ledger = OracleLedger()
    for entry in raw["entries"]:
        kind = entry.pop("kind")
        ledger._add(kind, **entry)
    ledger.seal()
    return compare(report, ledger)
