# SPDX-License-Identifier: GPL-3.0-or-later

"""Periodic pool sampling timer: scripted full runs.

Timeout-only scripted captures with fixture debugfs roots
prove the cadence (one sample per second of capture time),
unavailable reads (a denied used counter persists null
used halves beside live capacity, never failed runs), and
the config gate (no sampling without pool configuration).
Scripted clocks interleave iteration and sample-timestamp
reads explicitly, so every fire time is predicted, never
fitted. The 4096 count cap lives in the compiled probe
(case poolcap) because the JIT run is too slow for a unit
file.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
    snap_ok,
    stats_ok,
)
from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    PollOut,
)
from memveil.capture.pools import (
    NormalizedPoolSample,
    pool_sample_pressured,
)
from memveil.platform.reader import read_host_file


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-pool-timer-XXXXXX")
    var buf = List[UInt8]()
    for b in template.as_bytes():
        buf.append(b)
    buf.append(UInt8(0))
    var p = external_call["mkdtemp", UInt64](Span(buf).unsafe_ptr())
    if p == UInt64(0):
        raise Error("mkdtemp failed")
    var raw = List[UInt8]()
    for i in range(len(buf)):
        if buf[i] == UInt8(0):
            break
        raw.append(buf[i])
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("mkdtemp gave non-UTF8")


def _timeout() -> PollOut:
    return PollOut(String("timeout"), List[UInt8](), UInt32(0), String(""))


def _zeros(mut kernel: ScriptKernel, nstats: Int, nsnaps: Int):
    var zstats = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    for _ in range(nstats):
        kernel.add_stats(zstats.copy())
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(nsnaps):
        kernel.add_snap(zsnap.copy())


def _read_text(path: String) raises -> String:
    var raw = read_host_file(path, String("pool-timer"), 8388608)
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("pool timer bytes not UTF-8")


def _count(hay: String, needle: String) -> Int:
    """Non-overlapping byte-substring occurrences."""
    var hb = hay.as_bytes()
    var nb = needle.as_bytes()
    if len(nb) == 0 or len(nb) > len(hb):
        return 0
    var n = 0
    var i = 0
    while i + len(nb) <= len(hb):
        var j = 0
        while j < len(nb):
            if hb[i + j] != nb[j]:
                break
            j += 1
        if j == len(nb):
            n += 1
            i += len(nb)
        else:
            i += 1
    return n


def _line_kind(raw: Span[UInt8, ...], start: Int, end: Int) -> String:
    var tag = String("\"kind\":\"").as_bytes()
    var i = start
    while i + len(tag) <= end:
        var j = 0
        while j < len(tag):
            if raw[i + j] != tag[j]:
                break
            j += 1
        if j == len(tag):
            var val = List[UInt8]()
            var k = i + len(tag)
            while k < end and raw[k] != UInt8(0x22):
                val.append(raw[k])
                k += 1
            try:
                return String(from_utf8=Span(val))
            except:
                return String("")
        i += 1
    return String("")


def _kinds(events: String) -> List[String]:
    """Event kinds in file order."""
    var out = List[String]()
    var raw = events.as_bytes()
    var start = 0
    var i = 0
    while True:
        if i >= len(raw) or raw[i] == UInt8(0x0A):
            if i > start:
                var k = _line_kind(raw, start, i)
                if k != String(""):
                    out.append(k^)
            if i >= len(raw):
                break
            start = i + 1
        i += 1
    return out^


struct CaseOut:
    """One scripted run: exit plus retained capture text."""

    var exit_code: Int
    var end_reason: String
    var events: String
    var session: String

    def __init__(
        out self,
        exit_code: Int,
        end_reason: String,
        events: String,
        session: String,
    ):
        self.exit_code = exit_code
        self.end_reason = end_reason.copy()
        self.events = events.copy()
        self.session = session.copy()


def _clock_vals(dwells: List[UInt64]) -> List[UInt64]:
    """Startup reads, interleaved dwell/ts pairs, latch, tail.

    Every dwell iteration fires, so each dwell timestamp
    appears twice: once for the loop's deadline read and
    once for the sample's own timestamp read. The fifth
    startup value feeds the attach-completion stamp and
    the sixth the readiness stamp; without them the
    dwell pairs would shift by one.
    """
    var base = UInt64(1000000000)
    var out = List[UInt64]()
    out.append(base)
    out.append(base + UInt64(1))
    out.append(base + UInt64(2))
    out.append(base + UInt64(3))
    out.append(base + UInt64(4))
    out.append(base + UInt64(4))
    for i in range(len(dwells)):
        out.append(dwells[i])
        out.append(dwells[i])
    var latch = base + UInt64(61000000001)
    out.append(latch)
    for i in range(7):
        out.append(latch + UInt64(1 + i))
    return out^


def _run_case(
    pool_root: String,
    has_pool: Bool,
    vals: List[UInt64],
    step: UInt64,
    duration_s: UInt64,
    timeouts: Int,
) raises -> CaseOut:
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = duration_s
    cfg.max_events_bytes = 134217728
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("pool-timer-probe")
    cfg.pid = 4242
    cfg.has_pool_sample = has_pool
    cfg.pool_root = pool_root.copy()
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), timeouts)
    _zeros(kernel, 5, 4)
    var clock = ScriptClock()
    clock.step = step
    for i in range(len(vals)):
        clock.add(vals[i])
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var collector = Collector(cfg^)
    var result = collector.run(kernel, clock, signal, writer)
    var out = CaseOut(
        result.exit_code,
        result.end_reason,
        _read_text(tmp + String("/cap/events.ndjson")),
        _read_text(tmp + String("/cap/session.json")),
    )
    return out^


def _assert_kinds(got: List[String], want: List[String]) raises:
    assert_equal(len(got), len(want))
    for i in range(len(want)):
        assert_equal(got[i], want[i])


def test_periodic_cadence() raises:
    # The baseline persists at startup, then three dwell
    # iterations past the 1s cadence persist three
    # mid-stream samples ahead of the closing set: the file
    # stays chronological (baseline, periodic, final).
    var base = UInt64(1000000000)
    var dwells = List[UInt64]()
    dwells.append(base + UInt64(1500000000))
    dwells.append(base + UInt64(2500000000))
    dwells.append(base + UInt64(3500000000))
    var c = _run_case(
        String("tests/fixtures/pools/debugfs-ok"),
        True,
        _clock_vals(dwells),
        UInt64(1000000),
        UInt64(60),
        120,
    )
    assert_equal(c.exit_code, 0)
    assert_equal(c.end_reason, String("duration"))
    var want = List[String]()
    want.append(String("pool_sample"))
    want.append(String("pool_sample"))
    want.append(String("pool_sample"))
    want.append(String("pool_sample"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("pool_sample"))
    _assert_kinds(_kinds(c.events), want)
    # Fixture halves land on every sample, baseline first.
    assert_equal(
        _count(c.events, String("\"used_bytes\":\"24576\"")), 5
    )
    assert_equal(
        _count(c.events, String("\"capacity_bytes\":\"67108864\"")), 5
    )
    assert_equal(
        _count(c.events, String("\"pool_id\":\"swiotlb-default\"")), 5
    )
    # Periodic samples carry their scripted fire times.
    assert_equal(_count(c.events, String("\"ts_ns\":\"2500000000\"")), 1)
    assert_equal(_count(c.events, String("\"ts_ns\":\"3500000000\"")), 1)
    assert_equal(_count(c.events, String("\"ts_ns\":\"4500000000\"")), 1)
    assert_true(_count(c.session, String("3 periodic samples")) > 0)


def test_no_dwell_no_periodic() raises:
    # Without dwell the cadence never fires: the startup
    # baseline plus the closing final stand alone and the
    # session says zero.
    var dwells = List[UInt64]()
    var c = _run_case(
        String("tests/fixtures/pools/debugfs-ok"),
        True,
        _clock_vals(dwells),
        UInt64(1000000),
        UInt64(60),
        120,
    )
    assert_equal(c.exit_code, 0)
    assert_equal(c.end_reason, String("duration"))
    var want = List[String]()
    want.append(String("pool_sample"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("pool_sample"))
    _assert_kinds(_kinds(c.events), want)
    assert_true(_count(c.session, String("0 periodic samples")) > 0)


def test_denied_periodic_unavailable() raises:
    # A denied used counter persists a null used half beside
    # live capacity mid-stream too; the run still succeeds,
    # stays partial, and names the first read failure.
    var base = UInt64(1000000000)
    var dwells = List[UInt64]()
    dwells.append(base + UInt64(1500000000))
    dwells.append(base + UInt64(2500000000))
    var c = _run_case(
        String("tests/fixtures/pools/debugfs-denied"),
        True,
        _clock_vals(dwells),
        UInt64(1000000),
        UInt64(60),
        120,
    )
    assert_equal(c.exit_code, 0)
    assert_equal(c.end_reason, String("duration"))
    assert_equal(
        _count(c.events, String("\"kind\":\"pool_sample\"")), 4
    )
    assert_equal(_count(c.events, String("\"used_bytes\":null")), 4)
    assert_equal(
        _count(
            c.events, String("\"capacity_bytes\":\"67108864\"")
        ),
        4,
    )
    assert_true(_count(c.session, String("2 periodic samples")) > 0)
    assert_true(
        _count(
            c.session, String("first read failure: denied")
        )
        > 0
    )


def test_no_pool_config_no_timer() raises:
    # Dwell without pool configuration samples nothing.
    var base = UInt64(1000000000)
    var dwells = List[UInt64]()
    dwells.append(base + UInt64(1500000000))
    dwells.append(base + UInt64(2500000000))
    dwells.append(base + UInt64(3500000000))
    var c = _run_case(
        String("tests/fixtures/pools/debugfs-ok"),
        False,
        _clock_vals(dwells),
        UInt64(1000000),
        UInt64(60),
        120,
    )
    assert_equal(c.exit_code, 0)
    assert_equal(c.end_reason, String("duration"))
    var want = List[String]()
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    want.append(String("counter_snapshot"))
    _assert_kinds(_kinds(c.events), want)
    assert_true(
        _count(c.session, String("No pool source in this capture"))
        > 0
    )


def _pressured(used: UInt64, cap: UInt64) -> Bool:
    var sample = NormalizedPoolSample()
    sample.has_used_bytes = True
    sample.used_bytes = used
    sample.has_capacity_bytes = True
    sample.capacity_bytes = cap
    return pool_sample_pressured(sample)


def test_pressure_predicate_edges() raises:
    # Same 90% boundary the analysis streak uses, kept
    # beside it by these vectors (capacity 4096: integer
    # threshold 4096 - 409 = 3687 qualifies, 3686 not).
    assert_true(_pressured(UInt64(3687), UInt64(4096)))
    assert_true(not _pressured(UInt64(3686), UInt64(4096)))
    assert_true(not _pressured(UInt64(0), UInt64(0)))
    assert_true(not _pressured(UInt64(1), UInt64(0)))
    var missing = NormalizedPoolSample()
    missing.has_used_bytes = True
    missing.used_bytes = UInt64(4096)
    assert_true(not pool_sample_pressured(missing))
    var missing2 = NormalizedPoolSample()
    missing2.has_capacity_bytes = True
    missing2.capacity_bytes = UInt64(4096)
    assert_true(not pool_sample_pressured(missing2))
    assert_true(
        _pressured(UInt64(18446744073709551615), UInt64(18446744073709551615))
    )


def _capped_collector(pool_root: String) raises -> Collector:
    var cfg = CollectorConfig()
    cfg.has_pool_sample = True
    cfg.pool_root = pool_root.copy()
    var coll = Collector(cfg^)
    coll.pool_periodic = 4096
    coll.pool_periodic_capped = True
    coll.pool_next_ts = UInt64(1000000000)
    return coll^


def _drive_tick(
    mut coll: Collector, mut writer: ScriptWriter, now: UInt64
) raises -> String:
    var clock = ScriptClock()
    clock.add(now)
    return coll.maybe_sample_pool(clock, writer, now)


def _pool_writer() raises -> ScriptWriter:
    var tmp = _mkdtemp()
    var writer = ScriptWriter()
    var created = writer.create(
        tmp + String("/events.ndjson"), 134217728
    )
    assert_true(created.ok)
    return writer^


def test_postcap_quiet_persists_nothing() raises:
    # Past the routine cap, quiet ticks keep reading on
    # the cadence but persist nothing: no post-cap count,
    # no appends, timer still advancing.
    var coll = _capped_collector(
        String("tests/fixtures/pools/debugfs-ok")
    )
    var writer = _pool_writer()
    for i in range(3):
        var verdict = _drive_tick(
            coll, writer, UInt64(1000000000) + UInt64(i) * UInt64(1000000000)
        )
        assert_equal(verdict, String(""))
    assert_equal(coll.pool_postcap, 0)
    assert_equal(writer.appends, 0)
    assert_equal(coll.pool_next_ts, UInt64(4000000000))


def test_postcap_pressure_persists() raises:
    # Past the routine cap, pressurized ticks persist so
    # a pressure streak can still form on long captures.
    var coll = _capped_collector(
        String("tests/fixtures/pools/debugfs-pressure")
    )
    var writer = _pool_writer()
    for i in range(3):
        var verdict = _drive_tick(
            coll, writer, UInt64(1000000000) + UInt64(i) * UInt64(1000000000)
        )
        assert_equal(verdict, String(""))
    assert_equal(coll.pool_postcap, 3)
    assert_equal(writer.appends, 3)
    assert_true(not coll.pool_postcap_capped)


def test_postcap_budget_exhausts() raises:
    # The post-cap budget is hard: a pressurized tick past
    # 64 latches exhaustion and persists nothing.
    var coll = _capped_collector(
        String("tests/fixtures/pools/debugfs-pressure")
    )
    coll.pool_postcap = 64
    var writer = _pool_writer()
    var verdict = _drive_tick(coll, writer, UInt64(1000000000))
    assert_equal(verdict, String(""))
    assert_equal(coll.pool_postcap, 64)
    assert_equal(writer.appends, 0)
    assert_true(coll.pool_postcap_capped)


def test_postcap_session_note() raises:
    # The session reason names the thinning: routine stop,
    # post-cap count, exhaustion.
    var coll = _capped_collector(
        String("tests/fixtures/pools/debugfs-ok")
    )
    coll.pool_postcap = 2
    coll.pool_ok = True
    var session = coll.assemble()
    var reason = session.cap_pool_stats.reason
    assert_true(
        reason.find(String("routine sampling stopped at 4096"))
        != -1,
        reason,
    )
    assert_true(
        reason.find(
            String("2 pressurized samples persisted past the cap")
        )
        != -1,
        reason,
    )
    coll.pool_postcap_capped = True
    var session2 = coll.assemble()
    assert_true(
        session2.cap_pool_stats.reason.find(
            String("post-cap budget exhausted")
        )
        != -1,
        session2.cap_pool_stats.reason,
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_periodic_cadence]()
    suite.test[test_no_dwell_no_periodic]()
    suite.test[test_denied_periodic_unavailable]()
    suite.test[test_no_pool_config_no_timer]()
    suite.test[test_pressure_predicate_edges]()
    suite.test[test_postcap_quiet_persists_nothing]()
    suite.test[test_postcap_pressure_persists]()
    suite.test[test_postcap_budget_exhausts]()
    suite.test[test_postcap_session_note]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
