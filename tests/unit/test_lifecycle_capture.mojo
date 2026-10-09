# SPDX-License-Identifier: GPL-3.0-or-later

"""Offline lifecycle/copy capture tests through the real collector.

Drives scripted sources (kernel, clock, signal) plus a real
writer through full Collector runs and pins the exact
persisted events.ndjson lines and session.json quality
for the six canonical cases plus the unknown-copy drop,
the foreign-payload abort, and the lifecycle geometry
refusal.

v1 honesty rules pinned here: executed (never requested)
bytes persist; proved-zero persists; unknown lengths drop
as rejected; every lifecycle/copy event carries an
explicit unpaired cause; paired totals and lifetimes stay
unavailable; foreign records abort the capture; missing
channel geometry refuses before any capture exists.
"""

from std.ffi import external_call
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.collector import (
    EXIT_ERROR,
    EXIT_PARTIAL,
    EXIT_REFUSAL,
    Collector,
    CollectorConfig,
    PollOut,
    SnapOut,
    StatsOut,
)
from memveil.platform.reader import (
    bytes_to_text,
    is_valid_utf8,
    read_host_file,
)

from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
)


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-lc-cap-XXXXXX")
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


def _le16(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(v & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    return out^


def _le32(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(4):
        out.append(UInt8((v >> (8 * i)) & 0xFF))
    return out^


def _le64(v: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(8):
        out.append(UInt8((v >> UInt64(8 * i)) & UInt64(0xFF)))
    return out^


def _lc_raw(kind: Int, flags: Int, dir: Int, seq: UInt64,
            ktime: UInt64, size: UInt64, gen: UInt64) -> List[UInt8]:
    var out = _le32(0x434C564D)
    var tail = _le16(2) + _le16(kind) + _le16(flags) + _le16(dir)
    for b in tail:
        out.append(b)
    for b in _le64(seq) + _le64(ktime) + _le64(size) + _le64(gen):
        out.append(b)
    return out^


def _cp_raw(kind: Int, flags: Int, dir: Int, seq: UInt64,
            ktime: UInt64, requested: UInt64, effective: UInt64,
            reason: Int) -> List[UInt8]:
    var out = _le32(0x5043564D)
    var tail = _le16(1) + _le16(kind) + _le16(flags) + _le16(dir)
    for b in tail:
        out.append(b)
    for b in _le64(seq) + _le64(ktime) + _le64(requested) + _le64(effective):
        out.append(b)
    for b in _le16(reason):
        out.append(b)
    out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def _frame(payload: List[UInt8]) -> List[UInt8]:
    """Wrap one payload in a v1 bridge frame."""
    var out = _le32(len(payload))
    for b in _le16(1) + _le16(0):
        out.append(b)
    for b in payload:
        out.append(b)
    return out^


def _batch(payload: List[UInt8]) -> PollOut:
    return PollOut(
        String("batch"), _frame(payload), UInt32(0), String(""))


def _timeout() -> PollOut:
    return PollOut(String("timeout"), List[UInt8](), UInt32(0),
                   String(""))


def _snap(
    observed: UInt64, observed_bytes: UInt64, emitted: UInt64,
    emitted_bytes: UInt64, submit_fail: UInt64, flags: UInt64,
) -> SnapOut:
    var vals = List[UInt64]()
    vals.append(observed)
    vals.append(observed_bytes)
    vals.append(emitted)
    vals.append(emitted_bytes)
    vals.append(submit_fail)
    vals.append(flags)
    return SnapOut(True, vals^, String(""))


def _zero_snap() -> SnapOut:
    return _snap(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        UInt64(0))


def _stats(
    received: UInt64, delivered: UInt64, malformed: UInt64,
    dropped: UInt64,
) -> StatsOut:
    return StatsOut(
        True, received, delivered, UInt64(0), malformed,
        dropped, String(""))


def _zero_stats() -> StatsOut:
    return _stats(UInt64(0), UInt64(0), UInt64(0), UInt64(0))


def _contains(haystack: String, needle: String) -> Bool:
    var h = haystack.as_bytes()
    var n = needle.as_bytes()
    if len(n) == 0 or len(n) > len(h):
        return False
    var i = 0
    while i + len(n) <= len(h):
        var j = 0
        while j < len(n):
            if h[i + j] != n[j]:
                break
            j += 1
        if j == len(n):
            return True
        i += 1
    return False


def _lines(text: String) -> List[String]:
    var out = List[String]()
    var cur = String("")
    var raw = text.as_bytes()
    for i in range(len(raw)):
        if raw[i] == UInt8(0x0A):
            out.append(cur^)
            cur = String("")
        else:
            cur += String(text[byte=i])
    if cur != String(""):
        out.append(cur^)
    return out^


struct CaseOut(Movable):
    """One scripted run: result plus both output files as text."""

    var exit_code: Int
    var end_reason: String
    var outcome: String
    var diagnostic: String
    var events: String
    var session: String

    def __init__(
        out self, exit_code: Int, end_reason: String,
        outcome: String, diagnostic: String, events: String,
        session: String,
    ):
        self.exit_code = exit_code
        self.end_reason = end_reason
        self.outcome = outcome
        self.diagnostic = diagnostic
        self.events = events
        self.session = session


def _read_text(path: String) raises -> String:
    var raw = read_host_file(path, String("capture read"), 67108864)
    if not is_valid_utf8(raw):
        raise Error("capture output is not UTF-8: " + path)
    return bytes_to_text(raw)


def _run(
    payloads: List[List[UInt8]],
    end0: List[UInt64],
    end1: List[UInt64],
    rx1: UInt64,
    end2: List[UInt64],
    rx2: UInt64,
) raises -> CaseOut:
    """Run one scripted multi-channel capture; return its outputs.

    Both lifecycle and copy channels are enabled with
    8 MiB rings; end0/end1/end2 are the 6-word end cuts
    and rx1/rx2 the lifecycle/copy received/delivered
    counts (attempt traffic is the remainder). Signals
    stop the run after the last batch.
    """
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 1073741824
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_lifecycle = True
    cfg.lifecycle_ring_bytes = UInt32(8388608)
    cfg.has_copy = True
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    kernel.add_snap(_zero_snap())
    kernel.add_snap(_zero_snap())
    kernel.add_snap_at(1, _zero_snap())
    kernel.add_snap_at(1, _zero_snap())
    kernel.add_snap_at(2, _zero_snap())
    kernel.add_snap_at(2, _zero_snap())
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
    kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
    kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
    kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
    var n = UInt64(len(payloads))
    # Shared stats queue in read order: sum baseline, ch0
    # baseline, drain pair, drain cut, final sum, ch0 final.
    var total = _stats(n, n, UInt64(0), UInt64(0))
    var ch0n = _stats(
        n - rx1 - rx2, n - rx1 - rx2, UInt64(0), UInt64(0))
    kernel.add_stats(_zero_stats())
    kernel.add_stats(_zero_stats())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(ch0n)
    kernel.add_stats_at(1, _zero_stats())
    kernel.add_stats_at(1, _stats(rx1, rx1, UInt64(0), UInt64(0)))
    kernel.add_stats_at(2, _zero_stats())
    kernel.add_stats_at(2, _stats(rx2, rx2, UInt64(0), UInt64(0)))
    for i in range(len(payloads)):
        kernel.add_poll(_batch(payloads[i]), 1)
    kernel.add_poll(_timeout(), 102)
    var signal = ScriptSignal()
    for i in range(2 * len(payloads)):
        signal.add(String("none"))
    signal.add(String("pending"))
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    var result = collector.run(kernel, clock, signal, writer)
    var events = _read_text(cfg.output + String("/events.ndjson"))
    var session = _read_text(cfg.output + String("/session.json"))
    var out = CaseOut(
        result.exit_code,
        result.end_reason,
        result.outcome,
        result.diagnostic,
        events,
        session,
    )
    return out^


def _cut(
    observed: UInt64, observed_bytes: UInt64, emitted: UInt64,
    emitted_bytes: UInt64,
) -> List[UInt64]:
    var vals = List[UInt64]()
    vals.append(observed)
    vals.append(observed_bytes)
    vals.append(emitted)
    vals.append(emitted_bytes)
    vals.append(UInt64(0))
    vals.append(UInt64(0))
    return vals^


def _zero_cut() -> List[UInt64]:
    return _cut(UInt64(0), UInt64(0), UInt64(0), UInt64(0))


def test_nested_copies() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(101), UInt64(1001), UInt64(4096),
                UInt64(4096), 0))
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(102), UInt64(1002), UInt64(1024),
                UInt64(1024), 0))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(2), UInt64(5120), UInt64(2), UInt64(5120)),
        UInt64(2))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.end_reason, String("signal"))
    assert_equal(c.outcome, String("finalized"))
    var lines = _lines(c.events)
    assert_equal(len(lines), 6)
    assert_equal(
        lines[0],
        String(
            '{"schema_version":"0.1.1","session_id":"cap-0-7",'
            '"seq":"0","ts_ns":"1001","kind":"copy","source":'
            '{"hook":"fentry:swiotlb_bounce","backend":"tracing",'
            '"profile_id":"test-profile-1","measurement":'
            '"observed","correlation":"unpaired"},"data":'
            '{"operation_id":"lc-101","mapping_id":null,'
            '"direction":"original_to_bounce","bytes":"4096"}}'
        ),
    )
    assert_equal(
        lines[1],
        String(
            '{"schema_version":"0.1.1","session_id":"cap-0-7",'
            '"seq":"1","ts_ns":"1002","kind":"copy","source":'
            '{"hook":"fentry:swiotlb_bounce","backend":"tracing",'
            '"profile_id":"test-profile-1","measurement":'
            '"observed","correlation":"unpaired"},"data":'
            '{"operation_id":"lc-102","mapping_id":null,'
            '"direction":"original_to_bounce","bytes":"1024"}}'
        ),
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"scope":"0 bounce_attempt + 0 map_result/unmap'
                ' + 2 copy/sync_request events"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"correlation":{"status":"partial",'
                '"loss_count":null,"scope":"correlated '
                'lifecycle events","reason":"copy without '
                'pending operation","evidence_refs":'
                '["capture:seq=0","capture:seq=1"]}'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"copy_bytes":{"status":"partial","reason":'
                '"capture ok, 2 copy events persisted; admitted'
                ' under test-profile-1; v1 copy wire carries no '
                'mapping identity","hooks":'
                '["fentry:swiotlb_bounce"],"profile_id":'
                '"test-profile-1"}'
            ),
        )
    )


def test_copy_before_failed_map() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(111), UInt64(1011), UInt64(4096),
                UInt64(4096), 0))
    payloads.append(
        _lc_raw(1, 0, 1, UInt64(112), UInt64(1012),
                UInt64(4096), UInt64(0)))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    var lines = _lines(c.events)
    assert_equal(len(lines), 6)
    assert_true(_contains(lines[0], String('"bytes":"4096"')))
    assert_equal(
        lines[1],
        String(
            '{"schema_version":"0.1.1","session_id":"cap-0-7",'
            '"seq":"1","ts_ns":"1012","kind":"map_result",'
            '"source":{"hook":"fexit:swiotlb_tbl_map_single",'
            '"backend":"tracing","profile_id":"test-profile-1",'
            '"measurement":"observed","correlation":"unpaired"},'
            '"data":{"operation_id":"lc-112","success":false,'
            '"mapping_id":null,"return_code":null,'
            '"mapped_bytes":null,"wire_generation":"0",'
            '"wire_identity":null}}'
        ),
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"scope":"0 bounce_attempt + 1 map_result/unmap'
                ' + 1 copy/sync_request events"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"copy without pending operation; '
                'failure carries no mapping"'
            ),
        )
    )


def test_sync_invents_nothing() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(1, 1, 1, UInt64(201), UInt64(2001), UInt64(4096),
                UInt64(0), 4))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    var lines = _lines(c.events)
    assert_equal(len(lines), 5)
    assert_equal(
        lines[0],
        String(
            '{"schema_version":"0.1.1","session_id":"cap-0-7",'
            '"seq":"0","ts_ns":"2001","kind":"sync_request",'
            '"source":{"hook":"fentry:__swiotlb_sync_single_'
            'for_device","backend":"tracing","profile_id":'
            '"test-profile-1","measurement":"observed",'
            '"correlation":"unpaired"},"data":{"operation_id":'
            '"lc-201","mapping_id":"lc-201","offset_known":false,'
            '"offset":null,"length":"4096"}}'
        ),
    )
    assert_true(not _contains(c.events, String('"kind":"copy"')))
    assert_true(
        _contains(
            c.session,
            String('"reason":"sync references unknown mapping"'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"sync_requests":{"status":"partial","reason":'
                '"capture ok, 1 sync_request events persisted; '
                'admitted under test-profile-1; v1 copy wire '
                'carries no mapping identity"'
            ),
        )
    )


def test_clamped_copy_keeps_effective() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 7, 1, UInt64(211), UInt64(2011), UInt64(4096),
                UInt64(1024), 0))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    var lines = _lines(c.events)
    assert_equal(len(lines), 5)
    # Requested bytes stay in the aggregate counters only;
    # the event carries the executed 1024.
    assert_true(_contains(lines[0], String('"bytes":"1024"')))
    assert_true(not _contains(lines[0], String("4096")))


def test_early_zero_persists_proved_zero() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 10, 2, UInt64(221), UInt64(2021), UInt64(512),
                UInt64(0), 0))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(512), UInt64(1), UInt64(512)),
        UInt64(1))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    var lines = _lines(c.events)
    assert_equal(len(lines), 5)
    assert_true(_contains(lines[0], String('"kind":"copy"')))
    assert_true(_contains(lines[0], String('"bytes":"0"')))
    assert_true(
        _contains(lines[0], String('"direction":"bounce_to_original"'))
    )


def test_reuse_reports_distinct_ids() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(121), UInt64(1021),
                UInt64(4096), UInt64(41)))
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(122), UInt64(1022),
                UInt64(4096), UInt64(42)))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(2), UInt64(8192), UInt64(2), UInt64(8192)),
        UInt64(2), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    var lines = _lines(c.events)
    assert_equal(len(lines), 6)
    assert_true(
        _contains(lines[0], String('"mapping_id":"gen-41"')))
    assert_true(
        _contains(lines[1], String('"mapping_id":"gen-42"')))
    assert_true(
        _contains(lines[0], String('"correlation":"direct"')))
    assert_true(
        _contains(lines[1], String('"correlation":"direct"')))
    assert_true(
        _contains(
            c.session,
            String(
                '"mapping_lifecycle":{"status":"partial",'
                '"reason":"capture ok, 2 map_result/unmap '
                'events persisted; admitted under '
                'test-profile-1; v2 wire reports opaque mapping '
                'generations when observed","hooks":['
                '"fexit:swiotlb_tbl_map_single",'
                '"fentry:__swiotlb_tbl_unmap_single"],'
                '"profile_id":"test-profile-1"}'
            ),
        )
    )


def test_unknown_copy_drops_as_rejected() raises:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 0, 1, UInt64(231), UInt64(2031), UInt64(4096),
                UInt64(0), 1))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1))
    # Known loss: the delivered record is counted, never
    # persisted, and the capture still finalizes.
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    var lines = _lines(c.events)
    assert_equal(len(lines), 4)
    assert_true(not _contains(c.events, String('"kind":"copy"')))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 1 (submit_fail=(0) '
                'malformed=(0) dropped=(0) size_omitted=(0) '
                'duration_omitted=(0) signal_omitted=(0) '
                'rejected=(1) write_failed=(0))"'
            ),
        )
    )


def test_foreign_payload_aborts() raises:
    var payloads = List[List[UInt8]]()
    var bad = List[UInt8]()
    for i in range(37):
        bad.append(UInt8(0))
    payloads.append(bad^)
    var c = _run(
        payloads^,
        _cut(UInt64(1), UInt64(37), UInt64(1), UInt64(37)),
        _zero_cut(), UInt64(0), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_ERROR)
    assert_equal(c.end_reason, String("error"))
    assert_equal(c.outcome, String("error"))
    var lines = _lines(c.events)
    assert_equal(len(lines), 5)
    for i in range(4):
        assert_true(
            _contains(lines[i], String('"kind":"counter_snapshot"')))
    assert_true(_contains(lines[4], String('"kind":"gap"')))
    assert_true(
        _contains(
            lines[4],
            String('"reason":"detail closure unproven: error shutdown"'),
        )
    )


def test_lifecycle_geometry_refuses() raises:
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 1073741824
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_lifecycle = True
    cfg.lifecycle_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    kernel.ring_geom1.map_type = UInt32(2)
    var signal = ScriptSignal()
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_equal(result.outcome, String("refused"))
    assert_true(
        _contains(
            result.diagnostic,
            String("map lc mv_lifecycle geometry"),
        )
    )
    var missing = False
    try:
        _ = _read_text(tmp + String("/cap/events.ndjson"))
    except:
        missing = True
    assert_true(missing)


def test_stop_open_mappings_exact() raises:
    # Two successful maps, one unmap, one failed map:
    # the stop wire reports exactly one open mapping
    # (failed maps never count as opened).
    var payloads = List[List[UInt8]]()
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(121), UInt64(1021),
                UInt64(4096), UInt64(41)))
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(122), UInt64(1022),
                UInt64(4096), UInt64(42)))
    payloads.append(
        _lc_raw(2, 3, 2, UInt64(123), UInt64(1023),
                UInt64(4096), UInt64(41)))
    payloads.append(
        _lc_raw(1, 0, 1, UInt64(124), UInt64(1024),
                UInt64(4096), UInt64(0)))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(4), UInt64(16384), UInt64(4), UInt64(16384)),
        UInt64(4), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String('"open_mappings":"1"')))
    assert_true(
        _contains(c.session, String('"outcome":"partial"')))


def test_stop_open_mappings_saturate() raises:
    # A failed map plus an unpaired unmap: unmaps outrun
    # successful maps, so open mappings saturate at zero
    # instead of wrapping.
    var payloads = List[List[UInt8]]()
    payloads.append(
        _lc_raw(1, 0, 1, UInt64(131), UInt64(1031),
                UInt64(4096), UInt64(0)))
    payloads.append(
        _lc_raw(2, 3, 2, UInt64(132), UInt64(1032),
                UInt64(4096), UInt64(9)))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(2), UInt64(8192), UInt64(2), UInt64(8192)),
        UInt64(2), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String('"open_mappings":"0"')))


def test_stop_open_mappings_balance_limit() raises:
    # The wire count is a persisted-event balance, not an
    # inventory: an unpaired unmap masks a still-open map
    # made after it. Pin the specified arithmetic so the
    # limit stays explicit.
    var payloads = List[List[UInt8]]()
    payloads.append(
        _lc_raw(2, 3, 2, UInt64(141), UInt64(1041),
                UInt64(4096), UInt64(9)))
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(142), UInt64(1042),
                UInt64(4096), UInt64(41)))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(2), UInt64(8192), UInt64(2), UInt64(8192)),
        UInt64(2), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String('"open_mappings":"0"')))


def test_stop_open_mappings_churn() raises:
    # Sustained generation churn: 500 map/unmap cycles
    # with distinct generations persist exactly and
    # close with zero open mappings; nothing accumulates.
    var payloads = List[List[UInt8]]()
    for i in range(500):
        var gen = UInt64(100 + i)
        var seq = UInt64(1000 + 2 * i)
        var ktime = UInt64(5000 + 2 * i)
        payloads.append(
            _lc_raw(1, 1, 1, seq, ktime, UInt64(4096), gen))
        payloads.append(
            _lc_raw(2, 3, 2, seq + UInt64(1), ktime + UInt64(1),
                    UInt64(4096), gen))
    var c = _run(
        payloads^, _zero_cut(),
        _cut(UInt64(1000), UInt64(4096000),
             UInt64(1000), UInt64(4096000)),
        UInt64(1000), _zero_cut(), UInt64(0))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String('"open_mappings":"0"')))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
