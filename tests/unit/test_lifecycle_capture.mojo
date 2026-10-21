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

from memveil.analysis.engine import Analyzer
from memveil.capture.collector import (
    EXIT_ERROR,
    EXIT_PARTIAL,
    EXIT_REFUSAL,
    Collector,
    CollectorConfig,
    GeomOut,
    MissOut,
    OpOut,
    PollOut,
    RunResult,
    SnapOut,
    StatsOut,
)
from memveil.capture.reader import default_limits, read_capture
from memveil.model.session import parse_session
from memveil.render.json import render_json
from memveil.render.markdown import render_markdown
from memveil.render.text import render_text
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
    var signal_checks: Int
    var loop_polls: Int
    var calls: List[String]

    def __init__(
        out self, exit_code: Int, end_reason: String,
        outcome: String, diagnostic: String, events: String,
        session: String, signal_checks: Int = 0, loop_polls: Int = 0,
        calls: List[String] = List[String](),
    ):
        self.exit_code = exit_code
        self.end_reason = end_reason
        self.outcome = outcome
        self.diagnostic = diagnostic
        self.events = events
        self.session = session
        self.signal_checks = signal_checks
        self.loop_polls = loop_polls
        self.calls = calls.copy()


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
    grade: String = String(""),
    misses: MissOut = MissOut(True, UInt64(0), String("")),
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
    arm_out: OpOut = OpOut(True, String("")),
    disarm_out: OpOut = OpOut(True, String("")),
    read_files: Bool = True,
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
    cfg.grade = grade.copy()
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_lifecycle = True
    cfg.lifecycle_ring_bytes = UInt32(8388608)
    cfg.has_copy = True
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    kernel.misses_out = misses.copy()
    kernel.misses_out2 = misses2.copy()
    kernel.use_misses2 = use_misses2
    kernel.arm_out = arm_out.copy()
    kernel.disarm_out = disarm_out.copy()
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
    kernel.add_poll(_timeout(), 103)
    # One head check plus one gate per frame; the next head check latches.
    var signal = ScriptSignal()
    for i in range(len(payloads) + 1):
        signal.add(String("none"))
    signal.add(String("pending"))
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    var result = collector.run(kernel, clock, signal, writer)
    var events = String("")
    var session = String("")
    if read_files:
        events = _read_text(cfg.output + String("/events.ndjson"))
        session = _read_text(cfg.output + String("/session.json"))
    # Close-out drains poll with timeout 0; the loop never does.
    var loop_polls = 0
    for t in kernel.poll_timeouts:
        if t != 0:
            loop_polls += 1
    var out = CaseOut(
        result.exit_code,
        result.end_reason,
        result.outcome,
        result.diagnostic,
        events,
        session,
        signal.checks,
        loop_polls,
        kernel.calls.copy(),
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
                'lifecycle events","reason":"copy_attribution '
                'partial (copy without pending operation)",'
                '"evidence_refs":'
                '["capture:seq=0","capture:seq=1"],'
                '"relations":{"mapping_release":{"status":'
                '"complete_for_scope","loss_count":"0",'
                '"scope":"mapping and release pairing",'
                '"reason":"all mapping and release '
                'relationships paired","evidence_refs":[]},'
                '"copy_attribution":{"status":"partial",'
                '"loss_count":null,"scope":"copy attribution",'
                '"reason":"copy without pending operation",'
                '"evidence_refs":'
                '["capture:seq=0","capture:seq=1"]},'
                '"sync_attribution":{"status":'
                '"complete_for_scope","loss_count":"0",'
                '"scope":"sync attribution","reason":"all sync '
                'attribution relationships paired",'
                '"evidence_refs":[]}}}'
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
                '"reason":"mapping_release partial (failure '
                'carries no mapping); copy_attribution partial '
                '(copy without pending operation)"'
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
            String(
                '"reason":"sync_attribution partial (sync '
                'references unknown mapping)"'
            ),
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


def _session_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    return out^


def test_admitted_caps_carry_grade() raises:
    # The admission grade lands on every qualified
    # channel (bounce, lifecycle, copy, sync) and on no
    # auxiliary one (pool, conversion, region, task).
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(1, 1, 1, UInt64(201), UInt64(2001), UInt64(4096),
                UInt64(0), 4))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1), String("local-auto"))
    var s = parse_session(_session_bytes(c.session))
    assert_true(s.cap_bounce_attempts.has_grade)
    assert_equal(s.cap_bounce_attempts.grade, String("local-auto"))
    assert_true(s.cap_mapping_lifecycle.has_grade)
    assert_equal(s.cap_mapping_lifecycle.grade, String("local-auto"))
    assert_true(s.cap_copy_bytes.has_grade)
    assert_equal(s.cap_copy_bytes.grade, String("local-auto"))
    assert_true(s.cap_sync_requests.has_grade)
    assert_equal(s.cap_sync_requests.grade, String("local-auto"))
    assert_true(not s.cap_pool_stats.has_grade)
    assert_true(not s.cap_conversion_results.has_grade)
    assert_true(not s.cap_region_state.has_grade)
    assert_true(not s.cap_task_context.has_grade)


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
                'malformed=(0) dropped=(0) recursion_missed=(0) '
                'size_omitted=(0) '
                'duration_omitted=(0) signal_omitted=(0) '
                'rejected=(1) write_failed=(0))"'
            ),
        )
    )


def _one_copy_run(
    misses: MissOut,
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
) raises -> CaseOut:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(101), UInt64(1001), UInt64(4096),
                UInt64(4096), 0))
    return _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1), misses=misses, misses2=misses2,
        use_misses2=use_misses2)


def _error_copy_run(
    misses: MissOut,
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
) raises -> CaseOut:
    var payloads = List[List[UInt8]]()
    var bad = List[UInt8]()
    for i in range(37):
        bad.append(UInt8(0))
    payloads.append(bad^)
    return _run(
        payloads^,
        _cut(UInt64(1), UInt64(37), UInt64(1), UInt64(37)),
        _zero_cut(), UInt64(0), _zero_cut(), UInt64(0),
        misses=misses, misses2=misses2,
        use_misses2=use_misses2)


def test_recursion_misses_are_detail_loss() raises:
    # Kernel-skipped program runs never reach a ring; they
    # are loss, so a clean ring with misses is not complete.
    var c = _one_copy_run(MissOut(True, UInt64(5), String("")))
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 5 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(5) '
                'size_omitted=(0) duration_omitted=(0) '
                'signal_omitted=(0) rejected=(0) write_failed=(0))"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":"5",'),
        )
    )


def test_zero_recursion_misses_stay_complete() raises:
    var c = _one_copy_run(MissOut(True, UInt64(0), String("")))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 0 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(0) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"detail":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_unreadable_recursion_misses_make_loss_unknown() raises:
    # An unreadable count can never be reported as zero.
    var c = _one_copy_run(
        MissOut(False, UInt64(0), String("fdinfo gone"))
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss unknown (recursion misses '
                'unreadable: fdinfo gone; known: submit_fail=(0) '
                'malformed=(0) '
                'dropped=(0) recursion_missed=(unavailable) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"aggregate":{"status":"partial","loss_count":null,'),
        )
    )


def test_attempt_misses_make_aggregate_partial() raises:
    # Skipped attempt runs never advance the aggregate counters.
    var c = _one_copy_run(
        MissOut(True, UInt64(5), String(""), UInt64(3))
    )
    assert_true(
        _contains(
            c.session,
            String('"aggregate":{"status":"partial","loss_count":"3",'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 3 (recursion)"),
        )
    )


def test_copy_only_misses_keep_aggregate_complete() raises:
    var c = _one_copy_run(MissOut(True, UInt64(5), String("")))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_admitted_frame_skips_only_its_own_signal_check() raises:
    # Head check, frame, gate check, timeout, head check latches.
    var c = _one_copy_run(MissOut(True, UInt64(0), String("")))
    assert_equal(c.end_reason, String("signal"))
    assert_equal(c.signal_checks, 3)
    assert_equal(c.loop_polls, 2)


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
    # with distinct generations persist exactly as
    # 500 paired map_result/unmap records plus 4
    # counter snapshots; every generation pairs with
    # its own unmap, detail is lossless, correlation
    # pairs everything, and the persisted-event
    # balance closes at zero open mappings.
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
    var lines = _lines(c.events)
    assert_equal(len(lines), 1004)
    for i in range(500):
        var want_id = String('"mapping_id":"gen-')
        want_id += String(100 + i)
        want_id += String('"')
        assert_true(
            _contains(lines[2 * i], String('"kind":"map_result"')))
        assert_true(_contains(lines[2 * i], want_id))
        assert_true(
            _contains(lines[2 * i + 1], String('"kind":"unmap"')))
        assert_true(_contains(lines[2 * i + 1], want_id))
    for i in range(1000, 1004):
        assert_true(
            _contains(lines[i], String('"kind":"counter_snapshot"')))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"capture ok, 1000 map_result/unmap '
                'events persisted; admitted under '
                'test-profile-1; v2 wire reports opaque '
                'mapping generations when observed"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"loss_count":"0","scope":"0 bounce_attempt + '
                '1000 map_result/unmap + 0 copy/sync_request '
                'events"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"reason":"all lifecycle events paired"'),
        )
    )
    assert_true(
        _contains(c.session, String('"open_mappings":"0"')))


def test_dropped_map_unmap_still_reports() raises:
    # A dropped map with a persisting unmap still reports under partial loss.
    var tmp = _mkdtemp()
    var out_dir = tmp + String("/cap")
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 1073741824
    cfg.output = out_dir
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
    kernel.add_snap(SnapOut(True, _zero_cut().copy(), String("")))
    kernel.add_snap(SnapOut(True, _zero_cut().copy(), String("")))
    var lc_cut = _cut(UInt64(2), UInt64(8192), UInt64(2), UInt64(8192))
    kernel.add_snap_at(1, SnapOut(True, lc_cut.copy(), String("")))
    kernel.add_snap_at(1, SnapOut(True, lc_cut.copy(), String("")))
    kernel.add_snap_at(2, SnapOut(True, _zero_cut().copy(), String("")))
    kernel.add_snap_at(2, SnapOut(True, _zero_cut().copy(), String("")))
    # BPF emitted both records; the bridge delivered only the unmap.
    var flow = _stats(UInt64(2), UInt64(1), UInt64(0), UInt64(1))
    var ch0n = _stats(UInt64(0), UInt64(0), UInt64(0), UInt64(0))
    kernel.add_stats(_zero_stats())
    kernel.add_stats(_zero_stats())
    kernel.add_stats(flow.copy())
    kernel.add_stats(flow.copy())
    kernel.add_stats(flow.copy())
    kernel.add_stats(flow.copy())
    kernel.add_stats(ch0n)
    kernel.add_stats_at(1, _zero_stats())
    kernel.add_stats_at(1, flow.copy())
    kernel.add_stats_at(2, _zero_stats())
    kernel.add_stats_at(2, _zero_stats())
    var payloads = List[List[UInt8]]()
    # Ktime 30s lands inside the read-back window.
    payloads.append(
        _lc_raw(2, 3, 2, UInt64(121), UInt64(30000000000),
                UInt64(4096), UInt64(41)))
    for i in range(len(payloads)):
        kernel.add_poll(_batch(payloads[i]), 1)
    kernel.add_poll(_timeout(), 103)
    var signal = ScriptSignal()
    for i in range(len(payloads) + 1):
        signal.add(String("none"))
    signal.add(String("pending"))
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    var result = collector.run(kernel, clock, signal, writer)
    assert_equal(result.exit_code, EXIT_PARTIAL)
    assert_equal(result.outcome, String("finalized"))
    var events = _read_text(out_dir + String("/events.ndjson"))
    var session = _read_text(out_dir + String("/session.json"))
    var lines = _lines(events)
    assert_equal(len(lines), 5)
    assert_true(_contains(lines[0], String('"kind":"unmap"')))
    assert_true(_contains(lines[0], String('"mapping_id":"gen-41"')))
    assert_true(
        _contains(lines[0], String('"correlation":"unpaired"')))
    assert_true(
        _contains(
            session,
            String(
                '"reason":"detail loss 1 (submit_fail=(0) '
                'malformed=(0) dropped=(1) '
            ),
        )
    )
    assert_true(
        _contains(
            session,
            String(
                '"reason":"mapping_release partial (release '
                'of unknown mapping)"'
            ),
        )
    )
    # The offline report reads the capture with partial mapping correlation.
    var r = read_capture(out_dir, False, default_limits())
    var analyzer = Analyzer(r.session)
    var count = 0
    while r.has_more():
        analyzer.consume(r.next_event())
        count += 1
    assert_equal(count, 5)
    assert_true(not r.partial)
    var rep = analyzer.finish(r.session.window_end_ns, r.partial)
    assert_equal(rep.q_correlation.status, String("partial"))
    assert_equal(rep.q_corr_mapping.status, String("partial"))
    assert_true(rep.q_corr_mapping.has_loss_count)
    # No release invented: zero completed, one unpaired counted.
    var saw_completed = False
    var saw_unpaired = False
    for i in range(len(rep.metrics)):
        if rep.metrics[i].name == String("completed_lifetime_count"):
            saw_completed = True
            assert_true(rep.metrics[i].has_value)
            assert_equal(rep.metrics[i].value, UInt64(0))
            assert_equal(rep.metrics[i].coverage, String("partial"))
        if rep.metrics[i].name == String("unpaired_lifecycle_events"):
            saw_unpaired = True
            assert_true(rep.metrics[i].has_value)
            assert_equal(rep.metrics[i].value, UInt64(1))
    assert_true(saw_completed)
    assert_true(saw_unpaired)
    # Every renderer handles the degraded report.
    var text = render_text(rep)
    var md = render_markdown(rep)
    var js = render_json(rep)
    assert_true(text.byte_length() > 0)
    assert_true(md.byte_length() > 0)
    assert_true(js.byte_length() > 0)
    assert_true(_contains(text, String("partial")))
    assert_true(_contains(md, String("partial")))
    assert_true(_contains(js, String('"status": "partial"')))



def _detail_misses(
    bounce: UInt64,
    exit_misses: UInt64,
    sync_device: UInt64,
    sync_cpu: UInt64,
    lc_map: UInt64,
    lc_unmap: UInt64,
    deferred: UInt64,
    recovered: UInt64,
    attempt: UInt64 = UInt64(0),
) raises -> MissOut:
    return MissOut(
        True, UInt64(0), String(""), attempt, True, bounce,
        exit_misses, sync_device, sync_cpu, lc_map, lc_unmap,
        deferred, recovered,
    )


def test_exact_copy_loss_zero_stays_complete() raises:
    # E=100, D=10, R=110: every skipped or deferred copy
    # recovered, so busy capture stays complete.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 0 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(0) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"detail":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )
    assert_true(
        _contains(c.session, String("copy.mv_bounce_misses"))
    )
    assert_true(_contains(c.session, String("copy.deferred")))
    assert_true(_contains(c.session, String("copy.recovered")))


def test_exact_copy_loss_positive_is_partial() raises:
    # Others=3, E=10, D=2, R=5: loss is 3+7=10.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(10), UInt64(4), UInt64(1), UInt64(0),
            UInt64(1), UInt64(1), UInt64(2), UInt64(5),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 10 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(10) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":"10",'),
        )
    )


def test_exact_copy_loss_negative_is_unknown() raises:
    # R exceeds E+D: counters contradict, loss unknown.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(5), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(10),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(_contains(c.session, String("contradict")))
    assert_true(
        _contains(c.session, String("copy.mv_bounce_misses"))
    )


def test_exact_copy_loss_counts_attempt_misses() raises:
    # Attempt misses charge both detail and the aggregate.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(10), UInt64(4), UInt64(1), UInt64(0),
            UInt64(1), UInt64(1), UInt64(2), UInt64(5),
            UInt64(3),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '\"reason\":\"detail loss 13 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(13) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 3 (recursion)"),
        )
    )


def test_exact_copy_loss_counts_sync_cpu_misses() raises:
    # Sync_cpu misses charge detail like every other program.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(2),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '\"reason\":\"detail loss 2 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(2) '
            ),
        )
    )


def test_exact_copy_exit_only_stays_complete() raises:
    # Exit misses alone never lose a copy.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(0), UInt64(5), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 0 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(0) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"detail":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_exact_copy_identity_unreadable_is_unknown() raises:
    var c = _one_copy_run(
        MissOut(
            False, UInt64(0),
            String("copy program identity unreadable: no name"),
        )
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(_contains(c.session, String("identity")))
    assert_true(
        _contains(
            c.session, String("recursion_missed=(unavailable)")
        )
    )


def test_copy_fb_geometry_refuses() raises:
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 1073741824
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_copy = True
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    kernel.fb_geom.max_entries = UInt32(2)
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
            String("map cp mv_copy_fb geometry"),
        )
    )


def _good_fb() -> GeomOut:
    return GeomOut(
        True, UInt32(2), UInt32(4), UInt32(8), UInt32(4),
        String(""),
    )


def _good_claims() -> GeomOut:
    return GeomOut(
        True, UInt32(2), UInt32(4), UInt32(16), UInt32(4096),
        String(""),
    )


def _run_geom(fb: GeomOut, claims: GeomOut) raises -> RunResult:
    var tmp = _mkdtemp()
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 1073741824
    cfg.output = tmp + String("/cap")
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_copy = True
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    kernel.channels = 3
    kernel.fb_geom = fb.copy()
    kernel.claims_geom = claims.copy()
    var signal = ScriptSignal()
    var clock = ScriptClock()
    clock.add(UInt64(0))
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    return collector.run(kernel, clock, signal, writer)


def test_copy_fb_wrong_type_refuses() raises:
    var fb = _good_fb()
    fb.map_type = UInt32(1)
    var result = _run_geom(fb^, _good_claims())
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_copy_fb geometry")
        )
    )


def test_copy_fb_wrong_key_refuses() raises:
    var fb = _good_fb()
    fb.key_size = UInt32(8)
    var result = _run_geom(fb^, _good_claims())
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_copy_fb geometry")
        )
    )


def test_copy_fb_wrong_value_refuses() raises:
    var fb = _good_fb()
    fb.value_size = UInt32(4)
    var result = _run_geom(fb^, _good_claims())
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_copy_fb geometry")
        )
    )


def test_copy_claims_wrong_type_refuses() raises:
    var claims = _good_claims()
    claims.map_type = UInt32(1)
    var result = _run_geom(_good_fb(), claims^)
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_claims geometry")
        )
    )


def test_copy_claims_wrong_key_refuses() raises:
    var claims = _good_claims()
    claims.key_size = UInt32(8)
    var result = _run_geom(_good_fb(), claims^)
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_claims geometry")
        )
    )


def test_copy_claims_wrong_value_refuses() raises:
    var claims = _good_claims()
    claims.value_size = UInt32(8)
    var result = _run_geom(_good_fb(), claims^)
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_claims geometry")
        )
    )


def test_copy_claims_wrong_max_refuses() raises:
    var claims = _good_claims()
    claims.max_entries = UInt32(1024)
    var result = _run_geom(_good_fb(), claims^)
    assert_equal(result.exit_code, EXIT_REFUSAL)
    assert_true(
        _contains(
            result.diagnostic, String("map cp mv_claims geometry")
        )
    )


def test_copy_arm_failure_refuses_start() raises:
    # A failed arm write fails the capture closed, never unarmed.
    var payloads = List[List[UInt8]]()
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _zero_cut(), UInt64(0),
        arm_out=OpOut(False, String("map write denied")),
        read_files=False,
    )
    assert_equal(c.exit_code, EXIT_REFUSAL)
    assert_equal(c.outcome, String("refused"))
    assert_true(_contains(c.diagnostic, String("arm copy")))
    assert_equal(len(c.calls), 2)
    assert_equal(c.calls[0], String("attach"))
    assert_equal(c.calls[1], String("arm"))


def test_copy_disarm_failure_makes_detail_unknown() raises:
    # A failed disarm write leaves copy detail unknown, never complete.
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(101), UInt64(1001), UInt64(4096),
                UInt64(4096), 0))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1),
        disarm_out=OpOut(False, String("map write denied")),
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String('\"detail\":{\"status\":\"partial\",\"loss_count\":null,'),
        )
    )
    assert_true(_contains(c.session, String("copy disarm")))


def test_copy_arm_disarm_bracket_the_capture() raises:
    # The arm write lands after attach, the disarm before detach.
    var c = _one_copy_run(MissOut(True, UInt64(0), String("")))
    assert_equal(len(c.calls), 4)
    assert_equal(c.calls[0], String("attach"))
    assert_equal(c.calls[1], String("arm"))
    assert_equal(c.calls[2], String("disarm"))
    assert_equal(c.calls[3], String("detach"))


def test_copy_disarm_precedes_detach_on_error_close() raises:
    # The error path disarms before detach like the normal close.
    var c = _error_copy_run(MissOut(True, UInt64(0), String("")))
    assert_equal(c.outcome, String("error"))
    assert_equal(len(c.calls), 4)
    assert_equal(c.calls[0], String("attach"))
    assert_equal(c.calls[1], String("arm"))
    assert_equal(c.calls[2], String("disarm"))
    assert_equal(c.calls[3], String("detach"))


def test_copy_contradiction_keeps_aggregate_complete() raises:
    # A copy-counter contradiction poisons detail, not a clean aggregate.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(5), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(10),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('\"detail\":{\"status\":\"partial\",\"loss_count\":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"complete_for_scope\",'
                '\"loss_count\":\"0\",'
            ),
        )
    )


def test_copy_contradiction_keeps_attempt_loss() raises:
    # Attempt skips still charge the aggregate under a contradiction.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(5), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(10),
            UInt64(2),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('\"detail\":{\"status\":\"partial\",\"loss_count\":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"2\",'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 2 (recursion)"),
        )
    )


def test_copy_overflow_keeps_aggregate_complete() raises:
    # A copy-counter overflow poisons detail, not a clean aggregate.
    var c = _one_copy_run(
        _detail_misses(
            ~UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(1), UInt64(0),
        )
    )
    assert_true(_contains(c.session, String("overflow")))
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"complete_for_scope\",'
                '\"loss_count\":\"0\",'
            ),
        )
    )


def _stable_detail() raises -> MissOut:
    return _detail_misses(
        UInt64(100), UInt64(3), UInt64(0), UInt64(0),
        UInt64(0), UInt64(0), UInt64(10), UInt64(110),
    )


def test_stable_second_miss_read_keeps_exact_loss() raises:
    # Unchanged counters after settle and drain keep exact loss.
    var c = _one_copy_run(_stable_detail(), _stable_detail(), True)
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 0 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(0) '
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"detail":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_grown_entry_misses_after_detach_make_loss_unknown() raises:
    # E grows after the first read: detail loss unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(101), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.mv_bounce_misses",'
                '"interpretation":"100"'
            ),
        )
    )


def test_grown_deferred_after_detach_make_loss_unknown() raises:
    # D grows after the first read: detail loss unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(11), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.deferred","interpretation":"10"'
            ),
        )
    )


def test_grown_recovered_after_detach_make_loss_unknown() raises:
    # R grows after the first read: detail loss unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(111),
        ),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.recovered","interpretation":"110"'
            ),
        )
    )


def test_unreadable_second_miss_read_makes_loss_unknown() raises:
    # An unreadable second read cannot prove a quiet stop.
    var c = _one_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.mv_bounce_misses",'
                '"interpretation":"100"'
            ),
        )
    )


def test_error_close_stable_read_keeps_error_cause() raises:
    # A quiet error stop keeps its own cause, never a late one.
    var c = _error_copy_run(
        _stable_detail(), _stable_detail(), True)
    assert_equal(c.outcome, String("error"))
    assert_true(_contains(c.session, String("error shutdown")))
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_grown_entry_misses_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(101), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_grown_deferred_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(11), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_grown_recovered_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(111),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_unreadable_second_read_notes_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )


def _Detail_failed(attempt: UInt64, reason: String) raises -> MissOut:
    var m = MissOut(True, UInt64(0), String(""), attempt)
    m.detail_error = reason
    return m^


def test_wrapped_fallback_keeps_attempt_count() raises:
    # Wrapped fallback counters poison detail, not a read attempt count.
    var c = _one_copy_run(
        _Detail_failed(
            UInt64(3), String("ch2 fallback counters wrapped"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"partial\",'
                '\"loss_count\":\"3\",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 3 (recursion)"),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"detail\":{\"status\":\"partial\",'
                '\"loss_count\":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "copy detail unreadable: "
                "ch2 fallback counters wrapped"
            ),
        )
    )


def test_frame_lost_fallback_keeps_attempt_count() raises:
    # A lost frame names itself, never a counter wrap.
    var c = _one_copy_run(
        _Detail_failed(
            UInt64(3), String("ch2 fallback frame lost"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"partial\",'
                '\"loss_count\":\"3\",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"detail\":{\"status\":\"partial\",'
                '\"loss_count\":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "copy detail unreadable: ch2 fallback frame lost"
            ),
        )
    )


def test_unreadable_fallback_keeps_attempt_count() raises:
    # An unreadable fallback map poisons detail, not the attempt count.
    var c = _one_copy_run(
        _Detail_failed(
            UInt64(3), String("ch2 fallback: short fallback read"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"partial\",'
                '\"loss_count\":\"3\",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"detail\":{\"status\":\"partial\",'
                '\"loss_count\":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "copy detail unreadable: "
                "ch2 fallback: short fallback read"
            ),
        )
    )


def test_unreadable_lifecycle_misses_keep_attempt_count() raises:
    # Unreadable lifecycle misses poison detail, not the attempt count.
    var c = _one_copy_run(
        _Detail_failed(
            UInt64(3), String("ch1 lifecycle program count"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"partial\",'
                '\"loss_count\":\"3\",'
            ),
        )
    )
    assert_true(
        not _contains(
            c.session, String("attempt program skips unknown"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"detail\":{\"status\":\"partial\",'
                '\"loss_count\":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "copy detail unreadable: "
                "ch1 lifecycle program count"
            ),
        )
    )


def test_unreadable_copy_misses_keep_attempt_count() raises:
    # Unreadable copy misses poison detail, not the attempt count.
    var c = _one_copy_run(
        _Detail_failed(
            UInt64(3), String("ch2 copy program count"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"aggregate\":{\"status\":\"partial\",'
                '\"loss_count\":\"3\",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '\"detail\":{\"status\":\"partial\",'
                '\"loss_count\":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "copy detail unreadable: ch2 copy program count"
            ),
        )
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
