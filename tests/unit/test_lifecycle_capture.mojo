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
    channels: Int = 3,
    timeouts: Int = 103,
    confirm_poll_err: Bool = False,
    fail_confirm_stats: Bool = False,
    lower_bound: Bool = False,
) raises -> CaseOut:
    """Run one scripted multi-channel capture; return its outputs.

    Channels selects attempt-only (1), lifecycle (2),
    or copy (3); enabled channels use 8 MiB rings;
    end0/end1/end2 are the 6-word end cuts and rx1/rx2
    the lifecycle/copy received/delivered counts
    (attempt traffic is the remainder). Signals stop
    the run after the last batch. Timeouts sizes the
    trailing timeout script; confirm_poll_err appends
    one error poll after it; fail_confirm_stats breaks
    the confirm final on multi-channel runs.
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
    cfg.has_lifecycle = channels >= 2
    cfg.lifecycle_ring_bytes = UInt32(8388608)
    cfg.has_copy = channels >= 3
    cfg.copy_ring_bytes = UInt32(8388608)
    cfg.attempt_loss_lower_bound = lower_bound
    var kernel = ScriptKernel()
    kernel.channels = channels
    kernel.misses_out = misses.copy()
    kernel.misses_out2 = misses2.copy()
    kernel.use_misses2 = use_misses2
    kernel.arm_out = arm_out.copy()
    kernel.disarm_out = disarm_out.copy()
    kernel.add_snap(_zero_snap())
    kernel.add_snap(_zero_snap())
    if channels >= 2:
        kernel.add_snap_at(1, _zero_snap())
        kernel.add_snap_at(1, _zero_snap())
    if channels >= 3:
        kernel.add_snap_at(2, _zero_snap())
        kernel.add_snap_at(2, _zero_snap())
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    if channels >= 2:
        kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
        kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
    if channels >= 3:
        kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
        kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
    var n = UInt64(len(payloads))
    # Shared stats queue in read order: sum baseline, ch0
    # baseline, drain pair, drain cut, final sum, ch0 final.
    # Attempt-only skips both ch0 entries (no _at reads).
    var total = _stats(n, n, UInt64(0), UInt64(0))
    var ch0n = _stats(
        n - rx1 - rx2, n - rx1 - rx2, UInt64(0), UInt64(0))
    kernel.add_stats(_zero_stats())
    if channels >= 2:
        kernel.add_stats(_zero_stats())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    if fail_confirm_stats:
        kernel.add_stats(
            StatsOut(
                False, UInt64(0), UInt64(0), UInt64(0),
                UInt64(0), UInt64(0),
                String("confirm stats lost"),
            )
        )
    else:
        kernel.add_stats(total.copy())
    if channels >= 2:
        kernel.add_stats(ch0n)
        kernel.add_stats_at(1, _zero_stats())
        kernel.add_stats_at(1, _stats(rx1, rx1, UInt64(0), UInt64(0)))
    if channels >= 3:
        kernel.add_stats_at(2, _zero_stats())
        kernel.add_stats_at(2, _stats(rx2, rx2, UInt64(0), UInt64(0)))
    for i in range(len(payloads)):
        kernel.add_poll(_batch(payloads[i]), 1)
    kernel.add_poll(_timeout(), timeouts)
    if confirm_poll_err:
        kernel.add_poll(
            PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("confirm poll failed"),
            ),
            1,
        )
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


def _live_attach(
    clock_values: List[UInt64], has_lifecycle: Bool, has_copy: Bool
) -> UInt64:
    """Attach read of an explicit startup script (no pool)."""
    var nch = 1
    if has_lifecycle:
        nch += 1
    if has_copy:
        nch += 1
    return clock_values[1 + 2 * nch]


def _live_clock_values(
    base: UInt64, has_lifecycle: Bool, has_copy: Bool
) -> List[UInt64]:
    """Explicit startup reads through the ready stamp."""
    var nch = 1
    if has_lifecycle:
        nch += 1
    if has_copy:
        nch += 1
    var out = List[UInt64]()
    for i in range(1 + 2 * nch + 1):
        out.append(base + UInt64(i))
    return out^


def _run_live(
    payloads: List[List[UInt8]],
    clock_values: List[UInt64],
    end0: List[UInt64],
    end1: List[UInt64],
    rx1: UInt64,
    end2: List[UInt64],
    rx2: UInt64,
    has_lifecycle: Bool = True,
    has_copy: Bool = True,
    max_events_bytes: Int = 1073741824,
    duration_s: UInt64 = UInt64(60),
    timeouts: Int = 103,
    read_files: Bool = True,
    misses: MissOut = MissOut(True, UInt64(0), String("")),
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
) raises -> CaseOut:
    """_run with an explicit clock script and channel flags.

    Record ktimes are absolute; tests place them with
    _live_attach plus an offset. The scripted tail steps
    100ms per read.
    """
    var tmp = _mkdtemp()
    var out_dir = tmp + String("/cap")
    var cfg = CollectorConfig()
    cfg.duration_s = duration_s
    cfg.max_events_bytes = max_events_bytes
    cfg.output = out_dir
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(8388608)
    cfg.has_lifecycle = has_lifecycle
    cfg.lifecycle_ring_bytes = UInt32(8388608)
    cfg.has_copy = has_copy
    cfg.copy_ring_bytes = UInt32(8388608)
    var kernel = ScriptKernel()
    if has_copy:
        kernel.channels = 3
    elif has_lifecycle:
        kernel.channels = 2
    kernel.misses_out = misses.copy()
    kernel.misses_out2 = misses2.copy()
    kernel.use_misses2 = use_misses2
    kernel.add_snap(_zero_snap())
    kernel.add_snap(_zero_snap())
    if has_lifecycle:
        kernel.add_snap_at(1, _zero_snap())
        kernel.add_snap_at(1, _zero_snap())
    if has_copy:
        kernel.add_snap_at(2, _zero_snap())
        kernel.add_snap_at(2, _zero_snap())
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    kernel.add_snap(SnapOut(True, end0.copy(), String("")))
    if has_lifecycle:
        kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
        kernel.add_snap_at(1, SnapOut(True, end1.copy(), String("")))
    if has_copy:
        kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
        kernel.add_snap_at(2, SnapOut(True, end2.copy(), String("")))
    var n = UInt64(len(payloads))
    var total = _stats(n, n, UInt64(0), UInt64(0))
    var ch0n = _stats(
        n - rx1 - rx2, n - rx1 - rx2, UInt64(0), UInt64(0))
    kernel.add_stats(_zero_stats())
    var nch = 1
    if has_lifecycle:
        nch += 1
    if has_copy:
        nch += 1
    if nch >= 2:
        kernel.add_stats(_zero_stats())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    kernel.add_stats(total.copy())
    if nch >= 2:
        kernel.add_stats(ch0n)
    if has_lifecycle:
        kernel.add_stats_at(1, _zero_stats())
        kernel.add_stats_at(1, _stats(rx1, rx1, UInt64(0), UInt64(0)))
    if has_copy:
        kernel.add_stats_at(2, _zero_stats())
        kernel.add_stats_at(2, _stats(rx2, rx2, UInt64(0), UInt64(0)))
    for i in range(len(payloads)):
        kernel.add_poll(_batch(payloads[i]), 1)
    kernel.add_poll(_timeout(), timeouts)
    var signal = ScriptSignal()
    for i in range(len(payloads) + 1):
        signal.add(String("none"))
    signal.add(String("pending"))
    var clock = ScriptClock()
    clock.step = UInt64(100000000)
    for i in range(len(clock_values)):
        clock.add(clock_values[i])
    var writer = ScriptWriter()
    var collector = Collector(cfg)
    var result = collector.run(kernel, clock, signal, writer)
    var events = String("")
    var session = String("")
    if read_files:
        events = _read_text(cfg.output + String("/events.ndjson"))
        session = _read_text(cfg.output + String("/session.json"))
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
    submit_fail: UInt64 = UInt64(0),
) -> List[UInt64]:
    var vals = List[UInt64]()
    vals.append(observed)
    vals.append(observed_bytes)
    vals.append(emitted)
    vals.append(emitted_bytes)
    vals.append(submit_fail)
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
                'rejected=(1) write_failed=(0)); '
                'first unknown copy: SLOT_READ"'
            ),
        )
    )


def test_unknown_copies_counted_per_reason() raises:
    # Each unknown copy charges its wire reason; the detail names the first.
    var payloads = List[List[UInt8]]()
    var reasons = List[Int]()
    reasons.append(5)
    reasons.append(6)
    reasons.append(5)
    reasons.append(1)
    reasons.append(2)
    reasons.append(3)
    for i in range(len(reasons)):
        payloads.append(
            _cp_raw(2, 0, 2, UInt64(240 + i), UInt64(2040 + i),
                    UInt64(4096), UInt64(0), reasons[i]))
    var c = _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(6), UInt64(24576), UInt64(6), UInt64(24576)),
        UInt64(6))
    assert_equal(c.exit_code, EXIT_PARTIAL)
    assert_true(not _contains(c.events, String('"kind":"copy"')))
    assert_true(
        _contains(
            c.session,
            String(
                '"reason":"detail loss 6 (submit_fail=(0) '
                'malformed=(0) dropped=(0) recursion_missed=(0) '
                'size_omitted=(0) '
                'duration_omitted=(0) signal_omitted=(0) '
                'rejected=(6) write_failed=(0)); '
                'first unknown copy: LAYOUT"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.unknown_layout",'
                '"interpretation":"2"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.unknown_shift",'
                '"interpretation":"1"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.unknown_slot_read",'
                '"interpretation":"1"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.unknown_mask_read",'
                '"interpretation":"1"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"copy.unknown_bounds",'
                '"interpretation":"1"'
            ),
        )
    )


def _one_copy_run(
    misses: MissOut,
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
    timeouts: Int = 103,
    confirm_poll_err: Bool = False,
    fail_confirm_stats: Bool = False,
    lower_bound: Bool = False,
) raises -> CaseOut:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _cp_raw(2, 3, 1, UInt64(101), UInt64(1001), UInt64(4096),
                UInt64(4096), 0))
    return _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1), misses=misses, misses2=misses2,
        use_misses2=use_misses2, timeouts=timeouts,
        confirm_poll_err=confirm_poll_err,
        fail_confirm_stats=fail_confirm_stats,
        lower_bound=lower_bound)


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


def _one_attempt_run(
    misses: MissOut,
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
) raises -> CaseOut:
    var payloads = List[List[UInt8]]()
    return _run(
        payloads^, _zero_cut(), _zero_cut(), UInt64(0),
        _zero_cut(), UInt64(0),
        misses=misses, misses2=misses2,
        use_misses2=use_misses2, channels=1)


def _error_attempt_run(
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
        use_misses2=use_misses2, channels=1)


def _one_lc_run(
    misses: MissOut,
    misses2: MissOut = MissOut(True, UInt64(0), String("")),
    use_misses2: Bool = False,
) raises -> CaseOut:
    var payloads = List[List[UInt8]]()
    payloads.append(
        _lc_raw(1, 1, 1, UInt64(121), UInt64(1021),
                UInt64(4096), UInt64(41)))
    return _run(
        payloads^, _zero_cut(),
        _cut(UInt64(1), UInt64(4096), UInt64(1), UInt64(4096)),
        UInt64(1), _zero_cut(), UInt64(0),
        misses=misses, misses2=misses2,
        use_misses2=use_misses2, channels=2)


def _error_lc_run(
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
        use_misses2=use_misses2, channels=2)


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


def test_attempt_loss_lower_bound_labels_aggregate() raises:
    # Kernels before 6.7 skip programs in trace_call_bpf
    # without counting them: a claimed aggregate count is
    # a lower bound there and the reason says so. D34 caps
    # the status at partial even with zero known misses.
    var c = _one_copy_run(
        MissOut(True, UInt64(5), String(""), UInt64(3)),
        lower_bound=True,
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
            String(
                "attempt loss counts are a lower bound before 6.7"
            ),
        )
    )
    var zero = _one_copy_run(
        MissOut(True, UInt64(5), String("")), lower_bound=True
    )
    assert_true(
        _contains(
            zero.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":"0",'
            ),
        )
    )
    assert_true(
        _contains(
            zero.session,
            String(
                "attempt loss counts are a lower bound before 6.7"
            ),
        )
    )
    var plain = _one_copy_run(
        MissOut(True, UInt64(5), String(""), UInt64(3))
    )
    assert_true(
        not _contains(
            plain.session,
            String(
                "attempt loss counts are a lower bound before 6.7"
            ),
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
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
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


def test_error_close_unreadable_second_read_notes_unreadable() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_unreadable_second_read_keeps_its_diagnostic() raises:
    # A failed re-read keeps the kernel diagnostic in its reason.
    var c = _one_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                "recursion misses unreadable after settle: "
                "fdinfo gone"
            ),
        )
    )


def test_error_close_unreadable_second_read_keeps_diagnostic() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                "recursion misses unreadable after settle: "
                "fdinfo gone"
            ),
        )
    )


def test_failed_second_detail_read_keeps_its_diagnostic() raises:
    # A failed detail re-read keeps its diagnostic in its reason.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(0), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                "recursion misses unreadable after settle: "
                "ch2 fallback counters wrapped"
            ),
        )
    )


def test_error_close_failed_second_detail_read_keeps_diagnostic() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(0), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                "recursion misses unreadable after settle: "
                "ch2 fallback counters wrapped"
            ),
        )
    )


def test_attempt_only_stable_second_read_keeps_exact_loss() raises:
    # Unchanged attempt counters keep exact loss without extras.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(True, UInt64(0), String("")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
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
    assert_true(
        not _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_lifecycle_only_stable_second_read_keeps_exact_loss() raises:
    # Unchanged lifecycle counters keep exact loss without copy.
    var c = _one_lc_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(True, UInt64(0), String("")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
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
    assert_true(
        not _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_error_close_attempt_only_stable_read_keeps_error_cause() raises:
    # A quiet attempt-only error stop keeps its own cause.
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(True, UInt64(0), String("")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(_contains(c.session, String("error shutdown")))
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        not _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_error_close_lifecycle_only_stable_read_keeps_error_cause() raises:
    # A quiet lifecycle-only error stop keeps its own cause.
    var c = _error_lc_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(True, UInt64(0), String("")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(_contains(c.session, String("error shutdown")))
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        not _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_attempt_only_unreadable_second_read_goes_unknown() raises:
    # An unreadable ch0 re-read cannot prove a quiet stop.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )


def test_error_close_attempt_only_unreadable_second_read() raises:
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )


def test_lifecycle_only_failed_second_read_goes_unknown() raises:
    # A failed ch1 re-read fails closed with a stable attempt.
    var c = _one_lc_run(
        MissOut(True, UInt64(0), String("")),
        _detail_failed(
            UInt64(0), String("ch1 lifecycle program count")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
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
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_lifecycle_only_failed_second_read() raises:
    var c = _error_lc_run(
        MissOut(True, UInt64(0), String("")),
        _detail_failed(
            UInt64(0), String("ch1 lifecycle program count")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_copy_failed_second_detail_read_goes_unknown() raises:
    # A failed copy-detail re-read fails closed, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(0), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
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
            String(
                '"source":"copy.mv_bounce_misses",'
                '"interpretation":"100"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_error_close_copy_failed_second_detail_read() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(0), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
        )
    )
    assert_true(
        not _contains(c.session, String("post-snapshot activity"))
    )


def test_attempt_growth_after_detach_leaves_aggregate_unknown() raises:
    # A moved attempt count voids the first-read aggregate loss.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
            UInt64(1),
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_error_close_attempt_growth_leaves_aggregate_unknown() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
            UInt64(1),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_attempt_only_attempt_growth_leaves_aggregate_unknown() raises:
    # A moved attempt count voids the aggregate without extras.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String(""), UInt64(0)),
        MissOut(True, UInt64(0), String(""), UInt64(1)),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_error_close_attempt_only_attempt_growth_unknown() raises:
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String(""), UInt64(0)),
        MissOut(True, UInt64(0), String(""), UInt64(1)),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_unreadable_second_read_leaves_aggregate_unknown() raises:
    # An unreadable ch0 re-read voids the aggregate loss.
    var c = _one_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(recursion misses unreadable after settle)"
            ),
        )
    )


def test_error_close_unreadable_second_read_aggregate_unknown() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(recursion misses unreadable after settle)"
            ),
        )
    )


def test_attempt_only_unreadable_second_read_aggregate_unknown() raises:
    # An unreadable ch0 re-read voids the aggregate alone.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(recursion misses unreadable after settle)"
            ),
        )
    )


def test_error_close_attempt_only_unreadable_second_read_unknown() raises:
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String("")),
        MissOut(False, UInt64(0), String("fdinfo gone")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(recursion misses unreadable after settle)"
            ),
        )
    )


def test_confirm_poll_error_leaves_aggregate_unknown() raises:
    # A confirm poll failure skips the re-read; no exact loss.
    var c = _one_copy_run(
        _stable_detail(),
        timeouts=3,
        confirm_poll_err=True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(_contains(c.session, String("error shutdown")))
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(re-read skipped)"
            ),
        )
    )


def test_confirm_stats_error_leaves_aggregate_unknown() raises:
    # Unreadable confirm stats skip the re-read; no exact loss.
    var c = _one_copy_run(
        _stable_detail(),
        fail_confirm_stats=True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(_contains(c.session, String("error shutdown")))
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(re-read skipped)"
            ),
        )
    )


def test_copy_failed_second_read_with_attempt_growth_unknown() raises:
    # A failed detail re-read with a moved attempt voids both.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(2), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String("recursion misses unreadable after settle"),
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
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_error_close_copy_failed_second_read_attempt_growth() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_failed(
            UInt64(2), String("ch2 fallback counters wrapped")),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_grown_exit_misses_after_detach_make_loss_unknown() raises:
    # Exit misses grow alone: detail unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(4), UInt64(0), UInt64(0),
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
                '"source":"copy.mv_bounce_exit_misses",'
                '"interpretation":"3"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_grown_exit_misses_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(4), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_grown_sync_device_misses_after_detach_make_unknown() raises:
    # Sync-device misses grow alone: detail unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(1), UInt64(0),
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
                '"source":"copy.mv_sync_device_misses",'
                '"interpretation":"0"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_grown_sync_device_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(1), UInt64(0),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_grown_sync_cpu_misses_after_detach_make_unknown() raises:
    # Sync-cpu misses grow alone: detail unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(1),
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
                '"source":"copy.mv_sync_cpu_misses",'
                '"interpretation":"0"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_grown_sync_cpu_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(1),
            UInt64(0), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_grown_lc_map_misses_after_detach_make_unknown() raises:
    # Map misses grow alone: detail unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(1), UInt64(0), UInt64(10), UInt64(110),
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
                '"source":"lifecycle.mv_map_result_misses",'
                '"interpretation":"0"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_grown_lc_map_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(1), UInt64(0), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_grown_lc_unmap_misses_after_detach_make_unknown() raises:
    # Unmap misses grow alone: detail unknown, first kept.
    var c = _one_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(1), UInt64(10), UInt64(110),
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
                '"source":"lifecycle.mv_unmap_misses",'
                '"interpretation":"0"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_grown_lc_unmap_note_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        _detail_misses(
            UInt64(100), UInt64(3), UInt64(0), UInt64(0),
            UInt64(0), UInt64(1), UInt64(10), UInt64(110),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_detail_shape_flip_after_detach_makes_loss_unknown() raises:
    # A detail-to-count shape flip cannot prove a quiet stop.
    var c = _one_copy_run(
        _stable_detail(),
        MissOut(True, UInt64(0), String(""), UInt64(0)),
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
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_detail_shape_flip_notes_post_snapshot() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(True, UInt64(0), String(""), UInt64(0)),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_count_shape_flip_after_detach_makes_loss_unknown() raises:
    # A count-to-detail shape flip cannot prove a quiet stop.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String("")),
        _stable_detail(),
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
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_count_shape_flip_notes_post_snapshot() raises:
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String("")),
        _stable_detail(),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_detail_shape_flip_zero_counters_makes_unknown() raises:
    # A shape flip alone, with every counter zero, is unknown.
    var c = _one_copy_run(
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        ),
        MissOut(True, UInt64(0), String(""), UInt64(0)),
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
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_error_close_detail_shape_flip_zero_counters() raises:
    var c = _error_copy_run(
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        ),
        MissOut(True, UInt64(0), String(""), UInt64(0)),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_count_shape_flip_zero_counters_makes_unknown() raises:
    # A shape flip alone, with every counter zero, is unknown.
    var c = _one_attempt_run(
        MissOut(True, UInt64(0), String("")),
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
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
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_shape_flip_moved_attempt_after_failed_first_read_unknown() raises:
    # A failed first read hides the shape; a moved re-read voids loss.
    var c = _one_copy_run(
        _detail_failed(
            UInt64(0),
            String("ch2 fallback: short fallback read")),
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(1),
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_error_close_shape_flip_moved_attempt_failed_first_read() raises:
    var c = _error_copy_run(
        _detail_failed(
            UInt64(0),
            String("ch2 fallback: short fallback read")),
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(1),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_detail_shape_flip_moved_attempt_voids_aggregate() raises:
    # A detail-to-count flip with a moved attempt voids the loss.
    var c = _one_copy_run(
        _stable_detail(),
        MissOut(True, UInt64(0), String(""), UInt64(1)),
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
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_error_close_detail_shape_flip_moved_attempt_voids() raises:
    var c = _error_copy_run(
        _stable_detail(),
        MissOut(True, UInt64(0), String(""), UInt64(1)),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                "attempt program skips unknown "
                "(post-snapshot activity)"
            ),
        )
    )


def test_lifecycle_only_detail_failure_names_lifecycle_channel() raises:
    # A lifecycle-only detail failure names its own channel.
    var c = _one_lc_run(
        _detail_failed(
            UInt64(3), String("ch1 lifecycle program count"))
    )
    assert_equal(c.outcome, String("finalized"))
    assert_true(
        _contains(
            c.session,
            String(
                "lifecycle detail unreadable: "
                "ch1 lifecycle program count"
            ),
        )
    )
    assert_true(
        not _contains(c.session, String("copy detail unreadable"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"detail":{"status":"partial",'
                '"loss_count":null,'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":"3",'
            ),
        )
    )


def test_error_close_lifecycle_only_detail_failure_names_channel() raises:
    var c = _error_lc_run(
        _detail_failed(
            UInt64(3), String("ch1 lifecycle program count"))
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(
            c.session,
            String(
                "lifecycle detail unreadable: "
                "ch1 lifecycle program count"
            ),
        )
    )
    assert_true(
        not _contains(c.session, String("copy detail unreadable"))
    )


def test_error_close_count_shape_flip_zero_counters() raises:
    var c = _error_attempt_run(
        MissOut(True, UInt64(0), String("")),
        _detail_misses(
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        ),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"complete_for_scope",'
                '"loss_count":"0",'
            ),
        )
    )


def test_lifecycle_only_count_growth_keeps_attempt_loss() raises:
    # A count move with a stable attempt keeps exact attempt loss.
    var c = _one_lc_run(
        MissOut(True, UInt64(5), String(""), UInt64(2)),
        MissOut(True, UInt64(6), String(""), UInt64(2)),
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
                '"aggregate":{"status":"partial",'
                '"loss_count":"2",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 2 (recursion)"),
        )
    )


def test_error_close_lifecycle_only_count_growth_keeps_loss() raises:
    var c = _error_lc_run(
        MissOut(True, UInt64(5), String(""), UInt64(2)),
        MissOut(True, UInt64(6), String(""), UInt64(2)),
        True,
    )
    assert_equal(c.outcome, String("error"))
    assert_true(
        _contains(c.session, String("post-snapshot activity"))
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"aggregate":{"status":"partial",'
                '"loss_count":"2",'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String("attempt program runs skipped 2 (recursion)"),
        )
    )


def _detail_failed(attempt: UInt64, reason: String) raises -> MissOut:
    var m = MissOut(True, UInt64(0), String(""), attempt)
    m.detail_error = reason
    return m^


def test_wrapped_fallback_keeps_attempt_count() raises:
    # Wrapped fallback counters poison detail, not a read attempt count.
    var c = _one_copy_run(
        _detail_failed(
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
        _detail_failed(
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
        _detail_failed(
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
        _detail_failed(
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
        _detail_failed(
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


def test_collector_liveness_dead_copy_exit4() raises:
    # 200 maps over 3s with no copies: the session ends partial naming map->copy as silent.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(200):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(1000 + i),
                    attach + UInt64(i) * UInt64(15000000),
                    UInt64(4096), UInt64(1000 + i)))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        _zero_cut(), UInt64(0), duration_s=UInt64(3600))
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(c.session, String("hooks silent: map->copy"))
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
                '"copy_bytes":{"status":"partial",'
                '"reason":"capture ok, 0 copy events persisted; '
                'admitted under test-profile-1; v1 copy wire '
                'carries no mapping identity; liveness hooks silent"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"sync_requests":{"status":"partial",'
                '"reason":"capture ok, 0 sync_request events '
                'persisted; admitted under test-profile-1; v1 copy '
                'wire carries no mapping identity; '
                'liveness hooks silent"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"mapping_lifecycle":{"status":"partial",'
                '"reason":"capture ok, 200 map_result/unmap '
                'events persisted; admitted under '
                'test-profile-1; v2 wire reports opaque mapping '
                'generations when observed"'
            ),
        )
    )


def test_collector_liveness_healthy_verified() raises:
    # Matched copies verify with zero loss; exit stays 4 while terminal settlement is open.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(200):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(1000 + i),
                    attach + UInt64(i) * UInt64(15000000),
                    UInt64(4096), UInt64(1000 + i)))
    for i in range(200):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(2000 + i),
                    attach + UInt64(i) * UInt64(15000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200), duration_s=UInt64(3600))
    assert_equal(c.exit_code, 4)
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
        _contains(c.session, String("; liveness verified\""))
    )


def test_copy_only_session_partial() raises:
    # A copy-only session is never complete: lone copies stay unverified.
    var vals = _live_clock_values(UInt64(1000000000), False, True)
    var attach = _live_attach(vals, False, True)
    var payloads = List[List[UInt8]]()
    for i in range(50):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(3000 + i),
                    attach + UInt64(i) * UInt64(20000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(50), UInt64(204800), UInt64(50),
             UInt64(204800)), UInt64(50),
        has_lifecycle=False, has_copy=True)
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session,
            String("copy liveness unverified: lifecycle not captured"),
        )
    )


def test_copy_only_zero_records_unverified() raises:
    # No records at all still leaves the copy hooks unattributable.
    var vals = _live_clock_values(UInt64(1000000000), False, True)
    var payloads = List[List[UInt8]]()
    var c = _run_live(
        payloads^, vals^, _zero_cut(), _zero_cut(), UInt64(0),
        _zero_cut(), UInt64(0),
        has_lifecycle=False, has_copy=True)
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session,
            String("copy liveness unverified: lifecycle not captured"),
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )


def test_copy_only_syncs_without_copies_silent() raises:
    # Syncs with no copies prove the bounce hook dead, no lifecycle needed.
    var vals = _live_clock_values(UInt64(1000000000), False, True)
    var attach = _live_attach(vals, False, True)
    var payloads = List[List[UInt8]]()
    for i in range(30):
        payloads.append(
            _cp_raw(1, 1, 1, UInt64(3100 + i),
                    attach + UInt64(i) * UInt64(20000000),
                    UInt64(4096), UInt64(0), 4))
    var c = _run_live(
        payloads^, vals^, _zero_cut(), _zero_cut(), UInt64(0),
        _cut(UInt64(30), UInt64(122880), UInt64(30),
             UInt64(122880)), UInt64(30),
        has_lifecycle=False, has_copy=True)
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(c.session, String("hooks silent: map->copy"))
    )


def _detail_misses(
    bounce: UInt64, deferred: UInt64, recovered: UInt64
) -> MissOut:
    return MissOut(
        True, UInt64(0), String(""), UInt64(0), True, bounce,
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0),
        deferred, recovered)


def test_collector_liveness_submit_fail_absorbs_gap() raises:
    # Ring-full drops never emit, so they join the copy loss, never silence.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(100):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(7000 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(7000 + i)))
    for i in range(60):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(7100 + i),
                    attach + UInt64(i) * UInt64(50000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(UInt64(100), UInt64(409600), UInt64(60),
             UInt64(245760), submit_fail=UInt64(40)),
        UInt64(60), duration_s=UInt64(3600))
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(c.session, String("; liveness verified"))
    )


def test_collector_liveness_recursion_misses_absorb_gap() raises:
    # Skipped bounce runs never observe, so they join the copy loss too.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(100):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(7200 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(7200 + i)))
    for i in range(90):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(7300 + i),
                    attach + UInt64(i) * UInt64(33000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(UInt64(90), UInt64(368640), UInt64(90),
             UInt64(368640)), UInt64(90),
        duration_s=UInt64(3600),
        misses=_detail_misses(
            UInt64(10), UInt64(0), UInt64(0)))
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(c.session, String("; liveness verified"))
    )


def test_collector_liveness_deferred_absorbs_gap() raises:
    # Deferred-but-unrecovered entries never observe, so they join the loss.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(100):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(7400 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(7400 + i)))
    for i in range(90):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(7500 + i),
                    attach + UInt64(i) * UInt64(33000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(UInt64(90), UInt64(368640), UInt64(90),
             UInt64(368640)), UInt64(90),
        duration_s=UInt64(3600),
        misses=_detail_misses(
            UInt64(0), UInt64(10), UInt64(0)))
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(c.session, String("; liveness verified"))
    )


def test_collector_liveness_fallback_exact() raises:
    # Recovered entries never inflate the loss; over-recovery voids it.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(100):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(7600 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(7600 + i)))
    for i in range(90):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(7700 + i),
                    attach + UInt64(i) * UInt64(33000000),
                    UInt64(4096), UInt64(4096), 0))
    var even = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(UInt64(90), UInt64(368640), UInt64(90),
             UInt64(368640)), UInt64(90),
        duration_s=UInt64(3600),
        misses=_detail_misses(
            UInt64(0), UInt64(10), UInt64(10)))
    assert_equal(even.exit_code, 4)
    assert_true(
        _contains(even.session, String("hooks silent: map->copy"))
    )
    var vals2 = _live_clock_values(UInt64(1000000000), True, True)
    var attach2 = _live_attach(vals2, True, True)
    var payloads2 = List[List[UInt8]]()
    for i in range(100):
        payloads2.append(
            _lc_raw(1, 1, 1, UInt64(7800 + i),
                    attach2 + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(7800 + i)))
    for i in range(90):
        payloads2.append(
            _cp_raw(2, 3, 1, UInt64(7900 + i),
                    attach2 + UInt64(i) * UInt64(33000000),
                    UInt64(4096), UInt64(4096), 0))
    var contradict = _run_live(
        payloads2^, vals2^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(UInt64(90), UInt64(368640), UInt64(90),
             UInt64(368640)), UInt64(90),
        duration_s=UInt64(3600),
        misses=_detail_misses(
            UInt64(0), UInt64(0), UInt64(5)))
    assert_equal(contradict.exit_code, 4)
    assert_true(
        not _contains(contradict.session, String("hooks silent"))
    )
    assert_true(
        _contains(contradict.session, String("liveness unverified"))
    )


def _run_copy_liveness(
    n_cp: Int, cut_cp: UInt64, misses: MissOut
) raises -> CaseOut:
    # 100 lifecycle maps plus n_cp copies against a cut_cp copy cut.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(100):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(9100 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(9100 + i)))
    for i in range(n_cp):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(9300 + i),
                    attach + UInt64(i) * UInt64(30000000),
                    UInt64(4096), UInt64(4096), 0))
    return _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(100), UInt64(409600), UInt64(100),
             UInt64(409600)), UInt64(100),
        _cut(cut_cp, cut_cp * UInt64(4096), cut_cp,
             cut_cp * UInt64(4096)), cut_cp,
        duration_s=UInt64(3600),
        misses=misses.copy())


def test_collector_liveness_exit_recovered_misses_verify() raises:
    # E=10 D=0 R=10 with every copy emitted: the exit recovered
    # the entry-probe misses, so the copy loss is provably zero.
    var c = _run_copy_liveness(
        100, UInt64(100),
        _detail_misses(UInt64(10), UInt64(0), UInt64(10)))
    assert_equal(c.exit_code, 4)
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
        _contains(c.session, String("; liveness verified"))
    )
    assert_true(
        not _contains(c.session, String("liveness unverified"))
    )
    assert_true(not _contains(c.session, String("hooks silent")))


def test_collector_liveness_exit_recovered_misses_expose_gap() raises:
    # E=10 D=0 R=10 with 20 copies missing: the counters explain
    # nothing, so map->copy reads hooks silent with unknown loss.
    var c = _run_copy_liveness(
        80, UInt64(80),
        _detail_misses(UInt64(10), UInt64(0), UInt64(10)))
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session, String("hooks silent: map->copy (100 > 80)")
        )
    )
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":null,'),
        )
    )


def test_collector_liveness_partial_exit_recovery_charges_loss() raises:
    # E=10 D=0 R=6: four copies truly lost, charged as known loss.
    var c = _run_copy_liveness(
        96, UInt64(96),
        _detail_misses(UInt64(10), UInt64(0), UInt64(6)))
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session,
            String('"detail":{"status":"partial","loss_count":"4",'),
        )
    )
    assert_true(
        _contains(c.session, String("recursion_missed=(4)"))
    )
    assert_true(
        _contains(c.session, String("; liveness verified"))
    )
    assert_true(
        not _contains(c.session, String("liveness unverified"))
    )


def test_collector_liveness_unreadable_misses_unverified() raises:
    # Without the miss counters the gap is unprovable: unverified, not silent.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(200):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(8000 + i),
                    attach + UInt64(i) * UInt64(15000000),
                    UInt64(4096), UInt64(8000 + i)))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        _zero_cut(), UInt64(0), duration_s=UInt64(3600),
        misses=MissOut(False, UInt64(0), String("fdinfo gone")))
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(c.session, String("liveness unverified"))
    )


def test_collector_liveness_detail_error_unverified() raises:
    # A partial miss read splits no channel, so the gap stays unverified too.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(200):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(8100 + i),
                    attach + UInt64(i) * UInt64(15000000),
                    UInt64(4096), UInt64(8100 + i)))
    var bad = MissOut(True, UInt64(0), String(""))
    bad.detail_error = String("ch2 copy program count")
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        _zero_cut(), UInt64(0), duration_s=UInt64(3600),
        misses=bad.copy())
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(c.session, String("liveness unverified"))
    )


def test_collector_liveness_forward_only_suffixes_copy() raises:
    # Copies outside R verify only the copy channel; lifecycle stays bare.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var ready = attach + UInt64(100000000)
    var detach_begin = UInt64(21400000007)
    var payloads = List[List[UInt8]]()
    for i in range(50):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(9400 + i),
                    attach + UInt64(2000000000)
                    + UInt64(i) * UInt64(40000000),
                    UInt64(4096), UInt64(9400 + i)))
    for i in range(25):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(9500 + i),
                    ready + UInt64(25000000)
                    + UInt64(i) * UInt64(35000000),
                    UInt64(4096), UInt64(4096), 0))
    for i in range(25):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(9600 + i),
                    detach_begin - UInt64(25000000)
                    - UInt64(i) * UInt64(35000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(50), UInt64(204800), UInt64(50),
             UInt64(204800)), UInt64(50),
        _cut(UInt64(50), UInt64(204800), UInt64(50),
             UInt64(204800)), UInt64(50),
        duration_s=UInt64(3600))
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"detach_ns","interpretation":"21500000007"'
            ),
        )
    )
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(
            c.session,
            String(
                '"copy_bytes":{"status":"partial",'
                '"reason":"capture ok, 50 copy events persisted; '
                'admitted under test-profile-1; v1 copy wire '
                'carries no mapping identity; liveness verified"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"sync_requests":{"status":"partial",'
                '"reason":"capture ok, 0 sync_request events '
                'persisted; admitted under test-profile-1; v1 copy '
                'wire carries no mapping identity; '
                'liveness verified"'
            ),
        )
    )
    assert_true(
        _contains(
            c.session,
            String(
                '"mapping_lifecycle":{"status":"partial",'
                '"reason":"capture ok, 50 map_result/unmap '
                'events persisted; admitted under '
                'test-profile-1; v2 wire reports opaque mapping '
                'generations when observed"'
            ),
        )
    )


def test_collector_liveness_skipped_on_error_path() raises:
    # A torn run judges nothing: exercised windows stay out of the verdict.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(10):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(9700 + i),
                    attach + UInt64(i) * UInt64(10000000),
                    UInt64(4096), UInt64(9700 + i)))
    var bad = List[UInt8]()
    for i in range(37):
        bad.append(UInt8(0))
    payloads.append(bad^)
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(10), UInt64(40960), UInt64(10),
             UInt64(40960)), UInt64(10),
        _zero_cut(), UInt64(0), duration_s=UInt64(3600))
    assert_equal(c.exit_code, EXIT_ERROR)
    assert_equal(c.end_reason, String("error"))
    assert_equal(c.outcome, String("error"))
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(not _contains(c.session, String("liveness")))


def test_collector_liveness_busy_edges_clean() raises:
    # Guard-edge copies stay out of R while matched middle traffic verifies.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var ready = attach + UInt64(100000000)
    var detach_begin = UInt64(18000000007)
    var payloads = List[List[UInt8]]()
    for i in range(20):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(4000 + i),
                    attach + UInt64(2000000000)
                    + UInt64(i) * UInt64(100000000),
                    UInt64(4096), UInt64(4000 + i)))
    for i in range(20):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(4100 + i),
                    attach + UInt64(2000000000)
                    + UInt64(i) * UInt64(100000000),
                    UInt64(4096), UInt64(4096), 0))
    for i in range(20):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(4200 + i),
                    ready + UInt64(25000000)
                    + UInt64(i) * UInt64(50000000),
                    UInt64(4096), UInt64(4096), 0))
    for i in range(23):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(4300 + i),
                    detach_begin - UInt64(25000000)
                    - UInt64(i) * UInt64(42000000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(20), UInt64(81920), UInt64(20),
             UInt64(81920)), UInt64(20),
        _cut(UInt64(63), UInt64(257856), UInt64(63),
             UInt64(257856)), UInt64(63),
        duration_s=UInt64(3600))
    assert_equal(c.exit_code, 4)
    assert_true(
        _contains(
            c.session,
            String(
                '"source":"detach_ns","interpretation":"18100000007"'
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
    assert_true(not _contains(c.session, String("hooks silent")))
    assert_true(
        _contains(
            c.session,
            String(
                '"mapping_lifecycle":{"status":"partial",'
                '"reason":"capture ok, 20 map_result/unmap '
                'events persisted; admitted under '
                'test-profile-1; v2 wire reports opaque mapping '
                'generations when observed; liveness verified"'
            ),
        )
    )


def test_collector_liveness_size_limit_latch() raises:
    # 200+200 records latch the 128KiB budget with room to drain; stranded batches stay inside the loss so the forward equation stays quiet.
    var vals = _live_clock_values(UInt64(1000000000), True, True)
    var attach = _live_attach(vals, True, True)
    var payloads = List[List[UInt8]]()
    for i in range(200):
        payloads.append(
            _lc_raw(1, 1, 1, UInt64(5000 + i),
                    attach + UInt64(i) * UInt64(2500000),
                    UInt64(4096), UInt64(5000 + i)))
    for i in range(200):
        payloads.append(
            _cp_raw(2, 3, 1, UInt64(6000 + i),
                    attach + UInt64(1000000000) + UInt64(i) * UInt64(2500000),
                    UInt64(4096), UInt64(4096), 0))
    var c = _run_live(
        payloads^, vals^, _zero_cut(),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        _cut(UInt64(200), UInt64(819200), UInt64(200),
             UInt64(819200)), UInt64(200),
        max_events_bytes=131072, duration_s=UInt64(3600))
    assert_equal(c.end_reason, String("size_limit"))
    assert_equal(c.exit_code, 4)
    assert_true(not _contains(c.session, String("hooks silent")))


def test_scripted_old_ktimes_byte_identical() raises:
    # Pre-attach ktimes never enter a window: this nested-copy scenario replays byte-identical with liveness on.
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
        UInt64(2), read_files=True)
    assert_equal(c.events, _golden_events())
    assert_equal(_mask_output_fs(c.session), _mask_output_fs(_golden_session()))


def _mask_output_fs(session: String) raises -> String:
    # The output filesystem is the test host's, not part of the replay.
    var key = String('\"source\":\"output.fs\",\"interpretation\":\"').as_bytes()
    var b = session.as_bytes()
    var i = 0
    while i + len(key) <= len(b):
        var j = 0
        while j < len(key) and b[i + j] == key[j]:
            j += 1
        if j == len(key):
            var end = i + len(key)
            while end < len(b) and b[end] != UInt8(0x22):
                end += 1
            return (
                String(from_utf8=b[0 : i + len(key)])
                + String("FS")
                + String(from_utf8=b[end : len(b)])
            )
        i += 1
    raise Error("session has no output.fs provenance")


def _golden_events() -> String:
    return String(
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"0\",\"ts_ns\":\"1001\",\"kind\":\"copy\",\"source\":{\"h'
        'ook\":\"fentry:swiotlb_bounce\",\"backend\":\"tracing\",\"profile_id\":\"test-profile-1\",\"measurement\":\"observ'
        'ed\",\"correlation\":\"unpaired\"},\"data\":{\"operation_id\":\"lc-101\",\"mapping_id\":null,\"direction\":\"origina'
        'l_to_bounce\",\"bytes\":\"4096\"}}'
        '\n'
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"1\",\"ts_ns\":\"1002\",\"kind\":\"copy\",\"source\":{\"h'
        'ook\":\"fentry:swiotlb_bounce\",\"backend\":\"tracing\",\"profile_id\":\"test-profile-1\",\"measurement\":\"observ'
        'ed\",\"correlation\":\"unpaired\"},\"data\":{\"operation_id\":\"lc-102\",\"mapping_id\":null,\"direction\":\"origina'
        'l_to_bounce\",\"bytes\":\"1024\"}}'
        '\n'
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"2\",\"ts_ns\":\"2000000\",\"kind\":\"counter_snapsho'
        't\",\"source\":{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\"profile_id\":\"test-profile-1\",\"'
        'measurement\":\"observed\",\"correlation\":\"direct\"},\"data\":{\"counter_id\":\"swiotlb.bounce_attempts\",\"epoc'
        'h\":\"0\",\"scope\":{\"profile_id\":\"test-profile-1\"},\"value\":\"0\",\"unit\":\"count\"}}'
        '\n'
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"3\",\"ts_ns\":\"2000000\",\"kind\":\"counter_snapsho'
        't\",\"source\":{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\"profile_id\":\"test-profile-1\",\"'
        'measurement\":\"observed\",\"correlation\":\"direct\"},\"data\":{\"counter_id\":\"swiotlb.requested_bytes\",\"epoc'
        'h\":\"0\",\"scope\":{\"profile_id\":\"test-profile-1\"},\"value\":\"0\",\"unit\":\"bytes\"}}'
        '\n'
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"4\",\"ts_ns\":\"121000000\",\"kind\":\"counter_snaps'
        'hot\",\"source\":{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\"profile_id\":\"test-profile-1\"'
        ',\"measurement\":\"observed\",\"correlation\":\"direct\"},\"data\":{\"counter_id\":\"swiotlb.bounce_attempts\",\"ep'
        'och\":\"0\",\"scope\":{\"profile_id\":\"test-profile-1\"},\"value\":\"0\",\"unit\":\"count\"}}'
        '\n'
        '{\"schema_version\":\"0.1.1\",\"session_id\":\"cap-0-7\",\"seq\":\"5\",\"ts_ns\":\"121000000\",\"kind\":\"counter_snaps'
        'hot\",\"source\":{\"hook\":\"swiotlb:swiotlb_bounced\",\"backend\":\"tracepoint\",\"profile_id\":\"test-profile-1\"'
        ',\"measurement\":\"observed\",\"correlation\":\"direct\"},\"data\":{\"counter_id\":\"swiotlb.requested_bytes\",\"ep'
        'och\":\"0\",\"scope\":{\"profile_id\":\"test-profile-1\"},\"value\":\"0\",\"unit\":\"bytes\"}}'
        '\n'
    )

def _golden_session() -> String:
    return String(
        '{\"schema_version\":\"0.1.2\",\"session_id\":\"cap-0-7\",\"synthetic\":false,\"product\":{\"name\":\"memveil\",\"vers'
        'ion\":\"memveil-0.1.0\"},\"environment\":{\"mode\":\"unknown\",\"detection\":\"unverified\",\"attestation\":\"not_pe'
        'rformed\",\"evidence\":[{\"type\":\"provenance\",\"source\":\"attach_ns\",\"interpretation\":\"7000000\"},{\"type\":\"'
        'provenance\",\"source\":\"detach_ns\",\"interpretation\":\"16000000\"},{\"type\":\"provenance\",\"source\":\"drain_c'
        'losure\",\"interpretation\":\"proven\"},{\"type\":\"provenance\",\"source\":\"measurement_scope\",\"interpretation'
        '\":\"ordinals below observed at the end cut\"},{\"type\":\"provenance\",\"source\":\"output.fs\",\"interpretatio'
        'n\":\"btrfs\"}]},\"capture\":{\"mode\":\"live\",\"window\":{\"start_ns\":\"7000000\",\"end_ns\":\"127000001\",\"baseline'
        '_start_ns\":\"2000000\"},\"filters\":{},\"finalized\":true,\"end_reason\":\"signal\"},\"device_catalog\":{\"device'
        's\":[]},\"baseline\":{\"complete\":false,\"region_observations\":[]},\"capabilities\":{\"bounce_attempts\":{\"st'
        'atus\":\"partial\",\"reason\":\"capture ok, 0 attempts persisted; admitted under test-profile-1; device de'
        'tail grouped by observed name scope\",\"hooks\":[\"swiotlb:swiotlb_bounced\"],\"profile_id\":\"test-profile-'
        '1\"},\"mapping_lifecycle\":{\"status\":\"partial\",\"reason\":\"capture ok, 0 map_result/unmap events persiste'
        'd; admitted under test-profile-1; v2 wire reports opaque mapping generations when observed\",\"hooks\":'
        '[\"fexit:swiotlb_tbl_map_single\",\"fentry:__swiotlb_tbl_unmap_single\"],\"profile_id\":\"test-profile-1\"},'
        '\"copy_bytes\":{\"status\":\"partial\",\"reason\":\"capture ok, 2 copy events persisted; admitted under test-'
        'profile-1; v1 copy wire carries no mapping identity\",\"hooks\":[\"fentry:swiotlb_bounce\"],\"profile_id\":'
        '\"test-profile-1\"},\"sync_requests\":{\"status\":\"partial\",\"reason\":\"capture ok, 0 sync_request events pe'
        'rsisted; admitted under test-profile-1; v1 copy wire carries no mapping identity\",\"hooks\":[\"fentry:_'
        '_swiotlb_sync_single_for_device\",\"fentry:__swiotlb_sync_single_for_cpu\"],\"profile_id\":\"test-profile-'
        '1\"},\"conversion_results\":{\"status\":\"unavailable\",\"reason\":\"No conversion source in this capture.\",\"h'
        'ooks\":[]},\"region_state\":{\"status\":\"unavailable\",\"reason\":\"No region source in this capture.\",\"hooks'
        '\":[]},\"pool_stats\":{\"status\":\"unavailable\",\"reason\":\"No pool source in this capture.\",\"hooks\":[]},\"t'
        'ask_context\":{\"status\":\"unavailable\",\"reason\":\"No observer context in this capture.\",\"hooks\":[]}},\"q'
        'uality\":{\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",\"scope\":\"0 bounce_attempt + 0 map_'
        'result/unmap + 2 copy/sync_request events\",\"reason\":\"detail loss 0 (submit_fail=(0) malformed=(0) dr'
        'opped=(0) recursion_missed=(0) size_omitted=(0) duration_omitted=(0) signal_omitted=(0) rejected=(0)'
        ' write_failed=(0))\",\"evidence_refs\":[]},\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",'
        '\"scope\":\"counter snapshots (attempt channel) attached [8000000,15000000)\",\"reason\":\"counter snapshots present (valid cut, identi'
        'ty holds, coverage valid)\",\"evidence_refs\":[]},\"correlation\":{\"status\":\"partial\",\"loss_count\":null,\"'
        'scope\":\"correlated lifecycle events\",\"reason\":\"copy_attribution partial (copy without pending operat'
        'ion)\",\"evidence_refs\":[\"capture:seq=0\",\"capture:seq=1\"],\"relations\":{\"mapping_release\":{\"status\":\"co'
        'mplete_for_scope\",\"loss_count\":\"0\",\"scope\":\"mapping and release pairing\",\"reason\":\"all mapping and r'
        'elease relationships paired\",\"evidence_refs\":[]},\"copy_attribution\":{\"status\":\"partial\",\"loss_count\"'
        ':null,\"scope\":\"copy attribution\",\"reason\":\"copy without pending operation\",\"evidence_refs\":[\"capture'
        ':seq=0\",\"capture:seq=1\"]},\"sync_attribution\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",\"scope\"'
        ':\"sync attribution\",\"reason\":\"all sync attribution relationships paired\",\"evidence_refs\":[]}}},\"base'
        'line\":{\"status\":\"not_applicable\",\"loss_count\":null,\"scope\":\"attempt metrics\",\"reason\":\"Attempt metri'
        'cs need no baseline.\",\"evidence_refs\":[]},\"terminal\":{\"status\":\"partial\",\"loss_count\":null,\"scope\":\"'
        'capture finalization\",\"reason\":\"stop partial: quiescence unproven\",\"evidence_refs\":[]}},\"stop\":{\"out'
        'come\":\"partial\",\"reason\":\"quiescence unproven\",\"budget_ms\":\"5000\",\"elapsed_ms\":\"110\",\"admission_clos'
        'ed\":true,\"quiescence_observed\":false,\"writers_settled\":\"0\",\"in_flight_at_close\":\"0\",\"late_submits_dr'
        'ained\":\"0\",\"drained_records\":\"0\",\"busy_at_drain\":false,\"counters_valid\":true,\"open_mappings\":\"0\"}}'
    )

def _parse_attached_interval(scope: String) raises -> Tuple[UInt64, UInt64]:
    """Parse the D31 attached [A,B) claim from an aggregate scope."""
    var raw = scope.as_bytes()
    var mark = String("attached [").as_bytes()
    var at = -1
    var i = 0
    while i + len(mark) <= len(raw):
        var j = 0
        while j < len(mark) and raw[i + j] == mark[j]:
            j += 1
        if j == len(mark):
            at = i + len(mark)
            break
        i += 1
    if at < 0:
        raise Error("scope lacks attached interval")
    var a = UInt64(0)
    var k = at
    while k < len(raw) and raw[k] != UInt8(0x2C):
        var b = raw[k]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise Error("attached start not decimal")
        a = a * UInt64(10) + UInt64(Int(b) - 0x30)
        k += 1
    if k >= len(raw):
        raise Error("attached interval lacks comma")
    k += 1
    var c = UInt64(0)
    while k < len(raw) and raw[k] != UInt8(0x29):
        var b = raw[k]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise Error("attached end not decimal")
        c = c * UInt64(10) + UInt64(Int(b) - 0x30)
        k += 1
    return (a, c)


def _last_snapshot_ts(events: String) raises -> UInt64:
    """Max ts_ns over counter_snapshot lines."""
    var best = UInt64(0)
    var seen = False
    var key = String('"ts_ns":"').as_bytes()
    for line in _lines(events):
        if not _contains(line, String('"kind":"counter_snapshot"')):
            continue
        var raw = line.as_bytes()
        var at = -1
        var i = 0
        while i + len(key) <= len(raw):
            var j = 0
            while j < len(key) and raw[i + j] == key[j]:
                j += 1
            if j == len(key):
                at = i + len(key)
                break
            i += 1
        if at < 0:
            raise Error("snapshot lacks ts_ns")
        var ts = UInt64(0)
        var k = at
        while k < len(raw) and raw[k] != UInt8(0x22):
            var b = raw[k]
            if b < UInt8(0x30) or b > UInt8(0x39):
                raise Error("snapshot ts not decimal")
            ts = ts * UInt64(10) + UInt64(Int(b) - 0x30)
            k += 1
        if not seen or ts > best:
            best = ts
        seen = True
    if not seen:
        raise Error("no counter snapshots")
    return best


def test_aggregate_scope_claims_attached_interval() raises:
    # D31: the aggregate claim is scoped to the attempt hook's
    # attached interval, not the reading pair; the readings
    # extend past detach while the claim does not.
    var c = _one_copy_run(MissOut(True, UInt64(0), String("")))
    var s = parse_session(_session_bytes(c.session))
    var iv = _parse_attached_interval(s.q_aggregate.scope)
    assert_true(s.window_start_ns <= iv[0])
    assert_true(iv[0] < iv[1])
    assert_true(iv[1] <= s.window_end_ns)
    assert_true(iv[1] < _last_snapshot_ts(c.events))


def test_attempt_loss_lower_bound_caps_detail_partial() raises:
    # D34: on a pre-6.7 kernel the detail claim is capped at
    # partial with the lower-bound label; the known count
    # stays as the lower bound, and the aggregate matches.
    var c = _one_copy_run(
        MissOut(True, UInt64(0), String("")), lower_bound=True
    )
    var s = parse_session(_session_bytes(c.session))
    assert_equal(s.q_detail.status, String("partial"))
    assert_true(s.q_detail.has_loss_count)
    assert_equal(s.q_detail.loss_count, UInt64(0))
    assert_true(
        _contains(
            s.q_detail.reason,
            String(
                "attempt loss counts are a lower bound before 6.7"
            ),
        )
    )
    assert_equal(s.q_aggregate.status, String("partial"))
    assert_true(s.q_aggregate.has_loss_count)
    assert_equal(s.q_aggregate.loss_count, UInt64(0))
    assert_true(
        _contains(
            s.q_aggregate.reason,
            String(
                "attempt loss counts are a lower bound before 6.7"
            ),
        )
    )


def test_aggregate_missing_stamp_yields_partial() raises:
    # D31: without both attached-interval stamps the aggregate
    # is partial, never complete_for_scope.
    var cfg = CollectorConfig()
    cfg.profile_id = String("test-profile-1")
    cfg.pid = 7
    var collector = Collector(cfg)
    collector.snapshots_present = True
    collector.attempt_known = True
    var s = collector.assemble()
    assert_equal(s.q_aggregate.status, String("partial"))
    assert_true(not s.q_aggregate.has_loss_count)
    assert_true(
        _contains(s.q_aggregate.reason, String("attached interval"))
    )
    # Positive control: ordered stamps restore complete.
    collector.attempt_attach_done_ns = UInt64(100)
    collector.attempt_detach_begin_ns = UInt64(200)
    var s2 = collector.assemble()
    assert_equal(s2.q_aggregate.status, String("complete_for_scope"))
    assert_true(s2.q_aggregate.has_loss_count)
    assert_equal(s2.q_aggregate.loss_count, UInt64(0))
    var iv = _parse_attached_interval(s2.q_aggregate.scope)
    assert_equal(iv[0], UInt64(100))
    assert_equal(iv[1], UInt64(200))


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
