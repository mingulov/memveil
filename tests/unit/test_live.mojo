# SPDX-License-Identifier: GPL-3.0-or-later

"""LiveWriter adapter and tee refresh rules: real files on mkdtemp scratch dirs."""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.engine import Analyzer
from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    PollOut,
)
from memveil.capture.live import (
    LiveWriter,
    _residual_tail,
    _strip_residual_tail,
)
from memveil.capture.tee import RefreshSink, TeeWriter
from memveil.model.encode import encode_event_line
from memveil.model.event import Event, parse_event
from memveil.model.report import Report
from memveil.model.session import Session
from memveil.model.validate import format_u64
from memveil.platform.reader import read_host_file
from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    snap_ok,
    stats_ok,
)


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-live-XXXXXX")
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


def _line(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0x0A))
    return out^


def test_lifecycle() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = LiveWriter()
    assert_equal(w.committed_len(), 0)
    var made = w.create(target, 131072)
    assert_true(made.ok)
    var a1 = w.append(_line(String("a")))
    assert_true(a1.ok)
    assert_equal(w.committed_len(), 2)
    var mark = w.group_begin()
    assert_true(mark.ok)
    var a2 = w.append(_line(String("bbb")))
    assert_true(a2.ok)
    assert_equal(w.committed_len(), 6)
    var ab = w.group_abort(mark.mark)
    assert_true(ab.ok)
    assert_equal(w.committed_len(), 2)
    var fin = w.finalize(_line(String("{}")))
    assert_equal(fin.status, String("finalized"))
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(len(events), 2)
    assert_equal(events[0], UInt8(0x61))
    var session = read_host_file(
        target + String("/session.json"), String("session"), 1048576
    )
    assert_equal(len(session), 3)
    # Finalize consumes the slot.
    var fin2 = w.finalize(_line(String("{}")))
    assert_equal(fin2.status, String("unfinalized"))


def test_misuse_before_create() raises:
    var w = LiveWriter()
    assert_true(not w.append(_line(String("x"))).ok)
    assert_true(not w.append_closing(_line(String("x"))).ok)
    assert_true(not w.group_begin().ok)
    assert_true(not w.group_abort(0).ok)
    assert_equal(
        w.finalize(_line(String("{}"))).status, String("unfinalized")
    )


def test_empty_abandon_succeeds() raises:
    # Idempotent cleanup: abandoning a never-created writer
    # reports no residual (the normal pre-create startup
    # refusal path), matching discard and the scripted
    # writers.
    var w = LiveWriter()
    assert_equal(w.abandon(), String(""))


def test_residual_tail() raises:
    assert_equal(
        _residual_tail(String("fstat failed: errno 5")),
        String(""),
    )
    assert_equal(
        _residual_tail(
            String("fstat failed: errno 5; residuals: events,dir")
        ),
        String("events,dir"),
    )
    assert_equal(
        _residual_tail(String("x; residuals: events")),
        String("events"),
    )


def test_strip_residual_tail() raises:
    assert_equal(
        _strip_residual_tail(String("fstat failed: errno 5")),
        String("fstat failed: errno 5"),
    )
    assert_equal(
        _strip_residual_tail(
            String("fstat failed: errno 5; residuals: events,dir")
        ),
        String("fstat failed: errno 5"),
    )
    assert_equal(
        _strip_residual_tail(String("x; residuals: events")),
        String("x"),
    )


def test_create_guards() raises:
    var scratch = _mkdtemp()
    var w = LiveWriter()
    var twice = scratch + String("/twice")
    assert_true(w.create(twice, 131072).ok)
    var again = w.create(scratch + String("/other"), 131072)
    assert_true(not again.ok)
    assert_equal(again.kind, String("misuse"))
    var w2 = LiveWriter()
    var small = w2.create(scratch + String("/small"), 1024)
    assert_true(not small.ok)
    assert_equal(small.kind, String("budget"))
    var w3 = LiveWriter()
    var exists = w3.create(twice, 131072)
    assert_true(not exists.ok)
    assert_equal(exists.kind, String("exists"))


def test_abandon_and_discard() raises:
    var scratch = _mkdtemp()
    var w = LiveWriter()
    var gone = scratch + String("/gone")
    assert_true(w.create(gone, 131072).ok)
    assert_true(w.append(_line(String("x"))).ok)
    var note = w.abandon()
    assert_equal(note, String(""))
    var w2 = LiveWriter()
    # Abandon removed the directory: recreating works.
    assert_true(w2.create(gone, 131072).ok)
    var keep = scratch + String("/keep")
    var w3 = LiveWriter()
    assert_true(w3.create(keep, 131072).ok)
    assert_true(w3.append(_line(String("y"))).ok)
    w3.discard()
    var events = read_host_file(
        keep + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(len(events), 2)
    var failed = False
    try:
        _ = read_host_file(
            keep + String("/session.json"), String("session"), 1048576
        )
    except:
        failed = True
    assert_true(failed)


def _append_text(path: String, text: String) -> Bool:
    """Append text to path (create when missing); False on any error."""
    var cpath = List[UInt8]()
    for b in path.as_bytes():
        if b == UInt8(0):
            return False
        cpath.append(b)
    cpath.append(UInt8(0))
    var fd = external_call["open", Int32](
        Span(cpath).unsafe_ptr(), Int32(1089), UInt32(420)
    )
    if fd < Int32(0):
        return False
    var raw = text.as_bytes()
    var total = len(raw)
    var off = 0
    while off < total:
        var n = external_call["write", Int](
            Int(fd),
            Span(raw).unsafe_ptr().unsafe_offset(off),
            total - off,
        )
        if n <= 0:
            if n < 0:
                var p = external_call[
                    "__errno_location", Pointer[Int32, MutAnyOrigin]
                ]()
                if Int(p.unsafe_load()) == 4:
                    continue
            _ = external_call["close", Int32](fd)
            return False
        off += n
    _ = external_call["close", Int32](fd)
    return True


struct ScriptFileSink(RefreshSink):
    """RefreshSink that records horizon plus row digest per line."""

    var _path: String

    def __init__(out self, path: String):
        self._path = path.copy()

    def emit(mut self, var rep: Report, horizon_ns: UInt64) -> Bool:
        var record = (
            format_u64(horizon_ns)
            + String(" ")
            + _tee_digest(rep)
            + String("\n")
        )
        return _append_text(self._path, record)


struct RefuseOnceSink(RefreshSink):
    """Records refreshes but refuses the first emission."""

    var _path: String
    var _refused: Bool

    def __init__(out self, path: String):
        self._path = path.copy()
        self._refused = False

    def emit(mut self, var rep: Report, horizon_ns: UInt64) -> Bool:
        if not self._refused:
            self._refused = True
            _ = rep^
            return False
        var record = (
            format_u64(horizon_ns)
            + String(" ")
            + _tee_digest(rep)
            + String("\n")
        )
        return _append_text(self._path, record)


def _tee_base(kind: String, seq: UInt64, ts: UInt64) -> Event:
    var ev = Event()
    ev.session_id = String("teeprobe")
    ev.seq = seq
    ev.ts_ns = ts
    ev.kind = kind
    ev.source_hook = String("h")
    ev.source_backend = String("test")
    ev.source_profile_id = String("p1")
    ev.source_measurement = String("observed")
    ev.source_correlation = String("direct")
    return ev^


def _tee_attempt(op: String, seq: UInt64, ts: UInt64) -> Event:
    var ev = _tee_base(String("bounce_attempt"), seq, ts)
    ev.bounce.device_id = String("d1")
    ev.bounce.requested_bytes = UInt64(4096)
    ev.bounce.forced = False
    ev.bounce.operation_id = op
    return ev^


def _tee_line(ev: Event) raises -> List[UInt8]:
    var out = encode_event_line(ev)
    return out^


def _tee_map(op: String, mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _tee_base(String("map_result"), seq, ts)
    ev.map_result.operation_id = op
    ev.map_result.success = True
    ev.map_result.has_mapping_id = True
    ev.map_result.mapping_id = mapping
    ev.map_result.has_mapped_bytes = True
    ev.map_result.mapped_bytes = UInt64(4096)
    return ev^


def _tee_copy(op: String, n: UInt64, ts: UInt64, seq: UInt64) -> Event:
    var ev = _tee_base(String("copy"), seq, ts)
    ev.copy.operation_id = op
    ev.copy.direction = String("original_to_bounce")
    ev.copy.bytes = n
    return ev^


def _tee_unmap(mapping: String, ts: UInt64, seq: UInt64) -> Event:
    var ev = _tee_base(String("unmap"), seq, ts)
    ev.unmap.has_mapping_id = True
    ev.unmap.mapping_id = mapping
    return ev^


def _tee_pool_unavailable(
    pool: String, ts: UInt64, seq: UInt64, reason: String
) -> Event:
    var ev = _tee_base(String("pool_sample"), seq, ts)
    ev.pool.pool_id = pool
    ev.pool.unit = String("bytes")
    ev.pool.allocator = String("swiotlb")
    ev.pool.reason = reason
    return ev^


def _tee_gap(ts: UInt64, seq: UInt64) -> Event:
    var ev = _tee_base(String("gap"), seq, ts)
    ev.gap.channel = String("detail")
    ev.gap.has_lost_count = True
    ev.gap.lost_count = UInt64(3)
    ev.gap.reason = String("scripted cut")
    ev.gap.window_start_ns = UInt64(100)
    ev.gap.window_end_ns = ts
    return ev^


def _tee_pool(
    pool: String, used: UInt64, cap: UInt64, ts: UInt64, seq: UInt64
) -> Event:
    var ev = _tee_base(String("pool_sample"), seq, ts)
    ev.pool.pool_id = pool
    ev.pool.has_used = True
    ev.pool.used_bytes = used
    ev.pool.has_capacity = True
    ev.pool.capacity_bytes = cap
    ev.pool.unit = String("bytes")
    return ev^


def _tee_template() -> Session:
    """Provisional live session: the tee stamps the window."""
    var s = Session()
    s.session_id = String("teeprobe")
    s.synthetic = True
    s.product_version = String("0.0.0")
    s.env_mode = String("unknown")
    s.env_detection = String("unverified")
    s.env_attestation = String("not_performed")
    s.capture_mode = String("live")
    s.window_start_ns = UInt64(0)
    s.window_end_ns = ~UInt64(0)
    s.finalized = False
    s.q_detail.status = String("complete_for_scope")
    s.q_detail.has_loss_count = True
    s.q_detail.loss_count = UInt64(0)
    s.q_detail.scope = String("sc")
    s.q_detail.reason = String("rs")
    s.q_aggregate.status = String("complete_for_scope")
    s.q_aggregate.has_loss_count = True
    s.q_aggregate.loss_count = UInt64(0)
    s.q_aggregate.scope = String("sc")
    s.q_aggregate.reason = String("rs")
    s.q_correlation.status = String("complete_for_scope")
    s.q_correlation.has_loss_count = True
    s.q_correlation.loss_count = UInt64(0)
    s.q_correlation.scope = String("sc")
    s.q_correlation.reason = String("rs")
    s.q_baseline.status = String("not_applicable")
    s.q_baseline.scope = String("sc")
    s.q_baseline.reason = String("rs")
    s.q_terminal.status = String("complete_for_scope")
    s.q_terminal.scope = String("sc")
    s.q_terminal.reason = String("rs")
    return s^


def _tee_stripped(line: List[UInt8]) -> List[UInt8]:
    """Copy line minus one trailing newline, matching the reader."""
    var out = List[UInt8]()
    var n = len(line)
    if n > 0 and line[n - 1] == UInt8(0x0A):
        n -= 1
    for i in range(n):
        out.append(line[i])
    return out^


def _tee_digest(rep: Report) -> String:
    """Row scopes, values, notes, and quality in one string."""
    var d = String("")
    for i in range(len(rep.metrics)):
        var m = rep.metrics[i]
        d += m.name + String("|") + m.scope + String("|") + m.unit
        d += String("=")
        if m.has_value:
            d += format_u64(m.value)
        else:
            d += String("?")
        d += String(";")
    d += String("notes:")
    for i in range(len(rep.limitations)):
        d += rep.limitations[i] + String("|")
    d += String("q:")
    d += rep.q_detail.status + String(",")
    d += rep.q_aggregate.status + String(",")
    d += rep.q_correlation.status + String(",")
    d += rep.q_baseline.status + String(",")
    d += rep.q_terminal.status
    return d^


def _tee_direct(
    template: Session,
    first_ts: UInt64,
    lines: List[List[UInt8]],
    horizon: UInt64,
) raises -> String:
    """Digest of folding lines directly: the replay oracle."""
    var s = template.copy()
    s.window_start_ns = first_ts
    s.window_end_ns = ~UInt64(0)
    var a = Analyzer(s)
    for i in range(len(lines)):
        var body = _tee_stripped(lines[i])
        var ev = parse_event(body)
        a.consume(ev)
    var rep = a.snapshot(horizon, False)
    return _tee_digest(rep)


def _tee_text(data: List[UInt8]) raises -> String:
    try:
        return String(from_utf8=Span(data))
    except:
        raise Error("tee bytes not UTF-8")


def _tee_new(obs: String) -> TeeWriter[ScriptFileSink]:
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    return tee^


def test_tee_forwards_bytes_identical() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var obs = scratch + String("/obs.ndjson")
    var tee = _tee_new(obs)
    assert_true(tee.create(target, 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(120)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.committed_len(), len(l0) + len(l1) + len(l2))
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    var want = _tee_text(l0) + _tee_text(l1) + _tee_text(l2)
    assert_equal(_tee_text(events), want)


def test_tee_misuse_before_create() raises:
    var scratch = _mkdtemp()
    var tee = _tee_new(scratch + String("/obs.ndjson"))
    var line = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    assert_true(not tee.append(line).ok)
    assert_true(not tee.append_closing(line).ok)
    assert_true(not tee.group_begin().ok)
    assert_true(not tee.group_abort(0).ok)
    assert_equal(
        tee.finalize(_line(String("{}"))).status, String("unfinalized")
    )
    # Nothing folded, nothing emitted: creating now starts clean.
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    assert_equal(tee.committed_len(), 0)


def test_tee_first_data_establishes_silently() raises:
    # The first event only establishes the window: no empty
    # [T, T) refresh is ever printed.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var line = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    assert_true(tee.append(line).ok)
    assert_equal(tee.emission_count(), 0)
    var missing = False
    try:
        _ = read_host_file(obs, String("obs"), 1048576)
    except:
        missing = True
    assert_true(missing)


def test_tee_interval_gates_refresh() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(120)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 1)
    # The refresh at 200 covers [100, 200): the boundary
    # event folds after the snapshot.
    var covered = List[List[UInt8]]()
    covered.append(l0.copy())
    covered.append(l1.copy())
    var want = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), covered, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_decode_failure_is_loud() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var obs = scratch + String("/obs.ndjson")
    var tee = _tee_new(obs)
    assert_true(tee.create(target, 131072).ok)
    var bad = _line(String("not json{"))
    var out = tee.append(bad)
    assert_true(not out.ok)
    assert_equal(out.kind, String("internal"))
    # Atomic: the unfolded line is rolled back, so the
    # retained file stays replayable (replay raises on a
    # corrupt line; keeping it would poison the final).
    assert_equal(tee.committed_len(), 0)
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(_tee_text(events), String(""))
    var missing = False
    try:
        _ = read_host_file(obs, String("obs"), 1048576)
    except:
        missing = True
    assert_true(missing)


def test_tee_sink_failure_is_loud() raises:
    # The establishing event never touches the sink; the
    # first due refresh surfaces the refusal loudly.
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var tee = _tee_new(scratch + String("/no-such-dir/obs.ndjson"))
    assert_true(tee.create(target, 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    assert_true(tee.append(l0).ok)
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(200)))
    var out = tee.append(l1)
    assert_true(not out.ok)
    assert_equal(out.kind, String("internal"))
    # Atomic: the unfolded line is rolled back, so later
    # refreshes still match a replay of the retained file.
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(_tee_text(events), _tee_text(l0))


def test_tee_disorder_folds_forward_only() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(60)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(160)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    # Below the stamped floor: refolded with the floor
    # lowered, never counted below the window.
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 1)
    var covered = List[List[UInt8]]()
    covered.append(l0.copy())
    covered.append(l1.copy())
    var want = (
        format_u64(UInt64(160))
        + String(" ")
        + _tee_direct(tmpl, UInt64(60), covered, UInt64(160))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_same_reducer_mixed_kinds() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_map("op1", "m1", UInt64(110), UInt64(1)))
    var l2 = _tee_line(_tee_copy("op1", UInt64(4096), UInt64(120), UInt64(2)))
    var l3 = _tee_line(_tee_unmap("m1", UInt64(130), UInt64(3)))
    var l4 = _tee_line(
        _tee_pool("p", UInt64(10), UInt64(100), UInt64(140), UInt64(4))
    )
    var l5 = _tee_line(_tee_attempt("op2", UInt64(5), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    assert_true(tee.append(l2).ok)
    assert_true(tee.append(l3).ok)
    assert_true(tee.append(l4).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l5).ok)
    assert_equal(tee.emission_count(), 1)
    var covered = List[List[UInt8]]()
    covered.append(l0.copy())
    covered.append(l1.copy())
    covered.append(l2.copy())
    covered.append(l3.copy())
    covered.append(l4.copy())
    var want = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), covered, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_closing_lines_fold() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append_closing(l1).ok)
    assert_equal(tee.emission_count(), 1)
    var first = List[List[UInt8]]()
    first.append(l0.copy())
    var want = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), first, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_group_abort_rebuilds_prefix() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(target, 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(120)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(200)))
    var l3 = _tee_line(_tee_attempt("op4", UInt64(3), UInt64(260)))
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    var begun = tee.group_begin()
    assert_true(begun.ok)
    assert_true(tee.append(l2).ok)
    assert_true(tee.group_abort(begun.mark).ok)
    assert_true(tee.append(l3).ok)
    assert_equal(tee.emission_count(), 2)
    # The aborted refresh stands as printed; both refreshes
    # exclude their boundary event.
    var pre_abort = List[List[UInt8]]()
    pre_abort.append(l0.copy())
    pre_abort.append(l1.copy())
    var rec0 = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), pre_abort, UInt64(200))
        + String("\n")
    )
    var kept = List[List[UInt8]]()
    kept.append(l0.copy())
    kept.append(l1.copy())
    var rec1 = (
        format_u64(UInt64(260))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), kept, UInt64(260))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), rec0 + rec1)
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(len(events), tee.committed_len())
    var l2_text = _tee_text(l2)
    var file_text = _tee_text(events)
    assert_true(not _contains_text(file_text, l2_text))


def test_tee_abort_all_restarts_clean() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(target, 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(200)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(300)))
    var begun = tee.group_begin()
    assert_true(begun.ok)
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    assert_true(tee.group_abort(begun.mark).ok)
    assert_equal(tee.committed_len(), 0)
    # The aborted refresh stands; the restart re-establishes
    # silently with a fresh floor.
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 1)
    var pre_abort = List[List[UInt8]]()
    pre_abort.append(l0.copy())
    var rec0 = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), pre_abort, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), rec0)
    var events = read_host_file(
        target + String("/events.ndjson"), String("events"), 1048576
    )
    assert_equal(len(events), tee.committed_len())


def test_tee_refresh_excludes_boundary_event() raises:
    # A refresh at horizon H covers [start, H): the event at
    # H folds after the snapshot, matching replay. The first
    # event only establishes the window; it never emits an
    # empty [T, T) refresh.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 1)
    var first = List[List[UInt8]]()
    first.append(l0.copy())
    var want = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), first, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_rewound_horizon_never_reemits() raises:
    # After an abort rewinds the retained horizon below an
    # already-shown horizon, older horizons never re-emit:
    # the gap is guarded, never wrapped unsigned.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(200)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(1), UInt64(150)))
    var l3 = _tee_line(_tee_attempt("op4", UInt64(2), UInt64(300)))
    assert_true(tee.append(l0).ok)
    var begun = tee.group_begin()
    assert_true(begun.ok)
    assert_true(tee.append(l1).ok)
    assert_true(tee.group_abort(begun.mark).ok)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 1)
    assert_true(tee.append(l3).ok)
    assert_equal(tee.emission_count(), 2)
    var first = List[List[UInt8]]()
    first.append(l0.copy())
    var rec0 = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), first, UInt64(200))
        + String("\n")
    )
    var kept = List[List[UInt8]]()
    kept.append(l0.copy())
    kept.append(l2.copy())
    var rec1 = (
        format_u64(UInt64(300))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), kept, UInt64(300))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), rec0 + rec1)


def test_tee_below_floor_restamps_window() raises:
    # A reordered event below the stamped start lowers the
    # window floor to the retained minimum: nothing counts
    # below the declared window.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_attempt("op2", UInt64(1), UInt64(60)))
    var l2 = _tee_line(_tee_attempt("op3", UInt64(2), UInt64(200)))
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 1)
    var both = List[List[UInt8]]()
    both.append(l0.copy())
    both.append(l1.copy())
    var want = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(60), both, UInt64(200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_rebuild_streams_large_prefix() raises:
    # Rollback refolds the retained prefix without holding
    # the whole file: two thousand lines (several 64 KiB
    # chunks) rebuild to the exact oracle digest.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(1000000000000), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 134217728).ok)
    var kept = List[List[UInt8]]()
    for i in range(2000):
        var line = _tee_line(
            _tee_attempt(
                String("op") + format_u64(UInt64(i)),
                UInt64(i),
                UInt64(1000) + UInt64(i),
            )
        )
        kept.append(line.copy())
        assert_true(tee.append(line).ok)
    var begun = tee.group_begin()
    assert_true(begun.ok)
    var dropped = _tee_line(
        _tee_attempt(String("opx"), UInt64(2000), UInt64(5000))
    )
    assert_true(tee.append(dropped).ok)
    assert_true(tee.group_abort(begun.mark).ok)
    var probe = _tee_line(
        _tee_attempt(
            String("probe"), UInt64(2001), UInt64(2000000000000)
        )
    )
    assert_true(tee.append(probe).ok)
    assert_equal(tee.emission_count(), 1)
    var want = (
        format_u64(UInt64(2000000000000))
        + String(" ")
        + _tee_direct(
            tmpl, UInt64(1000), kept, UInt64(2000000000000)
        )
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_failed_fold_rolls_back_bytes() raises:
    # A line that persists but fails the fold is rolled
    # back: the retained bytes and the live analyzer agree,
    # and later refreshes match a replay of the file.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 134217728).ok)
    var l0 = _tee_line(
        _tee_attempt(String("op0"), UInt64(0), UInt64(1000))
    )
    var l1 = _tee_line(
        _tee_attempt(String("op1"), UInt64(1), UInt64(1010))
    )
    assert_true(tee.append(l0).ok)
    assert_true(tee.append(l1).ok)
    var before = tee.committed_len()
    var bad_text = String("{oops}\n")
    var bad = List[UInt8]()
    for b in bad_text.as_bytes():
        bad.append(b)
    var failed = tee.append(bad)
    assert_true(not failed.ok)
    assert_equal(failed.kind, String("internal"))
    assert_equal(tee.committed_len(), before)
    var events = read_host_file(
        scratch + String("/cap/events.ndjson"),
        String("events"),
        8388608,
    )
    var want_bytes = l0.copy()
    for i in range(len(l1)):
        want_bytes.append(l1[i])
    assert_equal(_tee_text(events), _tee_text(want_bytes))
    var probe = _tee_line(
        _tee_attempt(String("op2"), UInt64(2), UInt64(2000))
    )
    assert_true(tee.append(probe).ok)
    assert_equal(tee.emission_count(), 1)
    var kept = List[List[UInt8]]()
    kept.append(l0.copy())
    kept.append(l1.copy())
    var want = (
        format_u64(UInt64(2000))
        + String(" ")
        + _tee_direct(tmpl, UInt64(1000), kept, UInt64(2000))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_refused_refresh_rolls_back_line() raises:
    # A refused emission rolls the line back: the file
    # holds the prefix and the analyzer matches it, so a
    # re-append emits the prefix digest.
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[RefuseOnceSink](
        tmpl, UInt64(50), RefuseOnceSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 134217728).ok)
    var l0 = _tee_line(
        _tee_attempt(String("op0"), UInt64(0), UInt64(1000))
    )
    var l1 = _tee_line(
        _tee_attempt(String("op1"), UInt64(1), UInt64(1200))
    )
    assert_true(tee.append(l0).ok)
    var before = tee.committed_len()
    var refused = tee.append(l1)
    assert_true(not refused.ok)
    assert_equal(refused.kind, String("internal"))
    assert_equal(tee.committed_len(), before)
    var events = read_host_file(
        scratch + String("/cap/events.ndjson"),
        String("events"),
        8388608,
    )
    assert_equal(_tee_text(events), _tee_text(l0))
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 1)
    var kept = List[List[UInt8]]()
    kept.append(l0.copy())
    var want = (
        format_u64(UInt64(1200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(1000), kept, UInt64(1200))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), want)


def test_tee_empty_emits_nothing() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    tee.discard()
    assert_equal(tee.emission_count(), 0)
    var missing = False
    try:
        _ = read_host_file(obs, String("obs"), 1048576)
    except:
        missing = True
    assert_true(missing)


def test_tee_unavailable_pool_matches_offline() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(
        _tee_pool_unavailable(
            String("p"), UInt64(200), UInt64(1), String("denied")
        )
    )
    var l2 = _tee_line(_tee_attempt("op2", UInt64(2), UInt64(300)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 1)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 2)
    # The unavailable halves land in the refresh after the
    # snapshot they trigger.
    var first = List[List[UInt8]]()
    first.append(l0.copy())
    var rec0 = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), first, UInt64(200))
        + String("\n")
    )
    var both = List[List[UInt8]]()
    both.append(l0.copy())
    both.append(l1.copy())
    var rec1 = (
        format_u64(UInt64(300))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), both, UInt64(300))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), rec0 + rec1)


def test_tee_loss_matches_offline() raises:
    var scratch = _mkdtemp()
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(50), ScriptFileSink(obs)
    )
    assert_true(tee.create(scratch + String("/cap"), 131072).ok)
    var l0 = _tee_line(_tee_attempt("op1", UInt64(0), UInt64(100)))
    var l1 = _tee_line(_tee_gap(UInt64(200), UInt64(1)))
    var l2 = _tee_line(_tee_attempt("op2", UInt64(2), UInt64(300)))
    assert_true(tee.append(l0).ok)
    assert_equal(tee.emission_count(), 0)
    assert_true(tee.append(l1).ok)
    assert_equal(tee.emission_count(), 1)
    assert_true(tee.append(l2).ok)
    assert_equal(tee.emission_count(), 2)
    # Each refresh excludes its boundary event: the gap
    # folds after the snapshot it triggers and lands in the
    # next refresh.
    var first = List[List[UInt8]]()
    first.append(l0.copy())
    var rec0 = (
        format_u64(UInt64(200))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), first, UInt64(200))
        + String("\n")
    )
    var both = List[List[UInt8]]()
    both.append(l0.copy())
    both.append(l1.copy())
    var rec1 = (
        format_u64(UInt64(300))
        + String(" ")
        + _tee_direct(tmpl, UInt64(100), both, UInt64(300))
        + String("\n")
    )
    var raw = read_host_file(obs, String("obs"), 1048576)
    assert_equal(_tee_text(raw), rec0 + rec1)


def _prefix_timeout() -> PollOut:
    return PollOut(String("timeout"), List[UInt8](), UInt32(0), String(""))


def _prefix_zeros(mut kernel: ScriptKernel):
    var zstats = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    for _ in range(5):
        kernel.add_stats(zstats.copy())
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(4):
        kernel.add_snap(zsnap.copy())


def _prefix_clock_vals() -> List[UInt64]:
    """Four queued startup values plus the pool baseline read
    (startup consumes five with pool sampling: the baseline
    sample timestamp eats the first dwell value), three
    firing iterations, four quiet iterations, then the latch
    and tail (never reached: the scripted stop latches
    first). The next-fire deadline keys off the iteration
    timestamp, so every iteration at least one second past
    the last fire emits a sample."""
    var base = UInt64(1000000000)
    var out = List[UInt64]()
    out.append(base)
    out.append(base + UInt64(1))
    out.append(base + UInt64(2))
    out.append(base + UInt64(3))
    out.append(base + UInt64(1500000000))
    out.append(base + UInt64(1500000000))
    out.append(base + UInt64(2500000000))
    out.append(base + UInt64(2500000000))
    out.append(base + UInt64(3500000000))
    out.append(base + UInt64(3500000000))
    for i in range(5):
        out.append(base + UInt64(3500000001) + UInt64(i))
    var latch = base + UInt64(61000000001)
    out.append(latch)
    for i in range(7):
        out.append(latch + UInt64(1 + i))
    return out^


def _prefix_split_record(rec: String) raises -> Tuple[UInt64, String]:
    """Split one obs record into horizon plus row digest."""
    var raw = rec.as_bytes()
    var i = 0
    while i < len(raw) and raw[i] != UInt8(32):
        i += 1
    if i >= len(raw):
        raise Error("obs record has no digest")
    var horizon = UInt64(0)
    for j in range(i):
        var b = raw[j]
        if b < UInt8(48) or b > UInt8(57):
            raise Error("obs horizon not digits")
        horizon = horizon * UInt64(10) + UInt64(b - UInt8(48))
    var rest = List[UInt8]()
    for j in range(i + 1, len(raw)):
        rest.append(raw[j])
    try:
        return (horizon, String(from_utf8=Span(rest)))
    except:
        raise Error("obs digest not UTF-8")


def _prefix_retained_lines(path: String) raises -> List[List[UInt8]]:
    """Retained event lines in fold order, newlines kept."""
    var raw = read_host_file(path, String("events"), 8388608)
    var out = List[List[UInt8]]()
    var start = 0
    var i = 0
    while True:
        if i >= len(raw) or raw[i] == UInt8(0x0A):
            if i > start:
                var line = List[UInt8]()
                for j in range(start, i):
                    line.append(raw[j])
                line.append(UInt8(0x0A))
                out.append(line^)
            if i >= len(raw):
                break
            start = i + 1
        i += 1
    return out^


def _prefix_line_ts(line: List[UInt8]) raises -> UInt64:
    """Event timestamp of one retained line."""
    var body = _tee_stripped(line)
    var ev = parse_event(body)
    return ev.ts_ns


def test_tee_signal_stop_prefixes_match_offline() raises:
    # A scripted stop ends the run after three periodic pool
    # fires; every refresh equals the offline digest over the
    # retained arrival prefix strictly below its horizon (the
    # boundary event folds after the snapshot). Closing
    # lines fold too, so the two horizon-advancing closing
    # lines emit as well; each emission horizon is a running
    # maximum, so its prefix ends before the first retained
    # line carrying that timestamp.
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var obs = scratch + String("/obs.ndjson")
    var tmpl = _tee_template()
    var tee = TeeWriter[ScriptFileSink](
        tmpl, UInt64(1), ScriptFileSink(obs)
    )
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = 134217728
    cfg.output = target
    cfg.profile_id = String("prefix-probe")
    cfg.pid = 4242
    cfg.has_pool_sample = True
    cfg.pool_root = String("tests/fixtures/pools/debugfs-ok")
    var kernel = ScriptKernel()
    kernel.add_poll(_prefix_timeout(), 120)
    _prefix_zeros(kernel)
    var clock = ScriptClock()
    clock.step = UInt64(1000000)
    var vals = _prefix_clock_vals()
    for i in range(len(vals)):
        clock.add(vals[i])
    var signal = ScriptSignal()
    for _ in range(7):
        signal.add(String("none"))
    signal.add(String("pending"))
    var coll = Collector(cfg^)
    var res = coll.run(kernel, clock, signal, tee)
    assert_equal(res.exit_code, 4)
    assert_equal(res.end_reason, String("signal"))
    assert_equal(tee.emission_count(), 5)
    # The pool baseline read shifts the dwell pairs by one,
    # so the periodic timestamps trail the dwell values; the
    # baseline establishes the window silently.
    var want_horizons = List[UInt64]()
    want_horizons.append(UInt64(3500000000))
    want_horizons.append(UInt64(4500000000))
    want_horizons.append(UInt64(4500000001))
    var lines = _prefix_retained_lines(
        target + String("/events.ndjson")
    )
    assert_equal(len(lines), 9)
    var text = _tee_text(read_host_file(obs, String("obs"), 1048576))
    var records = text.split(String("\n"))
    var seen = 0
    var prev_horizon = UInt64(0)
    for i in range(len(records)):
        var rec = String(records[i])
        if rec.byte_length() == 0:
            continue
        var split = _prefix_split_record(rec)
        if seen < 3:
            assert_equal(split[0], want_horizons[seen])
        else:
            assert_true(split[0] > prev_horizon)
        prev_horizon = split[0]
        var end = 0
        while end < len(lines):
            if _prefix_line_ts(lines[end]) == split[0]:
                break
            end += 1
        assert_true(end < len(lines))
        var prefix = List[List[UInt8]]()
        var floor = ~UInt64(0)
        for j in range(end):
            prefix.append(lines[j].copy())
            var ts = _prefix_line_ts(lines[j])
            if ts < floor:
                floor = ts
        assert_true(len(prefix) > 0)
        var want = _tee_direct(tmpl, floor, prefix, split[0])
        assert_equal(split[1], want)
        seen += 1
    assert_equal(seen, 5)


def _contains_text(hay: String, needle: String) -> Bool:
    if len(needle.as_bytes()) == 0:
        return True
    var hb = hay.as_bytes()
    var nb = needle.as_bytes()
    var i = 0
    while i + len(nb) <= len(hb):
        var j = 0
        while j < len(nb):
            if hb[i + j] != nb[j]:
                break
            j += 1
        if j == len(nb):
            return True
        i += 1
    return False


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_lifecycle]()
    suite.test[test_misuse_before_create]()
    suite.test[test_empty_abandon_succeeds]()
    suite.test[test_residual_tail]()
    suite.test[test_strip_residual_tail]()
    suite.test[test_create_guards]()
    suite.test[test_abandon_and_discard]()
    suite.test[test_tee_forwards_bytes_identical]()
    suite.test[test_tee_misuse_before_create]()
    suite.test[test_tee_first_data_establishes_silently]()
    suite.test[test_tee_interval_gates_refresh]()
    suite.test[test_tee_decode_failure_is_loud]()
    suite.test[test_tee_sink_failure_is_loud]()
    suite.test[test_tee_disorder_folds_forward_only]()
    suite.test[test_tee_same_reducer_mixed_kinds]()
    suite.test[test_tee_closing_lines_fold]()
    suite.test[test_tee_group_abort_rebuilds_prefix]()
    suite.test[test_tee_abort_all_restarts_clean]()
    suite.test[test_tee_refresh_excludes_boundary_event]()
    suite.test[test_tee_rewound_horizon_never_reemits]()
    suite.test[test_tee_below_floor_restamps_window]()
    suite.test[test_tee_rebuild_streams_large_prefix]()
    suite.test[test_tee_failed_fold_rolls_back_bytes]()
    suite.test[test_tee_refused_refresh_rolls_back_line]()
    suite.test[test_tee_empty_emits_nothing]()
    suite.test[test_tee_unavailable_pool_matches_offline]()
    suite.test[test_tee_loss_matches_offline]()
    suite.test[test_tee_signal_stop_prefixes_match_offline]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
