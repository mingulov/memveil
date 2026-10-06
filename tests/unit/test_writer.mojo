"""EventWriter unit tests: creation, gates, groups, finalize.

In-process tests on mkdtemp scratch dirs (no shims here).
Fault injection (short writes, ENOSPC, fsync order, races)
runs shell-driven under LD_PRELOAD in the writer lane via
tests/unit/shim_probe.mojo.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.writer import (
    CLOSING_RESERVE,
    MAX_EVENTS_BUDGET,
    MIN_EVENTS_BUDGET,
    EventWriter,
)
from memveil.platform.reader import read_host_file


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-writer-XXXXXX")
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


def _line(byte: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n - 1):
        out.append(byte)
    out.append(UInt8(0x0A))
    return out^


def _read(path: String) raises -> List[UInt8]:
    return read_host_file(path, "writer test read", 67108864)


def test_create_append_finalize() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    w.append(_line(UInt8(0x42), 200))
    assert_equal(w.committed_len(), 300)
    var session = _line(UInt8(0x7B), 50)
    var outcome = w.finalize(session)
    assert_equal(outcome.status, String("finalized"))
    var events = _read(target + String("/events.ndjson"))
    assert_equal(len(events), 300)
    assert_equal(events[0], UInt8(0x41))
    assert_equal(events[99], UInt8(0x0A))
    assert_equal(events[100], UInt8(0x42))
    var back = _read(target + String("/session.json"))
    assert_equal(len(back), 50)


def test_exists_variants() raises:
    var scratch = _mkdtemp()
    # Nonempty dir (a previous capture).
    var w = EventWriter(scratch + String("/cap"), MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 10))
    var raised = False
    try:
        var w2 = EventWriter(scratch + String("/cap"), MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("exists"))
    assert_true(raised)
    # Empty dir.
    var empty_target = scratch + String("/empty")
    var path = List[UInt8]()
    for b in empty_target.as_bytes():
        path.append(b)
    path.append(UInt8(0))
    var made = external_call["mkdir", Int32](
        Span(path).unsafe_ptr(), 0o700
    )
    assert_equal(Int(made), 0)
    raised = False
    try:
        var w3 = EventWriter(empty_target, MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("exists"))
    assert_true(raised)
    # Plain file.
    var file_target = scratch + String("/file")
    var handle = open(file_target, "w")
    handle.write(String("x"))
    handle.close()
    raised = False
    try:
        var w4 = EventWriter(file_target, MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("exists"))
    assert_true(raised)
    # Symlink (dangling or not, must never be followed).
    var link_target = scratch + String("/link")
    var link = List[UInt8]()
    for b in link_target.as_bytes():
        link.append(b)
    link.append(UInt8(0))
    var dest = List[UInt8]()
    for b in empty_target.as_bytes():
        dest.append(b)
    dest.append(UInt8(0))
    var sl = external_call["symlink", Int32](
        Span(dest).unsafe_ptr(), Span(link).unsafe_ptr()
    )
    assert_equal(Int(sl), 0)
    raised = False
    try:
        var w5 = EventWriter(link_target, MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("exists"))
    assert_true(raised)


def test_budget_range() raises:
    var scratch = _mkdtemp()
    for bad in range(2):
        var budget = MIN_EVENTS_BUDGET - 1
        if bad == 1:
            budget = MAX_EVENTS_BUDGET + 1
        var raised = False
        try:
            var w = EventWriter(
                scratch + String("/cap") + String(bad), budget
            )
        except e:
            raised = True
            assert_equal(e.kind, String("budget"))
        assert_true(raised)
    var wmin = EventWriter(
        scratch + String("/min"), MIN_EVENTS_BUDGET
    )
    assert_equal(wmin.committed_len(), 0)


def test_size_gate_both_sides() raises:
    var scratch = _mkdtemp()
    var w = EventWriter(scratch + String("/cap"), MIN_EVENTS_BUDGET)
    var budget = MIN_EVENTS_BUDGET - CLOSING_RESERVE
    # Fill to exactly the attempt budget: admitted.
    var chunk = 4096
    var nchunks = budget // chunk
    for _ in range(nchunks):
        w.append(_line(UInt8(0x41), chunk))
    var rest = budget - nchunks * chunk
    if rest > 0:
        w.append(_line(UInt8(0x41), rest))
    assert_equal(w.committed_len(), budget)
    # One more byte: refused, nothing written.
    var raised = False
    try:
        w.append(_line(UInt8(0x42), 1))
    except e:
        raised = True
        assert_equal(e.kind, String("refused"))
    assert_true(raised)
    assert_equal(w.committed_len(), budget)
    var events = _read(scratch + String("/cap/events.ndjson"))
    assert_equal(len(events), budget)


def test_group_abort() raises:
    var scratch = _mkdtemp()
    var w = EventWriter(scratch + String("/cap"), MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    var mark = w.group_begin()
    assert_equal(mark, 100)
    w.append(_line(UInt8(0x42), 100))
    w.append(_line(UInt8(0x43), 100))
    assert_equal(w.committed_len(), 300)
    w.group_abort(mark)
    assert_equal(w.committed_len(), 100)
    w.append(_line(UInt8(0x44), 50))
    assert_equal(w.committed_len(), 150)
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("finalized"))
    var events = _read(scratch + String("/cap/events.ndjson"))
    assert_equal(len(events), 150)
    assert_equal(events[100], UInt8(0x44))
    # Bad marks.
    var w2 = EventWriter(scratch + String("/cap2"), MIN_EVENTS_BUDGET)
    var raised = False
    try:
        w2.group_abort(999)
    except e:
        raised = True
        assert_equal(e.kind, String("misuse"))
    assert_true(raised)


def test_misuse_after_finalize() raises:
    var scratch = _mkdtemp()
    var w = EventWriter(scratch + String("/cap"), MIN_EVENTS_BUDGET)
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("finalized"))
    for _ in range(2):
        var raised = False
        try:
            w.append(_line(UInt8(0x41), 10))
        except e:
            raised = True
            assert_equal(e.kind, String("misuse"))
        assert_true(raised)
    var raised = False
    try:
        var second = w.finalize(_line(UInt8(0x7B), 10))
    except e:
        raised = True
        assert_equal(e.kind, String("misuse"))
    assert_true(raised)


def test_abandon() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    var leftovers = w.abandon()
    assert_equal(leftovers, String(""))
    var gone = False
    try:
        _ = _read(target + String("/events.ndjson"))
    except:
        gone = True
    assert_true(gone)
    # The dir itself is gone: recreate works.
    var w2 = EventWriter(target, MIN_EVENTS_BUDGET)
    assert_equal(w2.committed_len(), 0)


def test_nul_path() raises:
    var raw = List[UInt8]()
    for b in String("/tmp/x").as_bytes():
        raw.append(b)
    raw.append(UInt8(0))
    raw.append(UInt8(0x41))
    var evil = String(from_utf8=Span(raw))
    var raised = False
    try:
        var w = EventWriter(evil, MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("io"))
    assert_true(raised)


def _unlink_path(path: String) raises:
    var buf = List[UInt8]()
    for b in path.as_bytes():
        buf.append(b)
    buf.append(UInt8(0))
    var rc = external_call["unlink", Int32](Span(buf).unsafe_ptr())
    if Int(rc) != 0:
        raise Error("unlink failed in test")


def _rmdir_path(path: String) raises:
    var buf = List[UInt8]()
    for b in path.as_bytes():
        buf.append(b)
    buf.append(UInt8(0))
    var rc = external_call["rmdir", Int32](Span(buf).unsafe_ptr())
    if Int(rc) != 0:
        raise Error("rmdir failed in test")


def _rename_path(old: String, new: String) raises:
    var a = List[UInt8]()
    for b in old.as_bytes():
        a.append(b)
    a.append(UInt8(0))
    var c = List[UInt8]()
    for b in new.as_bytes():
        c.append(b)
    c.append(UInt8(0))
    var rc = external_call["rename", Int32](
        Span(a).unsafe_ptr(), Span(c).unsafe_ptr()
    )
    if Int(rc) != 0:
        raise Error("rename failed in test")


def _contains(hay: String, needle: String) -> Bool:
    return len(hay.split(needle)) > 1


def test_abandon_preserves_replaced_events() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    _rename_path(
        target + String("/events.ndjson"),
        scratch + String("/stolen.ndjson"),
    )
    var repl = open(target + String("/events.ndjson"), "w")
    repl.write(String("ATTACKER\n"))
    repl.close()
    var leftovers = w.abandon()
    assert_true(leftovers != String(""))
    assert_true(_contains(leftovers, String("events file")))
    var body = _read(target + String("/events.ndjson"))
    assert_equal(len(body), 9)
    assert_equal(body[0], UInt8(0x41))
    var stolen = _read(scratch + String("/stolen.ndjson"))
    assert_equal(len(stolen), 100)
    var raised = False
    try:
        var w2 = EventWriter(target, MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("exists"))
    assert_true(raised)


def test_abandon_preserves_replaced_dir() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    _rename_path(target, scratch + String("/stolen-cap"))
    var made_target = scratch + String("/cap")
    var path = List[UInt8]()
    for b in made_target.as_bytes():
        path.append(b)
    path.append(UInt8(0))
    var made = external_call["mkdir", Int32](
        Span(path).unsafe_ptr(), 0o700
    )
    assert_equal(Int(made), 0)
    var leftovers = w.abandon()
    assert_true(leftovers != String(""))
    assert_true(_contains(leftovers, String("output dir")))
    var stolen = _read(scratch + String("/stolen-cap/events.ndjson"))
    assert_equal(len(stolen), 100)
    var repl = open(target + String("/planted"), "w")
    repl.write(String("x"))
    repl.close()
    var kept = _read(target + String("/planted"))
    assert_equal(len(kept), 1)


def test_abandon_reports_foreign_tmp() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    var tmp = open(target + String("/session.json.tmp"), "w")
    tmp.write(String("FOREIGN\n"))
    tmp.close()
    var leftovers = w.abandon()
    assert_true(leftovers != String(""))
    assert_true(_contains(leftovers, String("session.json.tmp")))
    var kept = _read(target + String("/session.json.tmp"))
    assert_equal(len(kept), 8)
    assert_equal(kept[0], UInt8(0x46))


def test_finalize_preserves_planted_tmp() raises:
    # A pre-existing session.json.tmp is foreign: O_EXCL
    # fails, finalize reports unfinalized, and the plant
    # survives (no deterministic deletion).
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    var tmp = open(target + String("/session.json.tmp"), "w")
    tmp.write(String("FOREIGN\n"))
    tmp.close()
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("unfinalized"))
    assert_true(_contains(outcome.message, String("tmp create failed")))
    var kept = _read(target + String("/session.json.tmp"))
    assert_equal(len(kept), 8)
    assert_equal(kept[0], UInt8(0x46))


def test_unlink_events_before_finalize() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    _unlink_path(target + String("/events.ndjson"))
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("unfinalized"))
    var gone = False
    try:
        _ = _read(target + String("/session.json"))
    except:
        gone = True
    assert_true(gone)


def test_unlink_dir_before_finalize() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    _unlink_path(target + String("/events.ndjson"))
    _rmdir_path(target)
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("unfinalized"))


def test_parent_is_file() raises:
    var scratch = _mkdtemp()
    var file = scratch + String("/blocker")
    var buf = _line(UInt8(0x78), 2)
    var cstr = List[UInt8]()
    for b in file.as_bytes():
        cstr.append(b)
    cstr.append(UInt8(0))
    var fd = external_call["openat", Int32](
        Int32(-100), Span(cstr).unsafe_ptr(), Int32(65), UInt32(0o600)
    )
    assert_true(fd >= Int32(0))
    var n = external_call["pwrite", Int64](
        fd, Span(buf).unsafe_ptr(), Int64(len(buf)), Int64(0)
    )
    assert_equal(Int(n), len(buf))
    _ = external_call["close", Int32](fd)
    var raised = False
    try:
        var w = EventWriter(file + String("/cap"), MIN_EVENTS_BUDGET)
    except e:
        raised = True
        assert_equal(e.kind, String("io"))
    assert_true(raised)


def test_trailing_slash_ok() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target + String("/"), MIN_EVENTS_BUDGET)
    w.append(_line(UInt8(0x41), 100))
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("finalized"))
    var ev = _read(target + String("/events.ndjson"))
    assert_equal(len(ev), 100)


def test_append_closing_uses_reserve() raises:
    var scratch = _mkdtemp()
    var target = scratch + String("/cap")
    var w = EventWriter(target, MIN_EVENTS_BUDGET)
    for _ in range(6):
        w.append(_line(UInt8(0x41), 10000))
    assert_equal(w.committed_len(), 60000)
    w.append_closing(_line(UInt8(0x43), 100))
    assert_equal(w.committed_len(), 60100)
    var refused = False
    try:
        w.append(_line(UInt8(0x42), 10000))
    except e:
        refused = True
        assert_equal(e.kind, String("refused"))
    assert_true(refused)
    w.append_closing(_line(UInt8(0x44), 100))
    assert_equal(w.committed_len(), 60200)
    var outcome = w.finalize(_line(UInt8(0x7B), 10))
    assert_equal(outcome.status, String("finalized"))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_create_append_finalize]()
    suite.test[test_exists_variants]()
    suite.test[test_budget_range]()
    suite.test[test_size_gate_both_sides]()
    suite.test[test_group_abort]()
    suite.test[test_misuse_after_finalize]()
    suite.test[test_abandon]()
    suite.test[test_abandon_preserves_replaced_events]()
    suite.test[test_abandon_preserves_replaced_dir]()
    suite.test[test_abandon_reports_foreign_tmp]()
    suite.test[test_finalize_preserves_planted_tmp]()
    suite.test[test_nul_path]()
    suite.test[test_unlink_events_before_finalize]()
    suite.test[test_unlink_dir_before_finalize]()
    suite.test[test_parent_is_file]()
    suite.test[test_trailing_slash_ok]()
    suite.test[test_append_closing_uses_reserve]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
