# SPDX-License-Identifier: GPL-3.0-or-later

"""LiveWriter adapter: real files on mkdtemp scratch dirs."""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.live import (
    LiveWriter,
    _residual_tail,
    _strip_residual_tail,
)
from memveil.platform.reader import read_host_file


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


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_lifecycle]()
    suite.test[test_misuse_before_create]()
    suite.test[test_empty_abandon_succeeds]()
    suite.test[test_residual_tail]()
    suite.test[test_strip_residual_tail]()
    suite.test[test_create_guards]()
    suite.test[test_abandon_and_discard]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
