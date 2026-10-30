# SPDX-License-Identifier: GPL-3.0-or-later

"""Fixture containment: symlink/dotdot escapes refuse as denied.

Builds hostile fixture trees in a tmpdir (symlinked files,
symlinked intermediate directories, dotdot paths, symlinked
meta.txt) and proves reads stay inside the fixture root.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.reader import (
    E_ABSENT,
    E_DENIED,
    E_META_BAD,
    EvidenceError,
    EvidenceReader,
    bytes_to_text,
    open_evidence_reader,
    read_evidence,
)


def _cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _mkdtemp() raises -> String:
    var template = String("/tmp/memveil-contain-XXXXXX")
    var buf = _cstr(template)
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


def _mkdir(path: String) raises:
    var cp = _cstr(path)
    var rc = external_call["mkdir", Int32](
        Span(cp).unsafe_ptr(), 0o755
    )
    if Int(rc) != 0:
        raise Error(String("mkdir failed: ") + path)


def _write(path: String, text: String) raises:
    var cp = _cstr(path)
    var cm = _cstr(String("wb"))
    var fp = external_call["fopen", UInt64](
        Span(cp).unsafe_ptr(), Span(cm).unsafe_ptr()
    )
    if fp == 0:
        raise Error(String("cannot write: ") + path)
    var data = text.as_bytes()
    var n = external_call["fwrite", Int64](
        Span(data).unsafe_ptr(), 1, len(data), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(data):
        raise Error(String("short write: ") + path)


def _symlink(target: String, link: String) raises:
    var ct = _cstr(target)
    var cl = _cstr(link)
    var rc = external_call["symlink", Int32](
        Span(ct).unsafe_ptr(), Span(cl).unsafe_ptr()
    )
    if Int(rc) != 0:
        raise Error(String("symlink failed: ") + link)


def _meta() -> String:
    return String("arch=x86_64\nrelease=7.0.0-test\neuid=0\n")


def _evil_root() raises -> String:
    """One hostile fixture plus an outside secret file."""
    var tmp = _mkdtemp()
    var root = tmp + String("/root")
    _mkdir(root)
    _write(root + String("/meta.txt"), _meta())
    _mkdir(root + String("/sys"))
    _write(root + String("/sys/x"), String("inside"))
    _write(tmp + String("/secret"), String("OUTSIDE"))
    _symlink(tmp + String("/secret"), root + String("/link"))
    _symlink(tmp, root + String("/sub"))
    return root^


def _expect_denied(reader: EvidenceReader, path: String) raises:
    var refused = False
    try:
        _ = read_evidence(reader, path, 65536)
    except e:  # E_DENIED refusal is the contained verdict
        assert_equal(e.code, E_DENIED)
        refused = True
    if not refused:
        raise Error(String("escape read succeeded: ") + path)


def test_fixture_symlink_file_refuses() raises:
    var reader = open_evidence_reader(_evil_root())
    var ok = read_evidence(reader, String("/sys/x"), 65536)
    assert_equal(bytes_to_text(ok^), String("inside"))
    _expect_denied(reader, String("/link"))


def test_fixture_symlink_dir_refuses() raises:
    var reader = open_evidence_reader(_evil_root())
    _expect_denied(reader, String("/sub/secret"))


def test_fixture_dotdot_refuses() raises:
    var reader = open_evidence_reader(_evil_root())
    _expect_denied(reader, String("/../secret"))


def test_fixture_absent_stays_absent() raises:
    var reader = open_evidence_reader(_evil_root())
    var absent = False
    try:
        _ = read_evidence(reader, String("/sys/nope"), 65536)
    except e:
        assert_equal(e.code, E_ABSENT)
        absent = True
    if not absent:
        raise Error("absent read succeeded")


def test_fixture_symlink_meta_refuses() raises:
    var tmp = _mkdtemp()
    var root = tmp + String("/root")
    _mkdir(root)
    _write(tmp + String("/real-meta"), _meta())
    _symlink(tmp + String("/real-meta"), root + String("/meta.txt"))
    var refused = False
    try:
        _ = open_evidence_reader(root)
    except e:
        assert_equal(e.code, E_META_BAD)
        refused = True
    if not refused:
        raise Error("symlink meta opened")


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_fixture_symlink_file_refuses]()
    suite.test[test_fixture_symlink_dir_refuses]()
    suite.test[test_fixture_dotdot_refuses]()
    suite.test[test_fixture_absent_stays_absent]()
    suite.test[test_fixture_symlink_meta_refuses]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
