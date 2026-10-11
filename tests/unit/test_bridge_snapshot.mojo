# SPDX-License-Identifier: GPL-3.0-or-later

"""Bridge snapshot: the hashed bytes are the loaded bytes.

Admission, provenance, and receipt minting must bind the exact
bytes the loader maps. The snapshot pins the resolved bridge
pathname with one open file description and names it through
/proc/self/fd/N for both hashing and loading, so a pathname
swap after resolution changes neither. These tests prove the
pin: swap the pathname after the snapshot and the snapshot
still reads the original bytes.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import _stop_mkdtemp

from memveil.cli.record import open_bridge_snapshot
from memveil.platform.hash import sha256_hex
from memveil.platform.reader import read_host_file


def _s_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _s_write(path: String, text: String) raises:
    var cpath = _s_cstr(path)
    var mode = _s_cstr("w")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == UInt64(0):
        raise Error("fopen failed for " + path)
    var raw = text.as_bytes()
    var n = external_call["fwrite", Int64](
        Span(raw).unsafe_ptr(), Int64(1), Int64(len(raw)), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(raw):
        raise Error("short write for " + path)


def test_snapshot_survives_pathname_swap() raises:
    # Snapshot P, then rename a replacement over P: the
    # snapshot hash and load path must still see the
    # original bytes while the pathname sees the swap.
    var base = _stop_mkdtemp()
    var path = base + String("/bridge.so")
    var repl = base + String("/replacement.so")
    _s_write(path, String("ORIGINAL-BRIDGE-BYTES\n"))
    _s_write(repl, String("SWAPPED-BRIDGE-BYTES\n"))
    var snap = open_bridge_snapshot(path)
    assert_true(snap.sha != String(""))
    var cr = _s_cstr(repl)
    var cp = _s_cstr(path)
    var r = external_call["rename", Int32](
        Span(cr).unsafe_ptr(), Span(cp).unsafe_ptr()
    )
    assert_equal(Int(r), 0)
    var now = read_host_file(path, String("bridge"), 4096)
    assert_equal(String(from_utf8=Span(now)), String("SWAPPED-BRIDGE-BYTES\n"))
    var pinned = read_host_file(snap.load_path, String("bridge"), 4096)
    assert_equal(
        String(from_utf8=Span(pinned)), String("ORIGINAL-BRIDGE-BYTES\n")
    )
    assert_equal(snap.sha, sha256_hex(Span(pinned)))


def test_snapshot_missing_path_degrades() raises:
    # An unresolvable bridge keeps the legacy
    # uncheckable semantics: empty hash, plain path for
    # the loader's own failure.
    var snap = open_bridge_snapshot(
        String("/nonexistent/memveil-bridge.so.1")
    )
    assert_equal(snap.sha, String(""))
    assert_equal(
        snap.load_path, String("/nonexistent/memveil-bridge.so.1")
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_snapshot_survives_pathname_swap]()
    suite.test[test_snapshot_missing_path_degrades]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
