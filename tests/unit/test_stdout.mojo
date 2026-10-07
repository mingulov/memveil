# SPDX-License-Identifier: GPL-3.0-or-later

"""Stdout writer unit tests: exact bytes, loud failures.

The success path writes exact bytes (verified byte-for-byte
by the CLI golden suites that run over this writer); the
failure path raises StdoutError instead of swallowing the
errno. A /dev/full redirect proves the raise in-process;
closed-pipe delivery and per-verb exit codes live in the CLI
harness.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.stdout import StdoutError, write_stdout

comptime _O_WRONLY = 1
comptime _AT_FDCWD = -100


def _cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        out.append(raw[i])
    out.append(UInt8(0))
    return out^


def test_success_writes_silently() raises:
    # Success carries no marker: it returns without raising.
    # (The byte-exact goldens in the reports/top lanes cover
    # what lands on fd 1.)
    write_stdout("")
    assert_true(True)


def test_error_carries_message() raises:
    var err = StdoutError("stdout write failed: errno 28")
    assert_equal(err.message, String("stdout write failed: errno 28"))


def test_write_to_full_device_raises() raises:
    # Redirect fd 1 to /dev/full, prove the write raises
    # instead of reporting success, then restore stdout
    # before any assertion output.
    var saved = external_call["dup", Int32](Int32(1))
    assert_true(saved >= Int32(0))
    var pname = _cstr(String("/dev/full"))
    var full = external_call["openat", Int32](
        Int32(_AT_FDCWD),
        Span(pname).unsafe_ptr(),
        Int32(_O_WRONLY),
        UInt32(0),
    )
    assert_true(full >= Int32(0))
    var moved = external_call["dup2", Int32](full, Int32(1))
    assert_true(moved >= Int32(0))
    _ = external_call["close", Int32](full)
    var raised = False
    try:
        write_stdout("x")
    except:
        raised = True
    _ = external_call["dup2", Int32](saved, Int32(1))
    _ = external_call["close", Int32](saved)
    assert_true(raised)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_success_writes_silently]()
    suite.test[test_error_carries_message]()
    suite.test[test_write_to_full_device_raises]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
