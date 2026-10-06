"""LmbKernel adapter: pre-open and open-failure paths.

Live paths need privileges and run in the VM gate;
these vectors pin the not-open taxonomy plus the
open-failure message shape.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from libbpf_mojo.batch import (
    POLL_BATCH,
    POLL_ERROR,
    POLL_SHORT,
    POLL_TIMEOUT,
)
from libbpf_mojo.error import EINTR

from memveil.capture.kernel import LmbKernel, poll_outcome


def _kernel() -> LmbKernel:
    var elf = List[UInt8]()
    elf.append(UInt8(0x7F))
    return LmbKernel(
        elf^,
        String("mv_attempts"),
        String("/nonexistent/libbpf_mojo.so.1"),
        String("mv_swiotlb_attempt"),
        String("swiotlb"),
        String("swiotlb_bounced"),
    )


def test_not_open_taxonomy() raises:
    var k = _kernel()
    assert_equal(k.load().ok, False)
    assert_equal(k.load().message, String("session not open"))
    var g = k.map_info(String("mv_counts"))
    assert_equal(g.ok, False)
    assert_equal(k.attach().message, String("session not open"))
    var p = k.poll(100, UInt32(4104))
    assert_equal(p.kind, String("error"))
    assert_equal(p.message, String("session not open"))
    var s = k.stats()
    assert_equal(s.ok, False)
    var snap = k.read_full()
    assert_equal(snap.ok, False)
    assert_equal(k.detach().message, String("session not open"))
    # Close is idempotent cleanup: closing a never-opened
    # session succeeds, so pre-open rollback stays clean.
    var closed = k.close()
    assert_equal(closed.ok, True)
    assert_equal(closed.message, String(""))


def test_open_failure_shape() raises:
    var k = _kernel()
    var out = k.open_session()
    assert_equal(out.ok, False)
    # Structured op/domain/code detail, never bare text.
    var msg = out.message.as_bytes()
    assert_true(len(msg) > 0)
    var has_op = False
    var want = String("op=").as_bytes()
    var i = 0
    while i + len(want) <= len(msg):
        var j = 0
        while j < len(want):
            if msg[i + j] != want[j]:
                break
            j += 1
        if j == len(want):
            has_op = True
            break
        i += 1
    assert_true(has_op)
    # A failed open leaves the adapter unopened.
    assert_equal(k.load().message, String("session not open"))


def test_poll_outcome_passthrough() raises:
    assert_equal(poll_outcome(POLL_BATCH, Int32(0)), String("batch"))
    assert_equal(poll_outcome(POLL_TIMEOUT, Int32(0)), String("timeout"))
    assert_equal(poll_outcome(POLL_SHORT, Int32(0)), String("short"))
    assert_equal(
        poll_outcome(POLL_ERROR, Int32(-22)), String("error")
    )
    assert_equal(poll_outcome(UInt32(99), Int32(0)), String("error"))


def test_poll_outcome_eintr() raises:
    # Interrupted waits retry as timeouts; the code match
    # applies to poll errors only.
    assert_equal(poll_outcome(POLL_ERROR, EINTR), String("timeout"))
    assert_equal(
        poll_outcome(UInt32(99), EINTR), String("error")
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_not_open_taxonomy]()
    suite.test[test_open_failure_shape]()
    suite.test[test_poll_outcome_passthrough]()
    suite.test[test_poll_outcome_eintr]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
