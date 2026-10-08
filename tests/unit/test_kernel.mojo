# SPDX-License-Identifier: GPL-3.0-or-later

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

from memveil.capture.kernel import (
    LmbKernel,
    join_op_message,
    poll_advance,
    poll_outcome,
)


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


def _multi() -> LmbKernel:
    var attempt = List[UInt8]()
    attempt.append(UInt8(0x7F))
    var lc = List[UInt8]()
    lc.append(UInt8(0x7F))
    var cp = List[UInt8]()
    cp.append(UInt8(0x7F))
    return LmbKernel.with_channels(
        attempt^,
        String("swiotlb"),
        String("swiotlb_bounced"),
        lc^,
        True,
        cp^,
        True,
        String("/nonexistent/libbpf_mojo.so.1"),
    )


def test_channel_counts() raises:
    assert_equal(_kernel().channel_count(), 1)
    assert_equal(_multi().channel_count(), 3)
    var attempt = List[UInt8]()
    attempt.append(UInt8(0x7F))
    var solo = LmbKernel.with_channels(
        attempt^,
        String("swiotlb"),
        String("swiotlb_bounced"),
        List[UInt8](),
        False,
        List[UInt8](),
        False,
        String("/nonexistent/libbpf_mojo.so.1"),
    )
    assert_equal(solo.channel_count(), 1)


def test_multi_not_open_taxonomy() raises:
    var k = _multi()
    for ch in range(3):
        var g = k.map_info_at(ch, String("mv_counts"))
        assert_equal(g.ok, False)
        assert_equal(g.message, String("session not open"))
        var snap = k.read_full_at(ch)
        assert_equal(snap.ok, False)
        assert_equal(snap.message, String("session not open"))
        var st = k.stats_at(ch)
        assert_equal(st.ok, False)
        assert_equal(st.message, String("session not open"))
    var bad = k.map_info_at(3, String("mv_counts"))
    assert_equal(bad.ok, False)
    assert_equal(bad.message, String("bad channel"))
    var bad_snap = k.read_full_at(-1)
    assert_equal(bad_snap.ok, False)
    assert_equal(bad_snap.message, String("bad channel"))
    var bad_stats = k.stats_at(9)
    assert_equal(bad_stats.ok, False)
    assert_equal(bad_stats.message, String("bad channel"))
    # Single-channel shorthands address channel 0.
    assert_equal(
        k.map_info(String("mv_counts")).message,
        String("session not open"),
    )
    assert_equal(
        k.read_full().message, String("session not open"))
    assert_equal(k.stats().message, String("session not open"))
    assert_equal(k.close().ok, True)


def test_multi_open_failure_shape() raises:
    var k = _multi()
    var out = k.open_session()
    assert_equal(out.ok, False)
    # Channel attribution plus structured op detail.
    var msg = out.message.as_bytes()
    assert_true(len(msg) > 0)
    var text = out.message
    assert_true(text.as_bytes()[0] == UInt8(0x63))  # 'c' of "ch0 "
    var want = String("op=").as_bytes()
    var has_op = False
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
    # A failed open leaves every channel unopened.
    for ch in range(3):
        assert_equal(
            k.map_info_at(ch, String("mv_counts")).message,
            String("session not open"),
        )


def test_poll_advance_sparse_order() raises:
    # Order [0, 2]: a batch on copy (position 1) must rotate
    # back to attempt (position 0), not reselect copy by id.
    assert_equal(poll_advance(2, 1, 0), 0)
    assert_equal(poll_advance(2, 0, 0), 1)
    assert_equal(poll_advance(2, 0, 1), 0)
    assert_equal(poll_advance(3, 2, 0), 0)
    assert_equal(poll_advance(3, 0, 2), 0)
    assert_equal(poll_advance(1, 0, 0), 0)


def test_join_op_message() raises:
    assert_equal(
        join_op_message(String(""), 0, String("boom")),
        String("ch0 boom"),
    )
    assert_equal(
        join_op_message(String("ch0 boom"), 2, String("bang")),
        String("ch0 boom; ch2 bang"),
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_not_open_taxonomy]()
    suite.test[test_open_failure_shape]()
    suite.test[test_poll_outcome_passthrough]()
    suite.test[test_poll_outcome_eintr]()
    suite.test[test_channel_counts]()
    suite.test[test_multi_not_open_taxonomy]()
    suite.test[test_multi_open_failure_shape]()
    suite.test[test_poll_advance_sparse_order]()
    suite.test[test_join_op_message]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
