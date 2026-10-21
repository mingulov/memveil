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

from memveil.capture.collector import PollOut
from memveil.capture.kernel import (
    ChannelPoller,
    LmbKernel,
    PollRotation,
    added_fds,
    fdinfo_u64,
    join_op_message,
    poll_advance,
    poll_outcome,
    prog_fds,
    rotate_poll,
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


struct _Backlog(ChannelPoller):
    """Synthetic rings: a fixed backlog per channel, no arrivals.

    A nonzero wait on an empty channel burns the whole
    timeout on blocked_ms, as epoll_wait does on a quiet ring.
    """

    var pending: List[Int]
    var delivered: List[Int]
    var blocked_ms: Int
    var order: List[Int]

    def __init__(out self, c0: Int, c1: Int, c2: Int):
        self.pending = [c0, c1, c2]
        self.delivered = [0, 0, 0]
        self.blocked_ms = 0
        self.order = List[Int]()

    def poll_channel(
        mut self, channel: Int, timeout_ms: Int, capacity: UInt32
    ) -> PollOut:
        if self.pending[channel] == 0:
            self.blocked_ms += timeout_ms
            return PollOut(
                String("timeout"), List[UInt8](), UInt32(0), String("")
            )
        self.pending[channel] -= 1
        self.delivered[channel] += 1
        self.order.append(channel)
        return PollOut(
            String("batch"), [UInt8(channel)], UInt32(0), String("")
        )


def _drain(mut ring: _Backlog, polls: Int):
    var rot = PollRotation(0, -1)
    for _ in range(polls):
        _ = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(65536))


def test_rotate_empty_channel_never_stalls_backlog() raises:
    # Attempt ring drained, lifecycle/copy backlogged: every
    # queued record is reachable without a blocking wait.
    var ring = _Backlog(0, 1000, 1000)
    _drain(ring, 2000)
    assert_equal(ring.delivered[1], 1000)
    assert_equal(ring.delivered[2], 1000)
    assert_equal(ring.blocked_ms, 0)


def test_rotate_all_empty_blocks_one_quantum() raises:
    # Quiet rings: one poll waits exactly one quantum, no spin.
    var ring = _Backlog(0, 0, 0)
    var rot = PollRotation(0, -1)
    var out = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(65536))
    assert_equal(out.kind, String("timeout"))
    assert_equal(ring.blocked_ms, 100)


def test_rotate_busy_channels_round_robin() raises:
    var ring = _Backlog(2, 2, 2)
    _drain(ring, 6)
    assert_equal(len(ring.order), 6)
    for i in range(6):
        assert_equal(ring.order[i], i % 3)
    assert_equal(ring.blocked_ms, 0)


struct _Script(ChannelPoller):
    """Scripted rings: per-channel result kinds, logged calls.

    Each call pops the channel's next kind ("batch", "short",
    "error"); an empty script reads as "timeout".
    """

    var script: List[List[String]]
    var calls: List[Int]
    var waits: List[Int]

    def __init__(out self):
        self.script = [List[String](), List[String](), List[String]()]
        self.calls = List[Int]()
        self.waits = List[Int]()

    def poll_channel(
        mut self, channel: Int, timeout_ms: Int, capacity: UInt32
    ) -> PollOut:
        self.calls.append(channel)
        self.waits.append(timeout_ms)
        if len(self.script[channel]) == 0:
            return PollOut(
                String("timeout"), List[UInt8](), UInt32(0), String("")
            )
        var kind = self.script[channel].pop(0)
        return PollOut(kind, List[UInt8](), UInt32(9), String("boom"))


def test_rotate_short_in_sweep_pins_channel() raises:
    var ring = _Script()
    ring.script[2].append(String("short"))
    ring.script[2].append(String("batch"))
    var rot = PollRotation(1, -1)
    var out = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(4))
    assert_equal(out.kind, String("short"))
    assert_equal(rot.short_ch, 2)
    # The retry polls only the pinned channel, then unpins.
    var retry = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(9))
    assert_equal(retry.kind, String("batch"))
    assert_equal(ring.calls[len(ring.calls) - 1], 2)
    assert_equal(len(ring.calls), 3)
    assert_equal(rot.short_ch, -1)


def test_rotate_short_in_wait_pins_channel() raises:
    var ring = _Script()
    var rot = PollRotation(0, -1)
    # Sweep sees nothing; the start channel's wait yields short.
    ring.script[0].append(String("timeout"))
    ring.script[0].append(String("short"))
    var out = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(4))
    assert_equal(out.kind, String("short"))
    assert_equal(rot.short_ch, 0)
    assert_equal(ring.waits[len(ring.waits) - 1], 100)


def test_rotate_errors_tagged_by_channel() raises:
    var ring = _Script()
    ring.script[1].append(String("error"))
    var rot = PollRotation(0, -1)
    var out = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(4))
    assert_equal(out.message, String("ch1 boom"))
    var waited = _Script()
    waited.script[0].append(String("timeout"))
    waited.script[0].append(String("error"))
    var rot2 = PollRotation(0, -1)
    var out2 = rotate_poll(waited, rot2, [0, 1, 2], 100, UInt32(4))
    assert_equal(out2.message, String("ch0 boom"))


def test_rotate_zero_timeout_never_waits() raises:
    # The stop drain polls with 0: n probes, none waits.
    var ring = _Script()
    var rot = PollRotation(0, -1)
    var out = rotate_poll(ring, rot, [0, 1, 2], 0, UInt32(4))
    assert_equal(out.kind, String("timeout"))
    assert_equal(len(ring.calls), 3)
    for i in range(3):
        assert_equal(ring.waits[i], 0)


def test_rotate_idle_wait_rotates() raises:
    var ring = _Script()
    var rot = PollRotation(0, -1)
    _ = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(4))
    _ = rotate_poll(ring, rot, [0, 1, 2], 100, UInt32(4))
    # Waits land on channel 0, then channel 1.
    assert_equal(ring.calls[3], 0)
    assert_equal(ring.waits[3], 100)
    assert_equal(ring.calls[7], 1)
    assert_equal(ring.waits[7], 100)


def test_rotate_sparse_order() raises:
    # Order [0, 2] with copy busy: attempt is probed every poll.
    var ring = _Script()
    for _ in range(4):
        ring.script[2].append(String("batch"))
    var rot = PollRotation(0, -1)
    for _ in range(4):
        var out = rotate_poll(ring, rot, [0, 2], 100, UInt32(4))
        assert_equal(out.kind, String("batch"))
    var probes0 = 0
    for i in range(len(ring.calls)):
        assert_true(ring.calls[i] != 1)
        if ring.calls[i] == 0:
            probes0 += 1
    assert_equal(probes0, 4)


def test_rotate_empty_order_errors() raises:
    var ring = _Script()
    var rot = PollRotation(0, -1)
    var out = rotate_poll(ring, rot, List[Int](), 100, UInt32(4))
    assert_equal(out.kind, String("error"))
    assert_equal(len(ring.calls), 0)


def test_join_op_message() raises:
    assert_equal(
        join_op_message(String(""), 0, String("boom")),
        String("ch0 boom"),
    )
    assert_equal(
        join_op_message(String("ch0 boom"), 2, String("bang")),
        String("ch0 boom; ch2 bang"),
    )


comptime _PROG_FDINFO = (
    "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t1057\n"
    "prog_type:\t26\nprog_jited:\t1\nprog_tag:\t3b185187f1855c4c\n"
    "memlock:\t4096\nprog_id:\t912\nrun_time_ns:\t0\nrun_cnt:\t0\n"
    "recursion_misses:\t11808\nverified_insns:\t371\n"
)


def test_fdinfo_u64_reads_fields() raises:
    var t = String(_PROG_FDINFO)
    assert_equal(fdinfo_u64(t, String("recursion_misses")).value(), UInt64(11808))
    assert_equal(fdinfo_u64(t, String("prog_type")).value(), UInt64(26))
    assert_equal(fdinfo_u64(t, String("prog_id")).value(), UInt64(912))


def test_fdinfo_u64_refuses_partial_keys_and_junk() raises:
    var t = String(_PROG_FDINFO)
    # A key matches only whole at a line start.
    assert_true(not fdinfo_u64(t, String("misses")))
    assert_true(not fdinfo_u64(t, String("prog")))
    assert_true(not fdinfo_u64(t, String("link_type")))
    # Hex, empty, trailing junk and overflow never parse.
    assert_true(not fdinfo_u64(String("prog_tag:\tdeadbeef\n"), String("prog_tag")))
    assert_true(not fdinfo_u64(String("x:\t\n"), String("x")))
    assert_true(not fdinfo_u64(String("x:\t12ab\n"), String("x")))
    assert_true(
        not fdinfo_u64(String("x:\t18446744073709551616\n"), String("x"))
    )
    assert_equal(
        fdinfo_u64(String("x:\t18446744073709551615"), String("x")).value(),
        UInt64(0xFFFFFFFFFFFFFFFF),
    )


def test_link_fdinfo_is_not_a_program() raises:
    # Links carry prog_id too; only prog_type marks a program.
    var link = String(
        "link_type:\ttracing\nlink_id:\t5\nprog_tag:\tab\n"
        "prog_id:\t912\nattach_type:\t25\n"
    )
    assert_true(not fdinfo_u64(link, String("prog_type")))


def test_added_fds_diff() raises:
    var before = List[Int]()
    before.append(3)
    before.append(7)
    var after = List[Int]()
    after.append(3)
    after.append(9)
    after.append(7)
    after.append(12)
    var got = added_fds(before, after)
    assert_equal(len(got), 2)
    assert_equal(got[0], 9)
    assert_equal(got[1], 12)


def test_prog_fds_lists_without_programs() raises:
    # This test process holds no BPF programs.
    var got = prog_fds()
    assert_true(Bool(got))
    assert_equal(len(got.value()), 0)


def test_recursion_misses_before_open() raises:
    var k = _kernel()
    var m = k.recursion_misses()
    assert_true(not m.ok)
    assert_equal(m.message, String("session not open"))


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
    suite.test[test_rotate_empty_channel_never_stalls_backlog]()
    suite.test[test_rotate_all_empty_blocks_one_quantum]()
    suite.test[test_rotate_busy_channels_round_robin]()
    suite.test[test_rotate_short_in_sweep_pins_channel]()
    suite.test[test_rotate_short_in_wait_pins_channel]()
    suite.test[test_rotate_errors_tagged_by_channel]()
    suite.test[test_rotate_zero_timeout_never_waits]()
    suite.test[test_rotate_idle_wait_rotates]()
    suite.test[test_rotate_sparse_order]()
    suite.test[test_rotate_empty_order_errors]()
    suite.test[test_join_op_message]()
    suite.test[test_fdinfo_u64_reads_fields]()
    suite.test[test_fdinfo_u64_refuses_partial_keys_and_junk]()
    suite.test[test_link_fdinfo_is_not_a_program]()
    suite.test[test_added_fds_diff]()
    suite.test[test_prog_fds_lists_without_programs]()
    suite.test[test_recursion_misses_before_open]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
