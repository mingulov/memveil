# SPDX-License-Identifier: GPL-3.0-or-later

"""Top unit tests: durations, arguments, refresh boundaries.

Durations share the capture options' checked rules (strict
decimal, refused overflow) with s/m/h units. Refresh
boundaries split the capture window into interval horizons;
the final snapshot always covers the whole window.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.cli.durations import parse_duration_ns
from memveil.cli.top import (
    BoundaryCursor,
    TopOptions,
    _wait_interval,
    _wait_slices,
    parse_top_args,
)
from memveil.platform.clock import MonoClock
from memveil.platform.signal import LiveSignalSource


def test_duration_units() raises:
    assert_equal(parse_duration_ns("1s"), UInt64(1000000000))
    assert_equal(parse_duration_ns("2m"), UInt64(120000000000))
    assert_equal(parse_duration_ns("1h"), UInt64(3600000000000))
    assert_equal(parse_duration_ns("5"), UInt64(5000000000))


def test_duration_rejects() raises:
    for bad in range(6):
        var text = String("0s")
        if bad == 1:
            text = String("01s")
        elif bad == 2:
            text = String("1x")
        elif bad == 3:
            text = String("")
        elif bad == 4:
            text = String("99999999999999999999h")
        elif bad == 5:
            text = String("18446744073709551615s")
        var raised = False
        try:
            _ = parse_duration_ns(text)
        except:
            raised = True
        assert_true(raised)


def _args(first: String, second: String) -> List[String]:
    var out = List[String]()
    if first != "":
        out.append(first)
    if second != "":
        out.append(second)
    return out^


def test_top_defaults() raises:
    var args = _args("capdir", "")
    var opts = parse_top_args(args)
    assert_equal(opts.interval_ns, UInt64(1000000000))
    assert_true(not opts.has_device)
    assert_true(not opts.has_long_lived_after)
    assert_equal(opts.dir, String("capdir"))


def test_top_flags() raises:
    var args = List[String]()
    args.append(String("--interval"))
    args.append(String("2s"))
    args.append(String("--device"))
    args.append(String("d000001"))
    args.append(String("--long-lived-after"))
    args.append(String("1m"))
    args.append(String("capdir"))
    var opts = parse_top_args(args)
    assert_equal(opts.interval_ns, UInt64(2000000000))
    assert_true(opts.has_device)
    assert_equal(opts.device, String("d000001"))
    assert_true(opts.has_long_lived_after)
    assert_equal(opts.long_lived_after_ns, UInt64(60000000000))


def test_top_arg_errors() raises:
    var raised = False
    try:
        var empty = List[String]()
        _ = parse_top_args(empty)
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        var args = List[String]()
        args.append(String("--interval"))
        args.append(String("nope"))
        args.append(String("capdir"))
        _ = parse_top_args(args)
    except:
        raised = True
    assert_true(raised)
    raised = False
    try:
        var args = List[String]()
        args.append(String("--nope"))
        args.append(String("capdir"))
        _ = parse_top_args(args)
    except:
        raised = True
    assert_true(raised)


def test_boundaries() raises:
    var cur = BoundaryCursor(
        UInt64(0), UInt64(2300000000), UInt64(1000000000)
    )
    assert_true(not cur.has_due(UInt64(999999999)))
    assert_true(cur.has_due(UInt64(1000000000)))
    assert_equal(cur.pop(), UInt64(1000000000))
    assert_true(not cur.has_due(UInt64(1999999999)))
    assert_true(cur.has_due(UInt64(2000000000)))
    assert_equal(cur.pop(), UInt64(2000000000))
    assert_true(not cur.has_due(~UInt64(0)))
    var none = BoundaryCursor(
        UInt64(500), UInt64(500), UInt64(1000000000)
    )
    assert_true(not none.has_due(~UInt64(0)))
    var short = BoundaryCursor(
        UInt64(0), UInt64(999), UInt64(1000000000)
    )
    assert_true(not short.has_due(~UInt64(0)))
    var zero = BoundaryCursor(
        UInt64(0), UInt64(2300000000), UInt64(0)
    )
    assert_true(not zero.has_due(~UInt64(0)))


def _raise_self(signo: Int):
    _ = external_call["raise", Int32](Int32(signo))


def test_wait_slices_bounded() raises:
    var parts = _wait_slices(250)
    assert_equal(len(parts), 3)
    assert_equal(parts[0], 100)
    assert_equal(parts[1], 100)
    assert_equal(parts[2], 50)
    assert_equal(len(_wait_slices(0)), 0)
    assert_equal(len(_wait_slices(-5)), 0)
    var hour = _wait_slices(3600000)
    assert_equal(len(hour), 36000)
    var total = 0
    for i in range(len(hour)):
        assert_true(hour[i] <= 100)
        total += hour[i]
    assert_equal(total, 3600000)


def test_wait_interval_polls_before_sleep() raises:
    var clock = MonoClock()
    var src = LiveSignalSource()
    var setup = src.setup()
    assert_true(setup.ok)
    # A signal already pending when the wait starts returns at
    # once instead of sleeping first: an hour-long wait with a
    # pending stop returns "pending", never after an hour.
    _raise_self(2)
    var got = _wait_interval(clock, src, 3600000)
    assert_equal(got.state, String("pending"))
    src.teardown()


def test_wait_interval_quiet_waits_full() raises:
    var clock = MonoClock()
    var src = LiveSignalSource()
    var setup = src.setup()
    assert_true(setup.ok)
    var got = _wait_interval(clock, src, 0)
    assert_equal(got.state, String("none"))
    src.teardown()


def test_cursor_streams_long_window() raises:
    # A full-range window at unit interval would materialize 2^64
    # horizons as a list; the cursor yields them one at a time
    # with constant memory, so this completes at all.
    var cur = BoundaryCursor(
        UInt64(0), ~UInt64(0), UInt64(1)
    )
    assert_true(not cur.has_due(UInt64(0)))
    assert_true(cur.has_due(UInt64(1)))
    assert_equal(cur.pop(), UInt64(1))
    assert_equal(cur.pop(), UInt64(2))
    assert_equal(cur.pop(), UInt64(3))
    assert_true(cur.has_due(UInt64(4)))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_duration_units]()
    suite.test[test_duration_rejects]()
    suite.test[test_top_defaults]()
    suite.test[test_top_flags]()
    suite.test[test_top_arg_errors]()
    suite.test[test_boundaries]()
    suite.test[test_cursor_streams_long_window]()
    suite.test[test_wait_slices_bounded]()
    suite.test[test_wait_interval_polls_before_sleep]()
    suite.test[test_wait_interval_quiet_waits_full]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
