"""Monotonic clock smoke plus timens offset vectors."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.clock import (
    MonoClock,
    check_timens_live,
    timens_has_offset,
)


def _body(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    return out^


def test_clean_offsets() raises:
    var clean = _body(
        String("monotonic           0         0\nboottime            0         0\n")
    )
    assert_true(not timens_has_offset(Span(clean)))
    var empty = List[UInt8]()
    assert_true(not timens_has_offset(Span(empty)))


def test_offset_vectors() raises:
    var shifted = _body(String("monotonic           0         0\nboottime         3600         0\n"))
    assert_true(timens_has_offset(Span(shifted)))
    var negative = _body(String("monotonic          -5         0\n"))
    assert_true(timens_has_offset(Span(negative)))
    var words_only = _body(String("monotonic boottime\n"))
    assert_true(not timens_has_offset(Span(words_only)))
    var minus_zero = _body(String("monotonic          -0         0\n"))
    assert_true(not timens_has_offset(Span(minus_zero)))
    var decimal = _body(String("monotonic         1.5         0\n"))
    # "1.5" is not an integer token, so it cannot be an offset.
    assert_true(not timens_has_offset(Span(decimal)))


def test_clock_live() raises:
    var clock = MonoClock()
    var t0 = clock.now()
    assert_true(t0 > UInt64(0))
    clock.sleep_ms(5)
    var t1 = clock.now()
    assert_true(t1 >= t0)


def test_timens_live_readable() raises:
    var out = check_timens_live()
    assert_true(out.ok)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_clean_offsets]()
    suite.test[test_offset_vectors]()
    suite.test[test_clock_live]()
    suite.test[test_timens_live_readable]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
