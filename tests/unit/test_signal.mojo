"""Pure signal-source tests: read classifier + mask bits.

No signals are raised here; live signalfd behavior runs
in the signals lane via tests/unit/signal_probe.mojo.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.signal import (
    READ_ERROR,
    READ_NONE,
    READ_PENDING,
    READ_RETRY,
    blocked_mask,
    classify_signal_read,
)


def test_classify() raises:
    assert_equal(classify_signal_read(128, 0), READ_PENDING)
    assert_equal(classify_signal_read(1, 0), READ_PENDING)
    assert_equal(classify_signal_read(-1, 11), READ_NONE)
    assert_equal(classify_signal_read(-1, 4), READ_RETRY)
    assert_equal(classify_signal_read(-1, 5), READ_ERROR)
    assert_equal(classify_signal_read(-1, 9), READ_ERROR)
    assert_equal(classify_signal_read(0, 0), READ_ERROR)


def test_mask_bits() raises:
    var mask = blocked_mask()
    assert_equal(len(mask), 128)
    assert_equal(Int(mask[0]), 0x02)
    assert_equal(Int(mask[1]), 0x40)
    for i in range(2, len(mask)):
        assert_equal(Int(mask[i]), 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_classify]()
    suite.test[test_mask_bits]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
