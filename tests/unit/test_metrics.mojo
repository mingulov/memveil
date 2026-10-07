# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared analysis math: checked sums, floor means, estimated quantiles.

Lifetime quantiles use the frozen 65-bucket integer-nanosecond
histogram: bucket 0 holds 0, bucket b in 1..64 holds
[2^(b-1), 2^b-1]. The estimate for p is the upper edge of the
bucket containing nearest rank ceil(p*n), labeled estimated.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.analysis.metrics import (
    QuantileBuckets,
    bucket_of,
    bucket_upper_edge,
    checked_sum,
    estimate_rank,
    floor_mean,
)


def u64max() -> UInt64:
    """All-ones UInt64 without an out-of-range literal."""
    return ~UInt64(0)


def _u64_list(a: UInt64, b: UInt64, c: UInt64) -> List[UInt64]:
    var out = List[UInt64]()
    out.append(a)
    out.append(b)
    out.append(c)
    return out^


def test_checked_sum_ok() raises:
    assert_equal(checked_sum(_u64_list(UInt64(1), UInt64(2), UInt64(3))), UInt64(6))
    var empty = List[UInt64]()
    assert_equal(checked_sum(empty), UInt64(0))


def test_checked_sum_overflow() raises:
    var vals = List[UInt64]()
    vals.append(u64max())
    vals.append(UInt64(1))
    var raised = False
    try:
        _ = checked_sum(vals)
    except:
        raised = True
    assert_true(raised)


def test_floor_mean() raises:
    assert_equal(floor_mean(UInt64(9), UInt64(4)), UInt64(2))
    assert_equal(floor_mean(UInt64(0), UInt64(3)), UInt64(0))
    var raised = False
    try:
        _ = floor_mean(UInt64(1), UInt64(0))
    except:
        raised = True
    assert_true(raised)


def test_bucket_of() raises:
    assert_equal(bucket_of(UInt64(0)), 0)
    assert_equal(bucket_of(UInt64(1)), 1)
    assert_equal(bucket_of(UInt64(2)), 2)
    assert_equal(bucket_of(UInt64(3)), 2)
    assert_equal(bucket_of(UInt64(4)), 3)
    assert_equal(bucket_of(UInt64(7)), 3)
    assert_equal(bucket_of(UInt64(8)), 4)
    assert_equal(bucket_of(u64max()), 64)


def test_bucket_upper_edge() raises:
    assert_equal(bucket_upper_edge(0), UInt64(0))
    assert_equal(bucket_upper_edge(1), UInt64(1))
    assert_equal(bucket_upper_edge(2), UInt64(3))
    assert_equal(bucket_upper_edge(3), UInt64(7))
    assert_equal(bucket_upper_edge(64), u64max())


def test_estimate_rank() raises:
    # ceil(50*4/100) = 2, ceil(99*4/100) = 4.
    assert_equal(estimate_rank(50, 100, UInt64(4)), UInt64(2))
    assert_equal(estimate_rank(99, 100, UInt64(4)), UInt64(4))
    assert_equal(estimate_rank(50, 100, UInt64(1)), UInt64(1))
    # No overflow for p*n near the u64 ceiling: ceil(99*n/100)
    # equals n - floor(n/100).
    assert_equal(
        estimate_rank(99, 100, u64max()), UInt64(18262276632972456099)
    )
    var raised = False
    try:
        _ = estimate_rank(50, 100, UInt64(0))
    except:
        raised = True
    assert_true(raised)


def test_histogram_lifetime_vector() raises:
    # Contract vector: [1,2,3,4] -> p50 estimated 3, p99 estimated 7.
    var h = QuantileBuckets()
    h.add(UInt64(1))
    h.add(UInt64(2))
    h.add(UInt64(3))
    h.add(UInt64(4))
    assert_equal(h.count(), UInt64(4))
    assert_equal(h.estimate(50, 100), UInt64(3))
    assert_equal(h.estimate(99, 100), UInt64(7))


def test_histogram_single_zero() raises:
    var h = QuantileBuckets()
    h.add(UInt64(0))
    assert_equal(h.estimate(50, 100), UInt64(0))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_checked_sum_ok]()
    suite.test[test_checked_sum_overflow]()
    suite.test[test_floor_mean]()
    suite.test[test_bucket_of]()
    suite.test[test_bucket_upper_edge]()
    suite.test[test_estimate_rank]()
    suite.test[test_histogram_lifetime_vector]()
    suite.test[test_histogram_single_zero]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
