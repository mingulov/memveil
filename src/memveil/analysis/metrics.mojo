# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared analysis math: checked sums, floor means, estimated quantiles.

Lifetime quantiles use the frozen 65-bucket integer-nanosecond
histogram: bucket 0 holds 0, bucket b in 1..64 holds
[2^(b-1), 2^b-1]. The estimate for a percentile fraction is the
upper edge of the bucket containing nearest rank ceil(p*n),
computed without overflowing p*n. Estimates always render with
measurement=estimated plus interval and sample-count metadata;
exact mean/count/min/max stay separate rows.
"""

from memveil.model.validate import ValidationError, checked_add


@fieldwise_init
struct MetricsError(Copyable, Writable):
    """One math precondition failure."""

    var message: String


def checked_sum(values: List[UInt64]) raises -> UInt64:
    """Sum with overflow refused instead of wrapped."""
    var acc = UInt64(0)
    for i in range(len(values)):
        acc = checked_add(acc, values[i])
    return acc


def floor_mean(total: UInt64, count: UInt64) raises -> UInt64:
    """Floor-division mean; a zero sample count raises."""
    if count == UInt64(0):
        raise MetricsError("mean of zero samples")
    return total // count


def bucket_of(v: UInt64) -> Int:
    """Histogram bucket for one nanosecond duration."""
    if v == UInt64(0):
        return 0
    var width = 0
    var rest = v
    while rest > UInt64(0):
        width += 1
        rest >>= 1
    return width


def bucket_upper_edge(bucket: Int) -> UInt64:
    """Inclusive upper edge of one histogram bucket."""
    if bucket <= 0:
        return UInt64(0)
    if bucket >= 64:
        return ~UInt64(0)
    return (UInt64(1) << UInt64(bucket)) - UInt64(1)


def estimate_rank(num: Int, den: Int, n: UInt64) raises -> UInt64:
    """Nearest rank ceil(num*n/den) without overflowing num*n.

    Requires 0 < num <= den <= 1000000 and n > 0. The quotient
    splits as q*num + ceil(r*num/den), where each term fits
    because the rank never exceeds n.
    """
    if den <= 0 or num <= 0 or num > den or den > 1000000:
        raise MetricsError("bad percentile fraction")
    if n == UInt64(0):
        raise MetricsError("rank of zero samples")
    var den64 = UInt64(den)
    var num64 = UInt64(num)
    var q = n // den64
    var r = n % den64
    var head = q * num64
    var tail = (r * num64 + den64 - UInt64(1)) // den64
    return head + tail


struct QuantileBuckets:
    """65-bucket integer histogram for estimated quantiles."""

    var _buckets: List[UInt64]
    var _total: UInt64

    def __init__(out self):
        self._buckets = List[UInt64]()
        for _ in range(65):
            self._buckets.append(UInt64(0))
        self._total = UInt64(0)

    def count(self) -> UInt64:
        return self._total

    def add(mut self, v: UInt64) raises:
        var b = bucket_of(v)
        self._buckets[b] = checked_add(self._buckets[b], UInt64(1))
        self._total = checked_add(self._total, UInt64(1))

    def estimate(self, num: Int, den: Int) raises -> UInt64:
        """Upper edge of the bucket holding rank ceil(num*n/den)."""
        var rank = estimate_rank(num, den, self._total)
        var cum = UInt64(0)
        for b in range(65):
            cum += self._buckets[b]
            if cum >= rank:
                return bucket_upper_edge(b)
        raise MetricsError("empty histogram")
