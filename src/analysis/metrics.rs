// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared analysis math: checked sums, floor means, estimated quantiles.
//!
//! Lifetime quantiles use the frozen 65-bucket integer-nanosecond
//! histogram: bucket 0 holds 0, bucket b in 1..64 holds
//! [2^(b-1), 2^b-1]. The estimate for a percentile fraction is the
//! upper edge of the bucket containing nearest rank ceil(p*n),
//! computed without overflowing p*n. Estimates always render with
//! measurement=estimated plus interval and sample-count metadata;
//! exact mean/count/min/max stay separate rows.

use crate::model::validate::checked_add;

/// One math precondition failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricsError {
    /// Human-readable failure.
    pub message: String,
}

impl MetricsError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MetricsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MetricsError {}

/// Sum with overflow refused instead of wrapped.
pub fn checked_sum(values: &[u64]) -> Result<u64, MetricsError> {
    let mut acc = 0u64;
    for v in values {
        acc = checked_add(acc, *v).map_err(|e| MetricsError::new(e.message))?;
    }
    Ok(acc)
}

/// Floor-division mean; a zero sample count raises.
pub fn floor_mean(total: u64, count: u64) -> Result<u64, MetricsError> {
    if count == 0 {
        return Err(MetricsError::new("mean of zero samples"));
    }
    Ok(total / count)
}

/// Histogram bucket for one nanosecond duration.
pub fn bucket_of(v: u64) -> usize {
    if v == 0 {
        return 0;
    }
    (u64::BITS - v.leading_zeros()) as usize
}

/// Inclusive upper edge of one histogram bucket.
pub fn bucket_upper_edge(bucket: usize) -> u64 {
    if bucket == 0 {
        return 0;
    }
    if bucket >= 64 {
        return u64::MAX;
    }
    (1u64 << bucket) - 1
}

/// Nearest rank ceil(num*n/den) without overflowing num*n.
///
/// Requires 0 < num <= den <= 1000000 and n > 0. The quotient
/// splits as q*num + ceil(r*num/den), where each term fits
/// because the rank never exceeds n.
pub fn estimate_rank(num: i64, den: i64, n: u64) -> Result<u64, MetricsError> {
    if den <= 0 || num <= 0 || num > den || den > 1000000 {
        return Err(MetricsError::new("bad percentile fraction"));
    }
    if n == 0 {
        return Err(MetricsError::new("rank of zero samples"));
    }
    let den64 = den as u64;
    let num64 = num as u64;
    let q = n / den64;
    let r = n % den64;
    let head = q * num64;
    let tail = (r * num64).div_ceil(den64);
    Ok(head + tail)
}

/// 65-bucket integer histogram for estimated quantiles.
#[derive(Debug, Clone)]
pub struct QuantileBuckets {
    buckets: [u64; 65],
    total: u64,
}

impl QuantileBuckets {
    /// Empty histogram.
    pub fn new() -> Self {
        Self {
            buckets: [0; 65],
            total: 0,
        }
    }

    /// Samples recorded.
    pub fn count(&self) -> u64 {
        self.total
    }

    /// Record one duration.
    pub fn add(&mut self, v: u64) -> Result<(), MetricsError> {
        let b = bucket_of(v);
        self.buckets[b] =
            checked_add(self.buckets[b], 1).map_err(|e| MetricsError::new(e.message))?;
        self.total = checked_add(self.total, 1).map_err(|e| MetricsError::new(e.message))?;
        Ok(())
    }

    /// Upper edge of the bucket holding rank ceil(num*n/den).
    pub fn estimate(&self, num: i64, den: i64) -> Result<u64, MetricsError> {
        let rank = estimate_rank(num, den, self.total)?;
        let mut cum = 0u64;
        for (b, count) in self.buckets.iter().enumerate() {
            cum += *count;
            if cum >= rank {
                return Ok(bucket_upper_edge(b));
            }
        }
        Err(MetricsError::new("empty histogram"))
    }
}

impl Default for QuantileBuckets {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_sum_ok() {
        assert_eq!(checked_sum(&[1, 2, 3]).unwrap(), 6);
        let empty: [u64; 0] = [];
        assert_eq!(checked_sum(&empty).unwrap(), 0);
    }

    #[test]
    fn checked_sum_overflow() {
        assert!(checked_sum(&[u64::MAX, 1]).is_err());
    }

    #[test]
    fn floor_mean_basic() {
        assert_eq!(floor_mean(9, 4).unwrap(), 2);
        assert_eq!(floor_mean(0, 3).unwrap(), 0);
        assert!(floor_mean(1, 0).is_err());
    }

    #[test]
    fn bucket_of_edges() {
        assert_eq!(bucket_of(0), 0);
        assert_eq!(bucket_of(1), 1);
        assert_eq!(bucket_of(2), 2);
        assert_eq!(bucket_of(3), 2);
        assert_eq!(bucket_of(4), 3);
        assert_eq!(bucket_of(7), 3);
        assert_eq!(bucket_of(8), 4);
        assert_eq!(bucket_of(u64::MAX), 64);
    }

    #[test]
    fn bucket_upper_edge_values() {
        assert_eq!(bucket_upper_edge(0), 0);
        assert_eq!(bucket_upper_edge(1), 1);
        assert_eq!(bucket_upper_edge(2), 3);
        assert_eq!(bucket_upper_edge(3), 7);
        assert_eq!(bucket_upper_edge(64), u64::MAX);
    }

    #[test]
    fn estimate_rank_values() {
        // ceil(50*4/100) = 2, ceil(99*4/100) = 4.
        assert_eq!(estimate_rank(50, 100, 4).unwrap(), 2);
        assert_eq!(estimate_rank(99, 100, 4).unwrap(), 4);
        assert_eq!(estimate_rank(50, 100, 1).unwrap(), 1);
        // No overflow for p*n near the u64 ceiling: ceil(99*n/100)
        // equals n - floor(n/100).
        assert_eq!(
            estimate_rank(99, 100, u64::MAX).unwrap(),
            18262276632972456099
        );
        assert!(estimate_rank(50, 100, 0).is_err());
        assert!(estimate_rank(0, 100, 4).is_err());
        assert!(estimate_rank(101, 100, 4).is_err());
        assert!(estimate_rank(50, 0, 4).is_err());
    }

    #[test]
    fn histogram_lifetime_vector() {
        // Contract vector: [1,2,3,4] -> p50 estimated 3, p99 estimated 7.
        let mut h = QuantileBuckets::new();
        h.add(1).unwrap();
        h.add(2).unwrap();
        h.add(3).unwrap();
        h.add(4).unwrap();
        assert_eq!(h.count(), 4);
        assert_eq!(h.estimate(50, 100).unwrap(), 3);
        assert_eq!(h.estimate(99, 100).unwrap(), 7);
    }

    #[test]
    fn histogram_single_zero() {
        let mut h = QuantileBuckets::new();
        h.add(0).unwrap();
        assert_eq!(h.estimate(50, 100).unwrap(), 0);
    }
}
