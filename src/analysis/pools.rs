// SPDX-License-Identifier: GPL-3.0-or-later
//! Pool sample tracker and pressure-rule inputs.
//!
//! Each pool id names one pool generation, so streaks never span a
//! re-creation. A sample qualifies only with byte units, a known
//! positive capacity, known usage, and usage at or above 90% of
//! that sample's contemporaneous capacity. Pressure needs three
//! consecutive qualifying samples; a missing half, a zero or
//! unknown capacity, a foreign unit, or a below-threshold reading
//! resets the streak. Each available gauge still lands
//! independently: a missing half resets only the streak, never
//! the known gauge. Pool metrics stay scoped to observed pools:
//! missing pool support never erases allocation evidence and never
//! implies an empty pool. Detail-channel loss (an observed gap or a
//! loss the engine propagates) degrades every gauge to partial:
//! a hidden sample may be the latest one.

use std::collections::BTreeMap;

use crate::model::event::Event;
use crate::model::identity::POOL_MAX;
use crate::model::metric::Metric;
use crate::model::validate::format_u64;

const MAX_POOL_DETAIL: usize = 256;

/// One pool lookup failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolError {
    /// Human-readable failure.
    pub message: String,
}

impl PoolError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for PoolError {}

#[derive(Debug, Clone, Default)]
struct PoolState {
    streak: usize,
    has_used: bool,
    used: u64,
    has_cap: bool,
    cap: u64,
    has_hiwater: bool,
    hiwater: u64,
    samples: usize,
    invalid: usize,
}

/// 90% of capacity without overflow: cap - floor(cap/10).
fn pressure_threshold(capacity: u64) -> u64 {
    capacity - capacity / 10
}

/// Bounded per-generation pool sampling state.
#[derive(Debug, Clone)]
pub struct PoolTracker<const POOL_N: usize = POOL_MAX> {
    pools: BTreeMap<String, PoolState>,
    samples: usize,
    refused: usize,
    detail_loss: bool,
    notes: Vec<String>,
}

impl<const POOL_N: usize> PoolTracker<POOL_N> {
    /// Empty tracker.
    pub fn new() -> Self {
        Self {
            pools: BTreeMap::new(),
            samples: 0,
            refused: 0,
            detail_loss: false,
            notes: Vec::new(),
        }
    }

    /// True once any pool sample was consumed.
    pub fn sees_pools(&self) -> bool {
        self.samples > 0
    }

    /// Break the proved streak: a hidden sample may be below threshold.
    pub fn note_detail_loss(&mut self) {
        self.detail_loss = true;
        for st in self.pools.values_mut() {
            st.streak = 0;
        }
    }

    fn coverage(&self, overlay_detail_loss: bool) -> String {
        if self.detail_loss || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    /// Current proved streak for one pool generation.
    pub fn streak_of(&self, pool: &str) -> Result<usize, PoolError> {
        self.pools
            .get(pool)
            .map(|st| st.streak)
            .ok_or_else(|| PoolError::new(format!("unknown pool {pool}")))
    }

    /// Pool ids with a proved pressure streak, in sorted order.
    pub fn pressured_pools(&self) -> Vec<String> {
        self.pools
            .iter()
            .filter(|(_, st)| st.streak >= 3)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Human-readable bounds/anomaly notes for the report.
    pub fn limitations(&self) -> Vec<String> {
        let mut out = self.notes.clone();
        if self.refused > 0 {
            out.push(format!(
                "{} pool samples refused (pool table exhausted).",
                self.refused
            ));
        }
        let pools = self.pools.len();
        if pools > MAX_POOL_DETAIL {
            out.push(format!(
                "{} pools withheld from per-pool rows ({}-pool detail budget).",
                pools - MAX_POOL_DETAIL,
                MAX_POOL_DETAIL
            ));
        }
        out
    }

    /// Fold one event; samples change state, detail gaps degrade.
    pub fn consume(&mut self, ev: &Event) {
        if ev.kind == "gap" {
            if ev.gap.channel == "detail" {
                self.note_detail_loss();
            }
            return;
        }
        if ev.kind != "pool_sample" {
            return;
        }
        self.samples += 1;
        let pool = ev.pool.pool_id.clone();
        if pool.is_empty() {
            self.note_once("pool sample without identity ignored");
            return;
        }
        if !self.pools.contains_key(&pool) {
            if self.pools.len() >= POOL_N {
                self.refused += 1;
                return;
            }
            self.pools.insert(pool.clone(), PoolState::default());
        }
        if ev.pool.unit != "bytes" {
            if let Some(st) = self.pools.get_mut(&pool) {
                st.samples += 1;
                st.invalid += 1;
                st.streak = 0;
            }
            self.note_once(&format!("non-byte pool sample ignored for {pool}"));
            return;
        }
        let zero_cap = ev.pool.has_capacity && ev.pool.capacity_bytes == 0;
        if zero_cap {
            self.note_once("zero pool capacity cannot form a ratio");
        }
        if let Some(st) = self.pools.get_mut(&pool) {
            st.samples += 1;
            // Each available gauge lands independently; only the
            // pressure streak needs both halves of one sample.
            // Hiwater lands independently too: it is a lifetime
            // mark, not a streak input.
            if ev.pool.has_used {
                st.has_used = true;
                st.used = ev.pool.used_bytes;
            }
            if ev.pool.has_hiwater {
                st.has_hiwater = true;
                st.hiwater = ev.pool.hiwater_bytes;
            }
            let mut usable_cap = false;
            let mut cap = 0u64;
            if ev.pool.has_capacity && !zero_cap {
                st.has_cap = true;
                st.cap = ev.pool.capacity_bytes;
                cap = ev.pool.capacity_bytes;
                usable_cap = true;
            }
            if !ev.pool.has_used || !usable_cap {
                st.invalid += 1;
                st.streak = 0;
                return;
            }
            if ev.pool.used_bytes >= pressure_threshold(cap) {
                st.streak += 1;
            } else {
                st.streak = 0;
            }
        }
    }

    fn note_once(&mut self, text: &str) {
        if !self.notes.iter().any(|n| n == text) {
            self.notes.push(text.to_string());
        }
    }

    /// Per-pool rows in sorted pool order.
    ///
    /// The overlay renders call-local detail uncertainty (a
    /// dropped tail) without latching tracker state: gauge
    /// coverage degrades and the proved streak reads zero in
    /// this view only, so a partial snapshot cannot alter
    /// later facts.
    pub fn metrics(&self, window: &str, overlay_detail_loss: bool) -> Vec<Metric> {
        let mut out = Vec::new();
        let kept = self.pools.len().min(MAX_POOL_DETAIL);
        for (pool, st) in self.pools.iter().take(kept) {
            let scope = format!("{window}; pool {pool}");
            let cov = self.coverage(overlay_detail_loss);
            let (u_measurement, u_coverage, u_agg, u_notes) = if st.has_used {
                (
                    "observed".to_string(),
                    cov.clone(),
                    "gauge".to_string(),
                    "Latest available usage sample.".to_string(),
                )
            } else {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No available usage sample for this pool.".to_string(),
                )
            };
            out.push(Metric {
                name: "pool_used_bytes".to_string(),
                has_value: st.has_used,
                value: st.used,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: u_measurement,
                coverage: u_coverage,
                has_aggregation: !u_agg.is_empty(),
                aggregation: u_agg,
                notes: u_notes,
                has_pool_id: true,
                pool_id: pool.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
            let (c_measurement, c_coverage, c_agg, c_notes) = if st.has_cap {
                (
                    "observed".to_string(),
                    cov.clone(),
                    "gauge".to_string(),
                    "Latest available capacity sample.".to_string(),
                )
            } else {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No available capacity sample for this pool.".to_string(),
                )
            };
            out.push(Metric {
                name: "pool_capacity_bytes".to_string(),
                has_value: st.has_cap,
                value: st.cap,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: c_measurement,
                coverage: c_coverage,
                has_aggregation: !c_agg.is_empty(),
                aggregation: c_agg,
                notes: c_notes,
                has_pool_id: true,
                pool_id: pool.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
            let mut shown_streak = st.streak;
            if overlay_detail_loss {
                shown_streak = 0;
            }
            out.push(Metric {
                name: "pool_pressure_samples".to_string(),
                has_value: true,
                value: shown_streak as u64,
                unit: "count".to_string(),
                confidence: "high".to_string(),
                measurement: "observed".to_string(),
                coverage: cov.clone(),
                has_aggregation: true,
                aggregation: "gauge".to_string(),
                has_pool_id: true,
                pool_id: pool.clone(),
                scope: scope.clone(),
                notes: format!(
                    "Consecutive qualifying samples ({} total, {} invalid); pressure needs 3.",
                    format_u64(st.samples as u64),
                    format_u64(st.invalid as u64)
                ),
                ..Default::default()
            });
            let (h_measurement, h_coverage, h_agg, h_notes) = if st.has_hiwater {
                (
                    "observed".to_string(),
                    cov.clone(),
                    "gauge".to_string(),
                    "Latest allocator high-water mark. Lifetime scope: the sampler never resets it, so the reset epoch is unproved."
                        .to_string(),
                )
            } else {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No high-water sample for this pool.".to_string(),
                )
            };
            out.push(Metric {
                name: "pool_hiwater_bytes".to_string(),
                has_value: st.has_hiwater,
                value: st.hiwater,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: h_measurement,
                coverage: h_coverage,
                has_aggregation: !h_agg.is_empty(),
                aggregation: h_agg,
                notes: h_notes,
                has_pool_id: true,
                pool_id: pool.clone(),
                scope: format!("{scope}; allocator lifetime, reset epoch unproved"),
                ..Default::default()
            });
        }
        out
    }
}

impl<const POOL_N: usize> Default for PoolTracker<POOL_N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event::{Event, Gap, PoolSample};
    use crate::model::metric::Metric;

    fn sample(
        pool: &str,
        has_used: bool,
        used: u64,
        has_cap: bool,
        cap: u64,
        unit: &str,
        seq: u64,
    ) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 1000 + seq,
            kind: "pool_sample".to_string(),
            source_hook: "pool_sampler".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            pool: PoolSample {
                pool_id: pool.to_string(),
                has_used,
                used_bytes: used,
                has_capacity: has_cap,
                capacity_bytes: cap,
                unit: unit.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn gap(channel: &str, seq: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 3000 + seq,
            kind: "gap".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            gap: Gap {
                channel: channel.to_string(),
                has_lost_count: true,
                lost_count: 2,
                reason: "test gap".to_string(),
                window_start_ns: 0,
                window_end_ns: 3000,
            },
            ..Default::default()
        }
    }

    fn find<'a>(metrics: &'a [Metric], name: &str, pool: &str) -> &'a Metric {
        metrics
            .iter()
            .find(|m| m.name == name && m.has_pool_id && m.pool_id == pool)
            .unwrap_or_else(|| panic!("metric not found: {name}"))
    }

    #[test]
    fn pressure_vector() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        assert_eq!(t.pressured_pools().len(), 0);
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 3));
        let hot = t.pressured_pools();
        assert_eq!(hot.len(), 1);
        assert_eq!(hot[0], "p1");
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_pressure_samples", "p1").value, 3);
        assert_eq!(find(&rows, "pool_used_bytes", "p1").confidence, "high");
    }

    #[test]
    fn below_threshold_no_pressure() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 899, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 3));
        assert_eq!(t.pressured_pools().len(), 0);
    }

    #[test]
    fn missing_sample_resets() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        t.consume(&sample("p1", false, 0, true, 1000, "bytes", 3));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 4));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 5));
        assert_eq!(t.pressured_pools().len(), 0);
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 6));
        assert_eq!(t.pressured_pools().len(), 1);
    }

    #[test]
    fn contemporaneous_capacity() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 1800, true, 2000, "bytes", 2));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 3));
        assert_eq!(t.pressured_pools().len(), 1);
    }

    #[test]
    fn generation_scoped_ids() {
        // Two pool ids for successive generations of one source name
        // keep independent streaks.
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1g1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1g1", true, 900, true, 1000, "bytes", 2));
        t.consume(&sample("p1g2", true, 900, true, 1000, "bytes", 3));
        assert_eq!(t.pressured_pools().len(), 0);
        assert_eq!(t.streak_of("p1g1").unwrap(), 2);
        assert_eq!(t.streak_of("p1g2").unwrap(), 1);
    }

    #[test]
    fn zero_capacity_invalid() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 0, true, 0, "bytes", 1));
        let rows = t.metrics("window [0,2000)", false);
        let cap = find(&rows, "pool_capacity_bytes", "p1");
        assert!(!cap.has_value);
        assert_eq!(t.streak_of("p1").unwrap(), 0);
    }

    #[test]
    fn unknown_unit_invalid() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "slots", 1));
        assert_eq!(t.streak_of("p1").unwrap(), 0);
        assert!(!t.limitations().is_empty());
    }

    #[test]
    fn pool_budget() {
        let mut t = PoolTracker::<1>::new();
        t.consume(&sample("p1", true, 1, true, 100, "bytes", 1));
        t.consume(&sample("p2", true, 1, true, 100, "bytes", 2));
        assert_eq!(t.streak_of("p1").unwrap(), 0);
        assert!(t.streak_of("p2").is_err());
        assert!(!t.limitations().is_empty());
    }

    #[test]
    fn pool_table_refusal_visible() {
        let mut t = PoolTracker::<2>::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p2", true, 900, true, 1000, "bytes", 2));
        t.consume(&sample("p3", true, 900, true, 1000, "bytes", 3));
        assert!(!t.limitations().is_empty());
        assert!(t.sees_pools());
    }

    #[test]
    fn latest_values() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 100, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 200, true, 1000, "bytes", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_used_bytes", "p1").value, 200);
        assert_eq!(find(&rows, "pool_capacity_bytes", "p1").value, 1000);
    }

    #[test]
    fn hiwater_gauge() {
        let mut t: PoolTracker = PoolTracker::new();
        let mut first = sample("p1", true, 100, true, 1000, "bytes", 1);
        first.pool.has_hiwater = true;
        first.pool.hiwater_bytes = 400;
        t.consume(&first);
        let rows = t.metrics("window [0,2000)", false);
        let h = find(&rows, "pool_hiwater_bytes", "p1");
        assert!(h.has_value);
        assert_eq!(h.value, 400);
        assert_eq!(h.unit, "bytes");
        assert_eq!(h.confidence, "high");
        // Latest wins; a sample without hiwater keeps the old mark.
        t.consume(&sample("p1", true, 100, true, 1000, "bytes", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_hiwater_bytes", "p1").value, 400);
        let mut second = sample("p1", true, 100, true, 1000, "bytes", 3);
        second.pool.has_hiwater = true;
        second.pool.hiwater_bytes = 500;
        t.consume(&second);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_hiwater_bytes", "p1").value, 500);
    }

    #[test]
    fn detail_gap_degrades_gauges() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&gap("detail", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_used_bytes", "p1").coverage, "partial");
        assert_eq!(find(&rows, "pool_capacity_bytes", "p1").coverage, "partial");
        assert_eq!(
            find(&rows, "pool_pressure_samples", "p1").coverage,
            "partial"
        );
    }

    #[test]
    fn partial_sample_keeps_known_half() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, false, 0, "bytes", 1));
        t.consume(&sample("p2", false, 0, true, 1000, "bytes", 2));
        let rows = t.metrics("window [0,2000)", false);
        let used = find(&rows, "pool_used_bytes", "p1");
        assert!(used.has_value);
        assert_eq!(used.value, 900);
        assert!(!find(&rows, "pool_capacity_bytes", "p1").has_value);
        let cap = find(&rows, "pool_capacity_bytes", "p2");
        assert!(cap.has_value);
        assert_eq!(cap.value, 1000);
        assert!(!find(&rows, "pool_used_bytes", "p2").has_value);
    }

    #[test]
    fn partial_sample_resets_streak() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        assert_eq!(t.streak_of("p1").unwrap(), 2);
        // The known half still lands, but pressure needs both halves.
        t.consume(&sample("p1", true, 950, false, 0, "bytes", 3));
        assert_eq!(t.streak_of("p1").unwrap(), 0);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "pool_used_bytes", "p1").value, 950);
    }

    #[test]
    fn unrelated_gap_keeps_gauges_complete() {
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&gap("aggregate", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(
            find(&rows, "pool_used_bytes", "p1").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn detail_gap_resets_streak() {
        // Streaks never cross a detail gap: a hidden sample may
        // sit below the threshold.
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        assert_eq!(t.streak_of("p1").unwrap(), 2);
        t.consume(&gap("detail", 3));
        assert_eq!(t.streak_of("p1").unwrap(), 0);
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 4));
        assert_eq!(t.streak_of("p1").unwrap(), 1);
        assert_eq!(t.pressured_pools().len(), 0);
    }

    #[test]
    fn threshold_floor_division() {
        // 90% of 1001 is 900.9: the floor-division threshold is
        // 901, so 900 does not qualify but 901 does.
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1001, "bytes", 1));
        assert_eq!(t.streak_of("p1").unwrap(), 0);
        t.consume(&sample("p1", true, 901, true, 1001, "bytes", 2));
        assert_eq!(t.streak_of("p1").unwrap(), 1);
    }

    #[test]
    fn over_capacity_counts() {
        // Usage at or above the threshold qualifies, even past
        // nominal capacity: over-capacity is pressure, not a reset.
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 1100, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 1100, true, 1000, "bytes", 2));
        t.consume(&sample("p1", true, 1100, true, 1000, "bytes", 3));
        assert_eq!(t.pressured_pools().len(), 1);
    }

    #[test]
    fn aggregate_gap_keeps_streak() {
        // Only the sample stream's own channel breaks streaks:
        // an aggregate gap leaves the streak and gauges alone.
        let mut t: PoolTracker = PoolTracker::new();
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 1));
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 2));
        t.consume(&gap("aggregate", 3));
        assert_eq!(t.streak_of("p1").unwrap(), 2);
        t.consume(&sample("p1", true, 900, true, 1000, "bytes", 4));
        assert_eq!(t.pressured_pools().len(), 1);
    }
}
