// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded region-state tracker over conversion observations.
//!
//! Each (identity, namespace, generation) triple names one proved
//! region lineage; split/merge of half-open intervals happens
//! only within that lineage, never across namespaces. Successful
//! resolved guest-physical transitions move intervals between
//! known shared and private; a failure without rollback proof
//! leaves its interval unknown; unresolved, identity-only, or
//! ordinary-kernel no-op requests count as requests without any
//! state transition. Mapping, copy, pool, and counter events
//! never touch region state.
//!
//! Unions cover guest-physical intervals only and sum disjoint
//! tracked intervals per proved identity; distinct identities
//! are assumed disjoint by the producer. A total that would
//! cover unknown intervals stays unavailable: known subsets
//! report with explicit partial scope instead. Detail loss
//! degrades counters and withholds current unions; baseline loss
//! degrades the unions alone, since observed transitions still count.

use std::collections::BTreeMap;

use crate::model::event::Event;
use crate::model::identity::REGION_MAX;
use crate::model::metric::Metric;
use crate::model::regions::RegionObservation;
use crate::model::validate::format_u64;

/// Global interval-segment budget.
pub const SEGMENTS_MAX: usize = 65536;

const UNKNOWN: u8 = 0;
const SHARED: u8 = 1;
const PRIVATE: u8 = 2;

#[derive(Debug, Clone, Copy, Default)]
struct Segment {
    start: u64,
    end: u64,
    state: u8,
}

fn append_merged(segments: &mut Vec<Segment>, segment: Segment) {
    if let Some(last) = segments.last_mut()
        && last.end == segment.start
        && last.state == segment.state
    {
        last.end = segment.end;
        return;
    }
    segments.push(segment);
}

fn assign(segments: &mut Vec<Segment>, start: u64, end: u64, state: u8, capacity: usize) -> bool {
    // Sorted disjoint intervals permit a bounded splice without rebuilding.
    let n = segments.len();
    let mut lo = 0;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if segments[mid].end <= start {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut first = lo;
    hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if segments[mid].start < end {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    let mut last = lo;
    let mut replacement: Vec<Segment> = Vec::with_capacity(3);
    if first < last && segments[first].start < start {
        let s = segments[first];
        append_merged(
            &mut replacement,
            Segment {
                start: s.start,
                end: start,
                state: s.state,
            },
        );
    }
    append_merged(&mut replacement, Segment { start, end, state });
    if first < last && segments[last - 1].end > end {
        let s = segments[last - 1];
        append_merged(
            &mut replacement,
            Segment {
                start: end,
                end: s.end,
                state: s.state,
            },
        );
    }
    if first > 0
        && segments[first - 1].end == replacement[0].start
        && segments[first - 1].state == replacement[0].state
    {
        first -= 1;
        replacement[0].start = segments[first].start;
    }
    let tail = replacement.len() - 1;
    if last < n
        && replacement[tail].end == segments[last].start
        && replacement[tail].state == segments[last].state
    {
        replacement[tail].end = segments[last].end;
        last += 1;
    }
    let size = n - (last - first) + replacement.len();
    if size > capacity {
        return false;
    }
    segments.splice(first..last, replacement);
    true
}

/// Bounded per-lineage interval state plus request counts.
#[derive(Debug, Clone)]
pub struct RegionTracker<const REGION_N: usize = REGION_MAX, const SEG_N: usize = SEGMENTS_MAX> {
    admitted: bool,
    baseline_complete: bool,
    index: BTreeMap<String, usize>,
    claimed: BTreeMap<String, String>,
    namespaces: Vec<String>,
    invalid: Vec<bool>,
    segments: Vec<Vec<Segment>>,
    segment_count: usize,
    storage_peaks: Vec<usize>,
    requests: usize,
    failures: usize,
    request_bytes: u64,
    bytes_overflow: bool,
    refused: usize,
    contradictions: usize,
    invalidated: usize,
    opaque: usize,
    saw_transition: bool,
    seeded: bool,
    detail_loss: bool,
    baseline_loss: bool,
    notes: Vec<String>,
}

impl<const REGION_N: usize, const SEG_N: usize> RegionTracker<REGION_N, SEG_N> {
    /// Empty tracker over one admission decision.
    pub fn new(transitions_admitted: bool, baseline_complete: bool) -> Self {
        Self {
            admitted: transitions_admitted,
            baseline_complete,
            index: BTreeMap::new(),
            claimed: BTreeMap::new(),
            namespaces: Vec::new(),
            invalid: Vec::new(),
            segments: Vec::new(),
            segment_count: 0,
            storage_peaks: Vec::new(),
            requests: 0,
            failures: 0,
            request_bytes: 0,
            bytes_overflow: false,
            refused: 0,
            contradictions: 0,
            invalidated: 0,
            opaque: 0,
            saw_transition: false,
            seeded: false,
            detail_loss: false,
            baseline_loss: false,
            notes: Vec::new(),
        }
    }

    /// True once a transition, baseline seed, or note was observed.
    pub fn sees_regions(&self) -> bool {
        self.saw_transition || self.seeded || !self.notes.is_empty()
    }

    /// Withhold current unions: an unseen transition can replace state.
    pub fn note_detail_loss(&mut self) {
        self.detail_loss = true;
    }

    /// Degrade unions alone: seeded state may be incomplete.
    pub fn note_baseline_loss(&mut self) {
        self.baseline_loss = true;
    }

    fn counter_coverage(&self, overlay_detail_loss: bool) -> String {
        if self.detail_loss || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    /// Human-readable bounds/anomaly notes for the report.
    pub fn limitations(&self) -> Vec<String> {
        let mut out = self.notes.clone();
        if self.refused > 0 {
            out.push(format!(
                "{} region observations refused (region table exhausted).",
                self.refused
            ));
        }
        if self.contradictions > 0 {
            out.push(format!(
                "{} region observations refused (token reused across namespaces).",
                self.contradictions
            ));
        }
        if self.invalidated > 0 {
            out.push(format!(
                "{} regions invalidated (interval budget exceeded; affected state excluded, never merged).",
                self.invalidated
            ));
        }
        if self.opaque > 0 {
            out.push(format!(
                "{} transition results carried no usable state; unions exclude them, never assume them.",
                self.opaque
            ));
        }
        out
    }

    /// Apply producer-attested initial intervals in listed order.
    pub fn seed_baseline(&mut self, obs: &[RegionObservation]) {
        if !obs.is_empty() {
            self.seeded = true;
        }
        if !self.admitted {
            if !obs.is_empty() {
                self.note_once(
                    "baseline observations ignored: region state unavailable on this profile",
                );
            }
            return;
        }
        for o in obs {
            let idx = self.region_for(&o.region_id, &o.address_space, o.generation);
            let Some(idx) = idx else {
                continue;
            };
            if o.length > u64::MAX - o.offset {
                self.note_once("baseline span overflows; interval ignored for state");
                continue;
            }
            let end = o.offset + o.length;
            self.apply(idx, o.offset, end, &o.state);
        }
    }

    /// Fold one event; transitions change state, gaps degrade.
    pub fn consume(&mut self, ev: &Event) {
        if ev.kind == "gap" {
            if ev.gap.channel == "detail" {
                self.note_detail_loss();
            } else if ev.gap.channel == "baseline" {
                self.note_baseline_loss();
            }
            return;
        }
        if ev.kind != "transition_result" {
            return;
        }
        self.saw_transition = true;
        self.requests += 1;
        if !ev.transition.success {
            self.failures += 1;
        }
        if !self.bytes_overflow {
            if ev.transition.length > u64::MAX - self.request_bytes {
                self.bytes_overflow = true;
            } else {
                self.request_bytes += ev.transition.length;
            }
        }
        if !self.admitted {
            return;
        }
        if !ev.transition.has_resolution {
            self.opaque += 1;
            return;
        }
        if ev.transition.resolution != "resolved" {
            self.opaque += 1;
            return;
        }
        if !ev.transition.has_address_space {
            self.opaque += 1;
            return;
        }
        let space = ev.transition.address_space.clone();
        if space == "identity_only" {
            self.opaque += 1;
            return;
        }
        if ev.transition.length > u64::MAX - ev.transition.offset {
            self.note_once("transition span overflows; ignored for state");
            self.opaque += 1;
            return;
        }
        let idx = self.region_for(&ev.transition.region_id, &space, ev.transition.generation);
        let Some(idx) = idx else {
            return;
        };
        let end = ev.transition.offset + ev.transition.length;
        if ev.transition.success {
            let state = ev.transition.requested_state.clone();
            self.apply(idx, ev.transition.offset, end, &state);
        } else {
            self.apply(idx, ev.transition.offset, end, "unknown");
        }
    }

    /// Request counts plus guest-physical state rows.
    ///
    /// Counters need transition evidence of their own: a
    /// seeded baseline proves state, never request counts.
    /// The overlay renders call-local detail uncertainty (a
    /// dropped tail) without latching tracker state, so a
    /// partial snapshot cannot alter later facts.
    pub fn metrics(&self, window: &str, overlay_detail_loss: bool) -> Vec<Metric> {
        let mut out = Vec::new();
        if !self.sees_regions() {
            return out;
        }
        if !self.saw_transition {
            out.push(self.unavailable_counter("conversion_requests", "count", window));
            out.push(self.unavailable_counter("conversion_failures", "count", window));
            out.push(self.unavailable_counter("conversion_request_bytes", "bytes", window));
        } else {
            let ccov = self.counter_coverage(overlay_detail_loss);
            out.push(Metric {
                name: "conversion_requests".to_string(),
                has_value: true,
                value: self.requests as u64,
                unit: "count".to_string(),
                confidence: "high".to_string(),
                measurement: "observed".to_string(),
                coverage: ccov.clone(),
                has_aggregation: true,
                aggregation: "counter".to_string(),
                scope: window.to_string(),
                notes: "Observed conversion API results; requests are not bytes.".to_string(),
                ..Default::default()
            });
            out.push(Metric {
                name: "conversion_failures".to_string(),
                has_value: true,
                value: self.failures as u64,
                unit: "count".to_string(),
                confidence: "high".to_string(),
                measurement: "observed".to_string(),
                coverage: ccov.clone(),
                has_aggregation: true,
                aggregation: "counter".to_string(),
                scope: window.to_string(),
                notes: "Failed conversion requests; affected intervals stay unknown without rollback proof."
                    .to_string(),
                ..Default::default()
            });
            let (rb_measurement, rb_coverage, rb_agg, rb_notes) = if self.bytes_overflow {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "Requested lengths exceed u64 range; total withheld.".to_string(),
                )
            } else {
                (
                    "observed".to_string(),
                    ccov.clone(),
                    "counter".to_string(),
                    "Sum of requested lengths, not unique physical bytes.".to_string(),
                )
            };
            out.push(Metric {
                name: "conversion_request_bytes".to_string(),
                has_value: !self.bytes_overflow,
                value: self.request_bytes,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: rb_measurement,
                coverage: rb_coverage,
                has_aggregation: !rb_agg.is_empty(),
                aggregation: rb_agg,
                notes: rb_notes,
                scope: window.to_string(),
                ..Default::default()
            });
        }
        let scope = format!("{window}; guest-physical regions");
        if !self.admitted {
            let why = "ordinary profile: conversions are no-ops; no state transition applies";
            out.push(self.unavailable_state("known_shared_region_bytes", &scope, why));
            out.push(self.unavailable_state("known_private_region_bytes", &scope, why));
            out.push(self.unavailable_state("unknown_region_bytes", &scope, why));
            return out;
        }
        if !self.baseline_complete {
            let why = "baseline incomplete: pre-existing state unknown";
            out.push(self.unavailable_state("known_shared_region_bytes", &scope, why));
            out.push(self.unavailable_state("known_private_region_bytes", &scope, why));
            out.push(self.unavailable_state("unknown_region_bytes", &scope, why));
            return out;
        }
        let mut shared = 0u64;
        let mut private = 0u64;
        let mut unknown = 0u64;
        let mut overflow = false;
        for (idx, segs) in self.segments.iter().enumerate() {
            if self.invalid[idx] || self.namespaces[idx] != "guest_physical" {
                continue;
            }
            for s in segs {
                let n = s.end - s.start;
                if s.state == SHARED {
                    if n > u64::MAX - shared {
                        overflow = true;
                    } else {
                        shared += n;
                    }
                } else if s.state == PRIVATE {
                    if n > u64::MAX - private {
                        overflow = true;
                    } else {
                        private += n;
                    }
                } else if n > u64::MAX - unknown {
                    overflow = true;
                } else {
                    unknown += n;
                }
            }
        }
        let partial = unknown > 0
            || self.refused > 0
            || self.contradictions > 0
            || self.invalidated > 0
            || self.opaque > 0
            || self.detail_loss
            || overlay_detail_loss
            || self.baseline_loss;
        out.push(self.union_row(
            "known_shared_region_bytes",
            &scope,
            shared,
            unknown,
            overflow,
            partial,
            "known-shared",
            overlay_detail_loss,
        ));
        out.push(self.union_row(
            "known_private_region_bytes",
            &scope,
            private,
            unknown,
            overflow,
            partial,
            "known-private",
            overlay_detail_loss,
        ));
        out.push(self.union_row(
            "unknown_region_bytes",
            &scope,
            unknown,
            unknown,
            overflow,
            partial,
            "unknown-state",
            overlay_detail_loss,
        ));
        out
    }

    #[allow(clippy::too_many_arguments)]
    fn union_row(
        &self,
        name: &str,
        scope: &str,
        value: u64,
        unknown: u64,
        overflow: bool,
        partial: bool,
        what: &str,
        overlay_detail_loss: bool,
    ) -> Metric {
        if self.detail_loss || overlay_detail_loss {
            return Metric {
                name: name.to_string(),
                unit: "bytes".to_string(),
                scope: scope.to_string(),
                confidence: "medium".to_string(),
                has_value: false,
                measurement: "unavailable".to_string(),
                coverage: "unavailable".to_string(),
                notes: "Detail loss may hide a shared/private transition; current region state is unknown, not zero."
                    .to_string(),
                ..Default::default()
            };
        }
        if overflow {
            return Metric {
                name: name.to_string(),
                unit: "bytes".to_string(),
                scope: scope.to_string(),
                confidence: "medium".to_string(),
                has_value: false,
                measurement: "unavailable".to_string(),
                coverage: "unavailable".to_string(),
                notes: "Tracked bytes exceed u64 range; total withheld.".to_string(),
                ..Default::default()
            };
        }
        let (coverage, notes) = if partial {
            let mut note = format!(
                "Sum over proved identities of disjoint {what} guest-physical intervals; excludes {} unknown-state bytes and any refused or invalidated state.",
                format_u64(unknown)
            );
            if self.opaque > 0 {
                note += &format!(
                    " {} transition results carried no usable state.",
                    self.opaque
                );
            }
            ("partial".to_string(), note)
        } else {
            (
                "complete_for_scope".to_string(),
                format!("Sum over proved identities of disjoint {what} guest-physical intervals."),
            )
        };
        Metric {
            name: name.to_string(),
            unit: "bytes".to_string(),
            scope: scope.to_string(),
            confidence: "medium".to_string(),
            has_value: true,
            value,
            measurement: "observed".to_string(),
            coverage,
            has_aggregation: true,
            aggregation: "gauge".to_string(),
            notes,
            ..Default::default()
        }
    }

    fn unavailable_counter(&self, name: &str, unit: &str, scope: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: false,
            unit: unit.to_string(),
            measurement: "unavailable".to_string(),
            coverage: "unavailable".to_string(),
            confidence: "high".to_string(),
            scope: scope.to_string(),
            notes: "No transition_result events in this capture; baseline seeds state, not counts."
                .to_string(),
            ..Default::default()
        }
    }

    fn unavailable_state(&self, name: &str, scope: &str, reason: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: false,
            unit: "bytes".to_string(),
            measurement: "unavailable".to_string(),
            coverage: "unavailable".to_string(),
            confidence: "medium".to_string(),
            scope: scope.to_string(),
            notes: reason.to_string(),
            ..Default::default()
        }
    }

    fn note_once(&mut self, text: &str) {
        if !self.notes.iter().any(|n| n == text) {
            self.notes.push(text.to_string());
        }
    }

    fn region_for(&mut self, identity: &str, namespace: &str, generation: i64) -> Option<usize> {
        let claim = format!("{identity}|{generation}");
        if let Some(seen) = self.claimed.get(&claim)
            && seen != namespace
        {
            self.contradictions += 1;
            self.note_once("region token reused across namespaces; later namespace refused");
            return None;
        }
        let key = format!("{namespace}|{generation}|{identity}");
        if let Some(idx) = self.index.get(&key) {
            return Some(*idx);
        }
        if self.namespaces.len() >= REGION_N {
            self.refused += 1;
            return None;
        }
        let idx = self.namespaces.len();
        self.namespaces.push(namespace.to_string());
        self.invalid.push(false);
        self.segments.push(Vec::new());
        self.storage_peaks.push(0);
        self.index.insert(key, idx);
        self.claimed
            .entry(claim)
            .or_insert_with(|| namespace.to_string());
        Some(idx)
    }

    fn apply(&mut self, idx: usize, start: u64, end: u64, state: &str) {
        if self.invalid[idx] || start >= end {
            return;
        }
        let mut tag = UNKNOWN;
        if state == "shared" {
            tag = SHARED;
        } else if state == "private" {
            tag = PRIVATE;
        }
        let old_size = self.segments[idx].len();
        let available = SEG_N - self.segment_count + old_size;
        if !assign(&mut self.segments[idx], start, end, tag, available) {
            self.invalid[idx] = true;
            self.invalidated += 1;
            self.note_once("interval budget exceeded; affected region excluded");
            self.segments[idx] = Vec::new();
            self.segment_count -= old_size;
            self.storage_peaks[idx] = 0;
            return;
        }
        let size = self.segments[idx].len();
        self.segment_count = self.segment_count - old_size + size;
        if size < self.storage_peaks[idx] / 2 {
            // Release old capacity after shrinkage across many lineages.
            let compact = self.segments[idx].clone();
            self.segments[idx] = compact;
            self.segments[idx].shrink_to_fit();
            self.storage_peaks[idx] = size;
        } else {
            self.storage_peaks[idx] = self.storage_peaks[idx].max(size);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event::{Event, Gap, MapResult, TransitionResult, Unmap};
    use crate::model::metric::Metric;
    use crate::model::regions::RegionObservation;

    fn transition(
        region: &str,
        state: &str,
        ok: bool,
        offset: u64,
        length: u64,
        seq: u64,
    ) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 1000 + seq,
            kind: "transition_result".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            transition: TransitionResult {
                region_id: region.to_string(),
                requested_state: state.to_string(),
                success: ok,
                has_return_code: true,
                return_code: if ok { 0 } else { -5 },
                offset,
                length,
                has_address_space: true,
                address_space: "guest_physical".to_string(),
                has_resolution: true,
                resolution: "resolved".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn unresolved(region: &str, state: &str, seq: u64) -> Event {
        let mut ev = transition(region, state, true, 0, 8192, seq);
        ev.transition.address_space = "identity_only".to_string();
        ev.transition.resolution = "unresolved".to_string();
        ev
    }

    fn map(op: &str, mapping: &str, seq: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 2000 + seq,
            kind: "map_result".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            map_result: MapResult {
                operation_id: op.to_string(),
                success: true,
                has_mapping_id: true,
                mapping_id: mapping.to_string(),
                has_mapped_bytes: true,
                mapped_bytes: 4096,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn unmap(mapping: &str, seq: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 3000 + seq,
            kind: "unmap".to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            unmap: Unmap {
                has_mapping_id: true,
                mapping_id: mapping.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn obs(region: &str, state: &str, offset: u64, length: u64) -> RegionObservation {
        RegionObservation {
            region_id: region.to_string(),
            state: state.to_string(),
            offset,
            length,
            address_space: "guest_physical".to_string(),
            provenance: "test-baseline".to_string(),
            ..Default::default()
        }
    }

    fn gap(channel: &str, seq: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 4000 + seq,
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
                window_end_ns: 4000,
            },
            ..Default::default()
        }
    }

    fn find<'a>(metrics: &'a [Metric], name: &str) -> &'a Metric {
        metrics
            .iter()
            .find(|m| m.name == name)
            .unwrap_or_else(|| panic!("missing metric {name}"))
    }

    #[test]
    fn region_union_shared() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&transition("r1", "shared", true, 4096, 8192, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert!(t.sees_regions());
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 12288);
        assert_eq!(find(&rows, "conversion_requests").value, 2);
        assert_eq!(find(&rows, "conversion_request_bytes").value, 16384);
        t.consume(&transition("r1", "private", true, 4096, 4096, 3));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 4096);
    }

    #[test]
    fn conversion_uncertain() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&transition("r1", "private", false, 0, 4096, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 4096);
        assert_eq!(find(&rows, "unknown_region_bytes").value, 4096);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        // Evidence classes: state interpretation is medium,
        // request counting is high, independent of coverage.
        assert_eq!(
            find(&rows, "known_shared_region_bytes").confidence,
            "medium"
        );
        assert_eq!(find(&rows, "conversion_requests").confidence, "high");
        assert_eq!(find(&rows, "conversion_failures").value, 1);
        assert_eq!(find(&rows, "conversion_requests").value, 2);
    }

    #[test]
    fn ordinary_noop() {
        let mut t: RegionTracker = RegionTracker::new(false, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        assert!(t.sees_regions());
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").value, 1);
        assert_eq!(find(&rows, "conversion_request_bytes").value, 8192);
        let shared = find(&rows, "known_shared_region_bytes");
        assert!(!shared.has_value);
        assert_eq!(shared.measurement, "unavailable");
    }

    #[test]
    fn unresolved_never_physical() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&unresolved("r1", "shared", 1));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").value, 1);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 0);
        // The request counts, but its state effect is opaque, so the
        // zero union is partial, never authoritative.
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        assert!(
            t.limitations()
                .iter()
                .any(|n| n.contains("no usable state"))
        );
    }

    #[test]
    fn mapping_events_ignored() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&map("op-9", "map-9", 2));
        t.consume(&unmap("map-9", 3));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
        assert_eq!(find(&rows, "conversion_requests").value, 1);
    }

    #[test]
    fn unknown_at_start() {
        let mut t: RegionTracker = RegionTracker::new(true, false);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").value, 1);
        let shared = find(&rows, "known_shared_region_bytes");
        assert!(!shared.has_value);
        assert_eq!(shared.measurement, "unavailable");
    }

    #[test]
    fn baseline_seed() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.seed_baseline(&[obs("r1", "shared", 0, 8192)]);
        assert!(t.sees_regions());
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
        // Baseline seeds state, never conversion counts: without a
        // transition source the counters stay unavailable, not zero.
        let req = find(&rows, "conversion_requests");
        assert!(!req.has_value);
        assert_eq!(req.measurement, "unavailable");
        assert!(!find(&rows, "conversion_failures").has_value);
        assert!(!find(&rows, "conversion_request_bytes").has_value);
    }

    #[test]
    fn baseline_unknown_preserved() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.seed_baseline(&[obs("r1", "unknown", 0, 4096)]);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "unknown_region_bytes").value, 4096);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 0);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
    }

    #[test]
    fn repeated_conversion() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 4096, 1));
        t.consume(&transition("r1", "private", true, 0, 4096, 2));
        t.consume(&transition("r1", "shared", true, 0, 4096, 3));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 4096);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 0);
    }

    #[test]
    fn independent_regions() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 4096, 1));
        t.consume(&transition("r2", "private", true, 0, 4096, 2));
        let mut g2 = obs("r1", "private", 0, 1024);
        g2.generation = 2;
        t.seed_baseline(&[g2]);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 4096);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 5120);
    }

    #[test]
    fn disjoint_intervals() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 4096, 1));
        t.consume(&transition("r1", "shared", true, 8192, 4096, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
    }

    #[test]
    fn zero_length_request() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 4096, 0, 1));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").value, 1);
        assert_eq!(find(&rows, "conversion_request_bytes").value, 0);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 0);
    }

    #[test]
    fn request_bytes_overflow() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, u64::MAX, 1));
        t.consume(&transition("r1", "shared", true, 0, 1, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").value, 2);
        let rb = find(&rows, "conversion_request_bytes");
        assert!(!rb.has_value);
        assert_eq!(rb.measurement, "unavailable");
    }

    #[test]
    fn contradictory_namespace() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        let mut kv = transition("r1", "private", true, 0, 8192, 2);
        kv.transition.address_space = "kernel_virtual".to_string();
        t.consume(&kv);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 0);
        assert_eq!(find(&rows, "conversion_requests").value, 2);
        assert!(!t.limitations().is_empty());
    }

    #[test]
    fn region_budget() {
        let mut t = RegionTracker::<1>::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 4096, 1));
        t.consume(&transition("r2", "shared", true, 0, 4096, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 4096);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        assert_eq!(find(&rows, "conversion_requests").value, 2);
        assert!(!t.limitations().is_empty());
    }

    #[test]
    fn segment_budget() {
        let mut t = RegionTracker::<{ crate::model::identity::REGION_MAX }, 1>::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 4096, 1));
        t.consume(&transition("r1", "private", true, 0, 1024, 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 0);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        assert_eq!(find(&rows, "conversion_requests").value, 2);
        assert!(!t.limitations().is_empty());
    }

    #[test]
    fn namespace_isolation() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        let mut kv = transition("r9", "shared", true, 0, 8192, 1);
        kv.transition.address_space = "kernel_virtual".to_string();
        t.consume(&kv);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 0);
        assert_eq!(
            find(&rows, "known_shared_region_bytes").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn empty_world() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        assert!(!t.sees_regions());
        let empty: [RegionObservation; 0] = [];
        t.seed_baseline(&empty);
        assert!(!t.sees_regions());
    }

    #[test]
    fn generation_lineage_isolated() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        let mut g1 = obs("r1", "shared", 0, 8192);
        g1.generation = 1;
        let mut g2 = obs("r1", "private", 0, 8192);
        g2.generation = 2;
        t.seed_baseline(&[g1, g2]);
        let mut tr = transition("r1", "shared", true, 0, 4096, 1);
        tr.transition.generation = 2;
        t.consume(&tr);
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 12288);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 4096);
    }

    #[test]
    fn detail_gap_withholds_current_unions() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&gap("detail", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "conversion_requests").coverage, "partial");
        assert_eq!(
            find(&rows, "known_shared_region_bytes").coverage,
            "unavailable"
        );
    }

    #[test]
    fn baseline_gap_degrades_unions_only() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&gap("baseline", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        assert_eq!(
            find(&rows, "conversion_requests").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn opaque_transition_degrades_known_unions() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&unresolved("r1", "private", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 8192);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
    }

    #[test]
    fn unrelated_gap_keeps_regions_complete() {
        let mut t: RegionTracker = RegionTracker::new(true, true);
        t.consume(&transition("r1", "shared", true, 0, 8192, 1));
        t.consume(&gap("aggregate", 2));
        let rows = t.metrics("window [0,2000)", false);
        assert_eq!(
            find(&rows, "conversion_requests").coverage,
            "complete_for_scope"
        );
        assert_eq!(
            find(&rows, "known_shared_region_bytes").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn pointwise_overlap_and_reused_generations() {
        // A byte-cell oracle has no interval splitting or merging algorithm.
        let mut t: RegionTracker = RegionTracker::new(true, true);
        let mut cells = vec![-1i64; 3 * 257];
        let mut requested: u64 = 0;
        for step in 0..513usize {
            let generation = (step % 3) as i64;
            let start = (step * 73) % 257;
            let length = (257 - start).min(1 + (step * 19) % 67);
            let shared = step % 5 < 2;
            let ok = step % 11 != 0;
            let mut state = "private";
            let mut cell = 2;
            if shared {
                state = "shared";
                cell = 1;
            }
            if !ok {
                cell = 3;
            }
            let mut ev = transition(
                "reused",
                state,
                ok,
                start as u64,
                length as u64,
                step as u64,
            );
            ev.transition.generation = generation;
            t.consume(&ev);
            requested += length as u64;
            for offset in start..start + length {
                cells[generation as usize * 257 + offset] = cell;
            }
            let mut want = [0u64; 4];
            for value in &cells {
                if *value > 0 {
                    want[*value as usize] += 1;
                }
            }
            let rows = t.metrics("pointwise", false);
            assert_eq!(find(&rows, "known_shared_region_bytes").value, want[1]);
            assert_eq!(find(&rows, "known_private_region_bytes").value, want[2]);
            assert_eq!(find(&rows, "unknown_region_bytes").value, want[3]);
            assert_eq!(find(&rows, "conversion_requests").value, step as u64 + 1);
            assert_eq!(find(&rows, "conversion_request_bytes").value, requested);
        }
        assert_eq!(t.limitations().len(), 0);
    }

    #[test]
    fn merge_at_global_budget_and_reuse_freed_capacity() {
        let mut t = RegionTracker::<{ crate::model::identity::REGION_MAX }, 5>::new(true, true);
        t.consume(&transition("a", "shared", true, 0, 100, 0));
        t.consume(&transition("a", "private", true, 40, 20, 1));
        t.consume(&transition("b", "private", true, 0, 100, 2));
        t.consume(&transition("c", "shared", true, 0, 100, 3));
        // Merging at capacity must be admitted before testing the new size.
        t.consume(&transition("a", "shared", true, 40, 20, 4));
        t.consume(&transition("b", "shared", true, 40, 20, 5));
        assert_eq!(t.limitations().len(), 0);
        // The extra split invalidates b only, freeing all three of its segments.
        t.consume(&transition("b", "private", true, 45, 10, 6));
        t.consume(&transition("c", "private", true, 40, 20, 7));
        // An invalidated lineage cannot resurrect on a later full assignment.
        t.consume(&transition("b", "shared", true, 0, 100, 8));
        let rows = t.metrics("budget", false);
        assert_eq!(find(&rows, "known_shared_region_bytes").value, 180);
        assert_eq!(find(&rows, "known_private_region_bytes").value, 20);
        assert_eq!(find(&rows, "known_shared_region_bytes").coverage, "partial");
        assert_eq!(find(&rows, "conversion_requests").value, 9);
    }

    #[test]
    fn baseline_seeds_tracker() {
        use crate::model::session::parse_session;
        use crate::platform::baseline::read_baseline;
        let path = format!(
            "{}/../tests/fixtures/baseline/session.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let bytes = std::fs::read(&path).expect("read baseline session");
        let s = parse_session(&bytes).expect("parse baseline session");
        let mut t: RegionTracker = RegionTracker::new(true, s.baseline_complete);
        let obs = read_baseline(&s);
        t.seed_baseline(&obs);
        assert!(t.sees_regions());
        let rows = t.metrics("window [0,2000)", false);
        let mut shared = 0;
        let mut unknown = 0;
        for m in &rows {
            if m.name == "known_shared_region_bytes" {
                shared = m.value;
            }
            if m.name == "unknown_region_bytes" {
                unknown = m.value;
            }
        }
        assert_eq!(shared, 8192);
        assert_eq!(unknown, 0);
    }
}
