// SPDX-License-Identifier: GPL-3.0-or-later
//! Attempt reducer: bounce counts, counter deltas, and report quality.
//!
//! The analyzer consumes validated events and finishes one Report. Its
//! rules:
//!
//! - Detail counts and requested bytes come from bounce_attempt events,
//!   globally and per device. Counter deltas are alternative
//!   measurements surfaced beside them, never added to them.
//! - Counter snapshots group by counter, device scope, profile, and
//!   unit with exact field comparison. A delta needs two readings in
//!   one epoch with no reset in between; anything else yields a
//!   limitation, never a row.
//! - Report quality echoes the session claims unless the stream
//!   contradicts them: observed gaps, snapshots against an unavailable
//!   aggregate claim, a missing finalization, or a dropped tail. The
//!   producer's loss counts are kept except where observations refute
//!   them.
//! - Quality channels the attempt scope does not measure (correlation,
//!   baseline) echo the producer claims verbatim.

use std::collections::BTreeMap;

use crate::ENGINE_VERSION;
use crate::capture::correlation::rollup_correlation;
use crate::model::event::Event;
use crate::model::metric::{Finding, Metric};
use crate::model::report::{
    Report, ReportCap, ReportEnv, incomplete_finding_severity, terminal_loss_leg,
    verdict_for_counts,
};
use crate::model::session::{Capability, Channel, Session, truncate_codepoints};
use crate::model::validate::{checked_add, format_u64};

const MAX_SUMMANDS: usize = 8;
const MAX_METRICS: usize = 4096;
const MAX_COUNTER_GROUPS: usize = 4096;
const MAX_LIMITATIONS: usize = 256;
const FIXED_TAIL_METRICS: usize = 10;
// Devices with per-device detail rows: 2 global rows + 2 rows per
// device + the fixed tail + 2 reserved counter rows must fit the
// frozen 4096-metric budget. Further devices keep exact global
// accounting; only their per-device rows are withheld (with a
// limitation note), so a 4096-device capture (PRD NFR-03) always
// replays with both aggregate metrics preserved.
const MAX_DETAILED_DEVICES: usize = (MAX_METRICS - 2 - FIXED_TAIL_METRICS - 2) / 2;
// Rendered metric scopes share the external report bound: a
// complete scope may name at most 256 characters.
const REPORT_SCOPE_MAX: usize = 256;

/// One analyzer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisError {
    /// Human-readable failure.
    pub message: String,
}

impl AnalysisError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for AnalysisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for AnalysisError {}

#[derive(Debug, Clone, Default)]
struct DeviceAcc {
    device_id: String,
    count: usize,
    total_bytes: u64,
    bytes_overflow: bool,
    summands: Vec<u64>,
    has_ts: bool,
    min_ts: u64,
    max_ts: u64,
}

#[derive(Debug, Clone, Default)]
struct CounterGroup {
    counter_id: String,
    has_device: bool,
    device: String,
    profile: String,
    unit: String,
    // The remaining source fields join the grouping key at
    // consume time; only the measurement leg is read back.
    source_measurement: String,
    first_epoch: u64,
    first_value: u64,
    first_ts: u64,
    last_epoch: u64,
    last_value: u64,
    last_ts: u64,
    max_value: u64,
    count: usize,
    has_other_epoch: bool,
    other_epoch: u64,
    has_decrease: bool,
    decrease_from: u64,
    decrease_to: u64,
    has_ts_reorder: bool,
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

/// Half-open window label shared by every tracker.
pub(crate) fn window_label(start_ns: u64, end_ns: u64) -> String {
    format!("window [{},{})", format_u64(start_ns), format_u64(end_ns))
}

/// True for counter ids with a metric mapping.
fn known_counter(counter_id: &str) -> bool {
    counter_id == "swiotlb.bounce_attempts" || counter_id == "swiotlb.requested_bytes"
}

fn counter_metric_name(counter_id: &str) -> String {
    // Counter rows carry a counter_ prefix so they never collide with
    // the detail rows they cross-check: one (name, dimensions) key maps
    // to exactly one measurement channel.
    if counter_id == "swiotlb.bounce_attempts" {
        return "counter_bounce_attempts".to_string();
    }
    if counter_id == "swiotlb.requested_bytes" {
        return "counter_requested_bounce_bytes".to_string();
    }
    counter_id.to_string()
}

fn expected_unit(counter_id: &str) -> String {
    // Unit a known counter must carry; empty when unmapped.
    if counter_id == "swiotlb.bounce_attempts" {
        return "count".to_string();
    }
    if counter_id == "swiotlb.requested_bytes" {
        return "bytes".to_string();
    }
    String::new()
}

fn worse_coverage(a: &str, b: &str) -> String {
    // Worse of two coverages for a derived row (oracle-coupled).
    let rank_a = if a == "partial" {
        1
    } else if a == "unavailable" || a == "not_applicable" {
        2
    } else {
        0
    };
    let rank_b = if b == "partial" {
        1
    } else if b == "unavailable" || b == "not_applicable" {
        2
    } else {
        0
    };
    if rank_a >= rank_b {
        a.to_string()
    } else {
        b.to_string()
    }
}

fn group_cause(g: &CounterGroup) -> String {
    // Empty when the group yields a delta; else the cause phrase.
    if !known_counter(&g.counter_id) {
        return "unknown counter id; no metric mapping".to_string();
    }
    let want = expected_unit(&g.counter_id);
    if g.unit != want {
        return format!(
            "unit mismatch: expected {want}, observed {}; no delta computed",
            g.unit
        );
    }
    if g.count < 2 {
        return "single snapshot; no pair for a delta".to_string();
    }
    if g.has_other_epoch {
        return format!(
            "epoch changed {} -> {}; no delta computed",
            format_u64(g.first_epoch),
            format_u64(g.other_epoch)
        );
    }
    if g.has_decrease {
        return format!(
            "value decreased {} -> {} within epoch {}; no delta computed",
            format_u64(g.decrease_from),
            format_u64(g.decrease_to),
            format_u64(g.first_epoch)
        );
    }
    if g.has_ts_reorder {
        return "timestamps out of order; no delta computed".to_string();
    }
    String::new()
}

fn group_scope_label(has_device: bool, device: &str) -> String {
    // Producer scope of one counter group.
    //
    // Device-unscoped groups keep the producer's all-devices scope
    // even when a capture filter is active: the filter selects which
    // detail events were recorded, and its effect on the producer's
    // aggregate channel is unknown. Only detail-side scopes carry the
    // filter phrase (see bounded_device_scope).
    if has_device {
        return format!("device {device}");
    }
    "all devices".to_string()
}

fn windows_overlap(starts: &[u64], ends: &[u64], s: u64, e: u64) -> bool {
    // True when half-open [s, e) meets any recorded window.
    for (ws, we) in starts.iter().zip(ends.iter()) {
        let lo = s.max(*ws);
        let hi = e.min(*we);
        if lo < hi {
            return true;
        }
    }
    false
}

fn group_before(a: &CounterGroup, b: &CounterGroup) -> bool {
    if a.counter_id != b.counter_id {
        return a.counter_id < b.counter_id;
    }
    let a_dev = if a.has_device { a.device.as_str() } else { "" };
    let b_dev = if b.has_device { b.device.as_str() } else { "" };
    if a_dev != b_dev {
        return a_dev < b_dev;
    }
    if a.profile != b.profile {
        return a.profile < b.profile;
    }
    a.unit < b.unit
}

fn coverage_of(status: &str) -> String {
    if status == "complete_for_scope" {
        return "complete_for_scope".to_string();
    }
    if status == "partial" {
        return "partial".to_string();
    }
    "unavailable".to_string()
}

fn attempt_lower_bound(session: &Session) -> bool {
    // True when the producer claims a pre-6.7 lower bound.
    let label = "attempt loss counts are a lower bound before 6.7";
    if session.q_detail.reason.contains(label) {
        return true;
    }
    session.q_aggregate.reason.contains(label)
}

fn rollup_split_relations(mapping: &Channel, copy: &Channel, sync: &Channel) -> Channel {
    // Analyzer aggregate over the three relation classes.
    //
    // The analyzer never trusts a producer aggregate in split
    // mode: the aggregate is recomputed from the classes on
    // every report, so any non-complete class yields partial.
    let map_causes = vec![mapping.reason.clone()];
    let copy_causes = vec![copy.reason.clone()];
    let sync_causes = vec![sync.reason.clone()];
    rollup_correlation(mapping, copy, sync, &map_causes, &copy_causes, &sync_causes)
}

fn summand_text(values: &[u64], total: u64, n: usize) -> String {
    if n == 0 {
        return "0".to_string();
    }
    if n <= MAX_SUMMANDS {
        return values
            .iter()
            .map(|v| format_u64(*v))
            .collect::<Vec<_>>()
            .join(" + ");
    }
    format_u64(total)
}

#[allow(clippy::too_many_arguments)]
fn detail_metric(
    name: &str,
    unit: &str,
    has_value: bool,
    value: u64,
    coverage: &str,
    has_device: bool,
    device: &str,
    scope: &str,
    notes: &str,
) -> Metric {
    let mut m = Metric {
        name: name.to_string(),
        has_value,
        value,
        unit: unit.to_string(),
        coverage: coverage.to_string(),
        confidence: "high".to_string(),
        has_device_id: has_device,
        device_id: device.to_string(),
        scope: scope.to_string(),
        notes: notes.to_string(),
        ..Default::default()
    };
    if has_value {
        m.measurement = "observed".to_string();
        m.has_aggregation = true;
        m.aggregation = "counter".to_string();
    }
    m
}

fn unavailable_metric(name: &str, unit: &str, scope: &str, notes: &str) -> Metric {
    Metric {
        name: name.to_string(),
        unit: unit.to_string(),
        scope: scope.to_string(),
        notes: notes.to_string(),
        confidence: "high".to_string(),
        ..Default::default()
    }
}

fn echo_cap(out: &mut Report, name: &str, cap: &Capability) {
    // Append one session capability claim to the report matrix.
    out.caps.push(ReportCap {
        name: name.to_string(),
        status: cap.status.clone(),
        has_grade: cap.has_grade,
        grade: cap.grade.clone(),
        reason: cap.reason.clone(),
    });
}

/// Incremental attempt reducer over one session's events.
#[derive(Debug, Clone)]
pub struct AttemptAnalyzer {
    session: Session,
    total_count: usize,
    total_bytes: u64,
    total_overflow: bool,
    total_summands: Vec<u64>,
    dev_index: BTreeMap<String, usize>,
    devs: Vec<DeviceAcc>,
    ctrs: Vec<CounterGroup>,
    ctr_index: BTreeMap<String, usize>,
    detail_gaps: usize,
    detail_unknown: bool,
    detail_lost: u64,
    detail_lost_overflow: bool,
    agg_gaps: usize,
    agg_unknown: bool,
    agg_lost: u64,
    corr_gaps: usize,
    base_gaps: usize,
    term_gaps: usize,
    saw_map: bool,
    saw_copy: bool,
    saw_unmap: bool,
    saw_sync: bool,
    ctrs_ignored: usize,
    fixed_notes: Vec<String>,
    data_notes: Vec<String>,
    detail_wstart: Vec<u64>,
    detail_wend: Vec<u64>,
    agg_wstart: Vec<u64>,
    agg_wend: Vec<u64>,
    has_detail_ts: bool,
    detail_min_ts: u64,
    detail_max_ts: u64,
    detail_non_observed: bool,
    disagree_text: String,
    disagree_extra: usize,
    disagree_refs: Vec<String>,
    scope_elided: bool,
}

impl AttemptAnalyzer {
    /// Empty reducer over one session's claims.
    pub fn new(session: Session) -> Self {
        Self {
            session,
            total_count: 0,
            total_bytes: 0,
            total_overflow: false,
            total_summands: Vec::new(),
            dev_index: BTreeMap::new(),
            devs: Vec::new(),
            ctrs: Vec::new(),
            ctr_index: BTreeMap::new(),
            detail_gaps: 0,
            detail_unknown: false,
            detail_lost: 0,
            detail_lost_overflow: false,
            agg_gaps: 0,
            agg_unknown: false,
            agg_lost: 0,
            corr_gaps: 0,
            base_gaps: 0,
            term_gaps: 0,
            saw_map: false,
            saw_copy: false,
            saw_unmap: false,
            saw_sync: false,
            ctrs_ignored: 0,
            fixed_notes: Vec::new(),
            data_notes: Vec::new(),
            detail_wstart: Vec::new(),
            detail_wend: Vec::new(),
            agg_wstart: Vec::new(),
            agg_wend: Vec::new(),
            has_detail_ts: false,
            detail_min_ts: 0,
            detail_max_ts: 0,
            detail_non_observed: false,
            disagree_text: String::new(),
            disagree_extra: 0,
            disagree_refs: Vec::new(),
            scope_elided: false,
        }
    }

    fn note_fixed(&mut self, text: String) {
        // Record one structural limitation (few by construction).
        self.fixed_notes.push(text);
    }

    fn note_data(&mut self, text: String) {
        // Record one data-driven limitation (bounded at merge).
        self.data_notes.push(text);
    }

    fn saw_lifecycle(&self) -> bool {
        // True once any lifecycle-kind event was consumed.
        self.saw_map || self.saw_copy || self.saw_unmap || self.saw_sync
    }

    fn bounded_device_scope(&mut self, window: &str, suffix: &str) -> String {
        // Complete windowed device scope within REPORT_SCOPE_MAX.
        //
        // Without a capture filter the totals cover every recorded
        // device; with one, only the filtered subset was recorded, so
        // the literal filter stays in the scope instead of claiming
        // all devices. The literal is named only when the complete
        // scope fits the report bound; otherwise the scope elides to
        // `recorded devices (filtered)` and the flag preserves the
        // exact selector in the report limitations.
        let phrase = if self.session.has_filter_device {
            format!("recorded devices (filter: {})", self.session.filter_device)
        } else {
            "all devices".to_string()
        };
        let full = format!("{window}, {phrase}{suffix}");
        if !self.session.has_filter_device || full.chars().count() <= REPORT_SCOPE_MAX {
            return full;
        }
        self.scope_elided = true;
        format!("{window}, recorded devices (filtered){suffix}")
    }

    /// Fold one validated event into the reduction.
    pub fn consume(&mut self, ev: &Event) {
        if ev.kind == "bounce_attempt" {
            self.consume_bounce(ev);
        } else if ev.kind == "counter_snapshot" {
            self.consume_snapshot(ev);
        } else if ev.kind == "gap" {
            self.consume_gap(ev);
        } else if ev.kind == "map_result" {
            self.saw_map = true;
        } else if ev.kind == "copy" {
            self.saw_copy = true;
        } else if ev.kind == "unmap" {
            self.saw_unmap = true;
        } else if ev.kind == "sync_request" {
            self.saw_sync = true;
        }
    }

    fn consume_bounce(&mut self, ev: &Event) {
        self.total_count += 1;
        if !self.has_detail_ts {
            self.has_detail_ts = true;
            self.detail_min_ts = ev.ts_ns;
            self.detail_max_ts = ev.ts_ns;
        } else {
            if ev.ts_ns < self.detail_min_ts {
                self.detail_min_ts = ev.ts_ns;
            }
            if ev.ts_ns > self.detail_max_ts {
                self.detail_max_ts = ev.ts_ns;
            }
        }
        if ev.source_measurement != "observed" {
            self.detail_non_observed = true;
        }
        match checked_add(self.total_bytes, ev.bounce.requested_bytes) {
            Ok(v) => self.total_bytes = v,
            Err(_) => self.total_overflow = true,
        }
        if self.total_summands.len() < MAX_SUMMANDS {
            self.total_summands.push(ev.bounce.requested_bytes);
        }
        let dev = ev.bounce.device_id.clone();
        let idx = if let Some(i) = self.dev_index.get(&dev) {
            *i
        } else {
            self.devs.push(DeviceAcc {
                device_id: ev.bounce.device_id.clone(),
                ..Default::default()
            });
            let idx = self.devs.len() - 1;
            self.dev_index.insert(dev, idx);
            idx
        };
        self.devs[idx].count += 1;
        if !self.devs[idx].has_ts {
            self.devs[idx].has_ts = true;
            self.devs[idx].min_ts = ev.ts_ns;
            self.devs[idx].max_ts = ev.ts_ns;
        } else {
            if ev.ts_ns < self.devs[idx].min_ts {
                self.devs[idx].min_ts = ev.ts_ns;
            }
            if ev.ts_ns > self.devs[idx].max_ts {
                self.devs[idx].max_ts = ev.ts_ns;
            }
        }
        let cur = self.devs[idx].total_bytes;
        match checked_add(cur, ev.bounce.requested_bytes) {
            Ok(v) => self.devs[idx].total_bytes = v,
            Err(_) => self.devs[idx].bytes_overflow = true,
        }
        if self.devs[idx].summands.len() < MAX_SUMMANDS {
            self.devs[idx].summands.push(ev.bounce.requested_bytes);
        }
    }

    fn consume_snapshot(&mut self, ev: &Event) {
        let flag = if ev.snapshot.has_scope_device {
            "1"
        } else {
            "0"
        };
        let counter = &ev.snapshot.counter_id;
        let dev = &ev.snapshot.scope_device_id;
        let profile = &ev.snapshot.scope_profile_id;
        let unit = &ev.snapshot.unit;
        let hook = &ev.source_hook;
        let backend = &ev.source_backend;
        let src_profile = &ev.source_profile_id;
        let measurement = &ev.source_measurement;
        let correlation = &ev.source_correlation;
        let key = format!(
            "{flag}#{}#{counter}#{}#{dev}#{}#{profile}#{}#{unit}#{}#{hook}#{}#{backend}#{}#{src_profile}#{}#{measurement}#{}#{correlation}",
            counter.len(),
            dev.len(),
            profile.len(),
            unit.len(),
            hook.len(),
            backend.len(),
            src_profile.len(),
            measurement.len(),
            correlation.len()
        );
        let idx = self.ctr_index.get(&key).copied().unwrap_or(usize::MAX);
        if idx == usize::MAX {
            if self.ctrs.len() >= MAX_COUNTER_GROUPS {
                self.ctrs_ignored += 1;
                return;
            }
            self.ctr_index.insert(key, self.ctrs.len());
            self.ctrs.push(CounterGroup {
                counter_id: ev.snapshot.counter_id.clone(),
                has_device: ev.snapshot.has_scope_device,
                device: ev.snapshot.scope_device_id.clone(),
                profile: ev.snapshot.scope_profile_id.clone(),
                unit: ev.snapshot.unit.clone(),
                source_measurement: ev.source_measurement.clone(),
                first_epoch: ev.snapshot.epoch,
                first_value: ev.snapshot.value,
                first_ts: ev.ts_ns,
                last_epoch: ev.snapshot.epoch,
                last_value: ev.snapshot.value,
                last_ts: ev.ts_ns,
                max_value: ev.snapshot.value,
                count: 1,
                ..Default::default()
            });
            return;
        }
        self.ctrs[idx].count += 1;
        if ev.ts_ns < self.ctrs[idx].last_ts {
            self.ctrs[idx].has_ts_reorder = true;
        }
        self.ctrs[idx].last_epoch = ev.snapshot.epoch;
        self.ctrs[idx].last_value = ev.snapshot.value;
        self.ctrs[idx].last_ts = ev.ts_ns;
        if ev.snapshot.epoch != self.ctrs[idx].first_epoch && !self.ctrs[idx].has_other_epoch {
            self.ctrs[idx].has_other_epoch = true;
            self.ctrs[idx].other_epoch = ev.snapshot.epoch;
        }
        if ev.snapshot.value < self.ctrs[idx].max_value && !self.ctrs[idx].has_decrease {
            self.ctrs[idx].has_decrease = true;
            self.ctrs[idx].decrease_from = self.ctrs[idx].max_value;
            self.ctrs[idx].decrease_to = ev.snapshot.value;
        }
        if ev.snapshot.value > self.ctrs[idx].max_value {
            self.ctrs[idx].max_value = ev.snapshot.value;
        }
    }

    fn consume_gap(&mut self, ev: &Event) {
        if ev.gap.channel == "detail" {
            self.detail_gaps += 1;
            if windows_overlap(
                &self.detail_wstart,
                &self.detail_wend,
                ev.gap.window_start_ns,
                ev.gap.window_end_ns,
            ) {
                self.detail_unknown = true;
            }
            self.detail_wstart.push(ev.gap.window_start_ns);
            self.detail_wend.push(ev.gap.window_end_ns);
            if !ev.gap.has_lost_count {
                self.detail_unknown = true;
            } else {
                match checked_add(self.detail_lost, ev.gap.lost_count) {
                    Ok(v) => self.detail_lost = v,
                    Err(_) => {
                        self.detail_lost_overflow = true;
                        self.detail_unknown = true;
                    }
                }
            }
        } else if ev.gap.channel == "aggregate" {
            self.agg_gaps += 1;
            if windows_overlap(
                &self.agg_wstart,
                &self.agg_wend,
                ev.gap.window_start_ns,
                ev.gap.window_end_ns,
            ) {
                self.agg_unknown = true;
            }
            self.agg_wstart.push(ev.gap.window_start_ns);
            self.agg_wend.push(ev.gap.window_end_ns);
            if !ev.gap.has_lost_count {
                self.agg_unknown = true;
            } else {
                match checked_add(self.agg_lost, ev.gap.lost_count) {
                    Ok(v) => self.agg_lost = v,
                    Err(_) => self.agg_unknown = true,
                }
            }
        } else if ev.gap.channel == "correlation" {
            self.corr_gaps += 1;
        } else if ev.gap.channel == "baseline" {
            self.base_gaps += 1;
        } else if ev.gap.channel == "terminal" {
            self.term_gaps += 1;
        }
    }

    fn group_order(&self) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.ctrs.len()).collect();
        if order.len() > 1 {
            order.sort_by(|a, b| {
                let ga = &self.ctrs[*a];
                let gb = &self.ctrs[*b];
                if group_before(ga, gb) {
                    std::cmp::Ordering::Less
                } else if group_before(gb, ga) {
                    std::cmp::Ordering::Greater
                } else {
                    std::cmp::Ordering::Equal
                }
            });
        }
        order
    }

    fn snapshot_total(&self) -> usize {
        self.ctrs.iter().map(|g| g.count).sum()
    }

    fn build_detail(&mut self, partial: bool) -> Channel {
        let mut ch = Channel::default();
        let producer = self.session.q_detail.clone();
        let gaps = self.detail_gaps > 0;
        if gaps || partial {
            ch.status = "partial".to_string();
        } else if producer.status == "complete_for_scope" {
            ch.status = "complete_for_scope".to_string();
        } else if producer.status == "unavailable" && self.total_count == 0 {
            ch.status = "unavailable".to_string();
        } else if producer.status == "unavailable" || producer.status == "not_applicable" {
            ch.status = "partial".to_string();
            self.note_fixed(format!(
                "Producer detail status {} contradicts {}",
                producer.status,
                plural(self.total_count, "observed event.", "observed events.")
            ));
        } else {
            ch.status = producer.status.clone();
        }
        let producer_zero = producer.status == "complete_for_scope"
            && producer.has_loss_count
            && producer.loss_count == 0;
        if partial {
            ch.has_loss_count = false;
        } else if gaps && producer_zero && !self.detail_unknown {
            ch.has_loss_count = true;
            ch.loss_count = self.detail_lost;
        } else if gaps || self.detail_unknown || !producer.has_loss_count {
            ch.has_loss_count = false;
        } else {
            ch.has_loss_count = true;
            ch.loss_count = producer.loss_count;
        }
        if gaps && !producer_zero && producer.has_loss_count {
            self.note_fixed(
                "Observed detail gaps may overlap the producer loss count; total unknown."
                    .to_string(),
            );
        }
        let mut scope = plural(
            self.total_count,
            "bounce_attempt event",
            "bounce_attempt events",
        );
        if gaps {
            scope += &format!(
                ", {}",
                plural(self.detail_gaps, "detail gap", "detail gaps")
            );
        }
        if partial {
            scope += ", truncated tail dropped";
        }
        ch.scope = scope;
        if gaps {
            ch.reason = plural(
                self.detail_gaps,
                "Detail gap event observed; counts are lower bounds.",
                "Detail gap events observed; counts are lower bounds.",
            );
            if partial {
                ch.reason += " Truncated tail dropped.";
            }
            if !ch.has_loss_count {
                ch.reason += " Loss total unknown.";
            }
        } else if partial {
            ch.reason = format!(
                "Truncated tail dropped; counts exclude it. Producer detail status {}.",
                producer.status
            );
        } else if producer.status != "complete_for_scope" {
            let mut loss_desc = "loss unknown".to_string();
            if producer.has_loss_count {
                loss_desc = format!("loss {}", format_u64(producer.loss_count));
            }
            ch.reason = format!(
                "Producer detail status {} ({}); {}",
                producer.status,
                loss_desc,
                plural(
                    self.total_count,
                    "event observed without gaps.",
                    "events observed without gaps."
                )
            );
        } else if producer.has_loss_count && producer.loss_count > 0 {
            ch.reason = format!(
                "Producer detail status complete_for_scope (loss {}); {}",
                format_u64(producer.loss_count),
                plural(
                    self.total_count,
                    "event observed without gaps.",
                    "events observed without gaps."
                )
            );
        } else if !producer.has_loss_count {
            ch.reason = format!(
                "Producer detail status complete_for_scope (loss unknown); {}",
                plural(
                    self.total_count,
                    "event observed without gaps.",
                    "events observed without gaps."
                )
            );
        } else if self.session.synthetic {
            ch.reason = "Authored fixture: no loss.".to_string();
        } else {
            ch.reason = "No detail loss observed.".to_string();
        }
        if attempt_lower_bound(&self.session) {
            // Pre-6.7 counts are a lower bound: the report
            // never claims complete or silent loss there.
            if ch.status == "complete_for_scope" {
                ch.status = "partial".to_string();
            }
            ch.reason += "; attempt loss counts are a lower bound before 6.7";
        }
        ch
    }

    fn build_aggregate(&mut self, noun: &str, order: &[usize]) -> Channel {
        let mut ch = Channel::default();
        let producer = self.session.q_aggregate.clone();
        let snapshots = self.snapshot_total();
        let mut unusable = 0;
        for oi in order {
            if !group_cause(&self.ctrs[*oi]).is_empty() {
                unusable += 1;
            }
        }
        let usable = order.len() - unusable;
        let omitted = self.ctrs_ignored;
        let contradict = self.agg_gaps > 0
            || unusable > 0
            || omitted > 0
            || (snapshots > 0
                && (producer.status == "unavailable" || producer.status == "not_applicable"));
        if contradict {
            if self.agg_gaps > 0 || unusable > 0 || omitted > 0 {
                ch.status = "partial".to_string();
            } else {
                ch.status = "complete_for_scope".to_string();
            }
        } else {
            ch.status = producer.status.clone();
        }
        let agg_gaps = self.agg_gaps > 0;
        let agg_zero = producer.status == "complete_for_scope"
            && producer.has_loss_count
            && producer.loss_count == 0;
        if agg_gaps && agg_zero && !self.agg_unknown && omitted == 0 {
            ch.has_loss_count = true;
            ch.loss_count = self.agg_lost;
        } else if agg_gaps || self.agg_unknown || omitted > 0 || !producer.has_loss_count {
            ch.has_loss_count = false;
        } else {
            ch.has_loss_count = true;
            ch.loss_count = producer.loss_count;
        }
        if agg_gaps && !agg_zero && producer.has_loss_count {
            self.note_fixed(
                "Observed aggregate gaps may overlap the producer loss count; total unknown."
                    .to_string(),
            );
        }
        ch.scope = "counter snapshots".to_string();
        if snapshots == 0 {
            ch.reason = format!("No counter snapshots in this {noun}.");
            if agg_gaps {
                ch.reason += &format!(
                    " {}",
                    plural(
                        self.agg_gaps,
                        "aggregate gap event observed.",
                        "aggregate gap events observed."
                    )
                );
            }
        } else {
            let mut reason = format!(
                "{}; {}",
                plural(usable, "usable counter group", "usable counter groups"),
                plural(usable, "delta computed.", "deltas computed.")
            );
            if unusable > 0 {
                reason += &format!(" {unusable} groups unusable (see limitations).");
            }
            if omitted > 0 {
                reason += &format!(
                    " {}: admission bound reached.",
                    plural(
                        omitted,
                        "counter reading omitted",
                        "counter readings omitted"
                    )
                );
            }
            if self.agg_gaps > 0 {
                reason += &format!(
                    " {}",
                    plural(
                        self.agg_gaps,
                        "aggregate gap event observed.",
                        "aggregate gap events observed."
                    )
                );
            }
            ch.reason = reason;
        }
        let observed = snapshots + omitted;
        if observed > 0 && (producer.status == "unavailable" || producer.status == "not_applicable")
        {
            self.note_fixed(format!(
                "Producer aggregate status {} contradicts {}",
                producer.status,
                plural(observed, "observed snapshot.", "observed snapshots.")
            ));
        }
        if self.agg_gaps > 0 {
            let mut lost = "unknown".to_string();
            if !self.agg_unknown {
                lost = format_u64(self.agg_lost);
            }
            self.note_fixed(format!(
                "{} ({} lost).",
                plural(self.agg_gaps, "aggregate gap event", "aggregate gap events"),
                lost
            ));
        }
        for oi in order {
            let g = &self.ctrs[*oi];
            let cause = group_cause(g);
            if !cause.is_empty() {
                self.note_data(format!(
                    "Counter {} ({}): {cause}.",
                    g.counter_id,
                    group_scope_label(g.has_device, &g.device)
                ));
            }
        }
        if attempt_lower_bound(&self.session) {
            if ch.status == "complete_for_scope" {
                ch.status = "partial".to_string();
            }
            ch.reason += "; attempt loss counts are a lower bound before 6.7";
        }
        ch
    }

    fn build_terminal(&mut self, partial: bool) -> Channel {
        let term_gaps = self.term_gaps > 0;
        let mut ch: Channel;
        if self.session.finalized && !partial && !term_gaps {
            ch = self.session.q_terminal.clone();
        } else {
            ch = Channel::default();
            ch.status = "partial".to_string();
            ch.scope = self.session.q_terminal.scope.clone();
            if !self.session.finalized && partial {
                ch.reason =
                    "Capture not finalized; final event line dropped as truncated (--allow-partial)."
                        .to_string();
            } else if !self.session.finalized {
                ch.reason = "Capture not finalized; window may be incomplete.".to_string();
            } else if partial {
                ch.reason = "Final event line dropped as truncated (--allow-partial).".to_string();
            } else {
                ch.reason = String::new();
            }
            if term_gaps {
                let phrase = format!(
                    "{} settlement unverified.",
                    plural(
                        self.term_gaps,
                        "terminal gap event observed;",
                        "terminal gap events observed;"
                    )
                );
                if !ch.reason.is_empty() {
                    ch.reason += " ";
                }
                ch.reason += &phrase;
            }
        }
        if !self.session.finalized {
            self.note_fixed("Capture not finalized; terminal loss unknown.".to_string());
        }
        if partial {
            self.note_fixed("Dropped 1 truncated tail line; counts exclude it.".to_string());
        }
        if term_gaps {
            self.note_fixed(format!(
                "{} settlement unverified.",
                plural(
                    self.term_gaps,
                    "terminal gap event observed;",
                    "terminal gap events observed;"
                )
            ));
        }
        ch
    }

    // Sequential field writes mirror the behavior source
    // line-for-line for auditability; a single literal
    // would bury the conditional channel logic.
    #[allow(clippy::field_reassign_with_default)]
    fn build_correlation(&mut self) -> (Channel, Channel, Channel, Channel) {
        let producer = self.session.q_correlation.clone();
        let mut rel_mapping = Channel::default();
        let mut rel_copy = Channel::default();
        let mut rel_sync = Channel::default();
        if self.session.has_corr_relations {
            rel_mapping = self.session.q_corr_mapping.clone();
            rel_copy = self.session.q_corr_copy.clone();
            rel_sync = self.session.q_corr_sync.clone();
        }
        if self.corr_gaps == 0 {
            if !self.session.has_corr_relations {
                return (producer, rel_mapping, rel_copy, rel_sync);
            }
            let agg = rollup_split_relations(&rel_mapping, &rel_copy, &rel_sync);
            return (agg, rel_mapping, rel_copy, rel_sync);
        }
        self.note_fixed(format!(
            "{} channel partial.",
            plural(
                self.corr_gaps,
                "correlation gap event observed;",
                "correlation gap events observed;"
            )
        ));
        if !self.session.has_corr_relations {
            let ch = Channel {
                status: "partial".to_string(),
                scope: producer.scope.clone(),
                reason: format!(
                    "{} cross-event evidence may be missing.",
                    plural(
                        self.corr_gaps,
                        "correlation gap event observed;",
                        "correlation gap events observed;"
                    )
                ),
                ..Default::default()
            };
            return (ch, rel_mapping, rel_copy, rel_sync);
        }
        // Split mode: a generic correlation gap is attributed
        // to the mapping/release class; the other classes pass
        // through untouched.
        let phrase = format!(
            "{} cross-event evidence may be missing.",
            plural(
                self.corr_gaps,
                "correlation gap event observed;",
                "correlation gap events observed;"
            )
        );
        if rel_mapping.status == "partial" {
            rel_mapping.reason = truncate_codepoints(
                &format!("{phrase}; previously: {}", rel_mapping.reason),
                512,
            );
        } else {
            rel_mapping.reason = phrase;
        }
        rel_mapping.status = "partial".to_string();
        rel_mapping.has_loss_count = false;
        let agg = rollup_split_relations(&rel_mapping, &rel_copy, &rel_sync);
        (agg, rel_mapping, rel_copy, rel_sync)
    }

    fn build_baseline(&mut self) -> Channel {
        let producer = self.session.q_baseline.clone();
        if self.base_gaps == 0 {
            return producer;
        }
        let ch = Channel {
            status: "partial".to_string(),
            scope: producer.scope.clone(),
            reason: format!(
                "{} baseline coverage unverified.",
                plural(
                    self.base_gaps,
                    "baseline gap event observed;",
                    "baseline gap events observed;"
                )
            ),
            ..Default::default()
        };
        self.note_fixed(format!(
            "{} channel partial.",
            plural(
                self.base_gaps,
                "baseline gap event observed;",
                "baseline gap events observed;"
            )
        ));
        ch
    }
}

impl AttemptAnalyzer {
    #[allow(clippy::too_many_arguments)]
    fn build_metrics(
        &mut self,
        out: &mut Report,
        window: &str,
        noun: &str,
        order: &[usize],
        partial: bool,
        has_pools: bool,
        has_regions: bool,
    ) {
        let detail_cov = coverage_of(&out.q_detail.status);
        let agg_cov = coverage_of(&out.q_aggregate.status);
        let snapshots = self.snapshot_total();
        let mut snap_frag = "; no counter snapshots to compare.".to_string();
        if snapshots > 0 {
            snap_frag = format!(
                "; {}",
                plural(
                    snapshots,
                    "counter snapshot observed separately (never added).",
                    "counter snapshots observed separately (never added)."
                )
            );
        }
        let mut gap_frag = String::new();
        if self.detail_gaps > 0 {
            gap_frag = "; counts are lower bounds.".to_string();
        }
        let mut partial_frag = String::new();
        if partial {
            partial_frag = "; truncated tail excluded.".to_string();
        }
        let producer_detail = self.session.q_detail.status.clone();
        let usable_detail = self.total_count > 0
            || producer_detail == "complete_for_scope"
            || producer_detail == "partial";
        let all_scope = self.bounded_device_scope(window, ", detail channel");
        if usable_detail {
            out.metrics.push(detail_metric(
                "bounce_attempts",
                "count",
                true,
                self.total_count as u64,
                &detail_cov,
                false,
                "",
                &all_scope,
                &format!(
                    "{}{}{}{}",
                    plural(self.total_count, "detail event", "detail events"),
                    snap_frag,
                    gap_frag,
                    partial_frag
                ),
            ));
        } else {
            out.metrics.push(detail_metric(
                "bounce_attempts",
                "count",
                true,
                0,
                &detail_cov,
                false,
                "",
                &all_scope,
                &format!(
                    "0 detail events observed; producer status {producer_detail}: zero is unconfirmed."
                ),
            ));
        }
        let mut ids: Vec<String> = self.devs.iter().map(|d| d.device_id.clone()).collect();
        ids.sort();
        let single = ids.len() == 1;
        let mut detailed = ids.len();
        if detailed > MAX_DETAILED_DEVICES {
            detailed = MAX_DETAILED_DEVICES;
        }
        let withheld_devs = ids.len() - detailed;
        for si in 0..detailed {
            let idx = self.dev_index[&ids[si]];
            let dev_id = self.devs[idx].device_id.clone();
            let dev_count = self.devs[idx].count;
            let scope = format!("{window}, device {dev_id}, detail channel");
            let cnt = plural(
                dev_count,
                "attempt observed device",
                "attempts observed device",
            );
            let mut note;
            if single {
                note = format!("All {cnt} {dev_id}.");
            } else {
                note = format!("{cnt} {dev_id}.");
            }
            note += &gap_frag;
            note += &partial_frag;
            out.metrics.push(detail_metric(
                "bounce_attempts",
                "count",
                true,
                dev_count as u64,
                &detail_cov,
                true,
                &dev_id,
                &scope,
                &note,
            ));
        }
        if usable_detail && !self.total_overflow {
            let text = summand_text(&self.total_summands, self.total_bytes, self.total_count);
            let mut outcome_frag = format!("; allocation outcomes are unavailable in this {noun}.");
            if self.saw_map {
                outcome_frag = "; see successful_allocations for observed outcomes.".to_string();
            }
            out.metrics.push(detail_metric(
                "requested_bounce_bytes",
                "bytes",
                true,
                self.total_bytes,
                &detail_cov,
                false,
                "",
                &all_scope,
                &format!(
                    "{text} requested bytes across {}{}{}{}",
                    plural(self.total_count, "attempt", "attempts"),
                    outcome_frag,
                    gap_frag,
                    partial_frag
                ),
            ));
        } else if usable_detail {
            out.metrics.push(detail_metric(
                "requested_bounce_bytes",
                "bytes",
                false,
                0,
                "unavailable",
                false,
                "",
                &all_scope,
                "Requested-byte total exceeds u64 range; value withheld.",
            ));
        } else {
            out.metrics.push(detail_metric(
                "requested_bounce_bytes",
                "bytes",
                true,
                0,
                &detail_cov,
                false,
                "",
                &all_scope,
                &format!(
                    "0 requested bytes observed; producer status {producer_detail}: zero is unconfirmed."
                ),
            ));
        }
        for si in 0..detailed {
            let idx = self.dev_index[&ids[si]];
            let dev_id = self.devs[idx].device_id.clone();
            let scope = format!("{window}, device {dev_id}, detail channel");
            if !self.devs[idx].bytes_overflow {
                let text = summand_text(
                    &self.devs[idx].summands.clone(),
                    self.devs[idx].total_bytes,
                    self.devs[idx].count,
                );
                out.metrics.push(detail_metric(
                    "requested_bounce_bytes",
                    "bytes",
                    true,
                    self.devs[idx].total_bytes,
                    &detail_cov,
                    true,
                    &dev_id,
                    &scope,
                    &format!("{text} requested bytes on device {dev_id}.{gap_frag}{partial_frag}"),
                ));
            } else {
                out.metrics.push(detail_metric(
                    "requested_bounce_bytes",
                    "bytes",
                    false,
                    0,
                    "unavailable",
                    true,
                    &dev_id,
                    &scope,
                    "Requested-byte total exceeds u64 range; value withheld.",
                ));
            }
        }
        let mut prev_emitted = false;
        let mut prev_name = String::new();
        let mut prev_has_device = false;
        let mut prev_device = String::new();
        let detail_cov2 = coverage_of(&out.q_detail.status);
        let row_cov = worse_coverage(&agg_cov, &detail_cov2);
        if withheld_devs > 0 {
            self.note_fixed(format!(
                "{} metric budget exhausted.",
                plural(
                    withheld_devs,
                    "device lacks detail rows:",
                    "devices lack detail rows:"
                )
            ));
        }
        let mut rows_left =
            MAX_METRICS as i64 - 2 - 2 * detailed as i64 - FIXED_TAIL_METRICS as i64;
        let mut rows_withheld = 0;
        for oi in order {
            let g = self.ctrs[*oi].clone();
            if !group_cause(&g).is_empty() {
                continue;
            }
            let delta = g.last_value - g.first_value;
            let cname = counter_metric_name(&g.counter_id);
            if prev_emitted
                && cname == prev_name
                && g.has_device == prev_has_device
                && g.device == prev_device
            {
                self.note_data(format!(
                    "Additional {} group ({}, profile {}) excluded from metrics; one row per name and dimensions.",
                    g.counter_id,
                    group_scope_label(g.has_device, &g.device),
                    g.profile
                ));
                continue;
            }
            if rows_left <= 0 {
                rows_withheld += 1;
                continue;
            }
            let scope = format!(
                "readings [{},{}), {}, aggregate channel",
                format_u64(g.first_ts),
                format_u64(g.last_ts),
                group_scope_label(g.has_device, &g.device)
            );
            let notes = format!(
                "Counter delta {} -> {} ({}); detail events counted separately (never added).",
                format_u64(g.first_value),
                format_u64(g.last_value),
                g.counter_id
            );
            let mut cm = detail_metric(
                &cname,
                &g.unit,
                true,
                delta,
                &row_cov,
                g.has_device,
                &g.device,
                &scope,
                &notes,
            );
            cm.measurement = "derived".to_string();
            out.metrics.push(cm);
            rows_left -= 1;
            prev_emitted = true;
            prev_name = cname;
            prev_has_device = g.has_device;
            prev_device = g.device;
        }
        if self.ctrs_ignored > 0 {
            self.note_fixed(format!(
                "{} admission bound reached.",
                plural(
                    self.ctrs_ignored,
                    "counter reading ignored:",
                    "counter readings ignored:"
                )
            ));
        }
        if rows_withheld > 0 {
            self.note_fixed(format!(
                "{} metric budget exhausted.",
                plural(
                    rows_withheld,
                    "counter delta withheld:",
                    "counter deltas withheld:"
                )
            ));
        }
        let uscope = self.bounded_device_scope(window, "");
        // Placeholders are skipped exactly when the composed
        // engine's tracker rows cover the same (name,
        // dimensions) key, so each key keeps one measurement
        // channel.
        if !self.saw_lifecycle() {
            out.metrics.push(unavailable_metric(
                "successful_allocations",
                "count",
                &uscope,
                &format!("No map_result source in this {noun}; attempts are not successes."),
            ));
            out.metrics.push(unavailable_metric(
                "copy_original_to_bounce_bytes",
                "bytes",
                &uscope,
                &format!("No copy source in this {noun}."),
            ));
            out.metrics.push(unavailable_metric(
                "copy_bounce_to_original_bytes",
                "bytes",
                &uscope,
                &format!("No copy source in this {noun}."),
            ));
            out.metrics.push(unavailable_metric(
                "live_observed_allocation_bytes",
                "bytes",
                &uscope,
                &format!("No lifecycle source in this {noun}."),
            ));
        }
        if !self.saw_map && !self.saw_unmap {
            out.metrics.push(unavailable_metric(
                "observed_mapping_lifetime_ns",
                "nanoseconds",
                &uscope,
                &format!("No lifecycle source in this {noun}."),
            ));
        }
        if !has_regions {
            out.metrics.push(unavailable_metric(
                "conversion_request_bytes",
                "bytes",
                &uscope,
                &format!("No conversion source in this {noun}."),
            ));
            out.metrics.push(unavailable_metric(
                "known_shared_region_bytes",
                "bytes",
                &uscope,
                &format!("No region source in this {noun}."),
            ));
        }
        if !has_pools {
            out.metrics.push(unavailable_metric(
                "pool_used_bytes",
                "bytes",
                &uscope,
                &format!("No pool source in this {noun}."),
            ));
            out.metrics.push(unavailable_metric(
                "pool_capacity_bytes",
                "bytes",
                &uscope,
                &format!("No pool source in this {noun}."),
            ));
            out.metrics.push(unavailable_metric(
                "pool_hiwater_bytes",
                "bytes",
                &uscope,
                &format!("No pool source in this {noun}."),
            ));
        }
    }

    /// Reduce the consumed stream to one Report.
    ///
    /// end_ns must equal the session window end: counts always
    /// cover the whole capture, so a narrowed horizon would label
    /// a scope the measurements do not match. Partial reports a
    /// dropped truncated tail. The composed engine passes
    /// has_pools/has_regions when it appends pool/region rows;
    /// lifecycle scope is detected from the consumed stream
    /// itself.
    pub fn finish(
        &mut self,
        end_ns: u64,
        partial: bool,
        has_pools: bool,
        has_regions: bool,
    ) -> Result<Report, AnalysisError> {
        if end_ns < self.session.window_start_ns || end_ns > self.session.window_end_ns {
            return Err(AnalysisError::new("horizon outside session window"));
        }
        if end_ns != self.session.window_end_ns {
            return Err(AnalysisError::new("narrowed horizon unsupported"));
        }
        Ok(self.render(end_ns, partial, has_pools, has_regions))
    }

    /// Reduce the stream so far through the finish reducers.
    ///
    /// Unlike finish, the horizon may narrow to a replay prefix.
    /// The build checkpoints and restores its note state, so
    /// snapshot and finish share every reducer with no
    /// destructive finalization; the equivalence tests pin this.
    pub fn snapshot(
        &mut self,
        end_ns: u64,
        partial: bool,
        has_pools: bool,
        has_regions: bool,
    ) -> Result<Report, AnalysisError> {
        if end_ns < self.session.window_start_ns || end_ns > self.session.window_end_ns {
            return Err(AnalysisError::new("horizon outside session window"));
        }
        Ok(self.render(end_ns, partial, has_pools, has_regions))
    }

    fn render(&mut self, end_ns: u64, partial: bool, has_pools: bool, has_regions: bool) -> Report {
        // Build one report, restoring mutable build state after.
        let saved_fixed = self.fixed_notes.clone();
        let saved_data = self.data_notes.clone();
        let saved_text = self.disagree_text.clone();
        let saved_extra = self.disagree_extra;
        let saved_refs = self.disagree_refs.clone();
        let out = self.build(end_ns, partial, has_pools, has_regions);
        self.fixed_notes = saved_fixed;
        self.data_notes = saved_data;
        self.disagree_text = saved_text;
        self.disagree_extra = saved_extra;
        self.disagree_refs = saved_refs;
        out
    }

    fn build(&mut self, end_ns: u64, partial: bool, has_pools: bool, has_regions: bool) -> Report {
        self.scope_elided = false;
        let mut out = Report {
            session_id: self.session.session_id.clone(),
            synthetic: self.session.synthetic,
            engine_version: ENGINE_VERSION.to_string(),
            window_start_ns: self.session.window_start_ns,
            window_end_ns: end_ns,
            env: ReportEnv {
                mode: self.session.env_mode.clone(),
                detection: self.session.env_detection.clone(),
                has_asserted_mode: self.session.has_asserted_mode,
                asserted_mode: self.session.asserted_mode.clone(),
                asserted_mode_present: self.session.asserted_mode_present,
                attestation: self.session.env_attestation.clone(),
                evidence: self.session.evidence.clone(),
            },
            devices: self.session.devices.clone(),
            ..Default::default()
        };
        echo_cap(
            &mut out,
            "bounce_attempts",
            &self.session.cap_bounce_attempts.clone(),
        );
        echo_cap(
            &mut out,
            "mapping_lifecycle",
            &self.session.cap_mapping_lifecycle.clone(),
        );
        echo_cap(&mut out, "copy_bytes", &self.session.cap_copy_bytes.clone());
        echo_cap(
            &mut out,
            "sync_requests",
            &self.session.cap_sync_requests.clone(),
        );
        echo_cap(
            &mut out,
            "conversion_results",
            &self.session.cap_conversion_results.clone(),
        );
        echo_cap(
            &mut out,
            "region_state",
            &self.session.cap_region_state.clone(),
        );
        echo_cap(&mut out, "pool_stats", &self.session.cap_pool_stats.clone());
        echo_cap(
            &mut out,
            "task_context",
            &self.session.cap_task_context.clone(),
        );
        let window = window_label(self.session.window_start_ns, end_ns);
        let mut noun = "capture";
        if self.session.synthetic {
            noun = "fixture";
        }
        if self.session.synthetic {
            self.note_fixed(
                "Synthetic fixture: every value is authored test data; no guest was booted and no hook attached."
                    .to_string(),
            );
        }
        if has_regions {
            self.note_fixed(
                "This analyzer reduces bounce attempts, counter deltas, and observed lifecycle/pool/region scope; task-context metrics are unavailable."
                    .to_string(),
            );
        } else if self.saw_lifecycle() || has_pools {
            self.note_fixed(
                "This analyzer reduces bounce attempts, counter deltas, and observed lifecycle/pool scope; conversion, region, and task-context metrics are unavailable."
                    .to_string(),
            );
        } else {
            self.note_fixed(
                "This analyzer reduces bounce attempts and counter deltas only; lifecycle, copy, sync, conversion, region, pool, and task-context metrics are unavailable."
                    .to_string(),
            );
        }
        if self.snapshot_total() == 0 {
            self.note_fixed(
                "No counter snapshots: attempt totals rest on the detail channel alone."
                    .to_string(),
            );
        }
        let order = self.group_order();
        out.q_detail = self.build_detail(partial);
        out.q_aggregate = self.build_aggregate(noun, &order);
        let (agg, rel_mapping, rel_copy, rel_sync) = self.build_correlation();
        out.q_correlation = agg;
        if self.session.has_corr_relations {
            out.has_corr_relations = true;
            out.q_corr_mapping = rel_mapping;
            out.q_corr_copy = rel_copy;
            out.q_corr_sync = rel_sync;
        }
        out.q_baseline = self.build_baseline();
        if self.detail_gaps > 0 {
            let mut lost = "unknown".to_string();
            if !self.detail_unknown {
                lost = format_u64(self.detail_lost);
            }
            self.note_fixed(format!(
                "Detail loss: {} ({} lost); attempt counts are lower bounds.",
                plural(self.detail_gaps, "gap event", "gap events"),
                lost
            ));
        }
        let mut overflow = self.total_overflow;
        for d in &self.devs {
            if d.bytes_overflow {
                overflow = true;
            }
        }
        if overflow {
            self.note_fixed("Requested-byte total exceeds u64 range; values withheld.".to_string());
        }
        out.q_terminal = self.build_terminal(partial);
        self.build_metrics(
            &mut out,
            &window,
            noun,
            &order,
            partial,
            has_pools,
            has_regions,
        );
        if attempt_lower_bound(&self.session) {
            // Attempt-channel measurements rest on uncounted
            // skips there; absence claims keep high.
            for m in out.metrics.iter_mut() {
                if m.measurement == "observed" || m.measurement == "derived" {
                    m.confidence = "medium".to_string();
                }
            }
        }
        self.compare_counters(&mut out);
        // The verdict judges the detail measurement: delivered counts
        // bounce_attempt records only, matching the collector's
        // persisted_attempt on intact loads (gap markers and closing
        // records belong to neither side). The counters leg is the
        // cross-check above; the terminal leg reuses the record-side
        // stop predicate, so the report verdict is never better than
        // the record verdict. It is computed before the finding so
        // bounded zero-loss incompleteness demotes to a note.
        let term = terminal_loss_leg(&out.q_terminal.status, &self.session.stop);
        out.detail_delivered = self.total_count as u64;
        out.verdict = verdict_for_counts(
            !out.counter_disagreement,
            out.q_detail.has_loss_count,
            out.q_detail.loss_count,
            out.q_detail.status != "complete_for_scope",
            term.0,
            term.1,
            term.2,
            self.total_count as u64,
        );
        let mut causes: Vec<String> = Vec::new();
        let mut refs: Vec<String> = Vec::new();
        if self.detail_gaps > 0 {
            causes.push("Detail loss observed".to_string());
            refs.push("channel:detail-loss".to_string());
        }
        if !self.session.finalized {
            causes.push("capture not finalized".to_string());
            refs.push("capture:finalized=false".to_string());
        }
        if partial {
            causes.push("truncated tail dropped".to_string());
            refs.push("capture:partial-tail".to_string());
        }
        if self.term_gaps > 0 {
            causes.push("terminal gap observed".to_string());
            refs.push("channel:terminal-gap".to_string());
        }
        if self.detail_gaps == 0 && out.q_detail.status != "complete_for_scope" {
            causes.push(format!(
                "Detail evidence incomplete: {}",
                out.q_detail.reason
            ));
            refs.push("channel:detail".to_string());
        }
        if self.term_gaps == 0 && out.q_terminal.status != "complete_for_scope" {
            causes.push(format!(
                "Terminal evidence incomplete: {}",
                out.q_terminal.reason
            ));
            refs.push("channel:terminal".to_string());
        }
        if self.saw_lifecycle() && out.q_correlation.status != "complete_for_scope" {
            causes.push(format!(
                "Lifecycle correlation incomplete: {}",
                out.q_correlation.reason
            ));
            refs.push("channel:correlation".to_string());
        }
        if out.counter_disagreement {
            let mut cause = format!("counter cross-check disagrees: {}", self.disagree_text);
            if self.disagree_extra > 0 {
                cause += &format!(
                    " {}",
                    plural(
                        self.disagree_extra,
                        "further disagreement",
                        "further disagreements"
                    )
                );
            }
            causes.push(cause);
            for r in self.disagree_refs.clone() {
                if refs.len() < 32 {
                    refs.push(r);
                }
            }
        }
        if !causes.is_empty() {
            let mut expl = format!("Capture incomplete: {}.", causes.join("; "));
            // Producer reasons remain in their quality channels;
            // their combined finding must fit the report text budget.
            if expl.chars().count() > 1024 {
                let prefix: String = expl.chars().take(1021).collect();
                expl = format!("{prefix}...");
            }
            out.findings.push(Finding {
                code: "CAPTURE_INCOMPLETE".to_string(),
                severity: incomplete_finding_severity(
                    &out.verdict.name,
                    out.verdict.loss_ratio_bps,
                ),
                explanation: expl,
                evidence_refs: refs,
                scope: window,
                limitations: "Counts exclude missing evidence. Terminal completeness requires a proven settlement protocol; repeating a capture does not by itself establish settlement."
                    .to_string(),
            });
        }
        if self.scope_elided {
            // The reader bounds the recorded selector to 256
            // characters, so this limitation always fits the
            // 1024-character report budget. Fixed notes always
            // survive the merge, so the literal is never withheld.
            self.note_fixed(format!(
                "Device scope elided to fit the 256-character report bound; capture recorded devices (filter: {}).",
                self.session.filter_device
            ));
        }
        self.merge_limitations(&mut out);
        out
    }

    fn compare_counters(&mut self, out: &mut Report) {
        // Cross-check usable counter deltas against detail counts.
        //
        // A pair is comparable only when quantities and units match by
        // construction, device scopes align, both sides are observed,
        // the reading interval strictly contains the detail span, the
        // detail channel is complete with known zero loss, no
        // relevant byte total overflowed, no capture filter hides the
        // group's scope, and a device-scoped group has observed detail
        // for its device. Anything else is inconclusive, never a
        // disagreement. A mismatch on a comparable pair sets the
        // disagreement flag.
        let detail_ok = out.q_detail.status == "complete_for_scope"
            && out.q_detail.has_loss_count
            && out.q_detail.loss_count == 0
            && !self.detail_non_observed;
        let mut inconclusive = 0;
        for ci in 0..self.ctrs.len() {
            let g = self.ctrs[ci].clone();
            if !group_cause(&g).is_empty() {
                continue;
            }
            let want_count = g.counter_id == "swiotlb.bounce_attempts";
            let want_bytes = g.counter_id == "swiotlb.requested_bytes";
            if !want_count && !want_bytes {
                continue;
            }
            let detail_val: u64;
            let mut overflow = false;
            let mut has_span = false;
            let mut dmin = 0u64;
            let mut dmax = 0u64;
            let mut label = "all devices".to_string();
            if g.has_device {
                label = format!("device {}", g.device);
                if let Some(di) = self.dev_index.get(&g.device) {
                    let di = *di;
                    if want_count {
                        detail_val = self.devs[di].count as u64;
                    } else {
                        detail_val = self.devs[di].total_bytes;
                    }
                    overflow = self.devs[di].bytes_overflow;
                    has_span = self.devs[di].has_ts;
                    dmin = self.devs[di].min_ts;
                    dmax = self.devs[di].max_ts;
                } else {
                    detail_val = 0;
                }
            } else {
                if want_count {
                    detail_val = self.total_count as u64;
                } else {
                    detail_val = self.total_bytes;
                }
                overflow = self.total_overflow;
                has_span = self.has_detail_ts;
                dmin = self.detail_min_ts;
                dmax = self.detail_max_ts;
            }
            let mut contained = true;
            if has_span {
                contained = g.first_ts < dmin && dmax < g.last_ts;
            }
            let mut scope_ok = true;
            if g.has_device {
                scope_ok = has_span;
            } else if self.session.has_filter_device {
                scope_ok = false;
            }
            let comparable = detail_ok
                && g.source_measurement == "observed"
                && contained
                && scope_ok
                && !(want_bytes && overflow);
            if !comparable {
                inconclusive += 1;
                continue;
            }
            let delta = g.last_value - g.first_value;
            if delta == detail_val {
                continue;
            }
            let mut metric = "bounce_attempts".to_string();
            if want_bytes {
                metric = "requested_bounce_bytes".to_string();
            }
            let text = format!(
                "{metric} ({label}): detail {} vs counter delta {}",
                format_u64(detail_val),
                format_u64(delta)
            );
            if !out.counter_disagreement {
                out.counter_disagreement = true;
                self.disagree_text = text;
            } else {
                self.disagree_extra += 1;
            }
            if self.disagree_refs.len() < 8 {
                self.disagree_refs.push(format!("counter:{}", g.counter_id));
            }
        }
        if inconclusive > 0 {
            self.note_fixed(format!(
                "{} scope or coverage insufficient.",
                plural(
                    inconclusive,
                    "counter comparison inconclusive;",
                    "counter comparisons inconclusive;"
                )
            ));
        }
    }

    fn merge_limitations(&mut self, out: &mut Report) {
        // Merge fixed and data notes into at most 256 limitations.
        //
        // Fixed notes are few by construction and always survive; data
        // notes fill the remaining room in emission order, and any
        // excess collapses into one withheld note. A final backstop
        // truncates defensively so the bound holds absolutely.
        out.limitations.extend(self.fixed_notes.iter().cloned());
        let mut budget = MAX_LIMITATIONS as i64 - 1 - out.limitations.len() as i64;
        if budget < 0 {
            budget = 0;
        }
        let mut kept = self.data_notes.len();
        if kept > budget as usize {
            kept = budget as usize;
        }
        out.limitations
            .extend(self.data_notes.iter().take(kept).cloned());
        let dropped = self.data_notes.len() - kept;
        if dropped > 0 {
            out.limitations.push(plural(
                dropped,
                "further limitation withheld.",
                "further limitations withheld.",
            ));
        }
        if out.limitations.len() > MAX_LIMITATIONS {
            let mut cut: Vec<String> = out
                .limitations
                .iter()
                .take(MAX_LIMITATIONS - 1)
                .cloned()
                .collect();
            cut.push("Further limitations withheld.".to_string());
            out.limitations = cut;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::reader::{default_limits, read_capture};
    use crate::model::event::{BounceAttempt, CounterSnapshot, Event, Gap};
    use crate::model::metric::Metric;
    use crate::model::report::Report;
    use crate::model::session::Channel;
    use crate::model::session::Session;

    fn fixture(rel: &str) -> String {
        format!("{}/../{rel}", env!("CARGO_MANIFEST_DIR"))
    }

    fn analyze(dir: &str, allow: bool) -> Report {
        let mut r = read_capture(&fixture(dir), allow, default_limits()).expect("read capture");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        while r.has_more().expect("has_more") {
            a.consume(&r.next_event().expect("next"));
        }
        let end = r.session.window_end_ns;
        let partial = r.partial;
        a.finish(end, partial, false, false).expect("finish")
    }

    fn metric_by_name<'a>(report: &'a Report, name: &str, device: &str) -> &'a Metric {
        report
            .metrics
            .iter()
            .find(|m| {
                if m.name != name {
                    return false;
                }
                if device.is_empty() {
                    !m.has_device_id
                } else {
                    m.has_device_id && m.device_id == device
                }
            })
            .unwrap_or_else(|| panic!("metric not found: {name} [{device}]"))
    }

    fn aggregate_metric<'a>(rep: &'a Report, name: &str) -> &'a Metric {
        rep.metrics
            .iter()
            .find(|m| m.name == name && m.scope.starts_with("readings ["))
            .unwrap_or_else(|| panic!("aggregate metric not found: {name}"))
    }

    fn has_limitation(rep: &Report, needle: &str) -> bool {
        rep.limitations.iter().any(|n| n.contains(needle))
    }

    fn bounce_event(device: &str, op: &str, req: u64) -> Event {
        Event {
            kind: "bounce_attempt".to_string(),
            bounce: BounceAttempt {
                device_id: device.to_string(),
                operation_id: op.to_string(),
                requested_bytes: req,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn snapshot_event(counter: &str, device: &str, profile: &str, epoch: u64, value: u64) -> Event {
        Event {
            kind: "counter_snapshot".to_string(),
            snapshot: CounterSnapshot {
                counter_id: counter.to_string(),
                has_scope_device: true,
                scope_device_id: device.to_string(),
                scope_profile_id: profile.to_string(),
                epoch,
                value,
                unit: "count".to_string(),
            },
            ..Default::default()
        }
    }

    fn gap_event(channel: &str, lost: u64, ws: u64, we: u64) -> Event {
        Event {
            kind: "gap".to_string(),
            gap: Gap {
                channel: channel.to_string(),
                has_lost_count: true,
                lost_count: lost,
                window_start_ns: ws,
                window_end_ns: we,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn reducer_attempts_fixture() {
        let rep = analyze("tests/fixtures/attempts", false);
        assert_eq!(rep.session_id, "attempts-3-session");
        assert!(rep.synthetic);
        assert_eq!(rep.engine_version, ENGINE_VERSION);
        // Parity pin: the single-sourced version stays
        // byte-identical with Mojo's ENGINE_VERSION.
        assert_eq!(crate::ENGINE_VERSION, "memveil-0.1.0");
        assert_eq!(rep.metrics.len(), 14);
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert!(attempts.has_value);
        assert_eq!(attempts.value, 3);
        assert_eq!(attempts.unit, "count");
        assert_eq!(attempts.measurement, "observed");
        assert_eq!(attempts.coverage, "complete_for_scope");
        assert_eq!(
            attempts.scope,
            "window [1000000000,4000000000), all devices, detail channel"
        );
        assert_eq!(
            attempts.notes,
            "3 detail events; no counter snapshots to compare."
        );
        let dev = metric_by_name(&rep, "bounce_attempts", "dev-1");
        assert_eq!(dev.value, 3);
        assert_eq!(dev.notes, "All 3 attempts observed device dev-1.");
        let bytes_all = metric_by_name(&rep, "requested_bounce_bytes", "");
        assert_eq!(bytes_all.value, 9216);
        assert_eq!(
            bytes_all.notes,
            "4096 + 4096 + 1024 requested bytes across 3 attempts; allocation outcomes are unavailable in this fixture."
        );
        let bytes_dev = metric_by_name(&rep, "requested_bounce_bytes", "dev-1");
        assert_eq!(bytes_dev.value, 9216);
        assert_eq!(
            bytes_dev.notes,
            "4096 + 4096 + 1024 requested bytes on device dev-1."
        );
        for name in [
            "successful_allocations",
            "copy_original_to_bounce_bytes",
            "copy_bounce_to_original_bytes",
            "live_observed_allocation_bytes",
            "observed_mapping_lifetime_ns",
            "conversion_request_bytes",
            "known_shared_region_bytes",
            "pool_used_bytes",
            "pool_capacity_bytes",
        ] {
            let m = metric_by_name(&rep, name, "");
            assert!(!m.has_value, "{name}");
            assert_eq!(m.measurement, "unavailable");
            assert_eq!(m.coverage, "unavailable");
        }
        assert_eq!(rep.q_detail.status, "complete_for_scope");
        assert!(rep.q_detail.has_loss_count);
        assert_eq!(rep.q_detail.loss_count, 0);
        assert_eq!(rep.q_detail.scope, "3 bounce_attempt events");
        assert_eq!(rep.q_detail.reason, "Authored fixture: no loss.");
        assert_eq!(rep.q_aggregate.status, "unavailable");
        assert_eq!(rep.q_correlation.status, "complete_for_scope");
        assert_eq!(rep.q_baseline.status, "not_applicable");
        assert_eq!(rep.q_terminal.status, "complete_for_scope");
        assert_eq!(rep.findings.len(), 0);
        assert_eq!(rep.limitations.len(), 3);
        assert_eq!(
            rep.limitations[0],
            "Synthetic fixture: every value is authored test data; no guest was booted and no hook attached."
        );
        assert_eq!(
            rep.limitations[1],
            "This analyzer reduces bounce attempts and counter deltas only; lifecycle, copy, sync, conversion, region, pool, and task-context metrics are unavailable."
        );
        assert_eq!(
            rep.limitations[2],
            "No counter snapshots: attempt totals rest on the detail channel alone."
        );
    }

    #[test]
    fn report_verdict_wiring() {
        // 3 bounce events consumed; the fixture terminal claims complete
        // but carries no proving stop evidence, so the verdict fails
        // closed to unknown with zero known loss.
        let rep = analyze("tests/fixtures/attempts", false);
        assert_eq!(rep.detail_delivered, 3);
        assert_eq!(rep.verdict.name, "partial_unknown_loss");
        assert_eq!(rep.verdict.loss_ratio_bps, 0);
    }

    #[test]
    fn reducer_device_dimensions() {
        let rep = analyze("tests/fixtures/reader/multidev", false);
        let all_m = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(all_m.value, 3);
        let d1 = metric_by_name(&rep, "bounce_attempts", "dev-1");
        let d2 = metric_by_name(&rep, "bounce_attempts", "dev-2");
        assert_eq!(d1.value, 2);
        assert_eq!(d2.value, 1);
        assert_eq!(d1.value + d2.value, all_m.value);
        assert_eq!(d1.notes, "2 attempts observed device dev-1.");
        let b1 = metric_by_name(&rep, "requested_bounce_bytes", "dev-1");
        let b2 = metric_by_name(&rep, "requested_bounce_bytes", "dev-2");
        assert_eq!(b1.value, 5120);
        assert_eq!(b2.value, 2048);
        assert_eq!(b1.notes, "4096 + 1024 requested bytes on device dev-1.");
        let mut seen_dev1 = None;
        let mut seen_dev2 = None;
        for (i, m) in rep.metrics.iter().enumerate() {
            if m.name == "bounce_attempts" && m.has_device_id {
                if m.device_id == "dev-1" {
                    seen_dev1 = Some(i);
                } else if m.device_id == "dev-2" {
                    seen_dev2 = Some(i);
                }
            }
        }
        let (d1i, d2i) = (seen_dev1.unwrap(), seen_dev2.unwrap());
        assert!(d1i < d2i);
    }

    #[test]
    fn counter_deltas() {
        let rep = analyze("tests/fixtures/reader/counters", false);
        let detail = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(detail.value, 3);
        let detail_bytes = metric_by_name(&rep, "requested_bounce_bytes", "");
        assert_eq!(detail_bytes.value, 9216);
        let agg = aggregate_metric(&rep, "counter_bounce_attempts");
        assert!(agg.has_value);
        assert_eq!(agg.value, 3);
        assert_eq!(agg.unit, "count");
        assert_eq!(agg.measurement, "derived");
        assert_eq!(agg.coverage, "complete_for_scope");
        assert_eq!(agg.aggregation, "counter");
        assert_eq!(
            agg.notes,
            "Counter delta 10 -> 13 (swiotlb.bounce_attempts); detail events counted separately (never added)."
        );
        let agg_bytes = aggregate_metric(&rep, "counter_requested_bounce_bytes");
        assert_eq!(agg_bytes.value, 9216);
        assert_eq!(agg_bytes.unit, "bytes");
        assert_eq!(agg_bytes.measurement, "derived");
        assert_eq!(rep.q_aggregate.status, "complete_for_scope");
        for n in &rep.limitations {
            assert_ne!(
                n,
                "No counter snapshots: attempt totals rest on the detail channel alone."
            );
        }
    }

    #[test]
    fn counter_unusable() {
        let epoch = analyze("tests/fixtures/reader/counters-epoch", false);
        assert_eq!(epoch.metrics.len(), 12);
        assert_eq!(
            epoch.limitations.last().unwrap(),
            "Counter swiotlb.bounce_attempts (all devices): epoch changed 3 -> 4; no delta computed."
        );
        let single = analyze("tests/fixtures/reader/counters-single", false);
        assert_eq!(
            single.limitations.last().unwrap(),
            "Counter swiotlb.bounce_attempts (all devices): single snapshot; no pair for a delta."
        );
        let decrease = analyze("tests/fixtures/reader/counters-decrease", false);
        assert_eq!(
            decrease.limitations.last().unwrap(),
            "Counter swiotlb.bounce_attempts (all devices): value decreased 13 -> 10 within epoch 3; no delta computed."
        );
        let scope = analyze("tests/fixtures/reader/counters-scope", false);
        assert_eq!(
            scope.limitations[scope.limitations.len() - 2],
            "Counter swiotlb.bounce_attempts (device dev-1): single snapshot; no pair for a delta."
        );
        assert_eq!(
            scope.limitations.last().unwrap(),
            "Counter swiotlb.bounce_attempts (device dev-2): single snapshot; no pair for a delta."
        );
        assert_eq!(epoch.q_aggregate.status, "partial");
    }

    #[test]
    fn counter_unknown_id() {
        let rep = analyze("tests/fixtures/reader/counters-unknown", false);
        assert_eq!(rep.metrics.len(), 12);
        assert_eq!(rep.q_aggregate.status, "partial");
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Counter vendor.mystery (all devices): unknown counter id; no metric mapping."
        );
        assert!(
            !rep.metrics
                .iter()
                .any(|m| m.name == "counter_vendor.mystery")
        );
    }

    #[test]
    fn counter_same_scope_collapse() {
        let rep = analyze("tests/fixtures/reader/counters-collapse", false);
        let agg = aggregate_metric(&rep, "counter_bounce_attempts");
        assert_eq!(agg.value, 3);
        assert_eq!(agg.measurement, "derived");
        assert_eq!(rep.metrics.len(), 13);
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Additional swiotlb.bounce_attempts group (all devices, profile synthetic-attempts-2) excluded from metrics; one row per name and dimensions."
        );
    }

    fn hooked_snapshot(hook: &str, ts: u64, value: u64) -> Event {
        let mut ev = snapshot_event("swiotlb.bounce_attempts", "dev-1", "p", 3, value);
        ev.source_hook = hook.to_string();
        ev.ts_ns = ts;
        ev
    }

    #[test]
    fn counter_sort_tie_keeps_insertion_order() {
        // Deliberate divergence from the Mojo behavior source: Mojo
        // orders counter groups with an unstable quicksort while Rust
        // uses a stable sort, so groups that tie on all four sort keys
        // (counter, device, profile, unit) keep insertion order here.
        // The tie is reachable because hook, backend, measurement, and
        // correlation join the grouping key but not the comparator.
        // The first-inserted group wins the single metric row; the
        // loser is disclosed as excluded. Both insertion orders are
        // pinned, so the winner follows arrival, not values.
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        a.consume(&hooked_snapshot("hook-a", 100, 10));
        a.consume(&hooked_snapshot("hook-a", 200, 13));
        a.consume(&hooked_snapshot("hook-b", 300, 100));
        a.consume(&hooked_snapshot("hook-b", 400, 200));
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        let rows: Vec<&Metric> = rep
            .metrics
            .iter()
            .filter(|m| m.name == "counter_bounce_attempts")
            .collect();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].value, 3);
        assert_eq!(
            rows[0].scope,
            "readings [100,200), device dev-1, aggregate channel"
        );
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Additional swiotlb.bounce_attempts group (device dev-1, profile p) excluded from metrics; one row per name and dimensions."
        );
        let mut b = AttemptAnalyzer::new(r.session.clone());
        b.consume(&hooked_snapshot("hook-b", 300, 100));
        b.consume(&hooked_snapshot("hook-b", 400, 200));
        b.consume(&hooked_snapshot("hook-a", 100, 10));
        b.consume(&hooked_snapshot("hook-a", 200, 13));
        let rep2 = b
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        let agg2 = aggregate_metric(&rep2, "counter_bounce_attempts");
        assert_eq!(agg2.value, 100);
        assert_eq!(
            agg2.scope,
            "readings [300,400), device dev-1, aggregate channel"
        );
        assert_eq!(
            rep2.limitations.last().unwrap(),
            "Additional swiotlb.bounce_attempts group (device dev-1, profile p) excluded from metrics; one row per name and dimensions."
        );
    }

    #[test]
    fn detail_loss() {
        let rep = analyze("tests/fixtures/reader/detail-gap", false);
        assert_eq!(rep.q_detail.status, "partial");
        assert!(rep.q_detail.has_loss_count);
        assert_eq!(rep.q_detail.loss_count, 2);
        assert_eq!(rep.q_detail.scope, "2 bounce_attempt events, 1 detail gap");
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(attempts.value, 2);
        assert_eq!(attempts.coverage, "partial");
        assert_eq!(rep.findings.len(), 1);
        assert_eq!(rep.findings[0].code, "CAPTURE_INCOMPLETE");
        assert_eq!(rep.findings[0].severity, "warning");
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Detail loss: 1 gap event (2 lost); attempt counts are lower bounds."
        );
        let unknown = analyze("tests/fixtures/reader/detail-gap-unknown", false);
        assert_eq!(unknown.q_detail.status, "partial");
        assert!(!unknown.q_detail.has_loss_count);
        assert_eq!(
            unknown.limitations.last().unwrap(),
            "Detail loss: 1 gap event (unknown lost); attempt counts are lower bounds."
        );
    }

    #[test]
    fn partial_and_unfinalized() {
        let mut r = read_capture(
            &fixture("tests/fixtures/reader/partial-tail"),
            true,
            default_limits(),
        )
        .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        while r.has_more().expect("has_more") {
            a.consume(&r.next_event().expect("next"));
        }
        let end = r.session.window_end_ns;
        let rep = a.finish(end, r.partial, false, false).expect("finish");
        assert!(r.partial);
        assert_eq!(rep.q_terminal.status, "partial");
        assert!(!rep.q_terminal.has_loss_count);
        assert_eq!(rep.findings.len(), 1);
        assert_eq!(rep.findings[0].code, "CAPTURE_INCOMPLETE");
        let clean = analyze("tests/fixtures/attempts", false);
        assert_eq!(clean.q_terminal.status, "complete_for_scope");
        let r2 = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut forced = AttemptAnalyzer::new(r2.session.clone());
        let rep_forced = forced
            .finish(4000000000, true, false, false)
            .expect("finish");
        assert_eq!(rep_forced.q_terminal.status, "partial");
        let unfin = analyze("tests/fixtures/reader/unfinalized", false);
        assert_eq!(unfin.q_terminal.status, "partial");
        assert_eq!(unfin.findings.len(), 1);
    }

    #[test]
    fn empty_capture() {
        let rep = analyze("tests/fixtures/reader/empty-events", false);
        assert_eq!(rep.metrics.len(), 12);
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert!(attempts.has_value);
        assert_eq!(attempts.value, 0);
        assert_eq!(attempts.coverage, "complete_for_scope");
        assert_eq!(
            attempts.notes,
            "0 detail events; no counter snapshots to compare."
        );
        assert_eq!(rep.findings.len(), 0);
    }

    #[test]
    fn requested_bytes_overflow() {
        // The reader rejects overflowing streams, so the analyzer's own
        // overflow guard is fed synthetic events directly here.
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        for _ in 0..2 {
            let ev = Event {
                kind: "bounce_attempt".to_string(),
                bounce: BounceAttempt {
                    device_id: "dev-1".to_string(),
                    requested_bytes: u64::MAX,
                    ..Default::default()
                },
                ..Default::default()
            };
            a.consume(&ev);
        }
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(attempts.value, 2);
        let bytes_all = metric_by_name(&rep, "requested_bounce_bytes", "");
        assert!(!bytes_all.has_value);
        assert_eq!(bytes_all.measurement, "unavailable");
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Requested-byte total exceeds u64 range; values withheld."
        );
    }

    #[test]
    fn tail_metric_count_pinned() {
        let rep = analyze("tests/fixtures/attempts", false);
        assert_eq!(rep.metrics.len(), 14);
        let names = [
            "successful_allocations",
            "copy_original_to_bounce_bytes",
            "copy_bounce_to_original_bytes",
            "live_observed_allocation_bytes",
            "observed_mapping_lifetime_ns",
            "conversion_request_bytes",
            "known_shared_region_bytes",
            "pool_used_bytes",
            "pool_capacity_bytes",
        ];
        for (i, want) in names.iter().enumerate() {
            assert_eq!(rep.metrics[4 + i].name, *want);
        }
    }

    #[test]
    fn device_admission_bound() {
        // Metric-budget contract: the analyzer never raises
        // past the device budget. Per-device detail rows are
        // withheld with a limitation note (counter-row
        // precedent) so every 4096-device capture replays with
        // exact globals. 2041 devices keep full detail and
        // both aggregate rows; the rest keep exact global
        // accounting without per-device rows.
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        for i in 0..2041 {
            a.consume(&bounce_event(&format!("dev-{i}"), &format!("op-{i}"), 8));
        }
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert_eq!(rep.metrics.len(), 2 + 2 * 2041 + 10);
        assert!(!has_limitation(&rep, "lack detail rows"));
        let mut b = AttemptAnalyzer::new(r.session.clone());
        for i in 0..2042 {
            b.consume(&bounce_event(&format!("dev-{i}"), &format!("op-{i}"), 8));
        }
        let rep2 = b
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert!(has_limitation(&rep2, "1 device lacks detail rows"));
        let all_m = metric_by_name(&rep2, "bounce_attempts", "");
        assert_eq!(all_m.value, 2042);
        assert!(rep2.metrics.len() <= 4096);
    }

    #[test]
    fn counter_budget_withheld() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        for i in 0..2041 {
            a.consume(&bounce_event(&format!("dev-{i}"), &format!("op-{i}"), 8));
        }
        for g in 0..4 {
            let dev = format!("dev-{}", g + 1);
            a.consume(&snapshot_event("swiotlb.bounce_attempts", &dev, "p", 3, 10));
            a.consume(&snapshot_event("swiotlb.bounce_attempts", &dev, "p", 3, 13));
        }
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert_eq!(rep.metrics.len(), 4096);
        assert!(has_limitation(
            &rep,
            "2 counter deltas withheld: metric budget exhausted."
        ));
        assert!(!has_limitation(&rep, "lack detail rows"));
    }

    #[test]
    fn counter_groups_ignored() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        for i in 0..4097 {
            a.consume(&snapshot_event(
                &format!("vendor.flood-{i}"),
                "dev-1",
                "p",
                3,
                10,
            ));
        }
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert_eq!(rep.limitations.len(), 256);
        assert!(has_limitation(
            &rep,
            "1 counter reading ignored: admission bound reached."
        ));
        assert!(has_limitation(&rep, "further limitations withheld."));
        assert_eq!(rep.q_aggregate.status, "partial");
        assert!(!rep.q_aggregate.has_loss_count);
        assert!(rep.q_aggregate.reason.contains("admission bound reached."));
    }

    #[test]
    fn f8_terminal_gap() {
        let rep = analyze("tests/fixtures/reader/f8-terminal-gap", false);
        assert_eq!(rep.q_terminal.status, "partial");
        assert!(!rep.q_terminal.has_loss_count);
        assert_eq!(rep.findings.len(), 1);
        assert!(
            rep.findings[0]
                .explanation
                .contains("terminal gap observed")
        );
    }

    #[test]
    fn f8_aggregate_gap() {
        let rep = analyze("tests/fixtures/reader/f8-aggregate-gap", false);
        assert_eq!(rep.q_aggregate.status, "partial");
        assert!(rep.q_aggregate.has_loss_count);
        assert_eq!(rep.q_aggregate.loss_count, 7);
    }

    #[test]
    fn f8_detail_producer_loss() {
        let rep = analyze("tests/fixtures/reader/f8-detail-producer-loss", false);
        assert_eq!(rep.q_detail.status, "complete_for_scope");
        assert!(rep.q_detail.has_loss_count);
        assert_eq!(rep.q_detail.loss_count, 9);
        assert!(rep.q_detail.reason.contains("(loss 9)"));
    }

    #[test]
    fn f8_partial_detail() {
        let rep = analyze("tests/fixtures/reader/partial-tail", true);
        assert_eq!(rep.q_detail.status, "partial");
        assert!(!rep.q_detail.has_loss_count);
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(attempts.coverage, "partial");
        assert!(attempts.notes.contains("truncated tail excluded"));
    }

    #[test]
    fn f8_gap_overlap() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        a.consume(&gap_event("detail", 5, 10, 20));
        a.consume(&gap_event("detail", 7, 15, 25));
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert_eq!(rep.q_detail.status, "partial");
        assert!(!rep.q_detail.has_loss_count);
        assert!(rep.q_detail.reason.contains("Loss total unknown"));
        let mut b = AttemptAnalyzer::new(r.session.clone());
        b.consume(&gap_event("detail", 5, 10, 20));
        b.consume(&gap_event("detail", 7, 20, 30));
        let rep2 = b
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert!(rep2.q_detail.has_loss_count);
        assert_eq!(rep2.q_detail.loss_count, 12);
    }

    #[test]
    fn f9_mismatch() {
        let rep = analyze("tests/fixtures/reader/f9-mismatch", false);
        assert!(rep.counter_disagreement);
        assert_eq!(rep.findings.len(), 1);
        assert!(
            rep.findings[0]
                .explanation
                .contains("counter cross-check disagrees")
        );
        assert!(
            rep.findings[0]
                .explanation
                .contains("detail 3 vs counter delta 8")
        );
        let row = metric_by_name(&rep, "counter_bounce_attempts", "");
        assert_eq!(
            row.scope,
            "readings [1050000000,1350000000), all devices, aggregate channel"
        );
        assert_eq!(row.coverage, "complete_for_scope");
    }

    #[test]
    fn f9_agree() {
        let rep = analyze("tests/fixtures/reader/f9-agree", false);
        assert!(!rep.counter_disagreement);
        assert_eq!(rep.findings.len(), 0);
    }

    #[test]
    fn f9_inconclusive() {
        let rep = analyze("tests/fixtures/reader/f9-inconclusive-scope", false);
        assert!(!rep.counter_disagreement);
        assert!(has_limitation(&rep, "1 counter comparison inconclusive;"));
        let rep2 = analyze("tests/fixtures/reader/f9-inconclusive-loss", false);
        assert!(!rep2.counter_disagreement);
        assert_eq!(rep2.q_detail.status, "partial");
        assert!(has_limitation(&rep2, "1 counter comparison inconclusive;"));
    }

    #[test]
    fn f9_unit_mismatch() {
        let rep = analyze("tests/fixtures/reader/f9-unit", false);
        assert!(!rep.counter_disagreement);
        assert!(has_limitation(
            &rep,
            "unit mismatch: expected count, observed bytes; no delta computed"
        ));
        assert!(
            !rep.metrics
                .iter()
                .any(|m| m.name == "counter_bounce_attempts")
        );
    }

    #[test]
    fn f9_partial_detail_coverage() {
        let rep = analyze("tests/fixtures/reader/f9-partial-detail", false);
        let row = metric_by_name(&rep, "counter_bounce_attempts", "");
        assert_eq!(row.coverage, "partial");
    }

    #[test]
    fn f9_device_and_source() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        let mut b1 = bounce_event("dev-1", "op-1", 8);
        b1.ts_ns = 1100000000;
        b1.source_measurement = "observed".to_string();
        a.consume(&b1);
        let mut s1 = snapshot_event("swiotlb.bounce_attempts", "dev-1", "p", 3, 0);
        s1.ts_ns = 1050000000;
        s1.source_measurement = "observed".to_string();
        a.consume(&s1);
        let mut s2 = snapshot_event("swiotlb.bounce_attempts", "dev-1", "p", 3, 9);
        s2.ts_ns = 1350000000;
        s2.source_measurement = "observed".to_string();
        a.consume(&s2);
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert!(rep.counter_disagreement);
        assert!(rep.findings[0].explanation.contains("(device dev-1)"));
        let mut c = AttemptAnalyzer::new(r.session.clone());
        let mut b2 = bounce_event("dev-1", "op-1", 8);
        b2.ts_ns = 1100000000;
        b2.source_measurement = "estimated".to_string();
        c.consume(&b2);
        let mut s3 = snapshot_event("swiotlb.bounce_attempts", "dev-1", "p", 3, 0);
        s3.ts_ns = 1050000000;
        s3.source_measurement = "observed".to_string();
        c.consume(&s3);
        let mut s4 = snapshot_event("swiotlb.bounce_attempts", "dev-1", "p", 3, 9);
        s4.ts_ns = 1350000000;
        s4.source_measurement = "observed".to_string();
        c.consume(&s4);
        let rep2 = c
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert!(!rep2.counter_disagreement);
        assert!(has_limitation(&rep2, "1 counter comparison inconclusive;"));
    }

    #[test]
    fn f13_literal_filter_scope() {
        let rep = analyze("tests/fixtures/reader/literal-filter", false);
        let row = metric_by_name(&rep, "bounce_attempts", "");
        assert!(row.scope.contains("recorded devices (filter: testdev0)"));
        assert!(!row.scope.contains("all devices"));
        let plain = analyze("tests/fixtures/attempts", false);
        let prow = metric_by_name(&plain, "bounce_attempts", "");
        assert!(prow.scope.contains("all devices"));
    }

    #[test]
    fn f9_profile_split() {
        let rep = analyze("tests/fixtures/reader/f9-profile-change", false);
        assert!(!rep.counter_disagreement);
        assert_eq!(rep.findings.len(), 0);
        let singles = rep
            .limitations
            .iter()
            .filter(|n| n.contains("single snapshot"))
            .count();
        assert_eq!(singles, 2);
        assert_eq!(rep.q_aggregate.status, "partial");
    }

    #[test]
    fn f9_filtered_global() {
        let rep = analyze("tests/fixtures/reader/f9-filtered-global", false);
        assert!(!rep.counter_disagreement);
        assert_eq!(rep.findings.len(), 0);
        assert!(has_limitation(&rep, "1 counter comparison inconclusive;"));
        let row = metric_by_name(&rep, "counter_bounce_attempts", "");
        assert!(row.scope.contains("all devices"));
        assert!(!row.scope.contains("filter:"));
        let head = metric_by_name(&rep, "bounce_attempts", "");
        assert!(head.scope.contains("filter: testdev0"));
    }

    #[test]
    fn f9_device_needs_span() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        let mut b1 = bounce_event("dev-1", "op-1", 8);
        b1.ts_ns = 1100000000;
        b1.source_measurement = "observed".to_string();
        a.consume(&b1);
        let mut s1 = snapshot_event("swiotlb.bounce_attempts", "dev-2", "p", 3, 0);
        s1.ts_ns = 1050000000;
        s1.source_measurement = "observed".to_string();
        a.consume(&s1);
        let mut s2 = snapshot_event("swiotlb.bounce_attempts", "dev-2", "p", 3, 9);
        s2.ts_ns = 1350000000;
        s2.source_measurement = "observed".to_string();
        a.consume(&s2);
        let rep = a
            .finish(r.session.window_end_ns, false, false, false)
            .expect("finish");
        assert!(!rep.counter_disagreement);
        assert!(has_limitation(&rep, "1 counter comparison inconclusive;"));
    }

    #[test]
    fn f8_corr_baseline_gaps() {
        let rep = analyze("tests/fixtures/reader/f8-correlation-gap", false);
        assert_eq!(rep.q_correlation.status, "partial");
        assert!(!rep.q_correlation.has_loss_count);
        let rep2 = analyze("tests/fixtures/reader/f8-baseline-gap", false);
        assert_eq!(rep2.q_baseline.status, "partial");
        assert!(!rep2.q_baseline.has_loss_count);
    }

    #[test]
    fn detail_unavailable_observed_zero() {
        let rep = analyze("tests/fixtures/reader/unavailable-detail", false);
        assert_eq!(rep.q_detail.status, "unavailable");
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert!(attempts.has_value);
        assert_eq!(attempts.value, 0);
        assert_eq!(attempts.measurement, "observed");
        assert_eq!(attempts.coverage, "unavailable");
        assert_eq!(
            attempts.notes,
            "0 detail events observed; producer status unavailable: zero is unconfirmed."
        );
        let bytes_all = metric_by_name(&rep, "requested_bounce_bytes", "");
        assert!(bytes_all.has_value);
        assert_eq!(bytes_all.value, 0);
        assert_eq!(bytes_all.coverage, "unavailable");
    }

    #[test]
    fn finish_horizon() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        for bad in [999, 4000000001, 2500000000, 1000000000] {
            let mut a = AttemptAnalyzer::new(r.session.clone());
            assert!(a.finish(bad, false, false, false).is_err(), "{bad}");
        }
        let mut ok = AttemptAnalyzer::new(r.session.clone());
        let rep = ok.finish(4000000000, false, false, false).expect("finish");
        assert_eq!(rep.window_end_ns, 4000000000);
    }

    #[test]
    fn snapshot_narrowed_ok() {
        let r = read_capture(&fixture("tests/fixtures/attempts"), false, default_limits())
            .expect("read");
        let mut a = AttemptAnalyzer::new(r.session.clone());
        let snap = a
            .snapshot(2500000000, false, false, false)
            .expect("snapshot");
        assert_eq!(snap.window_end_ns, 2500000000);
    }

    fn channel(status: &str, loss: bool) -> Channel {
        Channel {
            status: status.to_string(),
            has_loss_count: loss,
            loss_count: 0,
            scope: "sc".to_string(),
            reason: "rs".to_string(),
            ..Default::default()
        }
    }

    fn many_device_report(ndevs: usize) -> Report {
        use crate::capture::normalize::device_id_for;
        let s = Session {
            session_id: "many-devices".to_string(),
            synthetic: false,
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "live".to_string(),
            window_start_ns: 0,
            window_end_ns: 1000000000,
            finalized: true,
            q_detail: channel("complete_for_scope", true),
            q_aggregate: channel("complete_for_scope", true),
            q_correlation: channel("not_applicable", false),
            q_baseline: channel("not_applicable", false),
            q_terminal: channel("partial", false),
            ..Default::default()
        };
        let mut a = AttemptAnalyzer::new(s);
        for pair in 0..2 {
            let (counter, unit, total) = if pair == 1 {
                ("swiotlb.requested_bytes", "bytes", ndevs as u64 * 8)
            } else {
                ("swiotlb.bounce_attempts", "count", ndevs as u64)
            };
            for end in 0..2 {
                let (ts, value) = if end == 0 { (0, 0) } else { (999999999, total) };
                a.consume(&Event {
                    kind: "counter_snapshot".to_string(),
                    source_measurement: "observed".to_string(),
                    ts_ns: ts,
                    snapshot: CounterSnapshot {
                        counter_id: counter.to_string(),
                        has_scope_device: false,
                        scope_profile_id: "p".to_string(),
                        epoch: 0,
                        unit: unit.to_string(),
                        value,
                        ..Default::default()
                    },
                    ..Default::default()
                });
            }
        }
        for d in 0..ndevs {
            a.consume(&Event {
                session_id: "many-devices".to_string(),
                seq: d as u64,
                ts_ns: d as u64 + 1,
                kind: "bounce_attempt".to_string(),
                source_hook: "h".to_string(),
                source_backend: "tracepoint".to_string(),
                source_profile_id: "p".to_string(),
                source_measurement: "observed".to_string(),
                source_correlation: "direct".to_string(),
                bounce: BounceAttempt {
                    device_id: device_id_for(d + 1),
                    requested_bytes: 8,
                    forced: false,
                    operation_id: format!("op{d}"),
                },
                ..Default::default()
            });
        }
        a.finish(1000000000, false, false, false).expect("finish")
    }

    #[test]
    fn many_devices_2041_clean() {
        let rep = many_device_report(2041);
        assert!(!has_limitation(&rep, "lack detail rows"));
        let all_m = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(all_m.value, 2041);
        let last = metric_by_name(&rep, "bounce_attempts", "d002041");
        assert_eq!(last.value, 1);
        assert_eq!(
            metric_by_name(&rep, "counter_bounce_attempts", "").value,
            2041
        );
        assert_eq!(
            metric_by_name(&rep, "counter_requested_bounce_bytes", "").value,
            2041 * 8
        );
        assert!(!rep.counter_disagreement);
        assert!(rep.metrics.len() <= 4096);
    }

    #[test]
    fn many_devices_2042_withheld() {
        let rep = many_device_report(2042);
        assert!(has_limitation(&rep, "1 device lacks detail rows"));
        let all_m = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(all_m.value, 2042);
        assert_eq!(
            metric_by_name(&rep, "counter_bounce_attempts", "").value,
            2042
        );
        assert_eq!(
            metric_by_name(&rep, "counter_requested_bounce_bytes", "").value,
            2042 * 8
        );
        assert!(!rep.counter_disagreement);
        assert!(rep.metrics.len() <= 4096);
        assert!(
            !rep.metrics
                .iter()
                .any(|m| m.has_device_id && m.device_id == "d002042")
        );
    }

    fn analyze_with_filter(dir: &str, selector: &str) -> Report {
        let r = read_capture(&fixture(dir), false, default_limits()).expect("read");
        let mut s = r.session.clone();
        s.has_filter_device = true;
        s.filter_device = selector.to_string();
        let mut a = AttemptAnalyzer::new(s);
        let mut r2 = read_capture(&fixture(dir), false, default_limits()).expect("read");
        while r2.has_more().expect("has_more") {
            a.consume(&r2.next_event().expect("next"));
        }
        a.finish(r.session.window_end_ns, r.partial, false, false)
            .expect("finish")
    }

    #[test]
    fn long_filter_scopes_bounded() {
        // A 256-character recorded selector must still render a
        // schema-valid report: every metric scope stays within 256
        // characters, elided scopes say so, and the exact literal
        // survives in the report limitations.
        let literal = format!("longsel-{}", "z".repeat(248));
        assert_eq!(literal.chars().count(), 256);
        let rep = analyze("tests/fixtures/reader/selection-long", false);
        for m in &rep.metrics {
            assert!(m.scope.chars().count() <= 256, "{}", m.scope);
            assert!(!m.scope.contains(&literal));
        }
        let head = metric_by_name(&rep, "bounce_attempts", "");
        assert!(head.scope.contains("recorded devices (filtered)"));
        assert!(has_limitation(&rep, &literal));
    }

    #[test]
    fn filter_scope_exact_fit_boundary() {
        // Window [1000000000,4000000000) labels 30 characters, so
        // the fixed frame around the selector fits a 181-character
        // selector at exactly 256 characters and elides at 182.
        let fitting = "q".repeat(181);
        let fit = analyze_with_filter("tests/fixtures/reader/selection-unmatched", &fitting);
        let head = metric_by_name(&fit, "bounce_attempts", "");
        assert_eq!(head.scope.chars().count(), 256);
        assert!(head.scope.contains(&fitting));
        assert!(!has_limitation(&fit, "elided"));
        let past = "q".repeat(182);
        let over = analyze_with_filter("tests/fixtures/reader/selection-unmatched", &past);
        let ohead = metric_by_name(&over, "bounce_attempts", "");
        assert!(ohead.scope.chars().count() <= 256);
        assert!(ohead.scope.contains("recorded devices (filtered)"));
        assert!(has_limitation(&over, &past));
    }

    #[test]
    fn filter_scope_counts_codepoints() {
        // Scope fit is measured in characters, not bytes: 181
        // two-byte codepoints still name the selector verbatim at
        // exactly 256 characters, while 182 elide with the exact
        // literal preserved in the limitations.
        let fitting = "é".repeat(181);
        assert_eq!(fitting.chars().count(), 181);
        let fit = analyze_with_filter("tests/fixtures/reader/selection-unmatched", &fitting);
        let head = metric_by_name(&fit, "bounce_attempts", "");
        assert_eq!(head.scope.chars().count(), 256);
        assert!(head.scope.contains(&fitting));
        let past = "é".repeat(182);
        let over = analyze_with_filter("tests/fixtures/reader/selection-unmatched", &past);
        let ohead = metric_by_name(&over, "bounce_attempts", "");
        assert!(ohead.scope.chars().count() <= 256);
        assert!(ohead.scope.contains("recorded devices (filtered)"));
        assert!(has_limitation(&over, &past));
    }

    fn lower_bound_session() -> Session {
        // Live session whose producer claims a pre-6.7 lower bound.
        Session {
            session_id: "lower-bound".to_string(),
            synthetic: false,
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "live".to_string(),
            window_start_ns: 0,
            window_end_ns: 1000000000,
            finalized: true,
            q_detail: Channel {
                status: "partial".to_string(),
                has_loss_count: true,
                loss_count: 0,
                scope: "sc".to_string(),
                reason: "Detail loss 0 (submit_fail=(0) malformed=(0) dropped=(0) recursion_missed=(0) size_omitted=(0) duration_omitted=(0) signal_omitted=(0) rejected=(0) write_failed=(0)); attempt loss counts are a lower bound before 6.7"
                    .to_string(),
                ..Default::default()
            },
            q_aggregate: Channel {
                status: "partial".to_string(),
                has_loss_count: true,
                loss_count: 0,
                scope: "counter snapshots attached [1,2)".to_string(),
                reason: "counter snapshots present (valid cut, identity holds, coverage valid); attempt loss counts are a lower bound before 6.7"
                    .to_string(),
                ..Default::default()
            },
            q_correlation: channel("not_applicable", false),
            q_baseline: channel("not_applicable", false),
            q_terminal: channel("partial", false),
            ..Default::default()
        }
    }

    #[test]
    fn lower_bound_drops_confidence_and_labels_loss() {
        // A pre-6.7 lower-bound producer caps the report at
        // partial with the label in both channels, and attempt
        // metrics drop below high confidence.
        let mut a = AttemptAnalyzer::new(lower_bound_session());
        let rep = a.finish(1000000000, false, false, false).expect("finish");
        assert_eq!(rep.q_detail.status, "partial");
        assert!(rep.q_detail.reason.contains("lower bound"));
        assert!(!rep.q_detail.reason.contains("No detail loss observed."));
        assert_eq!(rep.q_aggregate.status, "partial");
        assert!(rep.q_aggregate.reason.contains("lower bound"));
        assert_eq!(
            metric_by_name(&rep, "bounce_attempts", "").confidence,
            "medium"
        );
        assert_eq!(
            metric_by_name(&rep, "requested_bounce_bytes", "").confidence,
            "medium"
        );
        // Control: without the label the same shape stays high.
        let mut plain = lower_bound_session();
        plain.q_detail.reason = "Detail loss 0".to_string();
        plain.q_aggregate.reason = "counter snapshots present".to_string();
        let mut b = AttemptAnalyzer::new(plain);
        let rep2 = b.finish(1000000000, false, false, false).expect("finish");
        assert_eq!(
            metric_by_name(&rep2, "bounce_attempts", "").confidence,
            "high"
        );
    }

    #[test]
    fn counters_survive_detail_loss() {
        let rep = analyze("tests/fixtures/reader/quality-detail-counters", false);
        assert_eq!(rep.q_detail.status, "partial");
        assert!(rep.q_detail.has_loss_count);
        assert_eq!(rep.q_detail.loss_count, 2);
        let detail = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(detail.value, 2);
        assert_eq!(detail.coverage, "partial");
        let agg = metric_by_name(&rep, "counter_bounce_attempts", "");
        assert!(agg.has_value);
        assert_eq!(agg.value, 3);
        assert_eq!(agg.measurement, "derived");
        assert_eq!(rep.q_aggregate.status, "complete_for_scope");
    }

    #[test]
    fn detail_survives_counter_reset() {
        let rep = analyze("tests/fixtures/reader/quality-reset-detail-ok", false);
        assert_eq!(rep.q_detail.status, "complete_for_scope");
        let detail = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(detail.value, 2);
        assert_eq!(detail.coverage, "complete_for_scope");
        assert_eq!(rep.q_aggregate.status, "partial");
        assert!(
            !rep.metrics
                .iter()
                .any(|m| m.name == "counter_bounce_attempts")
        );
    }

    #[test]
    fn unknown_loss_stays_null_with_reason() {
        let rep = analyze("tests/fixtures/reader/detail-gap-unknown", false);
        assert_eq!(rep.q_detail.status, "partial");
        assert!(!rep.q_detail.has_loss_count);
        let attempts = metric_by_name(&rep, "bounce_attempts", "");
        assert_eq!(attempts.value, 1);
        assert_eq!(attempts.coverage, "partial");
        assert_eq!(
            rep.limitations.last().unwrap(),
            "Detail loss: 1 gap event (unknown lost); attempt counts are lower bounds."
        );
    }
}
