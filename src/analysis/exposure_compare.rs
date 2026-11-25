// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure comparison over two persisted captures.
//!
//! [`compare_captures`] checks one per-metric compatibility
//! predicate and only then computes an exact unit-safe delta.
//! Incompatible metrics carry a typed reason and no numeric
//! delta; compatible metrics with an unknown or overflowing
//! value stay compatible with a null delta plus a reason.
//! Comparable unaffected metrics keep their own rows, so one
//! refused metric never hides the rest.
//!
//! The input carries no journal channel by construction: the
//! comparator only sees finalized metric values, so incomplete
//! journal events can never be netted into baseline state.
//! Callers only compare captures admitted under one semantic
//! profile; profile equality is a precondition, not a check.

use std::collections::BTreeMap;

/// One observed metric inside a persisted capture.
///
/// `value` is `None` exactly when the metric is unknown; then
/// `value_reason` names why. Unknown is never zero.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    pub metric_id: String,
    pub value: Option<u64>,
    pub value_reason: Option<String>,
    pub unit: String,
    pub scope: String,
    pub source_id: String,
    pub census_derived: bool,
}

/// One side of a comparison: persisted capture identity plus
/// the metric values to compare.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub evidence_id: String,
    pub profile_id: String,
    pub workload: String,
    pub epoch: u64,
    pub platform_cell: String,
    pub source_meanings: BTreeMap<String, String>,
    pub window_start: u64,
    pub window_end: u64,
    pub clock_domain: String,
    pub census_bounded: bool,
    pub legacy: bool,
    pub metrics: Vec<Metric>,
}

/// Per-comparison quality across the five channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quality {
    pub detail: String,
    pub aggregate: String,
    pub identity: String,
    pub baseline: String,
    pub terminal: String,
}

impl Quality {
    /// Quality for a fully determined comparison row.
    pub fn complete() -> Self {
        Self {
            detail: "complete".to_string(),
            aggregate: "complete".to_string(),
            identity: "complete".to_string(),
            baseline: "complete".to_string(),
            terminal: "complete".to_string(),
        }
    }
}

/// One compared metric: compatibility verdict plus, only for
/// compatible metrics, an exact delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub metric_id: String,
    pub compatibility: String,
    pub reason: String,
    pub left_evidence: String,
    pub right_evidence: String,
    pub delta: Option<i64>,
    pub delta_reason: Option<String>,
    pub unit: String,
    pub scope: String,
    pub quality: Quality,
}

fn refused(
    metric_id: &str,
    compatibility: &str,
    reason: &str,
    left: &Capture,
    right: &Capture,
    unit: &str,
    scope: &str,
) -> Comparison {
    Comparison {
        metric_id: metric_id.to_string(),
        compatibility: compatibility.to_string(),
        reason: reason.to_string(),
        left_evidence: left.evidence_id.clone(),
        right_evidence: right.evidence_id.clone(),
        delta: None,
        delta_reason: None,
        unit: unit.to_string(),
        scope: scope.to_string(),
        quality: Quality::complete(),
    }
}

fn find_metric<'m>(capture: &'m Capture, id: &str) -> Option<&'m Metric> {
    capture.metrics.iter().find(|m| m.metric_id == id)
}

/// Compare every metric unioned from both captures.
///
/// Row order is stable: left-capture order first, then metrics
/// seen only on the right. The first failing compatibility
/// check names the reason, in this order: metric presence,
/// unit, scope, legacy input, epoch, device binding, workload,
/// source meaning, clock domain, window, census completeness,
/// then value availability for the delta itself.
pub fn compare_captures(left: &Capture, right: &Capture) -> Vec<Comparison> {
    let mut ids: Vec<&str> = Vec::new();
    for metric in left.metrics.iter().chain(right.metrics.iter()) {
        if !ids.contains(&metric.metric_id.as_str()) {
            ids.push(metric.metric_id.as_str());
        }
    }
    ids.into_iter()
        .map(|id| compare_metric(left, right, id))
        .collect()
}

fn compare_metric(left: &Capture, right: &Capture, metric_id: &str) -> Comparison {
    let left_metric = find_metric(left, metric_id);
    let right_metric = find_metric(right, metric_id);
    let (Some(left_metric), Some(right_metric)) = (left_metric, right_metric) else {
        let shape = left_metric.or(right_metric).expect("union member");
        return refused(
            metric_id,
            "unavailable",
            "metric-missing",
            left,
            right,
            &shape.unit,
            &shape.scope,
        );
    };
    if left_metric.unit != right_metric.unit {
        return refused(
            metric_id,
            "incompatible",
            "unit-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left_metric.scope != right_metric.scope {
        return refused(
            metric_id,
            "incompatible",
            "scope-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.legacy || right.legacy {
        return refused(
            metric_id,
            "incompatible",
            "legacy-input",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.epoch != right.epoch {
        return refused(
            metric_id,
            "incompatible",
            "epoch-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.platform_cell != right.platform_cell {
        return refused(
            metric_id,
            "incompatible",
            "device-binding-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.workload != right.workload {
        return refused(
            metric_id,
            "incompatible",
            "workload-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    let meaning = left.source_meanings.get(&left_metric.source_id);
    if meaning != right.source_meanings.get(&left_metric.source_id) {
        return refused(
            metric_id,
            "incompatible",
            "source-meaning-change",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.clock_domain != right.clock_domain {
        return refused(
            metric_id,
            "incompatible",
            "clock-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left.window_start != right.window_start || left.window_end != right.window_end {
        return refused(
            metric_id,
            "incompatible",
            "window-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left_metric.census_derived && (left.census_bounded || right.census_bounded) {
        return refused(
            metric_id,
            "incompatible",
            "partial-census",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    let (Some(left_value), Some(right_value)) = (left_metric.value, right_metric.value) else {
        return Comparison {
            metric_id: metric_id.to_string(),
            compatibility: "compatible".to_string(),
            reason: "compatible".to_string(),
            left_evidence: left.evidence_id.clone(),
            right_evidence: right.evidence_id.clone(),
            delta: None,
            delta_reason: Some("value-unknown".to_string()),
            unit: left_metric.unit.clone(),
            scope: left_metric.scope.clone(),
            quality: Quality::complete(),
        };
    };
    let wide = (right_value as i128) - (left_value as i128);
    let delta = i64::try_from(wide).ok();
    Comparison {
        metric_id: metric_id.to_string(),
        compatibility: "compatible".to_string(),
        reason: "compatible".to_string(),
        left_evidence: left.evidence_id.clone(),
        right_evidence: right.evidence_id.clone(),
        delta,
        delta_reason: if delta.is_some() {
            None
        } else {
            Some("delta-overflow".to_string())
        },
        unit: left_metric.unit.clone(),
        scope: left_metric.scope.clone(),
        quality: Quality::complete(),
    }
}
