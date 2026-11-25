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
//! Captures admitted under different semantic profiles
//! refuse on every metric; profile equality is a check,
//! not a caller precondition. Malformed captures refuse
//! the whole comparison with [`InputRefusal`] before any
//! row runs, so there is never a repaired or guessed row.

use std::collections::BTreeMap;

/// One observed metric inside a persisted capture.
///
/// `value` is `None` exactly when the metric is unknown; then
/// `value_reason` names why with a non-blank reason free of
/// control characters. Unknown is never zero, and a blank
/// reason explains nothing.
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
        Self::level("complete", "complete")
    }

    /// Quality for a compatible row with a null delta: no
    /// channel claims completeness for unknown data.
    fn unknown() -> Self {
        Self::level("unknown", "unknown")
    }

    /// Quality for a refused row: the comparison never ran.
    fn refused() -> Self {
        Self::level("refused", "refused")
    }

    /// Quality for a row whose metric is missing on one
    /// side: identity is unknown, the rest refused.
    fn unavailable() -> Self {
        Self::level("refused", "unknown")
    }

    fn level(other: &str, identity: &str) -> Self {
        Self {
            detail: other.to_string(),
            aggregate: other.to_string(),
            identity: identity.to_string(),
            baseline: other.to_string(),
            terminal: other.to_string(),
        }
    }
}

/// Whole-input refusal: the captures cannot be compared
/// at all, so no rows are produced. Callers map this to a
/// rejected-input exit with no repaired or guessed result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputRefusal {
    pub reason: String,
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
    let quality = if compatibility == "unavailable" {
        Quality::unavailable()
    } else {
        Quality::refused()
    };
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
        quality,
    }
}

fn find_metric<'m>(capture: &'m Capture, id: &str) -> Option<&'m Metric> {
    capture.metrics.iter().find(|m| m.metric_id == id)
}

/// Compare every metric unioned from both captures.
///
/// Both captures validate first: the left capture, then the
/// right, each for a repeated metric id, a backward window,
/// value/reason pairing, source meaning content, then clock
/// content. Blank means empty or ASCII-whitespace-only, and
/// a control character means U+0000-U+001F or U+007F-U+009F;
/// both definitions are shared verbatim with the Python
/// oracle. A blank string counts as missing where its content
/// is interpreted, so a blank reason refuses as
/// `invalid-value` while a blank source meaning or clock
/// refuses its row as unknown. A unit outside the frozen
/// vocabulary (`bytes`, `unknown`) — a blank unit
/// included — likewise refuses its row as `unit-unknown`
/// with no delta. A non-blank string with a control
/// character is malformed input: meanings refuse as
/// `invalid-meaning`, clocks as `invalid-clock`, reasons as
/// `invalid-value`. An invalid input refuses the whole
/// comparison with [`InputRefusal`] and no rows.
///
/// Row order is stable: left-capture order first, then metrics
/// seen only on the right. The first failing compatibility
/// check names the reason, in this order: metric presence,
/// unit availability, unit, scope, legacy input, epoch,
/// device binding, profile, workload, per-side source,
/// source meaning availability, source meaning, clock
/// availability, clock domain, window, census completeness,
/// then value availability for the delta itself.
pub fn compare_captures(left: &Capture, right: &Capture) -> Result<Vec<Comparison>, InputRefusal> {
    validate_capture(left)?;
    validate_capture(right)?;
    let mut ids: Vec<&str> = Vec::new();
    for metric in left.metrics.iter().chain(right.metrics.iter()) {
        if !ids.contains(&metric.metric_id.as_str()) {
            ids.push(metric.metric_id.as_str());
        }
    }
    Ok(ids
        .into_iter()
        .map(|id| compare_metric(left, right, id))
        .collect())
}

fn refuse_input(reason: &str) -> InputRefusal {
    InputRefusal {
        reason: reason.to_string(),
    }
}

/// A meaning-carrying string counts as missing when it is
/// empty or every character is ASCII whitespace: space, tab,
/// line feed, carriage return, vertical tab or form feed.
/// This definition is shared verbatim with the Python oracle
/// so both sides always agree.
fn is_blank(value: &str) -> bool {
    value.is_empty()
        || value
            .chars()
            .all(|c| matches!(c, ' ' | '\t' | '\n' | '\r' | '\x0b' | '\x0c'))
}

/// A string carries a control character when any codepoint is
/// U+0000-U+001F or U+007F-U+009F. This definition is shared
/// verbatim with the Python oracle. ASCII whitespace overlaps
/// this range, so callers check blankness first: a blank
/// string is missing, never malformed.
fn has_control(value: &str) -> bool {
    value
        .chars()
        .any(|c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}'))
}

/// Frozen unit vocabulary from the exposure catalog:
/// only these labels compare; anything else (a blank
/// label included) records no unit.
const KNOWN_UNITS: [&str; 2] = ["bytes", "unknown"];

fn is_known_unit(unit: &str) -> bool {
    KNOWN_UNITS.contains(&unit)
}

fn validate_capture(capture: &Capture) -> Result<(), InputRefusal> {
    let mut seen: Vec<&str> = Vec::new();
    for metric in capture.metrics.iter() {
        if seen.contains(&metric.metric_id.as_str()) {
            return Err(refuse_input("duplicate-metric"));
        }
        seen.push(metric.metric_id.as_str());
    }
    if capture.window_start > capture.window_end {
        return Err(refuse_input("invalid-window"));
    }
    for metric in capture.metrics.iter() {
        match (metric.value, metric.value_reason.as_deref()) {
            (Some(_), None) => {}
            (None, Some(reason)) if !is_blank(reason) && !has_control(reason) => {}
            _ => return Err(refuse_input("invalid-value")),
        }
    }
    for meaning in capture.source_meanings.values() {
        if !is_blank(meaning) && has_control(meaning) {
            return Err(refuse_input("invalid-meaning"));
        }
    }
    if !is_blank(&capture.clock_domain) && has_control(&capture.clock_domain) {
        return Err(refuse_input("invalid-clock"));
    }
    Ok(())
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
    if !is_known_unit(&left_metric.unit) || !is_known_unit(&right_metric.unit) {
        return refused(
            metric_id,
            "incompatible",
            "unit-unknown",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
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
    if left.profile_id != right.profile_id {
        return refused(
            metric_id,
            "incompatible",
            "profile-mismatch",
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
    if left_metric.source_id != right_metric.source_id {
        return refused(
            metric_id,
            "incompatible",
            "source-mismatch",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    let left_meaning = left
        .source_meanings
        .get(&left_metric.source_id)
        .map(String::as_str);
    let right_meaning = right
        .source_meanings
        .get(&right_metric.source_id)
        .map(String::as_str);
    if left_meaning.is_none_or(is_blank) || right_meaning.is_none_or(is_blank) {
        return refused(
            metric_id,
            "incompatible",
            "source-meaning-unknown",
            left,
            right,
            &left_metric.unit,
            &left_metric.scope,
        );
    }
    if left_meaning != right_meaning {
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
    if is_blank(&left.clock_domain) || is_blank(&right.clock_domain) {
        return refused(
            metric_id,
            "incompatible",
            "clock-unknown",
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
    if (left_metric.census_derived || right_metric.census_derived)
        && (left.census_bounded || right.census_bounded)
    {
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
            quality: Quality::unknown(),
        };
    };
    let wide = (right_value as i128) - (left_value as i128);
    let delta = i64::try_from(wide).ok();
    let quality = if delta.is_some() {
        Quality::complete()
    } else {
        Quality::unknown()
    };
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
        quality,
    }
}
