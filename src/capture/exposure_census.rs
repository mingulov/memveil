// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-view census snapshots and their comparison.
//!
//! A census snapshot freezes one interval of guest-view
//! counting: a scope label, an observed window with time
//! bounds, the covered sources, the atomicity the sweep
//! ran under, the journal scope it belongs to, and the
//! per-class counts. Two snapshots compare only when
//! every compatibility check below admits the pair; the
//! first failing check names the reason, in this order:
//! "class-missing", "unit-unknown", "unit-mismatch",
//! "scope-unknown", "scope-mismatch", "profile-unknown",
//! "profile-mismatch", "workload-unknown",
//! "workload-mismatch", "epoch-mismatch",
//! "device-binding-unknown", "device-binding-mismatch",
//! "coverage-unknown", "coverage-mismatch",
//! "atomicity-unknown", "atomicity-mismatch",
//! "clock-unknown", "clock-mismatch", "window-mismatch",
//! "journal-scope-mismatch", "partial-journal".
//! A refused class carries no delta and no uncertainty.
//!
//! Compatible counts yield an exact delta with a stated
//! uncertainty: the saturating sum of both sides' race
//! bounds, zero when neither side raced. Unknown or
//! overflowing values stay compatible with a null delta
//! plus a reason. A partial journal refuses every class:
//! journal detail is never netted into snapshot state.
//!
//! The module is self-contained on purpose: it declares no
//! parent items, so it compiles both under its public module
//! path and through a direct path include in tests. It takes
//! no live input and performs no I/O. Snapshots record
//! guest-view counts only; every count is an observed
//! count total with a unit, never an interpreted verdict.

/// One observed class inside a census snapshot.
///
/// `value` is `None` exactly when the count is unknown; then
/// `value_reason` names why with a non-blank reason free of
/// control characters. Unknown is never zero, and a blank
/// reason explains nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusCount {
    pub class_id: String,
    pub unit: String,
    pub value: Option<u64>,
    pub value_reason: Option<String>,
}

/// How one snapshot sweep observed its counts.
///
/// `mode` names the frozen vocabulary (`atomic` for a single
/// atomic read, `interval` for a sweep over the window,
/// `unknown` when the sweep cannot say). `uncertainty_bound`
/// is `Some` exactly when `races_observed` is true: the
/// stated bound on what the races could have moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Atomicity {
    pub mode: String,
    pub races_observed: bool,
    pub uncertainty_bound: Option<u64>,
}

/// The journal scope one snapshot belongs to.
///
/// Only complete journals compare: a partial journal refuses
/// every class rather than netting unfinished detail into
/// snapshot state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalScope {
    pub scope_id: String,
    pub complete: bool,
}

/// The observed interval with its time bounds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Window {
    pub clock_domain: String,
    pub start: u64,
    pub end: u64,
}

/// One frozen census snapshot: guest-view scope, time
/// bounds, coverage, atomicity, journal scope, counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusSnapshot {
    pub evidence_id: String,
    pub profile_id: String,
    pub workload: String,
    pub epoch: u64,
    pub platform_cell: String,
    pub scope: String,
    pub window: Window,
    pub coverage: Vec<String>,
    pub atomicity: Atomicity,
    pub journal: JournalScope,
    pub counts: Vec<CensusCount>,
}

/// Per-row quality across the five channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quality {
    pub detail: String,
    pub aggregate: String,
    pub identity: String,
    pub baseline: String,
    pub terminal: String,
}

impl Quality {
    /// Quality for a fully determined row.
    pub fn complete() -> Self {
        Self::level("complete", "complete")
    }

    /// Quality for a compatible row with a null delta: no
    /// channel claims completeness for unknown data.
    pub fn unknown() -> Self {
        Self::level("unknown", "unknown")
    }

    /// Quality for a refused row: the comparison never ran.
    pub fn refused() -> Self {
        Self::level("refused", "refused")
    }

    /// Quality for a row whose class is missing on one
    /// side: identity is unknown, the rest refused.
    pub fn unavailable() -> Self {
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

/// Whole-input refusal: the snapshots cannot be compared
/// at all, so no rows are produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRefusal {
    pub reason: String,
}

/// One compared class: compatibility verdict plus, only for
/// compatible classes, an exact delta and stated uncertainty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CensusDelta {
    pub class_id: String,
    pub compatibility: String,
    pub reason: String,
    pub left_evidence: String,
    pub right_evidence: String,
    pub delta: Option<i64>,
    pub delta_reason: Option<String>,
    pub uncertainty: Option<u64>,
    pub unit: String,
    pub scope: String,
    pub quality: Quality,
}

/// One start/stop marker closing a snapshot window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub session_id: String,
    pub epoch: u64,
    pub ts: u64,
}

/// Collection prerequisites for the census probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRequirements {
    pub privileged: bool,
    pub symbols_resolved: bool,
    pub semantics_admitted: bool,
    pub bounds_sufficient: bool,
}

/// Collection refusal: the probe must not run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectionRefusal {
    pub reason: String,
}

fn refused(
    class_id: &str,
    compatibility: &str,
    reason: &str,
    left: &CensusSnapshot,
    right: &CensusSnapshot,
    unit: &str,
) -> CensusDelta {
    let quality = if compatibility == "unavailable" {
        Quality::unavailable()
    } else {
        Quality::refused()
    };
    CensusDelta {
        class_id: class_id.to_string(),
        compatibility: compatibility.to_string(),
        reason: reason.to_string(),
        left_evidence: left.evidence_id.clone(),
        right_evidence: right.evidence_id.clone(),
        delta: None,
        delta_reason: None,
        uncertainty: None,
        unit: unit.to_string(),
        scope: left.scope.clone(),
        quality,
    }
}

fn find_count<'m>(snapshot: &'m CensusSnapshot, id: &str) -> Option<&'m CensusCount> {
    snapshot.counts.iter().find(|c| c.class_id == id)
}

/// Compare every class unioned from both snapshots.
///
/// Both snapshots validate first: the left snapshot, then the
/// right, each for a repeated class id, a backward window,
/// count pairing, coverage content, journal content, atomicity
/// pairing, then scope and clock content. Blank means empty or
/// ASCII-whitespace-only, and a control character means
/// U+0000-U+001F or U+007F-U+009F; both definitions are shared
/// verbatim with the Python oracle. A blank string counts as
/// missing where its content is interpreted, so a blank scope
/// refuses its row as unknown while a non-blank scope with a
/// control character refuses the whole input. A unit outside
/// the frozen vocabulary (`bytes`, `unknown`) — a blank unit
/// included — refuses its row as `unit-unknown` with no delta
/// and records the result unit as `unknown`. A one-sided class
/// keeps reason `class-missing` but records `unknown` when its
/// present-side unit falls outside the vocabulary. An invalid
/// input refuses the whole comparison with [`SnapshotRefusal`]
/// and no rows.
///
/// Row order is stable: left-snapshot order first, then classes
/// seen only on the right. The first failing compatibility
/// check names the reason, in this order: class presence, unit
/// availability, unit, scope availability, scope, profile
/// availability, profile, workload availability, workload,
/// epoch, device-binding availability, device binding,
/// coverage availability, coverage, atomicity
/// availability, atomicity, clock availability, clock domain,
/// window, journal scope, journal completeness, then value
/// availability for the delta itself. Two unknowns never
/// compare equal: a blank binding or an empty coverage on
/// either side refuses, the same rule the scope check
/// already applies.
pub fn compare_snapshots(
    left: &CensusSnapshot,
    right: &CensusSnapshot,
) -> Result<Vec<CensusDelta>, SnapshotRefusal> {
    validate_snapshot(left)?;
    validate_snapshot(right)?;
    let mut ids: Vec<&str> = Vec::new();
    for count in left.counts.iter().chain(right.counts.iter()) {
        if !ids.contains(&count.class_id.as_str()) {
            ids.push(count.class_id.as_str());
        }
    }
    Ok(ids
        .into_iter()
        .map(|id| compare_class(left, right, id))
        .collect())
}

fn refuse_input(reason: &str) -> SnapshotRefusal {
    SnapshotRefusal {
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

/// Frozen census unit vocabulary from the exposure
/// catalog (`units: ["bytes", "unknown"]`): only these
/// labels compare; anything else refuses as unknown.
/// Count metrics use `unknown`: no admitted source
/// freezes an event-count unit, and only a catalog
/// revision may add one.
const KNOWN_UNITS: [&str; 2] = ["bytes", "unknown"];

fn is_known_unit(unit: &str) -> bool {
    KNOWN_UNITS.contains(&unit)
}

/// Frozen atomicity modes: a single atomic read, a sweep
/// over the window, or unknown. Unknown never compares.
const ATOMICITY_MODES: [&str; 3] = ["atomic", "interval", "unknown"];

fn validate_snapshot(snapshot: &CensusSnapshot) -> Result<(), SnapshotRefusal> {
    let mut seen: Vec<&str> = Vec::new();
    for count in snapshot.counts.iter() {
        if seen.contains(&count.class_id.as_str()) {
            return Err(refuse_input("duplicate-class"));
        }
        seen.push(count.class_id.as_str());
    }
    if snapshot.window.start > snapshot.window.end {
        return Err(refuse_input("invalid-window"));
    }
    for count in snapshot.counts.iter() {
        if is_blank(&count.class_id) || has_control(&count.class_id) {
            return Err(refuse_input("invalid-count"));
        }
        match (count.value, count.value_reason.as_deref()) {
            (Some(_), None) => {}
            (None, Some(reason)) if !is_blank(reason) && !has_control(reason) => {}
            _ => return Err(refuse_input("invalid-count")),
        }
    }
    let mut seen_coverage: Vec<&str> = Vec::new();
    for source in snapshot.coverage.iter() {
        if is_blank(source) || has_control(source) || seen_coverage.contains(&source.as_str()) {
            return Err(refuse_input("invalid-coverage"));
        }
        seen_coverage.push(source.as_str());
    }
    if is_blank(&snapshot.journal.scope_id) || has_control(&snapshot.journal.scope_id) {
        return Err(refuse_input("invalid-journal"));
    }
    if !ATOMICITY_MODES.contains(&snapshot.atomicity.mode.as_str())
        || snapshot.atomicity.races_observed != snapshot.atomicity.uncertainty_bound.is_some()
    {
        return Err(refuse_input("invalid-atomicity"));
    }
    if !is_blank(&snapshot.scope) && has_control(&snapshot.scope) {
        return Err(refuse_input("invalid-scope"));
    }
    if !is_blank(&snapshot.window.clock_domain) && has_control(&snapshot.window.clock_domain) {
        return Err(refuse_input("invalid-clock"));
    }
    Ok(())
}

fn coverage_matches(left: &CensusSnapshot, right: &CensusSnapshot) -> bool {
    let mut left_sources: Vec<&str> = left.coverage.iter().map(String::as_str).collect();
    let mut right_sources: Vec<&str> = right.coverage.iter().map(String::as_str).collect();
    left_sources.sort_unstable();
    right_sources.sort_unstable();
    left_sources == right_sources
}

fn race_bound(snapshot: &CensusSnapshot) -> u64 {
    if snapshot.atomicity.races_observed {
        snapshot.atomicity.uncertainty_bound.unwrap_or(0)
    } else {
        0
    }
}

fn stated_uncertainty(left: &CensusSnapshot, right: &CensusSnapshot) -> u64 {
    race_bound(left).saturating_add(race_bound(right))
}

fn result_unit(left_count: Option<&CensusCount>, right_count: Option<&CensusCount>) -> String {
    match (left_count, right_count) {
        (Some(present), _) | (None, Some(present)) if !is_known_unit(&present.unit) => {
            "unknown".to_string()
        }
        (Some(present), _) | (None, Some(present)) => present.unit.clone(),
        (None, None) => "unknown".to_string(),
    }
}

fn compare_class(left: &CensusSnapshot, right: &CensusSnapshot, id: &str) -> CensusDelta {
    let left_count = find_count(left, id);
    let right_count = find_count(right, id);
    let Some(left_count) = left_count else {
        let unit = result_unit(None, right_count);
        return refused(id, "unavailable", "class-missing", left, right, &unit);
    };
    let Some(right_count) = right_count else {
        let unit = result_unit(Some(left_count), None);
        return refused(id, "unavailable", "class-missing", left, right, &unit);
    };
    if !is_known_unit(&left_count.unit) || !is_known_unit(&right_count.unit) {
        return refused(id, "incompatible", "unit-unknown", left, right, "unknown");
    }
    if left_count.unit != right_count.unit {
        return refused(
            id,
            "incompatible",
            "unit-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if is_blank(&left.scope) || is_blank(&right.scope) {
        return refused(
            id,
            "incompatible",
            "scope-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.scope != right.scope {
        return refused(
            id,
            "incompatible",
            "scope-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if is_blank(&left.profile_id) || is_blank(&right.profile_id) {
        return refused(
            id,
            "incompatible",
            "profile-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.profile_id != right.profile_id {
        return refused(
            id,
            "incompatible",
            "profile-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if is_blank(&left.workload) || is_blank(&right.workload) {
        return refused(
            id,
            "incompatible",
            "workload-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.workload != right.workload {
        return refused(
            id,
            "incompatible",
            "workload-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.epoch != right.epoch {
        return refused(
            id,
            "incompatible",
            "epoch-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if is_blank(&left.platform_cell) || is_blank(&right.platform_cell) {
        return refused(
            id,
            "incompatible",
            "device-binding-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.platform_cell != right.platform_cell {
        return refused(
            id,
            "incompatible",
            "device-binding-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.coverage.is_empty() || right.coverage.is_empty() {
        return refused(
            id,
            "incompatible",
            "coverage-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if !coverage_matches(left, right) {
        return refused(
            id,
            "incompatible",
            "coverage-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.atomicity.mode == "unknown" || right.atomicity.mode == "unknown" {
        return refused(
            id,
            "incompatible",
            "atomicity-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.atomicity.mode != right.atomicity.mode {
        return refused(
            id,
            "incompatible",
            "atomicity-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if is_blank(&left.window.clock_domain) || is_blank(&right.window.clock_domain) {
        return refused(
            id,
            "incompatible",
            "clock-unknown",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.window.clock_domain != right.window.clock_domain {
        return refused(
            id,
            "incompatible",
            "clock-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.window.start != right.window.start || left.window.end != right.window.end {
        return refused(
            id,
            "incompatible",
            "window-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if left.journal.scope_id != right.journal.scope_id {
        return refused(
            id,
            "incompatible",
            "journal-scope-mismatch",
            left,
            right,
            &left_count.unit,
        );
    }
    if !left.journal.complete || !right.journal.complete {
        return refused(
            id,
            "incompatible",
            "partial-journal",
            left,
            right,
            &left_count.unit,
        );
    }
    let (delta, delta_reason, quality) = match (left_count.value, right_count.value) {
        (Some(before), Some(after)) => {
            let wide = (after as i128) - (before as i128);
            match i64::try_from(wide).ok() {
                Some(exact) => (Some(exact), None, Quality::complete()),
                None => (None, Some("delta-overflow".to_string()), Quality::unknown()),
            }
        }
        (None, _) | (_, None) => (None, Some("value-unknown".to_string()), Quality::unknown()),
    };
    CensusDelta {
        class_id: id.to_string(),
        compatibility: "compatible".to_string(),
        reason: "compatible".to_string(),
        left_evidence: left.evidence_id.clone(),
        right_evidence: right.evidence_id.clone(),
        delta,
        delta_reason,
        uncertainty: Some(stated_uncertainty(left, right)),
        unit: left_count.unit.clone(),
        scope: left.scope.clone(),
        quality,
    }
}

/// Close a snapshot window from its start and stop markers.
///
/// Both markers must name the same session and epoch, and the
/// stop must not precede the start; anything else refuses
/// with a typed reason instead of inventing a window.
pub fn observe_window(
    start: &Observation,
    stop: &Observation,
) -> Result<(u64, u64), SnapshotRefusal> {
    if start.session_id != stop.session_id {
        return Err(refuse_input("session-mismatch"));
    }
    if start.epoch != stop.epoch {
        return Err(refuse_input("epoch-mismatch"));
    }
    if stop.ts < start.ts {
        return Err(refuse_input("backward-observation"));
    }
    Ok((start.ts, stop.ts))
}

/// Admit census collection only when every prerequisite
/// holds: privileges, resolved symbols, admitted semantics,
/// and sufficient bounds. The first missing prerequisite
/// names the refusal; collection never runs degraded.
pub fn check_collection_readiness(req: &CollectionRequirements) -> Result<(), CollectionRefusal> {
    if !req.privileged {
        return Err(CollectionRefusal {
            reason: "privilege-refused".to_string(),
        });
    }
    if !req.symbols_resolved {
        return Err(CollectionRefusal {
            reason: "symbols-unresolved".to_string(),
        });
    }
    if !req.semantics_admitted {
        return Err(CollectionRefusal {
            reason: "semantics-unadmitted".to_string(),
        });
    }
    if !req.bounds_sufficient {
        return Err(CollectionRefusal {
            reason: "bounds-insufficient".to_string(),
        });
    }
    Ok(())
}
