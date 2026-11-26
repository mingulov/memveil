// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI capability selection and compare-verb exits.
//!
//! This module resolves a requested capability list to a
//! selection with its attempt-hook dependency, maps a run
//! outcome to the frozen exit table, and sketches the
//! compare verb as exit precedence over per-metric verdict
//! rows the comparator lane emits. Capability ids, the
//! composition rules, and the exits follow the frozen
//! exposure catalog (`profiles/exposure/catalog.json`);
//! unknown names and empty items refuse, planned channels
//! refuse as unknown until their collection adapter ships,
//! and journal channels parse but refuse as channel-less.
//!
//! Selection rules: an absent list selects the default
//! attempt channel; the sole item `all` expands to the
//! three ordinary channels and never implies an opt-in
//! journal channel; splitting is strict, so a spaced item
//! is unknown; duplicates collapse with the first
//! occurrence winning; an ordinary channel without the
//! attempt channel refuses; legacy input refuses journal
//! selections; and a device filter refuses journal
//! selections because filtering cannot hide global
//! conversion evidence. Any ordinary channel, or legacy
//! input, keeps the attempt dependency.
//!
//! Exit precedence: invalid input (2) beats missing
//! collection (3), missing beats every partial shape (4),
//! partial beats a strict proved violation (5), and an
//! ordinary valid report stays 0 with its policy field
//! shown independently. Recovery stays partial regardless
//! of policy flags; a comparison with refused requested
//! metrics is partial for the same reason.
//!
//! The module is self-contained on purpose: it declares no
//! parent items, so it compiles both under its public
//! module path and through a direct path include in tests.
//! It takes no live input and performs no I/O.

/// Clean exit: the stage accepted its input.
pub const EXIT_OK: i64 = 0;
/// Invalid input or usage.
pub const EXIT_INVALID: i64 = 2;
/// Refusal: required collection cannot start.
pub const EXIT_REFUSAL: i64 = 3;
/// Partial run: recovery, refused metrics, or incomplete strict evidence.
pub const EXIT_PARTIAL: i64 = 4;
/// Finalized strict proved policy violation.
pub const EXIT_POLICY_VIOLATION: i64 = 5;

/// Ordinary collection channels (implemented).
pub const ORDINARY_CAPABILITIES: &[&str] = &["attempt-trace", "mapping-lifecycle", "copy-actual"];
/// Opt-in journal channels (reserved; no record channel yet).
pub const JOURNAL_CAPABILITIES: &[&str] = &["conversion-observe", "conversion-journal"];
/// Planned exposure channels (refuse until their adapter ships).
pub const PLANNED_CAPABILITIES: &[&str] = &[
    "census",
    "object-lifetimes",
    "dma-paths",
    "shared-buffers",
    "host-interfaces",
    "mapping-inventory",
    "exposure-context",
];
/// Every capability id the frozen catalog names.
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "attempt-trace",
    "mapping-lifecycle",
    "copy-actual",
    "conversion-observe",
    "conversion-journal",
    "census",
    "object-lifetimes",
    "dma-paths",
    "shared-buffers",
    "host-interfaces",
    "mapping-inventory",
    "exposure-context",
];
/// Default selection when the list is absent.
pub const DEFAULT_CAPABILITY: &str = "attempt-trace";
/// Longest accepted device filter, in characters.
pub const MAX_DEVICE_CHARS: usize = 256;
/// Verdict labels the comparator lane emits per metric.
pub const KNOWN_COMPATIBILITY: &[&str] = &["compatible", "incompatible", "unavailable"];

/// One capability-list request: the raw list text, an
/// optional literal device filter, and whether the input
/// capture predates integrity metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionRequest {
    /// Comma-separated list; `None` selects the default channel.
    pub capabilities: Option<String>,
    /// Literal device name filter.
    pub device: Option<String>,
    /// True for pre-integrity (legacy) input captures.
    pub legacy: bool,
}

/// Resolved selection: the stage exit with its reason, the
/// selected ids in first-appearance order, the attempt-hook
/// dependency, and the recorded device filter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectionOutcome {
    /// Stage exit: 0 selected, 2 invalid, 3 channel-less.
    pub exit: i64,
    /// Refusal reason slug; `None` on a clean selection.
    pub reason: Option<String>,
    /// Selected ids; empty when parsing refused.
    pub selected: Vec<String>,
    /// True when collection needs the attempt hook.
    pub requires_attempt_hook: bool,
    /// Recorded device filter; `None` when absent or refused.
    pub device: Option<String>,
}

/// Flags feeding the exit table: input validity, collection
/// availability, recovery state, compare-row refusal, and
/// the strict/policy/evidence combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunOutcome {
    /// False when any input failed validation.
    pub inputs_valid: bool,
    /// True when required collection is unavailable.
    pub collection_missing: bool,
    /// True for a recovered unfinalized capture.
    pub recovered: bool,
    /// True when requested compare metrics were refused.
    pub refused_metrics: bool,
    /// True under the strict flag.
    pub strict: bool,
    /// True for a proved policy violation on finalized input.
    pub policy_violation_proved: bool,
    /// False when required strict evidence is incomplete.
    pub evidence_complete: bool,
}

/// One requested metric with its comparator verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricVerdict {
    /// Requested metric id.
    pub metric_id: String,
    /// One of [`KNOWN_COMPATIBILITY`].
    pub compatibility: String,
}

/// One compare request: both captures' validity, collection
/// and recovery state, the requested rows, and the
/// strict/policy/evidence combination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareRequest {
    /// False when the left capture failed validation.
    pub left_valid: bool,
    /// False when the right capture failed validation.
    pub right_valid: bool,
    /// True when required collection is unavailable.
    pub collection_missing: bool,
    /// True for a recovered unfinalized capture.
    pub recovered: bool,
    /// Requested metrics with their comparator verdicts.
    pub rows: Vec<MetricVerdict>,
    /// True under the strict flag.
    pub strict: bool,
    /// True for a proved policy violation on finalized input.
    pub policy_violation_proved: bool,
    /// False when required strict evidence is incomplete.
    pub evidence_complete: bool,
}

/// Compare exit with its refusal reason, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompareOutcome {
    /// Run exit following the precedence order.
    pub exit: i64,
    /// Refusal reason slug; `None` unless input refused.
    pub reason: Option<String>,
}

fn is_ordinary(id: &str) -> bool {
    ORDINARY_CAPABILITIES.contains(&id)
}

fn is_journal(id: &str) -> bool {
    JOURNAL_CAPABILITIES.contains(&id)
}

fn is_planned(id: &str) -> bool {
    PLANNED_CAPABILITIES.contains(&id)
}

/// Split a comma list strictly: no trimming, so a spaced
/// item stays a distinct (unknown) name.
fn split_list(text: &str) -> Vec<&str> {
    text.split(',').collect()
}

fn parse_refusal(reason: &str) -> SelectionOutcome {
    SelectionOutcome {
        exit: EXIT_INVALID,
        reason: Some(reason.to_string()),
        selected: Vec::new(),
        requires_attempt_hook: false,
        device: None,
    }
}

/// Resolve a capability-list request to its stage outcome.
///
/// Check order is fixed: list shape and names first, the
/// attempt-base rule, legacy input, the device value, then
/// the device combination. A parsed journal selection
/// reports its ids and hook dependency with the
/// channel-less refusal; only a clean ordinary selection
/// exits 0.
pub fn resolve_cli_selection(request: &SelectionRequest) -> SelectionOutcome {
    let ids: Vec<String> = match request.capabilities.as_deref() {
        None => vec![DEFAULT_CAPABILITY.to_string()],
        Some("") => return parse_refusal("empty-capability-list"),
        Some("all") => ORDINARY_CAPABILITIES
            .iter()
            .map(|name| name.to_string())
            .collect(),
        Some(list) => {
            let items = split_list(list);
            if items.iter().any(|item| item.is_empty()) {
                return parse_refusal("bad-capability-list");
            }
            let mut ids = Vec::new();
            for item in items {
                if is_planned(item) {
                    return parse_refusal("planned-capability");
                }
                if !is_ordinary(item) && !is_journal(item) {
                    return parse_refusal("unknown-capability");
                }
                if !ids.contains(&item.to_string()) {
                    ids.push(item.to_string());
                }
            }
            ids
        }
    };
    let has_ordinary = ids.iter().any(|id| is_ordinary(id));
    let has_journal = ids.iter().any(|id| is_journal(id));
    if has_ordinary && !ids.iter().any(|id| id == DEFAULT_CAPABILITY) {
        return parse_refusal("attempt-trace-required");
    }
    if request.legacy && has_journal {
        return parse_refusal("legacy-input");
    }
    if let Some(device) = request.device.as_deref() {
        if device.is_empty() || device.chars().count() > MAX_DEVICE_CHARS {
            return parse_refusal("invalid-device");
        }
        if has_journal {
            return parse_refusal("device-hides-global-evidence");
        }
    }
    let hook = has_ordinary || request.legacy;
    if has_journal {
        return SelectionOutcome {
            exit: EXIT_REFUSAL,
            reason: Some("no-record-channel".to_string()),
            selected: ids,
            requires_attempt_hook: hook,
            device: request.device.clone(),
        };
    }
    SelectionOutcome {
        exit: EXIT_OK,
        reason: None,
        selected: ids,
        requires_attempt_hook: hook,
        device: request.device.clone(),
    }
}

/// Map a run outcome to the process exit code.
///
/// Precedence: invalid input (2), missing collection (3),
/// recovered capture (4), refused requested metrics (4),
/// strict proved violation (5), strict incomplete evidence
/// (4), else 0. No other mapping exists.
pub fn exit_for_outcome(outcome: &RunOutcome) -> i64 {
    if !outcome.inputs_valid {
        return EXIT_INVALID;
    }
    if outcome.collection_missing {
        return EXIT_REFUSAL;
    }
    if outcome.recovered {
        return EXIT_PARTIAL;
    }
    if outcome.refused_metrics {
        return EXIT_PARTIAL;
    }
    if outcome.strict && outcome.policy_violation_proved {
        return EXIT_POLICY_VIOLATION;
    }
    if outcome.strict && !outcome.evidence_complete {
        return EXIT_PARTIAL;
    }
    EXIT_OK
}

/// Resolve a compare request to its exit.
///
/// Capture validity refuses before row shape; an empty
/// request, a repeated metric id, and an unknown verdict
/// label each refuse as invalid input. Any refused
/// requested metric makes the run partial; the surviving
/// flags then follow [`exit_for_outcome`].
pub fn resolve_compare(request: &CompareRequest) -> CompareOutcome {
    if !request.left_valid || !request.right_valid {
        return CompareOutcome {
            exit: EXIT_INVALID,
            reason: Some("invalid-capture".to_string()),
        };
    }
    if request.rows.is_empty() {
        return CompareOutcome {
            exit: EXIT_INVALID,
            reason: Some("no-requested-metrics".to_string()),
        };
    }
    let mut seen: Vec<&str> = Vec::new();
    for row in &request.rows {
        if seen.contains(&row.metric_id.as_str()) {
            return CompareOutcome {
                exit: EXIT_INVALID,
                reason: Some("duplicate-metric".to_string()),
            };
        }
        seen.push(row.metric_id.as_str());
        if !KNOWN_COMPATIBILITY.contains(&row.compatibility.as_str()) {
            return CompareOutcome {
                exit: EXIT_INVALID,
                reason: Some("unknown-compatibility".to_string()),
            };
        }
    }
    let refused = request
        .rows
        .iter()
        .any(|row| row.compatibility != "compatible");
    let outcome = RunOutcome {
        inputs_valid: true,
        collection_missing: request.collection_missing,
        recovered: request.recovered,
        refused_metrics: refused,
        strict: request.strict,
        policy_violation_proved: request.policy_violation_proved,
        evidence_complete: request.evidence_complete,
    };
    CompareOutcome {
        exit: exit_for_outcome(&outcome),
        reason: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_keeps_spacing_and_empties() {
        assert_eq!(split_list("a,b"), vec!["a", "b"]);
        assert_eq!(split_list("a,"), vec!["a", ""]);
        assert_eq!(split_list("a, b"), vec!["a", " b"]);
    }

    #[test]
    fn kinds_partition_the_known_ids() {
        for id in KNOWN_CAPABILITIES {
            let kinds = [is_ordinary(id), is_journal(id), is_planned(id)];
            assert_eq!(kinds.iter().filter(|kind| **kind).count(), 1, "id {id}");
        }
    }

    #[test]
    fn device_bound_counts_characters() {
        let ok = "d".repeat(MAX_DEVICE_CHARS);
        let long = "d".repeat(MAX_DEVICE_CHARS + 1);
        let base = SelectionRequest {
            capabilities: Some(DEFAULT_CAPABILITY.to_string()),
            device: None,
            legacy: false,
        };
        let accepted = SelectionRequest {
            device: Some(ok),
            ..base.clone()
        };
        assert_eq!(resolve_cli_selection(&accepted).exit, EXIT_OK);
        let refused = SelectionRequest {
            device: Some(long),
            ..base
        };
        assert_eq!(resolve_cli_selection(&refused).exit, EXIT_INVALID);
    }
}
