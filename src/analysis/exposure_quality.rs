// SPDX-License-Identifier: GPL-3.0-or-later
//! Source quality for sealed exposure records.
//!
//! The five quality channels (detail, aggregate, identity, baseline,
//! terminal) stay independent: one channel's loss never moves another
//! channel's verdict, and an unobserved loss is never a measured zero.
//! A rule is satisfied only by sealed, settled evidence over present,
//! usable required sources; anything weaker fails closed.
//!
//! The module is self-contained on purpose: it declares no parent
//! items, so it compiles both under its public module path and
//! through a direct path include in tests. It takes no live input
//! and performs no I/O; offline replay consumes persisted records
//! only.

use std::fmt;

/// Settled channel status.
pub const COMPLETE: &str = "complete_for_scope";
/// Settled-with-loss channel status.
pub const PARTIAL: &str = "partial";
/// Unusable channel status.
pub const UNAVAILABLE: &str = "unavailable";

/// True when the channel status carries usable evidence.
pub fn channel_usable(status: &str) -> bool {
    status == COMPLETE || status == PARTIAL
}

/// True when the loss count was measured, including a measured zero.
///
/// `None` means unobservable and never collapses to zero.
pub fn loss_known(loss: Option<u64>) -> bool {
    loss.is_some()
}

/// Per-channel usability across the five channels.
///
/// Each output derives from its own channel's status alone: varying
/// one channel's status or loss never moves another channel. Losses
/// ride along so callers can prove loss-independence; usability
/// derives from status, never from a loss value.
pub fn evaluate_all(statuses: &[&str; 5], losses: &[Option<u64>; 5]) -> [bool; 5] {
    let _ = losses;
    [
        channel_usable(statuses[0]),
        channel_usable(statuses[1]),
        channel_usable(statuses[2]),
        channel_usable(statuses[3]),
        channel_usable(statuses[4]),
    ]
}

/// Rule outcome over sealed evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleOutcome {
    /// Sealed, settled evidence over complete required sources.
    Satisfied,
    /// Terminal evidence missing; never satisfied.
    Partial,
    /// Sealed, settled evidence with an incomplete required source;
    /// never satisfied and never conforming.
    Incomplete,
    /// Unsealed, absent, or uncovered; no claim either way.
    Inconclusive,
}

impl fmt::Display for RuleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Satisfied => write!(f, "satisfied"),
            Self::Partial => write!(f, "partial"),
            Self::Incomplete => write!(f, "incomplete"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// Required-source evidence state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SourceState {
    /// Present with usable evidence.
    Complete,
    /// Present but partial with no usable quality channel.
    Incomplete,
    /// Missing, unusable-status, or unknown.
    Absent,
}

/// Classify one required source's evidence.
///
/// An available source carries usable evidence. A partial source
/// does only when at least one quality channel stays usable; a
/// partial source with no usable channel is incomplete evidence.
/// Anything else (a missing entry, an unavailable, disabled,
/// not-applicable or unknown status) is absent.
fn source_state(status: &str, present: bool, quality_usable: bool) -> SourceState {
    if !present {
        return SourceState::Absent;
    }
    if status == "available" {
        return SourceState::Complete;
    }
    if status == "partial" {
        return if quality_usable {
            SourceState::Complete
        } else {
            SourceState::Incomplete
        };
    }
    SourceState::Absent
}

/// Evaluate the metadata gate over a snapshot's settlement state.
///
/// `required` carries one `(source_id, status, present,
/// quality_usable)` tuple per required source, where
/// `quality_usable` is true when at least one quality channel
/// carries usable evidence. The outcome is
/// [`RuleOutcome::Satisfied`] only for sealed evidence with a
/// settled terminal channel and every required source present with
/// complete evidence; an empty required scope never satisfies. An
/// unsettled terminal channel yields [`RuleOutcome::Partial`].
/// Sealed, settled evidence with every required source present and
/// at least one incomplete yields [`RuleOutcome::Incomplete`];
/// anything else is [`RuleOutcome::Inconclusive`]. Unknown statuses
/// fail closed. The gate stays private: no caller can satisfy a rule
/// from metadata alone, only [`rule_outcome_with_facts`] reports a
/// verdict, and it additionally requires sealed facts from each
/// required source.
fn metadata_gate(
    sealed: bool,
    terminal_status: &str,
    required: &[(&str, &str, bool, bool)],
) -> RuleOutcome {
    let settled = terminal_status == COMPLETE;
    let states: Vec<SourceState> = required
        .iter()
        .map(|(_, status, present, usable)| source_state(status, *present, *usable))
        .collect();
    let complete = sealed
        && settled
        && !required.is_empty()
        && states.iter().all(|state| *state == SourceState::Complete);
    let incomplete = sealed
        && settled
        && !required.is_empty()
        && !states.contains(&SourceState::Absent)
        && states.contains(&SourceState::Incomplete);
    if complete {
        RuleOutcome::Satisfied
    } else if !settled {
        RuleOutcome::Partial
    } else if incomplete {
        RuleOutcome::Incomplete
    } else {
        RuleOutcome::Inconclusive
    }
}

/// Evaluate one rule over sealed evidence with replayed fact coverage.
///
/// `required` carries one `(source_id, status, present,
/// quality_usable)` tuple per required source; `fact_sources`
/// carries one `source_id` per fact replayed from the sealed lines.
/// This is the only verdict path: the outcome is
/// [`RuleOutcome::Satisfied`] only when the metadata gate passes
/// and every required source contributed at least one fact whose
/// `source_id` equals it. Usable metadata alone never satisfies,
/// and facts from other catalog sources never satisfy a required
/// source. Anything weaker keeps the metadata gate's weaker
/// outcome.
pub fn rule_outcome_with_facts(
    sealed: bool,
    terminal_status: &str,
    required: &[(&str, &str, bool, bool)],
    fact_sources: &[&str],
) -> RuleOutcome {
    let outcome = metadata_gate(sealed, terminal_status, required);
    if outcome != RuleOutcome::Satisfied {
        return outcome;
    }
    let covered = required
        .iter()
        .all(|(source, _, _, _)| fact_sources.contains(source));
    if covered {
        RuleOutcome::Satisfied
    } else {
        RuleOutcome::Inconclusive
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usability_comes_from_status_only() {
        assert!(channel_usable("complete_for_scope"));
        assert!(channel_usable("partial"));
        assert!(!channel_usable("unavailable"));
        assert!(!channel_usable("made_up"));
        assert!(!channel_usable(""));
        assert!(loss_known(Some(0)));
        assert!(loss_known(Some(9)));
        assert!(!loss_known(None));
    }

    #[test]
    fn rule_outcomes_fail_closed() {
        let full = [("sharing-census", "available", true, true)];
        let covering = ["sharing-census"];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &full, &covering),
            RuleOutcome::Satisfied
        );
        assert_eq!(
            rule_outcome_with_facts(false, COMPLETE, &full, &covering),
            RuleOutcome::Inconclusive
        );
        assert_eq!(
            rule_outcome_with_facts(true, PARTIAL, &full, &covering),
            RuleOutcome::Partial
        );
        assert_eq!(
            rule_outcome_with_facts(true, UNAVAILABLE, &full, &covering),
            RuleOutcome::Partial
        );
        assert_eq!(
            rule_outcome_with_facts(true, "made_up", &full, &covering),
            RuleOutcome::Partial
        );
        let missing = [("sharing-census", "available", false, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &missing, &covering),
            RuleOutcome::Inconclusive
        );
        let bad = [("sharing-census", "unavailable", true, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &bad, &covering),
            RuleOutcome::Inconclusive
        );
        let unknown = [("sharing-census", "made_up", true, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &unknown, &covering),
            RuleOutcome::Inconclusive
        );
        let empty: [(&str, &str, bool, bool); 0] = [];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &empty, &covering),
            RuleOutcome::Inconclusive
        );
    }

    #[test]
    fn rule_outcomes_need_facts_from_each_required_source() {
        let full = [("sharing-census", "available", true, true)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &full, &["sharing-census"]),
            RuleOutcome::Satisfied
        );
        // Facts from another catalog source never satisfy.
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &full, &["egress-controls"]),
            RuleOutcome::Inconclusive
        );
        // No facts never satisfy, even over usable metadata.
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &full, &[]),
            RuleOutcome::Inconclusive
        );
        // Weaker metadata outcomes pass through unchanged.
        assert_eq!(
            rule_outcome_with_facts(false, COMPLETE, &full, &["sharing-census"]),
            RuleOutcome::Inconclusive
        );
        assert_eq!(
            rule_outcome_with_facts(true, PARTIAL, &full, &["sharing-census"]),
            RuleOutcome::Partial
        );
    }

    #[test]
    fn outcomes_render() {
        assert_eq!(RuleOutcome::Satisfied.to_string(), "satisfied");
        assert_eq!(RuleOutcome::Partial.to_string(), "partial");
        assert_eq!(RuleOutcome::Incomplete.to_string(), "incomplete");
        assert_eq!(RuleOutcome::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn incomplete_required_evidence_is_incomplete() {
        let covering = ["sharing-census"];
        // A partial source with no usable quality channel can never
        // satisfy, even with covering facts: the verdict is
        // incomplete, never satisfied and never inconclusive.
        let partial = [("sharing-census", "partial", true, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &partial, &covering),
            RuleOutcome::Incomplete
        );
        // A partial source with usable quality still satisfies.
        let usable = [("sharing-census", "partial", true, true)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &usable, &covering),
            RuleOutcome::Satisfied
        );
        // Weaker outcomes keep their precedence below incomplete.
        assert_eq!(
            rule_outcome_with_facts(true, PARTIAL, &partial, &covering),
            RuleOutcome::Partial
        );
        assert_eq!(
            rule_outcome_with_facts(false, COMPLETE, &partial, &covering),
            RuleOutcome::Inconclusive
        );
        // Absent sources stay inconclusive, never incomplete.
        let missing = [("sharing-census", "partial", false, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &missing, &covering),
            RuleOutcome::Inconclusive
        );
        let unavailable = [("sharing-census", "unavailable", true, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &unavailable, &covering),
            RuleOutcome::Inconclusive
        );
        let disabled = [("sharing-census", "disabled", true, false)];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &disabled, &covering),
            RuleOutcome::Inconclusive
        );
        // Incomplete is a metadata outcome: it holds even when the
        // facts do not cover, exactly like Partial.
        let bare: [&str; 0] = [];
        assert_eq!(
            rule_outcome_with_facts(true, COMPLETE, &partial, &bare),
            RuleOutcome::Incomplete
        );
    }
}
