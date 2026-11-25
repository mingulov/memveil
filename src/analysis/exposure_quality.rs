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
    /// Unsealed or incomplete; no claim either way.
    Inconclusive,
}

impl fmt::Display for RuleOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Satisfied => write!(f, "satisfied"),
            Self::Partial => write!(f, "partial"),
            Self::Inconclusive => write!(f, "inconclusive"),
        }
    }
}

/// True when a required source status carries usable evidence.
fn source_usable(status: &str) -> bool {
    status == "available" || status == "partial"
}

/// Evaluate one rule over a snapshot's settlement state.
///
/// `required` carries one `(source_id, status, present)` triple per
/// required source. The outcome is [`RuleOutcome::Satisfied`] only for
/// sealed evidence with a settled terminal channel and every required
/// source present and usable; an empty required scope never satisfies.
/// An unsettled terminal channel yields
/// [`RuleOutcome::Partial`]; anything else is
/// [`RuleOutcome::Inconclusive`]. Unknown statuses fail closed.
pub fn rule_outcome(
    sealed: bool,
    terminal_status: &str,
    required: &[(&str, &str, bool)],
) -> RuleOutcome {
    let settled = terminal_status == COMPLETE;
    let complete = sealed
        && settled
        && !required.is_empty()
        && required
            .iter()
            .all(|(_, status, present)| *present && source_usable(status));
    if complete {
        RuleOutcome::Satisfied
    } else if !settled {
        RuleOutcome::Partial
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
        let full = [("sharing-census", "available", true)];
        assert_eq!(rule_outcome(true, COMPLETE, &full), RuleOutcome::Satisfied);
        assert_eq!(
            rule_outcome(false, COMPLETE, &full),
            RuleOutcome::Inconclusive
        );
        assert_eq!(rule_outcome(true, PARTIAL, &full), RuleOutcome::Partial);
        assert_eq!(rule_outcome(true, UNAVAILABLE, &full), RuleOutcome::Partial);
        assert_eq!(rule_outcome(true, "made_up", &full), RuleOutcome::Partial);
        let missing = [("sharing-census", "available", false)];
        assert_eq!(
            rule_outcome(true, COMPLETE, &missing),
            RuleOutcome::Inconclusive
        );
        let bad = [("sharing-census", "unavailable", true)];
        assert_eq!(
            rule_outcome(true, COMPLETE, &bad),
            RuleOutcome::Inconclusive
        );
        let unknown = [("sharing-census", "made_up", true)];
        assert_eq!(
            rule_outcome(true, COMPLETE, &unknown),
            RuleOutcome::Inconclusive
        );
        let empty: [(&str, &str, bool); 0] = [];
        assert_eq!(
            rule_outcome(true, COMPLETE, &empty),
            RuleOutcome::Inconclusive
        );
    }

    #[test]
    fn outcomes_render() {
        assert_eq!(RuleOutcome::Satisfied.to_string(), "satisfied");
        assert_eq!(RuleOutcome::Partial.to_string(), "partial");
        assert_eq!(RuleOutcome::Inconclusive.to_string(), "inconclusive");
    }
}
