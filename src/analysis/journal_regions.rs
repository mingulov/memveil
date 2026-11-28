// SPDX-License-Identifier: GPL-3.0-or-later
//! Synthetic offline region observation for conversion-journal evidence.
//!
//! A request-only source establishes no region identity, baseline, or
//! closure, so this tracker observes result counts only: it performs
//! no lifetime netting, reports no outstanding ranges, and never
//! infers host access. It stays synthetic and offline until a separate
//! lifetime source is admitted.

use crate::model::event::Event;

/// Offline region observation: counts without identity.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalRegions {
    /// Request-only results observed; none establishes identity.
    pub observed_results: u64,
}

impl JournalRegions {
    /// Empty offline observation.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one journal result without pairing or netting it.
    ///
    /// Every observation stays request-only: the tracker records that
    /// a result was seen and nothing about what it aliases, overlaps,
    /// or leaves outstanding.
    pub fn observe(&mut self, ev: &Event) {
        if ev.has_journal && ev.journal_version {
            self.observed_results += 1;
        }
    }
}
