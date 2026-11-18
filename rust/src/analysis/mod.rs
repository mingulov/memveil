// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline analysis: pure reducers over validated events plus diagnosis.
//!
//! The [`Analyzer`](engine::Analyzer) feeds one event stream to every
//! tracker and merges their rows into one report. Trackers never touch
//! live readers; diagnosis reads finished reports only.

pub mod attempts;
pub mod diagnostics;
pub mod engine;
pub mod mappings;
pub mod metrics;
pub mod pools;
pub mod regions;

/// Cap text at limit codepoints, on a char boundary.
pub(crate) fn truncate_codepoints(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect()
}
