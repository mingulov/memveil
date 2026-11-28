// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline analysis: pure reducers over validated events plus diagnosis.
//!
//! The [`Analyzer`](engine::Analyzer) feeds one event stream to every
//! tracker and merges their rows into one report. Trackers never touch
//! live readers; diagnosis reads finished reports only.

pub mod attempts;
pub mod diagnostics;
pub mod engine;
pub mod exposure_compare;
pub mod exposure_context;
pub mod exposure_lineage;
pub mod exposure_mappings;
pub mod exposure_policy;
pub mod exposure_quality;
pub mod journal_conversions;
pub mod journal_findings;
pub mod journal_regions;
pub mod mappings;
pub mod metrics;
pub mod pools;
pub mod regions;
