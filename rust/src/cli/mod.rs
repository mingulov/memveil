// SPDX-License-Identifier: GPL-3.0-or-later
//! Command-line verbs: argument parsing, dispatch helpers, and reporting.
//!
//! Each verb keeps its own parsing and usage next to its runner.
//! `report` additionally hosts the shared CLI infrastructure every
//! verb builds on: exit codes, scrubbed stderr writers, diagnostic
//! escaping, and refusal lines.

pub mod durations;
pub mod record;
pub mod report;
