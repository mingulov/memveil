// SPDX-License-Identifier: GPL-3.0-or-later
//! Report renderers: text, JSON, and Markdown views over [`Report`](crate::model::report::Report).
//!
//! Every renderer takes a finished report plus a display device
//! filter; analysis and capture never meet rendering here. The text
//! and Markdown layouts are pinned byte-for-byte by the golden files
//! under `tests/golden/`; JSON follows the report 0.1.4 key order
//! with canonical decimal strings for every number.

pub mod context;
pub mod filter;
pub mod json;
pub mod markdown;
// The dispatch module keeps its Mojo source basename (`render.mojo`),
// which collides with this directory module by design.
#[allow(clippy::module_inception)]
pub mod render;
pub mod text;

pub use context::{measured_duration, recorded_value};
pub use filter::{device_filter_resolves, resolve_device_filter};
pub use json::{REPORT_SCHEMA_VERSION, escape_json, render_json};
pub use markdown::{escape_markdown, render_markdown};
pub use render::{RenderError, render};
pub use text::{escape_text, integrity_line, render_compact, render_text, verdict_line};

#[cfg(test)]
pub(crate) fn analyze_fixture(rel: &str) -> crate::model::report::Report {
    use crate::analysis::diagnostics::diagnose_report;
    use crate::analysis::engine::Analyzer;
    use crate::capture::reader::{default_limits, read_capture};
    use crate::model::report::{apply_checkpoint, apply_integrity};

    let dir = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    let mut reader = read_capture(&dir, false, default_limits()).expect("read capture");
    let mut analyzer = Analyzer::new(reader.session.clone());
    while reader.has_more().expect("has_more") {
        let event = reader.next_event().expect("next event");
        analyzer.consume(&event).expect("consume");
    }
    let end = reader.session.window_end_ns;
    let partial = reader.partial;
    let mut rep = analyzer.finish(end, partial).expect("finish");
    apply_integrity(
        &mut rep,
        reader.integrity_verified,
        reader.session.integrity.events_bytes,
        reader.session.integrity.line_count,
    );
    if reader.checkpoint_prefix {
        apply_checkpoint(
            &mut rep,
            reader.session.integrity.events_bytes,
            reader.session.integrity.line_count,
            reader.unverified_bytes,
        );
    }
    diagnose_report(&mut rep, false, 0);
    rep
}

#[cfg(test)]
pub(crate) fn golden(rel: &str) -> String {
    let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("read golden file {rel}"))
}
