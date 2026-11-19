// SPDX-License-Identifier: GPL-3.0-or-later
//! Format dispatch for report rendering.

use super::json::render_json;
use super::markdown::render_markdown;
use super::text::render_text;
use crate::model::report::Report;

/// One rendering failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenderError {
    /// Human-readable failure message.
    pub message: String,
}

impl core::fmt::Display for RenderError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RenderError {}

/// Render the report in the named format.
///
/// Accepts text, json, and markdown; anything else fails. A
/// non-empty device filter shows global rows plus only the
/// matching device's per-device rows.
pub fn render(rep: &Report, format: &str, device_filter: &str) -> Result<String, RenderError> {
    if format != "text" && format != "json" && format != "markdown" {
        return Err(RenderError {
            message: format!("unknown format: {format}"),
        });
    }
    // The Rust renderers are infallible by construction, so there is
    // no inner failure to wrap; the unknown-format error above keeps
    // the Mojo dispatch contract.
    Ok(match format {
        "json" => render_json(rep, device_filter),
        "markdown" => render_markdown(rep, device_filter),
        _ => render_text(rep, device_filter),
    })
}

#[cfg(test)]
mod tests {
    use super::super::{analyze_fixture, golden};
    use super::*;

    fn structural_pipes(line: &str) -> usize {
        line.replace("\\\\", "\x00")
            .replace("\\|", "\x00")
            .matches('|')
            .count()
    }

    fn tables_rectangular(md: &str) -> bool {
        let mut block: Vec<usize> = Vec::new();
        for line in md.split('\n') {
            if line.starts_with('|') {
                block.push(structural_pipes(line));
            } else {
                if block.iter().collect::<std::collections::HashSet<_>>().len() > 1 {
                    return false;
                }
                block.clear();
            }
        }
        block.iter().collect::<std::collections::HashSet<_>>().len() <= 1
    }

    #[test]
    fn dispatch_renders_three_distinct_documents() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let text = render(&rep, "text", "").expect("text");
        let json = render(&rep, "json", "").expect("json");
        let md = render(&rep, "markdown", "").expect("markdown");
        assert_ne!(text, json);
        assert_ne!(text, md);
        assert_ne!(json, md);
        assert_eq!(text, render_text(&rep, ""));
        assert_eq!(json, render_json(&rep, ""));
        assert_eq!(md, render_markdown(&rep, ""));
    }

    #[test]
    fn dispatch_matches_direct_filtered_calls() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            render(&rep, "text", "dev-1").expect("text"),
            render_text(&rep, "dev-1")
        );
        assert_eq!(
            render(&rep, "json", "testdev0").expect("json"),
            render_json(&rep, "testdev0")
        );
        assert_eq!(
            render(&rep, "markdown", "dev-1").expect("markdown"),
            render_markdown(&rep, "dev-1")
        );
    }

    #[test]
    fn unknown_format_fails_loudly() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let err = render(&rep, "yaml", "").expect_err("yaml must fail");
        assert_eq!(err.message, "unknown format: yaml");
    }

    #[test]
    fn hostile_metadata_keeps_table_structure() {
        for cap in ["escape", "privacy-canary"] {
            let rep = analyze_fixture(&format!("tests/fixtures/reader/{cap}"));
            let md = render(&rep, "markdown", "").expect("markdown");
            assert!(
                tables_rectangular(&md),
                "{cap}: tables must stay rectangular"
            );
            assert!(!md.contains('\x1b'), "{cap}: no raw ESC in markdown");

            let text = render(&rep, "text", "").expect("text");
            let devs: Vec<&str> = text
                .split('\n')
                .filter(|ln| ln.starts_with("  dev-"))
                .collect();
            assert_eq!(devs.len(), 1, "{cap}: one device line");
            assert!(!text.contains('\x1b'), "{cap}: no raw ESC in text");

            let json = render(&rep, "json", "").expect("json");
            assert!(!json.contains('\x1b'), "{cap}: no raw ESC in json");
            let again = render(&rep, "json", "").expect("json again");
            assert_eq!(again, json, "{cap}: renders are byte-stable");
        }
    }

    #[test]
    fn canary_controls_never_render_raw() {
        let rep = analyze_fixture("tests/fixtures/reader/privacy-canary");
        let text = render(&rep, "text", "").expect("text");
        let md = render(&rep, "markdown", "").expect("markdown");
        let json = render(&rep, "json", "").expect("json");
        for (name, blob) in [
            ("text", text.as_bytes()),
            ("markdown", md.as_bytes()),
            ("json", json.as_bytes()),
        ] {
            assert!(!blob.contains(&0x1b), "no ESC in {name}");
            assert!(!blob.contains(&0x07), "no BEL in {name}");
            assert!(!blob.contains(&0x7f), "no DEL in {name}");
            assert!(
                !blob.windows(13).any(|w| w == b"MV-CANARY-COMM"),
                "no observer context in {name}"
            );
            assert!(
                !blob.windows(10).any(|w| w == b"plain-comm"),
                "no plain observer context in {name}"
            );
        }
        assert!(text.contains("MV-CANARY-DRIVER-L1\\nL2"));
        assert!(!text.contains("\x1b[2J"));
        assert!(text.contains("\\ttab"));

        assert!(md.contains("pipe\\|tick"));
        assert!(md.contains("tick\\`"));
        assert!(md.contains("star\\*"));
        assert!(md.contains("brack\\[et\\]"));
        assert!(md.contains("amp&amp;lt;"));
        assert!(!md.contains("pipe|tick"));
        let hits: Vec<&str> = md
            .split('\n')
            .filter(|ln| ln.contains("MV-CANARY-NAME"))
            .collect();
        assert_eq!(hits.len(), 1);

        assert!(json.contains("\\u001b"));
        assert!(json.contains("\\u007f"));
    }

    #[test]
    fn golden_files_cover_every_report_mapping() {
        for name in [
            "tests/golden/report-attempts.txt",
            "tests/golden/report-attempts.md",
            "tests/golden/report-escape.txt",
            "tests/golden/report-escape.md",
            "tests/golden/report-lifecycle-nested.txt",
            "tests/golden/report-copy-before-failure.txt",
            "tests/golden/report-pool-pressure.txt",
            "tests/golden/report-region-union.txt",
            "tests/golden/report-gen-lineage.txt",
            "tests/golden/report-conversion-uncertain.txt",
        ] {
            assert!(!golden(name).is_empty(), "{name} must be non-empty");
        }
    }
}
