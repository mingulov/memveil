// SPDX-License-Identifier: GPL-3.0-or-later
//! Markdown report renderer: tables for devices, quality, metrics.
//!
//! Free-text cells (names, drivers, scopes, reasons, notes, findings,
//! limitations, metric names, dimension values, units) pass through
//! [`escape_markdown`]: controls are neutralized first, then
//! HTML-significant characters (&, <, >) become entities so hostile
//! metadata cannot inject tags or comments, and Markdown-active
//! punctuation (backslash, pipe, star, underscore, brackets, backtick)
//! is backslash-escaped so tables and formatting cannot break.
//! Fixed-vocabulary tokens (channels, statuses, measurements,
//! coverages, confidences, severities, codes) render verbatim;
//! their character sets are inert in table cells.

use super::context::{measured_duration, recorded_value};
use super::filter::resolve_device_filter;
use super::text::{attestation_text, escape_text, integrity_line, summary_lines, verdict_line};
use crate::model::report::Report;
use crate::model::session::Channel;
use crate::model::validate::format_u64;

/// Neutralize controls, then HTML- and Markdown-escape one cell value.
pub fn escape_markdown(s: &str) -> String {
    let clean = escape_text(s);
    let mut out: Vec<u8> = Vec::with_capacity(clean.len());
    for &b in clean.as_bytes() {
        match b {
            0x26 => out.extend_from_slice(b"&amp;"),
            0x3C => out.extend_from_slice(b"&lt;"),
            0x3E => out.extend_from_slice(b"&gt;"),
            _ => {
                if b == 0x5C
                    || b == 0x7C
                    || b == 0x2A
                    || b == 0x5F
                    || b == 0x5B
                    || b == 0x5D
                    || b == 0x60
                {
                    out.push(0x5C);
                }
                out.push(b);
            }
        }
    }
    // escape_text output is valid UTF-8 and only ASCII bytes gain
    // ASCII prefixes here, so the result stays valid UTF-8.
    String::from_utf8(out).expect("escape_markdown output is UTF-8")
}

fn dims_cell(has_device: bool, device: &str, has_pool: bool, pool: &str) -> String {
    if has_device && has_pool {
        return format!(
            "device={}, pool={}",
            escape_markdown(device),
            escape_markdown(pool)
        );
    }
    if has_device {
        return format!("device={}", escape_markdown(device));
    }
    if has_pool {
        return format!("pool={}", escape_markdown(pool));
    }
    "all".to_string()
}

fn quality_row(label: &str, ch: &Channel) -> String {
    let mut out = String::from("| ");
    out.push_str(label);
    out.push_str(" | ");
    out.push_str(&ch.status);
    out.push_str(" | ");
    if ch.has_loss_count {
        out.push_str(&format_u64(ch.loss_count));
    } else {
        out.push_str("unknown");
    }
    out.push_str(" | ");
    out.push_str(&escape_markdown(&ch.scope));
    out.push_str(" | ");
    out.push_str(&escape_markdown(&ch.reason));
    out.push_str(" |\n");
    out
}

/// Render the report as Markdown, one trailing newline.
pub fn render_markdown(rep: &Report, device_filter: &str) -> String {
    let filt = resolve_device_filter(&rep.devices, device_filter);
    let mut out = String::from("# Memveil report `");
    out.push_str(&escape_text(&rep.session_id));
    out.push_str("`\n\n");
    for line in summary_lines(rep, escape_markdown, &filt) {
        out.push_str("- ");
        out.push_str(&line);
        out.push('\n');
    }
    if rep.synthetic {
        out.push_str("- synthetic: yes\n");
    } else {
        out.push_str("- synthetic: no\n");
    }
    out.push_str("- engine: ");
    out.push_str(&escape_text(&rep.engine_version));
    out.push_str("\n- ");
    out.push_str(&integrity_line(rep));
    out.push_str("\n- ");
    out.push_str(&verdict_line(rep));
    out.push_str("\n- window: [");
    out.push_str(&format_u64(rep.window_start_ns));
    out.push(',');
    out.push_str(&format_u64(rep.window_end_ns));
    out.push_str(")\n- duration: ");
    out.push_str(&measured_duration(rep));
    out.push_str("\n- environment: mode=");
    out.push_str(&escape_text(&rep.env.mode));
    out.push_str(" detection=");
    out.push_str(&escape_text(&rep.env.detection));
    out.push_str(" attestation=");
    out.push_str(&attestation_text(&rep.env.attestation));
    if rep.env.has_asserted_mode {
        out.push_str(" asserted=");
        out.push_str(&escape_text(&rep.env.asserted_mode));
    }
    out.push_str(" evidence=");
    out.push_str(&rep.env.evidence.len().to_string());
    for source in ["kernel.release", "profile.decision", "measurement_scope"] {
        out.push_str("\n- recorded ");
        out.push_str(&escape_markdown(source));
        out.push_str(": ");
        out.push_str(&escape_markdown(&recorded_value(&rep.env.evidence, source)));
    }
    out.push_str("\n- devices: ");
    out.push_str(&rep.devices.len().to_string());
    out.push_str("\n\n## Devices\n\n");
    out.push_str("| device_id | name | driver | identity |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for d in &rep.devices {
        out.push_str("| ");
        out.push_str(&escape_markdown(&d.device_id));
        out.push_str(" | ");
        out.push_str(&escape_markdown(&d.name));
        out.push_str(" | ");
        if d.has_driver {
            out.push_str(&escape_markdown(&d.driver));
        } else {
            out.push_str("none");
        }
        out.push_str(" | ");
        out.push_str(&escape_text(&d.identity_status));
        out.push_str(" |\n");
    }
    out.push_str("\n## Capabilities\n\n");
    out.push_str("| capability | status | grade | reason |\n");
    out.push_str("| --- | --- | --- | --- |\n");
    for c in &rep.caps {
        out.push_str("| ");
        out.push_str(&escape_markdown(&c.name));
        out.push_str(" | ");
        out.push_str(&escape_markdown(&c.status));
        out.push_str(" | ");
        if c.has_grade {
            out.push_str(&escape_markdown(&c.grade));
        } else {
            out.push_str("none");
        }
        out.push_str(" | ");
        out.push_str(&escape_markdown(&c.reason));
        out.push_str(" |\n");
    }
    out.push_str("\n## Quality\n\n");
    out.push_str("| channel | status | loss | scope | reason |\n");
    out.push_str("| --- | --- | --- | --- | --- |\n");
    out.push_str(&quality_row("detail", &rep.q_detail));
    out.push_str(&quality_row("aggregate", &rep.q_aggregate));
    out.push_str(&quality_row("correlation", &rep.q_correlation));
    out.push_str(&quality_row("baseline", &rep.q_baseline));
    out.push_str(&quality_row("terminal", &rep.q_terminal));
    out.push_str("\n## Metrics\n\n");
    out.push_str(
        "| name | dimensions | value | unit | measurement | coverage | confidence | scope | notes |\n",
    );
    out.push_str("| --- | --- | --- | --- | --- | --- | --- | --- | --- |\n");
    for m in &rep.metrics {
        if !filt.is_empty() && m.has_device_id && m.device_id != filt {
            continue;
        }
        out.push_str("| ");
        out.push_str(&escape_markdown(&m.name));
        out.push_str(" | ");
        out.push_str(&dims_cell(
            m.has_device_id,
            &m.device_id,
            m.has_pool_id,
            &m.pool_id,
        ));
        out.push_str(" | ");
        if m.has_value {
            out.push_str(&format_u64(m.value));
        } else {
            out.push_str("unavailable");
        }
        out.push_str(" | ");
        out.push_str(&escape_markdown(&m.unit));
        out.push_str(" | ");
        out.push_str(&escape_text(&m.measurement));
        out.push_str(" | ");
        out.push_str(&escape_text(&m.coverage));
        out.push_str(" | ");
        out.push_str(&escape_text(&m.confidence));
        out.push_str(" | ");
        out.push_str(&escape_markdown(&m.scope));
        out.push_str(" | ");
        out.push_str(&escape_markdown(&m.notes));
        out.push_str(" |\n");
    }
    out.push_str("\n## Findings\n\n");
    if rep.findings.is_empty() {
        out.push_str("none\n");
    } else {
        out.push_str("| severity | code | explanation | scope | limitations | refs |\n");
        out.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for finding in &rep.findings {
            out.push_str("| ");
            out.push_str(&escape_text(&finding.severity));
            out.push_str(" | ");
            out.push_str(&escape_text(&finding.code));
            out.push_str(" | ");
            out.push_str(&escape_markdown(&finding.explanation));
            out.push_str(" | ");
            out.push_str(&escape_markdown(&finding.scope));
            out.push_str(" | ");
            out.push_str(&escape_markdown(&finding.limitations));
            out.push_str(" | ");
            for (ri, reference) in finding.evidence_refs.iter().enumerate() {
                if ri > 0 {
                    out.push_str(", ");
                }
                out.push_str(&escape_markdown(reference));
            }
            out.push_str(" |\n");
        }
    }
    out.push_str("\n## Limitations\n\n");
    for limitation in &rep.limitations {
        out.push_str("- ");
        out.push_str(&escape_markdown(limitation));
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::{analyze_fixture, golden};
    use super::*;
    use crate::model::report::ReportCap;
    use crate::model::session::DeviceEntry;

    #[test]
    fn escape_markdown_matrix() {
        assert_eq!(
            escape_markdown("a|b*c_d[e]f`g\\h"),
            "a\\|b\\*c\\_d\\[e\\]f\\`g\\\\h"
        );
        assert_eq!(escape_markdown("plain (v1.5): ok"), "plain (v1.5): ok");
        assert_eq!(escape_markdown("a&b<c>d"), "a&amp;b&lt;c&gt;d");
        assert_eq!(
            escape_markdown("<!-- hidden --> <strong>forged</strong>"),
            "&lt;!-- hidden --&gt; &lt;strong&gt;forged&lt;/strong&gt;"
        );
        assert_eq!(
            escape_markdown("&lt;already&gt;"),
            "&amp;lt;already&amp;gt;"
        );
        assert_eq!(
            escape_markdown("<!-- hidden --> <strong>x</strong>"),
            "&lt;!-- hidden --&gt; &lt;strong&gt;x&lt;/strong&gt;"
        );
    }

    #[test]
    fn golden_markdown_attempts() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            render_markdown(&rep, ""),
            golden("tests/golden/report-attempts.md")
        );
    }

    #[test]
    fn golden_markdown_escape() {
        let rep = analyze_fixture("tests/fixtures/reader/escape");
        assert_eq!(
            render_markdown(&rep, ""),
            golden("tests/golden/report-escape.md")
        );
    }

    #[test]
    fn capabilities_matrix_markdown() {
        let mut rep = Report::default();
        rep.caps.push(ReportCap {
            name: "bounce_attempts".to_string(),
            status: "partial".to_string(),
            has_grade: true,
            grade: "local-auto".to_string(),
            reason: "capture ok".to_string(),
        });
        rep.caps.push(ReportCap {
            name: "mapping_lifecycle".to_string(),
            status: "unavailable".to_string(),
            reason: "no source".to_string(),
            ..ReportCap::default()
        });
        let md = render_markdown(&rep, "");
        assert!(md.contains(
            "| bounce\\_attempts | partial | local-auto | capture ok |\n| mapping\\_lifecycle | unavailable | none | no source |\n"
        ));
    }

    #[test]
    fn render_markdown_verdict_header() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let doc = render_markdown(&rep, "");
        assert!(doc.contains("- verdict: partial_unknown_loss (loss >=0.00%, 3 delivered)\n"));
    }

    #[test]
    fn render_missing_identity_markdown() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: "eth9".to_string(),
            identity_status: "unresolved".to_string(),
            ..DeviceEntry::default()
        });
        let md = render_markdown(&rep, "");
        assert!(md.contains("| unresolved |"));
        assert!(md.contains("| none |"));
    }

    #[test]
    fn device_name_filter_resolves_markdown() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            render_markdown(&rep, "testdev0"),
            render_markdown(&rep, "dev-1")
        );
    }

    #[test]
    fn undimensioned_metrics_mark_all() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let md = render_markdown(&rep, "");
        assert!(md.contains("| bounce\\_attempts | all | 3 |"));
    }

    #[test]
    fn summary_bullets_open_the_prose_list() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let md = render_markdown(&rep, "");
        assert!(md.starts_with("# Memveil report `attempts-3-session`\n\n"));
        assert!(md.contains(
            "- summary: attempts 3, requested bytes 9 KiB (9216 bytes) in 3.00 s\n- summary devices: dev-1 (testdev0): attempts 3, requested bytes 9 KiB (9216 bytes)\n"
        ));
    }

    #[test]
    fn attested_capture_marks_attestation_unverified_markdown() {
        let rep = analyze_fixture("tests/fixtures/reader/attested-external");
        let md = render_markdown(&rep, "");
        assert!(md.contains("attestation=external_verified (recorded, not verified by memveil)"));
    }

    #[test]
    fn summary_bullets_escape_markdown_cells() {
        let mut rep = crate::model::report::Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d1".to_string(),
            name: "a|b`c".to_string(),
            ..DeviceEntry::default()
        });
        let md = render_markdown(&rep, "");
        assert!(md.contains("- summary devices: d1 (a\\|b\\`c): attempts unavailable"));
        assert!(!md.contains("a|b"));
    }
}
