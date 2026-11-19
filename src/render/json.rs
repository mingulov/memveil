// SPDX-License-Identifier: GPL-3.0-or-later
//! JSON report renderer: report v0.1.4 output.
//!
//! Every string passes through [`escape_json`], which emits the quoted JSON
//! literal with short escapes for quote, backslash, and common controls
//! and `\u00XX` for the rest; valid multibyte UTF-8 passes through raw.
//! Numbers stay canonical decimal strings; absent optionals stay absent
//! while explicit nulls echo as null (asserted_mode, driver), so the
//! report matches the session exactly; evidence_refs are omitted when
//! empty.

use super::filter::resolve_device_filter;
use crate::model::report::Report;
use crate::model::session::Channel;
use crate::model::validate::format_u64;

/// Report schema version stamped on every JSON document.
pub const REPORT_SCHEMA_VERSION: &str = "0.1.4";

fn hex_nibble(v: u8) -> u8 {
    if v < 10 { b'0' + v } else { b'a' + v - 10 }
}

/// Render `s` as one quoted JSON string literal.
pub fn escape_json(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len() + 2);
    out.push(b'"');
    for &b in s.as_bytes() {
        match b {
            b'"' => out.extend_from_slice(b"\\\""),
            b'\\' => out.extend_from_slice(b"\\\\"),
            0x0A => out.extend_from_slice(b"\\n"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0D => out.extend_from_slice(b"\\r"),
            0x08 => out.extend_from_slice(b"\\b"),
            0x0C => out.extend_from_slice(b"\\f"),
            _ if b < 0x20 || b == 0x7F => {
                out.extend_from_slice(b"\\u00");
                out.push(hex_nibble(b >> 4));
                out.push(hex_nibble(b & 15));
            }
            _ => out.push(b),
        }
    }
    out.push(b'"');
    // Only ASCII bytes are replaced, and only by valid UTF-8, so a
    // valid UTF-8 input stays valid UTF-8.
    String::from_utf8(out).expect("escape_json output is UTF-8")
}

fn channel_json(label: &str, ch: &Channel, level: usize) -> String {
    let pad = "  ".repeat(level);
    let inner = format!("{pad}  ");
    let mut out = format!("{pad}{}: {{\n", escape_json(label));
    out.push_str(&format!(
        "{inner}\"status\": {},\n",
        escape_json(&ch.status)
    ));
    out.push_str(&format!("{inner}\"loss_count\": "));
    if ch.has_loss_count {
        out.push_str(&format!("\"{}\"", format_u64(ch.loss_count)));
    } else {
        out.push_str("null");
    }
    out.push_str(",\n");
    out.push_str(&format!("{inner}\"scope\": {},\n", escape_json(&ch.scope)));
    out.push_str(&format!("{inner}\"reason\": {}", escape_json(&ch.reason)));
    if !ch.evidence_refs.is_empty() {
        out.push_str(&format!(",\n{inner}\"evidence_refs\": ["));
        for (i, reference) in ch.evidence_refs.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&escape_json(reference));
        }
        out.push(']');
    }
    out.push_str(&format!("\n{pad}}}"));
    out
}

/// Render quality.correlation with its optional relations.
fn correlation_json(rep: &Report, level: usize) -> String {
    let pad = "  ".repeat(level);
    let inner = format!("{pad}  ");
    let ch = &rep.q_correlation;
    let mut out = format!("{pad}{}: {{\n", escape_json("correlation"));
    out.push_str(&format!(
        "{inner}\"status\": {},\n",
        escape_json(&ch.status)
    ));
    out.push_str(&format!("{inner}\"loss_count\": "));
    if ch.has_loss_count {
        out.push_str(&format!("\"{}\"", format_u64(ch.loss_count)));
    } else {
        out.push_str("null");
    }
    out.push_str(",\n");
    out.push_str(&format!("{inner}\"scope\": {},\n", escape_json(&ch.scope)));
    out.push_str(&format!("{inner}\"reason\": {}", escape_json(&ch.reason)));
    if !ch.evidence_refs.is_empty() {
        out.push_str(&format!(",\n{inner}\"evidence_refs\": ["));
        for (i, reference) in ch.evidence_refs.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&escape_json(reference));
        }
        out.push(']');
    }
    if rep.has_corr_relations {
        out.push_str(&format!(",\n{inner}\"relations\": {{\n"));
        out.push_str(&channel_json(
            "mapping_release",
            &rep.q_corr_mapping,
            level + 2,
        ));
        out.push_str(",\n");
        out.push_str(&channel_json(
            "copy_attribution",
            &rep.q_corr_copy,
            level + 2,
        ));
        out.push_str(",\n");
        out.push_str(&channel_json(
            "sync_attribution",
            &rep.q_corr_sync,
            level + 2,
        ));
        out.push_str(&format!("\n{inner}}}"));
    }
    out.push_str(&format!("\n{pad}}}"));
    out
}

/// Render the report as pretty JSON per report-v0.1.4.schema.json.
pub fn render_json(rep: &Report, device_filter: &str) -> String {
    let filt = resolve_device_filter(&rep.devices, device_filter);
    let mut out = String::from("{\n");
    out.push_str(&format!(
        "  \"schema_version\": \"{REPORT_SCHEMA_VERSION}\",\n"
    ));
    out.push_str(&format!(
        "  \"integrity\": {{\"status\": {}, \"verified_bytes\": \"{}\", \"verified_events\": \"{}\"",
        escape_json(&rep.integrity_status),
        format_u64(rep.verified_bytes),
        format_u64(rep.verified_events)
    ));
    if rep.integrity_status == "checkpoint_prefix" {
        out.push_str(&format!(
            ", \"unverified_bytes\": \"{}\"",
            format_u64(rep.unverified_bytes)
        ));
    }
    out.push_str("},\n");
    out.push_str(&format!(
        "  \"session_id\": {},\n",
        escape_json(&rep.session_id)
    ));
    if rep.synthetic {
        out.push_str("  \"synthetic\": true,\n");
    } else {
        out.push_str("  \"synthetic\": false,\n");
    }
    out.push_str(&format!(
        "  \"engine_version\": {},\n",
        escape_json(&rep.engine_version)
    ));
    out.push_str("  \"environment\": {\n");
    out.push_str(&format!("    \"mode\": {},\n", escape_json(&rep.env.mode)));
    out.push_str(&format!(
        "    \"detection\": {},\n",
        escape_json(&rep.env.detection)
    ));
    if rep.env.asserted_mode_present {
        out.push_str("    \"asserted_mode\": ");
        if rep.env.has_asserted_mode {
            out.push_str(&escape_json(&rep.env.asserted_mode));
        } else {
            out.push_str("null");
        }
        out.push_str(",\n");
    }
    out.push_str(&format!(
        "    \"attestation\": {},\n",
        escape_json(&rep.env.attestation)
    ));
    if rep.env.evidence.is_empty() {
        out.push_str("    \"evidence\": []\n");
    } else {
        out.push_str("    \"evidence\": [\n");
        for (i, e) in rep.env.evidence.iter().enumerate() {
            out.push_str(&format!(
                "      {{\"type\": {}, \"source\": {}, \"interpretation\": {}}}",
                escape_json(&e.item_type),
                escape_json(&e.source),
                escape_json(&e.interpretation)
            ));
            if i + 1 < rep.env.evidence.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("    ]\n");
    }
    out.push_str("  },\n");
    out.push_str("  \"device_catalog\": {\n");
    if rep.devices.is_empty() {
        out.push_str("    \"devices\": []\n");
    } else {
        out.push_str("    \"devices\": [\n");
        for (i, d) in rep.devices.iter().enumerate() {
            out.push_str(&format!(
                "      {{\"device_id\": {}, \"name\": {}",
                escape_json(&d.device_id),
                escape_json(&d.name)
            ));
            if d.driver_present {
                out.push_str(", \"driver\": ");
                if d.has_driver {
                    out.push_str(&escape_json(&d.driver));
                } else {
                    out.push_str("null");
                }
            }
            out.push_str(&format!(
                ", \"identity_status\": {}}}",
                escape_json(&d.identity_status)
            ));
            if i + 1 < rep.devices.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("    ]\n");
    }
    out.push_str("  },\n");
    out.push_str("  \"capabilities\": {\n");
    for (i, c) in rep.caps.iter().enumerate() {
        out.push_str(&format!(
            "    {}: {{\"status\": {}, \"grade\": ",
            escape_json(&c.name),
            escape_json(&c.status)
        ));
        if c.has_grade {
            out.push_str(&escape_json(&c.grade));
        } else {
            out.push_str("null");
        }
        out.push_str(&format!(", \"reason\": {}}}", escape_json(&c.reason)));
        if i + 1 < rep.caps.len() {
            out.push(',');
        }
        out.push('\n');
    }
    out.push_str("  },\n");
    out.push_str("  \"quality\": {\n");
    out.push_str(&channel_json("detail", &rep.q_detail, 2));
    out.push_str(",\n");
    out.push_str(&channel_json("aggregate", &rep.q_aggregate, 2));
    out.push_str(",\n");
    out.push_str(&correlation_json(rep, 2));
    out.push_str(",\n");
    out.push_str(&channel_json("baseline", &rep.q_baseline, 2));
    out.push_str(",\n");
    out.push_str(&channel_json("terminal", &rep.q_terminal, 2));
    out.push('\n');
    out.push_str("  },\n");
    out.push_str("  \"verdict\": {\n");
    out.push_str(&format!(
        "    \"name\": {},\n",
        escape_json(&rep.verdict.name)
    ));
    out.push_str(&format!(
        "    \"loss_ratio_bps\": \"{}\",\n",
        format_u64(u64::try_from(rep.verdict.loss_ratio_bps).expect("loss_ratio_bps non-negative"))
    ));
    out.push_str(&format!(
        "    \"delivered\": \"{}\"\n",
        format_u64(rep.detail_delivered)
    ));
    out.push_str("  },\n");
    let shown = rep
        .metrics
        .iter()
        .filter(|m| filt.is_empty() || !m.has_device_id || m.device_id == filt)
        .count();
    if shown == 0 {
        out.push_str("  \"metrics\": [],\n");
    } else {
        out.push_str("  \"metrics\": [\n");
        let mut emitted = 0;
        for m in &rep.metrics {
            if !filt.is_empty() && m.has_device_id && m.device_id != filt {
                continue;
            }
            out.push_str(&format!("    {{\"name\": {}", escape_json(&m.name)));
            out.push_str(", \"value\": ");
            if m.has_value {
                out.push_str(&format!("\"{}\"", format_u64(m.value)));
            } else {
                out.push_str("null");
            }
            out.push_str(&format!(
                ", \"unit\": {}, \"measurement\": {}, \"coverage\": {}, \"confidence\": {}",
                escape_json(&m.unit),
                escape_json(&m.measurement),
                escape_json(&m.coverage),
                escape_json(&m.confidence)
            ));
            out.push_str(", \"aggregation\": ");
            if m.has_aggregation {
                out.push_str(&escape_json(&m.aggregation));
            } else {
                out.push_str("null");
            }
            out.push_str(", \"sample_count\": ");
            if m.has_sample_count {
                out.push_str(&format!("\"{}\"", format_u64(m.sample_count)));
            } else {
                out.push_str("null");
            }
            out.push_str(", \"dimensions\": {\"device_id\": ");
            if m.has_device_id {
                out.push_str(&escape_json(&m.device_id));
            } else {
                out.push_str("null");
            }
            out.push_str(", \"pool_id\": ");
            if m.has_pool_id {
                out.push_str(&escape_json(&m.pool_id));
            } else {
                out.push_str("null");
            }
            out.push_str(&format!(
                "}}, \"scope\": {}, \"notes\": {}}}",
                escape_json(&m.scope),
                escape_json(&m.notes)
            ));
            emitted += 1;
            if emitted < shown {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
    }
    if rep.findings.is_empty() {
        out.push_str("  \"findings\": [],\n");
    } else {
        out.push_str("  \"findings\": [\n");
        for (i, finding) in rep.findings.iter().enumerate() {
            out.push_str(&format!(
                "    {{\"code\": {}, \"severity\": {}, \"explanation\": {}, \"evidence_refs\": [",
                escape_json(&finding.code),
                escape_json(&finding.severity),
                escape_json(&finding.explanation)
            ));
            for (ri, reference) in finding.evidence_refs.iter().enumerate() {
                if ri > 0 {
                    out.push_str(", ");
                }
                out.push_str(&escape_json(reference));
            }
            out.push_str(&format!(
                "], \"scope\": {}, \"limitations\": {}}}",
                escape_json(&finding.scope),
                escape_json(&finding.limitations)
            ));
            if i + 1 < rep.findings.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ],\n");
    }
    if rep.limitations.is_empty() {
        out.push_str("  \"limitations\": []\n");
    } else {
        out.push_str("  \"limitations\": [\n");
        for (i, limitation) in rep.limitations.iter().enumerate() {
            out.push_str(&format!("    {}", escape_json(limitation)));
            if i + 1 < rep.limitations.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push_str("  ]\n");
    }
    out.push_str("}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::super::analyze_fixture;
    use super::*;
    use crate::model::metric::Metric;
    use crate::model::report::ReportCap;
    use crate::model::scan::Scanner;
    use crate::model::session::DeviceEntry;

    fn parse_back(doc: &str) -> String {
        let mut scan = Scanner::new(doc.as_bytes());
        let out = scan.parse_string("test").expect("parse string");
        scan.skip_ws();
        assert!(scan.at_end());
        out
    }

    fn assert_wellformed(doc: &str) {
        let mut scan = Scanner::new(doc.as_bytes());
        scan.skip_value("test").expect("skip value");
        scan.skip_ws();
        assert!(scan.at_end());
    }

    #[test]
    fn escape_json_roundtrip() {
        let cases = [
            "plain".to_string(),
            "a\"b\\c/d\u{e9}\u{1f600}".to_string(),
            "x\u{1}\u{1b}\u{7f}\n\t end".to_string(),
        ];
        for case in cases {
            assert_eq!(parse_back(&escape_json(&case)), case);
        }
        assert_eq!(escape_json("a"), "\"a\"");
        assert_eq!(escape_json("say \"hi\""), "\"say \\\"hi\\\"\"");
    }

    #[test]
    fn escape_json_control_spellings() {
        assert_eq!(escape_json("\u{8}"), "\"\\b\"");
        assert_eq!(escape_json("\u{c}"), "\"\\f\"");
        assert_eq!(escape_json("\u{1}"), "\"\\u0001\"");
        assert_eq!(escape_json("\u{7f}"), "\"\\u007f\"");
        assert_eq!(escape_json("d\u{e9}e"), "\"d\u{e9}e\"");
    }

    #[test]
    fn json_wellformed_for_every_golden_input() {
        for dir in [
            "tests/fixtures/attempts",
            "tests/fixtures/reader/escape",
            "tests/fixtures/reader/privacy-canary",
            "tests/fixtures/lifecycle/lifecycle-nested",
            "tests/fixtures/lifecycle/copy-before-failure",
            "tests/fixtures/pools/pressure",
            "tests/fixtures/regions/region-union",
            "tests/fixtures/regions/gen-lineage",
            "tests/fixtures/regions/conversion-uncertain",
        ] {
            assert_wellformed(&render_json(&analyze_fixture(dir), ""));
        }
    }

    #[test]
    fn json_report_version() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert!(render_json(&rep, "").contains("\"schema_version\": \"0.1.4\""));
    }

    #[test]
    fn json_verdict() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let doc = render_json(&rep, "");
        assert!(doc.contains("\"verdict\": {"));
        assert!(doc.contains("\"name\": \"partial_unknown_loss\""));
        assert!(doc.contains("\"loss_ratio_bps\": \"0\""));
        assert!(doc.contains("\"delivered\": \"3\""));
    }

    #[test]
    fn json_top_level_key_order_verbatim() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let doc = render_json(&rep, "");
        let keys = [
            "\"schema_version\"",
            "\"integrity\"",
            "\"session_id\"",
            "\"synthetic\"",
            "\"engine_version\"",
            "\"environment\"",
            "\"device_catalog\"",
            "\"capabilities\"",
            "\"quality\"",
            "\"verdict\"",
            "\"metrics\"",
            "\"findings\"",
            "\"limitations\"",
        ];
        let mut prev = 0;
        for key in keys {
            let pos = doc.find(key).unwrap_or_else(|| panic!("missing {key}"));
            assert!(pos > prev, "{key} out of order");
            prev = pos;
        }
    }

    #[test]
    fn json_relations_present_when_split() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-copy-only");
        assert!(rep.has_corr_relations);
        let doc = render_json(&rep, "");
        assert!(doc.contains("\"relations\""));
        assert!(doc.contains("\"copy_attribution\""));
        assert_wellformed(&doc);
    }

    #[test]
    fn json_relations_absent_when_legacy() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-legacy-copy");
        assert!(!rep.has_corr_relations);
        assert!(!render_json(&rep, "").contains("\"relations\""));
    }

    #[test]
    fn json_escapes() {
        let rep = analyze_fixture("tests/fixtures/reader/escape");
        let out = render_json(&rep, "");
        let parts: Vec<&str> = out.split("\"a\\\"b\\\\c|d_e*f[g]h`i&<j>k\"").collect();
        assert_eq!(parts.len(), 2);
        let drv: Vec<&str> = out.split("\"dr\\nv\\u001be\"").collect();
        assert_eq!(drv.len(), 2);
    }

    #[test]
    fn json_tristate_echo() {
        let rep = analyze_fixture("tests/fixtures/reader/f6-absent-asserted");
        let doc = render_json(&rep, "");
        assert!(!doc.contains("\"asserted_mode\":"));
        assert!(doc.contains("\"driver\":"));
        let rep2 = analyze_fixture("tests/fixtures/reader/f6-absent-driver");
        let doc2 = render_json(&rep2, "");
        assert!(!doc2.contains("\"driver\":"));
        assert!(doc2.contains("\"asserted_mode\":"));
    }

    #[test]
    fn json_exact_u64() {
        let mut rep = Report {
            session_id: "u64probe".to_string(),
            synthetic: true,
            engine_version: crate::ENGINE_VERSION.to_string(),
            window_start_ns: 100,
            window_end_ns: 200,
            ..Report::default()
        };
        rep.env.mode = "unknown".to_string();
        rep.env.detection = "unverified".to_string();
        rep.env.attestation = "not_performed".to_string();
        rep.metrics.push(Metric {
            name: "big".to_string(),
            has_value: true,
            value: u64::MAX,
            unit: "bytes".to_string(),
            ..Metric::default()
        });
        assert!(render_json(&rep, "").contains("\"value\": \"18446744073709551615\""));
    }

    #[test]
    fn capabilities_matrix_json() {
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
        let doc = render_json(&rep, "");
        assert!(doc.contains(
            "\"bounce_attempts\": {\"status\": \"partial\", \"grade\": \"local-auto\", \"reason\": \"capture ok\"}"
        ));
        assert!(doc.contains(
            "\"mapping_lifecycle\": {\"status\": \"unavailable\", \"grade\": null, \"reason\": \"no source\"}"
        ));
    }

    #[test]
    fn render_missing_identity_json() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: "eth9".to_string(),
            identity_status: "unresolved".to_string(),
            ..DeviceEntry::default()
        });
        assert!(render_json(&rep, "").contains("\"identity_status\": \"unresolved\""));
    }

    #[test]
    fn device_name_filter_resolves_json() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(render_json(&rep, "testdev0"), render_json(&rep, "dev-1"));
    }

    #[test]
    fn golden_inputs_render_deterministically() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(render_json(&rep, ""), render_json(&rep, ""));
    }
}
