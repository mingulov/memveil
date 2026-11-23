// SPDX-License-Identifier: GPL-3.0-or-later
//! Plain-text report renderer.
//!
//! Every echoed value passes through [`escape_text`], so control bytes in
//! metadata (device names, drivers, reasons) can neither break the
//! line layout nor smuggle terminal sequences: newline, tab, and return
//! become literal backslash sequences, other C0 bytes and DEL become
//! U+FFFD, and printable text including multibyte characters passes
//! through untouched.

use super::context::{measured_duration, recorded_value};
use super::filter::resolve_device_filter;
use crate::model::metric::Metric;
use crate::model::report::Report;
use crate::model::session::Channel;
use crate::model::validate::format_u64;

pub fn escape_text(s: &str) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            0x0A => out.extend_from_slice(b"\\n"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0D => out.extend_from_slice(b"\\r"),
            _ if b < 0x20 || b == 0x7F => {
                out.extend_from_slice("\u{fffd}".as_bytes());
            }
            _ => out.push(b),
        }
    }
    // Only ASCII bytes are replaced, and only by valid UTF-8, so a
    // valid UTF-8 input stays valid UTF-8.
    String::from_utf8(out).expect("escape_text output is UTF-8")
}

fn dims_text(has_device: bool, device: &str, has_pool: bool, pool: &str) -> String {
    if has_device && has_pool {
        return format!(
            "{{device={}, pool={}}}",
            escape_text(device),
            escape_text(pool)
        );
    }
    if has_device {
        return format!("{{device={}}}", escape_text(device));
    }
    if has_pool {
        return format!("{{pool={}}}", escape_text(pool));
    }
    String::new()
}

fn channel_block(label: &str, ch: &Channel) -> String {
    let mut out = String::from("  ");
    out.push_str(label);
    out.push_str(": ");
    out.push_str(&escape_text(&ch.status));
    out.push_str(" loss=");
    if ch.has_loss_count {
        out.push_str(&format_u64(ch.loss_count));
    } else {
        out.push_str("unknown");
    }
    out.push_str("\n    scope: ");
    out.push_str(&escape_text(&ch.scope));
    out.push_str("\n    reason: ");
    out.push_str(&escape_text(&ch.reason));
    out.push('\n');
    out
}

/// True when the row survives the display device filter.
fn shown(m: &Metric, device_filter: &str) -> bool {
    if device_filter.is_empty() {
        return true;
    }
    if !m.has_device_id {
        return true;
    }
    m.device_id == device_filter
}

/// Format basis points as an exact two-place percent.
fn bps_percent(bps: i64) -> String {
    // Basis points are non-negative by construction; Mojo's
    // UInt64() conversion traps on negatives, so fail loudly
    // here too instead of wrapping.
    let whole = u64::try_from(bps / 100).expect("bps non-negative");
    let frac = u64::try_from(bps % 100).expect("bps non-negative");
    let mut out = format_u64(whole);
    out.push('.');
    if frac < 10 {
        out.push('0');
    }
    out.push_str(&format_u64(frac));
    out.push('%');
    out
}

/// Attestation value with its honesty qualifier, no trailing newline.
///
/// The value is recorded capture data: memveil performs no
/// attestation itself, so every prose rendering says the value
/// was recorded, not verified. JSON keeps the bare value.
pub fn attestation_text(value: &str) -> String {
    format!("{} (recorded, not verified by memveil)", escape_text(value))
}

/// One-line verdict header, no trailing newline.
///
/// Unknown verdicts carry a lower-bound marker: the ratio bounds
/// known loss from below and never claims a total.
pub fn verdict_line(rep: &Report) -> String {
    if rep.verdict.name.is_empty() {
        return "verdict: unavailable (not computed)".to_string();
    }
    let mut out = String::from("verdict: ");
    out.push_str(&rep.verdict.name);
    out.push_str(" (loss ");
    if rep.verdict.name == "partial_unknown_loss" {
        out.push_str(">=");
    }
    out.push_str(&bps_percent(rep.verdict.loss_ratio_bps));
    out.push_str(", ");
    out.push_str(&format_u64(rep.detail_delivered));
    out.push_str(" delivered)");
    out
}

/// Value of a global (dimension-free) metric, when measured.
///
/// Same row the compact headlines read; unknown stays unknown,
/// never zero.
fn global_metric_value(rep: &Report, name: &str) -> Option<u64> {
    for m in &rep.metrics {
        if m.name == name && !m.has_device_id && !m.has_pool_id && m.has_value {
            return Some(m.value);
        }
    }
    None
}

fn global_metric_text(rep: &Report, name: &str) -> String {
    match global_metric_value(rep, name) {
        Some(v) => format_u64(v),
        None => "withheld".to_string(),
    }
}

/// Value of one device's metric row, when measured.
fn device_metric_value(rep: &Report, name: &str, device_id: &str) -> Option<u64> {
    for m in &rep.metrics {
        if m.name == name
            && m.has_device_id
            && !m.has_pool_id
            && m.device_id == device_id
            && m.has_value
        {
            return Some(m.value);
        }
    }
    None
}

/// Human-readable byte count with the exact value in parentheses.
///
/// Exact multiples print without a fraction (`64 MiB (67108864
/// bytes)`); anything else rounds to one decimal place (`1.5 KiB
/// (1536 bytes)`). Counts below one kibibyte print bare (`900
/// bytes`). The parenthesized integer is the measured value, so
/// the rounded headline can never stand alone.
pub fn human_bytes(n: u64) -> String {
    const UNITS: [(u64, &str); 7] = [
        (1, "bytes"),
        (1024, "KiB"),
        (1048576, "MiB"),
        (1073741824, "GiB"),
        (1099511627776, "TiB"),
        (1125899906842624, "PiB"),
        (1152921504606846976, "EiB"),
    ];
    let mut unit = UNITS[0];
    for cand in UNITS {
        if n >= cand.0 {
            unit = cand;
        } else {
            break;
        }
    }
    if unit.0 == 1 {
        return format!("{n} bytes");
    }
    let q = n / unit.0;
    let r = n % unit.0;
    if r == 0 {
        return format!("{} {} ({n} bytes)", format_u64(q), unit.1);
    }
    let mut tenths = ((r as u128 * 10 + (unit.0 as u128) / 2) / unit.0 as u128) as u64;
    let mut q = q;
    if tenths == 10 {
        q += 1;
        tenths = 0;
    }
    format!("{}.{tenths} {} ({n} bytes)", format_u64(q), unit.1)
}

/// Human-readable seconds, rounded to centiseconds (`10.03 s`).
pub fn human_seconds(ns: u64) -> String {
    let rem = ns % 1_000_000_000;
    let mut secs = ns / 1_000_000_000;
    let mut centis = (rem + 5_000_000) / 10_000_000;
    if centis == 100 {
        // secs tops out at 18446744073, so +1 cannot overflow.
        secs += 1;
        centis = 0;
    }
    format!("{}.{:02} s", format_u64(secs), centis)
}

fn fmt_count(v: Option<u64>) -> String {
    match v {
        Some(n) => format_u64(n),
        None => "unavailable".to_string(),
    }
}

fn fmt_bytes(v: Option<u64>) -> String {
    match v {
        Some(n) => human_bytes(n),
        None => "unavailable".to_string(),
    }
}

/// Total pool use and capacity across every pool row.
///
/// Pool gauges carry per-pool dimensions only, so the headline
/// sums each half over the measured rows; a half with no
/// measured row stays unavailable. Saturating: hostile totals
/// clamp instead of wrapping.
fn pool_totals(rep: &Report) -> (Option<u64>, Option<u64>) {
    let mut used: Option<u64> = None;
    let mut cap: Option<u64> = None;
    for m in &rep.metrics {
        if !m.has_pool_id || !m.has_value {
            continue;
        }
        if m.name == "pool_used_bytes" {
            used = Some(used.unwrap_or(0).saturating_add(m.value));
        } else if m.name == "pool_capacity_bytes" {
            cap = Some(cap.unwrap_or(0).saturating_add(m.value));
        }
    }
    (used, cap)
}

/// Plain 4-5 line summary answering bouncing, how much, which device.
///
/// The headlines reuse the compact data (global attempt rows),
/// humanized for prose renderers only; JSON keeps raw integers.
/// `esc` neutralizes device text for the calling format. The
/// copies line appears only when a copy channel measured
/// something; the scope line always states what the numbers do
/// and do not prove. Whole-capture truth: the display device
/// filter does not narrow these lines.
pub fn summary_lines<E: Fn(&str) -> String>(rep: &Report, esc: E) -> Vec<String> {
    let attempts = global_metric_text(rep, "bounce_attempts");
    let attempts_known = global_metric_value(rep, "bounce_attempts").is_some();
    let bytes = match global_metric_value(rep, "requested_bounce_bytes") {
        Some(n) => human_bytes(n),
        None => "withheld".to_string(),
    };
    let mut lines = Vec::new();
    if rep.window_end_ns < rep.window_start_ns {
        lines.push(format!(
            "summary: attempts {attempts}, requested bytes {bytes} (window unavailable: invalid recorded window)"
        ));
    } else {
        lines.push(format!(
            "summary: attempts {attempts}, requested bytes {bytes} in {}",
            human_seconds(rep.window_end_ns - rep.window_start_ns)
        ));
    }
    if rep.devices.is_empty() {
        lines.push("summary devices: none recorded".to_string());
    } else {
        let mut parts = Vec::new();
        for d in &rep.devices {
            let a = fmt_count(device_metric_value(rep, "bounce_attempts", &d.device_id));
            let b = fmt_bytes(device_metric_value(
                rep,
                "requested_bounce_bytes",
                &d.device_id,
            ));
            parts.push(format!(
                "{} ({}): attempts {a}, requested bytes {b}",
                esc(&d.device_id),
                esc(&d.name)
            ));
        }
        lines.push(format!("summary devices: {}", parts.join("; ")));
    }
    let to_bounce = global_metric_value(rep, "copy_original_to_bounce_bytes");
    let to_original = global_metric_value(rep, "copy_bounce_to_original_bytes");
    let copies_known = to_bounce.is_some() || to_original.is_some();
    if copies_known {
        lines.push(format!(
            "summary copies: original-to-bounce {}, bounce-to-original {}",
            fmt_bytes(to_bounce),
            fmt_bytes(to_original)
        ));
    }
    let (used, cap) = pool_totals(rep);
    lines.push(format!(
        "summary pool: used {} of {} capacity",
        fmt_bytes(used),
        fmt_bytes(cap)
    ));
    let scope = match (attempts_known, copies_known) {
        (true, false) => {
            "proves bounce attempts were counted; does not prove bytes were copied or DMA succeeded"
        }
        (true, true) => {
            "proves bounce attempts were counted and executed copies were observed; does not prove DMA success"
        }
        (false, true) => {
            "proves executed copies were observed (attempts uncounted); does not prove DMA success"
        }
        (false, false) => {
            "proves nothing (attempts uncounted); does not prove bouncing occurred, bytes moved, or DMA ran"
        }
    };
    lines.push(format!("summary scope: {scope}"));
    lines
}

/// Render the per-refresh summary: verdict plus headlines.
pub fn render_compact(rep: &Report) -> String {
    let mut out = verdict_line(rep);
    out.push('\n');
    out.push_str(&integrity_line(rep));
    out.push('\n');
    out.push_str("attempts: ");
    out.push_str(&global_metric_text(rep, "bounce_attempts"));
    out.push_str("  requested bytes: ");
    out.push_str(&global_metric_text(rep, "requested_bounce_bytes"));
    out.push('\n');
    out.push_str("detail: ");
    out.push_str(&rep.q_detail.status);
    if rep.q_detail.has_loss_count {
        out.push_str(", loss ");
        out.push_str(&format_u64(rep.q_detail.loss_count));
    } else {
        out.push_str(", loss unknown");
    }
    out.push('\n');
    out.push_str("terminal: ");
    out.push_str(&rep.q_terminal.status);
    out.push('\n');
    if rep.findings.is_empty() {
        out.push_str("findings: none\n");
    } else {
        out.push_str("findings: ");
        out.push_str(&rep.findings.len().to_string());
        out.push_str(": ");
        for (i, finding) in rep.findings.iter().enumerate() {
            if i > 0 {
                out.push_str(", ");
            }
            out.push_str(&finding.code);
            out.push('(');
            out.push_str(&finding.severity);
            out.push(')');
        }
        out.push('\n');
    }
    out
}

/// Render the report as plain text, one trailing newline.
pub fn render_text(rep: &Report, device_filter: &str) -> String {
    let filt = resolve_device_filter(&rep.devices, device_filter);
    let mut out = String::new();
    for line in summary_lines(rep, escape_text) {
        out.push_str(&line);
        out.push('\n');
    }
    out.push_str(&verdict_line(rep));
    out.push('\n');
    out.push_str(&integrity_line(rep));
    out.push('\n');
    out.push_str("memveil report ");
    out.push_str(&escape_text(&rep.session_id));
    if rep.synthetic {
        out.push_str(" (synthetic, engine ");
    } else {
        out.push_str(" (live, engine ");
    }
    out.push_str(&escape_text(&rep.engine_version));
    out.push_str(")\n");
    out.push_str("window: [");
    out.push_str(&format_u64(rep.window_start_ns));
    out.push(',');
    out.push_str(&format_u64(rep.window_end_ns));
    out.push_str(")\n");
    out.push_str("duration: ");
    out.push_str(&measured_duration(rep));
    out.push('\n');
    out.push_str("environment: mode=");
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
    out.push('\n');
    for source in ["kernel.release", "profile.decision", "measurement_scope"] {
        out.push_str("recorded ");
        out.push_str(source);
        out.push_str(": ");
        out.push_str(&escape_text(&recorded_value(&rep.env.evidence, source)));
        out.push('\n');
    }
    out.push_str("devices (");
    out.push_str(&rep.devices.len().to_string());
    out.push_str("):\n");
    for d in &rep.devices {
        out.push_str("  ");
        out.push_str(&escape_text(&d.device_id));
        out.push(' ');
        out.push_str(&escape_text(&d.name));
        out.push_str(" driver=");
        if d.has_driver {
            out.push_str(&escape_text(&d.driver));
        } else {
            out.push_str("none");
        }
        out.push_str(" identity=");
        out.push_str(&escape_text(&d.identity_status));
        out.push('\n');
    }
    out.push_str("capabilities:\n");
    for c in &rep.caps {
        out.push_str("  ");
        out.push_str(&escape_text(&c.name));
        out.push_str(": ");
        out.push_str(&escape_text(&c.status));
        if c.has_grade {
            out.push_str(" [");
            out.push_str(&escape_text(&c.grade));
            out.push(']');
        }
        out.push_str(" - ");
        out.push_str(&escape_text(&c.reason));
        out.push('\n');
    }
    out.push_str("quality:\n");
    out.push_str(&channel_block("detail", &rep.q_detail));
    out.push_str(&channel_block("aggregate", &rep.q_aggregate));
    out.push_str(&channel_block("correlation", &rep.q_correlation));
    out.push_str(&channel_block("baseline", &rep.q_baseline));
    out.push_str(&channel_block("terminal", &rep.q_terminal));
    let shown_count = rep.metrics.iter().filter(|m| shown(m, &filt)).count();
    out.push_str("metrics (");
    out.push_str(&shown_count.to_string());
    out.push_str("):\n");
    for m in &rep.metrics {
        if !shown(m, &filt) {
            continue;
        }
        out.push_str("  ");
        out.push_str(&escape_text(&m.name));
        out.push_str(&dims_text(
            m.has_device_id,
            &m.device_id,
            m.has_pool_id,
            &m.pool_id,
        ));
        out.push_str(" = ");
        if m.has_value {
            out.push_str(&format_u64(m.value));
        } else {
            out.push_str("unavailable");
        }
        out.push(' ');
        out.push_str(&escape_text(&m.unit));
        out.push_str(" [");
        out.push_str(&escape_text(&m.measurement));
        out.push_str(", ");
        out.push_str(&escape_text(&m.coverage));
        out.push_str(", ");
        out.push_str(&escape_text(&m.confidence));
        if m.has_aggregation {
            out.push_str(", ");
            out.push_str(&escape_text(&m.aggregation));
        }
        out.push_str("]\n    scope: ");
        out.push_str(&escape_text(&m.scope));
        out.push_str("\n    notes: ");
        out.push_str(&escape_text(&m.notes));
        out.push('\n');
    }
    if rep.findings.is_empty() {
        out.push_str("findings: none\n");
    } else {
        out.push_str("findings (");
        out.push_str(&rep.findings.len().to_string());
        out.push_str("):\n");
        for finding in &rep.findings {
            out.push_str("  [");
            out.push_str(&escape_text(&finding.severity));
            out.push_str("] ");
            out.push_str(&escape_text(&finding.code));
            out.push_str(": ");
            out.push_str(&escape_text(&finding.explanation));
            out.push_str("\n    scope: ");
            out.push_str(&escape_text(&finding.scope));
            out.push_str("\n    limitations: ");
            out.push_str(&escape_text(&finding.limitations));
            out.push_str("\n    refs: ");
            for (ri, reference) in finding.evidence_refs.iter().enumerate() {
                if ri > 0 {
                    out.push_str(", ");
                }
                out.push_str(&escape_text(reference));
            }
            out.push('\n');
        }
    }
    out.push_str("limitations (");
    out.push_str(&rep.limitations.len().to_string());
    out.push_str("):\n");
    for limitation in &rep.limitations {
        out.push_str("  - ");
        out.push_str(&escape_text(limitation));
        out.push('\n');
    }
    out
}

pub fn integrity_line(rep: &Report) -> String {
    if rep.integrity_context != "capture" {
        return format!(
            "integrity: unverified {}; finalized file verification pending; completeness withheld",
            rep.integrity_context
        );
    }
    let mut out = String::from("integrity: ");
    out.push_str(&rep.integrity_status);
    out.push_str(" (verified bytes=");
    out.push_str(&format_u64(rep.verified_bytes));
    out.push_str(", events=");
    out.push_str(&format_u64(rep.verified_events));
    out.push(')');
    if rep.integrity_status == "checkpoint_prefix" {
        out.push_str("; unverified suffix bytes=");
        out.push_str(&format_u64(rep.unverified_bytes));
        out.push_str(
            "; verified prefix only; measurement window remains open; no authenticity claim",
        );
    } else if rep.integrity_status == "verified" {
        out.push_str("; literal capture bytes match SHA-256; no authenticity claim");
    } else {
        out.push_str("; arithmetic is unverified; completeness withheld");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::super::{analyze_fixture, golden};
    use super::*;
    use crate::model::metric::Metric;
    use crate::model::report::ReportCap;
    use crate::model::session::DeviceEntry;

    #[test]
    fn escape_text_neutralizes_controls() {
        let fffd = "\u{fffd}";
        let input = "a\n\t\r\u{1b}b\u{1}c\u{7f}d\u{e9}e";
        let want = format!("a\\n\\t\\r{fffd}b{fffd}c{fffd}d\u{e9}e");
        assert_eq!(escape_text(input), want);
    }

    #[test]
    fn escape_text_clean_passthrough() {
        assert_eq!(escape_text("plain-1.5 ok"), "plain-1.5 ok");
        assert_eq!(escape_text("café ☺"), "café ☺");
        assert_eq!(escape_text("<b>x</b>"), "<b>x</b>");
    }

    #[test]
    fn golden_text_attempts() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-attempts.txt")
        );
    }

    #[test]
    fn golden_text_escape() {
        let rep = analyze_fixture("tests/fixtures/reader/escape");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-escape.txt")
        );
    }

    #[test]
    fn golden_text_lifecycle_nested() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/lifecycle-nested");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-lifecycle-nested.txt")
        );
    }

    #[test]
    fn golden_text_copy_before_failure() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/copy-before-failure");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-copy-before-failure.txt")
        );
    }

    #[test]
    fn golden_text_pool_pressure() {
        let rep = analyze_fixture("tests/fixtures/pools/pressure");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-pool-pressure.txt")
        );
    }

    #[test]
    fn golden_text_region_union() {
        let rep = analyze_fixture("tests/fixtures/regions/region-union");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-region-union.txt")
        );
    }

    #[test]
    fn golden_text_gen_lineage() {
        let rep = analyze_fixture("tests/fixtures/regions/gen-lineage");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-gen-lineage.txt")
        );
    }

    #[test]
    fn golden_text_conversion_uncertain() {
        let rep = analyze_fixture("tests/fixtures/regions/conversion-uncertain");
        assert_eq!(
            render_text(&rep, ""),
            golden("tests/golden/report-conversion-uncertain.txt")
        );
    }

    fn capabilities_probe() -> Report {
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
        rep
    }

    #[test]
    fn capabilities_matrix_text() {
        let text = render_text(&capabilities_probe(), "");
        assert!(text.contains(
            "capabilities:\n  bounce_attempts: partial [local-auto] - capture ok\n  mapping_lifecycle: unavailable - no source\n"
        ));
    }

    #[test]
    fn verdict_line_shapes() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            verdict_line(&rep),
            "verdict: partial_unknown_loss (loss >=0.00%, 3 delivered)"
        );
        let gap = analyze_fixture("tests/fixtures/reader/detail-gap");
        assert_eq!(
            verdict_line(&gap),
            "verdict: partial_unknown_loss (loss >=50.00%, 2 delivered)"
        );
        let done = analyze_fixture("tests/fixtures/reader/complete-stop");
        assert_eq!(
            verdict_line(&done),
            "verdict: partial_unknown_loss (loss >=0.00%, 3 delivered)"
        );
        let unset = Report::default();
        assert_eq!(verdict_line(&unset), "verdict: unavailable (not computed)");
    }

    #[test]
    fn render_text_verdict_header() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let doc = render_text(&rep, "");
        assert!(doc.starts_with(
            "summary: attempts 3, requested bytes 9 KiB (9216 bytes) in 3.00 s\nsummary devices: dev-1 (testdev0): attempts 3, requested bytes 9 KiB (9216 bytes)\nsummary pool: used unavailable of unavailable capacity\nsummary scope: proves bounce attempts were counted; does not prove bytes were copied or DMA succeeded\nverdict: partial_unknown_loss (loss >=0.00%, 3 delivered)\nintegrity: legacy_unverified (verified bytes=0, events=0); arithmetic is unverified; completeness withheld\nmemveil report "
        ));
    }

    #[test]
    fn render_compact_attempts() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        assert_eq!(
            render_compact(&rep),
            "verdict: partial_unknown_loss (loss >=0.00%, 3 delivered)\nintegrity: legacy_unverified (verified bytes=0, events=0); arithmetic is unverified; completeness withheld\nattempts: 3  requested bytes: 9216\ndetail: partial, loss 0\nterminal: partial\nfindings: none\n"
        );
    }

    #[test]
    fn render_compact_detail_gap() {
        let rep = analyze_fixture("tests/fixtures/reader/detail-gap");
        assert_eq!(
            render_compact(&rep),
            "verdict: partial_unknown_loss (loss >=50.00%, 2 delivered)\nintegrity: legacy_unverified (verified bytes=0, events=0); arithmetic is unverified; completeness withheld\nattempts: 2  requested bytes: 5120\ndetail: partial, loss 2\nterminal: partial\nfindings: 1: CAPTURE_INCOMPLETE(warning)\n"
        );
    }

    fn identity_probe() -> Report {
        let mut rep = Report {
            session_id: "idprobe".to_string(),
            synthetic: true,
            engine_version: crate::ENGINE_VERSION.to_string(),
            window_start_ns: 100,
            window_end_ns: 200,
            ..Report::default()
        };
        rep.env.mode = "unknown".to_string();
        rep.env.detection = "unverified".to_string();
        rep.env.attestation = "not_performed".to_string();
        rep.devices.push(DeviceEntry {
            device_id: "d9".to_string(),
            name: "eth9".to_string(),
            identity_status: "unresolved".to_string(),
            ..DeviceEntry::default()
        });
        rep
    }

    #[test]
    fn render_missing_identity_text() {
        let text = render_text(&identity_probe(), "");
        assert!(text.contains("identity=unresolved"));
        assert!(text.contains("driver=none"));
    }

    #[test]
    fn device_name_filter_resolves_text() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let by_name = render_text(&rep, "testdev0");
        let by_id = render_text(&rep, "dev-1");
        assert_eq!(by_name, by_id);
        assert!(by_name.contains("{device=dev-1}"));
        let unknown = render_text(&rep, "nope");
        assert!(!unknown.contains("{device="));
    }

    #[test]
    fn unfinalized_stream_presentation() {
        let mut rep = analyze_fixture("tests/fixtures/reader/complete-stop");
        rep.integrity_context = "live stream".to_string();
        let text = render_compact(&rep);
        assert!(text.contains("integrity: unverified live stream"));
        assert!(!text.contains("legacy_unverified"));
        assert!(!text.contains("checkpoint_prefix"));
        assert!(!text.contains("complete_for_scope"));
        rep.integrity_context = "replay prefix".to_string();
        assert!(render_text(&rep, "").contains("integrity: unverified replay prefix"));
    }

    #[test]
    fn human_bytes_shapes() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(900), "900 bytes");
        assert_eq!(human_bytes(1023), "1023 bytes");
        assert_eq!(human_bytes(1024), "1 KiB (1024 bytes)");
        assert_eq!(human_bytes(1536), "1.5 KiB (1536 bytes)");
        assert_eq!(human_bytes(9216), "9 KiB (9216 bytes)");
        assert_eq!(human_bytes(67108864), "64 MiB (67108864 bytes)");
        assert_eq!(human_bytes(1048575), "1024.0 KiB (1048575 bytes)");
        assert_eq!(
            human_bytes(18446744073709551615),
            "16.0 EiB (18446744073709551615 bytes)"
        );
    }

    #[test]
    fn human_seconds_shapes() {
        assert_eq!(human_seconds(0), "0.00 s");
        assert_eq!(human_seconds(7), "0.00 s");
        assert_eq!(human_seconds(3_000_000_000), "3.00 s");
        assert_eq!(human_seconds(10_030_000_000), "10.03 s");
        assert_eq!(human_seconds(999_999_999_999), "1000.00 s");
        assert_eq!(human_seconds(u64::MAX), "18446744073.71 s");
    }

    fn valued_metric(name: &str, value: u64) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: true,
            value,
            ..Metric::default()
        }
    }

    fn scoped_metric(name: &str, value: u64, device_id: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: true,
            value,
            has_device_id: true,
            device_id: device_id.to_string(),
            ..Metric::default()
        }
    }

    fn pooled_metric(name: &str, value: u64, pool_id: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: true,
            value,
            has_pool_id: true,
            pool_id: pool_id.to_string(),
            ..Metric::default()
        }
    }

    #[test]
    fn summary_copies_line_needs_a_measured_copy() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/copy-before-failure");
        let lines = summary_lines(&rep, escape_text);
        assert_eq!(lines.len(), 5);
        // A measured zero is a value, not an unknown.
        assert_eq!(
            lines[2],
            "summary copies: original-to-bounce 4 KiB (4096 bytes), bounce-to-original 0 bytes"
        );
        assert_eq!(
            lines[4],
            "summary scope: proves bounce attempts were counted and executed copies were observed; does not prove DMA success"
        );
        let plain = analyze_fixture("tests/fixtures/attempts");
        let lines = summary_lines(&plain, escape_text);
        assert_eq!(lines.len(), 4);
        assert!(lines.iter().all(|l| !l.starts_with("summary copies:")));
    }

    #[test]
    fn summary_pool_sums_measured_pool_rows() {
        let rep = analyze_fixture("tests/fixtures/pools/pressure");
        let lines = summary_lines(&rep, escape_text);
        assert!(lines.contains(&"summary pool: used 900 bytes of 1000 bytes capacity".to_string()));
        let mut two = Report::default();
        two.metrics
            .push(pooled_metric("pool_used_bytes", 100, "pool-0"));
        two.metrics
            .push(pooled_metric("pool_capacity_bytes", 1000, "pool-0"));
        two.metrics
            .push(pooled_metric("pool_used_bytes", 50, "pool-1"));
        two.metrics
            .push(pooled_metric("pool_capacity_bytes", 500, "pool-1"));
        let lines = summary_lines(&two, escape_text);
        assert!(lines.contains(
            &"summary pool: used 150 bytes of 1.5 KiB (1500 bytes) capacity".to_string()
        ));
        let mut half = Report::default();
        half.metrics
            .push(pooled_metric("pool_used_bytes", 100, "pool-0"));
        let lines = summary_lines(&half, escape_text);
        assert!(
            lines.contains(&"summary pool: used 100 bytes of unavailable capacity".to_string())
        );
    }

    #[test]
    fn summary_scope_matrix() {
        let mut both = Report::default();
        both.metrics.push(valued_metric("bounce_attempts", 2));
        both.metrics
            .push(valued_metric("copy_original_to_bounce_bytes", 64));
        let lines = summary_lines(&both, escape_text);
        assert_eq!(
            lines[lines.len() - 1],
            "summary scope: proves bounce attempts were counted and executed copies were observed; does not prove DMA success"
        );
        let mut copies_only = Report::default();
        copies_only
            .metrics
            .push(valued_metric("copy_original_to_bounce_bytes", 64));
        let lines = summary_lines(&copies_only, escape_text);
        assert_eq!(
            lines[0],
            "summary: attempts withheld, requested bytes withheld in 0.00 s"
        );
        assert_eq!(
            lines[lines.len() - 1],
            "summary scope: proves executed copies were observed (attempts uncounted); does not prove DMA success"
        );
        let lines = summary_lines(&Report::default(), escape_text);
        assert_eq!(
            lines[lines.len() - 1],
            "summary scope: proves nothing (attempts uncounted); does not prove bouncing occurred, bytes moved, or DMA ran"
        );
    }

    #[test]
    fn summary_devices_cover_every_catalog_entry() {
        let mut rep = Report {
            window_start_ns: 0,
            window_end_ns: 10_030_000_000,
            ..Report::default()
        };
        rep.metrics.push(valued_metric("bounce_attempts", 3));
        rep.metrics
            .push(valued_metric("requested_bounce_bytes", 67108864));
        for (id, name) in [("d1", "eth0"), ("d2", "eth1")] {
            rep.devices.push(DeviceEntry {
                device_id: id.to_string(),
                name: name.to_string(),
                ..DeviceEntry::default()
            });
        }
        rep.metrics.push(scoped_metric("bounce_attempts", 3, "d1"));
        rep.metrics
            .push(scoped_metric("requested_bounce_bytes", 67108864, "d1"));
        let lines = summary_lines(&rep, escape_text);
        assert_eq!(
            lines[0],
            "summary: attempts 3, requested bytes 64 MiB (67108864 bytes) in 10.03 s"
        );
        assert_eq!(
            lines[1],
            "summary devices: d1 (eth0): attempts 3, requested bytes 64 MiB (67108864 bytes); d2 (eth1): attempts unavailable, requested bytes unavailable"
        );
        let bare = summary_lines(&Report::default(), escape_text);
        assert_eq!(bare[1], "summary devices: none recorded");
    }

    #[test]
    fn summary_escapes_hostile_device_text() {
        let mut rep = Report::default();
        rep.devices.push(DeviceEntry {
            device_id: "d1".to_string(),
            name: "a\nb|c\x1bd".to_string(),
            ..DeviceEntry::default()
        });
        let lines = summary_lines(&rep, escape_text);
        assert_eq!(
            lines[1],
            "summary devices: d1 (a\\nb|c�d): attempts unavailable, requested bytes unavailable"
        );
        assert!(!lines[1].contains('\x1b'));
        assert!(!lines[1].contains('\n'));
    }

    #[test]
    fn summary_marks_an_inverted_window() {
        let rep = Report {
            window_start_ns: 200,
            window_end_ns: 100,
            ..Report::default()
        };
        let lines = summary_lines(&rep, escape_text);
        assert_eq!(
            lines[0],
            "summary: attempts withheld, requested bytes withheld (window unavailable: invalid recorded window)"
        );
    }

    #[test]
    fn attested_capture_marks_attestation_unverified() {
        let rep = analyze_fixture("tests/fixtures/reader/attested-external");
        let doc = render_text(&rep, "");
        assert!(doc.contains("attestation=external_verified (recorded, not verified by memveil)"));
        assert!(!doc.contains("attestation=external_verified evidence="));
        // Machine data keeps the bare recorded value.
        let json = super::super::json::render_json(&rep, "");
        assert!(json.contains("\"attestation\": \"external_verified\""));
        assert!(!json.contains("recorded, not verified"));
    }

    #[test]
    fn summary_ignores_the_display_filter() {
        let rep = analyze_fixture("tests/fixtures/attempts");
        let filtered = render_text(&rep, "nope");
        assert!(filtered.contains(
            "summary devices: dev-1 (testdev0): attempts 3, requested bytes 9 KiB (9216 bytes)"
        ));
        assert!(!filtered.contains("{device="));
    }
}
