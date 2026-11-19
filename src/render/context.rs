// SPDX-License-Identifier: GPL-3.0-or-later
//! Captured context only; these strings never admit the current host.

use crate::model::report::Report;
use crate::model::session::EvidenceItem;
use crate::model::validate::format_u64;

/// Keep conflicting captured interpretations explicit, before escaping.
pub fn recorded_value(evidence: &[EvidenceItem], source: &str) -> String {
    let mut values: Vec<&str> = Vec::new();
    for item in evidence {
        if item.item_type != "provenance" || item.source != source {
            continue;
        }
        if !values.contains(&item.interpretation.as_str()) {
            values.push(item.interpretation.as_str());
        }
    }
    if values.is_empty() {
        return "unavailable (no captured provenance)".to_string();
    }
    if values.len() == 1 {
        if values[0].is_empty() {
            return "unavailable (empty captured provenance)".to_string();
        }
        return values[0].to_string();
    }
    format!("conflicting captured values: {}", values.join("; "))
}

/// Exact seconds and nanoseconds, including a replay prefix window.
pub fn measured_duration(rep: &Report) -> String {
    if rep.window_end_ns < rep.window_start_ns {
        return "unavailable (invalid recorded window)".to_string();
    }
    let duration = rep.window_end_ns - rep.window_start_ns;
    let seconds = duration / 1_000_000_000;
    let remainder = duration % 1_000_000_000;
    let mut fraction = format_u64(remainder);
    while fraction.len() < 9 {
        fraction.insert(0, '0');
    }
    format!(
        "{}.{fraction} s ({} ns)",
        format_u64(seconds),
        format_u64(duration)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(source: &str, interpretation: &str) -> EvidenceItem {
        EvidenceItem {
            item_type: "provenance".to_string(),
            source: source.to_string(),
            interpretation: interpretation.to_string(),
        }
    }

    #[test]
    fn recorded_value_absent_reports_no_provenance() {
        assert_eq!(
            recorded_value(&[], "kernel.release"),
            "unavailable (no captured provenance)"
        );
        let other = vec![provenance("profile.decision", "x")];
        assert_eq!(
            recorded_value(&other, "kernel.release"),
            "unavailable (no captured provenance)"
        );
        let typed = vec![EvidenceItem {
            item_type: "counter".to_string(),
            source: "kernel.release".to_string(),
            interpretation: "x".to_string(),
        }];
        assert_eq!(
            recorded_value(&typed, "kernel.release"),
            "unavailable (no captured provenance)"
        );
    }

    #[test]
    fn recorded_value_single_and_empty() {
        let one = vec![provenance("kernel.release", "6.8.0")];
        assert_eq!(recorded_value(&one, "kernel.release"), "6.8.0");
        let blank = vec![provenance("kernel.release", "")];
        assert_eq!(
            recorded_value(&blank, "kernel.release"),
            "unavailable (empty captured provenance)"
        );
    }

    #[test]
    fn recorded_value_dedupes_and_flags_conflicts() {
        let dup = vec![
            provenance("kernel.release", "6.8.0"),
            provenance("kernel.release", "6.8.0"),
        ];
        assert_eq!(recorded_value(&dup, "kernel.release"), "6.8.0");
        let split = vec![
            provenance("kernel.release", "6.8.0"),
            provenance("kernel.release", "6.9.0"),
        ];
        assert_eq!(
            recorded_value(&split, "kernel.release"),
            "conflicting captured values: 6.8.0; 6.9.0"
        );
    }

    #[test]
    fn measured_duration_exact_seconds_and_nanos() {
        let rep = Report {
            window_start_ns: 1_000_000_000,
            window_end_ns: 4_000_000_000,
            ..Report::default()
        };
        assert_eq!(measured_duration(&rep), "3.000000000 s (3000000000 ns)");
    }

    #[test]
    fn measured_duration_pads_fraction_and_rejects_inversion() {
        let rep = Report {
            window_start_ns: 100,
            window_end_ns: 200,
            ..Report::default()
        };
        assert_eq!(measured_duration(&rep), "0.000000100 s (100 ns)");
        let bad = Report {
            window_start_ns: 200,
            window_end_ns: 100,
            ..Report::default()
        };
        assert_eq!(
            measured_duration(&bad),
            "unavailable (invalid recorded window)"
        );
    }
}
