// SPDX-License-Identifier: GPL-3.0-or-later
//! Evidence-linked diagnosis over finished reports.
//!
//! The engine reads quality channels and metric rows and emits
//! findings with stable codes, each referencing the evidence it
//! explains. It never duplicates a code the report already
//! carries, never scores security, and never turns an open
//! allocation into a leak verdict: the long-lived policy is
//! informational and disabled unless configured.

use super::attempts::window_label;
use crate::model::metric::{Finding, Metric};
use crate::model::report::Report;
use crate::model::validate::format_u64;

/// Diagnosis inputs: long-lived threshold plus requested scope.
#[derive(Debug, Clone, Default)]
pub struct DiagnosticPolicy {
    /// True when a long-lived threshold was configured.
    pub has_long_lived_after: bool,
    /// Long-lived age threshold in nanoseconds.
    pub long_lived_after_ns: u64,
    /// Requested evidence scopes.
    pub requested: Vec<String>,
}

fn has_code(findings: &[Finding], code: &str) -> bool {
    findings.iter().any(|f| f.code == code)
}

fn valued_metric<'a>(metrics: &'a [Metric], name: &str, pool: &str) -> Option<&'a Metric> {
    metrics.iter().find(|m| {
        if m.name != name || !m.has_value {
            return false;
        }
        if pool.is_empty() {
            !m.has_pool_id
        } else {
            m.has_pool_id && m.pool_id == pool
        }
    })
}

fn any_valued(metrics: &[Metric], name: &str) -> bool {
    metrics.iter().any(|m| m.name == name && m.has_value)
}

fn row_notes(metrics: &[Metric], name: &str) -> String {
    // Notes of the first row with this name, valued or not.
    for m in metrics {
        if m.name == name && !m.has_device_id && !m.has_pool_id {
            return m.notes.clone();
        }
    }
    "no oldest_open_mapping_age_ns row".to_string()
}

/// Append derived findings to a finished report.
pub fn diagnose_report(rep: &mut Report, has_long_lived_after: bool, long_lived_after_ns: u64) {
    let mut policy = DiagnosticPolicy::default();
    if has_long_lived_after {
        policy.has_long_lived_after = true;
        policy.long_lived_after_ns = long_lived_after_ns;
    }
    let eng = DiagnosisEngine::new();
    let extra = eng.evaluate(rep, &policy);
    rep.findings.extend(extra);
}

/// Stateless finding derivation over one report.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiagnosisEngine;

impl DiagnosisEngine {
    /// Stateless engine.
    pub fn new() -> Self {
        DiagnosisEngine
    }

    /// Derive findings; never duplicate existing codes.
    pub fn evaluate(&self, report: &Report, policy: &DiagnosticPolicy) -> Vec<Finding> {
        let mut out = Vec::new();
        let window = window_label(report.window_start_ns, report.window_end_ns);
        if !has_code(&report.findings, "PROBE_UNAVAILABLE") {
            self.probe(report, &window, &mut out);
        }
        if !has_code(&report.findings, "UNPAIRED_LIFECYCLE") {
            self.unpaired(report, &window, &mut out);
        }
        if !has_code(&report.findings, "CONVERSION_FAILED") {
            self.conversion(report, &window, &mut out);
        }
        if !has_code(&report.findings, "POOL_PRESSURE") {
            self.pressure(report, &window, &mut out);
        }
        if !has_code(&report.findings, "LONG_LIVED_ALLOCATION")
            && !has_code(&report.findings, "LONG_LIVED_NOT_EVALUATED")
        {
            self.long_lived(report, policy, &window, &mut out);
        }
        if !has_code(&report.findings, "PROBE_UNAVAILABLE") {
            self.requested(report, policy, &window, &mut out);
        }
        out
    }

    fn probe(&self, report: &Report, window: &str, out: &mut Vec<Finding>) {
        // Only the detail channel reflects the event probe. The
        // aggregate channel is an optional counter cross-check:
        // its absence never constitutes a probe outage.
        if report.q_detail.status != "unavailable" {
            return;
        }
        let mut expl = format!("Detail probe unavailable: {}", report.q_detail.reason);
        if expl.as_bytes().last() != Some(&0x2E) {
            expl.push('.');
        }
        let mut f = Finding {
            code: "PROBE_UNAVAILABLE".to_string(),
            severity: "warning".to_string(),
            explanation: expl,
            scope: window.to_string(),
            limitations:
                "The detail channel carries no measurements; rerun with the probe attached."
                    .to_string(),
            ..Default::default()
        };
        for r in report.q_detail.evidence_refs.iter().take(32) {
            f.evidence_refs.push(r.clone());
        }
        out.push(f);
    }

    fn unpaired(&self, report: &Report, window: &str, out: &mut Vec<Finding>) {
        // The finding derives from the observed unpaired-event
        // row, never from channel loss: producer-claimed or
        // gap-derived correlation loss without pairing evidence
        // must not invent lifecycle exclusions.
        let row = valued_metric(&report.metrics, "unpaired_lifecycle_events", "");
        let Some(row) = row else {
            return;
        };
        if row.value == 0 {
            return;
        }
        out.push(Finding {
            code: "UNPAIRED_LIFECYCLE".to_string(),
            severity: "warning".to_string(),
            explanation: format!(
                "{} lifecycle events could not be paired and were excluded from pairing-dependent totals; independent facts retained.",
                format_u64(row.value)
            ),
            evidence_refs: vec!["metric:unpaired_lifecycle_events".to_string()],
            scope: window.to_string(),
            limitations: "Affected totals degrade; raw pairing detail stays out of the report."
                .to_string(),
        });
    }

    fn conversion(&self, report: &Report, window: &str, out: &mut Vec<Finding>) {
        let row = valued_metric(&report.metrics, "conversion_failures", "");
        let Some(row) = row else {
            return;
        };
        if row.value == 0 {
            return;
        }
        out.push(Finding {
            code: "CONVERSION_FAILED".to_string(),
            severity: "warning".to_string(),
            explanation: format!(
                "{} observed conversion requests failed; affected region state is invalid.",
                format_u64(row.value)
            ),
            evidence_refs: vec!["metric:conversion_failures".to_string()],
            scope: window.to_string(),
            limitations: "Failures invalidate state; they prove nothing about other regions."
                .to_string(),
        });
    }

    fn pressure(&self, report: &Report, window: &str, out: &mut Vec<Finding>) {
        for m in &report.metrics {
            if m.name != "pool_pressure_samples" || !m.has_value {
                continue;
            }
            if m.value < 3 || !m.has_pool_id {
                continue;
            }
            // Measured allocator states are notes, not alarms:
            // pressure never gated the exit and never will.
            out.push(Finding {
                code: "POOL_PRESSURE".to_string(),
                severity: "informational".to_string(),
                explanation: format!(
                    "Pool {} at or above 90% for {} consecutive valid samples.",
                    m.pool_id,
                    format_u64(m.value)
                ),
                evidence_refs: vec![
                    "metric:pool_pressure_samples".to_string(),
                    format!("pool:{}", m.pool_id),
                ],
                scope: format!("{window}; pool {}", m.pool_id),
                limitations: "Pressure is a measured allocator state, not a defect verdict."
                    .to_string(),
            });
        }
    }

    fn long_lived(
        &self,
        report: &Report,
        policy: &DiagnosticPolicy,
        window: &str,
        out: &mut Vec<Finding>,
    ) {
        if !policy.has_long_lived_after {
            return;
        }
        let row = valued_metric(&report.metrics, "oldest_open_mapping_age_ns", "");
        let Some(row) = row else {
            self.long_lived_unknown(report, policy, window, out);
            return;
        };
        if row.value < policy.long_lived_after_ns {
            return;
        }
        out.push(Finding {
            code: "LONG_LIVED_ALLOCATION".to_string(),
            severity: "informational".to_string(),
            explanation: format!(
                "Oldest open mapping is {} ns old, past the configured {} ns threshold.",
                format_u64(row.value),
                format_u64(policy.long_lived_after_ns)
            ),
            evidence_refs: vec!["metric:oldest_open_mapping_age_ns".to_string()],
            scope: window.to_string(),
            limitations: "Open is not a leak; the mapping may still be in legitimate use."
                .to_string(),
        });
    }

    fn long_lived_unknown(
        &self,
        report: &Report,
        _policy: &DiagnosticPolicy,
        window: &str,
        out: &mut Vec<Finding>,
    ) {
        // The threshold was configured but the age input is
        // missing: say so explicitly instead of vanishing.
        // The missing row's notes name the cause.
        let why = row_notes(&report.metrics, "oldest_open_mapping_age_ns");
        out.push(Finding {
            code: "LONG_LIVED_NOT_EVALUATED".to_string(),
            severity: "informational".to_string(),
            explanation: format!(
                "Long-lived check not evaluated: age input unavailable ({why})."
            ),
            evidence_refs: vec!["metric:oldest_open_mapping_age_ns".to_string()],
            scope: window.to_string(),
            limitations:
                "No long-lived verdict either way; rerun with the mapping state that produced the age row."
                    .to_string(),
        });
    }

    fn requested(
        &self,
        report: &Report,
        policy: &DiagnosticPolicy,
        window: &str,
        out: &mut Vec<Finding>,
    ) {
        for want in &policy.requested {
            if want == "lifecycle" && !any_valued(&report.metrics, "successful_allocations") {
                Self::requested_finding("lifecycle", window, out);
            } else if want == "pools" && !any_valued(&report.metrics, "pool_used_bytes") {
                Self::requested_finding("pools", window, out);
            }
            if has_code(out, "PROBE_UNAVAILABLE") {
                return;
            }
        }
    }

    fn requested_finding(scope: &str, window: &str, out: &mut Vec<Finding>) {
        out.push(Finding {
            code: "PROBE_UNAVAILABLE".to_string(),
            severity: "warning".to_string(),
            explanation: format!("Requested {scope} scope has no evidence in this capture."),
            scope: window.to_string(),
            limitations: "Rerun with the requested scope observable.".to_string(),
            ..Default::default()
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::metric::{Finding, Metric};
    use crate::model::report::Report;

    fn channel(status: &str) -> crate::model::session::Channel {
        crate::model::session::Channel {
            status: status.to_string(),
            scope: "sc".to_string(),
            reason: "rs".to_string(),
            ..Default::default()
        }
    }

    fn report() -> Report {
        Report {
            session_id: "d1".to_string(),
            synthetic: true,
            window_start_ns: 0,
            window_end_ns: 1000,
            q_detail: channel("complete_for_scope"),
            q_aggregate: channel("complete_for_scope"),
            q_correlation: channel("not_applicable"),
            q_baseline: channel("not_applicable"),
            q_terminal: channel("complete_for_scope"),
            ..Default::default()
        }
    }

    fn metric(name: &str, value: u64, pool: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: true,
            value,
            unit: "count".to_string(),
            measurement: "observed".to_string(),
            coverage: "complete_for_scope".to_string(),
            has_pool_id: !pool.is_empty(),
            pool_id: pool.to_string(),
            scope: "window [0,1000)".to_string(),
            ..Default::default()
        }
    }

    fn missing_metric(name: &str, notes: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: false,
            unit: "nanoseconds".to_string(),
            measurement: "unavailable".to_string(),
            coverage: "unavailable".to_string(),
            scope: "window [0,1000)".to_string(),
            notes: notes.to_string(),
            ..Default::default()
        }
    }

    fn codes(findings: &[Finding], code: &str) -> usize {
        findings.iter().filter(|f| f.code == code).count()
    }

    #[test]
    fn healthy_empty_scope() {
        let eng = DiagnosisEngine::new();
        let out = eng.evaluate(&report(), &DiagnosticPolicy::default());
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn unavailable_probe() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.q_detail.status = "unavailable".to_string();
        r.q_detail.reason = "tracepoint missing".to_string();
        r.q_detail
            .evidence_refs
            .push("hook:swiotlb_bounced".to_string());
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, "PROBE_UNAVAILABLE");
        assert_eq!(out[0].severity, "warning");
        assert_eq!(out[0].evidence_refs.len(), 1);
    }

    #[test]
    fn unpaired_lifecycle() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.metrics.push(metric("unpaired_lifecycle_events", 2, ""));
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].code, "UNPAIRED_LIFECYCLE");
        assert_eq!(out[0].severity, "warning");
    }

    #[test]
    fn correlation_loss_alone_yields_no_lifecycle_finding() {
        // Optional correlation loss without observed unpaired
        // lifecycle events must not invent a lifecycle finding: an
        // attempts-only capture with producer-claimed correlation
        // loss keeps its sufficient-evidence verdict.
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.q_correlation.status = "partial".to_string();
        r.q_correlation.has_loss_count = true;
        r.q_correlation.loss_count = 2;
        r.q_correlation.reason = "optional correlation loss".to_string();
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(codes(&out, "UNPAIRED_LIFECYCLE"), 0);
    }

    #[test]
    fn no_duplicate_codes() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.q_detail.status = "unavailable".to_string();
        r.q_detail.reason = "gone".to_string();
        r.findings.push(Finding {
            code: "PROBE_UNAVAILABLE".to_string(),
            severity: "warning".to_string(),
            explanation: "already reported".to_string(),
            scope: "sc".to_string(),
            ..Default::default()
        });
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(out.len(), 0);
    }

    #[test]
    fn long_lived_disabled_by_default() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.metrics
            .push(metric("oldest_open_mapping_age_ns", 900, ""));
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(codes(&out, "LONG_LIVED_ALLOCATION"), 0);
    }

    #[test]
    fn long_lived_threshold() {
        let eng = DiagnosisEngine::new();
        let p = DiagnosticPolicy {
            has_long_lived_after: true,
            long_lived_after_ns: 500,
            ..Default::default()
        };
        let mut r = report();
        r.metrics
            .push(metric("oldest_open_mapping_age_ns", 900, ""));
        let out = eng.evaluate(&r, &p);
        assert_eq!(codes(&out, "LONG_LIVED_ALLOCATION"), 1);
        assert_eq!(out[0].severity, "informational");
        let mut r2 = report();
        r2.metrics
            .push(metric("oldest_open_mapping_age_ns", 100, ""));
        let out2 = eng.evaluate(&r2, &p);
        assert_eq!(codes(&out2, "LONG_LIVED_ALLOCATION"), 0);
    }

    #[test]
    fn long_lived_not_evaluated() {
        let eng = DiagnosisEngine::new();
        let p = DiagnosticPolicy {
            has_long_lived_after: true,
            long_lived_after_ns: 500,
            ..Default::default()
        };
        let mut r = report();
        r.metrics.push(missing_metric(
            "oldest_open_mapping_age_ns",
            "Release without open mapping; age withheld.",
        ));
        let out = eng.evaluate(&r, &p);
        assert_eq!(codes(&out, "LONG_LIVED_NOT_EVALUATED"), 1);
        assert_eq!(codes(&out, "LONG_LIVED_ALLOCATION"), 0);
        assert_eq!(out[0].severity, "informational");
        assert!(
            out[0].explanation.contains("not evaluated"),
            "{}",
            out[0].explanation
        );
        assert!(
            out[0].explanation.contains("Release without open mapping"),
            "{}",
            out[0].explanation
        );
        assert_eq!(out[0].evidence_refs.len(), 1);
        assert_eq!(out[0].evidence_refs[0], "metric:oldest_open_mapping_age_ns");
        // Disabled policy stays silent even with the age missing.
        let mut r2 = report();
        r2.metrics
            .push(missing_metric("oldest_open_mapping_age_ns", "withheld"));
        let out2 = eng.evaluate(&r2, &DiagnosticPolicy::default());
        assert_eq!(codes(&out2, "LONG_LIVED_NOT_EVALUATED"), 0);
        // A valued row below threshold stays silent too: evaluated,
        // not missing.
        let mut r3 = report();
        r3.metrics
            .push(metric("oldest_open_mapping_age_ns", 100, ""));
        let out3 = eng.evaluate(&r3, &p);
        assert_eq!(codes(&out3, "LONG_LIVED_NOT_EVALUATED"), 0);
    }

    #[test]
    fn pool_pressure() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.metrics.push(metric("pool_pressure_samples", 3, "p1"));
        r.metrics.push(metric("pool_pressure_samples", 2, "p2"));
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(codes(&out, "POOL_PRESSURE"), 1);
        assert_eq!(out[0].severity, "informational");
        assert!(out[0].scope.contains("p1"));
    }

    #[test]
    fn conversion_failures() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.metrics.push(metric("conversion_failures", 1, ""));
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(codes(&out, "CONVERSION_FAILED"), 1);
    }

    #[test]
    fn requested_scope_missing() {
        let eng = DiagnosisEngine::new();
        let p = DiagnosticPolicy {
            requested: vec!["lifecycle".to_string()],
            ..Default::default()
        };
        let out = eng.evaluate(&report(), &p);
        assert_eq!(codes(&out, "PROBE_UNAVAILABLE"), 1);
    }

    #[test]
    fn requested_pools_scope_missing() {
        let eng = DiagnosisEngine::new();
        let p = DiagnosticPolicy {
            requested: vec!["pools".to_string()],
            ..Default::default()
        };
        let out = eng.evaluate(&report(), &p);
        assert_eq!(codes(&out, "PROBE_UNAVAILABLE"), 1);
    }

    #[test]
    fn finding_evidence_refs_resolve() {
        // Every metric:/pool: ref a finding emits must resolve
        // against the diagnosed row set; budgeting must never
        // strand a finding without its evidence.
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.metrics.push(metric("unpaired_lifecycle_events", 1, ""));
        r.metrics.push(metric("conversion_failures", 1, ""));
        r.metrics.push(metric("pool_pressure_samples", 3, "p1"));
        let mut names = Vec::new();
        let mut pools = Vec::new();
        for m in &r.metrics {
            names.push(m.name.clone());
            if m.has_pool_id {
                pools.push(m.pool_id.clone());
            }
        }
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert_eq!(out.len(), 3);
        for f in &out {
            for r in &f.evidence_refs {
                let parts: Vec<&str> = r.split(':').collect();
                assert_eq!(parts.len(), 2);
                let found = if parts[0] == "metric" {
                    names.iter().any(|n| n == parts[1])
                } else if parts[0] == "pool" {
                    pools.iter().any(|p| p == parts[1])
                } else {
                    false
                };
                assert!(found, "unresolved ref {r}");
            }
        }
    }

    #[test]
    fn findings_bounded() {
        let eng = DiagnosisEngine::new();
        let mut r = report();
        r.q_detail.status = "unavailable".to_string();
        r.q_detail.reason = "tracepoint missing".to_string();
        r.q_detail
            .evidence_refs
            .push("hook:swiotlb_bounced".to_string());
        r.q_aggregate.status = "partial".to_string();
        r.q_aggregate.reason = "detail loss".to_string();
        r.q_correlation.status = "partial".to_string();
        r.q_correlation.reason = "unpaired".to_string();
        r.q_terminal.status = "partial".to_string();
        r.q_terminal.reason = "stop partial".to_string();
        let out = eng.evaluate(&r, &DiagnosticPolicy::default());
        assert!(out.len() <= 8);
    }

    #[test]
    fn diagnose_report_appends() {
        let mut r = report();
        r.q_detail.status = "unavailable".to_string();
        r.q_detail.reason = "tracepoint missing".to_string();
        diagnose_report(&mut r, false, 0);
        assert_eq!(r.findings.len(), 1);
        assert_eq!(r.findings[0].code, "PROBE_UNAVAILABLE");
    }
}
