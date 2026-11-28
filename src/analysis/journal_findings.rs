// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal findings: native failures and incomplete coverage.
//!
//! Exactly two finding codes exist here. `CONVERSION_FAILED` marks one
//! admitted request whose native wrapper failed; the resulting state
//! stays unknown. `CAPTURE_INCOMPLETE` marks finalized evidence whose
//! Detail channel is not complete for its scope. There is no generic
//! leak finding, no expected-revert finding, and no caller finding:
//! unknown callers are never leak findings.

use crate::model::metric::Finding;
use crate::model::report::incomplete_finding_severity;
use crate::model::session::Session;

/// Scope carried by every journal finding.
pub const JOURNAL_FINDING_SCOPE: &str = "global conversion journal";
/// Explanation carried by every native-failure finding.
pub const CONVERSION_FAILED_EXPLANATION: &str =
    "Observed native wrapper failure; resulting state unknown.";
/// Limitations carried by native-failure findings over synthetic evidence.
pub const CONVERSION_FAILED_SYNTHETIC_LIMITATIONS: &str = "Synthetic request-only fixture.";
/// Limitations carried by native-failure findings over live evidence.
pub const CONVERSION_FAILED_LIVE_LIMITATIONS: &str =
    "Request-only conversion evidence; no region identity.";
/// Limitations carried by the incomplete-coverage finding.
pub const CAPTURE_INCOMPLETE_LIMITATIONS: &str = "Counts exclude missing evidence. Terminal completeness requires a proven settlement protocol; repeating a capture does not by itself establish settlement.";

/// Derive journal findings for one reduction.
///
/// One `CONVERSION_FAILED` per failed admitted request, each linked to
/// its `event:N` evidence ref, plus at most one `CAPTURE_INCOMPLETE`
/// when finalized evidence leaves the Detail channel incomplete. A
/// checkpoint prefix explains its own partial Detail, so it never
/// adds the incomplete-coverage finding.
pub fn journal_findings(
    failed_refs: &[String],
    session: &Session,
    verdict_name: &str,
    loss_ratio_bps: i64,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let limitations = if session.synthetic {
        CONVERSION_FAILED_SYNTHETIC_LIMITATIONS
    } else {
        CONVERSION_FAILED_LIVE_LIMITATIONS
    };
    for reference in failed_refs {
        out.push(Finding {
            code: "CONVERSION_FAILED".to_string(),
            severity: "warning".to_string(),
            explanation: CONVERSION_FAILED_EXPLANATION.to_string(),
            evidence_refs: vec![reference.clone()],
            scope: JOURNAL_FINDING_SCOPE.to_string(),
            limitations: limitations.to_string(),
        });
    }
    if session.finalized && session.q_detail.status != "complete_for_scope" {
        let mut expl = format!(
            "Capture incomplete: Detail evidence incomplete: {}.",
            session.q_detail.reason
        );
        if expl.chars().count() > 1024 {
            let prefix: String = expl.chars().take(1021).collect();
            expl = format!("{prefix}...");
        }
        out.push(Finding {
            code: "CAPTURE_INCOMPLETE".to_string(),
            severity: incomplete_finding_severity(verdict_name, loss_ratio_bps),
            explanation: expl,
            evidence_refs: vec!["channel:detail".to_string()],
            scope: JOURNAL_FINDING_SCOPE.to_string(),
            limitations: CAPTURE_INCOMPLETE_LIMITATIONS.to_string(),
        });
    }
    out
}
