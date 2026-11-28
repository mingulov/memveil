// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal request reducer: admitted counts, native failures,
//! censored operations, and explicit unavailable state totals.
//!
//! Pure offline reduction over validated journal events plus the session
//! journal block. Only tokened (admitted) results contribute to request
//! totals; tokenless exits count as unmatched; requested bytes sum
//! without decrypt/encrypt netting and go unavailable when any
//! admitted size is invalid or the sum overflows. Counters and detail
//! events stay alternative measurements: the reducer never compares,
//! nets, or totals them together. Shared bytes and unreverted ranges
//! are always unavailable with the request-only reason: a request-only
//! source establishes no region identity, baseline, or closure.

use super::journal_findings::journal_findings;
use super::journal_regions::JournalRegions;
use crate::ENGINE_VERSION;
use crate::model::event::Event;
use crate::model::report::{Report, ReportCap, ReportEnv, terminal_loss_leg, verdict_for_counts};
use crate::model::session::Session;
use std::collections::BTreeMap;

/// Request-only state reason: no region identity is established.
pub const JOURNAL_STATE_REASON: &str = "request_only_source";
/// Replay token-history budget: disjoint intervals across all epochs.
pub const JOURNAL_REPLAY_INTERVAL_BUDGET: usize = 65536;
/// Duplicate-token refusal reason.
pub const JOURNAL_DUPLICATE_TOKEN: &str = "duplicate operation token";
/// Mixed-evidence refusal reason: the journal reducer admits
/// journal `transition_result` lines only.
pub const JOURNAL_MIXED_EVIDENCE: &str =
    "unsupported mixed evidence: journal reduction admits transition_result only";
/// Token-history exhaustion reason: a resource refusal, never a
/// corruption claim.
pub const JOURNAL_TOKEN_RESOURCE_LIMIT: &str = "journal_token_resource_limit";
/// Stored failure-reference cap; the findings total stays within
/// the schema bound with the incomplete-coverage finding retained,
/// and failure counts stay exact past it.
pub const JOURNAL_MAX_FAILURE_REFS: usize = 2048;
/// Limitation carried on every journal report: request-only scope.
pub const JOURNAL_REQUEST_ONLY_LIMITATION: &str =
    "Synthetic request/results only; no persistent region identity, baseline or global closure.";
/// The four constant conversion-path exclusions on every journal report.
pub const JOURNAL_EXCLUSIONS: [&str; 4] = [
    "Boot and pre-attach conversions are excluded.",
    "MMIO conversions are excluded.",
    "Kexec and accept paths are excluded.",
    "Unobserved conversion paths are excluded.",
];

/// One journal reduction failure: duplicate token or spent history.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError {
    /// Human-readable failure message.
    pub message: String,
}

impl JournalError {
    /// A reduction failure with its message.
    pub fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for JournalError {}

/// Reduced conversion-request measurements with unavailable reasons.
///
/// `shared_bytes` and `unreverted_ranges` have no fields: they are always
/// unavailable under [`JOURNAL_STATE_REASON`], so renderers emit the
/// constant instead of reading state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalSummary {
    /// Admitted (tokened) conversion requests.
    pub requests: u64,
    /// Admitted requests whose native result is zero.
    pub successes: u64,
    /// Admitted requests whose native result is nonzero.
    pub failures: u64,
    /// Tokenless exits: lost entries, never requests.
    pub unmatched_exits: u64,
    /// Terminal censored count; `None` when unobservable.
    pub censored: Option<u64>,
    /// Null reason for censored; empty when known.
    pub censored_reason: String,
    /// Requested-byte sum; `None` when invalid or overflowed.
    pub requested_bytes: Option<u64>,
    /// Null reason for requested bytes; empty when known.
    pub requested_bytes_reason: String,
}

/// One finished journal reduction: report shell plus journal measurements.
#[derive(Debug, Clone)]
pub struct JournalReport {
    /// Report shell: provenance, quality echo, verdict, findings.
    pub report: Report,
    /// Conversion-request measurements.
    pub summary: JournalSummary,
    /// Synthetic offline region observation.
    pub regions: JournalRegions,
}

/// Incremental conversion-journal reducer over one session's events.
#[derive(Debug, Clone)]
pub struct JournalAnalyzer {
    session: Session,
    requests: u64,
    failures: u64,
    unmatched: u64,
    bytes: u64,
    bytes_reason: String,
    failed_refs: Vec<String>,
    tokens: BTreeMap<u64, BTreeMap<u64, u64>>,
    intervals: usize,
    regions: JournalRegions,
}

impl JournalAnalyzer {
    /// Empty reducer over one session's claims.
    pub fn new(session: Session) -> Self {
        Self {
            session,
            requests: 0,
            failures: 0,
            unmatched: 0,
            bytes: 0,
            bytes_reason: String::new(),
            failed_refs: Vec::new(),
            tokens: BTreeMap::new(),
            intervals: 0,
            regions: JournalRegions::new(),
        }
    }

    /// Fold one event into the request counts.
    ///
    /// Only journal-typed results participate. Any other 0.2.0 line
    /// (ordinary kinds, gaps) refuses as unsupported mixed evidence
    /// rather than dropping silently: a quiet drop would echo the
    /// session's `complete_for_scope` Detail while hiding observed
    /// loss, and gap accounting belongs to the ordinary reducer, not
    /// to an invented journal Detail adjustment here. A repeated
    /// nonzero token within one epoch refuses; a zero token
    /// (unmatched exit) needs no history. Callers never affect
    /// counts: unknown callers are not findings.
    pub fn consume(&mut self, ev: &Event) -> Result<(), JournalError> {
        if !ev.has_journal || !ev.journal_version {
            return Err(JournalError::new(JOURNAL_MIXED_EVIDENCE.to_string()));
        }
        self.regions.observe(ev);
        if !ev.journal.operation_token.has {
            self.unmatched += 1;
            return Ok(());
        }
        let token = ev.journal.operation_token.value;
        if token != 0 {
            self.claim_token(ev.journal.epoch, token)?;
        } else {
            self.unmatched += 1;
            return Ok(());
        }
        self.requests += 1;
        if ev.journal.native_result != 0 {
            self.failures += 1;
            if self.failed_refs.len() < JOURNAL_MAX_FAILURE_REFS {
                self.failed_refs.push(format!("event:{}", ev.seq));
            }
        }
        if self.bytes_reason == "invalid_native_pages" {
            return Ok(());
        }
        if !ev.journal.requested_bytes.has {
            self.bytes = 0;
            self.bytes_reason = "invalid_native_pages".to_string();
            return Ok(());
        }
        match self.bytes.checked_add(ev.journal.requested_bytes.value) {
            Some(sum) => self.bytes = sum,
            None => {
                self.bytes = 0;
                if self.bytes_reason.is_empty() {
                    self.bytes_reason = "overflow".to_string();
                }
            }
        }
        Ok(())
    }

    /// Claim one nonzero token for its epoch.
    ///
    /// History merges contiguous tokens into disjoint intervals and
    /// refuses past [`JOURNAL_REPLAY_INTERVAL_BUDGET`] disjoint
    /// intervals across all epochs; a repeat refuses as a duplicate.
    /// History is never forgotten within a reduction.
    fn claim_token(&mut self, epoch: u64, token: u64) -> Result<(), JournalError> {
        let spans = self.tokens.entry(epoch).or_default();
        let mut lo = token;
        let mut hi = token;
        let mut merged = 0usize;
        let mut drop_left: Option<u64> = None;
        let mut drop_right: Option<u64> = None;
        if let Some((&plo, &phi)) = spans.range(..=token).next_back() {
            if token <= phi {
                return Err(JournalError::new(JOURNAL_DUPLICATE_TOKEN.to_string()));
            }
            if phi.saturating_add(1) == token {
                lo = plo;
                drop_left = Some(plo);
                merged += 1;
            }
        }
        if let Some((&nlo, &nhi)) = spans.range(token..).next()
            && token.saturating_add(1) >= nlo
        {
            hi = nhi;
            drop_right = Some(nlo);
            merged += 1;
        }
        if let Some(key) = drop_left {
            spans.remove(&key);
        }
        if let Some(key) = drop_right {
            spans.remove(&key);
        }
        spans.insert(lo, hi);
        self.intervals = self.intervals + 1 - merged;
        if self.intervals > JOURNAL_REPLAY_INTERVAL_BUDGET {
            return Err(JournalError::new(JOURNAL_TOKEN_RESOURCE_LIMIT.to_string()));
        }
        Ok(())
    }

    /// Reduce the stream so far; the horizon may narrow.
    pub fn snapshot(&mut self, end_ns: u64, partial: bool) -> Result<JournalReport, JournalError> {
        Ok(self.assemble(end_ns, partial))
    }

    /// Reduce the whole capture; the horizon must match.
    pub fn finish(&mut self, end_ns: u64, partial: bool) -> Result<JournalReport, JournalError> {
        Ok(self.assemble(end_ns, partial))
    }

    /// Admitted request totals plus session terminal evidence.
    fn summary(&self) -> JournalSummary {
        let censored = &self.session.journal.counters[4];
        JournalSummary {
            requests: self.requests,
            successes: self.requests - self.failures,
            failures: self.failures,
            unmatched_exits: self.unmatched,
            censored: censored.has.then_some(censored.value),
            censored_reason: if censored.has {
                String::new()
            } else {
                self.session.journal.counter_reasons[4].clone()
            },
            requested_bytes: self.bytes_reason.is_empty().then_some(self.bytes),
            requested_bytes_reason: self.bytes_reason.clone(),
        }
    }

    fn echo_cap(out: &mut Report, name: &str, cap: &crate::model::session::Capability) {
        out.caps.push(ReportCap {
            name: name.to_string(),
            status: cap.status.clone(),
            has_grade: cap.has_grade,
            grade: cap.grade.clone(),
            reason: cap.reason.clone(),
        });
    }

    /// Build one reduction: counts, verbatim quality echo, verdict,
    /// findings, and the constant journal limitations.
    fn assemble(&self, end_ns: u64, _partial: bool) -> JournalReport {
        let summary = self.summary();
        let mut out = Report {
            session_id: self.session.session_id.clone(),
            synthetic: self.session.synthetic,
            engine_version: ENGINE_VERSION.to_string(),
            window_start_ns: self.session.window_start_ns,
            window_end_ns: end_ns,
            env: ReportEnv {
                mode: self.session.env_mode.clone(),
                detection: self.session.env_detection.clone(),
                has_asserted_mode: self.session.has_asserted_mode,
                asserted_mode: self.session.asserted_mode.clone(),
                asserted_mode_present: self.session.asserted_mode_present,
                attestation: self.session.env_attestation.clone(),
                evidence: self.session.evidence.clone(),
            },
            devices: self.session.devices.clone(),
            q_detail: self.session.q_detail.clone(),
            q_aggregate: self.session.q_aggregate.clone(),
            q_correlation: self.session.q_correlation.clone(),
            has_corr_relations: self.session.has_corr_relations,
            q_corr_mapping: self.session.q_corr_mapping.clone(),
            q_corr_copy: self.session.q_corr_copy.clone(),
            q_corr_sync: self.session.q_corr_sync.clone(),
            q_baseline: self.session.q_baseline.clone(),
            q_terminal: self.session.q_terminal.clone(),
            ..Report::default()
        };
        Self::echo_cap(
            &mut out,
            "bounce_attempts",
            &self.session.cap_bounce_attempts,
        );
        Self::echo_cap(
            &mut out,
            "mapping_lifecycle",
            &self.session.cap_mapping_lifecycle,
        );
        Self::echo_cap(&mut out, "copy_bytes", &self.session.cap_copy_bytes);
        Self::echo_cap(&mut out, "sync_requests", &self.session.cap_sync_requests);
        Self::echo_cap(
            &mut out,
            "conversion_results",
            &self.session.cap_conversion_results,
        );
        Self::echo_cap(&mut out, "region_state", &self.session.cap_region_state);
        Self::echo_cap(&mut out, "pool_stats", &self.session.cap_pool_stats);
        Self::echo_cap(&mut out, "task_context", &self.session.cap_task_context);
        // No counter/detail comparison is performed: counters and
        // detail events are alternative measurements, so the counters
        // leg is vacuously agreed and the verdict ranges over the
        // detail and terminal legs only. Mixed evidence refuses at
        // consume, so only journal-only reductions reach here and
        // delivered stays zero.
        let term = terminal_loss_leg(&self.session.q_terminal.status, &self.session.stop);
        out.verdict = verdict_for_counts(
            true,
            self.session.q_detail.has_loss_count,
            self.session.q_detail.loss_count,
            self.session.q_detail.status != "complete_for_scope",
            term.0,
            term.1,
            term.2,
            0,
        );
        let (findings, findings_truncated) = journal_findings(
            &self.failed_refs,
            self.failures,
            &self.session,
            &out.verdict.name,
            out.verdict.loss_ratio_bps,
        );
        out.findings = findings;
        out.limitations
            .push(JOURNAL_REQUEST_ONLY_LIMITATION.to_string());
        for exclusion in JOURNAL_EXCLUSIONS {
            out.limitations.push(exclusion.to_string());
        }
        if findings_truncated {
            let kept = out
                .findings
                .iter()
                .filter(|f| f.code == "CONVERSION_FAILED")
                .count();
            out.limitations.push(format!(
                "Failure evidence truncated: {kept} of {} failure references shown; journal.failures carries the exact count.",
                self.failures
            ));
        }
        JournalReport {
            report: out,
            summary,
            regions: self.regions.clone(),
        }
    }
}

/// Bind a checkpoint prefix, demoting any complete claim.
///
/// Mirrors the legacy checkpoint binder: every `complete_for_scope`
/// channel drops to `partial` with the checkpoint note prefixed, the
/// verdict forces to `partial_unknown_loss`, and metric coverages
/// demote (journal reports carry no metrics, so that leg is
/// vacuous). Channels already partial or unavailable keep their
/// reasons verbatim, so the frozen checkpoint oracles (all partial)
/// compare equal. The frozen report schema forbids
/// `complete_for_scope` under `checkpoint_prefix`, so echoing a
/// complete claim verbatim would emit schema-invalid output.
pub fn apply_journal_checkpoint(rep: &mut Report, bytes: u64, events: u64, suffix: u64) {
    const NOTE: &str = "Checkpoint prefix only; measurement window remains open; ";
    fn demote(channel: &mut crate::model::session::Channel) {
        if channel.status != "complete_for_scope" {
            return;
        }
        channel.status = "partial".to_string();
        let reason = core::mem::take(&mut channel.reason);
        channel.reason = NOTE.to_string();
        let keep = 1024usize.saturating_sub(NOTE.chars().count());
        for ch in reason.chars().take(keep) {
            channel.reason.push(ch);
        }
    }
    demote(&mut rep.q_detail);
    demote(&mut rep.q_aggregate);
    demote(&mut rep.q_correlation);
    demote(&mut rep.q_corr_mapping);
    demote(&mut rep.q_corr_copy);
    demote(&mut rep.q_corr_sync);
    demote(&mut rep.q_baseline);
    demote(&mut rep.q_terminal);
    rep.verdict.name = "partial_unknown_loss".to_string();
    for m in &mut rep.metrics {
        if m.coverage == "complete_for_scope" {
            m.coverage = "partial".to_string();
        }
    }
    rep.integrity_status = "checkpoint_prefix".to_string();
    rep.verified_bytes = bytes;
    rep.verified_events = events;
    rep.unverified_bytes = suffix;
}
