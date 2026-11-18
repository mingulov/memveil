// SPDX-License-Identifier: GPL-3.0-or-later
//! Derived report document.
//!
//! The analyzer builds this from one session plus its event stream;
//! renderers serialize it. Environment and device catalog echo the
//! session claims verbatim so provenance survives every export.
//! The terminal-loss leg and quiescence predicate live here with
//! the record verdict they feed.

use super::metric::{Finding, Metric};
use super::session::{Channel, DeviceEntry, EvidenceItem, Session, StopState};
use crate::ENGINE_VERSION;

/// Echoed session environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportEnv {
    /// Confidential-environment mode enum.
    pub mode: String,
    /// Environment detection enum.
    pub detection: String,
    /// True when an asserted mode was reported.
    pub has_asserted_mode: bool,
    /// Asserted mode; empty unless `has_asserted_mode`.
    pub asserted_mode: String,
    /// True when the asserted-mode key was present, even as null.
    pub asserted_mode_present: bool,
    /// Attestation enum.
    pub attestation: String,
    /// Environment evidence records.
    pub evidence: Vec<EvidenceItem>,
}

/// One echoed session capability claim: name plus grade.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReportCap {
    /// Capability name.
    pub name: String,
    /// Capability status enum.
    pub status: String,
    /// True when a grade was reported.
    pub has_grade: bool,
    /// Grade enum; empty unless `has_grade`.
    pub grade: String,
    /// Status reason text.
    pub reason: String,
}

/// One deterministic offline analysis result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Integrity scope label.
    pub integrity_context: String,
    /// Integrity status enum.
    pub integrity_status: String,
    /// Suffix bytes past the verified prefix.
    pub unverified_bytes: u64,
    /// Verified prefix bytes.
    pub verified_bytes: u64,
    /// Verified prefix events.
    pub verified_events: u64,
    /// Session identity.
    pub session_id: String,
    /// True for synthetic captures.
    pub synthetic: bool,
    /// Analyzer engine version.
    pub engine_version: String,
    /// Observation window start in nanoseconds.
    pub window_start_ns: u64,
    /// Observation window end in nanoseconds.
    pub window_end_ns: u64,
    /// Echoed session environment.
    pub env: ReportEnv,
    /// Echoed device catalog.
    pub devices: Vec<DeviceEntry>,
    /// Echoed capability claims.
    pub caps: Vec<ReportCap>,
    /// Detail quality channel.
    pub q_detail: Channel,
    /// Aggregate quality channel.
    pub q_aggregate: Channel,
    /// Correlation quality channel.
    pub q_correlation: Channel,
    /// True when relation classes were reported.
    pub has_corr_relations: bool,
    /// Mapping-release relation channel.
    pub q_corr_mapping: Channel,
    /// Copy-attribution relation channel.
    pub q_corr_copy: Channel,
    /// Sync-attribution relation channel.
    pub q_corr_sync: Channel,
    /// Baseline quality channel.
    pub q_baseline: Channel,
    /// Terminal quality channel.
    pub q_terminal: Channel,
    /// Derived metric rows.
    pub metrics: Vec<Metric>,
    /// Evidence-linked observations.
    pub findings: Vec<Finding>,
    /// Analysis limitations.
    pub limitations: Vec<String>,
    /// True when detail and counter measurements disagree.
    pub counter_disagreement: bool,
    /// Delivered detail records feeding the verdict ratio.
    pub detail_delivered: u64,
    /// Measurement verdict.
    pub verdict: Verdict,
}

impl Default for Report {
    fn default() -> Self {
        Self {
            integrity_context: "capture".to_string(),
            integrity_status: "legacy_unverified".to_string(),
            unverified_bytes: 0,
            verified_bytes: 0,
            verified_events: 0,
            session_id: String::new(),
            synthetic: false,
            engine_version: ENGINE_VERSION.to_string(),
            window_start_ns: 0,
            window_end_ns: 0,
            env: ReportEnv::default(),
            devices: Vec::new(),
            caps: Vec::new(),
            q_detail: Channel::default(),
            q_aggregate: Channel::default(),
            q_correlation: Channel::default(),
            has_corr_relations: false,
            q_corr_mapping: Channel::default(),
            q_corr_copy: Channel::default(),
            q_corr_sync: Channel::default(),
            q_baseline: Channel::default(),
            q_terminal: Channel::default(),
            metrics: Vec::new(),
            findings: Vec::new(),
            limitations: Vec::new(),
            counter_disagreement: false,
            detail_delivered: 0,
            verdict: Verdict::default(),
        }
    }
}

/// Measurement verdict: agreed counters plus bounded loss.
///
/// The name is one of complete, partial_known_loss, or
/// partial_unknown_loss. The ratio counts known lost records over
/// known lost plus delivered records in basis points (0..10000),
/// truncated; it is exact when every leg is known and a lower bound
/// otherwise, so partial_unknown_loss with ratio 0 means "no known
/// loss, more may hide", never "nothing lost".
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Verdict {
    /// Verdict name enum.
    pub name: String,
    /// Known-loss ratio in basis points, truncated.
    pub loss_ratio_bps: i64,
}

/// Assemble a verdict from counters agreement plus loss legs.
///
/// Only legs flagged known feed the ratio; unknown legs keep their
/// counts out of the numerator. Complete needs agreed counters,
/// every leg known, zero known loss, and no partial leg: a partial
/// leg with bounded loss (gap markers claiming zero, quiescence-only
/// spillover verified) stays partial_known_loss, never complete.
/// Known-loss ratio in basis points, truncated toward zero.
///
/// Division-first form: the exact floor without multiplying the
/// full count by 10000.
/// Deviation: Mojo traps on u64 overflow here; Rust computes the exact ratio in u128 per R14.
fn loss_ratio_bps(known_lost: u128, delivered: u64) -> i64 {
    let total = known_lost + delivered as u128;
    if total == 0 {
        return 0;
    }
    let head = (known_lost / total) * 10000;
    let rem = known_lost % total;
    let tail = rem * 10000 / total;
    (head + tail) as i64
}

#[allow(clippy::too_many_arguments)]
pub fn verdict_for_counts(
    counters_agree: bool,
    detail_loss_known: bool,
    detail_lost: u64,
    detail_partial: bool,
    terminal_partial: bool,
    terminal_loss_known: bool,
    terminal_lost: u64,
    delivered: u64,
) -> Verdict {
    // Deviation: Mojo traps when loss legs sum past u64::MAX; Rust accumulates exactly in u128 per R14.
    let mut known_lost = 0u128;
    if detail_loss_known {
        known_lost += detail_lost as u128;
    }
    if terminal_loss_known {
        known_lost += terminal_lost as u128;
    }
    let all_known = detail_loss_known && terminal_loss_known;
    let any_partial = detail_partial || terminal_partial;
    let name = if counters_agree && all_known && known_lost == 0 && !any_partial {
        "complete"
    } else if counters_agree && all_known {
        "partial_known_loss"
    } else {
        "partial_unknown_loss"
    };
    Verdict {
        name: name.to_string(),
        loss_ratio_bps: loss_ratio_bps(known_lost, delivered),
    }
}

/// Record-time verdict from session channels plus stop evidence.
///
/// The record side performs no counter comparison (the stream is not
/// read back), so the counters leg is vacuously agreed: the analysis
/// cross-check can only add unknown, never remove it. The detail leg
/// comes from the producer channel, the terminal leg from the shared
/// stop predicate, and delivered counts bounce_attempt records. The
/// report verdict is never better than this record verdict; the two
/// agree on intact gap-free loads.
pub fn verdict_for_session(session: &Session, delivered: u64) -> Verdict {
    let term = terminal_loss_leg(&session.q_terminal.status, &session.stop);
    verdict_for_counts(
        true,
        session.q_detail.has_loss_count,
        session.q_detail.loss_count,
        session.q_detail.status != "complete_for_scope",
        term.0,
        term.1,
        term.2,
        delivered,
    )
}

/// Severity for the aggregate incompleteness finding.
///
/// The finding demotes to informational only when the verdict
/// proves the incompleteness fully bounded with zero loss
/// (partial channels, nothing missing). Unknown loss, real
/// loss, and complete-with-correlation-caveats stay warning:
/// attribution gaps are not bounded by the detail verdict.
pub fn incomplete_finding_severity(verdict_name: &str, loss_ratio_bps: i64) -> String {
    if verdict_name == "partial_known_loss" && loss_ratio_bps == 0 {
        return "informational".to_string();
    }
    "warning".to_string()
}

/// True when quiescence is the only unproven stop stage.
///
/// Every other stage must carry its proof: admission closed, drain
/// ran, no busy ring, no submit past the drain, counters sampled,
/// budget met, and every in-flight submission drained. Writer settle
/// counts and open mappings are not record evidence and do not gate.
/// Sessions without stop proof (default fields) fail closed.
pub fn quiescence_only_spillover(stop: &StopState) -> bool {
    if stop.outcome != "partial" {
        return false;
    }
    if !stop.admission_closed {
        return false;
    }
    if stop.quiescence_observed {
        return false;
    }
    if !stop.drain_completed {
        return false;
    }
    if stop.submit_after_drain {
        return false;
    }
    if stop.busy_at_drain {
        return false;
    }
    if !stop.counters_valid {
        return false;
    }
    if stop.elapsed_ms > stop.budget_ms {
        return false;
    }
    stop.late_submits_drained == stop.in_flight_at_close
}

/// Terminal verdict leg: (partial, loss known, lost count).
///
/// A complete label counts only with a proving complete outcome; a
/// bare label with no stop evidence stays unknown. Partial counts as
/// known-zero only through the quiescence-only spillover rule. Any
/// other status fails closed to unknown with zero claimed loss.
pub fn terminal_loss_leg(status: &str, stop: &StopState) -> (bool, bool, u64) {
    if status == "complete_for_scope" {
        if stop.outcome == "complete" {
            return (false, true, 0);
        }
        return (false, false, 0);
    }
    if status == "partial" && quiescence_only_spillover(stop) {
        return (true, true, 0);
    }
    (true, false, 0)
}

fn unverified_channel(channel: &mut Channel, note: &str) {
    if channel.status == "complete_for_scope" {
        channel.status = "partial".to_string();
    }
    let reason = core::mem::take(&mut channel.reason);
    channel.reason = note.to_string();
    let keep = 1024usize.saturating_sub(note.chars().count());
    for ch in reason.chars().take(keep) {
        channel.reason.push(ch);
    }
}

fn demote_integrity(rep: &mut Report, note: &str) {
    unverified_channel(&mut rep.q_detail, note);
    unverified_channel(&mut rep.q_aggregate, note);
    unverified_channel(&mut rep.q_correlation, note);
    unverified_channel(&mut rep.q_corr_mapping, note);
    unverified_channel(&mut rep.q_corr_copy, note);
    unverified_channel(&mut rep.q_corr_sync, note);
    unverified_channel(&mut rep.q_baseline, note);
    unverified_channel(&mut rep.q_terminal, note);
    rep.verdict.name = "partial_unknown_loss".to_string();
    for m in &mut rep.metrics {
        if m.coverage == "complete_for_scope" {
            m.coverage = "partial".to_string();
        }
    }
}

/// Bind file verification after reduction without changing its arithmetic.
pub fn apply_integrity(rep: &mut Report, verified: bool, bytes: u64, events: u64) {
    if verified {
        rep.integrity_status = "verified".to_string();
        rep.verified_bytes = bytes;
        rep.verified_events = events;
        return;
    }
    rep.integrity_status = "legacy_unverified".to_string();
    rep.verified_bytes = 0;
    rep.verified_events = 0;
    demote_integrity(rep, "Capture integrity unverified; ");
}

/// Keep open-window uncertainty alongside verified prefix arithmetic.
pub fn apply_checkpoint(rep: &mut Report, bytes: u64, events: u64, suffix: u64) {
    demote_integrity(
        rep,
        "Checkpoint prefix only; measurement window remains open; ",
    );
    rep.integrity_status = "checkpoint_prefix".to_string();
    rep.verified_bytes = bytes;
    rep.verified_events = events;
    rep.unverified_bytes = suffix;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn counts(
        agree: bool,
        d_known: bool,
        d_lost: u64,
        d_partial: bool,
        t_partial: bool,
        t_known: bool,
        t_lost: u64,
        delivered: u64,
    ) -> Verdict {
        verdict_for_counts(
            agree, d_known, d_lost, d_partial, t_partial, t_known, t_lost, delivered,
        )
    }

    #[test]
    fn report_defaults_echo_unverified_capture() {
        let r = Report::default();
        assert_eq!(r.integrity_context, "capture");
        assert_eq!(r.integrity_status, "legacy_unverified");
        assert_eq!(r.unverified_bytes, 0);
        assert_eq!(r.verified_bytes, 0);
        assert_eq!(r.verified_events, 0);
        assert_eq!(r.session_id, "");
        assert!(!r.synthetic);
        assert_eq!(r.engine_version, "memveil-0.1.0");
        assert_eq!(r.window_start_ns, 0);
        assert_eq!(r.window_end_ns, 0);
        assert!(r.devices.is_empty());
        assert!(r.caps.is_empty());
        assert!(!r.has_corr_relations);
        assert!(r.metrics.is_empty());
        assert!(r.findings.is_empty());
        assert!(r.limitations.is_empty());
        assert!(!r.counter_disagreement);
        assert_eq!(r.detail_delivered, 0);
        assert_eq!(r.verdict, Verdict::default());
    }

    #[test]
    fn env_and_cap_defaults_are_empty() {
        let e = ReportEnv::default();
        assert_eq!(e.mode, "");
        assert_eq!(e.detection, "");
        assert!(!e.has_asserted_mode);
        assert_eq!(e.asserted_mode, "");
        assert!(!e.asserted_mode_present);
        assert_eq!(e.attestation, "");
        assert!(e.evidence.is_empty());
        let c = ReportCap::default();
        assert_eq!(c.name, "");
        assert_eq!(c.status, "");
        assert!(!c.has_grade);
        assert_eq!(c.grade, "");
        assert_eq!(c.reason, "");
    }

    #[test]
    fn verdict_struct_defaults() {
        let v = Verdict::default();
        assert_eq!(v.name, "");
        assert_eq!(v.loss_ratio_bps, 0);
        assert!(v.loss_ratio_bps >= 0);
    }

    #[test]
    fn verdict_complete_clean() {
        let v = counts(true, true, 0, false, false, true, 0, 100);
        assert_eq!(v.name, "complete");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_known_loss_ratio() {
        let v = counts(true, true, 5, true, false, true, 0, 95);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 500);
    }

    #[test]
    fn verdict_unknown_detail_lower_bound() {
        let v = counts(true, false, 0, true, false, true, 0, 100);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_unknown_terminal() {
        let v = counts(true, true, 0, false, true, false, 0, 100);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_counters_disagree() {
        let v = counts(false, true, 0, false, false, true, 0, 100);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_quiescence_spillover_known() {
        let v = counts(true, true, 0, false, true, true, 0, 100);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_vacuous_zero_zero() {
        let v = counts(true, true, 0, false, false, true, 0, 0);
        assert_eq!(v.name, "complete");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_ratio_truncates() {
        let v = counts(true, true, 1, true, false, true, 0, 2);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 3333);
    }

    #[test]
    fn verdict_terminal_known_loss() {
        let v = counts(true, true, 0, false, true, true, 3, 97);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 300);
    }

    #[test]
    fn verdict_disagree_keeps_lower_bound() {
        let v = counts(false, true, 5, true, false, true, 0, 95);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 500);
    }

    #[test]
    fn verdict_huge_counts_exact() {
        // R14: u128 intermediates report the exact ratio where Mojo
        // traps. Expected values are floor(known*10000/total).
        let v = counts(true, true, u64::MAX, true, false, true, 0, 1);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 9999);
        let v = counts(
            true,
            true,
            9_000_000_000_000_000_000,
            true,
            false,
            true,
            0,
            9_000_000_000_000_000_000,
        );
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 5000);
        let v = counts(
            true,
            true,
            9_000_000_000_000_000_000,
            true,
            false,
            true,
            0,
            1_000_000_000_000_000_000,
        );
        assert_eq!(v.loss_ratio_bps, 9000);
    }

    #[test]
    fn verdict_leg_sum_past_u64_exact() {
        // Detail + terminal legs summing past u64::MAX stay exact.
        let v = counts(true, true, u64::MAX, true, true, true, u64::MAX, 0);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 10000);
        let v = counts(true, true, u64::MAX, true, false, true, 1, u64::MAX);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 5000);
    }

    #[test]
    fn verdict_partial_detail_zero_loss() {
        let v = counts(true, true, 0, true, false, true, 0, 100);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn verdict_ratio_sweep() {
        // (known, delivered) -> truncated basis points.
        let cases = [
            (0u64, 1u64, 0i64),
            (1, 1, 5000),
            (1, 3, 2500),
            (2, 2, 5000),
            (3, 97, 300),
            (1, 199, 50),
            (9999, 1, 9999),
            (1, 0, 10000),
            (u64::MAX / 10001, 1, 9999),
        ];
        for (known, delivered, want) in cases {
            let v = counts(true, true, known, true, false, true, 0, delivered);
            assert_eq!(v.loss_ratio_bps, want, "ratio for {known}/{delivered}");
            assert!(v.loss_ratio_bps >= 0 && v.loss_ratio_bps <= 10000);
        }
    }

    fn quiescence_stop() -> StopState {
        StopState {
            outcome: "partial".to_string(),
            reason: "quiescence unproven".to_string(),
            budget_ms: 5000,
            elapsed_ms: 100,
            admission_closed: true,
            quiescence_observed: false,
            writers_settled: 0,
            in_flight_at_close: 3,
            late_submits_drained: 3,
            drained_records: 10,
            drain_completed: true,
            submit_after_drain: false,
            busy_at_drain: false,
            counters_valid: true,
            open_mappings: 0,
            ..StopState::default()
        }
    }

    #[test]
    fn terminal_complete_proved() {
        let s = StopState {
            outcome: "complete".to_string(),
            ..StopState::default()
        };
        assert_eq!(
            terminal_loss_leg("complete_for_scope", &s),
            (false, true, 0)
        );
    }

    #[test]
    fn terminal_complete_contradicted() {
        assert_eq!(
            terminal_loss_leg("complete_for_scope", &StopState::default()),
            (false, false, 0)
        );
    }

    #[test]
    fn terminal_quiescence_only() {
        assert_eq!(
            terminal_loss_leg("partial", &quiescence_stop()),
            (true, true, 0)
        );
    }

    #[test]
    fn terminal_quiescence_single_faults_stay_unknown() {
        let mut cases: Vec<(&str, StopState)> = Vec::new();
        let mut busy = quiescence_stop();
        busy.busy_at_drain = true;
        cases.push(("busy", busy));
        let mut short = quiescence_stop();
        short.late_submits_drained = 2;
        cases.push(("spillover short", short));
        let mut counters = quiescence_stop();
        counters.counters_valid = false;
        cases.push(("counters bad", counters));
        let mut late = quiescence_stop();
        late.submit_after_drain = true;
        cases.push(("late submit", late));
        let mut drain = quiescence_stop();
        drain.drain_completed = false;
        cases.push(("drain missing", drain));
        let mut admission = quiescence_stop();
        admission.admission_closed = false;
        cases.push(("admission open", admission));
        let mut observed = quiescence_stop();
        observed.quiescence_observed = true;
        observed.reason = "drain missing".to_string();
        cases.push(("quiescence observed", observed));
        let mut over = quiescence_stop();
        over.elapsed_ms = 6000;
        cases.push(("over budget", over));
        let mut outcome = quiescence_stop();
        outcome.outcome = "complete".to_string();
        cases.push(("outcome complete", outcome));
        for (name, stop) in &cases {
            assert_eq!(
                terminal_loss_leg("partial", stop),
                (true, false, 0),
                "{name} must stay unknown"
            );
        }
    }

    #[test]
    fn terminal_partial_default_stop() {
        assert_eq!(
            terminal_loss_leg("partial", &StopState::default()),
            (true, false, 0)
        );
    }

    #[test]
    fn terminal_unavailable() {
        assert_eq!(
            terminal_loss_leg("unavailable", &quiescence_stop()),
            (true, false, 0)
        );
    }

    #[test]
    fn quiescence_predicate_direct() {
        assert!(quiescence_only_spillover(&quiescence_stop()));
        assert!(!quiescence_only_spillover(&StopState::default()));
    }

    fn clean_session() -> Session {
        let mut s = Session::default();
        s.q_detail.status = "complete_for_scope".to_string();
        s.q_detail.has_loss_count = true;
        s.q_detail.loss_count = 0;
        s.q_terminal.status = "complete_for_scope".to_string();
        s.stop.outcome = "complete".to_string();
        s
    }

    #[test]
    fn session_verdict_complete() {
        let v = verdict_for_session(&clean_session(), 50);
        assert_eq!(v.name, "complete");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn session_verdict_producer_loss() {
        let mut s = clean_session();
        s.q_detail.status = "partial".to_string();
        s.q_detail.loss_count = 5;
        let v = verdict_for_session(&s, 95);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 500);
    }

    #[test]
    fn session_verdict_no_stop_proof() {
        let mut s = clean_session();
        s.stop.outcome = "partial".to_string();
        let v = verdict_for_session(&s, 50);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn session_verdict_unknown_detail() {
        let mut s = clean_session();
        s.q_detail.status = "partial".to_string();
        s.q_detail.has_loss_count = false;
        let v = verdict_for_session(&s, 10);
        assert_eq!(v.name, "partial_unknown_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn session_verdict_quiescence_only() {
        let mut s = clean_session();
        s.q_terminal.status = "partial".to_string();
        s.stop = quiescence_stop();
        let v = verdict_for_session(&s, 100);
        assert_eq!(v.name, "partial_known_loss");
        assert_eq!(v.loss_ratio_bps, 0);
    }

    #[test]
    fn severity_matrix() {
        assert_eq!(
            incomplete_finding_severity("partial_known_loss", 0),
            "informational"
        );
        assert_eq!(
            incomplete_finding_severity("partial_known_loss", 500),
            "warning"
        );
        assert_eq!(
            incomplete_finding_severity("partial_unknown_loss", 0),
            "warning"
        );
        assert_eq!(incomplete_finding_severity("complete", 0), "warning");
        assert_eq!(incomplete_finding_severity("", 0), "warning");
    }

    #[test]
    fn apply_integrity_verified_binds_counts() {
        let mut r = Report::default();
        r.q_detail.status = "complete_for_scope".to_string();
        apply_integrity(&mut r, true, 1155, 3);
        assert_eq!(r.integrity_status, "verified");
        assert_eq!(r.verified_bytes, 1155);
        assert_eq!(r.verified_events, 3);
        assert_eq!(r.q_detail.status, "complete_for_scope");
    }

    #[test]
    fn apply_integrity_unverified_demotes_everything() {
        let mut r = Report::default();
        r.verdict.name = "complete".to_string();
        r.q_detail.status = "complete_for_scope".to_string();
        r.q_detail.reason = "old".to_string();
        r.q_aggregate.status = "complete_for_scope".to_string();
        r.q_correlation.status = "partial".to_string();
        r.q_correlation.reason = "kept".to_string();
        let m = Metric {
            coverage: "complete_for_scope".to_string(),
            ..Metric::default()
        };
        let m2 = Metric {
            coverage: "partial".to_string(),
            ..Metric::default()
        };
        r.metrics.push(m);
        r.metrics.push(m2);
        apply_integrity(&mut r, false, 0, 0);
        assert_eq!(r.integrity_status, "legacy_unverified");
        assert_eq!(r.verified_bytes, 0);
        assert_eq!(r.verified_events, 0);
        assert_eq!(r.verdict.name, "partial_unknown_loss");
        assert_eq!(r.q_detail.status, "partial");
        assert_eq!(r.q_detail.reason, "Capture integrity unverified; old");
        assert_eq!(r.q_aggregate.status, "partial");
        assert_eq!(r.q_correlation.status, "partial");
        assert_eq!(r.q_correlation.reason, "Capture integrity unverified; kept");
        for ch in [
            &r.q_corr_mapping,
            &r.q_corr_copy,
            &r.q_corr_sync,
            &r.q_baseline,
            &r.q_terminal,
        ] {
            assert_eq!(ch.reason, "Capture integrity unverified; ");
        }
        assert_eq!(r.metrics[0].coverage, "partial");
        assert_eq!(r.metrics[1].coverage, "partial");
    }

    #[test]
    fn apply_integrity_note_truncates_at_1024_codepoints() {
        let mut r = Report::default();
        r.q_detail.reason = "é".repeat(2000);
        apply_integrity(&mut r, false, 0, 0);
        assert_eq!(r.q_detail.reason.chars().count(), 1024);
        assert!(
            r.q_detail
                .reason
                .starts_with("Capture integrity unverified; ")
        );
    }

    #[test]
    fn apply_checkpoint_keeps_prefix_with_open_window() {
        let mut r = Report::default();
        r.verdict.name = "complete".to_string();
        r.q_detail.status = "complete_for_scope".to_string();
        apply_checkpoint(&mut r, 500, 2, 700);
        assert_eq!(r.integrity_status, "checkpoint_prefix");
        assert_eq!(r.verified_bytes, 500);
        assert_eq!(r.verified_events, 2);
        assert_eq!(r.unverified_bytes, 700);
        assert_eq!(r.verdict.name, "partial_unknown_loss");
        assert_eq!(r.q_detail.status, "partial");
        assert!(r.q_detail.reason.starts_with("Checkpoint prefix only; "));
    }
}
