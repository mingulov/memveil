// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed conversion-journal window and counter evidence for the frozen
//! 0.2.0 session schema.
//!
//! A journal session block carries the admission window (nullable
//! admission evidence plus a verified prefix cut) and eleven
//! independent counters in a fixed order. Each counter is either
//! known (with an empty reason) or unknown (with a fixed null
//! reason); counters never net into snapshot state.

use super::common::MaybeU64;
use super::encode::quote_json;
use super::journal::JournalWindow;
use super::journal_event::{
    boolean, fields, member, null_value, nullable_text, nullable_uint, object_text, required_uint,
    text, uint,
};
use super::scan::Scanner;
use super::validate::{ValidationError, check_bounded_text, format_u64};

/// Session counters carried in the frozen fixed order.
pub const JOURNAL_COUNTER_COUNT: usize = 11;

/// Counter names in the frozen fixed order.
pub const JOURNAL_COUNTER_NAMES: [&str; JOURNAL_COUNTER_COUNT] = [
    "entries",
    "exits",
    "matched_results",
    "unmatched_exits",
    "censored",
    "operation_exhaustion",
    "nesting_exhaustion",
    "token_exhaustion",
    "ring_drops",
    "invalid_records",
    "missed_callbacks",
];

/// Counter name by position; valid only for `0..JOURNAL_COUNTER_COUNT`.
pub fn journal_counter_name(index: usize) -> &'static str {
    JOURNAL_COUNTER_NAMES[index]
}

/// One typed journal session block: admission window plus counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalSession {
    /// Source profile identity.
    pub profile_id: String,
    /// Evidence class enum.
    pub evidence_class: String,
    /// Nonzero capture admission epoch.
    pub epoch: u64,
    /// Actual admission start once the checkpoint is durable.
    pub admission_start_ns: MaybeU64,
    /// Actual admission end once entry admission closes.
    pub admission_end_ns: MaybeU64,
    /// Null reason for a known start; otherwise the unknown-start state.
    pub admission_start_reason: String,
    /// Null reason for a known end; otherwise the open/unknown state.
    pub admission_end_reason: String,
    /// Verified prefix cut on the capture clock, not settled closure.
    pub observation_end_ns: u64,
    /// True when bounded caller processing was requested.
    pub callers: bool,
    /// Closure enum: `proved` or `unproved`.
    pub closure: String,
    /// Closure evidence; nonempty only when proved.
    pub closure_evidence: String,
    /// Eleven counters in [`JOURNAL_COUNTER_NAMES`] order.
    pub counters: Vec<MaybeU64>,
    /// Eleven counter reasons in the same order.
    pub counter_reasons: Vec<String>,
}

impl Default for JournalSession {
    fn default() -> Self {
        Self {
            profile_id: String::new(),
            evidence_class: "source_reviewed_provisional".to_string(),
            epoch: 0,
            admission_start_ns: MaybeU64::absent(),
            admission_end_ns: MaybeU64::absent(),
            admission_start_reason: "not_opened".to_string(),
            admission_end_reason: "not_opened".to_string(),
            observation_end_ns: 0,
            callers: false,
            closure: "unproved".to_string(),
            closure_evidence: String::new(),
            counters: vec![MaybeU64::absent(); JOURNAL_COUNTER_COUNT],
            counter_reasons: vec!["not_observable".to_string(); JOURNAL_COUNTER_COUNT],
        }
    }
}

impl JournalSession {
    /// Validate the block against the 0.2.0 session contract.
    pub fn validate(&self) -> Result<(), ValidationError> {
        check_bounded_text(&self.profile_id, 1, 128, "journal profile")?;
        if self.evidence_class != "synthetic"
            && self.evidence_class != "source_reviewed_provisional"
            && self.evidence_class != "admitted"
        {
            return Err(ValidationError::new("journal", "evidence class"));
        }
        if self.epoch == 0
            || self.counters.len() != JOURNAL_COUNTER_COUNT
            || self.counter_reasons.len() != JOURNAL_COUNTER_COUNT
        {
            return Err(ValidationError::new("journal", "epoch/counter shape"));
        }
        if self.closure == "proved" {
            check_bounded_text(&self.closure_evidence, 1, 128, "closure evidence")?;
        } else if self.closure != "unproved" || !self.closure_evidence.is_empty() {
            return Err(ValidationError::new("journal", "closure"));
        }
        for i in 0..JOURNAL_COUNTER_COUNT {
            let reason = &self.counter_reasons[i];
            if self.counters[i].has {
                if !reason.is_empty() {
                    return Err(ValidationError::new("journal", "known counter reason"));
                }
            } else if reason != "not_observable" && reason != "read_failed" && reason != "overflow"
            {
                return Err(ValidationError::new("journal", "unknown counter reason"));
            }
        }
        Ok(())
    }

    /// Build the validated admission window for this block.
    ///
    /// An open prefix carries no terminal censored count, and no
    /// counts may precede readiness.
    pub fn window(
        &self,
        capture_start: u64,
        finalized: bool,
    ) -> Result<JournalWindow, ValidationError> {
        self.validate()?;
        let out = JournalWindow {
            epoch: self.epoch,
            capture_start,
            observation_end: self.observation_end_ns,
            start: self.admission_start_ns.clone(),
            cutoff: self.admission_end_ns.clone(),
            start_reason: self.admission_start_reason.clone(),
            end_reason: self.admission_end_reason.clone(),
            finalized,
        };
        out.validate()?;
        if !finalized && self.counters[4].has {
            return Err(ValidationError::new(
                "journal",
                "open prefix has no terminal censored count",
            ));
        }
        if self.admission_start_reason == "not_opened" {
            // `validate` above fixed the counter shape, so the take is exact.
            for counter in self.counters.iter().take(JOURNAL_COUNTER_COUNT) {
                if counter.has && counter.value != 0 {
                    return Err(ValidationError::new("journal", "counts before readiness"));
                }
            }
        }
        Ok(out)
    }
}

/// Parse one journal session block from the session cursor.
pub(crate) fn parse_journal_session(scan: &mut Scanner) -> Result<JournalSession, ValidationError> {
    let f = fields(
        scan,
        &[
            "profile_id",
            "evidence_class",
            "epoch",
            "admission_start_ns",
            "admission_end_ns",
            "admission_start_reason",
            "admission_end_reason",
            "observation_end_ns",
            "callers",
            "operation_capacity",
            "nesting_capacity",
            "caller_frame_capacity",
            "ring_bytes",
            "closure",
            "closure_evidence",
            "counters",
            "counter_reasons",
            "region_identity",
            "region_state",
            "state_reason",
        ],
    )?;
    let profile_id = text(f["profile_id"], false)?;
    let evidence_class = text(f["evidence_class"], false)?;
    let epoch = required_uint(f["epoch"])?;
    let admission_start_ns = uint(f["admission_start_ns"])?;
    let admission_end_ns = uint(f["admission_end_ns"])?;
    let admission_start_reason = text(f["admission_start_reason"], true)?;
    let admission_end_reason = text(f["admission_end_reason"], true)?;
    let observation_end_ns = required_uint(f["observation_end_ns"])?;
    let callers = boolean(f["callers"])?;
    let closure = text(f["closure"], false)?;
    let closure_evidence = text(f["closure_evidence"], true)?;
    null_value(f["region_identity"])?;
    null_value(f["region_state"])?;
    if text(f["operation_capacity"], false)? != "4096"
        || text(f["nesting_capacity"], false)? != "8"
        || text(f["caller_frame_capacity"], false)? != "16"
        || text(f["ring_bytes"], false)? != "8388608"
        || text(f["state_reason"], false)? != "request_only_source"
    {
        return Err(ValidationError::new("journal", "capacity/state contract"));
    }
    let mut counts_scan = Scanner::new(f["counters"]);
    let counts = fields(&mut counts_scan, &JOURNAL_COUNTER_NAMES)?;
    let mut reasons_scan = Scanner::new(f["counter_reasons"]);
    let reasons = fields(&mut reasons_scan, &JOURNAL_COUNTER_NAMES)?;
    let mut out = JournalSession {
        profile_id,
        evidence_class,
        epoch,
        admission_start_ns,
        admission_end_ns,
        admission_start_reason,
        admission_end_reason,
        observation_end_ns,
        callers,
        closure,
        closure_evidence,
        ..JournalSession::default()
    };
    for i in 0..JOURNAL_COUNTER_COUNT {
        let name = journal_counter_name(i);
        out.counters[i] = uint(counts[name])?;
        out.counter_reasons[i] = text(reasons[name], true)?;
    }
    out.validate()?;
    Ok(out)
}

/// Encode one journal session block in canonical member order.
pub(crate) fn encode_journal_session(value: &JournalSession) -> Result<String, ValidationError> {
    value.validate()?;
    let mut p: Vec<String> = Vec::new();
    p.push(member("profile_id", &quote_json(&value.profile_id)));
    p.push(member("evidence_class", &quote_json(&value.evidence_class)));
    p.push(member("epoch", &quote_json(&format_u64(value.epoch))));
    p.push(member(
        "admission_start_ns",
        &nullable_uint(&value.admission_start_ns),
    ));
    p.push(member(
        "admission_end_ns",
        &nullable_uint(&value.admission_end_ns),
    ));
    p.push(member(
        "admission_start_reason",
        &nullable_text(&value.admission_start_reason),
    ));
    p.push(member(
        "admission_end_reason",
        &nullable_text(&value.admission_end_reason),
    ));
    p.push(member(
        "observation_end_ns",
        &quote_json(&format_u64(value.observation_end_ns)),
    ));
    p.push(member(
        "callers",
        if value.callers { "true" } else { "false" },
    ));
    p.push(
        "\"operation_capacity\":\"4096\",\"nesting_capacity\":\"8\",\"caller_frame_capacity\":\"16\",\"ring_bytes\":\"8388608\""
            .to_string(),
    );
    p.push(member("closure", &quote_json(&value.closure)));
    p.push(member(
        "closure_evidence",
        &nullable_text(&value.closure_evidence),
    ));
    let mut counts: Vec<String> = Vec::new();
    let mut reasons: Vec<String> = Vec::new();
    for i in 0..JOURNAL_COUNTER_COUNT {
        let name = journal_counter_name(i);
        counts.push(member(name, &nullable_uint(&value.counters[i])));
        reasons.push(member(name, &nullable_text(&value.counter_reasons[i])));
    }
    p.push(member("counters", &object_text(&counts)));
    p.push(member("counter_reasons", &object_text(&reasons)));
    p.push(
        "\"region_identity\":null,\"region_state\":null,\"state_reason\":\"request_only_source\""
            .to_string(),
    );
    Ok(object_text(&p))
}
