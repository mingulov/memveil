// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed conversion-journal capture boundary: wire normalization,
//! bounded transport accounting, and window control.
//!
//! [`JournalCapture`] ingests raw 72-byte MVJR wire records into
//! typed journal events, tracking per-CPU transport sequences,
//! invalid records, and admission open/close. It owns no kernel
//! resources: [`JournalKernel`] is a trait-only source contract
//! whose native implementation lands with the producer slice.

use crate::model::common::MaybeU64;
use crate::model::event::Event;
use crate::model::journal::{JournalResult, decode_journal};
use crate::model::journal_event::{JournalEvent, caller_class, caller_label, caller_status};
use crate::model::journal_session::{JOURNAL_COUNTER_COUNT, JournalSession};
use crate::model::validate::ValidationError;
use crate::platform::outcome::OpOut;
use std::collections::HashMap;

/// Native counters read back per snapshot.
pub const JOURNAL_NATIVE_COUNTERS: usize = 15;

/// One bounded ring poll outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalPoll {
    /// True when the poll produced data or a clean timeout.
    pub ok: bool,
    /// Polled wire bytes; empty unless `ok` with data.
    pub data: Vec<u8>,
}

/// One native counter readback outcome.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct JournalCounters {
    /// True when all native counters read back.
    pub ok: bool,
    /// Counter values; empty unless `ok`.
    pub values: Vec<u64>,
}

/// Owned journal tracing transport contract.
///
/// Method signatures only: prepare opens the object, attach
/// enables the hooks, control writes the admission window,
/// poll/counters read records and counters, detach/close
/// release. No implementation, maps, attach, or control I/O
/// live in this slice.
pub trait JournalKernel {
    /// Open the journal object and check it into a readable state.
    fn prepare(&mut self, control: &[u8]) -> OpOut;
    /// Attach the journal hooks.
    fn attach(&mut self) -> OpOut;
    /// Write the admission control block with readback.
    fn control(&mut self, value: &[u8]) -> OpOut;
    /// Poll one ring batch, waiting at most `timeout_ms`.
    fn poll(&mut self, timeout_ms: i64) -> JournalPoll;
    /// Read back the native counters.
    fn counters(&mut self) -> JournalCounters;
    /// Detach the journal hooks.
    fn detach(&mut self) -> OpOut;
    /// Close the journal object.
    fn close(&mut self) -> OpOut;
}

/// Normalize one decoded wire result into a typed journal event.
pub(crate) fn normalize_journal_result(
    result: &JournalResult,
) -> Result<JournalEvent, ValidationError> {
    let (requested_pages, requested_bytes, size_reason) = if result.pages >= 0 {
        (
            MaybeU64::of(result.pages as u64),
            MaybeU64::of(result.pages as u64 * 4096),
            String::new(),
        )
    } else {
        (
            MaybeU64::absent(),
            MaybeU64::absent(),
            "invalid_native_pages".to_string(),
        )
    };
    let (operation_token, entry_ns, membership) = if result.matched {
        (
            MaybeU64::of(result.token),
            MaybeU64::of(result.entry_ns),
            "admitted".to_string(),
        )
    } else {
        (
            MaybeU64::absent(),
            MaybeU64::absent(),
            "unmatched_exit".to_string(),
        )
    };
    let out = JournalEvent {
        direction: if result.direction == 1 {
            "decrypt".to_string()
        } else {
            "encrypt".to_string()
        },
        requested_native_pages: result.pages,
        requested_pages,
        requested_bytes,
        size_reason,
        native_result: result.native_result,
        operation_token,
        entry_ns,
        epoch: result.epoch,
        membership,
        caller_status: caller_status(result.caller_status).to_string(),
        caller_class: caller_class(result.caller_class).to_string(),
        caller_label: caller_label(result.caller_label).to_string(),
    };
    out.validate()?;
    Ok(out)
}

/// Wrap one decoded wire result as a journal-typed event line.
pub(crate) fn normalize_journal_event(
    result: &JournalResult,
    session_id: &str,
    profile_id: &str,
) -> Result<Event, ValidationError> {
    Ok(Event {
        session_id: session_id.to_string(),
        kind: "transition_result".to_string(),
        ts_ns: result.exit_ns,
        journal_version: true,
        has_journal: true,
        journal: normalize_journal_result(result)?,
        source_hook: if result.direction == 1 {
            "set_memory_decrypted".to_string()
        } else {
            "set_memory_encrypted".to_string()
        },
        source_backend: "fentry_fexit".to_string(),
        source_profile_id: profile_id.to_string(),
        source_measurement: "observed".to_string(),
        source_correlation: "unpaired".to_string(),
        ..Event::default()
    })
}

/// Decode one native counter block into fifteen counters.
pub fn decode_journal_counters(raw: &[u8]) -> Result<Vec<u64>, ValidationError> {
    if raw.len() != JOURNAL_NATIVE_COUNTERS * 8 {
        return Err(ValidationError::new("journal counters", "length"));
    }
    let mut out = Vec::with_capacity(JOURNAL_NATIVE_COUNTERS);
    for i in 0..JOURNAL_NATIVE_COUNTERS {
        let mut value: u64 = 0;
        for j in 0..8 {
            value |= u64::from(raw[i * 8 + j]) << (8 * j);
        }
        out.push(value);
    }
    Ok(out)
}

/// Encode the 48-byte admission control block.
pub fn encode_journal_control(
    epoch: u64,
    start: u64,
    end: u64,
    opened: bool,
    observe: bool,
    callers: bool,
) -> Vec<u8> {
    let values: [u64; 6] = [
        epoch,
        start,
        end,
        u64::from(opened),
        u64::from(observe),
        u64::from(callers),
    ];
    let mut out = Vec::with_capacity(48);
    for value in values {
        for i in 0..8 {
            out.push(((value >> (8 * i)) & 255) as u8);
        }
    }
    out
}

/// Typed journal ingest: admission state plus transport accounting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalCapture {
    /// Session evidence under construction.
    pub session: JournalSession,
    /// Observed capture start on the capture clock.
    pub capture_start: u64,
    /// Wire/window/sequence refusals so far.
    pub invalid_records: u64,
    /// Skipped per-CPU transport sequences so far.
    pub sequence_gaps: u64,
    /// Next wanted per-CPU transport sequence, bounded to 4096 CPUs.
    pub sequences: HashMap<u32, u64>,
    /// Latest accepted exit timestamp.
    pub last_result: u64,
}

impl JournalCapture {
    /// Start a capture for `epoch` at `start` under `profile`.
    pub fn new(epoch: u64, start: u64, profile: String, callers: bool) -> Self {
        let session = JournalSession {
            epoch,
            profile_id: profile,
            callers,
            ..JournalSession::default()
        };
        Self {
            session,
            capture_start: start,
            invalid_records: 0,
            sequence_gaps: 0,
            sequences: HashMap::new(),
            last_result: start,
        }
    }

    /// Record durable admission opening at `start`.
    pub fn opened(&mut self, start: u64) -> Result<(), ValidationError> {
        if self.session.admission_start_ns.has
            || start < self.capture_start
            || self.session.epoch == 0
        {
            return Err(ValidationError::new("journal", "invalid admission opening"));
        }
        self.session.admission_start_ns = MaybeU64::of(start);
        self.session.admission_start_reason = String::new();
        self.session.admission_end_reason = "admission_open".to_string();
        Ok(())
    }

    /// Record admission closing at `end`, proved only on a durable write.
    pub fn closed(&mut self, end: u64, proved_write: bool) -> Result<(), ValidationError> {
        if !self.session.admission_start_ns.has || end < self.session.admission_start_ns.value {
            return Err(ValidationError::new("journal", "invalid admission closing"));
        }
        if proved_write {
            self.session.admission_end_ns = MaybeU64::of(end);
            self.session.admission_end_reason = String::new();
        } else {
            self.session.admission_end_reason = "close_unproved".to_string();
        }
        Ok(())
    }

    /// Ingest one raw wire record as a typed journal event.
    ///
    /// Decode, window, caller, and transport-sequence failures all
    /// count one invalid record and refuse with a single generic
    /// error; only the accounting survives a refusal.
    pub fn consume(
        &mut self,
        raw: &[u8],
        session_id: &str,
        observation_cut: u64,
    ) -> Result<Event, ValidationError> {
        let result = match self.consume_inner(raw, observation_cut) {
            Ok(result) => result,
            Err(_) => {
                self.invalid_records = self.invalid_records.saturating_add(1);
                return Err(ValidationError::new(
                    "journal",
                    "invalid wire/window/sequence",
                ));
            }
        };
        if result.exit_ns > self.last_result {
            self.last_result = result.exit_ns;
        }
        let profile = self.session.profile_id.clone();
        normalize_journal_event(&result, session_id, &profile)
    }

    /// Decode, admit, and sequence-check one raw wire record.
    fn consume_inner(
        &mut self,
        raw: &[u8],
        observation_cut: u64,
    ) -> Result<JournalResult, ValidationError> {
        let result = decode_journal(raw)?;
        let mut snapshot = self.session.clone();
        snapshot.observation_end_ns = observation_cut;
        let window = snapshot.window(
            self.capture_start,
            self.session.admission_end_reason != "admission_open",
        )?;
        window.validate_result(&result)?;
        if !self.session.callers && result.caller_status != 0 {
            return Err(ValidationError::new("journal", "unsolicited caller"));
        }
        if !self.sequences.contains_key(&result.cpu) && self.sequences.len() >= 4096 {
            return Err(ValidationError::new("journal", "cpu tracking budget"));
        }
        let wanted = self.sequences.get(&result.cpu).copied().unwrap_or(0);
        if result.sequence < wanted || result.sequence == u64::MAX {
            return Err(ValidationError::new(
                "journal",
                "transport sequence regression/exhaustion",
            ));
        }
        let gap = result.sequence - wanted;
        if gap > u64::MAX - self.sequence_gaps {
            return Err(ValidationError::new("journal", "sequence gap overflow"));
        }
        self.sequence_gaps += gap;
        // The exhaustion check above keeps `sequence + 1` in range.
        self.sequences.insert(result.cpu, result.sequence + 1);
        Ok(result)
    }

    /// Snapshot session evidence at `cut` from a native readback.
    ///
    /// Native counters map onto the session counters positionally;
    /// unreadable or overflowed positions keep fixed null reasons.
    /// Invalid records always report; an open prefix never carries a
    /// terminal censored count.
    pub fn snapshot(
        &self,
        cut: u64,
        finalized: bool,
        counters: &[u64],
        readable: bool,
    ) -> Result<JournalSession, ValidationError> {
        let mut out = self.session.clone();
        out.observation_end_ns = cut;
        if finalized && out.admission_end_reason == "admission_open" {
            out.admission_end_reason = "close_unproved".to_string();
        }
        let map_indices: [i64; JOURNAL_COUNTER_COUNT] = [0, 1, 2, 3, 4, 6, 7, 8, 5, -1, -1];
        let ok = readable && counters.len() == JOURNAL_NATIVE_COUNTERS;
        for i in 0..JOURNAL_COUNTER_COUNT {
            let index = map_indices[i];
            // The fixed table only holds -1 or 0..9, so the guarded
            // casts below stay in range.
            if index >= 0 {
                out.counter_reasons[i] = "read_failed".to_string();
                if ok {
                    let native = counters[index as usize];
                    if counters[11] & (1u64 << (index as u32)) != 0 {
                        out.counter_reasons[i] = "overflow".to_string();
                    } else {
                        out.counters[i] = MaybeU64::of(native);
                        out.counter_reasons[i] = String::new();
                    }
                }
            }
        }
        out.counters[9] = MaybeU64::of(self.invalid_records);
        out.counter_reasons[9] = String::new();
        if !finalized {
            out.counters[4] = MaybeU64::absent();
            out.counter_reasons[4] = "not_observable".to_string();
        } else if ok && out.counters[4].has {
            if counters[12] > u64::MAX - counters[4] {
                out.counters[4] = MaybeU64::absent();
                out.counter_reasons[4] = "overflow".to_string();
            } else {
                out.counters[4] = MaybeU64::of(counters[4] + counters[12]);
            }
        }
        out.window(self.capture_start, finalized)?;
        Ok(out)
    }
}
