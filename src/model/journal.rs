// SPDX-License-Identifier: GPL-3.0-or-later
//! Frozen 0.2.0 conversion journal model: selection, admission, wire decode,
//! token budgets, and window membership.
//!
//! This is the Rust port of the source-reviewed provisional journal contract:
//! capability selection, declared-admission checks, the strict 72-byte MVJR
//! wire v1 decoder, signed-page normalization, caller classification, bounded
//! operation-token checks, and admission-window membership. Admission success
//! means `ready_for_attachment`, never actual attachment or platform
//! qualification.
//!
//! The C decoder in `bpf/include/memveil_journal.h` is the wire oracle: the
//! contract test decodes every native vector with both decoders and requires
//! field-for-field agreement. Normative prose lives in
//! `docs/conversion-journal.md`. All numbers below are frozen; the 0.2.0
//! journal family stays versioned as-is, separate from the 0.3.0 exposure
//! family.

use super::common::MaybeU64;
use super::validate::ValidationError;

/// Journal contract version carried by the 0.2.0 schemas.
pub const JOURNAL_SCHEMA_VERSION: &str = "0.2.0";
/// Accepted MVJR wire version.
pub const JOURNAL_WIRE_VERSION: u16 = 1;
/// Accepted MVJR wire kind: native wrapper result.
pub const JOURNAL_WIRE_KIND_RESULT: u16 = 1;
/// MVJR wire magic (`MVJR` in ASCII).
pub const JOURNAL_WIRE_MAGIC: u32 = 0x524A_564D;
/// Fixed MVJR wire record length in bytes.
pub const JOURNAL_WIRE_BYTES: usize = 72;
/// Matched-entry flag value; every other flag bit must be zero.
pub const JOURNAL_FLAG_MATCHED: u16 = 1;
/// Outstanding conversion operations retained across task stacks.
pub const OPERATION_CAPACITY: i64 = 4096;
/// Tracked nesting depths per task.
pub const NESTING_CAPACITY: i64 = 8;
/// Disjoint token intervals the replay history may track.
pub const REPLAY_TOKEN_INTERVAL_CAPACITY: u64 = 65536;
/// Transient caller frames resolved per sample when callers are enabled.
pub const CALLER_FRAME_CAPACITY: u64 = 16;
/// Default journal ring size in bytes.
pub const JOURNAL_RING_BYTES: u64 = 8388608;
/// Highest assignable operation token; the final u64 value is reserved for
/// exhaustion detection.
pub const OPERATION_TOKEN_MAX: u64 = 18446744073709551614;
/// Highest CPU id the wire accepts.
pub const JOURNAL_CPU_MAX: u32 = 1048575;
/// Source-profile page size in bytes; any other size is unadmitted.
pub const JOURNAL_PAGE_SIZE: u64 = 4096;

/// Capability selection: which channels a request asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalSelection {
    /// True when an ordinary channel (or the empty default) is requested.
    pub attempts: bool,
    /// True when `conversion-journal` is requested.
    pub journal: bool,
    /// True when bounded caller processing is requested.
    pub callers: bool,
}

/// Parse a capability list plus journal options into a selection.
///
/// The empty list keeps the ordinary attempt-only default. Duplicate or
/// unknown capability ids are usage errors, as are journal options without
/// the journal and a device filter on a journal-only request (conversion
/// scope is global).
pub fn select_journal(
    capabilities: &str,
    callers: bool,
    device: bool,
    journal_object: bool,
) -> Result<JournalSelection, ValidationError> {
    if capabilities.len() > 256 {
        return Err(ValidationError::new("capability", "selector too long"));
    }
    let mut journal = false;
    let mut ordinary = capabilities.is_empty();
    let mut seen: Vec<&str> = Vec::new();
    if !capabilities.is_empty() {
        for item in capabilities.split(',') {
            if seen.contains(&item) {
                return Err(ValidationError::new("capability", "duplicate"));
            }
            seen.push(item);
            if item == "conversion-journal" {
                journal = true;
            } else if item == "attempt-trace"
                || item == "mapping-lifecycle"
                || item == "copy-actual"
                || item == "conversion-observe"
            {
                ordinary = true;
            } else {
                return Err(ValidationError::new("capability", "unknown"));
            }
        }
    }
    if (callers || journal_object) && !journal {
        return Err(ValidationError::new(
            "journal option",
            "requires conversion-journal",
        ));
    }
    if journal && !ordinary && device {
        return Err(ValidationError::new(
            "device",
            "journal-only scope is global",
        ));
    }
    Ok(JournalSelection {
        attempts: ordinary,
        journal,
        callers,
    })
}

/// Declared-admission decision: an exit code plus a fixed reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalAdmission {
    /// 0 when every requested channel admits, else 3.
    pub exit_code: i32,
    /// Machine-stable reason; `ready_for_attachment` on success.
    pub reason: String,
}

/// Check declared admission only; attachment remains a separate gate.
///
/// Every explicitly requested channel must admit or the request refuses
/// with exit 3; an unrequested channel can never cause refusal. A zero
/// result means `ready_for_attachment`, never actual attachment.
pub fn journal_admission(
    selection: JournalSelection,
    attempts_admitted: bool,
    journal_status: &str,
    callers_admitted: bool,
) -> JournalAdmission {
    if selection.journal && journal_status != "admitted" {
        return JournalAdmission {
            exit_code: 3,
            reason: "journal_profile_not_admitted".to_string(),
        };
    }
    if selection.attempts && !attempts_admitted {
        return JournalAdmission {
            exit_code: 3,
            reason: "attempts_not_admitted".to_string(),
        };
    }
    if selection.callers && !callers_admitted {
        return JournalAdmission {
            exit_code: 3,
            reason: "journal_callers_not_admitted".to_string(),
        };
    }
    JournalAdmission {
        exit_code: 0,
        reason: "ready_for_attachment".to_string(),
    }
}

/// Requested bytes for a signed native page count.
///
/// Negative pages stay signed native metadata (the caller reports them as
/// null with `invalid_native_pages`); only the admitted page size converts.
pub fn requested_bytes(pages: i32, page_size: u64) -> Result<u64, ValidationError> {
    if pages < 0 {
        return Err(ValidationError::new(
            "requested_pages",
            "invalid_native_pages",
        ));
    }
    if page_size != JOURNAL_PAGE_SIZE {
        return Err(ValidationError::new("page_size", "unadmitted size"));
    }
    // Nonnegative i32 times 4096 always fits u64 (below 2^43).
    Ok(u64::from(pages as u32) * page_size)
}

/// Caller status for one entry sample: 0 disabled, 1 resolved, 2
/// unresolved, 3 ambiguous, 4 truncated.
pub fn classify_caller(
    enabled: bool,
    truncated: bool,
    class_count: i64,
    unique_labels: i64,
) -> i64 {
    if !enabled {
        return 0;
    }
    if truncated {
        return 4;
    }
    if class_count > 1 || unique_labels < 0 {
        return 3;
    }
    if class_count != 1 || unique_labels == 0 {
        return 2;
    }
    1
}

/// Next session-local operation token after `previous`.
///
/// Refuses when the active-operation budget, the nesting budget, or the
/// token space is exhausted. Wrapping is forbidden.
pub fn next_operation_token(
    previous: u64,
    active: i64,
    depth: i64,
) -> Result<u64, ValidationError> {
    if !(0..OPERATION_CAPACITY).contains(&active) {
        return Err(ValidationError::new("journal", "operation_exhaustion"));
    }
    if !(0..NESTING_CAPACITY).contains(&depth) {
        return Err(ValidationError::new("journal", "nesting_exhaustion"));
    }
    if previous >= OPERATION_TOKEN_MAX {
        return Err(ValidationError::new("journal", "token_exhaustion"));
    }
    Ok(previous + 1)
}

/// One decoded MVJR native wrapper result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalResult {
    /// Direction: 1 decrypt, 2 encrypt.
    pub direction: u16,
    /// CPU observed at exit.
    pub cpu: u32,
    /// Per-CPU transport sequence.
    pub sequence: u64,
    /// Exit monotonic nanoseconds.
    pub exit_ns: u64,
    /// Nonzero capture admission epoch.
    pub epoch: u64,
    /// Operation token; zero only for an unmatched exit.
    pub token: u64,
    /// Entry monotonic nanoseconds; zero for an unmatched exit.
    pub entry_ns: u64,
    /// Signed native requested pages.
    pub pages: i32,
    /// Signed native result; positive nonzero values are failures too.
    pub native_result: i32,
    /// Caller status 0-4.
    pub caller_status: u16,
    /// Caller class 0-3.
    pub caller_class: u16,
    /// Finite caller label code 0-10.
    pub caller_label: u16,
    /// True when an admitted entry backs this exit.
    pub matched: bool,
}

/// Little-endian unsigned read of `width` bytes at `offset`.
fn read_unsigned(raw: &[u8], offset: usize, width: usize) -> u64 {
    let mut value: u64 = 0;
    for i in 0..width {
        value |= u64::from(raw[offset + i]) << (8 * i);
    }
    value
}

/// Little-endian signed 32-bit read at `offset`.
///
/// Signed native values stay distinct from requested unsigned
/// measurements; the sign handling matches the C oracle exactly.
fn read_signed(raw: &[u8], offset: usize) -> i32 {
    let value = read_unsigned(raw, offset, 4);
    if value >= 0x8000_0000 {
        (value as i64 - 0x1_0000_0000) as i32
    } else {
        value as i32
    }
}

/// Caller class for a finite label code: labels 1-2 are owned, 3-6
/// swiotlb, 7-10 direct_dma, anything else unavailable.
pub fn caller_label_class(label: u16) -> u16 {
    if (1..=2).contains(&label) {
        1
    } else if (3..=6).contains(&label) {
        2
    } else if (7..=10).contains(&label) {
        3
    } else {
        0
    }
}

/// Strictly decode one 72-byte MVJR wire record.
///
/// Reads bytes at fixed offsets, never casting an unaligned native struct.
/// Rejects bad length, magic, version, kind, flags, direction, CPU,
/// caller triples, epoch/token contradictions, and matched/unmatched
/// entry inconsistencies before normalizing anything.
pub fn decode_journal(raw: &[u8]) -> Result<JournalResult, ValidationError> {
    if raw.len() != JOURNAL_WIRE_BYTES {
        return Err(ValidationError::new("journal wire", "length"));
    }
    if read_unsigned(raw, 0, 4) != u64::from(JOURNAL_WIRE_MAGIC) {
        return Err(ValidationError::new("journal wire", "magic"));
    }
    if read_unsigned(raw, 4, 2) != u64::from(JOURNAL_WIRE_VERSION) {
        return Err(ValidationError::new("journal wire", "version"));
    }
    if read_unsigned(raw, 6, 2) != u64::from(JOURNAL_WIRE_KIND_RESULT) {
        return Err(ValidationError::new("journal wire", "kind"));
    }
    let flags = read_unsigned(raw, 8, 2);
    let direction = read_unsigned(raw, 10, 2);
    let cpu = read_unsigned(raw, 12, 4);
    let status = read_unsigned(raw, 64, 2);
    let cls = read_unsigned(raw, 66, 2);
    let label = read_unsigned(raw, 68, 2);
    if flags > u64::from(JOURNAL_FLAG_MATCHED) || read_unsigned(raw, 70, 2) != 0 {
        return Err(ValidationError::new("journal wire", "flags/reserved"));
    }
    if !(1..=2).contains(&direction) || cpu > u64::from(JOURNAL_CPU_MAX) {
        return Err(ValidationError::new("journal wire", "direction/cpu"));
    }
    if status > 4 {
        return Err(ValidationError::new("journal wire", "caller status"));
    }
    if status == 1 {
        if cls == 0 || u64::from(caller_label_class(label as u16)) != cls {
            return Err(ValidationError::new("journal wire", "caller label/class"));
        }
    } else if cls != 0 || label != 0 {
        return Err(ValidationError::new("journal wire", "unavailable caller"));
    }
    let epoch = read_unsigned(raw, 32, 8);
    let token = read_unsigned(raw, 40, 8);
    let entry = read_unsigned(raw, 48, 8);
    let end = read_unsigned(raw, 24, 8);
    if epoch == 0 || token > OPERATION_TOKEN_MAX {
        return Err(ValidationError::new("journal wire", "epoch/token"));
    }
    if flags == u64::from(JOURNAL_FLAG_MATCHED) {
        if token == 0 || entry > end {
            return Err(ValidationError::new("journal wire", "matched entry"));
        }
    } else if token != 0 || entry != 0 {
        return Err(ValidationError::new("journal wire", "unmatched exit"));
    }
    Ok(JournalResult {
        direction: direction as u16,
        cpu: cpu as u32,
        sequence: read_unsigned(raw, 16, 8),
        exit_ns: end,
        epoch,
        token,
        entry_ns: entry,
        pages: read_signed(raw, 56),
        native_result: read_signed(raw, 60),
        caller_status: status as u16,
        caller_class: cls as u16,
        caller_label: label as u16,
        matched: flags == u64::from(JOURNAL_FLAG_MATCHED),
    })
}

/// Check one result against an explicit admission window.
///
/// The exit must land in the half-open observation window; a matched
/// entry must land in the half-open admission window.
pub fn validate_membership(
    result: &JournalResult,
    epoch: u64,
    start: u64,
    cutoff: u64,
    end: u64,
) -> Result<(), ValidationError> {
    if epoch == 0 || result.epoch != epoch || start > cutoff || cutoff > end {
        return Err(ValidationError::new("journal window", "epoch/bounds"));
    }
    if result.exit_ns < start || result.exit_ns >= end {
        return Err(ValidationError::new(
            "journal window",
            "exit outside observation",
        ));
    }
    if result.matched && (result.entry_ns < start || result.entry_ns >= cutoff) {
        return Err(ValidationError::new(
            "journal window",
            "entry outside admission",
        ));
    }
    Ok(())
}

/// Nullable admission evidence, independent of the capture/prefix clock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalWindow {
    /// Nonzero capture admission epoch.
    pub epoch: u64,
    /// Observed capture start on the capture clock.
    pub capture_start: u64,
    /// Verified prefix cut on the capture clock, not settled closure.
    pub observation_end: u64,
    /// Actual admission start once the checkpoint is durable.
    pub start: MaybeU64,
    /// Actual admission end once entry admission closes.
    pub cutoff: MaybeU64,
    /// Null reason for a known start; otherwise the unknown-start state.
    pub start_reason: String,
    /// Null reason for a known end; otherwise the open/unknown state.
    pub end_reason: String,
    /// True once the capture finalized.
    pub finalized: bool,
}

impl JournalWindow {
    /// Validate the window state without turning a prefix cut into
    /// closure proof.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.epoch == 0 || self.capture_start > self.observation_end {
            return Err(ValidationError::new(
                "journal window",
                "epoch/prefix bounds",
            ));
        }
        if !self.start.has {
            if self.cutoff.has {
                return Err(ValidationError::new("journal window", "end without start"));
            }
            if self.start_reason == "not_opened" && self.end_reason == "not_opened" {
                return Ok(());
            }
            if self.start_reason == "readiness_unproved" && self.end_reason == "close_unproved" {
                return Ok(());
            }
            return Err(ValidationError::new(
                "journal window",
                "unknown start reason",
            ));
        }
        if !self.start_reason.is_empty()
            || self.start.value < self.capture_start
            || self.start.value > self.observation_end
        {
            return Err(ValidationError::new("journal window", "admission start"));
        }
        if self.cutoff.has {
            if !self.end_reason.is_empty()
                || self.cutoff.value < self.start.value
                || self.cutoff.value > self.observation_end
            {
                return Err(ValidationError::new("journal window", "admission end"));
            }
        } else if self.finalized {
            if self.end_reason != "close_unproved" {
                return Err(ValidationError::new(
                    "journal window",
                    "unknown final close",
                ));
            }
        } else if self.end_reason != "admission_open" {
            return Err(ValidationError::new(
                "journal window",
                "open admission reason",
            ));
        }
        Ok(())
    }

    /// Validate one result against this window.
    ///
    /// No result may precede readiness; a matched entry must land in the
    /// half-open admission window (or below the verified prefix cut while
    /// admission stays open).
    pub fn validate_result(&self, result: &JournalResult) -> Result<(), ValidationError> {
        self.validate()?;
        if result.epoch != self.epoch
            || result.exit_ns < self.capture_start
            || result.exit_ns >= self.observation_end
        {
            return Err(ValidationError::new(
                "journal window",
                "result epoch/prefix",
            ));
        }
        if self.start_reason == "not_opened" {
            return Err(ValidationError::new(
                "journal window",
                "result before readiness",
            ));
        }
        if result.matched {
            if !self.start.has {
                return Err(ValidationError::new(
                    "journal window",
                    "unproved admitted entry",
                ));
            }
            let mut ceiling = self.observation_end;
            if self.cutoff.has {
                ceiling = self.cutoff.value;
            }
            if result.entry_ns < self.start.value || result.entry_ns >= ceiling {
                return Err(ValidationError::new(
                    "journal window",
                    "entry outside admission",
                ));
            }
        }
        Ok(())
    }
}
