// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed conversion-journal event payload for the frozen 0.2.0 schemas.
//!
//! A journal event is a request-only result record: direction, signed
//! native page metadata, operation token, admission membership, and
//! caller evidence. Legacy region layouts stay separate; this module
//! owns only the journal `data` object. It also owns the small
//! closed-object JSON helpers shared with the journal session parser
//! (kept here at ~140 lines rather than a second module).
//!
//! Wire selection, admission, decoding, token budgets, and window
//! membership live in [`super::journal`]; this module calls them and
//! never reimplements them.

use super::common::MaybeU64;
use super::encode::quote_json;
use super::journal::{JournalResult, OPERATION_TOKEN_MAX, caller_label_class};
use super::scan::{
    Scanner, expect_colon, object_is_empty, object_next, parse_nullable_string, parse_nullable_u64,
};
use super::validate::{ValidationError, format_u64};
use std::collections::HashMap;

/// Read a closed object into deferred value spans.
///
/// Every name in `names` must appear exactly once; unknown or
/// duplicate keys refuse. Values stay borrowed spans for the
/// per-field readers below.
pub(crate) fn fields<'a>(
    scan: &mut Scanner<'a>,
    names: &[&str],
) -> Result<HashMap<String, &'a [u8]>, ValidationError> {
    let mut out: HashMap<String, &'a [u8]> = HashMap::new();
    scan.begin_object("journal")?;
    if !object_is_empty(scan, "journal")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("journal")?;
            if !names.contains(&key.as_str()) || out.contains_key(&key) {
                return Err(ValidationError::new(
                    "journal",
                    "unknown or duplicate field",
                ));
            }
            expect_colon(scan, "journal")?;
            let start = scan.offset();
            scan.skip_value("journal")?;
            let span = scan.span_bytes("journal", start, scan.offset())?;
            out.insert(key, span);
            if !object_next(scan, "journal")? {
                break;
            }
        }
    }
    scan.end_object("journal")?;
    if out.len() != names.len() {
        return Err(ValidationError::new("journal", "missing field"));
    }
    Ok(out)
}

/// Read a JSON string span; nullable spans map null to empty.
///
/// An explicitly empty nullable string refuses: absence is null,
/// never `""`.
pub(crate) fn text(span: &[u8], nullable: bool) -> Result<String, ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    if nullable {
        match parse_nullable_string(&mut scan, "journal")? {
            None => Ok(String::new()),
            Some(value) => {
                if value.is_empty() {
                    return Err(ValidationError::new("journal", "empty nullable string"));
                }
                Ok(value)
            }
        }
    } else {
        scan.parse_string("journal")
    }
}

/// Read a canonical-u64 JSON string span or null.
pub(crate) fn uint(span: &[u8]) -> Result<MaybeU64, ValidationError> {
    parse_nullable_u64(&mut Scanner::new(span), "journal")
}

/// Read a required canonical-u64 JSON string span.
pub(crate) fn required_uint(span: &[u8]) -> Result<u64, ValidationError> {
    let result = uint(span)?;
    if !result.has {
        return Err(ValidationError::new("journal", "unexpected null count"));
    }
    Ok(result.value)
}

/// Read a JSON integer span into the signed native range.
pub(crate) fn native_int(span: &[u8]) -> Result<i32, ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    let value = scan.parse_int("integer")?;
    if value < i64::from(i32::MIN) || value > i64::from(i32::MAX) {
        return Err(ValidationError::new("journal", "native int32 range"));
    }
    Ok(value as i32)
}

/// Read a JSON boolean span.
pub(crate) fn boolean(span: &[u8]) -> Result<bool, ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    scan.parse_bool("journal")
}

/// Require a JSON null span.
pub(crate) fn null_value(span: &[u8]) -> Result<(), ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    scan.parse_null("journal")
}

/// Render an empty-means-absent string as null or quoted text.
pub(crate) fn nullable_text(value: &str) -> String {
    if value.is_empty() {
        "null".to_string()
    } else {
        quote_json(value)
    }
}

/// Render a nullable u64 as a quoted canonical decimal or null.
pub(crate) fn nullable_uint(value: &MaybeU64) -> String {
    if value.has {
        quote_json(&format_u64(value.value))
    } else {
        "null".to_string()
    }
}

/// Render one `"key":value` member with a quoted key.
pub(crate) fn member(key: &str, value: &str) -> String {
    quote_json(key) + ":" + value
}

/// Render members as one compact JSON object.
pub(crate) fn object_text(parts: &[String]) -> String {
    let mut out = String::from("{");
    for (i, part) in parts.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(part);
    }
    out.push('}');
    out
}

/// Finite caller label names by code; code 0 and codes past 10 are
/// unavailable.
const CALLER_LABELS: [&str; 11] = [
    "",
    "mv_command_set [memveil_region_oracle]",
    "mv_restore [memveil_region_oracle]",
    "swiotlb_init_late",
    "swiotlb_alloc_tlb",
    "swiotlb_free_tlb",
    "swiotlb_exit",
    "dma_set_decrypted",
    "dma_set_encrypted",
    "dma_direct_alloc",
    "dma_direct_free",
];

/// Caller status names by code; codes past 4 are unavailable.
const CALLER_STATUSES: [&str; 5] = [
    "disabled",
    "resolved",
    "unresolved",
    "ambiguous",
    "truncated",
];

/// Caller class names by code; code 0 is unavailable.
const CALLER_CLASSES: [&str; 4] = ["", "owned", "swiotlb", "direct_dma"];

/// Caller label name for a finite code, or empty when unavailable.
pub fn caller_label(code: u16) -> &'static str {
    if code <= 10 {
        CALLER_LABELS[code as usize]
    } else {
        ""
    }
}

/// Caller status name for a finite code, or empty when unavailable.
pub fn caller_status(code: u16) -> &'static str {
    if code < 5 {
        CALLER_STATUSES[code as usize]
    } else {
        ""
    }
}

/// Caller class name for a finite code, or empty when unavailable.
pub fn caller_class(code: u16) -> &'static str {
    if code < 4 {
        CALLER_CLASSES[code as usize]
    } else {
        ""
    }
}

/// One typed request-only journal event payload.
///
/// The struct carries the journal `data` members; fixed contract
/// constants (page size, region state, effect) are checked on parse
/// and re-emitted on encode rather than stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalEvent {
    /// Direction enum: `decrypt` or `encrypt`.
    pub direction: String,
    /// Signed native requested pages; negative stays unavailable.
    pub requested_native_pages: i32,
    /// Requested pages; absent when native pages are invalid.
    pub requested_pages: MaybeU64,
    /// Requested bytes; absent when native pages are invalid.
    pub requested_bytes: MaybeU64,
    /// Null reason for unavailable sizes; empty when known.
    pub size_reason: String,
    /// Signed native result; any nonzero value is a failure.
    pub native_result: i32,
    /// Operation token; present only for admitted membership.
    pub operation_token: MaybeU64,
    /// Entry nanoseconds; present only for admitted membership.
    pub entry_ns: MaybeU64,
    /// Nonzero capture admission epoch.
    pub epoch: u64,
    /// Membership enum: `admitted` or `unmatched_exit`.
    pub membership: String,
    /// Caller status enum.
    pub caller_status: String,
    /// Caller class; empty unless resolved.
    pub caller_class: String,
    /// Caller label; empty unless resolved.
    pub caller_label: String,
}

impl Default for JournalEvent {
    fn default() -> Self {
        Self {
            direction: "decrypt".to_string(),
            requested_native_pages: 0,
            requested_pages: MaybeU64::absent(),
            requested_bytes: MaybeU64::absent(),
            size_reason: String::new(),
            native_result: 0,
            operation_token: MaybeU64::absent(),
            entry_ns: MaybeU64::absent(),
            epoch: 0,
            membership: "unmatched_exit".to_string(),
            caller_status: "disabled".to_string(),
            caller_class: String::new(),
            caller_label: String::new(),
        }
    }
}

impl JournalEvent {
    /// Validate the payload against the 0.2.0 event contract.
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.direction != "decrypt" && self.direction != "encrypt" {
            return Err(ValidationError::new("journal", "direction"));
        }
        if self.epoch == 0 {
            return Err(ValidationError::new("journal", "epoch"));
        }
        if self.requested_native_pages < 0 {
            if self.requested_pages.has
                || self.requested_bytes.has
                || self.size_reason != "invalid_native_pages"
            {
                return Err(ValidationError::new(
                    "journal",
                    "invalid pages must remain unavailable",
                ));
            }
        } else if !self.requested_pages.has
            || !self.requested_bytes.has
            || !self.size_reason.is_empty()
            || self.requested_pages.value != self.requested_native_pages as u64
            || self.requested_bytes.value != self.requested_native_pages as u64 * 4096
        {
            return Err(ValidationError::new(
                "journal",
                "requested size disagreement",
            ));
        }
        if self.membership == "admitted" {
            if !self.operation_token.has
                || !self.entry_ns.has
                || self.operation_token.value == 0
                || self.operation_token.value > OPERATION_TOKEN_MAX
            {
                return Err(ValidationError::new("journal", "admitted token"));
            }
        } else if self.membership != "unmatched_exit"
            || self.operation_token.has
            || self.entry_ns.has
        {
            return Err(ValidationError::new("journal", "unmatched token"));
        }
        if !CALLER_STATUSES.contains(&self.caller_status.as_str()) {
            return Err(ValidationError::new("journal", "caller status"));
        }
        if self.caller_status != "resolved" {
            if !self.caller_class.is_empty() || !self.caller_label.is_empty() {
                return Err(ValidationError::new("journal", "unavailable caller label"));
            }
        } else {
            let mut valid = false;
            for code in 1..=10u16 {
                if self.caller_label == caller_label(code)
                    && self.caller_class == caller_class(caller_label_class(code))
                {
                    valid = true;
                }
            }
            if !valid {
                return Err(ValidationError::new("journal", "caller label/class"));
            }
        }
        Ok(())
    }

    /// Convert a validated event into a window-checkable result.
    ///
    /// The entry must not postdate the exit; the typed layer owns no
    /// transport sequence, so the result carries sequence zero.
    pub fn to_result(&self, exit_ns: u64, cpu: u32) -> Result<JournalResult, ValidationError> {
        self.validate()?;
        if self.entry_ns.has && self.entry_ns.value > exit_ns {
            return Err(ValidationError::new("journal", "entry after result"));
        }
        let mut status = 0u16;
        for (code, name) in CALLER_STATUSES.iter().enumerate() {
            if self.caller_status == *name {
                status = code as u16;
            }
        }
        let mut label = 0u16;
        for code in 1..=10u16 {
            if self.caller_label == caller_label(code) {
                label = code;
            }
        }
        Ok(JournalResult {
            direction: if self.direction == "decrypt" { 1 } else { 2 },
            cpu,
            sequence: 0,
            exit_ns,
            epoch: self.epoch,
            token: if self.operation_token.has {
                self.operation_token.value
            } else {
                0
            },
            entry_ns: if self.entry_ns.has {
                self.entry_ns.value
            } else {
                0
            },
            pages: self.requested_native_pages,
            native_result: self.native_result,
            caller_status: status,
            caller_class: caller_label_class(label),
            caller_label: label,
            matched: self.membership == "admitted",
        })
    }
}

/// Parse one journal `data` object from the event cursor.
pub(crate) fn parse_journal_event(scan: &mut Scanner) -> Result<JournalEvent, ValidationError> {
    let f = fields(
        scan,
        &[
            "direction",
            "requested_state",
            "requested_native_pages",
            "requested_pages",
            "requested_bytes",
            "size_reason",
            "page_size",
            "native_result",
            "operation_token",
            "entry_ns",
            "epoch",
            "membership",
            "region",
            "region_reason",
            "effect",
            "caller",
        ],
    )?;
    let direction = text(f["direction"], false)?;
    let requested_native_pages = native_int(f["requested_native_pages"])?;
    let requested_pages = uint(f["requested_pages"])?;
    let requested_bytes = uint(f["requested_bytes"])?;
    let size_reason = text(f["size_reason"], true)?;
    let native_result = native_int(f["native_result"])?;
    let operation_token = uint(f["operation_token"])?;
    let entry_ns = uint(f["entry_ns"])?;
    let epoch = required_uint(f["epoch"])?;
    let membership = text(f["membership"], false)?;
    null_value(f["region"])?;
    let want_state = if direction == "decrypt" {
        "shared"
    } else {
        "private"
    };
    if text(f["page_size"], false)? != "4096"
        || text(f["effect"], false)? != "request_only"
        || text(f["region_reason"], false)? != "request_only_source"
        || text(f["requested_state"], false)? != want_state
    {
        return Err(ValidationError::new(
            "journal",
            "request-only source contract",
        ));
    }
    let mut callers = Scanner::new(f["caller"]);
    let c = fields(&mut callers, &["status", "class", "label"])?;
    let out = JournalEvent {
        direction,
        requested_native_pages,
        requested_pages,
        requested_bytes,
        size_reason,
        native_result,
        operation_token,
        entry_ns,
        epoch,
        membership,
        caller_status: text(c["status"], false)?,
        caller_class: text(c["class"], true)?,
        caller_label: text(c["label"], true)?,
    };
    out.validate()?;
    Ok(out)
}

/// Encode one journal `data` object in canonical member order.
pub(crate) fn encode_journal_event(value: &JournalEvent) -> Result<String, ValidationError> {
    value.validate()?;
    let mut p: Vec<String> = Vec::new();
    p.push(member("direction", &quote_json(&value.direction)));
    p.push(member(
        "requested_state",
        &quote_json(if value.direction == "decrypt" {
            "shared"
        } else {
            "private"
        }),
    ));
    p.push(member(
        "requested_native_pages",
        &value.requested_native_pages.to_string(),
    ));
    p.push(member(
        "requested_pages",
        &nullable_uint(&value.requested_pages),
    ));
    p.push(member(
        "requested_bytes",
        &nullable_uint(&value.requested_bytes),
    ));
    p.push(member("size_reason", &nullable_text(&value.size_reason)));
    p.push("\"page_size\":\"4096\"".to_string());
    p.push(member("native_result", &value.native_result.to_string()));
    p.push(member(
        "operation_token",
        &nullable_uint(&value.operation_token),
    ));
    p.push(member("entry_ns", &nullable_uint(&value.entry_ns)));
    p.push(member("epoch", &quote_json(&format_u64(value.epoch))));
    p.push(member("membership", &quote_json(&value.membership)));
    p.push(
        "\"region\":null,\"region_reason\":\"request_only_source\",\"effect\":\"request_only\""
            .to_string(),
    );
    let c = [
        member("status", &quote_json(&value.caller_status)),
        member("class", &nullable_text(&value.caller_class)),
        member("label", &nullable_text(&value.caller_label)),
    ];
    p.push(member("caller", &object_text(&c)));
    Ok(object_text(&p))
}
