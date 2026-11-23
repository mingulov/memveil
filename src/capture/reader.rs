// SPDX-License-Identifier: GPL-3.0-or-later
//! Streaming bounded capture reader: session.json plus events.ndjson.
//!
//! A capture directory holds session.json and events.ndjson. The reader
//! enforces byte limits while parsing: the session document is read whole
//! (16 MiB bound), while events stream in 64 KiB chunks, so resident memory
//! stays O(chunk + longest line) no matter how large the file is. Line
//! splitting and both byte bounds match the schema validator's line iterator
//! exactly: a line's content plus its newline terminator must fit
//! max_line_bytes, and total consumed bytes (including terminators) must fit
//! max_events_bytes.
//!
//! Lines parse lazily in order; every event must match the session ID, carry
//! a strictly increasing sequence number, and land inside the half-open
//! session window.
//!
//! Legacy input alone permits allow_partial to recover a truncated tail, and
//! only for the final record when the file lacks a trailing newline: a tail
//! that is a clean truncation (the classifier says incomplete) is dropped,
//! reported via partial, and never silently repaired. A final record that
//! parses but lacks its trailing newline is a framing error in both modes,
//! and so is an unterminated tail that is corrupt rather than truncated.
//! Interior corruption is always an error, as is a terminated final line
//! that fails to parse.
//!
//! A bare carriage return before a newline is tolerated because it is JSON
//! whitespace; anything else strict fails.
//!
//! Integrity-bearing streams bind literal bytes, counts, kinds and
//! contiguous sequences before integrity_verified becomes true at checked
//! EOF.

use crate::model::event::{
    EVENT_SCHEMA_VERSION, Event, parse_data_span, parse_event, parse_observer,
    parse_snapshot_scope, parse_source,
};
use crate::model::integrity::{
    INTEGRITY_KIND_COUNT, Integrity, integrity_kind, integrity_kind_index,
};
use crate::model::scan::Scanner;
use crate::model::session::{Session, parse_session};
use crate::model::validate::{ValidationError, checked_add};
use crate::platform::capturefiles::{RecoveryFiles, file_stat};
use crate::platform::hash::Sha256;
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

/// I/O failure reading the capture.
pub const READ_IO: u32 = 1;
/// A byte bound refused the capture.
pub const READ_TOO_BIG: u32 = 2;
/// Session or event bytes failed to parse.
pub const READ_PARSE: u32 = 3;
/// Parsed bytes contradict the capture contract.
pub const READ_INVALID: u32 = 4;

/// Default session-document bound (16 MiB).
pub const DEFAULT_MAX_SESSION_BYTES: usize = 16777216;
/// Default event-line bound (64 KiB).
pub const DEFAULT_MAX_LINE_BYTES: usize = 65536;
/// Default event-stream bound (1 GiB).
pub const DEFAULT_MAX_EVENTS_BYTES: usize = 1073741824;

/// Tail verdict: the bytes hold exactly one JSON value.
pub const TAIL_COMPLETE: u8 = 0;
/// Tail verdict: the bytes could still grow into one value.
pub const TAIL_INCOMPLETE: u8 = 1;
/// Tail verdict: definite corruption.
pub const TAIL_INVALID: u8 = 2;
/// Nesting depth cap shared with the model scanners.
pub const MAX_TAIL_DEPTH: usize = 64;

/// One capture-read failure. Callers match on code, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    /// Machine-stable failure code (`READ_*`).
    pub code: u32,
    /// 1-based event line, or 0 for session/stream-level failures.
    pub line_no: usize,
    /// Human detail; matched only by [`read_remedy`] over the
    /// fixed open-failure causes below.
    pub message: String,
}

/// Remedy line for a capture-open failure cause, when one applies.
///
/// Matches the fixed open-failure causes exactly (plus the two
/// member-ownership spellings by suffix): those strings carry no
/// caller bytes, so the CLI prints both lines unscrubbed.
/// Mid-stream and parse failures may echo capture bytes and stay
/// single-line.
pub fn read_remedy(cause: &str) -> Option<&'static str> {
    match cause {
        "capture directory does not exist" => {
            Some("check the path spelling and retry with an existing capture directory")
        }
        "capture path is not a directory" => {
            Some("pass a capture directory (a directory holding session.json and events.ndjson)")
        }
        "capture directory not owned by reader" => Some(
            "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
        ),
        "not a memveil capture: expected session.json/events.ndjson" => {
            Some("pass a capture directory (session.json and events.ndjson)")
        }
        "capture directory is inaccessible or a symlink" => {
            Some("check read access to every path component and that none is a symlink")
        }
        "cannot establish final session absence" => {
            Some("check read access to the capture path and retry")
        }
        "cannot establish absence of final session" => {
            Some("check read access to the capture path and retry")
        }
        _ => {
            if cause.ends_with(": not owned by reader") {
                Some(
                    "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
                )
            } else {
                None
            }
        }
    }
}

/// Byte limits for one read_capture call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReaderLimits {
    /// Session-document bound in bytes.
    pub max_session_bytes: usize,
    /// Event-line bound in bytes (content plus terminator).
    pub max_line_bytes: usize,
    /// Event-stream bound in bytes (including terminators).
    pub max_events_bytes: usize,
}

/// The default reader limits.
pub fn default_limits() -> ReaderLimits {
    ReaderLimits {
        max_session_bytes: DEFAULT_MAX_SESSION_BYTES,
        max_line_bytes: DEFAULT_MAX_LINE_BYTES,
        max_events_bytes: DEFAULT_MAX_EVENTS_BYTES,
    }
}

/// One object member with key/value byte spans and verdicts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TailMember {
    /// Key token start offset.
    pub key_start: usize,
    /// Key token end offset.
    pub key_end: usize,
    /// Key token verdict.
    pub key_verdict: u8,
    /// Value token start offset.
    pub val_start: usize,
    /// Value token end offset.
    pub val_end: usize,
    /// Value token verdict.
    pub val_verdict: u8,
}

fn tail_is_ws(b: u8) -> bool {
    b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
}

fn tail_skip_ws(data: &[u8], pos: &mut usize) {
    while *pos < data.len() && tail_is_ws(data[*pos]) {
        *pos += 1;
    }
}

fn tail_expect(data: &[u8], pos: &mut usize, want: u8) -> u8 {
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    if data[*pos] != want {
        return TAIL_INVALID;
    }
    *pos += 1;
    TAIL_COMPLETE
}

fn tail_string(data: &[u8], pos: &mut usize) -> u8 {
    *pos += 1;
    loop {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        let b = data[*pos];
        if b == 0x22 {
            *pos += 1;
            return TAIL_COMPLETE;
        }
        if b == 0x5C {
            let esc = tail_escape(data, pos);
            if esc != TAIL_COMPLETE {
                return esc;
            }
            continue;
        }
        if b < 0x20 {
            return TAIL_INVALID;
        }
        if b < 0x80 {
            *pos += 1;
            continue;
        }
        let uni = tail_utf8(data, pos);
        if uni != TAIL_COMPLETE {
            return uni;
        }
    }
}

fn tail_escape(data: &[u8], pos: &mut usize) -> u8 {
    *pos += 1;
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    let e = data[*pos];
    *pos += 1;
    if e == 0x22
        || e == 0x5C
        || e == 0x2F
        || e == 0x62
        || e == 0x66
        || e == 0x6E
        || e == 0x72
        || e == 0x74
    {
        return TAIL_COMPLETE;
    }
    if e != 0x75 {
        return TAIL_INVALID;
    }
    for _ in 0..4 {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        let h = data[*pos];
        let ok =
            (0x30..=0x39).contains(&h) || (0x41..=0x46).contains(&h) || (0x61..=0x66).contains(&h);
        if !ok {
            return TAIL_INVALID;
        }
        *pos += 1;
    }
    TAIL_COMPLETE
}

fn tail_utf8(data: &[u8], pos: &mut usize) -> u8 {
    let b0 = data[*pos];
    let (want, lo, hi): (usize, u8, u8) = if (0xC2..=0xDF).contains(&b0) {
        (1, 0x80, 0xBF)
    } else if b0 == 0xE0 {
        (2, 0xA0, 0xBF)
    } else if (0xE1..=0xEC).contains(&b0) {
        (2, 0x80, 0xBF)
    } else if b0 == 0xED {
        (2, 0x80, 0x9F)
    } else if (0xEE..=0xEF).contains(&b0) {
        (2, 0x80, 0xBF)
    } else if b0 == 0xF0 {
        (3, 0x90, 0xBF)
    } else if (0xF1..=0xF3).contains(&b0) {
        (3, 0x80, 0xBF)
    } else if b0 == 0xF4 {
        (3, 0x80, 0x8F)
    } else {
        return TAIL_INVALID;
    };
    *pos += 1;
    for i in 0..want {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        let c = data[*pos];
        let (floor, ceil) = if i == 0 { (lo, hi) } else { (0x80, 0xBF) };
        if c < floor || c > ceil {
            return TAIL_INVALID;
        }
        *pos += 1;
    }
    TAIL_COMPLETE
}

fn tail_number(data: &[u8], pos: &mut usize) -> u8 {
    if data[*pos] == 0x2D {
        *pos += 1;
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
    }
    let first = data[*pos];
    if !(0x30..=0x39).contains(&first) {
        return TAIL_INVALID;
    }
    if first == 0x30 {
        *pos += 1;
    } else {
        while *pos < data.len() && (0x30..=0x39).contains(&data[*pos]) {
            *pos += 1;
        }
    }
    if *pos < data.len() {
        let nxt = data[*pos];
        if first == 0x30 && (0x30..=0x39).contains(&nxt) {
            return TAIL_INVALID;
        }
    }
    if *pos < data.len() && data[*pos] == 0x2E {
        *pos += 1;
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if !(0x30..=0x39).contains(&data[*pos]) {
            return TAIL_INVALID;
        }
        while *pos < data.len() && (0x30..=0x39).contains(&data[*pos]) {
            *pos += 1;
        }
    }
    if *pos < data.len() && (data[*pos] == 0x65 || data[*pos] == 0x45) {
        *pos += 1;
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] == 0x2B || data[*pos] == 0x2D {
            *pos += 1;
            if *pos >= data.len() {
                return TAIL_INCOMPLETE;
            }
        }
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if !(0x30..=0x39).contains(&data[*pos]) {
            return TAIL_INVALID;
        }
        while *pos < data.len() && (0x30..=0x39).contains(&data[*pos]) {
            *pos += 1;
        }
    }
    TAIL_COMPLETE
}

fn tail_literal(data: &[u8], pos: &mut usize, word: &[u8]) -> u8 {
    for &w in word {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] != w {
            return TAIL_INVALID;
        }
        *pos += 1;
    }
    TAIL_COMPLETE
}

fn tail_value(data: &[u8], pos: &mut usize, depth: usize, max_depth: usize) -> u8 {
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    let b = data[*pos];
    if b == 0x22 {
        return tail_string(data, pos);
    }
    if b == 0x7B {
        return tail_object(data, pos, depth, max_depth);
    }
    if b == 0x5B {
        return tail_array(data, pos, depth, max_depth);
    }
    if b == 0x74 {
        return tail_literal(data, pos, b"true");
    }
    if b == 0x66 {
        return tail_literal(data, pos, b"false");
    }
    if b == 0x6E {
        return tail_literal(data, pos, b"null");
    }
    if b == 0x2D || (0x30..=0x39).contains(&b) {
        return tail_number(data, pos);
    }
    TAIL_INVALID
}

fn tail_object(data: &[u8], pos: &mut usize, depth: usize, max_depth: usize) -> u8 {
    if depth + 1 > max_depth {
        return TAIL_INVALID;
    }
    *pos += 1;
    tail_skip_ws(data, pos);
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    if data[*pos] == 0x7D {
        *pos += 1;
        return TAIL_COMPLETE;
    }
    loop {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] != 0x22 {
            return TAIL_INVALID;
        }
        let key = tail_string(data, pos);
        if key != TAIL_COMPLETE {
            return key;
        }
        tail_skip_ws(data, pos);
        let colon = tail_expect(data, pos, 0x3A);
        if colon != TAIL_COMPLETE {
            return colon;
        }
        tail_skip_ws(data, pos);
        let val = tail_value(data, pos, depth + 1, max_depth);
        if val != TAIL_COMPLETE {
            return val;
        }
        tail_skip_ws(data, pos);
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] == 0x2C {
            *pos += 1;
            tail_skip_ws(data, pos);
            continue;
        }
        if data[*pos] == 0x7D {
            *pos += 1;
            return TAIL_COMPLETE;
        }
        return TAIL_INVALID;
    }
}

fn tail_array(data: &[u8], pos: &mut usize, depth: usize, max_depth: usize) -> u8 {
    if depth + 1 > max_depth {
        return TAIL_INVALID;
    }
    *pos += 1;
    tail_skip_ws(data, pos);
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    if data[*pos] == 0x5D {
        *pos += 1;
        return TAIL_COMPLETE;
    }
    loop {
        let val = tail_value(data, pos, depth + 1, max_depth);
        if val != TAIL_COMPLETE {
            return val;
        }
        tail_skip_ws(data, pos);
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] == 0x2C {
            *pos += 1;
            tail_skip_ws(data, pos);
            continue;
        }
        if data[*pos] == 0x5D {
            *pos += 1;
            return TAIL_COMPLETE;
        }
        return TAIL_INVALID;
    }
}

/// Scan one object's members, recording complete-key spans.
///
/// pos must be at `{`. Members whose key token is complete append to out,
/// even when the colon or value is cut off (with an empty or partial value
/// span); the scan stops at the first incomplete key, the closing brace, or
/// a definite syntax error, and returns the object verdict. Depth
/// accounting matches tail_object exactly, so verdicts agree with
/// classify_tail on the same bytes.
pub fn tail_scan_members(
    data: &[u8],
    pos: &mut usize,
    depth: usize,
    max_depth: usize,
    out: &mut Vec<TailMember>,
) -> u8 {
    if depth + 1 > max_depth {
        return TAIL_INVALID;
    }
    *pos += 1;
    tail_skip_ws(data, pos);
    if *pos >= data.len() {
        return TAIL_INCOMPLETE;
    }
    if data[*pos] == 0x7D {
        *pos += 1;
        return TAIL_COMPLETE;
    }
    loop {
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] != 0x22 {
            return TAIL_INVALID;
        }
        let mut m = TailMember {
            key_start: *pos,
            key_end: *pos,
            key_verdict: TAIL_INVALID,
            val_start: *pos,
            val_end: *pos,
            val_verdict: TAIL_INVALID,
        };
        m.key_verdict = tail_string(data, pos);
        m.key_end = *pos;
        if m.key_verdict != TAIL_COMPLETE {
            return m.key_verdict;
        }
        tail_skip_ws(data, pos);
        let colon = tail_expect(data, pos, 0x3A);
        if colon != TAIL_COMPLETE {
            // The key is complete even though its value never starts:
            // expose it so duplicate/unknown-key checks see it, with an
            // empty value span.
            m.val_start = *pos;
            m.val_end = *pos;
            m.val_verdict = TAIL_INCOMPLETE;
            out.push(m);
            return colon;
        }
        tail_skip_ws(data, pos);
        m.val_start = *pos;
        m.val_verdict = tail_value(data, pos, depth + 1, max_depth);
        m.val_end = *pos;
        let verdict = m.val_verdict;
        out.push(m);
        if verdict != TAIL_COMPLETE {
            return verdict;
        }
        tail_skip_ws(data, pos);
        if *pos >= data.len() {
            return TAIL_INCOMPLETE;
        }
        if data[*pos] == 0x2C {
            *pos += 1;
            tail_skip_ws(data, pos);
            continue;
        }
        if data[*pos] == 0x7D {
            *pos += 1;
            return TAIL_COMPLETE;
        }
        return TAIL_INVALID;
    }
}

/// Classify final-record bytes without raising.
///
/// Returns TAIL_COMPLETE when the bytes hold exactly one JSON value,
/// TAIL_INCOMPLETE when the bytes could still grow into one (input ended
/// mid-value), and TAIL_INVALID for definite corruption. Framing only:
/// complete values may still fail schema validation downstream, and
/// surrogate pairing is not checked here.
pub fn classify_tail(data: &[u8]) -> u8 {
    classify_tail_depth(data, MAX_TAIL_DEPTH)
}

fn classify_tail_depth(data: &[u8], max_depth: usize) -> u8 {
    let mut pos = 0;
    tail_skip_ws(data, &mut pos);
    if pos >= data.len() {
        return TAIL_INVALID;
    }
    let val = tail_value(data, &mut pos, 0, max_depth);
    if val != TAIL_COMPLETE {
        return val;
    }
    tail_skip_ws(data, &mut pos);
    if pos >= data.len() {
        return TAIL_COMPLETE;
    }
    TAIL_INVALID
}

/// Mirror of parse_event's accepted top-level keys.
fn top_field_known(key: &str) -> bool {
    matches!(
        key,
        "schema_version"
            | "session_id"
            | "seq"
            | "ts_ns"
            | "kind"
            | "source"
            | "observer_context"
            | "data"
    )
}

/// Mirror of parse_source's accepted keys.
fn source_field_known(key: &str) -> bool {
    matches!(
        key,
        "hook" | "backend" | "profile_id" | "measurement" | "correlation"
    )
}

/// Mirror of parse_observer's accepted keys.
fn observer_field_known(key: &str) -> bool {
    matches!(
        key,
        "cpu" | "pid" | "tgid" | "comm" | "cgroup_id" | "relation"
    )
}

/// Mirror of parse_snapshot_scope's accepted keys.
fn scope_field_known(key: &str) -> bool {
    matches!(key, "device_id" | "profile_id")
}

/// Mirror of the per-kind data parsers' accepted keys.
fn data_field_known(kind: &str, key: &str) -> bool {
    match kind {
        "bounce_attempt" => {
            matches!(
                key,
                "device_id" | "requested_bytes" | "forced" | "operation_id"
            )
        }
        "map_result" => matches!(
            key,
            "operation_id"
                | "success"
                | "mapping_id"
                | "return_code"
                | "mapped_bytes"
                | "wire_generation"
                | "wire_identity"
        ),
        "unmap" => matches!(key, "mapping_id" | "wire_generation" | "wire_identity"),
        "copy" => matches!(
            key,
            "operation_id"
                | "mapping_id"
                | "direction"
                | "bytes"
                | "pool_private"
                | "offset_past_allocation"
        ),
        "sync_request" => {
            matches!(
                key,
                "operation_id" | "mapping_id" | "offset_known" | "offset" | "length"
            )
        }
        "transition_result" => matches!(
            key,
            "region_id"
                | "requested_state"
                | "success"
                | "return_code"
                | "offset"
                | "length"
                | "address_space"
                | "resolution"
                | "generation"
        ),
        "pool_sample" => matches!(
            key,
            "pool_id"
                | "used_bytes"
                | "capacity_bytes"
                | "unit"
                | "allocator"
                | "unit_bytes"
                | "hiwater_bytes"
                | "reason"
        ),
        "gap" => {
            matches!(
                key,
                "channel" | "lost_count" | "reason" | "window_start_ns" | "window_end_ns"
            )
        }
        "marker" => key == "text",
        "counter_snapshot" => {
            matches!(key, "counter_id" | "epoch" | "scope" | "value" | "unit")
        }
        _ => false,
    }
}

/// Accepted JSON value shapes as (ctx, kind, key, lead) rows.
///
/// Mirrors the value parser each model parser applies per key: s string,
/// b boolean, n number, o object, S string-or-null, N number-or-null. A
/// truncated value whose first byte cannot grow into its shape is
/// definitively invalid.
const TYPE_ROWS: &[(&str, &str, &str, &str)] = &[
    ("top", "", "schema_version", "s"),
    ("top", "", "session_id", "s"),
    ("top", "", "seq", "s"),
    ("top", "", "ts_ns", "s"),
    ("top", "", "kind", "s"),
    ("top", "", "source", "o"),
    ("top", "", "observer_context", "o"),
    ("top", "", "data", "o"),
    ("source", "", "hook", "s"),
    ("source", "", "backend", "s"),
    ("source", "", "profile_id", "s"),
    ("source", "", "measurement", "s"),
    ("source", "", "correlation", "s"),
    ("observer", "", "cpu", "n"),
    ("observer", "", "pid", "n"),
    ("observer", "", "tgid", "n"),
    ("observer", "", "comm", "s"),
    ("observer", "", "cgroup_id", "s"),
    ("observer", "", "relation", "s"),
    ("scope", "", "device_id", "S"),
    ("scope", "", "profile_id", "s"),
    ("data", "bounce_attempt", "device_id", "s"),
    ("data", "bounce_attempt", "requested_bytes", "s"),
    ("data", "bounce_attempt", "forced", "b"),
    ("data", "bounce_attempt", "operation_id", "s"),
    ("data", "map_result", "operation_id", "s"),
    ("data", "map_result", "success", "b"),
    ("data", "map_result", "mapping_id", "S"),
    ("data", "map_result", "return_code", "N"),
    ("data", "map_result", "mapped_bytes", "S"),
    ("data", "map_result", "wire_generation", "S"),
    ("data", "map_result", "wire_identity", "S"),
    ("data", "unmap", "mapping_id", "S"),
    ("data", "unmap", "wire_generation", "S"),
    ("data", "unmap", "wire_identity", "S"),
    ("data", "copy", "operation_id", "s"),
    ("data", "copy", "mapping_id", "S"),
    ("data", "copy", "direction", "s"),
    ("data", "copy", "bytes", "s"),
    ("data", "copy", "pool_private", "b"),
    ("data", "copy", "offset_past_allocation", "b"),
    ("data", "sync_request", "operation_id", "s"),
    ("data", "sync_request", "mapping_id", "S"),
    ("data", "sync_request", "offset_known", "b"),
    ("data", "sync_request", "offset", "S"),
    ("data", "sync_request", "length", "s"),
    ("data", "transition_result", "region_id", "s"),
    ("data", "transition_result", "requested_state", "s"),
    ("data", "transition_result", "success", "b"),
    ("data", "transition_result", "return_code", "N"),
    ("data", "transition_result", "offset", "s"),
    ("data", "transition_result", "length", "s"),
    ("data", "transition_result", "address_space", "s"),
    ("data", "transition_result", "resolution", "s"),
    ("data", "transition_result", "generation", "n"),
    ("data", "pool_sample", "pool_id", "s"),
    ("data", "pool_sample", "used_bytes", "S"),
    ("data", "pool_sample", "capacity_bytes", "S"),
    ("data", "pool_sample", "unit", "s"),
    ("data", "pool_sample", "allocator", "s"),
    ("data", "pool_sample", "unit_bytes", "s"),
    ("data", "pool_sample", "hiwater_bytes", "S"),
    ("data", "pool_sample", "reason", "s"),
    ("data", "gap", "channel", "s"),
    ("data", "gap", "lost_count", "S"),
    ("data", "gap", "reason", "s"),
    ("data", "gap", "window_start_ns", "s"),
    ("data", "gap", "window_end_ns", "s"),
    ("data", "marker", "text", "s"),
    ("data", "counter_snapshot", "counter_id", "s"),
    ("data", "counter_snapshot", "epoch", "s"),
    ("data", "counter_snapshot", "scope", "o"),
    ("data", "counter_snapshot", "value", "s"),
    ("data", "counter_snapshot", "unit", "s"),
];

/// Look up one field's expected JSON shape code, or "".
fn expected_lead(ctx: &str, kind: &str, key: &str) -> &'static str {
    for (c, k, f, lead) in TYPE_ROWS {
        if *c == ctx && *k == kind && *f == key {
            return lead;
        }
    }
    ""
}

/// True when a truncated value's first byte can still grow valid.
fn lead_ok(lead: &str, fb: u8) -> bool {
    match lead {
        "s" => fb == 0x22,
        "b" => fb == 0x74 || fb == 0x66,
        "n" => fb == 0x2D || (0x30..=0x39).contains(&fb),
        "o" => fb == 0x7B,
        "S" => fb == 0x22 || fb == 0x6E,
        "N" => fb == 0x2D || (0x30..=0x39).contains(&fb) || fb == 0x6E,
        _ => true,
    }
}

/// Decode one complete string token; the span is exact.
fn decode_span(span: &[u8]) -> Result<String, ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    let out = scan.parse_string("span")?;
    scan.skip_ws();
    if !scan.at_end() {
        return Err(ValidationError::new("span", "trailing data"));
    }
    Ok(out)
}

/// True when key is accepted in this nested object context.
fn ctx_known(ctx: &str, kind: &str, key: &str) -> bool {
    match ctx {
        "source" => source_field_known(key),
        "observer" => observer_field_known(key),
        "scope" => scope_field_known(key),
        "data" => data_field_known(kind, key),
        _ => true,
    }
}

/// True when complete keys in one nested object prove rejection.
///
/// Checks duplicates and unknown fields for every complete key, screens
/// truncated values against their expected JSON shape, direct-parses
/// complete objects where the schema is known, and recurses into the rest.
/// Complete scalar values are left to the completed-subdocument parse; only
/// key and value shape are judged here.
fn walk_keys(data: &[u8], members: &[TailMember], ctx: &str, kind: &str, depth: usize) -> bool {
    let mut seen = HashSet::new();
    for m in members {
        let key = match decode_span(&data[m.key_start..m.key_end]) {
            Ok(key) => key,
            Err(_) => return true,
        };
        if !seen.insert(key.clone()) {
            return true;
        }
        if !ctx.is_empty() && !ctx_known(ctx, kind, &key) {
            return true;
        }
        if m.val_verdict == TAIL_INVALID {
            return true;
        }
        let has_val = m.val_start < data.len();
        let is_obj = has_val && data[m.val_start] == 0x7B;
        let is_arr = has_val && data[m.val_start] == 0x5B;
        if !ctx.is_empty() && m.val_verdict == TAIL_INCOMPLETE && has_val {
            let lead = expected_lead(ctx, kind, &key);
            if !lead.is_empty() && !lead_ok(lead, data[m.val_start]) {
                return true;
            }
        }
        if m.val_verdict == TAIL_COMPLETE {
            if !is_obj {
                continue;
            }
            if ctx == "data" && key == "scope" && kind == "counter_snapshot" {
                let mut dummy = Event::default();
                let mut scan = Scanner::new(&data[m.val_start..m.val_end]);
                if parse_snapshot_scope(&mut scan, &mut dummy).is_err() {
                    return true;
                }
                continue;
            }
            if ctx.is_empty() {
                let mut sub = Vec::new();
                let mut p = m.val_start;
                let v = tail_scan_members(data, &mut p, depth + 1, MAX_TAIL_DEPTH, &mut sub);
                if v == TAIL_INVALID {
                    return true;
                }
                if walk_keys(data, &sub, "", "", depth + 1) {
                    return true;
                }
                continue;
            }
            return true;
        }
        if is_arr && !ctx.is_empty() {
            return true;
        }
        if !is_obj {
            continue;
        }
        if ctx == "data" && key == "scope" && kind == "counter_snapshot" {
            let mut sub = Vec::new();
            let mut p = m.val_start;
            let v = tail_scan_members(data, &mut p, depth + 1, MAX_TAIL_DEPTH, &mut sub);
            if v == TAIL_INVALID {
                return true;
            }
            // Scope rows carry an empty kind: passing the data kind here
            // would miss every shape lookup below.
            if walk_keys(data, &sub, "scope", "", depth + 1) {
                return true;
            }
            continue;
        }
        if ctx.is_empty() {
            let mut sub = Vec::new();
            let mut p = m.val_start;
            let v = tail_scan_members(data, &mut p, depth + 1, MAX_TAIL_DEPTH, &mut sub);
            if v == TAIL_INVALID {
                return true;
            }
            if walk_keys(data, &sub, "", "", depth + 1) {
                return true;
            }
            continue;
        }
        return true;
    }
    false
}

/// Rebuild one object from its complete members, recursively.
///
/// Complete values copy verbatim; incomplete objects rebuild from their own
/// complete members; anything else truncated drops out. The result holds no
/// partial token, so parsing it can only fail on violations already present
/// in the tail bytes.
fn completed_bytes(
    data: &[u8],
    members: &[TailMember],
    depth: usize,
    over_depth: &mut bool,
) -> Vec<u8> {
    let mut out = vec![0x7B];
    let mut first = true;
    for m in members {
        let mut use_sub = false;
        let mut sub = Vec::new();
        if m.val_verdict == TAIL_COMPLETE {
            // Verbatim below.
        } else if m.val_start < data.len() && data[m.val_start] == 0x7B {
            let mut sub_members = Vec::new();
            let mut p = m.val_start;
            let v = tail_scan_members(data, &mut p, depth + 1, MAX_TAIL_DEPTH, &mut sub_members);
            if v == TAIL_INVALID {
                *over_depth = true;
                return Vec::new();
            }
            sub = completed_bytes(data, &sub_members, depth + 1, over_depth);
            if *over_depth {
                return Vec::new();
            }
            use_sub = true;
        } else {
            continue;
        }
        if !first {
            out.push(0x2C);
        }
        first = false;
        out.extend_from_slice(&data[m.key_start..m.key_end]);
        out.push(0x3A);
        if use_sub {
            out.extend_from_slice(&sub);
        } else {
            out.extend_from_slice(&data[m.val_start..m.val_end]);
        }
    }
    out.push(0x7D);
    out
}

/// True when complete data bytes parse under some event kind.
fn parse_all_kinds(span: &[u8]) -> bool {
    for kind in [
        "bounce_attempt",
        "map_result",
        "unmap",
        "copy",
        "sync_request",
        "transition_result",
        "pool_sample",
        "gap",
        "marker",
        "counter_snapshot",
    ] {
        let mut dummy = Event::default();
        if parse_data_span(kind, span, EVENT_SCHEMA_VERSION, &mut dummy).is_ok() {
            return true;
        }
    }
    false
}

/// True when a truncated tail proves the record is invalid.
///
/// The tail classified TAIL_INCOMPLETE: clean truncation so far as JSON
/// syntax can tell. This scan looks further: complete keys are checked for
/// duplicates, unknown fields, and session match; complete nested objects
/// are parsed with the real schema validators; and the complete members
/// rebuild a subdocument whose parse reuses every value rule. Only a
/// "missing field" failure is inconclusive (members may have followed the
/// cut); any other failure, on bytes fully present, is definitive.
pub fn partial_record_definitive(data: &[u8], session_id: &str) -> bool {
    let mut p = 0;
    while p < data.len() && tail_is_ws(data[p]) {
        p += 1;
    }
    if p >= data.len() || data[p] != 0x7B {
        return true;
    }
    let mut members = Vec::new();
    let verdict = tail_scan_members(data, &mut p, 0, MAX_TAIL_DEPTH, &mut members);
    if verdict == TAIL_INVALID {
        return true;
    }
    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    let mut kind = String::new();
    let mut has_kind = false;
    let mut session = String::new();
    let mut has_session = false;
    for m in &members {
        let key = match decode_span(&data[m.key_start..m.key_end]) {
            Ok(key) => key,
            Err(_) => return true,
        };
        if !seen.insert(key.clone()) {
            return true;
        }
        keys.push(key.clone());
        if !top_field_known(&key) {
            return true;
        }
        if m.val_verdict == TAIL_INCOMPLETE && m.val_start < data.len() {
            let lead = expected_lead("top", "", &key);
            if !lead.is_empty() && !lead_ok(lead, data[m.val_start]) {
                return true;
            }
        }
        if key == "kind" && m.val_verdict == TAIL_COMPLETE {
            match decode_span(&data[m.val_start..m.val_end]) {
                Ok(k) => {
                    kind = k;
                    has_kind = true;
                }
                Err(_) => return true,
            }
        }
        if key == "session_id" && m.val_verdict == TAIL_COMPLETE {
            match decode_span(&data[m.val_start..m.val_end]) {
                Ok(s) => {
                    session = s;
                    has_session = true;
                }
                Err(_) => return true,
            }
        }
    }
    if has_session && session != session_id {
        return true;
    }
    for (i, m) in members.iter().enumerate() {
        let key = &keys[i];
        if m.val_verdict == TAIL_INVALID {
            return true;
        }
        let has_val = m.val_start < data.len();
        let is_obj = has_val && data[m.val_start] == 0x7B;
        let is_arr = has_val && data[m.val_start] == 0x5B;
        if m.val_verdict == TAIL_COMPLETE {
            if !is_obj && !is_arr {
                continue;
            }
            let span = &data[m.val_start..m.val_end];
            if key == "source" {
                let mut dummy = Event::default();
                let mut scan = Scanner::new(span);
                if parse_source(&mut scan, &mut dummy).is_err() {
                    return true;
                }
                if has_kind && kind == "copy" && dummy.source_measurement != "observed" {
                    return true;
                }
                continue;
            }
            if key == "observer_context" {
                let mut dummy = Event::default();
                let mut scan = Scanner::new(span);
                if parse_observer(&mut scan, &mut dummy).is_err() {
                    return true;
                }
                continue;
            }
            if key == "data" && !is_arr {
                if has_kind {
                    let mut dummy = Event::default();
                    if parse_data_span(&kind, span, EVENT_SCHEMA_VERSION, &mut dummy).is_err() {
                        return true;
                    }
                } else if !parse_all_kinds(span) {
                    return true;
                }
                continue;
            }
            return true;
        }
        if !is_obj {
            continue;
        }
        let mut sub = Vec::new();
        let mut sp = m.val_start;
        let sv = tail_scan_members(data, &mut sp, 1, MAX_TAIL_DEPTH, &mut sub);
        if sv == TAIL_INVALID {
            return true;
        }
        // Even an unfinished source object can contain a complete
        // measurement token that proves this copy invalid. Kind was
        // collected in the first pass, regardless of key order.
        if key == "source" && has_kind && kind == "copy" {
            for member in &sub {
                if member.val_verdict != TAIL_COMPLETE {
                    continue;
                }
                let source_key = match decode_span(&data[member.key_start..member.key_end]) {
                    Ok(k) => k,
                    Err(_) => return true,
                };
                if source_key == "measurement" {
                    let measurement = match decode_span(&data[member.val_start..member.val_end]) {
                        Ok(v) => v,
                        Err(_) => return true,
                    };
                    if measurement != "observed" {
                        return true;
                    }
                }
            }
        }
        let (child, child_kind) = if key == "source" {
            ("source", "")
        } else if key == "observer_context" {
            ("observer", "")
        } else if key == "data" && has_kind {
            ("data", kind.as_str())
        } else {
            ("", "")
        };
        // Keys without a schema context still screen duplicates; objects
        // under a known context walk against their rows.
        if walk_keys(data, &sub, child, child_kind, 1) {
            return true;
        }
    }
    let mut over_depth = false;
    let sub = completed_bytes(data, &members, 0, &mut over_depth);
    if over_depth {
        return true;
    }
    match parse_event(&sub) {
        Ok(_) => false,
        Err(e) => !e.to_string().contains("missing field"),
    }
}

/// Stream chunk size (64 KiB).
const CHUNK_BYTES: usize = 65536;

/// Tracked-identity cap shared with the writer's identity budget.
///
/// The writer stops while the next record still fits, so its finalized
/// captures always pass this admission; only hand-built captures can trip
/// it.
const MAX_TRACKED_IDS: usize = 4194304;

/// One open capture: validated session plus lazy event stream.
pub struct CaptureReader {
    /// The validated session document.
    pub session: Session,
    /// True when a truncated tail was recovered (or a checkpoint prefix).
    pub partial: bool,
    /// True when the stream is a checkpoint prefix, not a final capture.
    pub checkpoint_prefix: bool,
    /// Suffix bytes past the verified prefix.
    pub unverified_bytes: u64,
    /// True once an integrity-bearing stream binds at checked EOF.
    pub integrity_verified: bool,
    recovery: RecoveryFiles,
    integrity: Integrity,
    hash: Sha256,
    fd: i32,
    chunk: Vec<u8>,
    pos: usize,
    end: usize,
    pending: Vec<u8>,
    total: usize,
    lineno: usize,
    staged: bool,
    staged_final: bool,
    exhausted: bool,
    stream_eof: bool,
    allow_partial: bool,
    limits: ReaderLimits,
    has_prev: bool,
    prev_seq: u64,
    devices: HashSet<String>,
    ops: HashSet<String>,
    maps: HashSet<String>,
    dead: HashSet<String>,
    excused: HashSet<String>,
    ref_copy_ids: Vec<String>,
    ref_copy_lines: Vec<usize>,
    seen_copy_refs: HashSet<String>,
    ref_sync_ids: Vec<String>,
    ref_sync_lines: Vec<usize>,
    seen_sync_refs: HashSet<String>,
    req_total: u64,
    req_dev: HashMap<String, u64>,
}

impl CaptureReader {
    /// An empty reader shell (streams start via read_capture).
    pub fn new() -> Self {
        Self {
            session: Session::default(),
            partial: false,
            checkpoint_prefix: false,
            unverified_bytes: 0,
            integrity_verified: false,
            recovery: RecoveryFiles::new(),
            integrity: Integrity::default(),
            hash: Sha256::new(),
            fd: -1,
            chunk: vec![0; CHUNK_BYTES],
            pos: 0,
            end: 0,
            pending: Vec::new(),
            total: 0,
            lineno: 0,
            staged: false,
            staged_final: false,
            exhausted: false,
            stream_eof: false,
            allow_partial: false,
            limits: default_limits(),
            has_prev: false,
            prev_seq: 0,
            devices: HashSet::new(),
            ops: HashSet::new(),
            maps: HashSet::new(),
            dead: HashSet::new(),
            excused: HashSet::new(),
            ref_copy_ids: Vec::new(),
            ref_copy_lines: Vec::new(),
            seen_copy_refs: HashSet::new(),
            ref_sync_ids: Vec::new(),
            ref_sync_lines: Vec::new(),
            seen_sync_refs: HashSet::new(),
            req_total: 0,
            req_dev: HashMap::new(),
        }
    }

    /// True when another event awaits.
    ///
    /// With allow_partial, a final unterminated record that is a clean
    /// truncation (the classifier says incomplete) is dropped here:
    /// partial is set and iteration ends. A final record that parses but
    /// lacks its trailing newline is a framing error in both modes, and
    /// an unterminated record that is corrupt rather than truncated
    /// always raises.
    pub fn has_more(&mut self) -> Result<bool, ReadError> {
        self.ensure_staged()?;
        if !self.staged {
            return Ok(false);
        }
        if self.staged_final {
            return self.probe_tail();
        }
        Ok(true)
    }

    /// Parse, check, and return the next event in order.
    pub fn next_event(&mut self) -> Result<Event, ReadError> {
        self.ensure_staged()?;
        if !self.staged {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message: "no more events".to_string(),
            });
        }
        let lineno = self.lineno;
        let was_final = self.staged_final;
        self.staged = false;
        let ev = match parse_event(&self.pending) {
            Ok(ev) => ev,
            Err(e) => {
                return Err(ReadError {
                    code: READ_PARSE,
                    line_no: lineno,
                    message: format!("line {lineno}: {e}"),
                });
            }
        };
        self.check(&ev, lineno)?;
        if was_final {
            return Err(ReadError {
                code: READ_PARSE,
                line_no: lineno,
                message: format!("line {lineno}: final record lacks trailing newline"),
            });
        }
        if self.session.has_integrity {
            if ev.seq != self.integrity.line_count {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: lineno,
                    message: "capture integrity: sequence mismatch".to_string(),
                });
            }
            if let Some(kind) = integrity_kind_index(&ev.kind) {
                self.integrity.kinds[kind] += 1;
            }
            self.integrity.line_count += 1;
        }
        self.prev_seq = ev.seq;
        self.has_prev = true;
        self.pending = Vec::new();
        Ok(ev)
    }

    /// Decide the final unterminated line: recover, or raise.
    ///
    /// Recovery is only for clean truncation: an incomplete tail whose
    /// complete bytes already prove the record invalid is a definitive
    /// error, not a cut-off write, and raises in both modes.
    fn probe_tail(&mut self) -> Result<bool, ReadError> {
        let lineno = self.lineno;
        if self.session.has_integrity {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: "capture integrity: missing trailing newline".to_string(),
            });
        }
        let verdict = classify_tail(&self.pending);
        match parse_event(&self.pending) {
            Ok(probe) => {
                self.check(&probe, lineno)?;
                Err(ReadError {
                    code: READ_PARSE,
                    line_no: lineno,
                    message: format!("line {lineno}: final record lacks trailing newline"),
                })
            }
            Err(_) => {
                if self.allow_partial && verdict == TAIL_INCOMPLETE {
                    if partial_record_definitive(&self.pending, &self.session.session_id) {
                        return Err(ReadError {
                            code: READ_PARSE,
                            line_no: lineno,
                            message: format!("line {lineno}: definitive error in final record"),
                        });
                    }
                    self.partial = true;
                    self.staged = false;
                    self.exhausted = true;
                    self.close_now();
                    self.finish_checks()?;
                    return Ok(false);
                }
                Err(ReadError {
                    code: READ_PARSE,
                    line_no: lineno,
                    message: format!("line {lineno}: corrupt final record (not truncation)"),
                })
            }
        }
    }

    /// Stage the next line unless the stream already ended.
    fn ensure_staged(&mut self) -> Result<(), ReadError> {
        if self.staged || self.exhausted {
            return Ok(());
        }
        if self.fill_line()? {
            self.staged = true;
            return Ok(());
        }
        self.exhausted = true;
        self.close_now();
        self.finish_checks()
    }

    /// Accumulate one line into pending.
    ///
    /// Returns true with lineno advanced when a line (terminated or a
    /// final unterminated tail) is staged; false at clean EOF when no
    /// bytes remain. Byte bounds match the schema validator's line
    /// iterator exactly.
    fn fill_line(&mut self) -> Result<bool, ReadError> {
        self.pending = Vec::new();
        self.staged_final = false;
        loop {
            if self.pos >= self.end {
                if self.stream_eof {
                    if self.pending.is_empty() {
                        return Ok(false);
                    }
                    self.lineno += 1;
                    self.staged_final = true;
                    return Ok(true);
                }
                self.refill()?;
                continue;
            }
            let b = self.chunk[self.pos];
            self.pos += 1;
            self.total += 1;
            if self.total > self.limits.max_events_bytes {
                return Err(ReadError {
                    code: READ_TOO_BIG,
                    line_no: 0,
                    message: "events.ndjson too large".to_string(),
                });
            }
            if b == 0x0A {
                if self.pending.len() + 1 > self.limits.max_line_bytes {
                    return Err(ReadError {
                        code: READ_TOO_BIG,
                        line_no: self.lineno + 1,
                        message: "line too large".to_string(),
                    });
                }
                self.lineno += 1;
                return Ok(true);
            }
            self.pending.push(b);
            if self.pending.len() > self.limits.max_line_bytes {
                return Err(ReadError {
                    code: READ_TOO_BIG,
                    line_no: self.lineno + 1,
                    message: "line too large".to_string(),
                });
            }
        }
    }

    /// Read the next chunk; set stream_eof at clean EOF.
    fn refill(&mut self) -> Result<(), ReadError> {
        let mut want = CHUNK_BYTES;
        if self.checkpoint_prefix {
            let left = self
                .session
                .integrity
                .events_bytes
                .saturating_sub(self.total as u64);
            want = want.min(left as usize);
            if want == 0 {
                self.stream_eof = true;
                self.pos = 0;
                self.end = 0;
                return Ok(());
            }
        }
        let got: i64;
        if self.checkpoint_prefix {
            // SAFETY: live recovery fd with the in-range chunk; pread at
            // the absolute offset never moves the cursor.
            got = unsafe {
                libc::pread(
                    self.recovery.events_fd(),
                    self.chunk.as_mut_ptr().cast::<libc::c_void>(),
                    want,
                    self.total as libc::off_t,
                )
            } as i64;
            if got < 0 {
                return Err(ReadError {
                    code: READ_IO,
                    line_no: 0,
                    message: "cannot read checkpoint events prefix".to_string(),
                });
            }
        } else {
            // SAFETY: live pinned fd with the in-range chunk.
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.chunk.as_mut_ptr().cast::<libc::c_void>(),
                    want,
                )
            };
            if n < 0 {
                // EINTR retries, like the writer loops; anything else is I/O.
                let no = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
                if no == libc::EINTR {
                    return self.refill();
                }
                return Err(ReadError {
                    code: READ_IO,
                    line_no: 0,
                    message: "cannot read events.ndjson".to_string(),
                });
            }
            got = n as i64;
        }
        if got == 0 {
            self.stream_eof = true;
            self.pos = 0;
            self.end = 0;
            return Ok(());
        }
        self.pos = 0;
        self.end = got as usize;
        if self.session.has_integrity {
            self.hash.update(&self.chunk[..got as usize]);
        }
        Ok(())
    }

    /// Close the stream exactly once; safe to repeat.
    fn close_now(&mut self) {
        if self.fd >= 0 {
            // SAFETY: owned-or-negative fd; best effort.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }

    fn check(&mut self, ev: &Event, lineno: usize) -> Result<(), ReadError> {
        if ev.session_id != self.session.session_id {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("line {lineno}: session id"),
            });
        }
        if self.has_prev && ev.seq <= self.prev_seq {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("line {lineno}: seq order"),
            });
        }
        // Snapshots are admissible from the vouched baseline cut (read
        // before the ring existed); every other record must lie inside
        // the readiness-anchored window.
        let mut floor = self.session.window_start_ns;
        if ev.kind == "counter_snapshot" && self.session.has_baseline_start_ns {
            floor = self.session.baseline_start_ns;
        }
        if ev.ts_ns < floor {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("line {lineno}: ts before"),
            });
        }
        if ev.ts_ns >= self.session.window_end_ns {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("line {lineno}: ts after"),
            });
        }
        self.check_identities(ev, lineno)?;
        let tracked = self.ops.len()
            + self.maps.len()
            + self.excused.len()
            + self.ref_copy_ids.len()
            + self.ref_sync_ids.len();
        if tracked > MAX_TRACKED_IDS {
            return Err(ReadError {
                code: READ_TOO_BIG,
                line_no: lineno,
                message: "too many tracked identities".to_string(),
            });
        }
        Ok(())
    }

    /// Enforce cross-record identity rules for one event.
    ///
    /// Device membership, per-(kind, operation) uniqueness, mapping
    /// creation/release pairing, and deferred copy/sync references agree
    /// with the schema validator: unmap needs a prior live creation unless
    /// the mapping-release class (or the aggregate without relations) is
    /// partial or unavailable, in which case the id is remembered; a repeat
    /// release refuses as released twice and a later creation as duplicate.
    /// Copy/sync references resolve when the stream ends so forward
    /// references stay valid.
    fn check_identities(&mut self, ev: &Event, lineno: usize) -> Result<(), ReadError> {
        let tag = format!("line {lineno}: ");
        if ev.kind == "bounce_attempt" {
            if !self.devices.contains(&ev.bounce.device_id) {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: lineno,
                    message: format!("{tag}unknown device"),
                });
            }
            self.note_op(&ev.kind, &ev.bounce.operation_id, &tag, lineno)?;
            match checked_add(self.req_total, ev.bounce.requested_bytes) {
                Ok(sum) => self.req_total = sum,
                Err(_) => {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}requested bytes overflow"),
                    });
                }
            }
            // The per-device arm mirrors the validator's second sum. The
            // total is checked first and always dominates it, so this arm
            // is unreachable; it stands as a parity guard.
            let prior = self.req_dev.get(&ev.bounce.device_id).copied().unwrap_or(0);
            match checked_add(prior, ev.bounce.requested_bytes) {
                Ok(sum) => {
                    self.req_dev.insert(ev.bounce.device_id.clone(), sum);
                }
                Err(_) => {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}per-device bytes overflow"),
                    });
                }
            }
        } else if ev.kind == "map_result" {
            self.note_op(&ev.kind, &ev.map_result.operation_id, &tag, lineno)?;
            if ev.map_result.success && ev.map_result.has_mapping_id {
                let mid = &ev.map_result.mapping_id;
                if self.maps.contains(mid) {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}duplicate mapping"),
                    });
                }
                // An excused release admits no later creation of its id.
                if self.excused.contains(mid) {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}duplicate mapping"),
                    });
                }
                self.maps.insert(mid.clone());
            }
        } else if ev.kind == "unmap" {
            if ev.unmap.has_mapping_id {
                let target = &ev.unmap.mapping_id;
                if self.dead.contains(target) {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}mapping released twice"),
                    });
                }
                if self.excused.contains(target) {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}mapping released twice"),
                    });
                }
                if !self.maps.contains(target) {
                    // Session precedes events; excuse only declared loss.
                    if self.class_expected(&self.session.q_corr_mapping.status) {
                        self.excused.insert(target.clone());
                        return Ok(());
                    }
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: lineno,
                        message: format!("{tag}unknown mapping"),
                    });
                }
                self.dead.insert(target.clone());
            }
        } else if ev.kind == "copy" {
            // Copies repeat freely under one operation (nested, per-sync,
            // and completion copies share it); only attempts and map
            // results claim an operation once. Repeats record once: the
            // deferred list keeps the first line per id, and distinct ids
            // draw from the same identity budget as operations and
            // mappings.
            if ev.copy.has_mapping_id {
                self.note_copy_ref(&ev.copy.mapping_id, lineno);
            }
        } else if ev.kind == "sync_request" {
            // Syncs repeat freely under one operation for the same reason
            // as copies.
            if ev.sync.has_mapping_id {
                self.note_sync_ref(&ev.sync.mapping_id, lineno);
            }
        } else if ev.kind == "counter_snapshot"
            && ev.snapshot.has_scope_device
            && !self.devices.contains(&ev.snapshot.scope_device_id)
        {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("{tag}unknown device"),
            });
        }
        Ok(())
    }

    /// Record one (kind, operation) pair; reject repeats.
    ///
    /// The key embeds the operation byte length between separators, so
    /// splitting at the first two separators recovers the kind and
    /// operation uniquely no matter what the id contains.
    fn note_op(&mut self, kind: &str, op: &str, tag: &str, lineno: usize) -> Result<(), ReadError> {
        let key = format!("{kind}#{}#{op}", op.len());
        if self.ops.contains(&key) {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: lineno,
                message: format!("{tag}duplicate operation"),
            });
        }
        self.ops.insert(key);
        Ok(())
    }

    /// Defer one copy mapping reference, first line kept.
    ///
    /// Repeats of an already-recorded id add nothing: forward references
    /// still resolve at end of stream, and an unknown id still reports
    /// its first line. Distinct ids join the identity budget enforced
    /// after each event. Copy and sync references defer separately so
    /// each kind resolves against its own relation class.
    fn note_copy_ref(&mut self, mid: &str, lineno: usize) {
        if self.seen_copy_refs.contains(mid) {
            return;
        }
        self.seen_copy_refs.insert(mid.to_string());
        self.ref_copy_ids.push(mid.to_string());
        self.ref_copy_lines.push(lineno);
    }

    /// Defer one sync mapping reference, first line kept.
    fn note_sync_ref(&mut self, mid: &str, lineno: usize) {
        if self.seen_sync_refs.contains(mid) {
            return;
        }
        self.seen_sync_refs.insert(mid.to_string());
        self.ref_sync_ids.push(mid.to_string());
        self.ref_sync_lines.push(lineno);
    }

    /// True when one class excuses a dangling reference.
    fn class_expected(&self, cls_status: &str) -> bool {
        if !self.session.has_corr_relations {
            let corr = &self.session.q_correlation.status;
            return corr == "partial" || corr == "unavailable";
        }
        cls_status == "partial" || cls_status == "unavailable"
    }

    /// Resolve deferred copy/sync mapping references at end.
    ///
    /// References the session's correlation evidence declares unpairable
    /// (partial or unavailable) are expected: v2 syncs keep record-local
    /// ids that never match gen-N keys and copies keep operation id only.
    /// The analyzer counts them as unpaired lifecycle events. Without
    /// relations the aggregate excuses either kind; with relations each
    /// kind needs its own class, so copy uncertainty never excuses a
    /// dangling sync reference. A dangling reference while the session
    /// claims complete correlation contradicts the capture and refuses.
    fn finish_checks(&mut self) -> Result<(), ReadError> {
        if self.session.has_integrity {
            let expected = self.session.integrity.clone();
            if self.total as u64 != expected.events_bytes {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: 0,
                    message: "capture integrity: events_bytes mismatch".to_string(),
                });
            }
            if self.integrity.line_count != expected.line_count {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: 0,
                    message: "capture integrity: line_count mismatch".to_string(),
                });
            }
            for i in 0..INTEGRITY_KIND_COUNT {
                if self.integrity.kinds[i] != expected.kinds[i] {
                    return Err(ReadError {
                        code: READ_INVALID,
                        line_no: 0,
                        message: format!(
                            "capture integrity: kind count mismatch: {}",
                            integrity_kind(i)
                        ),
                    });
                }
            }
            if self.hash.copy_finish() != expected.events_sha256 {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: 0,
                    message: "capture integrity: events_sha256 mismatch".to_string(),
                });
            }
        }
        let copy_ok = self.class_expected(&self.session.q_corr_copy.status.clone());
        for i in 0..self.ref_copy_ids.len() {
            if !self.maps.contains(&self.ref_copy_ids[i]) {
                if copy_ok {
                    continue;
                }
                let lineno = self.ref_copy_lines[i];
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: lineno,
                    message: format!("line {lineno}: unknown mapping"),
                });
            }
        }
        let sync_ok = self.class_expected(&self.session.q_corr_sync.status.clone());
        for i in 0..self.ref_sync_ids.len() {
            if !self.maps.contains(&self.ref_sync_ids[i]) {
                if sync_ok {
                    continue;
                }
                let lineno = self.ref_sync_lines[i];
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: lineno,
                    message: format!("line {lineno}: unknown mapping"),
                });
            }
        }
        if self.checkpoint_prefix
            && let Err(e) = self.recovery.verify()
        {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message: e.to_string(),
            });
        }
        self.integrity_verified = self.session.has_integrity;
        Ok(())
    }

    /// White-box: known mapping count.
    #[cfg(test)]
    fn maps_len(&self) -> usize {
        self.maps.len()
    }

    /// White-box: deferred copy reference count.
    #[cfg(test)]
    fn ref_copy_len(&self) -> usize {
        self.ref_copy_ids.len()
    }

    /// White-box: one deferred copy reference plus its first line.
    #[cfg(test)]
    fn ref_copy_at(&self, index: usize) -> (String, usize) {
        (self.ref_copy_ids[index].clone(), self.ref_copy_lines[index])
    }

    /// White-box: deferred sync reference count.
    #[cfg(test)]
    fn ref_sync_len(&self) -> usize {
        self.ref_sync_ids.len()
    }

    /// White-box: one deferred sync reference plus its first line.
    #[cfg(test)]
    fn ref_sync_at(&self, index: usize) -> (String, usize) {
        (self.ref_sync_ids[index].clone(), self.ref_sync_lines[index])
    }
}

impl Drop for CaptureReader {
    fn drop(&mut self) {
        self.close_now();
    }
}

impl std::fmt::Debug for CaptureReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CaptureReader")
            .field("session_id", &self.session.session_id)
            .field("partial", &self.partial)
            .field("checkpoint_prefix", &self.checkpoint_prefix)
            .field("unverified_bytes", &self.unverified_bytes)
            .field("integrity_verified", &self.integrity_verified)
            .finish_non_exhaustive()
    }
}

impl Default for CaptureReader {
    fn default() -> Self {
        Self::new()
    }
}

/// NUL-terminate raw path bytes, refusing interior NULs.
fn to_cstr_bytes(raw: &[u8]) -> Result<Vec<u8>, ReadError> {
    if raw.contains(&0) {
        return Err(ReadError {
            code: READ_IO,
            line_no: 0,
            message: "NUL byte in path".to_string(),
        });
    }
    let mut out = Vec::with_capacity(raw.len() + 1);
    out.extend_from_slice(raw);
    out.push(0);
    Ok(out)
}

/// Join a capture directory and member name at the byte level.
fn join_member(dir: &[u8], name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(dir.len() + 1 + name.len());
    out.extend_from_slice(dir);
    out.push(b'/');
    out.extend_from_slice(name);
    out
}

/// Pin a nonblocking descriptor before admitting a regular input stream.
fn open_regular_stream_bytes(raw: &[u8], what: &str) -> Result<i32, ReadError> {
    let cpath = to_cstr_bytes(raw)?;
    // SAFETY: NUL-terminated path on AT_FDCWD.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            cpath.as_ptr().cast::<libc::c_char>(),
            libc::O_NONBLOCK | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(ReadError {
            code: READ_IO,
            line_no: 0,
            message: format!("{what}: cannot open"),
        });
    }
    match file_stat(fd) {
        Ok(ids) if ids[3] & 0o170000 == 0o100000 => Ok(fd),
        _ => {
            // SAFETY: owned test fd.
            unsafe {
                libc::close(fd);
            }
            Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message: format!("{what}: input is not a regular file"),
            })
        }
    }
}

/// Read a small file without ever over-allocating past limit.
///
/// Chunks stream through a fixed 64 KiB buffer; the running total is
/// checked before each chunk lands, so a huge file is rejected after one
/// chunk over the bound instead of being read fully.
fn read_bounded_bytes(raw: &[u8], what: &str, limit: usize) -> Result<Vec<u8>, ReadError> {
    let fd = open_regular_stream_bytes(raw, what)?;
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut out = Vec::new();
    loop {
        // SAFETY: live pinned fd with the in-range chunk.
        let got = unsafe { libc::read(fd, chunk.as_mut_ptr().cast::<libc::c_void>(), CHUNK_BYTES) };
        if got < 0 {
            let no = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if no == libc::EINTR {
                continue;
            }
            // SAFETY: as above.
            unsafe {
                libc::close(fd);
            }
            return Err(ReadError {
                code: READ_IO,
                line_no: 0,
                message: format!("{what}: cannot read"),
            });
        }
        if got == 0 {
            // SAFETY: as above.
            unsafe {
                libc::close(fd);
            }
            return Ok(out);
        }
        let n = got as usize;
        if out.len() + n > limit {
            // SAFETY: as above.
            unsafe {
                libc::close(fd);
            }
            return Err(ReadError {
                code: READ_TOO_BIG,
                line_no: 0,
                message: format!("{what} too large"),
            });
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Open the capture in dir: validate session, stream events.
pub fn read_capture(
    dir: &str,
    allow_partial: bool,
    limits: ReaderLimits,
) -> Result<CaptureReader, ReadError> {
    read_capture_os(OsStr::new(dir), allow_partial, limits)
}

/// Open the capture in dir over raw bytes: validate session, stream events.
///
/// The byte-level open: probe, recovery, and finalized order match
/// [`read_capture`] exactly, and non-UTF-8 directories open like any
/// other bytes.
pub fn read_capture_os(
    dir: &OsStr,
    allow_partial: bool,
    limits: ReaderLimits,
) -> Result<CaptureReader, ReadError> {
    let raw = dir.as_bytes();
    let final_path = to_cstr_bytes(&join_member(raw, b"session.json"))?;
    // SAFETY: NUL-terminated path on AT_FDCWD.
    let probe = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            final_path.as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    let mut recover = false;
    if probe >= 0 {
        // SAFETY: owned probe fd.
        unsafe {
            libc::close(probe);
        }
    } else {
        let no = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if no == libc::ENOTDIR {
            return Err(ReadError {
                code: READ_IO,
                line_no: 0,
                message: "capture path is not a directory".to_string(),
            });
        }
        if no != libc::ENOENT {
            return Err(ReadError {
                code: READ_IO,
                line_no: 0,
                message: "cannot establish final session absence".to_string(),
            });
        }
        recover = true;
    }
    let mut files = RecoveryFiles::new();
    let session_bytes: Vec<u8>;
    if recover {
        if let Err(e) = files.open_os(dir) {
            let message = e.to_string();
            // A directory without capture members is not a
            // capture at all, whatever else it holds.
            let message = match message.as_str() {
                "checkpoint.json: cannot open regular capture file"
                | "events.ndjson: cannot open regular capture file" => {
                    "not a memveil capture: expected session.json/events.ndjson".to_string()
                }
                _ => message,
            };
            return Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message,
            });
        }
        match files.read_checkpoint(limits.max_session_bytes) {
            Ok(bytes) => session_bytes = bytes,
            Err(e) => {
                return Err(ReadError {
                    code: READ_INVALID,
                    line_no: 0,
                    message: e.to_string(),
                });
            }
        }
    } else {
        session_bytes = read_bounded_bytes(
            &join_member(raw, b"session.json"),
            "session.json",
            limits.max_session_bytes,
        )?;
    }
    let session = match parse_session(&session_bytes) {
        Ok(session) => session,
        Err(e) => {
            return Err(ReadError {
                code: READ_PARSE,
                line_no: 0,
                message: format!("session.json: {e}"),
            });
        }
    };
    if recover {
        if !session.has_integrity
            || session.finalized
            || !session.has_checkpoint_generation
            || session.end_reason != "checkpoint"
        {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message: "invalid checkpoint session".to_string(),
            });
        }
        if session.integrity.events_bytes > files.events_len() {
            return Err(ReadError {
                code: READ_INVALID,
                line_no: 0,
                message: "checkpoint prefix exceeds events file".to_string(),
            });
        }
    } else if session.has_integrity && !session.finalized {
        return Err(ReadError {
            code: READ_INVALID,
            line_no: 0,
            message: "unfinalized session requires checkpoint recovery".to_string(),
        });
    }
    let mut out = CaptureReader::new();
    out.session = session;
    if recover {
        out.checkpoint_prefix = true;
        out.partial = true;
        out.unverified_bytes = files.events_len() - out.session.integrity.events_bytes;
        out.recovery = files;
    }
    out.allow_partial = allow_partial;
    out.limits = limits;
    for device in &out.session.devices {
        out.devices.insert(device.device_id.clone());
    }
    if !recover {
        out.fd = open_regular_stream_bytes(&join_member(raw, b"events.ndjson"), "events.ndjson")?;
    }
    if recover && !allow_partial {
        while out.has_more()? {
            out.next_event()?;
        }
        return Err(ReadError {
            code: READ_INVALID,
            line_no: 0,
            message: format!(
                "no final session; verified checkpoint prefix {} bytes; use --allow-partial to recover",
                out.session.integrity.events_bytes
            ),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::{
        CaptureReader, READ_INVALID, READ_IO, READ_PARSE, READ_TOO_BIG, ReaderLimits,
        TAIL_COMPLETE, TAIL_INCOMPLETE, TAIL_INVALID, classify_tail, default_limits,
        partial_record_definitive, read_capture, read_remedy,
    };
    use crate::model::encode::encode_session;
    use crate::model::event::{Event, parse_event};
    use crate::model::session::parse_session;
    use crate::platform::hash::sha256_hex;
    use crate::platform::test_support::{TestDir, repo_root};

    fn fixture(name: &str) -> String {
        repo_root()
            .join("tests/fixtures/reader")
            .join(name)
            .to_str()
            .expect("utf8")
            .to_string()
    }

    fn attempts() -> String {
        repo_root()
            .join("tests/fixtures/attempts")
            .to_str()
            .expect("utf8")
            .to_string()
    }

    fn fixture_bytes(name: &str) -> Vec<u8> {
        std::fs::read(repo_root().join("tests/fixtures").join(name)).expect("fixture read")
    }

    fn fixture_text(name: &str) -> String {
        String::from_utf8(fixture_bytes(name)).expect("fixture utf8")
    }

    fn first_line(name: &str) -> String {
        fixture_text(name)
            .split('\n')
            .next()
            .unwrap_or("")
            .to_string()
    }

    fn nth_line(name: &str, want: usize) -> String {
        let mut seen = 0;
        for chunk in fixture_text(name).split('\n') {
            if !chunk.is_empty() {
                if seen == want {
                    return chunk.to_string();
                }
                seen += 1;
            }
        }
        String::new()
    }

    fn tail_chunk(name: &str) -> Vec<u8> {
        for chunk in fixture_text(name).split('\n').rev() {
            if !chunk.is_empty() {
                return chunk.as_bytes().to_vec();
            }
        }
        Vec::new()
    }

    fn cut_last(text: &str) -> Vec<u8> {
        text.as_bytes()[..text.len() - 1].to_vec()
    }

    fn prefix_before(text: &str, marker: &str) -> Vec<u8> {
        let at = text.find(marker).expect("marker present");
        assert!(at > 0);
        text.as_bytes()[..at].to_vec()
    }

    fn cat(a: &[u8], b: &[u8]) -> Vec<u8> {
        [a, b].concat()
    }

    fn replace_first(hay: &[u8], needle: &[u8], rep: &[u8]) -> Vec<u8> {
        let mut out = hay.to_vec();
        if let Some(at) = hay.windows(needle.len()).position(|w| w == needle) {
            out.splice(at..at + needle.len(), rep.iter().copied());
        }
        out
    }

    fn drain(r: &mut CaptureReader) -> Result<Vec<Event>, super::ReadError> {
        let mut out = Vec::new();
        while r.has_more()? {
            out.push(r.next_event()?);
        }
        Ok(out)
    }

    fn expect_error(dir: &str, allow: bool, limits: ReaderLimits, code: u32, line: usize) {
        let mut got_code = 0;
        let mut got_line = usize::MAX;
        match read_capture(dir, allow, limits) {
            Ok(mut r) => match drain(&mut r) {
                Ok(_) => {}
                Err(e) => {
                    got_code = e.code;
                    got_line = e.line_no;
                }
            },
            Err(e) => {
                got_code = e.code;
                got_line = e.line_no;
            }
        }
        assert_eq!(
            (got_code, got_line),
            (code, line),
            "dir={dir} allow={allow}"
        );
    }

    fn expect_message(
        dir: &str,
        allow: bool,
        limits: ReaderLimits,
        code: u32,
        line: usize,
        message: &str,
    ) {
        let mut got = (0, usize::MAX, String::new());
        match read_capture(dir, allow, limits) {
            Ok(mut r) => match drain(&mut r) {
                Ok(_) => {}
                Err(e) => got = (e.code, e.line_no, e.message),
            },
            Err(e) => got = (e.code, e.line_no, e.message),
        }
        assert_eq!(got, (code, line, message.to_string()), "dir={dir}");
    }

    #[test]
    fn read_attempts_capture() {
        let mut r = read_capture(&attempts(), false, default_limits()).expect("open");
        assert_eq!(r.session.session_id, "attempts-3-session");
        assert!(!r.partial);
        let events = drain(&mut r).expect("drain");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[1].seq, 2);
        assert_eq!(events[2].seq, 3);
        assert_eq!(events[0].bounce.requested_bytes, 4096);
        assert_eq!(events[2].bounce.requested_bytes, 1024);
        assert!(!r.has_more().expect("eof"));
    }

    #[test]
    fn reader_cross_record() {
        let limits = default_limits();
        expect_error(&fixture("foreign"), false, limits, READ_INVALID, 1);
        expect_error(&fixture("badseq"), false, limits, READ_INVALID, 2);
        expect_error(&fixture("ts-end"), false, limits, READ_INVALID, 1);
        expect_error(&fixture("ts-start"), false, limits, READ_INVALID, 1);
        expect_error(&fixture("badkind"), false, limits, READ_PARSE, 1);
    }

    #[test]
    fn reader_baseline_floor() {
        let old =
            parse_session(&fixture_bytes("reader/counters-single/session.json")).expect("parse");
        assert!(!old.has_baseline_start_ns);
        let mut r =
            read_capture(&fixture("snap-baseline-ok"), false, default_limits()).expect("open");
        assert!(r.session.has_baseline_start_ns);
        assert_eq!(r.session.baseline_start_ns, 50);
        assert_eq!(drain(&mut r).expect("drain").len(), 3);
        let limits = default_limits();
        expect_error(
            &fixture("snap-baseline-low"),
            false,
            limits,
            READ_INVALID,
            1,
        );
        expect_error(&fixture("obs-baseline-gap"), false, limits, READ_INVALID, 1);
        expect_error(
            &fixture("baseline-after-window"),
            false,
            limits,
            READ_PARSE,
            0,
        );
    }

    #[test]
    fn reader_limits_exact() {
        let dir = attempts();
        let session_size = fixture_bytes("attempts/session.json").len();
        let events_size = fixture_bytes("attempts/events.ndjson").len();
        let first_record = fixture_text("attempts/events.ndjson")
            .split('\n')
            .next()
            .unwrap()
            .len()
            + 1;
        let mut ok = read_capture(
            &dir,
            false,
            ReaderLimits {
                max_session_bytes: session_size,
                max_line_bytes: first_record,
                max_events_bytes: events_size,
            },
        )
        .expect("exact bounds admit");
        assert_eq!(drain(&mut ok).expect("drain").len(), 3);
        expect_error(
            &dir,
            false,
            ReaderLimits {
                max_session_bytes: session_size - 1,
                max_line_bytes: first_record,
                max_events_bytes: events_size,
            },
            READ_TOO_BIG,
            0,
        );
        expect_error(
            &dir,
            false,
            ReaderLimits {
                max_session_bytes: session_size,
                max_line_bytes: first_record - 1,
                max_events_bytes: events_size,
            },
            READ_TOO_BIG,
            1,
        );
        expect_error(
            &dir,
            false,
            ReaderLimits {
                max_session_bytes: session_size,
                max_line_bytes: first_record,
                max_events_bytes: events_size - 1,
            },
            READ_TOO_BIG,
            0,
        );
    }

    #[test]
    fn reader_size_fixtures() {
        let limits = default_limits();
        expect_error(&fixture("size-ok"), false, limits, READ_PARSE, 1);
        expect_error(&fixture("size-over"), false, limits, READ_TOO_BIG, 1);
    }

    #[test]
    fn reader_partial_tail() {
        let dir = fixture("partial-tail");
        let limits = default_limits();
        expect_error(&dir, false, limits, READ_PARSE, 3);
        let mut r = read_capture(&dir, true, limits).expect("open partial");
        assert_eq!(drain(&mut r).expect("drain").len(), 2);
        assert!(r.partial);
        assert!(!r.has_more().expect("eof"));
    }

    #[test]
    fn reader_partial_only_final() {
        expect_error(
            &fixture("interior-corrupt"),
            true,
            default_limits(),
            READ_PARSE,
            2,
        );
    }

    #[test]
    fn reader_scanner_errors_carry_byte_offsets() {
        // Pinned against the Mojo reader: structural failures render
        // the scanner byte offset, not just the line number.
        let dir = fixture("interior-corrupt");
        let mut r = read_capture(&dir, false, default_limits()).expect("open");
        let err = drain(&mut r).unwrap_err();
        assert_eq!(
            err.message,
            "line 2: ScanError(offset=1, message=expected byte 34)"
        );
        let dir = fixture("adv-bad-utf8");
        let mut r = read_capture(&dir, false, default_limits()).expect("open");
        let err = drain(&mut r).unwrap_err();
        assert_eq!(
            err.message,
            "line 1: ScanError(offset=309, message=invalid utf-8 in string)"
        );
    }

    #[test]
    fn reader_corrupt_tail_not_recovered() {
        let dir = fixture("corrupt-tail");
        expect_error(&dir, false, default_limits(), READ_PARSE, 3);
        expect_error(&dir, true, default_limits(), READ_PARSE, 3);
    }

    #[test]
    fn reader_valid_no_newline_rejected() {
        let dir = fixture("valid-no-newline");
        expect_error(&dir, false, default_limits(), READ_PARSE, 3);
        expect_error(&dir, true, default_limits(), READ_PARSE, 3);
    }

    #[test]
    fn reader_tail_foreign_rejected() {
        let dir = fixture("tail-foreign");
        expect_error(&dir, false, default_limits(), READ_INVALID, 3);
        expect_error(&dir, true, default_limits(), READ_INVALID, 3);
    }

    #[test]
    fn reader_f2_identities() {
        let limits = default_limits();
        expect_error(
            &fixture("f2-unknown-device"),
            false,
            limits,
            READ_INVALID,
            1,
        );
        expect_error(
            &fixture("f2-unknown-snapshot-device"),
            false,
            limits,
            READ_INVALID,
            2,
        );
        expect_error(&fixture("f2-duplicate-op"), false, limits, READ_INVALID, 2);
        expect_error(
            &fixture("f2-duplicate-mapping"),
            false,
            limits,
            READ_INVALID,
            7,
        );
        expect_error(&fixture("f2-early-unmap"), false, limits, READ_INVALID, 1);
        expect_error(&fixture("f2-unknown-copy"), false, limits, READ_INVALID, 3);
        expect_error(&fixture("f2-unknown-sync"), false, limits, READ_INVALID, 9);
        expect_error(&fixture("f2-unknown-sync"), true, limits, READ_INVALID, 9);
        expect_error(&fixture("f2-double-unmap"), false, limits, READ_INVALID, 4);
        expect_error(
            &fixture("f2-contradictory-provenance"),
            false,
            limits,
            READ_PARSE,
            0,
        );
    }

    #[test]
    fn reader_f3_overflow() {
        let limits = default_limits();
        expect_error(&fixture("f3-sum-overflow"), false, limits, READ_INVALID, 2);
        expect_error(&fixture("f3-span-sync"), false, limits, READ_PARSE, 2);
        expect_error(&fixture("f3-span-transition"), false, limits, READ_PARSE, 2);
        expect_error(&fixture("f3-baseline"), false, limits, READ_PARSE, 0);
        expect_error(&fixture("overflow"), false, limits, READ_INVALID, 2);
    }

    #[test]
    fn reader_f2_lifecycle_ok() {
        let mut r =
            read_capture(&fixture("f2-lifecycle-ok"), false, default_limits()).expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
        let mut f =
            read_capture(&fixture("f2-forward-ref-ok"), false, default_limits()).expect("open");
        assert_eq!(drain(&mut f).expect("drain").len(), 4);
        assert!(!f.partial);
        let mut g = read_capture(&fixture("f2-repeat-copy-sync-ok"), false, default_limits())
            .expect("open");
        assert_eq!(drain(&mut g).expect("drain").len(), 8);
        assert!(!g.partial);
    }

    #[test]
    fn multiple_unassigned_map_results() {
        let mut r =
            read_capture(&fixture("f2-unassigned-maps-ok"), false, default_limits()).expect("open");
        let evs = drain(&mut r).expect("drain");
        assert_eq!(evs.len(), 2);
        assert!(!evs[0].map_result.has_mapping_id);
        assert!(!evs[1].map_result.has_mapping_id);
        assert_eq!(r.maps_len(), 0);
        assert!(!r.partial);
        let mut m = read_capture(
            &fixture("f2-known-unassigned-mix-ok"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut m).expect("drain").len(), 3);
        assert_eq!(m.maps_len(), 2);
        assert!(!m.partial);
        expect_error(
            &fixture("f2-duplicate-mapping"),
            false,
            default_limits(),
            READ_INVALID,
            7,
        );
    }

    #[test]
    fn reader_expected_dangling_ok() {
        let mut r =
            read_capture(&fixture("f2-dangling-expected"), false, default_limits()).expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
    }

    #[test]
    fn reader_denied_dangling_refused() {
        expect_error(
            &fixture("f2-dangling-denied"),
            false,
            default_limits(),
            READ_INVALID,
            3,
        );
    }

    #[test]
    fn reader_split_copy_dangling() {
        let mut r = read_capture(
            &fixture("f2-dangling-split-copy-ok"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
        expect_error(
            &fixture("f2-dangling-split-copy-deny"),
            false,
            default_limits(),
            READ_INVALID,
            3,
        );
    }

    #[test]
    fn reader_split_sync_dangling() {
        let mut r = read_capture(
            &fixture("f2-dangling-split-sync-ok"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
        expect_error(
            &fixture("f2-dangling-split-sync-deny"),
            false,
            default_limits(),
            READ_INVALID,
            3,
        );
    }

    #[test]
    fn reader_unavailable_dangling_ok() {
        let mut r = CaptureReader::new();
        r.session.q_correlation.status = "unavailable".to_string();
        r.note_copy_ref("lc-9", 8);
        r.note_sync_ref("lc-10", 9);
        r.finish_checks().expect("excused");
    }

    #[test]
    fn reader_unmap_aggregate() {
        let mut r = read_capture(
            &fixture("f2-dangling-unmap-expected"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
        let mut u = read_capture(
            &fixture("f2-dangling-unmap-unavailable"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut u).expect("drain").len(), 8);
        assert!(!u.partial);
        expect_error(
            &fixture("f2-dangling-unmap-denied"),
            false,
            default_limits(),
            READ_INVALID,
            3,
        );
    }

    #[test]
    fn reader_split_mapping_unmap() {
        let mut r = read_capture(
            &fixture("f2-dangling-split-mapping-ok"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 8);
        assert!(!r.partial);
        expect_error(
            &fixture("f2-dangling-split-mapping-deny"),
            false,
            default_limits(),
            READ_INVALID,
            3,
        );
        let mut u = read_capture(
            &fixture("f2-dangling-split-mapping-unavailable"),
            false,
            default_limits(),
        )
        .expect("open");
        assert_eq!(drain(&mut u).expect("drain").len(), 8);
        assert!(!u.partial);
    }

    #[test]
    fn reader_double_unmap_partial_still_refused() {
        expect_error(
            &fixture("f2-double-unmap-partial"),
            false,
            default_limits(),
            READ_INVALID,
            4,
        );
    }

    #[test]
    fn reader_excused_unmap_repeat_refused() {
        expect_message(
            &fixture("f2-excused-unmap-repeat"),
            false,
            default_limits(),
            READ_INVALID,
            4,
            "line 4: mapping released twice",
        );
    }

    #[test]
    fn reader_excused_unmap_remap_refused() {
        expect_message(
            &fixture("f2-excused-unmap-remap"),
            false,
            default_limits(),
            READ_INVALID,
            4,
            "line 4: duplicate mapping",
        );
    }

    #[test]
    fn reader_early_unmap_partial_ok() {
        let mut r = read_capture(&fixture("f2-early-unmap-partial"), false, default_limits())
            .expect("open");
        assert_eq!(drain(&mut r).expect("drain").len(), 1);
        assert!(!r.partial);
    }

    #[test]
    fn reader_ref_dedup() {
        let mut r = CaptureReader::new();
        r.note_copy_ref("m1", 5);
        r.note_copy_ref("m1", 7);
        r.note_sync_ref("m1", 9);
        r.note_copy_ref("m2", 11);
        assert_eq!(r.ref_copy_len(), 2);
        assert_eq!(r.ref_copy_at(0), ("m1".to_string(), 5));
        assert_eq!(r.ref_copy_at(1), ("m2".to_string(), 11));
        assert_eq!(r.ref_sync_len(), 1);
        assert_eq!(r.ref_sync_at(0), ("m1".to_string(), 9));
        let err = r.finish_checks().unwrap_err();
        assert_eq!((err.code, err.line_no), (READ_INVALID, 5));
    }

    #[test]
    fn reader_multi_chunk() {
        let mut r = read_capture(&fixture("multi-chunk"), false, default_limits()).expect("open");
        let events = drain(&mut r).expect("drain");
        assert_eq!(events.len(), 400);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[399].seq, 400);
        assert_eq!(events[399].ts_ns, 1400000000);
        assert!(!r.partial);
        assert!(!r.has_more().expect("eof"));
    }

    #[test]
    fn reader_missing() {
        // Contract: a missing dir or a capture without
        // session.json enters the recovery path, whose open
        // failures are READ_INVALID; only a finalized capture
        // with a missing events file is READ_IO.
        let limits = default_limits();
        expect_error(&fixture("no-such-dir"), false, limits, READ_INVALID, 0);
        expect_error(&fixture("missing-events"), false, limits, READ_IO, 0);
        expect_error(&fixture("missing-session"), false, limits, READ_INVALID, 0);
    }

    #[test]
    fn reader_nul_in_path() {
        // A NUL byte in the capture dir refuses as READ_IO in
        // both modes: the path never reaches the kernel.
        let limits = default_limits();
        let nul_dir = format!("{}/x\0y", fixture("missing-session"));
        expect_error(&nul_dir, false, limits, READ_IO, 0);
        expect_error(&nul_dir, true, limits, READ_IO, 0);
    }

    #[test]
    fn reader_empty_and_crlf() {
        let limits = default_limits();
        let mut empty = read_capture(&fixture("empty-events"), false, limits).expect("open");
        assert_eq!(drain(&mut empty).expect("drain").len(), 0);
        assert!(!empty.partial);
        let mut crlf = read_capture(&fixture("crlf"), false, limits).expect("open");
        assert_eq!(drain(&mut crlf).expect("drain").len(), 3);
    }

    fn check_tail(text: &str, want: u8) {
        assert_eq!(classify_tail(text.as_bytes()), want, "text={text:?}");
    }

    fn check_tail_bytes(raw: &[u8], want: u8) {
        assert_eq!(classify_tail(raw), want, "raw={raw:?}");
    }

    #[test]
    fn classify_tail_cases() {
        check_tail("{}", TAIL_COMPLETE);
        check_tail("[]", TAIL_COMPLETE);
        check_tail("123", TAIL_COMPLETE);
        check_tail("-0", TAIL_COMPLETE);
        check_tail("-0.5e+3", TAIL_COMPLETE);
        check_tail("\"a\"", TAIL_COMPLETE);
        check_tail("true", TAIL_COMPLETE);
        check_tail("false", TAIL_COMPLETE);
        check_tail("null", TAIL_COMPLETE);
        check_tail("  { \"a\" : [1, {\"b\": null}] }  ", TAIL_COMPLETE);
        check_tail("\"caf\\u00e9\"", TAIL_COMPLETE);
        check_tail("\"\\ud800\"", TAIL_COMPLETE);
        check_tail("{", TAIL_INCOMPLETE);
        check_tail("{\"a\"", TAIL_INCOMPLETE);
        check_tail("{\"a\":", TAIL_INCOMPLETE);
        check_tail("{\"a\":1", TAIL_INCOMPLETE);
        check_tail("{\"a\":1,", TAIL_INCOMPLETE);
        check_tail("[1,", TAIL_INCOMPLETE);
        check_tail("\"abc", TAIL_INCOMPLETE);
        check_tail("\"a\\u12", TAIL_INCOMPLETE);
        check_tail("\"a\\", TAIL_INCOMPLETE);
        check_tail("tru", TAIL_INCOMPLETE);
        check_tail("fals", TAIL_INCOMPLETE);
        check_tail("nul", TAIL_INCOMPLETE);
        check_tail("-", TAIL_INCOMPLETE);
        check_tail("1e", TAIL_INCOMPLETE);
        check_tail("1e+", TAIL_INCOMPLETE);
        check_tail("1.", TAIL_INCOMPLETE);
        check_tail("", TAIL_INVALID);
        check_tail("   ", TAIL_INVALID);
        check_tail("}", TAIL_INVALID);
        check_tail("{,}", TAIL_INVALID);
        check_tail("{\"a\":}", TAIL_INVALID);
        check_tail("[1,]", TAIL_INVALID);
        check_tail("hello", TAIL_INVALID);
        check_tail("truX", TAIL_INVALID);
        check_tail("01", TAIL_INVALID);
        check_tail("{}}", TAIL_INVALID);
        check_tail("{} {}", TAIL_INVALID);
        check_tail("\"\\x\"", TAIL_INVALID);
        check_tail("\"\\u12Z\"", TAIL_INVALID);
        let mut cut = b"\"ab".to_vec();
        cut.extend([0xE2, 0x82]);
        check_tail_bytes(&cut, TAIL_INCOMPLETE);
        let mut bad = b"\"ab".to_vec();
        bad.extend([0xFF, 0x22]);
        check_tail_bytes(&bad, TAIL_INVALID);
        let mut overlong = b"\"".to_vec();
        overlong.extend([0xC0, 0x80, 0x22]);
        check_tail_bytes(&overlong, TAIL_INVALID);
        check_tail(&"[".repeat(65), TAIL_INVALID);
        let mut raw = b"{\"k\":\"v".to_vec();
        raw.push(0x1B);
        check_tail_bytes(&raw, TAIL_INVALID);
    }

    #[test]
    fn partial_record_definitive_cases() {
        let sid = "attempts-3-session";
        let line = first_line("attempts/events.ndjson");
        assert!(!partial_record_definitive(&cut_last(&line), sid));
        assert!(!partial_record_definitive(
            &cat(&prefix_before(&line, "\"kind\""), b"\"kind\": \"bou"),
            sid
        ));
        assert!(!partial_record_definitive(
            &tail_chunk("reader/partial-tail/events.ndjson"),
            sid
        ));
        assert!(!partial_record_definitive(b"{", sid));
        let bad_version = line.replace("\"0.1.1\"", "\"9.0.0\"");
        assert!(partial_record_definitive(&cut_last(&bad_version), sid));
        assert!(partial_record_definitive(
            &cat(&cut_last(&line), b", \"seq\": \"9"),
            sid
        ));
        assert!(partial_record_definitive(b"{\"zzz\": \"tru", sid));
        let bad_kind = line.replace("\"bounce_attempt\"", "\"bogus\"");
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&bad_kind, "\"data\""),
                b"\"data\": {\"device_id\": \"dev-1\""
            ),
            sid
        ));
        let bad_measure = line.replace(
            "\"measurement\": \"observed\"",
            "\"measurement\": \"bogus\"",
        );
        assert!(partial_record_definitive(
            &prefix_before(&bad_measure, "\"data\""),
            sid
        ));
        assert!(partial_record_definitive(b"tru", sid));
        assert!(partial_record_definitive(b"[1,2", sid));
        let bad_session = line.replace(sid, "someone-else-session");
        assert!(partial_record_definitive(&cut_last(&bad_session), sid));
        let missing_backend = line.replace(", \"backend\": \"synthetic\"", "");
        assert!(partial_record_definitive(
            &prefix_before(&missing_backend, "\"data\""),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&line, "\"data\""),
                b"\"data\": {\"device_id\": \"dev-1\", \"zzz\": \"tru"
            ),
            sid
        ));
        let sync_line = nth_line("reader/f3-span-sync/events.ndjson", 1);
        assert!(sync_line.contains("sync_request"));
        assert!(partial_record_definitive(
            &cut_last(&sync_line),
            "lifecycle-mini-session"
        ));
        assert!(partial_record_definitive(
            b"{\"schema_version\": \"0.1.1\", \"schema_version\"",
            sid
        ));
        assert!(partial_record_definitive(b"{\"unknown\"", sid));
        assert!(partial_record_definitive(
            &cat(&prefix_before(&line, "\"seq\""), b"\"seq\": tru"),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(&prefix_before(&line, "\"forced\""), b"\"forced\": \"tru"),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&line, "\"source\""),
                b"\"source\": {\"hook\": tru"
            ),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(&prefix_before(&line, "\"data\""), b"\"data\": tru"),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&line, "\"data\""),
                b"\"data\": {\"device_id\": \"dev-1\", \"device_id\""
            ),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(&prefix_before(&line, "\"data\""), b"\"data\": {\"zzz\""),
            sid
        ));
        let life = "lifecycle-mini-session";
        let unmap_line = nth_line("lifecycle/events-ok.ndjson", 3);
        assert!(unmap_line.contains("\"unmap\""));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&unmap_line, "\"mapping_id\""),
                b"\"mapping_id\": tru"
            ),
            life
        ));
        assert!(!partial_record_definitive(
            &cat(&prefix_before(&line, "\"seq\""), b"\"seq\": \"12"),
            sid
        ));
        assert!(!partial_record_definitive(
            &cat(&prefix_before(&line, "\"forced\""), b"\"forced\": tru"),
            sid
        ));
        assert!(!partial_record_definitive(
            &cat(
                &prefix_before(&unmap_line, "\"mapping_id\""),
                b"\"mapping_id\": nul"
            ),
            life
        ));
        assert!(!partial_record_definitive(b"{\"seq\":", sid));
        assert!(!partial_record_definitive(
            &cat(
                &prefix_before(&line, "\"data\""),
                b"\"data\": {\"device_id\": \"dev-1\", \"requested_bytes\": \"40"
            ),
            sid
        ));
        assert!(!partial_record_definitive(
            &cat(
                &prefix_before(&line, "\"data\""),
                b"\"observer_context\": {\"cpu\": 4"
            ),
            sid
        ));
        let map_line = nth_line("lifecycle/events-ok.ndjson", 1);
        assert!(map_line.contains("\"map_result\""));
        assert!(!partial_record_definitive(
            &cat(
                &prefix_before(&map_line, "\"return_code\""),
                b"\"return_code\": nul"
            ),
            life
        ));
        let snap_line = nth_line("reader/f9-agree/events.ndjson", 3);
        assert!(snap_line.contains("\"counter_snapshot\""));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&snap_line, "\"scope\""),
                b"\"scope\": {\"device_id\": tru"
            ),
            sid
        ));
        assert!(partial_record_definitive(
            &cat(
                &prefix_before(&snap_line, "\"scope\""),
                b"\"scope\": {\"profile_id\": fal"
            ),
            sid
        ));
        assert!(!partial_record_definitive(
            &cat(
                &prefix_before(&snap_line, "\"scope\""),
                b"\"scope\": {\"device_id\": \"dev"
            ),
            sid
        ));
    }

    #[test]
    fn f12_hostile_member_not_echoed() {
        let line = first_line("reader/unsanitized-error/events.ndjson");
        assert!(line.contains("dummy_pin_0000"));
        let err = parse_event(line.as_bytes()).unwrap_err();
        let msg = err.to_string();
        assert!(!msg.contains("dummy_pin_0000"));
        assert!(msg.contains("unknown event field"));
        assert!(!msg.as_bytes().contains(&0x1B));
        let mut reader =
            read_capture(&fixture("unsanitized-error"), false, default_limits()).expect("open");
        let err = drain(&mut reader).unwrap_err();
        let rmsg = format!("{err:?}");
        assert!(!rmsg.contains("dummy_pin_0000"));
        assert!(!rmsg.as_bytes().contains(&0x1B));
    }

    #[test]
    fn adversarial_exact_line_boundary() {
        let limits = default_limits();
        expect_error(&fixture("size-ok"), false, limits, READ_PARSE, 1);
        expect_error(&fixture("size-over"), false, limits, READ_TOO_BIG, 1);
    }

    #[test]
    fn adversarial_hostile_bytes() {
        expect_error(
            &fixture("adv-bad-utf8"),
            false,
            default_limits(),
            READ_PARSE,
            1,
        );
        expect_error(&fixture("adv-nul"), false, default_limits(), READ_PARSE, 1);
        expect_error(
            &fixture("adv-unknown-field"),
            false,
            default_limits(),
            READ_PARSE,
            1,
        );
        expect_error(
            &fixture("adv-bad-seq-int"),
            false,
            default_limits(),
            READ_PARSE,
            1,
        );
    }

    #[test]
    fn adversarial_sequences() {
        expect_error(&fixture("badseq"), false, default_limits(), READ_INVALID, 2);
        expect_error(
            &fixture("adv-reversed-seq"),
            false,
            default_limits(),
            READ_INVALID,
            2,
        );
        expect_error(
            &fixture("foreign"),
            false,
            default_limits(),
            READ_INVALID,
            1,
        );
        expect_error(
            &fixture("f2-duplicate-op"),
            false,
            default_limits(),
            READ_INVALID,
            2,
        );
    }

    #[test]
    fn adversarial_depth_boundaries() {
        let limits = default_limits();
        expect_error(&fixture("adv-depth-64"), false, limits, READ_PARSE, 1);
        expect_error(&fixture("adv-depth-65"), false, limits, READ_PARSE, 1);
    }

    #[test]
    fn adversarial_definitive_dupkey() {
        // Three valid lines, then an unterminated tail repeating "seq":
        // the duplicate key is definitive on line 4.
        expect_error(
            &fixture("f4-definitive-dupkey"),
            false,
            default_limits(),
            READ_PARSE,
            4,
        );
    }

    #[test]
    fn adversarial_u64_sum_overflow() {
        let limits = default_limits();
        expect_error(&fixture("overflow"), false, limits, READ_INVALID, 2);
        expect_error(&fixture("f3-sum-overflow"), false, limits, READ_INVALID, 2);
    }

    #[test]
    fn adversarial_unknown_major_and_kind() {
        expect_error(
            &fixture("compat-major"),
            false,
            default_limits(),
            READ_PARSE,
            0,
        );
        expect_error(&fixture("badkind"), false, default_limits(), READ_PARSE, 1);
    }

    #[test]
    fn sealed_capture_reads() {
        let mut r =
            read_capture(&fixture("sealed-complete"), false, default_limits()).expect("open");
        assert!(!r.integrity_verified);
        let events = drain(&mut r).expect("drain");
        assert!(r.integrity_verified);
        assert_eq!(events.len() as u64, r.session.integrity.line_count);
    }

    fn sealed_case(session: &[u8], events: &[u8]) -> TestDir {
        let tmp = TestDir::create("memveil-sealed").expect("mkdtemp");
        std::fs::write(tmp.path().join("session.json"), session).expect("session");
        std::fs::write(tmp.path().join("events.ndjson"), events).expect("events");
        tmp
    }

    fn split_lines(raw: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut start = 0;
        for (i, &b) in raw.iter().enumerate() {
            if b == b'\n' {
                out.push(raw[start..=i].to_vec());
                start = i + 1;
            }
        }
        if start < raw.len() {
            out.push(raw[start..].to_vec());
        }
        out
    }

    #[test]
    fn sealed_event_mutations_refuse_in_both_modes() {
        let original = fixture_bytes("reader/sealed-complete/session.json");
        let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
        let lines = split_lines(&raw);
        assert!(lines.len() >= 3);
        let cases: Vec<(&str, Vec<u8>, u32, usize)> = vec![
            (
                "delete-first",
                [lines[1].clone(), lines[2].clone()].concat(),
                READ_INVALID,
                1,
            ),
            (
                "delete-middle",
                [lines[0].clone(), lines[2].clone()].concat(),
                READ_INVALID,
                2,
            ),
            (
                "delete-last",
                [lines[0].clone(), lines[1].clone()].concat(),
                READ_INVALID,
                0,
            ),
            (
                "same-length",
                replace_first(&raw, b"4096", b"4097"),
                READ_INVALID,
                0,
            ),
            (
                "append",
                [raw.clone(), lines[2].clone()].concat(),
                READ_INVALID,
                4,
            ),
            (
                "swap",
                [lines[1].clone(), lines[0].clone(), lines[2].clone()].concat(),
                READ_INVALID,
                1,
            ),
            (
                "duplicate",
                [lines[0].clone(), raw.clone()].concat(),
                READ_INVALID,
                2,
            ),
            (
                "missing-newline",
                raw[..raw.len() - 1].to_vec(),
                READ_INVALID,
                3,
            ),
            (
                "truncated-tail",
                raw[..raw.len() - 10].to_vec(),
                READ_INVALID,
                3,
            ),
            (
                "whitespace",
                replace_first(&raw, b"{", b"{ "),
                READ_INVALID,
                0,
            ),
            (
                "carriage-return",
                replace_first(&raw, b"\n", b"\r\n"),
                READ_INVALID,
                0,
            ),
        ];
        assert_eq!(cases[3].1.len(), raw.len(), "same-length keeps size");
        for (name, changed, _, _) in &cases {
            assert_ne!(*changed, raw, "{name}");
        }
        for (_, changed, code, line) in cases {
            for allow in [false, true] {
                let tmp = sealed_case(&original, &changed);
                expect_error(tmp.as_str(), allow, default_limits(), code, line);
            }
        }
    }

    #[test]
    fn sealed_session_mutations_name_integrity_mismatch() {
        let original = fixture_bytes("reader/sealed-complete/session.json");
        let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
        let lines = split_lines(&raw);
        let base = parse_session(&original).expect("sealed parses");
        let mut edits: Vec<(&str, crate::model::session::Session)> = Vec::new();
        let mut e = base.clone();
        e.integrity.events_bytes = raw.len() as u64 + 1;
        edits.push(("events_bytes", e));
        let mut e = base.clone();
        e.integrity.line_count = lines.len() as u64 + 1;
        e.integrity.last_seq = lines.len() as u64;
        e.integrity.kinds[8] = 1;
        edits.push(("line_count", e));
        let mut e = base.clone();
        e.integrity.kinds[0] -= 1;
        e.integrity.kinds[8] = 1;
        edits.push(("kinds", e));
        let mut e = base.clone();
        e.integrity.events_sha256 = "0".repeat(64);
        edits.push(("events_sha256", e));
        for (name, session) in edits {
            let encoded = encode_session(&session).expect("encode edit");
            for allow in [false, true] {
                let tmp = sealed_case(encoded.as_bytes(), &raw);
                let mut got_code = 0;
                let mut got_msg = String::new();
                match read_capture(tmp.as_str(), allow, default_limits()) {
                    Ok(mut r) => match drain(&mut r) {
                        Ok(_) => {}
                        Err(e) => {
                            got_code = e.code;
                            got_msg = e.message;
                        }
                    },
                    Err(e) => {
                        got_code = e.code;
                        got_msg = e.message;
                    }
                }
                assert_eq!(got_code, READ_INVALID, "mutation={name} allow={allow}");
                assert!(got_msg.contains("integrity"), "mutation={name}: {got_msg}");
                assert!(got_msg.contains("mismatch"), "mutation={name}: {got_msg}");
            }
        }
    }

    #[test]
    fn unfinalized_session_requires_checkpoint_recovery() {
        let original = fixture_bytes("reader/sealed-complete/session.json");
        let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
        let mut session = parse_session(&original).expect("sealed parses");
        session.finalized = false;
        session.end_reason = "checkpoint".to_string();
        session.has_checkpoint_generation = true;
        session.checkpoint_generation = 7;
        let encoded = encode_session(&session).expect("encode");
        let tmp = sealed_case(encoded.as_bytes(), &raw);
        expect_message(
            tmp.as_str(),
            false,
            default_limits(),
            READ_INVALID,
            0,
            "unfinalized session requires checkpoint recovery",
        );
    }

    fn checkpoint_case(suffix: &[u8]) -> (TestDir, Vec<u8>) {
        let original = fixture_bytes("reader/sealed-complete/session.json");
        let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
        let mut session = parse_session(&original).expect("sealed parses");
        session.finalized = false;
        session.end_reason = "checkpoint".to_string();
        session.has_checkpoint_generation = true;
        session.checkpoint_generation = 1;
        let encoded = encode_session(&session).expect("encode checkpoint");
        let tmp = TestDir::create("memveil-ckpt").expect("mkdtemp");
        std::fs::write(tmp.path().join("checkpoint.json"), encoded.as_bytes()).expect("ckpt");
        std::fs::write(
            tmp.path().join("events.ndjson"),
            [raw.clone(), suffix.to_vec()].concat(),
        )
        .expect("events");
        (tmp, raw)
    }

    #[test]
    fn recovery_verified_prefix_ignores_suffix() {
        let raw0 = fixture_bytes("reader/sealed-complete/events.ndjson");
        let suffixes: Vec<Vec<u8>> = vec![Vec::new(), b"not JSON\x00\xff".to_vec(), raw0.clone()];
        for suffix in suffixes {
            let (tmp, raw) = checkpoint_case(&suffix);
            // Without --allow-partial the prefix demand names the flag.
            let mut got_code = 0;
            let mut got_msg = String::new();
            match read_capture(tmp.as_str(), false, default_limits()) {
                Ok(mut r) => match drain(&mut r) {
                    Ok(_) => {}
                    Err(e) => {
                        got_code = e.code;
                        got_msg = e.message;
                    }
                },
                Err(e) => {
                    got_code = e.code;
                    got_msg = e.message;
                }
            }
            assert_eq!(got_code, READ_INVALID);
            assert!(got_msg.contains("--allow-partial"), "{got_msg}");
            let mut r = read_capture(tmp.as_str(), true, default_limits()).expect("recover");
            assert!(r.checkpoint_prefix);
            assert!(r.partial);
            assert_eq!(r.unverified_bytes, suffix.len() as u64);
            let events = drain(&mut r).expect("drain prefix");
            assert_eq!(events.len() as u64, r.session.integrity.line_count);
            assert_eq!(r.session.integrity.events_bytes, raw.len() as u64);
            assert!(r.integrity_verified);
        }
    }

    #[test]
    fn recovery_final_precedence_and_active_writer() {
        let (tmp, _) = checkpoint_case(b"");
        // An exclusively locked directory refuses as an active writer.
        let cpath = std::ffi::CString::new(tmp.as_str()).expect("cstr");
        // SAFETY: live scratch path; the fd closes below.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
        assert!(fd >= 0);
        // SAFETY: live dir fd.
        assert_eq!(unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) }, 0);
        let err = read_capture(tmp.as_str(), true, default_limits()).unwrap_err();
        // SAFETY: owned test fd.
        unsafe { libc::close(fd) };
        assert_eq!(err.code, READ_INVALID);
        assert!(err.message.contains("active writer"), "{}", err.message);
        // A broken final session fails closed even with --allow-partial.
        std::fs::write(tmp.path().join("session.json"), b"{broken").expect("break final");
        expect_error(tmp.as_str(), true, default_limits(), READ_PARSE, 0);
        // A valid final session takes precedence over the checkpoint.
        let sealed = fixture_bytes("reader/sealed-complete/session.json");
        std::fs::write(tmp.path().join("session.json"), &sealed).expect("restore final");
        let mut r = read_capture(tmp.as_str(), true, default_limits()).expect("final wins");
        assert!(!r.checkpoint_prefix);
        assert_eq!(drain(&mut r).expect("drain").len(), 3);
    }

    #[test]
    fn recovery_symlinks_and_special_files_refuse() {
        for name in ["checkpoint.json", "events.ndjson"] {
            for kind in ["symlink", "fifo", "directory"] {
                let (tmp, _) = checkpoint_case(b"");
                let target = tmp.path().join(name);
                std::fs::rename(&target, tmp.path().join("owned-backup")).expect("stash");
                match kind {
                    "symlink" => std::os::unix::fs::symlink("owned-backup", &target).expect("link"),
                    "fifo" => {
                        let c = std::ffi::CString::new(target.to_str().unwrap()).expect("cstr");
                        // SAFETY: scratch path.
                        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                    }
                    _ => std::fs::create_dir(&target).expect("mkdir"),
                }
                expect_error(tmp.as_str(), true, default_limits(), READ_INVALID, 0);
            }
        }
    }

    #[test]
    fn recovery_stale_tmp_ignored_but_fifo_final_refuses() {
        let (tmp, _) = checkpoint_case(b"");
        std::fs::write(
            tmp.path().join("checkpoint.json.tmp"),
            b"foreign stale checkpoint",
        )
        .expect("stale");
        let mut r = read_capture(tmp.as_str(), true, default_limits()).expect("stale ignored");
        assert_eq!(drain(&mut r).expect("drain").len(), 3);
        assert_eq!(
            std::fs::read(tmp.path().join("checkpoint.json.tmp")).expect("read stale"),
            b"foreign stale checkpoint"
        );
        let c = std::ffi::CString::new(tmp.path().join("session.json").to_str().unwrap())
            .expect("cstr");
        // SAFETY: scratch path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        expect_error(tmp.as_str(), true, default_limits(), READ_INVALID, 0);
    }

    #[test]
    fn recovery_symlinked_dir_refuses() {
        let (tmp, _) = checkpoint_case(b"");
        let alias = tmp
            .path()
            .parent()
            .unwrap()
            .join(format!("memveil-alias-{}", std::process::id()));
        std::os::unix::fs::symlink(tmp.path(), &alias).expect("alias");
        let err = read_capture(alias.to_str().unwrap(), true, default_limits()).unwrap_err();
        assert_eq!(err.code, READ_INVALID);
        std::fs::remove_file(&alias).expect("unlink alias");
    }

    #[test]
    fn recovery_corrupt_prefix_never_salvages() {
        let kinds = [
            "digest",
            "literal",
            "identity",
            "kinds",
            "torn-prefix",
            "unknown-version",
        ];
        for mutation in kinds {
            let original = fixture_bytes("reader/sealed-complete/session.json");
            let mut raw = fixture_bytes("reader/sealed-complete/events.ndjson");
            let mut session = parse_session(&original).expect("sealed parses");
            session.finalized = false;
            session.end_reason = "checkpoint".to_string();
            session.has_checkpoint_generation = true;
            session.checkpoint_generation = 1;
            if mutation == "digest" {
                session.integrity.events_sha256 = "f".repeat(64);
            } else if mutation == "identity" {
                session.session_id = "different-session".to_string();
            } else if mutation == "kinds" {
                session.integrity.kinds[0] = 2;
                session.integrity.kinds[3] = 1;
            } else if mutation == "torn-prefix" {
                session.integrity.events_bytes = raw.len() as u64 - 1;
                session.integrity.events_sha256 = sha256_hex(&raw[..raw.len() - 1]);
            }
            let mut encoded = encode_session(&session).expect("encode");
            if mutation == "unknown-version" {
                encoded = encoded.replacen("\"0.1.4\"", "\"0.1.5\"", 1);
                assert!(encoded.contains("\"0.1.5\""));
            }
            if mutation == "literal" {
                raw = replace_first(&raw, b"4096", b"4097");
            }
            let tmp = TestDir::create("memveil-ckpt").expect("mkdtemp");
            std::fs::write(tmp.path().join("checkpoint.json"), encoded.as_bytes()).expect("ckpt");
            std::fs::write(
                tmp.path().join("events.ndjson"),
                [raw, b"ignored suffix".to_vec()].concat(),
            )
            .expect("events");
            for allow in [false, true] {
                let mut got_code = 0;
                match read_capture(tmp.as_str(), allow, default_limits()) {
                    Ok(mut r) => {
                        if let Err(e) = drain(&mut r) {
                            got_code = e.code;
                        }
                    }
                    Err(e) => got_code = e.code,
                }
                assert!(
                    got_code == READ_INVALID || got_code == READ_PARSE,
                    "mutation={mutation} allow={allow}: code={got_code}"
                );
            }
        }
    }

    #[test]
    fn recovery_invalid_prefix_and_generation() {
        for spelling in ["0", "01"] {
            let original = fixture_bytes("reader/sealed-complete/session.json");
            let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
            let mut session = parse_session(&original).expect("sealed parses");
            session.finalized = false;
            session.end_reason = "checkpoint".to_string();
            session.has_checkpoint_generation = true;
            session.checkpoint_generation = 1;
            // Neither spelling is a valid generation; rewrite at text level.
            // Canonical encode spells `"key":"value"` with no space.
            let encoded = encode_session(&session).expect("encode").replacen(
                "\"checkpoint_generation\":\"1\"",
                &format!("\"checkpoint_generation\":\"{spelling}\""),
                1,
            );
            assert!(encoded.contains(&format!("\"checkpoint_generation\":\"{spelling}\"")));
            let tmp = TestDir::create("memveil-ckpt").expect("mkdtemp");
            std::fs::write(tmp.path().join("checkpoint.json"), encoded.as_bytes()).expect("ckpt");
            std::fs::write(tmp.path().join("events.ndjson"), &raw).expect("events");
            let mut got_code = 0;
            match read_capture(tmp.as_str(), true, default_limits()) {
                Ok(mut r) => {
                    if let Err(e) = drain(&mut r) {
                        got_code = e.code;
                    }
                }
                Err(e) => got_code = e.code,
            }
            assert!(
                got_code == READ_INVALID || got_code == READ_PARSE,
                "spelling={spelling}: code={got_code}"
            );
        }
        // Events shorter than the declared prefix refuse.
        let original = fixture_bytes("reader/sealed-complete/session.json");
        let raw = fixture_bytes("reader/sealed-complete/events.ndjson");
        let mut session = parse_session(&original).expect("sealed parses");
        session.finalized = false;
        session.end_reason = "checkpoint".to_string();
        session.has_checkpoint_generation = true;
        session.checkpoint_generation = 1;
        let encoded = encode_session(&session).expect("encode");
        let tmp = TestDir::create("memveil-ckpt").expect("mkdtemp");
        std::fs::write(tmp.path().join("checkpoint.json"), encoded.as_bytes()).expect("ckpt");
        std::fs::write(tmp.path().join("events.ndjson"), &raw[..raw.len() - 1]).expect("events");
        let mut got_code = 0;
        match read_capture(tmp.as_str(), true, default_limits()) {
            Ok(mut r) => {
                if let Err(e) = drain(&mut r) {
                    got_code = e.code;
                }
            }
            Err(e) => got_code = e.code,
        }
        assert!(
            got_code == READ_INVALID || got_code == READ_PARSE,
            "short events: code={got_code}"
        );
    }

    #[test]
    fn finalized_special_files_refuse_before_reading() {
        for fixture_name in ["sealed-complete", "sealed-empty", "complete-stop"] {
            for name in ["session.json", "events.ndjson"] {
                for kind in ["fifo", "directory", "device-link"] {
                    let tmp = TestDir::create("memveil-special").expect("mkdtemp");
                    for entry in ["session.json", "events.ndjson"] {
                        let data = fixture_bytes(&format!("reader/{fixture_name}/{entry}"));
                        std::fs::write(tmp.path().join(entry), data).expect("copy");
                    }
                    let target = tmp.path().join(name);
                    std::fs::remove_file(&target).expect("unlink");
                    match kind {
                        "fifo" => {
                            let c = std::ffi::CString::new(target.to_str().unwrap()).expect("cstr");
                            // SAFETY: scratch path.
                            assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
                        }
                        "directory" => std::fs::create_dir(&target).expect("mkdir"),
                        _ => std::os::unix::fs::symlink("/dev/null", &target).expect("dev link"),
                    }
                    for allow in [false, true] {
                        let mut got_code = 0;
                        match read_capture(tmp.as_str(), allow, default_limits()) {
                            Ok(mut r) => {
                                if let Err(e) = drain(&mut r) {
                                    got_code = e.code;
                                }
                            }
                            Err(e) => got_code = e.code,
                        }
                        assert!(
                            got_code == READ_INVALID || got_code == READ_PARSE,
                            "fixture={fixture_name} name={name} kind={kind} allow={allow}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn finalized_symlinks_and_hardlinks_compatible() {
        for kind in ["symlink", "hardlink"] {
            for fixture_name in ["sealed-complete", "complete-stop"] {
                let tmp = TestDir::create("memveil-link").expect("mkdtemp");
                for name in ["session.json", "events.ndjson"] {
                    if kind == "symlink" {
                        std::os::unix::fs::symlink(
                            repo_root()
                                .join("tests/fixtures/reader")
                                .join(fixture_name)
                                .join(name),
                            tmp.path().join(name),
                        )
                        .expect("symlink");
                    } else {
                        let data = fixture_bytes(&format!("reader/{fixture_name}/{name}"));
                        let real = tmp.path().join(format!("{name}.real"));
                        std::fs::write(&real, data).expect("write real");
                        std::fs::hard_link(&real, tmp.path().join(name)).expect("hardlink");
                    }
                }
                let mut r = read_capture(tmp.as_str(), false, default_limits())
                    .expect("linked capture opens");
                drain(&mut r).expect("linked capture drains");
            }
        }
    }

    #[test]
    fn read_capture_os_matches_str_reader() {
        // Differential pin: the byte entry point returns the &str
        // reader's own verdict on every ASCII shape, so existing
        // callers and corpus verdicts do not move.
        use super::read_capture_os;
        use std::ffi::OsStr;
        let tmp = TestDir::create("memveil-os-diff").expect("mkdtemp");
        let empty = tmp.path().join("empty");
        std::fs::create_dir(&empty).expect("mkdir empty");
        let file = tmp.path().join("file");
        std::fs::write(&file, b"x").expect("write file");
        let shapes = [
            "/nonexistent-memveil-os-diff-xyz".to_string(),
            "/tmp".to_string(),
            "/etc/hostname".to_string(),
            empty.to_str().expect("utf-8").to_string(),
            file.to_str().expect("utf-8").to_string(),
            fixture("sealed-complete"),
            fixture("sealed-empty"),
            fixture("corrupt-tail"),
        ];
        for path in shapes {
            for allow in [false, true] {
                let via_str = read_capture(&path, allow, default_limits())
                    .map(|r| (r.session.session_id.clone(), r.partial))
                    .map_err(|e| (e.code, e.line_no, e.message));
                let via_os = read_capture_os(OsStr::new(&path), allow, default_limits())
                    .map(|r| (r.session.session_id.clone(), r.partial))
                    .map_err(|e| (e.code, e.line_no, e.message));
                assert_eq!(via_str, via_os, "spellings must agree for {path}");
            }
        }
        // A drained capture agrees event for event.
        let mut a =
            read_capture(&fixture("sealed-complete"), false, default_limits()).expect("str opens");
        let mut b = read_capture_os(
            OsStr::new(&fixture("sealed-complete")),
            false,
            default_limits(),
        )
        .expect("os opens");
        let ea = drain(&mut a).expect("str drains");
        let eb = drain(&mut b).expect("os drains");
        assert_eq!(ea.len(), eb.len());
        assert_eq!(ea.len(), 3);
        for (x, y) in ea.iter().zip(eb.iter()) {
            assert_eq!(x.seq, y.seq);
            assert_eq!(x.ts_ns, y.ts_ns);
        }
        assert_eq!(a.integrity_verified, b.integrity_verified);
        assert!(a.integrity_verified);
    }

    #[test]
    fn read_capture_os_opens_non_utf8() {
        // Finalized and checkpoint captures at non-UTF-8 paths
        // open and drain like their ASCII twins.
        use super::read_capture_os;
        use std::os::unix::ffi::OsStringExt;
        let tmp = TestDir::create("memveil-os-ff").expect("mkdtemp");
        let ff = tmp
            .path()
            .join(std::ffi::OsString::from_vec(b"cap\xff".to_vec()));
        std::fs::create_dir(&ff).expect("mkdir ff dir");
        // Finalized twin: the sealed session and events verbatim.
        std::fs::write(
            ff.join("session.json"),
            fixture_bytes("reader/sealed-complete/session.json"),
        )
        .expect("write session");
        std::fs::write(
            ff.join("events.ndjson"),
            fixture_bytes("reader/sealed-complete/events.ndjson"),
        )
        .expect("write events");
        let mut r = read_capture_os(ff.as_os_str(), false, default_limits()).expect("ff opens");
        assert!(!r.checkpoint_prefix);
        assert_eq!(drain(&mut r).expect("ff drains").len(), 3);
        assert!(r.integrity_verified);
        // Checkpoint twin: sealed session retired to a checkpoint.
        let ck = tmp
            .path()
            .join(std::ffi::OsString::from_vec(b"ckpt\xff".to_vec()));
        std::fs::create_dir(&ck).expect("mkdir ck dir");
        let session = fixture_text("reader/sealed-complete/session.json");
        let retired = session.replacen("\"finalized\": true", "\"finalized\": false", 1);
        assert_ne!(retired, session);
        let checkpoint = retired.replacen(
            "\"end_reason\": \"duration\"",
            "\"end_reason\": \"checkpoint\",\n    \"checkpoint_generation\": \"1\"",
            1,
        );
        assert_ne!(checkpoint, retired);
        std::fs::write(ck.join("checkpoint.json"), checkpoint).expect("write checkpoint");
        std::fs::write(
            ck.join("events.ndjson"),
            fixture_bytes("reader/sealed-complete/events.ndjson"),
        )
        .expect("write events");
        let err = read_capture_os(ck.as_os_str(), false, default_limits()).unwrap_err();
        assert_eq!(err.code, READ_INVALID);
        assert!(err.message.contains("--allow-partial"), "{}", err.message);
        let mut r = read_capture_os(ck.as_os_str(), true, default_limits()).expect("ck recovers");
        assert!(r.checkpoint_prefix);
        assert!(r.partial);
        assert_eq!(drain(&mut r).expect("ck drains").len(), 3);
        assert!(r.integrity_verified);
        // Refusals keep their ASCII messages on raw paths.
        let missing = tmp
            .path()
            .join(std::ffi::OsString::from_vec(b"no\xff".to_vec()));
        let err = read_capture_os(missing.as_os_str(), false, default_limits()).unwrap_err();
        assert_eq!(err.message, "capture directory does not exist");
        assert!(read_remedy(&err.message).is_some());
    }

    #[test]
    fn read_remedy_pairs_and_gaps() {
        // Every fixed open cause carries a remedy; member
        // ownership shares the directory remedy; anything else
        // (caller bytes, parse detail) stays single-line.
        for (cause, fix) in [
            (
                "capture directory does not exist",
                "check the path spelling and retry with an existing capture directory",
            ),
            (
                "capture path is not a directory",
                "pass a capture directory (a directory holding session.json and events.ndjson)",
            ),
            (
                "capture directory not owned by reader",
                "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
            ),
            (
                "checkpoint.json: not owned by reader",
                "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
            ),
            (
                "events.ndjson: not owned by reader",
                "take ownership as the reading user (for example: sudo chown -R $(id -u):$(id -g) DIR)",
            ),
            (
                "not a memveil capture: expected session.json/events.ndjson",
                "pass a capture directory (session.json and events.ndjson)",
            ),
            (
                "capture directory is inaccessible or a symlink",
                "check read access to every path component and that none is a symlink",
            ),
            (
                "cannot establish final session absence",
                "check read access to the capture path and retry",
            ),
            (
                "cannot establish absence of final session",
                "check read access to the capture path and retry",
            ),
        ] {
            assert_eq!(read_remedy(cause), Some(fix), "{cause}");
        }
        for bare in [
            "session.json: ValidationError(what=x, message=y)",
            "line 1: ValidationError(what=x, message=y)",
            "no final session; verified checkpoint prefix 1155 bytes; use --allow-partial to recover",
            "events.ndjson: input is not a regular file",
            "capture directory does not exist, friend",
        ] {
            assert_eq!(read_remedy(bare), None, "{bare}");
        }
    }

    #[test]
    fn open_failures_round_trip_with_remedies() {
        let tmp = TestDir::create("memveil-read-remedy").expect("mkdtemp");
        let missing = tmp.path().join("no-such-dir");
        let err = read_capture(missing.to_str().unwrap(), false, default_limits()).unwrap_err();
        assert_eq!(err.message, "capture directory does not exist");
        assert!(read_remedy(&err.message).is_some());
        let file = tmp.path().join("plain-file");
        std::fs::write(&file, b"x").expect("write file");
        let err = read_capture(file.to_str().unwrap(), false, default_limits()).unwrap_err();
        assert_eq!(err.message, "capture path is not a directory");
        assert!(read_remedy(&err.message).is_some());
        let empty = tmp.path().join("empty-dir");
        std::fs::create_dir(&empty).expect("mkdir empty");
        let err = read_capture(empty.to_str().unwrap(), false, default_limits()).unwrap_err();
        assert_eq!(
            err.message,
            "not a memveil capture: expected session.json/events.ndjson"
        );
        assert!(read_remedy(&err.message).is_some());
    }
}
