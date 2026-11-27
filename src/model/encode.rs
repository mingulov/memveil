// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical JSON encoding for events and sessions.
//!
//! Byte rules mirror the event parsers exactly: u64 as quoted
//! canonical decimal, i64 and bool as bare JSON, strings quoted
//! with short escapes (`\" \\ \b \f \n \r \t`) and `\u00XX`
//! for other controls, raw UTF-8 otherwise. Key order is fixed;
//! required keys are always emitted (null when the struct flag
//! is clear); optional keys are emitted iff present.
//!
//! Output always reparses: any value the parser would reject
//! also fails the round-trip tests gating this module, so
//! validation checks are NOT duplicated here (a second copy
//! of every enum list would drift). Baseline region detail
//! round-trips exactly: the parser retains every observation
//! and the encoder reproduces the array in order.

use super::event::{EVENT_SCHEMA_VERSION, EVENT_SCHEMA_VERSION_PREV, Event};
use super::integrity::{Integrity, integrity_kind};
use super::journal::JOURNAL_SCHEMA_VERSION;
use super::journal_event::encode_journal_event;
use super::journal_session::encode_journal_session;
use super::regions::RegionObservation;
use super::session::{
    Capability, Channel, DeviceEntry, EvidenceItem, PRODUCT_NAME, SESSION_SCHEMA_VERSION,
    SESSION_SCHEMA_VERSION_INTEGRITY, Session, StopState,
};
use std::fmt;

/// Typical event lines are 300-400 bytes; longer ones grow the buffer.
const LINE_RESERVE: usize = 512;
/// NDJSON line cap including the trailing newline.
const MAX_LINE_BYTES: usize = 65536;

/// One encoding refusal naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    /// Field or check that failed.
    pub what: String,
    /// Machine-stable reason.
    pub message: String,
}

impl EncodeError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EncodeError(what={}, message={})",
            self.what, self.message
        )
    }
}

impl std::error::Error for EncodeError {}

/// Canonical bare JSON integer, i64 range.
pub fn format_i64(v: i64) -> String {
    v.to_string()
}

fn hex_lo(v: u8) -> u8 {
    if v < 10 { b'0' + v } else { b'a' + v - 10 }
}

/// Quote one string with canonical escapes.
///
/// Infallible: Rust strings are valid UTF-8 by construction, which
/// discharges the unencodable-text refusal the byte quoter keeps for
/// raw input.
pub fn quote_json(text: &str) -> String {
    let mut buf = Vec::with_capacity(text.len() + 2);
    put_span(&mut buf, text.as_bytes()).expect("valid UTF-8 input always quotes");
    String::from_utf8(buf).expect("quoted valid UTF-8 stays valid")
}

/// Append one quoted string; unescaped runs copy in bulk.
///
/// Raw bytes pass through with canonical escapes; when the input
/// carries non-ASCII bytes the quoted output must be valid UTF-8,
/// exactly as in the byte quoter this ports.
fn put_span(buf: &mut Vec<u8>, raw: &[u8]) -> Result<(), EncodeError> {
    let start = buf.len();
    buf.push(b'"');
    let mut run = 0;
    let mut seen = 0u8;
    for (i, &b) in raw.iter().enumerate() {
        seen |= b;
        if b >= 0x20 && b != b'"' && b != b'\\' {
            continue;
        }
        if i > run {
            buf.extend_from_slice(&raw[run..i]);
        }
        run = i + 1;
        buf.push(b'\\');
        match b {
            b'"' => buf.push(b'"'),
            b'\\' => buf.push(b'\\'),
            0x08 => buf.push(b'b'),
            0x09 => buf.push(b't'),
            0x0A => buf.push(b'n'),
            0x0C => buf.push(b'f'),
            0x0D => buf.push(b'r'),
            _ => {
                buf.push(b'u');
                buf.push(b'0');
                buf.push(b'0');
                buf.push(hex_lo(b >> 4));
                buf.push(hex_lo(b & 15));
            }
        }
    }
    if raw.len() > run {
        buf.extend_from_slice(&raw[run..]);
    }
    buf.push(b'"');
    // Only non-ASCII input can be invalid; check the quoted bytes as before.
    if seen >= 0x80 && core::str::from_utf8(&buf[start..]).is_err() {
        return Err(EncodeError::new("string", "unencodable text"));
    }
    Ok(())
}

fn put_str(buf: &mut Vec<u8>, text: &str) -> Result<(), EncodeError> {
    put_span(buf, text.as_bytes())
}

/// Bare canonical decimal.
fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(v.to_string().as_bytes());
}

fn put_qu64(buf: &mut Vec<u8>, v: u64) {
    buf.push(b'"');
    put_u64(buf, v);
    buf.push(b'"');
}

fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(v.to_string().as_bytes());
}

fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.extend_from_slice(if v { b"true" } else { b"false" });
}

fn put_key(buf: &mut Vec<u8>, key: &str) -> Result<(), EncodeError> {
    put_span(buf, key.as_bytes())?;
    buf.push(b':');
    Ok(())
}

fn put_observer(buf: &mut Vec<u8>, ev: &Event) -> Result<(), EncodeError> {
    buf.push(b'{');
    if ev.has_cpu {
        buf.extend_from_slice(b"\"cpu\":");
        put_i64(buf, ev.cpu);
        buf.push(b',');
    }
    if ev.has_pid {
        buf.extend_from_slice(b"\"pid\":");
        put_i64(buf, ev.pid);
        buf.push(b',');
    }
    if ev.has_tgid {
        buf.extend_from_slice(b"\"tgid\":");
        put_i64(buf, ev.tgid);
        buf.push(b',');
    }
    if ev.has_comm {
        buf.extend_from_slice(b"\"comm\":");
        put_str(buf, &ev.comm)?;
        buf.push(b',');
    }
    if ev.has_cgroup_id {
        buf.extend_from_slice(b"\"cgroup_id\":");
        put_str(buf, &ev.cgroup_id)?;
        buf.push(b',');
    }
    buf.extend_from_slice(b"\"relation\":\"execution_context_only\"}");
    Ok(())
}

fn put_opt_str(buf: &mut Vec<u8>, has: bool, v: &str) -> Result<(), EncodeError> {
    if has {
        put_str(buf, v)
    } else {
        buf.extend_from_slice(b"null");
        Ok(())
    }
}

fn put_opt_u64(buf: &mut Vec<u8>, has: bool, v: u64) {
    if has {
        put_qu64(buf, v);
    } else {
        buf.extend_from_slice(b"null");
    }
}

fn put_opt_i64(buf: &mut Vec<u8>, has: bool, v: i64) {
    if has {
        put_i64(buf, v);
    } else {
        buf.extend_from_slice(b"null");
    }
}

fn put_data(buf: &mut Vec<u8>, ev: &Event) -> Result<(), EncodeError> {
    if ev.kind == "bounce_attempt" {
        buf.extend_from_slice(b"{\"device_id\":");
        put_str(buf, &ev.bounce.device_id)?;
        buf.extend_from_slice(b",\"requested_bytes\":");
        put_qu64(buf, ev.bounce.requested_bytes);
        buf.extend_from_slice(b",\"forced\":");
        put_bool(buf, ev.bounce.forced);
        buf.extend_from_slice(b",\"operation_id\":");
        put_str(buf, &ev.bounce.operation_id)?;
    } else if ev.kind == "map_result" {
        let m = &ev.map_result;
        buf.extend_from_slice(b"{\"operation_id\":");
        put_str(buf, &m.operation_id)?;
        buf.extend_from_slice(b",\"success\":");
        put_bool(buf, m.success);
        buf.extend_from_slice(b",\"mapping_id\":");
        put_opt_str(buf, m.has_mapping_id, &m.mapping_id)?;
        buf.extend_from_slice(b",\"return_code\":");
        put_opt_i64(buf, m.has_return_code, m.return_code);
        buf.extend_from_slice(b",\"mapped_bytes\":");
        put_opt_u64(buf, m.has_mapped_bytes, m.mapped_bytes);
        buf.extend_from_slice(b",\"wire_generation\":");
        put_opt_u64(buf, m.has_wire_generation, m.wire_generation);
        buf.extend_from_slice(b",\"wire_identity\":");
        put_opt_str(buf, m.has_wire_identity, &m.wire_identity)?;
    } else if ev.kind == "unmap" {
        let u = &ev.unmap;
        buf.extend_from_slice(b"{\"mapping_id\":");
        put_opt_str(buf, u.has_mapping_id, &u.mapping_id)?;
        buf.extend_from_slice(b",\"wire_generation\":");
        put_opt_u64(buf, u.has_wire_generation, u.wire_generation);
        buf.extend_from_slice(b",\"wire_identity\":");
        put_opt_str(buf, u.has_wire_identity, &u.wire_identity)?;
    } else if ev.kind == "copy" {
        let c = &ev.copy;
        buf.extend_from_slice(b"{\"operation_id\":");
        put_str(buf, &c.operation_id)?;
        buf.extend_from_slice(b",\"mapping_id\":");
        put_opt_str(buf, c.has_mapping_id, &c.mapping_id)?;
        buf.extend_from_slice(b",\"direction\":");
        put_str(buf, &c.direction)?;
        buf.extend_from_slice(b",\"bytes\":");
        put_qu64(buf, c.bytes);
        if c.pool_private {
            buf.extend_from_slice(b",\"pool_private\":true");
        }
        if c.offset_past_allocation {
            buf.extend_from_slice(b",\"offset_past_allocation\":true");
        }
    } else if ev.kind == "sync_request" {
        let r = &ev.sync;
        buf.extend_from_slice(b"{\"operation_id\":");
        put_str(buf, &r.operation_id)?;
        buf.extend_from_slice(b",\"mapping_id\":");
        put_opt_str(buf, r.has_mapping_id, &r.mapping_id)?;
        buf.extend_from_slice(b",\"offset_known\":");
        put_bool(buf, r.has_offset);
        buf.extend_from_slice(b",\"offset\":");
        put_opt_u64(buf, r.has_offset, r.offset);
        buf.extend_from_slice(b",\"length\":");
        put_qu64(buf, r.length);
    } else if ev.kind == "transition_result" && ev.has_journal {
        let text = encode_journal_event(&ev.journal)
            .map_err(|_| EncodeError::new("journal", "invalid request/result payload"))?;
        buf.extend_from_slice(text.as_bytes());
        return Ok(());
    } else if ev.kind == "transition_result" {
        let t = &ev.transition;
        buf.extend_from_slice(b"{\"region_id\":");
        put_str(buf, &t.region_id)?;
        buf.extend_from_slice(b",\"requested_state\":");
        put_str(buf, &t.requested_state)?;
        buf.extend_from_slice(b",\"success\":");
        put_bool(buf, t.success);
        buf.extend_from_slice(b",\"return_code\":");
        put_opt_i64(buf, t.has_return_code, t.return_code);
        buf.extend_from_slice(b",\"offset\":");
        put_qu64(buf, t.offset);
        buf.extend_from_slice(b",\"length\":");
        put_qu64(buf, t.length);
        if t.has_address_space {
            buf.extend_from_slice(b",\"address_space\":");
            put_str(buf, &t.address_space)?;
        }
        if t.has_resolution {
            buf.extend_from_slice(b",\"resolution\":");
            put_str(buf, &t.resolution)?;
        }
        buf.extend_from_slice(b",\"generation\":");
        put_i64(buf, t.generation);
    } else if ev.kind == "pool_sample" {
        let p = &ev.pool;
        buf.extend_from_slice(b"{\"pool_id\":");
        put_str(buf, &p.pool_id)?;
        buf.extend_from_slice(b",\"used_bytes\":");
        put_opt_u64(buf, p.has_used, p.used_bytes);
        buf.extend_from_slice(b",\"capacity_bytes\":");
        put_opt_u64(buf, p.has_capacity, p.capacity_bytes);
        buf.extend_from_slice(b",\"unit\":");
        put_str(buf, &p.unit)?;
        if !p.allocator.is_empty() {
            buf.extend_from_slice(b",\"allocator\":");
            put_str(buf, &p.allocator)?;
        }
        if p.has_unit_bytes {
            buf.extend_from_slice(b",\"unit_bytes\":");
            put_qu64(buf, p.unit_bytes);
        }
        if p.has_hiwater {
            buf.extend_from_slice(b",\"hiwater_bytes\":");
            put_qu64(buf, p.hiwater_bytes);
        }
        if !p.reason.is_empty() {
            buf.extend_from_slice(b",\"reason\":");
            put_str(buf, &p.reason)?;
        }
    } else if ev.kind == "gap" {
        let g = &ev.gap;
        buf.extend_from_slice(b"{\"channel\":");
        put_str(buf, &g.channel)?;
        buf.extend_from_slice(b",\"lost_count\":");
        put_opt_u64(buf, g.has_lost_count, g.lost_count);
        buf.extend_from_slice(b",\"reason\":");
        put_str(buf, &g.reason)?;
        buf.extend_from_slice(b",\"window_start_ns\":");
        put_qu64(buf, g.window_start_ns);
        buf.extend_from_slice(b",\"window_end_ns\":");
        put_qu64(buf, g.window_end_ns);
    } else if ev.kind == "marker" {
        buf.extend_from_slice(b"{\"text\":");
        put_str(buf, &ev.marker.text)?;
    } else if ev.kind == "counter_snapshot" {
        let n = &ev.snapshot;
        buf.extend_from_slice(b"{\"counter_id\":");
        put_str(buf, &n.counter_id)?;
        buf.extend_from_slice(b",\"epoch\":");
        put_qu64(buf, n.epoch);
        buf.extend_from_slice(b",\"scope\":{");
        if n.has_scope_device {
            buf.extend_from_slice(b"\"device_id\":");
            put_str(buf, &n.scope_device_id)?;
            buf.push(b',');
        }
        buf.extend_from_slice(b"\"profile_id\":");
        put_str(buf, &n.scope_profile_id)?;
        buf.extend_from_slice(b"},\"value\":");
        put_qu64(buf, n.value);
        buf.extend_from_slice(b",\"unit\":");
        put_str(buf, &n.unit)?;
    } else {
        return Err(EncodeError::new(
            "kind",
            format!("unknown event kind: {}", ev.kind),
        ));
    }
    buf.push(b'}');
    Ok(())
}

fn put_event(buf: &mut Vec<u8>, ev: &Event) -> Result<(), EncodeError> {
    buf.extend_from_slice(b"{\"schema_version\":");
    if ev.journal_version || ev.has_journal {
        put_span(buf, JOURNAL_SCHEMA_VERSION.as_bytes())?;
    } else if ev.kind == "copy" && (ev.copy.pool_private || ev.copy.offset_past_allocation) {
        put_span(buf, EVENT_SCHEMA_VERSION.as_bytes())?;
    } else {
        put_span(buf, EVENT_SCHEMA_VERSION_PREV.as_bytes())?;
    }
    buf.extend_from_slice(b",\"session_id\":");
    put_str(buf, &ev.session_id)?;
    buf.extend_from_slice(b",\"seq\":");
    put_qu64(buf, ev.seq);
    buf.extend_from_slice(b",\"ts_ns\":");
    put_qu64(buf, ev.ts_ns);
    buf.extend_from_slice(b",\"kind\":");
    put_str(buf, &ev.kind)?;
    buf.extend_from_slice(b",\"source\":{\"hook\":");
    put_str(buf, &ev.source_hook)?;
    buf.extend_from_slice(b",\"backend\":");
    put_str(buf, &ev.source_backend)?;
    buf.extend_from_slice(b",\"profile_id\":");
    put_str(buf, &ev.source_profile_id)?;
    buf.extend_from_slice(b",\"measurement\":");
    put_str(buf, &ev.source_measurement)?;
    buf.extend_from_slice(b",\"correlation\":");
    put_str(buf, &ev.source_correlation)?;
    buf.push(b'}');
    if ev.has_observer {
        buf.extend_from_slice(b",\"observer_context\":");
        put_observer(buf, ev)?;
    }
    buf.extend_from_slice(b",\"data\":");
    put_data(buf, ev)?;
    buf.push(b'}');
    Ok(())
}

/// Encode one event in canonical form (no trailing newline).
pub fn encode_event(ev: &Event) -> Result<String, EncodeError> {
    let mut buf = Vec::with_capacity(LINE_RESERVE);
    put_event(&mut buf, ev)?;
    if buf.len() + 1 > MAX_LINE_BYTES {
        return Err(EncodeError::new(
            "event",
            "line exceeds 64 KiB including newline",
        ));
    }
    // Every string was validated by put_span.
    Ok(String::from_utf8(buf).expect("canonical event bytes are valid UTF-8"))
}

/// Encode one event plus the NDJSON trailing newline.
pub fn encode_event_line(ev: &Event) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::with_capacity(LINE_RESERVE);
    put_event(&mut buf, ev)?;
    buf.push(b'\n');
    if buf.len() > MAX_LINE_BYTES {
        return Err(EncodeError::new(
            "event",
            "line exceeds 64 KiB including newline",
        ));
    }
    Ok(buf)
}

fn put_capability(buf: &mut Vec<u8>, cap: &Capability) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_key(buf, "status")?;
    put_str(buf, &cap.status)?;
    buf.push(b',');
    put_key(buf, "reason")?;
    put_str(buf, &cap.reason)?;
    buf.push(b',');
    put_key(buf, "hooks")?;
    buf.push(b'[');
    for (i, hook) in cap.hooks.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_str(buf, hook)?;
    }
    buf.extend_from_slice(b"]");
    if cap.has_profile_id {
        buf.push(b',');
        put_key(buf, "profile_id")?;
        put_str(buf, &cap.profile_id)?;
    }
    if cap.has_grade {
        buf.push(b',');
        put_key(buf, "grade")?;
        put_str(buf, &cap.grade)?;
    }
    buf.push(b'}');
    Ok(())
}

fn put_channel_body(buf: &mut Vec<u8>, ch: &Channel) -> Result<(), EncodeError> {
    put_key(buf, "status")?;
    put_str(buf, &ch.status)?;
    buf.push(b',');
    put_key(buf, "loss_count")?;
    put_opt_u64(buf, ch.has_loss_count, ch.loss_count);
    buf.push(b',');
    put_key(buf, "scope")?;
    put_str(buf, &ch.scope)?;
    buf.push(b',');
    put_key(buf, "reason")?;
    put_str(buf, &ch.reason)?;
    buf.push(b',');
    put_key(buf, "evidence_refs")?;
    buf.push(b'[');
    for (i, r) in ch.evidence_refs.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_str(buf, r)?;
    }
    buf.extend_from_slice(b"]");
    Ok(())
}

fn put_channel(buf: &mut Vec<u8>, ch: &Channel) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_channel_body(buf, ch)?;
    buf.push(b'}');
    Ok(())
}

/// Encode quality.correlation with its optional relations.
fn put_correlation(buf: &mut Vec<u8>, s: &Session) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_channel_body(buf, &s.q_correlation)?;
    if s.has_corr_relations {
        buf.push(b',');
        put_key(buf, "relations")?;
        buf.push(b'{');
        put_key(buf, "mapping_release")?;
        put_channel(buf, &s.q_corr_mapping)?;
        buf.push(b',');
        put_key(buf, "copy_attribution")?;
        put_channel(buf, &s.q_corr_copy)?;
        buf.push(b',');
        put_key(buf, "sync_attribution")?;
        put_channel(buf, &s.q_corr_sync)?;
        buf.push(b'}');
    }
    buf.push(b'}');
    Ok(())
}

fn put_device(buf: &mut Vec<u8>, dev: &DeviceEntry) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_key(buf, "device_id")?;
    put_str(buf, &dev.device_id)?;
    buf.push(b',');
    put_key(buf, "name")?;
    put_str(buf, &dev.name)?;
    if dev.driver_present {
        buf.push(b',');
        put_key(buf, "driver")?;
        put_opt_str(buf, dev.has_driver, &dev.driver)?;
    }
    buf.push(b',');
    put_key(buf, "identity_status")?;
    put_str(buf, &dev.identity_status)?;
    buf.push(b'}');
    Ok(())
}

fn put_evidence_item(buf: &mut Vec<u8>, it: &EvidenceItem) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_key(buf, "type")?;
    put_str(buf, &it.item_type)?;
    buf.push(b',');
    put_key(buf, "source")?;
    put_str(buf, &it.source)?;
    buf.push(b',');
    put_key(buf, "interpretation")?;
    put_str(buf, &it.interpretation)?;
    buf.push(b'}');
    Ok(())
}

/// Encode one baseline observation in schema key order.
fn put_region_observation(buf: &mut Vec<u8>, o: &RegionObservation) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_key(buf, "region_id")?;
    put_str(buf, &o.region_id)?;
    buf.push(b',');
    put_key(buf, "state")?;
    put_str(buf, &o.state)?;
    buf.push(b',');
    put_key(buf, "offset")?;
    put_qu64(buf, o.offset);
    buf.push(b',');
    put_key(buf, "length")?;
    put_qu64(buf, o.length);
    buf.push(b',');
    put_key(buf, "address_space")?;
    put_str(buf, &o.address_space)?;
    buf.push(b',');
    put_key(buf, "provenance")?;
    put_str(buf, &o.provenance)?;
    buf.push(b',');
    put_key(buf, "generation")?;
    put_i64(buf, o.generation);
    buf.push(b'}');
    Ok(())
}

fn put_integrity(buf: &mut Vec<u8>, value: &Integrity) -> Result<(), EncodeError> {
    buf.push(b'{');
    put_key(buf, "algorithm")?;
    put_str(buf, "sha256")?;
    buf.push(b',');
    put_key(buf, "events_bytes")?;
    put_qu64(buf, value.events_bytes);
    buf.push(b',');
    put_key(buf, "line_count")?;
    put_qu64(buf, value.line_count);
    buf.push(b',');
    put_key(buf, "first_seq")?;
    put_opt_u64(buf, value.has_seq, value.first_seq);
    buf.push(b',');
    put_key(buf, "last_seq")?;
    put_opt_u64(buf, value.has_seq, value.last_seq);
    buf.push(b',');
    put_key(buf, "events_sha256")?;
    put_str(buf, &value.events_sha256)?;
    buf.push(b',');
    put_key(buf, "kinds")?;
    buf.push(b'{');
    for (i, count) in value.kinds.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_key(buf, integrity_kind(i))?;
        put_qu64(buf, *count);
    }
    buf.extend_from_slice(b"}}");
    Ok(())
}

/// Encode one integrity object in canonical form.
pub fn encode_integrity(value: &Integrity) -> Result<String, EncodeError> {
    value
        .validate()
        .map_err(|e| EncodeError::new("capture.integrity", e.to_string()))?;
    let mut buf = Vec::new();
    put_integrity(&mut buf, value)?;
    Ok(String::from_utf8(buf).expect("canonical integrity bytes are valid UTF-8"))
}

fn put_stop(buf: &mut Vec<u8>, st: &StopState) -> Result<(), EncodeError> {
    buf.push(b'{');
    let mut first = true;
    let mut sep = |buf: &mut Vec<u8>| {
        if !first {
            buf.push(b',');
        }
        first = false;
    };
    if st.has_checkpoint_failures {
        sep(buf);
        put_key(buf, "checkpoint_failures")?;
        put_qu64(buf, st.checkpoint_failures);
    }
    sep(buf);
    put_key(buf, "outcome")?;
    put_str(buf, &st.outcome)?;
    sep(buf);
    put_key(buf, "reason")?;
    put_str(buf, &st.reason)?;
    sep(buf);
    put_key(buf, "budget_ms")?;
    put_qu64(buf, st.budget_ms);
    sep(buf);
    put_key(buf, "elapsed_ms")?;
    put_qu64(buf, st.elapsed_ms);
    sep(buf);
    put_key(buf, "admission_closed")?;
    put_bool(buf, st.admission_closed);
    sep(buf);
    put_key(buf, "quiescence_observed")?;
    put_bool(buf, st.quiescence_observed);
    sep(buf);
    put_key(buf, "writers_settled")?;
    put_qu64(buf, st.writers_settled);
    sep(buf);
    put_key(buf, "in_flight_at_close")?;
    put_qu64(buf, st.in_flight_at_close);
    sep(buf);
    put_key(buf, "late_submits_drained")?;
    put_qu64(buf, st.late_submits_drained);
    sep(buf);
    put_key(buf, "drained_records")?;
    put_qu64(buf, st.drained_records);
    if st.has_drain_completed {
        sep(buf);
        put_key(buf, "drain_completed")?;
        put_bool(buf, st.drain_completed);
    }
    if st.has_submit_after_drain {
        sep(buf);
        put_key(buf, "submit_after_drain")?;
        put_bool(buf, st.submit_after_drain);
    }
    sep(buf);
    put_key(buf, "busy_at_drain")?;
    put_bool(buf, st.busy_at_drain);
    sep(buf);
    put_key(buf, "counters_valid")?;
    put_bool(buf, st.counters_valid);
    sep(buf);
    put_key(buf, "open_mappings")?;
    put_qu64(buf, st.open_mappings);
    buf.push(b'}');
    Ok(())
}

/// Encode one session in canonical form (no trailing newline).
pub fn encode_session(s: &Session) -> Result<String, EncodeError> {
    let mut buf = Vec::new();
    buf.push(b'{');
    put_key(&mut buf, "schema_version")?;
    if s.has_journal {
        put_str(&mut buf, JOURNAL_SCHEMA_VERSION)?;
    } else if s.has_integrity {
        put_str(&mut buf, SESSION_SCHEMA_VERSION_INTEGRITY)?;
    } else {
        put_str(&mut buf, SESSION_SCHEMA_VERSION)?;
    }
    buf.push(b',');
    put_key(&mut buf, "session_id")?;
    put_str(&mut buf, &s.session_id)?;
    if s.has_boot_id {
        buf.push(b',');
        put_key(&mut buf, "boot_id")?;
        put_str(&mut buf, &s.boot_id)?;
    }
    buf.push(b',');
    put_key(&mut buf, "synthetic")?;
    put_bool(&mut buf, s.synthetic);
    buf.push(b',');
    put_key(&mut buf, "product")?;
    buf.push(b'{');
    put_key(&mut buf, "name")?;
    put_str(&mut buf, PRODUCT_NAME)?;
    buf.push(b',');
    put_key(&mut buf, "version")?;
    put_str(&mut buf, &s.product_version)?;
    if s.has_build {
        buf.push(b',');
        put_key(&mut buf, "build")?;
        put_str(&mut buf, &s.build)?;
    }
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "environment")?;
    buf.push(b'{');
    put_key(&mut buf, "mode")?;
    put_str(&mut buf, &s.env_mode)?;
    buf.push(b',');
    put_key(&mut buf, "detection")?;
    put_str(&mut buf, &s.env_detection)?;
    if s.asserted_mode_present {
        buf.push(b',');
        put_key(&mut buf, "asserted_mode")?;
        put_opt_str(&mut buf, s.has_asserted_mode, &s.asserted_mode)?;
    }
    buf.push(b',');
    put_key(&mut buf, "attestation")?;
    put_str(&mut buf, &s.env_attestation)?;
    buf.push(b',');
    put_key(&mut buf, "evidence")?;
    buf.push(b'[');
    for (i, it) in s.evidence.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_evidence_item(&mut buf, it)?;
    }
    buf.extend_from_slice(b"]}");
    buf.push(b',');
    put_key(&mut buf, "capture")?;
    buf.push(b'{');
    put_key(&mut buf, "mode")?;
    put_str(&mut buf, &s.capture_mode)?;
    buf.push(b',');
    put_key(&mut buf, "window")?;
    buf.push(b'{');
    put_key(&mut buf, "start_ns")?;
    put_qu64(&mut buf, s.window_start_ns);
    buf.push(b',');
    put_key(&mut buf, "end_ns")?;
    put_qu64(&mut buf, s.window_end_ns);
    if s.has_baseline_start_ns {
        buf.push(b',');
        put_key(&mut buf, "baseline_start_ns")?;
        put_qu64(&mut buf, s.baseline_start_ns);
    }
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "filters")?;
    buf.push(b'{');
    if s.has_filter_device {
        put_key(&mut buf, "device")?;
        put_str(&mut buf, &s.filter_device)?;
    }
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "finalized")?;
    put_bool(&mut buf, s.finalized);
    if s.has_end_reason {
        buf.push(b',');
        put_key(&mut buf, "end_reason")?;
        put_str(&mut buf, &s.end_reason)?;
    }
    if s.has_checkpoint_generation {
        buf.push(b',');
        put_key(&mut buf, "checkpoint_generation")?;
        put_qu64(&mut buf, s.checkpoint_generation);
    }
    if s.has_integrity {
        buf.push(b',');
        put_key(&mut buf, "integrity")?;
        s.integrity
            .validate()
            .map_err(|e| EncodeError::new("capture.integrity", e.to_string()))?;
        put_integrity(&mut buf, &s.integrity)?;
    }
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "device_catalog")?;
    buf.extend_from_slice(b"{\"devices\":[");
    for (i, dev) in s.devices.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_device(&mut buf, dev)?;
    }
    buf.extend_from_slice(b"]}");
    buf.push(b',');
    put_key(&mut buf, "baseline")?;
    buf.push(b'{');
    put_key(&mut buf, "complete")?;
    put_bool(&mut buf, s.baseline_complete);
    buf.push(b',');
    put_key(&mut buf, "region_observations")?;
    buf.push(b'[');
    for (i, o) in s.baseline_regions.iter().enumerate() {
        if i > 0 {
            buf.push(b',');
        }
        put_region_observation(&mut buf, o)?;
    }
    buf.extend_from_slice(b"]}");
    buf.push(b',');
    put_key(&mut buf, "capabilities")?;
    buf.push(b'{');
    put_key(&mut buf, "bounce_attempts")?;
    put_capability(&mut buf, &s.cap_bounce_attempts)?;
    buf.push(b',');
    put_key(&mut buf, "mapping_lifecycle")?;
    put_capability(&mut buf, &s.cap_mapping_lifecycle)?;
    buf.push(b',');
    put_key(&mut buf, "copy_bytes")?;
    put_capability(&mut buf, &s.cap_copy_bytes)?;
    buf.push(b',');
    put_key(&mut buf, "sync_requests")?;
    put_capability(&mut buf, &s.cap_sync_requests)?;
    buf.push(b',');
    put_key(&mut buf, "conversion_results")?;
    put_capability(&mut buf, &s.cap_conversion_results)?;
    buf.push(b',');
    put_key(&mut buf, "region_state")?;
    put_capability(&mut buf, &s.cap_region_state)?;
    buf.push(b',');
    put_key(&mut buf, "pool_stats")?;
    put_capability(&mut buf, &s.cap_pool_stats)?;
    buf.push(b',');
    put_key(&mut buf, "task_context")?;
    put_capability(&mut buf, &s.cap_task_context)?;
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "quality")?;
    buf.push(b'{');
    put_key(&mut buf, "detail")?;
    put_channel(&mut buf, &s.q_detail)?;
    buf.push(b',');
    put_key(&mut buf, "aggregate")?;
    put_channel(&mut buf, &s.q_aggregate)?;
    buf.push(b',');
    put_key(&mut buf, "correlation")?;
    put_correlation(&mut buf, s)?;
    buf.push(b',');
    put_key(&mut buf, "baseline")?;
    put_channel(&mut buf, &s.q_baseline)?;
    buf.push(b',');
    put_key(&mut buf, "terminal")?;
    put_channel(&mut buf, &s.q_terminal)?;
    buf.extend_from_slice(b"}");
    buf.push(b',');
    put_key(&mut buf, "stop")?;
    put_stop(&mut buf, &s.stop)?;
    if s.has_journal {
        s.journal
            .window(s.window_start_ns, s.finalized)
            .map_err(|_| EncodeError::new("journal", "invalid window/counters"))?;
        let text = encode_journal_session(&s.journal)
            .map_err(|_| EncodeError::new("journal", "invalid window/counters"))?;
        buf.push(b',');
        put_key(&mut buf, "journal")?;
        buf.extend_from_slice(text.as_bytes());
    }
    if s.has_verdict {
        if s.verdict_loss_bps < 0 || s.verdict_loss_bps > 10000 {
            return Err(EncodeError::new("verdict.loss_ratio_bps", "out of range"));
        }
        buf.push(b',');
        put_key(&mut buf, "verdict")?;
        buf.push(b'{');
        put_key(&mut buf, "name")?;
        put_str(&mut buf, &s.verdict_name)?;
        buf.push(b',');
        put_key(&mut buf, "loss_ratio_bps")?;
        put_qu64(&mut buf, s.verdict_loss_bps as u64);
        buf.push(b',');
        put_key(&mut buf, "delivered")?;
        put_qu64(&mut buf, s.verdict_delivered);
        buf.push(b'}');
    }
    buf.push(b'}');
    Ok(String::from_utf8(buf).expect("canonical session bytes are valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::super::event::parse_event;
    use super::super::session::parse_session;
    use super::*;

    fn base_event() -> Event {
        Event {
            session_id: "s1".to_string(),
            seq: 7,
            ts_ns: 123,
            source_hook: "h".to_string(),
            source_backend: "tracepoint".to_string(),
            source_profile_id: "p".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ..Event::default()
        }
    }

    #[test]
    fn quote_ascii() {
        assert_eq!(quote_json("abc"), "\"abc\"");
        assert_eq!(quote_json(""), "\"\"");
    }

    #[test]
    fn quote_specials() {
        assert_eq!(quote_json("a\"b\\c"), "\"a\\\"b\\\\c\"");
    }

    #[test]
    fn quote_shorts() {
        assert_eq!(
            quote_json("\u{8}\u{9}\u{a}\u{c}\u{d}"),
            "\"\\b\\t\\n\\f\\r\""
        );
    }

    #[test]
    fn quote_controls() {
        // 0x7F passes through raw; other controls take \u00XX lowercase.
        assert_eq!(
            quote_json("\0\u{1}\u{1f}\u{7f}"),
            "\"\\u0000\\u0001\\u001f\u{7f}\""
        );
        assert_eq!(quote_json("\u{7}"), "\"\\u0007\"");
        assert_eq!(quote_json("\u{1b}"), "\"\\u001b\"");
    }

    #[test]
    fn quote_utf8() {
        assert_eq!(quote_json("é"), "\"é\"");
        assert_eq!(quote_json("€ 中文 😀"), "\"€ 中文 😀\"");
    }

    #[test]
    fn format_i64_edges() {
        assert_eq!(format_i64(0), "0");
        assert_eq!(format_i64(42), "42");
        assert_eq!(format_i64(-1), "-1");
        assert_eq!(format_i64(i64::MAX), "9223372036854775807");
        assert_eq!(format_i64(i64::MIN), "-9223372036854775808");
    }

    #[test]
    fn encode_error_identity() {
        let err = EncodeError::new("kind", "unknown event kind: nope");
        assert_eq!(err.what, "kind");
        assert_eq!(
            err.to_string(),
            "EncodeError(what=kind, message=unknown event kind: nope)"
        );
    }

    #[test]
    fn bounce_exact() {
        let mut ev = base_event();
        ev.kind = "bounce_attempt".to_string();
        ev.bounce.device_id = "d000001".to_string();
        ev.bounce.requested_bytes = 1500;
        ev.bounce.forced = true;
        ev.bounce.operation_id = "op7".to_string();
        assert_eq!(
            encode_event(&ev).unwrap(),
            concat!(
                "{\"schema_version\":\"0.1.1\",\"session_id\":\"s1\",",
                "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"bounce_attempt\",",
                "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\",",
                "\"profile_id\":\"p\",\"measurement\":\"observed\",",
                "\"correlation\":\"direct\"},\"data\":{\"device_id\":",
                "\"d000001\",\"requested_bytes\":\"1500\",\"forced\":true,",
                "\"operation_id\":\"op7\"}}",
            ),
        );
        let back = parse_event(encode_event(&ev).unwrap().as_bytes()).unwrap();
        assert_eq!(back.bounce.device_id, "d000001");
        assert_eq!(back.bounce.requested_bytes, 1500);
        assert!(back.bounce.forced);
        assert_eq!(back.seq, 7);
    }

    #[test]
    fn gap_null() {
        let mut ev = base_event();
        ev.kind = "gap".to_string();
        ev.gap.channel = "detail".to_string();
        ev.gap.reason = "why".to_string();
        ev.gap.window_start_ns = 1;
        ev.gap.window_end_ns = 2;
        assert_eq!(
            encode_event(&ev).unwrap(),
            concat!(
                "{\"schema_version\":\"0.1.1\",\"session_id\":\"s1\",",
                "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"gap\",",
                "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\",",
                "\"profile_id\":\"p\",\"measurement\":\"observed\",",
                "\"correlation\":\"direct\"},\"data\":{\"channel\":\"detail\",",
                "\"lost_count\":null,\"reason\":\"why\",",
                "\"window_start_ns\":\"1\",\"window_end_ns\":\"2\"}}",
            ),
        );
        let back = parse_event(encode_event(&ev).unwrap().as_bytes()).unwrap();
        assert!(!back.gap.has_lost_count);
    }

    #[test]
    fn transition_exact() {
        let mut ev = base_event();
        ev.kind = "transition_result".to_string();
        ev.transition.region_id = "r-1".to_string();
        ev.transition.requested_state = "shared".to_string();
        ev.transition.success = true;
        ev.transition.has_return_code = true;
        ev.transition.return_code = 0;
        ev.transition.offset = 0;
        ev.transition.length = 4096;
        ev.transition.has_address_space = true;
        ev.transition.address_space = "guest_physical".to_string();
        ev.transition.has_resolution = true;
        ev.transition.resolution = "resolved".to_string();
        ev.transition.generation = 2;
        assert_eq!(
            encode_event(&ev).unwrap(),
            concat!(
                "{\"schema_version\":\"0.1.1\",\"session_id\":\"s1\",",
                "\"seq\":\"7\",\"ts_ns\":\"123\",\"kind\":\"transition_result\",",
                "\"source\":{\"hook\":\"h\",\"backend\":\"tracepoint\",",
                "\"profile_id\":\"p\",\"measurement\":\"observed\",",
                "\"correlation\":\"direct\"},\"data\":{\"region_id\":",
                "\"r-1\",\"requested_state\":\"shared\",\"success\":true,",
                "\"return_code\":0,\"offset\":\"0\",\"length\":\"4096\",",
                "\"address_space\":\"guest_physical\",\"resolution\":",
                "\"resolved\",\"generation\":2}}",
            ),
        );
        let back = parse_event(encode_event(&ev).unwrap().as_bytes()).unwrap();
        assert_eq!(back.transition.generation, 2);
    }

    #[test]
    fn event_fixture_shape() {
        let mut ev = Event {
            session_id: "cap-31673397184-520".to_string(),
            seq: 2,
            ts_ns: 31_868_671_010,
            kind: "map_result".to_string(),
            source_hook: "fexit:swiotlb_tbl_map_single".to_string(),
            source_backend: "tracing".to_string(),
            source_profile_id: "linux-x86_64-7.0.0-34-generic".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ..Event::default()
        };
        ev.map_result.operation_id = "lc-0".to_string();
        ev.map_result.success = true;
        ev.map_result.has_mapping_id = true;
        ev.map_result.mapping_id = "gen-1".to_string();
        ev.map_result.has_mapped_bytes = true;
        ev.map_result.mapped_bytes = 4096;
        ev.map_result.has_wire_generation = true;
        ev.map_result.wire_generation = 1;
        ev.map_result.has_wire_identity = true;
        ev.map_result.wire_identity = "known".to_string();
        assert_eq!(
            encode_event(&ev).unwrap(),
            concat!(
                "{\"schema_version\":\"0.1.1\",\"session_id\":",
                "\"cap-31673397184-520\",\"seq\":\"2\",\"ts_ns\":",
                "\"31868671010\",\"kind\":\"map_result\",\"source\":",
                "{\"hook\":\"fexit:swiotlb_tbl_map_single\",\"backend\":",
                "\"tracing\",\"profile_id\":\"linux-x86_64-7.0.0-34-generic\",",
                "\"measurement\":\"observed\",\"correlation\":\"direct\"},",
                "\"data\":{\"operation_id\":\"lc-0\",\"success\":true,",
                "\"mapping_id\":\"gen-1\",\"return_code\":null,",
                "\"mapped_bytes\":\"4096\",\"wire_generation\":\"1\",",
                "\"wire_identity\":\"known\"}}",
            ),
        );
        let line = encode_event_line(&ev).unwrap();
        assert_eq!(line[line.len() - 1], b'\n');
    }

    #[test]
    fn snapshot_scopes() {
        let mut ev = base_event();
        ev.kind = "counter_snapshot".to_string();
        ev.snapshot.counter_id = "swiotlb.bounce_attempts".to_string();
        ev.snapshot.epoch = 0;
        ev.snapshot.scope_profile_id = "p".to_string();
        ev.snapshot.value = 9;
        ev.snapshot.unit = "count".to_string();
        let global = encode_event(&ev).unwrap();
        assert!(global.contains("\"scope\":{\"profile_id\":\"p\"}"));
        ev.snapshot.has_scope_device = true;
        ev.snapshot.scope_device_id = "d000001".to_string();
        let scoped = encode_event(&ev).unwrap();
        assert!(scoped.contains("\"scope\":{\"device_id\":\"d000001\",\"profile_id\":\"p\"}"));
        let back = parse_event(scoped.as_bytes()).unwrap();
        assert!(back.snapshot.has_scope_device);
        assert_eq!(back.snapshot.value, 9);
    }

    #[test]
    fn observer_shape() {
        let mut ev = base_event();
        ev.kind = "marker".to_string();
        ev.marker.text = "m".to_string();
        ev.has_observer = true;
        ev.has_cpu = true;
        ev.cpu = 3;
        ev.has_comm = true;
        ev.comm = "pc".to_string();
        let text = encode_event(&ev).unwrap();
        assert!(text.contains(
            "\"observer_context\":{\"cpu\":3,\"comm\":\"pc\",\"relation\":\"execution_context_only\"}"
        ));
        let back = parse_event(text.as_bytes()).unwrap();
        assert!(back.has_observer);
        assert_eq!(back.cpu, 3);
        assert!(!back.has_pid);
    }

    #[test]
    fn map_nulls() {
        let mut ev = base_event();
        ev.kind = "map_result".to_string();
        ev.map_result.operation_id = "op1".to_string();
        let text = encode_event(&ev).unwrap();
        assert!(text.contains("\"mapping_id\":null,\"return_code\":null,\"mapped_bytes\":null"));
        let back = parse_event(text.as_bytes()).unwrap();
        assert!(!back.map_result.has_mapping_id);
    }

    #[test]
    fn copy_version_selection() {
        let mut ev = base_event();
        ev.kind = "copy".to_string();
        ev.copy.operation_id = "op1".to_string();
        ev.copy.direction = "to_device".to_string();
        assert!(
            encode_event(&ev)
                .unwrap()
                .contains("\"schema_version\":\"0.1.1\"")
        );
        ev.copy.pool_private = true;
        assert!(
            encode_event(&ev)
                .unwrap()
                .contains("\"schema_version\":\"0.1.2\"")
        );
        ev.copy.pool_private = false;
        ev.copy.offset_past_allocation = true;
        assert!(
            encode_event(&ev)
                .unwrap()
                .contains("\"schema_version\":\"0.1.2\"")
        );
        // Markers on any other kind never upgrade the line version.
        let mut other = base_event();
        other.kind = "marker".to_string();
        other.copy.pool_private = true;
        assert!(
            encode_event(&other)
                .unwrap()
                .contains("\"schema_version\":\"0.1.1\"")
        );
    }

    #[test]
    fn unknown_kind_names_kind() {
        let mut ev = base_event();
        ev.kind = "nope".to_string();
        let err = encode_event(&ev).unwrap_err();
        assert_eq!(err.what, "kind");
        assert_eq!(err.message, "unknown event kind: nope");
        assert!(encode_event_line(&ev).is_err());
    }

    #[test]
    fn line_cap_boundary() {
        let mut ev = base_event();
        ev.kind = "marker".to_string();
        let base = encode_event(&ev).unwrap();
        // Room for text so the newline-terminated line is exactly 64 KiB.
        let room = MAX_LINE_BYTES - 1 - base.len();
        ev.marker.text = "x".repeat(room);
        let line = encode_event_line(&ev).unwrap();
        assert_eq!(line.len(), MAX_LINE_BYTES);
        assert_eq!(encode_event(&ev).unwrap().len() + 1, MAX_LINE_BYTES);
        ev.marker.text.push('x');
        let err = encode_event_line(&ev).unwrap_err();
        assert_eq!(err.what, "event");
        assert!(encode_event(&ev).is_err());
    }

    #[test]
    fn generation_sweep() {
        let vals: [i64; 12] = [
            1,
            2,
            3,
            127,
            128,
            255,
            256,
            65535,
            65536,
            2_147_483_647,
            2_147_483_648,
            9_223_372_036_854_775_807,
        ];
        for g in vals {
            let mut ev = base_event();
            ev.kind = "transition_result".to_string();
            ev.transition.region_id = "r-1".to_string();
            ev.transition.requested_state = "shared".to_string();
            ev.transition.success = true;
            ev.transition.has_return_code = true;
            ev.transition.offset = 0;
            ev.transition.length = 4096;
            ev.transition.generation = g;
            let line = encode_event(&ev).unwrap();
            let back = parse_event(line.as_bytes()).unwrap();
            assert_eq!(back.transition.generation, g);
            assert_eq!(encode_event(&back).unwrap(), line);

            let mut s = base_session();
            s.baseline_complete = true;
            s.baseline_region_count = 1;
            let o = RegionObservation {
                region_id: "r1".to_string(),
                state: "shared".to_string(),
                length: 8192,
                address_space: "guest_physical".to_string(),
                provenance: "sweep".to_string(),
                generation: g,
                ..RegionObservation::default()
            };
            s.baseline_regions.push(o);
            let text = encode_session(&s).unwrap();
            let bs = parse_session(text.as_bytes()).unwrap();
            assert_eq!(bs.baseline_regions.len(), 1);
            assert_eq!(bs.baseline_regions[0].generation, g);
            assert_eq!(encode_session(&bs).unwrap(), text);
        }
    }

    fn base_session() -> Session {
        let mut s = Session {
            session_id: "s1".to_string(),
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "live".to_string(),
            window_start_ns: 10,
            window_end_ns: 20,
            finalized: true,
            ..Session::default()
        };
        s.cap_bounce_attempts.status = "partial".to_string();
        s.cap_bounce_attempts.reason = "r".to_string();
        for cap in [
            &mut s.cap_mapping_lifecycle,
            &mut s.cap_copy_bytes,
            &mut s.cap_sync_requests,
            &mut s.cap_conversion_results,
            &mut s.cap_region_state,
            &mut s.cap_pool_stats,
            &mut s.cap_task_context,
        ] {
            cap.status = "unavailable".to_string();
            cap.reason = "r".to_string();
        }
        s.q_detail.status = "complete_for_scope".to_string();
        s.q_detail.has_loss_count = true;
        s.q_detail.loss_count = 0;
        s.q_detail.scope = "sc".to_string();
        s.q_detail.reason = "rs".to_string();
        s.q_aggregate.status = "unavailable".to_string();
        s.q_aggregate.scope = "sc".to_string();
        s.q_aggregate.reason = "rs".to_string();
        s.q_correlation.status = "not_applicable".to_string();
        s.q_correlation.scope = "sc".to_string();
        s.q_correlation.reason = "rs".to_string();
        s.q_baseline.status = "not_applicable".to_string();
        s.q_baseline.scope = "sc".to_string();
        s.q_baseline.reason = "rs".to_string();
        s.q_terminal.status = "partial".to_string();
        s.q_terminal.scope = "sc".to_string();
        s.q_terminal.reason = "rs".to_string();
        s.stop.outcome = "partial".to_string();
        s.stop.reason = "quiescence unproven".to_string();
        s.stop.budget_ms = 5000;
        s.stop.elapsed_ms = 120;
        s.stop.admission_closed = true;
        s.stop.drained_records = 7;
        s.stop.counters_valid = true;
        s
    }

    #[test]
    fn session_roundtrip() {
        let s = base_session();
        let text = encode_session(&s).unwrap();
        assert!(text.contains("\"name\":\"memveil\""));
        assert!(text.contains("\"loss_count\":\"0\""));
        assert!(text.contains("\"schema_version\":\"0.1.3\""));
        let back = parse_session(text.as_bytes()).unwrap();
        assert_eq!(back.session_id, "s1");
        assert!(back.q_detail.has_loss_count);
        assert!(!back.has_boot_id);
        assert_eq!(back.stop.outcome, "partial");
        assert_eq!(back.stop.reason, "quiescence unproven");
        assert_eq!(back.stop.budget_ms, 5000);
        assert_eq!(back.stop.elapsed_ms, 120);
        assert!(back.stop.admission_closed);
        assert!(!back.stop.quiescence_observed);
        assert_eq!(back.stop.drained_records, 7);
        assert!(back.stop.counters_valid);
        assert_eq!(encode_session(&back).unwrap(), text);
    }

    #[test]
    fn session_capability_grade_roundtrip() {
        let mut s = base_session();
        s.cap_bounce_attempts.has_grade = true;
        s.cap_bounce_attempts.grade = "local-auto".to_string();
        let text = encode_session(&s).unwrap();
        assert!(text.contains("\"grade\":\"local-auto\""));
        let back = parse_session(text.as_bytes()).unwrap();
        assert!(back.cap_bounce_attempts.has_grade);
        assert_eq!(back.cap_bounce_attempts.grade, "local-auto");
        assert!(!back.cap_mapping_lifecycle.has_grade);
        assert_eq!(encode_session(&back).unwrap(), text);
    }

    #[test]
    fn session_capability_grade_bad_enum() {
        // The encoder does not duplicate enum checks; the bad grade
        // must fail the reparse instead.
        let mut s = base_session();
        s.cap_bounce_attempts.has_grade = true;
        s.cap_bounce_attempts.grade = "attested".to_string();
        let text = encode_session(&s).unwrap();
        let err = parse_session(text.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("grade"));
    }

    #[test]
    fn session_regions_roundtrip() {
        let mut s = base_session();
        s.baseline_complete = true;
        s.baseline_region_count = 2;
        let first = RegionObservation {
            region_id: "r1".to_string(),
            state: "shared".to_string(),
            length: 8192,
            address_space: "guest_physical".to_string(),
            provenance: "seed-a".to_string(),
            generation: 2,
            ..RegionObservation::default()
        };
        let second = RegionObservation {
            region_id: "r2".to_string(),
            state: "unknown".to_string(),
            offset: 8192,
            length: 4096,
            address_space: "iova".to_string(),
            provenance: "seed-b".to_string(),
            ..RegionObservation::default()
        };
        s.baseline_regions.push(first);
        s.baseline_regions.push(second);
        let text = encode_session(&s).unwrap();
        assert!(text.contains("\"region_id\":\"r1\""));
        assert!(text.contains("\"length\":\"4096\""));
        assert!(text.contains("\"generation\":2"));
        assert!(text.contains("\"generation\":1"));
        let back = parse_session(text.as_bytes()).unwrap();
        assert_eq!(back.baseline_regions.len(), 2);
        assert_eq!(back.baseline_regions[0].region_id, "r1");
        assert_eq!(back.baseline_regions[0].generation, 2);
        assert_eq!(back.baseline_regions[1].address_space, "iova");
        assert_eq!(back.baseline_regions[1].generation, 1);
        assert_eq!(encode_session(&back).unwrap(), text);
    }

    #[test]
    fn session_key_order_is_fixed() {
        let mut s = base_session();
        s.has_boot_id = true;
        s.boot_id = "b1".to_string();
        s.has_build = true;
        s.build = "build-1".to_string();
        s.asserted_mode_present = true;
        s.has_asserted_mode = true;
        s.asserted_mode = "sev_snp".to_string();
        s.has_baseline_start_ns = true;
        s.baseline_start_ns = 5;
        s.has_filter_device = true;
        s.filter_device = "dev-1".to_string();
        // A checkpoint session: unfinalized with integrity, so the
        // generation key survives the reparse validity rules.
        s.finalized = false;
        s.has_integrity = true;
        s.has_end_reason = true;
        s.end_reason = "checkpoint".to_string();
        s.has_checkpoint_generation = true;
        s.checkpoint_generation = 2;
        s.has_verdict = true;
        s.verdict_name = "complete".to_string();
        s.verdict_loss_bps = 0;
        s.verdict_delivered = 50;
        s.stop.has_checkpoint_failures = true;
        s.stop.has_drain_completed = true;
        s.stop.drain_completed = true;
        s.stop.has_submit_after_drain = true;
        let text = encode_session(&s).unwrap();
        let order = [
            "\"schema_version\"",
            "\"session_id\"",
            "\"boot_id\"",
            "\"synthetic\"",
            "\"product\"",
            "\"environment\"",
            "\"capture\"",
            "\"device_catalog\"",
            "\"baseline\"",
            "\"capabilities\"",
            "\"quality\"",
            "\"stop\"",
            "\"verdict\"",
        ];
        let mut at = 0;
        for key in order {
            let pos = text[at..]
                .find(key)
                .unwrap_or_else(|| panic!("missing {key}"));
            at += pos + key.len();
        }
        let stop = &text[text.find("\"stop\"").unwrap()..];
        let stop_order = [
            "\"checkpoint_failures\"",
            "\"outcome\"",
            "\"reason\"",
            "\"budget_ms\"",
            "\"elapsed_ms\"",
            "\"admission_closed\"",
            "\"quiescence_observed\"",
            "\"writers_settled\"",
            "\"in_flight_at_close\"",
            "\"late_submits_drained\"",
            "\"drained_records\"",
            "\"drain_completed\"",
            "\"submit_after_drain\"",
            "\"busy_at_drain\"",
            "\"counters_valid\"",
            "\"open_mappings\"",
        ];
        let mut sat = 0;
        for key in stop_order {
            let pos = stop[sat..]
                .find(key)
                .unwrap_or_else(|| panic!("missing stop {key}"));
            sat += pos + key.len();
        }
        let back = parse_session(text.as_bytes()).unwrap();
        assert_eq!(encode_session(&back).unwrap(), text);
    }

    #[test]
    fn integrity_empty_encodes_exact() {
        let v = Integrity::default();
        assert_eq!(
            encode_integrity(&v).unwrap(),
            concat!(
                "{\"algorithm\":\"sha256\",\"events_bytes\":\"0\",",
                "\"line_count\":\"0\",\"first_seq\":null,\"last_seq\":null,",
                "\"events_sha256\":",
                "\"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\",",
                "\"kinds\":{\"bounce_attempt\":\"0\",\"map_result\":\"0\",",
                "\"unmap\":\"0\",\"copy\":\"0\",\"sync_request\":\"0\",",
                "\"transition_result\":\"0\",\"pool_sample\":\"0\",\"gap\":\"0\",",
                "\"marker\":\"0\",\"counter_snapshot\":\"0\"}}",
            ),
        );
    }

    #[test]
    fn integrity_encode_validates() {
        let v = Integrity {
            line_count: 1,
            ..Integrity::default()
        };
        let err = encode_integrity(&v).unwrap_err();
        assert_eq!(err.what, "capture.integrity");
    }

    #[test]
    fn integrity_session_roundtrip_boundaries() {
        let mut s = base_session();
        s.has_integrity = true;
        let empty = encode_session(&s).unwrap();
        assert!(empty.contains("\"schema_version\":\"0.1.4\""));
        let back = parse_session(empty.as_bytes()).unwrap();
        assert!(back.has_integrity);
        assert!(!back.integrity.has_seq);
        assert_eq!(encode_session(&back).unwrap(), empty);
        for size in [9_007_199_254_740_993u64, u64::MAX] {
            s.integrity.events_bytes = size;
            s.integrity.line_count = size;
            s.integrity.has_seq = true;
            s.integrity.last_seq = size - 1;
            s.integrity.kinds[0] = size;
            s.integrity.events_sha256 =
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string();
            let encoded = encode_session(&s).unwrap();
            let parsed = parse_session(encoded.as_bytes()).unwrap();
            assert_eq!(parsed.integrity.events_bytes, size);
            assert_eq!(parsed.integrity.line_count, size);
            assert_eq!(parsed.integrity.kinds[0], size);
            assert_eq!(encode_session(&parsed).unwrap(), encoded);
        }
    }

    #[test]
    fn integrity_session_rejects_bad_metadata() {
        let mut s = base_session();
        s.has_integrity = true;
        let text = encode_session(&s).unwrap();
        let corruptions = [
            text.replace("\"algorithm\":\"sha256\"", "\"algorithm\":\"sha512\""),
            text.replace("\"line_count\":\"0\"", "\"line_count\":\"00\""),
            text.replace(
                "\"events_bytes\":\"0\"",
                "\"events_bytes\":\"18446744073709551616\"",
            ),
            text.replace("\"first_seq\":null", "\"first_seq\":\"0\""),
            text.replace("\"marker\":\"0\",", ""),
            text.replace("\"marker\":\"0\"", "\"marker\":\"1\""),
            text.replace("\"marker\":\"0\"", "\"marker\":\"0\",\"marker\":\"0\""),
            text.replace(
                "\"schema_version\":\"0.1.4\"",
                "\"schema_version\":\"0.1.3\"",
            ),
        ];
        for bad in &corruptions {
            assert!(parse_session(bad.as_bytes()).is_err(), "must refuse {bad}");
        }
    }

    #[test]
    fn integrity_session_rejects_malformed_digest() {
        let mut s = base_session();
        s.has_integrity = true;
        s.integrity.events_bytes = 1;
        s.integrity.line_count = 1;
        s.integrity.has_seq = true;
        s.integrity.kinds[0] = 1;
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        s.integrity.events_sha256 = digest.to_string();
        let text = encode_session(&s).unwrap();
        parse_session(text.as_bytes()).unwrap();
        let cases = [
            String::new(),
            format!("{digest}0"),
            digest.replace('a', "A"),
            digest.replace('a', "g"),
        ];
        for bad in &cases {
            let err = parse_session(text.replace(digest, bad).as_bytes()).unwrap_err();
            assert_eq!(err.what, "capture.integrity.events_sha256");
        }
    }

    #[test]
    fn integrity_session_rejects_overflowed_kind_sum() {
        let mut s = base_session();
        s.has_integrity = true;
        s.integrity.events_bytes = u64::MAX;
        s.integrity.line_count = u64::MAX;
        s.integrity.has_seq = true;
        s.integrity.last_seq = u64::MAX - 1;
        s.integrity.kinds[0] = u64::MAX;
        let text = encode_session(&s).unwrap();
        parse_session(text.as_bytes()).unwrap();
        let bad = text.replace("\"marker\":\"0\"", "\"marker\":\"1\"");
        let err = parse_session(bad.as_bytes()).unwrap_err();
        assert!(err.message.contains("overflow"));
    }

    #[test]
    fn verdict_encode_range_and_shape() {
        let mut s = base_session();
        s.has_verdict = true;
        s.verdict_name = "partial_known_loss".to_string();
        s.verdict_loss_bps = 500;
        s.verdict_delivered = 95;
        let text = encode_session(&s).unwrap();
        assert!(text.contains(
            "\"verdict\":{\"name\":\"partial_known_loss\",\"loss_ratio_bps\":\"500\",\"delivered\":\"95\"}"
        ));
        let back = parse_session(text.as_bytes()).unwrap();
        assert_eq!(encode_session(&back).unwrap(), text);
        s.verdict_loss_bps = -1;
        assert_eq!(
            encode_session(&s).unwrap_err().what,
            "verdict.loss_ratio_bps"
        );
        s.verdict_loss_bps = 10001;
        assert_eq!(
            encode_session(&s).unwrap_err().what,
            "verdict.loss_ratio_bps"
        );
    }

    // Reference oracle: the composed-string encoder style, kept as an
    // independent check that the buffer encoder emits identical bytes.

    fn ref_hex_lo(v: u8) -> u8 {
        if v < 10 { b'0' + v } else { b'a' + v - 10 }
    }

    fn ref_escape_into(buf: &mut Vec<u8>, raw: &[u8]) {
        buf.push(b'"');
        for &b in raw {
            match b {
                b'"' => buf.extend_from_slice(b"\\\""),
                b'\\' => buf.extend_from_slice(b"\\\\"),
                0x08 => buf.extend_from_slice(b"\\b"),
                0x09 => buf.extend_from_slice(b"\\t"),
                0x0A => buf.extend_from_slice(b"\\n"),
                0x0C => buf.extend_from_slice(b"\\f"),
                0x0D => buf.extend_from_slice(b"\\r"),
                b if b < 0x20 => {
                    buf.extend_from_slice(b"\\u00");
                    buf.push(ref_hex_lo(b >> 4));
                    buf.push(ref_hex_lo(b & 15));
                }
                _ => buf.push(b),
            }
        }
        buf.push(b'"');
    }

    fn ref_quote_bytes(raw: &[u8]) -> Result<Vec<u8>, ()> {
        let mut buf = Vec::new();
        ref_escape_into(&mut buf, raw);
        String::from_utf8(buf.clone()).map(|_| buf).map_err(|_| ())
    }

    fn ref_quote(text: &str) -> String {
        let mut buf = Vec::new();
        ref_escape_into(&mut buf, text.as_bytes());
        String::from_utf8(buf).expect("test pool holds valid UTF-8")
    }

    fn ref_member(name: &str, value: String) -> String {
        format!("{}:{value}", ref_quote(name))
    }

    fn ref_jobj(parts: Vec<String>) -> String {
        format!("{{{}}}", parts.join(","))
    }

    fn ref_ju64(v: u64) -> String {
        ref_quote(&v.to_string())
    }

    fn ref_jbool(v: bool) -> String {
        if v {
            "true".to_string()
        } else {
            "false".to_string()
        }
    }

    fn ref_encode_source(ev: &Event) -> String {
        ref_jobj(vec![
            ref_member("hook", ref_quote(&ev.source_hook)),
            ref_member("backend", ref_quote(&ev.source_backend)),
            ref_member("profile_id", ref_quote(&ev.source_profile_id)),
            ref_member("measurement", ref_quote(&ev.source_measurement)),
            ref_member("correlation", ref_quote(&ev.source_correlation)),
        ])
    }

    fn ref_encode_observer(ev: &Event) -> String {
        let mut parts = Vec::new();
        if ev.has_cpu {
            parts.push(ref_member("cpu", format_i64(ev.cpu)));
        }
        if ev.has_pid {
            parts.push(ref_member("pid", format_i64(ev.pid)));
        }
        if ev.has_tgid {
            parts.push(ref_member("tgid", format_i64(ev.tgid)));
        }
        if ev.has_comm {
            parts.push(ref_member("comm", ref_quote(&ev.comm)));
        }
        if ev.has_cgroup_id {
            parts.push(ref_member("cgroup_id", ref_quote(&ev.cgroup_id)));
        }
        parts.push(ref_member("relation", ref_quote("execution_context_only")));
        ref_jobj(parts)
    }

    fn ref_opt_str(has: bool, v: &str) -> String {
        if has {
            ref_quote(v)
        } else {
            "null".to_string()
        }
    }

    fn ref_opt_u64(has: bool, v: u64) -> String {
        if has { ref_ju64(v) } else { "null".to_string() }
    }

    fn ref_opt_i64(has: bool, v: i64) -> String {
        if has {
            format_i64(v)
        } else {
            "null".to_string()
        }
    }

    fn ref_encode_data(ev: &Event) -> Result<String, EncodeError> {
        let kind = ev.kind.as_str();
        let parts = if kind == "bounce_attempt" {
            vec![
                ref_member("device_id", ref_quote(&ev.bounce.device_id)),
                ref_member("requested_bytes", ref_ju64(ev.bounce.requested_bytes)),
                ref_member("forced", ref_jbool(ev.bounce.forced)),
                ref_member("operation_id", ref_quote(&ev.bounce.operation_id)),
            ]
        } else if kind == "map_result" {
            let m = &ev.map_result;
            vec![
                ref_member("operation_id", ref_quote(&m.operation_id)),
                ref_member("success", ref_jbool(m.success)),
                ref_member("mapping_id", ref_opt_str(m.has_mapping_id, &m.mapping_id)),
                ref_member("return_code", ref_opt_i64(m.has_return_code, m.return_code)),
                ref_member(
                    "mapped_bytes",
                    ref_opt_u64(m.has_mapped_bytes, m.mapped_bytes),
                ),
                ref_member(
                    "wire_generation",
                    ref_opt_u64(m.has_wire_generation, m.wire_generation),
                ),
                ref_member(
                    "wire_identity",
                    ref_opt_str(m.has_wire_identity, &m.wire_identity),
                ),
            ]
        } else if kind == "unmap" {
            let u = &ev.unmap;
            vec![
                ref_member("mapping_id", ref_opt_str(u.has_mapping_id, &u.mapping_id)),
                ref_member(
                    "wire_generation",
                    ref_opt_u64(u.has_wire_generation, u.wire_generation),
                ),
                ref_member(
                    "wire_identity",
                    ref_opt_str(u.has_wire_identity, &u.wire_identity),
                ),
            ]
        } else if kind == "copy" {
            let c = &ev.copy;
            let mut parts = vec![
                ref_member("operation_id", ref_quote(&c.operation_id)),
                ref_member("mapping_id", ref_opt_str(c.has_mapping_id, &c.mapping_id)),
                ref_member("direction", ref_quote(&c.direction)),
                ref_member("bytes", ref_ju64(c.bytes)),
            ];
            if c.pool_private {
                parts.push(ref_member("pool_private", ref_jbool(c.pool_private)));
            }
            if c.offset_past_allocation {
                parts.push(ref_member(
                    "offset_past_allocation",
                    ref_jbool(c.offset_past_allocation),
                ));
            }
            parts
        } else if kind == "sync_request" {
            let r = &ev.sync;
            vec![
                ref_member("operation_id", ref_quote(&r.operation_id)),
                ref_member("mapping_id", ref_opt_str(r.has_mapping_id, &r.mapping_id)),
                ref_member("offset_known", ref_jbool(r.has_offset)),
                ref_member("offset", ref_opt_u64(r.has_offset, r.offset)),
                ref_member("length", ref_ju64(r.length)),
            ]
        } else if kind == "transition_result" {
            let t = &ev.transition;
            let mut parts = vec![
                ref_member("region_id", ref_quote(&t.region_id)),
                ref_member("requested_state", ref_quote(&t.requested_state)),
                ref_member("success", ref_jbool(t.success)),
                ref_member("return_code", ref_opt_i64(t.has_return_code, t.return_code)),
                ref_member("offset", ref_ju64(t.offset)),
                ref_member("length", ref_ju64(t.length)),
            ];
            if t.has_address_space {
                parts.push(ref_member("address_space", ref_quote(&t.address_space)));
            }
            if t.has_resolution {
                parts.push(ref_member("resolution", ref_quote(&t.resolution)));
            }
            parts.push(ref_member("generation", format_i64(t.generation)));
            parts
        } else if kind == "pool_sample" {
            let p = &ev.pool;
            let mut parts = vec![
                ref_member("pool_id", ref_quote(&p.pool_id)),
                ref_member("used_bytes", ref_opt_u64(p.has_used, p.used_bytes)),
                ref_member(
                    "capacity_bytes",
                    ref_opt_u64(p.has_capacity, p.capacity_bytes),
                ),
                ref_member("unit", ref_quote(&p.unit)),
            ];
            if !p.allocator.is_empty() {
                parts.push(ref_member("allocator", ref_quote(&p.allocator)));
            }
            if p.has_unit_bytes {
                parts.push(ref_member("unit_bytes", ref_ju64(p.unit_bytes)));
            }
            if p.has_hiwater {
                parts.push(ref_member("hiwater_bytes", ref_ju64(p.hiwater_bytes)));
            }
            if !p.reason.is_empty() {
                parts.push(ref_member("reason", ref_quote(&p.reason)));
            }
            parts
        } else if kind == "gap" {
            let g = &ev.gap;
            vec![
                ref_member("channel", ref_quote(&g.channel)),
                ref_member("lost_count", ref_opt_u64(g.has_lost_count, g.lost_count)),
                ref_member("reason", ref_quote(&g.reason)),
                ref_member("window_start_ns", ref_ju64(g.window_start_ns)),
                ref_member("window_end_ns", ref_ju64(g.window_end_ns)),
            ]
        } else if kind == "marker" {
            vec![ref_member("text", ref_quote(&ev.marker.text))]
        } else if kind == "counter_snapshot" {
            let n = &ev.snapshot;
            let mut scope = Vec::new();
            if n.has_scope_device {
                scope.push(ref_member("device_id", ref_quote(&n.scope_device_id)));
            }
            scope.push(ref_member("profile_id", ref_quote(&n.scope_profile_id)));
            vec![
                ref_member("counter_id", ref_quote(&n.counter_id)),
                ref_member("epoch", ref_ju64(n.epoch)),
                ref_member("scope", ref_jobj(scope)),
                ref_member("value", ref_ju64(n.value)),
                ref_member("unit", ref_quote(&n.unit)),
            ]
        } else {
            return Err(EncodeError::new(
                "kind",
                format!("unknown event kind: {kind}"),
            ));
        };
        Ok(ref_jobj(parts))
    }

    fn ref_encode_event(ev: &Event) -> Result<String, EncodeError> {
        let mut version = EVENT_SCHEMA_VERSION_PREV;
        if ev.kind == "copy" && (ev.copy.pool_private || ev.copy.offset_past_allocation) {
            version = EVENT_SCHEMA_VERSION;
        }
        let mut parts = vec![
            ref_member("schema_version", ref_quote(version)),
            ref_member("session_id", ref_quote(&ev.session_id)),
            ref_member("seq", ref_ju64(ev.seq)),
            ref_member("ts_ns", ref_ju64(ev.ts_ns)),
            ref_member("kind", ref_quote(&ev.kind)),
            ref_member("source", ref_encode_source(ev)),
        ];
        if ev.has_observer {
            parts.push(ref_member("observer_context", ref_encode_observer(ev)));
        }
        parts.push(ref_member("data", ref_encode_data(ev)?));
        Ok(ref_jobj(parts))
    }

    fn ref_encode_event_line(ev: &Event) -> Result<Vec<u8>, EncodeError> {
        let mut out = ref_encode_event(ev)?.into_bytes();
        out.push(b'\n');
        Ok(out)
    }

    fn assert_same(ev: &Event) -> bool {
        let got = encode_event(ev);
        let want = ref_encode_event(ev);
        assert_eq!(got, want);
        let a = encode_event_line(ev);
        let b = ref_encode_event_line(ev);
        assert_eq!(a, b);
        got.is_ok()
    }

    fn str_pool() -> Vec<String> {
        let mut out = vec![
            String::new(),
            "a".to_string(),
            "op0".to_string(),
            "d000001".to_string(),
            "linux-x86_64-7.0.0-34-generic".to_string(),
            "\"".to_string(),
            "\\".to_string(),
            "a\"b\\c".to_string(),
            "é".to_string(),
            "€ 中文 😀".to_string(),
        ];
        let mut shorts = Vec::new();
        for b in [0x08u8, 0x0C, 0x0A, 0x0D, 0x09] {
            shorts.push(b);
            out.push(String::from_utf8(vec![b]).unwrap());
        }
        out.push(String::from_utf8(shorts).unwrap());
        let mut controls: Vec<u8> = (0..0x20).collect();
        controls.push(0x7F);
        out.push(String::from_utf8(controls).unwrap());
        let edges = vec![0x0A, 0x61, 0x62, 0x22, 0x22, 0x5C, 0x01, 0xC3, 0xA9, 0x0A];
        out.push(String::from_utf8(edges).unwrap());
        let mut mixed = String::new();
        for i in 0..200u32 {
            mixed.push_str("run");
            mixed.push_str(&i.to_string());
            if i % 7 == 0 {
                mixed.push('"');
            }
            if i % 11 == 0 {
                mixed.push('\\');
            }
            if i % 13 == 0 {
                mixed.push(char::from(i as u8 % 32));
            }
            if i % 17 == 0 {
                mixed.push_str("ü😀");
            }
        }
        out.push(mixed);
        out.push("x".repeat(5000));
        out
    }

    fn u64_pool() -> Vec<u64> {
        vec![
            0,
            1,
            9,
            10,
            99,
            100,
            4096,
            4_294_967_296,
            9_007_199_254_740_993,
            10_000_000_000_000_000_000,
            u64::MAX,
        ]
    }

    fn i64_pool() -> Vec<i64> {
        vec![0, 1, -1, 9, -10, -4095, i64::MAX, i64::MIN]
    }

    fn kinds() -> Vec<&'static str> {
        vec![
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
        ]
    }

    struct Picker {
        strs: Vec<String>,
        u64s: Vec<u64>,
        i64s: Vec<i64>,
        state: u64,
    }

    impl Picker {
        fn new(seed: u64) -> Self {
            Self {
                strs: str_pool(),
                u64s: u64_pool(),
                i64s: i64_pool(),
                state: seed,
            }
        }

        fn next(&mut self) -> usize {
            // Wrapping LCG; determinism is what the tests need.
            self.state = self
                .state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (self.state >> 33) as usize
        }

        fn s(&mut self) -> String {
            let i = self.next() % self.strs.len();
            self.strs[i].clone()
        }

        fn u(&mut self) -> u64 {
            let i = self.next() % self.u64s.len();
            self.u64s[i]
        }

        fn i(&mut self) -> i64 {
            let i = self.next() % self.i64s.len();
            self.i64s[i]
        }
    }

    fn bit(mask: usize, n: u32) -> bool {
        (mask >> n) & 1 == 1
    }

    /// One event; mask bits 0-5 payload flags, 6-11 observer.
    fn build(kind: &str, mask: usize, p: &mut Picker) -> Event {
        // Field order matches the picker stream of the oracle builder.
        let mut ev = Event {
            session_id: p.s(),
            seq: p.u(),
            ts_ns: p.u(),
            kind: kind.to_string(),
            source_hook: p.s(),
            source_backend: p.s(),
            source_profile_id: p.s(),
            source_measurement: p.s(),
            source_correlation: p.s(),
            has_observer: bit(mask, 6),
            has_cpu: bit(mask, 7),
            cpu: p.i(),
            has_pid: bit(mask, 8),
            pid: p.i(),
            has_tgid: bit(mask, 9),
            tgid: p.i(),
            has_comm: bit(mask, 10),
            comm: p.s(),
            has_cgroup_id: bit(mask, 11),
            cgroup_id: p.s(),
            ..Event::default()
        };
        ev.bounce.device_id = p.s();
        ev.bounce.requested_bytes = p.u();
        ev.bounce.forced = bit(mask, 0);
        ev.bounce.operation_id = p.s();
        ev.map_result.operation_id = p.s();
        ev.map_result.success = bit(mask, 0);
        ev.map_result.has_mapping_id = bit(mask, 1);
        ev.map_result.mapping_id = p.s();
        ev.map_result.has_return_code = bit(mask, 2);
        ev.map_result.return_code = p.i();
        ev.map_result.has_mapped_bytes = bit(mask, 3);
        ev.map_result.mapped_bytes = p.u();
        ev.map_result.has_wire_generation = bit(mask, 4);
        ev.map_result.wire_generation = p.u();
        ev.map_result.has_wire_identity = bit(mask, 5);
        ev.map_result.wire_identity = p.s();
        ev.unmap.has_mapping_id = bit(mask, 0);
        ev.unmap.mapping_id = p.s();
        ev.unmap.has_wire_generation = bit(mask, 1);
        ev.unmap.wire_generation = p.u();
        ev.unmap.has_wire_identity = bit(mask, 2);
        ev.unmap.wire_identity = p.s();
        ev.copy.operation_id = p.s();
        ev.copy.has_mapping_id = bit(mask, 0);
        ev.copy.mapping_id = p.s();
        ev.copy.direction = p.s();
        ev.copy.bytes = p.u();
        ev.copy.pool_private = bit(mask, 1);
        ev.copy.offset_past_allocation = bit(mask, 2);
        ev.sync.operation_id = p.s();
        ev.sync.has_mapping_id = bit(mask, 0);
        ev.sync.mapping_id = p.s();
        ev.sync.has_offset = bit(mask, 1);
        ev.sync.offset = p.u();
        ev.sync.length = p.u();
        ev.transition.region_id = p.s();
        ev.transition.requested_state = p.s();
        ev.transition.success = bit(mask, 0);
        ev.transition.has_return_code = bit(mask, 1);
        ev.transition.return_code = p.i();
        ev.transition.offset = p.u();
        ev.transition.length = p.u();
        ev.transition.has_address_space = bit(mask, 2);
        ev.transition.address_space = p.s();
        ev.transition.has_resolution = bit(mask, 3);
        ev.transition.resolution = p.s();
        ev.transition.generation = p.i();
        ev.pool.pool_id = p.s();
        ev.pool.has_used = bit(mask, 0);
        ev.pool.used_bytes = p.u();
        ev.pool.has_capacity = bit(mask, 1);
        ev.pool.capacity_bytes = p.u();
        ev.pool.unit = p.s();
        ev.pool.allocator = if bit(mask, 2) { p.s() } else { String::new() };
        ev.pool.has_unit_bytes = bit(mask, 3);
        ev.pool.unit_bytes = p.u();
        ev.pool.has_hiwater = bit(mask, 4);
        ev.pool.hiwater_bytes = p.u();
        ev.pool.reason = if bit(mask, 5) { p.s() } else { String::new() };
        ev.gap.channel = p.s();
        ev.gap.has_lost_count = bit(mask, 0);
        ev.gap.lost_count = p.u();
        ev.gap.reason = p.s();
        ev.gap.window_start_ns = p.u();
        ev.gap.window_end_ns = p.u();
        ev.marker.text = p.s();
        ev.snapshot.counter_id = p.s();
        ev.snapshot.epoch = p.u();
        ev.snapshot.has_scope_device = bit(mask, 0);
        ev.snapshot.scope_device_id = p.s();
        ev.snapshot.scope_profile_id = p.s();
        ev.snapshot.value = p.u();
        ev.snapshot.unit = p.s();
        ev
    }

    fn check_span(raw: &[u8]) {
        let mut buf = Vec::new();
        let mine = put_span(&mut buf, raw);
        let refr = ref_quote_bytes(raw);
        match (mine, refr) {
            (Ok(()), Ok(want)) => assert_eq!(buf, want, "quoter mismatch for {raw:?}"),
            (Err(e), Err(())) => assert_eq!(e.what, "string"),
            (mine, refr) => panic!("quoter verdict split for {raw:?}: {mine:?} vs {refr:?}"),
        }
    }

    #[test]
    fn quote_byte_pairs() {
        // Every 1- and 2-byte string, valid or not.
        for a in 0..=255u8 {
            check_span(&[a]);
            for b in 0..=255u8 {
                check_span(&[a, b]);
            }
        }
    }

    #[test]
    fn quote_edge_sequences() {
        // Every 3- and 4-byte string over escape and UTF-8 edge bytes.
        let edge: Vec<u8> = vec![
            0x00, 0x0A, 0x1F, 0x22, 0x5C, 0x41, 0x7F, 0x80, 0xBF, 0xC2, 0xE0, 0xED, 0xF0, 0xF4,
            0xF5, 0xFF,
        ];
        let n = edge.len();
        for i in 0..n * n * n * n {
            let four = [
                edge[i % n],
                edge[(i / n) % n],
                edge[(i / (n * n)) % n],
                edge[i / (n * n * n)],
            ];
            check_span(&four[..3]);
            check_span(&four);
        }
    }

    #[test]
    fn quote_pool_matches_reference() {
        for text in str_pool() {
            assert_eq!(quote_json(&text), ref_quote(&text));
        }
    }

    #[test]
    fn event_flag_matrix() {
        // Every kind under every payload and observer flag combination.
        let kinds = kinds();
        let mut p = Picker::new(1);
        let mut encoded = 0;
        for kind in &kinds {
            for mask in 0..4096 {
                if assert_same(&build(kind, mask, &mut p)) {
                    encoded += 1;
                }
            }
        }
        assert_eq!(encoded, kinds.len() * 4096);
    }

    #[test]
    fn event_random() {
        let kinds = kinds();
        let mut p = Picker::new(20_261_021);
        for _ in 0..20_000 {
            let kind = kinds[p.next() % kinds.len()];
            assert_same(&build(kind, p.next() % 4096, &mut p));
        }
    }

    #[test]
    fn event_values() {
        // Each scalar extreme lands in every scalar slot.
        let kinds = kinds();
        let us = u64_pool();
        let vs = i64_pool();
        let mut p = Picker::new(7);
        for kind in &kinds {
            for v in &us {
                let mut ev = build(kind, 4095, &mut p);
                ev.seq = *v;
                ev.ts_ns = *v;
                ev.bounce.requested_bytes = *v;
                ev.map_result.mapped_bytes = *v;
                ev.map_result.wire_generation = *v;
                ev.unmap.wire_generation = *v;
                ev.copy.bytes = *v;
                ev.sync.offset = *v;
                ev.sync.length = *v;
                ev.transition.offset = *v;
                ev.transition.length = *v;
                ev.pool.used_bytes = *v;
                ev.pool.capacity_bytes = *v;
                ev.pool.unit_bytes = *v;
                ev.pool.hiwater_bytes = *v;
                ev.gap.lost_count = *v;
                ev.gap.window_start_ns = *v;
                ev.gap.window_end_ns = *v;
                ev.snapshot.epoch = *v;
                ev.snapshot.value = *v;
                assert!(assert_same(&ev));
            }
            for v in &vs {
                let mut ev = build(kind, 4095, &mut p);
                ev.cpu = *v;
                ev.pid = *v;
                ev.tgid = *v;
                ev.map_result.return_code = *v;
                ev.transition.return_code = *v;
                ev.transition.generation = *v;
                assert!(assert_same(&ev));
            }
        }
    }

    #[test]
    fn event_errors() {
        // Unknown kinds fail identically in both encoders; Rust
        // strings cannot carry the invalid-UTF-8 slots, which the
        // byte-quoter tests cover instead.
        let kinds = kinds();
        let mut p = Picker::new(99);
        for kind in &kinds {
            let mut ev = build(kind, 4095, &mut p);
            ev.kind = "nope".to_string();
            assert!(!assert_same(&ev));
        }
        let ev = build("nope", 4095, &mut p);
        let err = encode_event(&ev).unwrap_err();
        assert_eq!(err.what, "kind");
        assert_eq!(err.message, "unknown event kind: nope");
        // The truncated two-byte sequence both quoters must refuse.
        let mut buf = Vec::new();
        let err = put_span(&mut buf, b"a\xc3").unwrap_err();
        assert_eq!(err.what, "string");
        assert_eq!(err.message, "unencodable text");
    }

    // Fixture round-trip: every reader capture parses, encodes,
    // and reparses to an identical struct, with an idempotent
    // second encode. Intentionally-invalid captures must fail;
    // everything else must round-trip clean.

    const READER_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/reader");

    const EXPECT_FAIL: &[&str] = &[
        "adv-bad-seq-int/events.ndjson",
        "adv-bad-utf8/events.ndjson",
        "adv-depth-64/events.ndjson",
        "adv-depth-65/events.ndjson",
        "adv-int-bad/events.ndjson",
        "adv-int-leading-zero/events.ndjson",
        "adv-int-overflow/events.ndjson",
        "adv-nul/events.ndjson",
        "adv-unknown-field/events.ndjson",
        "badkind/events.ndjson",
        "baseline-after-window/session.json",
        "compat-major/session.json",
        "corrupt-tail/events.ndjson",
        "f2-contradictory-provenance/session.json",
        "f3-baseline/session.json",
        "f3-span-sync/events.ndjson",
        "f3-span-transition/events.ndjson",
        "f4-definitive-dupkey/events.ndjson",
        "f4-definitive-version/events.ndjson",
        "f4-nocolon-dupkey/events.ndjson",
        "f4-nocolon-unknown/events.ndjson",
        "f4-truncated-nested/events.ndjson",
        "f4-truncated-primitive/events.ndjson",
        "f4-truncated-scope-device/events.ndjson",
        "f4-truncated-scope-profile/events.ndjson",
        "interior-corrupt/events.ndjson",
        "partial-tail/events.ndjson",
        "size-ok/events.ndjson",
        "size-over/events.ndjson",
        "unsanitized-error/events.ndjson",
        "unsanitized-session/session.json",
    ];

    fn is_blank(line: &[u8]) -> bool {
        line.iter()
            .all(|b| *b == b' ' || *b == b'\t' || *b == b'\r')
    }

    fn roundtrip_session(data: &[u8]) -> Result<(), String> {
        let first = parse_session(data).map_err(|e| e.to_string())?;
        let text = encode_session(&first).map_err(|e| e.to_string())?;
        let second = parse_session(text.as_bytes()).map_err(|e| e.to_string())?;
        if first != second {
            return Err("session struct mismatch after reparse".to_string());
        }
        let again = encode_session(&second).map_err(|e| e.to_string())?;
        if again != text {
            return Err("session encode not idempotent".to_string());
        }
        Ok(())
    }

    fn roundtrip_events(data: &[u8]) -> Result<usize, String> {
        let mut count = 0;
        for line in data.split(|b| *b == b'\n') {
            if line.is_empty() || is_blank(line) {
                continue;
            }
            let first = parse_event(line).map_err(|e| format!("line {count}: {e}"))?;
            let text = encode_event(&first).map_err(|e| format!("line {count}: {e}"))?;
            let second = parse_event(text.as_bytes()).map_err(|e| format!("line {count}: {e}"))?;
            if first != second {
                return Err(format!("line {count}: event struct mismatch after reparse"));
            }
            let again = encode_event(&second).map_err(|e| format!("line {count}: {e}"))?;
            if again != text {
                return Err(format!("line {count}: event encode not idempotent"));
            }
            count += 1;
        }
        Ok(count)
    }

    #[test]
    fn reader_fixtures_roundtrip() {
        let mut failed: Vec<String> = Vec::new();
        let mut sessions = 0;
        let mut events = 0;
        let mut files = 0;
        let mut dirs: Vec<_> = std::fs::read_dir(READER_DIR)
            .expect("reader fixtures present")
            .collect::<Result<Vec<_>, _>>()
            .expect("fixture entries readable")
            .into_iter()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        dirs.sort();
        assert!(!dirs.is_empty(), "reader fixtures must exist");
        for dir in &dirs {
            for name in ["session.json", "events.ndjson"] {
                let path = format!("{READER_DIR}/{dir}/{name}");
                let Ok(data) = std::fs::read(&path) else {
                    continue;
                };
                files += 1;
                let rel = format!("{dir}/{name}");
                let outcome = if name == "session.json" {
                    roundtrip_session(&data).map(|()| 0)
                } else {
                    roundtrip_events(&data)
                };
                match outcome {
                    Ok(n) => {
                        if name == "session.json" {
                            sessions += 1;
                        } else {
                            events += n;
                        }
                    }
                    Err(detail) => {
                        failed.push(rel.clone());
                        eprintln!("roundtrip: {rel}: {detail}");
                    }
                }
            }
        }
        failed.sort();
        let mut want: Vec<String> = EXPECT_FAIL.iter().map(|s| s.to_string()).collect();
        want.sort();
        assert_eq!(failed, want, "unexpected round-trip failures");
        assert!(
            files > 200,
            "must cover the reader corpus, saw {files} files"
        );
        assert!(sessions > 100, "must round-trip sessions, saw {sessions}");
        assert!(events > 100, "must round-trip events, saw {events}");
        eprintln!("roundtrip: {sessions} sessions, {events} events, {files} files clean");
    }
}
