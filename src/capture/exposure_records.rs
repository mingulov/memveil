// SPDX-License-Identifier: GPL-3.0-or-later
//! Canonical exposure records over the durable capture protocol.
//!
//! Snapshot records share one capture protocol: canonical JSON lines,
//! fixed field order, duplicate-key refusal, and a committed-byte seal
//! verified against the 0.1.4 integrity rules. The seal accepts the
//! ten legacy event kinds plus the `exposure_fact` extension kind, so
//! a pure legacy stream verifies unchanged while exposure facts seal
//! under the same digest. No unsealed sidecar can supply policy
//! evidence: replay consumes the sealed lines only.
//!
//! The module is self-contained on purpose: it declares no parent
//! items, so it compiles both under its public module path and
//! through a direct path include in tests. It takes no live input
//! and performs no I/O. Lexical scalar checks that
//! need reader context stay with the owning reader; the normalizer
//! canonicalizes structure, field order and string quoting. Every
//! leaf takes exactly its canonical JSON type, arrays hold strings
//! only, and anything without a canonical order is refused.

use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::hash_map::Entry;
use std::fmt;

/// Frozen record shapes shared with the model validator.
///
/// Path-included from the model module rather than copied, so the
/// seal path and `ExposureFact::validate` enforce one frozen table
/// each; the path resolves from this file's directory in both
/// compilation modes (public module path and test path include).
/// Only the closed-vocabulary tables are read here; the remaining
/// items ride along unused. The second include of the model file is
/// deliberate sharing, not an accidental duplicate module.
#[allow(dead_code)]
#[allow(clippy::duplicate_mod)]
#[path = "../model/exposure.rs"]
mod exposure_shapes;

/// Ten legacy event kinds in integrity-table order.
pub const LEGACY_KINDS: [&str; 10] = [
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
];

/// Exposure-fact extension kind for 0.3.0 streams.
pub const EXPOSURE_FACT_KIND: &str = "exposure_fact";

/// Event-line contract selected by a snapshot's session version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealContract {
    /// 0.1.x sessions: ten legacy kinds under legacy rules.
    Legacy,
    /// 0.3.0 sessions: legacy kinds plus exposure facts, new checks.
    Exposure,
}

/// Legacy session versions selecting the legacy line contract.
const LEGACY_SESSION_VERSIONS: [&str; 4] = ["0.1.1", "0.1.2", "0.1.3", "0.1.4"];

/// Legacy line versions admitted under the legacy contract.
const LEGACY_LINE_VERSIONS: [&str; 2] = ["0.1.1", "0.1.2"];

/// Exposure line version: the only version under the exposure contract.
const EXPOSURE_LINE_VERSION: &str = "0.3.0";

/// Schema length bounds for the three free source strings.
const SOURCE_BOUNDS: [(&str, usize); 3] = [("hook", 256), ("backend", 64), ("profile_id", 128)];

/// The event-line contract a session selects, or `None` when unknown.
///
/// A 0.3.0 session selects the exposure contract; a 0.1.x session
/// selects the legacy contract. The seal validates every line under
/// the session's contract, so legacy captures verify under legacy
/// rules while 0.3.0 lines keep the new checks, and neither side
/// admits the other's version.
fn session_contract(session: &[(String, JsonValue)]) -> Option<SealContract> {
    let version = sealed_str(session, "schema_version")?;
    if version == EXPOSURE_LINE_VERSION {
        Some(SealContract::Exposure)
    } else if LEGACY_SESSION_VERSIONS.contains(&version) {
        Some(SealContract::Legacy)
    } else {
        None
    }
}

/// Digest of the empty event stream.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Snapshot event-line bound in bytes, content plus terminator.
///
/// Matches the capture reader's line bound exactly: one snapshot
/// entry carries exactly one physical line under the same 64 KiB
/// budget the reader enforces while staging lines.
pub const SNAPSHOT_MAX_LINE_BYTES: usize = 65536;

/// The seven integrity keys in seal order; nothing else is admitted.
const INTEGRITY_KEYS: [&str; 7] = [
    "algorithm",
    "events_bytes",
    "line_count",
    "first_seq",
    "last_seq",
    "events_sha256",
    "kinds",
];

/// Canonical event-envelope field order.
pub const ENVELOPE_FIELDS: [&str; 7] = [
    "schema_version",
    "session_id",
    "seq",
    "ts_ns",
    "kind",
    "source",
    "data",
];

/// Canonical envelope source order.
pub const SOURCE_FIELDS: [&str; 5] = [
    "hook",
    "backend",
    "profile_id",
    "measurement",
    "correlation",
];

/// Canonical coverage-source field order.
pub const COVERAGE_SOURCE_FIELDS: [&str; 11] = [
    "source_id",
    "capability",
    "profile_id",
    "subject_id",
    "platform_cell",
    "address_namespace",
    "phase",
    "status",
    "reason",
    "window",
    "quality",
];

/// Canonical exposure-fact field order, reason keys after their base key.
pub const EXPOSURE_FACT_FIELDS: [&str; 21] = [
    "evidence_id",
    "source_id",
    "epoch",
    "operation_id",
    "parent_operation_id",
    "parent_operation_id_reason",
    "kind",
    "direction",
    "object_token",
    "object_token_reason",
    "generation",
    "offset",
    "length_bytes",
    "native_result",
    "native_result_reason",
    "caller_class",
    "peer_class",
    "clock_domain",
    "observed_interval",
    "semantics",
    "quality",
];

/// Required exposure-fact keys; the rest is optional or reason-bound.
pub const EXPOSURE_FACT_REQUIRED: [&str; 16] = [
    "evidence_id",
    "source_id",
    "epoch",
    "operation_id",
    "kind",
    "direction",
    "generation",
    "offset",
    "length_bytes",
    "native_result",
    "caller_class",
    "peer_class",
    "clock_domain",
    "observed_interval",
    "semantics",
    "quality",
];

/// Canonical exposure-object field order.
pub const EXPOSURE_OBJECT_FIELDS: [&str; 10] = [
    "object_token",
    "generation",
    "object_class",
    "namespace",
    "origin_source",
    "lifecycle_status",
    "state",
    "state_evidence",
    "expected_boundary",
    "uncertainty",
];

/// Required exposure-object keys; the boundary is optional.
pub const EXPOSURE_OBJECT_REQUIRED: [&str; 9] = [
    "object_token",
    "generation",
    "object_class",
    "namespace",
    "origin_source",
    "lifecycle_status",
    "state",
    "state_evidence",
    "uncertainty",
];

/// Canonical baseline-sample field order.
pub const BASELINE_SAMPLE_FIELDS: [&str; 12] = [
    "sample_id",
    "source_id",
    "start_time",
    "end_time",
    "scope",
    "counts",
    "units",
    "visited",
    "returned",
    "bounded",
    "atomicity",
    "quality",
];

/// Canonical policy-result field order.
pub const POLICY_RESULT_FIELDS: [&str; 8] = [
    "rule_id",
    "scope_id",
    "result",
    "evidence_ids",
    "missing_sources",
    "exceptions_applied",
    "clock_domain",
    "reason",
];

/// Canonical comparison-result field order.
pub const COMPARISON_RESULT_FIELDS: [&str; 10] = [
    "metric_id",
    "compatibility",
    "reason",
    "left_evidence",
    "right_evidence",
    "delta",
    "delta_reason",
    "unit",
    "scope",
    "quality",
];

/// Required comparison-result keys; the delta pair is conditional.
pub const COMPARISON_RESULT_REQUIRED: [&str; 8] = [
    "metric_id",
    "compatibility",
    "reason",
    "left_evidence",
    "right_evidence",
    "unit",
    "scope",
    "quality",
];

/// Canonical observed-window field order.
pub const WINDOW_FIELDS: [&str; 2] = ["start_ns", "end_ns"];

/// Canonical observed-interval field order.
pub const OBSERVED_INTERVAL_FIELDS: [&str; 3] = ["start", "end", "uncertainty"];

/// Canonical record-quality channel order.
pub const QUALITY_FIELDS: [&str; 5] = ["detail", "aggregate", "identity", "baseline", "terminal"];

/// Canonical quality-channel field order.
pub const CHANNEL_FIELDS: [&str; 2] = ["status", "loss_count"];

/// Canonical uncertainty field order.
pub const UNCERTAINTY_FIELDS: [&str; 4] = [
    "alias_unknown",
    "reuse_unknown",
    "loss_unknown",
    "events_missed",
];

/// Canonical expected-boundary field order.
pub const BOUNDARY_FIELDS: [&str; 2] = ["boundary_type", "reference"];

/// Keys that may carry a present null; reason pairing stays with the
/// record validator.
const NULLABLE_KEYS: [&str; 5] = [
    "parent_operation_id",
    "object_token",
    "native_result",
    "delta",
    "loss_count",
];

/// Field leaves carrying bare signed integers.
const I64_LEAVES: [&str; 2] = ["native_result", "delta"];

/// Field leaves carrying bare booleans.
const BOOL_LEAVES: [&str; 5] = [
    "bounded",
    "alias_unknown",
    "reuse_unknown",
    "loss_unknown",
    "events_missed",
];

/// Fields carrying arrays of strings; every other array is refused.
const STRING_ARRAY_KEYS: [&str; 4] = [
    "evidence_ids",
    "missing_sources",
    "exceptions_applied",
    "state_evidence",
];

/// Field leaves carrying canonical u64 decimal strings.
const U64_LEAVES: [&str; 16] = [
    "seq",
    "ts_ns",
    "epoch",
    "generation",
    "offset",
    "length_bytes",
    "start",
    "end",
    "uncertainty",
    "start_ns",
    "end_ns",
    "start_time",
    "end_time",
    "visited",
    "returned",
    "loss_count",
];

/// True for a canonical u64 decimal string within range.
pub fn is_canonical_u64(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 20 {
        return false;
    }
    if raw.len() > 1 && raw[0] == b'0' {
        return false;
    }
    let mut acc: u64 = 0;
    for byte in raw {
        if !byte.is_ascii_digit() {
            return false;
        }
        let digit = u64::from(byte - b'0');
        if acc > (u64::MAX - digit) / 10 {
            return false;
        }
        acc = acc * 10 + digit;
    }
    true
}

/// One record encoding failure naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError {
    /// Field or check that failed.
    pub what: String,
    /// Machine-stable reason.
    pub message: String,
}

impl RecordError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "RecordError(what={}, message={})",
            self.what, self.message
        )
    }
}

impl std::error::Error for RecordError {}

/// One seal verification failure naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealError {
    /// Field or check that failed.
    pub what: String,
    /// Machine-stable reason.
    pub message: String,
}

impl SealError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealError(what={}, message={})", self.what, self.message)
    }
}

impl std::error::Error for SealError {}

/// A canonical field value for the generic record encoder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue<'a> {
    /// Quoted text with canonical escapes.
    Text(&'a str),
    /// Bare signed integer.
    Int(i64),
    /// Quoted canonical u64 decimal string.
    UInt(u64),
    /// Bare boolean.
    Bool(bool),
    /// Bare null.
    Null,
    /// Nested object in caller order; keys must be unique.
    Object(Vec<(&'a str, FieldValue<'a>)>),
    /// Array in order.
    Array(Vec<FieldValue<'a>>),
}

fn hex_lo(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}

/// Append one canonically quoted string: short escapes for the seven
/// named controls, `\u00XX` for the rest, raw UTF-8 otherwise.
fn quote_into(out: &mut Vec<u8>, text: &str) {
    out.push(b'"');
    for byte in text.bytes() {
        if byte >= 0x20 && byte != b'"' && byte != b'\\' {
            out.push(byte);
            continue;
        }
        out.push(b'\\');
        match byte {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            0x08 => out.push(b'b'),
            0x09 => out.push(b't'),
            0x0A => out.push(b'n'),
            0x0C => out.push(b'f'),
            0x0D => out.push(b'r'),
            _ => {
                out.extend_from_slice(b"u00");
                out.push(hex_lo(byte >> 4));
                out.push(hex_lo(byte & 15));
            }
        }
    }
    out.push(b'"');
}

fn render_fields(fields: &[(&str, FieldValue)], out: &mut Vec<u8>) -> Result<(), RecordError> {
    let mut seen: Vec<&str> = Vec::new();
    out.push(b'{');
    for (index, (key, value)) in fields.iter().enumerate() {
        if seen.contains(key) {
            return Err(RecordError::new(*key, "duplicate key"));
        }
        seen.push(key);
        if index > 0 {
            out.push(b',');
        }
        quote_into(out, key);
        out.push(b':');
        render_value(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

fn render_value(value: &FieldValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    match value {
        FieldValue::Text(text) => quote_into(out, text),
        FieldValue::Int(number) => out.extend_from_slice(number.to_string().as_bytes()),
        FieldValue::UInt(number) => {
            out.push(b'"');
            out.extend_from_slice(number.to_string().as_bytes());
            out.push(b'"');
        }
        FieldValue::Bool(true) => out.extend_from_slice(b"true"),
        FieldValue::Bool(false) => out.extend_from_slice(b"false"),
        FieldValue::Null => out.extend_from_slice(b"null"),
        FieldValue::Object(fields) => render_fields(fields, out)?,
        FieldValue::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                render_value(item, out)?;
            }
            out.push(b']');
        }
    }
    Ok(())
}

/// Render one canonical record object from caller-ordered fields.
///
/// Duplicate keys are refused. Callers pass the module's field-order
/// tables; the normalizer proves the output parses back byte-equal.
pub fn render_canonical(fields: &[(&str, FieldValue)]) -> Result<String, RecordError> {
    let mut out = Vec::new();
    render_fields(fields, &mut out)?;
    String::from_utf8(out).map_err(|_| RecordError::new("record", "invalid text"))
}

/// Nesting cap shared with the durable capture bounds.
const MAX_DEPTH: usize = 64;

/// One parsed JSON value with object order preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonValue {
    /// Unescaped text.
    Str(String),
    /// Validated bare integer text.
    Num(String),
    /// Bare boolean.
    Bool(bool),
    /// Bare null.
    Null,
    /// Array items in order.
    Array(Vec<JsonValue>),
    /// Object fields in encounter order; keys are unique.
    Object(Vec<(String, JsonValue)>),
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(text: &'a str) -> Self {
        Self {
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect(&mut self, byte: u8, what: &str) -> Result<(), RecordError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(RecordError::new(what, "unexpected byte"))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, RecordError> {
        if depth > MAX_DEPTH {
            return Err(RecordError::new("record", "too deep"));
        }
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.parse_object(depth),
            Some(b'[') => self.parse_array(depth),
            Some(b'"') => Ok(JsonValue::Str(self.parse_string()?)),
            Some(byte) if byte == b'-' || byte.is_ascii_digit() => {
                Ok(JsonValue::Num(self.parse_integer()?))
            }
            Some(b't') => self.parse_literal("true", JsonValue::Bool(true)),
            Some(b'f') => self.parse_literal("false", JsonValue::Bool(false)),
            Some(b'n') => self.parse_literal("null", JsonValue::Null),
            _ => Err(RecordError::new("record", "unexpected byte")),
        }
    }

    fn parse_literal(&mut self, word: &str, value: JsonValue) -> Result<JsonValue, RecordError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(RecordError::new("record", "unexpected byte"))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, RecordError> {
        self.expect(b'{', "record")?;
        let mut fields: Vec<(String, JsonValue)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(RecordError::new("record", "expected key"));
            }
            let key = self.parse_string()?;
            if fields.iter().any(|(seen, _)| *seen == key) {
                return Err(RecordError::new(key, "duplicate key"));
            }
            self.skip_ws();
            self.expect(b':', "record")?;
            let value = self.parse_value(depth + 1)?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(fields));
                }
                _ => return Err(RecordError::new("record", "unexpected byte")),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, RecordError> {
        self.expect(b'[', "record")?;
        let mut items: Vec<JsonValue> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(JsonValue::Array(items));
        }
        loop {
            items.push(self.parse_value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(JsonValue::Array(items));
                }
                _ => return Err(RecordError::new("record", "unexpected byte")),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, RecordError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(RecordError::new("string", "bad escape"));
        }
        let mut unit: u32 = 0;
        for offset in 0..4 {
            let digit = self.bytes[self.pos + offset];
            let value = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a') + 10,
                b'A'..=b'F' => u32::from(digit - b'A') + 10,
                _ => return Err(RecordError::new("string", "bad escape")),
            };
            unit = unit * 16 + value;
        }
        self.pos += 4;
        Ok(unit)
    }

    fn parse_string(&mut self) -> Result<String, RecordError> {
        self.expect(b'"', "string")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| RecordError::new("string", "unterminated"))?;
            self.pos += 1;
            match byte {
                b'"' => {
                    return String::from_utf8(out)
                        .map_err(|_| RecordError::new("string", "invalid text"));
                }
                b'\\' => {
                    let escape = self
                        .peek()
                        .ok_or_else(|| RecordError::new("string", "unterminated"))?;
                    self.pos += 1;
                    match escape {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(0x08),
                        b'f' => out.push(0x0C),
                        b'n' => out.push(0x0A),
                        b'r' => out.push(0x0D),
                        b't' => out.push(0x09),
                        b'u' => {
                            let unit = self.parse_hex4()?;
                            let point = if (0xD800..0xDC00).contains(&unit) {
                                if self.peek() == Some(b'\\')
                                    && self.bytes.get(self.pos + 1) == Some(&b'u')
                                {
                                    self.pos += 2;
                                    let low = self.parse_hex4()?;
                                    if !(0xDC00..0xE000).contains(&low) {
                                        return Err(RecordError::new("string", "bad escape"));
                                    }
                                    0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                                } else {
                                    return Err(RecordError::new("string", "lone surrogate"));
                                }
                            } else if (0xDC00..0xE000).contains(&unit) {
                                return Err(RecordError::new("string", "lone surrogate"));
                            } else {
                                unit
                            };
                            let glyph = char::from_u32(point)
                                .ok_or_else(|| RecordError::new("string", "bad escape"))?;
                            let mut encoded = [0u8; 4];
                            out.extend_from_slice(glyph.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return Err(RecordError::new("string", "bad escape")),
                    }
                }
                0x00..=0x1F => return Err(RecordError::new("string", "raw control")),
                _ => out.push(byte),
            }
        }
    }

    fn parse_integer(&mut self) -> Result<String, RecordError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        let digits = self.pos;
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else if matches!(self.peek(), Some(b'1'..=b'9')) {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        } else {
            return Err(RecordError::new("number", "bad integer"));
        }
        if self.pos == digits || matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(RecordError::new("number", "non-integer number"));
        }
        let text = &self.bytes[start..self.pos];
        let rendered =
            std::str::from_utf8(text).map_err(|_| RecordError::new("number", "bad integer"))?;
        let number: i64 = rendered
            .parse()
            .map_err(|_| RecordError::new("number", "integer overflow"))?;
        Ok(number.to_string())
    }
}

/// Parse one JSON value and require end of input.
fn parse_value(text: &str) -> Result<JsonValue, RecordError> {
    let mut parser = Parser::new(text);
    let value = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.peek().is_some() {
        return Err(RecordError::new("record", "trailing bytes"));
    }
    Ok(value)
}

fn find_field<'v>(fields: &'v [(String, JsonValue)], key: &str) -> Option<&'v JsonValue> {
    fields
        .iter()
        .find(|(seen, _)| seen == key)
        .map(|(_, value)| value)
}

fn check_keys(
    fields: &[(String, JsonValue)],
    order: &[&str],
    required: &[&str],
    what: &str,
) -> Result<(), RecordError> {
    for key in required {
        if find_field(fields, key).is_none() {
            return Err(RecordError::new(what, "missing field"));
        }
    }
    for (key, _) in fields {
        if !order.contains(&key.as_str()) {
            return Err(RecordError::new(key.clone(), "unknown field"));
        }
    }
    Ok(())
}

fn render_scalar(key: &str, value: &JsonValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    match value {
        JsonValue::Str(text) => {
            if U64_LEAVES.contains(&key) {
                if !is_canonical_u64(text) {
                    return Err(RecordError::new(key, "non-canonical u64"));
                }
            } else if I64_LEAVES.contains(&key) || BOOL_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "unexpected string"));
            }
            quote_into(out, text);
            Ok(())
        }
        JsonValue::Num(number) => {
            if U64_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "non-canonical u64"));
            }
            if !I64_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "unexpected number"));
            }
            out.extend_from_slice(number.as_bytes());
            Ok(())
        }
        JsonValue::Bool(true) => {
            if !BOOL_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "unexpected boolean"));
            }
            out.extend_from_slice(b"true");
            Ok(())
        }
        JsonValue::Bool(false) => {
            if !BOOL_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "unexpected boolean"));
            }
            out.extend_from_slice(b"false");
            Ok(())
        }
        JsonValue::Null => {
            if NULLABLE_KEYS.contains(&key) {
                out.extend_from_slice(b"null");
                Ok(())
            } else {
                Err(RecordError::new(key, "unexpected null"))
            }
        }
        JsonValue::Array(_) | JsonValue::Object(_) => {
            Err(RecordError::new(key, "unexpected composite"))
        }
    }
}

fn render_array(key: &str, items: &[JsonValue], out: &mut Vec<u8>) -> Result<(), RecordError> {
    out.push(b'[');
    for (index, item) in items.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        match item {
            JsonValue::Str(text) => quote_into(out, text),
            _ => return Err(RecordError::new(key, "unexpected array item")),
        }
    }
    out.push(b']');
    Ok(())
}

fn render_shaped_object(
    key: &str,
    value: &JsonValue,
    order: &[&str],
    out: &mut Vec<u8>,
) -> Result<(), RecordError> {
    let JsonValue::Object(fields) = value else {
        return Err(RecordError::new(key, "expected object"));
    };
    check_keys(fields, order, order, key)?;
    // Nested shaped objects hold scalar leaves only; routing them
    // through the top-level field dispatch would confuse same-named
    // keys such as the interval uncertainty with the object one.
    out.push(b'{');
    let mut first = true;
    for leaf in order {
        let Some(value) = find_field(fields, leaf) else {
            continue;
        };
        if !first {
            out.push(b',');
        }
        first = false;
        quote_into(out, leaf);
        out.push(b':');
        render_scalar(leaf, value, out)?;
    }
    out.push(b'}');
    Ok(())
}

/// Counter maps canonicalize by sorted counter name.
fn render_counts(key: &str, value: &JsonValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    let JsonValue::Object(fields) = value else {
        return Err(RecordError::new(key, "expected object"));
    };
    let mut names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
    names.sort_unstable();
    out.push(b'{');
    for (index, name) in names.iter().enumerate() {
        let Some(JsonValue::Str(text)) = find_field(fields, name) else {
            return Err(RecordError::new(key, "counter must be a decimal string"));
        };
        if !is_canonical_u64(text) {
            return Err(RecordError::new(key, "non-canonical u64"));
        }
        if index > 0 {
            out.push(b',');
        }
        quote_into(out, name);
        out.push(b':');
        quote_into(out, text);
    }
    out.push(b'}');
    Ok(())
}

fn render_quality(key: &str, value: &JsonValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    let JsonValue::Object(channels) = value else {
        return Err(RecordError::new(key, "expected object"));
    };
    check_keys(channels, &QUALITY_FIELDS, &QUALITY_FIELDS, key)?;
    out.push(b'{');
    for (index, channel) in QUALITY_FIELDS.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        quote_into(out, channel);
        out.push(b':');
        let Some(node) = find_field(channels, channel) else {
            return Err(RecordError::new(*channel, "missing channel"));
        };
        render_shaped_object(channel, node, &CHANNEL_FIELDS, out)?;
    }
    out.push(b'}');
    Ok(())
}

fn render_field(key: &str, value: &JsonValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    match key {
        "window" => render_shaped_object(key, value, &WINDOW_FIELDS, out),
        "observed_interval" => render_shaped_object(key, value, &OBSERVED_INTERVAL_FIELDS, out),
        "quality" => render_quality(key, value, out),
        "uncertainty" => render_shaped_object(key, value, &UNCERTAINTY_FIELDS, out),
        "expected_boundary" => render_shaped_object(key, value, &BOUNDARY_FIELDS, out),
        "source" => render_shaped_object(key, value, &SOURCE_FIELDS, out),
        "counts" => render_counts(key, value, out),
        _ => match value {
            JsonValue::Array(items) if STRING_ARRAY_KEYS.contains(&key) => {
                render_array(key, items, out)
            }
            JsonValue::Array(_) => Err(RecordError::new(key, "unexpected composite")),
            JsonValue::Object(_) => Err(RecordError::new(key, "no canonical order")),
            // Array fields never render as scalars: a bare string
            // is a mistyped record, not a one-element array.
            _ if STRING_ARRAY_KEYS.contains(&key) => Err(RecordError::new(key, "expected array")),
            _ => render_scalar(key, value, out),
        },
    }
}

fn render_ordered(
    fields: &[(String, JsonValue)],
    order: &[&str],
    out: &mut Vec<u8>,
) -> Result<(), RecordError> {
    out.push(b'{');
    let mut first = true;
    for key in order {
        let Some(value) = find_field(fields, key) else {
            continue;
        };
        if !first {
            out.push(b',');
        }
        first = false;
        quote_into(out, key);
        out.push(b':');
        render_field(key, value, out)?;
    }
    out.push(b'}');
    Ok(())
}

fn render_fact_data(data: &JsonValue, out: &mut Vec<u8>) -> Result<(), RecordError> {
    let JsonValue::Object(fields) = data else {
        return Err(RecordError::new("data", "expected object"));
    };
    check_keys(
        fields,
        &EXPOSURE_FACT_FIELDS,
        &EXPOSURE_FACT_REQUIRED,
        "data",
    )?;
    render_ordered(fields, &EXPOSURE_FACT_FIELDS, out)
}

/// Normalize one record to canonical bytes.
///
/// The record shape is detected from its key set: the event envelope
/// or one of the six exposure shapes. Unknown shapes, unknown fields
/// and shapes without a canonical order are refused, never passed
/// through. Normalization is idempotent: normalizing canonical bytes
/// returns them unchanged.
pub fn normalize_record(text: &str) -> Result<String, RecordError> {
    let value = parse_value(text)?;
    let JsonValue::Object(fields) = &value else {
        return Err(RecordError::new("record", "expected object"));
    };
    let keys: Vec<&str> = fields.iter().map(|(key, _)| key.as_str()).collect();
    let matches = |required: &[&str], full: &[&str]| {
        required.iter().all(|key| keys.contains(key)) && keys.iter().all(|key| full.contains(key))
    };
    let mut out = Vec::new();
    if matches(&ENVELOPE_FIELDS, &ENVELOPE_FIELDS) {
        let Some(JsonValue::Str(version)) = find_field(fields, "schema_version") else {
            return Err(RecordError::new("schema_version", "expected string"));
        };
        if version != "0.3.0" {
            return Err(RecordError::new("schema_version", "unsupported version"));
        }
        let Some(JsonValue::Str(kind)) = find_field(fields, "kind") else {
            return Err(RecordError::new("kind", "expected string"));
        };
        if kind != EXPOSURE_FACT_KIND {
            return Err(RecordError::new("kind", "no canonical order"));
        }
        out.push(b'{');
        for (index, key) in ENVELOPE_FIELDS.iter().enumerate() {
            if index > 0 {
                out.push(b',');
            }
            quote_into(&mut out, key);
            out.push(b':');
            let Some(value) = find_field(fields, key) else {
                return Err(RecordError::new(*key, "missing field"));
            };
            if *key == "data" {
                render_fact_data(value, &mut out)?;
            } else {
                render_field(key, value, &mut out)?;
            }
        }
        out.push(b'}');
    } else if matches(&EXPOSURE_FACT_REQUIRED, &EXPOSURE_FACT_FIELDS) {
        check_keys(
            fields,
            &EXPOSURE_FACT_FIELDS,
            &EXPOSURE_FACT_REQUIRED,
            "record",
        )?;
        render_ordered(fields, &EXPOSURE_FACT_FIELDS, &mut out)?;
    } else if matches(&COVERAGE_SOURCE_FIELDS, &COVERAGE_SOURCE_FIELDS) {
        render_ordered(fields, &COVERAGE_SOURCE_FIELDS, &mut out)?;
    } else if matches(&EXPOSURE_OBJECT_REQUIRED, &EXPOSURE_OBJECT_FIELDS) {
        check_keys(
            fields,
            &EXPOSURE_OBJECT_FIELDS,
            &EXPOSURE_OBJECT_REQUIRED,
            "record",
        )?;
        render_ordered(fields, &EXPOSURE_OBJECT_FIELDS, &mut out)?;
    } else if matches(&BASELINE_SAMPLE_FIELDS, &BASELINE_SAMPLE_FIELDS) {
        render_ordered(fields, &BASELINE_SAMPLE_FIELDS, &mut out)?;
    } else if matches(&POLICY_RESULT_FIELDS, &POLICY_RESULT_FIELDS) {
        render_ordered(fields, &POLICY_RESULT_FIELDS, &mut out)?;
    } else if matches(&COMPARISON_RESULT_REQUIRED, &COMPARISON_RESULT_FIELDS) {
        check_keys(
            fields,
            &COMPARISON_RESULT_FIELDS,
            &COMPARISON_RESULT_REQUIRED,
            "record",
        )?;
        render_ordered(fields, &COMPARISON_RESULT_FIELDS, &mut out)?;
    } else {
        return Err(RecordError::new("record", "unknown record shape"));
    }
    String::from_utf8(out).map_err(|_| RecordError::new("record", "invalid text"))
}

fn sha256_block(state: &mut [u32; 8], block: &[u8]) {
    #[rustfmt::skip]
    const K: [u32; 64] = [
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
        0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
        0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
        0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
        0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
        0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
        0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
        0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
        0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
    ];
    let mut w = [0u32; 64];
    for (index, slot) in w.iter_mut().enumerate().take(16) {
        let o = 4 * index;
        *slot = (u32::from(block[o]) << 24)
            | (u32::from(block[o + 1]) << 16)
            | (u32::from(block[o + 2]) << 8)
            | u32::from(block[o + 3]);
    }
    for index in 16..64 {
        let s0 =
            w[index - 15].rotate_right(7) ^ w[index - 15].rotate_right(18) ^ (w[index - 15] >> 3);
        let s1 =
            w[index - 2].rotate_right(17) ^ w[index - 2].rotate_right(19) ^ (w[index - 2] >> 10);
        w[index] = w[index - 16]
            .wrapping_add(s0)
            .wrapping_add(w[index - 7])
            .wrapping_add(s1);
    }
    let (mut a, mut b, mut c, mut d) = (state[0], state[1], state[2], state[3]);
    let (mut e, mut f, mut g, mut h) = (state[4], state[5], state[6], state[7]);
    for index in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[index])
            .wrapping_add(w[index]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// SHA-256 digest of `data` as 64 lowercase hex characters.
fn sha256_hex(data: &[u8]) -> String {
    let mut state = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB,
        0x5BE0CD19,
    ];
    let mut offset = 0;
    while offset + 64 <= data.len() {
        sha256_block(&mut state, &data[offset..offset + 64]);
        offset += 64;
    }
    let mut tail: Vec<u8> = data[offset..].to_vec();
    tail.push(0x80);
    while tail.len() % 64 != 56 {
        tail.push(0);
    }
    let bits = (data.len() as u64).wrapping_mul(8);
    for index in 0..8 {
        tail.push((bits >> (8 * (7 - index))) as u8);
    }
    for offset in (0..tail.len()).step_by(64) {
        sha256_block(&mut state, &tail[offset..offset + 64]);
    }
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for word in state {
        for shift in [24, 16, 8, 0] {
            let byte = (word >> shift) as u8;
            out.push(DIGITS[(byte >> 4) as usize] as char);
            out.push(DIGITS[(byte & 15) as usize] as char);
        }
    }
    out
}

/// Committed-byte seal over one sealed record stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntegritySeal {
    /// Committed stream bytes.
    pub bytes: u64,
    /// Committed line count.
    pub lines: u64,
    /// Committed first sequence; `None` for the empty stream.
    pub first: Option<u64>,
    /// Committed last sequence; `None` for the empty stream.
    pub last: Option<u64>,
    /// Lowercase hex SHA-256 over the literal stream bytes.
    pub digest: String,
    /// Per-kind line counts.
    pub kinds: Vec<(String, u64)>,
}

fn seal_u64(fields: &[(String, JsonValue)], key: &str) -> Result<u64, SealError> {
    let Some(JsonValue::Str(text)) = find_field(fields, key) else {
        return Err(SealError::new(key, "expected decimal string"));
    };
    if !is_canonical_u64(text) {
        return Err(SealError::new(key, "non-canonical u64"));
    }
    text.parse::<u64>()
        .map_err(|_| SealError::new(key, "non-canonical u64"))
}

fn seal_seq(fields: &[(String, JsonValue)], key: &str) -> Result<Option<u64>, SealError> {
    match find_field(fields, key) {
        None | Some(JsonValue::Null) => Ok(None),
        Some(JsonValue::Str(text)) => {
            if !is_canonical_u64(text) {
                return Err(SealError::new(key, "non-canonical u64"));
            }
            text.parse::<u64>()
                .map(Some)
                .map_err(|_| SealError::new(key, "non-canonical u64"))
        }
        Some(_) => Err(SealError::new(key, "expected decimal string or null")),
    }
}

/// Parse one integrity seal object following the 0.1.4 integrity rules.
///
/// The kinds table carries the ten legacy kinds, plus the
/// `exposure_fact` extension key for 0.3.0 streams; anything else is
/// refused. Structural self-consistency is checked; callers still
/// verify the digest over the literal bytes.
pub fn parse_integrity_seal(text: &str) -> Result<IntegritySeal, SealError> {
    let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
    let JsonValue::Object(fields) = &value else {
        return Err(SealError::new("integrity", "expected object"));
    };
    for key in INTEGRITY_KEYS {
        if find_field(fields, key).is_none() {
            return Err(SealError::new("integrity", "missing field"));
        }
    }
    for (key, _) in fields {
        if !INTEGRITY_KEYS.contains(&key.as_str()) {
            return Err(SealError::new("integrity", "unknown field"));
        }
    }
    let Some(JsonValue::Str(algorithm)) = find_field(fields, "algorithm") else {
        return Err(SealError::new("algorithm", "expected string"));
    };
    if algorithm != "sha256" {
        return Err(SealError::new("algorithm", "unsupported algorithm"));
    }
    let bytes = seal_u64(fields, "events_bytes")?;
    let lines = seal_u64(fields, "line_count")?;
    let first = seal_seq(fields, "first_seq")?;
    let last = seal_seq(fields, "last_seq")?;
    if first.is_none() != last.is_none() {
        return Err(SealError::new("integrity", "mismatched sequence bounds"));
    }
    let Some(JsonValue::Str(digest)) = find_field(fields, "events_sha256") else {
        return Err(SealError::new("events_sha256", "expected string"));
    };
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SealError::new("events_sha256", "bad digest"));
    }
    let Some(JsonValue::Object(kinds)) = find_field(fields, "kinds") else {
        return Err(SealError::new("kinds", "expected object"));
    };
    let mut table: Vec<(String, u64)> = Vec::new();
    for name in LEGACY_KINDS {
        let Some(JsonValue::Str(text)) = find_field(kinds, name) else {
            return Err(SealError::new("kinds", "missing kind"));
        };
        if !is_canonical_u64(text) {
            return Err(SealError::new("kinds", "non-canonical u64"));
        }
        let count = text
            .parse::<u64>()
            .map_err(|_| SealError::new("kinds", "non-canonical u64"))?;
        table.push((name.to_string(), count));
    }
    if let Some(extra) = find_field(kinds, EXPOSURE_FACT_KIND) {
        let JsonValue::Str(text) = extra else {
            return Err(SealError::new("kinds", "expected decimal string"));
        };
        if !is_canonical_u64(text) {
            return Err(SealError::new("kinds", "non-canonical u64"));
        }
        let count = text
            .parse::<u64>()
            .map_err(|_| SealError::new("kinds", "non-canonical u64"))?;
        table.push((EXPOSURE_FACT_KIND.to_string(), count));
    }
    if kinds.len() != table.len() {
        return Err(SealError::new("kinds", "unknown kind"));
    }
    let mut total: u64 = 0;
    for (_, count) in &table {
        total = total
            .checked_add(*count)
            .ok_or_else(|| SealError::new("kinds", "overflow"))?;
    }
    if total != lines {
        return Err(SealError::new("kinds", "sum differs from line_count"));
    }
    if lines == 0 {
        if first.is_some() || bytes != 0 || digest != EMPTY_SHA256 {
            return Err(SealError::new("integrity", "invalid empty stream"));
        }
    } else if first != Some(0) || last != Some(lines - 1) || bytes < lines {
        return Err(SealError::new(
            "integrity",
            "invalid sequence bounds or byte count",
        ));
    }
    Ok(IntegritySeal {
        bytes,
        lines,
        first,
        last,
        digest: digest.clone(),
        kinds: table,
    })
}

/// Identity of one exposure-fact line, when well-formed.
///
/// Returns `None` for lines without a usable evidence identity;
/// callers fail closed rather than dropping evidence silently.
fn fact_identity(text: &str) -> Option<SealedEvidenceKey> {
    let value = parse_value(text).ok()?;
    let JsonValue::Object(fields) = &value else {
        return None;
    };
    let JsonValue::Str(kind) = find_field(fields, "kind")? else {
        return None;
    };
    if kind != EXPOSURE_FACT_KIND {
        return None;
    }
    let JsonValue::Object(data) = find_field(fields, "data")? else {
        return None;
    };
    let JsonValue::Str(evidence_id) = find_field(data, "evidence_id")? else {
        return None;
    };
    let JsonValue::Str(source_id) = find_field(data, "source_id")? else {
        return None;
    };
    let JsonValue::Str(epoch) = find_field(data, "epoch")? else {
        return None;
    };
    if !is_canonical_u64(epoch) {
        return None;
    }
    let epoch = epoch.parse::<u64>().ok()?;
    Some(SealedEvidenceKey {
        evidence_id: evidence_id.clone(),
        source_id: source_id.clone(),
        epoch,
    })
}

/// True when one fact line validates completely at the seal boundary.
///
/// The whole line must normalize (canonical envelope, field order,
/// scalar types and canonical numerics), its envelope source must
/// carry frozen labels, and its data must build an
/// [`exposure_shapes::ExposureFact`] passing the model validator:
/// peer-class and source membership, interval order, quality-channel
/// statuses, maybe/reason pairing, closed enum sets and identifier
/// shapes. Well-typed-but-unknown labels fail the seal exactly like
/// a malformed field: the seal verifies false rather than admitting
/// them as verdict evidence. Membership reuses the model validator's
/// frozen tables, never a copy.
fn fact_sealed_valid(text: &str) -> bool {
    if normalize_record(text).is_err() {
        return false;
    }
    let Ok(JsonValue::Object(fields)) = parse_value(text) else {
        return false;
    };
    if !source_labels_valid(&fields) {
        return false;
    }
    let Some(JsonValue::Object(data)) = find_field(&fields, "data") else {
        return false;
    };
    fact_from_data(data).is_some_and(|fact| fact.validate().is_ok())
}

/// True when the envelope source block keeps its schema shape.
///
/// The hook, backend and profile leaves stay within their schema
/// bounds; the measurement and correlation leaves come from the
/// model's frozen tables, never a copy.
fn source_labels_valid(fields: &[(String, JsonValue)]) -> bool {
    let Some(JsonValue::Object(source)) = find_field(fields, "source") else {
        return false;
    };
    for (leaf, limit) in SOURCE_BOUNDS {
        let Some(JsonValue::Str(text)) = find_field(source, leaf) else {
            return false;
        };
        if !is_sized_text(text, limit) {
            return false;
        }
    }
    let Some(JsonValue::Str(measurement)) = find_field(source, "measurement") else {
        return false;
    };
    let Some(JsonValue::Str(correlation)) = find_field(source, "correlation") else {
        return false;
    };
    exposure_shapes::is_measurement(measurement) && exposure_shapes::is_correlation(correlation)
}

/// True for a non-empty string within its schema bound.
///
/// Length counts characters, like the schema's `maxLength`, not bytes.
fn is_sized_text(value: &str, limit: usize) -> bool {
    !value.is_empty() && value.chars().count() <= limit
}

/// True for a canonical u64 decimal string leaf.
fn is_u64_value(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Str(text) if is_canonical_u64(text))
}

/// True for a bounded opaque identifier leaf.
fn is_opaque_value(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Str(text) if exposure_shapes::is_opaque_id(text))
}

/// True for a bare JSON integer leaf.
///
/// The parser already canonicalizes bare integers to i64 text, so
/// any parsed number qualifies; anything beyond i64 never parses.
fn is_bare_int_value(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Num(_))
}

/// True for a null leaf or one passing the value check.
fn is_null_or(value: &JsonValue, check: fn(&JsonValue) -> bool) -> bool {
    matches!(value, JsonValue::Null) || check(value)
}

/// True when the object carries exactly the required keys.
///
/// Object keys are unique by parse, so required presence plus the
/// length match admits nothing unknown.
fn exact_keys(data: &[(String, JsonValue)], required: &[&str]) -> bool {
    data.len() == required.len() && required.iter().all(|key| find_field(data, key).is_some())
}

/// True when the required keys are present and nothing unknown rides along.
fn shaped_keys(data: &[(String, JsonValue)], required: &[&str], allowed: &[&str]) -> bool {
    required.iter().all(|key| find_field(data, key).is_some())
        && data.iter().all(|(key, _)| allowed.contains(&key.as_str()))
}

/// True when a legacy observer context keeps its schema shape.
///
/// The relation is fixed; cpu, pid, tgid, comm and cgroup_id are
/// optional bounded leaves. Only legacy lines carry one.
fn observer_context_valid(value: &JsonValue) -> bool {
    const LEAVES: [&str; 6] = ["cpu", "pid", "tgid", "comm", "cgroup_id", "relation"];
    let JsonValue::Object(context) = value else {
        return false;
    };
    for (key, _) in context {
        if !LEAVES.contains(&key.as_str()) {
            return false;
        }
    }
    let Some(JsonValue::Str(relation)) = find_field(context, "relation") else {
        return false;
    };
    if relation != "execution_context_only" {
        return false;
    }
    for (leaf, limit) in [
        ("cpu", 1_048_575_i64),
        ("pid", 4_194_304),
        ("tgid", 4_194_304),
    ] {
        if let Some(value) = find_field(context, leaf) {
            let JsonValue::Num(text) = value else {
                return false;
            };
            let Ok(number) = text.parse::<i64>() else {
                return false;
            };
            if !(0..=limit).contains(&number) {
                return false;
            }
        }
    }
    if let Some(value) = find_field(context, "comm") {
        let JsonValue::Str(comm) = value else {
            return false;
        };
        if comm.chars().count() > 64 {
            return false;
        }
    }
    if let Some(value) = find_field(context, "cgroup_id")
        && !is_opaque_value(value)
    {
        return false;
    }
    true
}

fn sealed_str<'v>(data: &'v [(String, JsonValue)], key: &str) -> Option<&'v str> {
    match find_field(data, key) {
        Some(JsonValue::Str(text)) => Some(text.as_str()),
        _ => None,
    }
}

fn sealed_u64(data: &[(String, JsonValue)], key: &str) -> Option<u64> {
    let text = sealed_str(data, key)?;
    if !is_canonical_u64(text) {
        return None;
    }
    text.parse::<u64>().ok()
}

/// One maybe/absent leaf with its typed reason, or `None` when mistyped.
///
/// An absent reason key and an explicit empty reason differ: only
/// the absent key decodes to no reason. An explicit empty string is
/// neither absent nor a typed reason, so it fails the seal rather
/// than decoding as if the key were omitted.
fn sealed_maybe(
    data: &[(String, JsonValue)],
    base: &str,
) -> Option<exposure_shapes::Maybe<String>> {
    let reason_key = format!("{base}_reason");
    let reason = match find_field(data, reason_key.as_str()) {
        None => String::new(),
        Some(JsonValue::Str(text)) if text.is_empty() => return None,
        Some(JsonValue::Str(text)) => text.clone(),
        Some(_) => return None,
    };
    match find_field(data, base) {
        None => Some(exposure_shapes::Maybe {
            present: false,
            value: None,
            reason,
        }),
        Some(JsonValue::Str(text)) => Some(exposure_shapes::Maybe {
            present: true,
            value: Some(text.clone()),
            reason,
        }),
        Some(JsonValue::Null) => Some(exposure_shapes::Maybe {
            present: true,
            value: None,
            reason,
        }),
        Some(_) => None,
    }
}

fn sealed_interval(data: &[(String, JsonValue)]) -> Option<(u64, u64, u64)> {
    let Some(JsonValue::Object(leaves)) = find_field(data, "observed_interval") else {
        return None;
    };
    Some((
        sealed_u64(leaves, "start")?,
        sealed_u64(leaves, "end")?,
        sealed_u64(leaves, "uncertainty")?,
    ))
}

/// One native result with its typed reason, or `None` when mistyped.
///
/// As with [`sealed_maybe`], an explicit empty reason is neither
/// absent nor typed, so it fails the seal.
fn sealed_native(data: &[(String, JsonValue)]) -> Option<(Option<i64>, String)> {
    let reason = match find_field(data, "native_result_reason") {
        None => String::new(),
        Some(JsonValue::Str(text)) if text.is_empty() => return None,
        Some(JsonValue::Str(text)) => text.clone(),
        Some(_) => return None,
    };
    let value = match find_field(data, "native_result") {
        // Bare integers parsed as i64 already; the re-parse only
        // converts the validated text and fails closed on drift.
        Some(JsonValue::Num(text)) => Some(text.parse::<i64>().ok()?),
        Some(JsonValue::Null) => None,
        _ => return None,
    };
    Some((value, reason))
}

fn sealed_quality(data: &[(String, JsonValue)]) -> Option<exposure_shapes::Quality> {
    let Some(JsonValue::Object(channels)) = find_field(data, "quality") else {
        return None;
    };
    let mut built: Vec<exposure_shapes::ChannelQuality> = Vec::with_capacity(5);
    for channel in exposure_shapes::CHANNELS {
        let node = find_field(channels, channel)?;
        let JsonValue::Object(leaves) = node else {
            return None;
        };
        let Some(JsonValue::Str(status)) = find_field(leaves, "status") else {
            return None;
        };
        let loss = match find_field(leaves, "loss_count") {
            Some(JsonValue::Null) => None,
            Some(JsonValue::Str(text)) if is_canonical_u64(text) => Some(text.parse::<u64>().ok()?),
            _ => return None,
        };
        built.push(exposure_shapes::ChannelQuality {
            status: status.clone(),
            loss,
        });
    }
    built.try_into().ok()
}

/// Build one [`exposure_shapes::ExposureFact`] from sealed line data.
///
/// Returns `None` for any shape the normalizer passed but the model
/// cannot take; callers fail closed rather than guessing a value.
fn fact_from_data(data: &[(String, JsonValue)]) -> Option<exposure_shapes::ExposureFact> {
    let (observed_start, observed_end, observed_uncertainty) = sealed_interval(data)?;
    let (native_result, native_result_reason) = sealed_native(data)?;
    Some(exposure_shapes::ExposureFact {
        evidence_id: sealed_str(data, "evidence_id")?.to_string(),
        source_id: sealed_str(data, "source_id")?.to_string(),
        epoch: sealed_u64(data, "epoch")?,
        operation_id: sealed_str(data, "operation_id")?.to_string(),
        parent_operation_id: sealed_maybe(data, "parent_operation_id")?,
        kind: sealed_str(data, "kind")?.to_string(),
        direction: sealed_str(data, "direction")?.to_string(),
        object_token: sealed_maybe(data, "object_token")?,
        generation: sealed_u64(data, "generation")?,
        offset: sealed_u64(data, "offset")?,
        length_bytes: sealed_u64(data, "length_bytes")?,
        native_result,
        native_result_reason,
        caller_class: sealed_str(data, "caller_class")?.to_string(),
        peer_class: sealed_str(data, "peer_class")?.to_string(),
        clock_domain: sealed_str(data, "clock_domain")?.to_string(),
        observed_start,
        observed_end,
        observed_uncertainty,
        semantics: sealed_str(data, "semantics")?.to_string(),
        quality: sealed_quality(data)?,
    })
}

/// True when one event envelope keeps its canonical shape.
///
/// The seven envelope keys are present with nothing unknown, except
/// that a legacy line may carry a validated observer context; the
/// version is the session's contract, the timestamp is a canonical
/// u64, and the source carries its five string leaves within their
/// bounds with frozen labels. Sequence and session checks stay with
/// the seal loop, as with facts; the caller owns kind membership.
fn event_envelope_valid(fields: &[(String, JsonValue)], contract: SealContract) -> bool {
    match contract {
        SealContract::Exposure => {
            if fields.len() != ENVELOPE_FIELDS.len() {
                return false;
            }
            for key in ENVELOPE_FIELDS {
                if find_field(fields, key).is_none() {
                    return false;
                }
            }
            let Some(JsonValue::Str(version)) = find_field(fields, "schema_version") else {
                return false;
            };
            if version != EXPOSURE_LINE_VERSION {
                return false;
            }
        }
        SealContract::Legacy => {
            let Some(JsonValue::Str(version)) = find_field(fields, "schema_version") else {
                return false;
            };
            if !LEGACY_LINE_VERSIONS.contains(&version.as_str()) {
                return false;
            }
            for key in ENVELOPE_FIELDS {
                if find_field(fields, key).is_none() {
                    return false;
                }
            }
            for (key, _) in fields {
                if key != "observer_context" && !ENVELOPE_FIELDS.contains(&key.as_str()) {
                    return false;
                }
            }
            if let Some(context) = find_field(fields, "observer_context")
                && !observer_context_valid(context)
            {
                return false;
            }
        }
    }
    if !matches!(find_field(fields, "session_id"), Some(JsonValue::Str(_))) {
        return false;
    }
    let Some(JsonValue::Str(ts_ns)) = find_field(fields, "ts_ns") else {
        return false;
    };
    if !is_canonical_u64(ts_ns) {
        return false;
    }
    if !matches!(find_field(fields, "kind"), Some(JsonValue::Str(_))) {
        return false;
    }
    let Some(JsonValue::Object(source)) = find_field(fields, "source") else {
        return false;
    };
    if source.len() != SOURCE_FIELDS.len() {
        return false;
    }
    for key in SOURCE_FIELDS {
        if !matches!(find_field(source, key), Some(JsonValue::Str(_))) {
            return false;
        }
    }
    source_labels_valid(fields)
}

/// True when a bounce-attempt payload keeps its schema shape.
///
/// The payload carries exactly the four schema leaves: two opaque
/// identifiers, a canonical byte count, and a bare flag.
fn bounce_payload_valid(data: &[(String, JsonValue)]) -> bool {
    if data.len() != 4 {
        return false;
    }
    let Some(JsonValue::Str(device)) = find_field(data, "device_id") else {
        return false;
    };
    let Some(JsonValue::Str(bytes)) = find_field(data, "requested_bytes") else {
        return false;
    };
    if !matches!(find_field(data, "forced"), Some(JsonValue::Bool(_))) {
        return false;
    }
    let Some(JsonValue::Str(operation)) = find_field(data, "operation_id") else {
        return false;
    };
    exposure_shapes::is_opaque_id(device)
        && is_canonical_u64(bytes)
        && exposure_shapes::is_opaque_id(operation)
}

/// True when a map-result payload keeps its schema shape.
fn map_result_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 7] = [
        "operation_id",
        "success",
        "mapping_id",
        "return_code",
        "mapped_bytes",
        "wire_generation",
        "wire_identity",
    ];
    if !exact_keys(data, &REQUIRED) {
        return false;
    }
    let Some(operation) = find_field(data, "operation_id") else {
        return false;
    };
    if !is_opaque_value(operation) {
        return false;
    }
    let success = match find_field(data, "success") {
        Some(JsonValue::Bool(flag)) => *flag,
        _ => return false,
    };
    let Some(mapping) = find_field(data, "mapping_id") else {
        return false;
    };
    if !is_null_or(mapping, is_opaque_value) {
        return false;
    }
    let Some(native) = find_field(data, "return_code") else {
        return false;
    };
    if !is_null_or(native, is_bare_int_value) {
        return false;
    }
    let Some(mapped) = find_field(data, "mapped_bytes") else {
        return false;
    };
    if !is_null_or(mapped, is_u64_value) {
        return false;
    }
    let Some(generation) = find_field(data, "wire_generation") else {
        return false;
    };
    if !is_null_or(generation, is_u64_value) {
        return false;
    }
    let Some(identity) = find_field(data, "wire_identity") else {
        return false;
    };
    if !matches!(identity, JsonValue::Null)
        && !matches!(identity, JsonValue::Str(text) if text == "known" || text == "unassigned")
    {
        return false;
    }
    let unassigned = matches!(identity, JsonValue::Str(text) if text == "unassigned");
    if success && !unassigned && (!is_opaque_value(mapping) || !is_u64_value(mapped)) {
        return false;
    }
    if success && unassigned && (!matches!(mapping, JsonValue::Null) || !is_u64_value(mapped)) {
        return false;
    }
    if !success
        && (!matches!(mapping, JsonValue::Null)
            || !matches!(mapped, JsonValue::Null)
            || !matches!(identity, JsonValue::Null))
    {
        return false;
    }
    if matches!(generation, JsonValue::Null) && !matches!(identity, JsonValue::Null) {
        return false;
    }
    if matches!(identity, JsonValue::Null)
        && !matches!(generation, JsonValue::Null)
        && (success || !matches!(generation, JsonValue::Str(text) if text == "0"))
    {
        return false;
    }
    true
}

/// True when an unmap payload keeps its schema shape.
fn unmap_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 3] = ["mapping_id", "wire_generation", "wire_identity"];
    if !exact_keys(data, &REQUIRED) {
        return false;
    }
    let Some(mapping) = find_field(data, "mapping_id") else {
        return false;
    };
    if !is_null_or(mapping, is_opaque_value) {
        return false;
    }
    let Some(generation) = find_field(data, "wire_generation") else {
        return false;
    };
    if !is_null_or(generation, is_u64_value) {
        return false;
    }
    let Some(identity) = find_field(data, "wire_identity") else {
        return false;
    };
    if !matches!(identity, JsonValue::Null)
        && !matches!(identity, JsonValue::Str(text) if text == "known" || text == "miss")
    {
        return false;
    }
    if matches!(generation, JsonValue::Null) && !matches!(identity, JsonValue::Null) {
        return false;
    }
    if matches!(identity, JsonValue::Null) && !matches!(generation, JsonValue::Null) {
        return false;
    }
    if matches!(mapping, JsonValue::Null)
        && !matches!(identity, JsonValue::Str(text) if text == "miss")
    {
        return false;
    }
    true
}

/// True when a copy payload keeps its schema shape.
///
/// Copies require observed measurement. The pool-private and
/// offset flags exist from line version 0.1.2 on; a 0.1.1 copy
/// carrying them refuses.
fn copy_valid(
    data: &[(String, JsonValue)],
    source: &[(String, JsonValue)],
    line_version: &str,
) -> bool {
    const BASE: [&str; 4] = ["operation_id", "mapping_id", "direction", "bytes"];
    const EXTENDED: [&str; 6] = [
        "operation_id",
        "mapping_id",
        "direction",
        "bytes",
        "pool_private",
        "offset_past_allocation",
    ];
    let allowed: &[&str] = if line_version == "0.1.1" {
        &BASE
    } else {
        &EXTENDED
    };
    if !shaped_keys(data, &BASE, allowed) {
        return false;
    }
    if !matches!(find_field(source, "measurement"), Some(JsonValue::Str(text)) if text == "observed")
    {
        return false;
    }
    let Some(operation) = find_field(data, "operation_id") else {
        return false;
    };
    if !is_opaque_value(operation) {
        return false;
    }
    let Some(mapping) = find_field(data, "mapping_id") else {
        return false;
    };
    if !is_null_or(mapping, is_opaque_value) {
        return false;
    }
    let Some(direction) = find_field(data, "direction") else {
        return false;
    };
    if !matches!(direction, JsonValue::Str(text) if text == "original_to_bounce" || text == "bounce_to_original")
    {
        return false;
    }
    let Some(bytes) = find_field(data, "bytes") else {
        return false;
    };
    if !is_u64_value(bytes) {
        return false;
    }
    for flag in ["pool_private", "offset_past_allocation"] {
        if let Some(value) = find_field(data, flag)
            && !matches!(value, JsonValue::Bool(true))
        {
            return false;
        }
    }
    true
}

/// True when a sync-request payload keeps its schema shape.
fn sync_request_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 5] = [
        "operation_id",
        "mapping_id",
        "offset_known",
        "offset",
        "length",
    ];
    if !exact_keys(data, &REQUIRED) {
        return false;
    }
    let Some(operation) = find_field(data, "operation_id") else {
        return false;
    };
    if !is_opaque_value(operation) {
        return false;
    }
    let Some(mapping) = find_field(data, "mapping_id") else {
        return false;
    };
    if !is_null_or(mapping, is_opaque_value) {
        return false;
    }
    let known = match find_field(data, "offset_known") {
        Some(JsonValue::Bool(flag)) => *flag,
        _ => return false,
    };
    let Some(offset) = find_field(data, "offset") else {
        return false;
    };
    if !is_null_or(offset, is_u64_value) {
        return false;
    }
    let Some(length) = find_field(data, "length") else {
        return false;
    };
    if !is_u64_value(length) {
        return false;
    }
    if known && !is_u64_value(offset) {
        return false;
    }
    if !known && !matches!(offset, JsonValue::Null) {
        return false;
    }
    true
}

/// True when a transition-result payload keeps its schema shape.
fn transition_result_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 6] = [
        "region_id",
        "requested_state",
        "success",
        "return_code",
        "offset",
        "length",
    ];
    const ALLOWED: [&str; 9] = [
        "region_id",
        "requested_state",
        "success",
        "return_code",
        "offset",
        "length",
        "address_space",
        "resolution",
        "generation",
    ];
    if !shaped_keys(data, &REQUIRED, &ALLOWED) {
        return false;
    }
    let Some(region) = find_field(data, "region_id") else {
        return false;
    };
    if !is_opaque_value(region) {
        return false;
    }
    let Some(state) = find_field(data, "requested_state") else {
        return false;
    };
    if !matches!(state, JsonValue::Str(text) if text == "shared" || text == "private") {
        return false;
    }
    if !matches!(find_field(data, "success"), Some(JsonValue::Bool(_))) {
        return false;
    }
    let Some(native) = find_field(data, "return_code") else {
        return false;
    };
    if !is_null_or(native, is_bare_int_value) {
        return false;
    }
    let Some(offset) = find_field(data, "offset") else {
        return false;
    };
    if !is_u64_value(offset) {
        return false;
    }
    let Some(length) = find_field(data, "length") else {
        return false;
    };
    if !is_u64_value(length) {
        return false;
    }
    if let Some(space) = find_field(data, "address_space")
        && !matches!(space, JsonValue::Str(text)
            if text == "guest_physical"
                || text == "kernel_virtual"
                || text == "iova"
                || text == "identity_only")
    {
        return false;
    }
    if let Some(resolution) = find_field(data, "resolution")
        && !matches!(resolution, JsonValue::Str(text) if text == "resolved" || text == "unresolved")
    {
        return false;
    }
    if let Some(value) = find_field(data, "generation") {
        let JsonValue::Num(text) = value else {
            return false;
        };
        let Ok(number) = text.parse::<i64>() else {
            return false;
        };
        if number < 1 {
            return false;
        }
    }
    true
}

/// True when a pool-sample payload keeps its schema shape.
fn pool_sample_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 4] = ["pool_id", "used_bytes", "capacity_bytes", "unit"];
    const ALLOWED: [&str; 8] = [
        "pool_id",
        "used_bytes",
        "capacity_bytes",
        "unit",
        "allocator",
        "unit_bytes",
        "hiwater_bytes",
        "reason",
    ];
    if !shaped_keys(data, &REQUIRED, &ALLOWED) {
        return false;
    }
    let Some(pool) = find_field(data, "pool_id") else {
        return false;
    };
    if !is_opaque_value(pool) {
        return false;
    }
    for leaf in ["used_bytes", "capacity_bytes"] {
        let Some(value) = find_field(data, leaf) else {
            return false;
        };
        if !is_null_or(value, is_u64_value) {
            return false;
        }
    }
    let Some(unit) = find_field(data, "unit") else {
        return false;
    };
    if !matches!(unit, JsonValue::Str(text) if text == "bytes" || text == "unknown") {
        return false;
    }
    if let Some(allocator) = find_field(data, "allocator")
        && !is_opaque_value(allocator)
    {
        return false;
    }
    if let Some(unit_bytes) = find_field(data, "unit_bytes")
        && !is_u64_value(unit_bytes)
    {
        return false;
    }
    if let Some(hiwater) = find_field(data, "hiwater_bytes")
        && !is_null_or(hiwater, is_u64_value)
    {
        return false;
    }
    if let Some(reason) = find_field(data, "reason")
        && !matches!(reason, JsonValue::Str(text)
            if text == "denied" || text == "absent" || text == "unparseable")
    {
        return false;
    }
    true
}

/// True when a gap payload keeps its schema shape.
fn gap_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 5] = [
        "channel",
        "lost_count",
        "reason",
        "window_start_ns",
        "window_end_ns",
    ];
    if !exact_keys(data, &REQUIRED) {
        return false;
    }
    let Some(channel) = find_field(data, "channel") else {
        return false;
    };
    if !matches!(channel, JsonValue::Str(text)
        if text == "detail"
            || text == "aggregate"
            || text == "correlation"
            || text == "baseline"
            || text == "terminal")
    {
        return false;
    }
    let Some(lost) = find_field(data, "lost_count") else {
        return false;
    };
    if !is_null_or(lost, is_u64_value) {
        return false;
    }
    let Some(reason) = find_field(data, "reason") else {
        return false;
    };
    if !matches!(reason, JsonValue::Str(text) if is_sized_text(text, 512)) {
        return false;
    }
    let Some(start) = find_field(data, "window_start_ns") else {
        return false;
    };
    if !is_u64_value(start) {
        return false;
    }
    let Some(end) = find_field(data, "window_end_ns") else {
        return false;
    };
    is_u64_value(end)
}

/// True when a counter-snapshot payload keeps its schema shape.
fn counter_snapshot_valid(data: &[(String, JsonValue)]) -> bool {
    const REQUIRED: [&str; 5] = ["counter_id", "epoch", "scope", "value", "unit"];
    if !exact_keys(data, &REQUIRED) {
        return false;
    }
    let Some(counter) = find_field(data, "counter_id") else {
        return false;
    };
    if !matches!(counter, JsonValue::Str(text) if is_sized_text(text, 128)) {
        return false;
    }
    let Some(epoch) = find_field(data, "epoch") else {
        return false;
    };
    if !is_u64_value(epoch) {
        return false;
    }
    let Some(scope_value) = find_field(data, "scope") else {
        return false;
    };
    let JsonValue::Object(scope) = scope_value else {
        return false;
    };
    if !shaped_keys(scope, &["profile_id"], &["device_id", "profile_id"]) {
        return false;
    }
    if let Some(device) = find_field(scope, "device_id")
        && !is_null_or(device, is_opaque_value)
    {
        return false;
    }
    let Some(profile) = find_field(scope, "profile_id") else {
        return false;
    };
    if !matches!(profile, JsonValue::Str(text) if is_sized_text(text, 128)) {
        return false;
    }
    let Some(value) = find_field(data, "value") else {
        return false;
    };
    if !is_u64_value(value) {
        return false;
    }
    let Some(unit) = find_field(data, "unit") else {
        return false;
    };
    matches!(unit, JsonValue::Str(text) if is_sized_text(text, 32))
}

/// True when a legacy payload keeps its per-kind schema shape.
///
/// Every legacy kind carries exactly its schema leaves; a copy
/// additionally requires observed measurement, and its two toggle
/// flags exist from line version 0.1.2 on. Mirrors the event
/// schemas and the oracle.
fn legacy_payload_valid(
    kind: &str,
    data: &[(String, JsonValue)],
    source: &[(String, JsonValue)],
    line_version: &str,
) -> bool {
    match kind {
        "marker" => {
            if !exact_keys(data, &["text"]) {
                return false;
            }
            let Some(JsonValue::Str(annotation)) = find_field(data, "text") else {
                return false;
            };
            is_sized_text(annotation, 256)
        }
        "bounce_attempt" => bounce_payload_valid(data),
        "map_result" => map_result_valid(data),
        "unmap" => unmap_valid(data),
        "copy" => copy_valid(data, source, line_version),
        "sync_request" => sync_request_valid(data),
        "transition_result" => transition_result_valid(data),
        "pool_sample" => pool_sample_valid(data),
        "gap" => gap_valid(data),
        "counter_snapshot" => counter_snapshot_valid(data),
        _ => false,
    }
}

/// True when a non-fact line keeps its envelope payload shape.
///
/// Every event line carries the canonical envelope under the
/// session's contract, so a dropped timestamp, a foreign version,
/// or an unfrozen source label fails the seal rather than
/// verifying. Every line carries an object `data` payload keeping
/// its per-kind schema shape, mirroring the event schemas; a copy
/// additionally requires observed measurement.
fn non_fact_shape_valid(kind: &str, text: &str, contract: SealContract) -> bool {
    let Ok(JsonValue::Object(fields)) = parse_value(text) else {
        return false;
    };
    if !event_envelope_valid(&fields, contract) {
        return false;
    }
    let Some(JsonValue::Object(data)) = find_field(&fields, "data") else {
        return false;
    };
    let Some(JsonValue::Object(source)) = find_field(&fields, "source") else {
        return false;
    };
    let Some(JsonValue::Str(version)) = find_field(&fields, "schema_version") else {
        return false;
    };
    legacy_payload_valid(kind, data, source, version)
}

/// Seal verification outcome over a snapshot's literal bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealReport {
    /// True only when the committed seal matches the literal bytes
    /// and the sealed evidence holds containment.
    pub verified: bool,
    /// Committed stream bytes; zero when unsealed.
    pub bytes: u64,
    /// Committed line count; zero when unsealed.
    pub lines: u64,
}

fn line_identity(line: &str) -> Option<(String, Option<u64>)> {
    let value = parse_value(line).ok()?;
    let JsonValue::Object(fields) = &value else {
        return None;
    };
    let JsonValue::Str(kind) = find_field(fields, "kind")? else {
        return None;
    };
    if !(LEGACY_KINDS.contains(&kind.as_str()) || kind == EXPOSURE_FACT_KIND) {
        return None;
    }
    let seq = match find_field(fields, "seq") {
        Some(JsonValue::Str(text)) if is_canonical_u64(text) => text.parse::<u64>().ok(),
        _ => None,
    };
    Some((kind.clone(), seq))
}

/// Session handle carried by one snapshot line, when well-formed.
fn line_session(line: &str) -> Option<String> {
    let value = parse_value(line).ok()?;
    let JsonValue::Object(fields) = &value else {
        return None;
    };
    match find_field(fields, "session_id") {
        Some(JsonValue::Str(id)) => Some(id.clone()),
        _ => None,
    }
}

/// One coverage identity for the duplicate-source gate.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CoverageKey {
    /// Catalog source entry.
    source: Option<String>,
    /// Observed subject.
    subject: Option<String>,
    /// Collection phase.
    phase: Option<String>,
    /// Window start in nanoseconds.
    window_start: Option<String>,
    /// Window end in nanoseconds.
    window_end: Option<String>,
}

/// Read one coverage entry's (source, subject, phase, window) identity.
///
/// Missing or mistyped leaves decode as `None`, so two entries that
/// both omit a leaf still collide: an unkeyed entry never slips
/// past the gate by being malformed.
fn coverage_key(entry: &JsonValue) -> Option<CoverageKey> {
    let JsonValue::Object(fields) = entry else {
        return None;
    };
    let leaf = |key: &str| match find_field(fields, key) {
        Some(JsonValue::Str(text)) => Some(text.clone()),
        _ => None,
    };
    let (window_start, window_end) = match find_field(fields, "window") {
        Some(JsonValue::Object(window)) => (
            match find_field(window, "start_ns") {
                Some(JsonValue::Str(text)) => Some(text.clone()),
                _ => None,
            },
            match find_field(window, "end_ns") {
                Some(JsonValue::Str(text)) => Some(text.clone()),
                _ => None,
            },
        ),
        _ => (None, None),
    };
    Some(CoverageKey {
        source: leaf("source_id"),
        subject: leaf("subject_id"),
        phase: leaf("phase"),
        window_start,
        window_end,
    })
}

/// True when the session repeats one coverage identity.
///
/// Sessions without an exposure sources array carry no coverage
/// and keep verifying; only a repeated (source, subject, phase,
/// window) refuses, deterministically on every ordering, so
/// conflicting availability never resolves by position.
fn duplicate_coverage(session: &[(String, JsonValue)]) -> bool {
    let Some(JsonValue::Object(exposure)) = find_field(session, "exposure") else {
        return false;
    };
    let Some(JsonValue::Array(sources)) = find_field(exposure, "sources") else {
        return false;
    };
    let mut seen: HashSet<CoverageKey> = HashSet::with_capacity(sources.len());
    for entry in sources {
        let Some(key) = coverage_key(entry) else {
            continue;
        };
        if !seen.insert(key) {
            return true;
        }
    }
    false
}

/// Verify one sealed snapshot: a session object plus its literal lines.
///
/// The snapshot carries `session` with `capture.integrity` and
/// `event_lines` holding the literal line bytes as JSON strings.
/// The session version selects the exposure or legacy line
/// contract; an unknown contract verifies false. Coverage entries
/// repeat no (source, subject, phase, window) identity: a repeated
/// identity verifies false on every ordering, so conflicting
/// availability never resolves by position. Every line ends
/// in a newline, carries its position as its sequence number, and
/// belongs to the snapshot's own session; one entry holds exactly
/// one physical line under the reader's 64 KiB bound. Malformed
/// snapshot framing is an error; a well-formed snapshot whose
/// bytes, counts or kind census differ from the commitment, whose
/// lines stray from the session or their contract, whose fact data
/// fails model validation, whose non-fact payloads lose their
/// shape, or whose fact identities break containment, verifies
/// false. An absent integrity object verifies false, while a
/// present non-object or an unknown integrity field is an error:
/// no unsealed sidecar can supply policy evidence.
pub fn verify_sealed_snapshot(text: &str) -> Result<SealReport, SealError> {
    let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
    let JsonValue::Object(top) = &value else {
        return Err(SealError::new("snapshot", "expected object"));
    };
    let unsealed = SealReport {
        verified: false,
        bytes: 0,
        lines: 0,
    };
    let Some(JsonValue::Object(session)) = find_field(top, "session") else {
        return Err(SealError::new("session", "expected object"));
    };
    let expected_session = match find_field(session, "session_id") {
        Some(JsonValue::Str(id)) => id.as_str(),
        _ => return Err(SealError::new("session_id", "expected string")),
    };
    let contract = session_contract(session);
    let Some(JsonValue::Array(lines)) = find_field(top, "event_lines") else {
        return Err(SealError::new("event_lines", "expected array"));
    };
    let mut literal: Vec<u8> = Vec::new();
    let mut kinds: Vec<String> = Vec::new();
    let mut fact_keys: Vec<SealedEvidenceKey> = Vec::new();
    let mut lines_ok = contract.is_some() && !duplicate_coverage(session);
    let mut contained_ok = true;
    for (position, line) in lines.iter().enumerate() {
        let JsonValue::Str(text) = line else {
            return Err(SealError::new("event_lines", "expected string lines"));
        };
        if !text.ends_with('\n') {
            return Err(SealError::new("event_lines", "missing trailing newline"));
        }
        // One entry is one physical line: split on the terminator
        // exactly like the capture reader and refuse stragglers.
        if text.split('\n').count() != 2 {
            return Err(SealError::new("event_lines", "extra newline"));
        }
        if text.len() > SNAPSHOT_MAX_LINE_BYTES {
            return Err(SealError::new("event_lines", "line too large"));
        }
        literal.extend_from_slice(text.as_bytes());
        match line_identity(text) {
            Some((kind, Some(seq))) if seq == position as u64 => {
                // Every line belongs to the snapshot's own session,
                // mirroring the capture reader's per-event check; a
                // foreign-session line verifies false, never errors.
                if line_session(text).as_deref() != Some(expected_session) {
                    lines_ok = false;
                }
                match contract {
                    Some(SealContract::Exposure) => {
                        if kind == EXPOSURE_FACT_KIND {
                            // Identity alone never admits a fact: the whole
                            // line must normalize and its data must pass the
                            // model validator, like the oracle's field check.
                            match fact_identity(text) {
                                Some(key) if fact_sealed_valid(text) => {
                                    fact_keys.push(key);
                                }
                                _ => contained_ok = false,
                            }
                        } else if !non_fact_shape_valid(&kind, text, SealContract::Exposure) {
                            lines_ok = false;
                        }
                    }
                    Some(SealContract::Legacy) => {
                        // Exposure facts exist only under the exposure
                        // contract; legacy lines keep legacy rules.
                        if kind == EXPOSURE_FACT_KIND
                            || !non_fact_shape_valid(&kind, text, SealContract::Legacy)
                        {
                            lines_ok = false;
                        }
                    }
                    None => {
                        lines_ok = false;
                    }
                }
                kinds.push(kind);
            }
            Some(_) => {
                return Err(SealError::new("event_lines", "sequence mismatch"));
            }
            None => lines_ok = false,
        }
    }
    let Some(JsonValue::Object(capture)) = find_field(session, "capture") else {
        return Err(SealError::new("capture", "expected object"));
    };
    let Some(integrity) = find_field(capture, "integrity") else {
        return Ok(unsealed);
    };
    let JsonValue::Object(fields) = integrity else {
        return Err(SealError::new("integrity", "expected object"));
    };
    for (key, _) in fields {
        if !INTEGRITY_KEYS.contains(&key.as_str()) {
            return Err(SealError::new("integrity", "unknown field"));
        }
    }
    let mut rendered = Vec::new();
    render_ordered_for_seal(fields, &mut rendered)?;
    let seal_text =
        String::from_utf8(rendered).map_err(|_| SealError::new("integrity", "invalid text"))?;
    let seal = parse_integrity_seal(&seal_text)?;
    if !lines_ok {
        return Ok(SealReport {
            verified: false,
            bytes: seal.bytes,
            lines: seal.lines,
        });
    }
    let borrowed: Vec<EvidenceKey<'_>> = fact_keys
        .iter()
        .map(|key| EvidenceKey {
            evidence_id: key.evidence_id.as_str(),
            source_id: key.source_id.as_str(),
            epoch: key.epoch,
        })
        .collect();
    if !contained_ok || check_evidence_keys(&borrowed).is_err() {
        return Ok(SealReport {
            verified: false,
            bytes: seal.bytes,
            lines: seal.lines,
        });
    }
    let mut census_ok = kinds.len() as u64 == seal.lines;
    for (name, count) in &seal.kinds {
        let seen = kinds.iter().filter(|kind| *kind == name).count() as u64;
        if seen != *count {
            census_ok = false;
        }
    }
    let verified = census_ok
        && seal.bytes == literal.len() as u64
        && seal.lines == lines.len() as u64
        && sha256_hex(&literal) == seal.digest;
    Ok(SealReport {
        verified,
        bytes: seal.bytes,
        lines: seal.lines,
    })
}

/// One evidence identity replayed from sealed snapshot lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedEvidenceKey {
    /// Session-unique evidence handle.
    pub evidence_id: String,
    /// Catalog source entry.
    pub source_id: String,
    /// Measurement epoch.
    pub epoch: u64,
}

/// Replay exposure-fact identities from the sealed lines only.
///
/// Lines of other kinds carry no evidence identities and are
/// skipped. Callers check [`verify_sealed_snapshot`] first; replay
/// itself refuses unparseable lines and fact lines without a
/// well-formed identity rather than dropping evidence silently.
pub fn sealed_evidence_keys(text: &str) -> Result<Vec<SealedEvidenceKey>, SealError> {
    let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
    let JsonValue::Object(top) = &value else {
        return Err(SealError::new("snapshot", "expected object"));
    };
    let Some(JsonValue::Array(lines)) = find_field(top, "event_lines") else {
        return Err(SealError::new("event_lines", "expected array"));
    };
    let mut keys = Vec::new();
    for line in lines {
        let JsonValue::Str(text) = line else {
            return Err(SealError::new("event_lines", "expected string lines"));
        };
        let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
        let JsonValue::Object(fields) = &value else {
            return Err(SealError::new("event_lines", "expected object lines"));
        };
        let Some(JsonValue::Str(kind)) = find_field(fields, "kind") else {
            return Err(SealError::new("kind", "expected string"));
        };
        if kind != EXPOSURE_FACT_KIND {
            continue;
        }
        let Some(JsonValue::Object(data)) = find_field(fields, "data") else {
            return Err(SealError::new("data", "expected object"));
        };
        let Some(JsonValue::Str(evidence_id)) = find_field(data, "evidence_id") else {
            return Err(SealError::new("evidence_id", "expected string"));
        };
        let Some(JsonValue::Str(source_id)) = find_field(data, "source_id") else {
            return Err(SealError::new("source_id", "expected string"));
        };
        let Some(JsonValue::Str(epoch)) = find_field(data, "epoch") else {
            return Err(SealError::new("epoch", "expected string"));
        };
        if !is_canonical_u64(epoch) {
            return Err(SealError::new("epoch", "non-canonical u64"));
        }
        let epoch = epoch
            .parse::<u64>()
            .map_err(|_| SealError::new("epoch", "non-canonical u64"))?;
        keys.push(SealedEvidenceKey {
            evidence_id: evidence_id.clone(),
            source_id: source_id.clone(),
            epoch,
        });
    }
    Ok(keys)
}

/// Read the session terminal-channel status from a snapshot.
///
/// The status names the snapshot's own settlement; callers compare
/// it against the settled label rather than assuming it.
pub fn snapshot_terminal_status(text: &str) -> Result<String, SealError> {
    let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
    let JsonValue::Object(top) = &value else {
        return Err(SealError::new("snapshot", "expected object"));
    };
    let Some(JsonValue::Object(session)) = find_field(top, "session") else {
        return Err(SealError::new("session", "expected object"));
    };
    let Some(JsonValue::Object(quality)) = find_field(session, "quality") else {
        return Err(SealError::new("quality", "expected object"));
    };
    let Some(JsonValue::Object(terminal)) = find_field(quality, "terminal") else {
        return Err(SealError::new("terminal", "expected object"));
    };
    let Some(JsonValue::Str(status)) = find_field(terminal, "status") else {
        return Err(SealError::new("terminal", "expected status"));
    };
    Ok(status.clone())
}

/// One required source's verdict inputs read from a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredSourceEvidence {
    /// True when the source id appears in session exposure sources.
    pub present: bool,
    /// Source status; empty when the source is absent.
    pub status: String,
    /// True when at least one quality channel carries usable evidence.
    pub quality_usable: bool,
}

/// Read one required source's status and quality usability.
///
/// The session exposure sources must exist; a missing source id
/// reads as absent rather than erroring. Every row carrying the
/// source id validates fully against the model: catalog
/// membership, capability pairing, identifier shapes, window
/// order, and a quality block of exactly the five exposure
/// channels with frozen statuses and null-or-canonical losses. A
/// row carries usable evidence only when it validates and at
/// least one channel reports a usable status; anything else
/// counts as unusable, failing closed rather than satisfying.
/// Rows for one source combine worst-first: a denied or
/// incomplete row dominates usable ones, and satisfaction needs
/// every row usable, identically in every row order, so
/// conflicting availability never resolves by position. A single
/// row reads exactly its own status and usability. Duplicate
/// coverage never reaches this reader under a verified seal: the
/// seal gate refuses repeated identities first.
pub fn snapshot_source_evidence(
    text: &str,
    source_id: &str,
) -> Result<RequiredSourceEvidence, SealError> {
    let value = parse_value(text).map_err(|err| SealError::new(err.what, err.message))?;
    let JsonValue::Object(top) = &value else {
        return Err(SealError::new("snapshot", "expected object"));
    };
    let Some(JsonValue::Object(session)) = find_field(top, "session") else {
        return Err(SealError::new("session", "expected object"));
    };
    let Some(JsonValue::Object(exposure)) = find_field(session, "exposure") else {
        return Err(SealError::new("exposure", "expected object"));
    };
    let Some(JsonValue::Array(sources)) = find_field(exposure, "sources") else {
        return Err(SealError::new("sources", "expected array"));
    };
    let absent = RequiredSourceEvidence {
        present: false,
        status: String::new(),
        quality_usable: false,
    };
    let mut worst: Option<(u8, String, bool)> = None;
    for entry in sources {
        let JsonValue::Object(fields) = entry else {
            continue;
        };
        let Some(JsonValue::Str(id)) = find_field(fields, "source_id") else {
            continue;
        };
        if id != source_id {
            continue;
        }
        let Some(JsonValue::Str(status)) = find_field(fields, "status") else {
            return Err(SealError::new("status", "expected string"));
        };
        let usable = coverage_usable(fields);
        let candidate = (evidence_rank(status, usable), status.clone(), usable);
        if worst.as_ref().is_none_or(|current| candidate < *current) {
            worst = Some(candidate);
        }
    }
    match worst {
        Some((_, status, usable)) => Ok(RequiredSourceEvidence {
            present: true,
            status,
            quality_usable: usable,
        }),
        None => Ok(absent),
    }
}

/// Build one [`exposure_shapes::CoverageSource`] from a coverage entry.
///
/// Returns `None` for any shape the model cannot take: a missing
/// or mistyped leaf, a window that is not two canonical counts,
/// or a quality block that is not exactly the five exposure
/// channels with exactly a status and a loss count each. Callers
/// fail closed rather than guessing a value.
fn coverage_from_entry(fields: &[(String, JsonValue)]) -> Option<exposure_shapes::CoverageSource> {
    let Some(JsonValue::Object(window)) = find_field(fields, "window") else {
        return None;
    };
    let start_ns = sealed_u64(window, "start_ns")?;
    let end_ns = sealed_u64(window, "end_ns")?;
    let Some(JsonValue::Object(quality)) = find_field(fields, "quality") else {
        return None;
    };
    if !exact_keys(quality, &exposure_shapes::CHANNELS) {
        return None;
    }
    for (_, node) in quality {
        let JsonValue::Object(leaves) = node else {
            return None;
        };
        if !exact_keys(leaves, &["status", "loss_count"]) {
            return None;
        }
    }
    Some(exposure_shapes::CoverageSource {
        source_id: sealed_str(fields, "source_id")?.to_string(),
        capability: sealed_str(fields, "capability")?.to_string(),
        profile_id: sealed_str(fields, "profile_id")?.to_string(),
        subject_id: sealed_str(fields, "subject_id")?.to_string(),
        platform_cell: sealed_str(fields, "platform_cell")?.to_string(),
        address_namespace: sealed_str(fields, "address_namespace")?.to_string(),
        phase: sealed_str(fields, "phase")?.to_string(),
        status: sealed_str(fields, "status")?.to_string(),
        reason: sealed_str(fields, "reason")?.to_string(),
        window_start_ns: start_ns,
        window_end_ns: end_ns,
        quality: sealed_quality(fields)?,
    })
}

/// True when a coverage entry validates with a usable quality channel.
///
/// The entry builds a [`exposure_shapes::CoverageSource`] passing
/// the model validator — catalog membership, capability pairing,
/// identifier shapes, window order, and channel statuses — and at
/// least one channel reports a usable status. Anything else counts
/// as unusable, failing closed rather than satisfying. Membership
/// reuses the model validator's frozen tables, never a copy.
fn coverage_usable(fields: &[(String, JsonValue)]) -> bool {
    let Some(coverage) = coverage_from_entry(fields) else {
        return false;
    };
    if coverage.validate().is_err() {
        return false;
    }
    coverage
        .quality
        .iter()
        .any(|channel| channel.status == "complete_for_scope" || channel.status == "partial")
}

/// Worst-first rank for one matching row: absent 0, incomplete 1, complete 2.
///
/// Mirrors the verdict gate's row mapping: an available row carries
/// usable evidence only with a usable channel, a partial row
/// without one is incomplete evidence, anything else is absent.
/// The verdict combines every matching row worst-first, so
/// conflicting rows never resolve by position.
fn evidence_rank(status: &str, usable: bool) -> u8 {
    if status == "available" {
        if usable { 2 } else { 0 }
    } else if status == "partial" {
        if usable { 2 } else { 1 }
    } else {
        0
    }
}

/// Policy file size cap in bytes.
///
/// Mirrors the published policy limits; the contract test pins
/// these values against the owning record definitions.
pub const POLICY_FILE_MAX_BYTES: usize = 1_048_576;
/// Rules per policy file.
pub const POLICY_FILE_MAX_RULES: usize = 1024;
/// Exceptions per rule.
pub const POLICY_FILE_MAX_EXCEPTIONS_PER_RULE: usize = 64;

/// One loaded policy file's bounded counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    /// Rules carried by the file.
    pub rules: usize,
    /// Exceptions carried by the file.
    pub exceptions: usize,
}

/// Load one authored policy file's bytes and enforce its bounds.
///
/// The size cap is checked before parsing. Rules number 1 through
/// 1024, required sources are never empty, and no rule carries more
/// than 64 exceptions. Shapes stay with the policy schema; only the
/// counts and the byte budget are enforced here.
pub fn parse_policy_file(text: &str) -> Result<PolicySummary, RecordError> {
    if text.len() > POLICY_FILE_MAX_BYTES {
        return Err(RecordError::new("policy", "too large"));
    }
    let value = parse_value(text)?;
    let JsonValue::Object(top) = &value else {
        return Err(RecordError::new("policy", "expected object"));
    };
    let Some(JsonValue::Str(schema)) = find_field(top, "schema") else {
        return Err(RecordError::new("schema", "expected string"));
    };
    if schema != "policy" {
        return Err(RecordError::new("schema", "unsupported file"));
    }
    let Some(JsonValue::Str(version)) = find_field(top, "schema_version") else {
        return Err(RecordError::new("schema_version", "expected string"));
    };
    if version != "0.1.0" {
        return Err(RecordError::new("schema_version", "unsupported version"));
    }
    let Some(JsonValue::Array(sources)) = find_field(top, "required_sources") else {
        return Err(RecordError::new("required_sources", "expected array"));
    };
    if sources.is_empty() {
        return Err(RecordError::new("required_sources", "empty scope"));
    }
    let Some(JsonValue::Array(rules)) = find_field(top, "rules") else {
        return Err(RecordError::new("rules", "expected array"));
    };
    if rules.is_empty() || rules.len() > POLICY_FILE_MAX_RULES {
        return Err(RecordError::new("rules", "rule count out of bounds"));
    }
    let Some(JsonValue::Array(exceptions)) = find_field(top, "exceptions") else {
        return Err(RecordError::new("exceptions", "expected array"));
    };
    let mut per_rule: HashMap<&str, usize> = HashMap::with_capacity(exceptions.len());
    for entry in exceptions {
        let JsonValue::Object(fields) = entry else {
            return Err(RecordError::new("exceptions", "expected object entries"));
        };
        let Some(JsonValue::Str(handle)) = find_field(fields, "rule_id") else {
            return Err(RecordError::new("exceptions", "expected rule handle"));
        };
        *per_rule.entry(handle).or_insert(0) += 1;
    }
    for count in per_rule.values() {
        if *count > POLICY_FILE_MAX_EXCEPTIONS_PER_RULE {
            return Err(RecordError::new("exceptions", "too many exceptions"));
        }
    }
    Ok(PolicySummary {
        rules: rules.len(),
        exceptions: exceptions.len(),
    })
}

/// Re-render a parsed integrity object for the seal parser.
fn render_ordered_for_seal(
    fields: &[(String, JsonValue)],
    out: &mut Vec<u8>,
) -> Result<(), SealError> {
    out.push(b'{');
    let mut first = true;
    for key in INTEGRITY_KEYS {
        let Some(value) = find_field(fields, key) else {
            continue;
        };
        if !first {
            out.push(b',');
        }
        first = false;
        quote_into(out, key);
        out.push(b':');
        render_seal_value(value, out)?;
    }
    out.push(b'}');
    Ok(())
}

fn render_seal_value(value: &JsonValue, out: &mut Vec<u8>) -> Result<(), SealError> {
    match value {
        JsonValue::Str(text) => quote_into(out, text),
        JsonValue::Null => out.extend_from_slice(b"null"),
        JsonValue::Object(fields) => {
            out.push(b'{');
            for (index, (key, item)) in fields.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                quote_into(out, key);
                out.push(b':');
                render_seal_value(item, out)?;
            }
            out.push(b'}');
        }
        JsonValue::Num(_) | JsonValue::Bool(_) | JsonValue::Array(_) => {
            return Err(SealError::new("integrity", "unexpected value"));
        }
    }
    Ok(())
}

/// One evidence identity for containment checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceKey<'a> {
    /// Session-unique evidence handle.
    pub evidence_id: &'a str,
    /// Catalog source entry.
    pub source_id: &'a str,
    /// Measurement epoch.
    pub epoch: u64,
}

/// Reject reused evidence handles and sources mixed across epochs.
///
/// Every evidence handle appears once per snapshot, and one source
/// contributes to exactly one epoch per snapshot; anything else is
/// refused, never merged. Both checks run in linear time over hash
/// sets, so doubling the snapshot near-doubles the cost.
pub fn check_evidence_keys(keys: &[EvidenceKey]) -> Result<(), RecordError> {
    let mut seen: HashSet<&str> = HashSet::with_capacity(keys.len());
    for key in keys {
        if !seen.insert(key.evidence_id) {
            return Err(RecordError::new("evidence_id", "duplicate evidence"));
        }
    }
    let mut epochs: HashMap<&str, u64> = HashMap::new();
    for key in keys {
        match epochs.entry(key.source_id) {
            Entry::Occupied(prior) if *prior.get() != key.epoch => {
                return Err(RecordError::new("source_id", "cross-epoch evidence"));
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(slot) => {
                slot.insert(key.epoch);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_vectors() {
        assert_eq!(sha256_hex(b""), EMPTY_SHA256);
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let thousand = "a".repeat(1000);
        assert_eq!(
            sha256_hex(thousand.as_bytes()),
            "41edece42d63e8d9bf515a9ba6932e1c20cbc9f5a5d134645adb5db1b9737ea3"
        );
    }

    #[test]
    fn canonical_u64_shapes() {
        assert!(is_canonical_u64("0"));
        assert!(is_canonical_u64("18446744073709551615"));
        assert!(!is_canonical_u64(""));
        assert!(!is_canonical_u64("01"));
        assert!(!is_canonical_u64("18446744073709551616"));
        assert!(!is_canonical_u64("1.0"));
        assert!(!is_canonical_u64("-1"));
        assert!(!is_canonical_u64(" 1"));
    }

    #[test]
    fn encoder_refuses_duplicate_keys() {
        let fields = vec![
            ("a", FieldValue::Bool(true)),
            ("a", FieldValue::Bool(false)),
        ];
        let err = render_canonical(&fields).unwrap_err();
        assert_eq!(err.what, "a");
    }

    #[test]
    fn normalize_refuses_malformed_input() {
        assert!(normalize_record("{\"a\":1}").is_err());
        assert!(normalize_record("not json").is_err());
        assert!(normalize_record("{\"a\":01}").is_err());
        assert!(normalize_record("{\"a\":1.5}").is_err());
        assert!(normalize_record("[1,2]").is_err());
        assert!(normalize_record("{\"metric_id\":\"m\"}").is_err());
        let deep = format!("{}\"x{}", "{\"a\":".repeat(70), "}".repeat(70));
        assert!(normalize_record(&deep).is_err());
    }

    #[test]
    fn normalize_enforces_fact_order_and_scalars() {
        let canonical = render_canonical(&[
            ("evidence_id", FieldValue::Text("ev-1")),
            ("source_id", FieldValue::Text("sharing-census")),
            ("epoch", FieldValue::UInt(7)),
            ("operation_id", FieldValue::Text("op-1")),
            ("kind", FieldValue::Text("census-entry")),
            ("direction", FieldValue::Text("egress")),
            ("generation", FieldValue::UInt(1)),
            ("offset", FieldValue::UInt(0)),
            ("length_bytes", FieldValue::UInt(4096)),
            ("native_result", FieldValue::Int(0)),
            ("caller_class", FieldValue::Text("allocator")),
            ("peer_class", FieldValue::Text("none-observed")),
            ("clock_domain", FieldValue::Text("guest_monotonic_active")),
            (
                "observed_interval",
                FieldValue::Object(vec![
                    ("start", FieldValue::UInt(1)),
                    ("end", FieldValue::UInt(2)),
                    ("uncertainty", FieldValue::UInt(0)),
                ]),
            ),
            ("semantics", FieldValue::Text("inventory")),
            (
                "quality",
                FieldValue::Object(vec![
                    (
                        "detail",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "aggregate",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "identity",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "baseline",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "terminal",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::Null),
                        ]),
                    ),
                ]),
            ),
        ])
        .unwrap();
        assert_eq!(normalize_record(&canonical).unwrap(), canonical);
        let shuffled = canonical
            .replacen(
                "\"evidence_id\":\"ev-1\",\"source_id\":\"sharing-census\"",
                "\"source_id\":\"sharing-census\",\"evidence_id\":\"ev-1\"",
                1,
            )
            .replacen(
                "\"start\":\"1\",\"end\":\"2\"",
                "\"end\":\"2\",\"start\":\"1\"",
                1,
            );
        assert_eq!(normalize_record(&shuffled).unwrap(), canonical);
        let bad_u64 = canonical.replacen("\"epoch\":\"7\"", "\"epoch\":\"07\"", 1);
        assert!(normalize_record(&bad_u64).is_err());
        let missing = canonical.replacen("\"semantics\":\"inventory\",", "", 1);
        assert!(normalize_record(&missing).is_err());
    }

    #[test]
    fn normalize_refuses_bare_integer_u64() {
        let canonical =
            include_str!("../../tests/exposure/fixtures/contracts/replay_canonical.json");
        assert!(normalize_record(canonical.trim_end()).is_ok());
        let bare = canonical.replacen("\"epoch\":\"7\"", "\"epoch\":7", 1);
        assert_ne!(bare, canonical);
        let err = normalize_record(bare.trim_end()).unwrap_err();
        assert_eq!(err.what, "epoch");
        assert_eq!(err.message, "non-canonical u64");
        let nested = canonical.replacen("\"uncertainty\":\"50\"", "\"uncertainty\":50", 1);
        assert_ne!(nested, canonical);
        let err = normalize_record(nested.trim_end()).unwrap_err();
        assert_eq!(err.what, "uncertainty");
        assert_eq!(err.message, "non-canonical u64");
    }

    #[test]
    fn normalize_refuses_non_canonical_scalar_types() {
        let canonical =
            include_str!("../../tests/exposure/fixtures/contracts/replay_canonical.json");
        assert!(normalize_record(canonical.trim_end()).is_ok());
        let cases = [
            ("\"epoch\":\"7\"", "\"epoch\":true", "epoch"),
            ("\"epoch\":\"7\"", "\"epoch\":[7]", "epoch"),
            ("\"epoch\":\"7\"", "\"epoch\":null", "epoch"),
            (
                "\"evidence_id\":\"ev-9\"",
                "\"evidence_id\":7",
                "evidence_id",
            ),
            (
                "\"evidence_id\":\"ev-9\"",
                "\"evidence_id\":true",
                "evidence_id",
            ),
            (
                "\"native_result\":0",
                "\"native_result\":\"0\"",
                "native_result",
            ),
            (
                "\"native_result\":0",
                "\"native_result\":[0]",
                "native_result",
            ),
            (
                "\"uncertainty\":\"50\"",
                "\"uncertainty\":false",
                "uncertainty",
            ),
        ];
        for (from, to, what) in cases {
            let bad = canonical.replacen(from, to, 1);
            assert_ne!(bad, canonical, "mutation {to}");
            let err = normalize_record(bad.trim_end()).unwrap_err();
            assert_eq!(err.what, what, "mutation {to}");
        }
        let policy = render_canonical(&[
            ("rule_id", FieldValue::Text("no-unexpected-queue")),
            ("scope_id", FieldValue::Text("virtio-queues")),
            ("result", FieldValue::Text("conforms")),
            (
                "evidence_ids",
                FieldValue::Array(vec![FieldValue::Text("ev-1")]),
            ),
            ("missing_sources", FieldValue::Array(vec![])),
            ("exceptions_applied", FieldValue::Array(vec![])),
            ("clock_domain", FieldValue::Text("guest_monotonic_active")),
            ("reason", FieldValue::Text("quiet ledger.")),
        ])
        .unwrap();
        assert_eq!(normalize_record(&policy).unwrap(), policy);
        for to in [
            "\"evidence_ids\":[7]",
            "\"evidence_ids\":[null]",
            "\"evidence_ids\":[\"ev-1\",[\"ev-2\"]]",
        ] {
            let bad = policy.replacen("\"evidence_ids\":[\"ev-1\"]", to, 1);
            assert_ne!(bad, policy, "mutation {to}");
            let err = normalize_record(&bad).unwrap_err();
            assert_eq!(err.what, "evidence_ids", "mutation {to}");
        }
    }

    #[test]
    fn normalize_refuses_scalar_strings_in_array_fields() {
        let policy = render_canonical(&[
            ("rule_id", FieldValue::Text("r")),
            ("scope_id", FieldValue::Text("s")),
            ("result", FieldValue::Text("conforms")),
            (
                "evidence_ids",
                FieldValue::Array(vec![FieldValue::Text("ev-1")]),
            ),
            ("missing_sources", FieldValue::Array(vec![])),
            ("exceptions_applied", FieldValue::Array(vec![])),
            ("clock_domain", FieldValue::Text("guest_monotonic_active")),
            ("reason", FieldValue::Text("quiet")),
        ])
        .unwrap();
        assert_eq!(normalize_record(&policy).unwrap(), policy);
        for (from, to, what) in [
            (
                "\"evidence_ids\":[\"ev-1\"]",
                "\"evidence_ids\":\"ev-1\"",
                "evidence_ids",
            ),
            (
                "\"missing_sources\":[]",
                "\"missing_sources\":\"sharing-census\"",
                "missing_sources",
            ),
            (
                "\"exceptions_applied\":[]",
                "\"exceptions_applied\":\"r\"",
                "exceptions_applied",
            ),
        ] {
            let bad = policy.replacen(from, to, 1);
            assert_ne!(bad, policy, "mutation {to}");
            let err = normalize_record(&bad).unwrap_err();
            assert_eq!(err.what, what, "mutation {to}");
            assert_eq!(err.message, "expected array", "mutation {to}");
        }
        let object = "{\"object_token\":\"tok-1\",\"generation\":\"1\",\
            \"object_class\":\"buffer\",\"namespace\":\"session_token\",\
            \"origin_source\":\"heap-dmabuf-objects\",\"lifecycle_status\":\"live\",\
            \"state\":\"shared\",\"state_evidence\":[\"ev-1\"],\
            \"uncertainty\":{\"alias_unknown\":false,\
            \"reuse_unknown\":false,\"loss_unknown\":false,\"events_missed\":false}}";
        assert_eq!(normalize_record(object).unwrap(), object);
        let bad = object.replacen(
            "\"state_evidence\":[\"ev-1\"]",
            "\"state_evidence\":\"ev-1\"",
            1,
        );
        assert_ne!(bad, object);
        let err = normalize_record(&bad).unwrap_err();
        assert_eq!(err.what, "state_evidence");
        assert_eq!(err.message, "expected array");
    }

    #[test]
    fn normalize_keeps_boolean_and_object_shapes() {
        let channel = "{\"status\":\"complete_for_scope\",\"loss_count\":\"0\"}";
        let quality = format!(
            "{{\"detail\":{channel},\"aggregate\":{channel},\"identity\":{channel},\
            \"baseline\":{channel},\"terminal\":{channel}}}"
        );
        let sample = format!(
            "{{\"sample_id\":\"sample-1\",\"source_id\":\"sharing-census\",\
            \"start_time\":\"1\",\"end_time\":\"2\",\"scope\":\"direct-map\",\
            \"counts\":{{\"apple\":\"1\"}},\"units\":\"bytes\",\"visited\":\"4\",\
            \"returned\":\"2\",\"bounded\":false,\"atomicity\":\"interval\",\
            \"quality\":{quality}}}"
        );
        assert_eq!(normalize_record(&sample).unwrap(), sample);
        let bad_sample = sample.replacen("\"bounded\":false", "\"bounded\":\"false\"", 1);
        assert_ne!(bad_sample, sample);
        let err = normalize_record(&bad_sample).unwrap_err();
        assert_eq!(err.what, "bounded");
        let object = "{\"object_token\":\"tok-1\",\"generation\":\"1\",\
            \"object_class\":\"buffer\",\"namespace\":\"session_token\",\
            \"origin_source\":\"heap-dmabuf-objects\",\"lifecycle_status\":\"live\",\
            \"state\":\"shared\",\"state_evidence\":[\"ev-1\"],\
            \"expected_boundary\":{\"boundary_type\":\"revert_boundary\",\
            \"reference\":\"release\"},\"uncertainty\":{\"alias_unknown\":false,\
            \"reuse_unknown\":false,\"loss_unknown\":false,\"events_missed\":false}}";
        assert_eq!(normalize_record(object).unwrap(), object);
        let bad_object = object.replacen("\"alias_unknown\":false", "\"alias_unknown\":\"no\"", 1);
        assert_ne!(bad_object, object);
        let err = normalize_record(&bad_object).unwrap_err();
        assert_eq!(err.what, "alias_unknown");
    }

    #[test]
    fn counts_sort_by_counter_name() {
        let sample = render_canonical(&[
            ("sample_id", FieldValue::Text("sample-1")),
            ("source_id", FieldValue::Text("sharing-census")),
            ("start_time", FieldValue::UInt(1)),
            ("end_time", FieldValue::UInt(2)),
            ("scope", FieldValue::Text("direct-map")),
            (
                "counts",
                FieldValue::Object(vec![
                    ("zebra", FieldValue::Text("2")),
                    ("apple", FieldValue::Text("1")),
                ]),
            ),
            ("units", FieldValue::Text("bytes")),
            ("visited", FieldValue::UInt(4)),
            ("returned", FieldValue::UInt(2)),
            ("bounded", FieldValue::Bool(false)),
            ("atomicity", FieldValue::Text("interval")),
            (
                "quality",
                FieldValue::Object(vec![
                    (
                        "detail",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "aggregate",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "identity",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "baseline",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                    (
                        "terminal",
                        FieldValue::Object(vec![
                            ("status", FieldValue::Text("complete_for_scope")),
                            ("loss_count", FieldValue::UInt(0)),
                        ]),
                    ),
                ]),
            ),
        ])
        .unwrap();
        let out = normalize_record(&sample).unwrap();
        assert!(out.contains("\"counts\":{\"apple\":\"1\",\"zebra\":\"2\"}"));
    }

    #[test]
    fn encoder_arrays_normalize_byte_equal() {
        let rendered = render_canonical(&[
            ("rule_id", FieldValue::Text("no-unexpected-queue")),
            ("scope_id", FieldValue::Text("virtio-queues")),
            ("result", FieldValue::Text("conforms")),
            (
                "evidence_ids",
                FieldValue::Array(vec![FieldValue::Text("ev-1")]),
            ),
            ("missing_sources", FieldValue::Array(vec![])),
            ("exceptions_applied", FieldValue::Array(vec![])),
            ("clock_domain", FieldValue::Text("guest_monotonic_active")),
            (
                "reason",
                FieldValue::Text("quiet ledger; next check again."),
            ),
        ])
        .unwrap();
        assert_eq!(normalize_record(&rendered).unwrap(), rendered);
    }

    #[test]
    fn legacy_envelope_has_no_canonical_order() {
        let line = "{\"schema_version\":\"0.3.0\",\"session_id\":\"s\",\"seq\":\"0\",\
            \"ts_ns\":\"1\",\"kind\":\"marker\",\"source\":{\"hook\":\"h\",\"backend\":\"b\",\
            \"profile_id\":\"p\",\"measurement\":\"observed\",\"correlation\":\"direct\"},\
            \"data\":{\"text\":\"note\"}}";
        let err = normalize_record(line).unwrap_err();
        assert_eq!(err.what, "kind");
    }

    #[test]
    fn seal_parses_empty_and_extension_forms() {
        let kinds = "\"bounce_attempt\":\"0\",\"map_result\":\"0\",\"unmap\":\"0\",\"copy\":\"0\",\
            \"sync_request\":\"0\",\"transition_result\":\"0\",\"pool_sample\":\"0\",\"gap\":\"0\",\
            \"marker\":\"0\",\"counter_snapshot\":\"0\"";
        let empty = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"0\",\"line_count\":\"0\",\
            \"first_seq\":null,\"last_seq\":null,\"events_sha256\":\"{EMPTY_SHA256}\",\
            \"kinds\":{{{kinds}}}}}"
        );
        let seal = parse_integrity_seal(&empty).unwrap();
        assert_eq!(seal.lines, 0);
        assert_eq!(seal.first, None);
        let extended = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"10\",\"line_count\":\"1\",\
            \"first_seq\":\"0\",\"last_seq\":\"0\",\"events_sha256\":\"{}\",\
            \"kinds\":{{{kinds},\"exposure_fact\":\"1\"}}}}",
            "0".repeat(64)
        );
        let seal = parse_integrity_seal(&extended).unwrap();
        assert_eq!(seal.kinds.len(), 11);
        let kinds2 = kinds.replacen("\"marker\":\"0\"", "\"marker\":\"1\"", 1);
        let legacy = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"10\",\"line_count\":\"1\",\
            \"first_seq\":\"0\",\"last_seq\":\"0\",\"events_sha256\":\"{}\",\
            \"kinds\":{{{kinds2}}}}}",
            "0".repeat(64)
        );
        let seal = parse_integrity_seal(&legacy).unwrap();
        assert_eq!(seal.kinds.len(), 10);
        let bogus = legacy.replacen("\"gap\":\"0\"", "\"gap\":\"0\",\"bogus\":\"0\"", 1);
        assert!(parse_integrity_seal(&bogus).is_err());
    }

    fn policy_doc(rules: &str, exceptions: &str) -> String {
        format!(
            "{{\"schema\":\"policy\",\"schema_version\":\"0.1.0\",\"policy_id\":\"p\",\
        \"subject_scope\":\"s\",\"applies_to\":{{\"platform\":\"ordinary-linux\",\
        \"profile\":\"p\"}},\"required_sources\":[\"sharing-census\"],\
        \"clock\":\"guest_monotonic_active\",\"role_bindings\":{{}},\
        \"rules\":[{rules}],\"exceptions\":[{exceptions}]}}"
        )
    }

    #[test]
    fn policy_loader_enforces_bounds() {
        let valid = include_str!("../../tests/exposure/fixtures/contracts/policy_valid.json");
        let summary = parse_policy_file(valid).unwrap();
        assert_eq!(summary.rules, 1);
        assert_eq!(summary.exceptions, 0);

        let big = " ".repeat(POLICY_FILE_MAX_BYTES + 1);
        let err = parse_policy_file(&big).unwrap_err();
        assert_eq!(err.what, "policy");

        let rule = "{\"rule_id\":\"r\"}";
        let exception = "{\"rule_id\":\"r\",\"constraint\":\"c\",\"reason\":\"w\"}";
        let err = parse_policy_file(&policy_doc("", "")).unwrap_err();
        assert_eq!(err.what, "rules");
        let many_rules = vec![rule; POLICY_FILE_MAX_RULES + 1].join(",");
        let err = parse_policy_file(&policy_doc(&many_rules, "")).unwrap_err();
        assert_eq!(err.what, "rules");
        let many_exceptions = vec![exception; POLICY_FILE_MAX_EXCEPTIONS_PER_RULE + 1].join(",");
        let err = parse_policy_file(&policy_doc(rule, &many_exceptions)).unwrap_err();
        assert_eq!(err.what, "exceptions");
        let capped = vec![exception; POLICY_FILE_MAX_EXCEPTIONS_PER_RULE].join(",");
        let summary = parse_policy_file(&policy_doc(rule, &capped)).unwrap();
        assert_eq!(summary.rules, 1);
        assert_eq!(summary.exceptions, POLICY_FILE_MAX_EXCEPTIONS_PER_RULE);

        let no_sources = policy_doc(rule, "").replacen("[\"sharing-census\"]", "[]", 1);
        let err = parse_policy_file(&no_sources).unwrap_err();
        assert_eq!(err.what, "required_sources");

        let wrong_version = policy_doc(rule, "").replacen("\"0.1.0\"", "\"9.9.9\"", 1);
        assert!(parse_policy_file(&wrong_version).is_err());
    }

    #[test]
    fn policy_loader_stays_linear_in_distinct_rule_ids() {
        const DISTINCT: usize = 25_000;
        let mut exceptions = String::new();
        for index in 0..DISTINCT {
            if index > 0 {
                exceptions.push(',');
            }
            exceptions.push_str(&format!("{{\"rule_id\":\"e{index:05}\"}}"));
        }
        let policy = policy_doc("{\"rule_id\":\"r\"}", &exceptions);
        assert!(
            policy.len() <= POLICY_FILE_MAX_BYTES,
            "synthetic policy fits the byte cap"
        );
        let start = std::time::Instant::now();
        let summary = parse_policy_file(&policy).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(summary.rules, 1);
        assert_eq!(summary.exceptions, DISTINCT);
        assert!(
            elapsed < std::time::Duration::from_secs(1),
            "25,000 distinct rule IDs must parse in well under a second, took {elapsed:?}"
        );
    }

    #[test]
    fn evidence_containment() {
        let clean = [
            EvidenceKey {
                evidence_id: "ev-1",
                source_id: "sharing-census",
                epoch: 7,
            },
            EvidenceKey {
                evidence_id: "ev-2",
                source_id: "sharing-census",
                epoch: 7,
            },
        ];
        check_evidence_keys(&clean).unwrap();
        let duplicate = [
            EvidenceKey {
                evidence_id: "ev-1",
                source_id: "sharing-census",
                epoch: 7,
            },
            EvidenceKey {
                evidence_id: "ev-1",
                source_id: "object-lineage",
                epoch: 7,
            },
        ];
        assert_eq!(
            check_evidence_keys(&duplicate).unwrap_err().what,
            "evidence_id"
        );
        let mixed = [
            EvidenceKey {
                evidence_id: "ev-1",
                source_id: "sharing-census",
                epoch: 7,
            },
            EvidenceKey {
                evidence_id: "ev-2",
                source_id: "sharing-census",
                epoch: 8,
            },
        ];
        assert_eq!(check_evidence_keys(&mixed).unwrap_err().what, "source_id");
    }

    #[test]
    fn evidence_containment_scales_linearly() {
        fn elapsed_for(count: usize) -> std::time::Duration {
            let ids: Vec<String> = (0..count).map(|index| format!("ev-{index:05}")).collect();
            let keys: Vec<EvidenceKey<'_>> = ids
                .iter()
                .map(|id| EvidenceKey {
                    evidence_id: id,
                    source_id: "sharing-census",
                    epoch: 7,
                })
                .collect();
            // Best of three runs, to smooth scheduling noise.
            let mut best = std::time::Duration::MAX;
            for _ in 0..3 {
                let start = std::time::Instant::now();
                check_evidence_keys(&keys).unwrap();
                best = best.min(start.elapsed());
            }
            best
        }
        let small = elapsed_for(10_000);
        let big = elapsed_for(20_000);
        assert!(
            big < small * 3,
            "doubled input must cost well under 3x, took {small:?} then {big:?}"
        );
    }

    /// One settled quality channel with measured zero loss.
    fn settled_channel() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("status", FieldValue::Text("complete_for_scope")),
            ("loss_count", FieldValue::UInt(0)),
        ])
    }

    /// Session handle shared by every probe snapshot line.
    const PROBE_SESSION: &str = "sealed-probe-1";

    /// Canonical fact-data fields; tests mutate single leaves from these.
    type FactData = Vec<(&'static str, FieldValue<'static>)>;

    /// One valid fact-data field list carrying the given enum labels.
    fn default_fact_data(semantics: &'static str, clock_domain: &'static str) -> FactData {
        let quality = FieldValue::Object(vec![
            ("detail", settled_channel()),
            ("aggregate", settled_channel()),
            ("identity", settled_channel()),
            ("baseline", settled_channel()),
            ("terminal", settled_channel()),
        ]);
        vec![
            ("evidence_id", FieldValue::Text("ev-1")),
            ("source_id", FieldValue::Text("sharing-census")),
            ("epoch", FieldValue::UInt(7)),
            ("operation_id", FieldValue::Text("op-1")),
            ("kind", FieldValue::Text("census-entry")),
            ("direction", FieldValue::Text("egress")),
            ("generation", FieldValue::UInt(1)),
            ("offset", FieldValue::UInt(0)),
            ("length_bytes", FieldValue::UInt(4096)),
            ("native_result", FieldValue::Int(0)),
            ("caller_class", FieldValue::Text("allocator")),
            ("peer_class", FieldValue::Text("none-observed")),
            ("clock_domain", FieldValue::Text(clock_domain)),
            (
                "observed_interval",
                FieldValue::Object(vec![
                    ("start", FieldValue::UInt(1_000_000_000)),
                    ("end", FieldValue::UInt(1_000_000_100)),
                    ("uncertainty", FieldValue::UInt(50)),
                ]),
            ),
            ("semantics", FieldValue::Text(semantics)),
            ("quality", quality),
        ]
    }

    /// Replace one known fact-data field in place.
    fn set_field(data: &mut FactData, key: &str, value: FieldValue<'static>) {
        let slot = data
            .iter_mut()
            .find(|(seen, _)| *seen == key)
            .expect("known fact field");
        slot.1 = value;
    }

    /// Settled quality with one channel reporting the given status.
    fn quality_with_status(channel: &'static str, status: &'static str) -> FieldValue<'static> {
        let mut channels: Vec<(&'static str, FieldValue<'static>)> = Vec::new();
        for name in ["detail", "aggregate", "identity", "baseline", "terminal"] {
            let state = if name == channel {
                status
            } else {
                "complete_for_scope"
            };
            channels.push((
                name,
                FieldValue::Object(vec![
                    ("status", FieldValue::Text(state)),
                    ("loss_count", FieldValue::UInt(0)),
                ]),
            ));
        }
        FieldValue::Object(channels)
    }

    fn probe_source() -> FieldValue<'static> {
        probe_source_with("observed", "direct")
    }

    /// One envelope source block carrying the given labels.
    fn probe_source_with(
        measurement: &'static str,
        correlation: &'static str,
    ) -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("hook", FieldValue::Text("synthetic:exposure")),
            ("backend", FieldValue::Text("synthetic")),
            ("profile_id", FieldValue::Text("synthetic-census-1")),
            ("measurement", FieldValue::Text(measurement)),
            ("correlation", FieldValue::Text(correlation)),
        ])
    }

    /// One canonical fact line at the given sequence position.
    fn fact_line(seq: u64, data: FactData) -> String {
        fact_line_with_source(seq, data, probe_source())
    }

    /// One canonical fact line carrying the given source block.
    fn fact_line_with_source(seq: u64, data: FactData, source: FieldValue<'_>) -> String {
        render_canonical(&[
            ("schema_version", FieldValue::Text("0.3.0")),
            ("session_id", FieldValue::Text(PROBE_SESSION)),
            ("seq", FieldValue::UInt(seq)),
            ("ts_ns", FieldValue::UInt(1_100_000_000 + seq)),
            ("kind", FieldValue::Text(EXPOSURE_FACT_KIND)),
            ("source", source),
            ("data", FieldValue::Object(data)),
        ])
        .unwrap()
    }

    /// One canonical marker line; `None` drops the payload entirely.
    fn marker_line(seq: u64, data: Option<FieldValue<'_>>) -> String {
        legacy_line(seq, "marker", Some(1_300_000_000), probe_source(), data)
    }

    /// One canonical legacy line; `None` timestamp or payload drops it.
    fn legacy_line(
        seq: u64,
        kind: &'static str,
        ts_ns: Option<u64>,
        source: FieldValue<'_>,
        data: Option<FieldValue<'_>>,
    ) -> String {
        let mut fields: Vec<(&str, FieldValue)> = vec![
            ("schema_version", FieldValue::Text("0.3.0")),
            ("session_id", FieldValue::Text(PROBE_SESSION)),
            ("seq", FieldValue::UInt(seq)),
        ];
        if let Some(stamp) = ts_ns {
            fields.push(("ts_ns", FieldValue::UInt(stamp)));
        }
        fields.push(("kind", FieldValue::Text(kind)));
        fields.push(("source", source));
        if let Some(payload) = data {
            fields.push(("data", payload));
        }
        render_canonical(&fields).unwrap()
    }

    /// One valid bounce-attempt payload.
    fn bounce_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("device_id", FieldValue::Text("dev-1")),
            ("requested_bytes", FieldValue::UInt(4096)),
            ("forced", FieldValue::Bool(false)),
            ("operation_id", FieldValue::Text("op-9")),
        ])
    }

    /// One canonical bounce-attempt line carrying the given payload.
    fn bounce_line(seq: u64, data: FieldValue<'static>) -> String {
        legacy_line(
            seq,
            "bounce_attempt",
            Some(1_300_000_000),
            probe_source(),
            Some(data),
        )
    }

    /// One canonical line under an explicit contract version, with an
    /// optional observer context.
    fn versioned_line(
        seq: u64,
        version: &'static str,
        kind: &'static str,
        source: FieldValue<'_>,
        data: FieldValue<'_>,
        observer: Option<FieldValue<'_>>,
    ) -> String {
        let mut fields: Vec<(&str, FieldValue)> = vec![
            ("schema_version", FieldValue::Text(version)),
            ("session_id", FieldValue::Text(PROBE_SESSION)),
            ("seq", FieldValue::UInt(seq)),
            ("ts_ns", FieldValue::UInt(1_300_000_000 + seq)),
            ("kind", FieldValue::Text(kind)),
            ("source", source),
        ];
        if let Some(context) = observer {
            fields.push(("observer_context", context));
        }
        fields.push(("data", data));
        render_canonical(&fields).unwrap()
    }

    /// One valid map-result payload: a successful known mapping.
    fn map_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(true)),
            ("mapping_id", FieldValue::Text("m-1")),
            ("return_code", FieldValue::Int(0)),
            ("mapped_bytes", FieldValue::UInt(4096)),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("known")),
        ])
    }

    /// One valid unmap payload: a known wire release.
    fn unmap_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("mapping_id", FieldValue::Text("m-1")),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("known")),
        ])
    }

    /// One valid copy payload: an observed CPU bounce copy.
    fn copy_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("direction", FieldValue::Text("original_to_bounce")),
            ("bytes", FieldValue::UInt(512)),
        ])
    }

    /// One valid sync-request payload: a known-offset request.
    fn sync_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("offset_known", FieldValue::Bool(true)),
            ("offset", FieldValue::UInt(128)),
            ("length", FieldValue::UInt(512)),
        ])
    }

    /// One valid transition-result payload: a shared conversion.
    fn transition_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("region_id", FieldValue::Text("r-1")),
            ("requested_state", FieldValue::Text("shared")),
            ("success", FieldValue::Bool(true)),
            ("return_code", FieldValue::Int(0)),
            ("offset", FieldValue::UInt(0)),
            ("length", FieldValue::UInt(4096)),
        ])
    }

    /// One valid pool-sample payload: a byte-unit reading.
    fn pool_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("pool_id", FieldValue::Text("swiotlb")),
            ("used_bytes", FieldValue::UInt(1024)),
            ("capacity_bytes", FieldValue::UInt(4096)),
            ("unit", FieldValue::Text("bytes")),
        ])
    }

    /// One valid gap payload: a measured detail loss.
    fn gap_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("channel", FieldValue::Text("detail")),
            ("lost_count", FieldValue::UInt(3)),
            ("reason", FieldValue::Text("ring full")),
            ("window_start_ns", FieldValue::UInt(100)),
            ("window_end_ns", FieldValue::UInt(200)),
        ])
    }

    /// One valid counter-snapshot payload: a profile-scoped reading.
    fn counter_payload() -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("counter_id", FieldValue::Text("swiotlb.bounce_attempts")),
            ("epoch", FieldValue::UInt(7)),
            (
                "scope",
                FieldValue::Object(vec![("profile_id", FieldValue::Text("p-1"))]),
            ),
            ("value", FieldValue::UInt(42)),
            ("unit", FieldValue::Text("count")),
        ])
    }

    /// One envelope source block with one leaf replaced.
    fn probe_source_leaf<'a>(leaf: &str, value: FieldValue<'a>) -> FieldValue<'a> {
        let mut fields: Vec<(&str, FieldValue)> = vec![
            ("hook", FieldValue::Text("synthetic:exposure")),
            ("backend", FieldValue::Text("synthetic")),
            ("profile_id", FieldValue::Text("synthetic-census-1")),
            ("measurement", FieldValue::Text("observed")),
            ("correlation", FieldValue::Text("direct")),
        ];
        let slot = fields
            .iter_mut()
            .find(|(seen, _)| *seen == leaf)
            .expect("known source leaf");
        slot.1 = value;
        FieldValue::Object(fields)
    }

    /// One sealed snapshot carrying exactly the given literal lines.
    ///
    /// Each line renders through the canonical encoder and the seal
    /// commits to the literal bytes, so only the shape gates can
    /// refuse: any other refusal would be a builder bug.
    fn sealed_lines_snapshot(lines: &[String], facts: u64, markers: u64) -> String {
        sealed_counted_snapshot(lines, facts, markers, 0)
    }

    /// One sealed snapshot with an explicit bounce-attempt count.
    fn sealed_counted_snapshot(lines: &[String], facts: u64, markers: u64, bounces: u64) -> String {
        assert!(!lines.is_empty(), "probe snapshot carries lines");
        let literal: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let entries: Vec<String> = lines
            .iter()
            .map(|line| {
                format!("{line}\n")
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
            })
            .collect();
        let bytes = literal.len();
        let digest = sha256_hex(literal.as_bytes());
        let count = lines.len() as u64;
        let kinds = format!(
            "\"bounce_attempt\":\"{bounces}\",\"map_result\":\"0\",\"unmap\":\"0\",\"copy\":\"0\",\
            \"sync_request\":\"0\",\"transition_result\":\"0\",\"pool_sample\":\"0\",\"gap\":\"0\",\
            \"marker\":\"{markers}\",\"counter_snapshot\":\"0\",\"exposure_fact\":\"{facts}\""
        );
        let integrity = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"{bytes}\",\"line_count\":\"{count}\",\
            \"first_seq\":\"0\",\"last_seq\":\"{}\",\"events_sha256\":\"{digest}\",\
            \"kinds\":{{{kinds}}}}}",
            count - 1
        );
        let rendered = entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"session\":{{\"schema_version\":\"0.3.0\",\
            \"session_id\":\"{PROBE_SESSION}\",\
            \"capture\":{{\"integrity\":{integrity}}}}},\
            \"event_lines\":[{rendered}]}}"
        )
    }

    /// Escape literal lines into snapshot string entries.
    fn escape_entries(lines: &[String]) -> (String, Vec<String>) {
        let literal: String = lines.iter().map(|line| format!("{line}\n")).collect();
        let entries: Vec<String> = lines
            .iter()
            .map(|line| {
                format!("{line}\n")
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
            })
            .collect();
        (literal, entries)
    }

    /// One sealed 0.3.0 snapshot with explicit per-kind counts.
    ///
    /// Unlisted kinds commit zero; the exposure-fact count rides in
    /// the same table. Only the shape gates can refuse the lines.
    fn sealed_kind_snapshot(lines: &[String], counts: &[(&str, u64)]) -> String {
        assert!(!lines.is_empty(), "probe snapshot carries lines");
        let (literal, entries) = escape_entries(lines);
        let bytes = literal.len();
        let digest = sha256_hex(literal.as_bytes());
        let count = lines.len() as u64;
        let mut table = String::new();
        for (index, name) in LEGACY_KINDS.iter().enumerate() {
            let committed = counts
                .iter()
                .find(|(seen, _)| seen == name)
                .map(|(_, total)| *total)
                .unwrap_or(0);
            if index > 0 {
                table.push(',');
            }
            table.push_str(&format!("\"{name}\":\"{committed}\""));
        }
        let facts = counts
            .iter()
            .find(|(seen, _)| *seen == EXPOSURE_FACT_KIND)
            .map(|(_, total)| *total)
            .unwrap_or(0);
        table.push_str(&format!(",\"{EXPOSURE_FACT_KIND}\":\"{facts}\""));
        let integrity = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"{bytes}\",\"line_count\":\"{count}\",\
            \"first_seq\":\"0\",\"last_seq\":\"{}\",\"events_sha256\":\"{digest}\",\
            \"kinds\":{{{table}}}}}",
            count - 1
        );
        let rendered = entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"session\":{{\"schema_version\":\"0.3.0\",\
            \"session_id\":\"{PROBE_SESSION}\",\
            \"capture\":{{\"integrity\":{integrity}}}}},\
            \"event_lines\":[{rendered}]}}"
        )
    }

    /// One sealed legacy snapshot: a 0.1.4 session with a ten-key
    /// kinds table committing to exactly the given literal lines.
    fn sealed_legacy_snapshot(lines: &[String], counts: &[(&str, u64)]) -> String {
        assert!(!lines.is_empty(), "probe snapshot carries lines");
        let (literal, entries) = escape_entries(lines);
        let bytes = literal.len();
        let digest = sha256_hex(literal.as_bytes());
        let count = lines.len() as u64;
        let mut table = String::new();
        for (index, name) in LEGACY_KINDS.iter().enumerate() {
            let committed = counts
                .iter()
                .find(|(seen, _)| seen == name)
                .map(|(_, total)| *total)
                .unwrap_or(0);
            if index > 0 {
                table.push(',');
            }
            table.push_str(&format!("\"{name}\":\"{committed}\""));
        }
        let integrity = format!(
            "{{\"algorithm\":\"sha256\",\"events_bytes\":\"{bytes}\",\"line_count\":\"{count}\",\
            \"first_seq\":\"0\",\"last_seq\":\"{}\",\"events_sha256\":\"{digest}\",\
            \"kinds\":{{{table}}}}}",
            count - 1
        );
        let rendered = entries
            .iter()
            .map(|entry| format!("\"{entry}\""))
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"session\":{{\"schema_version\":\"0.1.4\",\
            \"session_id\":\"{PROBE_SESSION}\",\
            \"capture\":{{\"integrity\":{integrity}}}}},\
            \"event_lines\":[{rendered}]}}"
        )
    }

    /// One sealed single-fact snapshot carrying the given enum labels.
    fn sealed_fact_snapshot(semantics: &'static str, clock_domain: &'static str) -> String {
        let line = fact_line(0, default_fact_data(semantics, clock_domain));
        sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0)
    }

    /// One sealed single-fact snapshot with mutated fact data.
    fn sealed_mutated_fact(mutate: fn(&mut FactData)) -> String {
        let mut data = default_fact_data("inventory", "guest_monotonic_active");
        mutate(&mut data);
        let line = fact_line(0, data);
        sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0)
    }

    fn break_peer_class(data: &mut FactData) {
        set_field(data, "peer_class", FieldValue::Text("unknown-peer"));
    }

    fn break_interval_order(data: &mut FactData) {
        set_field(
            data,
            "observed_interval",
            FieldValue::Object(vec![
                ("start", FieldValue::UInt(2_000_000_000)),
                ("end", FieldValue::UInt(1_000_000_100)),
                ("uncertainty", FieldValue::UInt(50)),
            ]),
        );
    }

    fn break_source(data: &mut FactData) {
        set_field(data, "source_id", FieldValue::Text("unknown-source"));
    }

    fn break_quality_status(data: &mut FactData) {
        set_field(
            data,
            "quality",
            quality_with_status("detail", "unknown-quality"),
        );
    }

    fn break_stray_parent_reason(data: &mut FactData) {
        data.push((
            "parent_operation_id_reason",
            FieldValue::Text("unknown-parent"),
        ));
    }

    fn break_native_reason(data: &mut FactData) {
        set_field(data, "native_result", FieldValue::Null);
    }

    fn break_evidence_id(data: &mut FactData) {
        set_field(data, "evidence_id", FieldValue::Text(""));
    }

    #[test]
    fn seal_refuses_unknown_fact_enums() {
        let bad_semantics = sealed_fact_snapshot("guess", "guest_monotonic_active");
        let report = verify_sealed_snapshot(&bad_semantics).expect("tainted parses");
        assert!(!report.verified, "unknown semantics cannot verify");
        let bad_clock = sealed_fact_snapshot("inventory", "wall_clock");
        let report = verify_sealed_snapshot(&bad_clock).expect("tainted parses");
        assert!(!report.verified, "unknown clock domain cannot verify");
    }

    #[test]
    fn seal_accepts_every_frozen_fact_enum() {
        for semantics in exposure_shapes::SEMANTICS {
            let snapshot = sealed_fact_snapshot(semantics, "guest_monotonic_active");
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "frozen semantics {semantics} must verify");
        }
        for clock in exposure_shapes::CLOCK_DOMAINS {
            let snapshot = sealed_fact_snapshot("inventory", clock);
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "frozen clock domain {clock} must verify");
        }
    }

    #[test]
    fn seal_refuses_invalid_fact_fields() {
        for (name, mutate) in [
            ("peer class", break_peer_class as fn(&mut FactData)),
            ("interval order", break_interval_order as fn(&mut FactData)),
            ("source", break_source as fn(&mut FactData)),
            ("quality status", break_quality_status as fn(&mut FactData)),
            (
                "stray parent reason",
                break_stray_parent_reason as fn(&mut FactData),
            ),
            ("native reason", break_native_reason as fn(&mut FactData)),
            ("evidence id", break_evidence_id as fn(&mut FactData)),
        ] {
            let snapshot = sealed_mutated_fact(mutate);
            let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
            assert!(!report.verified, "{name} cannot verify");
        }
    }

    #[test]
    fn seal_accepts_every_frozen_peer_class_source_and_status() {
        for peer in exposure_shapes::PEER_CLASSES {
            let mut data = default_fact_data("inventory", "guest_monotonic_active");
            set_field(&mut data, "peer_class", FieldValue::Text(peer));
            let line = fact_line(0, data);
            let snapshot = sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0);
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "frozen peer class {peer} must verify");
        }
        for source in exposure_shapes::EXPOSURE_SOURCES {
            let mut data = default_fact_data("inventory", "guest_monotonic_active");
            set_field(&mut data, "source_id", FieldValue::Text(source));
            let line = fact_line(0, data);
            let snapshot = sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0);
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "catalog source {source} must verify");
        }
        for status in exposure_shapes::QUALITY_STATUSES {
            let mut data = default_fact_data("inventory", "guest_monotonic_active");
            set_field(&mut data, "quality", quality_with_status("detail", status));
            let line = fact_line(0, data);
            let snapshot = sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0);
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "quality status {status} must verify");
        }
    }

    #[test]
    fn seal_refuses_malformed_non_fact_lines() {
        let marker = FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]);
        let control = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            marker_line(1, Some(marker)),
        ];
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(&control, 1, 1)).expect("control parses");
        assert!(report.verified, "valid marker must verify");

        let overlong = "x".repeat(257);
        let payloads: Vec<(&str, Option<FieldValue>)> = vec![
            ("missing payload", None),
            ("mistyped payload", Some(FieldValue::Text("nope"))),
            ("keyless payload", Some(FieldValue::Object(vec![]))),
            (
                "empty annotation",
                Some(FieldValue::Object(vec![("text", FieldValue::Text(""))])),
            ),
            (
                "overlong annotation",
                Some(FieldValue::Object(vec![(
                    "text",
                    FieldValue::Text(&overlong),
                )])),
            ),
            (
                "extra payload key",
                Some(FieldValue::Object(vec![
                    ("text", FieldValue::Text("census sealed")),
                    ("extra", FieldValue::Text("nope")),
                ])),
            ),
        ];
        for (name, payload) in payloads {
            let lines = vec![
                fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
                marker_line(1, payload),
            ];
            let report = verify_sealed_snapshot(&sealed_lines_snapshot(&lines, 1, 1))
                .expect("tainted parses");
            assert!(!report.verified, "marker with {name} cannot verify");
        }
    }

    fn empty_parent_reason(data: &mut FactData) {
        data.push(("parent_operation_id_reason", FieldValue::Text("")));
    }

    fn empty_object_reason(data: &mut FactData) {
        data.push(("object_token_reason", FieldValue::Text("")));
    }

    fn empty_native_reason(data: &mut FactData) {
        data.push(("native_result_reason", FieldValue::Text("")));
    }

    #[test]
    fn seal_refuses_explicit_empty_reasons() {
        for (name, mutate) in [
            ("parent", empty_parent_reason as fn(&mut FactData)),
            ("object", empty_object_reason as fn(&mut FactData)),
            ("native", empty_native_reason as fn(&mut FactData)),
        ] {
            let snapshot = sealed_mutated_fact(mutate);
            let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
            assert!(
                !report.verified,
                "explicit empty {name} reason cannot verify"
            );
        }
        // Absent reasons still verify: presence, not emptiness, is the gate.
        let bare = sealed_fact_snapshot("inventory", "guest_monotonic_active");
        let report = verify_sealed_snapshot(&bare).expect("control parses");
        assert!(report.verified, "absent reasons must verify");
        // A present null with a typed reason still verifies.
        let mut data = default_fact_data("inventory", "guest_monotonic_active");
        set_field(&mut data, "native_result", FieldValue::Null);
        data.push(("native_result_reason", FieldValue::Text("withheld")));
        let line = fact_line(0, data);
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0))
                .expect("control parses");
        assert!(report.verified, "null with a typed reason must verify");
    }

    #[test]
    fn seal_refuses_unknown_source_labels() {
        for (measurement, correlation) in [
            ("guess", "direct"),
            ("observed", "guess"),
            ("", "direct"),
            ("observed", ""),
        ] {
            let line = fact_line_with_source(
                0,
                default_fact_data("inventory", "guest_monotonic_active"),
                probe_source_with(measurement, correlation),
            );
            let report =
                verify_sealed_snapshot(&sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0))
                    .expect("tainted parses");
            assert!(
                !report.verified,
                "fact with {measurement}/{correlation} cannot verify"
            );
            let marker = legacy_line(
                0,
                "marker",
                Some(1_300_000_000),
                probe_source_with(measurement, correlation),
                Some(FieldValue::Object(vec![(
                    "text",
                    FieldValue::Text("census sealed"),
                )])),
            );
            let report =
                verify_sealed_snapshot(&sealed_lines_snapshot(std::slice::from_ref(&marker), 0, 1))
                    .expect("tainted parses");
            assert!(
                !report.verified,
                "marker with {measurement}/{correlation} cannot verify"
            );
        }
    }

    #[test]
    fn seal_accepts_frozen_source_labels() {
        for measurement in exposure_shapes::MEASUREMENTS {
            for correlation in exposure_shapes::CORRELATIONS {
                let line = fact_line_with_source(
                    0,
                    default_fact_data("inventory", "guest_monotonic_active"),
                    probe_source_with(measurement, correlation),
                );
                let report = verify_sealed_snapshot(&sealed_lines_snapshot(
                    std::slice::from_ref(&line),
                    1,
                    0,
                ))
                .expect("control parses");
                assert!(
                    report.verified,
                    "frozen labels {measurement}/{correlation} must verify"
                );
            }
        }
    }

    #[test]
    fn seal_refuses_non_fact_envelope_breaks() {
        let marker = FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]);
        // A missing timestamp refuses.
        let lines = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            legacy_line(1, "marker", None, probe_source(), Some(marker.clone())),
        ];
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(&lines, 1, 1)).expect("tainted parses");
        assert!(!report.verified, "marker without ts_ns cannot verify");
        // A non-canonical timestamp refuses.
        let mistimed = legacy_line(
            1,
            "marker",
            Some(1_300_000_000),
            probe_source(),
            Some(marker),
        )
        .replacen("\"ts_ns\":\"1300000000\"", "\"ts_ns\":\"01\"", 1);
        let lines = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            mistimed,
        ];
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(&lines, 1, 1)).expect("tainted parses");
        assert!(
            !report.verified,
            "marker with non-canonical ts_ns cannot verify"
        );
        // A foreign schema version refuses.
        let lines = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            marker_line(
                1,
                Some(FieldValue::Object(vec![("text", FieldValue::Text("x"))])),
            )
            .replacen(
                "\"schema_version\":\"0.3.0\"",
                "\"schema_version\":\"0.1.1\"",
                1,
            ),
        ];
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(&lines, 1, 1)).expect("tainted parses");
        assert!(
            !report.verified,
            "marker with a foreign version cannot verify"
        );
        // An unknown kind refuses.
        let lines = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            legacy_line(
                1,
                "frobnicate",
                Some(1_300_000_000),
                probe_source(),
                Some(FieldValue::Object(vec![(
                    "text",
                    FieldValue::Text("census sealed"),
                )])),
            ),
        ];
        let report =
            verify_sealed_snapshot(&sealed_lines_snapshot(&lines, 1, 1)).expect("tainted parses");
        assert!(!report.verified, "unknown kind cannot verify");
    }

    #[test]
    fn seal_validates_bounce_attempt_payloads() {
        let control = vec![
            fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
            bounce_line(1, bounce_payload()),
        ];
        let report = verify_sealed_snapshot(&sealed_counted_snapshot(&control, 1, 0, 1))
            .expect("control parses");
        assert!(report.verified, "valid bounce attempt must verify");

        let empty = FieldValue::Object(vec![]);
        let missing = FieldValue::Object(vec![
            ("requested_bytes", FieldValue::UInt(4096)),
            ("forced", FieldValue::Bool(false)),
            ("operation_id", FieldValue::Text("op-9")),
        ]);
        let mistyped = FieldValue::Object(vec![
            ("device_id", FieldValue::Text("dev-1")),
            ("requested_bytes", FieldValue::Text("01")),
            ("forced", FieldValue::Bool(false)),
            ("operation_id", FieldValue::Text("op-9")),
        ]);
        let unforced = FieldValue::Object(vec![
            ("device_id", FieldValue::Text("dev-1")),
            ("requested_bytes", FieldValue::UInt(4096)),
            ("forced", FieldValue::Text("false")),
            ("operation_id", FieldValue::Text("op-9")),
        ]);
        let padded = FieldValue::Object(vec![
            ("device_id", FieldValue::Text("dev-1")),
            ("requested_bytes", FieldValue::UInt(4096)),
            ("forced", FieldValue::Bool(false)),
            ("operation_id", FieldValue::Text("op-9")),
            ("extra", FieldValue::Text("nope")),
        ]);
        for (name, payload) in [
            ("empty payload", empty),
            ("missing device", missing),
            ("non-canonical bytes", mistyped),
            ("mistyped flag", unforced),
            ("extra key", padded),
        ] {
            let lines = vec![
                fact_line(0, default_fact_data("inventory", "guest_monotonic_active")),
                bounce_line(1, payload),
            ];
            let report = verify_sealed_snapshot(&sealed_counted_snapshot(&lines, 1, 0, 1))
                .expect("tainted parses");
            assert!(!report.verified, "bounce with {name} cannot verify");
        }
    }

    #[test]
    fn seal_dispatches_on_session_contract() {
        // A legacy session with valid 0.1.1 lines verifies under
        // legacy rules.
        let lines = vec![
            versioned_line(
                0,
                "0.1.1",
                "bounce_attempt",
                probe_source(),
                bounce_payload(),
                None,
            ),
            versioned_line(
                1,
                "0.1.1",
                "bounce_attempt",
                probe_source(),
                bounce_payload(),
                None,
            ),
        ];
        let snapshot = sealed_legacy_snapshot(&lines, &[("bounce_attempt", 2)]);
        let report = verify_sealed_snapshot(&snapshot).expect("legacy parses");
        assert!(report.verified, "valid legacy lines must verify");
        // An unknown session contract refuses even with valid lines.
        let forged = snapshot.replacen(
            "\"schema_version\":\"0.1.4\"",
            "\"schema_version\":\"9.9.9\"",
            1,
        );
        assert_ne!(forged, snapshot);
        let report = verify_sealed_snapshot(&forged).expect("forged parses");
        assert!(!report.verified, "unknown contract cannot verify");
        // A missing session contract refuses.
        let missing = snapshot.replacen("\"schema_version\":\"0.1.4\",", "", 1);
        assert_ne!(missing, snapshot);
        let report = verify_sealed_snapshot(&missing).expect("missing parses");
        assert!(!report.verified, "missing contract cannot verify");
        // An exposure fact verifies nowhere under a legacy contract.
        let fact = fact_line(0, default_fact_data("inventory", "guest_monotonic_active"));
        let snapshot =
            sealed_kind_snapshot(std::slice::from_ref(&fact), &[(EXPOSURE_FACT_KIND, 1)]);
        let legacy = snapshot.replacen(
            "\"schema_version\":\"0.3.0\"",
            "\"schema_version\":\"0.1.4\"",
            1,
        );
        assert_ne!(legacy, snapshot);
        let report = verify_sealed_snapshot(&legacy).expect("tainted parses");
        assert!(!report.verified, "fact under legacy contract cannot verify");
        // A 0.3.0 line verifies nowhere under a legacy contract.
        let marker = versioned_line(
            0,
            "0.3.0",
            "marker",
            probe_source(),
            FieldValue::Object(vec![("text", FieldValue::Text("x"))]),
            None,
        );
        let snapshot = sealed_kind_snapshot(std::slice::from_ref(&marker), &[("marker", 1)]);
        let legacy = snapshot.replacen(
            "\"schema_version\":\"0.3.0\"",
            "\"schema_version\":\"0.1.4\"",
            1,
        );
        assert_ne!(legacy, snapshot);
        let report = verify_sealed_snapshot(&legacy).expect("tainted parses");
        assert!(
            !report.verified,
            "0.3.0 line under legacy contract cannot verify"
        );
    }

    #[test]
    fn seal_validates_all_legacy_payloads() {
        let marker_text = || FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]);
        let cases: Vec<(&'static str, FieldValue<'static>)> = vec![
            ("bounce_attempt", bounce_payload()),
            ("map_result", map_payload()),
            ("unmap", unmap_payload()),
            ("copy", copy_payload()),
            ("sync_request", sync_payload()),
            ("transition_result", transition_payload()),
            ("pool_sample", pool_payload()),
            ("gap", gap_payload()),
            ("marker", marker_text()),
            ("counter_snapshot", counter_payload()),
        ];
        for (kind, payload) in cases {
            let line = versioned_line(0, "0.3.0", kind, probe_source(), payload, None);
            let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[(kind, 1)]);
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "valid {kind} must verify");
            let bogus = FieldValue::Object(vec![("bogus", FieldValue::Text("x"))]);
            let line = versioned_line(0, "0.3.0", kind, probe_source(), bogus, None);
            let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[(kind, 1)]);
            let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
            assert!(!report.verified, "bogus {kind} cannot verify");
        }
    }

    #[test]
    fn seal_bounds_legacy_return_codes_to_i64() {
        for kind in ["map_result", "transition_result"] {
            for bound in [i64::MAX, i64::MIN] {
                let payload = if kind == "map_result" {
                    map_payload()
                } else {
                    transition_payload()
                };
                let line = versioned_line(0, "0.3.0", kind, probe_source(), payload, None)
                    .replacen("\"return_code\":0", &format!("\"return_code\":{bound}"), 1);
                let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[(kind, 1)]);
                let report = verify_sealed_snapshot(&snapshot).expect("control parses");
                assert!(report.verified, "{kind} return_code {bound} must verify");
            }
            for overflow in ["9223372036854775808", "-9223372036854775809"] {
                let payload = if kind == "map_result" {
                    map_payload()
                } else {
                    transition_payload()
                };
                let line = versioned_line(0, "0.3.0", kind, probe_source(), payload, None)
                    .replacen(
                        "\"return_code\":0",
                        &format!("\"return_code\":{overflow}"),
                        1,
                    );
                let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[(kind, 1)]);
                let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
                assert!(
                    !report.verified,
                    "{kind} return_code {overflow} cannot verify"
                );
            }
        }
    }

    /// One probe coverage entry carrying the given status.
    ///
    /// Only the duplicate-key leaves ride along: source, subject,
    /// phase, and window identify coverage, never the status.
    fn probe_source_entry(status: &str) -> String {
        format!(
            "{{\"source_id\":\"sharing-census\",\"subject_id\":\"guest-direct-map\",\
            \"phase\":\"pre_attach\",\
            \"window\":{{\"start_ns\":\"1000000000\",\"end_ns\":\"4000000000\"}},\
            \"status\":\"{status}\"}}"
        )
    }

    /// One sealed probe snapshot carrying the given raw sources array.
    fn snapshot_with_sources(sources: &str) -> String {
        let marker = FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]);
        let line = marker_line(0, Some(marker));
        let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[("marker", 1)]);
        snapshot.replacen(
            "\"capture\":{",
            &format!("\"exposure\":{{\"sources\":[{sources}]}},\"capture\":{{"),
            1,
        )
    }

    #[test]
    fn seal_refuses_duplicate_coverage_sources() {
        let available = probe_source_entry("available");
        let denied = probe_source_entry("partial");
        for (label, sources) in [
            ("denied-first", format!("{denied},{available}")),
            ("available-first", format!("{available},{denied}")),
            ("identical twins", format!("{available},{available}")),
        ] {
            let snapshot = snapshot_with_sources(&sources);
            let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
            assert!(!report.verified, "{label} duplicate sources cannot verify");
        }
        // One differing key leaf is disjoint coverage, not a
        // duplicate: the seal keeps verifying.
        let splits = [
            available.replace("\"guest-direct-map\"", "\"guest-kernel-memory-management\""),
            available.replace("\"pre_attach\"", "\"observed\""),
            available.replace("\"end_ns\":\"4000000000\"", "\"end_ns\":\"5000000000\""),
            available.replace("\"sharing-census\"", "\"egress-controls\""),
        ];
        for (index, other) in splits.iter().enumerate() {
            assert_ne!(other, &available);
            let snapshot = snapshot_with_sources(&format!("{available},{other}"));
            let report = verify_sealed_snapshot(&snapshot).expect("control parses");
            assert!(report.verified, "split coverage {index} must verify");
        }
    }

    /// One snapshot text carrying a single raw coverage entry.
    fn evidence_snapshot(entry: &str) -> String {
        format!(
            "{{\"session\":{{\"session_id\":\"probe\",\"exposure\":{{\"sources\":[{entry}]}}}}}}"
        )
    }

    /// One raw coverage row with valid metadata and the given status.
    ///
    /// Catalog capability, opaque profile, frozen subject, cell,
    /// namespace, phase and reason, and an ordered window ride
    /// along, so usability failures pin the quality block rather
    /// than the metadata.
    fn full_source_entry(status: &str, quality: &str) -> String {
        format!(
            "{{\"source_id\":\"sharing-census\",\"capability\":\"census\",\
            \"profile_id\":\"synthetic-census-1\",\"subject_id\":\"guest-direct-map\",\
            \"platform_cell\":\"ordinary-linux\",\"address_namespace\":\"guest_physical\",\
            \"phase\":\"pre_attach\",\"status\":\"{status}\",\
            \"reason\":\"adapter-unimplemented\",\
            \"window\":{{\"start_ns\":\"1000000000\",\"end_ns\":\"4000000000\"}},\
            \"quality\":{quality}}}"
        )
    }

    /// One raw quality channel carrying the given status and loss.
    fn probe_channel(status: &str, loss: &str) -> String {
        format!("{{\"status\":\"{status}\",\"loss_count\":{loss}}}")
    }

    /// One raw quality block with every channel settled and measured.
    fn settled_quality() -> String {
        let channels: Vec<String> = ["detail", "aggregate", "identity", "baseline", "terminal"]
            .iter()
            .map(|name| {
                format!(
                    "\"{name}\":{}",
                    probe_channel("complete_for_scope", "\"0\"")
                )
            })
            .collect();
        format!("{{{}}}", channels.join(","))
    }

    /// One raw quality block with every channel unavailable.
    fn denied_quality() -> String {
        let channels: Vec<String> = ["detail", "aggregate", "identity", "baseline", "terminal"]
            .iter()
            .map(|name| format!("\"{name}\":{}", probe_channel("unavailable", "null")))
            .collect();
        format!("{{{}}}", channels.join(","))
    }

    #[test]
    fn source_evidence_validates_quality_blocks() {
        let usable = settled_quality();
        let none = denied_quality();
        let bogus_channel = format!(
            "{},\"made-up\":{}}}",
            none.strip_suffix('}').expect("quality object closes"),
            probe_channel("complete_for_scope", "\"0\"")
        );
        let bogus_loss = settled_quality().replacen(
            "\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\"}",
            "\"detail\":{\"status\":\"partial\",\"loss_count\":\"not-a-count\"}",
            1,
        );
        assert_ne!(bogus_loss, settled_quality());
        assert!(
            bogus_loss
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"not-a-count\"}"),
            "bad loss corrupts the value with the channel key intact"
        );
        for (label, status, quality, usable) in [
            ("settled available", "available", usable.as_str(), true),
            ("denied partial", "partial", none.as_str(), false),
            ("bogus channel", "partial", bogus_channel.as_str(), false),
            ("bogus loss", "partial", bogus_loss.as_str(), false),
        ] {
            let entry = full_source_entry(status, quality);
            let evidence = snapshot_source_evidence(&evidence_snapshot(&entry), "sharing-census")
                .expect("snapshot carries sources");
            assert!(evidence.present, "{label} source stays present");
            assert_eq!(evidence.status, status);
            assert_eq!(evidence.quality_usable, usable, "{label} usability");
        }
        let bare = "{\"source_id\":\"sharing-census\",\"status\":\"available\"}";
        let evidence = snapshot_source_evidence(&evidence_snapshot(bare), "sharing-census")
            .expect("snapshot carries sources");
        assert!(evidence.present);
        assert!(
            !evidence.quality_usable,
            "available source without quality stays unusable"
        );
    }

    #[test]
    fn source_evidence_combines_coverage_rows_worst_first() {
        let settled = || probe_quality_all("complete_for_scope", FieldValue::UInt(0));
        let denied = || probe_quality_all("unavailable", FieldValue::Null);
        let available_row =
            |subject: &'static str, phase: &'static str, start_ns: u64, end_ns: u64| {
                probe_coverage_identity(
                    "available",
                    settled(),
                    subject,
                    phase,
                    start_ns,
                    end_ns,
                    "adapter-unimplemented",
                )
            };
        let denied_row =
            |subject: &'static str, phase: &'static str, start_ns: u64, end_ns: u64| {
                probe_coverage_identity(
                    "partial",
                    denied(),
                    subject,
                    phase,
                    start_ns,
                    end_ns,
                    "access-denied",
                )
            };
        // One usable row plus one denied row over disjoint
        // coverage: the denied row dominates in either order,
        // and both orders read identical evidence.
        for axis in ["window", "subject", "phase"] {
            let (first, second) = match axis {
                "window" => (
                    available_row(
                        "guest-direct-map",
                        "pre_attach",
                        1_000_000_000,
                        2_000_000_000,
                    ),
                    denied_row(
                        "guest-direct-map",
                        "pre_attach",
                        2_000_000_000,
                        4_000_000_000,
                    ),
                ),
                "subject" => (
                    available_row(
                        "guest-direct-map",
                        "pre_attach",
                        1_000_000_000,
                        4_000_000_000,
                    ),
                    denied_row(
                        "guest-kernel-memory-management",
                        "pre_attach",
                        1_000_000_000,
                        4_000_000_000,
                    ),
                ),
                _ => (
                    available_row(
                        "guest-direct-map",
                        "pre_attach",
                        1_000_000_000,
                        4_000_000_000,
                    ),
                    denied_row("guest-direct-map", "observed", 1_000_000_000, 4_000_000_000),
                ),
            };
            let forward = snapshot_source_evidence(
                &source_snapshot(vec![first.clone(), second.clone()]),
                "sharing-census",
            )
            .expect("snapshot carries sources");
            let backward =
                snapshot_source_evidence(&source_snapshot(vec![second, first]), "sharing-census")
                    .expect("snapshot carries sources");
            assert_eq!(forward, backward, "{axis} rows combine order-free");
            assert!(forward.present, "{axis} source stays present");
            assert_eq!(forward.status, "partial", "{axis} denied row dominates");
            assert!(!forward.quality_usable, "{axis} denied row dominates");
        }
        // Every row usable still combines usable in either order.
        let usable = available_row(
            "guest-direct-map",
            "pre_attach",
            1_000_000_000,
            2_000_000_000,
        );
        let usable_other = available_row(
            "guest-direct-map",
            "pre_attach",
            2_000_000_000,
            4_000_000_000,
        );
        for (label, rows) in [
            (
                "available-first",
                vec![usable.clone(), usable_other.clone()],
            ),
            ("available-second", vec![usable_other, usable]),
        ] {
            let evidence = snapshot_source_evidence(&source_snapshot(rows), "sharing-census")
                .expect("snapshot carries sources");
            assert!(evidence.present, "{label} source stays present");
            assert_eq!(evidence.status, "available", "{label} stays usable");
            assert!(evidence.quality_usable, "{label} stays usable");
        }
        // An unavailable row dominates a usable row in either order.
        let unavailable = probe_coverage_identity(
            "unavailable",
            denied(),
            "guest-direct-map",
            "pre_attach",
            4_000_000_000,
            5_000_000_000,
            "no-safe-source",
        );
        let usable = available_row(
            "guest-direct-map",
            "pre_attach",
            1_000_000_000,
            4_000_000_000,
        );
        let forward = snapshot_source_evidence(
            &source_snapshot(vec![usable.clone(), unavailable.clone()]),
            "sharing-census",
        )
        .expect("snapshot carries sources");
        let backward = snapshot_source_evidence(
            &source_snapshot(vec![unavailable, usable]),
            "sharing-census",
        )
        .expect("snapshot carries sources");
        assert_eq!(forward, backward, "unavailable rows combine order-free");
        assert_eq!(forward.status, "unavailable");
        assert!(!forward.quality_usable);
    }

    #[test]
    fn source_evidence_refuses_invalid_coverage_rows() {
        let entry = full_source_entry("available", &settled_quality());
        let missing = entry.replacen(",\"subject_id\":\"guest-direct-map\"", "", 1);
        assert_ne!(missing, entry);
        assert!(!missing.contains("subject_id"));
        let reversed = entry.replacen(
            "\"start_ns\":\"1000000000\",\"end_ns\":\"4000000000\"",
            "\"start_ns\":\"4000000000\",\"end_ns\":\"1000000000\"",
            1,
        );
        assert_ne!(reversed, entry);
        let miscapped = entry.replacen(
            "\"capability\":\"census\"",
            "\"capability\":\"host-interfaces\"",
            1,
        );
        assert_ne!(miscapped, entry);
        for (label, mutated) in [
            ("missing subject", missing.as_str()),
            ("reversed window", reversed.as_str()),
            ("wrong capability", miscapped.as_str()),
        ] {
            let evidence = snapshot_source_evidence(&evidence_snapshot(mutated), "sharing-census")
                .expect("snapshot carries sources");
            assert!(evidence.present, "{label} source stays present");
            assert_eq!(
                evidence.status, "available",
                "{label} status stays verbatim"
            );
            assert!(
                !evidence.quality_usable,
                "{label} invalid metadata never supplies usability"
            );
        }
        // A partial row with invalid metadata stays unusable too.
        let denied = full_source_entry("partial", &denied_quality()).replacen(
            "\"start_ns\":\"1000000000\",\"end_ns\":\"4000000000\"",
            "\"start_ns\":\"4000000000\",\"end_ns\":\"1000000000\"",
            1,
        );
        let evidence = snapshot_source_evidence(&evidence_snapshot(&denied), "sharing-census")
            .expect("snapshot carries sources");
        assert_eq!(evidence.status, "partial");
        assert!(!evidence.quality_usable);
    }

    #[test]
    fn seal_enforces_legacy_conditionals() {
        let derived = probe_source_with("derived", "direct");
        let unassigned = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(true)),
            ("mapping_id", FieldValue::Null),
            ("return_code", FieldValue::Int(0)),
            ("mapped_bytes", FieldValue::UInt(4096)),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("unassigned")),
        ]);
        let failed_wire = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(false)),
            ("mapping_id", FieldValue::Null),
            ("return_code", FieldValue::Int(-12)),
            ("mapped_bytes", FieldValue::Null),
            ("wire_generation", FieldValue::UInt(0)),
            ("wire_identity", FieldValue::Null),
        ]);
        let success_without_mapping = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(true)),
            ("mapping_id", FieldValue::Null),
            ("return_code", FieldValue::Int(0)),
            ("mapped_bytes", FieldValue::UInt(4096)),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("known")),
        ]);
        let failed_with_mapping = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(false)),
            ("mapping_id", FieldValue::Text("m-1")),
            ("return_code", FieldValue::Int(0)),
            ("mapped_bytes", FieldValue::Null),
            ("wire_generation", FieldValue::Null),
            ("wire_identity", FieldValue::Null),
        ]);
        let null_generation_known = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("success", FieldValue::Bool(true)),
            ("mapping_id", FieldValue::Text("m-1")),
            ("return_code", FieldValue::Int(0)),
            ("mapped_bytes", FieldValue::UInt(4096)),
            ("wire_generation", FieldValue::Null),
            ("wire_identity", FieldValue::Text("known")),
        ]);
        let missed = FieldValue::Object(vec![
            ("mapping_id", FieldValue::Null),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("miss")),
        ]);
        let non_wire = FieldValue::Object(vec![
            ("mapping_id", FieldValue::Text("m-1")),
            ("wire_generation", FieldValue::Null),
            ("wire_identity", FieldValue::Null),
        ]);
        let null_mapping_known = FieldValue::Object(vec![
            ("mapping_id", FieldValue::Null),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Text("known")),
        ]);
        let null_identity_wired = FieldValue::Object(vec![
            ("mapping_id", FieldValue::Text("m-1")),
            ("wire_generation", FieldValue::UInt(3)),
            ("wire_identity", FieldValue::Null),
        ]);
        let unknown_offset = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Null),
            ("offset_known", FieldValue::Bool(false)),
            ("offset", FieldValue::Null),
            ("length", FieldValue::UInt(512)),
        ]);
        let known_without_offset = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("offset_known", FieldValue::Bool(true)),
            ("offset", FieldValue::Null),
            ("length", FieldValue::UInt(512)),
        ]);
        let unknown_with_offset = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("offset_known", FieldValue::Bool(false)),
            ("offset", FieldValue::UInt(128)),
            ("length", FieldValue::UInt(512)),
        ]);
        let resolved = FieldValue::Object(vec![
            ("region_id", FieldValue::Text("r-1")),
            ("requested_state", FieldValue::Text("private")),
            ("success", FieldValue::Bool(false)),
            ("return_code", FieldValue::Null),
            ("offset", FieldValue::UInt(0)),
            ("length", FieldValue::UInt(4096)),
            ("address_space", FieldValue::Text("iova")),
            ("resolution", FieldValue::Text("unresolved")),
            ("generation", FieldValue::Int(2)),
        ]);
        let zero_generation = FieldValue::Object(vec![
            ("region_id", FieldValue::Text("r-1")),
            ("requested_state", FieldValue::Text("shared")),
            ("success", FieldValue::Bool(true)),
            ("return_code", FieldValue::Int(0)),
            ("offset", FieldValue::UInt(0)),
            ("length", FieldValue::UInt(4096)),
            ("generation", FieldValue::Int(0)),
        ]);
        let unknown_pool = FieldValue::Object(vec![
            ("pool_id", FieldValue::Text("swiotlb")),
            ("used_bytes", FieldValue::Null),
            ("capacity_bytes", FieldValue::Null),
            ("unit", FieldValue::Text("unknown")),
            ("reason", FieldValue::Text("denied")),
        ]);
        let paged_pool = FieldValue::Object(vec![
            ("pool_id", FieldValue::Text("swiotlb")),
            ("used_bytes", FieldValue::UInt(1)),
            ("capacity_bytes", FieldValue::UInt(2)),
            ("unit", FieldValue::Text("pages")),
        ]);
        let unknown_loss = FieldValue::Object(vec![
            ("channel", FieldValue::Text("terminal")),
            ("lost_count", FieldValue::Null),
            ("reason", FieldValue::Text("dropped")),
            ("window_start_ns", FieldValue::UInt(100)),
            ("window_end_ns", FieldValue::UInt(200)),
        ]);
        let empty_reason = FieldValue::Object(vec![
            ("channel", FieldValue::Text("detail")),
            ("lost_count", FieldValue::UInt(3)),
            ("reason", FieldValue::Text("")),
            ("window_start_ns", FieldValue::UInt(100)),
            ("window_end_ns", FieldValue::UInt(200)),
        ]);
        let device_scope = FieldValue::Object(vec![
            ("counter_id", FieldValue::Text("c")),
            ("epoch", FieldValue::UInt(0)),
            (
                "scope",
                FieldValue::Object(vec![
                    ("device_id", FieldValue::Text("dev-1")),
                    ("profile_id", FieldValue::Text("p-1")),
                ]),
            ),
            ("value", FieldValue::UInt(0)),
            ("unit", FieldValue::Text("u")),
        ]);
        let empty_scope = FieldValue::Object(vec![
            ("counter_id", FieldValue::Text("c")),
            ("epoch", FieldValue::UInt(0)),
            ("scope", FieldValue::Object(vec![])),
            ("value", FieldValue::UInt(0)),
            ("unit", FieldValue::Text("u")),
        ]);
        let flagged_copy = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("direction", FieldValue::Text("bounce_to_original")),
            ("bytes", FieldValue::UInt(512)),
            ("pool_private", FieldValue::Bool(true)),
            ("offset_past_allocation", FieldValue::Bool(true)),
        ]);
        let sideways_copy = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("direction", FieldValue::Text("sideways")),
            ("bytes", FieldValue::UInt(512)),
        ]);
        let rows: Vec<(&str, &str, FieldValue, FieldValue, bool)> = vec![
            (
                "unassigned map",
                "map_result",
                unassigned,
                probe_source(),
                true,
            ),
            (
                "failed wire map",
                "map_result",
                failed_wire,
                probe_source(),
                true,
            ),
            (
                "success without mapping",
                "map_result",
                success_without_mapping,
                probe_source(),
                false,
            ),
            (
                "failure with mapping",
                "map_result",
                failed_with_mapping,
                probe_source(),
                false,
            ),
            (
                "null generation with known identity",
                "map_result",
                null_generation_known,
                probe_source(),
                false,
            ),
            ("missed unmap", "unmap", missed, probe_source(), true),
            ("non-wire unmap", "unmap", non_wire, probe_source(), true),
            (
                "null mapping with known identity",
                "unmap",
                null_mapping_known,
                probe_source(),
                false,
            ),
            (
                "null identity on wire",
                "unmap",
                null_identity_wired,
                probe_source(),
                false,
            ),
            (
                "unknown sync offset",
                "sync_request",
                unknown_offset,
                probe_source(),
                true,
            ),
            (
                "known sync offset missing",
                "sync_request",
                known_without_offset,
                probe_source(),
                false,
            ),
            (
                "unknown sync offset valued",
                "sync_request",
                unknown_with_offset,
                probe_source(),
                false,
            ),
            (
                "resolved transition",
                "transition_result",
                resolved,
                probe_source(),
                true,
            ),
            (
                "zero transition generation",
                "transition_result",
                zero_generation,
                probe_source(),
                false,
            ),
            (
                "unknown pool reading",
                "pool_sample",
                unknown_pool,
                probe_source(),
                true,
            ),
            (
                "paged pool unit",
                "pool_sample",
                paged_pool,
                probe_source(),
                false,
            ),
            (
                "unknown gap loss",
                "gap",
                unknown_loss,
                probe_source(),
                true,
            ),
            (
                "empty gap reason",
                "gap",
                empty_reason,
                probe_source(),
                false,
            ),
            (
                "device counter scope",
                "counter_snapshot",
                device_scope,
                probe_source(),
                true,
            ),
            (
                "empty counter scope",
                "counter_snapshot",
                empty_scope,
                probe_source(),
                false,
            ),
            ("flagged copy", "copy", flagged_copy, probe_source(), true),
            (
                "sideways copy",
                "copy",
                sideways_copy,
                probe_source(),
                false,
            ),
            ("derived copy", "copy", copy_payload(), derived, false),
        ];
        for (name, kind, payload, source, expect) in rows {
            let line = versioned_line(0, "0.3.0", kind, source, payload, None);
            let snapshot = sealed_kind_snapshot(std::slice::from_ref(&line), &[(kind, 1)]);
            let report = verify_sealed_snapshot(&snapshot).expect("probe parses");
            assert_eq!(report.verified, expect, "{name}");
        }
    }

    #[test]
    fn seal_gates_copy_extras_on_line_version() {
        let extras = FieldValue::Object(vec![
            ("operation_id", FieldValue::Text("op-1")),
            ("mapping_id", FieldValue::Text("m-1")),
            ("direction", FieldValue::Text("original_to_bounce")),
            ("bytes", FieldValue::UInt(512)),
            ("pool_private", FieldValue::Bool(true)),
            ("offset_past_allocation", FieldValue::Bool(true)),
        ]);
        for (version, expect) in [("0.1.1", false), ("0.1.2", true)] {
            let line = versioned_line(0, version, "copy", probe_source(), extras.clone(), None);
            let snapshot = sealed_legacy_snapshot(std::slice::from_ref(&line), &[("copy", 1)]);
            let report = verify_sealed_snapshot(&snapshot).expect("probe parses");
            assert_eq!(report.verified, expect, "copy extras under {version}");
        }
    }

    #[test]
    fn seal_enforces_source_string_bounds() {
        let hook_over = "x".repeat(257);
        let hook_max = "x".repeat(256);
        let backend_over = "x".repeat(65);
        let backend_max = "x".repeat(64);
        let profile_over = "x".repeat(129);
        let profile_max = "x".repeat(128);
        let rows: Vec<(&str, FieldValue, bool)> = vec![
            (
                "empty hook",
                probe_source_leaf("hook", FieldValue::Text("")),
                false,
            ),
            (
                "overlong hook",
                probe_source_leaf("hook", FieldValue::Text(&hook_over)),
                false,
            ),
            (
                "bounded hook",
                probe_source_leaf("hook", FieldValue::Text(&hook_max)),
                true,
            ),
            (
                "empty backend",
                probe_source_leaf("backend", FieldValue::Text("")),
                false,
            ),
            (
                "overlong backend",
                probe_source_leaf("backend", FieldValue::Text(&backend_over)),
                false,
            ),
            (
                "bounded backend",
                probe_source_leaf("backend", FieldValue::Text(&backend_max)),
                true,
            ),
            (
                "empty profile",
                probe_source_leaf("profile_id", FieldValue::Text("")),
                false,
            ),
            (
                "overlong profile",
                probe_source_leaf("profile_id", FieldValue::Text(&profile_over)),
                false,
            ),
            (
                "bounded profile",
                probe_source_leaf("profile_id", FieldValue::Text(&profile_max)),
                true,
            ),
        ];
        for (name, source, expect) in rows {
            let line = fact_line_with_source(
                0,
                default_fact_data("inventory", "guest_monotonic_active"),
                source.clone(),
            );
            let report =
                verify_sealed_snapshot(&sealed_lines_snapshot(std::slice::from_ref(&line), 1, 0))
                    .expect("probe parses");
            assert_eq!(report.verified, expect, "fact with {name}");
            let marker = versioned_line(
                0,
                "0.3.0",
                "marker",
                source,
                FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]),
                None,
            );
            let report = verify_sealed_snapshot(&sealed_kind_snapshot(
                std::slice::from_ref(&marker),
                &[("marker", 1)],
            ))
            .expect("probe parses");
            assert_eq!(report.verified, expect, "marker with {name}");
        }
    }

    #[test]
    fn seal_validates_observer_context() {
        let context = FieldValue::Object(vec![
            ("cpu", FieldValue::Int(3)),
            ("pid", FieldValue::Int(100)),
            ("tgid", FieldValue::Int(100)),
            ("comm", FieldValue::Text("memveil")),
            ("cgroup_id", FieldValue::Text("cgroup-1")),
            ("relation", FieldValue::Text("execution_context_only")),
        ]);
        let line = versioned_line(
            0,
            "0.1.1",
            "bounce_attempt",
            probe_source(),
            bounce_payload(),
            Some(context.clone()),
        );
        let snapshot =
            sealed_legacy_snapshot(std::slice::from_ref(&line), &[("bounce_attempt", 1)]);
        let report = verify_sealed_snapshot(&snapshot).expect("control parses");
        assert!(report.verified, "legacy context must verify");
        let bad = FieldValue::Object(vec![("relation", FieldValue::Text("owner"))]);
        let line = versioned_line(
            0,
            "0.1.1",
            "bounce_attempt",
            probe_source(),
            bounce_payload(),
            Some(bad),
        );
        let snapshot =
            sealed_legacy_snapshot(std::slice::from_ref(&line), &[("bounce_attempt", 1)]);
        let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
        assert!(!report.verified, "bad legacy context cannot verify");
        let modern = versioned_line(
            0,
            "0.3.0",
            "marker",
            probe_source(),
            FieldValue::Object(vec![("text", FieldValue::Text("census sealed"))]),
            Some(context),
        );
        let snapshot = sealed_kind_snapshot(std::slice::from_ref(&modern), &[("marker", 1)]);
        let report = verify_sealed_snapshot(&snapshot).expect("tainted parses");
        assert!(
            !report.verified,
            "0.3.0 line with observer context cannot verify"
        );
    }

    /// One quality block with every channel reporting the given
    /// status and loss.
    fn probe_quality_all(status: &'static str, loss: FieldValue<'static>) -> FieldValue<'static> {
        let mut channels: Vec<(&'static str, FieldValue<'static>)> = Vec::new();
        for name in ["detail", "aggregate", "identity", "baseline", "terminal"] {
            channels.push((
                name,
                FieldValue::Object(vec![
                    ("status", FieldValue::Text(status)),
                    ("loss_count", loss.clone()),
                ]),
            ));
        }
        FieldValue::Object(channels)
    }

    /// One coverage-source entry carrying the given status and quality.
    ///
    /// The row is fully valid: catalog capability, opaque profile,
    /// frozen subject, cell, namespace, phase and reason, and an
    /// ordered window, so usability failures pin the quality block
    /// rather than the metadata.
    fn probe_coverage_source(
        status: &'static str,
        quality: FieldValue<'static>,
    ) -> FieldValue<'static> {
        probe_coverage_identity(
            status,
            quality,
            "guest-direct-map",
            "pre_attach",
            1_000_000_000,
            4_000_000_000,
            "adapter-unimplemented",
        )
    }

    /// One coverage-source entry with the given status, quality and identity.
    ///
    /// The subject, phase, window and reason vary across rows of one
    /// source; every other leaf stays catalog-valid.
    #[allow(clippy::too_many_arguments)]
    fn probe_coverage_identity(
        status: &'static str,
        quality: FieldValue<'static>,
        subject: &'static str,
        phase: &'static str,
        window_start_ns: u64,
        window_end_ns: u64,
        reason: &'static str,
    ) -> FieldValue<'static> {
        FieldValue::Object(vec![
            ("source_id", FieldValue::Text("sharing-census")),
            ("capability", FieldValue::Text("census")),
            ("profile_id", FieldValue::Text("synthetic-census-1")),
            ("subject_id", FieldValue::Text(subject)),
            ("platform_cell", FieldValue::Text("ordinary-linux")),
            ("address_namespace", FieldValue::Text("guest_physical")),
            ("phase", FieldValue::Text(phase)),
            ("status", FieldValue::Text(status)),
            ("reason", FieldValue::Text(reason)),
            (
                "window",
                FieldValue::Object(vec![
                    ("start_ns", FieldValue::UInt(window_start_ns)),
                    ("end_ns", FieldValue::UInt(window_end_ns)),
                ]),
            ),
            ("quality", quality),
        ])
    }

    /// One snapshot carrying the given coverage sources and no lines.
    fn source_snapshot(sources: Vec<FieldValue<'_>>) -> String {
        render_canonical(&[
            (
                "session",
                FieldValue::Object(vec![
                    ("schema_version", FieldValue::Text("0.3.0")),
                    ("session_id", FieldValue::Text(PROBE_SESSION)),
                    (
                        "exposure",
                        FieldValue::Object(vec![("sources", FieldValue::Array(sources))]),
                    ),
                ]),
            ),
            ("event_lines", FieldValue::Array(vec![])),
        ])
        .unwrap()
    }

    #[test]
    fn snapshot_source_evidence_reads_quality() {
        let settled = probe_quality_all("complete_for_scope", FieldValue::UInt(0));
        let snapshot = source_snapshot(vec![probe_coverage_source("available", settled)]);
        let evidence =
            snapshot_source_evidence(&snapshot, "sharing-census").expect("reads evidence");
        assert!(evidence.present);
        assert_eq!(evidence.status, "available");
        assert!(evidence.quality_usable);

        let missing = probe_quality_all("unavailable", FieldValue::Null);
        let snapshot = source_snapshot(vec![probe_coverage_source("partial", missing)]);
        let evidence =
            snapshot_source_evidence(&snapshot, "sharing-census").expect("reads evidence");
        assert!(evidence.present);
        assert_eq!(evidence.status, "partial");
        assert!(!evidence.quality_usable, "no usable channel");

        let snapshot = source_snapshot(vec![probe_coverage_source(
            "partial",
            quality_with_status("detail", "unavailable"),
        )]);
        let evidence =
            snapshot_source_evidence(&snapshot, "sharing-census").expect("reads evidence");
        assert!(evidence.quality_usable, "one usable channel suffices");

        let absent =
            snapshot_source_evidence(&snapshot, "egress-controls").expect("reads evidence");
        assert!(!absent.present);
        assert_eq!(absent.status, "");
        assert!(!absent.quality_usable);

        let bare = render_canonical(&[
            (
                "session",
                FieldValue::Object(vec![
                    ("schema_version", FieldValue::Text("0.3.0")),
                    ("session_id", FieldValue::Text(PROBE_SESSION)),
                ]),
            ),
            ("event_lines", FieldValue::Array(vec![])),
        ])
        .unwrap();
        let err = snapshot_source_evidence(&bare, "sharing-census").unwrap_err();
        assert_eq!(err.what, "exposure");
    }
}
