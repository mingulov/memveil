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
//! The module is self-contained on purpose: it compiles both as
//! `capture::exposure_records` once integration adds that declaration
//! and through a path include in the lane's own integration test. It
//! takes no live input and performs no I/O. Lexical scalar checks that
//! need reader context stay with the owning reader; the normalizer
//! canonicalizes structure, field order and string quoting, carries
//! signed integers as written, and refuses bare integers for u64
//! leaves and anything without a canonical order.

use std::fmt;

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

/// Digest of the empty event stream.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

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
            if U64_LEAVES.contains(&key) && !is_canonical_u64(text) {
                return Err(RecordError::new(key, "non-canonical u64"));
            }
            quote_into(out, text);
            Ok(())
        }
        JsonValue::Num(number) => {
            if U64_LEAVES.contains(&key) {
                return Err(RecordError::new(key, "non-canonical u64"));
            }
            out.extend_from_slice(number.as_bytes());
            Ok(())
        }
        JsonValue::Bool(true) => {
            out.extend_from_slice(b"true");
            Ok(())
        }
        JsonValue::Bool(false) => {
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
            JsonValue::Num(number) => out.extend_from_slice(number.as_bytes()),
            JsonValue::Bool(true) => out.extend_from_slice(b"true"),
            JsonValue::Bool(false) => out.extend_from_slice(b"false"),
            JsonValue::Null => out.extend_from_slice(b"null"),
            JsonValue::Array(_) | JsonValue::Object(_) => {
                return Err(RecordError::new(key, "nested composite"));
            }
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
            JsonValue::Array(items) => render_array(key, items, out),
            JsonValue::Object(_) => Err(RecordError::new(key, "no canonical order")),
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
    const KEYS: [&str; 7] = [
        "algorithm",
        "events_bytes",
        "line_count",
        "first_seq",
        "last_seq",
        "events_sha256",
        "kinds",
    ];
    for key in KEYS {
        if find_field(fields, key).is_none() {
            return Err(SealError::new("integrity", "missing field"));
        }
    }
    for (key, _) in fields {
        if !KEYS.contains(&key.as_str()) {
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

/// Seal verification outcome over a snapshot's literal bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealReport {
    /// True only when the committed seal matches the literal bytes.
    pub verified: bool,
    /// Committed stream bytes; zero when unsealed.
    pub bytes: u64,
    /// Committed line count; zero when unsealed.
    pub lines: u64,
}

fn line_kind(line: &str) -> Option<String> {
    let value = parse_value(line).ok()?;
    let JsonValue::Object(fields) = &value else {
        return None;
    };
    let JsonValue::Str(kind) = find_field(fields, "kind")? else {
        return None;
    };
    if LEGACY_KINDS.contains(&kind.as_str()) || kind == EXPOSURE_FACT_KIND {
        Some(kind.clone())
    } else {
        None
    }
}

/// Verify one sealed snapshot: a session object plus its literal lines.
///
/// The snapshot carries `session` with `capture.integrity` and
/// `event_lines` holding the literal line bytes as JSON strings.
/// Malformed snapshot framing is an error; a well-formed snapshot
/// whose bytes, counts or kind census differ from the commitment
/// verifies false. An absent integrity object verifies false: no
/// unsealed sidecar can supply policy evidence.
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
    let Some(JsonValue::Array(lines)) = find_field(top, "event_lines") else {
        return Err(SealError::new("event_lines", "expected array"));
    };
    let mut literal: Vec<u8> = Vec::new();
    let mut kinds: Vec<String> = Vec::new();
    let mut lines_ok = true;
    for line in lines {
        let JsonValue::Str(text) = line else {
            return Err(SealError::new("event_lines", "expected string lines"));
        };
        literal.extend_from_slice(text.as_bytes());
        match line_kind(text) {
            Some(kind) => kinds.push(kind),
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
        return Ok(unsealed);
    };
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

/// Re-render a parsed integrity object for the seal parser.
fn render_ordered_for_seal(
    fields: &[(String, JsonValue)],
    out: &mut Vec<u8>,
) -> Result<(), SealError> {
    const ORDER: [&str; 7] = [
        "algorithm",
        "events_bytes",
        "line_count",
        "first_seq",
        "last_seq",
        "events_sha256",
        "kinds",
    ];
    out.push(b'{');
    let mut first = true;
    for key in ORDER {
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
/// refused, never merged.
pub fn check_evidence_keys(keys: &[EvidenceKey]) -> Result<(), RecordError> {
    let mut seen: Vec<&str> = Vec::new();
    for key in keys {
        if seen.contains(&key.evidence_id) {
            return Err(RecordError::new("evidence_id", "duplicate evidence"));
        }
        seen.push(key.evidence_id);
    }
    for (index, key) in keys.iter().enumerate() {
        for other in &keys[index + 1..] {
            if key.source_id == other.source_id && key.epoch != other.epoch {
                return Err(RecordError::new("source_id", "cross-epoch evidence"));
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
}
