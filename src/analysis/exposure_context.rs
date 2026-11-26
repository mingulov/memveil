// SPDX-License-Identifier: GPL-3.0-or-later
//! Egress context over persisted allowlisted control snapshots.
//!
//! The reader turns one fixture-shaped snapshot into timed typed
//! facts for swap, dump, hibernation, module, channel, NIC, and
//! device controls, plus explicit resample gaps. It consumes
//! snapshot text only: no live source, no full command, no
//! environment, no log, and no payload is ever read. Each fact
//! stands on its own sample; the reader never merges samples,
//! never interpolates across a gap, and never derives an
//! encryption state from a name. Facts describe control state
//! alone and stay silent about whether anything crossed a boundary.
//!
//! The module is self-contained on purpose: it declares no parent
//! items, so it compiles both under its public module path and
//! through a direct path include in tests. It performs no I/O.
//! Its JSON parser is intentionally small and duplicated per
//! reader rather than shared, so no wiring change is needed.

use std::fmt;

/// Snapshot format marker this reader accepts.
pub const FIXTURE_FORMAT: &str = "exposure-context-fixture/0.1.0";
/// Catalog source id this reader accepts.
pub const SOURCE_ID: &str = "egress-controls";
/// Samples refused above this count rather than truncated.
pub const MAX_SAMPLES: usize = 4096;

/// Controls this reader reports; anything else refuses the sample.
pub const KNOWN_CONTROLS: &[&str] = &[
    "swap",
    "dump",
    "hibernation",
    "module",
    "channel",
    "nic",
    "device",
];

/// Frozen clock domains (exposure catalog vocabularies).
pub const KNOWN_CLOCK_DOMAINS: &[&str] = &[
    "guest_monotonic_active",
    "guest_boottime_elapsed",
    "external_trusted_interval",
];

/// Detail keys the reader carries; anything else refuses the sample.
pub const DETAIL_KEYS: &[&str] = &[
    "backing",
    "encryption",
    "path_state",
    "mode",
    "channel",
    "name",
    "writeback",
];

/// Sample keys that refuse the whole read: full commands,
/// environments, logs, and payloads never enter a fact.
pub const FORBIDDEN_KEYS: &[&str] = &[
    "command",
    "command_line",
    "full_command",
    "environment",
    "env",
    "log",
    "logs",
    "payload",
    "content",
    "data",
    "bytes",
    "address",
    "source_path",
];

/// Value fragments that refuse the whole read: raw memory
/// device paths and movement-claim wording never enter a fact.
pub const FORBIDDEN_VALUES: &[&str] = &["dev/mem", "kcore", "/proc/", "exfil"];

/// Native results the reader maps; anything else refuses the sample.
pub const NATIVE_OBSERVED: i64 = 0;
/// Native result meaning metadata access was denied.
pub const NATIVE_DENIED: i64 = -13;
/// Native result meaning the control is unsupported.
pub const NATIVE_UNSUPPORTED: i64 = -22;

/// One timed typed control fact; each fact stands on its own sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextFact {
    /// Session-unique handle, `{capture_id}:{sample_id}`.
    pub evidence_id: String,
    /// Sample tick in the snapshot clock domain.
    pub tick: u64,
    /// Control this fact reports.
    pub control: String,
    /// One of `observed`, `denied`, `unsupported`.
    pub status: String,
    /// Swap backing label, when stated.
    pub backing: Option<String>,
    /// Encryption label from the explicit field only;
    /// `unknown` whenever the field is absent.
    pub encryption: Option<String>,
    /// Path resolution label, when stated.
    pub path_state: Option<String>,
    /// Control mode label, when stated.
    pub mode: Option<String>,
    /// Management channel label, when stated.
    pub channel: Option<String>,
    /// Short object name, when stated; never a full command.
    pub name: Option<String>,
    /// Writeback label, when stated.
    pub writeback: Option<String>,
}

/// One explicit resample gap: ticks the snapshot never covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// Last covered tick before the gap.
    pub from_tick: u64,
    /// First covered tick after the gap.
    pub to_tick: u64,
    /// Ticks spanned, `to_tick - from_tick`.
    pub ticks: u64,
}

/// One read snapshot: facts, gaps, and refusal count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// Capture the snapshot belongs to.
    pub capture_id: String,
    /// Bounded facts in snapshot order.
    pub facts: Vec<ContextFact>,
    /// Explicit gaps in tick order.
    pub gaps: Vec<Gap>,
    /// Samples refused without guessing.
    pub refused_samples: usize,
}

/// One snapshot read failure naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    /// Field or check that failed.
    pub what: String,
    /// Machine-stable reason.
    pub message: String,
}

impl ReadError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReadError(what={}, message={})", self.what, self.message)
    }
}

impl std::error::Error for ReadError {}

/// Parsed JSON value; numbers stay integers only.
enum JsonValue {
    Null,
    // Kept so literals parse; no control field reads a boolean.
    #[allow(dead_code)]
    Bool(bool),
    Num(i64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(Vec<(String, JsonValue)>),
}

/// Nesting limit for snapshot text.
const MAX_DEPTH: usize = 16;

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

    fn expect(&mut self, byte: u8, what: &str) -> Result<(), ReadError> {
        if self.peek() == Some(byte) {
            self.pos += 1;
            Ok(())
        } else {
            Err(ReadError::new(what, "unexpected byte"))
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<JsonValue, ReadError> {
        if depth > MAX_DEPTH {
            return Err(ReadError::new("snapshot", "too deep"));
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
            _ => Err(ReadError::new("snapshot", "unexpected byte")),
        }
    }

    fn parse_literal(&mut self, word: &str, value: JsonValue) -> Result<JsonValue, ReadError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(ReadError::new("snapshot", "unexpected byte"))
        }
    }

    fn parse_object(&mut self, depth: usize) -> Result<JsonValue, ReadError> {
        self.expect(b'{', "snapshot")?;
        let mut fields: Vec<(String, JsonValue)> = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(JsonValue::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(ReadError::new("snapshot", "expected key"));
            }
            let key = self.parse_string()?;
            if fields.iter().any(|(seen, _)| *seen == key) {
                return Err(ReadError::new(key, "duplicate key"));
            }
            self.skip_ws();
            self.expect(b':', "snapshot")?;
            let value = self.parse_value(depth + 1)?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(JsonValue::Object(fields));
                }
                _ => return Err(ReadError::new("snapshot", "unexpected byte")),
            }
        }
    }

    fn parse_array(&mut self, depth: usize) -> Result<JsonValue, ReadError> {
        self.expect(b'[', "snapshot")?;
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
                _ => return Err(ReadError::new("snapshot", "unexpected byte")),
            }
        }
    }

    fn parse_hex4(&mut self) -> Result<u32, ReadError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(ReadError::new("string", "bad escape"));
        }
        let mut unit: u32 = 0;
        for offset in 0..4 {
            let digit = self.bytes[self.pos + offset];
            let value = match digit {
                b'0'..=b'9' => u32::from(digit - b'0'),
                b'a'..=b'f' => u32::from(digit - b'a') + 10,
                b'A'..=b'F' => u32::from(digit - b'A') + 10,
                _ => return Err(ReadError::new("string", "bad escape")),
            };
            unit = unit * 16 + value;
        }
        self.pos += 4;
        Ok(unit)
    }

    fn parse_string(&mut self) -> Result<String, ReadError> {
        self.expect(b'"', "string")?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let byte = self
                .peek()
                .ok_or_else(|| ReadError::new("string", "unterminated"))?;
            self.pos += 1;
            match byte {
                b'"' => {
                    return String::from_utf8(out)
                        .map_err(|_| ReadError::new("string", "invalid text"));
                }
                b'\\' => {
                    let mark = self
                        .peek()
                        .ok_or_else(|| ReadError::new("string", "unterminated"))?;
                    self.pos += 1;
                    match mark {
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
                            if (0xD800..0xE000).contains(&unit) {
                                return Err(ReadError::new("string", "bad escape"));
                            }
                            let glyph = char::from_u32(unit)
                                .ok_or_else(|| ReadError::new("string", "bad escape"))?;
                            let mut encoded = [0u8; 4];
                            out.extend_from_slice(glyph.encode_utf8(&mut encoded).as_bytes());
                        }
                        _ => return Err(ReadError::new("string", "bad escape")),
                    }
                }
                0x00..=0x1F => return Err(ReadError::new("string", "raw control")),
                _ => out.push(byte),
            }
        }
    }

    fn parse_integer(&mut self) -> Result<i64, ReadError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else if matches!(self.peek(), Some(b'1'..=b'9')) {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        } else {
            return Err(ReadError::new("number", "bad integer"));
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err(ReadError::new("number", "non-integer number"));
        }
        let text = &self.bytes[start..self.pos];
        let rendered =
            std::str::from_utf8(text).map_err(|_| ReadError::new("number", "bad integer"))?;
        rendered
            .parse::<i64>()
            .map_err(|_| ReadError::new("number", "integer overflow"))
    }
}

/// Parse one JSON value and require end of input.
fn parse_value(text: &str) -> Result<JsonValue, ReadError> {
    let mut parser = Parser::new(text);
    let value = parser.parse_value(0)?;
    parser.skip_ws();
    if parser.peek().is_some() {
        return Err(ReadError::new("snapshot", "trailing bytes"));
    }
    Ok(value)
}

fn find_field<'v>(fields: &'v [(String, JsonValue)], key: &str) -> Option<&'v JsonValue> {
    fields
        .iter()
        .find(|(seen, _)| seen == key)
        .map(|(_, value)| value)
}

fn as_object<'v>(value: &'v JsonValue, what: &str) -> Result<&'v [(String, JsonValue)], ReadError> {
    match value {
        JsonValue::Object(fields) => Ok(fields),
        _ => Err(ReadError::new(what, "expected object")),
    }
}

fn as_array<'v>(value: &'v JsonValue, what: &str) -> Result<&'v [JsonValue], ReadError> {
    match value {
        JsonValue::Array(items) => Ok(items),
        _ => Err(ReadError::new(what, "expected array")),
    }
}

fn as_str<'v>(value: &'v JsonValue, what: &str) -> Result<&'v str, ReadError> {
    match value {
        JsonValue::Str(text) => Ok(text),
        _ => Err(ReadError::new(what, "expected string")),
    }
}

fn as_num(value: &JsonValue, what: &str) -> Result<i64, ReadError> {
    match value {
        JsonValue::Num(number) => Ok(*number),
        _ => Err(ReadError::new(what, "expected integer")),
    }
}

fn required<'v>(fields: &'v [(String, JsonValue)], key: &str) -> Result<&'v JsonValue, ReadError> {
    find_field(fields, key).ok_or_else(|| ReadError::new(key, "missing field"))
}

/// Refuse forbidden keys and value fragments in one object.
fn check_object_clean(fields: &[(String, JsonValue)]) -> Result<(), ReadError> {
    for (key, value) in fields {
        if FORBIDDEN_KEYS.contains(&key.as_str()) {
            return Err(ReadError::new(key.clone(), "forbidden field refused"));
        }
        if let JsonValue::Str(text) = value {
            for fragment in FORBIDDEN_VALUES {
                if text.contains(fragment) {
                    return Err(ReadError::new(key.clone(), "forbidden value refused"));
                }
            }
        }
    }
    Ok(())
}

fn status_name(native_result: i64) -> Option<&'static str> {
    match native_result {
        NATIVE_OBSERVED => Some("observed"),
        NATIVE_DENIED => Some("denied"),
        NATIVE_UNSUPPORTED => Some("unsupported"),
        _ => None,
    }
}

fn detail_string(detail: &[(String, JsonValue)], key: &str) -> Option<String> {
    match find_field(detail, key) {
        Some(JsonValue::Str(text)) => Some(text.clone()),
        _ => None,
    }
}

/// Read one egress-context snapshot into timed facts and gaps.
///
/// Unknown controls, ticks, or native results refuse the sample
/// and count it in `refused_samples`; nothing is guessed. Gaps
/// wider than the resample interval stay explicit records; the
/// reader never fills them. Forbidden fields or values refuse
/// the whole read. The snapshot's `expected` block, when
/// present, is never consulted.
pub fn read_context(text: &str) -> Result<Context, ReadError> {
    let root = parse_value(text)?;
    let fields = as_object(&root, "snapshot")?;
    let format = as_str(required(fields, "format")?, "format")?;
    if format != FIXTURE_FORMAT {
        return Err(ReadError::new("format", "unknown snapshot format"));
    }
    let source = as_str(required(fields, "source_id")?, "source_id")?;
    if source != SOURCE_ID {
        return Err(ReadError::new("source_id", "unexpected source"));
    }
    let capture = as_str(required(fields, "capture_id")?, "capture_id")?;
    if capture.is_empty() {
        return Err(ReadError::new("capture_id", "empty capture"));
    }
    let clock = as_str(required(fields, "clock_domain")?, "clock_domain")?;
    if !KNOWN_CLOCK_DOMAINS.contains(&clock) {
        return Err(ReadError::new("clock_domain", "unknown clock"));
    }
    let resample = as_object(required(fields, "resample")?, "resample")?;
    let interval = as_num(
        required(resample, "interval_ticks")?,
        "resample.interval_ticks",
    )?;
    if interval <= 0 {
        return Err(ReadError::new(
            "resample.interval_ticks",
            "non-positive interval",
        ));
    }
    let interval = interval as u64;
    let samples = as_array(required(fields, "samples")?, "samples")?;
    if samples.len() > MAX_SAMPLES {
        return Err(ReadError::new("samples", "too many samples"));
    }
    let mut facts = Vec::new();
    let mut refused = 0usize;
    let mut seen: Vec<String> = Vec::new();
    for sample in samples {
        let sample_fields = as_object(sample, "samples")?;
        check_object_clean(sample_fields)?;
        let detail = match find_field(sample_fields, "detail") {
            Some(JsonValue::Object(detail)) => detail,
            _ => {
                refused += 1;
                continue;
            }
        };
        check_object_clean(detail)?;
        let sample_id = match find_field(sample_fields, "sample_id") {
            Some(JsonValue::Str(text)) if !text.is_empty() => text.clone(),
            _ => {
                refused += 1;
                continue;
            }
        };
        if seen.contains(&sample_id) {
            return Err(ReadError::new("sample_id", "duplicate sample"));
        }
        seen.push(sample_id.clone());
        match read_sample_usable(&sample_id, capture, sample_fields, detail) {
            Some(fact) => facts.push(fact),
            None => refused += 1,
        }
    }
    let mut ticks: Vec<u64> = facts.iter().map(|fact| fact.tick).collect();
    ticks.sort();
    let mut gaps = Vec::new();
    for pair in ticks.windows(2) {
        let span = pair[1] - pair[0];
        if span > interval {
            gaps.push(Gap {
                from_tick: pair[0],
                to_tick: pair[1],
                ticks: span,
            });
        }
    }
    Ok(Context {
        capture_id: capture.to_string(),
        facts,
        gaps,
        refused_samples: refused,
    })
}

/// Extract a usable sample fact; `None` refuses without guessing.
///
/// Only the allowlisted sample keys are read; any other key
/// refuses the sample. Denied samples drop every detail field.
/// Encryption comes from the explicit field alone: a missing
/// field yields `unknown` no matter what any name suggests.
fn read_sample_usable(
    sample_id: &str,
    capture: &str,
    sample_fields: &[(String, JsonValue)],
    detail: &[(String, JsonValue)],
) -> Option<ContextFact> {
    const KNOWN: &[&str] = &["sample_id", "tick", "control", "native_result", "detail"];
    for (key, _) in sample_fields {
        if !KNOWN.contains(&key.as_str()) {
            return None;
        }
    }
    for (key, value) in detail {
        if !DETAIL_KEYS.contains(&key.as_str()) {
            return None;
        }
        if !matches!(value, JsonValue::Str(_)) {
            return None;
        }
    }
    let tick = match find_field(sample_fields, "tick") {
        Some(JsonValue::Num(number)) if *number >= 0 => *number as u64,
        _ => return None,
    };
    let control = match find_field(sample_fields, "control") {
        Some(JsonValue::Str(text)) if KNOWN_CONTROLS.contains(&text.as_str()) => text.clone(),
        _ => return None,
    };
    let native = match find_field(sample_fields, "native_result") {
        Some(JsonValue::Num(number)) => *number,
        _ => return None,
    };
    let status = status_name(native)?;
    let denied = native == NATIVE_DENIED;
    let encryption = if denied {
        None
    } else {
        Some(detail_string(detail, "encryption").unwrap_or_else(|| "unknown".to_string()))
    };
    let pick = |key: &str| {
        if denied {
            None
        } else {
            detail_string(detail, key)
        }
    };
    Some(ContextFact {
        evidence_id: format!("{capture}:{sample_id}"),
        tick,
        control,
        status: status.to_string(),
        backing: pick("backing"),
        encryption,
        path_state: pick("path_state"),
        mode: pick("mode"),
        channel: pick("channel"),
        name: pick("name"),
        writeback: pick("writeback"),
    })
}
