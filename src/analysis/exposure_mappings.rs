// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping inventory over persisted allowlisted metadata snapshots.
//!
//! The reader turns one fixture-shaped snapshot into bounded
//! mapping-class/peer/configuration facts plus an explicit DAX
//! presence/support status. It consumes snapshot text only: no
//! live source, no raw memory device, no payload, no address,
//! and no command is ever read. Facts carry labels alone; equal
//! mapping-class names never merge distinct trust boundaries,
//! and a DAX access claim exists only when separately proved.
//!
//! The module is self-contained on purpose: it declares no parent
//! items, so it compiles both under its public module path and
//! through a direct path include in tests. It performs no I/O.
//! Its JSON parser is intentionally small and duplicated per
//! reader rather than shared, so no wiring change is needed.

use std::fmt;

/// Snapshot format marker this reader accepts.
pub const FIXTURE_FORMAT: &str = "mapping-inventory-fixture/0.1.0";
/// Catalog source id this reader accepts.
pub const SOURCE_ID: &str = "mapping-inventory-scan";
/// Address namespace admitted for inventory entries.
pub const ADDRESS_NAMESPACE: &str = "guest_physical";
/// Entries refused above this count rather than truncated.
pub const MAX_ENTRIES: usize = 4096;

/// Frozen peer classes (exposure catalog vocabularies).
pub const KNOWN_PEER_CLASSES: &[&str] = &[
    "none-observed",
    "host-device",
    "device-or-subsystem",
    "device",
    "host-hypervisor",
    "host-tdx-module",
    "host-or-paravisor",
];

/// Entry keys that refuse the whole read: raw memory handles,
/// payloads, addresses, and commands never enter a fact.
pub const FORBIDDEN_KEYS: &[&str] = &[
    "address",
    "phys_addr",
    "virt_addr",
    "payload",
    "content",
    "data",
    "bytes",
    "source_path",
    "command",
    "command_line",
    "environment",
    "env",
    "log",
    "logs",
];

/// Value fragments that refuse the whole read: raw memory
/// device paths never enter a fact.
pub const FORBIDDEN_VALUES: &[&str] = &["dev/mem", "kcore", "/proc/"];

/// Native results the reader maps; anything else refuses the entry.
pub const NATIVE_PRESENT: i64 = 0;
/// Native result meaning access was denied.
pub const NATIVE_DENIED: i64 = -13;
/// Native result meaning the class is unsupported.
pub const NATIVE_UNSUPPORTED: i64 = -22;

/// One bounded inventory fact: labels only, no mapping bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingFact {
    /// Session-unique handle, `{capture_id}:{entry_id}`.
    pub evidence_id: String,
    /// Mapping class label; never a trust verdict on its own.
    pub mapping_class: String,
    /// Frozen peer class label.
    pub peer_class: String,
    /// Opaque boundary label carried verbatim.
    pub trust_boundary: String,
    /// One of `present`, `denied`, `unsupported`.
    pub configuration: String,
}

/// Explicit DAX status: presence and support stay visible while
/// an access claim exists only when separately proved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaxStatus {
    /// One of `present`, `absent`, `unknown`.
    pub presence: String,
    /// One of `supported`, `unsupported`, `unknown`.
    pub support: String,
    /// Proved claim only; `None` whenever unproved.
    pub access_claim: Option<String>,
}

/// One read snapshot: facts, DAX status, and refusal count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inventory {
    /// Capture the snapshot belongs to.
    pub capture_id: String,
    /// Always [`SOURCE_ID`].
    pub source_id: String,
    /// Bounded facts in snapshot order.
    pub facts: Vec<MappingFact>,
    /// Explicit DAX status.
    pub dax: DaxStatus,
    /// Entries refused without guessing.
    pub refused_entries: usize,
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

fn as_bool(value: &JsonValue, what: &str) -> Result<bool, ReadError> {
    match value {
        JsonValue::Bool(flag) => Ok(*flag),
        _ => Err(ReadError::new(what, "expected boolean")),
    }
}

fn required<'v>(fields: &'v [(String, JsonValue)], key: &str) -> Result<&'v JsonValue, ReadError> {
    find_field(fields, key).ok_or_else(|| ReadError::new(key, "missing field"))
}

/// Refuse forbidden keys and raw-device value fragments in one object.
fn check_object_clean(fields: &[(String, JsonValue)], what: &str) -> Result<(), ReadError> {
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
    let _ = what;
    Ok(())
}

fn configuration_name(native_result: i64) -> Option<&'static str> {
    match native_result {
        NATIVE_PRESENT => Some("present"),
        NATIVE_DENIED => Some("denied"),
        NATIVE_UNSUPPORTED => Some("unsupported"),
        _ => None,
    }
}

/// Read one mapping-inventory snapshot into bounded facts.
///
/// Unknown peers, namespaces, classes, or native results refuse
/// the entry and count it in `refused_entries`; nothing is
/// guessed. Forbidden fields or raw-device values refuse the
/// whole read. The snapshot's `expected` block, when present,
/// is never consulted.
pub fn read_inventory(text: &str) -> Result<Inventory, ReadError> {
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
    let entries = as_array(required(fields, "entries")?, "entries")?;
    if entries.len() > MAX_ENTRIES {
        return Err(ReadError::new("entries", "too many entries"));
    }
    let dax_fields = as_object(required(fields, "dax")?, "dax")?;
    check_object_clean(dax_fields, "dax")?;
    let presence = as_str(required(dax_fields, "presence")?, "dax.presence")?;
    if !matches!(presence, "present" | "absent" | "unknown") {
        return Err(ReadError::new("dax.presence", "unknown presence"));
    }
    let support = as_str(required(dax_fields, "support")?, "dax.support")?;
    if !matches!(support, "supported" | "unsupported" | "unknown") {
        return Err(ReadError::new("dax.support", "unknown support"));
    }
    let proved = as_bool(required(dax_fields, "access_proved")?, "dax.access_proved")?;
    let claim = match required(dax_fields, "access_claim")? {
        JsonValue::Null => None,
        JsonValue::Str(text) => Some(text.clone()),
        _ => {
            return Err(ReadError::new(
                "dax.access_claim",
                "expected string or null",
            ));
        }
    };
    if claim.is_some() && !proved {
        return Err(ReadError::new(
            "dax.access_claim",
            "access claim without proof refused",
        ));
    }
    let mut facts = Vec::new();
    let mut refused = 0usize;
    let mut seen: Vec<String> = Vec::new();
    for entry in entries {
        let entry_fields = as_object(entry, "entries")?;
        check_object_clean(entry_fields, "entries")?;
        let entry_id = match find_field(entry_fields, "entry_id") {
            Some(value) => as_str(value, "entry_id")?.to_string(),
            None => {
                refused += 1;
                continue;
            }
        };
        if entry_id.is_empty() || seen.contains(&entry_id) {
            if seen.contains(&entry_id) {
                return Err(ReadError::new("entry_id", "duplicate entry"));
            }
            refused += 1;
            continue;
        }
        seen.push(entry_id.clone());
        let usable = read_entry_usable(entry_fields);
        match usable {
            Some((class, peer, boundary, configuration)) => facts.push(MappingFact {
                evidence_id: format!("{capture}:{entry_id}"),
                mapping_class: class,
                peer_class: peer,
                trust_boundary: boundary,
                configuration: configuration.to_string(),
            }),
            None => refused += 1,
        }
    }
    Ok(Inventory {
        capture_id: capture.to_string(),
        source_id: source.to_string(),
        facts,
        dax: DaxStatus {
            presence: presence.to_string(),
            support: support.to_string(),
            access_claim: claim,
        },
        refused_entries: refused,
    })
}

/// Extract usable entry labels; `None` refuses without guessing.
///
/// Only the allowlisted entry keys are read; `alias_of` may ride
/// along as a string but never changes the fact, and any other
/// unknown key refuses the entry.
fn read_entry_usable(
    entry_fields: &[(String, JsonValue)],
) -> Option<(String, String, String, &str)> {
    const KNOWN: &[&str] = &[
        "entry_id",
        "mapping_class",
        "peer_class",
        "trust_boundary",
        "address_namespace",
        "native_result",
        "alias_of",
    ];
    for (key, _) in entry_fields {
        if !KNOWN.contains(&key.as_str()) {
            return None;
        }
    }
    if let Some(alias) = find_field(entry_fields, "alias_of")
        && !matches!(alias, JsonValue::Str(_))
    {
        return None;
    }
    let class = match find_field(entry_fields, "mapping_class") {
        Some(JsonValue::Str(text)) if !text.is_empty() => text.clone(),
        _ => return None,
    };
    let peer = match find_field(entry_fields, "peer_class") {
        Some(JsonValue::Str(text)) if KNOWN_PEER_CLASSES.contains(&text.as_str()) => text.clone(),
        _ => return None,
    };
    let boundary = match find_field(entry_fields, "trust_boundary") {
        Some(JsonValue::Str(text)) if !text.is_empty() => text.clone(),
        _ => return None,
    };
    match find_field(entry_fields, "address_namespace") {
        Some(JsonValue::Str(text)) if text == ADDRESS_NAMESPACE => {}
        _ => return None,
    }
    let native = match find_field(entry_fields, "native_result") {
        Some(JsonValue::Num(number)) => *number,
        _ => return None,
    };
    configuration_name(native).map(|name| (class, peer, boundary, name))
}
