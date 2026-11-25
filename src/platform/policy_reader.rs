// SPDX-License-Identifier: GPL-3.0-or-later
//! Policy file reader: bounded input plus strict shape checks.
//!
//! Reads one `policy-v0.1.0` document (frozen public text
//! `docs/exposure-policy.md`) into the evaluator model. The
//! reader enforces every documented bound — at most 1 MiB,
//! 1,024 rules, 64 exceptions per rule, 64-char ASCII
//! identifiers — and refuses duplicate keys, conflicting
//! rule ids, unknown kinds, and empty scopes, so no
//! malformed policy can produce a vacuous pass. Selectors
//! stay finite enumerated fields with exact labels; there
//! are no expressions and no patterns.
//!
//! The JSON parser below is dependency-free on purpose: the
//! crate carries no JSON library, and the policy surface is
//! small enough for a strict purpose-built reader with
//! duplicate-key detection and a nesting cap.
//!
//! Integration wiring: the lane test includes this file via
//! `#[path]`, so the model import below resolves through
//! the test crate root. When the controller moves this file
//! under `platform/`, point the import at the wired model
//! home (for example `crate::analysis::exposure_policy`).

use crate::exposure_policy::{
    Exception, KNOWN_CLOCK_DOMAINS, KNOWN_LIFECYCLE_STATUSES, Obligation, POLICY_SCHEMA,
    POLICY_SCHEMA_VERSION, Policy, Prerequisites, Rule,
};
use std::collections::HashSet;
use std::io::Read;
use std::path::Path;

/// Policy file cap in bytes (1 MiB).
pub const MAX_POLICY_BYTES: usize = 1_048_576;
/// Policy rule cap.
pub const MAX_RULES: usize = 1024;
/// Exception cap per rule.
pub const MAX_EXCEPTIONS_PER_RULE: usize = 64;
/// Identifier cap in bytes (ASCII only).
pub const MAX_ID_BYTES: usize = 64;
/// JSON nesting cap.
pub const MAX_JSON_DEPTH: usize = 64;
/// Human-note cap in chars.
pub const MAX_NOTE_CHARS: usize = 1024;
/// Workload-note cap in chars.
pub const MAX_WORKLOAD_CHARS: usize = 256;
/// Required-source cap.
pub const MAX_SOURCES: usize = 1024;
/// Logical-role binding cap.
pub const MAX_ROLE_BINDINGS: usize = 1024;
/// Admitted-label cap per exception.
pub const MAX_EXCEPTION_VALUES: usize = 64;

/// One parsed JSON value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    /// JSON null.
    Null,
    /// JSON boolean.
    Bool(bool),
    /// JSON string, escapes decoded.
    Str(String),
    /// JSON number in source spelling.
    Num(String),
    /// JSON array.
    Arr(Vec<Json>),
    /// JSON object in source order.
    Obj(Vec<(String, Json)>),
}

/// One read refusal. Callers match on `code`, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadError {
    /// Machine-stable refusal code.
    pub code: &'static str,
    /// Human detail; never matched on.
    pub message: String,
}

impl ReadError {
    fn new(code: &'static str, message: String) -> Self {
        Self { code, message }
    }
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ReadError(code={}, message={})", self.code, self.message)
    }
}

impl std::error::Error for ReadError {}

/// Read and validate one policy file.
pub fn read_policy_file(path: &Path) -> Result<Policy, ReadError> {
    // Bound the read itself: one byte past the cap is
    // enough to prove too-big, and an endless source
    // must never be read to the end first.
    let file = std::fs::File::open(path).map_err(|err| {
        ReadError::new("io-error", format!("cannot read {}: {err}", path.display()))
    })?;
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| {
            ReadError::new("io-error", format!("cannot read {}: {err}", path.display()))
        })?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err(ReadError::new(
            "too-big",
            format!(
                "policy file is {} bytes, cap is {MAX_POLICY_BYTES}",
                bytes.len()
            ),
        ));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| ReadError::new("malformed", "policy file is not UTF-8".to_string()))?;
    parse_policy_text(&text)
}

/// Parse and validate one policy document held in memory.
pub fn parse_policy_text(text: &str) -> Result<Policy, ReadError> {
    if text.len() > MAX_POLICY_BYTES {
        return Err(ReadError::new(
            "too-big",
            format!(
                "policy text is {} bytes, cap is {MAX_POLICY_BYTES}",
                text.len()
            ),
        ));
    }
    let root = parse_json(text)?;
    build_policy(&root)
}

/// Canonical decimal u64: digits only, no sign or leading
/// zeros, range checked. Mirrors the repository integer
/// convention for serialized counts.
pub fn parse_decimal_u64(text: &str) -> Result<u64, ReadError> {
    if text.is_empty() || text.len() > 20 {
        return Err(ReadError::new(
            "bad-integer",
            format!("integer {text:?} is not canonical decimal"),
        ));
    }
    if text.len() > 1 && text.starts_with('0') {
        return Err(ReadError::new(
            "bad-integer",
            format!("integer {text:?} has leading zeros"),
        ));
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ReadError::new(
            "bad-integer",
            format!("integer {text:?} is not canonical decimal"),
        ));
    }
    text.parse::<u64>()
        .map_err(|_| ReadError::new("bad-integer", format!("integer {text:?} overflows u64")))
}

/// Width in bytes of the UTF-8 sequence starting
/// with `lead`, or `None` for a stray continuation
/// byte. Overlong forms and out-of-range leads are
/// rejected; the caller validates the sliced bytes.
fn utf8_char_width(lead: u8) -> Option<usize> {
    if lead < 0x80 {
        Some(1)
    } else if (0xC2..=0xDF).contains(&lead) {
        Some(2)
    } else if (0xE0..=0xEF).contains(&lead) {
        Some(3)
    } else if (0xF0..=0xF4).contains(&lead) {
        Some(4)
    } else {
        None
    }
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

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.pos += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn fail(&self, what: &str) -> ReadError {
        ReadError::new("malformed", format!("{what} at byte {}", self.pos))
    }

    fn value(&mut self, depth: usize) -> Result<Json, ReadError> {
        self.skip_ws();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(b'-') | Some(b'0'..=b'9') => Ok(Json::Num(self.number()?)),
            _ => Err(self.fail("unexpected value")),
        }
    }

    fn literal(&mut self, word: &str, value: Json) -> Result<Json, ReadError> {
        if self.bytes[self.pos..].starts_with(word.as_bytes()) {
            self.pos += word.len();
            Ok(value)
        } else {
            Err(self.fail("bad literal"))
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, ReadError> {
        if depth >= MAX_JSON_DEPTH {
            return Err(ReadError::new(
                "too-deep",
                "object nests past 64".to_string(),
            ));
        }
        self.next();
        let mut pairs = Vec::new();
        let mut seen = HashSet::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.next();
            return Ok(Json::Obj(pairs));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(self.fail("object key must be a string"));
            }
            let key = self.string()?;
            if !seen.insert(key.clone()) {
                return Err(ReadError::new(
                    "duplicate-key",
                    format!("duplicate key {key:?}"),
                ));
            }
            self.skip_ws();
            if self.next() != Some(b':') {
                return Err(self.fail("object key lacks a colon"));
            }
            pairs.push((key, self.value(depth + 1)?));
            self.skip_ws();
            match self.next() {
                Some(b',') => {}
                Some(b'}') => return Ok(Json::Obj(pairs)),
                _ => return Err(self.fail("object lacks a separator")),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, ReadError> {
        if depth >= MAX_JSON_DEPTH {
            return Err(ReadError::new(
                "too-deep",
                "array nests past 64".to_string(),
            ));
        }
        self.next();
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.next();
            return Ok(Json::Arr(items));
        }
        loop {
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.next() {
                Some(b',') => {}
                Some(b']') => return Ok(Json::Arr(items)),
                _ => return Err(self.fail("array lacks a separator")),
            }
        }
    }

    fn hex4(&mut self) -> Result<u32, ReadError> {
        if self.pos + 4 > self.bytes.len() {
            return Err(self.fail("short unicode escape"));
        }
        let mut unit = 0u32;
        for _ in 0..4 {
            let digit = self.next().unwrap_or(0);
            let value = match digit {
                b'0'..=b'9' => (digit - b'0') as u32,
                b'a'..=b'f' => (digit - b'a' + 10) as u32,
                b'A'..=b'F' => (digit - b'A' + 10) as u32,
                _ => return Err(self.fail("bad unicode escape")),
            };
            unit = unit * 16 + value;
        }
        Ok(unit)
    }

    fn push_unit(out: &mut String, unit: u32) -> Result<(), ReadError> {
        char::from_u32(unit).map_or_else(
            || {
                Err(ReadError::new(
                    "malformed",
                    "bad unicode scalar".to_string(),
                ))
            },
            |ch| {
                out.push(ch);
                Ok(())
            },
        )
    }

    fn string(&mut self) -> Result<String, ReadError> {
        self.next();
        let mut out = String::new();
        loop {
            let Some(byte) = self.next() else {
                return Err(self.fail("unterminated string"));
            };
            match byte {
                b'"' => return Ok(out),
                b'\\' => match self.next() {
                    Some(b'"') => out.push('"'),
                    Some(b'\\') => out.push('\\'),
                    Some(b'/') => out.push('/'),
                    Some(b'b') => out.push('\u{8}'),
                    Some(b'f') => out.push('\u{c}'),
                    Some(b'n') => out.push('\n'),
                    Some(b'r') => out.push('\r'),
                    Some(b't') => out.push('\t'),
                    Some(b'u') => {
                        let unit = self.hex4()?;
                        if (0xD800..0xDC00).contains(&unit) {
                            if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                                return Err(self.fail("lone surrogate half"));
                            }
                            let low = self.hex4()?;
                            if !(0xDC00..0xE000).contains(&low) {
                                return Err(self.fail("lone surrogate half"));
                            }
                            let scalar = 0x1_0000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                            Self::push_unit(&mut out, scalar)?;
                        } else if (0xDC00..0xE000).contains(&unit) {
                            return Err(self.fail("lone surrogate half"));
                        } else {
                            Self::push_unit(&mut out, unit)?;
                        }
                    }
                    _ => return Err(self.fail("bad escape")),
                },
                0x00..=0x1F => return Err(self.fail("control byte in string")),
                _ => {
                    // The buffer is valid UTF-8 (`parse_json`
                    // takes `&str`), so decode exactly one
                    // scalar value instead of re-validating the
                    // whole tail on every character.
                    let start = self.pos - 1;
                    let width = utf8_char_width(byte)
                        .ok_or_else(|| self.fail("bad UTF-8 in string"))?;
                    let end = start + width;
                    if end > self.bytes.len() {
                        return Err(self.fail("bad UTF-8 in string"));
                    }
                    let text = std::str::from_utf8(&self.bytes[start..end])
                        .map_err(|_| self.fail("bad UTF-8 in string"))?;
                    let ch = text.chars().next().ok_or_else(|| self.fail("bad UTF-8"))?;
                    out.push(ch);
                    self.pos = end;
                }
            }
        }
    }

    fn number(&mut self) -> Result<String, ReadError> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => {
                self.pos += 1;
                if matches!(self.peek(), Some(b'0'..=b'9')) {
                    return Err(self.fail("leading zero in number"));
                }
            }
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.pos += 1;
                }
            }
            _ => return Err(self.fail("bad number")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.fail("bad fraction"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.fail("bad exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.pos += 1;
            }
        }
        Ok(String::from_utf8_lossy(&self.bytes[start..self.pos]).into_owned())
    }
}

/// Parse one JSON document with duplicate-key detection.
pub fn parse_json(text: &str) -> Result<Json, ReadError> {
    let mut parser = Parser::new(text);
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(parser.fail("trailing bytes"));
    }
    Ok(value)
}

fn obj<'a>(value: &'a Json, what: &str) -> Result<&'a Vec<(String, Json)>, ReadError> {
    match value {
        Json::Obj(pairs) => Ok(pairs),
        _ => Err(ReadError::new(
            "type-error",
            format!("{what} must be an object"),
        )),
    }
}

fn arr<'a>(value: &'a Json, what: &str) -> Result<&'a [Json], ReadError> {
    match value {
        Json::Arr(items) => Ok(items),
        _ => Err(ReadError::new(
            "type-error",
            format!("{what} must be an array"),
        )),
    }
}

fn text<'a>(value: &'a Json, what: &str) -> Result<&'a str, ReadError> {
    match value {
        Json::Str(s) => Ok(s),
        _ => Err(ReadError::new(
            "type-error",
            format!("{what} must be a string"),
        )),
    }
}

fn field<'a>(pairs: &'a [(String, Json)], key: &str, what: &str) -> Result<&'a Json, ReadError> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .ok_or_else(|| ReadError::new("missing-field", format!("{what} lacks {key}")))
}

fn unknown_fields(pairs: &[(String, Json)], known: &[&str], what: &str) -> Result<(), ReadError> {
    for (key, _) in pairs {
        if !known.contains(&key.as_str()) {
            return Err(ReadError::new(
                "unknown-field",
                format!("{what} carries unknown field {key:?}"),
            ));
        }
    }
    Ok(())
}

fn is_id(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_ID_BYTES
        && text.bytes().all(|b| (0x21..=0x7E).contains(&b))
}

fn identifier(value: &Json, what: &str) -> Result<String, ReadError> {
    let raw = text(value, what)?;
    if !is_id(raw) {
        return Err(ReadError::new(
            "bad-id",
            format!("{what} must be 1..=64 ASCII identifier bytes"),
        ));
    }
    Ok(raw.to_string())
}

fn plain_note(
    value: &Json,
    what: &str,
    max: usize,
    code: &'static str,
) -> Result<String, ReadError> {
    let raw = text(value, what)?;
    if raw.is_empty() || raw.chars().count() > max || raw.chars().any(|ch| ch < '\u{20}') {
        return Err(ReadError::new(
            code,
            format!("{what} must be non-empty plain text within {max} chars"),
        ));
    }
    Ok(raw.to_string())
}

fn build_policy(root: &Json) -> Result<Policy, ReadError> {
    let top = obj(root, "policy")?;
    unknown_fields(
        top,
        &[
            "schema",
            "schema_version",
            "policy_id",
            "subject_scope",
            "applies_to",
            "required_sources",
            "clock",
            "role_bindings",
            "rules",
            "exceptions",
            "prerequisites",
            "expected_findings",
        ],
        "policy",
    )?;
    if text(field(top, "schema", "policy")?, "schema")? != POLICY_SCHEMA {
        return Err(ReadError::new(
            "bad-version",
            "schema must be \"policy\"".to_string(),
        ));
    }
    if text(field(top, "schema_version", "policy")?, "schema_version")? != POLICY_SCHEMA_VERSION {
        return Err(ReadError::new(
            "bad-version",
            format!("schema_version must be {POLICY_SCHEMA_VERSION:?}"),
        ));
    }
    let policy_id = identifier(field(top, "policy_id", "policy")?, "policy_id")?;
    let scope_raw = text(field(top, "subject_scope", "policy")?, "subject_scope")?;
    if scope_raw.is_empty() {
        return Err(ReadError::new(
            "empty-scope",
            "subject_scope is empty".to_string(),
        ));
    }
    let subject_scope = identifier(field(top, "subject_scope", "policy")?, "subject_scope")?;
    let applies = obj(field(top, "applies_to", "policy")?, "applies_to")?;
    unknown_fields(applies, &["platform", "profile"], "applies_to")?;
    let platform = identifier(field(applies, "platform", "applies_to")?, "platform")?;
    let profile = identifier(field(applies, "profile", "applies_to")?, "profile")?;
    let sources = arr(
        field(top, "required_sources", "policy")?,
        "required_sources",
    )?;
    if sources.is_empty() {
        return Err(ReadError::new(
            "empty-scope",
            "required_sources is empty".to_string(),
        ));
    }
    if sources.len() > MAX_SOURCES {
        return Err(ReadError::new(
            "too-many-sources",
            format!("{} required sources exceed {MAX_SOURCES}", sources.len()),
        ));
    }
    let mut required_sources = Vec::with_capacity(sources.len());
    let mut seen_sources = HashSet::new();
    for entry in sources {
        let source = identifier(entry, "required source")?;
        if !seen_sources.insert(source.clone()) {
            return Err(ReadError::new(
                "duplicate-source",
                format!("required source {source:?} repeats"),
            ));
        }
        required_sources.push(source);
    }
    let clock = text(field(top, "clock", "policy")?, "clock")?;
    if !KNOWN_CLOCK_DOMAINS.contains(&clock) {
        return Err(ReadError::new(
            "unknown-clock",
            format!("clock {clock:?} is outside the frozen domains"),
        ));
    }
    let mut role_bindings = Vec::new();
    if let Some(bindings) = top
        .iter()
        .find(|(k, _)| k == "role_bindings")
        .map(|(_, v)| v)
    {
        let pairs = obj(bindings, "role_bindings")?;
        if pairs.len() > MAX_ROLE_BINDINGS {
            return Err(ReadError::new(
                "too-many-bindings",
                format!("{} role bindings exceed {MAX_ROLE_BINDINGS}", pairs.len()),
            ));
        }
        for (key, value) in pairs {
            if !is_id(key) {
                return Err(ReadError::new(
                    "bad-id",
                    "role binding key is not an id".to_string(),
                ));
            }
            let target = identifier(value, "role binding")?;
            role_bindings.push((key.clone(), target));
        }
        role_bindings.sort();
    }
    let rules = arr(field(top, "rules", "policy")?, "rules")?;
    if rules.is_empty() {
        return Err(ReadError::new("empty-scope", "rules are empty".to_string()));
    }
    if rules.len() > MAX_RULES {
        return Err(ReadError::new(
            "too-many-rules",
            format!("{} rules exceed {MAX_RULES}", rules.len()),
        ));
    }
    let mut parsed_rules = Vec::with_capacity(rules.len());
    let mut seen_rules = HashSet::new();
    for entry in rules {
        let rule = build_rule(entry)?;
        if !seen_rules.insert(rule.rule_id.clone()) {
            return Err(ReadError::new(
                "duplicate-rule",
                format!("rule id {:?} repeats", rule.rule_id),
            ));
        }
        parsed_rules.push(rule);
    }
    let exceptions = arr(field(top, "exceptions", "policy")?, "exceptions")?;
    let mut parsed_exceptions = Vec::with_capacity(exceptions.len());
    let mut seen_exceptions = HashSet::new();
    let mut per_rule: Vec<(String, usize)> = Vec::new();
    for entry in exceptions {
        let exc = build_exception(entry)?;
        if !parsed_rules.iter().any(|rule| rule.rule_id == exc.rule_id) {
            return Err(ReadError::new(
                "dangling-exception",
                format!("exception {:?} names no rule", exc.exception_id),
            ));
        }
        let target = parsed_rules
            .iter()
            .find(|rule| rule.rule_id == exc.rule_id)
            .expect("rule exists");
        if target.obligation.is_some() {
            return Err(ReadError::new(
                "obligation-exception",
                format!(
                    "exception {:?} names obligation rule {:?}",
                    exc.exception_id, exc.rule_id
                ),
            ));
        }
        if !seen_exceptions.insert(exc.exception_id.clone()) {
            return Err(ReadError::new(
                "duplicate-exception",
                format!("exception id {:?} repeats", exc.exception_id),
            ));
        }
        match per_rule.iter_mut().find(|(id, _)| *id == exc.rule_id) {
            Some((_, count)) => {
                *count += 1;
                if *count > MAX_EXCEPTIONS_PER_RULE {
                    return Err(ReadError::new(
                        "too-many-exceptions",
                        format!(
                            "rule {:?} exceeds {MAX_EXCEPTIONS_PER_RULE} exceptions",
                            exc.rule_id
                        ),
                    ));
                }
            }
            None => per_rule.push((exc.rule_id.clone(), 1)),
        }
        parsed_exceptions.push(exc);
    }
    let prerequisites = top
        .iter()
        .find(|(k, _)| k == "prerequisites")
        .map(|(_, v)| build_prerequisites(v))
        .transpose()?;
    let mut expected_findings = Vec::new();
    if let Some(findings) = top
        .iter()
        .find(|(k, _)| k == "expected_findings")
        .map(|(_, v)| v)
    {
        let list = arr(findings, "expected_findings")?;
        if list.is_empty() {
            return Err(ReadError::new(
                "bad-findings",
                "expected_findings must not be empty".to_string(),
            ));
        }
        for entry in list {
            expected_findings.push(plain_note(
                entry,
                "expected finding",
                MAX_NOTE_CHARS,
                "bad-findings",
            )?);
        }
    }
    Ok(Policy {
        policy_id,
        subject_scope,
        platform,
        profile,
        required_sources,
        clock: clock.to_string(),
        role_bindings,
        rules: parsed_rules,
        exceptions: parsed_exceptions,
        prerequisites,
        expected_findings,
    })
}

fn build_prerequisites(value: &Json) -> Result<Prerequisites, ReadError> {
    let pairs = obj(value, "prerequisites").map_err(|_| {
        ReadError::new(
            "bad-prerequisites",
            "prerequisites must be an object".to_string(),
        )
    })?;
    unknown_fields(pairs, &["platform_cell", "workload"], "prerequisites")
        .map_err(|err| ReadError::new("bad-prerequisites", err.message))?;
    let cell = field(pairs, "platform_cell", "prerequisites").map_err(|_| {
        ReadError::new(
            "bad-prerequisites",
            "prerequisites lack platform_cell".to_string(),
        )
    })?;
    let platform_cell = identifier(cell, "platform_cell").map_err(|_| {
        ReadError::new(
            "bad-prerequisites",
            "platform_cell is not an id".to_string(),
        )
    })?;
    let load = field(pairs, "workload", "prerequisites").map_err(|_| {
        ReadError::new(
            "bad-prerequisites",
            "prerequisites lack workload".to_string(),
        )
    })?;
    let workload = plain_note(load, "workload", MAX_WORKLOAD_CHARS, "bad-prerequisites")?;
    Ok(Prerequisites {
        platform_cell,
        workload,
    })
}

fn build_rule(entry: &Json) -> Result<Rule, ReadError> {
    let pairs = obj(entry, "rule")?;
    unknown_fields(
        pairs,
        &["rule_id", "selector", "permitted", "limit", "obligation"],
        "rule",
    )?;
    let rule_id = identifier(field(pairs, "rule_id", "rule")?, "rule_id")?;
    let obligation = match field(pairs, "obligation", "rule")? {
        Json::Null => None,
        value => Some(build_obligation(value)?),
    };
    let selector = build_selector(field(pairs, "selector", "rule")?, obligation.is_some())?;
    if text(field(pairs, "permitted", "rule")?, "permitted")? != "allowlisted-only" {
        return Err(ReadError::new(
            "unknown-permitted",
            "permitted must be \"allowlisted-only\"".to_string(),
        ));
    }
    let limit = obj(field(pairs, "limit", "rule")?, "limit")?;
    unknown_fields(limit, &["window", "max"], "limit")?;
    if text(field(limit, "window", "limit")?, "window")? != "capture" {
        return Err(ReadError::new(
            "unknown-window",
            "limit window must be \"capture\"".to_string(),
        ));
    }
    let limit_max = parse_decimal_u64(text(field(limit, "max", "limit")?, "max")?)?;
    Ok(Rule {
        rule_id,
        selector,
        permitted: "allowlisted-only".to_string(),
        limit_window: "capture".to_string(),
        limit_max,
        obligation,
    })
}

fn build_selector(value: &Json, obligation: bool) -> Result<Vec<(String, String)>, ReadError> {
    let pairs = obj(value, "selector")?;
    if pairs.is_empty() {
        return Err(ReadError::new(
            "empty-selector",
            "selector must name at least one constraint".to_string(),
        ));
    }
    let mut selector = Vec::with_capacity(pairs.len());
    for (field, value) in pairs {
        let known_fact = matches!(
            field.as_str(),
            "capability"
                | "source_id"
                | "semantics"
                | "peer_class"
                | "clock_domain"
                | "kind"
                | "direction"
                | "caller_class"
        );
        let known_object = matches!(field.as_str(), "object_class" | "source_id");
        if field != "object_class" && field != "source_id" && !known_fact {
            return Err(ReadError::new(
                "unknown-field",
                format!("selector carries unknown field {field:?}"),
            ));
        }
        if obligation && !known_object {
            return Err(ReadError::new(
                "selector-misplaced",
                format!("obligation selector cannot use {field:?}"),
            ));
        }
        if !obligation && field == "object_class" {
            return Err(ReadError::new(
                "selector-misplaced",
                "fact selector cannot use \"object_class\"".to_string(),
            ));
        }
        let label = text(value, "selector value")?;
        if label.is_empty() || label.len() > MAX_ID_BYTES || !label.is_ascii() {
            return Err(ReadError::new(
                "bad-id",
                format!("selector value for {field:?} is not a bounded ASCII label"),
            ));
        }
        selector.push((field.clone(), label.to_string()));
    }
    selector.sort();
    Ok(selector)
}

fn build_obligation(value: &Json) -> Result<Obligation, ReadError> {
    let pairs = obj(value, "obligation")?;
    unknown_fields(pairs, &["status", "within", "clock"], "obligation")?;
    let status = text(field(pairs, "status", "obligation")?, "status")?;
    if !KNOWN_LIFECYCLE_STATUSES.contains(&status) {
        return Err(ReadError::new(
            "unknown-status",
            format!("obligation status {status:?} is outside the frozen statuses"),
        ));
    }
    let within = pairs
        .iter()
        .find(|(k, _)| k == "within")
        .map(|(_, v)| parse_decimal_u64(text(v, "within")?))
        .transpose()?;
    let clock = pairs
        .iter()
        .find(|(k, _)| k == "clock")
        .map(|(_, v)| {
            let name = text(v, "obligation clock")?;
            if !KNOWN_CLOCK_DOMAINS.contains(&name) {
                return Err(ReadError::new(
                    "unknown-clock",
                    format!("obligation clock {name:?} is outside the frozen domains"),
                ));
            }
            Ok(name.to_string())
        })
        .transpose()?;
    match (&within, &clock) {
        (Some(_), None) => {
            return Err(ReadError::new(
                "within-needs-clock",
                "a duration obligation needs its declared clock".to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(ReadError::new(
                "clock-without-duration",
                "an obligation clock needs a declared duration".to_string(),
            ));
        }
        _ => {}
    }
    Ok(Obligation {
        status: status.to_string(),
        within,
        clock,
    })
}

fn build_exception(entry: &Json) -> Result<Exception, ReadError> {
    let pairs = obj(entry, "exception")?;
    unknown_fields(
        pairs,
        &["exception_id", "rule_id", "field", "values", "reason"],
        "exception",
    )?;
    let exception_id = identifier(field(pairs, "exception_id", "exception")?, "exception_id")?;
    let rule_id = identifier(field(pairs, "rule_id", "exception")?, "exception rule")?;
    let field_name = text(field(pairs, "field", "exception")?, "exception field")?;
    match field_name {
        "capability" | "source_id" | "semantics" | "peer_class" | "clock_domain" => {}
        "kind" | "direction" | "caller_class" => {
            return Err(ReadError::new(
                "deferred-field",
                format!("exception field {field_name:?} is deferred vocabulary"),
            ));
        }
        _ => {
            return Err(ReadError::new(
                "unknown-field",
                format!("exception field {field_name:?} is unknown"),
            ));
        }
    }
    let values = arr(field(pairs, "values", "exception")?, "exception values")?;
    if values.is_empty() {
        return Err(ReadError::new(
            "empty-values",
            "exception values must not be empty".to_string(),
        ));
    }
    if values.len() > MAX_EXCEPTION_VALUES {
        return Err(ReadError::new(
            "too-many-values",
            format!(
                "{} exception values exceed {MAX_EXCEPTION_VALUES}",
                values.len()
            ),
        ));
    }
    let mut labels = Vec::with_capacity(values.len());
    for value in values {
        let label = text(value, "exception value")?;
        if label.is_empty() || label.len() > MAX_ID_BYTES || !label.is_ascii() {
            return Err(ReadError::new(
                "bad-id",
                "exception value is not a bounded ASCII label".to_string(),
            ));
        }
        labels.push(label.to_string());
    }
    let reason = plain_note(
        field(pairs, "reason", "exception")?,
        "exception reason",
        MAX_NOTE_CHARS,
        "bad-reason",
    )?;
    Ok(Exception {
        exception_id,
        rule_id,
        field: field_name.to_string(),
        values: labels,
        reason,
    })
}
