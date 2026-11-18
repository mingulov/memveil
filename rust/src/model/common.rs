// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared schema-directed parse helpers.
//!
//! Session and event parsing share nullable-scalar handling. Every helper
//! rejects unknown input; nothing is skipped or defaulted silently.
//!
//! The document parsers own the JSON cursor; these helpers take the
//! already-extracted token (`None` stands for JSON null / an absent
//! field) and keep the scalar acceptance rules identical.
//!
//! Cursor stepping over objects and arrays (`object_is_empty`,
//! `object_next`, `array_is_empty`, `array_next`, `expect_colon`) stays
//! with the document parsers that own the JSON cursor.

use super::validate::{ValidationError, parse_u64};

/// A nullable JSON string: absent and null both clear `has`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaybeString {
    /// True only when a JSON string value was present.
    pub has: bool,
    /// The string value; empty unless `has`.
    pub value: String,
}

impl MaybeString {
    /// An absent value.
    pub fn absent() -> Self {
        Self::default()
    }

    /// A present value.
    pub fn of(value: String) -> Self {
        Self { has: true, value }
    }
}

/// A nullable canonical-u64 JSON string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaybeU64 {
    /// True only when a JSON string value was present.
    pub has: bool,
    /// The parsed value; zero unless `has`.
    pub value: u64,
}

impl MaybeU64 {
    /// An absent value.
    pub fn absent() -> Self {
        Self::default()
    }

    /// A present value.
    pub fn of(value: u64) -> Self {
        Self { has: true, value }
    }
}

/// A nullable JSON integer: absent and null both clear `has`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaybeI64 {
    /// True only when a JSON integer value was present.
    pub has: bool,
    /// The parsed value; zero unless `has`.
    pub value: i64,
}

impl MaybeI64 {
    /// An absent value.
    pub fn absent() -> Self {
        Self::default()
    }

    /// A present value.
    pub fn of(value: i64) -> Self {
        Self { has: true, value }
    }
}

/// Parse a JSON string or null token.
pub fn parse_maybe_string(text: Option<&str>) -> MaybeString {
    match text {
        None => MaybeString::absent(),
        Some(s) => MaybeString::of(s.to_string()),
    }
}

/// Parse a canonical-u64 JSON string or null token.
pub fn parse_maybe_u64(text: Option<&str>) -> Result<MaybeU64, ValidationError> {
    match text {
        None => Ok(MaybeU64::absent()),
        Some(s) => match parse_u64(s) {
            Ok(v) => Ok(MaybeU64::of(v)),
            Err(inner) => Err(ValidationError::wrap("u64", &inner)),
        },
    }
}

/// Parse one JSON integer token with the scanner's exact acceptance.
///
/// Optional `-` sign (no `+`), no leading zeros, i64 range. `-0` parses
/// to `0`. The whole token must be the integer: the document cursor
/// splits the digit run exactly as the Mojo scanner does, so trailing
/// garbage never reaches this function from document parsing.
/// The error is provisional: the owning JSON cursor maps it into its own error type under the reader's field context.
pub fn parse_json_int(text: &str) -> Result<i64, ValidationError> {
    let raw = text.as_bytes();
    let mut pos = 0;
    let mut neg = false;
    if pos < raw.len() && raw[pos] == b'-' {
        neg = true;
        pos += 1;
    }
    if pos >= raw.len() {
        return Err(ValidationError::new("integer", "bad integer"));
    }
    let first = raw[pos];
    if !first.is_ascii_digit() {
        return Err(ValidationError::new("integer", "bad integer"));
    }
    if first == b'0' {
        pos += 1;
        if pos < raw.len() {
            let nxt = raw[pos];
            if nxt.is_ascii_digit() {
                return Err(ValidationError::new("integer", "leading zero"));
            }
            return Err(ValidationError::new("integer", "bad integer"));
        }
        return Ok(0);
    }
    let mut acc: u64 = 0;
    while pos < raw.len() {
        let b = raw[pos];
        if !b.is_ascii_digit() {
            return Err(ValidationError::new("integer", "bad integer"));
        }
        let digit = u64::from(b - b'0');
        if acc > (u64::MAX - digit) / 10 {
            return Err(ValidationError::new("integer", "integer overflow"));
        }
        acc = acc * 10 + digit;
        pos += 1;
    }
    if !neg && acc > i64::MAX as u64 {
        return Err(ValidationError::new("integer", "integer overflow"));
    }
    if neg && acc > i64::MAX as u64 + 1 {
        return Err(ValidationError::new("integer", "integer overflow"));
    }
    if !neg {
        return Ok(acc as i64);
    }
    if acc == i64::MAX as u64 + 1 {
        return Ok(i64::MIN);
    }
    Ok(-(acc as i64))
}

/// Parse a JSON integer or null token.
///
/// Kept for report parsers that need nullable integers; no
/// current caller uses it outside tests.
#[allow(dead_code)]
pub(crate) fn parse_maybe_int(text: Option<&str>) -> Result<MaybeI64, ValidationError> {
    match text {
        None => Ok(MaybeI64::absent()),
        Some(s) => parse_json_int(s).map(MaybeI64::of),
    }
}

/// Parse a required canonical-u64 JSON string token, relabeled under `what`.
pub fn parse_u64_field(text: &str, what: &str) -> Result<u64, ValidationError> {
    parse_u64(text).map_err(|inner| ValidationError::wrap(what, &inner))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maybe_defaults_are_absent() {
        assert!(!MaybeString::default().has);
        assert_eq!(MaybeString::default().value, "");
        assert!(!MaybeU64::default().has);
        assert_eq!(MaybeU64::default().value, 0);
        assert!(!MaybeI64::default().has);
        assert_eq!(MaybeI64::default().value, 0);
    }

    #[test]
    fn maybe_string_null_is_absent() {
        let out = parse_maybe_string(None);
        assert!(!out.has);
        let out = parse_maybe_string(Some("dev-1"));
        assert!(out.has);
        assert_eq!(out.value, "dev-1");
    }

    #[test]
    fn maybe_u64_follows_canonical_u64() {
        let out = parse_maybe_u64(None).unwrap();
        assert!(!out.has);
        let out = parse_maybe_u64(Some("42")).unwrap();
        assert!(out.has);
        assert_eq!(out.value, 42);
        let err = parse_maybe_u64(Some("01")).unwrap_err();
        assert_eq!(err.what, "u64");
        assert_eq!(
            err.message,
            "ValidationError(what=u64, message=leading zero)"
        );
    }

    #[test]
    fn maybe_int_edges() {
        let out = parse_maybe_int(None).unwrap();
        assert!(!out.has);
        assert_eq!(parse_maybe_int(Some("0")).unwrap().value, 0);
        assert_eq!(parse_maybe_int(Some("-0")).unwrap().value, 0);
        assert_eq!(parse_maybe_int(Some("-5")).unwrap().value, -5);
        assert_eq!(
            parse_maybe_int(Some("9223372036854775807")).unwrap().value,
            i64::MAX
        );
        assert_eq!(
            parse_maybe_int(Some("-9223372036854775808")).unwrap().value,
            i64::MIN
        );
    }

    #[test]
    fn maybe_int_refuses() {
        for bad in [
            "",
            "01",
            "-01",
            "+5",
            "4x",
            "9223372036854775808",
            "-9223372036854775809",
        ] {
            assert!(parse_maybe_int(Some(bad)).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn u64_field_relabels_errors() {
        assert_eq!(parse_u64_field("42", "seq"), Ok(42));
        let err = parse_u64_field("01", "seq").unwrap_err();
        assert_eq!(err.what, "seq");
        assert_eq!(
            err.message,
            "ValidationError(what=u64, message=leading zero)"
        );
    }
}
