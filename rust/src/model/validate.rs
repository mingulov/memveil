// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared scalar validators for the frozen v0.1.0 contracts.
//!
//! Canonical u64 strings, opaque identifiers, and bounded text appear in
//! every capture document; one implementation serves the session, event,
//! and report layers so all three refuse the same malformed input.
//!
//! [`ValidationError`] is the shared scalar-failure type for the whole
//! model layer: later document parsers reuse it unchanged. Its display
//! rendering matches the Mojo original
//! (`ValidationError(what=..., message=...)`), and relabeling sites nest
//! the inner rendering inside the new message, exactly as the Mojo
//! `ValidationError(what, String(e))` chain does.

use std::fmt;

/// One scalar validation failure naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationError {
    /// Field or check that failed (e.g. `"u64"`, `"operation_id"`).
    pub what: String,
    /// Machine-stable reason (e.g. `"leading zero"`, `"overflow"`).
    pub message: String,
}

impl ValidationError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }

    /// Relabel an inner failure under a new field, nesting its rendering.
    pub fn wrap(what: impl Into<String>, inner: &ValidationError) -> Self {
        Self {
            what: what.into(),
            message: inner.to_string(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ValidationError(what={}, message={})",
            self.what, self.message
        )
    }
}

impl std::error::Error for ValidationError {}

/// Parse a canonical u64 decimal string.
///
/// Accepts `0` or a non-zero digit followed by up to 19 more digits,
/// then range-checks 0..=18446744073709551615. Anything else is refused:
/// empty input, signs, leading zeros, non-digits, overlong digit runs,
/// and overflow.
pub fn parse_u64(text: &str) -> Result<u64, ValidationError> {
    let raw = text.as_bytes();
    let n = raw.len();
    if n == 0 {
        return Err(ValidationError::new("u64", "empty value"));
    }
    if n > 20 {
        return Err(ValidationError::new("u64", "too many digits"));
    }
    if n > 1 && raw[0] == b'0' {
        return Err(ValidationError::new("u64", "leading zero"));
    }
    let mut acc: u64 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return Err(ValidationError::new("u64", "non-digit"));
        }
        let digit = u64::from(b - b'0');
        if acc > (u64::MAX - digit) / 10 {
            return Err(ValidationError::new("u64", "overflow"));
        }
        acc = acc * 10 + digit;
    }
    Ok(acc)
}

fn is_id_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn is_id_rest(b: u8) -> bool {
    is_id_start(b) || b == b'.' || b == b'-'
}

/// Accept `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` only.
///
/// The pattern is pure ASCII, so a byte scan decides it: any multibyte
/// sequence fails the character classes.
pub fn check_opaque_id(text: &str) -> Result<(), ValidationError> {
    let raw = text.as_bytes();
    let n = raw.len();
    if n == 0 {
        return Err(ValidationError::new("opaque_id", "empty value"));
    }
    if n > 128 {
        return Err(ValidationError::new("opaque_id", "too long"));
    }
    // Byte scan: `str` is UTF-8, so any multibyte lead byte fails the class.
    if !is_id_start(raw[0]) {
        return Err(ValidationError::new("opaque_id", "bad first character"));
    }
    for &b in &raw[1..] {
        if !is_id_rest(b) {
            return Err(ValidationError::new("opaque_id", "bad character"));
        }
    }
    Ok(())
}

/// Canonical decimal rendering: no sign, no leading zeros.
pub fn format_u64(v: u64) -> String {
    v.to_string()
}

/// Add with overflow refused instead of wrapped.
pub fn checked_add(a: u64, b: u64) -> Result<u64, ValidationError> {
    a.checked_add(b)
        .ok_or_else(|| ValidationError::new("add", "overflow"))
}

/// Check code-point length against a schema min/max length.
///
/// JSON Schema string lengths count characters, not UTF-8 bytes, so
/// a 64-code-point multibyte value passes a maxLength of 64.
pub fn check_bounded_text(
    text: &str,
    min_len: usize,
    max_len: usize,
    what: &str,
) -> Result<(), ValidationError> {
    let n = text.chars().count();
    if n < min_len {
        return Err(ValidationError::new(what, "too short"));
    }
    if n > max_len {
        return Err(ValidationError::new(what, "too long"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u64_canonical_edges() {
        assert_eq!(parse_u64("0"), Ok(0));
        assert_eq!(parse_u64("42"), Ok(42));
        assert_eq!(parse_u64("18446744073709551615"), Ok(u64::MAX));
    }

    #[test]
    fn u64_refuses_noncanonical() {
        let cases = [
            "",
            "00",
            "01",
            "-1",
            "+5",
            "4x",
            " 42",
            "18446744073709551616",
            "99999999999999999999999",
            "111111111111111111111",
        ];
        for bad in cases {
            assert!(parse_u64(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn u64_error_identity() {
        let err = parse_u64("").unwrap_err();
        assert_eq!(err.what, "u64");
        assert_eq!(err.message, "empty value");
        assert_eq!(
            parse_u64("111111111111111111111").unwrap_err().message,
            "too many digits"
        );
        assert_eq!(parse_u64("01").unwrap_err().message, "leading zero");
        assert_eq!(parse_u64("4x").unwrap_err().message, "non-digit");
        assert_eq!(
            parse_u64("18446744073709551616").unwrap_err().message,
            "overflow"
        );
    }

    #[test]
    fn opaque_id_accepts() {
        check_opaque_id("a").unwrap();
        check_opaque_id("dev-1").unwrap();
        check_opaque_id("A_0.-x").unwrap();
        check_opaque_id(&("a".to_string() + &"b".repeat(127))).unwrap();
    }

    #[test]
    fn opaque_id_rejects() {
        let long = "a".to_string() + &"b".repeat(128);
        let cases = ["", "-abc", ".x", "a b", "\u{e9}", "a/b", long.as_str()];
        for bad in cases {
            assert!(check_opaque_id(bad).is_err(), "must refuse {bad:?}");
        }
    }

    #[test]
    fn opaque_id_error_identity() {
        let err = check_opaque_id("").unwrap_err();
        assert_eq!(err.what, "opaque_id");
        assert_eq!(err.message, "empty value");
        assert_eq!(
            check_opaque_id(&"a".repeat(129)).unwrap_err().message,
            "too long"
        );
        assert_eq!(
            check_opaque_id("-abc").unwrap_err().message,
            "bad first character"
        );
        assert_eq!(check_opaque_id("a b").unwrap_err().message, "bad character");
    }

    #[test]
    fn bounded_text_counts_codepoints() {
        let sixty_four = "\u{e9}".repeat(64);
        check_bounded_text(&sixty_four, 1, 64, "probe").unwrap();
        let err = check_bounded_text(&format!("{sixty_four}\u{e9}"), 1, 64, "probe").unwrap_err();
        assert_eq!(err.what, "probe");
        assert_eq!(err.message, "too long");
        let err = check_bounded_text("", 1, 64, "probe").unwrap_err();
        assert_eq!(err.message, "too short");
    }

    #[test]
    fn format_u64_renders_canonical() {
        assert_eq!(format_u64(0), "0");
        assert_eq!(format_u64(42), "42");
        assert_eq!(format_u64(u64::MAX), "18446744073709551615");
    }

    #[test]
    fn checked_add_guards_overflow() {
        assert_eq!(checked_add(1, 2), Ok(3));
        assert_eq!(checked_add(u64::MAX, 0), Ok(u64::MAX));
        let err = checked_add(u64::MAX, 1).unwrap_err();
        assert_eq!(err.what, "add");
        assert_eq!(err.message, "overflow");
    }

    #[test]
    fn error_display_matches_mojo_rendering() {
        let err = ValidationError {
            what: "u64".to_string(),
            message: "leading zero".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "ValidationError(what=u64, message=leading zero)"
        );
    }
}
