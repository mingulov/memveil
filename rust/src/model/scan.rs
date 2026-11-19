// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded JSON cursor shared by the capture-document parsers.
//!
//! The event and session parsers read with a schema-directed cursor, never
//! a generic DOM, so every allocation stays proportional to an explicit
//! input bound. This module owns the lowest layer: scalar and structural
//! scanning with validated UTF-8 output, a hard nesting-depth cap, and
//! deferred value spans. Duplicate-key rejection lives with the callers:
//! each object parser tracks the keys it has seen and refuses repeats.
//! Key order is free; the event parser defers its `data` member by source
//! span until the kind is known, then re-parses the span.
//!
//! Error convention: every failure is a [`ValidationError`]. Structural
//! failures (string escapes, booleans, brackets, commas, colons, truncated
//! input, excessive depth) name the enclosing schema object in `what`,
//! keep the scanner message verbatim, and carry the cursor byte offset,
//! so they render as the Mojo `ScanError(offset=..., message=...)`.
//! Offsets step exactly like the scanner ported: a consumed offending
//! byte reports the position behind the cursor (`pos - 1`), anything
//! else reports the cursor itself, and a bad span reports its start.
//! Numeric-token failures wrap the scalar error under the reader's field
//! context: required u64/integer readers use the field path (like
//! `event.seq`), while the generic nullable readers use the scalar name
//! (`u64`, `integer`).

use super::common::{
    MaybeI64, MaybeString, MaybeU64, parse_json_int, parse_maybe_u64,
    parse_u64_field as token_u64_field,
};
use super::validate::{ValidationError, check_opaque_id};

/// Default nesting-depth cap for one document cursor.
pub(crate) const MAX_DEPTH_DEFAULT: usize = 64;

/// Cursor over one bounded JSON document.
///
/// The cursor borrows its input and tracks structural nesting depth so
/// deeply nested values refuse instead of recursing without bound.
pub(crate) struct Scanner<'a> {
    data: &'a [u8],
    pos: usize,
    depth: usize,
    max_depth: usize,
}

impl<'a> Scanner<'a> {
    /// Open a cursor over `data` with the default depth cap.
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            max_depth: MAX_DEPTH_DEFAULT,
        }
    }

    /// Open a cursor with an explicit depth cap.
    ///
    /// Kept for document parsers that need a custom cap; the event and
    /// session parsers use the default.
    #[allow(dead_code)]
    pub(crate) fn with_max_depth(data: &'a [u8], max_depth: usize) -> Self {
        Self {
            data,
            pos: 0,
            depth: 0,
            max_depth,
        }
    }

    /// Current byte offset into the input.
    pub(crate) fn offset(&self) -> usize {
        self.pos
    }

    /// True once the cursor has consumed all input.
    pub(crate) fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// Skip JSON whitespace: space, tab, LF, CR.
    pub(crate) fn skip_ws(&mut self) {
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' {
                self.pos += 1;
            } else {
                break;
            }
        }
    }

    /// Peek the next byte without consuming it.
    pub(crate) fn peek(&self, what: &str) -> Result<u8, ValidationError> {
        if self.pos >= self.data.len() {
            return Err(ValidationError::scan(
                self.pos,
                what,
                "unexpected end of input",
            ));
        }
        Ok(self.data[self.pos])
    }

    /// Parse `true` or `false` with no word-boundary check.
    pub(crate) fn parse_bool(&mut self, what: &str) -> Result<bool, ValidationError> {
        if self.data.len() - self.pos >= 4 && self.match_word(b"true") {
            return Ok(true);
        }
        if self.data.len() - self.pos >= 5 && self.match_word(b"false") {
            return Ok(false);
        }
        Err(ValidationError::scan(self.pos, what, "bad boolean"))
    }

    /// Parse `null`.
    pub(crate) fn parse_null(&mut self, what: &str) -> Result<(), ValidationError> {
        if self.data.len() - self.pos >= 4 && self.match_word(b"null") {
            return Ok(());
        }
        Err(ValidationError::scan(self.pos, what, "bad null"))
    }

    /// Parse one JSON integer, wrapping token failures under `field`.
    ///
    /// Steps exactly like the scanner this ports: an optional `-` sign,
    /// then a maximal digit run. A lone zero consumes one byte; longer
    /// zero-led runs fail the shared token parser, as does a missing
    /// digit run. The provisional token error is wrapped under `field`,
    /// paralleling the required-u64 reader.
    pub(crate) fn parse_int(&mut self, field: &str) -> Result<i64, ValidationError> {
        let start = self.pos;
        let mut pos = start;
        if pos < self.data.len() && self.data[pos] == b'-' {
            pos += 1;
        }
        if pos < self.data.len() && self.data[pos] == b'0' {
            pos += 1;
        }
        while pos < self.data.len() && self.data[pos].is_ascii_digit() {
            pos += 1;
        }
        self.pos = pos;
        let token = &self.data[start..pos];
        let text = core::str::from_utf8(token)
            .map_err(|_| ValidationError::new("integer", "bad integer"))?;
        parse_json_int(text).map_err(|inner| ValidationError::wrap(field, &inner))
    }

    /// Parse one JSON string; the cursor must sit on its quote.
    ///
    /// Raw bytes pass through and escapes decode; the concatenated
    /// result must be valid UTF-8, exactly as in the scanner ported.
    pub(crate) fn parse_string(&mut self, what: &str) -> Result<String, ValidationError> {
        self.expect(what, b'"')?;
        let mut out: Vec<u8> = Vec::new();
        loop {
            let b = self.take(what)?;
            if b == b'"' {
                break;
            }
            if b == b'\\' {
                self.parse_escape(what, &mut out)?;
            } else if b < 0x20 {
                return Err(ValidationError::scan(
                    self.pos - 1,
                    what,
                    "control in string",
                ));
            } else {
                out.push(b);
            }
        }
        String::from_utf8(out)
            .map_err(|_| ValidationError::scan(self.pos, what, "invalid utf-8 in string"))
    }

    /// Consume `{`, enforcing the depth cap.
    pub(crate) fn begin_object(&mut self, what: &str) -> Result<(), ValidationError> {
        self.skip_ws();
        self.expect(what, b'{')?;
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(ValidationError::scan(self.pos, what, "nesting too deep"));
        }
        Ok(())
    }

    /// Consume `}`.
    /// Pairs with [`begin_object`]: each call closes one open level.
    pub(crate) fn end_object(&mut self, what: &str) -> Result<(), ValidationError> {
        self.skip_ws();
        self.expect(what, b'}')?;
        self.depth -= 1;
        Ok(())
    }

    /// Consume `[`, enforcing the depth cap.
    pub(crate) fn begin_array(&mut self, what: &str) -> Result<(), ValidationError> {
        self.skip_ws();
        self.expect(what, b'[')?;
        self.depth += 1;
        if self.depth > self.max_depth {
            return Err(ValidationError::scan(self.pos, what, "nesting too deep"));
        }
        Ok(())
    }

    /// Consume `]`.
    /// Pairs with [`begin_array`]: each call closes one open level.
    pub(crate) fn end_array(&mut self, what: &str) -> Result<(), ValidationError> {
        self.skip_ws();
        self.expect(what, b']')?;
        self.depth -= 1;
        Ok(())
    }

    /// Borrow bytes `[start, end)`: one skipped value's source span.
    pub(crate) fn span_bytes(
        &self,
        what: &str,
        start: usize,
        end: usize,
    ) -> Result<&'a [u8], ValidationError> {
        if end < start || end > self.data.len() {
            return Err(ValidationError::scan(start, what, "bad span"));
        }
        let data: &'a [u8] = self.data;
        Ok(&data[start..end])
    }

    /// Skip one JSON value structurally, enforcing the depth cap.
    ///
    /// Strings are fully validated; numbers are consumed by charset
    /// only, since every skipped span of interest is re-parsed
    /// semantically afterwards.
    pub(crate) fn skip_value(&mut self, what: &str) -> Result<(), ValidationError> {
        self.skip_ws();
        let c = self.peek(what)?;
        if c == b'"' {
            self.parse_string(what)?;
        } else if c == b'{' {
            self.begin_object(what)?;
            self.skip_ws();
            if self.peek(what)? != b'}' {
                loop {
                    self.skip_ws();
                    self.parse_string(what)?;
                    self.skip_ws();
                    self.expect(what, b':')?;
                    self.skip_value(what)?;
                    self.skip_ws();
                    let s = self.peek(what)?;
                    if s == b',' {
                        self.expect(what, b',')?;
                    } else if s == b'}' {
                        break;
                    } else {
                        return Err(ValidationError::scan(self.pos, what, "want , or }"));
                    }
                }
            }
            self.end_object(what)?;
        } else if c == b'[' {
            self.begin_array(what)?;
            self.skip_ws();
            if self.peek(what)? != b']' {
                loop {
                    self.skip_value(what)?;
                    self.skip_ws();
                    let s = self.peek(what)?;
                    if s == b',' {
                        self.expect(what, b',')?;
                    } else if s == b']' {
                        break;
                    } else {
                        return Err(ValidationError::scan(self.pos, what, "want , or ]"));
                    }
                }
            }
            self.end_array(what)?;
        } else if c == b't' || c == b'f' {
            self.parse_bool(what)?;
        } else if c == b'n' {
            self.parse_null(what)?;
        } else {
            self.skip_number(what)?;
        }
        Ok(())
    }

    fn take(&mut self, what: &str) -> Result<u8, ValidationError> {
        if self.pos >= self.data.len() {
            return Err(ValidationError::scan(
                self.pos,
                what,
                "unexpected end of input",
            ));
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn expect(&mut self, what: &str, want: u8) -> Result<(), ValidationError> {
        let got = self.take(what)?;
        if got != want {
            return Err(ValidationError::scan(
                self.pos - 1,
                what,
                format!("expected byte {want}"),
            ));
        }
        Ok(())
    }

    fn match_word(&mut self, word: &[u8]) -> bool {
        if self.pos + word.len() > self.data.len() {
            return false;
        }
        if &self.data[self.pos..self.pos + word.len()] != word {
            return false;
        }
        self.pos += word.len();
        true
    }

    fn skip_number(&mut self, what: &str) -> Result<(), ValidationError> {
        let c = self.peek(what)?;
        if c != b'-' && !c.is_ascii_digit() {
            return Err(ValidationError::scan(self.pos, what, "bad value"));
        }
        while self.pos < self.data.len() {
            let b = self.data[self.pos];
            if b.is_ascii_digit() || b == b'-' || b == b'+' || b == b'.' || b == b'e' || b == b'E' {
                self.pos += 1;
            } else {
                break;
            }
        }
        Ok(())
    }

    fn take_hex4(&mut self, what: &str) -> Result<u32, ValidationError> {
        let mut value: u32 = 0;
        for _ in 0..4 {
            let b = self.take(what)?;
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'A'..=b'F' => u32::from(b - b'A') + 10,
                b'a'..=b'f' => u32::from(b - b'a') + 10,
                _ => return Err(ValidationError::scan(self.pos - 1, what, "bad hex digit")),
            };
            value = value * 16 + digit;
        }
        Ok(value)
    }

    fn emit_utf8(&self, what: &str, out: &mut Vec<u8>, cp: u32) -> Result<(), ValidationError> {
        if cp > 0x10FFFF {
            return Err(ValidationError::scan(
                self.pos,
                what,
                "code point out of range",
            ));
        }
        if (0xD800..0xE000).contains(&cp) {
            return Err(ValidationError::scan(self.pos, what, "lone surrogate"));
        }
        if cp < 0x80 {
            out.push(cp as u8);
        } else if cp < 0x800 {
            out.push((0xC0 | (cp >> 6)) as u8);
            out.push((0x80 | (cp & 0x3F)) as u8);
        } else if cp < 0x10000 {
            out.push((0xE0 | (cp >> 12)) as u8);
            out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
            out.push((0x80 | (cp & 0x3F)) as u8);
        } else {
            out.push((0xF0 | (cp >> 18)) as u8);
            out.push((0x80 | ((cp >> 12) & 0x3F)) as u8);
            out.push((0x80 | ((cp >> 6) & 0x3F)) as u8);
            out.push((0x80 | (cp & 0x3F)) as u8);
        }
        Ok(())
    }

    fn parse_escape(&mut self, what: &str, out: &mut Vec<u8>) -> Result<(), ValidationError> {
        let e = self.take(what)?;
        match e {
            b'"' => out.push(b'"'),
            b'\\' => out.push(b'\\'),
            b'/' => out.push(b'/'),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0C),
            b'n' => out.push(0x0A),
            b'r' => out.push(0x0D),
            b't' => out.push(0x09),
            b'u' => {
                let unit = self.take_hex4(what)?;
                if (0xD800..0xDC00).contains(&unit) {
                    self.expect(what, b'\\')?;
                    self.expect(what, b'u')?;
                    let low = self.take_hex4(what)?;
                    if !(0xDC00..0xE000).contains(&low) {
                        return Err(ValidationError::scan(self.pos, what, "bad low surrogate"));
                    }
                    let cp = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                    self.emit_utf8(what, out, cp)?;
                } else {
                    self.emit_utf8(what, out, unit)?;
                }
            }
            _ => return Err(ValidationError::scan(self.pos - 1, what, "bad escape")),
        }
        Ok(())
    }
}

/// True when the cursor sits on an empty object's closer.
pub(crate) fn object_is_empty(scan: &mut Scanner, what: &str) -> Result<bool, ValidationError> {
    scan.skip_ws();
    Ok(scan.peek(what)? == b'}')
}

/// Consume an object separator; true means another field follows.
pub(crate) fn object_next(scan: &mut Scanner, what: &str) -> Result<bool, ValidationError> {
    scan.skip_ws();
    let c = scan.peek(what)?;
    if c == b',' {
        scan.take(what)?;
        return Ok(true);
    }
    if c == b'}' {
        return Ok(false);
    }
    Err(ValidationError::scan(
        scan.offset(),
        what,
        format!("want , or }} in {what}"),
    ))
}

/// True when the cursor sits on an empty array's closer.
pub(crate) fn array_is_empty(scan: &mut Scanner, what: &str) -> Result<bool, ValidationError> {
    scan.skip_ws();
    Ok(scan.peek(what)? == b']')
}

/// Consume an array separator; true means another item follows.
pub(crate) fn array_next(scan: &mut Scanner, what: &str) -> Result<bool, ValidationError> {
    scan.skip_ws();
    let c = scan.peek(what)?;
    if c == b',' {
        scan.take(what)?;
        return Ok(true);
    }
    if c == b']' {
        return Ok(false);
    }
    Err(ValidationError::scan(
        scan.offset(),
        what,
        format!("want , or ] in {what}"),
    ))
}

/// Consume the colon between an object key and its value.
pub(crate) fn expect_colon(scan: &mut Scanner, what: &str) -> Result<(), ValidationError> {
    scan.skip_ws();
    if scan.peek(what)? != b':' {
        return Err(ValidationError::scan(
            scan.offset(),
            what,
            format!("want : in {what}"),
        ));
    }
    scan.take(what)?;
    scan.skip_ws();
    Ok(())
}

/// Parse a required canonical-u64 JSON string field value.
///
/// The cursor must already sit on the opening quote: like the schema
/// readers this ports, this function does no leading skip; every call
/// site follows [`expect_colon`], which leaves the cursor past trailing
/// whitespace.
pub(crate) fn parse_u64_field(scan: &mut Scanner, what: &str) -> Result<u64, ValidationError> {
    let text = scan.parse_string(what)?;
    token_u64_field(&text, what)
}

/// Parse a JSON string or null at the cursor.
pub(crate) fn parse_nullable_string(
    scan: &mut Scanner,
    what: &str,
) -> Result<Option<String>, ValidationError> {
    scan.skip_ws();
    if scan.peek(what)? == b'n' {
        scan.parse_null(what)?;
        return Ok(None);
    }
    Ok(Some(scan.parse_string(what)?))
}

/// Parse a canonical-u64 JSON string or null at the cursor.
///
/// Token failures wrap under `u64`, matching the shared nullable
/// scalar reader.
pub(crate) fn parse_nullable_u64(
    scan: &mut Scanner,
    what: &str,
) -> Result<MaybeU64, ValidationError> {
    let token = parse_nullable_string(scan, what)?;
    parse_maybe_u64(token.as_deref())
}

/// Parse a JSON integer or null at the cursor.
///
/// Token failures wrap under `integer`, paralleling the nullable
/// u64 reader; the caller supplies `what` for structural failures.
pub(crate) fn parse_nullable_int(
    scan: &mut Scanner,
    what: &str,
) -> Result<MaybeI64, ValidationError> {
    scan.skip_ws();
    if scan.peek(what)? == b'n' {
        scan.parse_null(what)?;
        return Ok(MaybeI64::absent());
    }
    Ok(MaybeI64::of(scan.parse_int("integer")?))
}

/// Parse a required opaque-identifier string, wrapped under `what`.
pub(crate) fn parse_id_field(scan: &mut Scanner, what: &str) -> Result<String, ValidationError> {
    let value = scan.parse_string(what)?;
    check_opaque_id(&value).map_err(|inner| ValidationError::wrap(what, &inner))?;
    Ok(value)
}

/// Parse an opaque-identifier string or null, wrapped under `what`.
pub(crate) fn parse_nullable_id(
    scan: &mut Scanner,
    what: &str,
) -> Result<MaybeString, ValidationError> {
    match parse_nullable_string(scan, what)? {
        None => Ok(MaybeString::absent()),
        Some(value) => {
            check_opaque_id(&value).map_err(|inner| ValidationError::wrap(what, &inner))?;
            Ok(MaybeString::of(value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(text: &str) -> Scanner<'_> {
        Scanner::new(text.as_bytes())
    }

    fn err_of(result: Result<(), ValidationError>) -> (String, String) {
        let err = result.unwrap_err();
        (err.what, err.message)
    }

    #[test]
    fn whitespace_and_peek() {
        let mut s = scan("  \t\n\r{");
        s.skip_ws();
        assert_eq!(s.offset(), 5);
        assert_eq!(s.peek("probe").unwrap(), b'{');
        assert!(!s.at_end());
        let empty = scan("");
        assert!(empty.at_end());
        assert_eq!(
            err_of(empty.peek("probe").map(|_| ())),
            ("probe".to_string(), "unexpected end of input".to_string())
        );
    }

    #[test]
    fn booleans_have_no_word_boundary() {
        assert!(scan("true").parse_bool("c").unwrap());
        assert!(!scan("false").parse_bool("c").unwrap());
        let mut s = scan("trueX");
        assert!(s.parse_bool("c").unwrap());
        assert_eq!(s.offset(), 4);
        assert_eq!(
            err_of(scan("tru").parse_bool("c").map(|_| ())),
            ("c".to_string(), "bad boolean".to_string())
        );
        assert_eq!(
            err_of(scan("yes").parse_bool("c").map(|_| ())),
            ("c".to_string(), "bad boolean".to_string())
        );
    }

    #[test]
    fn null_literal() {
        scan("null").parse_null("c").unwrap();
        assert_eq!(
            err_of(scan("nul").parse_null("c")),
            ("c".to_string(), "bad null".to_string())
        );
    }

    #[test]
    fn integers_step_like_the_scanner() {
        // Zero consumes exactly one byte; trailing garbage is left behind.
        let mut s = scan("0}");
        assert_eq!(s.parse_int("f").unwrap(), 0);
        assert_eq!(s.offset(), 1);
        assert_eq!(scan("-0").parse_int("f").unwrap(), 0);
        let mut s = scan("123,");
        assert_eq!(s.parse_int("f").unwrap(), 123);
        assert_eq!(s.offset(), 3);
        assert_eq!(scan("-42").parse_int("f").unwrap(), -42);
        assert_eq!(
            scan("9223372036854775807").parse_int("f").unwrap(),
            i64::MAX
        );
        assert_eq!(
            scan("-9223372036854775808").parse_int("f").unwrap(),
            i64::MIN
        );
    }

    #[test]
    fn integer_failures_wrap_under_the_field() {
        for bad in ["", "-", "x", "-x"] {
            let err = scan(bad).parse_int("observer.cpu").unwrap_err();
            assert_eq!(err.what, "observer.cpu");
            assert_eq!(
                err.message,
                "ValidationError(what=integer, message=bad integer)"
            );
        }
        let err = scan("00").parse_int("observer.cpu").unwrap_err();
        assert_eq!(err.what, "observer.cpu");
        assert_eq!(
            err.message,
            "ValidationError(what=integer, message=leading zero)"
        );
        let err = scan("-01").parse_int("f").unwrap_err();
        assert!(err.message.ends_with("leading zero)"), "{err}");
        let err = scan("9223372036854775808").parse_int("f").unwrap_err();
        assert!(err.message.ends_with("integer overflow)"), "{err}");
        let err = scan("99999999999999999999999999")
            .parse_int("f")
            .unwrap_err();
        assert!(err.message.ends_with("integer overflow)"), "{err}");
    }

    #[test]
    fn strings_decode_escapes() {
        assert_eq!(scan(r#""abc""#).parse_string("c").unwrap(), "abc");
        assert_eq!(
            scan(r#""\"\\\/\b\f\n\r\t""#).parse_string("c").unwrap(),
            "\"\\/\u{8}\u{c}\n\r\t"
        );
        assert_eq!(
            scan("\"caf\u{e9}\"").parse_string("c").unwrap(),
            "caf\u{e9}"
        );
        assert_eq!(scan(r#""A""#).parse_string("c").unwrap(), "A");
        assert_eq!(scan(r#""\u0041""#).parse_string("c").unwrap(), "A");
        assert_eq!(
            scan(r#""\uD800\uDC00""#).parse_string("c").unwrap(),
            "\u{10000}"
        );
    }

    #[test]
    fn strings_refuse_bad_escapes_and_controls() {
        assert_eq!(
            err_of(scan("\"a\nb\"").parse_string("c").map(|_| ())),
            ("c".to_string(), "control in string".to_string())
        );
        assert_eq!(
            err_of(scan(r#""\x""#).parse_string("c").map(|_| ())),
            ("c".to_string(), "bad escape".to_string())
        );
        assert_eq!(
            err_of(scan(r#""\u12ZZ""#).parse_string("c").map(|_| ())),
            ("c".to_string(), "bad hex digit".to_string())
        );
        assert_eq!(
            err_of(scan(r#""\uDC00""#).parse_string("c").map(|_| ())),
            ("c".to_string(), "lone surrogate".to_string())
        );
        assert_eq!(
            err_of(scan(r#""\uD800x""#).parse_string("c").map(|_| ())),
            ("c".to_string(), "expected byte 92".to_string())
        );
        assert_eq!(
            err_of(scan(r#""\uD800\u0041""#).parse_string("c").map(|_| ())),
            ("c".to_string(), "bad low surrogate".to_string())
        );
        assert_eq!(
            err_of(scan("\"ab").parse_string("c").map(|_| ())),
            ("c".to_string(), "unexpected end of input".to_string())
        );
        let mut raw = Scanner::new(&[0x22, 0xFF, 0x22]);
        assert_eq!(
            err_of(raw.parse_string("c").map(|_| ())),
            ("c".to_string(), "invalid utf-8 in string".to_string())
        );
    }

    #[test]
    fn brackets_enforce_depth() {
        let mut s = Scanner::with_max_depth(b"[{}]", 1);
        s.begin_array("c").unwrap();
        assert_eq!(
            err_of(s.begin_object("c").map(|_| ())),
            ("c".to_string(), "nesting too deep".to_string())
        );
        let mut s = scan("[{}]");
        s.begin_array("c").unwrap();
        s.begin_object("c").unwrap();
        assert!(object_is_empty(&mut s, "c").unwrap());
        s.end_object("c").unwrap();
        s.end_array("c").unwrap();
        assert!(s.at_end());
    }

    #[test]
    fn default_depth_cap_is_64() {
        let deep = "[".repeat(64) + &"]".repeat(64);
        let mut s = scan(&deep);
        for _ in 0..64 {
            s.begin_array("c").unwrap();
        }
        for _ in 0..64 {
            s.end_array("c").unwrap();
        }
        assert!(s.at_end());
        let over = "[".repeat(65);
        let mut s = scan(&over);
        for _ in 0..64 {
            s.begin_array("c").unwrap();
        }
        assert_eq!(
            err_of(s.begin_array("c").map(|_| ())),
            ("c".to_string(), "nesting too deep".to_string())
        );
    }

    #[test]
    fn skip_value_covers_all_shapes() {
        let mut s = scan(r#"{"a": [1, "x", true, null, {"b": 1.5e-3}], "c": {}}"trailing"#);
        s.skip_value("c").unwrap();
        assert_eq!(s.peek("c").unwrap(), b'"');
        let mut s = scan("12e+3- ");
        s.skip_value("c").unwrap();
        assert_eq!(s.offset(), 6);
        assert_eq!(
            err_of(scan("x").skip_value("c")),
            ("c".to_string(), "bad value".to_string())
        );
        assert_eq!(
            err_of(scan(r#"{"a": 1"#).skip_value("c")),
            ("c".to_string(), "unexpected end of input".to_string())
        );
        assert_eq!(
            err_of(scan(r#"{"a": 1 "b": 2}"#).skip_value("c")),
            ("c".to_string(), "want , or }".to_string())
        );
        assert_eq!(
            err_of(scan("[1 2]").skip_value("c")),
            ("c".to_string(), "want , or ]".to_string())
        );
    }

    #[test]
    fn object_stepping_reports_separators() {
        let mut s = scan("{}");
        s.begin_object("o").unwrap();
        assert!(object_is_empty(&mut s, "o").unwrap());
        s.end_object("o").unwrap();
        let mut s = scan(r#"{"a": 1, "b": 2}"#);
        s.begin_object("o").unwrap();
        assert!(!object_is_empty(&mut s, "o").unwrap());
        s.skip_ws();
        assert_eq!(s.parse_string("o").unwrap(), "a");
        expect_colon(&mut s, "o").unwrap();
        assert_eq!(s.parse_int("o.n").unwrap(), 1);
        assert!(object_next(&mut s, "o").unwrap());
        s.skip_ws();
        assert_eq!(s.parse_string("o").unwrap(), "b");
        expect_colon(&mut s, "o").unwrap();
        assert_eq!(s.parse_int("o.n").unwrap(), 2);
        assert!(!object_next(&mut s, "o").unwrap());
        s.end_object("o").unwrap();
        assert_eq!(
            err_of(scan(r#"{"a" 1}"#).parse_string("o").map(|_| ())),
            ("o".to_string(), "expected byte 34".to_string())
        );
    }

    #[test]
    fn separators_name_their_object() {
        let mut s = scan(r#"{"a": 1 "b": 2}"#);
        s.begin_object("evt").unwrap();
        s.skip_ws();
        s.parse_string("evt").unwrap();
        expect_colon(&mut s, "evt").unwrap();
        s.parse_int("evt.n").unwrap();
        assert_eq!(
            err_of(object_next(&mut s, "evt").map(|_| ())),
            ("evt".to_string(), "want , or } in evt".to_string())
        );
        let mut s = scan(r#"{"a" 1}"#);
        s.begin_object("evt").unwrap();
        s.skip_ws();
        s.parse_string("evt").unwrap();
        assert_eq!(
            err_of(expect_colon(&mut s, "evt")),
            ("evt".to_string(), "want : in evt".to_string())
        );
        let mut s = scan("[1 2]");
        s.begin_array("arr").unwrap();
        s.parse_int("arr.n").unwrap();
        assert_eq!(
            err_of(array_next(&mut s, "arr").map(|_| ())),
            ("arr".to_string(), "want , or ] in arr".to_string())
        );
        let mut s = scan("[1, 2]");
        s.begin_array("arr").unwrap();
        s.skip_ws();
        s.parse_int("arr.n").unwrap();
        assert!(array_next(&mut s, "arr").unwrap());
        s.skip_ws();
        s.parse_int("arr.n").unwrap();
        assert!(!array_next(&mut s, "arr").unwrap());
        s.end_array("arr").unwrap();
    }

    #[test]
    fn nullable_scalar_readers() {
        assert_eq!(parse_nullable_string(&mut scan("null"), "c").unwrap(), None);
        assert_eq!(
            parse_nullable_string(&mut scan(r#""s""#), "c").unwrap(),
            Some("s".to_string())
        );
        let out = parse_nullable_u64(&mut scan("null"), "c").unwrap();
        assert!(!out.has);
        let out = parse_nullable_u64(&mut scan(r#""42""#), "c").unwrap();
        assert!(out.has);
        assert_eq!(out.value, 42);
        let err = parse_nullable_u64(&mut scan(r#""01""#), "c").unwrap_err();
        assert_eq!(err.what, "u64");
        let out = parse_nullable_int(&mut scan("null"), "c").unwrap();
        assert!(!out.has);
        let out = parse_nullable_int(&mut scan("5"), "c").unwrap();
        assert!(out.has);
        assert_eq!(out.value, 5);
        let err = parse_nullable_int(&mut scan("01"), "c").unwrap_err();
        assert_eq!(err.what, "integer");
        assert_eq!(
            err.message,
            "ValidationError(what=integer, message=leading zero)"
        );
    }

    #[test]
    fn identifier_readers_wrap_opaque_failures() {
        assert_eq!(parse_id_field(&mut scan(r#""op-1""#), "f").unwrap(), "op-1");
        let err = parse_id_field(&mut scan(r#""bad id""#), "f").unwrap_err();
        assert_eq!(err.what, "f");
        assert_eq!(
            err.message,
            "ValidationError(what=opaque_id, message=bad character)"
        );
        let out = parse_nullable_id(&mut scan("null"), "f").unwrap();
        assert!(!out.has);
        let out = parse_nullable_id(&mut scan(r#""m-1""#), "f").unwrap();
        assert!(out.has);
        assert_eq!(out.value, "m-1");
    }

    #[test]
    fn required_u64_needs_a_string() {
        assert_eq!(
            parse_u64_field(&mut scan(r#""07""#), "f").unwrap_err().what,
            "f"
        );
        assert_eq!(
            err_of(parse_u64_field(&mut scan("42"), "f").map(|_| ())),
            ("f".to_string(), "expected byte 34".to_string())
        );
        assert_eq!(parse_u64_field(&mut scan(r#""42""#), "f").unwrap(), 42);
    }

    #[test]
    fn spans_borrow_source_bytes() {
        let s = scan("abcdef");
        assert_eq!(s.span_bytes("w", 1, 4).unwrap(), b"bcd");
        assert_eq!(
            err_of(s.span_bytes("w", 4, 1).map(|_| ())),
            ("w".to_string(), "bad span".to_string())
        );
        assert_eq!(
            err_of(s.span_bytes("w", 0, 99).map(|_| ())),
            ("w".to_string(), "bad span".to_string())
        );
    }

    fn offset_of(result: Result<(), ValidationError>) -> Option<usize> {
        result.unwrap_err().offset
    }

    #[test]
    fn structural_errors_carry_cursor_offsets() {
        // A consumed offending byte reports the position behind the
        // cursor; anything else reports the cursor itself.
        let mut s = scan("{oops");
        s.begin_object("c").unwrap();
        assert_eq!(offset_of(s.parse_string("c").map(|_| ())), Some(1));
        assert_eq!(offset_of(scan("").peek("c").map(|_| ())), Some(0));
        assert_eq!(offset_of(scan("nul").parse_null("c").map(|_| ())), Some(0));
        assert_eq!(offset_of(scan("truX").parse_bool("c").map(|_| ())), Some(0));
        assert_eq!(
            offset_of(scan("\"a\x01b\"").parse_string("c").map(|_| ())),
            Some(2)
        );
        assert_eq!(
            offset_of(scan("\"\\q\"").parse_string("c").map(|_| ())),
            Some(2)
        );
        assert_eq!(
            offset_of(scan("\"\\u12Z4\"").parse_string("c").map(|_| ())),
            Some(5)
        );
        assert_eq!(
            offset_of(scan("\"\\uDC00\"").parse_string("c").map(|_| ())),
            Some(7)
        );
        assert_eq!(
            offset_of(scan("\"\\uD800\\u0041\"").parse_string("c").map(|_| ())),
            Some(13)
        );
        assert_eq!(
            offset_of(scan("\"\u{0}ff\"").parse_string("c").map(|_| ())),
            Some(1)
        );
        assert_eq!(
            offset_of(scan("{\u{0}}").skip_value("c").map(|_| ())),
            Some(1)
        );
        let raw: &[u8] = b"\"d\xffv\"";
        assert_eq!(
            offset_of(Scanner::new(raw).parse_string("c").map(|_| ())),
            Some(5)
        );
        assert_eq!(offset_of(scan("x").skip_value("c").map(|_| ())), Some(0));
        assert_eq!(
            offset_of(scan(r#"{"a": 1"#).skip_value("c").map(|_| ())),
            Some(7)
        );
        assert_eq!(
            offset_of(scan(r#"{"a": 1 "b": 2}"#).skip_value("c").map(|_| ())),
            Some(8)
        );
        assert_eq!(
            offset_of(scan("[1 2]").skip_value("c").map(|_| ())),
            Some(3)
        );
        let mut s = scan(r#"{"a" 1}"#);
        s.begin_object("c").unwrap();
        s.skip_ws();
        s.parse_string("c").unwrap();
        assert_eq!(offset_of(expect_colon(&mut s, "c")), Some(5));
        let mut s = scan(r#"{"a": 1 "b": 2}"#);
        s.begin_object("c").unwrap();
        s.skip_ws();
        s.parse_string("c").unwrap();
        expect_colon(&mut s, "c").unwrap();
        s.parse_int("c.n").unwrap();
        assert_eq!(offset_of(object_next(&mut s, "c").map(|_| ())), Some(8));
        let mut s = scan("[1 2]");
        s.begin_array("c").unwrap();
        s.parse_int("c.n").unwrap();
        assert_eq!(offset_of(array_next(&mut s, "c").map(|_| ())), Some(3));
        let mut s = Scanner::with_max_depth(b"{", 0);
        assert_eq!(offset_of(s.begin_object("c").map(|_| ())), Some(1));
        let s = scan("abcdef");
        assert_eq!(offset_of(s.span_bytes("w", 4, 1).map(|_| ())), Some(4));
    }

    #[test]
    fn structural_errors_render_as_scan_errors() {
        let mut s = scan("{oops");
        s.begin_object("c").unwrap();
        let err = s.parse_string("c").unwrap_err();
        assert_eq!(err.what, "c");
        assert_eq!(
            err.to_string(),
            "ScanError(offset=1, message=expected byte 34)"
        );
    }
}
