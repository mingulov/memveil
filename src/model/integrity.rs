// SPDX-License-Identifier: GPL-3.0-or-later
//! Committed event-file measurements for capture format 0.1.4.
//!
//! The integrity object snapshots the literal event-file bytes: total
//! bytes, line count, the exact 0..N-1 sequence span, the lowercase
//! hex sha256 over the bytes including newlines, and per-kind line
//! counts for exactly the ten event kinds, zeros included. Parsing
//! checks structural self-consistency only; presence of the object
//! does not establish that the event file was verified.

use super::scan::{
    Scanner, expect_colon, object_is_empty, object_next, parse_nullable_u64, parse_u64_field,
};
use super::validate::{ValidationError, checked_add};

/// Digest of the empty event stream.
pub const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
/// Integrity kind table size: exactly the ten event kinds.
pub const INTEGRITY_KIND_COUNT: usize = 10;

/// Name one integrity kind by table index; empty when out of range.
pub fn integrity_kind(index: usize) -> &'static str {
    match index {
        0 => "bounce_attempt",
        1 => "map_result",
        2 => "unmap",
        3 => "copy",
        4 => "sync_request",
        5 => "transition_result",
        6 => "pool_sample",
        7 => "gap",
        8 => "marker",
        9 => "counter_snapshot",
        _ => "",
    }
}

/// Map one kind name to its integrity table index.
pub fn integrity_kind_index(name: &str) -> Option<usize> {
    match name {
        "bounce_attempt" => Some(0),
        "map_result" => Some(1),
        "unmap" => Some(2),
        "copy" => Some(3),
        "sync_request" => Some(4),
        "transition_result" => Some(5),
        "pool_sample" => Some(6),
        "gap" => Some(7),
        "marker" => Some(8),
        "counter_snapshot" => Some(9),
        _ => None,
    }
}

/// Committed-byte snapshot; presence does not establish verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Integrity {
    /// Committed event-file bytes.
    pub events_bytes: u64,
    /// Committed line count.
    pub line_count: u64,
    /// True when sequence bounds were reported.
    pub has_seq: bool,
    /// First committed sequence; zero unless `has_seq`.
    pub first_seq: u64,
    /// Last committed sequence; zero unless `has_seq`.
    pub last_seq: u64,
    /// Lowercase hex sha256 over literal event bytes.
    pub events_sha256: String,
    /// Per-kind line counts in [`integrity_kind`] order.
    pub kinds: [u64; INTEGRITY_KIND_COUNT],
}

impl Default for Integrity {
    fn default() -> Self {
        Self {
            events_bytes: 0,
            line_count: 0,
            has_seq: false,
            first_seq: 0,
            last_seq: 0,
            events_sha256: EMPTY_SHA256.to_string(),
            kinds: [0; INTEGRITY_KIND_COUNT],
        }
    }
}

impl Integrity {
    /// Check self-consistency: kind sum, empty/non-empty rules, digest.
    pub fn validate(&self) -> Result<(), ValidationError> {
        let mut total = 0u64;
        for kind in self.kinds {
            total = checked_add(total, kind)?;
        }
        if total != self.line_count {
            return Err(ValidationError::new(
                "capture.integrity.kinds",
                "sum differs from line_count",
            ));
        }
        if self.line_count == 0 {
            if self.has_seq || self.events_bytes != 0 || self.events_sha256 != EMPTY_SHA256 {
                return Err(ValidationError::new(
                    "capture.integrity",
                    "invalid empty stream",
                ));
            }
        } else if !self.has_seq
            || self.first_seq != 0
            || self.last_seq != self.line_count - 1
            || self.events_bytes < self.line_count
        {
            return Err(ValidationError::new(
                "capture.integrity",
                "invalid sequence bounds or byte count",
            ));
        }
        if self.events_sha256.len() != 64 {
            return Err(ValidationError::new(
                "capture.integrity.events_sha256",
                "digest length",
            ));
        }
        for b in self.events_sha256.bytes() {
            if !(b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                return Err(ValidationError::new(
                    "capture.integrity.events_sha256",
                    "digest must be lowercase hex",
                ));
            }
        }
        Ok(())
    }
}

/// Parse one integrity object; the cursor must sit on its `{`.
pub(crate) fn parse_integrity(scan: &mut Scanner) -> Result<Integrity, ValidationError> {
    scan.begin_object("capture.integrity")?;
    let mut out = Integrity::default();
    let mut seen: Vec<String> = Vec::new();
    let mut first_present = false;
    let mut last_present = false;
    if !object_is_empty(scan, "capture.integrity")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("capture.integrity")?;
            if seen.contains(&key) {
                return Err(ValidationError::new("capture.integrity", "duplicate key"));
            }
            seen.push(key.clone());
            expect_colon(scan, "capture.integrity")?;
            if key == "algorithm" {
                if scan.parse_string("capture.integrity")? != "sha256" {
                    return Err(ValidationError::new(
                        "capture.integrity.algorithm",
                        "unsupported algorithm",
                    ));
                }
            } else if key == "events_bytes" {
                out.events_bytes = parse_u64_field(scan, "capture.integrity.events_bytes")?;
            } else if key == "line_count" {
                out.line_count = parse_u64_field(scan, "capture.integrity.line_count")?;
            } else if key == "first_seq" {
                let v = parse_nullable_u64(scan, "capture.integrity")?;
                first_present = v.has;
                out.first_seq = v.value;
            } else if key == "last_seq" {
                let v = parse_nullable_u64(scan, "capture.integrity")?;
                last_present = v.has;
                out.last_seq = v.value;
            } else if key == "events_sha256" {
                out.events_sha256 = scan.parse_string("capture.integrity")?;
            } else if key == "kinds" {
                scan.begin_object("capture.integrity.kinds")?;
                let mut kinds_seen: Vec<String> = Vec::new();
                if !object_is_empty(scan, "capture.integrity.kinds")? {
                    loop {
                        scan.skip_ws();
                        let name = scan.parse_string("capture.integrity.kinds")?;
                        let index = match integrity_kind_index(&name) {
                            Some(index) if !kinds_seen.contains(&name) => index,
                            _ => {
                                return Err(ValidationError::new(
                                    "capture.integrity.kinds",
                                    "unknown or duplicate kind",
                                ));
                            }
                        };
                        kinds_seen.push(name);
                        expect_colon(scan, "capture.integrity.kinds")?;
                        out.kinds[index] = parse_u64_field(scan, "capture.integrity.kinds")?;
                        if !object_next(scan, "capture.integrity.kinds")? {
                            break;
                        }
                    }
                }
                scan.end_object("capture.integrity.kinds")?;
                if kinds_seen.len() != INTEGRITY_KIND_COUNT {
                    return Err(ValidationError::new(
                        "capture.integrity.kinds",
                        "missing kind",
                    ));
                }
            } else {
                return Err(ValidationError::new("capture.integrity", "unknown field"));
            }
            if !object_next(scan, "capture.integrity")? {
                break;
            }
        }
    }
    scan.end_object("capture.integrity")?;
    if seen.len() != 7 || first_present != last_present {
        return Err(ValidationError::new(
            "capture.integrity",
            "missing field or mismatched sequence bounds",
        ));
    }
    out.has_seq = first_present;
    out.validate()?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn parse(text: &str) -> Result<Integrity, ValidationError> {
        parse_integrity(&mut Scanner::new(text.as_bytes()))
    }

    #[test]
    fn kind_table_covers_ten_names_in_order() {
        let names = [
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
        assert_eq!(names.len(), INTEGRITY_KIND_COUNT);
        for (index, name) in names.iter().enumerate() {
            assert_eq!(integrity_kind(index), *name);
            assert_eq!(integrity_kind_index(name), Some(index));
        }
        assert_eq!(integrity_kind(INTEGRITY_KIND_COUNT), "");
        assert_eq!(integrity_kind(usize::MAX), "");
        assert_eq!(integrity_kind_index("nope"), None);
        assert_eq!(integrity_kind_index(""), None);
    }

    #[test]
    fn default_is_the_empty_stream() {
        let v = Integrity::default();
        assert_eq!(v.events_bytes, 0);
        assert_eq!(v.line_count, 0);
        assert!(!v.has_seq);
        assert_eq!(v.events_sha256, EMPTY_SHA256);
        assert!(v.kinds.iter().all(|k| *k == 0));
        v.validate().unwrap();
    }

    #[test]
    fn validate_accepts_nonempty_span() {
        let v = Integrity {
            events_bytes: 100,
            line_count: 3,
            has_seq: true,
            first_seq: 0,
            last_seq: 2,
            events_sha256: DIGEST.to_string(),
            kinds: [2, 0, 0, 0, 0, 0, 0, 0, 1, 0],
        };
        v.validate().unwrap();
    }

    #[test]
    fn validate_rejects_bad_spans_and_sums() {
        let v = Integrity {
            line_count: 1,
            has_seq: true,
            last_seq: 0,
            events_bytes: 10,
            events_sha256: DIGEST.to_string(),
            kinds: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            ..Integrity::default()
        };
        v.validate().unwrap();

        let short = Integrity {
            events_bytes: 0,
            ..v.clone()
        };
        assert!(short.validate().is_err());

        let shifted = Integrity {
            first_seq: 1,
            ..v.clone()
        };
        assert!(shifted.validate().is_err());

        let open = Integrity {
            last_seq: 1,
            ..v.clone()
        };
        assert!(open.validate().is_err());

        let noseq = Integrity {
            has_seq: false,
            ..v.clone()
        };
        assert!(noseq.validate().is_err());

        let sum = Integrity {
            kinds: [1, 0, 0, 0, 0, 0, 0, 0, 1, 0],
            ..v.clone()
        };
        let err = sum.validate().unwrap_err();
        assert_eq!(err.what, "capture.integrity.kinds");

        let big = Integrity {
            events_bytes: u64::MAX,
            line_count: u64::MAX,
            has_seq: true,
            first_seq: 0,
            last_seq: u64::MAX - 1,
            events_sha256: DIGEST.to_string(),
            kinds: [u64::MAX, 1, 0, 0, 0, 0, 0, 0, 0, 0],
        };
        let err = big.validate().unwrap_err();
        assert_eq!(err.message, "overflow");
    }

    #[test]
    fn validate_rejects_bad_empty_and_digest() {
        let v = Integrity {
            has_seq: true,
            ..Integrity::default()
        };
        assert!(v.validate().is_err());

        let v = Integrity {
            events_bytes: 1,
            ..Integrity::default()
        };
        assert!(v.validate().is_err());

        let v = Integrity {
            events_sha256: DIGEST.to_string(),
            ..Integrity::default()
        };
        assert!(v.validate().is_err());

        let v = Integrity {
            line_count: 1,
            has_seq: true,
            last_seq: 0,
            events_bytes: 1,
            kinds: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            events_sha256: "0123".to_string(),
            ..Integrity::default()
        };
        let err = v.validate().unwrap_err();
        assert_eq!(err.what, "capture.integrity.events_sha256");
        assert_eq!(err.message, "digest length");

        let v = Integrity {
            line_count: 1,
            has_seq: true,
            last_seq: 0,
            events_bytes: 1,
            kinds: [1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            events_sha256: DIGEST.to_uppercase(),
            ..Integrity::default()
        };
        let err = v.validate().unwrap_err();
        assert_eq!(err.message, "digest must be lowercase hex");
    }

    #[test]
    fn parse_roundtrip_empty() {
        let doc = [
            r#"{"algorithm":"sha256","events_bytes":"0","line_count":"0","#,
            r#""first_seq":null,"last_seq":null,"events_sha256":""#,
            EMPTY_SHA256,
            r#"","kinds":{"bounce_attempt":"0","map_result":"0","unmap":"0","#,
            r#""copy":"0","sync_request":"0","transition_result":"0","#,
            r#""pool_sample":"0","gap":"0","marker":"0","counter_snapshot":"0"}}"#,
        ]
        .concat();
        let v = parse(&doc).unwrap();
        assert_eq!(v, Integrity::default());
    }

    #[test]
    fn parse_rejects_structural_faults() {
        let kinds = r#""kinds":{"bounce_attempt":"1","map_result":"0","unmap":"0","copy":"0","sync_request":"0","transition_result":"0","pool_sample":"0","gap":"0","marker":"0","counter_snapshot":"0"}"#;
        let base = format!(
            r#"{{"algorithm":"sha256","events_bytes":"10","line_count":"1","first_seq":"0","last_seq":"0","events_sha256":"{DIGEST}",{kinds}}}"#
        );
        assert!(parse(&base).is_ok());
        let cases = [
            base.replace(r#""algorithm":"sha256""#, r#""algorithm":"sha512""#),
            base.replace(r#""line_count":"1""#, r#""line_count":"01""#),
            base.replace(r#""line_count":"1""#, r#""line_count":"2""#),
            base.replace(r#""first_seq":"0""#, r#""first_seq":null"#),
            base.replace(r#""marker":"0","#, ""),
            base.replace(r#""marker":"0""#, r#""marker":"1""#),
            base.replace(r#""marker":"0""#, r#""marker":"0","marker":"0""#),
            base.replace(r#""gap":"0""#, r#""bogus":"0""#),
            base.replace(r#"{"algorithm""#, r#"{"extra":1,"algorithm""#),
        ];
        for bad in cases {
            assert!(parse(&bad).is_err(), "must refuse {bad}");
        }
    }
}
