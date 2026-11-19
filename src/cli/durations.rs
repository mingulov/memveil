// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked duration parsing for CLI options.
//!
//! Accepted shapes: a strict decimal count of seconds with an
//! optional unit suffix: `s` (seconds), `m` (minutes), or `h`
//! (hours). Bare digits mean seconds, matching the capture
//! options. The digits share the capture rules: 1..20 digits, no
//! leading zeros, no zero, overflow refused. Results are integer
//! nanoseconds.

const NS_PER_S: u64 = 1_000_000_000;
const NS_PER_M: u64 = 60_000_000_000;
const NS_PER_H: u64 = 3_600_000_000_000;

/// One duration parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurationError {
    /// Failure detail, including the rejected text.
    pub message: String,
}

impl std::fmt::Display for DurationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Mirror the Mojo `String(e)` rendering: the default
        // struct spelling, which callers embed verbatim in
        // diagnostics (`--long-lived-after DurationError(...)`).
        write!(f, "DurationError(message={})", self.message)
    }
}

impl std::error::Error for DurationError {}

/// Parse DURATION to nanoseconds with refused overflow.
pub fn parse_duration_ns(text: &str) -> Result<u64, DurationError> {
    let raw = text.as_bytes();
    let n = raw.len();
    if n == 0 || n > 21 {
        return Err(DurationError {
            message: format!("bad duration: {text}"),
        });
    }
    let mut mult = NS_PER_S;
    let mut digits = n;
    let last = raw[n - 1];
    if last == b's' || last == b'm' || last == b'h' {
        digits = n - 1;
        if last == b'm' {
            mult = NS_PER_M;
        } else if last == b'h' {
            mult = NS_PER_H;
        }
    }
    if digits == 0 || digits > 20 {
        return Err(DurationError {
            message: format!("bad duration: {text}"),
        });
    }
    if raw[0] < b'1' || raw[0] > b'9' {
        return Err(DurationError {
            message: format!("bad duration: {text}"),
        });
    }
    let mut v: u64 = 0;
    for &b in &raw[..digits] {
        if !b.is_ascii_digit() {
            return Err(DurationError {
                message: format!("bad duration: {text}"),
            });
        }
        let d = u64::from(b - b'0');
        if v > (u64::MAX - d) / 10 {
            return Err(DurationError {
                message: format!("bad duration: {text}"),
            });
        }
        v = v * 10 + d;
    }
    if v > u64::MAX / mult {
        return Err(DurationError {
            message: "duration overflows nanoseconds".to_string(),
        });
    }
    Ok(v * mult)
}

#[cfg(test)]
mod tests {
    use super::parse_duration_ns;

    #[test]
    fn bare_digits_mean_seconds() {
        assert_eq!(parse_duration_ns("60").expect("60 parses"), 60_000_000_000);
        assert_eq!(parse_duration_ns("1").expect("1 parses"), 1_000_000_000);
    }

    #[test]
    fn unit_suffixes_scale() {
        assert_eq!(parse_duration_ns("5s").expect("5s parses"), 5_000_000_000);
        assert_eq!(parse_duration_ns("2m").expect("2m parses"), 120_000_000_000);
        assert_eq!(
            parse_duration_ns("1h").expect("1h parses"),
            3_600_000_000_000
        );
        assert_eq!(
            parse_duration_ns("24h").expect("24h parses"),
            86_400_000_000_000
        );
    }

    #[test]
    fn rejects_empty_zero_and_leading_zeros() {
        for bad in ["", "0", "00", "01", "0s"] {
            let err = parse_duration_ns(bad).expect_err("must reject");
            assert_eq!(err.message, format!("bad duration: {bad}"));
        }
    }

    #[test]
    fn rejects_bad_shapes() {
        for bad in [
            "s",
            "1x",
            "1S",
            "1H",
            "-5",
            "+5",
            "1 s",
            "1.5",
            " 5",
            "5 ",
            "99999999999999999999999",
        ] {
            let err = parse_duration_ns(bad).expect_err("must reject");
            assert_eq!(err.message, format!("bad duration: {bad}"));
        }
    }

    #[test]
    fn rejects_digit_overflow() {
        // Twenty digits that exceed u64 stay a bad duration.
        let err = parse_duration_ns("18446744073709551616").expect_err("2^64 rejects");
        assert_eq!(err.message, "bad duration: 18446744073709551616");
    }

    #[test]
    fn rejects_nanosecond_overflow() {
        // u64max seconds cannot fit in nanoseconds.
        let err = parse_duration_ns("18446744073709551615").expect_err("u64max rejects");
        assert_eq!(err.message, "duration overflows nanoseconds");
        // One second past the largest representable second count.
        let err = parse_duration_ns("18446744074s").expect_err("overflow rejects");
        assert_eq!(err.message, "duration overflows nanoseconds");
    }

    #[test]
    fn accepts_largest_representable_second() {
        assert_eq!(
            parse_duration_ns("18446744073s").expect("max second parses"),
            18_446_744_073_000_000_000
        );
    }

    #[test]
    fn display_matches_mojo_error_rendering() {
        let err = parse_duration_ns("bogus").expect_err("bogus rejects");
        assert_eq!(
            err.to_string(),
            "DurationError(message=bad duration: bogus)"
        );
    }
}
