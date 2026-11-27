// SPDX-License-Identifier: GPL-3.0-or-later
//! Transient finite symbol ranges; neither input nor addresses are exported.
//!
//! [`resolve_caller_ranges`] maps an allowlisted `/proc/kallsyms`-shaped
//! listing onto the ten finite caller labels: each label resolves to the
//! half-open range from its symbol address to the next higher address, or
//! to zero when the label is absent, duplicated, or unbounded. Overlapping
//! aliases mark the range ambiguous instead of resolving. The ranges live
//! only in the classifier map; the ring carries bare label codes.

use crate::model::journal_event::caller_label;
use crate::model::validate::ValidationError;

/// One transient classifier range: half-open `[start, end)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallerRange {
    /// Range start address; zero when unresolved.
    pub start: u64,
    /// Range end address; zero when unresolved.
    pub end: u64,
    /// True when overlapping aliases share the start.
    pub ambiguous: bool,
}

/// Parse one 16-digit lowercase-or-upper hexadecimal address.
fn parse_address(value: &str) -> Result<u64, ValidationError> {
    let raw = value.as_bytes();
    if raw.len() != 16 {
        return Err(ValidationError::new(
            "caller source",
            "invalid symbol shape",
        ));
    }
    let mut out: u64 = 0;
    for byte in raw {
        let digit = if byte.is_ascii_digit() {
            u64::from(byte - b'0')
        } else if (b'a'..=b'f').contains(byte) {
            u64::from(byte - b'a') + 10
        } else if (b'A'..=b'F').contains(byte) {
            u64::from(byte - b'A') + 10
        } else {
            return Err(ValidationError::new(
                "caller source",
                "invalid symbol shape",
            ));
        };
        out = (out << 4) | digit;
    }
    Ok(out)
}

/// Resolve the ten finite caller ranges from a symbol listing.
///
/// Refuses over-long input, over-long listings, and malformed lines;
/// labels 1-2 (owned-module symbols) resolve only under
/// `stable_owned_module`.
pub fn resolve_caller_ranges(
    source: &str,
    stable_owned_module: bool,
) -> Result<Vec<CallerRange>, ValidationError> {
    if source.len() > 16777216 {
        return Err(ValidationError::new("caller source", "input bound"));
    }
    let lines: Vec<&str> = source.split('\n').collect();
    if lines.len() > 262144 {
        return Err(ValidationError::new("caller source", "line bound"));
    }
    let mut out = vec![
        CallerRange {
            start: 0,
            end: 0,
            ambiguous: false,
        };
        10
    ];
    let mut seen = [0i64; 10];
    let mut aliases = [0i64; 10];
    for line in &lines {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        if parts.len() < 3 || parts.len() > 4 {
            return Err(ValidationError::new(
                "caller source",
                "invalid symbol shape",
            ));
        }
        let addr = parse_address(parts[0])?;
        let mut label = parts[2].to_string();
        if parts.len() == 4 {
            label += " ";
            label += parts[3];
        }
        for i in 0..10 {
            if i < 2 && !stable_owned_module {
                continue;
            }
            if label == caller_label((i + 1) as u16) && addr != 0 {
                seen[i] += 1;
                out[i].start = addr;
            }
        }
    }
    for line in &lines {
        if line.is_empty() {
            continue;
        }
        let parts: Vec<&str> = line.split(' ').collect();
        let addr = parse_address(parts[0])?;
        for i in 0..10 {
            let start = out[i].start;
            if start == 0 {
                continue;
            }
            if addr == start {
                aliases[i] += 1;
                out[i].ambiguous = aliases[i] > 1;
            }
            if addr > start && (out[i].end == 0 || addr < out[i].end) {
                out[i].end = addr;
            }
        }
    }
    for i in 0..10 {
        if seen[i] != 1 || out[i].end <= out[i].start {
            out[i] = CallerRange {
                start: 0,
                end: 0,
                ambiguous: false,
            };
        }
    }
    Ok(out)
}

/// Encode one classifier range as 24 little-endian bytes.
pub fn encode_caller_range(value: CallerRange) -> Vec<u8> {
    let mut out = Vec::with_capacity(24);
    for part in [value.start, value.end, u64::from(value.ambiguous)] {
        out.extend_from_slice(&part.to_le_bytes());
    }
    out
}
