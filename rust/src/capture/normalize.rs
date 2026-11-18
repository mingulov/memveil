// SPDX-License-Identifier: GPL-3.0-or-later
//! Attempt payload decode and normalization.
//!
//! Decodes the 98-byte product payloads produced by the swiotlb
//! attempt probe, assigns stable per-capture device ids, and maps
//! decoded fields onto normalized attempt records.
//!
//! Byte layout, check order, and reason vocabulary mirror
//! `bpf/include/memveil_events.h`. Wire decoding delegates to the
//! shared wire crate; this module maps its verdicts onto the
//! shared `PAY_*` reason vocabulary.

use std::collections::HashMap;

use crate::model::validate::format_u64;
use crate::platform::hash::bytes_to_hex;
use crate::platform::reader::is_valid_utf8;

/// Product payload length in bytes.
pub const PAYLOAD_LEN: usize = 98;
/// Maximum device-name length excluding the NUL terminator.
pub const NAME_MAX: usize = 63;
/// Maximum distinct devices interned per capture.
pub const DEVICE_MAX: usize = 4096;

/// One payload decode rejection naming its reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// Machine-stable reason (`PAY_*` vocabulary).
    pub reason: String,
    /// Fatal rejections abort the capture.
    pub fatal: bool,
}

impl DecodeError {
    fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_string(),
            fatal: true,
        }
    }
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for DecodeError {}

/// One normalization rejection.
///
/// Fatal rejections (device-table exhaustion) abort the capture;
/// non-fatal ones (bad UTF-8) drop one event and count it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizeError {
    /// Machine-stable reason.
    pub reason: String,
    /// Fatal rejections abort the capture.
    pub fatal: bool,
}

impl NormalizeError {
    fn new(reason: &str, fatal: bool) -> Self {
        Self {
            reason: reason.to_string(),
            fatal,
        }
    }
}

impl std::fmt::Display for NormalizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for NormalizeError {}

/// One decoded payload: raw fields, no identity assigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedAttempt {
    /// Requested bounce size.
    pub size: u64,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Device-name length excluding the NUL.
    pub name_len: usize,
    /// Forced bounce.
    pub force: bool,
    /// Raw device-name bytes.
    pub name: Vec<u8>,
}

/// One normalized attempt ready for the event writer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedAttempt {
    /// Interned device token.
    pub device_id: String,
    /// Requested transfer length in bytes.
    pub requested_bytes: u64,
    /// True when the bounce was forced.
    pub forced: bool,
    /// Session-local operation token.
    pub operation_id: String,
    /// Event timestamp in nanoseconds.
    pub ts_ns: u64,
}

/// Decode and strictly validate one product payload.
///
/// Check order matches the C reference: length, magic, version,
/// flags, name length, NUL terminator, interior NUL, then zero
/// padding. Rejections carry the shared reason vocabulary.
pub fn decode_payload(raw: &[u8]) -> Result<DecodedAttempt, DecodeError> {
    let wire = memveil_ebpf_common::decode_attempt(raw).map_err(|err| {
        let reason = match err {
            memveil_ebpf_common::DecodeError::Short => "PAY_SHORT",
            memveil_ebpf_common::DecodeError::Long => "PAY_LONG",
            memveil_ebpf_common::DecodeError::Magic => "PAY_MAGIC",
            memveil_ebpf_common::DecodeError::Version => "PAY_VERSION",
            memveil_ebpf_common::DecodeError::Flags => "PAY_FLAGS",
            memveil_ebpf_common::DecodeError::NameLen => "PAY_NAMELEN",
            memveil_ebpf_common::DecodeError::Nul => "PAY_NUL",
            memveil_ebpf_common::DecodeError::Pad => "PAY_PAD",
            // Unreachable in practice: the attempt decoder emits
            // no other verdict. Enumerated (not `_`) so a future
            // DecodeError variant fails the build here instead of
            // panicking at runtime.
            memveil_ebpf_common::DecodeError::Kind => "PAY_KIND",
            memveil_ebpf_common::DecodeError::Dir => "PAY_DIR",
            memveil_ebpf_common::DecodeError::Reason => "PAY_REASON",
            memveil_ebpf_common::DecodeError::Range => "PAY_RANGE",
            memveil_ebpf_common::DecodeError::TableBad => "PAY_TABLE",
        };
        DecodeError::new(reason)
    })?;
    let name_len = usize::from(wire.name_len);
    Ok(DecodedAttempt {
        size: wire.size,
        seq: wire.seq,
        ktime: wire.ktime,
        name_len,
        force: wire.force,
        name: wire.name[..name_len].to_vec(),
    })
}

/// Render a 1-based device number as a d000001-style id.
pub fn device_id_for(n: usize) -> String {
    format!("d{n:06}")
}

/// True for canonical PCI name scope DDDD:BB:DD.F.
///
/// Exactly twelve ASCII bytes: four hex digits, colon, two hex
/// digits, colon, two hex digits, dot, one hex digit. Anything
/// else (interface names, address-shaped blobs, paths) is not an
/// admittable scope.
pub fn is_pci_scope(name: &str) -> bool {
    fn is_hex(b: u8) -> bool {
        b.is_ascii_hexdigit()
    }
    let raw = name.as_bytes();
    if raw.len() != 12 {
        return false;
    }
    raw[..4].iter().all(|b| is_hex(*b))
        && raw[4] == b':'
        && is_hex(raw[5])
        && is_hex(raw[6])
        && raw[7] == b':'
        && is_hex(raw[8])
        && is_hex(raw[9])
        && raw[10] == b'.'
        && is_hex(raw[11])
}

/// Persistable catalog name: PCI scope or opaque marker.
///
/// Interning keeps exact bytes so distinct devices stay distinct;
/// only the human-readable label degrades.
pub fn admitted_name(name: &str) -> String {
    if is_pci_scope(name) {
        name.to_string()
    } else {
        "unresolved".to_string()
    }
}

/// Strict inverse of [`bytes_to_hex`] (lowercase, even length).
///
/// Table keys are produced by `bytes_to_hex`, so a violation means
/// memory corruption, never caller input.
pub fn hex_to_bytes(text: &str) -> Result<Vec<u8>, NormalizeError> {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            _ => None,
        }
    }
    let raw = text.as_bytes();
    if !raw.len().is_multiple_of(2) {
        return Err(NormalizeError::new("INTERNAL", true));
    }
    let mut out = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_chunks::<2>().0 {
        match (hex_val(pair[0]), hex_val(pair[1])) {
            (Some(hi), Some(lo)) => out.push(hi * 16 + lo),
            _ => return Err(NormalizeError::new("INTERNAL", true)),
        }
    }
    Ok(out)
}

/// One interned device: first-seen id plus admitted name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogEntry {
    /// Interned device token.
    pub device_id: String,
    /// Persistable catalog name.
    pub name: String,
}

/// Per-capture device interning: raw name bytes to d000001 ids.
///
/// Keys are hex renderings so arbitrary (even non-UTF8) names
/// intern without lossy decoding. Assignment order is first-seen
/// order starting at 1; past [`DEVICE_MAX`] distinct names the
/// table raises a fatal EXHAUSTED rejection.
#[derive(Debug)]
pub struct DeviceTable {
    index: HashMap<String, usize>,
    order: Vec<String>,
    next: usize,
}

impl Default for DeviceTable {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceTable {
    /// An empty table; the first id assigned is d000001.
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            order: Vec::new(),
            next: 1,
        }
    }

    /// Number of distinct names interned so far.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    /// True when no name has been interned yet.
    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Intern one raw name, returning its stable device id.
    pub fn device_for(&mut self, name: &[u8]) -> Result<String, NormalizeError> {
        let key = bytes_to_hex(name);
        if let Some(seen) = self.index.get(&key) {
            return Ok(device_id_for(*seen));
        }
        if self.index.len() >= DEVICE_MAX {
            return Err(NormalizeError::new("EXHAUSTED", true));
        }
        let fresh = self.next;
        self.next += 1;
        self.index.insert(key.clone(), fresh);
        self.order.push(key);
        Ok(device_id_for(fresh))
    }

    /// First-seen-ordered catalog (== device_id order).
    ///
    /// Only valid-UTF8 names reach the table through
    /// [`normalize_attempt`]; anything else here is fatal.
    pub fn entries(&self) -> Result<Vec<CatalogEntry>, NormalizeError> {
        let mut out = Vec::with_capacity(self.order.len());
        for key in &self.order {
            let num = self.index.get(key).copied().unwrap_or(0);
            if num == 0 {
                return Err(NormalizeError::new("INTERNAL", true));
            }
            let raw = hex_to_bytes(key)?;
            let name = String::from_utf8(raw).map_err(|_| NormalizeError::new("INTERNAL", true))?;
            out.push(CatalogEntry {
                device_id: device_id_for(num),
                name: admitted_name(&name),
            });
        }
        Ok(out)
    }
}

/// Map one decoded payload onto a normalized attempt record.
///
/// UTF-8 is checked before interning so a rejected name never
/// consumes a device id.
pub fn normalize_attempt(
    decoded: &DecodedAttempt,
    table: &mut DeviceTable,
) -> Result<NormalizedAttempt, NormalizeError> {
    if !is_valid_utf8(&decoded.name) {
        return Err(NormalizeError::new("UTF8", false));
    }
    Ok(NormalizedAttempt {
        device_id: table.device_for(&decoded.name)?,
        requested_bytes: decoded.size,
        forced: decoded.force,
        operation_id: format!("op{}", format_u64(decoded.seq)),
        ts_ns: decoded.ktime,
    })
}

/// True when raw name bytes exactly equal the selector.
///
/// The capture-time device selector is literal bytes: no glob,
/// prefix, case folding, or trimming. An empty selector never
/// matches; callers only invoke this when a selector is present.
/// Non-UTF8 names can never match a String selector.
pub fn selection_matches(name: &[u8], selector: &str) -> bool {
    name == selector.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name_bytes(text: &str) -> Vec<u8> {
        text.as_bytes().to_vec()
    }

    fn make_payload(size: u64, force: bool, seq: u64, name: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x3741_564Du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&(u16::from(force)).to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        for i in 0..64usize {
            out.push(if i < name.len() { name[i] } else { 0 });
        }
        out
    }

    #[test]
    fn decode_valid() {
        let raw = make_payload(98, false, 7, b"dev0");
        let got = decode_payload(&raw).expect("decodes");
        assert_eq!(got.size, 98);
        assert_eq!(got.seq, 7);
        assert_eq!(got.name_len, 4);
        assert!(!got.force);
        assert_eq!(bytes_to_hex(&got.name), "64657630");
    }

    #[test]
    fn decode_short() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw.pop();
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_SHORT");
        assert!(err.fatal);
    }

    #[test]
    fn decode_long() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw.push(0);
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_LONG");
    }

    #[test]
    fn decode_magic() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[0] = 0;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_MAGIC");
    }

    #[test]
    fn decode_version() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[4] = 2;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_VERSION");
    }

    #[test]
    fn decode_flags() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[6] = 2;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_FLAGS");
    }

    #[test]
    fn decode_namelen() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[32] = 64;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_NAMELEN");
    }

    #[test]
    fn decode_nul() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[34 + 1] = b'x';
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_NUL");
        let mut raw = make_payload(1, false, 0, b"ab");
        raw[34] = 0;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_NUL");
    }

    #[test]
    fn decode_pad() {
        let mut raw = make_payload(1, false, 0, b"a");
        raw[34 + 2] = 1;
        let err = decode_payload(&raw).expect_err("must reject");
        assert_eq!(err.reason, "PAY_PAD");
    }

    #[test]
    fn decode_max_values() {
        let big = vec![0x44u8; 63];
        let raw = make_payload(u64::MAX, true, u64::MAX, &big);
        let got = decode_payload(&raw).expect("decodes");
        assert_eq!(got.size, u64::MAX);
        assert_eq!(got.seq, u64::MAX);
        assert!(got.force);
        assert_eq!(got.name_len, 63);
    }

    #[test]
    fn device_ids() {
        let mut table = DeviceTable::new();
        assert_eq!(table.device_for(b"eth0").unwrap(), "d000001");
        assert_eq!(table.device_for(b"wlan0").unwrap(), "d000002");
        assert_eq!(table.device_for(b"eth0").unwrap(), "d000001");
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn device_id_format() {
        assert_eq!(device_id_for(1), "d000001");
        assert_eq!(device_id_for(4096), "d004096");
    }

    #[test]
    fn normalize_fields() {
        let mut table = DeviceTable::new();
        let raw = make_payload(1500, true, 123, b"pc");
        let decoded = decode_payload(&raw).expect("decodes");
        let norm = normalize_attempt(&decoded, &mut table).expect("normalizes");
        assert_eq!(norm.device_id, "d000001");
        assert_eq!(norm.requested_bytes, 1500);
        assert!(norm.forced);
        assert_eq!(norm.operation_id, "op123");
        assert_eq!(norm.ts_ns, 0);
    }

    #[test]
    fn normalize_utf8_reject() {
        let mut table = DeviceTable::new();
        let raw = make_payload(8, false, 3, &[0xFF, 0xFE]);
        let decoded = decode_payload(&raw).expect("decodes");
        let err = normalize_attempt(&decoded, &mut table).expect_err("must reject");
        assert_eq!(err.reason, "UTF8");
        assert!(!err.fatal);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn normalize_exhaustion() {
        let mut table = DeviceTable::new();
        for i in 0..DEVICE_MAX {
            let nm = format!("d{i}");
            table.device_for(nm.as_bytes()).expect("interns");
        }
        assert_eq!(table.len(), DEVICE_MAX);
        let err = table.device_for(b"one-too-many").expect_err("must reject");
        assert_eq!(err.reason, "EXHAUSTED");
        assert!(err.fatal);
    }

    #[test]
    fn normalize_exhaustion_counts() {
        let mut table = DeviceTable::new();
        for i in 0..DEVICE_MAX {
            let nm = format!("x{i}");
            table.device_for(nm.as_bytes()).expect("interns");
        }
        let raw = make_payload(8, false, 9, b"new-device");
        let decoded = decode_payload(&raw).expect("decodes");
        let err = normalize_attempt(&decoded, &mut table).expect_err("must reject");
        assert!(err.fatal);
    }

    #[test]
    fn payload_constants() {
        assert_eq!(PAYLOAD_LEN, 98);
        assert_eq!(NAME_MAX, 63);
    }

    #[test]
    fn catalog_entries() {
        let mut table = DeviceTable::new();
        let second = table.device_for(b"0000:00:0c.0").unwrap();
        let first = table.device_for(b"eth0").unwrap();
        assert_eq!(second, "d000001");
        assert_eq!(first, "d000002");
        assert_eq!(table.device_for(b"0000:00:0c.0").unwrap(), second);
        let got = table.entries().expect("entries");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].device_id, "d000001");
        assert_eq!(got[0].name, "0000:00:0c.0");
        assert_eq!(got[1].device_id, "d000002");
        assert_eq!(got[1].name, "unresolved");
    }

    #[test]
    fn pci_scope_vectors() {
        for good in ["0000:00:0c.0", "FFFF:FF:1F.7", "abcd:12:34.5"] {
            assert!(is_pci_scope(good), "{good} admits");
        }
        for bad in [
            "",
            "eth0",
            "ffff888012345000",
            "0000:00:0c",
            "0000:00:0c.00",
            "0000:00:0c.0 ",
            " 0000:00:0c.0",
            "0000-00-0c.0",
            "0000:00:0c:0",
            "gggg:00:0c.0",
            "0000:00:0c.g",
            "/etc/passwd",
            "0000:00:0c.0/extra",
        ] {
            assert!(!is_pci_scope(bad), "{bad} refuses");
        }
    }

    #[test]
    fn hex_roundtrip() {
        let raw = name_bytes("pci-00:1f.6");
        let back = hex_to_bytes(&bytes_to_hex(&raw)).expect("roundtrips");
        assert_eq!(back, raw);
        for bad in ["zz", "abc", "AB"] {
            let err = hex_to_bytes(bad).expect_err("must reject");
            assert_eq!(err.reason, "INTERNAL");
            assert!(err.fatal);
        }
    }

    #[test]
    fn selection_exact_match() {
        assert!(selection_matches(b"0000:00:1f.2", "0000:00:1f.2"));
        assert!(!selection_matches(b"0000:00:1f.2", "0000:00:1f.3"));
    }

    #[test]
    fn selection_no_partial_match() {
        let name = b"0000:00:1f.2";
        assert!(!selection_matches(name, "1f.2"));
        assert!(!selection_matches(name, "0000:00:1f."));
        assert!(!selection_matches(name, "0000:00:1F.2"));
        assert!(!selection_matches(name, ""));
    }

    #[test]
    fn selection_glob_is_literal() {
        assert!(selection_matches(b"dev*0", "dev*0"));
        assert!(!selection_matches(b"devX0", "dev*0"));
        assert!(!selection_matches(b"dev*0", "devX0"));
    }

    #[test]
    fn selection_non_utf8_never_matches() {
        let raw = [0xFF, 0xFE];
        assert!(!selection_matches(&raw, "??"));
        assert!(!selection_matches(&raw, ""));
    }

    #[test]
    fn selection_whitespace_is_literal() {
        assert!(selection_matches(b" dev0 ", " dev0 "));
        assert!(!selection_matches(b" dev0 ", "dev0"));
    }

    fn read_u32_le(blob: &[u8], pos: usize) -> u32 {
        u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap())
    }

    fn corpus_field<'a>(tail: &[&'a str], key: &str) -> &'a str {
        for tok in tail {
            if let Some(rest) = tok.strip_prefix(key) {
                return rest;
            }
        }
        panic!("missing field {key}");
    }

    fn parse_hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0);
        let digits: Vec<u8> = text.bytes().collect();
        let mut out = Vec::with_capacity(digits.len() / 2);
        for pair in digits.chunks(2) {
            let hi = char::from(pair[0]).to_digit(16).unwrap();
            let lo = char::from(pair[1]).to_digit(16).unwrap();
            out.push((hi * 16 + lo) as u8);
        }
        out
    }

    #[test]
    fn attempts_corpus_differential() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../tests/fixtures/attempts");
        let blob = std::fs::read(format!("{dir}/corpus.bin")).expect("corpus.bin");
        let text = std::fs::read_to_string(format!("{dir}/corpus.txt")).expect("corpus.txt");
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        let count = read_u32_le(&blob, 0) as usize;
        assert_eq!(count, lines.len(), "bin/txt vector count");
        let mut pos = 4usize;
        let mut payloads = 0usize;
        let mut skipped = 0usize;
        for (idx, line) in lines.iter().enumerate() {
            let kind = read_u32_le(&blob, pos);
            pos += 4;
            let rlen = read_u32_le(&blob, pos) as usize;
            pos += 4;
            let inp = &blob[pos..pos + rlen];
            pos += rlen;
            let mut words = line.split_whitespace();
            assert_eq!(words.next().expect("idx"), format!("{idx}"));
            let tag = words.next().expect("tag");
            let verdict = words.next().expect("verdict");
            let tail: Vec<&str> = words.collect();
            match (kind, tag) {
                (2, "payload") => {
                    payloads += 1;
                    match decode_payload(inp) {
                        Ok(got) => {
                            assert_eq!(verdict, "OK", "line {idx}");
                            assert_eq!(tail.len(), 6, "line {idx}: field count");
                            assert_eq!(
                                got.size,
                                corpus_field(&tail, "size=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                got.force,
                                corpus_field(&tail, "force=") == "1",
                                "line {idx}"
                            );
                            assert_eq!(
                                got.seq,
                                corpus_field(&tail, "seq=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                got.ktime,
                                corpus_field(&tail, "ktime=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                got.name_len,
                                corpus_field(&tail, "namelen=").parse::<usize>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                got.name,
                                parse_hex(corpus_field(&tail, "name=")),
                                "line {idx}"
                            );
                        }
                        Err(err) => assert_eq!(err.reason, verdict, "line {idx}"),
                    }
                }
                (1, "ctx") | (3, "tctx") => {
                    // Raw tracepoint contexts belong to the BPF-side
                    // extractor, not to payload normalization.
                    skipped += 1;
                }
                _ => panic!("line {idx}: bad kind/tag {kind}/{tag}"),
            }
        }
        assert_eq!(pos, blob.len(), "trailing corpus bytes");
        assert!(payloads > 0, "corpus must carry payload vectors");
        assert!(skipped > 0, "corpus must carry context vectors");
    }
}
