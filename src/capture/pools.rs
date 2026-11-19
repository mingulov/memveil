// SPDX-License-Identifier: GPL-3.0-or-later
//! Profile-selected pool sampler core.
//!
//! The sampler reads only admitted allocator fields on admitted
//! profiles and converts slots or pages to bytes only with a
//! verified unit size and checked arithmetic. A denied read, an
//! unknown unit size, or an overflow yields an unavailable sample
//! with a reason, never a zero that would fake an empty pool.
//!
//! The default-pool counter reader below covers exactly three
//! debugfs counter files; transient/dynamic pools are not sampled.

use crate::model::validate::{check_opaque_id, parse_u64};
use crate::platform::reader::{E_ABSENT, EvidenceReader, read_evidence};

/// Default-pool used-slots counter path.
pub const POOL_SWIOTLB_USED: &str = "/sys/kernel/debug/swiotlb/io_tlb_used";
/// Default-pool slab-count counter path.
pub const POOL_SWIOTLB_NSLABS: &str = "/sys/kernel/debug/swiotlb/io_tlb_nslabs";
/// Default-pool high-water counter path.
pub const POOL_SWIOTLB_HIWATER: &str = "/sys/kernel/debug/swiotlb/io_tlb_used_hiwater";
/// Default-pool allocator token.
pub const POOL_SWIOTLB_ALLOCATOR: &str = "swiotlb";
/// Default-pool slot size in bytes.
pub const POOL_SWIOTLB_UNIT: u64 = 2048;
/// Default-pool pool id.
pub const POOL_SWIOTLB_POOL_ID: &str = "swiotlb-default";
/// Debugfs counter read cap in bytes.
const COUNTER_CAP: usize = 64;

/// One sampler input failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoolSamplerError {
    /// Failure detail.
    pub message: String,
}

impl PoolSamplerError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PoolSamplerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PoolSamplerError(message={})", self.message)
    }
}

impl std::error::Error for PoolSamplerError {}

/// Accept only allowlisted allocator field names.
pub fn check_field_admitted(field: &str, admitted: &[String]) -> Result<(), PoolSamplerError> {
    for allow in admitted {
        if allow == field {
            return Ok(());
        }
    }
    Err(PoolSamplerError::new(format!(
        "field not admitted: {field}"
    )))
}

/// Convert allocator units to bytes with a verified size.
///
/// Raises without a verified positive size or on overflow.
pub fn slots_to_bytes(
    slots: u64,
    unit_size: u64,
    has_unit_size: bool,
) -> Result<u64, PoolSamplerError> {
    if !has_unit_size || unit_size == 0 {
        return Err(PoolSamplerError::new("unverified unit size"));
    }
    if slots > u64::MAX / unit_size {
        return Err(PoolSamplerError::new("unit conversion overflow"));
    }
    Ok(slots * unit_size)
}

/// One default-pool counter read with per-half status.
///
/// Each half is known or it is not; reason names the first
/// failure in used/capacity/hiwater order, and stays empty
/// when all three halves are known.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolCounterRead {
    /// True when the used half read.
    pub has_used: bool,
    /// Used slots; zero unless `has_used`.
    pub used_slots: u64,
    /// True when the capacity half read.
    pub has_cap: bool,
    /// Capacity slots; zero unless `has_cap`.
    pub cap_slots: u64,
    /// True when the high-water half read.
    pub has_hiwater: bool,
    /// High-water slots; zero unless `has_hiwater`.
    pub hiwater_slots: u64,
    /// First failure reason; empty when all halves read.
    pub reason: String,
}

/// Parse one debugfs counter: digits plus one trailing newline.
///
/// Byte-exact: anything else raises, and the digit run goes
/// through the canonical u64 parser, so leading zeros and
/// overflow raise too.
fn parse_counter(raw: &[u8]) -> Result<u64, PoolSamplerError> {
    let mut end = raw.len();
    if end > 0 && raw[end - 1] == 0x0A {
        end -= 1;
    }
    if end == 0 || end > 20 {
        return Err(PoolSamplerError::new("counter shape"));
    }
    for b in &raw[..end] {
        if !(0x30..=0x39).contains(b) {
            return Err(PoolSamplerError::new("counter not a number"));
        }
    }
    let text = std::str::from_utf8(&raw[..end])
        .map_err(|_| PoolSamplerError::new("counter not a number"))?;
    parse_u64(text).map_err(|e| PoolSamplerError::new(e.to_string()))
}

/// Read one counter file; failures become a reason string.
fn read_counter(reader: &EvidenceReader, path: &str) -> (bool, u64, String) {
    let raw = match read_evidence(reader, path, COUNTER_CAP) {
        Ok(raw) => raw,
        Err(e) => {
            if e.code == E_ABSENT {
                return (false, 0, "absent".to_string());
            }
            // E_DENIED and any other read failure both mean the
            // content is unreadable, which absence cannot prove.
            return (false, 0, "denied".to_string());
        }
    };
    match parse_counter(&raw) {
        Ok(v) => (true, v, String::new()),
        Err(_) => (false, 0, "unparseable".to_string()),
    }
}

/// Sample the default SWIOTLB pool counters; never raises.
///
/// Absent, denied, and unparseable files yield unknown halves
/// with a reason, never zeros. The hiwater file needs
/// track_hiwater and a reset discipline the sampler does not
/// perform; its value is historical, and analysis scopes it
/// as allocator-lifetime with an unproved reset epoch.
pub fn read_pool_counters(reader: &EvidenceReader) -> PoolCounterRead {
    let mut out = PoolCounterRead::default();
    let used = read_counter(reader, POOL_SWIOTLB_USED);
    out.has_used = used.0;
    out.used_slots = used.1;
    let cap = read_counter(reader, POOL_SWIOTLB_NSLABS);
    out.has_cap = cap.0;
    out.cap_slots = cap.1;
    let water = read_counter(reader, POOL_SWIOTLB_HIWATER);
    out.has_hiwater = water.0;
    out.hiwater_slots = water.1;
    if !used.0 {
        out.reason = used.2;
    } else if !cap.0 {
        out.reason = cap.2;
    } else if !water.0 {
        out.reason = water.2;
    }
    out
}

/// One normalized pool reading with byte units or reasons.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedPoolSample {
    /// Opaque pool token.
    pub pool_id: String,
    /// True when used bytes are known.
    pub has_used_bytes: bool,
    /// Used bytes; zero unless `has_used_bytes`.
    pub used_bytes: u64,
    /// True when capacity bytes are known.
    pub has_capacity_bytes: bool,
    /// Capacity bytes; zero unless `has_capacity_bytes`.
    pub capacity_bytes: u64,
    /// Unit enum.
    pub unit: String,
    /// Allocator token.
    pub allocator: String,
    /// True when the unit size is known.
    pub has_unit_bytes: bool,
    /// Unit size; zero unless `has_unit_bytes`.
    pub unit_bytes: u64,
    /// True when the high-water mark is known.
    pub has_hiwater_bytes: bool,
    /// High-water bytes; zero unless `has_hiwater_bytes`.
    pub hiwater_bytes: u64,
    /// Absence reason enum; empty unless reported.
    pub reason: String,
    /// Human notes.
    pub notes: String,
}

impl Default for NormalizedPoolSample {
    fn default() -> Self {
        Self {
            pool_id: String::new(),
            has_used_bytes: false,
            used_bytes: 0,
            has_capacity_bytes: false,
            capacity_bytes: 0,
            unit: "bytes".to_string(),
            allocator: String::new(),
            has_unit_bytes: false,
            unit_bytes: 0,
            has_hiwater_bytes: false,
            hiwater_bytes: 0,
            reason: String::new(),
            notes: String::new(),
        }
    }
}

/// Sample, convert, and normalize the default pool; never raises.
///
/// The unit size is caller-supplied (the live collector passes
/// the kernel-fixed slot size); a conversion overflow yields an
/// unavailable sample rather than a wrapped number.
pub fn sample_default_pool(
    reader: &EvidenceReader,
    pool_id: &str,
    unit_size: u64,
) -> NormalizedPoolSample {
    let counters = read_pool_counters(reader);
    match normalize_pool_sample(
        pool_id,
        counters.has_used,
        counters.used_slots,
        counters.has_cap,
        counters.cap_slots,
        unit_size,
        true,
        "swiotlb debugfs",
        POOL_SWIOTLB_ALLOCATOR,
        counters.has_hiwater,
        counters.hiwater_slots,
        &counters.reason,
    ) {
        Ok(sample) => sample,
        Err(_) => NormalizedPoolSample {
            pool_id: pool_id.to_string(),
            allocator: POOL_SWIOTLB_ALLOCATOR.to_string(),
            reason: "unparseable".to_string(),
            notes: "counter value unusable as bytes from swiotlb debugfs".to_string(),
            ..Default::default()
        },
    }
}

/// Normalize one raw pool reading.
///
/// Pool ids are generation-scoped opaque tokens: successive
/// generations of one source name sample under distinct ids so
/// streaks never span a pool re-creation. Missing halves stay
/// unavailable with a reason; conversion overflow raises. The
/// allocator names the sampled scope, unit_bytes records the
/// verified conversion basis, and hiwater carries the
/// allocator-lifetime high-water mark when the read succeeded.
#[allow(clippy::too_many_arguments)]
pub fn normalize_pool_sample(
    pool_id: &str,
    has_used_slots: bool,
    used_slots: u64,
    has_cap_slots: bool,
    cap_slots: u64,
    unit_size: u64,
    has_unit_size: bool,
    source: &str,
    allocator: &str,
    has_hw_slots: bool,
    hw_slots: u64,
    reason: &str,
) -> Result<NormalizedPoolSample, PoolSamplerError> {
    check_opaque_id(pool_id).map_err(|e| PoolSamplerError::new(e.to_string()))?;
    if source.is_empty() {
        return Err(PoolSamplerError::new("empty source"));
    }
    check_opaque_id(allocator).map_err(|e| PoolSamplerError::new(e.to_string()))?;
    if !reason.is_empty() && reason != "denied" && reason != "absent" && reason != "unparseable" {
        return Err(PoolSamplerError::new(format!("bad reason: {reason}")));
    }
    if has_unit_size && unit_size == 0 {
        return Err(PoolSamplerError::new("unit size must be positive"));
    }
    let mut out = NormalizedPoolSample {
        pool_id: pool_id.to_string(),
        allocator: allocator.to_string(),
        reason: reason.to_string(),
        ..Default::default()
    };
    if has_unit_size {
        out.unit_bytes = unit_size;
        out.has_unit_bytes = true;
    }
    if has_used_slots {
        out.used_bytes = slots_to_bytes(used_slots, unit_size, has_unit_size)?;
        out.has_used_bytes = true;
    } else {
        out.notes = format!("usage unavailable from {source}");
    }
    if has_cap_slots {
        out.capacity_bytes = slots_to_bytes(cap_slots, unit_size, has_unit_size)?;
        out.has_capacity_bytes = true;
    } else {
        if !out.notes.is_empty() {
            out.notes += "; ";
        }
        out.notes += &format!("capacity unavailable from {source}");
    }
    if has_hw_slots {
        out.hiwater_bytes = slots_to_bytes(hw_slots, unit_size, has_unit_size)?;
        out.has_hiwater_bytes = true;
    }
    Ok(out)
}

/// True when a sample shows pool pressure (collect-side).
///
/// Same predicate the analysis streak uses (used at or
/// above 90% of capacity, both halves present, nonzero
/// capacity): the collector gates post-cap persists on it
/// so a pressure finding can still form past the routine
/// cap.
pub fn pool_sample_pressured(sample: &NormalizedPoolSample) -> bool {
    if !sample.has_used_bytes {
        return false;
    }
    if !sample.has_capacity_bytes {
        return false;
    }
    if sample.capacity_bytes == 0 {
        return false;
    }
    let threshold = sample.capacity_bytes - sample.capacity_bytes / 10;
    sample.used_bytes >= threshold
}

#[cfg(test)]
mod tests {
    use super::{
        NormalizedPoolSample, POOL_SWIOTLB_ALLOCATOR, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT,
        check_field_admitted, normalize_pool_sample, pool_sample_pressured, read_pool_counters,
        sample_default_pool, slots_to_bytes,
    };
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::repo_root;

    fn fixture(name: &str) -> String {
        repo_root()
            .join("tests/fixtures/pools")
            .join(name)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    #[test]
    fn ok_counters_read() {
        let reader = open_evidence_reader(&fixture("debugfs-ok")).expect("reader");
        let got = read_pool_counters(&reader);
        assert!(got.has_used);
        assert_eq!(got.used_slots, 12);
        assert!(got.has_cap);
        assert_eq!(got.cap_slots, 32768);
        assert!(got.has_hiwater);
        assert_eq!(got.hiwater_slots, 64);
        assert_eq!(got.reason, "");
    }

    #[test]
    fn denied_used_names_denied_first() {
        let reader = open_evidence_reader(&fixture("debugfs-denied")).expect("reader");
        let got = read_pool_counters(&reader);
        assert!(!got.has_used);
        assert!(got.has_cap);
        assert_eq!(got.reason, "denied");
    }

    #[test]
    fn absent_counters_name_absent() {
        let reader = open_evidence_reader(&fixture("debugfs-absent")).expect("reader");
        let got = read_pool_counters(&reader);
        assert!(!got.has_used);
        assert!(!got.has_cap);
        assert!(!got.has_hiwater);
        assert_eq!(got.reason, "absent");
    }

    #[test]
    fn bad_counters_name_unparseable() {
        let reader = open_evidence_reader(&fixture("debugfs-bad")).expect("reader");
        let got = read_pool_counters(&reader);
        assert_eq!(got.reason, "unparseable");
    }

    #[test]
    fn sample_converts_slots_to_bytes() {
        let reader = open_evidence_reader(&fixture("debugfs-ok")).expect("reader");
        let got = sample_default_pool(&reader, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT);
        assert_eq!(got.pool_id, POOL_SWIOTLB_POOL_ID);
        assert_eq!(got.allocator, POOL_SWIOTLB_ALLOCATOR);
        assert!(got.has_used_bytes);
        assert_eq!(got.used_bytes, 12 * 2048);
        assert!(got.has_capacity_bytes);
        assert_eq!(got.capacity_bytes, 32768 * 2048);
        assert!(got.has_unit_bytes);
        assert_eq!(got.unit_bytes, 2048);
        assert!(got.has_hiwater_bytes);
        assert_eq!(got.hiwater_bytes, 64 * 2048);
        assert_eq!(got.reason, "");
    }

    #[test]
    fn sample_denied_stays_unavailable() {
        let reader = open_evidence_reader(&fixture("debugfs-denied")).expect("reader");
        let got = sample_default_pool(&reader, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT);
        assert!(!got.has_used_bytes);
        assert!(got.has_capacity_bytes);
        assert_eq!(got.reason, "denied");
        assert!(got.notes.contains("usage unavailable"));
    }

    #[test]
    fn slots_require_verified_size() {
        assert_eq!(slots_to_bytes(3, 2048, true).expect("ok"), 6144);
        assert!(slots_to_bytes(3, 2048, false).is_err());
        assert!(slots_to_bytes(3, 0, true).is_err());
        assert!(slots_to_bytes(u64::MAX, 2, true).is_err());
        assert_eq!(
            slots_to_bytes(u64::MAX / 2048, 2048, true).expect("edge"),
            u64::MAX / 2048 * 2048
        );
    }

    #[test]
    fn normalize_rejects_bad_inputs() {
        // Bad pool id.
        assert!(
            normalize_pool_sample(
                "",
                false,
                0,
                false,
                0,
                2048,
                true,
                "swiotlb debugfs",
                POOL_SWIOTLB_ALLOCATOR,
                false,
                0,
                "",
            )
            .is_err()
        );
        // Empty source.
        assert!(
            normalize_pool_sample(
                POOL_SWIOTLB_POOL_ID,
                false,
                0,
                false,
                0,
                2048,
                true,
                "",
                POOL_SWIOTLB_ALLOCATOR,
                false,
                0,
                "",
            )
            .is_err()
        );
        // Bad reason.
        assert!(
            normalize_pool_sample(
                POOL_SWIOTLB_POOL_ID,
                false,
                0,
                false,
                0,
                2048,
                true,
                "swiotlb debugfs",
                POOL_SWIOTLB_ALLOCATOR,
                false,
                0,
                "bogus",
            )
            .is_err()
        );
        // Zero unit size with the flag set.
        assert!(
            normalize_pool_sample(
                POOL_SWIOTLB_POOL_ID,
                false,
                0,
                false,
                0,
                0,
                true,
                "swiotlb debugfs",
                POOL_SWIOTLB_ALLOCATOR,
                false,
                0,
                "",
            )
            .is_err()
        );
        // Conversion overflow raises.
        assert!(
            normalize_pool_sample(
                POOL_SWIOTLB_POOL_ID,
                true,
                u64::MAX,
                false,
                0,
                2048,
                true,
                "swiotlb debugfs",
                POOL_SWIOTLB_ALLOCATOR,
                false,
                0,
                "",
            )
            .is_err()
        );
    }

    #[test]
    fn normalize_missing_halves_note_sources() {
        let got = normalize_pool_sample(
            POOL_SWIOTLB_POOL_ID,
            false,
            0,
            false,
            0,
            2048,
            true,
            "swiotlb debugfs",
            POOL_SWIOTLB_ALLOCATOR,
            false,
            0,
            "denied",
        )
        .expect("normalizes");
        assert!(!got.has_used_bytes);
        assert!(!got.has_capacity_bytes);
        assert!(got.has_unit_bytes);
        assert_eq!(
            got.notes,
            "usage unavailable from swiotlb debugfs; capacity unavailable from swiotlb debugfs"
        );
    }

    #[test]
    fn field_admission_allowlist() {
        let admitted = vec!["used".to_string(), "nslabs".to_string()];
        check_field_admitted("used", &admitted).expect("admitted");
        assert!(check_field_admitted("other", &admitted).is_err());
    }

    fn pressured(used: u64, cap: u64) -> bool {
        let sample = NormalizedPoolSample {
            has_used_bytes: true,
            used_bytes: used,
            has_capacity_bytes: true,
            capacity_bytes: cap,
            ..Default::default()
        };
        pool_sample_pressured(&sample)
    }

    #[test]
    fn pressure_predicate_edges() {
        // Same 90% boundary the analysis streak uses (capacity
        // 4096: integer threshold 4096 - 409 = 3687 qualifies,
        // 3686 not).
        assert!(pressured(3687, 4096));
        assert!(!pressured(3686, 4096));
        assert!(!pressured(0, 0));
        assert!(!pressured(1, 0));
        let missing = NormalizedPoolSample {
            has_used_bytes: true,
            used_bytes: 4096,
            ..Default::default()
        };
        assert!(!pool_sample_pressured(&missing));
        let missing2 = NormalizedPoolSample {
            has_capacity_bytes: true,
            capacity_bytes: 4096,
            ..Default::default()
        };
        assert!(!pool_sample_pressured(&missing2));
        assert!(pressured(u64::MAX, u64::MAX));
    }

    #[test]
    fn pressure_fixture_pressured_ok_quiet() {
        let reader = open_evidence_reader(&fixture("debugfs-pressure")).expect("reader");
        let hot = sample_default_pool(&reader, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT);
        assert!(pool_sample_pressured(&hot));
        let reader = open_evidence_reader(&fixture("debugfs-ok")).expect("reader");
        let calm = sample_default_pool(&reader, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT);
        assert!(!pool_sample_pressured(&calm));
    }
}
