// SPDX-License-Identifier: GPL-3.0-or-later
//! Lifecycle/copy wire decode, Event mapping, and the ledger.
//!
//! Decodes the 44-byte MVLC v2 and 48-byte MVCP v1 records produced
//! by the swiotlb lifecycle and copy probes. Byte layout, check
//! order, and reason vocabulary mirror
//! `bpf/include/memveil_events.h`. Wire decoding delegates to the
//! shared wire crate; this module maps verdicts onto the shared
//! reason vocabulary, normalizes records onto Events, and keeps
//! the per-event ledger.
//!
//! MVLC v2 carries an opaque mapping generation (0 = unknown);
//! the ledger pairs map/unmap only on nonzero generations and
//! reports lifetimes as eligible-but-incomplete after misses,
//! loss, or an invalid epoch. MVCP carries no identity: copy
//! and sync records never pair.

use crate::capture::normalize::{DecodeError, NormalizeError};
use crate::model::event::Event;
use crate::model::validate::{ValidationError, checked_add, format_u64};

/// MVLC v2 record length in bytes.
pub const LC_LEN: usize = 44;
/// MVCP v1 record length in bytes.
pub const CP_LEN: usize = 48;

/// Frozen probe hook identities shared by normalization,
/// registry admission, and session capabilities: one definition
/// so admission can never skew from emission.
pub const HOOK_MAP_RESULT: &str = "fexit:swiotlb_tbl_map_single";
/// Unmap probe hook identity.
pub const HOOK_UNMAP: &str = "fentry:__swiotlb_tbl_unmap_single";
/// Sync-for-device probe hook identity.
pub const HOOK_SYNC_DEVICE: &str = "fentry:__swiotlb_sync_single_for_device";
/// Sync-for-cpu probe hook identity.
pub const HOOK_SYNC_CPU: &str = "fentry:__swiotlb_sync_single_for_cpu";
/// Bounce-copy probe hook identity.
pub const HOOK_BOUNCE: &str = "fentry:swiotlb_bounce";

/// Copy record kind.
pub const CP_KIND_COPY: u16 = 2;
/// Copy unknown-effective reasons.
pub const CP_REASON_SLOT_READ: u16 = 1;
/// Copy unknown-effective reasons.
pub const CP_REASON_MASK_READ: u16 = 2;
/// Copy unknown-effective reasons.
pub const CP_REASON_BOUNDS: u16 = 3;
/// Copy unknown-effective reasons.
pub const CP_REASON_LAYOUT: u16 = 5;
/// Copy unknown-effective reasons.
pub const CP_REASON_SHIFT: u16 = 6;

/// One decoded MVLC v2 record: map result or unmap fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLifecycle {
    /// Record kind: map or unmap.
    pub kind: u16,
    /// Slots found (map) or entry live (unmap).
    pub ok: bool,
    /// Unmap skipped the sync.
    pub skip_sync: bool,
    /// Raw DMA data direction value.
    pub dir: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Mapping size.
    pub size: u64,
    /// Opaque mapping generation (0 means unknown).
    pub generation: u64,
}

/// One decoded MVCP record: sync request or executed copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedCopy {
    /// Record kind: sync or copy.
    pub kind: u16,
    /// Direction toward the device.
    pub to_device: bool,
    /// Effective length is known.
    pub known: bool,
    /// Effective length was clamped to the room.
    pub clamped: bool,
    /// Invalid slot, nothing copied.
    pub early_zero: bool,
    /// Offset ran past the allocation (wrapped room).
    pub offset_past: bool,
    /// Copy ran against the private pool.
    pub private_pool: bool,
    /// Raw DMA data direction value.
    pub dir: u16,
    /// Unknown-effective reason.
    pub reason: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Requested length.
    pub requested: u64,
    /// Executed length.
    pub effective: u64,
}

/// Replicated swiotlb_bounce length outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EffectiveOut {
    /// Executed copy length.
    pub effective: u64,
    /// Effective length was clamped to the room.
    pub clamped: bool,
    /// Invalid slot, nothing copied.
    pub early_zero: bool,
    /// Offset ran past the allocation (wrapped room).
    pub offset_past: bool,
}

/// Decode and strictly validate one MVLC v2 record.
///
/// Check order matches the C reference: header guard, magic,
/// version (v1 bytes fail here, not on length), length, kind,
/// flags, direction, flag/generation coupling, generation range.
pub fn decode_lifecycle(raw: &[u8]) -> Result<DecodedLifecycle, DecodeError> {
    let wire = memveil_ebpf_common::decode_lifecycle(raw).map_err(|err| {
        let reason = match err {
            memveil_ebpf_common::DecodeError::Short => "PAY_SHORT",
            memveil_ebpf_common::DecodeError::Long => "PAY_LONG",
            memveil_ebpf_common::DecodeError::Magic => "PAY_MAGIC",
            memveil_ebpf_common::DecodeError::Version => "PAY_VERSION",
            memveil_ebpf_common::DecodeError::Kind => "PAY_KIND",
            memveil_ebpf_common::DecodeError::Flags => "PAY_FLAGS",
            memveil_ebpf_common::DecodeError::Dir => "PAY_DIR",
            memveil_ebpf_common::DecodeError::Range => "PAY_RANGE",
            // Unreachable in practice: the lifecycle decoder emits
            // no other verdict. Enumerated (not `_`) so a future
            // DecodeError variant fails the build here instead of
            // panicking at runtime.
            memveil_ebpf_common::DecodeError::NameLen => "PAY_NAMELEN",
            memveil_ebpf_common::DecodeError::Nul => "PAY_NUL",
            memveil_ebpf_common::DecodeError::Pad => "PAY_PAD",
            memveil_ebpf_common::DecodeError::Reason => "PAY_REASON",
            memveil_ebpf_common::DecodeError::TableBad => "PAY_TABLE",
        };
        DecodeError {
            reason: reason.to_string(),
            fatal: true,
        }
    })?;
    Ok(DecodedLifecycle {
        kind: wire.kind,
        ok: wire.ok,
        skip_sync: wire.skip_sync,
        dir: wire.dir,
        seq: wire.seq,
        ktime: wire.ktime,
        size: wire.size,
        generation: wire.generation,
    })
}

/// Decode and strictly validate one MVCP record.
///
/// Check order matches the C reference: length, magic, version,
/// kind, flags (mask plus offset-past/private-pool coupling),
/// direction, then the known/reason cross rules.
pub fn decode_copy(raw: &[u8]) -> Result<DecodedCopy, DecodeError> {
    let wire = memveil_ebpf_common::decode_copy(raw).map_err(|err| {
        let reason = match err {
            memveil_ebpf_common::DecodeError::Short => "PAY_SHORT",
            memveil_ebpf_common::DecodeError::Long => "PAY_LONG",
            memveil_ebpf_common::DecodeError::Magic => "PAY_MAGIC",
            memveil_ebpf_common::DecodeError::Version => "PAY_VERSION",
            memveil_ebpf_common::DecodeError::Kind => "PAY_KIND",
            memveil_ebpf_common::DecodeError::Flags => "PAY_FLAGS",
            memveil_ebpf_common::DecodeError::Dir => "PAY_DIR",
            memveil_ebpf_common::DecodeError::Reason => "PAY_REASON",
            // Unreachable in practice: the copy decoder emits
            // no other verdict. Enumerated (not `_`) so a future
            // DecodeError variant fails the build here instead of
            // panicking at runtime.
            memveil_ebpf_common::DecodeError::NameLen => "PAY_NAMELEN",
            memveil_ebpf_common::DecodeError::Nul => "PAY_NUL",
            memveil_ebpf_common::DecodeError::Pad => "PAY_PAD",
            memveil_ebpf_common::DecodeError::Range => "PAY_RANGE",
            memveil_ebpf_common::DecodeError::TableBad => "PAY_TABLE",
        };
        DecodeError {
            reason: reason.to_string(),
            fatal: true,
        }
    })?;
    Ok(DecodedCopy {
        kind: wire.kind,
        to_device: wire.to_device,
        known: wire.known,
        clamped: wire.clamped,
        early_zero: wire.early_zero,
        offset_past: wire.offset_past,
        private_pool: wire.private_pool,
        dir: wire.dir,
        reason: wire.reason,
        seq: wire.seq,
        ktime: wire.ktime,
        requested: wire.requested,
        effective: wire.effective,
    })
}

/// Wire reason of an unknown copy, for quality reporting.
pub fn copy_unknown_reason_name(reason: u16) -> String {
    match reason {
        CP_REASON_SLOT_READ => "SLOT_READ".to_string(),
        CP_REASON_MASK_READ => "MASK_READ".to_string(),
        CP_REASON_BOUNDS => "BOUNDS".to_string(),
        CP_REASON_LAYOUT => "LAYOUT".to_string(),
        CP_REASON_SHIFT => "SHIFT".to_string(),
        _ => format!("REASON_{}", format_u64(u64::from(reason))),
    }
}

/// Replicate the hook tlb_offset math for cross-checks.
///
/// Mirrors the C reference: both masked terms fit in s32, so the
/// signed difference is exact.
pub fn tlb_offset(tlb_addr: u64, orig_addr: u64, min_align_mask: u32) -> i64 {
    let lo = (tlb_addr & 2047) as i64;
    let masked = (orig_addr & u64::from(min_align_mask) & 2047) as i64;
    lo - masked
}

/// Replicate the swiotlb_bounce length rule for cross-checks.
///
/// Mirrors the C reference: an invalid slot copies nothing (hook
/// early return); otherwise the room is alloc_size - tlb_offset
/// in wrapping u64 arithmetic exactly like the hook's
/// alloc_size -= tlb_offset in size_t, including the wrap when
/// the offset runs past the allocation.
pub fn effective_bytes(
    size: u64,
    tlb_offset: i64,
    alloc_size: u64,
    orig_valid: bool,
) -> EffectiveOut {
    if !orig_valid {
        return EffectiveOut {
            effective: 0,
            clamped: false,
            early_zero: true,
            offset_past: false,
        };
    }
    // Same formula as the C reference, including INT64_MIN:
    // tlb_offset + 1 cannot overflow, so its negation fits and
    // the +1 widening lands exactly at 2**63; no special case.
    let room = if tlb_offset < 0 {
        let widen = (0i64.wrapping_sub(tlb_offset.wrapping_add(1)) as u64).wrapping_add(1);
        alloc_size.wrapping_add(widen)
    } else {
        alloc_size.wrapping_sub(tlb_offset as u64)
    };
    let past = tlb_offset > 0 && (tlb_offset as u64) > alloc_size;
    if size > room {
        EffectiveOut {
            effective: room,
            clamped: true,
            early_zero: false,
            offset_past: past,
        }
    } else {
        EffectiveOut {
            effective: size,
            clamped: false,
            early_zero: false,
            offset_past: past,
        }
    }
}

/// Per-event lifecycle/copy facts plus wire-gen pairing scope.
///
/// Wire generations render as gen-N tokens; the ledger counts
/// unknown identities (unassigned maps, missed unmaps)
/// separately so they can never hide inside a paired total. The
/// open estimate stays maps minus unmaps saturated at zero and
/// is never a pairing claim; pairing itself lives in the
/// correlation registry. Totals use checked u64 arithmetic: a
/// note that would overflow raises and changes nothing.
#[derive(Debug, Default)]
pub struct LifecycleLedger {
    /// Successful maps.
    pub maps_ok: u64,
    /// Successful mapped bytes.
    pub maps_ok_bytes: u64,
    /// Failed maps.
    pub maps_failed: u64,
    /// Successful maps without an assigned generation.
    pub maps_unassigned: u64,
    /// Unmaps.
    pub unmaps: u64,
    /// Unmapped bytes.
    pub unmaps_bytes: u64,
    /// Unmaps that skipped the sync.
    pub unmaps_skip_sync: u64,
    /// Unmaps with a missed generation.
    pub unmaps_gen_miss: u64,
    /// Sync requests.
    pub sync_requests: u64,
    /// Known copies.
    pub copies_known: u64,
    /// Known effective bytes.
    pub copies_known_effective_bytes: u64,
    /// Private-pool effective bytes.
    pub copies_private_effective_bytes: u64,
    /// Offset-past-allocation copies.
    pub copies_offset_past: u64,
    /// Unknown copies.
    pub copies_unknown: u64,
    /// True once any wire generation is observed.
    pub saw_wire_gen: bool,
}

impl LifecycleLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count one lifecycle record; report its wire token.
    ///
    /// Returns the gen-N token for a known-generation map, or
    /// the empty string for failed maps, unassigned maps, and
    /// all unmaps (unknown identities never mint and never pair
    /// here). Raises without changing the ledger if any total
    /// would exceed u64.
    pub fn note_lifecycle(&mut self, d: &DecodedLifecycle) -> Result<String, ValidationError> {
        if d.kind == memveil_ebpf_common::MV_LC_KIND_MAP {
            if d.ok {
                let count = checked_add(self.maps_ok, 1)?;
                let total = checked_add(self.maps_ok_bytes, d.size)?;
                let mut unassigned = self.maps_unassigned;
                if d.generation == 0 {
                    unassigned = checked_add(self.maps_unassigned, 1)?;
                } else {
                    self.saw_wire_gen = true;
                }
                self.maps_ok = count;
                self.maps_ok_bytes = total;
                self.maps_unassigned = unassigned;
                if d.generation == 0 {
                    return Ok(String::new());
                }
                return Ok(wire_gen_token(d.generation));
            }
            self.maps_failed = checked_add(self.maps_failed, 1)?;
            return Ok(String::new());
        }
        let ucount = checked_add(self.unmaps, 1)?;
        let utotal = checked_add(self.unmaps_bytes, d.size)?;
        let mut scount = self.unmaps_skip_sync;
        if d.skip_sync {
            scount = checked_add(self.unmaps_skip_sync, 1)?;
        }
        let mut miss = self.unmaps_gen_miss;
        if d.generation == 0 {
            miss = checked_add(self.unmaps_gen_miss, 1)?;
        } else {
            self.saw_wire_gen = true;
        }
        self.unmaps = ucount;
        self.unmaps_bytes = utotal;
        self.unmaps_skip_sync = scount;
        self.unmaps_gen_miss = miss;
        Ok(String::new())
    }

    /// Count one copy record; sum effective bytes when KNOWN.
    ///
    /// Sync requests and unknown copies never contribute
    /// executed bytes; unknown copies count separately so a
    /// quiet effective total cannot hide missing evidence.
    /// Raises without changing the ledger if any total would
    /// exceed u64.
    pub fn note_copy(&mut self, d: &DecodedCopy) -> Result<(), ValidationError> {
        if d.kind == memveil_ebpf_common::MV_CP_KIND_SYNC {
            self.sync_requests = checked_add(self.sync_requests, 1)?;
            return Ok(());
        }
        if d.known {
            let count = checked_add(self.copies_known, 1)?;
            let total = checked_add(self.copies_known_effective_bytes, d.effective)?;
            let mut priv_total = self.copies_private_effective_bytes;
            if d.private_pool {
                priv_total = checked_add(priv_total, d.effective)?;
            }
            let mut past = self.copies_offset_past;
            if d.offset_past {
                past = checked_add(past, 1)?;
            }
            self.copies_known = count;
            self.copies_known_effective_bytes = total;
            self.copies_private_effective_bytes = priv_total;
            self.copies_offset_past = past;
        } else {
            self.copies_unknown = checked_add(self.copies_unknown, 1)?;
        }
        Ok(())
    }

    /// Maps minus unmaps, saturated: never a pairing claim.
    pub fn open_estimate(&self) -> u64 {
        self.maps_ok.saturating_sub(self.unmaps)
    }

    /// Eligible once any wire generation is observed.
    pub fn lifetimes_available(&self) -> bool {
        self.saw_wire_gen
    }

    /// Human-readable lifetime eligibility reason.
    pub fn lifetimes_reason(&self) -> String {
        if self.saw_wire_gen {
            "wire generations present; map/unmap pairing eligible (misses and loss still caveat \
             completeness)"
                .to_string()
        } else {
            "no wire mapping identity observed; pairing unavailable".to_string()
        }
    }
}

/// Mint one record-local id; never kernel identity.
fn record_id(seq: u64) -> String {
    format!("lc-{}", format_u64(seq))
}

/// Render one wire generation as an opaque mapping token.
///
/// Shared `gen-{n}` key namespace with the correlation
/// registry: both sides must mint identical tokens or
/// map/unmap pairing silently misattributes.
pub(crate) fn wire_gen_token(generation: u64) -> String {
    format!("gen-{}", format_u64(generation))
}

/// Map one decoded MVLC v2 record onto a normalized Event.
///
/// Kind, timestamp, per-probe hook name, and payload are set;
/// the collector stamps the capture-derived source block and
/// runs the correlation registry before persisting.
pub fn normalize_lifecycle_event(d: &DecodedLifecycle) -> Event {
    let mut ev = Event {
        ts_ns: d.ktime,
        ..Default::default()
    };
    if d.kind == memveil_ebpf_common::MV_LC_KIND_MAP {
        ev.kind = "map_result".to_string();
        ev.source_hook = HOOK_MAP_RESULT.to_string();
        ev.source_backend = "tracing".to_string();
        ev.map_result.operation_id = record_id(d.seq);
        ev.map_result.success = d.ok;
        ev.map_result.has_wire_generation = true;
        ev.map_result.wire_generation = d.generation;
        if d.ok {
            ev.map_result.has_mapped_bytes = true;
            ev.map_result.mapped_bytes = d.size;
            ev.map_result.has_wire_identity = true;
            if d.generation != 0 {
                ev.map_result.has_mapping_id = true;
                ev.map_result.mapping_id = wire_gen_token(d.generation);
                ev.map_result.wire_identity = "known".to_string();
            } else {
                ev.map_result.wire_identity = "unassigned".to_string();
            }
        }
        return ev;
    }
    ev.kind = "unmap".to_string();
    ev.source_hook = HOOK_UNMAP.to_string();
    ev.source_backend = "tracing".to_string();
    ev.unmap.has_wire_generation = true;
    ev.unmap.wire_generation = d.generation;
    ev.unmap.has_wire_identity = true;
    if d.generation != 0 {
        ev.unmap.has_mapping_id = true;
        ev.unmap.mapping_id = wire_gen_token(d.generation);
        ev.unmap.wire_identity = "known".to_string();
    } else {
        ev.unmap.wire_identity = "miss".to_string();
    }
    ev
}

/// Map one decoded MVCP record onto a normalized Event.
///
/// Sync requests become sync_request events with unobserved
/// offset; KNOWN copies become copy events with executed (never
/// requested) bytes; an unknown copy raises non-fatal
/// UNKNOWN_COPY so the collector drops exactly that record
/// instead of persisting an invented length.
pub fn normalize_copy_event(d: &DecodedCopy) -> Result<Event, NormalizeError> {
    let mut ev = Event {
        ts_ns: d.ktime,
        ..Default::default()
    };
    if d.kind == memveil_ebpf_common::MV_CP_KIND_SYNC {
        ev.kind = "sync_request".to_string();
        if d.to_device {
            ev.source_hook = HOOK_SYNC_DEVICE.to_string();
        } else {
            ev.source_hook = HOOK_SYNC_CPU.to_string();
        }
        ev.source_backend = "tracing".to_string();
        ev.sync.operation_id = record_id(d.seq);
        ev.sync.has_mapping_id = true;
        ev.sync.mapping_id = record_id(d.seq);
        ev.sync.has_offset = false;
        ev.sync.length = d.requested;
        return Ok(ev);
    }
    if !d.known {
        return Err(NormalizeError {
            reason: "UNKNOWN_COPY".to_string(),
            fatal: false,
        });
    }
    ev.kind = "copy".to_string();
    ev.source_hook = HOOK_BOUNCE.to_string();
    ev.source_backend = "tracing".to_string();
    ev.copy.operation_id = record_id(d.seq);
    if d.to_device {
        ev.copy.direction = "original_to_bounce".to_string();
    } else {
        ev.copy.direction = "bounce_to_original".to_string();
    }
    ev.copy.bytes = d.effective;
    ev.copy.pool_private = d.private_pool;
    ev.copy.offset_past_allocation = d.offset_past;
    Ok(ev)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lc_raw(
        kind: u16,
        flags: u16,
        dir: u16,
        seq: u64,
        ktime: u64,
        size: u64,
        generation: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x434C_564Du32.to_le_bytes());
        out.extend_from_slice(&2u16.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&dir.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ktime.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out.extend_from_slice(&generation.to_le_bytes());
        out
    }

    fn lc_raw_v1(kind: u16, flags: u16, dir: u16, seq: u64, ktime: u64, size: u64) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x434C_564Du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&dir.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ktime.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());
        out
    }

    // Eight wire fields in record order; a struct would hide the layout.
    #[allow(clippy::too_many_arguments)]
    fn cp_raw(
        kind: u16,
        flags: u16,
        dir: u16,
        seq: u64,
        ktime: u64,
        requested: u64,
        effective: u64,
        reason: u16,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x5043_564Du32.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&flags.to_le_bytes());
        out.extend_from_slice(&dir.to_le_bytes());
        out.extend_from_slice(&seq.to_le_bytes());
        out.extend_from_slice(&ktime.to_le_bytes());
        out.extend_from_slice(&requested.to_le_bytes());
        out.extend_from_slice(&effective.to_le_bytes());
        out.extend_from_slice(&reason.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }

    fn expect_lc(raw: &[u8], want: &str) {
        let err = decode_lifecycle(raw).expect_err("must reject");
        assert_eq!(err.reason, want);
        assert!(err.fatal);
    }

    fn expect_cp(raw: &[u8], want: &str) {
        let err = decode_copy(raw).expect_err("must reject");
        assert_eq!(err.reason, want);
        assert!(err.fatal);
    }

    #[test]
    fn wire_lengths() {
        assert_eq!(LC_LEN, 44);
        assert_eq!(CP_LEN, 48);
    }

    #[test]
    fn decode_lifecycle_map() {
        let d = decode_lifecycle(&lc_raw(1, 1, 1, 7, 9, 4096, 1)).expect("decodes");
        assert_eq!(d.kind, 1);
        assert!(d.ok);
        assert!(!d.skip_sync);
        assert_eq!(d.dir, 1);
        assert_eq!(d.seq, 7);
        assert_eq!(d.ktime, 9);
        assert_eq!(d.size, 4096);
        assert_eq!(d.generation, 1);
    }

    #[test]
    fn decode_lifecycle_unmap_skip_sync() {
        let d = decode_lifecycle(&lc_raw(2, 3, 2, 8, 10, 1024, 1)).expect("decodes");
        assert_eq!(d.kind, 2);
        assert!(d.ok);
        assert!(d.skip_sync);
        assert_eq!(d.dir, 2);
        assert_eq!(d.size, 1024);
        assert_eq!(d.generation, 1);
    }

    #[test]
    fn decode_copy_known() {
        let d = decode_copy(&cp_raw(2, 3, 1, 3, 4, 4096, 1024, 0)).expect("decodes");
        assert_eq!(d.kind, 2);
        assert!(d.to_device);
        assert!(d.known);
        assert!(!d.clamped);
        assert!(!d.early_zero);
        assert_eq!(d.requested, 4096);
        assert_eq!(d.effective, 1024);
    }

    #[test]
    fn decode_sync_request() {
        let d = decode_copy(&cp_raw(1, 1, 2, 5, 6, 512, 0, 4)).expect("decodes");
        assert_eq!(d.kind, 1);
        assert!(!d.known);
        assert_eq!(d.reason, 4);
        assert_eq!(d.requested, 512);
        assert_eq!(d.effective, 0);
    }

    #[test]
    fn lifecycle_rejections() {
        let good = lc_raw(1, 1, 0, 1, 1, 1, 1);
        expect_lc(&good[..5], "PAY_SHORT");
        expect_lc(&good[..35], "PAY_SHORT");
        let mut long = good.clone();
        long.push(0);
        expect_lc(&long, "PAY_LONG");
        let mut bad = good.clone();
        bad[0] = 0;
        expect_lc(&bad, "PAY_MAGIC");
        expect_lc(&lc_raw_v1(1, 1, 0, 1, 1, 1), "PAY_VERSION");
        let mut bad = good.clone();
        bad[4] = 3;
        expect_lc(&bad, "PAY_VERSION");
        expect_lc(&lc_raw(3, 1, 0, 1, 1, 1, 1), "PAY_KIND");
        expect_lc(&lc_raw(1, 16, 0, 1, 1, 1, 1), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 5, 0, 1, 1, 1, 4), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 9, 0, 1, 1, 1, 4), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 1, 0, 1, 1, 1, 0), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 2, 0, 1, 1, 1, 0), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 8, 0, 1, 1, 1, 0), "PAY_FLAGS");
        expect_lc(&lc_raw(2, 9, 0, 1, 1, 1, 0), "PAY_FLAGS");
        expect_lc(&lc_raw(2, 1, 0, 1, 1, 1, 0), "PAY_FLAGS");
        expect_lc(&lc_raw(2, 5, 0, 1, 1, 1, 4), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 1, 3, 1, 1, 1, 1), "PAY_DIR");
        expect_lc(&lc_raw(1, 1, 0, 1, 1, 1, u64::MAX), "PAY_RANGE");
        expect_lc(&lc_raw(2, 1, 0, 1, 1, 1, u64::MAX), "PAY_RANGE");
    }

    #[test]
    fn copy_rejections() {
        let good = cp_raw(2, 2, 1, 1, 1, 8, 8, 0);
        expect_cp(&good[..47], "PAY_SHORT");
        let mut long = good.clone();
        long.push(0);
        expect_cp(&long, "PAY_LONG");
        let mut bad = good.clone();
        bad[0] = 0;
        expect_cp(&bad, "PAY_MAGIC");
        let mut bad = good.clone();
        bad[4] = 2;
        expect_cp(&bad, "PAY_VERSION");
        expect_cp(&cp_raw(9, 2, 1, 1, 1, 8, 8, 0), "PAY_KIND");
        expect_cp(&cp_raw(2, 16, 1, 1, 1, 8, 8, 0), "PAY_FLAGS");
        expect_cp(&cp_raw(2, 2, 0, 1, 1, 8, 8, 0), "PAY_DIR");
        expect_cp(&cp_raw(2, 2, 1, 1, 1, 8, 8, 5), "PAY_REASON");
        expect_cp(&cp_raw(2, 2, 1, 1, 1, 8, 8, 1), "PAY_REASON");
        expect_cp(&cp_raw(1, 0, 1, 1, 1, 8, 0, 0), "PAY_REASON");
        expect_cp(&cp_raw(2, 0, 1, 1, 1, 8, 0, 0), "PAY_REASON");
        expect_cp(&cp_raw(2, 0, 1, 1, 1, 8, 0, 4), "PAY_REASON");
    }

    #[test]
    fn effective_rule() {
        let e = effective_bytes(4096, 0, 4096, false);
        assert_eq!(e.effective, 0);
        assert!(e.early_zero);
        assert!(!e.clamped);
        let e = effective_bytes(4096, 3072, 4096, true);
        assert_eq!(e.effective, 1024);
        assert!(e.clamped);
        let e = effective_bytes(1024, 0, 4096, true);
        assert_eq!(e.effective, 1024);
        assert!(!e.clamped);
        let e = effective_bytes(100, -50, 100, true);
        assert_eq!(e.effective, 100);
        assert!(!e.clamped);
        let e = effective_bytes(4096, 4096, 4096, true);
        assert_eq!(e.effective, 0);
        assert!(e.clamped);
    }

    #[test]
    fn canonical_nested_copies() {
        let mut ledger = LifecycleLedger::new();
        let a = decode_copy(&cp_raw(2, 3, 1, 1, 1, 4096, 4096, 0)).unwrap();
        let b = decode_copy(&cp_raw(2, 3, 1, 2, 2, 1024, 1024, 0)).unwrap();
        ledger.note_copy(&a).unwrap();
        ledger.note_copy(&b).unwrap();
        assert_eq!(ledger.copies_known, 2);
        assert_eq!(ledger.copies_known_effective_bytes, 5120);
    }

    #[test]
    fn canonical_copy_before_failed_map() {
        let mut ledger = LifecycleLedger::new();
        let cp = decode_copy(&cp_raw(2, 3, 1, 1, 1, 4096, 4096, 0)).unwrap();
        let mp = decode_lifecycle(&lc_raw(1, 0, 1, 1, 2, 4096, 0)).unwrap();
        ledger.note_copy(&cp).unwrap();
        ledger.note_lifecycle(&mp).unwrap();
        assert_eq!(ledger.copies_known_effective_bytes, 4096);
        assert_eq!(ledger.maps_ok, 0);
        assert_eq!(ledger.maps_failed, 1);
    }

    #[test]
    fn canonical_sync_invents_nothing() {
        let mut ledger = LifecycleLedger::new();
        let s = decode_copy(&cp_raw(1, 1, 1, 1, 1, 4096, 0, 4)).unwrap();
        ledger.note_copy(&s).unwrap();
        assert_eq!(ledger.sync_requests, 1);
        assert_eq!(ledger.copies_known, 0);
        assert_eq!(ledger.copies_known_effective_bytes, 0);
    }

    #[test]
    fn canonical_clamp_and_early_return() {
        let mut ledger = LifecycleLedger::new();
        let c = decode_copy(&cp_raw(2, 7, 1, 1, 1, 4096, 1024, 0)).unwrap();
        assert!(c.clamped);
        ledger.note_copy(&c).unwrap();
        let z = decode_copy(&cp_raw(2, 11, 2, 2, 2, 512, 0, 0)).unwrap();
        assert!(z.early_zero);
        ledger.note_copy(&z).unwrap();
        assert_eq!(ledger.copies_known_effective_bytes, 1024);
    }

    #[test]
    fn reuse_reports_distinct_wire_generations() {
        let mut ledger = LifecycleLedger::new();
        let a = decode_lifecycle(&lc_raw(1, 1, 1, 11, 1, 4096, 41)).unwrap();
        let b = decode_lifecycle(&lc_raw(1, 1, 1, 12, 2, 4096, 42)).unwrap();
        let ga = ledger.note_lifecycle(&a).unwrap();
        let gb = ledger.note_lifecycle(&b).unwrap();
        assert_eq!(ga, "gen-41");
        assert_eq!(gb, "gen-42");
        assert_ne!(ga, gb);
    }

    #[test]
    fn unknown_identities_never_mint() {
        let mut ledger = LifecycleLedger::new();
        let ua = decode_lifecycle(&lc_raw(1, 9, 1, 1, 1, 8, 0)).unwrap();
        assert_eq!(ledger.note_lifecycle(&ua).unwrap(), "");
        let miss = decode_lifecycle(&lc_raw(2, 5, 1, 2, 2, 8, 0)).unwrap();
        assert_eq!(ledger.note_lifecycle(&miss).unwrap(), "");
        assert_eq!(ledger.maps_ok, 1);
        assert_eq!(ledger.maps_unassigned, 1);
        assert_eq!(ledger.unmaps, 1);
        assert_eq!(ledger.unmaps_gen_miss, 1);
        assert!(!ledger.lifetimes_available());
    }

    #[test]
    fn lifetimes_available_on_wire_gen() {
        let mut ledger = LifecycleLedger::new();
        let m = decode_lifecycle(&lc_raw(1, 1, 1, 1, 1, 8, 7)).unwrap();
        let u = decode_lifecycle(&lc_raw(2, 1, 1, 2, 2, 8, 7)).unwrap();
        ledger.note_lifecycle(&m).unwrap();
        ledger.note_lifecycle(&u).unwrap();
        assert!(ledger.lifetimes_available());
        assert!(!ledger.lifetimes_reason().is_empty());
        assert_eq!(ledger.open_estimate(), 0);
        let lone = decode_lifecycle(&lc_raw(2, 5, 1, 3, 3, 8, 0)).unwrap();
        ledger.note_lifecycle(&lone).unwrap();
        assert_eq!(ledger.open_estimate(), 0);
        assert_eq!(ledger.unmaps, 2);
        assert_eq!(ledger.unmaps_gen_miss, 1);
    }

    #[test]
    fn decode_precedence_multi_fault() {
        let mut bad = lc_raw(9, 1, 0, 1, 1, 1, 1);
        bad[0] = 0;
        expect_lc(&bad, "PAY_MAGIC");
        expect_lc(&lc_raw(9, 16, 3, 1, 1, 1, u64::MAX), "PAY_KIND");
        expect_lc(&lc_raw(1, 16, 3, 1, 1, 1, u64::MAX), "PAY_FLAGS");
        expect_lc(&lc_raw(1, 1, 3, 1, 1, 1, u64::MAX), "PAY_DIR");
        expect_cp(&cp_raw(9, 16, 3, 1, 1, 8, 8, 5), "PAY_KIND");
        expect_cp(&cp_raw(2, 16, 3, 1, 1, 8, 8, 5), "PAY_FLAGS");
        expect_cp(&cp_raw(2, 2, 3, 1, 1, 8, 8, 5), "PAY_DIR");
    }

    #[test]
    fn decode_lifecycle_dir_zero_ok() {
        let d = decode_lifecycle(&lc_raw(1, 1, 0, 1, 1, 8, 9)).expect("decodes");
        assert_eq!(d.dir, 0);
        assert!(d.ok);
        assert_eq!(d.generation, 9);
    }

    #[test]
    fn decode_gen_max_boundary() {
        let top = u64::MAX - 1;
        let d = decode_lifecycle(&lc_raw(1, 1, 0, 1, 1, 8, top)).expect("decodes");
        assert_eq!(d.generation, top);
    }

    #[test]
    fn decode_copy_flags_combo() {
        let d = decode_copy(&cp_raw(2, 14, 1, 1, 1, 8, 8, 0)).expect("decodes");
        assert!(d.known);
        assert!(d.clamped);
        assert!(d.early_zero);
    }

    #[test]
    fn decode_copy_offset_past_known_ok() {
        let d = decode_copy(&cp_raw(2, 18, 1, 1, 1, 8, 8, 0)).expect("decodes");
        assert!(d.known);
        assert!(d.offset_past);
        assert!(!d.private_pool);
    }

    #[test]
    fn decode_copy_offset_past_requires_known() {
        expect_cp(&cp_raw(2, 16, 1, 1, 1, 8, 0, 1), "PAY_FLAGS");
    }

    #[test]
    fn decode_copy_offset_past_rejects_early_zero() {
        expect_cp(&cp_raw(2, 26, 1, 1, 1, 8, 0, 0), "PAY_FLAGS");
    }

    #[test]
    fn decode_copy_private_pool_known_ok() {
        let d = decode_copy(&cp_raw(2, 34, 1, 1, 1, 8, 8, 0)).expect("decodes");
        assert!(d.known);
        assert!(d.private_pool);
        assert!(!d.offset_past);
    }

    #[test]
    fn decode_copy_private_pool_on_sync_rejected() {
        expect_cp(&cp_raw(1, 33, 1, 1, 1, 8, 0, 4), "PAY_FLAGS");
    }

    #[test]
    fn decode_copy_private_pool_to_device_ok() {
        let d = decode_copy(&cp_raw(2, 35, 1, 1, 1, 8, 8, 0)).expect("decodes");
        assert!(d.to_device);
        assert!(d.known);
        assert!(d.private_pool);
        assert!(!d.offset_past);
    }

    #[test]
    fn decode_copy_reason_layout_shift_unknown_ok() {
        let lay = decode_copy(&cp_raw(2, 0, 1, 1, 1, 8, 0, 5)).expect("decodes");
        assert!(!lay.known);
        assert_eq!(lay.reason, 5);
        let shift = decode_copy(&cp_raw(2, 0, 1, 2, 1, 8, 0, 6)).expect("decodes");
        assert!(!shift.known);
        assert_eq!(shift.reason, 6);
    }

    #[test]
    fn decode_copy_reason_seven_rejected() {
        expect_cp(&cp_raw(2, 0, 1, 1, 1, 8, 0, 7), "PAY_REASON");
    }

    #[test]
    fn decode_copy_flag_0x40_rejected() {
        expect_cp(&cp_raw(2, 66, 1, 1, 1, 8, 8, 0), "PAY_FLAGS");
    }

    #[test]
    fn unknown_copy_reasons_exclude_bytes() {
        let mut ledger = LifecycleLedger::new();
        for reason in 1..4u16 {
            let d =
                decode_copy(&cp_raw(2, 0, 1, u64::from(reason), 1, 4096, 4096, reason)).unwrap();
            assert!(!d.known);
            ledger.note_copy(&d).unwrap();
        }
        assert_eq!(ledger.copies_unknown, 3);
        assert_eq!(ledger.copies_known, 0);
        assert_eq!(ledger.copies_known_effective_bytes, 0);
    }

    #[test]
    fn empty_ledger() {
        let ledger = LifecycleLedger::new();
        assert_eq!(ledger.maps_ok, 0);
        assert_eq!(ledger.maps_ok_bytes, 0);
        assert_eq!(ledger.maps_failed, 0);
        assert_eq!(ledger.maps_unassigned, 0);
        assert_eq!(ledger.unmaps, 0);
        assert_eq!(ledger.unmaps_bytes, 0);
        assert_eq!(ledger.unmaps_skip_sync, 0);
        assert_eq!(ledger.unmaps_gen_miss, 0);
        assert_eq!(ledger.sync_requests, 0);
        assert_eq!(ledger.copies_known, 0);
        assert_eq!(ledger.copies_known_effective_bytes, 0);
        assert_eq!(ledger.copies_unknown, 0);
        assert_eq!(ledger.open_estimate(), 0);
        assert!(!ledger.lifetimes_available());
        assert!(!ledger.lifetimes_reason().is_empty());
    }

    #[test]
    fn unmap_before_map() {
        let mut ledger = LifecycleLedger::new();
        let u = decode_lifecycle(&lc_raw(2, 5, 1, 1, 1, 8, 0)).unwrap();
        ledger.note_lifecycle(&u).unwrap();
        assert_eq!(ledger.open_estimate(), 0);
        let m = decode_lifecycle(&lc_raw(1, 1, 1, 2, 2, 8, 3)).unwrap();
        ledger.note_lifecycle(&m).unwrap();
        assert_eq!(ledger.maps_ok, 1);
        assert_eq!(ledger.unmaps, 1);
        assert_eq!(ledger.open_estimate(), 0);
        let m2 = decode_lifecycle(&lc_raw(1, 1, 1, 3, 3, 8, 4)).unwrap();
        ledger.note_lifecycle(&m2).unwrap();
        assert_eq!(ledger.open_estimate(), 1);
    }

    #[test]
    fn large_values_stay_exact() {
        let mut ledger = LifecycleLedger::new();
        let big = 9_007_199_254_740_993u64;
        let a = decode_copy(&cp_raw(2, 2, 1, 1, 1, big, big, 0)).unwrap();
        assert_eq!(a.effective, big);
        let b = decode_copy(&cp_raw(2, 2, 1, 2, 2, 1, 1, 0)).unwrap();
        ledger.note_copy(&a).unwrap();
        ledger.note_copy(&b).unwrap();
        assert_eq!(ledger.copies_known_effective_bytes, 9_007_199_254_740_994);
    }

    #[test]
    fn effective_int64_min() {
        let e = effective_bytes(u64::MAX, i64::MIN, 0, true);
        assert_eq!(e.effective, 9_223_372_036_854_775_808);
        assert!(e.clamped);
        assert!(!e.early_zero);
        let e = effective_bytes(u64::MAX, i64::MIN, 100, true);
        assert_eq!(e.effective, 9_223_372_036_854_775_908);
        assert!(e.clamped);
    }

    #[test]
    fn effective_negative_saturation() {
        let e = effective_bytes(u64::MAX, -1, u64::MAX, true);
        assert_eq!(e.effective, 0);
        assert!(e.clamped);
        assert!(!e.early_zero);
        assert!(!e.offset_past);
    }

    #[test]
    fn effective_offset_negative() {
        let e = effective_bytes(100, -16, 64, true);
        assert_eq!(e.effective, 80);
        assert!(e.clamped);
        assert!(!e.early_zero);
        assert!(!e.offset_past);
    }

    #[test]
    fn effective_offset_zero() {
        let e = effective_bytes(100, 0, 64, true);
        assert_eq!(e.effective, 64);
        assert!(e.clamped);
        assert!(!e.early_zero);
        assert!(!e.offset_past);
    }

    #[test]
    fn effective_offset_equals_alloc() {
        let e = effective_bytes(8, 64, 64, true);
        assert_eq!(e.effective, 0);
        assert!(e.clamped);
        assert!(!e.early_zero);
        assert!(!e.offset_past);
    }

    #[test]
    fn effective_offset_past_alloc() {
        let e = effective_bytes(8, 9, 8, true);
        assert_eq!(e.effective, 8);
        assert!(!e.clamped);
        assert!(!e.early_zero);
        assert!(e.offset_past);
    }

    #[test]
    fn effective_size_over_room() {
        let e = effective_bytes(4096, 0, 1024, true);
        assert_eq!(e.effective, 1024);
        assert!(e.clamped);
        assert!(!e.early_zero);
        assert!(!e.offset_past);
    }

    #[test]
    fn tlb_offset_mask() {
        assert_eq!(tlb_offset(0x1200, 0x31FF, 0xFFF), 1);
        assert_eq!(tlb_offset(0x1200, 0x31FF, 0), 0x200);
    }

    #[test]
    fn copy_bytes_overflow_raises() {
        let mut ledger = LifecycleLedger::new();
        let a = decode_copy(&cp_raw(2, 2, 1, 1, 1, u64::MAX, u64::MAX, 0)).unwrap();
        let b = decode_copy(&cp_raw(2, 2, 1, 2, 2, 1, 1, 0)).unwrap();
        ledger.note_copy(&a).unwrap();
        assert!(ledger.note_copy(&b).is_err());
        assert_eq!(ledger.copies_known, 1);
        assert_eq!(ledger.copies_known_effective_bytes, u64::MAX);
    }

    #[test]
    fn map_bytes_overflow_raises() {
        let mut ledger = LifecycleLedger::new();
        let m = decode_lifecycle(&lc_raw(1, 1, 1, 1, 1, u64::MAX, 5)).unwrap();
        ledger.note_lifecycle(&m).unwrap();
        let m2 = decode_lifecycle(&lc_raw(1, 1, 1, 2, 2, 1, 6)).unwrap();
        assert!(ledger.note_lifecycle(&m2).is_err());
        assert_eq!(ledger.maps_ok, 1);
        assert_eq!(ledger.maps_ok_bytes, u64::MAX);
    }

    #[test]
    fn ledger_private_overflow_raises() {
        let mut ledger = LifecycleLedger::new();
        let a = decode_copy(&cp_raw(2, 51, 1, 1, 1, u64::MAX, u64::MAX, 0)).unwrap();
        let b = decode_copy(&cp_raw(2, 35, 1, 2, 2, 1, 1, 0)).unwrap();
        ledger.note_copy(&a).unwrap();
        assert_eq!(ledger.copies_private_effective_bytes, u64::MAX);
        assert_eq!(ledger.copies_offset_past, 1);
        assert!(ledger.note_copy(&b).is_err());
        assert_eq!(ledger.copies_known, 1);
        assert_eq!(ledger.copies_known_effective_bytes, u64::MAX);
        assert_eq!(ledger.copies_private_effective_bytes, u64::MAX);
        assert_eq!(ledger.copies_offset_past, 1);
    }

    #[test]
    fn unmap_bytes_overflow_raises() {
        let mut ledger = LifecycleLedger::new();
        let u = decode_lifecycle(&lc_raw(2, 1, 1, 1, 1, u64::MAX, 5)).unwrap();
        ledger.note_lifecycle(&u).unwrap();
        let u2 = decode_lifecycle(&lc_raw(2, 1, 1, 2, 2, 1, 6)).unwrap();
        assert!(ledger.note_lifecycle(&u2).is_err());
        assert_eq!(ledger.unmaps, 1);
        assert_eq!(ledger.unmaps_bytes, u64::MAX);
    }

    #[test]
    fn copy_unknown_reason_names() {
        assert_eq!(copy_unknown_reason_name(1), "SLOT_READ");
        assert_eq!(copy_unknown_reason_name(2), "MASK_READ");
        assert_eq!(copy_unknown_reason_name(3), "BOUNDS");
        assert_eq!(copy_unknown_reason_name(5), "LAYOUT");
        assert_eq!(copy_unknown_reason_name(6), "SHIFT");
        assert_eq!(copy_unknown_reason_name(9), "REASON_9");
    }

    // Event normalization tests (from test_lifecycle_events).

    #[test]
    fn map_ok_event() {
        let d = decode_lifecycle(&lc_raw(1, 1, 1, 7, 9, 4096, 7)).unwrap();
        let ev = normalize_lifecycle_event(&d);
        assert_eq!(ev.kind, "map_result");
        assert_eq!(ev.ts_ns, 9);
        assert_eq!(ev.source_hook, "fexit:swiotlb_tbl_map_single");
        assert_eq!(ev.source_backend, "tracing");
        assert_eq!(ev.map_result.operation_id, "lc-7");
        assert!(ev.map_result.success);
        assert!(ev.map_result.has_mapping_id);
        assert_eq!(ev.map_result.mapping_id, "gen-7");
        assert!(!ev.map_result.has_return_code);
        assert!(ev.map_result.has_mapped_bytes);
        assert_eq!(ev.map_result.mapped_bytes, 4096);
        assert!(ev.map_result.has_wire_generation);
        assert_eq!(ev.map_result.wire_generation, 7);
        assert!(ev.map_result.has_wire_identity);
        assert_eq!(ev.map_result.wire_identity, "known");
    }

    #[test]
    fn map_failed_event_carries_no_mapping() {
        let d = decode_lifecycle(&lc_raw(1, 0, 1, 11, 12, 4096, 0)).unwrap();
        let ev = normalize_lifecycle_event(&d);
        assert_eq!(ev.kind, "map_result");
        assert_eq!(ev.map_result.operation_id, "lc-11");
        assert!(!ev.map_result.success);
        assert!(!ev.map_result.has_mapping_id);
        assert!(!ev.map_result.has_mapped_bytes);
        assert!(ev.map_result.has_wire_generation);
        assert!(!ev.map_result.has_wire_identity);
    }

    #[test]
    fn unmap_event() {
        let d = decode_lifecycle(&lc_raw(2, 3, 2, 8, 10, 1024, 8)).unwrap();
        let ev = normalize_lifecycle_event(&d);
        assert_eq!(ev.kind, "unmap");
        assert_eq!(ev.ts_ns, 10);
        assert_eq!(ev.source_hook, "fentry:__swiotlb_tbl_unmap_single");
        assert_eq!(ev.source_backend, "tracing");
        assert!(ev.unmap.has_mapping_id);
        assert_eq!(ev.unmap.mapping_id, "gen-8");
        assert!(ev.unmap.has_wire_generation);
        assert_eq!(ev.unmap.wire_generation, 8);
        assert!(ev.unmap.has_wire_identity);
        assert_eq!(ev.unmap.wire_identity, "known");
    }

    #[test]
    fn unassigned_map_event_carries_no_mapping() {
        let d = decode_lifecycle(&lc_raw(1, 9, 1, 13, 14, 4096, 0)).unwrap();
        let ev = normalize_lifecycle_event(&d);
        assert_eq!(ev.kind, "map_result");
        assert!(ev.map_result.success);
        assert!(!ev.map_result.has_mapping_id);
        assert!(ev.map_result.has_mapped_bytes);
        assert!(ev.map_result.has_wire_generation);
        assert!(ev.map_result.has_wire_identity);
        assert_eq!(ev.map_result.wire_identity, "unassigned");
    }

    #[test]
    fn missed_unmap_event_carries_no_mapping() {
        let d = decode_lifecycle(&lc_raw(2, 5, 1, 15, 16, 4096, 0)).unwrap();
        let ev = normalize_lifecycle_event(&d);
        assert_eq!(ev.kind, "unmap");
        assert!(!ev.unmap.has_mapping_id);
        assert!(ev.unmap.has_wire_generation);
        assert!(ev.unmap.has_wire_identity);
        assert_eq!(ev.unmap.wire_identity, "miss");
    }

    #[test]
    fn known_copy_event() {
        let d = decode_copy(&cp_raw(2, 3, 1, 3, 4, 4096, 1024, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.kind, "copy");
        assert_eq!(ev.ts_ns, 4);
        assert_eq!(ev.source_hook, "fentry:swiotlb_bounce");
        assert_eq!(ev.source_backend, "tracing");
        assert_eq!(ev.copy.operation_id, "lc-3");
        assert!(!ev.copy.has_mapping_id);
        assert_eq!(ev.copy.direction, "original_to_bounce");
        assert_eq!(ev.copy.bytes, 1024);
    }

    #[test]
    fn copy_from_device_direction() {
        let d = decode_copy(&cp_raw(2, 2, 2, 25, 26, 2048, 2048, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.copy.direction, "bounce_to_original");
        assert_eq!(ev.copy.bytes, 2048);
    }

    #[test]
    fn clamped_copy_keeps_effective() {
        let d = decode_copy(&cp_raw(2, 7, 1, 21, 22, 4096, 1024, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.copy.bytes, 1024);
    }

    #[test]
    fn early_zero_copy_persists_proved_zero() {
        let d = decode_copy(&cp_raw(2, 11, 2, 23, 24, 512, 0, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.kind, "copy");
        assert_eq!(ev.copy.bytes, 0);
    }

    #[test]
    fn unknown_copy_refuses() {
        let d = decode_copy(&cp_raw(2, 0, 1, 27, 28, 4096, 0, 1)).unwrap();
        let err = normalize_copy_event(&d).expect_err("must reject");
        assert_eq!(err.reason, "UNKNOWN_COPY");
        assert!(!err.fatal);
    }

    #[test]
    fn sync_for_device_event() {
        let d = decode_copy(&cp_raw(1, 1, 2, 5, 6, 512, 0, 4)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.kind, "sync_request");
        assert_eq!(ev.ts_ns, 6);
        assert_eq!(ev.source_hook, "fentry:__swiotlb_sync_single_for_device");
        assert_eq!(ev.source_backend, "tracing");
        assert_eq!(ev.sync.operation_id, "lc-5");
        assert!(ev.sync.has_mapping_id);
        assert_eq!(ev.sync.mapping_id, "lc-5");
        assert!(!ev.sync.has_offset);
        assert_eq!(ev.sync.length, 512);
    }

    #[test]
    fn sync_for_cpu_event() {
        let d = decode_copy(&cp_raw(1, 0, 1, 29, 30, 256, 0, 4)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert_eq!(ev.kind, "sync_request");
        assert_eq!(ev.source_hook, "fentry:__swiotlb_sync_single_for_cpu");
        assert_eq!(ev.sync.length, 256);
    }

    #[test]
    fn reuse_reports_distinct_event_ids() {
        let a = decode_lifecycle(&lc_raw(1, 1, 1, 121, 1, 4096, 41)).unwrap();
        let b = decode_lifecycle(&lc_raw(1, 1, 1, 122, 2, 4096, 42)).unwrap();
        let eva = normalize_lifecycle_event(&a);
        let evb = normalize_lifecycle_event(&b);
        assert_eq!(eva.map_result.mapping_id, "gen-41");
        assert_eq!(evb.map_result.mapping_id, "gen-42");
        assert_ne!(eva.map_result.mapping_id, evb.map_result.mapping_id);
    }

    #[test]
    fn copy_event_offset_past_field() {
        let d = decode_copy(&cp_raw(2, 18, 1, 31, 32, 4096, 4096, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert!(ev.copy.offset_past_allocation);
        assert!(!ev.copy.pool_private);
    }

    #[test]
    fn copy_event_private_field() {
        let d = decode_copy(&cp_raw(2, 35, 1, 49, 50, 2048, 2048, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert!(ev.copy.pool_private);
        assert!(!ev.copy.offset_past_allocation);
    }

    #[test]
    fn copy_event_plain_has_no_markers() {
        let d = decode_copy(&cp_raw(2, 3, 1, 3, 4, 4096, 1024, 0)).unwrap();
        let ev = normalize_copy_event(&d).expect("normalizes");
        assert!(!ev.copy.pool_private);
        assert!(!ev.copy.offset_past_allocation);
    }

    use super::super::read_u32_le;

    fn read_u64_le(blob: &[u8], pos: usize) -> u64 {
        u64::from_le_bytes(blob[pos..pos + 8].try_into().unwrap())
    }

    fn corpus_field<'a>(tail: &[&'a str], key: &str) -> &'a str {
        for tok in tail {
            if let Some(rest) = tok.strip_prefix(key) {
                return rest;
            }
        }
        panic!("missing field {key}");
    }

    fn corpus_bit(tail: &[&str], key: &str) -> bool {
        match corpus_field(tail, key) {
            "0" => false,
            "1" => true,
            other => panic!("bad bit {key}{other}"),
        }
    }

    #[test]
    fn lifecycle_wire_corpus_differential() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lifecycle-wire"
        );
        let blob = std::fs::read(format!("{dir}/corpus.bin")).expect("corpus.bin");
        let text = std::fs::read_to_string(format!("{dir}/corpus.txt")).expect("corpus.txt");
        let lines: Vec<&str> = text
            .lines()
            .filter(|line| !line.starts_with('#') && !line.is_empty())
            .collect();
        let count = read_u32_le(&blob, 0) as usize;
        assert_eq!(count, lines.len(), "bin/txt vector count");
        let mut pos = 4usize;
        let mut seen_lc = 0usize;
        let mut seen_cp = 0usize;
        let mut seen_eff = 0usize;
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
                (1, "lifecycle") => {
                    seen_lc += 1;
                    match decode_lifecycle(inp) {
                        Ok(d) => {
                            assert_eq!(verdict, "OK", "line {idx}");
                            assert_eq!(tail.len(), 8, "line {idx}: field count");
                            assert_eq!(
                                d.kind,
                                corpus_field(&tail, "kind=").parse::<u16>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(d.ok, corpus_bit(&tail, "ok="), "line {idx}");
                            assert_eq!(d.skip_sync, corpus_bit(&tail, "skip="), "line {idx}");
                            assert_eq!(
                                d.dir,
                                corpus_field(&tail, "dir=").parse::<u16>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.seq,
                                corpus_field(&tail, "seq=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.ktime,
                                corpus_field(&tail, "ktime=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.size,
                                corpus_field(&tail, "size=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.generation,
                                corpus_field(&tail, "gen=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                        }
                        Err(err) => assert_eq!(err.reason, verdict, "line {idx}"),
                    }
                }
                (2, "copy") => {
                    seen_cp += 1;
                    match decode_copy(inp) {
                        Ok(d) => {
                            assert_eq!(verdict, "OK", "line {idx}");
                            assert_eq!(tail.len(), 13, "line {idx}: field count");
                            assert_eq!(
                                d.kind,
                                corpus_field(&tail, "kind=").parse::<u16>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(d.to_device, corpus_bit(&tail, "todevice="), "line {idx}");
                            assert_eq!(d.known, corpus_bit(&tail, "known="), "line {idx}");
                            assert_eq!(d.clamped, corpus_bit(&tail, "clamped="), "line {idx}");
                            assert_eq!(d.early_zero, corpus_bit(&tail, "earlyzero="), "line {idx}");
                            assert_eq!(
                                d.offset_past,
                                corpus_bit(&tail, "offsetpast="),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.private_pool,
                                corpus_bit(&tail, "privatepool="),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.dir,
                                corpus_field(&tail, "dir=").parse::<u16>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.reason,
                                corpus_field(&tail, "reason=").parse::<u16>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.seq,
                                corpus_field(&tail, "seq=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.ktime,
                                corpus_field(&tail, "ktime=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.requested,
                                corpus_field(&tail, "requested=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                            assert_eq!(
                                d.effective,
                                corpus_field(&tail, "effective=").parse::<u64>().unwrap(),
                                "line {idx}"
                            );
                        }
                        Err(err) => assert_eq!(err.reason, verdict, "line {idx}"),
                    }
                }
                (3, "effective") => {
                    seen_eff += 1;
                    assert_eq!(rlen, 25, "line {idx}: effective input length");
                    assert_eq!(verdict, "OK", "line {idx}");
                    let size = read_u64_le(inp, 0);
                    let off = read_u64_le(inp, 8) as i64;
                    let alloc = read_u64_le(inp, 16);
                    let valid = inp[24] != 0;
                    let e = effective_bytes(size, off, alloc, valid);
                    assert_eq!(tail.len(), 4, "line {idx}: field count");
                    assert_eq!(
                        e.effective,
                        corpus_field(&tail, "effective=").parse::<u64>().unwrap(),
                        "line {idx}"
                    );
                    assert_eq!(e.clamped, corpus_bit(&tail, "clamped="), "line {idx}");
                    assert_eq!(e.early_zero, corpus_bit(&tail, "earlyzero="), "line {idx}");
                    assert_eq!(
                        e.offset_past,
                        corpus_bit(&tail, "offsetpast="),
                        "line {idx}"
                    );
                }
                _ => panic!("line {idx}: bad kind/tag {kind}/{tag}"),
            }
        }
        assert_eq!(pos, blob.len(), "trailing corpus bytes");
        assert!(seen_lc > 0 && seen_cp > 0 && seen_eff > 0);
    }
}
