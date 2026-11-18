// SPDX-License-Identifier: GPL-2.0-only
//! SWIOTLB lifecycle-channel probes.
//!
//! `mv_map_result` (fexit on `swiotlb_tbl_map_single`) reports whether the
//! inner allocator found slots, with the requested size and direction;
//! `mv_unmap` (fentry on `__swiotlb_tbl_unmap_single`) reports size,
//! direction, and the skip-sync bit. Both emit 44-byte MVLC v2 records on
//! `mv_lifecycle`; all accounting lives in `mv_counts` under the same
//! conservation rule as the attempt channel (observed == emitted +
//! submit_fail while no wrap bit is set).
//!
//! Mapping identity is `(device, tlb address) -> opaque generation` in
//! `mv_gen_table`; only the generation crosses the ring. 0 is never assigned
//! (unknown); tombstones (value 0) read as misses. No addresses are read or
//! emitted.
//!
//! Atomic counter access goes through `crate::common`; see that module for
//! the backend constraints (in particular the BPF CPU v3 requirement behind
//! the consumed fetch-add).

use aya_ebpf::{
    bindings::{BPF_EXIST, BPF_NOEXIST},
    helpers::bpf_ktime_get_ns,
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, RingBuf},
    programs::{FEntryContext, FExitContext},
    EbpfContext as _,
};
use memveil_ebpf_common::{
    MV_CNT_EMITTED, MV_CNT_EMITTED_BYTES, MV_CNT_FLAGS, MV_CNT_LEN, MV_CNT_OBSERVED,
    MV_CNT_OBSERVED_BYTES, MV_CNT_SUBMIT_FAIL, MV_FLAG_ARGCNT, MV_FLAG_BYTE_COVERAGE,
    MV_FLAG_EMITTED_BYTES_WRAP, MV_FLAG_EMITTED_WRAP, MV_FLAG_OBSERVED_BYTES_WRAP,
    MV_FLAG_OBSERVED_WRAP, MV_FLAG_SUBMIT_WRAP, MV_INVALID_PHYS, MV_LC_FLAG_GEN_MISS,
    MV_LC_FLAG_GEN_UNASSIGNED, MV_LC_FLAG_OK, MV_LC_FLAG_SKIP_SYNC, MV_LC_GEN_MAX, MV_LC_KIND_MAP,
    MV_LC_KIND_UNMAP, MV_LC_LEN, MV_LC_MAGIC, MV_LC_OFF_DIR, MV_LC_OFF_FLAGS, MV_LC_OFF_GEN,
    MV_LC_OFF_KIND, MV_LC_OFF_KTIME, MV_LC_OFF_MAGIC, MV_LC_OFF_SEQ, MV_LC_OFF_SIZE,
    MV_LC_OFF_VERSION, MV_LC_VERSION,
};

use crate::common::{count_cas, count_fetch_add, count_or, func_arg_cnt};

/// Expected `swiotlb_tbl_map_single` argument count (verified live, not assumed).
const MV_ARGS_MAP_SINGLE: i64 = 6;
/// Expected `__swiotlb_tbl_unmap_single` argument count (verified live, not assumed).
const MV_ARGS_UNMAP: i64 = 6;
/// `DMA_ATTR_SKIP_CPU_SYNC` is bit 5 (`dma-mapping.h`).
const MV_DMA_ATTR_SKIP_CPU_SYNC: u64 = 1 << 5;
/// Lifecycle ring capacity in bytes (32 MiB holds the measured `dd` burst).
const MV_RING_BYTES: u32 = 33_554_432;
/// Compare-and-swap retries for one generation allocation.
const MV_CAS_RETRIES: u32 = 8;

/// Stable `enum dma_data_direction` encodings (`dma-direction.h` values 0/1/2,
/// unchanged across kernels; aya offers no CO-RE enum relocation, so the
/// argc guard above is the live signature-drift check for these hooks).
const DMA_BIDIRECTIONAL: i32 = 0;
/// Stable `enum dma_data_direction` encoding for device-bound transfers.
const DMA_TO_DEVICE: i32 = 1;
/// Stable `enum dma_data_direction` encoding for CPU-bound transfers.
const DMA_FROM_DEVICE: i32 = 2;

#[map(name = "mv_counts")]
static MV_COUNTS: Array<u64> = Array::with_max_entries(MV_CNT_LEN as u32, 0);

#[map(name = "mv_lifecycle")]
static MV_LIFECYCLE: RingBuf = RingBuf::with_byte_size(MV_RING_BYTES, 0);

/// Mapping identity key: device pointer plus mapped TLB address. The key
/// stays in the kernel; only the generation crosses the ring.
#[repr(C)]
#[derive(Clone, Copy)]
struct GenKey {
    dev: u64,
    tlb: u64,
}

#[map(name = "mv_gen_table")]
static MV_GEN_TABLE: HashMap<GenKey, u64> = HashMap::with_max_entries(32768, 0);

#[map(name = "mv_gen_next")]
static MV_GEN_NEXT: Array<u64> = Array::with_max_entries(1, 0);

/// Resolve one kernel direction to the wire encoding (TO 1, FROM 2, BIDI 0);
/// `None` when the value matches nothing (including negatives).
#[inline(always)]
fn wire_dir(kdir: i32) -> Option<u16> {
    if kdir < 0 {
        return None;
    }
    match kdir {
        DMA_TO_DEVICE => Some(1),
        DMA_FROM_DEVICE => Some(2),
        DMA_BIDIRECTIONAL => Some(0),
        _ => None,
    }
}

/// Atomically OR one sticky flag bit.
#[inline(always)]
fn mv_raise(bit: u64) {
    if let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_FLAGS as u32) {
        count_or(slot, bit);
    }
}

/// Checked submit_fail increment; the wrapped value is never trusted.
#[inline(always)]
fn mv_submit_fail() {
    let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_SUBMIT_FAIL as u32) else {
        return;
    };
    if count_fetch_add(slot, 1) == u64::MAX {
        mv_raise(MV_FLAG_SUBMIT_WRAP);
    }
}

/// Shared emit path: counts the firing, validates, submits; `true` once the
/// record is in the ring, `false` when it was not emitted.
#[inline(always)]
#[allow(clippy::too_many_lines)]
fn mv_emit_lc(kind: u16, flags: u16, dir: u64, size: u64, gen: u64) -> bool {
    let Some(observed) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED as u32) else {
        return false;
    };
    // Step 1: every firing advances observed first.
    let seq = count_fetch_add(observed, 1);
    if seq == u64::MAX {
        mv_raise(MV_FLAG_OBSERVED_WRAP);
        mv_submit_fail();
        return false;
    }
    // Step 2: an invalid epoch is counted, never emitted.
    let Some(flag_slot) = MV_COUNTS.get_ptr(MV_CNT_FLAGS as u32) else {
        return false;
    };
    if unsafe { *flag_slot } != 0 {
        mv_submit_fail();
        return false;
    }
    // Step 3: dir is the resolved wire encoding; outside 0..2 is rejected, never emitted.
    if dir > 2 {
        mv_raise(MV_FLAG_BYTE_COVERAGE);
        mv_submit_fail();
        return false;
    }
    // Step 4: the byte aggregate advances before any fallible step (aggregate independence).
    let Some(observed_bytes) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED_BYTES as u32) else {
        return false;
    };
    let before = count_fetch_add(observed_bytes, size);
    if before > u64::MAX - size {
        mv_raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        mv_submit_fail();
        return false;
    }
    // Step 5: fill the header and submit. One ktime read: per-byte reads could tear.
    let ktime = unsafe { bpf_ktime_get_ns() };
    let mut payload = [0u8; MV_LC_LEN];
    payload[MV_LC_OFF_MAGIC..MV_LC_OFF_MAGIC + 4].copy_from_slice(&MV_LC_MAGIC.to_le_bytes());
    payload[MV_LC_OFF_VERSION..MV_LC_OFF_VERSION + 2].copy_from_slice(&MV_LC_VERSION.to_le_bytes());
    payload[MV_LC_OFF_KIND..MV_LC_OFF_KIND + 2].copy_from_slice(&kind.to_le_bytes());
    payload[MV_LC_OFF_FLAGS..MV_LC_OFF_FLAGS + 2].copy_from_slice(&flags.to_le_bytes());
    payload[MV_LC_OFF_DIR..MV_LC_OFF_DIR + 2].copy_from_slice(&(dir as u16).to_le_bytes());
    payload[MV_LC_OFF_SEQ..MV_LC_OFF_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    payload[MV_LC_OFF_KTIME..MV_LC_OFF_KTIME + 8].copy_from_slice(&ktime.to_le_bytes());
    payload[MV_LC_OFF_SIZE..MV_LC_OFF_SIZE + 8].copy_from_slice(&size.to_le_bytes());
    payload[MV_LC_OFF_GEN..MV_LC_OFF_GEN + 8].copy_from_slice(&gen.to_le_bytes());
    if MV_LIFECYCLE.output::<[u8; MV_LC_LEN]>(&payload, 0).is_err() {
        mv_submit_fail();
        return false;
    }
    // Step 6: once in the ring the event counts as emitted.
    let (Some(emitted), Some(emitted_bytes)) = (
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED as u32),
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED_BYTES as u32),
    ) else {
        return true;
    };
    if count_fetch_add(emitted, 1) == u64::MAX {
        mv_raise(MV_FLAG_EMITTED_WRAP);
    }
    if count_fetch_add(emitted_bytes, size) > u64::MAX - size {
        mv_raise(MV_FLAG_EMITTED_BYTES_WRAP);
    }
    true
}

/// Exist-only claim with tombstone reclaim: `true` with the key holding `gen`.
/// A live entry means a concurrent owner, so the caller diverts honest; on
/// EEXIST a zero tombstone is ours to take back with an exist-only update
/// (reclaim keeps failed deletes from stranding keys). A key deleted between
/// the calls retries once; anything else diverts.
#[inline(always)]
fn mv_claim_gen(key: &GenKey, gen: u64) -> bool {
    for _ in 0..2 {
        if MV_GEN_TABLE.insert(key, &gen, BPF_NOEXIST as u64).is_ok() {
            return true;
        }
        let Some(slot) = MV_GEN_TABLE.get_ptr_mut(key) else {
            continue;
        };
        if unsafe { *slot } != 0 {
            return false;
        }
        if MV_GEN_TABLE.insert(key, &gen, BPF_EXIST as u64).is_ok() {
            return true;
        }
    }
    false
}

/// Allocate one generation without wrapping: `Some(gen)` with the value set,
/// or `None` to divert (terminal, contention, or missing counter). The
/// counter never advances past `MV_LC_GEN_MAX`, so no value is ever assigned
/// twice.
#[inline(always)]
fn mv_alloc_gen() -> Option<u64> {
    let counter = MV_GEN_NEXT.get_ptr_mut(0)?;
    let mut current = unsafe { *counter };
    for _ in 0..MV_CAS_RETRIES {
        if current >= MV_LC_GEN_MAX {
            return None;
        }
        let previous = count_cas(counter, current, current + 1);
        if previous == current {
            return Some(current + 1);
        }
        current = previous;
    }
    None
}

/// fexit on `swiotlb_tbl_map_single`: slots found or not, with the requested
/// size and direction. An ok record means the inner allocator found slots;
/// the outer `dma_map_*` call may still fail afterwards (outer-failure
/// cleanup then runs a real unmap, observed as its own event).
#[fexit(function = "swiotlb_tbl_map_single")]
pub fn mv_map_result(ctx: FExitContext) -> i32 {
    try_mv_map_result(&ctx);
    0
}

fn try_mv_map_result(ctx: &FExitContext) {
    if func_arg_cnt(ctx.as_ptr()) != MV_ARGS_MAP_SINGLE {
        mv_raise(MV_FLAG_ARGCNT);
        return;
    }
    let ret: u64 = match ctx.ret() {
        Ok(value) => value,
        Err(_) => {
            mv_raise(MV_FLAG_ARGCNT);
            return;
        }
    };
    let dev: u64 = ctx.arg(0);
    let mapping_size: u64 = ctx.arg(2);
    let dir: i32 = ctx.arg(4);
    let mut wdir: u16 = 3;
    if let Some(resolved) = wire_dir(dir) {
        wdir = resolved;
    }
    if ret == MV_INVALID_PHYS {
        mv_emit_lc(MV_LC_KIND_MAP, 0, u64::from(wdir), mapping_size, 0);
        return;
    }
    let key = GenKey { dev, tlb: ret };
    // Divert without claiming when allocation or insert fails.
    let (gen, flags) = match mv_alloc_gen() {
        Some(assigned) if mv_claim_gen(&key, assigned) => (assigned, MV_LC_FLAG_OK),
        _ => (0, MV_LC_FLAG_OK | MV_LC_FLAG_GEN_UNASSIGNED),
    };
    // A lost map record cleans only its own generation: a key another owner
    // holds is none of this record's business, and a tombstone left by a
    // failed delete stays reclaimable.
    if !mv_emit_lc(MV_LC_KIND_MAP, flags, u64::from(wdir), mapping_size, gen) && gen != 0 {
        if let Some(slot) = MV_GEN_TABLE.get_ptr_mut(&key) {
            if count_cas(slot, gen, 0) == gen {
                let _ = MV_GEN_TABLE.remove(&key);
            }
        }
    }
}

/// fentry on `__swiotlb_tbl_unmap_single`: size, direction, and the skip-sync
/// bit, with the generation taken back out of `mv_gen_table`.
#[fentry(function = "__swiotlb_tbl_unmap_single")]
pub fn mv_unmap(ctx: FEntryContext) -> i32 {
    try_mv_unmap(&ctx);
    0
}

fn try_mv_unmap(ctx: &FEntryContext) {
    if func_arg_cnt(ctx.as_ptr()) != MV_ARGS_UNMAP {
        mv_raise(MV_FLAG_ARGCNT);
        return;
    }
    let dev: u64 = ctx.arg(0);
    let tlb_addr: u64 = ctx.arg(1);
    let mapping_size: u64 = ctx.arg(2);
    let dir: i32 = ctx.arg(3);
    let attrs: u64 = ctx.arg(4);
    let mut flags = MV_LC_FLAG_OK;
    if attrs & MV_DMA_ATTR_SKIP_CPU_SYNC != 0 {
        flags |= MV_LC_FLAG_SKIP_SYNC;
    }
    let mut wdir: u16 = 3;
    if let Some(resolved) = wire_dir(dir) {
        wdir = resolved;
    }
    let key = GenKey { dev, tlb: tlb_addr };
    let mut gen = 0;
    if let Some(slot) = MV_GEN_TABLE.get_ptr_mut(&key) {
        let current = unsafe { *slot };
        if current != 0 {
            gen = current;
            if count_cas(slot, gen, 0) != gen {
                // Lost to a concurrent owner: miss without escalation, the key stays live-owned.
                gen = 0;
                flags |= MV_LC_FLAG_GEN_MISS;
            } else {
                // Owned: a failed delete leaves a functional tombstone the next map reclaims.
                let _ = MV_GEN_TABLE.remove(&key);
            }
        } else {
            flags |= MV_LC_FLAG_GEN_MISS;
        }
    } else {
        flags |= MV_LC_FLAG_GEN_MISS;
    }
    mv_emit_lc(MV_LC_KIND_UNMAP, flags, u64::from(wdir), mapping_size, gen);
}
