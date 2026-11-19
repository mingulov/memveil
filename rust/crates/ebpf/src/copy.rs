//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil swiotlb copy probe: fentry on both sync hooks (requests: direction
//! and length, never executed bytes) plus fentry and fexit on swiotlb_bounce
//! (executed copies). Emits 48-byte MVCP v1 records on `mv_copies`.
//!
//! Line-for-line logic port of `bpf/programs/swiotlb_copy.bpf.c`, except the
//! CO-RE mechanism: aya emits no field relocations, so the probe reads every
//! kernel offset from the host-resolved `mv_copy_offs` table map instead of
//! `bpf_core_read` (see [`CopyOffsets`] for the exact layout). Guard behavior
//! is otherwise identical: unknown-with-reason on any effective-byte failure
//! with the request fact still emitted, and the claim/release protocol,
//! deferred/recovered/fallback flags, and loss accounting unchanged.

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{fentry, fexit, map},
    maps::{Array, RingBuf},
    programs::{FEntryContext, FExitContext},
    EbpfContext as _,
};
use core::ffi::c_void;
use memveil_ebpf_common::{
    CopyOffsets, MV_CNT_EMITTED, MV_CNT_EMITTED_BYTES, MV_CNT_FLAGS, MV_CNT_LEN, MV_CNT_OBSERVED,
    MV_CNT_OBSERVED_BYTES, MV_CNT_SUBMIT_FAIL, MV_COPY_OFFS_HAS_PRIVATE, MV_COPY_OFFS_MAGIC,
    MV_COPY_OFFS_VERSION, MV_CP_FLAG_CLAMPED, MV_CP_FLAG_EARLY_ZERO, MV_CP_FLAG_KNOWN,
    MV_CP_FLAG_OFFSET_PAST_ALLOC, MV_CP_FLAG_PRIVATE_POOL, MV_CP_FLAG_TO_DEVICE, MV_CP_KIND_COPY,
    MV_CP_KIND_SYNC, MV_CP_LEN, MV_CP_MAGIC, MV_CP_OFF_DIR, MV_CP_OFF_EFFECTIVE, MV_CP_OFF_FLAGS,
    MV_CP_OFF_KIND, MV_CP_OFF_KTIME, MV_CP_OFF_MAGIC, MV_CP_OFF_REASON, MV_CP_OFF_REQUESTED,
    MV_CP_OFF_SEQ, MV_CP_OFF_VERSION, MV_CP_REASON_BOUNDS, MV_CP_REASON_LAYOUT,
    MV_CP_REASON_MASK_READ, MV_CP_REASON_NONE, MV_CP_REASON_NOT_COPY, MV_CP_REASON_SHIFT,
    MV_CP_REASON_SLOT_READ, MV_CP_VERSION, MV_FLAG_ARGCNT, MV_FLAG_BYTE_COVERAGE,
    MV_FLAG_EMITTED_BYTES_WRAP, MV_FLAG_EMITTED_WRAP, MV_FLAG_OBSERVED_BYTES_WRAP,
    MV_FLAG_OBSERVED_WRAP, MV_FLAG_SUBMIT_WRAP, MV_INVALID_PHYS,
};

/// Expected hook argument counts (verified live, not assumed).
const MV_ARGS_SYNC: i64 = 5;
/// Expected hook argument counts (verified live, not assumed).
const MV_ARGS_BOUNCE: i64 = 5;

/// One pool slot covers 1 << 11 bytes. A literal like the C probe's
/// `MV_IO_TLB_SHIFT_WIRE`: shift drift is caught by the span guard returning
/// `SHIFT`, never by relocating this constant.
const MV_IO_TLB_SHIFT: u32 = 11;

/// 32 MiB holds the measured dd burst (196,608 records, ~11 MiB).
const MV_RING_BYTES: u32 = 33_554_432;

/// Claim table: 4096 slots, 8 linear probes per frame.
const MV_CLAIM_SLOTS: u32 = 4096;
/// Claim table: 4096 slots, 8 linear probes per frame.
const MV_CLAIM_PROBES: u32 = 8;

/// Fallback counters: deferred, recovered, flags, armed.
const MV_CP_FB_DEFERRED: u32 = 0;
/// Fallback counters: deferred, recovered, flags, armed.
const MV_CP_FB_RECOVERED: u32 = 1;
/// Fallback counters: deferred, recovered, flags, armed.
const MV_CP_FB_FLAGS: u32 = 2;
/// Fallback counters: deferred, recovered, flags, armed.
const MV_CP_FB_ARMED: u32 = 3;
/// Fallback counters: deferred, recovered, flags, armed.
const MV_CP_FB_LEN: u32 = 4;
/// Fallback flag bits.
const MV_CP_FB_FLAG_DEFERRED_WRAP: u64 = 1 << 0;
/// Fallback flag bits.
const MV_CP_FB_FLAG_RECOVERED_WRAP: u64 = 1 << 1;
/// Fallback flag bits.
const MV_CP_FB_FLAG_FRAME_LOST: u64 = 1 << 2;

// `CopyOffsets` and the `MV_COPY_OFFS_*` constants live in
// `memveil-ebpf-common`, shared with the host installer so the
// table layout cannot drift between the two sides.

/// One claim-table entry: the owning trampoline frame plus the call id.
#[repr(C)]
struct MvClaim {
    frame: u64,
    id: u64,
}

#[map(name = "mv_counts")]
static MV_COUNTS: Array<u64> = Array::with_max_entries(MV_CNT_LEN as u32, 0);

#[map(name = "mv_claims")]
static MV_CLAIMS: Array<MvClaim> = Array::with_max_entries(MV_CLAIM_SLOTS, 0);

#[map(name = "mv_copy_fb")]
static MV_COPY_FB: Array<u64> = Array::with_max_entries(MV_CP_FB_LEN, 0);

#[map(name = "mv_copies")]
static MV_COPIES: RingBuf = RingBuf::with_byte_size(MV_RING_BYTES, 0);

#[map(name = "mv_copy_offs")]
static MV_COPY_OFFS: Array<CopyOffsets> = Array::with_max_entries(1, 0);

/// Atomically OR one sticky flag bit.
#[inline(always)]
fn raise(bit: u64) {
    if let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_FLAGS as u32) {
        unsafe { crate::common::count_or(slot, bit) };
    }
}

/// Checked submit_fail increment; the wrapped value is never trusted.
#[inline(always)]
fn submit_fail() {
    let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_SUBMIT_FAIL as u32) else {
        return;
    };
    if unsafe { crate::common::count_fetch_add(slot, 1) } == u64::MAX {
        raise(MV_FLAG_SUBMIT_WRAP);
    }
}

/// Sticky fallback flag bit.
#[inline(always)]
fn fb_raise(bit: u64) {
    if let Some(slot) = MV_COPY_FB.get_ptr_mut(MV_CP_FB_FLAGS) {
        unsafe { crate::common::count_or(slot, bit) };
    }
}

/// Deferred count; the wrapped value is never trusted.
#[inline(always)]
fn fb_deferred() {
    let Some(slot) = MV_COPY_FB.get_ptr_mut(MV_CP_FB_DEFERRED) else {
        return;
    };
    if unsafe { crate::common::count_fetch_add(slot, 1) } == u64::MAX {
        fb_raise(MV_CP_FB_FLAG_DEFERRED_WRAP);
    }
}

/// Recovered count; the wrapped value is never trusted.
#[inline(always)]
fn fb_recovered() {
    let Some(slot) = MV_COPY_FB.get_ptr_mut(MV_CP_FB_RECOVERED) else {
        return;
    };
    if unsafe { crate::common::count_fetch_add(slot, 1) } == u64::MAX {
        fb_raise(MV_CP_FB_FLAG_RECOVERED_WRAP);
    }
}

/// Armed only while userspace holds the gate at exactly 1.
#[inline(always)]
fn armed() -> bool {
    MV_COPY_FB
        .get(MV_CP_FB_ARMED)
        .is_some_and(|slot| *slot == 1)
}

/// Read one u64 from a kernel address; `Err` on any fault.
#[inline(always)]
fn kread_u64(addr: u64) -> Result<u64, i32> {
    unsafe { bpf_probe_read_kernel(addr as *const u64) }
}

/// Read one u32 from a kernel address; `Err` on any fault.
#[inline(always)]
fn kread_u32(addr: u64) -> Result<u32, i32> {
    unsafe { bpf_probe_read_kernel(addr as *const u32) }
}

/// Read one byte from a kernel address; `Err` on any fault.
#[inline(always)]
fn kread_u8(addr: u64) -> Result<u8, i32> {
    unsafe { bpf_probe_read_kernel(addr as *const u8) }
}

/// The installed field table when its header is trusted (magic and version).
/// A missing entry or a bad header yields `None`: the direction is then
/// unresolvable and the firing is refused, never guessed.
#[inline(always)]
fn trusted_table() -> Option<CopyOffsets> {
    let tab: CopyOffsets = *MV_COPY_OFFS.get(0)?;
    if tab.magic == MV_COPY_OFFS_MAGIC && tab.version == MV_COPY_OFFS_VERSION {
        Some(tab)
    } else {
        None
    }
}

/// Resolve one kernel direction to the wire encoding (TO 1, FROM 2, BIDI 0)
/// against the table's enumerator values; `None` when the value matches
/// nothing, like the C probe's `mv_wire_dir` returning 0.
#[inline(always)]
fn wire_dir(kdir: i32, to: u32, from: u32, bidi: u32) -> Option<u16> {
    if kdir < 0 {
        return None;
    }
    let k = kdir as u64;
    if k == u64::from(to) {
        Some(1)
    } else if k == u64::from(from) {
        Some(2)
    } else if k == u64::from(bidi) {
        Some(0)
    } else {
        None
    }
}

/// Slot index over one pool: the span must be exactly nslabs slots wide, else
/// SHIFT; the address must land inside, else BOUNDS. Pure and loop-free.
#[inline(always)]
fn slot_index(start: u64, end: u64, nslabs: u64, tlb_addr: u64) -> Result<u64, u16> {
    if end < start {
        return Err(MV_CP_REASON_SHIFT);
    }
    if nslabs > u64::MAX >> MV_IO_TLB_SHIFT {
        return Err(MV_CP_REASON_SHIFT);
    }
    if end - start != nslabs << MV_IO_TLB_SHIFT {
        return Err(MV_CP_REASON_SHIFT);
    }
    if tlb_addr < start {
        return Err(MV_CP_REASON_BOUNDS);
    }
    let idx = (tlb_addr - start) >> MV_IO_TLB_SHIFT;
    if idx >= nslabs {
        return Err(MV_CP_REASON_BOUNDS);
    }
    Ok(idx)
}

/// Hook tlb_offset math: both masked terms fit in s32, so the signed
/// difference is exact.
#[inline(always)]
fn tlb_offset(tlb_addr: u64, orig_addr: u64, min_align_mask: u32) -> i32 {
    ((tlb_addr & 2047) as i32) - (((orig_addr & u64::from(min_align_mask)) & 2047) as i32)
}

/// Replicated swiotlb_bounce length rule.
struct Effective {
    effective: u64,
    clamped: bool,
    early_zero: bool,
    offset_past: bool,
}

/// Replicated swiotlb_bounce length rule: an invalid slot copies nothing
/// (hook early return); otherwise the room is `alloc_size - tlb_offset` in
/// u64 arithmetic, exactly like the hook's size_t math, including wrap past
/// the allocation.
#[inline(always)]
fn effective_bytes(size: u64, tlb_offset: i64, alloc_size: u64, orig_valid: bool) -> Effective {
    if !orig_valid {
        return Effective {
            effective: 0,
            clamped: false,
            early_zero: true,
            offset_past: false,
        };
    }
    let room = alloc_size.wrapping_sub(tlb_offset as u64);
    let (effective, clamped) = if size > room {
        (room, true)
    } else {
        (size, false)
    };
    Effective {
        effective,
        clamped,
        early_zero: false,
        offset_past: tlb_offset > 0 && (tlb_offset as u64) > alloc_size,
    }
}

/// Shared emit path: counts the firing, validates, submits.
#[inline(always)]
fn emit_cp(
    kind: u16,
    base_flags: u16,
    dir: u64,
    requested: u64,
    effective: u64,
    reason: u16,
) -> u32 {
    let Some(observed) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED as u32) else {
        return 0;
    };
    // Step 1: every firing advances observed first.
    let seq = unsafe { crate::common::count_fetch_add(observed, 1) };
    if seq == u64::MAX {
        raise(MV_FLAG_OBSERVED_WRAP);
        submit_fail();
        return 0;
    }
    // Step 2: an invalid epoch is counted, never emitted.
    let Some(flag_slot) = MV_COUNTS.get(MV_CNT_FLAGS as u32) else {
        return 0;
    };
    if *flag_slot != 0 {
        submit_fail();
        return 0;
    }
    // Step 3: dir is the resolved wire encoding; outside 0..2 is rejected,
    // never emitted, and a copy with dir 0 is impossible.
    if dir > 2 || (kind == MV_CP_KIND_COPY && dir == 0) {
        raise(MV_FLAG_BYTE_COVERAGE);
        submit_fail();
        return 0;
    }
    // Step 4: the byte aggregate advances before any fallible step (aggregate
    // independence). Requested bytes keep observed/emitted parallel.
    let Some(observed_bytes) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED_BYTES as u32) else {
        return 0;
    };
    let before = unsafe { crate::common::count_fetch_add(observed_bytes, requested) };
    if before > u64::MAX - requested {
        raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        submit_fail();
        return 0;
    }
    // Step 5: fill the header and submit.
    let ktime = unsafe { bpf_ktime_get_ns() };
    let mut payload = [0u8; MV_CP_LEN];
    payload[MV_CP_OFF_MAGIC..MV_CP_OFF_MAGIC + 4].copy_from_slice(&MV_CP_MAGIC.to_le_bytes());
    payload[MV_CP_OFF_VERSION..MV_CP_OFF_VERSION + 2].copy_from_slice(&MV_CP_VERSION.to_le_bytes());
    payload[MV_CP_OFF_KIND..MV_CP_OFF_KIND + 2].copy_from_slice(&kind.to_le_bytes());
    payload[MV_CP_OFF_FLAGS..MV_CP_OFF_FLAGS + 2].copy_from_slice(&base_flags.to_le_bytes());
    payload[MV_CP_OFF_DIR..MV_CP_OFF_DIR + 2].copy_from_slice(&(dir as u16).to_le_bytes());
    payload[MV_CP_OFF_SEQ..MV_CP_OFF_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    payload[MV_CP_OFF_KTIME..MV_CP_OFF_KTIME + 8].copy_from_slice(&ktime.to_le_bytes());
    payload[MV_CP_OFF_REQUESTED..MV_CP_OFF_REQUESTED + 8].copy_from_slice(&requested.to_le_bytes());
    payload[MV_CP_OFF_EFFECTIVE..MV_CP_OFF_EFFECTIVE + 8].copy_from_slice(&effective.to_le_bytes());
    payload[MV_CP_OFF_REASON..MV_CP_OFF_REASON + 2].copy_from_slice(&reason.to_le_bytes());
    if MV_COPIES.output::<[u8; MV_CP_LEN]>(&payload, 0).is_err() {
        submit_fail();
        return 0;
    }
    // Step 6: once in the ring the event counts as emitted.
    let (Some(emitted), Some(emitted_bytes)) = (
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED as u32),
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED_BYTES as u32),
    ) else {
        return 0;
    };
    if unsafe { crate::common::count_fetch_add(emitted, 1) } == u64::MAX {
        raise(MV_FLAG_EMITTED_WRAP);
    }
    if unsafe { crate::common::count_fetch_add(emitted_bytes, requested) } > u64::MAX - requested {
        raise(MV_FLAG_EMITTED_BYTES_WRAP);
    }
    0
}

/// Effective-byte resolution for one executed copy: table-consistency and
/// read guards identical to the C probe's `mv_emit_bounce` body, returning
/// the unknown reason (`NONE` when known) and filling `flags`/`effective`.
/// Any failure degrades the event to unknown-with-reason; the caller still
/// emits the request fact.
#[inline(always)]
fn bounce_unknown(
    tab: &CopyOffsets,
    dev: u64,
    tlb_addr: u64,
    size: u64,
    pool: u64,
    flags: &mut u16,
    effective: &mut u64,
) -> u16 {
    // Every relocated width must match its local spelling, else the reads
    // below would misinterpret memory. The stride must additionally be
    // nonzero and fit both slot field extents; CO-RE supplied a sane stride
    // implicitly, the table value is checked explicitly.
    if tab.flags & !MV_COPY_OFFS_HAS_PRIVATE != 0
        || tab.reserved0 != 0
        || tab.reserved1 != 0
        || tab.pool_start_size != 8
        || tab.pool_end_size != 8
        || tab.pool_nslabs_size != 8
        || tab.pool_slots_size != 8
        || tab.slot_orig_size != 8
        || tab.slot_alloc_size != 8
        || tab.dev_parms_size != 8
        || tab.mask_size != 4
        || tab.slot_size == 0
        || u64::from(tab.slot_orig_off) + 8 > u64::from(tab.slot_size)
        || u64::from(tab.slot_alloc_off) + 8 > u64::from(tab.slot_size)
    {
        return MV_CP_REASON_LAYOUT;
    }
    let Ok(start) = kread_u64(pool.wrapping_add(u64::from(tab.pool_start_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    let Ok(end) = kread_u64(pool.wrapping_add(u64::from(tab.pool_end_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    let Ok(nslabs) = kread_u64(pool.wrapping_add(u64::from(tab.pool_nslabs_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    let Ok(slots) = kread_u64(pool.wrapping_add(u64::from(tab.pool_slots_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    if slots == 0 || nslabs == 0 {
        return MV_CP_REASON_SLOT_READ;
    }
    let idx = match slot_index(start, end, nslabs, tlb_addr) {
        Ok(idx) => idx,
        Err(reason) => return reason,
    };
    // The stride is tabled, never a literal.
    let slot_addr = slots.wrapping_add(idx.wrapping_mul(u64::from(tab.slot_size)));
    let Ok(orig_addr) = kread_u64(slot_addr.wrapping_add(u64::from(tab.slot_orig_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    let Ok(alloc_size) = kread_u64(slot_addr.wrapping_add(u64::from(tab.slot_alloc_off))) else {
        return MV_CP_REASON_SLOT_READ;
    };
    let Ok(parms) = kread_u64(dev.wrapping_add(u64::from(tab.dev_parms_off))) else {
        return MV_CP_REASON_MASK_READ;
    };
    let mut mask: u32 = 0;
    if parms != 0 {
        let Ok(m) = kread_u32(parms.wrapping_add(u64::from(tab.mask_off))) else {
            return MV_CP_REASON_MASK_READ;
        };
        mask = m;
    }
    let off = tlb_offset(tlb_addr, orig_addr, mask);
    let eff = effective_bytes(
        size,
        i64::from(off),
        alloc_size,
        orig_addr != MV_INVALID_PHYS,
    );
    *flags |= MV_CP_FLAG_KNOWN
        | if eff.clamped { MV_CP_FLAG_CLAMPED } else { 0 }
        | if eff.early_zero {
            MV_CP_FLAG_EARLY_ZERO
        } else {
            0
        }
        | if eff.offset_past {
            MV_CP_FLAG_OFFSET_PAST_ALLOC
        } else {
            0
        };
    *effective = eff.effective;
    // Privacy is a marker, never a verdict: the toggle reads false on a
    // private pool, and anything unprovable leaves the flag clear.
    if tab.flags & MV_COPY_OFFS_HAS_PRIVATE != 0 && tab.mem_size == 8 && tab.cc_size == 1 {
        if let Ok(mem) = kread_u64(dev.wrapping_add(u64::from(tab.mem_off))) {
            if mem != 0 {
                if let Ok(shared) = kread_u8(mem.wrapping_add(u64::from(tab.cc_off))) {
                    if shared == 0 {
                        *flags |= MV_CP_FLAG_PRIVATE_POOL;
                    }
                }
            }
        }
    }
    MV_CP_REASON_NONE
}

/// Records one executed copy (shared by the fentry and fexit paths).
#[inline(always)]
fn emit_bounce(dev: u64, tlb_addr: u64, size: u64, kdir: i32, pool: u64) -> u32 {
    let mut wdir: u16 = 3;
    let mut flags: u16 = 0;
    let mut reason: u16 = MV_CP_REASON_NONE;
    let mut effective: u64 = 0;

    // The kernel direction resolves to the wire encoding; an unmapped value
    // rides the malformed path below.
    if let Some(tab) = trusted_table() {
        if let Some(w) = wire_dir(kdir, tab.dir_to, tab.dir_from, tab.dir_bidi) {
            wdir = w;
        }
        if wdir == 1 {
            flags |= MV_CP_FLAG_TO_DEVICE;
        }
        reason = bounce_unknown(&tab, dev, tlb_addr, size, pool, &mut flags, &mut effective);
    }
    emit_cp(
        MV_CP_KIND_COPY,
        flags,
        u64::from(wdir),
        size,
        effective,
        reason,
    )
}

/// Counts a firing whose copy neither path can record.
#[inline(always)]
fn lost() {
    let Some(observed) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED as u32) else {
        return;
    };
    if unsafe { crate::common::count_fetch_add(observed, 1) } == u64::MAX {
        raise(MV_FLAG_OBSERVED_WRAP);
    }
    submit_fail();
}

/// Trampoline frame address as a scalar (the verifier forbids hashing ctx):
/// the context pointer spills to the stack and is read back as raw bytes.
#[inline(always)]
fn trampoline_frame(ctx: *mut c_void) -> u64 {
    let ptr = ctx;
    unsafe { bpf_probe_read_kernel(&raw const ptr as *const u64).unwrap_or(0) }
}

/// Call id: arguments distinguish successive calls in one frame. A plain XOR
/// collides systematically (addresses and sizes share structure); the
/// splitmix64 finalizer avalanches all three inputs so only birthday
/// collisions remain.
#[inline(always)]
fn call_id(tlb_addr: u64, size: u64, kdir: i32) -> u64 {
    let dir = kdir as u64;
    let mut x = tlb_addr
        .wrapping_add(size.wrapping_mul(0x9E37_79B9_7F4A_7C15))
        .wrapping_add(dir.wrapping_mul(0xBF58_476D_1CE4_E5B9))
        .wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[inline(always)]
fn claim_index(frame: u64, i: u32) -> u32 {
    (((frame >> 4) as u32) ^ ((frame >> 16) as u32)).wrapping_add(i)
}

/// Claims frame's slot for id; false when every probed slot is busy.
#[inline(always)]
fn claim(frame: u64, id: u64) -> bool {
    // A slot holding this frame is stale: live frames are unique.
    for i in 0..MV_CLAIM_PROBES {
        let k = claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        let Some(slot) = MV_CLAIMS.get_ptr_mut(k) else {
            return false;
        };
        if unsafe { (*slot).frame } == frame {
            unsafe {
                (*slot).id = id;
            }
            return true;
        }
    }
    for i in 0..MV_CLAIM_PROBES {
        let k = claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        let Some(slot) = MV_CLAIMS.get_ptr_mut(k) else {
            return false;
        };
        if unsafe { (*slot).frame } == 0
            && unsafe { crate::common::count_cas(&raw mut (*slot).frame, 0, frame) } == 0
        {
            unsafe {
                (*slot).id = id;
            }
            return true;
        }
    }
    false
}

/// Releases frame's slot; true when it held id (mv_bounce recorded this call).
#[inline(always)]
fn release(frame: u64, id: u64) -> bool {
    for i in 0..MV_CLAIM_PROBES {
        let k = claim_index(frame, i) & (MV_CLAIM_SLOTS - 1);
        // Unreadable table: never record twice.
        let Some(slot) = MV_CLAIMS.get_ptr_mut(k) else {
            return true;
        };
        if unsafe { (*slot).frame } == frame {
            let mine = unsafe { (*slot).id } == id;
            unsafe {
                (*slot).frame = 0;
            }
            return mine;
        }
    }
    false
}

#[fentry(function = "__swiotlb_sync_single_for_device")]
pub fn mv_sync_device(ctx: FEntryContext) -> u32 {
    if unsafe { crate::common::func_arg_cnt(ctx.as_ptr()) } != MV_ARGS_SYNC {
        raise(MV_FLAG_ARGCNT);
        return 0;
    }
    let size: u64 = ctx.arg(2);
    let kdir: i32 = ctx.arg(3);
    // A sync request is not a copy: KNOWN stays clear and the reason says so
    // explicitly. An unresolvable direction rides the malformed path below.
    let wdir = trusted_table()
        .and_then(|tab| wire_dir(kdir, tab.dir_to, tab.dir_from, tab.dir_bidi))
        .unwrap_or(3);
    emit_cp(
        MV_CP_KIND_SYNC,
        MV_CP_FLAG_TO_DEVICE,
        u64::from(wdir),
        size,
        0,
        MV_CP_REASON_NOT_COPY,
    )
}

#[fentry(function = "__swiotlb_sync_single_for_cpu")]
pub fn mv_sync_cpu(ctx: FEntryContext) -> u32 {
    if unsafe { crate::common::func_arg_cnt(ctx.as_ptr()) } != MV_ARGS_SYNC {
        raise(MV_FLAG_ARGCNT);
        return 0;
    }
    let size: u64 = ctx.arg(2);
    let kdir: i32 = ctx.arg(3);
    let wdir = trusted_table()
        .and_then(|tab| wire_dir(kdir, tab.dir_to, tab.dir_from, tab.dir_bidi))
        .unwrap_or(3);
    emit_cp(
        MV_CP_KIND_SYNC,
        0,
        u64::from(wdir),
        size,
        0,
        MV_CP_REASON_NOT_COPY,
    )
}

#[fentry(function = "swiotlb_bounce")]
pub fn mv_bounce(ctx: FEntryContext) -> u32 {
    if unsafe { crate::common::func_arg_cnt(ctx.as_ptr()) } != MV_ARGS_BOUNCE {
        raise(MV_FLAG_ARGCNT);
        return 0;
    }
    let frame = trampoline_frame(ctx.as_ptr());
    // No frame: count the loss; a live exit may still record it unmatched.
    if frame == 0 {
        fb_raise(MV_CP_FB_FLAG_FRAME_LOST);
        lost();
        return 0;
    }
    let dev: u64 = ctx.arg(0);
    let tlb_addr: u64 = ctx.arg(1);
    let size: u64 = ctx.arg(2);
    let kdir: i32 = ctx.arg(3);
    let pool: u64 = ctx.arg(4);
    // Table full: count the deferral for mv_bounce_exit.
    if !claim(frame, call_id(tlb_addr, size, kdir)) {
        fb_deferred();
        return 0;
    }
    emit_bounce(dev, tlb_addr, size, kdir, pool)
}

/// Records the copy when mv_bounce skipped this call or found no free slot.
#[fexit(function = "swiotlb_bounce")]
pub fn mv_bounce_exit(ctx: FExitContext) -> u32 {
    if unsafe { crate::common::func_arg_cnt(ctx.as_ptr()) } != MV_ARGS_BOUNCE {
        raise(MV_FLAG_ARGCNT);
        return 0;
    }
    // Disarmed exit stays out: its recoveries would match no entry miss.
    if !armed() {
        return 0;
    }
    let frame = trampoline_frame(ctx.as_ptr());
    // No frame: mv_bounce counted the loss, so never record twice.
    if frame == 0 {
        return 0;
    }
    let dev: u64 = ctx.arg(0);
    let tlb_addr: u64 = ctx.arg(1);
    let size: u64 = ctx.arg(2);
    let kdir: i32 = ctx.arg(3);
    let pool: u64 = ctx.arg(4);
    if release(frame, call_id(tlb_addr, size, kdir)) {
        return 0;
    }
    fb_recovered();
    emit_bounce(dev, tlb_addr, size, kdir, pool)
}
