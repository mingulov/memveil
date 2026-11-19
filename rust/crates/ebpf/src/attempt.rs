//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil swiotlb attempt probe.
//!
//! Tracepoint program on `swiotlb:swiotlb_bounced`. Extracts (size, force,
//! device name) from the trace context, packs the 98-byte product payload,
//! and submits it on the `mv_attempts` ring. All accounting lives in
//! `mv_counts`; every firing is counted exactly once across observed /
//! emitted / submit_fail (counter conservation: observed == emitted +
//! submit_fail while no wrap bit is set; byte coverage needs the flags word
//! fully clear).
//!
//! Field positions come from the single-entry `mv_offsets` table userspace
//! installs between load and attach, so kernels whose format drifted stay
//! collectable. A missing, zero, or inconsistent table fails closed: counted
//! reject, never a misread.
//!
//! Behavior source: `bpf/programs/swiotlb_attempt.bpf.c` — this module ports
//! its logic step for step, including the exact counter order, wrap checks,
//! and refusal paths. Counter updates go through the shared
//! [`crate::common`] helpers: the BPF backend has no `AtomicU64`
//! read-modify-write methods, so fetching adds (wrap detection) and the
//! non-fetch flag OR lower to BPF ATOMIC insns via intrinsics instead.

use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel_buf},
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
    EbpfContext as _,
};
use memveil_ebpf_common::{
    decode_offsets_table, OffsetsTable, MV_CNT_EMITTED, MV_CNT_EMITTED_BYTES, MV_CNT_FLAGS,
    MV_CNT_LEN, MV_CNT_OBSERVED, MV_CNT_OBSERVED_BYTES, MV_CNT_SUBMIT_FAIL, MV_CTX_READ_CAP,
    MV_FLAG_BYTE_COVERAGE, MV_FLAG_EMITTED_BYTES_WRAP, MV_FLAG_EMITTED_WRAP, MV_FLAG_FORCE,
    MV_FLAG_OBSERVED_BYTES_WRAP, MV_FLAG_OBSERVED_WRAP, MV_FLAG_SUBMIT_WRAP, MV_MAGIC, MV_NAME_MAX,
    MV_OFF_FLAGS, MV_OFF_KTIME, MV_OFF_MAGIC, MV_OFF_NAME, MV_OFF_NAME_LEN, MV_OFF_SEQ,
    MV_OFF_SIZE, MV_OFF_VERSION, MV_PAYLOAD_LEN, MV_VERSION,
};

use crate::common::{count_fetch_add, count_or};

/// Attempt ring capacity in bytes (8 MiB, the production `MV_RING_BYTES`).
const MV_RING_BYTES: u32 = 8_388_608;

#[map(name = "mv_counts")]
static MV_COUNTS: Array<u64> = Array::with_max_entries(MV_CNT_LEN as u32, 0);

#[map(name = "mv_attempts")]
static MV_ATTEMPTS: RingBuf = RingBuf::with_byte_size(MV_RING_BYTES, 0);

#[map(name = "mv_offsets")]
static MV_OFFSETS: Array<OffsetsTable> = Array::with_max_entries(1, 0);

/// Atomically OR one sticky flag bit.
#[inline(always)]
fn mv_raise(bit: u64) {
    let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_FLAGS as u32) else {
        return;
    };
    unsafe { count_or(slot, bit) };
}

/// Checked submit_fail increment; the wrapped value is never trusted.
#[inline(always)]
fn mv_submit_fail() {
    let Some(slot) = MV_COUNTS.get_ptr_mut(MV_CNT_SUBMIT_FAIL as u32) else {
        return;
    };
    let old = unsafe { count_fetch_add(slot, 1) };
    if old == u64::MAX {
        mv_raise(MV_FLAG_SUBMIT_WRAP);
    }
}

/// Validate a `__data_loc` pair against a dynamic-data floor, the name cap,
/// the read cap, and the available context length. Check order is part of the
/// contract: length faults precede extent faults. Ports `mv_validate_loc_floor`.
#[inline(always)]
fn mv_loc_ok(off: u32, dlen: u32, ctx_len: u32, floor: u32) -> bool {
    if dlen == 0 {
        return false;
    }
    if dlen > MV_NAME_MAX as u32 + 1 {
        return false;
    }
    if off < floor {
        return false;
    }
    if off + dlen > MV_CTX_READ_CAP as u32 {
        return false;
    }
    if off + dlen > ctx_len {
        return false;
    }
    true
}

#[tracepoint(name = "swiotlb_bounced", category = "swiotlb")]
pub fn mv_swiotlb_attempt(ctx: TracePointContext) -> u32 {
    // Step 1: every firing advances observed first.
    let Some(observed) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED as u32) else {
        return 0;
    };
    let seq = unsafe { count_fetch_add(observed, 1) };
    if seq == u64::MAX {
        mv_raise(MV_FLAG_OBSERVED_WRAP);
        mv_submit_fail();
        return 0;
    }
    // Step 2: an invalid epoch is counted, never emitted.
    let Some(flags) = MV_COUNTS.get_ptr_mut(MV_CNT_FLAGS as u32) else {
        return 0;
    };
    if unsafe { *flags } != 0 {
        mv_submit_fail();
        return 0;
    }
    // Step 2b: load and validate the offset table. A missing, zero, or
    // inconsistent table fails closed: the firing counts as rejected, never
    // misread. Size is unread without a table, so the byte aggregate loses
    // coverage (sticky bit) on top of the counted reject. The shared decoder
    // is the same validation userspace applies, so the two cannot drift.
    let tab = match MV_OFFSETS.get_ptr_mut(0) {
        Some(tab) => tab,
        None => {
            mv_raise(MV_FLAG_BYTE_COVERAGE);
            mv_submit_fail();
            return 0;
        }
    };
    let tab_bytes = unsafe { core::slice::from_raw_parts(tab.cast::<u8>(), OffsetsTable::LEN) };
    let offsets = match decode_offsets_table(tab_bytes) {
        Ok(offsets) => offsets,
        Err(_) => {
            mv_raise(MV_FLAG_BYTE_COVERAGE);
            mv_submit_fail();
            return 0;
        }
    };
    // Step 2c: read the size slot. A short context fails here: the firing's
    // size is unknowable, so the byte aggregate loses coverage (sticky bit)
    // on top of the counted reject.
    let size = match unsafe { ctx.read_at::<u64>(offsets.size_off as usize) } {
        Ok(size) => size,
        Err(_) => {
            mv_raise(MV_FLAG_BYTE_COVERAGE);
            mv_submit_fail();
            return 0;
        }
    };
    // Step 3: the byte aggregate advances before any fallible step (aggregate
    // independence).
    let Some(observed_bytes) = MV_COUNTS.get_ptr_mut(MV_CNT_OBSERVED_BYTES as u32) else {
        return 0;
    };
    let before = unsafe { count_fetch_add(observed_bytes, size) };
    if before > u64::MAX - size {
        mv_raise(MV_FLAG_OBSERVED_BYTES_WRAP);
        mv_submit_fail();
        return 0;
    }
    // Step 4: read and validate the __data_loc pair. The kernel record length
    // is unknown here, so the read cap is the extent oracle and probe_read
    // failure covers actual shortness; both reject identically.
    let loc = match unsafe { ctx.read_at::<u32>(offsets.loc_off as usize) } {
        Ok(loc) => loc,
        Err(_) => {
            mv_submit_fail();
            return 0;
        }
    };
    let off = loc & 0xFFFF;
    let dlen = (loc >> 16) & 0xFFFF;
    if !mv_loc_ok(off, dlen, MV_CTX_READ_CAP as u32, offsets.fixed_end) {
        mv_submit_fail();
        return 0;
    }
    // Step 5: read the name straight into the payload name field, then check
    // NUL placement. dlen is in 1..64 here, so the read and the write stay in
    // bounds. Re-check on the read's own value: the compiler folds the cap
    // into loc math older verifiers cannot link to dlen.
    let mut payload = [0u8; MV_PAYLOAD_LEN];
    let dlen = core::hint::black_box(dlen);
    if dlen > MV_NAME_MAX as u32 + 1 {
        mv_submit_fail();
        return 0;
    }
    let name_dst = unsafe {
        core::slice::from_raw_parts_mut(payload.as_mut_ptr().add(MV_OFF_NAME), dlen as usize)
    };
    let name_src = unsafe { (ctx.as_ptr() as *const u8).add(off as usize) };
    if unsafe { bpf_probe_read_kernel_buf(name_src, name_dst) }.is_err() {
        mv_submit_fail();
        return 0;
    }
    for i in 0..dlen {
        let byte = unsafe { *payload.as_ptr().add(MV_OFF_NAME + i as usize) };
        if i + 1 == dlen {
            if byte != 0 {
                mv_submit_fail();
                return 0;
            }
        } else if byte == 0 {
            mv_submit_fail();
            return 0;
        }
    }
    // Step 5b: read the force byte at its tabled offset.
    let force = match unsafe { ctx.read_at::<u8>(offsets.force_off as usize) } {
        Ok(force) => force,
        Err(_) => {
            mv_submit_fail();
            return 0;
        }
    };
    if force != 0 && force != 1 {
        mv_submit_fail();
        return 0;
    }
    // Step 6: fill the header and submit. One ktime read: per-byte reads could
    // tear.
    payload[MV_OFF_MAGIC..MV_OFF_MAGIC + 4].copy_from_slice(&MV_MAGIC.to_le_bytes());
    payload[MV_OFF_VERSION..MV_OFF_VERSION + 2].copy_from_slice(&MV_VERSION.to_le_bytes());
    let out_flags: u16 = if force == 1 { MV_FLAG_FORCE } else { 0 };
    payload[MV_OFF_FLAGS..MV_OFF_FLAGS + 2].copy_from_slice(&out_flags.to_le_bytes());
    let ktime = unsafe { bpf_ktime_get_ns() };
    payload[MV_OFF_SEQ..MV_OFF_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    payload[MV_OFF_KTIME..MV_OFF_KTIME + 8].copy_from_slice(&ktime.to_le_bytes());
    payload[MV_OFF_SIZE..MV_OFF_SIZE + 8].copy_from_slice(&size.to_le_bytes());
    payload[MV_OFF_NAME_LEN..MV_OFF_NAME_LEN + 2].copy_from_slice(&(dlen as u16 - 1).to_le_bytes());
    if MV_ATTEMPTS
        .output::<[u8; MV_PAYLOAD_LEN]>(&payload, 0)
        .is_err()
    {
        mv_submit_fail();
        return 0;
    }
    // Step 7: once in the ring the event counts as emitted; a wrap here still
    // counts the event and invalidates only the epoch.
    let (Some(emitted), Some(emitted_bytes)) = (
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED as u32),
        MV_COUNTS.get_ptr_mut(MV_CNT_EMITTED_BYTES as u32),
    ) else {
        return 0;
    };
    if unsafe { count_fetch_add(emitted, 1) } == u64::MAX {
        mv_raise(MV_FLAG_EMITTED_WRAP);
    }
    if unsafe { count_fetch_add(emitted_bytes, size) } > u64::MAX - size {
        mv_raise(MV_FLAG_EMITTED_BYTES_WRAP);
    }
    0
}
