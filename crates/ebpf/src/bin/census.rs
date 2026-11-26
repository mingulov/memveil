//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil census BPF object: guest-view mapping-boundary counting.
//!
//! A raw tracepoint on `sys_enter` filters the x86-64 mmap/munmap
//! syscall ids and emits one fixed 32-byte MVCN v1 record per
//! crossing on `mv_census_events`, with `mv_census_counts`
//! carrying the observed/emitted/submit_fail/flags aggregates.
//! Records carry counts only — a sequence number, a timestamp,
//! and the syscall class — never addresses, sizes, payloads, or
//! anything outside the guest-view count contract. Other
//! syscalls are out of scope: they return without advancing
//! any counter, so they are neither counted nor lost.
//!
//! Privilege, symbol, semantic, and bound refusal lives with
//! the collector that attaches this object, not in the probe:
//! the probe counts only once attached. Built for
//! bpfel-unknown-none; the host build embeds it once the
//! controller wires the fourth channel.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{map, raw_tracepoint},
    maps::{Array, RingBuf},
    programs::RawTracePointContext,
};

#[path = "../common.rs"]
// Helpers used only by other channels are dead in this bin by design.
#[allow(dead_code)]
mod common;

// The shared wire const must resolve with the expected type; dependency or
// type drift fails the build here. Name/type agreement only — const-eval
// links no code from the dependency into this BPF object.
const _: u32 = memveil_ebpf_common::MV_MAGIC;

/// BPF license declaration: the kernel gates GPL-only helpers on it.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

/// Channel identity marker: self-describing bytes that travel with the
/// object so packaging and load checks can prove which channel's bytes
/// they stage (`memveil-channel:<name>` plus NUL). The packaging scripts
/// read this section and refuse on mismatch or absence; the name must stay
/// identical to the channel filename stem.
#[link_section = "memveil_channel"]
#[no_mangle]
static MEMVEIL_CHANNEL: [u8; 23] = *b"memveil-channel:census\0";

/// Required panic handler for the freestanding binary. Probe code must never
/// panic; a bug that does stalls the invocation instead of emitting garbage.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// x86-64 syscall id for mmap (counted class 1).
const SYS_MMAP: i64 = 9;
/// x86-64 syscall id for munmap (counted class 2).
const SYS_MUNMAP: i64 = 11;

/// MVCN record kind for an mmap boundary crossing.
const MV_CN_KIND_MMAP: u16 = 1;
/// MVCN record kind for a munmap boundary crossing.
const MV_CN_KIND_MUNMAP: u16 = 2;

/// MVCN v1 record: magic, version, kind, flags, reason, seq, ktime.
const MV_CN_MAGIC: u32 = 0x4E43_564D;
const MV_CN_VERSION: u16 = 1;
const MV_CN_LEN: usize = 32;
const MV_CN_OFF_MAGIC: usize = 0;
const MV_CN_OFF_VERSION: usize = 4;
const MV_CN_OFF_KIND: usize = 6;
const MV_CN_OFF_FLAGS: usize = 8;
const MV_CN_OFF_REASON: usize = 10;
const MV_CN_OFF_SEQ: usize = 12;
const MV_CN_OFF_KTIME: usize = 20;
const MV_CN_OFF_RESERVED: usize = 28;

/// `mv_census_counts` index: crossings admitted for counting.
const MV_CN_CNT_OBSERVED: u32 = 0;
/// `mv_census_counts` index: records submitted to the ring.
const MV_CN_CNT_EMITTED: u32 = 1;
/// `mv_census_counts` index: submissions refused or failed.
const MV_CN_CNT_SUBMIT_FAIL: u32 = 2;
/// `mv_census_counts` index: sticky wrap flags.
const MV_CN_CNT_FLAGS: u32 = 3;
/// `mv_census_counts` entry count.
const MV_CN_CNT_LEN: u32 = 4;

/// Sticky bit: the observed counter wrapped.
const MV_CN_FLAG_OBSERVED_WRAP: u64 = 1 << 0;
/// Sticky bit: the emitted counter wrapped.
const MV_CN_FLAG_EMITTED_WRAP: u64 = 1 << 1;
/// Sticky bit: the submit_fail counter wrapped.
const MV_CN_FLAG_SUBMIT_WRAP: u64 = 1 << 2;

/// 1 MiB holds 32,768 census records; the collector drains
/// faster than the mapping-boundary rate by construction.
const MV_CN_RING_BYTES: u32 = 1_048_576;

#[map(name = "mv_census_counts")]
static MV_CENSUS_COUNTS: Array<u64> = Array::with_max_entries(MV_CN_CNT_LEN, 0);

#[map(name = "mv_census_events")]
static MV_CENSUS_EVENTS: RingBuf = RingBuf::with_byte_size(MV_CN_RING_BYTES, 0);

/// Atomically OR one sticky flag bit.
#[inline(always)]
fn raise(bit: u64) {
    if let Some(slot) = MV_CENSUS_COUNTS.get_ptr_mut(MV_CN_CNT_FLAGS) {
        unsafe { crate::common::count_or(slot, bit) };
    }
}

/// Checked submit_fail increment; the wrapped value is never trusted.
#[inline(always)]
fn submit_fail() {
    let Some(slot) = MV_CENSUS_COUNTS.get_ptr_mut(MV_CN_CNT_SUBMIT_FAIL) else {
        return;
    };
    if unsafe { crate::common::count_fetch_add(slot, 1) } == u64::MAX {
        raise(MV_CN_FLAG_SUBMIT_WRAP);
    }
}

/// Count one mapping-boundary crossing: advance observed for
/// the sequence number, fill the record, submit it. A wrapped
/// observed counter or a failed submit counts submit_fail and
/// emits nothing, so the ring never carries a reused sequence.
#[inline(always)]
fn emit_cn(kind: u16) -> i32 {
    let Some(observed) = MV_CENSUS_COUNTS.get_ptr_mut(MV_CN_CNT_OBSERVED) else {
        return 0;
    };
    let seq = unsafe { crate::common::count_fetch_add(observed, 1) };
    if seq == u64::MAX {
        raise(MV_CN_FLAG_OBSERVED_WRAP);
        submit_fail();
        return 0;
    }
    let ktime = unsafe { bpf_ktime_get_ns() };
    let mut payload = [0u8; MV_CN_LEN];
    payload[MV_CN_OFF_MAGIC..MV_CN_OFF_MAGIC + 4].copy_from_slice(&MV_CN_MAGIC.to_le_bytes());
    payload[MV_CN_OFF_VERSION..MV_CN_OFF_VERSION + 2].copy_from_slice(&MV_CN_VERSION.to_le_bytes());
    payload[MV_CN_OFF_KIND..MV_CN_OFF_KIND + 2].copy_from_slice(&kind.to_le_bytes());
    // v1 carries no flags or reasons and no reserved payload: the
    // explicit zero writes pin the layout offsets at compile time.
    payload[MV_CN_OFF_FLAGS..MV_CN_OFF_FLAGS + 2].copy_from_slice(&0u16.to_le_bytes());
    payload[MV_CN_OFF_REASON..MV_CN_OFF_REASON + 2].copy_from_slice(&0u16.to_le_bytes());
    payload[MV_CN_OFF_RESERVED..MV_CN_OFF_RESERVED + 4].copy_from_slice(&0u32.to_le_bytes());
    payload[MV_CN_OFF_SEQ..MV_CN_OFF_SEQ + 8].copy_from_slice(&seq.to_le_bytes());
    payload[MV_CN_OFF_KTIME..MV_CN_OFF_KTIME + 8].copy_from_slice(&ktime.to_le_bytes());
    if MV_CENSUS_EVENTS
        .output::<[u8; MV_CN_LEN]>(&payload, 0)
        .is_err()
    {
        submit_fail();
        return 0;
    }
    let Some(emitted) = MV_CENSUS_COUNTS.get_ptr_mut(MV_CN_CNT_EMITTED) else {
        return 0;
    };
    if unsafe { crate::common::count_fetch_add(emitted, 1) } == u64::MAX {
        raise(MV_CN_FLAG_EMITTED_WRAP);
    }
    0
}

/// Raw tracepoint on `sys_enter`: count mmap/munmap boundary
/// crossings, ignore every other syscall without counting it.
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn census_sys_enter(ctx: RawTracePointContext) -> i32 {
    match ctx.arg::<i64>(1) {
        SYS_MMAP => emit_cn(MV_CN_KIND_MMAP),
        SYS_MUNMAP => emit_cn(MV_CN_KIND_MUNMAP),
        _ => 0,
    }
}
