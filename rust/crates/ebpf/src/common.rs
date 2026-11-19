//! SPDX-License-Identifier: GPL-2.0-only
//! Shared BPF-side counter primitives over `core::intrinsics`.
//!
//! The pinned BPF backend exposes only `target_has_atomic_load_store`, so
//! the `AtomicU64` read-modify-write methods do not exist for this target
//! and every counter op goes through these helpers. Ordering follows the
//! established probe pattern: compare-exchange pairs AcqRel success with
//! Acquire failure, and every op whose result is discarded lowers to the
//! non-fetch BPF ATOMIC form. The one exception is `count_fetch_add`,
//! whose consumed result needs BPF CPU v3 (the host build passes
//! `-C target-cpu=v3`). Each channel bin includes this file as
//! `crate::common` next to its own channel module.
//!
//! Every helper is `unsafe fn`: each dereferences a caller-provided raw
//! pointer (map-value slots from `get_ptr_mut`, or the probe context for
//! [`func_arg_cnt`]), and only the caller can vouch for the pointer. All
//! current call sites pass `get_ptr_mut` results, field projections of
//! them, or `ctx.as_ptr()` — but that audit lives at the call sites, not
//! in these signatures, so the unsafety is marked, not assumed.

use core::ffi::c_void;

/// Fetching atomic add of `v` to the counter at `ptr`; returns the
/// previous value so callers can detect a wrapping increment.
///
/// Every add site needs wrap detection, so every add goes through this
/// helper; there is deliberately no non-fetch add.
///
/// Needs BPF CPU v3 (see the `target-cpu` flag in the host build): the
/// consumed result cannot lower to the non-fetch `BPF_ADD` form.
///
/// # Safety
///
/// `ptr` must be a live, 8-byte-aligned map-value pointer for the whole
/// program run, as returned by `get_ptr_mut`. Concurrent firings on other
/// CPUs are the reason this is atomic rather than a plain read-add-write.
#[inline(always)]
pub unsafe fn count_fetch_add(ptr: *mut u64, v: u64) -> u64 {
    unsafe {
        core::intrinsics::atomic_xadd::<u64, u64, { core::intrinsics::AtomicOrdering::AcqRel }>(
            ptr, v,
        )
    }
}

/// Non-fetch atomic OR of `bits` into the flags word at `ptr`.
///
/// # Safety
///
/// Same contract as [`count_fetch_add`]: a live, aligned map-value pointer.
#[inline(always)]
pub unsafe fn count_or(ptr: *mut u64, bits: u64) {
    // As above, the discarded result selects the non-fetch BPF ATOMIC OR.
    let _ = unsafe {
        core::intrinsics::atomic_or::<u64, u64, { core::intrinsics::AtomicOrdering::AcqRel }>(
            ptr, bits,
        )
    };
}

/// Old-value compare-and-swap: stores `new` at `ptr` when it currently
/// holds `old`, and returns the previous value in either case.
///
/// # Safety
///
/// Same contract as [`count_fetch_add`]: a live, aligned map-value pointer.
#[inline(always)]
pub unsafe fn count_cas(ptr: *mut u64, old: u64, new: u64) -> u64 {
    unsafe {
        core::intrinsics::atomic_cxchg::<
            u64,
            { core::intrinsics::AtomicOrdering::AcqRel },
            { core::intrinsics::AtomicOrdering::Acquire },
        >(ptr, old, new)
        .0
    }
}

/// Live argument count of the traced kernel function for fentry/fexit
/// signature-drift checks. Returns the helper value verbatim; callers
/// compare it against the expected argc and take the unknown-with-reason
/// path on mismatch instead of reading registers.
///
/// # Safety
///
/// `ctx` must be the program's own fentry/fexit context pointer. A wrong
/// pointer fails the probe invocation; it cannot corrupt host memory.
#[inline(always)]
pub unsafe fn func_arg_cnt(ctx: *mut c_void) -> i64 {
    // The generated binding returns `c_long`: 64 bits on every BPF target,
    // so `as i64` is a lossless identity there (and sign-extending, never
    // truncating, on any platform where `c_long` is 32 bits).
    unsafe { aya_ebpf::helpers::generated::bpf_get_func_arg_cnt(ctx) as i64 }
}
