//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil conversion-journal BPF object: the set_memory fentry/fexit
//! producer plus its maps, built for bpfel-unknown-none.
//!
//! Hook-for-hook port of the retired C program of the same name (the C
//! sources are the semantic reference only; this Aya program is the
//! shippable object): four fentry/fexit hooks on `set_memory_decrypted`
//! and `set_memory_encrypted` pair bounded task/birth/epoch/depth
//! operations and emit byte-identical MVJR v1 records on `mv_journal`.
//! Control-plane constants below mirror `bpf/include/memveil_journal.h`
//! and `bpf/include/memveil_journal_control.h` from the old tree.
//!
//! Pairing keys (`current_task_pointer`, `start_boottime`, epoch, depth)
//! stay in kernel maps. The birth timestamp reads through the
//! host-resolved `mv_jr_offs` table (aya emits no field relocations,
//! so the tabled offset replaces the old CO-RE read, exactly like the
//! attempt/copy offset tables); the probe refuses pairing when the
//! table is missing or unreasonable. Caller frames resolve against
//! ten transient allowlisted ranges; only the outcome code crosses.
//!
//! Emission bans, machine-checked by the producer reference suite:
//! NO_ADDRESSES (no pointer, address, or offset crosses the ring),
//! NO_FRAMES (stack frames never cross, only the resolved label),
//! NO_TASK_NAMES (task identity stays a transient map key).
//!
//! Verifier shape: the four hooks are thin stubs over BPF subprograms
//! (`#[inline(never)]`). The counting CAS loop, pairing-key build,
//! poisoning sweep, caller classifier, and both pairing paths each
//! verify once under their own complexity budget instead of once per
//! inline copy; the 6.8 verifier otherwise explodes the exit path past
//! its instruction limit. Subprogram boundaries carry scalars and
//! borrowed pointers only — context and map-value pointers down,
//! stack out-pointers and one stack in-pointer across — never
//! multi-word returns, and the birth-offset bound is sequential
//! direct compares so the verifier links the bounded range to the
//! added register. Observable behavior — maps, counters, wire
//! bytes, refusal sets — is unchanged.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

use aya_ebpf::{
    bindings::BPF_NOEXIST,
    helpers::{
        bpf_ktime_get_ns, bpf_probe_read_kernel,
        generated::{bpf_get_current_task_btf, bpf_get_smp_processor_id, bpf_get_stack},
    },
    macros::{fentry, fexit, map},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
    EbpfContext as _,
};
use core::ffi::c_void;

#[path = "../common.rs"]
// Helpers used only by other channels are dead in this bin by design.
#[allow(dead_code)]
mod common;

use crate::common::{count_cas, count_fetch_add, count_or, func_arg_cnt};

/// MVJR wire magic (`MVJR` in ASCII).
const MV_JR_MAGIC: u32 = 0x524A_564D;
/// Fixed MVJR wire record length in bytes.
const MV_JR_LEN: usize = 72;
/// Wire field offsets, matching the carried header field for field.
const MV_JR_OFF_MAGIC: usize = 0;
/// Wire version field offset.
const MV_JR_OFF_VERSION: usize = 4;
/// Wire kind field offset.
const MV_JR_OFF_KIND: usize = 6;
/// Wire flags field offset.
const MV_JR_OFF_FLAGS: usize = 8;
/// Wire direction field offset.
const MV_JR_OFF_DIRECTION: usize = 10;
/// Wire CPU field offset.
const MV_JR_OFF_CPU: usize = 12;
/// Wire sequence field offset.
const MV_JR_OFF_SEQUENCE: usize = 16;
/// Wire exit timestamp field offset.
const MV_JR_OFF_EXIT_NS: usize = 24;
/// Wire epoch field offset.
const MV_JR_OFF_EPOCH: usize = 32;
/// Wire token field offset.
const MV_JR_OFF_TOKEN: usize = 40;
/// Wire entry timestamp field offset.
const MV_JR_OFF_ENTRY_NS: usize = 48;
/// Wire pages field offset.
const MV_JR_OFF_PAGES: usize = 56;
/// Wire native result field offset.
const MV_JR_OFF_RESULT: usize = 60;
/// Wire caller status field offset.
const MV_JR_OFF_CALLER_STATUS: usize = 64;
/// Wire caller class field offset.
const MV_JR_OFF_CALLER_CLASS: usize = 66;
/// Wire caller label field offset.
const MV_JR_OFF_CALLER_LABEL: usize = 68;
/// Wire reserved field offset.
const MV_JR_OFF_RESERVED: usize = 70;
/// Layout check: the 2-byte reserved field ends the record.
const _: () = assert!(MV_JR_OFF_RESERVED + 2 == MV_JR_LEN);

/// Outstanding conversion operations retained across task stacks.
const MV_JR_OPERATION_CAPACITY: u64 = 4096;
/// Tracked nesting depths per task.
const MV_JR_NESTING_CAPACITY: u64 = 8;
/// Transient caller frames resolved per sample.
const MV_JR_CALLER_FRAMES: usize = 16;
/// `bpf_get_stack` skip count: the helper now runs two BPF frames
/// below the fexit program (`mv_exit` -> `mv_callers`), and each
/// BPF-to-BPF call is a real JIT frame the unwinder walks, so skip
/// 2 restores the exact pre-rework window (helper called from the
/// program's own frame with skip 0) and its truncation rule. Must
/// stay equal to the subprogram nesting depth between the hook and
/// the helper call; the low 8 flag bits carry the skip count.
const MV_JR_STACK_SKIP: u64 = 2;
/// Journal ring capacity in bytes.
const MV_JR_RING_BYTES: u32 = 8388608;
/// Highest assignable operation token; the final u64 is exhaustion.
const MV_JR_TOKEN_MAX: u64 = u64::MAX - 1;
/// Expected wrapper argument count, verified live per firing.
const MV_JR_ARGC: i64 = 2;
/// Sanity ceiling for the installed birth-timestamp offset.
const MV_JR_OFFS_MAX: u64 = 65536;

/// Counter indices, in `memveil_journal_control.h` enum order.
const MV_JR_ENTRIES: u32 = 0;
/// Exit observations.
const MV_JR_EXITS: u32 = 1;
/// Matched exits.
const MV_JR_MATCHED: u32 = 2;
/// Unmatched exits.
const MV_JR_UNMATCHED: u32 = 3;
/// Poisoned (censored) operations.
const MV_JR_CENSORED: u32 = 4;
/// Ring reserve failures.
const MV_JR_RING_DROPS: u32 = 5;
/// Operation budget exhaustion.
const MV_JR_OPERATION_EXHAUSTION: u32 = 6;
/// Nesting budget exhaustion.
const MV_JR_NESTING_EXHAUSTION: u32 = 7;
/// Token space exhaustion.
const MV_JR_TOKEN_EXHAUSTION: u32 = 8;
/// Task identity read failures.
const MV_JR_IDENTITY_FAILURE: u32 = 9;
/// Poisoning events.
const MV_JR_POISONED: u32 = 10;
/// Sticky overflow bits.
const MV_JR_OVERFLOW: u32 = 11;
/// Currently retained operations.
const MV_JR_ACTIVE: u32 = 12;
/// Last assigned operation token.
const MV_JR_NEXT_TOKEN: u32 = 13;
/// Emitted records.
const MV_JR_EMITTED: u32 = 14;

/// Pairing key: transient task identity plus epoch and depth.
/// Internal map key only; never enters the wire.
#[repr(C)]
#[derive(Clone, Copy)]
struct JrKey {
    /// Current task pointer (transient).
    task: u64,
    /// Task birth timestamp (transient).
    birth: u64,
    /// Capture admission epoch.
    epoch: u64,
    /// Nesting depth; zero for the task row.
    depth: u32,
    /// Reserved, always zero.
    reserved: u32,
}

/// Per-task pairing state.
#[repr(C)]
#[derive(Clone, Copy)]
struct JrTask {
    /// Current nesting depth.
    depth: u64,
    /// Nonzero once pairing is unavailable.
    poisoned: u64,
}

/// One retained entry-side operation.
#[repr(C)]
#[derive(Clone, Copy)]
struct JrOp {
    /// Assigned operation token.
    token: u64,
    /// Entry monotonic nanoseconds.
    entry_ns: u64,
    /// Signed native requested pages.
    pages: i32,
    /// Direction: 1 decrypt, 2 encrypt.
    direction: u32,
}

/// Admission control block, written by the host with readback.
#[repr(C)]
#[derive(Clone, Copy)]
struct JrControl {
    /// Capture admission epoch; zero disables.
    epoch: u64,
    /// Admission start; entries before it stay unretained.
    start_ns: u64,
    /// Admission end (informational; close is explicit).
    end_ns: u64,
    /// Nonzero while entry admission is open.
    open: u64,
    /// Nonzero while observation runs.
    observe: u64,
    /// Nonzero while caller classification runs.
    callers: u64,
}

/// One transient classifier range: half-open `[start, end)`.
#[repr(C)]
#[derive(Clone, Copy)]
struct JrSymbol {
    /// Range start; zero when unresolved.
    start: u64,
    /// Range end; zero when unresolved.
    end: u64,
    /// Nonzero when overlapping aliases share the start.
    ambiguous: u64,
}

#[map(name = "mv_jr_tasks")]
static MV_JR_TASKS: HashMap<JrKey, JrTask> = HashMap::with_max_entries(4096, 0);

#[map(name = "mv_jr_ops")]
static MV_JR_OPS: HashMap<JrKey, JrOp> = HashMap::with_max_entries(4096, 0);

#[map(name = "mv_jr_control")]
static MV_JR_CONTROL: Array<JrControl> = Array::with_max_entries(1, 0);

#[map(name = "mv_jr_counts")]
static MV_JR_COUNTS: Array<u64> = Array::with_max_entries(15, 0);

#[map(name = "mv_jr_sequence")]
static MV_JR_SEQUENCE: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "mv_jr_symbols")]
static MV_JR_SYMBOLS: Array<JrSymbol> = Array::with_max_entries(10, 0);

#[map(name = "mv_journal")]
static MV_JOURNAL: RingBuf = RingBuf::with_byte_size(MV_JR_RING_BYTES, 0);

/// Host-resolved `task_struct.start_boottime` byte offset, one u64.
#[map(name = "mv_jr_offs")]
static MV_JR_OFFS: Array<u64> = Array::with_max_entries(1, 0);

/// Set the sticky overflow bit for one counter.
#[inline(never)]
fn mv_overflow(index: u32) {
    if let Some(bits) = MV_JR_COUNTS.get_ptr_mut(MV_JR_OVERFLOW) {
        unsafe { count_or(bits, 1u64 << index) };
    }
}

/// Checked saturating increment: 1 with the new value in `out` on
/// success, 0 at the ceiling, on contention, or when the slot is
/// missing. The 16-retry CAS loop is byte-faithful to the retired C
/// original; as a subprogram it verifies once, not once per counter.
#[inline(never)]
fn mv_increment(index: u32, ceiling: u64, out: &mut u64) -> u64 {
    let slot = match MV_JR_COUNTS.get_ptr_mut(index) {
        Some(slot) => slot,
        None => return 0,
    };
    let mut old = unsafe { *slot };
    for _ in 0..16 {
        if old >= ceiling {
            return 0;
        }
        let seen = unsafe { count_cas(slot, old, old + 1) };
        if seen == old {
            *out = old + 1;
            return 1;
        }
        old = seen;
    }
    0
}

/// Unbounded increment with sticky overflow on wrap.
#[inline(never)]
fn mv_count(index: u32) {
    let mut next = 0u64;
    if mv_increment(index, u64::MAX, &mut next) == 0 {
        mv_overflow(index);
    }
}

/// Release one retained operation.
#[inline(never)]
fn mv_release() {
    if let Some(slot) = MV_JR_COUNTS.get_ptr_mut(MV_JR_ACTIVE) {
        unsafe { count_fetch_add(slot, u64::MAX) };
    }
}

/// Build the pairing key for the current task into `out` (1), or
/// refuse pairing (0).
#[inline(never)]
fn mv_key(epoch: u64, out: &mut JrKey) -> u64 {
    let task = unsafe { bpf_get_current_task_btf() };
    if task.is_null() {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let off = match MV_JR_OFFS.get_ptr(0) {
        Some(slot) => unsafe { *slot },
        None => {
            mv_count(MV_JR_IDENTITY_FAILURE);
            return 0;
        }
    };
    // Sequential direct compares: each early return hands the
    // verifier a precise range fact on the fall-through path, so the
    // birth add below carries a bounded offset. (The retired OR-chain
    // lowered to a subtract-and-compare the 6.8 verifier could not
    // link back to the added register.) `off & 7` is exactly
    // `off % 8` for u64; the refusal set is unchanged: zero,
    // misaligned, or at/past the ceiling all refuse.
    if off == 0 {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    if off & 7 != 0 {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    if off >= MV_JR_OFFS_MAX {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let birth =
        unsafe { bpf_probe_read_kernel((task as *const u8).add(off as usize) as *const u64) };
    match birth {
        Ok(birth) => {
            *out = JrKey {
                task: task as u64,
                birth,
                epoch,
                depth: 0,
                reserved: 0,
            };
            1
        }
        Err(_) => {
            mv_count(MV_JR_IDENTITY_FAILURE);
            0
        }
    }
}

/// True while no identity read has failed on this object lifetime.
///
/// A failed identity read may have hidden a nested callback, so
/// pairing stays unavailable for this object lifetime, including
/// previously retained entries.
#[inline(never)]
fn mv_identity_healthy() -> bool {
    match MV_JR_COUNTS.get_ptr(MV_JR_IDENTITY_FAILURE) {
        Some(slot) => unsafe { *slot == 0 },
        None => false,
    }
}

/// Poison one task: pairing stays unavailable and every retained
/// operation for it is released as censored.
///
/// # Safety
///
/// `task` must be a live map-value pointer from `get_ptr_mut`, as
/// returned for `key` with depth zero.
#[inline(never)]
unsafe fn mv_poison(key: &mut JrKey, task: *mut JrTask) {
    unsafe { (*task).poisoned = 1 };
    mv_count(MV_JR_POISONED);
    for depth in 1..=MV_JR_NESTING_CAPACITY {
        key.depth = depth as u32;
        if MV_JR_OPS.get_ptr_mut(&*key).is_some() && MV_JR_OPS.remove(&*key).is_ok() {
            mv_release();
            mv_count(MV_JR_CENSORED);
        }
    }
    key.depth = 0;
}

/// Entry-side pairing: retain one operation under a fresh token.
#[inline(never)]
fn mv_enter(direction: u32, pages: i32) {
    let control = match MV_JR_CONTROL.get_ptr_mut(0) {
        Some(slot) => slot,
        None => return,
    };
    let epoch = unsafe { (*control).epoch };
    let observe = unsafe { (*control).observe };
    if epoch == 0 || observe == 0 {
        return;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    let open = unsafe { (*control).open };
    let start_ns = unsafe { (*control).start_ns };
    let eligible = open != 0 && now >= start_ns;
    if eligible {
        mv_count(MV_JR_ENTRIES);
    }
    let mut key = JrKey {
        task: 0,
        birth: 0,
        epoch: 0,
        depth: 0,
        reserved: 0,
    };
    if mv_key(epoch, &mut key) == 0 {
        return;
    }
    if !mv_identity_healthy() {
        return;
    }
    if MV_JR_TASKS.get_ptr_mut(&key).is_none() {
        let empty = JrTask {
            depth: 0,
            poisoned: 0,
        };
        if MV_JR_TASKS
            .insert(&key, &empty, BPF_NOEXIST as u64)
            .is_err()
        {
            mv_count(MV_JR_OPERATION_EXHAUSTION);
            return;
        }
    }
    let task = match MV_JR_TASKS.get_ptr_mut(&key) {
        Some(task) => task,
        None => {
            mv_count(MV_JR_OPERATION_EXHAUSTION);
            return;
        }
    };
    let seen = unsafe { (*task).depth };
    if seen == u64::MAX {
        unsafe { mv_poison(&mut key, task) };
        mv_overflow(MV_JR_NESTING_EXHAUSTION);
        return;
    }
    unsafe { (*task).depth = seen + 1 };
    if seen + 1 > MV_JR_NESTING_CAPACITY {
        mv_count(MV_JR_NESTING_EXHAUSTION);
        unsafe { mv_poison(&mut key, task) };
        return;
    }
    if unsafe { (*task).poisoned } != 0 || !eligible {
        return;
    }
    let mut active = 0u64;
    if mv_increment(MV_JR_ACTIVE, MV_JR_OPERATION_CAPACITY, &mut active) == 0 {
        mv_count(MV_JR_OPERATION_EXHAUSTION);
        unsafe { mv_poison(&mut key, task) };
        return;
    }
    let mut token = 0u64;
    if mv_increment(MV_JR_NEXT_TOKEN, MV_JR_TOKEN_MAX, &mut token) == 0 {
        mv_release();
        unsafe { (*control).open = 0 };
        mv_count(MV_JR_TOKEN_EXHAUSTION);
        unsafe { mv_poison(&mut key, task) };
        return;
    }
    key.depth = (seen + 1) as u32;
    let op = JrOp {
        token,
        entry_ns: now,
        pages,
        direction,
    };
    if MV_JR_OPS.insert(&key, &op, BPF_NOEXIST as u64).is_err() {
        mv_release();
        mv_count(MV_JR_OPERATION_EXHAUSTION);
        unsafe { mv_poison(&mut key, task) };
    }
}

/// Finite caller label class: 1 owned, 2 swiotlb, 3 direct_dma.
/// Plain comparisons (not range `contains`) so this stays `const`:
/// the class table below evaluates it at compile time, keeping one
/// source of truth for the mapping.
#[inline(never)]
const fn mv_label_class(label: u16) -> u16 {
    if label >= 1 && label <= 2 {
        1
    } else if label >= 3 && label <= 6 {
        2
    } else if label >= 7 && label <= 10 {
        3
    } else {
        0
    }
}

/// Per-symbol class table, indexed by symbol (label = index + 1).
/// Compile-time evaluation of [`mv_label_class`]: the ambiguity
/// scan reads classes from its stack copy instead of calling the
/// subprogram per match (the verifier re-verifies a callee per
/// distinct caller state, and per-match calls multiplied past the
/// instruction limit). The cascade still calls the function for the
/// single winner/first-class verdict.
const JR_CLASS_TABLE: [u16; 10] = [
    mv_label_class(1),
    mv_label_class(2),
    mv_label_class(3),
    mv_label_class(4),
    mv_label_class(5),
    mv_label_class(6),
    mv_label_class(7),
    mv_label_class(8),
    mv_label_class(9),
    mv_label_class(10),
];

/// First-hit verdict over the ten symbols: the winner label
/// (`want_class == 0`) or its class (`want_class != 0`), 0 when no
/// consulted frame falls in any live range. One symbol loop with an
/// inner frame loop that breaks on the first hit; the continue path
/// carries nothing but precise zeros, so the verifier meets ~340
/// states, not the product a carried minimum would fan out to.
///
/// # Safety
///
/// `frames` must point at 16 consecutive frame words (the caller's
/// consulted-frame array) and `size` must be the stack-read byte
/// count that bounds the scan, exactly as `mv_callers` passes them.
#[inline(never)]
unsafe fn mv_cascade(frames: *const u64, size: u64, want_class: u64) -> u16 {
    let mut out = 0u16;
    for index in 0..10u32 {
        let symbol = match MV_JR_SYMBOLS.get_ptr(index) {
            Some(symbol) => symbol,
            None => continue,
        };
        let start = unsafe { (*symbol).start };
        let end = unsafe { (*symbol).end };
        if start == 0 {
            continue;
        }
        let mut hit = false;
        for frame in 0..MV_JR_CALLER_FRAMES {
            if frame as u64 * 8 >= size {
                break;
            }
            let addr = unsafe { *frames.add(frame) };
            if addr >= start && addr < end {
                hit = true;
                break;
            }
        }
        if hit {
            out = if want_class != 0 {
                mv_label_class((index + 1) as u16)
            } else {
                (index + 1) as u16
            };
            break;
        }
    }
    out
}

/// Bounded caller classification: (status, class, label).
#[inline(never)]
fn mv_callers(ctx: *mut c_void) -> (u16, u16, u16) {
    let mut frames = [0u64; MV_JR_CALLER_FRAMES];
    // Skip the two enclosing BPF frames (`mv_exit`, `mv_callers`)
    // so the captured window and the truncation rule below match
    // the pre-rework program exactly (skip 0 from its own frame).
    let size = unsafe {
        bpf_get_stack(
            ctx,
            frames.as_mut_ptr() as *mut c_void,
            (MV_JR_CALLER_FRAMES * 8) as u32,
            MV_JR_STACK_SKIP,
        )
    };
    if size < 0 {
        return (2, 0, 0);
    }
    if size >= (MV_JR_CALLER_FRAMES * 8) as i64 {
        return (4, 0, 0);
    }
    let size = size as u64;
    // Three verifier-small passes over the same match relation (a
    // hit is a consulted frame in a live symbol's half-open range;
    // consulted means frame * 8 < size). Carrying the running
    // minimum label through one match nest fanned the verifier past
    // its instruction limit — every in-flight (label, flag) value
    // is a distinct state at every loop head — so the minimum is
    // found by cascades that carry nothing but precise zeros, and
    // the ambiguity scan carries one flag while the winner stays
    // out of its caller state entirely (recomputed afterwards; the
    // scan is read-only, so the second cascade agrees with the
    // first). The outcome is identical to the retired single nest:
    // the same minimum hit label wins, and the flag is the same
    // condition (a flagged hit, or hits spanning two classes — the
    // retired nest set it on a flagged match or a class change
    // against the running minimum, which holds exactly when the
    // match set spans two classes, regardless of visit order).
    let class = JR_CLASS_TABLE;
    // SAFETY: `frames` is the live 16-word consulted-frame array
    // and `size` is the stack-read byte count bounding the scan.
    let wclass = unsafe { mv_cascade(frames.as_ptr(), size, 1) };
    if wclass == 0 {
        return (2, 0, 0);
    }
    let mut ambiguous = false;
    for frame in 0..MV_JR_CALLER_FRAMES {
        if frame as u64 * 8 >= size {
            break;
        }
        if ambiguous {
            break;
        }
        for index in 0..10u32 {
            let symbol = match MV_JR_SYMBOLS.get_ptr(index) {
                Some(symbol) => symbol,
                None => continue,
            };
            let start = unsafe { (*symbol).start };
            let end = unsafe { (*symbol).end };
            if start == 0 || frames[frame] < start || frames[frame] >= end {
                continue;
            }
            if class[index as usize] != wclass {
                ambiguous = true;
            }
            if unsafe { (*symbol).ambiguous } != 0 {
                ambiguous = true;
            }
            if ambiguous {
                break;
            }
        }
    }
    if ambiguous {
        return (3, 0, 0);
    }
    // SAFETY: same as the first cascade above; the scan between
    // them is read-only, so frames, size, and symbols agree.
    let winner = unsafe { mv_cascade(frames.as_ptr(), size, 0) };
    if winner == 0 {
        // Defensive only: `wclass != 0` above proves a hit exists
        // and nothing between the cascades writes frames, size, or
        // the symbol map, so the second cascade repeats the hit.
        return (2, 0, 0);
    }
    (1, wclass, winner)
}

/// Little-endian field writers over the wire record.
#[inline(always)]
fn put_u16(wire: &mut [u8; MV_JR_LEN], off: usize, value: u16) {
    wire[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

/// Little-endian u32 field writer.
#[inline(always)]
fn put_u32(wire: &mut [u8; MV_JR_LEN], off: usize, value: u32) {
    wire[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Little-endian u64 field writer.
#[inline(always)]
fn put_u64(wire: &mut [u8; MV_JR_LEN], off: usize, value: u64) {
    wire[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

/// Little-endian i32 field writer (signed native values stay signed).
#[inline(always)]
fn put_i32(wire: &mut [u8; MV_JR_LEN], off: usize, value: i32) {
    wire[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

/// Exit-side pairing and emission: match, sequence, classify, submit.
#[inline(never)]
fn mv_exit(ctx: *mut c_void, direction: u32, pages: i32, result: i32) {
    let control = match MV_JR_CONTROL.get_ptr_mut(0) {
        Some(slot) => slot,
        None => return,
    };
    let epoch = unsafe { (*control).epoch };
    let observe = unsafe { (*control).observe };
    if epoch == 0 || observe == 0 {
        return;
    }
    let now = unsafe { bpf_ktime_get_ns() };
    // Classify here, before pairing: the classifier reads only
    // the context and the host-stable symbol map (no writes, no
    // counters), so its triple is identical at any point in this
    // path, and this keeps the caller's state singular at the call
    // (the verifier re-verifies a callee per distinct caller
    // state). The pairing block below fans out on token/entry/key
    // variants; classifying past it would multiply that fan-out
    // into the classifier's own match exploration.
    let callers = unsafe { (*control).callers };
    let (status, cls, label) = if callers != 0 {
        mv_callers(ctx)
    } else {
        (0, 0, 0)
    };
    let mut token = 0u64;
    let mut entry = 0u64;
    mv_count(MV_JR_EXITS);
    let mut key = JrKey {
        task: 0,
        birth: 0,
        epoch: 0,
        depth: 0,
        reserved: 0,
    };
    if mv_key(epoch, &mut key) != 0 {
        if let Some(task) = MV_JR_TASKS.get_ptr_mut(&key) {
            if unsafe { (*task).depth } != 0 {
                if !mv_identity_healthy() {
                    unsafe { mv_poison(&mut key, task) };
                }
                let poisoned = unsafe { (*task).poisoned };
                let depth = unsafe { (*task).depth };
                if poisoned == 0 && depth <= MV_JR_NESTING_CAPACITY {
                    key.depth = depth as u32;
                    if let Some(op) = MV_JR_OPS.get_ptr(&key) {
                        let op_direction = unsafe { (*op).direction };
                        let op_pages = unsafe { (*op).pages };
                        let op_entry = unsafe { (*op).entry_ns };
                        if op_direction == direction && op_pages == pages && op_entry <= now {
                            token = unsafe { (*op).token };
                            entry = op_entry;
                            if MV_JR_OPS.remove(&key).is_ok() {
                                mv_release();
                            } else {
                                token = 0;
                                entry = 0;
                                unsafe { mv_poison(&mut key, task) };
                            }
                        } else {
                            unsafe { mv_poison(&mut key, task) };
                        }
                    }
                }
                key.depth = 0;
                unsafe { (*task).depth -= 1 };
                if unsafe { (*task).depth } == 0 {
                    let _ = MV_JR_TASKS.remove(&key);
                }
            }
        }
    }
    mv_count(if token != 0 {
        MV_JR_MATCHED
    } else {
        MV_JR_UNMATCHED
    });
    let seq_slot = match MV_JR_SEQUENCE.get_ptr_mut(0) {
        Some(slot) => slot,
        None => {
            mv_overflow(MV_JR_EXITS);
            return;
        }
    };
    let sequence = unsafe { *seq_slot };
    if sequence == u64::MAX {
        mv_overflow(MV_JR_EXITS);
        return;
    }
    unsafe { *seq_slot = sequence + 1 };
    let mut payload = [0u8; MV_JR_LEN];
    put_u32(&mut payload, MV_JR_OFF_MAGIC, MV_JR_MAGIC);
    put_u16(&mut payload, MV_JR_OFF_VERSION, 1);
    put_u16(&mut payload, MV_JR_OFF_KIND, 1);
    put_u16(
        &mut payload,
        MV_JR_OFF_FLAGS,
        if token != 0 { 1 } else { 0 },
    );
    put_u16(&mut payload, MV_JR_OFF_DIRECTION, direction as u16);
    put_u32(&mut payload, MV_JR_OFF_CPU, unsafe {
        bpf_get_smp_processor_id()
    });
    put_u64(&mut payload, MV_JR_OFF_SEQUENCE, sequence);
    put_u64(&mut payload, MV_JR_OFF_EXIT_NS, now);
    put_u64(&mut payload, MV_JR_OFF_EPOCH, epoch);
    put_u64(&mut payload, MV_JR_OFF_TOKEN, token);
    put_u64(&mut payload, MV_JR_OFF_ENTRY_NS, entry);
    put_i32(&mut payload, MV_JR_OFF_PAGES, pages);
    put_i32(&mut payload, MV_JR_OFF_RESULT, result);
    put_u16(&mut payload, MV_JR_OFF_CALLER_STATUS, status);
    put_u16(&mut payload, MV_JR_OFF_CALLER_CLASS, cls);
    put_u16(&mut payload, MV_JR_OFF_CALLER_LABEL, label);
    match MV_JOURNAL.reserve_bytes(MV_JR_LEN, 0) {
        Some(mut wire) => {
            wire.copy_from_slice(&payload);
            wire.submit(0);
        }
        None => {
            mv_count(MV_JR_RING_DROPS);
            return;
        }
    }
    mv_count(MV_JR_EMITTED);
}

/// fentry on `set_memory_decrypted`: retain one decrypt operation.
#[fentry(function = "set_memory_decrypted")]
pub fn mv_jr_dec_enter(ctx: FEntryContext) -> i32 {
    if unsafe { func_arg_cnt(ctx.as_ptr()) } != MV_JR_ARGC {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let pages: i32 = ctx.arg(1);
    mv_enter(1, pages);
    0
}

/// fexit on `set_memory_decrypted`: match and emit one decrypt result.
#[fexit(function = "set_memory_decrypted")]
pub fn mv_jr_dec_exit(ctx: FExitContext) -> i32 {
    if unsafe { func_arg_cnt(ctx.as_ptr()) } != MV_JR_ARGC {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let pages: i32 = ctx.arg(1);
    let result: i32 = match ctx.ret() {
        Ok(value) => value,
        Err(_) => {
            mv_count(MV_JR_EXITS);
            mv_count(MV_JR_IDENTITY_FAILURE);
            mv_count(MV_JR_UNMATCHED);
            return 0;
        }
    };
    mv_exit(ctx.as_ptr(), 1, pages, result);
    0
}

/// fentry on `set_memory_encrypted`: retain one encrypt operation.
#[fentry(function = "set_memory_encrypted")]
pub fn mv_jr_enc_enter(ctx: FEntryContext) -> i32 {
    if unsafe { func_arg_cnt(ctx.as_ptr()) } != MV_JR_ARGC {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let pages: i32 = ctx.arg(1);
    mv_enter(2, pages);
    0
}

/// fexit on `set_memory_encrypted`: match and emit one encrypt result.
#[fexit(function = "set_memory_encrypted")]
pub fn mv_jr_enc_exit(ctx: FExitContext) -> i32 {
    if unsafe { func_arg_cnt(ctx.as_ptr()) } != MV_JR_ARGC {
        mv_count(MV_JR_IDENTITY_FAILURE);
        return 0;
    }
    let pages: i32 = ctx.arg(1);
    let result: i32 = match ctx.ret() {
        Ok(value) => value,
        Err(_) => {
            mv_count(MV_JR_EXITS);
            mv_count(MV_JR_IDENTITY_FAILURE);
            mv_count(MV_JR_UNMATCHED);
            return 0;
        }
    };
    mv_exit(ctx.as_ptr(), 2, pages, result);
    0
}

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
static MEMVEIL_CHANNEL: [u8; 24] = *b"memveil-channel:journal\0";

/// Required panic handler for the freestanding binary. Probe code must never
/// panic; a bug that does stalls the invocation instead of emitting garbage.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
