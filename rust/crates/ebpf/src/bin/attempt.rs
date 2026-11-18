//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil attempt-channel BPF object: the `swiotlb_bounced` tracepoint
//! program plus its maps, built for bpfel-unknown-none and embedded by the
//! host build as `DEP_MEMVEIL_EBPF_ATTEMPT_PATH`.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[path = "../attempt.rs"]
mod attempt;
#[path = "../common.rs"]
mod common;

// The shared wire const must resolve with the expected type; dependency or
// type drift fails the build here. Name/type agreement only — const-eval
// links no code from the dependency into this BPF object.
const _: u32 = memveil_ebpf_common::MV_MAGIC;

/// BPF license declaration: the kernel gates GPL-only helpers on it.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

/// Required panic handler for the freestanding binary. Probe code must never
/// panic; a bug that does stalls the invocation instead of emitting garbage.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
