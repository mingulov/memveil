//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil copy-channel BPF object: the sync/bounce fentry/fexit programs
//! plus their maps, built for bpfel-unknown-none and embedded by the host
//! build as `DEP_MEMVEIL_EBPF_COPY_PATH`.
#![no_std]
#![no_main]
#![feature(core_intrinsics)]
#![allow(internal_features)]

#[path = "../copy.rs"]
mod copy;
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
static MEMVEIL_CHANNEL: [u8; 21] = *b"memveil-channel:copy\0";

/// Required panic handler for the freestanding binary. Probe code must never
/// panic; a bug that does stalls the invocation instead of emitting garbage.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
