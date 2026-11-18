//! SPDX-License-Identifier: GPL-2.0-only
//! MemVeil SWIOTLB probes, one channel module per wire format. This scaffold
//! carries empty channel modules plus one temporary no-op program so the host
//! build always embeds a parseable object; the channel ports fill the modules
//! and remove the no-op.
#![no_std]
#![no_main]

mod attempt;
mod lifecycle;
mod copy;

use aya_ebpf::{macros::tracepoint, programs::TracePointContext};

// Compile-time proof that the shared wire types link into the BPF object.
const _: u32 = memveil_ebpf_common::MV_MAGIC;

/// BPF license declaration: the kernel gates GPL-only helpers on it.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 4] = *b"GPL\0";

/// Temporary no-op tracepoint; dropped once the channel probes land.
#[tracepoint]
pub fn memveil_noop(_ctx: TracePointContext) -> u32 {
    0
}

/// Required panic handler for the freestanding binary. Probe code must never
/// panic; a bug that does stalls the invocation instead of emitting garbage.
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
