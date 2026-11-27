// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture pipeline: collector state machine over a kernel source.

pub mod collector;
pub mod correlation;
pub mod exposure_census;
pub mod exposure_records;
pub mod journal_callers;
pub mod journal_capture;
pub mod journal_kernel;
pub mod kernel;
pub mod lifecycle;
pub mod live;
pub mod liveness;
pub mod loadcheck;
pub mod normalize;
pub mod pools;
pub mod reader;
pub mod regions;
pub mod run;
pub mod stop;
pub mod tee;
pub mod writer;

/// Test-only little-endian u32 reader shared by the wire
/// corpus differentials (normalize, lifecycle).
#[cfg(test)]
pub(crate) fn read_u32_le(blob: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes(blob[pos..pos + 4].try_into().unwrap())
}
