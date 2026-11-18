// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture pipeline: collector state machine over a kernel source.

pub mod collector;
pub mod correlation;
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
