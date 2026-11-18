// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture pipeline: collector state machine over a kernel source.

pub mod correlation;
pub mod lifecycle;
pub mod live;
pub mod liveness;
pub mod normalize;
pub mod reader;
pub mod tee;
pub mod writer;
