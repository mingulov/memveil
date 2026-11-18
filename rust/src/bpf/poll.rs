// SPDX-License-Identifier: GPL-3.0-or-later
//! Event flow: one decoded frame per channel plus poll accounting.
//!
//! The session drains its ring one item at a time and decodes through the
//! shared wire decoders. Decode failures count as malformed and are
//! skipped: a poisoned record never hides the good ones behind it, and the
//! count stays visible through [`Stats`].

use super::session::{Channel, SessionError};
use aya::maps::RingBuf;
use memveil_ebpf_common::{
    Attempt, Copy, Lifecycle, decode_attempt, decode_copy, decode_lifecycle,
};
use std::convert::TryFrom;

/// One decoded event frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    /// Decoded 98-byte attempt record.
    Attempt(Attempt),
    /// Decoded 44-byte lifecycle record.
    Lifecycle(Lifecycle),
    /// Decoded 48-byte copy record.
    Copy(Copy),
}

/// Host-side poll accounting for one session.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    /// Ring items consumed.
    pub received: u64,
    /// Decoded frames handed out.
    pub delivered: u64,
    /// Staged-but-undecoded items; always zero (decode failures count as
    /// malformed instead of staging).
    pub staged: u64,
    /// Consumed items the wire decoder rejected.
    pub malformed: u64,
    /// Kernel-side drops are invisible to the consumer (they surface as
    /// `submit_fail` in `mv_counts`); always zero here.
    pub dropped: u64,
}

/// Decode one raw ring item for the channel.
pub(crate) fn decode_frame(channel: Channel, bytes: &[u8]) -> Result<Frame, SessionError> {
    match channel {
        Channel::Attempt => decode_attempt(bytes)
            .map(Frame::Attempt)
            .map_err(|error| SessionError::Poll(format!("attempt frame rejected: {error}"))),
        Channel::Lifecycle => decode_lifecycle(bytes)
            .map(Frame::Lifecycle)
            .map_err(|error| SessionError::Poll(format!("lifecycle frame rejected: {error}"))),
        Channel::Copy => decode_copy(bytes)
            .map(Frame::Copy)
            .map_err(|error| SessionError::Poll(format!("copy frame rejected: {error}"))),
    }
}

/// Drain one raw item from the ring map without waiting. The consumer
/// position lives in the shared ring page, so constructing the consumer per
/// call is correct (each call re-reads the published position); it costs a
/// transient mapping pair per poll, which a later task may pin with an
/// owned consumer handle.
pub(crate) fn drain_one(bpf: &aya::Ebpf, ring: &str) -> Result<Option<Vec<u8>>, SessionError> {
    let map = bpf
        .map(ring)
        .ok_or_else(|| SessionError::Poll(format!("ring map `{ring}` missing")))?;
    let mut consumer = RingBuf::try_from(map)
        .map_err(|error| SessionError::Poll(format!("ring open: {error}")))?;
    Ok(consumer.next().map(|item| item.to_vec()))
}
