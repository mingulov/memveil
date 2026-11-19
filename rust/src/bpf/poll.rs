// SPDX-License-Identifier: GPL-3.0-or-later
//! Event flow: one decoded frame per channel plus poll accounting.
//!
//! The session drains its ring one item at a time and decodes through the
//! shared wire decoders. Decode failures count as malformed and are
//! skipped: a poisoned record never hides the good ones behind it, and the
//! count stays visible through [`Stats`].

use super::session::{Channel, SessionError};
use aya::maps::{Map, MapData, RingBuf};
use memveil_ebpf_common::{
    Attempt, Copy, Lifecycle, decode_attempt, decode_copy, decode_lifecycle,
};
use std::convert::TryFrom;
use std::os::fd::AsFd;

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

/// Open one owned ring consumer over a duplicated map fd. The session
/// pins the consumer at load and polls through it for life: building a
/// consumer per poll remaps the ring every record (mmap pair per item),
/// which stalls the collector under flood while the Mojo bridge's pinned
/// consumer keeps up. The source map stays in the loader (geometry gates
/// keep reading it there); only this consumer reads the ring.
pub(crate) fn open_consumer(map: &Map, ring: &str) -> Result<RingBuf<MapData>, SessionError> {
    let data = match map {
        Map::RingBuf(data) => data,
        _ => {
            return Err(SessionError::Load(format!(
                "ring map `{ring}` is not a ring buffer"
            )));
        }
    };
    let dup =
        data.fd().as_fd().try_clone_to_owned().map_err(|error| {
            SessionError::Load(format!("ring map `{ring}` fd dup failed: {error}"))
        })?;
    let owned = MapData::from_fd(dup)
        .map_err(|error| SessionError::Load(format!("ring map `{ring}` reopen failed: {error}")))?;
    RingBuf::try_from(Map::RingBuf(owned))
        .map_err(|error| SessionError::Load(format!("ring map `{ring}` open failed: {error}")))
}

#[cfg(test)]
mod tests {
    use super::{Frame, Stats, decode_frame};
    use crate::bpf::session::{Channel, Session};
    use memveil_ebpf_common::{
        MV_CP_FLAG_KNOWN, MV_CP_FLAG_TO_DEVICE, MV_CP_KIND_COPY, MV_CP_LEN, MV_CP_MAGIC,
        MV_CP_OFF_DIR, MV_CP_OFF_EFFECTIVE, MV_CP_OFF_FLAGS, MV_CP_OFF_KIND, MV_CP_OFF_KTIME,
        MV_CP_OFF_MAGIC, MV_CP_OFF_REASON, MV_CP_OFF_REQUESTED, MV_CP_OFF_SEQ, MV_CP_OFF_VERSION,
        MV_CP_REASON_NONE, MV_CP_VERSION, MV_FLAG_FORCE, MV_LC_FLAG_OK, MV_LC_KIND_MAP, MV_LC_LEN,
        MV_LC_MAGIC, MV_LC_OFF_DIR, MV_LC_OFF_FLAGS, MV_LC_OFF_GEN, MV_LC_OFF_KIND,
        MV_LC_OFF_KTIME, MV_LC_OFF_MAGIC, MV_LC_OFF_SEQ, MV_LC_OFF_SIZE, MV_LC_OFF_VERSION,
        MV_LC_VERSION, MV_MAGIC, MV_OFF_FLAGS, MV_OFF_KTIME, MV_OFF_MAGIC, MV_OFF_NAME,
        MV_OFF_NAME_LEN, MV_OFF_SEQ, MV_OFF_SIZE, MV_OFF_VERSION, MV_PAYLOAD_LEN, MV_VERSION,
    };

    fn put_u16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u32(buf: &mut [u8], at: usize, value: u32) {
        buf[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], at: usize, value: u64) {
        buf[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Minimal valid 98-byte attempt record: forced bounce of 4096 bytes on
    /// device "vd0", seq 7.
    fn valid_attempt() -> [u8; MV_PAYLOAD_LEN] {
        let mut buf = [0u8; MV_PAYLOAD_LEN];
        put_u32(&mut buf, MV_OFF_MAGIC, MV_MAGIC);
        put_u16(&mut buf, MV_OFF_VERSION, MV_VERSION);
        put_u16(&mut buf, MV_OFF_FLAGS, MV_FLAG_FORCE);
        put_u64(&mut buf, MV_OFF_SEQ, 7);
        put_u64(&mut buf, MV_OFF_KTIME, 123_456);
        put_u64(&mut buf, MV_OFF_SIZE, 4096);
        put_u16(&mut buf, MV_OFF_NAME_LEN, 3);
        buf[MV_OFF_NAME..MV_OFF_NAME + 3].copy_from_slice(b"vd0");
        buf
    }

    /// Minimal valid 44-byte lifecycle record: successful map, TO_DEVICE,
    /// generation 1.
    fn valid_lifecycle() -> [u8; MV_LC_LEN] {
        let mut buf = [0u8; MV_LC_LEN];
        put_u32(&mut buf, MV_LC_OFF_MAGIC, MV_LC_MAGIC);
        put_u16(&mut buf, MV_LC_OFF_VERSION, MV_LC_VERSION);
        put_u16(&mut buf, MV_LC_OFF_KIND, MV_LC_KIND_MAP);
        put_u16(&mut buf, MV_LC_OFF_FLAGS, MV_LC_FLAG_OK);
        put_u16(&mut buf, MV_LC_OFF_DIR, 1);
        put_u64(&mut buf, MV_LC_OFF_SEQ, 9);
        put_u64(&mut buf, MV_LC_OFF_KTIME, 654_321);
        put_u64(&mut buf, MV_LC_OFF_SIZE, 2048);
        put_u64(&mut buf, MV_LC_OFF_GEN, 1);
        buf
    }

    /// Minimal valid 48-byte copy record: known device-bound copy of 512
    /// requested / 512 effective bytes.
    fn valid_copy() -> [u8; MV_CP_LEN] {
        let mut buf = [0u8; MV_CP_LEN];
        put_u32(&mut buf, MV_CP_OFF_MAGIC, MV_CP_MAGIC);
        put_u16(&mut buf, MV_CP_OFF_VERSION, MV_CP_VERSION);
        put_u16(&mut buf, MV_CP_OFF_KIND, MV_CP_KIND_COPY);
        put_u16(
            &mut buf,
            MV_CP_OFF_FLAGS,
            MV_CP_FLAG_TO_DEVICE | MV_CP_FLAG_KNOWN,
        );
        put_u16(&mut buf, MV_CP_OFF_DIR, 1);
        put_u64(&mut buf, MV_CP_OFF_SEQ, 11);
        put_u64(&mut buf, MV_CP_OFF_KTIME, 999_999);
        put_u64(&mut buf, MV_CP_OFF_REQUESTED, 512);
        put_u64(&mut buf, MV_CP_OFF_EFFECTIVE, 512);
        put_u16(&mut buf, MV_CP_OFF_REASON, MV_CP_REASON_NONE);
        buf
    }

    #[test]
    fn decode_frame_routes_each_channel() {
        let attempt = valid_attempt();
        let Frame::Attempt(record) = decode_frame(Channel::Attempt, &attempt).expect("attempt")
        else {
            panic!("attempt bytes must decode as an attempt frame");
        };
        assert_eq!((record.seq, record.ktime, record.size), (7, 123_456, 4096));
        assert!(record.force);
        assert_eq!(record.name_len, 3);
        assert_eq!(&record.name[..3], b"vd0");

        let lifecycle = valid_lifecycle();
        let Frame::Lifecycle(record) =
            decode_frame(Channel::Lifecycle, &lifecycle).expect("lifecycle")
        else {
            panic!("lifecycle bytes must decode as a lifecycle frame");
        };
        assert_eq!(record.kind, MV_LC_KIND_MAP);
        assert!(record.ok);
        assert_eq!((record.dir, record.seq, record.generation), (1, 9, 1));

        let copy = valid_copy();
        let Frame::Copy(record) = decode_frame(Channel::Copy, &copy).expect("copy") else {
            panic!("copy bytes must decode as a copy frame");
        };
        assert_eq!(record.kind, MV_CP_KIND_COPY);
        assert!(record.to_device && record.known);
        assert_eq!(
            (record.seq, record.requested, record.effective),
            (11, 512, 512)
        );
    }

    #[test]
    fn decode_frame_rejects_wrong_channel_bytes() {
        // Lengths alone discriminate the channels: 98 vs 44 vs 48.
        let attempt = valid_attempt();
        assert!(decode_frame(Channel::Lifecycle, &attempt).is_err());
        assert!(decode_frame(Channel::Copy, &attempt).is_err());
        let lifecycle = valid_lifecycle();
        assert!(decode_frame(Channel::Attempt, &lifecycle).is_err());
        assert!(decode_frame(Channel::Copy, &lifecycle).is_err());
        let copy = valid_copy();
        assert!(decode_frame(Channel::Attempt, &copy).is_err());
        assert!(decode_frame(Channel::Lifecycle, &copy).is_err());
    }

    #[test]
    fn decode_frame_rejects_corrupt_buffers() {
        let mut bad = valid_attempt();
        bad[MV_OFF_MAGIC] ^= 0xff;
        assert!(decode_frame(Channel::Attempt, &bad).is_err());
        assert!(decode_frame(Channel::Attempt, &bad[..MV_PAYLOAD_LEN - 1]).is_err());

        let mut bad = valid_lifecycle();
        put_u16(&mut bad, MV_LC_OFF_DIR, 3);
        assert!(decode_frame(Channel::Lifecycle, &bad).is_err());

        let mut bad = valid_copy();
        put_u16(&mut bad, MV_CP_OFF_REASON, 99);
        assert!(decode_frame(Channel::Copy, &bad).is_err());
    }

    #[test]
    fn fresh_session_stats_are_zero() {
        // `Session::open` only parses the ELF, so this runs unprivileged and
        // pins the accounting start state every live poll builds on.
        let path = env!("DEP_MEMVEIL_EBPF_ATTEMPT_PATH");
        let bytes = std::fs::read(path).expect("read attempt ELF");
        let session = Session::open(&bytes, "mv_attempts").expect("open");
        assert_eq!(session.stats(), Stats::default());
        assert_eq!(
            session.stats(),
            Stats {
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
            }
        );
    }
}
