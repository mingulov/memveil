//! SPDX-License-Identifier: GPL-2.0-or-later
//! MemVeil eBPF/host shared wire record types and decoders.
//!
//! Layouts mirror `bpf/include/memveil_events.h`: attempt 98 B,
//! lifecycle 44 B, copy 48 B, offsets table 24 B.

#![cfg_attr(not(feature = "user"), no_std)]

#[cfg(test)]
extern crate std;

/* Attempt wire format: 98 bytes, little-endian, packed. */
/// Attempt payload length in bytes.
pub const MV_PAYLOAD_LEN: usize = 98;
/// Attempt magic (`"MVA7"`).
pub const MV_MAGIC: u32 = 0x3741_564D;
/// Attempt version.
pub const MV_VERSION: u16 = 1;
/// Attempt flags: forced bounce.
pub const MV_FLAG_FORCE: u16 = 0x1;
/// Maximum device-name length excluding the NUL terminator.
pub const MV_NAME_MAX: usize = 63;
/// Attempt field offsets.
pub const MV_OFF_MAGIC: usize = 0;
/// Attempt field offsets.
pub const MV_OFF_VERSION: usize = 4;
/// Attempt field offsets.
pub const MV_OFF_FLAGS: usize = 6;
/// Attempt field offsets.
pub const MV_OFF_SEQ: usize = 8;
/// Attempt field offsets.
pub const MV_OFF_KTIME: usize = 16;
/// Attempt field offsets.
pub const MV_OFF_SIZE: usize = 24;
/// Attempt field offsets.
pub const MV_OFF_NAME_LEN: usize = 32;
/// Attempt field offsets.
pub const MV_OFF_NAME: usize = 34;

/// Tracepoint context bounds (`swiotlb_bounced`).
pub const MV_CTX_FIXED: usize = 41;
/// Tracepoint context bounds (`swiotlb_bounced`).
pub const MV_CTX_READ_CAP: usize = 512;

/* Load-time trace-offset table: 24 bytes, little-endian, packed. */
/// Offsets-table magic (`"MFO5"`).
pub const MV_OFF_TABLE_MAGIC: u32 = 0x3546_4D4D;
/// Offsets-table version.
pub const MV_OFF_TABLE_VERSION: u16 = 1;
/// Fixed-region cap for tabled extents and the floor.
pub const MV_FIXED_MAX: u32 = 128;
/// Offsets-table length in bytes.
pub const MV_OFFSETS_TABLE_LEN: usize = 24;

/* Counter map indices (`mv_counts`, array of 6 u64). */
/// Counter map indices.
pub const MV_CNT_OBSERVED: usize = 0;
/// Counter map indices.
pub const MV_CNT_OBSERVED_BYTES: usize = 1;
/// Counter map indices.
pub const MV_CNT_EMITTED: usize = 2;
/// Counter map indices.
pub const MV_CNT_EMITTED_BYTES: usize = 3;
/// Counter map indices.
pub const MV_CNT_SUBMIT_FAIL: usize = 4;
/// Counter map indices.
pub const MV_CNT_FLAGS: usize = 5;
/// Counter map length.
pub const MV_CNT_LEN: usize = 6;

/* Flag word bits (sticky; any set bit invalidates the epoch). */
/// Flag word bits.
pub const MV_FLAG_OBSERVED_WRAP: u64 = 1 << 0;
/// Flag word bits.
pub const MV_FLAG_OBSERVED_BYTES_WRAP: u64 = 1 << 1;
/// Flag word bits.
pub const MV_FLAG_EMITTED_WRAP: u64 = 1 << 2;
/// Flag word bits.
pub const MV_FLAG_EMITTED_BYTES_WRAP: u64 = 1 << 3;
/// Flag word bits.
pub const MV_FLAG_SUBMIT_WRAP: u64 = 1 << 4;
/// Flag word bits.
pub const MV_FLAG_BYTE_COVERAGE: u64 = 1 << 5;
/// Flag word bits.
pub const MV_FLAG_ARGCNT: u64 = 1 << 6;

/* Lifecycle v2 wire format: 44 bytes, little-endian, packed. */
/// Lifecycle record length in bytes.
pub const MV_LC_LEN: usize = 44;
/// Lifecycle magic (`"MVLC"`).
pub const MV_LC_MAGIC: u32 = 0x434C_564D;
/// Lifecycle version.
pub const MV_LC_VERSION: u16 = 2;
/// Lifecycle kinds.
pub const MV_LC_KIND_MAP: u16 = 1;
/// Lifecycle kinds.
pub const MV_LC_KIND_UNMAP: u16 = 2;
/// Lifecycle flags.
pub const MV_LC_FLAG_OK: u16 = 0x1;
/// Lifecycle flags.
pub const MV_LC_FLAG_SKIP_SYNC: u16 = 0x2;
/// Lifecycle flags.
pub const MV_LC_FLAG_GEN_MISS: u16 = 0x4;
/// Lifecycle flags.
pub const MV_LC_FLAG_GEN_UNASSIGNED: u16 = 0x8;
/// Largest assignable mapping generation (0 means unknown).
pub const MV_LC_GEN_MAX: u64 = 0xFFFF_FFFF_FFFF_FFFE;
/// Lifecycle field offsets.
pub const MV_LC_OFF_MAGIC: usize = 0;
/// Lifecycle field offsets.
pub const MV_LC_OFF_VERSION: usize = 4;
/// Lifecycle field offsets.
pub const MV_LC_OFF_KIND: usize = 6;
/// Lifecycle field offsets.
pub const MV_LC_OFF_FLAGS: usize = 8;
/// Lifecycle field offsets.
pub const MV_LC_OFF_DIR: usize = 10;
/// Lifecycle field offsets.
pub const MV_LC_OFF_SEQ: usize = 12;
/// Lifecycle field offsets.
pub const MV_LC_OFF_KTIME: usize = 20;
/// Lifecycle field offsets.
pub const MV_LC_OFF_SIZE: usize = 28;
/// Lifecycle field offsets.
pub const MV_LC_OFF_GEN: usize = 36;

/* Copy v1 wire format: 48 bytes, little-endian, packed. */
/// Copy record length in bytes.
pub const MV_CP_LEN: usize = 48;
/// Copy magic (`"MVCP"`).
pub const MV_CP_MAGIC: u32 = 0x5043_564D;
/// Copy version.
pub const MV_CP_VERSION: u16 = 1;
/// Copy kinds.
pub const MV_CP_KIND_SYNC: u16 = 1;
/// Copy kinds.
pub const MV_CP_KIND_COPY: u16 = 2;
/// Copy flags.
pub const MV_CP_FLAG_TO_DEVICE: u16 = 0x1;
/// Copy flags.
pub const MV_CP_FLAG_KNOWN: u16 = 0x2;
/// Copy flags.
pub const MV_CP_FLAG_CLAMPED: u16 = 0x4;
/// Copy flags.
pub const MV_CP_FLAG_EARLY_ZERO: u16 = 0x8;
/// Copy flags.
pub const MV_CP_FLAG_OFFSET_PAST_ALLOC: u16 = 0x10;
/// Copy flags.
pub const MV_CP_FLAG_PRIVATE_POOL: u16 = 0x20;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_NONE: u16 = 0;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_SLOT_READ: u16 = 1;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_MASK_READ: u16 = 2;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_BOUNDS: u16 = 3;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_NOT_COPY: u16 = 4;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_LAYOUT: u16 = 5;
/// Copy unknown-effective reasons.
pub const MV_CP_REASON_SHIFT: u16 = 6;
/// Copy field offsets.
pub const MV_CP_OFF_MAGIC: usize = 0;
/// Copy field offsets.
pub const MV_CP_OFF_VERSION: usize = 4;
/// Copy field offsets.
pub const MV_CP_OFF_KIND: usize = 6;
/// Copy field offsets.
pub const MV_CP_OFF_FLAGS: usize = 8;
/// Copy field offsets.
pub const MV_CP_OFF_DIR: usize = 10;
/// Copy field offsets.
pub const MV_CP_OFF_SEQ: usize = 12;
/// Copy field offsets.
pub const MV_CP_OFF_KTIME: usize = 20;
/// Copy field offsets.
pub const MV_CP_OFF_REQUESTED: usize = 28;
/// Copy field offsets.
pub const MV_CP_OFF_EFFECTIVE: usize = 36;
/// Copy field offsets.
pub const MV_CP_OFF_REASON: usize = 44;

/// Failure sentinel shared by the map hooks: `(phys_addr_t)
/// DMA_MAPPING_ERROR`, i.e. all bits set.
pub const MV_INVALID_PHYS: u64 = 0xFFFF_FFFF_FFFF_FFFF;

/// Wire attempt record: exactly 98 bytes, packed. Fields are
/// unaligned; read them with `addr_of!` plus `read_unaligned`.
#[repr(C, packed)]
pub struct AttemptRecord {
    /// Magic, must equal [`MV_MAGIC`].
    pub magic: u32,
    /// Version, must equal [`MV_VERSION`].
    pub version: u16,
    /// Flags, only [`MV_FLAG_FORCE`] is defined.
    pub flags: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Requested bounce size.
    pub size: u64,
    /// Device-name length excluding the NUL.
    pub name_len: u16,
    /// NUL-terminated device name with zero padding.
    pub name: [u8; 64],
}

impl AttemptRecord {
    /// Wire length in bytes.
    pub const LEN: usize = MV_PAYLOAD_LEN;
}

/// Wire lifecycle record: exactly 44 bytes, packed. Fields are
/// unaligned; read them with `addr_of!` plus `read_unaligned`.
#[repr(C, packed)]
pub struct LifecycleRecord {
    /// Magic, must equal [`MV_LC_MAGIC`].
    pub magic: u32,
    /// Version, must equal [`MV_LC_VERSION`].
    pub version: u16,
    /// Kind, [`MV_LC_KIND_MAP`] or [`MV_LC_KIND_UNMAP`].
    pub kind: u16,
    /// Flags, only the `MV_LC_FLAG_*` bits are defined.
    pub flags: u16,
    /// Raw `enum dma_data_direction` value (0..2).
    pub dir: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Mapping size.
    pub size: u64,
    /// Opaque mapping generation (0 means unknown).
    pub generation: u64,
}

impl LifecycleRecord {
    /// Wire length in bytes.
    pub const LEN: usize = MV_LC_LEN;
}

/// Wire copy record: exactly 48 bytes, packed. Fields are
/// unaligned; read them with `addr_of!` plus `read_unaligned`.
#[repr(C, packed)]
pub struct CopyRecord {
    /// Magic, must equal [`MV_CP_MAGIC`].
    pub magic: u32,
    /// Version, must equal [`MV_CP_VERSION`].
    pub version: u16,
    /// Kind, [`MV_CP_KIND_SYNC`] or [`MV_CP_KIND_COPY`].
    pub kind: u16,
    /// Flags, only the `MV_CP_FLAG_*` bits are defined.
    pub flags: u16,
    /// Raw `enum dma_data_direction` value (0..2; copies use 1..2).
    pub dir: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Requested copy length.
    pub requested: u64,
    /// Executed copy length (valid only when known).
    pub effective: u64,
    /// Unknown-effective reason, one of `MV_CP_REASON_*`.
    pub reason: u16,
    /// Trailing pad to 48 bytes.
    pub pad: [u8; 2],
}

impl CopyRecord {
    /// Wire length in bytes.
    pub const LEN: usize = MV_CP_LEN;
}

/// Wire load-time offsets table: exactly 24 bytes, packed. Fields
/// are unaligned; read them with `addr_of!` plus `read_unaligned`.
#[repr(C, packed)]
pub struct OffsetsTable {
    /// Magic, must equal [`MV_OFF_TABLE_MAGIC`].
    pub magic: u32,
    /// Version, must equal [`MV_OFF_TABLE_VERSION`].
    pub version: u16,
    /// Reserved, ignored by validation.
    pub reserved: u16,
    /// `dev_name __data_loc` slot offset.
    pub loc_off: u32,
    /// `size` u64 slot offset.
    pub size_off: u32,
    /// `force` byte slot offset.
    pub force_off: u32,
    /// Dynamic-data floor over the live fixed fields.
    pub fixed_end: u32,
}

impl OffsetsTable {
    /// Wire length in bytes.
    pub const LEN: usize = MV_OFFSETS_TABLE_LEN;
}

/// Decoded attempt fields (host struct, not wire layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempt {
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Requested bounce size.
    pub size: u64,
    /// Device-name length excluding the NUL.
    pub name_len: u16,
    /// Forced bounce.
    pub force: bool,
    /// Device name with zero padding.
    pub name: [u8; 64],
}

/// Decoded lifecycle fields (host struct, not wire layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lifecycle {
    /// Kind, [`MV_LC_KIND_MAP`] or [`MV_LC_KIND_UNMAP`].
    pub kind: u16,
    /// Slots found (map) or entry live (unmap).
    pub ok: bool,
    /// Unmap skipped the sync (`attrs` bit 5).
    pub skip_sync: bool,
    /// Raw `enum dma_data_direction` value.
    pub dir: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Mapping size.
    pub size: u64,
    /// Opaque mapping generation (0 means unknown).
    pub generation: u64,
}

/// Decoded copy fields (host struct, not wire layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Copy {
    /// Kind, [`MV_CP_KIND_SYNC`] or [`MV_CP_KIND_COPY`].
    pub kind: u16,
    /// Direction toward the device.
    pub to_device: bool,
    /// Effective length is known.
    pub known: bool,
    /// Effective length was clamped to the room.
    pub clamped: bool,
    /// Invalid slot, nothing copied.
    pub early_zero: bool,
    /// Offset past the allocation (known copy, never early-zero).
    pub offset_past: bool,
    /// Private-pool copy (known copy only).
    pub private_pool: bool,
    /// Raw `enum dma_data_direction` value.
    pub dir: u16,
    /// Unknown-effective reason, one of `MV_CP_REASON_*`.
    pub reason: u16,
    /// Record sequence number.
    pub seq: u64,
    /// Kernel timestamp.
    pub ktime: u64,
    /// Requested copy length.
    pub requested: u64,
    /// Executed copy length (valid only when known).
    pub effective: u64,
}

/// Validated offsets-table fields (host struct, not wire layout).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offsets {
    /// `dev_name __data_loc` slot offset.
    pub loc_off: u32,
    /// `size` u64 slot offset.
    pub size_off: u32,
    /// `force` byte slot offset.
    pub force_off: u32,
    /// Dynamic-data floor over the live fixed fields.
    pub fixed_end: u32,
}

/// Wire decode failure. Names mirror the shared reason vocabulary
/// (`PAY_*`, plus `TableBad` for the offsets table).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input shorter than the record.
    Short,
    /// Input longer than the record.
    Long,
    /// Wrong magic.
    Magic,
    /// Wrong version.
    Version,
    /// Unknown or inconsistent flag bits.
    Flags,
    /// Device-name length above [`MV_NAME_MAX`].
    NameLen,
    /// Missing terminator or early NUL in the name.
    Nul,
    /// Nonzero padding after the name terminator.
    Pad,
    /// Unknown record kind.
    Kind,
    /// Direction outside the admitted range.
    Dir,
    /// Unknown or inconsistent copy reason.
    Reason,
    /// Generation outside the assignable range.
    Range,
    /// Missing, zero, or inconsistent offsets table.
    TableBad,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            DecodeError::Short => "short input",
            DecodeError::Long => "long input",
            DecodeError::Magic => "bad magic",
            DecodeError::Version => "bad version",
            DecodeError::Flags => "bad flags",
            DecodeError::NameLen => "bad name length",
            DecodeError::Nul => "bad name terminator",
            DecodeError::Pad => "nonzero name padding",
            DecodeError::Kind => "bad kind",
            DecodeError::Dir => "bad direction",
            DecodeError::Reason => "bad reason",
            DecodeError::Range => "generation out of range",
            DecodeError::TableBad => "bad offsets table",
        };
        f.write_str(text)
    }
}

impl core::error::Error for DecodeError {}

fn read_le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

fn read_le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_le64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// Decode and strictly validate one 98-byte attempt payload.
pub fn decode_attempt(buf: &[u8]) -> Result<Attempt, DecodeError> {
    if buf.len() < MV_PAYLOAD_LEN {
        return Err(DecodeError::Short);
    }
    if buf.len() > MV_PAYLOAD_LEN {
        return Err(DecodeError::Long);
    }
    if read_le32(buf, MV_OFF_MAGIC) != MV_MAGIC {
        return Err(DecodeError::Magic);
    }
    if read_le16(buf, MV_OFF_VERSION) != MV_VERSION {
        return Err(DecodeError::Version);
    }
    let flags = read_le16(buf, MV_OFF_FLAGS);
    if flags & !MV_FLAG_FORCE != 0 {
        return Err(DecodeError::Flags);
    }
    let name_len_raw = read_le16(buf, MV_OFF_NAME_LEN);
    if usize::from(name_len_raw) > MV_NAME_MAX {
        return Err(DecodeError::NameLen);
    }
    let name_len = usize::from(name_len_raw);
    if buf[MV_OFF_NAME + name_len] != 0 {
        return Err(DecodeError::Nul);
    }
    if buf[MV_OFF_NAME..MV_OFF_NAME + name_len].contains(&0) {
        return Err(DecodeError::Nul);
    }
    if buf[MV_OFF_NAME + name_len + 1..MV_OFF_NAME + MV_NAME_MAX + 1]
        .iter()
        .any(|byte| *byte != 0)
    {
        return Err(DecodeError::Pad);
    }
    let mut name = [0u8; 64];
    name[..name_len].copy_from_slice(&buf[MV_OFF_NAME..MV_OFF_NAME + name_len]);
    Ok(Attempt {
        seq: read_le64(buf, MV_OFF_SEQ),
        ktime: read_le64(buf, MV_OFF_KTIME),
        size: read_le64(buf, MV_OFF_SIZE),
        name_len: name_len_raw,
        force: flags & MV_FLAG_FORCE != 0,
        name,
    })
}

/// Decode and strictly validate one 44-byte lifecycle record.
/// Precedence is header-first: a short buffer that cannot hold
/// magic plus version fails [`DecodeError::Short`]; then magic,
/// version, length, kind, flags, dir, flag/generation coupling,
/// and generation range.
pub fn decode_lifecycle(buf: &[u8]) -> Result<Lifecycle, DecodeError> {
    if buf.len() < MV_LC_OFF_VERSION + 2 {
        return Err(DecodeError::Short);
    }
    if read_le32(buf, MV_LC_OFF_MAGIC) != MV_LC_MAGIC {
        return Err(DecodeError::Magic);
    }
    if read_le16(buf, MV_LC_OFF_VERSION) != MV_LC_VERSION {
        return Err(DecodeError::Version);
    }
    if buf.len() < MV_LC_LEN {
        return Err(DecodeError::Short);
    }
    if buf.len() > MV_LC_LEN {
        return Err(DecodeError::Long);
    }
    let kind = read_le16(buf, MV_LC_OFF_KIND);
    if kind != MV_LC_KIND_MAP && kind != MV_LC_KIND_UNMAP {
        return Err(DecodeError::Kind);
    }
    let flags = read_le16(buf, MV_LC_OFF_FLAGS);
    if flags
        & !(MV_LC_FLAG_OK | MV_LC_FLAG_SKIP_SYNC | MV_LC_FLAG_GEN_MISS | MV_LC_FLAG_GEN_UNASSIGNED)
        != 0
    {
        return Err(DecodeError::Flags);
    }
    let dir = read_le16(buf, MV_LC_OFF_DIR);
    if dir > 2 {
        return Err(DecodeError::Dir);
    }
    let generation = read_le64(buf, MV_LC_OFF_GEN);
    if kind == MV_LC_KIND_MAP {
        if flags & !(MV_LC_FLAG_OK | MV_LC_FLAG_GEN_UNASSIGNED) != 0 {
            return Err(DecodeError::Flags);
        }
        if flags & MV_LC_FLAG_OK != 0 {
            if (flags & MV_LC_FLAG_GEN_UNASSIGNED != 0) != (generation == 0) {
                return Err(DecodeError::Flags);
            }
        } else if flags != 0 || generation != 0 {
            return Err(DecodeError::Flags);
        }
    } else {
        if flags & !(MV_LC_FLAG_OK | MV_LC_FLAG_SKIP_SYNC | MV_LC_FLAG_GEN_MISS) != 0 {
            return Err(DecodeError::Flags);
        }
        if (flags & MV_LC_FLAG_GEN_MISS != 0) != (generation == 0) {
            return Err(DecodeError::Flags);
        }
    }
    if generation != 0 && generation > MV_LC_GEN_MAX {
        return Err(DecodeError::Range);
    }
    Ok(Lifecycle {
        kind,
        ok: flags & MV_LC_FLAG_OK != 0,
        skip_sync: flags & MV_LC_FLAG_SKIP_SYNC != 0,
        dir,
        seq: read_le64(buf, MV_LC_OFF_SEQ),
        ktime: read_le64(buf, MV_LC_OFF_KTIME),
        size: read_le64(buf, MV_LC_OFF_SIZE),
        generation,
    })
}

/// Decode and strictly validate one 48-byte copy record.
pub fn decode_copy(buf: &[u8]) -> Result<Copy, DecodeError> {
    if buf.len() < MV_CP_LEN {
        return Err(DecodeError::Short);
    }
    if buf.len() > MV_CP_LEN {
        return Err(DecodeError::Long);
    }
    if read_le32(buf, MV_CP_OFF_MAGIC) != MV_CP_MAGIC {
        return Err(DecodeError::Magic);
    }
    if read_le16(buf, MV_CP_OFF_VERSION) != MV_CP_VERSION {
        return Err(DecodeError::Version);
    }
    let kind = read_le16(buf, MV_CP_OFF_KIND);
    if kind != MV_CP_KIND_SYNC && kind != MV_CP_KIND_COPY {
        return Err(DecodeError::Kind);
    }
    let flags = read_le16(buf, MV_CP_OFF_FLAGS);
    if flags
        & !(MV_CP_FLAG_TO_DEVICE
            | MV_CP_FLAG_KNOWN
            | MV_CP_FLAG_CLAMPED
            | MV_CP_FLAG_EARLY_ZERO
            | MV_CP_FLAG_OFFSET_PAST_ALLOC
            | MV_CP_FLAG_PRIVATE_POOL)
        != 0
    {
        return Err(DecodeError::Flags);
    }
    if flags & MV_CP_FLAG_OFFSET_PAST_ALLOC != 0
        && (kind != MV_CP_KIND_COPY
            || flags & MV_CP_FLAG_KNOWN == 0
            || flags & MV_CP_FLAG_EARLY_ZERO != 0)
    {
        return Err(DecodeError::Flags);
    }
    if flags & MV_CP_FLAG_PRIVATE_POOL != 0
        && (kind != MV_CP_KIND_COPY || flags & MV_CP_FLAG_KNOWN == 0)
    {
        return Err(DecodeError::Flags);
    }
    let dir = read_le16(buf, MV_CP_OFF_DIR);
    if dir > 2 || (kind == MV_CP_KIND_COPY && dir == 0) {
        return Err(DecodeError::Dir);
    }
    let reason = read_le16(buf, MV_CP_OFF_REASON);
    if reason > MV_CP_REASON_SHIFT {
        return Err(DecodeError::Reason);
    }
    if flags & MV_CP_FLAG_KNOWN != 0 {
        if reason != MV_CP_REASON_NONE {
            return Err(DecodeError::Reason);
        }
    } else if kind == MV_CP_KIND_SYNC {
        if reason != MV_CP_REASON_NOT_COPY {
            return Err(DecodeError::Reason);
        }
    } else if reason == MV_CP_REASON_NONE || reason == MV_CP_REASON_NOT_COPY {
        return Err(DecodeError::Reason);
    }
    Ok(Copy {
        kind,
        to_device: flags & MV_CP_FLAG_TO_DEVICE != 0,
        known: flags & MV_CP_FLAG_KNOWN != 0,
        clamped: flags & MV_CP_FLAG_CLAMPED != 0,
        early_zero: flags & MV_CP_FLAG_EARLY_ZERO != 0,
        offset_past: flags & MV_CP_FLAG_OFFSET_PAST_ALLOC != 0,
        private_pool: flags & MV_CP_FLAG_PRIVATE_POOL != 0,
        dir,
        reason,
        seq: read_le64(buf, MV_CP_OFF_SEQ),
        ktime: read_le64(buf, MV_CP_OFF_KTIME),
        requested: read_le64(buf, MV_CP_OFF_REQUESTED),
        effective: read_le64(buf, MV_CP_OFF_EFFECTIVE),
    })
}

/// Decode and validate one 24-byte offsets table the way the
/// program does: magic, version, per-extent caps, dynamic-floor
/// cap, pairwise overlap among the tabled extents and the
/// common-type anchor, and floor coverage over every extent.
pub fn decode_offsets_table(buf: &[u8]) -> Result<Offsets, DecodeError> {
    if buf.len() < MV_OFFSETS_TABLE_LEN {
        return Err(DecodeError::Short);
    }
    if buf.len() > MV_OFFSETS_TABLE_LEN {
        return Err(DecodeError::Long);
    }
    if read_le32(buf, 0) != MV_OFF_TABLE_MAGIC {
        return Err(DecodeError::TableBad);
    }
    if read_le16(buf, 4) != MV_OFF_TABLE_VERSION {
        return Err(DecodeError::TableBad);
    }
    let loc_off = read_le32(buf, 8);
    let size_off = read_le32(buf, 12);
    let force_off = read_le32(buf, 16);
    let fixed_end = read_le32(buf, 20);
    if loc_off > MV_FIXED_MAX - 4
        || size_off > MV_FIXED_MAX - 8
        || force_off > MV_FIXED_MAX - 1
        || fixed_end > MV_FIXED_MAX
    {
        return Err(DecodeError::TableBad);
    }
    // The common-type anchor pins the trace-entry header at
    // context+0: no tabled extent may read header bytes as a
    // consumed field.
    if loc_off < 2 || size_off < 2 || force_off < 2 {
        return Err(DecodeError::TableBad);
    }
    let loc_end = loc_off + 4;
    let size_end = size_off + 8;
    let force_end = force_off + 1;
    if (loc_off < size_end && size_off < loc_end)
        || (loc_off < force_end && force_off < loc_end)
        || (size_off < force_end && force_off < size_end)
    {
        return Err(DecodeError::TableBad);
    }
    // The dynamic floor must cover every tabled extent.
    if fixed_end < loc_end || fixed_end < size_end || fixed_end < force_end {
        return Err(DecodeError::TableBad);
    }
    Ok(Offsets {
        loc_off,
        size_off,
        force_off,
        fixed_end,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn attempt_size_and_offsets() {
        assert_eq!(core::mem::size_of::<AttemptRecord>(), 98);
        assert_eq!(core::mem::offset_of!(AttemptRecord, magic), 0);
        assert_eq!(core::mem::offset_of!(AttemptRecord, version), 4);
        assert_eq!(core::mem::offset_of!(AttemptRecord, flags), 6);
        assert_eq!(core::mem::offset_of!(AttemptRecord, seq), 8);
        assert_eq!(core::mem::offset_of!(AttemptRecord, ktime), 16);
        assert_eq!(core::mem::offset_of!(AttemptRecord, size), 24);
        assert_eq!(core::mem::offset_of!(AttemptRecord, name_len), 32);
        assert_eq!(core::mem::offset_of!(AttemptRecord, name), 34);
    }

    #[test]
    fn lifecycle_size_and_offsets() {
        assert_eq!(core::mem::size_of::<LifecycleRecord>(), 44);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, kind), 6);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, flags), 8);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, dir), 10);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, seq), 12);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, ktime), 20);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, size), 28);
        assert_eq!(core::mem::offset_of!(LifecycleRecord, generation), 36);
    }

    #[test]
    fn copy_size_and_offsets() {
        assert_eq!(core::mem::size_of::<CopyRecord>(), 48);
        assert_eq!(core::mem::offset_of!(CopyRecord, kind), 6);
        assert_eq!(core::mem::offset_of!(CopyRecord, flags), 8);
        assert_eq!(core::mem::offset_of!(CopyRecord, dir), 10);
        assert_eq!(core::mem::offset_of!(CopyRecord, seq), 12);
        assert_eq!(core::mem::offset_of!(CopyRecord, ktime), 20);
        assert_eq!(core::mem::offset_of!(CopyRecord, requested), 28);
        assert_eq!(core::mem::offset_of!(CopyRecord, effective), 36);
        assert_eq!(core::mem::offset_of!(CopyRecord, reason), 44);
    }

    #[test]
    fn offsets_table_size_and_offsets() {
        assert_eq!(core::mem::size_of::<OffsetsTable>(), 24);
        assert_eq!(core::mem::offset_of!(OffsetsTable, magic), 0);
        assert_eq!(core::mem::offset_of!(OffsetsTable, version), 4);
        assert_eq!(core::mem::offset_of!(OffsetsTable, loc_off), 8);
        assert_eq!(core::mem::offset_of!(OffsetsTable, size_off), 12);
        assert_eq!(core::mem::offset_of!(OffsetsTable, force_off), 16);
        assert_eq!(core::mem::offset_of!(OffsetsTable, fixed_end), 20);
    }

    fn attempt_bytes() -> [u8; 98] {
        let mut buf = [0u8; 98];
        buf[0..4].copy_from_slice(&MV_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&MV_VERSION.to_le_bytes());
        buf
    }

    fn lifecycle_bytes() -> [u8; 44] {
        let mut buf = [0u8; 44];
        buf[0..4].copy_from_slice(&MV_LC_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&MV_LC_VERSION.to_le_bytes());
        buf[6..8].copy_from_slice(&MV_LC_KIND_MAP.to_le_bytes());
        buf[8..10].copy_from_slice(&MV_LC_FLAG_OK.to_le_bytes());
        buf[10..12].copy_from_slice(&1u16.to_le_bytes());
        buf[36..44].copy_from_slice(&1u64.to_le_bytes());
        buf
    }

    fn copy_bytes() -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..4].copy_from_slice(&MV_CP_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&MV_CP_VERSION.to_le_bytes());
        buf[6..8].copy_from_slice(&MV_CP_KIND_COPY.to_le_bytes());
        buf[8..10].copy_from_slice(&(MV_CP_FLAG_TO_DEVICE | MV_CP_FLAG_KNOWN).to_le_bytes());
        buf[10..12].copy_from_slice(&1u16.to_le_bytes());
        buf
    }

    #[test]
    fn decode_rejects_bad_magic() {
        let mut bad = attempt_bytes();
        bad[0] ^= 0xff;
        assert_eq!(decode_attempt(&bad), Err(DecodeError::Magic));
        let mut bad = lifecycle_bytes();
        bad[0] ^= 0xff;
        assert_eq!(decode_lifecycle(&bad), Err(DecodeError::Magic));
        let mut bad = copy_bytes();
        bad[0] ^= 0xff;
        assert_eq!(decode_copy(&bad), Err(DecodeError::Magic));
    }

    #[test]
    fn decode_rejects_bad_version() {
        let mut bad = attempt_bytes();
        bad[4] = bad[4].wrapping_add(1);
        assert_eq!(decode_attempt(&bad), Err(DecodeError::Version));
        let mut bad = lifecycle_bytes();
        bad[4] = bad[4].wrapping_add(1);
        assert_eq!(decode_lifecycle(&bad), Err(DecodeError::Version));
        let mut bad = copy_bytes();
        bad[4] = bad[4].wrapping_add(1);
        assert_eq!(decode_copy(&bad), Err(DecodeError::Version));
    }

    #[test]
    fn decode_rejects_short_input() {
        let buf = attempt_bytes();
        assert_eq!(decode_attempt(&buf[..97]), Err(DecodeError::Short));
        let buf = lifecycle_bytes();
        assert_eq!(decode_lifecycle(&buf[..5]), Err(DecodeError::Short));
        assert_eq!(decode_lifecycle(&buf[..43]), Err(DecodeError::Short));
        let buf = copy_bytes();
        assert_eq!(decode_copy(&buf[..47]), Err(DecodeError::Short));
    }

    #[test]
    fn valid_records_decode() {
        let attempt = decode_attempt(&attempt_bytes()).expect("valid attempt");
        assert_eq!((attempt.seq, attempt.ktime, attempt.size), (0, 0, 0));
        assert_eq!(attempt.name_len, 0);
        assert!(!attempt.force);
        let lifecycle = decode_lifecycle(&lifecycle_bytes()).expect("valid lifecycle");
        assert_eq!(lifecycle.kind, MV_LC_KIND_MAP);
        assert!(lifecycle.ok);
        assert_eq!(lifecycle.generation, 1);
        let copy = decode_copy(&copy_bytes()).expect("valid copy");
        assert_eq!(copy.kind, MV_CP_KIND_COPY);
        assert!(copy.to_device && copy.known);
        assert_eq!(copy.reason, MV_CP_REASON_NONE);
    }

    #[test]
    fn offsets_table_round_trip() {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&MV_OFF_TABLE_MAGIC.to_le_bytes());
        buf[4..6].copy_from_slice(&MV_OFF_TABLE_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&8u32.to_le_bytes());
        buf[12..16].copy_from_slice(&32u32.to_le_bytes());
        buf[16..20].copy_from_slice(&40u32.to_le_bytes());
        buf[20..24].copy_from_slice(&41u32.to_le_bytes());
        let table = decode_offsets_table(&buf).expect("valid table");
        assert_eq!(
            (
                table.loc_off,
                table.size_off,
                table.force_off,
                table.fixed_end
            ),
            (8, 32, 40, 41)
        );
        let mut bad = buf;
        bad[0] ^= 0xff;
        assert_eq!(decode_offsets_table(&bad), Err(DecodeError::TableBad));
        assert_eq!(decode_offsets_table(&buf[..23]), Err(DecodeError::Short));
    }

    fn read_u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().expect("u32"))
    }

    /// Split a `corpus.bin` blob into `(kind, bytes)` records.
    fn split_corpus(blob: &[u8]) -> Vec<(u32, Vec<u8>)> {
        let count = read_u32_le(blob, 0) as usize;
        let mut off = 4;
        let mut out = Vec::new();
        for _ in 0..count {
            let kind = read_u32_le(blob, off);
            let len = read_u32_le(blob, off + 4) as usize;
            out.push((kind, blob[off + 8..off + 8 + len].to_vec()));
            off += 8 + len;
        }
        assert_eq!(off, blob.len(), "trailing bytes in corpus.bin");
        out
    }

    fn verdict_error(verdict: &str) -> Option<DecodeError> {
        match verdict {
            "OK" => None,
            "PAY_SHORT" => Some(DecodeError::Short),
            "PAY_LONG" => Some(DecodeError::Long),
            "PAY_MAGIC" => Some(DecodeError::Magic),
            "PAY_VERSION" => Some(DecodeError::Version),
            "PAY_FLAGS" => Some(DecodeError::Flags),
            "PAY_NAMELEN" => Some(DecodeError::NameLen),
            "PAY_NUL" => Some(DecodeError::Nul),
            "PAY_PAD" => Some(DecodeError::Pad),
            "PAY_KIND" => Some(DecodeError::Kind),
            "PAY_DIR" => Some(DecodeError::Dir),
            "PAY_REASON" => Some(DecodeError::Reason),
            "PAY_RANGE" => Some(DecodeError::Range),
            _ => panic!("unexpected verdict {verdict}"),
        }
    }

    fn field<'a>(tail: &'a [&str], key: &str) -> &'a str {
        let prefix = std::format!("{key}=");
        tail.iter()
            .find_map(|pair| pair.strip_prefix(prefix.as_str()))
            .unwrap_or_else(|| panic!("missing field {key}"))
    }

    fn parse_u64(text: &str) -> u64 {
        text.parse::<u64>().expect("u64 field")
    }

    fn parse_hex(text: &str) -> Vec<u8> {
        assert!(text.len().is_multiple_of(2), "odd hex length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn attempts_corpus_decodes() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/fixtures/attempts"
        );
        let blob = std::fs::read(std::format!("{dir}/corpus.bin")).expect("corpus.bin");
        let text = std::fs::read_to_string(std::format!("{dir}/corpus.txt")).expect("corpus.txt");
        let records = split_corpus(&blob);
        let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(records.len(), lines.len(), "bin/txt vector count");
        let mut ctx_skipped = 0usize;
        for (idx, ((kind, bytes), line)) in records.iter().zip(lines.iter()).enumerate() {
            let mut words = line.split_whitespace();
            assert_eq!(
                words.next().expect("idx"),
                std::format!("{idx}"),
                "line {idx}"
            );
            let tag = words.next().expect("tag");
            let verdict = words.next().expect("verdict");
            let tail: Vec<&str> = words.collect();
            match (*kind, tag) {
                (1, "ctx") => {
                    // Raw tracepoint contexts carry no wire magic; the
                    // context extractor lands in a later task.
                    ctx_skipped += 1;
                }
                (2, "payload") => match verdict_error(verdict) {
                    None => {
                        assert_eq!(read_u32_le(bytes, 0), MV_MAGIC, "line {idx}: payload magic");
                        let attempt = decode_attempt(bytes).expect("line decodes");
                        assert_eq!(
                            u16::from_le_bytes(bytes[4..6].try_into().expect("ver")),
                            MV_VERSION,
                            "line {idx}: payload version"
                        );
                        assert_eq!(attempt.size, parse_u64(field(&tail, "size")), "line {idx}");
                        assert_eq!(attempt.force, field(&tail, "force") == "1", "line {idx}");
                        assert_eq!(attempt.seq, parse_u64(field(&tail, "seq")), "line {idx}");
                        assert_eq!(
                            attempt.ktime,
                            parse_u64(field(&tail, "ktime")),
                            "line {idx}"
                        );
                        assert_eq!(
                            attempt.name_len,
                            field(&tail, "namelen").parse::<u16>().expect("namelen"),
                            "line {idx}"
                        );
                        let want = parse_hex(field(&tail, "name"));
                        assert_eq!(
                            &attempt.name[..attempt.name_len as usize],
                            want.as_slice(),
                            "line {idx}"
                        );
                    }
                    Some(want) => assert_eq!(decode_attempt(bytes), Err(want), "line {idx}"),
                },
                (3, "tctx") => {
                    // The leading 24 bytes are the load-time offset
                    // table; the trailing context decodes in a later task.
                    let table = decode_offsets_table(&bytes[..24]);
                    if verdict == "OK" {
                        table.expect("table decodes");
                    } else {
                        assert_eq!(verdict, "CTX_TABLE_BAD", "line {idx}");
                        assert_eq!(table, Err(DecodeError::TableBad), "line {idx}");
                    }
                }
                _ => panic!("line {idx}: kind {kind} tag {tag} mismatch"),
            }
        }
        assert!(ctx_skipped > 0, "expected ctx vectors in the corpus");
    }

    #[test]
    fn lifecycle_wire_corpus_decodes() {
        let dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../../tests/fixtures/lifecycle-wire"
        );
        let blob = std::fs::read(std::format!("{dir}/corpus.bin")).expect("corpus.bin");
        let text = std::fs::read_to_string(std::format!("{dir}/corpus.txt")).expect("corpus.txt");
        let records = split_corpus(&blob);
        let lines: Vec<&str> = text.lines().filter(|line| !line.starts_with('#')).collect();
        assert_eq!(records.len(), lines.len(), "bin/txt vector count");
        let mut effective_skipped = 0usize;
        for (idx, ((kind, bytes), line)) in records.iter().zip(lines.iter()).enumerate() {
            let mut words = line.split_whitespace();
            assert_eq!(
                words.next().expect("idx"),
                std::format!("{idx}"),
                "line {idx}"
            );
            let tag = words.next().expect("tag");
            let verdict = words.next().expect("verdict");
            let tail: Vec<&str> = words.collect();
            match (*kind, tag) {
                (1, "lifecycle") => match verdict_error(verdict) {
                    None => {
                        assert_eq!(
                            read_u32_le(bytes, 0),
                            MV_LC_MAGIC,
                            "line {idx}: lifecycle magic"
                        );
                        assert_eq!(
                            u16::from_le_bytes(bytes[4..6].try_into().expect("ver")),
                            MV_LC_VERSION,
                            "line {idx}: lifecycle version"
                        );
                        let got = decode_lifecycle(bytes).expect("line decodes");
                        assert_eq!(
                            got.kind,
                            field(&tail, "kind").parse::<u16>().expect("kind"),
                            "line {idx}"
                        );
                        assert_eq!(got.ok, field(&tail, "ok") == "1", "line {idx}");
                        assert_eq!(got.skip_sync, field(&tail, "skip") == "1", "line {idx}");
                        assert_eq!(
                            got.dir,
                            field(&tail, "dir").parse::<u16>().expect("dir"),
                            "line {idx}"
                        );
                        assert_eq!(got.seq, parse_u64(field(&tail, "seq")), "line {idx}");
                        assert_eq!(got.ktime, parse_u64(field(&tail, "ktime")), "line {idx}");
                        assert_eq!(got.size, parse_u64(field(&tail, "size")), "line {idx}");
                        assert_eq!(got.generation, parse_u64(field(&tail, "gen")), "line {idx}");
                    }
                    Some(want) => {
                        assert_eq!(decode_lifecycle(bytes), Err(want), "line {idx}");
                    }
                },
                (2, "copy") => match verdict_error(verdict) {
                    None => {
                        assert_eq!(read_u32_le(bytes, 0), MV_CP_MAGIC, "line {idx}: copy magic");
                        assert_eq!(
                            u16::from_le_bytes(bytes[4..6].try_into().expect("ver")),
                            MV_CP_VERSION,
                            "line {idx}: copy version"
                        );
                        let got = decode_copy(bytes).expect("line decodes");
                        assert_eq!(
                            got.kind,
                            field(&tail, "kind").parse::<u16>().expect("kind"),
                            "line {idx}"
                        );
                        assert_eq!(got.to_device, field(&tail, "todevice") == "1", "line {idx}");
                        assert_eq!(got.known, field(&tail, "known") == "1", "line {idx}");
                        assert_eq!(got.clamped, field(&tail, "clamped") == "1", "line {idx}");
                        assert_eq!(
                            got.early_zero,
                            field(&tail, "earlyzero") == "1",
                            "line {idx}"
                        );
                        assert_eq!(
                            got.offset_past,
                            field(&tail, "offsetpast") == "1",
                            "line {idx}"
                        );
                        assert_eq!(
                            got.private_pool,
                            field(&tail, "privatepool") == "1",
                            "line {idx}"
                        );
                        assert_eq!(
                            got.dir,
                            field(&tail, "dir").parse::<u16>().expect("dir"),
                            "line {idx}"
                        );
                        assert_eq!(
                            got.reason,
                            field(&tail, "reason").parse::<u16>().expect("reason"),
                            "line {idx}"
                        );
                        assert_eq!(got.seq, parse_u64(field(&tail, "seq")), "line {idx}");
                        assert_eq!(got.ktime, parse_u64(field(&tail, "ktime")), "line {idx}");
                        assert_eq!(
                            got.requested,
                            parse_u64(field(&tail, "requested")),
                            "line {idx}"
                        );
                        assert_eq!(
                            got.effective,
                            parse_u64(field(&tail, "effective")),
                            "line {idx}"
                        );
                    }
                    Some(want) => {
                        assert_eq!(decode_copy(bytes), Err(want), "line {idx}");
                    }
                },
                (3, "effective") => {
                    // 25-byte effective-rule inputs, not wire records;
                    // the rule helper lands in a later task.
                    assert_eq!(verdict, "OK", "line {idx}");
                    assert_eq!(bytes.len(), 25, "line {idx}");
                    effective_skipped += 1;
                }
                _ => panic!("line {idx}: kind {kind} tag {tag} mismatch"),
            }
        }
        assert!(effective_skipped > 0, "expected effective vectors");
    }
}
