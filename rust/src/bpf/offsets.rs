// SPDX-License-Identifier: GPL-3.0-or-later
//! Load-time offset tables: tracefs-format probing for the attempt channel,
//! kernel-BTF resolution for the copy channel, and direction verification
//! for the lifecycle channel.
//!
//! Both tables translate live kernel layouts into the exact bytes the
//! probes read. Resolution is strict: any retype, resize, missing field,
//! overlap, or width drift refuses with a named cause instead of
//! installing a table that would misread memory.

use super::btf::Btf;
use super::session::SessionError;
use memveil_ebpf_common::{
    CopyOffsets, MV_COPY_OFFS_HAS_PRIVATE, MV_COPY_OFFS_LEN, MV_COPY_OFFS_MAGIC,
    MV_COPY_OFFS_VERSION, MV_FIXED_MAX, MV_OFF_TABLE_MAGIC, MV_OFF_TABLE_VERSION,
    MV_OFFSETS_TABLE_LEN,
};

/// Tracefs roots in libbpf's probe order: debugfs first, sys second.
const TRACEFS_DEBUG: &str = "/sys/kernel/debug/tracing";
/// Tracefs roots in libbpf's probe order: debugfs first, sys second.
const TRACEFS_SYS: &str = "/sys/kernel/tracing";

/// Format path under the tracefs root for the attempt event.
const ATTEMPT_FORMAT: &str = "events/swiotlb/swiotlb_bounced/format";

/// Cap on the format bytes read (1 MiB; the live file is under 1 KiB).
const MAX_FORMAT_BYTES: u64 = 1 << 20;

/// Kernel BTF path.
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

/// Cap on the BTF bytes read (64 MiB; the live file is about 7 MiB).
const MAX_BTF_BYTES: u64 = 64 << 20;

/// One discovered tracefs format field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TraceField {
    /// Field name.
    pub name: String,
    /// Type spelling.
    pub ftype: String,
    /// Byte offset in the trace record.
    pub offset: u32,
    /// Byte size in the trace record.
    pub size: u32,
}

/// One pinned program-read field: name, type spelling, offset, size.
struct FieldPin {
    name: &'static str,
    ftype: &'static str,
    offset: u32,
    size: u32,
}

/// Fields the attempt program reads, plus the `common_type` anchor.
/// Derived from the pinned tracepoint header plus natural alignment:
/// `dev_name` __data_loc u32 @8, padding to @16, dma_mask u64 @16, dev_addr
/// u64 @24, size u64 @32, force bool @40.
fn layout_pins() -> [FieldPin; 4] {
    [
        FieldPin {
            name: "common_type",
            ftype: "unsigned short",
            offset: 0,
            size: 2,
        },
        FieldPin {
            name: "dev_name",
            ftype: "__data_loc char[]",
            offset: 8,
            size: 4,
        },
        FieldPin {
            name: "size",
            ftype: "size_t",
            offset: 32,
            size: 8,
        },
        FieldPin {
            name: "force",
            ftype: "bool",
            offset: 40,
            size: 1,
        },
    ]
}

/// Decimal value, or `None` when empty, long, non-decimal, or overflowing
/// the pinned `i32` range.
fn parse_decimal(digits: &[u8]) -> Option<u32> {
    if digits.is_empty() || digits.len() > 10 {
        return None;
    }
    let mut value: u32 = 0;
    for byte in digits {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add(u32::from(byte - b'0'))?;
        if value > i32::MAX as u32 {
            return None;
        }
    }
    Some(value)
}

/// Strict-parse one `field:TYPE NAME;\toffset:O;\tsize:S;` line.
fn parse_format_field(line: &[u8]) -> Option<TraceField> {
    let mut parts = line.split(|byte| *byte == b'\t');
    let head = parts.next()?;
    let off = parts.next()?;
    let siz = parts.next()?;
    if !head.starts_with(b"field:") || head.last() != Some(&b';') {
        return None;
    }
    let inner = head.get(6..head.len() - 1)?;
    let cut = inner.iter().rposition(|byte| *byte == b' ')?;
    if cut == 0 || cut + 1 >= inner.len() {
        return None;
    }
    if !off.starts_with(b"offset:") || off.last() != Some(&b';') || off.len() <= 8 {
        return None;
    }
    if !siz.starts_with(b"size:") || siz.last() != Some(&b';') || siz.len() <= 6 {
        return None;
    }
    let offset = parse_decimal(off.get(7..off.len() - 1)?)?;
    let size = parse_decimal(siz.get(5..siz.len() - 1)?)?;
    let ftype = std::str::from_utf8(&inner[..cut]).ok()?;
    let name = std::str::from_utf8(&inner[cut + 1..]).ok()?;
    if ftype.is_empty() || name.is_empty() || ftype.contains('\0') || name.contains('\0') {
        return None;
    }
    Some(TraceField {
        name: name.to_owned(),
        ftype: ftype.to_owned(),
        offset,
        size,
    })
}

/// Strict-parse a tracefs event format into its field layout.
///
/// Non-field lines are skipped and leading blanks are tolerated (tracefs
/// indents field lines). Any unparseable field line, NUL byte in a field
/// name or type, or duplicate field name refuses: offsets derived from a
/// misread layout would read wrong bytes.
pub fn parse_trace_format(data: &[u8]) -> Result<Vec<TraceField>, SessionError> {
    let mut fields = Vec::new();
    for line in data.split(|byte| *byte == b'\n') {
        let start = line
            .iter()
            .position(|byte| *byte != b'\t' && *byte != b' ')
            .unwrap_or(line.len());
        if start >= line.len() {
            continue;
        }
        let body = &line[start..];
        if !body.starts_with(b"field:") {
            continue;
        }
        let Some(field) = parse_format_field(body) else {
            return Err(SessionError::Offsets("format line unparseable".to_owned()));
        };
        if fields
            .iter()
            .any(|seen: &TraceField| seen.name == field.name)
        {
            return Err(SessionError::Offsets(format!(
                "duplicate field {}",
                field.name
            )));
        }
        fields.push(field);
    }
    Ok(fields)
}

/// Bounds/overlap verdict for one offset table, else `Ok(())`.
///
/// Every tabled extent must sit inside the fixed-region cap, no two
/// extents (including the `common_type` anchor) may overlap, and the
/// dynamic floor must stay within the cap while covering every tabled
/// extent. The probe re-checks the same properties at runtime.
fn validate_table_extents(
    loc_off: u32,
    size_off: u32,
    force_off: u32,
    fixed_end: u32,
) -> Result<(), SessionError> {
    let overlaps = |a_off: u32, a_w: u32, b_off: u32, b_w: u32| {
        a_off < b_off.saturating_add(b_w) && b_off < a_off.saturating_add(a_w)
    };
    if loc_off.saturating_add(4) > MV_FIXED_MAX {
        return Err(SessionError::Offsets(format!(
            "field dev_name extent @{loc_off}:4 exceeds fixed cap {MV_FIXED_MAX}"
        )));
    }
    if size_off.saturating_add(8) > MV_FIXED_MAX {
        return Err(SessionError::Offsets(format!(
            "field size extent @{size_off}:8 exceeds fixed cap {MV_FIXED_MAX}"
        )));
    }
    if force_off.saturating_add(1) > MV_FIXED_MAX {
        return Err(SessionError::Offsets(format!(
            "field force extent @{force_off}:1 exceeds fixed cap {MV_FIXED_MAX}"
        )));
    }
    if overlaps(0, 2, loc_off, 4) {
        return Err(SessionError::Offsets(
            "overlapping extents common_type and dev_name".to_owned(),
        ));
    }
    if overlaps(0, 2, size_off, 8) {
        return Err(SessionError::Offsets(
            "overlapping extents common_type and size".to_owned(),
        ));
    }
    if overlaps(0, 2, force_off, 1) {
        return Err(SessionError::Offsets(
            "overlapping extents common_type and force".to_owned(),
        ));
    }
    if overlaps(loc_off, 4, size_off, 8) {
        return Err(SessionError::Offsets(
            "overlapping extents dev_name and size".to_owned(),
        ));
    }
    if overlaps(loc_off, 4, force_off, 1) {
        return Err(SessionError::Offsets(
            "overlapping extents dev_name and force".to_owned(),
        ));
    }
    if overlaps(size_off, 8, force_off, 1) {
        return Err(SessionError::Offsets(
            "overlapping extents size and force".to_owned(),
        ));
    }
    if fixed_end > MV_FIXED_MAX {
        return Err(SessionError::Offsets(format!(
            "fixed region end {fixed_end} exceeds cap {MV_FIXED_MAX}"
        )));
    }
    if fixed_end < loc_off.saturating_add(4) {
        return Err(SessionError::Offsets(format!(
            "fixed region end {fixed_end} below dev_name extent @{loc_off}:4"
        )));
    }
    if fixed_end < size_off.saturating_add(8) {
        return Err(SessionError::Offsets(format!(
            "fixed region end {fixed_end} below size extent @{size_off}:8"
        )));
    }
    if fixed_end < force_off.saturating_add(1) {
        return Err(SessionError::Offsets(format!(
            "fixed region end {fixed_end} below force extent @{force_off}:1"
        )));
    }
    Ok(())
}

/// One probed attempt table: the encoded 24 bytes plus whether the layout
/// drifted from the pinned one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttemptOffsets {
    /// Encoded table: magic, version, reserved, loc/size/force offsets,
    /// fixed end; 24 bytes, little-endian.
    pub table: [u8; MV_OFFSETS_TABLE_LEN],
    /// True when a probed offset differs from its pin.
    pub moved: bool,
}

/// Encode one attempt table: 24 bytes, little-endian.
fn encode_offsets_table(loc_off: u32, size_off: u32, force_off: u32, fixed_end: u32) -> [u8; 24] {
    let mut table = [0u8; 24];
    table[..4].copy_from_slice(&MV_OFF_TABLE_MAGIC.to_le_bytes());
    table[4..6].copy_from_slice(&MV_OFF_TABLE_VERSION.to_le_bytes());
    table[8..12].copy_from_slice(&loc_off.to_le_bytes());
    table[12..16].copy_from_slice(&size_off.to_le_bytes());
    table[16..20].copy_from_slice(&force_off.to_le_bytes());
    table[20..24].copy_from_slice(&fixed_end.to_le_bytes());
    table
}

/// Probe the live format into load-time table offsets.
///
/// The `common_type` anchor must match the pins exactly; `dev_name`,
/// `size`, and `force` keep their pinned type spellings and widths but
/// may sit at probed offsets; extra live fields are tolerated and the
/// dynamic floor is the max end over every parsed field, __data_loc
/// descriptors included. Any retype, resize, missing or duplicate field,
/// unparseable line, anchor drift, overlap, or cap breach refuses naming
/// its class.
pub fn probe_trace_offsets(data: &[u8]) -> Result<AttemptOffsets, SessionError> {
    let fields = parse_trace_format(data)?;
    let find = |want: &str| fields.iter().find(|field| field.name == want);
    let Some(anchor) = find("common_type") else {
        return Err(SessionError::Offsets(
            "missing field common_type".to_owned(),
        ));
    };
    if anchor.ftype != "unsigned short" {
        return Err(SessionError::Offsets(format!(
            "field common_type: want type unsigned short, live {}",
            anchor.ftype
        )));
    }
    if anchor.offset != 0 || anchor.size != 2 {
        return Err(SessionError::Offsets(format!(
            "field common_type: want @0:2, live @{}:{}",
            anchor.offset, anchor.size
        )));
    }
    let pins = layout_pins();
    let mut offs = [0u32; 4];
    for (slot, pin) in pins.iter().enumerate().skip(1) {
        let Some(got) = find(pin.name) else {
            return Err(SessionError::Offsets(format!("missing field {}", pin.name)));
        };
        if got.ftype != pin.ftype {
            return Err(SessionError::Offsets(format!(
                "field {}: want type {}, live {}",
                pin.name, pin.ftype, got.ftype
            )));
        }
        if got.size != pin.size {
            return Err(SessionError::Offsets(format!(
                "field {}: want size {}, live size {}",
                pin.name, pin.size, got.size
            )));
        }
        offs[slot] = got.offset;
    }
    let moved = offs[1] != pins[1].offset || offs[2] != pins[2].offset || offs[3] != pins[3].offset;
    // Every declared field occupies its fixed slot, including __data_loc
    // descriptors: each is a fixed u32 holding an offset/length pair, not
    // dynamic data itself.
    let mut fixed_end = 0u32;
    for field in &fields {
        fixed_end = fixed_end.max(field.offset.saturating_add(field.size));
    }
    validate_table_extents(offs[1], offs[2], offs[3], fixed_end)?;
    Ok(AttemptOffsets {
        table: encode_offsets_table(offs[1], offs[2], offs[3], fixed_end),
        moved,
    })
}

/// Read a capped file, refusing oversized input.
fn read_capped(path: &str, cap: u64, what: &str) -> Result<Vec<u8>, SessionError> {
    use std::io::Read;
    let file = std::fs::File::open(path)
        .map_err(|error| SessionError::Offsets(format!("cannot read {what} at {path}: {error}")))?;
    let mut take = file.take(cap + 1);
    let mut bytes = Vec::new();
    take.read_to_end(&mut bytes)
        .map_err(|error| SessionError::Offsets(format!("cannot read {what} at {path}: {error}")))?;
    if bytes.len() as u64 > cap {
        return Err(SessionError::Offsets(format!(
            "{what} at {path} exceeds {cap} bytes"
        )));
    }
    Ok(bytes)
}

/// Resolve the attempt table from the live tracefs format, probing the
/// debugfs tree first and the sys tree second.
pub fn resolve_attempt_offsets() -> Result<AttemptOffsets, SessionError> {
    let mut errors = Vec::new();
    for root in [TRACEFS_DEBUG, TRACEFS_SYS] {
        let path = format!("{root}/{ATTEMPT_FORMAT}");
        match read_capped(&path, MAX_FORMAT_BYTES, "tracefs format") {
            Ok(bytes) => return probe_trace_offsets(&bytes),
            Err(error) => errors.push(error.to_string()),
        }
    }
    Err(SessionError::Offsets(format!(
        "no readable tracefs format ({}): {}",
        ATTEMPT_FORMAT,
        errors.join("; ")
    )))
}

/// Resolve one struct member with its required width, refusing drift.
fn need_member(
    btf: &Btf<'_>,
    owner: &str,
    owner_size: u32,
    member: &str,
    width: u32,
) -> Result<u32, SessionError> {
    let (off, size) = btf.struct_member(owner, member)?;
    if size != width {
        return Err(SessionError::Offsets(format!(
            "BTF refused: {owner}.{member} width {size}, want {width}"
        )));
    }
    if off.saturating_add(size) > owner_size {
        return Err(SessionError::Offsets(format!(
            "BTF refused: {owner}.{member} extent @{off}:{size} escapes {owner} ({owner_size} bytes)"
        )));
    }
    Ok(off)
}

/// Resolve one pointer member with its required pointee struct.
fn need_pointer(
    btf: &Btf<'_>,
    owner: &str,
    owner_size: u32,
    member: &str,
    pointee: &str,
) -> Result<u32, SessionError> {
    let off = need_member(btf, owner, owner_size, member, 8)?;
    let got = btf.member_points_to(owner, member)?;
    if got != pointee {
        return Err(SessionError::Offsets(format!(
            "BTF refused: {owner}.{member} points at {got}, want {pointee}"
        )));
    }
    Ok(off)
}

/// Resolve the copy table from raw kernel-BTF bytes: the 8 pool/slot/parms
/// widths, the slot stride, the private-pool chain, and the direction
/// enumerators. A private-pool chain with both halves absent, or with
/// exactly one half present, downgrades to a flag-clear table (the
/// probe then leaves the private marker clear): privacy is a marker
/// the probes set only when fully provable, and ordinary kernels
/// carry the mem half without `cc_shared`. Only a present-but-wrong
/// half (bitfield, misalignment, oversize, corrupt image) refuses.
pub fn resolve_copy_offsets_from_btf(data: &[u8]) -> Result<CopyOffsets, SessionError> {
    let btf = Btf::parse(data)?;
    let pool_size = btf.struct_size("io_tlb_pool")?;
    let pool_start_off = need_member(&btf, "io_tlb_pool", pool_size, "start", 8)?;
    let pool_end_off = need_member(&btf, "io_tlb_pool", pool_size, "end", 8)?;
    let pool_nslabs_off = need_member(&btf, "io_tlb_pool", pool_size, "nslabs", 8)?;
    let pool_slots_off = need_pointer(&btf, "io_tlb_pool", pool_size, "slots", "io_tlb_slot")?;
    let slot_size = btf.struct_size("io_tlb_slot")?;
    if slot_size == 0 {
        return Err(SessionError::Offsets(
            "BTF refused: io_tlb_slot has zero size".to_owned(),
        ));
    }
    let slot_orig_off = need_member(&btf, "io_tlb_slot", slot_size, "orig_addr", 8)?;
    let slot_alloc_off = need_member(&btf, "io_tlb_slot", slot_size, "alloc_size", 8)?;
    let device_size = btf.struct_size("device")?;
    let dev_parms_off = need_pointer(
        &btf,
        "device",
        device_size,
        "dma_parms",
        "device_dma_parameters",
    )?;
    let parms_size = btf.struct_size("device_dma_parameters")?;
    let mask_off = need_member(
        &btf,
        "device_dma_parameters",
        parms_size,
        "min_align_mask",
        4,
    )?;
    // Private-pool chain: both halves present and well-formed (flag
    // set), else flag clear. The optional lookup separates absence
    // (`None`) from present-but-malformed (bitfield, misalignment,
    // oversize, corrupt image), which refuses through `?`; a
    // half-present chain downgrades like a fully absent one (the
    // present half alone proves nothing about pool privacy, and
    // ordinary kernels carry exactly the mem half).
    let mem = match btf.struct_member_opt("device", "dma_io_tlb_mem")? {
        Some((off, 8)) => {
            let pointee = btf.member_points_to("device", "dma_io_tlb_mem")?;
            if pointee.as_str() != "io_tlb_mem" {
                let message = format!(
                    "BTF refused: device.dma_io_tlb_mem points at {pointee}, want io_tlb_mem"
                );
                return Err(SessionError::Offsets(message));
            }
            if off.saturating_add(8) > device_size {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: device.dma_io_tlb_mem extent @{off}:8 escapes device"
                )));
            }
            Some(off)
        }
        Some((_, size)) => {
            return Err(SessionError::Offsets(format!(
                "BTF refused: device.dma_io_tlb_mem width {size}, want 8"
            )));
        }
        None => None,
    };
    let cc = match btf.struct_member_opt("io_tlb_mem", "cc_shared")? {
        Some((off, 1)) => {
            let mem_size = btf.struct_size("io_tlb_mem")?;
            if off.saturating_add(1) > mem_size {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: io_tlb_mem.cc_shared extent @{off}:1 escapes io_tlb_mem"
                )));
            }
            Some(off)
        }
        Some((_, size)) => {
            return Err(SessionError::Offsets(format!(
                "BTF refused: io_tlb_mem.cc_shared width {size}, want 1"
            )));
        }
        None => None,
    };
    let (flags, mem_off, mem_size, cc_off, cc_size) = match (mem, cc) {
        (Some(mem_off), Some(cc_off)) => (MV_COPY_OFFS_HAS_PRIVATE, mem_off, 8, cc_off, 1),
        // Absent or half-present: the marker is unprovable, so the
        // table leaves it clear and the probe never sets it.
        _ => (0, 0, 0, 0, 0),
    };
    let dir_to = btf.enum_value("dma_data_direction", "DMA_TO_DEVICE")?;
    let dir_from = btf.enum_value("dma_data_direction", "DMA_FROM_DEVICE")?;
    let dir_bidi = btf.enum_value("dma_data_direction", "DMA_BIDIRECTIONAL")?;
    if dir_to == dir_from || dir_to == dir_bidi || dir_from == dir_bidi {
        return Err(SessionError::Offsets(
            "BTF refused: dma_data_direction enumerators are not distinct".to_owned(),
        ));
    }
    let table = CopyOffsets {
        magic: MV_COPY_OFFS_MAGIC,
        version: MV_COPY_OFFS_VERSION,
        flags,
        pool_start_off,
        pool_start_size: 8,
        pool_end_off,
        pool_end_size: 8,
        pool_nslabs_off,
        pool_nslabs_size: 8,
        pool_slots_off,
        pool_slots_size: 8,
        slot_orig_off,
        slot_orig_size: 8,
        slot_alloc_off,
        slot_alloc_size: 8,
        dev_parms_off,
        dev_parms_size: 8,
        mask_off,
        mask_size: 4,
        slot_size,
        reserved0: 0,
        mem_off,
        mem_size,
        cc_off,
        cc_size,
        dir_to,
        dir_from,
        dir_bidi,
        reserved1: 0,
    };
    validate_copy_offsets(&table)?;
    Ok(table)
}

/// Resolve the copy table from the live kernel BTF.
pub fn resolve_copy_offsets() -> Result<CopyOffsets, SessionError> {
    let bytes = read_capped(KERNEL_BTF, MAX_BTF_BYTES, "kernel BTF")?;
    resolve_copy_offsets_from_btf(&bytes)
}

/// Frozen `enum dma_data_direction` encodings the Aya lifecycle probe
/// trusts (`rust/crates/ebpf/src/lifecycle.rs`, matching upstream
/// `dma-direction.h`): bidirectional 0, to-device 1, from-device 2.
/// The host verifies live kernel BTF against these before lifecycle
/// load and refuses on any drift, so a renumbered kernel fails loudly
/// instead of silently inverting directions.
pub const EXPECTED_DMA_BIDIRECTIONAL: u32 = 0;
/// Frozen to-device encoding trusted by the Aya lifecycle probe.
pub const EXPECTED_DMA_TO_DEVICE: u32 = 1;
/// Frozen from-device encoding trusted by the Aya lifecycle probe.
pub const EXPECTED_DMA_FROM_DEVICE: u32 = 2;

/// Resolve the three `dma_data_direction` enumerators from raw
/// kernel-BTF bytes, in (to, from, bidirectional) order.
pub fn lifecycle_dirs_from_btf(data: &[u8]) -> Result<(u32, u32, u32), SessionError> {
    let btf = Btf::parse(data)?;
    let to = btf.enum_value("dma_data_direction", "DMA_TO_DEVICE")?;
    let from = btf.enum_value("dma_data_direction", "DMA_FROM_DEVICE")?;
    let bidi = btf.enum_value("dma_data_direction", "DMA_BIDIRECTIONAL")?;
    Ok((to, from, bidi))
}

/// Verify the live kernel BTF carries the frozen direction encodings
/// before the lifecycle probe loads.
pub fn verify_lifecycle_dirs() -> Result<(), SessionError> {
    let bytes = read_capped(KERNEL_BTF, MAX_BTF_BYTES, "kernel BTF")?;
    verify_lifecycle_dirs_from_btf(&bytes)
}

/// Byte-slice form of [`verify_lifecycle_dirs`] for fixtures: every
/// drifted enumerator is named in the refusal.
pub fn verify_lifecycle_dirs_from_btf(data: &[u8]) -> Result<(), SessionError> {
    let (to, from, bidi) = lifecycle_dirs_from_btf(data)?;
    let mut drift = Vec::new();
    if to != EXPECTED_DMA_TO_DEVICE {
        drift.push(format!(
            "DMA_TO_DEVICE is {to}, want {EXPECTED_DMA_TO_DEVICE}"
        ));
    }
    if from != EXPECTED_DMA_FROM_DEVICE {
        drift.push(format!(
            "DMA_FROM_DEVICE is {from}, want {EXPECTED_DMA_FROM_DEVICE}"
        ));
    }
    if bidi != EXPECTED_DMA_BIDIRECTIONAL {
        drift.push(format!(
            "DMA_BIDIRECTIONAL is {bidi}, want {EXPECTED_DMA_BIDIRECTIONAL}"
        ));
    }
    if drift.is_empty() {
        Ok(())
    } else {
        Err(SessionError::Offsets(format!(
            "BTF refused: dma_data_direction drift ({})",
            drift.join("; ")
        )))
    }
}

/// Installer-side strict check: the table the probe would trust and run
/// on, with no surprises. Stricter than the probe in one place: a set
/// private flag requires well-formed private widths (the probe would
/// silently ignore a malformed private half), and a clear flag requires
/// zeroed private fields.
pub fn validate_copy_offsets(table: &CopyOffsets) -> Result<(), SessionError> {
    let refuse = |why: &str| SessionError::Offsets(format!("bad copy offsets table: {why}"));
    if table.magic != MV_COPY_OFFS_MAGIC {
        return Err(refuse("bad magic"));
    }
    if table.version != MV_COPY_OFFS_VERSION {
        return Err(refuse("bad version"));
    }
    if table.flags & !MV_COPY_OFFS_HAS_PRIVATE != 0 {
        return Err(refuse("bad flags"));
    }
    if table.reserved0 != 0 || table.reserved1 != 0 {
        return Err(refuse("reserved nonzero"));
    }
    for (what, got, want) in [
        ("pool_start_size", table.pool_start_size, 8),
        ("pool_end_size", table.pool_end_size, 8),
        ("pool_nslabs_size", table.pool_nslabs_size, 8),
        ("pool_slots_size", table.pool_slots_size, 8),
        ("slot_orig_size", table.slot_orig_size, 8),
        ("slot_alloc_size", table.slot_alloc_size, 8),
        ("dev_parms_size", table.dev_parms_size, 8),
        ("mask_size", table.mask_size, 4),
    ] {
        if got != want {
            return Err(refuse(&format!("{what} is {got}, want {want}")));
        }
    }
    if table.slot_size == 0 {
        return Err(refuse("zero slot stride"));
    }
    if table.slot_orig_off.saturating_add(8) > table.slot_size
        || table.slot_alloc_off.saturating_add(8) > table.slot_size
    {
        return Err(refuse("slot extent escapes the stride"));
    }
    if table.dir_to == table.dir_from
        || table.dir_to == table.dir_bidi
        || table.dir_from == table.dir_bidi
    {
        return Err(refuse("direction enumerators are not distinct"));
    }
    if table.flags & MV_COPY_OFFS_HAS_PRIVATE != 0 {
        if table.mem_size != 8 || table.cc_size != 1 {
            return Err(refuse("private flag with malformed private widths"));
        }
    } else if table.mem_off != 0 || table.mem_size != 0 || table.cc_off != 0 || table.cc_size != 0 {
        return Err(refuse("clear private flag with nonzero private fields"));
    }
    Ok(())
}

/// Encode the table to its 112 wire bytes, little-endian, field by field.
pub fn encode_copy_offsets(table: &CopyOffsets) -> [u8; MV_COPY_OFFS_LEN] {
    let mut out = [0u8; MV_COPY_OFFS_LEN];
    out[0..4].copy_from_slice(&table.magic.to_le_bytes());
    out[4..6].copy_from_slice(&table.version.to_le_bytes());
    out[6..8].copy_from_slice(&table.flags.to_le_bytes());
    let mut at = 8;
    for value in [
        table.pool_start_off,
        table.pool_start_size,
        table.pool_end_off,
        table.pool_end_size,
        table.pool_nslabs_off,
        table.pool_nslabs_size,
        table.pool_slots_off,
        table.pool_slots_size,
        table.slot_orig_off,
        table.slot_orig_size,
        table.slot_alloc_off,
        table.slot_alloc_size,
        table.dev_parms_off,
        table.dev_parms_size,
        table.mask_off,
        table.mask_size,
        table.slot_size,
        table.reserved0,
        table.mem_off,
        table.mem_size,
        table.cc_off,
        table.cc_size,
        table.dir_to,
        table.dir_from,
        table.dir_bidi,
        table.reserved1,
    ] {
        out[at..at + 4].copy_from_slice(&value.to_le_bytes());
        at += 4;
    }
    debug_assert_eq!(at, MV_COPY_OFFS_LEN);
    out
}

/// All-zero table for the BTF-unavailable seat: the probe trusts magic plus
/// version only, so this install refuses every firing with `BYTE_COVERAGE`
/// instead of running on guessed offsets. The installer itself rejects it;
/// install it only through a raw write when live resolution is impossible,
/// and escalate the gap.
pub fn sentinel_copy_offsets() -> CopyOffsets {
    CopyOffsets {
        magic: 0,
        version: 0,
        flags: 0,
        pool_start_off: 0,
        pool_start_size: 0,
        pool_end_off: 0,
        pool_end_size: 0,
        pool_nslabs_off: 0,
        pool_nslabs_size: 0,
        pool_slots_off: 0,
        pool_slots_size: 0,
        slot_orig_off: 0,
        slot_orig_size: 0,
        slot_alloc_off: 0,
        slot_alloc_size: 0,
        dev_parms_off: 0,
        dev_parms_size: 0,
        mask_off: 0,
        mask_size: 0,
        slot_size: 0,
        reserved0: 0,
        mem_off: 0,
        mem_size: 0,
        cc_off: 0,
        cc_size: 0,
        dir_to: 0,
        dir_from: 0,
        dir_bidi: 0,
        reserved1: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pinned-format bytes mirroring the live `swiotlb_bounced` layout.
    fn pinned_format() -> Vec<u8> {
        b"name: swiotlb_bounced\nID: 403\nformat:\n\
          \tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
          \tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n\
          \tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n\
          \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n\
          \n\
          \tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n\
          \tfield:u64 dma_mask;\toffset:16;\tsize:8;\tsigned:0;\n\
          \tfield:dma_addr_t dev_addr;\toffset:24;\tsize:8;\tsigned:0;\n\
          \tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n\
          \tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n"
            .to_vec()
    }

    #[test]
    fn pinned_format_probes_unmoved() {
        let probed = probe_trace_offsets(&pinned_format()).expect("pinned must probe");
        assert!(!probed.moved);
        let table =
            memveil_ebpf_common::decode_offsets_table(&probed.table).expect("table must decode");
        assert_eq!(
            (
                table.loc_off,
                table.size_off,
                table.force_off,
                table.fixed_end
            ),
            (8, 32, 40, 41)
        );
    }

    /// Pinned format with one textual substitution applied.
    fn substituted(from: &str, to: &str) -> Vec<u8> {
        String::from_utf8(pinned_format())
            .expect("pinned format is ASCII")
            .replace(from, to)
            .into_bytes()
    }

    #[test]
    fn drifted_offsets_probe_moved() {
        let format = substituted("size;\toffset:32;", "size;\toffset:48;");
        let probed = probe_trace_offsets(&format).expect("drifted must probe");
        assert!(probed.moved);
        let table = memveil_ebpf_common::decode_offsets_table(&probed.table).expect("decode");
        assert_eq!(table.size_off, 48);
        assert_eq!(table.fixed_end, 56);
    }

    #[test]
    fn retype_resize_missing_and_anchor_refused() {
        // Retyped size.
        let format = substituted("field:size_t size;", "field:u32 size;");
        assert!(probe_trace_offsets(&format).is_err());
        // Resized force.
        let format = substituted("force;\toffset:40;\tsize:1;", "force;\toffset:40;\tsize:2;");
        assert!(probe_trace_offsets(&format).is_err());
        // Missing dev_name.
        let format: Vec<u8> = String::from_utf8(pinned_format())
            .expect("pinned format is ASCII")
            .lines()
            .filter(|line| !line.contains("dev_name"))
            .flat_map(|line| line.bytes().chain(*b"\n"))
            .collect();
        assert!(probe_trace_offsets(&format).is_err());
        // Anchor drift.
        let format = substituted("common_type;\toffset:0;", "common_type;\toffset:2;");
        let error = probe_trace_offsets(&format).expect_err("anchor drift must refuse");
        assert!(error.to_string().contains("common_type"));
        // Unparseable field line.
        let mut format = pinned_format();
        format.extend_from_slice(b"\tfield:bogus\n");
        assert!(probe_trace_offsets(&format).is_err());
    }

    #[test]
    fn overlap_and_cap_breach_refused() {
        // size @10 overlaps dev_name @8:4.
        let format = substituted("size;\toffset:32;", "size;\toffset:10;");
        let error = probe_trace_offsets(&format).expect_err("overlap must refuse");
        assert!(error.to_string().contains("overlapping"));
        // A giant extra field pushes the floor past the cap.
        let mut format = pinned_format();
        format.extend_from_slice(b"\tfield:char giant[200];\toffset:128;\tsize:200;\tsigned:0;\n");
        let error = probe_trace_offsets(&format).expect_err("cap breach must refuse");
        assert!(error.to_string().contains("cap"));
    }

    /// A well-formed table for validator tests.
    fn good_table() -> CopyOffsets {
        let mut table = sentinel_copy_offsets();
        table.magic = MV_COPY_OFFS_MAGIC;
        table.version = MV_COPY_OFFS_VERSION;
        table.pool_start_size = 8;
        table.pool_end_size = 8;
        table.pool_nslabs_size = 8;
        table.pool_slots_size = 8;
        table.slot_orig_size = 8;
        table.slot_alloc_size = 8;
        table.dev_parms_size = 8;
        table.mask_size = 4;
        table.slot_orig_off = 0;
        table.slot_alloc_off = 8;
        table.slot_size = 24;
        table.dir_to = 1;
        table.dir_from = 2;
        table.dir_bidi = 0;
        table
    }

    #[test]
    fn validator_accepts_good_and_private() {
        validate_copy_offsets(&good_table()).expect("good must validate");
        let mut private = good_table();
        private.flags = MV_COPY_OFFS_HAS_PRIVATE;
        private.mem_size = 8;
        private.cc_size = 1;
        validate_copy_offsets(&private).expect("private must validate");
    }

    #[test]
    fn validator_refuses_garbage() {
        assert!(validate_copy_offsets(&sentinel_copy_offsets()).is_err());
        let mut bad = good_table();
        bad.version = 2;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.flags = 0xFFFF;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.mask_size = 8;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.slot_size = 8;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.dir_from = 1;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.flags = MV_COPY_OFFS_HAS_PRIVATE;
        assert!(validate_copy_offsets(&bad).is_err());
        let mut bad = good_table();
        bad.mem_size = 8;
        assert!(validate_copy_offsets(&bad).is_err());
    }

    #[test]
    fn encode_layout_matches_spec() {
        let table = good_table();
        let bytes = encode_copy_offsets(&table);
        assert_eq!(bytes.len(), MV_COPY_OFFS_LEN);
        assert_eq!(&bytes[..4], &MV_COPY_OFFS_MAGIC.to_le_bytes());
        assert_eq!(
            u16::from_le_bytes([bytes[4], bytes[5]]),
            MV_COPY_OFFS_VERSION
        );
        assert_eq!(
            u32::from_le_bytes([bytes[68], bytes[69], bytes[70], bytes[71]]),
            4
        );
        assert_eq!(
            u32::from_le_bytes([bytes[72], bytes[73], bytes[74], bytes[75]]),
            24
        );
        assert_eq!(
            u32::from_le_bytes([bytes[96], bytes[97], bytes[98], bytes[99]]),
            1
        );
    }

    /// Shape of the private-pool halves in the synthetic copy image.
    struct PrivateShape {
        /// Include `device.dma_io_tlb_mem` (pointer at `io_tlb_mem`).
        with_mem: bool,
        /// Point `io_tlb_pool.slots` at a decoy struct
        /// (pointee-mismatch negative; orthogonal to the private
        /// halves).
        slots_wrong_pointee: bool,
        /// Emit `device.dma_io_tlb_mem` at a non-byte-aligned bit offset.
        mem_misaligned: bool,
        /// Include the `io_tlb_mem` struct at all.
        with_mem_struct: bool,
        /// Include `io_tlb_mem.cc_shared`.
        with_cc: bool,
        /// Emit `io_tlb_mem.cc_shared` as a bitfield.
        cc_bitfield: bool,
        /// Emit `io_tlb_mem.cc_shared` with a gigantic array type whose
        /// width overflows `u32`.
        cc_oversize: bool,
    }

    impl PrivateShape {
        /// Both halves present and well-formed.
        fn full() -> Self {
            Self {
                with_mem: true,
                slots_wrong_pointee: false,
                mem_misaligned: false,
                with_mem_struct: true,
                with_cc: true,
                cc_bitfield: false,
                cc_oversize: false,
            }
        }

        /// Both halves absent; the structs stay.
        fn absent() -> Self {
            Self {
                with_mem: false,
                slots_wrong_pointee: false,
                mem_misaligned: false,
                with_mem_struct: true,
                with_cc: false,
                cc_bitfield: false,
                cc_oversize: false,
            }
        }
    }

    /// Build a synthetic kernel-BTF image carrying the six copy types
    /// (`io_tlb_pool`, `io_tlb_slot`, `device`, `device_dma_parameters`,
    /// `io_tlb_mem`, `dma_data_direction`) with the shaped private halves.
    /// Layouts mirror the live kernel (pool 0/8/24/56, slot stride 24,
    /// mask @4, directions 1/2/0).
    fn copy_btf_image(shape: &PrivateShape) -> Vec<u8> {
        copy_btf_image_with_dirs(shape, 1, 2, 0)
    }

    /// [`copy_btf_image`] with explicit direction enumerator values, for
    /// swapped-enum negatives.
    fn copy_btf_image_with_dirs(shape: &PrivateShape, to: u32, from: u32, bidi: u32) -> Vec<u8> {
        // BTF type-kind numbers (mirroring the loader's reader).
        const KIND_INT: u8 = 1;
        const KIND_PTR: u8 = 2;
        const KIND_ARRAY: u8 = 3;
        const KIND_STRUCT: u8 = 4;
        const KIND_ENUM: u8 = 6;

        let mut strings = vec![0u8];
        let mut intern = |text: &str| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let pool = intern("io_tlb_pool");
        let slot = intern("io_tlb_slot");
        let device = intern("device");
        let parms = intern("device_dma_parameters");
        let mem = intern("io_tlb_mem");
        let dir = intern("dma_data_direction");
        let start = intern("start");
        let end = intern("end");
        let nslabs = intern("nslabs");
        let slots = intern("slots");
        let orig = intern("orig_addr");
        let alloc = intern("alloc_size");
        let dma_parms = intern("dma_parms");
        let dma_mem = intern("dma_io_tlb_mem");
        let mask = intern("min_align_mask");
        let cc = intern("cc_shared");
        let to_name = intern("DMA_TO_DEVICE");
        let from_name = intern("DMA_FROM_DEVICE");
        let bidi_name = intern("DMA_BIDIRECTIONAL");
        let u64_name = intern("u64");
        let u32_name = intern("u32");
        let u8_name = intern("u8");
        let decoy_name = intern("wrong_slot");

        let mut types = Vec::new();
        let mut next_id = 0u32;
        let mut record =
            |name: u32, kind: u8, kind_flag: bool, vlen: u16, size: u32, payload: &[u8]| -> u32 {
                next_id += 1;
                types.extend_from_slice(&name.to_le_bytes());
                let mut info = u32::from(kind) << 24 | u32::from(vlen);
                if kind_flag {
                    info |= 1 << 31;
                }
                types.extend_from_slice(&info.to_le_bytes());
                types.extend_from_slice(&size.to_le_bytes());
                types.extend_from_slice(payload);
                next_id
            };
        let members = |fields: &[(u32, u32, u32)]| -> Vec<u8> {
            let mut out = Vec::new();
            for (name, ty, off) in fields {
                out.extend_from_slice(&name.to_le_bytes());
                out.extend_from_slice(&ty.to_le_bytes());
                out.extend_from_slice(&off.to_le_bytes());
            }
            out
        };

        let u64_id = record(u64_name, KIND_INT, false, 0, 8, &1u32.to_le_bytes());
        let u32_id = record(u32_name, KIND_INT, false, 0, 4, &1u32.to_le_bytes());
        let u8_id = record(u8_name, KIND_INT, false, 0, 1, &1u32.to_le_bytes());
        // Oversize decoy: u64 x u32::MAX bytes overflows u32 widths.
        let mut array_payload = Vec::new();
        array_payload.extend_from_slice(&u64_id.to_le_bytes());
        array_payload.extend_from_slice(&u32_id.to_le_bytes());
        array_payload.extend_from_slice(&u32::MAX.to_le_bytes());
        let big_id = record(0, KIND_ARRAY, false, 0, 0, &array_payload);
        let slot_id = record(
            slot,
            KIND_STRUCT,
            false,
            2,
            24,
            &members(&[(orig, u64_id, 0), (alloc, u64_id, 64)]),
        );
        let slot_ptr = record(0, KIND_PTR, false, 0, slot_id, &[]);
        // Decoy pointee for the mismatch negative: same member
        // widths as the slot, so kind/width checks pass while the
        // pointee check refuses.
        let decoy_id = record(
            decoy_name,
            KIND_STRUCT,
            false,
            2,
            24,
            &members(&[(orig, u64_id, 0), (alloc, u64_id, 64)]),
        );
        let decoy_ptr = record(0, KIND_PTR, false, 0, decoy_id, &[]);
        let slots_ptr = if shape.slots_wrong_pointee {
            decoy_ptr
        } else {
            slot_ptr
        };
        record(
            pool,
            KIND_STRUCT,
            false,
            4,
            64,
            &members(&[
                (start, u64_id, 0),
                (end, u64_id, 64),
                (nslabs, u64_id, 192),
                (slots, slots_ptr, 448),
            ]),
        );
        let parms_id = record(
            parms,
            KIND_STRUCT,
            false,
            1,
            8,
            &members(&[(mask, u32_id, 32)]),
        );
        let parms_ptr = record(0, KIND_PTR, false, 0, parms_id, &[]);
        // A present member needs its struct; the tests never shape it
        // otherwise.
        assert!(!shape.with_mem || shape.with_mem_struct);
        assert!(!shape.with_cc || shape.with_mem_struct);
        let mem_ptr = if shape.with_mem_struct {
            let cc_type = if shape.cc_oversize { big_id } else { u8_id };
            let cc_off = if shape.cc_bitfield { 1 << 24 } else { 0 };
            let cc_fields: Vec<(u32, u32, u32)> = if shape.with_cc {
                vec![(cc, cc_type, cc_off)]
            } else {
                Vec::new()
            };
            let mem_id = record(
                mem,
                KIND_STRUCT,
                shape.cc_bitfield,
                cc_fields.len() as u16,
                8,
                &members(&cc_fields),
            );
            record(0, KIND_PTR, false, 0, mem_id, &[])
        } else {
            0
        };
        let mut device_fields = vec![(dma_parms, parms_ptr, 0)];
        if shape.with_mem {
            let mem_off = if shape.mem_misaligned { 68 } else { 64 };
            device_fields.push((dma_mem, mem_ptr, mem_off));
        }
        record(
            device,
            KIND_STRUCT,
            false,
            device_fields.len() as u16,
            16,
            &members(&device_fields),
        );
        let mut values = Vec::new();
        for (name, value) in [(to_name, to), (from_name, from), (bidi_name, bidi)] {
            values.extend_from_slice(&name.to_le_bytes());
            values.extend_from_slice(&value.to_le_bytes());
        }
        record(dir, KIND_ENUM, false, 3, 4, &values);

        let mut out = Vec::new();
        out.extend_from_slice(&0xEB9Fu16.to_le_bytes());
        out.push(1);
        out.push(0);
        out.extend_from_slice(&24u32.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(types.len() as u32).to_le_bytes());
        out.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        out.extend_from_slice(&types);
        out.extend_from_slice(&strings);
        out
    }

    #[test]
    fn private_chain_full_present_sets_flag() {
        let table = resolve_copy_offsets_from_btf(&copy_btf_image(&PrivateShape::full()))
            .expect("full chain must resolve");
        assert_ne!(table.flags & MV_COPY_OFFS_HAS_PRIVATE, 0);
        assert_eq!((table.mem_off, table.mem_size), (8, 8));
        assert_eq!((table.cc_off, table.cc_size), (0, 1));
        assert_eq!(
            (
                table.pool_start_off,
                table.pool_end_off,
                table.pool_nslabs_off,
                table.pool_slots_off
            ),
            (0, 8, 24, 56)
        );
        assert_eq!((table.dir_to, table.dir_from, table.dir_bidi), (1, 2, 0));
    }

    #[test]
    fn private_chain_fully_absent_downgrades() {
        // Both halves missing downgrades whether the `io_tlb_mem` struct
        // itself is present or not.
        for with_mem_struct in [true, false] {
            let shape = PrivateShape {
                with_mem_struct,
                ..PrivateShape::absent()
            };
            let table = resolve_copy_offsets_from_btf(&copy_btf_image(&shape))
                .expect("absent chain must downgrade");
            assert_eq!(table.flags & MV_COPY_OFFS_HAS_PRIVATE, 0);
            assert_eq!(
                (table.mem_off, table.mem_size, table.cc_off, table.cc_size),
                (0, 0, 0, 0)
            );
        }
    }

    /// The refusal message of a copy resolution that must fail.
    /// (`CopyOffsets` has no `Debug`, so `expect_err` is unavailable.)
    fn expect_refusal(image: &[u8], what: &str) -> String {
        match resolve_copy_offsets_from_btf(image) {
            Ok(_) => panic!("{what} must refuse"),
            Err(error) => error.to_string(),
        }
    }

    #[test]
    fn private_chain_half_present_downgrades() {
        // One half present (the mem-only shape is what ordinary
        // kernels carry) downgrades to flag-clear like a fully
        // absent chain: the present half alone proves nothing
        // about pool privacy, and the probe leaves the marker
        // clear. Present-but-malformed halves still refuse (see
        // the malformed test below).
        for shape in [
            PrivateShape {
                with_cc: false,
                ..PrivateShape::full()
            },
            PrivateShape {
                with_mem: false,
                with_cc: true,
                ..PrivateShape::absent()
            },
        ] {
            let table = resolve_copy_offsets_from_btf(&copy_btf_image(&shape))
                .expect("half-present chain must downgrade");
            assert_eq!(table.flags & MV_COPY_OFFS_HAS_PRIVATE, 0);
            assert_eq!(
                (table.mem_off, table.mem_size, table.cc_off, table.cc_size),
                (0, 0, 0, 0)
            );
        }
    }

    #[test]
    fn slots_pointee_mismatch_refuses() {
        // The slots member keeps pointer kind and width but points
        // at the wrong struct: a kind/width check would pass, the
        // pointee check refuses naming both sides. Record's install
        // refuses here; doctor's preflight shares this resolver.
        let shape = PrivateShape {
            slots_wrong_pointee: true,
            ..PrivateShape::full()
        };
        let message = expect_refusal(&copy_btf_image(&shape), "pointee mismatch");
        assert!(
            message.contains("io_tlb_pool.slots points at wrong_slot"),
            "want the pointee refusal, got: {message}"
        );
        assert!(
            message.contains("want io_tlb_slot"),
            "want the expected pointee, got: {message}"
        );
    }

    #[test]
    fn private_chain_malformed_refuses() {
        // Bitfield cc_shared: present but unreadable as a whole byte.
        let shape = PrivateShape {
            cc_bitfield: true,
            ..PrivateShape::full()
        };
        let message = expect_refusal(&copy_btf_image(&shape), "bitfield half");
        assert!(
            message.contains("bitfield"),
            "want the bitfield refusal, got: {message}"
        );
        // Misaligned dma_io_tlb_mem: bit offset 68 is not byte-aligned.
        let shape = PrivateShape {
            mem_misaligned: true,
            ..PrivateShape::full()
        };
        let message = expect_refusal(&copy_btf_image(&shape), "misaligned half");
        assert!(
            message.contains("byte-aligned"),
            "want the misalignment refusal, got: {message}"
        );
        // Oversize cc_shared: the array width overflows u32.
        let shape = PrivateShape {
            cc_oversize: true,
            ..PrivateShape::full()
        };
        let message = expect_refusal(&copy_btf_image(&shape), "oversize half");
        assert!(
            message.contains("too large"),
            "want the oversize refusal, got: {message}"
        );
    }

    #[test]
    fn lifecycle_dirs_verify_normal_values() {
        // The live shape (1/2/0) verifies: the check is quiet on
        // every real kernel.
        verify_lifecycle_dirs_from_btf(&copy_btf_image(&PrivateShape::full()))
            .expect("normal 1/2/0 directions must verify");
    }

    #[test]
    fn lifecycle_dirs_swapped_enum_refuses() {
        // Swapped TO/FROM: the resolver still reads both values
        // (this is what the frozen probe would have trusted, and
        // the copy table accepts them since it installs rather
        // than assumes), but lifecycle verification refuses
        // naming exactly the drifted pair.
        let image = copy_btf_image_with_dirs(&PrivateShape::full(), 2, 1, 0);
        let (to, from, bidi) = lifecycle_dirs_from_btf(&image).expect("swapped enum must parse");
        assert_eq!((to, from, bidi), (2, 1, 0));
        let copy = resolve_copy_offsets_from_btf(&image).expect("swapped enum keeps copy green");
        assert_eq!((copy.dir_to, copy.dir_from, copy.dir_bidi), (2, 1, 0));
        let message = match verify_lifecycle_dirs_from_btf(&image) {
            Ok(()) => panic!("swapped enum must refuse"),
            Err(error) => error.to_string(),
        };
        assert!(
            message.contains("DMA_TO_DEVICE is 2"),
            "want the TO drift, got: {message}"
        );
        assert!(
            message.contains("DMA_FROM_DEVICE is 1"),
            "want the FROM drift, got: {message}"
        );
        assert!(
            !message.contains("BIDIRECTIONAL"),
            "bidi is fine, got: {message}"
        );
    }
}
