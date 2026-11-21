// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal kernel-BTF reader resolving the copy-channel field table.
//!
//! The Aya copy probe keeps no CO-RE relocations: userspace resolves
//! every offset the C probe relocates from live kernel BTF and
//! installs the 112-byte table into `mv_copy_offs` before attach.
//! This module reads exactly the structs, widths, and enum values
//! the table needs; anything missing or misshapen refuses loudly,
//! never with a guessed offset. Unprivileged: BTF bytes come from
//! `/sys/kernel/btf/vmlinux`, which any user may read.

use memveil_ebpf_common::{
    CopyOffsets, MV_COPY_OFFS_HAS_PRIVATE, MV_COPY_OFFS_LEN, MV_COPY_OFFS_MAGIC,
    MV_COPY_OFFS_VERSION,
};

/// Raw BTF container: the type section plus the string section.
pub struct BtfFile<'a> {
    types: &'a [u8],
    strings: &'a [u8],
}

/// BTF kinds (`linux/btf.h`).
const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

/// Pointer width on the x86-64 kernels this harness targets.
const PTR_SIZE: u32 = 8;

fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
}

fn read_u32(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..at.checked_add(4)?)
        .map(|w| u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// Parse raw BTF bytes: magic `0xEB9F`, version 1, bounded sections.
pub fn parse_btf(bytes: &[u8]) -> Result<BtfFile<'_>, String> {
    if bytes.len() < 24 {
        return Err("BTF shorter than its header".to_owned());
    }
    if read_u16(bytes, 0) != Some(0xEB9F) {
        return Err("BTF bad magic".to_owned());
    }
    if bytes.get(2) != Some(&1) {
        return Err("BTF bad version".to_owned());
    }
    let get = |at: usize| read_u32(bytes, at).ok_or_else(|| "BTF header truncated".to_owned());
    let hdr_len = get(4)? as usize;
    let type_off = get(8)? as usize;
    let type_len = get(12)? as usize;
    let str_off = get(16)? as usize;
    let str_len = get(20)? as usize;
    if hdr_len < 24 || hdr_len > bytes.len() {
        return Err("BTF bad header length".to_owned());
    }
    // Section offsets run from the end of the header, whose own
    // length varies (newer kernels append parent fields).
    let section = |off: usize, len: usize| {
        let start = hdr_len
            .checked_add(off)
            .ok_or_else(|| "BTF section outside its bytes".to_owned())?;
        let end = start
            .checked_add(len)
            .filter(|end| *end <= bytes.len())
            .ok_or_else(|| "BTF section outside its bytes".to_owned())?;
        Ok::<(usize, usize), String>((start, end))
    };
    let (type_start, type_end) = section(type_off, type_len)?;
    let (str_start, str_end) = section(str_off, str_len)?;
    let types = &bytes[type_start..type_end];
    let strings = &bytes[str_start..str_end];
    if strings.first() != Some(&0) {
        return Err("BTF strings do not start with NUL".to_owned());
    }
    Ok(BtfFile { types, strings })
}

/// One decoded type header plus its payload offset.
struct TypeHead {
    name_off: u32,
    kind: u8,
    vlen: u16,
    size_or_type: u32,
    payload: usize,
}

impl<'a> BtfFile<'a> {
    /// Walk the type section, calling `visit` per type id (from 1).
    fn each_type(
        &self,
        mut visit: impl FnMut(u32, TypeHead) -> Result<(), String>,
    ) -> Result<(), String> {
        let mut at = 0usize;
        let mut id = 1u32;
        while at < self.types.len() {
            let name_off =
                read_u32(self.types, at).ok_or_else(|| "BTF type truncated".to_owned())?;
            let info =
                read_u32(self.types, at + 4).ok_or_else(|| "BTF type truncated".to_owned())?;
            let size_or_type =
                read_u32(self.types, at + 8).ok_or_else(|| "BTF type truncated".to_owned())?;
            // Kind is 5 bits (up to ENUM64 = 19); bit 31 is
            // kflag, not kind.
            let kind = ((info >> 24) & 0x1F) as u8;
            let vlen = (info & 0xFFFF) as u16;
            let payload = at + 12;
            // Struct members and ENUM64 members are 12 bytes;
            // plain enum members are 8.
            let extra = if matches!(kind, KIND_ENUM64 | KIND_STRUCT | KIND_UNION) {
                usize::from(vlen).checked_mul(12)
            } else if kind == KIND_ENUM || kind == KIND_FUNC_PROTO {
                usize::from(vlen).checked_mul(8)
            } else if kind == KIND_DATASEC {
                usize::from(vlen).checked_mul(12)
            } else if kind == KIND_VAR || kind == KIND_DECL_TAG {
                // Linkage (VAR) and component index (DECL_TAG).
                Some(4)
            } else if matches!(kind, KIND_INT | KIND_ARRAY) {
                Some(if kind == KIND_INT { 4 } else { 12 })
            } else {
                Some(0)
            }
            .ok_or_else(|| "BTF member count overflows".to_owned())?;
            let next = payload
                .checked_add(extra)
                .filter(|next| *next <= self.types.len())
                .ok_or_else(|| "BTF type overruns its section".to_owned())?;
            visit(
                id,
                TypeHead {
                    name_off,
                    kind,
                    vlen,
                    size_or_type,
                    payload,
                },
            )?;
            at = next;
            id = id
                .checked_add(1)
                .ok_or_else(|| "BTF too many types".to_owned())?;
        }
        Ok(())
    }

    /// Read one type header by id.
    fn head(&self, id: u32) -> Result<TypeHead, String> {
        let mut found = None;
        self.each_type(|got, head| {
            if got == id {
                found = Some(head);
            }
            Ok(())
        })?;
        found.ok_or_else(|| format!("BTF type {id} missing"))
    }

    /// Resolve one string-table offset to bytes.
    fn string(&self, off: u32) -> Result<&'a [u8], String> {
        let start = off as usize;
        if start >= self.strings.len() {
            return Err("BTF string outside its table".to_owned());
        }
        let tail = &self.strings[start..];
        let end = tail
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| "BTF string unterminated".to_owned())?;
        Ok(&tail[..end])
    }

    /// Find the first struct/union/enum/enum64 carrying `name`.
    fn find_named(&self, name: &[u8], kinds: &[u8]) -> Result<u32, String> {
        let mut found = None;
        self.each_type(|id, head| {
            if kinds.contains(&head.kind)
                && let Ok(text) = self.string(head.name_off)
                && text == name
            {
                found = found.or(Some(id));
            }
            Ok(())
        })?;
        let label = String::from_utf8_lossy(name);
        found.ok_or_else(|| format!("BTF has no {label}"))
    }

    /// Follow typedefs and qualifiers to the underlying type id.
    fn peel(&self, mut id: u32) -> Result<u32, String> {
        for _ in 0..32 {
            let head = self.head(id)?;
            match head.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_DECL_TAG
                | KIND_TYPE_TAG => {
                    id = head.size_or_type;
                }
                _ => return Ok(id),
            }
        }
        Err("BTF qualifier chain too deep".to_owned())
    }

    /// Byte size of a resolved type.
    fn type_size(&self, id: u32) -> Result<u32, String> {
        let id = self.peel(id)?;
        let head = self.head(id)?;
        match head.kind {
            KIND_INT | KIND_FLOAT | KIND_ENUM | KIND_STRUCT | KIND_UNION => Ok(head.size_or_type),
            KIND_ENUM64 => Ok(8),
            KIND_PTR => Ok(PTR_SIZE),
            KIND_ARRAY => {
                let elem = read_u32(self.types, head.payload)
                    .ok_or_else(|| "BTF array truncated".to_owned())?;
                let nelems = read_u32(self.types, head.payload + 8)
                    .ok_or_else(|| "BTF array truncated".to_owned())?;
                self.type_size(elem)?
                    .checked_mul(nelems)
                    .ok_or_else(|| "BTF array size overflows".to_owned())
            }
            _ => Err(format!("BTF type {id} has no usable size")),
        }
    }

    /// Byte offset and width of `member` in the struct/union `id`.
    /// Bitfields refuse: the probe reads whole bytes only.
    fn member(&self, id: u32, member: &[u8]) -> Result<(u32, u32), String> {
        let id = self.peel(id)?;
        let head = self.head(id)?;
        if head.kind != KIND_STRUCT && head.kind != KIND_UNION {
            return Err(format!("BTF type {id} is not a struct"));
        }
        for slot in 0..head.vlen {
            let at = head.payload + usize::from(slot) * 12;
            let name_off =
                read_u32(self.types, at).ok_or_else(|| "BTF member truncated".to_owned())?;
            if self.string(name_off)? != member {
                continue;
            }
            let raw =
                read_u32(self.types, at + 8).ok_or_else(|| "BTF member truncated".to_owned())?;
            if raw & 0xFF00_0000 != 0 {
                return Err(format!(
                    "BTF member {} is a bitfield",
                    String::from_utf8_lossy(member)
                ));
            }
            if raw % 8 != 0 {
                return Err(format!(
                    "BTF member {} is not byte-aligned",
                    String::from_utf8_lossy(member)
                ));
            }
            let ty =
                read_u32(self.types, at + 4).ok_or_else(|| "BTF member truncated".to_owned())?;
            let width = self
                .type_size(ty)
                .map_err(|message| format!("{}: {message}", String::from_utf8_lossy(member)))?;
            return Ok((raw / 8, width));
        }
        Err(format!(
            "BTF struct {} has no member {}",
            self.struct_name(id)?,
            String::from_utf8_lossy(member)
        ))
    }

    /// Optional struct member: `None` when the member is absent.
    fn member_opt(&self, id: u32, member: &[u8]) -> Result<Option<(u32, u32)>, String> {
        match self.member(id, member) {
            Ok(found) => Ok(Some(found)),
            Err(message) if message.contains("has no member") => Ok(None),
            Err(message) => Err(message),
        }
    }

    fn struct_name(&self, id: u32) -> Result<String, String> {
        let head = self.head(id)?;
        Ok(String::from_utf8_lossy(self.string(head.name_off)?).into_owned())
    }

    /// Enumerator value by name from an enum/enum64.
    fn enum_value(&self, id: u32, member: &[u8]) -> Result<u64, String> {
        let id = self.peel(id)?;
        let head = self.head(id)?;
        for slot in 0..head.vlen {
            match head.kind {
                KIND_ENUM => {
                    let at = head.payload + usize::from(slot) * 8;
                    let name_off = read_u32(self.types, at)
                        .ok_or_else(|| "BTF enumerator truncated".to_owned())?;
                    if self.string(name_off)? != member {
                        continue;
                    }
                    let raw = read_u32(self.types, at + 4)
                        .ok_or_else(|| "BTF enumerator truncated".to_owned())?;
                    return Ok(u64::from(raw));
                }
                KIND_ENUM64 => {
                    let at = head.payload + usize::from(slot) * 12;
                    let name_off = read_u32(self.types, at)
                        .ok_or_else(|| "BTF enumerator truncated".to_owned())?;
                    if self.string(name_off)? != member {
                        continue;
                    }
                    let lo = read_u32(self.types, at + 4)
                        .ok_or_else(|| "BTF enumerator truncated".to_owned())?;
                    let hi = read_u32(self.types, at + 8)
                        .ok_or_else(|| "BTF enumerator truncated".to_owned())?;
                    return Ok(u64::from(lo) | (u64::from(hi) << 32));
                }
                _ => return Err(format!("BTF type {id} is not an enum")),
            }
        }
        Err(format!(
            "BTF enum {} has no {}",
            self.struct_name(id)?,
            String::from_utf8_lossy(member)
        ))
    }
}

/// Require an exact member width, naming the field on mismatch.
fn need(pair: (u32, u32), width: u32, what: &str) -> Result<u32, String> {
    if pair.1 != width {
        return Err(format!("BTF {what} width is {}, want {width}", pair.1));
    }
    Ok(pair.0)
}

/// Resolve the 112-byte copy field table from parsed kernel BTF.
/// Every offset comes from a named struct member, every width is
/// checked against the probe's fixed reads, and the private-pool
/// quartet is valid only when both halves exist with width 8/1.
pub fn resolve_copy_offsets(btf: &BtfFile<'_>) -> Result<CopyOffsets, String> {
    let pool = btf.find_named(b"io_tlb_pool", &[KIND_STRUCT, KIND_UNION])?;
    let slot = btf.find_named(b"io_tlb_slot", &[KIND_STRUCT, KIND_UNION])?;
    let device = btf.find_named(b"device", &[KIND_STRUCT, KIND_UNION])?;
    let parms = btf.find_named(b"device_dma_parameters", &[KIND_STRUCT, KIND_UNION])?;
    let pool_start_off = need(btf.member(pool, b"start")?, 8, "io_tlb_pool.start")?;
    let pool_end_off = need(btf.member(pool, b"end")?, 8, "io_tlb_pool.end")?;
    let pool_nslabs_off = need(btf.member(pool, b"nslabs")?, 8, "io_tlb_pool.nslabs")?;
    let pool_slots_off = need(btf.member(pool, b"slots")?, 8, "io_tlb_pool.slots")?;
    let slot_orig_off = need(btf.member(slot, b"orig_addr")?, 8, "io_tlb_slot.orig_addr")?;
    let slot_alloc_off = need(
        btf.member(slot, b"alloc_size")?,
        8,
        "io_tlb_slot.alloc_size",
    )?;
    let slot_size = btf.type_size(slot)?;
    if slot_size == 0 {
        return Err("BTF io_tlb_slot has zero size".to_owned());
    }
    let dev_parms_off = need(btf.member(device, b"dma_parms")?, 8, "device.dma_parms")?;
    let mask_off = need(
        btf.member(parms, b"min_align_mask")?,
        4,
        "device_dma_parameters.min_align_mask",
    )?;
    // The quartet resolves in one place so a half-present pool
    // chain clears the flag instead of shipping half offsets.
    let (mem_off, mem_size, cc_off, cc_size, flags) = private_quartet(btf, device)?;
    let dirs = btf.find_named(b"dma_data_direction", &[KIND_ENUM, KIND_ENUM64])?;
    let dir_to = btf.enum_value(dirs, b"DMA_TO_DEVICE")?;
    let dir_from = btf.enum_value(dirs, b"DMA_FROM_DEVICE")?;
    let dir_bidi = btf.enum_value(dirs, b"DMA_BIDIRECTIONAL")?;
    for (value, name) in [
        (dir_to, "DMA_TO_DEVICE"),
        (dir_from, "DMA_FROM_DEVICE"),
        (dir_bidi, "DMA_BIDIRECTIONAL"),
    ] {
        if value > u64::from(u32::MAX) {
            return Err(format!("BTF {name} does not fit u32"));
        }
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
        dir_to: dir_to as u32,
        dir_from: dir_from as u32,
        dir_bidi: dir_bidi as u32,
        reserved1: 0,
    };
    validate_table(&table)?;
    Ok(table)
}

/// Resolve the private-pool quartet: flag set only when
/// `device.dma_io_tlb_mem` (width 8) and `io_tlb_mem.cc_shared`
/// (width 1) both exist; otherwise all zeros with the flag clear.
fn private_quartet(btf: &BtfFile<'_>, device: u32) -> Result<(u32, u32, u32, u32, u16), String> {
    let Some(pair) = btf.member_opt(device, b"dma_io_tlb_mem")? else {
        return Ok((0, 0, 0, 0, 0));
    };
    if pair.1 != 8 {
        return Ok((0, 0, 0, 0, 0));
    }
    let mem = match btf.find_named(b"io_tlb_mem", &[KIND_STRUCT, KIND_UNION]) {
        Ok(id) => id,
        Err(_) => return Ok((0, 0, 0, 0, 0)),
    };
    let Some(cc) = btf.member_opt(mem, b"cc_shared")? else {
        return Ok((0, 0, 0, 0, 0));
    };
    if cc.1 != 1 {
        return Ok((0, 0, 0, 0, 0));
    }
    Ok((pair.0, 8, cc.0, 1, MV_COPY_OFFS_HAS_PRIVATE))
}

/// Validate a resolved table the way the probe does: magic,
/// version, flags, fixed widths, nonzero stride fitting both slot
/// field extents, and zero reserved words.
pub fn validate_table(table: &CopyOffsets) -> Result<(), String> {
    if table.magic != MV_COPY_OFFS_MAGIC {
        return Err("copy table bad magic".to_owned());
    }
    if table.version != MV_COPY_OFFS_VERSION {
        return Err("copy table bad version".to_owned());
    }
    if table.flags & !MV_COPY_OFFS_HAS_PRIVATE != 0 {
        return Err("copy table bad flags".to_owned());
    }
    for (got, name) in [
        (table.pool_start_size, "pool_start_size"),
        (table.pool_end_size, "pool_end_size"),
        (table.pool_nslabs_size, "pool_nslabs_size"),
        (table.pool_slots_size, "pool_slots_size"),
        (table.slot_orig_size, "slot_orig_size"),
        (table.slot_alloc_size, "slot_alloc_size"),
        (table.dev_parms_size, "dev_parms_size"),
    ] {
        if got != 8 {
            return Err(format!("copy table {name} is {got}, want 8"));
        }
    }
    if table.mask_size != 4 {
        return Err(format!(
            "copy table mask_size is {}, want 4",
            table.mask_size
        ));
    }
    if table.slot_size == 0 {
        return Err("copy table stride is zero".to_owned());
    }
    if table
        .slot_orig_off
        .checked_add(8)
        .is_none_or(|end| end > table.slot_size)
        || table
            .slot_alloc_off
            .checked_add(8)
            .is_none_or(|end| end > table.slot_size)
    {
        return Err("copy table slot fields escape the stride".to_owned());
    }
    if table.reserved0 != 0 || table.reserved1 != 0 {
        return Err("copy table reserved words nonzero".to_owned());
    }
    if table.flags & MV_COPY_OFFS_HAS_PRIVATE != 0 {
        if table.mem_size != 8 || table.cc_size != 1 {
            return Err("copy table private quartet widths wrong".to_owned());
        }
    } else if table.mem_off != 0 || table.mem_size != 0 || table.cc_off != 0 || table.cc_size != 0 {
        return Err("copy table private quartet set without the flag".to_owned());
    }
    Ok(())
}

/// Encode a validated table to its 112 wire bytes, little-endian.
pub fn encode_table(table: &CopyOffsets) -> [u8; MV_COPY_OFFS_LEN] {
    struct Writer {
        out: [u8; MV_COPY_OFFS_LEN],
        at: usize,
    }

    impl Writer {
        fn put16(&mut self, value: u16) {
            self.out[self.at..self.at + 2].copy_from_slice(&value.to_le_bytes());
            self.at += 2;
        }

        fn put32(&mut self, value: u32) {
            self.out[self.at..self.at + 4].copy_from_slice(&value.to_le_bytes());
            self.at += 4;
        }
    }

    let mut w = Writer {
        out: [0u8; MV_COPY_OFFS_LEN],
        at: 0,
    };
    w.put32(table.magic);
    w.put16(table.version);
    w.put16(table.flags);
    w.put32(table.pool_start_off);
    w.put32(table.pool_start_size);
    w.put32(table.pool_end_off);
    w.put32(table.pool_end_size);
    w.put32(table.pool_nslabs_off);
    w.put32(table.pool_nslabs_size);
    w.put32(table.pool_slots_off);
    w.put32(table.pool_slots_size);
    w.put32(table.slot_orig_off);
    w.put32(table.slot_orig_size);
    w.put32(table.slot_alloc_off);
    w.put32(table.slot_alloc_size);
    w.put32(table.dev_parms_off);
    w.put32(table.dev_parms_size);
    w.put32(table.mask_off);
    w.put32(table.mask_size);
    w.put32(table.slot_size);
    w.put32(table.reserved0);
    w.put32(table.mem_off);
    w.put32(table.mem_size);
    w.put32(table.cc_off);
    w.put32(table.cc_size);
    w.put32(table.dir_to);
    w.put32(table.dir_from);
    w.put32(table.dir_bidi);
    w.put32(table.reserved1);
    debug_assert_eq!(w.at, MV_COPY_OFFS_LEN);
    w.out
}

/// Read the frozen lifecycle direction encodings from kernel BTF.
/// Every real kernel carries 0/1/2; a renumbered kernel refuses
/// loudly instead of silently inverting directions.
pub fn lifecycle_dirs(btf: &BtfFile<'_>) -> Result<(u32, u32, u32), String> {
    let dirs = btf.find_named(b"dma_data_direction", &[KIND_ENUM, KIND_ENUM64])?;
    let to = btf.enum_value(dirs, b"DMA_TO_DEVICE")?;
    let from = btf.enum_value(dirs, b"DMA_FROM_DEVICE")?;
    let bidi = btf.enum_value(dirs, b"DMA_BIDIRECTIONAL")?;
    for (value, name) in [
        (to, "DMA_TO_DEVICE"),
        (from, "DMA_FROM_DEVICE"),
        (bidi, "DMA_BIDIRECTIONAL"),
    ] {
        if value > u64::from(u32::MAX) {
            return Err(format!("BTF {name} does not fit u32"));
        }
    }
    let got = (bidi as u32, to as u32, from as u32);
    if got != (0, 1, 2) {
        return Err(format!(
            "BTF dma_data_direction is {}/{}/{} (bidi/to/from), want 0/1/2",
            got.0, got.1, got.2
        ));
    }
    Ok(got)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unwrap the refusal side without needing `Debug` on success.
    fn refuse<T>(result: Result<T, String>) -> String {
        match result {
            Ok(_) => panic!("expected a refusal"),
            Err(message) => message,
        }
    }

    /// Append a string, returning its table offset.
    fn push_str(strings: &mut Vec<u8>, text: &str) -> u32 {
        let at = strings.len() as u32;
        strings.extend_from_slice(text.as_bytes());
        strings.push(0);
        at
    }

    fn push_type(types: &mut Vec<u8>, name_off: u32, kind: u8, vlen: u16, size_or_type: u32) {
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&((u32::from(kind) << 24 | u32::from(vlen)).to_le_bytes()));
        types.extend_from_slice(&size_or_type.to_le_bytes());
    }

    fn push_member(types: &mut Vec<u8>, name_off: u32, ty: u32, bit_off: u32) {
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&ty.to_le_bytes());
        types.extend_from_slice(&bit_off.to_le_bytes());
    }

    fn push_enum_value(types: &mut Vec<u8>, name_off: u32, value: u32) {
        types.extend_from_slice(&name_off.to_le_bytes());
        types.extend_from_slice(&value.to_le_bytes());
    }

    /// Build synthetic BTF with the kernel shapes the resolver
    /// needs, at fixed small offsets. Type ids: 1 u64, 2 u32, 3
    /// u8, 4 ptr, 5 io_tlb_pool, 6 io_tlb_slot, 7 device,
    /// 8 device_dma_parameters, 9 io_tlb_mem, 10 dma_data_direction.
    fn fixture(dirs: (u32, u32, u32), private: bool) -> Vec<u8> {
        let mut strings = vec![0u8];
        let empty = 0u32;
        let u64_name = push_str(&mut strings, "u64");
        let u32_name = push_str(&mut strings, "u32");
        let u8_name = push_str(&mut strings, "u8");
        let pool_name = push_str(&mut strings, "io_tlb_pool");
        let slot_name = push_str(&mut strings, "io_tlb_slot");
        let device_name = push_str(&mut strings, "device");
        let parms_name = push_str(&mut strings, "device_dma_parameters");
        let mem_name = push_str(&mut strings, "io_tlb_mem");
        let dirs_name = push_str(&mut strings, "dma_data_direction");
        let start = push_str(&mut strings, "start");
        let end = push_str(&mut strings, "end");
        let nslabs = push_str(&mut strings, "nslabs");
        let slots = push_str(&mut strings, "slots");
        let orig = push_str(&mut strings, "orig_addr");
        let alloc = push_str(&mut strings, "alloc_size");
        let dma_parms = push_str(&mut strings, "dma_parms");
        let mem_field = push_str(&mut strings, "dma_io_tlb_mem");
        let mask = push_str(&mut strings, "min_align_mask");
        let cc = push_str(&mut strings, "cc_shared");
        let to = push_str(&mut strings, "DMA_TO_DEVICE");
        let from = push_str(&mut strings, "DMA_FROM_DEVICE");
        let bidi = push_str(&mut strings, "DMA_BIDIRECTIONAL");
        let mut types = Vec::new();
        // 1: u64 INT.
        push_type(&mut types, u64_name, KIND_INT, 0, 8);
        types.extend_from_slice(&0x0800_0020u32.to_le_bytes());
        // 2: u32 INT.
        push_type(&mut types, u32_name, KIND_INT, 0, 4);
        types.extend_from_slice(&0x0800_0010u32.to_le_bytes());
        // 3: u8 INT.
        push_type(&mut types, u8_name, KIND_INT, 0, 1);
        types.extend_from_slice(&0x0800_0008u32.to_le_bytes());
        // 4: anonymous pointer.
        push_type(&mut types, empty, KIND_PTR, 0, 0);
        // 5: io_tlb_pool { start, end, nslabs: u64; slots: ptr }.
        push_type(&mut types, pool_name, KIND_STRUCT, 4, 32);
        push_member(&mut types, start, 1, 0);
        push_member(&mut types, end, 1, 64);
        push_member(&mut types, nslabs, 1, 128);
        push_member(&mut types, slots, 4, 192);
        // 6: io_tlb_slot { orig_addr, alloc_size: u64 }.
        push_type(&mut types, slot_name, KIND_STRUCT, 2, 16);
        push_member(&mut types, orig, 1, 0);
        push_member(&mut types, alloc, 1, 64);
        // 7: device { dma_parms: ptr; dma_io_tlb_mem: ptr? }.
        let members = if private { 2u16 } else { 1u16 };
        push_type(&mut types, device_name, KIND_STRUCT, members, 16);
        push_member(&mut types, dma_parms, 4, 0);
        if private {
            push_member(&mut types, mem_field, 4, 64);
        }
        // 8: device_dma_parameters { min_align_mask: u32 }.
        push_type(&mut types, parms_name, KIND_STRUCT, 1, 4);
        push_member(&mut types, mask, 2, 0);
        // 9: io_tlb_mem { cc_shared: u8 } (present iff private).
        if private {
            push_type(&mut types, mem_name, KIND_STRUCT, 1, 1);
            push_member(&mut types, cc, 3, 0);
        }
        // 10/9: dma_data_direction enum.
        push_type(&mut types, dirs_name, KIND_ENUM, 3, 4);
        push_enum_value(&mut types, bidi, dirs.0);
        push_enum_value(&mut types, to, dirs.1);
        push_enum_value(&mut types, from, dirs.2);
        // Lock the walk against kflag structs, prototypes, and
        // datasecs: set kflag on the pool struct (its info word
        // sits at 60 + 4, after 16 + 16 + 16 + 12 bytes of
        // scalars and one pointer), then append a two-parameter
        // prototype and a one-entry datasec. Resolution must not
        // notice either trailing type.
        types[60 + 7] |= 0x80;
        push_type(&mut types, empty, KIND_FUNC_PROTO, 2, 1);
        types.extend_from_slice(&empty.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&empty.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        let sec_name = push_str(&mut strings, ".data");
        push_type(&mut types, sec_name, KIND_DATASEC, 1, 16);
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        // An enum64 locks the 5-bit kind mask (19 needs it) and
        // the 12-byte member stride.
        let e64_name = push_str(&mut strings, "big_enum");
        let e64_a = push_str(&mut strings, "BIG_A");
        let e64_b = push_str(&mut strings, "BIG_B");
        push_type(&mut types, e64_name, KIND_ENUM64, 2, 8);
        types.extend_from_slice(&e64_a.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&e64_b.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // A VAR (linkage word) and a DECL_TAG (component index)
        // lock their 4-byte payloads in the walk.
        let var_name = push_str(&mut strings, "some_global");
        push_type(&mut types, var_name, KIND_VAR, 0, 1);
        types.extend_from_slice(&0u32.to_le_bytes());
        let tag_name = push_str(&mut strings, "some_tag");
        push_type(&mut types, tag_name, KIND_DECL_TAG, 0, 5);
        types.extend_from_slice(&0u32.to_le_bytes());
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
    fn resolves_private_table() {
        let bytes = fixture((0, 1, 2), true);
        let btf = parse_btf(&bytes).unwrap();
        let table = resolve_copy_offsets(&btf).unwrap();
        assert_eq!(table.magic, MV_COPY_OFFS_MAGIC);
        assert_eq!(table.flags, MV_COPY_OFFS_HAS_PRIVATE);
        assert_eq!(
            (
                table.pool_start_off,
                table.pool_end_off,
                table.pool_nslabs_off,
                table.pool_slots_off
            ),
            (0, 8, 16, 24)
        );
        assert_eq!(
            (table.slot_orig_off, table.slot_alloc_off, table.slot_size),
            (0, 8, 16)
        );
        assert_eq!((table.dev_parms_off, table.mask_off), (0, 0));
        assert_eq!(
            (table.mem_off, table.mem_size, table.cc_off, table.cc_size),
            (8, 8, 0, 1)
        );
        assert_eq!((table.dir_to, table.dir_from, table.dir_bidi), (1, 2, 0));
        let wire = encode_table(&table);
        assert_eq!(wire.len(), MV_COPY_OFFS_LEN);
        assert_eq!(
            u32::from_le_bytes(wire[0..4].try_into().unwrap()),
            MV_COPY_OFFS_MAGIC
        );
        assert_eq!(u32::from_le_bytes(wire[72..76].try_into().unwrap()), 16);
    }

    #[test]
    fn resolves_noprivate_table_with_clear_flag() {
        let bytes = fixture((0, 1, 2), false);
        let btf = parse_btf(&bytes).unwrap();
        let table = resolve_copy_offsets(&btf).unwrap();
        assert_eq!(table.flags, 0);
        assert_eq!(
            (table.mem_off, table.mem_size, table.cc_off, table.cc_size),
            (0, 0, 0, 0)
        );
    }

    #[test]
    fn wrong_width_refuses() {
        let mut strings = vec![0u8];
        let pool_name = push_str(&mut strings, "io_tlb_pool");
        let start = push_str(&mut strings, "start");
        let u32_name = push_str(&mut strings, "u32");
        let slot_name = push_str(&mut strings, "io_tlb_slot");
        let orig = push_str(&mut strings, "orig_addr");
        let alloc = push_str(&mut strings, "alloc_size");
        let device_name = push_str(&mut strings, "device");
        let dma_parms = push_str(&mut strings, "dma_parms");
        let parms_name = push_str(&mut strings, "device_dma_parameters");
        let mask = push_str(&mut strings, "min_align_mask");
        let dirs_name = push_str(&mut strings, "dma_data_direction");
        let to = push_str(&mut strings, "DMA_TO_DEVICE");
        let from = push_str(&mut strings, "DMA_FROM_DEVICE");
        let bidi = push_str(&mut strings, "DMA_BIDIRECTIONAL");
        let mut types = Vec::new();
        push_type(&mut types, u32_name, KIND_INT, 0, 4);
        types.extend_from_slice(&0x0800_0010u32.to_le_bytes());
        // pool.start as u32: wrong width.
        push_type(&mut types, pool_name, KIND_STRUCT, 1, 4);
        push_member(&mut types, start, 1, 0);
        push_type(&mut types, slot_name, KIND_STRUCT, 2, 8);
        push_member(&mut types, orig, 1, 0);
        push_member(&mut types, alloc, 1, 32);
        push_type(&mut types, device_name, KIND_STRUCT, 1, 4);
        push_member(&mut types, dma_parms, 1, 0);
        push_type(&mut types, parms_name, KIND_STRUCT, 1, 4);
        push_member(&mut types, mask, 1, 0);
        push_type(&mut types, dirs_name, KIND_ENUM, 3, 4);
        push_enum_value(&mut types, bidi, 0);
        push_enum_value(&mut types, to, 1);
        push_enum_value(&mut types, from, 2);
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
        let btf = parse_btf(&out).unwrap();
        let err = refuse(resolve_copy_offsets(&btf));
        assert!(err.contains("io_tlb_pool.start"), "{err}");
    }

    #[test]
    fn missing_struct_refuses() {
        let bytes = fixture((0, 1, 2), true);
        // Corrupt the pool name so the lookup misses.
        let mut broken = bytes.clone();
        let needle = b"io_tlb_pool";
        let pos = broken
            .windows(needle.len())
            .position(|w| w == needle)
            .unwrap();
        broken[pos] = b'X';
        let btf = parse_btf(&broken).unwrap();
        let err = refuse(resolve_copy_offsets(&btf));
        assert!(err.contains("io_tlb_pool"), "{err}");
    }

    #[test]
    fn bad_magic_refuses() {
        let err = refuse(parse_btf(&[0u8; 32]));
        assert!(err.contains("magic"), "{err}");
    }

    #[test]
    fn truncated_refuses() {
        let bytes = fixture((0, 1, 2), true);
        let cut = &bytes[..bytes.len() - 8];
        assert!(parse_btf(cut).is_err());
    }

    #[test]
    fn dirs_check_accepts_and_refuses() {
        let bytes = fixture((0, 1, 2), true);
        let btf = parse_btf(&bytes).unwrap();
        assert_eq!(lifecycle_dirs(&btf).unwrap(), (0, 1, 2));
        let moved = fixture((0, 2, 1), true);
        let btf = parse_btf(&moved).unwrap();
        let err = refuse(lifecycle_dirs(&btf));
        assert!(err.contains("want 0/1/2"), "{err}");
    }

    #[test]
    fn table_validation_catches_half_private_and_stride() {
        let bytes = fixture((0, 1, 2), true);
        let btf = parse_btf(&bytes).unwrap();
        let mut table = resolve_copy_offsets(&btf).unwrap();
        table.flags = 0;
        assert!(validate_table(&table).is_err());
        let mut table = resolve_copy_offsets(&btf).unwrap();
        table.slot_size = 8;
        assert!(validate_table(&table).is_err());
        let mut table = resolve_copy_offsets(&btf).unwrap();
        table.reserved1 = 1;
        assert!(validate_table(&table).is_err());
    }
}
