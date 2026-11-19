// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal kernel-BTF reader for the copy-channel field table.
//!
//! Parses raw `/sys/kernel/btf/vmlinux` bytes (little-endian 64-bit host
//! order) far enough to answer three questions: struct member offsets and
//! widths, struct sizes, and enumerator values. Every read is bounds-checked
//! and every inconsistency refuses: the installer must never derive offsets
//! from a misread layout.

use super::session::SessionError;

/// BTF magic (`0xEB9F`).
const BTF_MAGIC: u16 = 0xEB9F;
/// BTF version the parser accepts.
const BTF_VERSION: u8 = 1;

/// BTF type kinds.
const KIND_INT: u8 = 1;
/// BTF type kinds.
const KIND_PTR: u8 = 2;
/// BTF type kinds.
const KIND_ARRAY: u8 = 3;
/// BTF type kinds.
const KIND_STRUCT: u8 = 4;
/// BTF type kinds.
const KIND_UNION: u8 = 5;
/// BTF type kinds.
const KIND_ENUM: u8 = 6;
/// BTF type kinds.
const KIND_FWD: u8 = 7;
/// BTF type kinds.
const KIND_TYPEDEF: u8 = 8;
/// BTF type kinds.
const KIND_VOLATILE: u8 = 9;
/// BTF type kinds.
const KIND_CONST: u8 = 10;
/// BTF type kinds.
const KIND_RESTRICT: u8 = 11;
/// BTF type kinds.
const KIND_FUNC: u8 = 12;
/// BTF type kinds.
const KIND_FUNC_PROTO: u8 = 13;
/// BTF type kinds.
const KIND_VAR: u8 = 14;
/// BTF type kinds.
const KIND_DATASEC: u8 = 15;
/// BTF type kinds.
const KIND_FLOAT: u8 = 16;
/// BTF type kinds.
const KIND_DECL_TAG: u8 = 17;
/// BTF type kinds.
const KIND_TYPE_TAG: u8 = 18;
/// BTF type kinds.
const KIND_ENUM64: u8 = 19;

/// Cap on modifier/pointer chase depth (cycles refuse).
const MAX_RESOLVE_DEPTH: usize = 32;

/// One parsed type record: header plus its trailing payload slice.
#[derive(Clone, Copy, Debug)]
struct TypeRec<'a> {
    kind: u8,
    kind_flag: bool,
    name_off: u32,
    size_or_type: u32,
    vlen: u16,
    payload: &'a [u8],
}

/// Parsed BTF image borrowing its backing bytes.
#[derive(Clone, Debug)]
pub(crate) struct Btf<'a> {
    types: Vec<TypeRec<'a>>,
    strings: &'a [u8],
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..at + 4)
        .map(|window| u32::from_le_bytes([window[0], window[1], window[2], window[3]]))
}

impl<'a> Btf<'a> {
    /// Parse a raw BTF image. Refuses truncated headers, bad magic or
    /// version, out-of-range sections, and any type record the walker
    /// cannot size (unknown kinds refuse rather than desynchronize).
    pub(crate) fn parse(data: &'a [u8]) -> Result<Self, SessionError> {
        let refuse = |why: &str| SessionError::Offsets(format!("BTF invalid: {why}"));
        let Some(magic) = data.get(..2).map(|w| u16::from_le_bytes([w[0], w[1]])) else {
            return Err(refuse("header truncated"));
        };
        if magic != BTF_MAGIC {
            return Err(refuse("bad magic"));
        }
        if data.get(2) != Some(&BTF_VERSION) {
            return Err(refuse("bad version"));
        }
        let (Some(hdr_len), Some(type_off), Some(type_len), Some(str_off), Some(str_len)) = (
            read_u32(data, 4).map(|v| v as usize),
            read_u32(data, 8).map(|v| v as usize),
            read_u32(data, 12).map(|v| v as usize),
            read_u32(data, 16).map(|v| v as usize),
            read_u32(data, 20).map(|v| v as usize),
        ) else {
            return Err(refuse("header truncated"));
        };
        if hdr_len < 24 {
            return Err(refuse("header too short"));
        }
        let Some(type_end) = hdr_len
            .checked_add(type_off)
            .and_then(|b| b.checked_add(type_len))
        else {
            return Err(refuse("type section out of range"));
        };
        let Some(str_end) = hdr_len
            .checked_add(str_off)
            .and_then(|b| b.checked_add(str_len))
        else {
            return Err(refuse("string section out of range"));
        };
        if type_end > data.len() || str_end > data.len() {
            return Err(refuse("section out of range"));
        }
        let strings = &data[hdr_len + str_off..str_end];
        if strings.first() != Some(&0) {
            return Err(refuse("string table must start with NUL"));
        }
        let mut types = Vec::new();
        let mut at = hdr_len + type_off;
        while at < type_end {
            let (Some(name_off), Some(info), Some(size_or_type)) = (
                read_u32(data, at),
                read_u32(data, at + 4),
                read_u32(data, at + 8),
            ) else {
                return Err(refuse("type record truncated"));
            };
            // `BTF_INFO_KIND`: 7 bits (bits 24-30); kinds run to 19
            // (`ENUM64`), so a 4-bit mask would alias `FLOAT`+ onto
            // void/unknown. The kind flag is bit 31, read separately
            // as `kind_flag` below.
            let kind = ((info >> 24) & 0x7f) as u8;
            let kind_flag = info & (1 << 31) != 0;
            let vlen = (info & 0xFFFF) as u16;
            let payload_len: usize = match kind {
                KIND_STRUCT | KIND_UNION => usize::from(vlen) * 12,
                KIND_ENUM => usize::from(vlen) * 8,
                KIND_ENUM64 => usize::from(vlen) * 12,
                KIND_ARRAY => 12,
                KIND_FUNC_PROTO => usize::from(vlen) * 8,
                KIND_DATASEC => usize::from(vlen) * 12,
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                // Kind 0 (void) is never stored as a record; anything else
                // unknown refuses rather than desynchronizing the walk.
                _ => return Err(refuse("unknown type kind")),
            };
            let payload_at = at + 12;
            let Some(payload_end) = payload_at.checked_add(payload_len) else {
                return Err(refuse("type payload out of range"));
            };
            if payload_end > type_end {
                return Err(refuse("type payload truncated"));
            };
            types.push(TypeRec {
                kind,
                kind_flag,
                name_off,
                size_or_type,
                vlen,
                payload: &data[payload_at..payload_end],
            });
            at = payload_end;
        }
        let parsed = Self { types, strings };
        parsed.validate_names()?;
        Ok(parsed)
    }

    /// Validate every string reference the queries can reach (type names,
    /// struct member names, enumerator names), so post-parse lookups fail
    /// only on genuinely missing entries, never on a corrupt image the
    /// caller would mistake for absence.
    fn validate_names(&self) -> Result<(), SessionError> {
        for rec in &self.types {
            self.name(rec.name_off)?;
            match rec.kind {
                KIND_STRUCT | KIND_UNION => {
                    for index in 0..usize::from(rec.vlen) {
                        let at = index * 12;
                        let Some(member_name) = read_u32(rec.payload, at) else {
                            return Err(SessionError::Offsets(
                                "BTF invalid: member truncated".to_owned(),
                            ));
                        };
                        self.name(member_name)?;
                    }
                }
                KIND_ENUM => {
                    for index in 0..usize::from(rec.vlen) {
                        let at = index * 8;
                        let Some(value_name) = read_u32(rec.payload, at) else {
                            return Err(SessionError::Offsets(
                                "BTF invalid: enumerator truncated".to_owned(),
                            ));
                        };
                        self.name(value_name)?;
                    }
                }
                KIND_ENUM64 => {
                    for index in 0..usize::from(rec.vlen) {
                        let at = index * 12;
                        let Some(value_name) = read_u32(rec.payload, at) else {
                            return Err(SessionError::Offsets(
                                "BTF invalid: enumerator truncated".to_owned(),
                            ));
                        };
                        self.name(value_name)?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Look up a string-table name.
    fn name(&self, off: u32) -> Result<&'a str, SessionError> {
        let start = off as usize;
        if start >= self.strings.len() {
            return Err(SessionError::Offsets(
                "BTF invalid: bad string offset".to_owned(),
            ));
        }
        let tail = &self.strings[start..];
        let Some(len) = tail.iter().position(|byte| *byte == 0) else {
            return Err(SessionError::Offsets(
                "BTF invalid: unterminated string".to_owned(),
            ));
        };
        std::str::from_utf8(&tail[..len])
            .map_err(|_| SessionError::Offsets("BTF invalid: non-UTF8 name".to_owned()))
    }

    /// Record by 1-based type id.
    fn record(&self, id: u32) -> Result<&TypeRec<'a>, SessionError> {
        if id == 0 {
            return Err(SessionError::Offsets(
                "BTF invalid: void type reference".to_owned(),
            ));
        }
        self.types
            .get(id as usize - 1)
            .ok_or_else(|| SessionError::Offsets(format!("BTF invalid: bad type id {id}")))
    }

    /// Chase typedef/const/volatile/restrict/tag modifiers to the
    /// underlying type id.
    fn resolve(&self, mut id: u32) -> Result<u32, SessionError> {
        for _ in 0..MAX_RESOLVE_DEPTH {
            let rec = self.record(id)?;
            match rec.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = rec.size_or_type;
                }
                _ => return Ok(id),
            }
        }
        Err(SessionError::Offsets(format!(
            "BTF invalid: type cycle at {id}"
        )))
    }

    /// Byte size of the type id. Pointers are 8 (64-bit kernel); arrays
    /// multiply through with overflow refusal.
    fn size_of(&self, id: u32) -> Result<u64, SessionError> {
        let mut current = id;
        for _ in 0..MAX_RESOLVE_DEPTH {
            let rec = self.record(current)?;
            match rec.kind {
                KIND_PTR => return Ok(8),
                KIND_ARRAY => {
                    let elem = read_u32(rec.payload, 0).ok_or_else(|| {
                        SessionError::Offsets("BTF invalid: array truncated".to_owned())
                    })?;
                    let count = read_u32(rec.payload, 8).ok_or_else(|| {
                        SessionError::Offsets("BTF invalid: array truncated".to_owned())
                    })?;
                    let elem_size = self.size_of(elem)?;
                    return elem_size.checked_mul(u64::from(count)).ok_or_else(|| {
                        SessionError::Offsets("BTF invalid: array size overflows".to_owned())
                    });
                }
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    current = rec.size_or_type;
                }
                KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_INT | KIND_FLOAT => {
                    return Ok(u64::from(rec.size_or_type));
                }
                _ => {
                    return Err(SessionError::Offsets(format!(
                        "BTF invalid: unsized type id {current}"
                    )));
                }
            }
        }
        Err(SessionError::Offsets(format!(
            "BTF invalid: type cycle at {id}"
        )))
    }

    /// The single struct (or union) record with this name, or `None`
    /// when no such struct exists. Several same-named structs refuse:
    /// absence is the only soft outcome.
    fn struct_record_opt(&self, name: &str) -> Result<Option<&TypeRec<'a>>, SessionError> {
        let mut found = None;
        for rec in &self.types {
            if rec.kind != KIND_STRUCT && rec.kind != KIND_UNION {
                continue;
            }
            if self.name(rec.name_off)? == name {
                if found.is_some() {
                    return Err(SessionError::Offsets(format!(
                        "BTF ambiguous: several {name} structs"
                    )));
                }
                found = Some(rec);
            }
        }
        Ok(found)
    }

    /// The single struct (or union) record with this name.
    fn struct_record(&self, name: &str) -> Result<&TypeRec<'a>, SessionError> {
        self.struct_record_opt(name)?
            .ok_or_else(|| SessionError::Offsets(format!("BTF missing: struct {name}")))
    }

    /// Byte size of the named struct.
    pub(crate) fn struct_size(&self, name: &str) -> Result<u32, SessionError> {
        Ok(self.struct_record(name)?.size_or_type)
    }

    /// Byte offset and width of the named member, or `None` when the
    /// struct or member is genuinely absent. Present-but-malformed
    /// members (bitfield, misalignment, oversize) and corrupt images
    /// refuse: callers must never mistake them for absence.
    pub(crate) fn struct_member_opt(
        &self,
        name: &str,
        member: &str,
    ) -> Result<Option<(u32, u32)>, SessionError> {
        let Some(rec) = self.struct_record_opt(name)? else {
            return Ok(None);
        };
        for index in 0..usize::from(rec.vlen) {
            let at = index * 12;
            let (Some(member_name), Some(member_type), Some(raw_off)) = (
                read_u32(rec.payload, at),
                read_u32(rec.payload, at + 4),
                read_u32(rec.payload, at + 8),
            ) else {
                return Err(SessionError::Offsets(format!(
                    "BTF invalid: struct {name} member truncated"
                )));
            };
            if self.name(member_name)? != member {
                continue;
            }
            // With kind_flag set, the high 8 bits carry the bitfield width
            // (0 for plain members) and the low 24 are the bit offset; the
            // nonzero-width arm above already refused true bitfields. Without
            // the flag the whole word is the bit offset, so the mask applies
            // only to the flagged encoding: masking an unflagged word would
            // silently wrap bit offsets at or above 2^24 (2 MiB members).
            if rec.kind_flag && raw_off >> 24 != 0 {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: {name}.{member} is a bitfield"
                )));
            }
            let bit_off = if rec.kind_flag {
                raw_off & 0x00FF_FFFF
            } else {
                raw_off
            };
            if bit_off % 8 != 0 {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: {name}.{member} is not byte-aligned"
                )));
            }
            let off = bit_off / 8;
            let width = u32::try_from(self.size_of(member_type)?).map_err(|_| {
                SessionError::Offsets(format!("BTF invalid: {name}.{member} too large"))
            })?;
            return Ok(Some((off, width)));
        }
        Ok(None)
    }

    /// Byte offset and width of the named member. Bitfields refuse: the
    /// probe reads whole bytes only.
    pub(crate) fn struct_member(
        &self,
        name: &str,
        member: &str,
    ) -> Result<(u32, u32), SessionError> {
        self.struct_member_opt(name, member)?
            .ok_or_else(|| SessionError::Offsets(format!("BTF missing: {name}.{member}")))
    }

    /// Name of the struct the named member points to, through modifiers.
    pub(crate) fn member_points_to(
        &self,
        name: &str,
        member: &str,
    ) -> Result<String, SessionError> {
        let rec = self.struct_record(name)?;
        for index in 0..usize::from(rec.vlen) {
            let at = index * 12;
            let (Some(member_name), Some(member_type)) =
                (read_u32(rec.payload, at), read_u32(rec.payload, at + 4))
            else {
                return Err(SessionError::Offsets(format!(
                    "BTF invalid: struct {name} member truncated"
                )));
            };
            if self.name(member_name)? != member {
                continue;
            }
            let resolved = self.resolve(member_type)?;
            let target = self.record(resolved)?;
            if target.kind != KIND_PTR {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: {name}.{member} is not a pointer"
                )));
            }
            let pointee = self.resolve(target.size_or_type)?;
            let pointee_rec = self.record(pointee)?;
            if pointee_rec.kind != KIND_STRUCT && pointee_rec.kind != KIND_UNION {
                return Err(SessionError::Offsets(format!(
                    "BTF refused: {name}.{member} does not point at a struct"
                )));
            }
            return Ok(self.name(pointee_rec.name_off)?.to_owned());
        }
        Err(SessionError::Offsets(format!(
            "BTF missing: {name}.{member}"
        )))
    }

    /// Value of one enumerator in the named enum (plain or 64-bit).
    pub(crate) fn enum_value(&self, name: &str, enumerator: &str) -> Result<u32, SessionError> {
        let mut found = None;
        for rec in &self.types {
            if rec.kind != KIND_ENUM && rec.kind != KIND_ENUM64 {
                continue;
            }
            if self.name(rec.name_off)? == name {
                if found.is_some() {
                    return Err(SessionError::Offsets(format!(
                        "BTF ambiguous: several {name} enums"
                    )));
                }
                found = Some(rec);
            }
        }
        let Some(rec) = found else {
            return Err(SessionError::Offsets(format!("BTF missing: enum {name}")));
        };
        if rec.kind == KIND_ENUM {
            for index in 0..usize::from(rec.vlen) {
                let at = index * 8;
                let (Some(value_name), Some(value)) =
                    (read_u32(rec.payload, at), read_u32(rec.payload, at + 4))
                else {
                    return Err(SessionError::Offsets(format!(
                        "BTF invalid: enum {name} truncated"
                    )));
                };
                if self.name(value_name)? == enumerator {
                    return Ok(value);
                }
            }
        } else {
            for index in 0..usize::from(rec.vlen) {
                let at = index * 12;
                let (Some(value_name), Some(lo), Some(hi)) = (
                    read_u32(rec.payload, at),
                    read_u32(rec.payload, at + 4),
                    read_u32(rec.payload, at + 8),
                ) else {
                    return Err(SessionError::Offsets(format!(
                        "BTF invalid: enum {name} truncated"
                    )));
                };
                if self.name(value_name)? == enumerator {
                    if hi != 0 {
                        return Err(SessionError::Offsets(format!(
                            "BTF refused: {name}.{enumerator} exceeds u32"
                        )));
                    }
                    return Ok(lo);
                }
            }
        }
        Err(SessionError::Offsets(format!(
            "BTF missing: {name}.{enumerator}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a tiny synthetic BTF image: `struct pool { u64 start; u32 *slots;
    /// u8 tag; }` (size 24), `struct slot { }` (size 8), and `enum dir {
    /// TO = 1, FROM = 2 }`.
    fn synthetic() -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut intern = |text: &str| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let pool = intern("pool");
        let slot = intern("slot");
        let dir = intern("dir");
        let start = intern("start");
        let slots = intern("slots");
        let tag = intern("tag");
        let to = intern("TO");
        let from = intern("FROM");
        let u64_name = intern("u64");
        let u32_name = intern("u32");
        let u8_name = intern("u8");

        let mut types = Vec::new();
        let mut record = |name: u32, kind: u8, vlen: u16, size: u32, payload: &[u8]| {
            types.extend_from_slice(&name.to_le_bytes());
            let info = u32::from(kind) << 24 | u32::from(vlen);
            types.extend_from_slice(&info.to_le_bytes());
            types.extend_from_slice(&size.to_le_bytes());
            types.extend_from_slice(payload);
        };
        // id 1: u64 INT.
        record(u64_name, KIND_INT, 0, 8, &1u32.to_le_bytes());
        // id 2: u32 INT.
        record(u32_name, KIND_INT, 0, 4, &1u32.to_le_bytes());
        // id 3: u8 INT.
        record(u8_name, KIND_INT, 0, 1, &1u32.to_le_bytes());
        // id 4: struct slot (size 8).
        record(slot, KIND_STRUCT, 0, 8, &[]);
        // id 5: PTR to id 4 (struct slot).
        record(0, KIND_PTR, 0, 4, &[]);
        // id 6: struct pool: start @0:8, slots @8:8, tag @16:1.
        let mut members = Vec::new();
        for (name, ty, off) in [(start, 1u32, 0u32), (slots, 5, 64), (tag, 3, 128)] {
            members.extend_from_slice(&name.to_le_bytes());
            members.extend_from_slice(&ty.to_le_bytes());
            members.extend_from_slice(&off.to_le_bytes());
        }
        record(pool, KIND_STRUCT, 3, 24, &members);
        // id 7: enum dir.
        let mut values = Vec::new();
        for (name, value) in [(to, 1u32), (from, 2u32)] {
            values.extend_from_slice(&name.to_le_bytes());
            values.extend_from_slice(&value.to_le_bytes());
        }
        record(dir, KIND_ENUM, 2, 4, &values);

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
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
    fn synthetic_members_sizes_and_enum() {
        let image = synthetic();
        let btf = Btf::parse(&image).expect("synthetic image must parse");
        assert_eq!(btf.struct_size("pool"), Ok(24));
        assert_eq!(btf.struct_member("pool", "start"), Ok((0, 8)));
        assert_eq!(btf.struct_member("pool", "slots"), Ok((8, 8)));
        assert_eq!(btf.struct_member("pool", "tag"), Ok((16, 1)));
        assert_eq!(btf.member_points_to("pool", "slots"), Ok("slot".to_owned()));
        // start is a plain u64, not a pointer: the pointee check refuses.
        assert!(btf.member_points_to("pool", "start").is_err());
        assert!(btf.struct_member("pool", "nope").is_err());
        assert!(btf.struct_member("nope", "start").is_err());
        assert_eq!(btf.enum_value("dir", "TO"), Ok(1));
        assert_eq!(btf.enum_value("dir", "FROM"), Ok(2));
        assert!(btf.enum_value("dir", "NOPE").is_err());
    }

    #[test]
    fn member_opt_separates_absence_from_malformed() {
        let image = synthetic();
        let btf = Btf::parse(&image).expect("synthetic image must parse");
        assert_eq!(btf.struct_member_opt("pool", "start"), Ok(Some((0, 8))));
        // Missing struct or member yields None, never an error.
        assert_eq!(btf.struct_member_opt("pool", "nope"), Ok(None));
        assert_eq!(btf.struct_member_opt("nope", "start"), Ok(None));
        // The strict lookup keeps refusing absence with the missing marker.
        let error = btf
            .struct_member("pool", "nope")
            .expect_err("missing member must refuse");
        assert!(
            error.to_string().contains("BTF missing:"),
            "want the missing marker, got: {error}"
        );
    }

    #[test]
    fn truncated_and_garbage_refused() {
        let image = synthetic();
        assert!(Btf::parse(&[]).is_err());
        assert!(Btf::parse(&image[..10]).is_err());
        assert!(Btf::parse(&image[..image.len() - 8]).is_err());
        let mut bad = image.clone();
        bad[0] ^= 0xff;
        assert!(Btf::parse(&bad).is_err());
        let mut bad = image.clone();
        bad[2] = 9;
        assert!(Btf::parse(&bad).is_err());
        // An unterminated string-table tail refuses at parse: callers
        // must never mistake a corrupt image for absent fields.
        let mut bad = image;
        assert_eq!(bad.last(), Some(&0));
        let last = bad.len() - 1;
        bad[last] = b'x';
        assert!(Btf::parse(&bad).is_err());
    }

    /// Build a one-member image: `struct big` with a single `u64 field`
    /// at the caller-chosen raw offset word and kind flag.
    fn flagged_image(kind_flag: bool, raw_off: u32) -> Vec<u8> {
        let mut strings = vec![0u8];
        let mut intern = |text: &str| -> u32 {
            let at = strings.len() as u32;
            strings.extend_from_slice(text.as_bytes());
            strings.push(0);
            at
        };
        let big = intern("big");
        let field = intern("field");
        let u64_name = intern("u64");

        let mut types = Vec::new();
        let mut record = |name: u32, info: u32, size: u32, payload: &[u8]| {
            types.extend_from_slice(&name.to_le_bytes());
            types.extend_from_slice(&info.to_le_bytes());
            types.extend_from_slice(&size.to_le_bytes());
            types.extend_from_slice(payload);
        };
        // id 1: u64 INT.
        record(u64_name, u32::from(KIND_INT) << 24, 8, &1u32.to_le_bytes());
        // id 2: struct big with one member at the raw offset word.
        let mut info = u32::from(KIND_STRUCT) << 24 | 1;
        if kind_flag {
            info |= 1 << 31;
        }
        let mut members = Vec::new();
        members.extend_from_slice(&field.to_le_bytes());
        members.extend_from_slice(&1u32.to_le_bytes());
        members.extend_from_slice(&raw_off.to_le_bytes());
        record(big, info, 0x200008, &members);

        let mut out = Vec::new();
        out.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        out.push(BTF_VERSION);
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
    fn member_offset_mask_follows_kind_flag() {
        // Unflagged: the whole word is the bit offset, so a 2^24-bit
        // (2 MiB) member resolves instead of wrapping to zero.
        let image = flagged_image(false, 0x0100_0000);
        let btf = Btf::parse(&image).expect("unflagged image must parse");
        assert_eq!(btf.struct_member("big", "field"), Ok((0x200000, 8)));
        // Flagged with a zero width byte: the low 24 bits are the bit
        // offset and the mask still applies.
        let image = flagged_image(true, 0x0001_0000);
        let btf = Btf::parse(&image).expect("flagged image must parse");
        assert_eq!(btf.struct_member("big", "field"), Ok((0x2000, 8)));
        // Flagged with a nonzero width byte: a bitfield, refused.
        let image = flagged_image(true, (5 << 24) | 16);
        let btf = Btf::parse(&image).expect("bitfield image must parse");
        let error = btf
            .struct_member("big", "field")
            .expect_err("bitfield must refuse");
        assert!(
            error.to_string().contains("bitfield"),
            "want the bitfield refusal, got: {error}"
        );
    }

    #[test]
    fn member_offset_mask_boundary_pinned() {
        // Just below the wrap point both encodings agree.
        let image = flagged_image(false, 0x00FF_FFF8);
        let btf = Btf::parse(&image).expect("boundary image must parse");
        assert_eq!(btf.struct_member("big", "field"), Ok((0x1FFFFF, 8)));
        let image = flagged_image(true, 0x00FF_FFF8);
        let btf = Btf::parse(&image).expect("boundary image must parse");
        assert_eq!(btf.struct_member("big", "field"), Ok((0x1FFFFF, 8)));
    }
}
