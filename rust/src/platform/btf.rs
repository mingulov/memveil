// SPDX-License-Identifier: GPL-3.0-or-later
//! Minimal BTF map-definition reader for admission.
//!
//! Locates the `.BTF` section of a BPF object, walks its type
//! section, and extracts the map definitions the product
//! needs: `mv_counts` (ARRAY geometry, pinned exactly),
//! `mv_attempts` (RINGBUF type plus its declared ring size),
//! and, for the attempt object only, `mv_offsets` (ARRAY
//! geometry, pinned exactly). The ring size becomes the live
//! `ring_bytes` identity value and the collector's post-load
//! gate; the exact expected value is pinned by the admitting
//! profile binding, never here. Anything structurally off
//! refuses: this never loads or executes anything.
//!
//! BTF layout follows `linux/btf.h` (magic 0xeB9F, kind ids
//! 0..19). `__uint` members resolve as PTR straight to ARRAY
//! with the value in `nr_elems`; `__type` members resolve as
//! PTR through modifiers to INT with the size in bytes, or
//! to STRUCT with the size in bytes for the offsets value.
//!
//! Aya/bpf-linker objects carry DATASEC `maps` (not `.maps`)
//! with Rust-newtype-wrapped VARs (ring/array wrappers through
//! a shared spine to a flat seven-u32 definition) and the
//! definition bytes in the ELF `maps` section in DATASEC
//! member order: bpf-linker emits zero DATASEC offsets, so
//! order is the only association. The Aya lane pins the same
//! per-map contract through that shape: wrapper sizes, member
//! counts and names, the flat leaf layout, and the ELF entry
//! geometry. Failures with a libbpf analog reuse the exact
//! libbpf diagnostic; the genuinely new modes (newtype spine,
//! trailing leaf members, missing definition bytes) share the
//! one Aya cause (`{word} bad aya map shape`).

const BTF_MAGIC: i64 = 0xEB9F;
const BTF_VERSION: i64 = 1;
/// Kernel BTF read cap: 64 MiB. Canonical home: the evidence
/// adapter and narrow import this value instead of copying it.
pub const MAX_KERNEL_BTF_BYTES: usize = 67_108_864;
const MAP_ARRAY: i64 = 2;
const MAP_RINGBUF: i64 = 27;
const MAP_HASH: i64 = 1;
/// Flat Aya definition entry bytes: seven u32 words.
const AYA_MAP_DEF_BYTES: i64 = 28;
const MAX_INT: i64 = 9_223_372_036_854_775_807;
const MIN_RING_BYTES: i64 = 4096;
const MAX_RING_BYTES: i64 = 2_147_483_648;
// Total spell-depth budget: each pointer, modifier,
// or array level consumes one step of spell_btf_type,
// and each modifier hop consumes one step of
// int_size. Hook prototypes nest a few levels deep;
// 32 is generous and cycle-safe (cycles refuse via
// this budget). Pinned by the chain31/chain32 tests.
const MAX_SPELL_DEPTH: i64 = 32;
// Total member-search budget: find_member expands each
// reached record once per resolve call and memoizes the
// relative hit, so legit searches visit a handful of
// records; past this many expansions the graph is
// adversarial and the search refuses. Pinned by the
// dag32/fan8 tests (33 and 13 visits pass) and the wide
// test (4097 visits refuse).
const MAX_FIND_VISITS: i64 = 4096;

/// One BTF map read: geometry verdict plus the ring size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMaps {
    /// True when every pinned definition held.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// The admitted ring size; 0 unless `ok`.
    pub ring_bytes: i64,
}

impl BtfMaps {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            ring_bytes: 0,
        }
    }
}

/// One object map-byte read: lower bound or refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMapBytes {
    /// True when the bound below is complete.
    pub ok: bool,
    /// Lower-bound map bytes; 0 unless `ok`.
    pub bytes: i64,
    /// Refusal detail; empty on success.
    pub message: String,
}

impl ObjectMapBytes {
    fn new() -> Self {
        Self {
            ok: false,
            bytes: 0,
            message: String::new(),
        }
    }
}

struct BtfSection {
    found: bool,
    offset: i64,
    size: i64,
}

impl BtfSection {
    fn new() -> Self {
        Self {
            found: false,
            offset: 0,
            size: 0,
        }
    }
}

fn u16le(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at]) | (i64::from(data[at + 1]) << 8)
}

fn u32le(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at])
        | (i64::from(data[at + 1]) << 8)
        | (i64::from(data[at + 2]) << 16)
        | (i64::from(data[at + 3]) << 24)
}

fn u64le(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at])
        | (i64::from(data[at + 1]) << 8)
        | (i64::from(data[at + 2]) << 16)
        | (i64::from(data[at + 3]) << 24)
        | (i64::from(data[at + 4]) << 32)
        | (i64::from(data[at + 5]) << 40)
        | (i64::from(data[at + 6]) << 48)
        | (i64::from(data[at + 7]) << 56)
}

/// NUL-terminated string at base+off, bounded by limit.
fn table_text(data: &[u8], base: i64, limit: i64, off: i64) -> Option<String> {
    if off < 0 || base + off >= limit {
        return None;
    }
    let mut end = base + off;
    while end < limit && data[end as usize] != 0 {
        end += 1;
    }
    if end >= limit {
        return None;
    }
    let raw = &data[(base + off) as usize..end as usize];
    std::str::from_utf8(raw).ok().map(str::to_string)
}

/// Locate one ELF section by exact name (fail-closed).
fn find_section(data: &[u8], want: &str) -> BtfSection {
    let mut out = BtfSection::new();
    let total = data.len() as i64;
    if total < 64 {
        return out;
    }
    if data[0] != 0x7F
        || data[1] != 0x45
        || data[2] != 0x4C
        || data[3] != 0x46
        || data[4] != 2
        || data[5] != 1
        || data[6] != 1
    {
        return out;
    }
    if u16le(data, 0x10) != 1 || u16le(data, 0x12) != 247 {
        return out;
    }
    let shoff = u64le(data, 0x28);
    let shentsize = u16le(data, 0x3A);
    let shnum = u16le(data, 0x3C);
    let shstrndx = u16le(data, 0x3E);
    if shentsize != 64 || shnum == 0 || shstrndx >= shnum {
        return out;
    }
    if shoff < 0 || shoff > total || shnum > (total - shoff) / 64 {
        return out;
    }
    let str_base = shoff + shstrndx * 64;
    let str_off = u64le(data, str_base + 24);
    let str_size = u64le(data, str_base + 32);
    if str_off < 0 || str_size < 0 || str_off > total {
        return out;
    }
    if str_size > total - str_off {
        return out;
    }
    let str_end = str_off + str_size;
    for i in 0..shnum {
        let base = shoff + i * 64;
        let sh_name = u32le(data, base);
        let Some(sec_name) = table_text(data, str_off, str_end, sh_name) else {
            return out;
        };
        if sec_name == want {
            let sec_off = u64le(data, base + 24);
            let sec_size = u64le(data, base + 32);
            if sec_off < 0 || sec_size < 0 || sec_off > total {
                return out;
            }
            if sec_size > total - sec_off {
                return out;
            }
            out.found = true;
            out.offset = sec_off;
            out.size = sec_size;
            return out;
        }
    }
    out
}

/// One walked BTF blob: type records plus string bounds.
struct BtfWalk {
    ok: bool,
    message: String,
    offsets: Vec<i64>,
    kinds: Vec<i64>,
    kflags: Vec<i64>,
    vlens: Vec<i64>,
    sizes: Vec<i64>,
    str_base: i64,
    str_end: i64,
}

impl BtfWalk {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            offsets: Vec::new(),
            kinds: Vec::new(),
            kflags: Vec::new(),
            vlens: Vec::new(),
            sizes: Vec::new(),
            str_base: 0,
            str_end: 0,
        }
    }

    /// Name of one walked record (index into the walk lists).
    fn type_name(&self, data: &[u8], rec: usize) -> Option<String> {
        let name_off = u32le(data, self.offsets[rec]);
        table_text(data, self.str_base, self.str_end, name_off)
    }

    /// Walk-list index of the VAR named want.
    ///
    /// -1 missing, -2 strings corrupt, -3 duplicate name:
    /// a map name must associate with exactly one VAR.
    fn find_var(&self, data: &[u8], want: &str) -> i64 {
        let mut found: i64 = -1;
        for i in 0..self.offsets.len() {
            if self.kinds[i] != 14 {
                continue;
            }
            let Some(text) = self.type_name(data, i) else {
                return -2;
            };
            if text == want {
                if found >= 0 {
                    return -3;
                }
                found = i as i64;
            }
        }
        found
    }

    /// Membership of VAR rec in DATASEC sec.
    ///
    /// 1 member, 0 no such DATASEC, -1 strings corrupt,
    /// -2 duplicate DATASEC, -4 VAR not listed: each map
    /// VAR must sit in the one maps DATASEC exactly.
    fn datasec_var(&self, data: &[u8], sec: &str, var_rec: i64) -> i64 {
        let mut found: i64 = -1;
        for i in 0..self.offsets.len() {
            if self.kinds[i] != 15 {
                continue;
            }
            let Some(text) = self.type_name(data, i) else {
                return -1;
            };
            if text != sec {
                continue;
            }
            if found >= 0 {
                return -2;
            }
            found = i as i64;
        }
        if found < 0 {
            return 0;
        }
        let base = self.offsets[found as usize];
        let want = var_rec + 1;
        for m in 0..self.vlens[found as usize] {
            if u32le(data, base + 12 + m * 12) == want {
                return 1;
            }
        }
        -4
    }

    /// Type id of the STRUCT member named want, or -1 (-2 corrupt).
    fn member_type(&self, data: &[u8], rec: usize, want: &str) -> i64 {
        let base = self.offsets[rec];
        for m in 0..self.vlens[rec] {
            let name_off = u32le(data, base + 12 + m * 12);
            let Some(text) = table_text(data, self.str_base, self.str_end, name_off) else {
                return -2;
            };
            if text == want {
                return u32le(data, base + 12 + m * 12 + 4);
            }
        }
        -1
    }

    /// Bit offset of the STRUCT member named want, or -1 (-2 corrupt).
    fn member_offset(&self, data: &[u8], rec: usize, want: &str) -> i64 {
        let base = self.offsets[rec];
        for m in 0..self.vlens[rec] {
            let name_off = u32le(data, base + 12 + m * 12);
            let Some(text) = table_text(data, self.str_base, self.str_end, name_off) else {
                return -2;
            };
            if text == want {
                return u32le(data, base + 12 + m * 12 + 8);
            }
        }
        -1
    }

    fn rec_valid(&self, tid: i64) -> bool {
        tid >= 1 && tid <= self.offsets.len() as i64
    }

    /// nr_elems behind a direct PTR to ARRAY, or -1.
    fn uint_value(&self, data: &[u8], tid: i64) -> i64 {
        if !self.rec_valid(tid) || self.kinds[(tid - 1) as usize] != 2 {
            return -1;
        }
        let arr = self.sizes[(tid - 1) as usize];
        if !self.rec_valid(arr) || self.kinds[(arr - 1) as usize] != 3 {
            return -1;
        }
        u32le(data, self.offsets[(arr - 1) as usize] + 20)
    }

    /// Pointee INT size through modifiers, or -1.
    fn int_size(&self, _data: &[u8], tid: i64) -> i64 {
        if !self.rec_valid(tid) || self.kinds[(tid - 1) as usize] != 2 {
            return -1;
        }
        let mut cur = self.sizes[(tid - 1) as usize];
        for _ in 0..MAX_SPELL_DEPTH {
            if !self.rec_valid(cur) {
                return -1;
            }
            let kind = self.kinds[(cur - 1) as usize];
            if kind == 1 {
                return self.sizes[(cur - 1) as usize];
            }
            if kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18 {
                return -1;
            }
            cur = self.sizes[(cur - 1) as usize];
        }
        -1
    }

    /// Pointee STRUCT size through modifiers, or -1.
    fn struct_size(&self, _data: &[u8], tid: i64) -> i64 {
        if !self.rec_valid(tid) || self.kinds[(tid - 1) as usize] != 2 {
            return -1;
        }
        let mut cur = self.sizes[(tid - 1) as usize];
        for _ in 0..MAX_SPELL_DEPTH {
            if !self.rec_valid(cur) {
                return -1;
            }
            let kind = self.kinds[(cur - 1) as usize];
            if kind == 4 {
                return self.sizes[(cur - 1) as usize];
            }
            if kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18 {
                return -1;
            }
            cur = self.sizes[(cur - 1) as usize];
        }
        -1
    }

    fn var_linkage(&self, data: &[u8], rec: i64) -> i64 {
        u32le(data, self.offsets[rec as usize] + 12)
    }
}

fn refuse_walk(message: &str) -> BtfWalk {
    let mut out = BtfWalk::new();
    out.ok = false;
    out.message = message.to_string();
    out
}

/// Walk one BTF blob into indexed type records (1-based ids).
fn walk_btf(data: &[u8], base: i64, size: i64) -> BtfWalk {
    if size < 24 {
        return refuse_walk("BTF too small");
    }
    if u16le(data, base) != BTF_MAGIC || i64::from(data[(base + 2) as usize]) != BTF_VERSION {
        return refuse_walk("bad BTF header");
    }
    let hdr_len = u32le(data, base + 4);
    let type_off = u32le(data, base + 8);
    let type_len = u32le(data, base + 12);
    let str_off = u32le(data, base + 16);
    let str_len = u32le(data, base + 20);
    if hdr_len < 24 || hdr_len > size {
        return refuse_walk("bad BTF header");
    }
    if type_off < 0 || type_len < 0 || type_off > size - hdr_len {
        return refuse_walk("BTF sections out of range");
    }
    if type_len > size - hdr_len - type_off {
        return refuse_walk("BTF sections out of range");
    }
    if str_off < 0 || str_len < 0 || str_off > size - hdr_len {
        return refuse_walk("BTF sections out of range");
    }
    if str_len > size - hdr_len - str_off {
        return refuse_walk("BTF sections out of range");
    }
    let tbase = base + hdr_len + type_off;
    let tend = tbase + type_len;
    let mut out = BtfWalk::new();
    out.str_base = base + hdr_len + str_off;
    out.str_end = out.str_base + str_len;
    let mut p = tbase;
    while p < tend {
        if p + 12 > tend {
            return refuse_walk("BTF types corrupt");
        }
        let info = u32le(data, p + 4);
        let kind = (info >> 24) & 31;
        let kflag = (info >> 31) & 1;
        // kind_flag (bit 31) changes interpretation, not
        // record layout: STRUCT/UNION members stay 12
        // bytes (bitfield offsets pack into the offset
        // word) and ENUM/ENUM64 entries stay 8/12 bytes.
        // The walk below consumes only name/type/size
        // fields the flag never relocates, so flagged
        // records stay aligned and accepted; the flag is
        // recorded per type for future consumers.
        let vlen = info & 65535;
        let extra: i64 = if kind == 1 || kind == 14 || kind == 17 {
            4
        } else if kind == 3 {
            12
        } else if kind == 4 || kind == 5 || kind == 15 {
            vlen * 12
        } else if kind == 6 || kind == 13 {
            vlen * 8
        } else if kind == 19 {
            vlen * 12
        } else if matches!(kind, 0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18) {
            0
        } else {
            return refuse_walk(&format!("unknown BTF kind {kind}"));
        };
        if p + 12 + extra > tend {
            return refuse_walk("BTF types corrupt");
        }
        out.offsets.push(p);
        out.kinds.push(kind);
        out.kflags.push(kflag);
        out.vlens.push(vlen);
        out.sizes.push(u32le(data, p + 8));
        p += 12 + extra;
    }
    if p != tend {
        return refuse_walk("BTF types corrupt");
    }
    out.ok = true;
    out.message = String::new();
    out
}

/// Map one BTF reader message to a health code, else "".
///
/// Structural failures classify as truncated or
/// malformed; anything else (missing names, prototype
/// detail) is not structural and stays unclassified.
pub fn classify_btf_message(message: &str) -> String {
    if message == "BTF too small" {
        return "btf-truncated".to_string();
    }
    if message == "BTF sections out of range" {
        return "btf-truncated".to_string();
    }
    if message == "bad BTF header" {
        return "btf-malformed".to_string();
    }
    if message == "BTF types corrupt" {
        return "btf-malformed".to_string();
    }
    if message == "BTF strings corrupt" {
        return "btf-malformed".to_string();
    }
    if message == "type id out of range" {
        return "btf-malformed".to_string();
    }
    if message.starts_with("unknown BTF kind ") {
        return "btf-malformed".to_string();
    }
    String::new()
}

/// One BTF blob health verdict: ok, or a stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfHealth {
    /// True when the blob walks cleanly.
    pub ok: bool,
    /// Stable code; empty on success.
    pub code: String,
    /// Detail; empty on success.
    pub message: String,
}

impl BtfHealth {
    fn new() -> Self {
        Self {
            ok: false,
            code: String::new(),
            message: String::new(),
        }
    }
}

/// Classify one raw BTF blob: healthy, split, or broken.
///
/// A blob that walks but whose string section starts
/// past a NUL needs its base BTF; anything failing the
/// walk classifies as truncated or malformed, never ok.
pub fn check_btf_health(data: &[u8]) -> BtfHealth {
    let mut out = BtfHealth::new();
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        out.code = classify_btf_message(&walk.message);
        out.message = walk.message.clone();
        return out;
    }
    if walk.str_end > walk.str_base && data[walk.str_base as usize] != 0 {
        out.code = "btf-split".to_string();
        out.message = "split BTF needs base (string section does not start with NUL)".to_string();
        return out;
    }
    out.ok = true;
    out
}

fn refuse_maps(message: String) -> BtfMaps {
    let mut out = BtfMaps::new();
    out.ok = false;
    out.message = message;
    out.ring_bytes = 0;
    out
}

fn is_pow2(v: i64) -> bool {
    v > 0 && (v & (v - 1)) == 0
}

/// Read the mv_counts/mv_attempts/mv_offsets definitions.
///
/// Accepts libbpf (DATASEC `.maps`) and Aya (DATASEC `maps`)
/// definitions under the same per-map contract.
/// mv_counts geometry is pinned exactly (ARRAY, key 4,
/// value 8, 6 entries); mv_attempts must be RINGBUF with
/// a sane power-of-two ring size, which is returned; the
/// mv_offsets table geometry is pinned exactly (ARRAY,
/// key 4, value 24, 1 entry). The exact expected ring
/// size is the profile binding's job, never this reader's.
pub fn read_btf_maps(data: &[u8]) -> BtfMaps {
    read_btf_maps_inner(data, "mv_attempts", "attempts", true)
}

/// Read mv_counts plus one named ringbuf map definition.
///
/// Accepts libbpf (DATASEC `.maps`) and Aya (DATASEC `maps`)
/// definitions under the same per-map contract.
/// Same pinned mv_counts geometry as read_btf_maps; the
/// named ring variable must be RINGBUF with a sane
/// power-of-two size. Diagnostics name ring_word (short
/// channel word) and ring_var (BTF variable name).
/// Tracing channels carry no offset table, so no
/// offsets pin applies here.
pub fn read_btf_maps_ring(data: &[u8], ring_var: &str, ring_word: &str) -> BtfMaps {
    read_btf_maps_inner(data, ring_var, ring_word, false)
}

/// Offsets-table geometry verdict for one walk, else "".
///
/// mv_offsets must be a defined VAR in the maps DATASEC
/// with exactly ARRAY type, 1 entry, key width 4, and a
/// 24-byte struct value (struct mv_offsets).
fn check_offsets_map(data: &[u8], walk: &BtfWalk) -> String {
    let found = walk.find_var(data, "mv_offsets");
    if found == -1 {
        return "missing mv_offsets".to_string();
    }
    if found == -2 {
        return "BTF strings corrupt".to_string();
    }
    if found == -3 {
        return "duplicate mv_offsets".to_string();
    }
    let mem = walk.datasec_var(data, ".maps", found);
    if mem == 0 {
        return "no maps DATASEC".to_string();
    }
    if mem == -1 {
        return "BTF strings corrupt".to_string();
    }
    if mem == -2 {
        return "duplicate maps DATASEC".to_string();
    }
    if mem == -4 {
        return "offsets not in maps DATASEC".to_string();
    }
    let def_struct = walk.sizes[found as usize];
    if !walk.rec_valid(def_struct) {
        return "offsets not a struct".to_string();
    }
    let rec = (def_struct - 1) as usize;
    if walk.kinds[rec] != 4 {
        return "offsets not a struct".to_string();
    }
    let link = walk.var_linkage(data, found);
    if link != 0 && link != 1 {
        return format!("offsets linkage {link}");
    }
    let otype = walk.member_type(data, rec, "type");
    if otype == -1 {
        return "offsets missing type".to_string();
    }
    if otype == -2 {
        return "BTF strings corrupt".to_string();
    }
    let otype_v = walk.uint_value(data, otype);
    if otype_v < 0 {
        return "offsets bad type".to_string();
    }
    if otype_v != MAP_ARRAY {
        return format!("offsets type {otype_v}, want 2");
    }
    let omax = walk.member_type(data, rec, "max_entries");
    if omax == -1 {
        return "offsets missing max_entries".to_string();
    }
    if omax == -2 {
        return "BTF strings corrupt".to_string();
    }
    let omax_v = walk.uint_value(data, omax);
    if omax_v < 0 {
        return "offsets bad max_entries".to_string();
    }
    if omax_v != 1 {
        return format!("offsets max_entries {omax_v}, want 1");
    }
    let okey = walk.member_type(data, rec, "key");
    if okey == -1 {
        return "offsets missing key".to_string();
    }
    if okey == -2 {
        return "BTF strings corrupt".to_string();
    }
    let okey_v = walk.int_size(data, okey);
    if okey_v < 0 {
        return "offsets bad key".to_string();
    }
    if okey_v != 4 {
        return format!("offsets key {okey_v}, want 4");
    }
    let oval = walk.member_type(data, rec, "value");
    if oval == -1 {
        return "offsets missing value".to_string();
    }
    if oval == -2 {
        return "BTF strings corrupt".to_string();
    }
    let oval_v = walk.struct_size(data, oval);
    if oval_v < 0 {
        return "offsets bad value".to_string();
    }
    if oval_v != 24 {
        return format!("offsets value {oval_v}, want 24");
    }
    String::new()
}

/// Expected Aya geometry: max < 0 selects ring-size mode.
struct AyaExpect {
    typ: i64,
    key: i64,
    val: i64,
    max: i64,
}

/// One Aya map verdict: geometry max_entries, or a refusal.
struct AyaMapVerdict {
    bad: String,
    max: i64,
}

fn aya_refuse(message: String) -> AyaMapVerdict {
    AyaMapVerdict {
        bad: message,
        max: 0,
    }
}

/// Resolve one Aya newtype spine to its flat definition STRUCT.
///
/// Ring maps wrap `def` once; array maps wrap `def` plus a
/// zero-sized marker (`_t`); both continue through the shared
/// two-hop spine to the seven-member flat leaf. Sizes, member
/// counts and names, and zero spine offsets pin the exact
/// wrapper geometry; STRUCT names stay unpinned (Rust mangling
/// instantiates them per map). Returns the walk-list index of
/// the leaf, or -1.
fn aya_def_struct(data: &[u8], walk: &BtfWalk, top: i64, want_ring: bool) -> i64 {
    if !walk.rec_valid(top) {
        return -1;
    }
    let mut rec = (top - 1) as usize;
    if walk.kinds[rec] != 4 || walk.sizes[rec] != AYA_MAP_DEF_BYTES {
        return -1;
    }
    if want_ring && walk.vlens[rec] != 1 {
        return -1;
    }
    if !want_ring {
        if walk.vlens[rec] != 2 {
            return -1;
        }
        let phantom = walk.member_type(data, rec, "_t");
        if phantom < 0 || !walk.rec_valid(phantom) {
            return -1;
        }
        let p = (phantom - 1) as usize;
        if walk.kinds[p] != 4 || walk.sizes[p] != 0 || walk.vlens[p] != 0 {
            return -1;
        }
    }
    let def = walk.member_type(data, rec, "def");
    if def < 0 || walk.member_offset(data, rec, "def") != 0 {
        return -1;
    }
    if !walk.rec_valid(def) {
        return -1;
    }
    rec = (def - 1) as usize;
    if walk.kinds[rec] != 4 || walk.sizes[rec] != AYA_MAP_DEF_BYTES || walk.vlens[rec] != 1 {
        return -1;
    }
    let inner = walk.member_type(data, rec, "__0");
    if inner < 0 || walk.member_offset(data, rec, "__0") != 0 {
        return -1;
    }
    if !walk.rec_valid(inner) {
        return -1;
    }
    rec = (inner - 1) as usize;
    if walk.kinds[rec] != 4 || walk.sizes[rec] != AYA_MAP_DEF_BYTES || walk.vlens[rec] != 1 {
        return -1;
    }
    let leaf = walk.member_type(data, rec, "value");
    if leaf < 0 || walk.member_offset(data, rec, "value") != 0 {
        return -1;
    }
    if !walk.rec_valid(leaf) {
        return -1;
    }
    rec = (leaf - 1) as usize;
    if walk.kinds[rec] != 4 || walk.sizes[rec] != AYA_MAP_DEF_BYTES || walk.vlens[rec] != 7 {
        return -1;
    }
    rec as i64
}

/// One flat-leaf member check: 1 pinned, -1 missing, -2 malformed.
///
/// A pinned member is a plain u32 at its flat bit offset.
/// Missing covers missing names and corrupt strings; the caller
/// maps the codes into the per-member vocabulary.
fn aya_leaf_member(data: &[u8], walk: &BtfWalk, rec: usize, want: &str, bit: i64) -> i64 {
    let tid = walk.member_type(data, rec, want);
    if tid == -1 || tid == -2 {
        return -1;
    }
    if !walk.rec_valid(tid) {
        return -2;
    }
    let t = (tid - 1) as usize;
    if walk.kinds[t] != 1 || walk.sizes[t] != 4 {
        return -2;
    }
    if walk.member_offset(data, rec, want) != bit {
        return -2;
    }
    1
}

/// DATASEC `maps` member-list validation plus index of one VAR.
///
/// Every member must be a VAR of offset 0 and size 28 (one flat
/// definition): bpf-linker emits zero offsets, so list order is
/// the only ELF association, and any malformed or ambiguous
/// (twice-listed) entry refuses instead of misassociating.
/// Returns the 0-based index, -1 malformed, -2 not listed.
fn aya_layout_index(data: &[u8], walk: &BtfWalk, var_rec: i64) -> i64 {
    let mut found: i64 = -1;
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 15 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            return -1;
        };
        if text != "maps" {
            continue;
        }
        if found >= 0 {
            return -1;
        }
        found = i as i64;
    }
    if found < 0 {
        return -1;
    }
    let base = walk.offsets[found as usize];
    let want = var_rec + 1;
    let mut index: i64 = -2;
    let mut seen: Vec<i64> = Vec::new();
    for m in 0..walk.vlens[found as usize] {
        let tid = u32le(data, base + 12 + m * 12);
        if !walk.rec_valid(tid) {
            return -1;
        }
        if walk.kinds[(tid - 1) as usize] != 14 {
            return -1;
        }
        if u32le(data, base + 12 + m * 12 + 4) != 0 {
            return -1;
        }
        if u32le(data, base + 12 + m * 12 + 8) != AYA_MAP_DEF_BYTES {
            return -1;
        }
        if seen.contains(&tid) {
            return -1;
        }
        seen.push(tid);
        if tid == want {
            index = m;
        }
    }
    index
}

/// One flat definition entry: (type, key, value, max), or None.
///
/// Entry order follows the DATASEC member order; the trailing
/// flag words stay unread (the pins cover geometry only).
fn aya_entry(data: &[u8], index: i64) -> Option<[i64; 4]> {
    let sec = find_section(data, "maps");
    if !sec.found {
        return None;
    }
    let at = checked_mul(index, AYA_MAP_DEF_BYTES);
    if at < 0 {
        return None;
    }
    let end = checked_add(at, 16);
    if end < 0 || end > sec.size {
        return None;
    }
    let base = sec.offset + at;
    Some([
        u32le(data, base),
        u32le(data, base + 4),
        u32le(data, base + 8),
        u32le(data, base + 12),
    ])
}

/// Check one Aya map: VAR, membership, linkage, spine, leaf, bytes, pins.
///
/// Diagnostics reuse the libbpf vocabulary wherever the failure
/// has an exact analog (missing/duplicate VARs, DATASEC
/// membership, linkage, leaf members, per-field pins); the
/// genuinely new modes (newtype spine, trailing leaf members,
/// missing definition bytes) share the one Aya cause.
fn aya_check_map(
    data: &[u8],
    walk: &BtfWalk,
    var: &str,
    word: &str,
    want_ring: bool,
    exp: &AyaExpect,
) -> AyaMapVerdict {
    let found = walk.find_var(data, var);
    if found == -1 {
        return aya_refuse(format!("missing {var}"));
    }
    if found == -2 {
        return aya_refuse("BTF strings corrupt".to_string());
    }
    if found == -3 {
        return aya_refuse(format!("duplicate {var}"));
    }
    let mem = walk.datasec_var(data, "maps", found);
    if mem == 0 {
        return aya_refuse("no maps DATASEC".to_string());
    }
    if mem == -1 {
        return aya_refuse("BTF strings corrupt".to_string());
    }
    if mem == -2 {
        return aya_refuse("duplicate maps DATASEC".to_string());
    }
    if mem == -4 {
        return aya_refuse(format!("{word} not in maps DATASEC"));
    }
    let top = walk.sizes[found as usize];
    if !walk.rec_valid(top) {
        return aya_refuse(format!("{word} not a struct"));
    }
    if walk.kinds[(top - 1) as usize] != 4 {
        return aya_refuse(format!("{word} not a struct"));
    }
    let link = walk.var_linkage(data, found);
    if link != 0 && link != 1 {
        return aya_refuse(format!("{word} linkage {link}"));
    }
    let leaf = aya_def_struct(data, walk, top, want_ring);
    if leaf < 0 {
        return aya_refuse(format!("{word} bad aya map shape"));
    }
    let leaf_rec = leaf as usize;
    for (member, field, bit) in [
        ("type_", "type", 0),
        ("max_entries", "max_entries", 96),
        ("key_size", "key", 32),
        ("value_size", "value", 64),
    ] {
        let pin = aya_leaf_member(data, walk, leaf_rec, member, bit);
        if pin == -1 {
            return aya_refuse(format!("{word} missing {field}"));
        }
        if pin != 1 {
            return aya_refuse(format!("{word} bad {field}"));
        }
    }
    for (member, bit) in [("map_flags", 128), ("id", 160), ("pinning", 192)] {
        if aya_leaf_member(data, walk, leaf_rec, member, bit) != 1 {
            return aya_refuse(format!("{word} bad aya map shape"));
        }
    }
    let index = aya_layout_index(data, walk, found);
    if index == -1 {
        return aya_refuse("bad maps DATASEC".to_string());
    }
    if index < 0 {
        return aya_refuse(format!("{word} not in maps DATASEC"));
    }
    let Some(entry) = aya_entry(data, index) else {
        return aya_refuse(format!("{word} bad aya map shape"));
    };
    if entry[0] != exp.typ {
        return aya_refuse(format!("{} type {}, want {}", word, entry[0], exp.typ));
    }
    if exp.max < 0 {
        if !(MIN_RING_BYTES..=MAX_RING_BYTES).contains(&entry[3]) || !is_pow2(entry[3]) {
            return aya_refuse(format!("{word} ring size {} rejected", entry[3]));
        }
    } else {
        if entry[3] != exp.max {
            return aya_refuse(format!(
                "{} max_entries {}, want {}",
                word, entry[3], exp.max
            ));
        }
        if entry[1] != exp.key {
            return aya_refuse(format!("{} key {}, want {}", word, entry[1], exp.key));
        }
        if entry[2] != exp.val {
            return aya_refuse(format!("{} value {}, want {}", word, entry[2], exp.val));
        }
    }
    AyaMapVerdict {
        bad: String::new(),
        max: entry[3],
    }
}

/// Shared worker, Aya lane: DATASEC `maps` plus ELF definitions.
///
/// Same map contract as the libbpf lane (pinned counts geometry,
/// ring type plus sane size, pinned offsets table for attempts);
/// only the definition source differs (newtype spine plus flat
/// ELF entries instead of `__uint`/`__type` spellings).
fn read_aya_maps_inner(
    data: &[u8],
    walk: &BtfWalk,
    ring_var: &str,
    ring_word: &str,
    want_offsets: bool,
) -> BtfMaps {
    let counts_exp = AyaExpect {
        typ: MAP_ARRAY,
        key: 4,
        val: 8,
        max: 6,
    };
    let checked = aya_check_map(data, walk, "mv_counts", "counts", false, &counts_exp);
    if !checked.bad.is_empty() {
        return refuse_maps(checked.bad);
    }
    let ring_exp = AyaExpect {
        typ: MAP_RINGBUF,
        key: 0,
        val: 0,
        max: -1,
    };
    let rung = aya_check_map(data, walk, ring_var, ring_word, true, &ring_exp);
    if !rung.bad.is_empty() {
        return refuse_maps(rung.bad);
    }
    if want_offsets {
        let off_exp = AyaExpect {
            typ: MAP_ARRAY,
            key: 4,
            val: 24,
            max: 1,
        };
        let off = aya_check_map(data, walk, "mv_offsets", "offsets", false, &off_exp);
        if !off.bad.is_empty() {
            return refuse_maps(off.bad);
        }
    }
    let mut out = BtfMaps::new();
    out.ok = true;
    out.message = String::new();
    out.ring_bytes = rung.max;
    out
}

/// Shared worker: read_btf_maps with a ring variable name.
fn read_btf_maps_inner(
    data: &[u8],
    ring_var: &str,
    ring_word: &str,
    want_offsets: bool,
) -> BtfMaps {
    let sec = find_section(data, ".BTF");
    if !sec.found {
        return refuse_maps("no BTF section".to_string());
    }
    let walk = walk_btf(data, sec.offset, sec.size);
    if !walk.ok {
        return refuse_maps(walk.message.clone());
    }
    let counts = walk.find_var(data, "mv_counts");
    if counts == -1 {
        return refuse_maps("missing mv_counts".to_string());
    }
    if counts == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if counts == -3 {
        return refuse_maps("duplicate mv_counts".to_string());
    }
    // Lane select: libbpf objects list counts in DATASEC
    // `.maps`, Aya objects in DATASEC `maps`. Corrupt strings
    // or a duplicated DATASEC of either spelling refuse before
    // any lane runs; an object listing counts in `.maps` stays
    // on the libbpf lane below whatever else it carries, and an
    // object listing counts only in `maps` takes the Aya lane.
    // Objects without either spelling, or listing counts in
    // neither, refuse in the existing vocabulary.
    let cmem = walk.datasec_var(data, ".maps", counts);
    let amem = walk.datasec_var(data, "maps", counts);
    if cmem == -1 || amem == -1 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if cmem == -2 || amem == -2 {
        return refuse_maps("duplicate maps DATASEC".to_string());
    }
    if cmem != 1 && amem != 1 {
        if cmem == 0 && amem == 0 {
            return refuse_maps("no maps DATASEC".to_string());
        }
        return refuse_maps("counts not in maps DATASEC".to_string());
    }
    if cmem != 1 {
        return read_aya_maps_inner(data, &walk, ring_var, ring_word, want_offsets);
    }
    let counts_struct = walk.sizes[counts as usize];
    if !walk.rec_valid(counts_struct) {
        return refuse_maps("counts not a struct".to_string());
    }
    let cs = (counts_struct - 1) as usize;
    if walk.kinds[cs] != 4 {
        return refuse_maps("counts not a struct".to_string());
    }
    let link = walk.var_linkage(data, counts);
    if link != 0 && link != 1 {
        return refuse_maps(format!("counts linkage {link}"));
    }
    let ctype = walk.member_type(data, cs, "type");
    if ctype == -1 {
        return refuse_maps("counts missing type".to_string());
    }
    if ctype == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let ctype_v = walk.uint_value(data, ctype);
    if ctype_v < 0 {
        return refuse_maps("counts bad type".to_string());
    }
    if ctype_v != MAP_ARRAY {
        return refuse_maps(format!("counts type {ctype_v}, want 2"));
    }
    let cmax = walk.member_type(data, cs, "max_entries");
    if cmax == -1 {
        return refuse_maps("counts missing max_entries".to_string());
    }
    if cmax == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let cmax_v = walk.uint_value(data, cmax);
    if cmax_v < 0 {
        return refuse_maps("counts bad max_entries".to_string());
    }
    if cmax_v != 6 {
        return refuse_maps(format!("counts max_entries {cmax_v}, want 6"));
    }
    let ckey = walk.member_type(data, cs, "key");
    if ckey == -1 {
        return refuse_maps("counts missing key".to_string());
    }
    if ckey == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let ckey_v = walk.int_size(data, ckey);
    if ckey_v < 0 {
        return refuse_maps("counts bad key".to_string());
    }
    if ckey_v != 4 {
        return refuse_maps(format!("counts key {ckey_v}, want 4"));
    }
    let cval = walk.member_type(data, cs, "value");
    if cval == -1 {
        return refuse_maps("counts missing value".to_string());
    }
    if cval == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let cval_v = walk.int_size(data, cval);
    if cval_v < 0 {
        return refuse_maps("counts bad value".to_string());
    }
    if cval_v != 8 {
        return refuse_maps(format!("counts value {cval_v}, want 8"));
    }
    let attempts = walk.find_var(data, ring_var);
    if attempts == -1 {
        return refuse_maps(format!("missing {ring_var}"));
    }
    if attempts == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if attempts == -3 {
        return refuse_maps(format!("duplicate {ring_var}"));
    }
    let amem = walk.datasec_var(data, ".maps", attempts);
    if amem == 0 {
        return refuse_maps("no maps DATASEC".to_string());
    }
    if amem == -1 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if amem == -2 {
        return refuse_maps("duplicate maps DATASEC".to_string());
    }
    if amem == -4 {
        return refuse_maps(format!("{ring_word} not in maps DATASEC"));
    }
    let attempts_struct = walk.sizes[attempts as usize];
    if !walk.rec_valid(attempts_struct) {
        return refuse_maps(format!("{ring_word} not a struct"));
    }
    let aus = (attempts_struct - 1) as usize;
    if walk.kinds[aus] != 4 {
        return refuse_maps(format!("{ring_word} not a struct"));
    }
    let alink = walk.var_linkage(data, attempts);
    if alink != 0 && alink != 1 {
        return refuse_maps(format!("{ring_word} linkage {alink}"));
    }
    let atype = walk.member_type(data, aus, "type");
    if atype == -1 {
        return refuse_maps(format!("{ring_word} missing type"));
    }
    if atype == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let atype_v = walk.uint_value(data, atype);
    if atype_v < 0 {
        return refuse_maps(format!("{ring_word} bad type"));
    }
    if atype_v != MAP_RINGBUF {
        return refuse_maps(format!("{ring_word} type {atype_v}, want 27"));
    }
    let amax = walk.member_type(data, aus, "max_entries");
    if amax == -1 {
        return refuse_maps(format!("{ring_word} missing max_entries"));
    }
    if amax == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let ring = walk.uint_value(data, amax);
    if ring < 0 {
        return refuse_maps(format!("{ring_word} bad max_entries"));
    }
    if !(MIN_RING_BYTES..=MAX_RING_BYTES).contains(&ring) || !is_pow2(ring) {
        return refuse_maps(format!("{ring_word} ring size {ring} rejected"));
    }
    if want_offsets {
        let bad = check_offsets_map(data, &walk);
        if !bad.is_empty() {
            return refuse_maps(bad);
        }
    }
    let mut out = BtfMaps::new();
    out.ok = true;
    out.message = String::new();
    out.ring_bytes = ring;
    out
}

fn refuse_map_bytes(message: String) -> ObjectMapBytes {
    let mut out = ObjectMapBytes::new();
    out.message = message;
    out
}

fn round8(v: i64) -> i64 {
    ((v.wrapping_add(7)) / 8).wrapping_mul(8)
}

/// a + b, or -1 on overflow (inputs non-negative).
fn checked_add(a: i64, b: i64) -> i64 {
    if a > MAX_INT - b {
        return -1;
    }
    a + b
}

/// a * b, or -1 on overflow (inputs non-negative).
fn checked_mul(a: i64, b: i64) -> i64 {
    if a != 0 && b > MAX_INT / a {
        return -1;
    }
    a * b
}

/// Map key/value byte size: INT or STRUCT, or -1.
fn map_value_size(walk: &BtfWalk, data: &[u8], tid: i64) -> i64 {
    let size = walk.int_size(data, tid);
    if size >= 0 {
        return size;
    }
    walk.struct_size(data, tid)
}

/// Lower-bound map bytes over every map in .maps.
///
/// Ringbuf counts max_entries; array counts max_entries
/// times the rounded value size; hash counts max_entries
/// times the rounded key and value sizes. Any other map
/// type refuses; an object without a maps DATASEC holds
/// zero bytes.
pub fn read_object_map_bytes(data: &[u8]) -> ObjectMapBytes {
    let sec = find_section(data, ".BTF");
    if !sec.found {
        return refuse_map_bytes("no BTF section".to_string());
    }
    let walk = walk_btf(data, sec.offset, sec.size);
    if !walk.ok {
        return refuse_map_bytes(walk.message.clone());
    }
    let mut found: i64 = -1;
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 15 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            return refuse_map_bytes("BTF strings corrupt".to_string());
        };
        if text != ".maps" {
            continue;
        }
        if found >= 0 {
            return refuse_map_bytes("duplicate maps DATASEC".to_string());
        }
        found = i as i64;
    }
    let mut out = ObjectMapBytes::new();
    out.ok = true;
    if found < 0 {
        return out;
    }
    let base = walk.offsets[found as usize];
    for m in 0..walk.vlens[found as usize] {
        let var_tid = u32le(data, base + 12 + m * 12);
        if !walk.rec_valid(var_tid) {
            return refuse_map_bytes("bad maps DATASEC".to_string());
        }
        let rec = (var_tid - 1) as usize;
        if walk.kinds[rec] != 14 {
            return refuse_map_bytes("bad maps DATASEC".to_string());
        }
        let Some(name) = walk.type_name(data, rec) else {
            return refuse_map_bytes("BTF strings corrupt".to_string());
        };
        let struct_tid = walk.sizes[rec];
        if !walk.rec_valid(struct_tid) {
            return refuse_map_bytes(format!("{name} not a struct"));
        }
        let srec = (struct_tid - 1) as usize;
        if walk.kinds[srec] != 4 {
            return refuse_map_bytes(format!("{name} not a struct"));
        }
        let type_tid = walk.member_type(data, srec, "type");
        if type_tid == -1 {
            return refuse_map_bytes(format!("{name} missing type"));
        }
        if type_tid == -2 {
            return refuse_map_bytes("BTF strings corrupt".to_string());
        }
        let map_n = walk.uint_value(data, type_tid);
        if map_n < 0 {
            return refuse_map_bytes(format!("{name} bad type"));
        }
        let max_tid = walk.member_type(data, srec, "max_entries");
        if max_tid == -1 {
            return refuse_map_bytes(format!("{name} missing max_entries"));
        }
        if max_tid == -2 {
            return refuse_map_bytes("BTF strings corrupt".to_string());
        }
        let map_m = walk.uint_value(data, max_tid);
        if map_m < 0 {
            return refuse_map_bytes(format!("{name} bad max_entries"));
        }
        if map_n == MAP_RINGBUF {
            let total = checked_add(out.bytes, map_m);
            if total < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            out.bytes = total;
        } else if map_n == MAP_ARRAY {
            let key_tid = walk.member_type(data, srec, "key");
            if key_tid == -1 {
                return refuse_map_bytes(format!("{name} missing key"));
            }
            if key_tid == -2 {
                return refuse_map_bytes("BTF strings corrupt".to_string());
            }
            let val_tid = walk.member_type(data, srec, "value");
            if val_tid == -1 {
                return refuse_map_bytes(format!("{name} missing value"));
            }
            if val_tid == -2 {
                return refuse_map_bytes("BTF strings corrupt".to_string());
            }
            let val_size = map_value_size(&walk, data, val_tid);
            if val_size < 0 {
                return refuse_map_bytes(format!("{name} bad value"));
            }
            let add = checked_mul(map_m, round8(val_size));
            if add < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            let total = checked_add(out.bytes, add);
            if total < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            out.bytes = total;
        } else if map_n == MAP_HASH {
            let key_tid = walk.member_type(data, srec, "key");
            if key_tid == -1 {
                return refuse_map_bytes(format!("{name} missing key"));
            }
            if key_tid == -2 {
                return refuse_map_bytes("BTF strings corrupt".to_string());
            }
            let key_size = map_value_size(&walk, data, key_tid);
            if key_size < 0 {
                return refuse_map_bytes(format!("{name} bad key"));
            }
            let val_tid = walk.member_type(data, srec, "value");
            if val_tid == -1 {
                return refuse_map_bytes(format!("{name} missing value"));
            }
            if val_tid == -2 {
                return refuse_map_bytes("BTF strings corrupt".to_string());
            }
            let val_size = map_value_size(&walk, data, val_tid);
            if val_size < 0 {
                return refuse_map_bytes(format!("{name} bad value"));
            }
            let each = checked_add(round8(key_size), round8(val_size));
            if each < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            let add = checked_mul(map_m, each);
            if add < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            let total = checked_add(out.bytes, add);
            if total < 0 {
                return refuse_map_bytes(format!("{name} size overflows"));
            }
            out.bytes = total;
        } else {
            return refuse_map_bytes(format!("unsupported map type {map_n} in {name}"));
        }
    }
    out
}

/// Read the mv_copy_fb fallback counter definition.
///
/// Pinned exactly (ARRAY, key 4, value 8, 4 entries:
/// deferred, recovered, flags, armed). Ring size unused (0).
pub fn read_btf_copy_fb(data: &[u8]) -> BtfMaps {
    let sec = find_section(data, ".BTF");
    if !sec.found {
        return refuse_maps("no BTF section".to_string());
    }
    let walk = walk_btf(data, sec.offset, sec.size);
    if !walk.ok {
        return refuse_maps(walk.message.clone());
    }
    let found = walk.find_var(data, "mv_copy_fb");
    if found == -1 {
        return refuse_maps("missing mv_copy_fb".to_string());
    }
    if found == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if found == -3 {
        return refuse_maps("duplicate mv_copy_fb".to_string());
    }
    let mem = walk.datasec_var(data, ".maps", found);
    if mem == 0 {
        return refuse_maps("no maps DATASEC".to_string());
    }
    if mem == -1 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    if mem == -2 {
        return refuse_maps("duplicate maps DATASEC".to_string());
    }
    if mem == -4 {
        return refuse_maps("fallback not in maps DATASEC".to_string());
    }
    let fb_struct = walk.sizes[found as usize];
    if !walk.rec_valid(fb_struct) {
        return refuse_maps("fallback not a struct".to_string());
    }
    let rec = (fb_struct - 1) as usize;
    if walk.kinds[rec] != 4 {
        return refuse_maps("fallback not a struct".to_string());
    }
    let link = walk.var_linkage(data, found);
    if link != 0 && link != 1 {
        return refuse_maps(format!("fallback linkage {link}"));
    }
    let ftype = walk.member_type(data, rec, "type");
    if ftype == -1 {
        return refuse_maps("fallback missing type".to_string());
    }
    if ftype == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let ftype_v = walk.uint_value(data, ftype);
    if ftype_v < 0 {
        return refuse_maps("fallback bad type".to_string());
    }
    if ftype_v != MAP_ARRAY {
        return refuse_maps(format!("fallback type {ftype_v}, want 2"));
    }
    let fmax = walk.member_type(data, rec, "max_entries");
    if fmax == -1 {
        return refuse_maps("fallback missing max_entries".to_string());
    }
    if fmax == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let fmax_v = walk.uint_value(data, fmax);
    if fmax_v < 0 {
        return refuse_maps("fallback bad max_entries".to_string());
    }
    if fmax_v != 4 {
        return refuse_maps(format!("fallback max_entries {fmax_v}, want 4"));
    }
    let fkey = walk.member_type(data, rec, "key");
    if fkey == -1 {
        return refuse_maps("fallback missing key".to_string());
    }
    if fkey == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let fkey_v = walk.int_size(data, fkey);
    if fkey_v < 0 {
        return refuse_maps("fallback bad key".to_string());
    }
    if fkey_v != 4 {
        return refuse_maps(format!("fallback key {fkey_v}, want 4"));
    }
    let fval = walk.member_type(data, rec, "value");
    if fval == -1 {
        return refuse_maps("fallback missing value".to_string());
    }
    if fval == -2 {
        return refuse_maps("BTF strings corrupt".to_string());
    }
    let fval_v = walk.int_size(data, fval);
    if fval_v < 0 {
        return refuse_maps("fallback bad value".to_string());
    }
    if fval_v != 8 {
        return refuse_maps(format!("fallback value {fval_v}, want 8"));
    }
    let mut out = BtfMaps::new();
    out.ok = true;
    out.message = String::new();
    out.ring_bytes = 0;
    out
}

/// One BTF function prototype read (canonical iff ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfFuncProto {
    /// True when the prototype spelled.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// Canonical spelling; empty unless `ok`.
    pub canonical: String,
}

impl BtfFuncProto {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            canonical: String::new(),
        }
    }
}

/// One canonical type spelling plus its pointer depth.
struct TypeSpell {
    ok: bool,
    message: String,
    text: String,
    stars: i64,
}

impl TypeSpell {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            text: String::new(),
            stars: 0,
        }
    }
}

/// One C spelling for equivalent BTF integer names.
///
/// Kernel BTF spells some integers ("long unsigned int")
/// differently from C sources ("unsigned long"). Pairs
/// below name the same LP64 x86-64 type; anything unlisted
/// passes through verbatim so unknown spellings mismatch
/// loudly at comparison instead of equating silently.
fn normalize_int_name(name: &str) -> String {
    if name == "long unsigned int" {
        return "unsigned long".to_string();
    }
    if name == "long long unsigned int" {
        return "unsigned long long".to_string();
    }
    if name == "short unsigned int" {
        return "unsigned short".to_string();
    }
    if name == "short int" {
        return "short".to_string();
    }
    if name == "long int" {
        return "long".to_string();
    }
    if name == "long long int" {
        return "long long".to_string();
    }
    name.to_string()
}

/// Expected BTF size of one normalized integer name.
///
/// LP64 x86-64 only, the product's single supported
/// shape. -1 for unknown spellings: those pass through
/// unchecked (as today) and mismatch loudly at
/// comparison instead of equating silently.
fn lp64_int_size(name: &str) -> i64 {
    if name == "char" {
        return 1;
    }
    if name == "signed char" {
        return 1;
    }
    if name == "unsigned char" {
        return 1;
    }
    if name == "bool" {
        return 1;
    }
    if name == "short" {
        return 2;
    }
    if name == "unsigned short" {
        return 2;
    }
    if name == "int" {
        return 4;
    }
    if name == "unsigned int" {
        return 4;
    }
    if name == "long" {
        return 8;
    }
    if name == "unsigned long" {
        return 8;
    }
    if name == "long long" {
        return 8;
    }
    if name == "unsigned long long" {
        return 8;
    }
    if name == "size_t" {
        return 8;
    }
    -1
}

/// Canonical structural spelling of one BTF type id.
///
/// Modifiers and tags resolve silently, pointers add one
/// star each, and the first named type stops the walk with
/// its own name (typedef names are kept, never expanded).
/// Arrays spell as element plus [n]. Anything anonymous,
/// cyclic, nested-functional, or otherwise unnameable
/// refuses: discovery must not guess at kernel types.
fn spell_btf_type(walk: &BtfWalk, data: &[u8], tid: i64, budget: i64) -> TypeSpell {
    let mut out = TypeSpell::new();
    let mut stars = 0;
    let mut cur = tid;
    let mut left = budget;
    loop {
        if left <= 0 {
            out.message = "type graph too deep".to_string();
            return out;
        }
        left -= 1;
        if cur == 0 {
            // Void spells alone or terminates pointer
            // chains (const void *, the kfree shape).
            out.ok = true;
            out.text = "void".to_string();
            out.stars = stars;
            for _ in 0..stars {
                out.text += " *";
            }
            return out;
        }
        if !walk.rec_valid(cur) {
            out.message = "type id out of range".to_string();
            return out;
        }
        let kind = walk.kinds[(cur - 1) as usize];
        if kind == 2 {
            stars += 1;
            cur = walk.sizes[(cur - 1) as usize];
            continue;
        }
        if kind == 9 || kind == 10 || kind == 11 || kind == 18 {
            cur = walk.sizes[(cur - 1) as usize];
            continue;
        }
        if kind == 3 {
            let base = walk.offsets[(cur - 1) as usize];
            let elem = u32le(data, base + 12);
            let count = u32le(data, base + 20);
            let sub = spell_btf_type(walk, data, elem, left);
            if !sub.ok {
                return sub;
            }
            out.ok = true;
            out.text = format!("{}[{count}]", sub.text);
            out.stars = stars;
            for _ in 0..stars {
                out.text += " *";
            }
            return out;
        }
        let Some(name) = walk.type_name(data, (cur - 1) as usize) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        let base: String;
        if kind == 1 || kind == 16 {
            base = normalize_int_name(&name);
            let want = lp64_int_size(&base);
            if want >= 0 && walk.sizes[(cur - 1) as usize] != want {
                let have = walk.sizes[(cur - 1) as usize];
                out.message = format!("BTF int size {have} mismatch for {base}, want {want}");
                return out;
            }
        } else if kind == 4 {
            base = format!("struct {name}");
        } else if kind == 5 {
            base = format!("union {name}");
        } else if kind == 6 || kind == 19 {
            base = format!("enum {name}");
        } else if kind == 8 {
            base = name.clone();
        } else if kind == 13 {
            out.message = "function pointer in prototype".to_string();
            return out;
        } else {
            out.message = format!("unsupported type kind {kind}");
            return out;
        }
        if name.is_empty() {
            out.message = "anonymous type in prototype".to_string();
            return out;
        }
        out.ok = true;
        out.text = base;
        out.stars = stars;
        for _ in 0..stars {
            out.text += " *";
        }
        return out;
    }
}

/// Find FUNC name in a raw BTF blob; spell its prototype.
///
/// The blob is a header-at-zero BTF image such as
/// /sys/kernel/btf/vmlinux. The canonical form is
/// "<ret> (<t0> <n0>, ...)" with typedef names kept and
/// one " *" per pointer level; empty parameter lists
/// spell "(void)". A missing, duplicated, or unspellable
/// function refuses with the exact cause.
pub fn read_btf_func_proto(data: &[u8], name: &str) -> BtfFuncProto {
    let mut out = BtfFuncProto::new();
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        out.message = walk.message.clone();
        return out;
    }
    let mut found: i64 = -1;
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 12 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if text == name {
            if found >= 0 {
                out.message = format!("duplicate function {name}");
                return out;
            }
            found = i as i64;
        }
    }
    if found < 0 {
        out.message = format!("function {name} not found");
        return out;
    }
    let proto = walk.sizes[found as usize];
    if !walk.rec_valid(proto) || walk.kinds[(proto - 1) as usize] != 13 {
        out.message = "function has no prototype".to_string();
        return out;
    }
    let ret = spell_btf_type(
        &walk,
        data,
        walk.sizes[(proto - 1) as usize],
        MAX_SPELL_DEPTH,
    );
    if !ret.ok {
        out.message = ret.message.clone();
        return out;
    }
    let mut canon = ret.text + " (";
    let pbase = walk.offsets[(proto - 1) as usize];
    let pcount = walk.vlens[(proto - 1) as usize];
    if pcount == 0 {
        canon += "void";
    }
    for m in 0..pcount {
        let pname_off = u32le(data, pbase + 12 + m * 8);
        let ptype = u32le(data, pbase + 12 + m * 8 + 4);
        let Some(pname) = table_text(data, walk.str_base, walk.str_end, pname_off) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if pname.is_empty() {
            out.message = "unnamed parameter in prototype".to_string();
            return out;
        }
        let ps = spell_btf_type(&walk, data, ptype, MAX_SPELL_DEPTH);
        if !ps.ok {
            out.message = ps.message.clone();
            return out;
        }
        if m > 0 {
            canon += ", ";
        }
        canon += &ps.text;
        if ps.stars == 0 {
            canon += " ";
        }
        canon += &pname;
    }
    canon += ")";
    out.ok = true;
    out.message = String::new();
    out.canonical = canon;
    out
}

/// One BTF function signature read: types without names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfFuncSig {
    /// True when every prototype spelled identically.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// Spelled return type.
    pub ret: String,
    /// Spelled parameter types.
    pub params: Vec<String>,
    /// Resolved INT bit width per parameter, else 0.
    pub widths: Vec<i64>,
}

impl BtfFuncSig {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            ret: String::new(),
            params: Vec::new(),
            widths: Vec::new(),
        }
    }
}

/// Resolved INT bit width when tid is a bare typedef, else 0.
///
/// Modifiers peel to the first named stop: a typedef
/// with no pointer level resolves below itself (through
/// nested typedefs and modifiers) to INT; pointers,
/// direct types, and broken chains carry no width.
fn typedef_width(walk: &BtfWalk, _data: &[u8], tid: i64) -> i64 {
    let mut cur = tid;
    for _ in 0..MAX_SPELL_DEPTH {
        if !walk.rec_valid(cur) {
            return 0;
        }
        let kind = walk.kinds[(cur - 1) as usize];
        if kind == 2 {
            return 0;
        }
        if kind == 9 || kind == 10 || kind == 11 || kind == 18 {
            cur = walk.sizes[(cur - 1) as usize];
            continue;
        }
        if kind != 8 {
            return 0;
        }
        cur = walk.sizes[(cur - 1) as usize];
        for _ in 0..MAX_SPELL_DEPTH {
            if !walk.rec_valid(cur) {
                return 0;
            }
            let sub = walk.kinds[(cur - 1) as usize];
            if sub == 1 {
                return walk.sizes[(cur - 1) as usize] * 8;
            }
            if sub != 8 && sub != 9 && sub != 10 && sub != 11 && sub != 18 {
                return 0;
            }
            cur = walk.sizes[(cur - 1) as usize];
        }
        return 0;
    }
    0
}

/// Spell one FUNC_PROTO record as types without names.
///
/// Parameter names are validated but never kept: only
/// typedef-level type spellings compare, so unnamed
/// parameters spell fine.
fn spell_proto_sig(walk: &BtfWalk, data: &[u8], proto: i64) -> BtfFuncSig {
    let mut out = BtfFuncSig::new();
    let ret = spell_btf_type(
        walk,
        data,
        walk.sizes[(proto - 1) as usize],
        MAX_SPELL_DEPTH,
    );
    if !ret.ok {
        out.message = ret.message.clone();
        return out;
    }
    out.ret = ret.text.clone();
    let pbase = walk.offsets[(proto - 1) as usize];
    let pcount = walk.vlens[(proto - 1) as usize];
    for m in 0..pcount {
        let pname_off = u32le(data, pbase + 12 + m * 8);
        let ptype = u32le(data, pbase + 12 + m * 8 + 4);
        if table_text(data, walk.str_base, walk.str_end, pname_off).is_none() {
            out.message = "BTF strings corrupt".to_string();
            return out;
        }
        let ps = spell_btf_type(walk, data, ptype, MAX_SPELL_DEPTH);
        if !ps.ok {
            out.message = ps.message.clone();
            return out;
        }
        out.params.push(ps.text.clone());
        out.widths.push(typedef_width(walk, data, ptype));
    }
    out.ok = true;
    out
}

/// True when two spelled signatures agree on types and widths.
fn func_sig_same(a: &BtfFuncSig, b: &BtfFuncSig) -> bool {
    if a.ret != b.ret {
        return false;
    }
    if a.params.len() != b.params.len() {
        return false;
    }
    for i in 0..a.params.len() {
        if a.params[i] != b.params[i] {
            return false;
        }
        if a.widths[i] != b.widths[i] {
            return false;
        }
    }
    true
}

/// Find FUNC name in a raw BTF blob; spell types sans names.
///
/// The blob is a header-at-zero BTF image such as
/// /sys/kernel/btf/vmlinux. Parameters spell at typedef
/// level without names, each carrying its resolved INT
/// bit width when it is a bare typedef, else zero.
/// Duplicate FUNC entries are accepted only when every
/// prototype spells (and widths) identically.
pub fn read_btf_func_sig(data: &[u8], name: &str) -> BtfFuncSig {
    let mut out = BtfFuncSig::new();
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        out.message = walk.message.clone();
        return out;
    }
    let mut found: Vec<i64> = Vec::new();
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 12 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if text == name {
            found.push(i as i64);
        }
    }
    if found.is_empty() {
        out.message = format!("function {name} not found");
        return out;
    }
    let first_proto = walk.sizes[found[0] as usize];
    if !walk.rec_valid(first_proto) || walk.kinds[(first_proto - 1) as usize] != 13 {
        out.message = "function has no prototype".to_string();
        return out;
    }
    let first = spell_proto_sig(&walk, data, first_proto);
    if !first.ok {
        out.message = first.message.clone();
        return out;
    }
    for f in 1..found.len() {
        let proto = walk.sizes[found[f] as usize];
        if !walk.rec_valid(proto) || walk.kinds[(proto - 1) as usize] != 13 {
            out.message = "function has no prototype".to_string();
            return out;
        }
        let sp = spell_proto_sig(&walk, data, proto);
        if !sp.ok {
            out.message = sp.message.clone();
            return out;
        }
        if !func_sig_same(&first, &sp) {
            let n = found.len();
            out.message = format!("ambiguous FUNC {name} ({n} prototypes differ)");
            return out;
        }
    }
    first
}

/// One BTF struct member read (offsets valid iff ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfMember {
    /// True when the member resolved to a plain extent.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// Bit offset of the member.
    pub bit_offset: i64,
    /// Bit width of the member type.
    pub bit_size: i64,
}

impl BtfMember {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            bit_offset: 0,
            bit_size: 0,
        }
    }
}

/// One decoded member offset word.
struct MemberPos {
    bit_offset: i64,
    bitfield_size: i64,
}

/// Split one member offset word by its struct kind_flag.
///
/// Flagged structs pack the bitfield size into the top
/// byte and the bit offset into the low 24 bits; plain
/// structs hold the bit offset alone.
fn member_pos(word: i64, kflag: i64) -> MemberPos {
    if kflag != 0 {
        MemberPos {
            bit_offset: word & 0xFF_FFFF,
            bitfield_size: (word >> 24) & 0xFF,
        }
    } else {
        MemberPos {
            bit_offset: word,
            bitfield_size: 0,
        }
    }
}

/// Find STRUCT struct_name's member field_name in a raw BTF blob.
///
/// The blob is a header-at-zero BTF image such as
/// /sys/kernel/btf/vmlinux. The member's bit offset comes
/// straight from its record; its bit size is the member
/// type's byte width times eight, resolved through
/// typedefs and modifiers (pointers are 8 bytes, integers
/// use their size field). Anything else refuses with the
/// exact cause.
pub fn read_btf_member(data: &[u8], struct_name: &str, field_name: &str) -> BtfMember {
    let mut out = BtfMember::new();
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        out.message = walk.message.clone();
        return out;
    }
    let mut found: i64 = -1;
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 4 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if text == struct_name {
            if found >= 0 {
                out.message = format!("duplicate struct {struct_name}");
                return out;
            }
            found = i as i64;
        }
    }
    if found < 0 {
        out.message = format!("struct {struct_name} not found");
        return out;
    }
    let base = walk.offsets[found as usize];
    let mut member_tid: i64 = -1;
    let mut member_off = 0;
    let mut member_found = false;
    for m in 0..walk.vlens[found as usize] {
        let name_off = u32le(data, base + 12 + m * 12);
        let Some(text) = table_text(data, walk.str_base, walk.str_end, name_off) else {
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if text == field_name {
            member_tid = u32le(data, base + 12 + m * 12 + 4);
            member_off = u32le(data, base + 12 + m * 12 + 8);
            member_found = true;
            break;
        }
    }
    if !member_found {
        out.message = format!("member {field_name} not found in {struct_name}");
        return out;
    }
    let pos = member_pos(member_off, walk.kflags[found as usize]);
    if pos.bitfield_size != 0 {
        out.message = format!("bitfield member {struct_name}.{field_name} unsupported");
        return out;
    }
    let mut size_bytes: i64 = -1;
    let mut cur = member_tid;
    for _ in 0..MAX_SPELL_DEPTH {
        if !walk.rec_valid(cur) {
            out.message = "type id out of range".to_string();
            return out;
        }
        let kind = walk.kinds[(cur - 1) as usize];
        if kind == 2 {
            size_bytes = 8;
            break;
        }
        if kind == 1 {
            size_bytes = walk.sizes[(cur - 1) as usize];
            let enc = u32le(data, walk.offsets[(cur - 1) as usize] + 12) & 0xFF;
            if enc != size_bytes * 8 || pos.bit_offset % 8 != 0 {
                out.message = format!("bitfield member {struct_name}.{field_name} unsupported");
                return out;
            }
            break;
        }
        if kind != 8 && kind != 9 && kind != 10 && kind != 11 && kind != 18 {
            out.message = format!("unsupported member type kind {kind}");
            return out;
        }
        cur = walk.sizes[(cur - 1) as usize];
    }
    if size_bytes < 0 {
        out.message = "type graph too deep".to_string();
        return out;
    }
    out.ok = true;
    out.message = String::new();
    out.bit_offset = pos.bit_offset;
    out.bit_size = size_bytes * 8;
    out
}

/// One resolved member type: kind word plus bit width.
struct TypeBits {
    ok: bool,
    message: String,
    kind: String,
    bits: i64,
    is_int: bool,
    int_bits: i64,
    int_size: i64,
}

impl TypeBits {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            kind: String::new(),
            bits: 0,
            is_int: false,
            int_bits: 0,
            int_size: 0,
        }
    }
}

/// Resolve one member type id to a kind word and bit width.
///
/// Typedefs, modifiers, and tags resolve silently within
/// the hop budget; anything else spells by its own kind.
fn type_bits(walk: &BtfWalk, data: &[u8], tid: i64, budget: i64) -> TypeBits {
    let mut out = TypeBits::new();
    let mut cur = tid;
    let mut left = budget;
    loop {
        if left <= 0 {
            out.message = "type chain too long".to_string();
            return out;
        }
        left -= 1;
        if !walk.rec_valid(cur) {
            out.message = "type id out of range".to_string();
            return out;
        }
        let kind = walk.kinds[(cur - 1) as usize];
        if kind == 8 || kind == 9 || kind == 10 || kind == 11 || kind == 18 {
            cur = walk.sizes[(cur - 1) as usize];
            continue;
        }
        if kind == 2 {
            out.ok = true;
            out.kind = "ptr".to_string();
            out.bits = 64;
            return out;
        }
        if kind == 1 || kind == 16 {
            out.ok = true;
            out.is_int = kind == 1;
            out.int_size = walk.sizes[(cur - 1) as usize];
            out.bits = walk.sizes[(cur - 1) as usize] * 8;
            if kind == 1 {
                out.kind = "int".to_string();
                let enc = u32le(data, walk.offsets[(cur - 1) as usize] + 12);
                out.int_bits = enc & 0xFF;
            } else {
                out.kind = "float".to_string();
                out.int_bits = out.bits;
            }
            return out;
        }
        if kind == 3 {
            let base = walk.offsets[(cur - 1) as usize];
            let elem = u32le(data, base + 12);
            let count = u32le(data, base + 20);
            let sub = type_bits(walk, data, elem, left);
            if !sub.ok {
                return sub;
            }
            out.ok = true;
            out.kind = "array".to_string();
            // Wrapping: the Mojo source multiplies raw u32-range
            // values here; inputs that would overflow refuse
            // elsewhere or stay deterministic, never panic.
            out.bits = count.wrapping_mul(sub.bits);
            return out;
        }
        if kind == 4 || kind == 5 || kind == 6 || kind == 19 {
            out.ok = true;
            if kind == 4 {
                out.kind = "struct".to_string();
            } else if kind == 5 {
                out.kind = "union".to_string();
            } else {
                out.kind = "enum".to_string();
            }
            out.bits = walk.sizes[(cur - 1) as usize] * 8;
            return out;
        }
        if kind == 7 {
            out.message = "member type is a forward declaration".to_string();
            return out;
        }
        out.message = format!("unsupported member type kind {kind}");
        return out;
    }
}

/// One member search outcome inside a single struct.
#[derive(Clone)]
struct MemberHit {
    found: bool,
    failed: bool,
    message: String,
    bit_offset: i64,
    member_tid: i64,
    bitfield_size: i64,
}

impl MemberHit {
    fn new() -> Self {
        Self {
            found: false,
            failed: false,
            message: String::new(),
            bit_offset: 0,
            member_tid: 0,
            bitfield_size: 0,
        }
    }
}

/// One memoized member search: relative hit per record.
///
/// `rel[rec]` holds the hit relative to that record's
/// own start, so callers add their accumulated offset;
/// only found and not-found outcomes are stored, never
/// path-dependent failures. `visits` counts record
/// expansions against MAX_FIND_VISITS.
struct FindMemo {
    done: Vec<bool>,
    rel: Vec<MemberHit>,
    visits: i64,
}

impl FindMemo {
    fn new(n: usize) -> Self {
        Self {
            done: vec![false; n],
            rel: (0..n).map(|_| MemberHit::new()).collect(),
            visits: 0,
        }
    }
}

/// Depth-first member search through anonymous members.
///
/// Anonymous STRUCT/UNION members recurse with
/// accumulated offsets; any other empty-named member is
/// skipped, never descended into. Each reached record
/// expands once: the relative hit is memoized per type
/// id, so shared subtypes cost one expansion, and the
/// visit budget refuses adversarial graphs.
fn find_member(
    walk: &BtfWalk,
    data: &[u8],
    rec: usize,
    field: &str,
    acc: i64,
    depth: i64,
    memo: &mut FindMemo,
) -> MemberHit {
    let mut out = MemberHit::new();
    if depth > MAX_SPELL_DEPTH {
        out.failed = true;
        out.message = "type graph too deep".to_string();
        return out;
    }
    if memo.done[rec] {
        let mut hit = memo.rel[rec].clone();
        hit.bit_offset += acc;
        return hit;
    }
    memo.visits += 1;
    if memo.visits > MAX_FIND_VISITS {
        out.failed = true;
        out.message = "type graph too large".to_string();
        return out;
    }
    let base = walk.offsets[rec];
    let kflag = walk.kflags[rec];
    for m in 0..walk.vlens[rec] {
        let name_off = u32le(data, base + 12 + m * 12);
        let tid = u32le(data, base + 12 + m * 12 + 4);
        let word = u32le(data, base + 12 + m * 12 + 8);
        let pos = member_pos(word, kflag);
        if name_off == 0 {
            if walk.rec_valid(tid) {
                let mkind = walk.kinds[(tid - 1) as usize];
                if mkind == 4 || mkind == 5 {
                    let sub = find_member(
                        walk,
                        data,
                        (tid - 1) as usize,
                        field,
                        acc + pos.bit_offset,
                        depth + 1,
                        memo,
                    );
                    if sub.failed {
                        return sub;
                    }
                    if sub.found {
                        let mut held = MemberHit::new();
                        held.found = true;
                        held.bit_offset = sub.bit_offset - acc;
                        held.member_tid = sub.member_tid;
                        held.bitfield_size = sub.bitfield_size;
                        memo.done[rec] = true;
                        memo.rel[rec] = held;
                        return sub;
                    }
                }
            }
            continue;
        }
        let Some(text) = table_text(data, walk.str_base, walk.str_end, name_off) else {
            out.failed = true;
            out.message = "BTF strings corrupt".to_string();
            return out;
        };
        if text == field {
            out.found = true;
            out.bit_offset = acc + pos.bit_offset;
            out.member_tid = tid;
            out.bitfield_size = pos.bitfield_size;
            let mut direct = MemberHit::new();
            direct.found = true;
            direct.bit_offset = pos.bit_offset;
            direct.member_tid = tid;
            direct.bitfield_size = pos.bitfield_size;
            memo.done[rec] = true;
            memo.rel[rec] = direct;
            return out;
        }
    }
    memo.done[rec] = true;
    memo.rel[rec] = MemberHit::new();
    out
}

/// One BTF member, type, or enumerator resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfResolved {
    /// True when the search completed (see found/ambiguous).
    pub ok: bool,
    /// True when a same-named record exists.
    pub struct_found: bool,
    /// True when the member/type/enumerator resolved.
    pub found: bool,
    /// True when candidates disagreed.
    pub ambiguous: bool,
    /// True when the resolved member is a bitfield.
    pub bitfield: bool,
    /// Bit offset (members) or 0.
    pub bit_offset: i64,
    /// Bit width of the resolved type.
    pub bit_size: i64,
    /// Kind word (`int`, `ptr`, `struct`, ...).
    pub kind: String,
    /// Refusal/ambiguity detail; empty on clean resolve.
    pub message: String,
}

impl BtfResolved {
    fn new() -> Self {
        Self {
            ok: false,
            struct_found: false,
            found: false,
            ambiguous: false,
            bitfield: false,
            bit_offset: 0,
            bit_size: 0,
            kind: String::new(),
            message: String::new(),
        }
    }
}

fn refuse_resolved(message: String) -> BtfResolved {
    let mut out = BtfResolved::new();
    out.message = message;
    out
}

/// Resolve STRUCT/UNION struct_name's member field in raw BTF.
///
/// Every same-named struct or union is a candidate; the
/// search descends into anonymous members and candidates
/// lacking the member are ignored. Candidates holding it
/// must agree on offset, size, kind, and bitfield state.
pub fn resolve_btf_member(data: &[u8], struct_name: &str, field: &str) -> BtfResolved {
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        return refuse_resolved(walk.message.clone());
    }
    let mut cands: Vec<usize> = Vec::new();
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 4 && walk.kinds[i] != 5 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            return refuse_resolved("BTF strings corrupt".to_string());
        };
        if text == struct_name {
            cands.push(i);
        }
    }
    let mut out = BtfResolved::new();
    if cands.is_empty() {
        out.ok = true;
        return out;
    }
    out.struct_found = true;
    let mut offs: Vec<i64> = Vec::new();
    let mut sizes: Vec<i64> = Vec::new();
    let mut kinds: Vec<String> = Vec::new();
    let mut bfs: Vec<bool> = Vec::new();
    let mut memo = FindMemo::new(walk.offsets.len());
    for &cand in &cands {
        let hit = find_member(&walk, data, cand, field, 0, 0, &mut memo);
        if hit.failed {
            return refuse_resolved(hit.message.clone());
        }
        if !hit.found {
            continue;
        }
        let tb = type_bits(&walk, data, hit.member_tid, MAX_SPELL_DEPTH);
        if !tb.ok {
            return refuse_resolved(tb.message.clone());
        }
        let mut is_bf = hit.bitfield_size != 0;
        let mut bsize = tb.bits;
        if is_bf {
            bsize = hit.bitfield_size;
        } else if tb.is_int && (tb.int_bits != tb.int_size * 8 || hit.bit_offset % 8 != 0) {
            is_bf = true;
            bsize = tb.int_bits;
        }
        offs.push(hit.bit_offset);
        sizes.push(bsize);
        kinds.push(tb.kind.clone());
        bfs.push(is_bf);
    }
    if offs.is_empty() {
        out.ok = true;
        return out;
    }
    for h in 1..offs.len() {
        if offs[h] != offs[0] || sizes[h] != sizes[0] || kinds[h] != kinds[0] || bfs[h] != bfs[0] {
            out.ambiguous = true;
            let ndefs = offs.len();
            out.message = format!("struct {struct_name}: {ndefs} definitions disagree on {field}");
            return out;
        }
    }
    out.ok = true;
    out.found = true;
    out.bitfield = bfs[0];
    out.bit_offset = offs[0];
    out.bit_size = sizes[0];
    out.kind = kinds[0].clone();
    out.message = String::new();
    out
}

/// Resolve one named STRUCT, UNION, ENUM, or TYPEDEF.
///
/// Same-named candidates must agree on kind and size;
/// typedefs resolve through to their terminal kind.
pub fn resolve_btf_type(data: &[u8], name: &str, kind: &str) -> BtfResolved {
    let want_struct = kind == "struct";
    let want_union = kind == "union";
    let want_enum = kind == "enum";
    let want_typedef = kind == "typedef";
    if !want_struct && !want_union && !want_enum && !want_typedef {
        return refuse_resolved(format!("unknown type kind {kind}"));
    }
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        return refuse_resolved(walk.message.clone());
    }
    let mut cands: Vec<usize> = Vec::new();
    for i in 0..walk.offsets.len() {
        let k = walk.kinds[i];
        let mut kind_hit = false;
        if want_struct && k == 4 {
            kind_hit = true;
        }
        if want_union && k == 5 {
            kind_hit = true;
        }
        if want_enum && (k == 6 || k == 19) {
            kind_hit = true;
        }
        if want_typedef && k == 8 {
            kind_hit = true;
        }
        if !kind_hit {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            return refuse_resolved("BTF strings corrupt".to_string());
        };
        if text == name {
            cands.push(i);
        }
    }
    let mut out = BtfResolved::new();
    if cands.is_empty() {
        out.ok = true;
        return out;
    }
    out.struct_found = true;
    let mut sizes: Vec<i64> = Vec::new();
    let mut kinds: Vec<String> = Vec::new();
    for &rec in &cands {
        let k = walk.kinds[rec];
        if k == 4 {
            sizes.push(walk.sizes[rec] * 8);
            kinds.push("struct".to_string());
        } else if k == 5 {
            sizes.push(walk.sizes[rec] * 8);
            kinds.push("union".to_string());
        } else if k == 6 || k == 19 {
            sizes.push(walk.sizes[rec] * 8);
            kinds.push("enum".to_string());
        } else {
            let tb = type_bits(&walk, data, walk.sizes[rec], MAX_SPELL_DEPTH);
            if !tb.ok {
                return refuse_resolved(tb.message.clone());
            }
            sizes.push(tb.bits);
            kinds.push(tb.kind.clone());
        }
    }
    for h in 1..sizes.len() {
        if sizes[h] != sizes[0] || kinds[h] != kinds[0] {
            out.ambiguous = true;
            let ndefs = sizes.len();
            out.message = format!("type {name}: {ndefs} definitions disagree");
            return out;
        }
    }
    out.ok = true;
    out.found = true;
    out.bit_offset = 0;
    out.bit_size = sizes[0];
    out.kind = kinds[0].clone();
    out.message = String::new();
    out
}

/// Resolve one enumerator inside a named ENUM or ENUM64.
///
/// Candidates lacking the enumerator are ignored; the
/// rest must agree on the enum width.
pub fn resolve_btf_enumerator(data: &[u8], enum_name: &str, name: &str) -> BtfResolved {
    let walk = walk_btf(data, 0, data.len() as i64);
    if !walk.ok {
        return refuse_resolved(walk.message.clone());
    }
    let mut cands: Vec<usize> = Vec::new();
    for i in 0..walk.offsets.len() {
        if walk.kinds[i] != 6 && walk.kinds[i] != 19 {
            continue;
        }
        let Some(text) = walk.type_name(data, i) else {
            return refuse_resolved("BTF strings corrupt".to_string());
        };
        if text == enum_name {
            cands.push(i);
        }
    }
    let mut out = BtfResolved::new();
    if cands.is_empty() {
        out.ok = true;
        return out;
    }
    out.struct_found = true;
    let mut widths: Vec<i64> = Vec::new();
    for &rec in &cands {
        let base = walk.offsets[rec];
        let mut step = 8;
        if walk.kinds[rec] == 19 {
            step = 12;
        }
        let mut has = false;
        for e in 0..walk.vlens[rec] {
            let name_off = u32le(data, base + 12 + e * step);
            let Some(text) = table_text(data, walk.str_base, walk.str_end, name_off) else {
                return refuse_resolved("BTF strings corrupt".to_string());
            };
            if text == name {
                has = true;
                break;
            }
        }
        if has {
            widths.push(walk.sizes[rec] * 8);
        }
    }
    if widths.is_empty() {
        out.ok = true;
        return out;
    }
    for h in 1..widths.len() {
        if widths[h] != widths[0] {
            out.ambiguous = true;
            let ndefs = widths.len();
            out.message = format!("enum {enum_name}: {ndefs} definitions disagree on {name}");
            return out;
        }
    }
    out.ok = true;
    out.found = true;
    out.bit_offset = 0;
    out.bit_size = widths[0];
    out.kind = "enum".to_string();
    out.message = String::new();
    out
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_KERNEL_BTF_BYTES, check_btf_health, classify_btf_message, read_btf_copy_fb,
        read_btf_func_proto, read_btf_func_sig, read_btf_maps, read_btf_maps_ring, read_btf_member,
        read_object_map_bytes, resolve_btf_enumerator, resolve_btf_member, resolve_btf_type,
    };
    use crate::platform::evidence::evidence_btf_cap;
    use crate::platform::narrow::{MAX_NARROW_BTF_BYTES, verify_object_program};
    use crate::platform::test_support::repo_root;

    fn fixture(rel: &str) -> Vec<u8> {
        let path = repo_root().join(rel);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn elf(name: &str) -> Vec<u8> {
        fixture(&format!("tests/fixtures/elf/{name}"))
    }

    fn btf(name: &str) -> Vec<u8> {
        fixture(&format!("tests/fixtures/btf/{name}"))
    }

    #[test]
    fn btf_ok() {
        let raw = elf("ok.o");
        let v = read_btf_maps(&raw);
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 8_388_608);
    }

    #[test]
    fn btf_badring() {
        // A smaller but sane ring passes the static read; only
        // the identity binding pins the exact expected value.
        let raw = elf("badring.o");
        let v = read_btf_maps(&raw);
        assert!(v.ok);
        assert_eq!(v.ring_bytes, 4_194_304);
    }

    #[test]
    fn btf_badmap() {
        let raw = elf("badmap.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "counts max_entries 7, want 6");
    }

    #[test]
    fn btf_nobtf() {
        let raw = elf("nobtf.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "no BTF section");
    }

    #[test]
    fn btf_extern() {
        let raw = elf("extern.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "counts linkage 2");
    }

    #[test]
    fn btf_tiny() {
        let raw = elf("tiny.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "no BTF section");
    }

    #[test]
    fn btf_nodatasec() {
        let raw = elf("nodatasec.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "no maps DATASEC");
    }

    #[test]
    fn btf_unlisted() {
        let raw = elf("unlisted.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "counts not in maps DATASEC");
    }

    #[test]
    fn btf_dupvar() {
        let raw = elf("dupvar.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "duplicate mv_counts");
    }

    #[test]
    fn btf_offsets_map_ok() {
        // ok.o is the byte copy of the rebuilt attempt object:
        // the static pin holds over the real mv_offsets map.
        let raw = elf("ok.o");
        let v = read_btf_maps(&raw);
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 8_388_608);
    }

    #[test]
    fn btf_offsets_map_bad_geometry() {
        let raw = elf("badoff.o");
        let v = read_btf_maps(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "offsets max_entries 2, want 1");
        let missing = elf("nooff.o");
        let w = read_btf_maps(&missing);
        assert!(!w.ok);
        assert_eq!(w.message, "missing mv_offsets");
    }

    #[test]
    fn btf_inline_edges() {
        let v = read_btf_maps(&[]);
        assert!(!v.ok);
        assert_eq!(v.message, "no BTF section");
        let w = read_btf_maps(b"not an object\n");
        assert!(!w.ok);
        assert_eq!(w.message, "no BTF section");
    }

    #[test]
    fn btf_lifecycle_ring() {
        let raw = elf("lc-ok.o");
        let v = read_btf_maps_ring(&raw, "mv_lifecycle", "lifecycle");
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 33_554_432);
    }

    #[test]
    fn btf_copy_ring() {
        let raw = elf("cp-ok.o");
        let v = read_btf_maps_ring(&raw, "mv_copies", "copies");
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 33_554_432);
    }

    #[test]
    fn btf_copy_nonpow2() {
        let raw = elf("cp-nonpow2.o");
        let v = read_btf_maps_ring(&raw, "mv_copies", "copies");
        assert!(!v.ok);
        assert_eq!(v.message, "copies ring size 1000 rejected");
    }

    #[test]
    fn btf_missing_ring() {
        let raw = elf("lc-ok.o");
        let v = read_btf_maps_ring(&raw, "mv_copies", "copies");
        assert!(!v.ok);
        assert_eq!(v.message, "missing mv_copies");
    }

    #[test]
    fn func_proto_ok() {
        let raw = btf("funcproto.bin");
        let v = read_btf_func_proto(&raw, "test_fn");
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.canonical, "int (struct device *dev, size_t size)");
    }

    #[test]
    fn func_proto_missing() {
        let raw = btf("funcproto.bin");
        let v = read_btf_func_proto(&raw, "nope");
        assert!(!v.ok);
        assert_eq!(v.message, "function nope not found");
    }

    #[test]
    fn func_proto_duplicate() {
        let raw = btf("dupfunc.bin");
        let v = read_btf_func_proto(&raw, "test_fn");
        assert!(!v.ok);
        assert_eq!(v.message, "duplicate function test_fn");
    }

    #[test]
    fn func_proto_cycle() {
        let raw = btf("cycle.bin");
        let v = read_btf_func_proto(&raw, "cyc");
        assert!(!v.ok);
        assert_eq!(v.message, "type graph too deep");
    }

    #[test]
    fn func_proto_anon() {
        let raw = btf("anon.bin");
        let v = read_btf_func_proto(&raw, "anon");
        assert!(!v.ok);
        assert_eq!(v.message, "anonymous type in prototype");
    }

    #[test]
    fn func_proto_void() {
        let raw = btf("funcproto.bin");
        let v = read_btf_func_proto(&raw, "vret");
        assert!(v.ok);
        assert_eq!(v.canonical, "void (void)");
    }

    #[test]
    fn func_proto_int_alias() {
        let raw = btf("funcproto.bin");
        let v = read_btf_func_proto(&raw, "lint");
        assert!(v.ok);
        assert_eq!(v.canonical, "unsigned long (void)");
    }

    #[test]
    fn func_proto_voidptr() {
        let raw = btf("voidptr.bin");
        let v = read_btf_func_proto(&raw, "vptr");
        assert!(v.ok);
        assert_eq!(v.canonical, "void (void *p)");
    }

    #[test]
    fn func_proto_unnamed_param() {
        let raw = btf("unnamed.bin");
        let v = read_btf_func_proto(&raw, "unm");
        assert!(!v.ok);
        assert_eq!(v.message, "unnamed parameter in prototype");
    }

    #[test]
    fn func_proto_array() {
        let raw = btf("array.bin");
        let v = read_btf_func_proto(&raw, "arr");
        assert!(v.ok);
        assert_eq!(v.canonical, "void (int[4] a)");
    }

    #[test]
    fn func_proto_badref() {
        let raw = btf("badref.bin");
        let v = read_btf_func_proto(&raw, "bad");
        assert!(!v.ok);
        assert_eq!(v.message, "type id out of range");
    }

    #[test]
    fn func_proto_fnptr() {
        let raw = btf("fnptr.bin");
        let v = read_btf_func_proto(&raw, "cb");
        assert!(!v.ok);
        assert_eq!(v.message, "function pointer in prototype");
    }

    #[test]
    fn func_proto_chain31() {
        let raw = btf("chain31.bin");
        let v = read_btf_func_proto(&raw, "deep31");
        assert!(v.ok);
        let mut want = "void (int".to_string();
        for _ in 0..31 {
            want += " *";
        }
        want += "p)";
        assert_eq!(v.canonical, want);
    }

    #[test]
    fn func_proto_chain32() {
        let raw = btf("chain32.bin");
        let v = read_btf_func_proto(&raw, "deep32");
        assert!(!v.ok);
        assert_eq!(v.message, "type graph too deep");
    }

    #[test]
    fn func_proto_truncated() {
        let raw = btf("funcproto.bin");
        let cut = &raw[..raw.len() - 10];
        let v = read_btf_func_proto(cut, "test_fn");
        assert!(!v.ok);
        assert_eq!(v.message, "BTF sections out of range");
    }

    #[test]
    fn btf_kind_flag_struct_ok() {
        // kind_flag on STRUCT changes interpretation, not
        // member layout: the walker keeps 12-byte member
        // alignment and spells the return normally.
        let raw = btf("kflag.bin");
        let v = read_btf_func_proto(&raw, "kfs");
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.canonical, "struct device (void)");
    }

    #[test]
    fn btf_kind_flag_enum64_ok() {
        // kind_flag on ENUM64 likewise leaves the 12-byte
        // enumerator entries aligned; the parameter spells.
        let raw = btf("kflag.bin");
        let v = read_btf_func_proto(&raw, "kfe");
        assert!(v.ok);
        assert_eq!(v.message, "");
        assert_eq!(v.canonical, "void (enum color c)");
    }

    #[test]
    fn func_proto_int_size_mismatch() {
        // A 4-byte "long" is not an LP64 long: both the
        // return and the parameter position refuse with
        // the exact size diagnostic.
        let raw = btf("intsize-bad.bin");
        let r = read_btf_func_proto(&raw, "badret");
        assert!(!r.ok);
        assert_eq!(r.message, "BTF int size 4 mismatch for long, want 8");
        let p = read_btf_func_proto(&raw, "badpar");
        assert!(!p.ok);
        assert_eq!(p.message, "BTF int size 4 mismatch for long, want 8");
    }

    #[test]
    fn func_proto_int_size_lp64_ok() {
        // Every LP64 integer spelling (plus kernel/BTF
        // aliases and a size_t typedef) spells exactly as
        // before once its BTF size matches the table.
        let raw = btf("intsizes.bin");
        let v = read_btf_func_proto(&raw, "isz");
        assert!(v.ok);
        assert_eq!(v.message, "");
        let mut want = "void (char pa, signed char pb,".to_string();
        want += " unsigned char pc, short pd,";
        want += " unsigned short pe, int pf, unsigned int pg,";
        want += " long ph, unsigned long pi, long long pj,";
        want += " unsigned long long pk, bool pl, short pm,";
        want += " long pn, long long po, unsigned short pp,";
        want += " unsigned long pq, unsigned long long pr,";
        want += " size_t psz)";
        assert_eq!(v.canonical, want);
    }

    #[test]
    fn btf_member_pool() {
        let raw = btf("swiotlb-live.bin");
        let s = read_btf_member(&raw, "io_tlb_pool", "start");
        assert!(s.ok);
        assert_eq!(s.message, "");
        assert_eq!(s.bit_offset, 0);
        assert_eq!(s.bit_size, 64);
        let n = read_btf_member(&raw, "io_tlb_pool", "nslabs");
        assert!(n.ok);
        assert_eq!(n.bit_offset, 192);
        assert_eq!(n.bit_size, 64);
        let q = read_btf_member(&raw, "io_tlb_pool", "slots");
        assert!(q.ok);
        assert_eq!(q.bit_offset, 448);
        assert_eq!(q.bit_size, 64);
    }

    #[test]
    fn btf_member_slot() {
        let raw = btf("swiotlb-live.bin");
        let o = read_btf_member(&raw, "io_tlb_slot", "orig_addr");
        assert!(o.ok);
        assert_eq!(o.bit_offset, 0);
        assert_eq!(o.bit_size, 64);
        let a = read_btf_member(&raw, "io_tlb_slot", "alloc_size");
        assert!(a.ok);
        assert_eq!(a.bit_offset, 64);
        assert_eq!(a.bit_size, 64);
    }

    #[test]
    fn btf_member_device() {
        let raw = btf("swiotlb-live.bin");
        let m = read_btf_member(&raw, "device_dma_parameters", "min_align_mask");
        assert!(m.ok);
        assert_eq!(m.bit_offset, 32);
        assert_eq!(m.bit_size, 32);
        let d = read_btf_member(&raw, "device", "dma_parms");
        assert!(d.ok);
        assert_eq!(d.bit_offset, 5056);
        assert_eq!(d.bit_size, 64);
    }

    #[test]
    fn btf_member_not_found() {
        let raw = btf("swiotlb-live.bin");
        let s = read_btf_member(&raw, "no_such_struct", "start");
        assert!(!s.ok);
        assert_eq!(s.message, "struct no_such_struct not found");
        let m = read_btf_member(&raw, "io_tlb_pool", "no_such_field");
        assert!(!m.ok);
        assert_eq!(m.message, "member no_such_field not found in io_tlb_pool");
    }

    #[test]
    fn btf_copy_fallback_declared() {
        // Retargeted: the Mojo test reads the built copy object
        // out of build/bpf/; the Rust port reads the checked-in
        // copy fixture, which carries the same mv_copy_fb shape.
        let raw = elf("cp-ok.o");
        let fb = read_btf_copy_fb(&raw);
        assert!(fb.ok);
        assert_eq!(fb.message, "");
        let e = verify_object_program(&raw, "mv_bounce", "fentry/");
        assert!(e.ok);
        let x = verify_object_program(&raw, "mv_bounce_exit", "fexit/");
        assert!(x.ok);
    }

    #[test]
    fn member_anon_offsets() {
        let raw = btf("members.bin");
        let c = resolve_btf_member(&raw, "mvt_anon", "c");
        assert!(c.ok);
        assert!(c.found);
        assert_eq!(c.bit_offset, 128);
        assert_eq!(c.bit_size, 64);
        assert_eq!(c.kind, "int");
        let m = resolve_btf_member(&raw, "mvt_anon", "mapping");
        assert!(m.ok);
        assert_eq!(m.bit_offset, 192);
        assert_eq!(m.bit_size, 64);
        assert_eq!(m.kind, "ptr");
        let d = resolve_btf_member(&raw, "mvt_anon", "d");
        assert!(d.ok);
        assert!(d.found);
        assert_eq!(d.bit_offset, 64);
    }

    #[test]
    fn member_real_shapes() {
        let raw = btf("members.bin");
        let f = resolve_btf_member(&raw, "mvt_dev", "offline_disabled");
        assert!(f.ok);
        assert!(f.found);
        assert!(f.bitfield);
        assert_eq!(f.bit_offset, 6112);
        assert_eq!(f.bit_size, 1);
        let o = resolve_btf_member(&raw, "mvt_dev_old", "offline_disabled");
        assert!(o.ok);
        assert!(o.found);
        assert!(o.bitfield);
        let p = resolve_btf_member(&raw, "mvt_tag", "p");
        assert!(p.ok);
        assert_eq!(p.kind, "ptr");
        assert_eq!(p.bit_size, 64);
        let q = resolve_btf_member(&raw, "mvt_tag", "q");
        assert!(q.ok);
        assert_eq!(q.kind, "int");
        assert_eq!(q.bit_size, 64);
        let n = resolve_btf_member(&raw, "mvt_tag", "name");
        assert!(n.ok);
        assert_eq!(n.kind, "array");
        assert_eq!(n.bit_size, 128);
        let e = resolve_btf_enumerator(&raw, "mvt_e64", "MVT_BIG");
        assert!(e.ok);
        assert!(e.found);
        assert_eq!(e.kind, "enum");
        assert_eq!(e.bit_size, 64);
    }

    #[test]
    fn member_duplicates() {
        let raw = btf("members.bin");
        let c = resolve_btf_member(&raw, "mvt_console", "flags");
        assert!(c.ok);
        assert!(c.found);
        assert_eq!(c.bit_offset, 64);
        let d = resolve_btf_member(&raw, "mvt_dup", "flags");
        assert!(!d.ok);
        assert!(d.ambiguous);
        assert_eq!(d.message, "struct mvt_dup: 2 definitions disagree on flags");
        let e = resolve_btf_member(&raw, "mvt_partial", "extra");
        assert!(e.ok);
        assert!(e.found);
        assert_eq!(e.bit_offset, 96);
    }

    #[test]
    fn member_absent() {
        let raw = btf("members.bin");
        let m = resolve_btf_member(&raw, "mvt_anon", "nope");
        assert!(m.ok);
        assert!(m.struct_found);
        assert!(!m.found);
        let s = resolve_btf_member(&raw, "mvt_none", "a");
        assert!(s.ok);
        assert!(!s.struct_found);
    }

    #[test]
    fn member_legacy_refuses_bitfield() {
        let raw = btf("members.bin");
        let v = read_btf_member(&raw, "mvt_dev", "offline_disabled");
        assert!(!v.ok);
        assert_eq!(
            v.message,
            "bitfield member mvt_dev.offline_disabled unsupported"
        );
    }

    #[test]
    fn member_dag_fast() {
        // Shared anonymous subtypes fan the search out 2**32
        // and 8**12 paths; memoization answers in milliseconds.
        for name in ["dag32.bin", "fan8.bin"] {
            let raw = btf(name);
            let h = check_btf_health(&raw);
            assert!(h.ok);
            let start = std::time::Instant::now();
            let r = resolve_btf_member(&raw, "t0", "zz");
            let ms = start.elapsed().as_millis();
            assert!(r.ok);
            assert!(r.struct_found);
            assert!(!r.found);
            assert!(ms < 10_000, "{name} took {ms}ms");
        }
    }

    #[test]
    fn member_wide_refuses() {
        // 4097 expansions exceed the visit budget: the search
        // refuses instead of walking an adversarial graph.
        let raw = btf("wide.bin");
        let h = check_btf_health(&raw);
        assert!(h.ok);
        let r = resolve_btf_member(&raw, "wide0", "zz");
        assert!(!r.ok);
        assert_eq!(r.message, "type graph too large");
    }

    #[test]
    fn btf_health_classes() {
        let raw = btf("swiotlb-live.bin");
        let h = check_btf_health(&raw);
        assert!(h.ok);
        let split = btf("split.bin");
        let s = check_btf_health(&split);
        assert!(!s.ok);
        assert_eq!(s.code, "btf-split");
        assert_eq!(
            s.message,
            "split BTF needs base (string section does not start with NUL)"
        );
        let cut = &raw[0..600];
        let t = check_btf_health(cut);
        assert!(!t.ok);
        assert_eq!(t.code, "btf-truncated");
        let stand = fixture("tests/fixtures/capabilities/ordinary-7.0/sys/kernel/btf/vmlinux");
        let m = check_btf_health(&stand);
        assert!(!m.ok);
        assert_eq!(m.code, "btf-malformed");
        assert_eq!(m.message, "bad BTF header");
    }

    #[test]
    fn btf_cap_single() {
        assert_eq!(MAX_KERNEL_BTF_BYTES, 67_108_864);
        assert_eq!(MAX_NARROW_BTF_BYTES, MAX_KERNEL_BTF_BYTES);
        assert_eq!(evidence_btf_cap(), MAX_KERNEL_BTF_BYTES);
    }

    #[test]
    fn classify_reader_messages() {
        // A dangling type id is corrupt BTF, never a known refusal.
        assert_eq!(
            classify_btf_message("type id out of range"),
            "btf-malformed"
        );
        assert_eq!(classify_btf_message("BTF too small"), "btf-truncated");
        assert_eq!(classify_btf_message("function nope not found"), "");
    }

    #[test]
    fn func_sig_dups() {
        let raw = btf("sig-dup.bin");
        let f = read_btf_func_sig(&raw, "test_fn");
        assert!(f.ok);
        assert_eq!(f.ret, "int");
        assert_eq!(f.params.len(), 2);
        assert_eq!(f.params[0], "struct device *");
        assert_eq!(f.params[1], "size_t");
        let g = read_btf_func_sig(&raw, "test_gn");
        assert!(!g.ok);
        assert_eq!(g.message, "ambiguous FUNC test_gn (2 prototypes differ)");
    }

    #[test]
    fn object_map_bytes() {
        // Ported from the prechecks suite, which owns these
        // assertions in Mojo: the byte bounds are btf reads.
        // 8388608 ring + 6*8 counts + 1*24 offsets.
        let ok_raw = elf("ok.o");
        let ok = read_object_map_bytes(&ok_raw);
        assert!(ok.ok);
        assert_eq!(ok.bytes, 8_388_680);
        // 33554432 ring + 6*8 counts + 32768*24 gen_table + 8 gen_next.
        let lc_raw = elf("lc-ok.o");
        let lc = read_object_map_bytes(&lc_raw);
        assert!(lc.ok);
        assert_eq!(lc.bytes, 34_340_920);
        // 33554432 ring + 6*8 counts + 4096*16 claims + 4*8 copy_fb.
        let cp_raw = elf("cp-ok.o");
        let cp = read_object_map_bytes(&cp_raw);
        assert!(cp.ok);
        assert_eq!(cp.bytes, 33_620_048);
        // No BTF section refuses.
        let nobtf = elf("nobtf.o");
        let n = read_object_map_bytes(&nobtf);
        assert!(!n.ok);
        assert_eq!(n.message, "no BTF section");
    }

    #[test]
    fn resolve_type_struct_and_enum() {
        // Positive expectations verified against an independent
        // Python parse of the same fixtures (see the task report).
        let live = btf("swiotlb-live.bin");
        let s = resolve_btf_type(&live, "io_tlb_pool", "struct");
        assert!(s.ok);
        assert!(s.struct_found);
        assert!(s.found);
        assert_eq!(s.kind, "struct");
        assert_eq!(s.bit_offset, 0);
        assert_eq!(s.bit_size, 832);
        let members = btf("members.bin");
        let e = resolve_btf_type(&members, "mvt_e64", "enum");
        assert!(e.ok);
        assert!(e.found);
        assert_eq!(e.kind, "enum");
        assert_eq!(e.bit_size, 64);
    }

    #[test]
    fn resolve_type_typedef_terminal() {
        // size_t -> unsigned long (8 bytes) in the live blob.
        let live = btf("swiotlb-live.bin");
        let t = resolve_btf_type(&live, "size_t", "typedef");
        assert!(t.ok);
        assert!(t.found);
        assert_eq!(t.kind, "int");
        assert_eq!(t.bit_size, 64);
    }

    #[test]
    fn resolve_type_refusals() {
        let members = btf("members.bin");
        let u = resolve_btf_type(&members, "mvt_anon", "bogus");
        assert!(!u.ok);
        assert_eq!(u.message, "unknown type kind bogus");
        let m = resolve_btf_member(&members, "mvt_none", "a");
        assert!(m.ok);
        assert!(!m.struct_found);
        let s = resolve_btf_type(&members, "mvt_none", "struct");
        assert!(s.ok);
        assert!(!s.struct_found);
        assert!(!s.found);
    }

    #[test]
    fn resolve_type_ambiguous() {
        // Two same-named structs with different sizes refuse.
        // Header (24) + 2 STRUCT records (12 each, no members)
        // + strings ("\0t\0"). Both records name offset 1.
        let mut blob = vec![0u8; 24];
        blob[0] = 0x9F;
        blob[1] = 0xEB;
        blob[2] = 1;
        blob[4] = 24;
        // type_off = 0, type_len = 24.
        blob[12] = 24;
        // str_off = 24, str_len = 3.
        blob[16] = 24;
        blob[20] = 3;
        // Record 1: name 1, kind STRUCT (4 << 24), size 4.
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&((4u32) << 24).to_le_bytes());
        blob.extend_from_slice(&4u32.to_le_bytes());
        // Record 2: name 1, kind STRUCT, size 8.
        blob.extend_from_slice(&1u32.to_le_bytes());
        blob.extend_from_slice(&((4u32) << 24).to_le_bytes());
        blob.extend_from_slice(&8u32.to_le_bytes());
        blob.extend_from_slice(b"\0t\0");
        let r = resolve_btf_type(&blob, "t", "struct");
        assert!(!r.ok);
        assert!(r.ambiguous);
        assert_eq!(r.message, "type t: 2 definitions disagree");
    }

    #[test]
    fn embedded_copy_bytes_stay_fail_closed() {
        // Retarget seam: whatever the embedded copy ELF holds
        // today (stub or probe program), the static readers
        // return a well-formed verdict, never a panic.
        let bytes = crate::platform::runtime::embedded_object("copy").expect("copy ELF embedded");
        assert!(!bytes.is_empty());
        let fb = read_btf_copy_fb(bytes);
        assert_eq!(fb.ok, fb.message.is_empty());
        if fb.ok {
            assert_eq!(fb.ring_bytes, 0);
        }
    }

    /// Embedded Aya ELF bytes for one channel, copied for mutation.
    fn aya_bytes(kind: &str) -> Vec<u8> {
        crate::platform::runtime::embedded_object(kind)
            .expect("channel ELF embedded")
            .to_vec()
    }

    /// (header offset, name bytes offset, file offset, size) of
    /// one ELF section. Minimal parse for targeting mutations;
    /// verdicts stay production's.
    fn section_range(raw: &[u8], want: &[u8]) -> (usize, usize, usize, usize) {
        let shoff = u64::from_le_bytes(raw[0x28..0x30].try_into().unwrap()) as usize;
        let shnum = u16::from_le_bytes(raw[0x3C..0x3E].try_into().unwrap()) as usize;
        let shstrndx = u16::from_le_bytes(raw[0x3E..0x40].try_into().unwrap()) as usize;
        let str_hdr = shoff + shstrndx * 64;
        let str_off =
            u64::from_le_bytes(raw[str_hdr + 24..str_hdr + 32].try_into().unwrap()) as usize;
        for i in 0..shnum {
            let hdr = shoff + i * 64;
            let name_off = u32::from_le_bytes(raw[hdr..hdr + 4].try_into().unwrap()) as usize;
            let mut end = str_off + name_off;
            while raw[end] != 0 {
                end += 1;
            }
            if &raw[str_off + name_off..end] == want {
                let at = str_off + name_off;
                let off = u64::from_le_bytes(raw[hdr + 24..hdr + 32].try_into().unwrap()) as usize;
                let size = u64::from_le_bytes(raw[hdr + 32..hdr + 40].try_into().unwrap()) as usize;
                return (hdr, at, off, size);
            }
        }
        panic!("channel ELF must carry the wanted section");
    }

    /// One test-side BTF record: kind, vlen, file offset, size word.
    struct TestRec {
        kind: i64,
        vlen: i64,
        off: usize,
        size: i64,
    }

    struct TestBtf {
        recs: Vec<TestRec>,
        str_base: usize,
        str_end: usize,
    }

    fn u32_at(raw: &[u8], at: usize) -> i64 {
        super::u32le(raw, at as i64)
    }

    /// Minimal BTF index over the `.BTF` section for targeting
    /// mutations; verdicts stay production's.
    fn parse_btf(raw: &[u8]) -> TestBtf {
        let (_, _, base, size) = section_range(raw, b".BTF");
        assert_eq!(super::u16le(raw, base as i64), 0xEB9F);
        assert!(size > 24);
        let hdr = super::u32le(raw, base as i64 + 4) as usize;
        let toff = super::u32le(raw, base as i64 + 8) as usize;
        let tlen = super::u32le(raw, base as i64 + 12) as usize;
        let soff = super::u32le(raw, base as i64 + 16) as usize;
        let slen = super::u32le(raw, base as i64 + 20) as usize;
        let mut tb = TestBtf {
            recs: Vec::new(),
            str_base: base + hdr + soff,
            str_end: base + hdr + soff + slen,
        };
        let mut p = base + hdr + toff;
        let end = p + tlen;
        while p < end {
            let info = u32_at(raw, p + 4);
            let kind = (info >> 24) & 31;
            let vlen = info & 65535;
            let extra: i64 = if kind == 1 || kind == 14 || kind == 17 {
                4
            } else if kind == 3 {
                12
            } else if kind == 4 || kind == 5 || kind == 15 {
                vlen * 12
            } else if kind == 6 || kind == 13 {
                vlen * 8
            } else if kind == 19 {
                vlen * 12
            } else if matches!(kind, 0 | 2 | 7 | 8 | 9 | 10 | 11 | 12 | 16 | 18) {
                0
            } else {
                panic!("channel BTF must walk");
            };
            tb.recs.push(TestRec {
                kind,
                vlen,
                off: p,
                size: u32_at(raw, p + 8),
            });
            p += 12 + extra as usize;
        }
        assert_eq!(p, end);
        tb
    }

    fn btf_name(raw: &[u8], tb: &TestBtf, name_off: i64) -> String {
        let mut end = tb.str_base + name_off as usize;
        assert!(end < tb.str_end);
        while raw[end] != 0 {
            end += 1;
            assert!(end < tb.str_end);
        }
        String::from_utf8(raw[tb.str_base + name_off as usize..end].to_vec()).unwrap()
    }

    fn rec_name(raw: &[u8], tb: &TestBtf, rec: usize) -> String {
        btf_name(raw, tb, u32_at(raw, tb.recs[rec].off))
    }

    /// Record index of the VAR named want (exactly one).
    fn var_rec(raw: &[u8], tb: &TestBtf, want: &str) -> usize {
        let mut found = None;
        for (i, rec) in tb.recs.iter().enumerate() {
            if rec.kind != 14 {
                continue;
            }
            if rec_name(raw, tb, i) == want {
                assert!(found.is_none(), "VAR name must be unique");
                found = Some(i);
            }
        }
        found.expect("VAR must exist")
    }

    /// Record index of the DATASEC named want (exactly one).
    fn datasec_rec(raw: &[u8], tb: &TestBtf, want: &str) -> usize {
        let mut found = None;
        for (i, rec) in tb.recs.iter().enumerate() {
            if rec.kind != 15 {
                continue;
            }
            if rec_name(raw, tb, i) == want {
                assert!(found.is_none(), "DATASEC name must be unique");
                found = Some(i);
            }
        }
        found.expect("DATASEC must exist")
    }

    /// Record index of the STRUCT named want (exactly one).
    fn struct_rec(raw: &[u8], tb: &TestBtf, want: &str) -> usize {
        let mut found = None;
        for (i, rec) in tb.recs.iter().enumerate() {
            if rec.kind != 4 {
                continue;
            }
            if rec_name(raw, tb, i) == want {
                assert!(found.is_none(), "STRUCT name must be unique");
                found = Some(i);
            }
        }
        found.expect("STRUCT must exist")
    }

    /// 0-based DATASEC member index of one VAR (test targeting).
    fn datasec_index(raw: &[u8], tb: &TestBtf, sec: &str, var: &str) -> usize {
        let want = var_rec(raw, tb, var) as i64 + 1;
        let rec = datasec_rec(raw, tb, sec);
        let base = tb.recs[rec].off;
        for m in 0..tb.recs[rec].vlen {
            if u32_at(raw, base + 12 + m as usize * 12) == want {
                return m as usize;
            }
        }
        panic!("VAR must be listed");
    }

    /// Member (name, type id, bit offset) triple of one record.
    fn member_at(raw: &[u8], tb: &TestBtf, rec: usize, m: usize) -> (String, i64, i64) {
        let base = tb.recs[rec].off;
        let name = btf_name(raw, tb, u32_at(raw, base + 12 + m * 12));
        let tid = u32_at(raw, base + 12 + m * 12 + 4);
        let off = u32_at(raw, base + 12 + m * 12 + 8);
        (name, tid, off)
    }

    /// Overwrite bytes after asserting their current value.
    fn overwrite(raw: &mut [u8], at: usize, from: &[u8], to: &[u8]) {
        assert_eq!(from.len(), to.len());
        assert_eq!(&raw[at..at + from.len()], from);
        raw[at..at + to.len()].copy_from_slice(to);
    }

    fn set_u32(raw: &mut [u8], at: usize, val: u32) {
        raw[at..at + 4].copy_from_slice(&val.to_le_bytes());
    }

    /// Write one u32 word of one `maps` section entry: entry idx,
    /// field 0..4 (type, key_size, value_size, max_entries).
    fn set_map_word(raw: &mut [u8], idx: usize, field: usize, val: u32) {
        let (_, _, off, size) = section_range(raw, b"maps");
        let at = off + idx * 28 + field * 4;
        assert!(at + 4 <= off + size);
        set_u32(raw, at, val);
    }

    #[test]
    fn btf_aya_attempt_ok() {
        // The build's own Aya attempt object admits: DATASEC
        // `maps` with exact per-map geometry (counts ARRAY
        // 4/8/6, ringbuf 8 MiB, offsets ARRAY 4/24/1).
        let raw = aya_bytes("attempt");
        let v = read_btf_maps(&raw);
        assert!(v.ok, "Aya attempt refused: {}", v.message);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 8_388_608);
    }

    #[test]
    fn btf_aya_lifecycle_ring_ok() {
        let raw = aya_bytes("lifecycle");
        let v = read_btf_maps_ring(&raw, "mv_lifecycle", "lifecycle");
        assert!(v.ok, "Aya lifecycle refused: {}", v.message);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 33_554_432);
    }

    #[test]
    fn btf_aya_copy_ring_ok() {
        let raw = aya_bytes("copy");
        let v = read_btf_maps_ring(&raw, "mv_copies", "copies");
        assert!(v.ok, "Aya copy refused: {}", v.message);
        assert_eq!(v.message, "");
        assert_eq!(v.ring_bytes, 33_554_432);
    }

    #[test]
    fn btf_aya_bad_chain_shape() {
        // A malformed newtype spine refuses: the Aya lane pins
        // the exact wrapper geometry per map. (A STRUCT vlen
        // flip would desynchronize the walk itself, so the
        // spine pins are exercised through size words, which
        // keep the layout aligned, plus cross-wiring below.)
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let ring = struct_rec(&raw, &tb, "RingBuf");
        assert_eq!(tb.recs[ring].size, 28);
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[ring].off + 8, 20);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "attempts bad aya map shape");
        let array = struct_rec(&raw, &tb, "Array_3C_u64_3E_");
        assert_eq!(tb.recs[array].size, 28);
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[array].off + 8, 20);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "counts bad aya map shape");
    }

    #[test]
    fn btf_aya_crosswired() {
        // counts through a ring wrapper refuses, and the ring
        // through an array wrapper refuses: each map kind must
        // carry its own spine shape.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let counts = var_rec(&raw, &tb, "mv_counts");
        let attempts = var_rec(&raw, &tb, "mv_attempts");
        let ring = struct_rec(&raw, &tb, "RingBuf") as u32 + 1;
        let array = struct_rec(&raw, &tb, "Array_3C_u64_3E_") as u32 + 1;
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[counts].off + 8, ring);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "counts bad aya map shape");
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[attempts].off + 8, array);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "attempts bad aya map shape");
    }

    #[test]
    fn btf_aya_not_struct() {
        // counts through a bare INT refuses in the existing
        // vocabulary.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let counts = var_rec(&raw, &tb, "mv_counts");
        let mut int_tid = 0;
        for (i, rec) in tb.recs.iter().enumerate() {
            if rec.kind == 1 {
                int_tid = i as u32 + 1;
                break;
            }
        }
        assert_ne!(int_tid, 0);
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[counts].off + 8, int_tid);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "counts not a struct");
    }

    #[test]
    fn btf_aya_linkage() {
        // An extern counts VAR refuses, mirroring btf_extern.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let counts = var_rec(&raw, &tb, "mv_counts");
        assert_eq!(u32_at(&raw, tb.recs[counts].off + 12), 1);
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[counts].off + 12, 2);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "counts linkage 2");
    }

    #[test]
    fn btf_aya_missing_var() {
        // A renamed counts VAR refuses in the existing vocabulary.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let counts = var_rec(&raw, &tb, "mv_counts");
        let at = tb.str_base + u32_at(&raw, tb.recs[counts].off) as usize;
        let mut out = raw.clone();
        overwrite(&mut out, at, b"mv_counts", b"mv_countz");
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "missing mv_counts");
    }

    #[test]
    fn btf_aya_no_datasec() {
        // Without DATASEC `maps` the refusal stays the existing
        // vocabulary: unknown shapes stay refused.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let rec = datasec_rec(&raw, &tb, "maps");
        let at = tb.str_base + u32_at(&raw, tb.recs[rec].off) as usize;
        let mut out = raw.clone();
        overwrite(&mut out, at, b"maps", b"mapz");
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "no maps DATASEC");
    }

    #[test]
    fn btf_aya_datasec_entries_pinned() {
        // DATASEC members must be zero-offset 28-byte VARs:
        // order is the ELF association, so a malformed list
        // refuses instead of misassociating entries.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let rec = datasec_rec(&raw, &tb, "maps");
        let base = tb.recs[rec].off;
        assert_eq!(u32_at(&raw, base + 12 + 4), 0);
        assert_eq!(u32_at(&raw, base + 12 + 8), 28);
        let mut out = raw.clone();
        set_u32(&mut out, base + 12 + 4, 28);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "bad maps DATASEC");
        let mut out = raw.clone();
        set_u32(&mut out, base + 12 + 8, 0);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "bad maps DATASEC");
        // A twice-listed VAR is ambiguous: refuse, never guess.
        let mut out = raw.clone();
        let tid = u32_at(&raw, base + 12);
        set_u32(&mut out, base + 12 + 2 * 12, tid as u32);
        let d = read_btf_maps(&out);
        assert!(!d.ok);
        assert_eq!(d.message, "bad maps DATASEC");
    }

    #[test]
    fn btf_aya_section_missing_or_truncated() {
        // DATASEC `maps` without ELF definition bytes refuses:
        // geometry has no source to pin.
        let raw = aya_bytes("attempt");
        let (_, name_at, _, _) = section_range(&raw, b"maps");
        let mut out = raw.clone();
        overwrite(&mut out, name_at, b"maps", b"mapz");
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "counts bad aya map shape");
        // A section too short for the listed entries refuses too.
        let (hdr, _, _, _) = section_range(&raw, b"maps");
        let mut out = raw.clone();
        out[hdr + 32..hdr + 40].copy_from_slice(&28u64.to_le_bytes());
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "counts bad aya map shape");
    }

    #[test]
    fn btf_aya_leaf_members() {
        // The flat bpf_map_def leaf reuses the libbpf member
        // vocabulary: a missing type member and a non-u32
        // member refuse exactly like their libbpf analogs.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let leaf = struct_rec(&raw, &tb, "bpf_map_def");
        assert_eq!(tb.recs[leaf].vlen, 7);
        let (name, _, _) = member_at(&raw, &tb, leaf, 0);
        assert_eq!(name, "type_");
        let name_off = u32_at(&raw, tb.recs[leaf].off + 12);
        let mut out = raw.clone();
        overwrite(
            &mut out,
            tb.str_base + name_off as usize,
            b"type_",
            b"typo_",
        );
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "counts missing type");
        // Retarget the type member at a one-byte INT.
        let mut narrow = 0;
        for (i, rec) in tb.recs.iter().enumerate() {
            if rec.kind == 1 && rec.size == 1 {
                narrow = i as u32 + 1;
                break;
            }
        }
        assert_ne!(narrow, 0);
        let mut out = raw.clone();
        set_u32(&mut out, tb.recs[leaf].off + 12 + 4, narrow);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "counts bad type");
    }

    #[test]
    fn btf_aya_counts_geometry() {
        // Every counts geometry field pins exactly, in the
        // existing per-field vocabulary.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let idx = datasec_index(&raw, &tb, "maps", "mv_counts");
        for (field, val, want) in [
            (0, 27u32, "counts type 27, want 2"),
            (3, 7u32, "counts max_entries 7, want 6"),
            (1, 8u32, "counts key 8, want 4"),
            (2, 4u32, "counts value 4, want 8"),
        ] {
            let mut out = raw.clone();
            set_map_word(&mut out, idx, field, val);
            let v = read_btf_maps(&out);
            assert!(!v.ok, "field {field} admitted");
            assert_eq!(v.message, want);
        }
    }

    #[test]
    fn btf_aya_ring_geometry() {
        // The ring map pins type 27 plus a sane power-of-two size.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let idx = datasec_index(&raw, &tb, "maps", "mv_attempts");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 0, 2);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "attempts type 2, want 27");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 3, 1000);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "attempts ring size 1000 rejected");
    }

    #[test]
    fn btf_aya_offsets_geometry() {
        // The offsets table pins ARRAY 4/24/1 exactly.
        let raw = aya_bytes("attempt");
        let tb = parse_btf(&raw);
        let idx = datasec_index(&raw, &tb, "maps", "mv_offsets");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 2, 8);
        let v = read_btf_maps(&out);
        assert!(!v.ok);
        assert_eq!(v.message, "offsets value 8, want 24");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 3, 2);
        let w = read_btf_maps(&out);
        assert!(!w.ok);
        assert_eq!(w.message, "offsets max_entries 2, want 1");
    }

    #[test]
    fn btf_aya_lifecycle_geometry() {
        // The lifecycle ring pins per channel, not just admit.
        let raw = aya_bytes("lifecycle");
        let tb = parse_btf(&raw);
        let idx = datasec_index(&raw, &tb, "maps", "mv_lifecycle");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 0, 2);
        let v = read_btf_maps_ring(&out, "mv_lifecycle", "lifecycle");
        assert!(!v.ok);
        assert_eq!(v.message, "lifecycle type 2, want 27");
    }

    #[test]
    fn btf_aya_copy_geometry() {
        // The copies ring pins per channel, not just admit.
        let raw = aya_bytes("copy");
        let tb = parse_btf(&raw);
        let idx = datasec_index(&raw, &tb, "maps", "mv_copies");
        let mut out = raw.clone();
        set_map_word(&mut out, idx, 0, 2);
        let v = read_btf_maps_ring(&out, "mv_copies", "copies");
        assert!(!v.ok);
        assert_eq!(v.message, "copies type 2, want 27");
    }

    #[test]
    fn btf_aya_missing_ring() {
        // A wrong ring variable refuses, mirroring btf_missing_ring.
        let raw = aya_bytes("lifecycle");
        let v = read_btf_maps_ring(&raw, "mv_copies", "copies");
        assert!(!v.ok);
        assert_eq!(v.message, "missing mv_copies");
    }
}
