// SPDX-License-Identifier: GPL-3.0-or-later
//! Narrow identity bindings: grammar, live reads, checks.
//!
//! A profile carries narrow bindings in
//! `identity.source.note` as ordered space-separated `k=v`
//! pairs (section 5 grammar). This module strict-parses the
//! note, reads the live identity sources under a root
//! (`/` live, fixture dir in tests), and compares live
//! values against bindings. Outcomes: bound, mismatch with
//! the key, or uncheckable with the key. A note that does
//! not parse is an unbound reference, never an error.
//!
//! Retarget note: the object lane hashes explicit object
//! files ([`read_live_object`]) or embedded Aya ELF bytes
//! ([`read_live_object_bytes`]); object admission
//! ([`verify_object`], [`verify_object_program`]) already
//! takes bytes, so callers pass embedded bytes instead of
//! file bytes with no semantic change.

use super::btf::MAX_KERNEL_BTF_BYTES;
use super::gzip::gunzip_member;
use super::hash::{bytes_to_hex, sha256_hex};
use super::reader::{
    EVIDENCE_DENIED, EVIDENCE_OK, EvidenceReader, bytes_to_text, file_state, open_evidence_reader,
    read_evidence, read_host_file,
};
use super::tracefs::{probe_tracefs, tracefs_translate};

/// Kernel-config read cap: 8 MiB.
pub const MAX_NARROW_CONFIG_BYTES: usize = 8_388_608;
/// Narrow BTF read cap: the shared kernel BTF cap.
pub const MAX_NARROW_BTF_BYTES: usize = MAX_KERNEL_BTF_BYTES;
/// Trace-format read cap: 1 MiB.
pub const MAX_NARROW_FORMAT_BYTES: usize = 1_048_576;
/// BPF object read cap: 64 MiB. Canonical home: the
/// artifact snapshot adapter imports this value.
pub const MAX_NARROW_OBJECT_BYTES: usize = 67_108_864;
/// Boot-image read cap: 256 MiB.
pub const MAX_NARROW_IMAGE_BYTES: usize = 268_435_456;
/// Kernel-notes read cap: 1 MiB.
pub const MAX_NARROW_NOTES_BYTES: usize = 1_048_576;
/// Largest admissible ring size: u32::MAX.
pub const MAX_NARROW_RING_BYTES: i64 = 4_294_967_295;

/// Parsed section 5 grammar bindings (rings are canonical decimal).
///
/// Extended lifecycle/copy bindings stay empty for 8-field
/// attempt-only notes; a capture requesting those channels
/// refuses unless the note binds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowBindings {
    /// Config bytes hash (bare hex).
    pub config: String,
    /// `gz` or `file`.
    pub config_src: String,
    /// Kernel BTF hash (bare hex).
    pub btf: String,
    /// Trace-format hash (bare hex).
    pub format: String,
    /// Attempt object hash (bare hex).
    pub object: String,
    /// Boot-image hash (bare hex).
    pub image: String,
    /// Boot-image build id (40 hex).
    pub image_bid: String,
    /// Attempt ring size (canonical decimal).
    pub ring: String,
    /// Lifecycle object hash (bare hex).
    pub lc_object: String,
    /// Lifecycle ring size (canonical decimal).
    pub lc_ring: String,
    /// Copy object hash (bare hex).
    pub cp_object: String,
    /// Copy ring size (canonical decimal).
    pub cp_ring: String,
}

impl NarrowBindings {
    /// Empty bindings.
    pub fn new() -> Self {
        Self {
            config: String::new(),
            config_src: String::new(),
            btf: String::new(),
            format: String::new(),
            object: String::new(),
            image: String::new(),
            image_bid: String::new(),
            ring: String::new(),
            lc_object: String::new(),
            lc_ring: String::new(),
            cp_object: String::new(),
            cp_ring: String::new(),
        }
    }
}

impl Default for NarrowBindings {
    fn default() -> Self {
        Self::new()
    }
}

/// One note parse (bindings valid only when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowParse {
    /// True when the note parsed.
    pub ok: bool,
    /// The parsed bindings.
    pub bindings: NarrowBindings,
    /// Refusal detail; empty on success.
    pub message: String,
}

impl NarrowParse {
    fn new() -> Self {
        Self {
            ok: false,
            bindings: NarrowBindings::new(),
            message: String::new(),
        }
    }
}

/// One live identity read: value hex, or uncheckable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveValue {
    /// `value` or `uncheckable`.
    pub state: String,
    /// The hex value; empty unless `value`.
    pub value: String,
    /// Uncheckable detail; empty when valued.
    pub detail: String,
}

impl LiveValue {
    fn new() -> Self {
        Self {
            state: String::new(),
            value: String::new(),
            detail: String::new(),
        }
    }
}

/// Live kernel-config read plus the source that served it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigLive {
    /// The hashed value.
    pub value: LiveValue,
    /// `gz`, `file`, or "" when no source read.
    pub src: String,
}

impl ConfigLive {
    fn new() -> Self {
        Self {
            value: LiveValue::new(),
            src: String::new(),
        }
    }
}

/// Live values for every grammar key (rings set by record).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowLive {
    /// Live config hash.
    pub config: LiveValue,
    /// Live config source.
    pub config_src: String,
    /// Live BTF hash.
    pub btf: LiveValue,
    /// Live format hash.
    pub format: LiveValue,
    /// Live attempt object hash.
    pub object: LiveValue,
    /// Live image hash.
    pub image: LiveValue,
    /// Live image build id.
    pub image_bid: LiveValue,
    /// Live attempt ring size.
    pub ring: LiveValue,
    /// Live lifecycle object hash.
    pub lc_object: LiveValue,
    /// Live lifecycle ring size.
    pub lc_ring: LiveValue,
    /// Live copy object hash.
    pub cp_object: LiveValue,
    /// Live copy ring size.
    pub cp_ring: LiveValue,
}

impl NarrowLive {
    /// Empty live values.
    pub fn new() -> Self {
        Self {
            config: LiveValue::new(),
            config_src: String::new(),
            btf: LiveValue::new(),
            format: LiveValue::new(),
            object: LiveValue::new(),
            image: LiveValue::new(),
            image_bid: LiveValue::new(),
            ring: LiveValue::new(),
            lc_object: LiveValue::new(),
            lc_ring: LiveValue::new(),
            cp_object: LiveValue::new(),
            cp_ring: LiveValue::new(),
        }
    }
}

impl Default for NarrowLive {
    fn default() -> Self {
        Self::new()
    }
}

/// One binding check: bound, mismatch, or uncheckable + key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NarrowVerdict {
    /// `bound`, `mismatch`, or `uncheckable`.
    pub state: String,
    /// The deciding key; empty when bound.
    pub key: String,
}

impl NarrowVerdict {
    fn new() -> Self {
        Self {
            state: String::new(),
            key: String::new(),
        }
    }
}

/// Trace-format layout verdict against the program pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutCheck {
    /// True when the layout matches the pins.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
}

impl LayoutCheck {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
        }
    }
}

/// BPF object admission verdict (static ELF checks only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectCheck {
    /// True when the object admitted.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
}

impl ObjectCheck {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
        }
    }
}

/// One kernel config text read: text, denied, none, unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigText {
    /// `text`, `denied`, `none`, or `unreadable`.
    pub state: String,
    /// `gz` or `file`.
    pub src: String,
    /// The decoded text; empty unless `text`.
    pub text: String,
}

impl ConfigText {
    fn new() -> Self {
        Self {
            state: "none".to_string(),
            src: String::new(),
            text: String::new(),
        }
    }
}

/// Note assembly failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteError {
    /// What went wrong.
    pub message: String,
}

impl NoteError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "NoteError(message={})", self.message)
    }
}

impl std::error::Error for NoteError {}

fn is_hex_byte(b: u8) -> bool {
    b.is_ascii_digit() || (b'a'..=b'f').contains(&b)
}

/// Split on single spaces; empty pieces stay (strictness).
fn split_spaces(note: &str) -> Vec<String> {
    note.as_bytes()
        .split(|b| *b == 0x20)
        .map(|piece| std::str::from_utf8(piece).unwrap_or("").to_string())
        .collect()
}

/// Value after `key=`, or "" when the key does not match.
fn field_value(field: &str, key: &str) -> String {
    let want = format!("{key}=");
    let fb = field.as_bytes();
    let wb = want.as_bytes();
    if fb.len() <= wb.len() {
        return String::new();
    }
    for i in 0..wb.len() {
        if fb[i] != wb[i] {
            return String::new();
        }
    }
    std::str::from_utf8(&fb[wb.len()..])
        .unwrap_or("")
        .to_string()
}

/// True for exactly "sha256:" plus 64 lowercase hex digits.
pub fn is_sha256_value(text: &str) -> bool {
    let pre = "sha256:";
    let tb = text.as_bytes();
    let pb = pre.as_bytes();
    if tb.len() != pb.len() + 64 {
        return false;
    }
    for i in 0..pb.len() {
        if tb[i] != pb[i] {
            return false;
        }
    }
    for b in &tb[pb.len()..tb.len()] {
        if !is_hex_byte(*b) {
            return false;
        }
    }
    true
}

fn sha256_hex_value(text: &str) -> String {
    text.get(7..).unwrap_or("").to_string()
}

fn is_bid_value(text: &str) -> bool {
    let tb = text.as_bytes();
    if tb.len() != 40 {
        return false;
    }
    for b in tb {
        if !is_hex_byte(*b) {
            return false;
        }
    }
    true
}

/// Canonical decimal ring size, or "" when invalid.
fn parse_ring_value(text: &str) -> String {
    let tb = text.as_bytes();
    if tb.is_empty() || tb.len() > 10 {
        return String::new();
    }
    if tb[0] < 0x31 || tb[0] > 0x39 {
        return String::new();
    }
    let mut v: i64 = 0;
    for b in tb {
        if *b < 0x30 || *b > 0x39 {
            return String::new();
        }
        let d = i64::from(*b) - 0x30;
        if v > (MAX_NARROW_RING_BYTES - d) / 10 {
            return String::new();
        }
        v = v * 10 + d;
    }
    text.to_string()
}

/// Strict-parse the section 5 grammar note.
///
/// Fixed order, exact keys, single spaces, lowercase
/// hex, exact lengths: 8 fields for attempt-only notes,
/// 12 with the appended lc_object/lc_ring_bytes/cp_object/
/// cp_ring_bytes bindings. Anything else is an unbound
/// reference (ok False, key named, never an error).
pub fn parse_narrow_note(note: &str) -> NarrowParse {
    let mut out = NarrowParse::new();
    let fields = split_spaces(note);
    if fields.len() != 8 && fields.len() != 12 {
        out.message = "narrow note: want 8 or 12 fields".to_string();
        return out;
    }
    let config = field_value(&fields[0], "config");
    let config_src = field_value(&fields[1], "config_src");
    let btf = field_value(&fields[2], "btf");
    let format = field_value(&fields[3], "format");
    let object = field_value(&fields[4], "object");
    let image = field_value(&fields[5], "image");
    let image_bid = field_value(&fields[6], "image_bid");
    let ring = field_value(&fields[7], "ring_bytes");
    if config.is_empty() || !is_sha256_value(&config) {
        out.message = "narrow note: bad config".to_string();
        return out;
    }
    if config_src != "gz" && config_src != "file" {
        out.message = "narrow note: bad config_src".to_string();
        return out;
    }
    if btf.is_empty() || !is_sha256_value(&btf) {
        out.message = "narrow note: bad btf".to_string();
        return out;
    }
    if format.is_empty() || !is_sha256_value(&format) {
        out.message = "narrow note: bad format".to_string();
        return out;
    }
    if object.is_empty() || !is_sha256_value(&object) {
        out.message = "narrow note: bad object".to_string();
        return out;
    }
    if image.is_empty() || !is_sha256_value(&image) {
        out.message = "narrow note: bad image".to_string();
        return out;
    }
    if image_bid.is_empty() || !is_bid_value(&image_bid) {
        out.message = "narrow note: bad image_bid".to_string();
        return out;
    }
    let ring_ok = parse_ring_value(&ring);
    if ring_ok.is_empty() {
        out.message = "narrow note: bad ring_bytes".to_string();
        return out;
    }
    out.ok = true;
    out.bindings.config = sha256_hex_value(&config);
    out.bindings.config_src = config_src;
    out.bindings.btf = sha256_hex_value(&btf);
    out.bindings.format = sha256_hex_value(&format);
    out.bindings.object = sha256_hex_value(&object);
    out.bindings.image = sha256_hex_value(&image);
    out.bindings.image_bid = image_bid;
    out.bindings.ring = ring_ok;
    if fields.len() == 12 {
        let lc_object = field_value(&fields[8], "lc_object");
        let lc_ring = field_value(&fields[9], "lc_ring_bytes");
        let cp_object = field_value(&fields[10], "cp_object");
        let cp_ring = field_value(&fields[11], "cp_ring_bytes");
        if lc_object.is_empty() || !is_sha256_value(&lc_object) {
            out.ok = false;
            out.message = "narrow note: bad lc_object".to_string();
            return out;
        }
        let lc_ring_ok = parse_ring_value(&lc_ring);
        if lc_ring_ok.is_empty() {
            out.ok = false;
            out.message = "narrow note: bad lc_ring_bytes".to_string();
            return out;
        }
        if cp_object.is_empty() || !is_sha256_value(&cp_object) {
            out.ok = false;
            out.message = "narrow note: bad cp_object".to_string();
            return out;
        }
        let cp_ring_ok = parse_ring_value(&cp_ring);
        if cp_ring_ok.is_empty() {
            out.ok = false;
            out.message = "narrow note: bad cp_ring_bytes".to_string();
            return out;
        }
        out.bindings.lc_object = sha256_hex_value(&lc_object);
        out.bindings.lc_ring = lc_ring_ok;
        out.bindings.cp_object = sha256_hex_value(&cp_object);
        out.bindings.cp_ring = cp_ring_ok;
    }
    out.message = String::new();
    out
}

/// Assemble the section 5 grammar note from bindings.
///
/// Fixed order, exact keys, single spaces: the 8 base
/// fields, plus the lc/cp pairs when extra is True. The
/// grammar admits 8 or 12 fields only, so extra channels
/// bind together: extra with any extended binding empty
/// raises instead of minting an unparseable note.
pub fn format_narrow_note(bind: &NarrowBindings, extra: bool) -> Result<String, NoteError> {
    let mut parts: Vec<String> = Vec::new();
    parts.push(format!("config=sha256:{}", bind.config));
    parts.push(format!("config_src={}", bind.config_src));
    parts.push(format!("btf=sha256:{}", bind.btf));
    parts.push(format!("format=sha256:{}", bind.format));
    parts.push(format!("object=sha256:{}", bind.object));
    parts.push(format!("image=sha256:{}", bind.image));
    parts.push(format!("image_bid={}", bind.image_bid));
    parts.push(format!("ring_bytes={}", bind.ring));
    if extra {
        if bind.lc_object.is_empty()
            || bind.lc_ring.is_empty()
            || bind.cp_object.is_empty()
            || bind.cp_ring.is_empty()
        {
            return Err(NoteError::new("extended bindings incomplete".to_string()));
        }
        parts.push(format!("lc_object=sha256:{}", bind.lc_object));
        parts.push(format!("lc_ring_bytes={}", bind.lc_ring));
        parts.push(format!("cp_object=sha256:{}", bind.cp_object));
        parts.push(format!("cp_ring_bytes={}", bind.cp_ring));
    }
    Ok(parts.join(" "))
}

/// Return the note with exactly one object binding replaced.
///
/// `binding` names one grammar key: `object` for the
/// attempt channel, `lc_object` for mapping-lifecycle,
/// `cp_object` for copy-actual. `sha` is the bare-hex
/// replacement. The note must parse, the binding must be
/// known, the sha must be 64 lowercase hex, and the
/// lifecycle/copy bindings require a 12-field note; anything
/// else raises and no note is returned. Siblings are never
/// touched: a stale object hash rebinds only its own
/// binding, so one rebuilt object cannot silently drift
/// another channel's qualification. The result always
/// re-parses (it round-trips through parse and format).
pub fn rebind_note_object(note: &str, binding: &str, sha: &str) -> Result<String, NoteError> {
    let parsed = parse_narrow_note(note);
    if !parsed.ok {
        return Err(NoteError::new(format!("rebind: {}", parsed.message)));
    }
    if !is_sha256_value(&format!("sha256:{sha}")) {
        return Err(NoteError::new(
            "rebind: sha must be 64 lowercase hex digits".to_string(),
        ));
    }
    let mut bind = parsed.bindings;
    if binding == "object" {
        bind.object = sha.to_string();
    } else if binding == "lc_object" {
        if bind.lc_object.is_empty() {
            return Err(NoteError::new(
                "rebind: lc_object needs a 12-field note".to_string(),
            ));
        }
        bind.lc_object = sha.to_string();
    } else if binding == "cp_object" {
        if bind.cp_object.is_empty() {
            return Err(NoteError::new(
                "rebind: cp_object needs a 12-field note".to_string(),
            ));
        }
        bind.cp_object = sha.to_string();
    } else {
        return Err(NoteError::new(format!("rebind: unknown binding {binding}")));
    }
    let extra = !bind.lc_object.is_empty();
    format_narrow_note(&bind, extra)
}

fn join(root: &str, path: &str) -> String {
    if root == "/" || root.is_empty() {
        return path.to_string();
    }
    format!("{root}{path}")
}

fn uncheckable(detail: String) -> LiveValue {
    let mut v = LiveValue::new();
    v.state = "uncheckable".to_string();
    v.value = String::new();
    v.detail = detail;
    v
}

fn valued(hex: String) -> LiveValue {
    let mut v = LiveValue::new();
    v.state = "value".to_string();
    v.value = hex;
    v.detail = String::new();
    v
}

/// First available config source, hashed (bytes, gunzipped).
pub fn read_live_config(root: &str, release: &str, zlib: &str) -> ConfigLive {
    let mut out = ConfigLive::new();
    let gz_path = join(root, "/proc/config.gz");
    if let Ok(gz) = read_host_file(&gz_path, "config", MAX_NARROW_CONFIG_BYTES) {
        out.src = "gz".to_string();
        if gz.len() >= 2 && gz[0] == 0x1F && gz[1] == 0x8B {
            let inflated = gunzip_member(&gz, zlib);
            if !inflated.ok {
                out.value = uncheckable(inflated.message);
                return out;
            }
            out.value = valued(sha256_hex(&inflated.data));
            return out;
        }
        out.value = valued(sha256_hex(&gz));
        return out;
    }
    let file_path = join(root, &format!("/boot/config-{release}"));
    if let Ok(raw) = read_host_file(&file_path, "config", MAX_NARROW_CONFIG_BYTES) {
        out.src = "file".to_string();
        out.value = valued(sha256_hex(&raw));
        return out;
    }
    out.src = String::new();
    out.value = uncheckable("no config source".to_string());
    out
}

/// First available config source, decoded to text.
///
/// Mirrors read_live_config source order (/proc/config.gz
/// then /boot/config-<release>) but stays denied-aware:
/// denied evidence is never read through, and a denied
/// source with no readable fallback reports denied.
pub fn read_live_config_text(reader: &EvidenceReader, release: &str, zlib: &str) -> ConfigText {
    let mut out = ConfigText::new();
    let gz_path = "/proc/config.gz".to_string();
    let boot_path = format!("/boot/config-{release}");
    let gz_st = file_state(reader, &gz_path);
    let boot_st = file_state(reader, &boot_path);
    if gz_st == EVIDENCE_OK
        && let Ok(gz) = read_evidence(reader, &gz_path, MAX_NARROW_CONFIG_BYTES)
    {
        out.src = "gz".to_string();
        let is_gz = gz.len() >= 2 && gz[0] == 0x1F && gz[1] == 0x8B;
        if is_gz {
            let inflated = gunzip_member(&gz, zlib);
            if !inflated.ok {
                out.state = "unreadable".to_string();
                return out;
            }
            out.text = bytes_to_text(&inflated.data);
            out.state = "text".to_string();
            return out;
        }
        out.text = bytes_to_text(&gz);
        out.state = "text".to_string();
        return out;
    }
    if boot_st == EVIDENCE_OK {
        match read_evidence(reader, &boot_path, MAX_NARROW_CONFIG_BYTES) {
            Ok(raw) => {
                out.src = "file".to_string();
                out.text = bytes_to_text(&raw);
                out.state = "text".to_string();
                return out;
            }
            Err(_) => {
                out.src = "file".to_string();
                out.state = "unreadable".to_string();
                return out;
            }
        }
    }
    if gz_st == EVIDENCE_DENIED || boot_st == EVIDENCE_DENIED {
        out.state = "denied".to_string();
        if gz_st == EVIDENCE_DENIED {
            out.src = "gz".to_string();
        } else {
            out.src = "file".to_string();
        }
        return out;
    }
    out.state = "none".to_string();
    out
}

/// Hash one raw identity file (btf, format, image).
pub fn read_live_bytes(root: &str, path: &str, what: &str, cap: usize) -> LiveValue {
    match read_host_file(&join(root, path), what, cap) {
        Ok(raw) => valued(sha256_hex(&raw)),
        Err(_) => uncheckable(format!("{what} unreadable")),
    }
}

/// Translate one profile format path onto the live tracefs root.
///
/// An unopenable root keeps the profile path: the read
/// itself still fails closed downstream.
pub fn tracefs_format_path(root: &str, format_path: &str) -> String {
    match open_evidence_reader(root) {
        Ok(reader) => tracefs_translate(&probe_tracefs(&reader), format_path),
        Err(_) => format_path.to_string(),
    }
}

/// Hash the BPF object file bytes (explicit path).
pub fn read_live_object(path: &str) -> LiveValue {
    match read_host_file(path, "object", MAX_NARROW_OBJECT_BYTES) {
        Ok(raw) => valued(sha256_hex(&raw)),
        Err(_) => uncheckable("object unreadable".to_string()),
    }
}

/// Hash BPF object bytes already in hand (embedded lane).
///
/// The embedded Aya artifacts hash here instead of through
/// the filesystem: same sha256 over the same bytes the
/// loader consumes, so bound-vs-live comparison is unchanged.
pub fn read_live_object_bytes(data: &[u8]) -> LiveValue {
    valued(sha256_hex(data))
}

fn notes_u32(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at])
        | (i64::from(data[at + 1]) << 8)
        | (i64::from(data[at + 2]) << 16)
        | (i64::from(data[at + 3]) << 24)
}

/// First NT_GNU_BUILD_ID (type 3, name GNU) as 40 hex.
///
/// Malformed notes, a GNU note with a non-20-byte
/// descriptor, or no GNU note all report uncheckable.
pub fn parse_notes_bid(data: &[u8]) -> LiveValue {
    let total = data.len() as i64;
    let mut pos: i64 = 0;
    while pos + 12 <= total {
        let namesz = notes_u32(data, pos);
        let descsz = notes_u32(data, pos + 4);
        let ntype = notes_u32(data, pos + 8);
        pos += 12;
        if namesz < 0 || descsz < 0 {
            return uncheckable("notes unparseable".to_string());
        }
        let name_end = pos + ((namesz + 3) / 4) * 4;
        if name_end > total {
            return uncheckable("notes unparseable".to_string());
        }
        let is_gnu = ntype == 3
            && namesz == 4
            && data[pos as usize] == 0x47
            && data[(pos + 1) as usize] == 0x4E
            && data[(pos + 2) as usize] == 0x55
            && data[(pos + 3) as usize] == 0;
        pos = name_end;
        let desc_end = pos + ((descsz + 3) / 4) * 4;
        if desc_end > total {
            return uncheckable("notes unparseable".to_string());
        }
        if is_gnu {
            if descsz != 20 {
                return uncheckable("build-id malformed".to_string());
            }
            let mut desc: Vec<u8> = Vec::new();
            for i in 0..20 {
                desc.push(data[(pos + i) as usize]);
            }
            return valued(bytes_to_hex(&desc));
        }
        pos = desc_end;
    }
    uncheckable("no build-id note".to_string())
}

/// Running kernel GNU build-id from /sys/kernel/notes.
pub fn read_live_bid(root: &str) -> LiveValue {
    match read_host_file(
        &join(root, "/sys/kernel/notes"),
        "notes",
        MAX_NARROW_NOTES_BYTES,
    ) {
        Ok(raw) => parse_notes_bid(&raw),
        Err(_) => uncheckable("notes unreadable".to_string()),
    }
}

/// Measure live identity values; "" when all six read.
///
/// Reads config, BTF, trace format, image, and build-id
/// from the evidence tree under root into bindings.
/// Object and ring bindings stay empty: object bytes come
/// from an explicit path and ring sizes from the loaded
/// object, neither of which measuring owns. Shared by
/// qualify planning and live receipt verification so both
/// read the same six files the same way.
pub fn measure_live_bindings(
    root: &str,
    release: &str,
    zlib: &str,
    format_path: &str,
    bindings: &mut NarrowBindings,
) -> String {
    let cfg = read_live_config(root, release, zlib);
    if cfg.src.is_empty() || cfg.value.state != "value" {
        return "live bindings unmeasurable: config".to_string();
    }
    let btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    if btf.state != "value" {
        return "live bindings unmeasurable: btf".to_string();
    }
    let form = read_live_bytes(
        root,
        &tracefs_format_path(root, format_path),
        "format",
        MAX_NARROW_FORMAT_BYTES,
    );
    if form.state != "value" {
        return "live bindings unmeasurable: format".to_string();
    }
    let image = read_live_bytes(
        root,
        &format!("/boot/vmlinuz-{release}"),
        "image",
        MAX_NARROW_IMAGE_BYTES,
    );
    if image.state != "value" {
        return "live bindings unmeasurable: image".to_string();
    }
    let bid = read_live_bid(root);
    if bid.state != "value" {
        return "live bindings unmeasurable: image_bid".to_string();
    }
    bindings.config = cfg.value.value.clone();
    bindings.config_src = cfg.src.clone();
    bindings.btf = btf.value.clone();
    bindings.format = form.value.clone();
    bindings.image = image.value.clone();
    bindings.image_bid = bid.value.clone();
    String::new()
}

/// Compare live values against bindings (grammar order).
///
/// First failure wins: config_src, config, btf, format,
/// object, image, image_bid, ring_bytes.
pub fn check_narrow(bind: &NarrowBindings, live: &NarrowLive) -> NarrowVerdict {
    let mut out = NarrowVerdict::new();
    if live.config_src.is_empty() {
        out.state = "uncheckable".to_string();
        out.key = "config".to_string();
        return out;
    }
    if live.config_src != bind.config_src {
        out.state = "mismatch".to_string();
        out.key = "config_src".to_string();
        return out;
    }
    if live.config.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "config".to_string();
        return out;
    }
    if live.config.value != bind.config {
        out.state = "mismatch".to_string();
        out.key = "config".to_string();
        return out;
    }
    if live.btf.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "btf".to_string();
        return out;
    }
    if live.btf.value != bind.btf {
        out.state = "mismatch".to_string();
        out.key = "btf".to_string();
        return out;
    }
    if live.format.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "format".to_string();
        return out;
    }
    if live.format.value != bind.format {
        out.state = "mismatch".to_string();
        out.key = "format".to_string();
        return out;
    }
    if live.object.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "object".to_string();
        return out;
    }
    if live.object.value != bind.object {
        out.state = "mismatch".to_string();
        out.key = "object".to_string();
        return out;
    }
    if live.image.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "image".to_string();
        return out;
    }
    if live.image.value != bind.image {
        out.state = "mismatch".to_string();
        out.key = "image".to_string();
        return out;
    }
    if live.image_bid.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "image_bid".to_string();
        return out;
    }
    if live.image_bid.value != bind.image_bid {
        out.state = "mismatch".to_string();
        out.key = "image_bid".to_string();
        return out;
    }
    if live.ring.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "ring_bytes".to_string();
        return out;
    }
    if live.ring.value != bind.ring {
        out.state = "mismatch".to_string();
        out.key = "ring_bytes".to_string();
        return out;
    }
    out.state = "bound".to_string();
    out.key = String::new();
    out
}

/// Check identity bindings against live reads (no object/ring).
///
/// Compares config_src, config, btf, format, image, and
/// image_bid from the note against the evidence tree under
/// root, in grammar order with first failure winning. The
/// object and ring bindings stay record-time checks: object
/// bytes come from an explicit path and ring sizes from the
/// loaded object, neither of which passive selection owns.
pub fn check_identity_bindings(
    root: &str,
    release: &str,
    note: &str,
    zlib: &str,
    format_path: &str,
) -> NarrowVerdict {
    let mut out = NarrowVerdict::new();
    let parsed = parse_narrow_note(note);
    if !parsed.ok {
        out.state = "uncheckable".to_string();
        out.key = "note".to_string();
        return out;
    }
    let bind = parsed.bindings;
    let cfg = read_live_config(root, release, zlib);
    if cfg.src.is_empty() {
        out.state = "uncheckable".to_string();
        out.key = "config".to_string();
        return out;
    }
    if cfg.src != bind.config_src {
        out.state = "mismatch".to_string();
        out.key = "config_src".to_string();
        return out;
    }
    if cfg.value.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "config".to_string();
        return out;
    }
    if cfg.value.value != bind.config {
        out.state = "mismatch".to_string();
        out.key = "config".to_string();
        return out;
    }
    let btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    if btf.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "btf".to_string();
        return out;
    }
    if btf.value != bind.btf {
        out.state = "mismatch".to_string();
        out.key = "btf".to_string();
        return out;
    }
    let form = read_live_bytes(
        root,
        &tracefs_format_path(root, format_path),
        "format",
        MAX_NARROW_FORMAT_BYTES,
    );
    if form.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "format".to_string();
        return out;
    }
    if form.value != bind.format {
        out.state = "mismatch".to_string();
        out.key = "format".to_string();
        return out;
    }
    let image = read_live_bytes(
        root,
        &format!("/boot/vmlinuz-{release}"),
        "image",
        MAX_NARROW_IMAGE_BYTES,
    );
    if image.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "image".to_string();
        return out;
    }
    if image.value != bind.image {
        out.state = "mismatch".to_string();
        out.key = "image".to_string();
        return out;
    }
    let bid = read_live_bid(root);
    if bid.state != "value" {
        out.state = "uncheckable".to_string();
        out.key = "image_bid".to_string();
        return out;
    }
    if bid.value != bind.image_bid {
        out.state = "mismatch".to_string();
        out.key = "image_bid".to_string();
        return out;
    }
    out.state = "bound".to_string();
    out.key = String::new();
    out
}

/// Compare requested extended bindings (lc before cp).
///
/// Unrequested channels bind vacuously. A requested
/// channel without a note binding mismatches on its
/// object key; otherwise object bytes then ring size
/// must match exactly, like the base grammar.
pub fn check_narrow_extra(
    bind: &NarrowBindings,
    live: &NarrowLive,
    want_lc: bool,
    want_cp: bool,
) -> NarrowVerdict {
    let mut out = NarrowVerdict::new();
    if want_lc {
        if bind.lc_object.is_empty() {
            out.state = "mismatch".to_string();
            out.key = "lc_object".to_string();
            return out;
        }
        if live.lc_object.state != "value" {
            out.state = "uncheckable".to_string();
            out.key = "lc_object".to_string();
            return out;
        }
        if live.lc_object.value != bind.lc_object {
            out.state = "mismatch".to_string();
            out.key = "lc_object".to_string();
            return out;
        }
        if live.lc_ring.state != "value" {
            out.state = "uncheckable".to_string();
            out.key = "lc_ring_bytes".to_string();
            return out;
        }
        if live.lc_ring.value != bind.lc_ring {
            out.state = "mismatch".to_string();
            out.key = "lc_ring_bytes".to_string();
            return out;
        }
    }
    if want_cp {
        if bind.cp_object.is_empty() {
            out.state = "mismatch".to_string();
            out.key = "cp_object".to_string();
            return out;
        }
        if live.cp_object.state != "value" {
            out.state = "uncheckable".to_string();
            out.key = "cp_object".to_string();
            return out;
        }
        if live.cp_object.value != bind.cp_object {
            out.state = "mismatch".to_string();
            out.key = "cp_object".to_string();
            return out;
        }
        if live.cp_ring.state != "value" {
            out.state = "uncheckable".to_string();
            out.key = "cp_ring_bytes".to_string();
            return out;
        }
        if live.cp_ring.value != bind.cp_ring {
            out.state = "mismatch".to_string();
            out.key = "cp_ring_bytes".to_string();
            return out;
        }
    }
    out.state = "bound".to_string();
    out.key = String::new();
    out
}

/// One pinned trace-format field (name, type, offset, size).
struct FieldPin {
    name: String,
    ftype: String,
    offset: i64,
    size: i64,
}

/// Fields the BPF program reads, plus the common_type anchor.
///
/// Derived from the pinned tracepoint header plus natural
/// alignment: dev_name __data_loc u32 @8, padding to @16,
/// dma_mask u64 @16, dev_addr u64 @24, size u64 @32,
/// force bool @40.
fn layout_pins() -> Vec<FieldPin> {
    vec![
        FieldPin {
            name: "common_type".to_string(),
            ftype: "unsigned short".to_string(),
            offset: 0,
            size: 2,
        },
        FieldPin {
            name: "dev_name".to_string(),
            ftype: "__data_loc char[]".to_string(),
            offset: 8,
            size: 4,
        },
        FieldPin {
            name: "size".to_string(),
            ftype: "size_t".to_string(),
            offset: 32,
            size: 8,
        },
        FieldPin {
            name: "force".to_string(),
            ftype: "bool".to_string(),
            offset: 40,
            size: 1,
        },
    ]
}

/// Split bytes on newlines; a trailing empty piece is dropped.
fn split_lines(data: &[u8]) -> Vec<&[u8]> {
    let mut out: Vec<&[u8]> = data.split(|b| *b == 0x0A).collect();
    if out.last().is_some_and(|last| last.is_empty()) {
        out.pop();
    }
    out
}

fn starts_with(line: &[u8], pre: &str) -> bool {
    let pb = pre.as_bytes();
    if line.len() < pb.len() {
        return false;
    }
    for i in 0..pb.len() {
        if line[i] != pb[i] {
            return false;
        }
    }
    true
}

/// Decimal value, or -1 when empty, long, or non-decimal.
fn parse_decimal(digits: &[u8]) -> i64 {
    if digits.is_empty() || digits.len() > 10 {
        return -1;
    }
    let mut v: i64 = 0;
    for b in digits {
        if *b < 0x30 || *b > 0x39 {
            return -1;
        }
        let d = i64::from(*b) - 0x30;
        if v > (2_147_483_647 - d) / 10 {
            return -1;
        }
        v = v * 10 + d;
    }
    v
}

fn split_tabs(line: &[u8]) -> Vec<&[u8]> {
    line.split(|b| *b == 0x09).collect()
}

struct FormatField {
    ok: bool,
    name: String,
    ftype: String,
    offset: i64,
    size: i64,
}

impl FormatField {
    fn new() -> Self {
        Self {
            ok: false,
            name: String::new(),
            ftype: String::new(),
            offset: -1,
            size: -1,
        }
    }
}

/// True when the text holds an embedded NUL byte.
fn has_nul(text: &str) -> bool {
    text.as_bytes().contains(&0)
}

/// Strict-parse one `field:TYPE NAME;\toffset:O;\tsize:S;` line.
fn parse_format_field(line: &[u8]) -> FormatField {
    let mut out = FormatField::new();
    let parts = split_tabs(line);
    if parts.len() < 3 {
        return out;
    }
    let head = parts[0];
    if !starts_with(head, "field:") || head.last() != Some(&0x3B) {
        return out;
    }
    let inner = &head[6..head.len() - 1];
    let mut cut: i64 = -1;
    for (i, b) in inner.iter().enumerate() {
        if *b == 0x20 {
            cut = i as i64;
        }
    }
    if cut <= 0 || cut + 1 >= inner.len() as i64 {
        return out;
    }
    let off = parts[1];
    if !starts_with(off, "offset:") || off.last() != Some(&0x3B) || off.len() <= 8 {
        return out;
    }
    let siz = parts[2];
    if !starts_with(siz, "size:") || siz.last() != Some(&0x3B) || siz.len() <= 6 {
        return out;
    }
    let cut = cut as usize;
    let offset = parse_decimal(&off[7..off.len() - 1]);
    let size = parse_decimal(&siz[5..siz.len() - 1]);
    if offset < 0 || size < 0 {
        return out;
    }
    let Ok(ftype) = std::str::from_utf8(&inner[0..cut]) else {
        return out;
    };
    let Ok(name) = std::str::from_utf8(&inner[cut + 1..inner.len()]) else {
        return out;
    };
    if ftype.is_empty() || name.is_empty() {
        out.ok = false;
        return out;
    }
    out.ftype = ftype.to_string();
    out.name = name.to_string();
    out.offset = offset;
    out.size = size;
    out.ok = true;
    out
}

/// Verify the live format against the pinned program layout.
///
/// Non-field lines are skipped and leading blanks are
/// tolerated (tracefs indents field lines); every pinned
/// field must appear exactly once with the pinned type,
/// offset, and size. Anything else refuses: the program
/// would read the wrong bytes.
pub fn check_trace_layout(data: &[u8]) -> LayoutCheck {
    let mut out = LayoutCheck::new();
    let pins = layout_pins();
    let mut seen = vec![false; pins.len()];
    for line in split_lines(data) {
        let mut s = 0;
        while s < line.len() && (line[s] == 9 || line[s] == 0x20) {
            s += 1;
        }
        if s >= line.len() {
            continue;
        }
        let body = &line[s..line.len()];
        if !starts_with(body, "field:") {
            continue;
        }
        let f = parse_format_field(body);
        if !f.ok {
            out.message = "format line unparseable".to_string();
            return out;
        }
        for (i, pin) in pins.iter().enumerate() {
            if f.name == pin.name {
                if seen[i] {
                    out.message = format!("duplicate field {}", f.name);
                    return out;
                }
                seen[i] = true;
                if f.ftype != pin.ftype {
                    out.message = format!("field {}: want type {}", f.name, pin.ftype);
                    return out;
                }
                if f.offset != pin.offset || f.size != pin.size {
                    out.message = format!("field {}: want @{}:{}", f.name, pin.offset, pin.size);
                    return out;
                }
            }
        }
    }
    for i in 0..pins.len() {
        if !seen[i] {
            out.message = format!("missing field {}", pins[i].name);
            return out;
        }
    }
    out.ok = true;
    out.message = String::new();
    out
}

/// One discovered tracefs format field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceField {
    /// Field name.
    pub name: String,
    /// Field type spelling.
    pub ftype: String,
    /// Byte offset.
    pub offset: i64,
    /// Byte size.
    pub size: i64,
}

impl TraceField {
    fn new(name: String, ftype: String, offset: i64, size: i64) -> Self {
        Self {
            name,
            ftype,
            offset,
            size,
        }
    }
}

/// Discovered layout of one tracefs event format (fields valid iff ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceFormat {
    /// True when the layout parsed.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// The discovered fields.
    pub fields: Vec<TraceField>,
}

impl TraceFormat {
    /// An empty invalid layout.
    pub fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            fields: Vec::new(),
        }
    }
}

impl Default for TraceFormat {
    fn default() -> Self {
        Self::new()
    }
}

/// Strict-parse a tracefs event format into its field layout.
///
/// Non-field lines are skipped and leading blanks are
/// tolerated (tracefs indents field lines). Any unparseable
/// field line, NUL byte in a field name or type, or
/// duplicate field name refuses: offsets derived from a
/// misread layout would read wrong bytes. Bytes in skipped
/// lines and ignored trailing columns are never inspected.
pub fn parse_trace_format(data: &[u8]) -> TraceFormat {
    let mut out = TraceFormat::new();
    for line in split_lines(data) {
        let mut s = 0;
        while s < line.len() && (line[s] == 9 || line[s] == 0x20) {
            s += 1;
        }
        if s >= line.len() {
            continue;
        }
        let body = &line[s..line.len()];
        if !starts_with(body, "field:") {
            continue;
        }
        let f = parse_format_field(body);
        if !f.ok {
            out.message = "format line unparseable".to_string();
            return out;
        }
        if has_nul(&f.name) || has_nul(&f.ftype) {
            out.message = "format line unparseable".to_string();
            return out;
        }
        for i in 0..out.fields.len() {
            if out.fields[i].name == f.name {
                out.message = format!("duplicate field {}", f.name);
                return out;
            }
        }
        out.fields.push(TraceField::new(
            f.name.clone(),
            f.ftype.clone(),
            f.offset,
            f.size,
        ));
    }
    out.ok = true;
    out.message = String::new();
    out
}

/// Known-good attempt layout, as the program pins it.
pub fn known_trace_format() -> TraceFormat {
    let mut out = TraceFormat::new();
    let pins = layout_pins();
    for pin in &pins {
        out.fields.push(TraceField::new(
            pin.name.clone(),
            pin.ftype.clone(),
            pin.offset,
            pin.size,
        ));
    }
    out.ok = true;
    out.message = String::new();
    out
}

/// First structural difference of live against want, else "".
///
/// Every wanted field must exist in live with the same type,
/// offset, and size; extra live fields are tolerated because
/// kernels may extend the record. The message names exact
/// wanted and live values so diagnostics can quote it.
pub fn diff_trace_format(want: &TraceFormat, live: &TraceFormat) -> String {
    if !want.ok {
        return "want layout invalid".to_string();
    }
    if !live.ok {
        return format!("live layout invalid: {}", live.message);
    }
    for w in &want.fields {
        let mut found: i64 = -1;
        for (j, field) in live.fields.iter().enumerate() {
            if field.name == w.name {
                found = j as i64;
                break;
            }
        }
        if found < 0 {
            return format!("missing field {}", w.name);
        }
        let got = &live.fields[found as usize];
        if got.ftype != w.ftype {
            return format!(
                "field {}: want type {}, live {}",
                w.name, w.ftype, got.ftype
            );
        }
        if got.offset != w.offset || got.size != w.size {
            return format!(
                "field {}: want @{}:{}, live @{}:{}",
                w.name, w.offset, w.size, got.offset, got.size
            );
        }
    }
    String::new()
}

/// Offsets-table magic ("MFO5" little-endian).
///
/// Re-export of the canonical `memveil-ebpf-common` wire
/// constant as the `i64` outcome vocabulary this module
/// uses; values stay linked at compile time.
pub const MV_OFF_TABLE_MAGIC: i64 = memveil_ebpf_common::MV_OFF_TABLE_MAGIC as i64;
/// Offsets-table version (canonical re-export, see above).
pub const MV_OFF_TABLE_VERSION: i64 = memveil_ebpf_common::MV_OFF_TABLE_VERSION as i64;
/// Fixed-region cap for tabled extents (canonical re-export, see above).
pub const MV_FIXED_MAX: i64 = memveil_ebpf_common::MV_FIXED_MAX as i64;
/// Encoded offsets-table length in bytes (canonical re-export, see above).
pub const MV_OFFSETS_TABLE_LEN: i64 = memveil_ebpf_common::MV_OFFSETS_TABLE_LEN as i64;

/// One live-layout probe: table offsets, or a named refusal.
///
/// `ok` True carries the probed `__data_loc` slot,
/// size, and force offsets plus the dynamic-data floor
/// (`fixed_end`) for the load-time offset table;
/// `moved` tells a drifted-but-readable layout from
/// the pinned one. `ok` False carries the refusing
/// drift class in `message`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OffsetProbe {
    /// True when the layout probed.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// True when pins moved from the pinned layout.
    pub moved: bool,
    /// Probed dev_name offset.
    pub loc_off: i64,
    /// Probed size offset.
    pub size_off: i64,
    /// Probed force offset.
    pub force_off: i64,
    /// Dynamic-data floor.
    pub fixed_end: i64,
}

impl OffsetProbe {
    fn new() -> Self {
        Self {
            ok: false,
            message: String::new(),
            moved: false,
            loc_off: -1,
            size_off: -1,
            force_off: -1,
            fixed_end: -1,
        }
    }
}

fn refuse_probe(message: String) -> OffsetProbe {
    let mut out = OffsetProbe::new();
    out.ok = false;
    out.message = message;
    out
}

fn extents_overlap(a_off: i64, a_w: i64, b_off: i64, b_w: i64) -> bool {
    // Saturating ends match the bpf probe form; probe-reachable
    // values (parse caps offsets and sizes at i32::MAX) never
    // saturate, so this only removes the absurd-input panic edge.
    a_off < b_off.saturating_add(b_w) && b_off < a_off.saturating_add(a_w)
}

/// Index of the live field named want, or -1.
fn find_live_field(fields: &[TraceField], want: &str) -> i64 {
    for (i, field) in fields.iter().enumerate() {
        if field.name == want {
            return i as i64;
        }
    }
    -1
}

/// Bounds/overlap verdict for one offset table, else "".
///
/// Every tabled extent must sit inside the fixed-region
/// cap, no two pinned extents (including the
/// common_type anchor) may overlap, and the dynamic
/// floor must stay within the cap with margin under the
/// context read cap while covering every tabled
/// extent. The collector re-runs this on its
/// configured values before install; the BPF program
/// re-checks the same properties at runtime.
pub fn validate_table_extents(
    loc_off: i64,
    size_off: i64,
    force_off: i64,
    fixed_end: i64,
) -> String {
    if loc_off < 0 || size_off < 0 || force_off < 0 || fixed_end < 0 {
        return "negative table extent".to_string();
    }
    if loc_off.saturating_add(4) > MV_FIXED_MAX {
        return format!("field dev_name extent @{loc_off}:4 exceeds fixed cap {MV_FIXED_MAX}");
    }
    if size_off.saturating_add(8) > MV_FIXED_MAX {
        return format!("field size extent @{size_off}:8 exceeds fixed cap {MV_FIXED_MAX}");
    }
    if force_off.saturating_add(1) > MV_FIXED_MAX {
        return format!("field force extent @{force_off}:1 exceeds fixed cap {MV_FIXED_MAX}");
    }
    if extents_overlap(0, 2, loc_off, 4) {
        return "overlapping extents common_type and dev_name".to_string();
    }
    if extents_overlap(0, 2, size_off, 8) {
        return "overlapping extents common_type and size".to_string();
    }
    if extents_overlap(0, 2, force_off, 1) {
        return "overlapping extents common_type and force".to_string();
    }
    if extents_overlap(loc_off, 4, size_off, 8) {
        return "overlapping extents dev_name and size".to_string();
    }
    if extents_overlap(loc_off, 4, force_off, 1) {
        return "overlapping extents dev_name and force".to_string();
    }
    if extents_overlap(size_off, 8, force_off, 1) {
        return "overlapping extents size and force".to_string();
    }
    if fixed_end > MV_FIXED_MAX {
        return format!("fixed region end {fixed_end} exceeds cap {MV_FIXED_MAX}");
    }
    if fixed_end < loc_off.saturating_add(4) {
        return format!("fixed region end {fixed_end} below dev_name extent @{loc_off}:4");
    }
    if fixed_end < size_off.saturating_add(8) {
        return format!("fixed region end {fixed_end} below size extent @{size_off}:8");
    }
    if fixed_end < force_off.saturating_add(1) {
        return format!("fixed region end {fixed_end} below force extent @{force_off}:1");
    }
    String::new()
}

/// Probe the live format into load-time table offsets.
///
/// Pure classifier over already-read bytes: callers pass
/// the same buffer the format binding hashes, so probed
/// offsets inherit that binding (same-buffer derivation,
/// no re-read). The common_type anchor must match the
/// pins exactly; dev_name, size, and force keep their
/// pinned type spellings and widths but may sit at
/// probed offsets; extra live fields are tolerated and
/// the dynamic floor is the max end over every parsed
/// field, __data_loc descriptors included. Any retype,
/// resize, missing or
/// duplicate field, unparseable line, anchor drift,
/// overlap, or cap breach refuses naming its class.
pub fn probe_trace_offsets(data: &[u8]) -> OffsetProbe {
    let fmt = parse_trace_format(data);
    if !fmt.ok {
        return refuse_probe(fmt.message.clone());
    }
    let anchor = find_live_field(&fmt.fields, "common_type");
    if anchor < 0 {
        return refuse_probe("missing field common_type".to_string());
    }
    let got_anchor = &fmt.fields[anchor as usize];
    if got_anchor.ftype != "unsigned short" {
        return refuse_probe(format!(
            "field common_type: want type unsigned short, live {}",
            got_anchor.ftype
        ));
    }
    if got_anchor.offset != 0 || got_anchor.size != 2 {
        return refuse_probe(format!(
            "field common_type: want @0:2, live @{}:{}",
            got_anchor.offset, got_anchor.size
        ));
    }
    let pins = layout_pins();
    let mut offs = [-1; 4];
    for i in 1..4 {
        let at = find_live_field(&fmt.fields, &pins[i].name);
        if at < 0 {
            return refuse_probe(format!("missing field {}", pins[i].name));
        }
        let got = &fmt.fields[at as usize];
        if got.ftype != pins[i].ftype {
            return refuse_probe(format!(
                "field {}: want type {}, live {}",
                pins[i].name, pins[i].ftype, got.ftype
            ));
        }
        if got.size != pins[i].size {
            return refuse_probe(format!(
                "field {}: want size {}, live size {}",
                pins[i].name, pins[i].size, got.size
            ));
        }
        offs[i] = got.offset;
    }
    let moved = offs[1] != pins[1].offset || offs[2] != pins[2].offset || offs[3] != pins[3].offset;
    let mut fixed_end = 0;
    for field in &fmt.fields {
        // Every declared field occupies its fixed slot,
        // including __data_loc descriptors: each is a
        // fixed u32 holding an offset/length pair, not
        // dynamic data itself.
        let end = field.offset.saturating_add(field.size);
        if end > fixed_end {
            fixed_end = end;
        }
    }
    let bad = validate_table_extents(offs[1], offs[2], offs[3], fixed_end);
    if !bad.is_empty() {
        return refuse_probe(bad.clone());
    }
    let mut out = OffsetProbe::new();
    out.ok = true;
    out.message = String::new();
    out.moved = moved;
    out.loc_off = offs[1];
    out.size_off = offs[2];
    out.force_off = offs[3];
    out.fixed_end = fixed_end;
    out
}

fn append_le32(buf: &mut Vec<u8>, v: i64) {
    for i in 0..4 {
        buf.push(((v >> (8 * i)) & 0xFF) as u8);
    }
}

/// Encode one offset table: 24 bytes, little-endian.
///
/// Layout mirrors ``struct mv_offsets`` (magic, version,
/// reserved, loc/size/force offsets, fixed end). A
/// negative input encodes to empty, which install
/// refuses; callers pass probe-admitted or
/// validator-checked values.
pub fn encode_offsets_table(
    loc_off: i64,
    size_off: i64,
    force_off: i64,
    fixed_end: i64,
) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    if loc_off < 0 || size_off < 0 || force_off < 0 || fixed_end < 0 {
        return out;
    }
    append_le32(&mut out, MV_OFF_TABLE_MAGIC);
    out.push((MV_OFF_TABLE_VERSION & 0xFF) as u8);
    out.push(((MV_OFF_TABLE_VERSION >> 8) & 0xFF) as u8);
    out.push(0);
    out.push(0);
    append_le32(&mut out, loc_off);
    append_le32(&mut out, size_off);
    append_le32(&mut out, force_off);
    append_le32(&mut out, fixed_end);
    out
}

fn le16(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at]) | (i64::from(data[at + 1]) << 8)
}

fn le32(data: &[u8], at: i64) -> i64 {
    let at = at as usize;
    i64::from(data[at])
        | (i64::from(data[at + 1]) << 8)
        | (i64::from(data[at + 2]) << 16)
        | (i64::from(data[at + 3]) << 24)
}

fn le64(data: &[u8], at: i64) -> i64 {
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
fn strtab_text(data: &[u8], base: i64, limit: i64, off: i64) -> Option<String> {
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

fn str_starts_with(text: &str, pre: &str) -> bool {
    starts_with(text.as_bytes(), pre)
}

fn refuse(message: String) -> ObjectCheck {
    let mut out = ObjectCheck::new();
    out.ok = false;
    out.message = message;
    out
}

/// Static admission for a BPF object: class, machine, sections, symbol.
///
/// Requires ELF64LE relocatable EM_BPF with a tracepoint
/// section, a maps section, a license section, and the
/// named program as a defined global function living in a
/// tracepoint section. The maps section admits either the
/// libbpf `.maps` or the Aya/bpf-linker `maps` spelling;
/// both spellings face identical type and range rigor.
/// An object carrying both spellings must satisfy both;
/// neither spelling refuses as `no .maps section`.
/// When several required sections are bad, the refusal
/// names the first bad one in section-table order.
/// Required sections must be PROGBITS inside the file,
/// and the program symbol must name a non-empty extent
/// within its section. Any structural defect refuses;
/// this never executes or loads anything.
pub fn verify_object(data: &[u8], want_program: &str) -> ObjectCheck {
    verify_object_inner(data, want_program, "tracepoint/")
}

/// Static admission for one program in a known section kind.
///
/// Same ELF/maps/license/symbol checks as verify_object
/// (either maps spelling admitted with identical rigor),
/// but the program must live in a section starting with
/// section_prefix, one of tracepoint/, fentry/, or fexit/.
/// Anything else refuses without reading the object.
pub fn verify_object_program(data: &[u8], want_program: &str, section_prefix: &str) -> ObjectCheck {
    if section_prefix != "tracepoint/" && section_prefix != "fentry/" && section_prefix != "fexit/"
    {
        return refuse("bad section kind".to_string());
    }
    verify_object_inner(data, want_program, section_prefix)
}

/// Shared worker: verify_object with a section-kind prefix.
fn verify_object_inner(data: &[u8], want_program: &str, prefix: &str) -> ObjectCheck {
    let total = data.len() as i64;
    if total < 64 {
        return refuse("object too small".to_string());
    }
    if data[0] != 0x7F
        || data[1] != 0x45
        || data[2] != 0x4C
        || data[3] != 0x46
        || data[4] != 2
        || data[5] != 1
        || data[6] != 1
    {
        return refuse("not an ELF64LE object".to_string());
    }
    if le16(data, 0x10) != 1 {
        return refuse("not relocatable".to_string());
    }
    if le32(data, 0x14) != 1 {
        return refuse("bad ELF version".to_string());
    }
    if le16(data, 0x12) != 247 {
        return refuse("not a BPF object".to_string());
    }
    let shoff = le64(data, 0x28);
    let shentsize = le16(data, 0x3A);
    let shnum = le16(data, 0x3C);
    let shstrndx = le16(data, 0x3E);
    if shentsize != 64 || shnum == 0 {
        return refuse("no section table".to_string());
    }
    if shstrndx >= shnum || shoff < 0 || shoff > total {
        return refuse("section table out of range".to_string());
    }
    if shnum > (total - shoff) / 64 {
        return refuse("section table out of range".to_string());
    }
    let str_base = shoff + shstrndx * 64;
    let str_off = le64(data, str_base + 24);
    let str_size = le64(data, str_base + 32);
    if str_off < 0 || str_size < 0 || str_off > total {
        return refuse("names out of range".to_string());
    }
    if str_size > total - str_off {
        return refuse("names out of range".to_string());
    }
    let str_end = str_off + str_size;
    let mut names: Vec<String> = Vec::new();
    let mut types: Vec<i64> = Vec::new();
    let mut offs: Vec<i64> = Vec::new();
    let mut sizes: Vec<i64> = Vec::new();
    let mut has_want = false;
    let mut has_maps = false;
    let mut has_aya_maps = false;
    let mut has_license = false;
    let mut symtab: i64 = -1;
    for i in 0..shnum {
        let base = shoff + i * 64;
        let sh_name = le32(data, base);
        let sh_type = le32(data, base + 4);
        let Some(sec_name) = strtab_text(data, str_off, str_end, sh_name) else {
            return refuse("section names corrupt".to_string());
        };
        names.push(sec_name.clone());
        types.push(sh_type);
        offs.push(le64(data, base + 24));
        sizes.push(le64(data, base + 32));
        if str_starts_with(&sec_name, prefix) {
            has_want = true;
        }
        if sec_name == ".maps" {
            has_maps = true;
        }
        if sec_name == "maps" {
            has_aya_maps = true;
        }
        if sec_name == "license" {
            has_license = true;
        }
        if sh_type == 2 && symtab < 0 {
            symtab = i;
        }
    }
    if !has_want {
        let mut display = String::new();
        for (i, b) in prefix.as_bytes().iter().enumerate() {
            if *b == 0x2F {
                break;
            }
            display += &prefix[i..i + 1];
        }
        return refuse(format!("no {display} section"));
    }
    // Either maps spelling admits: libbpf objects carry
    // `.maps`, Aya/bpf-linker objects carry `maps`. Neither
    // spelling refuses with the existing taxonomy; an object
    // carrying both must satisfy both below. When several
    // required sections are bad, the refusal names the
    // first bad one in section-table order.
    if !has_maps && !has_aya_maps {
        return refuse("no .maps section".to_string());
    }
    if !has_license {
        return refuse("no license section".to_string());
    }
    // Required sections must be real PROGBITS content inside
    // the file: names alone admit out-of-file ranges and
    // wrong-type sections that later readers would misparse.
    // Map bytes, geometry, and pins are not parsed here for
    // either spelling: read_btf_maps owns that rigor
    // downstream, and its Aya DATASEC lane is a separate
    // change. This gate stays presence, type, and range.
    for i in 0..shnum {
        let iu = i as usize;
        let required = str_starts_with(&names[iu], prefix)
            || names[iu] == ".maps"
            || names[iu] == "maps"
            || names[iu] == "license";
        if !required {
            continue;
        }
        if types[iu] != 1 {
            return refuse(format!("{} section bad type", names[iu]));
        }
        if offs[iu] < 0 || sizes[iu] < 0 || offs[iu] > total || sizes[iu] > total - offs[iu] {
            return refuse(format!("{} section out of range", names[iu]));
        }
    }
    if symtab < 0 {
        return refuse("no symbol table".to_string());
    }
    let sym_base = shoff + symtab * 64;
    let sym_off = le64(data, sym_base + 24);
    let sym_size = le64(data, sym_base + 32);
    let sym_link = le32(data, sym_base + 40);
    let sym_entsize = le64(data, sym_base + 56);
    if sym_entsize != 24 {
        return refuse("bad symtab entry size".to_string());
    }
    if sym_off < 0 || sym_size < 0 || sym_off > total {
        return refuse("symbols out of range".to_string());
    }
    if sym_size > total - sym_off {
        return refuse("symbols out of range".to_string());
    }
    if sym_link < 0 || sym_link >= shnum {
        return refuse("bad symtab link".to_string());
    }
    let tab_base = shoff + sym_link * 64;
    let tab_off = le64(data, tab_base + 24);
    let tab_size = le64(data, tab_base + 32);
    if tab_off < 0 || tab_size < 0 || tab_off > total {
        return refuse("symbols out of range".to_string());
    }
    if tab_size > total - tab_off {
        return refuse("symbols out of range".to_string());
    }
    let tab_end = tab_off + tab_size;
    let mut detail = String::new();
    let count = sym_size / 24;
    for s in 0..count {
        let sb = sym_off + s * 24;
        let st_name = le32(data, sb);
        let st_info = i64::from(data[(sb + 4) as usize]);
        let st_shndx = le16(data, sb + 6);
        let Some(sym_name) = strtab_text(data, tab_off, tab_end, st_name) else {
            return refuse("symbol names corrupt".to_string());
        };
        if sym_name != want_program {
            continue;
        }
        let bind = st_info >> 4;
        let typ = st_info & 15;
        if bind != 1 || typ != 2 {
            detail = format!("bad binding/type @{st_shndx}");
            continue;
        }
        if st_shndx == 0 || st_shndx >= shnum {
            detail = "program undefined".to_string();
            continue;
        }
        if !str_starts_with(&names[st_shndx as usize], prefix) {
            detail = format!("program in {}", names[st_shndx as usize]);
            continue;
        }
        let st_value = le64(data, sb + 8);
        let st_size = le64(data, sb + 16);
        if st_size <= 0 {
            detail = "program empty".to_string();
            continue;
        }
        let sec_size = sizes[st_shndx as usize];
        if st_value < 0 || st_value > sec_size || st_size > sec_size - st_value {
            detail = "program outside section".to_string();
            continue;
        }
        let mut out = ObjectCheck::new();
        out.ok = true;
        out.message = String::new();
        return out;
    }
    if !detail.is_empty() {
        return refuse(format!("program symbol unusable: {detail}"));
    }
    refuse("program symbol missing".to_string())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_NARROW_OBJECT_BYTES, MV_FIXED_MAX, MV_OFF_TABLE_MAGIC, MV_OFF_TABLE_VERSION,
        MV_OFFSETS_TABLE_LEN, NarrowBindings, NarrowLive, check_identity_bindings, check_narrow,
        check_narrow_extra, check_trace_layout, diff_trace_format, encode_offsets_table,
        format_narrow_note, known_trace_format, measure_live_bindings, parse_narrow_note,
        parse_notes_bid, parse_trace_format, probe_trace_offsets, read_live_bid, read_live_bytes,
        read_live_config, read_live_config_text, read_live_object, read_live_object_bytes,
        rebind_note_object, tracefs_format_path, validate_table_extents, verify_object,
        verify_object_program,
    };
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::{gate_fixture, repo_root};

    const REL: &str = "7.0.0-test";
    const ZLIB: &str = "libz.so.1";
    const CONFIG: &str = "a5af36b05630b51bb596bc68f955ab97bb8802e857cd2fc1de05c0628e398fbb";
    const BTF: &str = "785b0751fc2c53dc14a4ce3d800e69ef9ce1009eb327ccf458afe09c242c26c9";
    const FORMAT: &str = "039a1a6bc665b91c4f846f735f9b2f9ec89d106d7d63a5e9d0b35e20213e80fb";
    const OBJECT: &str = "7549adfdf9837cefd566373a0efeee8550abdb4cd678b6fa15fe11f3f4785a37";
    const IMAGE: &str = "11a663ae36f0cdbecf94b8b7319503bbd0fffc2c3ba02c01cf81600d423dd251";
    const BID: &str = "0102030405060708090a0b0c0d0e0f1011121314";
    const LC_OBJECT: &str = "9c8e7d6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e";
    const CP_OBJECT: &str = "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b";
    const FMT_PATH: &str = "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format";
    const PROG: &str = "mv_swiotlb_attempt";

    fn fields(src: &str, ring: &str) -> Vec<String> {
        vec![
            format!("config=sha256:{CONFIG}"),
            format!("config_src={src}"),
            format!("btf=sha256:{BTF}"),
            format!("format=sha256:{FORMAT}"),
            format!("object=sha256:{OBJECT}"),
            format!("image=sha256:{IMAGE}"),
            format!("image_bid={BID}"),
            format!("ring_bytes={ring}"),
        ]
    }

    fn join(fields: &[String]) -> String {
        fields.join(" ")
    }

    fn fields12() -> Vec<String> {
        let mut out = fields("gz", "8388608");
        out.push(format!("lc_object=sha256:{LC_OBJECT}"));
        out.push("lc_ring_bytes=8388608".to_string());
        out.push(format!("cp_object=sha256:{CP_OBJECT}"));
        out.push("cp_ring_bytes=8388608".to_string());
        out
    }

    fn narrow_root(name: &str) -> String {
        repo_root()
            .join("tests/fixtures/narrow")
            .join(name)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    fn elf_fixture(name: &str) -> Vec<u8> {
        let path = repo_root().join("tests/fixtures/elf").join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn layout_fixture(name: &str) -> Vec<u8> {
        let path = repo_root().join("tests/fixtures/layout").join(name);
        std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    fn read_live(root: &str) -> NarrowLive {
        let mut live = NarrowLive::new();
        let cfg = read_live_config(root, REL, ZLIB);
        live.config = cfg.value;
        live.config_src = cfg.src;
        live.btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", 67_108_864);
        live.format = read_live_bytes(root, FMT_PATH, "format", 1_048_576);
        live.object = read_live_object(&format!("{root}/object.o"));
        live.image = read_live_bytes(root, &format!("/boot/vmlinuz-{REL}"), "image", 268_435_456);
        live.image_bid = read_live_bid(root);
        live.ring.state = "value".to_string();
        live.ring.value = "8388608".to_string();
        live
    }

    fn live_extra(lc_object: &str, lc_ring: &str, cp_object: &str, cp_ring: &str) -> NarrowLive {
        let mut live = NarrowLive::new();
        live.lc_object.state = "value".to_string();
        live.lc_object.value = lc_object.to_string();
        live.lc_ring.state = "value".to_string();
        live.lc_ring.value = lc_ring.to_string();
        live.cp_object.state = "value".to_string();
        live.cp_object.value = cp_object.to_string();
        live.cp_ring.state = "value".to_string();
        live.cp_ring.value = cp_ring.to_string();
        live
    }

    #[test]
    fn grammar_valid() {
        let p = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(p.ok);
        assert_eq!(p.bindings.config, CONFIG);
        assert_eq!(p.bindings.config_src, "gz");
        assert_eq!(p.bindings.btf, BTF);
        assert_eq!(p.bindings.format, FORMAT);
        assert_eq!(p.bindings.object, OBJECT);
        assert_eq!(p.bindings.image, IMAGE);
        assert_eq!(p.bindings.image_bid, BID);
        assert_eq!(p.bindings.ring, "8388608");
    }

    #[test]
    fn format_round_trip_eight() {
        // Parse then format is the identity on 8-field notes.
        let note = join(&fields("gz", "8388608"));
        let parsed = parse_narrow_note(&note);
        assert!(parsed.ok);
        assert_eq!(format_narrow_note(&parsed.bindings, false).unwrap(), note);
    }

    #[test]
    fn format_round_trip_twelve() {
        // Parse then format is the identity on 12-field notes.
        let mut f = fields("file", "8388608");
        f.push(format!("lc_object=sha256:{LC_OBJECT}"));
        f.push("lc_ring_bytes=33554432".to_string());
        f.push(format!("cp_object=sha256:{CP_OBJECT}"));
        f.push("cp_ring_bytes=33554432".to_string());
        let note = join(&f);
        let parsed = parse_narrow_note(&note);
        assert!(parsed.ok);
        assert_eq!(format_narrow_note(&parsed.bindings, true).unwrap(), note);
    }

    #[test]
    fn format_extra_incomplete_raises() {
        // Extra with a missing extended binding raises instead
        // of minting an unparseable 10-field note.
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(parsed.ok);
        assert!(format_narrow_note(&parsed.bindings, true).is_err());
    }

    #[test]
    fn grammar_lengths() {
        // Worst case stays under the 512 note limit; the
        // design's 477 is the gz spelling, 479 with file.
        let gz_note = join(&fields("gz", "4294967295"));
        let file_note = join(&fields("file", "4294967295"));
        assert_eq!(gz_note.len(), 477);
        assert_eq!(file_note.len(), 479);
        assert!(parse_narrow_note(&gz_note).ok);
        assert!(parse_narrow_note(&file_note).ok);
    }

    #[test]
    fn grammar_field_count() {
        let seven = fields("gz", "8388608");
        let p = parse_narrow_note(&join(&seven[..7]));
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: want 8 or 12 fields");
        let nine = join(&fields("gz", "8388608")) + " extra=1";
        let q = parse_narrow_note(&nine);
        assert!(!q.ok);
        assert_eq!(q.message, "narrow note: want 8 or 12 fields");
    }

    #[test]
    fn grammar_spacing() {
        let f = fields("gz", "8388608");
        let mut double = String::new();
        for (i, field) in f.iter().enumerate() {
            if i > 0 {
                if i == 2 {
                    double += "  ";
                } else {
                    double += " ";
                }
            }
            double += field;
        }
        let p = parse_narrow_note(&double);
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: want 8 or 12 fields");
        let base = join(&f);
        assert!(!parse_narrow_note(&format!(" {base}")).ok);
        assert!(!parse_narrow_note(&format!("{base} ")).ok);
        let mut tabbed = format!("{}\t{}", f[0], f[1]);
        for field in &f[2..] {
            tabbed += &format!(" {field}");
        }
        assert!(!parse_narrow_note(&tabbed).ok);
    }

    #[test]
    fn grammar_keys() {
        let mut f = fields("gz", "8388608");
        f.swap(2, 3);
        let p = parse_narrow_note(&join(&f));
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: bad btf");
        let mut f2 = fields("gz", "8388608");
        f2[1] = "config_src=gz".to_string();
        f2[0] = format!("conf=sha256:{CONFIG}");
        let q = parse_narrow_note(&join(&f2));
        assert!(!q.ok);
        assert_eq!(q.message, "narrow note: bad config");
    }

    #[test]
    fn grammar_values() {
        let mut f = fields("gz", "8388608");
        f[0] = "config=sha256:A5AF36b05630b51bb596bc68f955ab97bb8802e857cd2fc1de05c0628e398fbb"
            .to_string();
        let p = parse_narrow_note(&join(&f));
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: bad config");
        let mut f2 = fields("gz", "8388608");
        f2[0] = "config=sha256:a5af".to_string();
        assert_eq!(
            parse_narrow_note(&join(&f2)).message,
            "narrow note: bad config"
        );
        let mut f3 = fields("gz", "8388608");
        f3[0] = format!("config={CONFIG}");
        assert!(!parse_narrow_note(&join(&f3)).ok);
        let mut f4 = fields("gz", "8388608");
        f4[1] = "config_src=raw".to_string();
        assert_eq!(
            parse_narrow_note(&join(&f4)).message,
            "narrow note: bad config_src"
        );
        let mut f5 = fields("gz", "8388608");
        f5[6] = "image_bid=0102".to_string();
        assert_eq!(
            parse_narrow_note(&join(&f5)).message,
            "narrow note: bad image_bid"
        );
    }

    #[test]
    fn grammar_ring() {
        let zero = join(&fields("gz", "0"));
        assert_eq!(
            parse_narrow_note(&zero).message,
            "narrow note: bad ring_bytes"
        );
        let lead_zero = join(&fields("gz", "01024"));
        assert!(!parse_narrow_note(&lead_zero).ok);
        let huge = join(&fields("gz", "4294967296"));
        assert!(!parse_narrow_note(&huge).ok);
        let alpha = join(&fields("gz", "8m"));
        assert!(!parse_narrow_note(&alpha).ok);
        let mut f = fields("gz", "8388608");
        f[7] = "ring_bytes=".to_string();
        assert!(!parse_narrow_note(&join(&f)).ok);
    }

    #[test]
    fn live_ok_root() {
        let live = read_live(&narrow_root("ok"));
        assert_eq!(live.config_src, "gz");
        assert_eq!(live.config.state, "value");
        assert_eq!(live.config.value, CONFIG);
        assert_eq!(live.btf.value, BTF);
        assert_eq!(live.format.value, FORMAT);
        assert_eq!(live.object.value, OBJECT);
        assert_eq!(live.image.value, IMAGE);
        assert_eq!(live.image_bid.value, BID);
    }

    #[test]
    fn live_nogz_root() {
        let root = narrow_root("nogz");
        let cfg = read_live_config(&root, REL, ZLIB);
        assert_eq!(cfg.src, "file");
        assert_eq!(cfg.value.state, "value");
        assert_eq!(cfg.value.value, CONFIG);
    }

    #[test]
    fn live_none_root() {
        let root = narrow_root("none");
        let cfg = read_live_config(&root, REL, ZLIB);
        assert_eq!(cfg.src, "");
        assert_eq!(cfg.value.state, "uncheckable");
        let btf = read_live_bytes(&root, "/sys/kernel/btf/vmlinux", "btf", 67_108_864);
        assert_eq!(btf.state, "uncheckable");
        assert_eq!(read_live_bid(&root).state, "uncheckable");
        assert_eq!(
            read_live_object(&format!("{root}/object.o")).state,
            "uncheckable"
        );
    }

    #[test]
    fn check_bound() {
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(parsed.ok);
        let v = check_narrow(&parsed.bindings, &read_live(&narrow_root("ok")));
        assert_eq!(v.state, "bound");
        assert_eq!(v.key, "");
    }

    #[test]
    fn check_mismatch_keys() {
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        // config_src mismatch beats config mismatch.
        let file_parsed = parse_narrow_note(&join(&fields("file", "8388608")));
        let v = check_narrow(&file_parsed.bindings, &read_live(&narrow_root("ok")));
        assert_eq!(v.state, "mismatch");
        assert_eq!(v.key, "config_src");
        // Skewed disk image refuses while the bid still matches.
        let skew = read_live(&narrow_root("skew"));
        assert_ne!(skew.image.value, IMAGE);
        assert_eq!(skew.image_bid.value, BID);
        let s = check_narrow(&parsed.bindings, &skew);
        assert_eq!(s.state, "mismatch");
        assert_eq!(s.key, "image");
    }

    #[test]
    fn check_uncheckable_precedence() {
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        let mut live = read_live(&narrow_root("ok"));
        live.btf.state = "uncheckable".to_string();
        live.format.value =
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string();
        let v = check_narrow(&parsed.bindings, &live);
        assert_eq!(v.state, "uncheckable");
        assert_eq!(v.key, "btf");
        let mut live2 = read_live(&narrow_root("ok"));
        live2.ring.value = "4096".to_string();
        let w = check_narrow(&parsed.bindings, &live2);
        assert_eq!(w.state, "mismatch");
        assert_eq!(w.key, "ring_bytes");
    }

    #[test]
    fn identity_bindings_hold() {
        let note = join(&fields("gz", "8388608"));
        let v = check_identity_bindings(&narrow_root("ok"), REL, &note, ZLIB, FMT_PATH);
        assert_eq!(v.state, "bound");
        assert_eq!(v.key, "");
    }

    #[test]
    fn identity_bindings_mismatch() {
        let note = join(&fields("gz", "8388608"));
        let v = check_identity_bindings(&narrow_root("skew"), REL, &note, ZLIB, FMT_PATH);
        assert_eq!(v.state, "mismatch");
        assert_eq!(v.key, "image");
    }

    #[test]
    fn identity_bindings_uncheckable() {
        let note = join(&fields("gz", "8388608"));
        let v = check_identity_bindings(&narrow_root("missing-root"), REL, &note, ZLIB, FMT_PATH);
        assert_eq!(v.state, "uncheckable");
        assert_eq!(v.key, "config");
    }

    #[test]
    fn identity_bindings_bad_note() {
        let v = check_identity_bindings(&narrow_root("ok"), REL, "not a note", ZLIB, FMT_PATH);
        assert_eq!(v.state, "uncheckable");
        assert_eq!(v.key, "note");
    }

    fn append_u32(blob: &mut Vec<u8>, v: u32) {
        blob.extend_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn notes_vectors() {
        let mut blob = Vec::new();
        append_u32(&mut blob, 4);
        append_u32(&mut blob, 20);
        append_u32(&mut blob, 3);
        blob.extend_from_slice(b"GNU\0");
        for i in 1..21u8 {
            blob.push(i);
        }
        let v = parse_notes_bid(&blob);
        assert_eq!(v.state, "value");
        assert_eq!(v.value, BID);
        let cut = &blob[..blob.len() - 5];
        assert_eq!(parse_notes_bid(cut).state, "uncheckable");
        let e = parse_notes_bid(&[]);
        assert_eq!(e.state, "uncheckable");
        assert_eq!(e.detail, "no build-id note");
    }

    #[test]
    fn notes_decoy_and_malformed() {
        // A type-3 Xen note must not satisfy the GNU check.
        let mut blob = Vec::new();
        append_u32(&mut blob, 4);
        append_u32(&mut blob, 8);
        append_u32(&mut blob, 3);
        blob.extend_from_slice(b"Xen\0");
        blob.extend_from_slice(&[1u8; 8]);
        let v = parse_notes_bid(&blob);
        assert_eq!(v.state, "uncheckable");
        assert_eq!(v.detail, "no build-id note");
        // A GNU note with a short descriptor is malformed.
        let mut bad = Vec::new();
        append_u32(&mut bad, 4);
        append_u32(&mut bad, 8);
        append_u32(&mut bad, 3);
        bad.extend_from_slice(b"GNU\0");
        bad.extend_from_slice(&[2u8; 8]);
        let w = parse_notes_bid(&bad);
        assert_eq!(w.state, "uncheckable");
        assert_eq!(w.detail, "build-id malformed");
    }

    #[test]
    fn layout_ok() {
        let raw = layout_fixture("ok.format");
        let v = check_trace_layout(&raw);
        assert!(v.ok);
        assert_eq!(v.message, "");
    }

    #[test]
    fn layout_drift() {
        let raw = layout_fixture("moved.format");
        let v = check_trace_layout(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "field size: want @32:8");
    }

    #[test]
    fn layout_missing() {
        let raw = layout_fixture("missing.format");
        let v = check_trace_layout(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "missing field force");
    }

    #[test]
    fn layout_badtype() {
        let raw = layout_fixture("badtype.format");
        let v = check_trace_layout(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "field force: want type bool");
    }

    #[test]
    fn layout_garbage() {
        let raw = layout_fixture("garbage.format");
        let v = check_trace_layout(&raw);
        assert!(!v.ok);
        assert_eq!(v.message, "missing field common_type");
    }

    #[test]
    fn layout_inline_edges() {
        let v = check_trace_layout(b"field:bogus\n");
        assert!(!v.ok);
        assert_eq!(v.message, "format line unparseable");
        let line = "field:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n";
        let dup = line.to_string() + line;
        let w = check_trace_layout(dup.as_bytes());
        assert!(!w.ok);
        assert_eq!(w.message, "duplicate field size");
    }

    #[test]
    fn layout_legacy_geometry_before_duplicate() {
        // Characterization: the legacy checker validates each
        // pinned field at first sighting in file order, so a
        // drifted geometry reports before the duplicate is seen.
        let line = "field:size_t size;\toffset:40;\tsize:8;\tsigned:0;\n";
        let dup = line.to_string() + line;
        let v = check_trace_layout(dup.as_bytes());
        assert!(!v.ok);
        assert_eq!(v.message, "field size: want @32:8");
    }

    #[test]
    fn layout_legacy_duplicate_unpinned_passes() {
        // Characterization: the legacy checker tracks duplicates
        // for pinned fields only; a repeated unpinned field is
        // ignored. The strict discovery parser refuses this input.
        let mut raw = layout_fixture("ok.format");
        raw.extend_from_slice(
            b"\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n",
        );
        let v = check_trace_layout(&raw);
        assert!(v.ok);
        assert_eq!(v.message, "");
    }

    fn pin_line(ftype: &str, name: &str, off: i64, size: i64) -> String {
        format!("field:{ftype} {name};\toffset:{off};\tsize:{size};\tsigned:0;\n")
    }

    fn pin_format(moved: usize) -> String {
        // The four pinned fields, intact except pin `moved`
        // (0 common_type, 1 dev_name, 2 size, 3 force), whose
        // offset shifts by 8. The strict checker names every
        // such move; admission instead probes offsets and
        // admits tabled-pin moves.
        // NOTE: pin 2 (+8) lands size@40, colliding with
        // force@40; the strict checker reports the size diff
        // before any overlap notion applies.
        let mut offs = [0i64, 8, 32, 40];
        offs[moved] += 8;
        pin_line("unsigned short", "common_type", offs[0], 2)
            + &pin_line("__data_loc char[]", "dev_name", offs[1], 4)
            + &pin_line("size_t", "size", offs[2], 8)
            + &pin_line("bool", "force", offs[3], 1)
    }

    #[test]
    fn layout_strict_each_pin_drift_names_diff() {
        // Characterization: the strict pinned-layout checker
        // names every pin offset move. This pins the strict
        // primitive only; admission behavior for drifted
        // layouts lives in the offsets tests.
        let wants = [
            "field common_type: want @0:2",
            "field dev_name: want @8:4",
            "field size: want @32:8",
            "field force: want @40:1",
        ];
        for (i, want) in wants.iter().enumerate() {
            let body = pin_format(i);
            let v = check_trace_layout(body.as_bytes());
            assert!(!v.ok);
            assert_eq!(v.message, *want);
        }
    }

    #[test]
    fn object_ok() {
        let raw = elf_fixture("ok.o");
        let v = verify_object(&raw, PROG);
        assert!(v.ok);
        assert_eq!(v.message, "");
    }

    #[test]
    fn object_badarch() {
        let raw = elf_fixture("badarch.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "not a BPF object");
    }

    #[test]
    fn object_nosym() {
        let raw = elf_fixture("nosym.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "program symbol missing");
    }

    #[test]
    fn object_badsec() {
        // Losing the only tracepoint section refuses before
        // the symbol walk: section presence beats diagnosis.
        let raw = elf_fixture("badsec.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "no tracepoint section");
    }

    #[test]
    fn object_wrongsec() {
        // A local decoy plus the global program outside any
        // tracepoint section refuses with the section detail.
        let raw = elf_fixture("wrongsec.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "program symbol unusable: program in kprobe/foo");
    }

    #[test]
    fn object_tiny() {
        let raw = elf_fixture("tiny.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "object too small");
    }

    #[test]
    fn object_emptysec() {
        // An emptied program section refuses at the extent
        // check: the symbol no longer fits its section.
        let raw = elf_fixture("emptysec.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(
            v.message,
            "program symbol unusable: program outside section"
        );
    }

    #[test]
    fn object_zerosym() {
        let raw = elf_fixture("zerosym.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "program symbol unusable: program empty");
    }

    #[test]
    fn object_mapsrange() {
        let raw = elf_fixture("mapsrange.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, ".maps section out of range");
    }

    #[test]
    fn object_typemaps() {
        let raw = elf_fixture("typemaps.o");
        let v = verify_object(&raw, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, ".maps section bad type");
    }

    /// Header offset plus name-table offset of one section.
    fn section_header(raw: &[u8], want: &[u8]) -> (usize, usize) {
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
            assert!(
                end < raw.len(),
                "fixture section names must be NUL-terminated"
            );
            while raw[end] != 0 {
                end += 1;
                assert!(
                    end < raw.len(),
                    "fixture section names must be NUL-terminated"
                );
            }
            if &raw[str_off + name_off..end] == want {
                return (hdr, str_off + name_off);
            }
        }
        panic!("fixture must carry the wanted section");
    }

    /// Rewrite the `.maps` section name to `maps`, the Aya/
    /// bpf-linker spelling, keeping every other byte identical.
    fn aya_shape(raw: &[u8]) -> Vec<u8> {
        let mut out = raw.to_vec();
        let (_, name_at) = section_header(&out, b".maps");
        out[name_at..name_at + 5].copy_from_slice(b"maps\0");
        out
    }

    #[test]
    fn object_aya_shape_ok() {
        // The Aya lane admits the bpf-linker `maps` spelling
        // with the same rigor as the libbpf `.maps` lane.
        let raw = elf_fixture("ok.o");
        let v = verify_object(&aya_shape(&raw), PROG);
        assert!(v.ok, "Aya shape refused: {}", v.message);
        assert_eq!(v.message, "");
    }

    #[test]
    fn object_aya_shape_bad_type() {
        let raw = elf_fixture("ok.o");
        let (hdr, _) = section_header(&raw, b".maps");
        let mut shaped = aya_shape(&raw);
        shaped[hdr + 4..hdr + 8].copy_from_slice(&2u32.to_le_bytes());
        let v = verify_object(&shaped, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "maps section bad type");
    }

    #[test]
    fn object_aya_shape_out_of_range() {
        let raw = elf_fixture("ok.o");
        let (hdr, _) = section_header(&raw, b".maps");
        let mut shaped = aya_shape(&raw);
        let past_end = shaped.len() as u64 + 64;
        shaped[hdr + 24..hdr + 32].copy_from_slice(&past_end.to_le_bytes());
        let v = verify_object(&shaped, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "maps section out of range");
    }

    #[test]
    fn object_neither_maps_shape_refused() {
        // Neither spelling present refuses with the existing
        // taxonomy: unknown shapes stay refused, no new cause.
        let raw = elf_fixture("ok.o");
        let (_, name_at) = section_header(&raw, b".maps");
        let mut out = raw.clone();
        out[name_at..name_at + 6].copy_from_slice(b"xmaps\0");
        let v = verify_object(&out, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "no .maps section");
    }

    /// Add a well-formed libbpf `.maps` to the Aya shape by
    /// renaming the spare PROGBITS `.debug_frame` section, so
    /// the object carries both spellings. REL entries and the
    /// symtab link use section indices, never names, so the
    /// rename keeps every other check identical.
    fn both_shapes(raw: &[u8]) -> Vec<u8> {
        let mut out = aya_shape(raw);
        let (_, name_at) = section_header(&out, b".debug_frame");
        out[name_at..name_at + 6].copy_from_slice(b".maps\0");
        out
    }

    #[test]
    fn object_both_shapes_ok() {
        // Both spellings present and well-formed admits: an
        // object carrying both must satisfy both, and this
        // one does.
        let raw = elf_fixture("ok.o");
        let v = verify_object(&both_shapes(&raw), PROG);
        assert!(v.ok, "both shapes refused: {}", v.message);
        assert_eq!(v.message, "");
    }

    #[test]
    fn object_both_shapes_bad_aya() {
        // Both present with the Aya `maps` mistyped refuses,
        // even though the `.maps` spelling is well-formed.
        let raw = elf_fixture("ok.o");
        let mut shaped = both_shapes(&raw);
        let (hdr, _) = section_header(&shaped, b"maps");
        shaped[hdr + 4..hdr + 8].copy_from_slice(&2u32.to_le_bytes());
        let v = verify_object(&shaped, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "maps section bad type");
    }

    #[test]
    fn object_both_shapes_bad_libbpf() {
        // Both present with the libbpf `.maps` out of range
        // refuses from the other spelling, whatever its
        // table position relative to `maps`.
        let raw = elf_fixture("ok.o");
        let mut shaped = both_shapes(&raw);
        let (hdr, _) = section_header(&shaped, b".maps");
        let past_end = shaped.len() as u64 + 64;
        shaped[hdr + 24..hdr + 32].copy_from_slice(&past_end.to_le_bytes());
        let v = verify_object(&shaped, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, ".maps section out of range");
    }

    #[test]
    fn object_both_shapes_first_bad_wins() {
        // Both spellings bad: the refusal names the first bad
        // section in section-table order (`maps` sits earlier
        // than the renamed spare in the fixture).
        let raw = elf_fixture("ok.o");
        let mut shaped = both_shapes(&raw);
        let (aya_hdr, _) = section_header(&shaped, b"maps");
        shaped[aya_hdr + 4..aya_hdr + 8].copy_from_slice(&2u32.to_le_bytes());
        let (lib_hdr, _) = section_header(&shaped, b".maps");
        let past_end = shaped.len() as u64 + 64;
        shaped[lib_hdr + 24..lib_hdr + 32].copy_from_slice(&past_end.to_le_bytes());
        let v = verify_object(&shaped, PROG);
        assert!(!v.ok);
        assert_eq!(v.message, "maps section bad type");
    }

    #[test]
    fn object_aya_embedded_channels_admitted() {
        // The build's own Aya objects verify: attempt by
        // program name, lifecycle/copy per tracing-program
        // section kind, mirroring object_tracing_ok.
        let attempt =
            crate::platform::runtime::embedded_object("attempt").expect("attempt ELF embedded");
        let v = verify_object(attempt, PROG);
        assert!(v.ok, "attempt refused: {}", v.message);
        let lc =
            crate::platform::runtime::embedded_object("lifecycle").expect("lifecycle ELF embedded");
        let a = verify_object_program(lc, "mv_map_result", "fexit/");
        assert!(a.ok, "mv_map_result refused: {}", a.message);
        let b = verify_object_program(lc, "mv_unmap", "fentry/");
        assert!(b.ok, "mv_unmap refused: {}", b.message);
        let cp = crate::platform::runtime::embedded_object("copy").expect("copy ELF embedded");
        for name in ["mv_sync_device", "mv_sync_cpu", "mv_bounce"] {
            let p = verify_object_program(cp, name, "fentry/");
            assert!(p.ok, "{name} refused: {}", p.message);
        }
        let x = verify_object_program(cp, "mv_bounce_exit", "fexit/");
        assert!(x.ok, "mv_bounce_exit refused: {}", x.message);
    }

    #[test]
    fn grammar_extended_valid() {
        let p = parse_narrow_note(&join(&fields12()));
        assert!(p.ok);
        assert_eq!(p.bindings.lc_object, LC_OBJECT);
        assert_eq!(p.bindings.lc_ring, "8388608");
        assert_eq!(p.bindings.cp_object, CP_OBJECT);
        assert_eq!(p.bindings.cp_ring, "8388608");
        assert_eq!(p.bindings.object, OBJECT);
    }

    #[test]
    fn grammar_extended_absent() {
        let p = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(p.ok);
        assert_eq!(p.bindings.lc_object, "");
        assert_eq!(p.bindings.lc_ring, "");
        assert_eq!(p.bindings.cp_object, "");
        assert_eq!(p.bindings.cp_ring, "");
    }

    #[test]
    fn grammar_extended_field_count() {
        let ten = fields12();
        let p = parse_narrow_note(&join(&ten[..10]));
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: want 8 or 12 fields");
    }

    #[test]
    fn grammar_extended_values() {
        let mut f = fields12();
        f[8] = format!("lc_object=sha256:zz{}", &LC_OBJECT[2..]);
        let p = parse_narrow_note(&join(&f));
        assert!(!p.ok);
        assert_eq!(p.message, "narrow note: bad lc_object");
        let mut f = fields12();
        f[9] = "lc_ring_bytes=abc".to_string();
        let q = parse_narrow_note(&join(&f));
        assert!(!q.ok);
        assert_eq!(q.message, "narrow note: bad lc_ring_bytes");
        let mut f = fields12();
        f[10] = format!("cp_object=sha256:{}", &CP_OBJECT[..62]);
        let r = parse_narrow_note(&join(&f));
        assert!(!r.ok);
        assert_eq!(r.message, "narrow note: bad cp_object");
        let mut f = fields12();
        f[11] = "cp_ring_bytes=0".to_string();
        let s = parse_narrow_note(&join(&f));
        assert!(!s.ok);
        assert_eq!(s.message, "narrow note: bad cp_ring_bytes");
    }

    #[test]
    fn check_extra_unwanted() {
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(parsed.ok);
        let v = check_narrow_extra(&parsed.bindings, &NarrowLive::new(), false, false);
        assert_eq!(v.state, "bound");
        assert_eq!(v.key, "");
    }

    #[test]
    fn check_extra_absent_binding() {
        let parsed = parse_narrow_note(&join(&fields("gz", "8388608")));
        assert!(parsed.ok);
        let live = live_extra(LC_OBJECT, "8388608", CP_OBJECT, "8388608");
        let v = check_narrow_extra(&parsed.bindings, &live, true, false);
        assert_eq!(v.state, "mismatch");
        assert_eq!(v.key, "lc_object");
        let w = check_narrow_extra(&parsed.bindings, &live, false, true);
        assert_eq!(w.state, "mismatch");
        assert_eq!(w.key, "cp_object");
    }

    #[test]
    fn check_extra_drift() {
        let parsed = parse_narrow_note(&join(&fields12()));
        assert!(parsed.ok);
        let live = live_extra(
            &format!("0{}", &LC_OBJECT[1..]),
            "8388608",
            CP_OBJECT,
            "8388608",
        );
        let v = check_narrow_extra(&parsed.bindings, &live, true, true);
        assert_eq!(v.state, "mismatch");
        assert_eq!(v.key, "lc_object");
        let live2 = live_extra(LC_OBJECT, "8388608", CP_OBJECT, "4096");
        let w = check_narrow_extra(&parsed.bindings, &live2, true, true);
        assert_eq!(w.state, "mismatch");
        assert_eq!(w.key, "cp_ring_bytes");
    }

    #[test]
    fn check_extra_bound() {
        let parsed = parse_narrow_note(&join(&fields12()));
        assert!(parsed.ok);
        let live = live_extra(LC_OBJECT, "8388608", CP_OBJECT, "8388608");
        let v = check_narrow_extra(&parsed.bindings, &live, true, true);
        assert_eq!(v.state, "bound");
        assert_eq!(v.key, "");
    }

    #[test]
    fn object_tracing_ok() {
        let lc = elf_fixture("lc-ok.o");
        let a = verify_object_program(&lc, "mv_map_result", "fexit/");
        assert!(a.ok);
        let b = verify_object_program(&lc, "mv_unmap", "fentry/");
        assert!(b.ok);
        let cp = elf_fixture("cp-ok.o");
        for name in ["mv_sync_device", "mv_sync_cpu", "mv_bounce"] {
            let v = verify_object_program(&cp, name, "fentry/");
            assert!(v.ok);
        }
        // The fexit fallback records bounces that skipped mv_bounce.
        let x = verify_object_program(&cp, "mv_bounce_exit", "fexit/");
        assert!(x.ok);
    }

    #[test]
    fn object_tracing_wrongsec() {
        let lc = elf_fixture("lc-wrongsec.o");
        let v = verify_object_program(&lc, "mv_unmap", "fentry/");
        assert!(!v.ok);
        assert_eq!(v.message, "no fentry section");
        let cp = elf_fixture("cp-wrongsec.o");
        let w = verify_object_program(&cp, "mv_bounce", "fentry/");
        assert!(!w.ok);
        assert_eq!(
            w.message,
            "program symbol unusable: program in kprobe/swiotlb_bounce"
        );
    }

    #[test]
    fn object_bad_section_kind() {
        let raw = elf_fixture("ok.o");
        let v = verify_object_program(&raw, PROG, "kprobe/");
        assert!(!v.ok);
        assert_eq!(v.message, "bad section kind");
    }

    #[test]
    fn object_kind_mismatch() {
        let raw = elf_fixture("ok.o");
        let v = verify_object_program(&raw, PROG, "fentry/");
        assert!(!v.ok);
        assert_eq!(v.message, "no fentry section");
        let lc = elf_fixture("lc-ok.o");
        let w = verify_object_program(&lc, "mv_map_result", "tracepoint/");
        assert!(!w.ok);
        assert_eq!(w.message, "no tracepoint section");
    }

    const NEW_OBJECT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const NEW_LC: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const NEW_CP: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn eight() -> String {
        join(&fields("gz", "8388608"))
    }

    fn twelve() -> String {
        join(&fields12())
    }

    fn assert_base_siblings(bind_old: &str, bind_new: &str) {
        // Every non-object binding survives the rebind byte-identical.
        let old = parse_narrow_note(bind_old).bindings;
        let new = parse_narrow_note(bind_new).bindings;
        assert_eq!(new.config, old.config);
        assert_eq!(new.config_src, old.config_src);
        assert_eq!(new.btf, old.btf);
        assert_eq!(new.format, old.format);
        assert_eq!(new.image, old.image);
        assert_eq!(new.image_bid, old.image_bid);
        assert_eq!(new.ring, old.ring);
    }

    #[test]
    fn rebind_attempt_only() {
        let note = eight();
        let rebound = rebind_note_object(&note, "object", NEW_OBJECT).unwrap();
        let parsed = parse_narrow_note(&rebound);
        assert!(parsed.ok);
        assert_eq!(parsed.bindings.object, NEW_OBJECT);
        assert_eq!(parsed.bindings.lc_object, "");
        assert_eq!(parsed.bindings.cp_object, "");
        assert_base_siblings(&note, &rebound);
        assert_eq!(
            format_narrow_note(&parsed.bindings, false).unwrap(),
            rebound
        );
    }

    #[test]
    fn rebind_lifecycle_only() {
        let note = twelve();
        let rebound = rebind_note_object(&note, "lc_object", NEW_LC).unwrap();
        let parsed = parse_narrow_note(&rebound);
        assert!(parsed.ok);
        assert_eq!(parsed.bindings.lc_object, NEW_LC);
        assert_eq!(parsed.bindings.object, OBJECT);
        assert_eq!(parsed.bindings.cp_object, CP_OBJECT);
        assert_eq!(parsed.bindings.lc_ring, "8388608");
        assert_eq!(parsed.bindings.cp_ring, "8388608");
        assert_base_siblings(&note, &rebound);
        assert_eq!(format_narrow_note(&parsed.bindings, true).unwrap(), rebound);
    }

    #[test]
    fn rebind_copy_only() {
        let note = twelve();
        let rebound = rebind_note_object(&note, "cp_object", NEW_CP).unwrap();
        let parsed = parse_narrow_note(&rebound);
        assert!(parsed.ok);
        assert_eq!(parsed.bindings.cp_object, NEW_CP);
        assert_eq!(parsed.bindings.object, OBJECT);
        assert_eq!(parsed.bindings.lc_object, LC_OBJECT);
        assert_eq!(parsed.bindings.lc_ring, "8388608");
        assert_eq!(parsed.bindings.cp_ring, "8388608");
        assert_base_siblings(&note, &rebound);
        assert_eq!(format_narrow_note(&parsed.bindings, true).unwrap(), rebound);
    }

    #[test]
    fn rebind_attempt_on_twelve_keeps_extra() {
        let note = twelve();
        let rebound = rebind_note_object(&note, "object", NEW_OBJECT).unwrap();
        let parsed = parse_narrow_note(&rebound);
        assert!(parsed.ok);
        assert_eq!(parsed.bindings.object, NEW_OBJECT);
        assert_eq!(parsed.bindings.lc_object, LC_OBJECT);
        assert_eq!(parsed.bindings.cp_object, CP_OBJECT);
        assert_eq!(format_narrow_note(&parsed.bindings, true).unwrap(), rebound);
    }

    #[test]
    fn rebind_refusals() {
        let eight = eight();
        let mut refused = 0;
        if rebind_note_object(&eight, "image", NEW_OBJECT).is_err() {
            refused += 1;
        }
        if rebind_note_object(&eight, "object", "abc").is_err() {
            refused += 1;
        }
        if rebind_note_object(
            &eight,
            "object",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .is_err()
        {
            refused += 1;
        }
        if rebind_note_object("not a note", "object", NEW_OBJECT).is_err() {
            refused += 1;
        }
        if rebind_note_object(&eight, "lc_object", NEW_LC).is_err() {
            refused += 1;
        }
        if rebind_note_object(&eight, "cp_object", NEW_CP).is_err() {
            refused += 1;
        }
        assert_eq!(refused, 6);
    }

    fn good_format() -> String {
        let mut out = "name: swiotlb_bounced\nID: 382\nformat:\n".to_string();
        out += "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n";
        out += "\tfield:unsigned char common_flags;\toffset:2;\tsize:1;\tsigned:0;\n";
        out += "\tfield:unsigned char common_preempt_count;\toffset:3;\tsize:1;\tsigned:0;\n";
        out += "\tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n";
        out += "\n";
        out += "\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n";
        out += "\tfield:u64 dma_mask;\toffset:16;\tsize:8;\tsigned:0;\n";
        out += "\tfield:dma_addr_t dev_addr;\toffset:24;\tsize:8;\tsigned:0;\n";
        out += "\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n";
        out += "\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n";
        out += "\nprint fmt: \"dev_name: %s\"\n";
        out
    }

    fn without_force() -> String {
        let mut out = "name: swiotlb_bounced\nID: 382\nformat:\n".to_string();
        out += "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n";
        out += "\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n";
        out += "\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n";
        out
    }

    fn moved_size() -> String {
        let mut out = "name: swiotlb_bounced\nID: 382\nformat:\n".to_string();
        out += "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n";
        out += "\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n";
        out += "\tfield:size_t size;\toffset:40;\tsize:8;\tsigned:0;\n";
        out += "\tfield:bool force;\toffset:48;\tsize:1;\tsigned:0;\n";
        out
    }

    fn retyped_force() -> String {
        let mut out = "name: swiotlb_bounced\nID: 382\nformat:\n".to_string();
        out += "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n";
        out += "\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n";
        out += "\tfield:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n";
        out += "\tfield:u8 force;\toffset:40;\tsize:1;\tsigned:0;\n";
        out
    }

    #[test]
    fn parse_good_format() {
        let text = good_format();
        let layout = parse_trace_format(text.as_bytes());
        assert!(layout.ok);
        assert_eq!(layout.fields.len(), 9);
        assert_eq!(layout.fields[0].name, "common_type");
        assert_eq!(layout.fields[4].name, "dev_name");
        assert_eq!(layout.fields[4].ftype, "__data_loc char[]");
        assert_eq!(layout.fields[4].offset, 8);
        assert_eq!(layout.fields[4].size, 4);
        assert_eq!(layout.fields[8].name, "force");
    }

    #[test]
    fn parse_unparseable_line() {
        let text = good_format() + "\tfield:bogus\n";
        let layout = parse_trace_format(text.as_bytes());
        assert!(!layout.ok);
        assert_eq!(layout.message, "format line unparseable");
    }

    #[test]
    fn parse_duplicate_field() {
        let text = good_format() + "\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n";
        let layout = parse_trace_format(text.as_bytes());
        assert!(!layout.ok);
        assert_eq!(layout.message, "duplicate field force");
    }

    #[test]
    fn diff_identical_is_empty() {
        let text = good_format();
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        let known = known_trace_format();
        assert_eq!(diff_trace_format(&known, &live), "");
    }

    #[test]
    fn diff_missing_field() {
        let text = without_force();
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        let known = known_trace_format();
        assert_eq!(diff_trace_format(&known, &live), "missing field force");
    }

    #[test]
    fn diff_moved_offset() {
        let text = moved_size();
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        let known = known_trace_format();
        assert_eq!(
            diff_trace_format(&known, &live),
            "field size: want @32:8, live @40:8"
        );
    }

    #[test]
    fn diff_retyped_field() {
        let text = retyped_force();
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        let known = known_trace_format();
        assert_eq!(
            diff_trace_format(&known, &live),
            "field force: want type bool, live u8"
        );
    }

    #[test]
    fn parse_empty_input() {
        let layout = parse_trace_format(b"");
        assert!(layout.ok);
        assert_eq!(layout.fields.len(), 0);
    }

    #[test]
    fn parse_huge_offset_refused() {
        let text = "field:size_t size;\toffset:12345678901;\tsize:8;\tsigned:0;\n";
        let layout = parse_trace_format(text.as_bytes());
        assert!(!layout.ok);
        assert_eq!(layout.message, "format line unparseable");
    }

    #[test]
    fn parse_unterminated_final_line() {
        let text = "field:int common_pid;\toffset:4;\tsize:4;\tsigned:0;";
        let layout = parse_trace_format(text.as_bytes());
        assert!(layout.ok);
        assert_eq!(layout.fields.len(), 1);
        assert_eq!(layout.fields[0].name, "common_pid");
    }

    #[test]
    fn parse_data_loc_variant() {
        let text = "field:__data_loc unsigned char[] name;\toffset:8;\tsize:4;\tsigned:0;\n";
        let layout = parse_trace_format(text.as_bytes());
        assert!(layout.ok);
        assert_eq!(layout.fields[0].ftype, "__data_loc unsigned char[]");
    }

    #[test]
    fn parse_nul_name_refused() {
        let line = "field:int ab;\toffset:0;\tsize:4;\tsigned:0;\n";
        let mut raw = line.as_bytes().to_vec();
        raw[11] = 0;
        let layout = parse_trace_format(&raw);
        assert!(!layout.ok);
        assert_eq!(layout.message, "format line unparseable");
    }

    #[test]
    fn diff_size_only_drift() {
        let mut text = "name: swiotlb_bounced\nID: 382\nformat:\n".to_string();
        text += "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n";
        text += "\tfield:__data_loc char[] dev_name;\toffset:8;\tsize:4;\tsigned:0;\n";
        text += "\tfield:size_t size;\toffset:32;\tsize:4;\tsigned:0;\n";
        text += "\tfield:bool force;\toffset:40;\tsize:1;\tsigned:0;\n";
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        let known = known_trace_format();
        assert_eq!(
            diff_trace_format(&known, &live),
            "field size: want @32:8, live @32:4"
        );
    }

    #[test]
    fn diff_invalid_inputs() {
        let bad = super::TraceFormat::new();
        let text = good_format();
        let live = parse_trace_format(text.as_bytes());
        assert!(live.ok);
        assert_eq!(diff_trace_format(&bad, &live), "want layout invalid");
        let broken = parse_trace_format(b"field:bogus\n");
        assert!(!broken.ok);
        let known = known_trace_format();
        assert_eq!(
            diff_trace_format(&known, &broken),
            "live layout invalid: format line unparseable"
        );
    }

    fn offset_pin_format(moved: usize) -> String {
        // The four pinned fields, intact except pin `moved`
        // (0 common_type, 1 dev_name, 2 size, 3 force), which
        // shifts to a collision-free offset.
        let mut offs = [0i64, 8, 32, 40];
        if moved == 0 {
            offs[0] = 8;
        } else if moved == 1 {
            offs[1] = 16;
        } else if moved == 2 {
            offs[2] = 48;
        } else {
            offs[3] = 56;
        }
        pin_line("unsigned short", "common_type", offs[0], 2)
            + &pin_line("__data_loc char[]", "dev_name", offs[1], 4)
            + &pin_line("size_t", "size", offs[2], 8)
            + &pin_line("bool", "force", offs[3], 1)
    }

    fn full_pins(dev_off: i64, size_off: i64, force_off: i64) -> String {
        // Pinned header plus the three tabled pins at chosen
        // offsets; fixed_end covers force.
        pin_line("unsigned short", "common_type", 0, 2)
            + &pin_line("unsigned char", "common_flags", 2, 1)
            + &pin_line("int", "common_pid", 4, 4)
            + &pin_line("__data_loc char[]", "dev_name", dev_off, 4)
            + &pin_line("u64", "dma_mask", 16, 8)
            + &pin_line("size_t", "size", size_off, 8)
            + &pin_line("bool", "force", force_off, 1)
    }

    #[test]
    fn probe_pinned_layout_returns_pins() {
        let raw = layout_fixture("ok.format");
        let p = probe_trace_offsets(&raw);
        assert!(p.ok);
        assert_eq!(p.message, "");
        assert!(!p.moved);
        assert_eq!(p.loc_off, 8);
        assert_eq!(p.size_off, 32);
        assert_eq!(p.force_off, 40);
        assert_eq!(p.fixed_end, 41);
    }

    #[test]
    fn probe_each_pin_moved_admits_offset() {
        // Offset-only moves of the three tabled pins admit
        // with the probed offset; the common_type anchor
        // never moves.
        for i in 1..4 {
            let body = offset_pin_format(i);
            let p = probe_trace_offsets(body.as_bytes());
            assert!(p.ok);
            assert!(p.moved);
            let (want_loc, want_size, want_force) = if i == 1 {
                (16, 32, 40)
            } else if i == 2 {
                (8, 48, 40)
            } else {
                (8, 32, 56)
            };
            assert_eq!(p.loc_off, want_loc);
            assert_eq!(p.size_off, want_size);
            assert_eq!(p.force_off, want_force);
        }
    }

    #[test]
    fn probe_retype_refuses() {
        // Same-width respellings refuse: type is the semantic
        // contract, not the width.
        let body = pin_line("unsigned short", "common_type", 0, 2)
            + &pin_line("__data_loc char[]", "dev_name", 8, 4)
            + &pin_line("unsigned long", "size", 32, 8)
            + &pin_line("bool", "force", 40, 1);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(
            p.message,
            "field size: want type size_t, live unsigned long"
        );
        let fbody = pin_line("unsigned short", "common_type", 0, 2)
            + &pin_line("__data_loc char[]", "dev_name", 8, 4)
            + &pin_line("size_t", "size", 32, 8)
            + &pin_line("u8", "force", 40, 1);
        let q = probe_trace_offsets(fbody.as_bytes());
        assert!(!q.ok);
        assert_eq!(q.message, "field force: want type bool, live u8");
    }

    #[test]
    fn probe_resize_refuses() {
        let body = pin_line("unsigned short", "common_type", 0, 2)
            + &pin_line("__data_loc char[]", "dev_name", 8, 4)
            + &pin_line("size_t", "size", 32, 4)
            + &pin_line("bool", "force", 40, 1);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(p.message, "field size: want size 8, live size 4");
    }

    #[test]
    fn probe_missing_refuses() {
        let raw = layout_fixture("missing.format");
        let p = probe_trace_offsets(&raw);
        assert!(!p.ok);
        assert_eq!(p.message, "missing field force");
    }

    #[test]
    fn probe_common_type_move_refuses() {
        let body = offset_pin_format(0);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(p.message, "field common_type: want @0:2, live @8:2");
    }

    #[test]
    fn probe_overlap_refuses() {
        // size moved onto the force byte: one field's bytes
        // would read as another's.
        let body = full_pins(8, 40, 40);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(p.message, "overlapping extents size and force");
    }

    #[test]
    fn probe_over_cap_refuses() {
        let body = full_pins(8, 32, 200);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(p.message, "field force extent @200:1 exceeds fixed cap 128");
    }

    #[test]
    fn probe_extra_fields_admit() {
        // The drifted-layout fixture (extra field plus moved
        // pins) admits with probed offsets.
        let raw = layout_fixture("moved.format");
        let p = probe_trace_offsets(&raw);
        assert!(p.ok);
        assert!(p.moved);
        assert_eq!(p.loc_off, 8);
        assert_eq!(p.size_off, 40);
        assert_eq!(p.force_off, 48);
        assert_eq!(p.fixed_end, 49);
    }

    #[test]
    fn probe_fixed_end_covers_unpinned() {
        // An unpinned fixed field past every pin still sets
        // the dynamic floor.
        let body = full_pins(8, 32, 40) + &pin_line("u64", "extra_tail", 64, 8);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(p.ok);
        assert!(!p.moved);
        assert_eq!(p.fixed_end, 72);
    }

    #[test]
    fn probe_late_data_loc_sets_floor() {
        // A __data_loc descriptor past every other field
        // still sets the dynamic floor: the descriptor is
        // a fixed u32 slot, not dynamic data.
        let body = full_pins(120, 32, 40);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(p.ok);
        assert!(p.moved);
        assert_eq!(p.loc_off, 120);
        assert_eq!(p.fixed_end, 124);
    }

    #[test]
    fn probe_extra_descriptor_counts_toward_cap() {
        // An unpinned __data_loc descriptor is still a
        // fixed slot: past the cap it refuses.
        let body = full_pins(8, 32, 40) + &pin_line("__data_loc char[]", "extra_blob", 200, 4);
        let p = probe_trace_offsets(body.as_bytes());
        assert!(!p.ok);
        assert_eq!(p.message, "fixed region end 204 exceeds cap 128");
    }

    #[test]
    fn validate_table_floor_covers_extents() {
        // A floor below any tabled extent refuses:
        // dynamic data would otherwise start inside a
        // fixed slot.
        assert_eq!(
            validate_table_extents(8, 32, 40, 0),
            "fixed region end 0 below dev_name extent @8:4"
        );
        assert_eq!(
            validate_table_extents(8, 32, 40, 12),
            "fixed region end 12 below size extent @32:8"
        );
        assert_eq!(
            validate_table_extents(8, 32, 40, 40),
            "fixed region end 40 below force extent @40:1"
        );
        assert_eq!(validate_table_extents(120, 32, 40, 124), "");
    }

    #[test]
    fn probe_garbage_refuses() {
        let raw = layout_fixture("garbage.format");
        let p = probe_trace_offsets(&raw);
        assert!(!p.ok);
        assert_eq!(p.message, "missing field common_type");
        let q = probe_trace_offsets(b"field:bogus\n");
        assert!(!q.ok);
        assert_eq!(q.message, "format line unparseable");
        let line = "field:size_t size;\toffset:32;\tsize:8;\tsigned:0;\n";
        let dup = line.to_string() + line;
        let w = probe_trace_offsets(dup.as_bytes());
        assert!(!w.ok);
        assert_eq!(w.message, "duplicate field size");
    }

    #[test]
    fn validate_table_extents_cases() {
        assert_eq!(validate_table_extents(8, 32, 40, 41), "");
        assert_eq!(
            validate_table_extents(0, 32, 40, 41),
            "overlapping extents common_type and dev_name"
        );
        assert_eq!(
            validate_table_extents(8, 32, 40, 129),
            "fixed region end 129 exceeds cap 128"
        );
        assert_eq!(
            validate_table_extents(8, 125, 40, 41),
            "field size extent @125:8 exceeds fixed cap 128"
        );
    }

    #[test]
    fn encode_offsets_table_layout() {
        assert_eq!(MV_FIXED_MAX, 128);
        assert_eq!(MV_OFFSETS_TABLE_LEN, 24);
        assert_eq!(MV_OFF_TABLE_VERSION, 1);
        let table = encode_offsets_table(8, 32, 40, 41);
        assert_eq!(table.len(), 24);
        // magic "MFO5" little-endian, version 1, reserved 0.
        assert_eq!(table[0], 0x4D);
        assert_eq!(table[1], 0x4D);
        assert_eq!(table[2], 0x46);
        assert_eq!(table[3], 0x35);
        assert_eq!(table[4], 1);
        assert_eq!(table[5], 0);
        assert_eq!(table[6], 0);
        assert_eq!(table[7], 0);
        assert_eq!(table[8], 8);
        assert_eq!(table[12], 32);
        assert_eq!(table[16], 40);
        assert_eq!(table[20], 41);
        for (i, byte) in table.iter().enumerate() {
            if [0, 1, 2, 3, 4, 8, 12, 16, 20].contains(&i) {
                continue;
            }
            assert_eq!(*byte, 0);
        }
        assert_eq!(MV_OFF_TABLE_MAGIC, 0x3546_4D4D);
    }

    #[test]
    fn encode_offsets_negative_refuses() {
        let table = encode_offsets_table(-1, 32, 40, 41);
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn measure_live_bindings_ok() {
        // The qualify host root measures the same six files
        // the mint path hashes; object and ring stay empty.
        let mut bindings = NarrowBindings::new();
        let err = measure_live_bindings(&narrow_root("ok"), REL, ZLIB, FMT_PATH, &mut bindings);
        assert_eq!(err, "");
        assert_eq!(bindings.config, CONFIG);
        assert_eq!(bindings.config_src, "gz");
        assert_eq!(bindings.btf, BTF);
        assert_eq!(bindings.format, FORMAT);
        assert_eq!(bindings.image, IMAGE);
        assert_eq!(bindings.image_bid, BID);
        assert_eq!(bindings.object, "");
        assert_eq!(bindings.ring, "");
    }

    #[test]
    fn measure_live_bindings_missing_config() {
        let mut bindings = NarrowBindings::new();
        let err = measure_live_bindings(
            &narrow_root("missing-root"),
            REL,
            ZLIB,
            FMT_PATH,
            &mut bindings,
        );
        assert_eq!(err, "live bindings unmeasurable: config");
    }

    #[test]
    fn config_text_gate_base() {
        let reader = open_evidence_reader(&gate_fixture("base")).expect("fixture opens");
        let release = reader.release.clone();
        let cfg = read_live_config_text(&reader, &release, ZLIB);
        assert_eq!(cfg.state, "text");
        assert_eq!(cfg.src, "gz");
        assert!(cfg.text.contains("CONFIG_"));
    }

    #[test]
    fn config_text_denied_stays_denied() {
        let reader = open_evidence_reader(&gate_fixture("denied-all")).expect("fixture opens");
        let release = reader.release.clone();
        let cfg = read_live_config_text(&reader, &release, ZLIB);
        assert_eq!(cfg.state, "denied");
    }

    #[test]
    fn format_path_translation() {
        // A live tracefs tree keeps sys profile paths; an
        // unopenable root keeps the profile path verbatim.
        let got = tracefs_format_path(&narrow_root("ok"), FMT_PATH);
        assert_eq!(got, FMT_PATH);
        assert_eq!(tracefs_format_path("no-such-root", FMT_PATH), FMT_PATH);
        let dbg = tracefs_format_path(&gate_fixture("debugfs-root"), FMT_PATH);
        assert_eq!(
            dbg,
            "/sys/kernel/debug/tracing/events/swiotlb/swiotlb_bounced/format"
        );
    }

    #[test]
    fn narrow_cap_single() {
        assert_eq!(MAX_NARROW_OBJECT_BYTES, 67_108_864);
        assert_eq!(
            super::MAX_NARROW_BTF_BYTES,
            crate::platform::btf::MAX_KERNEL_BTF_BYTES
        );
    }

    #[test]
    fn live_object_bytes_hashes() {
        // Embedded-lane hashing: the sha256 of b"abc" is the
        // FIPS vector, independent of any fixture.
        let v = read_live_object_bytes(b"abc");
        assert_eq!(v.state, "value");
        assert_eq!(
            v.value,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(v.detail, "");
    }

    #[test]
    fn embedded_attempt_object_binds() {
        // Retarget seam: the embedded attempt ELF hashes to a
        // well-formed live value and verifies fail-closed.
        let bytes =
            crate::platform::runtime::embedded_object("attempt").expect("attempt ELF embedded");
        let live = read_live_object_bytes(bytes);
        assert_eq!(live.state, "value");
        assert_eq!(live.value.len(), 64);
        assert_eq!(live.value, crate::platform::hash::sha256_hex(bytes));
        let v = verify_object(bytes, PROG);
        assert_eq!(v.ok, v.message.is_empty());
    }
}
