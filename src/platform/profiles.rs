// SPDX-License-Identifier: GPL-3.0-or-later
//! Semantic profiles: exact-identity collection manifests.
//!
//! `parse_profile_bytes` validates one profile JSON document against
//! the profile-v0.1.1 rules (0.1.2 documents accepted). Parsing is
//! strict: unknown keys, duplicates, overlong text, bad enums, and
//! capability hook names that resolve to nothing are all rejected.
//!
//! `load_profiles` reads `<dir>/manifest.txt` (one filename per
//! line, strict grammar, no path separators) and parses each profile
//! in order. Only manifest-listed profiles are admitted.
//!
//! `select_profile` matches kernel identity against profiles in
//! manifest order: `arch` must equal and the release triple must
//! reach `min_kernel`. `matched` is true only for validated
//! profiles; a covering reference-unvalidated profile yields
//! `matched` false with a reason that says so. An unparseable
//! release covers nothing.

use crate::model::scan::{
    Scanner, array_is_empty, array_next, expect_colon, object_is_empty, object_next,
    parse_nullable_string, parse_u64_field,
};
use crate::model::validate::{ValidationError, check_bounded_text};
use crate::platform::artifact_files::join_root;
use crate::platform::btf::{
    BtfFuncSig, BtfResolved, check_btf_health, classify_btf_message, read_btf_func_proto,
    read_btf_func_sig, read_btf_member, resolve_btf_enumerator, resolve_btf_member,
    resolve_btf_type,
};
use crate::platform::evidence::{KernelInfo, parse_kernel_triple};
use crate::platform::kernelgate::{
    MAX_FILTER_FUNCS_BYTES, filter_line_counts, read_ftrace_enabled, read_ftrace_text,
};
use crate::platform::narrow::{
    MAX_NARROW_BTF_BYTES, MAX_NARROW_FORMAT_BYTES, NarrowBindings, check_identity_bindings,
    is_sha256_value, measure_live_bindings, parse_narrow_note, probe_trace_offsets,
};
use crate::platform::reader::{
    E_TOO_BIG, EVIDENCE_ABSENT, EVIDENCE_DENIED, EVIDENCE_OK, EvidenceReader, bytes_to_text,
    file_state, open_evidence_reader, read_evidence, read_host_file,
};
use crate::platform::tracefs::{probe_tracefs, tracefs_translate};
use crate::render::json::escape_json;

/// Profile schema version minted by current writers.
pub const PROFILE_SCHEMA_VERSION: &str = "0.1.1";
/// Most hooks one profile may declare.
pub const MAX_PROFILE_HOOKS: usize = 32;
/// Most capabilities one profile may declare.
pub const MAX_PROFILE_CAPS: usize = 16;
/// Most notes one profile may carry.
pub const MAX_PROFILE_NOTES: usize = 32;
/// Most hooks one capability may name.
pub const MAX_CAP_HOOKS: usize = 32;
/// Most alternate signatures one hook may carry.
pub const MAX_HOOK_ALT: usize = 4;
/// Most layouts one 0.1.1 profile may record.
pub const MAX_PROFILE_LAYOUTS: usize = 16;
/// Most layouts one 0.1.2 profile may record.
pub const MAX_PROFILE_LAYOUTS_V012: usize = 64;
/// Cap for /proc/kallsyms reads during hook arbitration.
pub const MAX_KALLSYMS_BYTES: usize = 67_108_864;
/// Attempt-trace capability id.
pub const ATTEMPT_TRACE_ID: &str = "attempt-trace";
/// Mapping-lifecycle capability id.
pub const LIFECYCLE_CAP_ID: &str = "mapping-lifecycle";
/// Copy-actual capability id.
pub const COPY_CAP_ID: &str = "copy-actual";

const MANIFEST_CAP: usize = 65536;
const PROFILE_CAP: usize = 1_048_576;
const INSTALLED_PROFILES_DIR: &str = "/usr/share/memveil/profiles";
const INSTALLED_RECEIPTS_DIR: &str = "/var/lib/memveil/receipts";

/// One hook named by a profile: tracepoint paths or tracing binding.
///
/// Tracepoint hooks carry id/format paths plus optional layout
/// text; tracing hooks carry the frozen function identity
/// (function, attach, signature) plus optional alternate
/// signatures instead. Each kind forbids the other's fields.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileHook {
    /// Hook name, unique within the profile.
    pub name: String,
    /// `tracepoint` or `tracing`.
    pub kind: String,
    /// Tracepoint id path (tracepoint only).
    pub id_path: String,
    /// Tracepoint format path (tracepoint only).
    pub format_path: String,
    /// True when a non-null format_text was recorded.
    pub format_has: bool,
    /// Recorded format text (tracepoint only).
    pub format_text: String,
    /// Frozen function name (tracing only).
    pub function: String,
    /// `fentry` or `fexit` (tracing only).
    pub attach: String,
    /// Frozen signature spelling (tracing only).
    pub signature: String,
    /// Alternate frozen spellings (tracing only).
    pub signature_alt: Vec<String>,
    /// True when a note was recorded.
    pub has_note: bool,
    /// Hook note.
    pub note: String,
}

/// One capability declaration: support level plus hook refs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileCapability {
    /// Capability id.
    pub id: String,
    /// `candidate`, `supported`, or `unsupported`.
    pub status: String,
    /// Names of hooks serving this capability.
    pub hooks: Vec<String>,
    /// Support-level reason.
    pub reason: String,
}

/// The source identity a profile claims (origin plus revision).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileSource {
    /// Claimed origin.
    pub origin: String,
    /// Claimed revision (a release on bound docs).
    pub revision: String,
    /// True when a note was recorded.
    pub has_note: bool,
    /// Source note (the narrow note on bound docs).
    pub note: String,
}

/// Kernel identity a profile covers: arch plus kernel floor.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileIdentity {
    /// Covered architecture.
    pub arch: String,
    /// Covered kernel floor text.
    pub min_kernel: String,
    /// Floor major component.
    pub min_major: i64,
    /// Floor minor component.
    pub min_minor: i64,
    /// Floor patch component.
    pub min_patch: i64,
    /// Claimed source identity.
    pub source: ProfileSource,
    /// True when a note was recorded.
    pub has_note: bool,
    /// Identity note.
    pub note: String,
}

/// One recorded BTF member layout: struct field plus bit geometry.
///
/// 0.1.1 items pin an exact `bit_offset`/`bit_size` pair checked
/// by copy-actual only. 0.1.2 items (`v012`) carry the owning
/// `capability`, a `target` (field, type, or enumerator), the
/// expected `type_kind`, and whether the item is `optional`;
/// the live check compares kind and size, never offsets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileLayout {
    /// Owning struct name.
    pub struct_name: String,
    /// Field name (empty for a `type` target).
    pub field_name: String,
    /// Recorded bit offset (0.1.1 only).
    pub bit_offset: i64,
    /// Recorded bit width.
    pub bit_size: i64,
    /// Owning capability (0.1.2 only).
    pub capability: String,
    /// `field`, `type`, or `enumerator` (0.1.2 only).
    pub target: String,
    /// Expected kind word (0.1.2 only).
    pub type_kind: String,
    /// True when absence passes (0.1.2 only).
    pub optional: bool,
    /// True for 0.1.2 items.
    pub v012: bool,
}

/// One validated profile manifest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Profile {
    /// Profile id.
    pub profile_id: String,
    /// `validated` or `reference-unvalidated`.
    pub status: String,
    /// `0.1.1` or `0.1.2`.
    pub schema_version: String,
    /// Covered kernel identity.
    pub identity: ProfileIdentity,
    /// Declared hooks.
    pub hooks: Vec<ProfileHook>,
    /// Declared capabilities.
    pub caps: Vec<ProfileCapability>,
    /// Free-text notes.
    pub notes: Vec<String>,
    /// Recorded layouts.
    pub layouts: Vec<ProfileLayout>,
}

/// The outcome of matching kernel identity against profiles.
///
/// `matched` is true only when a validated profile binds or
/// a reference profile matches with a verifying receipt.
/// `has_profile` is true whenever any profile (even a
/// reference one) covers the identity; then `profile` is
/// that manifest in full. `reason` always explains the
/// outcome. `grade` is "validated", "local-auto", or ""
/// when unmatched; `receipt_caps` lists the receipt's
/// qualified ids on a local-auto match and stays empty
/// otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileDecision {
    /// True on a validated or local-auto match.
    pub matched: bool,
    /// True when a profile covers the identity.
    pub has_profile: bool,
    /// The covering manifest (empty when none covers).
    pub profile: Profile,
    /// Human reason for the outcome.
    pub reason: String,
    /// `validated`, `local-auto`, or "".
    pub grade: String,
    /// Receipt qualified ids on a local-auto match.
    pub receipt_caps: Vec<String>,
}

/// Frozen-vs-live signature verdict for one tracing hook.
///
/// `ok` is true only when the frozen signature normalizes
/// and its parameter count and typedef-level type spellings
/// equal the live BTF prototype with 64-bit address widths.
/// `live` holds the live canonical spelling ("" when BTF
/// is unreadable) so callers can show both sides of a
/// mismatch. `code` names the machine reason class, ""
/// when ok or unclassified.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SigVerdict {
    /// Hook name.
    pub hook: String,
    /// True on a full match.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub reason: String,
    /// Live canonical spelling; empty when unreadable.
    pub live: String,
    /// Machine reason class; empty when ok or unclassified.
    pub code: String,
}

/// Check a profile_id against ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$.
fn check_profile_id(v: &str) -> Result<(), ValidationError> {
    check_bounded_text(v, 1, 128, "profile_id")
        .map_err(|e| ValidationError::new("profile_id", e.to_string()))?;
    let mut first = true;
    for &b in v.as_bytes() {
        let ok = (0x41..=0x5A).contains(&b)
            || (0x61..=0x7A).contains(&b)
            || (0x30..=0x39).contains(&b)
            || b == 0x5F
            || (!first && (b == 0x2E || b == 0x2D));
        if !ok {
            return Err(ValidationError::new("profile_id", "bad charset"));
        }
        first = false;
    }
    Ok(())
}

/// Parse `major.minor[.patch]` into (text, major, minor, patch).
///
/// The whole string must match: leading digits, one dot, digits,
/// an optional second dot plus digits, then the end. Anything
/// else (empty parts, extra dots, trailing text) is rejected.
fn parse_min_kernel(v: &str) -> Result<(String, i64, i64, i64), ValidationError> {
    let mut parts: Vec<i64> = Vec::new();
    let mut acc: i64 = 0;
    let mut have_digit = false;
    for &b in v.as_bytes() {
        if (0x30..=0x39).contains(&b) {
            let digit = i64::from(b) - 0x30;
            if acc > (2_147_483_647 - digit) / 10 {
                return Err(ValidationError::new("min_kernel", "component too large"));
            }
            acc = acc * 10 + digit;
            have_digit = true;
        } else if b == 0x2E {
            if !have_digit || parts.len() >= 2 {
                return Err(ValidationError::new("min_kernel", "bad shape"));
            }
            parts.push(acc);
            acc = 0;
            have_digit = false;
        } else {
            return Err(ValidationError::new("min_kernel", "bad charset"));
        }
    }
    if !have_digit {
        return Err(ValidationError::new("min_kernel", "bad shape"));
    }
    parts.push(acc);
    if parts.len() < 2 || parts.len() > 3 {
        return Err(ValidationError::new("min_kernel", "bad shape"));
    }
    let patch = if parts.len() > 2 { parts[2] } else { 0 };
    Ok((v.to_string(), parts[0], parts[1], patch))
}

/// Check an absolute hook path: rooted, canonical segments.
///
/// Must start with `/`; every `/`-separated segment must be
/// non-empty and neither `.` nor `..`, so profile paths
/// cannot escape the evidence root they resolve against. NUL
/// bytes are rejected outright: libc truncates paths at NUL, so
/// a NUL would smuggle a different path past validation.
fn check_hook_path(v: &str, what: &str) -> Result<(), ValidationError> {
    if v.as_bytes().contains(&0) {
        return Err(ValidationError::new(what, "nul byte"));
    }
    let parts: Vec<&str> = v.split('/').collect();
    if parts.len() < 2 {
        return Err(ValidationError::new(what, "not absolute"));
    }
    if !parts[0].is_empty() {
        return Err(ValidationError::new(what, "not absolute"));
    }
    for seg in parts.iter().skip(1) {
        if seg.is_empty() {
            return Err(ValidationError::new(what, "empty segment"));
        }
        if *seg == "." || *seg == ".." {
            return Err(ValidationError::new(what, "dot segment"));
        }
    }
    Ok(())
}

/// Check a tracing function name: C identifier, 1..128 chars.
fn check_function(v: &str) -> Result<(), ValidationError> {
    check_bounded_text(v, 1, 128, "hook.function")
        .map_err(|e| ValidationError::new("hook.function", e.to_string()))?;
    let mut first = true;
    for &b in v.as_bytes() {
        let ok = (0x41..=0x5A).contains(&b)
            || (0x61..=0x7A).contains(&b)
            || b == 0x5F
            || (!first && (0x30..=0x39).contains(&b));
        if !ok {
            return Err(ValidationError::new("hook.function", "bad charset"));
        }
        first = false;
    }
    Ok(())
}

fn bounded(v: &str, min_len: usize, max_len: usize, what: &str) -> Result<(), ValidationError> {
    check_bounded_text(v, min_len, max_len, what)
        .map_err(|e| ValidationError::new(what, e.to_string()))
}

/// Parse the identity.source object: origin, revision, note?.
fn parse_source(scan: &mut Scanner<'_>) -> Result<ProfileSource, ValidationError> {
    scan.begin_object("source")?;
    let mut out = ProfileSource::default();
    let mut has_origin = false;
    let mut has_revision = false;
    let mut has_note = false;
    if !object_is_empty(scan, "source")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("source")?;
            expect_colon(scan, "source")?;
            if key == "origin" {
                if has_origin {
                    return Err(ValidationError::new("source.origin", "duplicate"));
                }
                let v = scan.parse_string("source.origin")?;
                bounded(&v, 1, 64, "source.origin")?;
                out.origin = v;
                has_origin = true;
            } else if key == "revision" {
                if has_revision {
                    return Err(ValidationError::new("source.revision", "duplicate"));
                }
                let v = scan.parse_string("source.revision")?;
                bounded(&v, 1, 128, "source.revision")?;
                out.revision = v;
                has_revision = true;
            } else if key == "note" {
                if has_note {
                    return Err(ValidationError::new("source.note", "duplicate"));
                }
                let v = scan.parse_string("source.note")?;
                // Twelve-field narrow notes need ~700
                // chars; 8-field notes stay valid.
                bounded(&v, 0, 1024, "source.note")?;
                out.note = v;
                out.has_note = true;
                has_note = true;
            } else {
                return Err(ValidationError::new("source", "unknown source field"));
            }
            if !object_next(scan, "source")? {
                break;
            }
        }
    }
    scan.end_object("source")?;
    if !has_origin || !has_revision {
        return Err(ValidationError::new("source", "missing field"));
    }
    Ok(out)
}

/// Parse the identity object: arch, min_kernel, source, note?.
fn parse_identity(scan: &mut Scanner<'_>) -> Result<ProfileIdentity, ValidationError> {
    scan.begin_object("identity")?;
    let mut out = ProfileIdentity::default();
    let mut has_arch = false;
    let mut has_min = false;
    let mut has_source = false;
    let mut has_note = false;
    if !object_is_empty(scan, "identity")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("identity")?;
            expect_colon(scan, "identity")?;
            if key == "arch" {
                if has_arch {
                    return Err(ValidationError::new("identity.arch", "duplicate"));
                }
                let v = scan.parse_string("identity.arch")?;
                bounded(&v, 1, 32, "identity.arch")?;
                out.arch = v;
                has_arch = true;
            } else if key == "min_kernel" {
                if has_min {
                    return Err(ValidationError::new("identity.min_kernel", "duplicate"));
                }
                let v = scan.parse_string("identity.min_kernel")?;
                let (text, major, minor, patch) = parse_min_kernel(&v)?;
                out.min_kernel = text;
                out.min_major = major;
                out.min_minor = minor;
                out.min_patch = patch;
                has_min = true;
            } else if key == "source" {
                if has_source {
                    return Err(ValidationError::new("identity.source", "duplicate"));
                }
                out.source = parse_source(scan)?;
                has_source = true;
            } else if key == "note" {
                if has_note {
                    return Err(ValidationError::new("identity.note", "duplicate"));
                }
                let v = scan.parse_string("identity.note")?;
                bounded(&v, 0, 512, "identity.note")?;
                out.note = v;
                out.has_note = true;
                has_note = true;
            } else {
                return Err(ValidationError::new("identity", "unknown identity field"));
            }
            if !object_next(scan, "identity")? {
                break;
            }
        }
    }
    scan.end_object("identity")?;
    if !has_arch || !has_min || !has_source {
        return Err(ValidationError::new("identity", "missing field"));
    }
    Ok(out)
}

/// Parse one hooks[] item: name, kind, kind-shaped fields, note?.
///
/// Tracepoint hooks need id/format paths with optional
/// layout text; tracing hooks need the frozen function
/// identity (function, attach, signature) plus optional
/// alternate signatures. Each kind forbids the other's
/// fields.
fn parse_hook(scan: &mut Scanner<'_>) -> Result<ProfileHook, ValidationError> {
    scan.begin_object("hook")?;
    let mut out = ProfileHook::default();
    let mut has_name = false;
    let mut has_kind = false;
    let mut has_id = false;
    let mut has_format = false;
    let mut has_text = false;
    let mut has_function = false;
    let mut has_attach = false;
    let mut has_signature = false;
    let mut has_alt = false;
    let mut has_note = false;
    if !object_is_empty(scan, "hook")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("hook")?;
            expect_colon(scan, "hook")?;
            if key == "name" {
                if has_name {
                    return Err(ValidationError::new("hook.name", "duplicate"));
                }
                let v = scan.parse_string("hook.name")?;
                bounded(&v, 1, 128, "hook.name")?;
                out.name = v;
                has_name = true;
            } else if key == "kind" {
                if has_kind {
                    return Err(ValidationError::new("hook.kind", "duplicate"));
                }
                let v = scan.parse_string("hook.kind")?;
                if v != "tracepoint" && v != "tracing" {
                    return Err(ValidationError::new("hook.kind", "bad const"));
                }
                out.kind = v;
                has_kind = true;
            } else if key == "id_path" {
                if has_id {
                    return Err(ValidationError::new("hook.id_path", "duplicate"));
                }
                let v = scan.parse_string("hook.id_path")?;
                bounded(&v, 1, 256, "hook.id_path")?;
                check_hook_path(&v, "hook.id_path")?;
                out.id_path = v;
                has_id = true;
            } else if key == "format_path" {
                if has_format {
                    return Err(ValidationError::new("hook.format_path", "duplicate"));
                }
                let v = scan.parse_string("hook.format_path")?;
                bounded(&v, 1, 256, "hook.format_path")?;
                check_hook_path(&v, "hook.format_path")?;
                out.format_path = v;
                has_format = true;
            } else if key == "format_text" {
                if has_text {
                    return Err(ValidationError::new("hook.format_text", "duplicate"));
                }
                let m = parse_nullable_string(scan, "hook.format_text")?;
                if let Some(v) = m {
                    bounded(&v, 0, 65536, "hook.format_text")?;
                    out.format_text = v;
                    out.format_has = true;
                }
                has_text = true;
            } else if key == "function" {
                if has_function {
                    return Err(ValidationError::new("hook.function", "duplicate"));
                }
                let v = scan.parse_string("hook.function")?;
                check_function(&v)?;
                out.function = v;
                has_function = true;
            } else if key == "attach" {
                if has_attach {
                    return Err(ValidationError::new("hook.attach", "duplicate"));
                }
                let v = scan.parse_string("hook.attach")?;
                if v != "fentry" && v != "fexit" {
                    return Err(ValidationError::new("hook.attach", "bad const"));
                }
                out.attach = v;
                has_attach = true;
            } else if key == "signature" {
                if has_signature {
                    return Err(ValidationError::new("hook.signature", "duplicate"));
                }
                let v = scan.parse_string("hook.signature")?;
                bounded(&v, 1, 1024, "hook.signature")?;
                out.signature = v;
                has_signature = true;
            } else if key == "signature_alt" {
                if has_alt {
                    return Err(ValidationError::new("hook.signature_alt", "duplicate"));
                }
                scan.begin_array("hook.signature_alt")?;
                if !array_is_empty(scan, "hook.signature_alt")? {
                    loop {
                        scan.skip_ws();
                        let v = scan.parse_string("hook.signature_alt[]")?;
                        bounded(&v, 1, 512, "hook.signature_alt[]")?;
                        out.signature_alt.push(v);
                        if out.signature_alt.len() > MAX_HOOK_ALT {
                            return Err(ValidationError::new(
                                "hook.signature_alt",
                                "too many items",
                            ));
                        }
                        if !array_next(scan, "hook.signature_alt")? {
                            break;
                        }
                    }
                }
                scan.end_array("hook.signature_alt")?;
                has_alt = true;
            } else if key == "note" {
                if has_note {
                    return Err(ValidationError::new("hook.note", "duplicate"));
                }
                let v = scan.parse_string("hook.note")?;
                bounded(&v, 0, 512, "hook.note")?;
                out.note = v;
                out.has_note = true;
                has_note = true;
            } else {
                return Err(ValidationError::new("hook", "unknown hook field"));
            }
            if !object_next(scan, "hook")? {
                break;
            }
        }
    }
    scan.end_object("hook")?;
    if !has_name || !has_kind {
        return Err(ValidationError::new("hook", "missing field"));
    }
    if out.kind == "tracing" {
        if has_id || has_format || has_text {
            return Err(ValidationError::new("hook", "tracepoint field on tracing"));
        }
        if !has_function || !has_attach || !has_signature {
            return Err(ValidationError::new("hook", "missing field"));
        }
    } else {
        if has_function || has_attach || has_signature || has_alt {
            return Err(ValidationError::new("hook", "tracing field on tracepoint"));
        }
        if !has_id || !has_format {
            return Err(ValidationError::new("hook", "missing field"));
        }
    }
    Ok(out)
}

/// Parse one layouts[] item: struct, field, bit_offset, bit_size.
fn parse_layout(scan: &mut Scanner<'_>) -> Result<ProfileLayout, ValidationError> {
    scan.begin_object("layout")?;
    let mut out = ProfileLayout::default();
    let mut has_struct = false;
    let mut has_field = false;
    let mut has_off = false;
    let mut has_size = false;
    if !object_is_empty(scan, "layout")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("layout")?;
            expect_colon(scan, "layout")?;
            if key == "struct" {
                if has_struct {
                    return Err(ValidationError::new("layout.struct", "duplicate"));
                }
                let v = scan.parse_string("layout.struct")?;
                bounded(&v, 1, 128, "layout.struct")?;
                out.struct_name = v;
                has_struct = true;
            } else if key == "field" {
                if has_field {
                    return Err(ValidationError::new("layout.field", "duplicate"));
                }
                let v = scan.parse_string("layout.field")?;
                bounded(&v, 1, 128, "layout.field")?;
                out.field_name = v;
                has_field = true;
            } else if key == "bit_offset" {
                if has_off {
                    return Err(ValidationError::new("layout.bit_offset", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("layout.bit_offset")?;
                if v < 0 {
                    return Err(ValidationError::new("layout.bit_offset", "out of range"));
                }
                out.bit_offset = v;
                has_off = true;
            } else if key == "bit_size" {
                if has_size {
                    return Err(ValidationError::new("layout.bit_size", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("layout.bit_size")?;
                if v < 0 {
                    return Err(ValidationError::new("layout.bit_size", "out of range"));
                }
                out.bit_size = v;
                has_size = true;
            } else {
                return Err(ValidationError::new("layout", "unknown layout field"));
            }
            if !object_next(scan, "layout")? {
                break;
            }
        }
    }
    scan.end_object("layout")?;
    if !has_struct || !has_field || !has_off || !has_size {
        return Err(ValidationError::new("layout", "missing field"));
    }
    Ok(out)
}

/// Parse one 0.1.2 layouts[] item: capability, target, kind, size.
///
/// Every key is required except `field`, which a `type`
/// target omits. There is no `bit_offset`: offsets are
/// evidence only, never compared.
fn parse_layout_v012(scan: &mut Scanner<'_>) -> Result<ProfileLayout, ValidationError> {
    scan.begin_object("layout")?;
    let mut out = ProfileLayout {
        v012: true,
        ..ProfileLayout::default()
    };
    let mut has_cap = false;
    let mut has_target = false;
    let mut has_struct = false;
    let mut has_field = false;
    let mut has_kind = false;
    let mut has_size = false;
    let mut has_optional = false;
    if !object_is_empty(scan, "layout")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("layout")?;
            expect_colon(scan, "layout")?;
            if key == "capability" {
                if has_cap {
                    return Err(ValidationError::new("layout.capability", "duplicate"));
                }
                let v = scan.parse_string("layout.capability")?;
                if v != "attempt-trace" && v != "mapping-lifecycle" && v != "copy-actual" {
                    return Err(ValidationError::new("layout.capability", "bad enum"));
                }
                out.capability = v;
                has_cap = true;
            } else if key == "target" {
                if has_target {
                    return Err(ValidationError::new("layout.target", "duplicate"));
                }
                let v = scan.parse_string("layout.target")?;
                if v != "field" && v != "type" && v != "enumerator" {
                    return Err(ValidationError::new("layout.target", "bad enum"));
                }
                out.target = v;
                has_target = true;
            } else if key == "struct" {
                if has_struct {
                    return Err(ValidationError::new("layout.struct", "duplicate"));
                }
                let v = scan.parse_string("layout.struct")?;
                bounded(&v, 1, 128, "layout.struct")?;
                out.struct_name = v;
                has_struct = true;
            } else if key == "field" {
                if has_field {
                    return Err(ValidationError::new("layout.field", "duplicate"));
                }
                let v = scan.parse_string("layout.field")?;
                bounded(&v, 1, 128, "layout.field")?;
                out.field_name = v;
                has_field = true;
            } else if key == "type_kind" {
                if has_kind {
                    return Err(ValidationError::new("layout.type_kind", "duplicate"));
                }
                let v = scan.parse_string("layout.type_kind")?;
                if v != "int"
                    && v != "ptr"
                    && v != "array"
                    && v != "struct"
                    && v != "union"
                    && v != "enum"
                    && v != "float"
                {
                    return Err(ValidationError::new("layout.type_kind", "bad enum"));
                }
                out.type_kind = v;
                has_kind = true;
            } else if key == "bit_size" {
                if has_size {
                    return Err(ValidationError::new("layout.bit_size", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("layout.bit_size")?;
                if v < 1 {
                    return Err(ValidationError::new("layout.bit_size", "out of range"));
                }
                out.bit_size = v;
                has_size = true;
            } else if key == "optional" {
                if has_optional {
                    return Err(ValidationError::new("layout.optional", "duplicate"));
                }
                scan.skip_ws();
                out.optional = scan.parse_bool("layout.optional")?;
                has_optional = true;
            } else {
                return Err(ValidationError::new("layout", "unknown layout field"));
            }
            if !object_next(scan, "layout")? {
                break;
            }
        }
    }
    scan.end_object("layout")?;
    if out.target == "type" {
        if has_field {
            return Err(ValidationError::new("layout", "field on type target"));
        }
    } else if !has_field {
        return Err(ValidationError::new("layout", "missing field"));
    }
    if !has_cap || !has_target || !has_struct || !has_kind || !has_size || !has_optional {
        return Err(ValidationError::new("layout", "missing field"));
    }
    Ok(out)
}

/// Parse one capabilities[] item: id, status, hooks, reason.
fn parse_capability(scan: &mut Scanner<'_>) -> Result<ProfileCapability, ValidationError> {
    scan.begin_object("capability")?;
    let mut out = ProfileCapability::default();
    let mut has_id = false;
    let mut has_status = false;
    let mut has_hooks = false;
    let mut has_reason = false;
    if !object_is_empty(scan, "capability")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("capability")?;
            expect_colon(scan, "capability")?;
            if key == "id" {
                if has_id {
                    return Err(ValidationError::new("capability.id", "duplicate"));
                }
                let v = scan.parse_string("capability.id")?;
                if v != "attempt-trace"
                    && v != "mapping-lifecycle"
                    && v != "copy-actual"
                    && v != "conversion-observe"
                {
                    return Err(ValidationError::new("capability.id", "bad enum"));
                }
                out.id = v;
                has_id = true;
            } else if key == "status" {
                if has_status {
                    return Err(ValidationError::new("capability.status", "duplicate"));
                }
                let v = scan.parse_string("capability.status")?;
                if v != "candidate" && v != "supported" && v != "unsupported" {
                    return Err(ValidationError::new("capability.status", "bad enum"));
                }
                out.status = v;
                has_status = true;
            } else if key == "hooks" {
                if has_hooks {
                    return Err(ValidationError::new("capability.hooks", "duplicate"));
                }
                scan.begin_array("capability.hooks")?;
                if !array_is_empty(scan, "capability.hooks")? {
                    loop {
                        scan.skip_ws();
                        let v = scan.parse_string("capability.hooks[]")?;
                        bounded(&v, 1, 128, "capability.hooks[]")?;
                        out.hooks.push(v);
                        if out.hooks.len() > MAX_CAP_HOOKS {
                            return Err(ValidationError::new("capability.hooks", "too many items"));
                        }
                        if !array_next(scan, "capability.hooks")? {
                            break;
                        }
                    }
                }
                scan.end_array("capability.hooks")?;
                has_hooks = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new("capability.reason", "duplicate"));
                }
                let v = scan.parse_string("capability.reason")?;
                bounded(&v, 0, 512, "capability.reason")?;
                out.reason = v;
                has_reason = true;
            } else {
                return Err(ValidationError::new(
                    "capability",
                    "unknown capability field",
                ));
            }
            if !object_next(scan, "capability")? {
                break;
            }
        }
    }
    scan.end_object("capability")?;
    if !has_id || !has_status || !has_hooks || !has_reason {
        return Err(ValidationError::new("capability", "missing field"));
    }
    Ok(out)
}

/// Best-effort top-level schema_version, else "".
///
/// Layouts may precede schema_version in key order, so
/// the item shape needs the version before the main
/// parse reaches it. Only the shape decision reads this;
/// the main parse still validates the version itself.
fn prescan_schema_version(data: &[u8]) -> String {
    let found: Result<String, ValidationError> = (|| {
        let mut scan = Scanner::new(data);
        scan.skip_ws();
        scan.begin_object("profile")?;
        if !object_is_empty(&mut scan, "profile")? {
            loop {
                scan.skip_ws();
                let key = scan.parse_string("profile")?;
                expect_colon(&mut scan, "profile")?;
                if key == "schema_version" {
                    scan.skip_ws();
                    return scan.parse_string("profile");
                }
                scan.skip_value("profile")?;
                if !object_next(&mut scan, "profile")? {
                    break;
                }
            }
        }
        Ok(String::new())
    })();
    found.unwrap_or_default()
}

/// Parse and validate one profile JSON document.
pub fn parse_profile_bytes(data: &[u8]) -> Result<Profile, ValidationError> {
    let is_v012 = prescan_schema_version(data) == "0.1.2";
    let mut scan = Scanner::new(data);
    scan.skip_ws();
    scan.begin_object("profile")?;
    let mut out = Profile::default();
    let mut has_version = false;
    let mut has_id = false;
    let mut has_status = false;
    let mut has_identity = false;
    let mut has_hooks = false;
    let mut has_caps = false;
    let mut has_notes = false;
    let mut has_layouts = false;
    if !object_is_empty(&mut scan, "profile")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("profile")?;
            expect_colon(&mut scan, "profile")?;
            if key == "schema_version" {
                if has_version {
                    return Err(ValidationError::new("schema_version", "duplicate"));
                }
                let v = scan.parse_string("schema_version")?;
                if v != PROFILE_SCHEMA_VERSION && v != "0.1.2" {
                    return Err(ValidationError::new("schema_version", "bad const"));
                }
                out.schema_version = v;
                has_version = true;
            } else if key == "profile_id" {
                if has_id {
                    return Err(ValidationError::new("profile_id", "duplicate"));
                }
                let v = scan.parse_string("profile_id")?;
                check_profile_id(&v)?;
                out.profile_id = v;
                has_id = true;
            } else if key == "status" {
                if has_status {
                    return Err(ValidationError::new("status", "duplicate"));
                }
                let v = scan.parse_string("status")?;
                if v != "validated" && v != "reference-unvalidated" {
                    return Err(ValidationError::new("status", "bad enum"));
                }
                out.status = v;
                has_status = true;
            } else if key == "identity" {
                if has_identity {
                    return Err(ValidationError::new("identity", "duplicate"));
                }
                out.identity = parse_identity(&mut scan)?;
                has_identity = true;
            } else if key == "hooks" {
                if has_hooks {
                    return Err(ValidationError::new("hooks", "duplicate"));
                }
                scan.begin_array("hooks")?;
                if !array_is_empty(&mut scan, "hooks")? {
                    loop {
                        let h = parse_hook(&mut scan)?;
                        for prior in &out.hooks {
                            if prior.name == h.name {
                                return Err(ValidationError::new("hooks", "duplicate hook name"));
                            }
                        }
                        out.hooks.push(h);
                        if out.hooks.len() > MAX_PROFILE_HOOKS {
                            return Err(ValidationError::new("hooks", "too many items"));
                        }
                        if !array_next(&mut scan, "hooks")? {
                            break;
                        }
                    }
                }
                scan.end_array("hooks")?;
                has_hooks = true;
            } else if key == "capabilities" {
                if has_caps {
                    return Err(ValidationError::new("capabilities", "duplicate"));
                }
                scan.begin_array("capabilities")?;
                if !array_is_empty(&mut scan, "capabilities")? {
                    loop {
                        let c = parse_capability(&mut scan)?;
                        for prior in &out.caps {
                            if prior.id == c.id {
                                return Err(ValidationError::new(
                                    "capabilities",
                                    "duplicate capability id",
                                ));
                            }
                        }
                        out.caps.push(c);
                        if out.caps.len() > MAX_PROFILE_CAPS {
                            return Err(ValidationError::new("capabilities", "too many items"));
                        }
                        if !array_next(&mut scan, "capabilities")? {
                            break;
                        }
                    }
                }
                scan.end_array("capabilities")?;
                has_caps = true;
            } else if key == "notes" {
                if has_notes {
                    return Err(ValidationError::new("notes", "duplicate"));
                }
                scan.begin_array("notes")?;
                if !array_is_empty(&mut scan, "notes")? {
                    loop {
                        scan.skip_ws();
                        let v = scan.parse_string("notes[]")?;
                        bounded(&v, 0, 512, "notes[]")?;
                        out.notes.push(v);
                        if out.notes.len() > MAX_PROFILE_NOTES {
                            return Err(ValidationError::new("notes", "too many items"));
                        }
                        if !array_next(&mut scan, "notes")? {
                            break;
                        }
                    }
                }
                scan.end_array("notes")?;
                has_notes = true;
            } else if key == "layouts" {
                if has_layouts {
                    return Err(ValidationError::new("layouts", "duplicate"));
                }
                scan.begin_array("layouts")?;
                if !array_is_empty(&mut scan, "layouts")? {
                    loop {
                        let l = if is_v012 {
                            parse_layout_v012(&mut scan)?
                        } else {
                            parse_layout(&mut scan)?
                        };
                        if is_v012 {
                            for prior in &out.layouts {
                                if prior.capability == l.capability
                                    && prior.target == l.target
                                    && prior.struct_name == l.struct_name
                                    && prior.field_name == l.field_name
                                {
                                    return Err(ValidationError::new("layouts", "duplicate"));
                                }
                            }
                        }
                        out.layouts.push(l);
                        let layout_cap = if is_v012 {
                            MAX_PROFILE_LAYOUTS_V012
                        } else {
                            MAX_PROFILE_LAYOUTS
                        };
                        if out.layouts.len() > layout_cap {
                            return Err(ValidationError::new("layouts", "too many items"));
                        }
                        if !array_next(&mut scan, "layouts")? {
                            break;
                        }
                    }
                }
                scan.end_array("layouts")?;
                has_layouts = true;
            } else {
                return Err(ValidationError::new("profile", "unknown profile field"));
            }
            if !object_next(&mut scan, "profile")? {
                break;
            }
        }
    }
    scan.end_object("profile")?;
    if !has_version || !has_id || !has_status || !has_identity || !has_hooks || !has_caps {
        return Err(ValidationError::new("profile", "missing field"));
    }
    for cap in &out.caps {
        for need in &cap.hooks {
            let mut known = false;
            for hook in &out.hooks {
                if &hook.name == need {
                    known = true;
                    break;
                }
            }
            if !known {
                return Err(ValidationError::new(
                    "capability.hooks",
                    "unknown hook reference",
                ));
            }
        }
    }
    scan.skip_ws();
    if !scan.at_end() {
        return Err(ValidationError::new("profile", "trailing data"));
    }
    Ok(out)
}

/// Check one manifest filename: plain name, no path escape.
///
/// Accepts `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}` with no leading
/// dot, so `/`, `..`, and hidden files are all rejected and
/// the name always resolves directly under the profiles dir.
fn check_manifest_name(name: &str) -> Result<(), ValidationError> {
    check_bounded_text(name, 1, 128, "manifest")
        .map_err(|e| ValidationError::new("manifest", e.to_string()))?;
    let mut first = true;
    for &b in name.as_bytes() {
        let ok = (0x41..=0x5A).contains(&b)
            || (0x61..=0x7A).contains(&b)
            || (0x30..=0x39).contains(&b)
            || b == 0x5F
            || (!first && (b == 0x2E || b == 0x2D));
        if !ok {
            return Err(ValidationError::new("manifest", "bad filename"));
        }
        first = false;
    }
    Ok(())
}

/// Profiles plus their manifest entries, index-aligned.
///
/// One manifest read produces both lists, so `names[i]`
/// is always the file `profiles[i]` was parsed from.
/// Callers that re-resolve a planned document (the qualify
/// smoke) use the entry to preserve document identity
/// instead of resolving a bare id again.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamedProfiles {
    /// Manifest entries, index-aligned with `profiles`.
    pub names: Vec<String>,
    /// Parsed profiles in manifest order.
    pub profiles: Vec<Profile>,
}

/// Load every manifest-admitted profile with its entry.
///
/// `<dir>/manifest.txt` holds one filename per line: no blank
/// lines or padding (a single trailing newline is allowed), no
/// duplicates. An empty manifest admits nothing, which the
/// doctor reports as unknown coverage downstream.
pub fn load_profiles_named(dir: &str) -> Result<NamedProfiles, ValidationError> {
    let raw = read_host_file(&format!("{dir}/manifest.txt"), "manifest.txt", MANIFEST_CAP)
        .map_err(|e| ValidationError::new("manifest", e.message))?;
    let text = bytes_to_text(&raw);
    let mut names: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        if i == lines.len() - 1 && line.is_empty() {
            break;
        }
        if line.is_empty() {
            return Err(ValidationError::new("manifest", "blank line"));
        }
        check_manifest_name(line)?;
        for prior in &names {
            if prior == line {
                return Err(ValidationError::new("manifest", "duplicate entry"));
            }
        }
        names.push(line.to_string());
    }
    let mut out = NamedProfiles::default();
    for name in &names {
        let path = format!("{dir}/{name}");
        let data = read_host_file(&path, name, PROFILE_CAP)
            .map_err(|e| ValidationError::new(format!("profile {name}"), e.message))?;
        match parse_profile_bytes(&data) {
            Ok(prof) => out.profiles.push(prof),
            Err(e) => {
                return Err(ValidationError::new(
                    format!("profile {name}"),
                    e.to_string(),
                ));
            }
        }
    }
    out.names = names;
    Ok(out)
}

/// Load every manifest-admitted profile under dir, in order.
///
/// `<dir>/manifest.txt` holds one filename per line: no blank
/// lines or padding (a single trailing newline is allowed), no
/// duplicates. An empty manifest admits nothing, which the
/// doctor reports as unknown coverage downstream.
pub fn load_profiles(dir: &str) -> Result<Vec<Profile>, ValidationError> {
    Ok(load_profiles_named(dir)?.profiles)
}

/// True when `<dir>/manifest.txt` opens within the manifest cap.
///
/// Presence probe for executable-relative discovery: callers use it
/// to prefer an adjacent profiles dir before falling back to a
/// layout-specific search. Readability, not validity, decides; the
/// caller loads (and validates) the manifest afterwards, so a
/// corrupt-but-present manifest still surfaces its real error.
pub fn manifest_readable(dir: &str) -> bool {
    read_host_file(&format!("{dir}/manifest.txt"), "manifest.txt", MANIFEST_CAP).is_ok()
}

/// True when (major, minor, patch) reaches the wanted triple.
fn triple_ge(
    major: i64,
    minor: i64,
    patch: i64,
    want_major: i64,
    want_minor: i64,
    want_patch: i64,
) -> bool {
    if major != want_major {
        return major > want_major;
    }
    if minor != want_minor {
        return minor > want_minor;
    }
    patch >= want_patch
}

/// Match kernel identity against profiles in manifest order.
///
/// The first covering profile wins: `arch` must equal and the
/// release triple must reach `min_kernel`. `matched` is true
/// only for validated profiles. Never fails: an unparseable
/// release simply covers nothing.
pub fn select_profile(kernel: &KernelInfo, profiles: &[Profile]) -> ProfileDecision {
    if profiles.is_empty() {
        return ProfileDecision {
            matched: false,
            has_profile: false,
            profile: Profile::default(),
            reason: "no profiles admitted".to_string(),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    }
    let triple = parse_kernel_triple(&kernel.release);
    if !triple.ok {
        return ProfileDecision {
            matched: false,
            has_profile: false,
            profile: Profile::default(),
            reason: format!("release {} is unparseable; no coverage", kernel.release),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    }
    for p in profiles {
        let mut covered = p.identity.arch == kernel.arch;
        if covered {
            covered = triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                p.identity.min_major,
                p.identity.min_minor,
                p.identity.min_patch,
            );
        }
        if covered {
            if p.status == "validated" {
                return ProfileDecision {
                    matched: true,
                    has_profile: true,
                    profile: p.clone(),
                    reason: format!("profile {} matched (validated)", p.profile_id),
                    grade: "validated".to_string(),
                    receipt_caps: Vec::new(),
                };
            }
            return ProfileDecision {
                matched: false,
                has_profile: true,
                profile: p.clone(),
                reason: format!(
                    "profile {} covers this identity but is reference-unvalidated",
                    p.profile_id
                ),
                grade: String::new(),
                receipt_caps: Vec::new(),
            };
        }
    }
    ProfileDecision {
        matched: false,
        has_profile: false,
        profile: Profile::default(),
        reason: format!(
            "no profile covers arch {} release {}",
            kernel.arch, kernel.release
        ),
        grade: String::new(),
        receipt_caps: Vec::new(),
    }
}

/// One frozen tracing hook: name plus exact signature.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TraceWant {
    /// Hook name.
    pub name: String,
    /// Frozen function name.
    pub function: String,
    /// Frozen attach point.
    pub attach: String,
    /// Frozen signature spelling.
    pub signature: String,
}

impl TraceWant {
    fn of(name: &str, function: &str, attach: &str, signature: &str) -> Self {
        Self {
            name: name.to_string(),
            function: function.to_string(),
            attach: attach.to_string(),
            signature: signature.to_string(),
        }
    }
}

/// Frozen lifecycle tracing hooks; mirrors the hook freeze.
pub fn lc_trace() -> Vec<TraceWant> {
    vec![
        TraceWant::of(
            "fexit:swiotlb_tbl_map_single",
            "swiotlb_tbl_map_single",
            "fexit",
            "phys_addr_t swiotlb_tbl_map_single(struct device *dev, \
             phys_addr_t orig_addr, size_t mapping_size, \
             unsigned int alloc_align_mask, \
             enum dma_data_direction dir, unsigned long attrs)",
        ),
        TraceWant::of(
            "fentry:__swiotlb_tbl_unmap_single",
            "__swiotlb_tbl_unmap_single",
            "fentry",
            "void __swiotlb_tbl_unmap_single(struct device *dev, \
             phys_addr_t tlb_addr, size_t mapping_size, \
             enum dma_data_direction dir, unsigned long attrs, \
             struct io_tlb_pool *pool)",
        ),
    ]
}

/// Frozen copy tracing hooks; mirrors the hook freeze.
pub fn cp_trace() -> Vec<TraceWant> {
    vec![
        TraceWant::of(
            "fentry:__swiotlb_sync_single_for_device",
            "__swiotlb_sync_single_for_device",
            "fentry",
            "void __swiotlb_sync_single_for_device(struct device *dev, \
             phys_addr_t tlb_addr, size_t size, \
             enum dma_data_direction dir, struct io_tlb_pool *pool)",
        ),
        TraceWant::of(
            "fentry:__swiotlb_sync_single_for_cpu",
            "__swiotlb_sync_single_for_cpu",
            "fentry",
            "void __swiotlb_sync_single_for_cpu(struct device *dev, \
             phys_addr_t tlb_addr, size_t size, \
             enum dma_data_direction dir, struct io_tlb_pool *pool)",
        ),
        TraceWant::of(
            "fentry:swiotlb_bounce",
            "swiotlb_bounce",
            "fentry",
            "void swiotlb_bounce(struct device *dev, \
             phys_addr_t tlb_addr, size_t size, \
             enum dma_data_direction dir, struct io_tlb_pool *mem)",
        ),
    ]
}

/// First reason the doc's tracing bindings fail, else "".
///
/// Every hook named by a requested extra capability must
/// be a tracing hook whose (function, attach) pair is a
/// frozen member of that capability with matching frozen
/// parameter types, and every frozen member must be
/// named: no vacuous, partial, or substituted bindings.
/// Parameter names never compare. Live signature
/// identity rides the whole-BTF binding checked later;
/// this gate pins the document side. Record admission
/// and doctor availability share this one predicate so
/// the two verbs cannot disagree about a document's
/// tracing bindings.
pub fn tracing_gap(doc: &Profile, caps: &[String]) -> String {
    for cap in caps {
        if cap == ATTEMPT_TRACE_ID {
            continue;
        }
        let wants = if cap == LIFECYCLE_CAP_ID {
            lc_trace()
        } else {
            cp_trace()
        };
        let mut named: &[String] = &[];
        for c in &doc.caps {
            if &c.id == cap {
                named = &c.hooks;
                break;
            }
        }
        let mut seen = vec![false; wants.len()];
        for name in named {
            let mut hook: Option<&ProfileHook> = None;
            for h in &doc.hooks {
                if &h.name == name {
                    hook = Some(h);
                    break;
                }
            }
            let Some(hook) = hook else {
                return format!("capability {cap} names unknown hook {name}");
            };
            if hook.kind != "tracing" {
                return format!("capability {cap} hook {name} is not a tracing hook");
            }
            let mut member: Option<usize> = None;
            for (k, w) in wants.iter().enumerate() {
                if w.function == hook.function && w.attach == hook.attach {
                    member = Some(k);
                    break;
                }
            }
            let Some(member) = member else {
                return format!("capability {cap} hook {name} binds no frozen {cap} hook");
            };
            let have = frozen_sig_types(&hook.signature, &hook.function);
            let want = frozen_sig_types(&wants[member].signature, &wants[member].function);
            if !have.has || !want.has || !frozen_types_equal(&have, &want) {
                return format!("capability {cap} hook {name} signature mismatch");
            }
            seen[member] = true;
        }
        for (j, w) in wants.iter().enumerate() {
            if !seen[j] {
                return format!("capability {cap} missing frozen hook {}", w.name);
            }
        }
    }
    String::new()
}

/// Attempt-hook selection: ok plus hook, else refusal.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookSelection {
    /// True when a hook was selected.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub refusal: String,
    /// The selected hook (empty unless ok).
    pub hook: ProfileHook,
}

/// Select the attempt-trace hook of one profile.
///
/// The hook named by the attempt-trace capability wins;
/// otherwise the first tracepoint hook. Anything else
/// refuses: capture needs exactly one tracepoint site.
/// Shared by record admission and binding-aware selection
/// so both judge the same hook.
pub fn select_attempt_hook(profile: &Profile) -> HookSelection {
    let mut out = HookSelection::default();
    let mut want = "";
    for c in &profile.caps {
        if c.id == ATTEMPT_TRACE_ID {
            if !c.hooks.is_empty() {
                want = &c.hooks[0];
            }
            break;
        }
    }
    if !want.is_empty() {
        for h in &profile.hooks {
            if h.name == want {
                if h.kind != "tracepoint" {
                    out.refusal = "attempt-trace hook is not a tracepoint".to_string();
                    return out;
                }
                out.ok = true;
                out.hook = h.clone();
                return out;
            }
        }
        out.refusal = "attempt-trace hook missing".to_string();
        return out;
    }
    for h in &profile.hooks {
        if h.kind == "tracepoint" {
            out.ok = true;
            out.hook = h.clone();
            return out;
        }
    }
    out.refusal = "no tracepoint hook".to_string();
    out
}

/// Strip the function name from a frozen signature.
///
/// Frozen form is "<ret> <name>(<params>)"; the normalized
/// form "<ret> (<params>)" compares directly with the BTF
/// canonical spelling. Anything else (no paren, name not
/// immediately before it, empty return type, trailing
/// bytes) yields no value: the frozen text is malformed.
fn normalize_frozen_signature(frozen: &str, function: &str) -> Option<String> {
    let fb = frozen.as_bytes();
    let nb = function.as_bytes();
    if fb.is_empty() || nb.is_empty() {
        return None;
    }
    let mut open: Option<usize> = None;
    for (i, &b) in fb.iter().enumerate() {
        if b == 0x28 {
            open = Some(i);
            break;
        }
    }
    let open = open?;
    if fb[fb.len() - 1] != 0x29 {
        return None;
    }
    let need = nb.len() + 1;
    if open < need + 1 {
        return None;
    }
    if fb[open - need] != 0x20 {
        return None;
    }
    if fb[open - nb.len()..open] != nb[..] {
        return None;
    }
    let ret = core::str::from_utf8(&fb[0..open - need]).ok()?;
    let tail = core::str::from_utf8(&fb[open + 1..]).ok()?;
    Some(format!("{ret} ({tail}"))
}

/// One frozen signature split into return and type spellings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrozenSig {
    /// True when the signature normalized.
    pub has: bool,
    /// Return type spelling.
    pub ret: String,
    /// Parameter type spellings.
    pub params: Vec<String>,
}

/// True for C type keywords that name no parameter.
fn is_type_keyword(word: &str) -> bool {
    matches!(
        word,
        "void"
            | "char"
            | "short"
            | "int"
            | "long"
            | "float"
            | "double"
            | "signed"
            | "unsigned"
            | "_Bool"
            | "const"
            | "volatile"
    )
}

/// True for well-formed C identifiers.
fn is_identifier(word: &str) -> bool {
    let b = word.as_bytes();
    if b.is_empty() {
        return false;
    }
    let head = b[0] == 0x5F || (0x41..=0x5A).contains(&b[0]) || (0x61..=0x7A).contains(&b[0]);
    if !head {
        return false;
    }
    for &c in &b[1..] {
        let tail = c == 0x5F
            || (0x30..=0x39).contains(&c)
            || (0x41..=0x5A).contains(&c)
            || (0x61..=0x7A).contains(&c);
        if !tail {
            return false;
        }
    }
    true
}

/// Drop the parameter name, keeping the type spelling.
///
/// Pointer spellings cut after the last star. Plain
/// spellings drop a well-formed trailing name only when
/// the leading words form a complete type: a single
/// word, a keyword run, or tag plus name. Unnamed
/// multi-word types keep every word, and malformed
/// trailing words stay whole and mismatch loudly.
fn strip_param_name(p: &str) -> String {
    let b = p.as_bytes();
    let mut star: Option<usize> = None;
    for (i, &c) in b.iter().enumerate() {
        if c == 0x2A {
            star = Some(i);
        }
    }
    if let Some(star) = star {
        let mut clean = star + 1 < b.len();
        for &c in &b[star + 1..] {
            if c == 0x20 {
                clean = false;
                break;
            }
        }
        if clean && let Ok(s) = core::str::from_utf8(&b[0..star + 1]) {
            return s.to_string();
        }
        return p.to_string();
    }
    let words: Vec<&str> = p.split(' ').collect();
    if words.len() < 2 {
        return p.to_string();
    }
    let last = words[words.len() - 1];
    if is_type_keyword(last) {
        return p.to_string();
    }
    if !is_identifier(last) {
        return p.to_string();
    }
    let first = words[0];
    if first == "struct" || first == "union" || first == "enum" {
        if words.len() != 3 {
            return p.to_string();
        }
    } else if words.len() > 2 {
        for w in &words[..words.len() - 1] {
            if !is_type_keyword(w) {
                return p.to_string();
            }
        }
    }
    let mut sp: Option<usize> = None;
    for (i, &c) in b.iter().enumerate() {
        if c == 0x20 {
            sp = Some(i);
        }
    }
    if let Some(sp) = sp
        && let Ok(s) = core::str::from_utf8(&b[0..sp])
    {
        return s.to_string();
    }
    p.to_string()
}

/// Split a frozen signature into return and type spellings.
///
/// Built on the frozen normalizer; parameter names
/// are stripped, leaving typedef-level type spellings
/// that compare directly with the live BTF reading.
pub fn frozen_sig_types(sig: &str, function: &str) -> FrozenSig {
    let mut out = FrozenSig::default();
    let Some(norm) = normalize_frozen_signature(sig, function) else {
        return out;
    };
    let parts: Vec<&str> = norm.split(" (").collect();
    if parts.len() != 2 {
        return out;
    }
    let inner = parts[1];
    if !inner.ends_with(')') {
        return out;
    }
    let ib = inner.as_bytes();
    let Ok(body) = core::str::from_utf8(&ib[0..ib.len() - 1]) else {
        return out;
    };
    out.ret = parts[0].to_string();
    if body == "void" {
        out.has = true;
        return out;
    }
    for item in body.split(", ") {
        out.params.push(strip_param_name(item));
    }
    out.has = true;
    out
}

/// True when a live signature equals one frozen spelling.
fn sig_types_equal(sig: &BtfFuncSig, fs: &FrozenSig) -> bool {
    if sig.ret != fs.ret {
        return false;
    }
    if sig.params.len() != fs.params.len() {
        return false;
    }
    for (i, p) in sig.params.iter().enumerate() {
        if *p != fs.params[i] {
            return false;
        }
    }
    true
}

/// True when two frozen spellings name the same types.
fn frozen_types_equal(left: &FrozenSig, right: &FrozenSig) -> bool {
    if left.ret != right.ret {
        return false;
    }
    if left.params.len() != right.params.len() {
        return false;
    }
    for (i, p) in left.params.iter().enumerate() {
        if *p != right.params[i] {
            return false;
        }
    }
    true
}

/// First address-typedef width refusal, else "".
///
/// Every phys_addr_t, size_t, and dma_addr_t parameter
/// must resolve to 64 bits on the supported shape.
fn sig_width_refusal(hook: &str, sig: &BtfFuncSig) -> String {
    for (i, p) in sig.params.iter().enumerate() {
        if (p == "phys_addr_t" || p == "size_t" || p == "dma_addr_t") && sig.widths[i] != 64 {
            let w = sig.widths[i];
            return format!("{hook}: {p} width {w} bits (want 64)");
        }
    }
    String::new()
}

/// Compare frozen tracing signatures against live BTF bytes.
///
/// One verdict per tracing hook in profile order; tracepoint
/// hooks are skipped (their tracefs layout is checked
/// separately). A verdict is ok only when the frozen
/// signature (or any recorded alternate) matches the live
/// BTF prototype in return spelling, parameter count, and
/// every typedef-level parameter spelling, with 64-bit
/// address widths; every refusal names the hook and the
/// cause. Parameter names never compare.
pub fn verify_hook_signatures(profile: &Profile, btf: &[u8]) -> Vec<SigVerdict> {
    let mut out: Vec<SigVerdict> = Vec::new();
    for h in &profile.hooks {
        if h.kind != "tracing" {
            continue;
        }
        let mut v = SigVerdict {
            hook: h.name.clone(),
            ..SigVerdict::default()
        };
        let fsig = frozen_sig_types(&h.signature, &h.function);
        if !fsig.has {
            v.reason = format!("{}: frozen signature malformed", h.name);
            out.push(v);
            continue;
        }
        let mut alts: Vec<FrozenSig> = Vec::new();
        let mut alt_bad = false;
        for a in &h.signature_alt {
            let an = frozen_sig_types(a, &h.function);
            if !an.has {
                alt_bad = true;
                break;
            }
            alts.push(an);
        }
        if alt_bad {
            v.reason = format!("{}: frozen signature_alt malformed", h.name);
            out.push(v);
            continue;
        }
        let sig = read_btf_func_sig(btf, &h.function);
        if !sig.ok {
            v.reason = format!("{}: {}", h.name, sig.message);
            out.push(v);
            continue;
        }
        let proto = read_btf_func_proto(btf, &h.function);
        if proto.ok {
            v.live = proto.canonical.clone();
        }
        let mut hit = sig_types_equal(&sig, &fsig);
        for a in &alts {
            if sig_types_equal(&sig, a) {
                hit = true;
                break;
            }
        }
        if !hit {
            v.reason = format!("{}: signature mismatch", h.name);
            v.code = "signature-mismatch".to_string();
            out.push(v);
            continue;
        }
        let wref = sig_width_refusal(&h.name, &sig);
        if !wref.is_empty() {
            v.reason = wref;
            v.code = "signature-width".to_string();
            out.push(v);
            continue;
        }
        v.ok = true;
        out.push(v);
    }
    out
}

/// One live-interface verdict: ok, refused, or unknown.
///
/// `unknown` true means the evidence was unreadable, so
/// the interfaces are neither verified nor refused; every
/// other refusal carries `unknown` false. `reason` is
/// "" exactly when `ok`. `code` names the machine
/// reason class, "" when ok or unclassified. `evidence`
/// carries one line per checked 0.1.2 layout item.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiveVerdict {
    /// True when every interface verified.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub reason: String,
    /// True when evidence was unreadable.
    pub unknown: bool,
    /// Machine reason class; empty when ok or unclassified.
    pub code: String,
    /// One line per checked 0.1.2 layout item.
    pub evidence: Vec<String>,
}

/// One refusal verdict: not ok, known, with the reason.
fn live_refuse(reason: String) -> LiveVerdict {
    LiveVerdict {
        ok: false,
        reason,
        unknown: false,
        code: String::new(),
        evidence: Vec::new(),
    }
}

/// One unknown verdict: unreadable evidence, with the reason.
fn live_unknown(reason: String) -> LiveVerdict {
    LiveVerdict {
        ok: false,
        reason,
        unknown: true,
        code: String::new(),
        evidence: Vec::new(),
    }
}

/// One coded refusal verdict: not ok, known, with the code.
fn live_refuse_code(reason: String, code: &str) -> LiveVerdict {
    LiveVerdict {
        ok: false,
        reason,
        unknown: false,
        code: code.to_string(),
        evidence: Vec::new(),
    }
}

/// One coded unknown verdict: unreadable evidence, with the code.
fn live_unknown_code(reason: String, code: &str) -> LiveVerdict {
    LiveVerdict {
        ok: false,
        reason,
        unknown: true,
        code: code.to_string(),
        evidence: Vec::new(),
    }
}

/// Read host BTF with absent/denied tri-state.
///
/// Ok verdict carries the bytes in `btf`; anything else
/// carries the failure verdict. Absence refuses (a BTF-less
/// kernel cannot serve tracing), denial reports unknown,
/// and bytes failing the health check report unknown
/// with the health code.
fn read_live_btf(reader: &EvidenceReader, btf: &mut Vec<u8>) -> LiveVerdict {
    let st = file_state(reader, "/sys/kernel/btf/vmlinux");
    if st == EVIDENCE_ABSENT {
        return live_refuse_code(
            "BTF absent (kernel built without BTF)".to_string(),
            "btf-absent-unknown",
        );
    }
    if st == EVIDENCE_DENIED {
        return live_unknown_code("BTF denied (privilege)".to_string(), "btf-denied");
    }
    match read_host_file(
        &join_root(&reader.root, "/sys/kernel/btf/vmlinux"),
        "btf",
        MAX_NARROW_BTF_BYTES,
    ) {
        Ok(bytes) => *btf = bytes,
        Err(e) => {
            if e.code == E_TOO_BIG {
                return live_unknown_code(
                    format!("BTF too large (over {} bytes)", MAX_NARROW_BTF_BYTES),
                    "btf-too-large",
                );
            }
            return live_unknown_code(format!("BTF unreadable: {e}"), "btf-unreadable");
        }
    }
    let health = check_btf_health(btf);
    if !health.ok {
        return live_unknown_code(health.message.clone(), &health.code);
    }
    LiveVerdict {
        ok: true,
        ..LiveVerdict::default()
    }
}

/// True when sym is a dotted compiler clone of function.
///
/// Only .isra, .constprop, and .cold clones count; any
/// other dotted name is a different symbol.
fn kallsyms_clone(sym: &str, function: &str) -> bool {
    let prefix = format!("{function}.");
    if !sym.starts_with(&prefix) {
        return false;
    }
    let rest = &sym[prefix.len()..];
    if rest == "isra" || rest.starts_with("isra.") {
        return true;
    }
    if rest == "constprop" || rest.starts_with("constprop.") {
        return true;
    }
    if rest == "cold" || rest.starts_with("cold.") {
        return true;
    }
    false
}

/// The kallsyms name: cut a tab-suffixed module owner.
///
/// Core symbols stand alone; module symbols append a
/// tab and [owner] that never compares with the hook.
fn kallsyms_symbol(field: &str) -> String {
    match field.find('\t') {
        Some(i) => field[..i].to_string(),
        None => field.to_string(),
    }
}

/// Split a BTF-missing FUNC by /proc/kallsyms evidence.
///
/// A symbol a readable listing exports but BTF lacks is
/// not in BTF (naming the match); a symbol a readable
/// listing lacks is absent from this kernel. Absent,
/// denied, or unreadable kallsyms cannot arbitrate, so
/// it keeps the BTF verdict with a missing code.
fn live_kallsyms_split(reader: &EvidenceReader, hook: &str, function: &str) -> LiveVerdict {
    let base = format!("{hook}: function {function} not found");
    if file_state(reader, "/proc/kallsyms") != EVIDENCE_OK {
        return live_refuse_code(base, "btf-hook-missing");
    }
    let text = match read_evidence(reader, "/proc/kallsyms", MAX_KALLSYMS_BYTES) {
        Ok(raw) => bytes_to_text(&raw),
        Err(_) => return live_refuse_code(base, "btf-hook-missing"),
    };
    let mut clone = String::new();
    for line in text.split('\n') {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 3 {
            continue;
        }
        let sym = kallsyms_symbol(fields[2]);
        if sym == function {
            return live_refuse_code(
                format!("{hook}: function {function} present but not in BTF ({sym})"),
                "btf-hook-not-in-btf",
            );
        }
        if clone.is_empty() && kallsyms_clone(&sym, function) {
            clone = sym;
        }
    }
    if !clone.is_empty() {
        return live_refuse_code(
            format!("{hook}: function {function} present but not in BTF ({clone})"),
            "btf-hook-not-in-btf",
        );
    }
    live_refuse_code(
        format!("{hook}: function {function} absent from this kernel"),
        "btf-hook-absent",
    )
}

/// One item's display name: S.F, or S for a type target.
fn layout_display(item: &ProfileLayout) -> String {
    if item.target == "type" {
        return item.struct_name.clone();
    }
    format!("{}.{}", item.struct_name, item.field_name)
}

/// One reader-failure verdict: unknown, coded when structural.
fn core_reader_unknown(disp: String, message: &str) -> LiveVerdict {
    let scode = classify_btf_message(message);
    let why = format!("{disp}: {message}");
    if !scode.is_empty() {
        return live_unknown_code(why, &scode);
    }
    live_unknown(why)
}

/// Map one 0.1.2 resolution to its verdict.
///
/// Refusals and unknowns return directly; an ok verdict
/// means the item passed (its evidence line is already
/// appended) and the caller continues. Offsets print as
/// evidence only, never compare. A skipped size (a
/// struct or union type item, relocated by CO-RE)
/// prints the live size as evidence, never compares.
#[allow(clippy::too_many_arguments)]
fn core_apply_resolved(
    disp: String,
    r: &BtfResolved,
    want_kind: &str,
    want_size: i64,
    optional: bool,
    evidence: &mut Vec<String>,
    show_offset: bool,
    skip_size: bool,
) -> LiveVerdict {
    if r.ambiguous {
        return live_refuse_code(r.message.clone(), "layout-ambiguous");
    }
    if !r.ok {
        return core_reader_unknown(disp, &r.message);
    }
    if !r.found {
        if optional {
            evidence.push(format!("{disp}: absent (optional)"));
            return LiveVerdict {
                ok: true,
                ..LiveVerdict::default()
            };
        }
        return live_refuse_code(
            format!("layout: {disp} absent from kernel BTF"),
            "layout-missing",
        );
    }
    if r.bitfield {
        return live_refuse_code(
            format!("layout: {disp} is a bitfield (unsupported)"),
            "layout-bitfield",
        );
    }
    if r.kind != want_kind {
        return live_refuse_code(
            format!(
                "layout: {disp} kind {} differs from object kind {want_kind}",
                r.kind
            ),
            "layout-kind",
        );
    }
    if r.bit_size != want_size && !skip_size {
        return live_refuse_code(
            format!(
                "layout: {disp} size {} bits differs from object size {want_size} bits",
                r.bit_size
            ),
            "layout-size",
        );
    }
    if show_offset {
        evidence.push(format!(
            "{disp}: offset {} bits, size {} bits",
            r.bit_offset, r.bit_size
        ));
    } else {
        evidence.push(format!("{disp}: size {} bits", r.bit_size));
    }
    LiveVerdict {
        ok: true,
        ..LiveVerdict::default()
    }
}

/// Check one capability's 0.1.2 layouts against raw BTF.
///
/// Every item naming `cap_id` resolves through the
/// raw BTF reader: missing, bitfield, kind, size, and
/// ambiguity outcomes refuse with their layout code, a
/// broken blob is unknown with its health code, and an
/// absent optional item appends a note. A struct or
/// union type item skips the size compare (CO-RE
/// relocates it); its live size prints as evidence.
/// Success appends one evidence line per item; offsets
/// never compare.
pub fn verify_core_layouts(
    btf: &[u8],
    layouts: &[ProfileLayout],
    cap_id: &str,
    evidence: &mut Vec<String>,
) -> LiveVerdict {
    for item in layouts {
        if item.capability != cap_id {
            continue;
        }
        let disp = layout_display(item);
        if item.target == "type" {
            let mut agreed_kind = String::new();
            let mut agreed_size: i64 = 0;
            let mut nfound = 0;
            let mut disagree = false;
            for wi in 0..4 {
                let want = match wi {
                    1 => "union",
                    2 => "enum",
                    3 => "typedef",
                    _ => "struct",
                };
                let r = resolve_btf_type(btf, &item.struct_name, want);
                if r.ambiguous {
                    return live_refuse_code(r.message.clone(), "layout-ambiguous");
                }
                if !r.ok {
                    return core_reader_unknown(disp, &r.message);
                }
                if r.found {
                    nfound += 1;
                    if nfound == 1 {
                        agreed_kind = r.kind.clone();
                        agreed_size = r.bit_size;
                    } else if r.kind != agreed_kind || r.bit_size != agreed_size {
                        disagree = true;
                    }
                }
            }
            if disagree {
                return live_refuse_code(
                    format!("type {}: {nfound} definitions disagree", item.struct_name),
                    "layout-ambiguous",
                );
            }
            // The agreed resolution: found iff any kind hit.
            // kind/size hold the agreed values (zeros/"" when
            // nothing resolved, which the missing path reports).
            let agreed = BtfResolved {
                ok: true,
                struct_found: nfound >= 1,
                found: nfound >= 1,
                ambiguous: false,
                bitfield: false,
                bit_offset: 0,
                bit_size: agreed_size,
                kind: agreed_kind,
                message: String::new(),
            };
            let skip = item.type_kind == "struct" || item.type_kind == "union";
            let v = core_apply_resolved(
                disp,
                &agreed,
                &item.type_kind,
                item.bit_size,
                item.optional,
                evidence,
                false,
                skip,
            );
            if !v.ok {
                return v;
            }
        } else {
            let r = if item.target == "enumerator" {
                resolve_btf_enumerator(btf, &item.struct_name, &item.field_name)
            } else {
                resolve_btf_member(btf, &item.struct_name, &item.field_name)
            };
            let v = core_apply_resolved(
                disp,
                &r,
                &item.type_kind,
                item.bit_size,
                item.optional,
                evidence,
                item.target != "enumerator",
                false,
            );
            if !v.ok {
                return v;
            }
        }
    }
    LiveVerdict {
        ok: true,
        ..LiveVerdict::default()
    }
}

/// Verify one capability's live interfaces under reader.
///
/// Reads host BTF only when a tracing hook or a copy
/// layout needs it, then checks the capability's
/// declared hooks against the live kernel: the first
/// tracepoint-kind hook's format must read and its
/// layout must probe (offsets are probed live, never
/// pinned against recorded text; the id file is
/// best-effort, mirroring record, which never reads it),
/// every tracing hook's
/// frozen signature (or any recorded alternate) must
/// spell exactly the live BTF prototype, copy-actual
/// also checks every recorded member layout against the
/// same BTF bytes (a 0.1.2 doc instead checks kind and
/// size for the items naming this capability, except a
/// struct or union type size, which CO-RE relocates), a present
/// kernel.ftrace_enabled
/// must read 1 (absent draws no conclusion),
/// and every traced function must match exactly one
/// available_filter_functions first token (read under
/// the probed tracefs root; none or several refuse). A
/// capability naming no tracepoint hook falls back to
/// the doc's first tracepoint site only for
/// attempt-trace, one with no tracing hooks skips the
/// filter list, and only copy-actual checks member
/// layouts, so tracing-only caps never depend on
/// tracefs layout and tracepoint-only caps never depend
/// on ftrace. Never fails: unreadable evidence reports
/// unknown, everything else reports its own refusal.
pub fn verify_live_cap(reader: &EvidenceReader, profile: &Profile, cap_id: &str) -> LiveVerdict {
    let mut cap: Option<&ProfileCapability> = None;
    for c in &profile.caps {
        if c.id == cap_id {
            cap = Some(c);
            break;
        }
    }
    let Some(cap) = cap else {
        return live_refuse(format!("{cap_id}: capability not declared"));
    };
    let mut btf: Vec<u8> = Vec::new();
    let mut site: Option<&ProfileHook> = None;
    for name in &cap.hooks {
        for h in &profile.hooks {
            if &h.name == name {
                if h.kind == "tracepoint" {
                    site = Some(h);
                }
                break;
            }
        }
        if site.is_some() {
            break;
        }
    }
    if site.is_none() && cap_id == "attempt-trace" {
        // Mirror select_attempt_hook: attempt-trace naming
        // no tracepoint hook still proves the doc's first
        // tracepoint site when the doc carries one.
        // Tracing-only capabilities never fall back: they
        // must not depend on tracefs layout.
        for h in &profile.hooks {
            if h.kind == "tracepoint" {
                site = Some(h);
                break;
            }
        }
    }
    if let Some(site) = site {
        let tprobe = probe_tracefs(reader);
        let id_probe = tracefs_translate(&tprobe, &site.id_path);
        let fmt_probe = tracefs_translate(&tprobe, &site.format_path);
        let _ = read_host_file(
            &join_root(&reader.root, &id_probe),
            "id",
            MAX_NARROW_FORMAT_BYTES,
        );
        let fstate = file_state(reader, &fmt_probe);
        if fstate == EVIDENCE_ABSENT {
            return live_refuse(format!("tracepoint {} absent", site.name));
        }
        if fstate == EVIDENCE_DENIED {
            return live_unknown(format!("tracepoint {} denied (privilege)", site.name));
        }
        let form = match read_host_file(
            &join_root(&reader.root, &fmt_probe),
            "format",
            MAX_NARROW_FORMAT_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                return live_unknown(format!("tracepoint {} unreadable: {e}", site.name));
            }
        };
        let probe = probe_trace_offsets(&form);
        if !probe.ok {
            return live_refuse(format!("layout: {}", probe.message));
        }
    }
    let mut needs_btf = false;
    for name in &cap.hooks {
        for h in &profile.hooks {
            if &h.name == name {
                if h.kind == "tracing" {
                    needs_btf = true;
                }
                break;
            }
        }
        if needs_btf {
            break;
        }
    }
    if cap_id == COPY_CAP_ID && !profile.layouts.is_empty() {
        needs_btf = true;
    }
    for l in &profile.layouts {
        if l.v012 && l.capability == cap_id {
            needs_btf = true;
            break;
        }
    }
    if needs_btf {
        let bread = read_live_btf(reader, &mut btf);
        if !bread.ok {
            return bread;
        }
    }
    let mut want_names: Vec<&str> = Vec::new();
    let mut want_fns: Vec<&str> = Vec::new();
    for name in &cap.hooks {
        let mut hook: Option<&ProfileHook> = None;
        for h in &profile.hooks {
            if &h.name == name {
                hook = Some(h);
                break;
            }
        }
        let Some(hook) = hook else {
            return live_refuse(format!("{}: hook {name} missing", cap.id));
        };
        if hook.kind != "tracing" {
            continue;
        }
        let fsig = frozen_sig_types(&hook.signature, &hook.function);
        if !fsig.has {
            return live_refuse(format!("{}: frozen signature malformed", hook.name));
        }
        let mut alts: Vec<FrozenSig> = Vec::new();
        for a in &hook.signature_alt {
            let an = frozen_sig_types(a, &hook.function);
            if !an.has {
                return live_refuse(format!("{}: frozen signature_alt malformed", hook.name));
            }
            alts.push(an);
        }
        let sig = read_btf_func_sig(&btf, &hook.function);
        if !sig.ok {
            let scode = classify_btf_message(&sig.message);
            if !scode.is_empty() {
                return live_unknown_code(format!("{}: {}", hook.name, sig.message), &scode);
            }
            let missing = format!("function {} not found", hook.function);
            if sig.message == missing {
                return live_kallsyms_split(reader, &hook.name, &hook.function);
            }
            return live_refuse(format!("{}: {}", hook.name, sig.message));
        }
        let wref = sig_width_refusal(&hook.name, &sig);
        if !wref.is_empty() {
            return live_refuse_code(wref, "signature-width");
        }
        let mut hit = sig_types_equal(&sig, &fsig);
        for a in &alts {
            if sig_types_equal(&sig, a) {
                hit = true;
                break;
            }
        }
        if !hit {
            let mut suffix = String::new();
            let plive = read_btf_func_proto(&btf, &hook.function);
            if plive.ok {
                suffix = format!(" (live: {})", plive.canonical);
            }
            return live_refuse_code(
                format!("{}: signature mismatch{suffix}", hook.name),
                "signature-mismatch",
            );
        }
        want_names.push(&hook.name);
        want_fns.push(&hook.function);
    }
    let mut layout_lines: Vec<String> = Vec::new();
    if profile.schema_version == "0.1.2" {
        let mut core = verify_core_layouts(&btf, &profile.layouts, cap_id, &mut layout_lines);
        if !core.ok {
            core.evidence = layout_lines;
            return core;
        }
    } else if cap_id == COPY_CAP_ID {
        for lay in &profile.layouts {
            let m = read_btf_member(&btf, &lay.struct_name, &lay.field_name);
            if !m.ok {
                let why = format!("{}.{}: {}", lay.struct_name, lay.field_name, m.message);
                let scode = classify_btf_message(&m.message);
                if !scode.is_empty() {
                    return live_unknown_code(why, &scode);
                }
                return live_refuse(why);
            }
            if m.bit_offset != lay.bit_offset || m.bit_size != lay.bit_size {
                return live_refuse(format!(
                    "{}.{}: layout mismatch (live offset {} size {})",
                    lay.struct_name, lay.field_name, m.bit_offset, m.bit_size
                ));
            }
        }
    }
    if !want_fns.is_empty() {
        let fstate = read_ftrace_enabled(reader);
        if fstate.value == "0" {
            return live_refuse_code(
                "kernel.ftrace_enabled is 0 (function tracing disabled)".to_string(),
                "ftrace-disabled",
            );
        }
        if fstate.value == "denied" {
            return live_unknown_code("kernel.ftrace_enabled denied".to_string(), "ftrace-unknown");
        }
        if fstate.value == "malformed" {
            return live_unknown_code(
                format!(
                    "kernel.ftrace_enabled unreadable: {}",
                    read_ftrace_text(reader)
                ),
                "ftrace-unknown",
            );
        }
        let tprobe = probe_tracefs(reader);
        let fpath = tracefs_translate(&tprobe, "/sys/kernel/tracing/available_filter_functions");
        let lstate = file_state(reader, &fpath);
        if lstate == EVIDENCE_ABSENT {
            return live_refuse(
                "available_filter_functions absent (kernel built without ftrace)".to_string(),
            );
        }
        if lstate == EVIDENCE_DENIED {
            return live_unknown("available_filter_functions denied (privilege)".to_string());
        }
        let listed = match read_host_file(
            &join_root(&reader.root, &fpath),
            "filter functions",
            MAX_FILTER_FUNCS_BYTES,
        ) {
            Ok(bytes) => bytes,
            Err(e) => {
                return live_unknown(format!("available_filter_functions unreadable: {e}"));
            }
        };
        let text = bytes_to_text(&listed);
        let lines: Vec<&str> = text.split('\n').collect();
        for (i, want_fn) in want_fns.iter().enumerate() {
            let mut count = 0;
            for line in &lines {
                if filter_line_counts(line, want_fn) {
                    count += 1;
                }
            }
            if count == 0 {
                return live_refuse(format!(
                    "{}: function {want_fn} not listed in available_filter_functions",
                    want_names[i]
                ));
            }
            if count >= 2 {
                return live_refuse_code(
                    format!(
                        "{}: hook {want_fn} ambiguous ({count} available_filter_functions lines)",
                        want_names[i]
                    ),
                    "hook-ambiguous",
                );
            }
        }
    }
    LiveVerdict {
        ok: true,
        reason: String::new(),
        unknown: false,
        code: String::new(),
        evidence: layout_lines,
    }
}

/// Verify every named capability's live interfaces under a reader.
///
/// Checks each capability in order; the first refusal or
/// unknown wins. All verified yields ok with an empty
/// reason. Either way the returned verdict carries every
/// checked layout line so far.
pub fn verify_live_interfaces_with_reader(
    reader: &EvidenceReader,
    profile: &Profile,
    caps: &[String],
) -> LiveVerdict {
    let mut lines: Vec<String> = Vec::new();
    for cap in caps {
        let mut v = verify_live_cap(reader, profile, cap);
        for e in v.evidence.drain(..) {
            lines.push(e);
        }
        if !v.ok {
            v.evidence = lines;
            return v;
        }
    }
    LiveVerdict {
        ok: true,
        reason: String::new(),
        unknown: false,
        code: String::new(),
        evidence: lines,
    }
}

/// Verify every named capability's live interfaces from a root path.
///
/// Opens the evidence reader (live host for "", else
/// the fixture's meta, denied list included) and
/// delegates. An unopenable root reports unknown.
pub fn verify_live_interfaces(root: &str, profile: &Profile, caps: &[String]) -> LiveVerdict {
    match open_evidence_reader(root) {
        Ok(reader) => verify_live_interfaces_with_reader(&reader, profile, caps),
        Err(e) => live_unknown(format!("evidence root unusable: {e}")),
    }
}

/// One receipt check: note plus qualified caps on a hit.
///
/// `note` is "" when the receipt verifies and the doc's
/// identity bindings hold; "absent" when no receipt file
/// exists; else "<id> " plus the verify or identity cause.
/// `caps` carries the receipt's qualified ids on a hit
/// and stays empty otherwise.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReceiptHit {
    note: String,
    caps: Vec<String>,
}

/// Comparison key for a profiles dir, or "" when unusable.
///
/// Collapses redundant separators and drops `.`
/// components throughout (interior, trailing, and
/// combined, so `share//memveil/./profiles/` maps),
/// matching how the kernel normalizes the path. Used
/// only to recognize spellings of the installed
/// profiles dir; anything else keeps its byte-identical
/// `<profiles-dir>/receipts` fallback. Never resolves
/// `..`: `profiles/..` names the parent of the
/// installed dir, not the dir itself, and interior
/// `..` (`profiles/../profiles`) is deliberately
/// left unresolved too: lexical `..` resolution is
/// symlink-unsafe, so recognizing such spellings could
/// redirect a non-installed dir into the installed
/// state dir. Those spellings keep the byte-identical
/// fallback, which stays consistent between the
/// receipt write and the later read of the same
/// spelling.
fn installed_profiles_key(profiles_dir: &str) -> String {
    let raw = profiles_dir.as_bytes();
    let absolute = !raw.is_empty() && raw[0] == 0x2F;
    let mut flat: Vec<u8> = Vec::new();
    let mut first = true;
    let mut idx = 0;
    while idx < raw.len() {
        while idx < raw.len() && raw[idx] == 0x2F {
            idx += 1;
        }
        let start = idx;
        while idx < raw.len() && raw[idx] != 0x2F {
            idx += 1;
        }
        if idx == start {
            break;
        }
        let is_dot = idx - start == 1 && raw[start] == 0x2E;
        if is_dot {
            continue;
        }
        if first {
            first = false;
            if absolute {
                flat.push(0x2F);
            }
        } else {
            flat.push(0x2F);
        }
        flat.extend_from_slice(&raw[start..idx]);
    }
    String::from_utf8(flat).unwrap_or_default()
}

/// Receipts dir for a profiles dir.
///
/// The installed profiles dir keeps its receipts in
/// the writable state dir instead of beside the
/// read-only profiles; every other layout (bundle,
/// checkout, explicit override) keeps receipts under
/// `<profiles-dir>/receipts` exactly as before. The
/// comparison normalizes redundant separators and `.`
/// components throughout, so shell-completed or dotted
/// spellings of the installed dir cannot misplace a
/// receipt.
pub fn default_receipts_dir(profiles_dir: &str) -> String {
    if installed_profiles_key(profiles_dir) == INSTALLED_PROFILES_DIR {
        return INSTALLED_RECEIPTS_DIR.to_string();
    }
    format!("{profiles_dir}/receipts")
}

/// Receipt verdict for one covering reference doc.
///
/// A hit (empty note) means the receipt under the
/// receipts dir for pdir verifies against the doc,
/// the live kernel, and the resolved bridge hash, and
/// the doc's identity bindings hold; the caller
/// matches local-auto and keeps the qualified caps
/// for per-capability judging. An empty
/// `bridge_sha` means no bridge binding was
/// performed (the passive path never touches the
/// bridge): receipts then report an explicit
/// unchecked note instead of a mismatch, so the
/// caller never implies a binding that did not
/// happen. Never fails: unreadable files read as
/// absent, and the profile_id grammar admits no path
/// separators so the join cannot escape the dir.
fn check_receipt(
    doc: &Profile,
    kernel: &KernelInfo,
    root: &str,
    zlib: &str,
    pdir: &str,
    bridge_sha: &str,
) -> ReceiptHit {
    let mut out = ReceiptHit::default();
    if pdir.is_empty() {
        out.note = "absent".to_string();
        return out;
    }
    let path = format!("{}/{}.json", default_receipts_dir(pdir), doc.profile_id);
    let raw = match read_host_file(&path, "receipt", PROFILE_CAP) {
        Ok(bytes) => bytes,
        Err(_) => {
            out.note = "absent".to_string();
            return out;
        }
    };
    let noted = doc.identity.source.has_note && parse_narrow_note(&doc.identity.source.note).ok;
    if !noted {
        // A doc with no usable note verifies its receipt
        // against fresh live measurements; the passive
        // path resolves no objects, so artifact hashes are
        // presence-checked only.
        let v = verify_live_receipt(&raw, doc, kernel, bridge_sha, root, zlib, "", "", "");
        if !v.ok {
            if v.bridge_mismatch && bridge_sha.is_empty() {
                out.note = format!(
                    "{} receipt bridge unchecked: no binding performed on this path",
                    doc.profile_id
                );
                return out;
            }
            out.note = format!("{} {}", doc.profile_id, v.message);
            return out;
        }
        out.caps = v.caps;
        return out;
    }
    let v = verify_qualification_receipt(&raw, doc, kernel, bridge_sha);
    if !v.ok {
        if v.bridge_mismatch && bridge_sha.is_empty() {
            out.note = format!(
                "{} receipt bridge unchecked: no binding performed on this path",
                doc.profile_id
            );
            return out;
        }
        out.note = format!("{} {}", doc.profile_id, v.message);
        return out;
    }
    let sel = select_attempt_hook(doc);
    if !sel.ok {
        out.note = format!("{} receipt hook unusable", doc.profile_id);
        return out;
    }
    let b = check_identity_bindings(
        root,
        &kernel.release,
        &doc.identity.source.note,
        zlib,
        &sel.hook.format_path,
    );
    if b.state != "bound" {
        out.note = format!("{} receipt identity {}: {}", doc.profile_id, b.state, b.key);
        return out;
    }
    out.caps = v.caps;
    out
}

/// Match kernel identity, preferring a doc that binds.
///
/// Scans covering validated docs in manifest order and returns
/// the first whose recorded revision equals the running release
/// and whose identity bindings hold against the evidence tree
/// under root. Object and ring bindings stay record-time
/// checks. Otherwise every covering reference doc is tried
/// for a receipt under the receipts dir for pdir
/// verifying against the resolved bridge hash whose
/// identity bindings hold, first hit matching with
/// grade local-auto. An empty
/// bridge hash performs no binding: receipts then carry
/// an explicit unchecked note. With no
/// receipt hit it falls back to the
/// first covering doc of any status: a non-binding
/// validated doc reports its own failing key; other
/// reference cover names its receipt state plus the first
/// validated near-miss (if any) so callers can quote the
/// cause. Never fails: an unparseable release simply
/// covers nothing.
pub fn select_profile_bound(
    kernel: &KernelInfo,
    profiles: &[Profile],
    root: &str,
    zlib: &str,
    pdir: &str,
    bridge_sha: &str,
) -> ProfileDecision {
    if profiles.is_empty() {
        return ProfileDecision {
            matched: false,
            has_profile: false,
            profile: Profile::default(),
            reason: "no profiles admitted".to_string(),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    }
    let triple = parse_kernel_triple(&kernel.release);
    if !triple.ok {
        return ProfileDecision {
            matched: false,
            has_profile: false,
            profile: Profile::default(),
            reason: format!("release {} is unparseable; no coverage", kernel.release),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    }
    let mut near_id = String::new();
    let mut near_state = String::new();
    let mut near_key = String::new();
    for p in profiles {
        if p.status != "validated" {
            continue;
        }
        let mut covered = p.identity.arch == kernel.arch;
        if covered {
            covered = triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                p.identity.min_major,
                p.identity.min_minor,
                p.identity.min_patch,
            );
        }
        if !covered {
            continue;
        }
        let (state, key) = if kernel.release != p.identity.source.revision {
            ("mismatch".to_string(), "revision".to_string())
        } else {
            let sel = select_attempt_hook(p);
            if !sel.ok {
                ("uncheckable".to_string(), "hook".to_string())
            } else {
                let v = check_identity_bindings(
                    root,
                    &kernel.release,
                    &p.identity.source.note,
                    zlib,
                    &sel.hook.format_path,
                );
                (v.state, v.key)
            }
        };
        if state == "bound" {
            return ProfileDecision {
                matched: true,
                has_profile: true,
                profile: p.clone(),
                reason: format!("profile {} matched (validated)", p.profile_id),
                grade: "validated".to_string(),
                receipt_caps: Vec::new(),
            };
        }
        if near_id.is_empty() {
            near_id = p.profile_id.clone();
            near_state = state;
            near_key = key;
        }
    }
    let mut first_cover: Option<usize> = None;
    for (i, p) in profiles.iter().enumerate() {
        let mut covered = p.identity.arch == kernel.arch;
        if covered {
            covered = triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                p.identity.min_major,
                p.identity.min_minor,
                p.identity.min_patch,
            );
        }
        if !covered {
            continue;
        }
        if first_cover.is_none() {
            first_cover = Some(i);
        }
        if p.status == "validated" {
            continue;
        }
        let hit = check_receipt(p, kernel, root, zlib, pdir, bridge_sha);
        if hit.note.is_empty() {
            return ProfileDecision {
                matched: true,
                has_profile: true,
                profile: p.clone(),
                reason: format!("profile {} matched (local-auto)", p.profile_id),
                grade: "local-auto".to_string(),
                receipt_caps: hit.caps,
            };
        }
    }
    let Some(first_cover) = first_cover else {
        return ProfileDecision {
            matched: false,
            has_profile: false,
            profile: Profile::default(),
            reason: format!(
                "no profile covers arch {} release {}",
                kernel.arch, kernel.release
            ),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    };
    let first = &profiles[first_cover];
    if first.status == "validated" {
        return ProfileDecision {
            matched: false,
            has_profile: true,
            profile: first.clone(),
            reason: format!(
                "profile {} covers this identity but identity {near_state}: {near_key}",
                first.profile_id
            ),
            grade: String::new(),
            receipt_caps: Vec::new(),
        };
    }
    let receipt_hit = check_receipt(first, kernel, root, zlib, pdir, bridge_sha);
    let mut reason = format!(
        "profile {} covers this identity but is reference-unvalidated",
        first.profile_id
    );
    if receipt_hit.note != "absent" {
        reason += &format!("; {}", receipt_hit.note);
    }
    if !near_id.is_empty() {
        reason += &format!("; {near_id} identity {near_state}: {near_key}");
    }
    ProfileDecision {
        matched: false,
        has_profile: true,
        profile: first.clone(),
        reason,
        grade: String::new(),
        receipt_caps: Vec::new(),
    }
}

/// One capability result feeding a minted receipt.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapQualification {
    /// Capability id.
    pub id: String,
    /// Qualification detail.
    pub detail: String,
}

impl CapQualification {
    /// Build one capability result.
    pub fn new(id: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            detail: detail.into(),
        }
    }
}

/// Receipt verification: ok plus empty message, else cause.
///
/// `caps` lists the qualified capability ids in receipt
/// order on success and stays empty on any refusal.
/// `bridge_mismatch` is true only when every other check
/// passed and the receipt's bridge hash differs from the
/// resolved bridge, so callers can name the stale bridge
/// in their fallback reason.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReceiptVerdict {
    /// True when the receipt verifies.
    pub ok: bool,
    /// Refusal detail; empty on success.
    pub message: String,
    /// Qualified capability ids in receipt order.
    pub caps: Vec<String>,
    /// True on a pure bridge rotation.
    pub bridge_mismatch: bool,
}

/// Render a local-auto qualification receipt (schema 0.1.0).
///
/// Pure rendering: every input is caller-verified, so minting
/// itself cannot fail. Empty lifecycle/copy object hashes
/// omit those keys.
#[allow(clippy::too_many_arguments)]
pub fn mint_qualification_receipt(
    profile_id: &str,
    kernel: &KernelInfo,
    bind: &NarrowBindings,
    created_ns: u64,
    caps: &[CapQualification],
    memveil: &str,
    bridge: &str,
    obj_attempt: &str,
    obj_lc: &str,
    obj_cp: &str,
    duration_s: u64,
    note: &str,
) -> String {
    let mut out = String::from("{\n");
    out += "\"schema_version\": \"0.1.0\",\n";
    out += "\"kind\": \"memveil-qualification-receipt\",\n";
    out += &format!("\"profile_id\": {},\n", escape_json(profile_id));
    out += "\"grade\": \"local-auto\",\n";
    out += &format!("\"created_ns\": \"{created_ns}\",\n");
    out += &format!(
        "\"kernel\": {{\"arch\": {}, \"release\": {}}},\n",
        escape_json(&kernel.arch),
        escape_json(&kernel.release)
    );
    out += &format!(
        "\"bindings\": {{\"config\": {}, \"config_src\": {}, \"btf\": {}, \
         \"format\": {}, \"image\": {}, \"image_bid\": {}}},\n",
        escape_json(&format!("sha256:{}", bind.config)),
        escape_json(&bind.config_src),
        escape_json(&format!("sha256:{}", bind.btf)),
        escape_json(&format!("sha256:{}", bind.format)),
        escape_json(&format!("sha256:{}", bind.image)),
        escape_json(&bind.image_bid),
    );
    out += "\"capabilities\": {";
    for (i, c) in caps.iter().enumerate() {
        if i > 0 {
            out += ", ";
        }
        out += &format!(
            "{}: {{\"status\": \"qualified\", \"detail\": {}}}",
            escape_json(&c.id),
            escape_json(&c.detail)
        );
    }
    out += "},\n";
    out += &format!(
        "\"artifacts\": {{\"memveil\": {}, \"bridge\": {}, \
         \"objects\": {{\"attempt\": {}",
        escape_json(memveil),
        escape_json(bridge),
        escape_json(obj_attempt),
    );
    if !obj_lc.is_empty() {
        out += &format!(", \"lifecycle\": {}", escape_json(obj_lc));
    }
    if !obj_cp.is_empty() {
        out += &format!(", \"copy\": {}", escape_json(obj_cp));
    }
    out += "}},\n";
    out += &format!(
        "\"workload\": {{\"kind\": \"smoke\", \"duration_s\": \"{duration_s}\", \
         \"traffic_required\": false, \"note\": {}}}\n}}\n",
        escape_json(note)
    );
    out
}

/// Parsed receipt fields (valid only past the const checks).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReceiptData {
    profile_id: String,
    arch: String,
    release: String,
    config: String,
    config_src: String,
    btf: String,
    format: String,
    image: String,
    image_bid: String,
    cap_count: usize,
    cap_ids: Vec<String>,
    bridge: String,
    obj_attempt: String,
    obj_lc: String,
    obj_cp: String,
}

/// Parse receipt.kernel: arch, release.
fn parse_receipt_kernel(
    scan: &mut Scanner<'_>,
    rec: &mut ReceiptData,
) -> Result<(), ValidationError> {
    scan.begin_object("receipt.kernel")?;
    let mut has_arch = false;
    let mut has_release = false;
    if !object_is_empty(scan, "receipt.kernel")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("receipt.kernel")?;
            expect_colon(scan, "receipt.kernel")?;
            if key == "arch" {
                if has_arch {
                    return Err(ValidationError::new("receipt.kernel", "duplicate"));
                }
                let v = scan.parse_string("receipt.kernel.arch")?;
                bounded(&v, 1, 32, "receipt.kernel.arch")?;
                rec.arch = v;
                has_arch = true;
            } else if key == "release" {
                if has_release {
                    return Err(ValidationError::new("receipt.kernel", "duplicate"));
                }
                let v = scan.parse_string("receipt.kernel.release")?;
                bounded(&v, 1, 128, "receipt.kernel.release")?;
                rec.release = v;
                has_release = true;
            } else {
                return Err(ValidationError::new("receipt.kernel", "unknown field"));
            }
            if !object_next(scan, "receipt.kernel")? {
                break;
            }
        }
    }
    scan.end_object("receipt.kernel")?;
    if !has_arch || !has_release {
        return Err(ValidationError::new("receipt.kernel", "missing field"));
    }
    Ok(())
}

/// Strip a sha256: scheme, requiring 64 following bytes.
fn strip_sha256(v: &str, what: &str) -> Result<String, ValidationError> {
    let raw = v.as_bytes();
    if raw.len() != 71 {
        return Err(ValidationError::new(what, "bad sha256 value"));
    }
    if &raw[0..7] != b"sha256:" {
        return Err(ValidationError::new(what, "bad sha256 value"));
    }
    Ok(bytes_to_text(&raw[7..]))
}

/// Parse receipt.bindings: six identity values.
fn parse_receipt_bindings(
    scan: &mut Scanner<'_>,
    rec: &mut ReceiptData,
) -> Result<(), ValidationError> {
    scan.begin_object("receipt.bindings")?;
    let mut seen = [false; 6];
    if !object_is_empty(scan, "receipt.bindings")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("receipt.bindings")?;
            expect_colon(scan, "receipt.bindings")?;
            let idx = if key == "config" {
                0
            } else if key == "config_src" {
                1
            } else if key == "btf" {
                2
            } else if key == "format" {
                3
            } else if key == "image" {
                4
            } else if key == "image_bid" {
                5
            } else {
                return Err(ValidationError::new("receipt.bindings", "unknown field"));
            };
            if seen[idx] {
                return Err(ValidationError::new("receipt.bindings", "duplicate"));
            }
            let v = scan.parse_string("receipt.bindings")?;
            let bound = if idx == 1 {
                4
            } else if idx == 5 {
                64
            } else {
                71
            };
            bounded(&v, 1, bound, "receipt.bindings")?;
            // Hash bindings carry the sha256: scheme on the
            // wire; the note grammar stores bare hex, so strip
            // before comparing.
            if idx == 0 {
                rec.config = strip_sha256(&v, "receipt.bindings")?;
            } else if idx == 1 {
                rec.config_src = v;
            } else if idx == 2 {
                rec.btf = strip_sha256(&v, "receipt.bindings")?;
            } else if idx == 3 {
                rec.format = strip_sha256(&v, "receipt.bindings")?;
            } else if idx == 4 {
                rec.image = strip_sha256(&v, "receipt.bindings")?;
            } else {
                rec.image_bid = v;
            }
            seen[idx] = true;
            if !object_next(scan, "receipt.bindings")? {
                break;
            }
        }
    }
    scan.end_object("receipt.bindings")?;
    for s in &seen {
        if !s {
            return Err(ValidationError::new("receipt.bindings", "missing field"));
        }
    }
    Ok(())
}

/// Parse receipt.capabilities: at least one qualified entry.
fn parse_receipt_capabilities(
    scan: &mut Scanner<'_>,
    rec: &mut ReceiptData,
) -> Result<(), ValidationError> {
    scan.begin_object("receipt.capabilities")?;
    let mut count = 0;
    if !object_is_empty(scan, "receipt.capabilities")? {
        loop {
            scan.skip_ws();
            let cid = scan.parse_string("receipt.capabilities")?;
            bounded(&cid, 1, 64, "receipt.capabilities")?;
            if count >= MAX_PROFILE_CAPS {
                return Err(ValidationError::new("receipt.capabilities", "too many"));
            }
            expect_colon(scan, "receipt.capabilities")?;
            scan.begin_object("receipt.capability")?;
            let mut has_status = false;
            let mut has_detail = false;
            if !object_is_empty(scan, "receipt.capability")? {
                loop {
                    scan.skip_ws();
                    let key = scan.parse_string("receipt.capability")?;
                    expect_colon(scan, "receipt.capability")?;
                    if key == "status" {
                        if has_status {
                            return Err(ValidationError::new("receipt.capability", "duplicate"));
                        }
                        let v = scan.parse_string("receipt.capability")?;
                        if v != "qualified" {
                            return Err(ValidationError::new(
                                "receipt.capability",
                                "status is not qualified",
                            ));
                        }
                        has_status = true;
                    } else if key == "detail" {
                        if has_detail {
                            return Err(ValidationError::new("receipt.capability", "duplicate"));
                        }
                        let v = scan.parse_string("receipt.capability.detail")?;
                        bounded(&v, 1, 1024, "receipt.capability.detail")?;
                        has_detail = true;
                    } else {
                        return Err(ValidationError::new("receipt.capability", "unknown field"));
                    }
                    if !object_next(scan, "receipt.capability")? {
                        break;
                    }
                }
            }
            scan.end_object("receipt.capability")?;
            if !has_status || !has_detail {
                return Err(ValidationError::new("receipt.capability", "missing field"));
            }
            rec.cap_ids.push(cid);
            count += 1;
            if !object_next(scan, "receipt.capabilities")? {
                break;
            }
        }
    }
    scan.end_object("receipt.capabilities")?;
    if count == 0 {
        return Err(ValidationError::new("receipt.capabilities", "empty"));
    }
    rec.cap_count = count;
    Ok(())
}

/// Parse one string field that must equal want exactly.
fn parse_receipt_const_str(
    scan: &mut Scanner<'_>,
    want: &str,
    what: &str,
) -> Result<(), ValidationError> {
    let v = scan.parse_string(what)?;
    if v != want {
        return Err(ValidationError::new(what, "unexpected value"));
    }
    Ok(())
}

/// Parse receipt.artifacts.objects: attempt plus extras.
fn parse_receipt_objects(
    scan: &mut Scanner<'_>,
    rec: &mut ReceiptData,
) -> Result<(), ValidationError> {
    scan.begin_object("receipt.artifacts.objects")?;
    let mut has_attempt = false;
    let mut has_lc = false;
    let mut has_cp = false;
    if !object_is_empty(scan, "receipt.artifacts.objects")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("receipt.artifacts.objects")?;
            expect_colon(scan, "receipt.artifacts.objects")?;
            if key == "attempt" {
                if has_attempt {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("receipt.artifacts.objects")?;
                if !is_sha256_value(&v) {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "bad sha256 value",
                    ));
                }
                rec.obj_attempt = strip_sha256(&v, "receipt.artifacts.objects")?;
                has_attempt = true;
            } else if key == "lifecycle" {
                if has_lc {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("receipt.artifacts.objects")?;
                if !is_sha256_value(&v) {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "bad sha256 value",
                    ));
                }
                rec.obj_lc = strip_sha256(&v, "receipt.artifacts.objects")?;
                has_lc = true;
            } else if key == "copy" {
                if has_cp {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("receipt.artifacts.objects")?;
                if !is_sha256_value(&v) {
                    return Err(ValidationError::new(
                        "receipt.artifacts.objects",
                        "bad sha256 value",
                    ));
                }
                rec.obj_cp = strip_sha256(&v, "receipt.artifacts.objects")?;
                has_cp = true;
            } else {
                return Err(ValidationError::new(
                    "receipt.artifacts.objects",
                    "unknown field",
                ));
            }
            if !object_next(scan, "receipt.artifacts.objects")? {
                break;
            }
        }
    }
    scan.end_object("receipt.artifacts.objects")?;
    if !has_attempt {
        return Err(ValidationError::new(
            "receipt.artifacts.objects",
            "missing field",
        ));
    }
    Ok(())
}

/// Parse receipt.artifacts: version, bridge, object hashes.
fn parse_receipt_artifacts(
    scan: &mut Scanner<'_>,
    rec: &mut ReceiptData,
) -> Result<(), ValidationError> {
    scan.begin_object("receipt.artifacts")?;
    let mut has_memveil = false;
    let mut has_bridge = false;
    let mut has_objects = false;
    if !object_is_empty(scan, "receipt.artifacts")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("receipt.artifacts")?;
            expect_colon(scan, "receipt.artifacts")?;
            if key == "memveil" {
                if has_memveil {
                    return Err(ValidationError::new("receipt.artifacts", "duplicate"));
                }
                let v = scan.parse_string("receipt.artifacts.memveil")?;
                bounded(&v, 1, 64, "receipt.artifacts.memveil")?;
                has_memveil = true;
            } else if key == "bridge" {
                if has_bridge {
                    return Err(ValidationError::new("receipt.artifacts", "duplicate"));
                }
                let v = scan.parse_string("receipt.artifacts")?;
                if !is_sha256_value(&v) {
                    return Err(ValidationError::new(
                        "receipt.artifacts",
                        "bad sha256 value",
                    ));
                }
                rec.bridge = strip_sha256(&v, "receipt.artifacts")?;
                has_bridge = true;
            } else if key == "objects" {
                if has_objects {
                    return Err(ValidationError::new("receipt.artifacts", "duplicate"));
                }
                parse_receipt_objects(scan, rec)?;
                has_objects = true;
            } else {
                return Err(ValidationError::new("receipt.artifacts", "unknown field"));
            }
            if !object_next(scan, "receipt.artifacts")? {
                break;
            }
        }
    }
    scan.end_object("receipt.artifacts")?;
    if !has_memveil || !has_bridge || !has_objects {
        return Err(ValidationError::new("receipt.artifacts", "missing field"));
    }
    Ok(())
}

/// Parse receipt.workload: the smoke that minted this.
fn parse_receipt_workload(scan: &mut Scanner<'_>) -> Result<(), ValidationError> {
    scan.begin_object("receipt.workload")?;
    let mut has_kind = false;
    let mut has_duration = false;
    let mut has_traffic = false;
    let mut has_note = false;
    if !object_is_empty(scan, "receipt.workload")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("receipt.workload")?;
            expect_colon(scan, "receipt.workload")?;
            if key == "kind" {
                if has_kind {
                    return Err(ValidationError::new("receipt.workload", "duplicate"));
                }
                parse_receipt_const_str(scan, "smoke", "receipt.workload.kind")?;
                has_kind = true;
            } else if key == "duration_s" {
                if has_duration {
                    return Err(ValidationError::new("receipt.workload", "duplicate"));
                }
                let _ = parse_u64_field(scan, "receipt.workload.duration_s")?;
                has_duration = true;
            } else if key == "traffic_required" {
                if has_traffic {
                    return Err(ValidationError::new("receipt.workload", "duplicate"));
                }
                if scan.parse_bool("receipt.workload.traffic_required")? {
                    return Err(ValidationError::new(
                        "receipt.workload.traffic_required",
                        "must be false",
                    ));
                }
                has_traffic = true;
            } else if key == "note" {
                if has_note {
                    return Err(ValidationError::new("receipt.workload", "duplicate"));
                }
                let v = scan.parse_string("receipt.workload.note")?;
                bounded(&v, 1, 512, "receipt.workload.note")?;
                has_note = true;
            } else {
                return Err(ValidationError::new("receipt.workload", "unknown field"));
            }
            if !object_next(scan, "receipt.workload")? {
                break;
            }
        }
    }
    scan.end_object("receipt.workload")?;
    if !has_kind || !has_duration || !has_traffic || !has_note {
        return Err(ValidationError::new("receipt.workload", "missing field"));
    }
    Ok(())
}

/// Parsed receipt bytes: ok plus fields, else the cause.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ReceiptParse {
    ok: bool,
    message: String,
    rec: ReceiptData,
}

/// Parse one receipt blob with no trailing data.
///
/// Shared by the exact and live verifiers so both
/// enforce the same schema, grade, and field grammar.
/// JSON consumption validation finishes before any
/// binding or bridge comparison.
fn parse_receipt_data(data: &[u8]) -> ReceiptParse {
    let mut out = ReceiptParse::default();
    let parsed: Result<ReceiptData, ValidationError> = (|| {
        let text = bytes_to_text(data);
        let mut scan = Scanner::new(text.as_bytes());
        scan.begin_object("receipt")?;
        let mut rec = ReceiptData::default();
        let mut seen = [false; 10];
        if !object_is_empty(&mut scan, "receipt")? {
            loop {
                scan.skip_ws();
                let key = scan.parse_string("receipt")?;
                expect_colon(&mut scan, "receipt")?;
                if key == "schema_version" {
                    if seen[0] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_const_str(&mut scan, "0.1.0", "receipt.schema_version")?;
                    seen[0] = true;
                } else if key == "kind" {
                    if seen[1] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_const_str(
                        &mut scan,
                        "memveil-qualification-receipt",
                        "receipt.kind",
                    )?;
                    seen[1] = true;
                } else if key == "profile_id" {
                    if seen[2] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    let v = scan.parse_string("receipt.profile_id")?;
                    bounded(&v, 1, 128, "receipt.profile_id")?;
                    rec.profile_id = v;
                    seen[2] = true;
                } else if key == "grade" {
                    if seen[3] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_const_str(&mut scan, "local-auto", "receipt.grade")?;
                    seen[3] = true;
                } else if key == "created_ns" {
                    if seen[4] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    let _ = parse_u64_field(&mut scan, "receipt.created_ns")?;
                    seen[4] = true;
                } else if key == "kernel" {
                    if seen[5] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_kernel(&mut scan, &mut rec)?;
                    seen[5] = true;
                } else if key == "bindings" {
                    if seen[6] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_bindings(&mut scan, &mut rec)?;
                    seen[6] = true;
                } else if key == "capabilities" {
                    if seen[7] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_capabilities(&mut scan, &mut rec)?;
                    seen[7] = true;
                } else if key == "artifacts" {
                    if seen[8] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_artifacts(&mut scan, &mut rec)?;
                    seen[8] = true;
                } else if key == "workload" {
                    if seen[9] {
                        return Err(ValidationError::new("receipt", "duplicate"));
                    }
                    parse_receipt_workload(&mut scan)?;
                    seen[9] = true;
                } else {
                    return Err(ValidationError::new("receipt", "unknown field"));
                }
                if !object_next(&mut scan, "receipt")? {
                    break;
                }
            }
        }
        scan.end_object("receipt")?;
        for s in &seen {
            if !s {
                return Err(ValidationError::new("receipt", "missing field"));
            }
        }
        scan.skip_ws();
        if !scan.at_end() {
            return Err(ValidationError::new("receipt", "trailing data"));
        }
        Ok(rec)
    })();
    match parsed {
        Ok(rec) => {
            out.ok = true;
            out.rec = rec;
            out.message = String::new();
        }
        Err(e) => {
            out.message = format!("receipt unparseable: {e}");
        }
    }
    out
}

/// Verify a receipt against its document and the live kernel.
///
/// The receipt must parse with no trailing data, carry
/// schema 0.1.0 and grade local-auto for this document,
/// name this kernel, and repeat the document note's
/// identity bindings exactly. The kernel must also equal
/// the document revision, and every object hash the
/// receipt claims must equal the note's binding, so an
/// updated document or object cannot inherit an old
/// receipt. `bridge_sha` is the bare hex sha256 of the
/// currently-resolved bridge ("" when unresolvable);
/// the receipt's bridge hash must equal it, so a receipt
/// minted for one bridge cannot admit another. The
/// bridge compares last, after document and object
/// drift, so a pure bridge rotation names the bridge.
/// At least one capability must qualify; the workload
/// is shape-checked audit context. Never fails.
pub fn verify_qualification_receipt(
    data: &[u8],
    doc: &Profile,
    kernel: &KernelInfo,
    bridge_sha: &str,
) -> ReceiptVerdict {
    let mut out = ReceiptVerdict::default();
    let pre = parse_receipt_data(data);
    if !pre.ok {
        out.message = pre.message;
        return out;
    }
    let rec = pre.rec;
    if rec.profile_id != doc.profile_id {
        out.message = "receipt names another profile".to_string();
        return out;
    }
    if rec.arch != kernel.arch || rec.release != kernel.release {
        out.message = "receipt names another kernel".to_string();
        return out;
    }
    if doc.identity.source.revision != kernel.release {
        out.message = "receipt kernel differs from profile revision".to_string();
        return out;
    }
    let parsed = parse_narrow_note(&doc.identity.source.note);
    if !parsed.ok {
        out.message = "profile note unparseable".to_string();
        return out;
    }
    let bind = parsed.bindings;
    if rec.config != bind.config
        || rec.config_src != bind.config_src
        || rec.btf != bind.btf
        || rec.format != bind.format
        || rec.image != bind.image
        || rec.image_bid != bind.image_bid
    {
        out.message = "receipt bindings differ from note".to_string();
        return out;
    }
    if rec.obj_attempt != bind.object {
        out.message = "receipt artifacts differ from note".to_string();
        return out;
    }
    // Every qualified channel needs its own artifact
    // hash present and matching: a lifecycle-qualified
    // receipt without one would let a changed
    // lifecycle object inherit qualification. Hashes
    // for unqualified channels still compare when
    // present, so a stray wrong hash never verifies.
    let mut qualifies_lc = false;
    let mut qualifies_cp = false;
    for cid in &rec.cap_ids {
        if cid == LIFECYCLE_CAP_ID {
            qualifies_lc = true;
        }
        if cid == COPY_CAP_ID {
            qualifies_cp = true;
        }
    }
    if qualifies_lc && rec.obj_lc.is_empty() {
        out.message = "receipt lacks lifecycle hash for qualified mapping-lifecycle".to_string();
        return out;
    }
    if qualifies_cp && rec.obj_cp.is_empty() {
        out.message = "receipt lacks copy hash for qualified copy-actual".to_string();
        return out;
    }
    if (!rec.obj_lc.is_empty() && rec.obj_lc != bind.lc_object)
        || (!rec.obj_cp.is_empty() && rec.obj_cp != bind.cp_object)
    {
        out.message = "receipt artifacts differ from note".to_string();
        return out;
    }
    if rec.bridge != bridge_sha {
        out.message = "receipt bridge differs from resolved bridge".to_string();
        out.bridge_mismatch = true;
        return out;
    }
    out.caps = rec.cap_ids;
    out.ok = true;
    out.message = String::new();
    out
}

/// Verify a receipt for a doc with no usable narrow note.
///
/// Same schema, grade, profile, kernel, and bridge checks
/// as the exact verifier, but the receipt's identity
/// bindings compare against fresh live measurements under
/// root instead of a note, and the revision check is
/// skipped (a noteless revision is free text; the
/// receipt-kernel check still pins the kernel). Object
/// hashes compare against the given live-resolved shas;
/// an empty live sha skips that comparison (the passive
/// path resolves no objects), while qualified channels
/// still need their receipt hash present. Never fails.
#[allow(clippy::too_many_arguments)]
pub fn verify_live_receipt(
    data: &[u8],
    doc: &Profile,
    kernel: &KernelInfo,
    bridge_sha: &str,
    root: &str,
    zlib: &str,
    obj_attempt: &str,
    obj_lc: &str,
    obj_cp: &str,
) -> ReceiptVerdict {
    let mut out = ReceiptVerdict::default();
    let pre = parse_receipt_data(data);
    if !pre.ok {
        out.message = pre.message;
        return out;
    }
    let rec = pre.rec;
    if rec.profile_id != doc.profile_id {
        out.message = "receipt names another profile".to_string();
        return out;
    }
    if rec.arch != kernel.arch || rec.release != kernel.release {
        out.message = "receipt names another kernel".to_string();
        return out;
    }
    let sel = select_attempt_hook(doc);
    if !sel.ok {
        out.message = sel.refusal;
        return out;
    }
    let mut live = NarrowBindings::new();
    let unmeasured = measure_live_bindings(
        root,
        &kernel.release,
        zlib,
        &sel.hook.format_path,
        &mut live,
    );
    if !unmeasured.is_empty() {
        out.message = unmeasured;
        return out;
    }
    if rec.config != live.config
        || rec.config_src != live.config_src
        || rec.btf != live.btf
        || rec.format != live.format
        || rec.image != live.image
        || rec.image_bid != live.image_bid
    {
        out.message = "receipt bindings differ from live".to_string();
        return out;
    }
    let mut qualifies_lc = false;
    let mut qualifies_cp = false;
    for cid in &rec.cap_ids {
        if cid == LIFECYCLE_CAP_ID {
            qualifies_lc = true;
        }
        if cid == COPY_CAP_ID {
            qualifies_cp = true;
        }
    }
    if qualifies_lc && rec.obj_lc.is_empty() {
        out.message = "receipt lacks lifecycle hash for qualified mapping-lifecycle".to_string();
        return out;
    }
    if qualifies_cp && rec.obj_cp.is_empty() {
        out.message = "receipt lacks copy hash for qualified copy-actual".to_string();
        return out;
    }
    if !obj_attempt.is_empty() && rec.obj_attempt != obj_attempt {
        out.message = "receipt artifacts differ from objects".to_string();
        return out;
    }
    if !obj_lc.is_empty() && !rec.obj_lc.is_empty() && rec.obj_lc != obj_lc {
        out.message = "receipt artifacts differ from objects".to_string();
        return out;
    }
    if !obj_cp.is_empty() && !rec.obj_cp.is_empty() && rec.obj_cp != obj_cp {
        out.message = "receipt artifacts differ from objects".to_string();
        return out;
    }
    if rec.bridge != bridge_sha {
        out.message = "receipt bridge differs from resolved bridge".to_string();
        out.bridge_mismatch = true;
        return out;
    }
    out.caps = rec.cap_ids;
    out.ok = true;
    out.message = String::new();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::evidence::detect_environment;
    use crate::platform::narrow::{measure_live_bindings, parse_narrow_note};
    use crate::platform::reader::{open_evidence_reader, read_host_file};
    use crate::platform::test_support::{capabilities_fixture, gate_fixture, repo_root};

    const MINT_BRIDGE: &str = "5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270";
    const FOREIGN_BRIDGE: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    fn fx(name: &str) -> String {
        capabilities_fixture(name)
    }

    fn profiles_dir() -> String {
        repo_root()
            .join("profiles")
            .to_str()
            .expect("repo path must be UTF-8")
            .to_string()
    }

    fn fixture(path: &str) -> String {
        repo_root()
            .join(path)
            .to_str()
            .expect("repo path must be UTF-8")
            .to_string()
    }

    fn minimal_doc() -> String {
        "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
         \"status\":\"reference-unvalidated\",\"identity\":{\"arch\":\"x86_64\",\
         \"min_kernel\":\"7.0\",\"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
         \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\"id_path\":\"/i\",\
         \"format_path\":\"/f\"}],\"capabilities\":[{\"id\":\"attempt-trace\",\
         \"status\":\"candidate\",\"hooks\":[\"h\"],\"reason\":\"r\"}]}"
            .to_string()
    }

    fn expect_reject(doc: &str) {
        let err = parse_profile_bytes(doc.as_bytes()).expect_err("document parses");
        assert!(!err.to_string().is_empty());
    }

    fn tracing_doc() -> String {
        "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
         \"status\":\"reference-unvalidated\",\"identity\":{\"arch\":\"x86_64\",\
         \"min_kernel\":\"7.0\",\"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
         \"hooks\":[{\"name\":\"fexit:swiotlb_tbl_map_single\",\
         \"kind\":\"tracing\",\"function\":\"swiotlb_tbl_map_single\",\
         \"attach\":\"fexit\",\"signature\":\"phys_addr_t swiotlb_tbl_map_single\
         (struct device *dev)\"}],\
         \"capabilities\":[{\"id\":\"mapping-lifecycle\",\
         \"status\":\"candidate\",\"hooks\":[\"fexit:swiotlb_tbl_map_single\"],\
         \"reason\":\"r\"}]}"
            .to_string()
    }

    #[test]
    fn parse_conversion_capability() {
        let doc =
            minimal_doc().replace("\"id\":\"attempt-trace\"", "\"id\":\"conversion-observe\"");
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        assert_eq!(p.caps.len(), 1);
        assert_eq!(p.caps[0].id, "conversion-observe");
    }

    fn note_doc(n: usize) -> String {
        let pad = "x".repeat(n);
        minimal_doc().replace(
            "\"revision\":\"r\"",
            &format!("\"revision\":\"r\",\"note\":\"{pad}\""),
        )
    }

    #[test]
    fn parse_source_note_700_ok() {
        // Twelve-field narrow notes need ~700 chars; the
        // 1024 cap admits them.
        let p = parse_profile_bytes(note_doc(700).as_bytes()).expect("parses");
        assert_eq!(p.identity.source.note.len(), 700);
    }

    #[test]
    fn parse_source_note_1025_rejects() {
        expect_reject(&note_doc(1025));
    }

    #[test]
    fn admitted_profiles_lack_conversion() {
        // Guard: no shipped profile declares conversion hooks
        // until kernel-source evidence admits them.
        let ps = load_profiles(&profiles_dir()).expect("loads");
        for p in &ps {
            for c in &p.caps {
                assert_ne!(c.id, "conversion-observe");
            }
        }
    }

    #[test]
    fn parse_minimal_ok() {
        let p = parse_profile_bytes(minimal_doc().as_bytes()).expect("parses");
        assert_eq!(p.profile_id, "t");
        assert_eq!(p.status, "reference-unvalidated");
        assert_eq!(p.identity.arch, "x86_64");
        assert_eq!(p.identity.min_major, 7);
        assert_eq!(p.identity.min_minor, 0);
        assert_eq!(p.identity.min_patch, 0);
        assert_eq!(p.hooks.len(), 1);
        assert!(!p.hooks[0].format_has);
        assert_eq!(p.caps.len(), 1);
        assert_eq!(p.notes.len(), 0);
    }

    #[test]
    fn parse_reference_file() {
        let ps = load_profiles(&profiles_dir()).expect("loads");
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].profile_id, "linux-x86_64-7.0-reference");
        assert_eq!(ps[0].status, "reference-unvalidated");
        assert_eq!(ps[0].hooks.len(), 6);
        assert_eq!(ps[0].caps.len(), 3);
        assert_eq!(ps[0].notes.len(), 3);
        assert_eq!(ps[0].layouts.len(), 17);
        assert_eq!(ps[0].hooks[0].kind, "tracepoint");
        assert_eq!(ps[0].hooks[1].name, "fexit:swiotlb_tbl_map_single");
        assert_eq!(ps[0].hooks[1].signature_alt.len(), 1);
        // The 6plus reference reuses the same pins with a 6.0 floor.
        assert_eq!(ps[1].profile_id, "linux-x86_64-6plus-reference");
        assert_eq!(ps[1].status, "reference-unvalidated");
        assert_eq!(ps[1].identity.min_kernel, "6.0");
        assert_eq!(ps[1].hooks.len(), 6);
        assert_eq!(ps[1].layouts.len(), 17);
        assert_eq!(ps[1].hooks[1].signature_alt.len(), 1);
    }

    #[test]
    fn parse_narrow_test_file() {
        // The tool-minted narrow test doc carries the gate
        // shape (frozen tracing set, recorded format, CO-RE
        // layouts) with validated status, so the validated
        // selection path stays covered without a shipped
        // narrow profile.
        let ps = load_profiles(&fx("profiles-narrow-test")).expect("loads");
        assert_eq!(ps.len(), 2);
        assert_eq!(ps[0].profile_id, "linux-x86_64-7.0-reference");
        assert_eq!(ps[1].profile_id, "test-narrow-validated");
        assert_eq!(ps[1].status, "validated");
        assert_eq!(ps[1].hooks.len(), 6);
        assert!(ps[1].hooks[0].format_has);
        assert_eq!(ps[1].caps.len(), 3);
        assert_eq!(ps[1].layouts.len(), 17);
    }

    #[test]
    fn gate_doc_tracing_caps_supported() {
        // The admission flip: the gate doc carries the frozen
        // tracing set with both extra caps supported. Names and
        // membership are pinned through the tool-minted test
        // doc; the freeze moves only by re-qualification of
        // every lane together.
        let ps = load_profiles(&fx("profiles-narrow-test")).expect("loads");
        assert_eq!(ps[1].profile_id, "test-narrow-validated");
        let want = [
            "fexit:swiotlb_tbl_map_single",
            "fentry:__swiotlb_tbl_unmap_single",
            "fentry:__swiotlb_sync_single_for_device",
            "fentry:__swiotlb_sync_single_for_cpu",
            "fentry:swiotlb_bounce",
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(ps[1].hooks[i + 1].name, *w);
            assert_eq!(ps[1].hooks[i + 1].kind, "tracing");
            assert!(!ps[1].hooks[i + 1].signature.is_empty());
        }
        for c in &ps[1].caps {
            if c.id == "attempt-trace" {
                assert_eq!(c.status, "supported");
                assert_eq!(c.hooks.len(), 1);
            } else if c.id == "mapping-lifecycle" {
                assert_eq!(c.status, "supported");
                assert_eq!(c.hooks.len(), 2);
                assert_eq!(c.hooks[0], want[0]);
                assert_eq!(c.hooks[1], want[1]);
            } else if c.id == "copy-actual" {
                assert_eq!(c.status, "supported");
                assert_eq!(c.hooks.len(), 3);
                assert_eq!(c.hooks[0], want[2]);
                assert_eq!(c.hooks[1], want[3]);
                assert_eq!(c.hooks[2], want[4]);
            } else {
                panic!("unexpected capability {}", c.id);
            }
        }
    }

    #[test]
    fn parse_validated_file() {
        let ps = load_profiles(&fx("profiles-test")).expect("loads");
        assert_eq!(ps.len(), 1);
        assert_eq!(ps[0].status, "validated");
        assert!(ps[0].hooks[0].format_has);
        assert_eq!(ps[0].hooks[0].format_text.len(), 144);
    }

    #[test]
    fn parse_bad_status() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\"status\":\"draft\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_bad_version() {
        expect_reject(
            "{\"schema_version\":\"0.2.0\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_unknown_key() {
        let doc0 = minimal_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        assert_eq!(parts.len(), 2);
        expect_reject(&format!("{},\"zzz\":1}}]}}", parts[0]));
    }

    #[test]
    fn parse_dup_key() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\"profile_id\":\"u\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_bad_profile_id() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"-lead\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_bad_min_kernel() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.x\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_short_min_kernel() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_bad_kind() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"kprobe\",\"id_path\":\"/i\",\
             \"format_path\":\"/f\"}],\"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_tracing_hook_ok() {
        let p = parse_profile_bytes(tracing_doc().as_bytes()).expect("parses");
        assert_eq!(p.hooks.len(), 1);
        assert_eq!(p.hooks[0].kind, "tracing");
        assert_eq!(p.hooks[0].function, "swiotlb_tbl_map_single");
        assert_eq!(p.hooks[0].attach, "fexit");
        assert!(!p.hooks[0].signature.is_empty());
        assert!(!p.hooks[0].format_has);
    }

    #[test]
    fn parse_tracing_missing_signature_rejects() {
        let doc = tracing_doc().replace(
            ",\"signature\":\"phys_addr_t swiotlb_tbl_map_single(struct device *dev)\"",
            "",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_tracing_bad_attach_rejects() {
        let doc = tracing_doc().replace("\"attach\":\"fexit\"", "\"attach\":\"kprobe\"");
        expect_reject(&doc);
    }

    #[test]
    fn parse_tracing_with_format_path_rejects() {
        let doc = tracing_doc().replace(
            "\"attach\":\"fexit\"",
            "\"attach\":\"fexit\",\"format_path\":\"/f\"",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_tracepoint_with_function_rejects() {
        let doc = minimal_doc().replace(
            "\"format_path\":\"/f\"",
            "\"format_path\":\"/f\",\"function\":\"swiotlb_bounce\"",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_dup_hook() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\"id_path\":\"/i\",\
             \"format_path\":\"/f\"},{\"name\":\"h\",\"kind\":\"tracepoint\",\
             \"id_path\":\"/i2\",\"format_path\":\"/f2\"}],\"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_dangling_ref() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[{\"id\":\"attempt-trace\",\"status\":\"candidate\",\
             \"hooks\":[\"nope\"],\"reason\":\"r\"}]}",
        );
    }

    #[test]
    fn parse_dup_cap() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[{\"id\":\"attempt-trace\",\"status\":\"candidate\",\
             \"hooks\":[],\"reason\":\"r\"},{\"id\":\"attempt-trace\",\
             \"status\":\"unsupported\",\"hooks\":[],\"reason\":\"s\"}]}",
        );
    }

    #[test]
    fn parse_bad_cap_id() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[{\"id\":\"trace-all\",\"status\":\"candidate\",\
             \"hooks\":[],\"reason\":\"r\"}]}",
        );
    }

    #[test]
    fn parse_bad_cap_status() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[{\"id\":\"attempt-trace\",\"status\":\"maybe\",\
             \"hooks\":[],\"reason\":\"r\"}]}",
        );
    }

    #[test]
    fn parse_missing_field() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[],\
             \"capabilities\":[{\"id\":\"attempt-trace\",\"status\":\"candidate\",\
             \"hooks\":[]}]}",
        );
    }

    #[test]
    fn parse_trailing_data() {
        expect_reject(&(minimal_doc() + "x"));
    }

    #[test]
    fn parse_format_type() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\"id_path\":\"/i\",\
             \"format_path\":\"/f\",\"format_text\":123}],\"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_overlong_name() {
        let name = "n".repeat(129);
        expect_reject(&format!(
            "{{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
                 \"status\":\"reference-unvalidated\",\
                 \"identity\":{{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
                 \"source\":{{\"origin\":\"o\",\"revision\":\"r\"}}}},\
                 \"hooks\":[{{\"name\":\"{name}\",\"kind\":\"tracepoint\",\
                 \"id_path\":\"/i\",\"format_path\":\"/f\"}}],\
                 \"capabilities\":[]}}"
        ));
    }

    #[test]
    fn parse_hook_path_traversal() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\
             \"id_path\":\"/../outside/id\",\"format_path\":\"/f\"}],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_hook_path_dot() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\"id_path\":\"/i\",\
             \"format_path\":\"/a/./b\"}],\"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_hook_path_relative() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\
             \"id_path\":\"relative/id\",\"format_path\":\"/f\"}],\
             \"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_hook_path_nul() {
        expect_reject(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\
             \"hooks\":[{\"name\":\"h\",\"kind\":\"tracepoint\",\"id_path\":\"/i\",\
             \"format_path\":\"/f\\u0000ignored\"}],\"capabilities\":[]}",
        );
    }

    #[test]
    fn parse_empty_note_ok() {
        let doc0 = minimal_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        assert_eq!(parts.len(), 2);
        let p = parse_profile_bytes(format!("{}}}],\"notes\":[\"\"]}}", parts[0]).as_bytes())
            .expect("parses");
        assert_eq!(p.notes.len(), 1);
        assert_eq!(p.notes[0], "");
    }

    #[test]
    fn parse_too_many_hooks() {
        let mut doc = String::from(
            "{\"schema_version\":\"0.1.1\",\"profile_id\":\"t\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{\"origin\":\"o\",\"revision\":\"r\"}},\"hooks\":[",
        );
        for i in 0..33 {
            if i != 0 {
                doc += ",";
            }
            doc += &format!(
                "{{\"name\":\"h{i}\",\"kind\":\"tracepoint\",\
                 \"id_path\":\"/i\",\"format_path\":\"/f\"}}"
            );
        }
        doc += "],\"capabilities\":[]}";
        expect_reject(&doc);
    }

    #[test]
    fn parse_signature_alt_ok() {
        let doc = tracing_doc().replace(
            "\"attach\":\"fexit\"",
            "\"attach\":\"fexit\",\"signature_alt\":[\"x\",\"y\"]",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        assert_eq!(p.hooks[0].signature_alt.len(), 2);
        assert_eq!(p.hooks[0].signature_alt[0], "x");
        assert_eq!(p.hooks[0].signature_alt[1], "y");
    }

    #[test]
    fn parse_signature_alt_empty_rejects() {
        let doc = tracing_doc().replace(
            "\"attach\":\"fexit\"",
            "\"attach\":\"fexit\",\"signature_alt\":[\"\"]",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_signature_alt_too_many_rejects() {
        let doc = tracing_doc().replace(
            "\"attach\":\"fexit\"",
            "\"attach\":\"fexit\",\"signature_alt\":[\"a\",\"b\",\"c\",\"d\",\"e\"]",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_signature_alt_on_tracepoint_rejects() {
        let doc = minimal_doc().replace(
            "\"format_path\":\"/f\"",
            "\"format_path\":\"/f\",\"signature_alt\":[\"x\"]",
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_layouts_ok() {
        let doc0 = minimal_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        assert_eq!(parts.len(), 2);
        let doc = format!(
            "{}}}],\"layouts\":[{{\"struct\":\"io_tlb_pool\",\"field\":\"start\",\
             \"bit_offset\":0,\"bit_size\":64}}]}}",
            parts[0]
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        assert_eq!(p.layouts.len(), 1);
        assert_eq!(p.layouts[0].struct_name, "io_tlb_pool");
        assert_eq!(p.layouts[0].field_name, "start");
        assert_eq!(p.layouts[0].bit_offset, 0);
        assert_eq!(p.layouts[0].bit_size, 64);
    }

    #[test]
    fn parse_layouts_negative_rejects() {
        let doc0 = minimal_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        assert_eq!(parts.len(), 2);
        let doc = format!(
            "{}}}],\"layouts\":[{{\"struct\":\"s\",\"field\":\"f\",\
             \"bit_offset\":-1,\"bit_size\":64}}]}}",
            parts[0]
        );
        expect_reject(&doc);
    }

    #[test]
    fn parse_layouts_too_many_rejects() {
        let doc0 = minimal_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        assert_eq!(parts.len(), 2);
        let mut items = String::new();
        for i in 0..17 {
            if i > 0 {
                items += ",";
            }
            items += &format!(
                "{{\"struct\":\"s\",\"field\":\"f{i}\",\
                 \"bit_offset\":0,\"bit_size\":8}}"
            );
        }
        let doc = format!("{}}}],\"layouts\":[{items}]}}", parts[0]);
        expect_reject(&doc);
    }

    fn live_doc_with_layouts(layouts_json: &str) -> String {
        let doc0 = live_ref_doc();
        let parts: Vec<&str> = doc0.split("}]}").collect();
        format!("{}}}],\"layouts\":[{layouts_json}]}}", parts[0])
    }

    fn v012_doc(layouts_json: &str) -> String {
        live_doc_with_layouts(layouts_json).replace(
            "\"schema_version\":\"0.1.1\"",
            "\"schema_version\":\"0.1.2\"",
        )
    }

    #[test]
    fn parse_v012_layouts_ok() {
        let doc = v012_doc(
            "{\"capability\":\"copy-actual\",\"target\":\"field\",\
             \"struct\":\"io_tlb_pool\",\"field\":\"start\",\
             \"type_kind\":\"int\",\"bit_size\":64,\"optional\":false},\
             {\"capability\":\"mapping-lifecycle\",\"target\":\"type\",\
             \"struct\":\"mvt_dev\",\
             \"type_kind\":\"struct\",\"bit_size\":6144,\"optional\":true},\
             {\"capability\":\"attempt-trace\",\"target\":\"enumerator\",\
             \"struct\":\"mvt_e64\",\"field\":\"MVT_BIG\",\
             \"type_kind\":\"enum\",\"bit_size\":64,\"optional\":false}",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        assert_eq!(p.layouts.len(), 3);
        assert_eq!(p.schema_version, "0.1.2");
        assert_eq!(p.layouts[0].capability, "copy-actual");
        assert_eq!(p.layouts[0].target, "field");
        assert_eq!(p.layouts[0].type_kind, "int");
        assert_eq!(p.layouts[0].bit_size, 64);
        assert!(!p.layouts[0].optional);
        assert!(p.layouts[0].v012);
        assert_eq!(p.layouts[1].target, "type");
        assert_eq!(p.layouts[1].field_name, "");
        assert!(p.layouts[1].optional);
        assert!(p.layouts[1].v012);
        assert_eq!(p.layouts[2].target, "enumerator");
        assert_eq!(p.layouts[2].field_name, "MVT_BIG");
        assert!(p.layouts[2].v012);
    }

    #[test]
    fn parse_v012_rejects() {
        // bit_offset is not a 0.1.2 layout key.
        expect_reject(&v012_doc(
            "{\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f\",\"type_kind\":\"int\",\
                 \"bit_size\":8,\"bit_offset\":0,\"optional\":false}",
        ));
        // type_kind is required.
        expect_reject(&v012_doc(
            "{\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f\",\
                 \"bit_size\":8,\"optional\":false}",
        ));
        // At most 64 items.
        let mut items = String::new();
        for i in 0..65 {
            if i > 0 {
                items += ",";
            }
            items += &format!(
                "{{\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f{i}\",\
                 \"type_kind\":\"int\",\"bit_size\":8,\"optional\":false}}"
            );
        }
        expect_reject(&v012_doc(&items));
        // The 0.1.1 item shape is not a 0.1.2 item.
        expect_reject(&v012_doc(
            "{\"struct\":\"s\",\"field\":\"f\",\
                 \"bit_offset\":0,\"bit_size\":64}",
        ));
        // A type target omits field.
        expect_reject(&v012_doc(
            "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"s\",\"field\":\"f\",\"type_kind\":\"struct\",\
                 \"bit_size\":64,\"optional\":false}",
        ));
        // bit_size starts at 1.
        expect_reject(&v012_doc(
            "{\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f\",\"type_kind\":\"int\",\
                 \"bit_size\":0,\"optional\":false}",
        ));
        // Duplicates name layouts and duplicate.
        let err = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f\",\"type_kind\":\"int\",\
                 \"bit_size\":8,\"optional\":false},\
                 {\"capability\":\"copy-actual\",\"target\":\"field\",\
                 \"struct\":\"s\",\"field\":\"f\",\"type_kind\":\"int\",\
                 \"bit_size\":8,\"optional\":true}",
            )
            .as_bytes(),
        )
        .expect_err("duplicate layouts parse");
        assert!(err.to_string().contains("layouts"));
        assert!(err.to_string().contains("duplicate"));
    }

    fn expect_manifest_reject(name: &str, needle: &str) {
        let err = load_profiles(&fx(name)).expect_err("manifest loads");
        assert!(
            err.to_string().contains(needle),
            "error {err} names {needle}"
        );
    }

    #[test]
    fn manifest_empty() {
        let ps = load_profiles(&fx("profiles-empty")).expect("loads");
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn manifest_blank() {
        expect_manifest_reject("profiles-bad-manifest-blank", "manifest");
    }

    #[test]
    fn manifest_dup() {
        expect_manifest_reject("profiles-bad-manifest-dup", "manifest");
    }

    #[test]
    fn manifest_escape() {
        expect_manifest_reject("profiles-bad-manifest-escape", "manifest");
    }

    #[test]
    fn manifest_bad_doc() {
        expect_manifest_reject("profiles-bad-doc", "bad.json");
    }

    #[test]
    fn manifest_missing() {
        expect_manifest_reject("ordinary-7.0", "manifest.txt");
    }

    #[test]
    fn manifest_readable_probes_presence() {
        assert!(manifest_readable(&profiles_dir()));
        assert!(!manifest_readable(&fx("ordinary-7.0")));
    }

    #[test]
    fn load_profiles_named_aligns() {
        let named = load_profiles_named(&profiles_dir()).expect("loads");
        assert_eq!(named.names.len(), named.profiles.len());
        assert_eq!(named.names.len(), 2);
        assert_eq!(named.names[0], "linux-x86_64-7.0-reference.json");
        assert_eq!(named.profiles[0].profile_id, "linux-x86_64-7.0-reference");
    }

    #[test]
    fn select_reference_cover() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&profiles_dir()).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "linux-x86_64-7.0-reference");
        assert_eq!(
            d.reason,
            "profile linux-x86_64-7.0-reference covers this identity \
             but is reference-unvalidated",
        );
    }

    #[test]
    fn select_validated_match() {
        let r = open_evidence_reader(&fx("ready-validated")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-test")).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "test-validated");
        assert_eq!(d.reason, "profile test-validated matched (validated)");
    }

    #[test]
    fn select_bound_prefers_validated() {
        // Reference is listed first in profiles-bound, but the
        // validated doc's identity bindings hold, so it wins.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound"),
            "",
        );
        assert!(d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "test-bound-validated");
        assert_eq!(d.reason, "profile test-bound-validated matched (validated)",);
    }

    #[test]
    fn select_bound_multi_hook() {
        // A decoy tracepoint precedes the attempt hook; the
        // capability-named hook (whose format binds) must win,
        // mirroring record's hook selection exactly.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-multi")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound"),
            "",
        );
        assert!(d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "test-bound-multi");
        assert_eq!(d.reason, "profile test-bound-multi matched (validated)",);
    }

    #[test]
    fn select_bound_receipt_beats_first_covering() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let scan_raw = read_host_file(
            &fixture("tests/fixtures/scan/profiles/ref.json"),
            "profile",
            1_048_576,
        )
        .expect("scan fixture reads");
        let mut ps = vec![parse_profile_bytes(&scan_raw).expect("parses")];
        let refs = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        ps.push(refs[0].clone());
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            MINT_BRIDGE,
        );
        assert!(d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "ref-bindable");
        assert_eq!(d.reason, "profile ref-bindable matched (local-auto)");
    }

    #[test]
    fn select_bound_receipt_match() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            MINT_BRIDGE,
        );
        assert!(d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "ref-bindable");
        assert_eq!(d.reason, "profile ref-bindable matched (local-auto)");
    }

    #[test]
    fn select_bound_receipt_stale() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("ordinary-7.0"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            MINT_BRIDGE,
        );
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "ref-bindable");
        assert_eq!(
            d.reason,
            "profile ref-bindable covers this identity \
             but is reference-unvalidated; ref-bindable \
             receipt names another kernel",
        );
    }

    #[test]
    fn select_bound_receipt_bridge_mismatch() {
        // The bound-host receipt verifies everywhere except
        // the bridge: no local-auto match, and the fallback
        // reason names the bridge mismatch.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            FOREIGN_BRIDGE,
        );
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "ref-bindable");
        assert_eq!(
            d.reason,
            "profile ref-bindable covers this identity \
             but is reference-unvalidated; ref-bindable \
             receipt bridge differs from resolved bridge",
        );
    }

    #[test]
    fn select_bound_receipt_bridge_unchecked() {
        // The passive path performs no bridge binding
        // (empty hash): the otherwise-verifying receipt must
        // report unchecked explicitly instead of implying a
        // mismatch against a resolution that never ran.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            "",
        );
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "ref-bindable");
        assert_eq!(
            d.reason,
            "profile ref-bindable covers this identity \
             but is reference-unvalidated; ref-bindable \
             receipt bridge unchecked: \
             no binding performed on this path",
        );
    }

    #[test]
    fn select_bound_falls_back_with_reason() {
        // ordinary-7.0 runs 7.0.0-34-generic while the validated
        // doc records revision 7.0.0-test, so it cannot bind;
        // reference covers with the near-miss named in the reason.
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("ordinary-7.0"),
            "libz.so.1",
            &fx("profiles-bound"),
            "",
        );
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "linux-x86_64-7.0-reference");
        assert_eq!(
            d.reason,
            "profile linux-x86_64-7.0-reference covers this identity \
             but is reference-unvalidated; test-bound-validated \
             identity mismatch: revision",
        );
    }

    #[test]
    fn select_arch_mismatch() {
        let r = open_evidence_reader(&fx("arch-mismatch")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&profiles_dir()).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(!d.matched);
        assert!(!d.has_profile);
        assert!(d.reason.contains("no profile covers"));
    }

    #[test]
    fn select_68_covers_6plus_reference() {
        // A 6.8 kernel misses the 7.0 docs but the 6plus
        // reference covers it (still reference-unvalidated).
        let r = open_evidence_reader(&fx("kernel-6.8")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&profiles_dir()).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(!d.matched);
        assert!(d.has_profile);
        assert_eq!(d.profile.profile_id, "linux-x86_64-6plus-reference");
        assert_eq!(
            d.reason,
            "profile linux-x86_64-6plus-reference covers this identity \
             but is reference-unvalidated",
        );
    }

    #[test]
    fn select_empty() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-empty")).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(!d.has_profile);
        assert_eq!(d.reason, "no profiles admitted");
    }

    #[test]
    fn select_unparseable() {
        let r = open_evidence_reader(&fx("malformed-release")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&profiles_dir()).expect("loads");
        let d = select_profile(&env.kernel, &ps);
        assert!(!d.has_profile);
        assert!(d.reason.contains("unparseable"));
    }

    #[test]
    fn select_bound_receipt_grade_caps() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound-ref")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound-ref"),
            MINT_BRIDGE,
        );
        assert!(d.matched);
        assert_eq!(d.grade, "local-auto");
        assert_eq!(d.receipt_caps.len(), 1);
        assert_eq!(d.receipt_caps[0], "attempt-trace");
    }

    #[test]
    fn select_bound_validated_grade_caps() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let ps = load_profiles(&fx("profiles-bound")).expect("loads");
        let d = select_profile_bound(
            &env.kernel,
            &ps,
            &fx("bound-host"),
            "libz.so.1",
            &fx("profiles-bound"),
            "",
        );
        assert!(d.matched);
        assert_eq!(d.grade, "validated");
        assert_eq!(d.receipt_caps.len(), 0);
    }

    fn receipt_doc() -> Profile {
        let ps = load_profiles(&fx("profiles-bound")).expect("loads");
        ps[1].clone()
    }

    fn receipt_caps() -> Vec<CapQualification> {
        vec![CapQualification::new(
            "attempt-trace",
            "layout match; smoke attached, conservation holds",
        )]
    }

    fn mint_good() -> String {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            123_456_789,
            &receipt_caps(),
            "0.1.0",
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270",
            &format!("sha256:{}", parsed.bindings.object),
            "",
            "",
            3,
            "smoke: attach/poll/detach, no traffic required",
        )
    }

    fn verify_text(js: &str) -> String {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(!v.ok);
        v.message
    }

    fn swap_segment(js: &str, start_key: &str, end_key: &str, replacement: &str) -> String {
        // Replace from "start_key" up to (not incl.) "end_key".
        let a: Vec<&str> = js.split(&format!("\"{start_key}\"")).collect();
        let b: Vec<&str> = a[1].split(&format!("\"{end_key}\"")).collect();
        format!("{}{}\"{end_key}\"{}", a[0], replacement, b[1])
    }

    fn swap_tail(js: &str, key: &str, replacement: &str) -> String {
        // Replace from "key" to the end of the document.
        let a: Vec<&str> = js.split(&format!("\"{key}\"")).collect();
        format!("{}{}", a[0], replacement)
    }

    #[test]
    fn receipt_roundtrip() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            123_456_789,
            &receipt_caps(),
            "0.1.0",
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270",
            &format!("sha256:{}", parsed.bindings.object),
            "",
            "",
            3,
            "smoke: attach/poll/detach, no traffic required",
        );
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(v.ok);
        assert_eq!(v.message, "");
    }

    #[test]
    fn receipt_verdict_caps() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let js = mint_good();
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(v.ok);
        assert_eq!(v.caps.len(), 1);
        assert_eq!(v.caps[0], "attempt-trace");
    }

    #[test]
    fn receipt_verdict_caps_multi() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let mut doc = receipt_doc();
        // The fixture note carries attempt bindings only; extend
        // it with lifecycle/copy bindings so the multi-cap
        // receipt has hashes to match per qualified channel.
        doc.identity.source.note += " lc_object=sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
             lc_ring_bytes=8388608 \
             cp_object=sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb \
             cp_ring_bytes=8388608";
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let mut caps = receipt_caps();
        caps.push(CapQualification::new(
            "mapping-lifecycle",
            "fentry attach/poll/detach ok",
        ));
        caps.push(CapQualification::new(
            "copy-actual",
            "fentry attach/poll/detach ok",
        ));
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            123_456_789,
            &caps,
            "0.1.0",
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270",
            &format!("sha256:{}", parsed.bindings.object),
            &format!("sha256:{}", parsed.bindings.lc_object),
            &format!("sha256:{}", parsed.bindings.cp_object),
            3,
            "smoke: attach/poll/detach, no traffic required",
        );
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(v.ok);
        assert_eq!(v.caps.len(), 3);
        assert_eq!(v.caps[0], "attempt-trace");
        assert_eq!(v.caps[1], "mapping-lifecycle");
        assert_eq!(v.caps[2], "copy-actual");
    }

    #[test]
    fn receipt_lifecycle_missing_hash_refuses() {
        // A receipt qualifying mapping-lifecycle without a
        // lifecycle object hash must refuse: otherwise a
        // changed lifecycle object inherits qualification.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let mut caps = receipt_caps();
        caps.push(CapQualification::new(
            "mapping-lifecycle",
            "fentry attach/poll/detach ok",
        ));
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            123_456_789,
            &caps,
            "0.1.0",
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270",
            &format!("sha256:{}", parsed.bindings.object),
            "",
            "",
            3,
            "smoke: attach/poll/detach, no traffic required",
        );
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(!v.ok);
        assert_eq!(
            v.message,
            "receipt lacks lifecycle hash for qualified mapping-lifecycle",
        );
    }

    #[test]
    fn receipt_verdict_caps_empty_on_refusal() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let js = mint_good();
        let mut bad_kernel = env.kernel.clone();
        bad_kernel.release = "9.9.9-fake".to_string();
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &bad_kernel, MINT_BRIDGE);
        assert!(!v.ok);
        assert_eq!(v.caps.len(), 0);
    }

    #[test]
    fn receipt_artifacts_null() {
        let js = mint_good();
        let bad = swap_segment(&js, "artifacts", "workload", "\"artifacts\": null, ");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt unparseable"));
    }

    #[test]
    fn receipt_workload_false() {
        let js = mint_good();
        let bad = swap_tail(&js, "workload", "\"workload\": false}\n");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt unparseable"));
    }

    #[test]
    fn receipt_trailing_data() {
        let js = mint_good() + "{}\n";
        let msg = verify_text(&js);
        assert!(msg.contains("trailing data"));
    }

    #[test]
    fn receipt_bridge_shape() {
        let js = mint_good();
        let bad = js.replace(
            "\"bridge\": \"sha256:5e2e29c1",
            "\"bridge\": \"sha256:ZZZZZZZZ",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.artifacts"));
    }

    #[test]
    fn receipt_trailing_data_beats_bridge_mismatch() {
        // A foreign bridge hash plus appended garbage must
        // report trailing data (with no bridge verdict), not
        // a bridge-only mismatch: JSON consumption
        // validation finishes before the bridge compares.
        let js = mint_good() + "{}\n";
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, FOREIGN_BRIDGE);
        assert!(!v.ok);
        assert!(v.message.contains("trailing data"));
        assert!(!v.bridge_mismatch);
    }

    #[test]
    fn receipt_bridge_mismatch_refuses() {
        // The receipt is otherwise valid, but it was minted
        // for another bridge: verification must refuse with
        // the bridge named, so a swapped bridge cannot
        // inherit qualification.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let js = mint_good();
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &env.kernel, FOREIGN_BRIDGE);
        assert!(!v.ok);
        assert_eq!(v.message, "receipt bridge differs from resolved bridge");
        assert!(v.bridge_mismatch);
    }

    #[test]
    fn receipt_workload_kind() {
        let js = mint_good();
        let bad = js.replace("\"kind\": \"smoke\"", "\"kind\": \"fuzz");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_traffic_true() {
        let js = mint_good();
        let bad = js.replace("\"traffic_required\": false", "\"traffic_required\": true");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_duration_shape() {
        let js = mint_good();
        let bad = js.replace("\"duration_s\": \"3\"", "\"duration_s\": \"03\"");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_u64_max() {
        let js = mint_good();
        let good = js
            .replace(
                "\"created_ns\": \"123456789\"",
                "\"created_ns\": \"18446744073709551615\"",
            )
            .replace(
                "\"duration_s\": \"3\"",
                "\"duration_s\": \"18446744073709551615\"",
            );
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let v = verify_qualification_receipt(good.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(v.ok);
        assert_eq!(v.message, "");
    }

    #[test]
    fn receipt_created_ns_range() {
        let js = mint_good();
        let bad = js.replace(
            "\"created_ns\": \"123456789\"",
            "\"created_ns\": \"18446744073709551616\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.created_ns"));
    }

    #[test]
    fn receipt_created_ns_huge() {
        let js = mint_good();
        let bad = js.replace(
            "\"created_ns\": \"123456789\"",
            "\"created_ns\": \"99999999999999999999\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.created_ns"));
    }

    #[test]
    fn receipt_duration_range() {
        let js = mint_good();
        let bad = js.replace(
            "\"duration_s\": \"3\"",
            "\"duration_s\": \"18446744073709551616\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_duration_huge() {
        let js = mint_good();
        let bad = js.replace(
            "\"duration_s\": \"3\"",
            "\"duration_s\": \"99999999999999999999\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_note_empty() {
        let js = mint_good();
        let bad = js.replace(
            "\"note\": \"smoke: attach/poll/detach, no traffic required\"",
            "\"note\": \"\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.workload"));
    }

    #[test]
    fn receipt_memveil_empty() {
        let js = mint_good();
        let bad = js.replace("\"memveil\": \"0.1.0\"", "\"memveil\": \"\"");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.artifacts"));
    }

    #[test]
    fn receipt_objects_unknown_field() {
        let js = mint_good();
        let bad = js.replace(
            "\"objects\": {\"attempt\"",
            "\"objects\": {\"evil\": \"x\", \"attempt\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.artifacts"));
    }

    #[test]
    fn receipt_objects_empty() {
        let js = mint_good();
        let bad = swap_segment(&js, "objects", "workload", "\"objects\": {}, ");
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.artifacts"));
    }

    #[test]
    fn receipt_artifacts_unknown_field() {
        let js = mint_good();
        let bad = js.replace(
            "\"artifacts\": {\"memveil\"",
            "\"artifacts\": {\"evil\": \"x\", \"memveil\"",
        );
        let msg = verify_text(&bad);
        assert!(msg.contains("receipt.artifacts"));
    }

    #[test]
    fn receipt_artifact_mismatch() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let js = mint_good();
        let bad = js.replace(
            &format!("\"attempt\": \"sha256:{}\"", parsed.bindings.object),
            "\"attempt\": \"sha256:0000000000000000000000000000000000000000000000000000000000000000\"",
        );
        assert_ne!(bad, js);
        let v = verify_qualification_receipt(bad.as_bytes(), &doc, &env.kernel, MINT_BRIDGE);
        assert!(!v.ok);
        assert_eq!(v.message, "receipt artifacts differ from note");
    }

    #[test]
    fn receipt_revision_mismatch() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let mut fake = env.kernel.clone();
        fake.release = "9.9.9-fake".to_string();
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &fake,
            &parsed.bindings,
            123_456_789,
            &receipt_caps(),
            "0.1.0",
            "sha256:5e2e29c1dbc50b9041b2c1ad803fe2e71f1231c1f9a179aa29e72ebcb0b8d270",
            &format!("sha256:{}", parsed.bindings.object),
            "",
            "",
            3,
            "smoke: attach/poll/detach, no traffic required",
        );
        let v = verify_qualification_receipt(js.as_bytes(), &doc, &fake, MINT_BRIDGE);
        assert!(!v.ok);
        assert_eq!(v.message, "receipt kernel differs from profile revision");
    }

    #[test]
    fn receipt_wrong_kernel() {
        let js = mint_good();
        let bad = js.replace("\"release\": \"7.0.0-test\"", "\"release\": \"9.9.9-x\"");
        assert_eq!(verify_text(&bad), "receipt names another kernel");
    }

    #[test]
    fn receipt_wrong_binding() {
        let js = mint_good();
        let bad = js.replace("\"config\": \"sha256:a5af", "\"config\": \"sha256:b5af");
        assert_eq!(verify_text(&bad), "receipt bindings differ from note");
    }

    #[test]
    fn receipt_wrong_profile() {
        let js = mint_good();
        let bad = js.replace(
            "\"profile_id\": \"test-bound-validated\"",
            "\"profile_id\": \"other-profile\"",
        );
        assert_eq!(verify_text(&bad), "receipt names another profile");
    }

    #[test]
    fn receipt_bad_json() {
        let js = mint_good();
        let cut = &js.as_bytes()[..js.len() - 20];
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let v = verify_qualification_receipt(cut, &doc, &env.kernel, MINT_BRIDGE);
        assert!(!v.ok);
        assert!(v.message.starts_with("receipt unparseable: "));
    }

    #[test]
    fn receipt_empty_capabilities() {
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            1,
            &[],
            "0.1.0",
            "sha256:00",
            "sha256:00",
            "",
            "",
            3,
            "empty",
        );
        assert!(verify_text(&js).starts_with("receipt unparseable: "));
    }

    #[test]
    fn receipt_wrong_grade() {
        let js = mint_good();
        let bad = js.replace("\"grade\": \"local-auto\"", "\"grade\": \"validated\"");
        assert!(verify_text(&bad).starts_with("receipt unparseable: "));
    }

    fn frozen_hooks_json(wants: &[TraceWant]) -> String {
        // Hook array JSON rendered from frozen wants, in order.
        let mut out = String::new();
        for (i, w) in wants.iter().enumerate() {
            if i > 0 {
                out += ",";
            }
            out += &format!(
                "{{\"name\":\"{}\",\"kind\":\"tracing\",\"function\":\"{}\",\
                 \"attach\":\"{}\",\"signature\":\"{}\"}}",
                w.name, w.function, w.attach, w.signature
            );
        }
        out
    }

    fn frozen_hook_names_json(wants: &[TraceWant]) -> String {
        // Quoted hook-name list JSON from frozen wants, in order.
        let mut out = String::new();
        for (i, w) in wants.iter().enumerate() {
            if i > 0 {
                out += ",";
            }
            out += &format!("\"{}\"", w.name);
        }
        out
    }

    fn live_ref_doc() -> String {
        // One unbound reference doc with all five frozen hooks.
        //
        // No narrow note, so exact binding can never apply; the
        // live path verifies the tracing signatures plus
        // attachability instead. Lifecycle and copy declare
        // candidate, attempt declares supported with no hooks.
        format!(
            "{{\"schema_version\":\"0.1.1\",\"profile_id\":\"t-live\",\
             \"status\":\"reference-unvalidated\",\
             \"identity\":{{\"arch\":\"x86_64\",\"min_kernel\":\"7.0\",\
             \"source\":{{\"origin\":\"o\",\"revision\":\"r\"}}}},\
             \"hooks\":[\
             {{\"name\":\"swiotlb:swiotlb_bounced\",\"kind\":\"tracepoint\",\
             \"id_path\":\"/sys/kernel/tracing/events/swiotlb/\
             swiotlb_bounced/id\",\"format_path\":\"/sys/kernel/\
             tracing/events/swiotlb/swiotlb_bounced/format\"}},\
             {},{}\
             ],\"capabilities\":[{{\"id\":\"attempt-trace\",\
             \"status\":\"supported\",\"hooks\":[],\"reason\":\"r\"}},\
             {{\"id\":\"mapping-lifecycle\",\"status\":\"candidate\",\
             \"hooks\":[{}],\"reason\":\"r\"}},\
             {{\"id\":\"copy-actual\",\"status\":\"candidate\",\
             \"hooks\":[{}],\"reason\":\"r\"}}]}}",
            frozen_hooks_json(&lc_trace()),
            frozen_hooks_json(&cp_trace()),
            frozen_hook_names_json(&lc_trace()),
            frozen_hook_names_json(&cp_trace()),
        )
    }

    fn frozen_map_73() -> String {
        // Frozen 7.3 map signature: attrs arrives as a pointer.
        "phys_addr_t swiotlb_tbl_map_single(struct device *dev, \
         phys_addr_t orig_addr, size_t mapping_size, \
         unsigned int alloc_align_mask, \
         enum dma_data_direction dir, unsigned long *attrs)"
            .to_string()
    }

    fn live_doc_with_map_alt(alt: &str) -> String {
        // live_ref_doc plus one map signature_alt entry.
        let frozen70 = "phys_addr_t swiotlb_tbl_map_single(struct device *dev, \
         phys_addr_t orig_addr, size_t mapping_size, \
         unsigned int alloc_align_mask, \
         enum dma_data_direction dir, unsigned long attrs)";
        live_ref_doc().replace(
            &format!("\"signature\":\"{frozen70}\""),
            &format!("\"signature\":\"{frozen70}\",\"signature_alt\":[\"{alt}\"]"),
        )
    }

    fn seven_layouts_json() -> String {
        // The seven verified swiotlb member layouts as JSON.
        "{\"struct\":\"io_tlb_pool\",\"field\":\"start\",\
         \"bit_offset\":0,\"bit_size\":64},\
         {\"struct\":\"io_tlb_pool\",\"field\":\"nslabs\",\
         \"bit_offset\":192,\"bit_size\":64},\
         {\"struct\":\"io_tlb_pool\",\"field\":\"slots\",\
         \"bit_offset\":448,\"bit_size\":64},\
         {\"struct\":\"io_tlb_slot\",\"field\":\"orig_addr\",\
         \"bit_offset\":0,\"bit_size\":64},\
         {\"struct\":\"io_tlb_slot\",\"field\":\"alloc_size\",\
         \"bit_offset\":64,\"bit_size\":64},\
         {\"struct\":\"device_dma_parameters\",\"field\":\"min_align_mask\",\
         \"bit_offset\":32,\"bit_size\":32},\
         {\"struct\":\"device\",\"field\":\"dma_parms\",\
         \"bit_offset\":5056,\"bit_size\":64}"
            .to_string()
    }

    fn caps_of(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn verify_live_ok() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(
            &fx("kernel-38"),
            &doc,
            &caps_of(&["attempt-trace", "mapping-lifecycle"]),
        );
        assert!(v.ok);
        assert_eq!(v.reason, "");
    }

    #[test]
    fn verify_live_reader_form_agrees() {
        // The reader overload judges the same verdict as the root form.
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let reader = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let v = verify_live_interfaces_with_reader(
            &reader,
            &doc,
            &caps_of(&["attempt-trace", "mapping-lifecycle"]),
        );
        assert!(v.ok);
        assert_eq!(v.reason, "");
    }

    #[test]
    fn verify_live_reader_form_agrees_on_refusal() {
        // Refusal paths agree too: the same signature-mismatch
        // fixture yields equal ok, reason, and code in both forms.
        let doc = parse_profile_bytes(
            live_ref_doc()
                .replace("unsigned long attrs)", "unsigned long long attrs)")
                .as_bytes(),
        )
        .expect("parses");
        let caps = caps_of(&["mapping-lifecycle"]);
        let root = verify_live_interfaces(&fx("kernel-38"), &doc, &caps);
        let reader = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let via_reader = verify_live_interfaces_with_reader(&reader, &doc, &caps);
        assert!(!root.ok);
        assert!(!via_reader.ok);
        assert_eq!(via_reader.reason, root.reason);
        assert_eq!(via_reader.code, root.code);
        assert!(
            root.reason.contains("signature mismatch"),
            "{}",
            root.reason
        );
    }

    #[test]
    fn verify_live_sig_mismatch() {
        let doc = parse_profile_bytes(
            live_ref_doc()
                .replace("unsigned long attrs)", "unsigned long long attrs)")
                .as_bytes(),
        )
        .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert_eq!(
            v.reason,
            "fexit:swiotlb_tbl_map_single: signature mismatch \
             (live: phys_addr_t (struct device *dev, \
             phys_addr_t orig_addr, size_t mapping_size, \
             unsigned int alloc_align_mask, \
             enum dma_data_direction dir, unsigned long attrs))",
        );
    }

    #[test]
    fn verify_live_unattachable() {
        // swiotlb_map is present in the fixture BTF (with the
        // bounce prototype, so the signature matches) but
        // absent from the fixture filter-function list.
        let doc = parse_profile_bytes(
            live_ref_doc()
                .replace("swiotlb_bounce\"", "swiotlb_map\"")
                .replace("swiotlb_bounce(", "swiotlb_map(")
                .as_bytes(),
        )
        .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["copy-actual"]));
        assert!(!v.ok);
        assert_eq!(
            v.reason,
            "fentry:swiotlb_map: function swiotlb_map not listed in \
             available_filter_functions",
        );
    }

    #[test]
    fn verify_live_btf_absent() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("missing-btf"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert!(!v.unknown);
        assert!(v.reason.starts_with("BTF absent"));
    }

    #[test]
    fn verify_live_btf_corrupt() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("kernel-6.8"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert_eq!(v.reason, "bad BTF header");
    }

    #[test]
    fn verify_live_btf_corrupt_unknown() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("kernel-6.8"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert!(v.unknown);
        assert_eq!(v.code, "btf-malformed");
        assert_eq!(v.reason, "bad BTF header");
    }

    #[test]
    fn verify_live_btf_split_unknown() {
        // Split BTF needs its base blob: unknown, never admitted.
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(
            &gate_fixture("btf-split"),
            &doc,
            &caps_of(&["mapping-lifecycle"]),
        );
        assert!(!v.ok);
        assert!(v.unknown);
        assert_eq!(v.code, "btf-split");
    }

    #[test]
    fn verify_live_signame_accepted() {
        // Parameter names never compare on the live path.
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(
            &gate_fixture("sig-rename"),
            &doc,
            &caps_of(&["mapping-lifecycle"]),
        );
        assert!(v.ok);
    }

    #[test]
    fn verify_live_sigswap_mismatch() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(
            &gate_fixture("sig-swap"),
            &doc,
            &caps_of(&["mapping-lifecycle"]),
        );
        assert!(!v.ok);
        assert!(!v.unknown);
        assert_eq!(v.code, "signature-mismatch");
        assert!(
            v.reason
                .starts_with("fexit:swiotlb_tbl_map_single: signature mismatch")
        );
    }

    #[test]
    fn verify_live_sigwidth_refused() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(
            &gate_fixture("sig-width"),
            &doc,
            &caps_of(&["mapping-lifecycle"]),
        );
        assert!(!v.ok);
        assert!(!v.unknown);
        assert_eq!(v.code, "signature-width");
        assert_eq!(
            v.reason,
            "fexit:swiotlb_tbl_map_single: size_t width 32 bits (want 64)",
        );
    }

    #[test]
    fn frozen_sig_unnamed_params() {
        // Unnamed multi-word types keep every word; only a
        // well-formed trailing name strips, and malformed
        // trailing words stay whole and mismatch loudly.
        let u = frozen_sig_types("void f(unsigned long, size_t)", "f");
        assert!(u.has);
        assert_eq!(u.params.len(), 2);
        assert_eq!(u.params[0], "unsigned long");
        assert_eq!(u.params[1], "size_t");
        let n = frozen_sig_types("void f(unsigned long x, size_t y)", "f");
        assert!(n.has);
        assert_eq!(n.params[0], "unsigned long");
        assert_eq!(n.params[1], "size_t");
        let e = frozen_sig_types("void f(enum dma_data_direction)", "f");
        assert!(e.has);
        assert_eq!(e.params[0], "enum dma_data_direction");
        let m = frozen_sig_types("void f(unsigned long attrs!)", "f");
        assert!(m.has);
        assert_eq!(m.params[0], "unsigned long attrs!");
    }

    #[test]
    fn verify_live_73_sig_mismatch() {
        // The 7.3 map shape passes attrs as a pointer; without
        // an alt the frozen 7.0 spelling mismatches loudly.
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38-73"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert_eq!(
            v.reason,
            "fexit:swiotlb_tbl_map_single: signature mismatch \
             (live: phys_addr_t (struct device *dev, \
             phys_addr_t orig_addr, size_t mapping_size, \
             unsigned int alloc_align_mask, \
             enum dma_data_direction dir, unsigned long *attrs))",
        );
    }

    #[test]
    fn verify_live_73_alt_ok() {
        let doc = parse_profile_bytes(live_doc_with_map_alt(&frozen_map_73()).as_bytes())
            .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38-73"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(v.ok);
        assert_eq!(v.reason, "");
        // The primary spelling still admits the 7.0 shape.
        let doc70 = parse_profile_bytes(live_doc_with_map_alt(&frozen_map_73()).as_bytes())
            .expect("parses");
        let v70 =
            verify_live_interfaces(&fx("kernel-38"), &doc70, &caps_of(&["mapping-lifecycle"]));
        assert!(v70.ok);
    }

    #[test]
    fn verify_live_alt_malformed() {
        let doc = parse_profile_bytes(live_doc_with_map_alt("not a signature").as_bytes())
            .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(!v.ok);
        assert_eq!(
            v.reason,
            "fexit:swiotlb_tbl_map_single: frozen signature_alt malformed",
        );
    }

    #[test]
    fn verify_live_layout_ok() {
        let doc = parse_profile_bytes(live_doc_with_layouts(&seven_layouts_json()).as_bytes())
            .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["copy-actual"]));
        assert!(v.ok);
        assert_eq!(v.reason, "");
    }

    #[test]
    fn verify_live_layout_mismatch() {
        // A single drifted bit offset refuses with the live
        // geometry quoted.
        let layouts = "{\"struct\":\"io_tlb_pool\",\"field\":\"start\",\
         \"bit_offset\":8,\"bit_size\":64}";
        let doc = parse_profile_bytes(live_doc_with_layouts(layouts).as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["copy-actual"]));
        assert!(!v.ok);
        assert_eq!(
            v.reason,
            "io_tlb_pool.start: layout mismatch (live offset 0 size 64)",
        );
    }

    #[test]
    fn verify_live_layout_skipped_for_lifecycle() {
        // Layouts bind copy-actual only; a drifted layout
        // never refuses the lifecycle cap.
        let layouts = "{\"struct\":\"io_tlb_pool\",\"field\":\"start\",\
         \"bit_offset\":8,\"bit_size\":64}";
        let doc = parse_profile_bytes(live_doc_with_layouts(layouts).as_bytes()).expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["mapping-lifecycle"]));
        assert!(v.ok);
        assert_eq!(v.reason, "");
    }

    fn v012_field(
        cap: &str,
        sname: &str,
        fname: &str,
        kind: &str,
        size: i64,
        optional: bool,
    ) -> String {
        // One 0.1.2 field-target layout item as JSON.
        format!(
            "{{\"capability\":\"{cap}\",\"target\":\"field\",\"struct\":\"{sname}\",\
             \"field\":\"{fname}\",\"type_kind\":\"{kind}\",\
             \"bit_size\":{size},\"optional\":{optional}}}"
        )
    }

    fn v012_btf() -> Vec<u8> {
        // kernel-38 vmlinux BTF bytes.
        read_host_file(
            &format!("{}/sys/kernel/btf/vmlinux", fx("kernel-38")),
            "fixture",
            67_108_864,
        )
        .expect("btf reads")
    }

    fn members_btf() -> Vec<u8> {
        read_host_file(
            &fixture("tests/fixtures/btf/members.bin"),
            "fixture",
            67_108_864,
        )
        .expect("btf reads")
    }

    #[test]
    fn core_layout_live_ok() {
        let raw = v012_btf();
        let doc = parse_profile_bytes(
            v012_doc(&format!(
                "{},{},{}",
                v012_field("copy-actual", "io_tlb_pool", "start", "int", 64, false),
                v012_field("copy-actual", "io_tlb_pool", "slots", "ptr", 64, false),
                v012_field(
                    "copy-actual",
                    "device_dma_parameters",
                    "min_align_mask",
                    "int",
                    32,
                    false
                ),
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines = Vec::new();
        let v = verify_core_layouts(&raw, &doc.layouts, "copy-actual", &mut lines);
        assert!(v.ok);
        assert_eq!(v.reason, "");
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "io_tlb_pool.start: offset 0 bits, size 64 bits");
    }

    #[test]
    fn core_layout_live_refusals() {
        let raw = v012_btf();
        // An absent member refuses with its layout code.
        let doc = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "io_tlb_pool",
                "cc_shared",
                "int",
                8,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines = Vec::new();
        let v = verify_core_layouts(&raw, &doc.layouts, "copy-actual", &mut lines);
        assert!(!v.ok);
        assert!(!v.unknown);
        assert_eq!(v.code, "layout-missing");
        assert_eq!(
            v.reason,
            "layout: io_tlb_pool.cc_shared absent from kernel BTF",
        );
        // The same member, optional, passes with an absent note.
        let doc_opt = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "io_tlb_pool",
                "cc_shared",
                "int",
                8,
                true,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_opt = Vec::new();
        let v_opt = verify_core_layouts(&raw, &doc_opt.layouts, "copy-actual", &mut lines_opt);
        assert!(v_opt.ok);
        assert_eq!(lines_opt.len(), 1);
        assert_eq!(lines_opt[0], "io_tlb_pool.cc_shared: absent (optional)");
        // A drifted size refuses with both widths quoted.
        let doc_size = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "io_tlb_pool",
                "start",
                "int",
                32,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_size = Vec::new();
        let v_size = verify_core_layouts(&raw, &doc_size.layouts, "copy-actual", &mut lines_size);
        assert!(!v_size.ok);
        assert_eq!(v_size.code, "layout-size");
        assert_eq!(
            v_size.reason,
            "layout: io_tlb_pool.start size 64 bits \
             differs from object size 32 bits",
        );
        // A drifted kind refuses with both kinds quoted.
        let doc_kind = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "io_tlb_pool",
                "start",
                "ptr",
                64,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_kind = Vec::new();
        let v_kind = verify_core_layouts(&raw, &doc_kind.layouts, "copy-actual", &mut lines_kind);
        assert!(!v_kind.ok);
        assert_eq!(v_kind.code, "layout-kind");
        assert_eq!(
            v_kind.reason,
            "layout: io_tlb_pool.start kind int differs from object kind ptr",
        );
        // A lifecycle item refuses the lifecycle cap, not copy-actual.
        let doc_lc = parse_profile_bytes(
            v012_doc(&v012_field(
                "mapping-lifecycle",
                "io_tlb_pool",
                "cc_shared",
                "int",
                8,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_lc = Vec::new();
        let v_lc = verify_core_layouts(&raw, &doc_lc.layouts, "mapping-lifecycle", &mut lines_lc);
        assert!(!v_lc.ok);
        assert_eq!(v_lc.code, "layout-missing");
        let mut lines_cp = Vec::new();
        let v_cp = verify_core_layouts(&raw, &doc_lc.layouts, "copy-actual", &mut lines_cp);
        assert!(v_cp.ok);
        assert_eq!(lines_cp.len(), 0);
    }

    #[test]
    fn core_layout_live_type_enum() {
        let raw = members_btf();
        // A recorded struct matches kind and size; no offset prints.
        let doc = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_dev\",\"type_kind\":\"struct\",\
                 \"bit_size\":6144,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines = Vec::new();
        let v = verify_core_layouts(&raw, &doc.layouts, "copy-actual", &mut lines);
        assert!(v.ok);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0], "mvt_dev: size 6144 bits");
        // A typedef resolves through to its terminal kind.
        let doc_td = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_phys_t\",\"type_kind\":\"int\",\
                 \"bit_size\":64,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_td = Vec::new();
        let v_td = verify_core_layouts(&raw, &doc_td.layouts, "copy-actual", &mut lines_td);
        assert!(v_td.ok);
        assert_eq!(lines_td.len(), 1);
        assert_eq!(lines_td[0], "mvt_phys_t: size 64 bits");
        // A recorded enumerator matches the enum width.
        let doc_enum = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"enumerator\",\
                 \"struct\":\"mvt_e64\",\"field\":\"MVT_BIG\",\
                 \"type_kind\":\"enum\",\"bit_size\":64,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_enum = Vec::new();
        let v_enum = verify_core_layouts(&raw, &doc_enum.layouts, "copy-actual", &mut lines_enum);
        assert!(v_enum.ok);
        assert_eq!(lines_enum.len(), 1);
        assert_eq!(lines_enum[0], "mvt_e64.MVT_BIG: size 64 bits");
        // A missing type refuses without a member suffix.
        let doc_absent = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_none\",\"type_kind\":\"struct\",\
                 \"bit_size\":8,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_absent = Vec::new();
        let v_absent =
            verify_core_layouts(&raw, &doc_absent.layouts, "copy-actual", &mut lines_absent);
        assert!(!v_absent.ok);
        assert_eq!(v_absent.code, "layout-missing");
        assert_eq!(v_absent.reason, "layout: mvt_none absent from kernel BTF",);
        // A drifted type kind refuses with both kinds quoted.
        let doc_kind = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_dev\",\"type_kind\":\"union\",\
                 \"bit_size\":6144,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_kind = Vec::new();
        let v_kind = verify_core_layouts(&raw, &doc_kind.layouts, "copy-actual", &mut lines_kind);
        assert!(!v_kind.ok);
        assert_eq!(v_kind.code, "layout-kind");
        assert_eq!(
            v_kind.reason,
            "layout: mvt_dev kind struct differs from object kind union",
        );
    }

    #[test]
    fn core_layout_struct_union_size_relocated() {
        let raw = members_btf();
        // A struct type item smaller than live passes with
        // the live size as evidence; CO-RE relocates it.
        let doc_small = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_dev\",\"type_kind\":\"struct\",\
                 \"bit_size\":128,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_small = Vec::new();
        let v_small =
            verify_core_layouts(&raw, &doc_small.layouts, "copy-actual", &mut lines_small);
        assert!(v_small.ok);
        assert_eq!(lines_small.len(), 1);
        assert_eq!(lines_small[0], "mvt_dev: size 6144 bits");
        // A larger recorded struct size passes too: struct
        // sizes never compare.
        let doc_big = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_dev\",\"type_kind\":\"struct\",\
                 \"bit_size\":8192,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_big = Vec::new();
        let v_big = verify_core_layouts(&raw, &doc_big.layouts, "copy-actual", &mut lines_big);
        assert!(v_big.ok);
        assert_eq!(lines_big.len(), 1);
        assert_eq!(lines_big[0], "mvt_dev: size 6144 bits");
        // A union type item smaller than live passes likewise.
        let doc_union = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_choice\",\"type_kind\":\"union\",\
                 \"bit_size\":32,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_union = Vec::new();
        let v_union =
            verify_core_layouts(&raw, &doc_union.layouts, "copy-actual", &mut lines_union);
        assert!(v_union.ok);
        assert_eq!(lines_union.len(), 1);
        assert_eq!(lines_union[0], "mvt_choice: size 64 bits");
        // A scalar type item with a drifted size refuses.
        let doc_scalar = parse_profile_bytes(
            v012_doc(
                "{\"capability\":\"copy-actual\",\"target\":\"type\",\
                 \"struct\":\"mvt_phys_t\",\"type_kind\":\"int\",\
                 \"bit_size\":32,\"optional\":false}",
            )
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_scalar = Vec::new();
        let v_scalar =
            verify_core_layouts(&raw, &doc_scalar.layouts, "copy-actual", &mut lines_scalar);
        assert!(!v_scalar.ok);
        assert_eq!(v_scalar.code, "layout-size");
        assert_eq!(
            v_scalar.reason,
            "layout: mvt_phys_t size 64 bits differs from object size 32 bits",
        );
        // A field width mismatch refuses.
        let doc_field = parse_profile_bytes(
            v012_doc(&v012_field("copy-actual", "mvt_tag", "q", "int", 32, false)).as_bytes(),
        )
        .expect("parses");
        let mut lines_field = Vec::new();
        let v_field =
            verify_core_layouts(&raw, &doc_field.layouts, "copy-actual", &mut lines_field);
        assert!(!v_field.ok);
        assert_eq!(v_field.code, "layout-size");
        assert_eq!(
            v_field.reason,
            "layout: mvt_tag.q size 64 bits differs from object size 32 bits",
        );
    }

    #[test]
    fn core_layout_bitfield_ambiguous() {
        let raw = members_btf();
        // A bitfield member refuses even with a matching width.
        let doc_bf = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "mvt_dev",
                "offline_disabled",
                "int",
                1,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_bf = Vec::new();
        let v_bf = verify_core_layouts(&raw, &doc_bf.layouts, "copy-actual", &mut lines_bf);
        assert!(!v_bf.ok);
        assert!(!v_bf.unknown);
        assert_eq!(v_bf.code, "layout-bitfield");
        assert_eq!(
            v_bf.reason,
            "layout: mvt_dev.offline_disabled is a bitfield (unsupported)",
        );
        // Disagreeing definitions refuse with the resolver message.
        let doc_amb = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "mvt_dup",
                "flags",
                "int",
                32,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let mut lines_amb = Vec::new();
        let v_amb = verify_core_layouts(&raw, &doc_amb.layouts, "copy-actual", &mut lines_amb);
        assert!(!v_amb.ok);
        assert_eq!(v_amb.code, "layout-ambiguous");
        assert_eq!(
            v_amb.reason,
            "struct mvt_dup: 2 definitions disagree on flags",
        );
    }

    #[test]
    fn core_layout_reader_failure() {
        // A truncated blob is unknown with the health code, never refused.
        let raw = [0u8, 1u8];
        let doc = parse_profile_bytes(
            v012_doc(&v012_field("copy-actual", "s", "f", "int", 8, false)).as_bytes(),
        )
        .expect("parses");
        let mut lines = Vec::new();
        let v = verify_core_layouts(&raw, &doc.layouts, "copy-actual", &mut lines);
        assert!(!v.ok);
        assert!(v.unknown);
        assert_eq!(v.code, "btf-truncated");
    }

    #[test]
    fn verify_live_v012_evidence() {
        let doc = parse_profile_bytes(
            v012_doc(&v012_field(
                "copy-actual",
                "io_tlb_pool",
                "start",
                "int",
                64,
                false,
            ))
            .as_bytes(),
        )
        .expect("parses");
        let v = verify_live_interfaces(&fx("kernel-38"), &doc, &caps_of(&["copy-actual"]));
        assert!(v.ok);
        assert_eq!(v.reason, "");
        assert_eq!(v.evidence.len(), 1);
        assert_eq!(
            v.evidence[0],
            "io_tlb_pool.start: offset 0 bits, size 64 bits",
        );
    }

    fn mint_live() -> String {
        // Mint a local-auto receipt over live-measured bindings.
        let r = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let sel = select_attempt_hook(&doc);
        assert!(sel.ok);
        let mut bind = crate::platform::narrow::NarrowBindings::new();
        let unmeasured = measure_live_bindings(
            &fx("kernel-38"),
            &env.kernel.release,
            "libz.so.1",
            &sel.hook.format_path,
            &mut bind,
        );
        assert_eq!(unmeasured, "");
        let caps = vec![
            CapQualification::new("attempt-trace", "smoke ok"),
            CapQualification::new("mapping-lifecycle", "smoke ok"),
        ];
        mint_qualification_receipt(
            "t-live",
            &env.kernel,
            &bind,
            123_456_789,
            &caps,
            "0.1.0",
            &format!("sha256:{MINT_BRIDGE}"),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "",
            3,
            "smoke: attach/poll/detach, no traffic required",
        )
    }

    #[test]
    fn live_receipt_roundtrip() {
        let r = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let js = mint_live();
        // Object shas arrive bare (receipt parse strips the
        // prefix; record resolves bare hex the same way).
        let v = verify_live_receipt(
            js.as_bytes(),
            &doc,
            &env.kernel,
            MINT_BRIDGE,
            &fx("kernel-38"),
            "libz.so.1",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "",
        );
        assert!(v.ok);
        assert_eq!(v.caps.len(), 2);
    }

    #[test]
    fn live_receipt_drift_refuses() {
        // kernel-38-73 matches kernel-38 everywhere except
        // the BTF bytes, so the kernel-38 receipt fails there
        // with the live (not note) wording.
        let r = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let js = mint_live();
        let v = verify_live_receipt(
            js.as_bytes(),
            &doc,
            &env.kernel,
            MINT_BRIDGE,
            &fx("kernel-38-73"),
            "libz.so.1",
            "",
            "",
            "",
        );
        assert!(!v.ok);
        assert_eq!(v.message, "receipt bindings differ from live");
    }

    #[test]
    fn live_receipt_object_drift_refuses() {
        let r = open_evidence_reader(&fx("kernel-38")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        let js = mint_live();
        let v = verify_live_receipt(
            js.as_bytes(),
            &doc,
            &env.kernel,
            MINT_BRIDGE,
            &fx("kernel-38"),
            "libz.so.1",
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            "",
            "",
        );
        assert!(!v.ok);
        assert_eq!(v.message, "receipt artifacts differ from objects");
    }

    fn sig_doc(hooks_json: &str, cap_hooks_json: &str) -> String {
        // One minimal 0.1.1 document with caller-supplied hooks.
        format!(
            "{{\"schema_version\":\"0.1.1\",\"profile_id\":\"s\",\
             \"status\":\"reference-unvalidated\",\"identity\":{{\"arch\":\"x86_64\",\
             \"min_kernel\":\"7.0\",\"source\":{{\"origin\":\"o\",\"revision\":\"r\"}}}},\
             \"hooks\":[{hooks_json}],\
             \"capabilities\":[{{\"id\":\"mapping-lifecycle\",\
             \"status\":\"candidate\",\"hooks\":[{cap_hooks_json}],\
             \"reason\":\"r\"}}]}}"
        )
    }

    fn tracing_hook(function: &str, signature: &str) -> String {
        // One tracing hook JSON fragment for function/signature.
        format!(
            "{{\"name\":\"fentry:{function}\",\"kind\":\"tracing\",\
             \"function\":\"{function}\",\"attach\":\"fentry\",\
             \"signature\":\"{signature}\"}}"
        )
    }

    fn sig_btf() -> Vec<u8> {
        // Raw BTF bytes holding FUNC test_fn from funcproto.bin.
        read_host_file(
            &fixture("tests/fixtures/btf/funcproto.bin"),
            "fixture",
            67_108_864,
        )
        .expect("btf reads")
    }

    #[test]
    fn sig_match() {
        let doc = sig_doc(
            &tracing_hook("test_fn", "int test_fn(struct device *dev, size_t size)"),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].hook, "fentry:test_fn");
        assert!(vs[0].ok);
        assert_eq!(vs[0].reason, "");
        assert_eq!(vs[0].live, "int (struct device *dev, size_t size)");
    }

    #[test]
    fn sig_mismatch() {
        // Type spellings compare, never parameter names: a
        // differing return type still mismatches loudly.
        let doc = sig_doc(
            &tracing_hook("test_fn", "long test_fn(struct device *dev, size_t size)"),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert!(vs[0].reason.contains("signature mismatch"));
        assert_eq!(vs[0].live, "int (struct device *dev, size_t size)");
    }

    #[test]
    fn sig_missing_function() {
        let doc = sig_doc(&tracing_hook("nope", "int nope(int x)"), "\"fentry:nope\"");
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert!(vs[0].reason.contains("function nope not found"));
        assert_eq!(vs[0].live, "");
    }

    #[test]
    fn sig_malformed_frozen() {
        let doc = sig_doc(
            &tracing_hook("test_fn", "int test_fn"),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert!(vs[0].reason.contains("frozen signature malformed"));
    }

    #[test]
    fn sig_names_ignored() {
        let doc = sig_doc(
            &tracing_hook("test_fn", "int test_fn(struct device *d, size_t length)"),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(vs[0].ok);
        assert_eq!(vs[0].reason, "");
    }

    #[test]
    fn sig_typedef_swap() {
        let doc = sig_doc(
            &tracing_hook(
                "test_fn",
                "int test_fn(struct device *dev, phys_addr_t size)",
            ),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert!(vs[0].reason.contains("signature mismatch"));
    }

    #[test]
    fn sig_param_count() {
        let doc = sig_doc(
            &tracing_hook(
                "test_fn",
                "int test_fn(struct device *dev, size_t size, int extra)",
            ),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert!(vs[0].reason.contains("signature mismatch"));
    }

    #[test]
    fn sig_width() {
        let doc = sig_doc(
            &tracing_hook("test_fn", "int test_fn(struct device *dev, size_t size)"),
            "\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = read_host_file(
            &fixture("tests/fixtures/btf/sig-width.bin"),
            "fixture",
            67_108_864,
        )
        .expect("btf reads");
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert!(!vs[0].ok);
        assert_eq!(
            vs[0].reason,
            "fentry:test_fn: size_t width 32 bits (want 64)",
        );
    }

    #[test]
    fn sig_skips_tracepoint() {
        let doc = sig_doc(
            &format!(
                "{{\"name\":\"swiotlb:x\",\"kind\":\"tracepoint\",\
                 \"id_path\":\"/i\",\"format_path\":\"/f\"}},{}",
                tracing_hook("test_fn", "int test_fn(struct device *dev, size_t size)",)
            ),
            "\"swiotlb:x\",\"fentry:test_fn\"",
        );
        let p = parse_profile_bytes(doc.as_bytes()).expect("parses");
        let raw = sig_btf();
        let vs = verify_hook_signatures(&p, &raw);
        assert_eq!(vs.len(), 1);
        assert_eq!(vs[0].hook, "fentry:test_fn");
        assert!(vs[0].ok);
    }

    #[test]
    fn default_receipts_dir() {
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles/"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles//"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles/."),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles/./"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/./profiles"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share//memveil/profiles"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/./profiles/"),
            "/var/lib/memveil/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles/.."),
            "/usr/share/memveil/profiles/../receipts",
        );
        // Interior-.. spellings that the kernel would fold
        // to the installed dir keep the byte-identical
        // fallback: lexical .. resolution is symlink-unsafe.
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/profiles/../profiles"),
            "/usr/share/memveil/profiles/../profiles/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/usr/share/memveil/other/../profiles"),
            "/usr/share/memveil/other/../profiles/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("build/../profiles"),
            "build/../profiles/receipts",
        );
        assert_eq!(
            super::default_receipts_dir("/opt/mv/profiles"),
            "/opt/mv/profiles/receipts",
        );
    }

    #[test]
    fn receipt_escape_pins_del() {
        // The receipt quoter escapes DEL as \u007f: it mirrors
        // the report renderer, not the canonical event quoter.
        let r = open_evidence_reader(&fx("bound-host")).expect("fixture opens");
        let env = detect_environment(&r);
        let doc = receipt_doc();
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok);
        let js = mint_qualification_receipt(
            &doc.profile_id,
            &env.kernel,
            &parsed.bindings,
            1,
            &receipt_caps(),
            "0.1.0",
            "sha256:00",
            "sha256:00",
            "",
            "",
            3,
            "note\x7fend",
        );
        assert!(js.contains("note\\u007fend"), "escapes DEL: {js}");
        let bad = js.replace("\\u007f", "\x7f");
        assert_ne!(bad, js);
    }

    #[test]
    fn tracing_gap_pins() {
        // attempt-trace never binds: it is skipped outright.
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        assert_eq!(tracing_gap(&doc, &caps_of(&["attempt-trace"])), "");
        // The live ref doc carries the full frozen set.
        assert_eq!(
            tracing_gap(&doc, &caps_of(&["mapping-lifecycle", "copy-actual"])),
            ""
        );
        // A doc whose named hook drifts from the frozen
        // spelling names the mismatch.
        let thin = parse_profile_bytes(tracing_doc().as_bytes()).expect("parses");
        let gap = tracing_gap(&thin, &caps_of(&["mapping-lifecycle"]));
        assert!(
            gap.contains("signature mismatch"),
            "names the mismatch: {gap}"
        );
        // A tracepoint hook bound to an extra cap refuses.
        let tp = parse_profile_bytes(minimal_doc().as_bytes()).expect("parses");
        let gap_tp = tracing_gap(&tp, &caps_of(&["mapping-lifecycle"]));
        assert!(!gap_tp.is_empty());
    }

    #[test]
    fn attempt_hook_selection() {
        let doc = parse_profile_bytes(live_ref_doc().as_bytes()).expect("parses");
        // attempt-trace names no hooks: the first tracepoint wins.
        let sel = select_attempt_hook(&doc);
        assert!(sel.ok);
        assert_eq!(sel.hook.name, "swiotlb:swiotlb_bounced");
        // A tracing-named attempt hook refuses.
        let tracing = parse_profile_bytes(tracing_doc().as_bytes()).expect("parses");
        let mut bad = tracing.clone();
        bad.caps[0].id = "attempt-trace".to_string();
        let sel_bad = select_attempt_hook(&bad);
        assert!(!sel_bad.ok);
        assert_eq!(sel_bad.refusal, "attempt-trace hook is not a tracepoint");
        // No tracepoint hook at all refuses.
        let sel_none = select_attempt_hook(&tracing);
        assert!(!sel_none.ok);
        assert_eq!(sel_none.refusal, "no tracepoint hook");
    }
}
