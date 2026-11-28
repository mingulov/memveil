// SPDX-License-Identifier: GPL-3.0-or-later
//! Shared collection service: admission plus the collector run.
//!
//! The record verb, live top, and the qualify smoke share
//! this one narrow boundary: run options with fixed
//! defaults, capability parsing, profile admission
//! ([`decide_record`]), artifact discovery, and
//! [`run_collector_with`], which runs admission plus
//! collection and returns the raw outcome. Pre-run
//! refusals return exit 3 with an unprefixed diagnostic
//! and create no BPF or output resource; each command
//! adds its own verb prefix and renders its own output.
//! Ownership repair of a finalized capture stays shared
//! through [`repair_warning_for`] (pure: it returns the
//! warn-once line, else ""), while writing that line
//! stays with the calling command. Argument parsing and
//! presentation stay in the commands.
//!
//! Objects resolve explicitly or from the linked-in
//! artifacts ("": the statically linked loader needs no
//! bridge file, so an empty bridge is the normal case,
//! not a refusal).

use super::collector::{Collector, CollectorConfig, EXIT_INVALID, EXIT_REFUSAL, RunResult};
use super::journal_admission::{
    JOURNAL_NOT_ADMITTED, JournalDispatch, JournalReadiness, admit_journal, fix_for_discovery,
    gather_journal_evidence,
};
use super::journal_kernel::JournalKernel as NativeJournalKernel;
use super::kernel::AyaKernel;
use super::live::WriterSource;
use super::loadcheck::{LoadDiag, LoadRefusal, diagnose_load, parse_load_refusal};
use super::reader::DEFAULT_MAX_EVENTS_BYTES as REPLAY_MAX_EVENTS_BYTES;
use crate::model::journal::{JournalSelection, select_journal};
use crate::model::session::EvidenceItem;
use crate::model::validate::check_opaque_id;
use crate::platform::artifact_files::{join_root, open_bridge_snapshot, restore_capture_ownership};
use crate::platform::btf::{read_btf_copy_fb, read_btf_maps, read_btf_maps_ring};
use crate::platform::capabilities::{attempt_loss_exact, cap_floor_ok, cap_floor_refusal};
use crate::platform::clock::{MonoClock, check_timens_live};
use crate::platform::evidence::{KernelInfo, detect_environment};
use crate::platform::hash::sha256_hex;
use crate::platform::journal_profile::discover_journal_binding;
use crate::platform::kernelgate::{GateVerdict, kernel_gate, remedy_for};
use crate::platform::narrow::{
    LiveValue, MAX_NARROW_BTF_BYTES, MAX_NARROW_FORMAT_BYTES, MAX_NARROW_IMAGE_BYTES,
    MAX_NARROW_OBJECT_BYTES, MAX_NARROW_RING_BYTES, NarrowLive, OffsetProbe, check_narrow,
    check_narrow_extra, parse_narrow_note, probe_trace_offsets, read_live_bid, read_live_bytes,
    read_live_config, verify_object, verify_object_program,
};
use crate::platform::profiles::{
    Profile, ProfileHook, default_receipts_dir, load_profiles, parse_profile_bytes,
    select_attempt_hook, select_profile, tracing_gap, verify_live_interfaces, verify_live_receipt,
    verify_qualification_receipt,
};
use crate::platform::reader::{
    host_file_denied, open_evidence_reader, read_evidence, read_host_file, readlink_self,
};
use crate::platform::runtime::{discover_bridge, discover_object, embedded_object, live_uids};
use crate::platform::signal::LiveSignalSource;
use crate::platform::tracefs::{probe_tracefs, tracefs_translate};

/// Default capture duration in seconds.
pub const DEFAULT_DURATION_S: u64 = 60;
/// Default events budget: always replays under the report cap.
pub const DEFAULT_MAX_EVENTS_BYTES: u64 = REPLAY_MAX_EVENTS_BYTES as u64;
/// Minimum record budget in bytes.
pub const MIN_RECORD_BYTES: u64 = 131072;
/// Maximum record budget in bytes.
pub const MAX_RECORD_BYTES: u64 = 4294967296;
/// Profile document read cap in bytes.
pub const MAX_PROFILE_DOC_BYTES: usize = 1048576;
pub(crate) const ZLIB: &str = "libz.so.1";
const PROGRAM: &str = "mv_swiotlb_attempt";
const ATTEMPT_CAP: &str = "attempt-trace";
const LIFECYCLE_CAP: &str = "mapping-lifecycle";
const COPY_CAP: &str = "copy-actual";
const CONVERT_CAP: &str = "conversion-observe";
/// Journal selector (`docs/conversion-journal.md`): recognized
/// by the parser so admission answers it with the frozen
/// admission code (exit 3) instead of as an unknown id (exit 2).
/// The record channel behind it admits only on an exact
/// rebound-evidence match; anything else refuses before native
/// or output creation.
const JOURNAL_CAP: &str = "conversion-journal";
const RING_LC_MAP: &str = "mv_lifecycle";
const RING_CP_MAP: &str = "mv_copies";

/// Parsed record arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOptions {
    /// Capture duration in seconds.
    pub duration_s: u64,
    /// Events budget in bytes.
    pub max_events_bytes: u64,
    /// Output capture directory.
    pub output: String,
    /// Explicit attempt object path.
    pub object: String,
    /// Explicit bridge path.
    pub bridge: String,
    /// True when --bridge was passed.
    pub has_bridge: bool,
    /// Explicit profile id or path.
    pub profile: String,
    /// True when --profile was passed.
    pub has_profile: bool,
    /// Profiles directory.
    pub profiles_dir: String,
    /// True when --profiles-dir was passed.
    pub has_profiles_dir: bool,
    /// Explicit lifecycle object path.
    pub lc_object: String,
    /// Explicit copy object path.
    pub cp_object: String,
    /// Explicit journal object path.
    pub journal_object: String,
    /// True when bounded journal caller processing is requested.
    pub journal_callers: bool,
    /// Requested capabilities list.
    pub capabilities: String,
    /// Device selector.
    pub device: String,
    /// True when --device was passed.
    pub has_device: bool,
    /// Strict exit mode.
    pub strict: bool,
}

impl Default for RecordOptions {
    fn default() -> Self {
        Self {
            duration_s: DEFAULT_DURATION_S,
            max_events_bytes: DEFAULT_MAX_EVENTS_BYTES,
            output: String::new(),
            object: String::new(),
            bridge: String::new(),
            has_bridge: false,
            profile: String::new(),
            has_profile: false,
            profiles_dir: String::new(),
            has_profiles_dir: false,
            lc_object: String::new(),
            cp_object: String::new(),
            journal_object: String::new(),
            journal_callers: false,
            capabilities: String::new(),
            device: String::new(),
            has_device: false,
            strict: false,
        }
    }
}

/// One admitted extra channel: verified bytes, hash, ring.
///
/// Lifecycle and copy channels admit identically shaped
/// artifacts (verified object bytes, sha256, bound ring
/// size) through the same static checks; the struct
/// keeps that accounting grouped while each channel's
/// programs, ring map, and event semantics stay
/// explicit at its own call site. `present` False
/// carries empty artifacts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExtraChannel {
    /// True when the channel was requested and verified.
    pub present: bool,
    /// Verified object bytes.
    pub elf: Vec<u8>,
    /// Bound ring size.
    pub ring_bytes: i64,
    /// Object sha256.
    pub object_sha: String,
}

/// One admission decision: mode, hook, identity, bytes.
///
/// `ok` False carries an exit-3 `refusal`; otherwise
/// `kind` is validated, local-auto, candidate, or partial, `hook`
/// is the selected tracepoint hook with a verified live
/// layout, and `elf` is the verified object bytes (read
/// once, hashed and handed to the session unchanged).
/// Bound decisions also carry the measured narrow
/// identities (config/src, btf, format, image, image
/// build-id); partial decisions leave them empty so the
/// capture marks each one unavailable. `selected_caps`
/// names the requested capabilities in order; a selected
/// extra channel carries its verified object bytes, hash,
/// and bound ring size in `lc`/`cp`, and never runs
/// partial. `layout_evidence` carries one line per
/// checked 0.1.2 layout item. Admitted decisions carry
/// the probed
/// load-time table offsets (`off_*`, -1 when never
/// probed). Refusals carry a machine `refusal_code`
/// (`profile` for selection refusals), whether the
/// evidence was `refusal_unknown`, and a user `fix`
/// line ("" when none applies).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanDecision {
    /// True when admission succeeded.
    pub ok: bool,
    /// Refusal reason; empty when ok.
    pub refusal: String,
    /// Machine refusal code.
    pub refusal_code: String,
    /// True when the refusal is uncertainty.
    pub refusal_unknown: bool,
    /// User fix line.
    pub fix: String,
    /// validated, local-auto, candidate, or partial.
    pub kind: String,
    /// Admitted profile.
    pub profile: Profile,
    /// Selected tracepoint hook.
    pub hook: ProfileHook,
    /// Human decision reason.
    pub reason: String,
    /// Object sha256.
    pub object_sha: String,
    /// Bound ring size.
    pub ring_bytes: i64,
    /// Probed dev_name offset.
    pub off_loc: i64,
    /// Probed size offset.
    pub off_size: i64,
    /// Probed force offset.
    pub off_force: i64,
    /// Probed dynamic-data floor.
    pub off_fixed_end: i64,
    /// Verified object bytes.
    pub elf: Vec<u8>,
    /// Tracepoint system.
    pub tp_system: String,
    /// Tracepoint event.
    pub tp_event: String,
    /// Measured config identity.
    pub measured_config: LiveValue,
    /// Measured config source.
    pub measured_config_src: String,
    /// Measured BTF identity.
    pub measured_btf: LiveValue,
    /// Measured format identity.
    pub measured_format: LiveValue,
    /// Measured image identity.
    pub measured_image: LiveValue,
    /// Measured image build-id.
    pub measured_image_bid: LiveValue,
    /// Requested capabilities in order.
    pub selected_caps: String,
    /// One line per checked layout item.
    pub layout_evidence: Vec<String>,
    /// Admitted lifecycle channel.
    pub lc: ExtraChannel,
    /// Admitted copy channel.
    pub cp: ExtraChannel,
}

impl Default for ScanDecision {
    fn default() -> Self {
        Self {
            ok: false,
            refusal: String::new(),
            refusal_code: String::new(),
            refusal_unknown: false,
            fix: String::new(),
            kind: String::new(),
            profile: Profile::default(),
            hook: ProfileHook::default(),
            reason: String::new(),
            object_sha: String::new(),
            ring_bytes: 0,
            off_loc: -1,
            off_size: -1,
            off_force: -1,
            off_fixed_end: -1,
            elf: Vec::new(),
            tp_system: String::new(),
            tp_event: String::new(),
            measured_config: LiveValue {
                state: String::new(),
                value: String::new(),
                detail: String::new(),
            },
            measured_config_src: String::new(),
            measured_btf: LiveValue {
                state: String::new(),
                value: String::new(),
                detail: String::new(),
            },
            measured_format: LiveValue {
                state: String::new(),
                value: String::new(),
                detail: String::new(),
            },
            measured_image: LiveValue {
                state: String::new(),
                value: String::new(),
                detail: String::new(),
            },
            measured_image_bid: LiveValue {
                state: String::new(),
                value: String::new(),
                detail: String::new(),
            },
            selected_caps: String::new(),
            layout_evidence: Vec::new(),
            lc: ExtraChannel::default(),
            cp: ExtraChannel::default(),
        }
    }
}

fn refuse_scan(reason: String) -> ScanDecision {
    ScanDecision {
        ok: false,
        refusal: reason,
        refusal_code: "profile".to_string(),
        ..Default::default()
    }
}

/// One kernel-gate refusal: reason, code, unknown flag, fix.
fn refuse_scan_gate(gate: &GateVerdict) -> ScanDecision {
    ScanDecision {
        ok: false,
        refusal: gate.reason.clone(),
        refusal_code: gate.code.clone(),
        refusal_unknown: gate.unknown,
        fix: gate.remedy.clone(),
        ..Default::default()
    }
}

/// One live refusal code, defaulting to the selection class.
fn live_skip_code(code: &str) -> String {
    if code.is_empty() {
        return "profile".to_string();
    }
    code.to_string()
}

/// One live-check refusal: reason, code, unknown flag, fix.
fn refuse_scan_live(reason: String, code: &str, unknown: bool) -> ScanDecision {
    let refusal_code = live_skip_code(code);
    let fix = remedy_for(&refusal_code);
    ScanDecision {
        ok: false,
        refusal: reason,
        refusal_code,
        refusal_unknown: unknown,
        fix,
        ..Default::default()
    }
}

/// Last path component: refusal reasons leak no layout.
fn refusal_basename(path: &str) -> String {
    let b = path.as_bytes();
    let mut cut = 0;
    for (i, byte) in b.iter().enumerate() {
        if *byte == 0x2F {
            cut = i + 1;
        }
    }
    if cut >= b.len() {
        return path.to_string();
    }
    String::from_utf8(b[cut..].to_vec()).unwrap_or_else(|_| path.to_string())
}

/// Parsed capability request: caps in order, or err.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CapsOut {
    /// True when the request parsed.
    pub ok: bool,
    /// Requested caps in order.
    pub caps: Vec<String>,
    /// Parse failure; empty when ok.
    pub err: String,
}

/// Split a comma capability list (strict, no spaces).
fn split_caps(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for byte in text.as_bytes() {
        if *byte == 0x2C {
            out.push(String::from_utf8(cur.clone()).unwrap_or_default());
            cur = Vec::new();
        } else {
            cur.push(*byte);
        }
    }
    out.push(String::from_utf8(cur).unwrap_or_default());
    out
}

/// Resolve the capability list plus journal options into a selection.
///
/// The sole item "all" expands to the three ordinary record channels
/// (never the opt-in journal); everything else follows the frozen
/// journal selection contract: duplicates, unknown ids, journal
/// options without the journal, and a device filter on a
/// journal-only request refuse.
pub fn collection_selection(
    capabilities: &str,
    callers: bool,
    device: bool,
    journal_object: bool,
) -> Result<JournalSelection, crate::model::validate::ValidationError> {
    let mut selected = capabilities.to_string();
    if selected == "all" {
        selected = "attempt-trace,mapping-lifecycle,copy-actual".to_string();
    }
    select_journal(&selected, callers, device, journal_object)
}

/// Parse requested capabilities in order.
///
/// Empty means attempt-trace alone; the sole item "all"
/// expands to the three record channels. Unknown ids and
/// empty items refuse, and duplicate names are usage errors.
/// Requests naming an ordinary capability resolve attempt-trace
/// implicitly when it is missing: the attempt channel stays the
/// mandatory base channel without refusing wellformed lists.
/// Journal-only lists (conversion-journal and conversion-observe,
/// which name global conversion collection) need no
/// attempt hook; every consumer refuses them explicitly
/// (exit 3), never as unknown (exit 2).
pub fn parse_requested_caps(want: &str) -> CapsOut {
    let mut out = CapsOut::default();
    if want == "all" {
        out.caps.push(ATTEMPT_CAP.to_string());
        out.caps.push(LIFECYCLE_CAP.to_string());
        out.caps.push(COPY_CAP.to_string());
        out.ok = true;
        return out;
    }
    let mut items = Vec::new();
    if want.is_empty() {
        items.push(ATTEMPT_CAP.to_string());
    } else {
        items = split_caps(want);
    }
    for item in &items {
        if item.is_empty() {
            out.err = "bad capability list".to_string();
            return out;
        }
        if item != ATTEMPT_CAP
            && item != LIFECYCLE_CAP
            && item != COPY_CAP
            && item != CONVERT_CAP
            && item != JOURNAL_CAP
        {
            out.err = format!("unknown capability: {item}");
            return out;
        }
        for previous in &out.caps {
            if previous == item {
                out.err = format!("duplicate capability: {item}");
                return out;
            }
        }
        out.caps.push(item.clone());
    }
    let mut has_attempt = false;
    let mut has_ordinary = false;
    for cap in &out.caps {
        if cap == ATTEMPT_CAP {
            has_attempt = true;
        }
        if cap == ATTEMPT_CAP || cap == LIFECYCLE_CAP || cap == COPY_CAP {
            has_ordinary = true;
        }
    }
    if has_ordinary && !has_attempt {
        let mut caps = vec![ATTEMPT_CAP.to_string()];
        caps.extend(out.caps.iter().cloned());
        out.caps = caps;
    }
    out.ok = true;
    out
}

/// True when the doc admits the capability for capture.
///
/// Both supported and candidate declarations select;
/// the decision kind already tells them apart. Only
/// unsupported or missing declarations refuse.
fn cap_selectable(doc: &Profile, cap: &str) -> bool {
    for c in &doc.caps {
        if c.id == cap {
            return c.status == "supported" || c.status == "candidate";
        }
    }
    false
}

/// First hook a requested cap names that the doc lacks.
fn cap_unknown_hook(doc: &Profile, cap: &str) -> String {
    for c in &doc.caps {
        if c.id == cap {
            for want in &c.hooks {
                let mut found = false;
                for h in &doc.hooks {
                    if h.name == *want {
                        found = true;
                        break;
                    }
                }
                if !found {
                    return want.clone();
                }
            }
            return String::new();
        }
    }
    String::new()
}

/// One frozen tracing program: name plus section kind.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProgWant {
    name: String,
    section: String,
}

fn lc_progs() -> Vec<ProgWant> {
    vec![
        ProgWant {
            name: "mv_map_result".to_string(),
            section: "fexit/".to_string(),
        },
        ProgWant {
            name: "mv_unmap".to_string(),
            section: "fentry/".to_string(),
        },
    ]
}

fn cp_progs() -> Vec<ProgWant> {
    vec![
        ProgWant {
            name: "mv_bounce".to_string(),
            section: "fentry/".to_string(),
        },
        ProgWant {
            name: "mv_bounce_exit".to_string(),
            section: "fexit/".to_string(),
        },
        ProgWant {
            name: "mv_sync_device".to_string(),
            section: "fentry/".to_string(),
        },
        ProgWant {
            name: "mv_sync_cpu".to_string(),
            section: "fentry/".to_string(),
        },
    ]
}

/// Frozen attempt program names for load diagnostics.
pub fn attempt_program_names() -> Vec<String> {
    vec![PROGRAM.to_string()]
}

/// Frozen lifecycle program names for load diagnostics.
pub fn lifecycle_program_names() -> Vec<String> {
    lc_progs().iter().map(|w| w.name.clone()).collect()
}

/// Frozen copy program names for load diagnostics.
pub fn copy_program_names() -> Vec<String> {
    cp_progs().iter().map(|w| w.name.clone()).collect()
}

/// True when a parsed refusal names an EINVAL/EACCES load errno.
///
/// Only load-phase verifier-rejected refusals earn a replay:
/// other errnos carry no verifier lines worth recovering, a
/// codeless diagnostic replays nothing at all, and a link-phase
/// failure's program already loaded successfully — the link
/// failure itself has no verifier log, so a replay would reach
/// the next program and append its foreign verifier log to
/// this link refusal.
fn is_load_errno_failure(refusal: Option<&LoadRefusal>) -> bool {
    matches!(refusal, Some(parsed) if parsed.code == "verifier-rejected" && !parsed.link_phase)
}

/// 0/1/2 for the load channel a parsed refusal blames, else 0.
///
/// The blamed channel is the classifying header's own tag, so
/// routing can never disagree with the stamped code; the
/// verifier replay diagnoses the blamed object's load. An
/// unparsed diagnostic answers the attempt default, and the
/// caller replays only when `is_load_errno_failure` holds, so a
/// codeless diagnostic replays nothing at all.
fn load_fail_channel(refusal: Option<&LoadRefusal>) -> i64 {
    refusal.map(|parsed| parsed.channel).unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct ExtraOut {
    ok: bool,
    refusal: String,
    elf: Vec<u8>,
    sha: String,
    ring: i64,
}

/// Static admission for one extra channel object.
///
/// Verifies every frozen tracing program in its section
/// kind over the resolved bytes, and reads the channel
/// ring size from BTF. Refusals name the channel word.
fn verify_extra_object(
    elf: &[u8],
    word: &str,
    ring_var: &str,
    ring_word: &str,
    wants: &[ProgWant],
) -> ExtraOut {
    let mut out = ExtraOut::default();
    for want in wants {
        let chk = verify_object_program(elf, &want.name, &want.section);
        if !chk.ok {
            out.refusal = format!("{word} object refused: {}", chk.message);
            return out;
        }
    }
    let maps = read_btf_maps_ring(elf, ring_var, ring_word);
    if !maps.ok {
        out.refusal = format!("{word} object refused: {}", maps.message);
        return out;
    }
    if maps.ring_bytes > MAX_NARROW_RING_BYTES {
        out.refusal = format!("{word} object ring too large");
        return out;
    }
    if word == "cp" {
        let fb = read_btf_copy_fb(elf);
        if !fb.ok {
            out.refusal = format!("{word} object refused: {}", fb.message);
            return out;
        }
    }
    out.ok = true;
    out.elf = elf.to_vec();
    out.sha = sha256_hex(elf);
    out.ring = maps.ring_bytes;
    out
}

/// Split a `system:event` hook name into C identifiers.
fn split_site(name: &str) -> Option<(String, String)> {
    let raw = name.as_bytes();
    let mut cut: Option<usize> = None;
    for (i, byte) in raw.iter().enumerate() {
        if *byte == 0x3A {
            if cut.is_some() {
                return None;
            }
            cut = Some(i);
        }
    }
    let cut = cut?;
    if cut == 0 || cut + 1 >= raw.len() {
        return None;
    }
    for (i, byte) in raw.iter().enumerate() {
        if i == cut {
            continue;
        }
        let ok = byte.is_ascii_alphanumeric() || *byte == 0x5F;
        if !ok {
            return None;
        }
    }
    let sys = String::from_utf8(raw[..cut].to_vec()).ok()?;
    let evt = String::from_utf8(raw[cut + 1..].to_vec()).ok()?;
    Some((sys, evt))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BindingOut {
    ok: bool,
    reason: String,
    config: LiveValue,
    config_src: String,
    btf: LiveValue,
    format: LiveValue,
    image: LiveValue,
    image_bid: LiveValue,
}

fn live_value_empty() -> LiveValue {
    LiveValue {
        state: String::new(),
        value: String::new(),
        detail: String::new(),
    }
}

impl Default for BindingOut {
    fn default() -> Self {
        Self {
            ok: false,
            reason: String::new(),
            config: live_value_empty(),
            config_src: String::new(),
            btf: live_value_empty(),
            format: live_value_empty(),
            image: live_value_empty(),
            image_bid: live_value_empty(),
        }
    }
}

/// Full narrow binding of one doc against live identity.
///
/// Release must equal the recorded revision, the note
/// must parse, every live source must match, requested
/// extra channels must bind their object bytes and ring
/// sizes, and the live format bytes must equal the
/// embedded text.
#[allow(clippy::too_many_arguments)]
fn check_binding(
    root: &str,
    release: &str,
    doc: &Profile,
    hook: &ProfileHook,
    object_sha: &str,
    ring_bytes: i64,
    format_bytes: &[u8],
    lc_sha: &str,
    lc_ring: i64,
    cp_sha: &str,
    cp_ring: i64,
    want_lc: bool,
    want_cp: bool,
) -> BindingOut {
    let mut out = BindingOut::default();
    if release != doc.identity.source.revision {
        out.reason = "release != revision".to_string();
        return out;
    }
    let parsed = parse_narrow_note(&doc.identity.source.note);
    if !parsed.ok {
        out.reason = parsed.message;
        return out;
    }
    let bind = parsed.bindings;
    let mut live = NarrowLive::new();
    let cfg = read_live_config(root, release, ZLIB);
    live.config = cfg.value;
    live.config_src = cfg.src;
    live.btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    live.format = LiveValue {
        state: "value".to_string(),
        value: sha256_hex(format_bytes),
        detail: String::new(),
    };
    live.object = LiveValue {
        state: "value".to_string(),
        value: object_sha.to_string(),
        detail: String::new(),
    };
    live.image = read_live_bytes(
        root,
        &format!("/boot/vmlinuz-{release}"),
        "image",
        MAX_NARROW_IMAGE_BYTES,
    );
    live.image_bid = read_live_bid(root);
    live.ring = LiveValue {
        state: "value".to_string(),
        value: format!("{ring_bytes}"),
        detail: String::new(),
    };
    out.config = live.config.clone();
    out.config_src = live.config_src.clone();
    out.btf = live.btf.clone();
    out.format = live.format.clone();
    out.image = live.image.clone();
    out.image_bid = live.image_bid.clone();
    let verdict = check_narrow(&bind, &live);
    if verdict.state != "bound" {
        out.reason = format!("{} {}", verdict.state, verdict.key);
        return out;
    }
    live.lc_object = LiveValue {
        state: "value".to_string(),
        value: lc_sha.to_string(),
        detail: String::new(),
    };
    live.lc_ring = LiveValue {
        state: "value".to_string(),
        value: format!("{lc_ring}"),
        detail: String::new(),
    };
    live.cp_object = LiveValue {
        state: "value".to_string(),
        value: cp_sha.to_string(),
        detail: String::new(),
    };
    live.cp_ring = LiveValue {
        state: "value".to_string(),
        value: format!("{cp_ring}"),
        detail: String::new(),
    };
    let extra = check_narrow_extra(&bind, &live, want_lc, want_cp);
    if extra.state != "bound" {
        out.reason = format!("{} {}", extra.state, extra.key);
        return out;
    }
    if !hook.format_has {
        out.reason = "uncheckable format_text".to_string();
        return out;
    }
    let want = hook.format_text.as_bytes();
    if want.len() != format_bytes.len() {
        out.reason = "mismatch format_text".to_string();
        return out;
    }
    for i in 0..want.len() {
        if want[i] != format_bytes[i] {
            out.reason = "mismatch format_text".to_string();
            return out;
        }
    }
    out.ok = true;
    out.reason = String::new();
    out
}

/// Measure live narrow identities without comparing.
///
/// Reads the same live sources `check_binding`
/// hashes (config plus source, btf, format, image,
/// image build-id) for live-path candidates, which
/// carry no parsed note to compare against. The hook
/// rides along for the call shape only; no format
/// text comparison runs here.
fn measure_binding(
    root: &str,
    release: &str,
    _hook: &ProfileHook,
    format_bytes: &[u8],
) -> BindingOut {
    let mut out = BindingOut::default();
    let mut live = NarrowLive::new();
    let cfg = read_live_config(root, release, ZLIB);
    live.config = cfg.value;
    live.config_src = cfg.src;
    live.btf = read_live_bytes(root, "/sys/kernel/btf/vmlinux", "btf", MAX_NARROW_BTF_BYTES);
    live.format = LiveValue {
        state: "value".to_string(),
        value: sha256_hex(format_bytes),
        detail: String::new(),
    };
    live.image = read_live_bytes(
        root,
        &format!("/boot/vmlinuz-{release}"),
        "image",
        MAX_NARROW_IMAGE_BYTES,
    );
    live.image_bid = read_live_bid(root);
    out.config = live.config.clone();
    out.config_src = live.config_src.clone();
    out.btf = live.btf.clone();
    out.format = live.format.clone();
    out.image = live.image.clone();
    out.image_bid = live.image_bid.clone();
    out.ok = true;
    out.reason = String::new();
    out
}

fn covers(kernel: &KernelInfo, doc: &Profile) -> bool {
    select_profile(kernel, std::slice::from_ref(doc)).has_profile
}

/// True when a verifying receipt covers every wanted cap.
///
/// The receipt at <receipts-dir>/<id>.json must verify
/// against the doc, the live kernel, and the resolved
/// bridge hash, and qualify each requested capability.
/// Docs with a parseable narrow note verify exactly;
/// docs with no usable note verify against fresh live
/// measurements plus the given live-resolved object
/// shas. An empty pdir, a missing file, or any verify
/// failure yields False: scan falls through to the next
/// candidate. `bridge_mismatch` reports True when the
/// receipt was otherwise valid but named another
/// bridge, so the fallback reason can name it. Never
/// raises.
#[allow(clippy::too_many_arguments)]
fn receipt_covers(
    doc: &Profile,
    kernel: &KernelInfo,
    want: &[String],
    pdir: &str,
    bridge_sha: &str,
    root: &str,
    obj_attempt: &str,
    obj_lc: &str,
    obj_cp: &str,
) -> (bool, bool) {
    if pdir.is_empty() {
        return (false, false);
    }
    let path = format!("{}/{}.json", default_receipts_dir(pdir), doc.profile_id);
    let raw = match read_host_file(&path, "receipt", MAX_PROFILE_DOC_BYTES) {
        Ok(raw) => raw,
        Err(_) => return (false, false),
    };
    let noted = doc.identity.source.has_note && parse_narrow_note(&doc.identity.source.note).ok;
    let hit_caps: Vec<String> = if noted {
        let v = verify_qualification_receipt(&raw, doc, kernel, bridge_sha);
        if !v.ok {
            return (false, v.bridge_mismatch);
        }
        v.caps
    } else {
        let v = verify_live_receipt(
            &raw,
            doc,
            kernel,
            bridge_sha,
            root,
            ZLIB,
            obj_attempt,
            obj_lc,
            obj_cp,
        );
        if !v.ok {
            return (false, v.bridge_mismatch);
        }
        v.caps
    };
    for cap in want {
        let mut found = false;
        for hit in &hit_caps {
            if hit == cap {
                found = true;
                break;
            }
        }
        if !found {
            return (false, false);
        }
    }
    (true, false)
}

/// Read hook format bytes; "" when readable.
///
/// Failures name the translated path and the evidence
/// error, keeping the `format unreadable` prefix the
/// release gate matches.
fn read_format(root: &str, hook: &ProfileHook) -> Result<Vec<u8>, String> {
    let treader = match open_evidence_reader(root) {
        Ok(treader) => treader,
        Err(e) => {
            return Err(format!("format unreadable: {}: {}", hook.format_path, e));
        }
    };
    let fpath = tracefs_translate(&probe_tracefs(&treader), &hook.format_path);
    match read_evidence(&treader, &fpath, MAX_NARROW_FORMAT_BYTES) {
        Ok(raw) => Ok(raw),
        Err(e) => Err(format!("format unreadable: {fpath}: {e}")),
    }
}

struct AdmittedHook {
    hook: ProfileHook,
    raw: Vec<u8>,
    sys: String,
    evt: String,
    probe: OffsetProbe,
}

/// Select, read, verify, and probe one doc's hook.
///
/// "" when admitted, with the table offsets probed from
/// the same raw buffer the format binding hashes, so the
/// offsets inherit that binding.
fn admit_hook(root: &str, doc: &Profile) -> Result<AdmittedHook, String> {
    let sel = select_attempt_hook(doc);
    if !sel.ok {
        return Err(sel.refusal);
    }
    let hook = sel.hook;
    let raw = read_format(root, &hook)?;
    let probe = probe_trace_offsets(&raw);
    if !probe.ok {
        return Err(format!("layout: {}", probe.message));
    }
    let Some((sys, evt)) = split_site(&hook.name) else {
        return Err("bad hook site".to_string());
    };
    Ok(AdmittedHook {
        hook,
        raw,
        sys,
        evt,
        probe,
    })
}

/// First reason a doc cannot satisfy the request, else "".
///
/// Every requested extra capability needs a supported
/// or candidate declaration whose named hooks all
/// exist in the doc; the message names the capability
/// and the document. The attempt channel keeps its
/// legacy hook selection and refusals below.
fn selection_gap(doc: &Profile, caps: &[String]) -> String {
    for cap in caps {
        if cap == ATTEMPT_CAP {
            continue;
        }
        if !cap_selectable(doc, cap) {
            return format!("capability {cap} unsupported by {}", doc.profile_id);
        }
        let missing = cap_unknown_hook(doc, cap);
        if !missing.is_empty() {
            return format!("capability {cap} names unknown hook {missing}");
        }
    }
    String::new()
}

/// First privilege-independent selection gap, else "".
fn static_gap(doc: &Profile, caps: &[String]) -> String {
    let gap = selection_gap(doc, caps);
    if !gap.is_empty() {
        return gap;
    }
    tracing_gap(doc, caps)
}

/// True when the doc carries a parseable narrow note.
fn noted_doc(doc: &Profile) -> bool {
    if !doc.identity.source.has_note {
        return false;
    }
    parse_narrow_note(&doc.identity.source.note).ok
}

/// True when a noted-doc receipt routes without privilege.
///
/// Reuses receipt coverage for noted docs only; callers
/// must never pass a live doc here, whose receipt check
/// reads fresh live measurements behind the gate. Sets
/// denied_drop when the receipt file itself is denied,
/// bridge_drop when the receipt is blocked only by the
/// bridge.
fn static_receipt_ok(
    doc: &Profile,
    kernel: &KernelInfo,
    want: &[String],
    pdir: &str,
    bridge_sha: &str,
) -> (bool, bool, bool) {
    let (ok, bridge_drop) = receipt_covers(doc, kernel, want, pdir, bridge_sha, "", "", "", "");
    if ok {
        return (true, false, false);
    }
    let mut denied_drop = false;
    if !pdir.is_empty() {
        let path = format!("{}/{}.json", default_receipts_dir(pdir), doc.profile_id);
        if host_file_denied(&path) {
            denied_drop = true;
        }
    }
    (false, denied_drop, bridge_drop)
}

/// One unreadable-gate refusal: unknown, never admitted.
fn refuse_gate_unreadable(detail: String) -> ScanDecision {
    let mut out = refuse_scan(format!("kernel gate unreadable: {detail}"));
    out.refusal_unknown = true;
    out
}

/// True when the doc can only take the live path.
///
/// Reference docs (any status but validated) whose
/// narrow note is unusable - the source carries no
/// note or the note fails to parse - never bind
/// exactly; they verify live interfaces instead.
/// Docs with a parseable note never take the live
/// path.
fn live_doc(doc: &Profile) -> bool {
    if doc.status == "validated" {
        return false;
    }
    if !doc.identity.source.has_note {
        return true;
    }
    !parse_narrow_note(&doc.identity.source.note).ok
}
/// Decide admission: scan, object statics, hook, binding.
///
/// Explicit mode resolves one doc (file first, then id)
/// and enforces full binding when bindings exist. Scan
/// mode tries each covering validated doc in order, then
/// each covering reference doc whose receipt under
/// the receipts dir for the profiles dir verifies
/// (against the doc, the live kernel, and
/// ``bridge_sha``, the bare hex sha256 of the
/// resolved bridge) and covers the
/// requested capabilities ("" disables receipts), and
/// falls back to the first covering doc as partial. A
/// receipt blocked only by the bridge falls through to
/// partial with a reason naming the bridge mismatch,
/// never local-auto; requested extras with an unchecked
/// bridge ("") refuse unknown as bridge-unchecked
/// instead. Static object failures refuse
/// everywhere; identity failures fall through in scan
/// mode only. Requested extra capabilities need a
/// supported declaration, a resolvable object path, and
/// full extended binding; they never fall back to
/// partial. Reference docs without a usable narrow
/// note take the live path instead: their tracing
/// interfaces verify against the live host, and
/// success admits a candidate carrying measured
/// identities without exact binding.
///
/// Empty object paths resolve to the linked-in
/// artifacts; only an explicit unreadable path refuses.
#[allow(clippy::too_many_arguments)]
pub fn decide_record(
    root: &str,
    kernel: &KernelInfo,
    profiles: &[Profile],
    explicit: &str,
    has_explicit: bool,
    object_path: &str,
    lc_object: &str,
    cp_object: &str,
    want_caps: &str,
    profiles_dir: &str,
    bridge_sha: &str,
) -> ScanDecision {
    let mut out = ScanDecision::default();
    let ask = parse_requested_caps(want_caps);
    if !ask.ok {
        return refuse_scan(ask.err);
    }
    let mut want_lc = false;
    let mut want_cp = false;
    for cap in &ask.caps {
        if cap == LIFECYCLE_CAP {
            want_lc = true;
        }
        if cap == COPY_CAP {
            want_cp = true;
        }
        if cap == CONVERT_CAP {
            return refuse_scan("capability conversion-observe has no record channel".to_string());
        }
        if cap == JOURNAL_CAP {
            return refuse_scan("journal_profile_not_admitted".to_string());
        }
    }
    for cap in &ask.caps {
        if !cap_floor_ok(cap, &kernel.release) {
            return refuse_scan(cap_floor_refusal(cap, &kernel.release));
        }
    }
    let want_extra = want_lc || want_cp;
    let mut selected = ask.caps[0].clone();
    for cap in ask.caps.iter().skip(1) {
        selected = selected + "," + cap;
    }
    let mut candidates: Vec<Profile> = Vec::new();
    let want_explicit = has_explicit;
    if want_explicit {
        let doc_bytes = read_host_file(explicit, "profile", MAX_PROFILE_DOC_BYTES);
        if let Ok(doc_bytes) = doc_bytes {
            match parse_profile_bytes(&doc_bytes) {
                Ok(doc) => candidates.push(doc),
                Err(e) => {
                    return refuse_scan(format!("cannot parse --profile: {e}"));
                }
            }
        } else {
            let mut found = false;
            for p in profiles {
                if p.profile_id == explicit {
                    candidates.push(p.clone());
                    found = true;
                    break;
                }
            }
            if !found {
                return refuse_scan(format!("unknown --profile: {}", refusal_basename(explicit)));
            }
        }
        if !covers(kernel, &candidates[0]) {
            return refuse_scan("profile does not cover this kernel".to_string());
        }
    } else {
        for p in profiles {
            if covers(kernel, p) {
                candidates.push(p.clone());
            }
        }
        if candidates.is_empty() {
            return refuse_scan("no profile covers this kernel".to_string());
        }
    }
    if want_lc && lc_object.is_empty() && embedded_object("lifecycle").is_none() {
        return refuse_scan("no object: pass --lc-object PATH".to_string());
    }
    if want_cp && cp_object.is_empty() && embedded_object("copy").is_none() {
        return refuse_scan("no object: pass --cp-object PATH".to_string());
    }
    let elf: Vec<u8> = match resolve_channel_object(object_path, "attempt") {
        Ok(elf) => elf,
        Err(_) => return refuse_scan("object unreadable".to_string()),
    };
    let accuse = verify_object(&elf, PROGRAM);
    if !accuse.ok {
        return refuse_scan(format!("object refused: {}", accuse.message));
    }
    let maps = read_btf_maps(&elf);
    if !maps.ok {
        return refuse_scan(format!("object refused: {}", maps.message));
    }
    let ring = maps.ring_bytes;
    let sha = sha256_hex(&elf);
    if ring > MAX_NARROW_RING_BYTES {
        return refuse_scan("object ring too large".to_string());
    }
    let mut lc = ExtraOut::default();
    if want_lc {
        let lc_elf = match resolve_channel_object(lc_object, "lifecycle") {
            Ok(elf) => elf,
            Err(_) => return refuse_scan("lc object unreadable".to_string()),
        };
        lc = verify_extra_object(&lc_elf, "lc", RING_LC_MAP, "lifecycle", &lc_progs());
        if !lc.ok {
            return refuse_scan(lc.refusal.clone());
        }
    }
    let mut cp = ExtraOut::default();
    if want_cp {
        let cp_elf = match resolve_channel_object(cp_object, "copy") {
            Ok(elf) => elf,
            Err(_) => return refuse_scan("cp object unreadable".to_string()),
        };
        cp = verify_extra_object(&cp_elf, "cp", RING_CP_MAP, "copy", &cp_progs());
        if !cp.ok {
            return refuse_scan(cp.refusal.clone());
        }
    }
    let gate_reader = match open_evidence_reader(root) {
        Ok(reader) => reader,
        Err(e) => return refuse_gate_unreadable(e.to_string()),
    };
    // Privilege-independent selection refuses before the
    // kernel gate. Receipt checks against fresh live
    // measurements, hook format reads, live checks, and
    // bindings all run after it.
    if want_explicit {
        let egap = static_gap(&candidates[0], &ask.caps);
        if !egap.is_empty() {
            return refuse_scan(egap);
        }
    } else if want_extra {
        let mut pool: Vec<usize> = Vec::new();
        let mut denied_drop = false;
        let mut bridge_drop = false;
        for (i, candidate) in candidates.iter().enumerate() {
            if candidate.status == "validated" || live_doc(candidate) {
                pool.push(i);
            } else if noted_doc(candidate) {
                let (ok_static, dd, bd) =
                    static_receipt_ok(candidate, kernel, &ask.caps, profiles_dir, bridge_sha);
                if ok_static {
                    pool.push(i);
                } else if dd {
                    denied_drop = true;
                } else if bd {
                    bridge_drop = true;
                }
            }
        }
        let bridge_open = bridge_drop && bridge_sha.is_empty();
        if !pool.is_empty() {
            let mut last_gap = String::new();
            let mut all_gapped = true;
            for r in pool {
                let g = static_gap(&candidates[r], &ask.caps);
                if g.is_empty() {
                    all_gapped = false;
                    break;
                }
                last_gap = g;
            }
            if all_gapped {
                if bridge_open {
                    return refuse_scan_live(
                        "bridge unchecked: cannot verify receipts".to_string(),
                        "bridge-unchecked",
                        true,
                    );
                }
                return refuse_scan(last_gap);
            }
        } else if !denied_drop {
            if bridge_open {
                return refuse_scan_live(
                    "bridge unchecked: cannot verify receipts".to_string(),
                    "bridge-unchecked",
                    true,
                );
            }
            return refuse_scan("no profile satisfies requested capabilities".to_string());
        }
    }
    let gated = kernel_gate(&gate_reader, &kernel.release, ZLIB, &ask.caps);
    if !gated.ok {
        return refuse_scan_gate(&gated);
    }
    let mut order: Vec<usize> = Vec::new();
    let mut order_receipt: Vec<bool> = Vec::new();
    let mut order_live: Vec<bool> = Vec::new();
    let mut saw_bridge_mismatch = false;
    let mut saw_noted_bridge_mismatch = false;
    if want_explicit {
        order.push(0);
        order_receipt.push(false);
        order_live.push(live_doc(&candidates[0]));
    } else {
        for (i, candidate) in candidates.iter().enumerate() {
            if candidate.status == "validated" {
                order.push(i);
                order_receipt.push(false);
                order_live.push(false);
            }
        }
        for (i, candidate) in candidates.iter().enumerate() {
            if candidate.status == "validated" {
                continue;
            }
            let (covers, mism) = receipt_covers(
                candidate,
                kernel,
                &ask.caps,
                profiles_dir,
                bridge_sha,
                root,
                &sha,
                &lc.sha,
                &cp.sha,
            );
            if covers {
                order.push(i);
                order_receipt.push(true);
                order_live.push(false);
            } else if mism {
                saw_bridge_mismatch = true;
                if !live_doc(candidate) {
                    saw_noted_bridge_mismatch = true;
                }
            }
        }
        for (i, candidate) in candidates.iter().enumerate() {
            if candidate.status == "validated" {
                continue;
            }
            if live_doc(candidate) {
                order.push(i);
                order_receipt.push(false);
                order_live.push(true);
            }
        }
    }
    let mut skip_reason = String::new();
    let mut skip_code = "profile".to_string();
    let mut skip_unknown = false;
    for oi in 0..order.len() {
        let doc = candidates[order[oi]].clone();
        let gap = selection_gap(&doc, &ask.caps);
        if !gap.is_empty() {
            if want_explicit {
                return refuse_scan(gap);
            }
            skip_reason = gap;
            skip_code = "profile".to_string();
            skip_unknown = false;
            continue;
        }
        let tgap = tracing_gap(&doc, &ask.caps);
        if !tgap.is_empty() {
            if want_explicit {
                return refuse_scan(tgap);
            }
            skip_reason = tgap;
            skip_code = "profile".to_string();
            skip_unknown = false;
            continue;
        }
        let admitted = match admit_hook(root, &doc) {
            Ok(admitted) => admitted,
            Err(herr) => {
                if want_explicit {
                    return refuse_scan(herr);
                }
                skip_reason = herr;
                skip_code = "profile".to_string();
                skip_unknown = false;
                continue;
            }
        };
        if order_live[oi] {
            let live = verify_live_interfaces(root, &doc, &ask.caps);
            if !live.ok {
                if want_explicit {
                    if want_extra {
                        return refuse_scan_live(
                            format!("live check failed: {}", live.reason),
                            &live.code,
                            live.unknown,
                        );
                    }
                    out.ok = true;
                    out.kind = "partial".to_string();
                    out.reason = format!(
                        "explicit {} (reference, live check failed: {})",
                        doc.profile_id, live.reason
                    );
                    out.profile = doc;
                    out.hook = admitted.hook;
                    out.object_sha = sha.clone();
                    out.ring_bytes = ring;
                    out.off_loc = admitted.probe.loc_off;
                    out.off_size = admitted.probe.size_off;
                    out.off_force = admitted.probe.force_off;
                    out.off_fixed_end = admitted.probe.fixed_end;
                    out.elf = elf.clone();
                    out.tp_system = admitted.sys;
                    out.tp_event = admitted.evt;
                    out.selected_caps = selected.clone();
                    return out;
                }
                skip_reason = format!("live check failed: {}", live.reason);
                skip_code = live_skip_code(&live.code);
                skip_unknown = live.unknown;
                continue;
            }
            out.layout_evidence = live.evidence;
            let measured = measure_binding(root, &kernel.release, &admitted.hook, &admitted.raw);
            out.ok = true;
            out.kind = "candidate".to_string();
            out.reason = format!(
                "candidate {}: live interfaces verified (profile unvalidated)",
                doc.profile_id
            );
            out.profile = doc;
            out.hook = admitted.hook;
            out.object_sha = sha.clone();
            out.ring_bytes = ring;
            out.off_loc = admitted.probe.loc_off;
            out.off_size = admitted.probe.size_off;
            out.off_force = admitted.probe.force_off;
            out.off_fixed_end = admitted.probe.fixed_end;
            out.elf = elf.clone();
            out.tp_system = admitted.sys;
            out.tp_event = admitted.evt;
            out.measured_config = measured.config;
            out.measured_config_src = measured.config_src;
            out.measured_btf = measured.btf;
            out.measured_format = measured.format;
            out.measured_image = measured.image;
            out.measured_image_bid = measured.image_bid;
            out.selected_caps = selected.clone();
            out.lc.present = want_lc;
            out.cp.present = want_cp;
            if want_lc {
                out.lc.elf = lc.elf.clone();
                out.lc.object_sha = lc.sha.clone();
                out.lc.ring_bytes = lc.ring;
            }
            if want_cp {
                out.cp.elf = cp.elf.clone();
                out.cp.object_sha = cp.sha.clone();
                out.cp.ring_bytes = cp.ring;
            }
            return out;
        }
        let parsed = parse_narrow_note(&doc.identity.source.note);
        if !parsed.ok {
            if want_explicit {
                if want_extra {
                    return refuse_scan(format!("binding failed: {}", parsed.message));
                }
                // Unparseable bindings are never validated,
                // whatever the document status claims: without
                // a parsed note no identity check ran. Both
                // statuses proceed as unbound partials with
                // wording that reserves "validated" for
                // successful binding checks.
                out.ok = true;
                out.kind = "partial".to_string();
                if doc.status == "validated" {
                    out.reason = format!("explicit {} (unbound, no bindings)", doc.profile_id);
                } else {
                    out.reason = format!("explicit {} (reference, no bindings)", doc.profile_id);
                }
                out.profile = doc;
                out.hook = admitted.hook;
                out.object_sha = sha.clone();
                out.ring_bytes = ring;
                out.off_loc = admitted.probe.loc_off;
                out.off_size = admitted.probe.size_off;
                out.off_force = admitted.probe.force_off;
                out.off_fixed_end = admitted.probe.fixed_end;
                out.elf = elf.clone();
                out.tp_system = admitted.sys;
                out.tp_event = admitted.evt;
                out.selected_caps = selected.clone();
                return out;
            }
            skip_reason = format!("binding failed: {}", parsed.message);
            skip_code = "profile".to_string();
            skip_unknown = false;
            continue;
        }
        let bound = check_binding(
            root,
            &kernel.release,
            &doc,
            &admitted.hook,
            &sha,
            ring,
            &admitted.raw,
            &lc.sha,
            lc.ring,
            &cp.sha,
            cp.ring,
            want_lc,
            want_cp,
        );
        if !bound.ok {
            if want_explicit {
                return refuse_scan(format!("binding failed: {}", bound.reason));
            }
            skip_reason = format!("binding failed: {}", bound.reason);
            skip_code = "profile".to_string();
            skip_unknown = false;
            continue;
        }
        out.ok = true;
        if doc.status == "validated" {
            out.kind = "validated".to_string();
            out.reason = format!("validated {}: bindings hold", doc.profile_id);
        } else if order_receipt[oi] {
            out.kind = "local-auto".to_string();
            out.reason = format!(
                "local-auto {}: receipt verified, bindings hold",
                doc.profile_id
            );
        } else {
            out.kind = "candidate".to_string();
            out.reason = format!(
                "candidate {}: bindings hold (profile unvalidated)",
                doc.profile_id
            );
        }
        out.profile = doc;
        out.hook = admitted.hook;
        out.object_sha = sha.clone();
        out.ring_bytes = ring;
        out.off_loc = admitted.probe.loc_off;
        out.off_size = admitted.probe.size_off;
        out.off_force = admitted.probe.force_off;
        out.off_fixed_end = admitted.probe.fixed_end;
        out.elf = elf.clone();
        out.tp_system = admitted.sys;
        out.tp_event = admitted.evt;
        out.measured_config = bound.config;
        out.measured_config_src = bound.config_src;
        out.measured_btf = bound.btf;
        out.measured_format = bound.format;
        out.measured_image = bound.image;
        out.measured_image_bid = bound.image_bid;
        out.selected_caps = selected.clone();
        out.lc.present = want_lc;
        out.cp.present = want_cp;
        if want_lc {
            out.lc.elf = lc.elf.clone();
            out.lc.object_sha = lc.sha.clone();
            out.lc.ring_bytes = lc.ring;
        }
        if want_cp {
            out.cp.elf = cp.elf.clone();
            out.cp.object_sha = cp.sha.clone();
            out.cp.ring_bytes = cp.ring;
        }
        return out;
    }
    // Scan mode only: explicit always returns inside the loop.
    if want_extra {
        if bridge_sha.is_empty() && saw_noted_bridge_mismatch {
            return refuse_scan_live(
                "bridge unchecked: cannot verify receipts".to_string(),
                "bridge-unchecked",
                true,
            );
        }
        if skip_reason.is_empty() {
            return refuse_scan("no profile satisfies requested capabilities".to_string());
        }
        return refuse_scan_live(skip_reason, &skip_code, skip_unknown);
    }
    let first = candidates[0].clone();
    let admitted = match admit_hook(root, &first) {
        Ok(admitted) => admitted,
        Err(perr) => return refuse_scan(perr),
    };
    out.ok = true;
    out.kind = "partial".to_string();
    let mut had_validated = false;
    for candidate in &candidates {
        if candidate.status == "validated" {
            had_validated = true;
            break;
        }
    }
    if saw_bridge_mismatch {
        out.reason = format!("partial {}: receipt bridge mismatch", first.profile_id);
    } else if had_validated {
        out.reason = format!("partial {}: narrow identity unverified", first.profile_id);
    } else {
        out.reason = format!("partial {}: no validated profile", first.profile_id);
    }
    out.profile = first;
    out.hook = admitted.hook;
    out.object_sha = sha.clone();
    out.ring_bytes = ring;
    out.off_loc = admitted.probe.loc_off;
    out.off_size = admitted.probe.size_off;
    out.off_force = admitted.probe.force_off;
    out.off_fixed_end = admitted.probe.fixed_end;
    out.elf = elf.clone();
    out.tp_system = admitted.sys;
    out.tp_event = admitted.evt;
    out.selected_caps = selected.clone();
    out
}

/// Resolve one channel's object bytes: explicit path wins verbatim, else the linked-in artifact.
///
/// Shared by record admission and doctor load-check so both judge the
/// same bytes under zero-config.
pub(crate) fn resolve_channel_object(path: &str, kind: &str) -> Result<Vec<u8>, ()> {
    if !path.is_empty() {
        return read_host_file(path, "object", MAX_NARROW_OBJECT_BYTES).map_err(|_| ());
    }
    embedded_object(kind).map(|b| b.to_vec()).ok_or(())
}
/// Sha256 of the resolved bridge, else "" when unreadable.
///
/// Load-check admission binds receipts to the resolved
/// bridge bytes; an unresolvable bridge leaves every
/// receipt unchecked.
pub fn loadcheck_bridge_sha(bridge: &str, has_bridge: bool) -> String {
    let path = resolve_bridge(bridge, has_bridge);
    let snap = open_bridge_snapshot(&path);
    snap.sha.clone()
}

/// Explicit --bridge verbatim, else zero-config discovery.
///
/// Thin delegate over discover_bridge: the ambient env
/// value, live uids, and kernel-resolved executable path
/// feed the pure order. Never argv[0], PATH, or the working directory.
pub fn resolve_bridge(bridge: &str, has_bridge: bool) -> String {
    let exe_path = readlink_self().unwrap_or_default();
    let env_value = std::env::var("LMB_NATIVE_LIB").unwrap_or_default();
    discover_bridge(bridge, has_bridge, &env_value, live_uids(), &exe_path)
}

/// Explicit object path verbatim, else the linked-in artifact.
///
/// `kind` is attempt, lifecycle, or copy. An explicit
/// path wins unprobed; otherwise "" names the embedded
/// object bytes the loader carries.
pub fn resolve_object(explicit: &str) -> String {
    let has_explicit = !explicit.is_empty();
    discover_object("", explicit, has_explicit, "")
}

/// Live boot id when present and well-formed, else None.
fn read_boot_id(root: &str) -> Option<String> {
    let mut raw = read_host_file(
        &join_root(root, "/proc/sys/kernel/random/boot_id"),
        "boot_id",
        4096,
    )
    .ok()?;
    while !raw.is_empty() && raw[raw.len() - 1] == 0x0A {
        raw.pop();
    }
    if raw.is_empty() {
        return None;
    }
    let text = String::from_utf8(raw).ok()?;
    check_opaque_id(&text).ok()?;
    Some(text)
}

fn decision_item(reason: String) -> EvidenceItem {
    EvidenceItem {
        item_type: "provenance".to_string(),
        source: "profile.decision".to_string(),
        interpretation: reason,
    }
}

fn value_item(source: String, value: String) -> EvidenceItem {
    EvidenceItem {
        item_type: "provenance".to_string(),
        source,
        interpretation: value,
    }
}

/// Attempt-loss bound item on kernels before 6.7, else empty.
pub fn attempt_loss_evidence(release: &str) -> Vec<EvidenceItem> {
    let mut out = Vec::new();
    if attempt_loss_exact(release) {
        return out;
    }
    out.push(EvidenceItem {
        item_type: "attempt-loss-bound".to_string(),
        source: format!("kernel {release}"),
        interpretation: "attempt loss counts are a lower bound before 6.7: trace_call_bpf skipped programs without counting them".to_string(),
    });
    out
}

/// Append one present channel's hash and ring provenance.
///
/// Lifecycle and copy channels report the identical pair
/// (``<name>.object.sha256``, ``<name>.ring.bytes``);
/// absent channels append nothing.
fn append_channel_evidence(evidence: &mut Vec<EvidenceItem>, name: &str, channel: &ExtraChannel) {
    if !channel.present {
        return;
    }
    evidence.push(value_item(
        format!("{name}.object.sha256"),
        channel.object_sha.clone(),
    ));
    evidence.push(value_item(
        format!("{name}.ring.bytes"),
        format!("{}", channel.ring_bytes),
    ));
}

/// Append one layout item per checked CO-RE layout line.
///
/// Each line was verified against kernel BTF by the live
/// layout check; the item names that source.
fn append_layout_evidence(evidence: &mut Vec<EvidenceItem>, lines: &[String]) {
    for line in lines {
        evidence.push(EvidenceItem {
            item_type: "layout".to_string(),
            source: "kernel BTF".to_string(),
            interpretation: line.clone(),
        });
    }
}

/// One provenance item from a measured live identity.
///
/// Valued reads render their bare hex; anything else is
/// an explicit unavailable marker, never empty or zero.
/// Empty states mean no binding ran (partial decisions);
/// other states carry the read failure reason.
pub fn render_provenance(source: &str, v: &LiveValue) -> EvidenceItem {
    let mut item = EvidenceItem {
        item_type: "provenance".to_string(),
        source: source.to_string(),
        interpretation: String::new(),
    };
    if v.state == "value" {
        item.interpretation = v.value.clone();
    } else if v.state.is_empty() {
        item.interpretation = "unavailable: narrow identity unverified".to_string();
    } else if v.detail.is_empty() {
        item.interpretation = format!("unavailable: {}", v.state);
    } else {
        item.interpretation = format!("unavailable: {}: {}", v.state, v.detail);
    }
    item
}

/// Armed journal channel: readiness plus staged object bytes.
struct JournalArmed {
    /// Admitted profile id.
    profile_id: String,
    /// Staged object bytes the native source loads.
    elf: Vec<u8>,
    /// Rebound evidence the decision matched.
    evidence: crate::capture::journal_admission::JournalRuntimeEvidence,
}

/// Budget bounds shared by the ordinary and journal-only paths.
fn check_record_budget(max_events_bytes: u64) -> Option<RunResult> {
    if max_events_bytes < MIN_RECORD_BYTES {
        return Some(RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: format!("budget {max_events_bytes} below 131072"),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        });
    }
    if max_events_bytes > MAX_RECORD_BYTES {
        return Some(RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: format!("budget {max_events_bytes} above 4294967296"),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        });
    }
    None
}

/// Resolve the journal object bytes: an explicit path wins
/// verbatim and is never root-joined, else the embedded
/// channel artifact. Unreadable or absent resolves to None,
/// which refuses at the object binding.
fn resolve_journal_object(explicit: &str) -> Option<Vec<u8>> {
    if !explicit.is_empty() {
        return std::fs::read(explicit).ok();
    }
    embedded_object("journal").map(|bytes| bytes.to_vec())
}

/// Strip the journal cap from a mixed capability list.
fn strip_journal_caps(capabilities: &str) -> String {
    capabilities
        .split(',')
        .filter(|item| *item != JOURNAL_CAP)
        .collect::<Vec<_>>()
        .join(",")
}

/// Record the rebound journal evidence on the run.
fn push_journal_evidence(
    evidence: &mut Vec<EvidenceItem>,
    profile_id: &str,
    rebound: &crate::capture::journal_admission::JournalRuntimeEvidence,
) {
    evidence.push(value_item(
        "journal.profile_id".to_string(),
        profile_id.to_string(),
    ));
    evidence.push(value_item(
        "journal.source".to_string(),
        format!(
            "{}/{}/{}",
            rebound.release, rebound.architecture, rebound.page_size
        ),
    ));
    evidence.push(value_item(
        "journal.config.sha256".to_string(),
        rebound.config_sha256.clone(),
    ));
    evidence.push(value_item(
        "journal.btf.sha256".to_string(),
        rebound.btf_sha256.clone(),
    ));
    evidence.push(value_item(
        "journal.object.sha256".to_string(),
        rebound.object_sha256.clone(),
    ));
}

/// Run one admitted journal-only capture.
///
/// Budget and time-namespace gates mirror the ordinary path;
/// ordinary profiles, receipts, and the kernel floor do not
/// apply (capability failures surface as prepare/attach
/// refusals instead). No load-replay tail: journal failures
/// are fixed messages with no verifier text to recover.
fn run_journal_only<W: WriterSource>(
    root: &str,
    opts: &RecordOptions,
    writer: &mut W,
    ready: JournalReadiness,
    elf: Vec<u8>,
) -> RunResult {
    if let Some(refusal) = check_record_budget(opts.max_events_bytes) {
        return refusal;
    }
    let timens = check_timens_live();
    if !timens.ok {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: "time namespace unverifiable".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    if timens.offset {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: "time namespace offset present".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    let mut cfg = CollectorConfig {
        duration_s: opts.duration_s,
        max_events_bytes: opts.max_events_bytes,
        output: opts.output.clone(),
        profile_id: ready.profile_id.clone(),
        pid: std::process::id() as i64,
        has_journal: true,
        journal_only: true,
        journal_callers: opts.journal_callers,
        journal_profile: ready.profile_id.clone(),
        strict: opts.strict,
        ..Default::default()
    };
    if let Some(boot_id) = read_boot_id(root) {
        cfg.has_boot_id = true;
        cfg.boot_id = boot_id;
    }
    push_journal_evidence(&mut cfg.evidence, &ready.profile_id, &ready.evidence);
    let mut kernel =
        AyaKernel::with_channels(Vec::new(), "", "", Vec::new(), false, Vec::new(), false);
    let mut journal = NativeJournalKernel::new();
    // No owned module is asserted on the recording host, so
    // owned-module caller labels stay unresolved (zeroed).
    journal.setup(elf, false);
    let mut clock = MonoClock::new();
    let mut signal = LiveSignalSource::new();
    let mut collector = Collector::new(cfg);
    collector.run_with_journal(&mut kernel, &mut journal, &mut clock, &mut signal, writer)
}

/// Run admission plus collection; return the raw outcome.
///
/// `root` is the evidence root ("" for the live host) and
/// `profiles_dir` holds `manifest.txt`. Absent bridge
/// and object paths are discovered (explicit user input
/// wins verbatim and is never root-joined). Pre-run
/// refusals return exit 3 with an empty end reason and
/// the diagnostic unprefixed; the caller adds its verb
/// prefix. The collector runs only on approval, so
/// refusals create no BPF or output resource.
pub fn run_collector_with<W: WriterSource>(
    root: &str,
    profiles_dir: &str,
    opts: RecordOptions,
    writer: &mut W,
) -> RunResult {
    let selection = match collection_selection(
        &opts.capabilities,
        opts.journal_callers,
        opts.has_device,
        !opts.journal_object.is_empty(),
    ) {
        Ok(selection) => selection,
        Err(_) => {
            return RunResult {
                exit_code: EXIT_INVALID,
                end_reason: String::new(),
                outcome: String::new(),
                diagnostic: "invalid capability/journal selector".to_string(),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: true,
            };
        }
    };
    // Capabilities the ordinary stage decides: journal requests
    // strip the journal cap after the journal admits, so the
    // ordinary decision never sees it.
    let mut ordinary_caps = opts.capabilities.clone();
    // Armed journal channel: readiness plus the staged object
    // bytes the native source loads.
    let mut journal_armed: Option<JournalArmed> = None;
    if selection.journal {
        // Admission precedes all native and output creation:
        // discover the candidate, rebind runtime evidence at
        // dispatch time, and admit only on an exact match.
        // Refusals carry the bare frozen code plus the failed
        // gate; readiness arms the channel (journal-only runs
        // its own path, mixed requests fall through to ordinary
        // admission below).
        let binding = match discover_journal_binding(profiles_dir, &opts.profile, opts.has_profile)
        {
            Ok(binding) => binding,
            Err(failure) => {
                return RunResult {
                    exit_code: EXIT_REFUSAL,
                    end_reason: String::new(),
                    outcome: String::new(),
                    diagnostic: JOURNAL_NOT_ADMITTED.to_string(),
                    fix: fix_for_discovery(failure),
                    code: String::new(),
                    unknown: false,
                    trusted: true,
                };
            }
        };
        let elf = resolve_journal_object(&opts.journal_object);
        let evidence = gather_journal_evidence(root, elf.as_deref());
        let sub = JournalSelection {
            attempts: false,
            journal: true,
            callers: selection.callers,
        };
        match admit_journal(sub, false, &binding, &evidence) {
            JournalDispatch::Refused(refusal) => {
                return RunResult {
                    exit_code: refusal.exit_code,
                    end_reason: String::new(),
                    outcome: String::new(),
                    diagnostic: refusal.reason,
                    fix: refusal.fix,
                    code: String::new(),
                    unknown: false,
                    trusted: true,
                };
            }
            JournalDispatch::Ready(ready) => {
                if !selection.attempts {
                    return run_journal_only(root, &opts, writer, ready, elf.unwrap_or_default());
                }
                ordinary_caps = strip_journal_caps(&opts.capabilities);
                journal_armed = Some(JournalArmed {
                    profile_id: ready.profile_id.clone(),
                    elf: elf.unwrap_or_default(),
                    evidence: ready.evidence.clone(),
                });
            }
        }
    }
    if let Some(refusal) = check_record_budget(opts.max_events_bytes) {
        return refusal;
    }
    // The statically linked loader needs no bridge file:
    // an empty bridge is the normal case, not a refusal.
    // The snapshot's open file description feeds the
    // admission hash and the provenance below, so no
    // pathname swap can slip a different bridge between
    // the receipt check and the run. An unreadable
    // bridge hashes to "": receipts cannot admit
    // local-auto, and provenance marks the identity
    // uncheckable.
    let bridge = resolve_bridge(&opts.bridge, opts.has_bridge);
    let snap = open_bridge_snapshot(&bridge);
    let bridge_sha = snap.sha.clone();
    let mut bridge_v = LiveValue {
        state: String::new(),
        value: String::new(),
        detail: String::new(),
    };
    if !bridge_sha.is_empty() {
        bridge_v.state = "value".to_string();
        bridge_v.value = bridge_sha.clone();
    } else if bridge.is_empty() {
        bridge_v.state = "uncheckable".to_string();
        bridge_v.detail = "no bridge file (statically linked loader)".to_string();
    } else {
        bridge_v.state = "uncheckable".to_string();
        bridge_v.detail = "bridge unreadable".to_string();
    }
    let object_path = resolve_object(&opts.object);
    let lc_object = resolve_object(&opts.lc_object);
    let cp_object = resolve_object(&opts.cp_object);
    let reader = match open_evidence_reader(root) {
        Ok(reader) => reader,
        Err(e) => {
            return RunResult {
                exit_code: EXIT_REFUSAL,
                end_reason: String::new(),
                outcome: String::new(),
                diagnostic: format!("cannot open evidence: {e}"),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
    };
    let env = detect_environment(&reader);
    if !env.kernel.eligible_floor {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: format!("kernel {} below floor 6.0", env.kernel.release),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    let profiles = match load_profiles(profiles_dir) {
        Ok(profiles) => profiles,
        Err(e) => {
            return RunResult {
                exit_code: EXIT_REFUSAL,
                end_reason: String::new(),
                outcome: String::new(),
                diagnostic: format!("cannot load profiles: {e}"),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
    };
    // Mixed journal requests arrive with the journal cap already
    // stripped: the ordinary decision sees ordinary caps only.
    let decision = decide_record(
        root,
        &env.kernel,
        &profiles,
        &opts.profile,
        opts.has_profile,
        &object_path,
        &lc_object,
        &cp_object,
        &ordinary_caps,
        profiles_dir,
        &bridge_sha,
    );
    if !decision.ok {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: decision.refusal.clone(),
            fix: decision.fix.clone(),
            code: decision.refusal_code.clone(),
            unknown: decision.refusal_unknown,
            trusted: true,
        };
    }
    let timens = check_timens_live();
    if !timens.ok {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: "time namespace unverifiable".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    if timens.offset {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: "time namespace offset present".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    if decision.off_loc < 0
        || decision.off_size < 0
        || decision.off_force < 0
        || decision.off_fixed_end < 0
    {
        return RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: String::new(),
            outcome: String::new(),
            diagnostic: "admission did not probe offsets".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: true,
        };
    }
    // Live captures sample the default SWIOTLB pool counters at
    // start, periodically, and close; unreadable counters stay
    // in the samples as unavailable halves, never as failed runs.
    let mut cfg = CollectorConfig {
        duration_s: opts.duration_s,
        max_events_bytes: opts.max_events_bytes,
        output: opts.output.clone(),
        profile_id: decision.profile.profile_id.clone(),
        grade: decision.kind.clone(),
        off_loc: decision.off_loc,
        off_size: decision.off_size,
        off_force: decision.off_force,
        off_fixed_end: decision.off_fixed_end,
        has_pool_sample: true,
        pid: std::process::id() as i64,
        has_ring_bytes: true,
        ring_bytes: decision.ring_bytes as u32,
        has_lifecycle: decision.lc.present,
        lifecycle_ring_bytes: decision.lc.ring_bytes as u32,
        has_copy: decision.cp.present,
        copy_ring_bytes: decision.cp.ring_bytes as u32,
        has_device_filter: opts.has_device,
        device_filter: opts.device.clone(),
        strict: opts.strict,
        ..Default::default()
    };
    if let Some(armed) = &journal_armed {
        cfg.has_journal = true;
        cfg.journal_only = false;
        cfg.journal_callers = opts.journal_callers;
        cfg.journal_profile = armed.profile_id.clone();
    }
    if let Some(boot_id) = read_boot_id(root) {
        cfg.has_boot_id = true;
        cfg.boot_id = boot_id;
    }
    cfg.guest = env.guest.clone();
    cfg.evidence.push(decision_item(decision.reason.clone()));
    cfg.evidence.push(value_item(
        "object.sha256".to_string(),
        decision.object_sha.clone(),
    ));
    cfg.evidence.push(value_item(
        "ring.bytes".to_string(),
        format!("{}", decision.ring_bytes),
    ));
    cfg.evidence.push(value_item(
        "capabilities.selected".to_string(),
        decision.selected_caps.clone(),
    ));
    let loss_bound = attempt_loss_evidence(&env.kernel.release);
    for item in &loss_bound {
        cfg.evidence.push(item.clone());
    }
    cfg.attempt_loss_lower_bound = !attempt_loss_exact(&env.kernel.release);
    append_channel_evidence(&mut cfg.evidence, "lc", &decision.lc);
    append_channel_evidence(&mut cfg.evidence, "cp", &decision.cp);
    append_layout_evidence(&mut cfg.evidence, &decision.layout_evidence);
    if env.kernel.release.is_empty() {
        cfg.evidence.push(value_item(
            "kernel.release".to_string(),
            "unavailable: release unknown".to_string(),
        ));
    } else {
        cfg.evidence.push(value_item(
            "kernel.release".to_string(),
            env.kernel.release.clone(),
        ));
    }
    cfg.evidence.push(render_provenance(
        "kernel.build_id",
        &decision.measured_image_bid,
    ));
    cfg.evidence.push(render_provenance(
        "config.sha256",
        &decision.measured_config,
    ));
    let mut config_src = LiveValue {
        state: String::new(),
        value: String::new(),
        detail: String::new(),
    };
    if !decision.measured_config_src.is_empty() {
        config_src.state = "value".to_string();
        config_src.value = decision.measured_config_src.clone();
    }
    cfg.evidence
        .push(render_provenance("config.src", &config_src));
    cfg.evidence
        .push(render_provenance("btf.sha256", &decision.measured_btf));
    cfg.evidence.push(render_provenance(
        "format.sha256",
        &decision.measured_format,
    ));
    cfg.evidence
        .push(render_provenance("image.sha256", &decision.measured_image));
    cfg.evidence
        .push(render_provenance("bridge.sha256", &bridge_v));
    cfg.evidence.push(value_item(
        "bridge.abi".to_string(),
        "abi-v1 (required)".to_string(),
    ));
    if let Some(armed) = &journal_armed {
        push_journal_evidence(&mut cfg.evidence, &armed.profile_id, &armed.evidence);
    }
    let mut kernel = AyaKernel::with_channels(
        decision.elf.clone(),
        &decision.tp_system,
        &decision.tp_event,
        decision.lc.elf.clone(),
        decision.lc.present,
        decision.cp.elf.clone(),
        decision.cp.present,
    );
    let mut clock = MonoClock::new();
    let mut signal = LiveSignalSource::new();
    let mut collector = Collector::new(cfg);
    let mut journal = NativeJournalKernel::new();
    if let Some(armed) = &journal_armed {
        // No owned module is asserted on the recording host, so
        // owned-module caller labels stay unresolved (zeroed).
        journal.setup(armed.elf.clone(), false);
    }
    let mut out = if journal_armed.is_some() {
        collector.run_with_journal(&mut kernel, &mut journal, &mut clock, &mut signal, writer)
    } else {
        collector.run(&mut kernel, &mut clock, &mut signal, writer)
    };
    // Retain the bridge snapshot through the run above and
    // the load replay below: this explicit binding keeps
    // the fd open across the whole collection.
    let _snap = snap;
    let mut replay_lines = false;
    // One parse feeds routing, replay eligibility, and the stamp
    // below: the three read the same structure, never free text.
    let refusal = parse_load_refusal(&out.diagnostic);
    if is_load_errno_failure(refusal.as_ref()) {
        let fail_ch = load_fail_channel(refusal.as_ref());
        let diag: LoadDiag = if fail_ch == 1 {
            diagnose_load(&decision.lc.elf, &lifecycle_program_names())
        } else if fail_ch == 2 {
            diagnose_load(&decision.cp.elf, &copy_program_names())
        } else {
            diagnose_load(&decision.elf, &attempt_program_names())
        };
        for line in &diag.lines {
            out.diagnostic += &format!("\n{line}");
        }
        replay_lines = !diag.lines.is_empty();
    }
    stamp_parsed_refusal_code(&mut out, replay_lines, refusal.as_ref());
    out
}

/// Fix for a stamped load/attach refusal code: the shared remedy,
/// except a verifier rejection earns the evidence-aware text —
/// link-phase wording when the blamed segment failed linking an
/// already loaded program (the link step itself has no verifier
/// log), otherwise the
/// shared tail pointer when replay lines exist and the honest
/// lineless text when they do not. A refusal that yields no lines
/// (the blamed object loads fine, as in a link failure) fails
/// honest here, never silent with a promise of absent lines.
fn refusal_fix(code: &str, replay_lines: bool, link_phase: bool) -> String {
    if code == "verifier-rejected" && link_phase {
        return "the program loaded but the kernel refused to attach it; run as root and check the attach target".to_string();
    }
    if code == "verifier-rejected" && !replay_lines {
        return "the kernel verifier rejected the object; no verifier lines were recovered"
            .to_string();
    }
    remedy_for(code)
}

/// Stamp a parsed load/attach refusal onto a codeless refusal.
///
/// The collector reports the diagnostic without a machine code;
/// the parsed code (and its phase-aware remedy) stamps the
/// result so record agrees with the load-check doctor.
/// `replay_lines` tells whether the refusal replay appended
/// verifier lines, so the remedy never promises absent lines.
/// Non-refusals and already-coded results pass through untouched.
fn stamp_parsed_refusal_code(
    out: &mut RunResult,
    replay_lines: bool,
    refusal: Option<&LoadRefusal>,
) {
    if out.exit_code == EXIT_REFUSAL
        && out.code.is_empty()
        && let Some(parsed) = refusal
    {
        out.code = parsed.code.clone();
        let code = out.code.clone();
        out.fix = refusal_fix(&code, replay_lines, parsed.link_phase);
    }
}

/// Stamp a load/attach refusal code onto a codeless refusal.
///
/// Parses the diagnostic once, then stamps from the parse: the
/// offline shape of the record refusal path, where the live path
/// threads its own earlier parse through instead.
#[cfg(test)]
fn stamp_load_refusal_code(out: &mut RunResult, replay_lines: bool) {
    let refusal = parse_load_refusal(&out.diagnostic);
    stamp_parsed_refusal_code(out, replay_lines, refusal.as_ref());
}

/// Warn-once line for a failed ownership repair, with newline.
///
/// The record-flow wording stays fixed across callers:
/// live top and the qualify smoke reuse the record
/// flow, so their repair warnings keep the record
/// prefix, as before.
pub fn ownership_warning(uid: i64, gid: i64) -> String {
    format!("memveil record: warning: cannot restore capture ownership to {uid}:{gid}\n")
}

/// Restore a finalized capture's ownership; warn, or "".
///
/// Best-effort hand-back of a root-made capture to the
/// invoking user through the writer's finalize pin
/// (dev/inode continuity; only the recorded dir and
/// files transfer). Returns the warn-once line when an
/// attempted repair did not hold, else "": the capture
/// stands either way. Call only for a finalized
/// outcome; never raises.
pub fn repair_warning_for<W: WriterSource>(output: &str, writer: &W) -> String {
    let repair = restore_capture_ownership(output, &writer.finalized_identity());
    if repair.attempted && !repair.repaired {
        return ownership_warning(repair.uid, repair.gid);
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::{
        ExtraChannel, RecordOptions, ScanDecision, attempt_loss_evidence, decide_record,
        is_load_errno_failure, load_fail_channel, loadcheck_bridge_sha, ownership_warning,
        parse_requested_caps, refusal_fix, render_provenance, repair_warning_for, resolve_bridge,
        resolve_channel_object, resolve_object, run_collector_with, split_site,
        stamp_load_refusal_code,
    };
    use crate::bpf::session::{Channel, SessionError, format_failed_link, spec_for_program};
    use crate::capture::collector::EXIT_REFUSAL;
    use crate::capture::collector::script::{
        ScriptClock, ScriptKernel, ScriptSignal, ScriptWriter, zeros,
    };
    use crate::capture::collector::{Collector, CollectorConfig, EXIT_OK, RunResult};
    use crate::capture::kernel::session_message;
    use crate::capture::live::WriterSource;
    use crate::capture::loadcheck::parse_load_refusal;
    use crate::cli::report::refusal_stderr_lines;
    use crate::platform::evidence::KernelInfo;
    use crate::platform::narrow::LiveValue;
    use crate::platform::outcome::OpOut;
    use crate::platform::profiles::load_profiles;
    use crate::platform::test_support::{TestDir, repo_root};

    fn fixture(path: &str) -> String {
        repo_root()
            .join(path)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    fn live_value(state: &str, value: &str, detail: &str) -> LiveValue {
        LiveValue {
            state: state.to_string(),
            value: value.to_string(),
            detail: detail.to_string(),
        }
    }

    #[test]
    fn caps_parse_matrix() {
        let empty = parse_requested_caps("");
        assert!(empty.ok);
        assert_eq!(empty.caps, vec!["attempt-trace".to_string()]);
        let all = parse_requested_caps("all");
        assert!(all.ok);
        assert_eq!(all.caps.len(), 3);
        assert_eq!(all.caps[1], "mapping-lifecycle");
        assert_eq!(all.caps[2], "copy-actual");
        let dup = parse_requested_caps("attempt-trace,copy-actual,attempt-trace");
        assert!(!dup.ok);
        assert_eq!(dup.err, "duplicate capability: attempt-trace");
        let bad = parse_requested_caps("attempt-trace,,copy-actual");
        assert!(!bad.ok);
        assert_eq!(bad.err, "bad capability list");
        let unknown = parse_requested_caps("attempt-trace,nope");
        assert!(!unknown.ok);
        assert_eq!(unknown.err, "unknown capability: nope");
        // Ordinary channels without the base resolve it implicitly.
        let lifecycle = parse_requested_caps("mapping-lifecycle");
        assert!(lifecycle.ok);
        assert_eq!(lifecycle.caps, vec!["attempt-trace", "mapping-lifecycle"]);
        let noattempt = parse_requested_caps("copy-actual");
        assert!(noattempt.ok);
        assert_eq!(noattempt.caps, vec!["attempt-trace", "copy-actual"]);
        // Journal-only lists parse without attempt hooks;
        // mixed journal/ordinary lists keep attempts present.
        let journal = parse_requested_caps("conversion-journal");
        assert!(journal.ok);
        assert_eq!(journal.caps, vec!["conversion-journal".to_string()]);
        let observe = parse_requested_caps("conversion-observe");
        assert!(observe.ok);
        let mixed_journal = parse_requested_caps("copy-actual,conversion-journal");
        assert!(mixed_journal.ok);
        assert_eq!(mixed_journal.caps[0], "attempt-trace");
        let mixed_ok = parse_requested_caps("attempt-trace,conversion-journal");
        assert!(mixed_ok.ok);
    }

    fn scan_kernel() -> KernelInfo {
        KernelInfo {
            release: "7.0.0-test".to_string(),
            arch: "x86_64".to_string(),
            eligible_floor: true,
            floor_reason: String::new(),
        }
    }

    fn scan_profiles() -> Vec<crate::platform::profiles::Profile> {
        load_profiles(&fixture("tests/fixtures/scan/profiles")).expect("load profiles")
    }

    #[test]
    fn service_extra_channels_grouped() {
        // Requested extras verify as artifacts and land
        // grouped per channel (bytes, hash, ring), never
        // partial: the decision carries all three objects.
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            &fixture("tests/fixtures/scan/profiles/valid-lc.json"),
            true,
            &fixture("tests/fixtures/elf/ok.o"),
            &fixture("tests/fixtures/elf/lc-ok.o"),
            &fixture("tests/fixtures/elf/cp-ok.o"),
            "attempt-trace,mapping-lifecycle,copy-actual",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(decision.ok, "{}", decision.refusal);
        assert_eq!(decision.kind, "validated");
        assert_eq!(decision.ring_bytes, 8388608);
        assert!(decision.lc.present);
        assert!(decision.cp.present);
        assert_eq!(decision.lc.ring_bytes, 33554432);
        assert_eq!(decision.cp.ring_bytes, 33554432);
        // Hashes bind the exact admitted bytes.
        assert_eq!(decision.object_sha.len(), 64);
        assert_eq!(decision.lc.object_sha.len(), 64);
        assert_eq!(decision.cp.object_sha.len(), 64);
        assert!(!decision.elf.is_empty());
        assert!(!decision.lc.elf.is_empty());
        assert!(!decision.cp.elf.is_empty());
        assert_eq!(
            decision.selected_caps,
            "attempt-trace,mapping-lifecycle,copy-actual"
        );
    }

    #[test]
    fn service_unknown_profile_refuses() {
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "no-such-profile",
            true,
            &fixture("tests/fixtures/elf/ok.o"),
            "",
            "",
            "",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert!(decision.refusal.contains("unknown --profile"));
        assert_eq!(decision.refusal_code, "profile");
    }

    #[test]
    fn service_bad_caps_refuse() {
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            &fixture("tests/fixtures/elf/ok.o"),
            "",
            "",
            "attempt-trace,nope",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert!(decision.refusal.contains("unknown capability"));
    }

    #[test]
    fn service_conversion_cap_refuses() {
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            &fixture("tests/fixtures/elf/ok.o"),
            "",
            "",
            "attempt-trace,conversion-observe",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert!(
            decision
                .refusal
                .contains("conversion-observe has no record channel")
        );
    }

    #[test]
    fn service_journal_cap_refuses() {
        let profiles = scan_profiles();
        for want in ["conversion-journal", "attempt-trace,conversion-journal"] {
            let decision = decide_record(
                &fixture("tests/fixtures/scan/ok"),
                &scan_kernel(),
                &profiles,
                "",
                false,
                &fixture("tests/fixtures/elf/ok.o"),
                "",
                "",
                want,
                &fixture("tests/fixtures/scan/profiles"),
                "",
            );
            assert!(!decision.ok, "{want}");
            assert_eq!(decision.refusal, "journal_profile_not_admitted", "{want}");
        }
    }

    #[test]
    fn service_unreadable_object_refuses() {
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            "/nonexistent/object.o",
            "",
            "",
            "",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert_eq!(decision.refusal, "object unreadable");
    }

    #[test]
    fn service_no_coverage_refuses() {
        let profiles = scan_profiles();
        let kernel = KernelInfo {
            release: "7.0.0-test".to_string(),
            arch: "riscv64".to_string(),
            eligible_floor: true,
            floor_reason: String::new(),
        };
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &kernel,
            &profiles,
            "",
            false,
            &fixture("tests/fixtures/elf/ok.o"),
            "",
            "",
            "",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert_eq!(decision.refusal, "no profile covers this kernel");
    }

    #[test]
    fn service_missing_extra_object_refuses() {
        // An explicit unreadable extra object names its channel.
        let profiles = scan_profiles();
        let decision = decide_record(
            &fixture("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            &fixture("tests/fixtures/elf/ok.o"),
            "/nonexistent/lc.o",
            "",
            "attempt-trace,mapping-lifecycle",
            &fixture("tests/fixtures/scan/profiles"),
            "",
        );
        assert!(!decision.ok);
        assert_eq!(decision.refusal, "lc object unreadable");
    }

    #[test]
    fn split_site_matrix() {
        assert_eq!(
            split_site("swiotlb:swiotlb_bounced"),
            Some(("swiotlb".to_string(), "swiotlb_bounced".to_string()))
        );
        assert_eq!(split_site("nosite"), None);
        assert_eq!(split_site(":evt"), None);
        assert_eq!(split_site("sys:"), None);
        assert_eq!(split_site("a:b:c"), None);
        assert_eq!(split_site("sy-s:evt"), None);
        assert_eq!(split_site("sys:ev t"), None);
    }

    #[test]
    fn render_provenance_matrix() {
        let v = render_provenance("k", &live_value("value", "ab12", ""));
        assert_eq!(v.interpretation, "ab12");
        let u = render_provenance("k", &live_value("", "", ""));
        assert_eq!(u.interpretation, "unavailable: narrow identity unverified");
        let s = render_provenance("k", &live_value("mismatch", "", ""));
        assert_eq!(s.interpretation, "unavailable: mismatch");
        let d = render_provenance("k", &live_value("uncheckable", "", "denied"));
        assert_eq!(d.interpretation, "unavailable: uncheckable: denied");
    }

    #[test]
    fn ownership_warning_shape() {
        assert_eq!(
            ownership_warning(1000, 100),
            "memveil record: warning: cannot restore capture ownership to 1000:100\n"
        );
    }

    #[test]
    fn resolve_object_explicit_verbatim() {
        assert_eq!(resolve_object("/x/y.o"), "/x/y.o");
        assert_eq!(resolve_object(""), "");
    }

    #[test]
    fn resolve_channel_object_explicit_or_embedded() {
        // Explicit bytes win verbatim; an empty path falls back to
        // the embedded artifact; unknown kinds and missing files
        // refuse. Admission and load-check share this rule.
        for kind in ["attempt", "lifecycle", "copy", "journal"] {
            let got = resolve_channel_object("", kind).expect("embedded bytes");
            let want = crate::platform::runtime::embedded_object(kind).expect("embedded");
            assert_eq!(got, want.to_vec());
        }
        assert!(resolve_channel_object("", "bogus").is_err());
        assert!(resolve_channel_object("tests/fixtures/elf/no-such.o", "attempt").is_err());
        let path = fixture("tests/fixtures/elf/ok.o");
        let got = resolve_channel_object(&path, "attempt").expect("explicit bytes");
        assert_eq!(got, std::fs::read(&path).expect("read fixture"));
    }

    #[test]
    fn resolve_bridge_explicit_verbatim() {
        assert_eq!(resolve_bridge("/x/y.so", true), "/x/y.so");
    }

    #[test]
    fn loadcheck_bridge_sha_empty() {
        // No bridge anywhere: empty hash, never raises.
        let sha = loadcheck_bridge_sha("/nonexistent-bridge.so", true);
        assert_eq!(sha, "");
    }

    #[test]
    fn attempt_loss_evidence_matrix() {
        assert!(attempt_loss_evidence("7.3.0").is_empty());
        let old = attempt_loss_evidence("6.1.0");
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].item_type, "attempt-loss-bound");
        assert!(old[0].interpretation.contains("lower bound before 6.7"));
    }

    struct NullWriter;

    impl WriterSource for NullWriter {
        fn create(&mut self, _path: &str, _budget: u64) -> crate::capture::live::CreateOut {
            crate::capture::live::CreateOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }
        fn append(&mut self, _line: &[u8]) -> crate::capture::live::AppendOut {
            crate::capture::live::AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }
        fn append_closing(&mut self, _line: &[u8]) -> crate::capture::live::AppendOut {
            self.append(_line)
        }
        fn group_begin(&mut self) -> crate::capture::live::GroupOut {
            crate::capture::live::GroupOut {
                ok: true,
                mark: 0,
                kind: String::new(),
            }
        }
        fn group_abort(&mut self, _mark: u64) -> crate::capture::live::AppendOut {
            self.append(&[])
        }
        fn checkpoint(&mut self, _session: &[u8]) -> crate::capture::live::AppendOut {
            self.append(&[])
        }
        fn finalize(&mut self, _session: &[u8]) -> crate::capture::live::FinalOut {
            crate::capture::live::FinalOut {
                status: "finalized".to_string(),
                note: String::new(),
            }
        }
        fn abandon(&mut self) -> String {
            String::new()
        }
        fn discard(&mut self) {}
        fn committed_len(&self) -> u64 {
            0
        }
        fn finalized_identity(&self) -> Vec<u64> {
            Vec::new()
        }
    }

    fn run_opts() -> RecordOptions {
        RecordOptions {
            output: "/nonexistent-refusal/cap".to_string(),
            bridge: "test-bridge".to_string(),
            has_bridge: true,
            ..Default::default()
        }
    }

    #[test]
    fn service_run_bad_budgets_refuse() {
        // Budgets gate before any resource exists.
        for budget in [131071u64, 4294967297u64] {
            let mut opts = run_opts();
            opts.max_events_bytes = budget;
            let mut writer = NullWriter;
            let out = run_collector_with("", "", opts, &mut writer);
            assert_eq!(out.exit_code, EXIT_REFUSAL);
            assert!(out.diagnostic.contains("budget"));
            assert!(out.trusted);
        }
    }

    #[test]
    fn service_run_no_bridge_proceeds() {
        // The statically linked loader needs no bridge
        // file: an empty bridge proceeds to evidence,
        // which "" (live host) opens, then to profiles.
        let tmp = TestDir::create("memveil-run").expect("mkdtemp");
        let mut opts = run_opts();
        opts.has_bridge = false;
        opts.bridge = String::new();
        opts.profiles_dir = format!("{}/no-profiles", tmp.as_str());
        let mut writer = NullWriter;
        let out = run_collector_with("", &opts.profiles_dir.clone(), opts, &mut writer);
        assert_eq!(out.exit_code, EXIT_REFUSAL);
        // Past bridge resolution, the missing profiles dir refuses.
        assert!(out.diagnostic.contains("cannot load profiles"));
        assert!(!out.trusted);
    }

    #[test]
    fn service_run_cannot_open_evidence() {
        let opts = run_opts();
        let mut writer = NullWriter;
        let out = run_collector_with("/nonexistent-evidence-root-xyz", "", opts, &mut writer);
        assert_eq!(out.exit_code, EXIT_REFUSAL);
        assert!(out.diagnostic.contains("cannot open evidence"));
        assert!(!out.trusted);
    }

    #[test]
    fn service_run_cannot_load_profiles() {
        let tmp = TestDir::create("memveil-run").expect("mkdtemp");
        let mut opts = run_opts();
        opts.profiles_dir = format!("{}/no-profiles", tmp.as_str());
        let mut writer = NullWriter;
        let out = run_collector_with("", &opts.profiles_dir.clone(), opts, &mut writer);
        assert_eq!(out.exit_code, EXIT_REFUSAL);
        assert!(out.diagnostic.contains("cannot load profiles"));
        assert!(!out.trusted);
    }

    #[test]
    fn repair_warning_unattempted_empty() {
        // No finalize pin, no sudo: nothing attempted, no warning.
        let writer = NullWriter;
        assert_eq!(repair_warning_for("/tmp/whatever", &writer), "");
    }

    #[test]
    fn scan_decision_defaults_unprobed() {
        let d = ScanDecision::default();
        assert!(!d.ok);
        assert_eq!(d.off_loc, -1);
        assert_eq!(d.off_size, -1);
        assert_eq!(d.off_force, -1);
        assert_eq!(d.off_fixed_end, -1);
        assert!(!d.lc.present);
        assert!(!d.cp.present);
    }

    #[test]
    fn extra_channel_default_absent() {
        let c = ExtraChannel::default();
        assert!(!c.present);
        assert!(c.elf.is_empty());
    }

    fn failed_out(message: &str) -> OpOut {
        OpOut {
            ok: false,
            message: message.to_string(),
        }
    }

    /// Drive one scripted refusal through the collector and the
    /// refusal-code stamp: the offline shape of the record
    /// refusal path.
    fn run_scripted_refusal(tmp: &TestDir, load_out: OpOut, attach_out: OpOut) -> RunResult {
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "refuse-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.load_out = load_out;
        kernel.attach_out = attach_out;
        zeros(&mut kernel, 2, 2);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let mut result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        // The scripted path performs no verifier replay, so the
        // stamp never promises replay lines here.
        stamp_load_refusal_code(&mut result, false);
        result
    }

    fn ok_out() -> OpOut {
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    /// The exact attach-path nested-load diagnostic the kernel
    /// layer reports when the verifier rejects a program load
    /// during attach.
    fn nested_attach_failure() -> String {
        "ch2 op=3 domain=2 code=-13 EACCES: verifier rejected, see log: copy channel program `mv_bounce`: load for swiotlb_bounce failed: Permission denied (os error 13)".to_string()
    }

    #[test]
    fn attach_nested_refusal_emits_code_line() {
        // Attach-path nested load rejection: exit 3, no
        // capture, and the exact verifier-rejected code line.
        let tmp = TestDir::create("memveil-refuse").expect("mkdtemp");
        let failed = nested_attach_failure();
        let result = run_scripted_refusal(&tmp, ok_out(), failed_out(&failed));
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.end_reason, "unknown");
        assert_eq!(result.outcome, "refused");
        assert_eq!(result.diagnostic, format!("attach: {failed}"));
        assert!(
            !std::path::Path::new(&format!("{}/cap", tmp.as_str())).exists(),
            "a refused record leaves no capture"
        );
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
        // The scripted path performs no verifier replay, so its
        // lineless diagnostic earns the honest remedy, not the tail
        // pointer the live path shows above real replay lines.
        assert_eq!(
            lines[2],
            "memveil record: fix: the kernel verifier rejected the object; no verifier lines were recovered\n"
        );
    }

    #[test]
    fn attach_link_refusal_emits_code_line() {
        // Ordinary link failure, same errno: classified by the
        // errno, not by nested-load wording. The site marker —
        // not the cause text — steers the remedy, so even this
        // older producer shape (verifier cause, link site) earns
        // the honest link wording.
        let tmp = TestDir::create("memveil-refuse").expect("mkdtemp");
        let failed = "ch2 op=3 domain=2 code=-13 EACCES: verifier rejected, see log: copy channel program `mv_bounce`: attach to swiotlb_bounce failed: Permission denied (os error 13)".to_string();
        let result = run_scripted_refusal(&tmp, ok_out(), failed_out(&failed));
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.outcome, "refused");
        assert_eq!(result.diagnostic, format!("attach: {failed}"));
        assert!(
            !std::path::Path::new(&format!("{}/cap", tmp.as_str())).exists(),
            "a refused record leaves no capture"
        );
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
        assert_eq!(
            lines[2],
            "memveil record: fix: the program loaded but the kernel refused to attach it; run as root and check the attach target\n"
        );
    }

    #[test]
    fn load_phase_refusal_emits_code_line() {
        // Load-phase refusal with the same errno: the
        // precedent pin for the attach-path contract.
        let tmp = TestDir::create("memveil-refuse").expect("mkdtemp");
        let failed = "ch0 op=2 domain=2 code=-13 EACCES: verifier rejected, see log: attempt channel: load failed: Permission denied (os error 13)".to_string();
        let result = run_scripted_refusal(&tmp, failed_out(&failed), ok_out());
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.outcome, "refused");
        assert_eq!(result.diagnostic, format!("load: {failed}"));
        assert!(
            !std::path::Path::new(&format!("{}/cap", tmp.as_str())).exists(),
            "a refused record leaves no capture"
        );
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
    }

    #[test]
    fn real_link_errno_flows_to_code_line() {
        // A genuine ordinary-link failure end to end: the program
        // loads, then the raw-tracepoint link syscall refuses
        // EACCES and rollback succeeds (no suffix). Aya's Display
        // names only the failed call while the errno rides the
        // source chain, so every stage below must carry the real
        // errno without any injected code text.
        let error = aya::programs::ProgramError::from(aya::sys::SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error: std::io::Error::from_raw_os_error(libc::EACCES),
        });
        // Premise pin: the loader Display really is codeless, which
        // is why formatting it alone loses the errno.
        assert_eq!(error.to_string(), "`bpf_raw_tracepoint_open` failed");
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        let message = format_failed_link(&tag, &spec, &error);
        assert!(
            !message.contains("code=-13"),
            "the link message must not inject the code itself: {message}"
        );
        let oped = session_message(3, &SessionError::Attach(message));
        // Collector verb plus kernel channel tag wrap the segment.
        let diagnostic = format!("attach: ch2 {oped}");
        assert!(
            diagnostic.contains("op=3 domain=2 code=-13 EACCES"),
            "the op-3 segment carries the real errno: {diagnostic}"
        );
        let mut result = RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic,
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        };
        // A link failure's blamed object loads fine, so the replay
        // yields no lines; the remedy names the failed link
        // operation instead of the verifier, which never ran.
        stamp_load_refusal_code(&mut result, false);
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
        assert_eq!(
            lines[2],
            "memveil record: fix: the program loaded but the kernel refused to attach it; run as root and check the attach target\n"
        );
    }

    #[test]
    fn real_link_errno_carries_link_worded_diagnosis() {
        // A genuine ordinary-link failure end to end: the program
        // loads, then the raw-tracepoint link syscall refuses
        // EACCES. The machine code stays verifier-rejected per
        // the errno contract, but every human-readable word must
        // name the failed link operation — the program loaded fine
        // and only its link failed.
        let error = aya::programs::ProgramError::from(aya::sys::SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error: std::io::Error::from_raw_os_error(libc::EACCES),
        });
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        let message = format_failed_link(&tag, &spec, &error);
        let oped = session_message(3, &SessionError::Attach(message));
        let diagnostic = format!("attach: ch2 {oped}");
        assert!(
            oped.contains("attach refused"),
            "the cause names the failed link operation: {oped}"
        );
        assert!(
            !oped.contains("verifier rejected"),
            "a link failure never blames the verifier: {oped}"
        );
        let mut result = RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic,
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        };
        stamp_load_refusal_code(&mut result, false);
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
        assert_eq!(
            lines[2],
            "memveil record: fix: the program loaded but the kernel refused to attach it; run as root and check the attach target\n"
        );
    }

    /// Replay eligibility plus blamed channel for one
    /// diagnostic through the production call pattern: parse
    /// once, then route from the parse.
    fn replay_routing(diagnostic: &str) -> (bool, i64) {
        let refusal = parse_load_refusal(diagnostic);
        (
            is_load_errno_failure(refusal.as_ref()),
            load_fail_channel(refusal.as_ref()),
        )
    }

    #[test]
    fn load_fail_channel_recognizes_collector_verbs() {
        // The collector prefixes the first tagged segment with its
        // verb ("attach: ch2 ...", "load: ch1 ..."): the blamed
        // channel hides behind ": ", not just the string start or
        // a join separator. Missing it replays the attempt object
        // instead of the blamed one.
        assert_eq!(
            replay_routing(
                "attach: ch2 op=3 domain=2 code=-13 EACCES: verifier rejected, see log: copy channel program `mv_bounce`: load for swiotlb_bounce failed: Permission denied (os error 13)"
            ),
            (true, 2)
        );
        assert_eq!(
            replay_routing("load: ch1 op=2 domain=2 code=-22 EINVAL: x"),
            (true, 1)
        );
        // Bare tags, joins, and untagged diagnostics keep their
        // established shapes; a non-verifier errno classifies but
        // earns no replay.
        assert_eq!(replay_routing("ch2 op=3 domain=2 code=-13: x"), (true, 2));
        assert_eq!(
            replay_routing("ch0 op=2 domain=2: x; ch2 op=3 domain=2 code=-13: y"),
            (true, 2)
        );
        assert_eq!(
            replay_routing("load: ch0 op=2 domain=2 code=-1: x"),
            (false, 0)
        );
        assert_eq!(replay_routing("op=2 domain=2 code=-13: x"), (true, 0));
        // Two errno'd segments route to the first classifying
        // header — the one whose errno selects the stamped code —
        // never to a later tag the code ignores.
        assert_eq!(
            replay_routing("attach: ch2 op=3 domain=2 code=-13: x; ch1 op=2 domain=2 code=-13: y"),
            (true, 2)
        );
        // A rollback note names a channel without blaming it:
        // "rollback ch2:" carries a colon, never the tag's space,
        // and the codeless diagnostic replays nothing at all.
        assert_eq!(
            replay_routing("attach: ch0 op=2 domain=2: x; rollback ch2: detach failed"),
            (false, 0)
        );
    }

    #[test]
    fn codeless_diagnostic_replays_nothing() {
        // Replay eligibility and channel routing read the same
        // parsed refusal as the classifier: a codeless geometry
        // refusal whose free text happens to name a channel and
        // an errno replays no object at all.
        let diagnostic =
            "load: ch0 op=2 domain=2: attempt channel: unexpected map extra: ch2 note code=-13";
        assert_eq!(crate::capture::loadcheck::load_refusal_code(diagnostic), "");
        let refusal = parse_load_refusal(diagnostic);
        assert_eq!(refusal, None);
        assert!(
            !is_load_errno_failure(refusal.as_ref()),
            "a codeless diagnostic is never replay-eligible"
        );
        assert_eq!(load_fail_channel(refusal.as_ref()), 0);
    }

    #[test]
    fn blamed_channel_routing_follows_the_classifying_header() {
        // Genuine shapes route to the blamed object: the channel
        // tag of the header whose errno slot classified, with
        // untagged diagnostics replaying the attempt object.
        assert_eq!(
            replay_routing("attach: ch2 op=3 domain=2 code=-13 EACCES: x"),
            (true, 2)
        );
        assert_eq!(
            replay_routing("load: ch1 op=2 domain=2 code=-22 EINVAL: x"),
            (true, 1)
        );
        assert_eq!(
            replay_routing("ch0 op=2 domain=2: x; ch2 op=3 domain=2 code=-13: y"),
            (true, 2)
        );
        assert_eq!(replay_routing("op=2 domain=2 code=-13: x"), (true, 0));
        // A codeless later tag votes nothing: the blamed object is
        // the copy one even though ch1 is named.
        assert_eq!(
            replay_routing("attach: ch2 op=3 domain=2 code=-13: x; ch1 op=2 domain=2: y"),
            (true, 2)
        );
        // A non-verifier errno classifies but replays nothing:
        // only EINVAL/EACCES refusals carry verifier lines worth
        // recovering.
        assert_eq!(
            replay_routing("load: ch0 op=2 domain=2 code=-1 EPERM: x"),
            (false, 0)
        );
    }

    #[test]
    fn refusal_fix_honesty_matrix() {
        // Only the verifier remedy promises lines, so only it
        // branches on the replay evidence; link-phase refusals
        // name the failed attach instead, since the verifier
        // never ran; every other code keeps the shared remedy
        // either way.
        assert_eq!(
            refusal_fix("verifier-rejected", false, false),
            "the kernel verifier rejected the object; no verifier lines were recovered"
        );
        assert!(
            !refusal_fix("verifier-rejected", false, false).contains("lines above"),
            "a lineless remedy must not promise lines"
        );
        assert_eq!(
            refusal_fix("verifier-rejected", true, false),
            crate::platform::kernelgate::remedy_for("verifier-rejected")
        );
        assert!(
            refusal_fix("verifier-rejected", true, false).contains("lines above"),
            "real replay lines earn the tail pointer"
        );
        for replay_lines in [false, true] {
            let fix = refusal_fix("verifier-rejected", replay_lines, true);
            assert_eq!(
                fix,
                "the program loaded but the kernel refused to attach it; run as root and check the attach target"
            );
            assert!(
                !fix.contains("verifier"),
                "a link remedy never names the verifier: {fix}"
            );
        }
        for code in ["load-eperm", "load-enomem", "load-failed"] {
            let shared = crate::platform::kernelgate::remedy_for(code);
            assert_eq!(refusal_fix(code, false, false), shared);
            assert_eq!(refusal_fix(code, true, false), shared);
            assert_eq!(
                refusal_fix(code, false, true),
                shared,
                "the link flag only steers the verifier text"
            );
        }
    }

    #[test]
    fn attach_nested_refusal_with_lines_keeps_tail_pointer() {
        // The fixed live shape: the blamed-channel replay appends
        // real verifier lines to the diagnostic, so the stamp
        // keeps the shared tail-pointer remedy and the lines are
        // really above it in the rendered refusal line.
        let tmp = TestDir::create("memveil-refuse").expect("mkdtemp");
        let failed = nested_attach_failure();
        let mut result = run_scripted_refusal(&tmp, ok_out(), failed_out(&failed));
        assert_eq!(result.code, "verifier-rejected");
        // Replay the fixed production append verbatim: one newline
        // plus each tail line, then re-stamp with lines present.
        result.code.clear();
        result.fix.clear();
        result.diagnostic += "\n0: R1=ctx() R2=0";
        result.diagnostic += "\n1: R0=0";
        stamp_load_refusal_code(&mut result, true);
        assert_eq!(result.code, "verifier-rejected");
        let lines = refusal_stderr_lines("record", &result.diagnostic, &result.code, &result.fix);
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[1], "memveil record: code: verifier-rejected\n");
        assert_eq!(
            lines[2],
            "memveil record: fix: the kernel verifier rejected the object; see the verifier lines above\n"
        );
        assert!(
            lines[0].contains("R1=ctx()") && lines[0].contains("R0=0"),
            "the promised lines are really in the refusal line: {}",
            lines[0]
        );
    }

    #[test]
    fn refusal_stamp_base_control() {
        // Base control: finalized runs stay codeless and print
        // no code line; coded and unclassified refusals pass
        // through untouched. The finalized and pre-coded
        // controls carry a classifiable op-3 errno, so each
        // preservation guard is tested independently: without
        // its guard, the stamp would fire here.
        let classifiable =
            "ch2 op=3 domain=2 code=-13 EACCES: verifier rejected, see log: x".to_string();
        let mut done = RunResult {
            exit_code: EXIT_OK,
            end_reason: "complete".to_string(),
            outcome: "finalized".to_string(),
            diagnostic: classifiable.clone(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        };
        stamp_load_refusal_code(&mut done, false);
        assert!(done.code.is_empty());
        assert!(done.fix.is_empty());
        let lines = refusal_stderr_lines("record", "ready", &done.code, &done.fix);
        assert_eq!(lines, vec!["memveil record: ready\n".to_string()]);
        let mut coded = RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic: classifiable,
            fix: "check the lockdown state".to_string(),
            code: "tracefs-hidden".to_string(),
            unknown: false,
            trusted: false,
        };
        stamp_load_refusal_code(&mut coded, false);
        assert_eq!(coded.code, "tracefs-hidden");
        assert_eq!(coded.fix, "check the lockdown state");
        let mut other_op = RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic: "op=4 domain=2 code=-13: poll failed".to_string(),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        };
        stamp_load_refusal_code(&mut other_op, false);
        assert!(other_op.code.is_empty());
        assert!(other_op.fix.is_empty());
    }

    /// The genuine mv_bounce link-EACCES diagnostic, built exactly
    /// like `real_link_errno_flows_to_code_line`: the program
    /// loads, then the raw-tracepoint link syscall refuses EACCES.
    fn genuine_link_eacces_diagnostic() -> String {
        let error = aya::programs::ProgramError::from(aya::sys::SyscallError {
            call: "bpf_raw_tracepoint_open",
            io_error: std::io::Error::from_raw_os_error(libc::EACCES),
        });
        let spec = spec_for_program("mv_bounce").expect("copy channel bounce spec");
        let tag = format!("{} channel program `{}`", Channel::Copy, spec.program);
        let message = format_failed_link(&tag, &spec, &error);
        let oped = session_message(3, &SessionError::Attach(message));
        format!("attach: ch2 {oped}")
    }

    #[test]
    fn link_phase_verifier_rejection_replays_nothing() {
        // A genuine link denial parses link-phase with the
        // verifier-rejected machine code —
        // but the blamed program loaded fine and only its link
        // failed, so no replay may run (a replay would reach the next
        // program and append its foreign verifier log to this
        // link refusal). The machine code and link remedy stay.
        let diagnostic = genuine_link_eacces_diagnostic();
        let refusal = parse_load_refusal(&diagnostic).expect("a link errno classifies");
        assert_eq!(refusal.code, "verifier-rejected");
        assert_eq!(refusal.channel, 2);
        assert_eq!(refusal.op, 3);
        assert!(
            refusal.link_phase,
            "the blamed segment failed linking: {diagnostic}"
        );
        assert_eq!(
            replay_routing(&diagnostic),
            (false, 2),
            "a link-phase failure must not replay: {diagnostic}"
        );
        // The stamp still codes the refusal and words the remedy
        // for the failed link (no replay lines: nothing replayed).
        let mut result = RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic,
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        };
        stamp_load_refusal_code(&mut result, false);
        assert_eq!(result.code, "verifier-rejected");
        assert_eq!(
            result.fix,
            "the program loaded but the kernel refused to attach it; run as root and check the attach target"
        );
    }

    #[test]
    fn nested_load_phase_verifier_rejection_still_replays() {
        // Control: an attach-path nested program-load rejection
        // genuinely failed verification, so its blamed-channel
        // replay stays eligible.
        let diagnostic = format!("attach: {}", nested_attach_failure());
        let refusal = parse_load_refusal(&diagnostic).expect("a nested errno classifies");
        assert_eq!(refusal.code, "verifier-rejected");
        assert!(
            !refusal.link_phase,
            "a nested load failure is load-phase: {diagnostic}"
        );
        assert_eq!(
            replay_routing(&diagnostic),
            (true, 2),
            "a load-phase failure keeps its replay: {diagnostic}"
        );
    }

    #[test]
    fn link_phase_first_header_suppresses_later_load_replay() {
        // The first classifying header wins: when it is
        // link-phase, no replay runs even though a later segment
        // names a load-phase errno.
        let diagnostic = "attach: ch2 op=3 domain=2 code=-13 EACCES: attach refused: copy channel program `mv_bounce`: attach to swiotlb_bounce failed: Permission denied (os error 13); ch1 op=2 domain=2 code=-22 EINVAL: x";
        let refusal = parse_load_refusal(diagnostic).expect("the first errno classifies");
        assert_eq!(refusal.code, "verifier-rejected");
        assert_eq!(refusal.channel, 2);
        assert!(
            refusal.link_phase,
            "the classifying header is link-phase: {diagnostic}"
        );
        assert_eq!(
            replay_routing(diagnostic),
            (false, 2),
            "a link-phase classifying header suppresses replay: {diagnostic}"
        );
    }
}
