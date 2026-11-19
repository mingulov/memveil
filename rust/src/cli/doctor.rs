// SPDX-License-Identifier: GPL-3.0-or-later
//! memveil doctor: passive environment and capability report.
//!
//! `run_doctor` implements the `doctor` verb against the live host and
//! `profiles/`. `run_doctor_with` is the same flow against an explicit
//! evidence root and profiles directory, so tests drive fixtures through
//! the identical code path.
//!
//! Exit codes: 0 when attempt-trace is available (ready), 3 when the
//! requested collection is unavailable or unknown, 2 on usage or internal
//! errors (bad fixture header, unreadable profiles). The rendered report
//! goes to stdout and nothing else does; every diagnostic goes to stderr.
//! Only a broken standard error escapes as a failure.
//!
//! Text and `--json` render the same DoctorReport2; the JSON matches the
//! doctor-v0.1.1 schema exactly. Every interpolated evidence fragment is
//! sanitized for its sink.

use crate::capture::loadcheck::{LoadResult, LoadTarget, load_check, load_code_for};
use crate::capture::run::{
    attempt_program_names, copy_program_names, decide_record, lifecycle_program_names,
    loadcheck_bridge_sha, parse_requested_caps, resolve_object,
};
use crate::cli::report::{
    EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, EXIT_REFUSAL, sanitize_diagnostic, write_stderr,
};
use crate::platform::btf::read_object_map_bytes;
use crate::platform::capabilities::attempt_loss_exact;
use crate::platform::evidence::{EnvironmentEvidence, GuestInfo, KernelInfo, detect_environment};
use crate::platform::kernelgate::{BtfFacts, LockdownState, kernel_gate, remedy_for};
use crate::platform::prechecks::{PreCheck, check_memcg, check_privilege, check_unprivileged_bpf};
use crate::platform::profiles::{Profile, load_profiles, manifest_readable, select_profile_bound};
use crate::platform::reader::{
    EVIDENCE_ABSENT, EVIDENCE_OK, EvidenceError, EvidenceReader, bytes_to_text, file_state,
    open_evidence_reader, read_evidence, read_host_file, readlink_self,
};
use crate::platform::stdout::write_stdout;
use crate::render::json::escape_json;

/// Unavailable collection: the requested set is not ready.
pub const EXIT_UNAVAILABLE: i64 = EXIT_REFUSAL;
const ZLIB: &str = "libz.so.1";
const OBJECT_BYTES_CAP: usize = 67108864;
const CMDLINE_CAP: usize = 65536;
const NSLABS_CAP: usize = 64;

/// Usage text for the doctor verb.
pub fn doctor_usage() -> String {
    concat!(
        "usage: memveil doctor [--json] [--profiles-dir DIR]",
        " [--capability LIST] [--object PATH] [--lc-object PATH]",
        " [--cp-object PATH] [--bridge PATH] [--load-check]\n",
        "\n",
        "Judge every requested capability through record admission\n",
        "and print one environment and capability report on stdout.\n",
        "Diagnostics go to stderr. Exit 0 when the requested\n",
        "capabilities are available, 3 when requested collection\n",
        "is unavailable or unknown, 2 on usage or internal errors.\n",
        "Profiles resolve from the executable location, never from\n",
        "the caller's working directory.\n",
        "Passive by default: no BPF load, no bridge access;\n",
        "--load-check loads every requested object without attaching.\n",
        "\n",
        "  --json            print the doctor-v0.1.1 JSON report.\n",
        "  --profiles-dir DIR  profiles directory",
        " (default: executable-relative).\n",
        "  --capability LIST   comma-separated capability ids,",
        " or all (default all).\n",
        "  --object PATH       attempt channel object",
        " (default: discovered).\n",
        "  --lc-object PATH    lifecycle channel object",
        " (default: discovered).\n",
        "  --cp-object PATH    copy channel object",
        " (default: discovered).\n",
        "  --bridge PATH       bridge library",
        " (used only with --load-check).\n",
        "  --load-check        load every requested object",
        " without attaching.\n",
    )
    .to_string()
}

/// Locate the profiles dir from the program path.
///
/// Layout contract: the executable lives one directory below the tree
/// root (`<root>/build/memveil` in a checkout, `<root>/bin/memveil`
/// packaged), with profiles at `<root>/profiles`. An executable
/// installed at `/usr/bin` instead reads the FHS profiles dir. A bare
/// program name (PATH lookup) falls back to `./profiles`.
///
/// This is the canonical copy: record, top, qualify, and bind-profile
/// all resolve through it.
pub fn default_profiles_dir(prog: &str) -> String {
    let parts: Vec<&str> = prog.split('/').collect();
    if parts.len() < 2 {
        return "profiles".to_string();
    }
    let mut out = String::new();
    for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
        if i != 0 {
            out.push('/');
        }
        out.push_str(part);
    }
    if out.is_empty() {
        out = "/".to_string();
    }
    if out == "/" {
        return "/../profiles".to_string();
    }
    if out == "/usr/bin" {
        return "/usr/share/memveil/profiles".to_string();
    }
    out + "/../profiles"
}

/// Locate the profiles dir from the kernel-resolved binary path.
///
/// There is deliberately no argv[0] fallback: when /proc/self/exe cannot
/// be resolved, guessing from argv[0] or the working directory could load
/// a planted tree's profiles, so resolution failure is an explicit error
/// instead. A cargo checkout layout (`.../target/{debug,release}/memveil`)
/// falls back to [`cargo_checkout_profiles`] when no manifest sits beside
/// the executable; installed and packaged layouts keep exact Mojo behavior.
pub fn resolve_profiles_dir() -> Result<String, EvidenceError> {
    let exe = readlink_self()?;
    let dir = default_profiles_dir(&exe);
    if manifest_readable(&dir) {
        return Ok(dir);
    }
    if let Some(found) = cargo_checkout_profiles(&exe) {
        return Ok(found);
    }
    Ok(dir)
}

/// Profiles dir for a cargo-built executable inside a checkout.
///
/// The Mojo layout contract assumes the executable one directory below
/// the tree root, but cargo builds land at
/// `<project>/target/{debug,release}/memveil`, two levels deeper (plus
/// the pre-cutover `rust/` nesting). When the executable path matches
/// that shape, probe `<project>/profiles` then `<project>/../profiles`
/// for a readable manifest and return the first hit. Every candidate
/// anchors at the kernel-resolved executable path, never at argv[0] or
/// the working directory, so a planted cwd tree cannot hijack discovery.
/// Returns `None` for non-cargo layouts or when no manifest is found;
/// the caller then keeps the default dir and its real load error.
fn cargo_checkout_profiles(exe: &str) -> Option<String> {
    let parts: Vec<&str> = exe.split('/').collect();
    if parts.len() < 4 {
        return None;
    }
    let tail = &parts[parts.len() - 3..];
    if tail[0] != "target" || (tail[1] != "debug" && tail[1] != "release") {
        return None;
    }
    let project = parts[..parts.len() - 3].join("/");
    if project.is_empty() {
        return None;
    }
    [
        format!("{project}/profiles"),
        format!("{project}/../profiles"),
    ]
    .into_iter()
    .find(|candidate| manifest_readable(candidate))
}

/// Report one doctor failure on stderr; return EXIT_INVALID.
fn doctor_failed(detail: &str) -> i64 {
    match write_stderr(&format!(
        "memveil doctor: {}\n",
        sanitize_diagnostic(detail)
    )) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// One judged capability: status, reason, code, evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorCap {
    /// Capability id.
    pub id: String,
    /// `available`, `available-load-unchecked`, `unavailable`, `unknown`,
    /// or `unsupported`.
    pub status: String,
    /// Human reason.
    pub reason: String,
    /// Fixed remedy; empty when none applies.
    pub remedy: String,
    /// Machine reason code.
    pub reason_code: String,
    /// Evidence lines.
    pub evidence: Vec<String>,
}

impl Default for DoctorCap {
    fn default() -> Self {
        Self {
            id: String::new(),
            status: "unknown".to_string(),
            reason: String::new(),
            remedy: String::new(),
            reason_code: String::new(),
            evidence: Vec::new(),
        }
    }
}

/// Doctor inputs: roots, requested set, objects, load flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorOptions {
    /// Evidence root ("" for the live host).
    pub root: String,
    /// Profiles directory holding `manifest.txt`.
    pub profiles_dir: String,
    /// Render JSON instead of text.
    pub as_json: bool,
    /// Requested capability list.
    pub capabilities: String,
    /// Attempt channel object override.
    pub object: String,
    /// Lifecycle channel object override.
    pub lc_object: String,
    /// Copy channel object override.
    pub cp_object: String,
    /// Bridge library override.
    pub bridge: String,
    /// True when --bridge was passed.
    pub has_bridge: bool,
    /// Load every requested object without attaching.
    pub load_check: bool,
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            root: String::new(),
            profiles_dir: String::new(),
            as_json: false,
            capabilities: "all".to_string(),
            object: String::new(),
            lc_object: String::new(),
            cp_object: String::new(),
            bridge: String::new(),
            has_bridge: false,
            load_check: false,
        }
    }
}

/// One admission-judged doctor report, ready to render.
///
/// The 0.1.0 fields keep their meaning; `mode` names the run kind,
/// `btf`/`lockdown` carry the kernel gate facts,
/// `requested`/`prechecks`/`load`/`notes` record the judgment inputs,
/// and every capability gains a machine `reason_code` plus evidence
/// lines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DoctorReport2 {
    /// `live` or `fixture`.
    pub origin: String,
    /// Kernel identity and floor.
    pub kernel: KernelInfo,
    /// Guest-technology verdict.
    pub guest: GuestInfo,
    /// True on a validated or local-auto match.
    pub matched: bool,
    /// True when a profile covers the identity.
    pub has_profile: bool,
    /// Covering profile id.
    pub profile_id: String,
    /// Covering profile status.
    pub profile_status: String,
    /// Covering reason.
    pub profile_reason: String,
    /// One judged capability per requested id.
    pub caps: Vec<DoctorCap>,
    /// Effective uid.
    pub euid: i64,
    /// Privilege-denied evidence paths.
    pub denied: Vec<String>,
    /// `ready`, `ready-load-unchecked`, or `unavailable`.
    pub verdict: String,
    /// Human verdict line.
    pub summary: String,
    /// `passive` or `load-check`.
    pub mode: String,
    /// Kernel gate BTF facts.
    pub btf: BtfFacts,
    /// Kernel gate lockdown state.
    pub lockdown: LockdownState,
    /// Requested capability ids in order.
    pub requested: Vec<String>,
    /// Passive pre-check outcomes.
    pub prechecks: Vec<PreCheck>,
    /// One load entry per capability under --load-check.
    pub load: Vec<LoadResult>,
    /// Advisory notes.
    pub notes: Vec<String>,
}

impl Default for DoctorReport2 {
    fn default() -> Self {
        Self {
            origin: "fixture".to_string(),
            kernel: KernelInfo {
                release: String::new(),
                arch: String::new(),
                eligible_floor: false,
                floor_reason: String::new(),
            },
            guest: GuestInfo {
                tech: "unknown".to_string(),
                signals: Vec::new(),
                asserted: false,
                conflict: String::new(),
            },
            matched: false,
            has_profile: false,
            profile_id: String::new(),
            profile_status: String::new(),
            profile_reason: String::new(),
            caps: Vec::new(),
            euid: 0,
            denied: Vec::new(),
            verdict: "unavailable".to_string(),
            summary: String::new(),
            mode: "passive".to_string(),
            btf: BtfFacts {
                state: String::new(),
                bytes: 0,
                has_bytes: false,
                config_btf: String::new(),
                config_src: String::new(),
            },
            lockdown: LockdownState {
                mode: String::new(),
                src: String::new(),
                detail: String::new(),
            },
            requested: Vec::new(),
            prechecks: Vec::new(),
            load: Vec::new(),
            notes: Vec::new(),
        }
    }
}

/// Clip text to cap bytes at a UTF-8 edge, else verbatim.
fn clip_n(text: &str, cap: usize) -> String {
    if text.len() <= cap {
        return text.to_string();
    }
    let n = cap.min(text.len());
    text[..text.floor_char_boundary(n)].to_string()
}

/// True when one blank-separated token matches exactly.
fn has_token(cmdline: &str, token: &str) -> bool {
    cmdline
        .split([' ', '\t', '\n', '\r', '\0'])
        .any(|part| part == token)
}

/// True when raw is blank-padded ASCII digits of value 0.
fn ascii_is_zero(raw: &[u8]) -> bool {
    let mut started = false;
    let mut nonzero = false;
    let mut trailing = false;
    for &c in raw {
        if c == 0x20 || c == 0x09 || c == 0x0a || c == 0x0d {
            if started {
                trailing = true;
            }
            continue;
        }
        if trailing {
            return false;
        }
        if !c.is_ascii_digit() {
            return false;
        }
        started = true;
        if c != 0x30 {
            nonzero = true;
        }
    }
    started && !nonzero
}

/// True when debugfs shows a swiotlb dir with no slabs.
///
/// The kernel always creates the swiotlb directory and skips its files
/// when the slab count is zero, so an absent directory proves nothing
/// about the pool.
fn swiotlb_pool_inactive(reader: &EvidenceReader) -> bool {
    if file_state(reader, "/sys/kernel/debug/swiotlb") != EVIDENCE_OK {
        return false;
    }
    let npath = "/sys/kernel/debug/swiotlb/io_tlb_nslabs";
    let st = file_state(reader, npath);
    if st == EVIDENCE_ABSENT {
        return true;
    }
    if st != EVIDENCE_OK {
        return false;
    }
    match read_evidence(reader, npath, NSLABS_CAP) {
        Ok(raw) => ascii_is_zero(&raw),
        Err(_) => false,
    }
}

/// True when record refused over a channel object.
fn is_object_refusal(refusal: &str) -> bool {
    if refusal.starts_with("no object:") {
        return true;
    }
    if refusal == "object unreadable" {
        return true;
    }
    if refusal.starts_with("object refused") {
        return true;
    }
    if refusal.starts_with("object ring too large") {
        return true;
    }
    if refusal.contains(" object unreadable") {
        return true;
    }
    if refusal.contains(" object refused") {
        return true;
    }
    refusal.contains(" object ring too large")
}

/// True when record refused over the kernel floor.
fn is_floor_refusal(refusal: &str) -> bool {
    if refusal.contains(" is unparseable; floor unknown") {
        return true;
    }
    refusal.contains(" needs kernel ") && refusal.contains("(this kernel: ")
}

/// True for 'capability <cap> unsupported by <doc>'.
fn is_unsupported_declaration(refusal: &str, cap: &str) -> bool {
    let head = format!("capability {cap} unsupported by ");
    refusal.len() >= head.len() && refusal.starts_with(&head)
}

/// One machine code for a record refusal.
///
/// Gate codes pass through; selection refusals decode to the object,
/// floor, or profile code from their text.
fn reason_code_for(refusal: &str, code: &str) -> String {
    if code != "profile" {
        return code.to_string();
    }
    if is_object_refusal(refusal) {
        return "object-missing".to_string();
    }
    if is_floor_refusal(refusal) {
        return "floor".to_string();
    }
    "profile".to_string()
}

/// One evidence line for a non-pass pre-check.
fn precheck_line(pc: &PreCheck) -> String {
    format!("{}: {}: {}", pc.id, pc.state, pc.reason)
}

/// Channel kind for one capability, else `""`.
fn load_kind(cap_id: &str) -> &str {
    match cap_id {
        "attempt-trace" => "attempt",
        "mapping-lifecycle" => "lifecycle",
        "copy-actual" => "copy",
        _ => "",
    }
}

/// True when a failed pre-check demotes an admitted row.
///
/// Passive only: under `--load-check` the load itself decides, so the
/// row stays admitted into the load phase.
pub fn precheck_demotes(fail_code: &str, loading: bool) -> bool {
    !fail_code.is_empty() && !loading
}

/// One load entry: attempted result, race synthetic, or skipped.
fn result_for_cap(
    ti: i64,
    results: &[LoadResult],
    synth_caps: &[usize],
    synth_res: &[LoadResult],
    ci: usize,
    cap_id: &str,
) -> LoadResult {
    if ti >= 0 {
        return results[ti as usize].clone();
    }
    for (s, cap) in synth_caps.iter().enumerate() {
        if *cap == ci {
            return synth_res[s].clone();
        }
    }
    let kind = load_kind(cap_id);
    let object = if kind.is_empty() {
        cap_id.to_string()
    } else {
        kind.to_string()
    };
    LoadResult {
        object,
        detail: "passive checks did not pass".to_string(),
        ..LoadResult::default()
    }
}

/// Judge every requested capability through record admission.
///
/// Passive: no BPF load, no attach, no bridge access. Each of the three
/// record capabilities runs `decide_record` over its own set for its
/// display row, and the verdict judges the requested set through one
/// more call; conversion-observe has no record channel. A failed passive
/// pre-check demotes an admitted capability to unavailable with that
/// check's code. Bad roots, profiles, or capability lists yield an
/// unavailable report naming the failure; the exit-code mapping lives in
/// `run_doctor_opts`. Under `--load-check` on the live host, every
/// admitted object loads without attaching: loaded objects read
/// `available` and the verdict is `ready` only when every requested
/// object loaded.
///
/// The loader links statically, so an empty bridge is the normal case,
/// not a load failure: the bridge override only binds receipts through
/// the admission hash.
pub fn assess_doctor(opts: &DoctorOptions) -> DoctorReport2 {
    let mut out = DoctorReport2::default();
    let reader = match open_evidence_reader(&opts.root) {
        Ok(reader) => reader,
        Err(e) => {
            out.summary = format!("unavailable: cannot open evidence: {e}");
            return out;
        }
    };
    if reader.root.is_empty() {
        out.origin = "live".to_string();
    }
    let env: EnvironmentEvidence = detect_environment(&reader);
    out.kernel = env.kernel.clone();
    out.guest = env.guest.clone();
    out.euid = reader.euid;
    out.denied.clone_from(&env.denied);
    let profiles: Vec<Profile> = match load_profiles(&opts.profiles_dir) {
        Ok(profiles) => profiles,
        Err(e) => {
            out.summary = format!("unavailable: cannot load profiles: {e}");
            return out;
        }
    };
    let decision = select_profile_bound(
        &env.kernel,
        &profiles,
        &opts.root,
        ZLIB,
        &opts.profiles_dir,
        "",
    );
    out.matched = decision.matched;
    out.has_profile = decision.has_profile;
    if decision.has_profile {
        out.profile_id = decision.profile.profile_id.clone();
        out.profile_status = decision.profile.status.clone();
    }
    out.profile_reason = decision.reason.clone();
    let ask = parse_requested_caps(&opts.capabilities);
    if !ask.ok {
        out.summary = format!("unavailable: {}", ask.err);
        return out;
    }
    out.requested.clone_from(&ask.caps);
    let gated = kernel_gate(&reader, &env.kernel.release, ZLIB, &ask.caps);
    out.btf = gated.btf.clone();
    out.lockdown = gated.lockdown.clone();
    let object_path = resolve_object(&opts.object);
    let lc_path = resolve_object(&opts.lc_object);
    let cp_path = resolve_object(&opts.cp_object);
    let mut need: i64 = 0;
    for cap in &ask.caps {
        let mut p = object_path.clone();
        if cap == "mapping-lifecycle" {
            p = lc_path.clone();
        } else if cap == "copy-actual" {
            p = cp_path.clone();
        } else if cap != "attempt-trace" {
            continue;
        }
        if p.is_empty() {
            continue;
        }
        let elf = match read_host_file(&p, "object", OBJECT_BYTES_CAP) {
            Ok(elf) => elf,
            Err(_) => continue,
        };
        let mb = read_object_map_bytes(&elf);
        if !mb.ok || mb.bytes <= 0 {
            continue;
        }
        if need <= i64::MAX - mb.bytes {
            need += mb.bytes;
        } else {
            need = i64::MAX;
        }
    }
    let privc = check_privilege(&reader);
    let mem = check_memcg(&reader, need);
    let unp = check_unprivileged_bpf(&reader);
    out.prechecks.push(privc.clone());
    out.prechecks.push(mem.clone());
    out.prechecks.push(unp.clone());
    let mut fail_code = String::new();
    let mut fail_reason = String::new();
    if privc.state == "fail" {
        fail_code = privc.code.clone();
        fail_reason = privc.reason.clone();
    } else if mem.state == "fail" {
        fail_code = mem.code.clone();
        fail_reason = mem.reason.clone();
    }
    let loading = opts.load_check && opts.root.is_empty();
    let bridge_sha = if loading {
        loadcheck_bridge_sha(&opts.bridge, opts.has_bridge)
    } else {
        String::new()
    };
    let mut plines: Vec<String> = Vec::new();
    if privc.state != "pass" && plines.len() < 64 {
        plines.push(clip_n(&precheck_line(&privc), 512));
    }
    if mem.state != "pass" && plines.len() < 64 {
        plines.push(clip_n(&precheck_line(&mem), 512));
    }
    if unp.state != "pass" && plines.len() < 64 {
        plines.push(clip_n(&precheck_line(&unp), 512));
    }
    for cap in &ask.caps {
        let mut entry = DoctorCap {
            id: cap.clone(),
            ..DoctorCap::default()
        };
        if cap == "conversion-observe" {
            entry.status = "unsupported".to_string();
            entry.reason = "capability conversion-observe has no record channel".to_string();
            entry.reason_code = "unsupported".to_string();
            out.caps.push(entry);
            continue;
        }
        let mut want = "attempt-trace".to_string();
        if cap != "attempt-trace" {
            want = format!("attempt-trace,{cap}");
        }
        let pick = decide_record(
            &opts.root,
            &env.kernel,
            &profiles,
            "",
            false,
            &object_path,
            &lc_path,
            &cp_path,
            &want,
            &opts.profiles_dir,
            &bridge_sha,
        );
        if !pick.ok {
            if is_unsupported_declaration(&pick.refusal, cap) {
                entry.status = "unsupported".to_string();
                entry.reason_code = "unsupported".to_string();
            } else if pick.refusal_unknown {
                entry.status = "unknown".to_string();
                entry.reason_code = reason_code_for(&pick.refusal, &pick.refusal_code);
            } else {
                entry.status = "unavailable".to_string();
                entry.reason_code = reason_code_for(&pick.refusal, &pick.refusal_code);
            }
            entry.reason = clip_n(&pick.refusal, 512);
            if !pick.fix.is_empty() {
                entry.remedy = clip_n(&pick.fix, 512);
            } else {
                entry.remedy = clip_n(&remedy_for(&entry.reason_code), 512);
            }
            out.caps.push(entry);
            continue;
        }
        if precheck_demotes(&fail_code, loading) {
            entry.status = "unavailable".to_string();
            entry.reason = clip_n(&fail_reason, 512);
            entry.reason_code = fail_code.clone();
            entry.remedy = clip_n(&remedy_for(&fail_code), 512);
        } else {
            entry.status = "available-load-unchecked".to_string();
            entry.reason = clip_n(&pick.reason, 512);
            entry.reason_code = "available".to_string();
            entry.remedy = String::new();
        }
        for line in &plines {
            if entry.evidence.len() < 64 {
                entry.evidence.push(line.clone());
            }
        }
        if entry.id == "attempt-trace"
            && entry.status == "available-load-unchecked"
            && !attempt_loss_exact(&env.kernel.release)
            && entry.evidence.len() < 64
        {
            entry.evidence.push(
                "attempt loss counts are a lower bound before 6.7: trace_call_bpf skipped programs without counting them"
                    .to_string(),
            );
        }
        out.caps.push(entry);
    }
    // The verdict judges the requested set as one record admission;
    // per-capability rows are display only.
    let whole_want = ask.caps.join(",");
    let whole = decide_record(
        &opts.root,
        &env.kernel,
        &profiles,
        "",
        false,
        &object_path,
        &lc_path,
        &cp_path,
        &whole_want,
        &opts.profiles_dir,
        &bridge_sha,
    );
    if loading {
        out.mode = "load-check".to_string();
        let mut targets: Vec<LoadTarget> = Vec::new();
        let mut target_for_cap: Vec<i64> = vec![-1; out.caps.len()];
        let mut synth_caps: Vec<usize> = Vec::new();
        let mut synth_res: Vec<LoadResult> = Vec::new();
        for (i, cap) in out.caps.iter().enumerate() {
            let kind = load_kind(&cap.id);
            if kind.is_empty() {
                continue;
            }
            if cap.status != "available-load-unchecked" {
                continue;
            }
            let mut path = object_path.clone();
            if kind == "lifecycle" {
                path = lc_path.clone();
            } else if kind == "copy" {
                path = cp_path.clone();
            }
            let elf = match read_host_file(&path, "object", OBJECT_BYTES_CAP) {
                Ok(elf) => elf,
                Err(_) => {
                    synth_caps.push(i);
                    synth_res.push(LoadResult {
                        object: kind.to_string(),
                        state: "failed".to_string(),
                        detail: "object unreadable at load".to_string(),
                        ..LoadResult::default()
                    });
                    continue;
                }
            };
            let programs = if kind == "attempt" {
                attempt_program_names()
            } else if kind == "lifecycle" {
                lifecycle_program_names()
            } else {
                copy_program_names()
            };
            let target = LoadTarget {
                kind: kind.to_string(),
                elf,
                programs,
            };
            target_for_cap[i] = targets.len() as i64;
            targets.push(target);
        }
        // The loader links statically, so loads never depend on a
        // bridge file: an empty bridge is the normal case here, and
        // the --bridge override only binds receipts through the
        // admission hash above.
        let results: Vec<LoadResult> = if targets.is_empty() {
            Vec::new()
        } else {
            load_check(&targets)
        };
        for i in 0..out.caps.len() {
            let cap_id = out.caps[i].id.clone();
            let res = result_for_cap(
                target_for_cap[i],
                &results,
                &synth_caps,
                &synth_res,
                i,
                &cap_id,
            );
            if res.state == "loaded" {
                out.caps[i].status = "available".to_string();
            } else if res.state == "failed" {
                out.caps[i].status = "unavailable".to_string();
                if res.errno.is_empty() {
                    out.caps[i].reason = clip_n(&res.detail, 512);
                } else {
                    out.caps[i].reason =
                        clip_n(&format!("load {}: {}", res.errno, res.detail), 512);
                }
                out.caps[i].reason_code = load_code_for(&res.errno);
                let rcode = out.caps[i].reason_code.clone();
                out.caps[i].remedy = clip_n(&remedy_for(&rcode), 512);
                for line in &res.lines {
                    if out.caps[i].evidence.len() < 64 {
                        out.caps[i].evidence.push(line.clone());
                    }
                }
            }
            out.load.push(res);
        }
    }
    let mut want = "available-load-unchecked";
    if loading {
        want = "available";
    }
    let mut all_ok = true;
    let mut first_refusal = String::new();
    for cap in &out.caps {
        if cap.status != want {
            all_ok = false;
            if first_refusal.is_empty() {
                first_refusal = cap.reason.clone();
            }
        }
    }
    let names = out.requested.join(", ");
    if !whole.ok {
        out.verdict = "unavailable".to_string();
        out.summary = clip_n(&format!("unavailable: {}", whole.refusal), 1024);
    } else if all_ok && loading {
        out.verdict = "ready".to_string();
        out.summary = format!("ready: {names} available");
        if out.has_profile {
            out.summary += &format!(" under {}", out.profile_id);
        }
    } else if all_ok {
        out.verdict = "ready-load-unchecked".to_string();
        out.summary = format!("ready (load not checked): {names} available");
        if out.has_profile {
            out.summary += &format!(" under {}", out.profile_id);
        }
    } else {
        out.verdict = "unavailable".to_string();
        out.summary = clip_n(&format!("unavailable: {first_refusal}"), 1024);
    }
    let mut cmdline = String::new();
    let mut cmd_ok = false;
    if let Ok(raw) = read_evidence(&reader, "/proc/cmdline", CMDLINE_CAP) {
        cmdline = bytes_to_text(&raw);
        cmd_ok = true;
    }
    if (cmd_ok && has_token(&cmdline, "swiotlb=noforce")) || swiotlb_pool_inactive(&reader) {
        out.notes
            .push("no swiotlb pool active: attempts will be 0".to_string());
    }
    if unp.state == "pass" {
        out.notes.push(unp.reason.clone());
    }
    out
}

/// Render one DoctorReport2 as doctor-v0.1.1 JSON.
pub fn render_doctor_json2(rep: &DoctorReport2) -> String {
    let mut out = String::from("{\n");
    out += "  \"schema_version\": \"0.1.1\",\n";
    out += &format!("  \"mode\": {},\n", escape_json(&rep.mode));
    out += &format!(
        "  \"provenance\": {{\"origin\": {}}},\n",
        escape_json(&rep.origin)
    );
    out += "  \"kernel\": {\n";
    out += &format!("    \"release\": {},\n", escape_json(&rep.kernel.release));
    out += &format!("    \"arch\": {},\n", escape_json(&rep.kernel.arch));
    if rep.kernel.eligible_floor {
        out += "    \"eligible_floor\": true,\n";
    } else {
        out += "    \"eligible_floor\": false,\n";
    }
    out += &format!(
        "    \"floor_reason\": {},\n",
        escape_json(&rep.kernel.floor_reason)
    );
    out += &format!("    \"btf\": {{\"state\": {}", escape_json(&rep.btf.state));
    out += ", \"bytes\": ";
    if rep.btf.has_bytes {
        out += &escape_json(&rep.btf.bytes.to_string());
    } else {
        out += "null";
    }
    out += &format!(", \"config_btf\": {}", escape_json(&rep.btf.config_btf));
    out += &format!(
        ", \"config_src\": {}}},\n",
        escape_json(&rep.btf.config_src)
    );
    out += &format!(
        "    \"lockdown\": {{\"mode\": {}, \"src\": {}}}\n",
        escape_json(&rep.lockdown.mode),
        escape_json(&rep.lockdown.src)
    );
    out += "  },\n";
    out += "  \"guest\": {\n";
    out += &format!("    \"tech\": {},\n", escape_json(&rep.guest.tech));
    out += "    \"signals\": [";
    for (i, signal) in rep.guest.signals.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &escape_json(signal);
    }
    out += "],\n";
    if rep.guest.asserted {
        out += "    \"asserted\": true,\n";
    } else {
        out += "    \"asserted\": false,\n";
    }
    out += &format!("    \"conflict\": {}\n", escape_json(&rep.guest.conflict));
    out += "  },\n";
    out += "  \"profile\": {\n";
    if rep.matched {
        out += "    \"matched\": true,\n";
    } else {
        out += "    \"matched\": false,\n";
    }
    if rep.has_profile {
        out += &format!("    \"profile_id\": {},\n", escape_json(&rep.profile_id));
        out += &format!("    \"status\": {},\n", escape_json(&rep.profile_status));
    } else {
        out += "    \"profile_id\": null,\n";
        out += "    \"status\": null,\n";
    }
    out += &format!("    \"reason\": {}\n", escape_json(&rep.profile_reason));
    out += "  },\n";
    out += "  \"capabilities\": [";
    for (i, cap) in rep.caps.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &format!("{{\"id\": {}", escape_json(&cap.id));
        out += &format!(", \"status\": {}", escape_json(&cap.status));
        out += &format!(", \"reason\": {}", escape_json(&cap.reason));
        out += &format!(", \"remedy\": {}", escape_json(&cap.remedy));
        out += &format!(", \"reason_code\": {}", escape_json(&cap.reason_code));
        out += ", \"evidence\": [";
        for (j, line) in cap.evidence.iter().enumerate() {
            if j != 0 {
                out += ", ";
            }
            out += &escape_json(line);
        }
        out += "]}";
    }
    out += "],\n";
    out += "  \"privilege\": {\n";
    out += &format!("    \"euid\": {},\n", rep.euid);
    out += "    \"denied_paths\": [";
    for (i, denied) in rep.denied.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &escape_json(denied);
    }
    out += "]\n";
    out += "  },\n";
    out += "  \"requested\": [";
    for (i, req) in rep.requested.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &escape_json(req);
    }
    out += "],\n";
    out += "  \"prechecks\": [";
    for (i, pc) in rep.prechecks.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &format!("{{\"id\": {}", escape_json(&pc.id));
        out += &format!(", \"state\": {}", escape_json(&pc.state));
        out += &format!(", \"reason\": {}}}", escape_json(&pc.reason));
    }
    out += "],\n";
    out += "  \"load\": [";
    for (i, entry) in rep.load.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &format!("{{\"object\": {}", escape_json(&entry.object));
        out += &format!(", \"state\": {}", escape_json(&entry.state));
        out += ", \"errno\": ";
        if entry.errno.is_empty() {
            out += "null";
        } else {
            out += &escape_json(&entry.errno);
        }
        out += &format!(", \"detail\": {}}}", escape_json(&entry.detail));
    }
    out += "],\n";
    out += "  \"notes\": [";
    for (i, note) in rep.notes.iter().enumerate() {
        if i != 0 {
            out += ", ";
        }
        out += &escape_json(note);
    }
    out += "],\n";
    out += &format!("  \"verdict\": {},\n", escape_json(&rep.verdict));
    out += &format!("  \"summary\": {}\n", escape_json(&rep.summary));
    out += "}\n";
    out
}

/// Text spelling of one capability status.
fn doctor2_status_text(status: &str) -> String {
    if status == "available-load-unchecked" {
        return "available (load not checked)".to_string();
    }
    status.to_string()
}

/// Render one DoctorReport2 as human-readable text.
///
/// Same shape as the 0.1.0 text, plus one `note:` line per note;
/// load-unchecked statuses print in words. Every interpolated evidence
/// fragment passes through the single-line diagnostic sanitizer.
pub fn render_doctor_text2(rep: &DoctorReport2) -> String {
    let mut out = format!("memveil doctor ({}, {} evidence)\n", rep.mode, rep.origin);
    out += &format!(
        "kernel: {} {} (floor 6.0: ",
        sanitize_diagnostic(&rep.kernel.release),
        sanitize_diagnostic(&rep.kernel.arch)
    );
    if rep.kernel.eligible_floor {
        out += "yes";
    } else {
        out += "no";
    }
    out += ")\n";
    out += &format!("floor: {}\n", sanitize_diagnostic(&rep.kernel.floor_reason));
    out += &format!("guest: {}", sanitize_diagnostic(&rep.guest.tech));
    if rep.guest.asserted {
        out += " (user-asserted)";
    }
    out += "\n";
    for signal in &rep.guest.signals {
        out += &format!("  signal: {}\n", sanitize_diagnostic(signal));
    }
    if !rep.guest.conflict.is_empty() {
        out += &format!("  conflict: {}\n", sanitize_diagnostic(&rep.guest.conflict));
    }
    if rep.has_profile {
        out += &format!(
            "profile: {} ({})\n",
            sanitize_diagnostic(&rep.profile_id),
            sanitize_diagnostic(&rep.profile_status)
        );
    } else {
        out += "profile: none\n";
    }
    out += &format!(
        "profile-detail: {}\n",
        sanitize_diagnostic(&rep.profile_reason)
    );
    out += "capabilities:\n";
    for cap in &rep.caps {
        out += &format!(
            "  {}: {} - {}\n",
            sanitize_diagnostic(&cap.id),
            sanitize_diagnostic(&doctor2_status_text(&cap.status)),
            sanitize_diagnostic(&cap.reason)
        );
        if !cap.remedy.is_empty() {
            out += &format!("    fix: {}\n", sanitize_diagnostic(&cap.remedy));
        }
    }
    for note in &rep.notes {
        out += &format!("note: {}\n", sanitize_diagnostic(note));
    }
    out += &format!("privilege: euid {}", rep.euid);
    if !rep.denied.is_empty() {
        out += ", denied:";
        for denied in &rep.denied {
            out += &format!(" {}", sanitize_diagnostic(denied));
        }
    }
    out += "\n";
    out += &format!("verdict: {}\n", sanitize_diagnostic(&rep.verdict));
    out += &format!("summary: {}\n", sanitize_diagnostic(&rep.summary));
    out
}

/// Run the doctor flow against explicit roots; return exit code.
///
/// `root` is the evidence root ("" for the live host) and
/// `profiles_dir` holds `manifest.txt`. Wrapper over the
/// admission-judging pipeline with discovery for every object and
/// capabilities `all`. Doctor is bridge-independent: it never
/// discovers, opens, or hashes the bridge or any
/// environment-selected stream, so receipt checks run with an
/// unchecked bridge identity and report it as such; bridge admission
/// checks belong on collection paths. The report goes to stdout;
/// failures go to stderr with exit 2.
pub fn run_doctor_with(root: &str, profiles_dir: &str, as_json: bool) -> i64 {
    run_doctor_opts(&DoctorOptions {
        root: root.to_string(),
        profiles_dir: profiles_dir.to_string(),
        as_json,
        ..DoctorOptions::default()
    })
}

/// Run the admission-judging doctor flow; return exit code.
///
/// Bad roots, profiles, or capability lists fail with exit 2; a load
/// check against a fixture root is rejected the same way. Otherwise
/// the report goes to stdout with exit 0 when the requested set is
/// ready and 3 when it is unavailable. Passive runs never touch the
/// bridge.
pub fn run_doctor_opts(opts: &DoctorOptions) -> i64 {
    if opts.load_check && !opts.root.is_empty() {
        return doctor_failed("--load-check needs the live host");
    }
    if let Err(e) = open_evidence_reader(&opts.root) {
        return doctor_failed(&format!("cannot open evidence: {e}"));
    }
    if let Err(e) = load_profiles(&opts.profiles_dir) {
        return doctor_failed(&format!("cannot load profiles: {e}"));
    }
    let ask = parse_requested_caps(&opts.capabilities);
    if !ask.ok {
        return doctor_failed(&ask.err);
    }
    let drep = assess_doctor(opts);
    let ready = drep.verdict == "ready" || drep.verdict == "ready-load-unchecked";
    let text = if opts.as_json {
        render_doctor_json2(&drep)
    } else {
        render_doctor_text2(&drep)
    };
    if write_stdout(&text).is_err() {
        let _ = write_stderr("memveil doctor: cannot write stdout\n");
        return EXIT_INTERNAL;
    }
    if ready { EXIT_OK } else { EXIT_UNAVAILABLE }
}

/// Run the doctor verb; return the process exit code.
///
/// `args` excludes the program name and the doctor word. Only the
/// usage flags are accepted; anything else is a usage error. Without
/// the flag, profiles resolve from the kernel-resolved binary path,
/// never from argv[0] or the working directory.
pub fn run_doctor(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&doctor_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => {
                let _ = write_stderr("memveil doctor: cannot write stdout\n");
                return EXIT_INTERNAL;
            }
        }
    }
    let mut as_json = false;
    let mut profiles_dir = String::new();
    let mut has_profiles_dir = false;
    let mut capabilities = "all".to_string();
    let mut object = String::new();
    let mut lc_object = String::new();
    let mut cp_object = String::new();
    let mut bridge = String::new();
    let mut has_bridge = false;
    let mut load_check = false;
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--json" {
            as_json = true;
            i += 1;
        } else if tok == "--load-check" {
            load_check = true;
            i += 1;
        } else if tok == "--profiles-dir" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--profiles-dir needs a value");
            }
            profiles_dir = args[i + 1].clone();
            has_profiles_dir = true;
            i += 2;
        } else if tok == "--capability" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--capability needs a value");
            }
            capabilities = args[i + 1].clone();
            i += 2;
        } else if tok == "--object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--object needs a value");
            }
            object = args[i + 1].clone();
            i += 2;
        } else if tok == "--lc-object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--lc-object needs a value");
            }
            lc_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--cp-object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--cp-object needs a value");
            }
            cp_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--bridge" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return doctor_failed("--bridge needs a value");
            }
            bridge = args[i + 1].clone();
            has_bridge = true;
            i += 2;
        } else {
            return doctor_failed(&format!("unknown option: {tok}"));
        }
    }
    if !has_profiles_dir {
        match resolve_profiles_dir() {
            Ok(dir) => profiles_dir = dir,
            Err(e) => {
                return doctor_failed(&format!("cannot resolve profiles location: {}", e.message));
            }
        }
    }
    run_doctor_opts(&DoctorOptions {
        root: String::new(),
        profiles_dir,
        as_json,
        capabilities,
        object,
        lc_object,
        cp_object,
        bridge,
        has_bridge,
        load_check,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        DoctorOptions, EXIT_UNAVAILABLE, assess_doctor, cargo_checkout_profiles,
        default_profiles_dir, doctor_usage, precheck_demotes, render_doctor_json2,
        render_doctor_text2, resolve_profiles_dir, run_doctor, run_doctor_opts, run_doctor_with,
    };
    use crate::capture::run::decide_record;
    use crate::platform::evidence::detect_environment;
    use crate::platform::kernelgate::remedy_for;
    use crate::platform::profiles::load_profiles;
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::{TestDir, capabilities_fixture, gate_fixture, repo_root};

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn repo(path: &str) -> String {
        repo_root().join(path).to_str().expect("utf-8").to_string()
    }

    fn fx(name: &str) -> String {
        capabilities_fixture(name)
    }

    fn profiles_dir() -> String {
        repo("profiles")
    }

    fn elf(name: &str) -> String {
        repo(&format!("tests/fixtures/elf/{name}"))
    }

    fn doctor2_opts(
        root: String,
        profiles_dir: String,
        capabilities: &str,
        obj: &str,
        lc: &str,
        cp: &str,
    ) -> DoctorOptions {
        DoctorOptions {
            root,
            profiles_dir,
            as_json: false,
            capabilities: capabilities.to_string(),
            object: obj.to_string(),
            lc_object: lc.to_string(),
            cp_object: cp.to_string(),
            bridge: String::new(),
            has_bridge: false,
            load_check: false,
        }
    }

    fn drep2_for(fxname: &str, profdir: &str) -> super::DoctorReport2 {
        assess_doctor(&doctor2_opts(
            fx(fxname),
            profdir.to_string(),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        ))
    }

    fn live38_opts() -> DoctorOptions {
        doctor2_opts(
            gate_fixture("base"),
            repo("tests/fixtures/scan/profiles-live"),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        )
    }

    #[test]
    fn doctor2_build_ordinary() {
        let drep = drep2_for("ordinary-7.0", &profiles_dir());
        assert_eq!(drep.origin, "fixture");
        assert_eq!(drep.verdict, "unavailable");
        assert_eq!(
            drep.summary,
            "unavailable: layout: missing field common_type"
        );
        assert_eq!(drep.euid, 1001);
        assert!(drep.denied.is_empty());
        assert_eq!(drep.caps.len(), 3);
        assert!(!drep.matched);
        assert!(drep.has_profile);
        assert_eq!(drep.profile_id, "linux-x86_64-7.0-reference");
        assert_eq!(drep.profile_status, "reference-unvalidated");
    }

    #[test]
    fn doctor2_build_ready() {
        let drep = drep2_for("ready-validated", &fx("profiles-test"));
        assert_eq!(drep.origin, "fixture");
        assert_eq!(drep.verdict, "unavailable");
        assert_eq!(
            drep.summary,
            "unavailable: capability mapping-lifecycle unsupported by test-validated"
        );
        assert!(drep.matched);
        assert!(drep.has_profile);
        assert_eq!(drep.profile_id, "test-validated");
        assert_eq!(drep.profile_status, "validated");
    }

    #[test]
    fn doctor2_denied_merge() {
        let drep = drep2_for("denied-tracepoint", &profiles_dir());
        assert_eq!(drep.verdict, "unavailable");
        assert!(drep.denied.is_empty());
        let want = "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format";
        for cap in &drep.caps {
            assert!(cap.reason.contains("denied"), "{}", cap.reason);
            assert!(cap.reason.contains(want), "{}", cap.reason);
        }
    }

    #[test]
    fn doctor2_env_denied() {
        let drep = drep2_for("denied-guest-node", &profiles_dir());
        assert_eq!(drep.denied, vec!["/dev/sev-guest".to_string()]);
    }

    #[test]
    fn doctor2_json_ordinary_exact() {
        let drep = drep2_for("ordinary-7.0", &profiles_dir());
        let js = render_doctor_json2(&drep);
        let want = concat!(
            "{\n",
            "  \"schema_version\": \"0.1.1\",\n",
            "  \"mode\": \"passive\",\n",
            "  \"provenance\": {\"origin\": \"fixture\"},\n",
            "  \"kernel\": {\n",
            "    \"release\": \"7.0.0-34-generic\",\n",
            "    \"arch\": \"x86_64\",\n",
            "    \"eligible_floor\": true,\n",
            "    \"floor_reason\": \"release 7.0.0-34-generic meets the 6.0 floor\",\n",
            "    \"btf\": {\"state\": \"malformed\", \"bytes\": \"24\",",
            " \"config_btf\": \"unknown\", \"config_src\": \"none\"},\n",
            "    \"lockdown\": {\"mode\": \"unknown\", \"src\": \"none\"}\n",
            "  },\n",
            "  \"guest\": {\n",
            "    \"tech\": \"ordinary\",\n",
            "    \"signals\": [\"sev-node:absent\", \"tdx-node:absent\",",
            " \"cpu-flags:ok:none\", \"ordinary:absent-nodes-inference\",",
            " \"info:btf:present:24B\", \"info:config-gz:absent\",",
            " \"info:os:ubuntu:24.04\", \"info:boot-config:absent\"],\n",
            "    \"asserted\": false,\n",
            "    \"conflict\": \"\"\n",
            "  },\n",
            "  \"profile\": {\n",
            "    \"matched\": false,\n",
            "    \"profile_id\": \"linux-x86_64-7.0-reference\",\n",
            "    \"status\": \"reference-unvalidated\",\n",
            "    \"reason\": \"profile linux-x86_64-7.0-reference covers",
            " this identity but is reference-unvalidated\"\n",
            "  },\n",
            "  \"capabilities\": [{\"id\": \"attempt-trace\",",
            " \"status\": \"unavailable\",",
            " \"reason\": \"layout: missing field common_type\",",
            " \"remedy\": \"\", \"reason_code\": \"profile\", \"evidence\": []},",
            " {\"id\": \"mapping-lifecycle\", \"status\": \"unavailable\",",
            " \"reason\": \"layout: missing field common_type\",",
            " \"remedy\": \"\", \"reason_code\": \"profile\", \"evidence\": []},",
            " {\"id\": \"copy-actual\", \"status\": \"unavailable\",",
            " \"reason\": \"layout: missing field common_type\",",
            " \"remedy\": \"\", \"reason_code\": \"profile\", \"evidence\": []}],\n",
            "  \"privilege\": {\n",
            "    \"euid\": 1001,\n",
            "    \"denied_paths\": []\n",
            "  },\n",
            "  \"requested\": [\"attempt-trace\", \"mapping-lifecycle\",",
            " \"copy-actual\"],\n",
            "  \"prechecks\": [{\"id\": \"privilege\", \"state\": \"unknown\",",
            " \"reason\": \"CapEff unreadable: absent\"},",
            " {\"id\": \"memcg\", \"state\": \"unknown\",",
            " \"reason\": \"cgroup unreadable: absent\"},",
            " {\"id\": \"unprivileged-bpf\", \"state\": \"unknown\",",
            " \"reason\": \"unprivileged_bpf_disabled unreadable: absent\"}],\n",
            "  \"load\": [],\n",
            "  \"notes\": [],\n",
            "  \"verdict\": \"unavailable\",\n",
            "  \"summary\": \"unavailable: layout: missing field common_type\"\n",
            "}\n",
        );
        assert_eq!(js, want);
    }

    #[test]
    fn doctor2_json_narrow_test_near_miss() {
        let drep = drep2_for("ordinary-7.0", &fx("profiles-narrow-test"));
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\"schema_version\": \"0.1.1\""));
        assert!(js.contains(
            "profile linux-x86_64-7.0-reference covers this identity but is reference-unvalidated;\
             \u{20}test-narrow-validated identity uncheckable: config"
        ));
        assert!(js.contains("\"verdict\": \"unavailable\""));
    }

    #[test]
    fn doctor2_text_fix_lines() {
        let drep = drep2_for("meta-release-hostile", &profiles_dir());
        let text = render_doctor_text2(&drep);
        assert!(text.contains("tracefs not found"), "{text}");
        assert!(
            text.contains(&format!("    fix: {}\n", remedy_for("tracefs-not-mounted"))),
            "{text}"
        );
    }

    #[test]
    fn doctor2_json_matched() {
        let drep = drep2_for("ready-validated", &fx("profiles-test"));
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\"verdict\": \"unavailable\""));
        assert!(js.contains("\"matched\": true"));
    }

    #[test]
    fn doctor2_json_null_profile() {
        let drep = drep2_for("arch-mismatch", &profiles_dir());
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\"profile_id\": null"));
        assert!(js.contains("\"status\": null"));
        assert!(js.contains("\"matched\": false"));
    }

    #[test]
    fn doctor2_json_escapes_hostile() {
        let drep = drep2_for("meta-release-hostile", &profiles_dir());
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\\u001b"));
        assert!(!js.contains('\u{1b}'));
    }

    #[test]
    fn doctor2_live_origin() {
        let opts = DoctorOptions {
            profiles_dir: profiles_dir(),
            ..DoctorOptions::default()
        };
        let drep = assess_doctor(&opts);
        assert_eq!(drep.origin, "live");
    }

    #[test]
    fn doctor2_text_key_lines() {
        let drep = drep2_for("ordinary-7.0", &profiles_dir());
        let tx = render_doctor_text2(&drep);
        assert!(tx.contains("memveil doctor (passive, fixture evidence)"));
        assert!(tx.contains("guest: ordinary"));
        assert!(tx.contains("profile: linux-x86_64-7.0-reference (reference-unvalidated)"));
        assert!(tx.contains("privilege: euid 1001"));
        assert!(tx.contains("verdict: unavailable"));
    }

    #[test]
    fn doctor2_text_conflict_line() {
        let drep = drep2_for("conflicting-evidence", &profiles_dir());
        let tx = render_doctor_text2(&drep);
        assert!(tx.contains("conflict: sev-guest and tdx-guest nodes both present"));
    }

    #[test]
    fn doctor2_text_asserted_mark() {
        let drep = drep2_for("user-asserted-snp", &profiles_dir());
        let tx = render_doctor_text2(&drep);
        assert!(tx.contains("guest: snp (user-asserted)"));
    }

    #[test]
    fn doctor2_text_denied_lists() {
        let drep = drep2_for("denied-guest-node", &profiles_dir());
        let tx = render_doctor_text2(&drep);
        assert!(tx.contains("denied: /dev/sev-guest"));
    }

    #[test]
    fn doctor2_text_sanitizes_hostile() {
        let drep = drep2_for("meta-release-hostile", &profiles_dir());
        let tx = render_doctor_text2(&drep);
        assert!(!tx.contains('\u{1b}'));
        assert!(tx.contains("7.0/evil"));
    }

    #[test]
    fn exit_ready() {
        let code = run_doctor_with(&fx("ready-validated"), &fx("profiles-test"), true);
        assert_eq!(code, EXIT_UNAVAILABLE);
    }

    #[test]
    fn exit_unavailable() {
        let code = run_doctor_with(&fx("ordinary-7.0"), &profiles_dir(), false);
        assert_eq!(code, EXIT_UNAVAILABLE);
    }

    #[test]
    fn exit_bad_root() {
        let code = run_doctor_with("no-such-dir", &profiles_dir(), false);
        assert_eq!(code, 2);
    }

    #[test]
    fn exit_bad_profiles() {
        let code = run_doctor_with(&fx("ordinary-7.0"), "no-such-profiles", false);
        assert_eq!(code, 2);
    }

    #[test]
    fn exit_unknown_option() {
        assert_eq!(run_doctor(&args(&["--bogus"])), 2);
    }

    #[test]
    fn exit_profiles_dir_missing_value() {
        assert_eq!(run_doctor(&args(&["--profiles-dir"])), 2);
    }

    #[test]
    fn exit_profiles_dir_bad_path() {
        assert_eq!(
            run_doctor(&args(&[
                "--profiles-dir",
                "tests/fixtures/capabilities/nonexistent-xyz"
            ])),
            2
        );
    }

    #[test]
    fn exit_profiles_dir_valid_dir() {
        let code = run_doctor(&args(&["--profiles-dir", &fx("profiles-test")]));
        assert_ne!(code, 2);
    }

    #[test]
    fn resolve_shape() {
        let got = resolve_profiles_dir().expect("self exe resolves");
        assert!(got.ends_with("/../profiles"), "{got}");
        assert!(got.starts_with('/'), "{got}");
    }

    #[test]
    fn profiles_dir_vectors() {
        assert_eq!(default_profiles_dir("build/memveil"), "build/../profiles");
        assert_eq!(
            default_profiles_dir("/opt/mv/bin/memveil"),
            "/opt/mv/bin/../profiles"
        );
        assert_eq!(
            default_profiles_dir("/usr/bin/memveil"),
            "/usr/share/memveil/profiles"
        );
        assert_eq!(default_profiles_dir("memveil"), "profiles");
        assert_eq!(default_profiles_dir("/memveil"), "/../profiles");
    }

    fn write_manifest(dir: &std::path::Path) {
        let profiles = dir.join("profiles");
        std::fs::create_dir_all(&profiles).expect("mkdir profiles");
        std::fs::write(profiles.join("manifest.txt"), "p.json\n").expect("write manifest");
    }

    #[test]
    fn cargo_checkout_finds_project_profiles() {
        let tmp = TestDir::create("memveil-cargo-prof").expect("mkdtemp");
        let project = tmp.path().join("proj");
        let exe = project.join("target/release/memveil");
        std::fs::create_dir_all(exe.parent().expect("exe dir")).expect("mkdir exe dir");
        write_manifest(&project);
        let got = cargo_checkout_profiles(exe.to_str().expect("utf-8")).expect("found");
        assert_eq!(got, format!("{}/proj/profiles", tmp.as_str()));
    }

    #[test]
    fn cargo_checkout_finds_parent_profiles() {
        let tmp = TestDir::create("memveil-cargo-prof").expect("mkdtemp");
        let project = tmp.path().join("root/rust");
        let exe = project.join("target/debug/memveil");
        std::fs::create_dir_all(exe.parent().expect("exe dir")).expect("mkdir exe dir");
        write_manifest(tmp.path().join("root").as_path());
        let got = cargo_checkout_profiles(exe.to_str().expect("utf-8")).expect("found");
        assert_eq!(got, format!("{}/root/rust/../profiles", tmp.as_str()));
    }

    #[test]
    fn cargo_checkout_prefers_project_over_parent() {
        let tmp = TestDir::create("memveil-cargo-prof").expect("mkdtemp");
        let project = tmp.path().join("root/rust");
        let exe = project.join("target/release/memveil");
        std::fs::create_dir_all(exe.parent().expect("exe dir")).expect("mkdir exe dir");
        write_manifest(&project);
        write_manifest(tmp.path().join("root").as_path());
        let got = cargo_checkout_profiles(exe.to_str().expect("utf-8")).expect("found");
        assert_eq!(got, format!("{}/root/rust/profiles", tmp.as_str()));
    }

    #[test]
    fn cargo_checkout_rejects_non_cargo_layouts() {
        assert_eq!(cargo_checkout_profiles("build/memveil"), None);
        assert_eq!(cargo_checkout_profiles("/opt/mv/bin/memveil"), None);
        assert_eq!(cargo_checkout_profiles("/usr/bin/memveil"), None);
        assert_eq!(cargo_checkout_profiles("memveil"), None);
        assert_eq!(
            cargo_checkout_profiles("/root/target/deps/memveil-abc123"),
            None
        );
    }

    #[test]
    fn cargo_checkout_rejects_empty_project() {
        // A cargo-shaped path with no project prefix (/target/...)
        // is not a checkout: refuse rather than probing /profiles.
        assert_eq!(cargo_checkout_profiles("/target/release/memveil"), None);
        assert_eq!(cargo_checkout_profiles("/target/debug/memveil"), None);
    }

    #[test]
    fn cargo_checkout_miss_without_manifest() {
        let tmp = TestDir::create("memveil-cargo-prof").expect("mkdtemp");
        let project = tmp.path().join("proj");
        let exe = project.join("target/release/memveil");
        std::fs::create_dir_all(exe.parent().expect("exe dir")).expect("mkdir exe dir");
        assert_eq!(cargo_checkout_profiles(exe.to_str().expect("utf-8")), None);
    }

    #[test]
    fn usage_shape() {
        assert!(doctor_usage().contains("doctor [--json]"));
        assert!(doctor_usage().contains("--load-check"));
    }

    #[test]
    fn doctor2_validated_attempt() {
        let opts = doctor2_opts(
            repo("tests/fixtures/scan/ok"),
            repo("tests/fixtures/scan/profiles"),
            "attempt-trace",
            &elf("ok.o"),
            "",
            "",
        );
        let drep = assess_doctor(&opts);
        assert_eq!(drep.verdict, "ready-load-unchecked");
        assert_eq!(drep.caps.len(), 1);
        assert_eq!(drep.caps[0].id, "attempt-trace");
        assert_eq!(drep.caps[0].status, "available-load-unchecked");
        assert_eq!(run_doctor_opts(&opts), 0);
    }

    #[test]
    fn doctor2_all_on_live38() {
        let opts = live38_opts();
        let drep = assess_doctor(&opts);
        assert_eq!(drep.caps.len(), 3);
        for cap in &drep.caps {
            assert_eq!(cap.status, "available-load-unchecked");
        }
        assert_eq!(
            drep.requested,
            vec!["attempt-trace", "mapping-lifecycle", "copy-actual"]
        );
        assert!(drep.load.is_empty());
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\"mode\": \"passive\""));
        assert!(js.contains("\"lockdown\": {\"mode\": \"none\", \"src\": \"securityfs\"}"));
        assert!(js.contains(
            "\"btf\": {\"state\": \"present\", \"bytes\": \"1063\", \
             \"config_btf\": \"unknown\", \"config_src\": \"proc\"}"
        ));
    }

    #[test]
    fn doctor2_agrees_with_record() {
        let variants = [
            "base",
            "btf-absent-config",
            "btf-absent-unknown",
            "btf-denied",
            "btf-not-visible",
            "container-view",
            "denied-all",
            "events-denied",
            "hook-absent",
            "hook-clone",
            "hook-nokallsyms",
            "hook-not-in-btf",
            "lockdown-conf",
            "notracing-bpfevents",
            "notracing-config",
            "tracefs-gone",
            "tracefs-hidden",
            "tracefs-noevents",
            "tracefs-unmounted",
        ];
        let profiles_dir = repo("tests/fixtures/scan/profiles-live");
        let ok_o = elf("ok.o");
        let lc_o = elf("lc-ok.o");
        let cp_o = elf("cp-ok.o");
        for name in variants {
            let root = gate_fixture(name);
            let reader = open_evidence_reader(&root).expect("gate root opens");
            let env = detect_environment(&reader);
            let ps = load_profiles(&profiles_dir).expect("profiles load");
            let decision = decide_record(
                &root,
                &env.kernel,
                &ps,
                "",
                false,
                &ok_o,
                &lc_o,
                &cp_o,
                "all",
                &profiles_dir,
                "",
            );
            let opts = doctor2_opts(root, profiles_dir.clone(), "all", &ok_o, &lc_o, &cp_o);
            let drep = assess_doctor(&opts);
            assert_eq!(
                drep.verdict == "unavailable",
                !decision.ok,
                "variant {name}"
            );
            if !decision.ok {
                assert_eq!(
                    drep.summary,
                    format!("unavailable: {}", decision.refusal),
                    "variant {name}"
                );
            }
        }
    }

    fn live_cap(fxname: &str, cap_id: &str) -> super::DoctorCap {
        let opts = doctor2_opts(
            gate_fixture(fxname),
            repo("tests/fixtures/scan/profiles-live"),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let drep = assess_doctor(&opts);
        drep.caps
            .into_iter()
            .find(|c| c.id == cap_id)
            .unwrap_or_default()
    }

    #[test]
    fn doctor2_live_btf_truncated_unknown() {
        let lc = live_cap("btf-truncated", "mapping-lifecycle");
        assert_eq!(lc.status, "unknown");
        assert_eq!(lc.reason_code, "btf-truncated");
        assert_eq!(lc.remedy, remedy_for("btf-truncated"));
        let at = live_cap("btf-truncated", "attempt-trace");
        assert_eq!(at.status, "available-load-unchecked");
    }

    #[test]
    fn doctor2_live_ftrace_disabled_fix() {
        let lc = live_cap("ftrace-off", "mapping-lifecycle");
        assert_eq!(lc.status, "unavailable");
        assert_eq!(lc.reason_code, "ftrace-disabled");
        assert_eq!(lc.remedy, remedy_for("ftrace-disabled"));
    }

    #[test]
    fn doctor2_live_hook_ambiguous_code() {
        let lc = live_cap("aff-dup", "mapping-lifecycle");
        assert_eq!(lc.status, "unavailable");
        assert_eq!(lc.reason_code, "hook-ambiguous");
        assert_eq!(lc.remedy, remedy_for("hook-ambiguous"));
    }

    #[test]
    fn doctor2_live_hook_absent_code() {
        let lc = live_cap("hook-absent", "mapping-lifecycle");
        assert_eq!(lc.status, "unavailable");
        assert_eq!(lc.reason_code, "btf-hook-absent");
        assert_eq!(lc.remedy, remedy_for("btf-hook-absent"));
    }

    fn write_tmp_bytes(path: &std::path::Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("tmp parent");
        }
        std::fs::write(path, data).expect("tmp write");
    }

    #[test]
    fn doctor2_two_profile_verdict() {
        let tmp = TestDir::create("memveil-doctor-c3").expect("scratch");
        let raw = std::fs::read(repo("tests/fixtures/scan/profiles-live/live-ref.json"))
            .expect("live ref");
        let text = String::from_utf8(raw).expect("utf-8");
        let base = text.replace(
            "\"profile_id\": \"scan-live-ref\"",
            "\"profile_id\": \"rv-a\"",
        );
        let rva = base.replace(
            "\"id\": \"copy-actual\",\n      \"status\": \"candidate\"",
            "\"id\": \"copy-actual\",\n      \"status\": \"unsupported\"",
        );
        let base_b = text.replace(
            "\"profile_id\": \"scan-live-ref\"",
            "\"profile_id\": \"rv-b\"",
        );
        let rvb = base_b.replace(
            "\"id\": \"mapping-lifecycle\",\n      \"status\": \"candidate\"",
            "\"id\": \"mapping-lifecycle\",\n      \"status\": \"unsupported\"",
        );
        assert!(rva.contains("\"status\": \"unsupported\""));
        assert!(rvb.contains("\"status\": \"unsupported\""));
        write_tmp_bytes(&tmp.path().join("rv-a.json"), rva.as_bytes());
        write_tmp_bytes(&tmp.path().join("rv-b.json"), rvb.as_bytes());
        write_tmp_bytes(&tmp.path().join("manifest.txt"), b"rv-a.json\nrv-b.json\n");
        let pdir = tmp.as_str().to_string();
        let root = gate_fixture("base");
        let opts = doctor2_opts(
            root.clone(),
            pdir.clone(),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let drep = assess_doctor(&opts);
        assert_eq!(drep.verdict, "unavailable");
        assert_eq!(
            drep.summary,
            "unavailable: capability mapping-lifecycle unsupported by rv-b"
        );
        for cap in &drep.caps {
            assert_eq!(cap.status, "available-load-unchecked");
        }
        let reader = open_evidence_reader(&root).expect("root opens");
        let env = detect_environment(&reader);
        let whole = decide_record(
            &root,
            &env.kernel,
            &load_profiles(&pdir).expect("tmp profiles"),
            "",
            false,
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
            "attempt-trace,mapping-lifecycle,copy-actual",
            &pdir,
            "",
        );
        assert!(!whole.ok);
        assert_eq!(drep.summary, format!("unavailable: {}", whole.refusal));
    }

    #[test]
    fn doctor2_missing_objects_refuse() {
        // Explicit-but-absent objects refuse each row with the
        // object-missing code, like the Mojo undiscoverable case.
        let missing = repo("tests/fixtures/elf/no-such-object-xyz.o");
        let opts = doctor2_opts(
            gate_fixture("base"),
            repo("tests/fixtures/scan/profiles-live"),
            "all",
            &missing,
            &missing,
            &missing,
        );
        let drep = assess_doctor(&opts);
        assert_eq!(drep.caps.len(), 3);
        assert_eq!(drep.caps[0].id, "attempt-trace");
        assert_eq!(drep.caps[0].status, "unavailable");
        assert_eq!(drep.caps[0].reason_code, "object-missing");
        assert_eq!(
            drep.caps[0].remedy,
            "install the memveil BPF objects or pass --object, --lc-object, --cp-object"
        );
        assert_eq!(run_doctor_opts(&opts), EXIT_UNAVAILABLE);
    }

    #[test]
    fn doctor2_precheck_fail() {
        let profiles_dir = repo("tests/fixtures/scan/profiles-live");
        let opts = doctor2_opts(
            gate_fixture("caps-none"),
            profiles_dir.clone(),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let drep = assess_doctor(&opts);
        assert_eq!(drep.caps.len(), 3);
        for cap in &drep.caps {
            assert_eq!(cap.status, "unavailable");
            assert_eq!(cap.reason_code, "no-bpf-privilege");
        }
        let mopts = doctor2_opts(
            gate_fixture("memcg-v1"),
            profiles_dir.clone(),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let mdrep = assess_doctor(&mopts);
        assert_eq!(mdrep.caps.len(), 3);
        for cap in &mdrep.caps {
            assert_eq!(cap.status, "available-load-unchecked");
            assert!(cap.evidence.iter().any(|e| e.starts_with("memcg: unknown")));
        }
        let sopts = doctor2_opts(
            gate_fixture("memcg-small"),
            profiles_dir,
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let sdrep = assess_doctor(&sopts);
        assert_eq!(sdrep.caps.len(), 3);
        for cap in &sdrep.caps {
            assert_eq!(cap.status, "available-load-unchecked");
            assert!(cap.evidence.iter().any(|e| e.starts_with("memcg: unknown")));
        }
    }

    #[test]
    fn precheck_demotes_passive_only() {
        assert!(precheck_demotes("no-bpf-privilege", false));
        assert!(!precheck_demotes("no-bpf-privilege", true));
        assert!(!precheck_demotes("", false));
        assert!(!precheck_demotes("", true));
    }

    #[test]
    fn doctor2_bridge_unchecked_unknown() {
        let tmp = TestDir::create("memveil-doctor-i8").expect("scratch");
        let doc = std::fs::read(repo("tests/fixtures/scan/profiles/ref-lc.json")).expect("doc");
        write_tmp_bytes(&tmp.path().join("ref-lc.json"), &doc);
        write_tmp_bytes(&tmp.path().join("manifest.txt"), b"ref-lc.json\n");
        let rec = std::fs::read(repo(
            "tests/fixtures/scan/profiles/receipts/scan-ref-lc.json",
        ))
        .expect("receipt");
        write_tmp_bytes(&tmp.path().join("receipts/scan-ref-lc.json"), &rec);
        let opts = doctor2_opts(
            repo("tests/fixtures/scan/ok"),
            tmp.as_str().to_string(),
            "all",
            &elf("ok.o"),
            &elf("lc-ok.o"),
            &elf("cp-ok.o"),
        );
        let drep = assess_doctor(&opts);
        for cap in &drep.caps {
            if cap.id == "conversion-observe" {
                continue;
            }
            if cap.id == "attempt-trace" {
                assert_eq!(cap.status, "available-load-unchecked");
            } else {
                assert_eq!(cap.status, "unknown");
                assert_eq!(cap.reason_code, "bridge-unchecked");
                assert!(cap.reason.contains("bridge unchecked"), "{}", cap.reason);
            }
        }
        assert_eq!(drep.verdict, "unavailable");
        assert!(drep.summary.contains("bridge unchecked"));
    }

    #[test]
    fn doctor2_notes() {
        let profiles_dir = repo("tests/fixtures/scan/profiles-live");
        let want = "no swiotlb pool active: attempts will be 0";
        for name in ["swiotlb-noforce", "swiotlb-inactive", "swiotlb-noslabs"] {
            let opts = doctor2_opts(
                gate_fixture(name),
                profiles_dir.clone(),
                "all",
                &elf("ok.o"),
                &elf("lc-ok.o"),
                &elf("cp-ok.o"),
            );
            let drep = assess_doctor(&opts);
            assert!(drep.notes.iter().any(|n| n == want), "fixture {name}");
        }
        for name in ["base", "swiotlb-debugonly", "swiotlb-active"] {
            let opts = doctor2_opts(
                gate_fixture(name),
                profiles_dir.clone(),
                "all",
                &elf("ok.o"),
                &elf("lc-ok.o"),
                &elf("cp-ok.o"),
            );
            let drep = assess_doctor(&opts);
            assert!(!drep.notes.iter().any(|n| n == want), "fixture {name}");
        }
    }

    #[test]
    fn doctor2_flags() {
        assert_eq!(
            run_doctor(&args(&["--capability", "attempt-trace,nope"])),
            2
        );
        assert_eq!(run_doctor(&args(&["--capability"])), 2);
        let pdir = profiles_dir();
        let live = run_doctor(&[
            "--load-check".to_string(),
            "--profiles-dir".to_string(),
            pdir,
        ]);
        assert_ne!(live, 2);
    }

    #[test]
    fn doctor_load_check_needs_live() {
        let opts = DoctorOptions {
            root: gate_fixture("base"),
            profiles_dir: repo("tests/fixtures/scan/profiles-live"),
            load_check: true,
            ..DoctorOptions::default()
        };
        assert_eq!(run_doctor_opts(&opts), 2);
    }

    #[test]
    fn doctor2_json_schema_marker() {
        let drep = assess_doctor(&live38_opts());
        let js = render_doctor_json2(&drep);
        assert!(js.contains("\"schema_version\": \"0.1.1\""));
    }
}
