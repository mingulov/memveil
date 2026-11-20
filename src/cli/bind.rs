// Copyright (c) 2026 Denis Mingulov
// SPDX-License-Identifier: GPL-3.0-or-later
//! Mint a bound profile document from live evidence (bind-profile verb).

use crate::capture::run::{MAX_PROFILE_DOC_BYTES, parse_requested_caps, resolve_object};
use crate::cli::doctor::resolve_profiles_dir;
use crate::cli::qualify::publish_receipt;
use crate::cli::report::{
    CliError, EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, EXIT_REFUSAL, sanitize_diagnostic, write_stderr,
};
use crate::platform::artifact_files::join_root;
use crate::platform::evidence::{KernelInfo, detect_environment, parse_kernel_triple};
use crate::platform::narrow::{
    MAX_NARROW_FORMAT_BYTES, NarrowBindings, format_narrow_note, measure_live_bindings,
    read_live_object, tracefs_format_path,
};
use crate::platform::profiles::{
    NamedProfiles, Profile, ProfileHook, load_profiles, load_profiles_named, parse_profile_bytes,
    select_profile,
};
use crate::platform::reader::{open_evidence_reader, read_host_file, readlink_self};
use crate::platform::stdout::write_stdout;
use crate::render::json::escape_json;

const LIFECYCLE: &str = "mapping-lifecycle";
const COPY: &str = "copy-actual";
const CONVERT: &str = "conversion-observe";
const JOURNAL: &str = "conversion-journal";
const ZLIB: &str = "libz.so.1";
const RING_ATTEMPT: &str = "8388608";
const RING_EXTRA: &str = "33554432";
const MAX_FORMAT_TEXT: usize = 65536;
const MAX_NOTE: usize = 1024;
const CAP_REASON: &str = "Candidate collection source; availability is checked passively, semantics are unproven until qualify.";
const IDENTITY_NOTE: &str = "Narrow identity for this host; bindings refuse every other identity.";
const HOOK_NOTE: &str =
    "Hook definition copied from the covering reference; admission checks it live.";

/// Parsed bind-profile arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BindOptions {
    /// Minted document path.
    pub output: String,
    /// Attempt channel object override.
    pub object: String,
    /// Explicit base profile id or path.
    pub profile: String,
    /// True when --profile was passed.
    pub has_profile: bool,
    /// Profiles directory.
    pub profiles_dir: String,
    /// True when --profiles-dir was passed.
    pub has_profiles_dir: bool,
    /// Lifecycle channel object override.
    pub lc_object: String,
    /// Copy channel object override.
    pub cp_object: String,
    /// Requested capability list.
    pub capabilities: String,
    /// Minted profile id override.
    pub profile_id: String,
    /// True when --profile-id was passed.
    pub has_profile_id: bool,
}

fn is_option(text: &str) -> bool {
    text.as_bytes().first() == Some(&0x2d)
}

/// Parse bind-profile arguments without the leading verb.
pub fn parse_bind_args(args: &[String]) -> Result<BindOptions, CliError> {
    let mut opts = BindOptions::default();
    let mut i = 0;
    while i < args.len() {
        let tok = args[i].as_str();
        if tok == "--output" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--output needs a value".to_string(),
                });
            }
            opts.output = args[i + 1].clone();
            i += 2;
        } else if tok == "--object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--object needs a value".to_string(),
                });
            }
            opts.object = args[i + 1].clone();
            i += 2;
        } else if tok == "--profile" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--profile needs a value".to_string(),
                });
            }
            opts.profile = args[i + 1].clone();
            opts.has_profile = true;
            i += 2;
        } else if tok == "--profiles-dir" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--profiles-dir needs a value".to_string(),
                });
            }
            opts.profiles_dir = args[i + 1].clone();
            opts.has_profiles_dir = true;
            i += 2;
        } else if tok == "--lc-object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--lc-object needs a value".to_string(),
                });
            }
            opts.lc_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--cp-object" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--cp-object needs a value".to_string(),
                });
            }
            opts.cp_object = args[i + 1].clone();
            i += 2;
        } else if tok == "--capability" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--capability needs a value".to_string(),
                });
            }
            opts.capabilities = args[i + 1].clone();
            i += 2;
        } else if tok == "--profile-id" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--profile-id needs a value".to_string(),
                });
            }
            opts.profile_id = args[i + 1].clone();
            opts.has_profile_id = true;
            i += 2;
        } else if is_option(tok) {
            return Err(CliError {
                message: format!("unknown option: {tok}"),
            });
        } else {
            return Err(CliError {
                message: format!("unexpected argument: {tok}"),
            });
        }
    }
    if opts.output.is_empty() {
        return Err(CliError {
            message: "missing --output".to_string(),
        });
    }
    Ok(opts)
}

/// Usage text for the bind-profile verb.
pub fn bind_usage() -> String {
    concat!(
        "usage: memveil bind-profile --output PATH [--profile ID|PATH]\n",
        "       [--profiles-dir DIR] [--object PATH] [--lc-object PATH]\n",
        "       [--cp-object PATH] [--capability LIST] [--profile-id ID]\n",
        "\n",
        "Mint a bound reference-unvalidated profile document for\n",
        "this host: hook definitions come from the covering\n",
        "reference, identity bindings and tracepoint format text\n",
        "are measured live. Register the minted file first in\n",
        "the profiles manifest, then run qualify against it.\n",
        "Format text and the kernel image need root reads; run\n",
        "under sudo when they deny the current user.\n",
        "Attempt-trace is the mandatory base channel; extra\n",
        "channels bind together (both objects required) with\n",
        "the canonical ring sizes, verified live at qualify.\n",
        "Minted documents carry no BTF layouts: signature and\n",
        "smoke checks still apply, layout pins do not.\n",
        "--object is required: without it the run refuses.\n",
        "Extra channels need --lc-object and --cp-object\n",
        "together.\n",
    )
    .to_string()
}

/// Report one cannot-mint outcome; return EXIT_REFUSAL.
fn bind_failed(detail: &str) -> i64 {
    let line = format!("memveil bind-profile: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_REFUSAL,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Report one usage failure; return EXIT_INVALID.
fn bind_misused(detail: &str) -> i64 {
    let line = format!("memveil bind-profile: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Report one internal failure; return EXIT_INTERNAL.
fn bind_broken(detail: &str) -> i64 {
    let line = format!("memveil bind-profile: {}\n", sanitize_diagnostic(detail));
    let _ = write_stderr(&line);
    EXIT_INTERNAL
}

fn is_id_start(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == 0x5f
}

fn is_id_rest(b: u8) -> bool {
    is_id_start(b) || b == 0x2e || b == 0x2d
}

/// True for the profile_id schema pattern (1..128 chars).
pub fn valid_profile_id(text: &str) -> bool {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 128 {
        return false;
    }
    if !is_id_start(raw[0]) {
        return false;
    }
    raw[1..].iter().all(|&b| is_id_rest(b))
}

/// Derive local-\<release\> with unpatterned bytes dashed.
pub fn default_profile_id(release: &str) -> String {
    let mut out = String::from("local-");
    for &b in release.as_bytes() {
        if is_id_rest(b) {
            out.push(b as char);
        } else {
            out.push('-');
        }
    }
    if out.len() > 128 {
        out.truncate(128);
    }
    out
}

/// Major.minor cover floor for a release, or "".
pub fn min_kernel_for(release: &str) -> String {
    let triple = parse_kernel_triple(release);
    if !triple.ok {
        return String::new();
    }
    format!("{}.{}", triple.major, triple.minor)
}

/// Resolve the base document; returns the refusal, or "" resolved.
///
/// An explicit --profile wins by file then id; otherwise the first
/// covering manifest document wins, exactly like record admission.
fn resolve_base(
    explicit: &str,
    has_explicit: bool,
    profiles_dir: &str,
    kernel: &KernelInfo,
) -> Result<Profile, String> {
    if has_explicit {
        let named: NamedProfiles = match load_profiles_named(profiles_dir) {
            Ok(named) => named,
            Err(e) => return Err(format!("cannot load profiles: {e}")),
        };
        if let Ok(raw) = read_host_file(explicit, "profile", MAX_PROFILE_DOC_BYTES) {
            match parse_profile_bytes(&raw) {
                Ok(base) => return Ok(base),
                Err(e) => return Err(format!("cannot parse --profile: {e}")),
            }
        }
        for profile in &named.profiles {
            if profile.profile_id == explicit {
                return Ok(profile.clone());
            }
        }
        return Err(format!("unknown --profile: {explicit}"));
    }
    let docs = match load_profiles(profiles_dir) {
        Ok(docs) => docs,
        Err(e) => return Err(format!("cannot load profiles: {e}")),
    };
    let decision = select_profile(kernel, &docs);
    if !decision.has_profile {
        return Err(format!("no covering profile: {}", decision.reason));
    }
    Ok(decision.profile.clone())
}

/// Collect the base capability's hook names; empty when none.
fn base_hooks_for(base: &Profile, cap: &str) -> Vec<String> {
    for decl in &base.caps {
        if decl.id == cap {
            return decl.hooks.clone();
        }
    }
    Vec::new()
}

fn find_hook<'a>(base: &'a Profile, name: &str) -> Option<&'a ProfileHook> {
    base.hooks.iter().find(|hook| hook.name == name)
}

/// Live tracepoint format bytes, translated onto the root.
fn read_format_text(root: &str, hook: &ProfileHook) -> Result<String, String> {
    let path = tracefs_format_path(root, &hook.format_path);
    let raw = match read_host_file(&join_root(root, &path), "format", MAX_NARROW_FORMAT_BYTES) {
        Ok(raw) => raw,
        Err(_) => return Err(format!("format text unreadable: {}", hook.format_path)),
    };
    if raw.len() > MAX_FORMAT_TEXT {
        return Err("format text exceeds 65536 bytes".to_string());
    }
    match String::from_utf8(raw) {
        Ok(text) => Ok(text),
        Err(_) => Err("format text is not UTF-8".to_string()),
    }
}

/// Render one hook object; tracing keeps its signature.
fn hook_json(hook: &ProfileHook, format_text: &str, has_format: bool) -> String {
    let mut out = String::from("    {\n");
    out += &format!("      \"name\": {},\n", escape_json(&hook.name));
    out += &format!("      \"kind\": {},\n", escape_json(&hook.kind));
    if hook.kind == "tracepoint" {
        out += &format!("      \"id_path\": {},\n", escape_json(&hook.id_path));
        out += &format!(
            "      \"format_path\": {},\n",
            escape_json(&hook.format_path)
        );
        if has_format {
            out += &format!("      \"format_text\": {},\n", escape_json(format_text));
        }
    } else {
        out += &format!("      \"function\": {},\n", escape_json(&hook.function));
        out += &format!("      \"attach\": {},\n", escape_json(&hook.attach));
        out += &format!("      \"signature\": {},\n", escape_json(&hook.signature));
        if !hook.signature_alt.is_empty() {
            out += "      \"signature_alt\": [";
            for (i, alt) in hook.signature_alt.iter().enumerate() {
                if i > 0 {
                    out += ", ";
                }
                out += &escape_json(alt);
            }
            out += "],\n";
        }
    }
    if hook.has_note {
        out += &format!("      \"note\": {}\n", escape_json(&hook.note));
    } else {
        out += &format!("      \"note\": {}\n", escape_json(HOOK_NOTE));
    }
    out += "    }";
    out
}

/// Render one candidate capability object.
fn cap_json(cap: &str, hooks: &[String]) -> String {
    let mut out = String::from("    {\n");
    out += &format!("      \"id\": {},\n", escape_json(cap));
    out += "      \"status\": \"candidate\",\n";
    out += "      \"hooks\": [";
    for (i, hook) in hooks.iter().enumerate() {
        if i > 0 {
            out += ", ";
        }
        out += &escape_json(hook);
    }
    out += "],\n";
    out += &format!("      \"reason\": {}\n", escape_json(CAP_REASON));
    out += "    }";
    out
}

/// Render the minted 0.1.1 document text.
#[allow(clippy::too_many_arguments)]
pub fn render_bound_profile(
    profile_id: &str,
    arch: &str,
    min_kernel: &str,
    release: &str,
    note: &str,
    hooks: &[ProfileHook],
    formats: &[String],
    has_formats: &[bool],
    caps: &[String],
    cap_hooks: &[Vec<String>],
) -> String {
    let mut out = String::from("{\n");
    out += "  \"schema_version\": \"0.1.1\",\n";
    out += &format!("  \"profile_id\": {},\n", escape_json(profile_id));
    out += "  \"status\": \"reference-unvalidated\",\n";
    out += "  \"identity\": {\n";
    out += &format!("    \"arch\": {},\n", escape_json(arch));
    out += &format!("    \"min_kernel\": {},\n", escape_json(min_kernel));
    out += "    \"source\": {\n";
    out += "      \"origin\": \"distro\",\n";
    out += &format!("      \"revision\": {},\n", escape_json(release));
    out += &format!("      \"note\": {}\n", escape_json(note));
    out += "    },\n";
    out += &format!("    \"note\": {}\n", escape_json(IDENTITY_NOTE));
    out += "  },\n";
    out += "  \"hooks\": [\n";
    for (i, hook) in hooks.iter().enumerate() {
        if i > 0 {
            out += ",\n";
        }
        out += &hook_json(hook, &formats[i], has_formats[i]);
    }
    out += "\n  ],\n";
    out += "  \"capabilities\": [\n";
    for (i, cap) in caps.iter().enumerate() {
        if i > 0 {
            out += ",\n";
        }
        out += &cap_json(cap, &cap_hooks[i]);
    }
    out += "\n  ],\n";
    let minted = format!(
        "Minted from live {release} evidence by memveil bind-profile; inspection is not qualification evidence."
    );
    out += &format!("  \"notes\": [{}]\n", escape_json(&minted));
    out += "}\n";
    out
}

/// One mint attempt: doc text, or err with refusal text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MintOut {
    /// True when text holds the minted document.
    pub ok: bool,
    /// Minted document text.
    pub text: String,
    /// Refusal detail; empty when ok.
    pub err: String,
}

/// Measure live bindings and render the bound document.
///
/// Never fails: every failure returns err text naming the exact
/// unmeasurable binding, missing hook, or unresolved object. Object
/// paths are explicit-only (an absent path is a refusal
/// naming the missing flag); rings are the
/// canonical sizes, verified live again at qualify.
#[allow(clippy::too_many_arguments)]
pub fn mint_bound_profile(
    root: &str,
    exe_path: &str,
    base: &Profile,
    caps: &[String],
    obj: &str,
    lc_obj: &str,
    cp_obj: &str,
    profile_id: &str,
    release: &str,
    arch: &str,
) -> MintOut {
    let _ = exe_path;
    let mut out = MintOut::default();
    let mut want_extra = false;
    for cap in caps {
        if cap == LIFECYCLE || cap == COPY {
            want_extra = true;
        }
    }
    let mut emit_hooks: Vec<ProfileHook> = Vec::new();
    let mut emit_names: Vec<String> = Vec::new();
    let mut cap_hooks: Vec<Vec<String>> = Vec::new();
    for cap in caps {
        let names = base_hooks_for(base, cap);
        if names.is_empty() {
            out.err = format!("base profile has no hooks for {cap}");
            return out;
        }
        let mut one: Vec<String> = Vec::new();
        for name in &names {
            let hook = match find_hook(base, name) {
                Some(hook) => hook,
                None => {
                    out.err = format!("base profile lacks hook {name}");
                    return out;
                }
            };
            one.push(name.clone());
            if !emit_names.iter().any(|seen| seen == name) {
                emit_names.push(name.clone());
                emit_hooks.push(hook.clone());
            }
        }
        cap_hooks.push(one);
    }
    let attempt_hook = emit_hooks.iter().find(|hook| hook.kind == "tracepoint");
    let attempt_hook = match attempt_hook {
        Some(hook) => hook,
        None => {
            out.err = "no tracepoint hook to bind".to_string();
            return out;
        }
    };
    let mut bindings = NarrowBindings::new();
    let measure_err = measure_live_bindings(
        root,
        release,
        ZLIB,
        &attempt_hook.format_path,
        &mut bindings,
    );
    if !measure_err.is_empty() {
        out.err = measure_err;
        return out;
    }
    let obj_path = resolve_object(obj);
    if obj_path.is_empty() {
        out.err = "no object: pass --object PATH".to_string();
        return out;
    }
    let obj_live = read_live_object(&obj_path);
    if obj_live.state != "value" {
        out.err = format!("attempt object unreadable: {obj_path}");
        return out;
    }
    bindings.object = obj_live.value.clone();
    bindings.ring = RING_ATTEMPT.to_string();
    if want_extra {
        let lc_path = resolve_object(lc_obj);
        if lc_path.is_empty() {
            out.err = "no lifecycle object: pass --lc-object PATH".to_string();
            return out;
        }
        let lc_live = read_live_object(&lc_path);
        if lc_live.state != "value" {
            out.err = format!("lifecycle object unreadable: {lc_path}");
            return out;
        }
        let cp_path = resolve_object(cp_obj);
        if cp_path.is_empty() {
            out.err = "no copy object: pass --cp-object PATH".to_string();
            return out;
        }
        let cp_live = read_live_object(&cp_path);
        if cp_live.state != "value" {
            out.err = format!("copy object unreadable: {cp_path}");
            return out;
        }
        bindings.lc_object = lc_live.value.clone();
        bindings.lc_ring = RING_EXTRA.to_string();
        bindings.cp_object = cp_live.value.clone();
        bindings.cp_ring = RING_EXTRA.to_string();
    }
    let mut formats: Vec<String> = Vec::new();
    let mut has_formats: Vec<bool> = Vec::new();
    for hook in &emit_hooks {
        if hook.kind == "tracepoint" {
            match read_format_text(root, hook) {
                Ok(text) => formats.push(text),
                Err(e) => {
                    out.err = e;
                    return out;
                }
            }
            has_formats.push(true);
        } else {
            formats.push(String::new());
            has_formats.push(false);
        }
    }
    let note = match format_narrow_note(&bindings, want_extra) {
        Ok(note) => note,
        Err(e) => {
            out.err = format!("cannot assemble note: {e}");
            return out;
        }
    };
    if note.len() > MAX_NOTE {
        out.err = "assembled note exceeds 1024 bytes".to_string();
        return out;
    }
    let floor = min_kernel_for(release);
    if floor.is_empty() {
        out.err = format!("release {release} is unparseable");
        return out;
    }
    out.text = render_bound_profile(
        profile_id,
        arch,
        &floor,
        release,
        &note,
        &emit_hooks,
        &formats,
        &has_formats,
        caps,
        &cap_hooks,
    );
    out.ok = true;
    out
}

/// Run the bind flow against explicit roots; return exit code.
///
/// `root` is the evidence root ("" for the live host); `exe_path`
/// is ignored (retained for call-shape parity). Publishes
/// the minted document at
/// opts.output, atomically.
pub fn run_bind_with(root: &str, exe_path: &str, profiles_dir: &str, opts: &BindOptions) -> i64 {
    let ask = parse_requested_caps(&opts.capabilities);
    if !ask.ok {
        return bind_failed(&ask.err);
    }
    for cap in &ask.caps {
        if cap == CONVERT {
            return bind_failed("capability conversion-observe has no record channel");
        }
        if cap == JOURNAL {
            return bind_failed("capability conversion-journal has no record channel");
        }
    }
    if opts.has_profile_id && !valid_profile_id(&opts.profile_id) {
        return bind_misused(&format!("bad --profile-id: {}", opts.profile_id));
    }
    let reader = match open_evidence_reader(root) {
        Ok(reader) => reader,
        Err(e) => return bind_failed(&format!("cannot open evidence: {e}")),
    };
    let env = detect_environment(&reader);
    if !env.kernel.eligible_floor {
        return bind_failed(&env.kernel.floor_reason);
    }
    let mut pid = opts.profile_id.clone();
    if !opts.has_profile_id {
        pid = default_profile_id(&env.kernel.release);
    }
    let base = match resolve_base(&opts.profile, opts.has_profile, profiles_dir, &env.kernel) {
        Ok(base) => base,
        Err(err) => return bind_failed(&err),
    };
    let minted = mint_bound_profile(
        root,
        exe_path,
        &base,
        &ask.caps,
        &opts.object,
        &opts.lc_object,
        &opts.cp_object,
        &pid,
        &env.kernel.release,
        &env.kernel.arch,
    );
    if !minted.ok {
        return bind_failed(&minted.err);
    }
    if let Err(e) = publish_receipt(&opts.output, &minted.text) {
        return bind_broken(&format!("cannot publish document: {e}"));
    }
    let listed = ask.caps.join(",");
    if write_stdout(&format!(
        "bind-profile: {pid} caps={listed} path={}\n",
        opts.output
    ))
    .is_err()
    {
        return bind_broken("cannot write stdout");
    }
    EXIT_OK
}

/// Run the bind-profile verb; return the process exit code.
///
/// `args` excludes the program name and the bind-profile word.
/// Profiles resolve from --profiles-dir or the kernel-resolved
/// binary path, never from argv[0] or the working directory.
pub fn run_bind(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&bind_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => return bind_broken("cannot write stdout"),
        }
    }
    let opts = match parse_bind_args(args) {
        Ok(opts) => opts,
        Err(e) => return bind_misused(&e.message),
    };
    let profiles_dir = if opts.has_profiles_dir {
        opts.profiles_dir.clone()
    } else {
        match resolve_profiles_dir() {
            Ok(dir) => dir,
            Err(e) => {
                return bind_failed(&format!("cannot resolve profiles location: {}", e.message));
            }
        }
    };
    let exe_path = match readlink_self() {
        Ok(exe) => exe,
        Err(e) => return bind_broken(&format!("cannot resolve executable path: {e}")),
    };
    run_bind_with("", &exe_path, &profiles_dir, &opts)
}

#[cfg(test)]
mod tests {
    use super::{
        BindOptions, default_profile_id, min_kernel_for, mint_bound_profile, parse_bind_args,
        render_bound_profile, run_bind_with, valid_profile_id,
    };
    use crate::platform::narrow::{parse_narrow_note, read_live_object};
    use crate::platform::profiles::{Profile, parse_profile_bytes};
    use crate::platform::reader::read_host_file;
    use crate::platform::test_support::{TestDir, repo_root};

    fn repo(path: &str) -> String {
        repo_root().join(path).to_str().expect("utf-8").to_string()
    }

    fn host() -> String {
        repo("tests/fixtures/qualify/host")
    }

    fn pdir() -> String {
        repo("tests/fixtures/qualify/profiles")
    }

    fn obj() -> String {
        repo("tests/fixtures/elf/ok.o")
    }

    fn lc_obj() -> String {
        repo("tests/fixtures/elf/lc-ok.o")
    }

    fn cp_obj() -> String {
        repo("tests/fixtures/elf/cp-ok.o")
    }

    fn base_doc() -> Profile {
        let raw = read_host_file(&format!("{}/qual-ref.json", pdir()), "profile", 1048576)
            .expect("ref doc");
        parse_profile_bytes(&raw).expect("ref parses")
    }

    fn ref_note() -> String {
        base_doc().identity.source.note.clone()
    }

    #[test]
    fn bind_args_missing_output() {
        assert!(parse_bind_args(&[]).is_err());
    }

    #[test]
    fn bind_args_full() {
        let opts = parse_bind_args(&[
            "--output".to_string(),
            "/tmp/x.json".to_string(),
            "--profile".to_string(),
            "my-host".to_string(),
            "--profiles-dir".to_string(),
            "pd".to_string(),
            "--object".to_string(),
            "o".to_string(),
            "--lc-object".to_string(),
            "l".to_string(),
            "--cp-object".to_string(),
            "c".to_string(),
            "--capability".to_string(),
            "attempt-trace".to_string(),
            "--profile-id".to_string(),
            "pid".to_string(),
        ])
        .expect("full parses");
        assert_eq!(opts.output, "/tmp/x.json");
        assert_eq!(opts.profile, "my-host");
        assert!(opts.has_profile);
        assert_eq!(opts.profiles_dir, "pd");
        assert!(opts.has_profiles_dir);
        assert_eq!(opts.object, "o");
        assert_eq!(opts.lc_object, "l");
        assert_eq!(opts.cp_object, "c");
        assert_eq!(opts.capabilities, "attempt-trace");
        assert_eq!(opts.profile_id, "pid");
        assert!(opts.has_profile_id);
    }

    #[test]
    fn bind_args_rejections() {
        let cases: Vec<Vec<String>> = vec![
            vec!["--output".to_string()],
            vec![
                "--output".to_string(),
                "x".to_string(),
                "--bogus".to_string(),
            ],
            vec!["--output".to_string(), "x".to_string(), "stray".to_string()],
            vec![
                "--output".to_string(),
                "x".to_string(),
                "--profile-id".to_string(),
            ],
        ];
        for case in &cases {
            assert!(parse_bind_args(case).is_err(), "{case:?}");
        }
        let err = parse_bind_args(&[
            "--output".to_string(),
            "x".to_string(),
            "--bogus".to_string(),
        ])
        .expect_err("bogus rejects");
        assert_eq!(err.message, "unknown option: --bogus");
        let err = parse_bind_args(&["--output".to_string(), "x".to_string(), "stray".to_string()])
            .expect_err("stray rejects");
        assert_eq!(err.message, "unexpected argument: stray");
    }

    #[test]
    fn profile_id_rules() {
        assert!(valid_profile_id("my-host"));
        assert!(valid_profile_id("local-7.0.0-test"));
        assert!(!valid_profile_id(""));
        assert!(!valid_profile_id("-lead-dash"));
        assert!(!valid_profile_id("has space"));
        assert!(!valid_profile_id("has/slash"));
        assert!(!valid_profile_id(&"x".repeat(129)));
        assert_eq!(default_profile_id("7.0.0-test"), "local-7.0.0-test");
        assert_eq!(default_profile_id("7.0 foo!"), "local-7.0-foo-");
        assert_eq!(min_kernel_for("7.0.0-test"), "7.0");
        assert_eq!(min_kernel_for("6.12.1"), "6.12");
        assert_eq!(min_kernel_for("bogus"), "");
    }

    #[test]
    fn mint_reproduces_reference_note() {
        let minted = mint_bound_profile(
            &host(),
            "",
            &base_doc(),
            &["attempt-trace".to_string()],
            &obj(),
            "",
            "",
            "test-bind",
            "7.0.0-test",
            "x86_64",
        );
        assert!(minted.ok, "{}", minted.err);
        let doc = parse_profile_bytes(minted.text.as_bytes()).expect("minted parses");
        assert_eq!(doc.profile_id, "test-bind");
        assert_eq!(doc.status, "reference-unvalidated");
        assert_eq!(doc.schema_version, "0.1.1");
        assert_eq!(doc.identity.min_kernel, "7.0");
        assert_eq!(doc.identity.source.note, ref_note());
        assert_eq!(doc.caps.len(), 1);
        assert_eq!(doc.caps[0].id, "attempt-trace");
        assert_eq!(doc.caps[0].status, "candidate");
        let mut hook_text = String::new();
        for hook in &doc.hooks {
            if hook.kind == "tracepoint" {
                assert!(hook.format_has);
                hook_text = hook.format_text.clone();
            }
        }
        let raw = read_host_file(
            &format!(
                "{}/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format",
                host()
            ),
            "format",
            1048576,
        )
        .expect("format");
        assert_eq!(hook_text, String::from_utf8(raw).expect("utf-8"));
    }

    #[test]
    fn mint_extra_binds_twelve_fields() {
        let minted = mint_bound_profile(
            &host(),
            "",
            &base_doc(),
            &["attempt-trace".to_string(), "mapping-lifecycle".to_string()],
            &obj(),
            &lc_obj(),
            &cp_obj(),
            "test-bind-extra",
            "7.0.0-test",
            "x86_64",
        );
        assert!(minted.ok, "{}", minted.err);
        let doc = parse_profile_bytes(minted.text.as_bytes()).expect("minted parses");
        let parsed = parse_narrow_note(&doc.identity.source.note);
        assert!(parsed.ok, "{}", parsed.message);
        let lc = read_live_object(&lc_obj());
        let cp = read_live_object(&cp_obj());
        assert_eq!(lc.state, "value");
        assert_eq!(cp.state, "value");
        assert_eq!(parsed.bindings.lc_object, lc.value);
        assert_eq!(parsed.bindings.lc_ring, "33554432");
        assert_eq!(parsed.bindings.cp_object, cp.value);
        assert_eq!(parsed.bindings.cp_ring, "33554432");
        assert_eq!(doc.caps.len(), 2);
    }

    #[test]
    fn mint_refusals_name_cause() {
        let base = base_doc();
        let bad_root = mint_bound_profile(
            "no-such-root",
            "",
            &base,
            &["attempt-trace".to_string()],
            &obj(),
            "",
            "",
            "x",
            "7.0.0-test",
            "x86_64",
        );
        assert!(!bad_root.ok);
        assert!(bad_root.err.contains("config"), "{}", bad_root.err);
        let no_obj = mint_bound_profile(
            &host(),
            "",
            &base,
            &["attempt-trace".to_string()],
            "",
            "",
            "",
            "x",
            "7.0.0-test",
            "x86_64",
        );
        assert!(!no_obj.ok);
        assert!(no_obj.err.contains("no object"), "{}", no_obj.err);
        let no_lc = mint_bound_profile(
            &host(),
            "",
            &base,
            &["attempt-trace".to_string(), "mapping-lifecycle".to_string()],
            &obj(),
            "",
            &cp_obj(),
            "x",
            "7.0.0-test",
            "x86_64",
        );
        assert!(!no_lc.ok);
        assert!(no_lc.err.contains("lifecycle object"), "{}", no_lc.err);
        let no_hooks = mint_bound_profile(
            &host(),
            "",
            &base,
            &["copy-actual".to_string()],
            &obj(),
            "",
            "",
            "x",
            "7.0.0-test",
            "x86_64",
        );
        assert!(!no_hooks.ok);
        assert!(no_hooks.err.contains("no hooks"), "{}", no_hooks.err);
    }

    #[test]
    fn render_bound_profile_shape() {
        // The minted document round-trips through the profile parser
        // with the 0.1.1 envelope the manifest loader expects.
        let hooks = base_doc().hooks;
        let formats = vec!["fmt".to_string(); hooks.len()];
        let has_formats = vec![true; hooks.len()];
        let text = render_bound_profile(
            "shape-probe",
            "x86_64",
            "7.0",
            "7.0.0-test",
            "config=sha256:aa",
            &hooks,
            &formats,
            &has_formats,
            &["attempt-trace".to_string()],
            &[vec!["h".to_string()]],
        );
        assert!(text.starts_with("{\n  \"schema_version\": \"0.1.1\",\n"));
        assert!(text.ends_with("}\n"));
        assert!(text.contains("\"profile_id\": \"shape-probe\""));
    }

    fn bind_opts(output: String) -> BindOptions {
        BindOptions {
            output,
            object: obj(),
            ..BindOptions::default()
        }
    }

    #[test]
    fn run_bind_publishes() {
        let tmp = TestDir::create("memveil-bind").expect("scratch");
        let out = format!("{}/minted.json", tmp.as_str());
        let opts = bind_opts(out.clone());
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts), 0);
        let raw = read_host_file(&out, "minted", 1048576).expect("minted");
        let doc = parse_profile_bytes(&raw).expect("minted parses");
        assert_eq!(doc.profile_id, "local-7.0.0-test");
        assert_eq!(doc.identity.source.note, ref_note());
    }

    #[test]
    fn run_bind_exits() {
        let tmp = TestDir::create("memveil-bind").expect("scratch");
        let opts = bind_opts(format!("{}/x.json", tmp.as_str()));
        assert_eq!(run_bind_with("no-such-root", "", &pdir(), &opts), 3);
        let mut opts2 = bind_opts(format!("{}/y.json", tmp.as_str()));
        opts2.profile = "no-such-profile".to_string();
        opts2.has_profile = true;
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts2), 3);
        let mut opts3 = bind_opts(format!("{}/z.json", tmp.as_str()));
        opts3.profile_id = "bad id".to_string();
        opts3.has_profile_id = true;
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts3), 2);
        let mut opts4 = bind_opts(format!("{}/w.json", tmp.as_str()));
        opts4.capabilities = "bogus-cap".to_string();
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts4), 3);
        let mut opts5 = bind_opts(format!("{}/v.json", tmp.as_str()));
        opts5.capabilities = "conversion-observe".to_string();
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts5), 3);
        let mut opts6 = bind_opts(format!("{}/u.json", tmp.as_str()));
        opts6.capabilities = "conversion-journal".to_string();
        assert_eq!(run_bind_with(&host(), "", &pdir(), &opts6), 3);
    }
}
