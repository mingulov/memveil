// SPDX-License-Identifier: GPL-3.0-or-later
//! Local-auto qualification: prove this host, mint a receipt.
//!
//! `memveil qualify` runs a short smoke capture (attach, poll, detach; an
//! idle ring is honest success) against one covering profile and, when the
//! smoke proves the requested channels, publishes a machine-local receipt
//! under the receipts dir (`<profiles-dir>/receipts`, or
//! `/var/lib/memveil/receipts` for an installed package). Later `record`
//! runs re-verify the receipt at collection start and admit grade
//! local-auto. Qualify never mints grade validated and never rewrites the
//! shipped profiles: selection, binding, signature, smoke, mint, publish —
//! any refusal names its exact cause.

use crate::ENGINE_VERSION;
use crate::capture::live::LiveWriter;
use crate::capture::run::{
    MAX_PROFILE_DOC_BYTES, RecordOptions, parse_requested_caps, repair_warning_for, resolve_bridge,
    resolve_object, run_collector_with,
};
use crate::cli::doctor::resolve_profiles_dir;
use crate::cli::report::{
    CliError, EXIT_INTERNAL, EXIT_INVALID, EXIT_OK, EXIT_REFUSAL, sanitize_diagnostic,
    write_capture_location, write_stderr,
};
use crate::model::session::parse_session;
use crate::platform::artifact_files::{
    BridgeSnapshot, join_root, open_bridge_snapshot, open_object_snapshot,
};
use crate::platform::capabilities::{cap_floor_ok, cap_floor_refusal};
use crate::platform::clock::wall_ns;
use crate::platform::evidence::{KernelInfo, detect_environment};
use crate::platform::narrow::{
    MAX_NARROW_BTF_BYTES, NarrowBindings, check_identity_bindings, measure_live_bindings,
    parse_narrow_note,
};
use crate::platform::profiles::{
    CapQualification, NamedProfiles, Profile, SigVerdict, default_receipts_dir,
    load_profiles_named, mint_qualification_receipt, parse_profile_bytes, select_attempt_hook,
    select_profile, verify_hook_signatures, verify_live_interfaces,
};
use crate::platform::reader::{open_evidence_reader, read_host_file};
use crate::platform::stdout::write_stdout;

const BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
const SMOKE_DURATION_S: u64 = 3;
const SMOKE_NOTE: &str = "smoke: attach/poll/detach, no traffic required";
const ZLIB: &str = "libz.so.1";
const ATTEMPT: &str = "attempt-trace";
const CONVERT: &str = "conversion-observe";
const LIFECYCLE: &str = "mapping-lifecycle";
const COPY: &str = "copy-actual";

/// Parsed qualify arguments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QualifyOptions {
    /// Smoke capture directory.
    pub output: String,
    /// Attempt channel object override.
    pub object: String,
    /// Bridge library override.
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
    /// Lifecycle channel object override.
    pub lc_object: String,
    /// Copy channel object override.
    pub cp_object: String,
    /// Requested capability list.
    pub capabilities: String,
}

fn is_option(text: &str) -> bool {
    text.as_bytes().first() == Some(&0x2d)
}

/// Parse qualify arguments without the leading verb.
pub fn parse_qualify_args(args: &[String]) -> Result<QualifyOptions, CliError> {
    let mut opts = QualifyOptions::default();
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
        } else if tok == "--bridge" {
            if i + 1 >= args.len() || args[i + 1].is_empty() {
                return Err(CliError {
                    message: "--bridge needs a value".to_string(),
                });
            }
            opts.bridge = args[i + 1].clone();
            opts.has_bridge = true;
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

/// Usage text for the qualify verb.
pub fn qualify_usage() -> String {
    concat!(
        "usage: memveil qualify --output DIR [--object PATH]\n",
        "       [--bridge PATH] [--profile ID|PATH]\n",
        "       [--profiles-dir DIR] [--capability IDS]\n",
        "       [--lc-object PATH] [--cp-object PATH]\n",
        "\n",
        "Run a short smoke capture into DIR and, when it\n",
        "proves the requested channels, publish a\n",
        "machine-local local-auto receipt under\n",
        "<profiles-dir>/receipts (/var/lib/memveil/receipts\n",
        "for an installed package). Without --bridge, the native\n",
        "bridge is discovered: LMB_NATIVE_LIB when unprivileged,\n",
        "then beside the executable, then the system path.\n",
        "Without --object, --lc-object, or --cp-object, each\n",
        "BPF object is discovered beside the executable or\n",
        "under the system directory, else the run refuses.\n",
        "The smoke attaches, polls, and detaches once; an\n",
        "idle ring is honest success and still qualifies.\n",
        "Receipts never claim\n",
        "validated. Diagnostics go to stderr.\n",
        "\n",
        "--capability selects channels as a comma-separated\n",
        "list without spaces (default: attempt-trace, which\n",
        "is always required). mapping-lifecycle uses\n",
        "--lc-object and copy-actual uses --cp-object when\n",
        "given, else the discovered object for that channel.\n",
    )
    .to_string()
}

/// One qualification plan: doc, kernel, bindings, caps.
///
/// `ok` false carries an exit-3 `refusal`; otherwise the doc covers
/// this kernel, its identity bindings hold, every tracing-hook
/// signature matches live BTF, and `caps` names the requested
/// capabilities in order. `signatures` holds the per-hook verdicts
/// (all ok) for receipt detail and auditors. `doc_source` is the
/// exact file the smoke must resolve: the explicit path verbatim,
/// else the planned manifest entry under the profiles dir. The smoke
/// never re-resolves a bare id, so a same-named working-directory
/// file cannot substitute the doc.
#[derive(Debug, Clone)]
pub struct QualPlan {
    /// True when the smoke may run.
    pub ok: bool,
    /// Refusal reason; empty when ok.
    pub refusal: String,
    /// The planned profile document.
    pub doc: Profile,
    /// Exact doc file the smoke must resolve.
    pub doc_source: String,
    /// Live kernel identity.
    pub kernel: KernelInfo,
    /// Proven identity bindings.
    pub bindings: NarrowBindings,
    /// Requested capabilities in order.
    pub caps: Vec<String>,
    /// Per-hook signature verdicts (all ok).
    pub signatures: Vec<SigVerdict>,
}

impl Default for QualPlan {
    fn default() -> Self {
        Self {
            ok: false,
            refusal: String::new(),
            doc: Profile::default(),
            doc_source: String::new(),
            kernel: KernelInfo {
                release: String::new(),
                arch: String::new(),
                eligible_floor: false,
                floor_reason: String::new(),
            },
            bindings: NarrowBindings::new(),
            caps: Vec::new(),
            signatures: Vec::new(),
        }
    }
}

fn refuse_plan(reason: String) -> QualPlan {
    QualPlan {
        refusal: reason,
        ..QualPlan::default()
    }
}

fn covers(kernel: &KernelInfo, doc: &Profile) -> bool {
    select_profile(kernel, std::slice::from_ref(doc)).has_profile
}

/// Resolve --profile by file then id; `doc_source` reports the exact
/// file the smoke must resolve. Returns the refusal, or "" resolved.
fn explicit_doc(
    explicit: &str,
    named: &NamedProfiles,
    profiles_dir: &str,
) -> Result<(Profile, String), String> {
    if let Ok(doc_bytes) = read_host_file(explicit, "profile", MAX_PROFILE_DOC_BYTES) {
        match parse_profile_bytes(&doc_bytes) {
            Ok(doc) => return Ok((doc, explicit.to_string())),
            Err(e) => return Err(format!("cannot parse --profile: {e}")),
        }
    }
    for (i, profile) in named.profiles.iter().enumerate() {
        if profile.profile_id == explicit {
            return Ok((
                profile.clone(),
                format!("{profiles_dir}/{}", named.names[i]),
            ));
        }
    }
    Err(format!("unknown --profile: {explicit}"))
}

/// Plan from live interfaces for a noteless doc; never fails.
///
/// The live check proves the requested capabilities' trace formats,
/// hook signatures, and attachability; then the attempt hook is
/// selected, the live identity values are measured, BTF is re-read,
/// and every tracing-hook signature must match. Any failure refuses
/// with its exact cause.
fn plan_live(
    root: &str,
    doc: &Profile,
    source: &str,
    kernel: &KernelInfo,
    caps: &[String],
) -> QualPlan {
    let live = verify_live_interfaces(root, doc, caps);
    if !live.ok {
        return refuse_plan(format!("live check failed: {}", live.reason));
    }
    let sel = select_attempt_hook(doc);
    if !sel.ok {
        return refuse_plan(sel.refusal.clone());
    }
    let mut bindings = NarrowBindings::new();
    let unmeasured = measure_live_bindings(
        root,
        &kernel.release,
        ZLIB,
        &sel.hook.format_path,
        &mut bindings,
    );
    if !unmeasured.is_empty() {
        return refuse_plan(unmeasured);
    }
    let btf = match read_host_file(&join_root(root, BTF_PATH), "btf", MAX_NARROW_BTF_BYTES) {
        Ok(btf) => btf,
        Err(e) => return refuse_plan(format!("BTF unreadable: {e}")),
    };
    // Only hooks serving requested capabilities prove signatures: an
    // attempt-only plan must not trip on an unrequested lifecycle
    // hook this kernel does not have.
    let mut wanted: Vec<String> = Vec::new();
    for cap in caps {
        for decl in &doc.caps {
            if &decl.id == cap {
                wanted.extend(decl.hooks.iter().cloned());
            }
        }
    }
    let mut sub = doc.clone();
    sub.hooks = Vec::new();
    for hook in &doc.hooks {
        if wanted.iter().any(|w| w == &hook.name) {
            sub.hooks.push(hook.clone());
        }
    }
    let sigs = verify_hook_signatures(&sub, &btf);
    for sig in &sigs {
        if !sig.ok {
            return refuse_plan(sig.reason.clone());
        }
    }
    QualPlan {
        ok: true,
        doc: doc.clone(),
        doc_source: source.to_string(),
        kernel: kernel.clone(),
        bindings,
        caps: caps.to_vec(),
        signatures: sigs,
        ..QualPlan::default()
    }
}

/// Select one doc and prove it; never fails.
///
/// The capability request must parse and name a record channel, the
/// evidence root must open above the 6.0 floor with every requested
/// capability above its own floor, and one covering doc must exist
/// (explicit or first in manifest order). A doc with a parseable
/// narrow note must hold its identity bindings against the live tree;
/// a non-validated doc with no usable note (absent, or outside the
/// narrow grammar) instead proves the requested capabilities' live
/// interfaces and measures the live identity values. Every requested
/// tracing-hook signature must match live BTF either way. Any failure
/// refuses with its exact cause; the smoke runs only on an ok plan.
pub fn plan_qualification(root: &str, profiles_dir: &str, opts: &QualifyOptions) -> QualPlan {
    let ask = parse_requested_caps(&opts.capabilities);
    if !ask.ok {
        return refuse_plan(ask.err.clone());
    }
    for cap in &ask.caps {
        if cap == CONVERT {
            return refuse_plan("capability conversion-observe has no record channel".to_string());
        }
    }
    let reader = match open_evidence_reader(root) {
        Ok(reader) => reader,
        Err(e) => return refuse_plan(format!("cannot open evidence: {e}")),
    };
    let env = detect_environment(&reader);
    if !env.kernel.eligible_floor {
        return refuse_plan(format!("kernel {} below floor 6.0", env.kernel.release));
    }
    for cap in &ask.caps {
        if !cap_floor_ok(cap, &env.kernel.release) {
            return refuse_plan(cap_floor_refusal(cap, &env.kernel.release));
        }
    }
    let named = match load_profiles_named(profiles_dir) {
        Ok(named) => named,
        Err(e) => return refuse_plan(format!("cannot load profiles: {e}")),
    };
    let (doc, source) = if opts.has_profile {
        match explicit_doc(&opts.profile, &named, profiles_dir) {
            Ok(resolved) => resolved,
            Err(err) => return refuse_plan(err),
        }
    } else {
        let mut found: Option<(Profile, String)> = None;
        for (i, profile) in named.profiles.iter().enumerate() {
            if covers(&env.kernel, profile) {
                found = Some((
                    profile.clone(),
                    format!("{profiles_dir}/{}", named.names[i]),
                ));
                break;
            }
        }
        match found {
            Some(resolved) => resolved,
            None => return refuse_plan("no profile covers this kernel".to_string()),
        }
    };
    if opts.has_profile && !covers(&env.kernel, &doc) {
        // Explicit docs re-check coverage: file-first resolution may
        // have loaded a doc that covers nothing here.
        return refuse_plan("profile does not cover this kernel".to_string());
    }
    let parsed = parse_narrow_note(&doc.identity.source.note);
    if !parsed.ok {
        // An unbound reference (no note, or a note outside the narrow
        // grammar, prose included) never binds exactly; it plans from
        // live interfaces, mirroring record's admission trigger.
        if doc.status != "validated" {
            return plan_live(root, &doc, &source, &env.kernel, &ask.caps);
        }
        return refuse_plan(format!(
            "profile {} bindings unparseable: {}",
            doc.profile_id, parsed.message
        ));
    }
    let sel = select_attempt_hook(&doc);
    if !sel.ok {
        return refuse_plan(sel.refusal.clone());
    }
    let bound = check_identity_bindings(
        root,
        &env.kernel.release,
        &doc.identity.source.note,
        ZLIB,
        &sel.hook.format_path,
    );
    if bound.state != "bound" {
        return refuse_plan(format!("binding failed: {} {}", bound.key, bound.state));
    }
    let btf = match read_host_file(&join_root(root, BTF_PATH), "btf", MAX_NARROW_BTF_BYTES) {
        Ok(btf) => btf,
        // Binding just hashed this file, so only a concurrent
        // disappearance lands here.
        Err(e) => return refuse_plan(format!("BTF unreadable: {e}")),
    };
    let sigs = verify_hook_signatures(&doc, &btf);
    for sig in &sigs {
        if !sig.ok {
            return refuse_plan(sig.reason.clone());
        }
    }
    QualPlan {
        ok: true,
        doc,
        doc_source: source,
        kernel: env.kernel.clone(),
        bindings: parsed.bindings.clone(),
        caps: ask.caps.clone(),
        signatures: sigs,
        ..QualPlan::default()
    }
}

/// One receipt-publication failure: cause attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishError {
    /// Failure detail, including the errno number.
    pub message: String,
}

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublishError(message={})", self.message)
    }
}

impl std::error::Error for PublishError {}

fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn to_cstr(text: &str) -> Result<Vec<u8>, PublishError> {
    if text.as_bytes().contains(&0) {
        return Err(PublishError {
            message: "NUL byte in path".to_string(),
        });
    }
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    Ok(out)
}

fn close_quiet(fd: i32) {
    // SAFETY: owned test/publisher fd, closed once here.
    unsafe {
        libc::close(fd);
    }
}

fn write_all(fd: i32, raw: &[u8]) -> Result<(), PublishError> {
    let total = raw.len();
    let mut off = 0;
    while off < total {
        // SAFETY: fd with a live caller buffer; the range stays
        // inside `raw` as off counts up to total.
        let n = unsafe {
            libc::write(
                fd,
                raw.as_ptr().cast::<libc::c_void>().add(off),
                total - off,
            )
        };
        if n < 0 {
            let no = errno_now();
            if no == libc::EINTR {
                continue;
            }
            return Err(PublishError {
                message: format!("receipt write failed: errno {no}"),
            });
        }
        if n == 0 {
            return Err(PublishError {
                message: "receipt write returned 0".to_string(),
            });
        }
        off += n as usize;
    }
    Ok(())
}

fn unlink_at_quiet(dir_fd: i32, name: &[u8]) {
    // SAFETY: NUL-terminated tmp name under the pinned dir fd.
    unsafe {
        libc::unlinkat(dir_fd, name.as_ptr().cast::<libc::c_char>(), 0);
    }
}

fn open_tmp(dir_fd: i32, name: &[u8]) -> i32 {
    // SAFETY: NUL-terminated tmp name under the pinned dir fd.
    unsafe {
        libc::openat(
            dir_fd,
            name.as_ptr().cast::<libc::c_char>(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o644,
        )
    }
}

/// Atomically publish receipt text at path.
///
/// The parent directory is created when missing, then pinned with
/// O_DIRECTORY|O_NOFOLLOW before any byte is written; every later step
/// runs descriptor-relative, so a swapped parent or link cannot
/// redirect the write. The tmp file is created O_EXCL (a stale or
/// planted name is unlinked once and retried once, then refuses),
/// written, synced, and renamed over the final name, and the pinned
/// directory is synced last. A crash leaves the old receipt or nothing,
/// never a half-written file. Concurrent same-operator publishes from
/// separate processes resolve atomic last-writer-wins with whole files:
/// each publisher owns a distinct pid-suffixed tmp name, and readers
/// of the final path observe the old or the new whole receipt, never a
/// mix. Returns the errno-carrying failure on any error.
pub fn publish_receipt(path: &str, text: &str) -> Result<(), PublishError> {
    let raw = path.as_bytes();
    let mut slash: i64 = -1;
    for (i, b) in raw.iter().enumerate() {
        if *b == 0x2f {
            slash = i as i64;
        }
    }
    if slash <= 0 || slash + 1 >= raw.len() as i64 {
        return Err(PublishError {
            message: "receipt path has no directory".to_string(),
        });
    }
    let slash = slash as usize;
    let (parent, final_name) = match (
        std::str::from_utf8(&raw[..slash]),
        std::str::from_utf8(&raw[slash + 1..]),
    ) {
        (Ok(parent), Ok(final_name)) => (parent, final_name),
        _ => {
            return Err(PublishError {
                message: "receipt path undecodable".to_string(),
            });
        }
    };
    let parent_cstr = to_cstr(parent)?;
    // SAFETY: NUL-terminated parent path on AT_FDCWD.
    unsafe {
        libc::mkdirat(
            libc::AT_FDCWD,
            parent_cstr.as_ptr().cast::<libc::c_char>(),
            0o755,
        );
    }
    // SAFETY: as above; O_DIRECTORY|O_NOFOLLOW pins a real dir.
    let dir_fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            parent_cstr.as_ptr().cast::<libc::c_char>(),
            libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
    };
    if dir_fd < 0 {
        return Err(PublishError {
            message: format!("receipt dir unavailable: errno {}", errno_now()),
        });
    }
    // SAFETY: getpid has no failure mode.
    let pid = unsafe { libc::getpid() };
    let tmp_cstr = to_cstr(&format!("{final_name}.tmp.{pid}"))?;
    let mut fd = open_tmp(dir_fd, &tmp_cstr);
    if fd < 0 && errno_now() == libc::EEXIST {
        unlink_at_quiet(dir_fd, &tmp_cstr);
        fd = open_tmp(dir_fd, &tmp_cstr);
    }
    if fd < 0 {
        let no = errno_now();
        close_quiet(dir_fd);
        return Err(PublishError {
            message: format!("receipt create failed: errno {no}"),
        });
    }
    if let Err(e) = (|| -> Result<(), PublishError> {
        write_all(fd, text.as_bytes())?;
        // SAFETY: owned tmp fd.
        if unsafe { libc::fsync(fd) } != 0 {
            return Err(PublishError {
                message: format!("receipt fsync failed: errno {}", errno_now()),
            });
        }
        Ok(())
    })() {
        close_quiet(fd);
        unlink_at_quiet(dir_fd, &tmp_cstr);
        close_quiet(dir_fd);
        return Err(PublishError { message: e.message });
    }
    close_quiet(fd);
    let final_cstr = to_cstr(final_name)?;
    // Plain renameat intentionally replaces: re-qualify must
    // overwrite an expired receipt, and concurrent same-operator
    // qualifies resolve atomic last-writer-wins with whole files.
    // NOREPLACE would break renewal for no safety gain.
    // SAFETY: NUL-terminated names under the pinned dir fd.
    let rn = unsafe {
        libc::renameat(
            dir_fd,
            tmp_cstr.as_ptr().cast::<libc::c_char>(),
            dir_fd,
            final_cstr.as_ptr().cast::<libc::c_char>(),
        )
    };
    if rn != 0 {
        let no = errno_now();
        unlink_at_quiet(dir_fd, &tmp_cstr);
        close_quiet(dir_fd);
        return Err(PublishError {
            message: format!("receipt rename failed: errno {no}"),
        });
    }
    // SAFETY: pinned dir fd.
    if unsafe { libc::fsync(dir_fd) } != 0 {
        let no = errno_now();
        close_quiet(dir_fd);
        return Err(PublishError {
            message: format!("receipt dir fsync failed: errno {no}"),
        });
    }
    close_quiet(dir_fd);
    Ok(())
}

/// Report one cannot-qualify outcome; return EXIT_REFUSAL.
fn qualify_failed(detail: &str) -> i64 {
    let line = format!("memveil qualify: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_REFUSAL,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Report one usage failure; return EXIT_INVALID.
fn qualify_misused(detail: &str) -> i64 {
    let line = format!("memveil qualify: {}\n", sanitize_diagnostic(detail));
    match write_stderr(&line) {
        Ok(()) => EXIT_INVALID,
        Err(_) => EXIT_INTERNAL,
    }
}

/// Report one internal failure; return EXIT_INTERNAL.
fn qualify_broken(detail: &str) -> i64 {
    let line = format!("memveil qualify: {}\n", sanitize_diagnostic(detail));
    let _ = write_stderr(&line);
    EXIT_INTERNAL
}

/// Session-file proof the smoke shut down cleanly.
///
/// RunResult alone cannot tell failed-detach (dirty teardown, hooks
/// possibly still armed) from an idle ring (honest quiet): both end
/// duration/finalized with a nonzero exit. Only the written
/// session.json records stop.admission_closed, so qualify mints only
/// when the smoke's own session file says the collector closed
/// admission. Any read or parse failure refuses. The file is the
/// collector's own just-written output in this run's directory, not
/// cross-principal input: the operator qualifies their own machine.
pub fn smoke_shutdown_ok(output: &str) -> bool {
    let raw = match read_host_file(&format!("{output}/session.json"), "session", 8388608) {
        Ok(raw) => raw,
        Err(_) => return false,
    };
    match parse_session(&raw) {
        Ok(session) => session.stop.admission_closed,
        Err(_) => false,
    }
}

/// sha256: hash of the smoke's exercised bridge bytes.
///
/// The receipt binds the snapshot taken before the smoke, never a
/// post-smoke pathname re-read: a swap after the smoke cannot mint a
/// receipt for bytes the smoke never exercised. An unbound snapshot
/// (empty hash) refuses instead of hashing a pathname.
fn smoke_bridge_hash(snap: &BridgeSnapshot) -> Result<String, String> {
    if snap.sha.is_empty() {
        return Err("bridge identity unbound for this smoke".to_string());
    }
    Ok(format!("sha256:{}", snap.sha))
}

/// sha256: hash of the smoke's exercised object bytes.
///
/// The receipt binds the snapshot taken before the smoke, never a
/// post-smoke pathname re-read: a swap after the smoke cannot mint a
/// receipt for bytes the smoke never exercised. An unbound snapshot
/// (empty hash) refuses instead of hashing a pathname.
fn smoke_object_hash(snap: &BridgeSnapshot) -> Result<String, String> {
    if snap.sha.is_empty() {
        return Err("object identity unbound for this smoke".to_string());
    }
    Ok(format!("sha256:{}", snap.sha))
}

/// Refusal when a wanted channel object has no path; "" proceeds.
///
/// Qualify mints only explicit artifacts: a wanted lifecycle/copy
/// channel with neither an explicit flag nor a discovered file
/// refuses before the smoke, so the smoke never attaches on
/// embedded bytes the receipt cannot bind and no capture
/// directory is left behind. Lifecycle reports first, matching
/// admission order.
fn missing_channel_object(
    want_lc: bool,
    want_cp: bool,
    lc_object: &str,
    cp_object: &str,
) -> String {
    if want_lc && lc_object.is_empty() {
        return "no object: pass --lc-object PATH".to_string();
    }
    if want_cp && cp_object.is_empty() {
        return "no object: pass --cp-object PATH".to_string();
    }
    String::new()
}

/// Run the qualify flow against explicit roots; return exit code.
///
/// `root` is the evidence root ("" for the live host) and
/// `profiles_dir` holds `manifest.txt`; receipts publish under its
/// receipts dir. The smoke runs the collector in explicit mode
/// against the planned doc; a wanted lifecycle/copy channel with
/// no resolved object refuses before the smoke. Only a finalized
/// duration-ended smoke whose session file proves
/// stop.admission_closed mints, and minting publishes exactly one
/// local-auto receipt. Refusals print one diagnostic and exit 3
/// before any receipt exists.
pub fn run_qualify_with(root: &str, profiles_dir: &str, opts: &QualifyOptions) -> i64 {
    let output = opts.output.clone();
    let mut bridge = resolve_bridge(&opts.bridge, opts.has_bridge);
    // Pin the bridge before the smoke: the smoke loads through the
    // snapshot's fd alias and the receipt binds the snapshot hash, so
    // a pathname swap on either side of the smoke binds nothing new.
    // Rust drops locals at scope end (never early), so the pins below
    // outlive every open inside the smoke on every return path with
    // no explicit keep-alive.
    let snap = open_bridge_snapshot(&bridge);
    let object_path = resolve_object(&opts.object);
    if object_path.is_empty() {
        return qualify_failed("no object: pass --object PATH");
    }
    // Pin the objects before the smoke, like the bridge: the smoke
    // reads through the snapshot aliases and the receipt binds the
    // snapshot hashes, so a pathname swap on either side of the
    // smoke binds nothing new.
    let obj_snap = open_object_snapshot(&object_path);
    let mut lc_object = opts.lc_object.clone();
    let mut cp_object = opts.cp_object.clone();
    let want_caps = opts.capabilities.clone();
    let plan = plan_qualification(root, profiles_dir, opts);
    if !plan.ok {
        return qualify_failed(&plan.refusal);
    }
    let mut want_lc = false;
    let mut want_cp = false;
    for cap in &plan.caps {
        if cap == LIFECYCLE {
            want_lc = true;
        }
        if cap == COPY {
            want_cp = true;
        }
    }
    if lc_object.is_empty() && want_lc {
        lc_object = resolve_object("");
    }
    if cp_object.is_empty() && want_cp {
        cp_object = resolve_object("");
    }
    let missing = missing_channel_object(want_lc, want_cp, &lc_object, &cp_object);
    if !missing.is_empty() {
        return qualify_failed(&missing);
    }
    let lc_snap = open_object_snapshot(&lc_object);
    let cp_snap = open_object_snapshot(&cp_object);
    // The smoke resolves the planned source path, never a bare id:
    // plan.doc_source is the explicit file verbatim or the planned
    // manifest entry, so a same-named file in the working directory
    // cannot substitute the document through record's file-first
    // resolver.
    let ropts = RecordOptions {
        output: output.clone(),
        object: obj_snap.load_path.clone(),
        bridge: snap.load_path.clone(),
        has_bridge: !snap.load_path.is_empty(),
        profile: plan.doc_source.clone(),
        has_profile: true,
        lc_object: lc_snap.load_path.clone(),
        cp_object: cp_snap.load_path.clone(),
        capabilities: want_caps,
        duration_s: SMOKE_DURATION_S,
        ..RecordOptions::default()
    };
    let mut writer = LiveWriter::new();
    let result = run_collector_with(root, profiles_dir, ropts, &mut writer);
    if result.outcome == "finalized" {
        // A published capture lands root-owned under sudo; hand it to
        // the invoking user. Warn-only: the capture stands whatever
        // ownership repair does.
        let repair_line = repair_warning_for(&output, &writer);
        if !repair_line.is_empty() {
            let _ = write_stderr(&repair_line);
        }
    }
    if result.outcome != "finalized" || result.end_reason != "duration" {
        let mut detail = format!("smoke {}/{}", result.end_reason, result.outcome);
        if !result.diagnostic.is_empty() {
            detail += &format!(": {}", result.diagnostic);
        }
        return qualify_failed(&detail);
    }
    if !smoke_shutdown_ok(&output) {
        return qualify_failed(
            "smoke shutdown unproven: session stop.admission_closed is false or unreadable",
        );
    }
    let created = wall_ns();
    if created == 0 {
        return qualify_broken("wall clock unreadable");
    }
    let smoke = format!(
        "smoke end=duration outcome=finalized exit={}",
        result.exit_code
    );
    let mut caps: Vec<CapQualification> = Vec::new();
    for cap in &plan.caps {
        if cap == ATTEMPT {
            caps.push(CapQualification::new(
                cap.clone(),
                format!("layout holds; {smoke}"),
            ));
        } else {
            caps.push(CapQualification::new(
                cap.clone(),
                format!("signatures hold; {smoke}"),
            ));
        }
    }
    let obj_attempt = match smoke_object_hash(&obj_snap) {
        Ok(hash) => hash,
        Err(e) => return qualify_broken(&format!("smoke objects unbound: {e}")),
    };
    let obj_lc = if lc_object.is_empty() {
        String::new()
    } else {
        match smoke_object_hash(&lc_snap) {
            Ok(hash) => hash,
            Err(e) => return qualify_broken(&format!("smoke objects unbound: {e}")),
        }
    };
    let obj_cp = if cp_object.is_empty() {
        String::new()
    } else {
        match smoke_object_hash(&cp_snap) {
            Ok(hash) => hash,
            Err(e) => return qualify_broken(&format!("smoke objects unbound: {e}")),
        }
    };
    match smoke_bridge_hash(&snap) {
        Ok(hash) => bridge = hash,
        Err(e) => return qualify_broken(&format!("smoke bridge unbound: {e}")),
    }
    let receipt = mint_qualification_receipt(
        &plan.doc.profile_id,
        &plan.kernel,
        &plan.bindings,
        created,
        &caps,
        ENGINE_VERSION,
        &bridge,
        &obj_attempt,
        &obj_lc,
        &obj_cp,
        SMOKE_DURATION_S,
        SMOKE_NOTE,
    );
    let pid = plan.doc.profile_id.clone();
    let path = format!("{}/{pid}.json", default_receipts_dir(profiles_dir));
    if let Err(e) = publish_receipt(&path, &receipt) {
        return qualify_broken(&format!("cannot publish receipt: {e}"));
    }
    let listed = plan.caps.join(",");
    if write_stdout(&format!(
        "qualify: local-auto {pid} caps={listed} receipt={path}\n"
    ))
    .is_err()
    {
        let _ = write_capture_location(&output, &path);
        return EXIT_OK;
    }
    EXIT_OK
}

/// Run the qualify verb; return the process exit code.
///
/// `args` excludes the program name and the qualify word. Profiles
/// resolve from --profiles-dir or the kernel-resolved binary path,
/// never from argv[0] or the working directory.
pub fn run_qualify(args: &[String]) -> i64 {
    if args.iter().any(|a| a == "--help" || a == "-h") {
        match write_stdout(&qualify_usage()) {
            Ok(()) => return EXIT_OK,
            Err(_) => return qualify_broken("cannot write stdout"),
        }
    }
    let opts = match parse_qualify_args(args) {
        Ok(opts) => opts,
        Err(e) => return qualify_misused(&e.message),
    };
    let profiles_dir = if opts.has_profiles_dir {
        opts.profiles_dir.clone()
    } else {
        match resolve_profiles_dir() {
            Ok(dir) => dir,
            Err(e) => {
                return qualify_failed(&format!("cannot resolve profiles location: {}", e.message));
            }
        }
    };
    run_qualify_with("", &profiles_dir, &opts)
}

#[cfg(test)]
mod tests {
    use super::{
        EXIT_REFUSAL, QualifyOptions, missing_channel_object, parse_qualify_args,
        plan_qualification, publish_receipt, qualify_usage, run_qualify_with, smoke_bridge_hash,
        smoke_object_hash, smoke_shutdown_ok,
    };
    use crate::capture::run::decide_record;
    use crate::platform::artifact_files::{open_bridge_snapshot, open_object_snapshot};
    use crate::platform::evidence::KernelInfo;
    use crate::platform::hash::sha256_hex;
    use crate::platform::profiles::load_profiles;
    use crate::platform::reader::read_host_file;
    use crate::platform::test_support::{TestDir, repo_root};

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn repo(path: &str) -> String {
        repo_root().join(path).to_str().expect("utf-8").to_string()
    }

    fn host() -> String {
        repo("tests/fixtures/qualify/host")
    }

    fn pdir() -> String {
        repo("tests/fixtures/qualify/profiles")
    }

    fn base_args() -> Vec<String> {
        args(&["--output", "out", "--object", "obj.o"])
    }

    fn base_opts() -> QualifyOptions {
        QualifyOptions {
            output: "out".to_string(),
            object: "obj.o".to_string(),
            ..QualifyOptions::default()
        }
    }

    #[test]
    fn qualify_args_defaults() {
        let opts = parse_qualify_args(&base_args()).expect("base parses");
        assert_eq!(opts.output, "out");
        assert_eq!(opts.object, "obj.o");
        assert_eq!(opts.bridge, "");
        assert!(!opts.has_bridge);
        assert_eq!(opts.profile, "");
        assert!(!opts.has_profile);
        assert_eq!(opts.profiles_dir, "");
        assert!(!opts.has_profiles_dir);
        assert_eq!(opts.lc_object, "");
        assert_eq!(opts.cp_object, "");
        assert_eq!(opts.capabilities, "");
    }

    #[test]
    fn qualify_args_full() {
        let opts = parse_qualify_args(&args(&[
            "--output",
            "out",
            "--object",
            "obj.o",
            "--bridge",
            "br.so",
            "--profile",
            "p1",
            "--profiles-dir",
            "qd",
            "--lc-object",
            "lc.o",
            "--cp-object",
            "cp.o",
            "--capability",
            "attempt-trace,mapping-lifecycle",
        ]))
        .expect("full parses");
        assert_eq!(opts.bridge, "br.so");
        assert!(opts.has_bridge);
        assert_eq!(opts.profile, "p1");
        assert!(opts.has_profile);
        assert_eq!(opts.profiles_dir, "qd");
        assert!(opts.has_profiles_dir);
        assert_eq!(opts.lc_object, "lc.o");
        assert_eq!(opts.cp_object, "cp.o");
        assert_eq!(opts.capabilities, "attempt-trace,mapping-lifecycle");
    }

    #[test]
    fn qualify_args_values_needed() {
        for flag in [
            "--output",
            "--object",
            "--bridge",
            "--profile",
            "--profiles-dir",
            "--lc-object",
            "--cp-object",
            "--capability",
        ] {
            let err = parse_qualify_args(&args(&[flag])).expect_err("missing value rejects");
            assert_eq!(err.message, format!("{flag} needs a value"));
            let err = parse_qualify_args(&args(&[flag, ""])).expect_err("empty value rejects");
            assert_eq!(err.message, format!("{flag} needs a value"));
        }
    }

    #[test]
    fn qualify_args_unknown_option() {
        let mut words = base_args();
        words.push("--bogus".to_string());
        let err = parse_qualify_args(&words).expect_err("bogus rejects");
        assert!(
            err.message.contains("unknown option: --bogus"),
            "{}",
            err.message
        );
    }

    #[test]
    fn qualify_args_missing_output() {
        let err =
            parse_qualify_args(&args(&["--object", "obj.o"])).expect_err("missing output rejects");
        assert_eq!(err.message, "missing --output");
    }

    #[test]
    fn qualify_args_object_optional() {
        let opts = parse_qualify_args(&args(&["--output", "out"])).expect("object optional");
        assert_eq!(opts.output, "out");
        assert_eq!(opts.object, "");
    }

    #[test]
    fn qualify_usage_shape() {
        let text = qualify_usage();
        assert!(text.contains("qualify --output"));
        assert!(text.contains("[--object PATH]"));
        assert!(text.contains("discover"));
        assert!(text.contains("/var/lib/memveil/receipts"));
    }

    #[test]
    fn plan_ok() {
        let plan = plan_qualification(&host(), &pdir(), &base_opts());
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.refusal, "");
        assert_eq!(plan.doc.profile_id, "qual-ref");
        assert_eq!(plan.kernel.release, "7.0.0-test");
        assert_eq!(plan.caps, vec!["attempt-trace".to_string()]);
        assert_ne!(plan.bindings.config, "");
        assert_eq!(plan.signatures.len(), 1);
        assert!(plan.signatures[0].ok);
        assert_eq!(
            plan.signatures[0].live,
            "int (struct device *dev, size_t size)"
        );
    }

    #[test]
    fn plan_caps() {
        let mut opts = base_opts();
        opts.capabilities = "attempt-trace,mapping-lifecycle".to_string();
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.caps.len(), 2);
        assert_eq!(plan.caps[1], "mapping-lifecycle");
    }

    #[test]
    fn plan_live_reference() {
        let mut opts = base_opts();
        opts.capabilities = "attempt-trace,mapping-lifecycle".to_string();
        let plan = plan_qualification(
            &repo("tests/fixtures/qualify/host-live38"),
            &repo("tests/fixtures/qualify/profiles-live"),
            &opts,
        );
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.doc.profile_id, "scan-live-ref");
        assert_eq!(plan.caps.len(), 2);
        assert_eq!(plan.caps[1], "mapping-lifecycle");
    }

    #[test]
    fn plan_bad_caps() {
        let mut opts = base_opts();
        opts.capabilities = "bogus".to_string();
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "unknown capability: bogus");
    }

    #[test]
    fn plan_convert_refuses() {
        let mut opts = base_opts();
        opts.capabilities = "attempt-trace,conversion-observe".to_string();
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(
            plan.refusal,
            "capability conversion-observe has no record channel"
        );
    }

    #[test]
    fn plan_doc_source_automatic() {
        let plan = plan_qualification(&host(), &pdir(), &base_opts());
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.doc_source, format!("{}/qual-ref.json", pdir()));
    }

    #[test]
    fn plan_doc_source_explicit_id() {
        let mut opts = base_opts();
        opts.profile = "qual-ref".to_string();
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.doc_source, format!("{}/qual-ref.json", pdir()));
    }

    #[test]
    fn plan_doc_source_explicit_file() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-ref.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.doc_source, format!("{}/qual-ref.json", pdir()));
    }

    #[test]
    fn plan_no_hook() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-nohook.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "no tracepoint hook");
    }

    #[test]
    fn plan_unknown_profile() {
        let mut opts = base_opts();
        opts.profile = "nonexistent".to_string();
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "unknown --profile: nonexistent");
    }

    #[test]
    fn plan_unbound_note() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-unbound.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
        assert_eq!(plan.doc.profile_id, "qual-unbound");
        assert_eq!(plan.caps, vec!["attempt-trace".to_string()]);
    }

    #[test]
    fn plan_bad_signature() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-badsig.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "fentry:test_fn: signature mismatch");
    }

    #[test]
    fn plan_name_only_signature_accepted() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-namesig.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
    }

    #[test]
    fn plan_missing_function() {
        let mut opts = base_opts();
        opts.profile = format!("{}/qual-nofunc.json", pdir());
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(!plan.ok);
        assert!(
            plan.refusal.contains("function nope not found"),
            "{}",
            plan.refusal
        );
    }

    #[test]
    fn plan_binding_mismatch() {
        let plan = plan_qualification(&repo("tests/fixtures/scan/ok"), &pdir(), &base_opts());
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "binding failed: btf mismatch");
    }

    #[test]
    fn plan_no_cover() {
        let plan = plan_qualification(
            &repo("tests/fixtures/qualify/host-arm"),
            &pdir(),
            &base_opts(),
        );
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "no profile covers this kernel");
    }

    #[test]
    fn plan_below_floor_refuses() {
        let plan = plan_qualification(
            &repo("tests/fixtures/qualify/host-old"),
            &pdir(),
            &base_opts(),
        );
        assert!(!plan.ok);
        assert_eq!(plan.refusal, "kernel 5.15.0-test below floor 6.0");
    }

    #[test]
    fn plan_lc_below_611_refuses() {
        let mut opts = base_opts();
        opts.capabilities = "attempt-trace,mapping-lifecycle".to_string();
        let plan = plan_qualification(&repo("tests/fixtures/qualify/host-68"), &pdir(), &opts);
        assert!(!plan.ok);
        assert_eq!(
            plan.refusal,
            "capability mapping-lifecycle needs kernel 6.11+ (this kernel: 6.8.0-test)"
        );
    }

    #[test]
    fn plan_source_survives_cwd_shadow() {
        // chdir is process-global, so the shadow case runs in a child.
        if std::env::var("MEMVEIL_QUAL_SHADOW_CHILD").is_ok() {
            let tmp = TestDir::create("memveil-qual-shadow").expect("scratch");
            // SAFETY: single-purpose child; no other thread runs here.
            let cstr = std::ffi::CString::new(tmp.as_str()).expect("cstr");
            let rc = unsafe { libc::chdir(cstr.as_ptr()) };
            assert_eq!(rc, 0);
            shadow_body();
            std::process::exit(0);
        }
        let exe = std::env::current_exe().expect("test binary path resolves");
        let out = std::process::Command::new(exe)
            .arg("--exact")
            .arg("cli::qualify::tests::plan_source_survives_cwd_shadow")
            .arg("--nocapture")
            .env("MEMVEIL_QUAL_SHADOW_CHILD", "1")
            .output()
            .expect("child re-exec runs");
        assert_eq!(
            out.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    #[cfg(test)]
    fn shadow_body() {
        let mut opts = base_opts();
        opts.profile = "qual-ref".to_string();
        opts.has_profile = true;
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok);
        assert_eq!(plan.doc.profile_id, "qual-ref");
        // The shadow appears after planning, modeling a
        // working-directory file arriving between plan and smoke.
        publish_receipt("./qual-ref", "shadow-bytes\n").expect("shadow writes");
        let shadowed = decide_record(
            &host(),
            &plan.kernel,
            &[],
            "qual-ref",
            true,
            "nonexistent.o",
            "",
            "",
            "",
            "",
            "",
        );
        assert!(!shadowed.ok);
        assert!(
            shadowed.refusal.contains("cannot parse --profile"),
            "{}",
            shadowed.refusal
        );
        let sourced = decide_record(
            &host(),
            &plan.kernel,
            &[],
            &plan.doc_source,
            true,
            "nonexistent.o",
            "",
            "",
            "",
            "",
            "",
        );
        assert!(!sourced.ok);
        assert_eq!(sourced.refusal, "object unreadable");
    }

    #[test]
    fn plan_bad_root() {
        let plan = plan_qualification(
            &repo("tests/fixtures/qualify/nonexistent"),
            &pdir(),
            &base_opts(),
        );
        assert!(!plan.ok);
        assert!(
            plan.refusal.contains("cannot open evidence"),
            "{}",
            plan.refusal
        );
    }

    #[test]
    fn plan_bad_pdir() {
        let plan = plan_qualification(
            &host(),
            &repo("tests/fixtures/qualify/nonexistent"),
            &base_opts(),
        );
        assert!(!plan.ok);
        assert!(
            plan.refusal.contains("cannot load profiles"),
            "{}",
            plan.refusal
        );
    }

    #[test]
    fn publish_roundtrip() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let path = format!("{}/r.json", tmp.as_str());
        publish_receipt(&path, "{\"grade\":\"local-auto\"}\n").expect("publish");
        let back = read_host_file(&path, "receipt", 1048576).expect("read back");
        assert_eq!(
            String::from_utf8(back).expect("utf-8"),
            "{\"grade\":\"local-auto\"}\n"
        );
    }

    #[test]
    fn publish_overwrite() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let path = format!("{}/w.json", tmp.as_str());
        publish_receipt(&path, "first\n").expect("publish");
        publish_receipt(&path, "second\n").expect("publish");
        let back = read_host_file(&path, "receipt", 1048576).expect("read back");
        assert_eq!(String::from_utf8(back).expect("utf-8"), "second\n");
    }

    #[test]
    fn smoke_shutdown_missing() {
        assert!(!smoke_shutdown_ok(&repo(
            "tests/fixtures/qualify/nonexistent-xyz"
        )));
    }

    #[test]
    fn smoke_shutdown_unproven() {
        // A session that never closed admission proves nothing.
        assert!(!smoke_shutdown_ok(&repo("tests/fixtures/attempts")));
    }

    #[test]
    fn publish_bad_dir() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let path = format!("{}/noexist-xyz/receipts/r.json", tmp.as_str());
        assert!(publish_receipt(&path, "x\n").is_err());
    }

    fn symlink(target: &str, link: &str) {
        let t = std::ffi::CString::new(target).expect("cstr");
        let l = std::ffi::CString::new(link).expect("cstr");
        // SAFETY: live NUL-terminated test paths.
        let rc = unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn publish_parent_symlink_refuses() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        symlink(".", &format!("{}/qlink", tmp.as_str()));
        let err = publish_receipt(&format!("{}/qlink/refused.json", tmp.as_str()), "x\n")
            .expect_err("symlink parent refuses");
        assert!(err.to_string().contains("receipt"), "{}", err.to_string());
        assert!(read_host_file(&format!("{}/refused.json", tmp.as_str()), "probe", 16).is_err());
    }

    #[test]
    fn publish_tmp_symlink_never_truncates() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let dir = format!("{}/qx", tmp.as_str());
        std::fs::create_dir_all(&dir).expect("mkdir");
        publish_receipt(&format!("{dir}/victim"), "precious\n").expect("publish");
        // SAFETY: getpid has no failure mode.
        let pid = unsafe { libc::getpid() };
        let stale = format!("{dir}/r.json.tmp.{pid}");
        symlink("victim", &stale);
        publish_receipt(&format!("{dir}/r.json"), "new\n").expect("publish");
        let back = read_host_file(&format!("{dir}/victim"), "victim", 1048576).expect("victim");
        assert_eq!(String::from_utf8(back).expect("utf-8"), "precious\n");
        let fin = read_host_file(&format!("{dir}/r.json"), "receipt", 1048576).expect("final");
        assert_eq!(String::from_utf8(fin).expect("utf-8"), "new\n");
    }

    #[test]
    fn publish_final_symlink_replaced() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let dir = format!("{}/qf", tmp.as_str());
        std::fs::create_dir_all(&dir).expect("mkdir");
        publish_receipt(&format!("{dir}/victim"), "precious\n").expect("publish");
        symlink("victim", &format!("{dir}/r.json"));
        publish_receipt(&format!("{dir}/r.json"), "new\n").expect("publish");
        let back = read_host_file(&format!("{dir}/victim"), "victim", 1048576).expect("victim");
        assert_eq!(String::from_utf8(back).expect("utf-8"), "precious\n");
        let fin = read_host_file(&format!("{dir}/r.json"), "receipt", 1048576).expect("final");
        assert_eq!(String::from_utf8(fin).expect("utf-8"), "new\n");
    }

    #[test]
    fn publish_trailing_slash_refuses() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        assert!(publish_receipt(&format!("{}/", tmp.as_str()), "x\n").is_err());
    }

    fn publish_child(dir: &str, body: &str) -> std::process::Child {
        let exe = std::env::current_exe().expect("test binary path resolves");
        std::process::Command::new(exe)
            .arg("--exact")
            .arg("cli::qualify::tests::publish_child_entry")
            .arg("--nocapture")
            .env("MEMVEIL_QUAL_PUB_CHILD", format!("{dir}\u{1f}{body}"))
            .spawn()
            .expect("spawn publisher")
    }

    #[test]
    fn publish_child_entry() {
        let spec = match std::env::var("MEMVEIL_QUAL_PUB_CHILD") {
            Ok(spec) => spec,
            Err(_) => return,
        };
        let (dir, body) = spec.split_once('\u{1f}').expect("child spec");
        let count: usize = std::env::var("MEMVEIL_QUAL_PUB_COUNT")
            .ok()
            .and_then(|n| n.parse().ok())
            .unwrap_or(1);
        for i in 0..count {
            let text = if count == 1 {
                body.to_string()
            } else if i % 2 == 0 {
                format!("{body}-A")
            } else {
                format!("{body}-B")
            };
            publish_receipt(&format!("{dir}/live.json"), &text).expect("child publish");
        }
    }

    fn assert_no_tmp_left(dir: &str, name: &str, pids: &[u32]) {
        for pid in pids {
            let cand = format!("{dir}/{name}.tmp.{pid}");
            let cstr = std::ffi::CString::new(cand.clone()).expect("cstr");
            // SAFETY: exclusive-create probe; removed again on success.
            let fd = unsafe {
                libc::open(
                    cstr.as_ptr(),
                    libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                    0o644,
                )
            };
            assert!(fd >= 0, "stale tmp left: {cand}");
            // SAFETY: just-opened probe fd.
            unsafe {
                libc::close(fd);
            }
            std::fs::remove_file(&cand).expect("remove probe");
        }
    }

    #[test]
    fn publish_concurrent_last_writer_wins() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let dir = tmp.as_str().to_string();
        let mut children = Vec::new();
        for i in 0..8 {
            children.push(publish_child(&dir, &format!("publisher-{i}\n")));
        }
        let mut pids = Vec::new();
        for mut child in children {
            pids.push(child.id());
            assert!(child.wait().expect("reap").success());
        }
        // SAFETY: getpid has no failure mode.
        pids.push(unsafe { libc::getpid() } as u32);
        let back = read_host_file(&format!("{dir}/live.json"), "receipt", 1048576).expect("final");
        let text = String::from_utf8(back).expect("utf-8");
        assert!(
            (0..8).any(|i| text == format!("publisher-{i}\n")),
            "torn mix: {text:?}"
        );
        assert_no_tmp_left(&dir, "live.json", &pids);
    }

    #[test]
    fn publish_reader_sees_whole_files() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let dir = tmp.as_str().to_string();
        let body_a = "A".repeat(64_000);
        let body_b = "B".repeat(64_000);
        let exe = std::env::current_exe().expect("test binary path resolves");
        let mut child = std::process::Command::new(exe)
            .arg("--exact")
            .arg("cli::qualify::tests::publish_burst_entry")
            .arg("--nocapture")
            .env("MEMVEIL_QUAL_BURST_DIR", &dir)
            .spawn()
            .expect("spawn burst");
        // Gate the reads on the first publication.
        let mut ready = false;
        for _ in 0..100_000 {
            if read_host_file(&format!("{dir}/live.json"), "receipt", 1048576).is_ok() {
                ready = true;
                break;
            }
        }
        assert!(ready);
        let mut observed = 0;
        for _ in 0..1000 {
            if let Ok(back) = read_host_file(&format!("{dir}/live.json"), "receipt", 1048576)
                && let Ok(seen) = String::from_utf8(back)
            {
                assert!(seen == body_a || seen == body_b, "torn read");
                observed += 1;
            }
        }
        assert!(child.wait().expect("reap").success());
        assert!(observed > 0);
        assert_no_tmp_left(
            &dir,
            "live.json",
            // SAFETY: getpid has no failure mode.
            &[child.id(), unsafe { libc::getpid() } as u32],
        );
    }

    #[test]
    fn publish_burst_entry() {
        let dir = match std::env::var("MEMVEIL_QUAL_BURST_DIR") {
            Ok(dir) => dir,
            Err(_) => return,
        };
        let body_a = "A".repeat(64_000);
        let body_b = "B".repeat(64_000);
        for i in 0..1000 {
            let body = if i % 2 == 0 { &body_a } else { &body_b };
            publish_receipt(&format!("{dir}/live.json"), body).expect("burst publish");
        }
    }

    #[test]
    fn publish_stale_tmp_recycled() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        // SAFETY: getpid has no failure mode.
        let pid = unsafe { libc::getpid() };
        let path = format!("{}/r.json", tmp.as_str());
        std::fs::write(format!("{path}.tmp.{pid}"), "stale-junk\n").expect("stale");
        publish_receipt(&path, "fresh\n").expect("publish");
        let back = read_host_file(&path, "receipt", 1048576).expect("final");
        assert_eq!(String::from_utf8(back).expect("utf-8"), "fresh\n");
        assert_no_tmp_left(tmp.as_str(), "r.json", &[pid as u32]);
    }

    fn scan_kernel() -> KernelInfo {
        KernelInfo {
            release: "7.0.0-test".to_string(),
            arch: "x86_64".to_string(),
            eligible_floor: true,
            floor_reason: String::new(),
        }
    }

    #[test]
    fn smoke_bridge_binds_exercised_bytes() {
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let path = format!("{}/bridge.so", tmp.as_str());
        let repl = format!("{}/replacement.so", tmp.as_str());
        std::fs::write(&path, "EXERCISED-BRIDGE-BYTES\n").expect("write");
        std::fs::write(&repl, "SWAPPED-BRIDGE-BYTES\n").expect("write");
        let snap = open_bridge_snapshot(&path);
        std::fs::rename(&repl, &path).expect("swap");
        assert_eq!(
            smoke_bridge_hash(&snap).expect("hash"),
            format!("sha256:{}", sha256_hex(b"EXERCISED-BRIDGE-BYTES\n"))
        );
    }

    #[test]
    fn smoke_bridge_unbound_refuses() {
        let snap = open_bridge_snapshot("/nonexistent/memveil-bridge.so.1");
        assert!(smoke_bridge_hash(&snap).is_err());
    }

    #[test]
    fn smoke_object_binds_exercised_bytes() {
        let exercised =
            read_host_file(&repo("tests/fixtures/elf/ok.o"), "object", 1048576).expect("elf");
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let path = format!("{}/obj.o", tmp.as_str());
        let evil = format!("{}/evil.o", tmp.as_str());
        std::fs::write(&path, &exercised).expect("write");
        std::fs::write(&evil, "SWAPPED-OBJECT-BYTES\n").expect("write");
        let snap = open_object_snapshot(&path);
        let profiles = load_profiles(&repo("tests/fixtures/scan/profiles")).expect("profiles");
        let smoked = decide_record(
            &repo("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            &snap.load_path,
            "",
            "",
            "",
            "",
            "",
        );
        assert!(smoked.ok, "{}", smoked.refusal);
        assert_eq!(smoked.object_sha, snap.sha);
        std::fs::rename(&evil, &path).expect("swap");
        let swapped = read_host_file(&path, "object", 1048576).expect("swapped");
        assert_eq!(
            String::from_utf8(swapped).expect("utf-8"),
            "SWAPPED-OBJECT-BYTES\n"
        );
        let minted = smoke_object_hash(&snap).expect("hash");
        assert_eq!(minted, format!("sha256:{}", smoked.object_sha));
        assert_eq!(minted, format!("sha256:{}", sha256_hex(&exercised)));
    }

    #[test]
    fn smoke_object_unbound_refuses() {
        let snap = open_object_snapshot("/nonexistent/memveil-obj.o");
        assert!(smoke_object_hash(&snap).is_err());
    }

    #[test]
    fn smoke_pins_survive_through_inner_opens() {
        let exercised =
            read_host_file(&repo("tests/fixtures/elf/ok.o"), "object", 1048576).expect("elf");
        let tmp = TestDir::create("memveil-qual-pub").expect("scratch");
        let opath = format!("{}/obj.o", tmp.as_str());
        let bpath = format!("{}/bridge.so", tmp.as_str());
        std::fs::write(&opath, &exercised).expect("write");
        std::fs::write(&bpath, "OUTER-BRIDGE-BYTES\n").expect("write");
        let snap = open_bridge_snapshot(&bpath);
        let obj_snap = open_object_snapshot(&opath);
        assert_ne!(snap.sha, "");
        assert_ne!(obj_snap.sha, "");
        let want_bridge = snap.sha.clone();
        let want_object = obj_snap.sha.clone();
        let bridge_alias = snap.load_path.clone();
        let object_alias = obj_snap.load_path.clone();
        let inner = open_bridge_snapshot(&bridge_alias);
        let profiles = load_profiles(&repo("tests/fixtures/scan/profiles")).expect("profiles");
        let smoked = decide_record(
            &repo("tests/fixtures/scan/ok"),
            &scan_kernel(),
            &profiles,
            "",
            false,
            &object_alias,
            "",
            "",
            "",
            "",
            "",
        );
        std::hint::black_box((&snap, &obj_snap));
        assert_ne!(inner.sha, "");
        assert_eq!(inner.sha, want_bridge);
        assert!(smoked.ok, "{}", smoked.refusal);
        assert_eq!(smoked.object_sha, want_object);
    }

    #[test]
    fn channel_object_gate_matrix() {
        // Wanted channels without a resolved path refuse with the
        // collector's own wording; lifecycle reports first.
        assert_eq!(
            missing_channel_object(true, true, "", ""),
            "no object: pass --lc-object PATH"
        );
        assert_eq!(
            missing_channel_object(true, false, "", ""),
            "no object: pass --lc-object PATH"
        );
        assert_eq!(
            missing_channel_object(false, true, "", ""),
            "no object: pass --cp-object PATH"
        );
        assert_eq!(
            missing_channel_object(true, true, "lc.o", ""),
            "no object: pass --cp-object PATH"
        );
        // Explicit paths proceed, even unprobed: the smoke names
        // its own failure for a path that never opens.
        assert_eq!(missing_channel_object(true, true, "lc.o", "cp.o"), "");
        // Unwanted channels never gate, however empty.
        assert_eq!(missing_channel_object(false, false, "", ""), "");
        assert_eq!(missing_channel_object(true, false, "lc.o", ""), "");
        assert_eq!(missing_channel_object(false, true, "", "cp.o"), "");
    }

    #[test]
    fn qualify_refuses_unresolved_lc_before_smoke() {
        // The fixture plan covers mapping-lifecycle, but no
        // --lc-object is given and nothing is discovered, so the
        // run refuses before the smoke: no attach, no capture
        // directory, no receipt. Unprivileged-safe: the gate
        // returns before any privileged smoke setup.
        let tmp = TestDir::create("memveil-qual-gate").expect("scratch");
        let out = format!("{}/cap", tmp.as_str());
        let mut opts = base_opts();
        opts.output = out.clone();
        opts.capabilities = "attempt-trace,mapping-lifecycle".to_string();
        let code = run_qualify_with(&host(), &pdir(), &opts);
        assert_eq!(code, EXIT_REFUSAL);
        assert!(
            !std::path::Path::new(&out).exists(),
            "no capture dir on gate refusal"
        );
    }

    #[test]
    fn qualify_refuses_unresolved_cp_before_smoke() {
        // Same gate for copy-actual: an explicit lifecycle path
        // clears the first gate, the missing copy path refuses.
        let tmp = TestDir::create("memveil-qual-gate").expect("scratch");
        let out = format!("{}/cap", tmp.as_str());
        let mut opts = base_opts();
        opts.output = out.clone();
        opts.capabilities = "attempt-trace,mapping-lifecycle,copy-actual".to_string();
        opts.lc_object = "lc.o".to_string();
        let plan = plan_qualification(&host(), &pdir(), &opts);
        assert!(plan.ok, "{}", plan.refusal);
        let code = run_qualify_with(&host(), &pdir(), &opts);
        assert_eq!(code, EXIT_REFUSAL);
        assert!(
            !std::path::Path::new(&out).exists(),
            "no capture dir on gate refusal"
        );
    }
}
