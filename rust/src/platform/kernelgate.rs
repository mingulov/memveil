// SPDX-License-Identifier: GPL-3.0-or-later
//! Kernel gate probes: tracefs root, hook identity, ftrace state.
//!
//! The tracefs root follows libbpf's probe order (debugfs
//! first, sys second), so admission and the loader agree on
//! which tree they read. Hook identity counts exact
//! first-token matches in available_filter_functions;
//! dotted clones and longer names never count. Denied
//! evidence is never absence: every probe reports unknown
//! when the kernel hides the fact.

use super::btf::{MAX_KERNEL_BTF_BYTES, check_btf_health};
use super::narrow::read_live_config_text;
use super::reader::{
    E_TOO_BIG, EVIDENCE_ABSENT, EVIDENCE_DENIED, EVIDENCE_OK, EvidenceReader, bytes_to_text,
    exists_f_ok, file_state, read_evidence,
};
use super::tracefs::{TRACEFS_SYS, TracefsProbe, probe_tracefs, tracefs_translate};

/// available_filter_functions read cap: 8 MiB.
pub const MAX_FILTER_FUNCS_BYTES: usize = 8_388_608;
/// Hook count state when the file reads but resists parsing.
pub const HOOK_STATE_UNREADABLE: i32 = 3;

const MOUNTS_CAP: usize = 1_048_576;
const FTRACE_CAP: usize = 1024;
const FTRACE_TEXT_KEEP: usize = 64;
const LOCKDOWN_CAP: usize = 4096;
const CMDLINE_CAP: usize = 65_536;

/// One filter-file hook count: state plus matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookCount {
    /// Evidence state (or HOOK_STATE_UNREADABLE).
    pub state: i32,
    /// Exact first-token matches.
    pub count: i64,
    /// Dotted-clone first tokens.
    pub clones: i64,
}

impl HookCount {
    fn new() -> Self {
        Self {
            state: EVIDENCE_ABSENT,
            count: 0,
            clones: 0,
        }
    }
}

/// The line up to its first space, or the whole line.
fn first_token(line: &str) -> String {
    let b = line.as_bytes();
    for i in 0..b.len() {
        if b[i] == 0x20 {
            return std::str::from_utf8(&b[0..i]).unwrap_or("").to_string();
        }
    }
    line.to_string()
}

/// True when the line's first token equals the function.
///
/// Module suffixes ("fn [mod]") still count; dotted
/// clones ("fn.isra.0") and longer names never do.
pub fn filter_line_counts(line: &str, function: &str) -> bool {
    first_token(line) == function
}

/// True when the first token is a dotted clone of function.
fn filter_line_is_clone(line: &str, function: &str) -> bool {
    let tok = first_token(line);
    if tok == function {
        return false;
    }
    tok.starts_with(&format!("{function}."))
}

/// Count one function in available_filter_functions.
///
/// The file is read under the probed root; state carries
/// absent, denied, or unreadable without counting, and
/// clones count separately, never as matches.
pub fn count_filter_function(
    reader: &EvidenceReader,
    probe: &TracefsProbe,
    function: &str,
) -> HookCount {
    let mut out = HookCount::new();
    let fpath = tracefs_translate(probe, &format!("{TRACEFS_SYS}/available_filter_functions"));
    let st = file_state(reader, &fpath);
    if st != EVIDENCE_OK {
        out.state = st;
        return out;
    }
    let raw = match read_evidence(reader, &fpath, MAX_FILTER_FUNCS_BYTES) {
        Ok(raw) => raw,
        Err(_) => {
            out.state = HOOK_STATE_UNREADABLE;
            return out;
        }
    };
    let text = bytes_to_text(&raw);
    for line in text.split('\n') {
        if filter_line_counts(line, function) {
            out.count += 1;
        } else if filter_line_is_clone(line, function) {
            out.clones += 1;
        }
    }
    out.state = EVIDENCE_OK;
    out
}

/// One ftrace_enabled read: 1, 0, absent, denied, malformed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtraceState {
    /// The state word.
    pub value: String,
}

impl FtraceState {
    fn new() -> Self {
        Self {
            value: "malformed".to_string(),
        }
    }
}

/// Read the kernel.ftrace_enabled sysctl state word.
pub fn read_ftrace_enabled(reader: &EvidenceReader) -> FtraceState {
    let mut out = FtraceState::new();
    let st = file_state(reader, "/proc/sys/kernel/ftrace_enabled");
    if st == EVIDENCE_ABSENT {
        out.value = "absent".to_string();
        return out;
    }
    if st == EVIDENCE_DENIED {
        out.value = "denied".to_string();
        return out;
    }
    let raw = match read_evidence(reader, "/proc/sys/kernel/ftrace_enabled", FTRACE_CAP) {
        Ok(raw) => raw,
        Err(_) => {
            out.value = "malformed".to_string();
            return out;
        }
    };
    let text = bytes_to_text(&raw);
    let b = text.as_bytes();
    let mut end = b.len();
    if end > 0 && b[end - 1] == 0x0A {
        end -= 1;
    }
    let word = match std::str::from_utf8(&b[0..end]) {
        Ok(word) => word,
        Err(_) => {
            out.value = "malformed".to_string();
            return out;
        }
    };
    if word == "1" || word == "0" {
        out.value = word.to_string();
    } else {
        out.value = "malformed".to_string();
    }
    out
}

/// Raw ftrace_enabled content for messages, "" when unreadable.
pub fn read_ftrace_text(reader: &EvidenceReader) -> String {
    let raw = match read_evidence(reader, "/proc/sys/kernel/ftrace_enabled", FTRACE_CAP) {
        Ok(raw) => raw,
        Err(_) => return String::new(),
    };
    let text = bytes_to_text(&raw);
    let b = text.as_bytes();
    let mut end = b.len();
    if end > 0 && b[end - 1] == 0x0A {
        end -= 1;
    }
    if end > FTRACE_TEXT_KEEP {
        end = FTRACE_TEXT_KEEP;
    }
    std::str::from_utf8(&b[0..end]).unwrap_or("").to_string()
}

/// Mount word for one path: yes, no, or unknown.
///
/// Unknown covers unreadable, absent, and denied mount
/// tables: mounting is never disproven from them.
fn mounts_state(reader: &EvidenceReader, where_path: &str, fstype: &str) -> String {
    let mounts = match read_evidence(reader, "/proc/mounts", MOUNTS_CAP) {
        Ok(mounts) => mounts,
        Err(_) => return "unknown".to_string(),
    };
    let text = bytes_to_text(&mounts);
    for line in text.split('\n') {
        let fields: Vec<&str> = line.split(' ').collect();
        if fields.len() < 3 {
            continue;
        }
        if fields[1] == where_path && fields[2] == fstype {
            return "yes".to_string();
        }
    }
    "no".to_string()
}

/// One kernel lockdown read: mode, source, and detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockdownState {
    /// `none`, `integrity`, `confidentiality`, or `unknown`.
    pub mode: String,
    /// `securityfs`, `cmdline`, `config`, or `none`.
    pub src: String,
    /// Parse notes; empty when clean.
    pub detail: String,
}

impl LockdownState {
    fn new() -> Self {
        Self {
            mode: "unknown".to_string(),
            src: "none".to_string(),
            detail: String::new(),
        }
    }
}

/// Every [token] in one lockdown file body, in order.
fn lockdown_bracketed(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != 0x5B {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < b.len() && b[j] != 0x5D {
            j += 1;
        }
        if j < b.len() {
            if let Ok(token) = std::str::from_utf8(&b[i + 1..j]) {
                out.push(token.to_string());
            }
            i = j + 1;
        } else {
            i += 1;
        }
    }
    out
}

/// Mode word for one parsed level: 2, 1, or 0.
fn lockdown_mode(level: i64) -> String {
    if level >= 2 {
        return "confidentiality".to_string();
    }
    if level == 1 {
        return "integrity".to_string();
    }
    "none".to_string()
}

/// Read the kernel lockdown level with fallbacks.
///
/// The securityfs file wins when it parses under a
/// mounted securityfs; otherwise the cmdline level and
/// the config level combine by taking the higher one
/// (an absent lockdown LSM still forces none).
/// CONFIG_FORCE_NONE without securityfs reports
/// unknown: root may have raised the level since boot.
/// Silence everywhere reports unknown. Never mounts.
pub fn read_lockdown(reader: &EvidenceReader, release: &str, zlib: &str) -> LockdownState {
    let mut out = LockdownState::new();
    let mut notes: Vec<String> = Vec::new();
    let secfs = mounts_state(reader, "/sys/kernel/security", "securityfs");
    let st = file_state(reader, "/sys/kernel/security/lockdown");
    if st == EVIDENCE_OK
        && secfs != "no"
        && let Ok(lraw) = read_evidence(reader, "/sys/kernel/security/lockdown", LOCKDOWN_CAP)
    {
        let toks = lockdown_bracketed(&bytes_to_text(&lraw));
        if toks.len() == 1
            && (toks[0] == "none" || toks[0] == "integrity" || toks[0] == "confidentiality")
        {
            out.mode = toks[0].clone();
            out.src = "securityfs".to_string();
            return out;
        }
        notes.push("lockdown file malformed".to_string());
    }
    let mut cmd_level: i64 = 0;
    if file_state(reader, "/proc/cmdline") == EVIDENCE_OK
        && let Ok(craw) = read_evidence(reader, "/proc/cmdline", CMDLINE_CAP)
    {
        let mut ctext = bytes_to_text(&craw);
        let cb = ctext.as_bytes().to_vec();
        if !cb.is_empty()
            && cb[cb.len() - 1] == 0x0A
            && let Ok(trimmed) = std::str::from_utf8(&cb[0..cb.len() - 1])
        {
            ctext = trimmed.to_string();
        }
        for word in ctext.split(' ') {
            let tok = word.to_string();
            if tok == "--" {
                break;
            }
            if tok.starts_with("lockdown=") {
                let tb = tok.as_bytes();
                let val = std::str::from_utf8(&tb[9..tb.len()])
                    .unwrap_or("")
                    .to_string();
                if val == "integrity" {
                    if cmd_level < 1 {
                        cmd_level = 1;
                    }
                } else if val == "confidentiality" {
                    cmd_level = 2;
                } else {
                    notes.push(format!("lockdown={val} ignored"));
                }
            }
        }
    }
    let mut force_level: i64 = 0;
    let mut force_none = false;
    let mut lsm_absent = false;
    let cfg = read_live_config_text(reader, release, zlib);
    if cfg.state == "text" {
        for line in cfg.text.split('\n') {
            if line == "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y" {
                force_level = 2;
            } else if line == "CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y" {
                if force_level < 1 {
                    force_level = 1;
                }
            } else if line == "CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y" {
                force_none = true;
            } else if line == "# CONFIG_SECURITY_LOCKDOWN_LSM is not set" {
                lsm_absent = true;
            }
        }
    }
    if lsm_absent {
        out.mode = "none".to_string();
        out.src = "config".to_string();
    } else if cmd_level > 0 || force_level > 0 {
        if cmd_level >= force_level {
            out.mode = lockdown_mode(cmd_level);
            out.src = "cmdline".to_string();
        } else {
            out.mode = lockdown_mode(force_level);
            out.src = "config".to_string();
        }
    } else if force_none {
        // Forced none is only the boot default; without
        // the securityfs file the runtime level is open.
        out.mode = "unknown".to_string();
        out.src = "config".to_string();
    }
    if !notes.is_empty() {
        out.detail = notes.join("; ");
    }
    out
}

/// One fixed remedy text per reason code, else "".
///
/// Families share a text; anything outside the table
/// (profile refusals, unknown codes) carries no line.
pub fn remedy_for(code: &str) -> String {
    if code == "lockdown-confidentiality" {
        return "boot without lockdown=confidentiality or use a kernel without CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY; integrity mode is fine"
            .to_string();
    }
    if code == "no-bpf-tracing" {
        return "kernel has no BPF tracing support: use a kernel built with CONFIG_FTRACE=y and CONFIG_BPF_EVENTS=y"
            .to_string();
    }
    if code == "tracefs-not-mounted" {
        return "mount tracefs: mount -t tracefs nodev /sys/kernel/tracing".to_string();
    }
    if code == "tracefs-hidden" {
        return "check the lockdown state (cat /sys/kernel/security/lockdown) and that tracefs is mounted"
            .to_string();
    }
    if code == "tracefs-denied"
        || code == "btf-denied"
        || code == "no-bpf-privilege"
        || code == "load-eperm"
    {
        return "run as root: BPF load needs CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN), and tracefs reads follow libbpf's existence-order tree, which needs root while /sys/kernel/debug/tracing exists; there is no supported capabilities-only setup"
            .to_string();
    }
    if code == "btf-absent-config"
        || code == "btf-absent-unknown"
        || code == "btf-malformed"
        || code == "btf-truncated"
        || code == "btf-too-large"
        || code == "btf-split"
        || code == "btf-unreadable"
    {
        return "use a kernel built with CONFIG_DEBUG_INFO_BTF=y; memveil qualify cannot help"
            .to_string();
    }
    if code == "btf-hook-not-in-btf" {
        return "this kernel's BTF does not describe the hook function; use a kernel whose BTF includes it"
            .to_string();
    }
    if code == "btf-hook-missing" {
        return "check that /proc/kallsyms exists and is readable, so the hook can be verified against the live kernel"
            .to_string();
    }
    if code == "btf-not-visible" {
        return "run with the host /sys: this view hides /sys/kernel/btf/vmlinux".to_string();
    }
    if code == "btf-hook-absent" || code == "hook-ambiguous" || code == "hook-not-traceable" {
        return "this kernel does not expose the hook function for tracing; this capability cannot run here"
            .to_string();
    }
    if code == "ftrace-disabled" {
        return "enable function tracing: sysctl kernel.ftrace_enabled=1".to_string();
    }
    if code == "ftrace-unknown" {
        return "check that /proc/sys/kernel/ftrace_enabled is readable and holds 1".to_string();
    }
    if code == "layout-missing"
        || code == "layout-kind"
        || code == "layout-size"
        || code == "layout-bitfield"
        || code == "layout-ambiguous"
    {
        return "this kernel's struct layout differs from what the objects were built for; this capability cannot run here"
            .to_string();
    }
    if code == "signature-mismatch" || code == "signature-width" {
        return "refresh the profile's recorded signatures from this kernel, then re-prove with memveil qualify (see memveil qualify --help)"
            .to_string();
    }
    if code == "memcg-headroom" || code == "load-enomem" {
        return "raise the cgroup memory limit (memory.max) or RLIMIT_MEMLOCK".to_string();
    }
    if code == "object-missing" {
        return "install the memveil BPF objects or pass --object, --lc-object, --cp-object"
            .to_string();
    }
    if code == "verifier-rejected" {
        return "the kernel verifier rejected the object; see the verifier lines above".to_string();
    }
    if code == "bridge-unchecked" {
        return "run memveil doctor --load-check or memveil record to check the bridge".to_string();
    }
    String::new()
}

/// One kernel BTF fact set: state, bytes, config words.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtfFacts {
    /// `present`, `absent`, `denied`, `not-visible`,
    /// `malformed`, or `unreadable`.
    pub state: String,
    /// Blob length; valid only when `has_bytes`.
    pub bytes: i64,
    /// True when `bytes` was read.
    pub has_bytes: bool,
    /// `y`, `n`, or `unknown`.
    pub config_btf: String,
    /// `proc`, `boot`, or `none`.
    pub config_src: String,
}

impl BtfFacts {
    fn new() -> Self {
        Self {
            state: "unreadable".to_string(),
            bytes: 0,
            has_bytes: false,
            config_btf: "unknown".to_string(),
            config_src: "none".to_string(),
        }
    }
}

/// One shared kernel gate verdict with evidence facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GateVerdict {
    /// True when every check passed.
    pub ok: bool,
    /// True when the refusal is uncertainty, not fact.
    pub unknown: bool,
    /// Machine-stable reason code; empty when ok.
    pub code: String,
    /// Human reason; empty when ok.
    pub reason: String,
    /// Fixed remedy; empty when ok.
    pub remedy: String,
    /// BTF facts.
    pub btf: BtfFacts,
    /// Lockdown facts.
    pub lockdown: LockdownState,
    /// Tracefs facts.
    pub tracefs: TracefsProbe,
}

impl GateVerdict {
    fn new() -> Self {
        Self {
            ok: false,
            unknown: false,
            code: String::new(),
            reason: String::new(),
            remedy: String::new(),
            btf: BtfFacts::new(),
            lockdown: LockdownState::new(),
            tracefs: TracefsProbe::new(),
        }
    }
}

/// True when one exact config line is present.
fn config_has_line(text: &str, line: &str) -> bool {
    text.split('\n').any(|candidate| candidate == line)
}

/// Admit capabilities through the shared kernel checks.
///
/// Lockdown, tracing support, tracefs, and (for the BTF
/// channels) BTF presence decide in that order; the
/// first match wins and the facts always fill in for
/// doctor. Unhealthy BTF bytes are recorded, never
/// refused here: the live path reports them.
pub fn kernel_gate(
    reader: &EvidenceReader,
    release: &str,
    zlib: &str,
    caps: &[String],
) -> GateVerdict {
    let mut out = GateVerdict::new();
    out.lockdown = read_lockdown(reader, release, zlib);
    out.tracefs = probe_tracefs(reader);
    let cfg = read_live_config_text(reader, release, zlib);
    let mut cfg_text = String::new();
    if cfg.state == "text" {
        cfg_text = cfg.text.clone();
    }
    let mut facts = BtfFacts::new();
    if cfg.state == "text" {
        if cfg.src == "gz" {
            facts.config_src = "proc".to_string();
        } else if cfg.src == "file" {
            facts.config_src = "boot".to_string();
        }
        if config_has_line(&cfg_text, "CONFIG_DEBUG_INFO_BTF=y") {
            facts.config_btf = "y".to_string();
        } else if config_has_line(&cfg_text, "# CONFIG_DEBUG_INFO_BTF is not set") {
            facts.config_btf = "n".to_string();
        }
    }
    let btf_st = file_state(reader, "/sys/kernel/btf/vmlinux");
    let mut btf_too_big = false;
    let mut btf_read_ok = false;
    let mut btf_err = String::new();
    if btf_st == EVIDENCE_OK {
        match read_evidence(reader, "/sys/kernel/btf/vmlinux", MAX_KERNEL_BTF_BYTES) {
            Ok(btf_bytes) => {
                let health = check_btf_health(&btf_bytes);
                facts.bytes = btf_bytes.len() as i64;
                facts.has_bytes = true;
                btf_read_ok = true;
                if health.ok {
                    facts.state = "present".to_string();
                } else {
                    facts.state = "malformed".to_string();
                }
            }
            Err(error) => {
                btf_err = error.to_string();
                if error.code == E_TOO_BIG {
                    btf_too_big = true;
                }
            }
        }
    }
    if btf_st == EVIDENCE_DENIED {
        facts.state = "denied".to_string();
    } else if btf_st == EVIDENCE_ABSENT {
        facts.state = "absent".to_string();
        if facts.config_btf == "y" {
            facts.state = "not-visible".to_string();
        }
    } else if !btf_read_ok {
        facts.state = "unreadable".to_string();
    }
    out.btf = facts;
    let mut want_btf = false;
    for cap in caps {
        if cap == "mapping-lifecycle" || cap == "copy-actual" {
            want_btf = true;
            break;
        }
    }
    let mut code = String::new();
    let mut reason = String::new();
    let mut unknown = false;
    let mut refused = false;
    let troot = out.tracefs.root.clone();
    if out.lockdown.mode == "confidentiality" {
        let lsrc = out.lockdown.src.clone();
        code = "lockdown-confidentiality".to_string();
        reason = format!(
            "kernel lockdown is confidentiality ({lsrc}): tracefs is hidden and bpf_probe_read_kernel is denied"
        );
        refused = true;
    } else if config_has_line(&cfg_text, "# CONFIG_FTRACE is not set") {
        code = "no-bpf-tracing".to_string();
        reason =
            "kernel has no BPF tracing support (config has # CONFIG_FTRACE is not set)".to_string();
        refused = true;
    } else if config_has_line(&cfg_text, "CONFIG_FTRACE=y")
        && !config_has_line(&cfg_text, "CONFIG_BPF_EVENTS=y")
    {
        code = "no-bpf-tracing".to_string();
        reason = "kernel has no BPF tracing support (config has CONFIG_FTRACE=y without CONFIG_BPF_EVENTS=y)"
            .to_string();
        refused = true;
    } else if out.tracefs.mounted == "yes"
        && out.tracefs.events == EVIDENCE_ABSENT
        && out.lockdown.mode != "unknown"
    {
        code = "no-bpf-tracing".to_string();
        reason = format!(
            "kernel has no BPF tracing support (tracefs mounted at {troot} but has no events/)"
        );
        refused = true;
    } else if !out.tracefs.has_root {
        code = "tracefs-not-mounted".to_string();
        reason =
            "tracefs not found: neither /sys/kernel/debug/tracing nor /sys/kernel/tracing exists"
                .to_string();
        refused = true;
    } else if out.tracefs.events == EVIDENCE_DENIED {
        code = "tracefs-denied".to_string();
        reason = format!("tracefs denied (privilege): {troot}/events");
        unknown = true;
        refused = true;
    } else if out.tracefs.events == EVIDENCE_ABSENT && out.tracefs.mounted == "no" {
        code = "tracefs-not-mounted".to_string();
        reason = format!("tracefs not mounted at {troot} (no tracefs entry in /proc/mounts)");
        refused = true;
    } else if out.tracefs.events == EVIDENCE_ABSENT && out.lockdown.mode == "unknown" {
        code = "tracefs-hidden".to_string();
        reason =
            "tracepoint absent or tracefs hidden by lockdown (lockdown state unknown)".to_string();
        unknown = true;
        refused = true;
    } else if out.tracefs.events == EVIDENCE_ABSENT {
        code = "tracefs-not-mounted".to_string();
        reason = format!("{troot}/events absent (tracefs not mounted or mount state unreadable)");
        unknown = true;
        refused = true;
    } else if want_btf && btf_st == EVIDENCE_DENIED {
        code = "btf-denied".to_string();
        reason = "BTF denied (privilege)".to_string();
        unknown = true;
        refused = true;
    } else if want_btf
        && btf_st == EVIDENCE_ABSENT
        && out.btf.config_btf == "n"
        && exists_f_ok(reader, "/sys/kernel/notes")
    {
        code = "btf-absent-config".to_string();
        reason = "BTF absent (kernel built without BTF)".to_string();
        refused = true;
    } else if want_btf && btf_st == EVIDENCE_ABSENT && out.btf.config_btf == "y" {
        code = "btf-not-visible".to_string();
        reason = "BTF not visible (config has CONFIG_DEBUG_INFO_BTF=y but /sys/kernel/btf/vmlinux is missing)"
            .to_string();
        unknown = true;
        refused = true;
    } else if want_btf && btf_st == EVIDENCE_ABSENT {
        code = "btf-absent-unknown".to_string();
        reason = "BTF absent (not exposed: kernel built without BTF, or /sys/kernel/btf hidden)"
            .to_string();
        refused = true;
    } else if want_btf && btf_too_big {
        let cap = MAX_KERNEL_BTF_BYTES;
        code = "btf-too-large".to_string();
        reason = format!("BTF too large (over {cap} bytes)");
        unknown = true;
        refused = true;
    } else if want_btf && !btf_read_ok {
        code = "btf-unreadable".to_string();
        reason = format!("BTF unreadable: {btf_err}");
        unknown = true;
        refused = true;
    }
    if refused {
        out.code = code.clone();
        out.reason = reason.clone();
        out.unknown = unknown;
        out.remedy = remedy_for(&code);
        return out;
    }
    out.ok = true;
    out
}

#[cfg(test)]
mod tests {
    use super::{
        GateVerdict, LockdownState, count_filter_function, filter_line_counts, kernel_gate,
        read_ftrace_enabled, read_ftrace_text, read_lockdown, remedy_for,
    };
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::{TestDir, gate_fixture};
    use crate::platform::tracefs::probe_tracefs;

    fn lockdown_of(name: &str) -> LockdownState {
        let r = open_evidence_reader(&gate_fixture(name)).expect("fixture opens");
        read_lockdown(&r, &r.release.clone(), "libz.so.1")
    }

    fn gate_of(name: &str, caps: &[String]) -> GateVerdict {
        let r = open_evidence_reader(&gate_fixture(name)).expect("fixture opens");
        kernel_gate(&r, &r.release.clone(), "libz.so.1", caps)
    }

    fn one_cap(cap_id: &str) -> Vec<String> {
        vec![cap_id.to_string()]
    }

    fn attempt_only() -> Vec<String> {
        one_cap("attempt-trace")
    }

    fn all_caps() -> Vec<String> {
        vec![
            "attempt-trace".to_string(),
            "mapping-lifecycle".to_string(),
            "copy-actual".to_string(),
        ]
    }

    #[test]
    fn hook_identity_shapes() {
        let dup = open_evidence_reader(&gate_fixture("aff-dup")).expect("fixture opens");
        let hd = count_filter_function(&dup, &probe_tracefs(&dup), "swiotlb_tbl_map_single");
        assert_eq!(hd.count, 2);
        let module = open_evidence_reader(&gate_fixture("aff-module")).expect("fixture opens");
        let hm = count_filter_function(&module, &probe_tracefs(&module), "swiotlb_tbl_map_single");
        assert_eq!(hm.count, 1);
        let clone = open_evidence_reader(&gate_fixture("aff-clone")).expect("fixture opens");
        let hc = count_filter_function(&clone, &probe_tracefs(&clone), "swiotlb_tbl_map_single");
        assert_eq!(hc.count, 0);
        assert_eq!(hc.clones, 1);
        let prefix = open_evidence_reader(&gate_fixture("aff-prefix")).expect("fixture opens");
        let hp = count_filter_function(&prefix, &probe_tracefs(&prefix), "swiotlb_tbl_map_single");
        assert_eq!(hp.count, 1);
    }

    #[test]
    fn filter_line_counts_shapes() {
        // Module suffixes ("fn [mod]") still count; dotted
        // clones ("fn.isra.0") and longer names never do.
        assert!(filter_line_counts(
            "swiotlb_tbl_map_single",
            "swiotlb_tbl_map_single"
        ));
        assert!(filter_line_counts(
            "swiotlb_tbl_map_single [swiotlb]",
            "swiotlb_tbl_map_single"
        ));
        assert!(!filter_line_counts(
            "swiotlb_tbl_map_single.isra.0",
            "swiotlb_tbl_map_single"
        ));
        assert!(!filter_line_counts(
            "swiotlb_tbl_map_single_extra",
            "swiotlb_tbl_map_single"
        ));
        assert!(!filter_line_counts("", "swiotlb_tbl_map_single"));
    }

    #[test]
    fn lockdown_sources() {
        let b = lockdown_of("base");
        assert_eq!(b.mode, "none");
        assert_eq!(b.src, "securityfs");
        let c = lockdown_of("lockdown-conf");
        assert_eq!(c.mode, "confidentiality");
        assert_eq!(c.src, "securityfs");
        let i = lockdown_of("lockdown-integrity");
        assert_eq!(i.mode, "integrity");
        assert_eq!(i.src, "securityfs");
        let n = lockdown_of("lockdown-nosecfs");
        assert_eq!(n.mode, "confidentiality");
        assert_eq!(n.src, "cmdline");
        let g = lockdown_of("lockdown-config");
        assert_eq!(g.mode, "confidentiality");
        assert_eq!(g.src, "config");
        let l = lockdown_of("lockdown-nolsm");
        assert_eq!(l.mode, "none");
        assert_eq!(l.src, "config");
    }

    #[test]
    fn lockdown_malformed() {
        let d = lockdown_of("lockdown-dashdash");
        assert_eq!(d.mode, "unknown");
        assert_eq!(d.src, "none");
        let t = lockdown_of("lockdown-twobrackets");
        assert_eq!(t.mode, "unknown");
        assert_eq!(t.detail, "lockdown file malformed");
        let o = lockdown_of("lockdown-bogus");
        assert_eq!(o.mode, "unknown");
        assert_eq!(o.src, "none");
        assert!(o.detail.contains("lockdown=bogus ignored"));
        let x = lockdown_of("lockdown-denied");
        assert_eq!(x.mode, "unknown");
    }

    #[test]
    fn lockdown_forcenone_unknown() {
        // FORCE_NONE without securityfs cannot settle the
        // runtime level: root may have raised it since boot.
        let f = lockdown_of("lockdown-forcenone");
        assert_eq!(f.mode, "unknown");
        assert_eq!(f.src, "config");
    }

    #[test]
    fn gate_order() {
        let lc = gate_of("lockdown-conf", &attempt_only());
        assert!(!lc.ok);
        assert!(!lc.unknown);
        assert_eq!(lc.code, "lockdown-confidentiality");
        let nc = gate_of("notracing-config", &attempt_only());
        assert!(!nc.ok);
        assert_eq!(nc.code, "no-bpf-tracing");
        let nb = gate_of("notracing-bpfevents", &attempt_only());
        assert!(!nb.ok);
        assert_eq!(nb.code, "no-bpf-tracing");
        let ne = gate_of("tracefs-noevents", &attempt_only());
        assert!(!ne.ok);
        assert_eq!(ne.code, "no-bpf-tracing");
        assert_eq!(
            ne.reason,
            "kernel has no BPF tracing support (tracefs mounted at /sys/kernel/tracing but has no events/)"
        );
        let tu = gate_of("tracefs-unmounted", &attempt_only());
        assert!(!tu.ok);
        assert_eq!(tu.code, "tracefs-not-mounted");
        let tg = gate_of("tracefs-gone", &attempt_only());
        assert!(!tg.ok);
        assert_eq!(tg.code, "tracefs-not-mounted");
        let th = gate_of("tracefs-hidden", &attempt_only());
        assert!(!th.ok);
        assert!(th.unknown);
        assert_eq!(
            th.reason,
            "tracepoint absent or tracefs hidden by lockdown (lockdown state unknown)"
        );
        let ed = gate_of("events-denied", &attempt_only());
        assert!(!ed.ok);
        assert!(ed.unknown);
        assert_eq!(ed.code, "tracefs-denied");
        let b = gate_of("base", &all_caps());
        assert!(b.ok);
    }

    #[test]
    fn gate_noevents_unknown_lockdown_hidden() {
        // Mounted tracefs without events/ is only a definite
        // no-bpf-tracing verdict when lockdown is known;
        // otherwise lockdown may be hiding the mount.
        let g = gate_of("tracefs-noevents-nolock", &attempt_only());
        assert!(!g.ok);
        assert!(g.unknown);
        assert_eq!(g.code, "tracefs-hidden");
    }

    #[test]
    fn gate_btf_codes() {
        let lc = vec!["attempt-trace".to_string(), "mapping-lifecycle".to_string()];
        let c = gate_of("btf-absent-config", &lc);
        assert!(!c.ok);
        assert!(!c.unknown);
        assert_eq!(c.code, "btf-absent-config");
        assert_eq!(c.reason, "BTF absent (kernel built without BTF)");
        let u = gate_of("btf-absent-unknown", &lc);
        assert!(!u.ok);
        assert_eq!(u.code, "btf-absent-unknown");
        assert_eq!(
            u.reason,
            "BTF absent (not exposed: kernel built without BTF, or /sys/kernel/btf hidden)"
        );
        let n = gate_of("btf-not-visible", &lc);
        assert!(!n.ok);
        assert!(n.unknown);
        assert_eq!(n.code, "btf-not-visible");
        let d = gate_of("btf-denied", &lc);
        assert!(!d.ok);
        assert!(d.unknown);
        assert_eq!(d.code, "btf-denied");
        assert!(gate_of("btf-absent-config", &attempt_only()).ok);
        assert!(gate_of("btf-absent-unknown", &attempt_only()).ok);
        assert!(gate_of("btf-not-visible", &attempt_only()).ok);
        assert!(gate_of("btf-denied", &attempt_only()).ok);
    }

    #[test]
    fn gate_denied_never_absent() {
        let g = gate_of("denied-all", &all_caps());
        assert!(g.ok || g.unknown);
        assert_ne!(g.code, "btf-absent-config");
        assert_ne!(g.code, "btf-absent-unknown");
        assert_ne!(g.code, "tracefs-not-mounted");
        assert_ne!(g.code, "ftrace-disabled");
        assert_ne!(g.code, "no-bpf-tracing");
        assert_eq!(g.lockdown.mode, "unknown");
        let r = open_evidence_reader(&gate_fixture("denied-all")).expect("fixture opens");
        assert_eq!(read_ftrace_enabled(&r).value, "denied");
    }

    #[test]
    fn gate_container_views() {
        let caps = vec!["attempt-trace".to_string(), "copy-actual".to_string()];
        let v = gate_of("container-view", &caps);
        assert!(!v.ok);
        assert!(v.unknown);
        assert_eq!(v.tracefs.root, "/sys/kernel/debug/tracing");
        assert_eq!(v.code, "btf-not-visible");
        assert_eq!(
            v.remedy,
            "run with the host /sys: this view hides /sys/kernel/btf/vmlinux"
        );
    }

    #[test]
    fn remedy_per_code() {
        let priv_remedy = "run as root: BPF load needs CAP_BPF+CAP_PERFMON (or CAP_SYS_ADMIN), and tracefs reads follow libbpf's existence-order tree, which needs root while /sys/kernel/debug/tracing exists; there is no supported capabilities-only setup";
        let btfbuild =
            "use a kernel built with CONFIG_DEBUG_INFO_BTF=y; memveil qualify cannot help";
        let nohook = "this kernel does not expose the hook function for tracing; this capability cannot run here";
        let layout = "this kernel's struct layout differs from what the objects were built for; this capability cannot run here";
        let sig = "refresh the profile's recorded signatures from this kernel, then re-prove with memveil qualify (see memveil qualify --help)";
        let mem = "raise the cgroup memory limit (memory.max) or RLIMIT_MEMLOCK";
        let cases = [
            (
                "lockdown-confidentiality",
                "boot without lockdown=confidentiality or use a kernel without CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY; integrity mode is fine",
            ),
            (
                "no-bpf-tracing",
                "kernel has no BPF tracing support: use a kernel built with CONFIG_FTRACE=y and CONFIG_BPF_EVENTS=y",
            ),
            (
                "tracefs-not-mounted",
                "mount tracefs: mount -t tracefs nodev /sys/kernel/tracing",
            ),
            (
                "tracefs-hidden",
                "check the lockdown state (cat /sys/kernel/security/lockdown) and that tracefs is mounted",
            ),
            ("tracefs-denied", priv_remedy),
            ("btf-denied", priv_remedy),
            ("no-bpf-privilege", priv_remedy),
            ("load-eperm", priv_remedy),
            ("btf-absent-config", btfbuild),
            ("btf-absent-unknown", btfbuild),
            ("btf-malformed", btfbuild),
            ("btf-truncated", btfbuild),
            ("btf-too-large", btfbuild),
            ("btf-split", btfbuild),
            ("btf-unreadable", btfbuild),
            (
                "btf-hook-not-in-btf",
                "this kernel's BTF does not describe the hook function; use a kernel whose BTF includes it",
            ),
            (
                "btf-hook-missing",
                "check that /proc/kallsyms exists and is readable, so the hook can be verified against the live kernel",
            ),
            (
                "btf-not-visible",
                "run with the host /sys: this view hides /sys/kernel/btf/vmlinux",
            ),
            ("btf-hook-absent", nohook),
            ("hook-ambiguous", nohook),
            ("hook-not-traceable", nohook),
            (
                "ftrace-disabled",
                "enable function tracing: sysctl kernel.ftrace_enabled=1",
            ),
            (
                "ftrace-unknown",
                "check that /proc/sys/kernel/ftrace_enabled is readable and holds 1",
            ),
            ("layout-missing", layout),
            ("layout-kind", layout),
            ("layout-size", layout),
            ("layout-bitfield", layout),
            ("layout-ambiguous", layout),
            ("signature-mismatch", sig),
            ("signature-width", sig),
            ("memcg-headroom", mem),
            ("load-enomem", mem),
            (
                "object-missing",
                "install the memveil BPF objects or pass --object, --lc-object, --cp-object",
            ),
            (
                "bridge-unchecked",
                "run memveil doctor --load-check or memveil record to check the bridge",
            ),
            (
                "verifier-rejected",
                "the kernel verifier rejected the object; see the verifier lines above",
            ),
        ];
        for (code, want) in cases {
            assert_eq!(remedy_for(code), want, "code {code}");
        }
        assert_eq!(remedy_for("profile"), "");
        assert_eq!(remedy_for("no-such-code"), "");
        let mut shared = 0;
        for (code, _) in cases {
            if remedy_for(code) == sig {
                shared += 1;
            }
        }
        assert_eq!(shared, 2);
    }

    #[test]
    fn remedy_hook_btf_split() {
        // Both hook codes fire on kernels that have BTF, so
        // neither may ask for a BTF-built kernel: one names
        // the undescribed hook, the other the unreadable list.
        assert_eq!(
            remedy_for("btf-hook-not-in-btf"),
            "this kernel's BTF does not describe the hook function; use a kernel whose BTF includes it"
        );
        assert_eq!(
            remedy_for("btf-hook-missing"),
            "check that /proc/kallsyms exists and is readable, so the hook can be verified against the live kernel"
        );
    }

    #[test]
    fn ftrace_states() {
        let base = open_evidence_reader(&gate_fixture("base")).expect("fixture opens");
        assert_eq!(read_ftrace_enabled(&base).value, "1");
        let off = open_evidence_reader(&gate_fixture("ftrace-off")).expect("fixture opens");
        assert_eq!(read_ftrace_enabled(&off).value, "0");
        let denied = open_evidence_reader(&gate_fixture("ftrace-denied")).expect("fixture opens");
        assert_eq!(read_ftrace_enabled(&denied).value, "denied");
        let malformed =
            open_evidence_reader(&gate_fixture("ftrace-malformed")).expect("fixture opens");
        assert_eq!(read_ftrace_enabled(&malformed).value, "malformed");
    }

    fn copy_tree(src: &std::path::Path, dst: &std::path::Path) {
        for entry in std::fs::read_dir(src).expect("read fixture dir") {
            let entry = entry.expect("dir entry");
            let target = dst.join(entry.file_name());
            if entry.file_type().expect("file type").is_dir() {
                std::fs::create_dir_all(&target).expect("mkdir");
                copy_tree(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).expect("copy file");
            }
        }
    }

    #[test]
    fn btf_unreadable_reason_pins_mojo_rendering() {
        // A vmlinux path that exists (access: OK) but refuses
        // the contained open (O_NOFOLLOW symlink: ELOOP maps
        // to E_DENIED) drives the btf-unreadable lane. The
        // reason must render byte-identically to Mojo's
        // `"BTF unreadable: " + String(e)`: pinned Mojo 1.2.0
        // prints `EvidenceError(code=N, message=M)`, the same
        // shape as the Rust Display.
        let tmp = TestDir::create("kgate-unreadable").expect("mkdtemp");
        copy_tree(std::path::Path::new(&gate_fixture("base")), tmp.path());
        let vmlinux = tmp.path().join("sys/kernel/btf/vmlinux");
        std::fs::remove_file(&vmlinux).expect("remove vmlinux");
        std::os::unix::fs::symlink("../notes", &vmlinux).expect("link vmlinux");
        let r = open_evidence_reader(tmp.as_str()).expect("scratch opens");
        let caps = vec!["attempt-trace".to_string(), "mapping-lifecycle".to_string()];
        let g = kernel_gate(&r, &r.release.clone(), "libz.so.1", &caps);
        assert!(!g.ok);
        assert!(g.unknown);
        assert_eq!(g.code, "btf-unreadable");
        assert_eq!(
            g.reason,
            "BTF unreadable: EvidenceError(code=4, message=/sys/kernel/btf/vmlinux: denied)"
        );
        assert_eq!(g.btf.state, "unreadable");
    }

    #[test]
    fn ftrace_text_raw() {
        let base = open_evidence_reader(&gate_fixture("base")).expect("fixture opens");
        assert_eq!(read_ftrace_text(&base), "1");
        let off = open_evidence_reader(&gate_fixture("ftrace-off")).expect("fixture opens");
        assert_eq!(read_ftrace_text(&off), "0");
        let denied = open_evidence_reader(&gate_fixture("denied-all")).expect("fixture opens");
        assert_eq!(read_ftrace_text(&denied), "");
    }
}
