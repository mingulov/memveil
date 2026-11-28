// SPDX-License-Identifier: GPL-3.0-or-later
//! Host identity and guest-technology evidence for the passive doctor.
//!
//! [`detect_environment`] gathers every profile-independent fact the
//! doctor needs: kernel release/arch and floor eligibility, the
//! guest-technology verdict, BTF/config states, and the
//! privilege-denied path list. Scanning is byte-level over capped reads.
//!
//! The function is total: unreadable evidence degrades to explicit
//! unknown/conflict signals, never to an exception. Only structural
//! failures (a bad fixture header) fail, and those surface when the
//! reader is opened, before this module runs.
//!
//! Guest-technology rules are conservative, and every verdict names its
//! sources in `signals`:
//!
//! - `sev-guest` and `tdx-guest` nodes both readable: unknown plus
//!   a conflict. The nodes contradict each other.
//! - One node readable: the matching cpu flag corroborates it
//!   (`sev_snp` for snp, `sev` without `sev_snp` for sev-classic,
//!   `tdx_guest` for tdx). A flag token for the *other* technology
//!   contradicts the node and means unknown plus a conflict, as do
//!   readable flags that lack the node's own token. Unreadable flags
//!   mean unknown with an unavailable note.
//! - No nodes: readable flags mean ordinary, recorded explicitly as an
//!   absence-of-node inference; unreadable flags mean unknown. Stray
//!   technology tokens without any node do not contradict the
//!   absence inference: CPUID feature bits are leakable by the
//!   hypervisor, so flags alone never assert.
//! - The SNP-only `sev/vmpl` sysfs node is the kernel's own SNP
//!   proof: with a sev-guest node but flags that lack `sev`,
//!   vmpl content `0`..`3` affirms snp, while denied or
//!   malformed content keeps the conflict. With no guest node at
//!   all, a readable or denied vmpl node means unknown plus a
//!   conflict, never ordinary.
//! - Denied nodes or cpuinfo mean unknown, and the path lands in
//!   `denied_paths` so a privilege restriction reads differently
//!   from an absent kernel feature.
//! - A fixture-only user assertion breaks an unknown tie or agrees
//!   with the evidence verdict; when it contradicts the evidence the
//!   verdict is unknown plus a conflict. Live runs never assert.
//! - CPU vendor/model/family lines are never verdict sources. Only
//!   the three corroborating flag tokens are read, and only from
//!   `flags` lines.

use super::btf::MAX_KERNEL_BTF_BYTES;
use super::reader::{
    EVIDENCE_ABSENT, EVIDENCE_DENIED, EVIDENCE_OK, EvidenceReader, bytes_to_text, file_state,
    read_evidence,
};

/// cpuinfo evidence path.
pub const P_CPUINFO: &str = "/proc/cpuinfo";
/// os-release evidence path.
pub const P_OS_RELEASE: &str = "/etc/os-release";
/// Kernel BTF evidence path.
pub const P_BTF: &str = "/sys/kernel/btf/vmlinux";
/// Compressed kernel config evidence path.
pub const P_CONFIG_GZ: &str = "/proc/config.gz";
/// SEV guest device node.
pub const P_SEV_NODE: &str = "/dev/sev-guest";
/// TDX guest device node.
pub const P_TDX_NODE: &str = "/dev/tdx_guest";
/// TSM report directory.
pub const P_TSM_REPORT: &str = "/sys/kernel/config/tsm/report";
/// SNP vmpl sysfs node.
pub const P_SEV_VMPL: &str = "/sys/devices/system/cpu/sev/vmpl";
/// Boot config filename prefix.
pub const P_BOOT_CONFIG_PREFIX: &str = "/boot/config-";

const CPUINFO_CAP: usize = 1_048_576;
const VMPL_CAP: usize = 64;
const OS_RELEASE_CAP: usize = 65_536;
const BTF_CAP: usize = MAX_KERNEL_BTF_BYTES;
const TRIPLE_BOUND: i64 = 2_147_483_647;
const OS_VALUE_KEEP: usize = 64;

/// The kernel BTF read cap, one shared value.
pub fn evidence_btf_cap() -> usize {
    MAX_KERNEL_BTF_BYTES
}

/// A parsed kernel release triple. `ok` is false when unparseable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelTriple {
    /// True when leading digits parsed.
    pub ok: bool,
    /// Major component.
    pub major: i64,
    /// Minor component, default 0.
    pub minor: i64,
    /// Patch component, default 0.
    pub patch: i64,
}

/// Kernel identity plus the 6.0 eligibility floor check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KernelInfo {
    /// The release string.
    pub release: String,
    /// The architecture string.
    pub arch: String,
    /// True when the release meets the floor.
    pub eligible_floor: bool,
    /// Why the floor passed or failed.
    pub floor_reason: String,
}

/// Guest-technology verdict.
///
/// `tech` is one of `ordinary`, `snp`, `tdx`,
/// `sev-classic`, `unknown`. `signals` names every evidence
/// source behind the verdict (`info:`-prefixed entries are
/// environment context, not verdict sources). `asserted` is true
/// when a fixture-only user assertion contributed.
/// `conflict` is `""` when nothing contradicts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestInfo {
    /// The verdict token.
    pub tech: String,
    /// Every evidence source behind the verdict.
    pub signals: Vec<String>,
    /// True when a fixture assertion contributed.
    pub asserted: bool,
    /// The contradiction, or `""`.
    pub conflict: String,
}

/// All profile-independent doctor evidence for one reader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvironmentEvidence {
    /// Kernel identity and floor.
    pub kernel: KernelInfo,
    /// Guest-technology verdict.
    pub guest: GuestInfo,
    /// BTF evidence state.
    pub btf_state: i32,
    /// BTF bytes read, 0 unless present-and-read.
    pub btf_bytes: usize,
    /// config.gz evidence state.
    pub config_gz_state: i32,
    /// os-release ID.
    pub os_id: String,
    /// os-release VERSION_ID.
    pub os_version: String,
    /// Privilege-denied evidence paths.
    pub denied: Vec<String>,
}

/// Confidential-preflight lockdown fact: the kernel gate mode, surfaced.
///
/// Under `confidentiality` collection is impossible; the fact
/// reports that typed inability and the collector attempts no
/// alternative read to complete any other fact, never a bypass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightLockdown {
    /// `none`, `integrity`, `confidentiality`, or `unknown`.
    pub mode: String,
    /// `securityfs`, `cmdline`, `config`, or `none`.
    pub src: String,
}

impl Default for PreflightLockdown {
    fn default() -> Self {
        Self {
            mode: "unknown".to_string(),
            src: "none".to_string(),
        }
    }
}

/// Effective module-signature enforcement from three sources.
///
/// The sysfs parameter is runtime truth; kernel config
/// (`CONFIG_MODULE_SIG_FORCE`) and the `module.sig_enforce`
/// command-line token corroborate it. Any disagreement, or a
/// malformed runtime read, is `unknown`, never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightSigEnforce {
    /// `enforced`, `not_enforced`, or `unknown`.
    pub state: String,
    /// On-sources (`sysfs`, `config`, `cmdline`, `+`-joined)
    /// when enforced, observed off-sources when not enforced,
    /// else the unknown cause (`conflicting`, `malformed`,
    /// `denied`, `runtime_unobserved`), or `""` when nothing
    /// observed.
    pub reason: String,
}

impl Default for PreflightSigEnforce {
    fn default() -> Self {
        Self {
            state: "unknown".to_string(),
            reason: String::new(),
        }
    }
}

/// One 0/1/2 sysctl fact: module loading or kexec loading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightSysctl {
    /// `enabled`/`allowed`, `disabled`, or `unknown`.
    pub state: String,
    /// Observed level word (`0`, `1`, `2`), else `""`.
    pub level: String,
    /// `proc` when read, else `none`.
    pub src: String,
}

impl Default for PreflightSysctl {
    fn default() -> Self {
        Self {
            state: "unknown".to_string(),
            level: String::new(),
            src: "none".to_string(),
        }
    }
}

/// Hibernation state: runtime advertisement and build facts.
///
/// `runtime` reads the `/sys/power/state` advertisement only;
/// it never claims a hibernate transition would succeed.
/// `resume` records only whether a resume target is
/// configured; the target value is never read into a fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightHibernation {
    /// `available`, `unavailable`, or `unknown`.
    pub runtime: String,
    /// `platform`, `shutdown`, `reboot`, `suspend`,
    /// `test_resume`, or `unknown`.
    pub method: String,
    /// `yes`, `no`, or `unknown`.
    pub resume: String,
    /// `yes`, `no`, or `unknown`.
    pub compiled: String,
}

impl Default for PreflightHibernation {
    fn default() -> Self {
        Self {
            runtime: "unknown".to_string(),
            method: "unknown".to_string(),
            resume: "unknown".to_string(),
            compiled: "unknown".to_string(),
        }
    }
}

/// Kdump state: crash-image presence plus reservation context.
///
/// `image` is image presence only: it reveals nothing about
/// the second kernel's initramfs, filter, target, or whether
/// a dump ever completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightKdump {
    /// `loaded`, `not_loaded`, or `unknown`.
    pub image: String,
    /// Canonical decimal reservation bytes, else `""`.
    pub reservation: String,
}

impl Default for PreflightKdump {
    fn default() -> Self {
        Self {
            image: "unknown".to_string(),
            reservation: String::new(),
        }
    }
}

/// One swap source and its resolved backing verdict.
///
/// Labels are sanitized (`dev:` or `file:` plus an
/// allowlisted name, bare `mapper`, or `invalid`); raw paths,
/// mapper names, and dm uuids never reach a fact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightSwapBranch {
    /// Sanitized source label.
    pub source: String,
    /// Sanitized canonical device label, else `""`.
    pub device: String,
    /// `encrypted`, `no_encryption_observed`, `memory_only`,
    /// or `unknown`.
    pub verdict: String,
    /// Unknown cause, else `""`.
    pub reason: String,
}

/// Swap presence and backing protection, kept separate.
///
/// Presence answers whether swap is configured; backing
/// answers what the resolved guest-side topology reports.
/// Unknown or denied evidence never becomes an
/// encrypted/unencrypted assertion in either field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreflightSwap {
    /// `none`, `present`, or `unknown`.
    pub swap_presence: String,
    /// `enabled`, `disabled`, or `unknown`. A cache only:
    /// never hides the configured persistent backing.
    pub zswap: String,
    /// `kernel_reports_encrypted`,
    /// `no_guest_encryption_observed`, `unknown`, or `""`
    /// (null: no swap, or RAM-only zram without writeback).
    pub backing_protection: String,
    /// Null/unknown cause, else `""`.
    pub backing_reason: String,
    /// One entry per observed swap source, in file order.
    pub branches: Vec<PreflightSwapBranch>,
}

impl Default for PreflightSwap {
    fn default() -> Self {
        Self {
            swap_presence: "unknown".to_string(),
            zswap: "unknown".to_string(),
            backing_protection: String::new(),
            backing_reason: String::new(),
            branches: Vec::new(),
        }
    }
}

/// Bounded confidential-preflight facts for one evidence reader.
///
/// Every field degrades to an explicit unknown; the struct is
/// empty exactly when nothing was observed, and only then
/// does the doctor render its pre-preflight shape.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PreflightFacts {
    /// Lockdown mode, surfaced from the kernel gate.
    pub lockdown: PreflightLockdown,
    /// Effective module-signature enforcement.
    pub module_signature: PreflightSigEnforce,
    /// Module-loading sysctl.
    pub modules_disabled: PreflightSysctl,
    /// Kexec-loading sysctl.
    pub kexec: PreflightSysctl,
    /// Hibernation state.
    pub hibernation: PreflightHibernation,
    /// Kdump state.
    pub kdump: PreflightKdump,
    /// Swap presence and backing.
    pub swap: PreflightSwap,
}

impl PreflightFacts {
    /// True when no preflight fact was observed at all.
    ///
    /// Observed absence (`none` swap, `not_loaded` image) is
    /// knowledge and counts as non-empty; only the full
    /// unknown shape renders the legacy doctor document.
    pub fn is_empty(&self) -> bool {
        if self.lockdown.mode != "unknown" {
            return false;
        }
        if self.module_signature.state != "unknown" || !self.module_signature.reason.is_empty() {
            return false;
        }
        if self.modules_disabled.state != "unknown" || self.kexec.state != "unknown" {
            return false;
        }
        let h = &self.hibernation;
        if h.runtime != "unknown" || h.method != "unknown" || h.resume != "unknown" {
            return false;
        }
        if h.compiled != "unknown" {
            return false;
        }
        if self.kdump.image != "unknown" || !self.kdump.reservation.is_empty() {
            return false;
        }
        let s = &self.swap;
        if s.swap_presence != "unknown" || s.zswap != "unknown" {
            return false;
        }
        if !s.backing_protection.is_empty() || !s.backing_reason.is_empty() {
            return false;
        }
        if !s.branches.is_empty() {
            return false;
        }
        true
    }
}

/// Parse `major[.minor[.patch]]` from a release string.
///
/// Leading digits are the major (required); an optional dotted
/// minor and patch default to 0. Anything after the parsed triple
/// (`-34-generic`, `.0-...`) is ignored. No leading digits
/// means `ok` is false. Components are bounded; overflow makes
/// the release unparseable rather than wrapping.
pub fn parse_kernel_triple(release: &str) -> KernelTriple {
    let bad = KernelTriple {
        ok: false,
        major: 0,
        minor: 0,
        patch: 0,
    };
    let mut parts = Vec::new();
    let mut acc: i64 = 0;
    let mut have_digit = false;
    let mut failed = false;
    for &b in release.as_bytes() {
        if b.is_ascii_digit() {
            let digit = i64::from(b - b'0');
            if acc > (TRIPLE_BOUND - digit) / 10 {
                failed = true;
                break;
            }
            acc = acc * 10 + digit;
            have_digit = true;
        } else if b == 0x2E && parts.len() < 2 {
            if !have_digit {
                failed = true;
                break;
            }
            parts.push(acc);
            acc = 0;
            have_digit = false;
        } else {
            break;
        }
    }
    if failed || !have_digit {
        return bad;
    }
    parts.push(acc);
    let mut minor = 0;
    let mut patch = 0;
    if parts.len() > 1 {
        minor = parts[1];
    }
    if parts.len() > 2 {
        patch = parts[2];
    }
    KernelTriple {
        ok: true,
        major: parts[0],
        minor,
        patch,
    }
}

/// True when a parsed triple reaches `major.minor`.
pub fn triple_ge(t: &KernelTriple, major: i64, minor: i64) -> bool {
    if !t.ok {
        return false;
    }
    if t.major != major {
        return t.major > major;
    }
    t.minor >= minor
}

/// Check one release/arch pair against the 6.0 floor.
///
/// The program floor is the lowest kernel any capability
/// can serve (attempt-trace via its tracepoint); each
/// capability enforces its own higher floor where needed
/// (see `cap_floor_ok` in capabilities).
fn check_floor(release: &str, arch: &str) -> KernelInfo {
    let triple = parse_kernel_triple(release);
    if !triple.ok {
        return KernelInfo {
            release: release.to_string(),
            arch: arch.to_string(),
            eligible_floor: false,
            floor_reason: format!("release {release} is unparseable; floor unknown"),
        };
    }
    if triple_ge(&triple, 6, 0) {
        return KernelInfo {
            release: release.to_string(),
            arch: arch.to_string(),
            eligible_floor: true,
            floor_reason: format!("release {release} meets the 6.0 floor"),
        };
    }
    KernelInfo {
        release: release.to_string(),
        arch: arch.to_string(),
        eligible_floor: false,
        floor_reason: format!("release {release} is below the 6.0 floor"),
    }
}

/// Which corroborating tokens one cpuinfo scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FlagHits {
    sev: bool,
    snp: bool,
    tdx: bool,
    has_hypervisor: bool,
}

/// Scan cpuinfo `flags` lines for sev/sev_snp/tdx_guest.
///
/// Only lines starting with `flags` followed by blanks and a
/// colon are scanned; tokens split on blanks. Matches are whole
/// tokens only: `sev` never matches inside `sev_snp`. One
/// pass serves all four tokens.
fn scan_flags(view: &[u8]) -> FlagHits {
    let mut hit_sev = false;
    let mut hit_snp = false;
    let mut hit_tdx = false;
    let mut hit_hyp = false;
    let mut i = 0;
    let n = view.len();
    while i < n {
        let mut line_end = i;
        while line_end < n && view[line_end] != 0x0A {
            line_end += 1;
        }
        let mut is_flags = line_end - i >= 5;
        if is_flags {
            for (k, &want) in b"flags".iter().enumerate() {
                if view[i + k] != want {
                    is_flags = false;
                    break;
                }
            }
        }
        if is_flags {
            let mut j = i + 5;
            while j < line_end && (view[j] == 0x20 || view[j] == 0x09) {
                j += 1;
            }
            if j < line_end && view[j] == 0x3A {
                let mut t = j + 1;
                while t <= line_end {
                    let mut tend = t;
                    while tend < line_end && view[tend] != 0x20 && view[tend] != 0x09 {
                        tend += 1;
                    }
                    if tend > t {
                        let tok = &view[t..tend];
                        if tok == b"sev" {
                            hit_sev = true;
                        }
                        if tok == b"sev_snp" {
                            hit_snp = true;
                        }
                        if tok == b"tdx_guest" {
                            hit_tdx = true;
                        }
                        if tok == b"hypervisor" {
                            hit_hyp = true;
                        }
                    }
                    t = tend + 1;
                }
            }
        }
        i = line_end + 1;
    }
    FlagHits {
        sev: hit_sev,
        snp: hit_snp,
        tdx: hit_tdx,
        has_hypervisor: hit_hyp,
    }
}

/// ID and VERSION_ID read from os-release bytes.
struct OsVals {
    os_id: String,
    os_version: String,
}

/// Read `key=value` from one os-release line span.
///
/// Returns `None` unless the span starts with `key=`.
/// One pair of surrounding double quotes is stripped; values
/// keep raw bytes up to 64 of them; decoding is lossy downstream.
fn line_value(view: &[u8], start: usize, end: usize, key: &str) -> Option<String> {
    let kbytes = key.as_bytes();
    if end - start <= kbytes.len() {
        return None;
    }
    if view[start..start + kbytes.len()] != kbytes[..] {
        return None;
    }
    if view[start + kbytes.len()] != 0x3D {
        return None;
    }
    let mut vstart = start + kbytes.len() + 1;
    let mut vend = end;
    if vend - vstart >= 2 && view[vstart] == 0x22 && view[vend - 1] == 0x22 {
        vstart += 1;
        vend -= 1;
    }
    if vend - vstart > OS_VALUE_KEEP {
        vend = vstart + OS_VALUE_KEEP;
    }
    if vend > vstart && view[vend - 1] == 0x0D {
        vend -= 1;
    }
    Some(bytes_to_text(&view[vstart..vend]))
}

/// Read ID and VERSION_ID from os-release bytes.
///
/// The first `ID=` and `VERSION_ID=` lines win. Missing keys
/// read as "".
fn os_release_values(view: &[u8]) -> OsVals {
    let mut os_id = String::new();
    let mut os_version = String::new();
    let mut got_id = false;
    let mut got_ver = false;
    let mut i = 0;
    let n = view.len();
    while i < n {
        let mut line_end = i;
        while line_end < n && view[line_end] != 0x0A {
            line_end += 1;
        }
        if !got_id && let Some(hit) = line_value(view, i, line_end, "ID") {
            os_id = hit;
            got_id = true;
        }
        if !got_ver && let Some(hit) = line_value(view, i, line_end, "VERSION_ID") {
            os_version = hit;
            got_ver = true;
        }
        i = line_end + 1;
    }
    OsVals { os_id, os_version }
}

/// True when the release is safe to interpolate into a path.
///
/// Live uname releases always pass. A fixture release holding
/// `/` or `..` would escape the fixture root, so the boot
/// config probe is skipped for it instead.
fn release_path_safe(release: &str) -> bool {
    let mut prev_dot = false;
    for &b in release.as_bytes() {
        if b == 0x2F {
            return false;
        }
        if b == 0x2E && prev_dot {
            return false;
        }
        prev_dot = b == 0x2E;
    }
    true
}

/// True for ASCII whitespace around the vmpl level.
fn is_vmpl_space(b: u8) -> bool {
    b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D
}

/// One vmpl evidence signal, or `""` when absent.
///
/// The kernel prints one decimal level plus a newline; the
/// trimmed content must be exactly `0`..`3` within 8
/// bytes, else `sev-vmpl:malformed`. Denied stays
/// explicit; a read error is malformed, never absent.
fn vmpl_signal(reader: &EvidenceReader) -> String {
    let st = file_state(reader, P_SEV_VMPL);
    if st == EVIDENCE_ABSENT {
        return String::new();
    }
    if st == EVIDENCE_DENIED {
        return "sev-vmpl:denied".to_string();
    }
    let raw = match read_evidence(reader, P_SEV_VMPL, VMPL_CAP) {
        Ok(raw) => raw,
        Err(_) => return "sev-vmpl:malformed".to_string(),
    };
    if raw.is_empty() || raw.len() > 8 {
        return "sev-vmpl:malformed".to_string();
    }
    let mut lo = 0;
    let mut hi = raw.len();
    while lo < hi && is_vmpl_space(raw[lo]) {
        lo += 1;
    }
    while hi > lo && is_vmpl_space(raw[hi - 1]) {
        hi -= 1;
    }
    if hi - lo != 1 {
        return "sev-vmpl:malformed".to_string();
    }
    match raw[lo] {
        48 => "sev-vmpl:0".to_string(),
        49 => "sev-vmpl:1".to_string(),
        50 => "sev-vmpl:2".to_string(),
        51 => "sev-vmpl:3".to_string(),
        _ => "sev-vmpl:malformed".to_string(),
    }
}

/// True for a `sev-vmpl:<n>` level signal.
fn vmpl_is_level(sig: &str) -> bool {
    sig.starts_with("sev-vmpl:") && sig.len() == 10
}

/// Decide the guest technology from nodes, flags, and assertion.
///
/// Never fails: every unreadable input becomes an explicit
/// unknown or conflict outcome. Denied paths are re-derived from
/// the verdict signals by the caller.
fn detect_guest(reader: &EvidenceReader) -> GuestInfo {
    let mut signals = Vec::new();
    let asserted = reader.asserted_guest_tech.clone();
    let sev = file_state(reader, P_SEV_NODE);
    let tdx = file_state(reader, P_TDX_NODE);
    if sev == EVIDENCE_OK {
        signals.push("sev-node:present".to_string());
    } else if sev == EVIDENCE_DENIED {
        signals.push("sev-node:denied".to_string());
    } else {
        signals.push("sev-node:absent".to_string());
    }
    if tdx == EVIDENCE_OK {
        signals.push("tdx-node:present".to_string());
    } else if tdx == EVIDENCE_DENIED {
        signals.push("tdx-node:denied".to_string());
    } else {
        signals.push("tdx-node:absent".to_string());
    }
    let tsm = file_state(reader, P_TSM_REPORT);
    if tsm != EVIDENCE_ABSENT {
        signals.push("tsm:present".to_string());
    }
    let vmpl_sig = vmpl_signal(reader);
    let cpu = file_state(reader, P_CPUINFO);
    let mut flags_ok = false;
    let mut has_sev = false;
    let mut has_snp = false;
    let mut has_tdx = false;
    let mut has_hypervisor = false;
    if cpu == EVIDENCE_DENIED {
        signals.push("cpu-flags:denied".to_string());
    } else if cpu == EVIDENCE_ABSENT {
        signals.push("cpu-flags:absent".to_string());
    } else {
        match read_evidence(reader, P_CPUINFO, CPUINFO_CAP) {
            Ok(data) => {
                let hits = scan_flags(&data);
                has_sev = hits.sev;
                has_snp = hits.snp;
                has_tdx = hits.tdx;
                has_hypervisor = hits.has_hypervisor;
                flags_ok = true;
                let mut summary = "cpu-flags:ok:".to_string();
                let mut first = true;
                if has_sev {
                    summary += "sev";
                    first = false;
                }
                if has_snp {
                    if !first {
                        summary += "+";
                    }
                    summary += "sev_snp";
                    first = false;
                }
                if has_tdx {
                    if !first {
                        summary += "+";
                    }
                    summary += "tdx_guest";
                    first = false;
                }
                if first {
                    summary += "none";
                }
                signals.push(summary);
            }
            Err(_) => signals.push("cpu-flags:read-error".to_string()),
        }
    }
    let mut tech = "unknown".to_string();
    let mut conflict = String::new();
    if sev == EVIDENCE_OK && tdx == EVIDENCE_OK {
        conflict = "sev-guest and tdx-guest nodes both present".to_string();
    } else if sev == EVIDENCE_DENIED || tdx == EVIDENCE_DENIED {
        conflict = String::new();
    } else if sev == EVIDENCE_OK {
        if !flags_ok {
            conflict = String::new();
        } else if has_tdx {
            conflict = "sev-guest node present with tdx_guest cpu flag".to_string();
        } else if has_snp {
            tech = "snp".to_string();
        } else if has_sev {
            tech = "sev-classic".to_string();
        } else if vmpl_is_level(&vmpl_sig) {
            tech = "snp".to_string();
            signals.push(vmpl_sig.clone());
        } else {
            conflict = "sev-guest node present but cpu flags lack sev".to_string();
            if !vmpl_sig.is_empty() {
                signals.push(vmpl_sig.clone());
            }
        }
    } else if tdx == EVIDENCE_OK {
        if !flags_ok {
            conflict = String::new();
        } else if has_sev || has_snp {
            conflict = "tdx-guest node present with sev cpu flags".to_string();
        } else if has_tdx {
            tech = "tdx".to_string();
        } else {
            conflict = "tdx-guest node present but cpu flags lack tdx_guest".to_string();
        }
    } else if !vmpl_sig.is_empty() {
        tech = "unknown".to_string();
        conflict = "sev vmpl node present without sev-guest node:\
             \u{20}SNP guest with attestation device absent"
            .to_string();
        signals.push(vmpl_sig.clone());
    } else if flags_ok {
        if has_hypervisor && has_snp {
            tech = "unknown".to_string();
            conflict = "cpu flag sev_snp without guest node:\
                 \u{20}confidential guest with attestation device\
                 \u{20}absent, or flags spoofed"
                .to_string();
            signals.push("cc-flags:without-node:sev_snp".to_string());
        } else if has_hypervisor && has_tdx {
            tech = "unknown".to_string();
            conflict = "cpu flag tdx_guest without guest node:\
                 \u{20}confidential guest with attestation device\
                 \u{20}absent, or flags spoofed"
                .to_string();
            signals.push("cc-flags:without-node:tdx_guest".to_string());
        } else {
            tech = "ordinary".to_string();
            signals.push("ordinary:absent-nodes-inference".to_string());
        }
    }
    let mut used_assertion = false;
    if !asserted.is_empty() {
        signals.push(format!("asserted:{asserted}"));
        if conflict.is_empty() && (tech == "unknown" || tech == asserted) {
            tech = asserted.clone();
            used_assertion = true;
        } else if conflict.is_empty() {
            conflict = format!("evidence says {tech}, asserted {asserted}");
            tech = "unknown".to_string();
            used_assertion = true;
        } else {
            conflict = format!("{conflict}; asserted {asserted} unresolved");
            used_assertion = true;
        }
    }
    GuestInfo {
        tech,
        signals,
        asserted: used_assertion,
        conflict,
    }
}

/// Gather all profile-independent doctor evidence. Never fails.
pub fn detect_environment(reader: &EvidenceReader) -> EnvironmentEvidence {
    let kernel = check_floor(&reader.release, &reader.arch);
    let mut guest = detect_guest(reader);
    let mut denied = Vec::new();
    for s in &guest.signals {
        if s == "sev-node:denied" {
            denied.push(P_SEV_NODE.to_string());
        } else if s == "tdx-node:denied" {
            denied.push(P_TDX_NODE.to_string());
        } else if s == "cpu-flags:denied" {
            denied.push(P_CPUINFO.to_string());
        }
    }
    let mut info = Vec::new();
    let btf = file_state(reader, P_BTF);
    let mut btf_bytes = 0;
    if btf == EVIDENCE_OK {
        match read_evidence(reader, P_BTF, BTF_CAP) {
            Ok(data) => {
                btf_bytes = data.len();
                info.push(format!("info:btf:present:{btf_bytes}B"));
            }
            Err(_) => info.push("info:btf:read-error".to_string()),
        }
    } else if btf == EVIDENCE_DENIED {
        info.push("info:btf:denied".to_string());
        denied.push(P_BTF.to_string());
    } else {
        info.push("info:btf:absent".to_string());
    }
    let cfg = file_state(reader, P_CONFIG_GZ);
    if cfg == EVIDENCE_OK {
        info.push("info:config-gz:present".to_string());
    } else if cfg == EVIDENCE_DENIED {
        info.push("info:config-gz:denied".to_string());
        denied.push(P_CONFIG_GZ.to_string());
    } else {
        info.push("info:config-gz:absent".to_string());
    }
    let mut os_id = String::new();
    let mut os_version = String::new();
    let osst = file_state(reader, P_OS_RELEASE);
    if osst == EVIDENCE_OK {
        match read_evidence(reader, P_OS_RELEASE, OS_RELEASE_CAP) {
            Ok(osdata) => {
                let vals = os_release_values(&osdata);
                os_id = vals.os_id;
                os_version = vals.os_version;
                info.push(format!("info:os:{os_id}:{os_version}"));
            }
            Err(_) => info.push("info:os:read-error".to_string()),
        }
    } else if osst == EVIDENCE_DENIED {
        info.push("info:os:denied".to_string());
        denied.push(P_OS_RELEASE.to_string());
    } else {
        info.push("info:os:absent".to_string());
    }
    if release_path_safe(&reader.release) {
        let boot = format!("{}{}", P_BOOT_CONFIG_PREFIX, reader.release);
        let bst = file_state(reader, &boot);
        if bst == EVIDENCE_OK {
            info.push("info:boot-config:present".to_string());
        } else if bst == EVIDENCE_DENIED {
            info.push("info:boot-config:denied".to_string());
            denied.push(boot);
        } else {
            info.push("info:boot-config:absent".to_string());
        }
    } else {
        info.push("info:boot-config:skipped-unsafe-release".to_string());
    }
    let mut merged = Vec::new();
    for s in guest.signals {
        merged.push(s);
    }
    for s in info {
        merged.push(s);
    }
    guest.signals = merged;
    EnvironmentEvidence {
        kernel,
        guest,
        btf_state: btf,
        btf_bytes,
        config_gz_state: cfg,
        os_id,
        os_version,
        denied,
    }
}

#[cfg(test)]
mod tests {
    use super::{detect_environment, evidence_btf_cap, parse_kernel_triple};
    use crate::platform::reader::{EVIDENCE_ABSENT, EVIDENCE_OK, open_evidence_reader};
    use crate::platform::test_support::{capabilities_fixture, gate_fixture};

    fn fx(name: &str) -> String {
        capabilities_fixture(name)
    }

    fn gate(name: &str) -> String {
        gate_fixture(name)
    }

    fn has_signal(signals: &[String], want: &str) -> bool {
        signals.iter().any(|s| s == want)
    }

    #[test]
    fn triple_parse() {
        let t = parse_kernel_triple("7.0.0-34-generic");
        assert!(t.ok);
        assert_eq!(t.major, 7);
        assert_eq!(t.minor, 0);
        assert_eq!(t.patch, 0);
        let u = parse_kernel_triple("6.8.0");
        assert!(u.ok && u.major == 6 && u.minor == 8 && u.patch == 0);
        let v = parse_kernel_triple("7");
        assert!(v.ok && v.major == 7 && v.minor == 0 && v.patch == 0);
        let w = parse_kernel_triple("8.1");
        assert!(w.ok && w.major == 8 && w.minor == 1);
        assert!(!parse_kernel_triple("nope").ok);
        assert!(!parse_kernel_triple("").ok);
        assert!(!parse_kernel_triple("7.").ok);
        assert!(!parse_kernel_triple(".7").ok);
        let x = parse_kernel_triple("7.0.0.0");
        assert!(x.ok && x.major == 7 && x.minor == 0 && x.patch == 0);
        assert!(!parse_kernel_triple("123456789012345678901234567890").ok);
    }

    #[test]
    fn floor_pass() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 7.0.0-34-generic meets the 6.0 floor"
        );
    }

    #[test]
    fn floor_68_pass() {
        let r = open_evidence_reader(&fx("kernel-6.8")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 6.8.0-41-generic meets the 6.0 floor"
        );
    }

    #[test]
    fn floor_515_fail() {
        let r = open_evidence_reader(&fx("kernel-5.15")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(!env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 5.15.0-test is below the 6.0 floor"
        );
    }

    #[test]
    fn floor_unparseable() {
        let r = open_evidence_reader(&fx("malformed-release")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(!env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release not-a-kernel-release is unparseable; floor unknown"
        );
    }

    #[test]
    fn floor_exact_60_pass() {
        let r = open_evidence_reader(&fx("kernel-6.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 6.0.19-060019-generic meets the 6.0 floor"
        );
    }

    #[test]
    fn floor_611_pass() {
        let r = open_evidence_reader(&fx("kernel-6.11")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 6.11.11-061111-generic meets the 6.0 floor"
        );
    }

    #[test]
    fn floor_73_pass() {
        let r = open_evidence_reader(&fx("kernel-7.3")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert_eq!(
            env.kernel.floor_reason,
            "release 7.3.0-mv-7.3 meets the 6.0 floor"
        );
    }

    #[test]
    fn guest_ordinary() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "ordinary");
        assert!(!env.guest.asserted);
        assert_eq!(env.guest.conflict, "");
        assert_eq!(env.guest.signals.len(), 8);
        assert_eq!(env.guest.signals[0], "sev-node:absent");
        assert_eq!(env.guest.signals[1], "tdx-node:absent");
        assert_eq!(env.guest.signals[2], "cpu-flags:ok:none");
        assert_eq!(env.guest.signals[3], "ordinary:absent-nodes-inference");
        assert_eq!(env.guest.signals[4], "info:btf:present:24B");
        assert_eq!(env.guest.signals[5], "info:config-gz:absent");
        assert_eq!(env.guest.signals[6], "info:os:ubuntu:24.04");
        assert_eq!(env.guest.signals[7], "info:boot-config:absent");
    }

    #[test]
    fn guest_snp() {
        let r = open_evidence_reader(&fx("snp-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "snp");
        assert!(!env.guest.asserted);
        assert!(has_signal(&env.guest.signals, "sev-node:present"));
        assert!(has_signal(&env.guest.signals, "cpu-flags:ok:sev+sev_snp"));
    }

    #[test]
    fn guest_tdx() {
        let r = open_evidence_reader(&fx("tdx-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "tdx");
        assert!(has_signal(&env.guest.signals, "cpu-flags:ok:tdx_guest"));
    }

    #[test]
    fn guest_sev_classic() {
        let r = open_evidence_reader(&fx("sev-classic-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "sev-classic");
        assert!(has_signal(&env.guest.signals, "cpu-flags:ok:sev"));
    }

    #[test]
    fn guest_unavailable() {
        let r = open_evidence_reader(&fx("unavailable-evidence")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(env.guest.conflict, "");
        assert!(has_signal(&env.guest.signals, "cpu-flags:absent"));
    }

    #[test]
    fn guest_conflict_nodes() {
        let r = open_evidence_reader(&fx("conflicting-evidence")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(
            env.guest.conflict,
            "sev-guest and tdx-guest nodes both present"
        );
    }

    #[test]
    fn guest_conflict_flags() {
        let r = open_evidence_reader(&fx("conflicting-flags")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(
            env.guest.conflict,
            "sev-guest node present but cpu flags lack sev"
        );
    }

    #[test]
    fn guest_conflict_mixed_sev() {
        let r = open_evidence_reader(&fx("conflicting-flags-sev-tdx")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(
            env.guest.conflict,
            "sev-guest node present with tdx_guest cpu flag"
        );
    }

    #[test]
    fn guest_conflict_mixed_tdx() {
        let r = open_evidence_reader(&fx("conflicting-flags-tdx-sev")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(
            env.guest.conflict,
            "tdx-guest node present with sev cpu flags"
        );
    }

    #[test]
    fn asserted_tiebreak() {
        let r = open_evidence_reader(&fx("user-asserted-snp")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "snp");
        assert!(env.guest.asserted);
        assert!(has_signal(&env.guest.signals, "asserted:snp"));
    }

    #[test]
    fn asserted_agree() {
        let r = open_evidence_reader(&fx("user-asserted-agree")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "snp");
        assert!(env.guest.asserted);
        assert_eq!(env.guest.conflict, "");
    }

    #[test]
    fn asserted_conflict() {
        let r = open_evidence_reader(&fx("user-asserted-conflict")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert!(env.guest.asserted);
        assert_eq!(env.guest.conflict, "evidence says snp, asserted tdx");
    }

    #[test]
    fn denied_guest_node() {
        let r = open_evidence_reader(&fx("denied-guest-node")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.guest.tech, "unknown");
        assert_eq!(env.denied.len(), 1);
        assert_eq!(env.denied[0], "/dev/sev-guest");
        assert!(has_signal(&env.guest.signals, "sev-node:denied"));
    }

    #[test]
    fn btf_states() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        let env = detect_environment(&r);
        assert_eq!(env.btf_state, EVIDENCE_OK);
        assert_eq!(env.btf_bytes, 24);
        let m = open_evidence_reader(&fx("missing-btf")).expect("fixture opens");
        let menv = detect_environment(&m);
        assert_eq!(menv.btf_state, EVIDENCE_ABSENT);
        assert!(has_signal(&menv.guest.signals, "info:btf:absent"));
    }

    #[test]
    fn hostile_release() {
        let r = open_evidence_reader(&fx("meta-release-hostile")).expect("fixture opens");
        let env = detect_environment(&r);
        assert!(env.kernel.eligible_floor);
        assert!(has_signal(
            &env.guest.signals,
            "info:boot-config:skipped-unsafe-release"
        ));
    }

    #[test]
    fn cc_flags_without_node() {
        let snp = detect_environment(
            &open_evidence_reader(&gate("cc-flags-nonode")).expect("fixture opens"),
        );
        assert_eq!(snp.guest.tech, "unknown");
        assert_eq!(
            snp.guest.conflict,
            "cpu flag sev_snp without guest node: confidential guest\
             \u{20}with attestation device absent, or flags spoofed"
        );
        assert!(has_signal(
            &snp.guest.signals,
            "cc-flags:without-node:sev_snp"
        ));
        let tdx = detect_environment(
            &open_evidence_reader(&gate("cc-tdx-nonode")).expect("fixture opens"),
        );
        assert_eq!(tdx.guest.tech, "unknown");
        assert_eq!(
            tdx.guest.conflict,
            "cpu flag tdx_guest without guest node: confidential guest\
             \u{20}with attestation device absent, or flags spoofed"
        );
        let host = detect_environment(
            &open_evidence_reader(&gate("cc-flags-host")).expect("fixture opens"),
        );
        assert_eq!(host.guest.tech, "ordinary");
        assert_eq!(host.guest.conflict, "");
        let tsm =
            detect_environment(&open_evidence_reader(&gate("cc-tsm")).expect("fixture opens"));
        assert!(has_signal(&tsm.guest.signals, "tsm:present"));
    }

    #[test]
    fn cc_sev_vmpl_affirms_snp() {
        let vmpl =
            detect_environment(&open_evidence_reader(&gate("cc-snp-vmpl")).expect("fixture opens"));
        assert_eq!(vmpl.guest.tech, "snp");
        assert_eq!(vmpl.guest.conflict, "");
        assert!(has_signal(&vmpl.guest.signals, "sev-vmpl:0"));
        let tdx = detect_environment(
            &open_evidence_reader(&gate("cc-snp-vmpl-tdx")).expect("fixture opens"),
        );
        assert_eq!(tdx.guest.tech, "unknown");
        assert_eq!(
            tdx.guest.conflict,
            "sev-guest node present with tdx_guest cpu flag"
        );
        let bad = detect_environment(
            &open_evidence_reader(&gate("cc-snp-vmpl-bad")).expect("fixture opens"),
        );
        assert_eq!(bad.guest.tech, "unknown");
        assert_eq!(
            bad.guest.conflict,
            "sev-guest node present but cpu flags lack sev"
        );
        assert!(has_signal(&bad.guest.signals, "sev-vmpl:malformed"));
        let nonode = detect_environment(
            &open_evidence_reader(&gate("cc-vmpl-nonode")).expect("fixture opens"),
        );
        assert_eq!(nonode.guest.tech, "unknown");
        assert_eq!(
            nonode.guest.conflict,
            "sev vmpl node present without sev-guest node:\
             \u{20}SNP guest with attestation device absent"
        );
        assert!(has_signal(&nonode.guest.signals, "sev-vmpl:0"));
        let denied = detect_environment(
            &open_evidence_reader(&gate("cc-vmpl-denied-nonode")).expect("fixture opens"),
        );
        assert_eq!(denied.guest.tech, "unknown");
        assert_eq!(
            denied.guest.conflict,
            "sev vmpl node present without sev-guest node:\
             \u{20}SNP guest with attestation device absent"
        );
        assert!(has_signal(&denied.guest.signals, "sev-vmpl:denied"));
    }

    #[test]
    fn btf_cap_is_shared() {
        assert_eq!(evidence_btf_cap(), 67_108_864);
    }

    #[test]
    fn preflight_empty_shape() {
        use super::PreflightFacts;
        assert!(PreflightFacts::default().is_empty());
        let mut facts = PreflightFacts::default();
        facts.lockdown.mode = "none".to_string();
        assert!(!facts.is_empty());
        let mut facts = PreflightFacts::default();
        facts.swap.swap_presence = "none".to_string();
        facts.swap.backing_reason = "not_applicable".to_string();
        assert!(!facts.is_empty());
        let mut facts = PreflightFacts::default();
        facts.kdump.reservation = "0".to_string();
        assert!(!facts.is_empty());
        let mut facts = PreflightFacts::default();
        facts.module_signature.reason = "denied".to_string();
        assert!(!facts.is_empty());
    }
}
