// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded confidential-preflight facts: typed reads, never a scanner.
//!
//! [`collect_preflight`] gathers the doctor's preflight facts from
//! one evidence reader: lockdown mode (surfaced from the kernel
//! gate), effective module-signature enforcement, the module and
//! kexec sysctls, hibernation and kdump state, and swap presence
//! with backing protection. Every fact degrades to an explicit
//! unknown; unknown or denied evidence never becomes an
//! encrypted/unencrypted assertion.
//!
//! All direct reads go through the reader's preflight allowlist
//! ([`read_preflight`], [`preflight_state`],
//! [`list_preflight_dir`]); kernel config arrives through the
//! shared narrow helper and lockdown through the kernel gate.
//! The walk is read-then-classify throughout: a probe that says
//! OK never excuses a failed read, a vanishing node resolves to
//! unresolved (never to a verdict), and every traversal carries
//! an explicit cap past which the branch reports truncated.
//! Presence (`swap_presence`) and protection
//! (`backing_protection`) stay separate fields: the positive
//! backing value needs every persistent branch to report its
//! encryption layer, the resolved-negative value needs every
//! branch resolved with none observed, and mixed, denied,
//! unresolved, unsupported, or unproved branches keep the
//! aggregate unknown while retaining each branch's fact.

use super::evidence::{
    PreflightFacts, PreflightHibernation, PreflightKdump, PreflightSigEnforce, PreflightSwap,
    PreflightSwapBranch, PreflightSysctl,
};
use super::kernelgate::LockdownState;
use super::narrow::{ConfigText, read_live_config_text};
use super::reader::{
    E_ABSENT, E_DENIED, E_TOO_BIG, EVIDENCE_DENIED, EVIDENCE_OK, EvidenceReader, bytes_to_text,
    is_valid_utf8, list_preflight_dir, preflight_device_segment, preflight_state, read_preflight,
};

/// Sysfs single-word read cap.
const WORD_CAP: usize = 4096;
/// `/proc/swaps` read cap.
const SWAPS_CAP: usize = 65536;
/// `/proc/cmdline` read cap (matches the kernel gate).
const CMDLINE_CAP: usize = 65536;
/// `/sys/power/state` read cap.
const POWER_CAP: usize = 4096;
/// dm uuid/name read cap.
const DM_ID_CAP: usize = 256;
/// zram `backing_dev` read cap.
const BACKING_CAP: usize = 4096;
/// Longest command-line scan: past this the whole line is unobserved.
const MAX_CMDLINE_TOKENS: usize = 4096;
/// Most `/proc/swaps` entries resolved; more append one truncation branch.
const MAX_SWAP_BRANCHES: usize = 64;
/// Longest single `/proc/swaps` line parsed.
const MAX_SWAP_LINE: usize = 512;
/// Longest swap source path parsed.
const MAX_SOURCE_LEN: usize = 256;
/// Most `/sys/block` entries scanned for a partition parent.
const MAX_BLOCK_ENTRIES: usize = 4096;
/// Most slaves listed per node; more fail the branch truncated.
const MAX_SLAVES: usize = 64;
/// Deepest topology walk per branch; deeper fails truncated.
const MAX_WALK_DEPTH: usize = 8;
/// Most nodes walked per branch; more fail truncated.
const MAX_WALK_NODES: usize = 64;
/// Highest dm index probed for a `/dev/mapper` name.
const MAX_DM_INDEX: usize = 512;

/// One allowlisted word read: the word, or the failure class.
///
/// `Broken` covers read errors and malformed content alike:
/// both are unparseable, and both fail their fact closed.
enum WordRead {
    Word(String),
    Absent,
    Denied,
    Truncated,
    Broken,
}

/// Trimmed single word of sysfs-style bytes, or `None`.
///
/// ASCII whitespace trims off both ends; anything left must be
/// one valid-UTF-8 token with no interior blank or NUL.
/// Raw values never escape: callers match exact words only.
fn word_of(raw: &[u8]) -> Option<String> {
    let mut lo = 0;
    let mut hi = raw.len();
    while lo < hi && raw[lo].is_ascii_whitespace() {
        lo += 1;
    }
    while hi > lo && raw[hi - 1].is_ascii_whitespace() {
        hi -= 1;
    }
    if lo >= hi {
        return None;
    }
    let word = &raw[lo..hi];
    if !is_valid_utf8(word) {
        return None;
    }
    for &b in word {
        if b.is_ascii_whitespace() || b == 0 {
            return None;
        }
    }
    Some(bytes_to_text(word))
}

/// Read one allowlisted word file with its failure class.
fn read_word(reader: &EvidenceReader, path: &str, cap: usize) -> WordRead {
    match read_preflight(reader, path, cap) {
        Ok(raw) => match word_of(&raw) {
            Some(word) => WordRead::Word(word),
            None => WordRead::Broken,
        },
        Err(e) => match e.code {
            E_ABSENT => WordRead::Absent,
            E_DENIED => WordRead::Denied,
            E_TOO_BIG => WordRead::Truncated,
            _ => WordRead::Broken,
        },
    }
}

/// Failure reason for one failed topology read.
fn read_failure_reason(code: u32) -> String {
    match code {
        E_DENIED => "denied",
        E_TOO_BIG => "truncated",
        _ => "unresolved",
    }
    .to_string()
}

/// True for a `/proc/cmdline` separator: ASCII blanks and NUL.
fn is_cmd_sep(b: u8) -> bool {
    b == b' ' || b == b'\t' || b == b'\n' || b == b'\r' || b == 0
}

/// Tokenize command-line bytes, stopping at `--`.
///
/// Returns `None` past the token cap: a line too long to scan
/// is unobserved, never partially judged.
fn cmdline_tokens(raw: &[u8]) -> Option<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut i = 0;
    let n = raw.len();
    while i < n {
        while i < n && is_cmd_sep(raw[i]) {
            i += 1;
        }
        if i >= n {
            break;
        }
        let mut j = i;
        while j < n && !is_cmd_sep(raw[j]) {
            j += 1;
        }
        let tok = &raw[i..j];
        if tok == b"--" {
            break;
        }
        if out.len() + 1 > MAX_CMDLINE_TOKENS {
            return None;
        }
        out.push(tok);
        i = j;
    }
    Some(out)
}

/// One boolean word vote: 1 on, 0 off, -1 no signal.
fn cmd_bool_value(val: &[u8]) -> i32 {
    if val == b"1"
        || val == b"y"
        || val == b"Y"
        || val == b"t"
        || val == b"T"
        || val == b"yes"
        || val == b"Yes"
        || val == b"YES"
        || val == b"true"
        || val == b"True"
        || val == b"TRUE"
        || val == b"on"
        || val == b"On"
        || val == b"ON"
    {
        return 1;
    }
    if val == b"0"
        || val == b"n"
        || val == b"N"
        || val == b"f"
        || val == b"F"
        || val == b"no"
        || val == b"No"
        || val == b"NO"
        || val == b"false"
        || val == b"False"
        || val == b"FALSE"
        || val == b"off"
        || val == b"Off"
        || val == b"OFF"
    {
        return 0;
    }
    -1
}

/// Last `module.sig_enforce=` vote on the command line.
///
/// Later tokens win, matching kernel parsing; bare or
/// malformed values cast no vote.
fn cmdline_sig_vote(tokens: &[&[u8]]) -> i32 {
    let mut vote = -1;
    for tok in tokens {
        let prefix = b"module.sig_enforce=";
        if tok.len() <= prefix.len() || &tok[..prefix.len()] != prefix {
            continue;
        }
        let val = &tok[prefix.len()..];
        let v = cmd_bool_value(val);
        if v >= 0 {
            vote = v;
        }
    }
    vote
}

/// True when any pre-`--` token configures a resume target.
///
/// Only presence is judged; the target value is never read
/// into a fact.
fn cmdline_has_resume(tokens: &[&[u8]]) -> bool {
    let prefix = b"resume=";
    tokens
        .iter()
        .any(|t| t.len() > prefix.len() && &t[..prefix.len()] == prefix)
}

/// Config-file vote for one symbol: 1 forced on, 0 not set, -1 no signal.
fn config_vote(text: &str, symbol: &str) -> i32 {
    let on = format!("{symbol}=y");
    let off = format!("# {symbol} is not set");
    let mut seen_off = false;
    for line in text.split('\n') {
        if line == on {
            return 1;
        }
        if line == off {
            seen_off = true;
        }
    }
    if seen_off { 0 } else { -1 }
}

/// Signature-enforcement votes: 1 on, 0 off, -1 unobserved.
struct SigVotes {
    sys: i32,
    sys_malformed: bool,
    sys_denied: bool,
    cfg: i32,
    cfg_denied: bool,
    cmd: i32,
    cmd_denied: bool,
}

/// Combine the three enforcement sources.
///
/// The sysfs parameter is runtime truth: an on-runtime with an
/// explicit off command line, or an off-runtime against a
/// config force or an on command line, is conflicting. A
/// malformed runtime read fails closed regardless of the other
/// votes. Without the runtime read, a config force or an on
/// command line enforces (a force is not vetoed by an off
/// command line); any other observed vote leaves enforcement
/// off; nothing observed is unknown, denied when any source
/// refused.
fn combine_sig(v: &SigVotes) -> PreflightSigEnforce {
    let mut out = PreflightSigEnforce::default();
    if v.sys_malformed {
        out.reason = "malformed".to_string();
        return out;
    }
    if v.sys == 1 {
        if v.cmd == 0 {
            out.reason = "conflicting".to_string();
            return out;
        }
        out.state = "enforced".to_string();
        out.reason = on_voters(true, v.cfg == 1, v.cmd == 1);
        return out;
    }
    if v.sys == 0 {
        if v.cfg == 1 || v.cmd == 1 {
            out.reason = "conflicting".to_string();
            return out;
        }
        out.state = "not_enforced".to_string();
        out.reason = off_voters(true, v.cfg == 0, v.cmd == 0);
        return out;
    }
    if v.cfg == 1 || v.cmd == 1 {
        out.state = "enforced".to_string();
        out.reason = on_voters(false, v.cfg == 1, v.cmd == 1);
        return out;
    }
    if v.cfg != -1 || v.cmd != -1 {
        out.state = "not_enforced".to_string();
        out.reason = off_voters(false, v.cfg == 0, v.cmd == 0);
        return out;
    }
    if v.sys_denied || v.cfg_denied || v.cmd_denied {
        out.reason = "denied".to_string();
    }
    out
}

/// `+`-joined on-voters in sysfs/config/cmdline order.
fn on_voters(sys: bool, cfg: bool, cmd: bool) -> String {
    let mut parts = Vec::new();
    if sys {
        parts.push("sysfs");
    }
    if cfg {
        parts.push("config");
    }
    if cmd {
        parts.push("cmdline");
    }
    parts.join("+")
}

/// `+`-joined observed off-voters in sysfs/config/cmdline order.
fn off_voters(sys: bool, cfg: bool, cmd: bool) -> String {
    let mut parts = Vec::new();
    if sys {
        parts.push("sysfs");
    }
    if cfg {
        parts.push("config");
    }
    if cmd {
        parts.push("cmdline");
    }
    parts.join("+")
}

/// Collect effective module-signature enforcement.
fn collect_sig(
    reader: &EvidenceReader,
    config: &ConfigText,
    tokens: Option<&[&[u8]]>,
    cmd_denied: bool,
) -> PreflightSigEnforce {
    let mut votes = SigVotes {
        sys: -1,
        sys_malformed: false,
        sys_denied: false,
        cfg: -1,
        cfg_denied: false,
        cmd: -1,
        cmd_denied,
    };
    match read_word(
        reader,
        "/sys/module/module/parameters/sig_enforce",
        WORD_CAP,
    ) {
        WordRead::Word(w) => {
            if matches!(w.as_str(), "Y" | "y" | "1") {
                votes.sys = 1;
            } else if matches!(w.as_str(), "N" | "n" | "0") {
                votes.sys = 0;
            } else {
                votes.sys_malformed = true;
            }
        }
        WordRead::Denied => votes.sys_denied = true,
        WordRead::Broken | WordRead::Truncated => votes.sys_malformed = true,
        WordRead::Absent => {}
    }
    if config.state == "text" {
        votes.cfg = config_vote(&config.text, "CONFIG_MODULE_SIG_FORCE");
    } else if config.state == "denied" {
        votes.cfg_denied = true;
    }
    if let Some(tokens) = tokens {
        votes.cmd = cmdline_sig_vote(tokens);
    }
    combine_sig(&votes)
}

/// Collect one 0/1/2 sysctl: 0 opens, 1 and 2 close.
fn collect_sysctl(reader: &EvidenceReader, path: &str, open_word: &str) -> PreflightSysctl {
    let mut out = PreflightSysctl::default();
    if let WordRead::Word(w) = read_word(reader, path, WORD_CAP) {
        if w == "0" {
            out.state = open_word.to_string();
            out.level = w;
            out.src = "proc".to_string();
        } else if w == "1" || w == "2" {
            out.state = "disabled".to_string();
            out.level = w;
            out.src = "proc".to_string();
        }
    }
    out
}

/// First `[token]` hibernation method of one `/sys/power/disk` body.
///
/// Only the kernel's fixed method words qualify; anything
/// else is unknown and never echoed.
fn disk_method(raw: &[u8]) -> Option<String> {
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'[' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        while j < raw.len() && raw[j] != b']' {
            j += 1;
        }
        if j >= raw.len() {
            return None;
        }
        return match &raw[i + 1..j] {
            b"platform" => Some("platform".to_string()),
            b"shutdown" => Some("shutdown".to_string()),
            b"reboot" => Some("reboot".to_string()),
            b"suspend" => Some("suspend".to_string()),
            b"test_resume" => Some("test_resume".to_string()),
            _ => None,
        };
    }
    None
}

/// Collect hibernation state: advertisement, method, resume target, build.
fn collect_hibernation(
    reader: &EvidenceReader,
    tokens: Option<&[&[u8]]>,
    config_text: Option<&str>,
) -> PreflightHibernation {
    let mut out = PreflightHibernation::default();
    if let Ok(raw) = read_preflight(reader, "/sys/power/state", POWER_CAP) {
        let mut advertised = false;
        for tok in raw.split(|&b| b.is_ascii_whitespace() || b == 0) {
            if tok == b"disk" {
                advertised = true;
                break;
            }
        }
        if advertised {
            out.runtime = "available".to_string();
        } else {
            out.runtime = "unavailable".to_string();
        }
    }
    if let Ok(raw) = read_preflight(reader, "/sys/power/disk", WORD_CAP)
        && let Some(method) = disk_method(&raw)
    {
        out.method = method;
    }
    if let Some(tokens) = tokens {
        if cmdline_has_resume(tokens) {
            out.resume = "yes".to_string();
        } else {
            out.resume = "no".to_string();
        }
    }
    if let Some(text) = config_text {
        match config_vote(text, "CONFIG_HIBERNATION") {
            1 => out.compiled = "yes".to_string(),
            0 => out.compiled = "no".to_string(),
            _ => {}
        }
    }
    out
}

/// Canonical decimal u64 word, or `None`.
///
/// Leading zeros canonicalize away; overlong, non-digit, or
/// overflowing words are unusable.
fn canonical_u64(word: &str) -> Option<String> {
    let bytes = word.as_bytes();
    if bytes.is_empty() || bytes.len() > 20 {
        return None;
    }
    let mut acc: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add(u64::from(b - b'0'))?;
    }
    Some(acc.to_string())
}

/// Collect kdump state: crash-image presence plus reservation bytes.
fn collect_kdump(reader: &EvidenceReader) -> PreflightKdump {
    let mut out = PreflightKdump::default();
    if let WordRead::Word(w) = read_word(reader, "/sys/kernel/kexec_crash_loaded", WORD_CAP) {
        if w == "1" {
            out.image = "loaded".to_string();
        } else if w == "0" {
            out.image = "not_loaded".to_string();
        }
    }
    if let WordRead::Word(w) = read_word(reader, "/sys/kernel/kexec_crash_size", WORD_CAP)
        && let Some(bytes) = canonical_u64(&w)
    {
        out.reservation = bytes;
    }
    out
}

/// Sanitized output label for one path segment.
///
/// Allowlisted characters and length only; anything else
/// collapses to `renamed`, so hostile bytes never reach a fact.
fn output_label(bytes: &[u8]) -> String {
    if bytes.is_empty() || bytes.len() > 64 {
        return "renamed".to_string();
    }
    if !is_valid_utf8(bytes) {
        return "renamed".to_string();
    }
    let text = bytes_to_text(bytes);
    for b in text.bytes() {
        let ok = b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.' || b == b'+';
        if !ok {
            return "renamed".to_string();
        }
    }
    text
}

/// One parsed `/proc/swaps` entry: the source plus its deleted marker.
struct SwapEntry {
    source: Vec<u8>,
    deleted: bool,
}

/// Parse `/proc/swaps` bodies: entries plus the truncation flag.
///
/// Returns `None` when the body is unparseable (no `Filename`
/// header, an overlong line): a garbled table is unknown,
/// never partially judged. Lines past the branch cap set the
/// truncation flag instead of growing the table.
fn parse_swaps(raw: &[u8]) -> Option<(Vec<SwapEntry>, bool)> {
    let mut lines = raw.split(|&b| b == b'\n');
    let header = lines.next()?;
    if !header.starts_with(b"Filename") {
        return None;
    }
    let mut entries = Vec::new();
    let mut truncated = false;
    for line in lines {
        if line.len() > MAX_SWAP_LINE {
            return None;
        }
        let fields: Vec<&[u8]> = line
            .split(|&b| b == b' ' || b == b'\t' || b == b'\r')
            .filter(|f| !f.is_empty())
            .collect();
        if fields.is_empty() {
            continue;
        }
        if entries.len() >= MAX_SWAP_BRANCHES {
            truncated = true;
            break;
        }
        let deleted = fields.iter().any(|f| *f == b"(deleted)");
        entries.push(SwapEntry {
            source: fields[0].to_vec(),
            deleted,
        });
    }
    Some((entries, truncated))
}

/// Swap-source shape after validation.
enum SourceKind {
    Device,
    Mapper,
    File,
    Invalid,
}

/// One validated swap source: its shape, label, and exact name bytes.
struct ParsedSource {
    kind: SourceKind,
    label: String,
    name: Vec<u8>,
}

/// Validate one swap source path.
///
/// Absolute paths only, no NUL, no `..` segment, valid UTF-8.
/// `/dev/mapper/<name>` resolves through a dm-name scan;
/// single-level `/dev` names resolve as block nodes; every
/// other absolute path is an unsupported swap file, never
/// resolved. The label is sanitized; hostile bytes collapse.
fn parse_source(source: &[u8]) -> ParsedSource {
    let invalid = ParsedSource {
        kind: SourceKind::Invalid,
        label: "invalid".to_string(),
        name: Vec::new(),
    };
    if source.is_empty() || source.len() > MAX_SOURCE_LEN {
        return invalid;
    }
    if source.contains(&0) {
        return invalid;
    }
    if !is_valid_utf8(source) {
        return invalid;
    }
    if source[0] != b'/' {
        return invalid;
    }
    for seg in source.split(|&b| b == b'/') {
        if seg == b".." {
            return invalid;
        }
    }
    if let Some(rest) = source.strip_prefix(b"/dev/") {
        if rest.is_empty() {
            return invalid;
        }
        if let Some(mapper) = rest.strip_prefix(b"mapper/") {
            if mapper.is_empty() || mapper.contains(&b'/') {
                return invalid;
            }
            let label = format!("mapper:{}", output_label(mapper));
            return ParsedSource {
                kind: SourceKind::Mapper,
                label,
                name: mapper.to_vec(),
            };
        }
        if rest.contains(&b'/') {
            return invalid;
        }
        let label = format!("dev:{}", output_label(rest));
        return ParsedSource {
            kind: SourceKind::Device,
            label,
            name: rest.to_vec(),
        };
    }
    let base = source.rsplit(|&b| b == b'/').next().unwrap_or(b"");
    if base.is_empty() {
        return invalid;
    }
    ParsedSource {
        kind: SourceKind::File,
        label: format!("file:{}", output_label(base)),
        name: Vec::new(),
    }
}

/// True for `zram<N>` whole-device names.
fn is_zram(name: &[u8]) -> bool {
    let rest = match name.strip_prefix(b"zram") {
        Some(rest) => rest,
        None => return false,
    };
    !rest.is_empty() && rest.iter().all(|b| b.is_ascii_digit())
}

/// One branch verdict under construction.
fn branch_of(source: String, device: String, verdict: &str, reason: &str) -> PreflightSwapBranch {
    PreflightSwapBranch {
        source,
        device,
        verdict: verdict.to_string(),
        reason: reason.to_string(),
    }
}

/// Mutable state for one topology walk.
#[derive(Default)]
struct WalkState {
    /// Canonical node ids in visit order (cycle detection).
    visited: Vec<String>,
    /// True once any walked node reported a crypt layer.
    crypt_seen: bool,
    /// First failure reason, if the walk went unresolved.
    failure: Option<String>,
}

/// One slave-name resolution: the node, or the failure class.
enum ChildNode {
    Node { path: String, label: String },
    Denied,
    Truncated,
    Missing,
}

/// Resolve one slave name to its sysfs node.
///
/// Whole devices answer directly; otherwise every
/// `/sys/block` entry is probed as a partition parent in
/// sorted order. A denied sibling never blocks the scan, but
/// when no parent answers and any probe refused, the child is
/// denied rather than missing. Hostile parent names skip:
/// skipping can only miss a parent (unresolved), never a
/// crypt layer, which the slave walk refuses to skip instead.
fn resolve_child(reader: &EvidenceReader, slave: &str) -> ChildNode {
    let whole = format!("/sys/block/{slave}");
    let mut denied = false;
    match preflight_state(reader, &whole) {
        EVIDENCE_OK => {
            return ChildNode::Node {
                path: whole,
                label: format!("dev:{slave}"),
            };
        }
        EVIDENCE_DENIED => denied = true,
        _ => {}
    }
    let entries = match list_preflight_dir(reader, "/sys/block", MAX_BLOCK_ENTRIES) {
        Ok(entries) => entries,
        Err(e) => {
            if e.code == E_DENIED {
                return ChildNode::Denied;
            }
            if e.code == E_TOO_BIG {
                return ChildNode::Truncated;
            }
            return ChildNode::Missing;
        }
    };
    for parent in &entries {
        if !preflight_device_segment(parent) {
            continue;
        }
        let path = format!("/sys/block/{parent}/{slave}");
        match preflight_state(reader, &path) {
            EVIDENCE_OK => {
                return ChildNode::Node {
                    path,
                    label: format!("dev:{parent}/{slave}"),
                };
            }
            EVIDENCE_DENIED => denied = true,
            _ => {}
        }
    }
    if denied {
        ChildNode::Denied
    } else {
        ChildNode::Missing
    }
}

/// One `/dev/mapper` name scan: the dm index, or the failure class.
///
/// Names compare as exact bytes in memory; the name is never
/// persisted. A denied entry never matches, and when no index
/// matches and any probe refused, the source is denied.
enum MapperHit {
    Found(usize),
    Denied,
    Missing,
}

/// Scan `dm-0` through the index cap for one mapper name.
fn resolve_mapper(reader: &EvidenceReader, want: &[u8]) -> MapperHit {
    let mut denied = false;
    for n in 0..MAX_DM_INDEX {
        let path = format!("/sys/block/dm-{n}/dm/name");
        match read_preflight(reader, &path, DM_ID_CAP) {
            Ok(raw) => {
                if let Some(word) = word_of(&raw)
                    && word.as_bytes() == want
                {
                    return MapperHit::Found(n);
                }
            }
            Err(e) => {
                if e.code == E_DENIED {
                    denied = true;
                }
            }
        }
    }
    if denied {
        MapperHit::Denied
    } else {
        MapperHit::Missing
    }
}

/// Walk one topology node: crypt layer, then slaves.
///
/// Every node re-verifies its own directory first, so a device
/// that vanishes between the presence read and the backing
/// walk resolves to unresolved, never to a verdict. Revisits
/// report a cycle; depth and node caps report truncated. A
/// crypt layer is the `CRYPT-` uuid prefix matched in memory;
/// uuid bytes never reach a fact.
fn walk_node(reader: &EvidenceReader, node: &str, depth: usize, walk: &mut WalkState) {
    if walk.failure.is_some() {
        return;
    }
    if depth > MAX_WALK_DEPTH || walk.visited.len() >= MAX_WALK_NODES {
        walk.failure = Some("truncated".to_string());
        return;
    }
    if walk.visited.iter().any(|v| v == node) {
        walk.failure = Some("cycle".to_string());
        return;
    }
    match preflight_state(reader, node) {
        EVIDENCE_OK => {}
        EVIDENCE_DENIED => {
            walk.failure = Some("denied".to_string());
            return;
        }
        _ => {
            walk.failure = Some("unresolved".to_string());
            return;
        }
    }
    walk.visited.push(node.to_string());
    let uuid_path = format!("{node}/dm/uuid");
    match preflight_state(reader, &uuid_path) {
        EVIDENCE_OK => match read_preflight(reader, &uuid_path, DM_ID_CAP) {
            Ok(raw) => {
                if raw.starts_with(b"CRYPT-") {
                    walk.crypt_seen = true;
                }
            }
            Err(e) => {
                walk.failure = Some(read_failure_reason(e.code));
                return;
            }
        },
        EVIDENCE_DENIED => {
            walk.failure = Some("denied".to_string());
            return;
        }
        _ => {}
    }
    let slaves_path = format!("{node}/slaves");
    match preflight_state(reader, &slaves_path) {
        EVIDENCE_OK => {}
        EVIDENCE_DENIED => {
            walk.failure = Some("denied".to_string());
            return;
        }
        _ => return,
    }
    let slaves = match list_preflight_dir(reader, &slaves_path, MAX_SLAVES) {
        Ok(slaves) => slaves,
        Err(e) => {
            walk.failure = Some(read_failure_reason(e.code));
            return;
        }
    };
    for slave in &slaves {
        if walk.failure.is_some() {
            return;
        }
        if !preflight_device_segment(slave) {
            walk.failure = Some("unresolved".to_string());
            return;
        }
        match resolve_child(reader, slave) {
            ChildNode::Node { path, .. } => walk_node(reader, &path, depth + 1, walk),
            ChildNode::Denied => {
                walk.failure = Some("denied".to_string());
                return;
            }
            ChildNode::Truncated => {
                walk.failure = Some("truncated".to_string());
                return;
            }
            ChildNode::Missing => {
                walk.failure = Some("unresolved".to_string());
                return;
            }
        }
    }
}

/// Finish one walked branch: the failure, the crypt layer, or the leaf.
///
/// The canonical device label persists only on a clean walk;
/// a failed walk proves no identity.
fn finish_walk(
    source: String,
    device: String,
    walk: &WalkState,
    zram_leaf: bool,
) -> PreflightSwapBranch {
    if let Some(reason) = &walk.failure {
        return branch_of(source, String::new(), "unknown", reason);
    }
    if walk.crypt_seen {
        return branch_of(source, device, "encrypted", "");
    }
    if zram_leaf {
        return branch_of(source, device, "memory_only", "");
    }
    branch_of(source, device, "no_encryption_observed", "")
}

/// Resolve one zram swap source.
///
/// `backing_dev` of `none` is a RAM-only candidate, still
/// walked generically for subordinate layers; any configured
/// backing device is unproved writeback, never resolved
/// through; anything else leaves the branch unresolved.
fn resolve_zram(reader: &EvidenceReader, parsed: &ParsedSource) -> PreflightSwapBranch {
    let name = bytes_to_text(&parsed.name);
    let node = format!("/sys/block/{name}");
    match preflight_state(reader, &node) {
        EVIDENCE_OK => {}
        EVIDENCE_DENIED => {
            return branch_of(parsed.label.clone(), String::new(), "unknown", "denied");
        }
        _ => {
            return branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved");
        }
    }
    let backing_path = format!("{node}/backing_dev");
    match read_preflight(reader, &backing_path, BACKING_CAP) {
        Ok(raw) => match word_of(&raw) {
            Some(word) => {
                if word != "none" {
                    return branch_of(
                        parsed.label.clone(),
                        String::new(),
                        "unknown",
                        "unproved_writeback",
                    );
                }
            }
            None => {
                return branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved");
            }
        },
        Err(e) => {
            return branch_of(
                parsed.label.clone(),
                String::new(),
                "unknown",
                &read_failure_reason(e.code),
            );
        }
    }
    let mut walk = WalkState::default();
    walk_node(reader, &node, 0, &mut walk);
    finish_walk(parsed.label.clone(), format!("dev:{name}"), &walk, true)
}

/// Resolve one whole/partition block-device swap source.
fn resolve_device(reader: &EvidenceReader, parsed: &ParsedSource) -> PreflightSwapBranch {
    let name = bytes_to_text(&parsed.name);
    if !preflight_device_segment(&name) {
        return branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved");
    }
    match resolve_child(reader, &name) {
        ChildNode::Node { path, label } => {
            let mut walk = WalkState::default();
            walk_node(reader, &path, 0, &mut walk);
            finish_walk(parsed.label.clone(), label, &walk, false)
        }
        ChildNode::Denied => branch_of(parsed.label.clone(), String::new(), "unknown", "denied"),
        ChildNode::Truncated => {
            branch_of(parsed.label.clone(), String::new(), "unknown", "truncated")
        }
        ChildNode::Missing => {
            branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved")
        }
    }
}

/// Resolve one mapper swap source through its dm index.
fn resolve_mapper_source(reader: &EvidenceReader, parsed: &ParsedSource) -> PreflightSwapBranch {
    match resolve_mapper(reader, &parsed.name) {
        MapperHit::Found(n) => {
            let node = format!("/sys/block/dm-{n}");
            match preflight_state(reader, &node) {
                EVIDENCE_OK => {}
                EVIDENCE_DENIED => {
                    return branch_of(parsed.label.clone(), String::new(), "unknown", "denied");
                }
                _ => {
                    return branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved");
                }
            }
            let mut walk = WalkState::default();
            walk_node(reader, &node, 0, &mut walk);
            finish_walk(parsed.label.clone(), format!("dev:dm-{n}"), &walk, false)
        }
        MapperHit::Denied => branch_of(parsed.label.clone(), String::new(), "unknown", "denied"),
        MapperHit::Missing => {
            branch_of(parsed.label.clone(), String::new(), "unknown", "unresolved")
        }
    }
}

/// Resolve one swap entry to its branch fact.
fn resolve_branch(reader: &EvidenceReader, entry: &SwapEntry) -> PreflightSwapBranch {
    let parsed = parse_source(&entry.source);
    if entry.deleted {
        return branch_of(parsed.label, String::new(), "unknown", "deleted");
    }
    match parsed.kind {
        SourceKind::Invalid => branch_of(parsed.label, String::new(), "unknown", "invalid_source"),
        SourceKind::File => branch_of(
            parsed.label,
            String::new(),
            "unknown",
            "unsupported_swap_file",
        ),
        SourceKind::Mapper => resolve_mapper_source(reader, &parsed),
        SourceKind::Device => {
            if is_zram(&parsed.name) {
                resolve_zram(reader, &parsed)
            } else {
                resolve_device(reader, &parsed)
            }
        }
    }
}

/// Aggregate branch facts into the backing assessment.
///
/// RAM-only zram branches carry no persistent backing and
/// stay out of the aggregate while retaining their facts; a
/// table of only those reports a null backing with
/// `memory_only_no_writeback`. Otherwise the first unknown
/// branch in file order decides the cause, an
/// encrypted/unencrypted split reports `mixed`, and only a
/// unanimous resolved table asserts either direction.
fn aggregate_backing(branches: &[PreflightSwapBranch]) -> (String, String) {
    let mut encrypted = false;
    let mut negative = false;
    let mut persistent = false;
    for branch in branches {
        if branch.verdict == "memory_only" {
            continue;
        }
        persistent = true;
        if branch.verdict == "unknown" {
            return ("unknown".to_string(), branch.reason.clone());
        }
        if branch.verdict == "encrypted" {
            encrypted = true;
        } else if branch.verdict == "no_encryption_observed" {
            negative = true;
        }
    }
    if !persistent {
        return (String::new(), "memory_only_no_writeback".to_string());
    }
    if encrypted && negative {
        return ("unknown".to_string(), "mixed".to_string());
    }
    if encrypted {
        return ("kernel_reports_encrypted".to_string(), String::new());
    }
    ("no_guest_encryption_observed".to_string(), String::new())
}

/// Collect swap presence, zswap state, and backing protection.
fn collect_swap(reader: &EvidenceReader) -> PreflightSwap {
    let mut out = PreflightSwap::default();
    if let WordRead::Word(w) = read_word(reader, "/sys/module/zswap/parameters/enabled", WORD_CAP) {
        if matches!(w.as_str(), "Y" | "y" | "1") {
            out.zswap = "enabled".to_string();
        } else if matches!(w.as_str(), "N" | "n" | "0") {
            out.zswap = "disabled".to_string();
        }
    }
    match read_preflight(reader, "/proc/swaps", SWAPS_CAP) {
        Err(e) => {
            if e.code == E_DENIED {
                out.backing_protection = "unknown".to_string();
                out.backing_reason = "presence_denied".to_string();
            } else if out.zswap != "unknown" {
                // The table is missing but swap-adjacent state was
                // observed: presence is unknown, not empty.
                out.backing_protection = "unknown".to_string();
                out.backing_reason = "presence_unknown".to_string();
            }
        }
        Ok(raw) => match parse_swaps(&raw) {
            None => {
                out.backing_protection = "unknown".to_string();
                out.backing_reason = "unresolved".to_string();
            }
            Some((entries, truncated)) => {
                if entries.is_empty() && !truncated {
                    out.swap_presence = "none".to_string();
                    out.backing_reason = "not_applicable".to_string();
                    return out;
                }
                out.swap_presence = "present".to_string();
                let mut branches = Vec::new();
                for entry in &entries {
                    branches.push(resolve_branch(reader, entry));
                }
                if truncated {
                    branches.push(branch_of(
                        "unassessed".to_string(),
                        String::new(),
                        "unknown",
                        "truncated",
                    ));
                }
                let (backing, reason) = aggregate_backing(&branches);
                out.backing_protection = backing;
                out.backing_reason = reason;
                out.branches = branches;
            }
        },
    }
    out
}

/// Collect the bounded confidential-preflight facts.
///
/// `lockdown` arrives from the kernel gate; every other fact
/// reads through the preflight allowlist, the shared config
/// helper, or nothing at all. Total: every failure degrades
/// to an explicit unknown, and unknown or denied evidence
/// never becomes an encrypted/unencrypted assertion.
pub fn collect_preflight(
    reader: &EvidenceReader,
    release: &str,
    lockdown: &LockdownState,
    zlib: &str,
) -> PreflightFacts {
    let mut out = PreflightFacts::default();
    out.lockdown.mode = lockdown.mode.clone();
    out.lockdown.src = lockdown.src.clone();
    let config = read_live_config_text(reader, release, zlib);
    let config_text = if config.state == "text" {
        Some(config.text.as_str())
    } else {
        None
    };
    let cmd_read = read_preflight(reader, "/proc/cmdline", CMDLINE_CAP);
    let (tokens, cmd_denied) = match &cmd_read {
        Ok(raw) => (cmdline_tokens(raw), false),
        Err(e) => (None, e.code == E_DENIED),
    };
    let tokens_ref = tokens.as_deref();
    out.module_signature = collect_sig(reader, &config, tokens_ref, cmd_denied);
    out.modules_disabled = collect_sysctl(reader, "/proc/sys/kernel/modules_disabled", "enabled");
    out.kexec = collect_sysctl(reader, "/proc/sys/kernel/kexec_load_disabled", "allowed");
    out.hibernation = collect_hibernation(reader, tokens_ref, config_text);
    out.kdump = collect_kdump(reader);
    out.swap = collect_swap(reader);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::reader::open_evidence_reader;
    use crate::platform::test_support::TestDir;

    fn tree() -> TestDir {
        let tmp = TestDir::create("memveil-preflight-unit").expect("mkdtemp");
        std::fs::write(
            tmp.path().join("meta.txt"),
            b"arch=x86_64\nrelease=7.0.0-test\neuid=1001\n",
        )
        .expect("meta");
        tmp
    }

    fn reader_for(tmp: &TestDir) -> EvidenceReader {
        open_evidence_reader(tmp.as_str()).expect("opens")
    }

    fn votes(sys: i32, cfg: i32, cmd: i32) -> SigVotes {
        SigVotes {
            sys,
            sys_malformed: false,
            sys_denied: false,
            cfg,
            cfg_denied: false,
            cmd,
            cmd_denied: false,
        }
    }

    #[test]
    fn word_edges() {
        assert_eq!(word_of(b"1\n"), Some("1".to_string()));
        assert_eq!(word_of(b"  Y  "), Some("Y".to_string()));
        assert_eq!(word_of(b""), None);
        assert_eq!(word_of(b"  \t\n"), None);
        assert_eq!(word_of(b"a b"), None);
        assert_eq!(word_of(b"a\0"), None);
        assert_eq!(word_of(b"\xff"), None);
        assert_eq!(
            word_of(b"CRYPT-LUKS2-x\n"),
            Some("CRYPT-LUKS2-x".to_string())
        );
    }

    #[test]
    fn canonical_u64_edges() {
        assert_eq!(canonical_u64("0"), Some("0".to_string()));
        assert_eq!(canonical_u64("007"), Some("7".to_string()));
        assert_eq!(canonical_u64("268435456"), Some("268435456".to_string()));
        assert_eq!(
            canonical_u64("18446744073709551615"),
            Some("18446744073709551615".to_string())
        );
        assert_eq!(canonical_u64(""), None);
        assert_eq!(canonical_u64("12a"), None);
        assert_eq!(canonical_u64("-1"), None);
        assert_eq!(canonical_u64("18446744073709551616"), None);
        assert_eq!(canonical_u64("1".repeat(21).as_str()), None);
    }

    #[test]
    fn cmdline_token_edges() {
        let toks = cmdline_tokens(b"a=1 module.sig_enforce=1 resume=UUID=x\n").expect("tokens");
        assert_eq!(toks.len(), 3);
        let toks = cmdline_tokens(b"a=1 -- resume=x\n").expect("tokens");
        assert_eq!(toks.len(), 1);
        assert!(cmdline_tokens(b"").expect("empty").is_empty());
        let mut big = Vec::new();
        for _ in 0..5000 {
            big.extend_from_slice(b"a ");
        }
        assert!(cmdline_tokens(&big).is_none());
        assert_eq!(
            cmdline_sig_vote(&[
                b"module.sig_enforce=0".as_slice(),
                b"module.sig_enforce=1".as_slice()
            ]),
            1
        );
        assert_eq!(cmdline_sig_vote(&[b"module.sig_enforce".as_slice()]), -1);
        assert_eq!(
            cmdline_sig_vote(&[b"module.sig_enforce=bogus".as_slice()]),
            -1
        );
        assert_eq!(cmdline_sig_vote(&[b"xmodule.sig_enforce=1".as_slice()]), -1);
        assert!(cmdline_has_resume(&[b"resume=UUID=1-2".as_slice()]));
        assert!(!cmdline_has_resume(&[b"resume=".as_slice()]));
        assert!(!cmdline_has_resume(&[b"noresume".as_slice()]));
    }

    #[test]
    fn config_vote_edges() {
        assert_eq!(
            config_vote("CONFIG_MODULE_SIG_FORCE=y\n", "CONFIG_MODULE_SIG_FORCE"),
            1
        );
        assert_eq!(
            config_vote(
                "# CONFIG_MODULE_SIG_FORCE is not set\n",
                "CONFIG_MODULE_SIG_FORCE"
            ),
            0
        );
        assert_eq!(
            config_vote("CONFIG_OTHER=y\n", "CONFIG_MODULE_SIG_FORCE"),
            -1
        );
        assert_eq!(config_vote("", "CONFIG_MODULE_SIG_FORCE"), -1);
    }

    #[test]
    fn sig_combine_table() {
        let on = combine_sig(&votes(1, -1, -1));
        assert_eq!(
            (on.state.as_str(), on.reason.as_str()),
            ("enforced", "sysfs")
        );
        let on3 = combine_sig(&votes(1, 1, 1));
        assert_eq!(on3.reason, "sysfs+config+cmdline");
        let clash = combine_sig(&votes(1, -1, 0));
        assert_eq!(
            (clash.state.as_str(), clash.reason.as_str()),
            ("unknown", "conflicting")
        );
        let clash2 = combine_sig(&votes(0, 1, -1));
        assert_eq!(clash2.reason, "conflicting");
        let clash3 = combine_sig(&votes(0, -1, 1));
        assert_eq!(clash3.reason, "conflicting");
        let off = combine_sig(&votes(0, 0, 0));
        assert_eq!(
            (off.state.as_str(), off.reason.as_str()),
            ("not_enforced", "sysfs+config+cmdline")
        );
        // A config force is not vetoed by an off command line.
        let force = combine_sig(&votes(-1, 1, 0));
        assert_eq!(
            (force.state.as_str(), force.reason.as_str()),
            ("enforced", "config")
        );
        let cmd = combine_sig(&votes(-1, -1, 1));
        assert_eq!(cmd.reason, "cmdline");
        let cfg_off = combine_sig(&votes(-1, 0, -1));
        assert_eq!(
            (cfg_off.state.as_str(), cfg_off.reason.as_str()),
            ("not_enforced", "config")
        );
        let missing = combine_sig(&votes(-1, -1, -1));
        assert_eq!(
            (missing.state.as_str(), missing.reason.as_str()),
            ("unknown", "")
        );
        let mut denied = votes(-1, -1, -1);
        denied.sys_denied = true;
        assert_eq!(combine_sig(&denied).reason, "denied");
        let mut bad = votes(-1, 1, 1);
        bad.sys_malformed = true;
        let malformed = combine_sig(&bad);
        assert_eq!(
            (malformed.state.as_str(), malformed.reason.as_str()),
            ("unknown", "malformed")
        );
    }

    #[test]
    fn disk_method_edges() {
        assert_eq!(
            disk_method(b"[platform] shutdown\n"),
            Some("platform".to_string())
        );
        assert_eq!(disk_method(b"x [reboot] y"), Some("reboot".to_string()));
        assert_eq!(
            disk_method(b"[test_resume]"),
            Some("test_resume".to_string())
        );
        assert_eq!(disk_method(b"[evil]"), None);
        assert_eq!(disk_method(b"platform"), None);
        assert_eq!(disk_method(b"[platform"), None);
        assert_eq!(disk_method(b""), None);
    }

    #[test]
    fn label_edges() {
        assert_eq!(output_label(b"dm-0"), "dm-0");
        assert_eq!(output_label(b"nvme0n1p1"), "nvme0n1p1");
        assert_eq!(output_label(b""), "renamed");
        assert_eq!(output_label(b"has space"), "renamed");
        assert_eq!(output_label(b"has/slash"), "renamed");
        assert_eq!(output_label(b"\xff"), "renamed");
        assert_eq!(output_label(&[b'd'; 65]), "renamed");
        assert_eq!(output_label(&[b'd'; 64]).len(), 64);
    }

    #[test]
    fn source_parse_edges() {
        let dev = parse_source(b"/dev/dm-0");
        assert!(matches!(dev.kind, SourceKind::Device));
        assert_eq!(dev.label, "dev:dm-0");
        assert_eq!(dev.name, b"dm-0");
        let mapper = parse_source(b"/dev/mapper/crypt");
        assert!(matches!(mapper.kind, SourceKind::Mapper));
        assert_eq!(mapper.label, "mapper:crypt");
        let file = parse_source(b"/swapfile");
        assert!(matches!(file.kind, SourceKind::File));
        assert_eq!(file.label, "file:swapfile");
        for bad in [
            b"relative".as_slice(),
            b"".as_slice(),
            b"/".as_slice(),
            b"/dev/".as_slice(),
            b"/dev/mapper/".as_slice(),
            b"/dev/mapper/a/b".as_slice(),
            b"/dev/sda/x".as_slice(),
            b"/dev/../evil".as_slice(),
            b"/dev/dm-0\0".as_slice(),
            b"/dev/\xff".as_slice(),
        ] {
            let parsed = parse_source(bad);
            assert!(matches!(parsed.kind, SourceKind::Invalid), "{bad:?}");
            assert_eq!(parsed.label, "invalid");
        }
        assert!(is_zram(b"zram0"));
        assert!(is_zram(b"zram12"));
        assert!(!is_zram(b"zram"));
        assert!(!is_zram(b"zram0x"));
        assert!(!is_zram(b"sda"));
    }

    #[test]
    fn swaps_parse_edges() {
        let header = b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n";
        let (entries, truncated) = parse_swaps(header).expect("header-only");
        assert!(entries.is_empty() && !truncated);
        let body = [
            header.as_slice(),
            b"/dev/dm-0                               partition\t1\t0\t-2\n",
            b"/swapfile                                file\t\t2\t0\t-3\n",
        ]
        .concat();
        let (entries, truncated) = parse_swaps(&body).expect("two");
        assert!(!truncated && entries.len() == 2);
        assert_eq!(entries[0].source, b"/dev/dm-0");
        assert!(!entries[0].deleted);
        assert_eq!(entries[1].source, b"/swapfile");
        let gone = [header.as_slice(), b"/gone (deleted)\n"].concat();
        let (entries, _) = parse_swaps(&gone).expect("deleted");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source, b"/gone");
        assert!(entries[0].deleted);
        assert!(parse_swaps(b"garbage\n/dev/dm-0\n").is_none());
        assert!(parse_swaps(b"").is_none());
        let mut overlong = header.to_vec();
        overlong.extend_from_slice(&vec![b'x'; 513]);
        overlong.push(b'\n');
        assert!(parse_swaps(&overlong).is_none());
        let mut many = header.to_vec();
        for _ in 0..65 {
            many.extend_from_slice(b"/dev/dm-0 partition 1 0 -2\n");
        }
        let (entries, truncated) = parse_swaps(&many).expect("many");
        assert!(truncated && entries.len() == 64);
        let crlf = [header.as_slice(), b"/dev/sda3 partition 1 0 -2\r\n"].concat();
        let (entries, _) = parse_swaps(&crlf).expect("crlf");
        assert_eq!(entries[0].source, b"/dev/sda3");
    }

    #[test]
    fn aggregate_edges() {
        let enc = branch_of("s".to_string(), "d".to_string(), "encrypted", "");
        let neg = branch_of(
            "s".to_string(),
            "d".to_string(),
            "no_encryption_observed",
            "",
        );
        let mem = branch_of("s".to_string(), "d".to_string(), "memory_only", "");
        let unk = branch_of("s".to_string(), String::new(), "unknown", "denied");
        assert_eq!(
            aggregate_backing(&[enc.clone(), enc.clone()]),
            ("kernel_reports_encrypted".to_string(), String::new())
        );
        assert_eq!(
            aggregate_backing(&[neg.clone(), neg.clone()]),
            ("no_guest_encryption_observed".to_string(), String::new())
        );
        assert_eq!(
            aggregate_backing(&[enc.clone(), neg.clone()]),
            ("unknown".to_string(), "mixed".to_string())
        );
        assert_eq!(
            aggregate_backing(&[enc, unk.clone()]),
            ("unknown".to_string(), "denied".to_string())
        );
        assert_eq!(
            aggregate_backing(std::slice::from_ref(&mem)),
            (String::new(), "memory_only_no_writeback".to_string())
        );
        assert_eq!(
            aggregate_backing(&[mem, neg]),
            ("no_guest_encryption_observed".to_string(), String::new())
        );
        assert_eq!(
            aggregate_backing(&[unk]),
            ("unknown".to_string(), "denied".to_string())
        );
    }

    #[test]
    fn resolve_static_branches() {
        let tmp = tree();
        let r = reader_for(&tmp);
        let gone = resolve_branch(
            &r,
            &SwapEntry {
                source: b"/dev/dm-0".to_vec(),
                deleted: true,
            },
        );
        assert_eq!(
            (gone.verdict.as_str(), gone.reason.as_str()),
            ("unknown", "deleted")
        );
        assert_eq!(gone.source.as_str(), "dev:dm-0");
        let invalid = resolve_branch(
            &r,
            &SwapEntry {
                source: b"relative".to_vec(),
                deleted: false,
            },
        );
        assert_eq!(invalid.reason, "invalid_source");
        let file = resolve_branch(
            &r,
            &SwapEntry {
                source: b"/swapfile".to_vec(),
                deleted: false,
            },
        );
        assert_eq!(
            (file.source.as_str(), file.reason.as_str()),
            ("file:swapfile", "unsupported_swap_file")
        );
    }

    #[test]
    fn swaps_branch_cap_appends_truncation() {
        let tmp = tree();
        std::fs::create_dir_all(tmp.path().join("sys/block/sda1")).expect("leaf");
        let mut body = b"Filename\t\t\t\tType\t\tSize\t\tUsed\t\tPriority\n".to_vec();
        for _ in 0..65 {
            body.extend_from_slice(b"/dev/sda1 partition 1 0 -2\n");
        }
        std::fs::create_dir_all(tmp.path().join("proc")).expect("proc");
        std::fs::write(tmp.path().join("proc/swaps"), &body).expect("swaps");
        let r = reader_for(&tmp);
        let swap = collect_swap(&r);
        assert_eq!(swap.swap_presence, "present");
        assert_eq!(swap.branches.len(), 65);
        let tail = &swap.branches[64];
        assert_eq!(tail.source, "unassessed");
        assert_eq!(tail.reason, "truncated");
        assert_eq!(swap.backing_protection, "unknown");
        assert_eq!(swap.backing_reason, "truncated");
    }

    #[test]
    fn walk_slaves_cap_truncates() {
        let tmp = tree();
        let slaves = tmp.path().join("sys/block/dm-0/slaves");
        std::fs::create_dir_all(&slaves).expect("slaves");
        for n in 0..65 {
            std::fs::write(slaves.join(format!("s{n:02}")), b"").expect("slave");
        }
        let r = reader_for(&tmp);
        let mut walk = WalkState::default();
        walk_node(&r, "/sys/block/dm-0", 0, &mut walk);
        assert_eq!(walk.failure, Some("truncated".to_string()));
        assert!(!walk.crypt_seen);
    }

    #[test]
    fn walk_node_cap_truncates() {
        let tmp = tree();
        let slaves = tmp.path().join("sys/block/dm-0/slaves");
        std::fs::create_dir_all(&slaves).expect("slaves");
        for n in 0..64 {
            let leaf = format!("s{n:02}");
            std::fs::write(slaves.join(&leaf), b"").expect("slave");
            std::fs::create_dir_all(tmp.path().join(format!("sys/block/{leaf}")))
                .expect("leaf dir");
        }
        let r = reader_for(&tmp);
        let mut walk = WalkState::default();
        walk_node(&r, "/sys/block/dm-0", 0, &mut walk);
        assert_eq!(walk.failure, Some("truncated".to_string()));
        assert_eq!(walk.visited.len(), 64);
    }

    #[test]
    fn oversized_uuid_truncates_branch() {
        let tmp = tree();
        std::fs::create_dir_all(tmp.path().join("sys/block/dm-0/dm")).expect("dm");
        std::fs::write(
            tmp.path().join("sys/block/dm-0/dm/uuid"),
            vec![b'C'; DM_ID_CAP + 44],
        )
        .expect("uuid");
        std::fs::create_dir_all(tmp.path().join("sys/block/dm-0/slaves")).expect("slaves");
        let r = reader_for(&tmp);
        let branch = resolve_branch(
            &r,
            &SwapEntry {
                source: b"/dev/dm-0".to_vec(),
                deleted: false,
            },
        );
        assert_eq!(branch.verdict, "unknown");
        assert_eq!(branch.reason, "truncated");
        assert!(branch.device.is_empty());
    }

    #[test]
    fn mapper_scan_miss_and_denial() {
        let tmp = tree();
        let r = reader_for(&tmp);
        assert!(matches!(resolve_mapper(&r, b"ghost"), MapperHit::Missing));
        let tmp = TestDir::create("memveil-preflight-deny").expect("mkdtemp");
        std::fs::write(
            tmp.path().join("meta.txt"),
            b"arch=x86_64\nrelease=7.0.0-test\neuid=1001\ndenied=/sys/block/dm-0/dm/name\n",
        )
        .expect("meta");
        std::fs::create_dir_all(tmp.path().join("sys/block/dm-0/dm")).expect("dm");
        std::fs::write(tmp.path().join("sys/block/dm-0/dm/name"), b"ghost\n").expect("name");
        let r = reader_for(&tmp);
        assert!(matches!(resolve_mapper(&r, b"ghost"), MapperHit::Denied));
    }

    #[test]
    fn mapper_scan_bound() {
        let tmp = tree();
        std::fs::create_dir_all(tmp.path().join("sys/block/dm-511/dm")).expect("edge");
        std::fs::write(tmp.path().join("sys/block/dm-511/dm/name"), b"edge\n").expect("name");
        std::fs::create_dir_all(tmp.path().join("sys/block/dm-512/dm")).expect("beyond");
        std::fs::write(tmp.path().join("sys/block/dm-512/dm/name"), b"beyond\n").expect("name");
        let r = reader_for(&tmp);
        assert!(matches!(resolve_mapper(&r, b"edge"), MapperHit::Found(511)));
        assert!(matches!(resolve_mapper(&r, b"beyond"), MapperHit::Missing));
    }
}
