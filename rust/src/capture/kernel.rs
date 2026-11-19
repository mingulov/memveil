// SPDX-License-Identifier: GPL-3.0-or-later
//! Live kernel source: `KernelSource` over statically loaded sessions.
//!
//! Thin ownership adapter, no policy: every trait method
//! takes the session out of its slot, runs one loader
//! call, and puts the session back (close drops it on
//! success so drop has nothing to retry). Loader
//! failures surface as OpOut/GeomOut/PollOut/StatsOut/
//! SnapOut with structured op/domain/code detail; calls
//! before open (or after close) report "session not open",
//! except close, which is idempotent and succeeds.
//!
//! Channels share one open state: open_session opens every
//! present channel or none (rollback on failure), attach
//! attaches every present channel or none (explicit detach
//! rollback), and close releases everything. Channel 0 is
//! the attempt tracepoint object; channel 1 the lifecycle
//! tracing object; channel 2 the copy tracing object.
//! Attach sites are frozen per channel; record selects
//! which channels exist by passing their object bytes.
//!
//! Each channel remembers the program fds its attach created
//! (diffed from /proc/self/fdinfo, no loader call needed: Aya
//! defers program load to attach, unlike the C bridge).
//! Without copy, recursion_misses sums the per-program
//! counters; with copy, it identifies each tracing program
//! by kernel name and reads the fallback counters, so the
//! collector can charge exact copy loss.
//!
//! Poll rotates across present channels (sticky on short:
//! a short pins the next poll to the channel holding the
//! retained record) and waits only when every channel is
//! empty. Stats sum across present channels;
//! per-channel counters stay available through stats_at
//! and read_full_at.
//!
//! Poll batches re-encode decoded frames to raw payload
//! bytes: the ring yields items directly, so there is no
//! staging short or interruptible wait on the live path.
//! The op/domain/code diagnostic vocabulary of the retired
//! bridge ABI is retained, with the errno parsed from the
//! loader message, so load refusal classification keeps
//! working unchanged.

use super::collector::{GeomOut, KernelSource, MissOut, PollOut, SnapOut, StatsOut};
use super::loadcheck::{errno_cause, errno_from_chain, errno_name};
use crate::bpf::{
    AttachKind, AttachSpec, Frame, Session, SessionError, copy_specs, lifecycle_specs,
};
use crate::platform::narrow::{MV_OFF_TABLE_MAGIC, MV_OFFSETS_TABLE_LEN};
use crate::platform::outcome::OpOut;
use crate::platform::reader::{bytes_to_text, read_host_file};
use aya::EbpfLoader;
use memveil_ebpf_common::{
    MV_CP_FLAG_CLAMPED, MV_CP_FLAG_EARLY_ZERO, MV_CP_FLAG_KNOWN, MV_CP_FLAG_OFFSET_PAST_ALLOC,
    MV_CP_FLAG_PRIVATE_POOL, MV_CP_FLAG_TO_DEVICE, MV_CP_LEN, MV_CP_MAGIC, MV_CP_OFF_DIR,
    MV_CP_OFF_EFFECTIVE, MV_CP_OFF_FLAGS, MV_CP_OFF_KIND, MV_CP_OFF_KTIME, MV_CP_OFF_MAGIC,
    MV_CP_OFF_REASON, MV_CP_OFF_REQUESTED, MV_CP_OFF_SEQ, MV_CP_OFF_VERSION, MV_CP_VERSION,
    MV_FLAG_FORCE, MV_LC_FLAG_GEN_MISS, MV_LC_FLAG_GEN_UNASSIGNED, MV_LC_FLAG_OK,
    MV_LC_FLAG_SKIP_SYNC, MV_LC_KIND_MAP, MV_LC_LEN, MV_LC_MAGIC, MV_LC_OFF_DIR, MV_LC_OFF_FLAGS,
    MV_LC_OFF_GEN, MV_LC_OFF_KIND, MV_LC_OFF_KTIME, MV_LC_OFF_MAGIC, MV_LC_OFF_SEQ, MV_LC_OFF_SIZE,
    MV_LC_OFF_VERSION, MV_LC_VERSION, MV_MAGIC, MV_OFF_FLAGS, MV_OFF_KTIME, MV_OFF_MAGIC,
    MV_OFF_NAME, MV_OFF_NAME_LEN, MV_OFF_SEQ, MV_OFF_SIZE, MV_OFF_VERSION, MV_PAYLOAD_LEN,
    MV_VERSION,
};

// Retired bridge ABI op vocabulary, kept for diagnostics.
const OP_OPEN: u32 = 1;
const OP_LOAD: u32 = 2;
const OP_ATTACH: u32 = 3;
const OP_POLL: u32 = 4;
const OP_MAP_INFO: u32 = 5;
const OP_MAP_READ: u32 = 6;
const OP_MAP_WRITE: u32 = 7;
const OP_DETACH: u32 = 9;
const OP_CLOSE: u32 = 10;
// Loader domain in refusal diagnostics.
const DOMAIN_LOADER: u32 = 2;

const RING_ATTEMPT: &str = "mv_attempts";
const RING_LIFECYCLE: &str = "mv_lifecycle";
const RING_COPY: &str = "mv_copies";
const FDINFO_DIR: &str = "/proc/self/fdinfo";
const FDINFO_CAP: usize = 4096;
const BPF_OBJ_GET_INFO: libc::c_long = 15;
const PROG_INFO_SIZE: usize = 232;
const PROG_NAME_OFF: usize = 64;
const PROG_NAME_LEN: usize = 16;
const PROG_REC_OFF: usize = 208;

/// Last `(os error N)` errno in a loader message, if any.
fn os_errno(message: &str) -> Option<i32> {
    let marker = "(os error ";
    let mut found = None;
    let mut rest = message;
    while let Some(at) = rest.find(marker) {
        let tail = &rest[at + marker.len()..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if !digits.is_empty()
            && tail[digits.len()..].starts_with(')')
            && let Ok(n) = digits.parse::<i32>()
        {
            found = Some(n);
        }
        rest = &rest[at + 1..];
    }
    found
}

/// One loader failure as structured op/domain/code detail.
fn session_message(op: u32, err: &SessionError) -> String {
    let message = err.to_string();
    match os_errno(&message) {
        Some(n) => {
            let code = 0 - n;
            let mut out = format!(
                "op={op} domain={DOMAIN_LOADER} code={code} {}",
                errno_name(code)
            );
            let cause = errno_cause(code);
            if !cause.is_empty() {
                out += &format!(": {cause}");
            }
            out + &format!(": {message}")
        }
        None => format!("op={op} domain={DOMAIN_LOADER}: {message}"),
    }
}

/// One loader failure with an explicit errno, when one was recovered.
fn session_message_with(op: u32, message: &str, errno: Option<i32>) -> String {
    match errno {
        Some(n) => {
            let code = 0 - n;
            let mut out = format!(
                "op={op} domain={DOMAIN_LOADER} code={code} {}",
                errno_name(code),
            );
            let cause = errno_cause(code);
            if !cause.is_empty() {
                out += &format!(": {cause}");
            }
            out + &format!(": {message}")
        }
        None => format!("op={op} domain={DOMAIN_LOADER}: {message}"),
    }
}

/// Syscall errno behind a failed load, via a diagnostic replay.
///
/// The session verdict swallows the loader error chain, so a failed
/// load replays once to recover the authoritative errno for refusal
/// classification. Failed loads leave no kernel state, so the replay
/// is side-effect free; a replay that loads (or fails without an
/// errno, as geometry verdicts do) yields nothing.
fn load_errno(elf: &[u8]) -> Option<i32> {
    match EbpfLoader::new().load(elf) {
        Ok(bpf) => {
            drop(bpf);
            None
        }
        Err(e) => errno_from_chain(&e),
    }
}

fn channel_tag(channel: i64) -> String {
    format!("ch{channel} ")
}

/// Next poll position after a batch found at probe k.
///
/// Advances by order position, never by channel id, so a
/// sparse order like [0, 2] rotates instead of reselecting
/// a busy high channel and starving attempt.
pub fn poll_advance(order_len: i64, start: i64, k: i64) -> i64 {
    (start + k + 1) % order_len
}

/// Accumulate one channel failure into a combined message.
///
/// Teardown attempts every owned channel and reports all
/// failures; the first error never silences the rest.
pub fn join_op_message(acc: &str, channel: i64, message: &str) -> String {
    let piece = format!("{}{}", channel_tag(channel), message);
    if acc.is_empty() {
        return piece;
    }
    format!("{acc}; {piece}")
}

/// Accumulate one failed rollback step: `; rollback ch{j}: msg`
/// (Mojo taxonomy; distinct from the plain channel tag so a failed
/// rollback never reads as the original attach failure).
fn rollback_piece(message: &str, channel: i64, detail: &str) -> String {
    format!("{message}; rollback ch{channel}: {detail}")
}

/// One bounded poll on one channel; `rotate_poll` owns policy.
pub trait ChannelPoller {
    /// Poll one channel without touching the short pin.
    fn poll_channel(&mut self, channel: i64, timeout_ms: i64, capacity: u32) -> PollOut;
}

/// Rotation state: next order position, pinned short channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollRotation {
    /// Next order position to probe.
    pub next: i64,
    /// Pinned short channel, or -1.
    pub short_ch: i64,
}

/// One multi-channel poll over order (sticky on short).
///
/// Every channel is probed without waiting first; only when
/// all are empty does the start channel wait timeout_ms, so
/// a quiet ring never holds the wait while another ring has
/// records queued. Data arriving on a non-waited channel is
/// picked up by the next call, at most one finite wait later.
/// An empty order is an error, never a division by zero.
pub fn rotate_poll<P: ChannelPoller>(
    poller: &mut P,
    rot: &mut PollRotation,
    order: &[i64],
    timeout_ms: i64,
    capacity: u32,
) -> PollOut {
    if rot.short_ch >= 0 {
        let ch = rot.short_ch;
        let mut retry = poller.poll_channel(ch, timeout_ms, capacity);
        if retry.kind != "short" {
            rot.short_ch = -1;
        }
        if retry.kind == "error" {
            retry.message = format!("{}{}", channel_tag(ch), retry.message);
        }
        return retry;
    }
    let n = order.len() as i64;
    if n == 0 {
        return PollOut {
            kind: "error".to_string(),
            frame: Vec::new(),
            required: 0,
            message: "no channels to poll".to_string(),
        };
    }
    let start = rot.next % n;
    let mut probes = n;
    if timeout_ms != 0 {
        probes = n + 1;
    }
    for k in 0..probes {
        let pos = k % n;
        let ch = order[((start + pos) % n) as usize];
        let mut wait = 0;
        if k == n {
            wait = timeout_ms;
        }
        let mut out = poller.poll_channel(ch, wait, capacity);
        if out.kind == "batch" {
            rot.next = poll_advance(n, start, pos);
            return out;
        }
        if out.kind == "short" {
            rot.short_ch = ch;
            return out;
        }
        if out.kind == "error" {
            out.message = format!("{}{}", channel_tag(ch), out.message);
            return out;
        }
    }
    rot.next = (start + 1) % n;
    PollOut {
        kind: "timeout".to_string(),
        frame: Vec::new(),
        required: 0,
        message: String::new(),
    }
}

/// Decimal value of the `key:` line of one fdinfo text, if any.
pub fn fdinfo_u64(text: &str, key: &str) -> Option<u64> {
    let b = text.as_bytes();
    let k = key.as_bytes();
    let n = b.len();
    let mut i = 0;
    while i < n {
        let mut j = 0;
        while j < k.len() && i + j < n && b[i + j] == k[j] {
            j += 1;
        }
        if j == k.len() && i + j < n && b[i + j] == 58 {
            let mut p = i + j + 1;
            while p < n && (b[p] == 9 || b[p] == 32) {
                p += 1;
            }
            let mut v = 0u64;
            let mut digits = 0;
            while p < n && b[p].is_ascii_digit() {
                let d = u64::from(b[p] - 48);
                if v > (u64::MAX - d) / 10 {
                    return None;
                }
                v = v * 10 + d;
                digits += 1;
                p += 1;
            }
            if digits == 0 || (p < n && b[p] != 10) {
                return None;
            }
            return Some(v);
        }
        while i < n && b[i] != 10 {
            i += 1;
        }
        i += 1;
    }
    None
}

/// Decimal fd from a /proc/self/fdinfo entry name, or -1.
fn fd_number(name: &str) -> i64 {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 9 {
        return -1;
    }
    let mut v = 0i64;
    for byte in b {
        if !byte.is_ascii_digit() {
            return -1;
        }
        v = v * 10 + i64::from(byte - 48);
    }
    v
}

fn fdinfo_text(fd: i64) -> Result<String, String> {
    let path = format!("{FDINFO_DIR}/{fd}");
    read_host_file(&path, "fdinfo", FDINFO_CAP)
        .map(|raw| bytes_to_text(&raw))
        .map_err(|e| e.message)
}

/// This process's open BPF program fds; None if unlistable.
pub fn prog_fds() -> Option<Vec<i64>> {
    let names = std::fs::read_dir(FDINFO_DIR).ok()?;
    let mut out = Vec::new();
    for entry in names {
        let entry = entry.ok()?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let fd = fd_number(&name);
        if fd < 0 {
            continue;
        }
        // Fds closed since the listing (its own dir fd) are skipped.
        let Ok(text) = fdinfo_text(fd) else {
            continue;
        };
        if fdinfo_u64(&text, "prog_type").is_some() {
            out.push(fd);
        }
    }
    Some(out)
}

/// Fds in after that before lacks, in after's order.
pub fn added_fds(before: &[i64], after: &[i64]) -> Vec<i64> {
    let mut out = Vec::new();
    for fd in after {
        if !before.contains(fd) {
            out.push(*fd);
        }
    }
    out
}

/// Program name from a bpf_prog_info image, if readable.
pub fn parse_prog_name(info: &[u8]) -> Option<String> {
    if info.len() < PROG_NAME_OFF + PROG_NAME_LEN {
        return None;
    }
    let mut raw = Vec::new();
    for i in 0..PROG_NAME_LEN {
        let b = info[PROG_NAME_OFF + i];
        if b == 0 {
            break;
        }
        raw.push(b);
    }
    if raw.is_empty() {
        return None;
    }
    for b in &raw {
        let ok = b.is_ascii_alphanumeric() || *b == b'_';
        if !ok {
            return None;
        }
    }
    String::from_utf8(raw).ok()
}

/// Recursion misses from a bpf_prog_info image, else 0.
pub fn parse_prog_misses(info: &[u8]) -> u64 {
    if info.len() < PROG_REC_OFF + 8 {
        return 0;
    }
    let mut v = 0u64;
    for i in 0..8 {
        v |= u64::from(info[PROG_REC_OFF + i]) << (8 * i);
    }
    v
}

/// One copy-channel identification (misses valid when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopyProgs {
    /// True when the four programs identified.
    pub ok: bool,
    /// Failure detail; empty on success.
    pub message: String,
    /// Bounce-entry misses.
    pub bounce: u64,
    /// Bounce-exit misses.
    pub exit_misses: u64,
    /// Sync-device misses.
    pub sync_device: u64,
    /// Sync-cpu misses.
    pub sync_cpu: u64,
}

/// Match the four frozen copy programs by kernel name.
pub fn identify_copy_progs(names: &[String], misses: &[u64]) -> CopyProgs {
    let fail = |message: &str| CopyProgs {
        ok: false,
        message: message.to_string(),
        bounce: 0,
        exit_misses: 0,
        sync_device: 0,
        sync_cpu: 0,
    };
    if names.len() != 4 || misses.len() != 4 {
        return fail("copy program count");
    }
    let mut bounce = 0;
    let mut exit_misses = 0;
    let mut sync_device = 0;
    let mut sync_cpu = 0;
    let mut seen_bounce = false;
    let mut seen_exit = false;
    let mut seen_dev = false;
    let mut seen_cpu = false;
    for i in 0..4 {
        let n = names[i].as_str();
        if n == "mv_bounce" {
            if seen_bounce {
                return fail("copy program ambiguous");
            }
            seen_bounce = true;
            bounce = misses[i];
        } else if n == "mv_bounce_exit" {
            if seen_exit {
                return fail("copy program ambiguous");
            }
            seen_exit = true;
            exit_misses = misses[i];
        } else if n == "mv_sync_device" {
            if seen_dev {
                return fail("copy program ambiguous");
            }
            seen_dev = true;
            sync_device = misses[i];
        } else if n == "mv_sync_cpu" {
            if seen_cpu {
                return fail("copy program ambiguous");
            }
            seen_cpu = true;
            sync_cpu = misses[i];
        } else {
            return fail("copy program unexpected");
        }
    }
    if !(seen_bounce && seen_exit && seen_dev && seen_cpu) {
        return fail("copy program missing");
    }
    CopyProgs {
        ok: true,
        message: String::new(),
        bounce,
        exit_misses,
        sync_device,
        sync_cpu,
    }
}

/// One lifecycle-channel identification (valid when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleProgs {
    /// True when the two programs identified.
    pub ok: bool,
    /// Failure detail; empty on success.
    pub message: String,
    /// Map-result misses.
    pub map_misses: u64,
    /// Unmap misses.
    pub unmap_misses: u64,
}

/// Match the two frozen lifecycle programs by kernel name.
pub fn identify_lifecycle_progs(names: &[String], misses: &[u64]) -> LifecycleProgs {
    let fail = |message: &str| LifecycleProgs {
        ok: false,
        message: message.to_string(),
        map_misses: 0,
        unmap_misses: 0,
    };
    if names.len() != 2 || misses.len() != 2 {
        return fail("lifecycle program count");
    }
    let mut map_misses = 0;
    let mut unmap_misses = 0;
    let mut seen_map = false;
    let mut seen_unmap = false;
    for i in 0..2 {
        let n = names[i].as_str();
        if n == "mv_map_result" {
            if seen_map {
                return fail("lifecycle program ambiguous");
            }
            seen_map = true;
            map_misses = misses[i];
        } else if n == "mv_unmap" {
            if seen_unmap {
                return fail("lifecycle program ambiguous");
            }
            seen_unmap = true;
            unmap_misses = misses[i];
        } else {
            return fail("lifecycle program unexpected");
        }
    }
    if !(seen_map && seen_unmap) {
        return fail("lifecycle program missing");
    }
    LifecycleProgs {
        ok: true,
        message: String::new(),
        map_misses,
        unmap_misses,
    }
}

/// One program identity read (name/misses valid when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgInfo {
    /// True when the identity read.
    pub ok: bool,
    /// Failure detail; empty on success.
    pub message: String,
    /// Kernel program name.
    pub name: String,
    /// Recursion misses.
    pub misses: u64,
}

/// Kernel name and misses for one program fd, via info call.
pub fn prog_info(fd: i64) -> ProgInfo {
    let fail = |message: String| ProgInfo {
        ok: false,
        message,
        name: String::new(),
        misses: 0,
    };
    // The kernel writes the info struct through this pointer, so the
    // buffer is mutably borrowed: writing through a shared borrow
    // would be undefined behavior.
    let mut info = vec![0u8; PROG_INFO_SIZE];
    let mut attr = [0u8; 16];
    attr[0..4].copy_from_slice(&(fd as u32).to_le_bytes());
    attr[4..8].copy_from_slice(&(PROG_INFO_SIZE as u32).to_le_bytes());
    attr[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    // SAFETY: attr points at the two live buffers; the call
    // reads and writes them synchronously and returns 0/-1.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_bpf,
            BPF_OBJ_GET_INFO,
            attr.as_mut_ptr(),
            size_of_val(&attr),
        )
    };
    if rc != 0 {
        return fail(format!("prog info unreadable for fd {fd}"));
    }
    let Some(name) = parse_prog_name(&info) else {
        return fail(format!("program identity unreadable for fd {fd}"));
    };
    ProgInfo {
        ok: true,
        message: String::new(),
        name,
        misses: parse_prog_misses(&info),
    }
}

/// Fallback reads are usable only with three slots and no flags.
pub fn fb_valid(vals: &[u64]) -> bool {
    if vals.len() != 3 {
        return false;
    }
    vals[2] == 0
}

/// Detail text for a failed fallback-counter read: the channel tag
/// keeps the `fallback: ` infix (Mojo taxonomy).
fn fb_read_detail(message: &str) -> String {
    format!("ch2 fallback: {message}")
}

/// Detail text for invalid fallback counters: the flag reason (or the
/// short-read marker) joins the channel tag directly, with no infix
/// (Mojo taxonomy).
fn fb_invalid_detail(vals: &[u64]) -> String {
    let reason = if vals.len() == 3 {
        fb_flag_reason(vals[2])
    } else {
        "short fallback read".to_string()
    };
    format!("ch2 {reason}")
}

/// Name for nonzero fallback flags; empty when clean.
pub fn fb_flag_reason(flags: u64) -> String {
    if flags == 0 {
        return String::new();
    }
    // Bits 0-1 are counter wraps, bit 2 a lost frame.
    let mut out = String::new();
    if flags & 3 != 0 {
        out = "fallback counters wrapped".to_string();
    }
    if flags & 4 != 0 {
        if !out.is_empty() {
            out += "; ";
        }
        out += "fallback frame lost";
    }
    if flags & !7 != 0 {
        if !out.is_empty() {
            out += "; ";
        }
        out += "fallback flags invalid";
    }
    out
}

/// Inner channels first: copy, lifecycle, attempt.
///
/// Copies execute inside map, sync, and unmap, so the copy
/// hooks are live before any outer hook can fire; an
/// observed outer event never lacks inner evidence to
/// attach racing.
pub fn channel_attach_order() -> Vec<i64> {
    vec![2, 1, 0]
}

/// Outer channels first: attempt, lifecycle, copy.
pub fn channel_detach_order() -> Vec<i64> {
    vec![0, 1, 2]
}

/// Detach order for a failed attach: reverse of completion.
pub fn rollback_order(done: &[i64]) -> Vec<i64> {
    let mut out = Vec::new();
    for j in 0..done.len() {
        out.push(done[done.len() - 1 - j]);
    }
    out
}

fn put_u16(out: &mut [u8], at: usize, value: u16) {
    out[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

/// Re-encode one decoded attempt frame to raw payload bytes.
///
/// The decode validated every field, so the re-encode is
/// exact, including the NUL terminator and zero padding.
fn encode_attempt_frame(a: &memveil_ebpf_common::Attempt) -> Vec<u8> {
    let mut out = vec![0u8; MV_PAYLOAD_LEN];
    put_u32(&mut out, MV_OFF_MAGIC, MV_MAGIC);
    put_u16(&mut out, MV_OFF_VERSION, MV_VERSION);
    put_u16(
        &mut out,
        MV_OFF_FLAGS,
        if a.force { MV_FLAG_FORCE } else { 0 },
    );
    put_u64(&mut out, MV_OFF_SEQ, a.seq);
    put_u64(&mut out, MV_OFF_KTIME, a.ktime);
    put_u64(&mut out, MV_OFF_SIZE, a.size);
    put_u16(&mut out, MV_OFF_NAME_LEN, a.name_len);
    out[MV_OFF_NAME..MV_OFF_NAME + 64].copy_from_slice(&a.name);
    out
}

/// Re-encode one decoded lifecycle frame to raw payload bytes.
///
/// The generation-coupling flags re-derive from the
/// validated kind/ok/generation triple, reproducing the
/// exact wire flags the decode accepted.
fn encode_lifecycle_frame(l: &memveil_ebpf_common::Lifecycle) -> Vec<u8> {
    let mut out = vec![0u8; MV_LC_LEN];
    put_u32(&mut out, MV_LC_OFF_MAGIC, MV_LC_MAGIC);
    put_u16(&mut out, MV_LC_OFF_VERSION, MV_LC_VERSION);
    put_u16(&mut out, MV_LC_OFF_KIND, l.kind);
    let mut flags = 0u16;
    if l.ok {
        flags |= MV_LC_FLAG_OK;
    }
    if l.skip_sync {
        flags |= MV_LC_FLAG_SKIP_SYNC;
    }
    if l.kind == MV_LC_KIND_MAP {
        if l.ok && l.generation == 0 {
            flags |= MV_LC_FLAG_GEN_UNASSIGNED;
        }
    } else if l.generation == 0 {
        flags |= MV_LC_FLAG_GEN_MISS;
    }
    put_u16(&mut out, MV_LC_OFF_FLAGS, flags);
    put_u16(&mut out, MV_LC_OFF_DIR, l.dir);
    put_u64(&mut out, MV_LC_OFF_SEQ, l.seq);
    put_u64(&mut out, MV_LC_OFF_KTIME, l.ktime);
    put_u64(&mut out, MV_LC_OFF_SIZE, l.size);
    put_u64(&mut out, MV_LC_OFF_GEN, l.generation);
    out
}

/// Re-encode one decoded copy frame to raw payload bytes.
///
/// Every flag bit the decode accepted round-trips; the two
/// trailing pad bytes encode zero, which the decode ignores.
fn encode_copy_frame(c: &memveil_ebpf_common::Copy) -> Vec<u8> {
    let mut out = vec![0u8; MV_CP_LEN];
    put_u32(&mut out, MV_CP_OFF_MAGIC, MV_CP_MAGIC);
    put_u16(&mut out, MV_CP_OFF_VERSION, MV_CP_VERSION);
    put_u16(&mut out, MV_CP_OFF_KIND, c.kind);
    let mut flags = 0u16;
    if c.to_device {
        flags |= MV_CP_FLAG_TO_DEVICE;
    }
    if c.known {
        flags |= MV_CP_FLAG_KNOWN;
    }
    if c.clamped {
        flags |= MV_CP_FLAG_CLAMPED;
    }
    if c.early_zero {
        flags |= MV_CP_FLAG_EARLY_ZERO;
    }
    if c.offset_past {
        flags |= MV_CP_FLAG_OFFSET_PAST_ALLOC;
    }
    if c.private_pool {
        flags |= MV_CP_FLAG_PRIVATE_POOL;
    }
    put_u16(&mut out, MV_CP_OFF_FLAGS, flags);
    put_u16(&mut out, MV_CP_OFF_DIR, c.dir);
    put_u64(&mut out, MV_CP_OFF_SEQ, c.seq);
    put_u64(&mut out, MV_CP_OFF_KTIME, c.ktime);
    put_u64(&mut out, MV_CP_OFF_REQUESTED, c.requested);
    put_u64(&mut out, MV_CP_OFF_EFFECTIVE, c.effective);
    put_u16(&mut out, MV_CP_OFF_REASON, c.reason);
    out
}

/// Re-encode one decoded frame to raw payload bytes.
fn encode_frame(frame: &Frame) -> Vec<u8> {
    match frame {
        Frame::Attempt(a) => encode_attempt_frame(a),
        Frame::Lifecycle(l) => encode_lifecycle_frame(l),
        Frame::Copy(c) => encode_copy_frame(c),
    }
}

/// One object's session slot: elf, ring, sites, session.
struct ChannelSlot {
    elf: Vec<u8>,
    ring: String,
    specs: Vec<AttachSpec>,
    sess: Option<Session>,
    present: bool,
    progs: Vec<i64>,
    progs_known: bool,
}

impl ChannelSlot {
    fn new() -> Self {
        Self {
            elf: Vec::new(),
            ring: String::new(),
            specs: Vec::new(),
            sess: None,
            present: false,
            progs: Vec::new(),
            progs_known: false,
        }
    }

    fn setup(&mut self, elf: Vec<u8>, ring: &str, specs: Vec<AttachSpec>) {
        self.elf = elf;
        self.ring = ring.to_string();
        self.specs = specs;
        self.present = true;
    }

    fn is_open(&self) -> bool {
        self.sess.is_some()
    }

    fn open_session(&mut self) -> OpOut {
        if self.is_open() {
            return OpOut {
                ok: false,
                message: "session already open".to_string(),
            };
        }
        match Session::open(&self.elf, &self.ring) {
            Ok(sess) => {
                self.sess = Some(sess);
                OpOut {
                    ok: true,
                    message: String::new(),
                }
            }
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_OPEN, &e),
            },
        }
    }

    fn load(&mut self) -> OpOut {
        if !self.is_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        // No fd diff here: Aya's loader only parses and gates,
        // so no program fds exist yet; attach records them.
        let res = self.sess.as_mut().expect("open session").load();
        if let Err(e) = res {
            let message = session_message_with(OP_LOAD, &e.to_string(), load_errno(&self.elf));
            return OpOut { ok: false, message };
        }
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn misses(&mut self) -> MissOut {
        if !self.is_open() {
            return MissOut {
                ok: false,
                message: "session not open".to_string(),
                ..Default::default()
            };
        }
        if !self.progs_known {
            return MissOut {
                ok: false,
                message: "program fds unknown".to_string(),
                ..Default::default()
            };
        }
        let mut total = 0u64;
        for fd in self.progs.clone() {
            let text = match fdinfo_text(fd) {
                Ok(text) => text,
                Err(e) => {
                    return MissOut {
                        ok: false,
                        message: format!("fdinfo {fd}: {e}"),
                        ..Default::default()
                    };
                }
            };
            let Some(m) = fdinfo_u64(&text, "recursion_misses") else {
                return MissOut {
                    ok: false,
                    message: format!("fdinfo {fd}: no recursion_misses"),
                    ..Default::default()
                };
            };
            if total > u64::MAX - m {
                return MissOut {
                    ok: false,
                    message: "recursion misses wrap".to_string(),
                    ..Default::default()
                };
            }
            total += m;
        }
        MissOut {
            ok: true,
            count: total,
            ..Default::default()
        }
    }

    /// Kernel names and misses for every program fd, in order.
    fn prog_names_misses(&mut self) -> Result<(Vec<String>, Vec<u64>), String> {
        if !self.is_open() {
            return Err("session not open".to_string());
        }
        if !self.progs_known {
            return Err("program fds unknown".to_string());
        }
        let mut names = Vec::new();
        let mut misses = Vec::new();
        for fd in self.progs.clone() {
            let got = prog_info(fd);
            if !got.ok {
                return Err(got.message);
            }
            names.push(got.name);
            misses.push(got.misses);
        }
        Ok((names, misses))
    }

    fn misses_lifecycle(&mut self) -> LifecycleProgs {
        match self.prog_names_misses() {
            Ok((names, misses)) => identify_lifecycle_progs(&names, &misses),
            Err(message) => LifecycleProgs {
                ok: false,
                message,
                map_misses: 0,
                unmap_misses: 0,
            },
        }
    }

    fn misses_copy(&mut self) -> CopyProgs {
        match self.prog_names_misses() {
            Ok((names, misses)) => identify_copy_progs(&names, &misses),
            Err(message) => CopyProgs {
                ok: false,
                message,
                bounce: 0,
                exit_misses: 0,
                sync_device: 0,
                sync_cpu: 0,
            },
        }
    }

    fn read_fb(&mut self) -> SnapOut {
        if !self.is_open() {
            return SnapOut {
                ok: false,
                vals: Vec::new(),
                message: "session not open".to_string(),
            };
        }
        match self.sess.as_ref().expect("open session").read_copy_fb() {
            Ok(vals) => SnapOut {
                ok: true,
                vals: vals.to_vec(),
                message: String::new(),
            },
            Err(e) => SnapOut {
                ok: false,
                vals: Vec::new(),
                message: session_message(OP_MAP_READ, &e),
            },
        }
    }

    /// Write the fallback armed slot; exactly 1 arms the exit.
    fn set_fb_armed(&mut self, armed: bool) -> OpOut {
        if !self.is_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        match self
            .sess
            .as_mut()
            .expect("open session")
            .set_copy_armed(armed)
        {
            Ok(()) => OpOut {
                ok: true,
                message: String::new(),
            },
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_MAP_WRITE, &e),
            },
        }
    }

    fn map_info(&mut self, name: &str) -> GeomOut {
        let bad = |message: String| GeomOut {
            ok: false,
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            message,
        };
        if !self.is_open() {
            return bad("session not open".to_string());
        }
        match self.sess.as_ref().expect("open session").map_info(name) {
            Ok(info) => GeomOut {
                ok: true,
                map_type: info.map_type,
                key_size: info.key_size,
                value_size: info.value_size,
                max_entries: info.max_entries,
                message: String::new(),
            },
            Err(e) => bad(session_message(OP_MAP_INFO, &e)),
        }
    }

    /// Write the offset table, then read it back and compare.
    ///
    /// A short write, a short read-back, or any byte
    /// difference refuses: the program must never run on
    /// a mis-installed table.
    fn install_offsets(&mut self, table: &[u8]) -> OpOut {
        if !self.is_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        if table.len() != MV_OFFSETS_TABLE_LEN as usize {
            return OpOut {
                ok: false,
                message: "bad offsets table".to_string(),
            };
        }
        let mut magic = 0i64;
        for (i, byte) in table.iter().take(4).enumerate() {
            magic |= i64::from(*byte) << (8 * i);
        }
        if magic != MV_OFF_TABLE_MAGIC {
            return OpOut {
                ok: false,
                message: "bad offsets table".to_string(),
            };
        }
        let fixed: [u8; 24] = table.try_into().expect("24 table bytes");
        match self
            .sess
            .as_mut()
            .expect("open session")
            .install_offsets(&fixed)
        {
            Ok(()) => OpOut {
                ok: true,
                message: String::new(),
            },
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_MAP_WRITE, &e),
            },
        }
    }

    /// Record attach-time program fds from one fd-table diff.
    ///
    /// Aya creates program fds at attach (the loader only parses),
    /// so the diff the C-backed control takes at load happens here
    /// instead; the misses definition below is unchanged. New fds
    /// replace the record; an empty diff keeps a prior record
    /// (detach leaves loads behind, so a reattach adds nothing)
    /// and an unlistable table leaves state untouched.
    fn note_attach_progs(&mut self, before: &Option<Vec<i64>>, after: &Option<Vec<i64>>) {
        let (Some(before), Some(after)) = (before, after) else {
            return;
        };
        let added = added_fds(before, after);
        if !added.is_empty() {
            self.progs = added;
            self.progs_known = true;
        }
    }

    fn attach(&mut self) -> OpOut {
        if !self.is_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        let specs = self.specs.clone();
        let before = prog_fds();
        match self.sess.as_mut().expect("open session").attach(&specs) {
            Ok(()) => {
                let after = prog_fds();
                self.note_attach_progs(&before, &after);
                OpOut {
                    ok: true,
                    message: String::new(),
                }
            }
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_ATTACH, &e),
            },
        }
    }

    fn poll(&mut self, timeout_ms: i64, _capacity: u32) -> PollOut {
        if !self.is_open() {
            return PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: "session not open".to_string(),
            };
        }
        // No staging buffer on this path: capacity rides along
        // for the trait shape only and shorts never surface.
        let wait = timeout_ms.clamp(0, u32::MAX as i64) as u32;
        match self.sess.as_mut().expect("open session").poll(wait) {
            Ok(Some(frame)) => PollOut {
                kind: "batch".to_string(),
                frame: encode_frame(&frame),
                required: 0,
                message: String::new(),
            },
            Ok(None) => PollOut {
                kind: "timeout".to_string(),
                frame: Vec::new(),
                required: 0,
                message: String::new(),
            },
            Err(e) => PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: session_message(OP_POLL, &e),
            },
        }
    }

    fn stats(&mut self) -> StatsOut {
        if !self.is_open() {
            return StatsOut {
                ok: false,
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
                message: "session not open".to_string(),
            };
        }
        let st = self.sess.as_ref().expect("open session").stats();
        StatsOut {
            ok: true,
            received: st.received,
            delivered: st.delivered,
            staged: st.staged,
            malformed: st.malformed,
            dropped: st.dropped,
            message: String::new(),
        }
    }

    fn read_full(&mut self) -> SnapOut {
        if !self.is_open() {
            return SnapOut {
                ok: false,
                vals: Vec::new(),
                message: "session not open".to_string(),
            };
        }
        match self.sess.as_ref().expect("open session").read_counters() {
            Ok(vals) => SnapOut {
                ok: true,
                vals: vals.to_vec(),
                message: String::new(),
            },
            Err(e) => SnapOut {
                ok: false,
                vals: Vec::new(),
                message: session_message(OP_MAP_READ, &e),
            },
        }
    }

    fn detach(&mut self) -> OpOut {
        if !self.is_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        match self.sess.as_mut().expect("open session").detach() {
            Ok(()) => OpOut {
                ok: true,
                message: String::new(),
            },
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_DETACH, &e),
            },
        }
    }

    fn close(&mut self) -> OpOut {
        // Idempotent cleanup: closing a never-opened (or
        // already closed) session succeeds, so unconditional
        // rollback after a pre-open startup failure stays a
        // clean refusal instead of a rollback failure.
        if !self.is_open() {
            return OpOut {
                ok: true,
                message: String::new(),
            };
        }
        match self.sess.as_mut().expect("open session").close() {
            Ok(()) => {
                self.sess = None;
                self.progs = Vec::new();
                self.progs_known = false;
                OpOut {
                    ok: true,
                    message: String::new(),
                }
            }
            Err(e) => OpOut {
                ok: false,
                message: session_message(OP_CLOSE, &e),
            },
        }
    }
}

/// Live kernel: up to three owned loader sessions.
pub struct AyaKernel {
    ch0: ChannelSlot,
    ch1: ChannelSlot,
    ch2: ChannelSlot,
    rot: PollRotation,
}

impl AyaKernel {
    /// One attempt channel over explicit bytes and sites.
    pub fn new(elf: Vec<u8>, ring: &str, program: &str, tp_system: &str, tp_event: &str) -> Self {
        let mut kernel = Self {
            ch0: ChannelSlot::new(),
            ch1: ChannelSlot::new(),
            ch2: ChannelSlot::new(),
            rot: PollRotation {
                next: 0,
                short_ch: -1,
            },
        };
        kernel.ch0.setup(
            elf,
            ring,
            vec![AttachSpec::new(
                program,
                AttachKind::Tracepoint,
                tp_system,
                tp_event,
            )],
        );
        kernel
    }

    /// Attempt plus optional lifecycle/copy channels.
    pub fn with_channels(
        elf_attempt: Vec<u8>,
        tp_system: &str,
        tp_event: &str,
        elf_lc: Vec<u8>,
        has_lc: bool,
        elf_cp: Vec<u8>,
        has_cp: bool,
    ) -> Self {
        let mut kernel = Self::new(
            elf_attempt,
            RING_ATTEMPT,
            "mv_swiotlb_attempt",
            tp_system,
            tp_event,
        );
        if has_lc {
            kernel.ch1.setup(elf_lc, RING_LIFECYCLE, lifecycle_specs());
        }
        if has_cp {
            kernel.ch2.setup(elf_cp, RING_COPY, copy_specs());
        }
        kernel
    }

    /// True when the channel exists (attempt always does).
    fn present(&self, channel: i64) -> bool {
        if channel == 0 {
            return true;
        }
        if channel == 1 {
            return self.ch1.present;
        }
        if channel == 2 {
            return self.ch2.present;
        }
        false
    }

    fn slot(&mut self, channel: i64) -> &mut ChannelSlot {
        if channel == 1 {
            return &mut self.ch1;
        }
        if channel == 2 {
            return &mut self.ch2;
        }
        &mut self.ch0
    }

    /// True when any owned session is open.
    fn any_open(&self) -> bool {
        self.ch0.is_open() || self.ch1.is_open() || self.ch2.is_open()
    }

    fn order(&self) -> Vec<i64> {
        let mut order = Vec::new();
        for ch in [0, 1, 2] {
            if self.present(ch) {
                order.push(ch);
            }
        }
        order
    }
}

impl ChannelPoller for AyaKernel {
    fn poll_channel(&mut self, channel: i64, timeout_ms: i64, capacity: u32) -> PollOut {
        self.slot(channel).poll(timeout_ms, capacity)
    }
}

impl KernelSource for AyaKernel {
    fn open_session(&mut self) -> OpOut {
        if self.any_open() {
            return OpOut {
                ok: false,
                message: "session already open".to_string(),
            };
        }
        let opened = self.ch0.open_session();
        if !opened.ok {
            return OpOut {
                ok: false,
                message: format!("{}{}", channel_tag(0), opened.message),
            };
        }
        if self.ch1.present {
            let opened1 = self.ch1.open_session();
            if !opened1.ok {
                let _ = self.ch0.close();
                return OpOut {
                    ok: false,
                    message: format!("{}{}", channel_tag(1), opened1.message),
                };
            }
        }
        if self.ch2.present {
            let opened2 = self.ch2.open_session();
            if !opened2.ok {
                let _ = self.ch1.close();
                let _ = self.ch0.close();
                return OpOut {
                    ok: false,
                    message: format!("{}{}", channel_tag(2), opened2.message),
                };
            }
        }
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn load(&mut self) -> OpOut {
        if !self.any_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        let loaded = self.ch0.load();
        if !loaded.ok {
            return OpOut {
                ok: false,
                message: format!("{}{}", channel_tag(0), loaded.message),
            };
        }
        if self.ch1.present {
            let loaded1 = self.ch1.load();
            if !loaded1.ok {
                return OpOut {
                    ok: false,
                    message: format!("{}{}", channel_tag(1), loaded1.message),
                };
            }
        }
        if self.ch2.present {
            let loaded2 = self.ch2.load();
            if !loaded2.ok {
                return OpOut {
                    ok: false,
                    message: format!("{}{}", channel_tag(2), loaded2.message),
                };
            }
        }
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn map_info(&mut self, name: &str) -> GeomOut {
        self.ch0.map_info(name)
    }

    fn map_info_at(&mut self, channel: i64, name: &str) -> GeomOut {
        if !self.present(channel) {
            return GeomOut {
                ok: false,
                map_type: 0,
                key_size: 0,
                value_size: 0,
                max_entries: 0,
                message: "bad channel".to_string(),
            };
        }
        self.slot(channel).map_info(name)
    }

    fn channel_count(&self) -> i64 {
        // Count present channels, not the highest present one:
        // copy-without-lifecycle is two (Mojo parity).
        let mut n = 1;
        if self.ch1.present {
            n += 1;
        }
        if self.ch2.present {
            n += 1;
        }
        n
    }

    fn install_offsets(&mut self, table: &[u8]) -> OpOut {
        if !self.any_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        self.ch0.install_offsets(table)
    }

    fn attach(&mut self) -> OpOut {
        if !self.any_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        let mut done = Vec::new();
        for ch in channel_attach_order() {
            if !self.present(ch) {
                continue;
            }
            let attached = self.slot(ch).attach();
            if !attached.ok {
                let mut message = format!("{}{}", channel_tag(ch), attached.message);
                for back in rollback_order(&done) {
                    let undone = self.slot(back).detach();
                    if !undone.ok {
                        message = rollback_piece(&message, back, &undone.message);
                    }
                }
                return OpOut { ok: false, message };
            }
            done.push(ch);
        }
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn set_copy_armed(&mut self, armed: bool) -> OpOut {
        if !self.any_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        if !self.ch2.present {
            return OpOut {
                ok: false,
                message: "copy channel absent".to_string(),
            };
        }
        self.ch2.set_fb_armed(armed)
    }

    fn poll(&mut self, timeout_ms: i64, capacity: u32) -> PollOut {
        if !self.any_open() {
            return PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: "session not open".to_string(),
            };
        }
        let mut rot = self.rot;
        let order = self.order();
        let out = rotate_poll(self, &mut rot, &order, timeout_ms, capacity);
        self.rot = rot;
        out
    }

    fn stats(&mut self) -> StatsOut {
        if !self.any_open() {
            return StatsOut {
                ok: false,
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
                message: "session not open".to_string(),
            };
        }
        let bad = |message: String| StatsOut {
            ok: false,
            received: 0,
            delivered: 0,
            staged: 0,
            malformed: 0,
            dropped: 0,
            message,
        };
        // Checked sums fail the read closed on overflow instead of trapping:
        // any wrap breaks the collector identities and fails the run
        // closed, never silently.
        // Deviation: Mojo traps on these sums; Rust fails the read
        // closed per the R14 precedent (loud, fail-closed, never a
        // silent wrapped total).
        let mut received = 0u64;
        let mut delivered = 0u64;
        let mut staged = 0u64;
        let mut malformed = 0u64;
        let mut dropped = 0u64;
        for ch in [0, 1, 2] {
            if !self.present(ch) {
                continue;
            }
            let st = self.slot(ch).stats();
            if !st.ok {
                return bad(format!("{}{}", channel_tag(ch), st.message));
            }
            received = match received.checked_add(st.received) {
                Some(v) => v,
                None => return bad("stats sum overflow".to_string()),
            };
            delivered = match delivered.checked_add(st.delivered) {
                Some(v) => v,
                None => return bad("stats sum overflow".to_string()),
            };
            staged = match staged.checked_add(st.staged) {
                Some(v) => v,
                None => return bad("stats sum overflow".to_string()),
            };
            malformed = match malformed.checked_add(st.malformed) {
                Some(v) => v,
                None => return bad("stats sum overflow".to_string()),
            };
            dropped = match dropped.checked_add(st.dropped) {
                Some(v) => v,
                None => return bad("stats sum overflow".to_string()),
            };
        }
        StatsOut {
            ok: true,
            received,
            delivered,
            staged,
            malformed,
            dropped,
            message: String::new(),
        }
    }

    fn stats_at(&mut self, channel: i64) -> StatsOut {
        if !self.present(channel) {
            return StatsOut {
                ok: false,
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
                message: "bad channel".to_string(),
            };
        }
        self.slot(channel).stats()
    }

    fn read_full(&mut self) -> SnapOut {
        self.ch0.read_full()
    }

    fn read_full_at(&mut self, channel: i64) -> SnapOut {
        if !self.present(channel) {
            return SnapOut {
                ok: false,
                vals: Vec::new(),
                message: "bad channel".to_string(),
            };
        }
        self.slot(channel).read_full()
    }

    fn detach(&mut self) -> OpOut {
        if !self.any_open() {
            return OpOut {
                ok: false,
                message: "session not open".to_string(),
            };
        }
        let mut acc = String::new();
        let mut ok = true;
        for ch in channel_detach_order() {
            if !self.present(ch) {
                continue;
            }
            let done = self.slot(ch).detach();
            if !done.ok {
                ok = false;
                acc = join_op_message(&acc, ch, &done.message);
            }
        }
        OpOut { ok, message: acc }
    }

    fn recursion_misses(&mut self) -> MissOut {
        let m0 = self.ch0.misses();
        if !m0.ok {
            // Mojo tags the attempt-misses failure with "ch0 ".
            return MissOut {
                ok: false,
                message: format!("ch0 {}", m0.message),
                ..Default::default()
            };
        }
        if !self.ch2.present {
            if !self.ch1.present {
                return MissOut {
                    ok: true,
                    count: m0.count,
                    message: String::new(),
                    attempt: m0.count,
                    ..Default::default()
                };
            }
            let m1 = self.ch1.misses();
            if !m1.ok {
                // Detail failures keep ok:true: the attempt count
                // stays known and the collector voids only the
                // detail side (Mojo parity).
                return MissOut {
                    ok: true,
                    message: String::new(),
                    attempt: m0.count,
                    detail_error: format!("ch1 {}", m1.message),
                    ..Default::default()
                };
            }
            if m0.count > u64::MAX - m1.count {
                return MissOut {
                    ok: false,
                    message: "recursion misses wrap".to_string(),
                    ..Default::default()
                };
            }
            return MissOut {
                ok: true,
                count: m0.count + m1.count,
                message: String::new(),
                attempt: m0.count,
                ..Default::default()
            };
        }
        let lc = self.ch1.misses_lifecycle();
        if !lc.ok && self.ch1.present {
            return MissOut {
                ok: true,
                message: String::new(),
                attempt: m0.count,
                detail_error: format!("ch1 {}", lc.message),
                ..Default::default()
            };
        }
        let cp = self.ch2.misses_copy();
        if !cp.ok {
            return MissOut {
                ok: true,
                message: String::new(),
                attempt: m0.count,
                detail_error: format!("ch2 {}", cp.message),
                ..Default::default()
            };
        }
        let mut lc_map = 0u64;
        let mut lc_unmap = 0u64;
        if self.ch1.present {
            lc_map = lc.map_misses;
            lc_unmap = lc.unmap_misses;
        }
        let fb = self.ch2.read_fb();
        if !fb.ok {
            return MissOut {
                ok: true,
                message: String::new(),
                attempt: m0.count,
                detail_error: fb_read_detail(&fb.message),
                ..Default::default()
            };
        }
        if !fb_valid(&fb.vals) {
            return MissOut {
                ok: true,
                message: String::new(),
                attempt: m0.count,
                detail_error: fb_invalid_detail(&fb.vals),
                ..Default::default()
            };
        }
        MissOut {
            ok: true,
            message: String::new(),
            attempt: m0.count,
            has_copy_detail: true,
            bounce: cp.bounce,
            exit_misses: cp.exit_misses,
            sync_device: cp.sync_device,
            sync_cpu: cp.sync_cpu,
            lc_map,
            lc_unmap,
            deferred: fb.vals[0],
            recovered: fb.vals[1],
            ..Default::default()
        }
    }

    fn close(&mut self) -> OpOut {
        let mut acc = String::new();
        let mut ok = true;
        for ch in [0, 1, 2] {
            let done = self.slot(ch).close();
            if !done.ok {
                ok = false;
                acc = join_op_message(&acc, ch, &done.message);
            }
        }
        self.rot.short_ch = -1;
        OpOut { ok, message: acc }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AyaKernel, ChannelPoller, ChannelSlot, PollRotation, added_fds, channel_attach_order,
        channel_detach_order, encode_frame, fb_flag_reason, fb_invalid_detail, fb_read_detail,
        fb_valid, fdinfo_u64, identify_copy_progs, identify_lifecycle_progs, join_op_message,
        os_errno, parse_prog_misses, parse_prog_name, poll_advance, prog_fds, prog_info,
        rollback_order, rollback_piece, rotate_poll, session_message,
    };
    use super::{KernelSource, PollOut};
    use crate::bpf::{Frame, SessionError};

    struct ScriptPoller {
        outs: Vec<PollOut>,
        idx: usize,
        seen: Vec<(i64, i64, u32)>,
    }

    impl ScriptPoller {
        fn new(outs: Vec<PollOut>) -> Self {
            Self {
                outs,
                idx: 0,
                seen: Vec::new(),
            }
        }
    }

    impl ChannelPoller for ScriptPoller {
        fn poll_channel(&mut self, channel: i64, timeout_ms: i64, capacity: u32) -> PollOut {
            self.seen.push((channel, timeout_ms, capacity));
            if self.idx >= self.outs.len() {
                return PollOut {
                    kind: "timeout".to_string(),
                    frame: Vec::new(),
                    required: 0,
                    message: String::new(),
                };
            }
            let out = self.outs[self.idx].clone();
            self.idx += 1;
            out
        }
    }

    fn timeout_out() -> PollOut {
        PollOut {
            kind: "timeout".to_string(),
            frame: Vec::new(),
            required: 0,
            message: String::new(),
        }
    }

    fn batch_out(payload: Vec<u8>) -> PollOut {
        PollOut {
            kind: "batch".to_string(),
            frame: payload,
            required: 0,
            message: String::new(),
        }
    }

    fn short_out(required: u32) -> PollOut {
        PollOut {
            kind: "short".to_string(),
            frame: Vec::new(),
            required,
            message: String::new(),
        }
    }

    #[test]
    fn rotate_first_empty_waits_on_first() {
        // All empty: every channel probes without waiting,
        // then the start channel waits the timeout.
        let mut poller = ScriptPoller::new(vec![timeout_out(), timeout_out(), timeout_out()]);
        let mut rot = PollRotation {
            next: 0,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 64);
        assert_eq!(out.kind, "timeout");
        assert_eq!(poller.seen.len(), 3);
        assert_eq!(poller.seen[0], (0, 0, 64));
        assert_eq!(poller.seen[1], (1, 0, 64));
        assert_eq!(poller.seen[2], (0, 100, 64));
        assert_eq!(rot.next, 1);
    }

    #[test]
    fn rotate_prefers_ready_second_channel() {
        let mut poller = ScriptPoller::new(vec![timeout_out(), batch_out(vec![1, 2, 3])]);
        let mut rot = PollRotation {
            next: 0,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 64);
        assert_eq!(out.kind, "batch");
        assert_eq!(out.frame, vec![1, 2, 3]);
        assert_eq!(poller.seen.len(), 2);
        // Found at probe 1 of 2: next starts at 0 again.
        assert_eq!(rot.next, 0);
    }

    #[test]
    fn rotate_data_arrives_after_wait() {
        // Data on the waited channel still reports batch.
        let mut poller = ScriptPoller::new(vec![timeout_out(), timeout_out(), batch_out(vec![9])]);
        let mut rot = PollRotation {
            next: 0,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 64);
        assert_eq!(out.kind, "batch");
        assert_eq!(rot.next, 1);
    }

    #[test]
    fn rotate_empty_order_errors() {
        let mut poller = ScriptPoller::new(vec![]);
        let mut rot = PollRotation {
            next: 0,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[], 100, 64);
        assert_eq!(out.kind, "error");
    }

    #[test]
    fn rotate_short_pins_channel_until_batch() {
        // A short pins the next poll to its channel; the retry
        // clears the pin only when it stops shorting.
        let mut poller =
            ScriptPoller::new(vec![short_out(128), short_out(128), batch_out(vec![7])]);
        let mut rot = PollRotation {
            next: 0,
            short_ch: -1,
        };
        let first = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 64);
        assert_eq!(first.kind, "short");
        assert_eq!(rot.short_ch, 0);
        let second = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 128);
        assert_eq!(second.kind, "short");
        assert_eq!(poller.seen[1].0, 0);
        assert_eq!(rot.short_ch, 0);
        let third = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 128);
        assert_eq!(third.kind, "batch");
        assert_eq!(rot.short_ch, -1);
    }

    #[test]
    fn short_route_tags_channel() {
        let mut poller = ScriptPoller::new(vec![short_out(64)]);
        let mut rot = PollRotation {
            next: 1,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 32);
        assert_eq!(out.kind, "short");
        // Probed channel 1 first (start=1): pin lands there.
        assert_eq!(rot.short_ch, 1);
    }

    #[test]
    fn error_route_tags_channel() {
        let mut poller = ScriptPoller::new(vec![PollOut {
            kind: "error".to_string(),
            frame: Vec::new(),
            required: 0,
            message: "boom".to_string(),
        }]);
        let mut rot = PollRotation {
            next: 1,
            short_ch: -1,
        };
        let out = rotate_poll(&mut poller, &mut rot, &[0, 1], 100, 64);
        assert_eq!(out.kind, "error");
        assert_eq!(out.message, "ch1 boom");
    }

    #[test]
    fn poll_advance_wraps_by_position() {
        assert_eq!(poll_advance(2, 0, 0), 1);
        assert_eq!(poll_advance(2, 0, 1), 0);
        assert_eq!(poll_advance(2, 1, 0), 0);
        assert_eq!(poll_advance(3, 2, 2), 2);
    }

    #[test]
    fn fdinfo_u64_matrix() {
        let text = "pos:\t0\nflags:\t02000002\nmnt_id:\t12\nprog_type:\t3\nprog_id:\t42\nrecursion_misses:\t7\n";
        assert_eq!(fdinfo_u64(text, "prog_type"), Some(3));
        assert_eq!(fdinfo_u64(text, "recursion_misses"), Some(7));
        assert_eq!(fdinfo_u64(text, "nope"), None);
        assert_eq!(
            fdinfo_u64("recursion_misses: nope\n", "recursion_misses"),
            None
        );
        assert_eq!(
            fdinfo_u64("recursion_misses: 12x\n", "recursion_misses"),
            None
        );
        // Overflow pins to None, never wraps.
        assert_eq!(
            fdinfo_u64(
                "recursion_misses: 18446744073709551616\n",
                "recursion_misses"
            ),
            None
        );
        assert_eq!(
            fdinfo_u64(
                "recursion_misses: 18446744073709551615\n",
                "recursion_misses"
            ),
            Some(u64::MAX)
        );
    }

    #[test]
    fn added_fds_diff() {
        assert_eq!(added_fds(&[3, 4], &[3, 4, 9, 10]), vec![9, 10]);
        assert_eq!(added_fds(&[3, 4], &[3, 4]), Vec::<i64>::new());
        assert_eq!(added_fds(&[], &[7]), vec![7]);
    }

    #[test]
    fn prog_fds_listable() {
        // The listing itself works; contents depend on live loaders.
        assert!(prog_fds().is_some());
    }

    #[test]
    fn parse_prog_name_matrix() {
        let mut info = vec![0u8; 232];
        info[64..80].copy_from_slice(b"mv_bounce\x00\x00\x00\x00\x00\x00\x00");
        assert_eq!(parse_prog_name(&info), Some("mv_bounce".to_string()));
        info[64] = b'-';
        assert_eq!(parse_prog_name(&info), None);
        assert_eq!(parse_prog_name(&[0u8; 10]), None);
        assert_eq!(parse_prog_name(&[0u8; 232]), None);
    }

    #[test]
    fn parse_prog_misses_matrix() {
        let mut info = vec![0u8; 232];
        info[208..216].copy_from_slice(&39u64.to_le_bytes());
        assert_eq!(parse_prog_misses(&info), 39);
        assert_eq!(parse_prog_misses(&[0u8; 10]), 0);
    }

    #[test]
    fn prog_info_bad_fd() {
        let got = prog_info(1 << 30);
        assert!(!got.ok);
        assert!(got.message.contains("prog info unreadable"));
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn identify_copy_ok() {
        let got = identify_copy_progs(
            &names(&[
                "mv_bounce_exit",
                "mv_bounce",
                "mv_sync_cpu",
                "mv_sync_device",
            ]),
            &[30, 10, 40, 20],
        );
        assert!(got.ok);
        assert_eq!(got.bounce, 10);
        assert_eq!(got.exit_misses, 30);
        assert_eq!(got.sync_device, 20);
        assert_eq!(got.sync_cpu, 40);
    }

    #[test]
    fn identify_copy_count() {
        let got = identify_copy_progs(&names(&["mv_bounce"]), &[1]);
        assert!(!got.ok);
        assert_eq!(got.message, "copy program count");
    }

    #[test]
    fn identify_copy_ambiguous() {
        let got = identify_copy_progs(
            &names(&["mv_bounce", "mv_bounce", "mv_sync_cpu", "mv_sync_device"]),
            &[1, 2, 3, 4],
        );
        assert!(!got.ok);
        assert_eq!(got.message, "copy program ambiguous");
    }

    #[test]
    fn identify_copy_unexpected() {
        let got = identify_copy_progs(
            &names(&["mv_bounce", "mv_nope", "mv_sync_cpu", "mv_sync_device"]),
            &[1, 2, 3, 4],
        );
        assert!(!got.ok);
        assert_eq!(got.message, "copy program unexpected");
    }

    #[test]
    fn identify_lifecycle_ok() {
        let got = identify_lifecycle_progs(&names(&["mv_unmap", "mv_map_result"]), &[7, 5]);
        assert!(got.ok);
        assert_eq!(got.map_misses, 5);
        assert_eq!(got.unmap_misses, 7);
    }

    #[test]
    fn identify_lifecycle_count() {
        let got = identify_lifecycle_progs(&names(&["mv_unmap"]), &[7]);
        assert!(!got.ok);
        assert_eq!(got.message, "lifecycle program count");
    }

    #[test]
    fn identify_lifecycle_ambiguous() {
        let got = identify_lifecycle_progs(&names(&["mv_unmap", "mv_unmap"]), &[7, 8]);
        assert!(!got.ok);
        assert_eq!(got.message, "lifecycle program ambiguous");
    }

    #[test]
    fn identify_lifecycle_unexpected() {
        let got = identify_lifecycle_progs(&names(&["mv_unmap", "mv_nope"]), &[7, 8]);
        assert!(!got.ok);
        assert_eq!(got.message, "lifecycle program unexpected");
    }

    #[test]
    fn fb_valid_matrix() {
        assert!(fb_valid(&[10, 10, 0]));
        assert!(!fb_valid(&[10, 10, 1]));
        assert!(!fb_valid(&[10, 10]));
    }

    #[test]
    fn fb_flag_reason_matrix() {
        assert_eq!(fb_flag_reason(0), "");
        assert_eq!(fb_flag_reason(1), "fallback counters wrapped");
        assert_eq!(fb_flag_reason(4), "fallback frame lost");
        assert_eq!(
            fb_flag_reason(5),
            "fallback counters wrapped; fallback frame lost"
        );
        assert_eq!(fb_flag_reason(8), "fallback flags invalid");
    }

    #[test]
    fn channel_orders() {
        assert_eq!(channel_attach_order(), vec![2, 1, 0]);
        assert_eq!(channel_detach_order(), vec![0, 1, 2]);
        assert_eq!(rollback_order(&[2, 1]), vec![1, 2]);
        assert_eq!(rollback_order(&[2]), vec![2]);
        assert!(rollback_order(&[]).is_empty());
    }

    #[test]
    fn join_op_message_accumulates() {
        assert_eq!(join_op_message("", 0, "a"), "ch0 a");
        assert_eq!(join_op_message("ch0 a", 2, "b"), "ch0 a; ch2 b");
    }

    #[test]
    fn os_errno_matrix() {
        assert_eq!(
            os_errno("attempt channel: load failed: program error: x (os error 13)"),
            Some(13)
        );
        assert_eq!(os_errno("no errno here"), None);
        assert_eq!(os_errno("not an error (os error x)"), None);
        // Last occurrence wins.
        assert_eq!(os_errno("(os error 2) then (os error 22)"), Some(22));
    }

    #[test]
    fn session_message_shapes() {
        // Syscall failures carry op/domain/code + errno name.
        let err = SessionError::Load(
            "attempt channel: load failed: the BPF_PROG_LOAD syscall returned Permission denied (os error 13). Verifier output: ".to_string(),
        );
        let got = session_message(2, &err);
        assert!(got.contains("op=2 domain=2 code=-13 EACCES"), "{got}");
        assert!(got.contains("verifier rejected, see log"), "{got}");
        // The refusal classifier reads the same vocabulary.
        assert_eq!(
            crate::capture::loadcheck::load_refusal_code(&got),
            "verifier-rejected"
        );
        // Non-syscall failures carry op/domain without a code.
        let err2 = SessionError::Geometry("channel ring is not a ring buffer".to_string());
        let got2 = session_message(2, &err2);
        assert!(got2.contains("op=2 domain=2:"), "{got2}");
        assert!(!got2.contains("code="));
        assert_eq!(crate::capture::loadcheck::load_refusal_code(&got2), "");
    }

    #[test]
    fn encode_roundtrip_attempt() {
        use crate::capture::collector::script::attempt_payload;
        use memveil_ebpf_common::decode_attempt;
        let raw = attempt_payload(7, 8001, 512, "sda");
        let decoded = decode_attempt(&raw).expect("decode");
        let back = encode_frame(&Frame::Attempt(decoded));
        assert_eq!(back, raw);
        // Forced flag round-trips too.
        let mut raw2 = attempt_payload(9, 8002, 64, "nvme0n1");
        raw2[6] = 1;
        let decoded2 = decode_attempt(&raw2).expect("decode");
        assert!(decoded2.force);
        assert_eq!(encode_frame(&Frame::Attempt(decoded2)), raw2);
    }

    #[test]
    fn encode_roundtrip_lifecycle() {
        use crate::capture::collector::script::lc_raw;
        use memveil_ebpf_common::decode_lifecycle;
        for (kind, flags, dir, generation) in [
            (1u64, 1u64, 1u64, 41u64),
            (1, 9, 1, 0),
            (2, 3, 2, 9),
            (2, 7, 2, 0),
        ] {
            let raw = lc_raw(kind, flags, dir, 121, 1021, 4096, generation);
            let decoded = decode_lifecycle(&raw).expect("decode");
            assert_eq!(encode_frame(&Frame::Lifecycle(decoded)), raw);
        }
    }

    #[test]
    fn encode_roundtrip_copy() {
        use crate::capture::collector::script::cp_raw;
        use memveil_ebpf_common::decode_copy;
        for (kind, flags, dir, reason) in [
            (1u64, 1u64, 1u64, 4u64),
            (2, 3, 1, 0u64),
            (2, 7, 1, 0u64),
            (2, 55, 2, 0u64),
            (2, 11, 1, 0u64),
        ] {
            let effective = if flags == 11 { 0 } else { 1024 };
            let raw = cp_raw(kind, flags, dir, 101, 1001, 4096, effective, reason);
            let decoded = decode_copy(&raw).expect("decode");
            assert_eq!(encode_frame(&Frame::Copy(decoded)), raw);
        }
    }

    #[test]
    fn not_open_taxonomy() {
        // Calls before open refuse without touching the loader.
        let mut kernel = AyaKernel::new(vec![1, 2, 3], "mv_attempts", "p", "s", "e");
        assert_eq!(kernel.channel_count(), 1);
        assert_eq!(kernel.poll(0, 64).message, "session not open");
        assert_eq!(kernel.poll(0, 64).kind, "error");
        assert_eq!(kernel.stats_at(-1).message, "bad channel");
        assert_eq!(kernel.stats_at(3).message, "bad channel");
        assert_eq!(kernel.read_full_at(-1).message, "bad channel");
        assert_eq!(kernel.map_info_at(9, "mv_counts").message, "bad channel");
        assert!(!kernel.install_offsets(&[0u8; 24]).ok);
        assert_eq!(kernel.set_copy_armed(true).message, "session not open");
        // Bare any-open guards, mirroring the Mojo taxonomy.
        assert!(!kernel.load().ok);
        assert_eq!(kernel.load().message, "session not open");
        assert!(!kernel.map_info("mv_counts").ok);
        assert_eq!(kernel.attach().message, "session not open");
        assert!(!kernel.stats().ok);
        assert_eq!(kernel.stats().message, "session not open");
        assert!(!kernel.read_full().ok);
        assert_eq!(kernel.detach().message, "session not open");
        // Idempotent close succeeds.
        assert!(kernel.close().ok);
    }

    #[test]
    fn multi_not_open_taxonomy() {
        let mut kernel = AyaKernel::with_channels(vec![1], "s", "e", vec![2], true, vec![3], true);
        assert_eq!(kernel.channel_count(), 3);
        // Copy-without-lifecycle counts present channels (2),
        // not the highest present one.
        let sparse = AyaKernel::with_channels(vec![1], "s", "e", vec![], false, vec![3], true);
        assert_eq!(sparse.channel_count(), 2);
        // Present but unopened channels refuse with session state, not bad channel.
        assert_eq!(kernel.stats_at(1).message, "session not open");
        assert_eq!(kernel.stats_at(2).message, "session not open");
        assert_eq!(kernel.read_full_at(1).message, "session not open");
        assert_eq!(
            kernel.map_info_at(2, "mv_counts").message,
            "session not open"
        );
        // Detach before open hits the bare any-open guard.
        let detached = kernel.detach();
        assert!(!detached.ok);
        assert_eq!(detached.message, "session not open");
    }

    #[test]
    fn open_failure_shape() {
        // A garbage ELF fails open with op detail; rollback stays clean.
        let mut kernel = AyaKernel::with_channels(
            vec![0x7F, b'E', b'L', b'F', 9, 9, 9, 9],
            "s",
            "e",
            vec![9],
            true,
            vec![9],
            true,
        );
        let opened = kernel.open_session();
        assert!(!opened.ok);
        assert!(opened.message.contains("op="), "{}", opened.message);
        assert!(opened.message.contains("ch0 "), "{}", opened.message);
        assert!(kernel.close().ok);
    }

    #[test]
    fn install_table_shape_checked_before_open() {
        let mut kernel = AyaKernel::new(vec![1, 2, 3], "mv_attempts", "p", "s", "e");
        // Session state precedes table shape.
        assert_eq!(
            kernel.install_offsets(&[0u8; 3]).message,
            "session not open"
        );
    }

    #[test]
    fn open_ok_install_shape_checked() {
        // A real ELF fixture opens unprivileged; table shape still gates install.
        let path = crate::platform::test_support::repo_root().join("tests/fixtures/elf/ok.o");
        let elf = std::fs::read(&path).expect("read ok.o");
        let mut kernel = AyaKernel::new(
            elf,
            "mv_attempts",
            "mv_swiotlb_attempt",
            "swiotlb",
            "swiotlb_bounced",
        );
        let opened = kernel.open_session();
        assert!(opened.ok, "{}", opened.message);
        assert_eq!(
            kernel.install_offsets(&[0u8; 3]).message,
            "bad offsets table"
        );
        assert_eq!(
            kernel.install_offsets(&[0u8; 24]).message,
            "bad offsets table"
        );
        // A second open hits the bare any-open guard.
        assert_eq!(kernel.open_session().message, "session already open");
        assert!(kernel.close().ok);
    }

    #[test]
    fn load_eperm_unprivileged() {
        // Loading the fixture without privilege fails with the EPERM code.
        if unsafe { libc::geteuid() } == 0 {
            eprintln!("SKIP load_eperm_unprivileged: running as root");
            return;
        }
        let path = crate::platform::test_support::repo_root().join("tests/fixtures/elf/ok.o");
        let elf = std::fs::read(&path).expect("read ok.o");
        let mut kernel = AyaKernel::new(
            elf,
            "mv_attempts",
            "mv_swiotlb_attempt",
            "swiotlb",
            "swiotlb_bounced",
        );
        assert!(kernel.open_session().ok);
        let loaded = kernel.load();
        assert!(!loaded.ok);
        assert!(loaded.message.contains("code=-1"), "{}", loaded.message);
        assert_eq!(
            crate::capture::loadcheck::load_refusal_code(&loaded.message),
            "load-eperm"
        );
        let _ = kernel.close();
    }

    #[test]
    fn live_refuse_without_kernel() {
        // The collector over a live kernel with an unloadable
        // object refuses cleanly: exit 3, no output dir.
        use crate::capture::collector::{Collector, CollectorConfig};
        use crate::capture::live::LiveWriter;
        use crate::platform::clock::MonoClock;
        use crate::platform::signal::LiveSignalSource;
        let tmp =
            crate::platform::test_support::TestDir::create("memveil-live-refuse").expect("mkdtemp");
        let dir = format!("{}/cap", tmp.as_str());
        let cfg = CollectorConfig {
            output: dir.clone(),
            profile_id: "probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = AyaKernel::new(
            vec![0x7F, b'E', b'L', b'F', 9, 9, 9, 9],
            "mv_attempts",
            "mv_swiotlb_attempt",
            "swiotlb",
            "swiotlb_bounced",
        );
        let mut clock = MonoClock::new();
        let mut signal = LiveSignalSource::new();
        let mut writer = LiveWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, 3);
        assert_eq!(result.outcome, "refused");
        assert!(!std::path::Path::new(&dir).exists());
    }

    #[test]
    fn attach_fd_diff_records_progs() {
        // Scripted attach-time appearance: new prog fds become known.
        let mut slot = ChannelSlot::new();
        let before = Some(vec![3, 4]);
        let after = Some(vec![3, 4, 9, 10]);
        slot.note_attach_progs(&before, &after);
        assert_eq!(slot.progs, vec![9, 10]);
        assert!(slot.progs_known);
    }

    #[test]
    fn attach_fd_diff_empty_stays_unknown() {
        // No new fds at attach: misses stay fail-closed.
        let mut slot = ChannelSlot::new();
        let before = Some(vec![3, 4]);
        let after = Some(vec![3, 4]);
        slot.note_attach_progs(&before, &after);
        assert!(slot.progs.is_empty());
        assert!(!slot.progs_known);
    }

    #[test]
    fn attach_fd_diff_unlistable_keeps_state() {
        // An unlistable fd table leaves prior state untouched.
        let mut slot = ChannelSlot::new();
        slot.note_attach_progs(&None, &None);
        assert!(!slot.progs_known);
        let before = Some(vec![3]);
        slot.note_attach_progs(&before, &None);
        assert!(slot.progs.is_empty());
        assert!(!slot.progs_known);
    }

    #[test]
    fn attach_fd_diff_reattach_keeps_prior() {
        // Detach leaves loads behind, so a reattach that adds no
        // fds keeps the previously identified programs.
        let mut slot = ChannelSlot::new();
        let before = Some(vec![3]);
        let after = Some(vec![3, 9]);
        slot.note_attach_progs(&before, &after);
        assert!(slot.progs_known);
        let re_before = Some(vec![3, 9]);
        let re_after = Some(vec![3, 9]);
        slot.note_attach_progs(&re_before, &re_after);
        assert_eq!(slot.progs, vec![9]);
        assert!(slot.progs_known);
    }

    #[test]
    fn misses_unknown_before_attach() {
        // End to end over a real (unprivileged-open) session: with
        // no attach-time fd appearance, misses fail closed, root or
        // not (load may succeed as root but records nothing).
        let path = crate::platform::test_support::repo_root().join("tests/fixtures/elf/ok.o");
        let elf = std::fs::read(&path).expect("read ok.o");
        let mut kernel = AyaKernel::new(
            elf,
            "mv_attempts",
            "mv_swiotlb_attempt",
            "swiotlb",
            "swiotlb_bounced",
        );
        assert!(kernel.open_session().ok);
        let _ = kernel.load();
        let m = kernel.recursion_misses();
        assert!(!m.ok);
        assert!(m.message.contains("program fds unknown"), "{}", m.message);
        let _ = kernel.close();
    }

    fn elf_fixture(name: &str) -> Vec<u8> {
        let path = crate::platform::test_support::repo_root().join("tests/fixtures/elf/ok.o");
        let dir = path.parent().expect("fixture dir").to_path_buf();
        std::fs::read(dir.join(name)).unwrap_or_else(|_| panic!("read {name}"))
    }

    #[test]
    fn lifecycle_misses_failure_keeps_attempt_known() {
        // Live-path regression: a lifecycle detail failure voids
        // only the detail side (ok:true + detail_error), so the
        // collector keeps the exact attempt aggregate instead of
        // voiding it with an empty reason (Mojo parity).
        let mut kernel = AyaKernel::with_channels(
            elf_fixture("ok.o"),
            "swiotlb",
            "swiotlb_bounced",
            elf_fixture("lc-ok.o"),
            true,
            Vec::new(),
            false,
        );
        assert!(kernel.open_session().ok);
        // Attempt counted zero programs; lifecycle never attached.
        kernel.ch0.progs_known = true;
        let m = kernel.recursion_misses();
        assert!(m.ok, "detail failure must keep ok:true: {m:?}");
        assert!(m.message.is_empty());
        assert_eq!(m.attempt, 0);
        assert_eq!(m.detail_error, "ch1 program fds unknown");
        let _ = kernel.close();
    }

    #[test]
    fn lifecycle_identify_failure_keeps_attempt_known() {
        // Same ladder through misses_lifecycle: unidentifiable
        // programs (here: zero known fds) report the detail
        // cause with ok:true.
        let mut kernel = AyaKernel::with_channels(
            elf_fixture("ok.o"),
            "swiotlb",
            "swiotlb_bounced",
            elf_fixture("lc-ok.o"),
            true,
            elf_fixture("cp-ok.o"),
            true,
        );
        assert!(kernel.open_session().ok);
        kernel.ch0.progs_known = true;
        kernel.ch1.progs_known = true;
        let m = kernel.recursion_misses();
        assert!(m.ok, "detail failure must keep ok:true: {m:?}");
        assert!(m.message.is_empty());
        assert_eq!(m.attempt, 0);
        assert_eq!(m.detail_error, "ch1 lifecycle program count");
        let _ = kernel.close();
    }

    #[test]
    fn copy_identify_failure_keeps_attempt_known() {
        // Copy-without-lifecycle through misses_copy: same
        // ok:true + detail_error shape.
        let mut kernel = AyaKernel::with_channels(
            elf_fixture("ok.o"),
            "swiotlb",
            "swiotlb_bounced",
            Vec::new(),
            false,
            elf_fixture("cp-ok.o"),
            true,
        );
        assert!(kernel.open_session().ok);
        kernel.ch0.progs_known = true;
        kernel.ch2.progs_known = true;
        let m = kernel.recursion_misses();
        assert!(m.ok, "detail failure must keep ok:true: {m:?}");
        assert!(m.message.is_empty());
        assert_eq!(m.attempt, 0);
        assert_eq!(m.detail_error, "ch2 copy program count");
        let _ = kernel.close();
    }

    #[test]
    fn ch0_misses_failure_carries_channel_tag() {
        // Mojo tags the attempt-misses failure ("ch0 " prefix,
        // zero count); the bare message below the tag pins it.
        let mut kernel = AyaKernel::new(vec![1, 2, 3], "mv_attempts", "p", "s", "e");
        let m = kernel.recursion_misses();
        assert!(!m.ok);
        assert_eq!(m.count, 0);
        assert_eq!(m.message, "ch0 session not open");
        let _ = kernel.close();
    }

    #[test]
    fn fb_detail_strings_match_mojo_taxonomy() {
        // A failed fallback read keeps the `fallback: ` infix;
        // invalid counters join the flag reason (or the
        // short-read marker) to the tag directly.
        assert_eq!(
            fb_read_detail("short fallback read"),
            "ch2 fallback: short fallback read"
        );
        assert_eq!(
            fb_invalid_detail(&[7, 7, 3]),
            "ch2 fallback counters wrapped"
        );
        assert_eq!(fb_invalid_detail(&[7, 7, 4]), "ch2 fallback frame lost");
        assert_eq!(fb_invalid_detail(&[7, 7]), "ch2 short fallback read");
    }

    #[test]
    fn rollback_piece_names_rollback_channel() {
        // Attach rollback joins "; rollback ch{j}: msg", not the
        // plain channel tag (Mojo taxonomy).
        assert_eq!(
            rollback_piece("ch0 boom", 2, "gone"),
            "ch0 boom; rollback ch2: gone"
        );
    }

    #[test]
    fn live_invalid_fallback_keeps_attempt_known() {
        // Live-path regression for the invalid-fallback arm:
        // poisoned fallback flags report ok:true with the
        // infix-free detail string through a real load/attach.
        // SAFETY: pure id query.
        if unsafe { libc::geteuid() } != 0 {
            eprintln!("SKIP live_invalid_fallback_keeps_attempt_known: requires root");
            return;
        }
        let attempt = crate::platform::runtime::embedded_object("attempt").expect("embedded");
        let copy = crate::platform::runtime::embedded_object("copy").expect("embedded");
        let mut kernel = AyaKernel::with_channels(
            attempt.to_vec(),
            "swiotlb",
            "swiotlb_bounced",
            Vec::new(),
            false,
            copy.to_vec(),
            true,
        );
        if !kernel.open_session().ok {
            eprintln!("SKIP live_invalid_fallback_keeps_attempt_known: embedded open refused");
            return;
        }
        if !kernel.load().ok {
            eprintln!("SKIP live_invalid_fallback_keeps_attempt_known: load refused here");
            let _ = kernel.close();
            return;
        }
        if !kernel.attach().ok {
            eprintln!("SKIP live_invalid_fallback_keeps_attempt_known: attach refused here");
            let _ = kernel.close();
            return;
        }
        assert!(kernel.detach().ok);
        // Poison the fallback flags slot; the counters stay valid.
        kernel
            .ch2
            .sess
            .as_mut()
            .expect("open session")
            .map_write("mv_copy_fb", 2, &4u64.to_le_bytes())
            .expect("poison fallback flags");
        let m = kernel.recursion_misses();
        assert!(m.ok, "detail failure must keep ok:true: {m:?}");
        assert!(m.message.is_empty());
        assert_eq!(m.detail_error, "ch2 fallback frame lost");
        let _ = kernel.close();
    }

    #[test]
    fn attach_failure_records_nothing() {
        // Attach-failure wiring: over a real (unprivileged-open)
        // session with load skipped, attach() fails
        // deterministically with NotLoaded before any privileged
        // call, records no program fds, and misses stay
        // fail-closed, root or not.
        let path = crate::platform::test_support::repo_root().join("tests/fixtures/elf/ok.o");
        let elf = std::fs::read(&path).expect("read ok.o");
        let mut kernel = AyaKernel::new(
            elf,
            "mv_attempts",
            "mv_swiotlb_attempt",
            "swiotlb",
            "swiotlb_bounced",
        );
        assert!(kernel.open_session().ok);
        let attached = kernel.attach();
        assert!(!attached.ok);
        assert!(
            attached.message.contains("session not loaded"),
            "{}",
            attached.message
        );
        let m = kernel.recursion_misses();
        assert!(!m.ok);
        assert!(m.message.contains("program fds unknown"), "{}", m.message);
        let _ = kernel.close();
    }
}
