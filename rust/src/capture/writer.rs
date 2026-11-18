// SPDX-License-Identifier: GPL-3.0-or-later
//! Capture file writer: exclusive creation, explicit-offset appends.
//!
//! mkdir-0700 output, O_EXCL events file, pwrite-throughout appends with a
//! size gate, ftruncate recovery, snapshot rollback groups, and an
//! fsync/renameat2-NOREPLACE/dir-fsync publication protocol.
//!
//! The writer reports mechanism outcomes ([`WriteError`] kinds and
//! [`FinalOutcome`]); the collector maps them to dispositions, result states,
//! and exits. Disposition buckets live in the collector, never here.

use crate::model::integrity::{Integrity, integrity_kind_index};
use crate::model::validate::checked_add;
use crate::platform::capturefiles::{file_stat, open_directory};
use crate::platform::hash::Sha256;

/// Smallest admissible events budget (128 KiB).
pub const MIN_EVENTS_BUDGET: u64 = 131072;
/// Largest admissible events budget (4 GiB).
pub const MAX_EVENTS_BUDGET: u64 = 4294967296;
/// Closing-record reserve past the attempt gate (64 KiB).
pub const CLOSING_RESERVE: u64 = 65536;
/// Preallocated finalization space (17 MiB).
pub(crate) const FINALIZE_RESERVE_BYTES: u64 = 17 * 1024 * 1024;
/// Stuck-artifact bit: the owned events file survived construction unwind.
pub const RESIDUAL_EVENTS: u8 = 1;
/// Stuck-artifact bit: the owned output dir survived construction unwind.
pub const RESIDUAL_DIR: u8 = 2;

/// One writer failure: `kind` routes the collector decision.
///
/// Kinds: exists (output present), budget (range), io (create/stat failure),
/// refused (size gate, no write attempted), append_failed (attempted append
/// failed; prefix recovered), fatal (unrecoverable mid-append), misuse (use
/// after finalize/close).
///
/// `residuals` is a bitmask of stuck construction artifacts, nonzero only
/// when creation failed and its unwind left owned artifacts behind. The
/// message keeps the failure cause alone; residual accounting reads the
/// typed field, never the message text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteError {
    /// Machine-stable failure kind.
    pub kind: String,
    /// Human detail; never matched on.
    pub message: String,
    /// Stuck-artifact bits ([`RESIDUAL_EVENTS`]/[`RESIDUAL_DIR`]).
    pub residuals: u8,
}

impl WriteError {
    /// Build an error with no residuals.
    pub fn new(kind: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            residuals: 0,
        }
    }

    /// Build an error carrying stuck-artifact bits (masked to known bits).
    pub fn with_residuals(
        kind: impl Into<String>,
        message: impl Into<String>,
        residuals: u8,
    ) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            residuals: residuals & 3,
        }
    }
}

impl std::fmt::Display for WriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "WriteError(kind={}, message={})",
            self.kind, self.message
        )
    }
}

impl std::error::Error for WriteError {}

/// Canonical stuck-artifact list for typed residual bits.
///
/// Bound: at most the two known construction artifacts, in fixed order
/// ("", "events", "dir", "events,dir"). Unknown bits are ignored so the
/// list can never name anything outside the owned construction artifacts.
pub fn residual_text(residuals: u8) -> String {
    match residuals & 3 {
        3 => "events,dir".to_string(),
        1 => "events".to_string(),
        2 => "dir".to_string(),
        _ => String::new(),
    }
}

/// One publication result.
///
/// Status: finalized (session published + synced), present_unsynced (rename
/// ok, dir or parent fsync failed), unfinalized (no session.json).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalOutcome {
    /// Machine-stable publication status.
    pub status: String,
    /// Human detail; never matched on.
    pub message: String,
}

/// Bounded accounting advanced only after a successful atomic append.
///
/// Copy before a write group; restore that copy only after successful file
/// rollback. A poisoned file must never publish this snapshot.
#[derive(Debug, Clone)]
pub struct CommittedStream {
    hash: Sha256,
    integrity: Integrity,
}

impl CommittedStream {
    /// An empty accounting state.
    pub fn new() -> Self {
        Self {
            hash: Sha256::new(),
            integrity: Integrity::default(),
        }
    }

    /// Advance the accounting over one committed line of `kind`.
    pub fn commit(&mut self, line: &[u8], kind: &str) -> Result<(), String> {
        let Some(index) = integrity_kind_index(kind) else {
            return Err("invalid committed event kind or length".to_string());
        };
        if line.is_empty() || line.len() > 65536 {
            return Err("invalid committed event kind or length".to_string());
        }
        if line[line.len() - 1] != b'\n' {
            return Err("committed event lacks newline".to_string());
        }
        let byte_count = checked_add(self.integrity.events_bytes, line.len() as u64)
            .map_err(|e| e.to_string())?;
        let line_count = checked_add(self.integrity.line_count, 1).map_err(|e| e.to_string())?;
        self.hash.update(line);
        self.integrity.events_bytes = byte_count;
        self.integrity.line_count = line_count;
        self.integrity.has_seq = true;
        self.integrity.last_seq = line_count - 1;
        self.integrity.kinds[index] += 1;
        Ok(())
    }

    /// The current integrity snapshot over committed bytes.
    pub fn snapshot(&self) -> Integrity {
        let mut out = self.integrity.clone();
        out.events_sha256 = self.hash.copy_finish();
        out
    }
}

impl Default for CommittedStream {
    fn default() -> Self {
        Self::new()
    }
}

/// renameat2 flag: fail when the destination exists.
const RENAME_NOREPLACE: u32 = 1;
/// renameat2 flag: atomically exchange source and destination.
const RENAME_EXCHANGE: u32 = 2;
/// Largest checkpoint/session document (16 MiB).
const MAX_DOCUMENT_BYTES: usize = 16777216;
/// getdents64 buffer size.
const DIRENT_BUF_SIZE: usize = 8192;
/// d_name offset in the x86-64 Linux dirent.
const DIRENT_NAME_OFF: usize = 19;

fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn close_quiet(fd: i32) {
    if fd >= 0 {
        // SAFETY: owned-or-negative fd; best effort.
        unsafe {
            libc::close(fd);
        }
    }
}

fn writer_cstr(text: &str) -> Result<Vec<u8>, WriteError> {
    let mut out = Vec::with_capacity(text.len() + 1);
    for &b in text.as_bytes() {
        if b == 0 {
            return Err(WriteError::new("io", "NUL byte in path"));
        }
        out.push(b);
    }
    out.push(0);
    Ok(out)
}

/// Split an output path into (parent, base) without touching the filesystem.
fn split_parent(path: &str) -> (String, String) {
    let raw = path.as_bytes();
    let mut end = raw.len();
    while end > 1 && raw[end - 1] == b'/' {
        end -= 1;
    }
    let mut cut: Option<usize> = None;
    let mut i = end;
    while i > 0 {
        i -= 1;
        if raw[i] == b'/' {
            cut = Some(i);
            break;
        }
    }
    match cut {
        None => (
            ".".to_string(),
            String::from_utf8_lossy(&raw[..end]).into_owned(),
        ),
        Some(0) => (
            "/".to_string(),
            String::from_utf8_lossy(&raw[1..end]).into_owned(),
        ),
        Some(c) => (
            String::from_utf8_lossy(&raw[..c]).into_owned(),
            String::from_utf8_lossy(&raw[c + 1..end]).into_owned(),
        ),
    }
}

/// `[dev, ino, nlink]` identity pins for an open fd.
fn fstat_ids(fd: i32) -> Result<[u64; 3], WriteError> {
    let ids = stat_fd(fd)?;
    Ok([ids[0], ids[1], ids[2]])
}

fn stat_fd(fd: i32) -> Result<[u64; 7], WriteError> {
    let ids = file_stat(fd).map_err(|e| WriteError::new("io", e.message))?;
    #[cfg(test)]
    let ids = faults::sparse_adjust(ids);
    Ok(ids)
}

/// True when `name` under `dir_fd` resolves to `want`.
///
/// O_PATH|O_NOFOLLOW probe plus dev/ino compare; false on any failure
/// (missing, replaced, symlink, bad fd).
fn name_matches(dir_fd: i32, name: &str, want: &[u64; 3]) -> bool {
    let Ok(cname) = writer_cstr(name) else {
        return false;
    };
    // SAFETY: NUL-terminated name on a possibly-live dir fd.
    let probe = unsafe {
        libc::openat(
            dir_fd,
            cname.as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_NOFOLLOW,
            0 as libc::c_uint,
        )
    };
    if probe < 0 {
        return false;
    }
    let ids = fstat_ids(probe);
    close_quiet(probe);
    match ids {
        Ok(ids) => ids[0] == want[0] && ids[1] == want[1],
        Err(_) => false,
    }
}

/// True when `name` under `dir_fd` opens (no symlink follow).
fn name_exists(dir_fd: i32, name: &str) -> bool {
    let Ok(cname) = writer_cstr(name) else {
        return false;
    };
    // SAFETY: as above.
    let probe = unsafe {
        libc::openat(
            dir_fd,
            cname.as_ptr().cast::<libc::c_char>(),
            libc::O_PATH | libc::O_NOFOLLOW,
            0 as libc::c_uint,
        )
    };
    if probe < 0 {
        return false;
    }
    close_quiet(probe);
    true
}

fn sys_pwrite(fd: i32, buf: *const u8, len: usize, offset: i64, _tag: &'static str) -> i64 {
    #[cfg(test)]
    if let Some(outcome) = faults::pwrite_hook(_tag, len) {
        return outcome;
    }
    // SAFETY: caller guarantees buf/len readable; the offset is absolute.
    unsafe { libc::pwrite(fd, buf.cast::<libc::c_void>(), len, offset) as i64 }
}

fn sys_fsync(fd: i32, _tag: &'static str) -> i32 {
    #[cfg(test)]
    if let Some(outcome) = faults::fsync_hook(_tag) {
        return outcome;
    }
    // SAFETY: partner-checked fd; errors surface as -1.
    unsafe { libc::fsync(fd) }
}

fn sys_ftruncate(fd: i32, len: i64, _tag: &'static str) -> i32 {
    #[cfg(test)]
    if let Some(outcome) = faults::truncate_hook(_tag) {
        return outcome;
    }
    // SAFETY: as above.
    unsafe { libc::ftruncate(fd, len) }
}

fn sys_renameat2(
    dir_fd: i32,
    old: *const u8,
    new: *const u8,
    flags: u32,
    _new_tag: &'static str,
) -> i32 {
    #[cfg(test)]
    if let Some(outcome) = faults::rename_hook(_new_tag) {
        return outcome;
    }
    // SAFETY: NUL-terminated names on a live dir fd.
    unsafe {
        libc::renameat2(
            dir_fd,
            old.cast::<libc::c_char>(),
            dir_fd,
            new.cast::<libc::c_char>(),
            flags,
        )
    }
}

fn sys_fallocate(fd: i32, offset: i64, len: i64) -> i32 {
    #[cfg(test)]
    if let Some(errno) = faults::fallocate_hook() {
        return errno;
    }
    // SAFETY: live reserve fd; returns an errno-style status.
    unsafe { libc::posix_fallocate(fd, offset, len) }
}

fn sys_unlinkat(dir_fd: i32, name: *const u8, flags: i32, _tag: &'static str) -> i32 {
    #[cfg(test)]
    faults::trace("remove", _tag);
    // SAFETY: NUL-terminated name on a possibly-live dir fd.
    unsafe { libc::unlinkat(dir_fd, name.cast::<libc::c_char>(), flags) }
}

/// One capture's events file, from mkdir through finalize.
///
/// All-or-nothing creation: a failed [`EventWriter::new`] leaves no
/// residuals (only owned artifacts are removed). Use [`EventWriter::abandon`]
/// for pre-readiness collector rollback.
#[derive(Debug)]
pub struct EventWriter {
    dir_path: String,
    parent_path: String,
    base_name: String,
    parent_fd: i32,
    dir_fd: i32,
    ev_fd: i32,
    dir_ids: [u64; 3],
    ev_ids: [u64; 3],
    reserve_fd: i32,
    stage_fd: i32,
    reserve_ids: Option<[u64; 3]>,
    stage_ids: Option<[u64; 3]>,
    checkpoint_ids: Option<[u64; 3]>,
    prepared: bool,
    sess_ids: Option<[u64; 3]>,
    group_mark: Option<u64>,
    committed: u64,
    max: u64,
    finalized: bool,
    closed: bool,
}

impl EventWriter {
    /// Create the capture directory and its events file.
    pub fn new(dir_path: &str, max_events_bytes: u64) -> Result<Self, WriteError> {
        if !(MIN_EVENTS_BUDGET..=MAX_EVENTS_BUDGET).contains(&max_events_bytes) {
            return Err(WriteError::new(
                "budget",
                format!("events budget {max_events_bytes} outside 128 KiB..4 GiB"),
            ));
        }
        let (parent_path, base_name) = split_parent(dir_path);
        let parent_fd =
            open_directory(&parent_path).map_err(|e| WriteError::new("io", e.message))?;
        let base_cstr = match writer_cstr(&base_name) {
            Ok(base) => base,
            Err(e) => {
                close_quiet(parent_fd);
                return Err(e);
            }
        };
        // SAFETY: NUL-terminated base on a live parent fd.
        let made = unsafe { libc::mkdirat(parent_fd, base_cstr.as_ptr().cast(), 0o700) };
        if made != 0 {
            let no = errno_now();
            close_quiet(parent_fd);
            if no == libc::EEXIST {
                return Err(WriteError::new("exists", "output exists"));
            }
            return Err(WriteError::new("io", format!("mkdir failed: errno {no}")));
        }
        // SAFETY: as above.
        let dir_fd = unsafe {
            libc::openat(
                parent_fd,
                base_cstr.as_ptr().cast::<libc::c_char>(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        if dir_fd < 0 {
            let no = errno_now();
            sys_unlinkat(parent_fd, base_cstr.as_ptr(), libc::AT_REMOVEDIR, "dir");
            close_quiet(parent_fd);
            return Err(WriteError::new(
                "io",
                format!("dir open failed: errno {no}"),
            ));
        }
        if let Err(e) = require_private_empty_dir(dir_fd) {
            // A refusal ("exists") proves the name holds a foreign dir
            // swapped in after our mkdir: leave it untouched (never unlink
            // what we did not create) and close up. A check failure ("io")
            // leaves an unprovable dir behind: attempt the same by-name
            // rmdir unwind as a failed open so no residual stands behind
            // the error.
            if e.kind != "exists" {
                sys_unlinkat(parent_fd, base_cstr.as_ptr(), libc::AT_REMOVEDIR, "dir");
            }
            close_quiet(dir_fd);
            close_quiet(parent_fd);
            return Err(e);
        }
        // SAFETY: live dir fd.
        if unsafe { libc::flock(dir_fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            close_quiet(dir_fd);
            close_quiet(parent_fd);
            return Err(WriteError::new("io", "capture directory lock unavailable"));
        }
        let ev_name = writer_cstr("events.ndjson")?;
        // SAFETY: NUL-terminated name on a live dir fd.
        let ev_fd = unsafe {
            libc::openat(
                dir_fd,
                ev_name.as_ptr().cast::<libc::c_char>(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if ev_fd < 0 {
            let no = errno_now();
            close_quiet(dir_fd);
            sys_unlinkat(parent_fd, base_cstr.as_ptr(), libc::AT_REMOVEDIR, "dir");
            close_quiet(parent_fd);
            return Err(WriteError::new(
                "io",
                format!("events create failed: errno {no}"),
            ));
        }
        let dir_ids = match fstat_ids(dir_fd) {
            Ok(ids) => ids,
            Err(e) => {
                return Err(Self::unwind_failed_pins(
                    parent_fd, dir_fd, ev_fd, &base_cstr, e,
                ));
            }
        };
        let ev_ids = match fstat_ids(ev_fd) {
            Ok(ids) => ids,
            Err(e) => {
                return Err(Self::unwind_failed_pins(
                    parent_fd, dir_fd, ev_fd, &base_cstr, e,
                ));
            }
        };
        Ok(Self {
            dir_path: dir_path.to_string(),
            parent_path,
            base_name,
            parent_fd,
            dir_fd,
            ev_fd,
            dir_ids,
            ev_ids,
            reserve_fd: -1,
            stage_fd: -1,
            reserve_ids: None,
            stage_ids: None,
            checkpoint_ids: None,
            prepared: false,
            sess_ids: None,
            group_mark: None,
            committed: 0,
            max: max_events_bytes,
            finalized: false,
            closed: false,
        })
    }

    /// Unwind owned artifacts after a construction pin failure.
    fn unwind_failed_pins(
        parent_fd: i32,
        dir_fd: i32,
        ev_fd: i32,
        base_cstr: &[u8],
        cause: WriteError,
    ) -> WriteError {
        // Construction never published: unwind the owned events file and
        // dir before closing, so a pin failure leaves no orphaned
        // artifacts. No pins exist yet to compare against, so the window
        // is the microseconds since O_EXCL creation. Unwind failures ride
        // along as typed residual bits in the raised error: no writer
        // exists to carry residuals, and the message keeps the cause
        // alone.
        let mut stuck_events = false;
        if let Ok(ev_name) = writer_cstr("events.ndjson") {
            let r = sys_unlinkat(dir_fd, ev_name.as_ptr(), 0, "events.ndjson");
            if r != 0 && errno_now() != libc::ENOENT {
                stuck_events = true;
            }
        } else {
            stuck_events = true;
        }
        let mut stuck_dir = false;
        let rdir = sys_unlinkat(parent_fd, base_cstr.as_ptr(), libc::AT_REMOVEDIR, "dir");
        if rdir != 0 && errno_now() != libc::ENOENT {
            stuck_dir = true;
        }
        close_quiet(ev_fd);
        close_quiet(dir_fd);
        close_quiet(parent_fd);
        let mut bits = 0;
        if stuck_events {
            bits |= RESIDUAL_EVENTS;
        }
        if stuck_dir {
            bits |= RESIDUAL_DIR;
        }
        if bits != 0 {
            return WriteError::with_residuals(cause.kind, cause.message, bits);
        }
        cause
    }

    /// Allocate and sync actual finalization space before recording.
    pub fn prepare(&mut self) -> Result<(), WriteError> {
        self.check_open()?;
        if self.prepared {
            if !self.ready_files_ok() {
                return Err(WriteError::new(
                    "io",
                    "reserve or finalization staging identity changed",
                ));
            }
            return Ok(());
        }
        if !self.identity_ok() || !self.namespace_ok().is_empty() {
            return Err(WriteError::new(
                "io",
                "capture identity changed before reserve",
            ));
        }
        let (stage_fd, stage_ids) = self.create_owned("session.finalizing")?;
        self.stage_fd = stage_fd;
        self.stage_ids = Some(stage_ids);
        let (reserve_fd, reserve_ids) = self.create_owned(".finalization-reserve")?;
        self.reserve_fd = reserve_fd;
        self.reserve_ids = Some(reserve_ids);
        let size = FINALIZE_RESERVE_BYTES as i64;
        let allocated = sys_fallocate(self.reserve_fd, 0, size);
        if allocated != 0 {
            if allocated != libc::EOPNOTSUPP
                && allocated != libc::ENOSYS
                && allocated != libc::EINVAL
            {
                return Err(WriteError::new(
                    "io",
                    format!("reserve allocation failed: errno {allocated}"),
                ));
            }
            let block = [0u8; 65536];
            let mut offset = 0i64;
            while offset < size {
                let rest = (size - offset) as usize;
                let chunk = rest.min(block.len());
                // SAFETY: the zero block outlives the call.
                let n = sys_pwrite(
                    self.reserve_fd,
                    block.as_ptr(),
                    chunk,
                    offset,
                    ".finalization-reserve",
                );
                if n < 0 && errno_now() == libc::EINTR {
                    continue;
                }
                if n <= 0 {
                    return Err(WriteError::new("io", "reserve allocation write failed"));
                }
                offset += n;
            }
        }
        match stat_fd(self.reserve_fd) {
            Ok(stat) if stat[5] == size as u64 && stat[6] >= (size as u64) / 512 => {}
            _ => return Err(WriteError::new("io", "cannot verify allocated reserve")),
        }
        if sys_fsync(self.reserve_fd, ".finalization-reserve") != 0
            || sys_fsync(self.stage_fd, "session.finalizing") != 0
        {
            return Err(WriteError::new(
                "io",
                "reserve or finalization staging sync failed",
            ));
        }
        self.prepared = true;
        Ok(())
    }

    /// Publish by exchange, retaining the prior owned checkpoint until synced.
    pub fn checkpoint(&mut self, session: &[u8]) -> Result<(), WriteError> {
        self.check_open()?;
        if self.group_mark.is_some() {
            return Err(WriteError::new(
                "misuse",
                "checkpoint inside rollback group",
            ));
        }
        if session.len() > MAX_DOCUMENT_BYTES {
            return Err(WriteError::new("io", "checkpoint document too large"));
        }
        self.prepare()?;
        if !self.identity_ok() || !self.namespace_ok().is_empty() {
            return Err(WriteError::new(
                "io",
                "capture identity changed before checkpoint",
            ));
        }
        if sys_fsync(self.ev_fd, "events.ndjson") != 0 {
            return Err(WriteError::new("io", "checkpoint events sync failed"));
        }
        let (tmp, pin) = self.write_tmp("checkpoint.json.tmp", session)?;
        close_quiet(tmp);
        let old = writer_cstr("checkpoint.json.tmp")?;
        let dest = writer_cstr("checkpoint.json")?;
        let previous_ids = self.checkpoint_ids;
        let had_previous = previous_ids.is_some();
        if let Some(previous) = previous_ids
            && !name_matches(self.dir_fd, "checkpoint.json", &previous)
        {
            self.remove_tmp_if_owned("checkpoint.json.tmp", &pin);
            return Err(WriteError::new("io", "checkpoint replaced"));
        }
        if !name_matches(self.dir_fd, "checkpoint.json.tmp", &pin) {
            return Err(WriteError::new("io", "checkpoint staging replaced"));
        }
        let flags = if had_previous {
            RENAME_EXCHANGE
        } else {
            RENAME_NOREPLACE
        };
        if sys_renameat2(
            self.dir_fd,
            old.as_ptr(),
            dest.as_ptr(),
            flags,
            "checkpoint.json",
        ) != 0
        {
            self.remove_tmp_if_owned("checkpoint.json.tmp", &pin);
            return Err(WriteError::new("io", "checkpoint rename failed"));
        }
        let expected_swap = !had_previous
            || previous_ids.is_some_and(|p| name_matches(self.dir_fd, "checkpoint.json.tmp", &p));
        let ours = name_matches(self.dir_fd, "checkpoint.json", &pin);
        let mut synced = false;
        if expected_swap && ours {
            synced = sys_fsync(self.dir_fd, "dir") == 0 && sys_fsync(self.parent_fd, "parent") == 0;
        }
        if !synced {
            let mut restored = false;
            if ours {
                if had_previous {
                    restored = sys_renameat2(
                        self.dir_fd,
                        old.as_ptr(),
                        dest.as_ptr(),
                        RENAME_EXCHANGE,
                        "checkpoint.json",
                    ) == 0;
                } else {
                    restored = self.remove_tmp_if_owned("checkpoint.json", &pin);
                }
                if restored {
                    restored = sys_fsync(self.dir_fd, "dir") == 0
                        && sys_fsync(self.parent_fd, "parent") == 0;
                }
            }
            if restored && had_previous {
                self.remove_tmp_if_owned("checkpoint.json.tmp", &pin);
            }
            if !restored || !expected_swap || !ours {
                self.close_all();
                return Err(WriteError::new(
                    "fatal",
                    "checkpoint exchange, rollback or sync failed; writer poisoned",
                ));
            }
            return Err(WriteError::new("io", "checkpoint directory sync failed"));
        }
        self.checkpoint_ids = Some(pin);
        if let Some(previous) = previous_ids
            && (!self.remove_tmp_if_owned("checkpoint.json.tmp", &previous)
                || sys_fsync(self.dir_fd, "dir") != 0)
        {
            return Err(WriteError::new(
                "io",
                "previous checkpoint cleanup sync failed",
            ));
        }
        let checkpoint_ok = self
            .checkpoint_ids
            .is_some_and(|ids| name_matches(self.dir_fd, "checkpoint.json", &ids));
        if !self.identity_ok() || !self.namespace_ok().is_empty() || !checkpoint_ok {
            self.close_all();
            return Err(WriteError::new("fatal", "checkpoint namespace changed"));
        }
        Ok(())
    }

    /// Committed event-file bytes.
    pub fn committed_len(&self) -> u64 {
        self.committed
    }

    /// Dev/inode continuity for ownership repair, or empty.
    ///
    /// Returns [dir_dev, dir_ino, ev_dev, ev_ino, sess_dev, sess_ino] pinned
    /// at finalize, or an empty list when never finalized (or the session
    /// pin is missing). The repair compares every reopened descriptor
    /// against these before any fchown.
    pub fn finalized_identity(&self) -> Vec<u64> {
        let mut out = Vec::new();
        if !self.finalized {
            return out;
        }
        let Some(sess) = self.sess_ids else {
            return out;
        };
        out.extend([
            self.dir_ids[0],
            self.dir_ids[1],
            self.ev_ids[0],
            self.ev_ids[1],
            sess[0],
            sess[1],
        ]);
        out
    }

    /// Append one attempt line or raise.
    ///
    /// refused: attempt gate (nothing written). append_failed: attempted
    /// write failed, prefix recovered via ftruncate (zero-byte failures
    /// need no truncate). fatal: recovery itself failed.
    pub fn append(&mut self, line: &[u8]) -> Result<(), WriteError> {
        self.check_open()?;
        if self.committed.saturating_add(line.len() as u64) > self.max - CLOSING_RESERVE {
            return Err(WriteError::new(
                "refused",
                format!(
                    "size gate: {} over attempt budget",
                    self.committed.saturating_add(line.len() as u64)
                ),
            ));
        }
        self.write_line(line)
    }

    /// Append one closing line (snapshot/gap) or raise.
    ///
    /// Closing lines use the 64 KiB reserve: gated at the full budget, not
    /// the attempt gate. A refusal here means the reserve itself is
    /// exhausted (closing records are bounded small, so this needs a
    /// pathological budget or prefix, never normal flow).
    pub fn append_closing(&mut self, line: &[u8]) -> Result<(), WriteError> {
        self.check_open()?;
        if self.committed.saturating_add(line.len() as u64) > self.max {
            return Err(WriteError::new(
                "refused",
                format!(
                    "size gate: {} over closing budget",
                    self.committed.saturating_add(line.len() as u64)
                ),
            ));
        }
        self.write_line(line)
    }

    fn write_line(&mut self, line: &[u8]) -> Result<(), WriteError> {
        let mut done = 0usize;
        let total = line.len();
        let mut failed = false;
        let mut no = 0;
        while done < total {
            // SAFETY: the line outlives the call; the offset is absolute.
            let n = sys_pwrite(
                self.ev_fd,
                line.as_ptr().wrapping_add(done),
                total - done,
                (self.committed + done as u64) as i64,
                "events.ndjson",
            );
            if n < 0 {
                no = errno_now();
                if no == libc::EINTR {
                    continue;
                }
                failed = true;
                break;
            }
            if n == 0 {
                no = 0;
                failed = true;
                break;
            }
            done += n as usize;
        }
        if !failed {
            self.committed += total as u64;
            return Ok(());
        }
        if done == 0 {
            return Err(WriteError::new(
                "append_failed",
                format!("zero-byte append failed: errno {no}"),
            ));
        }
        if sys_ftruncate(self.ev_fd, self.committed as i64, "events.ndjson") != 0 {
            // Unrecoverable: the file holds bytes past committed that no
            // offset can resync. Close so no session can ever publish this
            // prefix.
            self.close_all();
            return Err(WriteError::new(
                "fatal",
                format!("torn append unrecoverable: errno {}", errno_now()),
            ));
        }
        Err(WriteError::new(
            "append_failed",
            format!("torn append recovered: errno {no}"),
        ))
    }

    /// Mark the pre-group offset for rollback.
    pub fn group_begin(&mut self) -> Result<u64, WriteError> {
        self.check_open()?;
        if self.group_mark.is_some() {
            return Err(WriteError::new("misuse", "nested rollback group"));
        }
        self.group_mark = Some(self.committed);
        Ok(self.committed)
    }

    /// Roll back to a group mark, erasing partial lines.
    ///
    /// Rollback failure closes the writer: the caller asked for atomicity
    /// and did not get it, so no session may publish this prefix
    /// (unfinalizable).
    pub fn group_abort(&mut self, mark: u64) -> Result<(), WriteError> {
        self.check_open()?;
        if mark > self.committed {
            return Err(WriteError::new("misuse", "bad group mark"));
        }
        if sys_ftruncate(self.ev_fd, mark as i64, "events.ndjson") != 0 {
            self.close_all();
            return Err(WriteError::new(
                "fatal",
                format!("group rollback failed: errno {}", errno_now()),
            ));
        }
        self.committed = mark;
        if self.group_mark.is_some_and(|g| mark <= g) {
            self.group_mark = None;
        }
        Ok(())
    }

    /// Publish session.json; single-shot, closes the writer.
    pub fn finalize(&mut self, session: &[u8]) -> Result<FinalOutcome, WriteError> {
        self.check_open()?;
        self.finalized = true;
        if !self.identity_ok() {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: "identity changed or unlinked".to_string(),
            });
        }
        let ns_note = self.namespace_ok();
        if !ns_note.is_empty() {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: ns_note,
            });
        }
        if self.prepared
            && let Err(e) = self.release_reserve()
        {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: e.message,
            });
        }
        if sys_fsync(self.ev_fd, "events.ndjson") != 0 {
            let no = errno_now();
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: format!("events fsync: errno {no}"),
            });
        }
        let (tmp_fd, tmp_ids) = match self.fill_or_write_stage(session) {
            Ok(v) => v,
            Err(e) => {
                // write_tmp cleans its own tmp on write/sync failures and
                // never unlinks on create failure (a pre-existing name is
                // foreign). A pin failure there also refuses finalization
                // here: the published session is always compared against
                // the creation-time identity.
                self.close_all();
                return Ok(FinalOutcome {
                    status: "unfinalized".to_string(),
                    message: e.message,
                });
            }
        };
        if let Some(fd) = tmp_fd {
            close_quiet(fd);
        }
        let stage_name = if self.prepared {
            "session.finalizing"
        } else {
            "session.json.tmp"
        };
        if self.prepared && !name_matches(self.dir_fd, stage_name, &tmp_ids) {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: "finalization staging replaced".to_string(),
            });
        }
        let Ok(old_name) = writer_cstr(stage_name) else {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: "NUL byte in path".to_string(),
            });
        };
        let Ok(new_name) = writer_cstr("session.json") else {
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: "NUL byte in path".to_string(),
            });
        };
        if sys_renameat2(
            self.dir_fd,
            old_name.as_ptr(),
            new_name.as_ptr(),
            RENAME_NOREPLACE,
            "session.json",
        ) != 0
        {
            let no = errno_now();
            let mut msg = format!("rename failed: errno {no}");
            if !self.remove_tmp_if_owned(stage_name, &tmp_ids) {
                msg.push_str("; tmp replacement left in place");
            }
            self.close_all();
            return Ok(FinalOutcome {
                status: "unfinalized".to_string(),
                message: msg,
            });
        }
        // Pin the published session file for ownership continuity: the
        // repair must compare reopened descriptors against these identities
        // before any fchown, so a substituted dir cannot transfer.
        match self.pin_published_session(&tmp_ids) {
            Ok(ids) => self.sess_ids = Some(ids),
            Err(message) => {
                self.close_all();
                return Ok(FinalOutcome {
                    status: "unfinalized".to_string(),
                    message,
                });
            }
        }
        if sys_fsync(self.dir_fd, "dir") != 0 {
            let no = errno_now();
            self.close_all();
            return Ok(FinalOutcome {
                status: "present_unsynced".to_string(),
                message: format!("dir fsync: errno {no}"),
            });
        }
        if sys_fsync(self.parent_fd, "parent") != 0 {
            let no = errno_now();
            self.close_all();
            return Ok(FinalOutcome {
                status: "present_unsynced".to_string(),
                message: format!("parent fsync: {}: errno {no}", self.parent_path),
            });
        }
        let session_ok = self
            .sess_ids
            .is_some_and(|ids| name_matches(self.dir_fd, "session.json", &ids));
        if !self.identity_ok() || !self.namespace_ok().is_empty() || !session_ok {
            self.close_all();
            return Ok(FinalOutcome {
                status: "present_unsynced".to_string(),
                message: "namespace changed after publication".to_string(),
            });
        }
        if let Some(checkpoint) = self.checkpoint_ids
            && (!self.remove_tmp_if_owned("checkpoint.json", &checkpoint)
                || sys_fsync(self.dir_fd, "dir") != 0)
        {
            self.close_all();
            return Ok(FinalOutcome {
                status: "present_unsynced".to_string(),
                message: "checkpoint cleanup failed after final publication".to_string(),
            });
        }
        self.close_all();
        Ok(FinalOutcome {
            status: "finalized".to_string(),
            message: String::new(),
        })
    }

    /// Close without publishing: events kept for forensics.
    ///
    /// Best-effort fsyncs the events file, then closes. No session.json is
    /// written. Idempotent.
    pub fn discard(&mut self) {
        if !self.closed {
            let _ = sys_fsync(self.ev_fd, "events.ndjson");
        }
        self.close_all();
    }

    /// Pre-readiness rollback: remove owned files, close up.
    ///
    /// Identity-gated: a name is removed only when it still resolves to
    /// the created file or dir (dev/ino via O_PATH|O_NOFOLLOW probes).
    /// Replacements and foreign files are preserved and reported. The tmp
    /// name is never removed here: finalize creates it and cleans its own
    /// tmp on every path, so any tmp seen at rollback is foreign. Returns
    /// "" when nothing is left behind, else a residual diagnostic. Never
    /// touches pre-existing paths: only the created dir and its events
    /// file.
    pub fn abandon(&mut self) -> String {
        if !name_matches(self.parent_fd, &self.base_name, &self.dir_ids) {
            self.close_all();
            return "output dir replaced or missing; left in place".to_string();
        }
        let mut leftovers = String::new();
        if let Some(ids) = self.reserve_ids
            && !self.remove_tmp_if_owned(".finalization-reserve", &ids)
        {
            leftovers.push_str("reserve replacement left in place; ");
        }
        if let Some(ids) = self.stage_ids
            && !self.remove_tmp_if_owned("session.finalizing", &ids)
        {
            leftovers.push_str("staging replacement left in place; ");
        }
        if let Some(ids) = self.checkpoint_ids
            && !self.remove_tmp_if_owned("checkpoint.json", &ids)
        {
            leftovers.push_str("checkpoint replacement left in place; ");
        }
        if name_matches(self.dir_fd, "events.ndjson", &self.ev_ids) {
            if let Ok(ev_name) = writer_cstr("events.ndjson") {
                sys_unlinkat(self.dir_fd, ev_name.as_ptr(), 0, "events.ndjson");
            }
        } else {
            leftovers = "events file replaced or missing; left in place".to_string();
        }
        if name_exists(self.dir_fd, "session.json.tmp") {
            if !leftovers.is_empty() {
                leftovers.push_str("; ");
            }
            leftovers.push_str("foreign session.json.tmp left in place");
        }
        let rmdir_failed = match writer_cstr(&self.base_name) {
            Ok(base) => {
                sys_unlinkat(self.parent_fd, base.as_ptr(), libc::AT_REMOVEDIR, "dir") != 0
                    && errno_now() != libc::ENOENT
            }
            Err(_) => true,
        };
        if rmdir_failed {
            if !leftovers.is_empty() {
                leftovers.push_str("; ");
            }
            leftovers.push_str(&format!("rmdir {} failed", self.dir_path));
        }
        self.close_all();
        leftovers
    }

    fn check_open(&self) -> Result<(), WriteError> {
        if self.closed || self.finalized {
            return Err(WriteError::new("misuse", "writer not open"));
        }
        Ok(())
    }

    fn create_owned(&self, name: &'static str) -> Result<(i32, [u64; 3]), WriteError> {
        let key = writer_cstr(name)?;
        // SAFETY: NUL-terminated name on a live dir fd.
        let fd = unsafe {
            libc::openat(
                self.dir_fd,
                key.as_ptr().cast::<libc::c_char>(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(WriteError::new(
                "io",
                format!("{name}: exclusive create failed"),
            ));
        }
        match fstat_ids(fd) {
            Ok(ids) => Ok((fd, ids)),
            Err(e) => {
                close_quiet(fd);
                Err(e)
            }
        }
    }

    fn ready_files_ok(&self) -> bool {
        let (Some(stage), Some(reserve)) = (self.stage_ids, self.reserve_ids) else {
            return false;
        };
        if !name_matches(self.dir_fd, "session.finalizing", &stage)
            || !name_matches(self.dir_fd, ".finalization-reserve", &reserve)
        {
            return false;
        }
        let (Ok(stage_stat), Ok(reserve_stat)) = (stat_fd(self.stage_fd), stat_fd(self.reserve_fd))
        else {
            return false;
        };
        // SAFETY: pure id query.
        let owner = unsafe { libc::geteuid() } as u64;
        if stage_stat[2] != 1 || reserve_stat[2] != 1 {
            return false;
        }
        if stage_stat[4] != owner || reserve_stat[4] != owner {
            return false;
        }
        if stage_stat[3] & 0o170000 != 0o100000 || reserve_stat[3] & 0o170000 != 0o100000 {
            return false;
        }
        stage_stat[5] == 0
            && reserve_stat[5] == FINALIZE_RESERVE_BYTES
            && reserve_stat[6] >= FINALIZE_RESERVE_BYTES / 512
    }

    fn release_reserve(&mut self) -> Result<(), WriteError> {
        if !self.ready_files_ok() {
            return Err(WriteError::new(
                "io",
                "reserve or finalization staging identity changed",
            ));
        }
        let reserve = self.reserve_ids.unwrap_or([0, 0, 0]);
        if !name_matches(self.dir_fd, ".finalization-reserve", &reserve) {
            return Err(WriteError::new("io", "finalization reserve replaced"));
        }
        if sys_ftruncate(self.reserve_fd, 0, ".finalization-reserve") != 0 {
            return Err(WriteError::new("io", "reserve release failed"));
        }
        if !self.remove_tmp_if_owned(".finalization-reserve", &reserve) {
            return Err(WriteError::new("io", "reserve removal failed"));
        }
        Ok(())
    }

    fn fill_stage(&mut self, data: &[u8]) -> Result<(), WriteError> {
        if data.len() > MAX_DOCUMENT_BYTES {
            return Err(WriteError::new("io", "session document too large"));
        }
        let stage = self.stage_ids.unwrap_or([0, 0, 0]);
        if !name_matches(self.dir_fd, "session.finalizing", &stage) {
            return Err(WriteError::new("io", "finalization staging replaced"));
        }
        if sys_ftruncate(self.stage_fd, 0, "session.finalizing") != 0 {
            return Err(WriteError::new(
                "io",
                "finalization staging truncate failed",
            ));
        }
        let mut done = 0usize;
        while done < data.len() {
            // SAFETY: the document outlives the call; the offset is absolute.
            let n = sys_pwrite(
                self.stage_fd,
                data.as_ptr().wrapping_add(done),
                data.len() - done,
                done as i64,
                "session.finalizing",
            );
            if n < 0 && errno_now() == libc::EINTR {
                continue;
            }
            if n <= 0 {
                return Err(WriteError::new("io", "finalization staging write failed"));
            }
            done += n as usize;
        }
        if sys_fsync(self.stage_fd, "session.finalizing") != 0 {
            return Err(WriteError::new("io", "finalization staging sync failed"));
        }
        Ok(())
    }

    /// Fill the preallocated stage, or stage through a fresh tmp file.
    ///
    /// Returns the owned tmp fd to close (None when the preallocated stage
    /// was used) plus the creation-time identity the published file is
    /// compared against.
    fn fill_or_write_stage(
        &mut self,
        session: &[u8],
    ) -> Result<(Option<i32>, [u64; 3]), WriteError> {
        if self.prepared {
            self.fill_stage(session)?;
            return Ok((None, self.stage_ids.unwrap_or([0, 0, 0])));
        }
        let (fd, ids) = self.write_tmp("session.json.tmp", session)?;
        Ok((Some(fd), ids))
    }

    /// Pin the just-published session.json against the staging identity.
    fn pin_published_session(&self, tmp_ids: &[u64; 3]) -> Result<[u64; 3], String> {
        let Ok(sess_name) = writer_cstr("session.json") else {
            return Err("session pin failed".to_string());
        };
        // SAFETY: NUL-terminated name on a live dir fd.
        let sess_fd = unsafe {
            libc::openat(
                self.dir_fd,
                sess_name.as_ptr().cast::<libc::c_char>(),
                // Metadata-only: a substituted FIFO must never block the
                // pin. Data was synced through the owned staging
                // descriptor above.
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        if sess_fd < 0 {
            return Err("session pin failed".to_string());
        }
        let sess_ids = fstat_ids(sess_fd);
        close_quiet(sess_fd);
        let Ok(sess_ids) = sess_ids else {
            return Err("session pin failed".to_string());
        };
        if sess_ids[0] != tmp_ids[0] || sess_ids[1] != tmp_ids[1] {
            return Err("session replaced after rename".to_string());
        }
        Ok(sess_ids)
    }

    /// Re-verify both fds still name the created files.
    ///
    /// dev/ino pins catch replacement; nlink pins catch mid-run unlinking
    /// (events file unlinked, or dir emptied and removed): either refuses
    /// publication.
    fn identity_ok(&self) -> bool {
        match (fstat_ids(self.dir_fd), fstat_ids(self.ev_fd)) {
            (Ok(dir_ids), Ok(ev_ids)) => {
                dir_ids[0] == self.dir_ids[0]
                    && dir_ids[1] == self.dir_ids[1]
                    && dir_ids[2] == self.dir_ids[2]
                    && ev_ids[0] == self.ev_ids[0]
                    && ev_ids[1] == self.ev_ids[1]
                    && ev_ids[2] == self.ev_ids[2]
            }
            _ => false,
        }
    }

    /// Compare the live namespace against held descriptors.
    ///
    /// Returns "" when the basename lookup through the held parent fd
    /// resolves to the held dir AND the events.ndjson lookup through the
    /// held dir fd resolves to the held events file (both without following
    /// symlinks); else a mismatch note. Catches rename-and-replace, which
    /// preserves the held fds' dev/ino/nlink. Proves integrity AT CHECK
    /// TIME against a quiescent mutator only.
    fn namespace_ok(&self) -> String {
        let Ok(base) = writer_cstr(&self.base_name) else {
            return "namespace: check failed".to_string();
        };
        // SAFETY: NUL-terminated base on a possibly-live parent fd.
        let dir_probe = unsafe {
            libc::openat(
                self.parent_fd,
                base.as_ptr().cast::<libc::c_char>(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY,
                0 as libc::c_uint,
            )
        };
        if dir_probe < 0 {
            return "namespace: output dir lookup failed".to_string();
        }
        let dir_ids = fstat_ids(dir_probe);
        close_quiet(dir_probe);
        let Ok(dir_ids) = dir_ids else {
            return "namespace: check failed".to_string();
        };
        if dir_ids[0] != self.dir_ids[0] || dir_ids[1] != self.dir_ids[1] {
            return "namespace: output dir replaced".to_string();
        }
        let Ok(ev_name) = writer_cstr("events.ndjson") else {
            return "namespace: check failed".to_string();
        };
        // SAFETY: as above.
        let ev_probe = unsafe {
            libc::openat(
                self.dir_fd,
                ev_name.as_ptr().cast::<libc::c_char>(),
                libc::O_PATH | libc::O_NOFOLLOW,
                0 as libc::c_uint,
            )
        };
        if ev_probe < 0 {
            return "namespace: events file lookup failed".to_string();
        }
        let ev_ids = fstat_ids(ev_probe);
        close_quiet(ev_probe);
        let Ok(ev_ids) = ev_ids else {
            return "namespace: check failed".to_string();
        };
        if ev_ids[0] != self.ev_ids[0] || ev_ids[1] != self.ev_ids[1] {
            return "namespace: events file replaced".to_string();
        }
        let path_probe = match open_directory(&self.dir_path) {
            Ok(fd) => fd,
            Err(_) => return "namespace: capture path lookup failed".to_string(),
        };
        let path_ids = fstat_ids(path_probe);
        close_quiet(path_probe);
        let Ok(path_ids) = path_ids else {
            return "namespace: path stat failed".to_string();
        };
        if path_ids[0] != self.dir_ids[0] || path_ids[1] != self.dir_ids[1] {
            return "namespace: capture path replaced".to_string();
        }
        String::new()
    }

    /// Unlink a tmp name only if it still resolves to `want`.
    ///
    /// Returns true when the name is gone (unlinked or already absent),
    /// false when a replacement was preserved. Never raises.
    fn remove_tmp_if_owned(&self, name: &'static str, want: &[u64; 3]) -> bool {
        if !name_matches(self.dir_fd, name, want) {
            return false;
        }
        let Ok(cname) = writer_cstr(name) else {
            return false;
        };
        let r = sys_unlinkat(self.dir_fd, cname.as_ptr(), 0, name);
        r == 0 || errno_now() == libc::ENOENT
    }

    /// Create + fill + fsync a tmp file; errno read before cleanup.
    ///
    /// Own-failure cleanup: write/sync failures remove the just-created tmp
    /// only when the name still resolves to it (dev/ino); replacements are
    /// preserved and reported in the raised error. Create failures never
    /// unlink: a pre-existing name is foreign. On success, the returned pin
    /// holds the creation-time [dev, ino, nlink] identity: finalize
    /// compares the published file against it, so no later re-pin can fail
    /// open.
    fn write_tmp(&self, name: &'static str, data: &[u8]) -> Result<(i32, [u64; 3]), WriteError> {
        let cname = writer_cstr(name)?;
        // SAFETY: NUL-terminated name on a live dir fd.
        let fd = unsafe {
            libc::openat(
                self.dir_fd,
                cname.as_ptr().cast::<libc::c_char>(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(WriteError::new(
                "io",
                format!("tmp create failed: errno {}", errno_now()),
            ));
        }
        let ids = match fstat_ids(fd) {
            Ok(ids) => ids,
            Err(_) => {
                close_quiet(fd);
                return Err(WriteError::new("io", "tmp pin failed; tmp left in place"));
            }
        };
        let mut done = 0usize;
        let total = data.len();
        while done < total {
            // SAFETY: the document outlives the call; offset is absolute.
            let n = sys_pwrite(
                fd,
                data.as_ptr().wrapping_add(done),
                total - done,
                done as i64,
                name,
            );
            if n < 0 {
                let no = errno_now();
                if no == libc::EINTR {
                    continue;
                }
                let gone = self.remove_tmp_if_owned(name, &ids);
                close_quiet(fd);
                let mut msg = format!("tmp write failed: errno {no}");
                if !gone {
                    msg.push_str("; tmp replacement left in place");
                }
                return Err(WriteError::new("io", msg));
            }
            if n == 0 {
                let gone = self.remove_tmp_if_owned(name, &ids);
                close_quiet(fd);
                let mut msg = "tmp write stalled".to_string();
                if !gone {
                    msg.push_str("; tmp replacement left in place");
                }
                return Err(WriteError::new("io", msg));
            }
            done += n as usize;
        }
        if sys_fsync(fd, name) != 0 {
            let no = errno_now();
            let gone = self.remove_tmp_if_owned(name, &ids);
            close_quiet(fd);
            let mut msg = format!("tmp fsync failed: errno {no}");
            if !gone {
                msg.push_str("; tmp replacement left in place");
            }
            return Err(WriteError::new("io", msg));
        }
        Ok((fd, ids))
    }

    fn close_all(&mut self) {
        close_quiet(self.reserve_fd);
        close_quiet(self.stage_fd);
        close_quiet(self.ev_fd);
        close_quiet(self.dir_fd);
        close_quiet(self.parent_fd);
        self.reserve_fd = -1;
        self.stage_fd = -1;
        self.ev_fd = -1;
        self.dir_fd = -1;
        self.parent_fd = -1;
        self.closed = true;
    }
}

impl Drop for EventWriter {
    fn drop(&mut self) {
        close_quiet(self.reserve_fd);
        close_quiet(self.stage_fd);
        close_quiet(self.ev_fd);
        close_quiet(self.dir_fd);
        close_quiet(self.parent_fd);
    }
}

/// Refuse a just-opened capture dir that is not ours.
///
/// mkdirat and the first openat are separate calls, so a foreign dir
/// swapped in between becomes the opened fd. Refuse it ("exists": the name
/// holds something we did not create) before any capture file is created
/// inside: a privately-created dir (mkdir 0700) carries no group/other
/// bits, is owned by this user, and starts empty. Inherited POSIX ACLs stay
/// bounded by the requested mode, so any observed group/other bits prove a
/// foreign dir and are refused (fail-closed). Raises "io" when the checks
/// themselves fail. Lists entries with getdents64 straight off the held fd
/// (no DIR stream): getdents64 advances the directory offset, so the caller
/// must pass a fresh descriptor it never lists twice (as the capture open
/// path does).
fn require_private_empty_dir(dir_fd: i32) -> Result<(), WriteError> {
    let ids = stat_fd(dir_fd)?;
    if ids[3] & 0o077 != 0 {
        return Err(WriteError::new(
            "exists",
            "output dir group/other accessible",
        ));
    }
    // SAFETY: pure id query.
    let me = unsafe { libc::geteuid() } as u64;
    if me != ids[4] {
        return Err(WriteError::new(
            "exists",
            "output dir owned by another user",
        ));
    }
    let mut buf = [0u8; DIRENT_BUF_SIZE];
    let mut dirty = false;
    let mut bad = false;
    let mut bad_no = 0;
    loop {
        // SAFETY: live dir fd with the 8 KiB buffer.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            bad_no = errno_now();
            bad = true;
            break;
        }
        if n == 0 {
            break;
        }
        let total = n as usize;
        let mut off = 0;
        while off < total {
            let nbase = off + DIRENT_NAME_OFF;
            if nbase > total {
                bad = true;
                break;
            }
            let reclen = usize::from(buf[off + 16]) | (usize::from(buf[off + 17]) << 8);
            if reclen < 20 || off + reclen > total {
                bad = true;
                break;
            }
            // d_name sits at byte 19 of the x86-64 Linux dirent (ino 8,
            // off 8, reclen 2, type 1); compare "." / ".." byte-wise.
            let mut nlen = 0;
            while DIRENT_NAME_OFF + nlen < reclen {
                if buf[nbase + nlen] == 0 {
                    break;
                }
                nlen += 1;
            }
            let is_dot = nlen == 1 && buf[nbase] == 0x2E;
            let is_dotdot = nlen == 2 && buf[nbase] == 0x2E && buf[nbase + 1] == 0x2E;
            if !is_dot && !is_dotdot {
                dirty = true;
                break;
            }
            off += reclen;
        }
        if dirty || bad {
            break;
        }
    }
    if bad {
        return Err(WriteError::new(
            "io",
            format!("dir read failed: errno {bad_no}"),
        ));
    }
    if dirty {
        return Err(WriteError::new("exists", "output dir not empty"));
    }
    Ok(())
}

/// Test-only syscall fault injector and I/O tracer.
///
/// Plans arm per calling thread: only the thread holding the armed guard
/// observes faults or records trace rows, so fault tests stay deterministic
/// while other threads run fault-free.
#[cfg(test)]
pub(crate) mod faults {
    /// One fault scenario; every field defaults to fault-free.
    #[derive(Debug, Clone, Default)]
    pub(crate) struct FaultPlan {
        /// 1-based pwrite call number returning a short count (once).
        pub pwrite_short_at: Option<u64>,
        /// Bytes the short pwrite returns.
        pub pwrite_short_len: usize,
        /// 1-based pwrite call number from which writes fail.
        pub pwrite_fail_from: Option<u64>,
        /// Errno the failing pwrite reports.
        pub pwrite_fail_errno: i32,
        /// Tags the pwrite failure applies to (empty means all).
        pub pwrite_fail_tags: Vec<&'static str>,
        /// Tags whose fsync fails (persistent).
        pub fsync_fail_tags: Vec<&'static str>,
        /// Tags whose fsync fails exactly once, then passes.
        pub fsync_fail_once_tags: Vec<&'static str>,
        /// Errno the failing fsync reports.
        pub fsync_errno: i32,
        /// Every ftruncate fails with EIO.
        pub truncate_fail: bool,
        /// Every renameat2 fails with EACCES.
        pub rename_fail: bool,
        /// Errno posix_fallocate reports (None means success).
        pub fallocate_errno: Option<i32>,
        /// Reserve stat reports zero allocated blocks.
        pub sparse_blocks: bool,
    }

    /// An armed plan; disarms (and clears the trace) on drop.
    pub(crate) struct ArmedFaults {
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    struct Injector {
        armed: bool,
        thread: Option<std::thread::ThreadId>,
        plan: FaultPlan,
        pwrite_calls: u64,
        trace: Vec<(String, String)>,
    }

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    static INJECTOR: std::sync::Mutex<Injector> = std::sync::Mutex::new(Injector {
        armed: false,
        thread: None,
        plan: FaultPlan {
            pwrite_short_at: None,
            pwrite_short_len: 0,
            pwrite_fail_from: None,
            pwrite_fail_errno: 0,
            pwrite_fail_tags: Vec::new(),
            fsync_fail_tags: Vec::new(),
            fsync_fail_once_tags: Vec::new(),
            fsync_errno: 0,
            truncate_fail: false,
            rename_fail: false,
            fallocate_errno: None,
            sparse_blocks: false,
        },
        pwrite_calls: 0,
        trace: Vec::new(),
    });

    /// Lock the injector, recovering from a poisoned panic abort.
    ///
    /// Every arm fully resets the armed state, so a previous test's panic
    /// mid-plan never leaks into the next plan.
    fn lock() -> std::sync::MutexGuard<'static, Injector> {
        INJECTOR
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Arm `plan` for the calling thread; serializes fault tests.
    pub(crate) fn arm(plan: FaultPlan) -> ArmedFaults {
        let guard = SERIAL
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut inj = lock();
        inj.armed = true;
        inj.thread = Some(std::thread::current().id());
        inj.plan = plan;
        inj.pwrite_calls = 0;
        inj.trace.clear();
        ArmedFaults { _guard: guard }
    }

    /// Drain the calling thread's recorded `(op, target)` rows.
    pub(crate) fn take_trace() -> Vec<(String, String)> {
        let mut inj = lock();
        if inj.armed && inj.thread == Some(std::thread::current().id()) {
            std::mem::take(&mut inj.trace)
        } else {
            Vec::new()
        }
    }

    impl Drop for ArmedFaults {
        fn drop(&mut self) {
            // A poisoned lock still disarms: never leak a plan.
            let mut inj = lock();
            inj.armed = false;
            inj.thread = None;
            inj.plan = FaultPlan::default();
            inj.pwrite_calls = 0;
            inj.trace.clear();
        }
    }

    fn armed_here(inj: &Injector) -> bool {
        inj.armed && inj.thread == Some(std::thread::current().id())
    }

    /// Record one `(op, target)` row for the armed thread.
    pub(super) fn trace(op: &str, target: &str) {
        let mut inj = lock();
        if armed_here(&inj) {
            inj.trace.push((op.to_string(), target.to_string()));
        }
    }

    /// Consult the armed plan for one pwrite; `None` passes through.
    pub(super) fn pwrite_hook(tag: &'static str, len: usize) -> Option<i64> {
        let mut inj = lock();
        if !armed_here(&inj) {
            return None;
        }
        inj.trace.push(("write".to_string(), tag.to_string()));
        inj.pwrite_calls += 1;
        let n = inj.pwrite_calls;
        if inj.plan.pwrite_short_at == Some(n) {
            return Some(inj.plan.pwrite_short_len.min(len) as i64);
        }
        if let Some(from) = inj.plan.pwrite_fail_from
            && n >= from
            && (inj.plan.pwrite_fail_tags.is_empty() || inj.plan.pwrite_fail_tags.contains(&tag))
        {
            let errno = inj.plan.pwrite_fail_errno;
            // SAFETY: sets the thread errno for the injected failure.
            unsafe {
                *libc::__errno_location() = errno;
            }
            return Some(-1);
        }
        None
    }

    /// Consult the armed plan for one fsync; `None` passes through.
    pub(super) fn fsync_hook(tag: &'static str) -> Option<i32> {
        let inj = lock();
        if !armed_here(&inj) {
            return None;
        }
        drop(inj);
        trace("sync", tag);
        let mut inj = lock();
        if let Some(pos) = inj.plan.fsync_fail_once_tags.iter().position(|t| *t == tag) {
            inj.plan.fsync_fail_once_tags.remove(pos);
            let errno = inj.plan.fsync_errno;
            // SAFETY: as above.
            unsafe {
                *libc::__errno_location() = errno;
            }
            return Some(-1);
        }
        if inj.plan.fsync_fail_tags.contains(&tag) {
            let errno = inj.plan.fsync_errno;
            // SAFETY: as above.
            unsafe {
                *libc::__errno_location() = errno;
            }
            return Some(-1);
        }
        None
    }

    /// Consult the armed plan for one ftruncate; `None` passes through.
    pub(super) fn truncate_hook(tag: &'static str) -> Option<i32> {
        let inj = lock();
        if !armed_here(&inj) {
            return None;
        }
        drop(inj);
        trace("truncate", tag);
        let inj = lock();
        if inj.plan.truncate_fail {
            // SAFETY: as above.
            unsafe {
                *libc::__errno_location() = libc::EIO;
            }
            return Some(-1);
        }
        None
    }

    /// Consult the armed plan for one renameat2; `None` passes through.
    pub(super) fn rename_hook(new_tag: &'static str) -> Option<i32> {
        let inj = lock();
        if !armed_here(&inj) {
            return None;
        }
        drop(inj);
        trace("rename", new_tag);
        let inj = lock();
        if inj.plan.rename_fail {
            // SAFETY: as above.
            unsafe {
                *libc::__errno_location() = libc::EACCES;
            }
            return Some(-1);
        }
        None
    }

    /// Consult the armed plan for one posix_fallocate; `None` passes through.
    pub(super) fn fallocate_hook() -> Option<i32> {
        let inj = lock();
        if !armed_here(&inj) {
            return None;
        }
        inj.plan.fallocate_errno
    }

    /// True when the armed plan fakes an unallocated reserve stat.
    pub(super) fn sparse_hook() -> bool {
        let inj = lock();
        armed_here(&inj) && inj.plan.sparse_blocks
    }

    /// Zero the allocated-block count when the sparse plan is armed.
    pub(super) fn sparse_adjust(mut ids: [u64; 7]) -> [u64; 7] {
        if sparse_hook() {
            ids[6] = 0;
        }
        ids
    }
}

#[cfg(test)]
mod tests {
    use super::faults::{FaultPlan, arm, take_trace};
    use super::{
        CLOSING_RESERVE, CommittedStream, EventWriter, MAX_EVENTS_BUDGET, MIN_EVENTS_BUDGET,
        RESIDUAL_DIR, RESIDUAL_EVENTS, residual_text,
    };
    use crate::model::integrity::{INTEGRITY_KIND_COUNT, integrity_kind};
    use crate::platform::hash::sha256_hex;
    use crate::platform::test_support::TestDir;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn line(byte: u8, n: usize) -> Vec<u8> {
        let mut out = vec![byte; n.saturating_sub(1)];
        out.push(b'\n');
        out
    }

    fn read_bytes(path: &Path) -> Vec<u8> {
        std::fs::read(path).expect("test read")
    }

    fn scratch() -> TestDir {
        TestDir::create("memveil-writer").expect("mkdtemp")
    }

    #[test]
    fn committed_stream_all_kinds_and_rollback() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut writer =
            EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        let mut stream = CommittedStream::new();
        let empty = stream.snapshot();
        assert_eq!(empty.line_count, 0);
        assert!(!empty.has_seq);
        for i in 0..INTEGRITY_KIND_COUNT {
            let buf = line(65 + i as u8, i + 2);
            writer.append(&buf).expect("append");
            stream.commit(&buf, integrity_kind(i)).expect("commit");
        }
        let before = stream.clone();
        let mark = writer.group_begin().expect("begin");
        let extra = line(65, 5);
        writer.append_closing(&extra).expect("closing");
        stream.commit(&extra, "gap").expect("commit gap");
        writer.group_abort(mark).expect("abort");
        stream = before;
        let snapshot = stream.snapshot();
        let bytes = read_bytes(&target.join("events.ndjson"));
        assert_eq!(snapshot.events_bytes, bytes.len() as u64);
        assert_eq!(snapshot.line_count, INTEGRITY_KIND_COUNT as u64);
        assert_eq!(snapshot.first_seq, 0);
        assert_eq!(snapshot.last_seq, INTEGRITY_KIND_COUNT as u64 - 1);
        assert_eq!(snapshot.events_sha256, sha256_hex(&bytes));
        for count in snapshot.kinds.iter().take(INTEGRITY_KIND_COUNT) {
            assert_eq!(*count, 1);
        }
        let err = writer
            .append(&line(65, MIN_EVENTS_BUDGET as usize))
            .unwrap_err();
        assert_eq!(err.kind, "refused");
        assert_eq!(stream.snapshot().events_sha256, snapshot.events_sha256);
        assert_eq!(writer.committed_len(), bytes.len() as u64);
        writer.discard();
    }

    #[test]
    fn committed_stream_rejects_bad_lines() {
        let mut stream = CommittedStream::new();
        assert!(stream.commit(&line(65, 4), "bogus-kind").is_err());
        assert!(stream.commit(b"", "gap").is_err());
        assert!(stream.commit(b"no-newline", "gap").is_err());
        let mut huge = vec![65u8; 65537];
        huge.push(b'\n');
        assert!(stream.commit(&huge, "gap").is_err());
        assert_eq!(stream.snapshot().line_count, 0);
    }

    #[test]
    fn create_append_finalize() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("a1");
        w.append(&line(0x42, 200)).expect("a2");
        assert_eq!(w.committed_len(), 300);
        let outcome = w.finalize(&line(0x7B, 50)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        let events = read_bytes(&target.join("events.ndjson"));
        assert_eq!(events.len(), 300);
        assert_eq!(events[0], 0x41);
        assert_eq!(events[99], 0x0A);
        assert_eq!(events[100], 0x42);
        let back = read_bytes(&target.join("session.json"));
        assert_eq!(back.len(), 50);
    }

    #[test]
    fn modes_are_private() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 10)).expect("append");
        w.prepare().expect("prepare");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        let dir_mode = std::fs::metadata(&target)
            .expect("stat dir")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
        for name in ["events.ndjson", "session.json"] {
            let mode = std::fs::metadata(target.join(name))
                .expect("stat member")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{name}");
        }
    }

    #[test]
    fn exists_variants() {
        let tmp = scratch();
        // Nonempty dir (a previous capture).
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        w.append(&line(0x41, 10)).expect("append");
        let err = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .unwrap_err();
        assert_eq!(err.kind, "exists");
        assert_eq!(err.message, "output exists");
        // Empty dir.
        std::fs::create_dir(tmp.path().join("empty")).expect("mkdir");
        let err = EventWriter::new(
            tmp.path().join("empty").to_str().unwrap(),
            MIN_EVENTS_BUDGET,
        )
        .unwrap_err();
        assert_eq!(err.kind, "exists");
        // Plain file.
        std::fs::write(tmp.path().join("file"), b"x").expect("write");
        let err = EventWriter::new(tmp.path().join("file").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .unwrap_err();
        assert_eq!(err.kind, "exists");
        // Symlink (dangling or not, must never be followed).
        std::os::unix::fs::symlink(tmp.path().join("empty"), tmp.path().join("link"))
            .expect("symlink");
        let err = EventWriter::new(tmp.path().join("link").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .unwrap_err();
        assert_eq!(err.kind, "exists");
        // The first writer still owns its capture.
        assert_eq!(w.committed_len(), 10);
        w.discard();
    }

    #[test]
    fn budget_range() {
        let tmp = scratch();
        for (i, budget) in [MIN_EVENTS_BUDGET - 1, MAX_EVENTS_BUDGET + 1]
            .into_iter()
            .enumerate()
        {
            let err =
                EventWriter::new(tmp.path().join(format!("cap{i}")).to_str().unwrap(), budget)
                    .unwrap_err();
            assert_eq!(err.kind, "budget");
        }
        let wmin = EventWriter::new(tmp.path().join("min").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("min");
        assert_eq!(wmin.committed_len(), 0);
        let wmax = EventWriter::new(tmp.path().join("max").to_str().unwrap(), MAX_EVENTS_BUDGET)
            .expect("max");
        assert_eq!(wmax.committed_len(), 0);
    }

    #[test]
    fn size_gate_both_sides() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let budget = MIN_EVENTS_BUDGET - CLOSING_RESERVE;
        let chunk = 4096u64;
        let nchunks = budget / chunk;
        for _ in 0..nchunks {
            w.append(&line(0x41, chunk as usize)).expect("fill");
        }
        let rest = budget - nchunks * chunk;
        if rest > 0 {
            w.append(&line(0x41, rest as usize)).expect("rest");
        }
        assert_eq!(w.committed_len(), budget);
        let err = w.append(&line(0x42, 1)).unwrap_err();
        assert_eq!(err.kind, "refused");
        assert_eq!(w.committed_len(), budget);
        let events = read_bytes(&tmp.path().join("cap/events.ndjson"));
        assert_eq!(events.len() as u64, budget);
    }

    #[test]
    fn group_abort() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        w.append(&line(0x41, 100)).expect("a");
        let mark = w.group_begin().expect("begin");
        assert_eq!(mark, 100);
        w.append(&line(0x42, 100)).expect("b");
        w.append(&line(0x43, 100)).expect("c");
        assert_eq!(w.committed_len(), 300);
        w.group_abort(mark).expect("abort");
        assert_eq!(w.committed_len(), 100);
        w.append(&line(0x44, 50)).expect("d");
        assert_eq!(w.committed_len(), 150);
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        let events = read_bytes(&tmp.path().join("cap/events.ndjson"));
        assert_eq!(events.len(), 150);
        assert_eq!(events[100], 0x44);
        // Bad marks.
        let mut w2 = EventWriter::new(tmp.path().join("cap2").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create2");
        let err = w2.group_abort(999).unwrap_err();
        assert_eq!(err.kind, "misuse");
        // Nested groups refuse.
        let mut w3 = EventWriter::new(tmp.path().join("cap3").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create3");
        w3.group_begin().expect("begin3");
        let err = w3.group_begin().unwrap_err();
        assert_eq!(err.kind, "misuse");
    }

    #[test]
    fn misuse_after_finalize() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        for _ in 0..2 {
            let err = w.append(&line(0x41, 10)).unwrap_err();
            assert_eq!(err.kind, "misuse");
        }
        let err = w.finalize(&line(0x7B, 10)).unwrap_err();
        assert_eq!(err.kind, "misuse");
    }

    #[test]
    fn abandon() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        assert_eq!(w.abandon(), "");
        assert!(!target.join("events.ndjson").exists());
        // The dir itself is gone: recreate works.
        let w2 = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("recreate");
        assert_eq!(w2.committed_len(), 0);
    }

    #[test]
    fn nul_path() {
        let mut raw = b"/tmp/x".to_vec();
        raw.push(0);
        raw.push(0x41);
        let evil = String::from_utf8(raw).expect("utf8");
        let err = EventWriter::new(&evil, MIN_EVENTS_BUDGET).unwrap_err();
        assert_eq!(err.kind, "io");
    }

    #[test]
    fn abandon_preserves_replaced_events() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::rename(
            target.join("events.ndjson"),
            tmp.path().join("stolen.ndjson"),
        )
        .expect("steal");
        std::fs::write(target.join("events.ndjson"), b"ATTACKER\n").expect("plant");
        let leftovers = w.abandon();
        assert_ne!(leftovers, "");
        assert!(leftovers.contains("events file"), "{leftovers}");
        let body = read_bytes(&target.join("events.ndjson"));
        assert_eq!(body.len(), 9);
        assert_eq!(body[0], 0x41);
        let stolen = read_bytes(&tmp.path().join("stolen.ndjson"));
        assert_eq!(stolen.len(), 100);
        let err = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).unwrap_err();
        assert_eq!(err.kind, "exists");
    }

    #[test]
    fn abandon_preserves_replaced_dir() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::rename(&target, tmp.path().join("stolen-cap")).expect("steal dir");
        std::fs::create_dir(&target).expect("replant dir");
        let leftovers = w.abandon();
        assert_ne!(leftovers, "");
        assert!(leftovers.contains("output dir"), "{leftovers}");
        let stolen = read_bytes(&tmp.path().join("stolen-cap/events.ndjson"));
        assert_eq!(stolen.len(), 100);
        std::fs::write(target.join("planted"), b"x").expect("plant");
        assert_eq!(read_bytes(&target.join("planted")).len(), 1);
    }

    #[test]
    fn abandon_reports_foreign_tmp() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::write(target.join("session.json.tmp"), b"FOREIGN\n").expect("plant tmp");
        let leftovers = w.abandon();
        assert_ne!(leftovers, "");
        assert!(leftovers.contains("session.json.tmp"), "{leftovers}");
        let kept = read_bytes(&target.join("session.json.tmp"));
        assert_eq!(kept.len(), 8);
        assert_eq!(kept[0], 0x46);
    }

    #[test]
    fn finalize_preserves_planted_tmp() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::write(target.join("session.json.tmp"), b"FOREIGN\n").expect("plant tmp");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "unfinalized");
        assert!(
            outcome.message.contains("tmp create failed"),
            "{}",
            outcome.message
        );
        let kept = read_bytes(&target.join("session.json.tmp"));
        assert_eq!(kept.len(), 8);
        assert_eq!(kept[0], 0x46);
    }

    #[test]
    fn unlink_events_before_finalize() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::remove_file(target.join("events.ndjson")).expect("unlink");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "unfinalized");
        assert!(!target.join("session.json").exists());
    }

    #[test]
    fn unlink_dir_before_finalize() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        std::fs::remove_file(target.join("events.ndjson")).expect("unlink");
        std::fs::remove_dir(&target).expect("rmdir");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "unfinalized");
    }

    #[test]
    fn parent_is_file() {
        let tmp = scratch();
        let file = tmp.path().join("blocker");
        std::fs::write(&file, line(0x78, 2)).expect("write");
        let err =
            EventWriter::new(file.join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET).unwrap_err();
        assert_eq!(err.kind, "io");
    }

    #[test]
    fn trailing_slash_ok() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(
            &(target.to_str().unwrap().to_string() + "/"),
            MIN_EVENTS_BUDGET,
        )
        .expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        assert_eq!(read_bytes(&target.join("events.ndjson")).len(), 100);
    }

    fn open_dir_fd(path: &Path) -> i32 {
        use std::ffi::CString;
        let c = CString::new(path.as_os_str().as_bytes()).expect("cstr");
        // SAFETY: NUL-terminated live path.
        let fd = unsafe { libc::openat(libc::AT_FDCWD, c.as_ptr(), libc::O_DIRECTORY, 0) };
        assert!(fd >= 0, "test dir open failed");
        fd
    }

    fn close_fd(fd: i32) {
        // SAFETY: owned test fd.
        unsafe {
            libc::close(fd);
        }
    }

    fn private_dir(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::create_dir(path).expect("mkdir");
        // create_dir honors the umask; pin 0700 exactly like mkdirat(0700).
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("chmod");
    }

    #[test]
    fn create_accepts_private_empty_dir() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        private_dir(&target);
        let fd = open_dir_fd(&target);
        super::require_private_empty_dir(fd).expect("private empty passes");
        close_fd(fd);
    }

    #[test]
    fn create_refuses_foreign_entries() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        private_dir(&target);
        std::fs::write(target.join("loot.txt"), b"LOOT\n").expect("loot");
        std::fs::create_dir(target.join("sub")).expect("subdir");
        let fd = open_dir_fd(&target);
        let err = super::require_private_empty_dir(fd).unwrap_err();
        close_fd(fd);
        assert_eq!(err.kind, "exists");
    }

    #[test]
    fn create_refuses_group_accessible_dir() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        std::fs::create_dir(&target).expect("mkdir");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let fd = open_dir_fd(&target);
        let err = super::require_private_empty_dir(fd).unwrap_err();
        close_fd(fd);
        assert_eq!(err.kind, "exists");
    }

    #[test]
    fn create_refuses_other_owned_dir() {
        // SAFETY: pure id query.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let tmp = scratch();
        let target = tmp.path().join("cap");
        private_dir(&target);
        use std::ffi::CString;
        let c = CString::new(target.as_os_str().as_bytes()).expect("cstr");
        // SAFETY: NUL-terminated live path.
        let rc = unsafe { libc::chown(c.as_ptr(), 65534, 65534) };
        assert_eq!(rc, 0);
        let fd = open_dir_fd(&target);
        let err = super::require_private_empty_dir(fd).unwrap_err();
        close_fd(fd);
        assert_eq!(err.kind, "exists");
    }

    #[test]
    fn append_closing_uses_reserve() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        for _ in 0..6 {
            w.append(&line(0x41, 10000)).expect("attempt");
        }
        assert_eq!(w.committed_len(), 60000);
        w.append_closing(&line(0x43, 100)).expect("closing");
        assert_eq!(w.committed_len(), 60100);
        let err = w.append(&line(0x42, 10000)).unwrap_err();
        assert_eq!(err.kind, "refused");
        w.append_closing(&line(0x44, 100)).expect("closing2");
        assert_eq!(w.committed_len(), 60200);
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
    }

    #[test]
    fn write_error_residuals_default_none() {
        let e = super::WriteError::new("io", "fstat failed: errno 5");
        assert_eq!(e.residuals, 0);
        assert_eq!(residual_text(e.residuals), "");
    }

    #[test]
    fn write_error_residual_bits_render() {
        assert_eq!(residual_text(RESIDUAL_EVENTS), "events");
        assert_eq!(residual_text(RESIDUAL_DIR), "dir");
        assert_eq!(residual_text(RESIDUAL_EVENTS | RESIDUAL_DIR), "events,dir");
        let e = super::WriteError::with_residuals(
            "io",
            "fstat failed: errno 5",
            RESIDUAL_EVENTS | RESIDUAL_DIR,
        );
        assert_eq!(e.message, "fstat failed: errno 5");
        assert_eq!(residual_text(e.residuals), "events,dir");
    }

    #[test]
    fn write_error_ignores_prose_residuals() {
        let e = super::WriteError::new("io", "fstat failed: errno 5; residuals: events,dir");
        assert_eq!(e.residuals, 0);
        assert_eq!(residual_text(e.residuals), "");
        let local = super::WriteError::new("io", "LOCALIZED fstat failure; residus: events,dir");
        assert_eq!(local.residuals, 0);
        assert_eq!(residual_text(local.residuals), "");
        let typed =
            super::WriteError::with_residuals("io", "unrelated; residuals: dir", RESIDUAL_EVENTS);
        assert_eq!(residual_text(typed.residuals), "events");
    }

    #[test]
    fn write_error_residuals_bounded() {
        let e = super::WriteError::with_residuals("io", "x", 255);
        assert_eq!(e.residuals, 3);
        assert_eq!(residual_text(255), "events,dir");
        assert_eq!(residual_text(4), "");
    }

    #[test]
    fn checkpoint_publish_and_exchange() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.checkpoint(b"checkpoint-one").expect("ckpt1");
        assert_eq!(
            read_bytes(&target.join("checkpoint.json")),
            b"checkpoint-one"
        );
        assert!(!target.join("checkpoint.json.tmp").exists());
        w.append(&line(0x42, 100)).expect("append2");
        w.checkpoint(b"checkpoint-two").expect("ckpt2");
        assert_eq!(
            read_bytes(&target.join("checkpoint.json")),
            b"checkpoint-two"
        );
        assert!(!target.join("checkpoint.json.tmp").exists());
        // Reserve and staging are in place with pinned sizes.
        assert_eq!(
            read_bytes(&target.join(".finalization-reserve")).len(),
            17 * 1024 * 1024
        );
        assert_eq!(read_bytes(&target.join("session.finalizing")).len(), 0);
        w.discard();
    }

    #[test]
    fn checkpoint_inside_group_misuse() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let mark = w.group_begin().expect("begin");
        let err = w.checkpoint(b"nope").unwrap_err();
        assert_eq!(err.kind, "misuse");
        w.group_abort(mark).expect("abort");
        w.checkpoint(b"ok").expect("ckpt after abort");
    }

    #[test]
    fn checkpoint_too_large() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let big = vec![0x7Bu8; 16777217];
        let err = w.checkpoint(&big).unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(!tmp.path().join("cap/checkpoint.json").exists());
    }

    #[test]
    fn finalize_removes_checkpoint() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.checkpoint(b"ckpt").expect("ckpt");
        assert!(target.join("checkpoint.json").exists());
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        assert!(!target.join("checkpoint.json").exists());
        assert!(!target.join("checkpoint.json.tmp").exists());
        assert!(!target.join(".finalization-reserve").exists());
        assert!(!target.join("session.finalizing").exists());
        let names: Vec<String> = std::fs::read_dir(&target)
            .expect("readdir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(names.contains(&"events.ndjson".to_string()));
        assert!(names.contains(&"session.json".to_string()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn finalized_identity_pins_outputs() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        assert!(w.finalized_identity().is_empty());
        w.append(&line(0x41, 10)).expect("append");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        let ids = w.finalized_identity();
        assert_eq!(ids.len(), 6);
        assert!(ids.iter().all(|&v| v != 0));
    }

    #[test]
    fn commit_order_trace() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let _armed = arm(FaultPlan::default());
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.prepare().expect("prepare");
        w.checkpoint(b"one").expect("ckpt1");
        w.append(&line(0x41, 100)).expect("append");
        w.append(&line(0x42, 100)).expect("append2");
        w.checkpoint(b"two").expect("ckpt2");
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize");
        assert_eq!(outcome.status, "finalized");
        let rows = take_trace();
        let steps: Vec<(&str, &str)> = rows
            .iter()
            .map(|(op, tgt)| (op.as_str(), tgt.as_str()))
            .collect();
        assert_eq!(
            steps[..3],
            [
                ("sync", ".finalization-reserve"),
                ("sync", "session.finalizing"),
                ("sync", "events.ndjson"),
            ]
        );
        let publishes: Vec<usize> = steps
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == ("rename", "checkpoint.json"))
            .map(|(i, _)| i)
            .collect();
        assert_eq!(publishes.len(), 2);
        for i in publishes {
            assert_eq!(
                steps[i - 2..i],
                [
                    ("write", "checkpoint.json.tmp"),
                    ("sync", "checkpoint.json.tmp")
                ]
            );
            assert_eq!(steps[i + 1].0, "sync");
            assert_eq!(steps[i + 2].0, "sync");
        }
        let final_pos = steps
            .iter()
            .position(|s| *s == ("rename", "session.json"))
            .expect("rename");
        let release = steps
            .iter()
            .position(|s| *s == ("truncate", ".finalization-reserve"))
            .expect("release");
        let last_events_sync = steps[..final_pos]
            .iter()
            .rposition(|s| *s == ("sync", "events.ndjson"))
            .expect("events sync");
        assert!(
            release < last_events_sync,
            "reserve released before final event sync"
        );
        assert_eq!(
            steps[final_pos - 2..final_pos],
            [
                ("write", "session.finalizing"),
                ("sync", "session.finalizing")
            ]
        );
        for step in &steps[final_pos + 1..] {
            assert!(
                step.0 == "sync" || *step == ("remove", "checkpoint.json"),
                "unexpected post-rename step {step:?}"
            );
        }
    }

    #[test]
    fn discard_keeps_events_without_session() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.discard();
        w.discard();
        assert_eq!(read_bytes(&target.join("events.ndjson")).len(), 100);
        assert!(!target.join("session.json").exists());
        let err = w.append(&line(0x41, 10)).unwrap_err();
        assert_eq!(err.kind, "misuse");
    }

    // ---- Fault injection ----

    #[test]
    fn enospc_zero_byte_append_fails_clean() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let _armed = arm(FaultPlan {
            pwrite_fail_from: Some(1),
            pwrite_fail_errno: libc::ENOSPC,
            ..Default::default()
        });
        let err = w.append(&line(0x41, 100)).unwrap_err();
        assert_eq!(err.kind, "append_failed");
        assert!(err.message.contains("zero-byte"), "{}", err.message);
        assert_eq!(w.committed_len(), 0);
        assert_eq!(read_bytes(&tmp.path().join("cap/events.ndjson")).len(), 0);
    }

    #[test]
    fn short_write_alone_retries_to_success() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let _armed = arm(FaultPlan {
            pwrite_short_at: Some(1),
            pwrite_short_len: 10,
            ..Default::default()
        });
        w.append(&line(0x41, 100)).expect("short write retries");
        assert_eq!(w.committed_len(), 100);
        assert_eq!(read_bytes(&tmp.path().join("cap/events.ndjson")).len(), 100);
    }

    #[test]
    fn torn_append_recovers_prefix() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        w.append(&line(0x41, 50)).expect("first");
        // Call numbers count armed-thread pwrites since arm(), so the
        // pre-arm append above is call zero of this plan.
        let _armed = arm(FaultPlan {
            pwrite_short_at: Some(1),
            pwrite_short_len: 10,
            pwrite_fail_from: Some(2),
            pwrite_fail_errno: libc::ENOSPC,
            ..Default::default()
        });
        let err = w.append(&line(0x42, 100)).unwrap_err();
        assert_eq!(err.kind, "append_failed");
        assert!(
            err.message.contains("torn append recovered"),
            "{}",
            err.message
        );
        assert_eq!(w.committed_len(), 50);
        let body = read_bytes(&tmp.path().join("cap/events.ndjson"));
        assert_eq!(body.len(), 50);
        assert!(body.iter().all(|&b| b == 0x41 || b == 0x0A));
    }

    #[test]
    fn torn_append_unrecoverable_poisons() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let _armed = arm(FaultPlan {
            pwrite_short_at: Some(1),
            pwrite_short_len: 10,
            pwrite_fail_from: Some(2),
            pwrite_fail_errno: libc::ENOSPC,
            truncate_fail: true,
            ..Default::default()
        });
        let err = w.append(&line(0x41, 100)).unwrap_err();
        assert_eq!(err.kind, "fatal");
        assert!(
            err.message.contains("torn append unrecoverable"),
            "{}",
            err.message
        );
        assert_eq!(w.append(&line(0x41, 10)).unwrap_err().kind, "misuse");
        assert_eq!(w.finalize(&line(0x7B, 10)).unwrap_err().kind, "misuse");
    }

    #[test]
    fn failed_group_rollback_poisons() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let mark = w.group_begin().expect("begin");
        w.append(&line(0x42, 100)).expect("append2");
        let _armed = arm(FaultPlan {
            truncate_fail: true,
            ..Default::default()
        });
        let err = w.group_abort(mark).unwrap_err();
        assert_eq!(err.kind, "fatal");
        assert!(
            err.message.contains("group rollback failed"),
            "{}",
            err.message
        );
        assert_eq!(w.append(&line(0x41, 10)).unwrap_err().kind, "misuse");
        assert_eq!(w.finalize(&line(0x7B, 10)).unwrap_err().kind, "misuse");
    }

    #[test]
    fn checkpoint_rename_failure_cleans_tmp() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let _armed = arm(FaultPlan {
            rename_fail: true,
            ..Default::default()
        });
        let err = w.checkpoint(b"one").unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(
            err.message.contains("checkpoint rename failed"),
            "{}",
            err.message
        );
        assert!(!target.join("checkpoint.json.tmp").exists());
        assert!(!target.join("checkpoint.json").exists());
        drop(_armed);
        // The writer survives: a clean checkpoint still publishes.
        let _armed = arm(FaultPlan::default());
        w.checkpoint(b"one").expect("retry works");
        assert_eq!(read_bytes(&target.join("checkpoint.json")), b"one");
    }

    #[test]
    fn checkpoint_tmp_enospc_cleans_tmp() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let _armed = arm(FaultPlan {
            pwrite_fail_from: Some(1),
            pwrite_fail_errno: libc::ENOSPC,
            pwrite_fail_tags: vec!["checkpoint.json.tmp"],
            ..Default::default()
        });
        let err = w.checkpoint(b"one").unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(err.message.contains("tmp write failed"), "{}", err.message);
        assert!(!target.join("checkpoint.json.tmp").exists());
        assert!(!target.join("checkpoint.json").exists());
    }

    #[test]
    fn finalize_dir_fsync_failure_is_present_unsynced() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let _armed = arm(FaultPlan {
            fsync_fail_tags: vec!["dir"],
            fsync_errno: libc::EIO,
            ..Default::default()
        });
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "present_unsynced");
        assert!(outcome.message.contains("dir fsync"), "{}", outcome.message);
        assert!(target.join("session.json").exists());
    }

    #[test]
    fn prepared_finalize_rename_failure_is_unfinalized() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.prepare().expect("prepare");
        let _armed = arm(FaultPlan {
            rename_fail: true,
            ..Default::default()
        });
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "unfinalized");
        assert!(
            outcome.message.contains("rename failed"),
            "{}",
            outcome.message
        );
        assert!(!target.join("session.json").exists());
        assert!(!target.join("session.finalizing").exists());
    }

    #[test]
    fn finalize_reserve_release_failure_is_unfinalized() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.prepare().expect("prepare");
        let _armed = arm(FaultPlan {
            truncate_fail: true,
            ..Default::default()
        });
        let outcome = w.finalize(&line(0x7B, 10)).expect("finalize runs");
        assert_eq!(outcome.status, "unfinalized");
        assert_eq!(outcome.message, "reserve release failed");
        assert!(!target.join("session.json").exists());
    }

    #[test]
    fn checkpoint_dir_fsync_failure_poisons() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let _armed = arm(FaultPlan {
            fsync_fail_tags: vec!["dir", "parent"],
            fsync_errno: libc::EIO,
            ..Default::default()
        });
        let err = w.checkpoint(b"one").unwrap_err();
        assert_eq!(err.kind, "fatal");
        assert!(err.message.contains("writer poisoned"), "{}", err.message);
        assert_eq!(w.append(&line(0x41, 10)).unwrap_err().kind, "misuse");
        assert!(!target.join("checkpoint.json").exists());
    }

    #[test]
    fn checkpoint_one_shot_dir_sync_failure_restores_previous() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        w.checkpoint(b"checkpoint-one").expect("ckpt1");
        assert_eq!(
            read_bytes(&target.join("checkpoint.json")),
            b"checkpoint-one"
        );
        w.append(&line(0x42, 100)).expect("append2");
        let _armed = arm(FaultPlan {
            fsync_fail_once_tags: vec!["dir"],
            fsync_errno: libc::EIO,
            ..Default::default()
        });
        // The exchange sync fails once; the restore re-sync passes, so the
        // previous checkpoint is wound back and the writer survives with `io`.
        let err = w.checkpoint(b"checkpoint-two").unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(
            err.message.contains("checkpoint directory sync failed"),
            "{}",
            err.message
        );
        assert_eq!(
            read_bytes(&target.join("checkpoint.json")),
            b"checkpoint-one"
        );
        assert!(!target.join("checkpoint.json.tmp").exists());
        drop(_armed);
        // The writer continues: a third checkpoint still publishes.
        w.checkpoint(b"checkpoint-three").expect("ckpt3");
        assert_eq!(
            read_bytes(&target.join("checkpoint.json")),
            b"checkpoint-three"
        );
        assert!(!target.join("checkpoint.json.tmp").exists());
        w.discard();
    }

    #[test]
    fn checkpoint_events_fsync_failure_is_io() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        w.append(&line(0x41, 100)).expect("append");
        let _armed = arm(FaultPlan {
            fsync_fail_tags: vec!["events.ndjson"],
            fsync_errno: libc::EIO,
            ..Default::default()
        });
        let err = w.checkpoint(b"one").unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(
            err.message.contains("checkpoint events sync failed"),
            "{}",
            err.message
        );
        assert!(!target.join("checkpoint.json").exists());
    }

    #[test]
    fn reserve_alloc_unsupported_falls_back_to_writes() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut w = EventWriter::new(target.to_str().unwrap(), MIN_EVENTS_BUDGET).expect("create");
        let _armed = arm(FaultPlan {
            fallocate_errno: Some(libc::EOPNOTSUPP),
            ..Default::default()
        });
        w.prepare().expect("fallback allocation works");
        let rows = take_trace();
        let writes = rows
            .iter()
            .filter(|(op, tgt)| op == "write" && tgt == ".finalization-reserve")
            .count();
        assert_eq!(writes, 272);
        let meta = std::fs::metadata(target.join(".finalization-reserve")).expect("stat");
        assert_eq!(meta.len(), 17 * 1024 * 1024);
    }

    #[test]
    fn reserve_alloc_full_fails_prepare() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let _armed = arm(FaultPlan {
            fallocate_errno: Some(libc::EOPNOTSUPP),
            pwrite_fail_from: Some(1),
            pwrite_fail_errno: libc::ENOSPC,
            pwrite_fail_tags: vec![".finalization-reserve"],
            ..Default::default()
        });
        let err = w.prepare().unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(
            err.message.contains("reserve allocation write failed"),
            "{}",
            err.message
        );
    }

    #[test]
    fn reserve_sparse_success_detected() {
        let tmp = scratch();
        let mut w = EventWriter::new(tmp.path().join("cap").to_str().unwrap(), MIN_EVENTS_BUDGET)
            .expect("create");
        let _armed = arm(FaultPlan {
            sparse_blocks: true,
            ..Default::default()
        });
        let err = w.prepare().unwrap_err();
        assert_eq!(err.kind, "io");
        assert!(err.message.contains("reserve"), "{}", err.message);
    }
}
