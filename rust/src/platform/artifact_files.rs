// SPDX-License-Identifier: GPL-3.0-or-later
//! Pinned artifact files: snapshots, root joining, ownership repair.
//!
//! Collection resolves bridge and BPF object pathnames once, pins
//! each behind one open file description, and hashes and loads
//! through the pin's /proc/self/fd/N alias, so a pathname swap
//! after resolution changes neither the hashed nor the loaded
//! bytes. Captures finalized by a root run are handed back to the
//! invoking user through retained descriptors with dev/inode
//! continuity. Helpers return explicit owned results and never
//! write diagnostics; callers render those.

use super::hash::sha256_hex;
use super::narrow::MAX_NARROW_OBJECT_BYTES;
use super::reader::{geteuid_live, read_host_file};

/// Join an evidence root with an absolute member path.
pub fn join_root(root: &str, path: &str) -> String {
    if root == "/" || root.is_empty() {
        return path.to_string();
    }
    format!("{root}{path}")
}

/// One pinned bridge file: the hashed bytes are the loaded bytes.
///
/// The resolved pathname opens once with O_RDONLY and
/// stays open; the loader and the admission hash both
/// name that same open file description through
/// /proc/self/fd/N, so a pathname swap after
/// resolution changes neither. The pin defeats
/// rename and symlink swaps, not in-place writes to
/// the pinned inode itself; the threat assumption is
/// unchanged. `sha` is the bare hex sha256 of the
/// pinned bytes, "" when the bridge is uncheckable;
/// `load_path` is the fd alias when pinned, else
/// the plain pathname for the loader's own failure.
/// Hold the snapshot until the load it guards
/// completes; dropping it closes the fd.
#[derive(Debug)]
pub struct BridgeSnapshot {
    /// The pinned fd, or -1 when degraded.
    pub fd: i32,
    /// The fd alias when pinned, else the plain pathname.
    pub load_path: String,
    /// The hex sha256 of the pinned bytes, or "".
    pub sha: String,
}

impl BridgeSnapshot {
    fn empty() -> Self {
        Self {
            fd: -1,
            load_path: String::new(),
            sha: String::new(),
        }
    }
}

impl Drop for BridgeSnapshot {
    fn drop(&mut self) {
        if self.fd >= 0 {
            // SAFETY: pinned fd, closed once here.
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

/// Pin one bridge file for hashing and loading.
///
/// Opens `path` O_RDONLY (following a final symlink
/// once, at open) and hashes the open description
/// through its /proc/self/fd/N alias; the loader
/// receives the same alias. When the open or the
/// alias read fails, the snapshot degrades to the
/// plain pathname with an empty hash: admission
/// cannot bind and the loader reports its own
/// failure, exactly as before. Never fails.
pub fn open_bridge_snapshot(path: &str) -> BridgeSnapshot {
    let mut snap = BridgeSnapshot::empty();
    if path.is_empty() {
        return snap;
    }
    let cpath = to_cstr(path);
    // SAFETY: NUL-terminated path with AT_FDCWD.
    let fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            cpath.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        snap.load_path = path.to_string();
        return snap;
    }
    let alias = format!("/proc/self/fd/{fd}");
    match read_host_file(&alias, "bridge", MAX_NARROW_OBJECT_BYTES) {
        Ok(raw) => {
            snap.sha = sha256_hex(&raw);
            snap.fd = fd;
            snap.load_path = alias;
        }
        Err(_) => {
            // SAFETY: just-opened fd, closed once here.
            unsafe {
                libc::close(fd);
            }
            snap.load_path = path.to_string();
        }
    }
    snap
}

/// Pin one BPF object file for smoke input and minting.
///
/// The same mechanism as `open_bridge_snapshot`: one
/// O_RDONLY open, hashed and read through its
/// /proc/self/fd/N alias, degrading to the plain
/// pathname with an empty hash when uncheckable.
/// Qualify snapshots each object before the smoke,
/// feeds the alias to the smoke as its load input,
/// and mints from the snapshot hash, so the receipt
/// binds the exercised bytes. Never fails.
pub fn open_object_snapshot(path: &str) -> BridgeSnapshot {
    open_bridge_snapshot(path)
}

/// Parse a SUDO_UID/SUDO_GID value, or -1 when insane.
///
/// Strict ASCII decimal fitting uid_t
/// (0..4294967295); empty, non-digit, and
/// overflowing values refuse. -1 never collides:
/// it lies outside the uid_t range.
pub fn parse_sudo_id(text: &str) -> i64 {
    let raw = text.as_bytes();
    if raw.is_empty() || raw.len() > 10 {
        return -1;
    }
    let mut v: u64 = 0;
    for &b in raw {
        if !b.is_ascii_digit() {
            return -1;
        }
        let d = u64::from(b - b'0');
        if v > (0xFFFF_FFFF - d) / 10 {
            return -1;
        }
        v = v * 10 + d;
    }
    v as i64
}

/// Copy text into a fresh NUL-terminated byte buffer.
fn to_cstr(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

const OWN_STAT_SIZE: usize = 144;
const OWN_S_IFMT: u64 = 0o170000;
const OWN_S_IFREG: u64 = 0o100000;
const OWN_S_IFDIR: u64 = 0o040000;
const OWN_DIRENT_NAME_OFF: usize = 19;
const OWN_DIRENT_BUF_SIZE: usize = 8192;

/// True when the NUL-bounded name equals text, byte-wise.
fn own_name_is(buf: &[u8], base: usize, nlen: usize, text: &str) -> bool {
    let mut i = 0;
    for &b in text.as_bytes() {
        if i >= nlen {
            return false;
        }
        if buf[base + i] != b {
            return false;
        }
        i += 1;
    }
    i == nlen
}

fn own_le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn own_le64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

/// `[mode, uid, nlink]` for an open fd (x86-64 stat layout).
fn own_fstat_ids(fd: i32) -> Option<[u64; 3]> {
    let mut buf = [0u8; OWN_STAT_SIZE];
    // SAFETY: 144-byte buffer outlives the call.
    let r = unsafe { libc::fstat(fd, buf.as_mut_ptr().cast::<libc::stat>()) };
    if r != 0 {
        return None;
    }
    Some([
        u64::from(own_le32(&buf, 24)),
        u64::from(own_le32(&buf, 28)),
        own_le64(&buf, 16),
    ])
}

/// `[st_dev, st_ino]` for an open fd (x86-64 stat layout).
fn own_fstat_devino(fd: i32) -> Option<[u64; 2]> {
    let mut buf = [0u8; OWN_STAT_SIZE];
    // SAFETY: 144-byte buffer outlives the call.
    let r = unsafe { libc::fstat(fd, buf.as_mut_ptr().cast::<libc::stat>()) };
    if r != 0 {
        return None;
    }
    Some([own_le64(&buf, 0), own_le64(&buf, 8)])
}

fn own_close_quiet(fd: i32) {
    if fd >= 0 {
        // SAFETY: best-effort close of an owned-or-negative fd.
        unsafe {
            libc::close(fd);
        }
    }
}

/// True when `dir` holds entries besides the capture files.
///
/// A finalized capture holds exactly events.ndjson and
/// session.json; any other entry proves a planted or
/// swapped-in foreign file, and the repair must not
/// transfer the directory out from under it. Listing
/// failures also refuse (fail closed). Lists entries
/// with getdents64 straight off the held fd (no
/// DIR stream): getdents64 advances the directory
/// offset, so the caller must pass a fresh
/// descriptor it never lists twice (as the repair
/// path does). Never fails.
fn own_dir_has_foreign(dir_fd: i32) -> bool {
    let mut buf = [0u8; OWN_DIRENT_BUF_SIZE];
    let mut foreign = false;
    let mut failed = false;
    loop {
        // SAFETY: live dir fd with the 8 KiB buffer.
        let n = unsafe { libc::syscall(libc::SYS_getdents64, dir_fd, buf.as_mut_ptr(), buf.len()) };
        if n < 0 {
            failed = true;
            break;
        }
        if n == 0 {
            break;
        }
        let total = n as usize;
        let mut off = 0;
        while off < total {
            let nbase = off + OWN_DIRENT_NAME_OFF;
            if nbase > total {
                failed = true;
                break;
            }
            // d_name sits at byte 19 of the x86-64
            // Linux dirent (ino 8, off 8, reclen 2,
            // type 1); match the capture files
            // byte-wise, anything else is foreign.
            let reclen = usize::from(buf[off + 16]) | (usize::from(buf[off + 17]) << 8);
            if reclen < 20 || off + reclen > total {
                failed = true;
                break;
            }
            let mut nlen = 0;
            while OWN_DIRENT_NAME_OFF + nlen < reclen {
                if buf[nbase + nlen] == 0 {
                    break;
                }
                nlen += 1;
            }
            let known = own_name_is(&buf, nbase, nlen, ".")
                || own_name_is(&buf, nbase, nlen, "..")
                || own_name_is(&buf, nbase, nlen, "events.ndjson")
                || own_name_is(&buf, nbase, nlen, "session.json");
            if !known {
                foreign = true;
                break;
            }
            off += reclen;
        }
        if foreign || failed {
            break;
        }
    }
    foreign || failed
}

/// Open the directory itself, never a symlink; -1 on failure.
fn own_open_dir(path: &str) -> i32 {
    let cpath = to_cstr(path);
    // SAFETY: NUL-terminated path with AT_FDCWD.
    unsafe {
        libc::openat(
            libc::AT_FDCWD,
            cpath.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0 as libc::c_uint,
        )
    }
}

/// Open one child by name, never a symlink; -1 on failure.
fn own_open_child(dir_fd: i32, name: &str) -> i32 {
    let cname = to_cstr(name);
    // SAFETY: NUL-terminated name on the live dir fd.
    unsafe {
        libc::openat(
            dir_fd,
            cname.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_NOFOLLOW,
            0 as libc::c_uint,
        )
    }
}

/// True when an open child is a single-link regular file.
///
/// Symlinks never reach here (O_NOFOLLOW refuses them
/// at open). This rejects directories, fifos, sockets,
/// and files with extra hard links. Ownership is
/// checked separately by the caller. Never fails.
fn own_child_ok(fd: i32) -> bool {
    match own_fstat_ids(fd) {
        Some(ids) => ids[0] & OWN_S_IFMT == OWN_S_IFREG && ids[2] == 1,
        None => false,
    }
}

/// Owner uid of an open fd, or -1 on failure.
///
/// Under sudo every true capture file is
/// root-created, so any other owner proves a planted
/// replacement. Never fails.
fn own_fd_uid(fd: i32) -> i64 {
    match own_fstat_ids(fd) {
        Some(ids) => ids[1] as i64,
        None => -1,
    }
}

/// True when an open fd names the recorded identity.
///
/// Mode/uid/nlink alone cannot tell a substituted
/// root-owned file from the capture's own; dev/inode
/// continuity can. Never fails.
fn own_fd_matches(fd: i32, want_dev: u64, want_ino: u64) -> bool {
    match own_fstat_devino(fd) {
        Some(ids) => ids[0] == want_dev && ids[1] == want_ino,
        None => false,
    }
}

/// True when one fchown call reports success.
fn own_fchown(fd: i32, uid: u32, gid: u32) -> bool {
    // SAFETY: live fd with plain ids.
    let r = unsafe { libc::fchown(fd, uid, gid) };
    r == 0
}

/// Hand one expected child to the invoking user.
///
/// The child opens through the retained directory
/// descriptor and every later step (identity check,
/// ownership transfer) acts on that same open file
/// description, so a mid-repair replacement cannot
/// redirect the chown. Only the recorded capture file
/// transfers: a root-owned single-link regular file
/// whose dev/inode matches the finalize pin, compared
/// before any fchown. Anything else is rejected
/// untouched. False when the child is missing,
/// rejected, or unchownable. Never fails.
fn own_repair_child(
    dir_fd: i32,
    name: &str,
    uid: u32,
    gid: u32,
    want_dev: u64,
    want_ino: u64,
) -> bool {
    let fd = own_open_child(dir_fd, name);
    if fd < 0 {
        return false;
    }
    let mut ok = own_child_ok(fd) && own_fd_uid(fd) == 0 && own_fd_matches(fd, want_dev, want_ino);
    if ok {
        ok = own_fchown(fd, uid, gid);
    }
    own_close_quiet(fd);
    ok
}

/// One capture ownership repair: attempted, and whether it held.
///
/// `attempted` is true only for a root run under sudo
/// with sane invoking ids; anything else is a silent
/// no-op. `repaired` is true only when every expected
/// transfer succeeded. `uid`/`gid` name the invoking
/// user for the caller's warning; they are -1 when the
/// repair never attempted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnershipRepair {
    /// True only for a root run under sudo with sane ids.
    pub attempted: bool,
    /// True only when every transfer succeeded.
    pub repaired: bool,
    /// Invoking uid, or -1 when never attempted.
    pub uid: i64,
    /// Invoking gid, or -1 when never attempted.
    pub gid: i64,
}

impl OwnershipRepair {
    fn new() -> Self {
        Self {
            attempted: false,
            repaired: false,
            uid: -1,
            gid: -1,
        }
    }
}

/// Best-effort capture ownership repair; never fails.
///
/// Under sudo the capture lands root-owned (mkdir
/// 0700), locking out the invoking user's replay.
/// When both SUDO_UID and SUDO_GID parse as uid_t
/// values and this process runs as root (a non-root
/// run already owns its files, so there is nothing
/// to restore), hand the capture to the invoking
/// user through retained descriptors: the directory
/// opens with O_DIRECTORY|O_NOFOLLOW and must itself
/// be the recorded capture dir (dev/inode continuity
/// against the finalize pin, compared before any
/// fchown; a substituted dir aborts the repair before
/// anything is touched); each expected flat file
/// (events.ndjson, session.json) opens through that
/// descriptor, proves the recorded root-owned
/// single-link regular file, and transfers via
/// fchown, and only when the directory holds exactly
/// those two files; any foreign entry aborts the repair
/// before anything is touched. `want` is the writer's
/// [dir_dev, dir_ino, ev_dev, ev_ino, sess_dev,
/// sess_ino] pin; any other shape aborts touching
/// nothing. The directory transfers LAST, so the
/// invoking user gains no write access until every
/// child is already handed back and nothing can be
/// planted mid-repair. The result reports the repair;
/// the caller warns once on stderr for an attempted
/// repair that did not hold, and the capture itself
/// stands either way.
pub fn restore_capture_ownership(output: &str, want: &[u64]) -> OwnershipRepair {
    let mut repair = OwnershipRepair::new();
    let uid = parse_sudo_id(&std::env::var("SUDO_UID").unwrap_or_default());
    let gid = parse_sudo_id(&std::env::var("SUDO_GID").unwrap_or_default());
    if uid < 0 || gid < 0 {
        return repair;
    }
    if geteuid_live() != 0 {
        return repair;
    }
    repair.attempted = true;
    repair.uid = uid;
    repair.gid = gid;
    let mut ok = true;
    if want.len() != 6 {
        return repair;
    }
    let dir_fd = own_open_dir(output);
    if dir_fd < 0 {
        ok = false;
    } else {
        let mut dir_ok = false;
        if let Some(ids) = own_fstat_ids(dir_fd) {
            dir_ok = ids[0] & OWN_S_IFMT == OWN_S_IFDIR
                && ids[1] == 0
                && own_fd_matches(dir_fd, want[0], want[1]);
        }
        if dir_ok && own_dir_has_foreign(dir_fd) {
            dir_ok = false;
        }
        if dir_ok {
            if !own_repair_child(
                dir_fd,
                "events.ndjson",
                uid as u32,
                gid as u32,
                want[2],
                want[3],
            ) {
                ok = false;
            }
            if !own_repair_child(
                dir_fd,
                "session.json",
                uid as u32,
                gid as u32,
                want[4],
                want[5],
            ) {
                ok = false;
            }
            if !own_fchown(dir_fd, uid as u32, gid as u32) {
                ok = false;
            }
        } else {
            ok = false;
        }
        own_close_quiet(dir_fd);
    }
    repair.repaired = ok;
    repair
}

#[cfg(test)]
mod tests {
    use super::{
        join_root, open_bridge_snapshot, open_object_snapshot, parse_sudo_id,
        restore_capture_ownership,
    };
    use crate::platform::hash::sha256_hex;
    use crate::platform::reader::{geteuid_live, read_host_file};
    use crate::platform::test_support::TestDir;

    #[test]
    fn join_root_edges() {
        assert_eq!(join_root("", "/a"), "/a");
        assert_eq!(join_root("/", "/a"), "/a");
        assert_eq!(join_root("/r", "/a"), "/r/a");
    }

    #[test]
    fn parse_sudo_id_edges() {
        assert_eq!(parse_sudo_id("1001"), 1001);
        assert_eq!(parse_sudo_id("0"), 0);
        assert_eq!(parse_sudo_id("4294967295"), 4_294_967_295);
        assert_eq!(parse_sudo_id(""), -1);
        assert_eq!(parse_sudo_id("nope"), -1);
        assert_eq!(parse_sudo_id("4294967296"), -1);
        assert_eq!(parse_sudo_id("-1"), -1);
        assert_eq!(parse_sudo_id("00001"), 1);
        assert_eq!(parse_sudo_id(" 1"), -1);
    }

    #[test]
    fn snapshot_missing_degrades() {
        let snap = open_bridge_snapshot("/nonexistent/memveil-bridge.so.1");
        assert_eq!(snap.sha, "");
        assert_eq!(snap.load_path, "/nonexistent/memveil-bridge.so.1");
        let obj = open_object_snapshot("/nonexistent/memveil-object.o");
        assert_eq!(obj.sha, "");
        assert_eq!(obj.load_path, "/nonexistent/memveil-object.o");
    }

    #[test]
    fn snapshot_empty_path_stays_empty() {
        let snap = open_bridge_snapshot("");
        assert_eq!(snap.sha, "");
        assert_eq!(snap.load_path, "");
    }

    #[test]
    fn snapshot_directory_degrades() {
        // A directory opens but never streams bytes, so the
        // snapshot falls back to the plain pathname.
        let tmp = TestDir::create("memveil-snap").expect("mkdtemp");
        let snap = open_bridge_snapshot(tmp.as_str());
        assert_eq!(snap.sha, "");
        assert_eq!(snap.load_path, tmp.as_str());
    }

    #[test]
    fn snapshot_survives_pathname_swap() {
        // Snapshot P, then rename a replacement over P: the
        // snapshot hash and load path must still see the
        // original bytes while the pathname sees the swap.
        let tmp = TestDir::create("memveil-snap").expect("mkdtemp");
        let path = tmp.path().join("bridge.so");
        let repl = tmp.path().join("replacement.so");
        std::fs::write(&path, b"ORIGINAL-BRIDGE-BYTES\n").expect("write orig");
        std::fs::write(&repl, b"SWAPPED-BRIDGE-BYTES\n").expect("write repl");
        let spath = path.to_str().unwrap().to_string();
        let snap = open_bridge_snapshot(&spath);
        assert_ne!(snap.sha, "");
        std::fs::rename(&repl, &path).expect("rename over");
        let now = read_host_file(&spath, "bridge", 4096).expect("pathname reads");
        assert_eq!(now, b"SWAPPED-BRIDGE-BYTES\n");
        let pinned = read_host_file(&snap.load_path, "bridge", 4096).expect("alias reads");
        assert_eq!(pinned, b"ORIGINAL-BRIDGE-BYTES\n");
        assert_eq!(snap.sha, sha256_hex(&pinned));
    }

    #[test]
    fn restore_silent_outside_root() {
        // Outside a root run there is nothing to hand back:
        // the repair reports unattempted and stays silent.
        // The root-only transfer probes stay with the
        // ownership suite, which runs them under sudo.
        if geteuid_live() == 0 {
            return;
        }
        let repair = restore_capture_ownership("/nonexistent-cap", &[]);
        assert!(!repair.attempted);
        assert!(!repair.repaired);
        assert_eq!(repair.uid, -1);
        assert_eq!(repair.gid, -1);
    }
}
