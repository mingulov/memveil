// SPDX-License-Identifier: GPL-3.0-or-later
//! Passive evidence reader: live host or recorded fixture.
//!
//! The doctor never loads BPF, never writes the system, and never
//! executes helpers. All platform evidence comes through this reader, which
//! either probes the live host (libc: uname, geteuid,
//! access, fread) or replays a recorded fixture tree.
//!
//! A fixture directory maps host paths to relative ones:
//!
//! ```text
//! <fixture>/meta.txt                    key=value inventory header
//!                                       (arch/release/euid required)
//! <fixture>/sys/kernel/tracing/...     evidence trees as found
//! <fixture>/sys/kernel/mm/...          SEV nodes, when present
//! <fixture>/sys/devices/virtual/...    TDX node, when present
//! <fixture>/proc/...                   proc evidence, when held
//! ```
//!
//! Live mode (`root == ""`) never consults `meta.txt` and never reports
//! asserted guest tech. Fixture mode requires `meta.txt`; a fixture
//! without it is rejected rather than half-read.
//!
//! Reads are capped; unreadable evidence is distinguished as absent (path
//! missing) versus denied (permission refused), never silently skipped.
//! Fixture reads open root-relative without following symlinks and
//! refuse dotdot escapes; the open itself classifies, with no
//! access-then-open race.

/// Evidence path exists and reads.
pub const EVIDENCE_OK: i32 = 0;
/// Evidence path is missing.
pub const EVIDENCE_ABSENT: i32 = 1;
/// Evidence path is refused.
pub const EVIDENCE_DENIED: i32 = 2;

/// Fixture without `meta.txt`.
pub const E_META_MISSING: u32 = 1;
/// Malformed fixture header.
pub const E_META_BAD: u32 = 2;
/// Evidence path is missing.
pub const E_ABSENT: u32 = 3;
/// Evidence path is refused.
pub const E_DENIED: u32 = 4;
/// Evidence exceeds the read cap.
pub const E_TOO_BIG: u32 = 5;
/// Evidence cannot be opened or read.
pub const E_IO: u32 = 6;
/// `uname` failed or is empty.
pub const E_UNAME: u32 = 7;

const CHUNK_BYTES: usize = 65_536;
const UTS_FIELD_LEN: usize = 65;
const FS_TMPFS: i64 = 0x0102_1994;
const FS_EXT: i64 = 0xEF53;
const FS_OVERLAY: i64 = 0x794C_7630;
const FS_XFS: i64 = 0x5846_5342;
const FS_BTRFS: i64 = 0x9123_683E;
const FS_NFS: i64 = 0x6969;
const FS_9P: i64 = 0x0102_1997;
const FS_FUSE: i64 = 0x6575_5546;
const MAX_EUID: i64 = 2_147_483_647;

/// One evidence failure. Callers match on `code`, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceError {
    /// Machine-stable failure code (`E_*`).
    pub code: u32,
    /// Human detail; never matched on.
    pub message: String,
}

impl EvidenceError {
    fn new(code: u32, message: String) -> Self {
        Self { code, message }
    }
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "EvidenceError(code={}, message={})",
            self.code, self.message
        )
    }
}

impl std::error::Error for EvidenceError {}

/// One evidence source: live host or one fixture directory.
///
/// `root` is `""` for the live host, else the fixture directory
/// path. `arch`/`release`/`euid` come from uname/geteuid live,
/// or from `meta.txt` in a fixture. `denied` holds
/// fixture-declared unreadable paths (always empty live).
/// `asserted_guest_tech` is non-empty only when a fixture author
/// recorded an out-of-band guest-tech note using the doctor
/// vocabulary (`snp`, `sev-classic`, `tdx`); live runs never
/// assert.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceReader {
    /// `""` live, else the fixture directory path.
    pub root: String,
    /// Machine architecture.
    pub arch: String,
    /// Kernel release.
    pub release: String,
    /// Effective uid.
    pub euid: i64,
    /// Fixture-declared unreadable paths.
    pub denied: Vec<String>,
    /// Fixture-only guest-tech assertion, else `""`.
    pub asserted_guest_tech: String,
}

/// Copy text into a fresh NUL-terminated byte buffer.
///
/// Small duplicate of the capture reader's helper: the platform
/// layer must not reach into capture internals.
fn to_cstr_local(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

/// Read the calling thread's libc errno value.
fn errno_now() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// True when the bytes are strict RFC 3629 UTF-8.
///
/// Rejects overlongs, surrogates, code points past U+10FFFF,
/// and truncated sequences. Paths that fail this check are
/// never lossy-decoded into a lookup: decoding substitutes
/// U+FFFD, which could resolve a different tree than the
/// kernel named.
pub fn is_valid_utf8(data: &[u8]) -> bool {
    let mut i = 0;
    let n = data.len();
    while i < n {
        let b0 = data[i];
        if b0 < 0x80 {
            i += 1;
            continue;
        }
        let need: usize;
        let mut lo = 0x80;
        let mut hi = 0xBF;
        if (0xC2..=0xDF).contains(&b0) {
            need = 1;
        } else if (0xE0..=0xEF).contains(&b0) {
            need = 2;
            if b0 == 0xE0 {
                lo = 0xA0;
            }
            if b0 == 0xED {
                hi = 0x9F;
            }
        } else if (0xF0..=0xF4).contains(&b0) {
            need = 3;
            if b0 == 0xF0 {
                lo = 0x90;
            }
            if b0 == 0xF4 {
                hi = 0x8F;
            }
        } else {
            return false;
        }
        if i + need >= n {
            return false;
        }
        for k in 1..=need {
            let bc = data[i + k];
            if k == 1 {
                if bc < lo || bc > hi {
                    return false;
                }
            } else if !(0x80..=0xBF).contains(&bc) {
                return false;
            }
        }
        i += need + 1;
    }
    true
}

/// Resolve the running executable via `/proc/self/exe`.
///
/// Unlike argv\[0\] this cannot be a bare PATH name or a spoofed
/// string: the kernel reports the true binary path. Linux-only,
/// matching the supported collection target. Fails with E_IO when
/// the link cannot be read, overruns the 4 KiB buffer, or is
/// not valid UTF-8 (a lossy substitute could resolve a
/// different tree than the kernel named).
pub fn readlink_self() -> Result<String, EvidenceError> {
    let link = to_cstr_local("/proc/self/exe");
    let mut buf = [0u8; 4096];
    // SAFETY: NUL-terminated link path with a live 4 KiB buffer.
    let n = unsafe {
        libc::readlink(
            link.as_ptr().cast::<libc::c_char>(),
            buf.as_mut_ptr().cast::<libc::c_char>(),
            buf.len(),
        )
    };
    if n <= 0 || n >= 4096 {
        return Err(EvidenceError::new(
            E_IO,
            "cannot resolve executable path".to_string(),
        ));
    }
    let raw = &buf[..n as usize];
    if !is_valid_utf8(raw) {
        return Err(EvidenceError::new(
            E_IO,
            "executable path not UTF-8".to_string(),
        ));
    }
    Ok(bytes_to_text(raw))
}

/// Decode one NUL-terminated utsname field.
fn uname_field(buf: &[libc::c_char; UTS_FIELD_LEN], what: &str) -> Result<String, EvidenceError> {
    let mut raw = Vec::new();
    for &c in buf.iter() {
        if c == 0 {
            break;
        }
        raw.push(c as u8);
    }
    if raw.is_empty() {
        return Err(EvidenceError::new(E_UNAME, format!("uname {what} empty")));
    }
    Ok(bytes_to_text(&raw))
}

/// Return the live machine field from uname(2), e.g. x86_64.
fn uname_machine() -> Result<String, EvidenceError> {
    // SAFETY: zeroed utsname outlives the call.
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let r = unsafe { libc::uname(&mut buf) };
    if r != 0 {
        return Err(EvidenceError::new(E_UNAME, "uname failed".to_string()));
    }
    uname_field(&buf.machine, "machine")
}

/// Return the live release field from uname(2).
fn uname_release() -> Result<String, EvidenceError> {
    // SAFETY: zeroed utsname outlives the call.
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let r = unsafe { libc::uname(&mut buf) };
    if r != 0 {
        return Err(EvidenceError::new(E_UNAME, "uname failed".to_string()));
    }
    uname_field(&buf.release, "release")
}

/// Return the live effective uid.
pub fn geteuid_live() -> i64 {
    // SAFETY: pure id query.
    unsafe { libc::geteuid() as i64 }
}

/// Return the live real uid.
pub fn getuid_live() -> i64 {
    // SAFETY: pure id query.
    unsafe { libc::getuid() as i64 }
}

/// Parse a meta.txt euid: decimal digits, 0..2**31-1.
fn parse_euid(text: &str) -> Result<i64, EvidenceError> {
    if text.is_empty() {
        return Err(EvidenceError::new(
            E_META_BAD,
            "meta euid empty".to_string(),
        ));
    }
    let mut acc: i64 = 0;
    for &b in text.as_bytes() {
        if !b.is_ascii_digit() {
            return Err(EvidenceError::new(
                E_META_BAD,
                "meta euid not decimal".to_string(),
            ));
        }
        let digit = i64::from(b - b'0');
        if acc > (MAX_EUID - digit) / 10 {
            return Err(EvidenceError::new(
                E_META_BAD,
                "meta euid too large".to_string(),
            ));
        }
        acc = acc * 10 + digit;
    }
    Ok(acc)
}

/// True when the path's first byte is /. Empty is not absolute.
fn is_absolute(path: &str) -> bool {
    path.as_bytes().first() == Some(&0x2F)
}

/// Parse a meta.txt denied list: comma-separated absolute paths.
fn parse_denied(text: &str) -> Result<Vec<String>, EvidenceError> {
    let mut out = Vec::new();
    if text.is_empty() {
        return Ok(out);
    }
    for cur in text.split(',') {
        if cur.is_empty() || !is_absolute(cur) {
            return Err(EvidenceError::new(
                E_META_BAD,
                "meta denied entry not absolute".to_string(),
            ));
        }
        if cur.len() > 256 {
            return Err(EvidenceError::new(
                E_META_BAD,
                "meta denied entry too long".to_string(),
            ));
        }
        out.push(cur.to_string());
    }
    Ok(out)
}

/// Parse meta.txt into a fixture reader skeleton (root unset).
///
/// Grammar: one `key=value` per line, LF-terminated, no comments,
/// no blank padding, no duplicate or unknown keys, no `=` inside
/// values, no NUL byte in any value (libc truncates paths at NUL,
/// so a NUL would smuggle a different path past validation).
/// Known keys: `arch`, `release`, `euid`, `denied`,
/// `asserted_guest_tech`. `arch`, `release`, and `euid` are
/// required; the others default to empty. Length bounds keep every
/// derived report field inside the doctor schema: `arch` 1..32
/// bytes, `release` 1..128 bytes, each `denied` entry 1..256
/// bytes.
fn parse_meta(text: &str) -> Result<EvidenceReader, EvidenceError> {
    let bad = |message: &str| EvidenceError::new(E_META_BAD, message.to_string());
    let mut arch = String::new();
    let mut release = String::new();
    let mut euid_text = String::new();
    let mut denied_text = String::new();
    let mut asserted = String::new();
    let mut seen_arch = false;
    let mut seen_release = false;
    let mut seen_euid = false;
    let mut seen_denied = false;
    let mut seen_asserted = false;
    let lines: Vec<&str> = text.split('\n').collect();
    for (i, line) in lines.iter().enumerate() {
        let last = i == lines.len() - 1;
        if last && line.is_empty() {
            break;
        }
        if line.is_empty() {
            return Err(bad("meta blank line"));
        }
        let kv: Vec<&str> = line.split('=').collect();
        if kv.len() != 2 {
            return Err(bad("meta line without one ="));
        }
        let (key, val) = (kv[0], kv[1]);
        if val.as_bytes().contains(&0) {
            return Err(bad("meta NUL byte"));
        }
        match key {
            "arch" => {
                if seen_arch {
                    return Err(bad("meta duplicate arch"));
                }
                seen_arch = true;
                arch = val.to_string();
            }
            "release" => {
                if seen_release {
                    return Err(bad("meta duplicate release"));
                }
                seen_release = true;
                release = val.to_string();
            }
            "euid" => {
                if seen_euid {
                    return Err(bad("meta duplicate euid"));
                }
                seen_euid = true;
                euid_text = val.to_string();
            }
            "denied" => {
                if seen_denied {
                    return Err(bad("meta duplicate denied"));
                }
                seen_denied = true;
                denied_text = val.to_string();
            }
            "asserted_guest_tech" => {
                if seen_asserted {
                    return Err(bad("meta duplicate asserted_guest_tech"));
                }
                seen_asserted = true;
                asserted = val.to_string();
            }
            _ => return Err(bad("meta unknown key")),
        }
    }
    if !seen_arch || !seen_release || !seen_euid {
        return Err(bad("meta missing arch, release, or euid"));
    }
    if arch.is_empty() {
        return Err(bad("meta arch empty"));
    }
    if arch.len() > 32 {
        return Err(bad("meta arch too long"));
    }
    if release.is_empty() {
        return Err(bad("meta release empty"));
    }
    if release.len() > 128 {
        return Err(bad("meta release too long"));
    }
    if !asserted.is_empty() && asserted != "snp" && asserted != "sev-classic" && asserted != "tdx" {
        return Err(bad("meta unknown guest tech"));
    }
    let euid = parse_euid(&euid_text)?;
    let denied = parse_denied(&denied_text)?;
    Ok(EvidenceReader {
        root: String::new(),
        arch,
        release,
        euid,
        denied,
        asserted_guest_tech: asserted,
    })
}

/// Read a small evidence file without over-allocating past `cap`.
///
/// Same chunked pattern as the capture reader: a fixed 64 KiB
/// buffer streams through, and the running total is checked before
/// each chunk lands, so an oversized file is rejected after one
/// chunk over the bound instead of being read fully.
fn read_bounded_local(path: &str, what: &str, cap: usize) -> Result<Vec<u8>, EvidenceError> {
    let cpath = to_cstr_local(path);
    // SAFETY: NUL-terminated path and mode; NULL means unopenable.
    let fp = unsafe { libc::fopen(cpath.as_ptr().cast::<libc::c_char>(), c"rb".as_ptr()) };
    if fp.is_null() {
        return Err(EvidenceError::new(E_IO, format!("{what}: cannot open")));
    }
    drain_fp(fp, what, cap)
}

/// Close when open; best effort, no error.
fn close_quiet_local(fd: libc::c_int) {
    if fd >= 0 {
        // SAFETY: best-effort close of an owned-or-negative fd.
        unsafe {
            libc::close(fd);
        }
    }
}

/// Drain one open stream with the shared chunk/cap rules.
///
/// E_IO on read failure, E_TOO_BIG past the cap; the stream
/// closes on every path.
fn drain_fp(fp: *mut libc::FILE, what: &str, cap: usize) -> Result<Vec<u8>, EvidenceError> {
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut out = Vec::new();
    loop {
        // SAFETY: live stream and chunk; fread reports a short count.
        let got = unsafe {
            libc::fread(
                chunk.as_mut_ptr().cast::<libc::c_void>(),
                1,
                CHUNK_BYTES,
                fp,
            )
        };
        if got == 0 {
            // SAFETY: as above; the stream closes on every path.
            let ferr = unsafe { libc::ferror(fp) };
            unsafe {
                libc::fclose(fp);
            }
            if ferr != 0 {
                return Err(EvidenceError::new(E_IO, format!("{what}: cannot read")));
            }
            return Ok(out);
        }
        let n = got as usize;
        if out.len() + n > cap {
            // SAFETY: as above.
            unsafe {
                libc::fclose(fp);
            }
            return Err(EvidenceError::new(E_TOO_BIG, format!("{what} too large")));
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Split a fixture path into contained components.
///
/// Empty parts and `.` collapse; `..` pops one part and
/// refuses past the root: a hostile fixture cannot spell an
/// escape.
fn lexical_parts(path: &str) -> Result<Vec<String>, EvidenceError> {
    let mut out = Vec::new();
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        if part == ".." {
            if out.is_empty() {
                return Err(EvidenceError::new(
                    E_DENIED,
                    format!("{path}: escapes fixture root"),
                ));
            }
            out.pop();
            continue;
        }
        out.push(part.to_string());
    }
    Ok(out)
}

/// Classify a failed open: only ENOENT is absent.
fn open_errno_error(path: &str) -> EvidenceError {
    if errno_now() == libc::ENOENT {
        EvidenceError::new(E_ABSENT, format!("{path}: absent"))
    } else {
        EvidenceError::new(E_DENIED, format!("{path}: denied"))
    }
}

/// Open one fixture path with no symlink following.
///
/// Walks root-relative with O_NOFOLLOW on every component,
/// so neither the final name nor an intermediate directory
/// can be a symlink escape. The root itself is
/// operator-supplied and opened plainly.
fn contained_fd(root: &str, path: &str) -> Result<libc::c_int, EvidenceError> {
    let parts = lexical_parts(path)?;
    let croot = to_cstr_local(root);
    // SAFETY: NUL-terminated root; failures classify from errno.
    if parts.is_empty() {
        let fd0 = unsafe {
            libc::open(
                croot.as_ptr().cast::<libc::c_char>(),
                libc::O_RDONLY | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        if fd0 < 0 {
            return Err(open_errno_error(path));
        }
        return Ok(fd0);
    }
    // SAFETY: as above.
    let mut dfd = unsafe {
        libc::open(
            croot.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    if dfd < 0 {
        return Err(open_errno_error(path));
    }
    let step_flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    for part in &parts[..parts.len() - 1] {
        let cp = to_cstr_local(part);
        // SAFETY: NUL-terminated component on a live dir fd.
        let nfd = unsafe {
            libc::openat(
                dfd,
                cp.as_ptr().cast::<libc::c_char>(),
                step_flags,
                0 as libc::c_uint,
            )
        };
        close_quiet_local(dfd);
        if nfd < 0 {
            return Err(open_errno_error(path));
        }
        dfd = nfd;
    }
    let last = to_cstr_local(&parts[parts.len() - 1]);
    // SAFETY: as above.
    let fd = unsafe {
        libc::openat(
            dfd,
            last.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    close_quiet_local(dfd);
    if fd < 0 {
        return Err(open_errno_error(path));
    }
    Ok(fd)
}

/// Read one fixture file, contained, without following links.
///
/// Fails with E_ABSENT when the contained path is missing, E_DENIED
/// when it is unreadable, a symlink, or an escape, E_TOO_BIG
/// past the cap, E_IO on read failure.
fn read_bounded_contained(
    root: &str,
    path: &str,
    what: &str,
    cap: usize,
) -> Result<Vec<u8>, EvidenceError> {
    let fd = contained_fd(root, path)?;
    // SAFETY: fdopen takes the fd on success; on NULL the fd closes here.
    let fp = unsafe { libc::fdopen(fd, c"rb".as_ptr()) };
    if fp.is_null() {
        close_quiet_local(fd);
        return Err(EvidenceError::new(E_IO, format!("{what}: cannot open")));
    }
    drain_fp(fp, what, cap)
}

/// Read one live path, opening first, symlinks followed.
///
/// Live system paths legitimately contain links; the open
/// errno classifies absent versus denied with no access()
/// probe, so no race sits between check and use.
fn read_bounded_mapped(path: &str, what: &str, cap: usize) -> Result<Vec<u8>, EvidenceError> {
    let cpath = to_cstr_local(path);
    // SAFETY: NUL-terminated path and mode; errno classifies failure.
    let fp = unsafe { libc::fopen(cpath.as_ptr().cast::<libc::c_char>(), c"rb".as_ptr()) };
    if fp.is_null() {
        return Err(open_errno_error(what));
    }
    drain_fp(fp, what, cap)
}

/// One streamed line consumer: fixed-chunk file reuse.
///
/// `feed` takes one nonempty LF-delimited line (the newline
/// itself is not included) and returns `""` on success. A
/// nonempty return is failure detail: the stream closes the
/// file and stops at once, so the first bad line is the one
/// reported. The sink records whatever it needs: the stream
/// holds only its 64 KiB chunk plus the current line.
pub trait LineSink {
    /// Consume one line; a nonempty return stops the stream.
    fn feed(&mut self, line: Vec<u8>) -> String;
}

/// Stream one host file to a line sink, capped at `cap` bytes.
///
/// Same open/read/cap semantics as `read_host_file`:
/// E_IO on open/read failure, E_TOO_BIG past the cap. Lines
/// are nonempty spans split on LF; a trailing span without a
/// newline is still delivered, and empty spans are skipped.
/// Stops after the first feed failure; the sink owns the
/// detail. Unlike `read_evidence` this never maps a fixture
/// root: the path is taken literally.
pub fn stream_host_lines<S: LineSink>(
    path: &str,
    what: &str,
    cap: usize,
    sink: &mut S,
) -> Result<(), EvidenceError> {
    let cpath = to_cstr_local(path);
    // SAFETY: NUL-terminated path and mode; NULL means unopenable.
    let fp = unsafe { libc::fopen(cpath.as_ptr().cast::<libc::c_char>(), c"rb".as_ptr()) };
    if fp.is_null() {
        return Err(EvidenceError::new(E_IO, format!("{what}: cannot open")));
    }
    let mut chunk = [0u8; CHUNK_BYTES];
    let mut acc = Vec::new();
    let mut total = 0usize;
    loop {
        // SAFETY: live stream and chunk; the stream closes on every path.
        let got = unsafe {
            libc::fread(
                chunk.as_mut_ptr().cast::<libc::c_void>(),
                1,
                CHUNK_BYTES,
                fp,
            )
        };
        if got == 0 {
            // SAFETY: as above.
            let ferr = unsafe { libc::ferror(fp) };
            unsafe {
                libc::fclose(fp);
            }
            if ferr != 0 {
                return Err(EvidenceError::new(E_IO, format!("{what}: cannot read")));
            }
            if !acc.is_empty() {
                let tail = std::mem::take(&mut acc);
                let _ = sink.feed(tail);
            }
            return Ok(());
        }
        let n = got as usize;
        if total + n > cap {
            // SAFETY: as above.
            unsafe {
                libc::fclose(fp);
            }
            return Err(EvidenceError::new(E_TOO_BIG, format!("{what} too large")));
        }
        total += n;
        for &b in &chunk[..n] {
            if b != 0x0A {
                acc.push(b);
                continue;
            }
            if acc.is_empty() {
                continue;
            }
            let span = std::mem::take(&mut acc);
            if !sink.feed(span).is_empty() {
                // SAFETY: as above.
                unsafe {
                    libc::fclose(fp);
                }
                return Ok(());
            }
        }
    }
}

/// Open the live host (`root == ""`) or one fixture directory.
///
/// Fixture mode requires `<root>/meta.txt` and rejects the
/// fixture when it is missing or malformed.
pub fn open_evidence_reader(root: &str) -> Result<EvidenceReader, EvidenceError> {
    if root.is_empty() {
        return Ok(EvidenceReader {
            root: String::new(),
            arch: uname_machine()?,
            release: uname_release()?,
            euid: geteuid_live(),
            denied: Vec::new(),
            asserted_guest_tech: String::new(),
        });
    }
    let raw = match read_bounded_contained(root, "/meta.txt", "meta.txt", CHUNK_BYTES) {
        Ok(raw) => raw,
        Err(e) => {
            if e.code == E_DENIED {
                return Err(EvidenceError::new(E_META_BAD, e.to_string()));
            }
            return Err(EvidenceError::new(E_META_MISSING, e.to_string()));
        }
    };
    if !is_valid_utf8(&raw) {
        return Err(EvidenceError::new(E_META_BAD, "meta not UTF-8".to_string()));
    }
    let text = bytes_to_text(&raw);
    let mut reader = parse_meta(&text)?;
    reader.root = root.to_string();
    Ok(reader)
}

/// Map a host-absolute evidence path into the reader's root.
pub fn evidence_path(reader: &EvidenceReader, path: &str) -> String {
    if reader.root.is_empty() {
        return path.to_string();
    }
    format!("{}{}", reader.root, path)
}

/// True when a fixture declares `path` unreadable. Always false live.
pub fn is_denied(reader: &EvidenceReader, path: &str) -> bool {
    reader.denied.iter().any(|d| d == path)
}

/// Classify one evidence path: OK, ABSENT, or DENIED.
///
/// Fixture-declared denied paths report DENIED even when the
/// fixture holds their content, so a fixture can model a live
/// refusal. Otherwise access() decides, with errno telling
/// absence from refusal: only ENOENT is ABSENT. Any other
/// failure (EACCES on the path or a parent, ELOOP, exotic
/// errors) is DENIED, since absence is unproven. Present and
/// readable is OK.
pub fn file_state(reader: &EvidenceReader, path: &str) -> i32 {
    if is_denied(reader, path) {
        return EVIDENCE_DENIED;
    }
    let mapped = evidence_path(reader, path);
    let cpath = to_cstr_local(&mapped);
    // SAFETY: NUL-terminated mapped path.
    let r = unsafe { libc::access(cpath.as_ptr().cast::<libc::c_char>(), libc::F_OK) };
    if r == 0 {
        // SAFETY: as above.
        let r2 = unsafe { libc::access(cpath.as_ptr().cast::<libc::c_char>(), libc::R_OK) };
        if r2 == 0 {
            return EVIDENCE_OK;
        }
        return EVIDENCE_DENIED;
    }
    if errno_now() == libc::ENOENT {
        EVIDENCE_ABSENT
    } else {
        EVIDENCE_DENIED
    }
}

/// True when a host path exists but reads as denied.
///
/// Host paths (profiles, receipts) are never
/// fixture-mapped: access() decides, with errno telling
/// absence from refusal, mirroring `file_state`.
pub fn host_file_denied(path: &str) -> bool {
    let cpath = to_cstr_local(path);
    // SAFETY: NUL-terminated host path.
    let r = unsafe { libc::access(cpath.as_ptr().cast::<libc::c_char>(), libc::F_OK) };
    if r == 0 {
        // SAFETY: as above.
        let r2 = unsafe { libc::access(cpath.as_ptr().cast::<libc::c_char>(), libc::R_OK) };
        return r2 != 0;
    }
    errno_now() != libc::ENOENT
}

/// Mirror faccessat(path, F_OK, AT_EACCESS): existence with teeth.
///
/// True when the mapped path exists. A fixture strict
/// ancestor listed in denied= hides the path (a live
/// EACCES on a parent reads the same); a denied path
/// itself still exists, since denied is never absent.
/// Effective ids match the loader, so a capability-held
/// caller sees the same tracefs root libbpf opens.
pub fn exists_f_ok(reader: &EvidenceReader, path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').collect();
    let end = parts.len().saturating_sub(1).max(1);
    let mut acc = String::new();
    for part in parts.iter().take(end).skip(1) {
        acc.push('/');
        acc.push_str(part);
        if is_denied(reader, &acc) {
            return false;
        }
    }
    let mapped = evidence_path(reader, path);
    let cpath = to_cstr_local(&mapped);
    // SAFETY: NUL-terminated mapped path with AT_FDCWD.
    let r = unsafe {
        libc::faccessat(
            libc::AT_FDCWD,
            cpath.as_ptr().cast::<libc::c_char>(),
            libc::F_OK,
            libc::AT_EACCESS,
        )
    };
    r == 0
}

/// Read one evidence file, capped at `cap` bytes.
///
/// Opens first and classifies from the open: no access()
/// probe sits between check and use. Fixture reads stay
/// inside the root and refuse symlinks; live reads follow
/// links as before. Fails with E_ABSENT when the path is
/// missing, E_DENIED when it is unreadable, a link, or an
/// escape, E_TOO_BIG past the cap, E_IO on read failure.
/// Bytes are returned raw; text decoding is the caller's
/// choice.
pub fn read_evidence(
    reader: &EvidenceReader,
    path: &str,
    cap: usize,
) -> Result<Vec<u8>, EvidenceError> {
    if is_denied(reader, path) {
        return Err(EvidenceError::new(E_DENIED, format!("{path}: denied")));
    }
    if reader.root.is_empty() {
        return read_bounded_mapped(path, path, cap);
    }
    read_bounded_contained(&reader.root, path, path, cap)
}

/// Read one small host file (profile, manifest), capped at `cap` bytes.
///
/// Unlike `read_evidence` this never maps a fixture root: profile
/// and manifest paths are taken literally. Fails with E_IO on open/read
/// failure and E_TOO_BIG past the cap.
pub fn read_host_file(path: &str, what: &str, cap: usize) -> Result<Vec<u8>, EvidenceError> {
    read_bounded_local(path, what, cap)
}

fn hex_trim(v: i64) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    let mut started = false;
    for i in 0..16 {
        let nib = ((v >> ((15 - i) * 4)) & 15) as usize;
        if nib != 0 || started || i == 15 {
            started = true;
            out.push(DIGITS[nib] as char);
        }
    }
    out
}

/// Filesystem type holding `path`, or an unavailable marker.
///
/// statfs(2) f_type mapped for common filesystems; unknown
/// magics render as hex, failures as unavailable markers.
/// Never fails.
pub fn fs_type_name(path: &str) -> String {
    let cstr = to_cstr_local(path);
    // SAFETY: zeroed statfs outlives the call.
    let mut buf: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: NUL-terminated path with the live buffer.
    let r = unsafe { libc::statfs(cstr.as_ptr().cast::<libc::c_char>(), &mut buf) };
    if r != 0 {
        return "unavailable: statfs failed".to_string();
    }
    // f_type is the 8 LE bytes the Mojo side accumulates by hand.
    let magic = buf.f_type;
    if magic == FS_TMPFS {
        return "tmpfs".to_string();
    }
    if magic == FS_EXT {
        return "ext2/ext3/ext4".to_string();
    }
    if magic == FS_OVERLAY {
        return "overlay".to_string();
    }
    if magic == FS_XFS {
        return "xfs".to_string();
    }
    if magic == FS_BTRFS {
        return "btrfs".to_string();
    }
    if magic == FS_NFS {
        return "nfs".to_string();
    }
    if magic == FS_9P {
        return "9p".to_string();
    }
    if magic == FS_FUSE {
        return "fuse".to_string();
    }
    format!("unknown:0x{}", hex_trim(magic))
}

/// Decode evidence bytes as UTF-8, replacing invalid sequences.
///
/// Evidence text (cpuinfo, release files, meta) is kernel or
/// distro ASCII in practice; lossy decoding keeps the doctor total
/// over hostile fixtures. Byte-exact comparisons (tracepoint
/// format signatures) never pass through here.
pub fn bytes_to_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::test_support::{TestDir, capabilities_fixture, gate_fixture};

    fn fx(name: &str) -> String {
        capabilities_fixture(name)
    }

    fn expect_code(result: Result<Vec<u8>, EvidenceError>, want: u32) {
        match result {
            Ok(_) => panic!("read succeeded, want code {want}"),
            Err(e) => assert_eq!(e.code, want),
        }
    }

    #[test]
    fn meta_ok() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        assert_eq!(r.arch, "x86_64");
        assert_eq!(r.release, "7.0.0-34-generic");
        assert_eq!(r.euid, 1001);
        assert_eq!(r.denied.len(), 0);
        assert_eq!(r.asserted_guest_tech, "");
    }

    #[test]
    fn meta_missing() {
        let err = open_evidence_reader(&fx("profiles-test")).unwrap_err();
        assert_eq!(err.code, E_META_MISSING);
    }

    #[test]
    fn meta_bad_fixtures() {
        for name in [
            "meta-bad-dup",
            "meta-bad-unknown-key",
            "meta-bad-euid-alpha",
            "meta-bad-euid-huge",
            "meta-bad-denied-relative",
            "meta-bad-tech",
            "meta-bad-arch-long",
            "meta-bad-release-long",
            "meta-bad-denied-long",
            "meta-bad-nul",
            "meta-bad-utf8",
        ] {
            let err = open_evidence_reader(&fx(name)).unwrap_err();
            assert_eq!(err.code, E_META_BAD, "fixture {name}");
        }
    }

    #[test]
    fn asserted_tech_ok() {
        let r = open_evidence_reader(&fx("user-asserted-snp")).expect("fixture opens");
        assert_eq!(r.asserted_guest_tech, "snp");
    }

    #[test]
    fn denied_list_ok() {
        let r = open_evidence_reader(&fx("denied-tracepoint")).expect("fixture opens");
        assert_eq!(r.denied.len(), 1);
        assert_eq!(
            r.denied[0],
            "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
        );
    }

    #[test]
    fn file_state_split() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        assert_eq!(file_state(&r, "/proc/cpuinfo"), EVIDENCE_OK);
        assert_eq!(file_state(&r, "/proc/no-such-memveil"), EVIDENCE_ABSENT);
        let d = open_evidence_reader(&fx("denied-tracepoint")).expect("fixture opens");
        assert_eq!(
            file_state(
                &d,
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
            EVIDENCE_DENIED
        );
    }

    #[test]
    fn eacces_parent_is_denied() {
        if geteuid_live() == 0 {
            return;
        }
        let base = TestDir::create("memveil-m1-perm").expect("mkdtemp");
        let sub = base.path().join("sub");
        std::fs::create_dir(&sub).expect("mkdir sub");
        std::fs::write(sub.join("f"), b"x").expect("write f");
        set_mode(&sub, 0);
        let r = open_evidence_reader("").expect("live reader opens");
        let f = sub.join("f").to_str().unwrap().to_string();
        assert_eq!(file_state(&r, &f), EVIDENCE_DENIED);
        assert_eq!(
            file_state(&r, &format!("{}/no-such-memveil", base.as_str())),
            EVIDENCE_ABSENT
        );
        set_mode(&sub, 0o755);
    }

    #[cfg(test)]
    fn set_mode(path: &std::path::Path, mode: u32) {
        use std::ffi::CString;
        let c = CString::new(path.to_str().unwrap()).unwrap();
        // SAFETY: NUL-terminated live path.
        let rc = unsafe { libc::chmod(c.as_ptr(), mode as libc::mode_t) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn read_absent() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        expect_code(read_evidence(&r, "/proc/no-such-memveil", 1024), E_ABSENT);
    }

    #[test]
    fn read_denied() {
        let r = open_evidence_reader(&fx("denied-tracepoint")).expect("fixture opens");
        expect_code(
            read_evidence(
                &r,
                "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format",
                65536,
            ),
            E_DENIED,
        );
    }

    #[test]
    fn read_too_big() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        expect_code(read_evidence(&r, "/proc/cpuinfo", 10), E_TOO_BIG);
    }

    #[test]
    fn bytes_to_text_lossy() {
        assert_eq!(bytes_to_text(b"ab"), "ab");
        let rep = bytes_to_text(&[0xFF]);
        assert_eq!(rep.len(), 3);
    }

    #[test]
    fn utf8_valid() {
        assert!(is_valid_utf8(b"abc"));
        assert!(is_valid_utf8(b""));
        assert!(is_valid_utf8(&[0x63, 0xC3, 0xA9]));
        assert!(is_valid_utf8(&[0xE6, 0x97, 0xA5]));
        assert!(is_valid_utf8(&[0xF0, 0x9F, 0x98, 0x80]));
    }

    #[test]
    fn utf8_invalid() {
        assert!(!is_valid_utf8(&[0xFF]));
        assert!(!is_valid_utf8(&[0x80]));
        assert!(!is_valid_utf8(&[0xC0, 0xAF]));
        assert!(!is_valid_utf8(&[0xE0, 0x80, 0x80]));
        assert!(!is_valid_utf8(&[0xED, 0xA0, 0x80]));
        assert!(!is_valid_utf8(&[0xF0, 0x80, 0x80, 0x80]));
        assert!(!is_valid_utf8(&[0xF4, 0x90, 0x80, 0x80]));
        assert!(!is_valid_utf8(&[0xF5, 0x80, 0x80, 0x80]));
        assert!(!is_valid_utf8(&[0xE2, 0x82]));
        assert!(!is_valid_utf8(&[0xE2, 0x28, 0xA1]));
    }

    /// One hostile fixture plus an outside secret file.
    fn evil_root() -> TestDir {
        let tmp = TestDir::create("memveil-contain").expect("mkdtemp");
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(
            root.join("meta.txt"),
            "arch=x86_64\nrelease=7.0.0-test\neuid=0\n",
        )
        .expect("write meta");
        std::fs::create_dir(root.join("sys")).expect("mkdir sys");
        std::fs::write(root.join("sys").join("x"), "inside").expect("write x");
        std::fs::write(tmp.path().join("secret"), "OUTSIDE").expect("write secret");
        std::os::unix::fs::symlink(tmp.path().join("secret"), root.join("link"))
            .expect("symlink file");
        std::os::unix::fs::symlink(tmp.path(), root.join("sub")).expect("symlink dir");
        tmp
    }

    fn evil_reader_path(tmp: &TestDir) -> String {
        tmp.path().join("root").to_str().unwrap().to_string()
    }

    #[test]
    fn fixture_symlink_file_refuses() {
        let tmp = evil_root();
        let reader = open_evidence_reader(&evil_reader_path(&tmp)).expect("fixture opens");
        let ok = read_evidence(&reader, "/sys/x", 65536).expect("inside reads");
        assert_eq!(bytes_to_text(&ok), "inside");
        expect_code(read_evidence(&reader, "/link", 65536), E_DENIED);
    }

    #[test]
    fn fixture_symlink_dir_refuses() {
        let tmp = evil_root();
        let reader = open_evidence_reader(&evil_reader_path(&tmp)).expect("fixture opens");
        expect_code(read_evidence(&reader, "/sub/secret", 65536), E_DENIED);
    }

    #[test]
    fn fixture_dotdot_refuses() {
        let tmp = evil_root();
        let reader = open_evidence_reader(&evil_reader_path(&tmp)).expect("fixture opens");
        expect_code(read_evidence(&reader, "/../secret", 65536), E_DENIED);
    }

    #[test]
    fn fixture_absent_stays_absent() {
        let tmp = evil_root();
        let reader = open_evidence_reader(&evil_reader_path(&tmp)).expect("fixture opens");
        expect_code(read_evidence(&reader, "/sys/nope", 65536), E_ABSENT);
    }

    #[test]
    fn fixture_symlink_meta_refuses() {
        let tmp = TestDir::create("memveil-contain").expect("mkdtemp");
        let root = tmp.path().join("root");
        std::fs::create_dir(&root).expect("mkdir root");
        std::fs::write(
            tmp.path().join("real-meta"),
            "arch=x86_64\nrelease=7.0.0-test\neuid=0\n",
        )
        .expect("write meta");
        std::os::unix::fs::symlink(tmp.path().join("real-meta"), root.join("meta.txt"))
            .expect("symlink meta");
        let err = open_evidence_reader(root.to_str().unwrap()).unwrap_err();
        assert_eq!(err.code, E_META_BAD);
    }

    #[test]
    fn fs_type_live() {
        // /tmp exists on every test host: the answer is a
        // known name or an explicit unknown-magic marker.
        let got = fs_type_name("/tmp");
        assert_ne!(got, "");
        assert_ne!(got, "unavailable: statfs failed");
        let known = matches!(
            got.as_str(),
            "tmpfs" | "ext2/ext3/ext4" | "overlay" | "xfs" | "btrfs" | "nfs" | "9p" | "fuse"
        );
        assert!(known || got.starts_with("unknown:0x"), "got {got}");
    }

    #[test]
    fn fs_type_missing() {
        assert_eq!(
            fs_type_name("/nonexistent-dir-xyz-123"),
            "unavailable: statfs failed"
        );
    }

    #[test]
    fn readlink_self_resolves_executable() {
        let exe = readlink_self().expect("exe resolves");
        assert!(!exe.is_empty());
        assert!(std::fs::metadata(&exe).is_ok());
    }

    #[test]
    fn live_reader_reports_host() {
        let r = open_evidence_reader("").expect("live reader opens");
        assert!(!r.arch.is_empty());
        assert!(!r.release.is_empty());
        assert_eq!(r.euid, geteuid_live());
        assert!(r.denied.is_empty());
        assert_eq!(r.asserted_guest_tech, "");
    }

    #[test]
    fn uid_helpers_match_libc() {
        // SAFETY: pure id queries.
        unsafe {
            assert_eq!(geteuid_live(), libc::geteuid() as i64);
            assert_eq!(getuid_live(), libc::getuid() as i64);
        }
    }

    #[test]
    fn evidence_path_maps_root() {
        let live = open_evidence_reader("").expect("live reader opens");
        assert_eq!(evidence_path(&live, "/proc/cpuinfo"), "/proc/cpuinfo");
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        assert_eq!(
            evidence_path(&r, "/proc/cpuinfo"),
            format!("{}/proc/cpuinfo", fx("ordinary-7.0"))
        );
    }

    #[test]
    fn denied_lookup() {
        let live = open_evidence_reader("").expect("live reader opens");
        assert!(!is_denied(&live, "/proc/cpuinfo"));
        let r = open_evidence_reader(&fx("denied-tracepoint")).expect("fixture opens");
        assert!(is_denied(
            &r,
            "/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
        ));
        assert!(!is_denied(&r, "/proc/cpuinfo"));
    }

    #[test]
    fn exists_f_ok_split() {
        let r = open_evidence_reader(&fx("ordinary-7.0")).expect("fixture opens");
        assert!(exists_f_ok(&r, "/proc/cpuinfo"));
        assert!(!exists_f_ok(&r, "/proc/no-such-memveil"));
        // A strict denied ancestor hides the path; a denied path
        // itself still exists, since denied is never absent.
        let mut hidden = r.clone();
        hidden.denied.push("/proc".to_string());
        assert!(!exists_f_ok(&hidden, "/proc/cpuinfo"));
        let mut itself = r.clone();
        itself.denied.push("/proc/cpuinfo".to_string());
        assert!(exists_f_ok(&itself, "/proc/cpuinfo"));
    }

    #[test]
    fn host_file_denied_split() {
        assert!(!host_file_denied("/nonexistent-memveil-host-file-xyz"));
        let tmp = TestDir::create("memveil-hostdeny").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"x").expect("write f");
        let path = f.to_str().unwrap().to_string();
        assert!(!host_file_denied(&path));
        if geteuid_live() != 0 {
            set_mode(&f, 0);
            assert!(host_file_denied(&path));
            set_mode(&f, 0o644);
        }
    }

    #[test]
    fn read_host_file_split() {
        let missing: Result<Vec<u8>, EvidenceError> =
            read_host_file("/nonexistent-memveil-host-file-xyz", "probe", 1024);
        assert_eq!(missing.unwrap_err().code, E_IO);
        let tmp = TestDir::create("memveil-hostread").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"0123456789").expect("write f");
        let path = f.to_str().unwrap().to_string();
        let data = read_host_file(&path, "probe", 1024).expect("host read works");
        assert_eq!(data, b"0123456789");
        let big = read_host_file(&path, "probe", 4).unwrap_err();
        assert_eq!(big.code, E_TOO_BIG);
    }

    struct CollectSink {
        lines: Vec<Vec<u8>>,
    }

    impl LineSink for CollectSink {
        fn feed(&mut self, line: Vec<u8>) -> String {
            self.lines.push(line);
            String::new()
        }
    }

    struct FailOnSink {
        needle: Vec<u8>,
        seen: Vec<Vec<u8>>,
    }

    impl LineSink for FailOnSink {
        fn feed(&mut self, line: Vec<u8>) -> String {
            self.seen.push(line.clone());
            if line == self.needle {
                return "bad line".to_string();
            }
            String::new()
        }
    }

    #[test]
    fn stream_splits_skips_and_delivers_tail() {
        let tmp = TestDir::create("memveil-stream").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"one\n\ntwo\ntail-no-newline").expect("write f");
        let path = f.to_str().unwrap().to_string();
        let mut sink = CollectSink { lines: Vec::new() };
        stream_host_lines(&path, "probe", 65536, &mut sink).expect("streams");
        assert_eq!(
            sink.lines,
            vec![
                b"one".to_vec(),
                b"two".to_vec(),
                b"tail-no-newline".to_vec()
            ]
        );
    }

    #[test]
    fn stream_stops_after_first_failure() {
        let tmp = TestDir::create("memveil-stream").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"one\nbad\ntwo\n").expect("write f");
        let path = f.to_str().unwrap().to_string();
        let mut sink = FailOnSink {
            needle: b"bad".to_vec(),
            seen: Vec::new(),
        };
        stream_host_lines(&path, "probe", 65536, &mut sink).expect("stops clean");
        assert_eq!(sink.seen, vec![b"one".to_vec(), b"bad".to_vec()]);
    }

    #[test]
    fn stream_tail_failure_ignored() {
        // An unterminated trailing span is still delivered, but its
        // feed result is ignored: the stream already reached EOF.
        let tmp = TestDir::create("memveil-stream").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"one\nbad").expect("write f");
        let path = f.to_str().unwrap().to_string();
        let mut sink = FailOnSink {
            needle: b"bad".to_vec(),
            seen: Vec::new(),
        };
        stream_host_lines(&path, "probe", 65536, &mut sink).expect("tail ok");
        assert_eq!(sink.seen, vec![b"one".to_vec(), b"bad".to_vec()]);
    }

    #[test]
    fn stream_cap_and_open_errors() {
        let mut sink = CollectSink { lines: Vec::new() };
        let err = stream_host_lines("/nonexistent-memveil-stream-xyz", "probe", 65536, &mut sink)
            .unwrap_err();
        assert_eq!(err.code, E_IO);
        let tmp = TestDir::create("memveil-stream").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"0123456789").expect("write f");
        let err = stream_host_lines(f.to_str().unwrap(), "probe", 4, &mut sink).unwrap_err();
        assert_eq!(err.code, E_TOO_BIG);
    }

    #[test]
    fn error_renders_like_mojo() {
        let err = EvidenceError {
            code: E_ABSENT,
            message: "/x: absent".to_string(),
        };
        assert_eq!(err.to_string(), "EvidenceError(code=3, message=/x: absent)");
    }

    #[test]
    fn gate_fixture_probe_smoke() {
        // The prechecks/tracefs suites share these trees; prove the
        // helper resolves one here so path rot fails fast.
        let r = open_evidence_reader(&gate_fixture("base")).expect("gate base opens");
        assert!(!r.release.is_empty());
    }
}
