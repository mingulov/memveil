// SPDX-License-Identifier: GPL-3.0-or-later
//! Descriptor-based recovery reads with directory locking and identity checks.

/// One capture-file failure, carrying the Mojo-side message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureError {
    /// Machine-stable reason.
    pub message: String,
}

impl CaptureError {
    fn new(message: String) -> Self {
        Self { message }
    }
}

impl std::fmt::Display for CaptureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CaptureError {}

/// NUL-terminate a capture path, refusing interior NULs.
pub fn cstr(text: &str) -> Result<Vec<u8>, CaptureError> {
    let mut out = Vec::with_capacity(text.len() + 1);
    for &b in text.as_bytes() {
        if b == 0 {
            return Err(CaptureError::new("NUL in capture path".to_string()));
        }
        out.push(b);
    }
    out.push(0);
    Ok(out)
}

/// Close when open; best effort, no error.
pub fn close_fd(fd: i32) {
    if fd >= 0 {
        // SAFETY: best-effort close of an owned-or-negative fd.
        unsafe {
            libc::close(fd);
        }
    }
}

/// `[dev, ino, nlink, mode, uid, size, blocks]` for an open fd.
///
/// The x86-64 stat layout behind these fields is pinned by the
/// `file_stat_layout` test against the standard metadata oracle.
pub fn file_stat(fd: i32) -> Result<[u64; 7], CaptureError> {
    // SAFETY: zeroed stat outlives the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::fstat(fd, &mut st) };
    if rc != 0 {
        return Err(CaptureError::new("capture stat failed".to_string()));
    }
    Ok([
        st.st_dev as u64,
        st.st_ino as u64,
        st.st_nlink as u64,
        u64::from(st.st_mode),
        u64::from(st.st_uid),
        st.st_size as u64,
        st.st_blocks as u64,
    ])
}

/// Open a capture directory component by component, never a symlink.
pub fn open_directory(path: &str) -> Result<i32, CaptureError> {
    let root = cstr(if path.starts_with('/') { "/" } else { "." })?;
    // SAFETY: NUL-terminated root with AT_FDCWD.
    let mut fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            root.as_ptr().cast::<libc::c_char>(),
            libc::O_DIRECTORY | libc::O_CLOEXEC,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(CaptureError::new("cannot open capture parent".to_string()));
    }
    for part in path.split('/') {
        if part.is_empty() || part == "." {
            continue;
        }
        let name = match cstr(part) {
            Ok(name) => name,
            Err(e) => {
                close_fd(fd);
                return Err(e);
            }
        };
        // SAFETY: NUL-terminated component on a live dir fd.
        let next_fd = unsafe {
            libc::openat(
                fd,
                name.as_ptr().cast::<libc::c_char>(),
                libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        close_fd(fd);
        if next_fd < 0 {
            return Err(CaptureError::new(
                "capture directory is inaccessible or a symlink".to_string(),
            ));
        }
        fd = next_fd;
    }
    Ok(fd)
}

/// Pinned capture descriptors with open-time identity.
pub struct RecoveryFiles {
    directory: i32,
    events: i32,
    checkpoint: i32,
    path: String,
    directory_ids: [u64; 7],
    events_ids: [u64; 7],
    checkpoint_ids: [u64; 7],
}

impl RecoveryFiles {
    /// Unopened file set; call [`RecoveryFiles::open`] next.
    pub fn new() -> Self {
        Self {
            directory: -1,
            events: -1,
            checkpoint: -1,
            path: String::new(),
            directory_ids: [0; 7],
            events_ids: [0; 7],
            checkpoint_ids: [0; 7],
        }
    }

    /// Open one regular member that the reader alone owns.
    pub fn open_regular(&self, name: &str) -> Result<i32, CaptureError> {
        let key = cstr(name)?;
        // SAFETY: NUL-terminated name on the live directory fd.
        let fd = unsafe {
            libc::openat(
                self.directory,
                key.as_ptr().cast::<libc::c_char>(),
                libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(CaptureError::new(format!(
                "{name}: cannot open regular capture file"
            )));
        }
        match file_stat(fd) {
            Ok(ids) => {
                if ids[3] & 0o170000 != 0o100000 || ids[2] != 1 {
                    close_fd(fd);
                    return Err(CaptureError::new(format!(
                        "{name}: not a singly linked regular file"
                    )));
                }
                // SAFETY: pure id query.
                let euid = unsafe { libc::geteuid() as u64 };
                if ids[4] != euid {
                    close_fd(fd);
                    return Err(CaptureError::new(format!("{name}: not owned by reader")));
                }
            }
            Err(e) => {
                close_fd(fd);
                return Err(e);
            }
        }
        Ok(fd)
    }

    /// Pin the capture directory and both members.
    pub fn open(&mut self, path: &str) -> Result<(), CaptureError> {
        self.path = path.to_string();
        self.directory = open_directory(path)?;
        // SAFETY: live directory fd.
        let locked = unsafe { libc::flock(self.directory, libc::LOCK_SH | libc::LOCK_NB) };
        if locked != 0 {
            return Err(CaptureError::new(
                "active writer or unavailable capture lock".to_string(),
            ));
        }
        self.directory_ids = file_stat(self.directory)?;
        // SAFETY: pure id query.
        let euid = unsafe { libc::geteuid() as u64 };
        if self.directory_ids[4] != euid {
            return Err(CaptureError::new(
                "capture directory not owned by reader".to_string(),
            ));
        }
        self.checkpoint = self.open_regular("checkpoint.json")?;
        self.events = self.open_regular("events.ndjson")?;
        self.checkpoint_ids = file_stat(self.checkpoint)?;
        self.events_ids = file_stat(self.events)?;
        self.verify()
    }

    /// Re-prove the pinned identity; refuse swaps and finalization.
    pub fn verify(&self) -> Result<(), CaptureError> {
        let current = open_directory(&self.path)?;
        let ids = match file_stat(current) {
            Ok(ids) => ids,
            Err(e) => {
                close_fd(current);
                return Err(e);
            }
        };
        close_fd(current);
        if ids[0] != self.directory_ids[0] || ids[1] != self.directory_ids[1] {
            return Err(CaptureError::new(
                "capture directory replaced during recovery".to_string(),
            ));
        }
        for name in ["checkpoint.json", "events.ndjson"] {
            let fd = self.open_regular(name)?;
            let now = match file_stat(fd) {
                Ok(now) => now,
                Err(e) => {
                    close_fd(fd);
                    return Err(e);
                }
            };
            close_fd(fd);
            let want = if name == "checkpoint.json" {
                self.checkpoint_ids
            } else {
                self.events_ids
            };
            if now[0] != want[0] || now[1] != want[1] || now[5] != want[5] {
                return Err(CaptureError::new(format!(
                    "{name}: replaced or resized during recovery"
                )));
            }
        }
        let final_name = cstr("session.json")?;
        // SAFETY: NUL-terminated name on the live directory fd.
        let present = unsafe {
            libc::openat(
                self.directory,
                final_name.as_ptr().cast::<libc::c_char>(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0 as libc::c_uint,
            )
        };
        if present >= 0 {
            close_fd(present);
            return Err(CaptureError::new(
                "final session appeared during recovery; retry finalized capture".to_string(),
            ));
        }
        if std::io::Error::last_os_error().raw_os_error().unwrap_or(0) != libc::ENOENT {
            return Err(CaptureError::new(
                "cannot establish absence of final session".to_string(),
            ));
        }
        Ok(())
    }

    /// Read the pinned checkpoint bytes, capped at `cap`.
    pub fn read_checkpoint(&self, cap: usize) -> Result<Vec<u8>, CaptureError> {
        if self.checkpoint_ids[5] > cap as u64 {
            return Err(CaptureError::new("checkpoint.json too large".to_string()));
        }
        let mut raw = vec![0u8; self.checkpoint_ids[5] as usize];
        let mut done = 0;
        while done < raw.len() {
            // SAFETY: live checkpoint fd with the in-range slice tail;
            // pread at the absolute offset never moves the cursor.
            let n = unsafe {
                libc::pread(
                    self.checkpoint,
                    raw.as_mut_ptr().cast::<libc::c_void>().add(done),
                    raw.len() - done,
                    done as libc::off_t,
                )
            };
            if n <= 0 {
                return Err(CaptureError::new(
                    "checkpoint.json: cannot read".to_string(),
                ));
            }
            done += n as usize;
        }
        Ok(raw)
    }

    /// Open events fd for the recovery reader's positional scan.
    ///
    /// The capture reader issues `pread` calls against this fd;
    /// ownership stays here and the fd closes on drop.
    pub fn events_fd(&self) -> i32 {
        self.events
    }

    /// Open-time `events.ndjson` byte size for the recovery reader.
    ///
    /// The capture reader bounds its scan with this pinned size
    /// (`events_ids[5]`), taken before any concurrent growth.
    pub fn events_len(&self) -> u64 {
        self.events_ids[5]
    }
}

impl Default for RecoveryFiles {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RecoveryFiles {
    fn drop(&mut self) {
        close_fd(self.events);
        close_fd(self.checkpoint);
        close_fd(self.directory);
    }
}

#[cfg(test)]
mod tests {
    use super::{RecoveryFiles, cstr, file_stat, open_directory};
    use crate::platform::reader::geteuid_live;
    use crate::platform::test_support::TestDir;
    use std::os::unix::fs::MetadataExt;

    /// One minimal capture directory: checkpoint + events.
    fn capture_dir() -> TestDir {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        std::fs::write(tmp.path().join("checkpoint.json"), b"{}").expect("write checkpoint");
        std::fs::write(tmp.path().join("events.ndjson"), b"{\"a\":1}\n").expect("write events");
        tmp
    }

    fn open_capture(tmp: &TestDir) -> RecoveryFiles {
        let mut files = RecoveryFiles::new();
        files.open(tmp.as_str()).expect("capture opens");
        files
    }

    #[test]
    fn roundtrip_open_verify_read() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        files.verify().expect("verify holds");
        let raw = files.read_checkpoint(1024).expect("checkpoint reads");
        assert_eq!(raw, b"{}");
    }

    #[test]
    fn cstr_rejects_nul() {
        assert_eq!(cstr("a\0b").unwrap_err().message, "NUL in capture path");
        assert!(cstr("/tmp/x").is_ok());
    }

    #[test]
    fn missing_directory_refuses() {
        let err = open_directory("/nonexistent-memveil-cap-xyz").unwrap_err();
        assert_eq!(
            err.message,
            "capture directory is inaccessible or a symlink"
        );
        let rel = open_directory("nonexistent-memveil-cap-xyz").unwrap_err();
        assert_eq!(
            rel.message,
            "capture directory is inaccessible or a symlink"
        );
    }

    #[test]
    fn file_path_refuses_as_directory() {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"x").expect("write f");
        let err = open_directory(f.to_str().unwrap()).unwrap_err();
        assert_eq!(
            err.message,
            "capture directory is inaccessible or a symlink"
        );
    }

    #[test]
    fn symlinked_directory_refuses() {
        let tmp = capture_dir();
        let link = tmp.path().join("linkdir");
        std::os::unix::fs::symlink(tmp.path(), &link).expect("symlink dir");
        // Every component opens with O_NOFOLLOW, so the walk
        // refuses a capture reached through a symlink.
        let err = open_directory(link.to_str().unwrap()).unwrap_err();
        assert_eq!(
            err.message,
            "capture directory is inaccessible or a symlink"
        );
    }

    #[test]
    fn active_writer_refuses() {
        use std::ffi::CString;
        let tmp = capture_dir();
        let c = CString::new(tmp.as_str()).unwrap();
        // SAFETY: NUL-terminated live path; the fd closes below.
        let fd = unsafe {
            libc::open(
                c.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY,
                0 as libc::c_uint,
            )
        };
        assert!(fd >= 0);
        // SAFETY: live dir fd.
        let locked = unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(locked, 0);
        let mut files = RecoveryFiles::new();
        let err = files.open(tmp.as_str()).unwrap_err();
        assert_eq!(err.message, "active writer or unavailable capture lock");
        // SAFETY: closing releases the lock.
        unsafe {
            libc::close(fd);
        }
    }

    #[test]
    fn symlinked_events_refuses() {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        std::fs::write(tmp.path().join("checkpoint.json"), b"{}").expect("write checkpoint");
        std::fs::write(tmp.path().join("real-events"), b"{}\n").expect("write real");
        std::os::unix::fs::symlink(
            tmp.path().join("real-events"),
            tmp.path().join("events.ndjson"),
        )
        .expect("symlink events");
        let mut files = RecoveryFiles::new();
        let err = files.open(tmp.as_str()).unwrap_err();
        assert_eq!(
            err.message,
            "events.ndjson: cannot open regular capture file"
        );
    }

    #[test]
    fn special_events_refuses() {
        for kind in ["fifo", "directory"] {
            let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
            std::fs::write(tmp.path().join("checkpoint.json"), b"{}").expect("write checkpoint");
            let ev = tmp.path().join("events.ndjson");
            if kind == "fifo" {
                use std::ffi::CString;
                let c = CString::new(ev.to_str().unwrap()).unwrap();
                // SAFETY: NUL-terminated live path.
                let rc = unsafe { libc::mkfifo(c.as_ptr(), 0o644) };
                assert_eq!(rc, 0);
            } else {
                std::fs::create_dir(&ev).expect("mkdir events");
            }
            let mut files = RecoveryFiles::new();
            let err = files.open(tmp.as_str()).unwrap_err();
            assert_eq!(
                err.message, "events.ndjson: not a singly linked regular file",
                "kind {kind}"
            );
        }
    }

    #[test]
    fn hardlinked_events_refuses() {
        let tmp = capture_dir();
        std::fs::hard_link(
            tmp.path().join("events.ndjson"),
            tmp.path().join("events-alias"),
        )
        .expect("hard link");
        let mut files = RecoveryFiles::new();
        let err = files.open(tmp.as_str()).unwrap_err();
        assert_eq!(
            err.message,
            "events.ndjson: not a singly linked regular file"
        );
    }

    #[test]
    fn missing_members_refuse() {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        std::fs::write(tmp.path().join("events.ndjson"), b"{}\n").expect("write events");
        let mut files = RecoveryFiles::new();
        assert_eq!(
            files.open(tmp.as_str()).unwrap_err().message,
            "checkpoint.json: cannot open regular capture file"
        );
        std::fs::write(tmp.path().join("checkpoint.json"), b"{}").expect("write checkpoint");
        std::fs::remove_file(tmp.path().join("events.ndjson")).expect("remove events");
        let mut files = RecoveryFiles::new();
        assert_eq!(
            files.open(tmp.as_str()).unwrap_err().message,
            "events.ndjson: cannot open regular capture file"
        );
    }

    #[test]
    fn swapped_events_refuses_verify() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        std::fs::write(tmp.path().join("events.ndjson"), b"swapped-{}\n").expect("swap events");
        assert_eq!(
            files.verify().unwrap_err().message,
            "events.ndjson: replaced or resized during recovery"
        );
    }

    #[test]
    fn resized_checkpoint_refuses_verify() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        std::fs::write(tmp.path().join("checkpoint.json"), b"{\"bigger\":true}")
            .expect("resize checkpoint");
        assert_eq!(
            files.verify().unwrap_err().message,
            "checkpoint.json: replaced or resized during recovery"
        );
    }

    #[test]
    fn replaced_directory_refuses_verify() {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        let cap = tmp.path().join("cap");
        std::fs::create_dir(&cap).expect("mkdir cap");
        std::fs::write(cap.join("checkpoint.json"), b"{}").expect("write checkpoint");
        std::fs::write(cap.join("events.ndjson"), b"{}\n").expect("write events");
        let path = cap.to_str().unwrap().to_string();
        let mut files = RecoveryFiles::new();
        files.open(&path).expect("capture opens");
        let moved = tmp.path().join("cap-moved");
        std::fs::rename(&cap, &moved).expect("move dir away");
        std::fs::create_dir(&cap).expect("mkdir replacement");
        assert_eq!(
            files.verify().unwrap_err().message,
            "capture directory replaced during recovery"
        );
    }

    #[test]
    fn final_session_refuses_verify() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        std::fs::write(tmp.path().join("session.json"), b"{}").expect("write session");
        assert_eq!(
            files.verify().unwrap_err().message,
            "final session appeared during recovery; retry finalized capture"
        );
    }

    #[test]
    fn finalized_capture_refuses_open() {
        let tmp = capture_dir();
        std::fs::write(tmp.path().join("session.json"), b"{}").expect("write session");
        let mut files = RecoveryFiles::new();
        assert_eq!(
            files.open(tmp.as_str()).unwrap_err().message,
            "final session appeared during recovery; retry finalized capture"
        );
    }

    #[test]
    fn checkpoint_cap_refuses() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        assert_eq!(
            files.read_checkpoint(1).unwrap_err().message,
            "checkpoint.json too large"
        );
    }

    #[test]
    fn truncated_checkpoint_fails_read() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        std::fs::write(tmp.path().join("checkpoint.json"), b"").expect("truncate checkpoint");
        assert_eq!(
            files.read_checkpoint(1024).unwrap_err().message,
            "checkpoint.json: cannot read"
        );
    }

    #[test]
    fn empty_checkpoint_reads_empty() {
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        std::fs::write(tmp.path().join("checkpoint.json"), b"").expect("write checkpoint");
        std::fs::write(tmp.path().join("events.ndjson"), b"{}\n").expect("write events");
        let files = open_capture(&tmp);
        assert_eq!(files.read_checkpoint(1024).expect("reads"), b"");
    }

    #[test]
    fn file_stat_layout() {
        use std::ffi::CString;
        let tmp = TestDir::create("memveil-cap").expect("mkdtemp");
        let f = tmp.path().join("f");
        std::fs::write(&f, b"0123456789").expect("write f");
        let c = CString::new(f.to_str().unwrap()).unwrap();
        // SAFETY: NUL-terminated live path; the fd closes below.
        let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY) };
        assert!(fd >= 0);
        let ids = file_stat(fd).expect("stat works");
        // SAFETY: closing the owned fd.
        unsafe {
            libc::close(fd);
        }
        let meta = std::fs::metadata(&f).expect("metadata works");
        // [dev, ino, nlink, mode, uid, size, blocks].
        assert_eq!(ids[0], meta.dev());
        assert_eq!(ids[1], meta.ino());
        assert_eq!(ids[2], 1);
        assert_eq!(ids[3] & 0o170000, 0o100000);
        assert_eq!(ids[4] as i64, geteuid_live());
        assert_eq!(ids[5], 10);
        assert!(ids[6] * 512 >= ids[5]);
        assert_eq!(file_stat(-1).unwrap_err().message, "capture stat failed");
    }

    #[test]
    fn events_accessors_match_pinned_identity() {
        let tmp = capture_dir();
        let files = open_capture(&tmp);
        assert!(files.events_fd() >= 0);
        let ids = file_stat(files.events_fd()).expect("events fd stats");
        assert_eq!(files.events_len(), ids[5]);
        assert_eq!(files.events_len(), 8);
    }
}
