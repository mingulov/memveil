// SPDX-License-Identifier: GPL-3.0-or-later
//! Checked standard-output writer: short writes fail loudly.
//!
//! The language print path and file writes swallow output errors
//! (`/dev/full` exits 0), so every product stdout write goes
//! through here instead: raw `write(2)` on fd 1 with an EINTR
//! retry loop and an exact byte count. A short write or an
//! error returns [`StdoutError`] carrying the errno, and the caller
//! maps it to exit 1 with a stderr reason. Nothing on stdout is
//! buffered here, and no other product code writes fd 1, so
//! bytes land in call order.

/// One standard-output failure: errno attached, never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StdoutError {
    /// Failure detail, including the errno number.
    pub message: String,
}

impl std::fmt::Display for StdoutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StdoutError {}

/// Write every byte of `text` to fd 1 or return [`StdoutError`].
pub fn write_stdout(text: &str) -> Result<(), StdoutError> {
    let raw = text.as_bytes();
    let total = raw.len();
    let mut off = 0;
    while off < total {
        // SAFETY: fd 1 with a live caller buffer; len counts down from
        // total so the pointer range stays inside `raw`.
        let n =
            unsafe { libc::write(1, raw.as_ptr().cast::<libc::c_void>().add(off), total - off) };
        if n < 0 {
            // SAFETY: errno read on the calling thread right after write.
            let no = unsafe { *libc::__errno_location() };
            if no == libc::EINTR {
                continue;
            }
            return Err(StdoutError {
                message: format!("stdout write failed: errno {no}"),
            });
        }
        if n == 0 {
            return Err(StdoutError {
                message: "stdout write returned 0".to_string(),
            });
        }
        off += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{StdoutError, write_stdout};

    #[test]
    fn success_writes_silently() {
        // Success carries no marker: it returns without failing.
        // (The byte-exact goldens in the reports/top lanes cover
        // what lands on fd 1.)
        write_stdout("").expect("empty write must succeed");
    }

    #[test]
    fn error_carries_message() {
        let err = StdoutError {
            message: "stdout write failed: errno 28".to_string(),
        };
        assert_eq!(err.message, "stdout write failed: errno 28");
        assert_eq!(err.to_string(), "stdout write failed: errno 28");
    }

    #[test]
    fn write_to_full_device_fails() {
        // Redirecting fd 1 is process-global, so the redirect
        // runs in a re-executed child: the parent only checks
        // the exit status, and parallel harness output in the
        // parent never observes the window.
        if std::env::var("MEMVEIL_T7A_STDOUT_FULL_CHILD").is_ok() {
            use std::ffi::CString;
            // SAFETY: dup/dup2/close/openat on fds owned by this
            // child; stdout is restored before exiting.
            let failed = unsafe {
                let saved = libc::dup(1);
                assert!(saved >= 0);
                let name = CString::new("/dev/full").expect("static path has no NUL");
                let full = libc::openat(libc::AT_FDCWD, name.as_ptr(), libc::O_WRONLY);
                assert!(full >= 0);
                let moved = libc::dup2(full, 1);
                assert!(moved >= 0);
                libc::close(full);
                let failed = write_stdout("x").is_err();
                libc::dup2(saved, 1);
                libc::close(saved);
                failed
            };
            std::process::exit(i32::from(!failed));
        }
        let exe = std::env::current_exe().expect("test binary path resolves");
        let status = std::process::Command::new(exe)
            .arg("--exact")
            .arg("platform::stdout::tests::write_to_full_device_fails")
            .arg("--nocapture")
            .env("MEMVEIL_T7A_STDOUT_FULL_CHILD", "1")
            .status()
            .expect("child re-exec runs");
        assert!(
            status.success(),
            "write to /dev/full must fail in the child"
        );
    }
}
