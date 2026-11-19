// SPDX-License-Identifier: GPL-3.0-or-later
//! Live signal source: signalfd(2) with inherent methods.
//!
//! Setup blocks SIGHUP/SIGINT/SIGTERM in the calling thread and
//! opens a nonblocking signalfd; `check` reports none,
//! pending, or error. Masks are restored when signalfd
//! creation fails and at teardown. Read diagnostics carry
//! the errno number only (sanitized form).
//!
//! Trait seam: this module ships inherent methods only, with
//! signatures the collector's `SignalSource` trait adopts
//! (`setup(&mut self) -> OpOut`, `check(&mut self) -> SignalOut`).
//! The trait definition and its `impl` for [`LiveSignalSource`]
//! land with the collector task; nothing here changes then.

use super::outcome::OpOut;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

/// One signal check: none, pending, or error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalOut {
    /// `none`, `pending`, or `error`.
    pub state: String,
    /// Failure detail; empty unless `error`.
    pub message: String,
}

/// Read disposition: no signal waiting.
pub const READ_NONE: i32 = 0;
/// Read disposition: a stop signal is pending.
pub const READ_PENDING: i32 = 1;
/// Read disposition: retry the read (EINTR).
pub const READ_RETRY: i32 = 2;
/// Read disposition: the source failed.
pub const READ_ERROR: i32 = 3;

const SIGSET_BYTES: usize = 128;
const SIGINFO_BYTES: usize = 128;
const SIGBLK_SENTINEL: &str = "MEMVEIL_SIGBLK";

const _: () = assert!(size_of::<libc::sigset_t>() == SIGSET_BYTES);

fn sig_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Pure read disposition: EAGAIN rests, EINTR retries.
pub fn classify_signal_read(n: i64, errno_no: i32) -> i32 {
    if n > 0 {
        return READ_PENDING;
    }
    if n == 0 {
        return READ_ERROR;
    }
    if errno_no == libc::EAGAIN {
        return READ_NONE;
    }
    if errno_no == libc::EINTR {
        return READ_RETRY;
    }
    READ_ERROR
}

/// 128-byte sigset with SIGHUP (bit 0), SIGINT (bit 1), SIGTERM (bit 14).
pub fn blocked_mask() -> [u8; SIGSET_BYTES] {
    let mut mask = [0u8; SIGSET_BYTES];
    mask[0] = 0x03;
    mask[1] = 0x40;
    mask
}

fn cstr_bytes(text: &str) -> Vec<u8> {
    let mut out = text.as_bytes().to_vec();
    out.push(0);
    out
}

/// One NUL-terminated argv body from raw bytes, never decoded.
fn cstr_bytes_os(arg: &OsStr) -> Vec<u8> {
    let mut out = arg.as_bytes().to_vec();
    out.push(0);
    out
}

/// Assemble the re-exec argv storage: the resolved exe path first,
/// then one NUL-terminated body per forwarded word (`args[0]` is
/// the caller's argv[0] placeholder and is skipped, exactly as the
/// Mojo guard skips its own argv[0]). Words cross byte-exact,
/// never decoded: the Mojo `argv()` preserves raw bytes, and a
/// lossy-decoded word could expand past `MAX_ARG_STRLEN` and trip
/// `E2BIG` before the verb ever runs (44,000 `0xff` bytes would
/// become 132,000). Interior NULs pass through here and truncate
/// at exec, exactly as the language-side builder behaves.
fn argv_storage(exe: &[u8], args: &[OsString]) -> Vec<Vec<u8>> {
    let mut storage: Vec<Vec<u8>> = Vec::new();
    let mut exe_path = exe.to_vec();
    exe_path.push(0);
    storage.push(exe_path);
    for arg in args.iter().skip(1) {
        storage.push(cstr_bytes_os(arg));
    }
    storage
}

/// True when MEMVEIL_SIGBLK=1 is set (exact lookup).
///
/// Uses the environment, not a capped /proc/self/environ scan: a
/// read-cap failure would report a set sentinel as absent
/// and loop the re-exec forever on large environments.
pub fn has_sigblk_sentinel() -> bool {
    std::env::var(SIGBLK_SENTINEL).as_deref() == Ok("1")
}

/// Ignored dispositions survive exec and apply to every runtime thread.
pub fn ignore_sigpipe() -> bool {
    // SAFETY: SIG_IGN is a valid disposition; SIG_ERR means failure.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) != libc::SIG_ERR }
}

/// Re-exec once so runtime threads inherit blocked signals.
///
/// Every spawn-before-main runtime thread starts with the
/// parent's (unblocked) mask; a process-directed
/// SIGHUP/SIGINT/SIGTERM would land in a worker and never
/// reach signalfd. Blocking here and re-executing makes the
/// runtime init inherit the block, so NO thread is eligible
/// and every stop signal stays pending for signalfd. Masks
/// survive exec, so the child skips the re-exec via the
/// MEMVEIL_SIGBLK=1 sentinel. The sentinel is verified,
/// not trusted: a pre-set variable without the mask
/// refuses instead of running unprotected (re-execing
/// would loop, since the child would inherit the same
/// unblocked mask plus the same sentinel).
///
/// Returns "" when the caller may proceed (already
/// inherited), else a refusal note (re-exec failed or
/// impossible). A successful re-exec never returns.
///
/// `args[0]` is a placeholder for the resolved exe path;
/// `args[1..]` are the raw argv words the child receives.
/// Raw bytes are required here, not decoded text: the
/// re-exec must forward exactly what the parent received.
pub fn ensure_inherited_signal_block(args: &[OsString]) -> String {
    if !ignore_sigpipe() {
        return "cannot ignore SIGPIPE before re-exec".to_string();
    }
    if has_sigblk_sentinel() {
        let probe_mask = blocked_mask();
        let mut old = [0u8; SIGSET_BYTES];
        // SAFETY: live 128-byte mask buffers.
        let probed = unsafe {
            libc::sigprocmask(
                libc::SIG_BLOCK,
                probe_mask.as_ptr().cast::<libc::sigset_t>(),
                old.as_mut_ptr().cast::<libc::sigset_t>(),
            )
        };
        if probed != 0 {
            return "cannot verify inherited signal mask".to_string();
        }
        if old[0] & 0x03 != 0x03 || old[1] & 0x40 != 0x40 {
            return "signal mask not inherited (MEMVEIL_SIGBLK set,\
                 \u{20}SIGHUP/SIGINT/SIGTERM unblocked); refusing"
                .to_string();
        }
        return String::new();
    }
    let mask = blocked_mask();
    let mut old = [0u8; SIGSET_BYTES];
    // SAFETY: live 128-byte mask buffers.
    let blocked = unsafe {
        libc::sigprocmask(
            libc::SIG_BLOCK,
            mask.as_ptr().cast::<libc::sigset_t>(),
            old.as_mut_ptr().cast::<libc::sigset_t>(),
        )
    };
    if blocked != 0 {
        return "cannot block signals for re-exec".to_string();
    }
    let sentinel = cstr_bytes(SIGBLK_SENTINEL);
    let one = cstr_bytes("1");
    // SAFETY: NUL-terminated name and value.
    let marked = unsafe {
        libc::setenv(
            sentinel.as_ptr().cast::<libc::c_char>(),
            one.as_ptr().cast::<libc::c_char>(),
            1,
        )
    };
    if marked != 0 {
        return "cannot mark signal re-exec".to_string();
    }
    let exe_link = cstr_bytes("/proc/self/exe");
    let mut exe_buf = [0u8; 4096];
    // SAFETY: NUL-terminated link with a live 4 KiB buffer.
    let n = unsafe {
        libc::readlink(
            exe_link.as_ptr().cast::<libc::c_char>(),
            exe_buf.as_mut_ptr().cast::<libc::c_char>(),
            4095,
        )
    };
    if n <= 0 {
        return "cannot resolve self path for re-exec".to_string();
    }
    // argv[0] is the resolved path; readlink wrote n
    // bytes and never NUL-terminates, so terminate here.
    let storage = argv_storage(&exe_buf[..n as usize], args);
    let mut argv: Vec<*const libc::c_char> = storage
        .iter()
        .map(|a| a.as_ptr().cast::<libc::c_char>())
        .collect();
    argv.push(std::ptr::null());
    // SAFETY: NUL-terminated path with a NULL-terminated argv;
    // returns only on failure.
    unsafe {
        libc::execv(storage[0].as_ptr().cast::<libc::c_char>(), argv.as_ptr());
    }
    format!("signal re-exec failed: errno {}", sig_errno())
}

/// signalfd SIGHUP/SIGINT/SIGTERM source for one thread.
///
/// Single-threaded use only: sigprocmask covers the
/// calling thread, and record spawns no threads.
/// `test_fail_setup_at` ("mask"/"signalfd") is a
/// test-only fault point for the two setup failures;
/// production leaves it "".
pub struct LiveSignalSource {
    fd: i32,
    old_mask: [u8; SIGSET_BYTES],
    armed: bool,
    /// Test-only setup fault point; production leaves it "".
    pub test_fail_setup_at: String,
    info: [u8; SIGINFO_BYTES],
}

impl LiveSignalSource {
    /// An unarmed source; call [`LiveSignalSource::setup`] next.
    pub fn new() -> Self {
        Self {
            fd: -1,
            old_mask: [0u8; SIGSET_BYTES],
            armed: false,
            test_fail_setup_at: String::new(),
            // One siginfo buffer reused by every check.
            info: [0u8; SIGINFO_BYTES],
        }
    }

    /// Block stop signals and open the signalfd.
    pub fn setup(&mut self) -> OpOut {
        if self.test_fail_setup_at == "mask" {
            return OpOut {
                ok: false,
                message: "test mask failure".to_string(),
            };
        }
        let mask = blocked_mask();
        let mut old = [0u8; SIGSET_BYTES];
        let mut scratch = [0u8; SIGSET_BYTES];
        // SAFETY: live 128-byte mask buffers.
        let blocked = unsafe {
            libc::sigprocmask(
                libc::SIG_BLOCK,
                mask.as_ptr().cast::<libc::sigset_t>(),
                old.as_mut_ptr().cast::<libc::sigset_t>(),
            )
        };
        if blocked != 0 {
            return OpOut {
                ok: false,
                message: format!("mask install failed: errno {}", sig_errno()),
            };
        }
        if self.test_fail_setup_at == "signalfd" {
            // SAFETY: as above; restoring the pre-setup mask.
            unsafe {
                libc::sigprocmask(
                    libc::SIG_SETMASK,
                    old.as_ptr().cast::<libc::sigset_t>(),
                    scratch.as_mut_ptr().cast::<libc::sigset_t>(),
                );
            }
            return OpOut {
                ok: false,
                message: "test signalfd failure".to_string(),
            };
        }
        // SAFETY: live mask; flags are CLOEXEC|NONBLOCK.
        let fd = unsafe {
            libc::signalfd(
                -1,
                mask.as_ptr().cast::<libc::sigset_t>(),
                libc::SFD_CLOEXEC | libc::SFD_NONBLOCK,
            )
        };
        if fd < 0 {
            let no = sig_errno();
            // SAFETY: as above; restoring the pre-setup mask.
            unsafe {
                libc::sigprocmask(
                    libc::SIG_SETMASK,
                    old.as_ptr().cast::<libc::sigset_t>(),
                    scratch.as_mut_ptr().cast::<libc::sigset_t>(),
                );
            }
            return OpOut {
                ok: false,
                message: format!("signalfd failed: errno {no}"),
            };
        }
        self.fd = fd;
        self.old_mask = old;
        self.armed = true;
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    /// Report none, pending, or error.
    pub fn check(&mut self) -> SignalOut {
        loop {
            // SAFETY: armed fd with the live siginfo buffer.
            let n = unsafe {
                libc::read(
                    self.fd,
                    self.info.as_mut_ptr().cast::<libc::c_void>(),
                    SIGINFO_BYTES,
                )
            };
            let mut no = 0;
            if n < 0 {
                no = sig_errno();
            }
            let code = classify_signal_read(n as i64, no);
            if code == READ_PENDING {
                return SignalOut {
                    state: "pending".to_string(),
                    message: String::new(),
                };
            }
            if code == READ_NONE {
                return SignalOut {
                    state: "none".to_string(),
                    message: String::new(),
                };
            }
            if code == READ_ERROR {
                if n == 0 {
                    return SignalOut {
                        state: "error".to_string(),
                        message: "signal read: short".to_string(),
                    };
                }
                return SignalOut {
                    state: "error".to_string(),
                    message: format!("signal read: errno {no}"),
                };
            }
        }
    }

    /// Restore the mask and close the fd (idempotent).
    pub fn teardown(&mut self) {
        if !self.armed {
            return;
        }
        // SAFETY: armed fd, closed once here.
        unsafe {
            libc::close(self.fd);
        }
        let mut scratch = [0u8; SIGSET_BYTES];
        // SAFETY: live 128-byte mask buffers.
        unsafe {
            libc::sigprocmask(
                libc::SIG_SETMASK,
                self.old_mask.as_ptr().cast::<libc::sigset_t>(),
                scratch.as_mut_ptr().cast::<libc::sigset_t>(),
            );
        }
        self.fd = -1;
        self.armed = false;
    }
}

impl Default for LiveSignalSource {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LiveSignalSource {
    fn drop(&mut self) {
        self.teardown();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        LiveSignalSource, READ_ERROR, READ_NONE, READ_PENDING, READ_RETRY, argv_storage,
        blocked_mask, classify_signal_read, ensure_inherited_signal_block,
    };
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn classify() {
        assert_eq!(classify_signal_read(128, 0), READ_PENDING);
        assert_eq!(classify_signal_read(1, 0), READ_PENDING);
        assert_eq!(classify_signal_read(-1, 11), READ_NONE);
        assert_eq!(classify_signal_read(-1, 4), READ_RETRY);
        assert_eq!(classify_signal_read(-1, 5), READ_ERROR);
        assert_eq!(classify_signal_read(-1, 9), READ_ERROR);
        assert_eq!(classify_signal_read(0, 0), READ_ERROR);
    }

    #[test]
    fn mask_bits() {
        let mask = blocked_mask();
        assert_eq!(mask.len(), 128);
        assert_eq!(mask[0], 0x03);
        assert_eq!(mask[1], 0x40);
        for b in mask.iter().skip(2) {
            assert_eq!(*b, 0);
        }
    }

    #[test]
    fn hangup_is_in_orderly_mask() {
        let mask = blocked_mask();
        assert_eq!(mask[0] & 1, 1);
    }

    #[test]
    fn setup_check_teardown_roundtrip() {
        let mut src = LiveSignalSource::new();
        let setup = src.setup();
        assert!(setup.ok, "setup failed: {}", setup.message);
        let first = src.check();
        assert_eq!(first.state, "none");
        assert_eq!(first.message, "");
        let second = src.check();
        assert_eq!(second.state, "none");
        src.teardown();
        // Teardown is idempotent.
        src.teardown();
    }

    #[test]
    fn setup_fault_points() {
        let mut mask_fail = LiveSignalSource::new();
        mask_fail.test_fail_setup_at = "mask".to_string();
        let out = mask_fail.setup();
        assert!(!out.ok);
        assert_eq!(out.message, "test mask failure");

        let mut fd_fail = LiveSignalSource::new();
        fd_fail.test_fail_setup_at = "signalfd".to_string();
        let out = fd_fail.setup();
        assert!(!out.ok);
        assert_eq!(out.message, "test signalfd failure");
    }

    #[test]
    fn pending_signal_reports() {
        let mut src = LiveSignalSource::new();
        let setup = src.setup();
        assert!(setup.ok, "setup failed: {}", setup.message);
        // SAFETY: directed at this thread only, whose stop signals
        // are blocked, so the signal stays pending for signalfd.
        unsafe {
            let rc = libc::pthread_kill(libc::pthread_self(), libc::SIGHUP);
            assert_eq!(rc, 0);
        }
        let got = src.check();
        assert_eq!(got.state, "pending");
        assert_eq!(got.message, "");
        src.teardown();
    }

    #[test]
    fn reexec_argv_forwards_raw_bytes_unexpanded() {
        // The 44,000-byte 0xff word beside --help must cross
        // the re-exec as 44,000 bytes plus NUL: lossy decoding
        // would expand it to 132,000 bytes and trip E2BIG
        // before the verb prints help (Mojo's argv() preserves
        // raw bytes, so its re-exec succeeds and exits 0).
        let big = OsString::from_vec(vec![0xff; 44_000]);
        let args = vec![
            OsString::new(),
            OsString::from("record"),
            big,
            OsString::from("--help"),
        ];
        let storage = argv_storage(b"/resolved/memveil", &args);
        assert_eq!(storage.len(), 4);
        assert_eq!(storage[0], b"/resolved/memveil\0");
        assert_eq!(storage[1], b"record\0");
        assert_eq!(storage[2].len(), 44_001);
        assert!(storage[2][..44_000].iter().all(|&b| b == 0xff));
        assert_eq!(storage[2][44_000], 0);
        assert_eq!(storage[3], b"--help\0");
    }

    #[test]
    fn reexec_argv_skips_placeholder_and_keeps_nuls() {
        // args[0] is the caller's placeholder, never forwarded;
        // interior NULs pass through and truncate at exec.
        let args = vec![
            OsString::from("placeholder"),
            OsString::from_vec(b"a\0b".to_vec()),
            OsString::new(),
        ];
        let storage = argv_storage(b"/x", &args);
        assert_eq!(
            storage,
            vec![b"/x\0".to_vec(), b"a\0b\0".to_vec(), b"\0".to_vec()]
        );
        let empty = argv_storage(b"/x", &[]);
        assert_eq!(empty, vec![b"/x\0".to_vec()]);
    }

    #[test]
    fn reexec_guard_sentinel_paths() {
        // One test for both sentinel paths: MEMVEIL_SIGBLK is
        // process-global, so two parallel tests could remove it
        // mid-flight of each other and send one down the live
        // re-exec path. Sequential phases cannot race.
        //
        // Refuse: the sentinel is set but this thread never
        // inherited the blocked mask.
        // SAFETY: the sentinel var is private to this test.
        unsafe {
            std::env::set_var("MEMVEIL_SIGBLK", "1");
        }
        let refused = ensure_inherited_signal_block(&[]);
        // SAFETY: restoring the environment.
        unsafe {
            std::env::remove_var("MEMVEIL_SIGBLK");
        }
        assert_eq!(
            refused,
            "signal mask not inherited (MEMVEIL_SIGBLK set,\
             \u{20}SIGHUP/SIGINT/SIGTERM unblocked); refusing"
        );

        // Accept: block the mask by hand, then prove the
        // sentinel path verifies it and lets the caller proceed.
        let mask = blocked_mask();
        let mut old = [0u8; 128];
        // SAFETY: live 128-byte mask buffers.
        unsafe {
            let rc = libc::sigprocmask(
                libc::SIG_BLOCK,
                mask.as_ptr().cast::<libc::sigset_t>(),
                old.as_mut_ptr().cast::<libc::sigset_t>(),
            );
            assert_eq!(rc, 0);
            std::env::set_var("MEMVEIL_SIGBLK", "1");
        }
        let note = ensure_inherited_signal_block(&[]);
        // SAFETY: restoring the mask and the environment.
        unsafe {
            let mut scratch = [0u8; 128];
            let rc = libc::sigprocmask(
                libc::SIG_SETMASK,
                old.as_ptr().cast::<libc::sigset_t>(),
                scratch.as_mut_ptr().cast::<libc::sigset_t>(),
            );
            assert_eq!(rc, 0);
            std::env::remove_var("MEMVEIL_SIGBLK");
        }
        assert_eq!(note, "");
    }
}
