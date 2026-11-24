// SPDX-License-Identifier: GPL-3.0-or-later
//! Iterator transport over shim fds: pipe-held bytes, never a live source.
//!
//! Lease-free coverage for the generic open/read/close owner. Every case
//! runs against pipes, a scratch regular file, or a pure disposition
//! function; no live kernel read happens here.
//!
//! Compile boundary: the module under test is included via `#[path]`
//! and must stay dependency-free (std plus libc only, no `crate::`
//! use). The `transport_holds_no_product_items` case enforces that
//! boundary by scanning the module text for forbidden tokens.

#[path = "../src/platform/iterator.rs"]
mod iterator;

use iterator::{FdIterator, READ_DELIVER, READ_EOF, READ_FAIL, READ_RETRY, READ_YIELD};
use iterator::{ITER_CANCELLED, ITER_CLOSED, ITER_IO, IterError, IterOutcome, classify_read};
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

/// Serializes every case in this binary: fd-lifetime assertions count
/// `/proc/self/fd` entries, which parallel cases would perturb.
static FD_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn lock() -> std::sync::MutexGuard<'static, ()> {
    FD_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("fd lock")
}

/// Live open fds of this process, counted via `/proc/self/fd`.
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .expect("read /proc/self/fd")
        .count()
}

/// `true` when `fd` refers to nothing (close released it exactly once).
fn fd_is_dead(fd: RawFd) -> bool {
    // SAFETY: F_GETFD never dereferences memory; it only probes the table.
    let rc = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if rc >= 0 {
        return false;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EBADF)
}

/// One pipe; the read end is nonblocking, both ends close-on-exec.
fn shim_pipe() -> (RawFd, RawFd) {
    let mut ends = [0 as libc::c_int; 2];
    // SAFETY: `ends` outlives the call; both fds are owned on success.
    let rc = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0, "pipe2 builds the shim");
    // SAFETY: live owned read end; F_SETFL touches flags only.
    let rc = unsafe { libc::fcntl(ends[0], libc::F_SETFL, libc::O_NONBLOCK) };
    assert_eq!(rc, 0, "read end goes nonblocking");
    (ends[0], ends[1])
}

fn write_all(fd: RawFd, bytes: &[u8]) {
    let mut at = 0;
    while at < bytes.len() {
        // SAFETY: live fd; the slice region is borrowed for the call.
        let n = unsafe {
            libc::write(
                fd,
                bytes[at..].as_ptr().cast::<libc::c_void>(),
                bytes.len() - at,
            )
        };
        assert!(n > 0, "shim write moves bytes");
        at += n as usize;
    }
}

fn close_fd(fd: RawFd) {
    // SAFETY: test-owned fd, closed exactly once here.
    let rc = unsafe { libc::close(fd) };
    assert_eq!(rc, 0, "shim close lands");
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("mv-iterator-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

/// Fixed clock: every sample reports `at`.
fn fixed_clock(at: u64) -> impl FnMut() -> u64 {
    move || at
}

#[test]
fn short_read_returns_partial_and_resumes() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    let mut out = Vec::new();

    write_all(write_end, b"abc");
    let first = it
        .read_into(&mut out, 10, &mut fixed_clock(0))
        .expect("partial read");
    assert_eq!(first.outcome, IterOutcome::More);
    assert_eq!(first.bytes, 3);
    assert_eq!(out, b"abc");
    assert_eq!(it.visited(), 3);

    write_all(write_end, b"de");
    close_fd(write_end);
    let second = it
        .read_into(&mut out, 10, &mut fixed_clock(0))
        .expect("resume read");
    assert_eq!(second.outcome, IterOutcome::Eof);
    assert_eq!(second.bytes, 2);
    assert_eq!(out, b"abcde");
    assert_eq!(it.visited(), 5);
}

#[test]
fn visit_bound_yields_scoped_partial() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    it.set_max_visit_bytes(10);
    let mut out = Vec::new();

    write_all(write_end, b"0123456789abcdef");
    close_fd(write_end);

    let first = it
        .read_into(&mut out, 8, &mut fixed_clock(0))
        .expect("first span");
    assert_eq!(first.outcome, IterOutcome::More);
    assert_eq!(first.bytes, 8);

    let second = it
        .read_into(&mut out, 8, &mut fixed_clock(0))
        .expect("bound span");
    assert_eq!(second.outcome, IterOutcome::VisitBound);
    assert_eq!(second.bytes, 2);
    assert_eq!(out.len(), 10);
    assert_eq!(it.visited(), 10);

    let third = it
        .read_into(&mut out, 8, &mut fixed_clock(0))
        .expect("bound sticks");
    assert_eq!(third.outcome, IterOutcome::VisitBound);
    assert_eq!(third.bytes, 0);
    assert_eq!(out.len(), 10);
}

#[test]
fn deadline_aborts_with_partial_not_silent_truncation() {
    let _guard = lock();
    let dir = scratch("deadline");
    let path = dir.join("bytes.bin");
    let body = vec![0x5Au8; 200_000];
    std::fs::write(&path, &body).expect("shim body");
    let mut it = FdIterator::open(&path, false).expect("shim open");
    it.set_deadline_ns(Some(250));
    let mut out = Vec::new();

    let mut now = 0u64;
    let read = it
        .read_into(&mut out, 200_000, &mut || {
            now += 100;
            now
        })
        .expect("deadline read");
    assert_eq!(read.outcome, IterOutcome::Deadline);
    assert!(!out.is_empty(), "partial bytes survive the abort");
    assert!(out.len() < body.len(), "the bound cut the scan short");
    assert_eq!(it.visited() as usize, out.len());
    assert!(out.iter().all(|b| *b == 0x5A));
}

#[test]
fn deadline_at_entry_aborts_before_any_read() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    it.set_deadline_ns(Some(1_000));
    let mut out = Vec::new();

    write_all(write_end, b"held");
    let read = it
        .read_into(&mut out, 4, &mut fixed_clock(1_000))
        .expect("deadline read");
    assert_eq!(read.outcome, IterOutcome::Deadline);
    assert_eq!(read.bytes, 0);
    assert!(out.is_empty());
    assert_eq!(it.visited(), 0);
    close_fd(write_end);
}

#[test]
fn eof_is_clean_and_sticky() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    close_fd(write_end);
    let mut it = FdIterator::from_fd(read_end);
    let mut out = Vec::new();

    let first = it
        .read_into(&mut out, 16, &mut fixed_clock(0))
        .expect("clean eof");
    assert_eq!(first.outcome, IterOutcome::Eof);
    assert_eq!(first.bytes, 0);
    let second = it
        .read_into(&mut out, 16, &mut fixed_clock(0))
        .expect("sticky eof");
    assert_eq!(second.outcome, IterOutcome::Eof);
    assert_eq!(second.bytes, 0);
}

#[test]
fn eintr_disposition_retries_eagain_yields() {
    let _guard = lock();
    assert_eq!(classify_read(7, 0), READ_DELIVER);
    assert_eq!(classify_read(0, 0), READ_EOF);
    assert_eq!(classify_read(-1, libc::EINTR), READ_RETRY);
    assert_eq!(classify_read(-1, libc::EAGAIN), READ_YIELD);
    assert_eq!(classify_read(-1, libc::EIO), READ_FAIL);
}

#[test]
fn eagain_yields_without_busy_loop() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    let mut out = Vec::new();

    let idle = it
        .read_into(&mut out, 16, &mut fixed_clock(0))
        .expect("idle read");
    assert_eq!(idle.outcome, IterOutcome::WouldBlock);
    assert_eq!(idle.bytes, 0);
    assert_eq!(it.visited(), 0);

    write_all(write_end, b"later");
    close_fd(write_end);
    let woke = it
        .read_into(&mut out, 16, &mut fixed_clock(0))
        .expect("woken read");
    assert_eq!(woke.bytes, 5);
    assert_eq!(out, b"later");
}

#[test]
fn cancel_then_close_is_safe() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    it.cancel();
    it.cancel();

    let mut out = Vec::new();
    let err = it
        .read_into(&mut out, 8, &mut fixed_clock(0))
        .expect_err("cancel refuses");
    assert_eq!(err.code, ITER_CANCELLED);

    it.close();
    assert!(it.is_closed());
    it.close();
    assert!(fd_is_dead(read_end), "cancel-then-close releases once");
    close_fd(write_end);
}

#[test]
fn double_close_releases_once() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    it.close();
    it.close();
    assert!(it.is_closed());
    assert!(fd_is_dead(read_end), "exactly one close lands");
    close_fd(write_end);
}

#[test]
fn drop_releases_the_held_reference() {
    let _guard = lock();
    let before = open_fd_count();
    let read_end = {
        let (read_end, write_end) = shim_pipe();
        let it = FdIterator::from_fd(read_end);
        assert!(!it.is_closed());
        close_fd(write_end);
        read_end
    };
    assert!(fd_is_dead(read_end), "drop closes the held fd");
    assert_eq!(open_fd_count(), before, "no fd survives the drop");
}

#[test]
fn repeated_open_close_cycles_hold_fd_count_steady() {
    let _guard = lock();
    let before = open_fd_count();
    for _ in 0..20 {
        let (read_end, write_end) = shim_pipe();
        let mut it = FdIterator::from_fd(read_end);
        let mut out = Vec::new();
        let idle = it
            .read_into(&mut out, 8, &mut fixed_clock(0))
            .expect("idle cycle read");
        assert_eq!(idle.outcome, IterOutcome::WouldBlock);
        it.close();
        close_fd(write_end);
    }
    assert_eq!(open_fd_count(), before, "cycles leak nothing");
}

#[test]
fn open_reads_a_path_and_sets_cloexec() {
    let _guard = lock();
    let dir = scratch("open");
    let path = dir.join("hello.txt");
    std::fs::write(&path, b"hello").expect("shim file");
    let mut it = FdIterator::open(&path, true).expect("shim open");
    assert!(!it.is_closed());
    // SAFETY: live owned fd; F_GETFD probes flags only.
    let flags = unsafe { libc::fcntl(it.raw_fd(), libc::F_GETFD) };
    assert!(flags >= 0, "owned fd answers");
    assert_ne!(flags & libc::FD_CLOEXEC, 0, "open sets close-on-exec");

    let mut out = Vec::new();
    let read = it
        .read_into(&mut out, 16, &mut fixed_clock(0))
        .expect("file read");
    assert_eq!(read.outcome, IterOutcome::Eof);
    assert_eq!(out, b"hello");
}

#[test]
fn open_missing_path_reports_io() {
    let _guard = lock();
    let dir = scratch("missing");
    let err = FdIterator::open(&dir.join("absent.txt"), false).expect_err("missing refuses");
    assert_eq!(err.code, ITER_IO);
    assert!(
        err.message.contains("2"),
        "diagnostic carries errno, got {}",
        err.message
    );
}

#[test]
fn read_after_close_reports_closed() {
    let _guard = lock();
    let (read_end, write_end) = shim_pipe();
    let mut it = FdIterator::from_fd(read_end);
    it.close();
    let mut out = Vec::new();
    let err = it
        .read_into(&mut out, 8, &mut fixed_clock(0))
        .expect_err("closed refuses");
    assert_eq!(err.code, ITER_CLOSED);
    close_fd(write_end);
}

#[test]
fn transport_holds_no_product_items() {
    let _guard = lock();
    let body = include_str!("../src/platform/iterator.rs");
    for token in [
        "crate::",
        "use crate",
        "exposure",
        "census",
        "schema",
        "model",
        "event",
        "record",
        "libbpf",
        "aya",
    ] {
        assert!(
            !body.to_lowercase().contains(token),
            "transport mentions forbidden token {token:?}"
        );
    }
    let _: IterError = IterError {
        code: ITER_IO,
        message: String::new(),
    };
}
