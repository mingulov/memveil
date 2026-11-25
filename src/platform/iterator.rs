// SPDX-License-Identifier: GPL-3.0-or-later
//! Generic iterator transport: open/read/close ownership over a byte fd.
//!
//! [`FdIterator`] owns one readable fd (a kernel text source, a pipe, or a
//! plain file) and moves bytes through a bounded loop: a short read hands
//! the partial span back for the caller to resume, `EINTR` retries,
//! `EAGAIN` yields to the caller, EOF sticks, and a total visit bound plus
//! an optional deadline cut the scan short with an explicit outcome
//! instead of silent truncation. Cancel refuses further reads; close is
//! idempotent; drop closes exactly once.
//!
//! The module is transport only: it knows bytes, fds, and bounds, and
//! nothing about the payload carried above it. It depends on std plus
//! libc and never on sibling product trees, so integrators can wire it
//! with one `pub mod iterator;` line and callers can hold it behind any
//! clock or source they choose.

use std::os::unix::io::RawFd;
use std::path::Path;

/// I/O failure opening or reading the source.
pub const ITER_IO: u32 = 1;
/// The iterator was cancelled; reads refuse.
pub const ITER_CANCELLED: u32 = 2;
/// The iterator is closed; reads refuse.
pub const ITER_CLOSED: u32 = 3;

/// Read disposition: bytes arrived.
pub const READ_DELIVER: i32 = 0;
/// Read disposition: clean end of stream.
pub const READ_EOF: i32 = 1;
/// Read disposition: retry the read (`EINTR`).
pub const READ_RETRY: i32 = 2;
/// Read disposition: no bytes now (`EAGAIN`); yield to the caller.
pub const READ_YIELD: i32 = 3;
/// Read disposition: the source failed.
pub const READ_FAIL: i32 = 4;

/// Largest single `read(2)` the loop issues (64 KiB).
const CHUNK_BYTES: usize = 65_536;

/// One iterator failure. Callers match on `code`, never text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IterError {
    /// Machine-stable failure code (`ITER_*`).
    pub code: u32,
    /// Human detail; carries the errno number only, never source bytes.
    pub message: String,
}

impl std::fmt::Display for IterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "IterError(code={}, message={})", self.code, self.message)
    }
}

impl std::error::Error for IterError {}

/// How one bounded read call finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IterOutcome {
    /// Bytes moved and more may be available; call again.
    More,
    /// Clean end of stream; sticky on later calls.
    Eof,
    /// Nothing ready now; the caller rests and calls again.
    WouldBlock,
    /// The total visit bound is reached; the partial span stays in `out`.
    VisitBound,
    /// The deadline passed; the partial span stays in `out`.
    Deadline,
}

/// Bytes appended to `out` by one [`FdIterator::read_into`] call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IterRead {
    /// How the call finished.
    pub outcome: IterOutcome,
    /// Bytes appended to `out` by this call.
    pub bytes: usize,
}

/// Pure `read(2)` disposition: `EINTR` retries, `EAGAIN` yields.
///
/// `n` is the raw return and `errno_no` the sampled errno (ignored
/// unless `n < 0`). The bounded loop obeys this table; shims assert it.
pub fn classify_read(n: i64, errno_no: i32) -> i32 {
    if n > 0 {
        return READ_DELIVER;
    }
    if n == 0 {
        return READ_EOF;
    }
    if errno_no == libc::EINTR {
        return READ_RETRY;
    }
    if errno_no == libc::EAGAIN {
        return READ_YIELD;
    }
    READ_FAIL
}

fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// One owned iterator fd with total visit and deadline bounds.
///
/// The handle owns the fd from `open`/`from_fd` until `close` or drop.
/// Reads append raw bytes to a caller buffer; bound hits surface as
/// [`IterOutcome::VisitBound`]/[`IterOutcome::Deadline`] with the partial
/// span intact.
#[derive(Debug)]
pub struct FdIterator {
    fd: RawFd,
    visited: u64,
    max_visit: u64,
    deadline_ns: Option<u64>,
    cancelled: bool,
    eof: bool,
}

impl FdIterator {
    /// Open `path` read-only with close-on-exec set atomically.
    pub fn open(path: &Path, nonblocking: bool) -> Result<Self, IterError> {
        use std::os::unix::ffi::OsStrExt;
        let bytes = path.as_os_str().as_bytes();
        if bytes.contains(&0) {
            return Err(IterError {
                code: ITER_IO,
                message: format!("cannot open iterator source (errno {})", libc::EINVAL),
            });
        }
        let mut body = Vec::with_capacity(bytes.len() + 1);
        body.extend_from_slice(bytes);
        body.push(0);
        let mut flags = libc::O_RDONLY | libc::O_CLOEXEC;
        if nonblocking {
            flags |= libc::O_NONBLOCK;
        }
        // SAFETY: NUL-terminated path; no mode needed for a read-only open.
        let fd = unsafe { libc::open(body.as_ptr().cast::<libc::c_char>(), flags) };
        if fd < 0 {
            return Err(IterError {
                code: ITER_IO,
                message: format!("cannot open iterator source (errno {})", last_errno()),
            });
        }
        Ok(Self::from_fd(fd))
    }

    /// Take ownership of a live readable fd (a shim pipe end in tests).
    ///
    /// A negative fd marks the handle closed at once; no close runs.
    pub fn from_fd(fd: RawFd) -> Self {
        Self {
            fd: if fd >= 0 { fd } else { -1 },
            visited: 0,
            max_visit: u64::MAX,
            deadline_ns: None,
            cancelled: false,
            eof: false,
        }
    }

    /// Cap total bytes moved across all calls (`u64::MAX` lifts the cap).
    pub fn set_max_visit_bytes(&mut self, max: u64) {
        self.max_visit = max;
    }

    /// Cut the scan once the caller clock reaches `deadline` (`None` lifts).
    ///
    /// The clock must report monotonic nanoseconds; the loop samples it
    /// before every `read(2)` and aborts with the partial span intact.
    pub fn set_deadline_ns(&mut self, deadline: Option<u64>) {
        self.deadline_ns = deadline;
    }

    /// Move up to `want` more bytes into `out`.
    ///
    /// A short read returns at once with [`IterOutcome::More`] and the
    /// partial span, so a call on a blocking fd never sleeps holding
    /// bytes it already moved; call again to resume. `EINTR` retries;
    /// `EAGAIN` returns at once ([`IterOutcome::WouldBlock`] when nothing
    /// moved, [`IterOutcome::More`] with the partial span otherwise) so
    /// the caller rests instead of spinning.
    ///
    /// On `Err`, bytes appended earlier in the same call stay in `out`
    /// and count in [`FdIterator::visited`]; the handle stays usable
    /// and the next call reads again.
    pub fn read_into(
        &mut self,
        out: &mut Vec<u8>,
        want: usize,
        clock: &mut impl FnMut() -> u64,
    ) -> Result<IterRead, IterError> {
        if self.fd < 0 {
            return Err(IterError {
                code: ITER_CLOSED,
                message: "iterator is closed".to_string(),
            });
        }
        if self.cancelled {
            return Err(IterError {
                code: ITER_CANCELLED,
                message: "iterator is cancelled".to_string(),
            });
        }
        if self.eof {
            return Ok(IterRead {
                outcome: IterOutcome::Eof,
                bytes: 0,
            });
        }
        let mut moved = 0usize;
        loop {
            if moved >= want {
                return Ok(IterRead {
                    outcome: IterOutcome::More,
                    bytes: moved,
                });
            }
            if self.visited >= self.max_visit {
                return Ok(IterRead {
                    outcome: IterOutcome::VisitBound,
                    bytes: moved,
                });
            }
            if let Some(limit) = self.deadline_ns
                && clock() >= limit
            {
                return Ok(IterRead {
                    outcome: IterOutcome::Deadline,
                    bytes: moved,
                });
            }
            let rest = self.max_visit - self.visited;
            let cap = usize::try_from(rest).unwrap_or(usize::MAX);
            let ask = (want - moved).min(CHUNK_BYTES).min(cap);
            let mut chunk = vec![0u8; ask];
            // SAFETY: live owned fd; the chunk is borrowed for the call.
            let n = unsafe { libc::read(self.fd, chunk.as_mut_ptr().cast::<libc::c_void>(), ask) };
            let no = if n < 0 { last_errno() } else { 0 };
            match classify_read(n as i64, no) {
                READ_DELIVER => {
                    let got = n as usize;
                    out.extend_from_slice(&chunk[..got]);
                    self.visited = self.visited.saturating_add(got as u64);
                    moved += got;
                    if got < ask {
                        // Short read: the source has nothing more ready
                        // now. Hand the partial span back instead of
                        // sleeping in another read(2) holding it; the
                        // caller resumes with the next call.
                        return Ok(IterRead {
                            outcome: IterOutcome::More,
                            bytes: moved,
                        });
                    }
                }
                READ_EOF => {
                    self.eof = true;
                    return Ok(IterRead {
                        outcome: IterOutcome::Eof,
                        bytes: moved,
                    });
                }
                READ_RETRY => continue,
                READ_YIELD => {
                    let outcome = if moved > 0 {
                        IterOutcome::More
                    } else {
                        IterOutcome::WouldBlock
                    };
                    return Ok(IterRead {
                        outcome,
                        bytes: moved,
                    });
                }
                _ => {
                    return Err(IterError {
                        code: ITER_IO,
                        message: format!("iterator read failed (errno {no})"),
                    });
                }
            }
        }
    }

    /// Refuse further reads; the fd stays owned until `close` or drop.
    pub fn cancel(&mut self) {
        self.cancelled = true;
    }

    /// Close the owned fd exactly once; safe to repeat.
    pub fn close(&mut self) {
        if self.fd >= 0 {
            // SAFETY: owned-or-negative fd; best effort.
            unsafe {
                libc::close(self.fd);
            }
            self.fd = -1;
        }
    }

    /// `true` once `close` has run (or a negative fd was adopted).
    pub fn is_closed(&self) -> bool {
        self.fd < 0
    }

    /// Total bytes moved across all calls.
    pub fn visited(&self) -> u64 {
        self.visited
    }

    /// The owned fd, borrowed; the caller must never close it.
    pub fn raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for FdIterator {
    fn drop(&mut self) {
        self.close();
    }
}
