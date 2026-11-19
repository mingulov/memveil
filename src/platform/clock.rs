// SPDX-License-Identifier: GPL-3.0-or-later
//! Monotonic clock and time-namespace guard for record.
//!
//! [`MonoClock`] reads CLOCK_MONOTONIC and sleeps via nanosleep
//! with inherent methods. Signals stay blocked during record, so
//! the sleep never EINTRs. The timens check refuses virtualized
//! clocks: any nonzero integer token in timens_offsets is an
//! offset. [`wall_ns`] reads CLOCK_REALTIME for receipt
//! timestamps; it is wall time, never capture time.
//!
//! Trait seam: this module ships inherent methods only, with
//! signatures the collector's `ClockSource` trait adopts
//! (`now(&mut self) -> u64`, `sleep_ms(&mut self, ms: i64)`).
//! The trait definition and its `impl` for [`MonoClock`]
//! land with the collector task; nothing here changes then.

use super::reader::read_host_file;

/// CLOCK_REALTIME nanoseconds since the epoch, 0 on failure.
pub fn wall_ns() -> u64 {
    // SAFETY: zeroed timespec outlives the call.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: as above.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };
    if rc != 0 {
        return 0;
    }
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

/// CLOCK_MONOTONIC nanoseconds plus settle sleeps.
pub struct MonoClock {
    _private: (),
}

impl MonoClock {
    /// A monotonic clock.
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// CLOCK_MONOTONIC nanoseconds, 0 on failure.
    pub fn now(&mut self) -> u64 {
        // SAFETY: zeroed timespec outlives the call.
        let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: as above.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            return 0;
        }
        ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
    }

    /// Sleep `ms` milliseconds (clamped at zero).
    pub fn sleep_ms(&mut self, ms: i64) {
        let clamped = ms.max(0) as u64;
        let req = libc::timespec {
            tv_sec: (clamped / 1000) as libc::time_t,
            tv_nsec: ((clamped % 1000) * 1_000_000) as libc::c_long,
        };
        // SAFETY: zeroed timespec outlives the call.
        let mut rem: libc::timespec = unsafe { std::mem::zeroed() };
        // SAFETY: live request and remainder; signals stay
        // blocked during record, so the sleep never EINTRs,
        // and the return is ignored either way.
        unsafe {
            libc::nanosleep(&req, &mut rem);
        }
    }
}

impl Default for MonoClock {
    fn default() -> Self {
        Self::new()
    }
}

fn is_integer_token(body: &[u8], lo: usize, hi: usize) -> bool {
    let mut start = lo;
    if start < hi && body[start] == 0x2D {
        start += 1;
    }
    if start >= hi {
        return false;
    }
    body[start..hi].iter().all(|b| b.is_ascii_digit())
}

fn token_is_nonzero(body: &[u8], lo: usize, hi: usize) -> bool {
    body[lo..hi].iter().any(|b| (0x31..=0x39).contains(b))
}

/// True when timens_offsets carries a nonzero integer token.
///
/// Clock names and blank runs are skipped; only integer
/// tokens count, and only when a nonzero digit appears.
pub fn timens_has_offset(body: &[u8]) -> bool {
    let total = body.len();
    let mut i = 0;
    while i < total {
        let b = body[i];
        if b == 0x20 || b == 0x09 || b == 0x0A || b == 0x0D {
            i += 1;
            continue;
        }
        let lo = i;
        while i < total {
            let c = body[i];
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D {
                break;
            }
            i += 1;
        }
        if is_integer_token(body, lo, i) && token_is_nonzero(body, lo, i) {
            return true;
        }
    }
    false
}

/// One timens read (`offset` valid only when `ok`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimensOut {
    /// True when the file read.
    pub ok: bool,
    /// True when an offset token was present.
    pub offset: bool,
    /// Failure detail; empty on success.
    pub message: String,
}

/// Read /proc/self/timens_offsets and look for an offset.
///
/// An unreadable file refuses admission: the clock cannot
/// be proven clean. Supported kernels (7.0+) always carry
/// this file when time namespaces exist.
pub fn check_timens_live() -> TimensOut {
    match read_host_file("/proc/self/timens_offsets", "timens", 4096) {
        Ok(raw) => TimensOut {
            ok: true,
            offset: timens_has_offset(&raw),
            message: String::new(),
        },
        Err(e) => TimensOut {
            ok: false,
            offset: false,
            message: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{MonoClock, check_timens_live, timens_has_offset, wall_ns};

    #[test]
    fn clean_offsets() {
        assert!(!timens_has_offset(
            b"monotonic           0         0\nboottime            0         0\n"
        ));
        assert!(!timens_has_offset(b""));
    }

    #[test]
    fn offset_vectors() {
        assert!(timens_has_offset(
            b"monotonic           0         0\nboottime         3600         0\n"
        ));
        assert!(timens_has_offset(b"monotonic          -5         0\n"));
        assert!(!timens_has_offset(b"monotonic boottime\n"));
        assert!(!timens_has_offset(b"monotonic          -0         0\n"));
        // "1.5" is not an integer token, so it cannot be an offset.
        assert!(!timens_has_offset(b"monotonic         1.5         0\n"));
    }

    #[test]
    fn clock_live() {
        let mut clock = MonoClock::new();
        let t0 = clock.now();
        assert!(t0 > 0);
        clock.sleep_ms(5);
        let t1 = clock.now();
        assert!(t1 >= t0);
    }

    #[test]
    fn timens_live_readable() {
        let out = check_timens_live();
        assert!(out.ok, "timens unreadable: {}", out.message);
    }

    #[test]
    fn wall_ns_live() {
        // CLOCK_REALTIME can step backwards (NTP/VM), so this
        // asserts sample validity, never ordering.
        let t0 = wall_ns();
        assert!(t0 > 1_600_000_000_000_000_000);
        let mut clock = MonoClock::new();
        clock.sleep_ms(5);
        let t1 = wall_ns();
        assert!(t1 > 1_600_000_000_000_000_000);
    }
}
