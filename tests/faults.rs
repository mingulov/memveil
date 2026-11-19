// SPDX-License-Identifier: GPL-3.0-or-later
//! Native fault-injection tests: fail-closed behavior for a flooded ring,
//! wrapped kernel counters, and a wrong probe argc.
//!
//! The live equivalents seed BPF maps on a privileged host
//! (`map_write` under `MEMVEIL_TEST_BPF_LIVE`); these tests pin the same
//! fail-closed contracts natively by scripting the public [`KernelSource`]
//! cuts a flood, a wrap, or an argc mismatch produces, then driving a full
//! [`Collector::run`] over a real [`LiveWriter`] capture:
//!
//! * ring flood: the kernel drops submissions under flood pressure and the
//!   drops surface as `submit_fail` in the `mv_counts` cut. Fail-closed
//!   means the loss is counted in the session (`submit_fail=(N)`), never
//!   silent.
//! * counter wrap: a wrapped counter sets its `FLAG_*_WRAP` bit. Fail-closed
//!   means the unreadable component renders `(unavailable)` and the detail
//!   verdict goes unknown instead of trusting a wrapped value.
//! * wrong argc: an fentry probe whose traced function changed arity sets
//!   `FLAG_ARGCNT`. Fail-closed means the channel takes the
//!   unknown-with-reason path (`argument count mismatch`) instead of
//!   reading registers under a stale layout.
//!
//! `report_top_stream_refusal` is the native equivalent of the
//! stream-creation refusal: a capture whose events path cannot be streamed
//! (fifo, directory) refuses with exit 2, empty stdout, and the exact
//! `cannot read capture` wording on both verbs.

use memveil::capture::collector::{ClockSource, SignalSource};
use memveil::capture::collector::{
    Collector, CollectorConfig, FLAG_ARGCNT, FLAG_SUBMIT_WRAP, GeomOut, KernelSource, MissOut,
    PollOut, SnapOut, StatsOut, all_zero, byte_coverage_valid, byte_identity, count_identity,
    counters_valid, submit_valid,
};
use memveil::capture::live::LiveWriter;
use memveil::model::session::EvidenceItem;
use memveil::platform::outcome::OpOut;
use memveil::platform::signal::SignalOut;
use std::path::{Path, PathBuf};

/// Fresh per-test scratch directory: pid + nanos + counter nonce, and any
/// stale directory at that path is cleared instead of reused.
fn workdir(tag: &str) -> PathBuf {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nonce = NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "memveil-faults-{}-{nanos:x}-{nonce}-{tag}",
        std::process::id()
    ));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("clear stale workdir");
    }
    std::fs::create_dir_all(&dir).expect("create workdir");
    dir
}

fn ok_out() -> OpOut {
    OpOut {
        ok: true,
        message: String::new(),
    }
}

fn ok_geom(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> GeomOut {
    GeomOut {
        ok: true,
        map_type,
        key_size,
        value_size,
        max_entries,
        message: String::new(),
    }
}

fn stats_ok(received: u64, delivered: u64, staged: u64, malformed: u64, dropped: u64) -> StatsOut {
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

fn snap_ok(
    observed: u64,
    observed_bytes: u64,
    emitted: u64,
    emitted_bytes: u64,
    submit_fail: u64,
    flags: u64,
) -> SnapOut {
    SnapOut {
        ok: true,
        vals: vec![
            observed,
            observed_bytes,
            emitted,
            emitted_bytes,
            submit_fail,
            flags,
        ],
        message: String::new(),
    }
}

fn timeout_poll() -> PollOut {
    PollOut {
        kind: "timeout".to_string(),
        frame: Vec::new(),
        required: 0,
        message: String::new(),
    }
}

/// Scripted kernel: queues for polls/stats/snaps with repeat-last tails, so
/// the scripts stay robust to read-count drift. The seeded *order* (zero
/// start cuts, then fault end cuts) is the pin; read counts are asserted
/// alongside the session content so a shifted script cannot pass silently.
struct ScriptKernel {
    polls: Vec<(PollOut, i64)>,
    poll_idx: usize,
    poll_left: i64,
    last_poll: PollOut,
    stats_q: Vec<StatsOut>,
    stats_idx: usize,
    stats_q1: Vec<StatsOut>,
    stats_idx1: usize,
    snaps: Vec<SnapOut>,
    snap_idx: usize,
    snaps1: Vec<SnapOut>,
    snap_idx1: usize,
    channels: i64,
    polls_done: usize,
    stats_done: usize,
    snaps_done: usize,
}

impl ScriptKernel {
    fn new() -> Self {
        Self {
            polls: Vec::new(),
            poll_idx: 0,
            poll_left: 0,
            last_poll: timeout_poll(),
            stats_q: Vec::new(),
            stats_idx: 0,
            stats_q1: Vec::new(),
            stats_idx1: 0,
            snaps: Vec::new(),
            snap_idx: 0,
            snaps1: Vec::new(),
            snap_idx1: 0,
            channels: 1,
            polls_done: 0,
            stats_done: 0,
            snaps_done: 0,
        }
    }

    fn add_poll(&mut self, item: PollOut, repeat: i64) {
        self.last_poll = item.clone();
        self.polls.push((item, repeat));
    }

    fn add_stats(&mut self, item: StatsOut) {
        self.stats_q.push(item);
    }

    fn add_stats_at(&mut self, channel: i64, item: StatsOut) {
        if channel == 1 {
            self.stats_q1.push(item);
        } else {
            self.stats_q.push(item);
        }
    }

    fn add_snap(&mut self, item: SnapOut) {
        self.snaps.push(item);
    }

    fn add_snap_at(&mut self, channel: i64, item: SnapOut) {
        if channel == 1 {
            self.snaps1.push(item);
        } else {
            self.snaps.push(item);
        }
    }

    fn next_poll(&mut self) -> PollOut {
        self.polls_done += 1;
        loop {
            if self.poll_idx >= self.polls.len() {
                return self.last_poll.clone();
            }
            if self.poll_left <= 0 {
                self.poll_left = self.polls[self.poll_idx].1;
            }
            if self.poll_left <= 0 {
                self.poll_idx += 1;
                continue;
            }
            self.poll_left -= 1;
            let out = self.polls[self.poll_idx].0.clone();
            self.last_poll = out.clone();
            if self.poll_left <= 0 {
                self.poll_idx += 1;
            }
            return out;
        }
    }

    fn next_stats(&mut self) -> StatsOut {
        self.stats_done += 1;
        if self.stats_idx < self.stats_q.len() {
            let out = self.stats_q[self.stats_idx].clone();
            self.stats_idx += 1;
            out
        } else {
            self.stats_q.last().cloned().unwrap_or_else(|| StatsOut {
                ok: false,
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
                message: "stats script empty".to_string(),
            })
        }
    }

    fn next_snap(&mut self) -> SnapOut {
        self.snaps_done += 1;
        if self.snap_idx < self.snaps.len() {
            let out = self.snaps[self.snap_idx].clone();
            self.snap_idx += 1;
            out
        } else {
            self.snaps.last().cloned().unwrap_or(SnapOut {
                ok: false,
                vals: Vec::new(),
                message: "snap script empty".to_string(),
            })
        }
    }
}

impl KernelSource for ScriptKernel {
    fn open_session(&mut self) -> OpOut {
        ok_out()
    }

    fn load(&mut self) -> OpOut {
        ok_out()
    }

    fn map_info(&mut self, name: &str) -> GeomOut {
        if name == "mv_counts" {
            return ok_geom(2, 4, 8, 6);
        }
        if name == "mv_offsets" {
            return ok_geom(2, 4, 24, 1);
        }
        ok_geom(27, 0, 0, 8388608)
    }

    fn map_info_at(&mut self, channel: i64, name: &str) -> GeomOut {
        if channel < 0 || channel >= self.channels {
            return GeomOut {
                ok: false,
                map_type: 0,
                key_size: 0,
                value_size: 0,
                max_entries: 0,
                message: "bad channel".to_string(),
            };
        }
        if name == "mv_counts" {
            return ok_geom(2, 4, 8, 6);
        }
        ok_geom(27, 0, 0, 8388608)
    }

    fn install_offsets(&mut self, _table: &[u8]) -> OpOut {
        ok_out()
    }

    fn attach(&mut self) -> OpOut {
        ok_out()
    }

    fn set_copy_armed(&mut self, _armed: bool) -> OpOut {
        ok_out()
    }

    fn poll(&mut self, _timeout_ms: i64, _capacity: u32) -> PollOut {
        self.next_poll()
    }

    fn stats(&mut self) -> StatsOut {
        self.next_stats()
    }

    fn stats_at(&mut self, channel: i64) -> StatsOut {
        if channel == 0 {
            return self.stats();
        }
        self.stats_done += 1;
        if channel == 1 {
            if self.stats_idx1 < self.stats_q1.len() {
                let out = self.stats_q1[self.stats_idx1].clone();
                self.stats_idx1 += 1;
                return out;
            }
            if let Some(last) = self.stats_q1.last() {
                return last.clone();
            }
        }
        StatsOut {
            ok: false,
            received: 0,
            delivered: 0,
            staged: 0,
            malformed: 0,
            dropped: 0,
            message: "bad channel".to_string(),
        }
    }

    fn read_full(&mut self) -> SnapOut {
        self.next_snap()
    }

    fn read_full_at(&mut self, channel: i64) -> SnapOut {
        if channel == 0 {
            return self.read_full();
        }
        self.snaps_done += 1;
        if channel == 1 {
            if self.snap_idx1 < self.snaps1.len() {
                let out = self.snaps1[self.snap_idx1].clone();
                self.snap_idx1 += 1;
                return out;
            }
            if let Some(last) = self.snaps1.last() {
                return last.clone();
            }
        }
        SnapOut {
            ok: false,
            vals: Vec::new(),
            message: "bad channel".to_string(),
        }
    }

    fn channel_count(&self) -> i64 {
        self.channels
    }

    fn detach(&mut self) -> OpOut {
        ok_out()
    }

    fn recursion_misses(&mut self) -> MissOut {
        MissOut {
            ok: true,
            ..Default::default()
        }
    }

    fn close(&mut self) -> OpOut {
        ok_out()
    }
}

/// Scripted clock: explicit values, then a 1 ms stepped tail.
struct ScriptClock {
    vals: Vec<u64>,
    idx: usize,
}

impl ScriptClock {
    fn new() -> Self {
        Self {
            vals: Vec::new(),
            idx: 0,
        }
    }

    fn add(&mut self, v: u64) {
        self.vals.push(v);
    }
}

impl ClockSource for ScriptClock {
    fn now(&mut self) -> u64 {
        let out = if self.idx < self.vals.len() {
            self.vals[self.idx]
        } else if let Some(last) = self.vals.last() {
            last.saturating_add(1_000_000 * (self.idx - self.vals.len() + 1) as u64)
        } else {
            0
        };
        self.idx += 1;
        out
    }

    fn sleep_ms(&mut self, _ms: i64) {}
}

/// Quiet signal source: setup ok, never pending (the duration latch ends
/// the loop).
struct QuietSignal;

impl SignalSource for QuietSignal {
    fn setup(&mut self) -> OpOut {
        ok_out()
    }

    fn check(&mut self) -> SignalOut {
        SignalOut {
            state: "none".to_string(),
            message: String::new(),
        }
    }
}

/// Standard clock: start/stable/attach/ready, two sub-deadline nows, the
/// duration latch jump, tail.
fn std_clock() -> ScriptClock {
    let mut clock = ScriptClock::new();
    let base = 1000000000u64;
    clock.add(base);
    clock.add(base + 1);
    clock.add(base + 2);
    clock.add(base + 3);
    clock.add(base + 4);
    clock.add(base + 4);
    clock.add(base + 4);
    clock.add(base + 5);
    let latch = base + 61000000001;
    clock.add(latch);
    for i in 0..7 {
        clock.add(latch + (1 + i) as u64);
    }
    clock
}

fn base_config(dir: &str) -> CollectorConfig {
    let mut cfg = CollectorConfig {
        duration_s: 60,
        max_events_bytes: 134217728,
        output: dir.to_string(),
        profile_id: "probe".to_string(),
        pid: 4242,
        has_boot_id: true,
        boot_id: "probe-boot".to_string(),
        ..Default::default()
    };
    cfg.evidence.push(EvidenceItem {
        item_type: "provenance".to_string(),
        source: "probe".to_string(),
        interpretation: "scripted run".to_string(),
    });
    cfg
}

/// One scripted run: exit/outcome plus both output files as text.
struct ProbeOut {
    exit_code: i64,
    end_reason: String,
    outcome: String,
    events: String,
    session: String,
    polls_done: usize,
    stats_done: usize,
    snaps_done: usize,
}

fn run_probe(work: &Path, kernel: &mut ScriptKernel, cfg: CollectorConfig) -> ProbeOut {
    let dir = work.join("cap");
    let mut writer = LiveWriter::new();
    let mut collector = Collector::new(cfg);
    let mut clock = std_clock();
    let mut signal = QuietSignal;
    let result = collector.run(kernel, &mut clock, &mut signal, &mut writer);
    ProbeOut {
        exit_code: result.exit_code,
        end_reason: result.end_reason,
        outcome: result.outcome,
        events: std::fs::read_to_string(dir.join("events.ndjson")).unwrap_or_default(),
        session: std::fs::read_to_string(dir.join("session.json")).unwrap_or_default(),
        polls_done: kernel.polls_done,
        stats_done: kernel.stats_done,
        snaps_done: kernel.snaps_done,
    }
}

/// Zero baseline + steady post-start flow (drain/end/final).
fn steady_flow(kernel: &mut ScriptKernel, r: u64, d: u64) {
    kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
    for _ in 0..4 {
        kernel.add_stats(stats_ok(r, d, 0, 0, 0));
    }
}

/// Zero start pair + stable end cut.
fn cuts(kernel: &mut ScriptKernel, o: u64, ob: u64, e: u64, eb: u64, s: u64, f: u64) {
    let zero = snap_ok(0, 0, 0, 0, 0, 0);
    kernel.add_snap(zero.clone());
    kernel.add_snap(zero);
    let cut = snap_ok(o, ob, e, eb, s, f);
    kernel.add_snap(cut.clone());
    kernel.add_snap(cut);
}

#[test]
fn ring_flood_submit_fail_is_counted_never_silent() {
    // Thirteen submissions dropped under flood pressure: observed(13) ==
    // emitted(0) + submit_fail(13), identity holds, and the session counts
    // every dropped submission in the detail loss line.
    let work = workdir("ringflood");
    let mut kernel = ScriptKernel::new();
    kernel.add_poll(timeout_poll(), 104);
    steady_flow(&mut kernel, 0, 0);
    cuts(&mut kernel, 13, 832, 0, 0, 13, 0);
    let dir = work.join("cap");
    let p = run_probe(&work, &mut kernel, base_config(dir.to_str().unwrap()));
    assert_eq!(p.exit_code, 0);
    assert_eq!(p.end_reason, "duration");
    assert_eq!(p.outcome, "finalized");
    assert!(p.polls_done > 0 && p.stats_done >= 5 && p.snaps_done >= 4);
    assert!(
        p.session.contains("detail loss 13 (submit_fail=(13)"),
        "flood loss counted: {}",
        p.session
    );
    assert!(
        p.session
            .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"13\","),
        "detail partial with count: {}",
        p.session
    );
    assert_eq!(
        p.events.matches("\"kind\":\"counter_snapshot\"").count(),
        4,
        "quiet flow persists four snapshots"
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn wrapped_submit_counter_renders_unavailable() {
    // SUBMIT_WRAP seeded: the submit_fail component is unreadable, so the
    // epoch is invalid and the session renders it unavailable instead of
    // trusting a wrapped value.
    let work = workdir("wrap");
    let mut kernel = ScriptKernel::new();
    kernel.add_poll(timeout_poll(), 104);
    steady_flow(&mut kernel, 0, 0);
    cuts(&mut kernel, 1, 64, 0, 0, 13, FLAG_SUBMIT_WRAP);
    let dir = work.join("cap");
    let p = run_probe(&work, &mut kernel, base_config(dir.to_str().unwrap()));
    assert_eq!(p.exit_code, 0);
    assert!(p.polls_done > 0 && p.stats_done >= 5 && p.snaps_done >= 4);
    assert!(p.session.contains("invalid epoch"), "epoch: {}", p.session);
    assert!(
        p.session.contains("submit_fail=(unavailable)"),
        "unavailable: {}",
        p.session
    );
    assert_eq!(
        p.events.matches("\"kind\":\"gap\"").count(),
        1,
        "wrap closes with one gap marker"
    );
    assert!(
        p.events.contains("detail closure unproven: invalid epoch"),
        "gap reason: {}",
        p.events
    );
    assert!(
        !p.events.contains("\"kind\":\"counter_snapshot\""),
        "unreadable counters persist no snapshots: {}",
        p.events
    );
    let _ = std::fs::remove_dir_all(&work);
}

#[test]
fn wrap_flags_fail_the_counter_contracts() {
    // The public cut contracts fail closed on every wrap flag: no wrapped
    // cut validates, and no wrapped identity holds.
    let clean = [10u64, 640, 9, 576, 1, 0];
    assert!(count_identity(&clean));
    assert!(byte_identity(&clean));
    assert!(counters_valid(&clean));
    assert!(byte_coverage_valid(&clean));
    assert!(submit_valid(&clean));
    assert!(!all_zero(&clean));
    for (name, flag) in [
        ("observed", 1u64),
        ("observed-bytes", 2),
        ("emitted", 4),
        ("emitted-bytes", 8),
        ("submit", FLAG_SUBMIT_WRAP),
    ] {
        let mut cut = clean.to_vec();
        cut[5] = flag;
        assert!(!counters_valid(&cut), "{name} wrap validates");
        assert!(!byte_coverage_valid(&cut), "{name} wrap covers bytes");
    }
    let mut submit = clean.to_vec();
    submit[5] = FLAG_SUBMIT_WRAP;
    assert!(!submit_valid(&submit), "submit wrap reads");
    assert!(
        !count_identity(&[10, 640, 9, 576, 2, 0]),
        "broken sum holds"
    );
    assert!(
        !count_identity(&[u64::MAX, 0, 1, 0, u64::MAX, 0]),
        "overflowing sum holds"
    );
    assert!(all_zero(&[0, 0, 0, 0, 0, 0]));
}

#[test]
fn wrong_probe_argc_takes_unknown_with_reason() {
    // The lifecycle probe reports an argument-count mismatch (its traced
    // function changed arity): the channel closes unknown with the reason
    // instead of decoding registers under a stale layout.
    let work = workdir("argc");
    let mut kernel = ScriptKernel::new();
    kernel.channels = 2;
    kernel.add_poll(timeout_poll(), 104);
    kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
    kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
    for _ in 0..4 {
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
    }
    kernel.add_stats_at(1, stats_ok(0, 0, 0, 0, 0));
    kernel.add_stats_at(1, stats_ok(0, 0, 0, 0, 0));
    let zero = snap_ok(0, 0, 0, 0, 0, 0);
    kernel.add_snap(zero.clone());
    kernel.add_snap(zero);
    let cut0 = snap_ok(0, 0, 0, 0, 0, 0);
    kernel.add_snap(cut0.clone());
    kernel.add_snap(cut0);
    let zero1 = snap_ok(0, 0, 0, 0, 0, 0);
    kernel.add_snap_at(1, zero1.clone());
    kernel.add_snap_at(1, zero1);
    let cut1 = snap_ok(0, 0, 0, 0, 0, FLAG_ARGCNT);
    kernel.add_snap_at(1, cut1.clone());
    kernel.add_snap_at(1, cut1);
    let dir = work.join("cap");
    let mut cfg = base_config(dir.to_str().unwrap());
    cfg.has_ring_bytes = true;
    cfg.ring_bytes = 8388608;
    cfg.has_lifecycle = true;
    cfg.lifecycle_ring_bytes = 8388608;
    let p = run_probe(&work, &mut kernel, cfg);
    assert_eq!(p.exit_code, 0);
    assert!(p.polls_done > 0 && p.stats_done >= 6 && p.snaps_done >= 8);
    assert!(
        p.session
            .contains("detail loss unknown (lifecycle argument count mismatch"),
        "argc reason: {}",
        p.session
    );
    assert!(
        p.session
            .contains("unknown: lifecycle argument count mismatch"),
        "argc evidence: {}",
        p.session
    );
    assert_eq!(
        p.events.matches("\"kind\":\"counter_snapshot\"").count(),
        4,
        "attempt channel persists four snapshots"
    );
    let _ = std::fs::remove_dir_all(&work);
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn report_top_stream_refusal() {
    // Native equivalent of the stream-creation refusal: a capture whose
    // events path cannot be streamed (fifo, directory) refuses on both
    // verbs with exit 2, empty stdout, and the exact wording.
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_memveil"));
    let src = repo_root().join("tests/fixtures/reader/sealed-complete");
    for kind in ["fifo", "directory"] {
        let work = workdir(kind);
        std::fs::copy(src.join("session.json"), work.join("session.json")).expect("copy session");
        let target = work.join("events.ndjson");
        if kind == "fifo" {
            let path = std::ffi::CString::new(target.to_str().unwrap()).unwrap();
            // SAFETY: mkfifo on a fresh temp path; checked return.
            let rc = unsafe { libc::mkfifo(path.as_ptr(), 0o644) };
            assert_eq!(rc, 0, "mkfifo");
        } else {
            std::fs::create_dir(&target).expect("mkdir events");
        }
        for verb in ["report", "top"] {
            let mut args = vec![verb];
            if verb == "top" {
                args.extend(["--interval", "1s"]);
            }
            args.push(work.to_str().unwrap());
            let out = std::process::Command::new(&bin)
                .args(&args)
                .current_dir(repo_root())
                .output()
                .expect("run verb");
            assert_eq!(out.status.code(), Some(2), "{verb} {kind} exit");
            assert!(out.stdout.is_empty(), "{verb} {kind} stdout");
            assert_eq!(
                out.stderr,
                format!("memveil {verb}: cannot read capture: events.ndjson: input is not a regular file\n")
                    .into_bytes(),
                "{verb} {kind} stderr"
            );
        }
        let _ = std::fs::remove_dir_all(&work);
    }
}
