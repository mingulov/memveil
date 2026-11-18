// SPDX-License-Identifier: GPL-3.0-or-later
//! Tee writer source: persist every line, fold a live analyzer.
//!
//! A WriterSource that forwards every call to an owned LiveWriter and, on
//! success only, decodes the same bytes and feeds the shared composed
//! analyzer. Persist and fold are atomic: when the fold fails, the line is
//! rolled back and the analyzer is rewound to the retained prefix, so live
//! input stays byte-identical to what replay will read. A decode failure is
//! an internal error, never a silent skip.
//!
//! The analyzer runs under a provisional session stamped from the template:
//! the window starts at the first folded event, ends at the event-time
//! horizon, and never claims finalization. Refresh timing is event time, not
//! wall time: a refresh emits when the running maximum event timestamp
//! reaches the interval past the last emission, so quiet periods
//! structurally print nothing and disordered events fold forward without
//! moving the horizon.
//!
//! Printed refreshes are never revised. A group abort rewinds the retained
//! prefix, so the tee rebuilds the analyzer by streaming the retained event
//! bytes in fixed chunks (aborts only happen on the failing closing path, so
//! the rebuild cost never touches clean runs) while the already printed
//! prefix refreshes stand. Emission cadence continues past the abort:
//! horizons already shown are not shown again.
//!
//! The tee never emits a final block: the caller replays the retained
//! capture for the final answer, which keeps the final live block equal to
//! a replay of that capture by construction.

use crate::capture::live::{AppendOut, CreateOut, FinalOut, GroupOut, LiveWriter, WriterSource};
use crate::model::event::{Event, parse_event};
use crate::model::report::Report;
use crate::model::session::Session;
use crate::platform::reader::{LineSink, stream_host_lines};

/// One live refresh consumer: report plus event-time horizon.
///
/// The report moves into the sink: the sink is its final consumer and may
/// diagnose it in place.
pub trait RefreshSink {
    /// Emit one refresh; false refuses the emission.
    fn emit(&mut self, rep: Report, horizon_ns: u64) -> bool;
}

/// The analysis-engine surface the tee folds through.
///
/// The real analyzer implements this trait; the tee only needs construction
/// from a stamped session, event consumption, and horizon snapshots.
pub trait LiveAnalyzer: Sized {
    /// Build an analyzer over the stamped provisional session.
    fn new(session: Session) -> Self;
    /// Fold one event.
    fn consume(&mut self, event: Event) -> Result<(), String>;
    /// Snapshot the fold at `horizon_ns`.
    fn snapshot(&self, horizon_ns: u64, finalized: bool) -> Result<Report, String>;
}

/// Copy line minus one trailing newline, matching the reader.
fn strip_newline(line: &[u8]) -> Vec<u8> {
    if line.last() == Some(&b'\n') {
        line[..line.len() - 1].to_vec()
    } else {
        line.to_vec()
    }
}

/// First rebuild pass: retained minimum, maximum, line count.
struct FloorScan {
    floor_ns: u64,
    horizon_ns: u64,
    lines: usize,
    failure: String,
}

impl FloorScan {
    fn new() -> Self {
        Self {
            floor_ns: u64::MAX,
            horizon_ns: 0,
            lines: 0,
            failure: String::new(),
        }
    }
}

impl LineSink for FloorScan {
    fn feed(&mut self, line: Vec<u8>) -> String {
        let ev = match parse_event(&line) {
            Ok(ev) => ev,
            Err(e) => {
                self.failure = e.to_string();
                return self.failure.clone();
            }
        };
        if ev.ts_ns < self.floor_ns {
            self.floor_ns = ev.ts_ns;
        }
        if ev.ts_ns > self.horizon_ns {
            self.horizon_ns = ev.ts_ns;
        }
        self.lines += 1;
        String::new()
    }
}

/// Second rebuild pass: fold the prefix into a fresh analyzer.
struct Refold<A: LiveAnalyzer> {
    template: Session,
    floor_ns: u64,
    analyzer: Option<A>,
    failure: String,
}

impl<A: LiveAnalyzer> Refold<A> {
    fn new(template: Session, floor_ns: u64) -> Self {
        Self {
            template,
            floor_ns,
            analyzer: None,
            failure: String::new(),
        }
    }

    fn drain(&mut self) -> Option<A> {
        self.analyzer.take()
    }
}

impl<A: LiveAnalyzer> LineSink for Refold<A> {
    fn feed(&mut self, line: Vec<u8>) -> String {
        let ev = match parse_event(&line) {
            Ok(ev) => ev,
            Err(e) => {
                self.failure = e.to_string();
                return self.failure.clone();
            }
        };
        if self.analyzer.is_none() {
            let mut stamped = self.template.clone();
            stamped.window_start_ns = self.floor_ns;
            stamped.window_end_ns = u64::MAX;
            self.analyzer = Some(A::new(stamped));
        }
        if let Some(work) = self.analyzer.as_mut()
            && let Err(e) = work.consume(ev)
        {
            self.failure = e;
            return self.failure.clone();
        }
        String::new()
    }
}

/// WriterSource that persists lines and folds live refreshes.
pub struct TeeWriter<S: RefreshSink, A: LiveAnalyzer> {
    inner: LiveWriter,
    sink: S,
    template: Session,
    interval_ns: u64,
    path: String,
    created: bool,
    analyzer: Option<A>,
    horizon_ns: u64,
    floor_ns: u64,
    last_emit_ns: u64,
    emissions: usize,
}

impl<S: RefreshSink, A: LiveAnalyzer> TeeWriter<S, A> {
    /// A tee over `template` emitting at `interval_ns` event-time cadence.
    pub fn new(template: Session, interval_ns: u64, sink: S) -> Self {
        Self {
            inner: LiveWriter::new(),
            sink,
            template,
            interval_ns,
            path: String::new(),
            created: false,
            analyzer: None,
            horizon_ns: 0,
            floor_ns: 0,
            last_emit_ns: 0,
            emissions: 0,
        }
    }

    /// Refreshes the sink accepted so far.
    pub fn emission_count(&self) -> usize {
        self.emissions
    }

    /// Roll back one persisted line, rewind the analyzer.
    ///
    /// A failed fold must not leave persisted-but-unfolded bytes: the
    /// collector keeps appending closing records after a failure, and
    /// every later refresh must match a replay of the retained file. The
    /// inner mark is a plain offset, so this nests safely inside a caller
    /// group. The original fold error is preserved; only a dead writer or
    /// a failed rewind supersedes it.
    fn undo_append(&mut self, mark: u64, err: AppendOut) -> AppendOut {
        let rolled = self.inner.group_abort(mark);
        if !rolled.ok {
            return rolled;
        }
        let rewound = self.rebuild();
        if !rewound.ok {
            return rewound;
        }
        err
    }

    /// Decode one persisted line, fold it, maybe refresh.
    ///
    /// A refresh at horizon H covers [floor, H): the event at H folds
    /// after the snapshot, matching replay. The first event only
    /// establishes the window; horizons at or below the last emission
    /// never re-emit, so a rewound horizon cannot wrap the unsigned gap.
    fn fold(&mut self, line: &[u8]) -> AppendOut {
        let body = strip_newline(line);
        let ev = match parse_event(&body) {
            Ok(ev) => ev,
            Err(e) => {
                return AppendOut {
                    ok: false,
                    kind: "internal".to_string(),
                    message: e.to_string(),
                };
            }
        };
        if self.analyzer.is_none() {
            let mut stamped = self.template.clone();
            stamped.window_start_ns = ev.ts_ns;
            stamped.window_end_ns = u64::MAX;
            let mut fresh = A::new(stamped);
            self.floor_ns = ev.ts_ns;
            self.horizon_ns = ev.ts_ns;
            self.last_emit_ns = ev.ts_ns;
            if let Err(e) = fresh.consume(ev) {
                self.analyzer = Some(fresh);
                return AppendOut {
                    ok: false,
                    kind: "internal".to_string(),
                    message: e,
                };
            }
            self.analyzer = Some(fresh);
            return AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            };
        }
        let mut horizon = self.horizon_ns;
        if ev.ts_ns > horizon {
            horizon = ev.ts_ns;
        }
        if horizon > self.last_emit_ns && horizon - self.last_emit_ns >= self.interval_ns {
            let snap = match self.analyzer.as_ref() {
                Some(shown) => shown.snapshot(horizon, false),
                None => {
                    return AppendOut {
                        ok: false,
                        kind: "internal".to_string(),
                        message: "missing analyzer".to_string(),
                    };
                }
            };
            let snap = match snap {
                Ok(snap) => snap,
                Err(e) => {
                    return AppendOut {
                        ok: false,
                        kind: "internal".to_string(),
                        message: e,
                    };
                }
            };
            if !self.sink.emit(snap, horizon) {
                return AppendOut {
                    ok: false,
                    kind: "internal".to_string(),
                    message: "refresh sink refused".to_string(),
                };
            }
            self.last_emit_ns = horizon;
            self.emissions += 1;
        }
        self.horizon_ns = horizon;
        if ev.ts_ns < self.floor_ns {
            // Below the stamped floor: refold the retained prefix with
            // the floor lowered to the retained minimum, so nothing
            // counts below the window.
            return self.rebuild();
        }
        match self.analyzer.as_mut() {
            Some(work) => match work.consume(ev) {
                Ok(()) => AppendOut {
                    ok: true,
                    kind: String::new(),
                    message: String::new(),
                },
                Err(e) => AppendOut {
                    ok: false,
                    kind: "internal".to_string(),
                    message: e,
                },
            },
            None => AppendOut {
                ok: false,
                kind: "internal".to_string(),
                message: "missing analyzer".to_string(),
            },
        }
    }

    /// Refold the retained prefix after a group abort.
    ///
    /// Streams the event file the inner writer owns in fixed 64 KiB
    /// chunks, twice: once for the retained minimum and maximum, once to
    /// fold the prefix into a fresh analyzer. The file is never held
    /// whole, so a large retained capture cannot exhaust memory on the
    /// abort path. The window floor is the retained minimum, never the
    /// first arrival. The emission cadence keeps its place: shown
    /// horizons stand.
    fn rebuild(&mut self) -> AppendOut {
        if !self.created || self.inner.committed_len() == 0 {
            self.analyzer = None;
            self.horizon_ns = 0;
            self.floor_ns = 0;
            return AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            };
        }
        let events_path = format!("{}/events.ndjson", self.path);
        let bound = self.inner.committed_len() as usize;
        let mut scan = FloorScan::new();
        if let Err(e) = stream_host_lines(&events_path, "events", bound, &mut scan) {
            return AppendOut {
                ok: false,
                kind: "internal".to_string(),
                message: e.to_string(),
            };
        }
        if !scan.failure.is_empty() {
            return AppendOut {
                ok: false,
                kind: "internal".to_string(),
                message: scan.failure,
            };
        }
        if scan.lines == 0 {
            self.analyzer = None;
            self.horizon_ns = 0;
            self.floor_ns = 0;
            return AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            };
        }
        let mut refold = Refold::<A>::new(self.template.clone(), scan.floor_ns);
        if let Err(e) = stream_host_lines(&events_path, "events", bound, &mut refold) {
            return AppendOut {
                ok: false,
                kind: "internal".to_string(),
                message: e.to_string(),
            };
        }
        if !refold.failure.is_empty() {
            return AppendOut {
                ok: false,
                kind: "internal".to_string(),
                message: refold.failure,
            };
        }
        match refold.drain() {
            Some(rebuilt) => self.analyzer = Some(rebuilt),
            None => {
                return AppendOut {
                    ok: false,
                    kind: "internal".to_string(),
                    message: "rebuild folded nothing".to_string(),
                };
            }
        }
        self.horizon_ns = scan.horizon_ns;
        self.floor_ns = scan.floor_ns;
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }
}

impl<S: RefreshSink, A: LiveAnalyzer> WriterSource for TeeWriter<S, A> {
    fn create(&mut self, path: &str, budget: u64) -> CreateOut {
        let out = self.inner.create(path, budget);
        if out.ok {
            self.path = path.to_string();
            self.created = true;
        }
        out
    }

    fn append(&mut self, line: &[u8]) -> AppendOut {
        let mark = self.inner.committed_len();
        let out = self.inner.append(line);
        if !out.ok {
            return out;
        }
        let folded = self.fold(line);
        if folded.ok {
            return folded;
        }
        self.undo_append(mark, folded)
    }

    fn append_closing(&mut self, line: &[u8]) -> AppendOut {
        let mark = self.inner.committed_len();
        let out = self.inner.append_closing(line);
        if !out.ok {
            return out;
        }
        let folded = self.fold(line);
        if folded.ok {
            return folded;
        }
        self.undo_append(mark, folded)
    }

    fn group_begin(&mut self) -> GroupOut {
        self.inner.group_begin()
    }

    fn group_abort(&mut self, mark: u64) -> AppendOut {
        let out = self.inner.group_abort(mark);
        if !out.ok {
            return out;
        }
        self.rebuild()
    }

    fn checkpoint(&mut self, session: &[u8]) -> AppendOut {
        self.inner.checkpoint(session)
    }

    fn finalize(&mut self, session: &[u8]) -> FinalOut {
        self.inner.finalize(session)
    }

    fn abandon(&mut self) -> String {
        self.inner.abandon()
    }

    fn discard(&mut self) {
        self.inner.discard();
    }

    fn committed_len(&self) -> u64 {
        self.inner.committed_len()
    }

    fn finalized_identity(&self) -> Vec<u64> {
        self.inner.finalized_identity()
    }
}

#[cfg(test)]
mod tests {
    use super::{LiveAnalyzer, RefreshSink, TeeWriter};
    use crate::capture::live::WriterSource;
    use crate::model::encode::encode_event_line;
    use crate::model::event::{Event, parse_event};
    use crate::model::metric::Metric;
    use crate::model::report::Report;
    use crate::model::session::Session;
    use crate::platform::test_support::TestDir;
    use std::path::PathBuf;

    /// Recording analyzer: the fold is its consume sequence plus the floor.
    struct StubAnalyzer {
        floor: u64,
        consumed: Vec<(String, u64, u64)>,
    }

    impl LiveAnalyzer for StubAnalyzer {
        fn new(session: Session) -> Self {
            Self {
                floor: session.window_start_ns,
                consumed: Vec::new(),
            }
        }

        fn consume(&mut self, event: Event) -> Result<(), String> {
            self.consumed
                .push((event.kind.clone(), event.seq, event.ts_ns));
            Ok(())
        }

        fn snapshot(&self, horizon_ns: u64, finalized: bool) -> Result<Report, String> {
            let mut rep = Report {
                window_start_ns: self.floor,
                window_end_ns: horizon_ns,
                session_id: format!("finalized={finalized}"),
                ..Default::default()
            };
            for (kind, seq, ts) in &self.consumed {
                rep.metrics.push(Metric {
                    name: kind.clone(),
                    has_value: true,
                    value: *seq,
                    unit: format!("ts={ts}"),
                    measurement: String::new(),
                    coverage: String::new(),
                    confidence: "high".to_string(),
                    has_aggregation: false,
                    aggregation: String::new(),
                    has_sample_count: false,
                    sample_count: 0,
                    has_device_id: false,
                    device_id: String::new(),
                    has_pool_id: false,
                    pool_id: String::new(),
                    scope: String::new(),
                    notes: String::new(),
                });
            }
            Ok(rep)
        }
    }

    /// Analyzer whose consume always fails.
    struct FailingAnalyzer;

    impl LiveAnalyzer for FailingAnalyzer {
        fn new(_session: Session) -> Self {
            Self
        }

        fn consume(&mut self, _event: Event) -> Result<(), String> {
            Err("stub consume refused".to_string())
        }

        fn snapshot(&self, _horizon_ns: u64, _finalized: bool) -> Result<Report, String> {
            Ok(Report::default())
        }
    }

    /// Analyzer whose snapshot always fails.
    struct SnapshotFailAnalyzer {
        consumed: u64,
    }

    impl LiveAnalyzer for SnapshotFailAnalyzer {
        fn new(_session: Session) -> Self {
            Self { consumed: 0 }
        }

        fn consume(&mut self, _event: Event) -> Result<(), String> {
            self.consumed += 1;
            Ok(())
        }

        fn snapshot(&self, _horizon_ns: u64, _finalized: bool) -> Result<Report, String> {
            Err("stub snapshot refused".to_string())
        }
    }

    /// RefreshSink that records horizon plus digest per line.
    struct ScriptFileSink {
        path: PathBuf,
    }

    impl ScriptFileSink {
        fn new(path: PathBuf) -> Self {
            Self { path }
        }
    }

    impl RefreshSink for ScriptFileSink {
        fn emit(&mut self, rep: Report, horizon_ns: u64) -> bool {
            let record = format!("{horizon_ns} {}\n", digest(&rep, horizon_ns));
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(record.as_bytes())
                })
                .is_ok()
        }
    }

    /// Records refreshes but refuses the first emission.
    struct RefuseOnceSink {
        path: PathBuf,
        refused: bool,
    }

    impl RefreshSink for RefuseOnceSink {
        fn emit(&mut self, rep: Report, horizon_ns: u64) -> bool {
            if !self.refused {
                self.refused = true;
                drop(rep);
                return false;
            }
            let record = format!("{horizon_ns} {}\n", digest(&rep, horizon_ns));
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .and_then(|mut f| {
                    use std::io::Write;
                    f.write_all(record.as_bytes())
                })
                .is_ok()
        }
    }

    fn digest(rep: &Report, horizon: u64) -> String {
        let mut d = format!("w={} h={} ", rep.window_start_ns, horizon);
        for m in &rep.metrics {
            d.push_str(&format!("{}|{}={};", m.name, m.unit, m.value));
        }
        d.push_str(&format!("fin={}", rep.session_id));
        d
    }

    fn tee_base(kind: &str, seq: u64, ts: u64) -> Event {
        Event {
            session_id: "teeprobe".to_string(),
            seq,
            ts_ns: ts,
            kind: kind.to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ..Default::default()
        }
    }

    fn tee_attempt(op: &str, seq: u64, ts: u64) -> Event {
        let mut ev = tee_base("bounce_attempt", seq, ts);
        ev.bounce.device_id = "d1".to_string();
        ev.bounce.requested_bytes = 4096;
        ev.bounce.operation_id = op.to_string();
        ev
    }

    fn tee_line(ev: &Event) -> Vec<u8> {
        encode_event_line(ev).expect("encode tee event")
    }

    fn tee_map(op: &str, mapping: &str, ts: u64, seq: u64) -> Event {
        let mut ev = tee_base("map_result", seq, ts);
        ev.map_result.operation_id = op.to_string();
        ev.map_result.success = true;
        ev.map_result.has_mapping_id = true;
        ev.map_result.mapping_id = mapping.to_string();
        ev.map_result.has_mapped_bytes = true;
        ev.map_result.mapped_bytes = 4096;
        ev
    }

    fn tee_copy(op: &str, n: u64, ts: u64, seq: u64) -> Event {
        let mut ev = tee_base("copy", seq, ts);
        ev.copy.operation_id = op.to_string();
        ev.copy.direction = "original_to_bounce".to_string();
        ev.copy.bytes = n;
        ev
    }

    fn tee_unmap(mapping: &str, ts: u64, seq: u64) -> Event {
        let mut ev = tee_base("unmap", seq, ts);
        ev.unmap.has_mapping_id = true;
        ev.unmap.mapping_id = mapping.to_string();
        ev
    }

    fn tee_pool_unavailable(pool: &str, ts: u64, seq: u64, reason: &str) -> Event {
        let mut ev = tee_base("pool_sample", seq, ts);
        ev.pool.pool_id = pool.to_string();
        ev.pool.unit = "bytes".to_string();
        ev.pool.allocator = "swiotlb".to_string();
        ev.pool.reason = reason.to_string();
        ev
    }

    fn tee_gap(ts: u64, seq: u64) -> Event {
        let mut ev = tee_base("gap", seq, ts);
        ev.gap.channel = "detail".to_string();
        ev.gap.has_lost_count = true;
        ev.gap.lost_count = 3;
        ev.gap.reason = "scripted cut".to_string();
        ev.gap.window_start_ns = 100;
        ev.gap.window_end_ns = ts;
        ev
    }

    fn tee_pool(pool: &str, used: u64, cap: u64, ts: u64, seq: u64) -> Event {
        let mut ev = tee_base("pool_sample", seq, ts);
        ev.pool.pool_id = pool.to_string();
        ev.pool.has_used = true;
        ev.pool.used_bytes = used;
        ev.pool.has_capacity = true;
        ev.pool.capacity_bytes = cap;
        ev.pool.unit = "bytes".to_string();
        ev
    }

    fn tee_template() -> Session {
        let mut s = Session {
            session_id: "teeprobe".to_string(),
            synthetic: true,
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "live".to_string(),
            ..Default::default()
        };
        for q in [
            &mut s.q_detail,
            &mut s.q_aggregate,
            &mut s.q_correlation,
            &mut s.q_terminal,
        ] {
            q.status = "complete_for_scope".to_string();
            q.has_loss_count = true;
            q.scope = "sc".to_string();
            q.reason = "rs".to_string();
        }
        s.q_baseline.status = "not_applicable".to_string();
        s.q_baseline.scope = "sc".to_string();
        s.q_baseline.reason = "rs".to_string();
        s
    }

    fn stripped(line: &[u8]) -> Vec<u8> {
        if line.last() == Some(&0x0A) {
            line[..line.len() - 1].to_vec()
        } else {
            line.to_vec()
        }
    }

    /// Digest of folding lines directly: the replay oracle.
    fn tee_direct(template: &Session, first_ts: u64, lines: &[Vec<u8>], horizon: u64) -> String {
        let mut s = template.clone();
        s.window_start_ns = first_ts;
        s.window_end_ns = u64::MAX;
        let mut a = StubAnalyzer::new(s);
        for line in lines {
            let ev = parse_event(&stripped(line)).expect("oracle parses");
            a.consume(ev).expect("oracle consumes");
        }
        let rep = a.snapshot(horizon, false).expect("oracle snapshots");
        digest(&rep, horizon)
    }

    fn tee_new(obs: PathBuf) -> TeeWriter<ScriptFileSink, StubAnalyzer> {
        TeeWriter::new(tee_template(), 50, ScriptFileSink::new(obs))
    }

    fn tee_with(
        tmpl: Session,
        interval: u64,
        obs: PathBuf,
    ) -> TeeWriter<ScriptFileSink, StubAnalyzer> {
        TeeWriter::new(tmpl, interval, ScriptFileSink::new(obs))
    }

    fn scratch() -> TestDir {
        TestDir::create("memveil-tee").expect("mkdtemp")
    }

    fn raw_line(text: &str) -> Vec<u8> {
        [text.as_bytes(), b"\n"].concat()
    }

    #[test]
    fn forwards_bytes_identical() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut tee = tee_new(tmp.path().join("obs.ndjson"));
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 120));
        let l2 = tee_line(&tee_attempt("op3", 2, 200));
        assert!(tee.append(&l0).ok);
        assert!(tee.append(&l1).ok);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.committed_len(), (l0.len() + l1.len() + l2.len()) as u64);
        let events = std::fs::read(target.join("events.ndjson")).expect("events");
        assert_eq!(events, [l0, l1, l2].concat());
    }

    #[test]
    fn misuse_before_create() {
        let tmp = scratch();
        let mut tee = tee_new(tmp.path().join("obs.ndjson"));
        let line = tee_line(&tee_attempt("op1", 0, 100));
        assert!(!tee.append(&line).ok);
        assert!(!tee.append_closing(&line).ok);
        assert!(!tee.group_begin().ok);
        assert!(!tee.group_abort(0).ok);
        assert_eq!(tee.finalize(&raw_line("{}")).status, "unfinalized");
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        assert_eq!(tee.committed_len(), 0);
    }

    #[test]
    fn first_data_establishes_silently() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let mut tee = tee_new(obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        assert!(tee.append(&tee_line(&tee_attempt("op1", 0, 100))).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(!obs.exists());
    }

    #[test]
    fn interval_gates_refresh() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 120));
        let l2 = tee_line(&tee_attempt("op3", 2, 200));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!("200 {}\n", tee_direct(&tmpl, 100, &[l0, l1], 200));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn decode_failure_is_loud() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let obs = tmp.path().join("obs.ndjson");
        let mut tee = tee_new(obs.clone());
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let out = tee.append(&raw_line("not json{"));
        assert!(!out.ok);
        assert_eq!(out.kind, "internal");
        assert_eq!(tee.committed_len(), 0);
        assert_eq!(
            std::fs::read(target.join("events.ndjson")).expect("events"),
            b""
        );
        assert!(!obs.exists());
    }

    #[test]
    fn sink_failure_is_loud() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut tee = tee_new(tmp.path().join("no-such-dir/obs.ndjson"));
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        assert!(tee.append(&l0).ok);
        let l1 = tee_line(&tee_attempt("op2", 1, 200));
        let out = tee.append(&l1);
        assert!(!out.ok);
        assert_eq!(out.kind, "internal");
        assert_eq!(
            std::fs::read(target.join("events.ndjson")).expect("events"),
            l0
        );
    }

    #[test]
    fn disorder_folds_forward_only() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 60));
        let l2 = tee_line(&tee_attempt("op3", 2, 160));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!("160 {}\n", tee_direct(&tmpl, 60, &[l0, l1], 160));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn same_reducer_mixed_kinds() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_map("op1", "m1", 110, 1));
        let l2 = tee_line(&tee_copy("op1", 4096, 120, 2));
        let l3 = tee_line(&tee_unmap("m1", 130, 3));
        let l4 = tee_line(&tee_pool("p", 10, 100, 140, 4));
        let l5 = tee_line(&tee_attempt("op2", 5, 200));
        for l in [&l0, &l1, &l2, &l3, &l4] {
            assert!(tee.append(l).ok);
        }
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l5).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, &[l0, l1, l2, l3, l4], 200)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn closing_lines_fold() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 200));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append_closing(&l1).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn group_abort_rebuilds_prefix() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 120));
        let l2 = tee_line(&tee_attempt("op3", 2, 200));
        let l3 = tee_line(&tee_attempt("op4", 3, 260));
        assert!(tee.append(&l0).ok);
        assert!(tee.append(&l1).ok);
        let begun = tee.group_begin();
        assert!(begun.ok);
        assert!(tee.append(&l2).ok);
        assert!(tee.group_abort(begun.mark).ok);
        assert!(tee.append(&l3).ok);
        assert_eq!(tee.emission_count(), 2);
        let rec0 = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, &[l0.clone(), l1.clone()], 200)
        );
        let rec1 = format!("260 {}\n", tee_direct(&tmpl, 100, &[l0, l1], 260));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), rec0 + &rec1);
        let events = std::fs::read(target.join("events.ndjson")).expect("events");
        assert_eq!(events.len() as u64, tee.committed_len());
        let file_text = String::from_utf8(events).expect("utf8");
        let l2_text = String::from_utf8(l2).expect("utf8");
        assert!(!file_text.contains(&l2_text));
    }

    #[test]
    fn abort_all_restarts_clean() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 200));
        let l2 = tee_line(&tee_attempt("op3", 2, 300));
        let begun = tee.group_begin();
        assert!(begun.ok);
        assert!(tee.append(&l0).ok);
        assert!(tee.append(&l1).ok);
        assert!(tee.group_abort(begun.mark).ok);
        assert_eq!(tee.committed_len(), 0);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 1);
        let rec0 = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), rec0);
        let events = std::fs::read(target.join("events.ndjson")).expect("events");
        assert_eq!(events.len() as u64, tee.committed_len());
    }

    #[test]
    fn refresh_excludes_boundary_event() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 200));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn rewound_horizon_never_reemits() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 200));
        let l2 = tee_line(&tee_attempt("op3", 1, 150));
        let l3 = tee_line(&tee_attempt("op4", 2, 300));
        assert!(tee.append(&l0).ok);
        let begun = tee.group_begin();
        assert!(begun.ok);
        assert!(tee.append(&l1).ok);
        assert!(tee.group_abort(begun.mark).ok);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 1);
        assert!(tee.append(&l3).ok);
        assert_eq!(tee.emission_count(), 2);
        let rec0 = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        let rec1 = format!("300 {}\n", tee_direct(&tmpl, 100, &[l0, l2], 300));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), rec0 + &rec1);
    }

    #[test]
    fn below_floor_restamps_window() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_attempt("op2", 1, 60));
        let l2 = tee_line(&tee_attempt("op3", 2, 200));
        assert!(tee.append(&l0).ok);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!("200 {}\n", tee_direct(&tmpl, 60, &[l0, l1], 200));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn rebuild_streams_large_prefix() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 1_000_000_000_000, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 134217728)
                .ok
        );
        let mut kept = Vec::new();
        for i in 0..2000u64 {
            let line = tee_line(&tee_attempt(&format!("op{i}"), i, 1000 + i));
            kept.push(line.clone());
            assert!(tee.append(&line).ok);
        }
        let begun = tee.group_begin();
        assert!(begun.ok);
        assert!(tee.append(&tee_line(&tee_attempt("opx", 2000, 5000))).ok);
        assert!(tee.group_abort(begun.mark).ok);
        let probe = tee_line(&tee_attempt("probe", 2001, 2_000_000_000_000));
        assert!(tee.append(&probe).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!(
            "2000000000000 {}\n",
            tee_direct(&tmpl, 1000, &kept, 2_000_000_000_000)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn failed_fold_rolls_back_bytes() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 134217728)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op0", 0, 1000));
        let l1 = tee_line(&tee_attempt("op1", 1, 1010));
        assert!(tee.append(&l0).ok);
        assert!(tee.append(&l1).ok);
        let before = tee.committed_len();
        let failed = tee.append(b"{oops}\n");
        assert!(!failed.ok);
        assert_eq!(failed.kind, "internal");
        assert_eq!(tee.committed_len(), before);
        let events = std::fs::read(tmp.path().join("cap/events.ndjson")).expect("events");
        assert_eq!(events, [l0.clone(), l1.clone()].concat());
        let probe = tee_line(&tee_attempt("op2", 2, 2000));
        assert!(tee.append(&probe).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!("2000 {}\n", tee_direct(&tmpl, 1000, &[l0, l1], 2000));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn refused_refresh_rolls_back_line() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = TeeWriter::<RefuseOnceSink, StubAnalyzer>::new(
            tmpl.clone(),
            50,
            RefuseOnceSink {
                path: obs.clone(),
                refused: false,
            },
        );
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 134217728)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op0", 0, 1000));
        let l1 = tee_line(&tee_attempt("op1", 1, 1200));
        assert!(tee.append(&l0).ok);
        let before = tee.committed_len();
        let refused = tee.append(&l1);
        assert!(!refused.ok);
        assert_eq!(refused.kind, "internal");
        assert_eq!(tee.committed_len(), before);
        assert_eq!(
            std::fs::read(tmp.path().join("cap/events.ndjson")).expect("events"),
            l0
        );
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 1);
        let want = format!(
            "1200 {}\n",
            tee_direct(&tmpl, 1000, std::slice::from_ref(&l0), 1200)
        );
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), want);
    }

    #[test]
    fn empty_emits_nothing() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let mut tee = tee_with(tee_template(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        tee.discard();
        assert_eq!(tee.emission_count(), 0);
        assert!(!obs.exists());
    }

    #[test]
    fn unavailable_pool_matches_offline() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_pool_unavailable("p", 200, 1, "denied"));
        let l2 = tee_line(&tee_attempt("op2", 2, 300));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 1);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 2);
        let rec0 = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        let rec1 = format!("300 {}\n", tee_direct(&tmpl, 100, &[l0, l1], 300));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), rec0 + &rec1);
    }

    #[test]
    fn loss_matches_offline() {
        let tmp = scratch();
        let obs = tmp.path().join("obs.ndjson");
        let tmpl = tee_template();
        let mut tee = tee_with(tmpl.clone(), 50, obs.clone());
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        let l0 = tee_line(&tee_attempt("op1", 0, 100));
        let l1 = tee_line(&tee_gap(200, 1));
        let l2 = tee_line(&tee_attempt("op2", 2, 300));
        assert!(tee.append(&l0).ok);
        assert_eq!(tee.emission_count(), 0);
        assert!(tee.append(&l1).ok);
        assert_eq!(tee.emission_count(), 1);
        assert!(tee.append(&l2).ok);
        assert_eq!(tee.emission_count(), 2);
        let rec0 = format!(
            "200 {}\n",
            tee_direct(&tmpl, 100, std::slice::from_ref(&l0), 200)
        );
        let rec1 = format!("300 {}\n", tee_direct(&tmpl, 100, &[l0, l1], 300));
        assert_eq!(std::fs::read_to_string(&obs).expect("obs"), rec0 + &rec1);
    }

    #[test]
    fn consume_failure_rolls_back_line() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut tee = TeeWriter::<ScriptFileSink, FailingAnalyzer>::new(
            tee_template(),
            50,
            ScriptFileSink::new(tmp.path().join("obs.ndjson")),
        );
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        let out = tee.append(&tee_line(&tee_attempt("op1", 0, 100)));
        assert!(!out.ok);
        assert_eq!(out.kind, "internal");
        assert_eq!(tee.committed_len(), 0);
        assert_eq!(
            std::fs::read(target.join("events.ndjson")).expect("events"),
            b""
        );
    }

    #[test]
    fn snapshot_failure_is_loud() {
        let tmp = scratch();
        let mut tee = TeeWriter::<ScriptFileSink, SnapshotFailAnalyzer>::new(
            tee_template(),
            50,
            ScriptFileSink::new(tmp.path().join("obs.ndjson")),
        );
        assert!(
            tee.create(tmp.path().join("cap").to_str().unwrap(), 131072)
                .ok
        );
        assert!(tee.append(&tee_line(&tee_attempt("op1", 0, 100))).ok);
        let out = tee.append(&tee_line(&tee_attempt("op2", 1, 200)));
        assert!(!out.ok);
        assert_eq!(out.kind, "internal");
        assert_eq!(tee.emission_count(), 0);
    }

    #[test]
    fn tee_checkpoint_and_finalize_forward() {
        let tmp = scratch();
        let target = tmp.path().join("cap");
        let mut tee = tee_new(tmp.path().join("obs.ndjson"));
        assert!(tee.create(target.to_str().unwrap(), 131072).ok);
        assert!(tee.append(&tee_line(&tee_attempt("op1", 0, 100))).ok);
        assert!(tee.checkpoint(b"ckpt").ok);
        assert_eq!(
            std::fs::read(target.join("checkpoint.json")).expect("ckpt"),
            b"ckpt"
        );
        let fin = tee.finalize(&raw_line("{}"));
        assert_eq!(fin.status, "finalized");
        assert_eq!(tee.finalized_identity().len(), 6);
    }
}
