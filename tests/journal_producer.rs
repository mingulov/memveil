// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal producer: native source, caller handling, profile
//! admission, collector orchestration, and the CLI refusal matrix.
//!
//! Port of the Mojo-era producer checks (`test_journal_callers`,
//! `test_journal_collection`, `test_producer.py`, `test_cli.py`) against
//! the Rust journal producer. Every leg is offline: the native
//! [`JournalKernel`] implementation is exercised through closed-state
//! and refused-open legs plus typed injection of a scripted source,
//! never through a live load/attach (real verifier/load/attach
//! stays lease-gated for final integration). The Aya program's
//! wire layout is pinned byte-for-byte against the carried C
//! header by
//! `tests/journal/producer_reference.py`, which consumes the corpus
//! this suite dumps (see `dump_wire_corpus`).

use memveil::capture::collector::{
    ClockSource, Collector, CollectorConfig, EXIT_ERROR, GeomOut, KernelSource, MAP_TYPE_ARRAY,
    MAP_TYPE_RINGBUF, MissOut, PollOut, SignalSource, SnapOut, StatsOut,
};
use memveil::capture::journal_callers::{CallerRange, encode_caller_range, resolve_caller_ranges};
use memveil::capture::journal_capture::{
    JOURNAL_NATIVE_COUNTERS, JournalCapture, JournalCounters, JournalKernel, JournalPoll,
    encode_journal_control,
};
use memveil::capture::journal_kernel::{
    JournalKernel as NativeJournalKernel, journal_attach_specs,
};
use memveil::capture::live::{AppendOut, CreateOut, FinalOut, GroupOut, WriterSource};
use memveil::capture::run::{
    RecordOptions, decide_record, parse_requested_caps, run_collector_with,
};
use memveil::model::event::parse_event;
use memveil::model::journal::select_journal;
use memveil::model::session::parse_session;
use memveil::platform::evidence::KernelInfo;
use memveil::platform::journal_profile::{
    JOURNAL_CANDIDATE_ID, JournalDiscoveryFailure, discover_journal_binding,
};
use memveil::platform::narrow::MV_OFFSETS_TABLE_LEN;
use memveil::platform::outcome::OpOut;
use memveil::platform::profiles::load_profiles;
use memveil::platform::signal::SignalOut;
use std::path::PathBuf;

fn ok_out() -> OpOut {
    OpOut {
        ok: true,
        message: String::new(),
    }
}

/// Scripted kernel recording every call; the journal-only leg must
/// leave it untouched.
struct ScriptKernel {
    calls: Vec<String>,
}

impl ScriptKernel {
    fn new() -> Self {
        Self { calls: Vec::new() }
    }
}

impl KernelSource for ScriptKernel {
    fn open_session(&mut self) -> OpOut {
        self.calls.push("open".to_string());
        ok_out()
    }

    fn load(&mut self) -> OpOut {
        self.calls.push("load".to_string());
        ok_out()
    }

    fn map_info(&mut self, name: &str) -> GeomOut {
        self.calls.push("map_info".to_string());
        // Admitted attempt-channel geometry, so a mixed
        // ordinary/journal run passes startup. Journal-only
        // legs never reach the kernel, so they observe no
        // change.
        let geom = match name {
            "mv_counts" => Some((MAP_TYPE_ARRAY, 4, 8, 6)),
            "mv_attempts" => Some((MAP_TYPE_RINGBUF, 0, 0, 0)),
            "mv_offsets" => Some((MAP_TYPE_ARRAY, 4, MV_OFFSETS_TABLE_LEN as u32, 1)),
            _ => None,
        };
        match geom {
            Some((map_type, key_size, value_size, max_entries)) => GeomOut {
                ok: true,
                map_type,
                key_size,
                value_size,
                max_entries,
                message: String::new(),
            },
            None => GeomOut {
                ok: false,
                map_type: 0,
                key_size: 0,
                value_size: 0,
                max_entries: 0,
                message: "scripted".to_string(),
            },
        }
    }

    fn map_info_at(&mut self, _channel: i64, _name: &str) -> GeomOut {
        self.calls.push("map_info_at".to_string());
        GeomOut {
            ok: false,
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            message: "scripted".to_string(),
        }
    }

    fn install_offsets(&mut self, _table: &[u8]) -> OpOut {
        self.calls.push("install_offsets".to_string());
        ok_out()
    }

    fn attach(&mut self) -> OpOut {
        self.calls.push("attach".to_string());
        ok_out()
    }

    fn set_copy_armed(&mut self, _armed: bool) -> OpOut {
        self.calls.push("set_copy_armed".to_string());
        ok_out()
    }

    fn poll(&mut self, _timeout_ms: i64, _capacity: u32) -> PollOut {
        self.calls.push("poll".to_string());
        PollOut {
            kind: "timeout".to_string(),
            frame: Vec::new(),
            required: 0,
            message: String::new(),
        }
    }

    fn stats(&mut self) -> StatsOut {
        self.calls.push("stats".to_string());
        StatsOut {
            ok: true,
            received: 0,
            delivered: 0,
            staged: 0,
            malformed: 0,
            dropped: 0,
            message: String::new(),
        }
    }

    fn stats_at(&mut self, _channel: i64) -> StatsOut {
        self.calls.push("stats_at".to_string());
        self.stats()
    }

    fn read_full(&mut self) -> SnapOut {
        self.calls.push("read_full".to_string());
        SnapOut {
            ok: true,
            vals: vec![0, 0, 0, 0, 0, 0],
            message: String::new(),
        }
    }

    fn read_full_at(&mut self, _channel: i64) -> SnapOut {
        self.calls.push("read_full_at".to_string());
        self.read_full()
    }

    fn channel_count(&self) -> i64 {
        1
    }

    fn detach(&mut self) -> OpOut {
        self.calls.push("detach".to_string());
        ok_out()
    }

    fn recursion_misses(&mut self) -> MissOut {
        self.calls.push("recursion_misses".to_string());
        MissOut {
            ok: true,
            count: 0,
            message: String::new(),
            attempt: 0,
            has_copy_detail: false,
            bounce: 0,
            exit_misses: 0,
            sync_device: 0,
            sync_cpu: 0,
            lc_map: 0,
            lc_unmap: 0,
            deferred: 0,
            recovered: 0,
            detail_error: String::new(),
        }
    }

    fn close(&mut self) -> OpOut {
        self.calls.push("close".to_string());
        ok_out()
    }
}

/// Scripted monotonic clock.
struct ScriptClock {
    now_ns: u64,
    step: u64,
}

impl ScriptClock {
    fn new(start: u64, step: u64) -> Self {
        Self {
            now_ns: start,
            step,
        }
    }
}

impl ClockSource for ScriptClock {
    fn now(&mut self) -> u64 {
        let out = self.now_ns;
        self.now_ns = self.now_ns.saturating_add(self.step);
        out
    }

    fn sleep_ms(&mut self, _ms: i64) {}
}

/// Scripted signal source: never pending.
struct ScriptSignal;

impl SignalSource for ScriptSignal {
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

/// Recording writer: keeps every line, checkpoint, and the final
/// session for assertions.
struct MemWriter {
    lines: Vec<Vec<u8>>,
    checkpoints: Vec<Vec<u8>>,
    session_bytes: Vec<u8>,
    finalized: bool,
    committed: u64,
    /// 1-based append ordinal that fails fatal; 0 never fails.
    fail_append_at: u64,
    /// Total append/append_closing calls observed.
    appends: u64,
    /// Discard calls observed.
    discards: u64,
}

impl MemWriter {
    fn new() -> Self {
        Self {
            lines: Vec::new(),
            checkpoints: Vec::new(),
            session_bytes: Vec::new(),
            finalized: false,
            committed: 0,
            fail_append_at: 0,
            appends: 0,
            discards: 0,
        }
    }
}

impl WriterSource for MemWriter {
    fn create(&mut self, _path: &str, _budget: u64) -> CreateOut {
        CreateOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn append(&mut self, line: &[u8]) -> AppendOut {
        self.appends += 1;
        if self.fail_append_at != 0 && self.appends == self.fail_append_at {
            return AppendOut {
                ok: false,
                kind: "fatal".to_string(),
                message: "scripted close-drain fault".to_string(),
            };
        }
        self.lines.push(line.to_vec());
        self.committed += line.len() as u64;
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn append_closing(&mut self, line: &[u8]) -> AppendOut {
        self.append(line)
    }

    fn group_begin(&mut self) -> GroupOut {
        GroupOut {
            ok: true,
            mark: self.committed,
            kind: String::new(),
        }
    }

    fn group_abort(&mut self, mark: u64) -> AppendOut {
        self.committed = mark;
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn checkpoint(&mut self, session: &[u8]) -> AppendOut {
        self.checkpoints.push(session.to_vec());
        AppendOut {
            ok: true,
            kind: String::new(),
            message: String::new(),
        }
    }

    fn finalize(&mut self, session: &[u8]) -> FinalOut {
        self.session_bytes = session.to_vec();
        self.finalized = true;
        FinalOut {
            status: "finalized".to_string(),
            note: String::new(),
        }
    }

    fn abandon(&mut self) -> String {
        String::new()
    }

    fn discard(&mut self) {
        self.discards += 1;
    }

    fn committed_len(&self) -> u64 {
        self.committed
    }

    fn finalized_identity(&self) -> Vec<u64> {
        Vec::new()
    }
}

/// Scripted journal source: records its call order, emits one
/// matched wire record while admission stays open, and reports
/// fixed native counters. Typed offline injection only: no BPF,
/// no privileges.
struct JournalFixture {
    control_bytes: Vec<u8>,
    calls: Vec<String>,
    sent: bool,
    attach_fail: bool,
    read_fail: bool,
}

impl JournalFixture {
    fn new() -> Self {
        Self {
            control_bytes: Vec::new(),
            calls: Vec::new(),
            sent: false,
            attach_fail: false,
            read_fail: false,
        }
    }

    fn control_u64(&self, offset: usize) -> u64 {
        let mut value: u64 = 0;
        for i in 0..8 {
            value |= u64::from(self.control_bytes[offset + i]) << (8 * i);
        }
        value
    }
}

impl JournalKernel for JournalFixture {
    fn prepare(&mut self, control: &[u8]) -> OpOut {
        self.calls.push("prepare".to_string());
        self.control_bytes = control.to_vec();
        ok_out()
    }

    fn attach(&mut self) -> OpOut {
        self.calls.push("attach".to_string());
        OpOut {
            ok: !self.attach_fail,
            message: if self.attach_fail {
                "scripted attach".to_string()
            } else {
                String::new()
            },
        }
    }

    fn control(&mut self, value: &[u8]) -> OpOut {
        let open = value.len() == 48 && value[24] == 1;
        self.calls.push(if open {
            "open".to_string()
        } else {
            "close-admission".to_string()
        });
        self.control_bytes = value.to_vec();
        ok_out()
    }

    fn poll(&mut self, _timeout_ms: i64) -> JournalPoll {
        if self.sent || self.control_bytes.len() != 48 || self.control_bytes[24] == 0 {
            return JournalPoll {
                ok: true,
                data: Vec::new(),
            };
        }
        let epoch = self.control_u64(0);
        let start = self.control_u64(8);
        let mut raw = vec![0u8; 72];
        raw[0..4].copy_from_slice(&0x524A_564Du32.to_le_bytes());
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
        raw[8..10].copy_from_slice(&1u16.to_le_bytes());
        raw[10..12].copy_from_slice(&1u16.to_le_bytes());
        raw[16..24].copy_from_slice(&0u64.to_le_bytes());
        raw[24..32].copy_from_slice(&(start + 1).to_le_bytes());
        raw[32..40].copy_from_slice(&epoch.to_le_bytes());
        raw[40..48].copy_from_slice(&1u64.to_le_bytes());
        raw[48..56].copy_from_slice(&start.to_le_bytes());
        raw[56..60].copy_from_slice(&3i32.to_le_bytes());
        raw[60..64].copy_from_slice(&0i32.to_le_bytes());
        self.sent = true;
        JournalPoll {
            ok: true,
            data: raw,
        }
    }

    fn counters(&mut self) -> JournalCounters {
        let mut values = vec![0u64; JOURNAL_NATIVE_COUNTERS];
        if self.sent {
            values[0] = 1;
            values[1] = 1;
            values[2] = 1;
            values[14] = 1;
        }
        JournalCounters {
            ok: !self.read_fail,
            values,
        }
    }

    fn detach(&mut self) -> OpOut {
        self.calls.push("detach".to_string());
        ok_out()
    }

    fn close(&mut self) -> OpOut {
        self.calls.push("release".to_string());
        ok_out()
    }
}

/// Journal source that stays quiet while admission is open and
/// emits exactly one matched record during the post-close drain.
/// Typed offline injection for the close-drain fault path: the
/// emitted record is the only writer append in the run, so a
/// first-append writer fault lands deterministically in the
/// drain, after the poll loop already latched a clean stop.
struct DrainEmitJournal {
    inner: JournalFixture,
    last_control: Vec<u8>,
    close_seen: bool,
    emitted: bool,
}

impl DrainEmitJournal {
    fn new() -> Self {
        Self {
            inner: JournalFixture::new(),
            last_control: Vec::new(),
            close_seen: false,
            emitted: false,
        }
    }

    fn control_u64(&self, offset: usize) -> u64 {
        let mut value: u64 = 0;
        for i in 0..8 {
            value |= u64::from(self.last_control[offset + i]) << (8 * i);
        }
        value
    }

    /// The fixture's matched record, keyed off the close
    /// control's epoch/start (same positions as the open
    /// control): matched entry inside admission, exit just
    /// after it.
    fn drain_record(&self) -> Vec<u8> {
        let epoch = self.control_u64(0);
        let start = self.control_u64(8);
        let mut raw = vec![0u8; 72];
        raw[0..4].copy_from_slice(&0x524A_564Du32.to_le_bytes());
        raw[4..6].copy_from_slice(&1u16.to_le_bytes());
        raw[6..8].copy_from_slice(&1u16.to_le_bytes());
        raw[8..10].copy_from_slice(&1u16.to_le_bytes());
        raw[10..12].copy_from_slice(&1u16.to_le_bytes());
        raw[16..24].copy_from_slice(&0u64.to_le_bytes());
        raw[24..32].copy_from_slice(&(start + 1).to_le_bytes());
        raw[32..40].copy_from_slice(&epoch.to_le_bytes());
        raw[40..48].copy_from_slice(&1u64.to_le_bytes());
        raw[48..56].copy_from_slice(&start.to_le_bytes());
        raw[56..60].copy_from_slice(&3i32.to_le_bytes());
        raw[60..64].copy_from_slice(&0i32.to_le_bytes());
        raw
    }
}

impl JournalKernel for DrainEmitJournal {
    fn prepare(&mut self, control: &[u8]) -> OpOut {
        self.inner.prepare(control)
    }

    fn attach(&mut self) -> OpOut {
        self.inner.attach()
    }

    fn control(&mut self, value: &[u8]) -> OpOut {
        self.last_control = value.to_vec();
        if value.len() == 48 && value[24] == 0 {
            self.close_seen = true;
        }
        self.inner.control(value)
    }

    fn poll(&mut self, _timeout_ms: i64) -> JournalPoll {
        // Never consult the inner fixture before the close:
        // its record must not leak into the poll phase.
        if !self.close_seen || self.emitted || self.last_control.len() != 48 {
            return JournalPoll {
                ok: true,
                data: Vec::new(),
            };
        }
        self.emitted = true;
        JournalPoll {
            ok: true,
            data: self.drain_record(),
        }
    }

    fn counters(&mut self) -> JournalCounters {
        self.inner.counters()
    }

    fn detach(&mut self) -> OpOut {
        self.inner.detach()
    }

    fn close(&mut self) -> OpOut {
        self.inner.close()
    }
}

/// One shared wire vector: name, raw bytes, and whether the
/// decoders must accept it. The corpus below mirrors the old
/// host-simulation scenarios (matched, unmatched, i32
/// extremes, direction 2, caller triples) plus fixed
/// negatives; `producer_reference.py` re-derives every byte
/// from the Aya program's documented layout and requires
/// byte equality with this table's dump.
struct CorpusVector {
    name: &'static str,
    raw: Vec<u8>,
    accept: bool,
}

fn put_u16(raw: &mut [u8], offset: usize, value: u16) {
    raw[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(raw: &mut [u8], offset: usize, value: u32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(raw: &mut [u8], offset: usize, value: u64) {
    raw[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_i32(raw: &mut [u8], offset: usize, value: i32) {
    raw[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Canonical matched record: decrypt, 3 pages, token 1, no callers.
fn base_wire() -> Vec<u8> {
    let mut raw = vec![0u8; 72];
    put_u32(&mut raw, 0, 0x524A_564D);
    put_u16(&mut raw, 4, 1);
    put_u16(&mut raw, 6, 1);
    put_u16(&mut raw, 8, 1);
    put_u16(&mut raw, 10, 1);
    put_u32(&mut raw, 12, 2);
    put_u64(&mut raw, 16, 0);
    put_u64(&mut raw, 24, 1100);
    put_u64(&mut raw, 32, 1000);
    put_u64(&mut raw, 40, 1);
    put_u64(&mut raw, 48, 1050);
    put_i32(&mut raw, 56, 3);
    put_i32(&mut raw, 60, -5);
    raw
}

fn wire_corpus() -> Vec<CorpusVector> {
    let mut out = Vec::new();
    out.push(CorpusVector {
        name: "matched",
        raw: base_wire(),
        accept: true,
    });
    let mut unmatched = base_wire();
    put_u16(&mut unmatched, 8, 0);
    put_u64(&mut unmatched, 40, 0);
    put_u64(&mut unmatched, 48, 0);
    out.push(CorpusVector {
        name: "unmatched",
        raw: unmatched,
        accept: true,
    });
    let mut extremes = base_wire();
    put_i32(&mut extremes, 56, i32::MIN);
    put_i32(&mut extremes, 60, i32::MAX);
    out.push(CorpusVector {
        name: "i32-extremes",
        raw: extremes,
        accept: true,
    });
    let mut dir2 = base_wire();
    put_u16(&mut dir2, 10, 2);
    out.push(CorpusVector {
        name: "direction-2",
        raw: dir2,
        accept: true,
    });
    let mut caller = base_wire();
    put_u16(&mut caller, 64, 1);
    put_u16(&mut caller, 66, 2);
    put_u16(&mut caller, 68, 6);
    out.push(CorpusVector {
        name: "caller-triple",
        raw: caller,
        accept: true,
    });
    let mut bad_magic = base_wire();
    put_u32(&mut bad_magic, 0, 0);
    out.push(CorpusVector {
        name: "bad-magic",
        raw: bad_magic,
        accept: false,
    });
    let mut truncated = base_wire();
    truncated.truncate(71);
    out.push(CorpusVector {
        name: "truncated",
        raw: truncated,
        accept: false,
    });
    let mut token_ceiling = base_wire();
    put_u64(&mut token_ceiling, 40, u64::MAX);
    out.push(CorpusVector {
        name: "token-ceiling",
        raw: token_ceiling,
        accept: false,
    });
    let mut long = base_wire();
    long.push(0);
    out.push(CorpusVector {
        name: "long-73",
        raw: long,
        accept: false,
    });
    let mut label_overflow = base_wire();
    put_u16(&mut label_overflow, 64, 1);
    put_u16(&mut label_overflow, 66, 3);
    put_u16(&mut label_overflow, 68, 11);
    out.push(CorpusVector {
        name: "label-overflow",
        raw: label_overflow,
        accept: false,
    });
    let mut label_mismatch = base_wire();
    put_u16(&mut label_mismatch, 64, 1);
    put_u16(&mut label_mismatch, 66, 2);
    put_u16(&mut label_mismatch, 68, 1);
    out.push(CorpusVector {
        name: "label-class-mismatch",
        raw: label_mismatch,
        accept: false,
    });
    let mut unmatched_caller = base_wire();
    put_u16(&mut unmatched_caller, 8, 0);
    put_u64(&mut unmatched_caller, 40, 0);
    put_u64(&mut unmatched_caller, 48, 0);
    put_u16(&mut unmatched_caller, 64, 1);
    put_u16(&mut unmatched_caller, 66, 3);
    put_u16(&mut unmatched_caller, 68, 10);
    out.push(CorpusVector {
        name: "unmatched-caller",
        raw: unmatched_caller,
        accept: true,
    });
    out
}

fn hex_bytes(raw: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(raw.len() * 2);
    for byte in raw {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 15) as usize] as char);
    }
    out
}

/// Corpus dump for the host-side differential: one
/// `CORPUS <name> <accept:1|0> <hex>` line per vector on
/// stdout. Always passes; `producer_reference.py` runs this
/// test with `--exact --nocapture` and requires byte
/// equality with its own Aya-layout derivation.
#[test]
fn dump_wire_corpus() {
    for vector in wire_corpus() {
        println!(
            "CORPUS {} {} {}",
            vector.name,
            if vector.accept { 1 } else { 0 },
            hex_bytes(&vector.raw)
        );
    }
}

/// Fresh capture admitting the corpus window: epoch 1000,
/// capture start 900, admission opened at 1000.
fn corpus_capture(callers: bool) -> JournalCapture {
    let mut capture = JournalCapture::new(1000, 900, JOURNAL_CANDIDATE_ID.to_string(), callers);
    capture.opened(1000).expect("admission opens");
    capture
}

#[test]
fn corpus_vectors_ingest_exactly() {
    for vector in wire_corpus() {
        let mut capture = corpus_capture(true);
        let event = capture.consume(&vector.raw, "cap-test", 1200);
        assert_eq!(event.is_ok(), vector.accept, "{}", vector.name);
        if vector.accept {
            let event = event.expect("accepted");
            assert!(event.has_journal, "{}", vector.name);
            assert!(event.journal_version, "{}", vector.name);
        } else {
            assert_eq!(capture.invalid_records, 1, "{}", vector.name);
        }
    }
}

#[test]
fn corpus_matched_normalizes() {
    let mut capture = corpus_capture(false);
    let event = capture
        .consume(&base_wire(), "cap-test", 1200)
        .expect("matched ingests");
    assert_eq!(event.journal.direction, "decrypt");
    assert_eq!(event.journal.requested_bytes.value, 12288);
    assert!(event.journal.requested_bytes.has);
    assert_eq!(event.journal.operation_token.value, 1);
    assert_eq!(event.journal.entry_ns.value, 1050);
    assert_eq!(event.journal.membership, "admitted");
    assert_eq!(event.source_hook, "set_memory_decrypted");
    assert_eq!(event.source_correlation, "direct");
}

#[test]
fn corpus_unmatched_and_extremes_normalize() {
    let mut capture = corpus_capture(false);
    let vectors = wire_corpus();
    let unmatched = capture
        .consume(&vectors[1].raw, "cap-test", 1200)
        .expect("unmatched ingests");
    assert_eq!(unmatched.journal.membership, "unmatched_exit");
    assert!(!unmatched.journal.operation_token.has);
    assert_eq!(unmatched.source_correlation, "unpaired");
    let mut capture = corpus_capture(false);
    let extremes = capture
        .consume(&vectors[2].raw, "cap-test", 1200)
        .expect("extremes ingest");
    assert!(!extremes.journal.requested_bytes.has);
    assert_eq!(extremes.journal.size_reason, "invalid_native_pages");
    assert_eq!(extremes.journal.native_result, i32::MAX);
}

#[test]
fn corpus_caller_triple_needs_callers() {
    let vectors = wire_corpus();
    let mut solicited = corpus_capture(true);
    let event = solicited
        .consume(&vectors[4].raw, "cap-test", 1200)
        .expect("solicited caller ingests");
    assert_eq!(event.journal.caller_status, "resolved");
    assert_eq!(event.journal.caller_class, "swiotlb");
    let mut unsolicited = corpus_capture(false);
    assert!(
        unsolicited
            .consume(&vectors[4].raw, "cap-test", 1200)
            .is_err()
    );
    assert_eq!(unsolicited.invalid_records, 1);
}

#[test]
fn transport_sequence_gap_regression_and_exhaustion() {
    // A jumped sequence counts the gap; a regressed or exhausted
    // sequence refuses and counts one invalid record.
    let mut capture = corpus_capture(false);
    let mut first = base_wire();
    put_u64(&mut first, 16, 5);
    capture
        .consume(&first, "cap-test", 1200)
        .expect("gap ingests");
    assert_eq!(capture.sequence_gaps, 5);
    let mut replay = base_wire();
    put_u64(&mut replay, 16, 5);
    assert!(capture.consume(&replay, "cap-test", 1200).is_err());
    assert_eq!(capture.invalid_records, 1);
    let mut exhausted = base_wire();
    put_u64(&mut exhausted, 16, u64::MAX);
    assert!(capture.consume(&exhausted, "cap-test", 1200).is_err());
    assert_eq!(capture.invalid_records, 2);
    // A fresh CPU starts its own sequence at zero.
    let mut other = base_wire();
    put_u32(&mut other, 12, 7);
    put_u64(&mut other, 16, 0);
    capture
        .consume(&other, "cap-test", 1200)
        .expect("new CPU ingests");
}

#[test]
fn unmatched_caller_needs_solicitation() {
    let vectors = wire_corpus();
    let raw = vectors
        .iter()
        .find(|v| v.name == "unmatched-caller")
        .expect("vector")
        .raw
        .clone();
    let mut solicited = corpus_capture(true);
    let event = solicited.consume(&raw, "cap-test", 1200).expect("ingests");
    assert_eq!(event.journal.membership, "unmatched_exit");
    assert_eq!(event.journal.caller_label, "dma_direct_free");
    let mut unsolicited = corpus_capture(false);
    assert!(unsolicited.consume(&raw, "cap-test", 1200).is_err());
}

#[test]
fn attach_specs_exit_before_entry() {
    let specs = journal_attach_specs();
    let names: Vec<&str> = specs.iter().map(|spec| spec.program.as_str()).collect();
    assert_eq!(
        names,
        vec![
            "mv_jr_dec_exit",
            "mv_jr_enc_exit",
            "mv_jr_dec_enter",
            "mv_jr_enc_enter",
        ]
    );
    assert_eq!(specs[0].target_a, "set_memory_decrypted");
    assert_eq!(specs[1].target_a, "set_memory_encrypted");
    assert_eq!(specs[2].target_a, "set_memory_decrypted");
    assert_eq!(specs[3].target_a, "set_memory_encrypted");
}

#[test]
fn native_kernel_closed_state() {
    let mut kernel = NativeJournalKernel::new();
    assert!(!kernel.poll(0).ok);
    assert!(kernel.poll(0).data.is_empty());
    assert!(!kernel.counters().ok);
    assert!(kernel.counters().values.is_empty());
    assert!(!kernel.attach().ok);
    assert_eq!(kernel.attach().message, "journal not open");
    assert!(!kernel.control(&[0u8; 48]).ok);
    // Detach and close on a never-opened source succeed: rollback
    // after a pre-open failure stays a clean refusal.
    assert!(kernel.detach().ok);
    assert!(kernel.close().ok);
}

#[test]
fn native_kernel_prepare_refuses_offline() {
    // Garbage bytes refuse without privileges, panic, or state:
    // the failure reads as unavailable, never as partial.
    let mut kernel = NativeJournalKernel::new();
    kernel.setup(vec![0u8; 64], false);
    let refused = kernel.prepare(&encode_journal_control(1, 0, 0, false, false, false));
    assert!(!refused.ok);
    assert!(
        refused.message == "journal open/load unavailable"
            || refused.message == "journal map geometry"
            || refused.message == "journal initial counters unavailable",
        "unexpected: {}",
        refused.message
    );
    // Still closed after the refusal: detach/close stay clean.
    assert!(kernel.detach().ok);
    assert!(kernel.close().ok);
    // Wrong-length control never reaches the kernel.
    let mut closed = NativeJournalKernel::new();
    let bad = closed.control(&[0u8; 47]);
    assert!(!bad.ok);
    assert_eq!(bad.message, "journal control unavailable");
}

/// Newest linked journal object under the workspace target dir, if any.
fn built_journal_object() -> Option<Vec<u8>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target = match std::env::var("CARGO_TARGET_DIR") {
        Ok(dir) if !dir.is_empty() => {
            let path = PathBuf::from(&dir);
            if path.is_absolute() {
                path
            } else {
                root.join(path)
            }
        }
        _ => root.join("target"),
    };
    let mut cands = Vec::new();
    for profile in ["debug", "release"] {
        let base = target.join(profile).join("build").join("memveil");
        let Ok(entries) = std::fs::read_dir(&base) else {
            continue;
        };
        for entry in entries.flatten() {
            let obj = entry
                .path()
                .join("out")
                .join("ebpf-target")
                .join("bpfel-unknown-none")
                .join("release")
                .join("memveil-ebpf-journal");
            if obj.is_file() {
                cands.push(obj);
            }
        }
    }
    cands
        .into_iter()
        .filter_map(|path| {
            let modified = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .ok()?;
            let bytes = std::fs::read(&path).ok()?;
            Some((modified, bytes))
        })
        .max_by(|left, right| left.0.cmp(&right.0))
        .map(|(_, bytes)| bytes)
}

#[test]
fn native_kernel_prepare_real_object_is_safe_offline() {
    let Some(elf) = built_journal_object() else {
        eprintln!("skip: no built journal object under target/");
        return;
    };
    assert!(!elf.is_empty());
    let mut kernel = NativeJournalKernel::new();
    kernel.setup(elf, false);
    let out = kernel.prepare(&encode_journal_control(1, 0, 0, false, false, false));
    if out.ok {
        // Privileged host: the full open path ran; cleanup stays clean.
        assert!(kernel.detach().ok);
        assert!(kernel.close().ok);
        return;
    }
    assert!(
        [
            "journal open/load unavailable",
            "journal map geometry",
            "journal initial counters unavailable",
            "journal initial counters nonzero",
            "journal offsets unavailable",
            "journal caller map unavailable",
            "journal control unavailable",
            "journal control write/readback failed",
        ]
        .contains(&out.message.as_str()),
        "unexpected: {}",
        out.message
    );
    assert!(kernel.detach().ok);
    assert!(kernel.close().ok);
}

#[test]
fn caller_ranges_bounded_allowlisted() {
    let table = resolve_caller_ranges(
        "0000000000000010 T dma_direct_alloc\n0000000000000020 T next_symbol\n",
        false,
    )
    .expect("resolves");
    assert_eq!(table.len(), 10);
    assert_eq!(table[8].start, 16);
    assert_eq!(table[8].end, 32);
    assert!(!table[8].ambiguous);
    let table = resolve_caller_ranges(
        "0000000000000010 T dma_direct_alloc\n0000000000000010 T alias\n0000000000000020 T next_symbol\n",
        false,
    )
    .expect("resolves");
    assert!(table[8].ambiguous);
    let table = resolve_caller_ranges(
        "0000000000000010 T dma_direct_alloc\n0000000000000020 T next_symbol\n0000000000000010 T alias\n",
        false,
    )
    .expect("resolves");
    assert!(table[8].ambiguous);
    // Owned-module labels stay zero without the stable module.
    let table = resolve_caller_ranges(
        "0000000000000010 t mv_command_set [memveil_region_oracle]\n0000000000000020 t next [memveil_region_oracle]\n",
        false,
    )
    .expect("resolves");
    assert_eq!(table[0].start, 0);
    let table = resolve_caller_ranges(
        "0000000000000010 t mv_command_set [memveil_region_oracle]\n0000000000000020 t next [memveil_region_oracle]\n",
        true,
    )
    .expect("resolves");
    assert_eq!(table[0].start, 16);
    assert_eq!(table[0].end, 32);
    // Zero addresses never resolve.
    let table = resolve_caller_ranges(
        "0000000000000000 T dma_direct_alloc\n0000000000000000 T next\n",
        true,
    )
    .expect("resolves");
    assert_eq!(table[8].start, 0);
}

#[test]
fn caller_range_encoding_and_bounds() {
    let encoded = encode_caller_range(CallerRange {
        start: 0x1122_3344_5566_7788,
        end: 0x99AA_BBCC_DDEE_FF00,
        ambiguous: true,
    });
    assert_eq!(encoded.len(), 24);
    assert_eq!(&encoded[0..8], &0x1122_3344_5566_7788u64.to_le_bytes());
    assert_eq!(&encoded[8..16], &0x99AA_BBCC_DDEE_FF00u64.to_le_bytes());
    assert_eq!(&encoded[16..24], &1u64.to_le_bytes());
    // Bounds refuse instead of truncating.
    assert!(resolve_caller_ranges(&"x".repeat(16_777_217), false).is_err());
    let mut lines = String::new();
    for _ in 0..262_145 {
        lines.push_str("0000000000000010 T x\n");
    }
    assert!(resolve_caller_ranges(&lines, false).is_err());
    assert!(resolve_caller_ranges("bogus line\n", false).is_err());
    assert!(resolve_caller_ranges("0010 T short\n", false).is_err());
}

fn write_profile(dir: &std::path::Path, name: &str, body: &str) {
    let nested = dir.join("journal-candidates");
    std::fs::create_dir_all(&nested).expect("profile dir");
    std::fs::write(nested.join(name), body).expect("profile write");
}

fn candidate_body() -> String {
    std::fs::read_to_string("profiles/journal-candidates/linux-7.0.14-x86-journal-provisional.json")
        .expect("carried candidate reads")
}

#[test]
fn profile_reason_matrix() {
    assert_eq!(JOURNAL_CANDIDATE_ID, "linux-7.0.14-x86-journal-provisional");
    let root = std::env::temp_dir().join(format!("memveil-jr-prof-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    // Missing profiles tree: unavailable, never admitted.
    assert_eq!(
        discover_journal_binding(root.to_str().expect("utf-8"), "", false),
        Err(JournalDiscoveryFailure::Unavailable)
    );
    // Carried candidate: present but unadmitted, null bindings.
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &candidate_body(),
    );
    let carried = discover_journal_binding(root.to_str().expect("utf-8"), "", false)
        .expect("carried candidate discovers");
    assert_eq!(carried.profile_id, JOURNAL_CANDIDATE_ID);
    assert_eq!(carried.status, "unadmitted");
    assert_eq!(carried.architecture, "x86_64");
    assert_eq!(carried.page_size, 4096);
    assert!(carried.callers_admitted);
    assert!(carried.config_sha256.is_empty());
    assert!(carried.btf_sha256.is_empty());
    assert!(carried.object_sha256.is_empty());
    // Explicit foreign id resolves as a path and fails closed.
    assert_eq!(
        discover_journal_binding(root.to_str().expect("utf-8"), "foreign.json", true),
        Err(JournalDiscoveryFailure::Unavailable)
    );
    // Explicit candidate id resolves to the same bindings.
    let explicit =
        discover_journal_binding(root.to_str().expect("utf-8"), JOURNAL_CANDIDATE_ID, true)
            .expect("explicit candidate discovers");
    assert_eq!(explicit, carried);
    // Invalid JSON fails closed as invalid.
    let bad = root.join("bad.json");
    std::fs::write(&bad, "{not json").expect("bad profile");
    assert_eq!(
        discover_journal_binding(
            root.to_str().expect("utf-8"),
            bad.to_str().expect("utf-8"),
            true
        ),
        Err(JournalDiscoveryFailure::Invalid)
    );
    // A tampered contract is invalid, never admitted.
    let tampered = candidate_body().replacen("memveil-journal-profile/1", "forged/9", 1);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &tampered,
    );
    assert_eq!(
        discover_journal_binding(root.to_str().expect("utf-8"), "", false),
        Err(JournalDiscoveryFailure::Invalid)
    );
    // Trailing bytes past the document read as invalid, while
    // trailing whitespace stays wellformed.
    let trailed = candidate_body() + "x";
    write_profile(&root, "linux-7.0.14-x86-journal-provisional.json", &trailed);
    assert_eq!(
        discover_journal_binding(root.to_str().expect("utf-8"), "", false),
        Err(JournalDiscoveryFailure::Invalid)
    );
    let spaced = candidate_body() + " \n";
    write_profile(&root, "linux-7.0.14-x86-journal-provisional.json", &spaced);
    let spaced_back = discover_journal_binding(root.to_str().expect("utf-8"), "", false)
        .expect("whitespace-framed candidate discovers");
    assert_eq!(spaced_back, carried);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn selection_matrix() {
    // Journal-only: no attempts, no device.
    let journal = select_journal("conversion-journal", false, false, false).expect("parses");
    assert!(journal.journal);
    assert!(!journal.attempts);
    assert!(select_journal("conversion-journal", false, true, false).is_err());
    // Mixed: attempts stay required-present.
    let mixed =
        select_journal("attempt-trace,conversion-journal", false, false, false).expect("parses");
    assert!(mixed.journal);
    assert!(mixed.attempts);
    // Journal options without the journal refuse.
    assert!(select_journal("attempt-trace", true, false, false).is_err());
    assert!(select_journal("attempt-trace", false, false, true).is_err());
    assert!(select_journal("", true, false, false).is_err());
    // Duplicates and unknown ids refuse.
    assert!(select_journal("conversion-journal,conversion-journal", false, false, false).is_err());
    assert!(select_journal("conversion-journal,nope", false, false, false).is_err());
}

#[test]
fn parse_compat_duplicates_error_and_lifecycle_resolves() {
    // Duplicate names are usage errors, including duplicates the
    // old parser silently collapsed.
    let dup = parse_requested_caps("attempt-trace,copy-actual,attempt-trace");
    assert!(!dup.ok);
    assert_eq!(dup.err, "duplicate capability: attempt-trace");
    let dup_journal = parse_requested_caps("conversion-journal,conversion-journal");
    assert!(!dup_journal.ok);
    assert_eq!(dup_journal.err, "duplicate capability: conversion-journal");
    // Ordinary channels without attempt-trace resolve it implicitly.
    let lifecycle = parse_requested_caps("mapping-lifecycle");
    assert!(lifecycle.ok);
    assert_eq!(lifecycle.caps, vec!["attempt-trace", "mapping-lifecycle"]);
    let copy = parse_requested_caps("copy-actual");
    assert!(copy.ok);
    assert_eq!(copy.caps, vec!["attempt-trace", "copy-actual"]);
    // Mixed ordinary/journal keeps attempts present.
    let mixed = parse_requested_caps("copy-actual,conversion-journal");
    assert!(mixed.ok);
    assert_eq!(mixed.caps[0], "attempt-trace");
    // Journal-only and observe-only need no attempts.
    let journal = parse_requested_caps("conversion-journal");
    assert!(journal.ok);
    assert_eq!(journal.caps, vec!["conversion-journal"]);
    let observe = parse_requested_caps("conversion-observe");
    assert!(observe.ok);
    assert_eq!(observe.caps, vec!["conversion-observe"]);
    // Unknown ids and empty items still refuse.
    assert!(!parse_requested_caps("attempt-trace,nope").ok);
    assert!(!parse_requested_caps("attempt-trace,,copy-actual").ok);
}

fn journal_only_config() -> CollectorConfig {
    CollectorConfig {
        has_journal: true,
        journal_only: true,
        journal_callers: false,
        journal_profile: JOURNAL_CANDIDATE_ID.to_string(),
        duration_s: 1,
        ..Default::default()
    }
}

#[test]
fn journal_only_collection_uses_no_attempt_source() {
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = JournalFixture::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = ScriptSignal;
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    assert!(writer.finalized);
    assert!(kernel.calls.is_empty(), "{:?}", kernel.calls);
    assert_eq!(writer.lines.len(), 1);
    let event = parse_event(&writer.lines[0]).expect("event parses");
    assert_eq!(event.journal.requested_bytes.value, 12288);
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert!(session.has_journal);
    assert!(session.has_integrity);
    assert_eq!(session.journal.closure, "unproved");
    assert!(!session.journal.counters[10].has);
    assert_eq!(session.cap_bounce_attempts.status, "unavailable");
    assert_eq!(journal.calls[0], "prepare");
    assert_eq!(journal.calls[1], "attach");
    assert_eq!(journal.calls[journal.calls.len() - 1], "release");
    // Readiness opens before the close sequence; detach precedes release.
    let order = |name: &str| journal.calls.iter().position(|c| c == name).expect(name);
    assert!(order("prepare") < order("attach"));
    assert!(order("attach") < order("open"));
    assert!(order("open") < order("close-admission"));
    assert!(order("close-admission") < order("detach"));
    assert!(order("detach") < order("release"));
}

#[test]
fn journal_checkpoint_carries_open_snapshot() {
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = JournalFixture::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = ScriptSignal;
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    // Readiness checkpoint plus the final snapshot both carry the
    // journal block; the open prefix never carries a terminal
    // censored count.
    assert!(!writer.checkpoints.is_empty());
    for checkpoint in &writer.checkpoints {
        let session = parse_session(checkpoint).expect("checkpoint parses");
        assert!(session.has_journal);
        assert!(!session.journal.counters[4].has);
    }
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert!(session.journal.counters[0].has);
    assert_eq!(session.journal.counters[0].value, 1);
    assert_eq!(session.journal.counters[9].value, 0);
    assert!(session.journal.counters[9].has);
}

#[test]
fn snapshot_maps_native_counters_positionally() {
    let mut capture = corpus_capture(false);
    capture
        .consume(&base_wire(), "cap-test", 1200)
        .expect("ingests");
    // Native layout: entries exits matched unmatched censored drops
    // op-exhaust nest-exhaust token-exhaust identity poisoned overflow
    // active next-token emitted.
    let native = [4, 5, 6, 7, 8, 9, 10, 11, 12, 0, 0, 0, 13, 14, 15];
    let snap = capture
        .snapshot(1300, true, &native, true)
        .expect("snapshots");
    let values: Vec<u64> = snap.counters.iter().map(|c| c.value).collect();
    assert_eq!(&values[0..9], &[4, 5, 6, 7, 8 + 13, 10, 11, 12, 9]);
    assert!(snap.counters.iter().take(9).all(|c| c.has));
    // Missed callbacks stay unknown with a reason, forever.
    assert!(!snap.counters[10].has);
    // An overflow bit nulls its position with the overflow reason.
    let mut overflowed = native;
    overflowed[11] = 1 << 6;
    let snap = capture
        .snapshot(1300, true, &overflowed, true)
        .expect("snapshots");
    assert!(!snap.counters[5].has);
    assert_eq!(snap.counter_reasons[5], "overflow");
    // An unreadable readback nulls every mapped position.
    let snap = capture
        .snapshot(1300, true, &native, false)
        .expect("snapshots");
    assert!(snap.counters.iter().take(9).all(|c| !c.has));
    assert_eq!(snap.counter_reasons[0], "read_failed");
}

#[test]
fn unproved_close_keeps_admission_end_absent() {
    struct FlakyControl(JournalFixture);
    impl JournalKernel for FlakyControl {
        fn prepare(&mut self, control: &[u8]) -> OpOut {
            self.0.prepare(control)
        }
        fn attach(&mut self) -> OpOut {
            self.0.attach()
        }
        fn control(&mut self, value: &[u8]) -> OpOut {
            self.0.control(value);
            // The close write never proves; readiness opens normally.
            if value.len() == 48 && value[24] == 0 && self.0.sent {
                return OpOut {
                    ok: false,
                    message: "scripted close".to_string(),
                };
            }
            ok_out()
        }
        fn poll(&mut self, timeout_ms: i64) -> JournalPoll {
            self.0.poll(timeout_ms)
        }
        fn counters(&mut self) -> JournalCounters {
            self.0.counters()
        }
        fn detach(&mut self) -> OpOut {
            self.0.detach()
        }
        fn close(&mut self) -> OpOut {
            self.0.close()
        }
    }
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = FlakyControl(JournalFixture::new());
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = ScriptSignal;
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 0, "{}", result.diagnostic);
    let session = parse_session(&writer.session_bytes).expect("session parses");
    assert!(!session.journal.admission_end_ns.has);
    assert_eq!(session.journal.admission_end_reason, "close_unproved");
}

#[test]
fn journal_attach_failure_refuses_cleanly() {
    let mut collector = Collector::new(journal_only_config());
    let mut kernel = ScriptKernel::new();
    let mut journal = JournalFixture::new();
    journal.attach_fail = true;
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = ScriptSignal;
    let mut writer = MemWriter::new();
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert_eq!(result.exit_code, 3);
    assert!(!writer.finalized);
    assert_eq!(journal.calls[journal.calls.len() - 1], "release");
}

#[test]
fn mixed_close_drain_fault_still_detaches_ordinary_session() {
    // Mixed run (attempts + journal): the poll loop latches a
    // clean duration stop, then the writer fails fatal exactly
    // on the close-drain record. The run must still detach the
    // ordinary kernel session through the normal close before
    // dropping as unfinalizable; skipping straight to the drop
    // would leak the ordinary session's close side effects.
    let mut collector = Collector::new(CollectorConfig {
        has_journal: true,
        journal_only: false,
        journal_callers: false,
        journal_profile: JOURNAL_CANDIDATE_ID.to_string(),
        duration_s: 1,
        ..Default::default()
    });
    let mut kernel = ScriptKernel::new();
    let mut journal = DrainEmitJournal::new();
    let mut clock = ScriptClock::new(1000, 100_000_000);
    let mut signal = ScriptSignal;
    let mut writer = MemWriter::new();
    // The drain record is the only append in the run: quiet
    // timeout polls persist nothing and checkpoints bypass
    // append, so the first-append fault lands in the drain.
    writer.fail_append_at = 1;
    let result = collector.run_with_journal(
        &mut kernel,
        &mut journal,
        &mut clock,
        &mut signal,
        &mut writer,
    );
    assert!(
        journal.close_seen && journal.emitted,
        "fault path not exercised: close_seen={} emitted={}",
        journal.close_seen,
        journal.emitted
    );
    assert_eq!(writer.appends, 1, "unexpected append count");
    assert_eq!(result.exit_code, EXIT_ERROR, "{}", result.diagnostic);
    assert_eq!(result.outcome, "unfinalizable");
    assert_eq!(writer.discards, 1);
    assert!(
        kernel.calls.iter().any(|call| call == "detach"),
        "ordinary detach skipped: {:?}",
        kernel.calls
    );
    assert!(
        journal.inner.calls.iter().any(|call| call == "detach"),
        "journal detach skipped: {:?}",
        journal.inner.calls
    );
}

#[test]
fn run_collector_refuses_journal_before_resources() {
    let root = std::env::temp_dir().join(format!("memveil-jr-ref-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("scratch");
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3);
    assert!(
        result
            .diagnostic
            .starts_with("journal_profile_not_admitted"),
        "{}",
        result.diagnostic
    );
    assert!(result.end_reason.is_empty());
    // Refusal precedes native and output creation alike.
    assert!(!out.exists());
    assert!(writer.lines.is_empty());
    assert!(!writer.finalized);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn run_collector_invalid_selector_is_usage_error() {
    let opts = RecordOptions {
        output: "unused".to_string(),
        capabilities: "conversion-journal".to_string(),
        has_device: true,
        device: "eth0".to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", "", opts, &mut writer);
    assert_eq!(result.exit_code, 2);
    assert_eq!(result.diagnostic, "invalid capability/journal selector");
}

fn scan_kernel() -> KernelInfo {
    KernelInfo {
        release: "7.0.0-test".to_string(),
        arch: "x86_64".to_string(),
        eligible_floor: true,
        floor_reason: String::new(),
    }
}

#[test]
fn conversion_observe_still_refused() {
    // No observe contract exists in this stack: the channel-less
    // refusal stays, through fixtures (no live host reads).
    let profiles = load_profiles("tests/fixtures/scan/profiles").expect("scan profiles load");
    for want in ["conversion-observe", "attempt-trace,conversion-observe"] {
        let decision = decide_record(
            "tests/fixtures/scan/ok",
            &scan_kernel(),
            &profiles,
            "",
            false,
            "tests/fixtures/elf/ok.o",
            "",
            "",
            want,
            "tests/fixtures/scan/profiles",
            "",
        );
        assert!(!decision.ok, "{want}");
        assert!(
            decision
                .refusal
                .contains("conversion-observe has no record channel"),
            "{want}: {}",
            decision.refusal
        );
    }
}

#[test]
fn decide_record_journal_reports_frozen_code() {
    let profiles = load_profiles("tests/fixtures/scan/profiles").expect("scan profiles load");
    for want in ["conversion-journal", "attempt-trace,conversion-journal"] {
        let decision = decide_record(
            "tests/fixtures/scan/ok",
            &scan_kernel(),
            &profiles,
            "",
            false,
            "tests/fixtures/elf/ok.o",
            "",
            "",
            want,
            "tests/fixtures/scan/profiles",
            "",
        );
        assert!(!decision.ok, "{want}");
        assert_eq!(decision.refusal, "journal_profile_not_admitted", "{want}");
    }
}

#[test]
fn unadmitted_profile_refuses_after_wiring() {
    // The carried candidate (unadmitted, null bindings) still
    // refuses at the dispatch gate now that positive dispatch
    // is wired: only an admitted profile with exactly matching
    // rebound evidence passes. The refusal creates no output
    // and no native state.
    let root = std::env::temp_dir().join(format!("memveil-jr-unw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    write_profile(
        &root,
        "linux-7.0.14-x86-journal-provisional.json",
        &candidate_body(),
    );
    let out = root.join("cap");
    let opts = RecordOptions {
        output: out.to_str().expect("utf-8").to_string(),
        capabilities: "conversion-journal".to_string(),
        ..Default::default()
    };
    let mut writer = MemWriter::new();
    let result = run_collector_with("", root.to_str().expect("utf-8"), opts, &mut writer);
    assert_eq!(result.exit_code, 3);
    assert_eq!(result.diagnostic, "journal_profile_not_admitted");
    assert!(!out.exists());
    assert!(!writer.finalized);
    let _ = std::fs::remove_dir_all(&root);
}
