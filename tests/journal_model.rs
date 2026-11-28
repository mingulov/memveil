// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed conversion-journal model integration: frozen 0.2.0 scenarios
//! through typed parse/validate/encode.
//!
//! Port of the Mojo-era `test_journal_producer` checks against the Rust
//! journal model (`model::journal_event`, `model::journal_session`) and
//! capture boundary (`capture::journal_capture`), extended with the
//! reader-ingest hook legs and equality against the carried
//! `expected.json` / `report.json` scalars. Reducer aggregates (request
//! verdicts, findings) stay out of scope: this suite only asserts
//! typed-derivable facts (line counts, nonzero native results,
//! unmatched membership, requested-byte totals, terminal censored
//! counters) against those files.

use memveil::capture::journal_capture::{
    JOURNAL_NATIVE_COUNTERS, JournalCapture, JournalCounters, JournalKernel, JournalPoll,
    decode_journal_counters, encode_journal_control,
};
use memveil::capture::reader::{default_limits, read_capture};
use memveil::model::encode::{encode_event_line, encode_session};
use memveil::model::event::{Event, parse_event};
use memveil::model::journal_session::JOURNAL_COUNTER_COUNT;
use memveil::model::session::{Session, parse_session};
use memveil::platform::outcome::OpOut;
use std::path::PathBuf;
use std::process::Command;

/// The 12 frozen scenarios carrying reports (`duplicate` has none and is
/// classified separately).
const SCENARIOS: [&str; 12] = [
    "success",
    "failure",
    "orphan-encrypt",
    "overlap",
    "pre-attach",
    "unresolved",
    "disabled",
    "persistent",
    "invalid-pages",
    "initial-checkpoint",
    "open-checkpoint",
    "censored",
];

fn fixture_bytes(name: &str, file: &str) -> Vec<u8> {
    std::fs::read(format!("tests/fixtures/journal/{name}/{file}"))
        .unwrap_or_else(|e| panic!("read fixture {name}/{file}: {e}"))
}

fn fixture_text(name: &str, file: &str) -> String {
    String::from_utf8(fixture_bytes(name, file)).expect("fixture text is UTF-8")
}

fn scenario_session(name: &str) -> Session {
    let file = if name == "initial-checkpoint" || name == "open-checkpoint" {
        "checkpoint.json"
    } else {
        "session.json"
    };
    let raw = fixture_bytes(name, file);
    parse_session(&raw).unwrap_or_else(|e| panic!("parse {name}/{file}: {e}"))
}

fn scenario_events(name: &str) -> Vec<Event> {
    let raw = fixture_text(name, "events.ndjson");
    let mut out = Vec::new();
    for line in raw.split('\n') {
        if line.is_empty() {
            continue;
        }
        out.push(parse_event(line.as_bytes()).unwrap_or_else(|e| panic!("parse {name} line: {e}")));
    }
    out
}

/// Tail of a frozen document after exactly one `"key":` occurrence.
fn scalar_tail(doc: &str, key: &str) -> String {
    let pat = format!("\"{key}\":");
    let mut hits = doc.match_indices(&pat);
    let (pos, _) = hits.next().unwrap_or_else(|| panic!("{key} present"));
    assert!(hits.next().is_none(), "{key} occurs once");
    doc[pos + pat.len()..].trim_start().to_string()
}

/// Quoted canonical u64 or null after `key` in a frozen oracle file.
fn frozen_u64_or_null(doc: &str, key: &str) -> Option<u64> {
    let tail = scalar_tail(doc, key);
    if let Some(stripped) = tail.strip_prefix("null") {
        let rest = stripped.trim_start();
        assert!(
            rest.starts_with(',') || rest.starts_with('}') || rest.starts_with(']'),
            "{key} null terminator"
        );
        return None;
    }
    assert!(tail.starts_with('"'), "{key} is quoted");
    let end = tail[1..].find('"').expect("closing quote");
    let digits = &tail[1..1 + end];
    let value: u64 = digits.parse().expect("decimal digits");
    assert_eq!(value.to_string(), digits, "{key} canonical");
    Some(value)
}

fn frozen_bool(doc: &str, key: &str) -> bool {
    let tail = scalar_tail(doc, key);
    if tail.starts_with("true") {
        return true;
    }
    assert!(tail.starts_with("false"), "{key} is a bool");
    false
}

#[test]
fn frozen_journal_event_and_session() {
    let raw = fixture_bytes("success", "events.ndjson");
    let line = raw.split(|b| *b == b'\n').next().expect("one line");
    let event = parse_event(line).expect("success line parses");
    assert_eq!(event.kind, "transition_result");
    let again = parse_event(&encode_event_line(&event).expect("encode line")).expect("reparse");
    assert_eq!(again.seq, 0);
    let session = scenario_session("success");
    let encoded = encode_session(&session).expect("encode session");
    assert!(encoded.contains("\"schema_version\":\"0.2.0\""));
}

#[test]
fn all_frozen_windows_and_signed_results() {
    for name in SCENARIOS {
        let session = scenario_session(name);
        assert!(session.has_journal, "{name} carries a journal block");
        let encoded = encode_session(&session).expect("encode session");
        let roundtrip =
            parse_session(encoded.as_bytes()).unwrap_or_else(|e| panic!("reparse {name}: {e}"));
        assert!(roundtrip.has_journal, "{name} roundtrip keeps journal");
        assert_eq!(roundtrip.journal, session.journal, "{name} journal fields");
        assert_eq!(
            roundtrip.journal.epoch, session.journal.epoch,
            "{name} epoch"
        );
        let raw = fixture_text(name, "events.ndjson");
        let mut events = Vec::new();
        for line in raw.split('\n') {
            if line.is_empty() {
                continue;
            }
            let event =
                parse_event(line.as_bytes()).unwrap_or_else(|e| panic!("parse {name} line: {e}"));
            assert!(
                event.has_journal && event.journal_version,
                "{name} line is journal-typed"
            );
            let wire = encode_event_line(&event).expect("encode line");
            assert_eq!(
                wire,
                format!("{line}\n").into_bytes(),
                "{name} line re-encodes byte-exact"
            );
            let again = parse_event(&wire).unwrap_or_else(|e| panic!("reparse {name}: {e}"));
            assert_eq!(
                again.journal.native_result, event.journal.native_result,
                "{name} native result"
            );
            assert_eq!(
                again.journal.requested_native_pages, event.journal.requested_native_pages,
                "{name} native pages"
            );
            assert_eq!(
                again.journal.operation_token.has, event.journal.operation_token.has,
                "{name} token presence"
            );
            let window = session
                .journal
                .window(session.window_start_ns, session.finalized)
                .unwrap_or_else(|e| panic!("{name} window: {e}"));
            let result = event
                .journal
                .to_result(event.ts_ns, 0)
                .unwrap_or_else(|e| panic!("{name} result: {e}"));
            window
                .validate_result(&result)
                .unwrap_or_else(|e| panic!("{name} membership: {e}"));
            events.push(event);
        }
        // Typed-derivable equalities against the carried oracle files.
        let expected = fixture_text(name, "expected.json");
        let report = fixture_text(name, "report.json");
        assert!(frozen_bool(&expected, "valid"), "{name} oracle verdict");
        let requests = frozen_u64_or_null(&expected, "requests").expect("requests known");
        assert_eq!(events.len() as u64, requests, "{name} request lines");
        assert_eq!(
            frozen_u64_or_null(&report, "requests"),
            Some(requests),
            "{name} report requests"
        );
        let failures = events
            .iter()
            .filter(|e| e.journal.native_result != 0)
            .count() as u64;
        assert_eq!(
            frozen_u64_or_null(&expected, "failures"),
            Some(failures),
            "{name} oracle failures"
        );
        assert_eq!(
            frozen_u64_or_null(&report, "failures"),
            Some(failures),
            "{name} report failures"
        );
        let unmatched = events
            .iter()
            .filter(|e| e.journal.membership == "unmatched_exit")
            .count() as u64;
        assert_eq!(
            frozen_u64_or_null(&report, "unmatched_exits"),
            Some(unmatched),
            "{name} report unmatched"
        );
        let mut bytes = Some(0u64);
        for event in &events {
            match bytes {
                None => break,
                Some(sum) => {
                    bytes = if event.journal.requested_bytes.has {
                        Some(sum + event.journal.requested_bytes.value)
                    } else {
                        None
                    };
                }
            }
        }
        assert_eq!(
            frozen_u64_or_null(&report, "requested_bytes"),
            bytes,
            "{name} report bytes"
        );
        let censored = &session.journal.counters[4];
        assert_eq!(
            frozen_u64_or_null(&report, "censored"),
            censored.has.then_some(censored.value),
            "{name} report censored"
        );
    }
}

#[test]
fn normalization_sequence_and_unknown_counters() {
    assert_eq!(JOURNAL_COUNTER_COUNT, 11);
    assert_eq!(JOURNAL_NATIVE_COUNTERS, 15);
    let mut capture = JournalCapture::new(
        23,
        10,
        "linux-7.0.14-x86-journal-provisional".to_string(),
        false,
    );
    let mut counters = vec![0u64; JOURNAL_NATIVE_COUNTERS];
    let initial = capture
        .snapshot(11, false, &counters, true)
        .expect("open snapshot");
    assert!(!initial.admission_start_ns.has && !initial.counters[4].has);
    assert!(!initial.counters[10].has);
    capture.opened(12).expect("admission opens");
    let mut raw = vec![0u8; 72];
    raw[0] = 77;
    raw[1] = 86;
    raw[2] = 74;
    raw[3] = 82;
    raw[4] = 1;
    raw[6] = 1;
    raw[8] = 1;
    raw[10] = 1;
    raw[24] = 30;
    raw[32] = 23;
    raw[40] = 9;
    raw[48] = 20;
    raw[56] = 3;
    raw[60] = 251;
    raw[61] = 255;
    raw[62] = 255;
    raw[63] = 255;
    let event = capture.consume(&raw, "capture", 31).expect("first result");
    assert_eq!(event.journal.native_result, -5);
    assert_eq!(event.journal.requested_bytes.value, 12288);
    assert_eq!(event.source_correlation, "direct");
    assert!(capture.consume(&raw, "capture", 31).is_err());
    capture.closed(32, true).expect("admission closes");
    raw[16] = 3;
    raw[24] = 40;
    capture.consume(&raw, "capture", 41).expect("gapped result");
    assert_eq!(capture.sequence_gaps, 2);
    counters[12] = 5;
    counters[4] = 2;
    let done = capture
        .snapshot(42, true, &counters, true)
        .expect("final snapshot");
    assert_eq!(done.counters[4].value, 7);
    assert_eq!(done.closure, "unproved");
    assert!(!done.counters[10].has);
    let failed = capture
        .snapshot(42, true, &counters, false)
        .expect("unread snapshot");
    assert!(!failed.counters[4].has);
    assert_eq!(failed.counter_reasons[4], "read_failed");
    counters[11] = 1;
    let overflow = capture
        .snapshot(42, true, &counters, true)
        .expect("overflow snapshot");
    assert!(!overflow.counters[0].has);
    assert_eq!(overflow.counter_reasons[0], "overflow");
    let control = encode_journal_control(23, 12, 32, false, true, false);
    assert_eq!(control.len(), 48);
    assert_eq!(control[32], 1);
    assert!(decode_journal_counters(&control).is_err());
}

/// Closed-resource stub: pins the seven trait signatures at compile
/// time and documents the closed-state contract (refuse use, accept
/// teardown). Positive open/attach/control behavior belongs to the
/// producer slice, not this typed boundary.
struct ClosedJournal;

impl JournalKernel for ClosedJournal {
    fn prepare(&mut self, _control: &[u8]) -> OpOut {
        OpOut {
            ok: false,
            message: "journal not open".to_string(),
        }
    }

    fn attach(&mut self) -> OpOut {
        OpOut {
            ok: false,
            message: "journal not open".to_string(),
        }
    }

    fn control(&mut self, _value: &[u8]) -> OpOut {
        OpOut {
            ok: false,
            message: "journal not open".to_string(),
        }
    }

    fn poll(&mut self, _timeout_ms: i64) -> JournalPoll {
        JournalPoll {
            ok: false,
            data: Vec::new(),
        }
    }

    fn counters(&mut self) -> JournalCounters {
        JournalCounters {
            ok: false,
            values: Vec::new(),
        }
    }

    fn detach(&mut self) -> OpOut {
        OpOut {
            ok: true,
            message: String::new(),
        }
    }

    fn close(&mut self) -> OpOut {
        OpOut {
            ok: true,
            message: String::new(),
        }
    }
}

#[test]
fn native_adapter_contract_without_resources() {
    let mut source = ClosedJournal;
    assert!(!source.attach().ok);
    assert!(!source.poll(0).ok);
    assert!(!source.counters().ok);
    assert!(source.detach().ok && source.close().ok);
}

#[test]
fn duplicate_tokens_classify_at_typed_level() {
    let session = scenario_session("duplicate");
    assert!(session.has_journal);
    let events = scenario_events("duplicate");
    assert_eq!(events.len(), 2);
    for event in &events {
        assert!(event.has_journal && event.journal_version);
    }
    // Both lines are well-typed journal results sharing one operation
    // token; the carried `valid: false` verdict is a replay-level
    // duplicate-token refusal owned by the analysis follow-on, not by
    // this typed boundary.
    let first = &events[0].journal;
    let second = &events[1].journal;
    assert!(first.operation_token.has && second.operation_token.has);
    assert_eq!(first.operation_token.value, second.operation_token.value);
    let expected = fixture_text("duplicate", "expected.json");
    assert!(!frozen_bool(&expected, "valid"));
    assert_eq!(frozen_u64_or_null(&expected, "requests"), Some(2));
}

fn stage_capture(name: &str, session: &[u8], events: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("journal-model-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("stage dir");
    std::fs::write(dir.join("session.json"), session).expect("stage session");
    std::fs::write(dir.join("events.ndjson"), events).expect("stage events");
    dir
}

#[test]
fn reader_ingests_journal_capture() {
    let mut reader = read_capture("tests/fixtures/journal/success", false, default_limits())
        .expect("open journal capture");
    let mut count = 0;
    while reader.has_more().expect("stream") {
        let event = reader.next_event().expect("journal event");
        assert!(event.has_journal && event.journal_version);
        count += 1;
    }
    assert_eq!(count, 1);
}

#[test]
fn reader_refuses_schema_mode_mismatch() {
    // Journal session with a legacy event line.
    let session = fixture_bytes("success", "session.json");
    let legacy =
        std::fs::read_to_string("tests/fixtures/reader/ev012/events.ndjson").expect("legacy lines");
    let line = legacy.lines().next().expect("one legacy line");
    assert!(line.contains("\"session_id\": \"ev012-session\""));
    let mixed = line.replacen(
        "\"session_id\": \"ev012-session\"",
        "\"session_id\": \"journal-success\"",
        1,
    );
    let dir = stage_capture("mode-journal-session", &session, &format!("{mixed}\n"));
    let mut reader = read_capture(dir.to_str().expect("utf8 dir"), false, default_limits())
        .expect("open mixed capture");
    assert!(reader.has_more().expect("stream"));
    let err = reader.next_event().expect_err("mode must refuse");
    assert_eq!(err.line_no, 1);
    assert!(err.message.contains("event/session schema mode mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
    // Legacy session with a journal event line.
    let legacy_session =
        std::fs::read("tests/fixtures/reader/ev012/session.json").expect("legacy session");
    let journal_line = fixture_text("success", "events.ndjson");
    let journal_line = journal_line.lines().next().expect("one journal line");
    assert!(journal_line.contains("\"session_id\":\"journal-success\""));
    let mixed = journal_line.replacen(
        "\"session_id\":\"journal-success\"",
        "\"session_id\":\"ev012-session\"",
        1,
    );
    let dir = stage_capture(
        "mode-legacy-session",
        &legacy_session,
        &format!("{mixed}\n"),
    );
    let mut reader = read_capture(dir.to_str().expect("utf8 dir"), false, default_limits())
        .expect("open mixed capture");
    assert!(reader.has_more().expect("stream"));
    let err = reader.next_event().expect_err("mode must refuse");
    assert_eq!(err.line_no, 1);
    assert!(err.message.contains("event/session schema mode mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn reader_refuses_journal_profile_and_window_mismatch() {
    let session = fixture_bytes("success", "session.json");
    let journal_line = fixture_text("success", "events.ndjson");
    let journal_line = journal_line
        .lines()
        .next()
        .expect("one journal line")
        .to_string();
    // Wrong source profile against the session journal profile.
    let bad_profile = journal_line.replacen(
        "\"profile_id\":\"linux-7.0.14-x86-journal-provisional\"",
        "\"profile_id\":\"other-profile\"",
        1,
    );
    assert_ne!(bad_profile, journal_line);
    let dir = stage_capture("profile-mismatch", &session, &format!("{bad_profile}\n"));
    let mut reader = read_capture(dir.to_str().expect("utf8 dir"), false, default_limits())
        .expect("open mixed capture");
    assert!(reader.has_more().expect("stream"));
    let err = reader.next_event().expect_err("profile must refuse");
    assert_eq!(err.line_no, 1);
    assert!(err.message.contains("journal profile/window mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
    // Matched entry before admission start: parses (entry predates the
    // exit) but lands outside the admission window.
    let bad_entry = journal_line.replacen(
        "\"entry_ns\":\"1000000010\"",
        "\"entry_ns\":\"999999999\"",
        1,
    );
    assert_ne!(bad_entry, journal_line);
    let dir = stage_capture("window-mismatch", &session, &format!("{bad_entry}\n"));
    let mut reader = read_capture(dir.to_str().expect("utf8 dir"), false, default_limits())
        .expect("open mixed capture");
    assert!(reader.has_more().expect("stream"));
    let err = reader.next_event().expect_err("window must refuse");
    assert_eq!(err.line_no, 1);
    assert!(err.message.contains("journal profile/window mismatch"));
    let _ = std::fs::remove_dir_all(&dir);
}

fn replay_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

/// Replay renders journal captures: exit 0 with conversion findings.
///
/// The reducer follow-on retired the exit-2 refusal: both replay
/// verbs now produce a journal report for journal captures.
#[test]
fn replay_renders_journal_capture() {
    for (verb, extra) in [("report", &[][..]), ("top", &["--interval", "1s"][..])] {
        let out = Command::new(replay_bin())
            .arg(verb)
            .args(extra)
            .arg("tests/fixtures/journal/success")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap_or_else(|e| panic!("run {verb} on journal capture: {e}"));
        assert_eq!(out.status.code(), Some(0), "{verb} exit");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.contains("conversion journal 1 requests (1 successes, 0 failures)"),
            "{verb} findings: {stdout}"
        );
        assert!(
            !stdout.contains("journal capture refused"),
            "{verb} must not refuse: {stdout}"
        );
    }
}

/// Legacy captures replay exactly as before through both verbs.
///
/// Exit 0 on both, and the final top block body equals report
/// stdout byte for byte (replay-prefix equivalence), pinning zero
/// behavior change on the non-journal path.
#[test]
fn replay_legacy_capture_unchanged() {
    let dir = "tests/fixtures/reader/sealed-complete";
    let report = Command::new(replay_bin())
        .arg("report")
        .arg(dir)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run report on legacy capture");
    assert_eq!(report.status.code(), Some(0));
    assert!(!report.stdout.is_empty());
    assert!(
        !String::from_utf8_lossy(&report.stderr).contains("journal"),
        "legacy report names no journal"
    );
    let top = Command::new(replay_bin())
        .arg("top")
        .arg("--interval")
        .arg("1s")
        .arg(dir)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run top on legacy capture");
    assert_eq!(top.status.code(), Some(0));
    let text = String::from_utf8_lossy(&top.stdout);
    let blocks: Vec<&str> = text.split("--- refresh ").collect();
    assert!(blocks.len() >= 2, "top prints a final block");
    let last = blocks[blocks.len() - 1];
    let body = last.split_once('\n').expect("header line").1;
    assert_eq!(body.as_bytes(), report.stdout.as_slice());
}
