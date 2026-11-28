// SPDX-License-Identifier: GPL-3.0-or-later
//! Conversion-journal report suite: reducer equality against the frozen
//! 0.2.0 oracles plus text/Markdown/JSON/top presentation legs.
//!
//! Every aggregate here is derived from the typed model plus the frozen
//! fixtures: per-scenario request counts, native failures, censored
//! operations, and explicit unavailable state totals must match the
//! carried `expected.json` / `report.json` scalars; the four
//! renderings (text, Markdown, JSON, top replay) share one reduction;
//! large values stay exact; and the four forbidden outcomes (inferred
//! host access, missing-baseline zero, synthetic provenance loss,
//! unattributed exact physical union) are each pinned by a negative
//! leg. Generated JSON must validate against
//! `schemas/report-v0.2.0.schema.json` via the frozen contract tool.

use memveil::analysis::journal_conversions::{
    JOURNAL_EXCLUSIONS, JOURNAL_REPLAY_INTERVAL_BUDGET, JournalAnalyzer,
};
use memveil::model::common::MaybeU64;
use memveil::model::event::{Event, parse_event};
use memveil::model::journal_event::JournalEvent;
use memveil::model::session::parse_session;
use memveil::platform::hash::sha256_hex;
use std::path::PathBuf;
use std::process::Command;

/// The 12 frozen scenarios carrying reports.
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

/// Checkpoint scenarios need `--allow-partial` to open.
fn is_checkpoint(name: &str) -> bool {
    name == "initial-checkpoint" || name == "open-checkpoint"
}

fn fixture_text(name: &str, file: &str) -> String {
    std::fs::read_to_string(format!("tests/fixtures/journal/{name}/{file}"))
        .unwrap_or_else(|e| panic!("read fixture {name}/{file}: {e}"))
}

fn replay_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_memveil"))
}

fn run_report(name: &str, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(replay_bin());
    cmd.arg("report")
        .args(extra)
        .arg(format!("tests/fixtures/journal/{name}"))
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.output().expect("run memveil report")
}

fn run_top(name: &str, extra: &[&str]) -> std::process::Output {
    let mut args: Vec<&str> = vec!["--interval", "1s"];
    args.extend(extra.iter().copied());
    let mut cmd = Command::new(replay_bin());
    cmd.arg("top")
        .args(&args)
        .arg(format!("tests/fixtures/journal/{name}"))
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.output().expect("run memveil top")
}

/// Top-level `"key":` value tail of a flat oracle document.
fn oracle_tail(doc: &str, key: &str) -> String {
    let pat = format!("\"{key}\":");
    let mut hits = doc.match_indices(&pat);
    let (pos, _) = hits.next().unwrap_or_else(|| panic!("{key} present"));
    assert!(hits.next().is_none(), "{key} occurs once");
    doc[pos + pat.len()..].trim_start().to_string()
}

fn oracle_bool(doc: &str, key: &str) -> bool {
    let tail = oracle_tail(doc, key);
    if tail.starts_with("true") {
        return true;
    }
    assert!(tail.starts_with("false"), "{key} is a bool");
    false
}

fn oracle_quoted(doc: &str, key: &str) -> String {
    let tail = oracle_tail(doc, key);
    assert!(tail.starts_with('"'), "{key} is quoted");
    let end = tail[1..].find('"').expect("closing quote");
    tail[1..1 + end].to_string()
}

fn oracle_int(doc: &str, key: &str) -> i64 {
    let tail = oracle_tail(doc, key);
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    assert!(!digits.is_empty(), "{key} is an integer");
    digits.parse().expect("integer digits")
}

/// Report verbs over one scenario with the flags it needs.
fn scenario_args(name: &str) -> Vec<&'static str> {
    if is_checkpoint(name) {
        vec!["--allow-partial"]
    } else {
        vec![]
    }
}

/// Deep-compare one generated journal JSON against its oracles.
///
/// The frozen `report.json` pins the journal measurements, verdict,
/// findings, quality echo, limitations, and integrity; the session
/// pins provenance. Only the engine identity differs: fixtures carry
/// `contract-fixture`, the binary stamps its own version.
fn assert_oracle_equal(name: &str, generated: &std::path::Path) {
    let session = if is_checkpoint(name) {
        "checkpoint.json"
    } else {
        "session.json"
    };
    let script = r#"
import json, sys
gen = json.load(open(sys.argv[1]))
ora = json.load(open(sys.argv[2]))
ses = json.load(open(sys.argv[3]))
assert gen["schema_version"] == "0.2.0", "schema version"
for key in ("session_id", "synthetic", "environment", "device_catalog"):
    assert gen[key] == ses[key] == ora[key], "provenance " + key
assert gen["engine_version"].startswith("memveil-"), "engine identity"
assert ora["engine_version"] == "contract-fixture", "oracle engine"
assert gen["quality"] == ses["quality"] == ora["quality"], "quality echo"
assert gen["verdict"] == ora["verdict"], "verdict"
assert gen["verdict"] == {"name": "partial_unknown_loss", "loss_ratio_bps": "0", "delivered": "0"}, "verdict value"
assert gen["metrics"] == [] == ora["metrics"], "no ordinary metrics"
assert gen["findings"] == ora["findings"], "findings"
for item in ora["limitations"]:
    assert item in gen["limitations"], "limitation: " + item
assert gen["integrity"] == ora["integrity"], "integrity"
assert gen["journal"] == ora["journal"], "journal measurements"
print("journal-oracle-ok")
"#;
    let out = Command::new("python3")
        .args([
            "-c",
            script,
            generated.to_str().expect("utf8 path"),
            &format!("tests/fixtures/journal/{name}/report.json"),
            &format!("tests/fixtures/journal/{name}/{session}"),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run oracle comparison");
    assert!(
        out.status.success(),
        "{name} oracle comparison failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "journal-oracle-ok"
    );
}

/// Validate one generated journal JSON against the frozen 0.2.0 report
/// schema using the frozen contract tool's own validator.
fn assert_schema_valid(generated: &std::path::Path) {
    let script = r#"
import importlib.machinery, json, sys
loader = importlib.machinery.SourceFileLoader("journal_contracts", "tools/validate-journal-contracts")
contract = loader.load_module()
contract.validate_document(json.load(open(sys.argv[1])), "report-v0.2.0")
print("schema-ok")
"#;
    let out = Command::new("python3")
        .args(["-c", script, generated.to_str().expect("utf8 path")])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run schema validation");
    assert!(
        out.status.success(),
        "schema validation failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "schema-ok");
}

fn stage_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("journal-reports-{}-{tag}", std::process::id()))
}

fn write_staged(tag: &str, session: &str, events: &str) -> PathBuf {
    let dir = stage_path(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("stage dir");
    std::fs::write(dir.join("session.json"), session).expect("stage session");
    std::fs::write(dir.join("events.ndjson"), events).expect("stage events");
    dir
}

/// Per-scenario reduction equals the frozen oracles.
///
/// Exit codes follow `expected.json` (`report_exit` 4 only for the
/// checkpoint recoveries); every JSON scalar equals the carried
/// `report.json`; and every generated JSON validates against the
/// frozen 0.2.0 report schema.
#[test]
fn journal_reports_match_frozen_oracles() {
    for name in SCENARIOS {
        let expected = fixture_text(name, "expected.json");
        assert!(oracle_bool(&expected, "valid"), "{name} oracle verdict");
        let want_exit = oracle_int(&expected, "report_exit");
        let mut args = scenario_args(name);
        args.push("--format");
        args.push("json");
        let out = run_report(name, &args);
        assert_eq!(out.status.code(), Some(want_exit as i32), "{name} exit");
        assert!(out.stdout.starts_with(b"{\n"), "{name} prints JSON");
        let dir = stage_path(&format!("oracle-{name}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("stage dir");
        let generated = dir.join("report.json");
        std::fs::write(&generated, &out.stdout).expect("stage generated JSON");
        assert_oracle_equal(name, &generated);
        assert_schema_valid(&generated);
        let requests = oracle_quoted(&expected, "requests");
        let failures = oracle_quoted(&expected, "failures");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("\"requests\": \"{requests}\"")),
            "{name} requests scalar"
        );
        assert!(
            text.contains(&format!("\"failures\": \"{failures}\"")),
            "{name} failures scalar"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Text and Markdown renderings match the committed journal goldens.
#[test]
fn journal_text_and_markdown_match_goldens() {
    for name in SCENARIOS {
        let args = scenario_args(name);
        let text = run_report(name, &args);
        let want_exit = if is_checkpoint(name) { 4 } else { 0 };
        assert_eq!(text.status.code(), Some(want_exit), "{name} text exit");
        let golden = std::fs::read(format!("tests/golden/report-journal-{name}.txt"))
            .unwrap_or_else(|e| panic!("read golden {name}.txt: {e}"));
        assert_eq!(text.stdout, golden, "{name} text golden");
        let mut md_args = scenario_args(name);
        md_args.push("--format");
        md_args.push("markdown");
        let md = run_report(name, &md_args);
        assert_eq!(md.status.code(), Some(want_exit), "{name} markdown exit");
        let golden = std::fs::read(format!("tests/golden/report-journal-{name}.md"))
            .unwrap_or_else(|e| panic!("read golden {name}.md: {e}"));
        assert_eq!(md.stdout, golden, "{name} markdown golden");
    }
}

/// Top replay ends where report stands: same reduction, fourth rendering.
///
/// The final top block body equals report text stdout byte for byte on
/// every scenario, pinning replay-prefix equivalence for journal
/// captures the way the legacy suite pins it for ordinary captures.
#[test]
fn journal_top_replay_equals_report() {
    for name in SCENARIOS {
        let args = scenario_args(name);
        let report = run_report(name, &args);
        let want_exit = if is_checkpoint(name) { 4 } else { 0 };
        assert_eq!(report.status.code(), Some(want_exit), "{name} report exit");
        let mut top_args = scenario_args(name);
        top_args.push("--full");
        let top = run_top(name, &top_args);
        assert_eq!(top.status.code(), Some(want_exit), "{name} top exit");
        let text = String::from_utf8_lossy(&top.stdout);
        let blocks: Vec<&str> = text.split("--- refresh ").collect();
        assert!(blocks.len() >= 2, "{name} top prints a final block");
        let last = blocks[blocks.len() - 1];
        let body = last.split_once('\n').expect("header line").1;
        assert_eq!(
            body.as_bytes(),
            report.stdout.as_slice(),
            "{name} final block"
        );
        let compact = run_top(name, &scenario_args(name));
        assert_eq!(
            compact.status.code(),
            Some(want_exit),
            "{name} compact top exit"
        );
    }
}

/// Duplicate operation tokens refuse at replay: exit 2, no report.
#[test]
fn journal_duplicate_token_refuses() {
    let expected = fixture_text("duplicate", "expected.json");
    assert!(!oracle_bool(&expected, "valid"));
    assert_eq!(oracle_quoted(&expected, "requests"), "2");
    for (verb, extra) in [("report", &[][..]), ("top", &["--interval", "1s"][..])] {
        let out = Command::new(replay_bin())
            .arg(verb)
            .args(extra)
            .arg("tests/fixtures/journal/duplicate")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .unwrap_or_else(|e| panic!("run {verb} on duplicate: {e}"));
        assert_eq!(out.status.code(), Some(2), "{verb} exit");
        assert!(out.stdout.is_empty(), "{verb} prints no report");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("duplicate operation token"),
            "{verb} names the refusal: {stderr}"
        );
    }
}

/// Verdict and `--strict` exits: journal verdicts never complete.
#[test]
fn journal_verdict_and_strict_exits() {
    for name in SCENARIOS {
        let mut args = scenario_args(name);
        args.push("--strict");
        let out = run_report(name, &args);
        assert_eq!(out.status.code(), Some(4), "{name} strict exit");
        assert!(!out.stdout.is_empty(), "{name} strict still prints");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("verdict: partial_unknown_loss"),
            "{name} verdict line"
        );
    }
    let plain = run_report("success", &[]);
    assert_eq!(plain.status.code(), Some(0));
    let checkpoint = run_report("open-checkpoint", &["--allow-partial"]);
    assert_eq!(checkpoint.status.code(), Some(4));
}

/// The four constant exclusions ride on every journal report.
#[test]
fn journal_exclusions_on_every_rendering() {
    let request_only = "Synthetic request/results only; no persistent region identity, baseline or global closure.";
    for name in SCENARIOS {
        let args = scenario_args(name);
        let text = run_report(name, &args);
        let body = String::from_utf8_lossy(&text.stdout);
        assert!(body.contains(request_only), "{name} text request-only");
        for exclusion in JOURNAL_EXCLUSIONS {
            assert!(body.contains(exclusion), "{name} text: {exclusion}");
        }
        let mut md_args = scenario_args(name);
        md_args.push("--format");
        md_args.push("markdown");
        let md = String::from_utf8_lossy(&run_report(name, &md_args).stdout).into_owned();
        assert!(md.contains(request_only), "{name} markdown request-only");
        for exclusion in JOURNAL_EXCLUSIONS {
            assert!(md.contains(exclusion), "{name} markdown: {exclusion}");
        }
        let mut json_args = scenario_args(name);
        json_args.push("--format");
        json_args.push("json");
        let json = String::from_utf8_lossy(&run_report(name, &json_args).stdout).into_owned();
        assert!(json.contains(request_only), "{name} json request-only");
        for exclusion in JOURNAL_EXCLUSIONS {
            assert!(json.contains(exclusion), "{name} json: {exclusion}");
        }
        let top = String::from_utf8_lossy(&run_top(name, &scenario_args(name)).stdout).into_owned();
        assert!(top.contains(request_only), "{name} top request-only");
        for exclusion in JOURNAL_EXCLUSIONS {
            assert!(top.contains(exclusion), "{name} top: {exclusion}");
        }
    }
}

/// One staged journal event line, edited from the success template.
struct StagedLine {
    seq: u64,
    ts_ns: u64,
    token: Option<u64>,
    entry_ns: u64,
    pages: i32,
    native_result: i32,
    encrypt: bool,
    caller: &'static str,
}

impl StagedLine {
    fn admitted(seq: u64, token: u64) -> Self {
        Self {
            seq,
            ts_ns: 1000000100 + seq,
            token: Some(token),
            entry_ns: 1000000010 + seq,
            pages: 1,
            native_result: 0,
            encrypt: false,
            caller: "disabled",
        }
    }

    fn render(&self, session_id: &str) -> String {
        let (direction, state, hook) = if self.encrypt {
            ("encrypt", "private", "set_memory_encrypted")
        } else {
            ("decrypt", "shared", "set_memory_decrypted")
        };
        let (membership, token, entry, correlation) = match self.token {
            Some(t) => (
                "admitted",
                format!("\"{t}\""),
                format!("\"{}\"", self.entry_ns),
                "direct",
            ),
            None => (
                "unmatched_exit",
                "null".to_string(),
                "null".to_string(),
                "unpaired",
            ),
        };
        let (pages, bytes, size_reason) = if self.pages < 0 {
            (
                self.pages.to_string(),
                "null".to_string(),
                "\"invalid_native_pages\"".to_string(),
            )
        } else {
            (
                self.pages.to_string(),
                format!("\"{}\"", self.pages as u64 * 4096),
                "null".to_string(),
            )
        };
        let caller = match self.caller {
            "resolved" => {
                "{\"status\":\"resolved\",\"class\":\"swiotlb\",\"label\":\"swiotlb_alloc_tlb\"}"
                    .to_string()
            }
            other => format!("{{\"status\":\"{other}\",\"class\":null,\"label\":null}}"),
        };
        format!(
            "{{\"schema_version\":\"0.2.0\",\"session_id\":\"{session_id}\",\"seq\":\"{}\",\"ts_ns\":\"{}\",\"kind\":\"transition_result\",\"source\":{{\"hook\":\"{hook}\",\"backend\":\"synthetic\",\"profile_id\":\"linux-7.0.14-x86-journal-provisional\",\"measurement\":\"observed\",\"correlation\":\"{correlation}\"}},\"data\":{{\"direction\":\"{direction}\",\"requested_state\":\"{state}\",\"requested_native_pages\":{pages},\"requested_pages\":{},\"requested_bytes\":{bytes},\"size_reason\":{size_reason},\"page_size\":\"4096\",\"native_result\":{},\"operation_token\":{token},\"entry_ns\":{entry},\"epoch\":\"1\",\"membership\":\"{membership}\",\"region\":null,\"region_reason\":\"request_only_source\",\"effect\":\"request_only\",\"caller\":{caller}}}}}\n",
            self.seq,
            self.ts_ns,
            if self.pages < 0 {
                "null".to_string()
            } else {
                format!("\"{}\"", self.pages)
            },
            self.native_result,
        )
    }
}

/// Stage a capture from the success session template with rebuilt
/// integrity over `events`.
fn stage_journal(
    tag: &str,
    session_id: &str,
    events: &str,
    session_edits: &[(&str, &str)],
) -> PathBuf {
    let lines: Vec<&str> = events.split_inclusive('\n').collect();
    let bytes = events.len() as u64;
    let count = lines.len() as u64;
    let mut session = std::fs::read_to_string("tests/fixtures/journal/success/session.json")
        .expect("read success session template");
    session = session.replacen(
        "\"session_id\": \"journal-success\"",
        &format!("\"session_id\": \"{session_id}\""),
        1,
    );
    assert!(session.contains(session_id));
    session = session.replacen(
        "\"events_bytes\": \"682\"",
        &format!("\"events_bytes\": \"{bytes}\""),
        1,
    );
    session = session.replacen(
        "\"line_count\": \"1\"",
        &format!("\"line_count\": \"{count}\""),
        1,
    );
    if count == 0 {
        session = session.replacen("\"first_seq\": \"0\"", "\"first_seq\": null", 1);
        session = session.replacen("\"last_seq\": \"0\"", "\"last_seq\": null", 1);
    } else {
        session = session.replacen(
            "\"last_seq\": \"0\"",
            &format!("\"last_seq\": \"{}\"", count - 1),
            1,
        );
    }
    let digest = sha256_hex(events.as_bytes());
    let old = session
        .split("\"events_sha256\": \"")
        .nth(1)
        .and_then(|tail| tail.split('"').next())
        .expect("template digest")
        .to_string();
    session = session.replacen(
        &format!("\"events_sha256\": \"{old}\""),
        &format!("\"events_sha256\": \"{digest}\""),
        1,
    );
    session = session.replacen(
        "\"transition_result\": \"1\"",
        &format!("\"transition_result\": \"{count}\""),
        1,
    );
    for (from, to) in session_edits {
        let next = session.replacen(from, to, 1);
        assert_ne!(next, session, "session edit applies: {from}");
        session = next;
    }
    // The staged session must parse before the CLI ever sees it.
    parse_session(session.as_bytes()).expect("staged session parses");
    for line in events.split('\n') {
        if line.is_empty() {
            continue;
        }
        parse_event(line.as_bytes()).expect("staged line parses");
    }
    write_staged(tag, &session, events)
}

fn run_report_dir(dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    let mut cmd = Command::new(replay_bin());
    cmd.arg("report").args(extra).arg(dir);
    cmd.current_dir(env!("CARGO_MANIFEST_DIR"));
    cmd.output().expect("run memveil report")
}

/// One synthetic journal event for in-process reducer legs.
fn synthetic_event(seq: u64, token: u64, bytes: Option<u64>) -> Event {
    Event {
        has_journal: true,
        journal_version: true,
        seq,
        journal: JournalEvent {
            operation_token: MaybeU64::of(token),
            requested_bytes: bytes.map_or(MaybeU64::absent(), MaybeU64::of),
            ..JournalEvent::default()
        },
        ..Event::default()
    }
}

/// Values above the exact double range stay exact everywhere.
#[test]
fn journal_values_above_double_range_stay_exact() {
    // 1025 maximal requests: 9015995343564800 requested bytes, past
    // 2^53 (9007199254740992), inside u64. Quoted decimals carry it
    // exactly; a float round-trip would not.
    let mut events = String::new();
    for i in 0..1025u64 {
        let mut line = StagedLine::admitted(i, i + 1);
        line.pages = 2147483647;
        events.push_str(&line.render("journal-staged-big"));
    }
    let dir = stage_journal("big", "journal-staged-big", &events, &[]);
    let out = run_report_dir(&dir, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let generated = dir.join("report.json");
    std::fs::write(&generated, &out.stdout).expect("stage generated JSON");
    assert_schema_valid(&generated);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"requested_bytes\": \"9015995343564800\""),
        "exact sum above 2^53"
    );
    assert!(text.contains("\"requests\": \"1025\""), "request count");
    // The sum sits above 2^53 and the JSON carries it as an exact
    // canonical decimal, never float formatting.
    let probe = Command::new("python3")
        .args([
            "-c",
            "import json,sys; d=json.load(open(sys.argv[1])); v=d['journal']['requested_bytes']; assert v == '9015995343564800', v; assert int(v) > 2**53, 'above exact double range'; assert repr(float(v)) != v, 'never float formatting'",
            generated.to_str().expect("utf8 path"),
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run float probe");
    assert!(
        probe.status.success(),
        "float probe: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    let text_out = run_report_dir(&dir, &[]);
    assert_eq!(text_out.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&text_out.stdout).contains("9015995343564800"),
        "text keeps the exact integer"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Requested-byte overflow goes unavailable with its reason.
#[test]
fn journal_requested_byte_overflow_is_unavailable() {
    let raw = std::fs::read("tests/fixtures/journal/success/session.json").expect("template");
    let session = parse_session(&raw).expect("parse template");
    let mut analyzer = JournalAnalyzer::new(session);
    for (seq, token, bytes) in [(0u64, 1u64, u64::MAX), (1, 2, 4096)] {
        analyzer
            .consume(&synthetic_event(seq, token, Some(bytes)))
            .expect("consume");
    }
    let reduced = analyzer.finish(2500000000, false).expect("finish");
    assert_eq!(reduced.summary.requested_bytes, None);
    assert_eq!(reduced.summary.requested_bytes_reason, "overflow");
    assert_eq!(reduced.summary.requests, 2);
}

/// Token history merges contiguous runs and refuses past its budget.
#[test]
fn journal_token_history_budget() {
    let raw = std::fs::read("tests/fixtures/journal/success/session.json").expect("template");
    let session = parse_session(&raw).expect("parse template");
    let mut contiguous = JournalAnalyzer::new(session.clone());
    for token in 1..=70000u64 {
        contiguous
            .consume(&synthetic_event(token - 1, token, None))
            .expect("contiguous tokens merge");
    }
    let reduced = contiguous.finish(2500000000, false).expect("finish");
    assert_eq!(reduced.summary.requests, 70000);
    // Sparse tokens hold one interval each: the 65537th refuses.
    let mut sparse = JournalAnalyzer::new(session);
    for i in 0..JOURNAL_REPLAY_INTERVAL_BUDGET {
        sparse
            .consume(&synthetic_event(i as u64, i as u64 * 2 + 1, None))
            .expect("within budget");
    }
    let err = sparse
        .consume(&synthetic_event(
            JOURNAL_REPLAY_INTERVAL_BUDGET as u64,
            u64::MAX - 1,
            None,
        ))
        .expect_err("past budget refuses");
    assert_eq!(err.message, "journal_token_resource_limit");
    // A repeat refuses as a duplicate, not a resource limit.
    let err = sparse
        .consume(&synthetic_event(
            JOURNAL_REPLAY_INTERVAL_BUDGET as u64 + 1,
            1,
            None,
        ))
        .expect_err("repeat refuses");
    assert_eq!(err.message, "duplicate operation token");
}

/// Cross-direction token repeats refuse: decrypt and encrypt are
/// separate requests, never a paired lifetime.
#[test]
fn journal_cross_direction_duplicate_refuses() {
    let mut events = String::new();
    events.push_str(&StagedLine::admitted(0, 5).render("journal-staged-xdir"));
    let mut second = StagedLine::admitted(1, 5);
    second.encrypt = true;
    events.push_str(&second.render("journal-staged-xdir"));
    let dir = stage_journal("xdir", "journal-staged-xdir", &events, &[]);
    let out = run_report_dir(&dir, &[]);
    assert_eq!(out.status.code(), Some(2));
    assert!(out.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("duplicate operation token"),
        "cross-direction refusal"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unmatched exits count apart from requests and never fail.
#[test]
fn journal_unmatched_exits_stay_apart() {
    let mut events = String::new();
    events.push_str(&StagedLine::admitted(0, 1).render("journal-staged-unmatched"));
    let mut lost = StagedLine::admitted(1, 2);
    lost.token = None;
    lost.native_result = -5;
    events.push_str(&lost.render("journal-staged-unmatched"));
    let dir = stage_journal("unmatched", "journal-staged-unmatched", &events, &[]);
    let out = run_report_dir(&dir, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\"requests\": \"1\""), "only admitted count");
    assert!(
        text.contains("\"failures\": \"0\""),
        "unmatched never fails"
    );
    assert!(
        text.contains("\"unmatched_exits\": \"1\""),
        "unmatched counted"
    );
    assert!(text.contains("\"findings\": []"), "no findings");
    let generated = dir.join("report.json");
    std::fs::write(&generated, &out.stdout).expect("stage generated JSON");
    assert_schema_valid(&generated);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Unknown callers are never leak findings, whatever their status.
#[test]
fn journal_unknown_callers_never_findings() {
    for name in ["unresolved", "disabled"] {
        let out = run_report(name, &["--format", "json"]);
        assert_eq!(out.status.code(), Some(0));
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\"findings\": []"),
            "{name} has no findings"
        );
    }
    for caller in ["ambiguous", "truncated", "resolved"] {
        let mut line = StagedLine::admitted(0, 1);
        line.caller = caller;
        let events = line.render("journal-staged-caller");
        let dir = stage_journal(
            &format!("caller-{caller}"),
            "journal-staged-caller",
            &events,
            &[],
        );
        let out = run_report_dir(&dir, &["--format", "json"]);
        assert_eq!(out.status.code(), Some(0), "{caller} reduces");
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\"findings\": []"),
            "{caller} caller is not a finding"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Finalized evidence with incomplete Detail draws the
/// incomplete-coverage finding; a checkpoint prefix explains itself.
#[test]
fn journal_incomplete_coverage_finding() {
    let line = StagedLine::admitted(0, 1);
    let events = line.render("journal-staged-partial");
    let dir = stage_journal(
        "partial",
        "journal-staged-partial",
        &events,
        &[
            (
                "\"status\": \"complete_for_scope\"",
                "\"status\": \"partial\"",
            ),
            ("\"loss_count\": \"0\"", "\"loss_count\": null"),
        ],
    );
    let out = run_report_dir(&dir, &["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"code\": \"CAPTURE_INCOMPLETE\""),
        "incomplete-coverage finding"
    );
    assert!(
        text.contains("\"evidence_refs\": [\"channel:detail\"]"),
        "evidence reference"
    );
    let generated = dir.join("report.json");
    std::fs::write(&generated, &out.stdout).expect("stage generated JSON");
    assert_schema_valid(&generated);
    let _ = std::fs::remove_dir_all(&dir);
    // The checkpoint oracles stay finding-free: their partial Detail
    // is the prefix itself, not missing evidence.
    for name in ["initial-checkpoint", "open-checkpoint"] {
        let out = run_report(name, &["--allow-partial", "--format", "json"]);
        assert_eq!(out.status.code(), Some(4));
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("\"findings\": []"),
            "{name} prefix needs no finding"
        );
    }
}

/// Region observation stays synthetic: counts without identity.
#[test]
fn journal_regions_stay_synthetic() {
    let raw = std::fs::read("tests/fixtures/journal/overlap/session.json").expect("template");
    let session = parse_session(&raw).expect("parse template");
    let mut analyzer = JournalAnalyzer::new(session);
    let raw = fixture_text("overlap", "events.ndjson");
    for line in raw.split('\n') {
        if line.is_empty() {
            continue;
        }
        let ev = parse_event(line.as_bytes()).expect("parse overlap line");
        analyzer.consume(&ev).expect("consume");
    }
    let reduced = analyzer.finish(2500000000, false).expect("finish");
    assert_eq!(reduced.regions.observed_results, 2);
    let text = run_report("overlap", &[]);
    let body = String::from_utf8_lossy(&text.stdout);
    assert!(
        body.contains("established: 0 (request-only source; no region identity)"),
        "no identity established"
    );
    assert!(
        body.contains("observed results: 2 (request-only; no lifetime netting)"),
        "observation without netting"
    );
    assert!(!body.contains("outstanding"), "no outstanding ranges");
}

/// Session counters never net into the reduction: alternatives only.
#[test]
fn journal_counters_stay_alternative() {
    let out = run_report("censored", &["--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("\"censored\": \"1\""),
        "terminal censored kept"
    );
    for counter in [
        "entries",
        "matched_results",
        "ring_drops",
        "invalid_records",
    ] {
        assert!(
            !text.contains(counter),
            "counter {counter} never nets into the report"
        );
    }
}

/// No generic leak or expected-revert finding exists anywhere.
#[test]
fn journal_no_generic_leak_or_revert_finding() {
    for name in SCENARIOS {
        let args = scenario_args(name);
        let text = String::from_utf8_lossy(&run_report(name, &args).stdout).into_owned();
        assert!(
            !text.to_lowercase().contains("leak"),
            "{name} text names no leak"
        );
        assert!(
            !text.contains("expected-revert")
                && !text.contains("expected_revert")
                && !text.contains("EXPECTED_REVERT"),
            "{name} text names no expected revert"
        );
        let mut md_args = scenario_args(name);
        md_args.push("--format");
        md_args.push("markdown");
        let md = String::from_utf8_lossy(&run_report(name, &md_args).stdout).into_owned();
        assert!(
            !md.to_lowercase().contains("leak"),
            "{name} markdown names no leak"
        );
    }
    // Finding codes across every scenario stay within the two
    // journal codes.
    let script = r#"
import json, subprocess, sys
allowed = {"CONVERSION_FAILED", "CAPTURE_INCOMPLETE"}
for name in sys.argv[2:]:
    args = ["--allow-partial"] if "checkpoint" in name else []
    p = subprocess.run([sys.argv[1], "report", "--format", "json"] + args + ["tests/fixtures/journal/" + name], capture_output=True, text=True)
    assert p.returncode in (0, 4), (name, p.returncode, p.stderr)
    for finding in json.loads(p.stdout)["findings"]:
        assert finding["code"] in allowed, (name, finding["code"])
print("codes-ok")
"#;
    let mut cmd = Command::new("python3");
    cmd.arg("-c")
        .arg(script)
        .arg(replay_bin())
        .args(SCENARIOS)
        .current_dir(env!("CARGO_MANIFEST_DIR"));
    let out = cmd.output().expect("run code sweep");
    assert!(
        out.status.success(),
        "code sweep: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Forbidden outcome: no inferred host access on any rendering.
#[test]
fn journal_no_inferred_host_access() {
    for name in SCENARIOS {
        let args = scenario_args(name);
        let text = String::from_utf8_lossy(&run_report(name, &args).stdout).into_owned();
        assert!(
            !text.to_lowercase().contains("host"),
            "{name} text infers no host access"
        );
        let mut md_args = scenario_args(name);
        md_args.push("--format");
        md_args.push("markdown");
        let md = String::from_utf8_lossy(&run_report(name, &md_args).stdout).into_owned();
        assert!(
            !md.to_lowercase().contains("host"),
            "{name} markdown infers no host access"
        );
        let mut json_args = scenario_args(name);
        json_args.push("--format");
        json_args.push("json");
        let json = String::from_utf8_lossy(&run_report(name, &json_args).stdout).into_owned();
        assert!(
            !json.to_lowercase().contains("host"),
            "{name} json infers no host access"
        );
        let top = String::from_utf8_lossy(&run_top(name, &scenario_args(name)).stdout).into_owned();
        assert!(
            !top.to_lowercase().contains("host"),
            "{name} top infers no host access"
        );
    }
}

/// Forbidden outcome: the unknown baseline is never reported as zero.
#[test]
fn journal_no_missing_baseline_zero() {
    for name in SCENARIOS {
        let mut args = scenario_args(name);
        args.push("--format");
        args.push("json");
        let json = String::from_utf8_lossy(&run_report(name, &args).stdout).into_owned();
        assert!(
            json.contains(
                "\"baseline\": {\n      \"status\": \"unavailable\",\n      \"loss_count\": null,"
            ),
            "{name} baseline stays unknown"
        );
        let text =
            String::from_utf8_lossy(&run_report(name, &scenario_args(name)).stdout).into_owned();
        assert!(
            text.contains("baseline: unavailable loss=unknown"),
            "{name} text baseline stays unknown"
        );
    }
}

/// Forbidden outcome: synthetic provenance survives every export.
#[test]
fn journal_no_synthetic_provenance_loss() {
    for name in SCENARIOS {
        let args = scenario_args(name);
        let text = String::from_utf8_lossy(&run_report(name, &args).stdout).into_owned();
        assert!(
            text.contains("(synthetic, engine memveil-"),
            "{name} text keeps synthetic provenance"
        );
        let mut md_args = scenario_args(name);
        md_args.push("--format");
        md_args.push("markdown");
        let md = String::from_utf8_lossy(&run_report(name, &md_args).stdout).into_owned();
        assert!(
            md.contains("- synthetic: yes"),
            "{name} markdown keeps synthetic provenance"
        );
        let mut json_args = scenario_args(name);
        json_args.push("--format");
        json_args.push("json");
        let json = String::from_utf8_lossy(&run_report(name, &json_args).stdout).into_owned();
        assert!(
            json.contains("\"synthetic\": true"),
            "{name} json keeps synthetic provenance"
        );
        let top = String::from_utf8_lossy(&run_top(name, &scenario_args(name)).stdout).into_owned();
        assert!(
            top.contains("(synthetic, engine memveil-"),
            "{name} top keeps synthetic provenance"
        );
    }
}

/// Forbidden outcome: no unattributed exact physical union.
#[test]
fn journal_no_unattributed_exact_physical_union() {
    for name in SCENARIOS {
        let mut args = scenario_args(name);
        args.push("--format");
        args.push("json");
        let json = String::from_utf8_lossy(&run_report(name, &args).stdout).into_owned();
        assert!(
            json.contains("\"shared_bytes\": null,")
                && json.contains("\"unreverted_ranges\": null,")
                && json.contains("\"state_reason\": \"request_only_source\""),
            "{name} state totals stay unavailable"
        );
        let body =
            String::from_utf8_lossy(&run_report(name, &scenario_args(name)).stdout).into_owned();
        assert!(
            !body.to_lowercase().contains("physical"),
            "{name} text claims no physical union"
        );
        assert!(
            body.contains("shared bytes: unavailable (request_only_source)"),
            "{name} text withholds shared bytes"
        );
    }
}
