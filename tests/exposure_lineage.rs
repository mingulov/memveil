// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure lineage replay: resolver, normalizer, bounded lineage.
//!
//! Each test replays one synthetic ledger under
//! `tests/exposure/fixtures/lineage/` through the replay
//! module and compares the full outcome against the
//! hand-computed golden beside it. The module compiles
//! through a `#[path]` include until the integration lane
//! wires it into the library; the JSON reader below is the
//! crate's own dependency-free policy reader.
//!
//! Behavior contract: a reused address yields a new
//! generation; alias mappings share one identity and never
//! double-count; ambiguous or failed joins keep UNKNOWN
//! state and never supply missing identity; quarantine is
//! not reuse; capture end is not teardown; clock, suspend
//! and loss gaps bound or void the affected claims;
//! lineage stays bounded per source and per generation;
//! baseline reconciliation is explicit and read-only.

#[path = "../src/analysis/exposure_lineage.rs"]
mod exposure_lineage;

use exposure_lineage::{
    BaselineEntry, LedgerRow, ReplayConfig, ReplayOutcome, distinct_known_objects,
    reconcile, replay,
};
use memveil::platform::policy_reader::{Json, parse_json};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir() -> PathBuf {
    repo_root()
        .join("tests")
        .join("exposure")
        .join("fixtures")
        .join("lineage")
}

fn load_json(name: &str) -> Json {
    let path = fixture_dir().join(name);
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {name}: {err}"));
    parse_json(&text).unwrap_or_else(|err| panic!("parse {name}: {err}"))
}

fn field<'a>(value: &'a Json, key: &str) -> &'a Json {
    match value {
        Json::Obj(entries) => &entries
            .iter()
            .find(|(name, _)| name == key)
            .unwrap_or_else(|| panic!("missing field '{key}'")),
            .1,
        other => panic!("want object for field '{key}', have {other:?}"),
    }
}

fn opt_field<'a>(value: &'a Json, key: &str) -> Option<&'a Json> {
    match value {
        Json::Obj(entries) => entries
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, found)| found),
        _ => None,
    }
}

fn as_str(value: &Json) -> &str {
    match value {
        Json::Str(text) => text,
        other => panic!("want string, have {other:?}"),
    }
}

fn as_u64(value: &Json) -> u64 {
    match value {
        Json::Num(text) => text
            .parse::<u64>()
            .unwrap_or_else(|err| panic!("bad u64 '{text}': {err}")),
        other => panic!("want number, have {other:?}"),
    }
}

fn as_usize(value: &Json) -> usize {
    as_u64(value) as usize
}

fn as_arr(value: &Json) -> &Vec<Json> {
    match value {
        Json::Arr(items) => items,
        other => panic!("want array, have {other:?}"),
    }
}

fn as_bool(value: &Json) -> bool {
    match value {
        Json::Bool(flag) => *flag,
        other => panic!("want bool, have {other:?}"),
    }
}

fn opt_string(value: &Json, key: &str) -> Option<String> {
    match opt_field(value, key) {
        None | Some(Json::Null) => None,
        Some(Json::Str(text)) => Some(text.clone()),
        Some(other) => panic!("want string-or-null for '{key}', have {other:?}"),
    }
}

fn str_vec(value: &Json) -> Vec<String> {
    as_arr(value)
        .iter()
        .map(|item| as_str(item).to_string())
        .collect()
}

fn ledger_row(value: &Json) -> LedgerRow {
    LedgerRow {
        row_id: as_str(field(value, "row_id")).to_string(),
        capture_id: as_str(field(value, "capture_id")).to_string(),
        source_id: as_str(field(value, "source_id")).to_string(),
        object_class: as_str(field(value, "object_class")).to_string(),
        virtual_id: as_str(field(value, "virtual_id")).to_string(),
        event: as_str(field(value, "event")).to_string(),
        seq: as_u64(field(value, "seq")),
        clock_domain: as_str(field(value, "clock_domain")).to_string(),
        alias_of: opt_string(value, "alias_of"),
        atom: opt_string(value, "atom"),
    }
}

fn ledger_config(ledger: &Json) -> ReplayConfig {
    let mut config = ReplayConfig::default();
    if let Some(raw) = opt_field(ledger, "config") {
        if let Some(max_gen) = opt_field(raw, "max_generation") {
            config.max_generation = as_u64(max_gen);
        }
        if let Some(max_open) = opt_field(raw, "max_open_per_source") {
            config.max_open_per_source = as_usize(max_open);
        }
    }
    config
}

fn ledger_baseline(ledger: &Json) -> Vec<BaselineEntry> {
    match opt_field(ledger, "baseline") {
        None => Vec::new(),
        Some(raw) => as_arr(raw)
            .iter()
            .map(|entry| BaselineEntry {
                virtual_id: as_str(field(entry, "virtual_id")).to_string(),
                generation: as_u64(field(entry, "generation")),
                status: as_str(field(entry, "status")).to_string(),
            })
            .collect(),
    }
}

/// Replay one case and compare the full outcome to its golden.
fn check_case(case: &str) -> ReplayOutcome {
    let ledger = load_json(&format!("{case}.ledger.json"));
    let gold = load_json(&format!("{case}.expected.json"));
    assert_eq!(
        as_str(field(&gold, "ledger")),
        format!("{case}.ledger.json"),
        "golden names the wrong ledger"
    );
    let rows: Vec<LedgerRow> = as_arr(field(&ledger, "rows"))
        .iter()
        .map(ledger_row)
        .collect();
    let capture = as_str(field(&ledger, "capture_id")).to_string();
    let outcome = replay(&rows, &capture, &ledger_config(&ledger));
    assert_eq!(outcome.capture_id, capture, "case {case}");

    let want_resolved = as_arr(field(&gold, "resolved"));
    assert_eq!(
        outcome.resolved.len(),
        want_resolved.len(),
        "case {case}: resolved row count"
    );
    for (got, want) in outcome.resolved.iter().zip(want_resolved.iter()) {
        let row_id = as_str(field(want, "row_id"));
        assert_eq!(got.row_id, row_id, "case {case}");
        assert_eq!(got.seq, as_u64(field(want, "seq")), "case {case} row {row_id}");
        match field(want, "identity") {
            Json::Null => assert!(
                got.identity.is_none(),
                "case {case} row {row_id}: want no identity, have {:?}",
                got.identity
            ),
            Json::Arr(pair) => {
                let id = got
                    .identity
                    .as_ref()
                    .unwrap_or_else(|| panic!("case {case} row {row_id}: want identity"));
                assert_eq!(id.token, as_str(&pair[0]), "case {case} row {row_id}");
                assert_eq!(id.generation, as_u64(&pair[1]), "case {case} row {row_id}");
            }
            other => panic!("case {case} row {row_id}: bad identity {other:?}"),
        }
        assert_eq!(
            got.status,
            as_str(field(want, "status")),
            "case {case} row {row_id}"
        );
        assert_eq!(
            got.certainty,
            as_str(field(want, "certainty")),
            "case {case} row {row_id}"
        );
        let needle = as_str(field(want, "note_contains"));
        assert!(
            got.note.contains(needle),
            "case {case} row {row_id}: note {:?} lacks {needle:?}",
            got.note
        );
        assert!(!got.note.is_empty(), "case {case} row {row_id}: empty note");
    }

    let want_objects = as_arr(field(&gold, "objects"));
    assert_eq!(
        outcome.objects.len(),
        want_objects.len(),
        "case {case}: object count"
    );
    for (got, want) in outcome.objects.iter().zip(want_objects.iter()) {
        assert_eq!(got.token, as_str(field(want, "token")), "case {case}");
        assert_eq!(
            got.generation,
            as_u64(field(want, "generation")),
            "case {case} token {}",
            got.token
        );
        assert_eq!(got.source_id, as_str(field(want, "source_id")), "case {case}");
        assert_eq!(
            got.object_class,
            as_str(field(want, "object_class")),
            "case {case}"
        );
        assert_eq!(got.status, as_str(field(want, "status")), "case {case}");
        assert_eq!(
            got.certainty,
            as_str(field(want, "certainty")),
            "case {case}"
        );
        assert_eq!(got.first_seq, as_u64(field(want, "first_seq")), "case {case}");
        assert_eq!(got.last_seq, as_u64(field(want, "last_seq")), "case {case}");
        assert_eq!(
            got.evidence,
            str_vec(field(want, "evidence")),
            "case {case}"
        );
        assert_eq!(got.linked, as_bool(field(want, "linked")), "case {case}");
    }

    assert_eq!(
        outcome.failed_joins,
        str_vec(field(&gold, "failed_joins")),
        "case {case}"
    );
    assert_eq!(
        outcome.refused_cross_capture,
        as_usize(field(&gold, "refused_cross_capture")),
        "case {case}"
    );
    assert_eq!(
        outcome.duplicate_rows,
        str_vec(field(&gold, "duplicate_rows")),
        "case {case}"
    );
    assert_eq!(
        outcome.overflow_refusals,
        as_usize(field(&gold, "overflow_refusals")),
        "case {case}"
    );
    assert_eq!(
        outcome.bound_refusals,
        as_usize(field(&gold, "bound_refusals")),
        "case {case}"
    );
    assert_eq!(
        outcome.unlinked_samples,
        as_usize(field(&gold, "unlinked_samples")),
        "case {case}"
    );
    assert_eq!(
        distinct_known_objects(&outcome),
        as_usize(field(&gold, "distinct_known_objects")),
        "case {case}"
    );

    if let Some(want_recon) = opt_field(&gold, "reconciliation") {
        let recon = reconcile(&ledger_baseline(&ledger), &outcome);
        assert_eq!(
            recon.confirmed,
            str_vec(field(want_recon, "confirmed")),
            "case {case}"
        );
        assert_eq!(
            recon.status_mismatch,
            str_vec(field(want_recon, "status_mismatch")),
            "case {case}"
        );
        assert_eq!(
            recon.missing_observation,
            str_vec(field(want_recon, "missing_observation")),
            "case {case}"
        );
        assert_eq!(
            recon.unconfirmed_observed,
            str_vec(field(want_recon, "unconfirmed_observed")),
            "case {case}"
        );
    }
    outcome
}

fn resolved<'a>(outcome: &'a ReplayOutcome, row_id: &str) -> &'a exposure_lineage::ResolvedRow {
    outcome
        .resolved
        .iter()
        .find(|row| row.row_id == row_id)
        .unwrap_or_else(|| panic!("no resolved row {row_id}"))
}

fn object<'a>(
    outcome: &'a ReplayOutcome,
    token: &str,
    generation: u64,
) -> &'a exposure_lineage::LineageObject {
    outcome
        .objects
        .iter()
        .find(|obj| obj.token == token && obj.generation == generation && obj.linked)
        .unwrap_or_else(|| panic!("no linked object {token}#{generation}"))
}

fn identity_of(outcome: &ReplayOutcome, row_id: &str) -> (String, u64) {
    let id = resolved(outcome, row_id)
        .identity
        .as_ref()
        .unwrap_or_else(|| panic!("row {row_id} has no identity"));
    (id.token.clone(), id.generation)
}

#[test]
fn test_reused_address_is_new_generation() {
    let outcome = check_case("reuse");
    assert_eq!(
        identity_of(&outcome, "r4"),
        ("tok-a".to_string(), 2),
        "re-allocation after release starts generation 2"
    );
    assert_eq!(object(&outcome, "tok-a", 1).status, "released");
    assert_eq!(object(&outcome, "tok-a", 2).status, "live");
    assert_eq!(distinct_known_objects(&outcome), 2);
    assert_eq!(outcome.refused_cross_capture, 1);
}

#[test]
fn test_alias_not_double_counted() {
    let outcome = check_case("alias");
    assert_eq!(
        identity_of(&outcome, "a3"),
        ("tok-a".to_string(), 1),
        "observations through the alias join the one canonical identity"
    );
    assert_eq!(distinct_known_objects(&outcome), 1);
    assert_eq!(outcome.objects.len(), 1);
    assert!(outcome.failed_joins.is_empty());
}

#[test]
fn test_failed_revert_keeps_unknown_state() {
    let outcome = check_case("revert");
    let failed = resolved(&outcome, "v3");
    assert_eq!(failed.status, "unknown");
    assert_eq!(failed.certainty, "unknown");
    assert_eq!(object(&outcome, "tok-a", 1).status, "unknown");
    assert!(resolved(&outcome, "v4").identity.is_none());
    assert_eq!(outcome.failed_joins, vec!["v4".to_string()]);
    assert_eq!(outcome.unlinked_samples, 1);
}

#[test]
fn test_quarantine_is_not_reuse() {
    let outcome = check_case("quarantine");
    assert_eq!(resolved(&outcome, "q2").status, "quarantined");
    assert_eq!(
        identity_of(&outcome, "q3"),
        ("tok-a".to_string(), 2),
        "allocation after quarantine starts a new generation"
    );
    assert_eq!(object(&outcome, "tok-a", 1).status, "quarantined");
    assert_eq!(object(&outcome, "tok-a", 2).status, "live");
}

#[test]
fn test_capture_end_is_not_teardown() {
    let outcome = check_case("capture-end");
    let end = resolved(&outcome, "e3");
    assert_eq!(identity_of(&outcome, "e3"), ("tok-a".to_string(), 1));
    assert_eq!(end.status, "live", "capture end leaves live objects live");
    assert_eq!(
        object(&outcome, "tok-a", 1).evidence,
        vec!["e1".to_string(), "e2".to_string()],
        "capture end adds no lifecycle evidence"
    );
    assert!(resolved(&outcome, "e4").identity.is_none());
}

#[test]
fn test_clock_change_bounds_temporal_claims() {
    let outcome = check_case("clock");
    assert_eq!(resolved(&outcome, "c2").certainty, "known");
    assert_eq!(resolved(&outcome, "c4").certainty, "bounded");
    assert_eq!(identity_of(&outcome, "c4"), ("tok-a".to_string(), 1));
    assert_eq!(resolved(&outcome, "c5").status, "released");
    assert_eq!(resolved(&outcome, "c5").certainty, "bounded");
    assert!(outcome.failed_joins.is_empty());
}

#[test]
fn test_suspend_gap_bounds_elapsed() {
    let outcome = check_case("suspend");
    assert_eq!(resolved(&outcome, "s3").certainty, "bounded");
    assert_eq!(identity_of(&outcome, "s3"), ("tok-a".to_string(), 1));
    assert_eq!(resolved(&outcome, "s4").certainty, "bounded");
    assert_eq!(object(&outcome, "tok-a", 1).certainty, "bounded");
}

#[test]
fn test_loss_gap_keeps_samples_separate() {
    let outcome = check_case("loss");
    assert!(resolved(&outcome, "l4").identity.is_none());
    assert_eq!(outcome.failed_joins, vec!["l4".to_string()]);
    assert_eq!(
        identity_of(&outcome, "l5"),
        ("tok-a".to_string(), 2),
        "only a fresh allocation re-establishes identity after loss"
    );
    assert_eq!(outcome.unlinked_samples, 1);
    assert_eq!(distinct_known_objects(&outcome), 2);
}

#[test]
fn test_ambiguous_join_fails_and_stays_unknown() {
    let outcome = check_case("overlap");
    assert_eq!(
        outcome.failed_joins,
        vec!["o3".to_string(), "o4".to_string()]
    );
    assert_eq!(object(&outcome, "tok-a", 1).status, "created");
    assert_eq!(object(&outcome, "tok-a", 2).status, "created");
    assert_eq!(outcome.duplicate_rows, vec!["o1".to_string()]);
}

#[test]
fn test_atom_group_failure_stays_separate() {
    let outcome = check_case("atom");
    assert!(resolved(&outcome, "t1").identity.is_none());
    assert!(resolved(&outcome, "t2").identity.is_none());
    assert_eq!(
        identity_of(&outcome, "t3"),
        ("tok-a".to_string(), 1),
        "the rolled-back allocation leaves no generation behind"
    );
    assert_eq!(identity_of(&outcome, "t5"), ("tok-c".to_string(), 1));
    assert_eq!(outcome.unlinked_samples, 1);
    assert_eq!(distinct_known_objects(&outcome), 2);
}

#[test]
fn test_generation_overflow_refuses_reuse() {
    let outcome = check_case("overflow");
    assert!(resolved(&outcome, "f5").identity.is_none());
    assert_eq!(outcome.overflow_refusals, 1);
    assert_eq!(
        outcome.failed_joins,
        vec!["f5".to_string(), "f6".to_string()]
    );
    assert_eq!(distinct_known_objects(&outcome), 2);
}

#[test]
fn test_open_bound_refuses_new_identity() {
    let outcome = check_case("bounds");
    assert!(resolved(&outcome, "b2").identity.is_none());
    assert_eq!(outcome.bound_refusals, 1);
    assert_eq!(
        identity_of(&outcome, "b4"),
        ("tok-b".to_string(), 1),
        "the bound frees once the earlier identity releases"
    );
    assert_eq!(distinct_known_objects(&outcome), 2);
}

#[test]
fn test_baseline_reconciliation_is_explicit() {
    let outcome = check_case("baseline");
    assert!(outcome.failed_joins.is_empty());
    let ledger = load_json("baseline.ledger.json");
    let recon = reconcile(&ledger_baseline(&ledger), &outcome);
    assert_eq!(recon.confirmed, vec!["tok-b#1".to_string()]);
    assert_eq!(recon.status_mismatch, vec!["tok-a#1".to_string()]);
    assert_eq!(recon.missing_observation, vec!["tok-c#2".to_string()]);
    assert_eq!(recon.unconfirmed_observed, vec!["tok-d#1".to_string()]);
}
