// SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed exposure records and source quality: contract tests.
//!
//! The three modules compile here through explicit path includes;
//! the crate root wires them as `model::exposure`,
//! `capture::exposure_records` and `analysis::exposure_quality` with
//! no edits to the module files themselves.

#[path = "../src/model/exposure.rs"]
mod exposure;

#[path = "../src/capture/exposure_records.rs"]
mod exposure_records;

#[path = "../src/analysis/exposure_quality.rs"]
mod exposure_quality;

use exposure::{
    BaselineSample, ComparisonResult, CoverageSource, ExposureFact, ExposureObject,
    POLICY_MAX_BYTES, POLICY_MAX_EXCEPTIONS_PER_RULE, POLICY_MAX_RULES, PolicyResult,
    is_exposure_version,
};
use exposure_quality::RuleOutcome;
use exposure_records::{
    EvidenceKey, check_evidence_keys, sealed_evidence_keys, snapshot_terminal_status,
    verify_sealed_snapshot,
};

const SEALED: &str = include_str!("exposure/fixtures/contracts/sealed_snapshot.json");
const UNSEALED: &str = include_str!("exposure/fixtures/contracts/unsealed_snapshot.json");
const DUPLICATE: &str = include_str!("exposure/fixtures/contracts/duplicate_evidence.json");
const CROSS_EPOCH: &str = include_str!("exposure/fixtures/contracts/cross_epoch_evidence.json");
const MISSING_TERMINAL: &str = include_str!("exposure/fixtures/contracts/missing_terminal.json");

fn keys_of(facts: &[ExposureFact]) -> Vec<EvidenceKey<'_>> {
    facts
        .iter()
        .map(|fact| EvidenceKey {
            evidence_id: fact.evidence_id.as_str(),
            source_id: fact.source_id.as_str(),
            epoch: fact.epoch,
        })
        .collect()
}

fn borrowed(keys: &[exposure_records::SealedEvidenceKey]) -> Vec<EvidenceKey<'_>> {
    keys.iter()
        .map(|key| EvidenceKey {
            evidence_id: key.evidence_id.as_str(),
            source_id: key.source_id.as_str(),
            epoch: key.epoch,
        })
        .collect()
}

#[test]
fn unsealed_snapshot_cannot_satisfy_rule() {
    let sealed = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(sealed.verified);
    let terminal = snapshot_terminal_status(SEALED).expect("control carries terminal");
    assert_eq!(terminal, "complete_for_scope");
    let outcome = exposure_quality::rule_outcome(
        sealed.verified,
        &terminal,
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Satisfied);

    let unsealed = verify_sealed_snapshot(UNSEALED).expect("unsealed parses");
    assert!(!unsealed.verified);
    let terminal = snapshot_terminal_status(UNSEALED).expect("unsealed carries terminal");
    let outcome = exposure_quality::rule_outcome(
        unsealed.verified,
        &terminal,
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Inconclusive);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn duplicate_source_and_cross_epoch_evidence_rejected() {
    let clean = vec![
        ExposureFact::example("ev-1", "sharing-census", 7),
        ExposureFact::example("ev-2", "sharing-census", 7),
    ];
    for fact in &clean {
        fact.validate().unwrap();
    }
    check_evidence_keys(&keys_of(&clean)).unwrap();

    let duplicate = vec![
        ExposureFact::example("ev-1", "sharing-census", 7),
        ExposureFact::example("ev-1", "sharing-census", 7),
    ];
    let err = check_evidence_keys(&keys_of(&duplicate)).unwrap_err();
    assert_eq!(err.what, "evidence_id");

    let mixed = vec![
        ExposureFact::example("ev-1", "sharing-census", 7),
        ExposureFact::example("ev-2", "sharing-census", 8),
    ];
    let err = check_evidence_keys(&keys_of(&mixed)).unwrap_err();
    assert_eq!(err.what, "source_id");

    let control = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(control.verified);
    let owned = sealed_evidence_keys(SEALED).expect("control replays");
    assert!(!owned.is_empty(), "control carries fact identities");
    check_evidence_keys(&borrowed(&owned)).unwrap();

    for (name, snapshot, what) in [
        ("duplicate", DUPLICATE, "evidence_id"),
        ("mixed epochs", CROSS_EPOCH, "source_id"),
    ] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(!report.verified, "{name} evidence cannot verify");
        let terminal = snapshot_terminal_status(snapshot).expect("tainted carries terminal");
        let outcome = exposure_quality::rule_outcome(
            report.verified,
            &terminal,
            &[("sharing-census", "available", true)],
        );
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
        let owned = sealed_evidence_keys(snapshot).expect("tainted replays");
        assert!(owned.len() >= 2, "{name} carries two identities");
        let err = check_evidence_keys(&borrowed(&owned)).unwrap_err();
        assert_eq!(err.what, what);
    }
}

#[test]
fn missing_terminal_evidence_is_partial() {
    let settled = verify_sealed_snapshot(SEALED).expect("positive control seals");
    let terminal = snapshot_terminal_status(SEALED).expect("control carries terminal");
    assert_eq!(terminal, "complete_for_scope");
    let outcome = exposure_quality::rule_outcome(
        settled.verified,
        &terminal,
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Satisfied);

    let unsettled = verify_sealed_snapshot(MISSING_TERMINAL).expect("partial parses");
    assert!(unsettled.verified, "partial evidence still seals");
    let terminal = snapshot_terminal_status(MISSING_TERMINAL).expect("partial carries terminal");
    assert_ne!(terminal, "complete_for_scope");
    let outcome = exposure_quality::rule_outcome(
        unsettled.verified,
        &terminal,
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Partial);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn record_shapes_validate_frozen_fields() {
    CoverageSource::example().validate().unwrap();
    ExposureFact::example("ev-1", "sharing-census", 7)
        .validate()
        .unwrap();
    ExposureObject::example().validate().unwrap();
    BaselineSample::example().validate().unwrap();
    PolicyResult::example().validate().unwrap();
    ComparisonResult::example().validate().unwrap();

    let mut bad = CoverageSource::example();
    bad.status = "made_up".to_string();
    assert!(bad.validate().is_err());

    let mut bad = ExposureFact::example("ev-1", "sharing-census", 7);
    bad.semantics = "guess".to_string();
    assert!(bad.validate().is_err());

    let mut bad = ExposureObject::example();
    bad.object_class = "heap".to_string();
    assert!(bad.validate().is_err());

    let mut bad = BaselineSample::example();
    bad.units = "pages".to_string();
    assert!(bad.validate().is_err());

    let mut bad = PolicyResult::example();
    bad.result = "conforms_maybe".to_string();
    assert!(bad.validate().is_err());

    let mut bad = ComparisonResult::example();
    bad.compatibility = "close_enough".to_string();
    assert!(bad.validate().is_err());
}

#[test]
fn canonical_encoding_round_trips_exactly() {
    let canonical = include_str!("exposure/fixtures/contracts/replay_canonical.json");
    let shuffled = include_str!("exposure/fixtures/contracts/replay_shuffled.json");
    let first = exposure_records::normalize_record(canonical).unwrap();
    assert_eq!(first, canonical.trim_end());
    let second = exposure_records::normalize_record(shuffled).unwrap();
    assert_eq!(second, canonical.trim_end());
    assert_eq!(
        exposure_records::normalize_record(&first).unwrap(),
        first,
        "normalization is idempotent"
    );
}

#[test]
fn snapshot_path_refuses_unknown_and_non_object_integrity() {
    let bogus = SEALED.replacen(
        "\"integrity\": {",
        "\"integrity\": {\n        \"bogus\": \"0\",",
        1,
    );
    assert_ne!(bogus, SEALED);
    let err = verify_sealed_snapshot(&bogus).unwrap_err();
    assert_eq!(err.what, "integrity");
    assert_eq!(err.message, "unknown field");

    let null = SEALED.replacen(
        "\"integrity\": {",
        "\"integrity\": null, \"sidelined\": {",
        1,
    );
    assert_ne!(null, SEALED);
    let err = verify_sealed_snapshot(&null).unwrap_err();
    assert_eq!(err.what, "integrity");
    assert_eq!(err.message, "expected object");

    let unsealed = verify_sealed_snapshot(UNSEALED).expect("unsealed parses");
    assert!(!unsealed.verified);
}

#[test]
fn snapshot_lines_carry_position_and_trailing_newline() {
    let shifted = SEALED.replacen("\\\"seq\\\":\\\"0\\\"", "\\\"seq\\\":\\\"5\\\"", 1);
    assert_ne!(shifted, SEALED);
    let err = verify_sealed_snapshot(&shifted).unwrap_err();
    assert_eq!(err.what, "event_lines");
    assert_eq!(err.message, "sequence mismatch");

    let stripped = SEALED.replacen("\\n\"", "\"", 1);
    assert_ne!(stripped, SEALED);
    let err = verify_sealed_snapshot(&stripped).unwrap_err();
    assert_eq!(err.what, "event_lines");
    assert_eq!(err.message, "missing trailing newline");
}

/// Byte offset just past the opening quote of the first event line.
fn first_entry_open(snapshot: &str) -> usize {
    let anchor = snapshot.find("\"event_lines\"").expect("event_lines key");
    let rest = &snapshot[anchor..];
    let bracket = rest.find('[').expect("event_lines array");
    let quote = rest[bracket..].find('"').expect("first entry") + bracket;
    anchor + quote + 1
}

/// Decoded byte length of the first event line entry.
fn first_entry_len(snapshot: &str) -> usize {
    let raw = snapshot.as_bytes();
    let mut pos = first_entry_open(snapshot);
    let mut len = 0;
    loop {
        let byte = raw[pos];
        if byte == b'\\' {
            assert_ne!(raw[pos + 1], b'u', "no unicode escapes in fixtures");
            pos += 2;
            len += 1;
            continue;
        }
        if byte == b'"' {
            break;
        }
        pos += 1;
        len += 1;
    }
    len
}

/// Insert `pad` spaces at the start of the first event line entry.
fn pad_first_entry(snapshot: &str, pad: usize) -> String {
    let at = first_entry_open(snapshot);
    let mut out = String::with_capacity(snapshot.len() + pad);
    out.push_str(&snapshot[..at]);
    out.push_str(&" ".repeat(pad));
    out.push_str(&snapshot[at..]);
    out
}

#[test]
fn snapshot_path_splits_and_bounds_physical_lines() {
    assert_eq!(
        exposure_records::SNAPSHOT_MAX_LINE_BYTES,
        65536,
        "snapshot line bound matches the capture reader"
    );
    let split = SEALED.replacen("\\n\"", "\\n\\n\"", 1);
    assert_ne!(split, SEALED);
    let err = verify_sealed_snapshot(&split).unwrap_err();
    assert_eq!(err.what, "event_lines");
    assert_eq!(err.message, "extra newline");

    let entry_len = first_entry_len(SEALED);
    assert!(entry_len < 65536, "fixture entry fits the bound");
    let capped = pad_first_entry(SEALED, 65536 - entry_len);
    let report = verify_sealed_snapshot(&capped).expect("capped line parses");
    assert!(!report.verified, "edited bytes must fail the seal");
    let oversize = pad_first_entry(SEALED, 65536 - entry_len + 1);
    let err = verify_sealed_snapshot(&oversize).unwrap_err();
    assert_eq!(err.what, "event_lines");
    assert_eq!(err.message, "line too large");
}

#[test]
fn tampered_bytes_fail_the_seal() {
    let report = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(report.verified);
    let tampered = SEALED.replacen("op-1", "op-2", 1);
    assert_ne!(tampered, SEALED);
    let report = verify_sealed_snapshot(&tampered).expect("tampered parses");
    assert!(!report.verified, "edited bytes must fail the seal");
}

#[test]
fn policy_file_bounds_match_published_limits() {
    assert_eq!(exposure_records::POLICY_FILE_MAX_BYTES, POLICY_MAX_BYTES);
    assert_eq!(exposure_records::POLICY_FILE_MAX_RULES, POLICY_MAX_RULES);
    assert_eq!(
        exposure_records::POLICY_FILE_MAX_EXCEPTIONS_PER_RULE,
        POLICY_MAX_EXCEPTIONS_PER_RULE
    );
    let policy = include_str!("exposure/fixtures/contracts/policy_valid.json");
    let summary = exposure_records::parse_policy_file(policy).unwrap();
    assert_eq!(summary.rules, 1);
    assert_eq!(summary.exceptions, 0);
}

#[test]
fn legacy_versions_stay_outside_exposure() {
    assert!(is_exposure_version("0.3.0"));
    assert!(!is_exposure_version("0.1.1"));
    assert!(!is_exposure_version("0.1.2"));
    assert!(!is_exposure_version("0.1.4"));
    assert!(!is_exposure_version("0.2.0"));
    assert!(!is_exposure_version(""));
}

#[test]
fn quality_channels_stay_independent() {
    let statuses = [
        "complete_for_scope",
        "complete_for_scope",
        "complete_for_scope",
        "complete_for_scope",
        "complete_for_scope",
    ];
    let losses = [Some(0), Some(0), Some(0), Some(0), Some(0)];
    let base = exposure_quality::evaluate_all(&statuses, &losses);
    assert!(base.iter().all(|usable| *usable));
    for channel in 0..5 {
        let mut varied = statuses;
        varied[channel] = "unavailable";
        let mut varied_loss = losses;
        varied_loss[channel] = None;
        let out = exposure_quality::evaluate_all(&varied, &varied_loss);
        for (index, usable) in out.iter().enumerate() {
            assert_eq!(
                *usable,
                index != channel,
                "channel {channel} must not move channel {index}"
            );
        }
    }
}
