// SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed exposure records and source quality: lane integration tests.
//!
//! The three lane modules compile here through explicit path includes;
//! integration wires them as `model::exposure`,
//! `capture::exposure_records` and `analysis::exposure_quality` with no
//! edits to the lane files themselves.

#[path = "../src/model/exposure.rs"]
mod exposure;

#[path = "../src/capture/exposure_records.rs"]
mod exposure_records;

#[path = "../src/analysis/exposure_quality.rs"]
mod exposure_quality;

use exposure::{
    BaselineSample, ComparisonResult, CoverageSource, ExposureFact, ExposureObject, PolicyResult,
    is_exposure_version,
};
use exposure_quality::RuleOutcome;
use exposure_records::{EvidenceKey, check_evidence_keys, verify_sealed_snapshot};

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

#[test]
fn unsealed_snapshot_cannot_satisfy_rule() {
    let sealed = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(sealed.verified);
    let outcome = exposure_quality::rule_outcome(
        sealed.verified,
        "complete_for_scope",
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Satisfied);

    let unsealed = verify_sealed_snapshot(UNSEALED).expect("unsealed parses");
    assert!(!unsealed.verified);
    let outcome = exposure_quality::rule_outcome(
        unsealed.verified,
        "complete_for_scope",
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

    assert!(verify_sealed_snapshot(DUPLICATE).is_ok());
    assert!(verify_sealed_snapshot(CROSS_EPOCH).is_ok());
}

#[test]
fn missing_terminal_evidence_is_partial() {
    let settled = verify_sealed_snapshot(SEALED).expect("positive control seals");
    let outcome = exposure_quality::rule_outcome(
        settled.verified,
        "complete_for_scope",
        &[("sharing-census", "available", true)],
    );
    assert_eq!(outcome, RuleOutcome::Satisfied);

    let unsettled = verify_sealed_snapshot(MISSING_TERMINAL).expect("partial parses");
    assert!(unsettled.verified, "partial evidence still seals");
    let outcome = exposure_quality::rule_outcome(
        unsettled.verified,
        "unavailable",
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
fn tampered_bytes_fail_the_seal() {
    let report = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(report.verified);
    let tampered = SEALED.replacen("op-1", "op-2", 1);
    assert_ne!(tampered, SEALED);
    let report = verify_sealed_snapshot(&tampered).expect("tampered parses");
    assert!(!report.verified, "edited bytes must fail the seal");
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
