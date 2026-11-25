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
    BaselineSample, CLOCK_DOMAINS, ComparisonResult, CoverageSource, ExposureFact, ExposureObject,
    POLICY_MAX_BYTES, POLICY_MAX_EXCEPTIONS_PER_RULE, POLICY_MAX_RULES, PolicyResult, SEMANTICS,
    is_exposure_version,
};
use exposure_quality::RuleOutcome;
use exposure_records::{
    EvidenceKey, check_evidence_keys, sealed_evidence_keys, snapshot_source_evidence,
    snapshot_terminal_status, verify_sealed_snapshot,
};

const SEALED: &str = include_str!("exposure/fixtures/contracts/sealed_snapshot.json");
const UNSEALED: &str = include_str!("exposure/fixtures/contracts/unsealed_snapshot.json");
const DUPLICATE: &str = include_str!("exposure/fixtures/contracts/duplicate_evidence.json");
const CROSS_EPOCH: &str = include_str!("exposure/fixtures/contracts/cross_epoch_evidence.json");
const MISSING_TERMINAL: &str = include_str!("exposure/fixtures/contracts/missing_terminal.json");
const FOREIGN_SESSION: &str = include_str!("exposure/fixtures/contracts/foreign_session.json");
const MALFORMED_FACT: &str = include_str!("exposure/fixtures/contracts/malformed_fact.json");
const INVALID_SEMANTICS: &str = include_str!("exposure/fixtures/contracts/invalid_semantics.json");
const INVALID_CLOCK: &str = include_str!("exposure/fixtures/contracts/invalid_clock_domain.json");
const EMPTY_REASON: &str = include_str!("exposure/fixtures/contracts/empty_reason.json");
const DUPLICATE_SEQ: &str = include_str!("exposure/fixtures/contracts/duplicate_seq.json");
const MISSING_CENSUS_KIND: &str =
    include_str!("exposure/fixtures/contracts/missing_census_kind.json");
const NULL_FACT_QUALITY: &str = include_str!("exposure/fixtures/contracts/null_fact_quality.json");
const MARKER_MISSING_TS: &str = include_str!("exposure/fixtures/contracts/marker_missing_ts.json");
const EMPTY_BOUNCE: &str = include_str!("exposure/fixtures/contracts/empty_bounce.json");
const GUESS_MEASUREMENT: &str = include_str!("exposure/fixtures/contracts/guess_measurement.json");
const SEALED_WITH_BOUNCE: &str =
    include_str!("exposure/fixtures/contracts/sealed_with_bounce.json");
const SOURCE_SCOPE: &str = include_str!("exposure/fixtures/contracts/source_scope.json");
const LEGACY_SEALED: &str = include_str!("exposure/fixtures/contracts/legacy_sealed.json");
const INCOMPLETE_SOURCE: &str = include_str!("exposure/fixtures/contracts/incomplete_source.json");
const BAD_GAP: &str = include_str!("exposure/fixtures/contracts/bad_gap_payload.json");
const EMPTY_HOOK: &str = include_str!("exposure/fixtures/contracts/empty_hook.json");
const DUPLICATE_SOURCES: &str = include_str!("exposure/fixtures/contracts/duplicate_sources.json");
const AVAILABLE_NO_QUALITY: &str =
    include_str!("exposure/fixtures/contracts/available_no_quality.json");
const PARTIAL_BOGUS_QUALITY: &str =
    include_str!("exposure/fixtures/contracts/partial_bogus_quality.json");
const OVERFLOW_RETURN_CODE: &str =
    include_str!("exposure/fixtures/contracts/overflow_return_code.json");
const MULTI_USABLE_SOURCES: &str =
    include_str!("exposure/fixtures/contracts/multi_usable_sources.json");
const MIXED_SOURCES: &str = include_str!("exposure/fixtures/contracts/mixed_sources.json");
const COVERAGE_EXTRA_FIELD: &str =
    include_str!("exposure/fixtures/contracts/coverage_extra_field.json");
const COVERAGE_EXTRA_WINDOW_FIELD: &str =
    include_str!("exposure/fixtures/contracts/coverage_extra_window_field.json");

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
    assert_eq!(seal_verdict(SEALED), RuleOutcome::Satisfied);

    let unsealed = verify_sealed_snapshot(UNSEALED).expect("unsealed parses");
    assert!(!unsealed.verified);
    let outcome = seal_verdict(UNSEALED);
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
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
        let owned = sealed_evidence_keys(snapshot).expect("tainted replays");
        assert!(owned.len() >= 2, "{name} carries two identities");
        let err = check_evidence_keys(&borrowed(&owned)).unwrap_err();
        assert_eq!(err.what, what);
    }
}

#[test]
fn foreign_session_and_malformed_facts_cannot_verify() {
    for (name, snapshot) in [
        ("foreign session", FOREIGN_SESSION),
        ("malformed fact", MALFORMED_FACT),
    ] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(!report.verified, "{name} evidence cannot verify");
        let terminal = snapshot_terminal_status(snapshot).expect("tainted carries terminal");
        assert_eq!(terminal, "complete_for_scope", "{name} stays settled");
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }
}

#[test]
fn unknown_fact_enums_cannot_verify() {
    for (name, snapshot) in [
        ("unknown semantics", INVALID_SEMANTICS),
        ("unknown clock domain", INVALID_CLOCK),
    ] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(!report.verified, "{name} evidence cannot verify");
        let terminal = snapshot_terminal_status(snapshot).expect("tainted carries terminal");
        assert_eq!(terminal, "complete_for_scope", "{name} stays settled");
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }

    // Every frozen enum value still validates: the seal gate refuses
    // unknown labels without over-tightening known ones.
    for semantics in SEMANTICS {
        let mut fact = ExposureFact::example("ev-1", "sharing-census", 7);
        fact.semantics = semantics.to_string();
        fact.validate().unwrap();
    }
    for clock in CLOCK_DOMAINS {
        let mut fact = ExposureFact::example("ev-1", "sharing-census", 7);
        fact.clock_domain = clock.to_string();
        fact.validate().unwrap();
    }
}

#[test]
fn required_sources_need_matching_sealed_facts() {
    let owned = sealed_evidence_keys(SEALED).expect("control replays");
    let sources: Vec<&str> = owned.iter().map(|key| key.source_id.as_str()).collect();
    assert!(sources.iter().all(|source| *source == "sharing-census"));
    let terminal = snapshot_terminal_status(SEALED).expect("control carries terminal");
    let outcome = exposure_quality::rule_outcome_with_facts(
        true,
        &terminal,
        &[("sharing-census", "available", true, true)],
        &sources,
    );
    assert_eq!(outcome, RuleOutcome::Satisfied);

    for (name, facts) in [
        ("undeclared-only", vec!["egress-controls"]),
        ("no facts", vec![]),
    ] {
        let outcome = exposure_quality::rule_outcome_with_facts(
            true,
            "complete_for_scope",
            &[("sharing-census", "available", true, true)],
            &facts,
        );
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} never satisfies");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }
}

/// Replayed fact sources for the composed seal-to-verdict path.
///
/// Snapshots that refuse replay carry no covering facts; the seal
/// gate already failed them, so an empty source list is exact.
fn replayed_sources(snapshot: &str) -> Vec<String> {
    sealed_evidence_keys(snapshot)
        .map(|keys| {
            keys.iter()
                .map(|key| key.source_id.clone())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

/// The composed verdict over one snapshot for one required source.
///
/// The required source's status and quality usability come from the
/// snapshot's own session, never from a hardcoded triple, so an
/// incomplete persisted source reaches the gate unchanged.
fn seal_verdict(snapshot: &str) -> RuleOutcome {
    let report = verify_sealed_snapshot(snapshot).expect("snapshot parses");
    let terminal = snapshot_terminal_status(snapshot).expect("snapshot carries terminal");
    let owned = replayed_sources(snapshot);
    let sources: Vec<&str> = owned.iter().map(String::as_str).collect();
    let evidence =
        snapshot_source_evidence(snapshot, "sharing-census").expect("snapshot carries sources");
    exposure_quality::rule_outcome_with_facts(
        report.verified,
        &terminal,
        &[(
            "sharing-census",
            evidence.status.as_str(),
            evidence.present,
            evidence.quality_usable,
        )],
        &sources,
    )
}

#[test]
fn persisted_seal_refusals_cannot_verify() {
    for (name, snapshot) in [
        ("empty reason", EMPTY_REASON),
        ("duplicate seq", DUPLICATE_SEQ),
        ("null fact quality", NULL_FACT_QUALITY),
        ("marker without ts_ns", MARKER_MISSING_TS),
        ("empty bounce", EMPTY_BOUNCE),
        ("guessed measurement", GUESS_MEASUREMENT),
    ] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(!report.verified, "{name} evidence cannot verify");
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }
    let err = verify_sealed_snapshot(MISSING_CENSUS_KIND).unwrap_err();
    assert_eq!(err.what, "kinds");
}

#[test]
fn sealed_bounce_control_verifies_and_satisfies() {
    let report = verify_sealed_snapshot(SEALED_WITH_BOUNCE).expect("bounce control seals");
    assert!(report.verified);
    assert_eq!(seal_verdict(SEALED_WITH_BOUNCE), RuleOutcome::Satisfied);
}

#[test]
fn source_scoped_verdict_needs_matching_facts() {
    let report = verify_sealed_snapshot(SOURCE_SCOPE).expect("scope seals");
    assert!(report.verified, "well-formed foreign facts still seal");
    let outcome = seal_verdict(SOURCE_SCOPE);
    assert_eq!(
        outcome,
        RuleOutcome::Inconclusive,
        "facts from another source never satisfy"
    );
    assert_ne!(outcome, RuleOutcome::Satisfied, "never satisfies");
}

#[test]
fn legacy_snapshot_verifies_under_legacy_rules() {
    let report = verify_sealed_snapshot(LEGACY_SEALED).expect("legacy parses");
    assert!(report.verified, "valid legacy lines must verify");
}

#[test]
fn persisted_shape_refusals_cannot_verify() {
    for (name, snapshot) in [("bad gap payload", BAD_GAP), ("empty hook", EMPTY_HOOK)] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(!report.verified, "{name} cannot verify");
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }
}

#[test]
fn incomplete_source_evidence_is_incomplete() {
    let report = verify_sealed_snapshot(INCOMPLETE_SOURCE).expect("partial parses");
    assert!(report.verified, "incomplete evidence still seals");
    let outcome = seal_verdict(INCOMPLETE_SOURCE);
    assert_eq!(outcome, RuleOutcome::Incomplete);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn duplicate_coverage_sources_refused_deterministically() {
    let report = verify_sealed_snapshot(DUPLICATE_SOURCES).expect("tainted parses");
    assert!(!report.verified, "duplicate sources cannot verify");
    let outcome = seal_verdict(DUPLICATE_SOURCES);
    assert_eq!(outcome, RuleOutcome::Inconclusive);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn available_source_without_quality_cannot_satisfy() {
    let report = verify_sealed_snapshot(AVAILABLE_NO_QUALITY).expect("tainted parses");
    assert!(report.verified, "session shape stays outside the seal");
    let outcome = seal_verdict(AVAILABLE_NO_QUALITY);
    assert_eq!(outcome, RuleOutcome::Inconclusive);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn partial_bogus_quality_is_incomplete() {
    let report = verify_sealed_snapshot(PARTIAL_BOGUS_QUALITY).expect("tainted parses");
    assert!(report.verified, "bogus quality still seals");
    let outcome = seal_verdict(PARTIAL_BOGUS_QUALITY);
    assert_eq!(outcome, RuleOutcome::Incomplete);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn overflow_return_code_cannot_verify() {
    let report = verify_sealed_snapshot(OVERFLOW_RETURN_CODE).expect("tainted parses");
    assert!(!report.verified, "return_code past i64 cannot verify");
    let outcome = seal_verdict(OVERFLOW_RETURN_CODE);
    assert_eq!(outcome, RuleOutcome::Inconclusive);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn multi_usable_sources_satisfy() {
    let report = verify_sealed_snapshot(MULTI_USABLE_SOURCES).expect("control parses");
    assert!(report.verified, "disjoint usable rows verify");
    let outcome = seal_verdict(MULTI_USABLE_SOURCES);
    assert_eq!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn mixed_coverage_sources_are_incomplete() {
    let report = verify_sealed_snapshot(MIXED_SOURCES).expect("tainted parses");
    assert!(report.verified, "disjoint mixed rows verify");
    let outcome = seal_verdict(MIXED_SOURCES);
    assert_eq!(outcome, RuleOutcome::Incomplete);
    assert_ne!(outcome, RuleOutcome::Satisfied);
}

#[test]
fn unknown_coverage_fields_cannot_satisfy() {
    let control = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(control.verified);
    assert_eq!(seal_verdict(SEALED), RuleOutcome::Satisfied);
    for (name, snapshot) in [
        ("extra row field", COVERAGE_EXTRA_FIELD),
        ("extra window field", COVERAGE_EXTRA_WINDOW_FIELD),
    ] {
        let report = verify_sealed_snapshot(snapshot).expect("tainted parses");
        assert!(report.verified, "{name} keeps the byte seal");
        let evidence =
            snapshot_source_evidence(snapshot, "sharing-census").expect("snapshot carries sources");
        assert!(evidence.present, "{name} source stays present");
        assert_eq!(evidence.status, "available");
        assert!(
            !evidence.quality_usable,
            "{name} unknown key never supplies usability"
        );
        let outcome = seal_verdict(snapshot);
        assert_eq!(outcome, RuleOutcome::Inconclusive, "{name} verdict");
        assert_ne!(outcome, RuleOutcome::Satisfied, "{name} never satisfies");
    }
}

#[test]
fn missing_terminal_evidence_is_partial() {
    let settled = verify_sealed_snapshot(SEALED).expect("positive control seals");
    assert!(settled.verified);
    let terminal = snapshot_terminal_status(SEALED).expect("control carries terminal");
    assert_eq!(terminal, "complete_for_scope");
    assert_eq!(seal_verdict(SEALED), RuleOutcome::Satisfied);

    let unsettled = verify_sealed_snapshot(MISSING_TERMINAL).expect("partial parses");
    assert!(unsettled.verified, "partial evidence still seals");
    let terminal = snapshot_terminal_status(MISSING_TERMINAL).expect("partial carries terminal");
    assert_ne!(terminal, "complete_for_scope");
    let outcome = seal_verdict(MISSING_TERMINAL);
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
