// SPDX-License-Identifier: GPL-3.0-or-later
//! Guest-view census snapshots: snapshot-contract tests.
//!
//! The census module compiles here through an explicit path
//! include; the crate root wires it as `capture::exposure_census`
//! at integration with no edits to the module file itself.
//! Each test mirrors one golden fixture under
//! tests/exposure/fixtures/census/ and names its case id;
//! the Python golden suite checks that coupling so the two
//! sides cannot drift apart.

#[path = "../src/capture/exposure_census.rs"]
mod exposure_census;

use exposure_census::{
    Atomicity, CensusCount, CensusDelta, CensusSnapshot, CollectionRequirements, JournalScope,
    Observation, Quality, Window, check_collection_readiness, compare_snapshots, observe_window,
};

fn count(id: &str, unit: &str, value: Option<u64>, reason: Option<&str>) -> CensusCount {
    CensusCount {
        class_id: id.to_string(),
        unit: unit.to_string(),
        value,
        value_reason: reason.map(str::to_string),
    }
}

fn atomicity(mode: &str, races: bool, bound: Option<u64>) -> Atomicity {
    Atomicity {
        mode: mode.to_string(),
        races_observed: races,
        uncertainty_bound: bound,
    }
}

fn journal(scope: &str, complete: bool) -> JournalScope {
    JournalScope {
        scope_id: scope.to_string(),
        complete,
    }
}

fn snapshot(evidence: &str, value: Option<u64>) -> CensusSnapshot {
    CensusSnapshot {
        evidence_id: evidence.to_string(),
        profile_id: "linux-x86_64-7.0-reference".to_string(),
        workload: "idle-snapshot".to_string(),
        epoch: 41,
        platform_cell: "ordinary-guest-01".to_string(),
        scope: "guest-view".to_string(),
        window: Window {
            clock_domain: "guest_monotonic_active".to_string(),
            start: 1000,
            end: 2000,
        },
        coverage: vec!["census-sweep".to_string()],
        atomicity: atomicity("atomic", false, None),
        journal: journal("journal-main", true),
        counts: vec![count("x", "unknown", value, None)],
    }
}

fn pair() -> (CensusSnapshot, CensusSnapshot) {
    (
        snapshot("snap-left-order", Some(1)),
        snapshot("snap-right-order", Some(9)),
    )
}

#[allow(clippy::too_many_arguments)]
fn expect_row(
    actual: &CensusDelta,
    class_id: &str,
    compatibility: &str,
    reason: &str,
    left: &str,
    right: &str,
    delta: Option<i64>,
    delta_reason: Option<&str>,
    uncertainty: Option<u64>,
    unit: &str,
    scope: &str,
    quality: Quality,
) {
    assert_eq!(actual.class_id, class_id, "class");
    assert_eq!(actual.compatibility, compatibility, "compatibility");
    assert_eq!(actual.reason, reason, "reason");
    assert_eq!(actual.left_evidence, left, "left evidence");
    assert_eq!(actual.right_evidence, right, "right evidence");
    assert_eq!(actual.delta, delta, "delta");
    assert_eq!(
        actual.delta_reason,
        delta_reason.map(str::to_string),
        "delta reason"
    );
    assert_eq!(actual.uncertainty, uncertainty, "uncertainty");
    assert_eq!(actual.unit, unit, "unit");
    assert_eq!(actual.scope, scope, "scope");
    assert_eq!(actual.quality, quality, "quality");
}

#[test]
fn compatible_golden_reports_exact_known_deltas() {
    // Fixture case "compatible-golden".
    let mut left = snapshot("snap-left-001", Some(120));
    left.counts
        .push(count("class-b", "unknown", Some(50), None));
    left.counts[0].class_id = "class-a".to_string();
    let mut right = snapshot("snap-right-001", Some(128));
    right
        .counts
        .push(count("class-b", "unknown", Some(41), None));
    right.counts[0].class_id = "class-a".to_string();
    let rows = compare_snapshots(&left, &right).expect("compatible pair compares");
    assert_eq!(rows.len(), 2);
    expect_row(
        &rows[0],
        "class-a",
        "compatible",
        "compatible",
        "snap-left-001",
        "snap-right-001",
        Some(8),
        None,
        Some(0),
        "unknown",
        "guest-view",
        Quality::complete(),
    );
    expect_row(
        &rows[1],
        "class-b",
        "compatible",
        "compatible",
        "snap-left-001",
        "snap-right-001",
        Some(-9),
        None,
        Some(0),
        "unknown",
        "guest-view",
        Quality::complete(),
    );
}

#[test]
fn missing_class_is_unavailable_without_numbers() {
    // Fixture case "class-missing".
    let left = snapshot("snap-left-002", Some(1));
    let mut right = snapshot("snap-right-002", Some(2));
    right.counts[0].class_id = "y".to_string();
    let rows = compare_snapshots(&left, &right).expect("one-sided pair compares");
    assert_eq!(rows.len(), 2);
    expect_row(
        &rows[0],
        "x",
        "unavailable",
        "class-missing",
        "snap-left-002",
        "snap-right-002",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::unavailable(),
    );
    expect_row(
        &rows[1],
        "y",
        "unavailable",
        "class-missing",
        "snap-left-002",
        "snap-right-002",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::unavailable(),
    );
}

#[test]
fn races_state_exact_delta_plus_uncertainty() {
    // Fixture case "race-uncertainty".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-014".to_string();
    left.atomicity = atomicity("interval", true, Some(4));
    left.counts = vec![
        count("x", "unknown", Some(100), None),
        count("y", "unknown", Some(7), None),
    ];
    right.evidence_id = "snap-right-014".to_string();
    right.atomicity = atomicity("interval", true, Some(6));
    right.counts = vec![
        count("x", "unknown", Some(150), None),
        count("y", "unknown", Some(7), None),
    ];
    let rows = compare_snapshots(&left, &right).expect("racy pair compares");
    assert_eq!(rows.len(), 2);
    expect_row(
        &rows[0],
        "x",
        "compatible",
        "compatible",
        "snap-left-014",
        "snap-right-014",
        Some(50),
        None,
        Some(10),
        "unknown",
        "guest-view",
        Quality::complete(),
    );
    expect_row(
        &rows[1],
        "y",
        "compatible",
        "compatible",
        "snap-left-014",
        "snap-right-014",
        Some(0),
        None,
        Some(10),
        "unknown",
        "guest-view",
        Quality::complete(),
    );
}

#[test]
fn uncertainty_saturates_at_u64_max() {
    // Fixture case "uncertainty-saturating".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-015".to_string();
    left.atomicity = atomicity("interval", true, Some(u64::MAX));
    left.counts = vec![count("x", "unknown", Some(5), None)];
    right.evidence_id = "snap-right-015".to_string();
    right.atomicity = atomicity("interval", true, Some(1));
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "compatible",
        "compatible",
        "snap-left-015",
        "snap-right-015",
        Some(4),
        None,
        Some(u64::MAX),
        "unknown",
        "guest-view",
        Quality::complete(),
    );
}

#[test]
fn one_sided_races_state_that_side_bound() {
    // Only the right side raced: the stated uncertainty
    // is the right bound alone. No fixture: bound
    // addition is covered by the saturating golden.
    let (left, mut right) = pair();
    right.atomicity = atomicity("interval", true, Some(3));
    let mut left = left;
    left.atomicity.mode = "interval".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].uncertainty, Some(3));
    assert_eq!(rows[0].delta, Some(8));
}

#[test]
fn clock_mismatch_refuses_comparison() {
    // Fixture case "clock-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-016".to_string();
    right.evidence_id = "snap-right-016".to_string();
    right.window.clock_domain = "guest_boottime_elapsed".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "clock-mismatch",
        "snap-left-016",
        "snap-right-016",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn blank_clock_is_unknown() {
    // Fixture case "clock-unknown".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-017".to_string();
    left.window.clock_domain = String::new();
    right.evidence_id = "snap-right-017".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "clock-unknown",
        "snap-left-017",
        "snap-right-017",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn window_mismatch_refuses_comparison() {
    // Fixture case "window-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-018".to_string();
    right.evidence_id = "snap-right-018".to_string();
    right.window.end = 3000;
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "window-mismatch",
        "snap-left-018",
        "snap-right-018",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn journal_scope_mismatch_refuses_comparison() {
    // Fixture case "journal-scope-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-019".to_string();
    right.evidence_id = "snap-right-019".to_string();
    right.journal.scope_id = "journal-retry".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "journal-scope-mismatch",
        "snap-left-019",
        "snap-right-019",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn partial_journal_refuses_and_never_nets() {
    // Fixture case "partial-journal".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-020".to_string();
    right.evidence_id = "snap-right-020".to_string();
    right.journal.complete = false;
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "partial-journal",
        "snap-left-020",
        "snap-right-020",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn unknown_value_stays_compatible_with_null_delta() {
    // Fixture case "value-unknown".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-021".to_string();
    left.counts = vec![
        count("x", "unknown", None, Some("source-unavailable")),
        count("y", "unknown", Some(3), None),
    ];
    right.evidence_id = "snap-right-021".to_string();
    right.counts = vec![
        count("x", "unknown", Some(9), None),
        count("y", "unknown", None, Some("drain-incomplete")),
    ];
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 2);
    expect_row(
        &rows[0],
        "x",
        "compatible",
        "compatible",
        "snap-left-021",
        "snap-right-021",
        None,
        Some("value-unknown"),
        Some(0),
        "unknown",
        "guest-view",
        Quality::unknown(),
    );
    expect_row(
        &rows[1],
        "y",
        "compatible",
        "compatible",
        "snap-left-021",
        "snap-right-021",
        None,
        Some("value-unknown"),
        Some(0),
        "unknown",
        "guest-view",
        Quality::unknown(),
    );
}

#[test]
fn delta_overflow_stays_compatible_with_null_delta() {
    // Fixture case "delta-overflow".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-022".to_string();
    left.counts = vec![
        count("x", "unknown", Some(u64::MAX), None),
        count("y", "unknown", Some(0), None),
    ];
    right.evidence_id = "snap-right-022".to_string();
    right.counts = vec![
        count("x", "unknown", Some(0), None),
        count("y", "unknown", Some(u64::MAX), None),
    ];
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 2);
    expect_row(
        &rows[0],
        "x",
        "compatible",
        "compatible",
        "snap-left-022",
        "snap-right-022",
        None,
        Some("delta-overflow"),
        Some(0),
        "unknown",
        "guest-view",
        Quality::unknown(),
    );
    expect_row(
        &rows[1],
        "y",
        "compatible",
        "compatible",
        "snap-left-022",
        "snap-right-022",
        None,
        Some("delta-overflow"),
        Some(0),
        "unknown",
        "guest-view",
        Quality::unknown(),
    );
}

#[test]
fn unknown_unit_refuses_without_copying_the_label() {
    // Fixture case "unit-unknown".
    let (mut left, right) = pair();
    left.evidence_id = "snap-left-003".to_string();
    left.counts[0].unit = String::new();
    let mut right = right;
    right.evidence_id = "snap-right-003".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "unit-unknown",
        "snap-left-003",
        "snap-right-003",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn blank_scope_is_unknown_never_equal() {
    // Fixture case "scope-unknown".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-005".to_string();
    left.scope = String::new();
    right.evidence_id = "snap-right-005".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "scope-unknown",
        "snap-left-005",
        "snap-right-005",
        None,
        None,
        None,
        "unknown",
        "",
        Quality::refused(),
    );
}

#[test]
fn scope_mismatch_refuses_comparison() {
    // Fixture case "scope-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-006".to_string();
    right.evidence_id = "snap-right-006".to_string();
    right.scope = "guest-view-narrow".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "scope-mismatch",
        "snap-left-006",
        "snap-right-006",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn profile_mismatch_refuses_comparison() {
    // Fixture case "profile-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-007".to_string();
    right.evidence_id = "snap-right-007".to_string();
    right.profile_id = "linux-x86_64-7.0-hardened".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "profile-mismatch",
        "snap-left-007",
        "snap-right-007",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn workload_mismatch_refuses_comparison() {
    // Fixture case "workload-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-008".to_string();
    right.evidence_id = "snap-right-008".to_string();
    right.workload = "io-batch".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "workload-mismatch",
        "snap-left-008",
        "snap-right-008",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn epoch_mismatch_refuses_comparison() {
    // Fixture case "epoch-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-009".to_string();
    right.evidence_id = "snap-right-009".to_string();
    right.epoch = 42;
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "epoch-mismatch",
        "snap-left-009",
        "snap-right-009",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn device_binding_mismatch_refuses_comparison() {
    // Fixture case "device-binding".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-010".to_string();
    right.evidence_id = "snap-right-010".to_string();
    right.platform_cell = "ordinary-guest-02".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "device-binding-mismatch",
        "snap-left-010",
        "snap-right-010",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn coverage_mismatch_refuses_comparison() {
    // Fixture case "coverage-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-011".to_string();
    right.evidence_id = "snap-right-011".to_string();
    right.coverage.push("census-resweep".to_string());
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "coverage-mismatch",
        "snap-left-011",
        "snap-right-011",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn coverage_order_does_not_matter() {
    // Coverage compares as a set: the same sources in a
    // different order still compare. No fixture: order is
    // a struct-level property, not a golden row.
    let (mut left, mut right) = pair();
    left.coverage.push("census-resweep".to_string());
    right.coverage = vec!["census-resweep".to_string(), "census-sweep".to_string()];
    let rows = compare_snapshots(&left, &right).expect("same coverage compares");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].reason, "compatible");
    assert_eq!(rows[0].delta, Some(8));
}

#[test]
fn unknown_atomicity_refuses_comparison() {
    // Fixture case "atomicity-unknown".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-012".to_string();
    right.evidence_id = "snap-right-012".to_string();
    right.atomicity.mode = "unknown".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "atomicity-unknown",
        "snap-left-012",
        "snap-right-012",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn duplicate_class_refuses_the_whole_input() {
    // Fixture case "duplicate-class".
    let (mut left, right) = pair();
    left.evidence_id = "snap-left-023".to_string();
    left.counts.push(count("x", "unknown", Some(5), None));
    let mut right = right;
    right.evidence_id = "snap-right-023".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("duplicates refuse");
    assert_eq!(refusal.reason, "duplicate-class");
}

#[test]
fn backward_window_refuses_the_whole_input() {
    // Fixture case "invalid-window".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-024".to_string();
    left.window.start = 3000;
    left.window.end = 2000;
    right.evidence_id = "snap-right-024".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("backward window refuses");
    assert_eq!(refusal.reason, "invalid-window");
}

#[test]
fn unpaired_count_refuses_the_whole_input() {
    // Fixture case "invalid-count".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-025".to_string();
    left.counts[0].value = None;
    left.counts[0].value_reason = None;
    right.evidence_id = "snap-right-025".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("unpaired count refuses");
    assert_eq!(refusal.reason, "invalid-count");
}

#[test]
fn duplicated_coverage_refuses_the_whole_input() {
    // Fixture case "invalid-coverage".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-026".to_string();
    left.coverage.push("census-sweep".to_string());
    right.evidence_id = "snap-right-026".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("duplicated coverage refuses");
    assert_eq!(refusal.reason, "invalid-coverage");
}

#[test]
fn blank_journal_scope_refuses_the_whole_input() {
    // Fixture case "invalid-journal".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-027".to_string();
    left.journal.scope_id = String::new();
    right.evidence_id = "snap-right-027".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("blank journal scope refuses");
    assert_eq!(refusal.reason, "invalid-journal");
}

#[test]
fn unpaired_race_bound_refuses_the_whole_input() {
    // Fixture case "invalid-atomicity".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-028".to_string();
    left.atomicity.races_observed = true;
    right.evidence_id = "snap-right-028".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("unpaired race bound refuses");
    assert_eq!(refusal.reason, "invalid-atomicity");
}

#[test]
fn bound_without_races_refuses_the_whole_input() {
    // A bound with no observed races is unpaired in the
    // other direction. No fixture: pairing is covered by
    // the invalid-atomicity golden.
    let (mut left, right) = pair();
    left.atomicity.uncertainty_bound = Some(7);
    let refusal = compare_snapshots(&left, &right).expect_err("bound without races refuses");
    assert_eq!(refusal.reason, "invalid-atomicity");
}

#[test]
fn control_characters_in_scope_refuse_the_whole_input() {
    // Fixture case "invalid-scope".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-029".to_string();
    left.scope = "guest\u{1c}view".to_string();
    right.evidence_id = "snap-right-029".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("control scope refuses");
    assert_eq!(refusal.reason, "invalid-scope");
}

#[test]
fn control_characters_in_clock_refuse_the_whole_input() {
    // Fixture case "invalid-clock".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-030".to_string();
    left.window.clock_domain = "guest\u{1c}clock".to_string();
    right.evidence_id = "snap-right-030".to_string();
    let refusal = compare_snapshots(&left, &right).expect_err("control clock refuses");
    assert_eq!(refusal.reason, "invalid-clock");
}

#[test]
fn left_snapshot_validates_before_right() {
    // Both sides invalid: the left refusal wins. No
    // fixture: precedence is a struct-level property.
    let (mut left, mut right) = pair();
    left.window.start = 3000;
    left.window.end = 2000;
    right.counts.push(count("x", "unknown", Some(5), None));
    let refusal = compare_snapshots(&left, &right).expect_err("invalid pair refuses");
    assert_eq!(refusal.reason, "invalid-window");
}

#[test]
fn rows_follow_left_order_then_right_only() {
    // Row order is stable: left order first, then classes
    // seen only on the right. No fixture: ordering is a
    // struct-level property, not a golden row.
    let (mut left, mut right) = pair();
    left.counts = vec![
        count("b", "unknown", Some(1), None),
        count("a", "unknown", Some(2), None),
    ];
    right.counts = vec![
        count("a", "unknown", Some(3), None),
        count("c", "unknown", Some(4), None),
        count("b", "unknown", Some(5), None),
    ];
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    let ids: Vec<&str> = rows.iter().map(|row| row.class_id.as_str()).collect();
    assert_eq!(ids, vec!["b", "a", "c"]);
    assert_eq!(rows[0].delta, Some(4));
    assert_eq!(rows[1].delta, Some(1));
    assert_eq!(rows[2].compatibility, "unavailable");
}

#[test]
fn checks_run_in_documented_order() {
    // Adjacent check pairs through the product: the
    // earlier check names the reason. Each pair breaks
    // two checks at once; absence is covered separately
    // because it preempts everything.
    fn break_both(first: &str, second: &str) -> String {
        let (mut left, mut right) = pair();
        for reason in [first, second] {
            match reason {
                "unit-unknown" => left.counts[0].unit = String::new(),
                "unit-mismatch" => right.counts[0].unit = "bytes".to_string(),
                "scope-unknown" => left.scope = String::new(),
                "scope-mismatch" => right.scope = "guest-view-narrow".to_string(),
                "profile-mismatch" => {
                    right.profile_id = "linux-x86_64-7.0-hardened".to_string();
                }
                "workload-mismatch" => right.workload = "io-batch".to_string(),
                "epoch-mismatch" => right.epoch = 42,
                "device-binding-mismatch" => {
                    right.platform_cell = "ordinary-guest-02".to_string();
                }
                "coverage-mismatch" => right.coverage.push("census-resweep".to_string()),
                "atomicity-unknown" => left.atomicity.mode = "unknown".to_string(),
                "atomicity-mismatch" => right.atomicity.mode = "interval".to_string(),
                "clock-unknown" => left.window.clock_domain = String::new(),
                "clock-mismatch" => {
                    right.window.clock_domain = "guest_boottime_elapsed".to_string();
                }
                "window-mismatch" => right.window.end = 3000,
                "journal-scope-mismatch" => {
                    right.journal.scope_id = "journal-retry".to_string();
                }
                "partial-journal" => right.journal.complete = false,
                other => panic!("no breaker for {other}"),
            }
        }
        let rows = compare_snapshots(&left, &right).expect("pair compares");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].compatibility, "incompatible");
        rows[0].reason.clone()
    }
    let order = [
        "unit-unknown",
        "unit-mismatch",
        "scope-unknown",
        "scope-mismatch",
        "profile-mismatch",
        "workload-mismatch",
        "epoch-mismatch",
        "device-binding-mismatch",
        "coverage-mismatch",
        "atomicity-unknown",
        "atomicity-mismatch",
        "clock-unknown",
        "clock-mismatch",
        "window-mismatch",
        "journal-scope-mismatch",
        "partial-journal",
    ];
    for pair in order.windows(2) {
        assert_eq!(break_both(pair[0], pair[1]), pair[0]);
    }
}

fn observation(session: &str, epoch: u64, ts: u64) -> Observation {
    Observation {
        session_id: session.to_string(),
        epoch,
        ts,
    }
}

#[test]
fn start_stop_observation_yields_the_window() {
    let start = observation("session-1", 41, 1000);
    let stop = observation("session-1", 41, 2000);
    assert_eq!(observe_window(&start, &stop), Ok((1000, 2000)));
}

#[test]
fn start_stop_observation_accepts_an_empty_window() {
    let start = observation("session-1", 41, 2000);
    let stop = observation("session-1", 41, 2000);
    assert_eq!(observe_window(&start, &stop), Ok((2000, 2000)));
}

#[test]
fn start_stop_observation_refuses_a_foreign_session() {
    let start = observation("session-1", 41, 1000);
    let stop = observation("session-2", 41, 2000);
    let refusal = observe_window(&start, &stop).expect_err("foreign session refuses");
    assert_eq!(refusal.reason, "session-mismatch");
}

#[test]
fn start_stop_observation_refuses_an_epoch_crossing() {
    let start = observation("session-1", 41, 1000);
    let stop = observation("session-1", 42, 2000);
    let refusal = observe_window(&start, &stop).expect_err("epoch crossing refuses");
    assert_eq!(refusal.reason, "epoch-mismatch");
}

#[test]
fn start_stop_observation_refuses_a_backward_stop() {
    let start = observation("session-1", 41, 2000);
    let stop = observation("session-1", 41, 1000);
    let refusal = observe_window(&start, &stop).expect_err("backward stop refuses");
    assert_eq!(refusal.reason, "backward-observation");
}

fn requirements() -> CollectionRequirements {
    CollectionRequirements {
        privileged: true,
        symbols_resolved: true,
        semantics_admitted: true,
        bounds_sufficient: true,
    }
}

#[test]
fn ready_collection_is_admitted() {
    assert!(check_collection_readiness(&requirements()).is_ok());
}

#[test]
fn unprivileged_collection_refuses_first() {
    let mut req = requirements();
    req.privileged = false;
    req.symbols_resolved = false;
    let refusal = check_collection_readiness(&req).expect_err("unprivileged refuses");
    assert_eq!(refusal.reason, "privilege-refused");
}

#[test]
fn unresolved_symbols_refuse_collection() {
    let mut req = requirements();
    req.symbols_resolved = false;
    let refusal = check_collection_readiness(&req).expect_err("unresolved symbols refuse");
    assert_eq!(refusal.reason, "symbols-unresolved");
}

#[test]
fn unadmitted_semantics_refuse_collection() {
    let mut req = requirements();
    req.semantics_admitted = false;
    let refusal = check_collection_readiness(&req).expect_err("unadmitted semantics refuse");
    assert_eq!(refusal.reason, "semantics-unadmitted");
}

#[test]
fn insufficient_bounds_refuse_collection() {
    let mut req = requirements();
    req.bounds_sufficient = false;
    let refusal = check_collection_readiness(&req).expect_err("insufficient bounds refuse");
    assert_eq!(refusal.reason, "bounds-insufficient");
}

#[test]
fn atomicity_mismatch_refuses_comparison() {
    // Fixture case "atomicity-mismatch".
    let (mut left, mut right) = pair();
    left.evidence_id = "snap-left-013".to_string();
    right.evidence_id = "snap-right-013".to_string();
    right.atomicity.mode = "interval".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "atomicity-mismatch",
        "snap-left-013",
        "snap-right-013",
        None,
        None,
        None,
        "unknown",
        "guest-view",
        Quality::refused(),
    );
}

#[test]
fn unit_mismatch_refuses_comparison() {
    // Fixture case "unit-mismatch".
    let (left, mut right) = pair();
    let mut left = left;
    left.evidence_id = "snap-left-004".to_string();
    right.evidence_id = "snap-right-004".to_string();
    left.counts[0].unit = "bytes".to_string();
    let rows = compare_snapshots(&left, &right).expect("pair compares");
    assert_eq!(rows.len(), 1);
    expect_row(
        &rows[0],
        "x",
        "incompatible",
        "unit-mismatch",
        "snap-left-004",
        "snap-right-004",
        None,
        None,
        None,
        "bytes",
        "guest-view",
        Quality::refused(),
    );
}
