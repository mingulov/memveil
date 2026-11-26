// SPDX-License-Identifier: GPL-3.0-or-later
//! CLI capability selection and compare-verb exits: contract tests.
//!
//! The module compiles here through an explicit path include;
//! the crate root wires it as `cli::compare` with no edits to
//! the module file itself. Each test mirrors one golden
//! fixture under tests/exposure/fixtures/cli/ and names its
//! case id; the Python golden suite checks that coupling so
//! the two sides cannot drift apart.

#[path = "../src/cli/compare.rs"]
mod compare;

use compare::{
    CompareRequest, MetricVerdict, RunOutcome, SelectionOutcome, SelectionRequest,
    exit_for_outcome, resolve_cli_selection, resolve_compare,
};

fn request(caps: Option<&str>, device: Option<&str>, legacy: bool) -> SelectionRequest {
    SelectionRequest {
        capabilities: caps.map(str::to_string),
        device: device.map(str::to_string),
        legacy,
    }
}

fn expect_selected(
    outcome: &SelectionOutcome,
    selected: &[&str],
    hook: bool,
    device: Option<&str>,
) {
    assert_eq!(outcome.exit, compare::EXIT_OK);
    assert_eq!(outcome.reason, None);
    assert_eq!(
        outcome.selected,
        selected
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(outcome.requires_attempt_hook, hook);
    assert_eq!(outcome.device, device.map(str::to_string));
}

fn expect_channel_refusal(outcome: &SelectionOutcome, selected: &[&str], hook: bool) {
    assert_eq!(outcome.exit, compare::EXIT_REFUSAL);
    assert_eq!(outcome.reason.as_deref(), Some("no-record-channel"));
    assert_eq!(
        outcome.selected,
        selected
            .iter()
            .map(|name| name.to_string())
            .collect::<Vec<_>>()
    );
    assert_eq!(outcome.requires_attempt_hook, hook);
}

fn expect_parse_refusal(outcome: &SelectionOutcome, reason: &str) {
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some(reason));
    assert!(outcome.selected.is_empty());
    assert!(!outcome.requires_attempt_hook);
    assert_eq!(outcome.device, None);
}

// case: default-selection
#[test]
fn absent_list_selects_the_default_channel() {
    let outcome = resolve_cli_selection(&request(None, None, false));
    expect_selected(&outcome, &["attempt-trace"], true, None);
}

// case: legacy-default
#[test]
fn legacy_default_keeps_the_attempt_dependency() {
    let outcome = resolve_cli_selection(&request(None, None, true));
    assert_eq!(outcome.exit, compare::EXIT_OK);
    assert_eq!(outcome.selected, vec!["attempt-trace".to_string()]);
    assert!(outcome.requires_attempt_hook);
}

// case: all-channels
#[test]
fn all_expands_to_the_ordinary_channels_only() {
    let outcome = resolve_cli_selection(&request(Some("all"), None, false));
    expect_selected(
        &outcome,
        &["attempt-trace", "mapping-lifecycle", "copy-actual"],
        true,
        None,
    );
}

// case: attempt-alone
#[test]
fn attempt_channel_selects_alone() {
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), None, false));
    expect_selected(&outcome, &["attempt-trace"], true, None);
}

// case: lifecycle-alone
#[test]
fn lifecycle_without_attempt_refuses() {
    let outcome = resolve_cli_selection(&request(Some("mapping-lifecycle"), None, false));
    expect_parse_refusal(&outcome, "attempt-trace-required");
}

// case: copy-alone
#[test]
fn copy_without_attempt_refuses() {
    let outcome = resolve_cli_selection(&request(Some("copy-actual"), None, false));
    expect_parse_refusal(&outcome, "attempt-trace-required");
}

// case: duplicates-first-wins
#[test]
fn repeated_names_collapse_to_first_order() {
    let outcome = resolve_cli_selection(&request(
        Some("attempt-trace,attempt-trace,mapping-lifecycle"),
        None,
        false,
    ));
    expect_selected(&outcome, &["attempt-trace", "mapping-lifecycle"], true, None);
}

// case: strict-no-spaces
#[test]
fn spaced_items_are_unknown() {
    let outcome =
        resolve_cli_selection(&request(Some("attempt-trace, mapping-lifecycle"), None, false));
    expect_parse_refusal(&outcome, "unknown-capability");
}

// case: journal-alone
#[test]
fn journal_channel_parses_without_the_hook() {
    let outcome = resolve_cli_selection(&request(Some("conversion-journal"), None, false));
    expect_channel_refusal(&outcome, &["conversion-journal"], false);
}

// case: observe-alone
#[test]
fn observe_channel_parses_without_the_hook() {
    let outcome = resolve_cli_selection(&request(Some("conversion-observe"), None, false));
    expect_channel_refusal(&outcome, &["conversion-observe"], false);
}

// case: journal-pair
#[test]
fn journal_pair_parses_without_the_hook() {
    let outcome = resolve_cli_selection(&request(
        Some("conversion-journal,conversion-observe"),
        None,
        false,
    ));
    expect_channel_refusal(&outcome, &["conversion-journal", "conversion-observe"], false);
}

// case: mixed-ordinary-journal
#[test]
fn mixed_list_keeps_the_attempt_dependency() {
    let outcome = resolve_cli_selection(&request(
        Some("attempt-trace,conversion-journal"),
        None,
        false,
    ));
    expect_channel_refusal(&outcome, &["attempt-trace", "conversion-journal"], true);
}

// case: attempt-required-beats-channel
#[test]
fn missing_attempt_beats_the_channel_refusal() {
    let outcome = resolve_cli_selection(&request(
        Some("mapping-lifecycle,conversion-journal"),
        None,
        false,
    ));
    expect_parse_refusal(&outcome, "attempt-trace-required");
}

// case: unknown-capability
#[test]
fn invented_names_refuse_as_unknown() {
    let outcome = resolve_cli_selection(&request(Some("census-2"), None, false));
    expect_parse_refusal(&outcome, "unknown-capability");
}

// case: planned-census
#[test]
fn planned_census_refuses_until_its_adapter_ships() {
    let outcome = resolve_cli_selection(&request(Some("census"), None, false));
    expect_parse_refusal(&outcome, "planned-capability");
}

// case: planned-shared-buffers
#[test]
fn planned_heap_channel_refuses_until_its_adapter_ships() {
    let outcome = resolve_cli_selection(&request(Some("shared-buffers"), None, false));
    expect_parse_refusal(&outcome, "planned-capability");
}

#[test]
fn every_planned_channel_refuses_as_planned() {
    for id in [
        "census",
        "object-lifetimes",
        "dma-paths",
        "shared-buffers",
        "host-interfaces",
        "mapping-inventory",
        "exposure-context",
    ] {
        let outcome = resolve_cli_selection(&request(Some(id), None, false));
        assert_eq!(outcome.exit, compare::EXIT_INVALID, "id {id}");
        assert_eq!(outcome.reason.as_deref(), Some("planned-capability"), "id {id}");
    }
}

// case: bad-list-empty-item
#[test]
fn trailing_comma_refuses() {
    let outcome = resolve_cli_selection(&request(Some("attempt-trace,"), None, false));
    expect_parse_refusal(&outcome, "bad-capability-list");
}

// case: explicit-empty-list
#[test]
fn explicit_empty_list_refuses() {
    let outcome = resolve_cli_selection(&request(Some(""), None, false));
    expect_parse_refusal(&outcome, "empty-capability-list");
}

// case: unknown-beats-device
#[test]
fn unknown_name_beats_a_bad_device() {
    let outcome = resolve_cli_selection(&request(Some("bogus"), Some(""), false));
    expect_parse_refusal(&outcome, "unknown-capability");
}

// case: device-accepted
#[test]
fn device_filter_selects_with_ordinary_channels() {
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), Some("0000:00:1f.2"), false));
    expect_selected(&outcome, &["attempt-trace"], true, Some("0000:00:1f.2"));
}

// case: device-256-chars
#[test]
fn longest_device_name_selects() {
    let name = "d".repeat(256);
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), Some(&name), false));
    expect_selected(&outcome, &["attempt-trace"], true, Some(&name));
}

// case: device-empty
#[test]
fn empty_device_refuses() {
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), Some(""), false));
    expect_parse_refusal(&outcome, "invalid-device");
}

// case: device-too-long
#[test]
fn overlong_device_refuses() {
    let name = "d".repeat(257);
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), Some(&name), false));
    expect_parse_refusal(&outcome, "invalid-device");
}

// case: device-hides-global
#[test]
fn device_filter_refuses_journal_channels() {
    let outcome = resolve_cli_selection(&request(Some("conversion-journal"), Some("eth0"), false));
    expect_parse_refusal(&outcome, "device-hides-global-evidence");
}

// case: legacy-ordinary
#[test]
fn legacy_input_selects_ordinary_channels() {
    let outcome = resolve_cli_selection(&request(Some("attempt-trace"), None, true));
    assert_eq!(outcome.exit, compare::EXIT_OK);
    assert!(outcome.requires_attempt_hook);
}

// case: legacy-journal
#[test]
fn legacy_input_refuses_journal_channels() {
    let outcome = resolve_cli_selection(&request(Some("conversion-journal"), None, true));
    expect_parse_refusal(&outcome, "legacy-input");
}

fn valid_outcome() -> RunOutcome {
    RunOutcome {
        inputs_valid: true,
        collection_missing: false,
        recovered: false,
        refused_metrics: false,
        strict: false,
        policy_violation_proved: false,
        evidence_complete: true,
    }
}

// case: outcome-invalid
#[test]
fn invalid_input_exits_two() {
    let outcome = RunOutcome {
        inputs_valid: false,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_INVALID);
}

// case: outcome-missing
#[test]
fn missing_collection_exits_three() {
    let outcome = RunOutcome {
        collection_missing: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_REFUSAL);
}

// case: outcome-invalid-beats-missing
#[test]
fn invalid_beats_missing() {
    let outcome = RunOutcome {
        inputs_valid: false,
        collection_missing: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_INVALID);
}

// case: outcome-recovered
#[test]
fn recovered_capture_exits_four() {
    let outcome = RunOutcome {
        recovered: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_PARTIAL);
}

// case: outcome-recovered-beats-strict
#[test]
fn recovered_beats_a_strict_violation() {
    let outcome = RunOutcome {
        recovered: true,
        strict: true,
        policy_violation_proved: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_PARTIAL);
}

// case: outcome-ordinary-valid
#[test]
fn ordinary_valid_report_exits_zero() {
    assert_eq!(exit_for_outcome(&valid_outcome()), compare::EXIT_OK);
}

// case: outcome-ordinary-policy-nonstrict
#[test]
fn non_strict_policy_result_exits_zero() {
    let outcome = RunOutcome {
        policy_violation_proved: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_OK);
}

// case: outcome-strict-violation
#[test]
fn strict_proved_violation_exits_five() {
    let outcome = RunOutcome {
        strict: true,
        policy_violation_proved: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_POLICY_VIOLATION);
}

// case: outcome-strict-incomplete
#[test]
fn strict_incomplete_evidence_exits_four() {
    let outcome = RunOutcome {
        strict: true,
        evidence_complete: false,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_PARTIAL);
}

// case: outcome-strict-clean
#[test]
fn strict_complete_clean_result_exits_zero() {
    let outcome = RunOutcome {
        strict: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_OK);
}

// case: outcome-missing-beats-recovered
#[test]
fn missing_beats_recovered() {
    let outcome = RunOutcome {
        collection_missing: true,
        recovered: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_REFUSAL);
}

// case: outcome-refused-beats-violation
#[test]
fn refused_metrics_beat_a_strict_violation() {
    let outcome = RunOutcome {
        refused_metrics: true,
        strict: true,
        policy_violation_proved: true,
        ..valid_outcome()
    };
    assert_eq!(exit_for_outcome(&outcome), compare::EXIT_PARTIAL);
}

fn verdicts(pairs: &[(&str, &str)]) -> Vec<MetricVerdict> {
    pairs
        .iter()
        .map(|(id, compatibility)| MetricVerdict {
            metric_id: id.to_string(),
            compatibility: compatibility.to_string(),
        })
        .collect()
}

fn compare_request(rows: Vec<MetricVerdict>) -> CompareRequest {
    CompareRequest {
        left_valid: true,
        right_valid: true,
        collection_missing: false,
        recovered: false,
        rows,
        strict: false,
        policy_violation_proved: false,
        evidence_complete: true,
    }
}

// case: compare-clean
#[test]
fn compatible_rows_compare_clean() {
    let request = compare_request(verdicts(&[
        ("shared-bytes", "compatible"),
        ("queue-count", "compatible"),
    ]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_OK);
    assert_eq!(outcome.reason, None);
}

// case: compare-incompatible
#[test]
fn incompatible_row_makes_the_run_partial() {
    let request = compare_request(verdicts(&[
        ("shared-bytes", "compatible"),
        ("queue-count", "incompatible"),
    ]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_PARTIAL);
    assert_eq!(outcome.reason, None);
}

// case: compare-unavailable
#[test]
fn unavailable_row_makes_the_run_partial() {
    let request = compare_request(verdicts(&[("shared-bytes", "unavailable")]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_PARTIAL);
    assert_eq!(outcome.reason, None);
}

// case: compare-invalid-capture
#[test]
fn invalid_capture_beats_row_shape() {
    let request = CompareRequest {
        left_valid: false,
        rows: verdicts(&[
            ("shared-bytes", "compatible"),
            ("shared-bytes", "compatible"),
        ]),
        ..compare_request(Vec::new())
    };
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("invalid-capture"));
}

// case: compare-invalid-beats-missing
#[test]
fn invalid_capture_beats_missing_collection() {
    let request = CompareRequest {
        right_valid: false,
        collection_missing: true,
        ..compare_request(verdicts(&[("shared-bytes", "compatible")]))
    };
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("invalid-capture"));
}

// case: compare-missing-beats-refused
#[test]
fn missing_collection_beats_refused_rows() {
    let request = CompareRequest {
        collection_missing: true,
        ..compare_request(verdicts(&[("shared-bytes", "incompatible")]))
    };
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_REFUSAL);
    assert_eq!(outcome.reason, None);
}

// case: compare-strict-violation
#[test]
fn strict_proved_violation_compares_to_five() {
    let request = CompareRequest {
        strict: true,
        policy_violation_proved: true,
        ..compare_request(verdicts(&[("shared-bytes", "compatible")]))
    };
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_POLICY_VIOLATION);
    assert_eq!(outcome.reason, None);
}

// case: compare-empty-rows
#[test]
fn empty_request_refuses() {
    let outcome = resolve_compare(&compare_request(Vec::new()));
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("no-requested-metrics"));
}

// case: compare-duplicate-metric
#[test]
fn repeated_metric_refuses() {
    let request = compare_request(verdicts(&[
        ("shared-bytes", "compatible"),
        ("shared-bytes", "compatible"),
    ]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("duplicate-metric"));
}

// case: compare-unknown-label
#[test]
fn unknown_verdict_label_refuses() {
    let request = compare_request(verdicts(&[("shared-bytes", "close-enough")]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("unknown-compatibility"));
}

// case: compare-duplicate-beats-label
#[test]
fn repeated_metric_beats_a_bad_label() {
    let request = compare_request(verdicts(&[
        ("shared-bytes", "compatible"),
        ("shared-bytes", "close-enough"),
    ]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_INVALID);
    assert_eq!(outcome.reason.as_deref(), Some("duplicate-metric"));
}

// case: compare-legacy-pair-refused
#[test]
fn legacy_pair_reports_partial_through_its_rows() {
    let request = compare_request(verdicts(&[
        ("shared-bytes", "incompatible"),
        ("queue-count", "incompatible"),
    ]));
    let outcome = resolve_compare(&request);
    assert_eq!(outcome.exit, compare::EXIT_PARTIAL);
    assert_eq!(outcome.reason, None);
}
