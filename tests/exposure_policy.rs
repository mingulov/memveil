// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline authored-policy checks: reader bounds plus rule evaluation.
//!
//! The two lane modules compile here through explicit path
//! includes, so no shared `mod.rs` changes. The controller
//! wires them into the library at integration; the module
//! headers record the handoff.
//!
//! Behavior contract (frozen public text:
//! `docs/exposure-policy.md` plus the exposure catalog
//! vocabularies): duplicate keys, conflicting rules,
//! unknown kinds and empty scopes refuse; an unknown
//! selector is inconclusive, never an allowlist match; a
//! proved violation outranks unrelated loss but keeps the
//! gap visible; cross-capture opaque-id equality is
//! refused.

#[path = "../src/analysis/exposure_policy.rs"]
mod exposure_policy;
#[path = "../src/platform/policy_reader.rs"]
mod policy_reader;

use exposure_policy::{EvalInput, Fact, Object, PolicyResult, evaluate, strict_exit};
use policy_reader::{Json, parse_decimal_u64, parse_json, parse_policy_text, read_policy_file};
use std::fs;
use std::path::{Path, PathBuf};

const SCOPE: &str = "virtio-queue-lifetimes";
const CAPTURE: &str = "cap-1";
const SOURCE: &str = "dma-virtio-paths";
const CONFIG_SOURCE: &str = "egress-controls";
const CLOCK: &str = "guest_monotonic_active";

const CLOSED_POLICY: &str = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "closed-scope",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "ordinary-linux", "profile": "synthetic-offline"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {
      "rule_id": "no-unexpected-queue",
      "selector": {"capability": "dma-paths", "source_id": "dma-virtio-paths", "semantics": "request"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": null
    }
  ],
  "exceptions": [
    {"exception_id": "admitted-device-path", "rule_id": "no-unexpected-queue", "field": "peer_class", "values": ["host-device"], "reason": "admitted device path"}
  ]
}"#;

fn fact(evidence: &str, peer: &str) -> Fact {
    Fact {
        evidence_id: evidence.to_string(),
        capture_id: CAPTURE.to_string(),
        source_id: SOURCE.to_string(),
        capability: Some("dma-paths".to_string()),
        semantics: "request".to_string(),
        peer_class: peer.to_string(),
        clock_domain: CLOCK.to_string(),
        kind: None,
        direction: None,
        caller_class: None,
    }
}

fn input_bundle(
    finalized: bool,
    available: &[&str],
    facts: Vec<Fact>,
    objects: Vec<Object>,
) -> EvalInput {
    EvalInput {
        scope_id: SCOPE.to_string(),
        capture_id: CAPTURE.to_string(),
        finalized,
        available_sources: available.iter().map(|s| s.to_string()).collect(),
        facts,
        objects,
    }
}

fn object(token: &str, status: &str) -> Object {
    Object {
        object_token: token.to_string(),
        generation: 1,
        capture_id: CAPTURE.to_string(),
        object_class: "queue".to_string(),
        origin_source: SOURCE.to_string(),
        lifecycle_status: status.to_string(),
        elapsed: None,
        elapsed_clock: None,
    }
}

fn only(results: &[PolicyResult]) -> &PolicyResult {
    assert_eq!(results.len(), 1, "want one rule result");
    &results[0]
}

#[test]
fn closed_policy_parses() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("valid policy parses");
    assert_eq!(policy.policy_id, "closed-scope");
    assert_eq!(policy.subject_scope, SCOPE);
    assert_eq!(policy.platform, "ordinary-linux");
    assert_eq!(policy.profile, "synthetic-offline");
    assert_eq!(policy.required_sources, vec![SOURCE.to_string()]);
    assert_eq!(policy.clock, CLOCK);
    assert!(policy.role_bindings.is_empty());
    assert_eq!(policy.rules.len(), 1);
    assert_eq!(policy.rules[0].permitted, "allowlisted-only");
    assert_eq!(policy.rules[0].limit_window, "capture");
    assert_eq!(policy.exceptions.len(), 1);
    assert_eq!(policy.exceptions[0].reason, "admitted device path");
    assert!(policy.prerequisites.is_none());
    assert!(policy.expected_findings.is_empty());
}

#[test]
fn empty_match_conforms_when_complete() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "conforms");
    assert_eq!(result.scope_id, SCOPE);
    assert_eq!(result.clock_domain, CLOCK);
    assert!(result.reason.contains("next:"));
    assert_eq!(out.overall, "conforms");
    assert_eq!(strict_exit(&out.overall), 0);
}

#[test]
fn covered_operation_deviates_known() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![fact("ev-1", "host-device")], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "deviates_known");
    assert_eq!(result.evidence_ids, vec!["ev-1".to_string()]);
    assert_eq!(
        result.exceptions_applied,
        vec!["no-unexpected-queue:admitted-device-path".to_string()]
    );
    assert_eq!(strict_exit(&out.overall), 0);
}

#[test]
fn unfinalized_capture_with_covered_fact_is_inconclusive() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(false, &[SOURCE], vec![fact("ev-1", "host-device")], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "inconclusive");
    assert!(result.reason.contains("unfinalized"));
    assert_eq!(out.overall, "inconclusive");
    assert_eq!(strict_exit(&out.overall), 4);
}

#[test]
fn uncovered_operation_violates() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![fact("ev-9", "host-hypervisor")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert_eq!(result.evidence_ids, vec!["ev-9".to_string()]);
    assert!(result.exceptions_applied.is_empty());
    assert_eq!(out.overall, "violates");
    assert_eq!(strict_exit(&out.overall), 5);
}

#[test]
fn violation_keeps_unrelated_loss_visible() {
    let text = CLOSED_POLICY.replace(
        r#""required_sources": ["dma-virtio-paths"]"#,
        r#""required_sources": ["dma-virtio-paths", "sharing-census"]"#,
    );
    let policy = parse_policy_text(&text).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![fact("ev-9", "host-hypervisor")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert_eq!(result.evidence_ids, vec!["ev-9".to_string()]);
    assert_eq!(result.missing_sources, vec!["sharing-census".to_string()]);
    assert_eq!(strict_exit(&out.overall), 5);
}

#[test]
fn missing_required_source_is_unavailable() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(true, &[], vec![], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "unavailable");
    assert_eq!(result.missing_sources, vec![SOURCE.to_string()]);
    assert!(result.evidence_ids.is_empty());
    assert_eq!(strict_exit(&out.overall), 4);
}

#[test]
fn unknown_peer_is_inconclusive() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![fact("ev-2", "future-peer")], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "inconclusive");
    assert!(result.reason.contains("future-peer"));
    assert_eq!(strict_exit(&out.overall), 4);
}

#[test]
fn missing_selected_field_is_inconclusive() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let mut thin = fact("ev-3", "host-device");
    thin.capability = None;
    let input = input_bundle(true, &[SOURCE], vec![thin], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "inconclusive");
}

#[test]
fn deferred_selector_field_is_inconclusive() {
    let text = CLOSED_POLICY.replace(
        r#""semantics": "request""#,
        r#""semantics": "request", "kind": "some-kind""#,
    );
    let policy = parse_policy_text(&text).expect("deferred field parses");
    let input = input_bundle(true, &[SOURCE], vec![fact("ev-1", "host-device")], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "inconclusive");
    assert!(result.reason.contains("kind"));
}

#[test]
fn unfinalized_capture_never_conforms() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(false, &[SOURCE], vec![], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "inconclusive");
}

#[test]
fn unfinalized_capture_keeps_proved_violation() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let input = input_bundle(
        false,
        &[SOURCE],
        vec![fact("ev-9", "host-hypervisor")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "violates");
}

#[test]
fn scope_mismatch_refuses() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let mut input = input_bundle(true, &[SOURCE], vec![], vec![]);
    input.scope_id = "other-scope".to_string();
    let err = evaluate(&policy, &input).expect_err("scope must match");
    assert!(err.to_string().contains("other-scope"));
}

#[test]
fn cross_capture_records_are_refused() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let mut foreign = fact("ev-x", "host-hypervisor");
    foreign.capture_id = "cap-2".to_string();
    let input = input_bundle(true, &[SOURCE], vec![foreign], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(out.refused_cross_capture, 1);
    assert_eq!(only(&out.results).result, "conforms");
}

#[test]
fn equal_tokens_across_captures_never_merge() {
    let text = CLOSED_POLICY
        .replace("\"obligation\": null", "\"obligation\": {\"status\": \"released\"}")
        .replace(
            r#"{"capability": "dma-paths", "source_id": "dma-virtio-paths", "semantics": "request"}"#,
            r#"{"source_id": "dma-virtio-paths"}"#,
        );
    let text = text.replace(
        r#""exceptions": [
    {"exception_id": "admitted-device-path", "rule_id": "no-unexpected-queue", "field": "peer_class", "values": ["host-device"], "reason": "admitted device path"}
  ]"#,
        r#""exceptions": []"#,
    );
    let policy = parse_policy_text(&text).expect("boundary policy parses");
    let mut live_elsewhere = object("tok-1", "live");
    live_elsewhere.capture_id = "cap-2".to_string();
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![],
        vec![object("tok-1", "released"), live_elsewhere],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(out.refused_cross_capture, 1);
    assert_eq!(only(&out.results).result, "conforms");
}

const LIMIT_POLICY: &str = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "limit-scope",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "ordinary-linux", "profile": "synthetic-offline"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {
      "rule_id": "at-most-two-queues",
      "selector": {"source_id": "dma-virtio-paths", "semantics": "request"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "2"},
      "obligation": null
    }
  ],
  "exceptions": []
}"#;

#[test]
fn limit_within_max_conforms() {
    let policy = parse_policy_text(LIMIT_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![fact("ev-1", "host-device"), fact("ev-2", "host-device")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "conforms");
    assert_eq!(strict_exit(&out.overall), 0);
}

#[test]
fn limit_breach_violates() {
    let policy = parse_policy_text(LIMIT_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![
            fact("ev-1", "host-device"),
            fact("ev-2", "host-device"),
            fact("ev-3", "host-device"),
        ],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert_eq!(result.evidence_ids.len(), 3);
    assert_eq!(strict_exit(&out.overall), 5);
}

#[test]
fn limit_breach_with_unknowns_still_violates() {
    let policy = parse_policy_text(LIMIT_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![
            fact("ev-1", "host-device"),
            fact("ev-2", "host-device"),
            fact("ev-3", "host-device"),
            fact("ev-4", "future-peer"),
        ],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert!(result.reason.contains("unknown"));
}

#[test]
fn limit_with_unknowns_below_max_is_inconclusive() {
    let policy = parse_policy_text(LIMIT_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![fact("ev-1", "host-device"), fact("ev-4", "future-peer")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "inconclusive");
}

const BOUNDARY_POLICY: &str = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "boundary-scope",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "ordinary-linux", "profile": "synthetic-offline"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {
      "rule_id": "queues-released",
      "selector": {"object_class": "queue", "source_id": "dma-virtio-paths"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": {"status": "released"}
    }
  ],
  "exceptions": []
}"#;

#[test]
fn released_objects_conform() {
    let policy = parse_policy_text(BOUNDARY_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![], vec![object("tok-1", "released")]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "conforms");
}

#[test]
fn live_objects_violate_boundary() {
    let policy = parse_policy_text(BOUNDARY_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![], vec![object("tok-1", "live")]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert_eq!(result.evidence_ids, vec!["object:tok-1#1".to_string()]);
}

#[test]
fn censored_capture_is_not_teardown() {
    let policy = parse_policy_text(BOUNDARY_POLICY).expect("parse");
    let input = input_bundle(
        false,
        &[SOURCE],
        vec![],
        vec![object("tok-1", "released"), object("tok-2", "live")],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "inconclusive");
    assert!(result.reason.contains("unfinalized"));
    assert_eq!(out.overall, "inconclusive");
    assert_eq!(strict_exit(&out.overall), 4);
}

#[test]
fn exceeded_duration_proves_in_censored_capture() {
    let text = BOUNDARY_POLICY.replace(
        r#""obligation": {"status": "released"}"#,
        r#""obligation": {"status": "released", "within": "5000", "clock": "guest_monotonic_active"}"#,
    );
    let policy = parse_policy_text(&text).expect("parse");
    let mut slow = object("tok-1", "released");
    slow.elapsed = Some(6000);
    slow.elapsed_clock = Some("guest_monotonic_active".to_string());
    let input = input_bundle(false, &[SOURCE], vec![], vec![slow]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "violates");
    assert_eq!(strict_exit(&out.overall), 5);
}

#[test]
fn unknown_lifecycle_status_is_inconclusive() {
    let policy = parse_policy_text(BOUNDARY_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![], vec![object("tok-1", "unknown")]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "inconclusive");
}

#[test]
fn duration_rule_needs_its_declared_clock() {
    let text = BOUNDARY_POLICY.replace(
        r#""obligation": {"status": "released"}"#,
        r#""obligation": {"status": "released", "within": "5000", "clock": "guest_monotonic_active"}"#,
    );
    let policy = parse_policy_text(&text).expect("parse");
    let mut quick = object("tok-1", "released");
    quick.elapsed = Some(100);
    quick.elapsed_clock = Some("guest_monotonic_active".to_string());
    let input = input_bundle(true, &[SOURCE], vec![], vec![quick]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "conforms");
    let mut other_clock = object("tok-2", "released");
    other_clock.elapsed = Some(100);
    other_clock.elapsed_clock = Some("guest_boottime_elapsed".to_string());
    let input = input_bundle(true, &[SOURCE], vec![], vec![other_clock]);
    let out = evaluate(&policy, &input).expect("evaluate");
    let result = only(&out.results);
    assert_eq!(result.result, "inconclusive");
    assert!(result.reason.contains("guest_boottime_elapsed"));
    let mut slow = object("tok-3", "released");
    slow.elapsed = Some(6000);
    slow.elapsed_clock = Some("guest_monotonic_active".to_string());
    let input = input_bundle(true, &[SOURCE], vec![], vec![slow]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "violates");
}

const CONFIG_POLICY: &str = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "config-scope",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "ordinary-linux", "profile": "synthetic-offline"},
  "required_sources": ["egress-controls"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {
      "rule_id": "no-unexpected-config",
      "selector": {"source_id": "egress-controls", "semantics": "state"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": null
    }
  ],
  "exceptions": []
}"#;

fn config_fact(evidence: &str) -> Fact {
    Fact {
        evidence_id: evidence.to_string(),
        capture_id: CAPTURE.to_string(),
        source_id: CONFIG_SOURCE.to_string(),
        capability: Some("exposure-context".to_string()),
        semantics: "state".to_string(),
        peer_class: "none-observed".to_string(),
        clock_domain: CLOCK.to_string(),
        kind: None,
        direction: None,
        caller_class: None,
    }
}

#[test]
fn unexpected_config_state_violates() {
    let policy = parse_policy_text(CONFIG_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[CONFIG_SOURCE],
        vec![config_fact("ev-cfg-1")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "violates");
}

#[test]
fn evaluation_is_stateless_across_runs() {
    let policy = parse_policy_text(CONFIG_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[CONFIG_SOURCE],
        vec![config_fact("ev-cfg-1")],
        vec![],
    );
    let first = evaluate(&policy, &input).expect("first");
    let second = evaluate(&policy, &input).expect("second");
    assert_eq!(first.results, second.results);
    let grown = input_bundle(
        true,
        &[CONFIG_SOURCE],
        vec![config_fact("ev-cfg-1"), config_fact("ev-cfg-2")],
        vec![],
    );
    let third = evaluate(&policy, &grown).expect("third");
    assert_eq!(only(&third.results).evidence_ids.len(), 2);
}

const PAIR_POLICY: &str = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "pair-scope",
  "subject_scope": "virtio-queue-lifetimes",
  "applies_to": {"platform": "ordinary-linux", "profile": "synthetic-offline"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {
      "rule_id": "b-second",
      "selector": {"source_id": "dma-virtio-paths", "semantics": "request"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": null
    },
    {
      "rule_id": "a-first",
      "selector": {"source_id": "dma-virtio-paths", "semantics": "request", "peer_class": "host-device"},
      "permitted": "allowlisted-only",
      "limit": {"window": "capture", "max": "0"},
      "obligation": null
    }
  ],
  "exceptions": [
    {"exception_id": "cover-a", "rule_id": "a-first", "field": "peer_class", "values": ["host-device"], "reason": "covers the narrow rule only"}
  ]
}"#;

#[test]
fn rule_order_does_not_change_results() {
    let mut policy = parse_policy_text(PAIR_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![fact("ev-1", "host-device")], vec![]);
    let before = evaluate(&policy, &input).expect("before");
    policy.rules.reverse();
    let after = evaluate(&policy, &input).expect("after");
    assert_eq!(before.results, after.results);
    let ids: Vec<&str> = before.results.iter().map(|r| r.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["a-first", "b-second"]);
}

#[test]
fn overlapping_rules_intersect() {
    let policy = parse_policy_text(PAIR_POLICY).expect("parse");
    let input = input_bundle(
        true,
        &[SOURCE],
        vec![fact("ev-1", "host-hypervisor")],
        vec![],
    );
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(out.results.len(), 2);
    assert_eq!(out.results[0].rule_id, "a-first");
    assert_eq!(out.results[0].result, "conforms");
    assert_eq!(out.results[1].rule_id, "b-second");
    assert_eq!(out.results[1].result, "violates");
    assert_eq!(out.overall, "violates");
}

#[test]
fn exception_covers_only_its_named_rule() {
    let policy = parse_policy_text(PAIR_POLICY).expect("parse");
    let input = input_bundle(true, &[SOURCE], vec![fact("ev-1", "host-device")], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(out.results[0].result, "deviates_known");
    assert_eq!(out.results[1].result, "violates");
    assert_eq!(out.overall, "violates");
    assert_eq!(strict_exit(&out.overall), 5);
}

#[test]
fn unmatched_activity_is_shown_separately() {
    let policy = parse_policy_text(CLOSED_POLICY).expect("parse");
    let mut stray = fact("ev-stray", "host-device");
    stray.source_id = "sharing-census".to_string();
    stray.semantics = "inventory".to_string();
    let input = input_bundle(true, &[SOURCE, "sharing-census"], vec![stray], vec![]);
    let out = evaluate(&policy, &input).expect("evaluate");
    assert_eq!(only(&out.results).result, "conforms");
    assert_eq!(out.unselected_evidence, vec!["ev-stray".to_string()]);
}

#[test]
fn strict_exit_table() {
    assert_eq!(strict_exit("conforms"), 0);
    assert_eq!(strict_exit("deviates_known"), 0);
    assert_eq!(strict_exit("violates"), 5);
    assert_eq!(strict_exit("inconclusive"), 4);
    assert_eq!(strict_exit("unavailable"), 4);
    assert_eq!(strict_exit("bogus"), 2);
}

fn refuse_code(text: &str) -> String {
    parse_policy_text(text)
        .expect_err("must refuse")
        .code
        .to_string()
}

#[test]
fn reader_refuses_malformed_policies() {
    assert_eq!(refuse_code("not json"), "malformed");
    assert_eq!(refuse_code(r#"{"schema": "policy"}"#), "missing-field");
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""schema_version": "0.1.0""#,
            r#""schema_version": "9.9.9""#
        )),
        "bad-version"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""permitted": "allowlisted-only""#,
            r#""permitted": "anything-goes""#
        )),
        "unknown-permitted"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(r#""window": "capture""#, r#""window": "forever""#)),
        "unknown-window"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""clock": "guest_monotonic_active""#,
            r#""clock": "wallclock""#
        )),
        "unknown-clock"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""selector": {"capability": "dma-paths", "source_id": "dma-virtio-paths", "semantics": "request"}"#,
            r#""selector": {"wiggle": "x"}"#
        )),
        "unknown-field"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(r#""field": "peer_class""#, r#""field": "kind""#)),
        "deferred-field"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""selector": {"capability": "dma-paths", "source_id": "dma-virtio-paths", "semantics": "request"}"#,
            r#""selector": {}"#
        )),
        "empty-selector"
    );
    assert_eq!(
        refuse_code(&CLOSED_POLICY.replace(
            r#""subject_scope": "virtio-queue-lifetimes""#,
            r#""subject_scope": """#
        )),
        "empty-scope"
    );
}

#[test]
fn reader_refuses_duplicate_keys_and_ids() {
    let dup_key = CLOSED_POLICY.replace(
        r#""policy_id": "closed-scope","#,
        r#""policy_id": "closed-scope", "policy_id": "dup","#,
    );
    assert_eq!(refuse_code(&dup_key), "duplicate-key");
    let two_same = PAIR_POLICY
        .replace(r#""rule_id": "b-second""#, r#""rule_id": "same-id""#)
        .replace(r#""rule_id": "a-first""#, r#""rule_id": "same-id""#);
    assert_eq!(refuse_code(&two_same), "duplicate-rule");
    let exc_twice = r#"{
  "schema": "policy",
  "schema_version": "0.1.0",
  "policy_id": "p",
  "subject_scope": "s",
  "applies_to": {"platform": "ordinary-linux", "profile": "x"},
  "required_sources": ["dma-virtio-paths"],
  "clock": "guest_monotonic_active",
  "role_bindings": {},
  "rules": [
    {"rule_id": "r1", "selector": {"source_id": "dma-virtio-paths"}, "permitted": "allowlisted-only", "limit": {"window": "capture", "max": "0"}, "obligation": null},
    {"rule_id": "r2", "selector": {"source_id": "dma-virtio-paths"}, "permitted": "allowlisted-only", "limit": {"window": "capture", "max": "0"}, "obligation": null}
  ],
  "exceptions": [
    {"exception_id": "e", "rule_id": "r1", "field": "peer_class", "values": ["host-device"], "reason": "x"},
    {"exception_id": "e", "rule_id": "r2", "field": "peer_class", "values": ["host-device"], "reason": "x"}
  ]
}"#;
    assert_eq!(refuse_code(exc_twice), "duplicate-exception");
    let dup_source = CLOSED_POLICY.replace(
        r#""required_sources": ["dma-virtio-paths"]"#,
        r#""required_sources": ["dma-virtio-paths", "dma-virtio-paths"]"#,
    );
    assert_eq!(refuse_code(&dup_source), "duplicate-source");
}

#[test]
fn reader_refuses_dangling_and_misplaced_exceptions() {
    let dangling = CLOSED_POLICY.replace(
        r#""rule_id": "no-unexpected-queue", "field""#,
        r#""rule_id": "no-such-rule", "field""#,
    );
    assert_eq!(refuse_code(&dangling), "dangling-exception");
    let text = BOUNDARY_POLICY.replace(
        r#""exceptions": []"#,
        r#""exceptions": [{"exception_id": "e1", "rule_id": "queues-released", "field": "peer_class", "values": ["host-device"], "reason": "misplaced"}]"#,
    );
    assert_eq!(refuse_code(&text), "obligation-exception");
    let misplaced = CLOSED_POLICY.replace(
        r#""semantics": "request""#,
        r#""semantics": "request", "object_class": "queue""#,
    );
    assert_eq!(refuse_code(&misplaced), "selector-misplaced");
    let fact_in_obligation = BOUNDARY_POLICY.replace(
        r#""object_class": "queue", "source_id": "dma-virtio-paths""#,
        r#""object_class": "queue", "peer_class": "host-device""#,
    );
    assert_eq!(refuse_code(&fact_in_obligation), "selector-misplaced");
}

#[test]
fn reader_refuses_bad_obligations_and_integers() {
    let no_clock = BOUNDARY_POLICY.replace(
        r#""obligation": {"status": "released"}"#,
        r#""obligation": {"status": "released", "within": "5000"}"#,
    );
    assert_eq!(refuse_code(&no_clock), "within-needs-clock");
    let clock_only = BOUNDARY_POLICY.replace(
        r#""obligation": {"status": "released"}"#,
        r#""obligation": {"status": "released", "clock": "guest_monotonic_active"}"#,
    );
    assert_eq!(refuse_code(&clock_only), "clock-without-duration");
    let bad_status = BOUNDARY_POLICY.replace(r#""status": "released""#, r#""status": "vaporized""#);
    assert_eq!(refuse_code(&bad_status), "unknown-status");
    for bad in ["18446744073709551616", "01", "", "-1", "12x", " 3", "3 "] {
        let text = CLOSED_POLICY.replace(r#""max": "0""#, &format!(r#""max": "{bad}""#));
        assert_eq!(refuse_code(&text), "bad-integer", "max {bad:?}");
    }
    assert_eq!(parse_decimal_u64("0").expect("zero"), 0);
    assert_eq!(
        parse_decimal_u64("18446744073709551615").expect("u64 max"),
        u64::MAX
    );
}

#[test]
fn reader_enforces_document_bounds() {
    let big = "x".repeat(1024 * 1024 + 1);
    assert_eq!(refuse_code(&big), "too-big");
    let id65 = "i".repeat(65);
    let text = CLOSED_POLICY
        .replace("closed-scope", &id65)
        .replace("no-unexpected-queue", "r")
        .replace("admitted-device-path", "e");
    assert_eq!(refuse_code(&text), "bad-id");
    let non_ascii = CLOSED_POLICY.replace("closed-scope", "política-1");
    assert_eq!(refuse_code(&non_ascii), "bad-id");
    let mut rules = String::from("[");
    for n in 0..1025 {
        if n > 0 {
            rules.push(',');
        }
        rules.push_str(&format!(
            r#"{{"rule_id": "r{n}", "selector": {{"source_id": "dma-virtio-paths"}}, "permitted": "allowlisted-only", "limit": {{"window": "capture", "max": "0"}}, "obligation": null}}"#
        ));
    }
    rules.push(']');
    let many = format!(
        r#"{{"schema": "policy", "schema_version": "0.1.0", "policy_id": "p", "subject_scope": "s", "applies_to": {{"platform": "ordinary-linux", "profile": "x"}}, "required_sources": ["dma-virtio-paths"], "clock": "guest_monotonic_active", "role_bindings": {{}}, "rules": {rules}, "exceptions": []}}"#
    );
    assert_eq!(refuse_code(&many), "too-many-rules");
    let mut excs = String::from("[");
    for n in 0..65 {
        if n > 0 {
            excs.push(',');
        }
        excs.push_str(&format!(
            r#"{{"exception_id": "e{n}", "rule_id": "r0", "field": "peer_class", "values": ["host-device"], "reason": "x"}}"#
        ));
    }
    excs.push(']');
    let single = r#"{"rule_id": "r0", "selector": {"source_id": "dma-virtio-paths"}, "permitted": "allowlisted-only", "limit": {"window": "capture", "max": "0"}, "obligation": null}"#;
    let crowded = format!(
        r#"{{"schema": "policy", "schema_version": "0.1.0", "policy_id": "p", "subject_scope": "s", "applies_to": {{"platform": "ordinary-linux", "profile": "x"}}, "required_sources": ["dma-virtio-paths"], "clock": "guest_monotonic_active", "role_bindings": {{}}, "rules": [{single}], "exceptions": {excs}}}"#
    );
    assert_eq!(refuse_code(&crowded), "too-many-exceptions");
    let deep = "[".repeat(65) + &"]".repeat(65);
    assert_eq!(
        parse_json(&deep).expect_err("deep nests").code.to_string(),
        "too-deep"
    );
}

#[test]
fn oversized_policy_file_refuses_too_big() {
    let path = std::env::temp_dir().join(format!(
        "policy-check-oversized-{}.json",
        std::process::id()
    ));
    fs::write(&path, vec![b'x'; 1024 * 1024 + 1]).expect("write oversized file");
    let code = read_policy_file(&path)
        .expect_err("oversized file refuses")
        .code;
    fs::remove_file(&path).expect("remove oversized file");
    assert_eq!(code, "too-big");
}

#[test]
fn endless_policy_source_refuses_without_reading_it_all() {
    let (done, wait) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let outcome = read_policy_file(Path::new("/dev/zero")).map(|_| "parsed");
        let _ = done.send(outcome.map_err(|err| err.code));
    });
    let outcome = wait
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("bounded read finishes promptly");
    assert_eq!(outcome.unwrap_err(), "too-big");
}

#[test]
fn json_parser_handles_values_and_escapes() {
    let value = parse_json(
        r#"{"s": "a\"b\\c\/d\u0008e\u000cf\n\r\té", "n": -12.5e2, "t": true, "f": false, "z": null, "a": [1, "x"], "u": "\u0041\u00e9"}"#,
    )
    .expect("values parse");
    let Json::Obj(pairs) = value else {
        panic!("want object");
    };
    assert_eq!(pairs.len(), 7);
    let get = |key: &str| {
        pairs
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
            .expect("key present")
    };
    assert_eq!(
        get("s"),
        &Json::Str("a\"b\\c/d\u{8}e\u{c}f\n\r\té".to_string())
    );
    assert_eq!(get("n"), &Json::Num("-12.5e2".to_string()));
    assert_eq!(get("t"), &Json::Bool(true));
    assert_eq!(get("f"), &Json::Bool(false));
    assert_eq!(get("z"), &Json::Null);
    assert_eq!(get("u"), &Json::Str("Aé".to_string()));
    assert!(parse_json(r#"{"a": 1} trailing"#).is_err());
    assert!(parse_json("").is_err());
    assert!(parse_json(r#"{"a": 01}"#).is_err());
    let dup = parse_json(r#"{"k": 1, "k": 2}"#).expect_err("dup key");
    assert_eq!(dup.code.to_string(), "duplicate-key");
    let nested = parse_json(r#"{"o": {"k": 1, "k": 2}}"#).expect_err("nested dup");
    assert_eq!(nested.code.to_string(), "duplicate-key");
    assert!(parse_json("\"\u{0}literal\"").is_err());
}

#[test]
fn large_non_ascii_document_parses_promptly() {
    let document = format!("[\"{}\"]", "é".repeat(200_000));
    assert!(document.len() < 1024 * 1024, "document fits the size cap");
    let start = std::time::Instant::now();
    let value = parse_json(&document).expect("large document parses");
    let elapsed = start.elapsed();
    let Json::Arr(items) = value else {
        panic!("want array");
    };
    assert_eq!(items.len(), 1);
    let Json::Str(text) = &items[0] else {
        panic!("want string");
    };
    assert_eq!(text.chars().count(), 200_000);
    assert!(
        elapsed < std::time::Duration::from_secs(30),
        "parse took {elapsed:?}, want milliseconds"
    );
}

#[test]
fn reader_refuses_residual_bad_shapes() {
    let top_extra = CLOSED_POLICY.replace(r#""exceptions": ["#, r#""mystery": 1, "exceptions": ["#);
    assert_eq!(refuse_code(&top_extra), "unknown-field");
    let rule_extra = CLOSED_POLICY.replace(
        r#""obligation": null"#,
        r#""obligation": null, "mystery": 1"#,
    );
    assert_eq!(refuse_code(&rule_extra), "unknown-field");
    let empty_reason =
        CLOSED_POLICY.replace(r#""reason": "admitted device path""#, r#""reason": """#);
    assert_eq!(refuse_code(&empty_reason), "bad-reason");
    let empty_values = CLOSED_POLICY.replace(r#""values": ["host-device"]"#, r#""values": []"#);
    assert_eq!(refuse_code(&empty_values), "empty-values");
    let mut values = String::from("[");
    for n in 0..65 {
        if n > 0 {
            values.push(',');
        }
        values.push_str(&format!(r#""v{n}""#));
    }
    values.push(']');
    let crowded_values = CLOSED_POLICY.replace(
        r#""values": ["host-device"]"#,
        &format!(r#""values": {values}"#),
    );
    assert_eq!(refuse_code(&crowded_values), "too-many-values");
    let empty_findings = CLOSED_POLICY.replace(
        r#""exceptions": ["#,
        r#""expected_findings": [], "exceptions": ["#,
    );
    assert_eq!(refuse_code(&empty_findings), "bad-findings");
    let mut bindings = String::from("{");
    for n in 0..1025 {
        if n > 0 {
            bindings.push(',');
        }
        bindings.push_str(&format!(r#""k{n}": "v{n}""#));
    }
    bindings.push('}');
    let crowded_bindings = CLOSED_POLICY.replace(
        r#""role_bindings": {}"#,
        &format!(r#""role_bindings": {bindings}"#),
    );
    assert_eq!(refuse_code(&crowded_bindings), "too-many-bindings");
    let mut sources = String::from("[");
    for n in 0..1025 {
        if n > 0 {
            sources.push(',');
        }
        sources.push_str(&format!(r#""s{n}""#));
    }
    sources.push(']');
    let crowded_sources = CLOSED_POLICY.replace(
        r#""required_sources": ["dma-virtio-paths"]"#,
        &format!(r#""required_sources": {sources}"#),
    );
    assert_eq!(refuse_code(&crowded_sources), "too-many-sources");
}

#[test]
fn reader_tolerates_documented_doc_fields() {
    let text = CLOSED_POLICY.replace(
        r#""exceptions": ["#,
        r#""prerequisites": {"platform_cell": "ordinary-linux", "workload": "synthetic offline bundle"}, "expected_findings": ["uncovered request violates"], "exceptions": ["#,
    );
    let policy = parse_policy_text(&text).expect("doc fields tolerated");
    assert_eq!(policy.policy_id, "closed-scope");
    let prereq = policy.prerequisites.as_ref().expect("prerequisites kept");
    assert_eq!(prereq.platform_cell, "ordinary-linux");
    assert_eq!(prereq.workload, "synthetic offline bundle");
    assert_eq!(
        policy.expected_findings,
        vec!["uncovered request violates".to_string()]
    );
    let bad_shape = CLOSED_POLICY.replace(
        r#""exceptions": ["#,
        r#""prerequisites": {"platform_cell": 7}, "exceptions": ["#,
    );
    assert_eq!(refuse_code(&bad_shape), "bad-prerequisites");
}

fn fixture_dir() -> PathBuf {
    PathBuf::from("tests/exposure/fixtures/policy")
}

fn sorted_names(dir: &Path, suffix: &str) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect("fixture dir readable")
        .map(|entry| entry.expect("dir entry").file_name())
        .map(|name| name.to_str().expect("utf-8 name").to_string())
        .filter(|name| name.ends_with(suffix))
        .collect();
    names.sort();
    names
}

#[test]
fn corpus_policies_match_their_names() {
    let dir = fixture_dir();
    let names = sorted_names(&dir, ".policy.json");
    assert!(!names.is_empty(), "policy corpus must exist");
    for name in names {
        let path = dir.join(&name);
        let verdict = read_policy_file(&path);
        if name.starts_with("ok-") {
            verdict.unwrap_or_else(|_| panic!("{name} must parse"));
        } else if name.starts_with("refuse-") {
            assert!(verdict.is_err(), "{name} must refuse");
        } else {
            panic!("corpus name needs ok-/refuse- prefix: {name}");
        }
    }
}

#[test]
fn worked_examples_parse() {
    let dir = PathBuf::from("examples/policies");
    let names = sorted_names(&dir, ".json");
    assert_eq!(
        names,
        vec![
            "closed-scope.json".to_string(),
            "config-deviation.json".to_string(),
            "lifecycle-boundary.json".to_string(),
        ]
    );
    for name in names {
        let policy = read_policy_file(&dir.join(&name)).unwrap_or_else(|_| panic!("{name} parses"));
        assert!(
            policy.prerequisites.is_some(),
            "{name} must state prerequisites"
        );
        assert!(
            !policy.expected_findings.is_empty(),
            "{name} must state expected findings"
        );
    }
}

fn obj<'a>(value: &'a Json, what: &str) -> &'a Vec<(String, Json)> {
    match value {
        Json::Obj(pairs) => pairs,
        _ => panic!("{what} must be an object"),
    }
}

fn field<'a>(pairs: &'a [(String, Json)], key: &str, what: &str) -> &'a Json {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v)
        .unwrap_or_else(|| panic!("{what} lacks {key}"))
}

fn text<'a>(value: &'a Json, what: &str) -> &'a str {
    match value {
        Json::Str(s) => s,
        _ => panic!("{what} must be a string"),
    }
}

fn opt_text(value: &Json) -> Option<String> {
    match value {
        Json::Null => None,
        Json::Str(s) => Some(s.clone()),
        _ => panic!("optional text must be string or null"),
    }
}

fn opt_field(pairs: &[(String, Json)], key: &str) -> Option<String> {
    pairs
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| opt_text(v))
}

fn flag(value: &Json, what: &str) -> bool {
    match value {
        Json::Bool(b) => *b,
        _ => panic!("{what} must be a boolean"),
    }
}

fn items<'a>(value: &'a Json, what: &str) -> &'a [Json] {
    match value {
        Json::Arr(list) => list,
        _ => panic!("{what} must be an array"),
    }
}

fn eval_input_from(path: &Path) -> EvalInput {
    let raw = fs::read_to_string(path).expect("input readable");
    let root = parse_json(&raw).expect("input parses");
    let top = obj(&root, "input");
    let what = path.display().to_string();
    let facts = items(field(top, "facts", &what), "facts")
        .iter()
        .map(|entry| {
            let f = obj(entry, "fact");
            Fact {
                evidence_id: text(field(f, "evidence_id", &what), "evidence_id").to_string(),
                capture_id: text(field(f, "capture_id", &what), "capture_id").to_string(),
                source_id: text(field(f, "source_id", &what), "source_id").to_string(),
                capability: opt_field(f, "capability"),
                semantics: text(field(f, "semantics", &what), "semantics").to_string(),
                peer_class: text(field(f, "peer_class", &what), "peer_class").to_string(),
                clock_domain: text(field(f, "clock_domain", &what), "clock_domain").to_string(),
                kind: opt_field(f, "kind"),
                direction: opt_field(f, "direction"),
                caller_class: opt_field(f, "caller_class"),
            }
        })
        .collect();
    let objects = items(field(top, "objects", &what), "objects")
        .iter()
        .map(|entry| {
            let o = obj(entry, "object");
            Object {
                object_token: text(field(o, "object_token", &what), "token").to_string(),
                generation: parse_decimal_u64(text(field(o, "generation", &what), "generation"))
                    .expect("canonical generation"),
                capture_id: text(field(o, "capture_id", &what), "capture_id").to_string(),
                object_class: text(field(o, "object_class", &what), "class").to_string(),
                origin_source: text(field(o, "origin_source", &what), "origin").to_string(),
                lifecycle_status: text(field(o, "lifecycle_status", &what), "status").to_string(),
                elapsed: o
                    .iter()
                    .find(|(k, _)| k == "elapsed")
                    .map(|(_, v)| parse_decimal_u64(text(v, "elapsed")).expect("elapsed")),
                elapsed_clock: opt_field(o, "elapsed_clock"),
            }
        })
        .collect();
    EvalInput {
        scope_id: text(field(top, "scope_id", &what), "scope_id").to_string(),
        capture_id: text(field(top, "capture_id", &what), "capture_id").to_string(),
        finalized: flag(field(top, "finalized", &what), "finalized"),
        available_sources: items(field(top, "available_sources", &what), "sources")
            .iter()
            .map(|s| text(s, "source").to_string())
            .collect(),
        facts,
        objects,
    }
}

fn strings(value: &Json, what: &str) -> Vec<String> {
    items(value, what)
        .iter()
        .map(|s| text(s, what).to_string())
        .collect()
}

fn golden_from(path: &Path) -> (String, String, Vec<PolicyResult>, i32) {
    let raw = fs::read_to_string(path).expect("golden readable");
    let root = parse_json(&raw).expect("golden parses");
    let top = obj(&root, "golden");
    let what = path.display().to_string();
    let results = items(field(top, "results", &what), "results")
        .iter()
        .map(|entry| {
            let r = obj(entry, "result");
            PolicyResult {
                rule_id: text(field(r, "rule_id", &what), "rule_id").to_string(),
                scope_id: text(field(r, "scope_id", &what), "scope_id").to_string(),
                result: text(field(r, "result", &what), "result").to_string(),
                evidence_ids: strings(field(r, "evidence_ids", &what), "evidence"),
                missing_sources: strings(field(r, "missing_sources", &what), "missing"),
                exceptions_applied: strings(field(r, "exceptions_applied", &what), "applied"),
                clock_domain: text(field(r, "clock_domain", &what), "clock").to_string(),
                reason: text(field(r, "reason", &what), "reason").to_string(),
            }
        })
        .collect();
    let exit = match field(top, "strict_exit", &what) {
        Json::Num(raw) => raw.parse::<i32>().expect("exit parses"),
        _ => panic!("strict_exit must be a number"),
    };
    (
        text(field(top, "policy", &what), "policy").to_string(),
        text(field(top, "input", &what), "input").to_string(),
        results,
        exit,
    )
}

#[test]
fn golden_evaluations_match() {
    let dir = fixture_dir();
    let names = sorted_names(&dir, ".expected.json");
    assert!(names.len() >= 5, "goldens must cover all five outcomes");
    for name in names {
        let (policy_name, input_name, want_results, want_exit) = golden_from(&dir.join(&name));
        let policy = read_policy_file(&dir.join(&policy_name))
            .unwrap_or_else(|_| panic!("{name} policy parses"));
        let input = eval_input_from(&dir.join(&input_name));
        let out = evaluate(&policy, &input).unwrap_or_else(|_| panic!("{name} evaluates"));
        assert_eq!(out.results, want_results, "{name} results");
        assert_eq!(strict_exit(&out.overall), want_exit, "{name} exit");
        for result in &out.results {
            assert!(
                result.reason.contains("next:"),
                "{name} {} lacks a next step",
                result.rule_id
            );
        }
    }
}
