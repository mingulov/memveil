// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline authored-policy evaluation over persisted exposure records.
//!
//! A policy states, in finite enumerated selectors and exact
//! labels, which operations and object lifetimes an allowlist
//! admits; evaluation compares one finalized capture bundle
//! against it and yields one [`PolicyResult`] per rule. There
//! is no learning: the same policy and bundle always yield
//! the same results, and observed activity never widens the
//! allowlist.
//!
//! Contract (frozen public text `docs/exposure-policy.md`
//! with the exposure catalog vocabularies):
//!
//! * Rules intersect: every rule sees every record, and an
//!   exception names exactly one rule, so covering one rule
//!   never silences another.
//! * A proved violation outranks unrelated loss but keeps
//!   the gap visible in `missing_sources`.
//! * An unknown selector value, a deferred-vocabulary
//!   field, a record that lacks a selected field, or a
//!   record carrying an unresolvable label is
//!   inconclusive, never an allowlist match.
//! * Conforming needs a finalized capture with complete
//!   required sources; a censored capture is not teardown.
//! * Records from another capture never match: opaque ids
//!   compare only through the capture they arrive with.
//!
//! The frozen label lists below transcribe catalog
//! `exposure_catalog_version 0.1.0`; the Python artifact
//! suite pins them against `profiles/exposure/catalog.json`
//! so drift fails loudly.
//!
//! Integration wiring: this file is intentionally
//! dependency-free (`std` only). The lane test includes it
//! via `#[path]`; the controller moves it under `analysis/`
//! and points `platform/policy_reader.rs` at its new home.

/// Policy file schema marker.
pub const POLICY_SCHEMA: &str = "policy";
/// Policy file schema version this lane reads.
pub const POLICY_SCHEMA_VERSION: &str = "0.1.0";

/// Frozen fact semantics (catalog vocabularies).
pub const KNOWN_SEMANTICS: &[&str] = &[
    "request",
    "result",
    "inventory",
    "lifecycle",
    "state",
    "native_rejection",
];
/// Frozen peer classes (catalog vocabularies).
pub const KNOWN_PEER_CLASSES: &[&str] = &[
    "none-observed",
    "host-device",
    "device-or-subsystem",
    "device",
    "host-hypervisor",
    "host-tdx-module",
    "host-or-paravisor",
];
/// Frozen clock domains (catalog vocabularies).
pub const KNOWN_CLOCK_DOMAINS: &[&str] = &[
    "guest_monotonic_active",
    "guest_boottime_elapsed",
    "external_trusted_interval",
];
/// Frozen object classes (catalog vocabularies).
pub const KNOWN_OBJECT_CLASSES: &[&str] = &["queue", "buffer", "channel", "mapping", "heap_object"];
/// Frozen lifecycle statuses (catalog vocabularies).
pub const KNOWN_LIFECYCLE_STATUSES: &[&str] =
    &["created", "live", "released", "quarantined", "unknown"];
/// Frozen policy outcomes (catalog vocabularies).
pub const KNOWN_POLICY_RESULTS: &[&str] = &[
    "conforms",
    "deviates_known",
    "violates",
    "inconclusive",
    "unavailable",
];
/// Catalog capability ids (planning freeze).
pub const KNOWN_CAPABILITIES: &[&str] = &[
    "attempt-trace",
    "mapping-lifecycle",
    "copy-actual",
    "conversion-observe",
    "conversion-journal",
    "census",
    "object-lifetimes",
    "dma-paths",
    "shared-buffers",
    "host-interfaces",
    "mapping-inventory",
    "exposure-context",
];
/// Catalog source ids (planning freeze).
pub const KNOWN_SOURCES: &[&str] = &[
    "conversion-requests",
    "sharing-census",
    "object-lineage",
    "dma-virtio-paths",
    "heap-dmabuf-objects",
    "ghcb-exceptions",
    "tdx-conversions",
    "tdx-ve-metadata",
    "vmbus-channels",
    "mapping-inventory-scan",
    "egress-controls",
];

/// Evidence ids carried per result; longer lists note the rest.
const MAX_EVIDENCE_IDS: usize = 1024;
/// Detail lines carried per reason; longer lists note the rest.
const MAX_REASON_DETAILS: usize = 32;

/// Admitted revert boundary or declared duration for one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Obligation {
    /// Lifecycle status the selected objects must reach.
    pub status: String,
    /// Declared duration bound, in the declared clock.
    pub within: Option<u64>,
    /// Clock the duration is measured in.
    pub clock: Option<String>,
}

/// One authored rule: selector AND-constraints plus a limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Stable authored rule id.
    pub rule_id: String,
    /// Exact (field, label) constraints, sorted by field.
    pub selector: Vec<(String, String)>,
    /// Permitted activity; only `allowlisted-only` exists.
    pub permitted: String,
    /// Limit window; only `capture` exists.
    pub limit_window: String,
    /// Admitted unexpected (or non-conforming) count.
    pub limit_max: u64,
    /// Present for lifecycle-boundary rules only.
    pub obligation: Option<Obligation>,
}

/// One exact bounded exception naming a single rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exception {
    /// Stable authored exception id.
    pub exception_id: String,
    /// The one rule this exception may cover.
    pub rule_id: String,
    /// The one record field this exception discriminates on.
    pub field: String,
    /// Exact admitted labels for that field.
    pub values: Vec<String>,
    /// Human note on why the exception is admitted.
    pub reason: String,
}

/// Documented platform/workload prerequisites (not evaluated).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prerequisites {
    /// Exact platform cell the policy targets.
    pub platform_cell: String,
    /// Workload the policy was authored against.
    pub workload: String,
}

/// One parsed policy-v0.1.0 document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// Policy id.
    pub policy_id: String,
    /// Scope every rule evaluates against.
    pub subject_scope: String,
    /// Target platform cell (validated shape, not evaluated).
    pub platform: String,
    /// Target profile pin (validated shape, not evaluated).
    pub profile: String,
    /// Sources the evaluation requires.
    pub required_sources: Vec<String>,
    /// Clock contract of the evaluation.
    pub clock: String,
    /// Logical-role bindings (validated, deferred to compare).
    pub role_bindings: Vec<(String, String)>,
    /// Authored rules.
    pub rules: Vec<Rule>,
    /// Top-level bounded exceptions.
    pub exceptions: Vec<Exception>,
    /// Optional documented prerequisites.
    pub prerequisites: Option<Prerequisites>,
    /// Optional documented expected findings.
    pub expected_findings: Vec<String>,
}

/// One persisted operation record (catalog ExposureFact subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// Session-unique evidence handle.
    pub evidence_id: String,
    /// Capture the record belongs to.
    pub capture_id: String,
    /// Catalog source entry.
    pub source_id: String,
    /// Owning capability, when the producer states it.
    pub capability: Option<String>,
    /// Record semantics class.
    pub semantics: String,
    /// Peer class; frozen labels only.
    pub peer_class: String,
    /// Clock domain of the observation.
    pub clock_domain: String,
    /// Deferred-vocabulary fields stay optional and unusable.
    pub kind: Option<String>,
    /// Deferred-vocabulary fields stay optional and unusable.
    pub direction: Option<String>,
    /// Deferred-vocabulary fields stay optional and unusable.
    pub caller_class: Option<String>,
}

/// One persisted object record (catalog ExposureObject subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Object {
    /// Session-local opaque token; never a physical address.
    pub object_token: String,
    /// Lineage generation.
    pub generation: u64,
    /// Capture the record belongs to.
    pub capture_id: String,
    /// Frozen object class.
    pub object_class: String,
    /// Catalog source that first observed the object.
    pub origin_source: String,
    /// Current lifecycle status.
    pub lifecycle_status: String,
    /// Elapsed boundary duration, when measured.
    pub elapsed: Option<u64>,
    /// Clock the elapsed duration is measured in.
    pub elapsed_clock: Option<String>,
}

/// One offline evaluation bundle: a single capture scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalInput {
    /// Scope the bundle covers.
    pub scope_id: String,
    /// Capture under evaluation.
    pub capture_id: String,
    /// False for censored or recovered-unfinalized captures.
    pub finalized: bool,
    /// Catalog sources present in the bundle.
    pub available_sources: Vec<String>,
    /// Operation records.
    pub facts: Vec<Fact>,
    /// Object records.
    pub objects: Vec<Object>,
}

/// One rule outcome (catalog PolicyResult shape).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    /// Stable authored rule id.
    pub rule_id: String,
    /// Scope the rule was evaluated against.
    pub scope_id: String,
    /// One of the frozen policy outcomes.
    pub result: String,
    /// Evidence supporting this result.
    pub evidence_ids: Vec<String>,
    /// Required sources absent from the capture.
    pub missing_sources: Vec<String>,
    /// Bounded exceptions that applied, as `rule:exception`.
    pub exceptions_applied: Vec<String>,
    /// Clock domain of the temporal evaluation.
    pub clock_domain: String,
    /// Outcome explanation with a next investigation.
    pub reason: String,
}

/// Full evaluation: per-rule results plus capture-level notes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    /// Per-rule results, sorted by rule id.
    pub results: Vec<PolicyResult>,
    /// Worst-of aggregate outcome.
    pub overall: String,
    /// Capture-scoped facts no rule selected, shown separately.
    pub unselected_evidence: Vec<String>,
    /// Records refused for belonging to another capture.
    pub refused_cross_capture: usize,
}

/// Evaluation refusal (wrong scope bundle, never a guess).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvalError {
    /// Human detail; callers match on construction, never text.
    pub message: String,
}

impl std::fmt::Display for EvalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for EvalError {}

fn vocab(field: &str) -> Option<&'static [&'static str]> {
    match field {
        "capability" => Some(KNOWN_CAPABILITIES),
        "source_id" => Some(KNOWN_SOURCES),
        "semantics" => Some(KNOWN_SEMANTICS),
        "peer_class" => Some(KNOWN_PEER_CLASSES),
        "clock_domain" => Some(KNOWN_CLOCK_DOMAINS),
        "object_class" => Some(KNOWN_OBJECT_CLASSES),
        _ => None,
    }
}

fn is_deferred(field: &str) -> bool {
    matches!(field, "kind" | "direction" | "caller_class")
}

fn fact_field<'a>(fact: &'a Fact, field: &str) -> Option<&'a str> {
    match field {
        "capability" => fact.capability.as_deref(),
        "source_id" => Some(fact.source_id.as_str()),
        "semantics" => Some(fact.semantics.as_str()),
        "peer_class" => Some(fact.peer_class.as_str()),
        "clock_domain" => Some(fact.clock_domain.as_str()),
        "kind" => fact.kind.as_deref(),
        "direction" => fact.direction.as_deref(),
        "caller_class" => fact.caller_class.as_deref(),
        _ => None,
    }
}

/// Sort, dedupe, and cap an id list, noting the remainder.
fn cap_list(mut ids: Vec<String>, max: usize) -> (Vec<String>, usize) {
    ids.sort();
    ids.dedup();
    let rest = ids.len().saturating_sub(max);
    ids.truncate(max);
    (ids, rest)
}

fn render_list(ids: &[String], rest: usize) -> String {
    if rest == 0 {
        return ids.join(", ");
    }
    format!("{} (+{rest} more)", ids.join(", "))
}

/// Evaluate every rule of `policy` against one capture bundle.
///
/// Rules evaluate independently over the same records; the
/// returned results sort by rule id so authoring order never
/// changes the output. Records from another capture are
/// refused, never matched.
pub fn evaluate(policy: &Policy, input: &EvalInput) -> Result<Evaluation, EvalError> {
    if policy.subject_scope != input.scope_id {
        return Err(EvalError {
            message: format!(
                "scope mismatch: policy wants '{}', input carries '{}'",
                policy.subject_scope, input.scope_id
            ),
        });
    }
    let mut refused = 0usize;
    let facts: Vec<&Fact> = input
        .facts
        .iter()
        .filter(|fact| {
            if fact.capture_id == input.capture_id {
                true
            } else {
                refused += 1;
                false
            }
        })
        .collect();
    let objects: Vec<&Object> = input
        .objects
        .iter()
        .filter(|object| {
            if object.capture_id == input.capture_id {
                true
            } else {
                refused += 1;
                false
            }
        })
        .collect();
    let mut missing: Vec<String> = policy
        .required_sources
        .iter()
        .filter(|source| !input.available_sources.contains(source))
        .cloned()
        .collect();
    missing.sort();
    missing.dedup();
    let mut results = Vec::with_capacity(policy.rules.len());
    let mut matched_all: Vec<String> = Vec::new();
    for rule in &policy.rules {
        let (result, matched) = if rule.obligation.is_some() {
            eval_obligation_rule(policy, input, &objects, &missing, rule)
        } else {
            eval_fact_rule(policy, input, &facts, &missing, rule)
        };
        matched_all.extend(matched);
        results.push(result);
    }
    results.sort_by(|a, b| a.rule_id.cmp(&b.rule_id));
    matched_all.sort();
    matched_all.dedup();
    let mut unselected: Vec<String> = facts
        .iter()
        .map(|fact| fact.evidence_id.clone())
        .filter(|id| !matched_all.contains(id))
        .collect();
    unselected.sort();
    Ok(Evaluation {
        overall: aggregate(&results).to_string(),
        results,
        unselected_evidence: unselected,
        refused_cross_capture: refused,
    })
}

/// Worst-of aggregate: violates, then inconclusive (an
/// unavailable required source counts here), then
/// deviates_known, then conforms.
pub fn aggregate(results: &[PolicyResult]) -> &'static str {
    let mut level = 0;
    for result in results {
        let rank = match result.result.as_str() {
            "violates" => 3,
            "inconclusive" | "unavailable" => 2,
            "deviates_known" => 1,
            _ => 0,
        };
        level = level.max(rank);
    }
    match level {
        3 => "violates",
        2 => "inconclusive",
        1 => "deviates_known",
        _ => "conforms",
    }
}

/// Strict exit for an aggregate outcome: proved violation is
/// 5, incomplete required evidence is 4, otherwise 0. An
/// unknown outcome refuses with 2 rather than guessing.
pub fn strict_exit(overall: &str) -> i32 {
    if !KNOWN_POLICY_RESULTS.contains(&overall) {
        return 2;
    }
    match overall {
        "violates" => 5,
        "inconclusive" | "unavailable" => 4,
        _ => 0,
    }
}

fn unavailable_reason(rule_id: &str, missing: &[String]) -> String {
    format!(
        "rule '{rule_id}': required sources absent: [{}]; next: re-run with the required collection admitted",
        missing.join(", ")
    )
}

fn inconclusive_reason(rule_id: &str, mut details: Vec<String>) -> String {
    details.sort();
    details.dedup();
    let rest = details.len().saturating_sub(MAX_REASON_DETAILS);
    details.truncate(MAX_REASON_DETAILS);
    let rendered = render_list(&details, rest);
    format!(
        "rule '{rule_id}': cannot resolve: {rendered}; next: re-run with complete observation or narrow the rule to frozen labels"
    )
}

fn missing_suffix(missing: &[String]) -> String {
    if missing.is_empty() {
        String::new()
    } else {
        format!("; required sources absent: [{}]", missing.join(", "))
    }
}

fn object_ref(object: &Object) -> String {
    format!("object:{}#{}", object.object_token, object.generation)
}

fn eval_fact_rule(
    policy: &Policy,
    input: &EvalInput,
    facts: &[&Fact],
    missing: &[String],
    rule: &Rule,
) -> (PolicyResult, Vec<String>) {
    let mut selector_details = Vec::new();
    for (field, value) in &rule.selector {
        if is_deferred(field) {
            selector_details.push(format!("deferred selector field '{field}'"));
            continue;
        }
        match vocab(field) {
            Some(list) if list.contains(&value.as_str()) => {}
            _ => selector_details.push(format!("unknown selector value '{value}' for '{field}'")),
        }
        if field == "source_id"
            && KNOWN_SOURCES.contains(&value.as_str())
            && !policy.required_sources.contains(value)
            && !input.available_sources.contains(value)
        {
            selector_details.push(format!("unresolved source '{value}'"));
        }
    }
    if !selector_details.is_empty() {
        if !missing.is_empty() {
            let result = PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: "unavailable".to_string(),
                evidence_ids: Vec::new(),
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason: unavailable_reason(&rule.rule_id, missing),
            };
            return (result, Vec::new());
        }
        let result = PolicyResult {
            rule_id: rule.rule_id.clone(),
            scope_id: policy.subject_scope.clone(),
            result: "inconclusive".to_string(),
            evidence_ids: Vec::new(),
            missing_sources: missing.to_vec(),
            exceptions_applied: Vec::new(),
            clock_domain: policy.clock.clone(),
            reason: inconclusive_reason(&rule.rule_id, selector_details),
        };
        return (result, Vec::new());
    }
    let mut matched: Vec<&&Fact> = Vec::new();
    let mut unknown: Vec<(String, String)> = Vec::new();
    for fact in facts {
        if !input.available_sources.contains(&fact.source_id) {
            unknown.push((
                fact.evidence_id.clone(),
                "evidence from unavailable source".to_string(),
            ));
            continue;
        }
        // A record carrying any unresolvable frozen-vocabulary
        // value can neither match nor violate; it poisons only
        // the completeness claim, never the allowlist.
        let held = [
            ("source_id", Some(fact.source_id.as_str())),
            ("capability", fact.capability.as_deref()),
            ("semantics", Some(fact.semantics.as_str())),
            ("peer_class", Some(fact.peer_class.as_str())),
            ("clock_domain", Some(fact.clock_domain.as_str())),
        ];
        let mut strange: Option<(&str, &str)> = None;
        for (field, value) in held {
            if let Some(have) = value
                && let Some(list) = vocab(field)
                && !list.contains(&have)
            {
                strange = Some((field, have));
                break;
            }
        }
        if let Some((field, have)) = strange {
            unknown.push((
                fact.evidence_id.clone(),
                format!("unknown {field} '{have}'"),
            ));
            continue;
        }
        let mut hit = true;
        for (field, value) in &rule.selector {
            match fact_field(fact, field) {
                None => {
                    unknown.push((fact.evidence_id.clone(), format!("missing {field}")));
                    hit = false;
                    break;
                }
                Some(have) if have != value.as_str() => {
                    hit = false;
                    break;
                }
                Some(_) => {}
            }
        }
        if hit {
            matched.push(fact);
        }
    }
    let mut covered: Vec<&&Fact> = Vec::new();
    let mut applied: Vec<String> = Vec::new();
    for fact in &matched {
        for exc in &policy.exceptions {
            if exc.rule_id != rule.rule_id {
                continue;
            }
            match fact_field(fact, &exc.field) {
                Some(have) if exc.values.iter().any(|v| v == have) => {
                    covered.push(fact);
                    applied.push(format!("{}:{}", exc.rule_id, exc.exception_id));
                    break;
                }
                _ => {}
            }
        }
    }
    let covered_ids: Vec<String> = covered
        .iter()
        .map(|fact| fact.evidence_id.clone())
        .collect();
    let unexpected: Vec<String> = matched
        .iter()
        .map(|fact| fact.evidence_id.clone())
        .filter(|id| !covered_ids.contains(id))
        .collect();
    let outcome = if unexpected.len() as u64 > rule.limit_max {
        "violates"
    } else if !missing.is_empty() {
        "unavailable"
    } else if !unknown.is_empty() {
        "inconclusive"
    } else if !applied.is_empty() {
        "deviates_known"
    } else if !input.finalized {
        "inconclusive"
    } else {
        "conforms"
    };
    let matched_ids: Vec<String> = matched
        .iter()
        .map(|fact| fact.evidence_id.clone())
        .collect();
    let result = match outcome {
        "violates" => {
            let (ids, rest) = cap_list(unexpected, MAX_EVIDENCE_IDS);
            let mut reason = format!(
                "rule '{}': {} unexpected operations exceed max {} (evidence [{}]); next: compare the listed evidence against the authored allowlist",
                rule.rule_id,
                ids.len() + rest,
                rule.limit_max,
                render_list(&ids, rest)
            );
            if !unknown.is_empty() {
                let evs: Vec<String> = unknown.iter().map(|(id, _)| id.clone()).collect();
                let (capped, more) = cap_list(evs, MAX_EVIDENCE_IDS);
                reason.push_str(&format!(
                    "; {} records need resolution (unknown: [{}])",
                    capped.len() + more,
                    render_list(&capped, more)
                ));
            }
            reason.push_str(&missing_suffix(missing));
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: outcome.to_string(),
                evidence_ids: ids,
                missing_sources: missing.to_vec(),
                exceptions_applied: cap_list(applied, MAX_EVIDENCE_IDS).0,
                clock_domain: policy.clock.clone(),
                reason,
            }
        }
        "unavailable" => PolicyResult {
            rule_id: rule.rule_id.clone(),
            scope_id: policy.subject_scope.clone(),
            result: outcome.to_string(),
            evidence_ids: Vec::new(),
            missing_sources: missing.to_vec(),
            exceptions_applied: Vec::new(),
            clock_domain: policy.clock.clone(),
            reason: unavailable_reason(&rule.rule_id, missing),
        },
        "inconclusive" => {
            let mut details: Vec<String> = Vec::new();
            if !input.finalized {
                details.push("capture unfinalized; absence unproved".to_string());
            }
            let mut groups: Vec<(String, Vec<String>)> = Vec::new();
            for (id, note) in &unknown {
                match groups.iter_mut().find(|(key, _)| key == note) {
                    Some((_, ids)) => ids.push(id.clone()),
                    None => groups.push((note.clone(), vec![id.clone()])),
                }
            }
            for (note, ids) in groups {
                let (capped, rest) = cap_list(ids, MAX_EVIDENCE_IDS);
                details.push(format!(
                    "{note} (evidence [{}])",
                    render_list(&capped, rest)
                ));
            }
            let evs: Vec<String> = unknown.iter().map(|(id, _)| id.clone()).collect();
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: outcome.to_string(),
                evidence_ids: cap_list(evs, MAX_EVIDENCE_IDS).0,
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason: inconclusive_reason(&rule.rule_id, details),
            }
        }
        "deviates_known" => {
            let (ids, rest) = cap_list(covered_ids, MAX_EVIDENCE_IDS);
            let (names, _) = cap_list(applied, MAX_EVIDENCE_IDS);
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: outcome.to_string(),
                evidence_ids: ids.clone(),
                missing_sources: missing.to_vec(),
                exceptions_applied: names.clone(),
                clock_domain: policy.clock.clone(),
                reason: format!(
                    "rule '{}': {} covered operations under exceptions [{}]; next: confirm the exceptions still reflect the authored allowlist",
                    rule.rule_id,
                    ids.len() + rest,
                    names.join(", ")
                ),
            }
        }
        _ => PolicyResult {
            rule_id: rule.rule_id.clone(),
            scope_id: policy.subject_scope.clone(),
            result: "conforms".to_string(),
            evidence_ids: Vec::new(),
            missing_sources: missing.to_vec(),
            exceptions_applied: Vec::new(),
            clock_domain: policy.clock.clone(),
            reason: format!(
                "rule '{}': {} of {} records matched, none unexpected; next: re-evaluate on the next capture",
                rule.rule_id,
                matched_ids.len(),
                facts.len()
            ),
        },
    };
    (result, matched_ids)
}

fn eval_obligation_rule(
    policy: &Policy,
    input: &EvalInput,
    objects: &[&Object],
    missing: &[String],
    rule: &Rule,
) -> (PolicyResult, Vec<String>) {
    let obligation = rule.obligation.as_ref().expect("obligation rule");
    let mut selector_details = Vec::new();
    for (field, value) in &rule.selector {
        if field == "object_class" && !KNOWN_OBJECT_CLASSES.contains(&value.as_str()) {
            selector_details.push(format!("unknown selector value '{value}' for '{field}'"));
        }
        if field == "source_id" {
            if !KNOWN_SOURCES.contains(&value.as_str()) {
                selector_details.push(format!("unknown selector value '{value}' for '{field}'"));
            } else if !policy.required_sources.contains(value)
                && !input.available_sources.contains(value)
            {
                selector_details.push(format!("unresolved source '{value}'"));
            }
        }
    }
    if !selector_details.is_empty() {
        if !missing.is_empty() {
            let result = PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: "unavailable".to_string(),
                evidence_ids: Vec::new(),
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason: unavailable_reason(&rule.rule_id, missing),
            };
            return (result, Vec::new());
        }
        let result = PolicyResult {
            rule_id: rule.rule_id.clone(),
            scope_id: policy.subject_scope.clone(),
            result: "inconclusive".to_string(),
            evidence_ids: Vec::new(),
            missing_sources: missing.to_vec(),
            exceptions_applied: Vec::new(),
            clock_domain: policy.clock.clone(),
            reason: inconclusive_reason(&rule.rule_id, selector_details),
        };
        return (result, Vec::new());
    }
    let class_want = rule
        .selector
        .iter()
        .find(|(field, _)| field == "object_class")
        .map(|(_, value)| value.as_str());
    let source_want = rule
        .selector
        .iter()
        .find(|(field, _)| field == "source_id")
        .map(|(_, value)| value.as_str());
    let mut nonconforming: Vec<String> = Vec::new();
    let mut details: Vec<String> = Vec::new();
    let mut selected = 0usize;
    for object in objects {
        if !KNOWN_SOURCES.contains(&object.origin_source.as_str()) {
            details.push(format!(
                "unknown origin_source '{}' ({})",
                object.origin_source,
                object_ref(object)
            ));
            continue;
        }
        if !input.available_sources.contains(&object.origin_source) {
            details.push(format!(
                "object from unavailable source ({})",
                object_ref(object)
            ));
            continue;
        }
        if let Some(want) = class_want
            && object.object_class != want
        {
            if !KNOWN_OBJECT_CLASSES.contains(&object.object_class.as_str()) {
                details.push(format!(
                    "unknown object_class '{}' ({})",
                    object.object_class,
                    object_ref(object)
                ));
            }
            continue;
        }
        if let Some(want) = source_want
            && object.origin_source != want
        {
            continue;
        }
        if !KNOWN_OBJECT_CLASSES.contains(&object.object_class.as_str()) {
            details.push(format!(
                "unknown object_class '{}' ({})",
                object.object_class,
                object_ref(object)
            ));
            continue;
        }
        selected += 1;
        let reference = object_ref(object);
        if !KNOWN_LIFECYCLE_STATUSES.contains(&object.lifecycle_status.as_str())
            || object.lifecycle_status == "unknown"
        {
            details.push(format!(
                "unknown lifecycle_status '{}' ({reference})",
                object.lifecycle_status
            ));
            continue;
        }
        if object.lifecycle_status != obligation.status {
            nonconforming.push(reference.clone());
        }
        if let Some(within) = obligation.within {
            let clock = obligation.clock.as_deref().unwrap_or("");
            match (&object.elapsed, &object.elapsed_clock) {
                (Some(elapsed), Some(have)) if have == clock => {
                    if *elapsed > within && !nonconforming.contains(&reference) {
                        nonconforming.push(reference.clone());
                    }
                }
                (Some(_), Some(have)) => {
                    details.push(format!(
                        "clock '{have}' lacks the declared '{clock}' ({reference})"
                    ));
                }
                _ => {
                    details.push(format!("missing elapsed duration ({reference})"));
                }
            }
        }
    }
    let outcome = if nonconforming.len() as u64 > rule.limit_max {
        "violates"
    } else if !missing.is_empty() {
        "unavailable"
    } else if !input.finalized || !details.is_empty() {
        "inconclusive"
    } else {
        "conforms"
    };
    let result = match outcome {
        "violates" => {
            let (ids, rest) = cap_list(nonconforming, MAX_EVIDENCE_IDS);
            let mut reason = format!(
                "rule '{}': {} objects miss '{}' (evidence [{}]); next: compare the listed evidence against the authored allowlist",
                rule.rule_id,
                ids.len() + rest,
                obligation.status,
                render_list(&ids, rest)
            );
            if !details.is_empty() {
                reason.push_str(&format!(
                    "; {} records need resolution (unknown)",
                    details.len()
                ));
            }
            reason.push_str(&missing_suffix(missing));
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: outcome.to_string(),
                evidence_ids: ids,
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason,
            }
        }
        "unavailable" => PolicyResult {
            rule_id: rule.rule_id.clone(),
            scope_id: policy.subject_scope.clone(),
            result: outcome.to_string(),
            evidence_ids: Vec::new(),
            missing_sources: missing.to_vec(),
            exceptions_applied: Vec::new(),
            clock_domain: policy.clock.clone(),
            reason: unavailable_reason(&rule.rule_id, missing),
        },
        "inconclusive" => {
            if !input.finalized {
                details.push("capture unfinalized; teardown unproved".to_string());
            }
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: outcome.to_string(),
                evidence_ids: Vec::new(),
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason: inconclusive_reason(&rule.rule_id, details),
            }
        }
        _ => {
            let span = match (obligation.within, &obligation.clock) {
                (Some(within), Some(clock)) => format!(" within {within} {clock}"),
                _ => String::new(),
            };
            PolicyResult {
                rule_id: rule.rule_id.clone(),
                scope_id: policy.subject_scope.clone(),
                result: "conforms".to_string(),
                evidence_ids: Vec::new(),
                missing_sources: missing.to_vec(),
                exceptions_applied: Vec::new(),
                clock_domain: policy.clock.clone(),
                reason: format!(
                    "rule '{}': {selected} objects reach '{}'{span}; next: re-evaluate on the next capture",
                    rule.rule_id, obligation.status
                ),
            }
        }
    };
    (result, Vec::new())
}
