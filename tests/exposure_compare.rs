// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure comparison: per-metric compatibility plus exact deltas.
//!
//! The comparator stays standalone (no shared module wiring)
//! so this suite includes it directly. Each test mirrors one
//! golden fixture under tests/exposure/fixtures/compare/ and
//! names its case id; the Python golden suite checks that
//! coupling so the two sides cannot drift apart.

#[path = "../src/analysis/exposure_compare.rs"]
mod exposure_compare;

use exposure_compare::{Capture, Comparison, Metric, Quality, compare_captures};

fn metric(
    id: &str,
    value: Option<u64>,
    reason: Option<&str>,
    unit: &str,
    scope: &str,
    source: &str,
    census_derived: bool,
) -> Metric {
    Metric {
        metric_id: id.to_string(),
        value,
        value_reason: reason.map(str::to_string),
        unit: unit.to_string(),
        scope: scope.to_string(),
        source_id: source.to_string(),
        census_derived,
    }
}

#[allow(clippy::too_many_arguments)]
fn capture(
    evidence: &str,
    workload: &str,
    epoch: u64,
    cell: &str,
    meanings: Vec<(&str, &str)>,
    start: u64,
    end: u64,
    clock: &str,
    bounded: bool,
    legacy: bool,
    metrics: Vec<Metric>,
) -> Capture {
    Capture {
        evidence_id: evidence.to_string(),
        profile_id: "linux-x86_64-7.0-reference".to_string(),
        workload: workload.to_string(),
        epoch,
        platform_cell: cell.to_string(),
        source_meanings: meanings
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect(),
        window_start: start,
        window_end: end,
        clock_domain: clock.to_string(),
        census_bounded: bounded,
        legacy,
        metrics,
    }
}

fn standard_meanings() -> Vec<(&'static str, &'static str)> {
    vec![
        ("census-direct-map", "meaning-1"),
        ("queue-ledger", "meaning-1"),
    ]
}

fn channel(value: &str) -> String {
    value.to_string()
}

fn compatible_row(
    metric: &str,
    left: &str,
    right: &str,
    delta: Option<i64>,
    delta_reason: Option<&str>,
    unit: &str,
    scope: &str,
) -> Comparison {
    // Only an exact delta claims complete quality; a null
    // delta reports unknown on every channel.
    let level = if delta.is_some() {
        "complete"
    } else {
        "unknown"
    };
    Comparison {
        metric_id: metric.to_string(),
        compatibility: "compatible".to_string(),
        reason: "compatible".to_string(),
        left_evidence: left.to_string(),
        right_evidence: right.to_string(),
        delta,
        delta_reason: delta_reason.map(str::to_string),
        unit: unit.to_string(),
        scope: scope.to_string(),
        quality: Quality {
            detail: channel(level),
            aggregate: channel(level),
            identity: channel(level),
            baseline: channel(level),
            terminal: channel(level),
        },
    }
}

fn refused_row(
    metric: &str,
    compatibility: &str,
    reason: &str,
    left: &str,
    right: &str,
    unit: &str,
    scope: &str,
) -> Comparison {
    // Refused rows never claim complete quality. A missing
    // metric additionally reports unknown identity.
    let identity = if compatibility == "unavailable" {
        "unknown"
    } else {
        "refused"
    };
    Comparison {
        metric_id: metric.to_string(),
        compatibility: compatibility.to_string(),
        reason: reason.to_string(),
        left_evidence: left.to_string(),
        right_evidence: right.to_string(),
        delta: None,
        delta_reason: None,
        unit: unit.to_string(),
        scope: scope.to_string(),
        quality: Quality {
            detail: channel("refused"),
            aggregate: channel("refused"),
            identity: channel(identity),
            baseline: channel("refused"),
            terminal: channel("refused"),
        },
    }
}

// case: equal-profile-different-workload
#[test]
fn workload_change_refuses_all_metrics() {
    let left = capture(
        "cap-left-001",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-001".to_string();
    right.workload = "io-batch".to_string();
    right.metrics[0].value = Some(12288);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "workload-mismatch",
                "cap-left-001",
                "cap-right-001",
                "bytes",
                "guest-direct-map",
            ),
            refused_row(
                "queue-count",
                "incompatible",
                "workload-mismatch",
                "cap-left-001",
                "cap-right-001",
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: different-epoch
#[test]
fn epoch_reset_refuses_all_metrics() {
    let left = capture(
        "cap-left-002",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(8192),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-002".to_string();
    right.epoch = 42;
    right.metrics[0].value = Some(8192);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![refused_row(
            "shared-bytes",
            "incompatible",
            "epoch-mismatch",
            "cap-left-002",
            "cap-right-002",
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: device-binding
#[test]
fn device_binding_change_refuses_all_metrics() {
    let left = capture(
        "cap-left-003",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(8192),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-003".to_string();
    right.platform_cell = "tdx-guest-02".to_string();
    right.metrics[0].value = Some(8192);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![refused_row(
            "shared-bytes",
            "incompatible",
            "device-binding-mismatch",
            "cap-left-003",
            "cap-right-003",
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: source-meaning-change
#[test]
fn meaning_change_refuses_only_its_source() {
    let left = capture(
        "cap-left-004",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-004".to_string();
    right
        .source_meanings
        .insert("census-direct-map".to_string(), "meaning-2".to_string());
    right.metrics[0].value = Some(8192);
    right.metrics[1].value = Some(6);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "source-meaning-change",
                "cap-left-004",
                "cap-right-004",
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "queue-count",
                "cap-left-004",
                "cap-right-004",
                Some(2),
                None,
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: unequal-window
#[test]
fn unequal_window_refuses_all_metrics() {
    let left = capture(
        "cap-left-005",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(8192),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-005".to_string();
    right.window_end = 3000;
    right.metrics[0].value = Some(12288);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![refused_row(
            "shared-bytes",
            "incompatible",
            "window-mismatch",
            "cap-left-005",
            "cap-right-005",
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: clock-mismatch
#[test]
fn clock_change_refuses_all_metrics() {
    let left = capture(
        "cap-left-006",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(8192),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-006".to_string();
    right.clock_domain = "guest_boottime_elapsed".to_string();
    right.metrics[0].value = Some(8192);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![refused_row(
            "shared-bytes",
            "incompatible",
            "clock-mismatch",
            "cap-left-006",
            "cap-right-006",
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: partial-census
#[test]
fn partial_census_keeps_unaffected_metrics() {
    let left = capture(
        "cap-left-007",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-007".to_string();
    right.census_bounded = true;
    right.metrics[0].census_derived = true;
    right.metrics[0].value = Some(12288);
    right.metrics[1].value = Some(5);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "partial-census",
                "cap-left-007",
                "cap-right-007",
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "queue-count",
                "cap-left-007",
                "cap-right-007",
                Some(1),
                None,
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: legacy-input
#[test]
fn legacy_side_refuses_all_metrics() {
    let left = capture(
        "cap-left-008",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        true,
        vec![metric(
            "shared-bytes",
            Some(8192),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-008".to_string();
    right.legacy = false;
    right.metrics[0].value = Some(8192);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![refused_row(
            "shared-bytes",
            "incompatible",
            "legacy-input",
            "cap-left-008",
            "cap-right-008",
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: compatible-golden
#[test]
fn equal_captures_yield_exact_deltas() {
    let left = capture(
        "cap-left-009",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(18446744073709551000),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "queue-count",
                Some(7),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
            metric(
                "heap-retained",
                None,
                Some("source-unavailable"),
                "bytes",
                "guest-kernel-allocator",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-009".to_string();
    right.metrics[0].value = Some(18446744073709551100);
    right.metrics[1].value = Some(5);
    right.metrics[2].value_reason = Some("source-unavailable".to_string());
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            compatible_row(
                "shared-bytes",
                "cap-left-009",
                "cap-right-009",
                Some(100),
                None,
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "queue-count",
                "cap-left-009",
                "cap-right-009",
                Some(-2),
                None,
                "bytes",
                "guest-driver-virtio",
            ),
            compatible_row(
                "heap-retained",
                "cap-left-009",
                "cap-right-009",
                None,
                Some("value-unknown"),
                "bytes",
                "guest-kernel-allocator",
            ),
        ]
    );
}

// case: metric-shape
#[test]
fn missing_unit_and_scope_shapes_refuse() {
    let left = capture(
        "cap-left-010",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "left-only",
                Some(3),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "unit-split",
                Some(9),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "scope-split",
                Some(9),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-010".to_string();
    right.metrics.retain(|m| m.metric_id != "left-only");
    right.metrics.push(metric(
        "right-only",
        Some(3),
        None,
        "bytes",
        "guest-direct-map",
        "census-direct-map",
        true,
    ));
    for m in right.metrics.iter_mut() {
        if m.metric_id == "unit-split" {
            m.unit = "unknown".to_string();
        }
        if m.metric_id == "scope-split" {
            m.scope = "guest-driver-virtio".to_string();
        }
    }
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "left-only",
                "unavailable",
                "metric-missing",
                "cap-left-010",
                "cap-right-010",
                "bytes",
                "guest-direct-map",
            ),
            refused_row(
                "unit-split",
                "incompatible",
                "unit-mismatch",
                "cap-left-010",
                "cap-right-010",
                "bytes",
                "guest-direct-map",
            ),
            refused_row(
                "scope-split",
                "incompatible",
                "scope-mismatch",
                "cap-left-010",
                "cap-right-010",
                "bytes",
                "guest-direct-map",
            ),
            refused_row(
                "right-only",
                "unavailable",
                "metric-missing",
                "cap-left-010",
                "cap-right-010",
                "bytes",
                "guest-direct-map",
            ),
        ]
    );
}

#[test]
fn overflowing_delta_stays_compatible_without_value() {
    let left = capture(
        "cap-left-011",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(0),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-011".to_string();
    right.metrics[0].value = Some(u64::MAX);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![compatible_row(
            "shared-bytes",
            "cap-left-011",
            "cap-right-011",
            None,
            Some("delta-overflow"),
            "bytes",
            "guest-direct-map",
        )]
    );
}

// case: profile-mismatch
#[test]
fn profile_change_refuses_all_metrics() {
    let left = capture(
        "cap-left-013",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-013".to_string();
    right.profile_id = "linux-x86_64-7.0-hardened".to_string();
    right.metrics[0].value = Some(12288);
    right.metrics[1].value = Some(5);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "profile-mismatch",
                "cap-left-013",
                "cap-right-013",
                "bytes",
                "guest-direct-map",
            ),
            refused_row(
                "queue-count",
                "incompatible",
                "profile-mismatch",
                "cap-left-013",
                "cap-right-013",
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: source-mismatch
#[test]
fn source_divergence_refuses_only_its_metric() {
    let left = capture(
        "cap-left-014",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                true,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-014".to_string();
    right.metrics[0].source_id = "queue-ledger".to_string();
    right.metrics[1].value = Some(6);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "source-mismatch",
                "cap-left-014",
                "cap-right-014",
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "queue-count",
                "cap-left-014",
                "cap-right-014",
                Some(2),
                None,
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: source-meaning-unknown
#[test]
fn unknown_meaning_on_both_sides_refuses() {
    let left = capture(
        "cap-left-015",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(8192),
                None,
                "bytes",
                "guest-direct-map",
                "unmapped-source",
                true,
            ),
            metric(
                "queue-count",
                Some(4),
                None,
                "bytes",
                "guest-driver-virtio",
                "queue-ledger",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-015".to_string();
    right.metrics[1].value = Some(6);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            refused_row(
                "shared-bytes",
                "incompatible",
                "source-meaning-unknown",
                "cap-left-015",
                "cap-right-015",
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "queue-count",
                "cap-left-015",
                "cap-right-015",
                Some(2),
                None,
                "bytes",
                "guest-driver-virtio",
            ),
        ]
    );
}

// case: duplicate-metric
#[test]
fn repeated_metric_id_refuses_input() {
    let left = capture(
        "cap-left-017",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(1),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
            metric(
                "shared-bytes",
                Some(1000),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
        ],
    );
    let right = capture(
        "cap-right-017",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(9),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let refusal = compare_captures(&left, &right).unwrap_err();
    assert_eq!(refusal.reason, "duplicate-metric");
}

// case: invalid-window
#[test]
fn backward_window_refuses_input() {
    let left = capture(
        "cap-left-018",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        3000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(1),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let right = capture(
        "cap-right-018",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(9),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let refusal = compare_captures(&left, &right).unwrap_err();
    assert_eq!(refusal.reason, "invalid-window");
}

// case: invalid-value
#[test]
fn unknown_value_without_reason_refuses_input() {
    let left = capture(
        "cap-left-019",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            None,
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let right = capture(
        "cap-right-019",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(9),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let refusal = compare_captures(&left, &right).unwrap_err();
    assert_eq!(refusal.reason, "invalid-value");
}

#[test]
fn known_value_with_reason_refuses_input() {
    let left = capture(
        "cap-left-020",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(1),
            Some("source-unavailable"),
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-020".to_string();
    right.metrics[0].value_reason = None;
    right.metrics[0].value = Some(9);
    let refusal = compare_captures(&left, &right).unwrap_err();
    assert_eq!(refusal.reason, "invalid-value");
}

#[test]
fn input_validation_order_is_documented() {
    // A repeated id beats a backward window on the same
    // capture, and the left capture validates first.
    let both_bad = capture(
        "cap-left-021",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        3000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(1),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
            metric(
                "shared-bytes",
                Some(2),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
        ],
    );
    let clean = capture(
        "cap-right-021",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(9),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let refusal = compare_captures(&both_bad, &clean).unwrap_err();
    assert_eq!(refusal.reason, "duplicate-metric");
    // The left capture validates first even when the right
    // side fails an earlier within-capture check.
    let left_value_bad = capture(
        "cap-left-022",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            None,
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let right_dup = capture(
        "cap-right-022",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "shared-bytes",
                Some(9),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
            metric(
                "shared-bytes",
                Some(10),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
        ],
    );
    let refusal = compare_captures(&left_value_bad, &right_dup).unwrap_err();
    assert_eq!(refusal.reason, "invalid-value");
}

// case: delta-overflow
#[test]
fn overflow_in_both_directions_stays_compatible_without_value() {
    let left = capture(
        "cap-left-023",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![
            metric(
                "counter-up",
                Some(0),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
            metric(
                "counter-down",
                Some(u64::MAX),
                None,
                "bytes",
                "guest-direct-map",
                "census-direct-map",
                false,
            ),
        ],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-023".to_string();
    right.metrics[0].value = Some(u64::MAX);
    right.metrics[1].value = Some(0);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(
        rows,
        vec![
            compatible_row(
                "counter-up",
                "cap-left-023",
                "cap-right-023",
                None,
                Some("delta-overflow"),
                "bytes",
                "guest-direct-map",
            ),
            compatible_row(
                "counter-down",
                "cap-left-023",
                "cap-right-023",
                None,
                Some("delta-overflow"),
                "bytes",
                "guest-direct-map",
            ),
        ]
    );
}

#[test]
fn predicate_order_is_deterministic() {
    // Epoch and workload both differ: the earlier epoch
    // check names the reason.
    let left = capture(
        "cap-left-012",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(1),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            true,
        )],
    );
    let mut right = left.clone();
    right.evidence_id = "cap-right-012".to_string();
    right.epoch = 42;
    right.workload = "io-batch".to_string();
    right.metrics[0].value = Some(2);
    let rows = compare_captures(&left, &right).expect("valid comparison inputs");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].compatibility, "incompatible");
    assert_eq!(rows[0].reason, "epoch-mismatch");
    assert_eq!(rows[0].delta, None);
}

#[test]
fn predicate_order_holds_across_new_checks() {
    // Each pair fails two checks; the earlier check in the
    // documented order names the reason.
    let left = capture(
        "cap-left-024",
        "idle-snapshot",
        41,
        "snp-guest-01",
        standard_meanings(),
        1000,
        2000,
        "guest_monotonic_active",
        false,
        false,
        vec![metric(
            "shared-bytes",
            Some(1),
            None,
            "bytes",
            "guest-direct-map",
            "census-direct-map",
            false,
        )],
    );
    let reason_of = |right: &Capture| {
        let rows = compare_captures(&left, right).expect("valid comparison inputs");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].compatibility, "incompatible");
        assert_eq!(rows[0].delta, None);
        rows[0].reason.clone()
    };
    // Profile beats workload.
    let mut right = left.clone();
    right.profile_id = "linux-x86_64-7.0-hardened".to_string();
    right.workload = "io-batch".to_string();
    assert_eq!(reason_of(&right), "profile-mismatch");
    // Per-side source beats a meaning change.
    let mut right = left.clone();
    right.metrics[0].source_id = "queue-ledger".to_string();
    right
        .source_meanings
        .insert("census-direct-map".to_string(), "meaning-2".to_string());
    assert_eq!(reason_of(&right), "source-mismatch");
    // Device binding beats profile.
    let mut right = left.clone();
    right.platform_cell = "tdx-guest-02".to_string();
    right.profile_id = "linux-x86_64-7.0-hardened".to_string();
    assert_eq!(reason_of(&right), "device-binding-mismatch");
    // Clock beats window.
    let mut right = left.clone();
    right.clock_domain = "guest_boottime_elapsed".to_string();
    right.window_end = 3000;
    assert_eq!(reason_of(&right), "clock-mismatch");
    // Window beats census.
    let mut right = left.clone();
    right.window_end = 3000;
    right.census_bounded = true;
    right.metrics[0].census_derived = true;
    assert_eq!(reason_of(&right), "window-mismatch");
}
