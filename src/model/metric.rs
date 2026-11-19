// SPDX-License-Identifier: GPL-3.0-or-later
//! Report metric and finding rows.
//!
//! Values stay numeric until rendering; the renderers format them
//! with canonical decimals so the JSON output carries exact quoted
//! strings.

/// One derived metric row.
///
/// Confidence is the evidence class behind the metric's
/// interpretation, independent of loss and coverage:
///
/// - high: directly observed quantity, no platform
///   interpretation (attempt counts, allocation bytes,
///   pool gauges, completed lifetimes).
/// - medium: observation interpreted through an admitted
///   profile (shared/private/unknown region state).
/// - proxy: an ordinary-guest number standing in for a
///   confidential-exposure question. No current metric
///   emits proxy: exposure-framed claims stay withheld
///   until platform sharing proof exists. Proxy never
///   downgrades an accurate allocator measurement and
///   never implies a calibrated probability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metric {
    /// Metric name.
    pub name: String,
    /// True when a value was computed.
    pub has_value: bool,
    /// Numeric value; zero unless `has_value`.
    pub value: u64,
    /// Value unit label.
    pub unit: String,
    /// Measurement class label.
    pub measurement: String,
    /// Coverage class label.
    pub coverage: String,
    /// Evidence class: high, medium, or proxy.
    pub confidence: String,
    /// True when an aggregation label was reported.
    pub has_aggregation: bool,
    /// Aggregation label; empty unless `has_aggregation`.
    pub aggregation: String,
    /// True when a sample count was reported.
    pub has_sample_count: bool,
    /// Sample count; zero unless `has_sample_count`.
    pub sample_count: u64,
    /// True when a device scope was reported.
    pub has_device_id: bool,
    /// Device scope; empty unless `has_device_id`.
    pub device_id: String,
    /// True when a pool scope was reported.
    pub has_pool_id: bool,
    /// Pool scope; empty unless `has_pool_id`.
    pub pool_id: String,
    /// Scope label.
    pub scope: String,
    /// Free-form notes.
    pub notes: String,
}

impl Default for Metric {
    fn default() -> Self {
        Self {
            name: String::new(),
            has_value: false,
            value: 0,
            unit: String::new(),
            measurement: "unavailable".to_string(),
            coverage: "unavailable".to_string(),
            confidence: String::new(),
            has_aggregation: false,
            aggregation: String::new(),
            has_sample_count: false,
            sample_count: 0,
            has_device_id: false,
            device_id: String::new(),
            has_pool_id: false,
            pool_id: String::new(),
            scope: String::new(),
            notes: String::new(),
        }
    }
}

/// One evidence-linked observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Finding code.
    pub code: String,
    /// Severity label.
    pub severity: String,
    /// Human explanation.
    pub explanation: String,
    /// Evidence reference labels.
    pub evidence_refs: Vec<String>,
    /// Scope label.
    pub scope: String,
    /// Known limitations.
    pub limitations: String,
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            code: String::new(),
            severity: "informational".to_string(),
            explanation: String::new(),
            evidence_refs: Vec::new(),
            scope: String::new(),
            limitations: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_defaults_are_unavailable_without_value() {
        let m = Metric::default();
        assert_eq!(m.name, "");
        assert!(!m.has_value);
        assert_eq!(m.value, 0);
        assert_eq!(m.unit, "");
        assert_eq!(m.measurement, "unavailable");
        assert_eq!(m.coverage, "unavailable");
        assert_eq!(m.confidence, "");
        assert!(!m.has_aggregation);
        assert!(!m.has_sample_count);
        assert!(!m.has_device_id);
        assert!(!m.has_pool_id);
        assert_eq!(m.scope, "");
        assert_eq!(m.notes, "");
    }

    #[test]
    fn finding_default_is_informational() {
        let f = Finding::default();
        assert_eq!(f.code, "");
        assert_eq!(f.severity, "informational");
        assert_eq!(f.explanation, "");
        assert!(f.evidence_refs.is_empty());
        assert_eq!(f.scope, "");
        assert_eq!(f.limitations, "");
    }
}
