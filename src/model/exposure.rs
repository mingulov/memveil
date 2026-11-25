// SPDX-License-Identifier: GPL-3.0-or-later
//! Sealed exposure record shapes for the 0.3.0 milestone.
//!
//! These are the frozen record types every exposure capability shares:
//! coverage sources, exposure facts, exposure objects, baseline samples,
//! policy results and comparison results. Field lists follow the frozen
//! exposure catalog; closed vocabularies are checked here, while labels
//! whose vocabularies freeze with adapter admission (kinds, directions,
//! caller classes, scopes, object states, counter names, null reasons)
//! keep a bounded shape check only. Semantic admission of those labels
//! happens at freeze time, never by guessing in an adapter.
//!
//! The module is self-contained on purpose: it declares no parent
//! items, so it compiles both under its public module path and
//! through a direct path include in tests. It takes no live input
//! and performs no I/O; parsing and transport stay with the owning
//! reader and writer.

/// Session contract version carrying exposure records.
pub const EXPOSURE_SESSION_VERSION: &str = "0.3.0";
/// Event contract version carrying exposure records.
pub const EXPOSURE_EVENT_VERSION: &str = "0.3.0";
/// Report contract version carrying exposure records.
pub const EXPOSURE_REPORT_VERSION: &str = "0.3.0";
/// Standalone authored-policy contract version.
pub const EXPOSURE_POLICY_VERSION: &str = "0.1.0";
/// Frozen exposure catalog version these shapes follow.
pub const EXPOSURE_CATALOG_VERSION: &str = "0.1.0";

/// True for the session/event/report versions carrying exposure records.
pub fn is_exposure_version(version: &str) -> bool {
    version == EXPOSURE_SESSION_VERSION
}

/// Live objects per inventory scan.
pub const MAX_OBJECTS: u64 = 65_536;
/// Reference edges per inventory scan.
pub const MAX_EDGES: u64 = 262_144;
/// Visited entries per inventory scan.
pub const MAX_VISITED: u64 = 1_048_576;
/// Returned records per inventory scan.
pub const MAX_RETURNED: u64 = 65_536;
/// Policy file size cap in bytes.
pub const POLICY_MAX_BYTES: usize = 1_048_576;
/// Rules per policy file.
pub const POLICY_MAX_RULES: usize = 1024;
/// Exceptions per rule.
pub const POLICY_MAX_EXCEPTIONS_PER_RULE: usize = 64;
/// Policy identifier length cap in ASCII characters.
pub const POLICY_MAX_ID_LEN: usize = 64;
/// Opaque identifier length cap in characters.
pub const MAX_ID_LEN: usize = 128;

/// Detail channel index into [`Quality`].
pub const DETAIL: usize = 0;
/// Aggregate channel index into [`Quality`].
pub const AGGREGATE: usize = 1;
/// Identity channel index into [`Quality`].
pub const IDENTITY: usize = 2;
/// Baseline channel index into [`Quality`].
pub const BASELINE: usize = 3;
/// Terminal channel index into [`Quality`].
pub const TERMINAL: usize = 4;
/// Independent quality channels in canonical order.
pub const CHANNELS: [&str; 5] = ["detail", "aggregate", "identity", "baseline", "terminal"];

/// Frozen fact semantics.
pub const SEMANTICS: [&str; 6] = [
    "request",
    "result",
    "inventory",
    "lifecycle",
    "state",
    "native_rejection",
];
/// Frozen observation phases.
pub const PHASES: [&str; 3] = ["boot", "pre_attach", "observed"];
/// Frozen source statuses.
pub const SOURCE_STATUSES: [&str; 5] = [
    "available",
    "partial",
    "unavailable",
    "not_applicable",
    "disabled",
];
/// Frozen policy results.
pub const POLICY_RESULTS: [&str; 5] = [
    "conforms",
    "deviates_known",
    "violates",
    "inconclusive",
    "unavailable",
];
/// Frozen comparison outcomes.
pub const COMPATIBILITIES: [&str; 3] = ["compatible", "incompatible", "unavailable"];
/// Frozen sample atomicity labels.
pub const ATOMICITIES: [&str; 3] = ["atomic", "interval", "unknown"];
/// Frozen clock domains.
pub const CLOCK_DOMAINS: [&str; 3] = [
    "guest_monotonic_active",
    "guest_boottime_elapsed",
    "external_trusted_interval",
];
/// Frozen address namespaces.
pub const ADDRESS_NAMESPACES: [&str; 6] = [
    "guest_virtual",
    "guest_physical",
    "session_token",
    "interface_register",
    "channel_relid",
    "not_applicable",
];
/// Frozen object classes.
pub const OBJECT_CLASSES: [&str; 5] = ["queue", "buffer", "channel", "mapping", "heap_object"];
/// Frozen lifecycle statuses.
pub const LIFECYCLE_STATUSES: [&str; 5] = ["created", "live", "released", "quarantined", "unknown"];
/// Frozen subject classes.
pub const SUBJECT_CLASSES: [&str; 9] = [
    "guest-kernel-memory-management",
    "guest-direct-map",
    "guest-kernel-allocator",
    "guest-driver-virtio",
    "guest-driver-dma",
    "guest-kernel-cc-platform",
    "guest-kernel-vmbus",
    "guest-configuration",
    "capture-evidence",
];
/// Frozen peer classes.
pub const PEER_CLASSES: [&str; 7] = [
    "none-observed",
    "host-device",
    "device-or-subsystem",
    "device",
    "host-hypervisor",
    "host-tdx-module",
    "host-or-paravisor",
];
/// Frozen units.
pub const UNITS: [&str; 2] = ["bytes", "unknown"];
/// Planned exposure capability identifiers.
pub const EXPOSURE_CAPABILITIES: [&str; 7] = [
    "census",
    "object-lifetimes",
    "dma-paths",
    "shared-buffers",
    "host-interfaces",
    "mapping-inventory",
    "exposure-context",
];
/// Each catalog source with its owning capability.
pub const SOURCE_CAPABILITIES: [(&str, &str); 10] = [
    ("sharing-census", "census"),
    ("object-lineage", "object-lifetimes"),
    ("dma-virtio-paths", "dma-paths"),
    ("heap-dmabuf-objects", "shared-buffers"),
    ("ghcb-exceptions", "host-interfaces"),
    ("tdx-conversions", "host-interfaces"),
    ("tdx-ve-metadata", "host-interfaces"),
    ("vmbus-channels", "host-interfaces"),
    ("mapping-inventory-scan", "mapping-inventory"),
    ("egress-controls", "exposure-context"),
];

/// Owning capability for a catalog source, or `None` when unknown.
pub fn source_capability(source_id: &str) -> Option<&'static str> {
    SOURCE_CAPABILITIES
        .iter()
        .find(|(source, _)| *source == source_id)
        .map(|(_, capability)| *capability)
}

/// Planned exposure source identifiers.
pub const EXPOSURE_SOURCES: [&str; 10] = [
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
/// Exact platform cells.
pub const PLATFORM_CELLS: [&str; 4] = ["ordinary-linux", "sev-snp", "tdx-standalone", "hyper-v"];
/// Source reason codes.
pub const SOURCE_REASONS: [&str; 8] = [
    "adapter-unimplemented",
    "no-safe-source",
    "lease-pending",
    "access-denied",
    "hook-absent",
    "cell-unselected",
    "quarantined",
    "not-applicable-platform",
];
/// Expected-boundary types carried by exposure objects.
pub const BOUNDARY_TYPES: [&str; 2] = ["revert_boundary", "declared_duration"];
/// Record quality statuses.
pub const QUALITY_STATUSES: [&str; 3] = ["complete_for_scope", "partial", "unavailable"];
/// Frozen envelope measurement labels.
pub const MEASUREMENTS: [&str; 3] = ["observed", "derived", "estimated"];
/// Frozen envelope correlation labels.
pub const CORRELATIONS: [&str; 2] = ["direct", "unpaired"];

fn is_one_of(value: &str, table: &[&str]) -> bool {
    table.contains(&value)
}

/// True for a frozen fact semantic.
pub fn is_semantics(value: &str) -> bool {
    is_one_of(value, &SEMANTICS)
}

/// True for a frozen observation phase.
pub fn is_phase(value: &str) -> bool {
    is_one_of(value, &PHASES)
}

/// True for a frozen source status.
pub fn is_source_status(value: &str) -> bool {
    is_one_of(value, &SOURCE_STATUSES)
}

/// True for a frozen policy result.
pub fn is_policy_result(value: &str) -> bool {
    is_one_of(value, &POLICY_RESULTS)
}

/// True for a frozen comparison outcome.
pub fn is_compatibility(value: &str) -> bool {
    is_one_of(value, &COMPATIBILITIES)
}

/// True for a frozen sample atomicity label.
pub fn is_atomicity(value: &str) -> bool {
    is_one_of(value, &ATOMICITIES)
}

/// True for a frozen clock domain.
pub fn is_clock_domain(value: &str) -> bool {
    is_one_of(value, &CLOCK_DOMAINS)
}

/// True for a frozen address namespace.
pub fn is_address_namespace(value: &str) -> bool {
    is_one_of(value, &ADDRESS_NAMESPACES)
}

/// True for a frozen object class.
pub fn is_object_class(value: &str) -> bool {
    is_one_of(value, &OBJECT_CLASSES)
}

/// True for a frozen lifecycle status.
pub fn is_lifecycle_status(value: &str) -> bool {
    is_one_of(value, &LIFECYCLE_STATUSES)
}

/// True for a frozen subject class.
pub fn is_subject_class(value: &str) -> bool {
    is_one_of(value, &SUBJECT_CLASSES)
}

/// True for a frozen peer class.
pub fn is_peer_class(value: &str) -> bool {
    is_one_of(value, &PEER_CLASSES)
}

/// True for a frozen unit.
pub fn is_unit(value: &str) -> bool {
    is_one_of(value, &UNITS)
}

/// True for a planned exposure capability identifier.
pub fn is_exposure_capability(value: &str) -> bool {
    is_one_of(value, &EXPOSURE_CAPABILITIES)
}

/// True for a planned exposure source identifier.
pub fn is_exposure_source(value: &str) -> bool {
    is_one_of(value, &EXPOSURE_SOURCES)
}

/// True for an exact platform cell.
pub fn is_platform_cell(value: &str) -> bool {
    is_one_of(value, &PLATFORM_CELLS)
}

/// True for a source reason code.
pub fn is_source_reason(value: &str) -> bool {
    is_one_of(value, &SOURCE_REASONS)
}

/// True for an expected-boundary type.
pub fn is_boundary_type(value: &str) -> bool {
    is_one_of(value, &BOUNDARY_TYPES)
}

/// True for a record quality status.
pub fn is_quality_status(value: &str) -> bool {
    is_one_of(value, &QUALITY_STATUSES)
}

/// True for a frozen envelope measurement label.
pub fn is_measurement(value: &str) -> bool {
    is_one_of(value, &MEASUREMENTS)
}

/// True for a frozen envelope correlation label.
pub fn is_correlation(value: &str) -> bool {
    is_one_of(value, &CORRELATIONS)
}

/// One record validation failure naming its field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureError {
    /// Field or check that failed.
    pub what: String,
    /// Machine-stable reason.
    pub message: String,
}

impl ExposureError {
    /// Build an error from field name and reason.
    pub fn new(what: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            what: what.into(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ExposureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ExposureError(what={}, message={})",
            self.what, self.message
        )
    }
}

impl std::error::Error for ExposureError {}

fn is_id_start(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_id_rest(byte: u8) -> bool {
    is_id_start(byte) || byte == b'.' || byte == b'-'
}

/// True for a bounded opaque identifier: an alphanumeric or underscore
/// start followed by identifier characters, at most [`MAX_ID_LEN`].
pub fn is_opaque_id(value: &str) -> bool {
    let raw = value.as_bytes();
    if raw.is_empty() || raw.len() > MAX_ID_LEN || !is_id_start(raw[0]) {
        return false;
    }
    raw[1..].iter().all(|byte| is_id_rest(*byte))
}

/// True for a bounded hyphen slug: lowercase alphanumeric segments joined
/// by hyphens, at most [`MAX_ID_LEN`] characters.
pub fn is_slug(value: &str) -> bool {
    let raw = value.as_bytes();
    if raw.is_empty() || raw.len() > MAX_ID_LEN {
        return false;
    }
    if !raw[0].is_ascii_lowercase() && !raw[0].is_ascii_digit() {
        return false;
    }
    raw.iter()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

/// True for bounded human-readable text: no ASCII control characters,
/// length within `1..=limit`.
pub fn is_bounded_text(value: &str, limit: usize) -> bool {
    if value.is_empty() || value.len() > limit {
        return false;
    }
    !value.bytes().any(|byte| byte.is_ascii_control())
}

fn check_id(field: &str, value: &str) -> Result<(), ExposureError> {
    if is_opaque_id(value) {
        Ok(())
    } else {
        Err(ExposureError::new(field, "invalid identifier"))
    }
}

fn check_closed(field: &str, value: &str, table: &[&str]) -> Result<(), ExposureError> {
    if table.contains(&value) {
        Ok(())
    } else {
        Err(ExposureError::new(field, "unknown value"))
    }
}

/// An optional field that may additionally be null with a typed reason.
///
/// Absent and null differ: `present == false` means the field does not
/// apply to this record, while a present null carries a reason naming
/// why the value is unknown. Unknown is never zero or an empty string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Maybe<T> {
    /// True when the key is present on the record.
    pub present: bool,
    /// The value; `None` is a present null.
    pub value: Option<T>,
    /// Typed reason, required exactly for a present null.
    pub reason: String,
}

impl<T> Maybe<T> {
    /// Check the present/null/reason shape; value checks stay with the caller.
    ///
    /// An absent field carries neither a value nor a reason: a reason
    /// always accompanies a present null, never an absent key.
    pub fn validate_shape(&self, field: &str) -> Result<(), ExposureError> {
        if !self.present && self.value.is_some() {
            return Err(ExposureError::new(field, "absent value"));
        }
        let null = self.present && self.value.is_none();
        if null != !self.reason.is_empty() {
            return Err(ExposureError::new(field, "reason shape"));
        }
        if !self.reason.is_empty() {
            check_id(&format!("{field}_reason"), &self.reason)?;
        }
        Ok(())
    }
}

/// One independent quality channel: a status plus an explicit loss count.
///
/// `loss` is `None` when unobservable and `Some(0)` only when measured
/// as zero; the two never collapse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelQuality {
    /// One of [`QUALITY_STATUSES`].
    pub status: String,
    /// Lost records, or `None` when unobservable.
    pub loss: Option<u64>,
}

impl ChannelQuality {
    /// Check the status label; any loss count is structurally valid.
    pub fn validate(&self, field: &str) -> Result<(), ExposureError> {
        check_closed(field, &self.status, &QUALITY_STATUSES)
    }
}

/// Independent detail, aggregate, identity, baseline and terminal quality.
pub type Quality = [ChannelQuality; 5];

/// A settled quality block with every loss measured at zero.
pub fn example_quality() -> Quality {
    [
        ChannelQuality {
            status: "complete_for_scope".to_string(),
            loss: Some(0),
        },
        ChannelQuality {
            status: "complete_for_scope".to_string(),
            loss: Some(0),
        },
        ChannelQuality {
            status: "complete_for_scope".to_string(),
            loss: Some(0),
        },
        ChannelQuality {
            status: "complete_for_scope".to_string(),
            loss: Some(0),
        },
        ChannelQuality {
            status: "complete_for_scope".to_string(),
            loss: Some(0),
        },
    ]
}

/// An unobserved quality block: every channel unavailable, every
/// loss unknown. An unimplemented adapter never claims a measured
/// zero; unknown loss never collapses to one.
pub fn unavailable_quality() -> Quality {
    [
        ChannelQuality {
            status: "unavailable".to_string(),
            loss: None,
        },
        ChannelQuality {
            status: "unavailable".to_string(),
            loss: None,
        },
        ChannelQuality {
            status: "unavailable".to_string(),
            loss: None,
        },
        ChannelQuality {
            status: "unavailable".to_string(),
            loss: None,
        },
        ChannelQuality {
            status: "unavailable".to_string(),
            loss: None,
        },
    ]
}

/// Check all five channels independently.
pub fn validate_quality(quality: &Quality, field: &str) -> Result<(), ExposureError> {
    for (index, channel) in quality.iter().enumerate() {
        channel.validate(&format!("{field}.{}", CHANNELS[index]))?;
    }
    Ok(())
}

/// Coverage claimed by one catalog source over one observed window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoverageSource {
    /// Catalog source entry this record describes.
    pub source_id: String,
    /// Owning capability identifier.
    pub capability: String,
    /// Semantic profile that admitted the source.
    pub profile_id: String,
    /// Frozen subject class.
    pub subject_id: String,
    /// Exact admitted platform cell.
    pub platform_cell: String,
    /// Namespace of every address-like field from this source.
    pub address_namespace: String,
    /// Observation phase.
    pub phase: String,
    /// Source status.
    pub status: String,
    /// Source reason code, required even when available.
    pub reason: String,
    /// Observed window start in nanoseconds.
    pub window_start_ns: u64,
    /// Observed window end in nanoseconds.
    pub window_end_ns: u64,
    /// Independent per-source quality.
    pub quality: Quality,
}

impl CoverageSource {
    /// A valid census source on the ordinary reference cell.
    pub fn example() -> Self {
        Self {
            source_id: "sharing-census".to_string(),
            capability: "census".to_string(),
            profile_id: "synthetic-census-1".to_string(),
            subject_id: "guest-direct-map".to_string(),
            platform_cell: "ordinary-linux".to_string(),
            address_namespace: "guest_physical".to_string(),
            phase: "pre_attach".to_string(),
            status: "unavailable".to_string(),
            reason: "adapter-unimplemented".to_string(),
            window_start_ns: 1_000_000_000,
            window_end_ns: 2_000_000_000,
            quality: unavailable_quality(),
        }
    }

    /// Check every field against the frozen catalog lists.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_closed("source_id", &self.source_id, &EXPOSURE_SOURCES)?;
        check_closed("capability", &self.capability, &EXPOSURE_CAPABILITIES)?;
        if source_capability(&self.source_id) != Some(self.capability.as_str()) {
            return Err(ExposureError::new("capability", "source mismatch"));
        }
        check_id("profile_id", &self.profile_id)?;
        check_closed("subject_id", &self.subject_id, &SUBJECT_CLASSES)?;
        check_closed("platform_cell", &self.platform_cell, &PLATFORM_CELLS)?;
        check_closed(
            "address_namespace",
            &self.address_namespace,
            &ADDRESS_NAMESPACES,
        )?;
        check_closed("phase", &self.phase, &PHASES)?;
        check_closed("status", &self.status, &SOURCE_STATUSES)?;
        check_closed("reason", &self.reason, &SOURCE_REASONS)?;
        if self.window_start_ns > self.window_end_ns {
            return Err(ExposureError::new("window", "start past end"));
        }
        validate_quality(&self.quality, "quality")
    }
}

/// One persisted exposure evidence record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureFact {
    /// Session-unique evidence handle.
    pub evidence_id: String,
    /// Catalog source entry.
    pub source_id: String,
    /// Measurement epoch; resets break comparability.
    pub epoch: u64,
    /// Operation handle; exists before any object token.
    pub operation_id: String,
    /// Parent operation; absent for top-level operations.
    pub parent_operation_id: Maybe<String>,
    /// Deferred kind label; admission freezes with the adapter.
    pub kind: String,
    /// Deferred direction label; CPU-copy direction stays separate.
    pub direction: String,
    /// Object token; never a physical address.
    pub object_token: Maybe<String>,
    /// Token generation; reuse starts a new lineage.
    pub generation: u64,
    /// Byte offset in the source namespace.
    pub offset: u64,
    /// Requested length; effective length stays separate.
    pub length_bytes: u64,
    /// Signed native result, or `None` when unobservable.
    pub native_result: Option<i64>,
    /// Typed reason, required exactly when the result is null.
    pub native_result_reason: String,
    /// Deferred caller class; never a raw address.
    pub caller_class: String,
    /// Frozen peer class.
    pub peer_class: String,
    /// Clock domain of the observed interval.
    pub clock_domain: String,
    /// Observed interval start in the stated clock domain.
    pub observed_start: u64,
    /// Observed interval end in the stated clock domain.
    pub observed_end: u64,
    /// Interval uncertainty in the stated clock domain.
    pub observed_uncertainty: u64,
    /// Record semantics class.
    pub semantics: String,
    /// Per-record quality; loss stays visible.
    pub quality: Quality,
}

impl ExposureFact {
    /// A valid census fact with the given handle, source and epoch.
    pub fn example(evidence_id: &str, source_id: &str, epoch: u64) -> Self {
        Self {
            evidence_id: evidence_id.to_string(),
            source_id: source_id.to_string(),
            epoch,
            operation_id: "op-1".to_string(),
            parent_operation_id: Maybe {
                present: false,
                value: None,
                reason: String::new(),
            },
            kind: "census-entry".to_string(),
            direction: "egress".to_string(),
            object_token: Maybe {
                present: true,
                value: Some("tok-1".to_string()),
                reason: String::new(),
            },
            generation: 1,
            offset: 0,
            length_bytes: 4096,
            native_result: Some(0),
            native_result_reason: String::new(),
            caller_class: "allocator".to_string(),
            peer_class: "none-observed".to_string(),
            clock_domain: "guest_monotonic_active".to_string(),
            observed_start: 1_000_000_000,
            observed_end: 1_000_000_100,
            observed_uncertainty: 50,
            semantics: "inventory".to_string(),
            quality: example_quality(),
        }
    }

    /// Check frozen fields closed and deferred labels bounded.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_id("evidence_id", &self.evidence_id)?;
        check_closed("source_id", &self.source_id, &EXPOSURE_SOURCES)?;
        check_id("operation_id", &self.operation_id)?;
        self.parent_operation_id
            .validate_shape("parent_operation_id")?;
        if let Some(parent) = self.parent_operation_id.value.as_ref() {
            check_id("parent_operation_id", parent)?;
        }
        check_id("kind", &self.kind)?;
        check_id("direction", &self.direction)?;
        self.object_token.validate_shape("object_token")?;
        if let Some(token) = self.object_token.value.as_ref() {
            check_id("object_token", token)?;
        }
        let null_result = self.native_result.is_none();
        if null_result != !self.native_result_reason.is_empty() {
            return Err(ExposureError::new("native_result", "reason shape"));
        }
        if !self.native_result_reason.is_empty() {
            check_id("native_result_reason", &self.native_result_reason)?;
        }
        check_id("caller_class", &self.caller_class)?;
        check_closed("peer_class", &self.peer_class, &PEER_CLASSES)?;
        check_closed("clock_domain", &self.clock_domain, &CLOCK_DOMAINS)?;
        if self.observed_start > self.observed_end {
            return Err(ExposureError::new("observed_interval", "start past end"));
        }
        check_closed("semantics", &self.semantics, &SEMANTICS)?;
        validate_quality(&self.quality, "quality")
    }
}

/// Admitted revert boundary or declared duration for an object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedBoundary {
    /// One of [`BOUNDARY_TYPES`].
    pub boundary_type: String,
    /// Boundary reference label.
    pub reference: String,
}

impl ExpectedBoundary {
    /// Check the boundary type closed and the reference bounded.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_closed(
            "expected_boundary.boundary_type",
            &self.boundary_type,
            &BOUNDARY_TYPES,
        )?;
        check_id("expected_boundary.reference", &self.reference)
    }
}

/// Explicit identity gaps: alias, reuse, loss and missed events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uncertainty {
    /// True when aliasing cannot be ruled out.
    pub alias_unknown: bool,
    /// True when token reuse cannot be ruled out.
    pub reuse_unknown: bool,
    /// True when loss cannot be ruled out.
    pub loss_unknown: bool,
    /// True when events were missed.
    pub events_missed: bool,
}

/// One qualified exposure object lifetime.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureObject {
    /// Session-local token; never a physical address.
    pub object_token: String,
    /// Lineage generation.
    pub generation: u64,
    /// Frozen object class.
    pub object_class: String,
    /// Address namespace of the token.
    pub namespace: String,
    /// Catalog source that first observed the object.
    pub origin_source: String,
    /// Frozen lifecycle status.
    pub lifecycle_status: String,
    /// Deferred object state; unresolved stays explicit.
    pub state: String,
    /// Evidence handles supporting the state claim.
    pub state_evidence: Vec<String>,
    /// Cleanup obligation; absent when none applies, never null.
    pub expected_boundary: Option<ExpectedBoundary>,
    /// Explicit gaps.
    pub uncertainty: Uncertainty,
}

impl ExposureObject {
    /// A valid shared-buffer object with a revert boundary.
    pub fn example() -> Self {
        Self {
            object_token: "tok-1".to_string(),
            generation: 1,
            object_class: "buffer".to_string(),
            namespace: "session_token".to_string(),
            origin_source: "heap-dmabuf-objects".to_string(),
            lifecycle_status: "live".to_string(),
            state: "shared".to_string(),
            state_evidence: vec!["ev-1".to_string()],
            expected_boundary: Some(ExpectedBoundary {
                boundary_type: "revert_boundary".to_string(),
                reference: "release".to_string(),
            }),
            uncertainty: Uncertainty {
                alias_unknown: false,
                reuse_unknown: false,
                loss_unknown: false,
                events_missed: false,
            },
        }
    }

    /// Check frozen fields closed and deferred labels bounded.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_id("object_token", &self.object_token)?;
        check_closed("object_class", &self.object_class, &OBJECT_CLASSES)?;
        check_closed("namespace", &self.namespace, &ADDRESS_NAMESPACES)?;
        check_closed("origin_source", &self.origin_source, &EXPOSURE_SOURCES)?;
        check_closed(
            "lifecycle_status",
            &self.lifecycle_status,
            &LIFECYCLE_STATUSES,
        )?;
        check_id("state", &self.state)?;
        for handle in &self.state_evidence {
            check_id("state_evidence", handle)?;
        }
        if let Some(boundary) = self.expected_boundary.as_ref() {
            boundary.validate()?;
        }
        Ok(())
    }
}

/// One bounded baseline inventory sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineSample {
    /// Session-unique sample handle.
    pub sample_id: String,
    /// Catalog source entry.
    pub source_id: String,
    /// Sample start in the stated clock domain.
    pub start_time: u64,
    /// Sample end; samples are interval-valued.
    pub end_time: u64,
    /// Deferred scan scope.
    pub scope: String,
    /// Observed counts keyed by deferred counter name.
    pub counts: Vec<(String, u64)>,
    /// Frozen units; unknown units disable ratio rules.
    pub units: String,
    /// Entries visited by the scan.
    pub visited: u64,
    /// Records returned; bounded separately from visited.
    pub returned: u64,
    /// True when the scan hit a bound and is explicitly partial.
    pub bounded: bool,
    /// Sample atomicity label.
    pub atomicity: String,
    /// Per-sample quality.
    pub quality: Quality,
}

impl BaselineSample {
    /// A valid census sample with one counter.
    pub fn example() -> Self {
        Self {
            sample_id: "sample-1".to_string(),
            source_id: "sharing-census".to_string(),
            start_time: 1_000_000_000,
            end_time: 1_000_500_000,
            scope: "direct-map".to_string(),
            counts: vec![("shared-pages".to_string(), 12)],
            units: "bytes".to_string(),
            visited: 64,
            returned: 1,
            bounded: false,
            atomicity: "interval".to_string(),
            quality: example_quality(),
        }
    }

    /// Check frozen fields closed, counters unique, bounds honored.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_id("sample_id", &self.sample_id)?;
        check_closed("source_id", &self.source_id, &EXPOSURE_SOURCES)?;
        if self.start_time > self.end_time {
            return Err(ExposureError::new("sample_interval", "start past end"));
        }
        check_id("scope", &self.scope)?;
        let mut names: Vec<&str> = Vec::new();
        for (name, _) in &self.counts {
            check_id("counts", name)?;
            if names.contains(&name.as_str()) {
                return Err(ExposureError::new("counts", "duplicate counter"));
            }
            names.push(name);
        }
        check_closed("units", &self.units, &UNITS)?;
        if self.visited > MAX_VISITED {
            return Err(ExposureError::new("visited", "over scan bound"));
        }
        if self.returned > MAX_RETURNED {
            return Err(ExposureError::new("returned", "over scan bound"));
        }
        if self.returned > self.visited {
            return Err(ExposureError::new("returned", "above visited"));
        }
        check_closed("atomicity", &self.atomicity, &ATOMICITIES)?;
        validate_quality(&self.quality, "quality")
    }
}

/// One authored-rule evaluation outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyResult {
    /// Stable authored rule identifier.
    pub rule_id: String,
    /// Scope the rule was evaluated against.
    pub scope_id: String,
    /// Frozen policy result.
    pub result: String,
    /// Evidence supporting this result.
    pub evidence_ids: Vec<String>,
    /// Required sources absent from the capture.
    pub missing_sources: Vec<String>,
    /// Bounded exceptions that applied, each naming its rule.
    pub exceptions_applied: Vec<String>,
    /// Clock domain of the temporal evaluation.
    pub clock_domain: String,
    /// Human-readable rule and outcome explanation.
    pub reason: String,
}

impl PolicyResult {
    /// A valid conforming rule evaluation.
    pub fn example() -> Self {
        Self {
            rule_id: "no-unexpected-queue".to_string(),
            scope_id: "virtio-queues".to_string(),
            result: "conforms".to_string(),
            evidence_ids: vec!["ev-1".to_string()],
            missing_sources: Vec::new(),
            exceptions_applied: Vec::new(),
            clock_domain: "guest_monotonic_active".to_string(),
            reason: "No unexpected queue appeared; next check the queue ledger.".to_string(),
        }
    }

    /// Check frozen fields closed and identifiers bounded.
    pub fn validate(&self) -> Result<(), ExposureError> {
        if !is_opaque_id(&self.rule_id) || self.rule_id.len() > POLICY_MAX_ID_LEN {
            return Err(ExposureError::new("rule_id", "invalid identifier"));
        }
        check_id("scope_id", &self.scope_id)?;
        check_closed("result", &self.result, &POLICY_RESULTS)?;
        for handle in &self.evidence_ids {
            check_id("evidence_ids", handle)?;
        }
        for source in &self.missing_sources {
            check_closed("missing_sources", source, &EXPOSURE_SOURCES)?;
        }
        for handle in &self.exceptions_applied {
            check_id("exceptions_applied", handle)?;
        }
        check_closed("clock_domain", &self.clock_domain, &CLOCK_DOMAINS)?;
        if !is_bounded_text(&self.reason, 1024) {
            return Err(ExposureError::new("reason", "invalid text"));
        }
        Ok(())
    }
}

/// One per-metric before/after comparison outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComparisonResult {
    /// Compared metric.
    pub metric_id: String,
    /// Frozen compatibility outcome.
    pub compatibility: String,
    /// Per-metric compatibility reason.
    pub reason: String,
    /// Left-capture evidence handle.
    pub left_evidence: String,
    /// Right-capture evidence handle.
    pub right_evidence: String,
    /// Signed delta; absent for incompatible metrics.
    pub delta: Maybe<i64>,
    /// Delta unit.
    pub unit: String,
    /// Deferred comparison scope.
    pub scope: String,
    /// Per-comparison quality.
    pub quality: Quality,
}

impl ComparisonResult {
    /// A valid compatible comparison with a zero delta.
    pub fn example() -> Self {
        Self {
            metric_id: "shared-pages".to_string(),
            compatibility: "compatible".to_string(),
            reason: "Same identity, profile, workload, window and unit.".to_string(),
            left_evidence: "ev-left".to_string(),
            right_evidence: "ev-right".to_string(),
            delta: Maybe {
                present: true,
                value: Some(0),
                reason: String::new(),
            },
            unit: "bytes".to_string(),
            scope: "direct-map".to_string(),
            quality: example_quality(),
        }
    }

    /// Check frozen fields closed and the delta shape honest.
    pub fn validate(&self) -> Result<(), ExposureError> {
        check_id("metric_id", &self.metric_id)?;
        check_closed("compatibility", &self.compatibility, &COMPATIBILITIES)?;
        if !is_bounded_text(&self.reason, 1024) {
            return Err(ExposureError::new("reason", "invalid text"));
        }
        check_id("left_evidence", &self.left_evidence)?;
        check_id("right_evidence", &self.right_evidence)?;
        self.delta.validate_shape("delta")?;
        if !self.delta.present && self.compatibility == "compatible" {
            return Err(ExposureError::new("delta", "absent for compatible metric"));
        }
        if self.delta.present && self.compatibility == "incompatible" {
            return Err(ExposureError::new("delta", "delta for incompatible metric"));
        }
        if self.delta.value.is_some() && self.compatibility != "compatible" {
            return Err(ExposureError::new("delta", "delta for incompatible metric"));
        }
        check_closed("unit", &self.unit, &UNITS)?;
        check_id("scope", &self.scope)?;
        validate_quality(&self.quality, "quality")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_and_bounds_match_contract() {
        assert!(is_exposure_version("0.3.0"));
        assert!(!is_exposure_version("0.1.4"));
        assert_eq!(EXPOSURE_EVENT_VERSION, "0.3.0");
        assert_eq!(EXPOSURE_REPORT_VERSION, "0.3.0");
        assert_eq!(EXPOSURE_POLICY_VERSION, "0.1.0");
        assert_eq!(EXPOSURE_CATALOG_VERSION, "0.1.0");
        assert_eq!(MAX_OBJECTS, 65_536);
        assert_eq!(MAX_EDGES, 262_144);
        assert_eq!(MAX_VISITED, 1_048_576);
        assert_eq!(MAX_RETURNED, 65_536);
        assert_eq!(POLICY_MAX_BYTES, 1_048_576);
        assert_eq!(POLICY_MAX_RULES, 1024);
        assert_eq!(POLICY_MAX_EXCEPTIONS_PER_RULE, 64);
        assert_eq!(POLICY_MAX_ID_LEN, 64);
        assert_eq!(
            CHANNELS,
            ["detail", "aggregate", "identity", "baseline", "terminal"]
        );
        assert_eq!(
            (DETAIL, AGGREGATE, IDENTITY, BASELINE, TERMINAL),
            (0, 1, 2, 3, 4)
        );
    }

    #[test]
    fn frozen_vocabularies_pin_closed_lists() {
        for value in SEMANTICS {
            assert!(is_semantics(value));
        }
        assert!(!is_semantics("guess"));
        for value in PHASES {
            assert!(is_phase(value));
        }
        assert!(!is_phase("later"));
        for value in SOURCE_STATUSES {
            assert!(is_source_status(value));
        }
        assert!(!is_source_status("made_up"));
        for value in POLICY_RESULTS {
            assert!(is_policy_result(value));
        }
        assert!(!is_policy_result("conforms_maybe"));
        for value in COMPATIBILITIES {
            assert!(is_compatibility(value));
        }
        assert!(!is_compatibility("close_enough"));
        for value in ATOMICITIES {
            assert!(is_atomicity(value));
        }
        assert!(!is_atomicity("sometimes"));
        for value in CLOCK_DOMAINS {
            assert!(is_clock_domain(value));
        }
        assert!(!is_clock_domain("wall_clock"));
        for value in ADDRESS_NAMESPACES {
            assert!(is_address_namespace(value));
        }
        assert!(!is_address_namespace("physical"));
        for value in OBJECT_CLASSES {
            assert!(is_object_class(value));
        }
        assert!(!is_object_class("heap"));
        for value in LIFECYCLE_STATUSES {
            assert!(is_lifecycle_status(value));
        }
        assert!(!is_lifecycle_status("gone"));
        for value in SUBJECT_CLASSES {
            assert!(is_subject_class(value));
        }
        assert!(!is_subject_class("guest-user"));
        for value in PEER_CLASSES {
            assert!(is_peer_class(value));
        }
        assert!(!is_peer_class("host-everything"));
        for value in UNITS {
            assert!(is_unit(value));
        }
        assert!(!is_unit("pages"));
        for value in EXPOSURE_CAPABILITIES {
            assert!(is_exposure_capability(value));
        }
        assert!(!is_exposure_capability("conversion-journal"));
        for value in EXPOSURE_SOURCES {
            assert!(is_exposure_source(value));
        }
        assert!(!is_exposure_source("conversion-requests"));
        for value in PLATFORM_CELLS {
            assert!(is_platform_cell(value));
        }
        assert!(!is_platform_cell("6.11.0"));
        for value in SOURCE_REASONS {
            assert!(is_source_reason(value));
        }
        assert!(!is_source_reason("no-reason"));
        for value in BOUNDARY_TYPES {
            assert!(is_boundary_type(value));
        }
        assert!(!is_boundary_type("whenever"));
        for value in QUALITY_STATUSES {
            assert!(is_quality_status(value));
        }
        assert!(!is_quality_status("complete"));
        for value in MEASUREMENTS {
            assert!(is_measurement(value));
        }
        assert!(!is_measurement("guess"));
        for value in CORRELATIONS {
            assert!(is_correlation(value));
        }
        assert!(!is_correlation("guess"));
    }

    #[test]
    fn identifier_shapes() {
        assert!(is_opaque_id("ev-1"));
        assert!(is_opaque_id("a.b_c-d"));
        assert!(!is_opaque_id(""));
        assert!(!is_opaque_id("-lead"));
        assert!(!is_opaque_id(".lead"));
        assert!(!is_opaque_id("has space"));
        assert!(!is_opaque_id(&"a".repeat(129)));
        assert!(is_slug("sharing-census"));
        assert!(!is_slug("Sharing-Census"));
        assert!(!is_slug("has_space"));
        assert!(!is_slug(""));
        assert!(is_bounded_text("next: check the ledger.", 1024));
        assert!(!is_bounded_text("", 1024));
        assert!(!is_bounded_text("has\nnewline", 1024));
    }

    #[test]
    fn maybe_reason_shape() {
        let absent: Maybe<String> = Maybe {
            present: false,
            value: None,
            reason: String::new(),
        };
        absent.validate_shape("field").unwrap();
        let valued: Maybe<String> = Maybe {
            present: true,
            value: Some("v".to_string()),
            reason: String::new(),
        };
        valued.validate_shape("field").unwrap();
        let null: Maybe<String> = Maybe {
            present: true,
            value: None,
            reason: "withheld".to_string(),
        };
        null.validate_shape("field").unwrap();
        let missing: Maybe<String> = Maybe {
            present: true,
            value: None,
            reason: String::new(),
        };
        assert!(missing.validate_shape("field").is_err());
        let stray: Maybe<String> = Maybe {
            present: true,
            value: Some("v".to_string()),
            reason: "withheld".to_string(),
        };
        assert!(stray.validate_shape("field").is_err());
        let absent_reason: Maybe<String> = Maybe {
            present: false,
            value: None,
            reason: "withheld".to_string(),
        };
        assert!(absent_reason.validate_shape("field").is_err());
        let absent_valued: Maybe<String> = Maybe {
            present: false,
            value: Some("v".to_string()),
            reason: String::new(),
        };
        assert!(absent_valued.validate_shape("field").is_err());
    }

    #[test]
    fn source_capability_pairs_follow_catalog() {
        let example = CoverageSource::example();
        assert_eq!(example.status, "unavailable");
        assert_eq!(example.reason, "adapter-unimplemented");
        example.validate().unwrap();
        for (source, capability) in SOURCE_CAPABILITIES {
            assert!(is_exposure_source(source));
            assert!(is_exposure_capability(capability));
            assert_eq!(source_capability(source), Some(capability));
            let mut owned = CoverageSource::example();
            owned.source_id = source.to_string();
            owned.capability = capability.to_string();
            owned.validate().unwrap();
        }
        assert_eq!(source_capability("unknown-source"), None);
        let mut mixed = CoverageSource::example();
        mixed.capability = "host-interfaces".to_string();
        assert!(mixed.validate().is_err());
    }

    #[test]
    fn unavailable_example_carries_unknown_loss() {
        let example = CoverageSource::example();
        assert_eq!(example.status, "unavailable");
        assert_eq!(example.reason, "adapter-unimplemented");
        for channel in &example.quality {
            assert_eq!(channel.status, "unavailable");
            assert_eq!(channel.loss, None);
        }
        example.validate().unwrap();
    }

    #[test]
    fn missing_sources_name_catalog_entries() {
        let mut result = PolicyResult::example();
        result.missing_sources = vec!["sharing-census".to_string()];
        result.validate().unwrap();
        result.missing_sources = vec!["unknown-source".to_string()];
        assert!(result.validate().is_err());
    }

    #[test]
    fn windows_and_samples_reject_reversed_bounds() {
        let mut source = CoverageSource::example();
        source.window_start_ns = 2;
        source.window_end_ns = 1;
        assert!(source.validate().is_err());
        let mut fact = ExposureFact::example("ev-1", "sharing-census", 7);
        fact.observed_start = 2;
        fact.observed_end = 1;
        assert!(fact.validate().is_err());
        let mut sample = BaselineSample::example();
        sample.start_time = 2;
        sample.end_time = 1;
        assert!(sample.validate().is_err());
        sample.start_time = 1;
        sample.end_time = 1;
        sample.returned = 2;
        sample.visited = 1;
        assert!(sample.validate().is_err());
        sample.returned = 1;
        sample.visited = MAX_VISITED + 1;
        assert!(sample.validate().is_err());
        sample.visited = 1;
        sample.counts.push(("shared-pages".to_string(), 1));
        assert!(sample.validate().is_err());
    }

    #[test]
    fn comparison_delta_rules() {
        let mut good = ComparisonResult::example();
        good.validate().unwrap();
        good.compatibility = "incompatible".to_string();
        good.delta = Maybe {
            present: false,
            value: None,
            reason: String::new(),
        };
        good.validate().unwrap();
        good.delta = Maybe {
            present: true,
            value: Some(3),
            reason: String::new(),
        };
        assert!(good.validate().is_err());
        good.delta = Maybe {
            present: true,
            value: None,
            reason: "uncomputable".to_string(),
        };
        assert!(good.validate().is_err());
        good.compatibility = "compatible".to_string();
        good.validate().unwrap();
        good.delta = Maybe {
            present: false,
            value: None,
            reason: String::new(),
        };
        assert!(good.validate().is_err());
    }
}
