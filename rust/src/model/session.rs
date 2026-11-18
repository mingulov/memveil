// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed capture session: session.json, formats 0.1.1 to 0.1.4.
//!
//! The parser validates the whole document against the frozen session
//! schemas: required fields, version membership, enum membership, string
//! lengths, array item caps, and no unknown or duplicated keys. Format
//! 0.1.2 adds the optional correlation relations object; 0.1.1 documents
//! carrying relations are refused. Format 0.1.3 adds the optional record
//! verdict object plus the optional drain_completed and submit_after_drain
//! stop keys; older documents carrying any of them are refused. Format
//! 0.1.4 requires committed-byte integrity metadata; structural parsing
//! does not verify the event file. The observation window must satisfy
//! start <= end; an empty window is valid and simply matches no event.
//! Device IDs must be unique within the catalog.

use super::integrity::{Integrity, parse_integrity};
use super::regions::{RegionObservation, check_region_space, check_region_state};
use super::scan::{
    Scanner, array_is_empty, array_next, expect_colon, object_is_empty, object_next,
    parse_id_field, parse_nullable_string, parse_u64_field,
};
use super::validate::{ValidationError, check_bounded_text, checked_add};

/// Environment evidence list cap.
pub const MAX_EVIDENCE_ITEMS: usize = 64;
/// Device catalog cap.
pub const MAX_DEVICES: usize = 4096;
/// Baseline region observation cap.
pub const MAX_REGION_OBSERVATIONS: usize = 4096;
/// Capability hook list cap.
pub const MAX_HOOKS: usize = 32;
/// Channel evidence reference cap.
pub const MAX_EVIDENCE_REFS: usize = 32;
/// Session schema with committed-byte integrity.
pub const SESSION_SCHEMA_VERSION_INTEGRITY: &str = "0.1.4";
/// Current session schema without integrity.
pub const SESSION_SCHEMA_VERSION: &str = "0.1.3";
/// Previous session schema with correlation relations.
pub const SESSION_SCHEMA_VERSION_PREV: &str = "0.1.2";
/// Oldest accepted session schema.
pub const SESSION_SCHEMA_VERSION_PREV2: &str = "0.1.1";
const PRODUCT_NAME: &str = "memveil";
const CORR_RELATION_MAPPING: &str = "mapping_release";
const CORR_RELATION_COPY: &str = "copy_attribution";
const CORR_RELATION_SYNC: &str = "sync_attribution";

/// One environment evidence record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceItem {
    /// Evidence type label.
    pub item_type: String,
    /// Evidence source label.
    pub source: String,
    /// Human interpretation.
    pub interpretation: String,
}

/// One catalogued device.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DeviceEntry {
    /// Interned device token.
    pub device_id: String,
    /// Display name.
    pub name: String,
    /// True when a driver string was reported.
    pub has_driver: bool,
    /// Driver name; empty unless `has_driver`.
    pub driver: String,
    /// True when the driver key was present, even as null.
    pub driver_present: bool,
    /// Identity resolution status enum.
    pub identity_status: String,
}

/// One producer capability claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Capability {
    /// Capability status enum.
    pub status: String,
    /// Status reason text.
    pub reason: String,
    /// Claimed hook identities.
    pub hooks: Vec<String>,
    /// True when a profile was reported.
    pub has_profile_id: bool,
    /// Profile identity; empty unless `has_profile_id`.
    pub profile_id: String,
    /// True when a grade was reported.
    pub has_grade: bool,
    /// Grade enum; empty unless `has_grade`.
    pub grade: String,
}

/// One session quality channel claim.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Channel {
    /// Channel status enum.
    pub status: String,
    /// True when a loss count was reported.
    pub has_loss_count: bool,
    /// Lost records; zero unless `has_loss_count`.
    pub loss_count: u64,
    /// Claim scope text.
    pub scope: String,
    /// Status reason text.
    pub reason: String,
    /// Evidence reference labels.
    pub evidence_refs: Vec<String>,
}

/// Terminal stop evidence: the six stages, proved or not.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StopState {
    /// Stop outcome enum.
    pub outcome: String,
    /// Outcome reason text.
    pub reason: String,
    /// Stop budget in milliseconds.
    pub budget_ms: u64,
    /// Elapsed stop time in milliseconds.
    pub elapsed_ms: u64,
    /// True when admission closed.
    pub admission_closed: bool,
    /// True when quiescence was observed.
    pub quiescence_observed: bool,
    /// Writers settled count.
    pub writers_settled: u64,
    /// In-flight submissions at close.
    pub in_flight_at_close: u64,
    /// Late submissions drained.
    pub late_submits_drained: u64,
    /// Records drained.
    pub drained_records: u64,
    /// True when the drain completed.
    pub drain_completed: bool,
    /// True when a submit landed after the drain.
    pub submit_after_drain: bool,
    /// True when the drain key was present.
    pub has_drain_completed: bool,
    /// True when the submit-after-drain key was present.
    pub has_submit_after_drain: bool,
    /// True when the ring was busy at the drain.
    pub busy_at_drain: bool,
    /// True when counters were sampled.
    pub counters_valid: bool,
    /// Mappings still open.
    pub open_mappings: u64,
    /// Checkpoint failures.
    pub checkpoint_failures: u64,
    /// True when the checkpoint-failures key was present.
    pub has_checkpoint_failures: bool,
}

/// One validated capture session header.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct Session {
    /// Session identity.
    pub session_id: String,
    /// True when a boot identity was reported.
    pub has_boot_id: bool,
    /// Boot identity; empty unless `has_boot_id`.
    pub boot_id: String,
    /// True for synthetic captures.
    pub synthetic: bool,
    /// Producer name const.
    pub product_name: String,
    /// Producer version.
    pub product_version: String,
    /// True when a build label was reported.
    pub has_build: bool,
    /// Build label; empty unless `has_build`.
    pub build: String,
    /// Confidential-environment mode enum.
    pub env_mode: String,
    /// Environment detection enum.
    pub env_detection: String,
    /// True when an asserted mode was reported.
    pub has_asserted_mode: bool,
    /// Asserted mode; empty unless `has_asserted_mode`.
    pub asserted_mode: String,
    /// True when the asserted-mode key was present, even as null.
    pub asserted_mode_present: bool,
    /// Attestation enum.
    pub env_attestation: String,
    /// Environment evidence records.
    pub evidence: Vec<EvidenceItem>,
    /// Capture mode enum.
    pub capture_mode: String,
    /// Observation window start in nanoseconds.
    pub window_start_ns: u64,
    /// Observation window end in nanoseconds.
    pub window_end_ns: u64,
    /// True when a baseline floor was reported.
    pub has_baseline_start_ns: bool,
    /// Baseline floor; zero unless `has_baseline_start_ns`.
    pub baseline_start_ns: u64,
    /// True when a device filter was reported.
    pub has_filter_device: bool,
    /// Device filter; empty unless `has_filter_device`.
    pub filter_device: String,
    /// True when the capture finalized.
    pub finalized: bool,
    /// Checkpoint generation; zero unless `has_checkpoint_generation`.
    pub checkpoint_generation: u64,
    /// True when a checkpoint generation was reported.
    pub has_checkpoint_generation: bool,
    /// True when integrity metadata was reported.
    pub has_integrity: bool,
    /// Committed-byte snapshot.
    pub integrity: Integrity,
    /// True when an end reason was reported.
    pub has_end_reason: bool,
    /// End reason; empty unless `has_end_reason`.
    pub end_reason: String,
    /// Catalogued devices.
    pub devices: Vec<DeviceEntry>,
    /// True when the baseline completed.
    pub baseline_complete: bool,
    /// Baseline region observation count.
    pub baseline_region_count: usize,
    /// Baseline region observations.
    pub baseline_regions: Vec<RegionObservation>,
    /// Bounce-attempt capability.
    pub cap_bounce_attempts: Capability,
    /// Mapping-lifecycle capability.
    pub cap_mapping_lifecycle: Capability,
    /// Copy-bytes capability.
    pub cap_copy_bytes: Capability,
    /// Sync-request capability.
    pub cap_sync_requests: Capability,
    /// Conversion-result capability.
    pub cap_conversion_results: Capability,
    /// Region-state capability.
    pub cap_region_state: Capability,
    /// Pool-statistics capability.
    pub cap_pool_stats: Capability,
    /// Task-context capability.
    pub cap_task_context: Capability,
    /// Detail quality channel.
    pub q_detail: Channel,
    /// Aggregate quality channel.
    pub q_aggregate: Channel,
    /// Correlation quality channel.
    pub q_correlation: Channel,
    /// True when relation classes were reported.
    pub has_corr_relations: bool,
    /// Mapping-release relation channel.
    pub q_corr_mapping: Channel,
    /// Copy-attribution relation channel.
    pub q_corr_copy: Channel,
    /// Sync-attribution relation channel.
    pub q_corr_sync: Channel,
    /// Baseline quality channel.
    pub q_baseline: Channel,
    /// Terminal quality channel.
    pub q_terminal: Channel,
    /// Terminal stop evidence.
    pub stop: StopState,
    /// True when a record verdict was reported.
    pub has_verdict: bool,
    /// Verdict name enum; empty unless `has_verdict`.
    pub verdict_name: String,
    /// Verdict loss ratio in basis points.
    pub verdict_loss_bps: i64,
    /// Verdict delivered records.
    pub verdict_delivered: u64,
}

#[derive(Debug, Clone, Default)]
struct Capture {
    mode: String,
    window_start_ns: u64,
    window_end_ns: u64,
    has_baseline_start_ns: bool,
    baseline_start_ns: u64,
    has_filter_device: bool,
    filter_device: String,
    finalized: bool,
    checkpoint_generation: u64,
    has_checkpoint_generation: bool,
    has_integrity: bool,
    integrity: Integrity,
    has_end_reason: bool,
    end_reason: String,
}

#[derive(Debug, Clone, Default)]
struct Baseline {
    complete: bool,
    region_count: usize,
    regions: Vec<RegionObservation>,
}

fn check_env_mode(value: &str) -> Result<(), ValidationError> {
    if value == "none"
        || value == "sev"
        || value == "sev_es"
        || value == "sev_snp"
        || value == "tdx"
        || value == "unknown"
    {
        return Ok(());
    }
    Err(ValidationError::new("environment.mode", "bad enum"))
}

fn check_detection(value: &str) -> Result<(), ValidationError> {
    if value == "kernel_reported" || value == "unverified" || value == "conflicting" {
        return Ok(());
    }
    Err(ValidationError::new("environment.detection", "bad enum"))
}

fn check_asserted_mode(value: &str) -> Result<(), ValidationError> {
    if value == "none"
        || value == "sev"
        || value == "sev_es"
        || value == "sev_snp"
        || value == "tdx"
        || value == "unknown"
    {
        return Ok(());
    }
    Err(ValidationError::new(
        "environment.asserted_mode",
        "bad enum",
    ))
}

fn check_attestation(value: &str) -> Result<(), ValidationError> {
    if value == "not_performed" || value == "external_verified" || value == "failed" {
        return Ok(());
    }
    Err(ValidationError::new("environment.attestation", "bad enum"))
}

fn check_capture_mode(value: &str) -> Result<(), ValidationError> {
    if value == "live" || value == "synthetic" {
        return Ok(());
    }
    Err(ValidationError::new("capture.mode", "bad enum"))
}

fn check_end_reason(value: &str) -> Result<(), ValidationError> {
    if value == "checkpoint"
        || value == "duration"
        || value == "size_limit"
        || value == "signal"
        || value == "error"
        || value == "unknown"
    {
        return Ok(());
    }
    Err(ValidationError::new("capture.end_reason", "bad enum"))
}

fn check_identity_status(value: &str) -> Result<(), ValidationError> {
    if value == "resolved" || value == "unresolved" || value == "exhausted" {
        return Ok(());
    }
    Err(ValidationError::new("device.identity_status", "bad enum"))
}

fn check_capability_status(value: &str) -> Result<(), ValidationError> {
    if value == "verified" || value == "partial" || value == "unavailable" || value == "disabled" {
        return Ok(());
    }
    Err(ValidationError::new("capability.status", "bad enum"))
}

fn check_capability_grade(value: &str) -> Result<(), ValidationError> {
    if value == "validated" || value == "local-auto" || value == "candidate" || value == "partial" {
        return Ok(());
    }
    Err(ValidationError::new("capability.grade", "bad enum"))
}

fn check_channel_status(value: &str) -> Result<(), ValidationError> {
    if value == "complete_for_scope"
        || value == "partial"
        || value == "unavailable"
        || value == "not_applicable"
    {
        return Ok(());
    }
    Err(ValidationError::new("channel.status", "bad enum"))
}

fn check_stop_outcome(value: &str) -> Result<(), ValidationError> {
    if value == "complete" || value == "partial" {
        return Ok(());
    }
    Err(ValidationError::new("stop.outcome", "bad enum"))
}

fn check_verdict_name(value: &str) -> Result<(), ValidationError> {
    if value == "complete" || value == "partial_known_loss" || value == "partial_unknown_loss" {
        return Ok(());
    }
    Err(ValidationError::new("verdict.name", "bad enum"))
}

fn parse_evidence_item(scan: &mut Scanner) -> Result<EvidenceItem, ValidationError> {
    scan.begin_object("evidence_item")?;
    let mut out = EvidenceItem::default();
    let mut has_type = false;
    let mut has_source = false;
    let mut has_interp = false;
    if !object_is_empty(scan, "evidence_item")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("evidence_item")?;
            expect_colon(scan, "evidence_item")?;
            if key == "type" {
                if has_type {
                    return Err(ValidationError::new("evidence_item.type", "duplicate"));
                }
                let v = scan.parse_string("evidence_item")?;
                check_bounded_text(&v, 1, 64, "evidence_item.type")?;
                out.item_type = v;
                has_type = true;
            } else if key == "source" {
                if has_source {
                    return Err(ValidationError::new("evidence_item.source", "duplicate"));
                }
                let v = scan.parse_string("evidence_item")?;
                check_bounded_text(&v, 1, 256, "evidence_item.source")?;
                out.source = v;
                has_source = true;
            } else if key == "interpretation" {
                if has_interp {
                    return Err(ValidationError::new(
                        "evidence_item.interpretation",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("evidence_item")?;
                check_bounded_text(&v, 0, 1024, "evidence_item.interpretation")?;
                out.interpretation = v;
                has_interp = true;
            } else {
                return Err(ValidationError::new(
                    "evidence_item",
                    "unknown evidence_item field",
                ));
            }
            if !object_next(scan, "evidence_item")? {
                break;
            }
        }
    }
    scan.end_object("evidence_item")?;
    if !has_type || !has_source || !has_interp {
        return Err(ValidationError::new("evidence_item", "missing field"));
    }
    Ok(out)
}

fn parse_device(scan: &mut Scanner) -> Result<DeviceEntry, ValidationError> {
    scan.begin_object("device")?;
    let mut out = DeviceEntry::default();
    let mut has_id = false;
    let mut has_name = false;
    let mut has_driver = false;
    let mut has_status = false;
    if !object_is_empty(scan, "device")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("device")?;
            expect_colon(scan, "device")?;
            if key == "device_id" {
                if has_id {
                    return Err(ValidationError::new("device.device_id", "duplicate"));
                }
                out.device_id = parse_id_field(scan, "device.device_id")?;
                has_id = true;
            } else if key == "name" {
                if has_name {
                    return Err(ValidationError::new("device.name", "duplicate"));
                }
                let v = scan.parse_string("device")?;
                check_bounded_text(&v, 0, 256, "device.name")?;
                out.name = v;
                has_name = true;
            } else if key == "driver" {
                if has_driver {
                    return Err(ValidationError::new("device.driver", "duplicate"));
                }
                let m = parse_nullable_string(scan, "device")?;
                out.driver_present = true;
                if let Some(v) = m {
                    check_bounded_text(&v, 1, 128, "device.driver")?;
                    out.driver = v;
                    out.has_driver = true;
                }
                has_driver = true;
            } else if key == "identity_status" {
                if has_status {
                    return Err(ValidationError::new("device.identity_status", "duplicate"));
                }
                let v = scan.parse_string("device")?;
                check_identity_status(&v)?;
                out.identity_status = v;
                has_status = true;
            } else {
                return Err(ValidationError::new("device", "unknown device field"));
            }
            if !object_next(scan, "device")? {
                break;
            }
        }
    }
    scan.end_object("device")?;
    if !has_id || !has_name || !has_status {
        return Err(ValidationError::new("device", "missing field"));
    }
    Ok(out)
}

fn parse_hooks(scan: &mut Scanner) -> Result<Vec<String>, ValidationError> {
    scan.begin_array("capability.hooks")?;
    let mut out: Vec<String> = Vec::new();
    if !array_is_empty(scan, "capability.hooks")? {
        loop {
            scan.skip_ws();
            let v = scan.parse_string("capability.hooks")?;
            check_bounded_text(&v, 1, 256, "capability.hooks[]")?;
            out.push(v);
            if out.len() > MAX_HOOKS {
                return Err(ValidationError::new("capability.hooks", "too many items"));
            }
            if !array_next(scan, "capability.hooks")? {
                break;
            }
        }
    }
    scan.end_array("capability.hooks")?;
    Ok(out)
}

fn parse_capability(scan: &mut Scanner, what: &str) -> Result<Capability, ValidationError> {
    scan.begin_object(what)?;
    let mut out = Capability::default();
    let mut has_status = false;
    let mut has_reason = false;
    let mut has_hooks = false;
    let mut has_profile = false;
    let mut has_grade = false;
    if !object_is_empty(scan, what)? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string(what)?;
            expect_colon(scan, what)?;
            if key == "status" {
                if has_status {
                    return Err(ValidationError::new(format!("{what}.status"), "duplicate"));
                }
                let v = scan.parse_string(what)?;
                check_capability_status(&v)?;
                out.status = v;
                has_status = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new(format!("{what}.reason"), "duplicate"));
                }
                let v = scan.parse_string(what)?;
                let field = format!("{what}.reason");
                check_bounded_text(&v, 1, 512, &field)?;
                out.reason = v;
                has_reason = true;
            } else if key == "hooks" {
                if has_hooks {
                    return Err(ValidationError::new(format!("{what}.hooks"), "duplicate"));
                }
                out.hooks = parse_hooks(scan)?;
                has_hooks = true;
            } else if key == "profile_id" {
                if has_profile {
                    return Err(ValidationError::new(
                        format!("{what}.profile_id"),
                        "duplicate",
                    ));
                }
                let m = parse_nullable_string(scan, what)?;
                if let Some(v) = m {
                    let field = format!("{what}.profile_id");
                    check_bounded_text(&v, 1, 128, &field)?;
                    out.profile_id = v;
                    out.has_profile_id = true;
                }
                has_profile = true;
            } else if key == "grade" {
                if has_grade {
                    return Err(ValidationError::new(format!("{what}.grade"), "duplicate"));
                }
                let g = parse_nullable_string(scan, what)?;
                if let Some(v) = g {
                    check_capability_grade(&v)?;
                    out.grade = v;
                    out.has_grade = true;
                }
                has_grade = true;
            } else {
                return Err(ValidationError::new(
                    what.to_string(),
                    "unknown capability field",
                ));
            }
            if !object_next(scan, what)? {
                break;
            }
        }
    }
    scan.end_object(what)?;
    if !has_status || !has_reason || !has_hooks {
        return Err(ValidationError::new(what.to_string(), "missing field"));
    }
    Ok(out)
}

fn parse_channel(scan: &mut Scanner, what: &str) -> Result<Channel, ValidationError> {
    scan.begin_object(what)?;
    let mut out = Channel::default();
    let mut has_status = false;
    let mut has_loss = false;
    let mut has_scope = false;
    let mut has_reason = false;
    let mut has_refs = false;
    if !object_is_empty(scan, what)? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string(what)?;
            expect_colon(scan, what)?;
            if key == "status" {
                if has_status {
                    return Err(ValidationError::new(format!("{what}.status"), "duplicate"));
                }
                let v = scan.parse_string(what)?;
                check_channel_status(&v)?;
                out.status = v;
                has_status = true;
            } else if key == "loss_count" {
                if has_loss {
                    return Err(ValidationError::new(
                        format!("{what}.loss_count"),
                        "duplicate",
                    ));
                }
                scan.skip_ws();
                if scan.peek(what)? == b'n' {
                    scan.parse_null(what)?;
                } else {
                    let field = format!("{what}.loss_count");
                    out.loss_count = parse_u64_field(scan, &field)?;
                    out.has_loss_count = true;
                }
                has_loss = true;
            } else if key == "scope" {
                if has_scope {
                    return Err(ValidationError::new(format!("{what}.scope"), "duplicate"));
                }
                let v = scan.parse_string(what)?;
                let field = format!("{what}.scope");
                check_bounded_text(&v, 1, 256, &field)?;
                out.scope = v;
                has_scope = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new(format!("{what}.reason"), "duplicate"));
                }
                let v = scan.parse_string(what)?;
                let field = format!("{what}.reason");
                check_bounded_text(&v, 1, 512, &field)?;
                out.reason = v;
                has_reason = true;
            } else if key == "evidence_refs" {
                if has_refs {
                    return Err(ValidationError::new(
                        format!("{what}.evidence_refs"),
                        "duplicate",
                    ));
                }
                let refs_what = format!("{what}.evidence_refs");
                scan.begin_array(&refs_what)?;
                if !array_is_empty(scan, &refs_what)? {
                    loop {
                        scan.skip_ws();
                        let v = scan.parse_string(&refs_what)?;
                        let item = format!("{what}.evidence_refs[]");
                        check_bounded_text(&v, 1, 256, &item)?;
                        out.evidence_refs.push(v);
                        if out.evidence_refs.len() > MAX_EVIDENCE_REFS {
                            return Err(ValidationError::new(
                                format!("{what}.evidence_refs"),
                                "too many items",
                            ));
                        }
                        if !array_next(scan, &refs_what)? {
                            break;
                        }
                    }
                }
                scan.end_array(&refs_what)?;
                has_refs = true;
            } else {
                return Err(ValidationError::new(
                    what.to_string(),
                    "unknown channel field",
                ));
            }
            if !object_next(scan, what)? {
                break;
            }
        }
    }
    scan.end_object(what)?;
    if !has_status || !has_loss || !has_scope || !has_reason {
        return Err(ValidationError::new(what.to_string(), "missing field"));
    }
    Ok(out)
}

fn parse_relations(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("quality.correlation.relations")?;
    let mut seen: Vec<String> = Vec::new();
    if !object_is_empty(scan, "quality.correlation.relations")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("quality.correlation.relations")?;
            expect_colon(scan, "quality.correlation.relations")?;
            if seen.contains(&key) {
                return Err(ValidationError::new(
                    "quality.correlation.relations",
                    "duplicate member",
                ));
            }
            seen.push(key.clone());
            if key == CORR_RELATION_MAPPING {
                out.q_corr_mapping =
                    parse_channel(scan, "quality.correlation.relations.mapping_release")?;
            } else if key == CORR_RELATION_COPY {
                out.q_corr_copy =
                    parse_channel(scan, "quality.correlation.relations.copy_attribution")?;
            } else if key == CORR_RELATION_SYNC {
                out.q_corr_sync =
                    parse_channel(scan, "quality.correlation.relations.sync_attribution")?;
            } else {
                return Err(ValidationError::new(
                    "quality.correlation.relations",
                    "unknown relation class",
                ));
            }
            if !object_next(scan, "quality.correlation.relations")? {
                break;
            }
        }
    }
    scan.end_object("quality.correlation.relations")?;
    if seen.len() != 3 {
        return Err(ValidationError::new(
            "quality.correlation.relations",
            "missing field",
        ));
    }
    out.has_corr_relations = true;
    Ok(())
}

fn parse_correlation_channel(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("quality.correlation")?;
    let mut channel = Channel::default();
    let mut has_status = false;
    let mut has_loss = false;
    let mut has_scope = false;
    let mut has_reason = false;
    let mut has_refs = false;
    let mut has_relations = false;
    if !object_is_empty(scan, "quality.correlation")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("quality.correlation")?;
            expect_colon(scan, "quality.correlation")?;
            if key == "status" {
                if has_status {
                    return Err(ValidationError::new(
                        "quality.correlation.status",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("quality.correlation")?;
                check_channel_status(&v)?;
                channel.status = v;
                has_status = true;
            } else if key == "loss_count" {
                if has_loss {
                    return Err(ValidationError::new(
                        "quality.correlation.loss_count",
                        "duplicate",
                    ));
                }
                scan.skip_ws();
                if scan.peek("quality.correlation")? == b'n' {
                    scan.parse_null("quality.correlation")?;
                } else {
                    channel.loss_count = parse_u64_field(scan, "quality.correlation.loss_count")?;
                    channel.has_loss_count = true;
                }
                has_loss = true;
            } else if key == "scope" {
                if has_scope {
                    return Err(ValidationError::new(
                        "quality.correlation.scope",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("quality.correlation")?;
                check_bounded_text(&v, 1, 256, "quality.correlation.scope")?;
                channel.scope = v;
                has_scope = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new(
                        "quality.correlation.reason",
                        "duplicate",
                    ));
                }
                let v = scan.parse_string("quality.correlation")?;
                check_bounded_text(&v, 1, 512, "quality.correlation.reason")?;
                channel.reason = v;
                has_reason = true;
            } else if key == "evidence_refs" {
                if has_refs {
                    return Err(ValidationError::new(
                        "quality.correlation.evidence_refs",
                        "duplicate",
                    ));
                }
                scan.begin_array("quality.correlation.evidence_refs")?;
                if !array_is_empty(scan, "quality.correlation.evidence_refs")? {
                    loop {
                        scan.skip_ws();
                        let v = scan.parse_string("quality.correlation.evidence_refs")?;
                        check_bounded_text(&v, 1, 256, "quality.correlation.evidence_refs[]")?;
                        channel.evidence_refs.push(v);
                        if channel.evidence_refs.len() > MAX_EVIDENCE_REFS {
                            return Err(ValidationError::new(
                                "quality.correlation.evidence_refs",
                                "too many items",
                            ));
                        }
                        if !array_next(scan, "quality.correlation.evidence_refs")? {
                            break;
                        }
                    }
                }
                scan.end_array("quality.correlation.evidence_refs")?;
                has_refs = true;
            } else if key == "relations" {
                if has_relations {
                    return Err(ValidationError::new(
                        "quality.correlation.relations",
                        "duplicate",
                    ));
                }
                parse_relations(scan, out)?;
                has_relations = true;
            } else {
                return Err(ValidationError::new(
                    "quality.correlation",
                    "unknown channel field",
                ));
            }
            if !object_next(scan, "quality.correlation")? {
                break;
            }
        }
    }
    scan.end_object("quality.correlation")?;
    if !has_status || !has_loss || !has_scope || !has_reason {
        return Err(ValidationError::new("quality.correlation", "missing field"));
    }
    out.q_correlation = channel;
    Ok(())
}

fn parse_region_observation(scan: &mut Scanner) -> Result<RegionObservation, ValidationError> {
    scan.begin_object("region_observation")?;
    let mut out = RegionObservation::default();
    let mut has_region = false;
    let mut has_state = false;
    let mut has_offset = false;
    let mut has_length = false;
    let mut has_space = false;
    let mut has_prov = false;
    let mut has_generation = false;
    if !object_is_empty(scan, "region_observation")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("region_observation")?;
            expect_colon(scan, "region_observation")?;
            if key == "region_id" {
                if has_region {
                    return Err(ValidationError::new("region_id", "duplicate"));
                }
                out.region_id = parse_id_field(scan, "region_id")?;
                has_region = true;
            } else if key == "state" {
                if has_state {
                    return Err(ValidationError::new("state", "duplicate"));
                }
                let v = scan.parse_string("region_observation")?;
                check_region_state(&v)?;
                out.state = v;
                has_state = true;
            } else if key == "offset" {
                if has_offset {
                    return Err(ValidationError::new("offset", "duplicate"));
                }
                out.offset = parse_u64_field(scan, "region_observation.offset")?;
                has_offset = true;
            } else if key == "length" {
                if has_length {
                    return Err(ValidationError::new("length", "duplicate"));
                }
                out.length = parse_u64_field(scan, "region_observation.length")?;
                has_length = true;
            } else if key == "address_space" {
                if has_space {
                    return Err(ValidationError::new("address_space", "duplicate"));
                }
                let v = scan.parse_string("region_observation")?;
                check_region_space(&v)?;
                out.address_space = v;
                has_space = true;
            } else if key == "provenance" {
                if has_prov {
                    return Err(ValidationError::new("provenance", "duplicate"));
                }
                let v = scan.parse_string("region_observation")?;
                check_bounded_text(&v, 1, 512, "region_observation.provenance")?;
                out.provenance = v;
                has_prov = true;
            } else if key == "generation" {
                if has_generation {
                    return Err(ValidationError::new("generation", "duplicate"));
                }
                scan.skip_ws();
                let g = scan.parse_int("region_observation.generation")?;
                if g < 1 {
                    return Err(ValidationError::new(
                        "region_observation.generation",
                        "must be positive",
                    ));
                }
                out.generation = g;
                has_generation = true;
            } else {
                return Err(ValidationError::new(
                    "region_observation",
                    "unknown region_observation field",
                ));
            }
            if !object_next(scan, "region_observation")? {
                break;
            }
        }
    }
    scan.end_object("region_observation")?;
    if !has_region || !has_state || !has_offset || !has_length || !has_space || !has_prov {
        return Err(ValidationError::new("region_observation", "missing field"));
    }
    if checked_add(out.offset, out.length).is_err() {
        return Err(ValidationError::new("region_observation", "span overflows"));
    }
    Ok(out)
}

fn parse_environment(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("environment")?;
    let mut has_mode = false;
    let mut has_detection = false;
    let mut has_asserted = false;
    let mut has_attestation = false;
    let mut has_evidence = false;
    if !object_is_empty(scan, "environment")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("environment")?;
            expect_colon(scan, "environment")?;
            if key == "mode" {
                if has_mode {
                    return Err(ValidationError::new("environment.mode", "duplicate"));
                }
                let v = scan.parse_string("environment")?;
                check_env_mode(&v)?;
                out.env_mode = v;
                has_mode = true;
            } else if key == "detection" {
                if has_detection {
                    return Err(ValidationError::new("environment.detection", "duplicate"));
                }
                let v = scan.parse_string("environment")?;
                check_detection(&v)?;
                out.env_detection = v;
                has_detection = true;
            } else if key == "asserted_mode" {
                if has_asserted {
                    return Err(ValidationError::new(
                        "environment.asserted_mode",
                        "duplicate",
                    ));
                }
                let m = parse_nullable_string(scan, "environment")?;
                out.asserted_mode_present = true;
                if let Some(v) = m {
                    check_asserted_mode(&v)?;
                    out.asserted_mode = v;
                    out.has_asserted_mode = true;
                }
                has_asserted = true;
            } else if key == "attestation" {
                if has_attestation {
                    return Err(ValidationError::new("environment.attestation", "duplicate"));
                }
                let v = scan.parse_string("environment")?;
                check_attestation(&v)?;
                out.env_attestation = v;
                has_attestation = true;
            } else if key == "evidence" {
                if has_evidence {
                    return Err(ValidationError::new("environment.evidence", "duplicate"));
                }
                scan.begin_array("environment.evidence")?;
                if !array_is_empty(scan, "environment.evidence")? {
                    loop {
                        scan.skip_ws();
                        out.evidence.push(parse_evidence_item(scan)?);
                        if out.evidence.len() > MAX_EVIDENCE_ITEMS {
                            return Err(ValidationError::new(
                                "environment.evidence",
                                "too many items",
                            ));
                        }
                        if !array_next(scan, "environment.evidence")? {
                            break;
                        }
                    }
                }
                scan.end_array("environment.evidence")?;
                has_evidence = true;
            } else {
                return Err(ValidationError::new(
                    "environment",
                    "unknown environment field",
                ));
            }
            if !object_next(scan, "environment")? {
                break;
            }
        }
    }
    scan.end_object("environment")?;
    if !has_mode || !has_detection || !has_attestation || !has_evidence {
        return Err(ValidationError::new("environment", "missing field"));
    }
    Ok(())
}

fn parse_window(scan: &mut Scanner) -> Result<Capture, ValidationError> {
    scan.begin_object("window")?;
    let mut out = Capture::default();
    let mut has_start = false;
    let mut has_end = false;
    let mut has_baseline = false;
    if !object_is_empty(scan, "window")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("window")?;
            expect_colon(scan, "window")?;
            if key == "start_ns" {
                if has_start {
                    return Err(ValidationError::new("window.start_ns", "duplicate"));
                }
                out.window_start_ns = parse_u64_field(scan, "window.start_ns")?;
                has_start = true;
            } else if key == "end_ns" {
                if has_end {
                    return Err(ValidationError::new("window.end_ns", "duplicate"));
                }
                out.window_end_ns = parse_u64_field(scan, "window.end_ns")?;
                has_end = true;
            } else if key == "baseline_start_ns" {
                if has_baseline {
                    return Err(ValidationError::new(
                        "window.baseline_start_ns",
                        "duplicate",
                    ));
                }
                out.baseline_start_ns = parse_u64_field(scan, "window.baseline_start_ns")?;
                out.has_baseline_start_ns = true;
                has_baseline = true;
            } else {
                return Err(ValidationError::new("window", "unknown window field"));
            }
            if !object_next(scan, "window")? {
                break;
            }
        }
    }
    scan.end_object("window")?;
    if !has_start || !has_end {
        return Err(ValidationError::new("window", "missing field"));
    }
    Ok(out)
}

fn parse_filters(scan: &mut Scanner) -> Result<Option<String>, ValidationError> {
    scan.begin_object("filters")?;
    let mut out: Option<String> = None;
    let mut has_device = false;
    if !object_is_empty(scan, "filters")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("filters")?;
            expect_colon(scan, "filters")?;
            if key == "device" {
                if has_device {
                    return Err(ValidationError::new("filters.device", "duplicate"));
                }
                let m = parse_nullable_string(scan, "filters")?;
                if let Some(v) = m {
                    check_bounded_text(&v, 1, 256, "filters.device")?;
                    out = Some(v);
                }
                has_device = true;
            } else {
                return Err(ValidationError::new("filters", "unknown filters field"));
            }
            if !object_next(scan, "filters")? {
                break;
            }
        }
    }
    scan.end_object("filters")?;
    Ok(out)
}

fn parse_capture(scan: &mut Scanner) -> Result<Capture, ValidationError> {
    scan.begin_object("capture")?;
    let mut out = Capture::default();
    let mut has_mode = false;
    let mut has_window = false;
    let mut has_filters = false;
    let mut has_finalized = false;
    let mut has_reason = false;
    if !object_is_empty(scan, "capture")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("capture")?;
            expect_colon(scan, "capture")?;
            if key == "mode" {
                if has_mode {
                    return Err(ValidationError::new("capture.mode", "duplicate"));
                }
                let v = scan.parse_string("capture")?;
                check_capture_mode(&v)?;
                out.mode = v;
                has_mode = true;
            } else if key == "window" {
                if has_window {
                    return Err(ValidationError::new("capture.window", "duplicate"));
                }
                let w = parse_window(scan)?;
                out.window_start_ns = w.window_start_ns;
                out.window_end_ns = w.window_end_ns;
                out.has_baseline_start_ns = w.has_baseline_start_ns;
                out.baseline_start_ns = w.baseline_start_ns;
                has_window = true;
            } else if key == "filters" {
                if has_filters {
                    return Err(ValidationError::new("capture.filters", "duplicate"));
                }
                let m = parse_filters(scan)?;
                if let Some(v) = m {
                    out.filter_device = v;
                    out.has_filter_device = true;
                }
                has_filters = true;
            } else if key == "finalized" {
                if has_finalized {
                    return Err(ValidationError::new("capture.finalized", "duplicate"));
                }
                scan.skip_ws();
                out.finalized = scan.parse_bool("capture")?;
                has_finalized = true;
            } else if key == "checkpoint_generation" {
                if out.has_checkpoint_generation {
                    return Err(ValidationError::new(
                        "capture.checkpoint_generation",
                        "duplicate",
                    ));
                }
                out.checkpoint_generation = parse_u64_field(scan, "capture.checkpoint_generation")?;
                out.has_checkpoint_generation = true;
            } else if key == "integrity" {
                if out.has_integrity {
                    return Err(ValidationError::new("capture.integrity", "duplicate"));
                }
                out.integrity = parse_integrity(scan)?;
                out.has_integrity = true;
            } else if key == "end_reason" {
                if has_reason {
                    return Err(ValidationError::new("capture.end_reason", "duplicate"));
                }
                let m = parse_nullable_string(scan, "capture")?;
                if let Some(v) = m {
                    check_end_reason(&v)?;
                    out.end_reason = v;
                    out.has_end_reason = true;
                }
                has_reason = true;
            } else {
                return Err(ValidationError::new("capture", "unknown capture field"));
            }
            if !object_next(scan, "capture")? {
                break;
            }
        }
    }
    scan.end_object("capture")?;
    if !has_mode || !has_window || !has_filters || !has_finalized {
        return Err(ValidationError::new("capture", "missing field"));
    }
    if out.window_start_ns > out.window_end_ns {
        return Err(ValidationError::new("window", "start after end"));
    }
    if out.has_baseline_start_ns && out.baseline_start_ns > out.window_start_ns {
        return Err(ValidationError::new("window", "baseline after start"));
    }
    Ok(out)
}

fn parse_device_catalog(scan: &mut Scanner) -> Result<Vec<DeviceEntry>, ValidationError> {
    scan.begin_object("device_catalog")?;
    let mut out: Vec<DeviceEntry> = Vec::new();
    let mut has_devices = false;
    if !object_is_empty(scan, "device_catalog")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("device_catalog")?;
            expect_colon(scan, "device_catalog")?;
            if key == "devices" {
                if has_devices {
                    return Err(ValidationError::new("device_catalog.devices", "duplicate"));
                }
                scan.begin_array("device_catalog.devices")?;
                if !array_is_empty(scan, "device_catalog.devices")? {
                    loop {
                        scan.skip_ws();
                        out.push(parse_device(scan)?);
                        if out.len() > MAX_DEVICES {
                            return Err(ValidationError::new(
                                "device_catalog.devices",
                                "too many items",
                            ));
                        }
                        if !array_next(scan, "device_catalog.devices")? {
                            break;
                        }
                    }
                }
                scan.end_array("device_catalog.devices")?;
                has_devices = true;
            } else {
                return Err(ValidationError::new(
                    "device_catalog",
                    "unknown device_catalog field",
                ));
            }
            if !object_next(scan, "device_catalog")? {
                break;
            }
        }
    }
    scan.end_object("device_catalog")?;
    if !has_devices {
        return Err(ValidationError::new("device_catalog", "missing field"));
    }
    for i in 0..out.len() {
        for j in 0..i {
            if out[i].device_id == out[j].device_id {
                return Err(ValidationError::new(
                    "device_catalog.devices",
                    "duplicate device_id",
                ));
            }
        }
    }
    Ok(out)
}

fn parse_baseline(scan: &mut Scanner) -> Result<Baseline, ValidationError> {
    scan.begin_object("baseline")?;
    let mut out = Baseline::default();
    let mut has_complete = false;
    let mut has_regions = false;
    if !object_is_empty(scan, "baseline")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("baseline")?;
            expect_colon(scan, "baseline")?;
            if key == "complete" {
                if has_complete {
                    return Err(ValidationError::new("baseline.complete", "duplicate"));
                }
                scan.skip_ws();
                out.complete = scan.parse_bool("baseline")?;
                has_complete = true;
            } else if key == "region_observations" {
                if has_regions {
                    return Err(ValidationError::new(
                        "baseline.region_observations",
                        "duplicate",
                    ));
                }
                scan.begin_array("baseline.region_observations")?;
                if !array_is_empty(scan, "baseline.region_observations")? {
                    loop {
                        scan.skip_ws();
                        out.regions.push(parse_region_observation(scan)?);
                        out.region_count += 1;
                        if out.region_count > MAX_REGION_OBSERVATIONS {
                            return Err(ValidationError::new(
                                "baseline.region_observations",
                                "too many items",
                            ));
                        }
                        if !array_next(scan, "baseline.region_observations")? {
                            break;
                        }
                    }
                }
                scan.end_array("baseline.region_observations")?;
                has_regions = true;
            } else {
                return Err(ValidationError::new("baseline", "unknown baseline field"));
            }
            if !object_next(scan, "baseline")? {
                break;
            }
        }
    }
    scan.end_object("baseline")?;
    if !has_complete || !has_regions {
        return Err(ValidationError::new("baseline", "missing field"));
    }
    Ok(out)
}

fn parse_product(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("product")?;
    let mut has_name = false;
    let mut has_version = false;
    let mut has_build = false;
    if !object_is_empty(scan, "product")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("product")?;
            expect_colon(scan, "product")?;
            if key == "name" {
                if has_name {
                    return Err(ValidationError::new("product.name", "duplicate"));
                }
                let v = scan.parse_string("product")?;
                if v != PRODUCT_NAME {
                    return Err(ValidationError::new("product.name", "bad const"));
                }
                out.product_name = v;
                has_name = true;
            } else if key == "version" {
                if has_version {
                    return Err(ValidationError::new("product.version", "duplicate"));
                }
                let v = scan.parse_string("product")?;
                check_bounded_text(&v, 1, 64, "product.version")?;
                out.product_version = v;
                has_version = true;
            } else if key == "build" {
                if has_build {
                    return Err(ValidationError::new("product.build", "duplicate"));
                }
                let m = parse_nullable_string(scan, "product")?;
                if let Some(v) = m {
                    check_bounded_text(&v, 0, 128, "product.build")?;
                    out.build = v;
                    out.has_build = true;
                }
                has_build = true;
            } else {
                return Err(ValidationError::new("product", "unknown product field"));
            }
            if !object_next(scan, "product")? {
                break;
            }
        }
    }
    scan.end_object("product")?;
    if !has_name || !has_version {
        return Err(ValidationError::new("product", "missing field"));
    }
    Ok(())
}

fn parse_capabilities(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("capabilities")?;
    let mut seen: Vec<String> = Vec::new();
    if !object_is_empty(scan, "capabilities")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("capabilities")?;
            expect_colon(scan, "capabilities")?;
            if seen.contains(&key) {
                return Err(ValidationError::new("capabilities", "duplicate member"));
            }
            seen.push(key.clone());
            if key == "bounce_attempts" {
                out.cap_bounce_attempts = parse_capability(scan, "capabilities.bounce_attempts")?;
            } else if key == "mapping_lifecycle" {
                out.cap_mapping_lifecycle =
                    parse_capability(scan, "capabilities.mapping_lifecycle")?;
            } else if key == "copy_bytes" {
                out.cap_copy_bytes = parse_capability(scan, "capabilities.copy_bytes")?;
            } else if key == "sync_requests" {
                out.cap_sync_requests = parse_capability(scan, "capabilities.sync_requests")?;
            } else if key == "conversion_results" {
                out.cap_conversion_results =
                    parse_capability(scan, "capabilities.conversion_results")?;
            } else if key == "region_state" {
                out.cap_region_state = parse_capability(scan, "capabilities.region_state")?;
            } else if key == "pool_stats" {
                out.cap_pool_stats = parse_capability(scan, "capabilities.pool_stats")?;
            } else if key == "task_context" {
                out.cap_task_context = parse_capability(scan, "capabilities.task_context")?;
            } else {
                return Err(ValidationError::new("capabilities", "unknown capability"));
            }
            if !object_next(scan, "capabilities")? {
                break;
            }
        }
    }
    scan.end_object("capabilities")?;
    if seen.len() != 8 {
        return Err(ValidationError::new("capabilities", "missing field"));
    }
    Ok(())
}

fn parse_quality(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("quality")?;
    let mut seen: Vec<String> = Vec::new();
    if !object_is_empty(scan, "quality")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("quality")?;
            expect_colon(scan, "quality")?;
            if seen.contains(&key) {
                return Err(ValidationError::new("quality", "duplicate member"));
            }
            seen.push(key.clone());
            if key == "detail" {
                out.q_detail = parse_channel(scan, "quality.detail")?;
            } else if key == "aggregate" {
                out.q_aggregate = parse_channel(scan, "quality.aggregate")?;
            } else if key == "correlation" {
                parse_correlation_channel(scan, out)?;
            } else if key == "baseline" {
                out.q_baseline = parse_channel(scan, "quality.baseline")?;
            } else if key == "terminal" {
                out.q_terminal = parse_channel(scan, "quality.terminal")?;
            } else {
                return Err(ValidationError::new("quality", "unknown quality channel"));
            }
            if !object_next(scan, "quality")? {
                break;
            }
        }
    }
    scan.end_object("quality")?;
    if seen.len() != 5 {
        return Err(ValidationError::new("quality", "missing field"));
    }
    Ok(())
}

fn parse_verdict(scan: &mut Scanner, out: &mut Session) -> Result<(), ValidationError> {
    scan.begin_object("verdict")?;
    let mut has_name = false;
    let mut has_bps = false;
    let mut has_delivered = false;
    if !object_is_empty(scan, "verdict")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("verdict")?;
            expect_colon(scan, "verdict")?;
            if key == "name" {
                if has_name {
                    return Err(ValidationError::new("verdict.name", "duplicate"));
                }
                let v = scan.parse_string("verdict")?;
                check_verdict_name(&v)?;
                out.verdict_name = v;
                has_name = true;
            } else if key == "loss_ratio_bps" {
                if has_bps {
                    return Err(ValidationError::new("verdict.loss_ratio_bps", "duplicate"));
                }
                let v = parse_u64_field(scan, "verdict.loss_ratio_bps")?;
                if v > 10000 {
                    return Err(ValidationError::new(
                        "verdict.loss_ratio_bps",
                        "out of range",
                    ));
                }
                out.verdict_loss_bps = v as i64;
                has_bps = true;
            } else if key == "delivered" {
                if has_delivered {
                    return Err(ValidationError::new("verdict.delivered", "duplicate"));
                }
                out.verdict_delivered = parse_u64_field(scan, "verdict.delivered")?;
                has_delivered = true;
            } else {
                return Err(ValidationError::new("verdict", "unknown verdict field"));
            }
            if !object_next(scan, "verdict")? {
                break;
            }
        }
    }
    scan.end_object("verdict")?;
    if !has_name || !has_bps || !has_delivered {
        return Err(ValidationError::new("verdict", "missing field"));
    }
    out.has_verdict = true;
    Ok(())
}

fn parse_stop(scan: &mut Scanner) -> Result<StopState, ValidationError> {
    scan.begin_object("stop")?;
    let mut out = StopState::default();
    let mut has_outcome = false;
    let mut has_reason = false;
    let mut has_budget = false;
    let mut has_elapsed = false;
    let mut has_closed = false;
    let mut has_quiesced = false;
    let mut has_settled = false;
    let mut has_in_flight = false;
    let mut has_late = false;
    let mut has_drained = false;
    let mut has_busy = false;
    let mut has_counters = false;
    let mut has_open = false;
    if !object_is_empty(scan, "stop")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("stop")?;
            expect_colon(scan, "stop")?;
            if key == "outcome" {
                if has_outcome {
                    return Err(ValidationError::new("stop.outcome", "duplicate"));
                }
                let v = scan.parse_string("stop")?;
                check_stop_outcome(&v)?;
                out.outcome = v;
                has_outcome = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new("stop.reason", "duplicate"));
                }
                let v = scan.parse_string("stop")?;
                check_bounded_text(&v, 0, 512, "stop.reason")?;
                out.reason = v;
                has_reason = true;
            } else if key == "budget_ms" {
                if has_budget {
                    return Err(ValidationError::new("stop.budget_ms", "duplicate"));
                }
                out.budget_ms = parse_u64_field(scan, "stop.budget_ms")?;
                has_budget = true;
            } else if key == "elapsed_ms" {
                if has_elapsed {
                    return Err(ValidationError::new("stop.elapsed_ms", "duplicate"));
                }
                out.elapsed_ms = parse_u64_field(scan, "stop.elapsed_ms")?;
                has_elapsed = true;
            } else if key == "admission_closed" {
                if has_closed {
                    return Err(ValidationError::new("stop.admission_closed", "duplicate"));
                }
                scan.skip_ws();
                out.admission_closed = scan.parse_bool("stop")?;
                has_closed = true;
            } else if key == "quiescence_observed" {
                if has_quiesced {
                    return Err(ValidationError::new(
                        "stop.quiescence_observed",
                        "duplicate",
                    ));
                }
                scan.skip_ws();
                out.quiescence_observed = scan.parse_bool("stop")?;
                has_quiesced = true;
            } else if key == "writers_settled" {
                if has_settled {
                    return Err(ValidationError::new("stop.writers_settled", "duplicate"));
                }
                out.writers_settled = parse_u64_field(scan, "stop.writers_settled")?;
                has_settled = true;
            } else if key == "in_flight_at_close" {
                if has_in_flight {
                    return Err(ValidationError::new("stop.in_flight_at_close", "duplicate"));
                }
                out.in_flight_at_close = parse_u64_field(scan, "stop.in_flight_at_close")?;
                has_in_flight = true;
            } else if key == "late_submits_drained" {
                if has_late {
                    return Err(ValidationError::new(
                        "stop.late_submits_drained",
                        "duplicate",
                    ));
                }
                out.late_submits_drained = parse_u64_field(scan, "stop.late_submits_drained")?;
                has_late = true;
            } else if key == "drained_records" {
                if has_drained {
                    return Err(ValidationError::new("stop.drained_records", "duplicate"));
                }
                out.drained_records = parse_u64_field(scan, "stop.drained_records")?;
                has_drained = true;
            } else if key == "drain_completed" {
                if out.has_drain_completed {
                    return Err(ValidationError::new("stop.drain_completed", "duplicate"));
                }
                scan.skip_ws();
                out.drain_completed = scan.parse_bool("stop")?;
                out.has_drain_completed = true;
            } else if key == "submit_after_drain" {
                if out.has_submit_after_drain {
                    return Err(ValidationError::new("stop.submit_after_drain", "duplicate"));
                }
                scan.skip_ws();
                out.submit_after_drain = scan.parse_bool("stop")?;
                out.has_submit_after_drain = true;
            } else if key == "busy_at_drain" {
                if has_busy {
                    return Err(ValidationError::new("stop.busy_at_drain", "duplicate"));
                }
                scan.skip_ws();
                out.busy_at_drain = scan.parse_bool("stop")?;
                has_busy = true;
            } else if key == "counters_valid" {
                if has_counters {
                    return Err(ValidationError::new("stop.counters_valid", "duplicate"));
                }
                scan.skip_ws();
                out.counters_valid = scan.parse_bool("stop")?;
                has_counters = true;
            } else if key == "checkpoint_failures" {
                if out.has_checkpoint_failures {
                    return Err(ValidationError::new(
                        "stop.checkpoint_failures",
                        "duplicate",
                    ));
                }
                out.checkpoint_failures = parse_u64_field(scan, "stop.checkpoint_failures")?;
                out.has_checkpoint_failures = true;
            } else if key == "open_mappings" {
                if has_open {
                    return Err(ValidationError::new("stop.open_mappings", "duplicate"));
                }
                out.open_mappings = parse_u64_field(scan, "stop.open_mappings")?;
                has_open = true;
            } else {
                return Err(ValidationError::new("stop", "unknown stop field"));
            }
            if !object_next(scan, "stop")? {
                break;
            }
        }
    }
    scan.end_object("stop")?;
    if !has_outcome
        || !has_reason
        || !has_budget
        || !has_elapsed
        || !has_closed
        || !has_quiesced
        || !has_settled
        || !has_in_flight
        || !has_late
        || !has_drained
        || !has_busy
        || !has_counters
        || !has_open
    {
        return Err(ValidationError::new("stop", "missing field"));
    }
    if out.outcome == "complete" && !out.reason.is_empty() {
        return Err(ValidationError::new(
            "stop.reason",
            "complete carries no reason",
        ));
    }
    if out.outcome == "partial" && out.reason.is_empty() {
        return Err(ValidationError::new(
            "stop.reason",
            "partial needs a reason",
        ));
    }
    Ok(out)
}

/// Parse and validate one session.json document.
pub fn parse_session(data: &[u8]) -> Result<Session, ValidationError> {
    let mut scan = Scanner::new(data);
    scan.skip_ws();
    scan.begin_object("session")?;
    let mut out = Session::default();
    let mut out_version = String::new();
    let mut has_version = false;
    let mut has_session = false;
    let mut has_boot = false;
    let mut has_synthetic = false;
    let mut has_product = false;
    let mut has_env = false;
    let mut has_capture = false;
    let mut has_catalog = false;
    let mut has_baseline = false;
    let mut has_caps = false;
    let mut has_quality = false;
    let mut has_stop = false;
    let mut has_verdict_key = false;
    if !object_is_empty(&mut scan, "session")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("session")?;
            expect_colon(&mut scan, "session")?;
            if key == "schema_version" {
                if has_version {
                    return Err(ValidationError::new("schema_version", "duplicate"));
                }
                let v = scan.parse_string("session")?;
                if v != SESSION_SCHEMA_VERSION_INTEGRITY
                    && v != SESSION_SCHEMA_VERSION
                    && v != SESSION_SCHEMA_VERSION_PREV
                    && v != SESSION_SCHEMA_VERSION_PREV2
                {
                    return Err(ValidationError::new("schema_version", "bad const"));
                }
                out_version = v;
                has_version = true;
            } else if key == "session_id" {
                if has_session {
                    return Err(ValidationError::new("session_id", "duplicate"));
                }
                out.session_id = parse_id_field(&mut scan, "session_id")?;
                has_session = true;
            } else if key == "boot_id" {
                if has_boot {
                    return Err(ValidationError::new("boot_id", "duplicate"));
                }
                out.boot_id = parse_id_field(&mut scan, "boot_id")?;
                out.has_boot_id = true;
                has_boot = true;
            } else if key == "synthetic" {
                if has_synthetic {
                    return Err(ValidationError::new("synthetic", "duplicate"));
                }
                scan.skip_ws();
                out.synthetic = scan.parse_bool("session")?;
                has_synthetic = true;
            } else if key == "product" {
                if has_product {
                    return Err(ValidationError::new("product", "duplicate"));
                }
                parse_product(&mut scan, &mut out)?;
                has_product = true;
            } else if key == "environment" {
                if has_env {
                    return Err(ValidationError::new("environment", "duplicate"));
                }
                parse_environment(&mut scan, &mut out)?;
                has_env = true;
            } else if key == "capture" {
                if has_capture {
                    return Err(ValidationError::new("capture", "duplicate"));
                }
                let c = parse_capture(&mut scan)?;
                out.capture_mode = c.mode;
                out.window_start_ns = c.window_start_ns;
                out.window_end_ns = c.window_end_ns;
                out.has_baseline_start_ns = c.has_baseline_start_ns;
                out.baseline_start_ns = c.baseline_start_ns;
                out.has_filter_device = c.has_filter_device;
                out.filter_device = c.filter_device;
                out.finalized = c.finalized;
                out.checkpoint_generation = c.checkpoint_generation;
                out.has_checkpoint_generation = c.has_checkpoint_generation;
                out.has_integrity = c.has_integrity;
                out.integrity = c.integrity;
                out.has_end_reason = c.has_end_reason;
                out.end_reason = c.end_reason;
                has_capture = true;
            } else if key == "device_catalog" {
                if has_catalog {
                    return Err(ValidationError::new("device_catalog", "duplicate"));
                }
                out.devices = parse_device_catalog(&mut scan)?;
                has_catalog = true;
            } else if key == "baseline" {
                if has_baseline {
                    return Err(ValidationError::new("baseline", "duplicate"));
                }
                let b = parse_baseline(&mut scan)?;
                out.baseline_complete = b.complete;
                out.baseline_region_count = b.region_count;
                out.baseline_regions = b.regions;
                has_baseline = true;
            } else if key == "capabilities" {
                if has_caps {
                    return Err(ValidationError::new("capabilities", "duplicate"));
                }
                parse_capabilities(&mut scan, &mut out)?;
                has_caps = true;
            } else if key == "quality" {
                if has_quality {
                    return Err(ValidationError::new("quality", "duplicate"));
                }
                parse_quality(&mut scan, &mut out)?;
                has_quality = true;
            } else if key == "stop" {
                if has_stop {
                    return Err(ValidationError::new("stop", "duplicate"));
                }
                out.stop = parse_stop(&mut scan)?;
                has_stop = true;
            } else if key == "verdict" {
                if has_verdict_key {
                    return Err(ValidationError::new("verdict", "duplicate"));
                }
                parse_verdict(&mut scan, &mut out)?;
                has_verdict_key = true;
            } else {
                return Err(ValidationError::new("session", "unknown session field"));
            }
            if !object_next(&mut scan, "session")? {
                break;
            }
        }
    }
    scan.end_object("session")?;
    if !has_version
        || !has_session
        || !has_synthetic
        || !has_product
        || !has_env
        || !has_capture
        || !has_catalog
        || !has_baseline
        || !has_caps
        || !has_quality
        || !has_stop
    {
        return Err(ValidationError::new("session", "missing field"));
    }
    if out.synthetic != (out.capture_mode == "synthetic") {
        return Err(ValidationError::new(
            "synthetic",
            "contradicts capture mode",
        ));
    }
    if out_version == SESSION_SCHEMA_VERSION_PREV2 && out.has_corr_relations {
        return Err(ValidationError::new(
            "quality.correlation.relations",
            "relations need schema 0.1.2",
        ));
    }
    if (out_version == SESSION_SCHEMA_VERSION_INTEGRITY) != out.has_integrity {
        return Err(ValidationError::new(
            "capture.integrity",
            "required only by schema 0.1.4",
        ));
    }
    if out.has_checkpoint_generation
        && (!out.has_integrity
            || out.finalized
            || out.end_reason != "checkpoint"
            || out.checkpoint_generation == 0)
    {
        return Err(ValidationError::new(
            "capture.checkpoint_generation",
            "invalid checkpoint",
        ));
    }
    if out.end_reason == "checkpoint" && !out.has_checkpoint_generation {
        return Err(ValidationError::new(
            "capture.checkpoint_generation",
            "required for checkpoint",
        ));
    }
    if out.stop.has_checkpoint_failures && !out.has_integrity {
        return Err(ValidationError::new(
            "stop.checkpoint_failures",
            "requires schema 0.1.4",
        ));
    }
    if out_version != SESSION_SCHEMA_VERSION && out_version != SESSION_SCHEMA_VERSION_INTEGRITY {
        if out.has_verdict {
            return Err(ValidationError::new(
                "verdict",
                "verdict needs schema 0.1.3",
            ));
        }
        if out.stop.has_drain_completed || out.stop.has_submit_after_drain {
            return Err(ValidationError::new("stop", "drain keys need schema 0.1.3"));
        }
    }
    scan.skip_ws();
    if !scan.at_end() {
        return Err(ValidationError::new("session", "trailing data"));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::integrity::EMPTY_SHA256;
    use std::path::PathBuf;

    const EV012: &str = include_str!("../../../tests/fixtures/reader/ev012/session.json");
    const SEL011: &str =
        include_str!("../../../tests/fixtures/reader/selection-retained/session.json");
    const COMPAT: &str = include_str!("../../../tests/fixtures/reader/compat-major/session.json");
    const SEALED: &str =
        include_str!("../../../tests/fixtures/reader/sealed-complete/session.json");
    const SEALED_EMPTY: &str =
        include_str!("../../../tests/fixtures/reader/sealed-empty/session.json");
    const SEALED_PARTIAL: &str =
        include_str!("../../../tests/fixtures/reader/sealed-partial/session.json");
    const F2_012: &str =
        include_str!("../../../tests/fixtures/reader/f2-dangling-split-copy-ok/session.json");
    const COMPLETE_STOP: &str =
        include_str!("../../../tests/fixtures/reader/complete-stop/session.json");
    const BADKIND_SESS: &str = include_str!("../../../tests/fixtures/reader/badkind/session.json");
    const BADSEQ_SESS: &str = include_str!("../../../tests/fixtures/reader/badseq/session.json");
    const F3_BASELINE: &str =
        include_str!("../../../tests/fixtures/reader/f3-baseline/session.json");
    const PROVENANCE: &str = include_str!("../../../tests/fixtures/reader/provenance/session.json");
    const F6_DRIVER: &str =
        include_str!("../../../tests/fixtures/reader/f6-absent-driver/session.json");
    const BASELINE_WINDOW: &str =
        include_str!("../../../tests/fixtures/reader/baseline-after-window/session.json");

    fn parse(text: &str) -> Result<Session, ValidationError> {
        parse_session(text.as_bytes())
    }

    fn err_of(text: &str) -> (String, String) {
        let err = parse(text).unwrap_err();
        (err.what, err.message)
    }

    #[test]
    fn fixture_ev012_session_values() {
        let s = parse(EV012).unwrap();
        assert_eq!(s.session_id, "ev012-session");
        assert!(!s.has_boot_id);
        assert!(s.synthetic);
        assert_eq!(s.product_name, "memveil");
        assert_eq!(s.product_version, "0.1.0");
        assert!(!s.has_build);
        assert_eq!(s.env_mode, "unknown");
        assert_eq!(s.env_detection, "unverified");
        assert!(s.asserted_mode_present);
        assert!(!s.has_asserted_mode);
        assert_eq!(s.env_attestation, "not_performed");
        assert!(s.evidence.is_empty());
        assert_eq!(s.capture_mode, "synthetic");
        assert_eq!(s.window_start_ns, 1000000000);
        assert_eq!(s.window_end_ns, 4000000000);
        assert!(!s.has_baseline_start_ns);
        assert!(!s.has_filter_device);
        assert!(s.finalized);
        assert!(!s.has_checkpoint_generation);
        assert!(!s.has_integrity);
        assert!(s.has_end_reason);
        assert_eq!(s.end_reason, "duration");
        assert_eq!(s.devices.len(), 1);
        assert_eq!(s.devices[0].device_id, "dev-1");
        assert_eq!(s.devices[0].name, "testdev0");
        assert!(s.devices[0].driver_present);
        assert!(s.devices[0].has_driver);
        assert_eq!(s.devices[0].driver, "synthetic-test");
        assert_eq!(s.devices[0].identity_status, "resolved");
        assert!(!s.baseline_complete);
        assert_eq!(s.baseline_region_count, 0);
        assert!(s.baseline_regions.is_empty());
        assert_eq!(s.cap_bounce_attempts.status, "verified");
        assert_eq!(
            s.cap_bounce_attempts.reason,
            "Fictional successful state for analyzer tests; this session is synthetic."
        );
        assert_eq!(s.cap_bounce_attempts.hooks, ["swiotlb:swiotlb_bounced"]);
        assert!(s.cap_bounce_attempts.has_profile_id);
        assert_eq!(s.cap_bounce_attempts.profile_id, "synthetic-attempts-1");
        assert!(!s.cap_bounce_attempts.has_grade);
        assert_eq!(s.q_detail.status, "complete_for_scope");
        assert!(s.q_detail.has_loss_count);
        assert_eq!(s.q_detail.loss_count, 0);
        assert_eq!(s.q_detail.scope, "3 bounce_attempt events");
        assert!(s.q_detail.evidence_refs.is_empty());
        assert_eq!(s.q_correlation.status, "complete_for_scope");
        assert!(!s.has_corr_relations);
        assert_eq!(s.stop.outcome, "complete");
        assert_eq!(s.stop.reason, "");
        assert_eq!(s.stop.budget_ms, 5000);
        assert_eq!(s.stop.elapsed_ms, 120);
        assert!(s.stop.admission_closed);
        assert!(s.stop.quiescence_observed);
        assert_eq!(s.stop.drained_records, 3);
        assert!(s.stop.has_drain_completed);
        assert!(s.stop.drain_completed);
        assert!(s.stop.has_submit_after_drain);
        assert!(!s.stop.submit_after_drain);
        assert!(!s.stop.busy_at_drain);
        assert!(s.stop.counters_valid);
        assert!(!s.stop.has_checkpoint_failures);
        assert!(s.has_verdict);
        assert_eq!(s.verdict_name, "complete");
        assert_eq!(s.verdict_loss_bps, 0);
        assert_eq!(s.verdict_delivered, 3);
    }

    #[test]
    fn fixture_selection_retained_is_011_minimal() {
        let s = parse(SEL011).unwrap();
        assert_eq!(s.session_id, "selection-retained-session");
        assert_eq!(s.window_start_ns, 1000000000);
        assert_eq!(s.window_end_ns, 2500000000);
        assert_eq!(s.devices.len(), 1);
        assert!(s.baseline_complete);
        assert_eq!(s.baseline_region_count, 0);
        assert!(!s.has_verdict);
        assert!(!s.has_corr_relations);
        assert!(!s.stop.has_drain_completed);
        assert!(!s.stop.has_submit_after_drain);
    }

    #[test]
    fn fixture_compat_major_refuses_fast() {
        // The 1.0.0 version refuses at its key, before any missing-field
        // check could fire (this session also lacks a stop block).
        assert_eq!(
            err_of(COMPAT),
            ("schema_version".to_string(), "bad const".to_string())
        );
    }

    #[test]
    fn fixture_sealed_complete_carries_integrity() {
        let s = parse(SEALED).unwrap();
        assert_eq!(s.session_id, "attempts-3-session");
        assert!(s.has_integrity);
        assert_eq!(s.integrity.events_bytes, 1155);
        assert_eq!(s.integrity.line_count, 3);
        assert!(s.integrity.has_seq);
        assert_eq!(s.integrity.first_seq, 0);
        assert_eq!(s.integrity.last_seq, 2);
        assert_eq!(
            s.integrity.events_sha256,
            "8ae8e11a69f9a51ae5371c6264953d13029d5857d56519b23464c3c46a8438ef"
        );
        assert_eq!(s.integrity.kinds[0], 3);
        assert!(s.integrity.kinds[1..].iter().all(|k| *k == 0));
        assert!(s.finalized);
        assert!(s.has_verdict);
        assert_eq!(s.verdict_name, "complete");
    }

    #[test]
    fn fixture_sealed_empty_is_the_empty_stream() {
        let s = parse(SEALED_EMPTY).unwrap();
        assert!(s.has_integrity);
        assert_eq!(s.integrity.events_bytes, 0);
        assert_eq!(s.integrity.line_count, 0);
        assert!(!s.integrity.has_seq);
        assert_eq!(s.integrity.events_sha256, EMPTY_SHA256);
        assert!(s.integrity.kinds.iter().all(|k| *k == 0));
    }

    #[test]
    fn fixture_sealed_partial_matches_complete_bytes() {
        let s = parse(SEALED_PARTIAL).unwrap();
        assert!(s.has_integrity);
        assert_eq!(s.integrity.events_bytes, 1155);
        assert_eq!(s.integrity.line_count, 3);
        assert_eq!(s.stop.outcome, "partial");
        assert_eq!(s.stop.reason, "fixture predates stop evidence");
    }

    #[test]
    fn fixture_f2_012_carries_relations() {
        let s = parse(F2_012).unwrap();
        assert_eq!(s.session_id, "lifecycle-dangling-session");
        assert!(s.has_corr_relations);
        assert_eq!(s.q_correlation.status, "partial");
        assert!(!s.q_correlation.has_loss_count);
        assert_eq!(s.q_correlation.scope, "correlated lifecycle events");
        assert_eq!(s.q_corr_mapping.status, "complete_for_scope");
        assert!(s.q_corr_mapping.has_loss_count);
        assert_eq!(s.q_corr_mapping.scope, "mapping and release pairing");
        assert_eq!(s.q_corr_copy.status, "partial");
        assert!(!s.q_corr_copy.has_loss_count);
        assert_eq!(s.q_corr_sync.status, "complete_for_scope");
        assert_eq!(s.q_corr_sync.scope, "sync attribution");
        assert_eq!(s.q_baseline.status, "not_applicable");
    }

    #[test]
    fn fixture_complete_stop_parses() {
        let s = parse(COMPLETE_STOP).unwrap();
        assert!(s.has_verdict);
        assert_eq!(s.verdict_name, "complete");
        assert_eq!(s.stop.outcome, "complete");
        assert!(!s.has_integrity);
    }

    #[test]
    fn fixture_badkind_and_badseq_sessions_parse() {
        assert!(parse(BADKIND_SESS).is_ok());
        assert!(parse(BADSEQ_SESS).is_ok());
    }

    #[test]
    fn fixture_f3_baseline_region_span_overflows() {
        assert_eq!(
            err_of(F3_BASELINE),
            (
                "region_observation".to_string(),
                "span overflows".to_string()
            )
        );
        // With a valid offset the observation parses to exact values.
        let fixed =
            F3_BASELINE.replace("\"offset\": \"18446744073709551615\"", "\"offset\": \"0\"");
        let s = parse(&fixed).unwrap();
        assert_eq!(s.baseline_region_count, 1);
        assert_eq!(s.baseline_regions.len(), 1);
        let region = &s.baseline_regions[0];
        assert_eq!(region.region_id, "r-1");
        assert_eq!(region.state, "shared");
        assert_eq!(region.offset, 0);
        assert_eq!(region.length, 1);
        assert_eq!(region.address_space, "iova");
        assert_eq!(region.provenance, "synthetic-test");
        assert_eq!(region.generation, 1);
    }

    #[test]
    fn fixture_provenance_carries_evidence() {
        let s = parse(PROVENANCE).unwrap();
        assert_eq!(s.evidence.len(), 3);
        assert_eq!(s.evidence[0].item_type, "provenance");
        assert_eq!(s.evidence[0].source, "kernel.release");
        assert_eq!(s.evidence[0].interpretation, "7.0.0-test");
        assert_eq!(s.evidence[1].source, "bridge.sha256");
    }

    #[test]
    fn fixture_f6_driver_key_absent() {
        let s = parse(F6_DRIVER).unwrap();
        assert_eq!(s.devices.len(), 1);
        assert!(!s.devices[0].driver_present);
        assert!(!s.devices[0].has_driver);
    }

    #[test]
    fn fixture_baseline_after_window_refuses() {
        assert_eq!(
            err_of(BASELINE_WINDOW),
            ("window".to_string(), "baseline after start".to_string())
        );
    }

    #[test]
    fn session_versions_accept_four_and_refuse_the_rest() {
        for bad in ["0.1.0", "0.1.5", "0.2.0", "1.0.0", "1.0.1"] {
            let mutated = EV012.replacen(
                "\"schema_version\": \"0.1.3\"",
                &format!("\"schema_version\": \"{bad}\""),
                1,
            );
            assert_eq!(
                err_of(&mutated),
                ("schema_version".to_string(), "bad const".to_string()),
                "version {bad} must refuse"
            );
        }
    }

    #[test]
    fn integrity_is_required_only_by_014() {
        // A 0.1.4 session without integrity refuses ...
        let bumped = EV012.replacen(
            "\"schema_version\": \"0.1.3\"",
            "\"schema_version\": \"0.1.4\"",
            1,
        );
        assert_eq!(
            err_of(&bumped),
            (
                "capture.integrity".to_string(),
                "required only by schema 0.1.4".to_string()
            )
        );
        // ... as does a 0.1.3 session carrying integrity.
        let downgraded = SEALED.replacen(
            "\"schema_version\": \"0.1.4\"",
            "\"schema_version\": \"0.1.3\"",
            1,
        );
        assert_eq!(
            err_of(&downgraded),
            (
                "capture.integrity".to_string(),
                "required only by schema 0.1.4".to_string()
            )
        );
    }

    #[test]
    fn relations_need_schema_012() {
        let downgraded = F2_012.replacen(
            "\"schema_version\": \"0.1.2\"",
            "\"schema_version\": \"0.1.1\"",
            1,
        );
        assert_eq!(
            err_of(&downgraded),
            (
                "quality.correlation.relations".to_string(),
                "relations need schema 0.1.2".to_string()
            )
        );
    }

    #[test]
    fn verdict_and_drain_keys_need_schema_013() {
        let downgraded = EV012.replacen(
            "\"schema_version\": \"0.1.3\"",
            "\"schema_version\": \"0.1.2\"",
            1,
        );
        assert_eq!(
            err_of(&downgraded),
            (
                "verdict".to_string(),
                "verdict needs schema 0.1.3".to_string()
            )
        );
        // Drain keys alone (verdict stripped) refuse on their own rule.
        let no_verdict = EV012.replace(
            ",\n  \"verdict\": {\n    \"name\": \"complete\",\n    \"loss_ratio_bps\": \"0\",\n    \"delivered\": \"3\"\n  }",
            "",
        );
        assert!(parse(&no_verdict).is_ok());
        let downgraded = no_verdict.replacen(
            "\"schema_version\": \"0.1.3\"",
            "\"schema_version\": \"0.1.2\"",
            1,
        );
        assert_eq!(
            err_of(&downgraded),
            (
                "stop".to_string(),
                "drain keys need schema 0.1.3".to_string()
            )
        );
        // A 0.1.2 session gains drain keys only by refusing.
        let with_drain = F2_012.replace(
            "\"open_mappings\": \"0\"\n  }",
            "\"open_mappings\": \"0\",\n    \"drain_completed\": true\n  }",
        );
        assert_eq!(
            err_of(&with_drain),
            (
                "stop".to_string(),
                "drain keys need schema 0.1.3".to_string()
            )
        );
    }

    #[test]
    fn synthetic_must_match_capture_mode() {
        let flipped = EV012.replace("\"synthetic\": true", "\"synthetic\": false");
        assert_eq!(
            err_of(&flipped),
            (
                "synthetic".to_string(),
                "contradicts capture mode".to_string()
            )
        );
    }

    #[test]
    fn window_order_is_checked() {
        let swapped = EV012.replace(
            "\"start_ns\": \"1000000000\"",
            "\"start_ns\": \"4000000001\"",
        );
        assert_eq!(
            err_of(&swapped),
            ("window".to_string(), "start after end".to_string())
        );
        // An empty window is valid.
        let empty = EV012.replace(
            "\"start_ns\": \"1000000000\"",
            "\"start_ns\": \"4000000000\"",
        );
        assert!(parse(&empty).is_ok());
        // Baseline at or below the start is valid; above refuses.
        let at_start = EV012.replace(
            "\"end_ns\": \"4000000000\"",
            "\"end_ns\": \"4000000000\",\n      \"baseline_start_ns\": \"1000000000\"",
        );
        let s = parse(&at_start).unwrap();
        assert!(s.has_baseline_start_ns);
        assert_eq!(s.baseline_start_ns, 1000000000);
        let above = EV012.replace(
            "\"end_ns\": \"4000000000\"",
            "\"end_ns\": \"4000000000\",\n      \"baseline_start_ns\": \"1000000001\"",
        );
        assert_eq!(
            err_of(&above),
            ("window".to_string(), "baseline after start".to_string())
        );
    }

    #[test]
    fn duplicate_device_ids_refuse() {
        let entry = "{\n        \"device_id\": \"dev-1\",\n        \"name\": \"testdev0\",\n        \"driver\": \"synthetic-test\",\n        \"identity_status\": \"resolved\"\n      }";
        let doubled = EV012.replace(entry, &format!("{entry},\n      {entry}"));
        assert_eq!(
            err_of(&doubled),
            (
                "device_catalog.devices".to_string(),
                "duplicate device_id".to_string()
            )
        );
    }

    #[test]
    fn stop_reason_matches_outcome() {
        let with_reason = EV012.replace(
            "\"outcome\": \"complete\",\n    \"reason\": \"\"",
            "\"outcome\": \"complete\",\n    \"reason\": \"x\"",
        );
        assert_eq!(
            err_of(&with_reason),
            (
                "stop.reason".to_string(),
                "complete carries no reason".to_string()
            )
        );
        let no_reason = SEALED_PARTIAL.replace(
            "\"reason\": \"fixture predates stop evidence\"",
            "\"reason\": \"\"",
        );
        assert_eq!(
            err_of(&no_reason),
            (
                "stop.reason".to_string(),
                "partial needs a reason".to_string()
            )
        );
    }

    #[test]
    fn checkpoint_rules_follow_integrity() {
        // Checkpoint end without a generation refuses ...
        let ckpt = SEALED
            .replacen("\"finalized\": true", "\"finalized\": false", 1)
            .replacen(
                "\"end_reason\": \"duration\"",
                "\"end_reason\": \"checkpoint\"",
                1,
            );
        assert_eq!(
            err_of(&ckpt),
            (
                "capture.checkpoint_generation".to_string(),
                "required for checkpoint".to_string()
            )
        );
        // ... a generation completes the checkpoint ...
        let ckpt7 = ckpt.replacen(
            "\"finalized\": false",
            "\"finalized\": false,\n    \"checkpoint_generation\": \"7\"",
            1,
        );
        let s = parse(&ckpt7).unwrap();
        assert!(s.has_checkpoint_generation);
        assert_eq!(s.checkpoint_generation, 7);
        // ... but zero, finalization, a settled end reason, or a legacy
        // schema each invalidate it.
        let ckpt0 = ckpt.replacen(
            "\"finalized\": false",
            "\"finalized\": false,\n    \"checkpoint_generation\": \"0\"",
            1,
        );
        assert_eq!(
            err_of(&ckpt0),
            (
                "capture.checkpoint_generation".to_string(),
                "invalid checkpoint".to_string()
            )
        );
        let finalized = SEALED.replacen(
            "\"finalized\": true",
            "\"finalized\": true,\n    \"checkpoint_generation\": \"7\"",
            1,
        );
        assert_eq!(
            err_of(&finalized),
            (
                "capture.checkpoint_generation".to_string(),
                "invalid checkpoint".to_string()
            )
        );
        // Checkpoint failures need integrity too.
        let legacy_fail = EV012.replace(
            "\"open_mappings\": \"0\"",
            "\"open_mappings\": \"0\",\n    \"checkpoint_failures\": \"0\"",
        );
        assert_eq!(
            err_of(&legacy_fail),
            (
                "stop.checkpoint_failures".to_string(),
                "requires schema 0.1.4".to_string()
            )
        );
        let sealed_fail = SEALED.replace(
            "\"open_mappings\": \"0\"",
            "\"open_mappings\": \"0\",\n    \"checkpoint_failures\": \"2\"",
        );
        let s = parse(&sealed_fail).unwrap();
        assert!(s.stop.has_checkpoint_failures);
        assert_eq!(s.stop.checkpoint_failures, 2);
    }

    #[test]
    fn capability_membership_is_exact() {
        let unknown = EV012.replace(
            "    \"task_context\": {",
            "    \"zzz\": {},\n    \"task_context\": {",
        );
        assert_eq!(
            err_of(&unknown),
            ("capabilities".to_string(), "unknown capability".to_string())
        );
        let dup = EV012.replace(
            "    \"mapping_lifecycle\": {",
            "    \"bounce_attempts\": {\"status\": \"verified\", \"reason\": \"x\", \"hooks\": []},\n    \"mapping_lifecycle\": {",
        );
        assert_eq!(
            err_of(&dup),
            ("capabilities".to_string(), "duplicate member".to_string())
        );
        let dropped = EV012.replace(
            ",\n    \"task_context\": {\n      \"status\": \"unavailable\",\n      \"reason\": \"No observer context in this fixture.\",\n      \"hooks\": [],\n      \"profile_id\": null\n    }",
            "",
        );
        assert_eq!(
            err_of(&dropped),
            ("capabilities".to_string(), "missing field".to_string())
        );
        let bad_status = EV012.replace(
            "\"status\": \"verified\",\n      \"reason\": \"Fictional",
            "\"status\": \"bogus\",\n      \"reason\": \"Fictional",
        );
        assert_eq!(
            err_of(&bad_status),
            ("capability.status".to_string(), "bad enum".to_string())
        );
        let graded = EV012.replace(
            "\"profile_id\": \"synthetic-attempts-1\"\n    },\n    \"mapping_lifecycle\"",
            "\"profile_id\": \"synthetic-attempts-1\",\n      \"grade\": \"validated\"\n    },\n    \"mapping_lifecycle\"",
        );
        let s = parse(&graded).unwrap();
        assert!(s.cap_bounce_attempts.has_grade);
        assert_eq!(s.cap_bounce_attempts.grade, "validated");
        let bad_grade = graded.replace("\"grade\": \"validated\"", "\"grade\": \"bogus\"");
        assert_eq!(
            err_of(&bad_grade),
            ("capability.grade".to_string(), "bad enum".to_string())
        );
    }

    #[test]
    fn quality_membership_is_exact() {
        let unknown = EV012.replace(
            "    \"terminal\": {",
            "    \"zzz\": {},\n    \"terminal\": {",
        );
        assert_eq!(
            err_of(&unknown),
            ("quality".to_string(), "unknown quality channel".to_string())
        );
        let dropped = EV012.replace(
            ",\n    \"terminal\": {\n      \"status\": \"complete_for_scope\",\n      \"loss_count\": \"0\",\n      \"scope\": \"authored fixture finalization\",\n      \"reason\": \"Authored fixture: finalized.\"\n    }",
            "",
        );
        assert_eq!(
            err_of(&dropped),
            ("quality".to_string(), "missing field".to_string())
        );
    }

    #[test]
    fn relation_membership_is_exact() {
        let unknown = F2_012.replace(
            "        \"sync_attribution\": {",
            "        \"zzz\": {},\n        \"sync_attribution\": {",
        );
        assert_eq!(
            err_of(&unknown),
            (
                "quality.correlation.relations".to_string(),
                "unknown relation class".to_string()
            )
        );
        let dropped = F2_012.replace(
            ",\n        \"sync_attribution\": {\n          \"status\": \"complete_for_scope\",\n          \"loss_count\": \"0\",\n          \"scope\": \"sync attribution\",\n          \"reason\": \"Authored fixture: sync proof holds.\",\n          \"evidence_refs\": []\n        }",
            "",
        );
        assert_eq!(
            err_of(&dropped),
            (
                "quality.correlation.relations".to_string(),
                "missing field".to_string()
            )
        );
    }

    #[test]
    fn list_caps_are_exact() {
        let refs: Vec<String> = (0..33).map(|i| format!("\"r{i}\"")).collect();
        let many_refs = EV012.replace(
            "\"scope\": \"3 bounce_attempt events\",\n      \"reason\": \"Authored fixture: no loss.\"",
            &format!(
                "\"scope\": \"3 bounce_attempt events\",\n      \"reason\": \"Authored fixture: no loss.\",\n      \"evidence_refs\": [{}]",
                refs.join(", ")
            ),
        );
        assert_eq!(
            err_of(&many_refs),
            (
                "quality.detail.evidence_refs".to_string(),
                "too many items".to_string()
            )
        );
        let hooks: Vec<String> = (0..33).map(|i| format!("\"h{i}\"")).collect();
        let many_hooks = EV012.replace(
            "\"hooks\": [\n        \"swiotlb:swiotlb_bounced\"\n      ]",
            &format!("\"hooks\": [{}]", hooks.join(", ")),
        );
        assert_eq!(
            err_of(&many_hooks),
            ("capability.hooks".to_string(), "too many items".to_string())
        );
    }

    #[test]
    fn integrity_self_checks_match() {
        assert_eq!(
            err_of(&SEALED.replace("\"bounce_attempt\": \"3\"", "\"bounce_attempt\": \"2\"")),
            (
                "capture.integrity.kinds".to_string(),
                "sum differs from line_count".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("        \"marker\": \"0\",\n", "")),
            (
                "capture.integrity.kinds".to_string(),
                "missing kind".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace(
                "\"marker\": \"0\",",
                "\"marker\": \"0\",\n        \"marker\": \"0\","
            )),
            (
                "capture.integrity.kinds".to_string(),
                "unknown or duplicate kind".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace(
                "\"marker\": \"0\",",
                "\"marker\": \"0\",\n        \"zzz\": \"0\","
            )),
            (
                "capture.integrity.kinds".to_string(),
                "unknown or duplicate kind".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"first_seq\": \"0\"", "\"first_seq\": null")),
            (
                "capture.integrity".to_string(),
                "missing field or mismatched sequence bounds".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("      \"algorithm\": \"sha256\",\n", "")),
            (
                "capture.integrity".to_string(),
                "missing field or mismatched sequence bounds".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"algorithm\": \"sha256\"", "\"algorithm\": \"sha512\"")),
            (
                "capture.integrity.algorithm".to_string(),
                "unsupported algorithm".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"bounce_attempt\": \"3\"", "\"bounce_attempt\": 3")),
            (
                "capture.integrity.kinds".to_string(),
                "expected byte 34".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"first_seq\": \"0\"", "\"first_seq\": \"1\"")),
            (
                "capture.integrity".to_string(),
                "invalid sequence bounds or byte count".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"last_seq\": \"2\"", "\"last_seq\": \"5\"")),
            (
                "capture.integrity".to_string(),
                "invalid sequence bounds or byte count".to_string()
            )
        );
        assert_eq!(
            err_of(&SEALED.replace("\"events_bytes\": \"1155\"", "\"events_bytes\": \"2\"")),
            (
                "capture.integrity".to_string(),
                "invalid sequence bounds or byte count".to_string()
            )
        );
        let upper = SEALED.replace(
            "8ae8e11a69f9a51ae5371c6264953d13029d5857d56519b23464c3c46a8438ef",
            "8AE8E11A69F9A51AE5371C6264953D13029D5857D56519B23464C3C46A8438EF",
        );
        assert_eq!(
            err_of(&upper),
            (
                "capture.integrity.events_sha256".to_string(),
                "digest must be lowercase hex".to_string()
            )
        );
        let short = SEALED.replace(
            "8ae8e11a69f9a51ae5371c6264953d13029d5857d56519b23464c3c46a8438ef",
            "8ae8e11a",
        );
        assert_eq!(
            err_of(&short),
            (
                "capture.integrity.events_sha256".to_string(),
                "digest length".to_string()
            )
        );
        let with_seq = SEALED_EMPTY
            .replace("\"first_seq\": null", "\"first_seq\": \"0\"")
            .replace("\"last_seq\": null", "\"last_seq\": \"0\"");
        assert_eq!(
            err_of(&with_seq),
            (
                "capture.integrity".to_string(),
                "invalid empty stream".to_string()
            )
        );
    }

    #[test]
    fn verdict_basis_points_cap_at_10000() {
        let over = EV012.replace("\"loss_ratio_bps\": \"0\"", "\"loss_ratio_bps\": \"10001\"");
        assert_eq!(
            err_of(&over),
            (
                "verdict.loss_ratio_bps".to_string(),
                "out of range".to_string()
            )
        );
        let max = EV012.replace("\"loss_ratio_bps\": \"0\"", "\"loss_ratio_bps\": \"10000\"");
        assert_eq!(parse(&max).unwrap().verdict_loss_bps, 10000);
    }

    #[test]
    fn nullable_presence_matrices_match() {
        // Driver: value, null, absent.
        assert!(
            parse(&EV012.replace("\"driver\": \"synthetic-test\"", "\"driver\": null"))
                .unwrap()
                .devices[0]
                .driver_present
        );
        assert!(
            !parse(&EV012.replace("\"driver\": \"synthetic-test\"", "\"driver\": null"))
                .unwrap()
                .devices[0]
                .has_driver
        );
        let no_driver = EV012.replace(",\n        \"driver\": \"synthetic-test\"", "");
        let s = parse(&no_driver).unwrap();
        assert!(!s.devices[0].driver_present);
        assert!(!s.devices[0].has_driver);
        // Asserted mode: null, value, absent, bad enum.
        let asserted = EV012.replace("\"asserted_mode\": null", "\"asserted_mode\": \"sev_snp\"");
        let s = parse(&asserted).unwrap();
        assert!(s.asserted_mode_present);
        assert!(s.has_asserted_mode);
        assert_eq!(s.asserted_mode, "sev_snp");
        let no_asserted = EV012.replace("    \"asserted_mode\": null,\n", "");
        assert!(!parse(&no_asserted).unwrap().asserted_mode_present);
        assert_eq!(
            err_of(&EV012.replace("\"asserted_mode\": null", "\"asserted_mode\": \"bogus\"")),
            (
                "environment.asserted_mode".to_string(),
                "bad enum".to_string()
            )
        );
        // Build: null, empty, absent.
        let empty_build = EV012.replace("\"build\": null", "\"build\": \"\"");
        let s = parse(&empty_build).unwrap();
        assert!(s.has_build);
        assert_eq!(s.build, "");
        let no_build = EV012.replace(",\n    \"build\": null", "");
        assert!(!parse(&no_build).unwrap().has_build);
        assert_eq!(
            err_of(&EV012.replace(
                "\"build\": null",
                &format!("\"build\": \"{}\"", "x".repeat(129))
            )),
            ("product.build".to_string(), "too long".to_string())
        );
        // Boot: present, null, bad id.
        let boot = EV012.replace(
            "\"session_id\": \"ev012-session\",",
            "\"session_id\": \"ev012-session\",\n  \"boot_id\": \"b1\",",
        );
        let s = parse(&boot).unwrap();
        assert!(s.has_boot_id);
        assert_eq!(s.boot_id, "b1");
        assert_eq!(
            err_of(&boot.replace("\"boot_id\": \"b1\"", "\"boot_id\": null")),
            ("boot_id".to_string(), "expected byte 34".to_string())
        );
        assert_eq!(
            err_of(&boot.replace("\"boot_id\": \"b1\"", "\"boot_id\": \"bad id\"")).0,
            "boot_id".to_string()
        );
    }

    #[test]
    fn filters_end_reason_and_env_enums_match() {
        let filtered = EV012.replace("\"device\": null", "\"device\": \"dev-9\"");
        let s = parse(&filtered).unwrap();
        assert!(s.has_filter_device);
        assert_eq!(s.filter_device, "dev-9");
        assert_eq!(
            err_of(&EV012.replace("\"device\": null", "\"device\": \"\"")),
            ("filters.device".to_string(), "too short".to_string())
        );
        assert!(
            !parse(&EV012.replace("\"end_reason\": \"duration\"", "\"end_reason\": null"))
                .unwrap()
                .has_end_reason
        );
        assert_eq!(
            err_of(&EV012.replace("\"end_reason\": \"duration\"", "\"end_reason\": \"bogus\"")),
            ("capture.end_reason".to_string(), "bad enum".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace("\"mode\": \"unknown\"", "\"mode\": \"bogus\"")),
            ("environment.mode".to_string(), "bad enum".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace("\"detection\": \"unverified\"", "\"detection\": \"bogus\"")),
            ("environment.detection".to_string(), "bad enum".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace(
                "\"attestation\": \"not_performed\"",
                "\"attestation\": \"bogus\""
            )),
            (
                "environment.attestation".to_string(),
                "bad enum".to_string()
            )
        );
        assert_eq!(
            err_of(&EV012.replace(
                "\"identity_status\": \"resolved\"",
                "\"identity_status\": \"bogus\""
            )),
            ("device.identity_status".to_string(), "bad enum".to_string())
        );
    }

    #[test]
    fn loss_count_forms_match() {
        // Detail carries "0"; aggregate carries null in this fixture.
        let s = parse(EV012).unwrap();
        assert!(s.q_detail.has_loss_count);
        assert!(!s.q_aggregate.has_loss_count);
        assert_eq!(
            err_of(&EV012.replacen("\"loss_count\": \"0\"", "\"loss_count\": 0", 1)),
            (
                "quality.detail.loss_count".to_string(),
                "expected byte 34".to_string()
            )
        );
    }

    #[test]
    fn region_observation_errors_match() {
        let fixed =
            F3_BASELINE.replace("\"offset\": \"18446744073709551615\"", "\"offset\": \"0\"");
        // Generation key absent defaults to 1.
        assert_eq!(parse(&fixed).unwrap().baseline_regions[0].generation, 1);
        let with_gen = fixed.replace(
            "\"provenance\": \"synthetic-test\"",
            "\"provenance\": \"synthetic-test\",\n      \"generation\": 2",
        );
        assert_eq!(parse(&with_gen).unwrap().baseline_regions[0].generation, 2);
        let gen0 = fixed.replace(
            "\"provenance\": \"synthetic-test\"",
            "\"provenance\": \"synthetic-test\",\n      \"generation\": 0",
        );
        assert_eq!(
            err_of(&gen0),
            (
                "region_observation.generation".to_string(),
                "must be positive".to_string()
            )
        );
        assert_eq!(
            err_of(&fixed.replace("\"state\": \"shared\"", "\"state\": \"bogus\"")),
            ("region_state".to_string(), "bad enum".to_string())
        );
        assert_eq!(
            err_of(&fixed.replace(
                "\"address_space\": \"iova\"",
                "\"address_space\": \"bogus\""
            )),
            ("address_space".to_string(), "bad enum".to_string())
        );
    }

    #[test]
    fn corpus_walk_matches_pinned_verdicts() {
        // Every reader fixture parses, except the pinned per-line and
        // per-session refusals below. Each pin is verified against the
        // Mojo parser: same verdict, same reason class.
        use crate::model::event::parse_event;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../tests/fixtures/reader");
        let rejects: &[(&str, usize, &str, &str)] = &[
            (
                "adv-bad-seq-int",
                0,
                "event.seq",
                "ValidationError(what=u64, message=leading zero)",
            ),
            ("adv-bad-utf8", 0, "data", "invalid utf-8 in string"),
            ("adv-depth-64", 0, "event", "expected byte 123"),
            ("adv-depth-65", 0, "event", "expected byte 123"),
            ("adv-nul", 0, "data", "control in string"),
            ("adv-unknown-field", 0, "event", "unknown event field"),
            ("badkind", 0, "kind", "unknown event kind"),
            ("corrupt-tail", 2, "event", "expected byte 34"),
            ("f3-span-sync", 1, "sync_request", "span overflows"),
            (
                "f3-span-transition",
                1,
                "transition_result",
                "span overflows",
            ),
            ("f4-definitive-dupkey", 3, "seq", "duplicate"),
            ("f4-definitive-version", 3, "schema_version", "bad const"),
            ("f4-nocolon-dupkey", 3, "event", "unexpected end of input"),
            ("f4-nocolon-unknown", 3, "event", "unexpected end of input"),
            ("f4-truncated-nested", 3, "source", "expected byte 34"),
            ("f4-truncated-primitive", 3, "event.seq", "expected byte 34"),
            ("f4-truncated-scope-device", 5, "data", "bad boolean"),
            ("f4-truncated-scope-profile", 5, "data", "bad boolean"),
            ("interior-corrupt", 1, "event", "expected byte 34"),
            ("partial-tail", 2, "event", "unexpected end of input"),
            ("size-ok", 0, "event", "expected byte 123"),
            ("size-over", 0, "event", "expected byte 123"),
            ("unsanitized-error", 0, "event", "unknown event field"),
        ];
        let session_rejects: &[(&str, &str, &str)] = &[
            ("compat-major", "schema_version", "bad const"),
            ("baseline-after-window", "window", "baseline after start"),
            ("f3-baseline", "region_observation", "span overflows"),
            (
                "f2-contradictory-provenance",
                "synthetic",
                "contradicts capture mode",
            ),
            ("unsanitized-session", "session", "unknown session field"),
        ];
        let mut entries: Vec<PathBuf> = std::fs::read_dir(&root)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        entries.sort();
        assert!(!entries.is_empty());
        for dir in entries {
            let name = dir.file_name().unwrap().to_str().unwrap().to_string();
            let session_path = dir.join("session.json");
            if session_path.exists() {
                let bytes = std::fs::read(&session_path).unwrap();
                let verdict = parse_session(&bytes);
                match session_rejects.iter().find(|r| r.0 == name) {
                    Some(pin) => {
                        let err = verdict.unwrap_err();
                        assert_eq!(err.what, pin.1, "{name}/session.json what");
                        assert_eq!(err.message, pin.2, "{name}/session.json message");
                    }
                    None => {
                        verdict
                            .unwrap_or_else(|err| panic!("{name}/session.json must parse: {err}"));
                    }
                }
            }
            let events_path = dir.join("events.ndjson");
            if !events_path.exists() {
                continue;
            }
            let bytes = std::fs::read(&events_path).unwrap();
            for (index, line) in bytes
                .split(|b| *b == b'\n')
                .filter(|l| !l.is_empty())
                .enumerate()
            {
                let verdict = parse_event(line);
                match rejects.iter().find(|r| r.0 == name && r.1 == index) {
                    Some(pin) => {
                        let err = verdict.unwrap_err();
                        assert_eq!(err.what, pin.2, "{name}:{index} what");
                        assert_eq!(err.message, pin.3, "{name}:{index} message");
                    }
                    None => {
                        verdict.unwrap_or_else(|err| panic!("{name}:{index} must parse: {err}"));
                    }
                }
            }
        }
    }

    #[test]
    fn product_session_keys_and_trailing_match() {
        assert_eq!(
            err_of(&EV012.replace("\"name\": \"memveil\"", "\"name\": \"other\"")),
            ("product.name".to_string(), "bad const".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace("\"version\": \"0.1.0\"", "\"version\": \"\"")),
            ("product.version".to_string(), "too short".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace(
                "\"session_id\": \"ev012-session\",",
                "\"session_id\": \"ev012-session\",\n  \"session_id\": \"dup\","
            )),
            ("session_id".to_string(), "duplicate".to_string())
        );
        assert_eq!(
            err_of(&EV012.replace(
                "\"session_id\": \"ev012-session\",",
                "\"session_id\": \"ev012-session\",\n  \"zzz\": 1,"
            )),
            ("session".to_string(), "unknown session field".to_string())
        );
        assert_eq!(
            err_of("{}"),
            ("session".to_string(), "missing field".to_string())
        );
        assert_eq!(
            err_of(&format!("{EV012} x")),
            ("session".to_string(), "trailing data".to_string())
        );
    }
}
