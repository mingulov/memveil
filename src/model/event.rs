// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed normalized event: one events.ndjson line.
//!
//! The parser validates a single line against the frozen event schema:
//! record version, opaque IDs, canonical u64 strings, source and observer
//! bounds, and the kind-specific payload. Unknown kinds, unknown fields,
//! and duplicated keys are refused. Cross-record rules (session match,
//! strictly increasing sequence, window membership) belong to the capture
//! reader, not to this per-line parse.
//!
//! Key order is free: the `data` object is captured as a source span on
//! first sight and parsed after the kind is known. JSON integers are
//! accepted within the int64 domain; schema maxima for observer cpu,
//! pid, and tgid are enforced exactly.

use super::scan::{
    Scanner, expect_colon, object_is_empty, object_next, parse_id_field, parse_nullable_id,
    parse_nullable_int, parse_nullable_u64, parse_u64_field,
};
use super::validate::{ValidationError, check_bounded_text, checked_add};

/// Current event-line schema version.
pub const EVENT_SCHEMA_VERSION: &str = "0.1.2";
/// Previous event-line schema version, still accepted per record.
pub const EVENT_SCHEMA_VERSION_PREV: &str = "0.1.1";
const MAX_CPU: i64 = 1048575;
const MAX_PID: i64 = 4194304;

/// One bounce-attempt observation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BounceAttempt {
    /// Interned device token.
    pub device_id: String,
    /// Requested transfer length in bytes.
    pub requested_bytes: u64,
    /// True when the bounce was forced.
    pub forced: bool,
    /// Session-local operation token.
    pub operation_id: String,
}

/// One mapping call result.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MapResult {
    /// Session-local operation token.
    pub operation_id: String,
    /// True when the call established a mapping.
    pub success: bool,
    /// True when a mapping token was reported.
    pub has_mapping_id: bool,
    /// The mapping token; empty unless `has_mapping_id`.
    pub mapping_id: String,
    /// True when a return code was reported.
    pub has_return_code: bool,
    /// The return code; zero unless `has_return_code`.
    pub return_code: i64,
    /// True when a mapped length was reported.
    pub has_mapped_bytes: bool,
    /// The mapped length; zero unless `has_mapped_bytes`.
    pub mapped_bytes: u64,
    /// True when a wire generation was reported.
    pub has_wire_generation: bool,
    /// The wire generation; zero unless `has_wire_generation`.
    pub wire_generation: u64,
    /// True when a wire identity was reported.
    pub has_wire_identity: bool,
    /// The wire identity; empty unless `has_wire_identity`.
    pub wire_identity: String,
}

/// One mapping release.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Unmap {
    /// True when a mapping token was reported.
    pub has_mapping_id: bool,
    /// The mapping token; empty unless `has_mapping_id`.
    pub mapping_id: String,
    /// True when a wire generation was reported.
    pub has_wire_generation: bool,
    /// The wire generation; zero unless `has_wire_generation`.
    pub wire_generation: u64,
    /// True when a wire identity was reported.
    pub has_wire_identity: bool,
    /// The wire identity; empty unless `has_wire_identity`.
    pub wire_identity: String,
}

/// One executed bounce copy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CopyPayload {
    /// Session-local operation token.
    pub operation_id: String,
    /// True when a mapping token was reported.
    pub has_mapping_id: bool,
    /// The mapping token; empty unless `has_mapping_id`.
    pub mapping_id: String,
    /// Copy direction enum.
    pub direction: String,
    /// Copied length in bytes.
    pub bytes: u64,
    /// True only for a proven pool-private 0.1.2 copy.
    pub pool_private: bool,
    /// True only for a proven past-allocation 0.1.2 copy.
    pub offset_past_allocation: bool,
}

/// One synchronization request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncRequest {
    /// Session-local operation token.
    pub operation_id: String,
    /// True when a mapping token was reported.
    pub has_mapping_id: bool,
    /// The mapping token; empty unless `has_mapping_id`.
    pub mapping_id: String,
    /// True when the offset is known.
    pub has_offset: bool,
    /// The sync offset; zero unless `has_offset`.
    pub offset: u64,
    /// The sync length in bytes.
    pub length: u64,
}

/// One region-transition result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionResult {
    /// Opaque session-local region identity.
    pub region_id: String,
    /// Requested state enum.
    pub requested_state: String,
    /// True when the transition applied.
    pub success: bool,
    /// True when a return code was reported.
    pub has_return_code: bool,
    /// The return code; zero unless `has_return_code`.
    pub return_code: i64,
    /// Offset relative to the region identity.
    pub offset: u64,
    /// Interval length in bytes.
    pub length: u64,
    /// True when an address space was reported.
    pub has_address_space: bool,
    /// The address space; empty unless `has_address_space`.
    pub address_space: String,
    /// True when a resolution was reported.
    pub has_resolution: bool,
    /// The resolution; empty unless `has_resolution`.
    pub resolution: String,
    /// Mapping generation; starts at 1.
    pub generation: i64,
}

impl Default for TransitionResult {
    fn default() -> Self {
        Self {
            region_id: String::new(),
            requested_state: String::new(),
            success: false,
            has_return_code: false,
            return_code: 0,
            offset: 0,
            length: 0,
            has_address_space: false,
            address_space: String::new(),
            has_resolution: false,
            resolution: String::new(),
            generation: 1,
        }
    }
}

/// One pool utilization sample.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PoolSample {
    /// Opaque pool token.
    pub pool_id: String,
    /// True when a used count was reported.
    pub has_used: bool,
    /// Used bytes; zero unless `has_used`.
    pub used_bytes: u64,
    /// True when a capacity was reported.
    pub has_capacity: bool,
    /// Capacity bytes; zero unless `has_capacity`.
    pub capacity_bytes: u64,
    /// Unit enum.
    pub unit: String,
    /// Allocator token; empty unless reported.
    pub allocator: String,
    /// True when a unit size was reported.
    pub has_unit_bytes: bool,
    /// Unit size; zero unless `has_unit_bytes`.
    pub unit_bytes: u64,
    /// True when a high-water mark was reported.
    pub has_hiwater: bool,
    /// High-water bytes; zero unless `has_hiwater`.
    pub hiwater_bytes: u64,
    /// Absence reason enum; empty unless reported.
    pub reason: String,
}

/// One producer-attested loss window.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Gap {
    /// Quality channel enum.
    pub channel: String,
    /// True when a lost count was reported.
    pub has_lost_count: bool,
    /// Lost records; zero unless `has_lost_count`.
    pub lost_count: u64,
    /// Loss reason text.
    pub reason: String,
    /// Window start in nanoseconds.
    pub window_start_ns: u64,
    /// Window end in nanoseconds.
    pub window_end_ns: u64,
}

/// One operator annotation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Marker {
    /// Annotation text.
    pub text: String,
}

/// One monotonic counter reading.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CounterSnapshot {
    /// Counter identity.
    pub counter_id: String,
    /// Counter epoch.
    pub epoch: u64,
    /// True when a scope device was reported.
    pub has_scope_device: bool,
    /// Scope device token; empty unless `has_scope_device`.
    pub scope_device_id: String,
    /// Scope profile identity.
    pub scope_profile_id: String,
    /// Counter value.
    pub value: u64,
    /// Value unit.
    pub unit: String,
}

/// One validated normalized event.
///
/// Only the kind-matching payload is populated; the rest keep their
/// defaults.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// Session the line belongs to.
    pub session_id: String,
    /// Line sequence number.
    pub seq: u64,
    /// Event timestamp in nanoseconds.
    pub ts_ns: u64,
    /// Event kind enum.
    pub kind: String,
    /// Producer hook identity.
    pub source_hook: String,
    /// Producer backend identity.
    pub source_backend: String,
    /// Semantic profile identity.
    pub source_profile_id: String,
    /// Measurement enum.
    pub source_measurement: String,
    /// Correlation enum.
    pub source_correlation: String,
    /// True when an observer block was present.
    pub has_observer: bool,
    /// True when a CPU was reported.
    pub has_cpu: bool,
    /// Observing CPU; zero unless `has_cpu`.
    pub cpu: i64,
    /// True when a PID was reported.
    pub has_pid: bool,
    /// Observing PID; zero unless `has_pid`.
    pub pid: i64,
    /// True when a TGID was reported.
    pub has_tgid: bool,
    /// Observing TGID; zero unless `has_tgid`.
    pub tgid: i64,
    /// True when a command name was reported.
    pub has_comm: bool,
    /// Command name; empty unless `has_comm`.
    pub comm: String,
    /// True when a cgroup token was reported.
    pub has_cgroup_id: bool,
    /// Cgroup token; empty unless `has_cgroup_id`.
    pub cgroup_id: String,
    /// Bounce-attempt payload.
    pub bounce: BounceAttempt,
    /// Mapping-result payload.
    pub map_result: MapResult,
    /// Unmap payload.
    pub unmap: Unmap,
    /// Copy payload.
    pub copy: CopyPayload,
    /// Sync-request payload.
    pub sync: SyncRequest,
    /// Transition-result payload.
    pub transition: TransitionResult,
    /// Pool-sample payload.
    pub pool: PoolSample,
    /// Gap payload.
    pub gap: Gap,
    /// Marker payload.
    pub marker: Marker,
    /// Counter-snapshot payload.
    pub snapshot: CounterSnapshot,
}

fn check_measurement(value: &str) -> Result<(), ValidationError> {
    if value == "observed" || value == "derived" || value == "estimated" {
        return Ok(());
    }
    Err(ValidationError::new("source.measurement", "bad enum"))
}

fn check_correlation(value: &str) -> Result<(), ValidationError> {
    if value == "direct" || value == "unpaired" {
        return Ok(());
    }
    Err(ValidationError::new("source.correlation", "bad enum"))
}

fn check_kind(value: &str) -> Result<(), ValidationError> {
    if value == "bounce_attempt"
        || value == "map_result"
        || value == "unmap"
        || value == "copy"
        || value == "sync_request"
        || value == "transition_result"
        || value == "pool_sample"
        || value == "gap"
        || value == "marker"
        || value == "counter_snapshot"
    {
        return Ok(());
    }
    Err(ValidationError::new("kind", "unknown event kind"))
}

fn check_wire_identity_map(value: &str) -> Result<(), ValidationError> {
    if value == "known" || value == "unassigned" {
        return Ok(());
    }
    Err(ValidationError::new("map_result.wire_identity", "bad enum"))
}

fn check_wire_identity_unmap(value: &str) -> Result<(), ValidationError> {
    if value == "known" || value == "miss" {
        return Ok(());
    }
    Err(ValidationError::new("unmap.wire_identity", "bad enum"))
}

fn parse_bounce(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("bounce_attempt")?;
    let mut has_device = false;
    let mut has_bytes = false;
    let mut has_forced = false;
    let mut has_op = false;
    if !object_is_empty(scan, "bounce_attempt")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("bounce_attempt")?;
            expect_colon(scan, "bounce_attempt")?;
            if key == "device_id" {
                if has_device {
                    return Err(ValidationError::new("device_id", "duplicate"));
                }
                out.bounce.device_id = parse_id_field(scan, "bounce.device_id")?;
                has_device = true;
            } else if key == "requested_bytes" {
                if has_bytes {
                    return Err(ValidationError::new("requested_bytes", "duplicate"));
                }
                out.bounce.requested_bytes = parse_u64_field(scan, "bounce.requested_bytes")?;
                has_bytes = true;
            } else if key == "forced" {
                if has_forced {
                    return Err(ValidationError::new("forced", "duplicate"));
                }
                scan.skip_ws();
                out.bounce.forced = scan.parse_bool("bounce_attempt")?;
                has_forced = true;
            } else if key == "operation_id" {
                if has_op {
                    return Err(ValidationError::new("operation_id", "duplicate"));
                }
                out.bounce.operation_id = parse_id_field(scan, "bounce.operation_id")?;
                has_op = true;
            } else {
                return Err(ValidationError::new(
                    "bounce_attempt",
                    "unknown bounce_attempt field",
                ));
            }
            if !object_next(scan, "bounce_attempt")? {
                break;
            }
        }
    }
    scan.end_object("bounce_attempt")?;
    if !has_device || !has_bytes || !has_forced || !has_op {
        return Err(ValidationError::new("bounce_attempt", "missing field"));
    }
    Ok(())
}

fn parse_map_result(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("map_result")?;
    let mut has_op = false;
    let mut has_success = false;
    let mut has_mapping = false;
    let mut has_code = false;
    let mut has_bytes = false;
    let mut has_wgen = false;
    let mut has_wid = false;
    if !object_is_empty(scan, "map_result")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("map_result")?;
            expect_colon(scan, "map_result")?;
            if key == "operation_id" {
                if has_op {
                    return Err(ValidationError::new("operation_id", "duplicate"));
                }
                out.map_result.operation_id = parse_id_field(scan, "map_result.operation_id")?;
                has_op = true;
            } else if key == "success" {
                if has_success {
                    return Err(ValidationError::new("success", "duplicate"));
                }
                scan.skip_ws();
                out.map_result.success = scan.parse_bool("map_result")?;
                has_success = true;
            } else if key == "mapping_id" {
                if has_mapping {
                    return Err(ValidationError::new("mapping_id", "duplicate"));
                }
                let m = parse_nullable_id(scan, "map_result.mapping_id")?;
                if m.has {
                    out.map_result.mapping_id = m.value;
                    out.map_result.has_mapping_id = true;
                }
                has_mapping = true;
            } else if key == "return_code" {
                if has_code {
                    return Err(ValidationError::new("return_code", "duplicate"));
                }
                let m = parse_nullable_int(scan, "map_result")?;
                if m.has {
                    out.map_result.return_code = m.value;
                    out.map_result.has_return_code = true;
                }
                has_code = true;
            } else if key == "mapped_bytes" {
                if has_bytes {
                    return Err(ValidationError::new("mapped_bytes", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "map_result")?;
                if m.has {
                    out.map_result.mapped_bytes = m.value;
                    out.map_result.has_mapped_bytes = true;
                }
                has_bytes = true;
            } else if key == "wire_generation" {
                if has_wgen {
                    return Err(ValidationError::new("wire_generation", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "map_result")?;
                if m.has {
                    out.map_result.wire_generation = m.value;
                    out.map_result.has_wire_generation = true;
                }
                has_wgen = true;
            } else if key == "wire_identity" {
                if has_wid {
                    return Err(ValidationError::new("wire_identity", "duplicate"));
                }
                let m = parse_nullable_id(scan, "map_result.wire_identity")?;
                if m.has {
                    check_wire_identity_map(&m.value)?;
                    out.map_result.wire_identity = m.value;
                    out.map_result.has_wire_identity = true;
                }
                has_wid = true;
            } else {
                return Err(ValidationError::new(
                    "map_result",
                    "unknown map_result field",
                ));
            }
            if !object_next(scan, "map_result")? {
                break;
            }
        }
    }
    scan.end_object("map_result")?;
    if !has_op || !has_success || !has_mapping || !has_code || !has_bytes || !has_wgen || !has_wid {
        return Err(ValidationError::new("map_result", "missing field"));
    }
    let seen_gen = out.map_result.has_wire_generation;
    let seen_ident = out.map_result.has_wire_identity;
    if seen_gen != seen_ident
        && (out.map_result.success || seen_ident || out.map_result.wire_generation != 0)
    {
        return Err(ValidationError::new(
            "map_result",
            "wire generation/identity mismatch",
        ));
    }
    if out.map_result.success {
        if !out.map_result.has_mapping_id
            && !(seen_gen && seen_ident && out.map_result.wire_identity == "unassigned")
        {
            return Err(ValidationError::new(
                "map_result",
                "success lacks mapping_id",
            ));
        }
        if !out.map_result.has_mapped_bytes {
            return Err(ValidationError::new(
                "map_result",
                "success lacks mapped_bytes",
            ));
        }
    } else {
        if out.map_result.has_mapping_id {
            return Err(ValidationError::new(
                "map_result",
                "failure carries mapping_id",
            ));
        }
        if out.map_result.has_mapped_bytes {
            return Err(ValidationError::new(
                "map_result",
                "failure carries mapped_bytes",
            ));
        }
        if seen_ident {
            return Err(ValidationError::new(
                "map_result",
                "failure carries wire_identity",
            ));
        }
    }
    Ok(())
}

fn parse_unmap(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("unmap")?;
    let mut has_mapping = false;
    let mut has_wgen = false;
    let mut has_wid = false;
    if !object_is_empty(scan, "unmap")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("unmap")?;
            expect_colon(scan, "unmap")?;
            if key == "mapping_id" {
                if has_mapping {
                    return Err(ValidationError::new("mapping_id", "duplicate"));
                }
                let m = parse_nullable_id(scan, "unmap.mapping_id")?;
                if m.has {
                    out.unmap.mapping_id = m.value;
                    out.unmap.has_mapping_id = true;
                }
                has_mapping = true;
            } else if key == "wire_generation" {
                if has_wgen {
                    return Err(ValidationError::new("wire_generation", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "unmap")?;
                if m.has {
                    out.unmap.wire_generation = m.value;
                    out.unmap.has_wire_generation = true;
                }
                has_wgen = true;
            } else if key == "wire_identity" {
                if has_wid {
                    return Err(ValidationError::new("wire_identity", "duplicate"));
                }
                let m = parse_nullable_id(scan, "unmap.wire_identity")?;
                if m.has {
                    check_wire_identity_unmap(&m.value)?;
                    out.unmap.wire_identity = m.value;
                    out.unmap.has_wire_identity = true;
                }
                has_wid = true;
            } else {
                return Err(ValidationError::new("unmap", "unknown unmap field"));
            }
            if !object_next(scan, "unmap")? {
                break;
            }
        }
    }
    scan.end_object("unmap")?;
    if !has_mapping || !has_wgen || !has_wid {
        return Err(ValidationError::new("unmap", "missing field"));
    }
    let seen_gen = out.unmap.has_wire_generation;
    let seen_ident = out.unmap.has_wire_identity;
    if seen_gen != seen_ident {
        return Err(ValidationError::new(
            "unmap",
            "wire generation/identity mismatch",
        ));
    }
    if !out.unmap.has_mapping_id && !(seen_gen && seen_ident && out.unmap.wire_identity == "miss") {
        return Err(ValidationError::new("unmap", "unmap lacks mapping_id"));
    }
    Ok(())
}

fn parse_copy(scan: &mut Scanner, out: &mut Event, version: &str) -> Result<(), ValidationError> {
    scan.begin_object("copy")?;
    let mut has_op = false;
    let mut has_mapping = false;
    let mut has_dir = false;
    let mut has_bytes = false;
    let mut has_private = false;
    let mut has_past = false;
    if !object_is_empty(scan, "copy")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("copy")?;
            expect_colon(scan, "copy")?;
            if key == "operation_id" {
                if has_op {
                    return Err(ValidationError::new("operation_id", "duplicate"));
                }
                out.copy.operation_id = parse_id_field(scan, "copy.operation_id")?;
                has_op = true;
            } else if key == "mapping_id" {
                if has_mapping {
                    return Err(ValidationError::new("mapping_id", "duplicate"));
                }
                let m = parse_nullable_id(scan, "copy.mapping_id")?;
                if m.has {
                    out.copy.mapping_id = m.value;
                    out.copy.has_mapping_id = true;
                }
                has_mapping = true;
            } else if key == "direction" {
                if has_dir {
                    return Err(ValidationError::new("direction", "duplicate"));
                }
                let v = scan.parse_string("copy")?;
                if v != "original_to_bounce" && v != "bounce_to_original" {
                    return Err(ValidationError::new("copy.direction", "bad enum"));
                }
                out.copy.direction = v;
                has_dir = true;
            } else if key == "bytes" {
                if has_bytes {
                    return Err(ValidationError::new("bytes", "duplicate"));
                }
                out.copy.bytes = parse_u64_field(scan, "copy.bytes")?;
                has_bytes = true;
            } else if key == "pool_private" {
                if has_private {
                    return Err(ValidationError::new("pool_private", "duplicate"));
                }
                if version != EVENT_SCHEMA_VERSION {
                    return Err(ValidationError::new(
                        "copy",
                        "0.1.1 line carries 0.1.2 field",
                    ));
                }
                scan.skip_ws();
                if !scan.parse_bool("copy")? {
                    return Err(ValidationError::new("copy.pool_private", "must be true"));
                }
                out.copy.pool_private = true;
                has_private = true;
            } else if key == "offset_past_allocation" {
                if has_past {
                    return Err(ValidationError::new("offset_past_allocation", "duplicate"));
                }
                if version != EVENT_SCHEMA_VERSION {
                    return Err(ValidationError::new(
                        "copy",
                        "0.1.1 line carries 0.1.2 field",
                    ));
                }
                scan.skip_ws();
                if !scan.parse_bool("copy")? {
                    return Err(ValidationError::new(
                        "copy.offset_past_allocation",
                        "must be true",
                    ));
                }
                out.copy.offset_past_allocation = true;
                has_past = true;
            } else {
                return Err(ValidationError::new("copy", "unknown copy field"));
            }
            if !object_next(scan, "copy")? {
                break;
            }
        }
    }
    scan.end_object("copy")?;
    if !has_op || !has_mapping || !has_dir || !has_bytes {
        return Err(ValidationError::new("copy", "missing field"));
    }
    Ok(())
}

fn parse_sync(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("sync_request")?;
    let mut has_op = false;
    let mut has_mapping = false;
    let mut has_known_key = false;
    let mut has_offset_key = false;
    let mut has_length = false;
    let mut offset_saw_value = false;
    if !object_is_empty(scan, "sync_request")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("sync_request")?;
            expect_colon(scan, "sync_request")?;
            if key == "operation_id" {
                if has_op {
                    return Err(ValidationError::new("operation_id", "duplicate"));
                }
                out.sync.operation_id = parse_id_field(scan, "sync.operation_id")?;
                has_op = true;
            } else if key == "mapping_id" {
                if has_mapping {
                    return Err(ValidationError::new("mapping_id", "duplicate"));
                }
                let m = parse_nullable_id(scan, "sync.mapping_id")?;
                if m.has {
                    out.sync.mapping_id = m.value;
                    out.sync.has_mapping_id = true;
                }
                has_mapping = true;
            } else if key == "offset_known" {
                if has_known_key {
                    return Err(ValidationError::new("offset_known", "duplicate"));
                }
                scan.skip_ws();
                out.sync.has_offset = scan.parse_bool("sync_request")?;
                has_known_key = true;
            } else if key == "offset" {
                if has_offset_key {
                    return Err(ValidationError::new("offset", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "sync_request")?;
                if m.has {
                    out.sync.offset = m.value;
                    offset_saw_value = true;
                }
                has_offset_key = true;
            } else if key == "length" {
                if has_length {
                    return Err(ValidationError::new("length", "duplicate"));
                }
                out.sync.length = parse_u64_field(scan, "sync.length")?;
                has_length = true;
            } else {
                return Err(ValidationError::new(
                    "sync_request",
                    "unknown sync_request field",
                ));
            }
            if !object_next(scan, "sync_request")? {
                break;
            }
        }
    }
    scan.end_object("sync_request")?;
    if !has_op || !has_mapping || !has_known_key || !has_offset_key || !has_length {
        return Err(ValidationError::new("sync_request", "missing field"));
    }
    if out.sync.has_offset != offset_saw_value {
        return Err(ValidationError::new(
            "sync_request",
            "offset/known mismatch",
        ));
    }
    if !out.sync.has_offset {
        out.sync.offset = 0;
    }
    if out.sync.has_offset && checked_add(out.sync.offset, out.sync.length).is_err() {
        return Err(ValidationError::new("sync_request", "span overflows"));
    }
    Ok(())
}

fn parse_transition(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("transition_result")?;
    let mut has_region = false;
    let mut has_state = false;
    let mut has_success = false;
    let mut has_code = false;
    let mut has_offset = false;
    let mut has_length = false;
    let mut has_generation = false;
    let mut has_space = false;
    let mut has_resolution = false;
    if !object_is_empty(scan, "transition_result")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("transition_result")?;
            expect_colon(scan, "transition_result")?;
            if key == "region_id" {
                if has_region {
                    return Err(ValidationError::new("region_id", "duplicate"));
                }
                out.transition.region_id = parse_id_field(scan, "transition.region_id")?;
                has_region = true;
            } else if key == "requested_state" {
                if has_state {
                    return Err(ValidationError::new("requested_state", "duplicate"));
                }
                let v = scan.parse_string("transition_result")?;
                if v != "shared" && v != "private" {
                    return Err(ValidationError::new(
                        "transition.requested_state",
                        "bad enum",
                    ));
                }
                out.transition.requested_state = v;
                has_state = true;
            } else if key == "success" {
                if has_success {
                    return Err(ValidationError::new("success", "duplicate"));
                }
                scan.skip_ws();
                out.transition.success = scan.parse_bool("transition_result")?;
                has_success = true;
            } else if key == "return_code" {
                if has_code {
                    return Err(ValidationError::new("return_code", "duplicate"));
                }
                let m = parse_nullable_int(scan, "transition_result")?;
                if m.has {
                    out.transition.return_code = m.value;
                    out.transition.has_return_code = true;
                }
                has_code = true;
            } else if key == "offset" {
                if has_offset {
                    return Err(ValidationError::new("offset", "duplicate"));
                }
                out.transition.offset = parse_u64_field(scan, "transition.offset")?;
                has_offset = true;
            } else if key == "length" {
                if has_length {
                    return Err(ValidationError::new("length", "duplicate"));
                }
                out.transition.length = parse_u64_field(scan, "transition.length")?;
                has_length = true;
            } else if key == "generation" {
                if has_generation {
                    return Err(ValidationError::new("generation", "duplicate"));
                }
                scan.skip_ws();
                let g = scan.parse_int("transition.generation")?;
                if g < 1 {
                    return Err(ValidationError::new(
                        "transition.generation",
                        "must be positive",
                    ));
                }
                out.transition.generation = g;
                has_generation = true;
            } else if key == "address_space" {
                if has_space {
                    return Err(ValidationError::new("address_space", "duplicate"));
                }
                let v = scan.parse_string("transition_result")?;
                if v != "guest_physical"
                    && v != "kernel_virtual"
                    && v != "iova"
                    && v != "identity_only"
                {
                    return Err(ValidationError::new("transition.address_space", "bad enum"));
                }
                out.transition.address_space = v;
                out.transition.has_address_space = true;
                has_space = true;
            } else if key == "resolution" {
                if has_resolution {
                    return Err(ValidationError::new("resolution", "duplicate"));
                }
                let v = scan.parse_string("transition_result")?;
                if v != "resolved" && v != "unresolved" {
                    return Err(ValidationError::new("transition.resolution", "bad enum"));
                }
                out.transition.resolution = v;
                out.transition.has_resolution = true;
                has_resolution = true;
            } else {
                return Err(ValidationError::new(
                    "transition_result",
                    "unknown transition_result field",
                ));
            }
            if !object_next(scan, "transition_result")? {
                break;
            }
        }
    }
    scan.end_object("transition_result")?;
    if !has_region || !has_state || !has_success || !has_code || !has_offset || !has_length {
        return Err(ValidationError::new("transition_result", "missing field"));
    }
    if checked_add(out.transition.offset, out.transition.length).is_err() {
        return Err(ValidationError::new("transition_result", "span overflows"));
    }
    Ok(())
}

fn parse_pool(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("pool_sample")?;
    let mut has_pool = false;
    let mut has_used = false;
    let mut has_cap = false;
    let mut has_unit = false;
    let mut has_allocator = false;
    let mut has_unit_bytes = false;
    let mut has_hiwater = false;
    let mut has_reason = false;
    if !object_is_empty(scan, "pool_sample")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("pool_sample")?;
            expect_colon(scan, "pool_sample")?;
            if key == "pool_id" {
                if has_pool {
                    return Err(ValidationError::new("pool_id", "duplicate"));
                }
                out.pool.pool_id = parse_id_field(scan, "pool.pool_id")?;
                has_pool = true;
            } else if key == "used_bytes" {
                if has_used {
                    return Err(ValidationError::new("used_bytes", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "pool_sample")?;
                if m.has {
                    out.pool.used_bytes = m.value;
                    out.pool.has_used = true;
                }
                has_used = true;
            } else if key == "capacity_bytes" {
                if has_cap {
                    return Err(ValidationError::new("capacity_bytes", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "pool_sample")?;
                if m.has {
                    out.pool.capacity_bytes = m.value;
                    out.pool.has_capacity = true;
                }
                has_cap = true;
            } else if key == "unit" {
                if has_unit {
                    return Err(ValidationError::new("unit", "duplicate"));
                }
                let v = scan.parse_string("pool_sample")?;
                if v != "bytes" && v != "unknown" {
                    return Err(ValidationError::new("pool.unit", "bad enum"));
                }
                out.pool.unit = v;
                has_unit = true;
            } else if key == "allocator" {
                if has_allocator {
                    return Err(ValidationError::new("allocator", "duplicate"));
                }
                out.pool.allocator = parse_id_field(scan, "pool.allocator")?;
                has_allocator = true;
            } else if key == "unit_bytes" {
                if has_unit_bytes {
                    return Err(ValidationError::new("unit_bytes", "duplicate"));
                }
                let u = parse_u64_field(scan, "pool.unit_bytes")?;
                if u == 0 {
                    return Err(ValidationError::new("pool.unit_bytes", "must be positive"));
                }
                out.pool.unit_bytes = u;
                out.pool.has_unit_bytes = true;
                has_unit_bytes = true;
            } else if key == "hiwater_bytes" {
                if has_hiwater {
                    return Err(ValidationError::new("hiwater_bytes", "duplicate"));
                }
                let h = parse_nullable_u64(scan, "pool_sample")?;
                if h.has {
                    out.pool.hiwater_bytes = h.value;
                    out.pool.has_hiwater = true;
                }
                has_hiwater = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new("reason", "duplicate"));
                }
                let r = scan.parse_string("pool_sample")?;
                if r != "denied" && r != "absent" && r != "unparseable" {
                    return Err(ValidationError::new("pool.reason", "bad enum"));
                }
                out.pool.reason = r;
                has_reason = true;
            } else {
                return Err(ValidationError::new(
                    "pool_sample",
                    "unknown pool_sample field",
                ));
            }
            if !object_next(scan, "pool_sample")? {
                break;
            }
        }
    }
    scan.end_object("pool_sample")?;
    if !has_pool || !has_used || !has_cap || !has_unit {
        return Err(ValidationError::new("pool_sample", "missing field"));
    }
    Ok(())
}

fn parse_gap(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("gap")?;
    let mut has_channel = false;
    let mut has_lost = false;
    let mut has_reason = false;
    let mut has_start = false;
    let mut has_end = false;
    if !object_is_empty(scan, "gap")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("gap")?;
            expect_colon(scan, "gap")?;
            if key == "channel" {
                if has_channel {
                    return Err(ValidationError::new("channel", "duplicate"));
                }
                let v = scan.parse_string("gap")?;
                if v != "detail"
                    && v != "aggregate"
                    && v != "correlation"
                    && v != "baseline"
                    && v != "terminal"
                {
                    return Err(ValidationError::new("gap.channel", "bad enum"));
                }
                out.gap.channel = v;
                has_channel = true;
            } else if key == "lost_count" {
                if has_lost {
                    return Err(ValidationError::new("lost_count", "duplicate"));
                }
                let m = parse_nullable_u64(scan, "gap")?;
                if m.has {
                    out.gap.lost_count = m.value;
                    out.gap.has_lost_count = true;
                }
                has_lost = true;
            } else if key == "reason" {
                if has_reason {
                    return Err(ValidationError::new("reason", "duplicate"));
                }
                let v = scan.parse_string("gap")?;
                check_bounded_text(&v, 1, 512, "gap.reason")?;
                out.gap.reason = v;
                has_reason = true;
            } else if key == "window_start_ns" {
                if has_start {
                    return Err(ValidationError::new("window_start_ns", "duplicate"));
                }
                out.gap.window_start_ns = parse_u64_field(scan, "gap.window_start_ns")?;
                has_start = true;
            } else if key == "window_end_ns" {
                if has_end {
                    return Err(ValidationError::new("window_end_ns", "duplicate"));
                }
                out.gap.window_end_ns = parse_u64_field(scan, "gap.window_end_ns")?;
                has_end = true;
            } else {
                return Err(ValidationError::new("gap", "unknown gap field"));
            }
            if !object_next(scan, "gap")? {
                break;
            }
        }
    }
    scan.end_object("gap")?;
    if !has_channel || !has_lost || !has_reason || !has_start || !has_end {
        return Err(ValidationError::new("gap", "missing field"));
    }
    Ok(())
}

fn parse_marker(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("marker")?;
    let mut has_text = false;
    if !object_is_empty(scan, "marker")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("marker")?;
            expect_colon(scan, "marker")?;
            if key == "text" {
                if has_text {
                    return Err(ValidationError::new("text", "duplicate"));
                }
                let v = scan.parse_string("marker")?;
                check_bounded_text(&v, 1, 256, "marker.text")?;
                out.marker.text = v;
                has_text = true;
            } else {
                return Err(ValidationError::new("marker", "unknown marker field"));
            }
            if !object_next(scan, "marker")? {
                break;
            }
        }
    }
    scan.end_object("marker")?;
    if !has_text {
        return Err(ValidationError::new("marker", "missing field"));
    }
    Ok(())
}

/// Parse one counter scope object into the snapshot payload.
pub(crate) fn parse_snapshot_scope(
    scan: &mut Scanner,
    out: &mut Event,
) -> Result<(), ValidationError> {
    scan.begin_object("counter_snapshot.scope")?;
    let mut has_device = false;
    let mut has_profile = false;
    if !object_is_empty(scan, "counter_snapshot.scope")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("counter_snapshot.scope")?;
            expect_colon(scan, "counter_snapshot.scope")?;
            if key == "device_id" {
                if has_device {
                    return Err(ValidationError::new("device_id", "duplicate"));
                }
                let m = parse_nullable_id(scan, "snapshot.scope.device_id")?;
                if m.has {
                    out.snapshot.scope_device_id = m.value;
                    out.snapshot.has_scope_device = true;
                }
                has_device = true;
            } else if key == "profile_id" {
                if has_profile {
                    return Err(ValidationError::new("profile_id", "duplicate"));
                }
                let v = scan.parse_string("counter_snapshot.scope")?;
                check_bounded_text(&v, 1, 128, "snapshot.scope.profile_id")?;
                out.snapshot.scope_profile_id = v;
                has_profile = true;
            } else {
                return Err(ValidationError::new(
                    "counter_snapshot.scope",
                    "unknown snapshot scope field",
                ));
            }
            if !object_next(scan, "counter_snapshot.scope")? {
                break;
            }
        }
    }
    scan.end_object("counter_snapshot.scope")?;
    if !has_profile {
        return Err(ValidationError::new(
            "counter_snapshot.scope",
            "missing field",
        ));
    }
    Ok(())
}

fn parse_snapshot(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("counter_snapshot")?;
    let mut has_counter = false;
    let mut has_epoch = false;
    let mut has_scope = false;
    let mut has_value = false;
    let mut has_unit = false;
    if !object_is_empty(scan, "counter_snapshot")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("counter_snapshot")?;
            expect_colon(scan, "counter_snapshot")?;
            if key == "counter_id" {
                if has_counter {
                    return Err(ValidationError::new("counter_id", "duplicate"));
                }
                let v = scan.parse_string("counter_snapshot")?;
                check_bounded_text(&v, 1, 128, "snapshot.counter_id")?;
                out.snapshot.counter_id = v;
                has_counter = true;
            } else if key == "epoch" {
                if has_epoch {
                    return Err(ValidationError::new("epoch", "duplicate"));
                }
                out.snapshot.epoch = parse_u64_field(scan, "snapshot.epoch")?;
                has_epoch = true;
            } else if key == "scope" {
                if has_scope {
                    return Err(ValidationError::new("scope", "duplicate"));
                }
                parse_snapshot_scope(scan, out)?;
                has_scope = true;
            } else if key == "value" {
                if has_value {
                    return Err(ValidationError::new("value", "duplicate"));
                }
                out.snapshot.value = parse_u64_field(scan, "snapshot.value")?;
                has_value = true;
            } else if key == "unit" {
                if has_unit {
                    return Err(ValidationError::new("unit", "duplicate"));
                }
                let v = scan.parse_string("counter_snapshot")?;
                check_bounded_text(&v, 1, 32, "snapshot.unit")?;
                out.snapshot.unit = v;
                has_unit = true;
            } else {
                return Err(ValidationError::new(
                    "counter_snapshot",
                    "unknown counter_snapshot field",
                ));
            }
            if !object_next(scan, "counter_snapshot")? {
                break;
            }
        }
    }
    scan.end_object("counter_snapshot")?;
    if !has_counter || !has_epoch || !has_scope || !has_value || !has_unit {
        return Err(ValidationError::new("counter_snapshot", "missing field"));
    }
    Ok(())
}

/// Parse one event source object into the event header fields.
pub(crate) fn parse_source(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("source")?;
    let mut has_hook = false;
    let mut has_backend = false;
    let mut has_profile = false;
    let mut has_measurement = false;
    let mut has_correlation = false;
    if !object_is_empty(scan, "source")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("source")?;
            expect_colon(scan, "source")?;
            if key == "hook" {
                if has_hook {
                    return Err(ValidationError::new("source.hook", "duplicate"));
                }
                let v = scan.parse_string("source")?;
                check_bounded_text(&v, 1, 256, "source.hook")?;
                out.source_hook = v;
                has_hook = true;
            } else if key == "backend" {
                if has_backend {
                    return Err(ValidationError::new("source.backend", "duplicate"));
                }
                let v = scan.parse_string("source")?;
                check_bounded_text(&v, 1, 64, "source.backend")?;
                out.source_backend = v;
                has_backend = true;
            } else if key == "profile_id" {
                if has_profile {
                    return Err(ValidationError::new("source.profile_id", "duplicate"));
                }
                let v = scan.parse_string("source")?;
                check_bounded_text(&v, 1, 128, "source.profile_id")?;
                out.source_profile_id = v;
                has_profile = true;
            } else if key == "measurement" {
                if has_measurement {
                    return Err(ValidationError::new("source.measurement", "duplicate"));
                }
                let v = scan.parse_string("source")?;
                check_measurement(&v)?;
                out.source_measurement = v;
                has_measurement = true;
            } else if key == "correlation" {
                if has_correlation {
                    return Err(ValidationError::new("source.correlation", "duplicate"));
                }
                let v = scan.parse_string("source")?;
                check_correlation(&v)?;
                out.source_correlation = v;
                has_correlation = true;
            } else {
                return Err(ValidationError::new("source", "unknown source field"));
            }
            if !object_next(scan, "source")? {
                break;
            }
        }
    }
    scan.end_object("source")?;
    if !has_hook || !has_backend || !has_profile || !has_measurement || !has_correlation {
        return Err(ValidationError::new("source", "missing field"));
    }
    Ok(())
}

/// Parse one observer-context object into the event header fields.
pub(crate) fn parse_observer(scan: &mut Scanner, out: &mut Event) -> Result<(), ValidationError> {
    scan.begin_object("observer_context")?;
    let mut has_cpu = false;
    let mut has_pid = false;
    let mut has_tgid = false;
    let mut has_comm = false;
    let mut has_cgroup = false;
    let mut has_relation = false;
    if !object_is_empty(scan, "observer_context")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("observer_context")?;
            expect_colon(scan, "observer_context")?;
            if key == "cpu" {
                if has_cpu {
                    return Err(ValidationError::new("observer.cpu", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("observer.cpu")?;
                if !(0..=MAX_CPU).contains(&v) {
                    return Err(ValidationError::new("observer.cpu", "out of range"));
                }
                out.cpu = v;
                out.has_cpu = true;
                has_cpu = true;
            } else if key == "pid" {
                if has_pid {
                    return Err(ValidationError::new("observer.pid", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("observer.pid")?;
                if !(0..=MAX_PID).contains(&v) {
                    return Err(ValidationError::new("observer.pid", "out of range"));
                }
                out.pid = v;
                out.has_pid = true;
                has_pid = true;
            } else if key == "tgid" {
                if has_tgid {
                    return Err(ValidationError::new("observer.tgid", "duplicate"));
                }
                scan.skip_ws();
                let v = scan.parse_int("observer.tgid")?;
                if !(0..=MAX_PID).contains(&v) {
                    return Err(ValidationError::new("observer.tgid", "out of range"));
                }
                out.tgid = v;
                out.has_tgid = true;
                has_tgid = true;
            } else if key == "comm" {
                if has_comm {
                    return Err(ValidationError::new("observer.comm", "duplicate"));
                }
                let v = scan.parse_string("observer_context")?;
                check_bounded_text(&v, 0, 64, "observer.comm")?;
                out.comm = v;
                out.has_comm = true;
                has_comm = true;
            } else if key == "cgroup_id" {
                if has_cgroup {
                    return Err(ValidationError::new("observer.cgroup_id", "duplicate"));
                }
                out.cgroup_id = parse_id_field(scan, "observer.cgroup_id")?;
                out.has_cgroup_id = true;
                has_cgroup = true;
            } else if key == "relation" {
                if has_relation {
                    return Err(ValidationError::new("observer.relation", "duplicate"));
                }
                let v = scan.parse_string("observer_context")?;
                if v != "execution_context_only" {
                    return Err(ValidationError::new("observer.relation", "bad const"));
                }
                has_relation = true;
            } else {
                return Err(ValidationError::new("observer", "unknown observer field"));
            }
            if !object_next(scan, "observer_context")? {
                break;
            }
        }
    }
    scan.end_object("observer_context")?;
    if !has_relation {
        return Err(ValidationError::new("observer_context", "missing field"));
    }
    out.has_observer = true;
    Ok(())
}

/// Parse a deferred data object now that the kind is known.
pub(crate) fn parse_data_span(
    kind: &str,
    span: &[u8],
    version: &str,
    out: &mut Event,
) -> Result<(), ValidationError> {
    let mut scan = Scanner::new(span);
    scan.skip_ws();
    if kind == "bounce_attempt" {
        parse_bounce(&mut scan, out)?;
    } else if kind == "map_result" {
        parse_map_result(&mut scan, out)?;
    } else if kind == "unmap" {
        parse_unmap(&mut scan, out)?;
    } else if kind == "copy" {
        parse_copy(&mut scan, out, version)?;
    } else if kind == "sync_request" {
        parse_sync(&mut scan, out)?;
    } else if kind == "transition_result" {
        parse_transition(&mut scan, out)?;
    } else if kind == "pool_sample" {
        parse_pool(&mut scan, out)?;
    } else if kind == "gap" {
        parse_gap(&mut scan, out)?;
    } else if kind == "marker" {
        parse_marker(&mut scan, out)?;
    } else if kind == "counter_snapshot" {
        parse_snapshot(&mut scan, out)?;
    } else {
        return Err(ValidationError::new("kind", "unknown event kind"));
    }
    scan.skip_ws();
    if !scan.at_end() {
        return Err(ValidationError::new("data", "trailing data"));
    }
    Ok(())
}

/// Parse and validate one event line.
///
/// Key order is free: the data object is captured as a source span
/// on first sight and parsed after the kind is known.
pub fn parse_event(data: &[u8]) -> Result<Event, ValidationError> {
    let mut scan = Scanner::new(data);
    scan.skip_ws();
    scan.begin_object("event")?;
    let mut out = Event::default();
    let mut line_version = String::new();
    let mut has_version = false;
    let mut has_session = false;
    let mut has_seq = false;
    let mut has_ts = false;
    let mut has_kind = false;
    let mut has_source = false;
    let mut has_observer = false;
    let mut has_data = false;
    let mut data_span: Option<(usize, usize)> = None;
    if !object_is_empty(&mut scan, "event")? {
        loop {
            scan.skip_ws();
            let key = scan.parse_string("event")?;
            expect_colon(&mut scan, "event")?;
            if key == "schema_version" {
                if has_version {
                    return Err(ValidationError::new("schema_version", "duplicate"));
                }
                let v = scan.parse_string("event")?;
                if v != EVENT_SCHEMA_VERSION && v != EVENT_SCHEMA_VERSION_PREV {
                    return Err(ValidationError::new("schema_version", "bad const"));
                }
                line_version = v;
                has_version = true;
            } else if key == "session_id" {
                if has_session {
                    return Err(ValidationError::new("session_id", "duplicate"));
                }
                out.session_id = parse_id_field(&mut scan, "event.session_id")?;
                has_session = true;
            } else if key == "seq" {
                if has_seq {
                    return Err(ValidationError::new("seq", "duplicate"));
                }
                out.seq = parse_u64_field(&mut scan, "event.seq")?;
                has_seq = true;
            } else if key == "ts_ns" {
                if has_ts {
                    return Err(ValidationError::new("ts_ns", "duplicate"));
                }
                out.ts_ns = parse_u64_field(&mut scan, "event.ts_ns")?;
                has_ts = true;
            } else if key == "kind" {
                if has_kind {
                    return Err(ValidationError::new("kind", "duplicate"));
                }
                let v = scan.parse_string("event")?;
                check_kind(&v)?;
                out.kind = v;
                has_kind = true;
            } else if key == "source" {
                if has_source {
                    return Err(ValidationError::new("source", "duplicate"));
                }
                parse_source(&mut scan, &mut out)?;
                has_source = true;
            } else if key == "observer_context" {
                if has_observer {
                    return Err(ValidationError::new("observer_context", "duplicate"));
                }
                parse_observer(&mut scan, &mut out)?;
                has_observer = true;
            } else if key == "data" {
                if has_data {
                    return Err(ValidationError::new("data", "duplicate"));
                }
                scan.skip_ws();
                let start = scan.offset();
                scan.skip_value("data")?;
                let end = scan.offset();
                data_span = Some((start, end));
                has_data = true;
            } else {
                return Err(ValidationError::new("event", "unknown event field"));
            }
            if !object_next(&mut scan, "event")? {
                break;
            }
        }
    }
    scan.end_object("event")?;
    if !has_version || !has_session || !has_seq || !has_ts || !has_kind || !has_source || !has_data
    {
        return Err(ValidationError::new("event", "missing field"));
    }
    scan.skip_ws();
    if !scan.at_end() {
        return Err(ValidationError::new("event", "trailing data"));
    }
    let (start, end) = match data_span {
        Some(span) => span,
        None => return Err(ValidationError::new("event", "missing field")),
    };
    let span = scan.span_bytes("data", start, end)?;
    if out.kind == "copy" && out.source_measurement != "observed" {
        return Err(ValidationError::new(
            "copy.source.measurement",
            "executed copies require observed measurement",
        ));
    }
    let kind = out.kind.clone();
    parse_data_span(&kind, span, &line_version, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EV012: &str = include_str!("../../tests/fixtures/reader/ev012/events.ndjson");
    const RETAINED: &str =
        include_str!("../../tests/fixtures/reader/selection-retained/events.ndjson");
    const BADKIND: &str = include_str!("../../tests/fixtures/reader/badkind/events.ndjson");
    const BADSEQ: &str = include_str!("../../tests/fixtures/reader/badseq/events.ndjson");
    const COMPAT_LINE: &str =
        include_str!("../../tests/fixtures/reader/compat-major/events.ndjson");
    const SEALED: &str =
        include_str!("../../tests/fixtures/reader/sealed-complete/events.ndjson");

    fn lines_of(doc: &str) -> Vec<&str> {
        doc.split('\n').filter(|l| !l.is_empty()).collect()
    }

    fn parse(text: &str) -> Result<Event, ValidationError> {
        parse_event(text.as_bytes())
    }

    fn err_of(text: &str) -> (String, String) {
        let err = parse(text).unwrap_err();
        (err.what, err.message)
    }

    fn doc(kind: &str, data: &str) -> String {
        format!(
            "{{\"schema_version\": \"0.1.1\", \"session_id\": \"s1\", \"seq\": \"7\", \
             \"ts_ns\": \"50\", \"kind\": \"{kind}\", \"source\": {{\"hook\": \"h\", \
             \"backend\": \"b\", \"profile_id\": \"p\", \"measurement\": \"observed\", \
             \"correlation\": \"direct\"}}, \"data\": {data}}}"
        )
    }

    #[test]
    fn fixture_ev012_lines_parse_to_exact_values() {
        let lines = lines_of(EV012);
        assert_eq!(lines.len(), 3);
        let first = parse(lines[0]).unwrap();
        assert_eq!(first.session_id, "ev012-session");
        assert_eq!(first.seq, 1);
        assert_eq!(first.ts_ns, 1100000000);
        assert_eq!(first.kind, "bounce_attempt");
        assert_eq!(first.source_hook, "swiotlb:swiotlb_bounced");
        assert_eq!(first.source_backend, "synthetic");
        assert_eq!(first.source_profile_id, "synthetic-attempts-1");
        assert_eq!(first.source_measurement, "observed");
        assert_eq!(first.source_correlation, "direct");
        assert!(!first.has_observer);
        assert_eq!(first.bounce.device_id, "dev-1");
        assert_eq!(first.bounce.requested_bytes, 4096);
        assert!(first.bounce.forced);
        assert_eq!(first.bounce.operation_id, "op-1");
        let second = parse(lines[1]).unwrap();
        assert_eq!(second.seq, 2);
        assert_eq!(second.kind, "map_result");
        assert_eq!(second.map_result.operation_id, "op-1");
        assert!(second.map_result.success);
        assert!(second.map_result.has_mapping_id);
        assert_eq!(second.map_result.mapping_id, "m-9");
        assert!(second.map_result.has_return_code);
        assert_eq!(second.map_result.return_code, 0);
        assert!(second.map_result.has_mapped_bytes);
        assert_eq!(second.map_result.mapped_bytes, 4096);
        assert!(!second.map_result.has_wire_generation);
        assert!(!second.map_result.has_wire_identity);
        let third = parse(lines[2]).unwrap();
        assert_eq!(third.seq, 3);
        assert_eq!(third.kind, "copy");
        assert_eq!(third.copy.operation_id, "op-1");
        assert!(third.copy.has_mapping_id);
        assert_eq!(third.copy.mapping_id, "m-9");
        assert_eq!(third.copy.direction, "original_to_bounce");
        assert_eq!(third.copy.bytes, 4096);
        assert!(third.copy.pool_private);
        assert!(third.copy.offset_past_allocation);
    }

    #[test]
    fn fixture_selection_retained_covers_seven_kinds() {
        let lines = lines_of(RETAINED);
        assert_eq!(lines.len(), 7);
        let kinds: Vec<String> = lines.iter().map(|l| parse(l).unwrap().kind).collect();
        assert_eq!(
            kinds,
            [
                "bounce_attempt",
                "transition_result",
                "map_result",
                "copy",
                "unmap",
                "counter_snapshot",
                "counter_snapshot"
            ]
        );
        let transition = parse(lines[1]).unwrap();
        assert_eq!(transition.transition.region_id, "r1");
        assert_eq!(transition.transition.requested_state, "shared");
        assert!(transition.transition.success);
        assert!(transition.transition.has_return_code);
        assert_eq!(transition.transition.offset, 0);
        assert_eq!(transition.transition.length, 8192);
        assert!(transition.transition.has_address_space);
        assert_eq!(transition.transition.address_space, "guest_physical");
        assert!(transition.transition.has_resolution);
        assert_eq!(transition.transition.resolution, "resolved");
        assert_eq!(transition.transition.generation, 1);
        let unmap = parse(lines[4]).unwrap();
        assert!(unmap.unmap.has_mapping_id);
        assert_eq!(unmap.unmap.mapping_id, "m-1");
        let snap = parse(lines[5]).unwrap();
        assert_eq!(snap.snapshot.counter_id, "swiotlb.bounce_attempts");
        assert_eq!(snap.snapshot.epoch, 3);
        assert!(!snap.snapshot.has_scope_device);
        assert_eq!(snap.snapshot.scope_profile_id, "synthetic-regions-1");
        assert_eq!(snap.snapshot.value, 0);
        assert_eq!(snap.snapshot.unit, "count");
        assert_eq!(parse(lines[6]).unwrap().snapshot.value, 8);
    }

    #[test]
    fn fixture_badkind_refuses_the_kind() {
        let lines = lines_of(BADKIND);
        assert_eq!(lines.len(), 1);
        assert_eq!(
            err_of(lines[0]),
            ("kind".to_string(), "unknown event kind".to_string())
        );
    }

    #[test]
    fn fixture_badseq_lines_parse_individually() {
        // Duplicate sequence numbers are a cross-record refusal owned by
        // the capture reader; per-line parsing accepts both records.
        let lines = lines_of(BADSEQ);
        assert_eq!(lines.len(), 2);
        let first = parse(lines[0]).unwrap();
        let second = parse(lines[1]).unwrap();
        assert_eq!(first.seq, 1);
        assert_eq!(second.seq, 1);
        assert_eq!(first.kind, "bounce_attempt");
        assert_eq!(second.kind, "bounce_attempt");
    }

    #[test]
    fn fixture_compat_major_line_parses() {
        // The rejected 1.0.0 session version never touches line parsing.
        let lines = lines_of(COMPAT_LINE);
        assert_eq!(lines.len(), 1);
        let event = parse(lines[0]).unwrap();
        assert_eq!(event.kind, "bounce_attempt");
        assert_eq!(event.seq, 1);
    }

    #[test]
    fn fixture_sealed_lines_keep_their_own_versions() {
        // Lines under a 0.1.4 session still parse at their own 0.1.1:
        // the session version never upgrades lines.
        let lines = lines_of(SEALED);
        assert_eq!(lines.len(), 3);
        for (index, line) in lines.iter().enumerate() {
            let event = parse(line).unwrap();
            assert_eq!(event.kind, "bounce_attempt");
            assert_eq!(event.seq, index as u64);
        }
    }

    #[test]
    fn event_versions_accept_two_and_refuse_the_rest() {
        let line = lines_of(EV012)[0].to_string();
        assert!(parse(&line).is_ok());
        let prev = line.replace("0.1.2", "0.1.1");
        assert!(parse(&prev).is_ok());
        for bad in ["0.1.0", "0.1.3", "0.2.0", "1.0.0", "9.0.0"] {
            let mutated = line.replacen("0.1.2", bad, 1);
            assert_eq!(
                err_of(&mutated),
                ("schema_version".to_string(), "bad const".to_string()),
                "version {bad} must refuse"
            );
        }
    }

    #[test]
    fn copy_markers_need_line_version_012() {
        let markers = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4", "pool_private": true}"#;
        assert_eq!(
            err_of(&doc("copy", markers)),
            (
                "copy".to_string(),
                "0.1.1 line carries 0.1.2 field".to_string()
            )
        );
        let markers = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4", "offset_past_allocation": true}"#;
        assert_eq!(
            err_of(&doc("copy", markers)),
            (
                "copy".to_string(),
                "0.1.1 line carries 0.1.2 field".to_string()
            )
        );
        // Markers stay optional on 0.1.2 lines.
        let plain = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4"}"#;
        let line = doc("copy", plain).replace("0.1.1", "0.1.2");
        let event = parse(&line).unwrap();
        assert!(!event.copy.pool_private);
        assert!(!event.copy.offset_past_allocation);
        // Present markers must be true.
        let off = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4", "pool_private": false}"#;
        let line = doc("copy", off).replace("0.1.1", "0.1.2");
        assert_eq!(
            err_of(&line),
            ("copy.pool_private".to_string(), "must be true".to_string())
        );
        let off = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4", "offset_past_allocation": false}"#;
        let line = doc("copy", off).replace("0.1.1", "0.1.2");
        assert_eq!(
            err_of(&line),
            (
                "copy.offset_past_allocation".to_string(),
                "must be true".to_string()
            )
        );
    }

    #[test]
    fn copies_require_observed_measurement() {
        let data = r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4"}"#;
        for measurement in ["derived", "estimated"] {
            let line = doc("copy", data).replace("observed", measurement);
            assert_eq!(
                err_of(&line),
                (
                    "copy.source.measurement".to_string(),
                    "executed copies require observed measurement".to_string()
                )
            );
        }
        let bounce = r#"{"device_id": "dev-1", "requested_bytes": "4", "forced": true, "operation_id": "op"}"#;
        let line = doc("bounce_attempt", bounce).replace("observed", "derived");
        assert!(parse(&line).is_ok());
    }

    #[test]
    fn key_order_is_free() {
        // Data before kind exercises the deferred span.
        let line = "{\"data\": {\"text\": \"t\"}, \"source\": {\"hook\": \"h\", \"backend\": \"b\", \
             \"profile_id\": \"p\", \"measurement\": \"observed\", \"correlation\": \"direct\"}, \
             \"kind\": \"marker\", \"ts_ns\": \"50\", \"seq\": \"7\", \
             \"session_id\": \"s1\", \"schema_version\": \"0.1.1\"}";
        let event = parse(line).unwrap();
        assert_eq!(event.kind, "marker");
        assert_eq!(event.marker.text, "t");
        assert_eq!(event.seq, 7);
    }

    #[test]
    fn duplicate_keys_refuse() {
        let base = doc("marker", r#"{"text": "t"}"#);
        let dup = base.replace("\"seq\": \"7\"", "\"seq\": \"7\", \"seq\": \"8\"");
        assert_eq!(err_of(&dup), ("seq".to_string(), "duplicate".to_string()));
        let dup = base.replace(
            "\"kind\": \"marker\"",
            "\"kind\": \"marker\", \"kind\": \"gap\"",
        );
        assert_eq!(err_of(&dup), ("kind".to_string(), "duplicate".to_string()));
        let dup = base.replace("\"hook\": \"h\"", "\"hook\": \"h\", \"hook\": \"h2\"");
        assert_eq!(
            err_of(&dup),
            ("source.hook".to_string(), "duplicate".to_string())
        );
        let bounce = doc(
            "bounce_attempt",
            r#"{"device_id": "dev-1", "device_id": "dev-2", "requested_bytes": "4", "forced": true, "operation_id": "op"}"#,
        );
        assert_eq!(
            err_of(&bounce),
            ("device_id".to_string(), "duplicate".to_string())
        );
        let line = base.replace(
            "\"data\": {\"text\": \"t\"}",
            "\"observer_context\": {\"cpu\": 1, \"cpu\": 2, \"relation\": \"execution_context_only\"}, \"data\": {\"text\": \"t\"}",
        );
        assert_eq!(
            err_of(&line),
            ("observer.cpu".to_string(), "duplicate".to_string())
        );
    }

    #[test]
    fn unknown_fields_refuse() {
        let base = doc("marker", r#"{"text": "t"}"#);
        let line = base.replace("\"seq\": \"7\"", "\"seq\": \"7\", \"zzz\": 1");
        assert_eq!(
            err_of(&line),
            ("event".to_string(), "unknown event field".to_string())
        );
        let line = base.replace("\"hook\": \"h\"", "\"hook\": \"h\", \"zzz\": 1");
        assert_eq!(
            err_of(&line),
            ("source".to_string(), "unknown source field".to_string())
        );
        let copy = doc(
            "copy",
            r#"{"operation_id": "op", "mapping_id": null, "direction": "original_to_bounce", "bytes": "4", "zzz": 1}"#,
        );
        assert_eq!(
            err_of(&copy),
            ("copy".to_string(), "unknown copy field".to_string())
        );
        let line = base.replace(
            "\"data\": {\"text\": \"t\"}",
            "\"observer_context\": {\"zzz\": 1, \"relation\": \"execution_context_only\"}, \"data\": {\"text\": \"t\"}",
        );
        assert_eq!(
            err_of(&line),
            ("observer".to_string(), "unknown observer field".to_string())
        );
        let snap = doc(
            "counter_snapshot",
            r#"{"counter_id": "c", "epoch": "1", "scope": {"profile_id": "p", "zzz": 1}, "value": "2", "unit": "u"}"#,
        );
        assert_eq!(
            err_of(&snap),
            (
                "counter_snapshot.scope".to_string(),
                "unknown snapshot scope field".to_string()
            )
        );
    }

    #[test]
    fn missing_fields_and_trailing_data_refuse() {
        assert_eq!(
            err_of("{}"),
            ("event".to_string(), "missing field".to_string())
        );
        let base = doc("marker", r#"{"text": "t"}"#);
        let line = base.replace(", \"data\": {\"text\": \"t\"}", "");
        assert_eq!(
            err_of(&line),
            ("event".to_string(), "missing field".to_string())
        );
        let bounce = doc(
            "bounce_attempt",
            r#"{"device_id": "dev-1", "requested_bytes": "4", "operation_id": "op"}"#,
        );
        assert_eq!(
            err_of(&bounce),
            ("bounce_attempt".to_string(), "missing field".to_string())
        );
        assert_eq!(
            err_of(&format!("{base} {{}}")),
            ("event".to_string(), "trailing data".to_string())
        );
        assert!(parse(&format!("{base}\n")).is_ok());
    }

    #[test]
    fn observer_bounds_are_exact() {
        let base = doc("marker", r#"{"text": "t"}"#);
        let with = |observer: &str| {
            base.replace(
                "\"data\": {\"text\": \"t\"}",
                &format!("\"observer_context\": {{{observer}}}, \"data\": {{\"text\": \"t\"}}"),
            )
        };
        assert!(!parse(&base).unwrap().has_observer);
        let event = parse(&with(
            "\"cpu\": 1048575, \"relation\": \"execution_context_only\"",
        ))
        .unwrap();
        assert!(event.has_observer);
        assert!(event.has_cpu);
        assert_eq!(event.cpu, 1048575);
        assert_eq!(
            err_of(&with(
                "\"cpu\": 1048576, \"relation\": \"execution_context_only\""
            )),
            ("observer.cpu".to_string(), "out of range".to_string())
        );
        assert_eq!(
            err_of(&with(
                "\"cpu\": -1, \"relation\": \"execution_context_only\""
            )),
            ("observer.cpu".to_string(), "out of range".to_string())
        );
        assert!(
            parse(&with(
                "\"pid\": 4194304, \"relation\": \"execution_context_only\""
            ))
            .is_ok()
        );
        assert_eq!(
            err_of(&with(
                "\"pid\": 4194305, \"relation\": \"execution_context_only\""
            )),
            ("observer.pid".to_string(), "out of range".to_string())
        );
        assert_eq!(
            err_of(&with(
                "\"tgid\": -1, \"relation\": \"execution_context_only\""
            )),
            ("observer.tgid".to_string(), "out of range".to_string())
        );
        let event = parse(&with(
            "\"comm\": \"\", \"relation\": \"execution_context_only\"",
        ))
        .unwrap();
        assert!(event.has_comm);
        assert_eq!(event.comm, "");
        let long = "x".repeat(65);
        assert_eq!(
            err_of(&with(&format!(
                "\"comm\": \"{long}\", \"relation\": \"execution_context_only\""
            ))),
            ("observer.comm".to_string(), "too long".to_string())
        );
        assert_eq!(
            err_of(&with(
                "\"cgroup_id\": \"bad id\", \"relation\": \"execution_context_only\""
            )),
            (
                "observer.cgroup_id".to_string(),
                "ValidationError(what=opaque_id, message=bad character)".to_string()
            )
        );
        assert_eq!(
            err_of(&with("\"cpu\": 1")),
            ("observer_context".to_string(), "missing field".to_string())
        );
        assert_eq!(
            err_of(&with("\"relation\": \"causal\"")),
            ("observer.relation".to_string(), "bad const".to_string())
        );
    }

    #[test]
    fn integer_and_u64_token_failure_shapes() {
        // Integers fail bare with the cursor offset (Mojo
        // ScanError); u64 tokens wrap under the field.
        let base = doc("marker", r#"{"text": "t"}"#);
        let with = |observer: &str| {
            base.replace(
                "\"data\": {\"text\": \"t\"}",
                &format!("\"observer_context\": {{{observer}}}, \"data\": {{\"text\": \"t\"}}"),
            )
        };
        let err = parse(&with(
            "\"cpu\": 01, \"relation\": \"execution_context_only\"",
        ))
        .unwrap_err();
        assert_eq!(err.what, "observer.cpu");
        assert_eq!(err.message, "leading zero");
        assert_eq!(err.offset, Some(234));
        let map = |data: &str| doc("map_result", data);
        let err = parse(&map(
            r#"{"operation_id": "op", "success": true, "mapping_id": "m", "return_code": 01, "mapped_bytes": "4", "wire_generation": null, "wire_identity": null}"#,
        ))
        .unwrap_err();
        assert_eq!(err.what, "integer");
        assert_eq!(err.message, "leading zero");
        // Span-relative: data re-parses on its own cursor.
        assert_eq!(err.offset, Some(75));
        let event = parse(&map(
            r#"{"operation_id": "op", "success": true, "mapping_id": "m", "return_code": -0, "mapped_bytes": "4", "wire_generation": null, "wire_identity": null}"#,
        ))
        .unwrap();
        assert!(event.map_result.has_return_code);
        assert_eq!(event.map_result.return_code, 0);
        let err = parse(&base.replace("\"seq\": \"7\"", "\"seq\": \"01\"")).unwrap_err();
        assert_eq!(err.what, "event.seq");
        let bounce = doc(
            "bounce_attempt",
            r#"{"device_id": "dev-1", "requested_bytes": "18446744073709551616", "forced": true, "operation_id": "op"}"#,
        );
        let err = parse(&bounce).unwrap_err();
        assert_eq!(err.what, "bounce.requested_bytes");
        assert!(err.message.ends_with("overflow)"), "{err}");
        assert!(parse(&base.replace("\"seq\": \"7\"", "\"seq\": \"0\"")).is_ok());
    }

    #[test]
    fn map_wire_rules_match() {
        let map = |data: &str| doc("map_result", data);
        // Success with unassigned wire identity needs no mapping token.
        let event = parse(&map(
            r#"{"operation_id": "op", "success": true, "mapping_id": null, "return_code": 0, "mapped_bytes": "5", "wire_generation": "3", "wire_identity": "unassigned"}"#,
        ))
        .unwrap();
        assert!(!event.map_result.has_mapping_id);
        assert_eq!(event.map_result.wire_generation, 3);
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": true, "mapping_id": null, "return_code": 0, "mapped_bytes": "5", "wire_generation": null, "wire_identity": null}"#,
            )),
            (
                "map_result".to_string(),
                "success lacks mapping_id".to_string()
            )
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": true, "mapping_id": "m", "return_code": 0, "mapped_bytes": null, "wire_generation": null, "wire_identity": null}"#,
            )),
            (
                "map_result".to_string(),
                "success lacks mapped_bytes".to_string()
            )
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": "m", "return_code": 1, "mapped_bytes": null, "wire_generation": null, "wire_identity": null}"#,
            )),
            (
                "map_result".to_string(),
                "failure carries mapping_id".to_string()
            )
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": null, "return_code": 1, "mapped_bytes": "5", "wire_generation": null, "wire_identity": null}"#,
            )),
            (
                "map_result".to_string(),
                "failure carries mapped_bytes".to_string()
            )
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": null, "return_code": 1, "mapped_bytes": null, "wire_generation": "2", "wire_identity": "known"}"#,
            )),
            (
                "map_result".to_string(),
                "failure carries wire_identity".to_string()
            )
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": null, "return_code": 1, "mapped_bytes": null, "wire_generation": "5", "wire_identity": null}"#,
            )),
            (
                "map_result".to_string(),
                "wire generation/identity mismatch".to_string()
            )
        );
        // A zero generation with null identity on failure is accepted.
        assert!(
            parse(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": null, "return_code": 1, "mapped_bytes": null, "wire_generation": "0", "wire_identity": null}"#,
            ))
            .is_ok()
        );
        assert_eq!(
            err_of(&map(
                r#"{"operation_id": "op", "success": false, "mapping_id": null, "return_code": 1, "mapped_bytes": null, "wire_generation": null, "wire_identity": "miss"}"#,
            )),
            (
                "map_result.wire_identity".to_string(),
                "bad enum".to_string()
            )
        );
    }

    #[test]
    fn unmap_wire_rules_match() {
        let unmap = |data: &str| doc("unmap", data);
        assert!(
            parse(&unmap(
                r#"{"mapping_id": "m", "wire_generation": null, "wire_identity": null}"#
            ))
            .is_ok()
        );
        let event = parse(&unmap(
            r#"{"mapping_id": null, "wire_generation": "4", "wire_identity": "miss"}"#,
        ))
        .unwrap();
        assert!(!event.unmap.has_mapping_id);
        assert_eq!(
            err_of(&unmap(
                r#"{"mapping_id": null, "wire_generation": null, "wire_identity": null}"#
            )),
            ("unmap".to_string(), "unmap lacks mapping_id".to_string())
        );
        assert_eq!(
            err_of(&unmap(
                r#"{"mapping_id": null, "wire_generation": "2", "wire_identity": null}"#
            )),
            (
                "unmap".to_string(),
                "wire generation/identity mismatch".to_string()
            )
        );
        assert_eq!(
            err_of(&unmap(
                r#"{"mapping_id": null, "wire_generation": "2", "wire_identity": "known"}"#
            )),
            ("unmap".to_string(), "unmap lacks mapping_id".to_string())
        );
        assert_eq!(
            err_of(&unmap(
                r#"{"mapping_id": null, "wire_generation": null, "wire_identity": "bogus"}"#
            )),
            ("unmap.wire_identity".to_string(), "bad enum".to_string())
        );
    }

    #[test]
    fn sync_offset_known_pairing_is_checked() {
        let sync = |data: &str| doc("sync_request", data);
        let event = parse(&sync(
            r#"{"operation_id": "op", "mapping_id": "m", "offset_known": false, "offset": null, "length": "8"}"#,
        ))
        .unwrap();
        assert!(!event.sync.has_offset);
        assert_eq!(event.sync.offset, 0);
        assert_eq!(
            err_of(&sync(
                r#"{"operation_id": "op", "mapping_id": null, "offset_known": true, "offset": null, "length": "8"}"#,
            )),
            (
                "sync_request".to_string(),
                "offset/known mismatch".to_string()
            )
        );
        assert_eq!(
            err_of(&sync(
                r#"{"operation_id": "op", "mapping_id": null, "offset_known": false, "offset": "4", "length": "8"}"#,
            )),
            (
                "sync_request".to_string(),
                "offset/known mismatch".to_string()
            )
        );
        assert_eq!(
            err_of(&sync(
                r#"{"operation_id": "op", "mapping_id": null, "offset_known": true, "offset": "18446744073709551615", "length": "1"}"#,
            )),
            ("sync_request".to_string(), "span overflows".to_string())
        );
        assert_eq!(
            err_of(&doc(
                "transition_result",
                r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "18446744073709551615", "length": "1"}"#,
            )),
            (
                "transition_result".to_string(),
                "span overflows".to_string()
            )
        );
    }

    #[test]
    fn payload_enums_refuse_unknown_values() {
        let copy = doc(
            "copy",
            r#"{"operation_id": "op", "mapping_id": null, "direction": "sideways", "bytes": "4"}"#,
        );
        assert_eq!(
            err_of(&copy),
            ("copy.direction".to_string(), "bad enum".to_string())
        );
        let transition = doc(
            "transition_result",
            r#"{"region_id": "r", "requested_state": "unknown", "success": true, "return_code": null, "offset": "0", "length": "8"}"#,
        );
        assert_eq!(
            err_of(&transition),
            (
                "transition.requested_state".to_string(),
                "bad enum".to_string()
            )
        );
        let pool = doc(
            "pool_sample",
            r#"{"pool_id": "p", "used_bytes": null, "capacity_bytes": "8", "unit": "count"}"#,
        );
        assert_eq!(
            err_of(&pool),
            ("pool.unit".to_string(), "bad enum".to_string())
        );
        let pool = doc(
            "pool_sample",
            r#"{"pool_id": "p", "used_bytes": null, "capacity_bytes": "8", "unit": "bytes", "reason": "lost"}"#,
        );
        assert_eq!(
            err_of(&pool),
            ("pool.reason".to_string(), "bad enum".to_string())
        );
        let gap = doc(
            "gap",
            r#"{"channel": "side", "lost_count": null, "reason": "r", "window_start_ns": "1", "window_end_ns": "2"}"#,
        );
        assert_eq!(
            err_of(&gap),
            ("gap.channel".to_string(), "bad enum".to_string())
        );
        let base = doc("marker", r#"{"text": "t"}"#);
        assert_eq!(
            err_of(&base.replace("\"measurement\": \"observed\"", "\"measurement\": \"felt\"")),
            ("source.measurement".to_string(), "bad enum".to_string())
        );
        assert_eq!(
            err_of(&base.replace("\"correlation\": \"direct\"", "\"correlation\": \"nearby\"")),
            ("source.correlation".to_string(), "bad enum".to_string())
        );
        let transition = doc(
            "transition_result",
            r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "0", "length": "8", "address_space": "far"}"#,
        );
        assert_eq!(
            err_of(&transition),
            (
                "transition.address_space".to_string(),
                "bad enum".to_string()
            )
        );
        let transition = doc(
            "transition_result",
            r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "0", "length": "8", "resolution": "maybe"}"#,
        );
        assert_eq!(
            err_of(&transition),
            ("transition.resolution".to_string(), "bad enum".to_string())
        );
    }

    #[test]
    fn pool_gap_marker_accept_paths() {
        let pool = doc(
            "pool_sample",
            r#"{"pool_id": "p", "used_bytes": "3", "capacity_bytes": null, "unit": "bytes", "allocator": "slab", "unit_bytes": "512", "hiwater_bytes": null, "reason": "denied"}"#,
        );
        let event = parse(&pool).unwrap();
        assert_eq!(event.pool.pool_id, "p");
        assert!(event.pool.has_used);
        assert_eq!(event.pool.used_bytes, 3);
        assert!(!event.pool.has_capacity);
        assert_eq!(event.pool.unit, "bytes");
        assert_eq!(event.pool.allocator, "slab");
        assert!(event.pool.has_unit_bytes);
        assert_eq!(event.pool.unit_bytes, 512);
        assert!(!event.pool.has_hiwater);
        assert_eq!(event.pool.reason, "denied");
        // Allocator, unit size, high-water, and reason stay optional.
        let minimal = doc(
            "pool_sample",
            r#"{"pool_id": "p", "used_bytes": null, "capacity_bytes": "8", "unit": "unknown"}"#,
        );
        let event = parse(&minimal).unwrap();
        assert_eq!(event.pool.allocator, "");
        assert!(!event.pool.has_unit_bytes);
        assert_eq!(
            err_of(&doc(
                "pool_sample",
                r#"{"pool_id": "p", "used_bytes": null, "capacity_bytes": "8", "unit": "bytes", "unit_bytes": "0"}"#,
            )),
            (
                "pool.unit_bytes".to_string(),
                "must be positive".to_string()
            )
        );
        assert_eq!(
            err_of(&doc(
                "pool_sample",
                r#"{"pool_id": "p", "used_bytes": null, "capacity_bytes": "8", "unit": "bytes", "unit_bytes": null}"#,
            )),
            (
                "pool.unit_bytes".to_string(),
                "expected byte 34".to_string()
            )
        );
        let gap = doc(
            "gap",
            r#"{"channel": "detail", "lost_count": "2", "reason": "ring full", "window_start_ns": "1", "window_end_ns": "2"}"#,
        );
        let event = parse(&gap).unwrap();
        assert_eq!(event.gap.channel, "detail");
        assert!(event.gap.has_lost_count);
        assert_eq!(event.gap.lost_count, 2);
        assert_eq!(event.gap.reason, "ring full");
        assert_eq!(
            err_of(&doc("marker", r#"{"text": ""}"#)),
            ("marker.text".to_string(), "too short".to_string())
        );
        assert_eq!(
            err_of(&doc(
                "gap",
                r#"{"channel": "detail", "lost_count": null, "reason": "", "window_start_ns": "1", "window_end_ns": "2"}"#,
            )),
            ("gap.reason".to_string(), "too short".to_string())
        );
    }

    #[test]
    fn snapshot_scope_device_is_optional() {
        let snap = doc(
            "counter_snapshot",
            r#"{"counter_id": "c", "epoch": "1", "scope": {"device_id": "dev-9", "profile_id": "p"}, "value": "2", "unit": "u"}"#,
        );
        let event = parse(&snap).unwrap();
        assert!(event.snapshot.has_scope_device);
        assert_eq!(event.snapshot.scope_device_id, "dev-9");
        let snap = doc(
            "counter_snapshot",
            r#"{"counter_id": "c", "epoch": "1", "scope": {"profile_id": "p"}, "value": "2", "unit": "u"}"#,
        );
        assert!(!parse(&snap).unwrap().snapshot.has_scope_device);
        assert_eq!(
            err_of(&doc(
                "counter_snapshot",
                r#"{"counter_id": "c", "epoch": "1", "scope": {"device_id": "dev-9"}, "value": "2", "unit": "u"}"#,
            )),
            (
                "counter_snapshot.scope".to_string(),
                "missing field".to_string()
            )
        );
    }

    #[test]
    fn transition_generation_defaults_to_one() {
        let plain = doc(
            "transition_result",
            r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "0", "length": "8"}"#,
        );
        assert_eq!(parse(&plain).unwrap().transition.generation, 1);
        let with_gen = doc(
            "transition_result",
            r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "0", "length": "8", "generation": 2}"#,
        );
        assert_eq!(parse(&with_gen).unwrap().transition.generation, 2);
        assert_eq!(
            err_of(&doc(
                "transition_result",
                r#"{"region_id": "r", "requested_state": "shared", "success": true, "return_code": null, "offset": "0", "length": "8", "generation": 0}"#,
            )),
            (
                "transition.generation".to_string(),
                "must be positive".to_string()
            )
        );
    }

    #[test]
    fn data_must_be_an_object() {
        assert_eq!(
            err_of(&doc("bounce_attempt", "5")),
            (
                "bounce_attempt".to_string(),
                "expected byte 123".to_string()
            )
        );
        assert_eq!(
            err_of(&doc("bounce_attempt", "null")),
            (
                "bounce_attempt".to_string(),
                "expected byte 123".to_string()
            )
        );
    }

    #[test]
    fn deep_data_hits_the_depth_cap() {
        let arrays = |n: usize| format!("{}1{}", "[".repeat(n), "]".repeat(n));
        assert_eq!(
            err_of(&doc("marker", &arrays(63))),
            ("marker".to_string(), "expected byte 123".to_string())
        );
        assert_eq!(
            err_of(&doc("marker", &arrays(64))),
            ("data".to_string(), "nesting too deep".to_string())
        );
    }

    #[test]
    fn source_text_bounds_are_exact() {
        let base = doc("marker", r#"{"text": "t"}"#);
        assert_eq!(
            err_of(&base.replace("\"hook\": \"h\"", "\"hook\": \"\"")),
            ("source.hook".to_string(), "too short".to_string())
        );
        let long = "x".repeat(65);
        assert_eq!(
            err_of(&base.replace("\"backend\": \"b\"", &format!("\"backend\": \"{long}\""))),
            ("source.backend".to_string(), "too long".to_string())
        );
        let long = "x".repeat(129);
        assert_eq!(
            err_of(&base.replace(
                "\"profile_id\": \"p\"",
                &format!("\"profile_id\": \"{long}\"")
            )),
            ("source.profile_id".to_string(), "too long".to_string())
        );
    }

    #[test]
    fn empty_and_garbage_inputs_refuse() {
        assert_eq!(
            err_of(""),
            ("event".to_string(), "unexpected end of input".to_string())
        );
        assert_eq!(
            err_of("["),
            ("event".to_string(), "expected byte 123".to_string())
        );
        assert_eq!(
            err_of("{\"schema_version\" \"0.1.1\"}"),
            ("event".to_string(), "want : in event".to_string())
        );
    }
}
