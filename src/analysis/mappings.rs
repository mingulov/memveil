// SPDX-License-Identifier: GPL-3.0-or-later
//! Mapping, copy, and lifetime reducer over lifecycle events.
//!
//! The tracker consumes normalized events and derives allocation,
//! actual-copy, live-byte, and completed-lifetime metrics:
//!
//! - Successful allocations count map successes; failures never
//!   create mappings. Copies observed before a later outer failure
//!   stay counted; a sync request alone copies nothing.
//! - Live bytes sum only tracked open mappings. Any duplicate
//!   result, detail gap, active-table refusal, or unpaired
//!   release invalidates the total instead of lowering it. A
//!   release without an observed map is the expected pre-window
//!   class: the observed release proves its mapping closed, so
//!   the end-state total stands with partial coverage while
//!   only the peak (pre-window occupancy unknown) is withheld.
//!   Refused observations still count in observed event totals;
//!   only the state they would join is withheld.
//! - Completed lifetimes cover releases with provable durations.
//!   Open, uncertain, and refused mappings are censored from the
//!   statistics, never labeled leaks and never completed samples.
//! - Device attribution needs a proven operation or mapping link.
//!   Unattributable bytes stay in global totals with a note.
//! - Events the correlator left unpaired degrade gracefully: an
//!   unpaired success creates no mapping, an unpaired copy still
//!   adds its bytes to direction totals without attribution,
//!   an unpaired failure still counts, and an unpaired release
//!   invalidates live state.
//!
//! Metrics are a pure function of consumed state, so snapshot and
//! finish share this one implementation.

use std::collections::BTreeMap;

use super::metrics::{QuantileBuckets, floor_mean};
use crate::model::event::Event;
use crate::model::identity::{ACTIVE_MAX, DEVICE_MAX_ID, PENDING_MAX, RESOLVED_MAX, RETIRED_MAX};
use crate::model::metric::Metric;
use crate::model::validate::{checked_add, format_u64};

const MAX_MAPPING_DEVICES: usize = 512;

/// One lifecycle reduction failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappingError {
    /// Human-readable failure.
    pub message: String,
}

impl MappingError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MappingError {}

#[derive(Debug, Clone, Default)]
struct LiveMapping {
    device: String,
    has_device: bool,
    map_ts: u64,
    mapped_bytes: u64,
}

#[derive(Debug, Clone, Default)]
struct DeviceCopy {
    allocations: u64,
    mapped: u64,
    mapped_overflow: bool,
    o2b: u64,
    o2b_overflow: bool,
    b2o: u64,
    b2o_overflow: bool,
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("1 {one}")
    } else {
        format!("{n} {many}")
    }
}

fn detail_loss_cause() -> String {
    "Detail loss reported by the producer may hide a release".to_string()
}

/// Bounded lifecycle state with shared snapshot/finish metrics.
#[derive(Debug, Clone)]
pub struct MappingTracker<
    const ACTIVE_N: usize = ACTIVE_MAX,
    const PENDING_N: usize = PENDING_MAX,
    const DEVICE_N: usize = DEVICE_MAX_ID,
    const RESOLVED_N: usize = RESOLVED_MAX,
    const RETIRED_N: usize = RETIRED_MAX,
> {
    op_device: BTreeMap<String, String>,
    resolved: BTreeMap<String, bool>,
    resolved_order: Vec<String>,
    resolved_next: usize,
    live: BTreeMap<String, LiveMapping>,
    retired: BTreeMap<String, bool>,
    retired_order: Vec<String>,
    retired_next: usize,
    devices: BTreeMap<String, DeviceCopy>,
    lifetimes: QuantileBuckets,
    lifecycle_events: usize,
    saw_map: bool,
    saw_copy: bool,
    saw_unmap: bool,
    saw_sync: bool,
    allocations: u64,
    failed: u64,
    mapped_total: u64,
    mapped_overflow: bool,
    o2b: u64,
    o2b_overflow: bool,
    b2o: u64,
    b2o_overflow: bool,
    priv_bytes: u64,
    priv_overflow: bool,
    opast: u64,
    opast_overflow: bool,
    syncs: u64,
    live_bytes: u64,
    live_invalid: bool,
    live_cause: String,
    peak_live_bytes: u64,
    peak_order_ok: bool,
    peak_ts_high: u64,
    peak_map_at_high: bool,
    byte_us: u64,
    byte_us_overflow: bool,
    degraded: bool,
    degrade_cause: String,
    degraded_copy: bool,
    degrade_copy_cause: String,
    degraded_sync: bool,
    degrade_sync_cause: String,
    detail_lost: bool,
    saw_correlation_gap: bool,
    split_relations: bool,
    completed: u64,
    lifetime_total: u64,
    lifetime_overflow: bool,
    min_life: u64,
    max_life: u64,
    has_life: bool,
    uncertain_closes: usize,
    orphan_releases: usize,
    unpaired: usize,
    unpaired_map: usize,
    unpaired_copy: usize,
    unpaired_sync: usize,
    unattributed_copy_bytes: u64,
    refused_ops: usize,
    refused_active: usize,
    evicted_resolved: usize,
    evicted_retired: usize,
    notes: Vec<String>,
}

impl<
    const ACTIVE_N: usize,
    const PENDING_N: usize,
    const DEVICE_N: usize,
    const RESOLVED_N: usize,
    const RETIRED_N: usize,
> MappingTracker<ACTIVE_N, PENDING_N, DEVICE_N, RESOLVED_N, RETIRED_N>
{
    /// Empty tracker.
    pub fn new() -> Self {
        Self {
            op_device: BTreeMap::new(),
            resolved: BTreeMap::new(),
            resolved_order: Vec::new(),
            resolved_next: 0,
            live: BTreeMap::new(),
            retired: BTreeMap::new(),
            retired_order: Vec::new(),
            retired_next: 0,
            devices: BTreeMap::new(),
            lifetimes: QuantileBuckets::new(),
            lifecycle_events: 0,
            saw_map: false,
            saw_copy: false,
            saw_unmap: false,
            saw_sync: false,
            allocations: 0,
            failed: 0,
            mapped_total: 0,
            mapped_overflow: false,
            o2b: 0,
            o2b_overflow: false,
            b2o: 0,
            b2o_overflow: false,
            priv_bytes: 0,
            priv_overflow: false,
            opast: 0,
            opast_overflow: false,
            syncs: 0,
            live_bytes: 0,
            live_invalid: false,
            live_cause: String::new(),
            peak_live_bytes: 0,
            peak_order_ok: true,
            peak_ts_high: 0,
            peak_map_at_high: false,
            byte_us: 0,
            byte_us_overflow: false,
            degraded: false,
            degrade_cause: String::new(),
            degraded_copy: false,
            degrade_copy_cause: String::new(),
            degraded_sync: false,
            degrade_sync_cause: String::new(),
            detail_lost: false,
            saw_correlation_gap: false,
            split_relations: false,
            completed: 0,
            lifetime_total: 0,
            lifetime_overflow: false,
            min_life: 0,
            max_life: 0,
            has_life: false,
            uncertain_closes: 0,
            orphan_releases: 0,
            unpaired: 0,
            unpaired_map: 0,
            unpaired_copy: 0,
            unpaired_sync: 0,
            unattributed_copy_bytes: 0,
            refused_ops: 0,
            refused_active: 0,
            evicted_resolved: 0,
            evicted_retired: 0,
            notes: Vec::new(),
        }
    }

    /// True once any lifecycle-kind event was consumed.
    pub fn sees_lifecycle(&self) -> bool {
        self.lifecycle_events > 0
    }

    /// Observed unpaired lifecycle events.
    pub fn unpaired_count(&self) -> usize {
        self.unpaired
    }

    /// Observed unpaired mapping/release events.
    pub fn unpaired_mapping_count(&self) -> usize {
        self.unpaired_map
    }

    /// Observed unpaired copy events.
    pub fn unpaired_copy_count(&self) -> usize {
        self.unpaired_copy
    }

    /// Observed unpaired sync events.
    pub fn unpaired_sync_count(&self) -> usize {
        self.unpaired_sync
    }

    /// Select split relation-class interpretation.
    ///
    /// Legacy mode (default) propagates analyzer-observed
    /// unpaired copies and syncs coarsely to every mapping-row
    /// family. Split mode degrades only the affected family:
    /// copy uncertainty preserves proven occupancy, and sync
    /// uncertainty preserves everything but the sync row.
    pub fn set_relation_split(&mut self, split: bool) {
        self.split_relations = split;
    }

    /// Invalidate live state and degrade aggregates.
    ///
    /// Producer-claimed loss may hide a release, exactly like an
    /// observed detail gap, so open mappings and live bytes are
    /// withheld; cumulative counters keep their values with
    /// partial coverage. This covers producer-claimed loss and
    /// recovered tails the event stream never shows. The loss
    /// is shared across every row family, including split
    /// copy and sync coverage.
    pub fn note_detail_loss(&mut self) {
        self.detail_lost = true;
        self.invalidate_live(&detail_loss_cause());
    }

    /// Lost relationships may hide a mapping release.
    pub fn note_correlation_loss(&mut self) {
        self.invalidate_live("Correlation loss may hide a release relationship");
    }

    /// True when observed orphan releases explain the class.
    ///
    /// A producer mapping_release partial claim with no
    /// observed correlation gap, no unpaired mapping, and at
    /// least one paired release of an unknown mapping is
    /// explained by the expected pre-window class: those
    /// releases prove closure without touching observed
    /// live accounting. Anything else stays fail-closed.
    pub fn pre_window_explains_mapping_release(&self) -> bool {
        if self.saw_correlation_gap {
            return false;
        }
        if self.unpaired_map != 0 {
            return false;
        }
        self.orphan_releases > 0
    }

    /// Lost copy attribution degrades copy rows only.
    ///
    /// Proven occupancy is unaffected: a missing copy link
    /// cannot hide a release.
    pub fn note_copy_attribution_loss(&mut self) {
        self.degrade_copy("Copy attribution loss may hide a copy relationship");
    }

    /// Lost sync attribution degrades the sync row only.
    pub fn note_sync_attribution_loss(&mut self) {
        self.degrade_sync("Sync attribution loss may hide a sync relationship");
    }

    fn invalidate_live(&mut self, cause: &str) {
        if !self.live_invalid {
            self.live_invalid = true;
            self.live_cause = cause.to_string();
        }
        self.degrade(cause);
    }

    fn degrade(&mut self, cause: &str) {
        if !self.degraded {
            self.degraded = true;
            self.degrade_cause = cause.to_string();
        }
    }

    fn degrade_copy(&mut self, cause: &str) {
        if !self.degraded_copy {
            self.degraded_copy = true;
            self.degrade_copy_cause = cause.to_string();
        }
    }

    fn degrade_sync(&mut self, cause: &str) {
        if !self.degraded_sync {
            self.degraded_sync = true;
            self.degrade_sync_cause = cause.to_string();
        }
    }

    fn note_unpaired_mapping(&mut self) {
        self.unpaired += 1;
        self.unpaired_map += 1;
        if self.split_relations {
            // Observed mapping loss makes the mapping/release
            // class partial, and valued occupancy needs that
            // class complete: withhold it.
            self.invalidate_live("Unpaired mapping observed");
        } else {
            self.degrade("unpaired lifecycle evidence");
        }
    }

    fn note_unpaired_copy(&mut self) {
        self.unpaired += 1;
        self.unpaired_copy += 1;
        if self.split_relations {
            self.degrade_copy("unpaired copy evidence");
        } else {
            self.degrade("unpaired lifecycle evidence");
        }
    }

    fn note_unpaired_sync(&mut self) {
        self.unpaired += 1;
        self.unpaired_sync += 1;
        if self.split_relations {
            self.degrade_sync("unpaired sync evidence");
        } else {
            self.degrade("unpaired lifecycle evidence");
        }
    }

    fn note_live_level(&mut self) {
        if self.live_bytes > self.peak_live_bytes {
            self.peak_live_bytes = self.live_bytes;
        }
    }

    fn note_peak_order(&mut self, is_map: bool, ts: u64) {
        // Extend the delivery-order proof behind the peak sweep.
        //
        // The delivery-order live accumulator is a valid
        // time-domain occupancy sweep while map/unmap state
        // events arrive in non-decreasing timestamp order with
        // releases before maps at equal timestamps (half-open
        // interval sweep order). That sweep order is a sufficient
        // certificate, not a necessary one: some out-of-order
        // deliveries still have a provable peak, but the tracker
        // conservatively withholds those too. The first violation
        // latches the peak unavailable with a concrete reason;
        // live bytes, open counts, and per-generation durations
        // stay valid.
        if !self.peak_order_ok {
            return;
        }
        if ts < self.peak_ts_high {
            self.break_peak_order();
            return;
        }
        if ts > self.peak_ts_high {
            self.peak_ts_high = ts;
            self.peak_map_at_high = is_map;
            return;
        }
        if !is_map && self.peak_map_at_high {
            self.break_peak_order();
            return;
        }
        if is_map {
            self.peak_map_at_high = true;
        }
    }

    fn break_peak_order(&mut self) {
        self.peak_order_ok = false;
        self.note("Mapping/release delivery order does not prove timestamp order; peak withheld.");
    }

    fn add_byte_us(&mut self, byte_us: u64) {
        match checked_add(self.byte_us, byte_us) {
            Ok(v) => self.byte_us = v,
            Err(_) => self.latch_byte_us_overflow(),
        }
    }

    fn latch_byte_us_overflow(&mut self) {
        if !self.byte_us_overflow {
            self.byte_us_overflow = true;
            self.note("Allocation byte-time exceeds u64 range; value withheld.");
        }
    }

    fn note(&mut self, text: &str) {
        self.notes.push(text.to_string());
    }

    fn device_acc(&mut self, dev: &str) -> bool {
        // Ensure a device row; False when the device budget is out.
        if self.devices.contains_key(dev) {
            return true;
        }
        if self.devices.len() >= DEVICE_N {
            return false;
        }
        self.devices.insert(dev.to_string(), DeviceCopy::default());
        true
    }

    /// Fold one normalized event into lifecycle state.
    pub fn consume(&mut self, ev: &Event) -> Result<(), MappingError> {
        let kind = ev.kind.as_str();
        if kind == "copy" && ev.source_measurement != "observed" {
            return Err(MappingError::new(
                "executed copies require observed measurement",
            ));
        }
        let paired = ev.source_correlation != "unpaired";
        if kind == "bounce_attempt" {
            if paired {
                self.remember_op(&ev.bounce.operation_id, &ev.bounce.device_id);
            }
            return Ok(());
        }
        if kind == "map_result" {
            self.lifecycle_events += 1;
            self.saw_map = true;
            self.apply_map(ev, paired)?;
            return Ok(());
        }
        if kind == "copy" {
            self.lifecycle_events += 1;
            self.saw_copy = true;
            self.apply_copy(ev, paired);
            return Ok(());
        }
        if kind == "sync_request" {
            self.lifecycle_events += 1;
            self.saw_sync = true;
            self.syncs = checked_add(self.syncs, 1).map_err(|e| MappingError::new(e.message))?;
            if !paired {
                self.note_unpaired_sync();
            }
            return Ok(());
        }
        if kind == "unmap" {
            self.lifecycle_events += 1;
            self.saw_unmap = true;
            self.apply_unmap(ev, paired)?;
            return Ok(());
        }
        if kind == "gap" && ev.gap.channel == "correlation" {
            self.saw_correlation_gap = true;
            self.note_correlation_loss();
            return Ok(());
        }
        if kind == "gap" && ev.gap.channel == "detail" {
            self.detail_lost = true;
            self.invalidate_live("Detail loss may hide a release");
            return Ok(());
        }
        Ok(())
    }

    fn remember_op(&mut self, op: &str, dev: &str) {
        if op.is_empty() || dev.is_empty() {
            return;
        }
        if self.op_device.contains_key(op) || self.resolved.contains_key(op) {
            return;
        }
        if self.op_device.len() >= PENDING_N {
            self.refused_ops += 1;
            self.degrade("operation table exhausted");
            return;
        }
        self.op_device.insert(op.to_string(), dev.to_string());
    }

    fn remember_resolved(&mut self, op: &str) {
        // Record one resolved op in the bounded ring.
        //
        // Eviction degrades totals instead of failing: a
        // duplicate past the horizon is undetectable, so every
        // valued row keeps partial coverage with a note.
        if RESOLVED_N == 0 {
            return;
        }
        if self.resolved_order.len() < RESOLVED_N {
            self.resolved_order.push(op.to_string());
        } else {
            let victim = self.resolved_order[self.resolved_next].clone();
            self.resolved.remove(&victim);
            self.resolved_order[self.resolved_next] = op.to_string();
            self.resolved_next += 1;
            if self.resolved_next >= RESOLVED_N {
                self.resolved_next = 0;
            }
            self.evicted_resolved += 1;
            self.degrade("resolved-operation history exceeded");
        }
        self.resolved.insert(op.to_string(), true);
    }

    fn remember_retired(&mut self, mapping: &str) {
        // Record one retired mapping in the bounded ring.
        //
        // Eviction preserves uncertainty: identity reuse past
        // the horizon is undetectable, so totals degrade with a
        // note instead of claiming a duplicate verdict.
        if RETIRED_N == 0 {
            return;
        }
        if self.retired_order.len() < RETIRED_N {
            self.retired_order.push(mapping.to_string());
        } else {
            let victim = self.retired_order[self.retired_next].clone();
            self.retired.remove(&victim);
            self.retired_order[self.retired_next] = mapping.to_string();
            self.retired_next += 1;
            if self.retired_next >= RETIRED_N {
                self.retired_next = 0;
            }
            self.evicted_retired += 1;
            self.degrade("retired-mapping history exceeded");
        }
        self.retired.insert(mapping.to_string(), true);
    }

    fn apply_map(&mut self, ev: &Event, paired: bool) -> Result<(), MappingError> {
        let op = ev.map_result.operation_id.clone();
        if !paired {
            self.note_unpaired_mapping();
            // An explicit failure is an independent fact: it
            // counts even though it opens no lifetime.
            if !ev.map_result.success {
                self.failed =
                    checked_add(self.failed, 1).map_err(|e| MappingError::new(e.message))?;
            }
            return Ok(());
        }
        if self.resolved.contains_key(&op) {
            self.invalidate_live(&format!("Duplicate result for operation {op}"));
            return Ok(());
        }
        self.remember_resolved(&op);
        let mut dev = String::new();
        let mut has_dev = false;
        if let Some(d) = self.op_device.remove(&op) {
            dev = d;
            has_dev = true;
        }
        if !ev.map_result.success {
            self.failed = checked_add(self.failed, 1).map_err(|e| MappingError::new(e.message))?;
            return Ok(());
        }
        if !ev.map_result.has_mapping_id {
            self.invalidate_live("Success lacks mapping identity");
            return Ok(());
        }
        self.note_peak_order(true, ev.ts_ns);
        let mapping = ev.map_result.mapping_id.clone();
        let mut mapped = 0u64;
        if ev.map_result.has_mapped_bytes {
            mapped = ev.map_result.mapped_bytes;
        }
        if self.live.contains_key(&mapping) || self.retired.contains_key(&mapping) {
            self.invalidate_live(&format!("Duplicate mapping identity {mapping}"));
            return Ok(());
        }
        self.allocations =
            checked_add(self.allocations, 1).map_err(|e| MappingError::new(e.message))?;
        match checked_add(self.mapped_total, mapped) {
            Ok(v) => self.mapped_total = v,
            Err(_) => {
                if !self.mapped_overflow {
                    self.mapped_overflow = true;
                    self.note("Mapped-byte total exceeds u64 range; value withheld.");
                }
            }
        }
        if has_dev
            && self.device_acc(&dev)
            && let Some(acc) = self.devices.get_mut(&dev)
        {
            acc.allocations =
                checked_add(acc.allocations, 1).map_err(|e| MappingError::new(e.message))?;
            match checked_add(acc.mapped, mapped) {
                Ok(v) => acc.mapped = v,
                Err(_) => acc.mapped_overflow = true,
            }
        }
        if self.live.len() >= ACTIVE_N {
            self.refused_active += 1;
            self.invalidate_live("Active mapping table exhausted");
            return Ok(());
        }
        self.live.insert(
            mapping,
            LiveMapping {
                device: dev,
                has_device: has_dev,
                map_ts: ev.ts_ns,
                mapped_bytes: mapped,
            },
        );
        match checked_add(self.live_bytes, mapped) {
            Ok(v) => self.live_bytes = v,
            Err(_) => {
                self.invalidate_live("Live-byte total overflowed");
                return Ok(());
            }
        }
        self.note_live_level();
        Ok(())
    }

    fn apply_copy(&mut self, ev: &Event, paired: bool) {
        let direction = ev.copy.direction.as_str();
        if direction != "original_to_bounce" && direction != "bounce_to_original" {
            self.degrade("copy with unknown direction");
            return;
        }
        // Executed bytes are an independent event fact: every
        // observed copy aggregates into its direction total
        // before pairing decides attribution.
        let n = ev.copy.bytes;
        if direction == "original_to_bounce" {
            match checked_add(self.o2b, n) {
                Ok(v) => self.o2b = v,
                Err(_) => {
                    if !self.o2b_overflow {
                        self.o2b_overflow = true;
                        self.note("Original-to-bounce total exceeds u64 range; value withheld.");
                    }
                }
            }
        } else {
            match checked_add(self.b2o, n) {
                Ok(v) => self.b2o = v,
                Err(_) => {
                    if !self.b2o_overflow {
                        self.b2o_overflow = true;
                        self.note("Bounce-to-original total exceeds u64 range; value withheld.");
                    }
                }
            }
        }
        // Subset facts ride the direction totals: marked copies still count as executed bytes.
        if ev.copy.pool_private {
            match checked_add(self.priv_bytes, n) {
                Ok(v) => self.priv_bytes = v,
                Err(_) => {
                    if !self.priv_overflow {
                        self.priv_overflow = true;
                        self.note("Private-pool total exceeds u64 range; value withheld.");
                    }
                }
            }
        }
        if ev.copy.offset_past_allocation {
            match checked_add(self.opast, 1) {
                Ok(v) => self.opast = v,
                Err(_) => {
                    if !self.opast_overflow {
                        self.opast_overflow = true;
                        self.note("Past-allocation count exceeds u64 range; value withheld.");
                    }
                }
            }
        }
        if !paired {
            self.note_unpaired_copy();
            return;
        }
        let mut dev = String::new();
        let mut attributed = false;
        if ev.copy.has_mapping_id {
            let mapping = ev.copy.mapping_id.clone();
            if let Some(rec) = self.live.get(&mapping)
                && rec.has_device
            {
                dev = rec.device.clone();
                attributed = true;
            }
        } else {
            let op = ev.copy.operation_id.clone();
            if let Some(d) = self.op_device.get(&op) {
                dev = d.clone();
                attributed = true;
            }
        }
        if !attributed {
            if let Ok(v) = checked_add(self.unattributed_copy_bytes, n) {
                self.unattributed_copy_bytes = v;
            }
            return;
        }
        if !self.device_acc(&dev) {
            if let Ok(v) = checked_add(self.unattributed_copy_bytes, n) {
                self.unattributed_copy_bytes = v;
            }
            return;
        }
        if let Some(acc) = self.devices.get_mut(&dev) {
            if direction == "original_to_bounce" {
                match checked_add(acc.o2b, n) {
                    Ok(v) => acc.o2b = v,
                    Err(_) => acc.o2b_overflow = true,
                }
            } else {
                match checked_add(acc.b2o, n) {
                    Ok(v) => acc.b2o = v,
                    Err(_) => acc.b2o_overflow = true,
                }
            }
        }
    }

    fn apply_unmap(&mut self, ev: &Event, paired: bool) -> Result<(), MappingError> {
        if !paired {
            self.unpaired += 1;
            self.unpaired_map += 1;
            self.invalidate_live("Unpaired release observed");
            return Ok(());
        }
        if !ev.unmap.has_mapping_id {
            self.invalidate_live("Release lacks mapping identity");
            return Ok(());
        }
        self.note_peak_order(false, ev.ts_ns);
        let mapping = ev.unmap.mapping_id.clone();
        if !self.live.contains_key(&mapping) {
            // Expected pre-window class: the observed release
            // proves its mapping is closed, so end-state live
            // answers stand; only the peak (pre-window
            // occupancy unknown) is withheld. Coverage still
            // degrades to partial.
            self.orphan_releases += 1;
            self.degrade("Release without open mapping");
            return Ok(());
        }
        let rec = self.live.remove(&mapping).unwrap_or_default();
        self.remember_retired(&mapping);
        if rec.mapped_bytes > self.live_bytes {
            self.invalidate_live("Live-byte accounting fault");
        } else {
            self.live_bytes -= rec.mapped_bytes;
        }
        if ev.ts_ns < rec.map_ts {
            self.uncertain_closes += 1;
            self.degrade("Release predates its mapping");
            return Ok(());
        }
        let dur = ev.ts_ns - rec.map_ts;
        self.lifetimes
            .add(dur)
            .map_err(|e| MappingError::new(e.message))?;
        // Completed byte-time: exact under any interleaving, since
        // each mapping carries its own provable duration.
        let dur_us = dur / 1000;
        if dur_us > 0 && rec.mapped_bytes > 0 {
            let limit = u64::MAX / rec.mapped_bytes;
            if dur_us > limit {
                self.latch_byte_us_overflow();
            } else {
                self.add_byte_us(rec.mapped_bytes * dur_us);
            }
        }
        match checked_add(self.lifetime_total, dur) {
            Ok(v) => self.lifetime_total = v,
            Err(_) => {
                if !self.lifetime_overflow {
                    self.lifetime_overflow = true;
                    self.note("Lifetime sum exceeds u64 range; mean withheld.");
                }
            }
        }
        self.completed =
            checked_add(self.completed, 1).map_err(|e| MappingError::new(e.message))?;
        if !self.has_life || dur < self.min_life {
            self.min_life = dur;
        }
        if !self.has_life || dur > self.max_life {
            self.max_life = dur;
        }
        self.has_life = true;
        Ok(())
    }
}

impl<
    const ACTIVE_N: usize,
    const PENDING_N: usize,
    const DEVICE_N: usize,
    const RESOLVED_N: usize,
    const RETIRED_N: usize,
> Default for MappingTracker<ACTIVE_N, PENDING_N, DEVICE_N, RESOLVED_N, RETIRED_N>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<
    const ACTIVE_N: usize,
    const PENDING_N: usize,
    const DEVICE_N: usize,
    const RESOLVED_N: usize,
    const RETIRED_N: usize,
> MappingTracker<ACTIVE_N, PENDING_N, DEVICE_N, RESOLVED_N, RETIRED_N>
{
    /// Human-readable bounds/anomaly notes for the report.
    pub fn limitations(&self) -> Vec<String> {
        let mut out = self.notes.clone();
        if self.orphan_releases > 0 {
            let mut origin = "mapped before observation began";
            if self.detail_lost {
                origin = "map record unobserved";
            }
            out.push(format!(
                "{}; closed mappings excluded correctly, peak withheld.",
                plural(
                    self.orphan_releases,
                    &format!("pre-window release ({origin})"),
                    &format!("pre-window releases ({origin})")
                )
            ));
        }
        if self.uncertain_closes > 0 {
            out.push(format!(
                "{}; excluded from completed lifetimes.",
                plural(
                    self.uncertain_closes,
                    "release with unprovable duration",
                    "releases with unprovable durations"
                )
            ));
        }
        if self.unpaired > 0 {
            out.push(format!(
                "{}; independent facts retained; affected totals degrade.",
                plural(
                    self.unpaired,
                    "unpaired lifecycle event excluded from pairing-dependent state",
                    "unpaired lifecycle events excluded from pairing-dependent state"
                )
            ));
        }
        if self.refused_ops > 0 || self.refused_active > 0 {
            out.push(format!(
                "Bounded tables refused {} lifecycle records; affected totals degrade.",
                self.refused_ops + self.refused_active
            ));
        }
        if self.evicted_resolved > 0 {
            out.push(format!(
                "{} resolved operations evicted (history exceeded); duplicates past the horizon are undetectable.",
                self.evicted_resolved
            ));
        }
        if self.evicted_retired > 0 {
            out.push(format!(
                "{} retired mappings evicted (history exceeded); identity reuse past the horizon is undetectable.",
                self.evicted_retired
            ));
        }
        if self.unattributed_copy_bytes > 0 {
            out.push(format!(
                "{} copy bytes lack device attribution and appear in global totals only.",
                format_u64(self.unattributed_copy_bytes)
            ));
        }
        let devices = self.devices.len();
        if devices > MAX_MAPPING_DEVICES {
            out.push(format!(
                "{} devices withheld from per-device rows ({}-device detail budget).",
                devices - MAX_MAPPING_DEVICES,
                MAX_MAPPING_DEVICES
            ));
        }
        out
    }

    fn coverage(&self, overlay_detail_loss: bool) -> String {
        if self.degraded || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    fn coverage_copy(&self, overlay_detail_loss: bool) -> String {
        // Copy-family coverage: coarse in legacy, scoped in split.
        //
        // Split scoping still shares consumed detail loss across
        // every family; only mapping-only correlation loss stays
        // out of this family's verdict.
        if !self.split_relations {
            return self.coverage(overlay_detail_loss);
        }
        if self.degraded_copy || self.detail_lost || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    fn coverage_sync(&self, overlay_detail_loss: bool) -> String {
        // Sync-family coverage: coarse in legacy, scoped in split.
        //
        // Split scoping still shares consumed detail loss across
        // every family; only mapping-only correlation loss stays
        // out of this family's verdict.
        if !self.split_relations {
            return self.coverage(overlay_detail_loss);
        }
        if self.degraded_sync || self.detail_lost || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    fn coverage_device(&self, overlay_detail_loss: bool) -> String {
        // Device-row coverage: mapping or copy loss degrades.
        //
        // Per-device rows carry attribution, so in split mode they
        // degrade under either mapping or copy uncertainty; the
        // sync row is the only family sync loss touches. Legacy
        // mode stays coarse.
        if !self.split_relations {
            return self.coverage(overlay_detail_loss);
        }
        if self.degraded || self.degraded_copy || overlay_detail_loss {
            return "partial".to_string();
        }
        "complete_for_scope".to_string()
    }

    fn view_live_invalid(&self, overlay_detail_loss: bool) -> bool {
        // Live state is withheld under consumed or overlaid loss.
        self.live_invalid || overlay_detail_loss
    }

    fn view_live_cause(&self, overlay_detail_loss: bool) -> String {
        // Withhold reason, preferring the latched consumed cause.
        if self.live_invalid {
            return self.live_cause.clone();
        }
        if overlay_detail_loss {
            return detail_loss_cause();
        }
        self.live_cause.clone()
    }

    #[allow(clippy::too_many_arguments)]
    fn row(
        &self,
        name: &str,
        unit: &str,
        has_value: bool,
        value: u64,
        measurement: &str,
        coverage: &str,
        aggregation: &str,
        has_samples: bool,
        samples: u64,
        has_device: bool,
        device: &str,
        scope: &str,
        notes: &str,
    ) -> Metric {
        let mut m = Metric {
            name: name.to_string(),
            has_value,
            value,
            unit: unit.to_string(),
            measurement: measurement.to_string(),
            coverage: coverage.to_string(),
            confidence: "high".to_string(),
            has_sample_count: has_samples,
            sample_count: samples,
            has_device_id: has_device,
            device_id: device.to_string(),
            scope: scope.to_string(),
            notes: notes.to_string(),
            ..Default::default()
        };
        if !aggregation.is_empty() {
            m.has_aggregation = true;
            m.aggregation = aggregation.to_string();
        }
        m
    }

    #[allow(clippy::too_many_arguments)]
    fn valued(
        &self,
        name: &str,
        unit: &str,
        value: u64,
        aggregation: &str,
        has_samples: bool,
        samples: u64,
        scope: &str,
        notes: &str,
        overlay_detail_loss: bool,
    ) -> Metric {
        let coverage = self.coverage(overlay_detail_loss);
        self.row(
            name,
            unit,
            true,
            value,
            "observed",
            &coverage,
            aggregation,
            has_samples,
            samples,
            false,
            "",
            scope,
            notes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn valued_copy(
        &self,
        name: &str,
        unit: &str,
        value: u64,
        aggregation: &str,
        has_samples: bool,
        samples: u64,
        scope: &str,
        notes: &str,
        overlay_detail_loss: bool,
    ) -> Metric {
        let coverage = self.coverage_copy(overlay_detail_loss);
        self.row(
            name,
            unit,
            true,
            value,
            "observed",
            &coverage,
            aggregation,
            has_samples,
            samples,
            false,
            "",
            scope,
            notes,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn valued_sync(
        &self,
        name: &str,
        unit: &str,
        value: u64,
        aggregation: &str,
        has_samples: bool,
        samples: u64,
        scope: &str,
        notes: &str,
        overlay_detail_loss: bool,
    ) -> Metric {
        let coverage = self.coverage_sync(overlay_detail_loss);
        self.row(
            name,
            unit,
            true,
            value,
            "observed",
            &coverage,
            aggregation,
            has_samples,
            samples,
            false,
            "",
            scope,
            notes,
        )
    }

    fn missing(&self, name: &str, unit: &str, scope: &str, notes: &str) -> Metric {
        // A null value always carries unavailable coverage: the
        // row's own measurement is missing, whatever the evidence
        // quality behind it. The reason lives in the notes.
        self.row(
            name,
            unit,
            false,
            0,
            "unavailable",
            "unavailable",
            "",
            false,
            0,
            false,
            "",
            scope,
            notes,
        )
    }

    /// One deterministic row set; shared by snapshot/finish.
    ///
    /// Without a horizon the oldest-open age stays unavailable;
    /// pass the horizon explicitly for age-aware rows. The
    /// overlay renders call-local detail uncertainty (a
    /// dropped tail) without latching tracker state, so a
    /// partial snapshot cannot alter later facts.
    pub fn metrics(
        &self,
        window: &str,
        overlay_detail_loss: bool,
    ) -> Result<Vec<Metric>, MappingError> {
        self.metrics_horizon(window, 0, overlay_detail_loss)
    }

    fn oldest_open_ts(&self) -> u64 {
        // Minimum map timestamp over live mappings; 0 when none.
        self.live.values().map(|r| r.map_ts).min().unwrap_or(0)
    }

    /// Row set with oldest-open age against one horizon.
    ///
    /// Each family stays null without its own source kinds: a
    /// zero would claim an empty observation the capture cannot
    /// prove. Unknown is null with a reason, never zero. The
    /// overlay renders call-local detail uncertainty (a
    /// dropped tail) without latching tracker state.
    pub fn metrics_horizon(
        &self,
        window: &str,
        horizon_ns: u64,
        overlay_detail_loss: bool,
    ) -> Result<Vec<Metric>, MappingError> {
        let mut out = Vec::new();
        let scope = format!("{window}; observed mappings");
        if !self.saw_map {
            let no_map = "No map_result events in this capture.";
            out.push(self.missing("successful_allocations", "count", &scope, no_map));
            out.push(self.missing("failed_allocations", "count", &scope, no_map));
            out.push(self.missing("mapped_bytes_total", "bytes", &scope, no_map));
        } else {
            out.push(self.valued(
                "successful_allocations",
                "count",
                self.allocations,
                "counter",
                false,
                0,
                &scope,
                "Map successes with mapping identity.",
                overlay_detail_loss,
            ));
            out.push(self.valued(
                "failed_allocations",
                "count",
                self.failed,
                "counter",
                false,
                0,
                &scope,
                "Map failures; no mapping created.",
                overlay_detail_loss,
            ));
            if self.mapped_overflow {
                out.push(self.missing(
                    "mapped_bytes_total",
                    "bytes",
                    &scope,
                    "Mapped-byte total exceeds u64 range; value withheld.",
                ));
            } else {
                out.push(self.valued(
                    "mapped_bytes_total",
                    "bytes",
                    self.mapped_total,
                    "counter",
                    false,
                    0,
                    &scope,
                    "Sum of mapped bytes over successes.",
                    overlay_detail_loss,
                ));
            }
        }
        if !self.saw_copy {
            let no_copy = "No copy events in this capture.";
            out.push(self.missing("copy_original_to_bounce_bytes", "bytes", &scope, no_copy));
            out.push(self.missing("copy_bounce_to_original_bytes", "bytes", &scope, no_copy));
        } else {
            if self.o2b_overflow {
                out.push(self.missing(
                    "copy_original_to_bounce_bytes",
                    "bytes",
                    &scope,
                    "Total exceeds u64 range; withheld.",
                ));
            } else {
                out.push(self.valued_copy(
                    "copy_original_to_bounce_bytes",
                    "bytes",
                    self.o2b,
                    "counter",
                    false,
                    0,
                    &scope,
                    "Observed original-to-bounce copies only; sync requests add nothing.",
                    overlay_detail_loss,
                ));
            }
            if self.b2o_overflow {
                out.push(self.missing(
                    "copy_bounce_to_original_bytes",
                    "bytes",
                    &scope,
                    "Total exceeds u64 range; withheld.",
                ));
            } else {
                out.push(self.valued_copy(
                    "copy_bounce_to_original_bytes",
                    "bytes",
                    self.b2o,
                    "counter",
                    false,
                    0,
                    &scope,
                    "Observed bounce-to-original copies only; sync requests add nothing.",
                    overlay_detail_loss,
                ));
            }
            // Subset rows appear only when nonzero, inside the direction totals.
            if self.priv_overflow {
                out.push(self.missing(
                    "copy_private_pool_bytes",
                    "bytes",
                    &scope,
                    "Total exceeds u64 range; withheld.",
                ));
            } else if self.priv_bytes != 0 {
                out.push(self.valued_copy(
                    "copy_private_pool_bytes",
                    "bytes",
                    self.priv_bytes,
                    "counter",
                    false,
                    0,
                    &scope,
                    "Private-pool copies only, a subset of the direction totals; never exposure.",
                    overlay_detail_loss,
                ));
            }
            if self.opast_overflow {
                out.push(self.missing(
                    "copy_offset_past_allocation_count",
                    "count",
                    &scope,
                    "Total exceeds u64 range; withheld.",
                ));
            } else if self.opast != 0 {
                out.push(self.valued_copy(
                    "copy_offset_past_allocation_count",
                    "count",
                    self.opast,
                    "counter",
                    false,
                    0,
                    &scope,
                    "Copies whose offset ran past the allocation; their bytes stay in the direction totals.",
                    overlay_detail_loss,
                ));
            }
        }
        let has_mapping_state = self.saw_map || self.saw_unmap;
        if self.view_live_invalid(overlay_detail_loss) {
            let mut cause = self.view_live_cause(overlay_detail_loss);
            if !has_mapping_state && cause.is_empty() {
                cause = "No mapping evidence".to_string();
            }
            out.push(self.missing(
                "live_observed_allocation_bytes",
                "bytes",
                &scope,
                &format!("{cause}; live total withheld, not a lower bound."),
            ));
            out.push(self.missing(
                "open_mappings",
                "count",
                &scope,
                &format!("{cause}; open count withheld."),
            ));
            out.push(self.missing(
                "peak_live_observed_allocation_bytes",
                "bytes",
                &scope,
                &format!("{cause}; peak withheld with live state."),
            ));
        } else if !has_mapping_state {
            let no_state = "No map or release events in this capture.";
            out.push(self.missing("live_observed_allocation_bytes", "bytes", &scope, no_state));
            out.push(self.missing("open_mappings", "count", &scope, no_state));
            out.push(self.missing(
                "peak_live_observed_allocation_bytes",
                "bytes",
                &scope,
                no_state,
            ));
        } else {
            out.push(self.valued(
                "live_observed_allocation_bytes",
                "bytes",
                self.live_bytes,
                "gauge",
                false,
                0,
                &scope,
                "Mapped bytes still open at the horizon.",
                overlay_detail_loss,
            ));
            out.push(self.valued(
                "open_mappings",
                "count",
                self.live.len() as u64,
                "gauge",
                false,
                0,
                &scope,
                "Open mappings are censored from completed lifetimes, not leaks.",
                overlay_detail_loss,
            ));
            if !self.peak_order_ok {
                out.push(self.missing(
                    "peak_live_observed_allocation_bytes",
                    "bytes",
                    &scope,
                    "Mapping/release delivery order does not prove timestamp order; peak withheld.",
                ));
            } else if self.orphan_releases > 0 {
                out.push(self.missing(
                    "peak_live_observed_allocation_bytes",
                    "bytes",
                    &scope,
                    &format!(
                        "{}; pre-window occupancy unknown; peak withheld.",
                        plural(
                            self.orphan_releases,
                            "release without an observed map",
                            "releases without an observed map"
                        )
                    ),
                ));
            } else {
                out.push(self.valued(
                    "peak_live_observed_allocation_bytes",
                    "bytes",
                    self.peak_live_bytes,
                    "gauge",
                    false,
                    0,
                    &scope,
                    "Maximum live mapped bytes reached; peak observed allocation occupancy in this window; release does not prove reprivatization or erasure.",
                    overlay_detail_loss,
                ));
            }
        }
        if has_mapping_state
            && !self.view_live_invalid(overlay_detail_loss)
            && !self.live.is_empty()
            && horizon_ns > 0
            && self.oldest_open_ts() <= horizon_ns
        {
            out.push(self.valued(
                "oldest_open_mapping_age_ns",
                "nanoseconds",
                horizon_ns - self.oldest_open_ts(),
                "gauge",
                false,
                0,
                &scope,
                "Horizon minus oldest open map time; an input to the long-lived policy, never a leak verdict.",
                overlay_detail_loss,
            ));
        } else {
            let mut age_why = "No open mappings at the horizon.".to_string();
            if !has_mapping_state {
                age_why = "No map or release events in this capture.".to_string();
            } else if self.view_live_invalid(overlay_detail_loss) {
                age_why = format!(
                    "{}; age withheld.",
                    self.view_live_cause(overlay_detail_loss)
                );
            } else if !self.live.is_empty() && horizon_ns == 0 {
                age_why = "No horizon supplied for open age.".to_string();
            }
            out.push(self.missing(
                "oldest_open_mapping_age_ns",
                "nanoseconds",
                &scope,
                &age_why,
            ));
        }
        out.push(self.byte_time_row(&scope, horizon_ns, has_mapping_state, overlay_detail_loss));
        if self.saw_sync {
            out.push(self.valued_sync(
                "sync_requests",
                "count",
                self.syncs,
                "counter",
                false,
                0,
                &scope,
                "Sync requests observed; requests are not copies.",
                overlay_detail_loss,
            ));
        } else {
            out.push(self.missing(
                "sync_requests",
                "count",
                &scope,
                "No sync_request events in this capture.",
            ));
        }
        if self.saw_unmap {
            out.push(self.valued(
                "completed_lifetime_count",
                "count",
                self.completed,
                "counter",
                true,
                self.completed,
                &scope,
                "Releases with provable durations; open and uncertain mappings excluded.",
                overlay_detail_loss,
            ));
        } else {
            out.push(self.missing(
                "completed_lifetime_count",
                "count",
                &scope,
                "No release events in this capture; open mappings are censored, not completed.",
            ));
        }
        if self.completed == 0 {
            let mut reason = "No completed lifetimes".to_string();
            if !self.live.is_empty() {
                reason += &format!("; {} mappings still open at the horizon", self.live.len());
            }
            reason += ".";
            out.push(self.missing("lifetime_mean_ns", "nanoseconds", &scope, &reason));
            out.push(self.missing("lifetime_min_ns", "nanoseconds", &scope, &reason));
            out.push(self.missing("lifetime_max_ns", "nanoseconds", &scope, &reason));
            out.push(self.missing("lifetime_p50_ns", "nanoseconds", &scope, &reason));
            out.push(self.missing("lifetime_p95_ns", "nanoseconds", &scope, &reason));
            out.push(self.missing("lifetime_p99_ns", "nanoseconds", &scope, &reason));
        } else {
            out.push(self.mean_row(&scope, overlay_detail_loss)?);
            let coverage = self.coverage(overlay_detail_loss);
            out.push(self.row(
                "lifetime_min_ns",
                "nanoseconds",
                true,
                self.min_life,
                "observed",
                &coverage,
                "gauge",
                true,
                self.completed,
                false,
                "",
                &scope,
                "Exact minimum completed lifetime.",
            ));
            out.push(self.row(
                "lifetime_max_ns",
                "nanoseconds",
                true,
                self.max_life,
                "observed",
                &coverage,
                "gauge",
                true,
                self.completed,
                false,
                "",
                &scope,
                "Exact maximum completed lifetime.",
            ));
            let p50 = self
                .lifetimes
                .estimate(50, 100)
                .map_err(|e| MappingError::new(e.message))?;
            out.push(self.row(
                "lifetime_p50_ns",
                "nanoseconds",
                true,
                p50,
                "estimated",
                &coverage,
                "p50",
                true,
                self.completed,
                false,
                "",
                &scope,
                "Estimated 65-bucket upper edge; exact min/max stay separate.",
            ));
            let p95 = self
                .lifetimes
                .estimate(95, 100)
                .map_err(|e| MappingError::new(e.message))?;
            out.push(self.row(
                "lifetime_p95_ns",
                "nanoseconds",
                true,
                p95,
                "estimated",
                &coverage,
                "p95",
                true,
                self.completed,
                false,
                "",
                &scope,
                "Estimated 65-bucket upper edge; exact min/max stay separate.",
            ));
            let p99 = self
                .lifetimes
                .estimate(99, 100)
                .map_err(|e| MappingError::new(e.message))?;
            out.push(self.row(
                "lifetime_p99_ns",
                "nanoseconds",
                true,
                p99,
                "estimated",
                &coverage,
                "p99",
                true,
                self.completed,
                false,
                "",
                &scope,
                "Estimated 65-bucket upper edge; exact min/max stay separate.",
            ));
        }
        self.device_rows(&mut out, window, overlay_detail_loss);
        Ok(out)
    }

    fn byte_time_row(
        &self,
        scope: &str,
        horizon_ns: u64,
        has_mapping_state: bool,
        overlay_detail_loss: bool,
    ) -> Metric {
        // Allocation byte-time: completed plus open mappings.
        //
        // Each mapping contributes mapped bytes times its own
        // provable duration, so interleaved streams integrate
        // exactly. Open mappings need a horizon; without one the
        // row is withheld while anything is still open.
        if self.view_live_invalid(overlay_detail_loss) {
            return self.missing(
                "allocation_byte_microseconds",
                "byte_microseconds",
                scope,
                &format!(
                    "{}; byte-time withheld with live state.",
                    self.view_live_cause(overlay_detail_loss)
                ),
            );
        }
        if !has_mapping_state {
            return self.missing(
                "allocation_byte_microseconds",
                "byte_microseconds",
                scope,
                "No map or release events in this capture.",
            );
        }
        if horizon_ns == 0 && !self.live.is_empty() {
            return self.missing(
                "allocation_byte_microseconds",
                "byte_microseconds",
                scope,
                "Open mappings need a horizon for byte-time; completed mappings alone would undercount.",
            );
        }
        if self.byte_us_overflow {
            return self.missing(
                "allocation_byte_microseconds",
                "byte_microseconds",
                scope,
                "Allocation byte-time exceeds u64 range; value withheld.",
            );
        }
        let mut total = self.byte_us;
        if horizon_ns > 0 {
            for rec in self.live.values() {
                if rec.map_ts >= horizon_ns {
                    continue;
                }
                let open_us = (horizon_ns - rec.map_ts) / 1000;
                if open_us == 0 || rec.mapped_bytes == 0 {
                    continue;
                }
                let limit = u64::MAX / rec.mapped_bytes;
                if open_us > limit {
                    return self.missing(
                        "allocation_byte_microseconds",
                        "byte_microseconds",
                        scope,
                        "Allocation byte-time exceeds u64 range; value withheld.",
                    );
                }
                match checked_add(total, rec.mapped_bytes * open_us) {
                    Ok(v) => total = v,
                    Err(_) => {
                        return self.missing(
                            "allocation_byte_microseconds",
                            "byte_microseconds",
                            scope,
                            "Allocation byte-time exceeds u64 range; value withheld.",
                        );
                    }
                }
            }
        }
        self.valued(
            "allocation_byte_microseconds",
            "byte_microseconds",
            total,
            "counter",
            false,
            0,
            scope,
            "Observed allocation byte-time, not a measured sharing lifetime. Completed mappings use exact durations; open mappings integrate to the horizon.",
            overlay_detail_loss,
        )
    }

    fn mean_row(&self, scope: &str, overlay_detail_loss: bool) -> Result<Metric, MappingError> {
        if self.lifetime_overflow {
            return Ok(self.missing(
                "lifetime_mean_ns",
                "nanoseconds",
                scope,
                "Lifetime sum exceeds u64 range; mean withheld, count/min/max stay valid.",
            ));
        }
        let mean = floor_mean(self.lifetime_total, self.completed)
            .map_err(|e| MappingError::new(e.message))?;
        let coverage = self.coverage(overlay_detail_loss);
        Ok(self.row(
            "lifetime_mean_ns",
            "nanoseconds",
            true,
            mean,
            "observed",
            &coverage,
            "mean",
            true,
            self.completed,
            false,
            "",
            scope,
            "Floor mean over completed lifetimes.",
        ))
    }

    fn device_rows(&self, out: &mut Vec<Metric>, window: &str, overlay_detail_loss: bool) {
        // Per-device detail rows in sorted device order.
        //
        // Families follow the same source gates as the global
        // rows: null without their own source kinds.
        let kept = self.devices.len().min(MAX_MAPPING_DEVICES);
        for (dev, acc) in self.devices.iter().take(kept) {
            let scope = format!("{window}; device {dev}");
            let dev_cov = self.coverage_device(overlay_detail_loss);
            let (m_measurement, m_coverage, m_agg, m_notes) = if self.saw_map {
                (
                    "observed".to_string(),
                    dev_cov.clone(),
                    "counter".to_string(),
                    "Map successes on this device.".to_string(),
                )
            } else {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No map_result events in this capture.".to_string(),
                )
            };
            out.push(Metric {
                name: "successful_allocations".to_string(),
                has_value: self.saw_map,
                value: acc.allocations,
                unit: "count".to_string(),
                confidence: "high".to_string(),
                measurement: m_measurement,
                coverage: m_coverage,
                has_aggregation: !m_agg.is_empty(),
                aggregation: m_agg,
                notes: m_notes,
                has_device_id: true,
                device_id: dev.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
            let (b_measurement, b_coverage, b_agg, b_notes) = if !self.saw_map {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No map_result events in this capture.".to_string(),
                )
            } else if acc.mapped_overflow {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "Total exceeds u64 range.".to_string(),
                )
            } else {
                (
                    "observed".to_string(),
                    dev_cov.clone(),
                    "counter".to_string(),
                    "Mapped bytes on this device.".to_string(),
                )
            };
            out.push(Metric {
                name: "mapped_bytes_total".to_string(),
                has_value: self.saw_map && !acc.mapped_overflow,
                value: acc.mapped,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: b_measurement,
                coverage: b_coverage,
                has_aggregation: !b_agg.is_empty(),
                aggregation: b_agg,
                notes: b_notes,
                has_device_id: true,
                device_id: dev.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
            let (o_measurement, o_coverage, o_agg, o_notes) = if !self.saw_copy {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No copy events in this capture.".to_string(),
                )
            } else if acc.o2b_overflow {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "Total exceeds u64 range.".to_string(),
                )
            } else {
                (
                    "observed".to_string(),
                    dev_cov.clone(),
                    "counter".to_string(),
                    "Attributed copies on this device.".to_string(),
                )
            };
            out.push(Metric {
                name: "copy_original_to_bounce_bytes".to_string(),
                has_value: self.saw_copy && !acc.o2b_overflow,
                value: acc.o2b,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: o_measurement,
                coverage: o_coverage,
                has_aggregation: !o_agg.is_empty(),
                aggregation: o_agg,
                notes: o_notes,
                has_device_id: true,
                device_id: dev.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
            let (r_measurement, r_coverage, r_agg, r_notes) = if !self.saw_copy {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "No copy events in this capture.".to_string(),
                )
            } else if acc.b2o_overflow {
                (
                    "unavailable".to_string(),
                    "unavailable".to_string(),
                    String::new(),
                    "Total exceeds u64 range.".to_string(),
                )
            } else {
                (
                    "observed".to_string(),
                    dev_cov.clone(),
                    "counter".to_string(),
                    "Attributed copies on this device.".to_string(),
                )
            };
            out.push(Metric {
                name: "copy_bounce_to_original_bytes".to_string(),
                has_value: self.saw_copy && !acc.b2o_overflow,
                value: acc.b2o,
                unit: "bytes".to_string(),
                confidence: "high".to_string(),
                measurement: r_measurement,
                coverage: r_coverage,
                has_aggregation: !r_agg.is_empty(),
                aggregation: r_agg,
                notes: r_notes,
                has_device_id: true,
                device_id: dev.clone(),
                scope: scope.clone(),
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::event::Event;
    use crate::model::metric::Metric;

    fn base(kind: &str, seq: u64, ts: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: ts,
            kind: kind.to_string(),
            source_hook: "h".to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ..Default::default()
        }
    }

    fn attempt(op: &str, device: &str, seq: u64) -> Event {
        let mut ev = base("bounce_attempt", seq, 1000 + seq);
        ev.bounce.device_id = device.to_string();
        ev.bounce.requested_bytes = 4096;
        ev.bounce.forced = false;
        ev.bounce.operation_id = op.to_string();
        ev
    }

    fn map(op: &str, ok: bool, mapping: &str, mapped: u64, ts: u64, seq: u64) -> Event {
        let mut ev = base("map_result", seq, ts);
        ev.map_result.operation_id = op.to_string();
        ev.map_result.success = ok;
        if !mapping.is_empty() {
            ev.map_result.has_mapping_id = true;
            ev.map_result.mapping_id = mapping.to_string();
        }
        if ok {
            ev.map_result.has_mapped_bytes = true;
            ev.map_result.mapped_bytes = mapped;
        } else {
            ev.map_result.has_return_code = true;
            ev.map_result.return_code = -12;
        }
        ev
    }

    fn copy(op: &str, mapping: &str, direction: &str, n: u64, seq: u64) -> Event {
        let mut ev = base("copy", seq, 2000 + seq);
        ev.copy.operation_id = op.to_string();
        if !mapping.is_empty() {
            ev.copy.has_mapping_id = true;
            ev.copy.mapping_id = mapping.to_string();
        }
        ev.copy.direction = direction.to_string();
        ev.copy.bytes = n;
        ev
    }

    fn sync(op: &str, mapping: &str, length: u64, seq: u64) -> Event {
        let mut ev = base("sync_request", seq, 3000 + seq);
        ev.sync.operation_id = op.to_string();
        ev.sync.has_mapping_id = true;
        ev.sync.mapping_id = mapping.to_string();
        ev.sync.has_offset = true;
        ev.sync.offset = 0;
        ev.sync.length = length;
        ev
    }

    fn unmap(mapping: &str, ts: u64, seq: u64) -> Event {
        let mut ev = base("unmap", seq, ts);
        ev.unmap.has_mapping_id = true;
        ev.unmap.mapping_id = mapping.to_string();
        ev
    }

    fn gap(seq: u64) -> Event {
        let mut ev = base("gap", seq, 4000 + seq);
        ev.gap.channel = "detail".to_string();
        ev.gap.has_lost_count = true;
        ev.gap.lost_count = 2;
        ev.gap.reason = "test drop".to_string();
        ev
    }

    fn find<'a>(metrics: &'a [Metric], name: &str, device: &str) -> &'a Metric {
        metrics
            .iter()
            .find(|m| {
                if m.name != name {
                    return false;
                }
                if device.is_empty() {
                    !m.has_device_id
                } else {
                    m.has_device_id && m.device_id == device
                }
            })
            .unwrap_or_else(|| panic!("metric not found: {name}"))
    }

    fn global<'a>(metrics: &'a [Metric], name: &str) -> &'a Metric {
        find(metrics, name, "")
    }

    #[test]
    fn non_observed_copy_rejected() {
        for measurement in ["estimated", "derived"] {
            let mut t: MappingTracker = MappingTracker::new();
            t.consume(&attempt("op1", "dev1", 1)).unwrap();
            let mut ev = copy("op1", "", "original_to_bounce", 99, 2);
            ev.source_measurement = measurement.to_string();
            assert!(t.consume(&ev).is_err());
        }
    }

    #[test]
    fn lifecycle_nested() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&copy("op1", "", "original_to_bounce", 4096, 2))
            .unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1300000000, 3))
            .unwrap();
        t.consume(&sync("op1", "m1", 1024, 4)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 1024, 5))
            .unwrap();
        t.consume(&unmap("m1", 2300000000, 6)).unwrap();
        let rows = t.metrics("window [0,2300000000)", false).unwrap();
        assert!(t.sees_lifecycle());
        assert_eq!(global(&rows, "successful_allocations").value, 1);
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 5120);
        assert_eq!(global(&rows, "live_observed_allocation_bytes").value, 0);
        assert_eq!(global(&rows, "completed_lifetime_count").value, 1);
        let mean = global(&rows, "lifetime_mean_ns");
        assert_eq!(mean.value, 1000000000);
        assert!(mean.has_sample_count);
        assert_eq!(mean.sample_count, 1);
        assert_eq!(global(&rows, "sync_requests").value, 1);
        // 1e9 ns sits in [2^29, 2^30-1]: estimated edge 2^30-1.
        assert_eq!(global(&rows, "lifetime_p50_ns").value, 1073741823);
        assert_eq!(global(&rows, "lifetime_p50_ns").measurement, "estimated");
    }

    #[test]
    fn copy_before_failure() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&copy("op1", "", "original_to_bounce", 4096, 2))
            .unwrap();
        t.consume(&map("op1", false, "", 0, 100, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 0);
        assert_eq!(global(&rows, "failed_allocations").value, 1);
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 4096);
        assert!(!global(&rows, "completed_lifetime_count").has_value);
    }

    #[test]
    fn request_is_not_copy() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&sync("op1", "m1", 1024, 3)).unwrap();
        t.consume(&unmap("m1", 200, 4)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        // No copy events: the copy metric stays unavailable, and the
        // sync request is counted separately without adding bytes.
        let cp = global(&rows, "copy_original_to_bounce_bytes");
        assert!(!cp.has_value);
        assert_eq!(cp.measurement, "unavailable");
        assert_eq!(global(&rows, "sync_requests").value, 1);
    }

    #[test]
    fn orphan_release_keeps_live_withholds_peak() {
        // A release without an observed map proves its mapping is
        // closed, so the end-state live answers stand with partial
        // coverage; only the peak (pre-window occupancy unknown)
        // is withheld, with the class named in limitations.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&unmap("ghost", 200, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "partial");
        let opened = global(&rows, "open_mappings");
        assert!(opened.has_value);
        assert_eq!(opened.value, 1);
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(!peak.has_value);
        assert!(
            peak.notes.contains("without an observed map"),
            "{}",
            peak.notes
        );
        assert!(t.limitations().iter().any(|n| n.contains("pre-window")));
    }

    #[test]
    fn orphan_release_plus_correlation_gap_withholds_live() {
        // Fail-closed twin: an observed correlation gap defeats
        // the pre-window explanation, so live state is withheld
        // even though an orphan release was observed.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&unmap("ghost", 200, 3)).unwrap();
        let mut g = gap(4);
        g.gap.channel = "correlation".to_string();
        t.consume(&g).unwrap();
        assert!(!t.pre_window_explains_mapping_release());
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn producer_loss_invalidates_live_keeps_aggregates() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        // Producer-reported detail loss may hide a release, exactly like
        // an observed gap: live state is withheld, aggregates keep their
        // values with partial coverage.
        t.note_detail_loss();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(!live.has_value);
        assert_eq!(live.measurement, "unavailable");
        assert!(!global(&rows, "open_mappings").has_value);
        let allocs = global(&rows, "successful_allocations");
        assert_eq!(allocs.value, 1);
        assert_eq!(allocs.coverage, "partial");
        assert_eq!(global(&rows, "mapped_bytes_total").value, 4096);
    }

    #[test]
    fn peak_and_byte_time() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        // m1: 4096 bytes over [100ms, 300ms); m2: 8192 bytes over
        // [200ms, horizon). Live bytes: 4096, then 12288, then 8192.
        t.consume(&map("op1", true, "m1", 4096, 100000000, 3))
            .unwrap();
        t.consume(&map("op2", true, "m2", 8192, 200000000, 4))
            .unwrap();
        t.consume(&unmap("m1", 300000000, 5)).unwrap();
        let rows = t
            .metrics_horizon("window [0,1000000000)", 1000000000, false)
            .unwrap();
        assert_eq!(
            global(&rows, "peak_live_observed_allocation_bytes").value,
            12288
        );
        // 4096*100ms + 12288*100ms + 8192*700ms, in byte-microseconds.
        assert_eq!(
            global(&rows, "allocation_byte_microseconds").value,
            7372800000
        );
    }

    #[test]
    fn peak_and_byte_time_withheld_when_live_invalid() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100000000, 2))
            .unwrap();
        t.note_detail_loss();
        let rows = t
            .metrics_horizon("window [0,1000000000)", 1000000000, false)
            .unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(!peak.has_value);
        assert_eq!(peak.measurement, "unavailable");
        let bt = global(&rows, "allocation_byte_microseconds");
        assert!(!bt.has_value);
        assert_eq!(bt.measurement, "unavailable");
    }

    #[test]
    fn byte_time_withheld_without_horizon_while_open() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100000000, 2))
            .unwrap();
        // No horizon: the open mapping's contribution is unprovable,
        // so completed-only would undercount and the row is withheld.
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "allocation_byte_microseconds").has_value);
        let rows2 = t
            .metrics_horizon("window [0,1000000000)", 1000000000, false)
            .unwrap();
        assert_eq!(
            global(&rows2, "allocation_byte_microseconds").value,
            3686400000
        );
    }

    #[test]
    fn overlapping_intervals_delivered_out_of_time_order() {
        // [1.1s,1.3s) and [1.2s,1.4s) overlap over 100ms: the
        // independent interval peak is 8192, but delivery order
        // map1/release1/map2/release2 only ever sees 4096 live.
        // The peak is withheld with an ordering reason instead
        // of claiming 4096 complete.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&unmap("m1", 1300000000, 4)).unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1200000000, 5))
            .unwrap();
        t.consume(&unmap("m2", 1400000000, 6)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(!peak.has_value);
        assert_eq!(peak.measurement, "unavailable");
        assert_eq!(peak.coverage, "unavailable");
        assert!(peak.notes.contains("timestamp order"));
        // Per-generation facts stay valid and complete: two 200ms
        // lifetimes, their byte-time, and no live bytes at the
        // horizon. Withholding the peak must not degrade them.
        let completed = global(&rows, "completed_lifetime_count");
        assert_eq!(completed.value, 2);
        assert_eq!(completed.coverage, "complete_for_scope");
        let mean = global(&rows, "lifetime_mean_ns");
        assert_eq!(mean.value, 200000000);
        assert_eq!(mean.coverage, "complete_for_scope");
        assert_eq!(
            global(&rows, "allocation_byte_microseconds").value,
            1638400000
        );
        let live = global(&rows, "live_observed_allocation_bytes");
        assert_eq!(live.value, 0);
        assert_eq!(live.coverage, "complete_for_scope");
        // Repeated violations still disclose exactly once.
        let mut u: MappingTracker = MappingTracker::new();
        u.consume(&attempt("op1", "d1", 1)).unwrap();
        u.consume(&attempt("op2", "d1", 2)).unwrap();
        u.consume(&map("op1", true, "m1", 4096, 200, 3)).unwrap();
        u.consume(&map("op2", true, "m2", 4096, 100, 4)).unwrap();
        u.consume(&unmap("m1", 50, 5)).unwrap();
        u.consume(&unmap("m2", 300, 6)).unwrap();
        let notes = u.limitations();
        assert_eq!(
            notes
                .iter()
                .filter(|n| n.contains("timestamp order"))
                .count(),
            1
        );
    }

    #[test]
    fn ordered_overlap_reports_peak() {
        // Same intervals delivered in timestamp order: the sweep
        // is valid and the 8192 peak stands with full coverage.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1200000000, 4))
            .unwrap();
        t.consume(&unmap("m1", 1300000000, 5)).unwrap();
        t.consume(&unmap("m2", 1400000000, 6)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(peak.has_value);
        assert_eq!(peak.value, 8192);
        assert_eq!(peak.coverage, "complete_for_scope");
    }

    #[test]
    fn ordered_disjoint_reports_peak() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&unmap("m1", 1200000000, 4)).unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1300000000, 5))
            .unwrap();
        t.consume(&unmap("m2", 1400000000, 6)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(peak.has_value);
        assert_eq!(peak.value, 4096);
    }

    #[test]
    fn equal_timestamp_release_first_keeps_peak() {
        // Half-open [1.1,1.2) and [1.2,1.4) never coincide; the
        // release-first tie order is a valid sweep.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&unmap("m1", 1200000000, 4)).unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1200000000, 5))
            .unwrap();
        t.consume(&unmap("m2", 1400000000, 6)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(peak.has_value);
        assert_eq!(peak.value, 4096);
    }

    #[test]
    fn equal_timestamp_map_first_withholds_peak() {
        // Map before release at the shared instant would sum both
        // intervals the delivery order cannot separate.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1200000000, 4))
            .unwrap();
        t.consume(&unmap("m1", 1200000000, 5)).unwrap();
        t.consume(&unmap("m2", 1400000000, 6)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(!peak.has_value);
        assert!(peak.notes.contains("timestamp order"));
    }

    #[test]
    fn reversed_lifetime_withholds_peak() {
        // A release predating its mapping breaks the sweep proof
        // as well as the per-generation duration.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 500, 2)).unwrap();
        t.consume(&unmap("m1", 100, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "peak_live_observed_allocation_bytes").has_value);
        assert_eq!(global(&rows, "completed_lifetime_count").value, 0);
    }

    #[test]
    fn ordered_open_intervals_keep_peak() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 3))
            .unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1200000000, 4))
            .unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(peak.has_value);
        assert_eq!(peak.value, 8192);
        assert_eq!(global(&rows, "open_mappings").value, 2);
    }

    #[test]
    fn zero_timestamp_tie_withholds_spike() {
        // A zero-duration map/release tie at timestamp zero needs
        // no initialization sentinel: the delivery-order spike is
        // withheld while the valid zero-duration lifetime stands.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 0, 2)).unwrap();
        t.consume(&unmap("m1", 0, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "peak_live_observed_allocation_bytes").has_value);
        assert_eq!(global(&rows, "completed_lifetime_count").value, 1);
    }

    #[test]
    fn non_state_events_ignore_peak_proof() {
        // Copies, syncs, and attempts never join the live sweep,
        // so their timestamps cannot break its proof.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1100000000, 2))
            .unwrap();
        let mut cp = copy("op1", "m1", "original_to_bounce", 4096, 3);
        cp.ts_ns = 0;
        t.consume(&cp).unwrap();
        let mut sy = sync("op1", "m1", 1024, 4);
        sy.ts_ns = 0;
        t.consume(&sy).unwrap();
        t.consume(&unmap("m1", 1300000000, 5)).unwrap();
        let rows = t.metrics("window [0,2000000000)", false).unwrap();
        let peak = global(&rows, "peak_live_observed_allocation_bytes");
        assert!(peak.has_value);
        assert_eq!(peak.value, 4096);
    }

    #[test]
    fn lifetime_p95() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&unmap("m1", 300, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        // One completed lifetime: every percentile lands in its bucket.
        assert_eq!(
            global(&rows, "lifetime_p95_ns").value,
            global(&rows, "lifetime_p50_ns").value
        );
        let mut t2: MappingTracker = MappingTracker::new();
        t2.consume(&attempt("op1", "d1", 1)).unwrap();
        t2.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        let rows2 = t2.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows2, "lifetime_p95_ns").has_value);
    }

    #[test]
    fn detail_gap_invalidates_live() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&gap(3)).unwrap();
        t.consume(&unmap("m1", 200, 4)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        assert_eq!(global(&rows, "lifetime_mean_ns").coverage, "partial");
    }

    #[test]
    fn duplicate_result_refused() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&map("op1", true, "m2", 4096, 110, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 1);
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn reused_generation_two_samples() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 512, 100, 2)).unwrap();
        t.consume(&unmap("m1", 150, 3)).unwrap();
        t.consume(&attempt("op2", "d1", 4)).unwrap();
        t.consume(&map("op2", true, "m2", 512, 200, 5)).unwrap();
        t.consume(&unmap("m2", 260, 6)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 2);
        assert_eq!(global(&rows, "completed_lifetime_count").value, 2);
        assert_eq!(global(&rows, "lifetime_mean_ns").value, 55);
        assert_eq!(global(&rows, "lifetime_min_ns").value, 50);
        assert_eq!(global(&rows, "lifetime_max_ns").value, 60);
    }

    #[test]
    fn oldest_open_age() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&attempt("op2", "d1", 3)).unwrap();
        t.consume(&map("op2", true, "m2", 8, 700, 4)).unwrap();
        // Horizon 1000: oldest open maps at 100, age 900.
        let rows = t.metrics_horizon("window [0,1000)", 1000, false).unwrap();
        assert_eq!(global(&rows, "oldest_open_mapping_age_ns").value, 900);
        let mut closed: MappingTracker = MappingTracker::new();
        closed.consume(&attempt("op1", "d1", 1)).unwrap();
        closed
            .consume(&map("op1", true, "m1", 4096, 100, 2))
            .unwrap();
        closed.consume(&unmap("m1", 200, 3)).unwrap();
        let norows = closed
            .metrics_horizon("window [0,1000)", 1000, false)
            .unwrap();
        assert!(!global(&norows, "oldest_open_mapping_age_ns").has_value);
    }

    #[test]
    fn open_at_end_censored() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "open_mappings").value, 1);
        assert_eq!(global(&rows, "live_observed_allocation_bytes").value, 4096);
        // No releases observed: the completed count stays null rather
        // than claiming an empty observation.
        assert!(!global(&rows, "completed_lifetime_count").has_value);
        let mean = global(&rows, "lifetime_mean_ns");
        assert!(!mean.has_value);
        assert!(!mean.notes.is_empty());
    }

    #[test]
    fn mapped_bytes_overflow_withheld() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", u64::MAX, 100, 2))
            .unwrap();
        t.consume(&attempt("op2", "d1", 3)).unwrap();
        t.consume(&map("op2", true, "m2", 1, 110, 4)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 2);
        assert!(!global(&rows, "mapped_bytes_total").has_value);
    }

    #[test]
    fn reversed_timestamps_uncertain() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 500, 2)).unwrap();
        t.consume(&unmap("m1", 100, 3)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "live_observed_allocation_bytes").value, 0);
        assert_eq!(global(&rows, "completed_lifetime_count").value, 0);
        assert!(!global(&rows, "lifetime_mean_ns").has_value);
    }

    #[test]
    fn unpaired_map_excluded() {
        let mut t: MappingTracker = MappingTracker::new();
        let mut ev = map("op1", true, "m1", 4096, 100, 1);
        ev.source_correlation = "unpaired".to_string();
        t.consume(&ev).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 0);
        // No copy events at all: null with an unavailable marker, and
        // the unpaired exclusion is told by the degraded allocations.
        let cp = global(&rows, "copy_original_to_bounce_bytes");
        assert!(!cp.has_value);
        assert_eq!(global(&rows, "successful_allocations").coverage, "partial");
        // Legacy mode keeps the coarse verdict: coverage
        // degrades but occupancy stays valued.
        assert!(global(&rows, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn unpaired_unmap_invalidates_live() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        let mut ev = unmap("m1", 200, 3);
        ev.source_correlation = "unpaired".to_string();
        t.consume(&ev).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn unpaired_release_without_map_degrades() {
        // A dropped map with a persisting unmap degrades totals without release.
        for split in [false, true] {
            let mut t: MappingTracker = MappingTracker::new();
            t.set_relation_split(split);
            let mut ev = unmap("m-9", 1300, 1);
            ev.source_correlation = "unpaired".to_string();
            t.consume(&ev).unwrap();
            assert_eq!(t.unpaired_count(), 1);
            assert_eq!(t.unpaired_mapping_count(), 1);
            let rows = t.metrics("window [0,1000)", false).unwrap();
            let live = global(&rows, "live_observed_allocation_bytes");
            assert!(!live.has_value);
            assert_eq!(live.measurement, "unavailable");
            assert!(!global(&rows, "open_mappings").has_value);
            // No release invented: zero completed, never a phantom sample.
            let done = global(&rows, "completed_lifetime_count");
            assert!(done.has_value);
            assert_eq!(done.value, 0);
            assert_eq!(done.coverage, "partial");
            // No map kind observed: allocation rows stay null with a reason.
            let allocs = global(&rows, "successful_allocations");
            assert!(!allocs.has_value);
            assert_eq!(allocs.measurement, "unavailable");
        }
    }

    #[test]
    fn unpaired_copy_bytes_retained() {
        // Known identityless copies are independent byte facts:
        // 4096 + 1024 aggregate to 5120 even though neither
        // carries attribution.
        let mut t: MappingTracker = MappingTracker::new();
        let mut first = copy("lc-101", "", "original_to_bounce", 4096, 1);
        first.source_correlation = "unpaired".to_string();
        t.consume(&first).unwrap();
        let mut second = copy("lc-102", "", "original_to_bounce", 1024, 2);
        second.source_correlation = "unpaired".to_string();
        t.consume(&second).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let cp = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(cp.value, 5120);
        assert_eq!(cp.coverage, "partial");
        // No bounce-to-original copies observed: a measured zero
        // over observed events, not an unknown.
        let back = global(&rows, "copy_bounce_to_original_bytes");
        assert!(back.has_value);
        assert_eq!(back.value, 0);
    }

    #[test]
    fn unpaired_bounce_to_original_retained() {
        let mut t: MappingTracker = MappingTracker::new();
        let mut ev = copy("lc-103", "", "bounce_to_original", 2048, 1);
        ev.source_correlation = "unpaired".to_string();
        t.consume(&ev).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let cp = global(&rows, "copy_bounce_to_original_bytes");
        assert_eq!(cp.value, 2048);
        assert_eq!(cp.coverage, "partial");
    }

    #[test]
    fn unpaired_failure_counted() {
        // An explicit failed inner allocation with no mapping
        // identity is one observed failure, not a silent drop;
        // it opens no lifetime.
        let mut t: MappingTracker = MappingTracker::new();
        let mut ev = map("lc-103", false, "", 0, 100, 1);
        ev.source_correlation = "unpaired".to_string();
        t.consume(&ev).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let fails = global(&rows, "failed_allocations");
        assert_eq!(fails.value, 1);
        assert_eq!(fails.coverage, "partial");
        let allocs = global(&rows, "successful_allocations");
        assert!(allocs.has_value);
        assert_eq!(allocs.value, 0);
        let opened = global(&rows, "open_mappings");
        assert!(opened.has_value);
        assert_eq!(opened.value, 0);
        assert!(!global(&rows, "completed_lifetime_count").has_value);
    }

    #[test]
    fn unpaired_copy_before_failure() {
        // Copies survive a later outer failure even when both
        // records are unpaired: bytes and failure count coexist.
        let mut t: MappingTracker = MappingTracker::new();
        let mut cp = copy("lc-104", "", "original_to_bounce", 4096, 1);
        cp.source_correlation = "unpaired".to_string();
        t.consume(&cp).unwrap();
        let mut fail = map("lc-104", false, "", 0, 100, 2);
        fail.source_correlation = "unpaired".to_string();
        t.consume(&fail).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 4096);
        assert_eq!(global(&rows, "failed_allocations").value, 1);
    }

    #[test]
    fn mixed_paired_unpaired_copies() {
        // Paired and unpaired copies sum into the global total;
        // only the paired copy lands in the device subset, even
        // when an unpaired copy names a resolvable mapping.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 100, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 4096, 3))
            .unwrap();
        let mut loose = copy("lc-9", "", "original_to_bounce", 1024, 4);
        loose.source_correlation = "unpaired".to_string();
        t.consume(&loose).unwrap();
        let mut sneaky = copy("lc-10", "m1", "original_to_bounce", 512, 5);
        sneaky.source_correlation = "unpaired".to_string();
        t.consume(&sneaky).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 5632);
        let subset = find(&rows, "copy_original_to_bounce_bytes", "d1");
        assert!(subset.has_value);
        assert_eq!(subset.value, 4096);
    }

    #[test]
    fn unpaired_copy_overflow_withheld() {
        let mut t: MappingTracker = MappingTracker::new();
        let mut first = copy("lc-1", "", "original_to_bounce", u64::MAX, 1);
        first.source_correlation = "unpaired".to_string();
        t.consume(&first).unwrap();
        let mut second = copy("lc-2", "", "original_to_bounce", 1, 2);
        second.source_correlation = "unpaired".to_string();
        t.consume(&second).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let cp = global(&rows, "copy_original_to_bounce_bytes");
        assert!(!cp.has_value);
        assert!(!cp.notes.is_empty());
    }

    #[test]
    fn active_budget() {
        let mut t = MappingTracker::<1>::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 8, 100, 2)).unwrap();
        t.consume(&attempt("op2", "d1", 3)).unwrap();
        t.consume(&map("op2", true, "m2", 8, 110, 4)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        // Both successes were observed, so both count; only the live
        // state the refused mapping would join is withheld.
        assert_eq!(global(&rows, "successful_allocations").value, 2);
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn mapping_tracker_op_refusal_visible() {
        let mut t = MappingTracker::<16, 2, 4096>::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&attempt("op2", "d1", 2)).unwrap();
        t.consume(&attempt("op3", "d1", 3)).unwrap();
        assert!(!t.limitations().is_empty());
        // The refusal degrades nothing else: rows still render.
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert!(!rows.is_empty());
    }

    #[test]
    fn mapping_tracker_active_refusal_withholds_live() {
        let mut t = MappingTracker::<1, 16, 4096>::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 1001, 2)).unwrap();
        t.consume(&attempt("op2", "d1", 3)).unwrap();
        t.consume(&map("op2", true, "m2", 4096, 1003, 4)).unwrap();
        assert!(!t.limitations().is_empty());
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let mut found = false;
        for m in &rows {
            if m.name == "live_observed_allocation_bytes" {
                found = true;
                assert!(!m.has_value);
            }
        }
        assert!(found);
    }

    #[test]
    fn resolved_history_bounded() {
        let mut t = MappingTracker::<16, 16, 16, 4, 16>::new();
        let mut seq = 1;
        for i in 0..6 {
            let op = format!("op{i}");
            let mapping = format!("m{i}");
            t.consume(&attempt(&op, "d1", seq)).unwrap();
            seq += 1;
            t.consume(&map(&op, true, &mapping, 4096, 1000 + i as u64, seq))
                .unwrap();
            seq += 1;
        }
        // Six ops through a four-deep history: two evicted, totals
        // degrade with a visible note.
        let rows = t.metrics_horizon("window [0,2000)", 2000, false).unwrap();
        assert_eq!(global(&rows, "successful_allocations").value, 6);
        assert_eq!(global(&rows, "successful_allocations").coverage, "partial");
        assert!(
            t.limitations()
                .iter()
                .any(|n| n.contains("history exceeded"))
        );
        // The evicted op is no longer recognized: resubmission is
        // accepted as new, with uncertainty preserved via partial
        // coverage rather than a duplicate verdict.
        t.consume(&map("op0", true, "m9", 4096, 5000, seq)).unwrap();
        let rows2 = t.metrics_horizon("window [0,6000)", 6000, false).unwrap();
        assert_eq!(global(&rows2, "successful_allocations").value, 7);
        assert!(global(&rows2, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn retired_history_bounded() {
        let mut t = MappingTracker::<16, 16, 16, 16, 4>::new();
        let mut seq = 1;
        for i in 0..6 {
            let op = format!("op{i}");
            let mapping = format!("m{i}");
            t.consume(&attempt(&op, "d1", seq)).unwrap();
            seq += 1;
            t.consume(&map(&op, true, &mapping, 4096, 1000 + i as u64, seq))
                .unwrap();
            seq += 1;
            t.consume(&unmap(&mapping, 1500 + i as u64, seq)).unwrap();
            seq += 1;
        }
        // Six retirements through a four-deep history: two evicted.
        let rows = t.metrics_horizon("window [0,2000)", 2000, false).unwrap();
        assert_eq!(global(&rows, "completed_lifetime_count").value, 6);
        assert_eq!(
            global(&rows, "completed_lifetime_count").coverage,
            "partial"
        );
        assert!(
            t.limitations()
                .iter()
                .any(|n| n.contains("history exceeded"))
        );
        // The evicted retired id is no longer recognized: reuse is
        // accepted as a fresh mapping, never a duplicate verdict.
        t.consume(&attempt("op9", "d1", seq)).unwrap();
        seq += 1;
        t.consume(&map("op9", true, "m0", 4096, 5000, seq)).unwrap();
        let rows2 = t.metrics_horizon("window [0,6000)", 6000, false).unwrap();
        assert!(global(&rows2, "live_observed_allocation_bytes").has_value);
        assert_eq!(global(&rows2, "live_observed_allocation_bytes").value, 4096);
    }

    #[test]
    fn per_device_rows() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 100, 100, 2)).unwrap();
        t.consume(&attempt("op2", "d2", 3)).unwrap();
        t.consume(&map("op2", true, "m2", 300, 110, 4)).unwrap();
        t.consume(&copy("op2", "m2", "bounce_to_original", 40, 5))
            .unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(find(&rows, "successful_allocations", "d1").value, 1);
        assert_eq!(find(&rows, "mapped_bytes_total", "d2").value, 300);
        assert_eq!(find(&rows, "copy_bounce_to_original_bytes", "d2").value, 40);
        assert_eq!(global(&rows, "copy_bounce_to_original_bytes").value, 40);
    }

    #[test]
    fn legacy_unpaired_copy_degrades_all_rows() {
        // Default legacy mode: one unpaired copy degrades every
        // mapping-row family coarsely.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        let mut cp = copy("op1", "", "original_to_bounce", 1024, 2);
        cp.source_correlation = "unpaired".to_string();
        t.consume(&cp).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 3)).unwrap();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "partial");
        assert_eq!(global(&rows, "successful_allocations").coverage, "partial");
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 1024);
        assert_eq!(o2b.coverage, "partial");
    }

    #[test]
    fn split_unpaired_copy_preserves_mapping_coverage() {
        // Split mode: copy-attribution-only uncertainty preserves
        // proven occupancy with complete mapping coverage while
        // only copy and device-attribution rows degrade.
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        let mut cp = copy("op1", "", "original_to_bounce", 1024, 2);
        cp.source_correlation = "unpaired".to_string();
        t.consume(&cp).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 3)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 512, 4))
            .unwrap();
        assert_eq!(t.unpaired_count(), 1);
        assert_eq!(t.unpaired_copy_count(), 1);
        assert_eq!(t.unpaired_sync_count(), 0);
        assert_eq!(t.unpaired_mapping_count(), 0);
        let rows = t.metrics("window [0,6000)", false).unwrap();
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "complete_for_scope");
        assert_eq!(
            global(&rows, "successful_allocations").coverage,
            "complete_for_scope"
        );
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 1536);
        assert_eq!(o2b.coverage, "partial");
        assert_eq!(
            find(&rows, "successful_allocations", "dev1").coverage,
            "partial"
        );
    }

    #[test]
    fn split_unpaired_sync_scoped_to_sync_row() {
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        let mut sy = sync("op1", "m1", 1024, 3);
        sy.source_correlation = "unpaired".to_string();
        t.consume(&sy).unwrap();
        assert_eq!(t.unpaired_sync_count(), 1);
        assert_eq!(t.unpaired_copy_count(), 0);
        let rows = t.metrics("window [0,6000)", false).unwrap();
        let syncs = global(&rows, "sync_requests");
        assert!(syncs.has_value);
        assert_eq!(syncs.value, 1);
        assert_eq!(syncs.coverage, "partial");
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.coverage, "complete_for_scope");
        assert_eq!(
            global(&rows, "successful_allocations").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn split_unpaired_release_withholds_live_only() {
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 512, 3))
            .unwrap();
        let mut rel = unmap("ghost", 5500, 4);
        rel.source_correlation = "unpaired".to_string();
        t.consume(&rel).unwrap();
        assert_eq!(t.unpaired_mapping_count(), 1);
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        let allocs = global(&rows, "successful_allocations");
        assert!(allocs.has_value);
        assert_eq!(allocs.coverage, "partial");
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 512);
        assert_eq!(o2b.coverage, "complete_for_scope");
    }

    #[test]
    fn split_producer_copy_loss_scoped() {
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 512, 3))
            .unwrap();
        t.note_copy_attribution_loss();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.coverage, "complete_for_scope");
        assert_eq!(
            global(&rows, "copy_original_to_bounce_bytes").coverage,
            "partial"
        );
        assert_eq!(
            find(&rows, "mapped_bytes_total", "dev1").coverage,
            "partial"
        );
    }

    #[test]
    fn split_producer_sync_loss_scoped() {
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&sync("op1", "m1", 1024, 3)).unwrap();
        t.note_sync_attribution_loss();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert_eq!(global(&rows, "sync_requests").coverage, "partial");
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.coverage, "complete_for_scope");
    }

    #[test]
    fn split_gap_correlation_hits_mapping_only() {
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 512, 3))
            .unwrap();
        let mut ev = base("gap", 4, 4004);
        ev.gap.channel = "correlation".to_string();
        ev.gap.has_lost_count = true;
        ev.gap.lost_count = 2;
        ev.gap.reason = "test drop".to_string();
        t.consume(&ev).unwrap();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 512);
        assert_eq!(o2b.coverage, "complete_for_scope");
    }

    #[test]
    fn split_producer_detail_loss_degrades_copy_and_sync() {
        // Split mode: producer-declared detail loss is shared
        // across every family, so copy bytes and sync requests
        // degrade even though no attribution loss occurred.
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 1024, 3))
            .unwrap();
        t.consume(&sync("op1", "m1", 1024, 4)).unwrap();
        t.note_detail_loss();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 1024);
        assert_eq!(o2b.coverage, "partial");
        let syncs = global(&rows, "sync_requests");
        assert_eq!(syncs.value, 1);
        assert_eq!(syncs.coverage, "partial");
    }

    #[test]
    fn split_consumed_detail_gap_degrades_copy_and_sync() {
        // Split mode: a consumed detail gap carries the same
        // shared loss as a producer declaration.
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 1024, 3))
            .unwrap();
        t.consume(&sync("op1", "m1", 1024, 4)).unwrap();
        t.consume(&gap(5)).unwrap();
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 1024);
        assert_eq!(o2b.coverage, "partial");
        let syncs = global(&rows, "sync_requests");
        assert_eq!(syncs.value, 1);
        assert_eq!(syncs.coverage, "partial");
    }

    #[test]
    fn split_unpaired_map_withholds_occupancy() {
        // Split mode: an observed unpaired mapping invalidates
        // occupancy (mapping/release evidence incomplete) while
        // copy rows keep their scoped coverage.
        let mut t: MappingTracker = MappingTracker::new();
        t.set_relation_split(true);
        t.consume(&attempt("op1", "dev1", 1)).unwrap();
        t.consume(&map("op1", true, "m1", 4096, 5000, 2)).unwrap();
        t.consume(&copy("op1", "m1", "original_to_bounce", 512, 3))
            .unwrap();
        let mut extra = map("op2", true, "m2", 4096, 5100, 4);
        extra.source_correlation = "unpaired".to_string();
        t.consume(&extra).unwrap();
        assert_eq!(t.unpaired_mapping_count(), 1);
        let rows = t.metrics("window [0,6000)", false).unwrap();
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        assert!(!global(&rows, "open_mappings").has_value);
        let o2b = global(&rows, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 512);
        assert_eq!(o2b.coverage, "complete_for_scope");
    }

    fn feed_prefix(t: &mut MappingTracker) {
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&copy("op1", "", "original_to_bounce", 4096, 2))
            .unwrap();
    }

    #[test]
    fn snapshot_replay_equivalence() {
        // Snapshotting mid-stream must not change the final result:
        // metrics() shares the finish reducers with no destructive
        // finalization.
        let mut snapshotted: MappingTracker = MappingTracker::new();
        feed_prefix(&mut snapshotted);
        let mid = snapshotted.metrics("window [0,1300000000)", false).unwrap();
        assert_eq!(global(&mid, "copy_original_to_bounce_bytes").value, 4096);
        snapshotted
            .consume(&map("op1", true, "m1", 4096, 1300000000, 3))
            .unwrap();
        let mut direct: MappingTracker = MappingTracker::new();
        feed_prefix(&mut direct);
        direct
            .consume(&map("op1", true, "m1", 4096, 1300000000, 3))
            .unwrap();
        let a = snapshotted.metrics("window [0,2300000000)", false).unwrap();
        let b = direct.metrics("window [0,2300000000)", false).unwrap();
        assert_eq!(a.len(), b.len());
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.has_value, y.has_value);
            if x.has_value {
                assert_eq!(x.value, y.value);
            }
        }
    }

    #[test]
    fn private_pool_bytes_not_exposure() {
        // A private-pool copy stays inside its direction total as a named
        // subset; no metric frames pool placement as exposure.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        let mut priv_ev = copy("op1", "", "original_to_bounce", 4096, 2);
        priv_ev.copy.pool_private = true;
        t.consume(&priv_ev).unwrap();
        t.consume(&copy("op1", "", "original_to_bounce", 1024, 3))
            .unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 5120);
        assert_eq!(global(&rows, "copy_private_pool_bytes").value, 4096);
        for m in &rows {
            assert!(!m.name.contains("exposure"));
        }
    }

    #[test]
    fn offset_past_count() {
        // Past-allocation copies count separately while their bytes stay in
        // the direction totals; the private subset stays absent at zero.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        let mut first = copy("op1", "", "original_to_bounce", 4096, 2);
        first.copy.offset_past_allocation = true;
        t.consume(&first).unwrap();
        let mut second = copy("op1", "", "bounce_to_original", 1024, 3);
        second.copy.offset_past_allocation = true;
        t.consume(&second).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_offset_past_allocation_count").value, 2);
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 4096);
        assert_eq!(global(&rows, "copy_bounce_to_original_bytes").value, 1024);
        assert!(!rows.iter().any(|m| m.name == "copy_private_pool_bytes"));
    }

    #[test]
    fn paired_copy_without_link_stays_unattributed() {
        // Paired but unattributable: no mapping link and no known
        // operation. Bytes stay in the global total with a note.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&copy("ghost-op", "", "original_to_bounce", 512, 2))
            .unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 512);
        assert!(
            t.limitations()
                .iter()
                .any(|n| n.contains("lack device attribution"))
        );
    }

    #[test]
    fn split_metrics_absent_when_zero() {
        // Plain copies emit exactly the legacy metric set: subset rows appear
        // only when nonzero.
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        t.consume(&copy("op1", "", "original_to_bounce", 4096, 2))
            .unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        assert_eq!(global(&rows, "copy_original_to_bounce_bytes").value, 4096);
        for m in &rows {
            assert!(!m.name.contains("private_pool"));
            assert!(!m.name.contains("offset_past"));
        }
    }

    fn cycle(t: &mut MappingTracker, op: &str, mapping: &str, dur: u64, base_seq: u64) {
        t.consume(&attempt(op, "d1", base_seq)).unwrap();
        t.consume(&map(op, true, mapping, 8, 1000000, base_seq + 1))
            .unwrap();
        t.consume(&unmap(mapping, 1000000 + dur, base_seq + 2))
            .unwrap();
    }

    #[test]
    fn histogram_vector() {
        // Contract vector: [1,2,3,4] -> count 4, floor mean 2,
        // estimated p50 3, estimated p99 7.
        let mut t: MappingTracker = MappingTracker::new();
        cycle(&mut t, "op1", "m1", 1, 1);
        cycle(&mut t, "op2", "m2", 2, 10);
        cycle(&mut t, "op3", "m3", 3, 20);
        cycle(&mut t, "op4", "m4", 4, 30);
        let rows = t.metrics("window [0,2000000)", false).unwrap();
        let count = global(&rows, "completed_lifetime_count");
        assert_eq!(count.value, 4);
        assert!(count.has_sample_count);
        assert_eq!(count.sample_count, 4);
        let mean = global(&rows, "lifetime_mean_ns");
        assert_eq!(mean.value, 2);
        assert_eq!(mean.aggregation, "mean");
        assert_eq!(mean.sample_count, 4);
        // Rank ceil(50*4/100)=2 lands on value 2 in [2,3]: edge 3.
        let p50 = global(&rows, "lifetime_p50_ns");
        assert_eq!(p50.value, 3);
        assert_eq!(p50.measurement, "estimated");
        // Rank ceil(99*4/100)=4 lands on value 4 in [4,7]: edge 7.
        let p99 = global(&rows, "lifetime_p99_ns");
        assert_eq!(p99.value, 7);
        assert_eq!(p99.measurement, "estimated");
        assert_eq!(global(&rows, "lifetime_min_ns").value, 1);
        assert_eq!(global(&rows, "lifetime_max_ns").value, 4);
    }

    #[test]
    fn open_excluded_from_samples() {
        let mut t: MappingTracker = MappingTracker::new();
        cycle(&mut t, "op1", "m1", 10, 1);
        t.consume(&attempt("op2", "d1", 10)).unwrap();
        t.consume(&map("op2", true, "m2", 8, 1000000, 11)).unwrap();
        let rows = t.metrics("window [0,2000000)", false).unwrap();
        assert_eq!(global(&rows, "completed_lifetime_count").value, 1);
        assert_eq!(global(&rows, "lifetime_mean_ns").value, 10);
        assert_eq!(global(&rows, "open_mappings").value, 1);
    }

    #[test]
    fn uncertain_excluded_from_samples() {
        let mut t: MappingTracker = MappingTracker::new();
        cycle(&mut t, "op1", "m1", 10, 1);
        t.consume(&attempt("op2", "d1", 10)).unwrap();
        t.consume(&map("op2", true, "m2", 8, 9000000, 11)).unwrap();
        t.consume(&unmap("m2", 100, 12)).unwrap();
        let rows = t.metrics("window [0,10000000)", false).unwrap();
        assert_eq!(global(&rows, "completed_lifetime_count").value, 1);
        assert_eq!(global(&rows, "lifetime_mean_ns").value, 10);
        assert_eq!(global(&rows, "lifetime_mean_ns").coverage, "partial");
    }

    #[test]
    fn empty_lifetimes_unavailable() {
        let mut t: MappingTracker = MappingTracker::new();
        t.consume(&attempt("op1", "d1", 1)).unwrap();
        let rows = t.metrics("window [0,1000)", false).unwrap();
        let count = global(&rows, "completed_lifetime_count");
        assert!(!count.has_value);
        assert_eq!(count.measurement, "unavailable");
        let mean = global(&rows, "lifetime_mean_ns");
        assert!(!mean.has_value);
        assert_eq!(mean.measurement, "unavailable");
        assert!(!mean.notes.is_empty());
    }

    fn map_metrics(dir: &str) -> Vec<Metric> {
        use crate::capture::reader::{default_limits, read_capture};
        let path = format!("{}/{dir}", env!("CARGO_MANIFEST_DIR"));
        let mut r = read_capture(&path, false, default_limits()).expect("read capture");
        let mut t: MappingTracker = MappingTracker::new();
        while r.has_more().expect("has_more") {
            t.consume(&r.next_event().expect("next")).unwrap();
        }
        t.metrics("window [0,2500000000)", false).unwrap()
    }

    #[test]
    fn open_mapping_censored_not_leaked() {
        let rows = map_metrics("tests/fixtures/lifecycle/open-at-end");
        let live = global(&rows, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert!(!global(&rows, "completed_lifetime_count").has_value);
    }

    #[test]
    fn gap_with_open_mapping_withholds_live() {
        let rows = map_metrics("tests/fixtures/lifecycle/quality-gap-open");
        assert!(!global(&rows, "live_observed_allocation_bytes").has_value);
        assert!(!global(&rows, "completed_lifetime_count").has_value);
    }
}
