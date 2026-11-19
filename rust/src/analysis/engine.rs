// SPDX-License-Identifier: GPL-3.0-or-later
//! Composed analysis engine: attempts plus lifecycle plus pools plus regions.
//!
//! The analyzer feeds one event stream to every tracker and merges
//! their rows into one report. Attempts-only captures keep exactly
//! their old rows and notes; lifecycle, pool, and region rows
//! appear only with observed evidence, and the scope note switches
//! to the extended wording exactly then. Snapshot and finish share
//! every tracker reducer with no destructive finalization: consumed
//! loss latches tracker state monotonically, while a partial call
//! overlays its call-local uncertainty on the returned view only,
//! so a partial snapshot cannot alter later facts. The merged row
//! set never exceeds the 4096-row external budget: any excess is
//! withheld deterministically (tracker order, then row order) with
//! a visible limitation.

use super::attempts::{AttemptAnalyzer, window_label};
use super::mappings::MappingTracker;
use super::pools::PoolTracker;
use super::regions::RegionTracker;
use crate::capture::correlation::rollup_correlation;
use crate::model::event::Event;
use crate::model::metric::Metric;
use crate::model::report::Report;
use crate::model::session::{Channel, Session, truncate_codepoints};

/// Merged metric-row budget.
pub const MAX_REPORT_METRICS: usize = 4096;
/// Merged limitation-note budget.
pub const MAX_REPORT_LIMITATIONS: usize = 256;
const MAX_NOTE_CODEPOINTS: usize = 1024;

/// One composed-analysis failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineError {
    /// Human-readable failure.
    pub message: String,
}

impl EngineError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for EngineError {}

/// Cap one limitation at 1024 codepoints, on a char boundary.
pub fn truncate_note(text: &str) -> String {
    truncate_codepoints(text, MAX_NOTE_CODEPOINTS)
}

/// Row prefix plus the deterministic withheld count.
#[derive(Debug, Clone)]
pub struct TruncatedRows {
    /// Kept rows.
    pub rows: Vec<Metric>,
    /// Rows withheld by the budget.
    pub withheld: usize,
}

/// Keep mandatory evidence rows before optional device detail.
///
/// Rows without a device id (global measurements and per-pool
/// diagnostic evidence) hold the diagnosis and exit inputs, so
/// they receive budget first in merge order; per-device detail
/// rows fill whatever budget remains, also in merge order. No
/// finding derives from a per-device row, so omitting device
/// detail can never suppress a positive. When mandatory rows
/// alone exceed the budget, the first budget mandatory rows
/// win; that degenerate case keeps the row bound but may
/// still omit evidence. At or under budget every row is kept
/// in merge order, so small reports never reorder.
pub fn budget_rows(rows: &[Metric], budget: i64) -> TruncatedRows {
    if rows.len() as i64 <= budget {
        return truncate_rows(rows, budget);
    }
    let mut out = TruncatedRows {
        rows: Vec::new(),
        withheld: 0,
    };
    let mut room = budget;
    if room < 0 {
        room = 0;
    }
    for m in rows {
        if room <= 0 {
            break;
        }
        if m.has_device_id {
            continue;
        }
        out.rows.push(m.clone());
        room -= 1;
    }
    for m in rows {
        if room <= 0 {
            break;
        }
        if !m.has_device_id {
            continue;
        }
        out.rows.push(m.clone());
        room -= 1;
    }
    out.withheld = rows.len() - out.rows.len();
    out
}

/// Cap tracker notes to the schema budget, keeping disclosure.
///
/// Tracker notes share one 256-note budget: keep the first
/// notes in merge order and summarize the rest. When rows
/// were withheld, their disclosure reserves the last slot so
/// the omission notice always survives capping.
pub fn finalize_limitations(notes: &[String], withheld_rows: usize) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut room = MAX_REPORT_LIMITATIONS as i64;
    let mut extra = String::new();
    if withheld_rows > 0 {
        extra = format!("{withheld_rows} metric rows withheld (4096-row report budget).");
        room -= 1;
    }
    if notes.len() as i64 > room {
        for n in notes.iter().take((room - 1) as usize) {
            out.push(n.clone());
        }
        let dropped = notes.len() as i64 - (room - 1);
        out.push(format!(
            "{dropped} further limitations withheld (256-note report budget)."
        ));
    } else {
        out.extend(notes.iter().cloned());
    }
    if !extra.is_empty() {
        out.push(extra);
    }
    out
}

/// Keep the first budget rows in order; count the rest.
pub fn truncate_rows(rows: &[Metric], budget: i64) -> TruncatedRows {
    let mut out = TruncatedRows {
        rows: Vec::new(),
        withheld: 0,
    };
    let mut keep = rows.len() as i64;
    if keep > budget {
        keep = budget;
    }
    if keep < 0 {
        keep = 0;
    }
    out.rows.extend(rows.iter().take(keep as usize).cloned());
    out.withheld = rows.len() - keep as usize;
    out
}

fn fold_class_count(ch: &mut Channel, observed: usize, noun_phrase: &str) {
    // Fold an exact observed count into one report class.
    //
    // A producer-complete class turns partial with the exact
    // count; any other class keeps its claim and appends the
    // exact observed count, bounded to the channel limit.
    let note = format!("{observed} unpaired {noun_phrase}");
    if ch.status == "complete_for_scope" {
        ch.reason = note;
    } else {
        ch.reason = truncate_codepoints(&format!("{}; {note}", ch.reason), 512);
    }
    ch.status = "partial".to_string();
    ch.has_loss_count = true;
    ch.loss_count = observed as u64;
}

/// One-stream, four-tracker composed reducer.
#[derive(Debug, Clone)]
pub struct Analyzer {
    attempts: AttemptAnalyzer,
    mappings: MappingTracker,
    pools: PoolTracker,
    regions: RegionTracker,
    session: Session,
}

impl Analyzer {
    /// Empty reducer over one session's claims.
    pub fn new(session: Session) -> Self {
        let mut mappings: MappingTracker = MappingTracker::new();
        mappings.set_relation_split(session.has_corr_relations);
        let status = session.cap_region_state.status.as_str();
        let admitted = status == "verified" || status == "partial";
        let mut regions: RegionTracker = RegionTracker::new(admitted, session.baseline_complete);
        regions.seed_baseline(&session.baseline_regions);
        Self {
            attempts: AttemptAnalyzer::new(session.clone()),
            mappings,
            pools: PoolTracker::new(),
            regions,
            session,
        }
    }

    /// Fold one event into every tracker.
    pub fn consume(&mut self, ev: &Event) -> Result<(), EngineError> {
        self.attempts.consume(ev);
        self.mappings
            .consume(ev)
            .map_err(|e| EngineError::new(e.message))?;
        self.pools.consume(ev);
        self.regions.consume(ev);
        Ok(())
    }

    /// Reduce the stream so far; the horizon may narrow.
    pub fn snapshot(&mut self, end_ns: u64, partial: bool) -> Result<Report, EngineError> {
        self.merge(end_ns, partial, false)
    }

    /// Reduce the whole capture; the horizon must match.
    pub fn finish(&mut self, end_ns: u64, partial: bool) -> Result<Report, EngineError> {
        self.merge(end_ns, partial, true)
    }

    fn fold_observed_unpaired(&self, rep: &mut Report) {
        // Fold analyzer-observed unpaired counts into relations.
        //
        // Report-side classes carry exact per-class counts plus an
        // aggregate total. A producer-complete class with observed
        // unpaired events turns partial with the exact count; a
        // producer-non-complete class keeps its claim and appends
        // the exact observed count.
        let um = self.mappings.unpaired_mapping_count();
        let uc = self.mappings.unpaired_copy_count();
        let us = self.mappings.unpaired_sync_count();
        let mut mapping = rep.q_corr_mapping.clone();
        let mut copy = rep.q_corr_copy.clone();
        let mut sync = rep.q_corr_sync.clone();
        if um > 0 {
            fold_class_count(
                &mut mapping,
                um,
                "mapping or release events excluded from pairing-dependent totals; independent facts retained.",
            );
        }
        let map_causes = vec![mapping.reason.clone()];
        if uc > 0 {
            fold_class_count(
                &mut copy,
                uc,
                "copy events excluded from copy attribution; independent facts retained.",
            );
        }
        let copy_causes = vec![copy.reason.clone()];
        if us > 0 {
            fold_class_count(
                &mut sync,
                us,
                "sync events excluded from sync attribution; independent facts retained.",
            );
        }
        let sync_causes = vec![sync.reason.clone()];
        let mut aggregate = rollup_correlation(
            &mapping,
            &copy,
            &sync,
            &map_causes,
            &copy_causes,
            &sync_causes,
        );
        aggregate.has_loss_count = true;
        aggregate.loss_count = (um + uc + us) as u64;
        rep.q_correlation = aggregate;
        rep.q_corr_mapping = mapping;
        rep.q_corr_copy = copy;
        rep.q_corr_sync = sync;
    }

    fn merge(&mut self, end_ns: u64, partial: bool, strict: bool) -> Result<Report, EngineError> {
        let has_pools = self.pools.sees_pools();
        let has_regions = self.regions.sees_regions();
        let mut rep: Report;
        if strict {
            rep = self
                .attempts
                .finish(end_ns, partial, has_pools, has_regions)
                .map_err(|e| EngineError::new(e.message))?;
        } else {
            rep = self
                .attempts
                .snapshot(end_ns, partial, has_pools, has_regions)
                .map_err(|e| EngineError::new(e.message))?;
        }
        // The attempt reducer folds observed gaps, recovered
        // tails, and producer claims into the quality channels;
        // trackers only see events, so loss the stream never
        // shows is propagated here before any tracker rows emit.
        // Consumed detail loss latches tracker state
        // monotonically: observed gaps already folded at consume
        // time, producer claims echoed here. The call-local
        // dropped tail never latches; it renders as a view
        // overlay in this report only, so a partial snapshot
        // cannot alter later facts.
        if self.session.q_detail.status != "complete_for_scope" {
            self.mappings.note_detail_loss();
            self.regions.note_detail_loss();
            self.pools.note_detail_loss();
        }
        if self.mappings.sees_lifecycle() {
            if self.session.has_corr_relations {
                if rep.q_corr_mapping.status != "complete_for_scope" {
                    // A mapping_release partial fully explained
                    // by observed pre-window releases keeps
                    // in-window live state; only the peak (whose
                    // pre-window occupancy is unknown) is
                    // withheld by the tracker.
                    if !self.mappings.pre_window_explains_mapping_release() {
                        self.mappings.note_correlation_loss();
                    }
                }
                if rep.q_corr_copy.status != "complete_for_scope" {
                    self.mappings.note_copy_attribution_loss();
                }
                if rep.q_corr_sync.status != "complete_for_scope" {
                    self.mappings.note_sync_attribution_loss();
                }
            } else if rep.q_correlation.status != "complete_for_scope" {
                self.mappings.note_correlation_loss();
            }
        }
        if rep.q_baseline.status != "complete_for_scope"
            && rep.q_baseline.status != "not_applicable"
        {
            self.regions.note_baseline_loss();
        }
        let window = window_label(self.session.window_start_ns, end_ns);
        if self.mappings.sees_lifecycle() {
            let mrows = self
                .mappings
                .metrics_horizon(&window, end_ns, partial)
                .map_err(|e| EngineError::new(e.message))?;
            rep.metrics.extend(mrows);
            rep.limitations.extend(self.mappings.limitations());
        }
        if self.pools.sees_pools() {
            rep.metrics.extend(self.pools.metrics(&window, partial));
            rep.limitations.extend(self.pools.limitations());
        }
        if self.regions.sees_regions() {
            rep.metrics.extend(self.regions.metrics(&window, partial));
            rep.limitations.extend(self.regions.limitations());
        }
        let unpaired = self.mappings.unpaired_count();
        if unpaired > 0 && self.session.has_corr_relations {
            self.fold_observed_unpaired(&mut rep);
        }
        if unpaired > 0 && !self.session.has_corr_relations {
            rep.q_correlation.status = "partial".to_string();
            rep.q_correlation.has_loss_count = true;
            rep.q_correlation.loss_count = unpaired as u64;
            rep.q_correlation.scope = "correlated lifecycle events".to_string();
            rep.q_correlation.reason = format!(
                "{unpaired} unpaired lifecycle events excluded from pairing-dependent totals; independent facts retained."
            );
        }
        if unpaired > 0 {
            // Observed pairing evidence as a row: diagnosis
            // derives its finding from this count, never from
            // channel loss alone.
            rep.metrics.push(Metric {
                name: "unpaired_lifecycle_events".to_string(),
                has_value: true,
                value: unpaired as u64,
                unit: "count".to_string(),
                confidence: "high".to_string(),
                measurement: "observed".to_string(),
                coverage: "partial".to_string(),
                has_aggregation: true,
                aggregation: "counter".to_string(),
                scope: format!("{window}; observed mappings"),
                notes: "Lifecycle events the correlator left unpaired; excluded from pairing-dependent state, independent facts retained."
                    .to_string(),
                ..Default::default()
            });
        }
        let mut withheld_rows = 0;
        if rep.metrics.len() > MAX_REPORT_METRICS {
            let cut = budget_rows(&rep.metrics, MAX_REPORT_METRICS as i64);
            withheld_rows = cut.withheld;
            rep.metrics = cut.rows;
        }
        // Merged tracker notes share one 256-note schema budget;
        // the row-budget disclosure keeps the last slot, then
        // every note is capped at 1024 codepoints.
        rep.limitations = finalize_limitations(&rep.limitations.clone(), withheld_rows);
        for n in rep.limitations.iter_mut() {
            *n = truncate_note(n);
        }
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::reader::{default_limits, read_capture};
    use crate::model::event::Event;
    use crate::model::metric::Metric;
    use crate::model::report::Report;
    use crate::model::session::{Channel, Session};

    fn fixture(rel: &str) -> String {
        format!("{}/../{rel}", env!("CARGO_MANIFEST_DIR"))
    }

    fn channel(status: &str, loss: bool) -> Channel {
        Channel {
            status: status.to_string(),
            has_loss_count: loss,
            loss_count: 0,
            scope: "sc".to_string(),
            reason: "rs".to_string(),
            ..Default::default()
        }
    }

    fn session() -> Session {
        Session {
            session_id: "eng".to_string(),
            synthetic: true,
            product_version: "0.0.0".to_string(),
            env_mode: "unknown".to_string(),
            env_detection: "unverified".to_string(),
            env_attestation: "not_performed".to_string(),
            capture_mode: "replay".to_string(),
            window_start_ns: 0,
            window_end_ns: 2300000000,
            finalized: true,
            q_detail: channel("complete_for_scope", true),
            q_aggregate: channel("complete_for_scope", true),
            q_correlation: channel("complete_for_scope", true),
            q_baseline: channel("not_applicable", false),
            q_terminal: channel("complete_for_scope", false),
            ..Default::default()
        }
    }

    fn base(kind: &str, seq: u64, ts: u64) -> Event {
        Event {
            session_id: "eng".to_string(),
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

    fn attempt(op: &str, seq: u64) -> Event {
        let mut ev = base("bounce_attempt", seq, 500);
        ev.bounce.device_id = "d1".to_string();
        ev.bounce.requested_bytes = 4096;
        ev.bounce.forced = false;
        ev.bounce.operation_id = op.to_string();
        ev
    }

    fn map(op: &str, mapping: &str, ts: u64, seq: u64) -> Event {
        let mut ev = base("map_result", seq, ts);
        ev.map_result.operation_id = op.to_string();
        ev.map_result.success = true;
        ev.map_result.has_mapping_id = true;
        ev.map_result.mapping_id = mapping.to_string();
        ev.map_result.has_mapped_bytes = true;
        ev.map_result.mapped_bytes = 4096;
        ev
    }

    fn copy(op: &str, n: u64, seq: u64) -> Event {
        let mut ev = base("copy", seq, 600 + seq);
        ev.copy.operation_id = op.to_string();
        ev.copy.direction = "original_to_bounce".to_string();
        ev.copy.bytes = n;
        ev
    }

    fn unmap(mapping: &str, ts: u64, seq: u64) -> Event {
        let mut ev = base("unmap", seq, ts);
        ev.unmap.has_mapping_id = true;
        ev.unmap.mapping_id = mapping.to_string();
        ev
    }

    fn sync(op: &str, mapping: &str, seq: u64) -> Event {
        let mut ev = base("sync_request", seq, 700 + seq);
        ev.sync.operation_id = op.to_string();
        ev.sync.has_mapping_id = true;
        ev.sync.mapping_id = mapping.to_string();
        ev.sync.has_offset = true;
        ev.sync.offset = 0;
        ev.sync.length = 1024;
        ev
    }

    fn pool(pool: &str, used: u64, cap: u64, seq: u64) -> Event {
        let mut ev = base("pool_sample", seq, 700 + seq);
        ev.pool.pool_id = pool.to_string();
        ev.pool.has_used = true;
        ev.pool.used_bytes = used;
        ev.pool.has_capacity = true;
        ev.pool.capacity_bytes = cap;
        ev.pool.unit = "bytes".to_string();
        ev
    }

    fn region_session() -> Session {
        let mut s = session();
        s.cap_conversion_results.status = "verified".to_string();
        s.cap_conversion_results.reason = "test".to_string();
        s.cap_region_state.status = "verified".to_string();
        s.cap_region_state.reason = "test".to_string();
        s.baseline_complete = true;
        s
    }

    fn transition(region: &str, state: &str, seq: u64) -> Event {
        let mut ev = base("transition_result", seq, 800 + seq);
        ev.transition.region_id = region.to_string();
        ev.transition.requested_state = state.to_string();
        ev.transition.success = true;
        ev.transition.has_return_code = true;
        ev.transition.return_code = 0;
        ev.transition.offset = 0;
        ev.transition.length = 8192;
        ev.transition.has_address_space = true;
        ev.transition.address_space = "guest_physical".to_string();
        ev.transition.has_resolution = true;
        ev.transition.resolution = "resolved".to_string();
        ev
    }

    fn gap(channel: &str, seq: u64) -> Event {
        let mut ev = base("gap", seq, 900);
        ev.gap.channel = channel.to_string();
        ev.gap.has_lost_count = true;
        ev.gap.lost_count = 2;
        ev.gap.reason = "test gap".to_string();
        ev.gap.window_start_ns = 0;
        ev.gap.window_end_ns = 900;
        ev
    }

    fn count(rows: &[Metric], name: &str) -> usize {
        rows.iter().filter(|m| m.name == name).count()
    }

    fn names(rows: &[Metric], want: &str) -> bool {
        rows.iter().any(|m| m.name == want)
    }

    fn find<'a>(rows: &'a [Metric], name: &str) -> &'a Metric {
        rows.iter()
            .find(|m| m.name == name && !m.has_device_id && !m.has_pool_id)
            .unwrap_or_else(|| panic!("metric not found: {name}"))
    }

    fn find_pool<'a>(rows: &'a [Metric], name: &str, pool: &str) -> &'a Metric {
        rows.iter()
            .find(|m| m.name == name && m.has_pool_id && m.pool_id == pool)
            .unwrap_or_else(|| panic!("pool metric not found: {name}"))
    }

    fn feed_nested(a: &mut Analyzer) {
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&copy("op1", 4096, 2)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 3)).unwrap();
        a.consume(&unmap("m1", 2300000000, 4)).unwrap();
    }

    fn split_copy_session() -> Session {
        let mut s = session();
        s.q_correlation.status = "partial".to_string();
        s.q_correlation.has_loss_count = false;
        s.q_correlation.loss_count = 0;
        s.q_correlation.reason =
            "copy_attribution partial (copy without pending operation)".to_string();
        s.has_corr_relations = true;
        s.q_corr_mapping.status = "complete_for_scope".to_string();
        s.q_corr_mapping.has_loss_count = true;
        s.q_corr_mapping.loss_count = 0;
        s.q_corr_mapping.scope = "mapping and release pairing".to_string();
        s.q_corr_mapping.reason = "test: every mapping pairs".to_string();
        s.q_corr_copy.status = "partial".to_string();
        s.q_corr_copy.has_loss_count = false;
        s.q_corr_copy.scope = "copy attribution".to_string();
        s.q_corr_copy.reason = "test: copy without pending operation".to_string();
        s.q_corr_sync.status = "complete_for_scope".to_string();
        s.q_corr_sync.has_loss_count = true;
        s.q_corr_sync.loss_count = 0;
        s.q_corr_sync.scope = "sync attribution".to_string();
        s.q_corr_sync.reason = "test: every sync pairs".to_string();
        s
    }

    fn split_mapping_session() -> Session {
        let mut s = session();
        s.q_correlation.status = "partial".to_string();
        s.q_correlation.has_loss_count = false;
        s.q_correlation.loss_count = 0;
        s.q_correlation.reason = "mapping_release partial (release of unknown mapping)".to_string();
        s.has_corr_relations = true;
        s.q_corr_mapping.status = "partial".to_string();
        s.q_corr_mapping.has_loss_count = false;
        s.q_corr_mapping.scope = "mapping and release pairing".to_string();
        s.q_corr_mapping.reason = "test: release of unknown mapping".to_string();
        s.q_corr_copy.status = "complete_for_scope".to_string();
        s.q_corr_copy.has_loss_count = true;
        s.q_corr_copy.loss_count = 0;
        s.q_corr_copy.scope = "copy attribution".to_string();
        s.q_corr_copy.reason = "test: every copy pairs".to_string();
        s.q_corr_sync.status = "complete_for_scope".to_string();
        s.q_corr_sync.has_loss_count = true;
        s.q_corr_sync.loss_count = 0;
        s.q_corr_sync.scope = "sync attribution".to_string();
        s.q_corr_sync.reason = "test: every sync pairs".to_string();
        s
    }

    fn split_complete_session() -> Session {
        let mut s = session();
        s.has_corr_relations = true;
        s.q_corr_mapping.status = "complete_for_scope".to_string();
        s.q_corr_mapping.has_loss_count = true;
        s.q_corr_mapping.loss_count = 0;
        s.q_corr_mapping.scope = "mapping and release pairing".to_string();
        s.q_corr_mapping.reason = "test: every mapping pairs".to_string();
        s.q_corr_copy.status = "complete_for_scope".to_string();
        s.q_corr_copy.has_loss_count = true;
        s.q_corr_copy.loss_count = 0;
        s.q_corr_copy.scope = "copy attribution".to_string();
        s.q_corr_copy.reason = "test: every copy pairs".to_string();
        s.q_corr_sync.status = "complete_for_scope".to_string();
        s.q_corr_sync.has_loss_count = true;
        s.q_corr_sync.loss_count = 0;
        s.q_corr_sync.scope = "sync attribution".to_string();
        s.q_corr_sync.reason = "test: every sync pairs".to_string();
        s
    }

    #[test]
    fn split_producer_copy_loss_preserves_occupancy() {
        // Producer copy-attribution-only loss with every event
        // paired: occupancy stays valued with complete mapping
        // coverage; copy rows degrade.
        let mut a = Analyzer::new(split_copy_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&copy("op1", 512, 3)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "complete_for_scope");
        let o2b = find(&rep.metrics, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 512);
        assert_eq!(o2b.coverage, "partial");
        assert!(rep.has_corr_relations);
        assert_eq!(rep.q_corr_mapping.status, "complete_for_scope");
        assert!(rep.q_corr_mapping.has_loss_count);
        assert_eq!(rep.q_corr_copy.status, "partial");
        assert_eq!(rep.q_corr_sync.status, "complete_for_scope");
        assert_eq!(rep.q_correlation.status, "partial");
    }

    #[test]
    fn split_producer_mapping_loss_withholds_occupancy() {
        // Producer mapping/release loss withholds occupancy even
        // though every observed event pairs; copy rows stay valued
        // with complete coverage.
        let mut a = Analyzer::new(split_mapping_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&copy("op1", 512, 3)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
        let o2b = find(&rep.metrics, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 512);
        assert_eq!(o2b.coverage, "complete_for_scope");
        assert!(rep.has_corr_relations);
        assert_eq!(rep.q_corr_mapping.status, "partial");
        assert_eq!(rep.q_corr_copy.status, "complete_for_scope");
    }

    #[test]
    fn split_pre_window_release_keeps_live_withholds_peak() {
        // Producer mapping_release partial explained by an
        // observed paired release of an unknown mapping: the
        // expected pre-window class keeps in-window live state
        // valued with partial coverage; only the peak (whose
        // pre-window occupancy is unknown) is withheld.
        let mut a = Analyzer::new(split_mapping_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&unmap("ghost", 1400000000, 3)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "partial");
        let opened = find(&rep.metrics, "open_mappings");
        assert!(opened.has_value);
        assert_eq!(opened.value, 1);
        let peak = find(&rep.metrics, "peak_live_observed_allocation_bytes");
        assert!(!peak.has_value);
        assert!(
            peak.notes.contains("without an observed map"),
            "{}",
            peak.notes
        );
        assert_eq!(rep.q_corr_mapping.status, "partial");
        assert!(rep.limitations.iter().any(|n| n.contains("pre-window")));
    }

    #[test]
    fn split_detail_loss_degrades_copy_and_sync_rows() {
        // Replay probe: split relations with complete pairing
        // claims plus producer-declared detail loss labels copy
        // bytes and sync requests partial.
        let mut s = split_complete_session();
        s.q_detail.status = "partial".to_string();
        s.q_detail.has_loss_count = false;
        s.q_detail.reason = "test: producer detail loss".to_string();
        let mut a = Analyzer::new(s);
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&copy("op1", 1024, 3)).unwrap();
        a.consume(&sync("op1", "m1", 4)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
        let o2b = find(&rep.metrics, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 1024);
        assert_eq!(o2b.coverage, "partial");
        let syncs = find(&rep.metrics, "sync_requests");
        assert_eq!(syncs.value, 1);
        assert_eq!(syncs.coverage, "partial");
    }

    #[test]
    fn split_observed_mapping_loss_withholds_occupancy() {
        // Replay probe: complete split headers, one known open
        // mapping, one additional unpaired successful map_result:
        // mapping_release turns partial and every occupancy row
        // is withheld while attribution classes stay complete.
        let mut a = Analyzer::new(split_complete_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        let mut extra = map("op2", "m2", 1400000000, 3);
        extra.source_correlation = "unpaired".to_string();
        a.consume(&extra).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
        assert!(!find(&rep.metrics, "open_mappings").has_value);
        assert!(!find(&rep.metrics, "peak_live_observed_allocation_bytes").has_value);
        assert!(!find(&rep.metrics, "oldest_open_mapping_age_ns").has_value);
        assert!(!find(&rep.metrics, "allocation_byte_microseconds").has_value);
        assert_eq!(rep.q_corr_mapping.status, "partial");
        assert!(rep.q_corr_mapping.has_loss_count);
        assert_eq!(rep.q_corr_mapping.loss_count, 1);
        assert_eq!(rep.q_corr_copy.status, "complete_for_scope");
        assert_eq!(rep.q_corr_sync.status, "complete_for_scope");
    }

    #[test]
    fn split_contradictory_aggregate_recomputed() {
        // A split header claiming a complete aggregate over a
        // partial class is recomputed: with no gaps and no
        // observed unpaired events the analyzer aggregate is
        // partial and the incompleteness is found.
        let mut s = split_copy_session();
        s.q_correlation.status = "complete_for_scope".to_string();
        s.q_correlation.has_loss_count = true;
        s.q_correlation.loss_count = 0;
        s.q_correlation.reason = "all lifecycle events paired".to_string();
        let mut a = Analyzer::new(s);
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&copy("op1", 512, 3)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(rep.q_correlation.status, "partial");
        assert_eq!(rep.q_corr_copy.status, "partial");
        assert_eq!(rep.findings.len(), 1);
        assert_eq!(rep.findings[0].code, "CAPTURE_INCOMPLETE");
    }

    fn analyze_fixture(dir: &str) -> Report {
        let mut r = read_capture(&fixture(dir), false, default_limits()).expect("read capture");
        let mut a = Analyzer::new(r.session.clone());
        while r.has_more().expect("has_more") {
            a.consume(&r.next_event().expect("next")).unwrap();
        }
        let end = r.session.window_end_ns;
        let partial = r.partial;
        a.finish(end, partial).expect("finish")
    }

    #[test]
    fn fixture_copy_only_preserves_occupancy() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-copy-only");
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "complete_for_scope");
        let o2b = find(&rep.metrics, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 5120);
        assert_eq!(o2b.coverage, "partial");
        let syncs = find(&rep.metrics, "sync_requests");
        assert_eq!(syncs.value, 1);
        assert_eq!(syncs.coverage, "complete_for_scope");
        assert!(rep.has_corr_relations);
        assert_eq!(rep.q_corr_mapping.status, "complete_for_scope");
        assert!(rep.q_corr_mapping.has_loss_count);
        assert_eq!(rep.q_corr_mapping.loss_count, 0);
        assert_eq!(rep.q_corr_copy.status, "partial");
        assert!(rep.q_corr_copy.has_loss_count);
        assert_eq!(rep.q_corr_copy.loss_count, 1);
        assert_eq!(rep.q_corr_sync.status, "complete_for_scope");
        assert_eq!(rep.q_correlation.status, "partial");
        assert!(rep.q_correlation.has_loss_count);
        assert_eq!(rep.q_correlation.loss_count, 1);
    }

    #[test]
    fn fixture_lost_release_withholds_occupancy() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-lost-release");
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
        assert!(!find(&rep.metrics, "open_mappings").has_value);
        let o2b = find(&rep.metrics, "copy_original_to_bounce_bytes");
        assert_eq!(o2b.value, 5120);
        assert_eq!(o2b.coverage, "complete_for_scope");
        assert!(rep.has_corr_relations);
        assert_eq!(rep.q_corr_mapping.status, "partial");
        assert!(rep.q_corr_mapping.has_loss_count);
        assert_eq!(rep.q_corr_mapping.loss_count, 1);
        assert_eq!(rep.q_corr_copy.status, "complete_for_scope");
        assert_eq!(rep.q_corr_sync.status, "complete_for_scope");
    }

    #[test]
    fn fixture_legacy_copy_degrades_coarsely() {
        // Legacy 0.1.1 header claims complete correlation but the
        // stream holds an unpaired copy: every mapping-row family
        // degrades, exactly as before relation classes existed.
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-legacy-copy");
        assert!(!rep.has_corr_relations);
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 0);
        assert_eq!(live.coverage, "partial");
        assert_eq!(
            find(&rep.metrics, "successful_allocations").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "copy_original_to_bounce_bytes").coverage,
            "partial"
        );
        assert_eq!(rep.q_correlation.status, "partial");
        assert!(rep.q_correlation.has_loss_count);
        assert_eq!(rep.q_correlation.loss_count, 1);
    }

    #[test]
    fn fixture_legacy_sync_degrades_coarsely() {
        let rep = analyze_fixture("tests/fixtures/lifecycle/relations-legacy-sync");
        assert!(!rep.has_corr_relations);
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 0);
        assert_eq!(live.coverage, "partial");
        assert_eq!(find(&rep.metrics, "sync_requests").coverage, "partial");
        assert_eq!(rep.q_correlation.status, "partial");
        assert_eq!(rep.q_correlation.loss_count, 1);
    }

    #[test]
    fn fixture_gap_open_still_withholds() {
        // Independent safeguards stay authoritative: complete
        // correlation with detail loss still withholds live state.
        let rep = analyze_fixture("tests/fixtures/lifecycle/quality-gap-open");
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
    }

    #[test]
    fn fixture_reordered_peak_still_withheld() {
        // Complete correlation with unproven peak order still
        // withholds the peak while settled state stays valued.
        let rep = analyze_fixture("tests/fixtures/lifecycle/reordered-peak");
        assert!(!find(&rep.metrics, "peak_live_observed_allocation_bytes").has_value);
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 0);
    }

    #[test]
    fn merged_rows() {
        let mut a = Analyzer::new(session());
        feed_nested(&mut a);
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(find(&rep.metrics, "bounce_attempts").value, 1);
        assert_eq!(find(&rep.metrics, "successful_allocations").value, 1);
        assert_eq!(
            find(&rep.metrics, "copy_original_to_bounce_bytes").value,
            4096
        );
        assert_eq!(
            find(&rep.metrics, "live_observed_allocation_bytes").value,
            0
        );
        // No pool source: pool placeholders stay unavailable.
        assert!(!find(&rep.metrics, "pool_used_bytes").has_value);
    }

    #[test]
    fn pool_rows_gated() {
        let mut a = Analyzer::new(session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&pool("p1", 900, 1000, 2)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert!(names(&rep.metrics, "pool_used_bytes"));
        // No lifecycle source: the attempts placeholders stay null
        // and no tracker rows appear.
        assert!(!find(&rep.metrics, "successful_allocations").has_value);
        assert!(!find(&rep.metrics, "copy_original_to_bounce_bytes").has_value);
    }

    #[test]
    fn attempts_only_unchanged() {
        let mut a = Analyzer::new(session());
        a.consume(&attempt("op1", 1)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        // Placeholders stay unavailable; no valued tracker rows appear.
        assert!(!find(&rep.metrics, "successful_allocations").has_value);
        assert!(!find(&rep.metrics, "pool_used_bytes").has_value);
        assert!(!find(&rep.metrics, "copy_original_to_bounce_bytes").has_value);
        assert!(!find(&rep.metrics, "live_observed_allocation_bytes").has_value);
        assert!(
            rep.limitations
                .iter()
                .any(|n| n.contains("reduces bounce attempts"))
        );
    }

    #[test]
    fn snapshot_finish_equivalence() {
        let mut a = Analyzer::new(session());
        feed_nested(&mut a);
        let snap = a.snapshot(2300000000, false).unwrap();
        let fin = a.finish(2300000000, false).unwrap();
        assert_eq!(snap.metrics.len(), fin.metrics.len());
        for (s, f) in snap.metrics.iter().zip(fin.metrics.iter()) {
            assert_eq!(s.name, f.name);
            assert_eq!(s.has_value, f.has_value);
            if s.has_value {
                assert_eq!(s.value, f.value);
            }
        }
    }

    #[test]
    fn snapshot_narrowed_ok_finish_strict() {
        let mut a = Analyzer::new(session());
        a.consume(&attempt("op1", 1)).unwrap();
        let snap = a.snapshot(1000000000, false).unwrap();
        assert_eq!(snap.window_end_ns, 1000000000);
        assert!(a.finish(1000000000, false).is_err());
    }

    #[test]
    fn unpaired_degrades_correlation() {
        let mut a = Analyzer::new(session());
        let mut ev = map("op1", "m1", 100, 1);
        ev.source_correlation = "unpaired".to_string();
        a.consume(&ev).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(rep.q_correlation.status, "partial");
    }

    #[test]
    fn unpaired_events_emit_metric() {
        let mut a = Analyzer::new(session());
        let mut ev = map("op1", "m1", 100, 1);
        ev.source_correlation = "unpaired".to_string();
        a.consume(&ev).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        let row = find(&rep.metrics, "unpaired_lifecycle_events");
        assert!(row.has_value);
        assert_eq!(row.value, 1);
        assert_eq!(row.unit, "count");
    }

    #[test]
    fn paired_events_emit_no_unpaired_metric() {
        let mut a = Analyzer::new(session());
        feed_nested(&mut a);
        let rep = a.finish(2300000000, false).unwrap();
        assert!(!names(&rep.metrics, "unpaired_lifecycle_events"));
    }

    #[test]
    fn region_rows_merged() {
        let mut a = Analyzer::new(region_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&transition("r1", "shared", 2)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(find(&rep.metrics, "conversion_requests").value, 1);
        assert_eq!(find(&rep.metrics, "known_shared_region_bytes").value, 8192);
        assert_eq!(count(&rep.metrics, "conversion_request_bytes"), 1);
        assert_eq!(count(&rep.metrics, "known_shared_region_bytes"), 1);
        let snap = a.snapshot(2300000000, false).unwrap();
        assert_eq!(find(&snap.metrics, "known_shared_region_bytes").value, 8192);
    }

    #[test]
    fn region_rows_absent_without_source() {
        let mut a = Analyzer::new(session());
        a.consume(&attempt("op1", 1)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert!(!find(&rep.metrics, "conversion_request_bytes").has_value);
        assert!(!find(&rep.metrics, "known_shared_region_bytes").has_value);
    }

    #[test]
    fn partial_tail_downgrades_stateful_metrics() {
        let mut a = Analyzer::new(region_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&pool("p1", 900, 1000, 3)).unwrap();
        a.consume(&transition("r1", "shared", 4)).unwrap();
        let rep = a.finish(2300000000, true).unwrap();
        // A partial tail may hide a release, so the live mapping gauge
        // is withheld (null/unavailable), not a degraded number: unknown
        // is not zero. Cumulative counters keep values with partial
        // coverage. Latest observed pool samples keep their values;
        // region current state is withheld because a transition may be missing.
        let live = find(&rep.metrics, "live_observed_allocation_bytes");
        assert!(!live.has_value);
        assert_eq!(live.coverage, "unavailable");
        assert_eq!(
            find(&rep.metrics, "successful_allocations").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "successful_allocations").confidence,
            "high"
        );
        assert_eq!(
            find_pool(&rep.metrics, "pool_used_bytes", "p1").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "known_shared_region_bytes").coverage,
            "unavailable"
        );
    }

    #[test]
    fn detail_gap_downgrades_pool_and_region() {
        let mut a = Analyzer::new(region_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&pool("p1", 900, 1000, 2)).unwrap();
        a.consume(&transition("r1", "shared", 3)).unwrap();
        a.consume(&gap("detail", 4)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(
            find_pool(&rep.metrics, "pool_used_bytes", "p1").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "conversion_requests").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "known_shared_region_bytes").coverage,
            "unavailable"
        );
    }

    #[test]
    fn baseline_gap_downgrades_region_unions_only() {
        let mut a = Analyzer::new(region_session());
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&transition("r1", "shared", 2)).unwrap();
        a.consume(&gap("baseline", 3)).unwrap();
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(
            find(&rep.metrics, "known_shared_region_bytes").coverage,
            "partial"
        );
        assert_eq!(
            find(&rep.metrics, "conversion_requests").coverage,
            "complete_for_scope"
        );
    }

    fn feed_snapshot_control(a: &mut Analyzer) {
        // Open 4096-byte mapping, 3 pressure samples, 8192 shared bytes.
        a.consume(&attempt("op1", 1)).unwrap();
        a.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        a.consume(&pool("p1", 900, 1000, 3)).unwrap();
        a.consume(&pool("p1", 900, 1000, 4)).unwrap();
        a.consume(&pool("p1", 900, 1000, 5)).unwrap();
        a.consume(&transition("r1", "shared", 6)).unwrap();
    }

    fn assert_same_metrics(got: &Report, want: &Report) {
        // Every returned row matches: name, value, and coverage.
        assert_eq!(got.metrics.len(), want.metrics.len());
        for (g, w) in got.metrics.iter().zip(want.metrics.iter()) {
            assert_eq!(g.name, w.name);
            assert_eq!(g.has_value, w.has_value);
            if g.has_value {
                assert_eq!(g.value, w.value);
            }
            assert_eq!(g.coverage, w.coverage);
            assert_eq!(g.measurement, w.measurement);
        }
    }

    #[test]
    fn partial_snapshot_preserves_later_facts() {
        let mut probed = Analyzer::new(region_session());
        feed_snapshot_control(&mut probed);
        let snap = probed.snapshot(2300000000, true).unwrap();
        // The partial view itself stays degraded: a dropped tail may
        // hide a release, a transition, or the latest pool sample.
        let snap_live = find(&snap.metrics, "live_observed_allocation_bytes");
        assert!(!snap_live.has_value);
        assert_eq!(snap_live.coverage, "unavailable");
        let snap_streak = find_pool(&snap.metrics, "pool_pressure_samples", "p1");
        assert_eq!(snap_streak.value, 0);
        assert_eq!(snap_streak.coverage, "partial");
        let snap_shared = find(&snap.metrics, "known_shared_region_bytes");
        assert!(!snap_shared.has_value);
        // The later finish matches a fresh analyzer exactly.
        let fin = probed.finish(2300000000, false).unwrap();
        let mut fresh = Analyzer::new(region_session());
        feed_snapshot_control(&mut fresh);
        let want = fresh.finish(2300000000, false).unwrap();
        assert_same_metrics(&fin, &want);
        let live = find(&fin.metrics, "live_observed_allocation_bytes");
        assert!(live.has_value);
        assert_eq!(live.value, 4096);
        assert_eq!(live.coverage, "complete_for_scope");
        assert_eq!(find(&fin.metrics, "open_mappings").value, 1);
        let shared = find(&fin.metrics, "known_shared_region_bytes");
        assert!(shared.has_value);
        assert_eq!(shared.value, 8192);
        assert_eq!(shared.coverage, "complete_for_scope");
        let streak = find_pool(&fin.metrics, "pool_pressure_samples", "p1");
        assert_eq!(streak.value, 3);
        assert_eq!(streak.coverage, "complete_for_scope");
        assert_eq!(fin.q_detail.status, "complete_for_scope");
    }

    #[test]
    fn repeated_partial_snapshots_preserve_facts() {
        let mut probed = Analyzer::new(region_session());
        probed.consume(&attempt("op1", 1)).unwrap();
        probed.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        probed.consume(&pool("p1", 900, 1000, 3)).unwrap();
        probed.consume(&pool("p1", 900, 1000, 4)).unwrap();
        probed.consume(&transition("r1", "shared", 5)).unwrap();
        probed.snapshot(2300000000, true).unwrap();
        probed.snapshot(2300000000, false).unwrap();
        probed.snapshot(2300000000, true).unwrap();
        probed.consume(&pool("p1", 900, 1000, 6)).unwrap();
        probed.snapshot(2300000000, true).unwrap();
        let fin = probed.finish(2300000000, false).unwrap();
        let mut fresh = Analyzer::new(region_session());
        fresh.consume(&attempt("op1", 1)).unwrap();
        fresh.consume(&map("op1", "m1", 1300000000, 2)).unwrap();
        fresh.consume(&pool("p1", 900, 1000, 3)).unwrap();
        fresh.consume(&pool("p1", 900, 1000, 4)).unwrap();
        fresh.consume(&transition("r1", "shared", 5)).unwrap();
        fresh.consume(&pool("p1", 900, 1000, 6)).unwrap();
        let want = fresh.finish(2300000000, false).unwrap();
        assert_same_metrics(&fin, &want);
        assert_eq!(
            find_pool(&fin.metrics, "pool_pressure_samples", "p1").value,
            3
        );
        assert_eq!(
            find(&fin.metrics, "live_observed_allocation_bytes").value,
            4096
        );
        assert_eq!(find(&fin.metrics, "known_shared_region_bytes").value, 8192);
    }

    #[test]
    fn consumed_detail_gap_stays_degraded() {
        let mut probed = Analyzer::new(region_session());
        feed_snapshot_control(&mut probed);
        probed.consume(&gap("detail", 7)).unwrap();
        probed.consume(&pool("p1", 900, 1000, 8)).unwrap();
        probed.snapshot(2300000000, true).unwrap();
        probed.snapshot(2300000000, false).unwrap();
        let fin = probed.finish(2300000000, false).unwrap();
        let mut fresh = Analyzer::new(region_session());
        feed_snapshot_control(&mut fresh);
        fresh.consume(&gap("detail", 7)).unwrap();
        fresh.consume(&pool("p1", 900, 1000, 8)).unwrap();
        let want = fresh.finish(2300000000, false).unwrap();
        assert_same_metrics(&fin, &want);
        // Real loss stays degraded: live and current region state
        // are withheld, counters keep partial coverage, and only
        // the post-gap pool sample rebuilds the streak.
        let live = find(&fin.metrics, "live_observed_allocation_bytes");
        assert!(!live.has_value);
        assert_eq!(
            find(&fin.metrics, "successful_allocations").coverage,
            "partial"
        );
        assert_eq!(
            find_pool(&fin.metrics, "pool_used_bytes", "p1").coverage,
            "partial"
        );
        assert_eq!(
            find_pool(&fin.metrics, "pool_pressure_samples", "p1").value,
            1
        );
        assert_eq!(
            find(&fin.metrics, "conversion_requests").coverage,
            "partial"
        );
        assert_eq!(
            find(&fin.metrics, "known_shared_region_bytes").coverage,
            "unavailable"
        );
    }

    #[test]
    fn gap_between_snapshots_stays_degraded() {
        let mut probed = Analyzer::new(region_session());
        feed_snapshot_control(&mut probed);
        probed.snapshot(2300000000, true).unwrap();
        probed.consume(&gap("detail", 7)).unwrap();
        probed.snapshot(2300000000, false).unwrap();
        let fin = probed.finish(2300000000, false).unwrap();
        let mut fresh = Analyzer::new(region_session());
        feed_snapshot_control(&mut fresh);
        fresh.consume(&gap("detail", 7)).unwrap();
        let want = fresh.finish(2300000000, false).unwrap();
        assert_same_metrics(&fin, &want);
        assert!(!find(&fin.metrics, "live_observed_allocation_bytes").has_value);
        assert_eq!(
            find_pool(&fin.metrics, "pool_pressure_samples", "p1").value,
            0
        );
        assert_eq!(
            find(&fin.metrics, "known_shared_region_bytes").coverage,
            "unavailable"
        );
    }

    #[test]
    fn post_gap_pool_run_survives_snapshots() {
        let mut a = Analyzer::new(session());
        a.consume(&pool("p1", 900, 1000, 1)).unwrap();
        a.consume(&pool("p1", 900, 1000, 2)).unwrap();
        a.consume(&gap("detail", 3)).unwrap();
        a.consume(&pool("p1", 900, 1000, 4)).unwrap();
        let before = a.snapshot(2300000000, false).unwrap();
        assert_eq!(
            find_pool(&before.metrics, "pool_pressure_samples", "p1").value,
            1
        );
        a.consume(&pool("p1", 900, 1000, 5)).unwrap();
        a.consume(&pool("p1", 900, 1000, 6)).unwrap();
        let after = a.finish(2300000000, false).unwrap();
        assert_eq!(
            find_pool(&after.metrics, "pool_pressure_samples", "p1").value,
            3
        );
    }

    #[test]
    fn sustained_churn_stable() {
        let mut a = Analyzer::new(session());
        let mut seq = 1;
        for i in 0..300 {
            let op = format!("op{i}");
            let mapping = format!("m{i}");
            a.consume(&attempt(&op, seq)).unwrap();
            seq += 1;
            a.consume(&map(&op, &mapping, 1000 + i as u64, seq))
                .unwrap();
            seq += 1;
            a.consume(&unmap(&mapping, 2000 + i as u64, seq)).unwrap();
            seq += 1;
        }
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(find(&rep.metrics, "successful_allocations").value, 300);
        assert_eq!(find(&rep.metrics, "completed_lifetime_count").value, 300);
        assert_eq!(
            find(&rep.metrics, "live_observed_allocation_bytes").value,
            0
        );
        assert_eq!(find(&rep.metrics, "open_mappings").value, 0);
        assert_eq!(
            find(&rep.metrics, "completed_lifetime_count").coverage,
            "complete_for_scope"
        );
    }

    #[test]
    fn limitations_capped_at_schema_budget() {
        let mut a = Analyzer::new(session());
        a.consume(&attempt("op1", 1)).unwrap();
        for i in 0..300 {
            let mut ev = base("pool_sample", 10 + i as u64, 700);
            ev.pool.pool_id = format!("p{i}");
            ev.pool.has_used = true;
            ev.pool.used_bytes = 1;
            ev.pool.has_capacity = true;
            ev.pool.capacity_bytes = 100;
            ev.pool.unit = "slots".to_string();
            a.consume(&ev).unwrap();
        }
        let rep = a.finish(2300000000, false).unwrap();
        assert_eq!(rep.limitations.len(), 256);
        assert!(rep.limitations.last().unwrap().contains("withheld"));
        for n in &rep.limitations {
            assert!(n.chars().count() <= 1024);
            assert!(!n.is_empty());
        }
    }

    #[test]
    fn truncate_note_test() {
        assert_eq!(truncate_note("fine"), "fine");
        let long = "x".repeat(1100);
        assert_eq!(truncate_note(&long).chars().count(), 1024);
        let wide = "é".repeat(1100);
        assert_eq!(truncate_note(&wide).chars().count(), 1024);
    }

    #[test]
    fn truncate_rows_test() {
        let mut rows = Vec::new();
        for i in 0..5u64 {
            rows.push(Metric {
                name: format!("m{i}"),
                has_value: true,
                value: i,
                ..Default::default()
            });
        }
        let kept = truncate_rows(&rows, 3);
        assert_eq!(kept.rows.len(), 3);
        assert_eq!(kept.withheld, 2);
        assert_eq!(kept.rows[0].name, "m0");
        let all = truncate_rows(&rows, 5);
        assert_eq!(all.rows.len(), 5);
        assert_eq!(all.withheld, 0);
    }

    #[test]
    fn report_row_truncation_exact() {
        assert_eq!(MAX_REPORT_METRICS, 4096);
        let mut rows = Vec::new();
        for i in 0..4097 {
            rows.push(Metric {
                name: format!("m{i}"),
                ..Default::default()
            });
        }
        let cut = truncate_rows(&rows, MAX_REPORT_METRICS as i64);
        assert_eq!(cut.rows.len(), 4096);
        assert_eq!(cut.withheld, 1);
        assert_eq!(cut.rows[0].name, "m0");
        let exact = truncate_rows(&cut.rows, MAX_REPORT_METRICS as i64);
        assert_eq!(exact.rows.len(), 4096);
        assert_eq!(exact.withheld, 0);
    }

    fn budget_row(name: &str, device: &str, pool: &str) -> Metric {
        Metric {
            name: name.to_string(),
            has_value: true,
            value: 1,
            has_device_id: !device.is_empty(),
            device_id: device.to_string(),
            has_pool_id: !pool.is_empty(),
            pool_id: pool.to_string(),
            ..Default::default()
        }
    }

    fn row_names(rows: &[Metric]) -> Vec<String> {
        rows.iter().map(|m| m.name.clone()).collect()
    }

    #[test]
    fn budget_keeps_mandatory_first() {
        // Device detail floods the budget; global and per-pool
        // evidence rows still win it in merge order.
        let mut rows = Vec::new();
        for i in 0..10 {
            rows.push(budget_row(&format!("dev{i}"), "d", ""));
        }
        rows.push(budget_row("global-a", "", ""));
        rows.push(budget_row("pool-p", "", "p1"));
        rows.push(budget_row("global-b", "", ""));
        let cut = budget_rows(&rows, 5);
        assert_eq!(cut.rows.len(), 5);
        assert_eq!(cut.withheld, 8);
        let nm = row_names(&cut.rows);
        assert_eq!(nm[0], "global-a");
        assert_eq!(nm[1], "pool-p");
        assert_eq!(nm[2], "global-b");
        assert_eq!(nm[3], "dev0");
        assert_eq!(nm[4], "dev1");
    }

    #[test]
    fn budget_under_budget_keeps_order() {
        let rows = vec![
            budget_row("dev0", "d0", ""),
            budget_row("global", "", ""),
            budget_row("dev1", "d1", ""),
        ];
        let cut = budget_rows(&rows, 4096);
        assert_eq!(cut.rows.len(), 3);
        assert_eq!(cut.withheld, 0);
        let nm = row_names(&cut.rows);
        assert_eq!(nm[0], "dev0");
        assert_eq!(nm[1], "global");
        assert_eq!(nm[2], "dev1");
    }

    #[test]
    fn budget_degenerate_mandatory_overflow() {
        // Mandatory rows alone exceed the budget: the first
        // budget mandatory rows win in merge order.
        let mut rows = Vec::new();
        for i in 0..6 {
            rows.push(budget_row(&format!("g{i}"), "", ""));
        }
        let cut = budget_rows(&rows, 4);
        assert_eq!(cut.rows.len(), 4);
        assert_eq!(cut.withheld, 2);
        assert_eq!(cut.rows[0].name, "g0");
        assert_eq!(cut.rows[3].name, "g3");
    }

    #[test]
    fn budget_boundaries() {
        let none: Vec<Metric> = Vec::new();
        let empty = budget_rows(&none, 5);
        assert_eq!(empty.rows.len(), 0);
        assert_eq!(empty.withheld, 0);
        let rows = vec![budget_row("dev0", "d0", ""), budget_row("global", "", "")];
        // Exact budget keeps merge order, never reorders.
        let exact = budget_rows(&rows, 2);
        assert_eq!(exact.rows.len(), 2);
        assert_eq!(exact.withheld, 0);
        assert_eq!(exact.rows[0].name, "dev0");
        assert_eq!(exact.rows[1].name, "global");
        let zero = budget_rows(&rows, 0);
        assert_eq!(zero.rows.len(), 0);
        assert_eq!(zero.withheld, 2);
        let neg = budget_rows(&rows, -3);
        assert_eq!(neg.rows.len(), 0);
        assert_eq!(neg.withheld, 2);
    }

    #[test]
    fn budget_all_device_keeps_prefix() {
        let mut rows = Vec::new();
        for i in 0..6 {
            rows.push(budget_row(&format!("dev{i}"), "d", ""));
        }
        let cut = budget_rows(&rows, 4);
        assert_eq!(cut.rows.len(), 4);
        assert_eq!(cut.withheld, 2);
        assert_eq!(cut.rows[0].name, "dev0");
        assert_eq!(cut.rows[3].name, "dev3");
    }

    fn notes(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("note{i}")).collect()
    }

    #[test]
    fn finalize_limitations_keeps_row_disclosure() {
        // Both ceilings at once: 300 tracker notes plus withheld
        // rows still disclose the row omission in the last slot.
        let capped = finalize_limitations(&notes(300), 17);
        assert_eq!(capped.len(), 256);
        assert_eq!(capped[0], "note0");
        assert_eq!(capped[253], "note253");
        assert!(capped[254].contains("further limitations withheld"));
        assert_eq!(
            capped[255],
            "17 metric rows withheld (4096-row report budget)."
        );
    }

    #[test]
    fn finalize_limitations_without_rows() {
        let same = finalize_limitations(&notes(10), 0);
        assert_eq!(same.len(), 10);
        assert_eq!(same[9], "note9");
        let capped = finalize_limitations(&notes(300), 0);
        assert_eq!(capped.len(), 256);
        assert_eq!(capped[254], "note254");
        assert!(capped[255].contains("further limitations withheld"));
        let edge = finalize_limitations(&notes(255), 5);
        assert_eq!(edge.len(), 256);
        assert_eq!(edge[254], "note254");
        assert_eq!(
            edge[255],
            "5 metric rows withheld (4096-row report budget)."
        );
    }
}
