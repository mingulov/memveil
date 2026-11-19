// SPDX-License-Identifier: GPL-3.0-or-later
//! Explicit start/stop boundaries and terminal evidence.
//!
//! The stop protocol runs readiness, admission close, quiescence
//! of admitted writer activity, bounded drain to a proved
//! transport boundary, counter sampling, and finalization. Each
//! stage records what it proved; finalization reports `complete`
//! only when admission closed, every admitted writer settled, the
//! drain reached its boundary, and the final counter sample
//! succeeded. Anything less yields `partial` with a named reason,
//! never a silent complete. A failed admission close finalizes
//! through `fail_close` with its own reason; the close is never
//! claimed when the detach failed.
//!
//! A quiet ring proves nothing by itself: zero drained records
//! with unsettled writers (or without observed quiescence) stays
//! partial. A submit landing after the drain recorded its
//! boundary claim likewise stays partial: the drain cannot have
//! covered that record. A later drain re-proves the boundary.
//! A new boundary claim also invalidates any earlier counter
//! sample, which must follow the last drain. Finalization is
//! terminal: a second finalize raises instead of replacing
//! the evidence. Open logical DMA mappings are reported beside the
//! verdict and never block callback quiescence: the controller
//! waits for BPF callbacks, not for logical mappings to end.
//!
//! The default stop budget is 5000 ms of monotonic time. The
//! budget bounds waiting; a deadline never establishes
//! quiescence. Elapsed time and the budget travel in the evidence
//! so session metadata can record them.

/// Default stop budget in milliseconds.
pub const STOP_BUDGET_MS: i64 = 5000;

/// One stop-protocol misuse: stage called out of order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopError {
    /// Misuse detail.
    pub message: String,
}

impl StopError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for StopError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "StopError(message={})", self.message)
    }
}

impl std::error::Error for StopError {}

/// Terminal evidence for one stop sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopEvidence {
    /// `complete` or `partial`.
    pub outcome: String,
    /// Failure reason; empty when complete.
    pub reason: String,
    /// Stop budget in milliseconds.
    pub stop_budget_ms: i64,
    /// Elapsed stop time in milliseconds.
    pub elapsed_ms: i64,
    /// True when admission closed cleanly.
    pub admission_closed: bool,
    /// True when quiescence was observed.
    pub quiescence_observed: bool,
    /// Writers settled count.
    pub writers_settled: i64,
    /// In-flight submissions at close.
    pub in_flight_at_close: i64,
    /// Late submissions covered by the drain.
    pub late_submits_drained: i64,
    /// Records the drain claimed.
    pub drained_records: i64,
    /// True when a drain ran.
    pub has_drained: bool,
    /// True when a submit landed after the drain.
    pub submit_after_drain: bool,
    /// True when the ring was busy at the drain.
    pub busy_at_drain: bool,
    /// True when the final counter sample succeeded.
    pub counters_valid: bool,
    /// Mappings still open.
    pub open_mappings: i64,
}

/// Scripted stop protocol with explicit per-stage proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopController {
    ready: bool,
    closed: bool,
    close_ok: bool,
    in_flight: i64,
    in_flight_at_close: i64,
    reserved: i64,
    settled: i64,
    late_submits: i64,
    late_covered: i64,
    quiesced: bool,
    drained: i64,
    has_drained: bool,
    submit_after_drain: bool,
    busy: bool,
    sampled: bool,
    counters_ok: bool,
    finalized: bool,
}

impl StopController {
    /// A fresh controller; call [`StopController::mark_ready`] next.
    pub fn new() -> Self {
        Self {
            ready: false,
            closed: false,
            close_ok: false,
            in_flight: 0,
            in_flight_at_close: 0,
            reserved: 0,
            settled: 0,
            late_submits: 0,
            late_covered: 0,
            quiesced: false,
            drained: 0,
            has_drained: false,
            submit_after_drain: false,
            busy: false,
            sampled: false,
            counters_ok: false,
            finalized: false,
        }
    }

    /// Record startup readiness; measurement may begin.
    pub fn mark_ready(&mut self) {
        self.ready = true;
    }

    /// Admit one writer; false once admission closed.
    pub fn writer_begin(&mut self) -> Result<bool, StopError> {
        if !self.ready {
            return Err(StopError::new("writer_begin before mark_ready"));
        }
        if self.closed {
            return Ok(false);
        }
        self.in_flight += 1;
        Ok(true)
    }

    /// Record one writer entering its reserve step.
    pub fn writer_reserve(&mut self) -> Result<(), StopError> {
        if self.in_flight <= 0 {
            return Err(StopError::new("writer_reserve with no live writer"));
        }
        self.reserved += 1;
        Ok(())
    }

    /// Record one reserved writer submitting its record.
    pub fn writer_submit(&mut self) -> Result<(), StopError> {
        if self.reserved <= 0 {
            return Err(StopError::new("writer_submit with no reservation"));
        }
        self.reserved -= 1;
        if self.closed {
            self.late_submits += 1;
        }
        if self.has_drained {
            self.submit_after_drain = true;
        }
        Ok(())
    }

    /// Record one admitted writer exiting cleanly.
    pub fn writer_settle(&mut self) -> Result<(), StopError> {
        if self.in_flight <= 0 {
            return Err(StopError::new("writer_settle with no live writer"));
        }
        self.in_flight -= 1;
        self.settled += 1;
        Ok(())
    }

    /// Close admission; no new writer may begin.
    pub fn close_admission(&mut self) -> Result<(), StopError> {
        if !self.ready {
            return Err(StopError::new("close_admission before mark_ready"));
        }
        if self.closed {
            return Err(StopError::new("close_admission twice"));
        }
        self.closed = true;
        self.close_ok = true;
        self.in_flight_at_close = self.in_flight;
        Ok(())
    }

    /// Record a failed admission close; finalizes partial.
    pub fn fail_close(&mut self) -> Result<(), StopError> {
        if !self.ready {
            return Err(StopError::new("fail_close before mark_ready"));
        }
        if self.closed {
            return Err(StopError::new("fail_close twice"));
        }
        self.closed = true;
        self.in_flight_at_close = self.in_flight;
        Ok(())
    }

    /// True once every admitted writer settled.
    pub fn try_quiescence(&mut self) -> bool {
        if self.closed && self.in_flight == 0 {
            self.quiesced = true;
            return true;
        }
        false
    }

    /// Require quiescence; raise while writers are in flight.
    pub fn observe_quiescence(&mut self) -> Result<(), StopError> {
        if !self.try_quiescence() {
            return Err(StopError::new("writers still in flight"));
        }
        Ok(())
    }

    /// Record one bounded drain: records read, BUSY seen or not.
    ///
    /// A new boundary claim invalidates any earlier
    /// counter sample: the sample must follow the last
    /// drain.
    pub fn drain(&mut self, records: i64, busy: bool) -> Result<(), StopError> {
        if !self.closed {
            return Err(StopError::new("drain before close_admission"));
        }
        self.drained = records;
        self.has_drained = true;
        self.submit_after_drain = false;
        self.late_covered = self.late_submits;
        self.sampled = false;
        self.counters_ok = false;
        self.busy = busy;
        Ok(())
    }

    /// Record the final counter-sample outcome.
    pub fn sample_counters(&mut self, ok: bool) {
        self.sampled = true;
        self.counters_ok = ok;
    }

    /// Finalize with 0 elapsed ms (budget met by construction).
    pub fn finalize(&mut self, open_mappings: i64) -> Result<StopEvidence, StopError> {
        self.finalize_over_budget(0, open_mappings)
    }

    /// Build terminal evidence; partial unless all stages proved.
    pub fn finalize_over_budget(
        &mut self,
        elapsed_ms: i64,
        open_mappings: i64,
    ) -> Result<StopEvidence, StopError> {
        if !self.closed {
            return Err(StopError::new("finalize before close_admission"));
        }
        if self.finalized {
            return Err(StopError::new("finalize twice"));
        }
        self.finalized = true;
        let mut reason = String::new();
        let mut complete = true;
        if !self.close_ok {
            complete = false;
            reason = "admission close failed".to_string();
        } else if !self.quiesced {
            complete = false;
            reason = "quiescence unproven".to_string();
        } else if !self.has_drained {
            complete = false;
            reason = "drain missing".to_string();
        } else if self.busy {
            complete = false;
            reason = "transport BUSY at drain".to_string();
        } else if self.submit_after_drain {
            complete = false;
            reason = "late submit past drain".to_string();
        } else if !self.sampled || !self.counters_ok {
            complete = false;
            reason = "final counter sample failed".to_string();
        } else if elapsed_ms > STOP_BUDGET_MS {
            complete = false;
            reason = "stop budget exhausted".to_string();
        }
        let outcome = if complete { "complete" } else { "partial" }.to_string();
        Ok(StopEvidence {
            outcome,
            reason,
            stop_budget_ms: STOP_BUDGET_MS,
            elapsed_ms,
            admission_closed: self.close_ok,
            quiescence_observed: self.quiesced,
            writers_settled: self.settled,
            in_flight_at_close: self.in_flight_at_close,
            late_submits_drained: self.late_covered,
            drained_records: self.drained,
            has_drained: self.has_drained,
            submit_after_drain: self.submit_after_drain,
            busy_at_drain: self.busy,
            counters_valid: self.sampled && self.counters_ok,
            open_mappings,
        })
    }
}

impl Default for StopController {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{STOP_BUDGET_MS, StopController};

    #[test]
    fn clean_stop_completes() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.stop_budget_ms, STOP_BUDGET_MS);
        assert!(ev.counters_valid);
    }

    #[test]
    fn writer_between_admission_and_count_settles() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.close_admission().expect("close");
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(1, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.writers_settled, 1);
    }

    #[test]
    fn admission_after_close_refused() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        assert!(!ctl.writer_begin().expect("begin"));
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
    }

    #[test]
    fn stop_during_reserve_drains_late_submit() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.writer_reserve().expect("reserve");
        ctl.close_admission().expect("close");
        ctl.writer_submit().expect("submit");
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(1, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.late_submits_drained, 1);
    }

    #[test]
    fn delayed_submit_past_drain_bound_partial() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.writer_reserve().expect("reserve");
        ctl.close_admission().expect("close");
        // The writer never submits: quiescence is unproven, so the
        // drain cannot cover its record and the stop stays partial.
        assert!(!ctl.try_quiescence());
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert!(!ev.reason.is_empty());
    }

    #[test]
    fn missing_writer_decrement_partial() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.close_admission().expect("close");
        assert!(!ctl.try_quiescence());
        let ev = ctl.finalize(1).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.in_flight_at_close, 1);
    }

    #[test]
    fn failed_final_snapshot_partial() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(false);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert!(!ev.counters_valid);
    }

    #[test]
    fn busy_record_retried_then_partial() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, true).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert!(ev.busy_at_drain);
    }

    #[test]
    fn quiet_ring_without_quiescence_never_complete() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.close_admission().expect("close");
        // Zero drained records with a writer still in flight proves
        // nothing: finalizing without observed quiescence is partial.
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
    }

    #[test]
    fn open_mappings_do_not_block_quiescence() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(7).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.open_mappings, 7);
    }

    #[test]
    fn budget_exhaustion_partial() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        let ev = ctl
            .finalize_over_budget(STOP_BUDGET_MS + 1, 0)
            .expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.elapsed_ms, STOP_BUDGET_MS + 1);
        assert_eq!(ev.stop_budget_ms, STOP_BUDGET_MS);
    }

    #[test]
    fn finalize_requires_close() {
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.finalize(0).is_err());
    }

    #[test]
    fn failed_admission_close_partial() {
        // A failed admission close finalizes partial with its
        // own reason, not as unproven quiescence.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.fail_close().expect("fail close");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize_over_budget(10, 0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.reason, "admission close failed");
        assert!(!ev.admission_closed);
    }

    #[test]
    fn barrier_submit_after_drain_partial() {
        // Barrier interleaving: writer A reserves before the
        // close; the drain claims an empty boundary while the
        // reservation is still held; A submits late. The drain's
        // boundary claim is stale, so the stop stays partial even
        // though every writer settles and the transport never
        // reported BUSY. The late submit is observed but covered
        // by no drain.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.writer_reserve().expect("reserve");
        ctl.close_admission().expect("close");
        ctl.drain(0, false).expect("drain");
        ctl.writer_submit().expect("submit");
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.reason, "late submit past drain");
        assert_eq!(ev.late_submits_drained, 0);
        assert_eq!(ev.drained_records, 0);
    }

    #[test]
    fn barrier_two_writers_staggered_complete() {
        // Two writers advance on independent barriers: A
        // reserves before the close while B only begins; both
        // submit and settle after the close. Quiescence polls
        // between barriers stay false until the last settle.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("a"));
        ctl.writer_reserve().expect("reserve");
        assert!(ctl.writer_begin().expect("b"));
        ctl.close_admission().expect("close");
        assert!(!ctl.try_quiescence());
        ctl.writer_submit().expect("submit");
        ctl.writer_settle().expect("settle");
        assert!(!ctl.try_quiescence());
        ctl.writer_reserve().expect("reserve");
        ctl.writer_submit().expect("submit");
        assert!(!ctl.try_quiescence());
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(2, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.writers_settled, 2);
        assert_eq!(ev.in_flight_at_close, 2);
        assert_eq!(ev.late_submits_drained, 2);
        assert_eq!(ev.drained_records, 2);
    }

    #[test]
    fn barrier_begin_races_close() {
        // A begin racing the close is refused while an
        // admitted writer is still mid-callback; the admitted
        // writer settles and the stop completes with exact
        // in-flight accounting.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("a"));
        ctl.close_admission().expect("close");
        assert!(!ctl.writer_begin().expect("late"));
        assert!(!ctl.try_quiescence());
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.writers_settled, 1);
        assert_eq!(ev.in_flight_at_close, 1);
    }

    #[test]
    fn barrier_redrain_covers_late_submit() {
        // A drain re-run after a late submit re-proves the
        // boundary: the stale claim is replaced, not sticky.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.writer_reserve().expect("reserve");
        ctl.close_admission().expect("close");
        ctl.drain(0, false).expect("drain");
        ctl.writer_submit().expect("submit");
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(1, false).expect("redrain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.late_submits_drained, 1);
        assert_eq!(ev.drained_records, 1);
    }

    #[test]
    fn barrier_redrain_invalidates_sample() {
        // Stage order is drain, then sample: a counter sample
        // taken before the last drain cannot cover later
        // activity, so finalizing without re-sampling stays
        // partial even though every writer settles.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("begin"));
        ctl.writer_reserve().expect("reserve");
        ctl.close_admission().expect("close");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        ctl.writer_submit().expect("submit");
        ctl.writer_settle().expect("settle");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(1, false).expect("redrain");
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.reason, "final counter sample failed");
        assert!(!ev.counters_valid);
    }

    #[test]
    fn finalize_seals_evidence() {
        // Finalization is terminal: a second finalize raises
        // instead of erasing an established failure. A budget
        // failure proved once cannot become complete.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        ctl.close_admission().expect("close");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl
            .finalize_over_budget(STOP_BUDGET_MS + 1, 0)
            .expect("finalize");
        assert_eq!(ev.outcome, "partial");
        assert_eq!(ev.reason, "stop budget exhausted");
        assert!(ctl.finalize(0).is_err());
    }

    #[test]
    fn barrier_in_flight_snapshot_at_close() {
        // in_flight_at_close snapshots writers live at the
        // close: a writer that settles before the close is
        // settled, not in flight.
        let mut ctl = StopController::new();
        ctl.mark_ready();
        assert!(ctl.writer_begin().expect("a"));
        ctl.writer_settle().expect("settle a");
        assert!(ctl.writer_begin().expect("b"));
        ctl.close_admission().expect("close");
        ctl.writer_settle().expect("settle b");
        ctl.observe_quiescence().expect("quiesce");
        ctl.drain(0, false).expect("drain");
        ctl.sample_counters(true);
        let ev = ctl.finalize(0).expect("finalize");
        assert_eq!(ev.outcome, "complete");
        assert_eq!(ev.writers_settled, 2);
        assert_eq!(ev.in_flight_at_close, 1);
    }

    #[test]
    fn close_requires_ready() {
        let mut ctl = StopController::new();
        assert!(ctl.close_admission().is_err());
    }
}
