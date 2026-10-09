# SPDX-License-Identifier: GPL-3.0-or-later

"""Explicit start/stop boundaries and terminal evidence.

The stop protocol runs readiness, admission close, quiescence
of admitted writer activity, bounded drain to a proved
transport boundary, counter sampling, and finalization. Each
stage records what it proved; finalization reports `complete`
only when admission closed, every admitted writer settled, the
drain reached its boundary, and the final counter sample
succeeded. Anything less yields `partial` with a named reason,
never a silent complete. A failed admission close finalizes
through `fail_close` with its own reason; the close is never
claimed when the detach failed.

A quiet ring proves nothing by itself: zero drained records
with unsettled writers (or without observed quiescence) stays
partial. A submit landing after the drain recorded its
boundary claim likewise stays partial: the drain cannot have
covered that record. A later drain re-proves the boundary.
Open logical DMA mappings are reported beside the
verdict and never block callback quiescence: the controller
waits for BPF callbacks, not for logical mappings to end.

The default stop budget is 5000 ms of monotonic time. The
budget bounds waiting; a deadline never establishes
quiescence. Elapsed time and the budget travel in the evidence
so session metadata can record them.

This model is deterministic and scripted: unit tests drive the
writer interleavings directly, and the live collector maps the
same stages onto the control-map protocol in
`bpf/include/memveil_control.h`. See `docs/measurement-windows.md`
for the proof obligations.
"""

comptime STOP_BUDGET_MS = 5000


@fieldwise_init
struct StopError(Copyable, Writable):
    """One stop-protocol misuse: stage called out of order."""

    var message: String


@fieldwise_init
struct StopEvidence(ImplicitlyCopyable):
    """Terminal evidence for one stop sequence."""

    var outcome: String
    var reason: String
    var stop_budget_ms: Int
    var elapsed_ms: Int
    var admission_closed: Bool
    var quiescence_observed: Bool
    var writers_settled: Int
    var in_flight_at_close: Int
    var late_submits_drained: Int
    var drained_records: Int
    var busy_at_drain: Bool
    var counters_valid: Bool
    var open_mappings: Int


struct StopController:
    """Scripted stop protocol with explicit per-stage proof."""

    var _ready: Bool
    var _closed: Bool
    var _close_ok: Bool
    var _in_flight: Int
    var _reserved: Int
    var _settled: Int
    var _late_submits: Int
    var _quiesced: Bool
    var _drained: Int
    var _has_drained: Bool
    var _submit_after_drain: Bool
    var _busy: Bool
    var _sampled: Bool
    var _counters_ok: Bool

    def __init__(out self):
        self._ready = False
        self._closed = False
        self._close_ok = False
        self._in_flight = 0
        self._reserved = 0
        self._settled = 0
        self._late_submits = 0
        self._quiesced = False
        self._drained = 0
        self._has_drained = False
        self._submit_after_drain = False
        self._busy = False
        self._sampled = False
        self._counters_ok = False

    def mark_ready(mut self):
        """Record startup readiness; measurement may begin."""
        self._ready = True

    def writer_begin(mut self) raises -> Bool:
        """Admit one writer; False once admission closed."""
        if not self._ready:
            raise StopError("writer_begin before mark_ready")
        if self._closed:
            return False
        self._in_flight += 1
        return True

    def writer_reserve(mut self) raises:
        """Record one writer entering its reserve step."""
        if self._in_flight <= 0:
            raise StopError("writer_reserve with no live writer")
        self._reserved += 1

    def writer_submit(mut self) raises:
        """Record one reserved writer submitting its record."""
        if self._reserved <= 0:
            raise StopError("writer_submit with no reservation")
        self._reserved -= 1
        if self._closed:
            self._late_submits += 1
        if self._has_drained:
            self._submit_after_drain = True

    def writer_settle(mut self) raises:
        """Record one admitted writer exiting cleanly."""
        if self._in_flight <= 0:
            raise StopError("writer_settle with no live writer")
        self._in_flight -= 1
        self._settled += 1

    def close_admission(mut self) raises:
        """Close admission; no new writer may begin."""
        if not self._ready:
            raise StopError("close_admission before mark_ready")
        if self._closed:
            raise StopError("close_admission twice")
        self._closed = True
        self._close_ok = True

    def fail_close(mut self) raises:
        """Record a failed admission close; finalizes partial."""
        if not self._ready:
            raise StopError("fail_close before mark_ready")
        if self._closed:
            raise StopError("fail_close twice")
        self._closed = True

    def try_quiescence(mut self) -> Bool:
        """True once every admitted writer settled."""
        if self._closed and self._in_flight == 0:
            self._quiesced = True
            return True
        return False

    def observe_quiescence(mut self) raises:
        """Require quiescence; raise while writers are in flight."""
        if not self.try_quiescence():
            raise StopError("writers still in flight")

    def drain(mut self, records: Int, busy: Bool) raises:
        """Record one bounded drain: records read, BUSY seen or not."""
        if not self._closed:
            raise StopError("drain before close_admission")
        self._drained = records
        self._has_drained = True
        self._submit_after_drain = False
        self._busy = busy

    def sample_counters(mut self, ok: Bool):
        """Record the final counter-sample outcome."""
        self._sampled = True
        self._counters_ok = ok

    def finalize(
        mut self, open_mappings: Int
    ) raises -> StopEvidence:
        """Finalize with 0 elapsed ms (budget met by construction)."""
        return self.finalize_over_budget(0, open_mappings)

    def finalize_over_budget(
        mut self, elapsed_ms: Int, open_mappings: Int
    ) raises -> StopEvidence:
        """Build terminal evidence; partial unless all stages proved."""
        if not self._closed:
            raise StopError("finalize before close_admission")
        var reason = String("")
        var complete = True
        if not self._close_ok:
            complete = False
            reason = String("admission close failed")
        elif not self._quiesced:
            complete = False
            reason = String("quiescence unproven")
        elif not self._has_drained:
            complete = False
            reason = String("drain missing")
        elif self._busy:
            complete = False
            reason = String("transport BUSY at drain")
        elif self._submit_after_drain:
            complete = False
            reason = String("late submit past drain")
        elif not self._sampled or not self._counters_ok:
            complete = False
            reason = String("final counter sample failed")
        elif elapsed_ms > STOP_BUDGET_MS:
            complete = False
            reason = String("stop budget exhausted")
        var outcome = String("partial")
        if complete:
            outcome = String("complete")
        return StopEvidence(
            outcome,
            reason,
            STOP_BUDGET_MS,
            elapsed_ms,
            self._close_ok,
            self._quiesced,
            self._settled,
            self._settled + self._in_flight,
            self._late_submits,
            self._drained,
            self._busy,
            self._sampled and self._counters_ok,
            open_mappings,
        )
