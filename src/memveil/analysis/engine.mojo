# SPDX-License-Identifier: GPL-3.0-or-later

"""Composed analysis engine: attempts plus lifecycle plus pools plus regions.

The analyzer feeds one event stream to every tracker and merges
their rows into one report. Attempts-only captures keep exactly
their old rows and notes; lifecycle, pool, and region rows
appear only with observed evidence, and the scope note switches
to the extended wording exactly then. Snapshot and finish share
every tracker reducer with no destructive finalization: consumed
loss latches tracker state monotonically, while a partial call
overlays its call-local uncertainty on the returned view only,
so a partial snapshot cannot alter later facts. The merged row
set never exceeds the 4096-row external budget: any excess is
withheld deterministically (tracker order, then row order) with
a visible limitation.
"""

from memveil.analysis.attempts import AttemptAnalyzer, window_label
from memveil.analysis.mappings import MappingTracker
from memveil.analysis.pools import PoolTracker
from memveil.analysis.regions import RegionTracker
from memveil.model.event import Event
from memveil.model.metric import Metric
from memveil.model.report import Report
from memveil.model.session import (
    Channel,
    Session,
    rollup_correlation,
    truncate_codepoints,
)

comptime MAX_REPORT_METRICS = 4096
comptime MAX_REPORT_LIMITATIONS = 256
comptime _MAX_NOTE_CODEPOINTS = 1024


def truncate_note(text: String) -> String:
    """Cap one limitation at 1024 codepoints, on a char boundary."""
    if text.count_codepoints() <= _MAX_NOTE_CODEPOINTS:
        return text
    var out = String("")
    var n = 0
    for cp in text.codepoint_slices():
        if n >= _MAX_NOTE_CODEPOINTS:
            break
        out += String(cp)
        n += 1
    return out^


struct TruncatedRows:
    """Row prefix plus the deterministic withheld count."""

    var rows: List[Metric]
    var withheld: Int

    def __init__(out self):
        self.rows = List[Metric]()
        self.withheld = 0


def budget_rows(rows: List[Metric], budget: Int) -> TruncatedRows:
    """Keep mandatory evidence rows before optional device detail.

    Rows without a device id (global measurements and per-pool
    diagnostic evidence) hold the diagnosis and exit inputs, so
    they receive budget first in merge order; per-device detail
    rows fill whatever budget remains, also in merge order. No
    finding derives from a per-device row, so omitting device
    detail can never suppress a positive. When mandatory rows
    alone exceed the budget, the first budget mandatory rows
    win; that degenerate case keeps the row bound but may
    still omit evidence. At or under budget every row is kept
    in merge order, so small reports never reorder.
    """
    if len(rows) <= budget:
        return truncate_rows(rows, budget)
    var out = TruncatedRows()
    var room = budget
    if room < 0:
        room = 0
    for i in range(len(rows)):
        if room <= 0:
            break
        if rows[i].has_device_id:
            continue
        out.rows.append(rows[i])
        room -= 1
    for i in range(len(rows)):
        if room <= 0:
            break
        if not rows[i].has_device_id:
            continue
        out.rows.append(rows[i])
        room -= 1
    out.withheld = len(rows) - len(out.rows)
    return out^


def finalize_limitations(
    notes: List[String], withheld_rows: Int
) -> List[String]:
    """Cap tracker notes to the schema budget, keeping disclosure.

    Tracker notes share one 256-note budget: keep the first
    notes in merge order and summarize the rest. When rows
    were withheld, their disclosure reserves the last slot so
    the omission notice always survives capping.
    """
    var out = List[String]()
    var room = MAX_REPORT_LIMITATIONS
    var extra = String("")
    if withheld_rows > 0:
        extra = (
            String(withheld_rows)
            + " metric rows withheld (4096-row report budget)."
        )
        room -= 1
    if len(notes) > room:
        for i in range(room - 1):
            out.append(notes[i])
        var dropped = len(notes) - (room - 1)
        out.append(
            String(dropped)
            + " further limitations withheld (256-note"
            " report budget)."
        )
    else:
        for i in range(len(notes)):
            out.append(notes[i])
    if extra != "":
        out.append(extra)
    return out^


def truncate_rows(rows: List[Metric], budget: Int) -> TruncatedRows:
    """Keep the first budget rows in order; count the rest."""
    var out = TruncatedRows()
    var keep = len(rows)
    if keep > budget:
        keep = budget
    if keep < 0:
        keep = 0
    for i in range(keep):
        out.rows.append(rows[i])
    out.withheld = len(rows) - keep
    return out^


def _fold_class_count(
    mut ch: Channel, observed: Int, noun_phrase: String
):
    """Fold an exact observed count into one report class.

    A producer-complete class turns partial with the exact
    count; any other class keeps its claim and appends the
    exact observed count, bounded to the channel limit.
    """
    var note = String(
        String(observed) + " unpaired " + noun_phrase
    )
    if ch.status == String("complete_for_scope"):
        ch.reason = note
    else:
        ch.reason = truncate_codepoints(
            ch.reason + "; " + note, 512
        )
    ch.status = String("partial")
    ch.has_loss_count = True
    ch.loss_count = UInt64(observed)


struct Analyzer:
    """One-stream, four-tracker composed reducer."""

    var _attempts: AttemptAnalyzer
    var _mappings: MappingTracker[]
    var _pools: PoolTracker[]
    var _regions: RegionTracker[]
    var _session: Session

    def __init__(out self, session: Session):
        self._attempts = AttemptAnalyzer(session)
        self._mappings = MappingTracker()
        self._mappings.set_relation_split(session.has_corr_relations)
        self._pools = PoolTracker()
        var status = session.cap_region_state.status
        var admitted = status == "verified" or status == "partial"
        self._regions = RegionTracker(
            admitted, session.baseline_complete
        )
        self._regions.seed_baseline(session.baseline_regions.copy())
        self._session = session.copy()

    def consume(mut self, ev: Event) raises:
        """Fold one event into every tracker."""
        self._attempts.consume(ev)
        self._mappings.consume(ev)
        self._pools.consume(ev)
        self._regions.consume(ev)

    def snapshot(mut self, end_ns: UInt64, partial: Bool) raises -> Report:
        """Reduce the stream so far; the horizon may narrow."""
        return self._merge(end_ns, partial, False)

    def finish(mut self, end_ns: UInt64, partial: Bool) raises -> Report:
        """Reduce the whole capture; the horizon must match."""
        return self._merge(end_ns, partial, True)

    def _fold_observed_unpaired(mut self, mut rep: Report):
        """Fold analyzer-observed unpaired counts into relations.

        Report-side classes carry exact per-class counts plus an
        aggregate total. A producer-complete class with observed
        unpaired events turns partial with the exact count; a
        producer-non-complete class keeps its claim and appends
        the exact observed count.
        """
        var um = self._mappings.unpaired_mapping_count()
        var uc = self._mappings.unpaired_copy_count()
        var us = self._mappings.unpaired_sync_count()
        var mapping = rep.q_corr_mapping.copy()
        var copy = rep.q_corr_copy.copy()
        var sync = rep.q_corr_sync.copy()
        var map_causes = List[String]()
        var copy_causes = List[String]()
        var sync_causes = List[String]()
        if um > 0:
            _fold_class_count(
                mapping,
                um,
                String(
                    "mapping or release events excluded from"
                    " pairing-dependent totals; independent facts"
                    " retained."
                ),
            )
        map_causes.append(mapping.reason)
        if uc > 0:
            _fold_class_count(
                copy,
                uc,
                String(
                    "copy events excluded from copy attribution;"
                    " independent facts retained."
                ),
            )
        copy_causes.append(copy.reason)
        if us > 0:
            _fold_class_count(
                sync,
                us,
                String(
                    "sync events excluded from sync attribution;"
                    " independent facts retained."
                ),
            )
        sync_causes.append(sync.reason)
        var aggregate = rollup_correlation(
            mapping,
            copy,
            sync,
            map_causes,
            copy_causes,
            sync_causes,
        )
        aggregate.has_loss_count = True
        aggregate.loss_count = UInt64(um + uc + us)
        rep.q_correlation = aggregate^
        rep.q_corr_mapping = mapping^
        rep.q_corr_copy = copy^
        rep.q_corr_sync = sync^

    def _merge(
        mut self, end_ns: UInt64, partial: Bool, strict: Bool
    ) raises -> Report:
        var has_pools = self._pools.sees_pools()
        var has_regions = self._regions.sees_regions()
        var rep: Report
        if strict:
            rep = self._attempts.finish(
                end_ns, partial, has_pools, has_regions
            )
        else:
            rep = self._attempts.snapshot(
                end_ns, partial, has_pools, has_regions
            )
        # The attempt reducer folds observed gaps, recovered
        # tails, and producer claims into the quality channels;
        # trackers only see events, so loss the stream never
        # shows is propagated here before any tracker rows emit.
        # Consumed detail loss latches tracker state
        # monotonically: observed gaps already folded at consume
        # time, producer claims echoed here. The call-local
        # dropped tail never latches; it renders as a view
        # overlay in this report only, so a partial snapshot
        # cannot alter later facts.
        if self._session.q_detail.status != "complete_for_scope":
            self._mappings.note_detail_loss()
            self._regions.note_detail_loss()
            self._pools.note_detail_loss()
        if self._mappings.sees_lifecycle():
            if self._session.has_corr_relations:
                if rep.q_corr_mapping.status != "complete_for_scope":
                    self._mappings.note_correlation_loss()
                if rep.q_corr_copy.status != "complete_for_scope":
                    self._mappings.note_copy_attribution_loss()
                if rep.q_corr_sync.status != "complete_for_scope":
                    self._mappings.note_sync_attribution_loss()
            elif rep.q_correlation.status != "complete_for_scope":
                self._mappings.note_correlation_loss()
        if (
            rep.q_baseline.status != "complete_for_scope"
            and rep.q_baseline.status != "not_applicable"
        ):
            self._regions.note_baseline_loss()
        var window = window_label(
            self._session.window_start_ns, end_ns
        )
        if self._mappings.sees_lifecycle():
            var mrows = self._mappings.metrics_horizon(
                window, end_ns, partial
            )
            for i in range(len(mrows)):
                rep.metrics.append(mrows[i])
            var mnotes = self._mappings.limitations()
            for i in range(len(mnotes)):
                rep.limitations.append(mnotes[i])
        if self._pools.sees_pools():
            var prows = self._pools.metrics(window, partial)
            for i in range(len(prows)):
                rep.metrics.append(prows[i])
            var pnotes = self._pools.limitations()
            for i in range(len(pnotes)):
                rep.limitations.append(pnotes[i])
        if self._regions.sees_regions():
            var rrows = self._regions.metrics(window, partial)
            for i in range(len(rrows)):
                rep.metrics.append(rrows[i])
            var rnotes = self._regions.limitations()
            for i in range(len(rnotes)):
                rep.limitations.append(rnotes[i])
        var unpaired = self._mappings.unpaired_count()
        if unpaired > 0 and self._session.has_corr_relations:
            self._fold_observed_unpaired(rep)
        if unpaired > 0 and not self._session.has_corr_relations:
            rep.q_correlation.status = String("partial")
            rep.q_correlation.has_loss_count = True
            rep.q_correlation.loss_count = UInt64(unpaired)
            rep.q_correlation.scope = String(
                "correlated lifecycle events"
            )
            rep.q_correlation.reason = String(
                String(unpaired)
                + " unpaired lifecycle events excluded from"
                " pairing-dependent totals; independent facts"
                " retained."
            )
        if unpaired > 0:
            # Observed pairing evidence as a row: diagnosis
            # derives its finding from this count, never from
            # channel loss alone.
            var um = Metric()
            um.name = String("unpaired_lifecycle_events")
            um.has_value = True
            um.value = UInt64(unpaired)
            um.unit = String("count")
            um.confidence = String("high")
            um.measurement = String("observed")
            um.coverage = String("partial")
            um.has_aggregation = True
            um.aggregation = String("counter")
            um.scope = window + "; observed mappings"
            um.notes = String(
                "Lifecycle events the correlator left unpaired;"
                " excluded from pairing-dependent state,"
                " independent facts retained."
            )
            rep.metrics.append(um^)
        var withheld_rows = 0
        if len(rep.metrics) > MAX_REPORT_METRICS:
            var cut = budget_rows(rep.metrics, MAX_REPORT_METRICS)
            withheld_rows = cut.withheld
            rep.metrics = cut.rows.copy()
        # Merged tracker notes share one 256-note schema budget;
        # the row-budget disclosure keeps the last slot, then
        # every note is capped at 1024 codepoints.
        rep.limitations = finalize_limitations(
            rep.limitations, withheld_rows
        )
        for i in range(len(rep.limitations)):
            rep.limitations[i] = truncate_note(rep.limitations[i])
        return rep^
