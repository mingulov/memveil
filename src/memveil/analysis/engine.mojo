# SPDX-License-Identifier: GPL-3.0-or-later

"""Composed analysis engine: attempts plus lifecycle plus pools plus regions.

The analyzer feeds one event stream to every tracker and merges
their rows into one report. Attempts-only captures keep exactly
their old rows and notes; lifecycle, pool, and region rows
appear only with observed evidence, and the scope note switches
to the extended wording exactly then. Snapshot and finish share
every tracker reducer with no destructive finalization, and the
merged row set never exceeds the 4096-row external budget: any
excess is withheld deterministically (tracker order, then row
order) with a visible limitation.
"""

from memveil.analysis.attempts import AttemptAnalyzer, window_label
from memveil.analysis.mappings import MappingTracker
from memveil.analysis.pools import PoolTracker
from memveil.analysis.regions import RegionTracker
from memveil.model.event import Event
from memveil.model.metric import Metric
from memveil.model.report import Report
from memveil.model.session import Session

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
        # Each note is idempotent across snapshot and finish.
        if rep.q_detail.status != "complete_for_scope":
            self._mappings.note_detail_loss()
            self._pools.note_detail_loss()
            self._regions.note_detail_loss()
        if (
            rep.q_baseline.status != "complete_for_scope"
            and rep.q_baseline.status != "not_applicable"
        ):
            self._regions.note_baseline_loss()
        var window = window_label(
            self._session.window_start_ns, end_ns
        )
        if self._mappings.sees_lifecycle():
            var mrows = self._mappings.metrics_horizon(window, end_ns)
            for i in range(len(mrows)):
                rep.metrics.append(mrows[i])
            var mnotes = self._mappings.limitations()
            for i in range(len(mnotes)):
                rep.limitations.append(mnotes[i])
        if self._pools.sees_pools():
            var prows = self._pools.metrics(window)
            for i in range(len(prows)):
                rep.metrics.append(prows[i])
            var pnotes = self._pools.limitations()
            for i in range(len(pnotes)):
                rep.limitations.append(pnotes[i])
        if self._regions.sees_regions():
            var rrows = self._regions.metrics(window)
            for i in range(len(rrows)):
                rep.metrics.append(rrows[i])
            var rnotes = self._regions.limitations()
            for i in range(len(rnotes)):
                rep.limitations.append(rnotes[i])
        var unpaired = self._mappings.unpaired_count()
        if unpaired > 0:
            rep.q_correlation.status = String("partial")
            rep.q_correlation.has_loss_count = True
            rep.q_correlation.loss_count = UInt64(unpaired)
            rep.q_correlation.scope = String(
                "correlated lifecycle events"
            )
            rep.q_correlation.reason = String(
                String(unpaired)
                + " unpaired lifecycle events excluded from"
                " lifecycle totals."
            )
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
                " excluded from lifecycle totals."
            )
            rep.metrics.append(um^)
        if len(rep.metrics) > MAX_REPORT_METRICS:
            var cut = truncate_rows(rep.metrics, MAX_REPORT_METRICS)
            var dropped = cut.withheld
            rep.metrics = cut.rows.copy()
            rep.limitations.append(
                String(dropped)
                + " metric rows withheld (4096-row report budget)."
            )
        # Merged tracker notes share one 256-note schema budget:
        # keep the first 255 in merge order and summarize the
        # rest, then cap every note at 1024 codepoints.
        if len(rep.limitations) > MAX_REPORT_LIMITATIONS:
            var kept = List[String]()
            for i in range(MAX_REPORT_LIMITATIONS - 1):
                kept.append(rep.limitations[i])
            var withheld = len(rep.limitations) - (
                MAX_REPORT_LIMITATIONS - 1
            )
            kept.append(
                String(withheld)
                + " further limitations withheld (256-note"
                " report budget)."
            )
            rep.limitations = kept^
        for i in range(len(rep.limitations)):
            rep.limitations[i] = truncate_note(rep.limitations[i])
        return rep^
