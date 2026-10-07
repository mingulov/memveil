# SPDX-License-Identifier: GPL-3.0-or-later

"""Attempt reducer: bounce counts, counter deltas, and report quality.

The analyzer consumes validated events and finishes one Report. Its
rules:

- Detail counts and requested bytes come from bounce_attempt events,
  globally and per device. Counter deltas are alternative
  measurements surfaced beside them, never added to them.
- Counter snapshots group by counter, device scope, profile, and
  unit with exact field comparison. A delta needs two readings in
  one epoch with no reset in between; anything else yields a
  limitation, never a row.
- Report quality echoes the session claims unless the stream
  contradicts them: observed gaps, snapshots against an unavailable
  aggregate claim, a missing finalization, or a dropped tail. The
  producer's loss counts are kept except where observations refute
  them.
- Quality channels the attempt scope does not measure (correlation,
  baseline) echo the producer claims verbatim.
"""

from memveil.model.event import Event
from memveil.model.metric import Finding, Metric
from memveil.model.report import ENGINE_VERSION, Report
from memveil.model.session import Channel, Session
from memveil.model.validate import checked_add, format_u64

comptime MAX_SUMMANDS = 8
comptime _MAX_METRICS = 4096
comptime _MAX_COUNTER_GROUPS = 4096
comptime _MAX_LIMITATIONS = 256
comptime _FIXED_TAIL_METRICS = 9
# Devices with per-device detail rows: 2 global rows + 2 rows per
# device + the fixed tail + 2 reserved counter rows must fit the
# frozen 4096-metric budget. Further devices keep exact global
# accounting; only their per-device rows are withheld (with a
# limitation note), so a 4096-device capture (PRD NFR-03) always
# replays with both aggregate metrics preserved.
comptime _MAX_DETAILED_DEVICES = (
    _MAX_METRICS - 2 - _FIXED_TAIL_METRICS - 2
) // 2


@fieldwise_init
struct AnalysisError(Copyable, Writable):
    """One analyzer failure."""

    var message: String


struct _DeviceAcc:
    var device_id: String
    var count: Int
    var total_bytes: UInt64
    var bytes_overflow: Bool
    var summands: List[UInt64]
    var has_ts: Bool
    var min_ts: UInt64
    var max_ts: UInt64

    def __init__(out self):
        self.device_id = String("")
        self.count = 0
        self.total_bytes = UInt64(0)
        self.bytes_overflow = False
        self.summands = List[UInt64]()
        self.has_ts = False
        self.min_ts = UInt64(0)
        self.max_ts = UInt64(0)


struct _CounterGroup(ImplicitlyCopyable):
    var counter_id: String
    var has_device: Bool
    var device: String
    var profile: String
    var unit: String
    var source_hook: String
    var source_backend: String
    var source_profile: String
    var source_measurement: String
    var source_correlation: String
    var first_epoch: UInt64
    var first_value: UInt64
    var first_ts: UInt64
    var last_epoch: UInt64
    var last_value: UInt64
    var last_ts: UInt64
    var max_value: UInt64
    var count: Int
    var has_other_epoch: Bool
    var other_epoch: UInt64
    var has_decrease: Bool
    var decrease_from: UInt64
    var decrease_to: UInt64
    var has_ts_reorder: Bool

    def __init__(out self):
        self.counter_id = String("")
        self.has_device = False
        self.device = String("")
        self.profile = String("")
        self.unit = String("")
        self.source_hook = String("")
        self.source_backend = String("")
        self.source_profile = String("")
        self.source_measurement = String("")
        self.source_correlation = String("")
        self.first_epoch = UInt64(0)
        self.first_value = UInt64(0)
        self.first_ts = UInt64(0)
        self.last_epoch = UInt64(0)
        self.last_value = UInt64(0)
        self.last_ts = UInt64(0)
        self.max_value = UInt64(0)
        self.count = 0
        self.has_other_epoch = False
        self.other_epoch = UInt64(0)
        self.has_decrease = False
        self.decrease_from = UInt64(0)
        self.decrease_to = UInt64(0)
        self.has_ts_reorder = False


def _partition_strings(mut items: List[String], lo: Int, hi: Int) -> Int:
    var mid = lo + (hi - lo) // 2
    var tmp = items[mid]
    items[mid] = items[hi]
    items[hi] = tmp
    var pivot = items[hi]
    var i = lo
    for j in range(lo, hi):
        if items[j] < pivot:
            var t = items[i]
            items[i] = items[j]
            items[j] = t
            i += 1
    var last = items[i]
    items[i] = items[hi]
    items[hi] = last
    return i


def _quicksort_strings(mut items: List[String], lo: Int, hi: Int):
    """Quicksort that recurses on the smaller half: depth O(log n)."""
    var first = lo
    var last = hi
    while first < last:
        var p = _partition_strings(items, first, last)
        if p - first < last - p:
            _quicksort_strings(items, first, p - 1)
            first = p + 1
        else:
            _quicksort_strings(items, p + 1, last)
            last = p - 1


def _sorted_strings(items: List[String]) -> List[String]:
    var out = List[String]()
    for i in range(len(items)):
        out.append(items[i])
    if len(out) > 1:
        _quicksort_strings(out, 0, len(out) - 1)
    return out^


def _partition_order(
    mut order: List[Int], ctrs: List[_CounterGroup], lo: Int, hi: Int
) -> Int:
    var mid = lo + (hi - lo) // 2
    var tmp = order[mid]
    order[mid] = order[hi]
    order[hi] = tmp
    var pivot = order[hi]
    var i = lo
    for j in range(lo, hi):
        if _group_before(ctrs[order[j]], ctrs[pivot]):
            var t = order[i]
            order[i] = order[j]
            order[j] = t
            i += 1
    var last = order[i]
    order[i] = order[hi]
    order[hi] = last
    return i


def _quicksort_order(
    mut order: List[Int], ctrs: List[_CounterGroup], lo: Int, hi: Int
):
    """Quicksort that recurses on the smaller half: depth O(log n)."""
    var first = lo
    var last = hi
    while first < last:
        var p = _partition_order(order, ctrs, first, last)
        if p - first < last - p:
            _quicksort_order(order, ctrs, first, p - 1)
            first = p + 1
        else:
            _quicksort_order(order, ctrs, p + 1, last)
            last = p - 1


def _plural(n: Int, one: String, many: String) -> String:
    if n == 1:
        return "1 " + one
    return String(n) + " " + many


def window_label(start_ns: UInt64, end_ns: UInt64) -> String:
    """Half-open window label shared by every tracker."""
    return (
        "window ["
        + format_u64(start_ns)
        + ","
        + format_u64(end_ns)
        + ")"
    )


def _known_counter(counter_id: String) -> Bool:
    """True for counter ids with a metric mapping."""
    return (
        counter_id == "swiotlb.bounce_attempts"
        or counter_id == "swiotlb.requested_bytes"
    )


def _counter_metric_name(counter_id: String) -> String:
    """Metric row name for a counter delta.

    Counter rows carry a counter_ prefix so they never collide with
    the detail rows they cross-check: one (name, dimensions) key maps
    to exactly one measurement channel.
    """
    if counter_id == "swiotlb.bounce_attempts":
        return String("counter_bounce_attempts")
    if counter_id == "swiotlb.requested_bytes":
        return String("counter_requested_bounce_bytes")
    var out = String("")
    out += counter_id
    return out^


def _expected_unit(counter_id: String) -> String:
    """Unit a known counter must carry; empty when unmapped."""
    if counter_id == "swiotlb.bounce_attempts":
        return String("count")
    if counter_id == "swiotlb.requested_bytes":
        return String("bytes")
    return String("")


def _worse_coverage(a: String, b: String) -> String:
    """Worse of two coverages for a derived row (oracle-coupled)."""
    var rank_a = 0
    var rank_b = 0
    if a == "partial":
        rank_a = 1
    elif a == "unavailable" or a == "not_applicable":
        rank_a = 2
    if b == "partial":
        rank_b = 1
    elif b == "unavailable" or b == "not_applicable":
        rank_b = 2
    if rank_a >= rank_b:
        return a
    return b


def _group_cause(g: _CounterGroup) -> String:
    """Empty when the group yields a delta; else the cause phrase."""
    if not _known_counter(g.counter_id):
        return String("unknown counter id; no metric mapping")
    var want = _expected_unit(g.counter_id)
    if g.unit != want:
        return (
            "unit mismatch: expected "
            + want
            + ", observed "
            + g.unit
            + "; no delta computed"
        )
    if g.count < 2:
        return String("single snapshot; no pair for a delta")
    if g.has_other_epoch:
        return (
            "epoch changed "
            + format_u64(g.first_epoch)
            + " -> "
            + format_u64(g.other_epoch)
            + "; no delta computed"
        )
    if g.has_decrease:
        return (
            "value decreased "
            + format_u64(g.decrease_from)
            + " -> "
            + format_u64(g.decrease_to)
            + " within epoch "
            + format_u64(g.first_epoch)
            + "; no delta computed"
        )
    if g.has_ts_reorder:
        return String("timestamps out of order; no delta computed")
    return String("")


def _group_scope_label(has_device: Bool, device: String) -> String:
    """Producer scope of one counter group.

    Device-unscoped groups keep the producer's all-devices scope
    even when a capture filter is active: the filter selects which
    detail events were recorded, and its effect on the producer's
    aggregate channel is unknown. Only detail-side scopes carry the
    filter phrase (see _unscoped_devices).
    """
    if has_device:
        return "device " + device
    return String("all devices")


def _windows_overlap(
    starts: List[UInt64], ends: List[UInt64], s: UInt64, e: UInt64
) -> Bool:
    """True when half-open [s, e) meets any recorded window."""
    for i in range(len(starts)):
        var lo = s
        if starts[i] > lo:
            lo = starts[i]
        var hi = e
        if ends[i] < hi:
            hi = ends[i]
        if lo < hi:
            return True
    return False


def _group_before(a: _CounterGroup, b: _CounterGroup) -> Bool:
    if a.counter_id != b.counter_id:
        return a.counter_id < b.counter_id
    var a_dev = String("")
    if a.has_device:
        a_dev = a.device
    var b_dev = String("")
    if b.has_device:
        b_dev = b.device
    if a_dev != b_dev:
        return a_dev < b_dev
    if a.profile != b.profile:
        return a.profile < b.profile
    return a.unit < b.unit


def _coverage(status: String) -> String:
    if status == "complete_for_scope":
        return String("complete_for_scope")
    if status == "partial":
        return String("partial")
    return String("unavailable")


def _summand_text(values: List[UInt64], total: UInt64, n: Int) -> String:
    if n == 0:
        return String("0")
    if n <= MAX_SUMMANDS:
        var out = String("")
        for i in range(len(values)):
            if i > 0:
                out += " + "
            out += format_u64(values[i])
        return out^
    return format_u64(total)


def _detail_metric(
    name: String,
    unit: String,
    has_value: Bool,
    value: UInt64,
    coverage: String,
    has_device: Bool,
    device: String,
    scope: String,
    notes: String,
) -> Metric:
    var m = Metric()
    m.name = name
    m.has_value = has_value
    m.value = value
    m.unit = unit
    if has_value:
        m.measurement = String("observed")
    m.coverage = coverage
    if has_value:
        m.has_aggregation = True
        m.aggregation = String("counter")
    m.has_device_id = has_device
    m.device_id = device
    m.scope = scope
    m.notes = notes
    return m^


def _unavailable_metric(name: String, unit: String, scope: String, notes: String) -> Metric:
    var m = Metric()
    m.name = name
    m.unit = unit
    m.scope = scope
    m.notes = notes
    return m^


struct AttemptAnalyzer:
    """Incremental attempt reducer over one session's events."""

    var _session: Session
    var _total_count: Int
    var _total_bytes: UInt64
    var _total_overflow: Bool
    var _total_summands: List[UInt64]
    var _dev_index: Dict[String, Int]
    var _devs: List[_DeviceAcc]
    var _ctrs: List[_CounterGroup]
    var _ctr_index: Dict[String, Int]
    var _detail_gaps: Int
    var _detail_unknown: Bool
    var _detail_lost: UInt64
    var _detail_lost_overflow: Bool
    var _agg_gaps: Int
    var _agg_unknown: Bool
    var _agg_lost: UInt64
    var _corr_gaps: Int
    var _base_gaps: Int
    var _term_gaps: Int
    var _saw_map: Bool
    var _saw_copy: Bool
    var _saw_unmap: Bool
    var _saw_sync: Bool
    var _ctrs_ignored: Int
    var _fixed_notes: List[String]
    var _data_notes: List[String]
    var _detail_wstart: List[UInt64]
    var _detail_wend: List[UInt64]
    var _agg_wstart: List[UInt64]
    var _agg_wend: List[UInt64]
    var _has_detail_ts: Bool
    var _detail_min_ts: UInt64
    var _detail_max_ts: UInt64
    var _detail_non_observed: Bool
    var _disagree_text: String
    var _disagree_extra: Int
    var _disagree_refs: List[String]

    def __init__(out self, session: Session):
        self._session = session.copy()
        self._total_count = 0
        self._total_bytes = UInt64(0)
        self._total_overflow = False
        self._total_summands = List[UInt64]()
        self._dev_index = Dict[String, Int]()
        self._devs = List[_DeviceAcc]()
        self._ctrs = List[_CounterGroup]()
        self._ctr_index = Dict[String, Int]()
        self._detail_gaps = 0
        self._detail_unknown = False
        self._detail_lost = UInt64(0)
        self._detail_lost_overflow = False
        self._agg_gaps = 0
        self._agg_unknown = False
        self._agg_lost = UInt64(0)
        self._corr_gaps = 0
        self._base_gaps = 0
        self._term_gaps = 0
        self._saw_map = False
        self._saw_copy = False
        self._saw_unmap = False
        self._saw_sync = False
        self._ctrs_ignored = 0
        self._fixed_notes = List[String]()
        self._data_notes = List[String]()
        self._detail_wstart = List[UInt64]()
        self._detail_wend = List[UInt64]()
        self._agg_wstart = List[UInt64]()
        self._agg_wend = List[UInt64]()
        self._has_detail_ts = False
        self._detail_min_ts = UInt64(0)
        self._detail_max_ts = UInt64(0)
        self._detail_non_observed = False
        self._disagree_text = String("")
        self._disagree_extra = 0
        self._disagree_refs = List[String]()

    def _note_fixed(mut self, text: String):
        """Record one structural limitation (few by construction)."""
        self._fixed_notes.append(text)

    def _note_data(mut self, text: String):
        """Record one data-driven limitation (bounded at merge)."""
        self._data_notes.append(text)

    def _saw_lifecycle(self) -> Bool:
        """True once any lifecycle-kind event was consumed."""
        return (
            self._saw_map
            or self._saw_copy
            or self._saw_unmap
            or self._saw_sync
        )

    def _unscoped_devices(self) -> String:
        """Device phrase for totals spanning the recorded set.

        Without a capture filter the totals cover every recorded
        device; with one, only the filtered subset was recorded, so
        the literal filter stays in the scope instead of claiming
        all devices.
        """
        if self._session.has_filter_device:
            return (
                "recorded devices (filter: "
                + self._session.filter_device
                + ")"
            )
        return String("all devices")

    def consume(mut self, ev: Event) raises:
        """Fold one validated event into the reduction."""
        if ev.kind == "bounce_attempt":
            self._consume_bounce(ev)
        elif ev.kind == "counter_snapshot":
            self._consume_snapshot(ev)
        elif ev.kind == "gap":
            self._consume_gap(ev)
        elif ev.kind == "map_result":
            self._saw_map = True
        elif ev.kind == "copy":
            self._saw_copy = True
        elif ev.kind == "unmap":
            self._saw_unmap = True
        elif ev.kind == "sync_request":
            self._saw_sync = True

    def _consume_bounce(mut self, ev: Event) raises:
        self._total_count += 1
        if not self._has_detail_ts:
            self._has_detail_ts = True
            self._detail_min_ts = ev.ts_ns
            self._detail_max_ts = ev.ts_ns
        else:
            if ev.ts_ns < self._detail_min_ts:
                self._detail_min_ts = ev.ts_ns
            if ev.ts_ns > self._detail_max_ts:
                self._detail_max_ts = ev.ts_ns
        if ev.source_measurement != "observed":
            self._detail_non_observed = True
        try:
            self._total_bytes = checked_add(
                self._total_bytes, ev.bounce.requested_bytes
            )
        except:
            self._total_overflow = True
        if len(self._total_summands) < MAX_SUMMANDS:
            self._total_summands.append(ev.bounce.requested_bytes)
        var dev = ev.bounce.device_id
        var idx = -1
        if dev in self._dev_index:
            idx = self._dev_index[dev]
        if idx < 0:
            var fresh = _DeviceAcc()
            fresh.device_id = ev.bounce.device_id
            self._devs.append(fresh^)
            idx = len(self._devs) - 1
            self._dev_index[dev] = idx
        self._devs[idx].count += 1
        if not self._devs[idx].has_ts:
            self._devs[idx].has_ts = True
            self._devs[idx].min_ts = ev.ts_ns
            self._devs[idx].max_ts = ev.ts_ns
        else:
            if ev.ts_ns < self._devs[idx].min_ts:
                self._devs[idx].min_ts = ev.ts_ns
            if ev.ts_ns > self._devs[idx].max_ts:
                self._devs[idx].max_ts = ev.ts_ns
        try:
            self._devs[idx].total_bytes = checked_add(
                self._devs[idx].total_bytes, ev.bounce.requested_bytes
            )
        except:
            self._devs[idx].bytes_overflow = True
        if len(self._devs[idx].summands) < MAX_SUMMANDS:
            self._devs[idx].summands.append(ev.bounce.requested_bytes)

    def _consume_snapshot(mut self, ev: Event) raises:
        var flag = String("0")
        if ev.snapshot.has_scope_device:
            flag = String("1")
        var counter = ev.snapshot.counter_id
        var dev = ev.snapshot.scope_device_id
        var profile = ev.snapshot.scope_profile_id
        var unit = ev.snapshot.unit
        var hook = ev.source_hook
        var backend = ev.source_backend
        var src_profile = ev.source_profile_id
        var measurement = ev.source_measurement
        var correlation = ev.source_correlation
        var key = (
            flag
            + "#"
            + String(counter.byte_length())
            + "#"
            + counter
            + "#"
            + String(dev.byte_length())
            + "#"
            + dev
            + "#"
            + String(profile.byte_length())
            + "#"
            + profile
            + "#"
            + String(unit.byte_length())
            + "#"
            + unit
            + "#"
            + String(hook.byte_length())
            + "#"
            + hook
            + "#"
            + String(backend.byte_length())
            + "#"
            + backend
            + "#"
            + String(src_profile.byte_length())
            + "#"
            + src_profile
            + "#"
            + String(measurement.byte_length())
            + "#"
            + measurement
            + "#"
            + String(correlation.byte_length())
            + "#"
            + correlation
        )
        var idx: Int
        try:
            idx = self._ctr_index[key]
        except:
            idx = -1
        if idx < 0:
            if len(self._ctrs) >= _MAX_COUNTER_GROUPS:
                self._ctrs_ignored += 1
                return
            self._ctr_index[key] = len(self._ctrs)
            var g = _CounterGroup()
            g.counter_id = ev.snapshot.counter_id
            g.has_device = ev.snapshot.has_scope_device
            g.device = ev.snapshot.scope_device_id
            g.profile = ev.snapshot.scope_profile_id
            g.unit = ev.snapshot.unit
            g.source_hook = ev.source_hook
            g.source_backend = ev.source_backend
            g.source_profile = ev.source_profile_id
            g.source_measurement = ev.source_measurement
            g.source_correlation = ev.source_correlation
            g.first_epoch = ev.snapshot.epoch
            g.first_value = ev.snapshot.value
            g.first_ts = ev.ts_ns
            g.last_epoch = ev.snapshot.epoch
            g.last_value = ev.snapshot.value
            g.last_ts = ev.ts_ns
            g.max_value = ev.snapshot.value
            g.count = 1
            self._ctrs.append(g^)
            return
        self._ctrs[idx].count += 1
        if ev.ts_ns < self._ctrs[idx].last_ts:
            self._ctrs[idx].has_ts_reorder = True
        self._ctrs[idx].last_epoch = ev.snapshot.epoch
        self._ctrs[idx].last_value = ev.snapshot.value
        self._ctrs[idx].last_ts = ev.ts_ns
        if ev.snapshot.epoch != self._ctrs[idx].first_epoch:
            if not self._ctrs[idx].has_other_epoch:
                self._ctrs[idx].has_other_epoch = True
                self._ctrs[idx].other_epoch = ev.snapshot.epoch
        if ev.snapshot.value < self._ctrs[idx].max_value:
            if not self._ctrs[idx].has_decrease:
                self._ctrs[idx].has_decrease = True
                self._ctrs[idx].decrease_from = self._ctrs[idx].max_value
                self._ctrs[idx].decrease_to = ev.snapshot.value
        if ev.snapshot.value > self._ctrs[idx].max_value:
            self._ctrs[idx].max_value = ev.snapshot.value

    def _consume_gap(mut self, ev: Event) raises:
        if ev.gap.channel == "detail":
            self._detail_gaps += 1
            if _windows_overlap(
                self._detail_wstart,
                self._detail_wend,
                ev.gap.window_start_ns,
                ev.gap.window_end_ns,
            ):
                self._detail_unknown = True
            self._detail_wstart.append(ev.gap.window_start_ns)
            self._detail_wend.append(ev.gap.window_end_ns)
            if not ev.gap.has_lost_count:
                self._detail_unknown = True
            else:
                try:
                    self._detail_lost = checked_add(
                        self._detail_lost, ev.gap.lost_count
                    )
                except:
                    self._detail_lost_overflow = True
                    self._detail_unknown = True
        elif ev.gap.channel == "aggregate":
            self._agg_gaps += 1
            if _windows_overlap(
                self._agg_wstart,
                self._agg_wend,
                ev.gap.window_start_ns,
                ev.gap.window_end_ns,
            ):
                self._agg_unknown = True
            self._agg_wstart.append(ev.gap.window_start_ns)
            self._agg_wend.append(ev.gap.window_end_ns)
            if not ev.gap.has_lost_count:
                self._agg_unknown = True
            else:
                try:
                    self._agg_lost = checked_add(
                        self._agg_lost, ev.gap.lost_count
                    )
                except:
                    self._agg_unknown = True
        elif ev.gap.channel == "correlation":
            self._corr_gaps += 1
        elif ev.gap.channel == "baseline":
            self._base_gaps += 1
        elif ev.gap.channel == "terminal":
            self._term_gaps += 1

    def _group_order(self) -> List[Int]:
        var order = List[Int]()
        for i in range(len(self._ctrs)):
            order.append(i)
        if len(order) > 1:
            _quicksort_order(order, self._ctrs, 0, len(order) - 1)
        return order^

    def _snapshot_total(self) -> Int:
        var total = 0
        for i in range(len(self._ctrs)):
            total += self._ctrs[i].count
        return total

    def _build_detail(mut self, partial: Bool) -> Channel:
        var ch = Channel()
        var producer = self._session.q_detail.copy()
        var gaps = self._detail_gaps > 0
        if gaps or partial:
            ch.status = String("partial")
        elif producer.status == "complete_for_scope":
            ch.status = String("complete_for_scope")
        elif producer.status == "unavailable" and self._total_count == 0:
            ch.status = String("unavailable")
        elif (
            producer.status == "unavailable"
            or producer.status == "not_applicable"
        ):
            ch.status = String("partial")
            self._note_fixed(
                "Producer detail status "
                + producer.status
                + " contradicts "
                + _plural(
                    self._total_count,
                    "observed event.",
                    "observed events.",
                )
            )
        else:
            ch.status = producer.status
        var producer_zero = (
            producer.status == "complete_for_scope"
            and producer.has_loss_count
            and producer.loss_count == UInt64(0)
        )
        if partial:
            ch.has_loss_count = False
        elif gaps and producer_zero and not self._detail_unknown:
            ch.has_loss_count = True
            ch.loss_count = self._detail_lost
        elif gaps or self._detail_unknown or not producer.has_loss_count:
            ch.has_loss_count = False
        else:
            ch.has_loss_count = True
            ch.loss_count = producer.loss_count
        if gaps and not producer_zero and producer.has_loss_count:
            self._note_fixed(
                String(
                    "Observed detail gaps may overlap the producer loss count;"
                    " total unknown."
                )
            )
        var scope = _plural(
            self._total_count,
            "bounce_attempt event",
            "bounce_attempt events",
        )
        if gaps:
            scope += ", " + _plural(
                self._detail_gaps, "detail gap", "detail gaps"
            )
        if partial:
            scope += ", truncated tail dropped"
        ch.scope = scope
        if gaps:
            ch.reason = _plural(
                self._detail_gaps,
                "Detail gap event observed; counts are lower bounds.",
                "Detail gap events observed; counts are lower bounds.",
            )
            if partial:
                ch.reason += " Truncated tail dropped."
            if not ch.has_loss_count:
                ch.reason += " Loss total unknown."
        elif partial:
            ch.reason = (
                "Truncated tail dropped; counts exclude it. Producer detail"
                " status "
                + producer.status
                + "."
            )
        elif producer.status != "complete_for_scope":
            var loss_desc = String("loss unknown")
            if producer.has_loss_count:
                loss_desc = "loss " + format_u64(producer.loss_count)
            ch.reason = (
                "Producer detail status "
                + producer.status
                + " ("
                + loss_desc
                + "); "
                + _plural(
                    self._total_count,
                    "event observed without gaps.",
                    "events observed without gaps.",
                )
            )
        elif (
            producer.has_loss_count and producer.loss_count > UInt64(0)
        ):
            ch.reason = (
                "Producer detail status complete_for_scope (loss "
                + format_u64(producer.loss_count)
                + "); "
                + _plural(
                    self._total_count,
                    "event observed without gaps.",
                    "events observed without gaps.",
                )
            )
        elif not producer.has_loss_count:
            ch.reason = (
                "Producer detail status complete_for_scope (loss unknown); "
                + _plural(
                    self._total_count,
                    "event observed without gaps.",
                    "events observed without gaps.",
                )
            )
        elif self._session.synthetic:
            ch.reason = String("Authored fixture: no loss.")
        else:
            ch.reason = String("No detail loss observed.")
        return ch^

    def _build_aggregate(
        mut self, noun: String, order: List[Int]
    ) -> Channel:
        var ch = Channel()
        var producer = self._session.q_aggregate.copy()
        var snapshots = self._snapshot_total()
        var unusable = 0
        for oi in range(len(order)):
            if _group_cause(self._ctrs[order[oi]]) != "":
                unusable += 1
        var usable = len(order) - unusable
        var omitted = self._ctrs_ignored
        var contradict = (
            self._agg_gaps > 0
            or unusable > 0
            or omitted > 0
            or (
                snapshots > 0
                and (
                    producer.status == "unavailable"
                    or producer.status == "not_applicable"
                )
            )
        )
        if contradict:
            if self._agg_gaps > 0 or unusable > 0 or omitted > 0:
                ch.status = String("partial")
            else:
                ch.status = String("complete_for_scope")
        else:
            ch.status = producer.status
        var agg_gaps = self._agg_gaps > 0
        var agg_zero = (
            producer.status == "complete_for_scope"
            and producer.has_loss_count
            and producer.loss_count == UInt64(0)
        )
        if agg_gaps and agg_zero and not self._agg_unknown and omitted == 0:
            ch.has_loss_count = True
            ch.loss_count = self._agg_lost
        elif (
            agg_gaps
            or self._agg_unknown
            or omitted > 0
            or not producer.has_loss_count
        ):
            ch.has_loss_count = False
        else:
            ch.has_loss_count = True
            ch.loss_count = producer.loss_count
        if agg_gaps and not agg_zero and producer.has_loss_count:
            self._note_fixed(
                String(
                    "Observed aggregate gaps may overlap the producer loss"
                    " count; total unknown."
                )
            )
        ch.scope = String("counter snapshots")
        if snapshots == 0:
            ch.reason = "No counter snapshots in this " + noun + "."
            if agg_gaps:
                ch.reason += " " + _plural(
                    self._agg_gaps,
                    "aggregate gap event observed.",
                    "aggregate gap events observed.",
                )
        else:
            var reason = (
                _plural(
                    usable, "usable counter group", "usable counter groups"
                )
                + "; "
                + _plural(usable, "delta computed.", "deltas computed.")
            )
            if unusable > 0:
                reason += (
                    " "
                    + String(unusable)
                    + " groups unusable (see limitations)."
                )
            if omitted > 0:
                reason += (
                    " "
                    + _plural(
                        omitted,
                        "counter reading omitted:",
                        "counter readings omitted:",
                    )
                    + " admission bound reached."
                )
            if self._agg_gaps > 0:
                reason += " " + _plural(
                    self._agg_gaps,
                    "aggregate gap event observed.",
                    "aggregate gap events observed.",
                )
            ch.reason = reason
        var observed = snapshots + omitted
        if observed > 0 and (
            producer.status == "unavailable"
            or producer.status == "not_applicable"
        ):
            self._note_fixed(
                "Producer aggregate status "
                + producer.status
                + " contradicts "
                + _plural(
                    observed, "observed snapshot.", "observed snapshots."
                )
            )
        if self._agg_gaps > 0:
            var lost = String("unknown")
            if not self._agg_unknown:
                lost = format_u64(self._agg_lost)
            self._note_fixed(
                _plural(
                    self._agg_gaps,
                    "aggregate gap event",
                    "aggregate gap events",
                )
                + " ("
                + lost
                + " lost)."
            )
        for oi in range(len(order)):
            var g = self._ctrs[order[oi]]
            var cause = _group_cause(g)
            if cause != "":
                self._note_data(
                    "Counter "
                    + g.counter_id
                    + " ("
                    + _group_scope_label(g.has_device, g.device)
                    + "): "
                    + cause
                    + "."
                )
        return ch^

    def _build_terminal(mut self, partial: Bool) -> Channel:
        var ch: Channel
        var term_gaps = self._term_gaps > 0
        if self._session.finalized and not partial and not term_gaps:
            ch = self._session.q_terminal.copy()
        else:
            ch = Channel()
            ch.status = String("partial")
            ch.scope = self._session.q_terminal.scope
            if not self._session.finalized and partial:
                ch.reason = String(
                    "Capture not finalized; final event line dropped as"
                    " truncated (--allow-partial)."
                )
            elif not self._session.finalized:
                ch.reason = String(
                    "Capture not finalized; window may be incomplete."
                )
            elif partial:
                ch.reason = String(
                    "Final event line dropped as truncated (--allow-partial)."
                )
            else:
                ch.reason = String("")
            if term_gaps:
                var phrase = _plural(
                    self._term_gaps,
                    "terminal gap event observed;",
                    "terminal gap events observed;",
                ) + " settlement unverified."
                if ch.reason != "":
                    ch.reason += " "
                ch.reason += phrase
        if not self._session.finalized:
            self._note_fixed(
                String("Capture not finalized; terminal loss unknown.")
            )
        if partial:
            self._note_fixed(
                String("Dropped 1 truncated tail line; counts exclude it.")
            )
        if term_gaps:
            self._note_fixed(
                _plural(
                    self._term_gaps,
                    "terminal gap event observed;",
                    "terminal gap events observed;",
                )
                + " settlement unverified."
            )
        return ch^

    def _build_correlation(mut self) -> Channel:
        var producer = self._session.q_correlation.copy()
        if self._corr_gaps == 0:
            return producer^
        var ch = Channel()
        ch.status = String("partial")
        ch.scope = producer.scope
        ch.reason = _plural(
            self._corr_gaps,
            "correlation gap event observed;",
            "correlation gap events observed;",
        ) + " cross-event evidence may be missing."
        self._note_fixed(
            _plural(
                self._corr_gaps,
                "correlation gap event observed;",
                "correlation gap events observed;",
            )
            + " channel partial."
        )
        return ch^

    def _build_baseline(mut self) -> Channel:
        var producer = self._session.q_baseline.copy()
        if self._base_gaps == 0:
            return producer^
        var ch = Channel()
        ch.status = String("partial")
        ch.scope = producer.scope
        ch.reason = _plural(
            self._base_gaps,
            "baseline gap event observed;",
            "baseline gap events observed;",
        ) + " baseline coverage unverified."
        self._note_fixed(
            _plural(
                self._base_gaps,
                "baseline gap event observed;",
                "baseline gap events observed;",
            )
            + " channel partial."
        )
        return ch^

    def _build_metrics(
        mut self,
        mut out: Report,
        window: String,
        noun: String,
        order: List[Int],
        partial: Bool,
        has_pools: Bool,
        has_regions: Bool,
    ) raises:
        var detail_cov = _coverage(out.q_detail.status)
        var agg_cov = _coverage(out.q_aggregate.status)
        var snapshots = self._snapshot_total()
        var snap_frag = String("; no counter snapshots to compare.")
        if snapshots > 0:
            snap_frag = (
                "; "
                + _plural(
                    snapshots,
                    "counter snapshot observed separately (never added).",
                    "counter snapshots observed separately (never added).",
                )
            )
        var gap_frag = String("")
        if self._detail_gaps > 0:
            gap_frag = "; counts are lower bounds."
        var partial_frag = String("")
        if partial:
            partial_frag = "; truncated tail excluded."
        var producer_detail = self._session.q_detail.status
        var usable_detail = (
            self._total_count > 0
            or producer_detail == "complete_for_scope"
            or producer_detail == "partial"
        )
        var all_scope = window + ", " + self._unscoped_devices() + ", detail channel"
        if usable_detail:
            out.metrics.append(
                _detail_metric(
                    String("bounce_attempts"),
                    String("count"),
                    True,
                    UInt64(self._total_count),
                    detail_cov,
                    False,
                    String(""),
                    all_scope,
                    _plural(
                        self._total_count, "detail event", "detail events"
                    )
                    + snap_frag
                    + gap_frag
                    + partial_frag,
                )
            )
        else:
            out.metrics.append(
                _detail_metric(
                    String("bounce_attempts"),
                    String("count"),
                    True,
                    UInt64(0),
                    detail_cov,
                    False,
                    String(""),
                    all_scope,
                    "0 detail events observed; producer status "
                    + producer_detail
                    + ": zero is unconfirmed.",
                )
            )
        var ids = List[String]()
        for i in range(len(self._devs)):
            ids.append(self._devs[i].device_id)
        var sorted_ids = _sorted_strings(ids)
        var single = len(sorted_ids) == 1
        var detailed = len(sorted_ids)
        if detailed > _MAX_DETAILED_DEVICES:
            detailed = _MAX_DETAILED_DEVICES
        var withheld_devs = len(sorted_ids) - detailed
        for si in range(detailed):
            var idx = self._dev_index[sorted_ids[si]]
            var dev_id = self._devs[idx].device_id
            var dev_count = self._devs[idx].count
            var scope = window + ", device " + dev_id + ", detail channel"
            var cnt = _plural(
                dev_count,
                "attempt observed device",
                "attempts observed device",
            )
            var note: String
            if single:
                note = "All " + cnt + " " + dev_id + "."
            else:
                note = cnt + " " + dev_id + "."
            note += gap_frag
            note += partial_frag
            out.metrics.append(
                _detail_metric(
                    String("bounce_attempts"),
                    String("count"),
                    True,
                    UInt64(dev_count),
                    detail_cov,
                    True,
                    dev_id,
                    scope,
                    note,
                )
            )
        if usable_detail and not self._total_overflow:
            var text = _summand_text(
                self._total_summands, self._total_bytes, self._total_count
            )
            var outcome_frag = (
                "; allocation outcomes are unavailable in this "
                + noun
                + "."
            )
            if self._saw_map:
                outcome_frag = (
                    "; see successful_allocations for observed"
                    " outcomes."
                )
            out.metrics.append(
                _detail_metric(
                    String("requested_bounce_bytes"),
                    String("bytes"),
                    True,
                    self._total_bytes,
                    detail_cov,
                    False,
                    String(""),
                    all_scope,
                    text
                    + " requested bytes across "
                    + _plural(
                        self._total_count, "attempt", "attempts"
                    )
                    + outcome_frag
                    + gap_frag
                    + partial_frag,
                )
            )
        elif usable_detail:
            out.metrics.append(
                _detail_metric(
                    String("requested_bounce_bytes"),
                    String("bytes"),
                    False,
                    UInt64(0),
                    String("unavailable"),
                    False,
                    String(""),
                    all_scope,
                    String(
                        "Requested-byte total exceeds u64 range;"
                        " value withheld."
                    ),
                )
            )
        else:
            out.metrics.append(
                _detail_metric(
                    String("requested_bounce_bytes"),
                    String("bytes"),
                    True,
                    UInt64(0),
                    detail_cov,
                    False,
                    String(""),
                    all_scope,
                    "0 requested bytes observed; producer status "
                    + producer_detail
                    + ": zero is unconfirmed.",
                )
            )
        for si in range(detailed):
            var idx = self._dev_index[sorted_ids[si]]
            var dev_id = self._devs[idx].device_id
            var scope = window + ", device " + dev_id + ", detail channel"
            if not self._devs[idx].bytes_overflow:
                var text = _summand_text(
                    self._devs[idx].summands,
                    self._devs[idx].total_bytes,
                    self._devs[idx].count,
                )
                out.metrics.append(
                    _detail_metric(
                        String("requested_bounce_bytes"),
                        String("bytes"),
                        True,
                        self._devs[idx].total_bytes,
                        detail_cov,
                        True,
                        dev_id,
                        scope,
                        text
                        + " requested bytes on device "
                        + dev_id
                        + "."
                        + gap_frag
                        + partial_frag,
                    )
                )
            else:
                out.metrics.append(
                    _detail_metric(
                        String("requested_bounce_bytes"),
                        String("bytes"),
                        False,
                        UInt64(0),
                        String("unavailable"),
                        True,
                        dev_id,
                        scope,
                        String(
                            "Requested-byte total exceeds u64 range;"
                            " value withheld."
                        ),
                    )
                )
        var prev_emitted = False
        var prev_name = String("")
        var prev_has_device = False
        var prev_device = String("")
        var row_cov = _worse_coverage(
            agg_cov, _coverage(out.q_detail.status)
        )
        if withheld_devs > 0:
            self._note_fixed(
                _plural(
                    withheld_devs,
                    "device lacks detail rows:",
                    "devices lack detail rows:",
                )
                + " metric budget exhausted."
            )
        var rows_left = (
            _MAX_METRICS - 2 - 2 * detailed - _FIXED_TAIL_METRICS
        )
        var rows_withheld = 0
        for oi in range(len(order)):
            var g = self._ctrs[order[oi]]
            if _group_cause(g) != "":
                continue
            var delta = g.last_value - g.first_value
            var cname = _counter_metric_name(g.counter_id)
            if (
                prev_emitted
                and cname == prev_name
                and g.has_device == prev_has_device
                and g.device == prev_device
            ):
                self._note_data(
                    "Additional "
                    + g.counter_id
                    + " group ("
                    + _group_scope_label(g.has_device, g.device)
                    + ", profile "
                    + g.profile
                    + ") excluded from metrics; one row per name and"
                    " dimensions."
                )
                continue
            if rows_left <= 0:
                rows_withheld += 1
                continue
            var scope = (
                "readings ["
                + format_u64(g.first_ts)
                + ","
                + format_u64(g.last_ts)
                + "), "
                + _group_scope_label(g.has_device, g.device)
                + ", aggregate channel"
            )
            var notes = (
                "Counter delta "
                + format_u64(g.first_value)
                + " -> "
                + format_u64(g.last_value)
                + " ("
                + g.counter_id
                + "); detail events counted separately (never added)."
            )
            var cm = _detail_metric(
                cname,
                g.unit,
                True,
                delta,
                row_cov,
                g.has_device,
                g.device,
                scope,
                notes,
            )
            cm.measurement = String("derived")
            out.metrics.append(cm^)
            rows_left -= 1
            prev_emitted = True
            prev_name = cname
            prev_has_device = g.has_device
            prev_device = g.device
        if self._ctrs_ignored > 0:
            self._note_fixed(
                _plural(
                    self._ctrs_ignored,
                    "counter reading ignored:",
                    "counter readings ignored:",
                )
                + " admission bound reached."
            )
        if rows_withheld > 0:
            self._note_fixed(
                _plural(
                    rows_withheld,
                    "counter delta withheld:",
                    "counter deltas withheld:",
                )
                + " metric budget exhausted."
            )
        var uscope = window + ", " + self._unscoped_devices()
        # Placeholders are skipped exactly when the composed
        # engine's tracker rows cover the same (name,
        # dimensions) key, so each key keeps one measurement
        # channel.
        if not self._saw_lifecycle():
            out.metrics.append(
                _unavailable_metric(
                    String("successful_allocations"),
                    String("count"),
                    uscope,
                    "No map_result source in this "
                    + noun
                    + "; attempts are not successes.",
                )
            )
            out.metrics.append(
                _unavailable_metric(
                    String("copy_original_to_bounce_bytes"),
                    String("bytes"),
                    uscope,
                    "No copy source in this " + noun + ".",
                )
            )
            out.metrics.append(
                _unavailable_metric(
                    String("copy_bounce_to_original_bytes"),
                    String("bytes"),
                    uscope,
                    "No copy source in this " + noun + ".",
                )
            )
            out.metrics.append(
                _unavailable_metric(
                    String("live_observed_allocation_bytes"),
                    String("bytes"),
                    uscope,
                    "No lifecycle source in this " + noun + ".",
                )
            )
        if not self._saw_map and not self._saw_unmap:
            out.metrics.append(
                _unavailable_metric(
                    String("observed_mapping_lifetime_ns"),
                    String("nanoseconds"),
                    uscope,
                    "No lifecycle source in this " + noun + ".",
                )
            )
        if not has_regions:
            out.metrics.append(
                _unavailable_metric(
                    String("conversion_request_bytes"),
                    String("bytes"),
                    uscope,
                    "No conversion source in this " + noun + ".",
                )
            )
            out.metrics.append(
                _unavailable_metric(
                    String("known_shared_region_bytes"),
                    String("bytes"),
                    uscope,
                    "No region source in this " + noun + ".",
                )
            )
        if not has_pools:
            out.metrics.append(
                _unavailable_metric(
                    String("pool_used_bytes"),
                    String("bytes"),
                    uscope,
                    "No pool source in this " + noun + ".",
                )
            )
            out.metrics.append(
                _unavailable_metric(
                    String("pool_capacity_bytes"),
                    String("bytes"),
                    uscope,
                    "No pool source in this " + noun + ".",
                )
            )

    def finish(
        mut self,
        end_ns: UInt64,
        partial: Bool,
        has_pools: Bool = False,
        has_regions: Bool = False,
    ) raises -> Report:
        """Reduce the consumed stream to one Report.

        end_ns must equal the session window end: counts always
        cover the whole capture, so a narrowed horizon would label
        a scope the measurements do not match. Partial reports a
        dropped truncated tail. The composed engine passes
        has_pools/has_regions when it appends pool/region rows;
        lifecycle scope is detected from the consumed stream
        itself.
        """
        if (
            end_ns < self._session.window_start_ns
            or end_ns > self._session.window_end_ns
        ):
            raise AnalysisError("horizon outside session window")
        if end_ns != self._session.window_end_ns:
            raise AnalysisError("narrowed horizon unsupported")
        return self._render(end_ns, partial, has_pools, has_regions)

    def snapshot(
        mut self,
        end_ns: UInt64,
        partial: Bool,
        has_pools: Bool = False,
        has_regions: Bool = False,
    ) raises -> Report:
        """Reduce the stream so far through the finish reducers.

        Unlike finish, the horizon may narrow to a replay prefix.
        The build checkpoints and restores its note state, so
        snapshot and finish share every reducer with no
        destructive finalization; the equivalence tests pin this.
        """
        if (
            end_ns < self._session.window_start_ns
            or end_ns > self._session.window_end_ns
        ):
            raise AnalysisError("horizon outside session window")
        return self._render(end_ns, partial, has_pools, has_regions)

    def _render(
        mut self,
        end_ns: UInt64,
        partial: Bool,
        has_pools: Bool,
        has_regions: Bool,
    ) raises -> Report:
        """Build one report, restoring mutable build state after."""
        var saved_fixed = List[String]()
        for i in range(len(self._fixed_notes)):
            saved_fixed.append(self._fixed_notes[i])
        var saved_data = List[String]()
        for i in range(len(self._data_notes)):
            saved_data.append(self._data_notes[i])
        var saved_text = self._disagree_text
        var saved_extra = self._disagree_extra
        var saved_refs = List[String]()
        for i in range(len(self._disagree_refs)):
            saved_refs.append(self._disagree_refs[i])
        var out = self._build(end_ns, partial, has_pools, has_regions)
        self._fixed_notes = saved_fixed^
        self._data_notes = saved_data^
        self._disagree_text = saved_text
        self._disagree_extra = saved_extra
        self._disagree_refs = saved_refs^
        return out^

    def _build(
        mut self,
        end_ns: UInt64,
        partial: Bool,
        has_pools: Bool,
        has_regions: Bool,
    ) raises -> Report:
        var out = Report()
        out.session_id = self._session.session_id
        out.synthetic = self._session.synthetic
        out.engine_version = String(ENGINE_VERSION)
        out.window_start_ns = self._session.window_start_ns
        out.window_end_ns = end_ns
        out.env.mode = self._session.env_mode
        out.env.detection = self._session.env_detection
        out.env.has_asserted_mode = self._session.has_asserted_mode
        out.env.asserted_mode = self._session.asserted_mode
        out.env.asserted_mode_present = self._session.asserted_mode_present
        out.env.attestation = self._session.env_attestation
        for i in range(len(self._session.evidence)):
            out.env.evidence.append(self._session.evidence[i])
        for i in range(len(self._session.devices)):
            out.devices.append(self._session.devices[i])
        var window = window_label(self._session.window_start_ns, end_ns)
        var noun = String("capture")
        if self._session.synthetic:
            noun = String("fixture")
        if self._session.synthetic:
            self._note_fixed(
                String(
                    "Synthetic fixture: every value is authored test data;"
                    " no guest was booted and no hook attached."
                )
            )
        if has_regions:
            self._note_fixed(
                String(
                    "This analyzer reduces bounce attempts, counter"
                    " deltas, and observed lifecycle/pool/region"
                    " scope; task-context metrics are unavailable."
                )
            )
        elif self._saw_lifecycle() or has_pools:
            self._note_fixed(
                String(
                    "This analyzer reduces bounce attempts, counter"
                    " deltas, and observed lifecycle/pool scope;"
                    " conversion, region, and task-context metrics"
                    " are unavailable."
                )
            )
        else:
            self._note_fixed(
                String(
                    "This analyzer reduces bounce attempts and counter"
                    " deltas only; lifecycle, copy, sync, conversion,"
                    " region, pool, and task-context metrics are"
                    " unavailable."
                )
            )
        if self._snapshot_total() == 0:
            self._note_fixed(
                String(
                    "No counter snapshots: attempt totals rest on the detail"
                    " channel alone."
                )
            )
        var order = self._group_order()
        out.q_detail = self._build_detail(partial)
        out.q_aggregate = self._build_aggregate(noun, order)
        out.q_correlation = self._build_correlation()
        out.q_baseline = self._build_baseline()
        if self._detail_gaps > 0:
            var lost = String("unknown")
            if not self._detail_unknown:
                lost = format_u64(self._detail_lost)
            self._note_fixed(
                "Detail loss: "
                + _plural(
                    self._detail_gaps, "gap event", "gap events"
                )
                + " ("
                + lost
                + " lost); attempt counts are lower bounds."
            )
        var overflow = self._total_overflow
        for i in range(len(self._devs)):
            if self._devs[i].bytes_overflow:
                overflow = True
        if overflow:
            self._note_fixed(
                String(
                    "Requested-byte total exceeds u64 range; values withheld."
                )
            )
        out.q_terminal = self._build_terminal(partial)
        self._build_metrics(
            out, window, noun, order, partial, has_pools, has_regions
        )
        self._compare_counters(out)
        var causes = List[String]()
        var refs = List[String]()
        if self._detail_gaps > 0:
            causes.append(String("Detail loss observed"))
            refs.append(String("channel:detail-loss"))
        if not self._session.finalized:
            causes.append(String("capture not finalized"))
            refs.append(String("capture:finalized=false"))
        if partial:
            causes.append(String("truncated tail dropped"))
            refs.append(String("capture:partial-tail"))
        if self._term_gaps > 0:
            causes.append(String("terminal gap observed"))
            refs.append(String("channel:terminal-gap"))
        if out.counter_disagreement:
            var cause = String("counter cross-check disagrees: ")
            cause += self._disagree_text
            if self._disagree_extra > 0:
                cause += " " + _plural(
                    self._disagree_extra,
                    "further disagreement",
                    "further disagreements",
                )
            causes.append(cause^)
            for i in range(len(self._disagree_refs)):
                refs.append(self._disagree_refs[i])
        if len(causes) > 0:
            var f = Finding()
            f.code = String("CAPTURE_INCOMPLETE")
            f.severity = String("warning")
            var expl = String("Capture incomplete: ")
            for i in range(len(causes)):
                if i > 0:
                    expl += "; "
                expl += causes[i]
            expl += "."
            f.explanation = expl
            f.evidence_refs = refs^
            f.scope = window
            f.limitations = String(
                "Counts exclude missing evidence; rerun the capture to close"
                " the gap."
            )
            out.findings.append(f^)
        self._merge_limitations(out)
        return out^

    def _compare_counters(mut self, mut out: Report):
        """Cross-check usable counter deltas against detail counts.

        A pair is comparable only when quantities and units match by
        construction, device scopes align, both sides are observed,
        the reading interval strictly contains the detail span, the
        detail channel is complete with known zero loss, no
        relevant byte total overflowed, no capture filter hides the
        group's scope, and a device-scoped group has observed detail
        for its device. Anything else is inconclusive, never a
        disagreement. A mismatch on a comparable pair sets the
        disagreement flag.
        """
        var detail_ok = (
            out.q_detail.status == "complete_for_scope"
            and out.q_detail.has_loss_count
            and out.q_detail.loss_count == UInt64(0)
            and not self._detail_non_observed
        )
        var inconclusive = 0
        for ci in range(len(self._ctrs)):
            var g = self._ctrs[ci]
            if _group_cause(g) != "":
                continue
            var want_count = g.counter_id == "swiotlb.bounce_attempts"
            var want_bytes = g.counter_id == "swiotlb.requested_bytes"
            if not want_count and not want_bytes:
                continue
            var detail_val: UInt64
            var overflow = False
            var has_span = False
            var dmin = UInt64(0)
            var dmax = UInt64(0)
            var label = String("all devices")
            if g.has_device:
                label = "device " + g.device
                try:
                    var di = self._dev_index[g.device]
                    if want_count:
                        detail_val = UInt64(self._devs[di].count)
                    else:
                        detail_val = self._devs[di].total_bytes
                    overflow = self._devs[di].bytes_overflow
                    has_span = self._devs[di].has_ts
                    dmin = self._devs[di].min_ts
                    dmax = self._devs[di].max_ts
                except:
                    detail_val = UInt64(0)
            else:
                if want_count:
                    detail_val = UInt64(self._total_count)
                else:
                    detail_val = self._total_bytes
                overflow = self._total_overflow
                has_span = self._has_detail_ts
                dmin = self._detail_min_ts
                dmax = self._detail_max_ts
            var contained = True
            if has_span:
                contained = (
                    g.first_ts < dmin and dmax < g.last_ts
                )
            var scope_ok = True
            if g.has_device:
                scope_ok = has_span
            elif self._session.has_filter_device:
                scope_ok = False
            var comparable = (
                detail_ok
                and g.source_measurement == "observed"
                and contained
                and scope_ok
                and not (want_bytes and overflow)
            )
            if not comparable:
                inconclusive += 1
                continue
            var delta = g.last_value - g.first_value
            if delta == detail_val:
                continue
            var metric = String("bounce_attempts")
            if want_bytes:
                metric = String("requested_bounce_bytes")
            var text = (
                metric
                + " ("
                + label
                + "): detail "
                + format_u64(detail_val)
                + " vs counter delta "
                + format_u64(delta)
            )
            if not out.counter_disagreement:
                out.counter_disagreement = True
                self._disagree_text = text
            else:
                self._disagree_extra += 1
            if len(self._disagree_refs) < 8:
                self._disagree_refs.append("counter:" + g.counter_id)
        if inconclusive > 0:
            self._note_fixed(
                _plural(
                    inconclusive,
                    "counter comparison inconclusive;",
                    "counter comparisons inconclusive;",
                )
                + " scope or coverage insufficient."
            )

    def _merge_limitations(mut self, mut out: Report):
        """Merge fixed and data notes into at most 256 limitations.

        Fixed notes are few by construction and always survive; data
        notes fill the remaining room in emission order, and any
        excess collapses into one withheld note. A final backstop
        truncates defensively so the bound holds absolutely.
        """
        for i in range(len(self._fixed_notes)):
            out.limitations.append(self._fixed_notes[i])
        var budget = _MAX_LIMITATIONS - 1 - len(out.limitations)
        if budget < 0:
            budget = 0
        var kept = len(self._data_notes)
        if kept > budget:
            kept = budget
        for i in range(kept):
            out.limitations.append(self._data_notes[i])
        var dropped = len(self._data_notes) - kept
        if dropped > 0:
            out.limitations.append(
                _plural(
                    dropped,
                    "further limitation withheld.",
                    "further limitations withheld.",
                )
            )
        if len(out.limitations) > _MAX_LIMITATIONS:
            var cut = List[String]()
            for i in range(_MAX_LIMITATIONS - 1):
                cut.append(out.limitations[i])
            cut.append(String("Further limitations withheld."))
            out.limitations = cut^
