# SPDX-License-Identifier: GPL-3.0-or-later

"""Mapping, copy, and lifetime reducer over lifecycle events.

The tracker consumes normalized events and derives allocation,
actual-copy, live-byte, and completed-lifetime metrics:

- Successful allocations count map successes; failures never
  create mappings. Copies observed before a later outer failure
  stay counted; a sync request alone copies nothing.
- Live bytes sum only tracked open mappings. Any orphan release,
  duplicate result, detail gap, active-table refusal, or unpaired
  release invalidates the total instead of lowering it. Refused
  observations still count in observed event totals; only the
  state they would join is withheld.
- Completed lifetimes cover releases with provable durations.
  Open, uncertain, and refused mappings are censored from the
  statistics, never labeled leaks and never completed samples.
- Device attribution needs a proven operation or mapping link.
  Unattributable bytes stay in global totals with a note.
- Events the correlator left unpaired degrade gracefully: an
  unpaired success creates no mapping, an unpaired copy still
  adds its bytes to direction totals without attribution,
  an unpaired failure still counts, and an unpaired release
  invalidates live state.

Metrics are a pure function of consumed state, so snapshot and
finish share this one implementation.
"""

from memveil.analysis.metrics import QuantileBuckets, floor_mean
from memveil.model.event import Event
from memveil.model.identity import (
    ACTIVE_MAX,
    DEVICE_MAX_ID,
    PENDING_MAX,
    RESOLVED_MAX,
    RETIRED_MAX,
)
from memveil.model.metric import Metric
from memveil.model.validate import checked_add, format_u64

comptime _MAX_MAPPING_DEVICES = 512


struct _LiveMapping(ImplicitlyCopyable):
    var device: String
    var has_device: Bool
    var map_ts: UInt64
    var mapped_bytes: UInt64

    def __init__(out self):
        self.device = String("")
        self.has_device = False
        self.map_ts = UInt64(0)
        self.mapped_bytes = UInt64(0)


struct _DeviceCopy(ImplicitlyCopyable):
    var allocations: UInt64
    var mapped: UInt64
    var mapped_overflow: Bool
    var o2b: UInt64
    var o2b_overflow: Bool
    var b2o: UInt64
    var b2o_overflow: Bool

    def __init__(out self):
        self.allocations = UInt64(0)
        self.mapped = UInt64(0)
        self.mapped_overflow = False
        self.o2b = UInt64(0)
        self.o2b_overflow = False
        self.b2o = UInt64(0)
        self.b2o_overflow = False


def _sort_strings(items: List[String]) -> List[String]:
    var out = List[String]()
    for i in range(len(items)):
        out.append(items[i])
    var n = len(out)
    var i = 1
    while i < n:
        var key = out[i]
        var j = i - 1
        while j >= 0 and out[j] > key:
            out[j + 1] = out[j]
            j -= 1
        out[j + 1] = key
        i += 1
    return out^


def _plural(n: Int, one: String, many: String) -> String:
    if n == 1:
        return "1 " + one
    return String(n) + " " + many


def _detail_loss_cause() -> String:
    """Shared cause when detail loss may hide a release."""
    return String(
        "Detail loss reported by the producer may hide a release"
    )


struct MappingTracker[
    ACTIVE_N: Int = ACTIVE_MAX,
    PENDING_N: Int = PENDING_MAX,
    DEVICE_N: Int = DEVICE_MAX_ID,
    RESOLVED_N: Int = RESOLVED_MAX,
    RETIRED_N: Int = RETIRED_MAX,
]:
    """Bounded lifecycle state with shared snapshot/finish metrics."""

    var _op_device: Dict[String, String]
    var _resolved: Dict[String, Bool]
    var _resolved_order: List[String]
    var _resolved_next: Int
    var _live: Dict[String, _LiveMapping]
    var _retired: Dict[String, Bool]
    var _retired_order: List[String]
    var _retired_next: Int
    var _devices: Dict[String, _DeviceCopy]
    var _lifetimes: QuantileBuckets
    var _lifecycle_events: Int
    var _saw_map: Bool
    var _saw_copy: Bool
    var _saw_unmap: Bool
    var _saw_sync: Bool
    var _allocations: UInt64
    var _failed: UInt64
    var _mapped_total: UInt64
    var _mapped_overflow: Bool
    var _o2b: UInt64
    var _o2b_overflow: Bool
    var _b2o: UInt64
    var _b2o_overflow: Bool
    var _priv: UInt64
    var _priv_overflow: Bool
    var _opast: UInt64
    var _opast_overflow: Bool
    var _syncs: UInt64
    var _live_bytes: UInt64
    var _live_invalid: Bool
    var _live_cause: String
    var _peak_live_bytes: UInt64
    var _peak_order_ok: Bool
    var _peak_ts_high: UInt64
    var _peak_map_at_high: Bool
    var _byte_us: UInt64
    var _byte_us_overflow: Bool
    var _degraded: Bool
    var _degrade_cause: String
    var _degraded_copy: Bool
    var _degrade_copy_cause: String
    var _degraded_sync: Bool
    var _degrade_sync_cause: String
    var _detail_lost: Bool
    var _split_relations: Bool
    var _completed: UInt64
    var _lifetime_total: UInt64
    var _lifetime_overflow: Bool
    var _min_life: UInt64
    var _max_life: UInt64
    var _has_life: Bool
    var _uncertain_closes: Int
    var _orphan_releases: Int
    var _unpaired: Int
    var _unpaired_map: Int
    var _unpaired_copy: Int
    var _unpaired_sync: Int
    var _unattributed_copy_bytes: UInt64
    var _refused_ops: Int
    var _refused_active: Int
    var _evicted_resolved: Int
    var _evicted_retired: Int
    var _notes: List[String]

    def __init__(out self):
        self._op_device = Dict[String, String]()
        self._resolved = Dict[String, Bool]()
        self._resolved_order = List[String]()
        self._resolved_next = 0
        self._live = Dict[String, _LiveMapping]()
        self._retired = Dict[String, Bool]()
        self._retired_order = List[String]()
        self._retired_next = 0
        self._devices = Dict[String, _DeviceCopy]()
        self._lifetimes = QuantileBuckets()
        self._lifecycle_events = 0
        self._saw_map = False
        self._saw_copy = False
        self._saw_unmap = False
        self._saw_sync = False
        self._allocations = UInt64(0)
        self._failed = UInt64(0)
        self._mapped_total = UInt64(0)
        self._mapped_overflow = False
        self._o2b = UInt64(0)
        self._o2b_overflow = False
        self._b2o = UInt64(0)
        self._b2o_overflow = False
        self._priv = UInt64(0)
        self._priv_overflow = False
        self._opast = UInt64(0)
        self._opast_overflow = False
        self._syncs = UInt64(0)
        self._live_bytes = UInt64(0)
        self._live_invalid = False
        self._live_cause = String("")
        self._peak_live_bytes = UInt64(0)
        self._peak_order_ok = True
        self._peak_ts_high = UInt64(0)
        self._peak_map_at_high = False
        self._byte_us = UInt64(0)
        self._byte_us_overflow = False
        self._degraded = False
        self._degrade_cause = String("")
        self._degraded_copy = False
        self._degrade_copy_cause = String("")
        self._degraded_sync = False
        self._degrade_sync_cause = String("")
        self._detail_lost = False
        self._split_relations = False
        self._completed = UInt64(0)
        self._lifetime_total = UInt64(0)
        self._lifetime_overflow = False
        self._min_life = UInt64(0)
        self._max_life = UInt64(0)
        self._has_life = False
        self._uncertain_closes = 0
        self._orphan_releases = 0
        self._unpaired = 0
        self._unpaired_map = 0
        self._unpaired_copy = 0
        self._unpaired_sync = 0
        self._unattributed_copy_bytes = UInt64(0)
        self._refused_ops = 0
        self._refused_active = 0
        self._evicted_resolved = 0
        self._evicted_retired = 0
        self._notes = List[String]()

    def sees_lifecycle(self) -> Bool:
        """True once any lifecycle-kind event was consumed."""
        return self._lifecycle_events > 0

    def unpaired_count(self) -> Int:
        return self._unpaired

    def unpaired_mapping_count(self) -> Int:
        return self._unpaired_map

    def unpaired_copy_count(self) -> Int:
        return self._unpaired_copy

    def unpaired_sync_count(self) -> Int:
        return self._unpaired_sync

    def set_relation_split(mut self, split: Bool):
        """Select split relation-class interpretation.

        Legacy mode (default) propagates analyzer-observed
        unpaired copies and syncs coarsely to every mapping-row
        family. Split mode degrades only the affected family:
        copy uncertainty preserves proven occupancy, and sync
        uncertainty preserves everything but the sync row.
        """
        self._split_relations = split

    def note_detail_loss(mut self):
        """Invalidate live state and degrade aggregates.

        Producer-claimed loss may hide a release, exactly like an
        observed detail gap, so open mappings and live bytes are
        withheld; cumulative counters keep their values with
        partial coverage. This covers producer-claimed loss and
        recovered tails the event stream never shows. The loss
        is shared across every row family, including split
        copy and sync coverage.
        """
        self._detail_lost = True
        self._invalidate_live(_detail_loss_cause())

    def note_correlation_loss(mut self):
        """Lost relationships may hide a mapping release."""
        self._invalidate_live(
            "Correlation loss may hide a release relationship"
        )

    def note_copy_attribution_loss(mut self):
        """Lost copy attribution degrades copy rows only.

        Proven occupancy is unaffected: a missing copy link
        cannot hide a release.
        """
        self._degrade_copy(
            "Copy attribution loss may hide a copy relationship"
        )

    def note_sync_attribution_loss(mut self):
        """Lost sync attribution degrades the sync row only."""
        self._degrade_sync(
            "Sync attribution loss may hide a sync relationship"
        )

    def _invalidate_live(mut self, cause: String):
        if not self._live_invalid:
            self._live_invalid = True
            self._live_cause = cause
        self._degrade(cause)

    def _degrade(mut self, cause: String):
        if not self._degraded:
            self._degraded = True
            self._degrade_cause = cause

    def _degrade_copy(mut self, cause: String):
        if not self._degraded_copy:
            self._degraded_copy = True
            self._degrade_copy_cause = cause

    def _degrade_sync(mut self, cause: String):
        if not self._degraded_sync:
            self._degraded_sync = True
            self._degrade_sync_cause = cause

    def _note_unpaired_mapping(mut self):
        self._unpaired += 1
        self._unpaired_map += 1
        if self._split_relations:
            # Observed mapping loss makes the mapping/release
            # class partial, and valued occupancy needs that
            # class complete: withhold it.
            self._invalidate_live("Unpaired mapping observed")
        else:
            self._degrade("unpaired lifecycle evidence")

    def _note_unpaired_copy(mut self):
        self._unpaired += 1
        self._unpaired_copy += 1
        if self._split_relations:
            self._degrade_copy("unpaired copy evidence")
        else:
            self._degrade("unpaired lifecycle evidence")

    def _note_unpaired_sync(mut self):
        self._unpaired += 1
        self._unpaired_sync += 1
        if self._split_relations:
            self._degrade_sync("unpaired sync evidence")
        else:
            self._degrade("unpaired lifecycle evidence")

    def _note_live_level(mut self):
        if self._live_bytes > self._peak_live_bytes:
            self._peak_live_bytes = self._live_bytes

    def _note_peak_order(mut self, is_map: Bool, ts: UInt64):
        """Extend the delivery-order proof behind the peak sweep.

        The delivery-order live accumulator is a valid
        time-domain occupancy sweep while map/unmap state
        events arrive in non-decreasing timestamp order with
        releases before maps at equal timestamps (half-open
        interval sweep order). That sweep order is a sufficient
        certificate, not a necessary one: some out-of-order
        deliveries still have a provable peak, but the tracker
        conservatively withholds those too. The first violation
        latches the peak unavailable with a concrete reason;
        live bytes, open counts, and per-generation durations
        stay valid.
        """
        if not self._peak_order_ok:
            return
        if ts < self._peak_ts_high:
            self._break_peak_order()
            return
        if ts > self._peak_ts_high:
            self._peak_ts_high = ts
            self._peak_map_at_high = is_map
            return
        if not is_map and self._peak_map_at_high:
            self._break_peak_order()
            return
        if is_map:
            self._peak_map_at_high = True

    def _break_peak_order(mut self):
        self._peak_order_ok = False
        self._note(
            "Mapping/release delivery order does not prove"
            " timestamp order; peak withheld."
        )

    def _add_byte_us(mut self, byte_us: UInt64):
        try:
            self._byte_us = checked_add(self._byte_us, byte_us)
        except:
            self._latch_byte_us_overflow()

    def _latch_byte_us_overflow(mut self):
        if not self._byte_us_overflow:
            self._byte_us_overflow = True
            self._note(
                "Allocation byte-time exceeds u64 range;"
                " value withheld."
            )

    def _note(mut self, text: String):
        self._notes.append(text)

    def _device_acc(mut self, dev: String) -> Bool:
        """Ensure a device row; False when the device budget is out."""
        if dev in self._devices:
            return True
        if len(self._devices) >= Self.DEVICE_N:
            return False
        self._devices[dev] = _DeviceCopy()
        return True

    def consume(mut self, ev: Event) raises:
        """Fold one normalized event into lifecycle state."""
        var kind = ev.kind
        if kind == "copy" and ev.source_measurement != "observed":
            raise Error("executed copies require observed measurement")
        var paired = ev.source_correlation != "unpaired"
        if kind == "bounce_attempt":
            if paired:
                self._remember_op(ev.bounce.operation_id,
                                  ev.bounce.device_id)
            return
        if kind == "map_result":
            self._lifecycle_events += 1
            self._saw_map = True
            self._apply_map(ev, paired)
            return
        if kind == "copy":
            self._lifecycle_events += 1
            self._saw_copy = True
            self._apply_copy(ev, paired)
            return
        if kind == "sync_request":
            self._lifecycle_events += 1
            self._saw_sync = True
            self._syncs = checked_add(self._syncs, UInt64(1))
            if not paired:
                self._note_unpaired_sync()
            return
        if kind == "unmap":
            self._lifecycle_events += 1
            self._saw_unmap = True
            self._apply_unmap(ev, paired)
            return
        if kind == "gap" and ev.gap.channel == "correlation":
            self.note_correlation_loss()
            return
        if kind == "gap" and ev.gap.channel == "detail":
            self._detail_lost = True
            self._invalidate_live("Detail loss may hide a release")
            return

    def _remember_op(mut self, op: String, dev: String):
        if op == "" or dev == "":
            return
        if op in self._op_device or op in self._resolved:
            return
        if len(self._op_device) >= Self.PENDING_N:
            self._refused_ops += 1
            self._degrade("operation table exhausted")
            return
        self._op_device[op] = dev

    def _remember_resolved(mut self, op: String) raises:
        """Record one resolved op in the bounded ring.

        Eviction degrades totals instead of failing: a
        duplicate past the horizon is undetectable, so every
        valued row keeps partial coverage with a note.
        """
        if Self.RESOLVED_N <= 0:
            return
        if len(self._resolved_order) < Self.RESOLVED_N:
            self._resolved_order.append(op)
        else:
            var victim = self._resolved_order[self._resolved_next]
            _ = self._resolved.pop(victim)
            self._resolved_order[self._resolved_next] = op
            self._resolved_next += 1
            if self._resolved_next >= Self.RESOLVED_N:
                self._resolved_next = 0
            self._evicted_resolved += 1
            self._degrade("resolved-operation history exceeded")
        self._resolved[op] = True

    def _remember_retired(mut self, mapping: String) raises:
        """Record one retired mapping in the bounded ring.

        Eviction preserves uncertainty: identity reuse past
        the horizon is undetectable, so totals degrade with a
        note instead of claiming a duplicate verdict.
        """
        if Self.RETIRED_N <= 0:
            return
        if len(self._retired_order) < Self.RETIRED_N:
            self._retired_order.append(mapping)
        else:
            var victim = self._retired_order[self._retired_next]
            _ = self._retired.pop(victim)
            self._retired_order[self._retired_next] = mapping
            self._retired_next += 1
            if self._retired_next >= Self.RETIRED_N:
                self._retired_next = 0
            self._evicted_retired += 1
            self._degrade("retired-mapping history exceeded")
        self._retired[mapping] = True

    def _apply_map(mut self, ev: Event, paired: Bool) raises:
        var op = ev.map_result.operation_id
        if not paired:
            self._note_unpaired_mapping()
            # An explicit failure is an independent fact: it
            # counts even though it opens no lifetime.
            if not ev.map_result.success:
                self._failed = checked_add(self._failed, UInt64(1))
            return
        if op in self._resolved:
            self._invalidate_live(
                "Duplicate result for operation " + op
            )
            return
        self._remember_resolved(op)
        var dev = String("")
        var has_dev = False
        if op in self._op_device:
            dev = self._op_device.get(op, String(""))
            has_dev = True
            _ = self._op_device.pop(op)
        if not ev.map_result.success:
            self._failed = checked_add(self._failed, UInt64(1))
            return
        if not ev.map_result.has_mapping_id:
            self._invalidate_live("Success lacks mapping identity")
            return
        self._note_peak_order(True, ev.ts_ns)
        var mapping = ev.map_result.mapping_id
        var mapped = UInt64(0)
        if ev.map_result.has_mapped_bytes:
            mapped = ev.map_result.mapped_bytes
        if mapping in self._live or mapping in self._retired:
            self._invalidate_live(
                "Duplicate mapping identity " + mapping
            )
            return
        self._allocations = checked_add(self._allocations, UInt64(1))
        try:
            self._mapped_total = checked_add(
                self._mapped_total, mapped
            )
        except:
            if not self._mapped_overflow:
                self._mapped_overflow = True
                self._note(
                    "Mapped-byte total exceeds u64 range;"
                    " value withheld."
                )
        if has_dev and self._device_acc(dev):
            var acc = self._devices.get(dev, _DeviceCopy())
            acc.allocations = checked_add(acc.allocations, UInt64(1))
            try:
                acc.mapped = checked_add(acc.mapped, mapped)
            except:
                acc.mapped_overflow = True
            self._devices[dev] = acc
        if len(self._live) >= Self.ACTIVE_N:
            self._refused_active += 1
            self._invalidate_live("Active mapping table exhausted")
            return
        var rec = _LiveMapping()
        rec.device = dev
        rec.has_device = has_dev
        rec.map_ts = ev.ts_ns
        rec.mapped_bytes = mapped
        self._live[mapping] = rec
        try:
            self._live_bytes = checked_add(self._live_bytes, mapped)
        except:
            self._invalidate_live("Live-byte total overflowed")
            return
        self._note_live_level()

    def _apply_copy(mut self, ev: Event, paired: Bool) raises:
        var direction = ev.copy.direction
        if direction != "original_to_bounce" and (
            direction != "bounce_to_original"
        ):
            self._degrade("copy with unknown direction")
            return
        # Executed bytes are an independent event fact: every
        # observed copy aggregates into its direction total
        # before pairing decides attribution.
        var n = ev.copy.bytes
        if direction == "original_to_bounce":
            try:
                self._o2b = checked_add(self._o2b, n)
            except:
                if not self._o2b_overflow:
                    self._o2b_overflow = True
                    self._note(
                        "Original-to-bounce total exceeds u64"
                        " range; value withheld."
                    )
        else:
            try:
                self._b2o = checked_add(self._b2o, n)
            except:
                if not self._b2o_overflow:
                    self._b2o_overflow = True
                    self._note(
                        "Bounce-to-original total exceeds u64"
                        " range; value withheld."
                    )
        # Subset facts ride with the direction totals: a
        # private-pool copy is still executed bytes in its
        # direction, and a past-allocation copy still counts.
        if ev.copy.pool_private:
            try:
                self._priv = checked_add(self._priv, n)
            except:
                if not self._priv_overflow:
                    self._priv_overflow = True
                    self._note(
                        "Private-pool total exceeds u64"
                        " range; value withheld."
                    )
        if ev.copy.offset_past_allocation:
            try:
                self._opast = checked_add(self._opast, UInt64(1))
            except:
                if not self._opast_overflow:
                    self._opast_overflow = True
                    self._note(
                        "Past-allocation count exceeds u64"
                        " range; value withheld."
                    )
        if not paired:
            self._note_unpaired_copy()
            return
        var dev = String("")
        var attributed = False
        if ev.copy.has_mapping_id:
            var mapping = ev.copy.mapping_id
            if mapping in self._live:
                var rec = self._live.get(mapping, _LiveMapping())
                if rec.has_device:
                    dev = rec.device
                    attributed = True
        else:
            var op = ev.copy.operation_id
            if op in self._op_device:
                dev = self._op_device.get(op, String(""))
                attributed = True
        if not attributed:
            try:
                self._unattributed_copy_bytes = checked_add(
                    self._unattributed_copy_bytes, n
                )
            except:
                pass
            return
        if not self._device_acc(dev):
            try:
                self._unattributed_copy_bytes = checked_add(
                    self._unattributed_copy_bytes, n
                )
            except:
                pass
            return
        var acc = self._devices.get(dev, _DeviceCopy())
        if direction == "original_to_bounce":
            try:
                acc.o2b = checked_add(acc.o2b, n)
            except:
                acc.o2b_overflow = True
        else:
            try:
                acc.b2o = checked_add(acc.b2o, n)
            except:
                acc.b2o_overflow = True
        self._devices[dev] = acc

    def _apply_unmap(mut self, ev: Event, paired: Bool) raises:
        if not paired:
            self._unpaired += 1
            self._unpaired_map += 1
            self._invalidate_live("Unpaired release observed")
            return
        if not ev.unmap.has_mapping_id:
            self._invalidate_live("Release lacks mapping identity")
            return
        self._note_peak_order(False, ev.ts_ns)
        var mapping = ev.unmap.mapping_id
        if mapping not in self._live:
            self._orphan_releases += 1
            self._invalidate_live("Release without open mapping")
            return
        var rec = self._live.get(mapping, _LiveMapping())
        _ = self._live.pop(mapping)
        self._remember_retired(mapping)
        if rec.mapped_bytes > self._live_bytes:
            self._invalidate_live("Live-byte accounting fault")
        else:
            self._live_bytes -= rec.mapped_bytes
        if ev.ts_ns < rec.map_ts:
            self._uncertain_closes += 1
            self._degrade("Release predates its mapping")
            return
        var dur = ev.ts_ns - rec.map_ts
        self._lifetimes.add(dur)
        # Completed byte-time: exact under any interleaving, since
        # each mapping carries its own provable duration.
        var dur_us = dur // UInt64(1000)
        if dur_us > UInt64(0) and rec.mapped_bytes > UInt64(0):
            var limit = UInt64(18446744073709551615) // rec.mapped_bytes
            if dur_us > limit:
                self._latch_byte_us_overflow()
            else:
                self._add_byte_us(rec.mapped_bytes * dur_us)
        try:
            self._lifetime_total = checked_add(
                self._lifetime_total, dur
            )
        except:
            if not self._lifetime_overflow:
                self._lifetime_overflow = True
                self._note(
                    "Lifetime sum exceeds u64 range; mean"
                    " withheld."
                )
        self._completed = checked_add(self._completed, UInt64(1))
        if not self._has_life or dur < self._min_life:
            self._min_life = dur
        if not self._has_life or dur > self._max_life:
            self._max_life = dur
        self._has_life = True

    def limitations(self) -> List[String]:
        """Human-readable bounds/anomaly notes for the report."""
        var out = List[String]()
        for i in range(len(self._notes)):
            out.append(self._notes[i])
        if self._orphan_releases > 0:
            out.append(
                _plural(
                    self._orphan_releases,
                    "release without open mapping;",
                    "releases without open mappings;",
                )
                + " live totals withheld."
            )
        if self._uncertain_closes > 0:
            out.append(
                _plural(
                    self._uncertain_closes,
                    "release with unprovable duration;",
                    "releases with unprovable durations;",
                )
                + " excluded from completed lifetimes."
            )
        if self._unpaired > 0:
            out.append(
                _plural(
                    self._unpaired,
                    "unpaired lifecycle event excluded from"
                    " pairing-dependent state;",
                    "unpaired lifecycle events excluded from"
                    " pairing-dependent state;",
                )
                + " independent facts retained; affected"
                " totals degrade."
            )
        if self._refused_ops > 0 or self._refused_active > 0:
            out.append(
                "Bounded tables refused "
                + String(self._refused_ops + self._refused_active)
                + " lifecycle records; affected totals degrade."
            )
        if self._evicted_resolved > 0:
            out.append(
                String(self._evicted_resolved)
                + " resolved operations evicted (history"
                " exceeded); duplicates past the horizon are"
                " undetectable."
            )
        if self._evicted_retired > 0:
            out.append(
                String(self._evicted_retired)
                + " retired mappings evicted (history exceeded);"
                " identity reuse past the horizon is"
                " undetectable."
            )
        if self._unattributed_copy_bytes > UInt64(0):
            out.append(
                format_u64(self._unattributed_copy_bytes)
                + " copy bytes lack device attribution and appear"
                " in global totals only."
            )
        var devices = len(self._devices)
        if devices > _MAX_MAPPING_DEVICES:
            out.append(
                String(devices - _MAX_MAPPING_DEVICES)
                + " devices withheld from per-device rows ("
                + String(_MAX_MAPPING_DEVICES)
                + "-device detail budget)."
            )
        return out^

    def _coverage(self, overlay_detail_loss: Bool) -> String:
        if self._degraded or overlay_detail_loss:
            return String("partial")
        return String("complete_for_scope")

    def _coverage_copy(self, overlay_detail_loss: Bool) -> String:
        """Copy-family coverage: coarse in legacy, scoped in split.

        Split scoping still shares consumed detail loss across
        every family; only mapping-only correlation loss stays
        out of this family's verdict.
        """
        if not self._split_relations:
            return self._coverage(overlay_detail_loss)
        if (
            self._degraded_copy
            or self._detail_lost
            or overlay_detail_loss
        ):
            return String("partial")
        return String("complete_for_scope")

    def _coverage_sync(self, overlay_detail_loss: Bool) -> String:
        """Sync-family coverage: coarse in legacy, scoped in split.

        Split scoping still shares consumed detail loss across
        every family; only mapping-only correlation loss stays
        out of this family's verdict.
        """
        if not self._split_relations:
            return self._coverage(overlay_detail_loss)
        if (
            self._degraded_sync
            or self._detail_lost
            or overlay_detail_loss
        ):
            return String("partial")
        return String("complete_for_scope")

    def _coverage_device(self, overlay_detail_loss: Bool) -> String:
        """Device-row coverage: mapping or copy loss degrades.

        Per-device rows carry attribution, so in split mode they
        degrade under either mapping or copy uncertainty; the
        sync row is the only family sync loss touches. Legacy
        mode stays coarse.
        """
        if not self._split_relations:
            return self._coverage(overlay_detail_loss)
        if (
            self._degraded
            or self._degraded_copy
            or overlay_detail_loss
        ):
            return String("partial")
        return String("complete_for_scope")

    def _view_live_invalid(self, overlay_detail_loss: Bool) -> Bool:
        """Live state is withheld under consumed or overlaid loss."""
        return self._live_invalid or overlay_detail_loss

    def _view_live_cause(self, overlay_detail_loss: Bool) -> String:
        """Withhold reason, preferring the latched consumed cause."""
        if self._live_invalid:
            return self._live_cause.copy()
        if overlay_detail_loss:
            return _detail_loss_cause()
        return self._live_cause.copy()

    def _row(
        self,
        name: String,
        unit: String,
        has_value: Bool,
        value: UInt64,
        measurement: String,
        coverage: String,
        aggregation: String,
        has_samples: Bool,
        samples: UInt64,
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
        m.measurement = measurement
        m.coverage = coverage
        m.confidence = String("high")
        if aggregation != "":
            m.has_aggregation = True
            m.aggregation = aggregation
        m.has_sample_count = has_samples
        m.sample_count = samples
        m.has_device_id = has_device
        m.device_id = device
        m.scope = scope
        m.notes = notes
        return m^

    def _valued(
        self,
        name: String,
        unit: String,
        value: UInt64,
        aggregation: String,
        has_samples: Bool,
        samples: UInt64,
        scope: String,
        notes: String,
        overlay_detail_loss: Bool,
    ) -> Metric:
        return self._row(
            name,
            unit,
            True,
            value,
            String("observed"),
            self._coverage(overlay_detail_loss),
            aggregation,
            has_samples,
            samples,
            False,
            String(""),
            scope,
            notes,
        )

    def _valued_copy(
        self,
        name: String,
        unit: String,
        value: UInt64,
        aggregation: String,
        has_samples: Bool,
        samples: UInt64,
        scope: String,
        notes: String,
        overlay_detail_loss: Bool,
    ) -> Metric:
        return self._row(
            name,
            unit,
            True,
            value,
            String("observed"),
            self._coverage_copy(overlay_detail_loss),
            aggregation,
            has_samples,
            samples,
            False,
            String(""),
            scope,
            notes,
        )

    def _valued_sync(
        self,
        name: String,
        unit: String,
        value: UInt64,
        aggregation: String,
        has_samples: Bool,
        samples: UInt64,
        scope: String,
        notes: String,
        overlay_detail_loss: Bool,
    ) -> Metric:
        return self._row(
            name,
            unit,
            True,
            value,
            String("observed"),
            self._coverage_sync(overlay_detail_loss),
            aggregation,
            has_samples,
            samples,
            False,
            String(""),
            scope,
            notes,
        )

    def _missing(
        self, name: String, unit: String, scope: String, notes: String
    ) -> Metric:
        # A null value always carries unavailable coverage: the
        # row's own measurement is missing, whatever the evidence
        # quality behind it. The reason lives in the notes.
        return self._row(
            name,
            unit,
            False,
            UInt64(0),
            String("unavailable"),
            String("unavailable"),
            String(""),
            False,
            UInt64(0),
            False,
            String(""),
            scope,
            notes,
        )

    def metrics(
        self, window: String, overlay_detail_loss: Bool = False
    ) raises -> List[Metric]:
        """One deterministic row set; shared by snapshot/finish.

        Without a horizon the oldest-open age stays unavailable;
        pass the horizon explicitly for age-aware rows. The
        overlay renders call-local detail uncertainty (a
        dropped tail) without latching tracker state, so a
        partial snapshot cannot alter later facts.
        """
        return self.metrics_horizon(
            window, UInt64(0), overlay_detail_loss
        )

    def _oldest_open_ts(self) -> UInt64:
        """Minimum map timestamp over live mappings; 0 when none."""
        var found = False
        var oldest = UInt64(0)
        for entry in self._live.items():
            if not found or entry.value.map_ts < oldest:
                oldest = entry.value.map_ts
                found = True
        if not found:
            return UInt64(0)
        return oldest

    def metrics_horizon(
        self,
        window: String,
        horizon_ns: UInt64,
        overlay_detail_loss: Bool = False,
    ) raises -> List[Metric]:
        """Row set with oldest-open age against one horizon.

        Each family stays null without its own source kinds: a
        zero would claim an empty observation the capture cannot
        prove. Unknown is null with a reason, never zero. The
        overlay renders call-local detail uncertainty (a
        dropped tail) without latching tracker state.
        """
        var out = List[Metric]()
        var scope = window + "; observed mappings"
        if not self._saw_map:
            var no_map = String(
                "No map_result events in this capture."
            )
            out.append(
                self._missing(
                    String("successful_allocations"),
                    String("count"),
                    scope,
                    no_map,
                )
            )
            out.append(
                self._missing(
                    String("failed_allocations"),
                    String("count"),
                    scope,
                    no_map,
                )
            )
            out.append(
                self._missing(
                    String("mapped_bytes_total"),
                    String("bytes"),
                    scope,
                    no_map,
                )
            )
        else:
            out.append(
                self._valued(
                    String("successful_allocations"),
                    String("count"),
                    self._allocations,
                    String("counter"),
                    False,
                    UInt64(0),
                    scope,
                    String("Map successes with mapping identity."),
                    overlay_detail_loss,
                )
            )
            out.append(
                self._valued(
                    String("failed_allocations"),
                    String("count"),
                    self._failed,
                    String("counter"),
                    False,
                    UInt64(0),
                    scope,
                    String("Map failures; no mapping created."),
                    overlay_detail_loss,
                )
            )
            if self._mapped_overflow:
                out.append(
                    self._missing(
                        String("mapped_bytes_total"),
                        String("bytes"),
                        scope,
                        String(
                            "Mapped-byte total exceeds u64 range;"
                            " value withheld."
                        ),
                    )
                )
            else:
                out.append(
                    self._valued(
                        String("mapped_bytes_total"),
                        String("bytes"),
                        self._mapped_total,
                        String("counter"),
                        False,
                        UInt64(0),
                        scope,
                        String("Sum of mapped bytes over successes."),
                        overlay_detail_loss,
                    )
                )
        if not self._saw_copy:
            var no_copy = String("No copy events in this capture.")
            out.append(
                self._missing(
                    String("copy_original_to_bounce_bytes"),
                    String("bytes"),
                    scope,
                    no_copy,
                )
            )
            out.append(
                self._missing(
                    String("copy_bounce_to_original_bytes"),
                    String("bytes"),
                    scope,
                    no_copy,
                )
            )
        else:
            if self._o2b_overflow:
                out.append(
                    self._missing(
                        String("copy_original_to_bounce_bytes"),
                        String("bytes"),
                        scope,
                        String("Total exceeds u64 range; withheld."),
                    )
                )
            else:
                out.append(
                    self._valued_copy(
                        String("copy_original_to_bounce_bytes"),
                        String("bytes"),
                        self._o2b,
                        String("counter"),
                        False,
                        UInt64(0),
                        scope,
                        String(
                            "Observed original-to-bounce copies"
                            " only; sync requests add nothing."
                        ),
                        overlay_detail_loss,
                    )
                )
            if self._b2o_overflow:
                out.append(
                    self._missing(
                        String("copy_bounce_to_original_bytes"),
                        String("bytes"),
                        scope,
                        String("Total exceeds u64 range; withheld."),
                    )
                )
            else:
                out.append(
                    self._valued_copy(
                        String("copy_bounce_to_original_bytes"),
                        String("bytes"),
                        self._b2o,
                        String("counter"),
                        False,
                        UInt64(0),
                        scope,
                        String(
                            "Observed bounce-to-original copies"
                            " only; sync requests add nothing."
                        ),
                        overlay_detail_loss,
                    )
                )
            # Subset rows appear only when nonzero; the private
            # bytes stay inside the direction totals above.
            if self._priv_overflow:
                out.append(
                    self._missing(
                        String("copy_private_pool_bytes"),
                        String("bytes"),
                        scope,
                        String("Total exceeds u64 range; withheld."),
                    )
                )
            elif self._priv != UInt64(0):
                out.append(
                    self._valued_copy(
                        String("copy_private_pool_bytes"),
                        String("bytes"),
                        self._priv,
                        String("counter"),
                        False,
                        UInt64(0),
                        scope,
                        String(
                            "Private-pool copies only, a subset"
                            " of the direction totals; never"
                            " exposure."
                        ),
                        overlay_detail_loss,
                    )
                )
            if self._opast_overflow:
                out.append(
                    self._missing(
                        String("copy_offset_past_allocation_count"),
                        String("count"),
                        scope,
                        String("Total exceeds u64 range; withheld."),
                    )
                )
            elif self._opast != UInt64(0):
                out.append(
                    self._valued_copy(
                        String("copy_offset_past_allocation_count"),
                        String("count"),
                        self._opast,
                        String("counter"),
                        False,
                        UInt64(0),
                        scope,
                        String(
                            "Copies whose offset ran past the"
                            " allocation; their bytes stay in"
                            " the direction totals."
                        ),
                        overlay_detail_loss,
                    )
                )
        var has_mapping_state = self._saw_map or self._saw_unmap
        if self._view_live_invalid(overlay_detail_loss):
            var cause = self._view_live_cause(overlay_detail_loss)
            if not has_mapping_state and cause == "":
                cause = String("No mapping evidence")
            out.append(
                self._missing(
                    String("live_observed_allocation_bytes"),
                    String("bytes"),
                    scope,
                    cause
                    + "; live total withheld, not a lower bound.",
                )
            )
            out.append(
                self._missing(
                    String("open_mappings"),
                    String("count"),
                    scope,
                    cause + "; open count withheld.",
                )
            )
            out.append(
                self._missing(
                    String("peak_live_observed_allocation_bytes"),
                    String("bytes"),
                    scope,
                    cause + "; peak withheld with live state.",
                )
            )
        elif not has_mapping_state:
            var no_state = String(
                "No map or release events in this capture."
            )
            out.append(
                self._missing(
                    String("live_observed_allocation_bytes"),
                    String("bytes"),
                    scope,
                    no_state,
                )
            )
            out.append(
                self._missing(
                    String("open_mappings"),
                    String("count"),
                    scope,
                    no_state,
                )
            )
            out.append(
                self._missing(
                    String("peak_live_observed_allocation_bytes"),
                    String("bytes"),
                    scope,
                    no_state,
                )
            )
        else:
            out.append(
                self._valued(
                    String("live_observed_allocation_bytes"),
                    String("bytes"),
                    self._live_bytes,
                    String("gauge"),
                    False,
                    UInt64(0),
                    scope,
                    String("Mapped bytes still open at the horizon."),
                    overlay_detail_loss,
                )
            )
            out.append(
                self._valued(
                    String("open_mappings"),
                    String("count"),
                    UInt64(len(self._live)),
                    String("gauge"),
                    False,
                    UInt64(0),
                    scope,
                    String(
                        "Open mappings are censored from completed"
                        " lifetimes, not leaks."
                    ),
                    overlay_detail_loss,
                )
            )
            if not self._peak_order_ok:
                out.append(
                    self._missing(
                        String("peak_live_observed_allocation_bytes"),
                        String("bytes"),
                        scope,
                        String(
                            "Mapping/release delivery order does not"
                            " prove timestamp order; peak withheld."
                        ),
                    )
                )
            else:
                out.append(
                    self._valued(
                        String("peak_live_observed_allocation_bytes"),
                        String("bytes"),
                        self._peak_live_bytes,
                        String("gauge"),
                        False,
                        UInt64(0),
                        scope,
                        String(
                            "Maximum live mapped bytes reached; peak"
                            " observed allocation occupancy in this window;"
                            " release does not prove reprivatization or erasure."
                        ),
                        overlay_detail_loss,
                    )
                )
        if (
            has_mapping_state
            and not self._view_live_invalid(overlay_detail_loss)
            and len(self._live) > 0
            and horizon_ns > UInt64(0)
            and self._oldest_open_ts() <= horizon_ns
        ):
            out.append(
                self._valued(
                    String("oldest_open_mapping_age_ns"),
                    String("nanoseconds"),
                    horizon_ns - self._oldest_open_ts(),
                    String("gauge"),
                    False,
                    UInt64(0),
                    scope,
                    String(
                        "Horizon minus oldest open map time; an"
                        " input to the long-lived policy, never a"
                        " leak verdict."
                    ),
                    overlay_detail_loss,
                )
            )
        else:
            var age_why = String("No open mappings at the horizon.")
            if not has_mapping_state:
                age_why = String(
                    "No map or release events in this capture."
                )
            elif self._view_live_invalid(overlay_detail_loss):
                age_why = self._view_live_cause(overlay_detail_loss) + (
                    "; age withheld."
                )
            elif len(self._live) > 0 and horizon_ns == UInt64(0):
                age_why = String("No horizon supplied for open age.")
            out.append(
                self._missing(
                    String("oldest_open_mapping_age_ns"),
                    String("nanoseconds"),
                    scope,
                    age_why,
                )
            )
        out.append(
            self._byte_time_row(
                scope, horizon_ns, has_mapping_state, overlay_detail_loss
            )
        )
        if self._saw_sync:
            out.append(
                self._valued_sync(
                    String("sync_requests"),
                    String("count"),
                    self._syncs,
                    String("counter"),
                    False,
                    UInt64(0),
                    scope,
                    String(
                        "Sync requests observed; requests are not"
                        " copies."
                    ),
                    overlay_detail_loss,
                )
            )
        else:
            out.append(
                self._missing(
                    String("sync_requests"),
                    String("count"),
                    scope,
                    String("No sync_request events in this capture."),
                )
            )
        if self._saw_unmap:
            out.append(
                self._valued(
                    String("completed_lifetime_count"),
                    String("count"),
                    self._completed,
                    String("counter"),
                    True,
                    self._completed,
                    scope,
                    String(
                        "Releases with provable durations; open and"
                        " uncertain mappings excluded."
                    ),
                    overlay_detail_loss,
                )
            )
        else:
            out.append(
                self._missing(
                    String("completed_lifetime_count"),
                    String("count"),
                    scope,
                    String(
                        "No release events in this capture; open"
                        " mappings are censored, not completed."
                    ),
                )
            )
        if self._completed == UInt64(0):
            var reason = String("No completed lifetimes")
            if len(self._live) > 0:
                reason += (
                    "; "
                    + String(len(self._live))
                    + " mappings still open at the horizon"
                )
            reason += "."
            out.append(
                self._missing(
                    String("lifetime_mean_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
            out.append(
                self._missing(
                    String("lifetime_min_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
            out.append(
                self._missing(
                    String("lifetime_max_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
            out.append(
                self._missing(
                    String("lifetime_p50_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
            out.append(
                self._missing(
                    String("lifetime_p95_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
            out.append(
                self._missing(
                    String("lifetime_p99_ns"),
                    String("nanoseconds"),
                    scope,
                    reason,
                )
            )
        else:
            out.append(self._mean_row(scope, overlay_detail_loss))
            out.append(
                self._row(
                    String("lifetime_min_ns"),
                    String("nanoseconds"),
                    True,
                    self._min_life,
                    String("observed"),
                    self._coverage(overlay_detail_loss),
                    String("gauge"),
                    True,
                    self._completed,
                    False,
                    String(""),
                    scope,
                    String("Exact minimum completed lifetime."),
                )
            )
            out.append(
                self._row(
                    String("lifetime_max_ns"),
                    String("nanoseconds"),
                    True,
                    self._max_life,
                    String("observed"),
                    self._coverage(overlay_detail_loss),
                    String("gauge"),
                    True,
                    self._completed,
                    False,
                    String(""),
                    scope,
                    String("Exact maximum completed lifetime."),
                )
            )
            var p50 = self._lifetimes.estimate(50, 100)
            out.append(
                self._row(
                    String("lifetime_p50_ns"),
                    String("nanoseconds"),
                    True,
                    p50,
                    String("estimated"),
                    self._coverage(overlay_detail_loss),
                    String("p50"),
                    True,
                    self._completed,
                    False,
                    String(""),
                    scope,
                    String(
                        "Estimated 65-bucket upper edge; exact"
                        " min/max stay separate."
                    ),
                )
            )
            var p95 = self._lifetimes.estimate(95, 100)
            out.append(
                self._row(
                    String("lifetime_p95_ns"),
                    String("nanoseconds"),
                    True,
                    p95,
                    String("estimated"),
                    self._coverage(overlay_detail_loss),
                    String("p95"),
                    True,
                    self._completed,
                    False,
                    String(""),
                    scope,
                    String(
                        "Estimated 65-bucket upper edge; exact"
                        " min/max stay separate."
                    ),
                )
            )
            var p99 = self._lifetimes.estimate(99, 100)
            out.append(
                self._row(
                    String("lifetime_p99_ns"),
                    String("nanoseconds"),
                    True,
                    p99,
                    String("estimated"),
                    self._coverage(overlay_detail_loss),
                    String("p99"),
                    True,
                    self._completed,
                    False,
                    String(""),
                    scope,
                    String(
                        "Estimated 65-bucket upper edge; exact"
                        " min/max stay separate."
                    ),
                )
            )
        self._device_rows(out, window, overlay_detail_loss)
        return out^

    def _byte_time_row(
        self,
        scope: String,
        horizon_ns: UInt64,
        has_mapping_state: Bool,
        overlay_detail_loss: Bool,
    ) -> Metric:
        """Allocation byte-time: completed plus open mappings.

        Each mapping contributes mapped bytes times its own
        provable duration, so interleaved streams integrate
        exactly. Open mappings need a horizon; without one the
        row is withheld while anything is still open.
        """
        if self._view_live_invalid(overlay_detail_loss):
            return self._missing(
                String("allocation_byte_microseconds"),
                String("byte_microseconds"),
                scope,
                self._view_live_cause(overlay_detail_loss)
                + "; byte-time withheld with live state.",
            )
        if not has_mapping_state:
            return self._missing(
                String("allocation_byte_microseconds"),
                String("byte_microseconds"),
                scope,
                String("No map or release events in this capture."),
            )
        if horizon_ns == UInt64(0) and len(self._live) > 0:
            return self._missing(
                String("allocation_byte_microseconds"),
                String("byte_microseconds"),
                scope,
                String(
                    "Open mappings need a horizon for byte-time;"
                    " completed mappings alone would undercount."
                ),
            )
        if self._byte_us_overflow:
            return self._missing(
                String("allocation_byte_microseconds"),
                String("byte_microseconds"),
                scope,
                String(
                    "Allocation byte-time exceeds u64 range;"
                    " value withheld."
                ),
            )
        var total = self._byte_us
        if horizon_ns > UInt64(0):
            for entry in self._live.items():
                var rec = entry.value
                if rec.map_ts >= horizon_ns:
                    continue
                var open_us = (horizon_ns - rec.map_ts) // UInt64(1000)
                if open_us == UInt64(0) or rec.mapped_bytes == UInt64(0):
                    continue
                var limit = (
                    UInt64(18446744073709551615) // rec.mapped_bytes
                )
                if open_us > limit:
                    return self._missing(
                        String("allocation_byte_microseconds"),
                        String("byte_microseconds"),
                        scope,
                        String(
                            "Allocation byte-time exceeds u64 range;"
                            " value withheld."
                        ),
                    )
                try:
                    total = checked_add(
                        total, rec.mapped_bytes * open_us
                    )
                except:
                    return self._missing(
                        String("allocation_byte_microseconds"),
                        String("byte_microseconds"),
                        scope,
                        String(
                            "Allocation byte-time exceeds u64 range;"
                            " value withheld."
                        ),
                    )
        return self._valued(
            String("allocation_byte_microseconds"),
            String("byte_microseconds"),
            total,
            String("counter"),
            False,
            UInt64(0),
            scope,
            String(
                "Observed allocation byte-time, not a measured sharing"
                " lifetime. Completed mappings use"
                " exact durations; open mappings integrate to"
                " the horizon."
            ),
            overlay_detail_loss,
        )

    def _mean_row(
        self, scope: String, overlay_detail_loss: Bool
    ) raises -> Metric:
        if self._lifetime_overflow:
            return self._missing(
                String("lifetime_mean_ns"),
                String("nanoseconds"),
                scope,
                String(
                    "Lifetime sum exceeds u64 range; mean"
                    " withheld, count/min/max stay valid."
                ),
            )
        return self._row(
            String("lifetime_mean_ns"),
            String("nanoseconds"),
            True,
            floor_mean(self._lifetime_total, self._completed),
            String("observed"),
            self._coverage(overlay_detail_loss),
            String("mean"),
            True,
            self._completed,
            False,
            String(""),
            scope,
            String("Floor mean over completed lifetimes."),
        )

    def _device_rows(
        self, mut out: List[Metric], window: String, overlay_detail_loss: Bool
    ):
        """Per-device detail rows in sorted device order.

        Families follow the same source gates as the global
        rows: null without their own source kinds.
        """
        var names = List[String]()
        for entry in self._devices.items():
            names.append(entry.key)
        var ordered = _sort_strings(names)
        var kept = len(ordered)
        if kept > _MAX_MAPPING_DEVICES:
            kept = _MAX_MAPPING_DEVICES
        for i in range(kept):
            var dev = ordered[i]
            var acc = self._devices.get(dev, _DeviceCopy())
            var scope = window + "; device " + dev
            var m = Metric()
            m.name = String("successful_allocations")
            m.has_value = self._saw_map
            m.value = acc.allocations
            m.unit = String("count")
            m.confidence = String("high")
            if self._saw_map:
                m.measurement = String("observed")
                m.coverage = self._coverage_device(overlay_detail_loss)
                m.has_aggregation = True
                m.aggregation = String("counter")
                m.notes = String("Map successes on this device.")
            else:
                m.measurement = String("unavailable")
                m.coverage = String("unavailable")
                m.notes = String(
                    "No map_result events in this capture."
                )
            m.has_device_id = True
            m.device_id = dev
            m.scope = scope
            out.append(m^)
            var b = Metric()
            b.name = String("mapped_bytes_total")
            b.has_value = self._saw_map and not acc.mapped_overflow
            b.value = acc.mapped
            b.unit = String("bytes")
            b.confidence = String("high")
            if not self._saw_map:
                b.measurement = String("unavailable")
                b.notes = String(
                    "No map_result events in this capture."
                )
                b.coverage = String("unavailable")
            elif acc.mapped_overflow:
                b.measurement = String("unavailable")
                b.notes = String("Total exceeds u64 range.")
                b.coverage = String("unavailable")
            else:
                b.measurement = String("observed")
                b.has_aggregation = True
                b.aggregation = String("counter")
                b.notes = String("Mapped bytes on this device.")
                b.coverage = self._coverage_device(overlay_detail_loss)
            b.has_device_id = True
            b.device_id = dev
            b.scope = scope
            out.append(b^)
            var o = Metric()
            o.name = String("copy_original_to_bounce_bytes")
            o.has_value = self._saw_copy and not acc.o2b_overflow
            o.value = acc.o2b
            o.unit = String("bytes")
            o.confidence = String("high")
            if not self._saw_copy:
                o.measurement = String("unavailable")
                o.notes = String("No copy events in this capture.")
                o.coverage = String("unavailable")
            elif acc.o2b_overflow:
                o.measurement = String("unavailable")
                o.notes = String("Total exceeds u64 range.")
                o.coverage = String("unavailable")
            else:
                o.measurement = String("observed")
                o.has_aggregation = True
                o.aggregation = String("counter")
                o.notes = String("Attributed copies on this device.")
                o.coverage = self._coverage_device(overlay_detail_loss)
            o.has_device_id = True
            o.device_id = dev
            o.scope = scope
            out.append(o^)
            var r = Metric()
            r.name = String("copy_bounce_to_original_bytes")
            r.has_value = self._saw_copy and not acc.b2o_overflow
            r.value = acc.b2o
            r.unit = String("bytes")
            r.confidence = String("high")
            if not self._saw_copy:
                r.measurement = String("unavailable")
                r.notes = String("No copy events in this capture.")
                r.coverage = String("unavailable")
            elif acc.b2o_overflow:
                r.measurement = String("unavailable")
                r.notes = String("Total exceeds u64 range.")
                r.coverage = String("unavailable")
            else:
                r.measurement = String("observed")
                r.has_aggregation = True
                r.aggregation = String("counter")
                r.notes = String("Attributed copies on this device.")
                r.coverage = self._coverage_device(overlay_detail_loss)
            r.has_device_id = True
            r.device_id = dev
            r.scope = scope
            out.append(r^)
