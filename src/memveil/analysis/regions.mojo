# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded region-state tracker over conversion observations.

Each (identity, namespace, generation) triple names one proved
region lineage; split/merge of half-open intervals happens
only within that lineage, never across namespaces. Successful
resolved guest-physical transitions move intervals between
known shared and private; a failure without rollback proof
leaves its interval unknown; unresolved, identity-only, or
ordinary-kernel no-op requests count as requests without any
state transition. Mapping, copy, pool, and counter events
never touch region state.

Unions cover guest-physical intervals only and sum disjoint
tracked intervals per proved identity; distinct identities
are assumed disjoint by the producer. A total that would
cover unknown intervals stays unavailable: known subsets
report with explicit partial scope instead. Detail loss
degrades counters and unions; baseline loss degrades the
unions alone, since observed transitions still count.
"""

from memveil.model.event import Event
from memveil.model.identity import REGION_MAX
from memveil.model.metric import Metric
from memveil.model.regions import RegionObservation
from memveil.model.validate import format_u64

comptime SEGMENTS_MAX = 65536


struct _Segment(ImplicitlyCopyable):
    var region: Int
    var start: UInt64
    var end: UInt64
    var state: String

    def __init__(out self):
        self.region = -1
        self.start = UInt64(0)
        self.end = UInt64(0)
        self.state = String("")


def _u64max() -> UInt64:
    return ~UInt64(0)


struct RegionTracker[REGION_N: Int = REGION_MAX, SEG_N: Int = SEGMENTS_MAX]:
    """Bounded per-lineage interval state plus request counts."""

    var _admitted: Bool
    var _baseline_complete: Bool
    var _index: Dict[String, Int]
    var _claimed: Dict[String, String]
    var _namespaces: List[String]
    var _invalid: List[Bool]
    var _segments: List[_Segment]
    var _requests: Int
    var _failures: Int
    var _request_bytes: UInt64
    var _bytes_overflow: Bool
    var _refused: Int
    var _contradictions: Int
    var _invalidated: Int
    var _opaque: Int
    var _saw_transition: Bool
    var _seeded: Bool
    var _detail_loss: Bool
    var _baseline_loss: Bool
    var _notes: List[String]

    def __init__(
        out self,
        transitions_admitted: Bool = True,
        baseline_complete: Bool = True,
    ):
        self._admitted = transitions_admitted
        self._baseline_complete = baseline_complete
        self._index = Dict[String, Int]()
        self._claimed = Dict[String, String]()
        self._namespaces = List[String]()
        self._invalid = List[Bool]()
        self._segments = List[_Segment]()
        self._requests = 0
        self._failures = 0
        self._request_bytes = UInt64(0)
        self._bytes_overflow = False
        self._refused = 0
        self._contradictions = 0
        self._invalidated = 0
        self._opaque = 0
        self._saw_transition = False
        self._seeded = False
        self._detail_loss = False
        self._baseline_loss = False
        self._notes = List[String]()

    def sees_regions(self) -> Bool:
        return self._saw_transition or self._seeded or len(self._notes) > 0

    def note_detail_loss(mut self):
        """Degrade counters and unions: loss may hide transitions."""
        self._detail_loss = True

    def note_baseline_loss(mut self):
        """Degrade unions alone: seeded state may be incomplete."""
        self._baseline_loss = True

    def _counter_coverage(self) -> String:
        if self._detail_loss:
            return String("partial")
        return String("complete_for_scope")

    def limitations(self) -> List[String]:
        var out = List[String]()
        for i in range(len(self._notes)):
            out.append(self._notes[i])
        if self._refused > 0:
            out.append(
                String(self._refused)
                + " region observations refused (region table exhausted)."
            )
        if self._contradictions > 0:
            out.append(
                String(self._contradictions)
                + " region observations refused (token reused across"
                " namespaces)."
            )
        if self._invalidated > 0:
            out.append(
                String(self._invalidated)
                + " regions invalidated (interval budget exceeded;"
                " affected state excluded, never merged)."
            )
        if self._opaque > 0:
            out.append(
                String(self._opaque)
                + " transition results carried no usable state;"
                " unions exclude them, never assume them."
            )
        return out^

    def seed_baseline(mut self, obs: List[RegionObservation]):
        """Apply producer-attested initial intervals in listed order."""
        if len(obs) > 0:
            self._seeded = True
        if not self._admitted:
            if len(obs) > 0:
                self._note_once(
                    "baseline observations ignored: region state"
                    " unavailable on this profile"
                )
            return
        for i in range(len(obs)):
            var o = obs[i]
            var idx = self._region_for(
                o.region_id, o.address_space, o.generation
            )
            if idx < 0:
                continue
            var end = o.offset + o.length
            if o.length > _u64max() - o.offset:
                self._note_once(
                    "baseline span overflows; interval ignored for state"
                )
                continue
            self._apply(idx, o.offset, end, o.state)

    def consume(mut self, ev: Event):
        """Fold one event; transitions change state, gaps degrade."""
        if ev.kind == "gap":
            if ev.gap.channel == "detail":
                self.note_detail_loss()
            elif ev.gap.channel == "baseline":
                self.note_baseline_loss()
            return
        if ev.kind != "transition_result":
            return
        self._saw_transition = True
        self._requests += 1
        if not ev.transition.success:
            self._failures += 1
        if self._bytes_overflow:
            pass
        elif ev.transition.length > _u64max() - self._request_bytes:
            self._bytes_overflow = True
        else:
            self._request_bytes += ev.transition.length
        if not self._admitted:
            return
        if not ev.transition.has_resolution:
            self._opaque += 1
            return
        if ev.transition.resolution != "resolved":
            self._opaque += 1
            return
        if not ev.transition.has_address_space:
            self._opaque += 1
            return
        var space = ev.transition.address_space
        if space == "identity_only":
            self._opaque += 1
            return
        if ev.transition.length > _u64max() - ev.transition.offset:
            self._note_once(
                "transition span overflows; ignored for state"
            )
            self._opaque += 1
            return
        var idx = self._region_for(
            ev.transition.region_id, space, ev.transition.generation
        )
        if idx < 0:
            return
        var end = ev.transition.offset + ev.transition.length
        if ev.transition.success:
            self._apply(
                idx, ev.transition.offset, end,
                ev.transition.requested_state,
            )
        else:
            self._apply(idx, ev.transition.offset, end, String("unknown"))

    def metrics(self, window: String) -> List[Metric]:
        """Request counts plus guest-physical state rows.

        Counters need transition evidence of their own: a
        seeded baseline proves state, never request counts.
        """
        var out = List[Metric]()
        if not self.sees_regions():
            return out^
        if not self._saw_transition:
            out.append(self._unavailable_counter(
                String("conversion_requests"), String("count"), window
            ))
            out.append(self._unavailable_counter(
                String("conversion_failures"), String("count"), window
            ))
            out.append(self._unavailable_counter(
                String("conversion_request_bytes"),
                String("bytes"),
                window,
            ))
        else:
            var rq = Metric()
            rq.name = String("conversion_requests")
            rq.has_value = True
            rq.value = UInt64(self._requests)
            rq.unit = String("count")
            rq.confidence = String("high")
            rq.measurement = String("observed")
            rq.coverage = self._counter_coverage()
            rq.has_aggregation = True
            rq.aggregation = String("counter")
            rq.scope = window
            rq.notes = String(
                "Observed conversion API results; requests are not"
                " bytes."
            )
            out.append(rq^)
            var fl = Metric()
            fl.name = String("conversion_failures")
            fl.has_value = True
            fl.value = UInt64(self._failures)
            fl.unit = String("count")
            fl.confidence = String("high")
            fl.measurement = String("observed")
            fl.coverage = self._counter_coverage()
            fl.has_aggregation = True
            fl.aggregation = String("counter")
            fl.scope = window
            fl.notes = String(
                "Failed conversion requests; affected intervals stay"
                " unknown without rollback proof."
            )
            out.append(fl^)
            var rb = Metric()
            rb.name = String("conversion_request_bytes")
            rb.has_value = not self._bytes_overflow
            rb.value = self._request_bytes
            rb.unit = String("bytes")
            rb.confidence = String("high")
            if self._bytes_overflow:
                rb.measurement = String("unavailable")
                rb.coverage = String("unavailable")
                rb.notes = String(
                    "Requested lengths exceed u64 range; total"
                    " withheld."
                )
            else:
                rb.measurement = String("observed")
                rb.coverage = self._counter_coverage()
                rb.has_aggregation = True
                rb.aggregation = String("counter")
                rb.notes = String(
                    "Sum of requested lengths, not unique physical"
                    " bytes."
                )
            rb.scope = window
            out.append(rb^)
        var scope = window + "; guest-physical regions"
        if not self._admitted:
            out.append(self._unavailable_state(
                String("known_shared_region_bytes"), scope,
                String(
                    "ordinary profile: conversions are no-ops; no state"
                    " transition applies"
                ),
            ))
            out.append(self._unavailable_state(
                String("known_private_region_bytes"), scope,
                String(
                    "ordinary profile: conversions are no-ops; no state"
                    " transition applies"
                ),
            ))
            out.append(self._unavailable_state(
                String("unknown_region_bytes"), scope,
                String(
                    "ordinary profile: conversions are no-ops; no state"
                    " transition applies"
                ),
            ))
            return out^
        if not self._baseline_complete:
            out.append(self._unavailable_state(
                String("known_shared_region_bytes"), scope,
                String(
                    "baseline incomplete: pre-existing state unknown"
                ),
            ))
            out.append(self._unavailable_state(
                String("known_private_region_bytes"), scope,
                String(
                    "baseline incomplete: pre-existing state unknown"
                ),
            ))
            out.append(self._unavailable_state(
                String("unknown_region_bytes"), scope,
                String(
                    "baseline incomplete: pre-existing state unknown"
                ),
            ))
            return out^
        var shared = UInt64(0)
        var private = UInt64(0)
        var unknown = UInt64(0)
        var overflow = False
        for i in range(len(self._segments)):
            var s = self._segments[i]
            if self._invalid[s.region]:
                continue
            if self._namespaces[s.region] != "guest_physical":
                continue
            var n = s.end - s.start
            if s.state == "shared":
                if n > _u64max() - shared:
                    overflow = True
                else:
                    shared += n
            elif s.state == "private":
                if n > _u64max() - private:
                    overflow = True
                else:
                    private += n
            else:
                if n > _u64max() - unknown:
                    overflow = True
                else:
                    unknown += n
        var partial = (
            unknown > UInt64(0)
            or self._refused > 0
            or self._contradictions > 0
            or self._invalidated > 0
            or self._opaque > 0
            or self._detail_loss
            or self._baseline_loss
        )
        out.append(self._union_row(
            String("known_shared_region_bytes"), scope, shared,
            unknown, overflow, partial,
            String("known-shared"),
        ))
        out.append(self._union_row(
            String("known_private_region_bytes"), scope, private,
            unknown, overflow, partial,
            String("known-private"),
        ))
        out.append(self._union_row(
            String("unknown_region_bytes"), scope, unknown,
            unknown, overflow, partial,
            String("unknown-state"),
        ))
        return out^

    def _union_row(
        self,
        name: String,
        scope: String,
        value: UInt64,
        unknown: UInt64,
        overflow: Bool,
        partial: Bool,
        what: String,
    ) -> Metric:
        var m = Metric()
        m.name = name
        m.unit = String("bytes")
        m.scope = scope
        m.confidence = String("medium")
        if overflow:
            m.has_value = False
            m.measurement = String("unavailable")
            m.coverage = String("unavailable")
            m.notes = String(
                "Tracked bytes exceed u64 range; total withheld."
            )
            return m^
        m.has_value = True
        m.value = value
        m.measurement = String("observed")
        m.has_aggregation = True
        m.aggregation = String("gauge")
        if partial:
            m.coverage = String("partial")
            var note = (
                String("Sum over proved identities of disjoint ")
                + what
                + " guest-physical intervals; excludes "
                + format_u64(unknown)
                + " unknown-state bytes and any refused or"
                " invalidated state."
            )
            if self._opaque > 0:
                note += (
                    " "
                    + String(self._opaque)
                    + " transition results carried no usable state."
                )
            m.notes = note
        else:
            m.coverage = String("complete_for_scope")
            m.notes = String(
                "Sum over proved identities of disjoint "
                + what
                + " guest-physical intervals."
            )
        return m^

    def _unavailable_counter(
        self, name: String, unit: String, scope: String
    ) -> Metric:
        var m = Metric()
        m.name = name
        m.has_value = False
        m.unit = unit
        m.measurement = String("unavailable")
        m.coverage = String("unavailable")
        m.confidence = String("high")
        m.scope = scope
        m.notes = String(
            "No transition_result events in this capture; baseline"
            " seeds state, not counts."
        )
        return m^

    def _unavailable_state(
        self, name: String, scope: String, reason: String
    ) -> Metric:
        var m = Metric()
        m.name = name
        m.has_value = False
        m.unit = String("bytes")
        m.measurement = String("unavailable")
        m.coverage = String("unavailable")
        m.confidence = String("medium")
        m.scope = scope
        m.notes = reason
        return m^

    def _note_once(mut self, text: String):
        for i in range(len(self._notes)):
            if self._notes[i] == text:
                return
        self._notes.append(text)

    def _region_for(
        mut self, identity: String, namespace: String, generation: Int
    ) -> Int:
        var claim = identity + "|" + String(generation)
        if claim in self._claimed:
            if self._claimed.get(claim, String("")) != namespace:
                self._contradictions += 1
                self._note_once(
                    "region token reused across namespaces; later"
                    " namespace refused"
                )
                return -1
        var key = namespace + "|" + String(generation) + "|" + identity
        if key in self._index:
            return self._index.get(key, -1)
        if len(self._namespaces) >= Self.REGION_N:
            self._refused += 1
            return -1
        var idx = len(self._namespaces)
        self._namespaces.append(namespace)
        self._invalid.append(False)
        self._index[key] = idx
        if claim not in self._claimed:
            self._claimed[claim] = namespace
        return idx

    def _apply(
        mut self, idx: Int, start: UInt64, end: UInt64, state: String
    ):
        if self._invalid[idx]:
            return
        if start >= end:
            return
        var starts = List[UInt64]()
        var ends = List[UInt64]()
        var states = List[String]()
        for i in range(len(self._segments)):
            var s = self._segments[i]
            if s.region != idx:
                continue
            if s.end <= start or s.start >= end:
                starts.append(s.start)
                ends.append(s.end)
                states.append(s.state)
                continue
            if s.start < start:
                starts.append(s.start)
                ends.append(start)
                states.append(s.state)
            if s.end > end:
                starts.append(end)
                ends.append(s.end)
                states.append(s.state)
        starts.append(start)
        ends.append(end)
        states.append(state)
        self._sort_by_start(starts, ends, states)
        var total = len(self._segments)
        for i in range(len(self._segments)):
            if self._segments[i].region == idx:
                total -= 1
        var merged_starts = List[UInt64]()
        var merged_ends = List[UInt64]()
        var merged_states = List[String]()
        for i in range(len(starts)):
            var n = len(merged_starts)
            if (
                n > 0
                and merged_states[n - 1] == states[i]
                and merged_ends[n - 1] == starts[i]
            ):
                merged_ends[n - 1] = ends[i]
            else:
                merged_starts.append(starts[i])
                merged_ends.append(ends[i])
                merged_states.append(states[i])
        if total + len(merged_starts) > Self.SEG_N:
            self._invalid[idx] = True
            self._invalidated += 1
            self._note_once(
                "interval budget exceeded; affected region excluded"
            )
            var kept = List[_Segment]()
            for i in range(len(self._segments)):
                if self._segments[i].region != idx:
                    kept.append(self._segments[i])
            self._segments = kept^
            return
        var next = List[_Segment]()
        for i in range(len(self._segments)):
            if self._segments[i].region != idx:
                next.append(self._segments[i])
        for i in range(len(merged_starts)):
            var s = _Segment()
            s.region = idx
            s.start = merged_starts[i]
            s.end = merged_ends[i]
            s.state = merged_states[i]
            next.append(s^)
        self._segments = next^

    def _sort_by_start(
        mut self,
        mut starts: List[UInt64],
        mut ends: List[UInt64],
        mut states: List[String],
    ):
        # Insertion sort over one region's fragments, in place.
        var n = len(starts)
        var i = 1
        while i < n:
            var ks = starts[i]
            var ke = ends[i]
            var kt = states[i]
            var j = i - 1
            while j >= 0 and starts[j] > ks:
                starts[j + 1] = starts[j]
                ends[j + 1] = ends[j]
                states[j + 1] = states[j]
                j -= 1
            starts[j + 1] = ks
            ends[j + 1] = ke
            states[j + 1] = kt
            i += 1
