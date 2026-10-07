# SPDX-License-Identifier: GPL-3.0-or-later

"""Pool sample tracker and pressure-rule inputs.

Each pool id names one pool generation, so streaks never span a
re-creation. A sample qualifies only with byte units, a known
positive capacity, known usage, and usage at or above 90% of
that sample's contemporaneous capacity. Pressure needs three
consecutive qualifying samples; a missing half, a zero or
unknown capacity, a foreign unit, or a below-threshold reading
resets the streak. Each available gauge still lands
independently: a missing half resets only the streak, never
the known gauge. Pool metrics stay scoped to observed pools:
missing pool support never erases allocation evidence and never
implies an empty pool. Detail-channel loss (an observed gap or a
loss the engine propagates) degrades every gauge to partial:
a hidden sample may be the latest one.
"""

from memveil.model.event import Event
from memveil.model.identity import POOL_MAX
from memveil.model.metric import Metric
from memveil.model.validate import format_u64

comptime _MAX_POOL_DETAIL = 256


struct _PoolState(ImplicitlyCopyable):
    var streak: Int
    var has_used: Bool
    var used: UInt64
    var has_cap: Bool
    var cap: UInt64
    var samples: Int
    var invalid: Int

    def __init__(out self):
        self.streak = 0
        self.has_used = False
        self.used = UInt64(0)
        self.has_cap = False
        self.cap = UInt64(0)
        self.samples = 0
        self.invalid = 0


def _pressure_threshold(capacity: UInt64) -> UInt64:
    """90% of capacity without overflow: cap - floor(cap/10)."""
    return capacity - capacity // UInt64(10)


def _sorted_pool_ids(states: Dict[String, _PoolState]) -> List[String]:
    var names = List[String]()
    for entry in states.items():
        names.append(entry.key)
    var n = len(names)
    var i = 1
    while i < n:
        var key = names[i]
        var j = i - 1
        while j >= 0 and names[j] > key:
            names[j + 1] = names[j]
            j -= 1
        names[j + 1] = key
        i += 1
    return names^


struct PoolTracker[POOL_N: Int = POOL_MAX]:
    """Bounded per-generation pool sampling state."""

    var _pools: Dict[String, _PoolState]
    var _samples: Int
    var _refused: Int
    var _detail_loss: Bool
    var _notes: List[String]

    def __init__(out self):
        self._pools = Dict[String, _PoolState]()
        self._samples = 0
        self._refused = 0
        self._detail_loss = False
        self._notes = List[String]()

    def sees_pools(self) -> Bool:
        return self._samples > 0

    def note_detail_loss(mut self):
        """Degrade every gauge: detail loss may hide samples."""
        self._detail_loss = True

    def _coverage(self) -> String:
        if self._detail_loss:
            return String("partial")
        return String("complete_for_scope")

    def streak_of(self, pool: String) raises -> Int:
        if pool not in self._pools:
            raise Error("unknown pool " + pool)
        return self._pools.get(pool, _PoolState()).streak

    def pressured_pools(self) -> List[String]:
        var out = List[String]()
        var names = _sorted_pool_ids(self._pools)
        for i in range(len(names)):
            var st = self._pools.get(names[i], _PoolState())
            if st.streak >= 3:
                out.append(names[i])
        return out^

    def limitations(self) -> List[String]:
        var out = List[String]()
        for i in range(len(self._notes)):
            out.append(self._notes[i])
        if self._refused > 0:
            out.append(
                String(self._refused)
                + " pool samples refused (pool table exhausted)."
            )
        var pools = len(self._pools)
        if pools > _MAX_POOL_DETAIL:
            out.append(
                String(pools - _MAX_POOL_DETAIL)
                + " pools withheld from per-pool rows ("
                + String(_MAX_POOL_DETAIL)
                + "-pool detail budget)."
            )
        return out^

    def consume(mut self, ev: Event):
        """Fold one event; samples change state, detail gaps degrade."""
        if ev.kind == "gap":
            if ev.gap.channel == "detail":
                self.note_detail_loss()
            return
        if ev.kind != "pool_sample":
            return
        self._samples += 1
        var pool = ev.pool.pool_id
        if pool == "":
            self._note_once("pool sample without identity ignored")
            return
        if pool not in self._pools:
            if len(self._pools) >= Self.POOL_N:
                self._refused += 1
                return
            self._pools[pool] = _PoolState()
        var st = self._pools.get(pool, _PoolState())
        st.samples += 1
        if ev.pool.unit != "bytes":
            st.invalid += 1
            st.streak = 0
            self._pools[pool] = st
            self._note_once(
                "non-byte pool sample ignored for " + pool
            )
            return
        # Each available gauge lands independently; only the
        # pressure streak needs both halves of one sample.
        if ev.pool.has_used:
            st.has_used = True
            st.used = ev.pool.used_bytes
        var usable_cap = False
        var cap = UInt64(0)
        if ev.pool.has_capacity:
            if ev.pool.capacity_bytes == UInt64(0):
                self._note_once(
                    "zero pool capacity cannot form a ratio"
                )
            else:
                st.has_cap = True
                st.cap = ev.pool.capacity_bytes
                cap = ev.pool.capacity_bytes
                usable_cap = True
        if not ev.pool.has_used or not usable_cap:
            st.invalid += 1
            st.streak = 0
            self._pools[pool] = st
            return
        if ev.pool.used_bytes >= _pressure_threshold(cap):
            st.streak += 1
        else:
            st.streak = 0
        self._pools[pool] = st

    def _note_once(mut self, text: String):
        for i in range(len(self._notes)):
            if self._notes[i] == text:
                return
        self._notes.append(text)

    def metrics(self, window: String) -> List[Metric]:
        """Per-pool rows in sorted pool order."""
        var out = List[Metric]()
        var names = _sorted_pool_ids(self._pools)
        var kept = len(names)
        if kept > _MAX_POOL_DETAIL:
            kept = _MAX_POOL_DETAIL
        for i in range(kept):
            var pool = names[i]
            var st = self._pools.get(pool, _PoolState())
            var scope = window + "; pool " + pool
            var u = Metric()
            u.name = String("pool_used_bytes")
            u.has_value = st.has_used
            u.value = st.used
            u.unit = String("bytes")
            u.confidence = String("high")
            if st.has_used:
                u.measurement = String("observed")
                u.has_aggregation = True
                u.aggregation = String("gauge")
                u.notes = String("Latest available usage sample.")
                u.coverage = self._coverage()
            else:
                u.measurement = String("unavailable")
                u.notes = String(
                    "No available usage sample for this pool."
                )
                u.coverage = String("unavailable")
            u.has_pool_id = True
            u.pool_id = pool
            u.scope = scope
            out.append(u^)
            var c = Metric()
            c.name = String("pool_capacity_bytes")
            c.has_value = st.has_cap
            c.value = st.cap
            c.unit = String("bytes")
            c.confidence = String("high")
            if st.has_cap:
                c.measurement = String("observed")
                c.has_aggregation = True
                c.aggregation = String("gauge")
                c.notes = String("Latest available capacity sample.")
                c.coverage = self._coverage()
            else:
                c.measurement = String("unavailable")
                c.notes = String(
                    "No available capacity sample for this pool."
                )
                c.coverage = String("unavailable")
            c.has_pool_id = True
            c.pool_id = pool
            c.scope = scope
            out.append(c^)
            var s = Metric()
            s.name = String("pool_pressure_samples")
            s.has_value = True
            s.value = UInt64(st.streak)
            s.unit = String("count")
            s.confidence = String("high")
            s.measurement = String("observed")
            s.coverage = self._coverage()
            s.has_aggregation = True
            s.aggregation = String("gauge")
            s.has_pool_id = True
            s.pool_id = pool
            s.scope = scope
            s.notes = String(
                "Consecutive qualifying samples ("
                + format_u64(UInt64(st.samples))
                + " total, "
                + format_u64(UInt64(st.invalid))
                + " invalid); pressure needs 3."
            )
            out.append(s^)
        return out^
