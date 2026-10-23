# SPDX-License-Identifier: GPL-3.0-or-later

"""Hook liveness over windowed record counts.

A capture is complete only if its hooks were live. The copy
hooks attach before the lifecycle hooks, so cumulative
equalities false-fire at the edges: every map in the attach
gap leaves a TO copy with no map record. Only one-sided
inequalities over windows away from the edges are sound:

- F = [T_a, T_d - GUARD] (forward: causes in F, effects over
  the whole run); R = [T_r, T_d - GUARD] (reverse: effects in
  R, causes over the whole run).
- E1 attempt->map, E2f map->copy, E2r copy->map, E3f
  unmap->copy, E3r copy->unmap.

Bucketed counts include only whole buckets inside the
window: every left-hand side is under-counted, which can
only suppress a firing, never cause one. The tally runs
before the device filter and the latch gate; evaluation
happens once at close with the detach timestamp.
"""

from memveil.model.validate import format_u64


comptime LIVENESS_GUARD_NS = UInt64(1000000000)
comptime LIVENESS_BUCKET_NS = UInt64(250000000)
comptime LIVENESS_BUCKETS = 8

comptime _MAX_SPAN_NS = UInt64(2592000000000000)


def sat_add_u64(a: UInt64, b: UInt64) -> Tuple[UInt64, Bool]:
    """Saturating u64 add plus an overflow flag."""
    var r = a + b
    if r < a:
        return (~UInt64(0), True)
    return (r, False)


struct LivenessCounts(Copyable, Movable):
    """One window's record counts; saturates, never wraps."""

    var attempts: UInt64
    var maps_all: UInt64
    var maps_ok: UInt64
    var unmaps_from: UInt64
    var syncd_to: UInt64
    var syncc_from: UInt64
    var copies_to: UInt64
    var copies_from: UInt64
    var saturated: Bool

    def __init__(out self):
        self.attempts = UInt64(0)
        self.maps_all = UInt64(0)
        self.maps_ok = UInt64(0)
        self.unmaps_from = UInt64(0)
        self.syncd_to = UInt64(0)
        self.syncc_from = UInt64(0)
        self.copies_to = UInt64(0)
        self.copies_from = UInt64(0)
        self.saturated = False

    def _inc(mut self, v: UInt64) -> UInt64:
        var r = sat_add_u64(v, UInt64(1))
        if r[1]:
            self.saturated = True
        return r[0]

    def bump_attempts(mut self):
        self.attempts = self._inc(self.attempts)

    def bump_maps_all(mut self):
        self.maps_all = self._inc(self.maps_all)

    def bump_maps_ok(mut self):
        self.maps_ok = self._inc(self.maps_ok)

    def bump_unmaps_from(mut self):
        self.unmaps_from = self._inc(self.unmaps_from)

    def bump_syncd_to(mut self):
        self.syncd_to = self._inc(self.syncd_to)

    def bump_syncc_from(mut self):
        self.syncc_from = self._inc(self.syncc_from)

    def bump_copies_to(mut self):
        self.copies_to = self._inc(self.copies_to)

    def bump_copies_from(mut self):
        self.copies_from = self._inc(self.copies_from)

    def combine(mut self, other: LivenessCounts):
        """Fold other in, saturating; saturation propagates."""
        var r = sat_add_u64(self.attempts, other.attempts)
        self.attempts = r[0]
        var sat = r[1]
        r = sat_add_u64(self.maps_all, other.maps_all)
        self.maps_all = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.maps_ok, other.maps_ok)
        self.maps_ok = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.unmaps_from, other.unmaps_from)
        self.unmaps_from = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.syncd_to, other.syncd_to)
        self.syncd_to = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.syncc_from, other.syncc_from)
        self.syncc_from = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.copies_to, other.copies_to)
        self.copies_to = r[0]
        sat = sat or r[1]
        r = sat_add_u64(self.copies_from, other.copies_from)
        self.copies_from = r[0]
        sat = sat or r[1]
        self.saturated = self.saturated or other.saturated or sat


struct _Bucket(Copyable, Movable):
    var index: Int
    var counts: LivenessCounts

    def __init__(out self):
        self.index = -1
        self.counts = LivenessCounts()


struct LivenessTally(Movable):
    """Per-record counts plus F/R window buckets.

    `all` counts every record; seen_lc/seen_cp count every
    lifecycle/copy record the tally observed, including
    direction-skipped ones, so emitted-minus-seen is the
    record loss. The ring holds the trailing buckets;
    win_f/win_r accumulate folded buckets. A bucket
    leaving the ring folds into win_f (eviction implies it
    ended over a second before any detach the drain can
    reach, so it sits wholly inside F), and into win_r when
    its start reaches t_r. Records before t_a, past the span
    bound, or for an evicted bucket count in `all` only:
    left-hand sides under-count, which suppresses firing.
    """

    var t_a: UInt64
    var t_r: UInt64
    var all: LivenessCounts
    var win_f: LivenessCounts
    var win_r: LivenessCounts
    var ring: List[_Bucket]
    var seen_lc: UInt64
    var seen_cp: UInt64

    def __init__(out self):
        self.t_a = UInt64(0)
        self.t_r = UInt64(0)
        self.all = LivenessCounts()
        self.win_f = LivenessCounts()
        self.win_r = LivenessCounts()
        self.ring = List[_Bucket]()
        for _ in range(LIVENESS_BUCKETS):
            self.ring.append(_Bucket())
        self.seen_lc = UInt64(0)
        self.seen_cp = UInt64(0)

    def __init__(out self, t_a: UInt64, t_r: UInt64):
        self.t_a = t_a
        self.t_r = t_r
        self.all = LivenessCounts()
        self.win_f = LivenessCounts()
        self.win_r = LivenessCounts()
        self.ring = List[_Bucket]()
        for _ in range(LIVENESS_BUCKETS):
            self.ring.append(_Bucket())
        self.seen_lc = UInt64(0)
        self.seen_cp = UInt64(0)

    def retarget(mut self, t_a: UInt64, t_r: UInt64):
        """Bind the windows once readiness is stamped; resets.

        The collector calls this exactly once, after the arm,
        before any record is tallied; nothing is lost by the
        reset because nothing was tallied yet.
        """
        self.t_a = t_a
        self.t_r = t_r
        self.all = LivenessCounts()
        self.win_f = LivenessCounts()
        self.win_r = LivenessCounts()
        self.ring = List[_Bucket]()
        for _ in range(LIVENESS_BUCKETS):
            self.ring.append(_Bucket())
        self.seen_lc = UInt64(0)
        self.seen_cp = UInt64(0)

    def _slot_for(mut self, ts: UInt64) -> Int:
        """Ring slot for ts, evicting as needed; -1 is all-only."""
        if ts < self.t_a:
            return -1
        var span = ts - self.t_a
        if span > _MAX_SPAN_NS:
            return -1
        var b = Int(span // LIVENESS_BUCKET_NS)
        # start <= ts cannot wrap (b * BUCKET <= span); the
        # end can, and a wrapped end stays out of the ring.
        var start = self.t_a + UInt64(b) * LIVENESS_BUCKET_NS
        var end = start + LIVENESS_BUCKET_NS
        if end < start:
            return -1
        var s = b % LIVENESS_BUCKETS
        var cur = self.ring[s].index
        if cur == b:
            return s
        if cur > b:
            return -1
        if cur >= 0:
            var old = self.ring[s].counts.copy()
            var old_start = (
                self.t_a + UInt64(cur) * LIVENESS_BUCKET_NS
            )
            self.win_f.combine(old)
            if old_start >= self.t_r:
                self.win_r.combine(old.copy())
        self.ring[s].index = b
        self.ring[s].counts = LivenessCounts()
        return s

    def note_attempt(mut self, ts: UInt64):
        self.all.bump_attempts()
        var s = self._slot_for(ts)
        if s >= 0:
            self.ring[s].counts.bump_attempts()

    def _bump_seen_lc(mut self):
        var r = sat_add_u64(self.seen_lc, UInt64(1))
        self.seen_lc = r[0]
        if r[1]:
            self.all.saturated = True

    def _bump_seen_cp(mut self):
        var r = sat_add_u64(self.seen_cp, UInt64(1))
        self.seen_cp = r[0]
        if r[1]:
            self.all.saturated = True

    def note_map(mut self, ts: UInt64, ok: Bool):
        self._bump_seen_lc()
        self.all.bump_maps_all()
        if ok:
            self.all.bump_maps_ok()
        var s = self._slot_for(ts)
        if s >= 0:
            self.ring[s].counts.bump_maps_all()
            if ok:
                self.ring[s].counts.bump_maps_ok()

    def note_unmap(mut self, ts: UInt64, dir: UInt16, skip_sync: Bool):
        self._bump_seen_lc()
        if skip_sync or (dir != UInt16(2) and dir != UInt16(0)):
            return
        self.all.bump_unmaps_from()
        var s = self._slot_for(ts)
        if s >= 0:
            self.ring[s].counts.bump_unmaps_from()

    def note_sync(mut self, ts: UInt64, to_device: Bool, dir: UInt16):
        var to = to_device and (
            dir == UInt16(1) or dir == UInt16(0)
        )
        var frm = not to_device and (
            dir == UInt16(2) or dir == UInt16(0)
        )
        self._bump_seen_cp()
        if not to and not frm:
            return
        if to:
            self.all.bump_syncd_to()
        else:
            self.all.bump_syncc_from()
        var s = self._slot_for(ts)
        if s >= 0:
            if to:
                self.ring[s].counts.bump_syncd_to()
            else:
                self.ring[s].counts.bump_syncc_from()

    def note_copy(mut self, ts: UInt64, dir: UInt16):
        self._bump_seen_cp()
        if dir != UInt16(1) and dir != UInt16(2):
            return
        if dir == UInt16(1):
            self.all.bump_copies_to()
        else:
            self.all.bump_copies_from()
        var s = self._slot_for(ts)
        if s >= 0:
            if dir == UInt16(1):
                self.ring[s].counts.bump_copies_to()
            else:
                self.ring[s].counts.bump_copies_from()


@fieldwise_init
struct LivenessLoss(ImplicitlyCopyable):
    """Lifecycle/copy record loss; known pins both terms."""

    var lc: UInt64
    var cp: UInt64
    var known: Bool


@fieldwise_init
struct LivenessVerdict(Copyable, Movable):
    """state in hooks_silent/unverified/verified/not_exercised.

    equation names the first violated or unverified equation
    (attempt->map, map->copy, copy->map, unmap->copy,
    copy->unmap), or the copy-without-lifecycle marker; detail
    carries "<lhs> > <rhs>" with numbers. Both stay empty when
    nothing fired and nothing stayed unverified.
    """

    var state: String
    var equation: String
    var detail: String


def _sat_sum2(a: UInt64, b: UInt64) -> UInt64:
    return sat_add_u64(a, b)[0]


def _sat_sum4(a: UInt64, b: UInt64, c: UInt64, d: UInt64) -> UInt64:
    return sat_add_u64(sat_add_u64(a, b)[0], sat_add_u64(c, d)[0])[0]


def _windowed(
    tally: LivenessTally, t_c: UInt64
) -> Tuple[LivenessCounts, LivenessCounts]:
    """Fold whole ring buckets into copies of win_f/win_r."""
    var win_f = tally.win_f.copy()
    var win_r = tally.win_r.copy()
    for i in range(len(tally.ring)):
        var b = tally.ring[i].index
        if b < 0:
            continue
        var start = tally.t_a + UInt64(b) * LIVENESS_BUCKET_NS
        var end = start + LIVENESS_BUCKET_NS
        if end < start:
            continue
        if end > t_c:
            continue
        var counts = tally.ring[i].counts.copy()
        win_f.combine(counts.copy())
        if start >= tally.t_r:
            win_r.combine(counts^)
    return (win_f^, win_r^)


def _judge(
    needs: Bool,
    window_empty: Bool,
    lhs: UInt64,
    rhs: UInt64,
    loss_known: Bool,
    saturated: Bool,
) -> String:
    if not needs:
        return String("not_exercised")
    if window_empty:
        return String("not_exercised")
    if lhs == UInt64(0):
        return String("not_exercised")
    if not loss_known:
        return String("unverified")
    if saturated:
        return String("unverified")
    if lhs > rhs:
        return String("hooks_silent")
    return String("verified")


def evaluate_liveness(
    tally: LivenessTally,
    t_d: UInt64,
    has_attempt: Bool,
    has_lifecycle: Bool,
    has_copy: Bool,
    loss: LivenessLoss,
) -> LivenessVerdict:
    """Judge the hook-liveness equations; precedence silent over unverified.

    F = [t_a, t_d - GUARD], R = [t_r, t_d - GUARD]; a copy
    without lifecycle stays unverified regardless of the
    equations. Saturation and unknown loss turn an exercised
    equation unverified, never silent.
    """
    var t_c = UInt64(0)
    if t_d >= LIVENESS_GUARD_NS:
        t_c = t_d - LIVENESS_GUARD_NS
    var f_empty = t_c <= tally.t_a
    var r_empty = t_c <= tally.t_r
    var wins = _windowed(tally, t_c)
    var win_f = wins[0].copy()
    var win_r = wins[1].copy()
    var sat_f = win_f.saturated or tally.all.saturated
    var sat_r = win_r.saturated or tally.all.saturated
    var names = List[String]()
    var states = List[String]()
    var lhs_s = List[UInt64]()
    var rhs_s = List[UInt64]()
    # E1 attempt->map.
    var lhs = win_f.attempts
    var rhs = _sat_sum2(tally.all.maps_all, loss.lc)
    names.append(String("attempt->map"))
    states.append(
        _judge(
            has_attempt and has_lifecycle,
            f_empty,
            lhs,
            rhs,
            loss.known,
            sat_f,
        )
    )
    lhs_s.append(lhs)
    rhs_s.append(rhs)
    # E2f map->copy; copy-only runs judge the sync-only terms.
    lhs = _sat_sum2(win_f.maps_ok, win_f.syncd_to)
    rhs = _sat_sum2(tally.all.copies_to, loss.cp)
    names.append(String("map->copy"))
    states.append(
        _judge(
            has_copy,
            f_empty,
            lhs,
            rhs,
            loss.known,
            sat_f,
        )
    )
    lhs_s.append(lhs)
    rhs_s.append(rhs)
    # E2r copy->map.
    lhs = win_r.copies_to
    rhs = _sat_sum4(
        tally.all.maps_ok, tally.all.syncd_to, loss.lc, loss.cp
    )
    names.append(String("copy->map"))
    states.append(
        _judge(
            has_lifecycle and has_copy,
            r_empty,
            lhs,
            rhs,
            loss.known,
            sat_r,
        )
    )
    lhs_s.append(lhs)
    rhs_s.append(rhs)
    # E3f unmap->copy; copy-only runs judge the sync-only terms.
    lhs = _sat_sum2(win_f.unmaps_from, win_f.syncc_from)
    rhs = _sat_sum2(tally.all.copies_from, loss.cp)
    names.append(String("unmap->copy"))
    states.append(
        _judge(
            has_copy,
            f_empty,
            lhs,
            rhs,
            loss.known,
            sat_f,
        )
    )
    lhs_s.append(lhs)
    rhs_s.append(rhs)
    # E3r copy->unmap.
    lhs = win_r.copies_from
    rhs = _sat_sum4(
        tally.all.unmaps_from,
        tally.all.syncc_from,
        loss.lc,
        loss.cp,
    )
    names.append(String("copy->unmap"))
    states.append(
        _judge(
            has_lifecycle and has_copy,
            r_empty,
            lhs,
            rhs,
            loss.known,
            sat_r,
        )
    )
    lhs_s.append(lhs)
    rhs_s.append(rhs)
    for i in range(len(names)):
        if states[i] == String("hooks_silent"):
            return LivenessVerdict(
                String("hooks_silent"),
                names[i].copy(),
                format_u64(lhs_s[i])
                + String(" > ")
                + format_u64(rhs_s[i]),
            )
    if has_copy and not has_lifecycle:
        return LivenessVerdict(
            String("unverified"),
            String("copy liveness needs lifecycle"),
            String(""),
        )
    for i in range(len(names)):
        if states[i] == String("unverified"):
            return LivenessVerdict(
                String("unverified"),
                names[i].copy(),
                format_u64(lhs_s[i])
                + String(" > ")
                + format_u64(rhs_s[i]),
            )
    for i in range(len(names)):
        if states[i] == String("verified"):
            return LivenessVerdict(
                String("verified"), String(""), String("")
            )
    return LivenessVerdict(
        String("not_exercised"), String(""), String("")
    )
