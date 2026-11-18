// SPDX-License-Identifier: GPL-3.0-or-later
//! Hook liveness over windowed record counts.
//!
//! A capture is complete only if its hooks were live. The copy
//! hooks attach before the lifecycle hooks, so cumulative
//! equalities false-fire at the edges: every map in the attach
//! gap leaves a TO copy with no map record. Only one-sided
//! inequalities over windows away from the edges are sound:
//!
//! - F = [T_a, T_d - GUARD] (forward: causes in F, effects over
//!   the whole run); R = [T_r, T_d - GUARD] (reverse: effects in
//!   R, causes over the whole run).
//! - E1 attempt->map, E2f map->copy, E2r copy->map, E3f
//!   unmap->copy, E3r copy->unmap.
//!
//! Bucketed counts include only whole buckets inside the
//! window: every left-hand side is under-counted, which can
//! only suppress a firing, never cause one. The tally runs
//! before the device filter and the latch gate; evaluation
//! happens once at close with the detach timestamp.

use crate::model::validate::format_u64;

/// Detach guard: windows end this far before detach.
pub const LIVENESS_GUARD_NS: u64 = 1_000_000_000;
/// Window bucket width in nanoseconds.
pub const LIVENESS_BUCKET_NS: u64 = 250_000_000;
/// Trailing buckets held in the ring.
pub const LIVENESS_BUCKETS: usize = 8;

const MAX_SPAN_NS: u64 = 2_592_000_000_000_000;

/// Saturating u64 add plus an overflow flag.
pub fn sat_add_u64(a: u64, b: u64) -> (u64, bool) {
    match a.checked_add(b) {
        Some(sum) => (sum, false),
        None => (u64::MAX, true),
    }
}

/// One window's record counts; saturates, never wraps.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LivenessCounts {
    /// Bounce attempts.
    pub attempts: u64,
    /// All maps.
    pub maps_all: u64,
    /// Successful maps.
    pub maps_ok: u64,
    /// Unmaps from the device.
    pub unmaps_from: u64,
    /// Syncs to the device.
    pub syncd_to: u64,
    /// Syncs from the device.
    pub syncc_from: u64,
    /// Copies to the device.
    pub copies_to: u64,
    /// Copies from the device.
    pub copies_from: u64,
    /// True once any counter saturated.
    pub saturated: bool,
}

impl LivenessCounts {
    fn inc(&mut self, v: u64) -> u64 {
        let (r, overflow) = sat_add_u64(v, 1);
        if overflow {
            self.saturated = true;
        }
        r
    }

    /// Bump the attempts count.
    pub fn bump_attempts(&mut self) {
        self.attempts = self.inc(self.attempts);
    }

    /// Bump the all-maps count.
    pub fn bump_maps_all(&mut self) {
        self.maps_all = self.inc(self.maps_all);
    }

    /// Bump the successful-maps count.
    pub fn bump_maps_ok(&mut self) {
        self.maps_ok = self.inc(self.maps_ok);
    }

    /// Bump the from-device unmap count.
    pub fn bump_unmaps_from(&mut self) {
        self.unmaps_from = self.inc(self.unmaps_from);
    }

    /// Bump the to-device sync count.
    pub fn bump_syncd_to(&mut self) {
        self.syncd_to = self.inc(self.syncd_to);
    }

    /// Bump the from-device sync count.
    pub fn bump_syncc_from(&mut self) {
        self.syncc_from = self.inc(self.syncc_from);
    }

    /// Bump the to-device copy count.
    pub fn bump_copies_to(&mut self) {
        self.copies_to = self.inc(self.copies_to);
    }

    /// Bump the from-device copy count.
    pub fn bump_copies_from(&mut self) {
        self.copies_from = self.inc(self.copies_from);
    }

    /// Fold other in, saturating; saturation propagates.
    pub fn combine(&mut self, other: &LivenessCounts) {
        let (r, mut sat) = sat_add_u64(self.attempts, other.attempts);
        self.attempts = r;
        let (r, s) = sat_add_u64(self.maps_all, other.maps_all);
        self.maps_all = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.maps_ok, other.maps_ok);
        self.maps_ok = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.unmaps_from, other.unmaps_from);
        self.unmaps_from = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.syncd_to, other.syncd_to);
        self.syncd_to = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.syncc_from, other.syncc_from);
        self.syncc_from = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.copies_to, other.copies_to);
        self.copies_to = r;
        sat = sat || s;
        let (r, s) = sat_add_u64(self.copies_from, other.copies_from);
        self.copies_from = r;
        sat = sat || s;
        self.saturated = self.saturated || other.saturated || sat;
    }
}

/// Per-record counts plus F/R window buckets.
///
/// `all` counts every record; seen_lc/seen_cp count every
/// lifecycle/copy record the tally observed, including
/// direction-skipped ones, so emitted-minus-seen is the record
/// loss. The ring holds the trailing buckets; win_f/win_r
/// accumulate folded buckets. A bucket leaving the ring folds
/// into win_f (eviction implies it ended over a second before
/// any detach the drain can reach, so it sits wholly inside F),
/// and into win_r when its start reaches t_r. Records before
/// t_a, past the span bound, or for an evicted bucket count in
/// `all` only: left-hand sides under-count, which suppresses
/// firing.
#[derive(Debug, Clone)]
pub struct LivenessTally {
    /// Attach timestamp: windows start here.
    pub t_a: u64,
    /// Reverse-window start.
    pub t_r: u64,
    /// Counts over every record.
    pub all: LivenessCounts,
    /// Folded forward-window counts.
    pub win_f: LivenessCounts,
    /// Folded reverse-window counts.
    pub win_r: LivenessCounts,
    ring: Vec<Bucket>,
    /// Lifecycle records observed.
    pub seen_lc: u64,
    /// Copy records observed.
    pub seen_cp: u64,
}

#[derive(Debug, Clone)]
struct Bucket {
    index: i64,
    counts: LivenessCounts,
}

impl Default for LivenessTally {
    fn default() -> Self {
        Self::new()
    }
}

impl LivenessTally {
    /// A tally with windows at zero (rebind with [`LivenessTally::retarget`]).
    pub fn new() -> Self {
        Self::with_windows(0, 0)
    }

    /// A tally with explicit window starts.
    pub fn with_windows(t_a: u64, t_r: u64) -> Self {
        let mut tally = Self {
            t_a,
            t_r,
            all: LivenessCounts::default(),
            win_f: LivenessCounts::default(),
            win_r: LivenessCounts::default(),
            ring: Vec::with_capacity(LIVENESS_BUCKETS),
            seen_lc: 0,
            seen_cp: 0,
        };
        tally.reset_ring();
        tally
    }

    fn reset_ring(&mut self) {
        self.ring.clear();
        for _ in 0..LIVENESS_BUCKETS {
            self.ring.push(Bucket {
                index: -1,
                counts: LivenessCounts::default(),
            });
        }
    }

    /// Bind the windows once readiness is stamped; resets.
    ///
    /// The collector calls this exactly once, after the arm,
    /// before any record is tallied; nothing is lost by the
    /// reset because nothing was tallied yet.
    pub fn retarget(&mut self, t_a: u64, t_r: u64) {
        self.t_a = t_a;
        self.t_r = t_r;
        self.all = LivenessCounts::default();
        self.win_f = LivenessCounts::default();
        self.win_r = LivenessCounts::default();
        self.reset_ring();
        self.seen_lc = 0;
        self.seen_cp = 0;
    }

    /// Ring slot for ts, evicting as needed; None is all-only.
    fn slot_for(&mut self, ts: u64) -> Option<usize> {
        if ts < self.t_a {
            return None;
        }
        let span = ts - self.t_a;
        if span > MAX_SPAN_NS {
            return None;
        }
        let b = (span / LIVENESS_BUCKET_NS) as i64;
        // b * BUCKET <= span cannot wrap but the end can; a wrapped end stays out of the ring.
        let start = self
            .t_a
            .wrapping_add((b as u64).wrapping_mul(LIVENESS_BUCKET_NS));
        let end = start.wrapping_add(LIVENESS_BUCKET_NS);
        if end < start {
            return None;
        }
        let s = (b as usize) % LIVENESS_BUCKETS;
        let cur = self.ring[s].index;
        if cur == b {
            return Some(s);
        }
        if cur > b {
            return None;
        }
        if cur >= 0 {
            let old = self.ring[s].counts.clone();
            let old_start = self
                .t_a
                .wrapping_add((cur as u64).wrapping_mul(LIVENESS_BUCKET_NS));
            self.win_f.combine(&old);
            if old_start >= self.t_r {
                self.win_r.combine(&old);
            }
        }
        self.ring[s].index = b;
        self.ring[s].counts = LivenessCounts::default();
        Some(s)
    }

    /// Note one bounce attempt at ts.
    pub fn note_attempt(&mut self, ts: u64) {
        self.all.bump_attempts();
        if let Some(s) = self.slot_for(ts) {
            self.ring[s].counts.bump_attempts();
        }
    }

    fn bump_seen_lc(&mut self) {
        let (r, overflow) = sat_add_u64(self.seen_lc, 1);
        self.seen_lc = r;
        if overflow {
            self.all.saturated = true;
        }
    }

    fn bump_seen_cp(&mut self) {
        let (r, overflow) = sat_add_u64(self.seen_cp, 1);
        self.seen_cp = r;
        if overflow {
            self.all.saturated = true;
        }
    }

    /// Note one map at ts.
    pub fn note_map(&mut self, ts: u64, ok: bool) {
        self.bump_seen_lc();
        self.all.bump_maps_all();
        if ok {
            self.all.bump_maps_ok();
        }
        if let Some(s) = self.slot_for(ts) {
            self.ring[s].counts.bump_maps_all();
            if ok {
                self.ring[s].counts.bump_maps_ok();
            }
        }
    }

    /// Note one unmap at ts.
    pub fn note_unmap(&mut self, ts: u64, dir: u16, skip_sync: bool) {
        self.bump_seen_lc();
        if skip_sync || (dir != 2 && dir != 0) {
            return;
        }
        self.all.bump_unmaps_from();
        if let Some(s) = self.slot_for(ts) {
            self.ring[s].counts.bump_unmaps_from();
        }
    }

    /// Note one sync at ts.
    pub fn note_sync(&mut self, ts: u64, to_device: bool, dir: u16) {
        let to = to_device && (dir == 1 || dir == 0);
        let frm = !to_device && (dir == 2 || dir == 0);
        self.bump_seen_cp();
        if !to && !frm {
            return;
        }
        if to {
            self.all.bump_syncd_to();
        } else {
            self.all.bump_syncc_from();
        }
        if let Some(s) = self.slot_for(ts) {
            if to {
                self.ring[s].counts.bump_syncd_to();
            } else {
                self.ring[s].counts.bump_syncc_from();
            }
        }
    }

    /// Note one copy at ts.
    pub fn note_copy(&mut self, ts: u64, dir: u16) {
        self.bump_seen_cp();
        if dir != 1 && dir != 2 {
            return;
        }
        if dir == 1 {
            self.all.bump_copies_to();
        } else {
            self.all.bump_copies_from();
        }
        if let Some(s) = self.slot_for(ts) {
            if dir == 1 {
                self.ring[s].counts.bump_copies_to();
            } else {
                self.ring[s].counts.bump_copies_from();
            }
        }
    }
}

/// Lifecycle/copy record loss; each known pins its own term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LivenessLoss {
    /// Lifecycle record loss.
    pub lc: u64,
    /// Copy record loss.
    pub cp: u64,
    /// Lifecycle loss is known.
    pub known_lc: bool,
    /// Copy loss is known.
    pub known_cp: bool,
}

/// state in hooks_silent/unverified/verified/not_exercised.
///
/// equation names the first violated or unverified equation
/// (attempt->map, map->copy, copy->map, unmap->copy,
/// copy->unmap), or the copy-without-lifecycle marker; detail
/// carries ``<lhs> > <rhs>`` when silent and ``<lhs> vs <rhs>``
/// when unverified. Both stay empty when nothing fired and
/// nothing stayed unverified. lc rolls up the lifecycle
/// equations (attempt->map, copy->map, copy->unmap) and cp the
/// copy equations (map->copy, unmap->copy), each silent over
/// unverified over verified over not exercised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessVerdict {
    /// Overall state.
    pub state: String,
    /// First violated or unverified equation.
    pub equation: String,
    /// Counter detail for the equation.
    pub detail: String,
    /// Lifecycle channel rollup.
    pub lc: String,
    /// Copy channel rollup.
    pub cp: String,
}

/// Judge the hook-liveness equations; precedence silent over unverified.
///
/// F = [t_a, t_d - GUARD], R = [t_r, t_d - GUARD]; a copy
/// without lifecycle stays unverified regardless of the
/// equations. Saturation and unknown loss turn an exercised
/// equation unverified, never silent.
fn sat_sum2(a: u64, b: u64) -> u64 {
    sat_add_u64(a, b).0
}

fn sat_sum4(a: u64, b: u64, c: u64, d: u64) -> u64 {
    sat_add_u64(sat_add_u64(a, b).0, sat_add_u64(c, d).0).0
}

/// Fold whole ring buckets into copies of win_f/win_r.
fn windowed(tally: &LivenessTally, t_c: u64) -> (LivenessCounts, LivenessCounts) {
    let mut win_f = tally.win_f.clone();
    let mut win_r = tally.win_r.clone();
    for bucket in &tally.ring {
        let b = bucket.index;
        if b < 0 {
            continue;
        }
        let start = tally
            .t_a
            .wrapping_add((b as u64).wrapping_mul(LIVENESS_BUCKET_NS));
        let end = start.wrapping_add(LIVENESS_BUCKET_NS);
        if end < start {
            continue;
        }
        if end > t_c {
            continue;
        }
        win_f.combine(&bucket.counts);
        if start >= tally.t_r {
            win_r.combine(&bucket.counts);
        }
    }
    (win_f, win_r)
}

fn judge(
    needs: bool,
    window_empty: bool,
    lhs: u64,
    rhs: u64,
    loss_known: bool,
    saturated: bool,
) -> &'static str {
    if !needs {
        return "not_exercised";
    }
    if window_empty {
        return "not_exercised";
    }
    if lhs == 0 {
        return "not_exercised";
    }
    if !loss_known {
        return "unverified";
    }
    if saturated {
        return "unverified";
    }
    if lhs > rhs {
        return "hooks_silent";
    }
    "verified"
}

/// One channel over its equations: silent over unverified over verified.
fn rollup_channel(a: &str, b: &str, c: &str) -> String {
    if a == "hooks_silent" || b == "hooks_silent" || c == "hooks_silent" {
        return "hooks_silent".to_string();
    }
    if a == "unverified" || b == "unverified" || c == "unverified" {
        return "unverified".to_string();
    }
    if a == "verified" || b == "verified" || c == "verified" {
        return "verified".to_string();
    }
    "not_exercised".to_string()
}

pub fn evaluate_liveness(
    tally: &LivenessTally,
    t_d: u64,
    has_attempt: bool,
    has_lifecycle: bool,
    has_copy: bool,
    loss: &LivenessLoss,
) -> LivenessVerdict {
    let t_c = t_d.saturating_sub(LIVENESS_GUARD_NS);
    let f_empty = t_c <= tally.t_a;
    let r_empty = t_c <= tally.t_r;
    let (win_f, win_r) = windowed(tally, t_c);
    let sat_f = win_f.saturated || tally.all.saturated;
    let sat_r = win_r.saturated || tally.all.saturated;
    let mut names: Vec<&str> = Vec::new();
    let mut states: Vec<&str> = Vec::new();
    let mut lhs_s: Vec<u64> = Vec::new();
    let mut rhs_s: Vec<u64> = Vec::new();
    // E1 attempt->map.
    let lhs = win_f.attempts;
    let rhs = sat_sum2(tally.all.maps_all, loss.lc);
    names.push("attempt->map");
    states.push(judge(
        has_attempt && has_lifecycle,
        f_empty,
        lhs,
        rhs,
        loss.known_lc,
        sat_f,
    ));
    lhs_s.push(lhs);
    rhs_s.push(rhs);
    // E2f map->copy; copy-only runs judge the sync-only terms.
    let lhs = sat_sum2(win_f.maps_ok, win_f.syncd_to);
    let rhs = sat_sum2(tally.all.copies_to, loss.cp);
    names.push("map->copy");
    states.push(judge(has_copy, f_empty, lhs, rhs, loss.known_cp, sat_f));
    lhs_s.push(lhs);
    rhs_s.push(rhs);
    // E2r copy->map.
    let lhs = win_r.copies_to;
    let rhs = sat_sum4(tally.all.maps_ok, tally.all.syncd_to, loss.lc, loss.cp);
    names.push("copy->map");
    states.push(judge(
        has_lifecycle && has_copy,
        r_empty,
        lhs,
        rhs,
        loss.known_lc && loss.known_cp,
        sat_r,
    ));
    lhs_s.push(lhs);
    rhs_s.push(rhs);
    // E3f unmap->copy; copy-only runs judge the sync-only terms.
    let lhs = sat_sum2(win_f.unmaps_from, win_f.syncc_from);
    let rhs = sat_sum2(tally.all.copies_from, loss.cp);
    names.push("unmap->copy");
    states.push(judge(has_copy, f_empty, lhs, rhs, loss.known_cp, sat_f));
    lhs_s.push(lhs);
    rhs_s.push(rhs);
    // E3r copy->unmap.
    let lhs = win_r.copies_from;
    let rhs = sat_sum4(
        tally.all.unmaps_from,
        tally.all.syncc_from,
        loss.lc,
        loss.cp,
    );
    names.push("copy->unmap");
    states.push(judge(
        has_lifecycle && has_copy,
        r_empty,
        lhs,
        rhs,
        loss.known_lc && loss.known_cp,
        sat_r,
    ));
    lhs_s.push(lhs);
    rhs_s.push(rhs);
    let lc = rollup_channel(states[0], states[2], states[4]);
    let cp = rollup_channel(states[1], states[3], "not_exercised");
    for i in 0..names.len() {
        if states[i] == "hooks_silent" {
            return LivenessVerdict {
                state: "hooks_silent".to_string(),
                equation: names[i].to_string(),
                detail: format!("{} > {}", format_u64(lhs_s[i]), format_u64(rhs_s[i])),
                lc: lc.clone(),
                cp: cp.clone(),
            };
        }
    }
    if has_copy && !has_lifecycle {
        // Copies without lifecycle stay unattributable even when held.
        return LivenessVerdict {
            state: "unverified".to_string(),
            equation: "copy liveness needs lifecycle".to_string(),
            detail: String::new(),
            lc: lc.clone(),
            cp: "unverified".to_string(),
        };
    }
    for i in 0..names.len() {
        if states[i] == "unverified" {
            return LivenessVerdict {
                state: "unverified".to_string(),
                equation: names[i].to_string(),
                detail: format!("{} vs {}", format_u64(lhs_s[i]), format_u64(rhs_s[i])),
                lc: lc.clone(),
                cp: cp.clone(),
            };
        }
    }
    if states.contains(&"verified") {
        return LivenessVerdict {
            state: "verified".to_string(),
            equation: String::new(),
            detail: String::new(),
            lc: lc.clone(),
            cp: cp.clone(),
        };
    }
    LivenessVerdict {
        state: "not_exercised".to_string(),
        equation: String::new(),
        detail: String::new(),
        lc,
        cp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tally() -> LivenessTally {
        LivenessTally::with_windows(1_000_000_000, 3_000_000_000)
    }

    fn loss(lc: u64, cp: u64) -> LivenessLoss {
        LivenessLoss {
            lc,
            cp,
            known_lc: true,
            known_cp: true,
        }
    }

    fn loss_split(lc: u64, cp: u64, known_lc: bool, known_cp: bool) -> LivenessLoss {
        LivenessLoss {
            lc,
            cp,
            known_lc,
            known_cp,
        }
    }

    fn td() -> u64 {
        10_000_000_000
    }

    #[test]
    fn dead_copy_hook_fires() {
        let mut t = tally();
        for _ in 0..100 {
            t.note_map(4_000_000_000, true);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "map->copy");
        assert_eq!(v.detail, "100 > 0");
    }

    #[test]
    fn dead_lifecycle_hook_fires() {
        let mut t = tally();
        for _ in 0..50 {
            t.note_attempt(4_000_000_000);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "attempt->map");
        assert_eq!(v.detail, "50 > 0");
    }

    #[test]
    fn dead_unmap_path_fires() {
        let mut t = tally();
        for _ in 0..40 {
            t.note_unmap(4_000_000_000, 2, false);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "unmap->copy");
        assert_eq!(v.detail, "40 > 0");
    }

    #[test]
    fn orphan_copies_fire_reverse() {
        let mut t = tally();
        for _ in 0..30 {
            t.note_copy(4_000_000_000, 1);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "copy->map");
        assert_eq!(v.detail, "30 > 0");
    }

    #[test]
    fn skip_sync_unmaps_excluded() {
        let mut t = tally();
        for _ in 0..40 {
            t.note_unmap(4_000_000_000, 2, true);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "not_exercised");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn loss_absorbs_deficit() {
        let mut t = tally();
        for _ in 0..100 {
            t.note_map(4_000_000_000, true);
        }
        for _ in 0..90 {
            t.note_copy(4_000_000_000, 1);
        }
        let ok = evaluate_liveness(&t, td(), true, true, true, &loss(0, 10));
        assert_eq!(ok.state, "verified");
        assert_eq!(ok.equation, "");
        assert_eq!(ok.detail, "");
        let bad = evaluate_liveness(&t, td(), true, true, true, &loss(0, 9));
        assert_eq!(bad.state, "hooks_silent");
        assert_eq!(bad.equation, "map->copy");
        assert_eq!(bad.detail, "100 > 99");
    }

    #[test]
    fn unknown_loss_unverified() {
        let mut t = tally();
        for _ in 0..100 {
            t.note_map(4_000_000_000, true);
        }
        for _ in 0..90 {
            t.note_copy(4_000_000_000, 1);
        }
        let v = evaluate_liveness(
            &t,
            td(),
            true,
            true,
            true,
            &LivenessLoss {
                lc: 0,
                cp: 10,
                known_lc: false,
                known_cp: false,
            },
        );
        assert_eq!(v.state, "unverified");
        assert_eq!(v.equation, "map->copy");
        assert_eq!(v.detail, "100 vs 100");
    }

    #[test]
    fn channel_rollup_forward_only() {
        let mut t = tally();
        for _ in 0..50 {
            t.note_map(4_000_000_000, true);
        }
        for _ in 0..50 {
            t.note_copy(2_000_000_000, 1);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "verified");
        assert_eq!(v.lc, "not_exercised");
        assert_eq!(v.cp, "verified");
    }

    #[test]
    fn channel_rollup_silent_copy() {
        let mut t = tally();
        for _ in 0..50 {
            t.note_map(4_000_000_000, true);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "map->copy");
        assert_eq!(v.lc, "not_exercised");
        assert_eq!(v.cp, "hooks_silent");
    }

    #[test]
    fn loss_known_per_channel() {
        let mut t = tally();
        for _ in 0..50 {
            t.note_attempt(4_000_000_000);
        }
        for _ in 0..50 {
            t.note_map(4_000_000_000, true);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss_split(0, 0, true, false));
        assert_eq!(v.state, "unverified");
        assert_eq!(v.equation, "map->copy");
        assert_eq!(v.detail, "50 vs 0");
    }

    #[test]
    fn edge_excess_inside_guard_never_fires() {
        let mut t = tally();
        for _ in 0..1000 {
            t.note_copy(2_000_000_000, 1);
        }
        for _ in 0..1000 {
            t.note_copy(9_500_000_000, 1);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "not_exercised");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn records_before_attach_ignored() {
        let mut t = tally();
        for i in 0..10u64 {
            let ts = 1001 + i;
            t.note_attempt(ts);
            t.note_map(ts, true);
            t.note_copy(ts, 1);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "not_exercised");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn copy_without_lifecycle_unverified() {
        let mut t = tally();
        for _ in 0..30 {
            t.note_copy(4_000_000_000, 1);
        }
        let v = evaluate_liveness(&t, td(), true, false, true, &loss(0, 0));
        assert_eq!(v.state, "unverified");
        assert_eq!(v.equation, "copy liveness needs lifecycle");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn copy_only_empty_unverified() {
        let t = tally();
        let v = evaluate_liveness(&t, td(), true, false, true, &loss(0, 0));
        assert_eq!(v.state, "unverified");
        assert_eq!(v.equation, "copy liveness needs lifecycle");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn copy_only_syncs_without_copies_silent() {
        let mut t = tally();
        for _ in 0..30 {
            t.note_sync(4_000_000_000, true, 1);
        }
        let v = evaluate_liveness(&t, td(), true, false, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "map->copy");
        assert_eq!(v.detail, "30 > 0");
    }

    #[test]
    fn copy_only_cpu_syncs_without_copies_silent() {
        let mut t = tally();
        for _ in 0..20 {
            t.note_sync(4_000_000_000, false, 2);
        }
        let v = evaluate_liveness(&t, td(), true, false, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "unmap->copy");
        assert_eq!(v.detail, "20 > 0");
    }

    #[test]
    fn omitted_records_counted_as_loss() {
        let mut t = tally();
        for _ in 0..100 {
            t.note_map(4_000_000_000, true);
        }
        for _ in 0..60 {
            t.note_copy(4_000_000_000, 1);
        }
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 40));
        assert_eq!(v.state, "verified");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn short_run_not_exercised() {
        let mut t = tally();
        for _ in 0..5 {
            t.note_attempt(2_000_000_000);
        }
        for _ in 0..10 {
            t.note_map(2_000_000_000, true);
        }
        for _ in 0..10 {
            t.note_copy(2_000_000_000, 1);
        }
        let v = evaluate_liveness(&t, 3_500_000_000, true, true, true, &loss(0, 0));
        assert_eq!(v.state, "verified");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn bucket_boundary_conservative() {
        let mut t = tally();
        for _ in 0..100 {
            t.note_map(9_050_000_000, true);
        }
        let v = evaluate_liveness(&t, 10_100_000_000, true, true, true, &loss(0, 0));
        assert_eq!(v.state, "not_exercised");
        assert_eq!(v.equation, "");
        assert_eq!(v.detail, "");
    }

    #[test]
    fn counter_saturation_unverified() {
        let exact = sat_add_u64(5, 6);
        assert_eq!(exact.0, 11);
        assert!(!exact.1);
        let capped = sat_add_u64(u64::MAX, 1);
        assert_eq!(capped.0, u64::MAX);
        assert!(capped.1);
        let mut t = tally();
        for _ in 0..50 {
            t.note_attempt(4_000_000_000);
        }
        t.all.saturated = true;
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "unverified");
        assert_eq!(v.equation, "attempt->map");
        assert_eq!(v.detail, "50 vs 0");
    }

    #[test]
    fn precedence_silent_over_unverified() {
        let mut t = tally();
        for _ in 0..50 {
            t.note_attempt(4_000_000_000);
        }
        for _ in 0..30 {
            t.note_copy(4_000_000_000, 1);
        }
        t.win_r.saturated = true;
        let v = evaluate_liveness(&t, td(), true, true, true, &loss(0, 0));
        assert_eq!(v.state, "hooks_silent");
        assert_eq!(v.equation, "attempt->map");
        assert_eq!(v.detail, "50 > 0");
    }

    #[test]
    fn liveness_constants() {
        assert_eq!(LIVENESS_GUARD_NS, 1_000_000_000);
        assert_eq!(LIVENESS_BUCKET_NS, 250_000_000);
        assert_eq!(LIVENESS_BUCKETS, 8);
    }

    #[test]
    fn retarget_rebinds_and_resets() {
        let mut t = tally();
        t.note_attempt(4_000_000_000);
        t.retarget(5_000_000_000, 6_000_000_000);
        assert_eq!(t.t_a, 5_000_000_000);
        assert_eq!(t.t_r, 6_000_000_000);
        assert_eq!(t.all.attempts, 0);
        assert_eq!(t.seen_lc, 0);
        assert_eq!(t.seen_cp, 0);
    }
}
