// SPDX-License-Identifier: GPL-3.0-or-later
//! Offline exposure lineage: qualified identities, lifetimes, cleanup duties.
//!
//! This module replays synthetic ledger rows into qualified
//! identities of the form `(token, generation)` and tracks
//! each identity through its lifecycle. A virtual id is a
//! session-local opaque handle, never a host address, and
//! the replay refuses to manufacture certainty: ambiguous
//! joins fail, failed reverts keep UNKNOWN state,
//! quarantine never counts as reuse, and capture end never
//! counts as teardown. Gaps bound or void the claims they
//! touch: a clock-domain change, a suspend gap, or a row
//! observed in a new clock domain bounds temporal claims,
//! while an event-loss gap keeps later observations as
//! separate samples until a fresh allocation
//! re-establishes identity. Certainty only moves down:
//! unknown lines never upgrade to bounded or known.
//!
//! Contract:
//!
//! * Normalization orders rows by `(seq, row_id)`; the
//!   first row wins a duplicated `row_id` and later copies
//!   are refused. Rows from another capture are refused,
//!   never matched.
//! * A reused address yields a NEW generation; the older
//!   generation keeps its own terminal state.
//! * A row joins only lines from its own source and
//!   object class. A refused allocation keeps the token
//!   ambiguous: later joins stay unlinked, since an
//!   untracked generation may exist.
//! * Alias mappings bind one canonical identity plus
//!   one generation per origin, so observations through
//!   an alias
//!   never double-count and never follow address reuse
//!   until the alias is rebound. An ambiguous or
//!   loss-sealed target refuses the alias. Invalidating a
//!   pin never erases the handle's recorded allocations:
//!   a reuse through a live binding keeps later rows at
//!   the handle ambiguous while both lines stay open, and
//!   the handle refuses rebinding while it records a
//!   tracked allocation.
//! * Rows that share an `atom` marker commit only as a
//!   unit: when any leg cannot join, every leg resolves
//!   UNKNOWN and the legs stay separate samples. A group
//!   interleaved with other rows is refused outright, and
//!   output always follows ledger order. Gap evidence
//!   still records at its ledger position: rollback
//!   re-derives each gap leg against proved state and
//!   keeps tentative seals and bounds only for lines the
//!   group did not create, while a refused group's gap
//!   rows record once replay passes them. Continuity past
//!   a gap stays unproved even when the group as a unit is
//!   unproved, and a fresh allocation never inherits a gap
//!   that struck a rolled-back object.
//! * Lineage is bounded per source and per generation.
//!   Past either bound the replay refuses the new
//!   identity instead of wrapping or growing without
//!   limit.
//! * Baseline reconciliation is explicit and read-only: it
//!   reports confirmed, mismatched, missing, and
//!   unconfirmed entries without changing the replay.
//! * The replay reports identities and lifecycle states
//!   only; it offers no byte aggregates keyed by virtual
//!   id, since virtual handles never identify host bytes.
//!
//! Frozen labels transcribed from exposure catalog
//! version 0.1.1: lifecycle statuses `created`, `live`,
//! `released`, `quarantined`, `unknown`; object classes
//! `queue`, `buffer`, `channel`, `mapping`, `heap_object`;
//! clock domains `guest_monotonic_active`,
//! `guest_boottime_elapsed`, `external_trusted_interval`.
//!
//! This file is intentionally dependency-free (`std` only)
//! so the offline replay stays small and reviewable.

use std::collections::{BTreeMap, BTreeSet};

/// Default cap on open identities per origin source.
pub const DEFAULT_MAX_OPEN_PER_SOURCE: usize = 4096;

/// Lifecycle states that still accept observations.
const OPEN_STATUSES: &[&str] = &["created", "live"];

/// Alias-chain hop cap; longer chains refuse instead of looping.
const MAX_ALIAS_HOPS: usize = 64;

/// Bounds for one replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayConfig {
    /// Highest generation a token may reach; further reuse refuses.
    pub max_generation: u64,
    /// Highest count of open identities per origin source.
    pub max_open_per_source: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            max_generation: u64::MAX,
            max_open_per_source: DEFAULT_MAX_OPEN_PER_SOURCE,
        }
    }
}

/// One synthetic ledger row: an allocation, conversion, or
/// lifetime observation over a session-local virtual id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRow {
    /// Session-unique row handle; first copy wins.
    pub row_id: String,
    /// Capture the row belongs to.
    pub capture_id: String,
    /// Catalog source entry that observed the row.
    pub source_id: String,
    /// Frozen object class.
    pub object_class: String,
    /// Opaque session-local handle, never a host address.
    pub virtual_id: String,
    /// Row event; see the module contract for the set.
    pub event: String,
    /// Ledger order key.
    pub seq: u64,
    /// Clock domain of the observation.
    pub clock_domain: String,
    /// Alias target for `alias` rows, otherwise absent.
    pub alias_of: Option<String>,
    /// Atomic group marker; shared markers commit as a unit.
    pub atom: Option<String>,
}

/// One qualified identity: canonical token plus generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QualifiedIdentity {
    /// Canonical token after alias resolution.
    pub token: String,
    /// Generation; reused addresses start a new one.
    pub generation: u64,
}

/// One admitted row after replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRow {
    /// Row handle from the ledger.
    pub row_id: String,
    /// Ledger order key from the row.
    pub seq: u64,
    /// Joined identity, or `None` when no join was proved.
    pub identity: Option<QualifiedIdentity>,
    /// Lifecycle status after this row.
    pub status: String,
    /// `known`, `bounded`, or `unknown`.
    pub certainty: String,
    /// Human note; callers match on structure, never text.
    pub note: String,
}

/// One lineage object: a single `(token, generation)` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineageObject {
    /// Canonical token.
    pub token: String,
    /// Generation; unlinked samples carry 0.
    pub generation: u64,
    /// Source of the allocating row.
    pub source_id: String,
    /// Frozen object class.
    pub object_class: String,
    /// Current lifecycle status.
    pub status: String,
    /// `known`, `bounded`, or `unknown`.
    pub certainty: String,
    /// First sequence touching this line.
    pub first_seq: u64,
    /// Latest sequence touching this line.
    pub last_seq: u64,
    /// Row handles that form this line, in replay order.
    pub evidence: Vec<String>,
    /// False for unlinked post-gap samples.
    pub linked: bool,
}

/// Full replay outcome for one capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayOutcome {
    /// Capture that was replayed.
    pub capture_id: String,
    /// Admitted rows in ledger order.
    pub resolved: Vec<ResolvedRow>,
    /// Lineage lines sorted by `(token, generation, first_seq)`.
    pub objects: Vec<LineageObject>,
    /// Admitted rows whose join failed, in ledger order.
    pub failed_joins: Vec<String>,
    /// Rows refused for belonging to another capture.
    pub refused_cross_capture: usize,
    /// Refused duplicate row handles, in replay order.
    pub duplicate_rows: Vec<String>,
    /// Allocations refused past the generation cap.
    pub overflow_refusals: usize,
    /// Allocations refused past the per-source open cap.
    pub bound_refusals: usize,
    /// Unlinked samples (generation 0 lines).
    pub unlinked_samples: usize,
}

/// One declared baseline expectation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaselineEntry {
    /// Canonical token the declaration names.
    pub virtual_id: String,
    /// Generation the declaration names.
    pub generation: u64,
    /// Lifecycle status the declaration expects.
    pub status: String,
}

/// Explicit baseline reconciliation; read-only over the replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    /// Entries whose observed state matches, as `token#generation`.
    pub confirmed: Vec<String>,
    /// Entries observed in a different state.
    pub status_mismatch: Vec<String>,
    /// Entries with no observed line.
    pub missing_observation: Vec<String>,
    /// Observed linked lines with no entry.
    pub unconfirmed_observed: Vec<String>,
}

/// Count of distinct linked identities. Aliases resolve to
/// the canonical line and unlinked samples stay outside the
/// count, so neither inflates the total.
pub fn distinct_known_objects(outcome: &ReplayOutcome) -> usize {
    outcome.objects.iter().filter(|obj| obj.linked).count()
}

#[derive(Debug, Clone)]
struct ObjState {
    source_id: String,
    object_class: String,
    clock_domain: String,
    status: String,
    certainty: String,
    first_seq: u64,
    last_seq: u64,
    evidence: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct State {
    linked: BTreeMap<(String, u64), ObjState>,
    latest: BTreeMap<String, u64>,
    /// Alias bindings: (alias, source, class) to
    /// (canonical token, generation). A binding pins
    /// one exact generation for its own origin, so an
    /// alias never follows address reuse until it is
    /// explicitly rebound, and one source never
    /// overwrites another source's binding.
    alias: BTreeMap<(String, String, String), (String, u64)>,
    /// Handle provenance of allocations: (handle,
    /// source, class) to the (canonical token,
    /// generation) lines recorded through that handle
    /// under a different token. A reuse through a live
    /// binding records the new generation under the
    /// canonical token, but the allocation was made at
    /// the handle, so later rows at the handle still see
    /// it after the pin is invalidated.
    handle_alloc: BTreeMap<(String, String, String), Vec<(String, u64)>>,
    /// Pins invalidated by allocation: (handle, source,
    /// class) to the (canonical token, generation) the
    /// pin last bound. A reuse through a live binding
    /// leaves both the old pinned generation and the new
    /// allocation plausible at the handle, so the old pin
    /// answers no later rows alone but keeps them
    /// ambiguous while its line stays open.
    dropped_pin: BTreeMap<(String, String, String), (String, u64)>,
    /// Lines with temporally bounded claims, keyed per
    /// generation and origin: a gap observed through one
    /// source and class never bounds another origin's
    /// claims, and a fresh generation starts its own
    /// temporal line without clearing older ones.
    temporal_bounded: BTreeSet<(String, u64, String, String)>,
    sealed: BTreeSet<(String, u64)>,
    samples: Vec<(String, ObjState)>,
}

/// Refusal events survive group rollback: a refused row
/// stays refused even when its group rolls back, and a
/// refused allocation keeps later joins to its token
/// ambiguous, since an untracked generation may exist
/// beside any tracked line.
#[derive(Debug, Clone, Default)]
struct Refusals {
    overflow: usize,
    bound: usize,
    /// Refused allocations, keyed per origin: a refusal in
    /// one source and class never blocks another origin's
    /// joins.
    refused_alloc: BTreeSet<(String, String, String)>,
}

fn is_open(status: &str) -> bool {
    OPEN_STATUSES.contains(&status)
}

/// Follow the alias map to the canonical token,
/// staying inside the row's own origin: a binding from
/// another source or class never redirects this lookup.
fn resolve(state: &State, row: &LedgerRow, virtual_id: &str) -> Option<String> {
    let mut current = virtual_id.to_string();
    let mut seen = BTreeSet::new();
    seen.insert(current.clone());
    for _ in 0..MAX_ALIAS_HOPS {
        match state
            .alias
            .get(&alias_key(&current, row))
            .map(|(token, _)| token.clone())
        {
            None => return Some(current),
            Some(next) => {
                if !seen.insert(next.clone()) {
                    return None;
                }
                current = next;
            }
        }
    }
    None
}

/// Token an allocation row names: a handle bound in
/// the row's own origin to a still-open unsealed line
/// continues that address's reuse chain through the
/// canonical token; a handle bound to a closed or
/// loss-sealed line, bound only in another origin, or
/// bound to no line, names its own fresh identity
/// instead of following the stale binding.
fn allocation_token(state: &State, row: &LedgerRow, handle: &str) -> Option<String> {
    match state.alias.get(&alias_key(handle, row)) {
        Some((token, generation)) => {
            let key = (token.clone(), *generation);
            let reusable = state
                .linked
                .get(&key)
                .map(|obj| is_open(obj.status.as_str()))
                .unwrap_or(false)
                && !state.sealed.contains(&key);
            if reusable {
                resolve(state, row, handle)
            } else {
                Some(handle.to_string())
            }
        }
        None => Some(handle.to_string()),
    }
}

/// Open generations of one canonical token, oldest first.
fn open_generations(state: &State, token: &str) -> Vec<u64> {
    let mut gens: Vec<u64> = state
        .linked
        .iter()
        .filter(|((name, _), obj)| name == token && is_open(obj.status.as_str()))
        .map(|((_, generation), _)| *generation)
        .collect();
    gens.sort();
    gens.dedup();
    gens
}

/// Certainty recorded by a state-changing row: a
/// temporally bounded line bounds the claim in the
/// row's own origin, and an unknown or bounded line
/// never upgrades.
fn event_certainty(
    state: &State,
    row: &LedgerRow,
    canonical: &str,
    generation: u64,
    line_certainty: &str,
) -> String {
    if line_certainty == "unknown" {
        return "unknown".to_string();
    }
    if state
        .temporal_bounded
        .contains(&bound_key(canonical, generation, row))
    {
        return "bounded".to_string();
    }
    line_certainty.to_string()
}

struct Applied {
    resolved: ResolvedRow,
    failed: bool,
}

fn unknown_row(row: &LedgerRow, note: String) -> ResolvedRow {
    ResolvedRow {
        row_id: row.row_id.clone(),
        seq: row.seq,
        identity: None,
        status: "unknown".to_string(),
        certainty: "unknown".to_string(),
        note,
    }
}

fn failed(row: &LedgerRow, note: String) -> Applied {
    Applied {
        resolved: unknown_row(row, note),
        failed: true,
    }
}

/// A row joins only lines from the same origin: token
/// equality alone never crosses sources or object
/// classes.
fn same_origin(obj: &ObjState, row: &LedgerRow) -> bool {
    obj.source_id == row.source_id && obj.object_class == row.object_class
}

/// Per-generation, per-origin key for gap state: the
/// canonical token and generation plus the row's own
/// source and object class.
fn bound_key(canonical: &str, generation: u64, row: &LedgerRow) -> (String, u64, String, String) {
    (
        canonical.to_string(),
        generation,
        row.source_id.clone(),
        row.object_class.clone(),
    )
}

/// Bound the lines a gap row can see in the row's
/// own origin: a row addressed through a pinned alias
/// bounds only that generation, so a suspend or clock
/// marker never bounds a newer generation the pin does
/// not address; an unpinned row bounds every
/// same-origin line its handle denotes, including
/// generations recorded through the handle under another
/// token and the generation an invalidated pin last
/// bound. Other origins' lines stay unaffected either way.
fn bound_token_lines(state: &mut State, row: &LedgerRow, canonical: &str, pinned: Option<u64>) {
    let bound: Vec<(String, u64)> = match pinned {
        Some(generation) => state
            .linked
            .get(&(canonical.to_string(), generation))
            .filter(|obj| same_origin(obj, row))
            .map(|_| vec![(canonical.to_string(), generation)])
            .unwrap_or_default(),
        None => {
            let mut bound: Vec<(String, u64)> = state
                .linked
                .iter()
                .filter(|((name, _), obj)| name == canonical && same_origin(obj, row))
                .map(|((name, generation), _)| (name.clone(), *generation))
                .collect();
            bound.extend(denoted_extras(state, row, canonical));
            bound.sort();
            bound.dedup();
            bound
        }
    };
    for (token, generation) in bound {
        state
            .temporal_bounded
            .insert(bound_key(&token, generation, row));
    }
}

/// Per-origin key for allocation refusals: the refused
/// token plus the refusing row's source and class.
fn refusal_key(token: &str, row: &LedgerRow) -> (String, String, String) {
    (
        token.to_string(),
        row.source_id.clone(),
        row.object_class.clone(),
    )
}

/// Per-origin key for alias bindings: the alias handle
/// plus the row's own source and object class.
fn alias_key(handle: &str, row: &LedgerRow) -> (String, String, String) {
    (
        handle.to_string(),
        row.source_id.clone(),
        row.object_class.clone(),
    )
}

/// Lines one unpinned handle denotes beyond its own
/// token's lines: generations recorded through the handle
/// under another token, plus the generation an invalidated
/// pin last bound. Only lines still tracked in the row's
/// own origin count; callers apply their own status and
/// seal filters. Sorted and deduplicated.
fn denoted_extras(state: &State, row: &LedgerRow, handle: &str) -> Vec<(String, u64)> {
    let mut lines: Vec<(String, u64)> = Vec::new();
    if let Some(recorded) = state.handle_alloc.get(&alias_key(handle, row)) {
        for (token, generation) in recorded {
            if state
                .linked
                .get(&(token.clone(), *generation))
                .map(|obj| same_origin(obj, row))
                .unwrap_or(false)
            {
                lines.push((token.clone(), *generation));
            }
        }
    }
    if let Some((token, generation)) = state.dropped_pin.get(&alias_key(handle, row))
        && state
            .linked
            .get(&(token.clone(), *generation))
            .map(|obj| same_origin(obj, row))
            .unwrap_or(false)
    {
        lines.push((token.clone(), *generation));
    }
    lines.sort();
    lines.dedup();
    lines
}

/// Compare a row's clock domain against the generation it
/// joined or shows: a mismatch crosses a clock-domain
/// change, so the token's later claims in this origin stay
/// bounded. Older or newer generations never mask the
/// mismatch, and other origins stay unaffected.
fn note_domain(state: &mut State, row: &LedgerRow, canonical: &str, generation: u64) {
    let shares = state
        .linked
        .get(&(canonical.to_string(), generation))
        .map(|obj| obj.clock_domain == row.clock_domain)
        .unwrap_or(false);
    if !shares {
        state
            .temporal_bounded
            .insert(bound_key(canonical, generation, row));
    }
}

/// Whether any handle on the alias path from `start` to
/// the terminal token carries a refused allocation in the
/// row's origin: a refusal stored under an intermediate
/// handle poisons every lookup that goes through it,
/// since an untracked generation may sit beside the
/// pinned one. The walk stays inside the row's own
/// origin, like every other alias lookup.
fn refused_on_path(
    state: &State,
    refusals: &Refusals,
    row: &LedgerRow,
    start: &str,
    terminal: &str,
) -> bool {
    let mut probe = start.to_string();
    for _ in 0..=MAX_ALIAS_HOPS {
        if refusals.refused_alloc.contains(&refusal_key(&probe, row)) {
            return true;
        }
        if probe == terminal {
            break;
        }
        match state
            .alias
            .get(&alias_key(&probe, row))
            .map(|(token, _)| token.clone())
        {
            Some(next) => probe = next,
            None => break,
        }
    }
    refusals.refused_alloc.contains(&refusal_key(terminal, row))
}

/// Generations one lookup may join: open lines, plus
/// restoration-uncertain lines when the caller allows
/// them, restricted to the row's own origin and
/// excluding loss-sealed lines. Oldest first.
fn joinable(state: &State, row: &LedgerRow, token: &str, unknown_ok: bool) -> Vec<u64> {
    let mut gens: Vec<u64> = state
        .linked
        .iter()
        .filter(|((name, generation), obj)| {
            name == token
                && (is_open(obj.status.as_str()) || (unknown_ok && obj.status == "unknown"))
                && !state.sealed.contains(&(token.to_string(), *generation))
                && same_origin(obj, row)
        })
        .map(|((_, generation), _)| *generation)
        .collect();
    gens.sort();
    gens.dedup();
    gens
}

/// Restoration-uncertain lines that keep an ordinary
/// join ambiguous: unknown-status lines of the row's own
/// origin that no loss gap sealed. No lifetime event
/// ended them, so one may still answer the row beside
/// any open line. Sealed lines keep their last state and
/// exclude themselves.
fn has_unsealed_unknown(state: &State, row: &LedgerRow, token: &str) -> bool {
    state.linked.iter().any(|((name, generation), obj)| {
        name == token
            && obj.status == "unknown"
            && !state.sealed.contains(&(token.to_string(), *generation))
            && same_origin(obj, row)
    })
}

/// Restoration-uncertain lines one handle denotes beyond
/// its own token's lines: generations recorded through
/// the handle under another token, or the generation an
/// invalidated pin last bound, that no loss gap sealed.
/// No lifetime event ended them, so one may still answer
/// the row beside any open line, exactly like an
/// uncertain line of the requested token.
fn has_denoted_uncertain_extra(state: &State, row: &LedgerRow, handle: &str) -> bool {
    denoted_extras(state, row, handle)
        .iter()
        .any(|(token, generation)| {
            let key = (token.clone(), *generation);
            !state.sealed.contains(&key)
                && state
                    .linked
                    .get(&key)
                    .map(|obj| obj.status == "unknown")
                    .unwrap_or(false)
        })
}

/// Shared lookup for state-changing rows and alias binds:
/// exactly one joinable line must exist. An unpinned handle
/// denotes its own token's lines plus the generations it
/// recorded under another token and the generation an
/// invalidated pin last bound, so a reuse through a live
/// binding keeps later rows at the handle ambiguous while
/// both lines stay open. A line sealed by
/// a loss gap keeps its last state but accepts no new
/// joins, so a fresh post-loss allocation stays
/// unambiguous; a refused allocation keeps the token
/// ambiguous, since an untracked generation may exist
/// beside any tracked line. A restoration-uncertain line
/// beside the one open candidate keeps the join
/// ambiguous too, since no lifetime event ended it —
/// including an uncertain line the handle denotes through
/// a recorded allocation or an invalidated pin.
fn join(
    state: &State,
    refusals: &Refusals,
    row: &LedgerRow,
    token: &str,
    pinned: Option<u64>,
    unknown_ok: bool,
) -> Result<(String, u64), String> {
    if let Some(generation) = pinned {
        if refused_on_path(state, refusals, row, &row.virtual_id, token) {
            return Err(format!(
                "ambiguous join for '{token}': a refused allocation may hide \
                 another generation beside pinned generation {generation}"
            ));
        }
        return join_pinned(state, row, token, generation, unknown_ok);
    }
    let mut candidates: Vec<(String, u64)> = joinable(state, row, token, unknown_ok)
        .into_iter()
        .map(|generation| (token.to_string(), generation))
        .collect();
    for (extra_token, extra_generation) in denoted_extras(state, row, token) {
        let key = (extra_token.clone(), extra_generation);
        let usable = state
            .linked
            .get(&key)
            .map(|obj| {
                (is_open(obj.status.as_str()) || (unknown_ok && obj.status == "unknown"))
                    && !state.sealed.contains(&key)
            })
            .unwrap_or(false);
        if usable {
            candidates.push((extra_token, extra_generation));
        }
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() > 1 {
        return Err(format!(
            "ambiguous join: {} joinable generations for '{token}'",
            candidates.len()
        ));
    }
    if let Some((joined_token, generation)) = candidates.into_iter().next() {
        let refused = refusals.refused_alloc.contains(&refusal_key(token, row))
            || (joined_token != token
                && refusals
                    .refused_alloc
                    .contains(&refusal_key(&joined_token, row)));
        if refused {
            return Err(format!(
                "ambiguous join for '{token}': a refused allocation may hide \
                 another generation beside open generation {generation}"
            ));
        }
        let uncertain = has_unsealed_unknown(state, row, token)
            || (joined_token != token && has_unsealed_unknown(state, row, &joined_token))
            || has_denoted_uncertain_extra(state, row, token);
        if !unknown_ok && uncertain {
            return Err(format!(
                "ambiguous join for '{token}': a restoration-uncertain line may \
                 still answer beside open generation {generation}"
            ));
        }
        return Ok((joined_token, generation));
    }
    if !state.latest.contains_key(token) {
        return Err(format!("no allocated identity for '{token}'"));
    }
    let sealed_open = open_generations(state, token).iter().any(|generation| {
        let key = (token.to_string(), *generation);
        state.sealed.contains(&key)
            && state
                .linked
                .get(&key)
                .map(|obj| same_origin(obj, row))
                .unwrap_or(false)
    });
    if sealed_open {
        return Err(format!(
            "event-loss gap precedes row '{}'; observation stays a separate sample",
            row.row_id
        ));
    }
    let foreign_open = open_generations(state, token).iter().any(|generation| {
        state
            .linked
            .get(&(token.to_string(), *generation))
            .map(|obj| !same_origin(obj, row))
            .unwrap_or(false)
    });
    if foreign_open {
        return Err(format!(
            "no open generation for '{token}' from source '{}' class '{}'",
            row.source_id, row.object_class
        ));
    }
    Err(format!("no open generation for '{token}'"))
}

/// A lookup through an alias binding: the binding pins one
/// exact generation, so only that line may join. A binding
/// left behind by release, reuse, or a loss gap stays
/// unlinked until the alias is explicitly rebound.
fn join_pinned(
    state: &State,
    row: &LedgerRow,
    token: &str,
    generation: u64,
    unknown_ok: bool,
) -> Result<(String, u64), String> {
    let key = (token.to_string(), generation);
    let obj = match state.linked.get(&key) {
        Some(obj) => obj,
        None => {
            return Err(format!(
                "alias binding to '{token}' generation {generation} names no tracked line"
            ));
        }
    };
    if state.sealed.contains(&key) {
        return Err(format!(
            "event-loss gap precedes row '{}'; observation stays a separate sample",
            row.row_id
        ));
    }
    if !is_open(obj.status.as_str()) && !(unknown_ok && obj.status == "unknown") {
        return Err(format!(
            "alias binding to '{token}' generation {generation} is no longer open; \
             rebind the alias before joining"
        ));
    }
    if !same_origin(obj, row) {
        return Err(format!(
            "no open generation for '{token}' from source '{}' class '{}'",
            row.source_id, row.object_class
        ));
    }
    Ok((token.to_string(), generation))
}

/// Certainty shown for one line: a loss-sealed line shows
/// unknown, an unknown line never upgrades, and a
/// temporally bounded token shows bounded at best in the
/// row's own origin.
fn shown_certainty(
    state: &State,
    row: &LedgerRow,
    token: &str,
    generation: u64,
    line_certainty: &str,
) -> String {
    if state.sealed.contains(&(token.to_string(), generation)) {
        return "unknown".to_string();
    }
    if line_certainty == "unknown" {
        return "unknown".to_string();
    }
    if state
        .temporal_bounded
        .contains(&bound_key(token, generation, row))
    {
        return "bounded".to_string();
    }
    line_certainty.to_string()
}

/// Identity shown by informational rows. An alias
/// binding shows its pinned generation; otherwise exactly
/// one joinable line must exist, else the row shows no
/// identity. The candidates are the same lines an
/// ordinary join could take: the handle's own token plus
/// the generations it recorded under another token and
/// the generation an invalidated pin last bound, even
/// when the handle never allocated its own token. A
/// restoration-uncertain line beside that one
/// candidate keeps the display ambiguous, as with ordinary
/// joins, and a refused allocation of the shown token
/// hides the display, since an untracked generation may
/// sit beside it. One sealed line shows its last state with
/// unknown certainty, and an unambiguous closed line
/// shows its terminal state; ambiguity never shows an
/// identity.
fn shown_identity(
    state: &mut State,
    refusals: &Refusals,
    row: &LedgerRow,
    token: &str,
    pinned: Option<u64>,
) -> Option<(QualifiedIdentity, String, String)> {
    // A handle with no allocation of its own still
    // denotes the generations it recorded under another
    // token and the generation an invalidated pin last
    // bound: consult those before giving up, as ordinary
    // joins do.
    if !state.latest.contains_key(token) && denoted_extras(state, row, token).is_empty() {
        return None;
    }
    if refusals.refused_alloc.contains(&refusal_key(token, row)) {
        return None;
    }
    if let Some(generation) = pinned {
        if refused_on_path(state, refusals, row, &row.virtual_id, token) {
            return None;
        }
        let (status, line_certainty) = match state.linked.get(&(token.to_string(), generation)) {
            Some(obj) if same_origin(obj, row) => (obj.status.clone(), obj.certainty.clone()),
            _ => return None,
        };
        note_domain(state, row, token, generation);
        return Some((
            QualifiedIdentity {
                token: token.to_string(),
                generation,
            },
            status,
            shown_certainty(state, row, token, generation, &line_certainty),
        ));
    }
    // The same denoted lines as ordinary joins: the
    // handle's own token plus the generations it recorded
    // under another token and the generation an
    // invalidated pin last bound. Informational rows show
    // only what a join could prove.
    let mut candidates: Vec<(String, u64)> = joinable(state, row, token, false)
        .into_iter()
        .map(|generation| (token.to_string(), generation))
        .collect();
    for (extra_token, extra_generation) in denoted_extras(state, row, token) {
        let key = (extra_token.clone(), extra_generation);
        let usable = state
            .linked
            .get(&key)
            .map(|obj| is_open(obj.status.as_str()) && !state.sealed.contains(&key))
            .unwrap_or(false);
        if usable {
            candidates.push((extra_token, extra_generation));
        }
    }
    candidates.sort();
    candidates.dedup();
    if candidates.len() > 1 {
        return None;
    }
    if let Some((shown_token, generation)) = candidates.into_iter().next() {
        // The same restoration-uncertain guard as ordinary
        // joins: an unsealed unknown-status line may still
        // answer beside this candidate, so the row shows no
        // identity rather than select a generation.
        let uncertain = has_unsealed_unknown(state, row, token)
            || (shown_token != token && has_unsealed_unknown(state, row, &shown_token))
            || has_denoted_uncertain_extra(state, row, token);
        if uncertain {
            return None;
        }
        // The same refusal check as ordinary joins: a
        // refused allocation of the shown token may hide
        // an untracked generation beside it, so the row
        // shows no identity rather than display past the
        // refusal.
        if shown_token != token
            && refusals
                .refused_alloc
                .contains(&refusal_key(&shown_token, row))
        {
            return None;
        }
        let (status, line_certainty) = {
            let obj = state.linked.get(&(shown_token.clone(), generation))?;
            (obj.status.clone(), obj.certainty.clone())
        };
        note_domain(state, row, &shown_token, generation);
        return Some((
            QualifiedIdentity {
                token: shown_token.clone(),
                generation,
            },
            status,
            shown_certainty(state, row, &shown_token, generation, &line_certainty),
        ));
    }
    // No joinable line: one sealed line shows its last
    // state as unknown, but two sealed lines could each
    // match, so the row shows no identity rather than
    // select a generation. Sealed restoration-uncertain
    // lines count beside sealed open lines; an unambiguous
    // same-origin closed line shows its terminal state.
    // Recorded and invalidated-pin lines count here too, as
    // with the joinable candidates above.
    let mut sealed: Vec<(String, u64)> = state
        .linked
        .iter()
        .filter(|((name, generation), obj)| {
            name == token
                && (is_open(obj.status.as_str()) || obj.status == "unknown")
                && state.sealed.contains(&(token.to_string(), *generation))
                && same_origin(obj, row)
        })
        .map(|((name, generation), _)| (name.clone(), *generation))
        .collect();
    for (extra_token, extra_generation) in denoted_extras(state, row, token) {
        let key = (extra_token.clone(), extra_generation);
        let usable = state
            .linked
            .get(&key)
            .map(|obj| {
                (is_open(obj.status.as_str()) || obj.status == "unknown")
                    && state.sealed.contains(&key)
            })
            .unwrap_or(false);
        if usable {
            sealed.push((extra_token, extra_generation));
        }
    }
    sealed.sort();
    sealed.dedup();
    if sealed.len() > 1 {
        return None;
    }
    // The same restoration-uncertain guard as the open
    // candidate above: when one sealed line could show,
    // an unsealed unknown-status line may still answer
    // beside it, so the row shows no identity rather
    // than select the older sealed generation.
    if sealed.len() == 1 {
        let (shown_token, _) = &sealed[0];
        let uncertain = has_unsealed_unknown(state, row, token)
            || (shown_token != token && has_unsealed_unknown(state, row, shown_token))
            || has_denoted_uncertain_extra(state, row, token);
        if uncertain {
            return None;
        }
    }
    if let Some((shown_token, generation)) = sealed.pop() {
        if shown_token != token
            && refusals
                .refused_alloc
                .contains(&refusal_key(&shown_token, row))
        {
            return None;
        }
        let status = {
            let obj = state.linked.get(&(shown_token.clone(), generation))?;
            obj.status.clone()
        };
        note_domain(state, row, &shown_token, generation);
        return Some((
            QualifiedIdentity {
                token: shown_token.clone(),
                generation,
            },
            status,
            "unknown".to_string(),
        ));
    }
    let mut closed: Vec<(String, u64)> = state
        .linked
        .iter()
        .filter(|((name, _), obj)| {
            name == token && same_origin(obj, row) && !is_open(obj.status.as_str())
        })
        .map(|((name, generation), _)| (name.clone(), *generation))
        .collect();
    for (extra_token, extra_generation) in denoted_extras(state, row, token) {
        let key = (extra_token.clone(), extra_generation);
        let usable = state
            .linked
            .get(&key)
            .map(|obj| !is_open(obj.status.as_str()))
            .unwrap_or(false);
        if usable {
            closed.push((extra_token, extra_generation));
        }
    }
    closed.sort();
    closed.dedup();
    // Like the sealed fallback above: two terminal
    // generations could each match, so the row shows no
    // identity rather than select the highest one.
    if closed.len() > 1 {
        return None;
    }
    let (shown_token, generation) = closed.pop()?;
    if shown_token != token
        && refusals
            .refused_alloc
            .contains(&refusal_key(&shown_token, row))
    {
        return None;
    }
    let (status, line_certainty) = {
        let obj = state.linked.get(&(shown_token.clone(), generation))?;
        (obj.status.clone(), obj.certainty.clone())
    };
    note_domain(state, row, &shown_token, generation);
    Some((
        QualifiedIdentity {
            token: shown_token.clone(),
            generation,
        },
        status,
        shown_certainty(state, row, &shown_token, generation, &line_certainty),
    ))
}

/// Record only the gap evidence of one gap row —
/// the loss seal or temporal bound — without displaying
/// any identity. Rollback and refused-group paths reuse
/// this so a gap row records its discontinuity even when
/// its own leg never applied or its group never proved.
/// Addressing mirrors `apply_row`: aliases resolve first
/// and a looping chain records nothing, exactly as a
/// replayed row would. Other events are a no-op.
fn record_gap(state: &mut State, row: &LedgerRow) {
    match row.event.as_str() {
        "loss_gap" | "suspend_gap" | "clock_change" => {}
        _ => return,
    }
    let canonical = match resolve(state, row, row.virtual_id.as_str()) {
        Some(token) => token,
        None => return,
    };
    let pinned = state
        .alias
        .get(&alias_key(row.virtual_id.as_str(), row))
        .map(|(_, generation)| *generation);
    record_gap_lines(state, row, &canonical, pinned);
}

/// Re-derive one rolled-back leg's discontinuity evidence
/// against restored state, without joining or displaying
/// any identity. Gap legs record their seal or bound; an
/// observation, release, quarantine, recorded conversion,
/// informational display, or alias bind keeps a carried
/// clock-domain change bounded, so a refused group drops no
/// temporal evidence whatever leg order replayed first; a
/// failed revert keeps the restoration
/// uncertainty it recorded, so a later row can no longer
/// claim the line is known. Addressing mirrors `apply_row`:
/// aliases resolve first, a looping chain records nothing,
/// and a leg that joins no single line records nothing,
/// exactly as a replayed row would. Only the discontinuity
/// outlives the refused group: binds, fresh lines and other
/// lifecycle transitions never survive.
/// Events whose discontinuity evidence outlives a refused
/// group: explicit gaps plus the rows that join or show a
/// line and note its clock domain — state-changing rows,
/// informational rows, and alias binds. Rollback
/// re-derivation handles exactly this set, and the
/// interleaved-group deferral filter reuses it, so neither
/// path drops a carried clock change or a failed revert's
/// uncertainty.
fn preserves_discontinuity(event: &str) -> bool {
    matches!(
        event,
        "loss_gap"
            | "suspend_gap"
            | "clock_change"
            | "observed"
            | "released"
            | "quarantined"
            | "revert_ok"
            | "revert_failed"
            | "capture_end"
            | "baseline"
            | "alias"
    )
}

fn record_rollback_evidence(state: &mut State, refusals: &Refusals, row: &LedgerRow) {
    if !preserves_discontinuity(row.event.as_str()) {
        return;
    }
    match row.event.as_str() {
        "loss_gap" | "suspend_gap" | "clock_change" => {
            record_gap(state, row);
            return;
        }
        _ => {}
    }
    let canonical = match resolve(state, row, row.virtual_id.as_str()) {
        Some(token) => token,
        None => return,
    };
    let pinned = state
        .alias
        .get(&alias_key(row.virtual_id.as_str(), row))
        .map(|(_, generation)| *generation);
    // An informational leg shows the current line exactly
    // as a replayed row would, keeping only the clock
    // evidence its display records; an alias leg notes the
    // bound line's clock domain without installing the
    // binding, which never survives a refused group.
    match row.event.as_str() {
        "capture_end" | "baseline" => {
            let _ = shown_identity(state, refusals, row, &canonical, pinned);
            return;
        }
        "alias" => {
            record_alias_evidence(state, refusals, row);
            return;
        }
        _ => {}
    }
    // Quarantine sees restoration-uncertain lines, exactly
    // as a replayed quarantine row would; every other leg
    // joins open lines only.
    let unknown_ok = row.event == "quarantined";
    let (joined, generation) = match join(state, refusals, row, &canonical, pinned, unknown_ok) {
        Ok(joined) => joined,
        Err(_) => return,
    };
    if row.event != "revert_failed" {
        note_domain(state, row, &joined, generation);
        return;
    }
    // A failed revert inside a refused group still observed
    // that the prior state was not restored: the joined line
    // keeps unknown state and certainty, exactly as a
    // replayed revert would record, while its other
    // bookkeeping stays at the checkpoint.
    if let Some(obj) = state.linked.get_mut(&(joined, generation)) {
        obj.status = "unknown".to_string();
        obj.certainty = "unknown".to_string();
    }
}

/// Re-derive one rolled-back alias leg's clock evidence
/// against restored state, without joining or displaying
/// any identity and without installing the binding. The
/// resolution mirrors `apply_alias` check for check: a
/// leg the replayed row would refuse records nothing,
/// while a bindable leg notes the bound line's clock
/// domain exactly as the replayed bind would.
fn record_alias_evidence(state: &mut State, refusals: &Refusals, row: &LedgerRow) {
    let target = match row.alias_of.as_deref() {
        Some(name) => name,
        None => return,
    };
    if refusals
        .refused_alloc
        .contains(&refusal_key(&row.virtual_id, row))
    {
        return;
    }
    let target_canonical = match resolve(state, row, target) {
        Some(token) => token,
        None => return,
    };
    let allocated_here = state
        .linked
        .iter()
        .any(|((name, _), obj)| name == &row.virtual_id && same_origin(obj, row));
    let recorded_here = state
        .handle_alloc
        .get(&alias_key(row.virtual_id.as_str(), row))
        .map(|lines| {
            lines
                .iter()
                .any(|(token, generation)| state.linked.contains_key(&(token.clone(), *generation)))
        })
        .unwrap_or(false);
    if allocated_here || recorded_here {
        return;
    }
    if row.virtual_id == target_canonical {
        return;
    }
    let mut probe = target_canonical.clone();
    for _ in 0..=MAX_ALIAS_HOPS {
        if probe == row.virtual_id {
            return;
        }
        match state
            .alias
            .get(&alias_key(&probe, row))
            .map(|(token, _)| token.clone())
        {
            Some(next) => probe = next,
            None => break,
        }
    }
    let (bound_token, generation) = match state
        .alias
        .get(&alias_key(target, row))
        .map(|(_, generation)| *generation)
    {
        Some(bound) => {
            if refused_on_path(state, refusals, row, target, &target_canonical) {
                return;
            }
            let key = (target_canonical.clone(), bound);
            let obj = match state.linked.get(&key) {
                Some(obj) => obj,
                None => return,
            };
            if state.sealed.contains(&key) {
                return;
            }
            if !is_open(obj.status.as_str()) {
                return;
            }
            if !same_origin(obj, row) {
                return;
            }
            (target_canonical.clone(), bound)
        }
        None => match join(state, refusals, row, &target_canonical, None, false) {
            Ok(joined) => joined,
            Err(_) => return,
        },
    };
    note_domain(state, row, &bound_token, generation);
}

/// Seal or bound the lines one gap row denotes. A loss
/// gap seals only lines the gap's own origin observed: a
/// foreign loss row never seals same-source identities.
/// Open lines and restoration-uncertain lines both seal,
/// so a failed revert followed by loss accepts no later
/// joins. A row addressed through a pinned alias seals or
/// bounds only that generation; loss through an old pin
/// never seals a newer generation. An unpinned row seals
/// or bounds every same-origin line its handle denotes,
/// including generations recorded through the handle
/// under another token and the generation an invalidated
/// pin last bound.
fn record_gap_lines(state: &mut State, row: &LedgerRow, canonical: &str, pinned: Option<u64>) {
    match row.event.as_str() {
        "loss_gap" => {
            let seal: Vec<(String, u64)> = match pinned {
                Some(generation) => state
                    .linked
                    .get(&(canonical.to_string(), generation))
                    .filter(|obj| {
                        (is_open(obj.status.as_str()) || obj.status == "unknown")
                            && same_origin(obj, row)
                    })
                    .map(|_| vec![(canonical.to_string(), generation)])
                    .unwrap_or_default(),
                None => {
                    let mut seal: Vec<(String, u64)> = state
                        .linked
                        .iter()
                        .filter(|((name, _), obj)| {
                            name == canonical
                                && (is_open(obj.status.as_str()) || obj.status == "unknown")
                                && same_origin(obj, row)
                        })
                        .map(|((name, generation), _)| (name.clone(), *generation))
                        .collect();
                    let extras = denoted_extras(state, row, canonical);
                    for (extra_token, extra_generation) in extras {
                        let key = (extra_token.clone(), extra_generation);
                        let usable = state
                            .linked
                            .get(&key)
                            .map(|obj| is_open(obj.status.as_str()) || obj.status == "unknown")
                            .unwrap_or(false);
                        if usable {
                            seal.push((extra_token, extra_generation));
                        }
                    }
                    seal.sort();
                    seal.dedup();
                    seal
                }
            };
            for (token, generation) in seal {
                state.sealed.insert((token, generation));
            }
        }
        "suspend_gap" | "clock_change" => {
            bound_token_lines(state, row, canonical, pinned);
        }
        _ => {}
    }
}

fn apply_row(
    state: &mut State,
    config: &ReplayConfig,
    refusals: &mut Refusals,
    row: &LedgerRow,
) -> Applied {
    // An allocation names its own handle first: a handle
    // bound to a still-open unsealed line continues that
    // address's reuse chain, while any other handle —
    // unbound, or bound to a closed or loss-sealed line —
    // starts its own identity.
    // Every other event resolves aliases before it joins.
    let addressed = if row.event == "allocated" {
        allocation_token(state, row, row.virtual_id.as_str())
    } else {
        resolve(state, row, row.virtual_id.as_str())
    };
    let canonical = match addressed {
        Some(token) => token,
        None => {
            return failed(
                row,
                format!(
                    "alias chain for '{}' closes a loop; no identity joined",
                    row.virtual_id
                ),
            );
        }
    };
    // A row addressed through a bound alias may join only
    // the pinned generation. Clock-domain comparison
    // happens at the join or display below, against the
    // generation the row actually joined or shows.
    let pinned = state
        .alias
        .get(&alias_key(row.virtual_id.as_str(), row))
        .map(|(_, generation)| *generation);
    match row.event.as_str() {
        "allocated" => {
            let applied = apply_allocated(state, config, refusals, row, &canonical);
            // A successful allocation drops the handle's
            // stale binding but keeps its provenance: a
            // fresh identity addresses the new line, and a
            // reuse through a live binding leaves both
            // generations plausible, so the old pin must
            // not answer later rows alone yet still keeps
            // them ambiguous while its line stays open. A
            // refusal changes nothing.
            if !applied.failed
                && let Some(prior) = state.alias.remove(&alias_key(row.virtual_id.as_str(), row))
            {
                state
                    .dropped_pin
                    .insert(alias_key(row.virtual_id.as_str(), row), prior);
            }
            applied
        }
        "observed" => {
            let (canonical, generation) =
                match join(state, refusals, row, &canonical, pinned, false) {
                    Ok(joined) => joined,
                    Err(note) => return failed(row, note),
                };
            note_domain(state, row, &canonical, generation);
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, row, &canonical, generation, &line_certainty);
            let obj = state
                .linked
                .get_mut(&(canonical.clone(), generation))
                .expect("joined generation exists");
            obj.status = "live".to_string();
            obj.certainty = certainty.clone();
            obj.last_seq = row.seq;
            obj.evidence.push(row.row_id.clone());
            Applied {
                resolved: ResolvedRow {
                    row_id: row.row_id.clone(),
                    seq: row.seq,
                    identity: Some(QualifiedIdentity {
                        token: canonical.clone(),
                        generation,
                    }),
                    status: "live".to_string(),
                    certainty,
                    note: format!("joined open generation {generation} of '{canonical}'"),
                },
                failed: false,
            }
        }
        "released" => {
            let (canonical, generation) =
                match join(state, refusals, row, &canonical, pinned, false) {
                    Ok(joined) => joined,
                    Err(note) => return failed(row, note),
                };
            note_domain(state, row, &canonical, generation);
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, row, &canonical, generation, &line_certainty);
            let obj = state
                .linked
                .get_mut(&(canonical.clone(), generation))
                .expect("joined generation exists");
            obj.status = "released".to_string();
            obj.certainty = certainty.clone();
            obj.last_seq = row.seq;
            obj.evidence.push(row.row_id.clone());
            Applied {
                resolved: ResolvedRow {
                    row_id: row.row_id.clone(),
                    seq: row.seq,
                    identity: Some(QualifiedIdentity {
                        token: canonical.clone(),
                        generation,
                    }),
                    status: "released".to_string(),
                    certainty,
                    note: format!("released generation {generation} of '{canonical}'"),
                },
                failed: false,
            }
        }
        "quarantined" => {
            // Quarantine also sees restoration-uncertain
            // lines: a failed revert keeps the line
            // visible here, and the recorded quarantine
            // preserves the unknown certainty.
            let (canonical, generation) = match join(state, refusals, row, &canonical, pinned, true)
            {
                Ok(joined) => joined,
                Err(note) => return failed(row, note),
            };
            note_domain(state, row, &canonical, generation);
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, row, &canonical, generation, &line_certainty);
            let obj = state
                .linked
                .get_mut(&(canonical.clone(), generation))
                .expect("joined generation exists");
            obj.status = "quarantined".to_string();
            obj.certainty = certainty.clone();
            obj.last_seq = row.seq;
            obj.evidence.push(row.row_id.clone());
            Applied {
                resolved: ResolvedRow {
                    row_id: row.row_id.clone(),
                    seq: row.seq,
                    identity: Some(QualifiedIdentity {
                        token: canonical.clone(),
                        generation,
                    }),
                    status: "quarantined".to_string(),
                    certainty,
                    note: format!(
                        "quarantined generation {generation} of '{canonical}'; \
                         quarantine is not reuse"
                    ),
                },
                failed: false,
            }
        }
        "revert_ok" => {
            // A successful revert records the conversion
            // without ending the live allocation: the
            // lifecycle status is unchanged.
            let (canonical, generation) =
                match join(state, refusals, row, &canonical, pinned, false) {
                    Ok(joined) => joined,
                    Err(note) => return failed(row, note),
                };
            note_domain(state, row, &canonical, generation);
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, row, &canonical, generation, &line_certainty);
            let obj = state
                .linked
                .get_mut(&(canonical.clone(), generation))
                .expect("joined generation exists");
            let status = obj.status.clone();
            obj.certainty = certainty.clone();
            obj.last_seq = row.seq;
            obj.evidence.push(row.row_id.clone());
            Applied {
                resolved: ResolvedRow {
                    row_id: row.row_id.clone(),
                    seq: row.seq,
                    identity: Some(QualifiedIdentity {
                        token: canonical.clone(),
                        generation,
                    }),
                    status: status.clone(),
                    certainty,
                    note: format!(
                        "recorded conversion of generation {generation} of '{canonical}'; \
                         allocation stays {status}"
                    ),
                },
                failed: false,
            }
        }
        "revert_failed" => {
            let (canonical, generation) =
                match join(state, refusals, row, &canonical, pinned, false) {
                    Ok(joined) => joined,
                    Err(note) => return failed(row, note),
                };
            note_domain(state, row, &canonical, generation);
            let obj = state
                .linked
                .get_mut(&(canonical.clone(), generation))
                .expect("joined generation exists");
            obj.status = "unknown".to_string();
            obj.certainty = "unknown".to_string();
            obj.last_seq = row.seq;
            obj.evidence.push(row.row_id.clone());
            Applied {
                resolved: ResolvedRow {
                    row_id: row.row_id.clone(),
                    seq: row.seq,
                    identity: Some(QualifiedIdentity {
                        token: canonical.clone(),
                        generation,
                    }),
                    status: "unknown".to_string(),
                    certainty: "unknown".to_string(),
                    note: format!(
                        "revert failed for generation {generation} of '{canonical}'; \
                         prior state not restored"
                    ),
                },
                failed: false,
            }
        }
        "alias" => apply_alias(state, refusals, row),
        "capture_end" => apply_shown(
            state,
            refusals,
            row,
            &canonical,
            pinned,
            "capture end is not teardown".to_string(),
        ),
        "baseline" => apply_shown(
            state,
            refusals,
            row,
            &canonical,
            pinned,
            "baseline declaration; reconciled explicitly".to_string(),
        ),
        "loss_gap" => {
            record_gap_lines(state, row, &canonical, pinned);
            apply_shown(
                state,
                refusals,
                row,
                &canonical,
                pinned,
                "event-loss gap; later observations stay separate samples".to_string(),
            )
        }
        "suspend_gap" => {
            record_gap_lines(state, row, &canonical, pinned);
            apply_shown(
                state,
                refusals,
                row,
                &canonical,
                pinned,
                "suspend gap; elapsed unknown".to_string(),
            )
        }
        "clock_change" => {
            record_gap_lines(state, row, &canonical, pinned);
            apply_shown(
                state,
                refusals,
                row,
                &canonical,
                pinned,
                "clock domain change; temporal claims bounded".to_string(),
            )
        }
        other => failed(
            row,
            format!("unknown event '{other}' in row '{}'", row.row_id),
        ),
    }
}

fn apply_allocated(
    state: &mut State,
    config: &ReplayConfig,
    refusals: &mut Refusals,
    row: &LedgerRow,
    canonical: &str,
) -> Applied {
    let generation = match state
        .latest
        .get(canonical)
        .copied()
        .unwrap_or(0)
        .checked_add(1)
    {
        Some(generation) => generation,
        None => {
            refusals.overflow += 1;
            refusals.refused_alloc.insert(refusal_key(canonical, row));
            return failed(
                row,
                format!("generation overflow at '{canonical}'; reuse refused"),
            );
        }
    };
    if generation > config.max_generation {
        refusals.overflow += 1;
        refusals.refused_alloc.insert(refusal_key(canonical, row));
        return failed(
            row,
            format!("generation overflow at '{canonical}'; reuse refused"),
        );
    }
    // A failed conversion is not a lifetime end: open
    // lines and restoration-uncertain lines both occupy
    // the per-source cap, so failed conversions never free
    // capacity without an observed teardown.
    let open_here = state
        .linked
        .values()
        .filter(|obj| {
            obj.source_id == row.source_id
                && (is_open(obj.status.as_str()) || obj.status == "unknown")
        })
        .count();
    if open_here >= config.max_open_per_source {
        refusals.bound += 1;
        refusals.refused_alloc.insert(refusal_key(canonical, row));
        return failed(
            row,
            format!(
                "open identity bound reached for source '{}'; allocation refused",
                row.source_id
            ),
        );
    }
    state.linked.insert(
        (canonical.to_string(), generation),
        ObjState {
            source_id: row.source_id.clone(),
            object_class: row.object_class.clone(),
            clock_domain: row.clock_domain.clone(),
            status: "created".to_string(),
            certainty: "known".to_string(),
            first_seq: row.seq,
            last_seq: row.seq,
            evidence: vec![row.row_id.clone()],
        },
    );
    state.latest.insert(canonical.to_string(), generation);
    // A reuse through a live binding records the new
    // generation under the canonical token but the
    // allocation was made at the handle: keep that
    // provenance so later rows at the handle still see
    // the open allocation after the pin is invalidated.
    if row.virtual_id != canonical {
        state
            .handle_alloc
            .entry(alias_key(row.virtual_id.as_str(), row))
            .or_default()
            .push((canonical.to_string(), generation));
    }
    // A fresh generation starts its own temporal line in
    // this origin: gap state is keyed per generation, so
    // the new line starts unbounded without clearing
    // older generations' bounds. Other origins keep
    // their gap state.
    Applied {
        resolved: ResolvedRow {
            row_id: row.row_id.clone(),
            seq: row.seq,
            identity: Some(QualifiedIdentity {
                token: canonical.to_string(),
                generation,
            }),
            status: "created".to_string(),
            certainty: "known".to_string(),
            note: format!("allocated generation {generation} for '{canonical}'"),
        },
        failed: false,
    }
}

fn apply_alias(state: &mut State, refusals: &Refusals, row: &LedgerRow) -> Applied {
    let target = match row.alias_of.as_deref() {
        Some(name) => name,
        None => return failed(row, format!("alias row '{}' names no target", row.row_id)),
    };
    // The handle being bound joins the refusal check
    // beside the target path: a refused allocation of
    // this handle may hide an untracked generation, so
    // the alias refuses rather than bind over ambiguity.
    if refusals
        .refused_alloc
        .contains(&refusal_key(&row.virtual_id, row))
    {
        return failed(
            row,
            format!(
                "allocation of '{}' was refused; alias refused",
                row.virtual_id
            ),
        );
    }
    let target_canonical = match resolve(state, row, target) {
        Some(token) => token,
        None => {
            return failed(
                row,
                format!("alias chain for '{target}' closes a loop; alias refused"),
            );
        }
    };
    // Admission is per origin: a handle allocated only
    // in another source or class stays bindable here,
    // while a handle already allocated in this origin
    // refuses the alias instead of binding over it. A
    // handle that recorded an allocation under another
    // token counts as allocated too: the still-tracked
    // line was made at this handle, so rebinding would
    // hide it.
    let allocated_here = state
        .linked
        .iter()
        .any(|((name, _), obj)| name == &row.virtual_id && same_origin(obj, row));
    let recorded_here = state
        .handle_alloc
        .get(&alias_key(row.virtual_id.as_str(), row))
        .map(|lines| {
            lines
                .iter()
                .any(|(token, generation)| state.linked.contains_key(&(token.clone(), *generation)))
        })
        .unwrap_or(false);
    if allocated_here || recorded_here {
        return failed(
            row,
            format!(
                "token '{}' already allocated; alias refused",
                row.virtual_id
            ),
        );
    }
    if row.virtual_id == target_canonical {
        return failed(row, "token cannot alias itself".to_string());
    }
    let mut probe = target_canonical.clone();
    for _ in 0..=MAX_ALIAS_HOPS {
        if probe == row.virtual_id {
            return failed(row, "alias would close a loop; alias refused".to_string());
        }
        match state
            .alias
            .get(&alias_key(&probe, row))
            .map(|(token, _)| token.clone())
        {
            Some(next) => probe = next,
            None => break,
        }
    }
    // An alias of a bound alias inherits its exact
    // binding when the bound line is still open;
    // otherwise the target must offer exactly one
    // joinable line through the shared lookup, so an
    // ambiguous, closed, or loss-sealed target refuses
    // the alias instead of selecting a generation. A
    // refused allocation poisons the inherited binding
    // too, since an untracked generation may sit beside
    // the pinned one.
    let (bound_token, generation) = match state
        .alias
        .get(&alias_key(target, row))
        .map(|(_, generation)| *generation)
    {
        Some(bound) => {
            if refused_on_path(state, refusals, row, target, &target_canonical) {
                return failed(
                    row,
                    format!(
                        "a refused allocation on the alias path to '{target_canonical}' may hide \
                         another generation; alias refused"
                    ),
                );
            }
            let key = (target_canonical.clone(), bound);
            let obj = match state.linked.get(&key) {
                Some(obj) => obj,
                None => {
                    return failed(
                        row,
                        format!("alias target '{target}' names no tracked line; alias refused"),
                    );
                }
            };
            if state.sealed.contains(&key) {
                return failed(
                    row,
                    format!(
                        "event-loss gap precedes row '{}'; alias stays unlinked",
                        row.row_id
                    ),
                );
            }
            if !is_open(obj.status.as_str()) {
                return failed(
                    row,
                    format!(
                        "alias target '{target}' generation {bound} is no longer open; \
                         alias refused"
                    ),
                );
            }
            if !same_origin(obj, row) {
                return failed(
                    row,
                    format!(
                        "no open generation for '{target_canonical}' from source '{}' class '{}'",
                        row.source_id, row.object_class
                    ),
                );
            }
            (target_canonical.clone(), bound)
        }
        None => match join(state, refusals, row, &target_canonical, None, false) {
            Ok(joined) => joined,
            Err(note) => return failed(row, note),
        },
    };
    state.alias.insert(
        alias_key(row.virtual_id.as_str(), row),
        (bound_token.clone(), generation),
    );
    let bound = state
        .linked
        .get(&(bound_token.clone(), generation))
        .expect("bound generation exists");
    let mut certainty = shown_certainty(
        state,
        row,
        &bound_token,
        generation,
        bound.certainty.as_str(),
    );
    // A binding claimed from a clock domain the bound
    // line does not share is temporally bounded,
    // without changing the target's own standing.
    // Older generations never mask the mismatch, and the
    // crossing bounds the token's later claims in this
    // origin.
    let line_clock = bound.clock_domain.clone();
    let line_status = bound.status.clone();
    if line_clock != row.clock_domain {
        state
            .temporal_bounded
            .insert(bound_key(&bound_token, generation, row));
        if certainty == "known" {
            certainty = "bounded".to_string();
        }
    }
    Applied {
        resolved: ResolvedRow {
            row_id: row.row_id.clone(),
            seq: row.seq,
            identity: Some(QualifiedIdentity {
                token: bound_token.clone(),
                generation,
            }),
            status: line_status,
            certainty,
            note: format!(
                "token '{}' aliases '{bound_token}' at generation {generation}",
                row.virtual_id
            ),
        },
        failed: false,
    }
}

/// Informational rows (`capture_end`, `baseline`, gaps):
/// they show the current line but change no lifecycle.
/// Showing a line still notes its clock domain, so a
/// cross-domain display bounds later claims.
fn apply_shown(
    state: &mut State,
    refusals: &Refusals,
    row: &LedgerRow,
    canonical: &str,
    pinned: Option<u64>,
    note: String,
) -> Applied {
    match shown_identity(state, refusals, row, canonical, pinned) {
        Some((identity, status, certainty)) => Applied {
            resolved: ResolvedRow {
                row_id: row.row_id.clone(),
                seq: row.seq,
                identity: Some(identity),
                status,
                certainty,
                note,
            },
            failed: false,
        },
        None => Applied {
            resolved: unknown_row(row, format!("{note}; no identity joined")),
            failed: false,
        },
    }
}

/// Record a refused observation as an unlinked sample,
/// so it stays visible without joining any identity.
fn push_unlinked_sample(state: &mut State, row: &LedgerRow) {
    if row.event != "observed" {
        return;
    }
    let token =
        resolve(state, row, row.virtual_id.as_str()).unwrap_or_else(|| row.virtual_id.clone());
    state.samples.push((
        token,
        ObjState {
            source_id: row.source_id.clone(),
            object_class: row.object_class.clone(),
            clock_domain: row.clock_domain.clone(),
            status: "unknown".to_string(),
            certainty: "unknown".to_string(),
            first_seq: row.seq,
            last_seq: row.seq,
            evidence: vec![row.row_id.clone()],
        },
    ));
}

/// Replay one capture of ledger rows.
///
/// Rows normalize by `(seq, row_id)`; rows from another
/// capture and duplicated row handles are refused before
/// replay. Rows sharing an `atom` marker commit as a unit:
/// when any leg fails, the group rolls back and every leg
/// resolves UNKNOWN with the legs left separate, while
/// each discontinuity leg still records its evidence
/// against proved state. A group whose legs are
/// interleaved with other rows is refused outright, with
/// its discontinuity legs recorded once replay passes
/// their ledger positions, and output always follows
/// ledger order.
pub fn replay(rows: &[LedgerRow], capture_id: &str, config: &ReplayConfig) -> ReplayOutcome {
    let mut order: Vec<usize> = (0..rows.len()).collect();
    order.sort_by(|&left, &right| {
        (rows[left].seq, &rows[left].row_id).cmp(&(rows[right].seq, &rows[right].row_id))
    });
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    let mut refused_cross_capture = 0usize;
    let mut duplicate_rows = Vec::new();
    let mut admitted: Vec<&LedgerRow> = Vec::new();
    for index in order {
        let row = &rows[index];
        if row.capture_id != capture_id {
            refused_cross_capture += 1;
            continue;
        }
        if !seen.insert(row.row_id.as_str()) {
            duplicate_rows.push(row.row_id.clone());
            continue;
        }
        admitted.push(row);
    }

    let mut atom_group: BTreeMap<&str, usize> = BTreeMap::new();
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for (position, row) in admitted.iter().enumerate() {
        match row.atom.as_deref() {
            None => groups.push(vec![position]),
            Some(atom) => match atom_group.get(atom) {
                Some(&group) => groups[group].push(position),
                None => {
                    atom_group.insert(atom, groups.len());
                    groups.push(vec![position]);
                }
            },
        }
    }

    let mut state = State::default();
    let mut refusals = Refusals::default();
    let mut resolved = Vec::new();
    let mut failed_joins = Vec::new();
    // Ledger positions of discontinuity legs deferred
    // from refused interleaved groups, recorded once
    // replay passes them.
    let mut pending_deferred: Vec<usize> = Vec::new();
    for group in &groups {
        let legs: Vec<&LedgerRow> = group.iter().map(|&position| admitted[position]).collect();
        // Record deferred legs whose ledger position
        // replay has passed, oldest first: every earlier
        // row already applied, so each leg re-derives its
        // discontinuity against its exact prefix while rows
        // before it replayed unaffected.
        pending_deferred.sort();
        let mut due = 0;
        while due < pending_deferred.len() && pending_deferred[due] < group[0] {
            due += 1;
        }
        for position in pending_deferred.drain(..due) {
            record_rollback_evidence(&mut state, &refusals, admitted[position]);
        }
        // An atomic group whose legs are interleaved with
        // other rows cannot commit as a unit: refuse every
        // leg without applying any, so replay never pulls
        // a later leg ahead of intervening evidence.
        let contiguous = group.len() < 2 || group[group.len() - 1] - group[0] + 1 == group.len();
        if !contiguous {
            for row in &legs {
                resolved.push(unknown_row(
                    row,
                    "atomic group interleaved with other rows; atomicity not proved, \
                     legs stay separate"
                        .to_string(),
                ));
                failed_joins.push(row.row_id.clone());
                push_unlinked_sample(&mut state, row);
            }
            // A refused group's discontinuity legs still
            // observed a break in the ledger stream: defer
            // each one to its own ledger position so rows
            // before it replay unaffected while later rows
            // see the seal, bound, or uncertainty.
            for &position in group {
                if preserves_discontinuity(admitted[position].event.as_str()) {
                    pending_deferred.push(position);
                }
            }
            continue;
        }
        let checkpoint = state.clone();
        let resolved_len = resolved.len();
        let failed_len = failed_joins.len();
        let mut tentative = Vec::new();
        // Refusal set at each leg's ledger position, taken
        // before its tentative replay: rollback re-resolves
        // every leg against the refusals proved when replay
        // reached it, never against a later leg's refusal.
        // Legs share one snapshot while no leg adds a
        // refusal, so a large group keeps one copy instead
        // of a full clone per leg. Refusals only grow —
        // counters increment, keys insert — so equal
        // counters and length mean an unchanged set.
        let mut refusal_snapshots: Vec<Refusals> = Vec::new();
        let mut leg_snapshot: Vec<usize> = Vec::new();
        let mut group_failed = false;
        for row in &legs {
            let reuse = leg_snapshot.last().copied().filter(|&index| {
                let snapshot = &refusal_snapshots[index];
                snapshot.overflow == refusals.overflow
                    && snapshot.bound == refusals.bound
                    && snapshot.refused_alloc.len() == refusals.refused_alloc.len()
            });
            match reuse {
                Some(index) => leg_snapshot.push(index),
                None => {
                    leg_snapshot.push(refusal_snapshots.len());
                    refusal_snapshots.push(refusals.clone());
                }
            }
            let applied = apply_row(&mut state, config, &mut refusals, row);
            if applied.failed {
                group_failed = true;
            }
            // A shared group commits only as a unit: a leg
            // that joins no identity — including an
            // informational leg that merely shows nothing —
            // leaves the unit unproved, so the group rolls
            // back. Standalone rows keep their own
            // informational behavior.
            if !group_failed && legs.len() > 1 && applied.resolved.identity.is_none() {
                group_failed = true;
            }
            tentative.push(applied);
            if group_failed {
                break;
            }
        }
        if !group_failed {
            for applied in tentative {
                resolved.push(applied.resolved);
            }
            continue;
        }
        // Discontinuity evidence survives group rollback,
        // re-derived against the restored checkpoint: a loss
        // seal, a temporal bound, or a clock-domain change a
        // state-changing row carried records a break in the
        // ledger stream, not a join claim, so continuity past
        // the break stays unproved even when the group as a
        // unit is unproved. Tentative seals and bounds
        // survive only for lines the group did not create:
        // a later fresh allocation must not inherit a gap
        // that struck a rolled-back object. Every leg —
        // applied or skipped past the first failure — then
        // records its discontinuity against proved state,
        // so a provisional release cannot suppress a loss
        // seal, a skipped gap row still seals or bounds, a
        // skipped observation, release, quarantine,
        // conversion, informational display, or alias bind
        // keeps its clock change bounded whatever leg order
        // replayed first, and a failed revert keeps the
        // restoration uncertainty it recorded — including
        // the tentative mark when re-resolution below turns
        // ambiguous.
        let tentative_sealed = state.sealed.clone();
        let tentative_bounded = state.temporal_bounded.clone();
        // Lines tentative legs left
        // restoration-uncertain: re-resolution below may
        // see every candidate open again and record
        // nothing, so the tentative uncertainty outlives
        // the rollback exactly like a seal or bound, and
        // only for lines the group did not create. Any
        // uncertain line counts whatever status a later
        // tentative leg recorded: a quarantine leg keeps
        // the unknown certainty while renaming the
        // status, and the rolled-back rename must not
        // hide the earlier failed revert.
        let tentative_unknown: Vec<(String, u64)> = state
            .linked
            .iter()
            .filter(|(_, obj)| obj.certainty == "unknown")
            .map(|((token, generation), _)| (token.clone(), *generation))
            .collect();
        state = checkpoint;
        for key in &tentative_sealed {
            if state.linked.contains_key(key) {
                state.sealed.insert(key.clone());
            }
        }
        for key in &tentative_bounded {
            if state.linked.contains_key(&(key.0.clone(), key.1)) {
                state.temporal_bounded.insert(key.clone());
            }
        }
        for key in &tentative_unknown {
            if let Some(obj) = state.linked.get_mut(key) {
                // Tentative replay only adds uncertainty:
                // a line already restoration-uncertain
                // before the group keeps its checkpoint
                // state, quarantine status included.
                if obj.certainty != "unknown" {
                    obj.status = "unknown".to_string();
                    obj.certainty = "unknown".to_string();
                }
            }
        }
        // Each leg re-resolves against its own ledger
        // position: a leg that replayed tentatively sees the
        // refusals proved before it ran, so a later leg's
        // refusal never suppresses its evidence; a leg past
        // the first failure sees the tentative set, since its
        // position follows every leg that ran.
        for (index, row) in legs.iter().enumerate() {
            let at_position = leg_snapshot
                .get(index)
                .and_then(|slot| refusal_snapshots.get(*slot))
                .unwrap_or(&refusals);
            record_rollback_evidence(&mut state, at_position, row);
        }
        resolved.truncate(resolved_len);
        failed_joins.truncate(failed_len);
        for row in &legs {
            let specific = tentative
                .iter()
                .find(|applied| applied.resolved.row_id == row.row_id && applied.failed)
                .map(|applied| applied.resolved.note.clone());
            let note = specific
                .unwrap_or_else(|| "atomic group not proved; legs stay separate".to_string());
            resolved.push(unknown_row(row, note));
            failed_joins.push(row.row_id.clone());
            push_unlinked_sample(&mut state, row);
        }
    }
    // Legs deferred past the last group still record,
    // against final state: no later row can observe them,
    // but the evidence stays total.
    pending_deferred.sort();
    for position in pending_deferred {
        record_rollback_evidence(&mut state, &refusals, admitted[position]);
    }
    // Groups replay at their first leg; restore ledger
    // order so output always follows (seq, row_id).
    resolved.sort_by(|left, right| (left.seq, &left.row_id).cmp(&(right.seq, &right.row_id)));
    let admission: BTreeMap<&str, (u64, &str)> = admitted
        .iter()
        .map(|row| (row.row_id.as_str(), (row.seq, row.row_id.as_str())))
        .collect();
    failed_joins.sort_by(|left, right| admission[left.as_str()].cmp(&admission[right.as_str()]));

    let mut objects: Vec<LineageObject> = Vec::new();
    for ((token, generation), obj) in &state.linked {
        objects.push(LineageObject {
            token: token.clone(),
            generation: *generation,
            source_id: obj.source_id.clone(),
            object_class: obj.object_class.clone(),
            status: obj.status.clone(),
            certainty: obj.certainty.clone(),
            first_seq: obj.first_seq,
            last_seq: obj.last_seq,
            evidence: obj.evidence.clone(),
            linked: true,
        });
    }
    for (token, obj) in &state.samples {
        objects.push(LineageObject {
            token: token.clone(),
            generation: 0,
            source_id: obj.source_id.clone(),
            object_class: obj.object_class.clone(),
            status: obj.status.clone(),
            certainty: obj.certainty.clone(),
            first_seq: obj.first_seq,
            last_seq: obj.last_seq,
            evidence: obj.evidence.clone(),
            linked: false,
        });
    }
    objects.sort_by(|left, right| {
        (left.token.clone(), left.generation, left.first_seq).cmp(&(
            right.token.clone(),
            right.generation,
            right.first_seq,
        ))
    });

    ReplayOutcome {
        capture_id: capture_id.to_string(),
        resolved,
        unlinked_samples: state.samples.len(),
        overflow_refusals: refusals.overflow,
        bound_refusals: refusals.bound,
        objects,
        failed_joins,
        refused_cross_capture,
        duplicate_rows,
    }
}

/// Reconcile declared baseline entries against linked
/// replay lines. The comparison is exact and read-only:
/// it never repairs the replay, and unlinked samples stay
/// outside it.
pub fn reconcile(baseline: &[BaselineEntry], outcome: &ReplayOutcome) -> Reconciliation {
    let mut confirmed = Vec::new();
    let mut status_mismatch = Vec::new();
    let mut missing_observation = Vec::new();
    for entry in baseline {
        let key = format!("{}#{}", entry.virtual_id, entry.generation);
        match outcome.objects.iter().find(|obj| {
            obj.linked && obj.token == entry.virtual_id && obj.generation == entry.generation
        }) {
            Some(obj) if obj.status == entry.status => confirmed.push(key),
            Some(_) => status_mismatch.push(key),
            None => missing_observation.push(key),
        }
    }
    let mut unconfirmed_observed = Vec::new();
    for obj in &outcome.objects {
        if !obj.linked {
            continue;
        }
        let covered = baseline
            .iter()
            .any(|entry| entry.virtual_id == obj.token && entry.generation == obj.generation);
        if !covered {
            unconfirmed_observed.push(format!("{}#{}", obj.token, obj.generation));
        }
    }
    confirmed.sort();
    status_mismatch.sort();
    missing_observation.sort();
    unconfirmed_observed.sort();
    Reconciliation {
        confirmed,
        status_mismatch,
        missing_observation,
        unconfirmed_observed,
    }
}
