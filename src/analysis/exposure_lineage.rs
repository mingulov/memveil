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
//!   one generation, so observations through an alias
//!   never double-count and never follow address reuse
//!   until the alias is rebound. An ambiguous or
//!   loss-sealed target refuses the alias.
//! * Rows that share an `atom` marker commit only as a
//!   unit: when any leg cannot join, every leg resolves
//!   UNKNOWN and the legs stay separate samples. A group
//!   interleaved with other rows is refused outright, and
//!   output always follows ledger order.
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
    /// Alias bindings: alias to (canonical token,
    /// generation). A binding pins one exact generation,
    /// so an alias never follows address reuse until it
    /// is explicitly rebound.
    alias: BTreeMap<String, (String, u64)>,
    temporal_bounded: BTreeSet<String>,
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
    refused_alloc: BTreeSet<String>,
}

fn is_open(status: &str) -> bool {
    OPEN_STATUSES.contains(&status)
}

/// Follow the alias map to the canonical token.
fn resolve(state: &State, virtual_id: &str) -> Option<String> {
    let mut current = virtual_id.to_string();
    let mut seen = BTreeSet::new();
    seen.insert(current.clone());
    for _ in 0..MAX_ALIAS_HOPS {
        match state.alias.get(&current).map(|(token, _)| token.clone()) {
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
/// temporally bounded token bounds the claim, and an
/// unknown or bounded line never upgrades.
fn event_certainty(state: &State, token: &str, line_certainty: &str) -> String {
    if line_certainty == "unknown" {
        return "unknown".to_string();
    }
    if state.temporal_bounded.contains(token) {
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

/// Generations one lookup may join: open lines, plus
/// restoration-uncertain lines when the caller allows
/// them, restricted to the row's own origin and
/// excluding loss-sealed lines. Oldest first.
fn joinable(
    state: &State,
    row: &LedgerRow,
    token: &str,
    unknown_ok: bool,
) -> Vec<u64> {
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

/// Shared lookup for state-changing rows and alias binds:
/// exactly one joinable line must exist. A line sealed by
/// a loss gap keeps its last state but accepts no new
/// joins, so a fresh post-loss allocation stays
/// unambiguous; a refused allocation keeps the token
/// ambiguous, since an untracked generation may exist
/// beside any tracked line.
fn join(
    state: &State,
    refusals: &Refusals,
    row: &LedgerRow,
    token: &str,
    pinned: Option<u64>,
    unknown_ok: bool,
) -> Result<u64, String> {
    if !state.latest.contains_key(token) {
        return Err(format!("no allocated identity for '{token}'"));
    }
    if let Some(generation) = pinned {
        return join_pinned(state, row, token, generation, unknown_ok);
    }
    let candidates = joinable(state, row, token, unknown_ok);
    if candidates.len() > 1 {
        return Err(format!(
            "ambiguous join: {} joinable generations for '{token}'",
            candidates.len()
        ));
    }
    if let Some(generation) = candidates.into_iter().next() {
        if refusals.refused_alloc.contains(token) {
            return Err(format!(
                "ambiguous join for '{token}': a refused allocation may hide \
                 another generation beside open generation {generation}"
            ));
        }
        return Ok(generation);
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
) -> Result<u64, String> {
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
    Ok(generation)
}

/// Certainty shown for one line: a loss-sealed line shows
/// unknown, an unknown line never upgrades, and a
/// temporally bounded token shows bounded at best.
fn shown_certainty(
    state: &State,
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
    if state.temporal_bounded.contains(token) {
        return "bounded".to_string();
    }
    line_certainty.to_string()
}

/// Identity shown by informational rows. An alias
/// binding shows its pinned generation; otherwise exactly
/// one joinable line must exist, else the row shows no
/// identity. A sealed line shows its last state with
/// unknown certainty, and an unambiguous closed line
/// shows its terminal state; ambiguity never shows an
/// identity.
fn shown_identity(
    state: &State,
    refusals: &Refusals,
    row: &LedgerRow,
    token: &str,
    pinned: Option<u64>,
) -> Option<(QualifiedIdentity, String, String)> {
    if !state.latest.contains_key(token) {
        return None;
    }
    if refusals.refused_alloc.contains(token) {
        return None;
    }
    if let Some(generation) = pinned {
        let obj = state.linked.get(&(token.to_string(), generation))?;
        return Some((
            QualifiedIdentity {
                token: token.to_string(),
                generation: generation,
            },
            obj.status.clone(),
            shown_certainty(state, token, generation, obj.certainty.as_str()),
        ));
    }
    let candidates = joinable(state, row, token, false);
    if candidates.len() > 1 {
        return None;
    }
    if let Some(generation) = candidates.into_iter().next() {
        let obj = state.linked.get(&(token.to_string(), generation))?;
        return Some((
            QualifiedIdentity {
                token: token.to_string(),
                generation: generation,
            },
            obj.status.clone(),
            shown_certainty(state, token, generation, obj.certainty.as_str()),
        ));
    }
    // No joinable line: a sealed line shows its last state
    // as unknown; an unambiguous same-origin closed line
    // shows its terminal state.
    let mut sealed: Vec<u64> = open_generations(state, token)
        .into_iter()
        .filter(|generation| {
            let key = (token.to_string(), *generation);
            state.sealed.contains(&key)
                && state
                    .linked
                    .get(&key)
                    .map(|obj| same_origin(obj, row))
                    .unwrap_or(false)
        })
        .collect();
    sealed.sort();
    if let Some(generation) = sealed.pop() {
        let obj = state.linked.get(&(token.to_string(), generation))?;
        return Some((
            QualifiedIdentity {
                token: token.to_string(),
                generation: generation,
            },
            obj.status.clone(),
            "unknown".to_string(),
        ));
    }
    let mut closed: Vec<u64> = state
        .linked
        .iter()
        .filter(|((name, _), obj)| {
            name == token && same_origin(obj, row) && !is_open(obj.status.as_str())
        })
        .map(|((_, generation), _)| *generation)
        .collect();
    closed.sort();
    let generation = closed.pop()?;
    let obj = state.linked.get(&(token.to_string(), generation))?;
    Some((
        QualifiedIdentity {
            token: token.to_string(),
            generation: generation,
        },
        obj.status.clone(),
        shown_certainty(state, token, generation, obj.certainty.as_str()),
    ))
}

fn apply_row(
    state: &mut State,
    config: &ReplayConfig,
    refusals: &mut Refusals,
    row: &LedgerRow,
) -> Applied {
    let canonical = match resolve(state, row.virtual_id.as_str()) {
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
    // the pinned generation.
    let pinned = state
        .alias
        .get(row.virtual_id.as_str())
        .map(|(_, generation)| *generation);
    // A row observed in a clock domain none of the token's
    // lines shares crosses a clock-domain change: the
    // token's temporal claims bound from here on.
    let token_tracked = state.latest.contains_key(&canonical);
    let shares_domain = state.linked.iter().any(|((name, _), obj)| {
        name == &canonical && obj.clock_domain == row.clock_domain
    });
    if token_tracked && !shares_domain {
        state.temporal_bounded.insert(canonical.clone());
    }
    match row.event.as_str() {
        "allocated" => apply_allocated(state, config, refusals, row, &canonical),
        "observed" => {
            let generation = match join(state, refusals, row, &canonical, pinned, false) {
                Ok(generation) => generation,
                Err(note) => return failed(row, note),
            };
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, &canonical, &line_certainty);
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
                        generation: generation,
                    }),
                    status: "live".to_string(),
                    certainty,
                    note: format!("joined open generation {generation} of '{canonical}'"),
                },
                failed: false,
            }
        }
        "released" => {
            let generation = match join(state, refusals, row, &canonical, pinned, false) {
                Ok(generation) => generation,
                Err(note) => return failed(row, note),
            };
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, &canonical, &line_certainty);
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
                        generation: generation,
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
            let generation = match join(state, refusals, row, &canonical, pinned, true) {
                Ok(generation) => generation,
                Err(note) => return failed(row, note),
            };
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, &canonical, &line_certainty);
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
                        generation: generation,
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
            let generation = match join(state, refusals, row, &canonical, pinned, false) {
                Ok(generation) => generation,
                Err(note) => return failed(row, note),
            };
            let line_certainty = state
                .linked
                .get(&(canonical.clone(), generation))
                .expect("joined generation exists")
                .certainty
                .clone();
            let certainty = event_certainty(state, &canonical, &line_certainty);
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
                        generation: generation,
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
            let generation = match join(state, refusals, row, &canonical, pinned, false) {
                Ok(generation) => generation,
                Err(note) => return failed(row, note),
            };
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
                        generation: generation,
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
            for generation in open_generations(state, &canonical) {
                state.sealed.insert((canonical.clone(), generation));
            }
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
            if state.latest.contains_key(&canonical) {
                state.temporal_bounded.insert(canonical.clone());
            }
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
            if state.latest.contains_key(&canonical) {
                state.temporal_bounded.insert(canonical.clone());
            }
            apply_shown(
                state,
                refusals,
                row,
                &canonical,
                pinned,
                "clock domain change; temporal claims bounded".to_string(),
            )
        }
        other => failed(row, format!("unknown event '{other}' in row '{}'", row.row_id)),
    }
}

fn apply_allocated(
    state: &mut State,
    config: &ReplayConfig,
    refusals: &mut Refusals,
    row: &LedgerRow,
    canonical: &str,
) -> Applied {
    let generation = match state.latest.get(canonical).copied().unwrap_or(0).checked_add(1) {
        Some(generation) => generation,
        None => {
            refusals.overflow += 1;
            refusals.refused_alloc.insert(canonical.to_string());
            return failed(
                row,
                format!("generation overflow at '{canonical}'; reuse refused"),
            );
        }
    };
    if generation > config.max_generation {
        refusals.overflow += 1;
        refusals.refused_alloc.insert(canonical.to_string());
        return failed(
            row,
            format!("generation overflow at '{canonical}'; reuse refused"),
        );
    }
    let open_here = state
        .linked
        .values()
        .filter(|obj| obj.source_id == row.source_id && is_open(obj.status.as_str()))
        .count();
    if open_here >= config.max_open_per_source {
        refusals.bound += 1;
        refusals.refused_alloc.insert(canonical.to_string());
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
    state.temporal_bounded.remove(canonical);
    Applied {
        resolved: ResolvedRow {
            row_id: row.row_id.clone(),
            seq: row.seq,
            identity: Some(QualifiedIdentity {
                token: canonical.to_string(),
                generation: generation,
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
    let target_canonical = match resolve(state, target) {
        Some(token) => token,
        None => {
            return failed(
                row,
                format!("alias chain for '{target}' closes a loop; alias refused"),
            );
        }
    };
    if state.latest.contains_key(&row.virtual_id) {
        return failed(
            row,
            format!("token '{}' already allocated; alias refused", row.virtual_id),
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
        match state.alias.get(&probe).map(|(token, _)| token.clone()) {
            Some(next) => probe = next,
            None => break,
        }
    }
    // An alias of a bound alias inherits its exact
    // binding; otherwise the target must offer exactly one
    // joinable line through the shared lookup, so an
    // ambiguous or loss-sealed target refuses the alias
    // instead of selecting a generation.
    let generation = match state.alias.get(target).map(|(_, generation)| *generation) {
        Some(bound) => {
            let key = (target_canonical.clone(), bound);
            let obj = match state.linked.get(&key) {
                Some(obj) => obj,
                None => {
                    return failed(
                        row,
                        format!(
                            "alias target '{target}' names no tracked line; alias refused"
                        ),
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
            if !same_origin(obj, row) {
                return failed(
                    row,
                    format!(
                        "no open generation for '{target_canonical}' from source '{}' class '{}'",
                        row.source_id, row.object_class
                    ),
                );
            }
            bound
        }
        None => match join(state, refusals, row, &target_canonical, None, false) {
            Ok(generation) => generation,
            Err(note) => return failed(row, note),
        },
    };
    state.alias.insert(
        row.virtual_id.clone(),
        (target_canonical.clone(), generation),
    );
    let obj = state
        .linked
        .get(&(target_canonical.clone(), generation))
        .expect("bound generation exists");
    let mut certainty = shown_certainty(
        state,
        &target_canonical,
        generation,
        obj.certainty.as_str(),
    );
    // A binding claimed from a clock domain none of the
    // target's lines shares is temporally bounded,
    // without changing the target's own standing.
    let shares_domain = state.linked.iter().any(|((name, _), line)| {
        name == &target_canonical && line.clock_domain == row.clock_domain
    });
    if !shares_domain && certainty == "known" {
        certainty = "bounded".to_string();
    }
    Applied {
        resolved: ResolvedRow {
            row_id: row.row_id.clone(),
            seq: row.seq,
            identity: Some(QualifiedIdentity {
                token: target_canonical.clone(),
                generation: generation,
            }),
            status: obj.status.clone(),
            certainty,
            note: format!(
                "token '{}' aliases '{target_canonical}' at generation {generation}",
                row.virtual_id
            ),
        },
        failed: false,
    }
}

/// Informational rows (`capture_end`, `baseline`, gaps):
/// they show the current line but change no lifecycle.
fn apply_shown(
    state: &State,
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
        resolve(state, row.virtual_id.as_str()).unwrap_or_else(|| row.virtual_id.clone());
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
/// resolves UNKNOWN with the legs left separate. A group
/// whose legs are interleaved with other rows is refused
/// outright, and output always follows ledger order.
pub fn replay(
    rows: &[LedgerRow],
    capture_id: &str,
    config: &ReplayConfig,
) -> ReplayOutcome {
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
    for group in &groups {
        let legs: Vec<&LedgerRow> = group.iter().map(|&position| admitted[position]).collect();
        // An atomic group whose legs are interleaved with
        // other rows cannot commit as a unit: refuse every
        // leg without applying any, so replay never pulls
        // a later leg ahead of intervening evidence.
        let contiguous =
            group.len() < 2 || group[group.len() - 1] - group[0] + 1 == group.len();
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
            continue;
        }
        let checkpoint = state.clone();
        let resolved_len = resolved.len();
        let failed_len = failed_joins.len();
        let mut tentative = Vec::new();
        let mut group_failed = false;
        for row in &legs {
            let applied = apply_row(&mut state, config, &mut refusals, row);
            if applied.failed {
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
        state = checkpoint;
        resolved.truncate(resolved_len);
        failed_joins.truncate(failed_len);
        for row in &legs {
            let specific = tentative
                .iter()
                .find(|applied| applied.resolved.row_id == row.row_id && applied.failed)
                .map(|applied| applied.resolved.note.clone());
            let note = specific.unwrap_or_else(|| {
                "atomic group not proved; legs stay separate".to_string()
            });
            resolved.push(unknown_row(row, note));
            failed_joins.push(row.row_id.clone());
            push_unlinked_sample(&mut state, row);
        }
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
pub fn reconcile(
    baseline: &[BaselineEntry],
    outcome: &ReplayOutcome,
) -> Reconciliation {
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
