// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded lifecycle correlation over normalized events.
//!
//! The registry proves relationships without raw addresses, PID or
//! timestamp proximity, or hidden collector state:
//!
//! - Operation identity opens with a bounce attempt and precedes
//!   any mapping result. A failed allocation creates no mapping,
//!   but an actual copy observed before the failure stays paired.
//! - Each successful mapping joins one live generation per
//!   (device, namespace) lineage. A reused token gets a new
//!   generation; the same token under another namespace is a
//!   distinct lineage that never merges.
//! - Sync and unmap resolve only against the live generation.
//!   Repeat or unknown releases stay unpaired; retired tombstones
//!   are a bounded ring, so references older than retained
//!   evidence stay uncertain instead of borrowing certainty.
//! - Observer cpu/pid/tgid/comm is execution context and never
//!   enters a pairing key.
//! - Hook names map to address namespaces through the admitted
//!   profile table only. Events from unadmitted hooks stay
//!   unpaired.
//!
//! Pending holds unresolved operations only: each result moves
//! its operation into bounded resolved history, so completed
//! churn never refuses new attempts as pending exhaustion.
//! Resolved pressure degrades correlation quality explicitly,
//! and references past the retained horizon stay uncertain
//! instead of borrowing duplicate or nesting verdicts.
//! A copy naming a live mapping pairs against the mapping's
//! recorded operation, so delayed references survive resolved
//! turnover; copies against wire-created mappings still need a
//! known operation. Budgets are constructor parameters so tests
//! prove N/N+1 logic on small instances while production uses
//! the contract ceilings.

use std::collections::{HashMap, HashSet};

use crate::model::event::Event;
use crate::model::identity::{
    ACTIVE_MAX, DEVICE_MAX_ID, NESTED_MAX, PENDING_MAX, RESOLVED_MAX, RETIRED_MAX,
    check_address_space,
};
use crate::model::session::Channel;
use crate::model::validate::format_u64;

/// Relation class owning mapping/release pairing.
pub const CLS_MAPPING: u8 = 0;
/// Relation class owning copy attribution.
pub const CLS_COPY: u8 = 1;
/// Relation class owning sync attribution.
pub const CLS_SYNC: u8 = 2;

/// One correlation input failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorrelationError {
    /// Human-readable failure.
    pub message: String,
}

impl CorrelationError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CorrelationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CorrelationError {}

/// Production budget ceilings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryBudgets {
    /// Pending-operation ceiling.
    pub pending: usize,
    /// Live-mapping ceiling.
    pub active: usize,
    /// Per-operation nesting ceiling.
    pub nested: usize,
    /// Retired-tombstone ring ceiling.
    pub retired: usize,
    /// Distinct-device ceiling.
    pub devices: usize,
    /// Resolved-history ring ceiling.
    pub resolved: usize,
}

/// Contract ceilings used by default registry instances.
pub fn budgets() -> RegistryBudgets {
    RegistryBudgets {
        pending: PENDING_MAX,
        active: ACTIVE_MAX,
        nested: NESTED_MAX,
        retired: RETIRED_MAX,
        devices: DEVICE_MAX_ID,
        resolved: RESOLVED_MAX,
    }
}

/// Producer correlation evidence: aggregate plus classes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CorrelationHealth {
    /// Aggregate rollup over the three classes.
    pub aggregate: Channel,
    /// Mapping/release class channel.
    pub mapping_release: Channel,
    /// Copy attribution class channel.
    pub copy_attribution: Channel,
    /// Sync attribution class channel.
    pub sync_attribution: Channel,
}

/// Pairing validator with bounded pending/active/resolved stores.
///
/// Pending holds unresolved operations only; each result moves
/// its operation into the bounded resolved ring, whose pressure
/// degrades quality explicitly.
#[derive(Debug)]
pub struct CorrelationRegistry {
    budgets: RegistryBudgets,
    _hooks: HashMap<String, String>,
    _pending: HashMap<String, PendingOp>,
    _resolved: HashSet<String>,
    _resolved_order: Vec<String>,
    _resolved_next: usize,
    _active: HashMap<String, ActiveMapping>,
    _retired: HashMap<String, u64>,
    _retired_order: Vec<String>,
    _retired_next: usize,
    _lineage_next: HashMap<String, usize>,
    _devices: HashSet<String>,
    _unpaired: usize,
    _unpaired_map: usize,
    _unpaired_copy: usize,
    _unpaired_sync: usize,
    _causes_map: HashSet<String>,
    _causes_copy: HashSet<String>,
    _causes_sync: HashSet<String>,
    _cause_order_map: Vec<String>,
    _cause_order_copy: Vec<String>,
    _cause_order_sync: Vec<String>,
    _cause_codes_map: Vec<String>,
    _cause_codes_copy: Vec<String>,
    _cause_codes_sync: Vec<String>,
    _refs_map: Vec<String>,
    _refs_copy: Vec<String>,
    _refs_sync: Vec<String>,
}

#[derive(Debug, Clone)]
struct PendingOp {
    device: String,
    nested: usize,
}

#[derive(Debug, Clone)]
struct ActiveMapping {
    op: String,
    generation: u64,
    wire: bool,
}

impl Default for CorrelationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CorrelationRegistry {
    /// A registry with the contract ceiling budgets.
    pub fn new() -> Self {
        Self::with_budgets(budgets())
    }

    /// A registry with explicit budgets (tests prove N/N+1 logic).
    pub fn with_budgets(b: RegistryBudgets) -> Self {
        Self {
            budgets: b,
            _hooks: HashMap::new(),
            _pending: HashMap::new(),
            _resolved: HashSet::new(),
            _resolved_order: Vec::new(),
            _resolved_next: 0,
            _active: HashMap::new(),
            _retired: HashMap::new(),
            _retired_order: Vec::new(),
            _retired_next: 0,
            _lineage_next: HashMap::new(),
            _devices: HashSet::new(),
            _unpaired: 0,
            _unpaired_map: 0,
            _unpaired_copy: 0,
            _unpaired_sync: 0,
            _causes_map: HashSet::new(),
            _causes_copy: HashSet::new(),
            _causes_sync: HashSet::new(),
            _cause_order_map: Vec::new(),
            _cause_order_copy: Vec::new(),
            _cause_order_sync: Vec::new(),
            _cause_codes_map: Vec::new(),
            _cause_codes_copy: Vec::new(),
            _cause_codes_sync: Vec::new(),
            _refs_map: Vec::new(),
            _refs_copy: Vec::new(),
            _refs_sync: Vec::new(),
        }
    }

    /// Admit one hook under an address namespace.
    pub fn admit_hook(&mut self, hook: &str, namespace: &str) -> Result<(), CorrelationError> {
        check_address_space(namespace).map_err(|err| {
            CorrelationError::new(format!("bad namespace {namespace}: {}", err.message))
        })?;
        if hook.is_empty() {
            return Err(CorrelationError::new("empty hook name"));
        }
        self._hooks.insert(hook.to_string(), namespace.to_string());
        Ok(())
    }

    /// Number of live mappings.
    pub fn active_count(&self) -> usize {
        self._active.len()
    }

    /// Generation of one mapping token, live or retired.
    pub fn generation_of(
        &self,
        device: &str,
        namespace: &str,
        mapping: &str,
    ) -> Result<u64, CorrelationError> {
        let _ = device;
        let key = format!("{namespace}|{mapping}");
        if let Some(m) = self._active.get(&key) {
            return Ok(m.generation);
        }
        if let Some(generation) = self._retired.get(&key) {
            return Ok(*generation);
        }
        Err(CorrelationError::new(format!("unknown mapping {mapping}")))
    }

    /// Correlation quality: aggregate rollup plus classes.
    pub fn health_full(&self) -> CorrelationHealth {
        let mapping_release = self.class_channel(CLS_MAPPING);
        let copy_attribution = self.class_channel(CLS_COPY);
        let sync_attribution = self.class_channel(CLS_SYNC);
        let aggregate = rollup_correlation(
            &mapping_release,
            &copy_attribution,
            &sync_attribution,
            &self._cause_order_map,
            &self._cause_order_copy,
            &self._cause_order_sync,
        );
        CorrelationHealth {
            aggregate,
            mapping_release,
            copy_attribution,
            sync_attribution,
        }
    }

    /// Correlation quality aggregate: paired scope or causes.
    pub fn health(&self) -> Channel {
        self.health_full().aggregate
    }

    /// Validate one event's pairing and label it.
    ///
    /// Lifecycle kinds return with source_correlation direct or
    /// unpaired; other kinds pass through untouched. Raises only
    /// for malformed records and empty sources, never for an
    /// unproved relationship.
    pub fn normalize(&mut self, ev: Event, source: &str) -> Result<Event, CorrelationError> {
        if source.is_empty() {
            return Err(CorrelationError::new("empty source"));
        }
        if !is_lifecycle(&ev.kind) {
            return Ok(ev);
        }
        let hook = ev.source_hook.clone();
        let namespace = match self._hooks.get(&hook) {
            Some(namespace) => namespace.clone(),
            None => {
                let cls = class_for_kind(&ev.kind);
                return Ok(self.unpaired_event(
                    ev,
                    "hook not admitted",
                    &format!(": {hook}"),
                    source,
                    cls,
                ));
            }
        };
        match ev.kind.as_str() {
            "bounce_attempt" => self.open_attempt(ev, &namespace, source),
            "map_result" => self.apply_map_result(ev, &namespace, source),
            "copy" => self.apply_copy(ev, &namespace, source),
            "sync_request" => self.apply_sync(ev, &namespace, source),
            _ => self.apply_unmap(ev, &namespace, source),
        }
    }

    /// One relation class: paired scope or its own causes.
    fn class_channel(&self, cls: u8) -> Channel {
        let mut out = Channel::default();
        let (scope, done, n) = match cls {
            CLS_COPY => (
                CORR_SCOPE_COPY,
                "all copy attribution relationships paired",
                self._unpaired_copy,
            ),
            CLS_SYNC => (
                CORR_SCOPE_SYNC,
                "all sync attribution relationships paired",
                self._unpaired_sync,
            ),
            _ => (
                CORR_SCOPE_MAPPING,
                "all mapping and release relationships paired",
                self._unpaired_map,
            ),
        };
        out.scope = scope.to_string();
        if n == 0 {
            out.status = "complete_for_scope".to_string();
            out.has_loss_count = true;
            out.loss_count = 0;
            out.reason = done.to_string();
            return out;
        }
        out.status = "partial".to_string();
        let (order, codes, refs) = match cls {
            CLS_COPY => (
                &self._cause_order_copy,
                &self._cause_codes_copy,
                &self._refs_copy,
            ),
            CLS_SYNC => (
                &self._cause_order_sync,
                &self._cause_codes_sync,
                &self._refs_sync,
            ),
            _ => (
                &self._cause_order_map,
                &self._cause_codes_map,
                &self._refs_map,
            ),
        };
        out.reason = bound_cause_reason(order, codes);
        out.evidence_refs.extend(refs.iter().cloned());
        out
    }

    /// Record one unpaired event under a fixed class cause code.
    ///
    /// Deduplication keys on the (class, code) pair only: the
    /// first identity example is retained for diagnosis and
    /// later identities under the same code add no storage, so
    /// diagnostic history plateaus with the code set instead of
    /// growing per operation or mapping identity. A cause never
    /// merges across classes, so copy uncertainty cannot excuse
    /// a dangling sync reference.
    fn note(&mut self, cls: u8, code: &str, example: &str, seq: u64, source: &str) {
        self._unpaired += 1;
        let anchor = format!("{source}:seq={}", format_u64(seq));
        let (count, causes, order, codes, refs) = match cls {
            CLS_COPY => (
                &mut self._unpaired_copy,
                &mut self._causes_copy,
                &mut self._cause_order_copy,
                &mut self._cause_codes_copy,
                &mut self._refs_copy,
            ),
            CLS_SYNC => (
                &mut self._unpaired_sync,
                &mut self._causes_sync,
                &mut self._cause_order_sync,
                &mut self._cause_codes_sync,
                &mut self._refs_sync,
            ),
            _ => (
                &mut self._unpaired_map,
                &mut self._causes_map,
                &mut self._cause_order_map,
                &mut self._cause_codes_map,
                &mut self._refs_map,
            ),
        };
        *count += 1;
        if !causes.contains(code) {
            causes.insert(code.to_string());
            codes.push(code.to_string());
            if example.is_empty() {
                order.push(code.to_string());
            } else {
                order.push(format!("{code}{example}"));
            }
        }
        if refs.len() < 8 {
            refs.push(anchor);
        }
    }

    /// Label one event unpaired under one relation class.
    ///
    /// The mapping/release class is the default: attempt, map,
    /// and unmap pairing plus resolved-history pressure. Copy
    /// and sync call sites pass their class explicitly.
    fn unpaired_event(
        &mut self,
        mut ev: Event,
        code: &str,
        example: &str,
        source: &str,
        cls: u8,
    ) -> Event {
        self.note(cls, code, example, ev.seq, source);
        ev.source_correlation = "unpaired".to_string();
        ev
    }

    fn open_attempt(
        &mut self,
        mut ev: Event,
        _namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        let op = ev.bounce.operation_id.clone();
        let dev = ev.bounce.device_id.clone();
        if op.is_empty() || dev.is_empty() {
            return Err(CorrelationError::new("malformed attempt"));
        }
        if self._pending.contains_key(&op) || self._resolved.contains(&op) {
            return Ok(self.unpaired_event(
                ev,
                "duplicate operation",
                &format!(" {op}"),
                source,
                CLS_MAPPING,
            ));
        }
        if !self._devices.contains(&dev) {
            if self._devices.len() >= self.budgets.devices {
                return Ok(self.unpaired_event(
                    ev,
                    "device table exhausted",
                    "",
                    source,
                    CLS_MAPPING,
                ));
            }
            self._devices.insert(dev.clone());
        }
        if self._pending.len() >= self.budgets.pending {
            return Ok(self.unpaired_event(ev, "pending table exhausted", "", source, CLS_MAPPING));
        }
        self._pending.insert(
            op,
            PendingOp {
                device: dev,
                nested: 0,
            },
        );
        ev.source_correlation = "direct".to_string();
        Ok(ev)
    }

    fn wire_gen_token(generation: u64) -> String {
        format!("gen-{}", format_u64(generation))
    }

    /// Pair one MVLC v2 map without requiring an attempt.
    ///
    /// Precedence: wire-identity validation, then duplicate and
    /// bound checks, then active-state insert. Unknown identities
    /// land unpaired with explicit causes and never mint.
    fn apply_wire_map(
        &mut self,
        mut ev: Event,
        namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        let op = ev.map_result.operation_id.clone();
        let generation = ev.map_result.wire_generation;
        if !ev.map_result.success {
            if ev.map_result.has_wire_identity {
                return Err(CorrelationError::new("failure carries wire_identity"));
            }
            if generation != 0 {
                return Err(CorrelationError::new("failure carries generation"));
            }
            return Ok(self.unpaired_event(
                ev,
                "failure carries no mapping",
                "",
                source,
                CLS_MAPPING,
            ));
        }
        if !ev.map_result.has_wire_identity {
            return Err(CorrelationError::new("success lacks wire_identity"));
        }
        let ident = ev.map_result.wire_identity.clone();
        if ident != "known" && ident != "unassigned" {
            return Err(CorrelationError::new("bad wire_identity"));
        }
        if ident == "unassigned" {
            if ev.map_result.has_mapping_id {
                return Err(CorrelationError::new("unassigned carries mapping"));
            }
            return Ok(self.unpaired_event(
                ev,
                "unassigned mapping identity",
                "",
                source,
                CLS_MAPPING,
            ));
        }
        if !ev.map_result.has_mapping_id {
            return Err(CorrelationError::new("known identity lacks mapping"));
        }
        if ev.map_result.mapping_id != Self::wire_gen_token(generation) {
            return Err(CorrelationError::new("wire mapping/generation mismatch"));
        }
        if !ev.map_result.has_mapped_bytes {
            return Err(CorrelationError::new("success lacks mapped_bytes"));
        }
        let key = format!("{namespace}|{}", ev.map_result.mapping_id);
        if self._active.contains_key(&key) {
            let example = format!(": {}", ev.map_result.mapping_id);
            return Ok(self.unpaired_event(
                ev,
                "mapping already live",
                &example,
                source,
                CLS_MAPPING,
            ));
        }
        if self._active.len() >= self.budgets.active {
            return Ok(self.unpaired_event(ev, "active table exhausted", "", source, CLS_MAPPING));
        }
        self._active.insert(
            key,
            ActiveMapping {
                op,
                generation,
                wire: true,
            },
        );
        ev.source_correlation = "direct".to_string();
        Ok(ev)
    }

    fn apply_map_result(
        &mut self,
        mut ev: Event,
        namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        let op = ev.map_result.operation_id.clone();
        if op.is_empty() {
            return Err(CorrelationError::new("malformed map_result"));
        }
        if ev.map_result.has_wire_generation {
            return self.apply_wire_map(ev, namespace, source);
        }
        if self._resolved.contains(&op) {
            return Ok(self.unpaired_event(
                ev,
                "duplicate result",
                &format!(" for {op}"),
                source,
                CLS_MAPPING,
            ));
        }
        if !self._pending.contains_key(&op) {
            return Ok(self.unpaired_event(
                ev,
                "map_result without pending operation",
                "",
                source,
                CLS_MAPPING,
            ));
        }
        let p = self._pending.get(&op).cloned().expect("pending checked");
        if !ev.map_result.success {
            if ev.map_result.has_mapping_id {
                return Err(CorrelationError::new("failure carries mapping"));
            }
            self._pending.remove(&op);
            self.remember_resolved(&op, ev.seq, source);
            ev.source_correlation = "direct".to_string();
            return Ok(ev);
        }
        if !ev.map_result.has_mapping_id {
            return Err(CorrelationError::new("success lacks mapping"));
        }
        if !ev.map_result.has_mapped_bytes {
            return Err(CorrelationError::new("success lacks mapped_bytes"));
        }
        let key = format!("{namespace}|{}", ev.map_result.mapping_id);
        if self._active.contains_key(&key) {
            let example = format!(": {}", ev.map_result.mapping_id);
            return Ok(self.unpaired_event(
                ev,
                "mapping already live",
                &example,
                source,
                CLS_MAPPING,
            ));
        }
        if self._active.len() >= self.budgets.active {
            return Ok(self.unpaired_event(ev, "active table exhausted", "", source, CLS_MAPPING));
        }
        let lineage = format!("{}|{namespace}", p.device);
        let generation = self._lineage_next.get(&lineage).copied().unwrap_or(1);
        self._lineage_next.insert(lineage, generation + 1);
        self._active.insert(
            key,
            ActiveMapping {
                op: op.clone(),
                generation: generation as u64,
                wire: false,
            },
        );
        self._pending.remove(&op);
        self.remember_resolved(&op, ev.seq, source);
        ev.source_correlation = "direct".to_string();
        Ok(ev)
    }

    fn apply_copy(
        &mut self,
        mut ev: Event,
        namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        let op = ev.copy.operation_id.clone();
        if op.is_empty() {
            return Err(CorrelationError::new("malformed copy"));
        }
        if ev.copy.has_mapping_id {
            let key = format!("{namespace}|{}", ev.copy.mapping_id);
            let Some(m) = self._active.get(&key) else {
                return Ok(self.unpaired_event(
                    ev,
                    "copy references unknown mapping",
                    "",
                    source,
                    CLS_COPY,
                ));
            };
            if m.op != op {
                return Ok(self.unpaired_event(
                    ev,
                    "copy operation mismatch",
                    "",
                    source,
                    CLS_COPY,
                ));
            }
            let known = self._pending.contains_key(&op) || self._resolved.contains(&op);
            if !known && m.wire {
                return Ok(self.unpaired_event(
                    ev,
                    "copy without pending operation",
                    "",
                    source,
                    CLS_COPY,
                ));
            }
            ev.source_correlation = "direct".to_string();
            return Ok(ev);
        }
        if self._resolved.contains(&op) {
            return Ok(self.unpaired_event(
                ev,
                "copy after operation resolved",
                "",
                source,
                CLS_COPY,
            ));
        }
        if !self._pending.contains_key(&op) {
            return Ok(self.unpaired_event(
                ev,
                "copy without pending operation",
                "",
                source,
                CLS_COPY,
            ));
        }
        let nested = self._pending.get(&op).map(|p| p.nested).unwrap_or(0);
        if nested >= self.budgets.nested {
            return Ok(self.unpaired_event(ev, "nesting budget exceeded", "", source, CLS_COPY));
        }
        if let Some(p) = self._pending.get_mut(&op) {
            p.nested += 1;
        }
        ev.source_correlation = "direct".to_string();
        Ok(ev)
    }

    fn apply_sync(
        &mut self,
        mut ev: Event,
        namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        let op = ev.sync.operation_id.clone();
        if op.is_empty() || !ev.sync.has_mapping_id {
            return Err(CorrelationError::new("malformed sync_request"));
        }
        let key = format!("{namespace}|{}", ev.sync.mapping_id);
        let Some(m) = self._active.get(&key) else {
            return Ok(self.unpaired_event(
                ev,
                "sync references unknown mapping",
                "",
                source,
                CLS_SYNC,
            ));
        };
        if m.op != op {
            return Ok(self.unpaired_event(ev, "sync operation mismatch", "", source, CLS_SYNC));
        }
        ev.source_correlation = "direct".to_string();
        Ok(ev)
    }

    fn apply_unmap(
        &mut self,
        mut ev: Event,
        namespace: &str,
        source: &str,
    ) -> Result<Event, CorrelationError> {
        if ev.unmap.has_wire_generation {
            if !ev.unmap.has_wire_identity {
                return Err(CorrelationError::new("unmap lacks wire_identity"));
            }
            let ident = ev.unmap.wire_identity.clone();
            if ident != "known" && ident != "miss" {
                return Err(CorrelationError::new("bad wire_identity"));
            }
            if ident == "miss" {
                if ev.unmap.has_mapping_id {
                    return Err(CorrelationError::new("miss carries mapping"));
                }
                return Ok(self.unpaired_event(
                    ev,
                    "release of unknown mapping",
                    "",
                    source,
                    CLS_MAPPING,
                ));
            }
            if !ev.unmap.has_mapping_id {
                return Err(CorrelationError::new("known identity lacks mapping"));
            }
            if ev.unmap.mapping_id != Self::wire_gen_token(ev.unmap.wire_generation) {
                return Err(CorrelationError::new("wire mapping/generation mismatch"));
            }
        }
        if !ev.unmap.has_mapping_id {
            return Err(CorrelationError::new("malformed unmap"));
        }
        let key = format!("{namespace}|{}", ev.unmap.mapping_id);
        if let Some(m) = self._active.remove(&key) {
            self.retire(&key, m.generation);
            ev.source_correlation = "direct".to_string();
            return Ok(ev);
        }
        if self._retired.contains_key(&key) {
            return Ok(self.unpaired_event(
                ev,
                "release of retired mapping",
                "",
                source,
                CLS_MAPPING,
            ));
        }
        Ok(self.unpaired_event(ev, "release of unknown mapping", "", source, CLS_MAPPING))
    }

    /// Move one resolved operation into bounded history.
    ///
    /// Eviction is explicit: forgotten operations lose their
    /// duplicate and nesting verdicts, and correlation quality
    /// records the pressure instead of refusing new attempts as
    /// pending exhaustion.
    fn remember_resolved(&mut self, op: &str, seq: u64, source: &str) {
        if self._resolved.contains(op) {
            return;
        }
        if self.budgets.resolved == 0 {
            return;
        }
        if self._resolved_order.len() < self.budgets.resolved {
            self._resolved_order.push(op.to_string());
        } else {
            let victim = self._resolved_order[self._resolved_next].clone();
            self._resolved.remove(&victim);
            self._resolved_order[self._resolved_next] = op.to_string();
            self._resolved_next += 1;
            if self._resolved_next >= self.budgets.resolved {
                self._resolved_next = 0;
            }
            self.note(
                CLS_MAPPING,
                "resolved-operation history exceeded",
                "",
                seq,
                source,
            );
        }
        self._resolved.insert(op.to_string());
    }

    /// Record one tombstone in the bounded ring.
    fn retire(&mut self, key: &str, generation: u64) {
        if self._retired.contains_key(key) {
            self._retired.insert(key.to_string(), generation);
            return;
        }
        if self.budgets.retired == 0 {
            return;
        }
        if self._retired_order.len() < self.budgets.retired {
            self._retired_order.push(key.to_string());
        } else {
            let victim = self._retired_order[self._retired_next].clone();
            self._retired.remove(&victim);
            self._retired_order[self._retired_next] = key.to_string();
            self._retired_next += 1;
            if self._retired_next >= self.budgets.retired {
                self._retired_next = 0;
            }
        }
        self._retired.insert(key.to_string(), generation);
    }
}

fn is_lifecycle(kind: &str) -> bool {
    matches!(
        kind,
        "bounce_attempt" | "map_result" | "copy" | "sync_request" | "unmap"
    )
}

/// Relation class owning one lifecycle kind's pairing.
fn class_for_kind(kind: &str) -> u8 {
    if kind == "copy" {
        CLS_COPY
    } else if kind == "sync_request" {
        CLS_SYNC
    } else {
        CLS_MAPPING
    }
}

const CORR_RELATION_MAPPING: &str = "mapping_release";
const CORR_RELATION_COPY: &str = "copy_attribution";
const CORR_RELATION_SYNC: &str = "sync_attribution";
const CORR_SCOPE_MAPPING: &str = "mapping and release pairing";
const CORR_SCOPE_COPY: &str = "copy attribution";
const CORR_SCOPE_SYNC: &str = "sync attribution";

/// Cap text at limit codepoints, on a char boundary.
fn truncate_codepoints(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect()
}

fn join_causes(items: &[String]) -> String {
    items.join("; ")
}

/// Bound one per-class cause list to the 512-char channel limit.
///
/// Full code-plus-example text first, then codes only, then
/// trailing causes drop; the first code is always kept. Callers
/// pass at least one cause.
fn bound_cause_reason(causes: &[String], codes: &[String]) -> String {
    let full = join_causes(causes);
    if full.chars().count() <= 512 {
        return full;
    }
    let short = join_causes(codes);
    if short.chars().count() <= 512 {
        return short;
    }
    let mut kept = codes.len();
    while kept > 1 {
        kept -= 1;
        if join_causes(&codes[..kept]).chars().count() <= 512 {
            return join_causes(&codes[..kept]);
        }
    }
    truncate_codepoints(&codes[0], 512)
}

/// Aggregate status over the three relation classes.
///
/// The producer and the analyzer apply this same rule:
/// not_applicable only when every class is, complete only when
/// every class is, else partial.
fn rollup_correlation_status(mapping: &Channel, copy: &Channel, sync: &Channel) -> String {
    if mapping.status == "not_applicable"
        && copy.status == "not_applicable"
        && sync.status == "not_applicable"
    {
        return "not_applicable".to_string();
    }
    if mapping.status == "complete_for_scope"
        && copy.status == "complete_for_scope"
        && sync.status == "complete_for_scope"
    {
        return "complete_for_scope".to_string();
    }
    "partial".to_string()
}

/// Render class tokens plus their kept causes, in class order.
fn render_rollup(
    statuses: &[String],
    kept_map: &[String],
    kept_copy: &[String],
    kept_sync: &[String],
) -> String {
    let relations = [
        CORR_RELATION_MAPPING,
        CORR_RELATION_COPY,
        CORR_RELATION_SYNC,
    ];
    let kept_all = [kept_map, kept_copy, kept_sync];
    let mut out = String::new();
    let mut first = true;
    for ((status, relation), kept) in statuses.iter().zip(relations.iter()).zip(kept_all.iter()) {
        if status == "complete_for_scope" {
            continue;
        }
        if !first {
            out += "; ";
        }
        first = false;
        out += relation;
        out += " ";
        out += status;
        if !kept.is_empty() {
            out += " (";
            out += &join_causes(kept);
            out += ")";
        }
    }
    out
}

/// Bounded aggregate summary naming every non-complete class.
///
/// Every affected class keeps its "<class> <status>" token;
/// causes fill the remaining 512-char budget in fixed class
/// order, so later detail drops before any class name does.
fn rollup_correlation_reason(
    mapping: &Channel,
    copy: &Channel,
    sync: &Channel,
    mapping_causes: &[String],
    copy_causes: &[String],
    sync_causes: &[String],
) -> String {
    let statuses = [
        mapping.status.clone(),
        copy.status.clone(),
        sync.status.clone(),
    ];
    let affected = statuses
        .iter()
        .filter(|s| s.as_str() != "complete_for_scope")
        .count();
    if affected == 0 {
        return "all lifecycle events paired".to_string();
    }
    if statuses.iter().all(|s| s == "not_applicable") {
        return "no cross-event correlation in scope".to_string();
    }
    let mut kept_map: Vec<String> = Vec::new();
    let mut kept_copy: Vec<String> = Vec::new();
    let mut kept_sync: Vec<String> = Vec::new();
    let mut order: Vec<usize> = Vec::new();
    for (i, status) in statuses.iter().enumerate() {
        if status != "complete_for_scope" {
            order.push(i);
        }
    }
    let mut stopped = false;
    for cls in order {
        if stopped {
            break;
        }
        let total = match cls {
            0 => mapping_causes.len(),
            1 => copy_causes.len(),
            _ => sync_causes.len(),
        };
        for c in 0..total {
            let cause = match cls {
                0 => &mapping_causes[c],
                1 => &copy_causes[c],
                _ => &sync_causes[c],
            };
            match cls {
                0 => kept_map.push(cause.clone()),
                1 => kept_copy.push(cause.clone()),
                _ => kept_sync.push(cause.clone()),
            }
            let rendered = render_rollup(&statuses, &kept_map, &kept_copy, &kept_sync);
            if rendered.chars().count() <= 512 {
                continue;
            }
            match cls {
                0 => kept_map.pop(),
                1 => kept_copy.pop(),
                _ => kept_sync.pop(),
            };
            let base = render_rollup(&statuses, &kept_map, &kept_copy, &kept_sync);
            let kept_len = match cls {
                0 => kept_map.len(),
                1 => kept_copy.len(),
                _ => kept_sync.len(),
            };
            let overhead: isize = if kept_len == 0 { 3 } else { 2 };
            let room = 512isize - base.chars().count() as isize - overhead;
            if room >= 16 {
                let frag = truncate_codepoints(cause, room as usize);
                match cls {
                    0 => kept_map.push(frag),
                    1 => kept_copy.push(frag),
                    _ => kept_sync.push(frag),
                }
            }
            stopped = true;
            break;
        }
    }
    render_rollup(&statuses, &kept_map, &kept_copy, &kept_sync)
}

/// Aggregate channel over three relation classes, same rule.
///
/// Fixed class order, bounded reason, per-class refs
/// concatenated and capped at 8. The session-side loss
/// convention is 0 when complete, null when partial.
fn rollup_correlation(
    mapping: &Channel,
    copy: &Channel,
    sync: &Channel,
    mapping_causes: &[String],
    copy_causes: &[String],
    sync_causes: &[String],
) -> Channel {
    let status = rollup_correlation_status(mapping, copy, sync);
    let complete = status == "complete_for_scope";
    let mut out = Channel {
        status,
        has_loss_count: complete,
        loss_count: 0,
        scope: "correlated lifecycle events".to_string(),
        reason: rollup_correlation_reason(
            mapping,
            copy,
            sync,
            mapping_causes,
            copy_causes,
            sync_causes,
        ),
        evidence_refs: Vec::new(),
    };
    for r in mapping
        .evidence_refs
        .iter()
        .chain(copy.evidence_refs.iter())
        .chain(sync.evidence_refs.iter())
    {
        if out.evidence_refs.len() >= 8 {
            break;
        }
        out.evidence_refs.push(r.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::identity::{ACTIVE_MAX, DEVICE_MAX_ID, NESTED_MAX, PENDING_MAX};
    use crate::model::identity::{RESOLVED_MAX, RETIRED_MAX};

    fn reg_with(
        pending: usize,
        active: usize,
        nested: usize,
        retired: usize,
        devices: usize,
        resolved: usize,
    ) -> CorrelationRegistry {
        CorrelationRegistry::with_budgets(RegistryBudgets {
            pending,
            active,
            nested,
            retired,
            devices,
            resolved,
        })
    }

    fn base(kind: &str, hook: &str, seq: u64) -> Event {
        Event {
            session_id: "s1".to_string(),
            seq,
            ts_ns: 1000 + seq,
            kind: kind.to_string(),
            source_hook: hook.to_string(),
            source_backend: "test".to_string(),
            source_profile_id: "p1".to_string(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ..Default::default()
        }
    }

    fn attempt(op: &str, device: &str, hook: &str, seq: u64) -> Event {
        let mut ev = base("bounce_attempt", hook, seq);
        ev.bounce.device_id = device.to_string();
        ev.bounce.requested_bytes = 4096;
        ev.bounce.operation_id = op.to_string();
        ev
    }

    fn map(op: &str, ok: bool, mapping: &str, hook: &str, seq: u64) -> Event {
        let mut ev = base("map_result", hook, seq);
        ev.map_result.operation_id = op.to_string();
        ev.map_result.success = ok;
        if !mapping.is_empty() {
            ev.map_result.has_mapping_id = true;
            ev.map_result.mapping_id = mapping.to_string();
        }
        if ok {
            ev.map_result.has_mapped_bytes = true;
            ev.map_result.mapped_bytes = 4096;
        } else {
            ev.map_result.has_return_code = true;
            ev.map_result.return_code = -12;
        }
        ev
    }

    fn copy(op: &str, mapping: &str, hook: &str, seq: u64) -> Event {
        let mut ev = base("copy", hook, seq);
        ev.copy.operation_id = op.to_string();
        if !mapping.is_empty() {
            ev.copy.has_mapping_id = true;
            ev.copy.mapping_id = mapping.to_string();
        }
        ev.copy.direction = "original_to_bounce".to_string();
        ev.copy.bytes = 1024;
        ev
    }

    fn sync(op: &str, mapping: &str, hook: &str, seq: u64) -> Event {
        let mut ev = base("sync_request", hook, seq);
        ev.sync.operation_id = op.to_string();
        if !mapping.is_empty() {
            ev.sync.has_mapping_id = true;
            ev.sync.mapping_id = mapping.to_string();
        }
        ev.sync.has_offset = true;
        ev.sync.length = 1024;
        ev
    }

    fn unmap(mapping: &str, hook: &str, seq: u64) -> Event {
        let mut ev = base("unmap", hook, seq);
        if !mapping.is_empty() {
            ev.unmap.has_mapping_id = true;
            ev.unmap.mapping_id = mapping.to_string();
        }
        ev
    }

    fn wire_map(op: &str, generation: u64, hook: &str, seq: u64) -> Event {
        let mut ev = base("map_result", hook, seq);
        ev.map_result.operation_id = op.to_string();
        ev.map_result.success = true;
        ev.map_result.has_mapping_id = true;
        ev.map_result.mapping_id = format!("gen-{generation}");
        ev.map_result.has_mapped_bytes = true;
        ev.map_result.mapped_bytes = 4096;
        ev.map_result.has_wire_generation = true;
        ev.map_result.wire_generation = generation;
        ev.map_result.has_wire_identity = true;
        ev.map_result.wire_identity = "known".to_string();
        ev
    }

    fn wire_unmap(generation: u64, hook: &str, seq: u64) -> Event {
        let mut ev = base("unmap", hook, seq);
        ev.unmap.has_mapping_id = true;
        ev.unmap.mapping_id = format!("gen-{generation}");
        ev.unmap.has_wire_generation = true;
        ev.unmap.wire_generation = generation;
        ev.unmap.has_wire_identity = true;
        ev.unmap.wire_identity = "known".to_string();
        ev
    }

    fn paired(ev: &Event) -> bool {
        ev.source_correlation == "direct"
    }

    #[test]
    fn attempt_opens_pending() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let out = reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        assert!(paired(&out));
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn map_requires_pending() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let out = reg
            .normalize(map("ghost", true, "m1", "h", 1), "ring")
            .unwrap();
        assert!(!paired(&out));
        assert_eq!(reg.health().status, "partial");
    }

    #[test]
    fn map_success_creates_mapping() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        let out = reg
            .normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        assert!(paired(&out));
        assert_eq!(reg.generation_of("d1", "iova", "m1").unwrap(), 1);
        assert_eq!(reg.active_count(), 1);
    }

    #[test]
    fn same_address_new_generation() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        let rel = reg.normalize(unmap("m1", "h", 3), "ring").unwrap();
        assert!(paired(&rel));
        reg.normalize(attempt("op2", "d1", "h", 4), "ring").unwrap();
        let second = reg
            .normalize(map("op2", true, "m2", "h", 5), "ring")
            .unwrap();
        assert!(paired(&second));
        let g1 = reg.generation_of("d1", "iova", "m1").unwrap();
        let g2 = reg.generation_of("d1", "iova", "m2").unwrap();
        assert_ne!(g1, g2);
        assert_eq!(g2, 2);
    }

    #[test]
    fn cross_namespace_no_merge() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hk", "kvirt").unwrap();
        reg.admit_hook("hg", "gphys").unwrap();
        reg.normalize(attempt("op1", "d1", "hk", 1), "ring")
            .unwrap();
        reg.normalize(attempt("op2", "d1", "hg", 2), "ring")
            .unwrap();
        let a = reg
            .normalize(map("op1", true, "tok", "hk", 3), "ring")
            .unwrap();
        let b = reg
            .normalize(map("op2", true, "tok", "hg", 4), "ring")
            .unwrap();
        assert!(paired(&a));
        assert!(paired(&b));
        assert_eq!(reg.active_count(), 2);
        let rel = reg.normalize(unmap("tok", "hk", 5), "ring").unwrap();
        assert!(paired(&rel));
        assert_eq!(reg.active_count(), 1);
        let still = reg.normalize(sync("op2", "tok", "hg", 6), "ring").unwrap();
        assert!(paired(&still));
    }

    #[test]
    fn interior_sync_matches_live_generation() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        let live = reg.normalize(sync("op1", "m1", "h", 3), "ring").unwrap();
        assert!(paired(&live));
        reg.normalize(unmap("m1", "h", 4), "ring").unwrap();
        let stale = reg.normalize(sync("op1", "m1", "h", 5), "ring").unwrap();
        assert!(!paired(&stale));
    }

    #[test]
    fn nested_copy_before_result() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        let nested = reg.normalize(copy("op1", "", "h", 2), "ring").unwrap();
        assert!(paired(&nested));
        reg.normalize(map("op1", true, "m1", "h", 3), "ring")
            .unwrap();
        let direct = reg.normalize(copy("op1", "m1", "h", 4), "ring").unwrap();
        assert!(paired(&direct));
    }

    #[test]
    fn nesting_budget() {
        let mut reg = reg_with(65536, 65536, 1, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        let first = reg.normalize(copy("op1", "", "h", 2), "ring").unwrap();
        assert!(paired(&first));
        let second = reg.normalize(copy("op1", "", "h", 3), "ring").unwrap();
        assert!(!paired(&second));
        assert_eq!(reg.health().status, "partial");
    }

    #[test]
    fn nesting_budget_production_bound() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        for i in 0..NESTED_MAX {
            let cp = reg
                .normalize(copy("op1", "", "h", 2 + i as u64), "ring")
                .unwrap();
            assert!(paired(&cp));
        }
        let over = reg
            .normalize(copy("op1", "", "h", 2 + NESTED_MAX as u64), "ring")
            .unwrap();
        assert!(!paired(&over));
        assert_eq!(reg.health().status, "partial");
    }

    #[test]
    fn copy_preserved_when_map_fails() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        let cp = reg.normalize(copy("op1", "", "h", 2), "ring").unwrap();
        assert!(paired(&cp));
        let fail = reg
            .normalize(map("op1", false, "", "h", 3), "ring")
            .unwrap();
        assert!(paired(&fail));
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn copy_after_failure_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", false, "", "h", 2), "ring")
            .unwrap();
        let late = reg.normalize(copy("op1", "", "h", 3), "ring").unwrap();
        assert!(!paired(&late));
    }

    #[test]
    fn interrupt_context_not_origin() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let mut a = attempt("op1", "d1", "h", 1);
        a.has_observer = true;
        a.has_pid = true;
        a.pid = 11;
        reg.normalize(a, "ring").unwrap();
        let mut m = map("op1", true, "m1", "h", 2);
        m.has_observer = true;
        m.has_pid = true;
        m.pid = 99;
        let out = reg.normalize(m, "ring").unwrap();
        assert!(paired(&out));
    }

    #[test]
    fn duplicate_result_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        let dup = reg
            .normalize(map("op1", true, "m2", "h", 3), "ring")
            .unwrap();
        assert!(!paired(&dup));
    }

    #[test]
    fn unmap_unknown_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let out = reg.normalize(unmap("ghost", "h", 1), "ring").unwrap();
        assert!(!paired(&out));
    }

    #[test]
    fn retired_eviction_uncertain() {
        let mut reg = reg_with(65536, 65536, 8, 1, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        reg.normalize(unmap("m1", "h", 3), "ring").unwrap();
        reg.normalize(attempt("op2", "d1", "h", 4), "ring").unwrap();
        reg.normalize(map("op2", true, "m2", "h", 5), "ring")
            .unwrap();
        reg.normalize(unmap("m2", "h", 6), "ring").unwrap();
        let again = reg.normalize(unmap("m1", "h", 7), "ring").unwrap();
        assert!(!paired(&again));
    }

    #[test]
    fn pending_exhaustion() {
        let mut reg = reg_with(1, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let first = reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        assert!(paired(&first));
        let second = reg.normalize(attempt("op2", "d1", "h", 2), "ring").unwrap();
        assert!(!paired(&second));
        assert_eq!(reg.health().status, "partial");
    }

    #[test]
    fn device_exhaustion() {
        let mut reg = reg_with(65536, 65536, 8, 16384, 1, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let first = reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        assert!(paired(&first));
        let second = reg.normalize(attempt("op2", "d2", "h", 2), "ring").unwrap();
        assert!(!paired(&second));
    }

    #[test]
    fn active_exhaustion() {
        let mut reg = reg_with(65536, 1, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        reg.normalize(attempt("op2", "d1", "h", 3), "ring").unwrap();
        let over = reg
            .normalize(map("op2", true, "m2", "h", 4), "ring")
            .unwrap();
        assert!(!paired(&over));
    }

    #[test]
    fn hook_not_admitted() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let out = reg
            .normalize(attempt("op1", "d1", "other", 1), "ring")
            .unwrap();
        assert!(!paired(&out));
    }

    #[test]
    fn default_budgets() {
        let b = budgets();
        assert_eq!(b.pending, PENDING_MAX);
        assert_eq!(b.active, ACTIVE_MAX);
        assert_eq!(b.nested, NESTED_MAX);
        assert_eq!(b.retired, RETIRED_MAX);
        assert_eq!(b.devices, DEVICE_MAX_ID);
        assert_eq!(b.resolved, RESOLVED_MAX);
    }

    #[test]
    fn malformed_raises() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        let bad = map("op1", true, "", "h", 2);
        assert!(reg.normalize(bad, "ring").is_err());
    }

    #[test]
    fn empty_source_raises() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        assert!(reg.normalize(attempt("op1", "d1", "h", 1), "").is_err());
    }

    #[test]
    fn non_lifecycle_passthrough() {
        let mut reg = CorrelationRegistry::new();
        let mut ev = base("gap", "any", 1);
        ev.gap.channel = "detail".to_string();
        ev.gap.reason = "test".to_string();
        let out = reg.normalize(ev, "ring").unwrap();
        assert_eq!(out.kind, "gap");
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn wire_map_pairs_without_pending() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        reg.admit_hook("hu", "tlb-phys").unwrap();
        let out = reg
            .normalize(wire_map("lc-1", 41, "hm", 1), "ring")
            .unwrap();
        assert!(paired(&out));
        assert_eq!(
            reg.generation_of("unattributed", "tlb-phys", "gen-41")
                .unwrap(),
            41
        );
        let rel = reg.normalize(wire_unmap(41, "hu", 2), "ring").unwrap();
        assert!(paired(&rel));
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn wire_reuse_pairs_independently() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        reg.admit_hook("hu", "tlb-phys").unwrap();
        reg.normalize(wire_map("lc-1", 41, "hm", 1), "ring")
            .unwrap();
        reg.normalize(wire_unmap(41, "hu", 2), "ring").unwrap();
        reg.normalize(wire_map("lc-3", 42, "hm", 3), "ring")
            .unwrap();
        let rel = reg.normalize(wire_unmap(42, "hu", 4), "ring").unwrap();
        assert!(paired(&rel));
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn wire_double_map_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        reg.normalize(wire_map("lc-1", 7, "hm", 1), "ring").unwrap();
        let out = reg.normalize(wire_map("lc-2", 7, "hm", 2), "ring").unwrap();
        assert!(!paired(&out));
        assert!(reg.health().reason.contains("mapping already live"));
    }

    #[test]
    fn wire_double_unmap_retired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        reg.admit_hook("hu", "tlb-phys").unwrap();
        reg.normalize(wire_map("lc-1", 7, "hm", 1), "ring").unwrap();
        reg.normalize(wire_unmap(7, "hu", 2), "ring").unwrap();
        let out = reg.normalize(wire_unmap(7, "hu", 3), "ring").unwrap();
        assert!(!paired(&out));
        assert!(reg.health().reason.contains("release of retired mapping"));
    }

    #[test]
    fn wire_unassigned_never_pairs() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        let mut ev = base("map_result", "hm", 1);
        ev.map_result.operation_id = "lc-1".to_string();
        ev.map_result.success = true;
        ev.map_result.has_mapped_bytes = true;
        ev.map_result.mapped_bytes = 4096;
        ev.map_result.has_wire_generation = true;
        ev.map_result.has_wire_identity = true;
        ev.map_result.wire_identity = "unassigned".to_string();
        let out = reg.normalize(ev, "ring").unwrap();
        assert!(!paired(&out));
        assert!(reg.health().reason.contains("unassigned mapping identity"));
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn wire_miss_never_pairs() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hu", "tlb-phys").unwrap();
        let mut ev = base("unmap", "hu", 1);
        ev.unmap.has_wire_generation = true;
        ev.unmap.has_wire_identity = true;
        ev.unmap.wire_identity = "miss".to_string();
        let out = reg.normalize(ev, "ring").unwrap();
        assert!(!paired(&out));
        assert!(reg.health().reason.contains("release of unknown mapping"));
    }

    #[test]
    fn wire_failed_map_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        let mut ev = base("map_result", "hm", 1);
        ev.map_result.operation_id = "lc-1".to_string();
        ev.map_result.has_wire_generation = true;
        let out = reg.normalize(ev, "ring").unwrap();
        assert!(!paired(&out));
        assert!(reg.health().reason.contains("failure carries no mapping"));
    }

    #[test]
    fn wire_token_mismatch_raises() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        let mut ev = wire_map("lc-1", 7, "hm", 1);
        ev.map_result.mapping_id = "gen-9".to_string();
        assert!(reg.normalize(ev, "ring").is_err());
    }

    #[test]
    fn completed_success_cycles_free_pending_capacity() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("op{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            let done = reg
                .normalize(map(&op, true, &format!("m{i}"), "h", s), "ring")
                .unwrap();
            s += 1;
            assert!(paired(&done));
        }
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn completed_failure_cycles_free_pending_capacity() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..5 {
            let op = format!("fop{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            let failed = reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&failed));
        }
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn sequential_completions_beyond_pending_budget() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..8 {
            let op = format!("cop{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            if i % 2 == 0 {
                let tok = format!("cm{i}");
                let done = reg.normalize(map(&op, true, &tok, "h", s), "ring").unwrap();
                s += 1;
                assert!(paired(&done));
                let rel = reg.normalize(unmap(&tok, "h", s), "ring").unwrap();
                s += 1;
                assert!(paired(&rel));
            } else {
                let failed = reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
                s += 1;
                assert!(paired(&failed));
            }
        }
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn completion_frees_saturated_pending() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let first = reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        assert!(paired(&first));
        let second = reg.normalize(attempt("op2", "d1", "h", 2), "ring").unwrap();
        assert!(paired(&second));
        let refused = reg.normalize(attempt("op3", "d1", "h", 3), "ring").unwrap();
        assert!(!paired(&refused));
        assert!(reg.health().reason.contains("pending table exhausted"));
        let done = reg
            .normalize(map("op1", true, "m1", "h", 4), "ring")
            .unwrap();
        assert!(paired(&done));
        let retry = reg.normalize(attempt("op3", "d1", "h", 5), "ring").unwrap();
        assert!(paired(&retry));
    }

    #[test]
    fn mapping_token_reuse_across_cycles() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, RESOLVED_MAX);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("rop{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            let done = reg.normalize(map(&op, true, "m", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&done));
            assert_eq!(
                reg.generation_of("d1", "iova", "m").unwrap(),
                (i + 1) as u64
            );
            let rel = reg.normalize(unmap("m", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&rel));
        }
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn production_pending_churn_at_concurrency_one() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        for i in 0..PENDING_MAX + 1 {
            let op = format!("pop{i}");
            let opened = reg
                .normalize(attempt(&op, "d1", "h", 2 * i as u64 + 1), "ring")
                .unwrap();
            assert!(paired(&opened));
            let failed = reg
                .normalize(map(&op, false, "", "h", 2 * i as u64 + 2), "ring")
                .unwrap();
            assert!(paired(&failed));
        }
        assert!(
            reg.health()
                .reason
                .contains("resolved-operation history exceeded")
        );
        assert!(!reg.health().reason.contains("pending table exhausted"));
    }

    #[test]
    fn duplicate_result_after_other_cycles() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        reg.normalize(attempt("op2", "d1", "h", 3), "ring").unwrap();
        reg.normalize(map("op2", true, "m2", "h", 4), "ring")
            .unwrap();
        let dup = reg
            .normalize(map("op1", true, "m9", "h", 5), "ring")
            .unwrap();
        assert!(!paired(&dup));
        assert!(reg.health().reason.contains("duplicate result for op1"));
    }

    #[test]
    fn duplicate_attempt_after_resolution() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", false, "", "h", 2), "ring")
            .unwrap();
        let dup = reg.normalize(attempt("op1", "d1", "h", 3), "ring").unwrap();
        assert!(!paired(&dup));
        assert!(reg.health().reason.contains("duplicate operation op1"));
    }

    #[test]
    fn copy_against_wire_mapping_stays_unpaired() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("hm", "tlb-phys").unwrap();
        reg.normalize(wire_map("lc-1", 7, "hm", 1), "ring").unwrap();
        let out = reg
            .normalize(copy("lc-1", "gen-7", "hm", 2), "ring")
            .unwrap();
        assert!(!paired(&out));
        assert!(
            reg.health()
                .reason
                .contains("copy without pending operation")
        );
    }

    #[test]
    fn resolved_history_pressure_is_explicit() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("eop{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            let failed = reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&failed));
        }
        assert_eq!(reg.health().status, "partial");
        assert!(
            reg.health()
                .reason
                .contains("resolved-operation history exceeded")
        );
        assert!(!reg.health().reason.contains("pending table exhausted"));
    }

    #[test]
    fn delayed_copy_survives_resolved_eviction() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        reg.normalize(attempt("op2", "d1", "h", 3), "ring").unwrap();
        reg.normalize(map("op2", false, "", "h", 4), "ring")
            .unwrap();
        reg.normalize(attempt("op3", "d1", "h", 5), "ring").unwrap();
        reg.normalize(map("op3", false, "", "h", 6), "ring")
            .unwrap();
        let late = reg.normalize(copy("op1", "m1", "h", 7), "ring").unwrap();
        assert!(paired(&late));
        assert!(
            reg.health()
                .reason
                .contains("resolved-operation history exceeded")
        );
    }

    #[test]
    fn expired_duplicate_loses_duplicate_verdict() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("xop{i}");
            reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
        }
        let dup = reg
            .normalize(map("xop0", false, "", "h", 7), "ring")
            .unwrap();
        assert!(!paired(&dup));
        assert!(
            reg.health()
                .reason
                .contains("map_result without pending operation")
        );
        assert!(!reg.health().reason.contains("duplicate result for xop0"));
        let dup_kept = reg
            .normalize(map("xop2", false, "", "h", 8), "ring")
            .unwrap();
        assert!(!paired(&dup_kept));
        assert!(reg.health().reason.contains("duplicate result for xop2"));
    }

    #[test]
    fn operation_id_reuse_after_expiry_pairs_as_new() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("rop{i}");
            reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
        }
        let reopened = reg
            .normalize(attempt("rop0", "d1", "h", 7), "ring")
            .unwrap();
        assert!(paired(&reopened));
        let redone = reg
            .normalize(map("rop0", false, "", "h", 8), "ring")
            .unwrap();
        assert!(paired(&redone));
    }

    #[test]
    fn duplicate_churn_keeps_bounded_causes() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..64 {
            let op = format!("dop{i}");
            let opened = reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&opened));
            let failed = reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
            assert!(paired(&failed));
            let dup = reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
            assert!(!paired(&dup));
        }
        assert_eq!(reg._pending.len(), 0);
        assert_eq!(reg._resolved.len(), 2);
        assert_eq!(reg._cause_order_map.len(), 2);
        assert_eq!(
            reg.health().reason,
            "mapping_release partial (duplicate result for dop0; \
             resolved-operation history exceeded)"
        );
    }

    fn long_id(prefix: &str, n: usize) -> String {
        format!("{prefix}{}", "x".repeat(n))
    }

    #[test]
    fn complete_health_has_complete_relations() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "complete_for_scope");
        assert!(full.mapping_release.has_loss_count);
        assert_eq!(full.mapping_release.loss_count, 0);
        assert_eq!(full.mapping_release.scope, "mapping and release pairing");
        assert_eq!(full.copy_attribution.status, "complete_for_scope");
        assert!(full.copy_attribution.has_loss_count);
        assert_eq!(full.copy_attribution.scope, "copy attribution");
        assert_eq!(full.sync_attribution.status, "complete_for_scope");
        assert!(full.sync_attribution.has_loss_count);
        assert_eq!(full.sync_attribution.scope, "sync attribution");
        assert_eq!(full.aggregate.status, "complete_for_scope");
        assert_eq!(full.aggregate.reason, "all lifecycle events paired");
        assert_eq!(reg.health().status, "complete_for_scope");
    }

    #[test]
    fn copy_loss_scoped_to_copy_class() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        reg.normalize(attempt("op2", "d1", "h", 3), "ring").unwrap();
        let out = reg.normalize(copy("op2", "m1", "h", 4), "ring").unwrap();
        assert!(!paired(&out));
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "complete_for_scope");
        assert_eq!(full.copy_attribution.status, "partial");
        assert!(!full.copy_attribution.has_loss_count);
        assert!(
            full.copy_attribution
                .reason
                .contains("copy operation mismatch")
        );
        assert_eq!(full.sync_attribution.status, "complete_for_scope");
        assert_eq!(full.aggregate.status, "partial");
        assert!(full.aggregate.reason.contains("copy_attribution"));
        assert!(!full.aggregate.reason.contains("mapping_release"));
        assert!(!full.aggregate.reason.contains("sync_attribution"));
    }

    #[test]
    fn sync_loss_scoped_to_sync_class() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "h", 1), "ring").unwrap();
        reg.normalize(map("op1", true, "m1", "h", 2), "ring")
            .unwrap();
        let out = reg.normalize(sync("op1", "ghost", "h", 3), "ring").unwrap();
        assert!(!paired(&out));
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "complete_for_scope");
        assert_eq!(full.copy_attribution.status, "complete_for_scope");
        assert_eq!(full.sync_attribution.status, "partial");
        assert!(
            full.sync_attribution
                .reason
                .contains("sync references unknown mapping")
        );
        assert_eq!(full.aggregate.status, "partial");
        assert!(full.aggregate.reason.contains("sync_attribution"));
        assert!(!full.aggregate.reason.contains("mapping_release"));
    }

    #[test]
    fn mapping_loss_scoped_to_mapping_class() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        let out = reg
            .normalize(map("ghost", true, "m1", "h", 1), "ring")
            .unwrap();
        assert!(!paired(&out));
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "partial");
        assert!(
            full.mapping_release
                .reason
                .contains("map_result without pending operation")
        );
        assert_eq!(full.copy_attribution.status, "complete_for_scope");
        assert_eq!(full.sync_attribution.status, "complete_for_scope");
        assert_eq!(
            full.aggregate.reason,
            "mapping_release partial (map_result without pending operation)"
        );
    }

    #[test]
    fn resolved_pressure_scoped_to_mapping_class() {
        let mut reg = reg_with(2, 65536, 8, 16384, 4096, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        for i in 0..3 {
            let op = format!("rop{i}");
            reg.normalize(attempt(&op, "d1", "h", s), "ring").unwrap();
            s += 1;
            reg.normalize(map(&op, false, "", "h", s), "ring").unwrap();
            s += 1;
        }
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "partial");
        assert!(
            full.mapping_release
                .reason
                .contains("resolved-operation history exceeded")
        );
        assert_eq!(full.copy_attribution.status, "complete_for_scope");
        assert_eq!(full.sync_attribution.status, "complete_for_scope");
        assert!(full.aggregate.reason.contains("mapping_release"));
    }

    #[test]
    fn hook_not_admitted_scoped_by_kind() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(attempt("op1", "d1", "nope", 1), "ring")
            .unwrap();
        reg.normalize(copy("op1", "", "nope", 2), "ring").unwrap();
        reg.normalize(sync("op1", "m1", "nope", 3), "ring").unwrap();
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "partial");
        assert!(full.mapping_release.reason.contains("hook not admitted"));
        assert_eq!(full.copy_attribution.status, "partial");
        assert!(full.copy_attribution.reason.contains("hook not admitted"));
        assert_eq!(full.sync_attribution.status, "partial");
        assert!(full.sync_attribution.reason.contains("hook not admitted"));
    }

    #[test]
    fn mixed_loss_names_every_class_in_order() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        reg.normalize(map("ghost", true, "m1", "h", 1), "ring")
            .unwrap();
        reg.normalize(copy("ghost", "", "h", 2), "ring").unwrap();
        reg.normalize(sync("ghost", "ghost", "h", 3), "ring")
            .unwrap();
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "partial");
        assert_eq!(full.copy_attribution.status, "partial");
        assert_eq!(full.sync_attribution.status, "partial");
        let at_map = full.aggregate.reason.find("mapping_release").unwrap();
        let at_copy = full.aggregate.reason.find("copy_attribution").unwrap();
        let at_sync = full.aggregate.reason.find("sync_attribution").unwrap();
        assert!(at_map < at_copy);
        assert!(at_copy < at_sync);
    }

    #[test]
    fn relation_refs_capped_per_class_and_total() {
        let mut reg = CorrelationRegistry::new();
        reg.admit_hook("h", "iova").unwrap();
        for i in 0..10 {
            reg.normalize(copy(&format!("cop{i}"), "", "h", i + 1), "ring")
                .unwrap();
        }
        let full = reg.health_full();
        assert_eq!(full.copy_attribution.evidence_refs.len(), 8);
        assert_eq!(full.copy_attribution.evidence_refs[0], "ring:seq=1");
        assert!(full.aggregate.evidence_refs.len() <= 8);
    }

    #[test]
    fn relation_reasons_stay_bounded() {
        let mut reg = reg_with(8, 2, 1, 16384, 2, 2);
        reg.admit_hook("h", "iova").unwrap();
        let mut s = 1u64;
        let next = |reg: &mut CorrelationRegistry, ev: Event| {
            reg.normalize(ev, "ring").unwrap();
        };
        let big1 = long_id("op-", 100);
        next(&mut reg, attempt(&big1, "d1", "h", s));
        s += 1;
        next(&mut reg, attempt(&big1, "d1", "h", s));
        s += 1;
        let big2 = long_id("res-", 100);
        next(&mut reg, attempt(&big2, "d1", "h", s));
        s += 1;
        next(&mut reg, map(&big2, false, "", "h", s));
        s += 1;
        next(&mut reg, map(&big2, false, "", "h", s));
        s += 1;
        next(&mut reg, map("ghost", true, "m1", "h", s));
        s += 1;
        next(&mut reg, attempt("opA", "d1", "h", s));
        s += 1;
        next(&mut reg, map("opA", true, "mA", "h", s));
        s += 1;
        next(&mut reg, attempt("opB", "d1", "h", s));
        s += 1;
        next(&mut reg, map("opB", true, "mA", "h", s));
        s += 1;
        next(&mut reg, attempt("opC", "d1", "h", s));
        s += 1;
        next(&mut reg, map("opC", true, "mC", "h", s));
        s += 1;
        next(&mut reg, attempt("opD", "d1", "h", s));
        s += 1;
        next(&mut reg, map("opD", true, "mD", "h", s));
        s += 1;
        next(&mut reg, unmap("mA", "h", s));
        s += 1;
        next(&mut reg, unmap("mA", "h", s));
        s += 1;
        next(&mut reg, unmap("ghost", "h", s));
        s += 1;
        next(&mut reg, attempt("opE", "d2", "h", s));
        s += 1;
        next(&mut reg, attempt("opF", "d3", "h", s));
        s += 1;
        next(&mut reg, copy("opB", "mC", "h", s));
        s += 1;
        next(&mut reg, copy("opB", "ghost-map", "h", s));
        s += 1;
        next(&mut reg, copy("ghost-op", "", "h", s));
        s += 1;
        next(&mut reg, copy("opC", "", "h", s));
        s += 1;
        next(&mut reg, copy("opE", "", "h", s));
        s += 1;
        next(&mut reg, copy("opE", "", "h", s));
        s += 1;
        next(&mut reg, sync("opC", "ghost-sync", "h", s));
        s += 1;
        next(&mut reg, sync("opB", "mC", "h", s));
        s += 1;
        let long_hook = long_id("hook-", 400);
        next(&mut reg, attempt("opG", "d1", &long_hook, s));
        s += 1;
        next(&mut reg, copy("cop1", "mC", &long_hook, s));
        s += 1;
        next(&mut reg, sync("opC", "mC", &long_hook, s));
        let full = reg.health_full();
        assert_eq!(full.mapping_release.status, "partial");
        assert_eq!(full.copy_attribution.status, "partial");
        assert_eq!(full.sync_attribution.status, "partial");
        assert!(full.mapping_release.reason.chars().count() <= 512);
        assert!(full.copy_attribution.reason.chars().count() <= 512);
        assert!(full.sync_attribution.reason.chars().count() <= 512);
        assert!(full.aggregate.reason.chars().count() <= 512);
        assert!(full.mapping_release.reason.contains("duplicate operation"));
        assert!(full.copy_attribution.reason.contains("hook not admitted"));
        assert!(!full.copy_attribution.reason.contains(&long_hook));
        assert!(full.aggregate.reason.contains("mapping_release"));
        assert!(full.aggregate.reason.contains("copy_attribution"));
        assert!(full.aggregate.reason.contains("sync_attribution"));
    }
}
