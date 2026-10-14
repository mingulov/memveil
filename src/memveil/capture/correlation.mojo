# SPDX-License-Identifier: GPL-3.0-or-later

"""Bounded lifecycle correlation over normalized events.

The registry proves relationships without raw addresses, PID or
timestamp proximity, or hidden collector state:

- Operation identity opens with a bounce attempt and precedes any
  mapping result. A failed allocation creates no mapping, but an
  actual copy observed before the failure stays paired.
- Each successful mapping joins one live generation per (device,
  namespace) lineage. A reused token gets a new generation; the
  same token under another namespace is a distinct lineage that
  never merges.
- Sync and unmap resolve only against the live generation. Repeat
  or unknown releases stay unpaired; retired tombstones are a
  bounded ring, so references older than retained evidence stay
  uncertain instead of borrowing certainty.
- Observer cpu/pid/tgid/comm is execution context and never
  enters a pairing key.
- Hook names map to address namespaces through the admitted
  profile table only. Events from unadmitted hooks stay unpaired.

Pending holds unresolved operations only: each result moves
its operation into bounded resolved history, so completed
churn never refuses new attempts as pending exhaustion.
Resolved pressure degrades correlation quality explicitly,
and references past the retained horizon stay uncertain
instead of borrowing duplicate or nesting verdicts.
A copy naming a live mapping pairs against the mapping's
recorded operation, so delayed references survive resolved
turnover; copies against wire-created mappings still need
a known operation. Budgets are struct parameters so tests
prove N/N+1 logic on small instances while production
uses the contract ceilings.
"""

from memveil.model.event import Event
from memveil.model.identity import (
    ACTIVE_MAX,
    DEVICE_MAX_ID,
    NESTED_MAX,
    PENDING_MAX,
    RESOLVED_MAX,
    RETIRED_MAX,
    check_address_space,
)
from memveil.model.session import Channel
from memveil.model.validate import format_u64


@fieldwise_init
struct CorrelationError(Copyable, Writable):
    """One correlation input failure."""

    var message: String


@fieldwise_init
struct RegistryBudgets(ImplicitlyCopyable):
    """Production budget ceilings."""

    var pending: Int
    var active: Int
    var nested: Int
    var retired: Int
    var devices: Int
    var resolved: Int


def budgets() -> RegistryBudgets:
    """Contract ceilings used by default registry instances."""
    return RegistryBudgets(
        PENDING_MAX,
        ACTIVE_MAX,
        NESTED_MAX,
        RETIRED_MAX,
        DEVICE_MAX_ID,
        RESOLVED_MAX,
    )


struct _PendingOp(ImplicitlyCopyable):
    var device: String
    var nested: Int

    def __init__(out self):
        self.device = String("")
        self.nested = 0


struct _ActiveMapping(ImplicitlyCopyable):
    var op: String
    var device: String
    var namespace: String
    var generation: UInt64
    var map_ts: UInt64
    var mapped_bytes: UInt64
    var wire: Bool

    def __init__(out self):
        self.op = String("")
        self.device = String("")
        self.namespace = String("")
        self.generation = UInt64(0)
        self.map_ts = UInt64(0)
        self.mapped_bytes = UInt64(0)
        self.wire = False


def _is_lifecycle(kind: String) -> Bool:
    return (
        kind == "bounce_attempt"
        or kind == "map_result"
        or kind == "copy"
        or kind == "sync_request"
        or kind == "unmap"
    )


struct CorrelationRegistry[
    PENDING_N: Int = PENDING_MAX,
    ACTIVE_N: Int = ACTIVE_MAX,
    NESTED_N: Int = NESTED_MAX,
    RETIRED_N: Int = RETIRED_MAX,
    DEVICE_N: Int = DEVICE_MAX_ID,
    RESOLVED_N: Int = RESOLVED_MAX,
]:
    """Pairing validator with bounded pending/active/resolved stores.

    Pending holds unresolved operations only; each result moves
    its operation into the bounded resolved ring, whose pressure
    degrades quality explicitly.
    """

    var _hooks: Dict[String, String]
    var _pending: Dict[String, _PendingOp]
    var _resolved: Dict[String, Bool]
    var _resolved_order: List[String]
    var _resolved_next: Int
    var _active: Dict[String, _ActiveMapping]
    var _retired: Dict[String, UInt64]
    var _retired_order: List[String]
    var _retired_next: Int
    var _lineage_next: Dict[String, Int]
    var _devices: Dict[String, Bool]
    var _unpaired: Int
    var _causes: Dict[String, Bool]
    var _cause_order: List[String]
    var _refs: List[String]

    def __init__(out self):
        self._hooks = Dict[String, String]()
        self._pending = Dict[String, _PendingOp]()
        self._resolved = Dict[String, Bool]()
        self._resolved_order = List[String]()
        self._resolved_next = 0
        self._active = Dict[String, _ActiveMapping]()
        self._retired = Dict[String, UInt64]()
        self._retired_order = List[String]()
        self._retired_next = 0
        self._lineage_next = Dict[String, Int]()
        self._devices = Dict[String, Bool]()
        self._unpaired = 0
        self._causes = Dict[String, Bool]()
        self._cause_order = List[String]()
        self._refs = List[String]()

    def admit_hook(mut self, hook: String, namespace: String) raises:
        """Admit one hook under an address namespace."""
        check_address_space(namespace)
        if hook == "":
            raise CorrelationError("empty hook name")
        self._hooks[hook] = namespace

    def active_count(self) -> Int:
        return len(self._active)

    def generation_of(
        self, device: String, namespace: String, mapping: String
    ) raises -> UInt64:
        """Generation of one mapping token, live or retired."""
        var key = namespace + "|" + mapping
        if key in self._active:
            return self._active[key].generation
        if key in self._retired:
            return self._retired[key]
        raise CorrelationError("unknown mapping " + mapping)

    def health(self) -> Channel:
        """Correlation quality: paired scope or explicit causes."""
        var out = Channel()
        out.scope = String("correlated lifecycle events")
        if self._unpaired == 0:
            out.status = String("complete_for_scope")
            out.has_loss_count = True
            out.loss_count = UInt64(0)
            out.reason = String("all lifecycle events paired")
            return out^
        out.status = String("partial")
        var reason = String("")
        for i in range(len(self._cause_order)):
            if i > 0:
                reason += "; "
            reason += self._cause_order[i]
        out.reason = reason
        for i in range(len(self._refs)):
            out.evidence_refs.append(self._refs[i])
        return out^

    def _note(
        mut self, code: String, example: String, seq: UInt64,
        source: String,
    ):
        """Record one unpaired event under a fixed cause code.

        Deduplication keys on the fixed code only: the first
        identity example is retained for diagnosis and later
        identities under the same code add no storage, so
        diagnostic history plateaus with the code set instead
        of growing per operation or mapping identity.
        """
        self._unpaired += 1
        if code not in self._causes:
            self._causes[code] = True
            if example == "":
                self._cause_order.append(code)
            else:
                self._cause_order.append(code + example)
        if len(self._refs) < 8:
            self._refs.append(
                source + ":seq=" + format_u64(seq)
            )

    def _unpaired_event(
        mut self, var ev: Event, code: String, example: String,
        source: String,
    ) -> Event:
        self._note(code, example, ev.seq, source)
        ev.source_correlation = String("unpaired")
        return ev^

    def _namespace_for(
        self, hook: String, mut found: Bool
    ) -> String:
        if hook in self._hooks:
            found = True
            return self._hooks.get(hook, String(""))
        found = False
        return String("")

    def normalize(
        mut self, var ev: Event, source: String
    ) raises -> Event:
        """Validate one event's pairing and label it.

        Lifecycle kinds return with source_correlation direct or
        unpaired; other kinds pass through untouched. Raises only
        for malformed records and empty sources, never for an
        unproved relationship.
        """
        if source == "":
            raise CorrelationError("empty source")
        if not _is_lifecycle(ev.kind):
            return ev^
        var admitted = False
        var hook = ev.source_hook
        var ns = self._namespace_for(hook, admitted)
        if not admitted:
            return self._unpaired_event(
                ev^,
                "hook not admitted",
                ": " + hook,
                source,
            )
        if ev.kind == "bounce_attempt":
            return self._open_attempt(ev^, ns, source)
        if ev.kind == "map_result":
            return self._apply_map_result(ev^, ns, source)
        if ev.kind == "copy":
            return self._apply_copy(ev^, ns, source)
        if ev.kind == "sync_request":
            return self._apply_sync(ev^, ns, source)
        return self._apply_unmap(ev^, ns, source)

    def _open_attempt(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        _ = ns
        var op = ev.bounce.operation_id
        var dev = ev.bounce.device_id
        if op == "" or dev == "":
            raise CorrelationError("malformed attempt")
        if op in self._pending or op in self._resolved:
            return self._unpaired_event(
                ev^,
                "duplicate operation",
                " " + op,
                source,
            )
        if dev not in self._devices:
            if len(self._devices) >= Self.DEVICE_N:
                return self._unpaired_event(
                    ev^,
                    "device table exhausted",
                    String(""),
                    source,
                )
            self._devices[dev] = True
        if len(self._pending) >= Self.PENDING_N:
            return self._unpaired_event(
                ev^,
                "pending table exhausted",
                String(""),
                source,
            )
        var p = _PendingOp()
        p.device = dev
        self._pending[op] = p
        ev.source_correlation = String("direct")
        return ev^

    def _wire_gen_token(self, gen: UInt64) -> String:
        return String("gen-") + format_u64(gen)

    def _apply_wire_map(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        """Pair one MVLC v2 map without requiring an attempt.

        Precedence: wire-identity validation, then duplicate
        and bound checks, then active-state insert. Unknown
        identities land unpaired with explicit causes and
        never mint.
        """
        var op = ev.map_result.operation_id
        var gen = ev.map_result.wire_generation
        if not ev.map_result.success:
            if ev.map_result.has_wire_identity:
                raise CorrelationError("failure carries wire_identity")
            if gen != UInt64(0):
                raise CorrelationError("failure carries generation")
            return self._unpaired_event(
                ev^,
                "failure carries no mapping",
                String(""),
                source,
            )
        if not ev.map_result.has_wire_identity:
            raise CorrelationError("success lacks wire_identity")
        var ident = ev.map_result.wire_identity
        if ident != "known" and ident != "unassigned":
            raise CorrelationError("bad wire_identity")
        if ident == "unassigned":
            if ev.map_result.has_mapping_id:
                raise CorrelationError("unassigned carries mapping")
            return self._unpaired_event(
                ev^,
                "unassigned mapping identity",
                String(""),
                source,
            )
        if not ev.map_result.has_mapping_id:
            raise CorrelationError("known identity lacks mapping")
        if ev.map_result.mapping_id != self._wire_gen_token(gen):
            raise CorrelationError("wire mapping/generation mismatch")
        if not ev.map_result.has_mapped_bytes:
            raise CorrelationError("success lacks mapped_bytes")
        var key = ns + "|" + ev.map_result.mapping_id
        if key in self._active:
            return self._unpaired_event(
                ev^,
                "mapping already live",
                ": " + ev.map_result.mapping_id,
                source,
            )
        if len(self._active) >= Self.ACTIVE_N:
            return self._unpaired_event(
                ev^,
                "active table exhausted",
                String(""),
                source,
            )
        var m = _ActiveMapping()
        m.op = op
        m.device = String("unattributed")
        m.namespace = ns
        m.generation = gen
        m.map_ts = ev.ts_ns
        m.mapped_bytes = ev.map_result.mapped_bytes
        m.wire = True
        self._active[key] = m
        ev.source_correlation = String("direct")
        return ev^

    def _apply_map_result(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        var op = ev.map_result.operation_id
        if op == "":
            raise CorrelationError("malformed map_result")
        if ev.map_result.has_wire_generation:
            return self._apply_wire_map(ev^, ns, source)
        if op in self._resolved:
            return self._unpaired_event(
                ev^,
                "duplicate result",
                " for " + op,
                source,
            )
        if op not in self._pending:
            return self._unpaired_event(
                ev^,
                "map_result without pending operation",
                String(""),
                source,
            )
        var p = self._pending[op]
        if not ev.map_result.success:
            if ev.map_result.has_mapping_id:
                raise CorrelationError("failure carries mapping")
            _ = self._pending.pop(op)
            self._remember_resolved(op, ev.seq, source)
            ev.source_correlation = String("direct")
            return ev^
        if not ev.map_result.has_mapping_id:
            raise CorrelationError("success lacks mapping")
        if not ev.map_result.has_mapped_bytes:
            raise CorrelationError("success lacks mapped_bytes")
        var key = ns + "|" + ev.map_result.mapping_id
        if key in self._active:
            return self._unpaired_event(
                ev^,
                "mapping already live",
                ": " + ev.map_result.mapping_id,
                source,
            )
        if len(self._active) >= Self.ACTIVE_N:
            return self._unpaired_event(
                ev^,
                "active table exhausted",
                String(""),
                source,
            )
        var lineage = p.device + "|" + ns
        var gen = 1
        if lineage in self._lineage_next:
            gen = self._lineage_next[lineage]
        self._lineage_next[lineage] = gen + 1
        var m = _ActiveMapping()
        m.op = op
        m.device = p.device
        m.namespace = ns
        m.generation = UInt64(gen)
        m.map_ts = ev.ts_ns
        m.mapped_bytes = ev.map_result.mapped_bytes
        self._active[key] = m
        _ = self._pending.pop(op)
        self._remember_resolved(op, ev.seq, source)
        ev.source_correlation = String("direct")
        return ev^

    def _apply_copy(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        var op = ev.copy.operation_id
        if op == "":
            raise CorrelationError("malformed copy")
        if ev.copy.has_mapping_id:
            var key = ns + "|" + ev.copy.mapping_id
            if key not in self._active:
                return self._unpaired_event(
                    ev^,
                    "copy references unknown mapping",
                    String(""),
                    source,
                )
            if self._active[key].op != op:
                return self._unpaired_event(
                    ev^,
                    "copy operation mismatch",
                    String(""),
                    source,
                )
            var known = op in self._pending or op in self._resolved
            if not known and self._active[key].wire:
                return self._unpaired_event(
                    ev^,
                    "copy without pending operation",
                    String(""),
                    source,
                )
            ev.source_correlation = String("direct")
            return ev^
        if op in self._resolved:
            return self._unpaired_event(
                ev^,
                "copy after operation resolved",
                String(""),
                source,
            )
        if op not in self._pending:
            return self._unpaired_event(
                ev^,
                "copy without pending operation",
                String(""),
                source,
            )
        var p = self._pending[op]
        if p.nested >= Self.NESTED_N:
            return self._unpaired_event(
                ev^,
                "nesting budget exceeded",
                String(""),
                source,
            )
        p.nested += 1
        self._pending[op] = p
        ev.source_correlation = String("direct")
        return ev^

    def _apply_sync(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        var op = ev.sync.operation_id
        if op == "" or not ev.sync.has_mapping_id:
            raise CorrelationError("malformed sync_request")
        var key = ns + "|" + ev.sync.mapping_id
        if key not in self._active:
            return self._unpaired_event(
                ev^,
                "sync references unknown mapping",
                String(""),
                source,
            )
        if self._active[key].op != op:
            return self._unpaired_event(
                ev^,
                "sync operation mismatch",
                String(""),
                source,
            )
        ev.source_correlation = String("direct")
        return ev^

    def _apply_unmap(
        mut self, var ev: Event, ns: String, source: String
    ) raises -> Event:
        if ev.unmap.has_wire_generation:
            if not ev.unmap.has_wire_identity:
                raise CorrelationError("unmap lacks wire_identity")
            var ident = ev.unmap.wire_identity
            if ident != "known" and ident != "miss":
                raise CorrelationError("bad wire_identity")
            if ident == "miss":
                if ev.unmap.has_mapping_id:
                    raise CorrelationError("miss carries mapping")
                return self._unpaired_event(
                    ev^,
                    "release of unknown mapping",
                    String(""),
                    source,
                )
            if not ev.unmap.has_mapping_id:
                raise CorrelationError("known identity lacks mapping")
            if ev.unmap.mapping_id != self._wire_gen_token(
                ev.unmap.wire_generation
            ):
                raise CorrelationError("wire mapping/generation mismatch")
        if not ev.unmap.has_mapping_id:
            raise CorrelationError("malformed unmap")
        var key = ns + "|" + ev.unmap.mapping_id
        if key in self._active:
            var gen = self._active[key].generation
            _ = self._active.pop(key)
            self._retire(key, gen)
            ev.source_correlation = String("direct")
            return ev^
        if key in self._retired:
            return self._unpaired_event(
                ev^,
                "release of retired mapping",
                String(""),
                source,
            )
        return self._unpaired_event(
            ev^,
            "release of unknown mapping",
            String(""),
            source,
        )

    def _remember_resolved(
        mut self, op: String, seq: UInt64, source: String
    ) raises:
        """Move one resolved operation into bounded history.

        Eviction is explicit: forgotten operations lose their
        duplicate and nesting verdicts, and correlation
        quality records the pressure instead of refusing new
        attempts as pending exhaustion.
        """
        if op in self._resolved:
            return
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
            self._note(
                "resolved-operation history exceeded",
                String(""),
                seq,
                source,
            )
        self._resolved[op] = True

    def _retire(mut self, key: String, gen: UInt64) raises:
        """Record one tombstone in the bounded ring."""
        if key in self._retired:
            self._retired[key] = gen
            return
        if Self.RETIRED_N <= 0:
            return
        if len(self._retired_order) < Self.RETIRED_N:
            self._retired_order.append(key)
        else:
            var victim = self._retired_order[self._retired_next]
            _ = self._retired.pop(victim)
            self._retired_order[self._retired_next] = key
            self._retired_next += 1
            if self._retired_next >= Self.RETIRED_N:
                self._retired_next = 0
        self._retired[key] = gen
