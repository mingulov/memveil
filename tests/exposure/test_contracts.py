#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sealed exposure record contracts: seal gating, containment, settlement.

Offline contract checks over the exposure fixtures in
``fixtures/contracts/``. Every helper here is pure standard
library code over persisted bytes: facts replay only from
the sealed event lines, an unsealed snapshot can never
satisfy a rule, duplicate evidence and mixed epochs are
rejected, and a snapshot without terminal evidence stays
partial. The Rust modules implement the same contract;
this file is their independent oracle.
"""

import hashlib
import json
import os
import re

import jsonschema
import pytest

TESTS = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(TESTS)
FIX = os.path.join(TESTS, "exposure", "fixtures", "contracts")

U64MAX = 18446744073709551615
U64RE = re.compile(r"(0|[1-9][0-9]{0,19})")
HEX64RE = re.compile(r"[0-9a-f]{64}")
OPAQUE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

FROZEN_SEMANTICS = ("request", "result", "inventory", "lifecycle",
                    "state", "native_rejection")
FROZEN_PEER = ("none-observed", "host-device", "device-or-subsystem",
               "device", "host-hypervisor", "host-tdx-module",
               "host-or-paravisor")
FROZEN_PHASE = ("boot", "pre_attach", "observed")
FROZEN_STATUS = ("available", "partial", "unavailable",
                 "not_applicable", "disabled")
FROZEN_CLOCK = ("guest_monotonic_active", "guest_boottime_elapsed",
                "external_trusted_interval")
FROZEN_NAMESPACE = ("guest_virtual", "guest_physical", "session_token",
                    "interface_register", "channel_relid", "not_applicable")
FROZEN_OBJECT_CLASS = ("queue", "buffer", "channel", "mapping",
                       "heap_object")
FROZEN_LIFECYCLE = ("created", "live", "released", "quarantined",
                    "unknown")
FROZEN_UNITS = ("bytes", "unknown")
FROZEN_POLICY_RESULT = ("conforms", "deviates_known", "violates",
                        "inconclusive", "unavailable")
FROZEN_COMPATIBILITY = ("compatible", "incompatible", "unavailable")
FROZEN_MEASUREMENT = ("observed", "derived", "estimated")
FROZEN_CORRELATION = ("direct", "unpaired")
QUALITY_CHANNELS = ("detail", "aggregate", "identity", "baseline",
                    "terminal")
SESSION_CHANNELS = ("detail", "aggregate", "correlation", "baseline",
                    "terminal")

INTEGRITY_KEYS = ("algorithm", "events_bytes", "line_count",
                  "first_seq", "last_seq", "events_sha256", "kinds")
SEAL_KINDS = ("bounce_attempt", "map_result", "unmap", "copy",
              "sync_request", "transition_result", "pool_sample",
              "gap", "marker", "counter_snapshot", "exposure_fact")

# Snapshot event-line bound in bytes, content plus terminator. Matches
# the capture reader's line bound exactly: one snapshot entry carries
# exactly one physical line under the same 64 KiB budget.
SNAPSHOT_MAX_LINE_BYTES = 65536

# Each catalog source with its owning capability.
SOURCE_CAPABILITIES = {
    "sharing-census": "census",
    "object-lineage": "object-lifetimes",
    "dma-virtio-paths": "dma-paths",
    "heap-dmabuf-objects": "shared-buffers",
    "ghcb-exceptions": "host-interfaces",
    "tdx-conversions": "host-interfaces",
    "tdx-ve-metadata": "host-interfaces",
    "vmbus-channels": "host-interfaces",
    "mapping-inventory-scan": "mapping-inventory",
    "egress-controls": "exposure-context",
}

COVERAGE_SOURCE_REQUIRED = ("source_id", "capability", "profile_id",
                            "subject_id", "platform_cell",
                            "address_namespace", "phase", "status",
                            "reason", "window", "quality")
EXPOSURE_FACT_REQUIRED = ("evidence_id", "source_id", "epoch",
                          "operation_id", "kind", "direction",
                          "generation", "offset", "length_bytes",
                          "native_result", "caller_class", "peer_class",
                          "clock_domain", "observed_interval",
                          "semantics", "quality")


class DuplicateKeyError(ValueError):
    """One JSON object repeats a key; the seal path refuses these."""


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError("duplicate key %r" % key)
        obj[key] = value
    return obj


def loads_strict(text):
    """Parse JSON refusing duplicate object keys, like the Rust parser."""
    return json.loads(text, object_pairs_hook=_unique_object)


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        return json.load(handle, object_pairs_hook=_unique_object)


def check_u64(value, where):
    assert isinstance(value, str), "%s must be a decimal string" % where
    assert U64RE.fullmatch(value), "%s not canonical: %r" % (where, value)
    number = int(value)
    assert number <= U64MAX, "%s overflows u64" % where
    return number


def check_opaque_id(value, where):
    assert isinstance(value, str), "%s must be a string" % where
    assert OPAQUE_RE.fullmatch(value), \
        "%s not an opaque id: %r" % (where, value)


def check_quality(quality, where):
    assert isinstance(quality, dict), "%s must be an object" % where
    assert set(quality.keys()) == set(QUALITY_CHANNELS), \
        "%s channels" % where
    for channel in QUALITY_CHANNELS:
        node = quality[channel]
        assert isinstance(node, dict), \
            "%s.%s must be an object" % (where, channel)
        assert set(node.keys()) == {"status", "loss_count"}, \
            "%s.%s leaves" % (where, channel)
        assert node["status"] in ("complete_for_scope", "partial",
                                  "unavailable"), \
            "%s.%s status" % (where, channel)
        loss = node["loss_count"]
        if loss is not None:
            check_u64(loss, "%s.%s.loss_count" % (where, channel))


def check_session_quality(quality):
    assert set(quality.keys()) == set(SESSION_CHANNELS), \
        "session quality keeps the capture channels"
    assert quality["terminal"]["status"] in ("complete_for_scope",
                                             "partial", "unavailable",
                                             "not_applicable")


def check_source_capability(entry):
    """The source's capability must be its catalog owner."""
    assert entry["source_id"] in SOURCE_CAPABILITIES, "unknown source"
    assert SOURCE_CAPABILITIES[entry["source_id"]] == entry["capability"], \
        "source mismatch"


def check_missing_sources(entry):
    """Missing sources name catalog entries, never free slugs."""
    missing = entry["missing_sources"]
    assert isinstance(missing, list), "missing_sources must be an array"
    for source in missing:
        assert source in SOURCE_CAPABILITIES, \
            "unknown missing source %r" % source


def check_policy_result_arrays(entry):
    """Policy-result array fields hold string arrays, never scalars.

    Mirrors the report schema: each of the three fields is an
    array of strings, so a bare string refuses here as it does
    in the schema and in the Rust normalizer.
    """
    for field in ("evidence_ids", "missing_sources",
                  "exceptions_applied"):
        values = entry[field]
        assert isinstance(values, list), "%s must be an array" % field
        for value in values:
            assert isinstance(value, str), \
                "%s holds strings only" % field
    check_missing_sources(entry)


EXPOSURE_FACT_OPTIONAL = ("parent_operation_id",
                            "parent_operation_id_reason", "object_token",
                            "object_token_reason", "native_result_reason")
I64MIN = -(2**63)
I64MAX = 2**63 - 1


def check_maybe_pairing(fact, base, where):
    """An absent key carries no reason; a null needs one; a value none."""
    reason_key = base + "_reason"
    valued = base in fact
    reasoned = reason_key in fact
    if not valued:
        assert not reasoned, "%s strays without %s" % (reason_key, base)
        return
    value = fact[base]
    if value is None:
        assert reasoned, "%s null needs %s" % (base, reason_key)
    else:
        assert isinstance(value, str), "%s must be a string" % where
        check_opaque_id(value, where)
        assert not reasoned, "%s strays beside a value" % reason_key
    if reasoned:
        check_opaque_id(fact[reason_key], reason_key)


def fact_fields_valid(fact):
    """True when every exposure-fact field keeps its frozen shape.

    Mirrors the event schema and the Rust snapshot path: the
    required keys are present, nothing unknown rides along, u64
    leaves are canonical, identifiers are bounded, closed labels
    stay in their frozen sets, the observed interval orders
    start before end, quality channels are well-formed, and each
    nullable leaf pairs with its reason key exactly when null.
    """
    try:
        if not isinstance(fact, dict):
            return False
        allowed = set(EXPOSURE_FACT_REQUIRED) | set(EXPOSURE_FACT_OPTIONAL)
        if set(fact.keys()) - allowed:
            return False
        for field in EXPOSURE_FACT_REQUIRED:
            assert field in fact, "missing fact field %s" % field
        check_opaque_id(fact["evidence_id"], "evidence_id")
        if fact["source_id"] not in SOURCE_CAPABILITIES:
            return False
        check_u64(fact["epoch"], "epoch")
        check_opaque_id(fact["operation_id"], "operation_id")
        check_opaque_id(fact["kind"], "kind")
        check_opaque_id(fact["direction"], "direction")
        check_u64(fact["generation"], "generation")
        check_u64(fact["offset"], "offset")
        check_u64(fact["length_bytes"], "length_bytes")
        check_opaque_id(fact["caller_class"], "caller_class")
        assert fact["peer_class"] in FROZEN_PEER, "unknown peer class"
        assert fact["clock_domain"] in FROZEN_CLOCK
        interval = fact["observed_interval"]
        assert isinstance(interval, dict), "interval must be an object"
        assert set(interval.keys()) == {"start", "end", "uncertainty"}, \
            "interval leaves"
        start = check_u64(interval["start"], "interval.start")
        end = check_u64(interval["end"], "interval.end")
        check_u64(interval["uncertainty"], "interval.uncertainty")
        assert start <= end, "interval start past end"
        assert fact["semantics"] in FROZEN_SEMANTICS
        check_quality(fact["quality"], "fact quality")
        check_maybe_pairing(fact, "parent_operation_id", "parent")
        check_maybe_pairing(fact, "object_token", "object token")
        native = fact["native_result"]
        reasoned = "native_result_reason" in fact
        if native is None:
            assert reasoned, "null native result needs a reason"
        else:
            assert isinstance(native, int) \
                and not isinstance(native, bool), "native type"
            assert I64MIN <= native <= I64MAX, "native range"
            assert not reasoned, "native reason strays beside a value"
        if reasoned:
            check_opaque_id(fact["native_result_reason"],
                            "native_result_reason")
    except (AssertionError, KeyError, TypeError):
        return False
    return True


ENVELOPE_FIELDS = ("schema_version", "session_id", "seq", "ts_ns",
                   "kind", "source", "data")
SOURCE_FIELDS = ("hook", "backend", "profile_id", "measurement",
                 "correlation")


def event_envelope_valid(event):
    """True when one event envelope keeps its canonical shape.

    The seven envelope keys are present with nothing unknown, the
    version is the exposure contract, the timestamp is a canonical
    u64, and the source carries its five string leaves with frozen
    labels. Sequence and session checks stay with the seal loop,
    as in Rust; the caller owns kind membership.
    """
    try:
        if not isinstance(event, dict):
            return False
        if set(event.keys()) != set(ENVELOPE_FIELDS):
            return False
        if event["schema_version"] != "0.3.0":
            return False
        if not isinstance(event["session_id"], str):
            return False
        check_u64(event["ts_ns"], "ts_ns")
        source = event["source"]
        if not isinstance(source, dict):
            return False
        if set(source.keys()) != set(SOURCE_FIELDS):
            return False
        for field in ("hook", "backend", "profile_id"):
            if not isinstance(source[field], str):
                return False
        if source["measurement"] not in FROZEN_MEASUREMENT:
            return False
        if source["correlation"] not in FROZEN_CORRELATION:
            return False
    except (AssertionError, KeyError, TypeError):
        return False
    return True


def fact_envelope_valid(event):
    """True when an exposure-fact line keeps its canonical envelope.

    Mirrors the Rust normalizer's envelope checks plus the seal
    path's frozen source labels: the seven envelope keys are
    present with nothing unknown, the version is the exposure
    contract, the timestamp is a canonical u64, and the source
    carries its five string leaves with frozen labels. Sequence
    and session checks stay with the seal loop, as in Rust.
    """
    if not isinstance(event, dict):
        return False
    return event.get("kind") == "exposure_fact" \
        and event_envelope_valid(event)


def bounce_payload_valid(data):
    """True when a bounce-attempt payload keeps its schema shape.

    The payload carries exactly the four schema leaves: two opaque
    identifiers, a canonical byte count, and a bare flag.
    """
    try:
        if set(data.keys()) != {"device_id", "requested_bytes",
                                "forced", "operation_id"}:
            return False
        check_opaque_id(data["device_id"], "device_id")
        check_u64(data["requested_bytes"], "requested_bytes")
        if not isinstance(data["forced"], bool):
            return False
        check_opaque_id(data["operation_id"], "operation_id")
    except (AssertionError, KeyError, TypeError):
        return False
    return True


def non_fact_fields_valid(event):
    """True when a non-fact line keeps its envelope payload shape.

    The kind is a legacy seal kind, the envelope keeps its
    canonical shape with frozen source labels, and the object
    ``data`` payload carries at least one key. A marker's payload
    holds exactly its bounded ``text`` annotation and a bounce
    attempt carries exactly its four schema leaves, mirroring the
    event schema and the Rust snapshot path.
    """
    try:
        if not isinstance(event, dict):
            return False
        kind = event.get("kind")
        if kind == "exposure_fact" or kind not in SEAL_KINDS:
            return False
        if not event_envelope_valid(event):
            return False
        data = event.get("data")
        if not isinstance(data, dict):
            return False
        if kind == "marker":
            if set(data.keys()) != {"text"}:
                return False
            text = data["text"]
            if not isinstance(text, str) or not 1 <= len(text) <= 256:
                return False
            return True
        if kind == "bounce_attempt":
            return bounce_payload_valid(data)
        return len(data) > 0
    except (AttributeError, TypeError):
        return False


def facts_from_lines(snapshot):
    """Replay exposure facts from the sealed lines only.

    No sidecar supplies policy evidence: every fact comes
    from an ``exposure_fact`` line of the sealed stream.
    Lines parse strictly, so a duplicated key refuses here
    as it does at the seal.
    """
    facts = []
    for line in snapshot["event_lines"]:
        event = loads_strict(line)
        if event["kind"] == "exposure_fact":
            facts.append(event["data"])
    return facts


def integrity_self_consistent(integrity):
    unknown = sorted(set(integrity.keys()) - set(INTEGRITY_KEYS))
    if unknown:
        raise ValueError("unknown integrity field %r" % unknown[0])
    assert integrity["algorithm"] == "sha256"
    check_u64(integrity["events_bytes"], "events_bytes")
    lines = check_u64(integrity["line_count"], "line_count")
    kinds = integrity["kinds"]
    if not isinstance(kinds, dict):
        raise ValueError("kinds must be an object")
    for name in SEAL_KINDS:
        if name == "exposure_fact":
            continue
        assert name in kinds, "missing integrity kind %r" % name
    total = 0
    for name, value in sorted(kinds.items()):
        if name not in SEAL_KINDS:
            raise ValueError("unknown integrity kind %r" % name)
        total += check_u64(value, "kinds")
    assert total == lines, "kind sum differs from line_count"
    assert HEX64RE.fullmatch(integrity["events_sha256"]), "digest shape"
    first = integrity["first_seq"]
    last = integrity["last_seq"]
    if lines == 0:
        assert first is None and last is None, "empty stream keeps no bounds"
        assert integrity["events_bytes"] == "0", "empty stream keeps no bytes"
        assert integrity["events_sha256"] == EMPTY_SHA256, "empty digest"
    else:
        assert first == "0", "span starts at zero"
        assert check_u64(last, "last_seq") == lines - 1, "span ends at N-1"
        assert int(integrity["events_bytes"]) >= lines, "bytes cover lines"


def seal_verified(snapshot):
    """True only when the committed seal matches the literal bytes.

    An absent integrity object verifies false; a present non-object,
    a non-object kinds table, or an unknown integrity field or kind
    raises, mirroring the Rust snapshot path. A well-formed seal that
    mismatches the bytes, that leaves a census kind uncommitted, or
    whose fact identities break containment, verifies false. Every
    line parses without duplicated keys, ends in a newline, carries
    its position as its sequence number, and belongs to the
    snapshot's own session; one entry holds exactly one physical
    line under the reader's 64 KiB bound. Framing violations raise.
    A foreign-session line, a duplicated key, an exposure fact whose
    envelope, source labels or fields fail validation, or a non-fact
    line whose envelope, source labels or payload loses its shape
    verifies false, like a containment break: none can support a
    verdict.
    """
    expected_session = snapshot["session"].get("session_id")
    for position, line in enumerate(snapshot["event_lines"]):
        if not line.endswith("\n"):
            raise ValueError("line %d lacks trailing newline" % position)
        if len(line.split("\n")) != 2:
            raise ValueError("line %d holds extra newline" % position)
        if len(line.encode("utf-8")) > SNAPSHOT_MAX_LINE_BYTES:
            raise ValueError("line %d too large" % position)
        try:
            event = loads_strict(line)
        except DuplicateKeyError:
            return False
        if not isinstance(event, dict):
            return False
        if event.get("seq") != str(position):
            raise ValueError("line %d sequence mismatch" % position)
        if event.get("session_id") != expected_session:
            return False
        if event.get("kind") == "exposure_fact":
            if not fact_envelope_valid(event):
                return False
            if not fact_fields_valid(event.get("data")):
                return False
        elif not non_fact_fields_valid(event):
            return False
    capture = snapshot["session"]["capture"]
    if "integrity" not in capture:
        return False
    integrity = capture["integrity"]
    if not isinstance(integrity, dict):
        raise ValueError("integrity must be an object")
    try:
        integrity_self_consistent(integrity)
    except AssertionError:
        return False
    literal = "".join(snapshot["event_lines"]).encode("utf-8")
    if hashlib.sha256(literal).hexdigest() != integrity["events_sha256"]:
        return False
    if int(integrity["events_bytes"]) != len(literal):
        return False
    if int(integrity["line_count"]) != len(snapshot["event_lines"]):
        return False
    census = {}
    for line in snapshot["event_lines"]:
        kind = json.loads(line)["kind"]
        census[kind] = census.get(kind, 0) + 1
    for kind, value in integrity["kinds"].items():
        if census.get(kind, 0) != int(value):
            return False
    facts = facts_from_lines(snapshot)
    if duplicate_evidence_error(facts) is not None:
        return False
    return cross_epoch_error(facts) is None


def duplicate_evidence_error(facts):
    seen = set()
    for fact in facts:
        handle = fact["evidence_id"]
        if handle in seen:
            return "duplicate evidence_id %r" % handle
        seen.add(handle)
    return None


def cross_epoch_error(facts):
    epochs = {}
    for fact in facts:
        epochs.setdefault(fact["source_id"], set()).add(fact["epoch"])
    mixed = sorted(source for source, values in epochs.items()
                   if len(values) > 1)
    if mixed:
        return "cross-epoch source %r" % mixed[0]
    return None


def rule_satisfied(snapshot, required_sources):
    """A rule is satisfied only by sealed, settled, covering evidence.

    Usable metadata alone never satisfies: every required source
    needs at least one sealed fact whose ``source_id`` equals it.
    """
    if not required_sources:
        return False
    if not seal_verified(snapshot):
        return False
    session = snapshot["session"]
    terminal = session["quality"]["terminal"]
    if terminal["status"] != "complete_for_scope":
        return False
    by_source = {entry["source_id"]: entry
                 for entry in session["exposure"]["sources"]}
    for source in required_sources:
        entry = by_source.get(source)
        if entry is None or entry["status"] not in ("available", "partial"):
            return False
    facts = facts_from_lines(snapshot)
    if not facts:
        return False
    for source in required_sources:
        if not any(fact["source_id"] == source for fact in facts):
            return False
    # The seal already gates containment; these stay as a second layer.
    if duplicate_evidence_error(facts) is not None:
        return False
    return cross_epoch_error(facts) is None


def snapshot_verdict(snapshot, required_sources):
    """Satisfied, partial, or inconclusive; never a vacuous pass."""
    if rule_satisfied(snapshot, required_sources):
        return "satisfied"
    session = snapshot["session"]
    if session["quality"]["terminal"]["status"] != "complete_for_scope":
        return "partial"
    return "inconclusive"


def test_unsealed_snapshot_cannot_satisfy_rule():
    required = ["sharing-census"]
    sealed = load("sealed_snapshot.json")
    assert seal_verified(sealed), "positive control must verify"
    assert rule_satisfied(sealed, required), "positive control satisfies"
    assert snapshot_verdict(sealed, required) == "satisfied"
    unsealed = load("unsealed_snapshot.json")
    assert not seal_verified(unsealed), "seal must be absent"
    assert not rule_satisfied(unsealed, required), \
        "unsealed evidence satisfies no rule"
    assert snapshot_verdict(unsealed, required) != "satisfied"


def test_duplicate_source_and_cross_epoch_evidence_rejected():
    clean = facts_from_lines(load("sealed_snapshot.json"))
    assert clean, "positive control replays facts"
    assert duplicate_evidence_error(clean) is None
    assert cross_epoch_error(clean) is None
    duplicate = facts_from_lines(load("duplicate_evidence.json"))
    assert duplicate_evidence_error(duplicate) is not None, \
        "reused evidence handle must be rejected"
    mixed = facts_from_lines(load("cross_epoch_evidence.json"))
    assert cross_epoch_error(mixed) is not None, \
        "one source across two epochs must be rejected"
    assert not rule_satisfied(load("duplicate_evidence.json"),
                              ["sharing-census"])
    assert not rule_satisfied(load("cross_epoch_evidence.json"),
                              ["sharing-census"])
    assert not seal_verified(load("duplicate_evidence.json")), \
        "duplicate evidence cannot verify"
    assert not seal_verified(load("cross_epoch_evidence.json")), \
        "mixed epochs cannot verify"


def test_snapshot_path_refuses_unknown_and_non_object_integrity():
    sealed = load("sealed_snapshot.json")
    bogus = json.loads(json.dumps(sealed))
    bogus["session"]["capture"]["integrity"]["bogus"] = "0"
    with pytest.raises(ValueError):
        seal_verified(bogus)
    kinds = json.loads(json.dumps(sealed))
    kinds["session"]["capture"]["integrity"]["kinds"]["bogus"] = "1"
    with pytest.raises(ValueError):
        seal_verified(kinds)
    null = json.loads(json.dumps(sealed))
    null["session"]["capture"]["integrity"] = None
    with pytest.raises(ValueError):
        seal_verified(null)
    assert not seal_verified(load("unsealed_snapshot.json")), \
        "absent integrity stays merely unsealed"


def test_snapshot_lines_carry_position_and_trailing_newline():
    sealed = load("sealed_snapshot.json")
    shifted = json.loads(json.dumps(sealed))
    line = json.loads(shifted["event_lines"][0])
    line["seq"] = "5"
    shifted["event_lines"][0] = json.dumps(line) + "\n"
    with pytest.raises(ValueError):
        seal_verified(shifted)
    stripped = json.loads(json.dumps(sealed))
    stripped["event_lines"][0] = stripped["event_lines"][0].rstrip("\n")
    with pytest.raises(ValueError):
        seal_verified(stripped)


def test_snapshot_lines_split_and_bound_physical_lines():
    sealed = load("sealed_snapshot.json")
    split = json.loads(json.dumps(sealed))
    split["event_lines"][0] = split["event_lines"][0] + "\n"
    with pytest.raises(ValueError):
        seal_verified(split)
    entry = sealed["event_lines"][0]
    pad = SNAPSHOT_MAX_LINE_BYTES - len(entry.encode("utf-8"))
    assert pad > 0, "fixture entry fits the bound"
    oversize = json.loads(json.dumps(sealed))
    oversize["event_lines"][0] = " " * (pad + 1) + entry
    with pytest.raises(ValueError):
        seal_verified(oversize)
    capped = json.loads(json.dumps(sealed))
    capped["event_lines"][0] = " " * pad + entry
    assert not seal_verified(capped), "edited bytes must fail the seal"


def resealed_mutation(mutator):
    """The sealed snapshot with line 0 mutated and the seal recomputed."""
    snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
    lines = snapshot["event_lines"]
    event = json.loads(lines[0])
    assert event["kind"] == "exposure_fact"
    mutator(event)
    lines[0] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    snapshot["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    return snapshot


def test_foreign_session_fact_cannot_satisfy_rule():
    def foreign(event):
        event["session_id"] = "other-session"

    mutated = resealed_mutation(foreign)
    assert not seal_verified(mutated), \
        "foreign-session fact must fail the seal"
    assert not rule_satisfied(mutated, ["sharing-census"]), \
        "foreign-session evidence never satisfies"
    assert snapshot_verdict(mutated, ["sharing-census"]) == "inconclusive"


def test_malformed_fact_fields_cannot_satisfy_rule():
    def mistyped(event):
        event["data"]["native_result"] = "0"

    mutated = resealed_mutation(mistyped)
    assert not seal_verified(mutated), \
        "mistyped fact field must fail the seal"
    assert not rule_satisfied(mutated, ["sharing-census"]), \
        "malformed fact evidence never satisfies"
    assert snapshot_verdict(mutated, ["sharing-census"]) == "inconclusive"


def test_persisted_foreign_and_malformed_snapshots_refused():
    required = ["sharing-census"]
    foreign = load("foreign_session.json")
    assert not seal_verified(foreign), \
        "persisted foreign-session snapshot must fail the seal"
    assert snapshot_verdict(foreign, required) == "inconclusive"
    malformed = load("malformed_fact.json")
    assert not seal_verified(malformed), \
        "persisted malformed-fact snapshot must fail the seal"
    assert snapshot_verdict(malformed, required) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in malformed["event_lines"]:
            jsonschema.validate(json.loads(line), schema)


def test_persisted_unknown_enum_snapshots_refused():
    required = ["sharing-census"]
    schema = load_schema("event-v0.3.0.schema.json")
    for name in ("invalid_semantics.json", "invalid_clock_domain.json"):
        snapshot = load(name)
        assert not seal_verified(snapshot), \
            "persisted %s must fail the seal" % name
        assert snapshot_verdict(snapshot, required) == "inconclusive"
        with pytest.raises(jsonschema.ValidationError):
            for line in snapshot["event_lines"]:
                jsonschema.validate(json.loads(line), schema)


def test_unknown_fact_enums_cannot_satisfy_rule():
    def mistyped_semantics(event):
        event["data"]["semantics"] = "guess"

    def mistyped_clock(event):
        event["data"]["clock_domain"] = "wall_clock"

    for mutator, label in ((mistyped_semantics, "semantics"),
                           (mistyped_clock, "clock domain")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "unknown %s must fail the seal" % label
        assert not rule_satisfied(mutated, ["sharing-census"]), \
            "unknown-%s evidence never satisfies" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_every_frozen_fact_enum_verifies():
    def relabel(field, value):
        def apply(event):
            event["data"][field] = value
        return apply

    for semantics in FROZEN_SEMANTICS:
        mutated = resealed_mutation(relabel("semantics", semantics))
        assert seal_verified(mutated), \
            "frozen semantics %r must verify" % semantics
    for clock in FROZEN_CLOCK:
        mutated = resealed_mutation(relabel("clock_domain", clock))
        assert seal_verified(mutated), \
            "frozen clock domain %r must verify" % clock


def test_every_frozen_peer_and_source_verifies():
    def relabel(field, value):
        def apply(event):
            event["data"][field] = value
        return apply

    for peer in FROZEN_PEER:
        mutated = resealed_mutation(relabel("peer_class", peer))
        assert seal_verified(mutated), \
            "frozen peer class %r must verify" % peer
    for source in SOURCE_CAPABILITIES:
        mutated = resealed_mutation(relabel("source_id", source))
        assert seal_verified(mutated), \
            "catalog source %r must verify" % source


def test_unknown_peer_and_reversed_interval_cannot_satisfy_rule():
    def bad_peer(event):
        event["data"]["peer_class"] = "unknown-peer"

    def reversed_interval(event):
        event["data"]["observed_interval"]["start"] = "2000000000"

    for mutator, label in ((bad_peer, "peer class"),
                           (reversed_interval, "interval order")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "unknown %s must fail the seal" % label
        assert not rule_satisfied(mutated, ["sharing-census"]), \
            "unknown-%s evidence never satisfies" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_unknown_source_quality_and_stray_reason_cannot_satisfy():
    def bad_source(event):
        event["data"]["source_id"] = "unknown-source"

    def bad_quality(event):
        event["data"]["quality"]["detail"]["status"] = "unknown-quality"

    def stray_reason(event):
        event["data"]["parent_operation_id_reason"] = "unknown-parent"

    for mutator, label in ((bad_source, "source"),
                           (bad_quality, "quality status"),
                           (stray_reason, "stray reason")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "unknown %s must fail the seal" % label
        assert not rule_satisfied(mutated, ["sharing-census"]), \
            "unknown-%s evidence never satisfies" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_fact_identifier_and_interval_shapes_cannot_satisfy():
    def empty_id(event):
        event["data"]["evidence_id"] = ""

    def null_interval(event):
        event["data"]["observed_interval"] = None

    def native_without_reason(event):
        event["data"]["native_result"] = None

    for mutator, label in ((empty_id, "evidence id"),
                           (null_interval, "interval shape"),
                           (native_without_reason, "native reason")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "malformed %s must fail the seal" % label
        assert not rule_satisfied(mutated, ["sharing-census"]), \
            "malformed-%s evidence never satisfies" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_fact_envelope_must_keep_its_canonical_shape():
    def bad_version(event):
        event["schema_version"] = "0.1.1"

    def bad_timestamp(event):
        event["ts_ns"] = "01"

    def bad_source(event):
        del event["source"]["correlation"]

    for mutator, label in ((bad_version, "schema version"),
                           (bad_timestamp, "timestamp"),
                           (bad_source, "source")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "malformed %s must fail the seal" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def resealed_marker(payload):
    """The sealed snapshot with the marker payload replaced.

    A payload of ``None`` drops ``data`` entirely; the seal is
    recomputed so only the shape gate can refuse.
    """
    snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
    lines = snapshot["event_lines"]
    for index, line in enumerate(lines):
        event = json.loads(line)
        if event["kind"] != "marker":
            continue
        if payload is None:
            del event["data"]
        else:
            event["data"] = payload
        lines[index] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    snapshot["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    return snapshot


def test_malformed_marker_payloads_cannot_verify():
    assert seal_verified(resealed_marker({"text": "census sealed"})), \
        "valid marker must verify"
    assert seal_verified(resealed_marker({"text": "x" * 256})), \
        "bounded marker must verify"
    payloads = (None, "nope", {}, {"text": ""}, {"text": "x" * 257},
                {"text": "census sealed", "extra": "nope"})
    for payload in payloads:
        mutated = resealed_marker(payload)
        assert not seal_verified(mutated), \
            "malformed marker %r must fail the seal" % (payload,)
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_rule_needs_facts_from_each_required_source():
    snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
    lines = snapshot["event_lines"]
    for index, line in enumerate(lines):
        event = json.loads(line)
        if event["kind"] == "exposure_fact":
            event["data"]["source_id"] = "egress-controls"
            lines[index] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    snapshot["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    assert seal_verified(snapshot), \
        "well-formed foreign facts still seal"
    assert not rule_satisfied(snapshot, ["sharing-census"]), \
        "facts from another source never satisfy"
    assert snapshot_verdict(snapshot, ["sharing-census"]) == "inconclusive"


def resealed_marker_event(mutator):
    """The sealed snapshot with the whole marker event mutated.

    Unlike :func:`resealed_marker`, the mutation sees the full
    envelope, so envelope breaks (a dropped timestamp, a stray
    source key) can be resealed; only the shape gates can refuse.
    """
    snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
    lines = snapshot["event_lines"]
    for index, line in enumerate(lines):
        event = json.loads(line)
        if event["kind"] != "marker":
            continue
        mutator(event)
        lines[index] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    snapshot["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    return snapshot


def resealed_bounce(mutator):
    """The bounce control snapshot with the bounce line mutated.

    The seal is recomputed so only the payload gates can refuse.
    """
    snapshot = json.loads(json.dumps(load("sealed_with_bounce.json")))
    lines = snapshot["event_lines"]
    for index, line in enumerate(lines):
        event = json.loads(line)
        if event["kind"] != "bounce_attempt":
            continue
        mutator(event)
        lines[index] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    snapshot["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    return snapshot


def test_empty_reasons_cannot_verify():
    def empty_parent(event):
        event["data"]["parent_operation_id_reason"] = ""

    def empty_object(event):
        event["data"]["object_token_reason"] = ""

    def empty_native(event):
        event["data"]["native_result_reason"] = ""

    for mutator, label in ((empty_parent, "parent"),
                           (empty_object, "object"),
                           (empty_native, "native")):
        mutated = resealed_mutation(mutator)
        assert not seal_verified(mutated), \
            "empty %s reason must fail the seal" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"
    persisted = load("empty_reason.json")
    assert not seal_verified(persisted), \
        "persisted empty reason must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in persisted["event_lines"]:
            jsonschema.validate(json.loads(line), schema)


def test_duplicate_event_keys_cannot_verify():
    persisted = load("duplicate_seq.json")
    assert not seal_verified(persisted), \
        "duplicated seq must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    with pytest.raises(DuplicateKeyError):
        loads_strict(persisted["event_lines"][0])
    assert loads_strict('{"a":"1"}') == {"a": "1"}


def test_incomplete_seal_census_cannot_verify():
    persisted = load("missing_census_kind.json")
    assert not seal_verified(persisted), \
        "missing census kind must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("session-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(persisted["session"], schema)


def test_null_fact_quality_refused_cleanly():
    persisted = load("null_fact_quality.json")
    assert not seal_verified(persisted), \
        "null fact quality must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in persisted["event_lines"]:
            jsonschema.validate(json.loads(line), schema)


def test_non_fact_lines_keep_their_envelope():
    persisted = load("marker_missing_ts.json")
    assert not seal_verified(persisted), \
        "marker without ts_ns must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in persisted["event_lines"]:
            jsonschema.validate(json.loads(line), schema)

    def drop_ts(event):
        del event["ts_ns"]

    def bad_ts(event):
        event["ts_ns"] = "01"

    def bad_version(event):
        event["schema_version"] = "0.1.1"

    def drop_source_key(event):
        del event["source"]["correlation"]

    for mutator, label in ((drop_ts, "timestamp"),
                           (bad_ts, "timestamp shape"),
                           (bad_version, "schema version"),
                           (drop_source_key, "source")):
        mutated = resealed_marker_event(mutator)
        assert not seal_verified(mutated), \
            "marker with malformed %s must fail the seal" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"
    control = json.loads(load("sealed_snapshot.json")["event_lines"][2])
    assert control["kind"] == "marker"
    assert non_fact_fields_valid(control), "valid marker must verify"
    control["kind"] = "frobnicate"
    assert not non_fact_fields_valid(control), \
        "unknown kind verifies nowhere"


def test_bounce_attempt_payload_validated():
    control = load("sealed_with_bounce.json")
    assert seal_verified(control), "valid bounce control must verify"
    assert rule_satisfied(control, ["sharing-census"])
    assert snapshot_verdict(control, ["sharing-census"]) == "satisfied"
    persisted = load("empty_bounce.json")
    assert not seal_verified(persisted), \
        "empty bounce payload must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in persisted["event_lines"]:
            jsonschema.validate(json.loads(line), schema)

    def drop_device(event):
        del event["data"]["device_id"]

    def mistype_forced(event):
        event["data"]["forced"] = "false"

    def mistype_bytes(event):
        event["data"]["requested_bytes"] = "01"

    def extra_key(event):
        event["data"]["extra"] = "nope"

    def empty_data(event):
        event["data"] = {}

    for mutator, label in ((drop_device, "device"),
                           (mistype_forced, "forced flag"),
                           (mistype_bytes, "byte count"),
                           (extra_key, "extra key"),
                           (empty_data, "empty payload")):
        mutated = resealed_bounce(mutator)
        assert not seal_verified(mutated), \
            "bounce with malformed %s must fail the seal" % label
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_source_labels_come_from_frozen_sets():
    persisted = load("guess_measurement.json")
    assert not seal_verified(persisted), \
        "guessed measurement must fail the seal"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "inconclusive"
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        for line in persisted["event_lines"]:
            jsonschema.validate(json.loads(line), schema)

    def mislabel(leaf, value):
        def apply(event):
            event["source"][leaf] = value
        return apply

    for leaf, value in (("measurement", "guess"),
                        ("correlation", "guess"),
                        ("measurement", ""),
                        ("correlation", "")):
        mutated = resealed_mutation(mislabel(leaf, value))
        assert not seal_verified(mutated), \
            "fact with %s %r must fail the seal" % (leaf, value)
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"
    for leaf in ("measurement", "correlation"):
        mutated = resealed_marker_event(mislabel(leaf, "guess"))
        assert not seal_verified(mutated), \
            "marker with guessed %s must fail the seal" % leaf
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"
    for measurement in FROZEN_MEASUREMENT:
        for correlation in FROZEN_CORRELATION:
            def apply(event):
                event["source"]["measurement"] = measurement
                event["source"]["correlation"] = correlation

            mutated = resealed_mutation(apply)
            assert seal_verified(mutated), \
                "frozen labels %r/%r must verify" % (measurement,
                                                    correlation)


def test_persisted_source_scope_needs_matching_facts():
    snapshot = load("source_scope.json")
    assert seal_verified(snapshot), \
        "well-formed foreign facts still seal"
    assert not rule_satisfied(snapshot, ["sharing-census"]), \
        "facts from another source never satisfy"
    assert snapshot_verdict(snapshot, ["sharing-census"]) == "inconclusive"


def test_missing_terminal_evidence_is_partial():
    required = ["sharing-census"]
    assert snapshot_verdict(load("sealed_snapshot.json"),
                            required) == "satisfied"
    unsettled = load("missing_terminal.json")
    assert unsettled["session"]["quality"]["terminal"]["status"] \
        != "complete_for_scope"
    assert snapshot_verdict(unsettled, required) == "partial"
    assert not rule_satisfied(unsettled, required), \
        "unsettled evidence never satisfies"


def test_legacy_fixtures_immutable():
    pinned = {
        "tests/fixtures/attempts/session.json":
            "77bc1cfd5b5c474d873566a7cdb80a3adfa20bd8033c4e56ede5763a10c53b2b",
        "tests/fixtures/attempts/events.ndjson":
            "f1bd78555a56c88fb7180b10bf16612b1f0c5a3cdfb7d5ef15df476082543ec8",
        "tests/fixtures/attempts/expected-report.json":
            "fd9141a9194ec8fd9df56e1245fd422a64eafff34c8e5fd1208c504e55e01152",
    }
    for rel, digest in pinned.items():
        with open(os.path.join(REPO, rel), "rb") as handle:
            body = handle.read()
        assert hashlib.sha256(body).hexdigest() == digest, \
            "legacy fixture changed: %s" % rel
    with open(os.path.join(REPO, "tests", "fixtures", "attempts",
                            "session.json"), encoding="utf-8") as handle:
        session = json.load(handle)
    assert session["schema_version"] == "0.1.1"
    assert session["session_id"] == "attempts-3-session"
    with open(os.path.join(REPO, "tests", "fixtures", "attempts",
                            "events.ndjson"), encoding="utf-8") as handle:
        first = json.loads(handle.readline())
    assert first["schema_version"] == "0.1.1"
    assert first["kind"] == "bounce_attempt"


def test_schema_files_wellformed():
    names = ("session-v0.3.0.schema.json", "event-v0.3.0.schema.json",
             "report-v0.3.0.schema.json", "policy-v0.1.0.schema.json")
    for name in names:
        with open(os.path.join(REPO, "schemas", name),
                  encoding="utf-8") as handle:
            doc = json.load(handle)
        assert doc["$schema"] == \
            "https://json-schema.org/draft/2020-12/schema", name
        assert doc["$id"] == name, name
    session = load("sealed_snapshot.json")["session"]
    assert session["schema_version"] == "0.3.0"


def test_fixture_records_match_frozen_shapes():
    snapshot = load("sealed_snapshot.json")
    session = snapshot["session"]
    for entry in session["exposure"]["sources"]:
        for field in COVERAGE_SOURCE_REQUIRED:
            assert field in entry, "coverage source field %s" % field
        check_source_capability(entry)
        assert entry["phase"] in FROZEN_PHASE
        assert entry["status"] in FROZEN_STATUS
        assert entry["address_namespace"] in FROZEN_NAMESPACE
        check_u64(entry["window"]["start_ns"], "window.start_ns")
        check_u64(entry["window"]["end_ns"], "window.end_ns")
        check_quality(entry["quality"], "coverage source quality")
    check_session_quality(session["quality"])
    facts = facts_from_lines(snapshot)
    assert facts, "positive control carries facts"
    for fact in facts:
        for field in EXPOSURE_FACT_REQUIRED:
            assert field in fact, "exposure fact field %s" % field
        check_u64(fact["epoch"], "epoch")
        check_u64(fact["generation"], "generation")
        check_u64(fact["offset"], "offset")
        check_u64(fact["length_bytes"], "length_bytes")
        assert fact["semantics"] in FROZEN_SEMANTICS
        assert fact["clock_domain"] in FROZEN_CLOCK
        check_quality(fact["quality"], "fact quality")
        native = fact["native_result"]
        reason = fact.get("native_result_reason")
        assert (native is None) == (reason is not None), \
            "null native result needs a typed reason"


def test_coverage_pairing_and_missing_sources_follow_catalog():
    snapshot = load("sealed_snapshot.json")
    for entry in snapshot["session"]["exposure"]["sources"]:
        check_source_capability(entry)
    mixed = json.loads(json.dumps(snapshot))
    mixed["session"]["exposure"]["sources"][0]["capability"] = \
        "host-interfaces"
    with pytest.raises(AssertionError):
        check_source_capability(
            mixed["session"]["exposure"]["sources"][0])
    report = load("report_valid.json")
    for entry in report["policy_results"]:
        check_missing_sources(entry)
    unknown = json.loads(json.dumps(report))
    unknown["policy_results"][0]["missing_sources"] = ["unknown-source"]
    with pytest.raises(AssertionError):
        check_missing_sources(unknown["policy_results"][0])


def test_policy_file_shape():
    policy = load("policy_valid.json")
    assert policy["schema"] == "policy"
    assert policy["schema_version"] == "0.1.0"
    for field in ("policy_id", "subject_scope", "applies_to",
                  "required_sources", "clock", "role_bindings",
                  "rules", "exceptions"):
        assert field in policy, "policy field %s" % field
    assert policy["clock"] in FROZEN_CLOCK
    assert 1 <= len(policy["policy_id"]) <= 64
    assert len(policy["rules"]) >= 1
    for rule in policy["rules"]:
        for field in ("rule_id", "selector", "permitted", "limit"):
            assert field in rule, "rule field %s" % field
        assert 1 <= len(rule["rule_id"]) <= 64
    assert len(policy["exceptions"]) == 0


def load_schema(name):
    with open(os.path.join(REPO, "schemas", name),
              encoding="utf-8") as handle:
        return json.load(handle)


def test_all_fixtures_validate_against_schemas():
    session_schema = load_schema("session-v0.3.0.schema.json")
    event_schema = load_schema("event-v0.3.0.schema.json")
    report_schema = load_schema("report-v0.3.0.schema.json")
    policy_schema = load_schema("policy-v0.1.0.schema.json")
    sealed_names = ("sealed_snapshot.json", "duplicate_evidence.json",
                    "cross_epoch_evidence.json", "missing_terminal.json",
                    "foreign_session.json", "sealed_with_bounce.json",
                    "source_scope.json")
    for name in sealed_names:
        snapshot = load(name)
        jsonschema.validate(snapshot["session"], session_schema)
        assert snapshot["event_lines"], "%s carries lines" % name
        for line in snapshot["event_lines"]:
            jsonschema.validate(json.loads(line), event_schema)
    unsealed = load("unsealed_snapshot.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(unsealed["session"], session_schema)
    for line in unsealed["event_lines"]:
        jsonschema.validate(json.loads(line), event_schema)
    jsonschema.validate(load("report_valid.json"), report_schema)
    jsonschema.validate(load("policy_valid.json"), policy_schema)


def test_comparison_delta_follows_compatibility():
    schema = load_schema("report-v0.3.0.schema.json")

    def check(comparison, valid):
        report = load("report_valid.json")
        report["comparisons"] = [comparison]
        if valid:
            jsonschema.validate(report, schema)
        else:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(report, schema)

    base = load("report_valid.json")["comparisons"][0]
    check(dict(base), True)
    null_delta = dict(base)
    null_delta["delta"] = None
    null_delta["delta_reason"] = "uncomputable"
    check(null_delta, True)
    incompatible = dict(base)
    incompatible["compatibility"] = "incompatible"
    del incompatible["delta"]
    check(incompatible, True)
    bad_null = dict(incompatible)
    bad_null["delta"] = None
    bad_null["delta_reason"] = "uncomputable"
    check(bad_null, False)
    bad_valued = dict(incompatible)
    bad_valued["delta"] = 3
    check(bad_valued, False)
    bad_absent = dict(base)
    del bad_absent["delta"]
    check(bad_absent, False)


def test_stray_reason_without_value_refused():
    schema = load_schema("event-v0.3.0.schema.json")
    for key in ("parent_operation_id", "object_token"):
        event = json.loads(load("sealed_snapshot.json")["event_lines"][0])
        event["data"].pop(key, None)
        event["data"][key + "_reason"] = "unknown"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(event, schema)
        paired = json.loads(load("sealed_snapshot.json")["event_lines"][0])
        paired["data"][key] = None
        paired["data"][key + "_reason"] = "unknown"
        jsonschema.validate(paired, schema)
    report_schema = load_schema("report-v0.3.0.schema.json")
    report = load("report_valid.json")
    comparison = report["comparisons"][0]
    comparison.update(compatibility="incompatible",
                      delta_reason="unknown")
    del comparison["delta"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(report, report_schema)


def test_signed_fields_bounded_to_i64():
    schema = load_schema("event-v0.3.0.schema.json")

    def check_event(value, valid):
        event = json.loads(load("sealed_snapshot.json")["event_lines"][0])
        event["data"]["native_result"] = value
        if valid:
            jsonschema.validate(event, schema)
        else:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(event, schema)

    check_event(2**63 - 1, True)
    check_event(-(2**63), True)
    check_event(2**63, False)
    check_event(-(2**63) - 1, False)
    report_schema = load_schema("report-v0.3.0.schema.json")

    def check_delta(value, valid):
        report = load("report_valid.json")
        report["comparisons"][0]["delta"] = value
        if valid:
            jsonschema.validate(report, report_schema)
        else:
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(report, report_schema)

    check_delta(2**63 - 1, True)
    check_delta(-(2**63), True)
    check_delta(2**63, False)
    check_delta(-(2**63) - 1, False)


POLICY_MAX_BYTES = 1048576
POLICY_MAX_RULES = 1024
POLICY_MAX_EXCEPTIONS_PER_RULE = 64


def check_policy_bounds(policy, raw):
    """Enforce the published policy-file bounds on bytes and counts.

    Shapes stay with the schema; the loader refuses oversize files,
    an empty or overfull rule list, and any rule carrying more than
    64 exceptions.
    """
    if len(raw) > POLICY_MAX_BYTES:
        raise ValueError("policy file exceeds 1 MiB")
    rules = policy["rules"]
    if not 1 <= len(rules) <= POLICY_MAX_RULES:
        raise ValueError("rule count out of bounds")
    if not policy["required_sources"]:
        raise ValueError("required sources must not be empty")
    per_rule = {}
    for entry in policy["exceptions"]:
        handle = entry["rule_id"]
        per_rule[handle] = per_rule.get(handle, 0) + 1
    for handle in sorted(per_rule):
        if per_rule[handle] > POLICY_MAX_EXCEPTIONS_PER_RULE:
            raise ValueError("rule %r exceeds 64 exceptions" % handle)
    return (len(rules), len(policy["exceptions"]))


def test_policy_bounds_enforced():
    with open(os.path.join(FIX, "policy_valid.json"), "rb") as handle:
        raw = handle.read()
    policy = json.loads(raw.decode("utf-8"))
    assert check_policy_bounds(policy, raw) == (1, 0)
    with pytest.raises(ValueError):
        check_policy_bounds(policy, b"x" * (POLICY_MAX_BYTES + 1))
    empty = json.loads(json.dumps(policy))
    empty["rules"] = []
    with pytest.raises(ValueError):
        check_policy_bounds(empty, b"{}")
    flood = json.loads(json.dumps(policy))
    flood["exceptions"] = [{"rule_id": "r", "constraint": "c",
                            "reason": "w"} for _ in range(65)]
    with pytest.raises(ValueError):
        check_policy_bounds(flood, b"{}")
    capped = json.loads(json.dumps(policy))
    capped["exceptions"] = [{"rule_id": "r", "constraint": "c",
                             "reason": "w"} for _ in range(64)]
    assert check_policy_bounds(capped, b"{}") == (1, 64)
    schema = load_schema("policy-v0.1.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(empty, schema)


def test_policy_result_arrays_reject_scalar_strings():
    schema = load_schema("report-v0.3.0.schema.json")
    report = load("report_valid.json")
    check_policy_result_arrays(report["policy_results"][0])
    scalars = {"evidence_ids": "ev-1",
               "missing_sources": "sharing-census",
               "exceptions_applied": "rule-1"}
    for field, scalar in scalars.items():
        mutated = json.loads(json.dumps(report))
        mutated["policy_results"][0][field] = scalar
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(mutated, schema)
        with pytest.raises(AssertionError):
            check_policy_result_arrays(mutated["policy_results"][0])


def test_report_records_shape():
    report = load("report_valid.json")
    assert report["schema_version"] == "0.3.0"
    assert report["policy_results"], "report carries policy results"
    for entry in report["policy_results"]:
        for field in ("rule_id", "scope_id", "result", "evidence_ids",
                      "missing_sources", "exceptions_applied",
                      "clock_domain", "reason"):
            assert field in entry, "policy result field %s" % field
        assert entry["result"] in FROZEN_POLICY_RESULT
        check_missing_sources(entry)
        assert entry["clock_domain"] in FROZEN_CLOCK
    assert report["comparisons"], "report carries comparisons"
    for entry in report["comparisons"]:
        for field in ("metric_id", "compatibility", "reason",
                      "left_evidence", "right_evidence", "unit",
                      "scope", "quality"):
            assert field in entry, "comparison field %s" % field
        assert entry["compatibility"] in FROZEN_COMPATIBILITY
        check_quality(entry["quality"], "comparison quality")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
