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
FROZEN_SUBJECT = ("guest-kernel-memory-management", "guest-direct-map",
                  "guest-kernel-allocator", "guest-driver-virtio",
                  "guest-driver-dma", "guest-kernel-cc-platform",
                  "guest-kernel-vmbus", "guest-configuration",
                  "capture-evidence")
FROZEN_CELL = ("ordinary-linux", "sev-snp", "tdx-standalone",
               "hyper-v")
FROZEN_REASON = ("adapter-unimplemented", "no-safe-source",
                 "lease-pending", "access-denied", "hook-absent",
                 "cell-unselected", "quarantined",
                 "not-applicable-platform")
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

EXPOSURE_CONTRACT = "exposure"
LEGACY_CONTRACT = "legacy"
LEGACY_SESSION_VERSIONS = ("0.1.1", "0.1.2", "0.1.3", "0.1.4")
LEGACY_LINE_VERSIONS = ("0.1.1", "0.1.2")
SOURCE_BOUNDS = (("hook", 256), ("backend", 64), ("profile_id", 128))


def snapshot_contract(session):
    """The event-line contract a session selects, or None when unknown.

    A 0.3.0 session selects the exposure contract; a 0.1.x session
    selects the legacy contract. The seal validates every line
    under the session's contract, so legacy captures verify under
    legacy rules while 0.3.0 lines keep the new checks, and neither
    side admits the other's version.
    """
    version = session.get("schema_version")
    if version == "0.3.0":
        return EXPOSURE_CONTRACT
    if version in LEGACY_SESSION_VERSIONS:
        return LEGACY_CONTRACT
    return None


def is_u64_text(value):
    """True for a canonical u64 decimal string within range."""
    return isinstance(value, str) and U64RE.fullmatch(value) is not None \
        and int(value) <= U64MAX


def is_opaque_text(value):
    """True for a bounded opaque identifier."""
    return isinstance(value, str) \
        and OPAQUE_RE.fullmatch(value) is not None


def is_bare_int(value):
    """True for a bare JSON integer within i64 range, never a boolean.

    Mirrors the Rust parser, which canonicalizes bare integers to
    i64 text: anything past the range never parses there, so it
    refuses here too.
    """
    return isinstance(value, int) and not isinstance(value, bool) \
        and I64MIN <= value <= I64MAX


def is_sized_text(value, limit):
    """True for a non-empty string within the schema length bound."""
    return isinstance(value, str) and 1 <= len(value) <= limit


def source_bounds_valid(source):
    """True when hook, backend and profile_id keep their bounds."""
    try:
        for field, limit in SOURCE_BOUNDS:
            if not is_sized_text(source[field], limit):
                return False
    except (KeyError, TypeError):
        return False
    return True


def observer_context_valid(value):
    """True when a legacy observer context keeps its schema shape.

    The relation is fixed; cpu, pid, tgid, comm and cgroup_id are
    optional bounded leaves. Only legacy lines carry one.
    """
    try:
        if not isinstance(value, dict):
            return False
        allowed = {"cpu", "pid", "tgid", "comm", "cgroup_id",
                   "relation"}
        if set(value.keys()) - allowed:
            return False
        if value.get("relation") != "execution_context_only":
            return False
        for field, limit in (("cpu", 1048575), ("pid", 4194304),
                             ("tgid", 4194304)):
            if field in value:
                number = value[field]
                if not is_bare_int(number):
                    return False
                if not 0 <= number <= limit:
                    return False
        if "comm" in value:
            comm = value["comm"]
            if not isinstance(comm, str) or len(comm) > 64:
                return False
        if "cgroup_id" in value:
            check_opaque_id(value["cgroup_id"], "cgroup_id")
    except (AssertionError, KeyError, TypeError):
        return False
    return True


def event_envelope_valid(event, contract):
    """True when one event envelope keeps its canonical shape.

    The seven envelope keys are present with nothing unknown,
    except that a legacy line may carry a validated observer
    context; the version is the session's contract, the timestamp
    is a canonical u64, and the source carries its five string
    leaves within their bounds with frozen labels. Sequence and
    session checks stay with the seal loop, as in Rust; the caller
    owns kind membership.
    """
    try:
        if not isinstance(event, dict):
            return False
        keys = set(event.keys())
        if contract == EXPOSURE_CONTRACT:
            if keys != set(ENVELOPE_FIELDS):
                return False
            if event["schema_version"] != "0.3.0":
                return False
        elif contract == LEGACY_CONTRACT:
            if event.get("schema_version") not in LEGACY_LINE_VERSIONS:
                return False
            allowed = set(ENVELOPE_FIELDS) | {"observer_context"}
            if keys - allowed or not set(ENVELOPE_FIELDS) <= keys:
                return False
            if "observer_context" in event and not observer_context_valid(
                    event["observer_context"]):
                return False
        else:
            return False
        if not isinstance(event["session_id"], str):
            return False
        check_u64(event["ts_ns"], "ts_ns")
        source = event["source"]
        if not isinstance(source, dict):
            return False
        if set(source.keys()) != set(SOURCE_FIELDS):
            return False
        if not source_bounds_valid(source):
            return False
        if source["measurement"] not in FROZEN_MEASUREMENT:
            return False
        if source["correlation"] not in FROZEN_CORRELATION:
            return False
    except (AssertionError, KeyError, TypeError):
        return False
    return True


def fact_envelope_valid(event, contract):
    """True when an exposure-fact line keeps its canonical envelope.

    Exposure facts exist only under the exposure contract.
    Otherwise mirrors the Rust normalizer's envelope checks plus
    the seal path's frozen source labels: the seven envelope keys
    are present with nothing unknown, the version is the exposure
    contract, the timestamp is a canonical u64, and the source
    carries its five string leaves within their bounds with frozen
    labels. Sequence and session checks stay with the seal loop,
    as in Rust.
    """
    if contract != EXPOSURE_CONTRACT:
        return False
    if not isinstance(event, dict):
        return False
    return event.get("kind") == "exposure_fact" \
        and event_envelope_valid(event, contract)


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


def map_result_valid(data):
    """True when a map-result payload keeps its schema shape."""
    try:
        if set(data.keys()) != {"operation_id", "success", "mapping_id",
                                "return_code", "mapped_bytes",
                                "wire_generation", "wire_identity"}:
            return False
        if not is_opaque_text(data["operation_id"]):
            return False
        success = data["success"]
        if not isinstance(success, bool):
            return False
        mapping = data["mapping_id"]
        if mapping is not None and not is_opaque_text(mapping):
            return False
        native = data["return_code"]
        if native is not None and not is_bare_int(native):
            return False
        mapped = data["mapped_bytes"]
        if mapped is not None and not is_u64_text(mapped):
            return False
        generation = data["wire_generation"]
        if generation is not None and not is_u64_text(generation):
            return False
        identity = data["wire_identity"]
        if identity is not None \
                and identity not in ("known", "unassigned"):
            return False
        if success and identity != "unassigned":
            if not is_opaque_text(mapping) or not is_u64_text(mapped):
                return False
        if success and identity == "unassigned":
            if mapping is not None or not is_u64_text(mapped):
                return False
        if not success:
            if mapping is not None or mapped is not None \
                    or identity is not None:
                return False
        if generation is None and identity is not None:
            return False
        if identity is None and generation is not None \
                and (success or generation != "0"):
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def unmap_valid(data):
    """True when an unmap payload keeps its schema shape."""
    try:
        if set(data.keys()) != {"mapping_id", "wire_generation",
                                "wire_identity"}:
            return False
        mapping = data["mapping_id"]
        if mapping is not None and not is_opaque_text(mapping):
            return False
        generation = data["wire_generation"]
        if generation is not None and not is_u64_text(generation):
            return False
        identity = data["wire_identity"]
        if identity is not None and identity not in ("known", "miss"):
            return False
        if generation is None and identity is not None:
            return False
        if identity is None and generation is not None:
            return False
        if mapping is None and identity != "miss":
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def copy_valid(data, source, line_version):
    """True when a copy payload keeps its schema shape.

    Copies require observed measurement. The pool-private and
    offset flags exist from line version 0.1.2 on; a 0.1.1 copy
    carrying them refuses.
    """
    try:
        allowed = {"operation_id", "mapping_id", "direction", "bytes"}
        if line_version != "0.1.1":
            allowed |= {"pool_private", "offset_past_allocation"}
        keys = set(data.keys())
        if keys - allowed \
                or not {"operation_id", "mapping_id", "direction",
                        "bytes"} <= keys:
            return False
        if not isinstance(source, dict):
            return False
        if source.get("measurement") != "observed":
            return False
        if not is_opaque_text(data["operation_id"]):
            return False
        mapping = data["mapping_id"]
        if mapping is not None and not is_opaque_text(mapping):
            return False
        if data["direction"] not in ("original_to_bounce",
                                     "bounce_to_original"):
            return False
        if not is_u64_text(data["bytes"]):
            return False
        for flag in ("pool_private", "offset_past_allocation"):
            if flag in data and data[flag] is not True:
                return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def sync_request_valid(data):
    """True when a sync-request payload keeps its schema shape."""
    try:
        if set(data.keys()) != {"operation_id", "mapping_id",
                                "offset_known", "offset", "length"}:
            return False
        if not is_opaque_text(data["operation_id"]):
            return False
        mapping = data["mapping_id"]
        if mapping is not None and not is_opaque_text(mapping):
            return False
        known = data["offset_known"]
        if not isinstance(known, bool):
            return False
        offset = data["offset"]
        if offset is not None and not is_u64_text(offset):
            return False
        if not is_u64_text(data["length"]):
            return False
        if known and not is_u64_text(offset):
            return False
        if not known and offset is not None:
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def transition_result_valid(data):
    """True when a transition-result payload keeps its schema shape."""
    try:
        required = {"region_id", "requested_state", "success",
                    "return_code", "offset", "length"}
        allowed = required | {"address_space", "resolution",
                              "generation"}
        keys = set(data.keys())
        if keys - allowed or not required <= keys:
            return False
        if not is_opaque_text(data["region_id"]):
            return False
        if data["requested_state"] not in ("shared", "private"):
            return False
        if not isinstance(data["success"], bool):
            return False
        native = data["return_code"]
        if native is not None and not is_bare_int(native):
            return False
        if not is_u64_text(data["offset"]):
            return False
        if not is_u64_text(data["length"]):
            return False
        if "address_space" in data and data["address_space"] not in (
                "guest_physical", "kernel_virtual", "iova",
                "identity_only"):
            return False
        if "resolution" in data \
                and data["resolution"] not in ("resolved", "unresolved"):
            return False
        if "generation" in data:
            generation = data["generation"]
            if not is_bare_int(generation):
                return False
            if not 1 <= generation <= I64MAX:
                return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def pool_sample_valid(data):
    """True when a pool-sample payload keeps its schema shape."""
    try:
        required = {"pool_id", "used_bytes", "capacity_bytes", "unit"}
        allowed = required | {"allocator", "unit_bytes",
                              "hiwater_bytes", "reason"}
        keys = set(data.keys())
        if keys - allowed or not required <= keys:
            return False
        if not is_opaque_text(data["pool_id"]):
            return False
        for field in ("used_bytes", "capacity_bytes"):
            if data[field] is not None \
                    and not is_u64_text(data[field]):
                return False
        if data["unit"] not in ("bytes", "unknown"):
            return False
        if "allocator" in data \
                and not is_opaque_text(data["allocator"]):
            return False
        if "unit_bytes" in data \
                and not is_u64_text(data["unit_bytes"]):
            return False
        if "hiwater_bytes" in data:
            hiwater = data["hiwater_bytes"]
            if hiwater is not None and not is_u64_text(hiwater):
                return False
        if "reason" in data and data["reason"] not in (
                "denied", "absent", "unparseable"):
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def gap_valid(data):
    """True when a gap payload keeps its schema shape."""
    try:
        if set(data.keys()) != {"channel", "lost_count", "reason",
                                "window_start_ns", "window_end_ns"}:
            return False
        if data["channel"] not in ("detail", "aggregate", "correlation",
                                   "baseline", "terminal"):
            return False
        lost = data["lost_count"]
        if lost is not None and not is_u64_text(lost):
            return False
        if not is_sized_text(data["reason"], 512):
            return False
        if not is_u64_text(data["window_start_ns"]):
            return False
        if not is_u64_text(data["window_end_ns"]):
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def counter_snapshot_valid(data):
    """True when a counter-snapshot payload keeps its schema shape."""
    try:
        if set(data.keys()) != {"counter_id", "epoch", "scope", "value",
                                "unit"}:
            return False
        if not is_sized_text(data["counter_id"], 128):
            return False
        if not is_u64_text(data["epoch"]):
            return False
        scope = data["scope"]
        if not isinstance(scope, dict):
            return False
        keys = set(scope.keys())
        if keys - {"device_id", "profile_id"} \
                or "profile_id" not in keys:
            return False
        if "device_id" in scope:
            device = scope["device_id"]
            if device is not None and not is_opaque_text(device):
                return False
        if not is_sized_text(scope["profile_id"], 128):
            return False
        if not is_u64_text(data["value"]):
            return False
        if not is_sized_text(data["unit"], 32):
            return False
    except (AttributeError, KeyError, TypeError):
        return False
    return True


def legacy_payload_valid(kind, data, source, line_version):
    """True when a legacy payload keeps its per-kind schema shape.

    Every legacy kind carries exactly its schema leaves; a copy
    additionally requires observed measurement, and its two
    toggle flags exist from line version 0.1.2 on. Mirrors the
    event schemas and the Rust snapshot path.
    """
    if not isinstance(data, dict):
        return False
    if kind == "marker":
        return set(data.keys()) == {"text"} \
            and is_sized_text(data["text"], 256)
    if kind == "bounce_attempt":
        return bounce_payload_valid(data)
    if kind == "map_result":
        return map_result_valid(data)
    if kind == "unmap":
        return unmap_valid(data)
    if kind == "copy":
        return copy_valid(data, source, line_version)
    if kind == "sync_request":
        return sync_request_valid(data)
    if kind == "transition_result":
        return transition_result_valid(data)
    if kind == "pool_sample":
        return pool_sample_valid(data)
    if kind == "gap":
        return gap_valid(data)
    if kind == "counter_snapshot":
        return counter_snapshot_valid(data)
    return False


def non_fact_fields_valid(event, contract):
    """True when a non-fact line keeps its envelope payload shape.

    The kind is a legacy seal kind, the envelope keeps its
    canonical shape under the session's contract with bounded
    source strings and frozen labels, and the object ``data``
    payload keeps its per-kind schema shape. Mirrors the event
    schemas and the Rust snapshot path.
    """
    try:
        if not isinstance(event, dict):
            return False
        kind = event.get("kind")
        if kind == "exposure_fact" or kind not in SEAL_KINDS:
            return False
        if not event_envelope_valid(event, contract):
            return False
        return legacy_payload_valid(kind, event.get("data"),
                                    event.get("source"),
                                    event.get("schema_version"))
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


def coverage_key(entry):
    """The (source, subject, phase, window) identity of a coverage entry.

    Missing or mistyped leaves decode as None, so two entries that
    both omit a leaf still collide: an unkeyed entry never slips
    past the duplicate gate by being malformed.
    """
    if not isinstance(entry, dict):
        return None
    window = entry.get("window")
    if isinstance(window, dict):
        start = window.get("start_ns")
        end = window.get("end_ns")
    else:
        start = end = None

    def leaf(value):
        return value if isinstance(value, str) else None

    return (leaf(entry.get("source_id")), leaf(entry.get("subject_id")),
            leaf(entry.get("phase")), leaf(start), leaf(end))


def duplicate_coverage_error(sources):
    """The first repeated coverage identity, or None when unique."""
    seen = set()
    for entry in sources:
        key = coverage_key(entry)
        if key is None:
            continue
        if key in seen:
            return "duplicate coverage %r" % (key,)
        seen.add(key)
    return None


def seal_verified(snapshot):
    """True only when the committed seal matches the literal bytes.

    An absent integrity object verifies false; a present non-object,
    a non-object kinds table, or an unknown integrity field or kind
    raises, mirroring the Rust snapshot path. A well-formed seal that
    mismatches the bytes, that leaves a census kind uncommitted, or
    whose fact identities break containment, verifies false. The
    session carries its string session id even when the stream is
    empty, and its version selects the exposure or legacy line
    contract; an unknown contract verifies false. Coverage entries
    repeat no (source, subject, phase, window) identity: a repeated
    identity verifies false on every ordering, so conflicting
    availability never resolves by position. Every line parses
    without duplicated keys, ends in a newline, carries its
    position as its sequence number, and belongs to the snapshot's
    own session; one entry holds exactly one physical line under
    the reader's 64 KiB bound. Framing violations raise. A
    foreign-session line, a duplicated key, an exposure fact whose
    envelope, source labels or fields fail validation, or a
    non-fact line whose envelope, source labels or payload loses
    its shape verifies false, like a containment break: none can
    support a verdict.
    """
    expected_session = snapshot["session"].get("session_id")
    if not isinstance(expected_session, str):
        return False
    contract = snapshot_contract(snapshot["session"])
    if contract is None:
        return False
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
            if not fact_envelope_valid(event, contract):
                return False
            if not fact_fields_valid(event.get("data")):
                return False
        elif not non_fact_fields_valid(event, contract):
            return False
    exposure = snapshot["session"].get("exposure")
    if isinstance(exposure, dict) \
            and isinstance(exposure.get("sources"), list):
        if duplicate_coverage_error(exposure["sources"]) is not None:
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


def source_quality_usable(quality):
    """True when a coverage quality block validates with usable evidence.

    The block keeps exactly the five exposure channels, each with a
    frozen status and a null-or-canonical loss count; one unknown
    channel or invalid loss fails the whole block, never just that
    channel. Usability then follows the channel rule: a settled or
    partial channel carries evidence, anything else does not.
    """
    try:
        check_quality(quality, "source quality")
    except (AssertionError, KeyError, TypeError):
        return False
    return any(quality[channel]["status"] in ("complete_for_scope",
                                              "partial")
               for channel in QUALITY_CHANNELS)


def source_row_valid(entry):
    """True when a coverage row passes the full model validation.

    Mirrors ``CoverageSource::validate`` check for check: exactly
    the eleven coverage leaves with nothing unknown, a catalog
    source with its owning capability, an opaque profile, a frozen
    subject, cell, namespace, phase, status and reason, an ordered
    canonical window of exactly start and end, and a quality block
    of exactly the five exposure channels. Anything else fails
    closed: the row carries no usable evidence.
    """
    try:
        if not isinstance(entry, dict):
            return False
        assert set(entry.keys()) == set(COVERAGE_SOURCE_REQUIRED), \
            "coverage source shape"
        assert entry["source_id"] in SOURCE_CAPABILITIES, \
            "unknown source"
        check_source_capability(entry)
        check_opaque_id(entry["profile_id"], "profile_id")
        assert entry["subject_id"] in FROZEN_SUBJECT, "subject"
        assert entry["platform_cell"] in FROZEN_CELL, "cell"
        assert entry["address_namespace"] in FROZEN_NAMESPACE, \
            "namespace"
        assert entry["phase"] in FROZEN_PHASE, "phase"
        assert entry["status"] in FROZEN_STATUS, "status"
        assert entry["reason"] in FROZEN_REASON, "reason"
        window = entry["window"]
        assert isinstance(window, dict), "window must be an object"
        assert set(window.keys()) == {"start_ns", "end_ns"}, \
            "window leaves"
        start = check_u64(window["start_ns"], "window.start_ns")
        end = check_u64(window["end_ns"], "window.end_ns")
        assert start <= end, "window start past end"
        check_quality(entry["quality"], "source quality")
    except (AssertionError, KeyError, TypeError):
        return False
    return True


def source_evidence_state(entry):
    """Complete, incomplete, or absent for one required source entry.

    An available source carries usable evidence only when the row
    validates fully and its quality block validates with a usable
    channel; without either the availability claim stays
    unconfirmed. A partial source carries usable evidence only
    when the row validates and at least one quality channel stays
    usable; a partial source with no usable channel is incomplete
    evidence, never satisfaction. Anything else (a missing entry,
    an unavailable, disabled, not-applicable or unknown status) is
    absent, and stays inconclusive.
    """
    if entry is None:
        return "absent"
    status = entry.get("status")
    usable = source_row_valid(entry) \
        and source_quality_usable(entry.get("quality"))
    if status == "available":
        return "complete" if usable else "absent"
    if status != "partial":
        return "absent"
    return "complete" if usable else "incomplete"


def combined_source_state(entries, source):
    """Worst-first evidence state across every row for one source.

    Every coverage row carrying the source id classifies on its
    own; the rows combine worst-first, so a denied or incomplete
    row dominates usable ones and satisfaction needs every row
    usable, identically in every row order. A source with no row
    is absent. Mirrors the Rust evidence combination exactly: no
    first-match or last-match divergence.
    """
    states = [source_evidence_state(entry) for entry in entries
              if isinstance(entry, dict)
              and entry.get("source_id") == source]
    if not states:
        return "absent"
    if "absent" in states:
        return "absent"
    if "incomplete" in states:
        return "incomplete"
    return "complete"


def rule_satisfied(snapshot, required_sources):
    """A rule is satisfied only by sealed, settled, covering evidence.

    Every required source needs complete evidence, and usable
    metadata alone never satisfies: every required source needs at
    least one sealed fact whose ``source_id`` equals it.
    """
    if not required_sources:
        return False
    if not seal_verified(snapshot):
        return False
    session = snapshot["session"]
    terminal = session["quality"]["terminal"]
    if terminal["status"] != "complete_for_scope":
        return False
    sources = session["exposure"]["sources"]
    for source in required_sources:
        if combined_source_state(sources, source) != "complete":
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


def evidence_incomplete(snapshot, required_sources):
    """True when sealed, settled evidence leaves a source incomplete.

    Every required source is present, and at least one carries
    incomplete evidence: partial status with no usable quality
    channel. Unsealed, unsettled, or absent-source snapshots never
    qualify; they keep their weaker verdict.
    """
    if not required_sources:
        return False
    if not seal_verified(snapshot):
        return False
    sources = snapshot["session"]["exposure"]["sources"]
    states = [combined_source_state(sources, source)
              for source in required_sources]
    return "absent" not in states and "incomplete" in states


def snapshot_verdict(snapshot, required_sources):
    """Satisfied, partial, incomplete, or inconclusive; never vacuous."""
    if rule_satisfied(snapshot, required_sources):
        return "satisfied"
    session = snapshot["session"]
    if session["quality"]["terminal"]["status"] != "complete_for_scope":
        return "partial"
    if evidence_incomplete(snapshot, required_sources):
        return "incomplete"
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


def snapshot_from_reader(name):
    """A snapshot dict converted from a reader fixture directory."""
    directory = os.path.join(REPO, "tests", "fixtures", "reader", name)
    with open(os.path.join(directory, "session.json"),
              encoding="utf-8") as handle:
        session = json.load(handle, object_pairs_hook=_unique_object)
    with open(os.path.join(directory, "events.ndjson"),
              encoding="utf-8") as handle:
        lines = handle.read().splitlines(keepends=True)
    return {"session": session, "event_lines": lines}


def resealed_snapshot_lines(snapshot, mutator, index):
    """A copy of the snapshot with one event line mutated, resealed.

    Unlike the sealed-control helpers, the snapshot and the line
    index are explicit, so legacy snapshots can be mutated too.
    The seal is recomputed; the kind census is the caller's.
    """
    out = json.loads(json.dumps(snapshot))
    lines = out["event_lines"]
    event = json.loads(lines[index])
    mutator(event)
    lines[index] = json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(lines).encode("utf-8")
    out["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    return out


# One schema-valid payload per legacy event kind, shared by the
# per-kind controls. Each control is validated against the event
# schema in-test, so a stale payload fails loudly, never silently.
VALID_LEGACY_PAYLOADS = {
    "bounce_attempt": {"device_id": "dev-1", "requested_bytes": "4096",
                       "forced": True, "operation_id": "op-9"},
    "map_result": {"operation_id": "op-1", "success": True,
                   "mapping_id": "m-1", "return_code": 0,
                   "mapped_bytes": "4096", "wire_generation": "3",
                   "wire_identity": "known"},
    "unmap": {"mapping_id": "m-1", "wire_generation": "3",
              "wire_identity": "known"},
    "copy": {"operation_id": "op-1", "mapping_id": "m-1",
             "direction": "original_to_bounce", "bytes": "512"},
    "sync_request": {"operation_id": "op-1", "mapping_id": "m-1",
                     "offset_known": True, "offset": "128",
                     "length": "512"},
    "transition_result": {"region_id": "r-1", "requested_state": "shared",
                          "success": True, "return_code": 0,
                          "offset": "0", "length": "4096"},
    "pool_sample": {"pool_id": "swiotlb", "used_bytes": "1024",
                    "capacity_bytes": "4096", "unit": "bytes"},
    "gap": {"channel": "detail", "lost_count": "3", "reason": "ring full",
            "window_start_ns": "100", "window_end_ns": "200"},
    "marker": {"text": "census sealed"},
    "counter_snapshot": {"counter_id": "swiotlb.bounce_attempts",
                         "epoch": "7", "scope": {"profile_id": "p-1"},
                         "value": "42", "unit": "count"},
}


def resealed_kind_event(kind, data, source_mutator=None):
    """The sealed snapshot with the marker line retargeted, resealed.

    The marker line becomes ``kind`` carrying ``data`` (and an
    optionally retouched source); the kind census follows, so only
    the shape gates can refuse.
    """
    def retarget(event):
        event.update(kind=kind, data=data)
        if source_mutator is not None:
            source_mutator(event["source"])

    snapshot = resealed_marker_event(retarget)
    if kind != "marker":
        snapshot["session"]["capture"]["integrity"]["kinds"].update(
            {kind: "1", "marker": "0"})
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
    assert non_fact_fields_valid(control, EXPOSURE_CONTRACT), \
        "valid marker must verify"
    control["kind"] = "frobnicate"
    assert not non_fact_fields_valid(control, EXPOSURE_CONTRACT), \
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


def test_legacy_snapshots_verify_under_legacy_rules():
    for name in ("sealed-complete", "sealed-partial", "sealed-empty"):
        snapshot = snapshot_from_reader(name)
        assert seal_verified(snapshot), \
            "legacy %s must verify under legacy rules" % name
    assert seal_verified(load("legacy_sealed.json")), \
        "persisted legacy snapshot must verify"


def test_unknown_session_contract_refuses():
    assert snapshot_contract(
        load("sealed_snapshot.json")["session"]) == "exposure"
    assert snapshot_contract(
        load("legacy_sealed.json")["session"]) == "legacy"
    forged = json.loads(json.dumps(load("sealed_snapshot.json")))
    forged["session"]["schema_version"] = "9.9.9"
    assert snapshot_contract(forged["session"]) is None
    assert not seal_verified(forged), \
        "unknown contract must fail the seal"
    assert snapshot_verdict(forged, ["sharing-census"]) == "inconclusive"
    missing = json.loads(json.dumps(load("sealed_snapshot.json")))
    del missing["session"]["schema_version"]
    assert snapshot_contract(missing["session"]) is None
    assert not seal_verified(missing), \
        "missing contract must fail the seal"


def test_legacy_per_kind_payloads_validated():
    schema = load_schema("event-v0.3.0.schema.json")
    for kind, data in sorted(VALID_LEGACY_PAYLOADS.items()):
        control = resealed_kind_event(kind, json.loads(json.dumps(data)))
        jsonschema.validate(json.loads(control["event_lines"][2]), schema)
        assert seal_verified(control), "valid %s must verify" % kind
        assert snapshot_verdict(control, ["sharing-census"]) == "satisfied"
        mutated = resealed_kind_event(kind, {"bogus": "x"})
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(json.loads(mutated["event_lines"][2]),
                                schema)
        assert not seal_verified(mutated), \
            "bogus %s must fail the seal" % kind
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


CONDITIONAL_PAYLOADS = {
"valid": [
    ("map_result", {"operation_id": "op-1", "success": True,
                    "mapping_id": None, "return_code": 0,
                    "mapped_bytes": "4096", "wire_generation": "3",
                    "wire_identity": "unassigned"}),
    ("map_result", {"operation_id": "op-1", "success": False,
                    "mapping_id": None, "return_code": -12,
                    "mapped_bytes": None, "wire_generation": "0",
                    "wire_identity": None}),
    ("map_result", {"operation_id": "op-1", "success": False,
                    "mapping_id": None, "return_code": None,
                    "mapped_bytes": None, "wire_generation": None,
                    "wire_identity": None}),
    ("unmap", {"mapping_id": None, "wire_generation": "3",
               "wire_identity": "miss"}),
    ("unmap", {"mapping_id": "m-1", "wire_generation": None,
               "wire_identity": None}),
    ("sync_request", {"operation_id": "op-1", "mapping_id": None,
                      "offset_known": False, "offset": None,
                      "length": "512"}),
    ("transition_result", {"region_id": "r-1",
                           "requested_state": "private",
                           "success": False, "return_code": None,
                           "offset": "0", "length": "4096",
                           "address_space": "iova",
                           "resolution": "unresolved",
                           "generation": 2}),
    ("pool_sample", {"pool_id": "swiotlb", "used_bytes": None,
                     "capacity_bytes": None, "unit": "unknown",
                     "reason": "denied"}),
    ("gap", {"channel": "terminal", "lost_count": None,
             "reason": "dropped", "window_start_ns": "100",
             "window_end_ns": "200"}),
    ("counter_snapshot", {"counter_id": "c", "epoch": "0",
                          "scope": {"device_id": "dev-1",
                                    "profile_id": "p-1"},
                          "value": "0", "unit": "u"}),
    ("copy", {"operation_id": "op-1", "mapping_id": "m-1",
              "direction": "bounce_to_original", "bytes": "512",
              "pool_private": True,
              "offset_past_allocation": True}),
],
"invalid": [
    ("map_result", {"operation_id": "op-1", "success": True,
                    "mapping_id": None, "return_code": 0,
                    "mapped_bytes": "4096", "wire_generation": "3",
                    "wire_identity": "known"}),
    ("map_result", {"operation_id": "op-1", "success": False,
                    "mapping_id": "m-1", "return_code": 0,
                    "mapped_bytes": None, "wire_generation": None,
                    "wire_identity": None}),
    ("map_result", {"operation_id": "op-1", "success": True,
                    "mapping_id": "m-1", "return_code": 0,
                    "mapped_bytes": "4096", "wire_generation": None,
                    "wire_identity": "known"}),
    ("unmap", {"mapping_id": None, "wire_generation": "3",
               "wire_identity": "known"}),
    ("unmap", {"mapping_id": "m-1", "wire_generation": "3",
               "wire_identity": None}),
    ("sync_request", {"operation_id": "op-1", "mapping_id": "m-1",
                      "offset_known": True, "offset": None,
                      "length": "512"}),
    ("sync_request", {"operation_id": "op-1", "mapping_id": "m-1",
                      "offset_known": False, "offset": "128",
                      "length": "512"}),
    ("transition_result", {"region_id": "r-1",
                           "requested_state": "shared",
                           "success": True, "return_code": 0,
                           "offset": "0", "length": "4096",
                           "generation": 0}),
    ("pool_sample", {"pool_id": "swiotlb", "used_bytes": "1",
                     "capacity_bytes": "2", "unit": "pages"}),
    ("gap", {"channel": "detail", "lost_count": "3", "reason": "",
             "window_start_ns": "100", "window_end_ns": "200"}),
    ("counter_snapshot", {"counter_id": "c", "epoch": "0",
                          "scope": {}, "value": "0", "unit": "u"}),
    ("copy", {"operation_id": "op-1", "mapping_id": "m-1",
              "direction": "sideways", "bytes": "512"}),
    ("copy", {"operation_id": "op-1", "mapping_id": "m-1",
              "direction": "original_to_bounce", "bytes": "512",
              "pool_private": False}),
]}


def test_legacy_conditional_payloads_validated():
    schema = load_schema("event-v0.3.0.schema.json")
    valid = CONDITIONAL_PAYLOADS["valid"]
    invalid = CONDITIONAL_PAYLOADS["invalid"]
    for kind, data in valid:
        control = resealed_kind_event(kind, data)
        jsonschema.validate(json.loads(control["event_lines"][2]), schema)
        assert seal_verified(control), \
            "valid %s %r must verify" % (kind, data)
    for kind, data in invalid:
        mutated = resealed_kind_event(kind, data)
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(json.loads(mutated["event_lines"][2]),
                                schema)
        assert not seal_verified(mutated), \
            "invalid %s %r must fail the seal" % (kind, data)
        assert snapshot_verdict(mutated, ["sharing-census"]) == \
            "inconclusive"


def test_legacy_copy_requires_observed_measurement():
    def derived(source):
        source["measurement"] = "derived"

    payload = json.loads(json.dumps(VALID_LEGACY_PAYLOADS["copy"]))
    mutated = resealed_kind_event("copy", payload, derived)
    schema = load_schema("event-v0.3.0.schema.json")
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(mutated["event_lines"][2]), schema)
    assert not seal_verified(mutated), \
        "derived copy must fail the seal"
    assert snapshot_verdict(mutated, ["sharing-census"]) == "inconclusive"
    control = resealed_kind_event(
        "copy", json.loads(json.dumps(VALID_LEGACY_PAYLOADS["copy"])))
    assert seal_verified(control), "observed copy must verify"


def test_legacy_copy_extras_follow_line_version():
    extras = json.loads(json.dumps(VALID_LEGACY_PAYLOADS["copy"]))
    extras.update(pool_private=True, offset_past_allocation=True)
    modern = resealed_kind_event("copy", dict(extras))
    assert seal_verified(modern), "0.3.0 copy extras must verify"
    tainted = json.loads(json.dumps(load("legacy_sealed.json")))
    lines = tainted["event_lines"]
    event = json.loads(lines[0])
    event.update(kind="copy", data=dict(extras))
    lines[0] = json.dumps(event, separators=(",", ":")) + "\n"
    tainted["session"]["capture"]["integrity"]["kinds"].update(
        copy="1", bounce_attempt="2")
    raw = "".join(lines).encode("utf-8")
    tainted["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(tainted["event_lines"][0]),
                            load_schema("event-v0.1.1.schema.json"))
    assert not seal_verified(tainted), \
        "0.1.1 copy extras must fail the seal"
    upgraded = json.loads(json.dumps(tainted))
    event = json.loads(upgraded["event_lines"][0])
    event["schema_version"] = "0.1.2"
    upgraded["event_lines"][0] = \
        json.dumps(event, separators=(",", ":")) + "\n"
    raw = "".join(upgraded["event_lines"]).encode("utf-8")
    upgraded["session"]["capture"]["integrity"].update(
        events_bytes=str(len(raw)),
        events_sha256=hashlib.sha256(raw).hexdigest())
    jsonschema.validate(json.loads(upgraded["event_lines"][0]),
                        load_schema("event-v0.1.2.schema.json"))
    assert seal_verified(upgraded), "0.1.2 copy extras must verify"


def test_source_string_bounds_enforced():
    schema = load_schema("event-v0.3.0.schema.json")
    for field, limit in (("hook", 256), ("backend", 64),
                         ("profile_id", 128)):
        for value, label in (("", "empty"),
                             ("x" * (limit + 1), "overlong")):
            def apply(event, field=field, value=value):
                event["source"][field] = value

            mutated = resealed_mutation(apply)
            with pytest.raises(jsonschema.ValidationError):
                jsonschema.validate(json.loads(mutated["event_lines"][0]),
                                    schema)
            assert not seal_verified(mutated), \
                "fact with %s %s must fail the seal" % (label, field)
            assert snapshot_verdict(mutated, ["sharing-census"]) == \
                "inconclusive"
            marked = resealed_marker_event(apply)
            assert not seal_verified(marked), \
                "marker with %s %s must fail the seal" % (label, field)
            assert snapshot_verdict(marked, ["sharing-census"]) == \
                "inconclusive"
        for value in ("x", "x" * limit):
            def apply(event, field=field, value=value):
                event["source"][field] = value

            assert seal_verified(resealed_mutation(apply)), \
                "fact with bounded %s must verify" % field
            assert seal_verified(resealed_marker_event(apply)), \
                "marker with bounded %s must verify" % field


def test_empty_seal_requires_session_id():
    snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
    snapshot["event_lines"] = []
    integrity = snapshot["session"]["capture"]["integrity"]
    integrity.update(events_bytes="0", line_count="0", first_seq=None,
                     last_seq=None, events_sha256=EMPTY_SHA256,
                     kinds=dict.fromkeys(integrity["kinds"], "0"))
    assert seal_verified(snapshot), "empty control must verify"
    del snapshot["session"]["session_id"]
    assert not seal_verified(snapshot), \
        "empty seal without a session id must fail"


def test_incomplete_required_evidence_yields_incomplete():
    persisted = load("incomplete_source.json")
    assert seal_verified(persisted), "incomplete evidence still seals"
    assert not rule_satisfied(persisted, ["sharing-census"]), \
        "incomplete evidence never satisfies"
    assert snapshot_verdict(persisted, ["sharing-census"]) == "incomplete"
    jsonschema.validate(persisted["session"],
                        load_schema("session-v0.3.0.schema.json"))
    event_schema = load_schema("event-v0.3.0.schema.json")
    for line in persisted["event_lines"]:
        jsonschema.validate(json.loads(line), event_schema)
    mutated = json.loads(json.dumps(load("sealed_snapshot.json")))
    source = mutated["session"]["exposure"]["sources"][0]
    source.update(status="partial", reason="access-denied")
    for channel in source["quality"].values():
        channel.update(status="unavailable", loss_count=None)
    assert seal_verified(mutated)
    assert snapshot_verdict(mutated, ["sharing-census"]) == "incomplete"
    usable = json.loads(json.dumps(load("sealed_snapshot.json")))
    usable["session"]["exposure"]["sources"][0].update(
        status="partial", reason="access-denied")
    assert snapshot_verdict(usable, ["sharing-census"]) == "satisfied", \
        "partial source with usable quality still satisfies"


def test_legacy_observer_context_validated():
    context = {"cpu": 3, "pid": 100, "tgid": 100, "comm": "memveil",
               "cgroup_id": "cgroup-1",
               "relation": "execution_context_only"}
    snapshot = resealed_snapshot_lines(
        load("legacy_sealed.json"),
        lambda event: event.update(
            observer_context=json.loads(json.dumps(context))), 0)
    jsonschema.validate(json.loads(snapshot["event_lines"][0]),
                        load_schema("event-v0.1.1.schema.json"))
    assert seal_verified(snapshot), "legacy context must verify"
    bad = resealed_snapshot_lines(
        load("legacy_sealed.json"),
        lambda event: event.update(
            observer_context={"relation": "owner"}), 0)
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(bad["event_lines"][0]),
                            load_schema("event-v0.1.1.schema.json"))
    assert not seal_verified(bad), \
        "bad legacy context must fail the seal"
    modern = resealed_marker_event(
        lambda event: event.update(
            observer_context=json.loads(json.dumps(context))))
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(json.loads(modern["event_lines"][2]),
                            load_schema("event-v0.3.0.schema.json"))
    assert not seal_verified(modern), \
        "0.3.0 line with observer context must fail the seal"


def test_persisted_shape_refusals_refused():
    schema = load_schema("event-v0.3.0.schema.json")
    for name in ("bad_gap_payload.json", "empty_hook.json"):
        persisted = load(name)
        assert not seal_verified(persisted), \
            "%s must fail the seal" % name
        assert snapshot_verdict(persisted, ["sharing-census"]) == \
            "inconclusive"
        with pytest.raises(jsonschema.ValidationError):
            for line in persisted["event_lines"]:
                jsonschema.validate(json.loads(line), schema)


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


def denied_source_entry(source):
    """A partial access-denied copy of a coverage source entry."""
    denied = json.loads(json.dumps(source))
    denied.update(status="partial", reason="access-denied")
    for channel in denied["quality"].values():
        channel.update(status="unavailable", loss_count=None)
    return denied


def test_available_source_requires_valid_quality():
    required = ["sharing-census"]
    assert snapshot_verdict(load("sealed_snapshot.json"),
                            required) == "satisfied"
    persisted = load("available_no_quality.json")
    assert seal_verified(persisted), \
        "the seal covers event lines, not session shape"
    assert not rule_satisfied(persisted, required), \
        "available evidence without quality never satisfies"
    assert snapshot_verdict(persisted, required) == "inconclusive"
    assert source_evidence_state(
        persisted["session"]["exposure"]["sources"][0]) == "absent"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(persisted["session"],
                            load_schema("session-v0.3.0.schema.json"))
    tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
    quality = tainted["session"]["exposure"]["sources"][0]["quality"]
    quality["made-up"] = {"status": "complete_for_scope",
                          "loss_count": "0"}
    assert not rule_satisfied(tainted, required), \
        "unknown quality channel never supplies usability"
    assert snapshot_verdict(tainted, required) == "inconclusive"
    assert source_evidence_state(
        tainted["session"]["exposure"]["sources"][0]) == "absent"
    tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
    tainted["session"]["exposure"]["sources"][0]["quality"]["detail"] = \
        {"status": "partial", "loss_count": "not-a-count"}
    assert set(tainted["session"]["exposure"]["sources"][0]["quality"]) \
        == set(QUALITY_CHANNELS), "bad loss keeps the channel keys"
    assert not rule_satisfied(tainted, required), \
        "invalid loss count never supplies usability"
    assert snapshot_verdict(tainted, required) == "inconclusive"


def test_partial_source_with_only_bogus_quality_is_incomplete():
    required = ["sharing-census"]
    persisted = load("partial_bogus_quality.json")
    assert seal_verified(persisted), "bogus quality still seals"
    assert not rule_satisfied(persisted, required), \
        "bogus quality never satisfies"
    assert snapshot_verdict(persisted, required) == "incomplete"
    assert source_evidence_state(
        persisted["session"]["exposure"]["sources"][0]) == "incomplete"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(persisted["session"],
                            load_schema("session-v0.3.0.schema.json"))
    tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
    denied = denied_source_entry(
        tainted["session"]["exposure"]["sources"][0])
    denied["quality"]["detail"] = {"status": "partial",
                                   "loss_count": "not-a-count"}
    assert set(denied["quality"]) == set(QUALITY_CHANNELS), \
        "bad loss keeps the channel keys"
    tainted["session"]["exposure"]["sources"][0] = denied
    assert seal_verified(tainted)
    assert snapshot_verdict(tainted, required) == "incomplete", \
        "invalid loss never supplies usability"
    mixed = json.loads(json.dumps(load("sealed_snapshot.json")))
    entry = mixed["session"]["exposure"]["sources"][0]
    entry.update(status="partial", reason="access-denied")
    entry["quality"]["made-up"] = {"status": "complete_for_scope",
                                   "loss_count": "0"}
    assert snapshot_verdict(mixed, required) == "incomplete", \
        "one unknown channel fails the whole quality block"
    mixed_loss = json.loads(json.dumps(load("sealed_snapshot.json")))
    entry = mixed_loss["session"]["exposure"]["sources"][0]
    entry.update(status="partial", reason="access-denied")
    entry["quality"]["aggregate"] = {"status": "partial",
                                     "loss_count": "not-a-count"}
    assert set(entry["quality"]) == set(QUALITY_CHANNELS), \
        "bad loss keeps the channel keys"
    assert snapshot_verdict(mixed_loss, required) == "incomplete", \
        "one invalid loss fails the whole quality block"
    usable = json.loads(json.dumps(load("sealed_snapshot.json")))
    usable["session"]["exposure"]["sources"][0].update(
        status="partial", reason="access-denied")
    assert snapshot_verdict(usable, required) == "satisfied", \
        "partial source with valid usable quality still satisfies"


def test_duplicate_coverage_sources_refused():
    required = ["sharing-census"]
    persisted = load("duplicate_sources.json")
    jsonschema.validate(persisted["session"],
                        load_schema("session-v0.3.0.schema.json"))
    assert not seal_verified(persisted), \
        "denied-first duplicate sources must fail the seal"
    assert snapshot_verdict(persisted, required) == "inconclusive"
    flipped = json.loads(json.dumps(load("sealed_snapshot.json")))
    sources = flipped["session"]["exposure"]["sources"]
    sources.append(denied_source_entry(sources[0]))
    assert not seal_verified(flipped), \
        "available-first duplicate sources must fail the seal"
    assert snapshot_verdict(flipped, required) == "inconclusive"
    twins = json.loads(json.dumps(load("sealed_snapshot.json")))
    sources = twins["session"]["exposure"]["sources"]
    sources.append(json.loads(json.dumps(sources[0])))
    assert not seal_verified(twins), \
        "identical duplicate sources must fail the seal"
    assert snapshot_verdict(twins, required) == "inconclusive"
    split_window = json.loads(json.dumps(load("sealed_snapshot.json")))
    sources = split_window["session"]["exposure"]["sources"]
    other = denied_source_entry(sources[0])
    other["window"] = {"start_ns": "4000000000", "end_ns": "5000000000"}
    sources.append(other)
    jsonschema.validate(split_window["session"],
                        load_schema("session-v0.3.0.schema.json"))
    assert seal_verified(split_window), \
        "same source over disjoint windows is not a duplicate"
    split_subject = json.loads(json.dumps(load("sealed_snapshot.json")))
    sources = split_subject["session"]["exposure"]["sources"]
    other = denied_source_entry(sources[0])
    other["subject_id"] = "guest-kernel-memory-management"
    sources.append(other)
    jsonschema.validate(split_subject["session"],
                        load_schema("session-v0.3.0.schema.json"))
    assert seal_verified(split_subject), \
        "same source over disjoint subjects is not a duplicate"


def test_legacy_return_codes_bounded_to_i64():
    required = ["sharing-census"]
    persisted = load("overflow_return_code.json")
    jsonschema.validate(json.loads(persisted["event_lines"][2]),
                        load_schema("event-v0.3.0.schema.json"))
    assert not seal_verified(persisted), \
        "map return_code past i64 must fail the seal"
    assert snapshot_verdict(persisted, required) == "inconclusive"
    kinds = {
        "map_result": {"operation_id": "op-1", "success": False,
                       "mapping_id": None, "mapped_bytes": None,
                       "wire_generation": None, "wire_identity": None},
        "transition_result": {"region_id": "r-1",
                              "requested_state": "shared",
                              "success": False, "offset": "0",
                              "length": "4096"},
    }
    for kind, base in kinds.items():
        for value in (2**63, -(2**63) - 1):
            data = dict(base, return_code=value)
            mutated = resealed_kind_event(kind, data)
            assert not seal_verified(mutated), \
                "%s return_code %r must fail the seal" % (kind, value)
            assert snapshot_verdict(mutated, required) == "inconclusive"
        for value in (2**63 - 1, -(2**63)):
            data = dict(base, return_code=value)
            control = resealed_kind_event(kind, data)
            assert seal_verified(control), \
                "%s return_code %r must verify" % (kind, value)
            assert snapshot_verdict(control, required) == "satisfied"


def test_multi_row_sources_combine_worst_first():
    required = ["sharing-census"]
    for axis in ("window", "subject", "phase"):
        for label, denied_first in (("available-first", False),
                                    ("denied-first", True)):
            snapshot = json.loads(json.dumps(load("sealed_snapshot.json")))
            rows = snapshot["session"]["exposure"]["sources"]
            available = rows[0]
            denied = denied_source_entry(available)
            if axis == "window":
                available["window"]["end_ns"] = "2000000000"
                denied["window"]["start_ns"] = "2000000000"
            elif axis == "subject":
                denied["subject_id"] = "guest-kernel-memory-management"
            else:
                denied["phase"] = "observed"
            rows[:] = [denied, available] if denied_first \
                else [available, denied]
            jsonschema.validate(
                snapshot["session"],
                load_schema("session-v0.3.0.schema.json"))
            assert seal_verified(snapshot), \
                "%s %s distinct rows must verify" % (axis, label)
            assert snapshot_verdict(snapshot, required) == "incomplete", \
                "%s %s: the denied row dominates" % (axis, label)
    usable = load("multi_usable_sources.json")
    jsonschema.validate(usable["session"],
                        load_schema("session-v0.3.0.schema.json"))
    assert seal_verified(usable), "disjoint usable rows verify"
    assert snapshot_verdict(usable, required) == "satisfied", \
        "every row usable still satisfies"
    mixed = load("mixed_sources.json")
    jsonschema.validate(mixed["session"],
                        load_schema("session-v0.3.0.schema.json"))
    assert seal_verified(mixed), "disjoint mixed rows verify"
    assert snapshot_verdict(mixed, required) == "incomplete"
    absent_mix = json.loads(json.dumps(load("sealed_snapshot.json")))
    rows = absent_mix["session"]["exposure"]["sources"]
    other = denied_source_entry(rows[0])
    other.update(status="unavailable", reason="no-safe-source")
    other["window"] = {"start_ns": "4000000000",
                       "end_ns": "5000000000"}
    rows.append(other)
    assert seal_verified(absent_mix)
    assert snapshot_verdict(absent_mix, required) == "inconclusive"
    rows.reverse()
    assert seal_verified(absent_mix)
    assert snapshot_verdict(absent_mix, required) == "inconclusive", \
        "an unavailable row dominates in either order"


def test_invalid_source_metadata_cannot_satisfy():
    required = ["sharing-census"]
    for case in ("missing-key", "reversed-window", "wrong-capability"):
        tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
        source = tainted["session"]["exposure"]["sources"][0]
        if case == "missing-key":
            del source["subject_id"]
        elif case == "reversed-window":
            source["window"] = {"start_ns": "2000000000",
                                "end_ns": "1000000000"}
        else:
            source["capability"] = "host-interfaces"
        assert seal_verified(tainted), \
            "%s keeps the byte seal" % case
        assert not rule_satisfied(tainted, required), \
            "%s never satisfies" % case
        assert snapshot_verdict(tainted, required) == "inconclusive"
        assert source_evidence_state(source) == "absent"
    tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
    denied = denied_source_entry(
        tainted["session"]["exposure"]["sources"][0])
    denied["window"] = {"start_ns": "2000000000",
                        "end_ns": "1000000000"}
    tainted["session"]["exposure"]["sources"][0] = denied
    assert seal_verified(tainted)
    assert snapshot_verdict(tainted, required) == "incomplete", \
        "invalid metadata never supplies usability"


def test_unknown_coverage_fields_cannot_satisfy():
    required = ["sharing-census"]
    control = load("sealed_snapshot.json")
    assert source_row_valid(
        control["session"]["exposure"]["sources"][0]), \
        "positive control row stays valid"
    assert snapshot_verdict(control, required) == "satisfied"
    for case in ("extra-row-field", "extra-window-field"):
        tainted = json.loads(json.dumps(load("sealed_snapshot.json")))
        source = tainted["session"]["exposure"]["sources"][0]
        if case == "extra-row-field":
            source["unexpected"] = "synthetic"
        else:
            source["window"]["unexpected"] = "synthetic"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(tainted["session"],
                                load_schema("session-v0.3.0.schema.json"))
        assert not source_row_valid(source), \
            "%s row must refuse the unknown key" % case
        assert seal_verified(tainted), \
            "%s keeps the byte seal" % case
        assert not rule_satisfied(tainted, required), \
            "%s never satisfies" % case
        assert snapshot_verdict(tainted, required) == "inconclusive"
        assert source_evidence_state(source) == "absent"
    for name in ("coverage_extra_field.json",
                 "coverage_extra_window_field.json"):
        persisted = load(name)
        assert seal_verified(persisted), \
            "%s keeps the byte seal" % name
        assert not source_row_valid(
            persisted["session"]["exposure"]["sources"][0]), \
            "%s persisted row must refuse" % name
        assert not rule_satisfied(persisted, required), \
            "%s never satisfies" % name
        assert snapshot_verdict(persisted, required) == "inconclusive"
        assert source_evidence_state(
            persisted["session"]["exposure"]["sources"][0]) == "absent"
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(persisted["session"],
                                load_schema("session-v0.3.0.schema.json"))


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
