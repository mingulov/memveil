#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Channel-lifecycle shape fixtures: strict loader and family pins.

Offline shape checks over the authored channel fixtures in
``fixtures/vmbus/``. Every helper here is pure standard
library code over persisted bytes: the envelope keeps exactly
its pinned keys, every fact, object, and coverage row keeps
the frozen catalog shapes, offers precede attaches, token
generations never alias, host-facing and paravisor paths
stay distinct, and no fixture labels an outcome as an
exploit success. Nothing here attaches to a kernel, opens a
channel, or replays a guest; collection and live legs stay
unattempted.

Run directly: `python3 -m pytest tests/exposure/test_vmbus.py -q`.
"""

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "vmbus")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")

FORMAT = "exposure-shape-fixture/0.1.0"

LANE_SOURCES = ("vmbus-channels",)
LANE_CAPABILITY = "host-interfaces"
LANE_CELL = "hyper-v"
LANE_PEER = "host-or-paravisor"
LANE_NAMESPACE = "channel_relid"
LANE_SUBJECT = "guest-kernel-vmbus"

# Closed kind spellings for this lane; anything else refuses.
LANE_KINDS = (
    "channel-offer", "channel-attach", "channel-observe",
    "channel-teardown", "channel-reoffer", "gpadl-establish",
    "gpadl-transfer", "gpadl-ack", "gpadl-teardown",
    "buffer-retain", "buffer-observe", "ring-observe",
    "conversion-request", "conversion-result",
    "reversion-request", "reversion-result",
)

# Pinned family manifest: exactly these files, no more, no fewer.
MANIFEST = (
    "offer-before-attach.json",
    "missing-offer.json",
    "gpadl-lifecycle.json",
    "channel-reuse.json",
    "netvsc-persistent-buffer.json",
    "confidential-ring.json",
    "conversion-tuples.json",
    "partial-failure-stages.json",
    "wrong-peer-topology.json",
    "ordinary-noop.json",
)

ACCEPT = (
    "offer-before-attach.json",
    "gpadl-lifecycle.json",
    "channel-reuse.json",
    "netvsc-persistent-buffer.json",
    "confidential-ring.json",
    "conversion-tuples.json",
    "partial-failure-stages.json",
    "ordinary-noop.json",
)

# Frozen catalog vocabularies, cross-checked against the catalog file.
FROZEN_SEMANTICS = ("request", "result", "inventory", "lifecycle",
                    "state", "native_rejection")
FROZEN_PHASE = ("boot", "pre_attach", "observed")
FROZEN_STATUS = ("available", "partial", "unavailable",
                 "not_applicable", "disabled")
FROZEN_REASON = ("adapter-unimplemented", "no-safe-source",
                 "lease-pending", "access-denied", "hook-absent",
                 "cell-unselected", "quarantined",
                 "not-applicable-platform")
FROZEN_CLOCK = ("guest_monotonic_active", "guest_boottime_elapsed",
                "external_trusted_interval")
FROZEN_PEER = ("none-observed", "host-device", "device-or-subsystem",
               "device", "host-hypervisor", "host-tdx-module",
               "host-or-paravisor")
FROZEN_SUBJECT = ("guest-kernel-memory-management", "guest-direct-map",
                  "guest-kernel-allocator", "guest-driver-virtio",
                  "guest-driver-dma", "guest-kernel-cc-platform",
                  "guest-kernel-vmbus", "guest-configuration",
                  "capture-evidence")
FROZEN_NAMESPACE = ("guest_virtual", "guest_physical", "session_token",
                    "interface_register", "channel_relid",
                    "not_applicable")
FROZEN_OBJECT_CLASS = ("queue", "buffer", "channel", "mapping",
                       "heap_object")
FROZEN_LIFECYCLE = ("created", "live", "released", "quarantined",
                    "unknown")
FROZEN_QUALITY_STATUS = ("complete_for_scope", "partial", "unavailable")
QUALITY_CHANNELS = ("detail", "aggregate", "identity", "baseline",
                    "terminal")

# Verdict discipline: no fixture may label an outcome as an
# exploit success or an attack. Matched case-insensitively on
# word starts so frozen labels such as `native_rejection`
# stay usable.
FORBIDDEN = (
    "exploit", "attack", "success", "succeed", "compromis",
    "malicious", "vulnerab", "verdict", "escape", "payload",
)
FORBIDDEN_RE = re.compile(
    r"\b(?:" + "|".join(FORBIDDEN) + r")\w*", re.IGNORECASE)

U64MAX = 18446744073709551615
U64RE = re.compile(r"(0|[1-9][0-9]{0,19})")
OPAQUE_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
I64MIN = -(2 ** 63)
I64MAX = 2 ** 63 - 1

ENVELOPE_REQUIRED = ("format", "provenance", "family", "source_id",
                     "capability", "platform_cell", "expect")
ENVELOPE_SECTIONS = ("facts", "objects", "coverage")

FACT_REQUIRED = ("evidence_id", "source_id", "epoch", "operation_id",
                 "kind", "direction", "generation", "offset",
                 "length_bytes", "native_result", "caller_class",
                 "peer_class", "clock_domain", "observed_interval",
                 "semantics", "quality")
FACT_OPTIONAL = ("parent_operation_id", "parent_operation_id_reason",
                 "object_token", "object_token_reason",
                 "native_result_reason")

OBJECT_REQUIRED = ("object_token", "generation", "object_class",
                   "namespace", "origin_source", "lifecycle_status",
                   "state", "state_evidence", "uncertainty")
OBJECT_OPTIONAL = ("expected_boundary",)

COVERAGE_REQUIRED = ("source_id", "capability", "profile_id",
                     "subject_id", "platform_cell",
                     "address_namespace", "phase", "status",
                     "reason", "window", "quality")


class DuplicateKeyError(ValueError):
    """One JSON object repeats a key; the loader refuses these."""


def _unique_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise DuplicateKeyError("duplicate key %r" % key)
        obj[key] = value
    return obj


def load_raw(name):
    """The raw text and strictly parsed document for one fixture."""
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        text = handle.read()
    return text, json.loads(text, object_pairs_hook=_unique_object)


def is_u64(value):
    """True for a canonical u64 decimal string within range."""
    return isinstance(value, str) \
        and U64RE.fullmatch(value) is not None \
        and int(value) <= U64MAX


def is_opaque(value):
    """True for a bounded opaque identifier."""
    return isinstance(value, str) \
        and OPAQUE_RE.fullmatch(value) is not None


def is_i64(value):
    """True for a bare JSON integer within i64 range, never a bool."""
    return isinstance(value, int) and not isinstance(value, bool) \
        and I64MIN <= value <= I64MAX


def check_quality(out, quality, where):
    """Five exposure channels, each with a status and loss count."""
    if not isinstance(quality, dict):
        out.append("%s: quality must be an object" % where)
        return
    if set(quality.keys()) != set(QUALITY_CHANNELS):
        out.append("%s: quality channels %r"
                   % (where, sorted(quality.keys())))
        return
    for channel in QUALITY_CHANNELS:
        node = quality[channel]
        here = "%s quality %s" % (where, channel)
        if not isinstance(node, dict) \
                or set(node.keys()) != {"status", "loss_count"}:
            out.append("%s: leaves" % here)
            continue
        if node["status"] not in FROZEN_QUALITY_STATUS:
            out.append("%s: status %r" % (here, node["status"]))
        loss = node["loss_count"]
        if loss is not None and not is_u64(loss):
            out.append("%s: loss_count not canonical u64" % here)


def check_nullable(out, fact, base, where, is_value):
    """Absent carries no reason; null needs one; a value needs none."""
    reason = base + "_reason"
    valued = base in fact
    reasoned = reason in fact
    if not valued:
        if reasoned:
            out.append("%s: %s strays without %s"
                       % (where, reason, base))
        return
    value = fact[base]
    if value is None:
        if not reasoned:
            out.append("%s: null %s needs %s" % (where, base, reason))
        elif not is_opaque(fact[reason]):
            out.append("%s: %s not opaque" % (where, reason))
    else:
        if not is_value(value):
            out.append("%s: %s mistyped" % (where, base))
        if reasoned:
            out.append("%s: %s strays beside a value"
                       % (where, reason))


def check_fact(out, fact, source_id, where):
    """One exposure fact keeps the frozen record shape."""
    if not isinstance(fact, dict):
        out.append("%s: fact must be an object" % where)
        return
    allowed = set(FACT_REQUIRED) | set(FACT_OPTIONAL)
    if set(fact.keys()) - allowed:
        out.append("%s: unknown fact keys %r"
                   % (where, sorted(set(fact.keys()) - allowed)))
        return
    missing = [field for field in FACT_REQUIRED if field not in fact]
    if missing:
        out.append("%s: missing fact fields %r" % (where, missing))
        return
    for field in ("evidence_id", "operation_id", "direction",
                  "caller_class"):
        if not is_opaque(fact[field]):
            out.append("%s: %s not opaque" % (where, field))
    if fact["kind"] not in LANE_KINDS:
        out.append("%s: kind %r outside the lane spellings"
                   % (where, fact["kind"]))
    if fact["source_id"] != source_id:
        out.append("%s: source_id %r leaves the envelope source"
                   % (where, fact["source_id"]))
    for field in ("epoch", "generation", "offset", "length_bytes"):
        if not is_u64(fact[field]):
            out.append("%s: %s not canonical u64" % (where, field))
    if fact["peer_class"] != LANE_PEER:
        out.append("%s: peer_class %r is not the lane peer"
                   % (where, fact["peer_class"]))
    if fact["clock_domain"] not in FROZEN_CLOCK:
        out.append("%s: clock_domain %r" % (where, fact["clock_domain"]))
    interval = fact["observed_interval"]
    if not isinstance(interval, dict) \
            or set(interval.keys()) != {"start", "end", "uncertainty"}:
        out.append("%s: observed_interval leaves" % where)
    else:
        leaves = [interval[key] for key in ("start", "end",
                                           "uncertainty")]
        if not all(is_u64(leaf) for leaf in leaves):
            out.append("%s: interval not canonical u64" % where)
        elif int(interval["start"]) > int(interval["end"]):
            out.append("%s: interval start past end" % where)
    if fact["semantics"] not in FROZEN_SEMANTICS:
        out.append("%s: semantics %r" % (where, fact["semantics"]))
    check_quality(out, fact["quality"], where)
    check_nullable(out, fact, "parent_operation_id", where, is_opaque)
    check_nullable(out, fact, "object_token", where, is_opaque)
    native = fact["native_result"]
    if native is None:
        if "native_result_reason" not in fact:
            out.append("%s: null native_result needs a reason" % where)
        elif not is_opaque(fact["native_result_reason"]):
            out.append("%s: native_result_reason not opaque" % where)
    else:
        if not is_i64(native):
            out.append("%s: native_result mistyped" % where)
        if "native_result_reason" in fact:
            out.append("%s: native_result_reason strays" % where)


def check_object(out, obj, evidence, where):
    """One exposure object keeps the frozen lineage shape."""
    if not isinstance(obj, dict):
        out.append("%s: object must be an object" % where)
        return
    allowed = set(OBJECT_REQUIRED) | set(OBJECT_OPTIONAL)
    if set(obj.keys()) - allowed:
        out.append("%s: unknown object keys %r"
                   % (where, sorted(set(obj.keys()) - allowed)))
        return
    missing = [field for field in OBJECT_REQUIRED if field not in obj]
    if missing:
        out.append("%s: missing object fields %r" % (where, missing))
        return
    if not is_opaque(obj["object_token"]):
        out.append("%s: object_token not opaque" % where)
    if not is_u64(obj["generation"]):
        out.append("%s: generation not canonical u64" % where)
    if obj["object_class"] not in FROZEN_OBJECT_CLASS:
        out.append("%s: object_class %r" % (where, obj["object_class"]))
    if obj["namespace"] != LANE_NAMESPACE:
        out.append("%s: namespace %r leaves the lane" % (where,
                                                         obj["namespace"]))
    if obj["origin_source"] not in LANE_SOURCES:
        out.append("%s: origin_source %r" % (where, obj["origin_source"]))
    if obj["lifecycle_status"] not in FROZEN_LIFECYCLE:
        out.append("%s: lifecycle_status %r"
                   % (where, obj["lifecycle_status"]))
    if not is_opaque(obj["state"]):
        out.append("%s: state not opaque" % where)
    cited = obj["state_evidence"]
    if not isinstance(cited, list) \
            or not all(isinstance(entry, str) for entry in cited):
        out.append("%s: state_evidence must be a string array" % where)
    else:
        for entry in cited:
            if entry not in evidence:
                out.append("%s: state_evidence cites unknown %r"
                           % (where, entry))
    gap = obj["uncertainty"]
    if not isinstance(gap, dict) \
            or set(gap.keys()) != {"alias", "reuse", "loss",
                                   "missed_events"} \
            or not all(isinstance(gap[key], bool)
                       for key in ("alias", "reuse", "loss",
                                   "missed_events")):
        out.append("%s: uncertainty leaves" % where)
    if "expected_boundary" in obj:
        bound = obj["expected_boundary"]
        if not isinstance(bound, dict) \
                or set(bound.keys()) != {"boundary", "reference"} \
                or not all(isinstance(bound[key], str)
                           for key in ("boundary", "reference")):
            out.append("%s: expected_boundary leaves" % where)


def check_coverage(out, entry, cell, where):
    """One coverage row keeps the frozen source-record shape."""
    if not isinstance(entry, dict):
        out.append("%s: coverage must be an object" % where)
        return
    if set(entry.keys()) != set(COVERAGE_REQUIRED):
        out.append("%s: coverage keys %r"
                   % (where, sorted(entry.keys())))
        return
    if entry["source_id"] not in LANE_SOURCES:
        out.append("%s: source_id %r" % (where, entry["source_id"]))
    if entry["capability"] != LANE_CAPABILITY:
        out.append("%s: capability %r" % (where, entry["capability"]))
    if not is_opaque(entry["profile_id"]):
        out.append("%s: profile_id not opaque" % where)
    if entry["subject_id"] not in FROZEN_SUBJECT:
        out.append("%s: subject_id %r" % (where, entry["subject_id"]))
    if entry["platform_cell"] != cell:
        out.append("%s: platform_cell %r leaves the envelope cell"
                   % (where, entry["platform_cell"]))
    if entry["address_namespace"] != LANE_NAMESPACE:
        out.append("%s: address_namespace %r"
                   % (where, entry["address_namespace"]))
    if entry["phase"] not in FROZEN_PHASE:
        out.append("%s: phase %r" % (where, entry["phase"]))
    if entry["status"] not in FROZEN_STATUS:
        out.append("%s: status %r" % (where, entry["status"]))
    if entry["reason"] not in FROZEN_REASON:
        out.append("%s: reason %r" % (where, entry["reason"]))
    window = entry["window"]
    if not isinstance(window, dict) \
            or set(window.keys()) != {"start_ns", "end_ns"}:
        out.append("%s: window leaves" % where)
    else:
        start = window["start_ns"]
        end = window["end_ns"]
        if not is_u64(start) or not is_u64(end):
            out.append("%s: window not canonical u64" % where)
        elif int(start) > int(end):
            out.append("%s: window start past end" % where)
    check_quality(out, entry["quality"], where)


def interval_start(fact):
    """The interval start as an int, or None when ill-formed."""
    try:
        start = fact["observed_interval"]["start"]
    except (KeyError, TypeError):
        return None
    return int(start) if is_u64(start) else None


def check_offer_before_attach(out, facts, name):
    """Every attach rides on an earlier offer for the same token."""
    offers = {}
    for fact in facts:
        if not isinstance(fact, dict):
            continue
        if fact.get("kind") != "channel-offer":
            continue
        token = fact.get("object_token")
        start = interval_start(fact)
        if token is not None and start is not None:
            offers[token] = min(start, offers.get(token, start))
    for pos, fact in enumerate(facts):
        if not isinstance(fact, dict):
            continue
        if fact.get("kind") != "channel-attach":
            continue
        token = fact.get("object_token")
        start = interval_start(fact)
        offered = offers.get(token)
        if token is None or offered is None or start is None \
                or offered > start:
            out.append("%s fact %d: attach lineage without an offer"
                       % (name, pos))


def validate(doc, name):
    """Every violation in one fixture; empty means the shape holds."""
    out = []
    if not isinstance(doc, dict):
        return ["%s: fixture must be an object" % name]
    allowed = set(ENVELOPE_REQUIRED) | set(ENVELOPE_SECTIONS)
    if set(doc.keys()) - allowed:
        return ["%s: unknown envelope keys %r"
                % (name, sorted(set(doc.keys()) - allowed))]
    missing = [field for field in ENVELOPE_REQUIRED if field not in doc]
    if missing:
        return ["%s: missing envelope fields %r" % (name, missing)]
    if doc["format"] != FORMAT:
        out.append("%s: format %r" % (name, doc["format"]))
    for field in ("provenance", "family"):
        if not isinstance(doc[field], str) or not doc[field]:
            out.append("%s: %s must be a non-empty string"
                       % (name, field))
    if doc["family"] != name[:-len(".json")]:
        out.append("%s: family %r must match the file stem"
                   % (name, doc["family"]))
    if doc["source_id"] not in LANE_SOURCES:
        out.append("%s: source_id %r" % (name, doc["source_id"]))
    if doc["capability"] != LANE_CAPABILITY:
        out.append("%s: capability %r" % (name, doc["capability"]))
    if doc["platform_cell"] != LANE_CELL:
        out.append("%s: platform_cell %r" % (name, doc["platform_cell"]))
    if doc["expect"] not in ("accept", "reject"):
        out.append("%s: expect %r" % (name, doc["expect"]))
    sections = {}
    for section in ENVELOPE_SECTIONS:
        rows = doc.get(section, [])
        if not isinstance(rows, list):
            out.append("%s: %s must be an array" % (name, section))
            rows = []
        sections[section] = rows
    facts = sections["facts"]
    for pos, fact in enumerate(facts):
        check_fact(out, fact, doc["source_id"],
                   "%s fact %d" % (name, pos))
    seen = [fact["evidence_id"] for fact in facts
            if isinstance(fact, dict) and "evidence_id" in fact]
    if len(set(seen)) != len(seen):
        out.append("%s: duplicate evidence_id" % name)
    epochs = {fact["epoch"] for fact in facts
              if isinstance(fact, dict) and "epoch" in fact}
    if len(epochs) > 1:
        out.append("%s: facts span several epochs" % name)
    evidence = set(seen)
    lineages = set()
    for pos, obj in enumerate(sections["objects"]):
        check_object(out, obj, evidence, "%s object %d" % (name, pos))
        if isinstance(obj, dict) and "object_token" in obj \
                and "generation" in obj:
            key = (obj["object_token"], obj["generation"])
            if key in lineages:
                out.append("%s object %d: duplicate lineage %r"
                           % (name, pos, key))
            lineages.add(key)
    for pos, fact in enumerate(facts):
        if not isinstance(fact, dict):
            continue
        token = fact.get("object_token")
        if token is not None and (token, fact.get("generation")) \
                not in lineages:
            out.append("%s fact %d: token lineage without an object"
                       % (name, pos))
    check_offer_before_attach(out, facts, name)
    for pos, entry in enumerate(sections["coverage"]):
        check_coverage(out, entry, doc["platform_cell"],
                       "%s coverage %d" % (name, pos))
    return out


def test_manifest_pins_family_set():
    assert sorted(os.listdir(FIX)) == sorted(MANIFEST)


def test_accept_files_validate_clean():
    for name in ACCEPT:
        _, doc = load_raw(name)
        assert validate(doc, name) == [], name
        assert doc["expect"] == "accept", name


def test_missing_offer_flags_lineage():
    _, doc = load_raw("missing-offer.json")
    joined = "\n".join(validate(doc, "missing-offer.json"))
    assert joined, "missing-offer control must fail validation"
    assert "lineage" in joined
    assert doc["expect"] == "reject"


def test_wrong_peer_topology_flags_peer():
    _, doc = load_raw("wrong-peer-topology.json")
    joined = "\n".join(validate(doc, "wrong-peer-topology.json"))
    assert joined, "wrong-peer control must fail validation"
    assert "peer_class" in joined
    assert doc["expect"] == "reject"


def test_no_forbidden_labels_in_accept_fixtures():
    for name in ACCEPT:
        text, _ = load_raw(name)
        assert FORBIDDEN_RE.findall(text) == [], name


def test_offer_before_attach_pins():
    _, doc = load_raw("offer-before-attach.json")
    facts = doc["facts"]
    assert [fact["kind"] for fact in facts] == [
        "channel-offer", "channel-attach"]
    assert [fact["native_result"] for fact in facts] == [0, 0]
    assert [fact["object_token"] for fact in facts] == [
        "obj-chn-1", "obj-chn-1"]
    offered = facts[0]["observed_interval"]
    attached = facts[1]["observed_interval"]
    assert int(offered["start"]) <= int(attached["start"])
    assert [(obj["object_token"], obj["generation"],
             obj["lifecycle_status"]) for obj in doc["objects"]] == [
                 ("obj-chn-1", "1", "live")]


def test_gpadl_lifecycle_pins():
    _, doc = load_raw("gpadl-lifecycle.json")
    facts = doc["facts"]
    assert [(fact["kind"], fact["semantics"], fact["native_result"])
            for fact in facts] == [
                ("gpadl-establish", "result", 0),
                ("gpadl-transfer", "native_rejection", -5),
                ("gpadl-ack", "result", 0),
                ("gpadl-teardown", "result", 0)]
    assert [obj["object_token"] for obj in doc["objects"]] == [
        "obj-gpadl-1"]


def test_channel_reuse_pins():
    _, doc = load_raw("channel-reuse.json")
    assert [(obj["object_token"], obj["generation"],
             obj["lifecycle_status"]) for obj in doc["objects"]] == [
                 ("obj-chn-reuse-1", "1", "released"),
                 ("obj-chn-reuse-1", "2", "live")]
    facts = doc["facts"]
    assert [fact["kind"] for fact in facts] == [
        "channel-teardown", "channel-reoffer"]
    assert [fact["generation"] for fact in facts] == ["1", "2"]
    assert [fact["native_result"] for fact in facts] == [0, 0]


def test_netvsc_buffer_pins():
    _, doc = load_raw("netvsc-persistent-buffer.json")
    facts = doc["facts"]
    assert [fact["semantics"] for fact in facts] == [
        "lifecycle", "state"]
    assert [fact["native_result"] for fact in facts] == [0, 0]
    assert [obj["state"] for obj in doc["objects"]] == [
        "observed-retained"]


def test_confidential_ring_pins():
    _, doc = load_raw("confidential-ring.json")
    facts = doc["facts"]
    assert [fact["semantics"] for fact in facts] == ["state"]
    assert [fact["peer_class"] for fact in facts] == [
        "host-or-paravisor"]
    assert [(obj["object_class"], obj["state"])
            for obj in doc["objects"]] == [
                ("queue", "unresolved-pending-evidence")]


def test_conversion_tuples_pin():
    _, doc = load_raw("conversion-tuples.json")
    facts = doc["facts"]
    assert [(fact["operation_id"], fact["semantics"],
             fact["native_result"]) for fact in facts] == [
                 ("op-hv-conv-1", "request", 0),
                 ("op-hv-conv-1", "result", 0),
                 ("op-hv-conv-2", "request", 0),
                 ("op-hv-conv-2", "native_rejection", -22),
                 ("op-hv-rev-1", "request", 0),
                 ("op-hv-rev-1", "result", 0)]
    assert [fact["kind"] for fact in facts] == [
        "conversion-request", "conversion-result",
        "conversion-request", "conversion-result",
        "reversion-request", "reversion-result"]


def test_partial_failure_stages_pin():
    _, doc = load_raw("partial-failure-stages.json")
    rows = doc["coverage"]
    assert [(row["status"], row["reason"]) for row in rows] == [
        ("partial", "quarantined")]
    assert [fact["native_result"] for fact in doc["facts"]] == [-22, 0]


def test_ordinary_noop_pins():
    _, doc = load_raw("ordinary-noop.json")
    facts = doc["facts"]
    assert [(fact["kind"], fact["semantics"], fact["native_result"])
            for fact in facts] == [
                ("channel-observe", "request", 0),
                ("channel-observe", "result", 0)]
    assert doc["objects"] == []
    assert doc["coverage"] == []


def test_host_and_paravisor_paths_stay_distinct():
    _, host = load_raw("netvsc-persistent-buffer.json")
    _, ring = load_raw("confidential-ring.json")
    host_states = [obj["state"] for obj in host["objects"]]
    ring_states = [obj["state"] for obj in ring["objects"]]
    assert host_states == ["observed-retained"]
    assert ring_states == ["unresolved-pending-evidence"]
    assert host_states != ring_states
    for doc in (host, ring):
        assert {fact["semantics"]
                for fact in doc["facts"]} <= {"lifecycle", "state"}
        for fact in doc["facts"]:
            assert fact["peer_class"] == "host-or-paravisor"


def test_catalog_conformance():
    with open(CATALOG, encoding="utf-8") as handle:
        catalog = json.load(handle)
    frozen = catalog["vocabularies"]["frozen"]
    assert tuple(frozen["semantics"]) == FROZEN_SEMANTICS
    assert tuple(frozen["phase"]) == FROZEN_PHASE
    assert tuple(frozen["source_status"]) == FROZEN_STATUS
    assert tuple(frozen["peer_classes"]) == FROZEN_PEER
    assert tuple(frozen["subject_classes"]) == FROZEN_SUBJECT
    assert tuple(frozen["address_namespaces"]) == FROZEN_NAMESPACE
    assert tuple(frozen["object_classes"]) == FROZEN_OBJECT_CLASS
    assert tuple(frozen["lifecycle_statuses"]) == FROZEN_LIFECYCLE
    assert [row["code"]
            for row in catalog["source_reasons"]] == list(FROZEN_REASON)
    sources = {row["source_id"]: row for row in catalog["sources"]}
    row = sources["vmbus-channels"]
    assert row["capability"] == LANE_CAPABILITY
    assert row["subject_class"] == LANE_SUBJECT
    assert row["peer_class"] == LANE_PEER
    assert row["address_namespace"] == LANE_NAMESPACE
    cells = {row["cell"]: row for row in catalog["platforms"]}
    assert LANE_CAPABILITY in cells[LANE_CELL]["for_capabilities"]
