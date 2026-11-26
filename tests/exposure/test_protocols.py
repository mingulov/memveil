#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Interface-exchange shape fixtures: strict loader and family pins.

Offline shape checks over the authored interface fixtures in
``fixtures/protocols/``. Every helper here is pure standard
library code over persisted bytes: the envelope keeps exactly
its pinned keys, every fact, object, and coverage row keeps
the frozen catalog shapes, the paired benign and shaped
records keep identical counts, and no fixture labels an
outcome as an exploit success. Nothing here attaches to a
kernel, probes an interface, or replays a guest; collection
and live legs stay unattempted.

Run directly: `python3 -m pytest tests/exposure/test_protocols.py -q`.
"""

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "protocols")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")

FORMAT = "exposure-shape-fixture/0.1.0"

LANE_SOURCES = ("ghcb-exceptions",)
LANE_CAPABILITY = "host-interfaces"
LANE_CELL = "sev-snp"
LANE_PEER = "host-hypervisor"
LANE_NAMESPACE = "interface_register"
LANE_SUBJECT = "guest-kernel-cc-platform"

# Closed kind spellings for this lane; anything else refuses.
LANE_KINDS = ("interface-use",)

# Pinned family manifest: exactly these files, no more, no fewer.
MANIFEST = (
    "normal-exchange.json",
    "native-rejection.json",
    "unsupported-source.json",
    "parity-benign.json",
    "parity-adversarial.json",
    "negative-shape.json",
    "negative-label.json",
)

ACCEPT = (
    "normal-exchange.json",
    "native-rejection.json",
    "unsupported-source.json",
    "parity-benign.json",
    "parity-adversarial.json",
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
            lineages.add((obj["object_token"], obj["generation"]))
    for pos, fact in enumerate(facts):
        if not isinstance(fact, dict):
            continue
        token = fact.get("object_token")
        if token is not None and (token, fact.get("generation")) \
                not in lineages:
            out.append("%s fact %d: token lineage without an object"
                       % (name, pos))
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


def test_negative_shape_flags_peer_and_generation():
    _, doc = load_raw("negative-shape.json")
    joined = "\n".join(validate(doc, "negative-shape.json"))
    assert joined, "negative control must fail validation"
    assert "peer_class" in joined
    assert "generation" in joined
    assert doc["expect"] == "reject"


def test_negative_label_trips_verdict_scan_only():
    text, doc = load_raw("negative-label.json")
    assert validate(doc, "negative-label.json") == []
    assert FORBIDDEN_RE.findall(text), \
        "label control must trip the verdict scan"
    assert doc["expect"] == "reject"


def test_no_forbidden_labels_in_accept_fixtures():
    for name in ACCEPT:
        text, _ = load_raw(name)
        assert FORBIDDEN_RE.findall(text) == [], name


def test_normal_exchange_pins():
    _, doc = load_raw("normal-exchange.json")
    facts = doc["facts"]
    assert len(facts) == 4
    assert [fact["semantics"] for fact in facts] == [
        "request", "result", "request", "result"]
    assert [fact["native_result"] for fact in facts] == [0, 0, 0, 0]
    assert [fact["kind"] for fact in facts] == ["interface-use"] * 4
    assert "conver" not in json.dumps(facts)
    assert [obj["object_token"] for obj in doc["objects"]] == [
        "obj-ifc-port-1"]
    assert doc["coverage"] == []


def test_native_rejection_pins():
    _, doc = load_raw("native-rejection.json")
    facts = doc["facts"]
    assert len(facts) == 3
    assert [fact["semantics"] for fact in facts] == [
        "native_rejection"] * 3
    assert [fact["native_result"] for fact in facts] == [-22, -95, None]
    assert facts[2]["native_result_reason"] == "reason-unobserved"


def test_unsupported_source_pins():
    _, doc = load_raw("unsupported-source.json")
    rows = doc["coverage"]
    assert [(row["status"], row["reason"]) for row in rows] == [
        ("unavailable", "no-safe-source"),
        ("unavailable", "adapter-unimplemented")]
    assert [row["subject_id"] for row in rows] == [
        "guest-kernel-cc-platform", "capture-evidence"]
    assert doc["facts"] == []
    assert doc["objects"] == []


def semantics_counts(facts):
    """Hand-tallied per-semantics counts as canonical u64 strings."""
    tally = {}
    for fact in facts:
        key = fact["semantics"]
        tally[key] = tally.get(key, 0) + 1
    return {key: str(tally[key]) for key in sorted(tally)}


def test_parity_keeps_identical_counts():
    _, benign = load_raw("parity-benign.json")
    _, shaped = load_raw("parity-adversarial.json")
    plain = benign["facts"]
    other = shaped["facts"]
    assert len(plain) == len(other) == 4
    assert [fact["semantics"] for fact in plain] == [
        fact["semantics"] for fact in other] == [
            "request", "result", "request", "result"]
    assert [sorted(fact.keys()) for fact in plain] == [
        sorted(fact.keys()) for fact in other]
    assert sorted(fact["native_result"] for fact in plain) == sorted(
        fact["native_result"] for fact in other) == [0, 0, 0, 0]
    assert semantics_counts(plain) == semantics_counts(other) == {
        "request": "2", "result": "2"}
    assert benign["family"] == "parity-benign"
    assert shaped["family"] == "parity-adversarial"


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
    row = sources["ghcb-exceptions"]
    assert row["capability"] == LANE_CAPABILITY
    assert row["subject_class"] == LANE_SUBJECT
    assert row["peer_class"] == LANE_PEER
    assert row["address_namespace"] == LANE_NAMESPACE
    cells = {row["cell"]: row for row in catalog["platforms"]}
    assert LANE_CAPABILITY in cells[LANE_CELL]["for_capabilities"]
