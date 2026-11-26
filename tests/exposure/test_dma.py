#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline DMA/virtio path fixtures: strict shape pinning.

Pure-offline loader/validator over
``fixtures/dma/*.json``. Every fixture is shaped by the
frozen exposure catalog field lists (ExposureFact,
ExposureObject, CoverageSource); this module pins required
keys, closed enums, the u64 decimal-string rule, and the
null-with-reason rule, then re-derives each fixture's
hand-computed ``expected`` block with an independent
predicate. Malformed fixtures must be rejected with the
mapped error code.

Covered families: persistent-queue steady I/O, nested
mixed scatter-gather, failure after internal allocation,
device reset/reuse, and pre-attach inventory.

Run directly: `python3 -m pytest tests/exposure/test_dma.py -q`.
"""

import json
import os
import re

FIX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "dma")
ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(
    ROOT, "profiles", "exposure", "catalog.json")

FORMAT = "exposure-dma-fixture/0.1.0"

# Family -> valid fixture files. Every card-named DMA
# family must stay covered by at least one fixture.
FAMILIES = {
    "persistent-queue-steady-io": [
        "persistent_queue_steady_io.json",
    ],
    "nested-mixed-sg": [
        "nested_mixed_sg.json",
    ],
    "failure-after-internal-allocation": [
        "failure_after_internal_allocation.json",
    ],
    "device-reset-reuse": [
        "device_reset_reuse.json",
    ],
    "pre-attach": [
        "pre_attach.json",
    ],
}

# Malformed fixture -> expected error-code substring. One
# negative per family; each defect rotates across the
# shape rules (missing key, bad enum, bare null, bad u64).
MALFORMED = {
    "malformed_persistent_queue_missing_key.json":
        "missing-required-key",
    "malformed_nested_sg_bad_enum.json":
        "closed-enum-violation",
    "malformed_failure_bare_null.json":
        "bare-null-without-reason",
    "malformed_reset_bad_u64.json":
        "bad-u64",
    "malformed_pre_attach_bad_label.json":
        "bad-label",
}

ENVELOPE_REQUIRED = (
    "format", "family", "scenario", "provenance",
    "namespace", "capability", "source_id", "coverage",
    "objects", "facts", "conversions_observed",
    "bytes_transferred", "expected",
)

FACT_REQUIRED = (
    "evidence_id", "source_id", "epoch", "operation_id",
    "kind", "direction", "generation", "offset",
    "length_bytes", "native_result", "caller_class",
    "peer_class", "clock_domain", "observed_interval",
    "semantics", "quality",
)

FACT_OPTIONAL_NULLABLE = (
    "parent_operation_id", "object_token",
)

OBJECT_REQUIRED = (
    "object_token", "generation", "object_class",
    "namespace", "origin_source", "lifecycle_status",
    "state", "state_evidence", "uncertainty",
)

COVERAGE_REQUIRED = (
    "source_id", "capability", "profile_id",
    "subject_id", "platform_cell",
    "address_namespace", "phase", "status", "reason",
    "window", "quality",
)

QUALITY_DIMS = (
    "detail", "aggregate", "identity",
    "baseline", "terminal",
)

# Lane-local closed sets for catalog-deferred labels.
# The catalog freezes kinds, directions, caller classes,
# object states, and null reasons from admitted sources;
# until then these lane-local sets pin the fixture
# vocabulary so no adapter can invent a label silently.
LANE_KINDS = (
    "queue-create", "queue-use", "queue-teardown",
    "segment-bounced", "segment-direct",
    "operation-outer", "allocation-internal",
    "reset-reuse", "pre-attach-inventory",
)
LANE_DIRECTIONS = (
    "to-device", "from-device", "bidirectional", "none",
)
LANE_CALLERS = (
    "virtio-driver", "dma-api", "block-layer",
    "net-layer", "unknown-caller",
)
LANE_STATES = (
    "steady", "nested", "failed", "reset",
    "pre-attach",
)
LANE_NULL_REASONS = (
    "unknown", "unobserved", "not-applicable",
    "withheld", "out-of-window",
)
LANE_SCOPES = (
    "persistent-queue-traffic",
    "bounced-and-direct-paths",
)

# Lane capability pinned by the envelope: a fact
# may only cite a catalog source carrying this
# capability. Another lane's source id exists in
# the catalog but backs no coverage here.
LANE_CAPABILITY = "dma-paths"

U64_MAX = 18446744073709551615
U64_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
S64_MIN = -(2 ** 63)
S64_MAX = 2 ** 63 - 1
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
HEXADDR_RE = re.compile(r"0x[0-9a-fA-F]{3,}")

# Strings that must never appear in a fixture: raw
# addresses, payload/key material, or verdict language.
FORBIDDEN = (
    "payload", "private", "secret", "password",
    "decrypt", "plaintext", "exploit", "verdict",
)

# Object keys that disclose buffer identity or raw
# addressing; never accepted anywhere in a fixture,
# whatever object carries them.
DISCLOSURE_FIELDS = (
    "buffer_name", "raw_pointer",
)


def disclosure_key(name):
    """Normalize a key before the disclosure match.

    Underscore, hyphen, case, and camelCase
    spellings of the same field disclose the same
    identity or addressing, so they match as one
    field.
    """
    split = re.sub(r"([a-z0-9])([A-Z])",
                   r"\1_\2", name)
    split = re.sub(r"([A-Z]+)([A-Z][a-z])",
                   r"\1_\2", split)
    return re.sub(r"[^a-z0-9]+", "",
                  split.casefold())


DISCLOSURE_KEYS = frozenset(
    disclosure_key(field)
    for field in DISCLOSURE_FIELDS)

# Closed expected-boundary shape: an admitted revert
# boundary or declared duration carries exactly a
# boundary type and a reference label; no payload
# field belongs here.
BOUNDARY_REQUIRED = (
    "boundary_type", "reference",
)
BOUNDARY_TYPES = (
    "revert_boundary", "declared_duration",
)
BOUNDARY_REF_RE = re.compile(
    r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")

# Closed expected-block shape per family: the
# shared derived keys plus that family's
# hand-computed expectations. Anything else in
# `expected` is refused, exactly like
# expected_boundary.
EXPECTED_FAMILY_KEYS = {
    "persistent-queue-steady-io": (
        "bytes_transferred", "informational_only",
    ),
    "nested-mixed-sg": (
        "outer_complete", "outer_operations",
    ),
    "failure-after-internal-allocation": (
        "bytes_transferred", "failed_operations",
        "final_success",
    ),
    "device-reset-reuse": (
        "lineages",
    ),
    "pre-attach": (),
}

# Integer counters among the family-specific
# expectations. No DMA family carries one today
# (`bytes_transferred` is a decimal string, the
# rest are flags, id lists, or lineages); the
# map stays so a future counter is strictly
# typed by construction, exactly like the
# shared `fact_count`.
FAMILY_COUNT_KEYS = {}


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def catalog():
    return load_json(CATALOG)


def frozen(name):
    return catalog()["vocabularies"]["frozen"][name]


def lane_sources():
    return [entry["source_id"]
            for entry in catalog()["sources"]
            if entry["capability"]
            == LANE_CAPABILITY]


def is_u64(value):
    # fullmatch: `$` alone would still accept a
    # trailing newline before the end of string.
    return (isinstance(value, str)
            and U64_RE.fullmatch(value) is not None
            and int(value) <= U64_MAX)


def check_u64(errors, where, value):
    if not is_u64(value):
        errors.append("bad-u64: %s=%r" % (where, value))


def check_slug(errors, where, value):
    if not isinstance(value, str) or not value:
        errors.append("bad-label: %s is not a string"
                      % where)
    elif SLUG_RE.match(value) is None:
        errors.append("bad-label: %s=%r" % (where, value))


def check_enum(errors, where, value, allowed):
    if value not in allowed:
        errors.append("closed-enum-violation: %s=%r"
                      % (where, value))


def check_keys(errors, where, record, required,
               optional=(), reason_bases=()):
    if not isinstance(record, dict):
        errors.append("missing-required-key: %s is not "
                      "an object" % where)
        return False
    for name in required:
        if name not in record:
            errors.append("missing-required-key: %s.%s"
                          % (where, name))
    allowed = set(required) | set(optional)
    allowed |= {base + "_reason"
                for base in reason_bases}
    for name in record:
        if name not in allowed:
            errors.append("unknown-field: %s.%s"
                          % (where, name))
    return True


def check_present_reason(errors, where, record,
                         name):
    # A reason carried alongside a present (non-null)
    # value must still be a closed-set null-reason
    # string; reason objects or disclosure-shaped
    # fields are never accepted.
    key = name + "_reason"
    if key not in record:
        return
    reason = record[key]
    if not isinstance(reason, str) or not reason:
        errors.append("bad-reason: %s.%s is not a "
                      "null-reason string" % (where, key))
    elif reason not in LANE_NULL_REASONS:
        errors.append("closed-enum-violation: "
                      "%s.%s=%r"
                      % (where, key, reason))


def check_nullable(errors, where, record, name,
                   expect_reason=True):
    if name not in record:
        # A reason without its base value is still
        # validated: disclosure-shaped reasons must
        # fail even when the base field is absent.
        check_present_reason(errors, where, record,
                             name)
        return
    if record[name] is not None:
        check_present_reason(errors, where, record,
                             name)
        return
    reason = record.get(name + "_reason")
    if not expect_reason:
        errors.append("bare-null-without-reason: "
                      "%s.%s must never be null"
                      % (where, name))
    elif not isinstance(reason, str) or not reason:
        errors.append("bare-null-without-reason: "
                      "%s.%s" % (where, name))
    elif reason not in LANE_NULL_REASONS:
        errors.append("closed-enum-violation: "
                      "%s.%s_reason=%r"
                      % (where, name, reason))


def check_quality(errors, where, value):
    if not isinstance(value, dict):
        errors.append("missing-required-key: %s.quality "
                      "is not an object" % where)
        return
    if sorted(value.keys()) != sorted(QUALITY_DIMS):
        errors.append("missing-required-key: "
                      "%s.quality dims=%r"
                      % (where, sorted(value.keys())))
        return
    for dim in QUALITY_DIMS:
        if not isinstance(value[dim], str) \
                or not value[dim]:
            errors.append("bad-label: %s.quality.%s"
                          % (where, dim))


def check_interval(errors, where, value):
    if not isinstance(value, dict):
        errors.append("missing-required-key: %s is not "
                      "an object" % where)
        return
    for end in ("start", "end"):
        if end not in value:
            errors.append("missing-required-key: "
                          "%s.%s" % (where, end))
        else:
            check_u64(errors, "%s.%s" % (where, end),
                      value[end])
    for name in value:
        if name not in ("start", "end", "clock_domain"):
            errors.append("unknown-field: %s.%s"
                          % (where, name))
    # Intervals are well-formed only when start
    # precedes end; a reversed interval overlaps
    # nothing and proves no observation window.
    if is_u64(value.get("start")) and \
            is_u64(value.get("end")) and \
            int(value["start"]) > int(value["end"]):
        errors.append("bad-interval: %s start=%r is "
                      "after end=%r"
                      % (where, value["start"],
                         value["end"]))


def check_window(errors, where, value):
    check_interval(errors, where, value)


def check_fact(errors, where, fact, catalog_sources):
    if not check_keys(
            errors, where, fact, FACT_REQUIRED,
            FACT_OPTIONAL_NULLABLE,
            tuple(FACT_OPTIONAL_NULLABLE)
            + ("native_result",)):
        return
    check_slug(errors, where + ".evidence_id",
               fact.get("evidence_id"))
    if fact.get("source_id") not in catalog_sources:
        errors.append("closed-enum-violation: "
                      "%s.source_id=%r"
                      % (where, fact.get("source_id")))
    elif fact.get("source_id") not in lane_sources():
        errors.append("foreign-source: "
                      "%s.source_id=%r is outside this "
                      "lane's sources %r"
                      % (where, fact.get("source_id"),
                         lane_sources()))
    check_u64(errors, where + ".epoch",
              fact.get("epoch"))
    check_slug(errors, where + ".operation_id",
               fact.get("operation_id"))
    check_enum(errors, where + ".kind",
               fact.get("kind"), LANE_KINDS)
    check_enum(errors, where + ".direction",
               fact.get("direction"), LANE_DIRECTIONS)
    check_u64(errors, where + ".generation",
              fact.get("generation"))
    check_u64(errors, where + ".offset",
              fact.get("offset"))
    check_u64(errors, where + ".length_bytes",
              fact.get("length_bytes"))
    native = fact.get("native_result")
    if native is None:
        check_nullable(errors, where, fact,
                       "native_result")
    else:
        check_present_reason(errors, where, fact,
                             "native_result")
        if not isinstance(native, int) \
                or isinstance(native, bool):
            errors.append(
                "bad-s64: %s.native_result=%r"
                % (where, native))
        elif not S64_MIN <= native <= S64_MAX:
            errors.append(
                "bad-s64: %s.native_result=%r "
                "outside s64" % (where, native))
    check_enum(errors, where + ".caller_class",
               fact.get("caller_class"), LANE_CALLERS)
    check_enum(errors, where + ".peer_class",
               fact.get("peer_class"),
               frozen("peer_classes"))
    check_enum(errors, where + ".clock_domain",
               fact.get("clock_domain"),
               frozen("clock_domains"))
    interval = fact.get("observed_interval")
    check_interval(errors,
                   where + ".observed_interval",
                   interval)
    # A nested interval clock restates the
    # fact-level clock; a conflicting declaration
    # proves no comparable observation window.
    if isinstance(interval, dict) and \
            "clock_domain" in interval and \
            interval["clock_domain"] != \
            fact.get("clock_domain"):
        errors.append("clock-domain-conflict: "
                      "%s.observed_interval.clock_domain"
                      "=%r disagrees with "
                      "%s.clock_domain=%r"
                      % (where,
                         interval["clock_domain"],
                         where,
                         fact.get("clock_domain")))
    check_enum(errors, where + ".semantics",
               fact.get("semantics"),
               frozen("semantics"))
    check_quality(errors, where, fact.get("quality"))
    for name in FACT_OPTIONAL_NULLABLE:
        if name in fact and fact[name] is not None:
            check_slug(errors, "%s.%s" % (where, name),
                       fact[name])
        check_nullable(errors, where, fact, name)


def check_object(errors, where, obj, catalog_sources):
    if not check_keys(errors, where, obj,
                      OBJECT_REQUIRED,
                      ("expected_boundary",)):
        return
    check_slug(errors, where + ".object_token",
               obj.get("object_token"))
    check_u64(errors, where + ".generation",
              obj.get("generation"))
    check_enum(errors, where + ".object_class",
               obj.get("object_class"),
               frozen("object_classes"))
    check_enum(errors, where + ".namespace",
               obj.get("namespace"),
               frozen("address_namespaces"))
    if obj.get("origin_source") not in catalog_sources:
        errors.append("closed-enum-violation: "
                      "%s.origin_source=%r"
                      % (where, obj.get("origin_source")))
    elif obj.get("origin_source") not in lane_sources():
        errors.append("foreign-source: "
                      "%s.origin_source=%r is outside "
                      "this lane's sources %r"
                      % (where, obj.get("origin_source"),
                         lane_sources()))
    check_enum(errors, where + ".lifecycle_status",
               obj.get("lifecycle_status"),
               frozen("lifecycle_statuses"))
    check_enum(errors, where + ".state",
               obj.get("state"), LANE_STATES)
    evidence = obj.get("state_evidence")
    if not isinstance(evidence, list):
        errors.append("missing-required-key: "
                      "%s.state_evidence is not a list"
                      % where)
    else:
        for ident in evidence:
            check_slug(errors,
                       where + ".state_evidence[]",
                       ident)
    if "expected_boundary" in obj:
        boundary = obj["expected_boundary"]
        if boundary is None:
            errors.append(
                "bare-null-without-reason: "
                "%s.expected_boundary must never "
                "be null" % where)
        elif not isinstance(boundary, dict):
            errors.append(
                "bad-boundary: "
                "%s.expected_boundary is not an "
                "object" % where)
        else:
            check_keys(
                errors,
                "%s.expected_boundary" % where,
                boundary, BOUNDARY_REQUIRED)
            check_enum(
                errors,
                "%s.expected_boundary.boundary_type"
                % where,
                boundary.get("boundary_type"),
                BOUNDARY_TYPES)
            reference = boundary.get("reference")
            if not isinstance(reference, str) \
                    or BOUNDARY_REF_RE.fullmatch(
                        reference) is None:
                errors.append(
                    "bad-label: "
                    "%s.expected_boundary.reference=%r"
                    % (where, reference))
    gaps = obj.get("uncertainty")
    if not isinstance(gaps, dict):
        errors.append("missing-required-key: "
                      "%s.uncertainty is not an object"
                      % where)
    else:
        for name in gaps:
            if name != "gaps":
                errors.append("unknown-field: "
                              "%s.uncertainty.%s"
                              % (where, name))
        if "gaps" not in gaps \
                or not isinstance(gaps["gaps"], list):
            errors.append("missing-required-key: "
                          "%s.uncertainty.gaps" % where)
        else:
            for entry in gaps["gaps"]:
                check_slug(
                    errors,
                    where + ".uncertainty.gaps[]",
                    entry)


def check_coverage(errors, where, record,
                   catalog_sources):
    if not check_keys(errors, where, record,
                      COVERAGE_REQUIRED):
        return
    if record.get("source_id") not in catalog_sources:
        errors.append("closed-enum-violation: "
                      "%s.source_id=%r"
                      % (where, record.get("source_id")))
    elif record.get("source_id") not in lane_sources():
        errors.append("foreign-source: "
                      "%s.source_id=%r is outside this "
                      "lane's sources %r"
                      % (where, record.get("source_id"),
                         lane_sources()))
    check_slug(errors, where + ".capability",
               record.get("capability"))
    # A coverage record must pair its source with
    # that source's catalog capability: a kept
    # source id with the other lane's capability
    # claims coverage the source never backs.
    if record.get("source_id") in lane_sources():
        want = {entry["source_id"]:
                entry["capability"]
                for entry in
                catalog()["sources"]}[
                    record["source_id"]]
        if record.get("capability") != want:
            errors.append(
                "capability-mismatch: "
                "%s.capability=%r contradicts "
                "catalog capability %r for "
                "source %r"
                % (where, record.get("capability"),
                   want, record["source_id"]))
    # A coverage record must pair its source with
    # that source's catalog address namespace: a
    # kept source id with the other lane's
    # namespace claims coverage in an address
    # space the source never observes.
    if record.get("source_id") in lane_sources():
        want_namespace = {
            entry["source_id"]:
            entry["address_namespace"]
            for entry in catalog()["sources"]}[
                record["source_id"]]
        if record.get("address_namespace") != \
                want_namespace:
            errors.append(
                "namespace-mismatch: "
                "%s.address_namespace=%r contradicts "
                "catalog address namespace %r for "
                "source %r"
                % (where,
                   record.get("address_namespace"),
                   want_namespace,
                   record["source_id"]))
    if not isinstance(record.get("profile_id"), str) \
            or not record.get("profile_id"):
        errors.append("bad-label: %s.profile_id" % where)
    check_enum(errors, where + ".subject_id",
               record.get("subject_id"),
               frozen("subject_classes"))
    check_slug(errors, where + ".platform_cell",
               record.get("platform_cell"))
    check_enum(errors, where + ".address_namespace",
               record.get("address_namespace"),
               frozen("address_namespaces"))
    check_enum(errors, where + ".phase",
               record.get("phase"), frozen("phase"))
    check_enum(errors, where + ".status",
               record.get("status"),
               frozen("source_status"))
    reasons = [entry["code"]
               for entry in catalog()["source_reasons"]]
    check_enum(errors, where + ".reason",
               record.get("reason"), reasons)
    check_window(errors, where + ".window",
                 record.get("window"))
    check_quality(errors, where, record.get("quality"))


def check_no_disclosure(errors, where, value):
    if isinstance(value, str):
        lowered = value.lower()
        for word in FORBIDDEN:
            if word in lowered:
                errors.append("forbidden-content: "
                              "%s contains %r"
                              % (where, word))
        if HEXADDR_RE.search(value):
            errors.append("forbidden-content: %s holds "
                          "a raw address" % where)
    elif isinstance(value, dict):
        for name, item in value.items():
            if isinstance(name, str) and \
                    disclosure_key(name) in \
                    DISCLOSURE_KEYS:
                errors.append("forbidden-content: "
                              "%s.%s discloses identity "
                              "or addressing"
                              % (where, name))
            check_no_disclosure(
                errors, "%s.%s" % (where, name), item)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            check_no_disclosure(
                errors, "%s[%d]" % (where, index), item)


def validate_fixture(doc):
    """Return the list of shape errors (empty when valid)."""
    errors = []
    if not check_keys(errors, "envelope", doc,
                      ENVELOPE_REQUIRED):
        return errors
    if doc.get("format") != FORMAT:
        errors.append("closed-enum-violation: "
                      "envelope.format=%r"
                      % (doc.get("format"),))
    check_enum(errors, "envelope.family",
               doc.get("family"),
               tuple(FAMILIES))
    check_enum(errors, "envelope.scenario",
               doc.get("scenario"), LANE_SCOPES)
    if not isinstance(doc.get("provenance"), str) \
            or not doc.get("provenance"):
        errors.append("bad-label: envelope.provenance")
    check_enum(errors, "envelope.namespace",
               doc.get("namespace"),
               frozen("address_namespaces"))
    if doc.get("namespace") != "guest_physical":
        errors.append("closed-enum-violation: "
                      "envelope.namespace=%r"
                      % (doc.get("namespace"),))
    check_slug(errors, "envelope.capability",
               doc.get("capability"))
    if doc.get("capability") != "dma-paths":
        errors.append("closed-enum-violation: "
                      "envelope.capability=%r"
                      % (doc.get("capability"),))
    sources = [entry["source_id"]
               for entry in catalog()["sources"]]
    if doc.get("source_id") not in sources:
        errors.append("closed-enum-violation: "
                      "envelope.source_id=%r"
                      % (doc.get("source_id"),))
    elif doc.get("source_id") not in lane_sources():
        errors.append("foreign-source: "
                      "envelope.source_id=%r is outside "
                      "this lane's sources %r"
                      % (doc.get("source_id"),
                         lane_sources()))
    if not isinstance(doc.get("coverage"), list) \
            or not doc.get("coverage"):
        errors.append("missing-required-key: "
                      "envelope.coverage is empty")
    else:
        for index, record in \
                enumerate(doc["coverage"]):
            check_coverage(
                errors, "coverage[%d]" % index,
                record, sources)
    if not isinstance(doc.get("objects"), list):
        errors.append("missing-required-key: "
                      "envelope.objects is not a list")
    else:
        for index, obj in enumerate(doc["objects"]):
            check_object(errors,
                         "objects[%d]" % index, obj,
                         sources)
    if not isinstance(doc.get("facts"), list):
        errors.append("missing-required-key: "
                      "envelope.facts is not a list")
    else:
        for index, fact in enumerate(doc["facts"]):
            check_fact(errors, "facts[%d]" % index,
                       fact, sources)
    check_u64(errors, "envelope.conversions_observed",
              doc.get("conversions_observed"))
    check_u64(errors, "envelope.bytes_transferred",
              doc.get("bytes_transferred"))
    if not isinstance(doc.get("expected"), dict):
        errors.append("missing-required-key: "
                      "envelope.expected is not an "
                      "object")
    check_no_disclosure(errors, "envelope", doc)
    # Cross references: every state-evidence id names a
    # fact, every fact token/generation names an object
    # lineage, every parent names an operation.
    if isinstance(doc.get("facts"), list) and \
            isinstance(doc.get("objects"), list):
        evidence = {fact.get("evidence_id")
                    for fact in doc["facts"]
                    if isinstance(fact, dict)}
        # Evidence ids are session-unique: a
        # duplicated fact record must be rejected
        # even when the expected counts were
        # adjusted to match, so the lookup index
        # above must not silently collapse
        # duplicates.
        seen = set()
        for fact in doc["facts"]:
            if not isinstance(fact, dict):
                continue
            ident = fact.get("evidence_id")
            if not isinstance(ident, str):
                continue
            if ident in seen:
                errors.append(
                    "duplicate-evidence-id: "
                    "facts evidence_id=%r is not "
                    "session-unique" % (ident,))
            else:
                seen.add(ident)
        lineages = {(obj.get("object_token"),
                     obj.get("generation"))
                    for obj in doc["objects"]
                    if isinstance(obj, dict)}
        operations = {fact.get("operation_id")
                      for fact in doc["facts"]
                      if isinstance(fact, dict)}
        for index, obj in enumerate(doc["objects"]):
            if not isinstance(obj, dict):
                continue
            for ident in \
                    obj.get("state_evidence", []):
                if ident not in evidence:
                    errors.append(
                        "dangling-reference: "
                        "objects[%d].state_evidence=%r"
                        % (index, ident))
        for index, fact in enumerate(doc["facts"]):
            if not isinstance(fact, dict):
                continue
            token = fact.get("object_token")
            if token is not None and \
                    (token,
                     fact.get("generation")) \
                    not in lineages:
                errors.append(
                    "dangling-reference: "
                    "facts[%d].object_token=%r"
                    % (index, token))
            parent = fact.get("parent_operation_id")
            if parent is not None and \
                    parent not in operations:
                errors.append(
                    "dangling-reference: "
                    "facts[%d].parent_operation_id=%r"
                    % (index, parent))
    return errors


def load_fixture(name):
    return load_json(os.path.join(FIX, name))


def expected_counts(doc):
    """Independently re-derive the shared expectations."""
    facts = doc["facts"]
    objects = doc["objects"]
    semantics = {}
    for fact in facts:
        semantics[fact["semantics"]] = \
            semantics.get(fact["semantics"], 0) + 1
    return {
        "fact_count": len(facts),
        "evidence_ids": sorted(
            fact["evidence_id"] for fact in facts),
        "operations": sorted(
            {fact["operation_id"] for fact in facts}),
        "live_tokens": sorted(
            obj["object_token"] for obj in objects
            if obj["lifecycle_status"] == "live"),
        "semantics_counts": semantics,
    }


def check_shared_expected(doc):
    derived = expected_counts(doc)
    expected = doc["expected"]
    allowed = set(derived) | set(
        EXPECTED_FAMILY_KEYS[doc["family"]])
    assert set(expected) == allowed, \
        "%s: expected keys=%r allowed=%r" % (
            doc["family"], sorted(expected),
            sorted(allowed))
    for name, value in derived.items():
        got = expected.get(name)
        # Python `True == 1`, so plain equality
        # lets a boolean pass as an integer count.
        # The recorded type must match the derived
        # type exactly, including every per-key
        # count.
        assert type(got) is type(value), \
            "%s: expected.%s type %s != " \
            "derived %s" % (
                doc["family"], name,
                type(got).__name__,
                type(value).__name__)
        if isinstance(value, dict):
            for key in value:
                assert type(got.get(key)) is int, \
                    "%s: expected.%s[%r]=%r is " \
                    "not an int" % (
                        doc["family"], name, key,
                        got.get(key))
        assert got == value, \
            "%s: expected.%s=%r derived=%r" % (
                doc["family"], name, got, value)
    for name in FAMILY_COUNT_KEYS.get(
            doc["family"], ()):
        value = expected.get(name)
        assert type(value) is int, \
            "%s: expected.%s=%r is not an int" % (
                doc["family"], name, value)


def valid_fixtures():
    names = []
    for files in FAMILIES.values():
        names.extend(files)
    return names


def effective_clock(fact):
    """The clock a fact's interval is read in.

    A nested interval clock restates the
    fact-level clock (shape validation refuses a
    conflict); the completion comparison reads
    the nested declaration when present.
    """
    interval = fact.get("observed_interval")
    if isinstance(interval, dict) and \
            "clock_domain" in interval:
        return interval["clock_domain"]
    return fact.get("clock_domain")


def test_fixtures_present():
    assert os.path.isdir(FIX), "missing %s" % FIX
    for name in valid_fixtures():
        path = os.path.join(FIX, name)
        assert os.path.isfile(path), \
            "missing fixture %s" % name


def test_valid_shapes():
    for name in valid_fixtures():
        errors = validate_fixture(load_fixture(name))
        assert errors == [], \
            "%s: %r" % (name, errors)


def test_shared_expected_values():
    for name in valid_fixtures():
        check_shared_expected(load_fixture(name))


def test_malformed_rejected():
    assert len(MALFORMED) == len(FAMILIES), \
        "one malformed negative per family"
    for name, code in MALFORMED.items():
        path = os.path.join(FIX, name)
        assert os.path.isfile(path), \
            "missing malformed fixture %s" % name
        errors = validate_fixture(load_json(path))
        assert errors, \
            "%s: malformed fixture accepted" % name
        joined = "\n".join(errors)
        assert code in joined, \
            "%s: want %r in %r" % (name, code, errors)


def test_catalog_pins_unchanged():
    assert frozen("semantics") == [
        "request", "result", "inventory",
        "lifecycle", "state", "native_rejection",
    ]
    assert frozen("phase") == [
        "boot", "pre_attach", "observed",
    ]
    assert "dma-virtio-paths" in [
        entry["source_id"]
        for entry in catalog()["sources"]
    ]


def test_lifetime_conversion_bytes_distinct():
    # Allocation/queue lifetimes, conversion counts, and
    # transferred bytes are three separate dimensions;
    # no fixture may merge them into one number.
    for name in valid_fixtures():
        doc = load_fixture(name)
        assert isinstance(doc["objects"], list)
        assert is_u64(doc["conversions_observed"])
        assert is_u64(doc["bytes_transferred"])
        assert "expected" in doc


def test_steady_io_no_new_conversions():
    doc = load_fixture(
        "persistent_queue_steady_io.json")
    assert doc["family"] == "persistent-queue-steady-io"
    assert doc["conversions_observed"] == "0"
    uses = [fact for fact in doc["facts"]
            if fact["kind"] == "queue-use"]
    assert uses, "steady I/O needs transfer facts"
    # Requested length is not transferred length: a
    # failed queue use moves no bytes, so only uses
    # with a successful native result contribute to
    # the transferred total.
    succeeded = [fact for fact in uses
                 if fact["native_result"] == 0]
    derived = sum(int(fact["length_bytes"])
                  for fact in succeeded)
    assert derived > 0
    assert doc["expected"]["bytes_transferred"] == \
        str(derived)
    assert doc["bytes_transferred"] == str(derived)
    assert doc["expected"]["informational_only"] is True
    kinds = {fact["kind"] for fact in doc["facts"]}
    assert kinds <= {"queue-create", "queue-use"}, kinds
    assert doc["expected"]["live_tokens"] != []


def test_nested_mixed_sg_segments():
    doc = load_fixture("nested_mixed_sg.json")
    assert doc["family"] == "nested-mixed-sg"
    # One transfer, one measurement epoch:
    # segment cover math across a reset is not
    # comparable.
    epochs = {fact["epoch"] for fact in doc["facts"]}
    assert len(epochs) == 1, \
        "mixed transfer spans epochs: %r" % (
            sorted(epochs),)
    children = [fact for fact in doc["facts"]
                if fact.get("parent_operation_id")]
    assert children, "nested segments need parents"
    derived_outer = sorted(
        {fact["parent_operation_id"]
         for fact in children})
    assert doc["expected"]["outer_operations"] == \
        derived_outer
    kinds = {fact["kind"] for fact in children}
    assert "segment-bounced" in kinds, kinds
    assert "segment-direct" in kinds, kinds
    outer = [fact for fact in doc["facts"]
             if fact["kind"] == "operation-outer"]
    assert outer, "outer operation fact required"
    results = [fact for fact in outer
               if fact["semantics"] == "result"]
    assert results, "outer result fact required"
    for fact in results:
        assert fact["native_result"] == 0, \
            "failed outer is not complete: %r" % (
                fact["evidence_id"],)
    requests = [fact for fact in outer
                if fact["semantics"] == "request"]
    assert requests, "outer request fact required"
    # Request and result describe the same outer
    # transfer: their extents must agree. A 1-byte
    # request paired with an 8192-byte result is not
    # a coherent transfer.
    by_operation = {}
    for fact in outer:
        by_operation.setdefault(
            fact["operation_id"], []).append(fact)
    for operation, group in by_operation.items():
        # A request in one operation and a result in
        # another are not a paired transfer: each
        # outer operation must carry both records.
        semantics = {fact["semantics"]
                     for fact in group}
        assert {"request", "result"} <= semantics, \
            "outer operation %r lacks a paired " \
            "request and result: %r" % (
                operation, sorted(semantics))
        # Pairing needs one measurement epoch: a
        # result from another epoch is not
        # comparable with this request, because a
        # reset breaks comparability.
        epochs = {fact["epoch"] for fact in group}
        assert len(epochs) == 1, \
            "outer operation %r pairs facts " \
            "across epochs: %r" % (
                operation, sorted(epochs))
        # Pairing needs one clock domain: no clock
        # silently replaces another.
        domains = {effective_clock(fact)
                   for fact in group}
        assert len(domains) == 1, \
            "outer operation %r pairs facts " \
            "across clock domains: %r" % (
                operation, sorted(domains))
        # The result must not precede its request:
        # a completion observed before the request
        # starts is not this transfer.
        starts = {}
        for fact in group:
            starts.setdefault(
                fact["semantics"], []).append(
                    int(fact["observed_interval"][
                        "start"]))
        for result_start in starts["result"]:
            for request_start in starts["request"]:
                assert result_start >= request_start, \
                    "outer result before its " \
                    "request for %r: result %r " \
                    "request %r" % (
                        operation, result_start,
                        request_start)
        extents = {(fact["offset"],
                    fact["length_bytes"])
                   for fact in group}
        assert len(extents) == 1, \
            "outer request/result extent mismatch " \
            "for %r: %r" % (
                operation, sorted(extents))
    # Every required segment must sit inside the
    # outer completion window: a segment observed
    # after the outer result ends is not part of
    # this complete transfer. Bounds come from the
    # parent operation's request start and result
    # end; order compares only within one clock
    # domain.
    for fact in children:
        parent = fact["parent_operation_id"]
        group = by_operation.get(parent, [])
        assert group, \
            "segment %r names no outer operation " \
            "%r" % (fact["evidence_id"], parent)
        domains = {effective_clock(entry)
                   for entry in group}
        domains.add(effective_clock(fact))
        assert len(domains) == 1, \
            "segment %r order needs one clock " \
            "domain: %r" % (
                fact["evidence_id"],
                sorted(domains))
        window_start = min(
            int(entry["observed_interval"]["start"])
            for entry in group
            if entry["semantics"] == "request")
        window_end = max(
            int(entry["observed_interval"]["end"])
            for entry in group
            if entry["semantics"] == "result")
        start = int(
            fact["observed_interval"]["start"])
        end = int(fact["observed_interval"]["end"])
        assert window_start <= start \
            and end <= window_end, \
            "segment %r outside the outer " \
            "completion window [%r, %r]: %r" % (
                fact["evidence_id"], window_start,
                window_end, (start, end))
    # Every child segment must have succeeded: a
    # failed segment while claiming complete
    # transfer is not a complete transfer.
    for fact in children:
        assert fact["native_result"] == 0, \
            "failed segment is not complete " \
            "transfer: %r" % (fact["evidence_id"],)
    # Segment extents must be disjoint and jointly
    # cover the outer transfer length.
    extents = sorted(
        (int(fact["offset"]),
         int(fact["offset"])
         + int(fact["length_bytes"]))
        for fact in children)
    for first, second in zip(extents, extents[1:]):
        assert first[1] <= second[0], \
            "overlapping segment extents: %r" % (
                extents,)
    outer_length = int(results[0]["length_bytes"])
    assert sum(end - start
               for start, end in extents) == \
        outer_length
    # Every segment must lie inside the outer extent;
    # disjoint cover alone would also accept a
    # segment moved past the outer end.
    outer_start = int(results[0]["offset"])
    outer_end = outer_start + outer_length
    for start, end in extents:
        assert outer_start <= start and end <= outer_end, \
            "segment outside outer extent: %r not in " \
            "[%r, %r]" % ((start, end),
                           outer_start, outer_end)
    # The envelope total is the outer transfer length,
    # not an independent number.
    assert doc["bytes_transferred"] == str(outer_length), \
        "bytes_transferred=%r outer=%r" % (
            doc["bytes_transferred"], outer_length)
    assert doc["expected"]["outer_complete"] is True


def test_failure_after_internal_allocation():
    doc = load_fixture(
        "failure_after_internal_allocation.json")
    assert doc["family"] == \
        "failure-after-internal-allocation"
    internal = [fact for fact in doc["facts"]
                if fact["kind"] == "allocation-internal"
                and fact["native_result"] == 0]
    assert internal, "internal allocation must precede"
    failed = [fact["operation_id"]
              for fact in doc["facts"]
              if fact["semantics"] == "result"
              and isinstance(
                  fact["native_result"], int)
              and fact["native_result"] != 0]
    assert failed, "a failed native result is required"
    assert sorted(doc["expected"][
        "failed_operations"]) == sorted(failed)
    # No bytes may be attributed to the failed
    # allocation: the envelope total is zero and each
    # failed result carries a zero transfer length.
    assert doc["expected"]["bytes_transferred"] == "0"
    assert doc["bytes_transferred"] == "0"
    for fact in doc["facts"]:
        if fact["operation_id"] in failed \
                and fact["semantics"] == "result":
            assert fact["length_bytes"] == "0", \
                fact["evidence_id"]
    statuses = {obj["lifecycle_status"]
                for obj in doc["objects"]}
    assert statuses <= {"quarantined", "released"}, \
        statuses
    assert doc["expected"]["final_success"] is False


def test_device_reset_reuse_lineages():
    doc = load_fixture("device_reset_reuse.json")
    assert doc["family"] == "device-reset-reuse"
    lineages = {}
    for obj in doc["objects"]:
        lineages.setdefault(
            obj["object_token"], []).append(
                obj["generation"])
    for token in lineages:
        lineages[token] = sorted(lineages[token],
                                 key=int)
    assert doc["expected"]["lineages"] == lineages
    assert any(len(gens) > 1
               for gens in lineages.values()), \
        "reuse needs a second generation"
    by_lineage = {(obj["object_token"],
                   obj["generation"]): obj
                  for obj in doc["objects"]}
    first = sorted(by_lineage)[0]
    assert by_lineage[first][
        "lifecycle_status"] == "released"
    last = sorted(by_lineage,
                  key=lambda pair: int(pair[1]))[-1]
    assert by_lineage[last][
        "lifecycle_status"] == "live"


def test_pre_attach_inventory_only():
    doc = load_fixture("pre_attach.json")
    assert doc["family"] == "pre-attach"
    phases = {record["phase"]
              for record in doc["coverage"]}
    assert "pre_attach" in phases, phases
    semantics = {fact["semantics"]
                 for fact in doc["facts"]}
    assert semantics == {"inventory"}, semantics
    assert doc["conversions_observed"] == "0"
