#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline shared-buffer fixtures: strict shape pinning.

Pure-offline loader/validator over
``fixtures/buffers/*.json``. Every fixture is shaped by
the frozen exposure catalog field lists (ExposureFact,
ExposureObject, CoverageSource, BaselineSample); this
module pins required keys, closed enums, the u64
decimal-string rule, and the null-with-reason rule, then
re-derives each fixture's hand-computed ``expected``
block with an independent predicate. Malformed fixtures
must be rejected with the mapped error code.

Covered families: generic non-shared negative,
two-holder retention, last-reference teardown, callback
failure, scan-held reference, and concurrent
create/reuse with an independent release witness.

Run directly: `python3 -m pytest tests/exposure/test_buffers.py -q`.
"""

import json
import os
import re

FIX = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "fixtures", "buffers")
ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(
    ROOT, "profiles", "exposure", "catalog.json")

FORMAT = "exposure-buffers-fixture/0.1.0"

# Family -> valid fixture files. Every card-named
# buffers family must stay covered by at least one
# fixture.
FAMILIES = {
    "generic-nonshared-negative": [
        "generic_nonshared_negative.json",
    ],
    "two-holder-retention": [
        "two_holder_retention.json",
    ],
    "last-reference-teardown": [
        "last_reference_teardown.json",
    ],
    "callback-failure": [
        "callback_failure.json",
    ],
    "scan-held-reference": [
        "scan_held_reference.json",
    ],
    "concurrent-create-reuse": [
        "concurrent_create_reuse.json",
    ],
}

# Malformed fixture -> expected error-code substring. One
# negative per family; each defect rotates across the
# shape rules (missing key, bad enum, bare null, bad u64,
# bad label, dangling reference).
MALFORMED = {
    "malformed_generic_missing_key.json":
        "missing-required-key",
    "malformed_two_holder_bad_enum.json":
        "closed-enum-violation",
    "malformed_teardown_bare_null.json":
        "bare-null-without-reason",
    "malformed_callback_bad_u64.json":
        "bad-u64",
    "malformed_scan_bad_label.json":
        "bad-label",
    "malformed_concurrent_dangling.json":
        "dangling-reference",
}

ENVELOPE_REQUIRED = (
    "format", "family", "scenario", "provenance",
    "namespace", "capability", "source_id", "coverage",
    "objects", "facts", "release_witness", "expected",
)

ENVELOPE_OPTIONAL = (
    "scan",
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

WITNESS_REQUIRED = (
    "witness_id", "object_token", "generation",
    "observed", "detail",
)

SCAN_REQUIRED = (
    "sample_id", "source_id", "start_time",
    "end_time", "scope", "counts", "units",
    "visited", "returned", "bounded", "atomicity",
    "quality",
)

QUALITY_DIMS = (
    "detail", "aggregate", "identity",
    "baseline", "terminal",
)

# Lane-local closed sets for catalog-deferred labels.
# The catalog freezes kinds, directions, caller classes,
# object states, scopes, and null reasons from admitted
# sources; until then these lane-local sets pin the
# fixture vocabulary so no adapter can invent a label
# silently.
LANE_KINDS = (
    "inventory", "creation", "attachment",
    "release-put", "destruction", "mapping-entry",
    "callback-result", "scan-hold",
)
LANE_DIRECTIONS = (
    "to-device", "from-device", "bidirectional", "none",
)
LANE_CALLERS = (
    "dma-buf-core", "heap-driver", "v4l2-consumer",
    "unknown-caller",
)
LANE_STATES = (
    "inventoried", "shared-live", "released",
    "quarantined", "scan-held", "reused",
)
LANE_NULL_REASONS = (
    "unknown", "unobserved", "not-applicable",
    "withheld", "out-of-window",
)
LANE_SCOPES = (
    "shared-heap-retention",
)
LANE_SCAN_SCOPES = (
    "heap-scan", "attachment-scan",
)

# State evidence must support the claimed state:
# each object state needs at least one cited fact
# whose kind observes the claim. Same lineage
# alone is not support: a creation fact proves
# the object existed, never that it was
# released, quarantined, or held. A put is not
# destruction: a release claim needs
# destruction-kind evidence, never a lone put.
STATE_SUPPORT = {
    "inventoried": ("inventory",),
    "shared-live": ("attachment",),
    "released": ("destruction",),
    "quarantined": ("callback-result",),
    "scan-held": ("scan-hold",),
    "reused": ("creation", "destruction"),
}

# Lane capability pinned by the envelope: a fact
# may only cite a catalog source carrying this
# capability. Another lane's source id exists in
# the catalog but backs no coverage here.
LANE_CAPABILITY = "shared-buffers"

U64_MAX = 18446744073709551615
U64_RE = re.compile(r"^(0|[1-9][0-9]{0,19})$")
S64_MIN = -(2 ** 63)
S64_MAX = 2 ** 63 - 1
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")
HEXADDR_RE = re.compile(r"0x[0-9a-fA-F]{3,}")
# Witness affirmation frame: an optional "<ordinal>
# generation" prefix naming the witnessed
# generation, then one event-kind token, then the
# terminal "observed" marker. The claimed kind,
# generation, and polarity come from these
# structural slots; wording outside the frame
# affirms nothing.
WITNESS_FRAME_RE = re.compile(
    r"(?:([a-z]+) generation )?([a-z0-9]+"
    r"(?:-[a-z0-9]+)*) observed")

# Closed ordinal vocabulary for the named witness
# generation: the prefix word must name a
# generation number, and that number must match
# the referenced fact's generation.
WITNESS_GENERATIONS = {
    "first": "1",
    "second": "2",
    "third": "3",
    "fourth": "4",
    "fifth": "5",
    "sixth": "6",
    "seventh": "7",
    "eighth": "8",
    "ninth": "9",
    "tenth": "10",
    "eleventh": "11",
    "twelfth": "12",
}

# Strings that must never appear in a fixture: raw
# addresses, payload/key material, buffer names, or
# verdict language.
FORBIDDEN = (
    "payload", "private", "secret", "password",
    "decrypt", "plaintext", "exploit", "verdict",
    ".c", ".h", "/dev/", "heap-name",
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
    "generic-nonshared-negative": (
        "complete_graph", "shared_origin_proved",
    ),
    "two-holder-retention": (
        "puts", "destructions", "observer_retention",
    ),
    "last-reference-teardown": (
        "puts", "destructions", "mapping_success",
    ),
    "callback-failure": (
        "failed_callbacks",
    ),
    "scan-held-reference": (
        "scan_complete", "scan_bounded",
        "observer_retention",
    ),
    "concurrent-create-reuse": (
        "lineages", "witness_agrees",
    ),
}

# Integer counters among the family-specific
# expectations. Every count field is strictly
# typed, not just the shared `fact_count`:
# Python `True == 1`, so plain equality would
# let a boolean pass as a count.
FAMILY_COUNT_KEYS = {
    "two-holder-retention": ("puts", "destructions"),
    "last-reference-teardown": (
        "puts", "destructions",
    ),
}


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


def check_nullable(errors, where, record, name):
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
    if not isinstance(reason, str) or not reason:
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
    check_interval(errors, where + ".window",
                   record.get("window"))
    check_quality(errors, where, record.get("quality"))


def check_witness(errors, where, event):
    if not check_keys(errors, where, event,
                      WITNESS_REQUIRED):
        return
    check_slug(errors, where + ".witness_id",
               event.get("witness_id"))
    check_slug(errors, where + ".object_token",
               event.get("object_token"))
    check_u64(errors, where + ".generation",
              event.get("generation"))
    check_enum(errors, where + ".observed",
               event.get("observed"),
               frozen("semantics"))
    if not isinstance(event.get("detail"), str) \
            or not event.get("detail"):
        errors.append("bad-label: %s.detail" % where)


def check_scan(errors, where, scan, catalog_sources):
    if not check_keys(errors, where, scan,
                      SCAN_REQUIRED):
        return
    check_slug(errors, where + ".sample_id",
               scan.get("sample_id"))
    if scan.get("source_id") not in catalog_sources:
        errors.append("closed-enum-violation: "
                      "%s.source_id=%r"
                      % (where, scan.get("source_id")))
    check_u64(errors, where + ".start_time",
              scan.get("start_time"))
    check_u64(errors, where + ".end_time",
              scan.get("end_time"))
    if is_u64(scan.get("start_time")) and \
            is_u64(scan.get("end_time")) and \
            int(scan["start_time"]) > \
            int(scan["end_time"]):
        errors.append("bad-interval: %s start_time=%r "
                      "is after end_time=%r"
                      % (where, scan["start_time"],
                         scan["end_time"]))
    check_enum(errors, where + ".scope",
               scan.get("scope"), LANE_SCAN_SCOPES)
    counts = scan.get("counts")
    if not isinstance(counts, dict) or not counts:
        errors.append("missing-required-key: "
                      "%s.counts is empty" % where)
    else:
        for name, value in counts.items():
            check_slug(errors, "%s.counts key" % where,
                       name)
            check_u64(errors,
                      "%s.counts.%s" % (where, name),
                      value)
    check_enum(errors, where + ".units",
               scan.get("units"), frozen("units"))
    check_u64(errors, where + ".visited",
              scan.get("visited"))
    check_u64(errors, where + ".returned",
              scan.get("returned"))
    if not isinstance(scan.get("bounded"), bool):
        errors.append("bad-label: %s.bounded is not "
                      "a boolean" % where)
    check_enum(errors, where + ".atomicity",
               scan.get("atomicity"),
               frozen("atomicity"))
    check_quality(errors, where, scan.get("quality"))


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
                      ENVELOPE_REQUIRED,
                      ENVELOPE_OPTIONAL):
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
    if doc.get("namespace") != "session_token":
        errors.append("closed-enum-violation: "
                      "envelope.namespace=%r"
                      % (doc.get("namespace"),))
    if doc.get("capability") != "shared-buffers":
        errors.append("closed-enum-violation: "
                      "envelope.capability=%r"
                      % (doc.get("capability"),))
    sources = [entry["source_id"]
               for entry in catalog()["sources"]]
    if doc.get("source_id") not in sources:
        errors.append("closed-enum-violation: "
                      "envelope.source_id=%r"
                      % (doc.get("source_id"),))
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
    witness = doc.get("release_witness")
    if not isinstance(witness, list) or not witness:
        errors.append("missing-required-key: "
                      "envelope.release_witness is "
                      "empty")
    else:
        for index, event in enumerate(witness):
            check_witness(
                errors, "release_witness[%d]" % index,
                event)
    if "scan" in doc:
        check_scan(errors, "scan", doc["scan"],
                   sources)
    if not isinstance(doc.get("expected"), dict):
        errors.append("missing-required-key: "
                      "envelope.expected is not an "
                      "object")
    check_no_disclosure(errors, "envelope", doc)
    # Cross references: every state-evidence id names a
    # fact for that object's own lineage, every fact
    # token/generation names an object lineage, every
    # parent names an operation, and every witness event
    # names an object lineage.
    if isinstance(doc.get("facts"), list) and \
            isinstance(doc.get("objects"), list):
        evidence = {fact.get("evidence_id"): fact
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
            cited_kinds = []
            for ident in \
                    obj.get("state_evidence", []):
                if ident not in evidence:
                    errors.append(
                        "dangling-reference: "
                        "objects[%d].state_evidence=%r"
                        % (index, ident))
                else:
                    cited = evidence[ident]
                    cited_kinds.append(
                        cited.get("kind"))
                    if (cited.get("object_token"),
                            cited.get("generation")) != \
                            (obj.get("object_token"),
                             obj.get("generation")):
                        errors.append(
                            "unsupported-state-evidence: "
                            "objects[%d].state_evidence="
                            "%r names a fact for lineage "
                            "%r, not %r"
                            % (index, ident,
                               (cited.get("object_token"),
                                cited.get("generation")),
                               (obj.get("object_token"),
                                obj.get("generation"))))
            # The cited evidence must support the
            # claimed state kind: at least one cited
            # fact carries a kind that observes the
            # claim.
            want_kinds = STATE_SUPPORT.get(
                obj.get("state"))
            if want_kinds is not None and \
                    not any(kind in want_kinds
                            for kind in cited_kinds):
                errors.append(
                    "unsupported-state-evidence: "
                    "objects[%d] state=%r cites no "
                    "supporting kind %r"
                    % (index, obj.get("state"),
                       want_kinds))
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
        if isinstance(witness, list):
            for index, event in enumerate(witness):
                if not isinstance(event, dict):
                    continue
                pair = (event.get("object_token"),
                        event.get("generation"))
                if pair not in lineages:
                    errors.append(
                        "dangling-reference: "
                        "release_witness[%d]=%r"
                        % (index, pair))
        # Lifecycle coherence: a recorded
        # destruction is terminal evidence for its
        # lineage, so an object carrying
        # destruction evidence cannot still be
        # alive: neither `created` nor `live`
        # coheres with recorded destruction.
        destroyed = {(fact.get("object_token"),
                      fact.get("generation"))
                     for fact in doc["facts"]
                     if isinstance(fact, dict)
                     and fact.get("kind")
                     == "destruction"}
        for index, obj in enumerate(doc["objects"]):
            if not isinstance(obj, dict):
                continue
            pair = (obj.get("object_token"),
                    obj.get("generation"))
            status = obj.get("lifecycle_status")
            if status in ("created", "live") \
                    and pair in destroyed:
                errors.append(
                    "lifecycle-coherence: "
                    "objects[%d].lifecycle_status="
                    "%r contradicts recorded "
                    "destruction for lineage %r"
                    % (index, status, pair))
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
    kinds = {}
    for fact in facts:
        kinds[fact["kind"]] = \
            kinds.get(fact["kind"], 0) + 1
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
        "kind_counts": kinds,
        "witness_ids": sorted(
            event["witness_id"]
            for event in doc["release_witness"]),
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


def kind_facts(doc, kind):
    return [fact for fact in doc["facts"]
            if fact["kind"] == kind]


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
    assert "heap-dmabuf-objects" in [
        entry["source_id"]
        for entry in catalog()["sources"]
    ]


def test_capabilities_stay_distinct():
    # Inventory, export/attach, map, use, and destruction
    # are separate capabilities; no single capability
    # label may stand in for the graph.
    for name in valid_fixtures():
        doc = load_fixture(name)
        kinds = {fact["kind"] for fact in doc["facts"]}
        assert kinds <= set(LANE_KINDS), (name, kinds)


def test_generic_negative_proves_no_origin():
    doc = load_fixture("generic_nonshared_negative.json")
    assert doc["family"] == "generic-nonshared-negative"
    assert doc["expected"]["shared_origin_proved"] \
        is False
    assert doc["expected"]["complete_graph"] is False
    assert {fact["kind"] for fact in doc["facts"]} == \
        {"inventory"}
    assert {event["observed"]
            for event in doc["release_witness"]} == \
        {"inventory"}


def test_two_holder_put_is_not_destruction():
    doc = load_fixture("two_holder_retention.json")
    assert doc["family"] == "two-holder-retention"
    attaches = kind_facts(doc, "attachment")
    puts = kind_facts(doc, "release-put")
    destroys = kind_facts(doc, "destruction")
    assert len(attaches) == 2, "two holders attach"
    assert len(puts) == 1, "one holder puts"
    assert destroys == [], "no destruction observed"
    assert doc["expected"]["puts"] == 1
    assert doc["expected"]["destructions"] == 0
    assert doc["expected"]["live_tokens"] != []
    assert doc["expected"]["observer_retention"] \
        is False


def test_last_reference_teardown():
    doc = load_fixture("last_reference_teardown.json")
    assert doc["family"] == "last-reference-teardown"
    attaches = kind_facts(doc, "attachment")
    puts = kind_facts(doc, "release-put")
    destroys = kind_facts(doc, "destruction")
    assert len(attaches) == len(puts) > 0
    assert len(destroys) == 1, \
        "teardown needs one destruction fact"
    # Destruction is witnessed only after the last
    # put: compare the observed timestamps, not just
    # the counts. Timestamps order only within one
    # clock domain; mixed domains prove no order.
    domains = {fact["clock_domain"]
               for fact in puts + destroys}
    assert len(domains) == 1, \
        "teardown order needs one clock domain: " \
        "%r" % (sorted(domains),)
    last_put_end = max(
        int(fact["observed_interval"]["end"])
        for fact in puts)
    first_destroy_start = min(
        int(fact["observed_interval"]["start"])
        for fact in destroys)
    assert first_destroy_start >= last_put_end, \
        "destruction before last put: %r < %r" % (
            first_destroy_start, last_put_end)
    assert doc["expected"]["puts"] == len(puts)
    assert doc["expected"]["destructions"] == 1
    assert doc["expected"]["live_tokens"] == []
    # Mmap entry is not success: the mapping-entry fact
    # carries no observable native result.
    entries = kind_facts(doc, "mapping-entry")
    assert len(entries) == 1
    assert entries[0]["native_result"] is None
    assert entries[0]["native_result_reason"] == \
        "unobserved"
    assert doc["expected"]["mapping_success"] is False


def test_callback_failure_quarantines():
    doc = load_fixture("callback_failure.json")
    assert doc["family"] == "callback-failure"
    failed = [fact for fact in doc["facts"]
              if fact["kind"] == "callback-result"
              and isinstance(
                  fact["native_result"], int)
              and fact["native_result"] != 0]
    assert len(failed) == 1
    assert doc["expected"]["failed_callbacks"] == \
        [failed[0]["operation_id"]]
    statuses = {obj["lifecycle_status"]
                for obj in doc["objects"]}
    assert statuses == {"quarantined"}, statuses
    gaps = [gap for obj in doc["objects"]
            for gap in obj["uncertainty"]["gaps"]]
    assert gaps != [], "failure must record a gap"


def test_scan_held_reference_bounded():
    doc = load_fixture("scan_held_reference.json")
    assert doc["family"] == "scan-held-reference"
    assert "scan" in doc, "scan family needs a sample"
    scan = doc["scan"]
    assert scan["bounded"] is True
    assert int(scan["visited"]) >= int(scan["returned"])
    assert scan["atomicity"] == "interval"
    # A scan that hit its bound is explicitly
    # partial, never complete.
    assert scan["quality"]["terminal"] == "partial"
    assert doc["expected"]["scan_complete"] is False
    # The visit counter must agree with the visited
    # total; retention stays attributed to the scan
    # hold, never to the observer.
    assert scan["counts"]["buffers-visited"] == \
        scan["visited"]
    assert doc["expected"]["observer_retention"] \
        is False
    assert doc["expected"]["scan_bounded"] is True
    holds = kind_facts(doc, "scan-hold")
    assert holds != []
    # A hold is evidence for this scan only when its
    # observed interval meets the scan window; a hold
    # entirely outside the window proves nothing
    # about the scan.
    window_start = int(scan["start_time"])
    window_end = int(scan["end_time"])
    for fact in holds:
        start = int(fact["observed_interval"]["start"])
        end = int(fact["observed_interval"]["end"])
        assert start <= window_end \
            and end >= window_start, \
            "scan hold outside the scan window: " \
            "%r not meeting [%r, %r]" % (
                (start, end),
                window_start, window_end)
    assert kind_facts(doc, "destruction") == []
    assert doc["expected"]["live_tokens"] != []


def test_concurrent_create_reuse_witness():
    doc = load_fixture("concurrent_create_reuse.json")
    assert doc["family"] == "concurrent-create-reuse"
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
    # The witness must record actual release
    # evidence; a bare inventory entry is not a
    # release observation.
    for event in doc["release_witness"]:
        assert event["observed"] in (
            "lifecycle", "result"), \
            "release witness without release " \
            "evidence: %r" % (event["witness_id"],)
    # Each witness event must name genuine evidence
    # for its lineage: some fact for that
    # token/generation must carry the observed
    # semantics. An unrelated result observed
    # nowhere in the lineage is not evidence.
    observed_by_lineage = {}
    for fact in doc["facts"]:
        observed_by_lineage.setdefault(
            (fact.get("object_token"),
             fact.get("generation")),
            set()).add(fact["semantics"])
    for event in doc["release_witness"]:
        pair = (event["object_token"],
                event["generation"])
        assert event["observed"] in \
            observed_by_lineage.get(pair, set()), \
            "witness %r claims %r with no such " \
            "fact for lineage %r" % (
                event["witness_id"],
                event["observed"], pair)
    # Each witness event must affirm one observed
    # event kind for its lineage through the fixed
    # detail frame, and the claimed kind plus the
    # witnessed semantics must match one referenced
    # fact for that token/generation. A named
    # "<ordinal> generation" prefix must name the
    # referenced fact's generation as well: a
    # detail naming another generation, or no
    # known generation, describes no observed
    # event — whatever words it shares with a
    # recorded kind.
    facts_by_lineage = {}
    for fact in doc["facts"]:
        facts_by_lineage.setdefault(
            (fact.get("object_token"),
             fact.get("generation")),
            []).append(fact)
    lane_kinds = set(LANE_KINDS)
    for event in doc["release_witness"]:
        pair = (event["object_token"],
                event["generation"])
        detail = event["detail"].casefold().strip()
        match = WITNESS_FRAME_RE.fullmatch(detail)
        assert match, \
            "witness %r affirms no observed event " \
            "kind for lineage %r" % (
                event["witness_id"], pair)
        named = match.group(1)
        claimed = match.group(2)
        assert claimed in lane_kinds, \
            "witness %r names no observed event " \
            "kind for lineage %r" % (
                event["witness_id"], pair)
        want_generation = None
        if named is not None:
            assert named in WITNESS_GENERATIONS, \
                "witness %r names no known " \
                "generation for lineage %r" % (
                    event["witness_id"], pair)
            want_generation = \
                WITNESS_GENERATIONS[named]
        lineage = facts_by_lineage.get(pair, [])
        kinds = {fact["kind"] for fact in lineage}
        assert claimed in kinds, \
            "witness %r claims %r with no such " \
            "fact for lineage %r" % (
                event["witness_id"], claimed, pair)
        assert any(fact["kind"] == claimed
                   and fact["semantics"]
                   == event["observed"]
                   for fact in lineage), \
            "witness %r claims %r with no such " \
            "%r fact for lineage %r" % (
                event["witness_id"], claimed,
                event["observed"], pair)
        if want_generation is not None:
            assert any(fact["kind"] == claimed
                       and fact["semantics"]
                       == event["observed"]
                       and fact["generation"]
                       == want_generation
                       for fact in lineage), \
                "witness %r names generation %r " \
                "with no such %r %r fact for " \
                "lineage %r" % (
                    event["witness_id"],
                    want_generation, claimed,
                    event["observed"], pair)
    witnessed = sorted(
        {(event["object_token"],
          event["generation"])
         for event in doc["release_witness"]})
    derived = sorted(
        {(obj["object_token"], obj["generation"])
         for obj in doc["objects"]})
    assert witnessed == derived, \
        "independent witness must agree per lineage"
    assert doc["expected"]["witness_agrees"] is True
