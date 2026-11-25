#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Sealed exposure record contracts: seal gating, containment, settlement.

Offline contract checks over the exposure fixtures in
``fixtures/contracts/``. Every helper here is pure standard
library code over persisted bytes: facts replay only from
the sealed event lines, an unsealed snapshot can never
satisfy a rule, duplicate evidence and mixed epochs are
rejected, and a snapshot without terminal evidence stays
partial. The Rust lane modules implement the same contract;
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
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

FROZEN_SEMANTICS = ("request", "result", "inventory", "lifecycle",
                    "state", "native_rejection")
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
QUALITY_CHANNELS = ("detail", "aggregate", "identity", "baseline",
                    "terminal")
SESSION_CHANNELS = ("detail", "aggregate", "correlation", "baseline",
                    "terminal")

INTEGRITY_KEYS = ("algorithm", "events_bytes", "line_count",
                  "first_seq", "last_seq", "events_sha256", "kinds")
SEAL_KINDS = ("bounce_attempt", "map_result", "unmap", "copy",
              "sync_request", "transition_result", "pool_sample",
              "gap", "marker", "counter_snapshot", "exposure_fact")

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


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        return json.load(handle)


def check_u64(value, where):
    assert isinstance(value, str), "%s must be a decimal string" % where
    assert U64RE.fullmatch(value), "%s not canonical: %r" % (where, value)
    number = int(value)
    assert number <= U64MAX, "%s overflows u64" % where
    return number


def check_quality(quality, where):
    assert set(quality.keys()) == set(QUALITY_CHANNELS), \
        "%s channels" % where
    for channel in QUALITY_CHANNELS:
        node = quality[channel]
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


def facts_from_lines(snapshot):
    """Replay exposure facts from the sealed lines only.

    No sidecar supplies policy evidence: every fact comes
    from an ``exposure_fact`` line of the sealed stream.
    """
    facts = []
    for line in snapshot["event_lines"]:
        event = json.loads(line)
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

    An absent integrity object verifies false; a present non-object
    or an unknown integrity field or kind raises, mirroring the Rust
    snapshot path. A well-formed seal that mismatches the bytes
    verifies false. Every line ends in a newline and carries its
    position as its sequence number; violations raise.
    """
    for position, line in enumerate(snapshot["event_lines"]):
        if not line.endswith("\n"):
            raise ValueError("line %d lacks trailing newline" % position)
        if json.loads(line).get("seq") != str(position):
            raise ValueError("line %d sequence mismatch" % position)
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
    return True


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
    """A rule is satisfied only by sealed, settled, complete evidence."""
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
                    "cross_epoch_evidence.json", "missing_terminal.json")
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
