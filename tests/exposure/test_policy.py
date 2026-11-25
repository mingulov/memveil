#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline policy artifact checks: fixtures, goldens, and worked examples.

Static checks only: every fixture and golden parses, the
goldens cover all five policy outcomes with exits that match
the frozen exposure catalog, the policy corpus stays within
the documented bounds, the worked examples each declare
exact platform/workload prerequisites with expected
findings, and no artifact carries a host-read, payload, or
safety claim. The Rust integration suite
(`tests/exposure_policy.rs`) executes the reader and the
evaluator; this file never runs them.

Run directly: `python3 -m pytest tests/exposure/test_policy.py -q`.
"""

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "policy")
EX = os.path.join(ROOT, "examples", "policies")
CATALOG = os.path.join(
    ROOT, "profiles", "exposure", "catalog.json")
MODEL = os.path.join(
    ROOT, "src", "analysis", "exposure_policy.rs")

POLICY_RESULTS = (
    "conforms", "deviates_known", "violates",
    "inconclusive", "unavailable",
)

# Claim-discipline phrases: no host-read, payload, or
# safety wording may appear in a lane artifact. Matched
# case-insensitively on word boundaries so frozen labels
# such as `host-device` stay usable.
FORBIDDEN = (
    "host read", "host-read", "host access", "host-access",
    "secure", "attack", "malicious", "content", "payload",
    "verdict", "safe", "safety", "exploit", "vulnerab",
    "threat", "compromis", "confidential", "escape",
    "no sharing", "read detected",
)

TOP_REQUIRED = (
    "schema", "schema_version", "policy_id",
    "subject_scope", "applies_to", "required_sources",
    "clock", "rules", "exceptions",
)

RESULT_FIELDS = (
    "rule_id", "scope_id", "result", "evidence_ids",
    "missing_sources", "exceptions_applied",
    "clock_domain", "reason",
)


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def fixture_files(suffix):
    return sorted(name for name in os.listdir(FIX)
                  if name.endswith(suffix))


def catalog():
    return load_json(CATALOG)


def catalog_vocab(name):
    return catalog()["vocabularies"]["frozen"][name]


def test_fixtures_present():
    assert os.path.isdir(FIX), "missing %s" % FIX
    policies = fixture_files(".policy.json")
    inputs = fixture_files(".input.json")
    expected = fixture_files(".expected.json")
    assert policies, "no policy corpus files"
    assert inputs, "no input bundles"
    assert len(expected) >= 5, \
        "need goldens for all five outcomes, have %d" % len(expected)
    for name in expected:
        gold = load_json(os.path.join(FIX, name))
        for key in ("policy", "input"):
            sibling = os.path.join(FIX, gold[key])
            assert os.path.isfile(sibling), \
                "%s names missing %s" % (name, gold[key])


def test_fixture_json_wellformed():
    for name in sorted(os.listdir(FIX)):
        if not name.endswith(".json"):
            continue
        load_json(os.path.join(FIX, name))


def check_dup_keys(text):
    found = []

    def hook(pairs):
        seen = set()
        for key, _ in pairs:
            if key in seen:
                found.append(key)
            seen.add(key)
        return dict(pairs)

    json.loads(text, object_pairs_hook=hook)
    return found


def canonical_u64(raw):
    if not isinstance(raw, str) or not raw:
        return False
    if len(raw) > 1 and raw.startswith("0"):
        return False
    if not raw.isdigit() or not raw.isascii():
        return False
    return int(raw) <= 18446744073709551615


def static_defects(name, doc, text):
    """Bounds/shape defects a reader must refuse.

    Mirrors the documented file bounds (1 MiB, 1,024
    rules, 64 exceptions per rule, 64-char ASCII ids)
    plus duplicate keys, empty-scope shapes, dangling
    references, and non-canonical integers.
    """
    defects = []
    if len(text.encode("utf-8")) > 1024 * 1024:
        defects.append("over-1mib")
    if check_dup_keys(text):
        defects.append("duplicate-key")
    for key in TOP_REQUIRED:
        if key not in doc:
            defects.append("missing-%s" % key)
    if doc.get("schema") != "policy":
        defects.append("bad-schema")
    if doc.get("schema_version") != "0.1.0":
        defects.append("bad-schema-version")
    for key in ("policy_id", "subject_scope"):
        value = doc.get(key, "")
        if not value:
            defects.append("empty-%s" % key)
    if not doc.get("required_sources"):
        defects.append("empty-required-sources")
    if not doc.get("rules"):
        defects.append("empty-rules")
    if len(doc.get("rules", [])) > 1024:
        defects.append("too-many-rules")
    per_rule = {}
    for exc in doc.get("exceptions", []):
        rid = exc.get("rule_id", "")
        per_rule[rid] = per_rule.get(rid, 0) + 1
    if any(count > 64 for count in per_rule.values()):
        defects.append("too-many-exceptions")
    ids = [doc.get("policy_id", ""), doc.get("subject_scope", "")]
    ids += [rule.get("rule_id", "")
            for rule in doc.get("rules", [])]
    ids += [exc.get("exception_id", "")
            for exc in doc.get("exceptions", [])]
    for value in ids:
        if len(value) > 64 or not value.isascii():
            defects.append("bad-id")
            break
    rule_ids = [rule.get("rule_id", "")
                for rule in doc.get("rules", [])]
    if len(set(rule_ids)) != len(rule_ids):
        defects.append("duplicate-rule")
    exc_ids = [exc.get("exception_id", "")
               for exc in doc.get("exceptions", [])]
    if len(set(exc_ids)) != len(exc_ids):
        defects.append("duplicate-exception")
    for rule in doc.get("rules", []):
        if not rule.get("selector"):
            defects.append("empty-selector")
        if rule.get("permitted") != "allowlisted-only":
            defects.append("unknown-permitted")
        limit = rule.get("limit", {})
        if limit.get("window") != "capture":
            defects.append("unknown-window")
        if not canonical_u64(limit.get("max", "")):
            defects.append("bad-integer")
    for exc in doc.get("exceptions", []):
        if exc.get("rule_id") not in rule_ids:
            defects.append("dangling-exception")
    return defects


def test_policy_corpus_bounds():
    for name in fixture_files(".policy.json"):
        path = os.path.join(FIX, name)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        defects = static_defects(name, json.loads(text), text)
        if name.startswith("refuse-"):
            assert defects, \
                "%s must carry a refusal defect" % name
        elif name.startswith("ok-"):
            assert not defects, \
                "%s must be defect-free: %s" % (name, defects)
        else:
            raise AssertionError(
                "corpus name must start with ok- or refuse-: %s"
                % name)


def test_input_shape():
    for name in fixture_files(".input.json"):
        doc = load_json(os.path.join(FIX, name))
        for key in ("scope_id", "capture_id", "finalized",
                    "available_sources", "facts", "objects"):
            assert key in doc, "%s lacks %s" % (name, key)
        assert isinstance(doc["finalized"], bool), name
        assert isinstance(doc["available_sources"], list), name
        for fact in doc["facts"]:
            for key in ("evidence_id", "capture_id",
                        "source_id", "semantics",
                        "peer_class", "clock_domain"):
                assert key in fact, \
                    "%s fact lacks %s" % (name, key)
        for obj in doc["objects"]:
            for key in ("object_token", "generation",
                        "capture_id", "object_class",
                        "origin_source", "lifecycle_status"):
                assert key in obj, \
                    "%s object lacks %s" % (name, key)


def test_single_capture_inputs():
    for name in fixture_files(".input.json"):
        doc = load_json(os.path.join(FIX, name))
        want = doc["capture_id"]
        records = list(doc["facts"]) + list(doc["objects"])
        for record in records:
            assert record["capture_id"] == want, \
                "%s mixes captures; cross-capture opaque-id " \
                "equality is refused" % name


def test_golden_shape():
    vocab = catalog_vocab("policy_result")
    assert sorted(vocab) == sorted(POLICY_RESULTS), vocab
    for name in fixture_files(".expected.json"):
        gold = load_json(os.path.join(FIX, name))
        assert gold["strict_exit"] in (0, 4, 5), name
        assert gold["results"], "%s has no results" % name
        for entry in gold["results"]:
            assert tuple(sorted(entry)) == \
                tuple(sorted(RESULT_FIELDS)), \
                "%s result keys %s" % (name, sorted(entry))
            assert entry["result"] in vocab, \
                "%s result %r outside frozen vocab" % (
                    name, entry["result"])
            assert "next:" in entry["reason"], \
                "%s reason lacks a next investigation" % name


def worst(results):
    order = {"conforms": 0, "deviates_known": 1,
             "inconclusive": 2, "unavailable": 2,
             "violates": 3}
    return max(order[entry["result"]] for entry in results)


def test_golden_coverage():
    seen = set()
    for name in fixture_files(".expected.json"):
        gold = load_json(os.path.join(FIX, name))
        for entry in gold["results"]:
            seen.add(entry["result"])
    assert seen == set(POLICY_RESULTS), \
        "goldens miss %s" % (set(POLICY_RESULTS) - seen)


def test_golden_exits_consistent():
    for name in fixture_files(".expected.json"):
        gold = load_json(os.path.join(FIX, name))
        level = worst(gold["results"])
        want = {0: 0, 1: 0, 2: 4, 3: 5}[level]
        assert gold["strict_exit"] == want, \
            "%s exit %d, want %d" % (
                name, gold["strict_exit"], want)


def test_golden_conforms_needs_complete():
    for name in fixture_files(".expected.json"):
        gold = load_json(os.path.join(FIX, name))
        if not any(entry["result"] == "conforms"
                   for entry in gold["results"]):
            continue
        policy = load_json(os.path.join(FIX, gold["policy"]))
        bundle = load_json(os.path.join(FIX, gold["input"]))
        assert bundle["finalized"], \
            "%s conforms on an unfinalized capture" % name
        missing = set(policy["required_sources"]) - \
            set(bundle["available_sources"])
        assert not missing, \
            "%s conforms with %s absent" % (name, missing)


def rust_string_list(text, name):
    match = re.search(
        r"pub const %s: &\[&str\]\s*=\s*&\s*\[(.*?)\];" % name,
        text, re.S)
    assert match, "model lacks %s" % name
    return re.findall(r'"([^"]*)"', match.group(1))


def test_model_lists_match_catalog():
    """Transcribed frozen lists cannot drift from the catalog."""
    with open(MODEL, encoding="utf-8") as handle:
        text = handle.read()
    assert catalog()["exposure_catalog_version"] == "0.1.0"
    assert sorted(rust_string_list(text, "KNOWN_SEMANTICS")) == \
        sorted(catalog_vocab("semantics"))
    assert sorted(rust_string_list(text, "KNOWN_PEER_CLASSES")) == \
        sorted(catalog_vocab("peer_classes"))
    assert sorted(rust_string_list(text, "KNOWN_CLOCK_DOMAINS")) == \
        sorted(catalog_vocab("clock_domains"))
    assert sorted(rust_string_list(text, "KNOWN_OBJECT_CLASSES")) == \
        sorted(catalog_vocab("object_classes"))
    assert sorted(rust_string_list(
        text, "KNOWN_LIFECYCLE_STATUSES")) == \
        sorted(catalog_vocab("lifecycle_statuses"))
    assert sorted(rust_string_list(text, "KNOWN_POLICY_RESULTS")) == \
        sorted(catalog_vocab("policy_result"))
    assert sorted(rust_string_list(text, "KNOWN_CAPABILITIES")) == \
        sorted(entry["id"] for entry in catalog()["capabilities"])
    assert sorted(rust_string_list(text, "KNOWN_SOURCES")) == \
        sorted(entry["source_id"]
               for entry in catalog()["sources"])


def test_examples():
    assert os.path.isdir(EX), "missing %s" % EX
    cells = set(entry["cell"] for entry in catalog()["platforms"])
    names = ("closed-scope.json", "lifecycle-boundary.json",
             "config-deviation.json")
    for name in names:
        doc = load_json(os.path.join(EX, name))
        assert not static_defects(name, doc, json.dumps(doc)), \
            "%s must be a defect-free policy" % name
        prereq = doc.get("prerequisites", {})
        assert prereq.get("platform_cell") in cells, \
            "%s names no exact catalog cell" % name
        assert prereq.get("workload"), \
            "%s lacks a workload prerequisite" % name
        assert doc.get("expected_findings"), \
            "%s lacks expected findings" % name
    readme = os.path.join(EX, "README.md")
    assert os.path.isfile(readme), "missing policies README"
    text = open(readme, encoding="utf-8").read()
    for name in names:
        assert name in text, "README omits %s" % name
    assert text.count("prerequisite") >= 3, \
        "README must state prerequisites per example"
    assert text.count("expected finding") >= 3, \
        "README must state expected findings per example"


def test_claim_discipline():
    hits = []
    for base in (FIX, EX):
        for name in sorted(os.listdir(base)):
            path = os.path.join(base, name)
            if not os.path.isfile(path):
                continue
            text = open(path, encoding="utf-8").read()
            for phrase in FORBIDDEN:
                if re.search(r"\b%s\b" % re.escape(phrase),
                             text, re.I):
                    hits.append("%s: %r" % (name, phrase))
    assert not hits, "; ".join(hits)
