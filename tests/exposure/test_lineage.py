#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline exposure lineage checks: golden ledgers pin the identity contract.

Static checks only: every synthetic ledger under
`tests/exposure/fixtures/lineage/` parses, each ledger has
a hand-computed `.expected.json` golden, and the goldens
satisfy the lineage contract directly (reused addresses get
a new generation, aliases share one identity, ambiguous or
failed joins keep UNKNOWN state, quarantine and capture end
never act as reuse or teardown, clock/suspend/loss gaps
bound or void the affected claims). The Rust integration
suite (`tests/exposure_lineage.rs`) executes the replay
module against the same ledgers; this file never runs it,
so the two sides pin each other: Python pins
goldens-to-contract, Rust pins module-to-goldens.

Run directly: `python3 -m pytest tests/exposure/test_lineage.py -q`.
"""

import json
import os
import re

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "lineage")
MODEL = os.path.join(
    ROOT, "src", "analysis", "exposure_lineage.rs")
RUST_TEST = os.path.join(ROOT, "tests", "exposure_lineage.rs")
CATALOG = os.path.join(
    ROOT, "profiles", "exposure", "catalog.json")

CASES = (
    "reuse", "alias", "revert", "quarantine", "capture-end",
    "clock", "suspend", "loss", "overlap", "atom",
    "overflow", "bounds", "baseline",
)

STATUSES = ("created", "live", "released", "quarantined", "unknown")
CERTAINTY = ("known", "bounded", "unknown")

# Claim-discipline substrings: no lane artifact may carry a
# byte-total-from-virtual-ids claim, a host-read claim, or a
# safety/reading claim. Matched case-insensitively.
FORBIDDEN_SUB = (
    "physical", "phys_", "byte total", "bytes total",
    "total bytes", "payload", "host read", "host-read",
    "host access", "host-access", "no sharing", "read detected",
    "exploit", "vulnerab", "malicious", "compromis",
)
FORBIDDEN_WORD = (
    "secure", "attack", "verdict", "safety",
)


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def ledger(name):
    return load_json(os.path.join(FIX, name + ".ledger.json"))


def expected(name):
    return load_json(os.path.join(FIX, name + ".expected.json"))


def resolved_map(gold):
    return {row["row_id"]: row for row in gold["resolved"]}


def object_map(gold):
    found = {}
    for obj in gold["objects"]:
        found.setdefault((obj["token"], obj["generation"]), []).append(obj)
    return found


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


def test_fixtures_present():
    assert os.path.isdir(FIX), "missing %s" % FIX
    for name in CASES:
        led = os.path.join(FIX, name + ".ledger.json")
        gold = os.path.join(FIX, name + ".expected.json")
        assert os.path.isfile(led), "missing ledger %s" % led
        assert os.path.isfile(gold), "missing golden %s" % gold
        assert expected(name)["ledger"] == name + ".ledger.json", \
            "golden %s names the wrong ledger" % gold
        assert ledger(name)["case"] == name, \
            "ledger %s carries the wrong case id" % led


def test_fixture_json_wellformed():
    for name in sorted(os.listdir(FIX)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(FIX, name)
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        json.loads(text)
        assert check_dup_keys(text) == [], \
            "duplicate keys in %s" % name


def test_vocab_pinned_to_catalog():
    catalog = load_json(CATALOG)
    assert catalog["exposure_catalog_version"] == "0.1.1"
    frozen = catalog["vocabularies"]["frozen"]
    with open(MODEL, encoding="utf-8") as handle:
        model = handle.read()
    assert "0.1.1" in model, "model must cite the frozen catalog version"
    for vocab in ("lifecycle_statuses", "object_classes", "clock_domains"):
        for label in frozen[vocab]:
            assert label in model, \
                "frozen %s label %r missing from the model" % (vocab, label)
    sources = catalog["sources"]
    if isinstance(sources, dict):
        source_ids = set(sources.keys())
    else:
        source_ids = {entry["source_id"] for entry in sources}
    for name in CASES:
        for row in ledger(name)["rows"]:
            assert row["object_class"] in frozen["object_classes"], name
            assert row["clock_domain"] in frozen["clock_domains"], name
            assert row["source_id"] in source_ids, name
        for row in expected(name)["resolved"]:
            assert row["status"] in STATUSES, name
            assert row["certainty"] in CERTAINTY, name


def test_no_byte_totals_or_claims():
    paths = [MODEL, RUST_TEST, os.path.abspath(__file__)]
    paths.extend(os.path.join(FIX, name)
                 for name in sorted(os.listdir(FIX))
                 if name.endswith(".json"))
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
        lowered = text.lower()
        for phrase in FORBIDDEN_SUB:
            assert phrase not in lowered, \
                "%s carries forbidden %r" % (path, phrase)
        for word in FORBIDDEN_WORD:
            assert re.search(r"\b%s\b" % word, lowered) is None, \
                "%s carries forbidden %r" % (path, word)


def test_rust_suite_covers_every_case():
    with open(RUST_TEST, encoding="utf-8") as handle:
        text = handle.read()
    for name in CASES:
        assert '"%s"' % name in text, \
            "Rust suite never replays case %s" % name


def test_failed_joins_never_resolve_identity():
    for name in CASES:
        gold = expected(name)
        rows = resolved_map(gold)
        for row_id in gold["failed_joins"]:
            row = rows[row_id]
            assert row["identity"] is None, (name, row_id)
            assert row["status"] == "unknown", (name, row_id)
            assert row["certainty"] == "unknown", (name, row_id)


def test_counts_exclude_aliases_and_samples():
    for name in CASES:
        gold = expected(name)
        linked = [obj for obj in gold["objects"] if obj["linked"]]
        samples = [obj for obj in gold["objects"] if not obj["linked"]]
        assert gold["distinct_known_objects"] == len(linked), name
        assert gold["unlinked_samples"] == len(samples), name
        for obj in samples:
            assert obj["generation"] == 0, (name, obj)
            assert obj["status"] == "unknown", (name, obj)
            assert obj["certainty"] == "unknown", (name, obj)


def test_reused_address_is_new_generation():
    gold = expected("reuse")
    rows = resolved_map(gold)
    assert rows["r1"]["identity"] == ["tok-a", 1]
    assert rows["r3"]["identity"] == ["tok-a", 1]
    assert rows["r3"]["status"] == "released"
    assert rows["r4"]["identity"] == ["tok-a", 2]
    assert rows["r4"]["status"] == "created"
    assert rows["r5"]["identity"] == ["tok-a", 2]
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "released"
    assert objs[("tok-a", 2)][0]["status"] == "live"
    assert gold["distinct_known_objects"] == 2
    assert gold["failed_joins"] == []
    assert gold["refused_cross_capture"] == 1


def test_alias_not_double_counted():
    gold = expected("alias")
    rows = resolved_map(gold)
    assert rows["a2"]["identity"] == ["tok-a", 1]
    assert rows["a3"]["identity"] == ["tok-a", 1]
    assert rows["a3"]["status"] == "live"
    assert rows["a4"]["identity"] == ["tok-a", 1]
    assert gold["distinct_known_objects"] == 1
    assert len(gold["objects"]) == 1
    assert gold["objects"][0]["evidence"] == ["a1", "a3", "a4"]
    assert gold["failed_joins"] == []


def test_failed_revert_keeps_unknown_state():
    gold = expected("revert")
    rows = resolved_map(gold)
    assert rows["v3"]["identity"] == ["tok-a", 1]
    assert rows["v3"]["status"] == "unknown"
    assert rows["v3"]["certainty"] == "unknown"
    assert rows["v4"]["identity"] is None
    assert rows["v4"]["status"] == "unknown"
    assert gold["failed_joins"] == ["v4"]
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "unknown"
    assert objs[("tok-a", 1)][0]["certainty"] == "unknown"
    assert gold["unlinked_samples"] == 1
    assert gold["distinct_known_objects"] == 1


def test_quarantine_is_not_reuse():
    gold = expected("quarantine")
    rows = resolved_map(gold)
    assert rows["q2"]["identity"] == ["tok-a", 1]
    assert rows["q2"]["status"] == "quarantined"
    assert rows["q3"]["identity"] == ["tok-a", 2]
    assert rows["q3"]["status"] == "created"
    assert rows["q4"]["identity"] == ["tok-a", 2]
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "quarantined"
    assert objs[("tok-a", 2)][0]["status"] == "live"
    assert gold["distinct_known_objects"] == 2
    assert gold["failed_joins"] == []


def test_capture_end_is_not_teardown():
    gold = expected("capture-end")
    rows = resolved_map(gold)
    assert rows["e3"]["identity"] == ["tok-a", 1]
    assert rows["e3"]["status"] == "live"
    assert "not teardown" in rows["e3"]["note_contains"]
    assert rows["e4"]["identity"] is None
    assert rows["e4"]["status"] == "unknown"
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "live"
    assert objs[("tok-a", 1)][0]["evidence"] == ["e1", "e2"]
    assert gold["failed_joins"] == []


def test_clock_change_bounds_temporal_claims():
    gold = expected("clock")
    rows = resolved_map(gold)
    assert rows["c2"]["certainty"] == "known"
    assert rows["c3"]["identity"] == ["tok-a", 1]
    assert rows["c3"]["certainty"] == "bounded"
    assert rows["c4"]["identity"] == ["tok-a", 1]
    assert rows["c4"]["certainty"] == "bounded"
    assert rows["c5"]["status"] == "released"
    assert rows["c5"]["certainty"] == "bounded"
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["certainty"] == "bounded"
    assert gold["failed_joins"] == []


def test_suspend_gap_bounds_elapsed():
    gold = expected("suspend")
    rows = resolved_map(gold)
    assert rows["s3"]["identity"] == ["tok-a", 1]
    assert rows["s3"]["certainty"] == "bounded"
    assert "elapsed unknown" in rows["s3"]["note_contains"]
    assert rows["s4"]["identity"] == ["tok-a", 1]
    assert rows["s4"]["certainty"] == "bounded"
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["certainty"] == "bounded"
    assert gold["failed_joins"] == []


def test_loss_gap_keeps_samples_separate():
    gold = expected("loss")
    rows = resolved_map(gold)
    assert rows["l4"]["identity"] is None
    assert gold["failed_joins"] == ["l4"]
    assert rows["l5"]["identity"] == ["tok-a", 2]
    assert rows["l5"]["certainty"] == "known"
    assert rows["l6"]["identity"] == ["tok-a", 2]
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "live"
    assert ("tok-a", 0) in objs
    assert objs[("tok-a", 0)][0]["linked"] is False
    assert gold["unlinked_samples"] == 1
    assert gold["distinct_known_objects"] == 2


def test_ambiguous_join_fails_and_stays_unknown():
    gold = expected("overlap")
    rows = resolved_map(gold)
    assert rows["o3"]["identity"] is None
    assert rows["o4"]["identity"] is None
    assert gold["failed_joins"] == ["o3", "o4"]
    objs = object_map(gold)
    assert objs[("tok-a", 1)][0]["status"] == "created"
    assert objs[("tok-a", 2)][0]["status"] == "created"
    assert objs[("tok-a", 1)][0]["evidence"] == ["o1"]
    assert objs[("tok-a", 2)][0]["evidence"] == ["o2"]
    assert gold["duplicate_rows"] == ["o1"]
    assert gold["distinct_known_objects"] == 2


def test_atom_group_failure_stays_separate():
    gold = expected("atom")
    rows = resolved_map(gold)
    assert rows["t1"]["identity"] is None
    assert rows["t2"]["identity"] is None
    assert "not proved" in rows["t1"]["note_contains"]
    assert gold["failed_joins"] == ["t1", "t2"]
    assert rows["t3"]["identity"] == ["tok-a", 1]
    assert rows["t4"]["identity"] == ["tok-c", 1]
    assert rows["t5"]["identity"] == ["tok-c", 1]
    objs = object_map(gold)
    assert ("tok-b", 0) in objs
    assert gold["unlinked_samples"] == 1
    assert gold["distinct_known_objects"] == 2


def test_generation_overflow_refuses_reuse():
    led = ledger("overflow")
    assert led["config"]["max_generation"] == 2
    gold = expected("overflow")
    rows = resolved_map(gold)
    assert rows["f5"]["identity"] is None
    assert "overflow" in rows["f5"]["note_contains"]
    assert gold["failed_joins"] == ["f5", "f6"]
    assert gold["overflow_refusals"] == 1
    assert gold["distinct_known_objects"] == 2


def test_open_bound_refuses_new_identity():
    led = ledger("bounds")
    assert led["config"]["max_open_per_source"] == 1
    gold = expected("bounds")
    rows = resolved_map(gold)
    assert rows["b2"]["identity"] is None
    assert gold["failed_joins"] == ["b2"]
    assert gold["bound_refusals"] == 1
    assert rows["b4"]["identity"] == ["tok-b", 1]
    assert rows["b4"]["status"] == "created"
    assert gold["distinct_known_objects"] == 2


def test_baseline_reconciliation_is_explicit():
    led = ledger("baseline")
    assert len(led["baseline"]) == 3
    gold = expected("baseline")
    assert gold["failed_joins"] == []
    recon = gold["reconciliation"]
    assert recon["confirmed"] == ["tok-b#1"]
    assert recon["status_mismatch"] == ["tok-a#1"]
    assert recon["missing_observation"] == ["tok-c#2"]
    assert recon["unconfirmed_observed"] == ["tok-d#1"]
