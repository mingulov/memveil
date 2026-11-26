#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline egress-context checks: fixtures plus an independent oracle.

Static checks over ``fixtures/context/*.json``: every family
fixture parses, carries the expected format marker, stays inside
the frozen exposure catalog vocabularies, and matches the oracle
below, which re-derives timed typed control facts and explicit
resample gaps from the fixture inputs by hand-written rules. The
Rust reader (``src/analysis/exposure_context.rs``) implements the
same contract; this file never runs it.

Hard refusals: no fixture carries a full command, an
environment, a log, or a payload; encryption state is reported
only from an explicit field, never inferred from a name; and no
fact claims information left the guest.

Run directly: `python3 -m pytest tests/exposure/test_context.py -q`.
"""

import json
import os

import pytest

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "context")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")
MODEL = os.path.join(ROOT, "src", "analysis", "exposure_context.rs")

FORMAT = "exposure-context-fixture/0.1.0"
SOURCE_ID = "egress-controls"
CAPABILITY = "exposure-context"

FAMILIES = (
    "swap-encrypted.json",
    "swap-mixed-unresolved.json",
    "zram-writeback-zswap.json",
    "transient-changes.json",
    "denied-unknown-mode.json",
)

CONTROLS = (
    "swap", "dump", "hibernation", "module",
    "channel", "nic", "device",
)

DETAIL_KEYS = (
    "backing", "encryption", "path_state", "mode",
    "channel", "name", "writeback",
)

# Tokens no context fixture may carry: commands,
# environments, logs, payloads, or movement claims.
FIXTURE_ABSENT = (
    "command", "environ", "log", "payload", "content",
    "exfil", "escaped", "leaked", "movement", "dev/mem",
    "kcore", "/proc/",
)

# Tokens the reader's refusal list must name.
SOURCE_REFUSAL_PRESENT = (
    "command", "environment", "payload", "exfil",
)

# Inference wording the reader must never contain: it emits
# bounded control facts only.
SOURCE_ABSENT = (
    "escaped", "leaked", "read detected", "no sharing",
    "left the guest",
)

# The reader takes fixture text and performs no I/O.
SOURCE_NO_IO = (
    "std::fs", "std::process", "std::net", "std::env", "std::io",
)

SAMPLE_REQUIRED = (
    "sample_id", "tick", "control", "native_result", "detail",
)

STATUS = {0: "observed", -13: "denied", -22: "unsupported"}


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        return json.load(handle)


def catalog():
    with open(CATALOG, encoding="utf-8") as handle:
        return json.load(handle)


def oracle(document):
    """Re-derive facts, gaps and refusal count by hand rules."""
    assert document["format"] == FORMAT
    assert document["source_id"] == SOURCE_ID
    frozen = catalog()["vocabularies"]["frozen"]
    assert document["clock_domain"] in frozen["clock_domains"]
    interval = document["resample"]["interval_ticks"]
    assert isinstance(interval, int) and interval > 0
    facts = []
    refused = 0
    ticks = []
    seen = set()
    for sample in document["samples"]:
        for key in SAMPLE_REQUIRED:
            assert key in sample, sample
        assert sample["sample_id"] not in seen, sample["sample_id"]
        seen.add(sample["sample_id"])
        usable = (
            sample["control"] in CONTROLS
            and sample["native_result"] in STATUS
            and isinstance(sample["tick"], int)
            and sample["tick"] >= 0
            and all(key in DETAIL_KEYS
                    for key in sample["detail"])
        )
        if not usable:
            refused += 1
            continue
        ticks.append(sample["tick"])
        detail = sample["detail"]
        denied = sample["native_result"] == -13
        fact = {
            "evidence_id": "%s:%s" % (
                document["capture_id"], sample["sample_id"]),
            "tick": sample["tick"],
            "control": sample["control"],
            "status": STATUS[sample["native_result"]],
        }
        for key in DETAIL_KEYS:
            if denied:
                fact[key] = None
            elif key == "encryption":
                # Explicit field only: a suggestive name
                # never implies an encryption state.
                fact[key] = detail.get(key, "unknown")
            else:
                fact[key] = detail.get(key)
        facts.append(fact)
    gaps = []
    for before, after in zip(sorted(ticks), sorted(ticks)[1:]):
        if after - before > interval:
            gaps.append({"from_tick": before, "to_tick": after,
                         "ticks": after - before})
    return facts, gaps, refused


def test_all_families_present_and_shaped():
    assert sorted(os.listdir(FIX)) == sorted(FAMILIES)
    for name in FAMILIES:
        document = load(name)
        assert list(document.keys()) == [
            "format", "provenance", "capture_id", "source_id",
            "clock_domain", "resample", "samples", "expected",
        ], name
        assert document["format"] == FORMAT, name
        assert document["source_id"] == SOURCE_ID, name
        assert list(document["resample"].keys()) == [
            "interval_ticks"], name
        assert list(document["expected"].keys()) == [
            "facts", "gaps", "refused_samples"], name
        for fact in document["expected"]["facts"]:
            assert list(fact.keys()) == [
                "evidence_id", "tick", "control", "status",
            ] + list(DETAIL_KEYS), name


def test_oracle_matches_hand_written_expectations():
    for name in FAMILIES:
        document = load(name)
        facts, gaps, refused = oracle(document)
        expected = document["expected"]
        assert facts == expected["facts"], name
        assert gaps == expected["gaps"], name
        assert refused == expected["refused_samples"], name


def test_oracle_is_deterministic_and_sidecar_free():
    before = sorted(os.listdir(FIX))
    first = [oracle(load(name)) for name in FAMILIES]
    second = [oracle(load(name)) for name in FAMILIES]
    assert first == second, "pure oracle repeats exactly"
    assert sorted(os.listdir(FIX)) == before, "no sidecars appear"


def test_source_and_clock_stay_in_catalog():
    sources = [entry["source_id"]
               for entry in catalog()["sources"]]
    assert SOURCE_ID in sources
    caps = [entry["id"] for entry in catalog()["capabilities"]]
    assert CAPABILITY in caps


def test_resolved_paths_stay_distinct_from_unknown():
    document = load("swap-mixed-unresolved.json")
    facts, _, refused = oracle(document)
    assert refused == 0
    by_state = {}
    for fact in facts:
        by_state.setdefault(
            (fact["encryption"], fact["path_state"]),
            []).append(fact["evidence_id"])
    assert ("mixed", "resolved") in by_state
    assert ("unresolved", "unresolved") in by_state
    assert ("unknown", "unresolved") in by_state


def test_encryption_never_inferred_from_name():
    document = load("swap-mixed-unresolved.json")
    named = [sample for sample in document["samples"]
             if sample["detail"].get("name") == "cryptswap0"]
    assert len(named) == 1
    assert "encryption" not in named[0]["detail"]
    facts, _, _ = oracle(document)
    match = [fact for fact in facts
             if fact["name"] == "cryptswap0"]
    assert len(match) == 1
    assert match[0]["encryption"] == "unknown"
    plain = load("swap-encrypted.json")
    for fact in oracle(plain)[0]:
        if fact["encryption"] == "encrypted":
            sample = [item for item in plain["samples"]
                      if fact["evidence_id"].endswith(
                          item["sample_id"])][0]
            assert sample["detail"]["encryption"] == "encrypted"


def test_gaps_are_explicit_and_bounded():
    document = load("zram-writeback-zswap.json")
    facts, gaps, refused = oracle(document)
    assert refused == 0
    assert len(facts) == 3
    assert gaps == [{"from_tick": 5, "to_tick": 50, "ticks": 45}]
    assert load("swap-encrypted.json")["expected"]["gaps"] == []


def test_transient_changes_yield_independent_facts():
    document = load("transient-changes.json")
    facts, _, refused = oracle(document)
    assert refused == 0
    assert len(facts) == len(document["samples"])
    modes = [fact["mode"] for fact in facts
             if fact["control"] == "module"]
    assert modes == ["strict", "permissive", "strict"]
    assert len({fact["tick"] for fact in facts}) == len(facts)


def test_denied_drops_detail_and_unknown_refuses():
    document = load("denied-unknown-mode.json")
    facts, _, refused = oracle(document)
    assert refused == 1, "unknown control refuses"
    denied = [fact for fact in facts
              if fact["status"] == "denied"]
    assert len(denied) == 1
    for key in DETAIL_KEYS:
        assert denied[0][key] is None
    unknown = [fact for fact in facts
               if fact["control"] == "device"]
    assert len(unknown) == 1
    assert unknown[0]["mode"] == "unknown"
    assert unknown[0]["status"] == "observed"


def test_fixtures_carry_no_forbidden_source():
    for name in FAMILIES:
        with open(os.path.join(FIX, name),
                  encoding="utf-8") as handle:
            text = handle.read()
        for token in FIXTURE_ABSENT:
            assert token not in text, (name, token)


def test_reader_source_refuses_and_stays_offline():
    with open(MODEL, encoding="utf-8") as handle:
        text = handle.read()
    for token in SOURCE_REFUSAL_PRESENT:
        assert token in text, token
    for token in SOURCE_ABSENT + SOURCE_NO_IO:
        assert token not in text, token


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
