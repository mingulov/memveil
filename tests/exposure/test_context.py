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
import re

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
    "two-control-gaps.json",
)

CONTROLS = (
    "swap", "dump", "hibernation", "module",
    "channel", "nic", "device",
)

DETAIL_KEYS = (
    "backing", "encryption", "path_state", "mode",
    "channel", "name", "writeback",
)

# Closed detail vocabularies, mirroring the reader: an
# unknown value refuses its sample without guessing.
VOCABULARIES = {
    "encryption": ("encrypted", "mixed", "unresolved", "unknown"),
    "mode": ("strict", "permissive", "unknown"),
    "backing": ("partition", "file", "zram", "zswap"),
}

# Token grammar for every carried identifier and label,
# mirroring the reader: lowercase letters, digits,
# hyphens, and underscores, bounded length.
TOKEN = re.compile(r"\A[a-z0-9_-]{1,64}\Z")

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

# The capture identifier itself is scanned: a poisoned
# top-level capture refuses before entering any evidence handle.
SOURCE_CAPTURE_REFUSAL = '"capture_id", "forbidden value refused"'

# Capture values the oracle and the reader must both refuse.
POISONED_CAPTURES = ("/dev/mem", "/proc/kcore", "kcore-view-1")

# Capture values outside the token grammar, refused even
# though no refusal-list fragment matches them.
GRAMMAR_POISONS = (
    "/dev//mem", "/dev/./mem", "/dev/kmem", "/proc",
    "proc/self/mem", "UPPER", "has space", "a=b",
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
    for token in ("dev/mem", "kcore", "/proc/", "exfil"):
        assert token not in document["capture_id"], \
            document["capture_id"]
    assert TOKEN.match(document["capture_id"]), \
        document["capture_id"]
    frozen = catalog()["vocabularies"]["frozen"]
    assert document["clock_domain"] in frozen["clock_domains"]
    interval = document["resample"]["interval_ticks"]
    assert isinstance(interval, int) and interval > 0
    facts = []
    refused = 0
    by_control = {}
    seen = set()
    for sample in document["samples"]:
        for key in SAMPLE_REQUIRED:
            assert key in sample, sample
        assert sample["sample_id"] not in seen, sample["sample_id"]
        seen.add(sample["sample_id"])
        assert TOKEN.match(sample["sample_id"]), sample
        for value in sample["detail"].values():
            assert isinstance(value, str) and TOKEN.match(value), \
                sample
        usable = (
            sample["control"] in CONTROLS
            and sample["native_result"] in STATUS
            and isinstance(sample["tick"], int)
            and sample["tick"] >= 0
            and all(key in DETAIL_KEYS
                    for key in sample["detail"])
            and all(sample["detail"][key] in vocabulary
                    for key, vocabulary in VOCABULARIES.items()
                    if key in sample["detail"])
        )
        if not usable:
            refused += 1
            continue
        by_control.setdefault(sample["control"], []).append(
            sample["tick"])
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
    for control in sorted(by_control):
        ordered = sorted(by_control[control])
        for before, after in zip(ordered, ordered[1:]):
            if after - before > interval:
                gaps.append({"from_tick": before, "to_tick": after,
                             "ticks": after - before})
    gaps.sort(key=lambda gap: (gap["from_tick"], gap["to_tick"]))
    merged = [gap for index, gap in enumerate(gaps)
              if index == 0 or gap != gaps[index - 1]]
    return facts, merged, refused


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


def test_gaps_are_per_control():
    document = load("two-control-gaps.json")
    facts, gaps, refused = oracle(document)
    assert refused == 0
    assert len(facts) == 5
    assert gaps == [{"from_tick": 0, "to_tick": 40, "ticks": 40}], \
        "module ticks between swap ticks never fill the swap gap"


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


def test_poisoned_capture_id_refuses():
    for poison in POISONED_CAPTURES:
        document = load("swap-encrypted.json")
        document["capture_id"] = poison
        with pytest.raises(AssertionError):
            oracle(document)


def test_grammar_poison_capture_id_refuses():
    for poison in GRAMMAR_POISONS:
        for fragment in ("dev/mem", "kcore", "/proc/", "exfil"):
            assert fragment not in poison, poison
        document = load("swap-encrypted.json")
        document["capture_id"] = poison
        with pytest.raises(AssertionError):
            oracle(document)


def test_detail_values_stay_in_vocabulary():
    for name in FAMILIES:
        for sample in load(name)["samples"]:
            for key, vocabulary in VOCABULARIES.items():
                if key in sample["detail"]:
                    assert sample["detail"][key] in vocabulary, \
                        (name, sample)


def test_reader_source_refuses_and_stays_offline():
    with open(MODEL, encoding="utf-8") as handle:
        text = handle.read()
    for token in SOURCE_REFUSAL_PRESENT:
        assert token in text, token
    assert SOURCE_CAPTURE_REFUSAL in text
    for marker in ("value outside token grammar", "KNOWN_ENCRYPTION",
                   "KNOWN_MODES", "KNOWN_BACKING"):
        assert marker in text, marker
    for token in SOURCE_ABSENT + SOURCE_NO_IO:
        assert token not in text, token


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
