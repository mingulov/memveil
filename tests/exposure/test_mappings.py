#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline mapping-inventory checks: fixtures plus an independent oracle.

Static checks over ``fixtures/mappings/*.json``: every family
fixture parses, carries the expected format marker, stays inside
the frozen exposure catalog vocabularies, and matches the oracle
below, which re-derives bounded mapping-class/peer/configuration
facts from the fixture inputs by hand-written rules. The Rust
reader (``src/analysis/exposure_mappings.rs``) implements the same
contract; this file never runs it.

Hard refusals: no fixture names a raw memory source, a payload,
an address, or a command; DAX access claims stay absent unless
separately proved; equal mapping-class names never imply equal
trust boundaries.

Run directly: `python3 -m pytest tests/exposure/test_mappings.py -q`.
"""

import json
import os
import re

import pytest

ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
FIX = os.path.join(ROOT, "tests", "exposure", "fixtures", "mappings")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")
MODEL = os.path.join(ROOT, "src", "analysis", "exposure_mappings.rs")

FORMAT = "mapping-inventory-fixture/0.1.0"
SOURCE_ID = "mapping-inventory-scan"
CAPABILITY = "mapping-inventory"

FAMILIES = (
    "mmio-supported.json",
    "dax-absent-unsupported.json",
    "alias-distinct-boundaries.json",
    "access-denied.json",
    "paravisor-private-mmio.json",
)

# Tokens no mapping fixture may carry: raw memory sources,
# payloads, addresses, or commands. `"address"` is quoted so
# the legitimate `address_namespace` key stays usable.
FIXTURE_ABSENT = (
    "dev/mem", "kcore", "/proc/", "payload", "content",
    '"address"', "phys_addr", "virt_addr", "command",
    "environ", "exfil", "escaped", "leaked",
)

# Tokens the reader's refusal list must name.
SOURCE_REFUSAL_PRESENT = (
    "dev/mem", "kcore", "payload", "command", "environment",
)

# Inference wording the reader must never contain: it emits
# bounded inventory facts only.
SOURCE_ABSENT = (
    "exfil", "escaped", "leaked", "read detected", "no sharing",
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

# Closed mapping-class vocabulary, mirroring the reader.
MAPPING_CLASSES = ("mmio", "dax")

# Token grammar for every carried identifier and label,
# mirroring the reader: lowercase letters, digits,
# hyphens, and underscores, bounded length.
TOKEN = re.compile(r"\A[a-z0-9_-]{1,64}\Z")

ENTRY_REQUIRED = (
    "entry_id", "mapping_class", "peer_class",
    "trust_boundary", "address_namespace", "native_result",
)

CONFIGURATION = {0: "present", -13: "denied", -22: "unsupported"}


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as handle:
        return json.load(handle)


def catalog():
    with open(CATALOG, encoding="utf-8") as handle:
        return json.load(handle)


def oracle(document):
    """Re-derive facts, DAX status and refusal count by hand rules."""
    assert document["format"] == FORMAT
    assert document["source_id"] == SOURCE_ID
    for token in ("dev/mem", "kcore", "/proc/"):
        assert token not in document["capture_id"], \
            document["capture_id"]
    assert TOKEN.match(document["capture_id"]), \
        document["capture_id"]
    facts = []
    refused = 0
    frozen = catalog()["vocabularies"]["frozen"]
    peers = frozen["peer_classes"]
    seen = set()
    for entry in document["entries"]:
        for key in ENTRY_REQUIRED:
            assert key in entry, entry
        assert entry["entry_id"] not in seen, entry["entry_id"]
        seen.add(entry["entry_id"])
        carried = [entry["entry_id"], entry["mapping_class"],
                   entry["peer_class"], entry["trust_boundary"],
                   entry["address_namespace"]]
        if "alias_of" in entry:
            carried.append(entry["alias_of"])
        for value in carried:
            assert isinstance(value, str) and TOKEN.match(value), \
                entry
        usable = (
            entry["peer_class"] in peers
            and entry["address_namespace"] == "guest_physical"
            and entry["mapping_class"] in MAPPING_CLASSES
            and bool(entry["trust_boundary"])
            and entry["native_result"] in CONFIGURATION
        )
        if not usable:
            refused += 1
            continue
        facts.append({
            "evidence_id": "%s:%s" % (
                document["capture_id"], entry["entry_id"]),
            "mapping_class": entry["mapping_class"],
            "peer_class": entry["peer_class"],
            "trust_boundary": entry["trust_boundary"],
            "configuration": CONFIGURATION[entry["native_result"]],
        })
    dax = document["dax"]
    assert dax["presence"] in ("present", "absent", "unknown")
    assert dax["support"] in ("supported", "unsupported", "unknown")
    # This slice carries no separate proof, so any positive
    # access attestation fails closed in the reader.
    assert dax["access_proved"] is False
    assert dax["access_claim"] is None
    return facts, dax, refused


def test_all_families_present_and_shaped():
    assert sorted(os.listdir(FIX)) == sorted(FAMILIES)
    for name in FAMILIES:
        document = load(name)
        assert list(document.keys()) == [
            "format", "provenance", "capture_id", "source_id",
            "entries", "dax", "expected",
        ], name
        assert document["format"] == FORMAT, name
        assert document["source_id"] == SOURCE_ID, name
        assert isinstance(document["entries"], list), name
        assert list(document["dax"].keys()) == [
            "presence", "support", "access_proved",
            "access_claim",
        ], name
        assert list(document["expected"].keys()) == [
            "facts", "dax_presence", "dax_support",
            "dax_access_claim", "refused_entries",
        ], name


def test_oracle_matches_hand_written_expectations():
    for name in FAMILIES:
        document = load(name)
        facts, dax, refused = oracle(document)
        expected = document["expected"]
        assert facts == expected["facts"], name
        assert dax["presence"] == expected["dax_presence"], name
        assert dax["support"] == expected["dax_support"], name
        assert dax["access_claim"] == \
            expected["dax_access_claim"], name
        assert refused == expected["refused_entries"], name


def test_oracle_is_deterministic_and_sidecar_free():
    before = sorted(os.listdir(FIX))
    first = [oracle(load(name)) for name in FAMILIES]
    second = [oracle(load(name)) for name in FAMILIES]
    assert first == second, "pure oracle repeats exactly"
    assert sorted(os.listdir(FIX)) == before, "no sidecars appear"


def test_source_and_peers_stay_in_catalog():
    frozen = catalog()["vocabularies"]["frozen"]
    sources = [entry["source_id"]
               for entry in catalog()["sources"]]
    assert SOURCE_ID in sources
    caps = [entry["id"] for entry in catalog()["capabilities"]]
    assert CAPABILITY in caps
    for name in FAMILIES:
        for entry in load(name)["entries"]:
            if entry["peer_class"] not in frozen["peer_classes"]:
                assert load(name)["expected"][
                    "refused_entries"] > 0, name


def test_equal_class_names_never_merge_boundaries():
    by_class = {}
    for name in FAMILIES:
        for fact in load(name)["expected"]["facts"]:
            by_class.setdefault(
                fact["mapping_class"], set()).add(
                    fact["trust_boundary"])
    assert len(by_class["mmio"]) >= 3, \
        "mmio spans guest, alias and paravisor boundaries"
    for name in FAMILIES:
        for fact in load(name)["expected"]["facts"]:
            assert fact["trust_boundary"], name


def test_alias_keeps_own_boundary():
    document = load("alias-distinct-boundaries.json")
    facts, _, refused = oracle(document)
    assert refused == 0
    assert len(facts) == 2
    assert facts[0]["mapping_class"] == facts[1]["mapping_class"]
    assert facts[0]["trust_boundary"] != facts[1]["trust_boundary"]
    assert facts[0]["evidence_id"] != facts[1]["evidence_id"]


def test_denied_and_refused_stay_visible():
    document = load("access-denied.json")
    facts, _, refused = oracle(document)
    assert refused == 1, "unknown peer refuses without guessing"
    denied = [fact for fact in facts
              if fact["configuration"] == "denied"]
    assert len(denied) == 1
    assert denied[0]["peer_class"] == "device"


def test_unsupported_dax_stays_visible_without_claim():
    for name in FAMILIES:
        expected = load(name)["expected"]
        assert expected["dax_access_claim"] is None, name
    document = load("dax-absent-unsupported.json")
    facts, dax, refused = oracle(document)
    assert refused == 0
    assert dax["presence"] == "absent"
    assert dax["support"] == "unsupported"
    assert len(facts) == 1
    assert facts[0]["configuration"] == "unsupported"
    assert facts[0]["mapping_class"] == "dax"


def test_fixtures_carry_no_forbidden_source():
    for name in FAMILIES:
        with open(os.path.join(FIX, name),
                  encoding="utf-8") as handle:
            text = handle.read()
        for token in FIXTURE_ABSENT:
            assert token not in text, (name, token)


def test_poisoned_capture_id_refuses():
    for poison in POISONED_CAPTURES:
        document = load("mmio-supported.json")
        document["capture_id"] = poison
        with pytest.raises(AssertionError):
            oracle(document)


def test_grammar_poison_capture_id_refuses():
    for poison in GRAMMAR_POISONS:
        for fragment in ("dev/mem", "kcore", "/proc/"):
            assert fragment not in poison, poison
        document = load("mmio-supported.json")
        document["capture_id"] = poison
        with pytest.raises(AssertionError):
            oracle(document)


def test_mapping_classes_stay_in_vocabulary():
    for name in FAMILIES:
        for entry in load(name)["entries"]:
            assert entry["mapping_class"] in MAPPING_CLASSES, \
                (name, entry)


def test_reader_source_refuses_and_stays_offline():
    with open(MODEL, encoding="utf-8") as handle:
        text = handle.read()
    for token in SOURCE_REFUSAL_PRESENT:
        assert token in text, token
    assert SOURCE_CAPTURE_REFUSAL in text
    for marker in ("value outside token grammar",
                   "KNOWN_MAPPING_CLASSES"):
        assert marker in text, marker
    for token in SOURCE_ABSENT + SOURCE_NO_IO:
        assert token not in text, token


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
