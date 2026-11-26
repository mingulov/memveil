#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline CLI-selection goldens: fixture contract checks.

Each fixture under fixtures/cli/ pairs one synthetic
capability-selection, run-outcome or compare request shaped
by the frozen exposure catalog with the expected stage
exit. This module re-derives every expectation with an
independent predicate (never by running the product
selection resolver), so a fixture can only pass when its
expected exit was computed independently of the
implementation.

Covered legs: default and explicit capability lists with
their attempt-hook dependency, caller opt-in for the
journal channels, device filters, legacy input, the full
policy/strict/recovery exit table, and the compare-verb
exit precedence. Stage exits only: invalid input=2,
missing collection=3, partial=4, finalized strict proved
policy violation=5, ordinary valid report=0.
"""

import json
import os

FIXTURES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "cli")
ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
RUST_TEST = os.path.join(ROOT, "tests", "exposure_cli.rs")
COVERAGE_DOC = os.path.join(ROOT, "docs", "exposure-coverage.md")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")

# Family name -> fixture files. Every leg the card lists
# must stay covered by at least one fixture.
FAMILIES = {
    "default selection": [
        "sel_default.json",
        "sel_legacy_default.json",
    ],
    "ordinary lists": [
        "sel_all.json",
        "sel_attempt_alone.json",
        "sel_lifecycle_alone.json",
        "sel_copy_alone.json",
        "sel_duplicates_first_wins.json",
        "sel_strict_no_spaces.json",
    ],
    "caller opt-in": [
        "sel_journal_alone.json",
        "sel_observe_alone.json",
        "sel_journal_pair.json",
        "sel_mixed_ordinary_journal.json",
        "sel_attempt_required_beats_channel.json",
    ],
    "unknown and planned names": [
        "sel_unknown.json",
        "sel_planned_census.json",
        "sel_planned_shared_buffers.json",
        "sel_bad_list_empty_item.json",
        "sel_explicit_empty_list.json",
        "sel_unknown_beats_device.json",
    ],
    "device filters": [
        "sel_device_accepted.json",
        "sel_device_256.json",
        "sel_device_empty.json",
        "sel_device_too_long.json",
        "sel_device_hides_global.json",
    ],
    "legacy input": [
        "sel_legacy_ordinary.json",
        "sel_legacy_journal.json",
        "cmp_legacy_pair_refused.json",
    ],
    "policy/strict/recovery exits": [
        "out_invalid.json",
        "out_missing.json",
        "out_invalid_beats_missing.json",
        "out_recovered.json",
        "out_recovered_beats_strict.json",
        "out_ordinary_valid.json",
        "out_ordinary_policy_nonstrict.json",
        "out_strict_violation.json",
        "out_strict_incomplete.json",
        "out_strict_clean.json",
        "out_missing_beats_recovered.json",
        "out_refused_beats_violation.json",
    ],
    "compare precedence": [
        "cmp_clean.json",
        "cmp_incompatible.json",
        "cmp_unavailable.json",
        "cmp_invalid_capture.json",
        "cmp_invalid_beats_missing.json",
        "cmp_missing_beats_refused.json",
        "cmp_strict_violation.json",
        "cmp_empty_rows.json",
        "cmp_duplicate_metric.json",
        "cmp_unknown_label.json",
        "cmp_duplicate_beats_label.json",
    ],
}

# Reason codes the coverage section documents. The word
# list stays in lockstep with the selection oracle below.
# Reasons are hyphenated slugs per the frozen catalog
# label rule.
REASONS = (
    "unknown-capability",
    "planned-capability",
    "bad-capability-list",
    "empty-capability-list",
    "attempt-trace-required",
    "invalid-device",
    "device-hides-global-evidence",
    "legacy-input",
    "no-record-channel",
    "invalid-capture",
    "no-requested-metrics",
    "duplicate-metric",
    "unknown-compatibility",
)

# Conclusion language that must never appear: a smaller
# count never implies a healthier guest.
FORBIDDEN_CONCLUSIONS = (
    "safer",
    "secure",
    "no attack",
    "less sharing",
)

# Frozen catalog capability partition. The catalog test
# below pins these lists against the catalog file, so a
# catalog edit cannot silently move an id.
ORDINARY = ("attempt-trace", "mapping-lifecycle", "copy-actual")
JOURNAL = ("conversion-observe", "conversion-journal")
PLANNED = ("census", "object-lifetimes", "dma-paths",
           "shared-buffers", "host-interfaces",
           "mapping-inventory", "exposure-context")
DEFAULT_IDS = ("attempt-trace",)

# Device names are 1..256 characters, mirroring the
# record verb's literal device selector.
MAX_DEVICE_CHARS = 256

# Compare row verdicts the comparator lane emits; the
# skeleton reads them but never invents them.
KNOWN_COMPATIBILITY = ("compatible", "incompatible", "unavailable")


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def all_fixtures():
    names = []
    for files in FAMILIES.values():
        names.extend(files)
    return names


def expect_selection(sel):
    """Independent capability-list oracle.

    Absent list means the default channel; the sole item
    "all" expands to the three ordinary channels and never
    implies an opt-in journal channel. Splitting is
    strict: no trimming, so a spaced item is unknown.
    Duplicates collapse with the first occurrence winning.
    An ordinary id without attempt-trace refuses, legacy
    input refuses journal selections, and a device filter
    refuses journal selections because filtering cannot
    hide global conversion evidence. Returns the full
    stage outcome: exit, reason, selected ids in order,
    the attempt-hook dependency, and the device filter.
    """
    want = sel.get("capabilities")
    if want is None:
        ids = list(DEFAULT_IDS)
    elif want == "":
        return {"exit": 2, "reason": "empty-capability-list",
                "selected": [], "requires_attempt_hook": False,
                "device": None}
    elif want == "all":
        ids = list(ORDINARY)
    else:
        items = want.split(",")
        if any(item == "" for item in items):
            return {"exit": 2, "reason": "bad-capability-list",
                    "selected": [], "requires_attempt_hook": False,
                    "device": None}
        ids = []
        for item in items:
            if item in PLANNED:
                return {"exit": 2, "reason": "planned-capability",
                        "selected": [],
                        "requires_attempt_hook": False,
                        "device": None}
            if item not in ORDINARY and item not in JOURNAL:
                return {"exit": 2, "reason": "unknown-capability",
                        "selected": [],
                        "requires_attempt_hook": False,
                        "device": None}
            if item not in ids:
                ids.append(item)
    has_ordinary = any(cap in ORDINARY for cap in ids)
    has_journal = any(cap in JOURNAL for cap in ids)
    if has_ordinary and "attempt-trace" not in ids:
        return {"exit": 2, "reason": "attempt-trace-required",
                "selected": [], "requires_attempt_hook": False,
                "device": None}
    legacy = sel.get("legacy", False)
    if legacy and has_journal:
        return {"exit": 2, "reason": "legacy-input",
                "selected": [], "requires_attempt_hook": False,
                "device": None}
    device = sel.get("device")
    if device is not None:
        if device == "" or len(device) > MAX_DEVICE_CHARS:
            return {"exit": 2, "reason": "invalid-device",
                    "selected": [], "requires_attempt_hook": False,
                    "device": None}
        if has_journal:
            return {"exit": 2,
                    "reason": "device-hides-global-evidence",
                    "selected": [],
                    "requires_attempt_hook": False,
                    "device": None}
    hook = has_ordinary or legacy
    if has_journal:
        return {"exit": 3, "reason": "no-record-channel",
                "selected": ids, "requires_attempt_hook": hook,
                "device": device}
    return {"exit": 0, "reason": None, "selected": ids,
            "requires_attempt_hook": hook, "device": device}


def expect_exit(outcome):
    """Independent exit-table oracle, in precedence order.

    Invalid input beats missing collection, missing beats
    every partial shape, partial beats a strict proved
    violation, and only then does the strict violation
    exit apply. A non-strict valid report stays 0 with
    its policy field shown independently.
    """
    if not outcome["inputs_valid"]:
        return 2
    if outcome["collection_missing"]:
        return 3
    if outcome["recovered"]:
        return 4
    if outcome["refused_metrics"]:
        return 4
    if outcome["strict"] and outcome["policy_violation_proved"]:
        return 5
    if outcome["strict"] and not outcome["evidence_complete"]:
        return 4
    return 0


def expect_compare(case):
    """Independent compare-verb oracle.

    Capture validity refuses before row shape; an empty
    request, a repeated metric id, and an unknown verdict
    label each refuse as invalid input. Any refused
    requested metric makes the run partial. The surviving
    flags then follow the exit-table precedence.
    """
    if not case["left_valid"] or not case["right_valid"]:
        return {"exit": 2, "reason": "invalid-capture"}
    rows = case["rows"]
    if not rows:
        return {"exit": 2, "reason": "no-requested-metrics"}
    seen = set()
    for row in rows:
        if row["metric_id"] in seen:
            return {"exit": 2, "reason": "duplicate-metric"}
        seen.add(row["metric_id"])
        if row["compatibility"] not in KNOWN_COMPATIBILITY:
            return {"exit": 2, "reason": "unknown-compatibility"}
    refused = any(row["compatibility"] != "compatible"
                  for row in rows)
    outcome = {"inputs_valid": True,
               "collection_missing": case["collection_missing"],
               "recovered": case["recovered"],
               "refused_metrics": refused,
               "strict": case["strict"],
               "policy_violation_proved":
                   case["policy_violation_proved"],
               "evidence_complete": case["evidence_complete"]}
    return {"exit": expect_exit(outcome), "reason": None}


def test_all_families_present():
    for family, files in FAMILIES.items():
        for name in files:
            path = os.path.join(FIXTURES, name)
            assert os.path.isfile(path), \
                "missing fixture for %s: %s" % (family, name)


def test_fixture_expectations_match_oracle():
    for name in all_fixtures():
        fixture = load_fixture(name)
        assert "case" in fixture, "%s: missing case id" % name
        assert "description" in fixture, \
            "%s: missing description" % name
        if "selection" in fixture:
            want = expect_selection(fixture["selection"])
            assert fixture["expected"] == want, \
                "%s: want %r got %r" % (
                    name, want, fixture["expected"])
        elif "outcome" in fixture:
            want = expect_exit(fixture["outcome"])
            assert fixture["expected"] == {"exit": want}, \
                "%s: want exit %d got %r" % (
                    name, want, fixture["expected"])
        elif "compare" in fixture:
            want = expect_compare(fixture["compare"])
            assert fixture["expected"] == want, \
                "%s: want %r got %r" % (
                    name, want, fixture["expected"])
        else:
            raise AssertionError(
                "%s: no selection/outcome/compare input" % name)


def test_expected_ids_match_catalog():
    with open(CATALOG, encoding="utf-8") as handle:
        catalog = json.load(handle)
    kinds = {}
    for cap in catalog["capabilities"]:
        kinds[cap["id"]] = (cap["kind"], cap["status"])
    assert {cap for cap in kinds
            if kinds[cap] == ("ordinary", "implemented")} \
        == set(ORDINARY), "oracle ordinary ids drifted"
    assert {cap for cap in kinds
            if kinds[cap] == ("journal", "reserved")} \
        == set(JOURNAL), "oracle journal ids drifted"
    assert {cap for cap in kinds
            if kinds[cap] == ("exposure", "planned")} \
        == set(PLANNED), "oracle planned ids drifted"
    refusals = catalog["request_refusals"]
    assert refusals["conversion-journal"]["exit"] == 3
    assert refusals["conversion-observe"]["exit"] == 3
    assert refusals["planned-exposure"]["exit"] == 2
    assert set(refusals["planned-exposure"]["applies_to"]) \
        == set(PLANNED)
    for name in all_fixtures():
        fixture = load_fixture(name)
        if "selection" not in fixture:
            continue
        for cap in fixture["expected"]["selected"]:
            assert cap in kinds, \
                "%s: selected id %r outside the catalog" % (
                    name, cap)


def test_stage_exits_stay_closed():
    for name in all_fixtures():
        fixture = load_fixture(name)
        code = fixture["expected"]["exit"]
        if "selection" in fixture:
            assert code in (0, 2, 3), \
                "%s: selection stage exit %r" % (name, code)
        else:
            assert code in (0, 2, 3, 4, 5), \
                "%s: run exit %r" % (name, code)
        if code == 0:
            assert fixture["expected"]["reason"] is None, \
                "%s: clean exit carries a reason" % name
        else:
            assert fixture["expected"]["reason"] in REASONS, \
                "%s: undocumented reason %r" % (
                    name, fixture["expected"]["reason"])


# Precedence order, earliest first. The order test walks
# every pair through the oracle with both conditions set
# and requires the earlier condition's exit.
PRECEDENCE = (
    ("invalid", 2),
    ("missing", 3),
    ("recovered", 4),
    ("refused", 4),
    ("proved", 5),
    ("incomplete", 4),
    ("clean", 0),
)


def precedence_outcome(name):
    outcome = {"inputs_valid": True,
               "collection_missing": False,
               "recovered": False,
               "refused_metrics": False,
               "strict": False,
               "policy_violation_proved": False,
               "evidence_complete": True}
    if name == "invalid":
        outcome["inputs_valid"] = False
    elif name == "missing":
        outcome["collection_missing"] = True
    elif name == "recovered":
        outcome["recovered"] = True
    elif name == "refused":
        outcome["refused_metrics"] = True
    elif name == "proved":
        outcome["strict"] = True
        outcome["policy_violation_proved"] = True
    elif name == "incomplete":
        outcome["strict"] = True
        outcome["evidence_complete"] = False
    return outcome


def merge_outcomes(first, second):
    merged = dict(first)
    for key, value in second.items():
        if key == "inputs_valid":
            merged[key] = merged[key] and value
        elif key == "evidence_complete":
            merged[key] = merged[key] and value
        else:
            merged[key] = merged[key] or value
    return merged


def test_exit_precedence_order():
    singles = {}
    for name, code in PRECEDENCE:
        got = expect_exit(precedence_outcome(name))
        assert got == code, \
            "single %s: want %d got %d" % (name, code, got)
        singles[name] = got
    for pos, (earlier, _) in enumerate(PRECEDENCE):
        for later, _ in PRECEDENCE[pos + 1:]:
            merged = merge_outcomes(
                precedence_outcome(earlier),
                precedence_outcome(later))
            got = expect_exit(merged)
            assert got == singles[earlier], \
                "%s+%s: want %d got %d" % (
                    earlier, later, singles[earlier], got)


def test_opt_in_channels_never_implied():
    default = expect_selection({"capabilities": None,
                                "device": None, "legacy": False})
    expanded = expect_selection({"capabilities": "all",
                                 "device": None, "legacy": False})
    for name, outcome in (("default", default),
                          ("all", expanded)):
        assert outcome["exit"] == 0, "%s must select" % name
        for cap in outcome["selected"]:
            assert cap not in JOURNAL, \
                "%s implies opt-in %s" % (name, cap)
            assert cap not in PLANNED, \
                "%s implies planned %s" % (name, cap)


def test_no_safety_conclusion_language():
    for name in all_fixtures():
        text = json.dumps(load_fixture(name)).lower()
        for phrase in FORBIDDEN_CONCLUSIONS:
            assert phrase not in text, \
                "%s: forbidden conclusion %r" % (name, phrase)
    with open(COVERAGE_DOC, encoding="utf-8") as handle:
        doc = handle.read().lower()
    section = doc.split("cli capability selection")[-1]
    assert section != doc, "capability section missing"
    for phrase in FORBIDDEN_CONCLUSIONS:
        assert phrase not in section, \
            "docs conclusion %r" % phrase


def test_reason_codes_documented():
    with open(COVERAGE_DOC, encoding="utf-8") as handle:
        doc = handle.read()
    assert "CLI capability selection" in doc
    for reason in REASONS:
        assert reason in doc, "undocumented reason %s" % reason


def test_rust_suite_covers_every_fixture():
    with open(RUST_TEST, encoding="utf-8") as handle:
        suite = handle.read()
    for name in all_fixtures():
        case = load_fixture(name)["case"]
        assert case in suite, \
            "rust suite never mentions case %s" % case
    assert "compare.rs" in suite \
        or "cli::compare" in suite, \
        "rust suite never binds the selection resolver"
