#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline exposure-comparison goldens: fixture contract checks.

Each fixture under fixtures/compare/ pairs two synthetic
captures shaped by the frozen exposure catalog field lists
with the expected per-metric ComparisonResult rows. This
module re-derives every expectation with an independent
predicate (never by running the product comparator), so a
fixture can only pass when its expected rows were computed
independently of the implementation.

Covered families: equal-profile/different-workload,
different-epoch/device binding, source meaning change,
unequal window/clock, partial census, legacy input, plus
profile mismatch, per-side source mismatch, unknown
source meaning, a fully compatible golden and
metric-shape edges.
"""

import json
import os
import re

FIXTURES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "compare")
ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
RUST_TEST = os.path.join(ROOT, "tests", "exposure_compare.rs")
COVERAGE_DOC = os.path.join(ROOT, "docs", "exposure-coverage.md")
CATALOG = os.path.join(ROOT, "profiles", "exposure", "catalog.json")

# Family name -> fixture files. Every family the card lists
# must stay covered by at least one fixture.
FAMILIES = {
    "equal-profile/different-workload": [
        "equal_profile_different_workload.json",
    ],
    "different-epoch/device binding": [
        "different_epoch.json",
        "device_binding.json",
    ],
    "source meaning change": [
        "source_meaning_change.json",
    ],
    "profile mismatch": [
        "profile_mismatch.json",
    ],
    "source mismatch": [
        "source_mismatch.json",
    ],
    "unknown source meaning": [
        "source_meaning_unknown.json",
    ],
    "unequal window/clock": [
        "unequal_window.json",
        "clock_mismatch.json",
    ],
    "partial census": [
        "partial_census.json",
    ],
    "legacy input": [
        "legacy_input.json",
    ],
    "compatible golden": [
        "compatible_golden.json",
    ],
    "metric shape": [
        "metric_shape.json",
    ],
}

# Reason codes the compatibility table documents. The word
# list stays in lockstep with the per-metric predicate.
# Reasons are hyphenated slugs per the frozen catalog
# label rule; closed enums keep underscores.
REASONS = (
    "compatible",
    "metric-missing",
    "unit-mismatch",
    "scope-mismatch",
    "legacy-input",
    "epoch-mismatch",
    "device-binding-mismatch",
    "profile-mismatch",
    "workload-mismatch",
    "source-mismatch",
    "source-meaning-unknown",
    "source-meaning-change",
    "clock-mismatch",
    "window-mismatch",
    "partial-census",
    "value-unknown",
    "delta-overflow",
)

# Conclusion language that must never appear: a smaller
# count never implies a safer guest.
FORBIDDEN_CONCLUSIONS = (
    "safer",
    "secure",
    "no attack",
    "less sharing",
)


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def all_fixtures():
    names = []
    for files in FAMILIES.values():
        names.extend(files)
    return names


def metric_by_id(capture, metric_id):
    for metric in capture["metrics"]:
        if metric["metric_id"] == metric_id:
            return metric
    return None


def expect_compatible(left_metric, right_metric):
    """Independent delta oracle: exact difference or null."""
    if left_metric["value"] is None or right_metric["value"] is None:
        return None, "value-unknown"
    delta = int(right_metric["value"]) - int(left_metric["value"])
    if delta < -(2 ** 63) or delta > 2 ** 63 - 1:
        return None, "delta-overflow"
    return delta, None


def expect_row(case, left, right, metric_id):
    """Independent compatibility predicate over one metric."""
    left_metric = metric_by_id(left, metric_id)
    right_metric = metric_by_id(right, metric_id)
    if left_metric is None or right_metric is None:
        return ("unavailable", "metric-missing", "absent")
    if left_metric["unit"] != right_metric["unit"]:
        return ("incompatible", "unit-mismatch", "absent")
    if left_metric["scope"] != right_metric["scope"]:
        return ("incompatible", "scope-mismatch", "absent")
    if left.get("legacy", False) or right.get("legacy", False):
        return ("incompatible", "legacy-input", "absent")
    if left["epoch"] != right["epoch"]:
        return ("incompatible", "epoch-mismatch", "absent")
    if left["platform_cell"] != right["platform_cell"]:
        return ("incompatible", "device-binding-mismatch", "absent")
    if left["profile_id"] != right["profile_id"]:
        return ("incompatible", "profile-mismatch", "absent")
    if left["workload"] != right["workload"]:
        return ("incompatible", "workload-mismatch", "absent")
    if left_metric["source_id"] != right_metric["source_id"]:
        return ("incompatible", "source-mismatch", "absent")
    left_meaning = left["source_meanings"].get(left_metric["source_id"])
    right_meaning = right["source_meanings"].get(right_metric["source_id"])
    if left_meaning is None or right_meaning is None:
        return ("incompatible", "source-meaning-unknown", "absent")
    if left_meaning != right_meaning:
        return ("incompatible", "source-meaning-change", "absent")
    if (left["window"]["clock_domain"]
            != right["window"]["clock_domain"]):
        return ("incompatible", "clock-mismatch", "absent")
    if (left["window"]["start"] != right["window"]["start"]
            or left["window"]["end"] != right["window"]["end"]):
        return ("incompatible", "window-mismatch", "absent")
    if ((left_metric.get("census_derived", False)
            or right_metric.get("census_derived", False))
            and (left.get("census_bounded", False)
                 or right.get("census_bounded", False))):
        return ("incompatible", "partial-census", "absent")
    delta, reason = expect_compatible(left_metric, right_metric)
    if reason is not None:
        return ("compatible", "compatible", ("null", reason))
    return ("compatible", "compatible", ("delta", delta))


def test_all_families_present():
    for family, files in FAMILIES.items():
        for name in files:
            path = os.path.join(FIXTURES, name)
            assert os.path.isfile(path), \
                "missing fixture for %s: %s" % (family, name)


def test_fixture_expectations_match_oracle():
    for name in all_fixtures():
        fixture = load_fixture(name)
        left = fixture["left"]
        right = fixture["right"]
        seen = set()
        for row in fixture["expected"]:
            metric_id = row["metric_id"]
            assert metric_id not in seen, \
                "%s: duplicate row %s" % (name, metric_id)
            seen.add(metric_id)
            compatibility, reason, delta = expect_row(
                fixture["case"], left, right, metric_id)
            assert row["compatibility"] == compatibility, \
                "%s/%s: want %s got %s" % (
                    name, metric_id, compatibility,
                    row["compatibility"])
            assert row["reason"] == reason, \
                "%s/%s: want %s got %s" % (
                    name, metric_id, reason, row["reason"])
            if delta == "absent":
                assert "delta" not in row, \
                    "%s/%s: incompatible metric carries a delta" % (
                        name, metric_id)
            elif delta[0] == "null":
                assert row.get("delta") is None, \
                    "%s/%s: want null delta" % (name, metric_id)
                assert row.get("delta_reason") == delta[1], \
                    "%s/%s: want %s" % (name, metric_id, delta[1])
            else:
                assert row["delta"] == delta[1], \
                    "%s/%s: want %d got %r" % (
                        name, metric_id, delta[1],
                        row.get("delta"))
            assert row["left_evidence"] == left["evidence_id"]
            assert row["right_evidence"] == right["evidence_id"]
            anchor = metric_by_id(left, metric_id) \
                or metric_by_id(right, metric_id)
            assert row["unit"] == anchor["unit"], \
                "%s/%s: unit follows the present side" % (
                    name, metric_id)
            assert row["scope"] == anchor["scope"], \
                "%s/%s: scope follows the present side" % (
                    name, metric_id)
        ids = {m["metric_id"] for m in left["metrics"]}
        ids |= {m["metric_id"] for m in right["metrics"]}
        assert seen == ids, \
            "%s: expected rows %s miss metrics %s" % (
                name, sorted(seen), sorted(ids))


def test_incompatible_rows_carry_no_numeric_delta():
    for name in all_fixtures():
        for row in load_fixture(name)["expected"]:
            if row["compatibility"] in ("incompatible", "unavailable"):
                assert "delta" not in row, \
                    "%s/%s: numeric delta on %s" % (
                        name, row["metric_id"],
                        row["compatibility"])
                assert "delta_reason" not in row


def test_expected_rows_match_catalog_fields():
    with open(CATALOG, encoding="utf-8") as handle:
        catalog = json.load(handle)
    fields = {field["name"] for field in
              catalog["records"]["ComparisonResult"]["fields"]}
    fields |= {"delta_reason"}
    for name in all_fixtures():
        for row in load_fixture(name)["expected"]:
            assert set(row) <= fields, \
                "%s/%s: unknown fields %s" % (
                    name, row["metric_id"],
                    sorted(set(row) - fields))
            for field in fields - {"delta", "delta_reason"}:
                assert field in row, \
                    "%s/%s: missing %s" % (
                        name, row["metric_id"], field)


def test_journal_events_are_never_netted():
    for name in all_fixtures():
        fixture = load_fixture(name)
        journals = []
        for side in ("left", "right"):
            journals.extend(
                fixture[side].get("journal_events", []))
        if not journals:
            continue
        for row in fixture["expected"]:
            if row["compatibility"] != "compatible":
                continue
            if row.get("delta") is None:
                continue
            left = metric_by_id(fixture["left"], row["metric_id"])
            right = metric_by_id(fixture["right"], row["metric_id"])
            assert row["delta"] == (
                int(right["value"]) - int(left["value"])), \
                "%s/%s: delta nets journal events" % (
                    name, row["metric_id"])


def test_no_safety_conclusion_language():
    for name in all_fixtures():
        text = json.dumps(load_fixture(name)).lower()
        for phrase in FORBIDDEN_CONCLUSIONS:
            assert phrase not in text, \
                "%s: forbidden conclusion %r" % (name, phrase)
    with open(COVERAGE_DOC, encoding="utf-8") as handle:
        doc = handle.read().lower()
    section = doc.split("capture comparison compatibility")[-1]
    assert section != doc, "compatibility section missing"
    for phrase in FORBIDDEN_CONCLUSIONS:
        assert phrase not in section, \
            "docs conclusion %r" % phrase


def test_reason_codes_documented():
    with open(COVERAGE_DOC, encoding="utf-8") as handle:
        doc = handle.read()
    assert "Capture comparison compatibility" in doc
    for reason in REASONS:
        assert reason in doc, "undocumented reason %s" % reason


def test_rust_suite_covers_every_fixture():
    with open(RUST_TEST, encoding="utf-8") as handle:
        suite = handle.read()
    for name in all_fixtures():
        case = load_fixture(name)["case"]
        assert case in suite, \
            "rust suite never mentions case %s" % case
    assert "exposure_compare.rs" in suite
