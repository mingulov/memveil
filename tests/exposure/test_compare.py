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
source meaning, refused invalid inputs, delta
overflow in both directions, a fully compatible golden
and metric-shape edges.
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
        "source_meaning_blank.json",
    ],
    "delta overflow": [
        "delta_overflow.json",
    ],
    "unequal window/clock": [
        "unequal_window.json",
        "clock_mismatch.json",
        "clock_unknown.json",
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
        "unit_unknown.json",
    ],
    "invalid input": [
        "duplicate_metric.json",
        "invalid_window.json",
        "invalid_value.json",
        "invalid_value_blank_reason.json",
        "invalid_meaning.json",
        "invalid_clock.json",
    ],
}

# Reason codes the compatibility table documents. The word
# list stays in lockstep with the per-metric predicate.
# Reasons are hyphenated slugs per the frozen catalog
# label rule; closed enums keep underscores.
REASONS = (
    "compatible",
    "metric-missing",
    "unit-unknown",
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
    "clock-unknown",
    "clock-mismatch",
    "window-mismatch",
    "partial-census",
    "value-unknown",
    "delta-overflow",
    "duplicate-metric",
    "invalid-window",
    "invalid-value",
    "invalid-meaning",
    "invalid-clock",
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


# ASCII whitespace for the shared blank definition:
# space, tab, line feed, carriage return, vertical tab,
# form feed.
ASCII_WHITESPACE = " \t\n\r\x0b\x0c"


def is_blank(value):
    """A meaning-carrying string counts as missing when it
    is empty or every character is ASCII whitespace. This
    definition is shared verbatim with the Rust comparator
    so both sides always agree."""
    return value == "" or all(c in ASCII_WHITESPACE for c in value)


def has_control(value):
    """A string carries a control character when any
    codepoint is U+0000-U+001F or U+007F-U+009F. This
    definition is shared verbatim with the Rust comparator.
    ASCII whitespace overlaps this range, so callers check
    blankness first: a blank string is missing, never
    malformed."""
    return any("\x00" <= c <= "\x1f" or "\x7f" <= c <= "\x9f"
               for c in value)


def validate_capture(capture):
    """Independent input validation over one capture.

    Order within a capture: repeated metric id, backward
    window, value/reason pairing, source meaning content,
    then clock content. Blank means empty or
    ASCII-whitespace-only; a control character means
    U+0000-U+001F or U+007F-U+009F. A blank reason counts
    as missing, so a null value with a blank reason
    refuses; a non-blank reason with a control character
    is malformed and refuses too. Meanings and clocks
    with control characters refuse as invalid-meaning and
    invalid-clock. Returns the refusal reason, or None
    when the capture validates. Callers validate the left
    capture before the right.
    """
    seen = set()
    for metric in capture["metrics"]:
        if metric["metric_id"] in seen:
            return "duplicate-metric"
        seen.add(metric["metric_id"])
    if (int(capture["window"]["start"])
            > int(capture["window"]["end"])):
        return "invalid-window"
    for metric in capture["metrics"]:
        value = metric["value"]
        reason = metric.get("value_reason")
        if value is not None:
            if reason is not None:
                return "invalid-value"
        elif reason is None or is_blank(reason):
            return "invalid-value"
        elif has_control(reason):
            return "invalid-value"
    for meaning in capture["source_meanings"].values():
        if not is_blank(meaning) and has_control(meaning):
            return "invalid-meaning"
    clock = capture["window"]["clock_domain"]
    if not is_blank(clock) and has_control(clock):
        return "invalid-clock"
    return None


def expect_compatible(left_metric, right_metric):
    """Independent delta oracle: exact difference or null."""
    if left_metric["value"] is None or right_metric["value"] is None:
        return None, "value-unknown"
    delta = int(right_metric["value"]) - int(left_metric["value"])
    if delta < -(2 ** 63) or delta > 2 ** 63 - 1:
        return None, "delta-overflow"
    return delta, None


# Frozen unit vocabulary from the exposure
# catalog: only these labels compare; anything else
# (a blank label included) records no unit.
KNOWN_UNITS = ("bytes", "unknown")


def expect_row(case, left, right, metric_id):
    """Independent compatibility predicate over one metric."""
    left_metric = metric_by_id(left, metric_id)
    right_metric = metric_by_id(right, metric_id)
    if left_metric is None or right_metric is None:
        return ("unavailable", "metric-missing", "absent")
    if (left_metric["unit"] not in KNOWN_UNITS
            or right_metric["unit"] not in KNOWN_UNITS):
        return ("incompatible", "unit-unknown", "absent")
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
    if (left_meaning is None or is_blank(left_meaning)
            or right_meaning is None or is_blank(right_meaning)):
        return ("incompatible", "source-meaning-unknown", "absent")
    if left_meaning != right_meaning:
        return ("incompatible", "source-meaning-change", "absent")
    left_clock = left["window"]["clock_domain"]
    right_clock = right["window"]["clock_domain"]
    if is_blank(left_clock) or is_blank(right_clock):
        return ("incompatible", "clock-unknown", "absent")
    if left_clock != right_clock:
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


def expect_quality(compatibility, delta):
    """Independent quality oracle: quality derives from the row.

    Only a row with an exact delta claims complete quality.
    Compatible rows with a null delta report unknown on all
    five channels; refused rows report refused, except an
    unavailable row reports unknown identity.
    """
    if compatibility == "incompatible":
        channels = ("refused",) * 5
    elif compatibility == "unavailable":
        channels = ("refused", "refused", "unknown", "refused", "refused")
    elif delta[0] == "null":
        channels = ("unknown",) * 5
    else:
        channels = ("complete",) * 5
    detail, aggregate, identity, baseline, terminal = channels
    return {"detail": detail, "aggregate": aggregate,
            "identity": identity, "baseline": baseline,
            "terminal": terminal}


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
        if "refused" in fixture:
            refusal = (validate_capture(left)
                       or validate_capture(right))
            assert refusal == fixture["refused"], \
                "%s: want refusal %s got %r" % (
                    name, fixture["refused"], refusal)
            assert "expected" not in fixture, \
                "%s: refused input carries rows" % name
            continue
        assert validate_capture(left) is None, \
            "%s: left capture invalid" % name
        assert validate_capture(right) is None, \
            "%s: right capture invalid" % name
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
            assert row["quality"] == expect_quality(
                compatibility, delta), \
                "%s/%s: quality derives from the row" % (
                    name, metric_id)
        ids = {m["metric_id"] for m in left["metrics"]}
        ids |= {m["metric_id"] for m in right["metrics"]}
        assert seen == ids, \
            "%s: expected rows %s miss metrics %s" % (
                name, sorted(seen), sorted(ids))


def test_incompatible_rows_carry_no_numeric_delta():
    for name in all_fixtures():
        fixture = load_fixture(name)
        if "refused" in fixture:
            continue
        for row in fixture["expected"]:
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
        fixture = load_fixture(name)
        if "refused" in fixture:
            continue
        for row in fixture["expected"]:
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
        if "refused" in fixture:
            continue
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


# Per-metric refusal reasons in predicate order. The
# order test walks adjacent pairs through the oracle and
# the docs test requires the compatibility table to list
# this same sequence.
CHECK_ORDER = (
    "metric-missing",
    "unit-unknown",
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
    "clock-unknown",
    "clock-mismatch",
    "window-mismatch",
    "partial-census",
)


def base_pair():
    """Two fully compatible captures with one metric."""
    meanings = {"census-direct-map": "meaning-1",
                "queue-ledger": "meaning-1"}

    def side(evidence):
        return {
            "census_bounded": False,
            "epoch": "41",
            "evidence_id": evidence,
            "legacy": False,
            "metrics": [{
                "census_derived": False,
                "metric_id": "x",
                "scope": "guest-direct-map",
                "source_id": "census-direct-map",
                "unit": "bytes",
                "value": "1",
            }],
            "platform_cell": "snp-guest-01",
            "profile_id": "linux-x86_64-7.0-reference",
            "source_meanings": dict(meanings),
            "window": {"clock_domain": "guest_monotonic_active",
                       "end": "2000", "start": "1000"},
            "workload": "idle-snapshot",
        }

    left = side("cap-left-order")
    right = side("cap-right-order")
    right["metrics"][0]["value"] = "9"
    return left, right


def break_check(reason, left, right):
    """Fail exactly one compatibility check on the pair."""
    metric = right["metrics"][0]
    if reason == "metric-missing":
        right["metrics"] = []
    elif reason == "unit-unknown":
        left["metrics"][0]["unit"] = ""
    elif reason == "unit-mismatch":
        metric["unit"] = "unknown"
    elif reason == "scope-mismatch":
        metric["scope"] = "guest-driver-virtio"
    elif reason == "legacy-input":
        right["legacy"] = True
    elif reason == "epoch-mismatch":
        right["epoch"] = "42"
    elif reason == "device-binding-mismatch":
        right["platform_cell"] = "tdx-guest-02"
    elif reason == "profile-mismatch":
        right["profile_id"] = "linux-x86_64-7.0-hardened"
    elif reason == "workload-mismatch":
        right["workload"] = "io-batch"
    elif reason == "source-mismatch":
        metric["source_id"] = "queue-ledger"
    elif reason == "source-meaning-unknown":
        del left["source_meanings"]["census-direct-map"]
        del right["source_meanings"]["census-direct-map"]
    elif reason == "source-meaning-change":
        right["source_meanings"]["census-direct-map"] = "meaning-2"
    elif reason == "clock-unknown":
        left["window"]["clock_domain"] = ""
    elif reason == "clock-mismatch":
        right["window"]["clock_domain"] = "guest_boottime_elapsed"
    elif reason == "window-mismatch":
        right["window"]["end"] = "3000"
    elif reason == "partial-census":
        metric["census_derived"] = True
        right["census_bounded"] = True
    else:  # pragma: no cover
        raise AssertionError("no breaker for %s" % reason)


def test_checks_run_in_documented_order():
    for index in range(len(CHECK_ORDER) - 1):
        earlier = CHECK_ORDER[index]
        later = CHECK_ORDER[index + 1]
        if earlier == "metric-missing":
            continue  # absence preempts every check; see below
        left, right = base_pair()
        break_check(earlier, left, right)
        break_check(later, left, right)
        assert validate_capture(left) is None
        assert validate_capture(right) is None
        compatibility, reason, _delta = expect_row(
            "order", left, right, "x")
        assert compatibility == "incompatible", (earlier, later)
        assert reason == earlier, \
            "want %s before %s, got %s" % (earlier, later, reason)
    # A missing metric preempts every later check at once.
    left, right = base_pair()
    for reason in CHECK_ORDER:
        if reason != "metric-missing":
            break_check(reason, left, right)
    break_check("metric-missing", left, right)
    compatibility, reason, _delta = expect_row(
        "order", left, right, "x")
    assert (compatibility, reason) == ("unavailable", "metric-missing")
    # The last check beats the delta stage: a bounded census
    # row with an unknown value still refuses.
    left, right = base_pair()
    break_check("partial-census", left, right)
    left["metrics"][0]["value"] = None
    left["metrics"][0]["value_reason"] = "source-unavailable"
    compatibility, reason, _delta = expect_row(
        "order", left, right, "x")
    assert (compatibility, reason) == ("incompatible", "partial-census")
    # Validation order mirrors the product: duplicates beat a
    # backward window, and the left capture goes first.
    left, right = base_pair()
    left["metrics"].append(dict(left["metrics"][0]))
    left["window"]["start"] = "3000"
    left["window"]["end"] = "2000"
    assert validate_capture(left) == "duplicate-metric"
    left, right = base_pair()
    left["metrics"][0]["value"] = None
    right["metrics"].append(dict(right["metrics"][0]))
    assert validate_capture(left) == "invalid-value"
    assert validate_capture(right) == "duplicate-metric"
    assert (validate_capture(left) or validate_capture(right)) \
        == "invalid-value"
    # Malformed content refuses after the pairing rule: a
    # bad value beats a bad meaning, which beats a bad
    # clock, and the left capture still goes first.
    left, right = base_pair()
    left["metrics"][0]["value"] = None
    left["metrics"][0]["value_reason"] = None
    left["source_meanings"]["census-direct-map"] = "\x1c"
    assert validate_capture(left) == "invalid-value"
    left, right = base_pair()
    left["source_meanings"]["census-direct-map"] = "\x1c"
    left["window"]["clock_domain"] = "\x1c"
    assert validate_capture(left) == "invalid-meaning"
    left, right = base_pair()
    left["window"]["clock_domain"] = "\x1c"
    right["source_meanings"]["census-direct-map"] = "\x1c"
    assert validate_capture(left) == "invalid-clock"
    assert validate_capture(right) == "invalid-meaning"
    assert (validate_capture(left) or validate_capture(right)) \
        == "invalid-clock"


def test_docs_table_follows_check_order():
    with open(COVERAGE_DOC, encoding="utf-8") as handle:
        doc = handle.read()
    section = doc.split("Checks run in order;")[1]
    section = section.split("Compatible rows carry")[0]
    codes = re.findall(r"^\|\s*\d+\s*\|\s*`([^`]+)`",
                       section, re.MULTILINE)
    assert tuple(codes) == CHECK_ORDER + ("compatible",), codes


def test_blank_meanings_are_unknown():
    # A blank meaning records no meaning: empty or
    # whitespace-only on either side, or both, refuses
    # the metric as unknown with no delta. Two blanks
    # are not equal; blank against changed is unknown,
    # never a change.
    cases = [
        ("", ""),
        ("", "meaning-1"),
        ("meaning-1", ""),
        ("   ", "meaning-1"),
        ("meaning-1", "   "),
        ("", "meaning-2"),
    ]
    for left_blank, right_blank in cases:
        left, right = base_pair()
        left["source_meanings"]["census-direct-map"] = left_blank
        right["source_meanings"]["census-direct-map"] = right_blank
        assert validate_capture(left) is None
        assert validate_capture(right) is None
        assert expect_row("blank", left, right, "x") == (
            "incompatible", "source-meaning-unknown", "absent"), \
            (left_blank, right_blank)


def test_one_sided_omission_is_unknown():
    # A meaning missing on exactly one side cannot prove
    # comparability: unknown wins over change.
    left, right = base_pair()
    del right["source_meanings"]["census-direct-map"]
    assert expect_row("omission", left, right, "x") == (
        "incompatible", "source-meaning-unknown", "absent")
    left, right = base_pair()
    del left["source_meanings"]["census-direct-map"]
    right["source_meanings"]["census-direct-map"] = "meaning-2"
    assert expect_row("omission", left, right, "x") == (
        "incompatible", "source-meaning-unknown", "absent")


def test_blank_value_reason_refuses_input():
    # A null value with a blank reason explains nothing:
    # the capture refuses as invalid-value. A known value
    # carrying any reason, blank or not, also refuses.
    left, _right = base_pair()
    left["metrics"][0]["value"] = None
    left["metrics"][0]["value_reason"] = ""
    assert validate_capture(left) == "invalid-value"
    left, _right = base_pair()
    left["metrics"][0]["value"] = None
    left["metrics"][0]["value_reason"] = "   "
    assert validate_capture(left) == "invalid-value"
    left, _right = base_pair()
    left["metrics"][0]["value_reason"] = ""
    assert validate_capture(left) == "invalid-value"


def test_blank_clocks_are_unknown():
    # A blank clock names no clock: empty or ASCII
    # whitespace on either side, or both, refuses the
    # metric as unknown with no delta. Two blank clocks
    # are not a shared clock; blank against a changed
    # clock is unknown, never a mismatch.
    cases = [
        ("", ""),
        ("", "guest_monotonic_active"),
        ("guest_monotonic_active", ""),
        ("   ", "guest_monotonic_active"),
        ("guest_monotonic_active", "\t"),
        ("", "guest_boottime_elapsed"),
    ]
    for left_blank, right_blank in cases:
        left, right = base_pair()
        left["window"]["clock_domain"] = left_blank
        right["window"]["clock_domain"] = right_blank
        assert validate_capture(left) is None
        assert validate_capture(right) is None
        assert expect_row("blank-clock", left, right, "x") == (
            "incompatible", "clock-unknown", "absent"), \
            (left_blank, right_blank)


def test_blank_units_are_unknown():
    # A blank unit names no unit: empty or ASCII
    # whitespace on either side, or both, refuses the
    # metric as unknown with no delta. Two blank units
    # are not a shared unit; blank against a changed
    # unit is unknown, never a mismatch.
    cases = [
        ("", ""),
        ("", "bytes"),
        ("bytes", ""),
        ("   ", "bytes"),
        ("bytes", "\t"),
        ("", "unknown"),
    ]
    for left_blank, right_blank in cases:
        left, right = base_pair()
        left["metrics"][0]["unit"] = left_blank
        right["metrics"][0]["unit"] = right_blank
        assert validate_capture(left) is None
        assert validate_capture(right) is None
        assert expect_row("blank-unit", left, right, "x") == (
            "incompatible", "unit-unknown", "absent"), \
            (left_blank, right_blank)


def test_unlisted_units_are_unknown():
    # A unit outside the frozen vocabulary (bytes,
    # unknown) records no unit even when both sides
    # agree on the label: the metric refuses as
    # unknown with no delta. A control character in a
    # unit never refuses the whole input here; the
    # future capture reader owns malformed refusal.
    cases = [
        ("counts", "counts"),
        ("counts", "bytes"),
        ("bytes", "counts"),
        ("\x1c", "\x1c"),
        ("bytes", "a\x00b"),
    ]
    for left_unit, right_unit in cases:
        left, right = base_pair()
        left["metrics"][0]["unit"] = left_unit
        right["metrics"][0]["unit"] = right_unit
        assert validate_capture(left) is None
        assert validate_capture(right) is None
        assert expect_row("unit-unknown", left, right, "x") == (
            "incompatible", "unit-unknown", "absent"), \
            (left_unit, right_unit)


# Tricky-string battery: (value, kind) with kind one of
# "blank" (empty or ASCII-whitespace-only),
# "malformed" (non-blank with a control character) or
# "content" (anything else). The Rust suite carries this
# same table in the same order under
# tricky_string_battery_matches_oracle; both sides must
# agree on every row, and the coupling test below pins
# the shared literals.
TRICKY_STRINGS = (
    ("", "blank"),
    ("   ", "blank"),
    ("\t", "blank"),
    ("\n", "blank"),
    ("\r", "blank"),
    ("\x0b", "blank"),
    ("\x0c", "blank"),
    ("\x00", "malformed"),
    ("\x1c", "malformed"),
    ("\x1f", "malformed"),
    ("\x7f", "malformed"),
    ("\x9f", "malformed"),
    ("a\x00b", "malformed"),
    (" \x1c ", "malformed"),
    ("\u00a0", "content"),
    (" \u00a0", "content"),
    ("a\u00a0b", "content"),
    ("\u200b", "content"),
    ("\ufeff", "content"),
    ("\u200b\u200b", "content"),
    ("a\u200bb", "content"),
    ("meaning-1", "content"),
)


def test_tricky_string_battery():
    for value, kind in TRICKY_STRINGS:
        # Meaning position: blank is unknown per row,
        # malformed refuses the whole input, content
        # compares by equality (equal pairs keep delta 8).
        left, right = base_pair()
        left["source_meanings"]["census-direct-map"] = value
        right["source_meanings"]["census-direct-map"] = value
        if kind == "blank":
            assert validate_capture(left) is None, repr(value)
            assert validate_capture(right) is None, repr(value)
            assert expect_row("tricky", left, right, "x") == (
                "incompatible", "source-meaning-unknown",
                "absent"), repr(value)
        elif kind == "malformed":
            assert validate_capture(left) == "invalid-meaning", \
                repr(value)
            assert validate_capture(right) == "invalid-meaning", \
                repr(value)
        else:
            assert validate_capture(left) is None, repr(value)
            assert validate_capture(right) is None, repr(value)
            assert expect_row("tricky", left, right, "x") == (
                "compatible", "compatible",
                ("delta", 8)), repr(value)
        # Clock position mirrors the meaning position:
        # blank is unknown per row, malformed refuses the
        # whole input, equal content keeps delta 8.
        left, right = base_pair()
        left["window"]["clock_domain"] = value
        right["window"]["clock_domain"] = value
        if kind == "blank":
            assert validate_capture(left) is None, repr(value)
            assert validate_capture(right) is None, repr(value)
            assert expect_row("tricky", left, right, "x") == (
                "incompatible", "clock-unknown", "absent"), \
                repr(value)
        elif kind == "malformed":
            assert validate_capture(left) == "invalid-clock", \
                repr(value)
            assert validate_capture(right) == "invalid-clock", \
                repr(value)
        else:
            assert validate_capture(left) is None, repr(value)
            assert validate_capture(right) is None, repr(value)
            assert expect_row("tricky", left, right, "x") == (
                "compatible", "compatible",
                ("delta", 8)), repr(value)
        # Reason position with a null value: blank and
        # malformed both refuse as invalid-value, while
        # content (even invisible content) is a usable
        # reason and yields a value-unknown row.
        left, right = base_pair()
        left["metrics"][0]["value"] = None
        left["metrics"][0]["value_reason"] = value
        if kind == "content":
            assert validate_capture(left) is None, repr(value)
            assert validate_capture(right) is None, repr(value)
            assert expect_row("tricky", left, right, "x") == (
                "compatible", "compatible",
                ("null", "value-unknown")), repr(value)
        else:
            assert validate_capture(left) == "invalid-value", \
                repr(value)
    # One-sided malformed input refuses whichever side
    # carries it; one-sided blank clocks stay unknown;
    # invisible content still compares by equality.
    left, right = base_pair()
    right["source_meanings"]["census-direct-map"] = "\x1c"
    assert validate_capture(right) == "invalid-meaning"
    left, right = base_pair()
    left["window"]["clock_domain"] = "\x1c"
    assert validate_capture(left) == "invalid-clock"
    left, right = base_pair()
    right["window"]["clock_domain"] = ""
    assert expect_row("tricky", left, right, "x") == (
        "incompatible", "clock-unknown", "absent")
    left, right = base_pair()
    left["source_meanings"]["census-direct-map"] = "\u200b"
    assert expect_row("tricky", left, right, "x") == (
        "incompatible", "source-meaning-change", "absent")


def test_rust_suite_covers_tricky_string_battery():
    with open(RUST_TEST, encoding="utf-8") as handle:
        suite = handle.read()
    assert "tricky_string_battery_matches_oracle" in suite
    # The battery literals in Rust escape spelling; every
    # row of TRICKY_STRINGS above must appear on the Rust
    # side or the two batteries drift apart.
    for escape in (r'"\u{0}"', r'"\u{1c}"', r'"\u{1f}"',
                   r'"\u{7f}"', r'"\u{9f}"', r'"\u{a0}"',
                   r'"\u{200b}"', r'"\u{feff}"', r'"\t"',
                   r'"\n"', r'"\r"', r'"\x0b"',
                   r'"\x0c"', r'"a\x00b"'):
        assert escape in suite, "rust battery lacks %s" % escape
