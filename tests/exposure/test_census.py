#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline guest-census snapshot goldens: fixture contract checks.

Each fixture under fixtures/census/ pairs two synthetic
guest-view census snapshots with the expected per-class
CensusDelta rows. This module re-derives every expectation
with an independent predicate (never by running the product
comparator), so a fixture can only pass when its expected
rows were computed independently of the implementation.

Covered families: a compatible golden with exact known
deltas, class shape edges, guest-view scope, capture
binding (profile/workload/epoch/device), coverage,
atomicity and stated race uncertainty, interval/time
bounds, journal scope and partial-journal refusal, the
delta stage (unknown values, overflow), and refused
invalid inputs.
"""

import json
import os

FIXTURES = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "census")
ROOT = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
RUST_TEST = os.path.join(ROOT, "tests", "exposure_census.rs")
RUST_MODULE = os.path.join(
    ROOT, "src", "capture", "exposure_census.rs")

# Family name -> fixture files. Every family the card lists
# must stay covered by at least one fixture.
FAMILIES = {
    "compatible golden": [
        "compatible_golden.json",
    ],
    "class shape": [
        "class_missing.json",
        "unit_unknown.json",
        "unit_mismatch.json",
    ],
    "scope": [
        "scope_mismatch.json",
        "scope_unknown.json",
    ],
    "capture binding": [
        "profile_mismatch.json",
        "workload_mismatch.json",
        "epoch_mismatch.json",
        "device_binding.json",
    ],
    "coverage": [
        "coverage_mismatch.json",
    ],
    "atomicity": [
        "atomicity_mismatch.json",
        "atomicity_unknown.json",
        "race_uncertainty.json",
        "uncertainty_saturating.json",
    ],
    "time bounds": [
        "clock_mismatch.json",
        "clock_unknown.json",
        "window_mismatch.json",
    ],
    "journal": [
        "journal_scope_mismatch.json",
        "partial_journal.json",
    ],
    "delta stage": [
        "value_unknown.json",
        "delta_overflow.json",
    ],
    "invalid input": [
        "duplicate_class.json",
        "invalid_window.json",
        "invalid_count.json",
        "invalid_coverage.json",
        "invalid_journal.json",
        "invalid_atomicity.json",
        "invalid_scope.json",
        "invalid_clock.json",
    ],
}

# Reason codes of the snapshot contract. The word list
# stays in lockstep with the per-class predicate and with
# the order list below. Reasons are hyphenated slugs per
# the frozen catalog label rule; closed enums keep
# underscores.
REASONS = (
    "compatible",
    "class-missing",
    "unit-unknown",
    "unit-mismatch",
    "scope-unknown",
    "scope-mismatch",
    "profile-mismatch",
    "workload-mismatch",
    "epoch-mismatch",
    "device-binding-mismatch",
    "coverage-mismatch",
    "atomicity-unknown",
    "atomicity-mismatch",
    "clock-unknown",
    "clock-mismatch",
    "window-mismatch",
    "journal-scope-mismatch",
    "partial-journal",
    "value-unknown",
    "delta-overflow",
    "duplicate-class",
    "invalid-window",
    "invalid-count",
    "invalid-coverage",
    "invalid-journal",
    "invalid-atomicity",
    "invalid-scope",
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

# Truth the guest census must never claim: ordinary counts
# carry no platform-confidential meaning and no
# physical/host truth.
FORBIDDEN_MEANINGS = (
    "physical",
    "rmp",
    "snp",
    "sev",
    "tdx",
    "host truth",
    "host-truth",
)

# Frozen CensusDelta row fields. Refused rows omit the
# delta triple and the uncertainty; compatible rows with a
# null delta add the delta reason.
ROW_FIELDS = {
    "class_id",
    "compatibility",
    "reason",
    "left_evidence",
    "right_evidence",
    "delta",
    "delta_reason",
    "uncertainty",
    "unit",
    "scope",
    "quality",
}

QUALITY_CHANNELS = (
    "detail",
    "aggregate",
    "identity",
    "baseline",
    "terminal",
)


def load_fixture(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return json.load(handle)


def all_fixtures():
    names = []
    for files in FAMILIES.values():
        names.extend(files)
    return names


def count_by_id(snapshot, class_id):
    for count in snapshot["counts"]:
        if count["class_id"] == class_id:
            return count
    return None


# ASCII whitespace for the shared blank definition:
# space, tab, line feed, carriage return, vertical tab,
# form feed.
ASCII_WHITESPACE = " \t\n\r\x0b\x0c"


def is_blank(value):
    """A meaning-carrying string counts as missing when it
    is empty or every character is ASCII whitespace. This
    definition is shared verbatim with the Rust census
    module so both sides always agree."""
    return value == "" or all(c in ASCII_WHITESPACE for c in value)


def has_control(value):
    """A string carries a control character when any
    codepoint is U+0000-U+001F or U+007F-U+009F. This
    definition is shared verbatim with the Rust census
    module. ASCII whitespace overlaps this range, so
    callers check blankness first: a blank string is
    missing, never malformed."""
    return any("\x00" <= c <= "\x1f" or "\x7f" <= c <= "\x9f"
               for c in value)


# Frozen atomicity modes: a single atomic read, a sweep
# over the window, or unknown. Unknown never compares.
ATOMICITY_MODES = ("atomic", "interval", "unknown")


def validate_snapshot(snapshot):
    """Independent input validation over one snapshot.

    Order within a snapshot: repeated class id, backward
    window, count pairing, coverage content, journal
    content, atomicity pairing, then scope and clock
    content. A null value needs a non-blank reason free
    of control characters; a present value takes none.
    Coverage entries must be unique, non-blank, and free
    of control characters. The journal scope id must be
    non-blank. An uncertainty bound is required exactly
    when races were observed, and the mode must name the
    frozen vocabulary. A non-blank scope or clock with a
    control character is malformed. Returns the refusal
    reason, or None when the snapshot validates. Callers
    validate the left snapshot before the right.
    """
    seen = set()
    for count in snapshot["counts"]:
        if count["class_id"] in seen:
            return "duplicate-class"
        seen.add(count["class_id"])
    if (int(snapshot["window"]["start"])
            > int(snapshot["window"]["end"])):
        return "invalid-window"
    for count in snapshot["counts"]:
        if (is_blank(count["class_id"])
                or has_control(count["class_id"])):
            return "invalid-count"
        value = count["value"]
        reason = count.get("value_reason")
        if value is not None:
            if reason is not None:
                return "invalid-count"
        elif reason is None or is_blank(reason):
            return "invalid-count"
        elif has_control(reason):
            return "invalid-count"
    seen_coverage = set()
    for source in snapshot["coverage"]:
        if (is_blank(source) or has_control(source)
                or source in seen_coverage):
            return "invalid-coverage"
        seen_coverage.add(source)
    journal = snapshot["journal"]
    if is_blank(journal["scope_id"]) or has_control(journal["scope_id"]):
        return "invalid-journal"
    atomicity = snapshot["atomicity"]
    if atomicity["mode"] not in ATOMICITY_MODES:
        return "invalid-atomicity"
    bound = atomicity.get("uncertainty_bound")
    if atomicity["races_observed"] != (bound is not None):
        return "invalid-atomicity"
    scope = snapshot["scope"]
    if not is_blank(scope) and has_control(scope):
        return "invalid-scope"
    clock = snapshot["window"]["clock_domain"]
    if not is_blank(clock) and has_control(clock):
        return "invalid-clock"
    return None


def expect_compatible(left_count, right_count):
    """Independent delta oracle: exact difference or null."""
    if left_count["value"] is None or right_count["value"] is None:
        return None, "value-unknown"
    delta = int(right_count["value"]) - int(left_count["value"])
    if delta < -(2 ** 63) or delta > 2 ** 63 - 1:
        return None, "delta-overflow"
    return delta, None


U64_MAX = 2 ** 64 - 1


def bound_of(snapshot):
    """Stated race bound: the recorded bound when races
    were observed, else zero. Validation already paired
    the bound with the race flag."""
    if not snapshot["atomicity"]["races_observed"]:
        return 0
    return int(snapshot["atomicity"]["uncertainty_bound"])


def expect_uncertainty(left, right):
    """Independent uncertainty oracle: the saturating sum
    of both sides' stated race bounds, as a canonical u64
    decimal string. A pair observed without races states
    zero; saturation keeps the bound representable."""
    return str(min(bound_of(left) + bound_of(right), U64_MAX))


# Frozen census unit vocabulary from the exposure
# catalog (units ["bytes", "unknown"]): only these labels
# compare; anything else (a blank label included) refuses
# as unknown and records the unknown result unit. Count
# metrics use "unknown": no admitted source freezes an
# event-count unit, and only a catalog revision may add one.
KNOWN_UNITS = ("bytes", "unknown")


def expect_unit(left, right, class_id, reason):
    """Independent result-unit oracle: the emitted label.

    A unit-unknown refusal never copies the invalid
    input label; it records the unknown unit. A
    class-missing row carries the present side's unit
    only when it names the frozen vocabulary, else
    unknown. Every other row carries the left side's
    unit: the unit checks already proved both equal.
    """
    if reason == "unit-unknown":
        return "unknown"
    anchor = count_by_id(left, class_id) \
        or count_by_id(right, class_id)
    if (reason == "class-missing"
            and anchor["unit"] not in KNOWN_UNITS):
        return "unknown"
    return anchor["unit"]


def expect_row(case, left, right, class_id):
    """Independent compatibility predicate over one class."""
    left_count = count_by_id(left, class_id)
    right_count = count_by_id(right, class_id)
    if left_count is None or right_count is None:
        return ("unavailable", "class-missing", "absent")
    if (left_count["unit"] not in KNOWN_UNITS
            or right_count["unit"] not in KNOWN_UNITS):
        return ("incompatible", "unit-unknown", "absent")
    if left_count["unit"] != right_count["unit"]:
        return ("incompatible", "unit-mismatch", "absent")
    if is_blank(left["scope"]) or is_blank(right["scope"]):
        return ("incompatible", "scope-unknown", "absent")
    if left["scope"] != right["scope"]:
        return ("incompatible", "scope-mismatch", "absent")
    if left["profile_id"] != right["profile_id"]:
        return ("incompatible", "profile-mismatch", "absent")
    if left["workload"] != right["workload"]:
        return ("incompatible", "workload-mismatch", "absent")
    if left["epoch"] != right["epoch"]:
        return ("incompatible", "epoch-mismatch", "absent")
    if left["platform_cell"] != right["platform_cell"]:
        return ("incompatible", "device-binding-mismatch", "absent")
    if sorted(left["coverage"]) != sorted(right["coverage"]):
        return ("incompatible", "coverage-mismatch", "absent")
    left_mode = left["atomicity"]["mode"]
    right_mode = right["atomicity"]["mode"]
    if left_mode == "unknown" or right_mode == "unknown":
        return ("incompatible", "atomicity-unknown", "absent")
    if left_mode != right_mode:
        return ("incompatible", "atomicity-mismatch", "absent")
    left_clock = left["window"]["clock_domain"]
    right_clock = right["window"]["clock_domain"]
    if is_blank(left_clock) or is_blank(right_clock):
        return ("incompatible", "clock-unknown", "absent")
    if left_clock != right_clock:
        return ("incompatible", "clock-mismatch", "absent")
    if (left["window"]["start"] != right["window"]["start"]
            or left["window"]["end"] != right["window"]["end"]):
        return ("incompatible", "window-mismatch", "absent")
    if left["journal"]["scope_id"] != right["journal"]["scope_id"]:
        return ("incompatible", "journal-scope-mismatch", "absent")
    if not left["journal"]["complete"] or not right["journal"]["complete"]:
        return ("incompatible", "partial-journal", "absent")
    delta, reason = expect_compatible(left_count, right_count)
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
            refusal = (validate_snapshot(left)
                       or validate_snapshot(right))
            assert refusal == fixture["refused"], \
                "%s: want refusal %s got %r" % (
                    name, fixture["refused"], refusal)
            assert "expected" not in fixture, \
                "%s: refused input carries rows" % name
            continue
        assert validate_snapshot(left) is None, \
            "%s: left snapshot invalid" % name
        assert validate_snapshot(right) is None, \
            "%s: right snapshot invalid" % name
        seen = set()
        for row in fixture["expected"]:
            class_id = row["class_id"]
            assert class_id not in seen, \
                "%s: duplicate row %s" % (name, class_id)
            seen.add(class_id)
            compatibility, reason, delta = expect_row(
                fixture["case"], left, right, class_id)
            assert row["compatibility"] == compatibility, \
                "%s/%s: want %s got %s" % (
                    name, class_id, compatibility,
                    row["compatibility"])
            assert row["reason"] == reason, \
                "%s/%s: want %s got %s" % (
                    name, class_id, reason, row["reason"])
            if delta == "absent":
                assert "delta" not in row, \
                    "%s/%s: refused class carries a delta" % (
                        name, class_id)
                assert "delta_reason" not in row
                assert "uncertainty" not in row, \
                    "%s/%s: refused class states uncertainty" % (
                        name, class_id)
            elif delta[0] == "null":
                assert row.get("delta") is None, \
                    "%s/%s: want null delta" % (name, class_id)
                assert row.get("delta_reason") == delta[1], \
                    "%s/%s: want %s" % (name, class_id, delta[1])
                assert row["uncertainty"] == expect_uncertainty(
                    left, right), \
                    "%s/%s: uncertainty follows the oracle" % (
                        name, class_id)
            else:
                assert row["delta"] == delta[1], \
                    "%s/%s: want %d got %r" % (
                        name, class_id, delta[1],
                        row.get("delta"))
                assert row["uncertainty"] == expect_uncertainty(
                    left, right), \
                    "%s/%s: uncertainty follows the oracle" % (
                        name, class_id)
            assert row["left_evidence"] == left["evidence_id"]
            assert row["right_evidence"] == right["evidence_id"]
            assert row["unit"] == expect_unit(
                left, right, class_id, reason), \
                "%s/%s: unit follows the oracle" % (
                    name, class_id)
            assert row["scope"] == left["scope"], \
                "%s/%s: scope follows the left snapshot" % (
                    name, class_id)
            assert row["quality"] == expect_quality(
                compatibility, delta), \
                "%s/%s: quality derives from the row" % (
                    name, class_id)
        ids = {c["class_id"] for c in left["counts"]}
        ids |= {c["class_id"] for c in right["counts"]}
        assert seen == ids, \
            "%s: expected rows %s miss classes %s" % (
                name, sorted(seen), sorted(ids))


def test_refused_rows_carry_no_numbers():
    for name in all_fixtures():
        fixture = load_fixture(name)
        if "refused" in fixture:
            continue
        for row in fixture["expected"]:
            if row["compatibility"] in ("incompatible", "unavailable"):
                assert "delta" not in row, \
                    "%s/%s: numeric delta on %s" % (
                        name, row["class_id"],
                        row["compatibility"])
                assert "delta_reason" not in row
                assert "uncertainty" not in row, \
                    "%s/%s: uncertainty on %s" % (
                        name, row["class_id"],
                        row["compatibility"])


def test_expected_rows_match_contract_fields():
    for name in all_fixtures():
        fixture = load_fixture(name)
        if "refused" in fixture:
            continue
        for row in fixture["expected"]:
            assert set(row) <= ROW_FIELDS, \
                "%s/%s: unknown fields %s" % (
                    name, row["class_id"],
                    sorted(set(row) - ROW_FIELDS))
            required = ROW_FIELDS - {"delta", "delta_reason",
                                     "uncertainty"}
            for field in required:
                assert field in row, \
                    "%s/%s: missing %s" % (
                        name, row["class_id"], field)
            assert set(row["quality"]) == set(QUALITY_CHANNELS), \
                "%s/%s: quality channels drift" % (
                    name, row["class_id"])


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
            left = count_by_id(fixture["left"], row["class_id"])
            right = count_by_id(fixture["right"], row["class_id"])
            assert row["delta"] == (
                int(right["value"]) - int(left["value"])), \
                "%s/%s: delta nets journal events" % (
                    name, row["class_id"])


def test_no_conclusion_or_foreign_meaning_language():
    for name in all_fixtures():
        text = json.dumps(load_fixture(name)).lower()
        for phrase in FORBIDDEN_CONCLUSIONS:
            assert phrase not in text, \
                "%s: forbidden conclusion %r" % (name, phrase)
        for token in FORBIDDEN_MEANINGS:
            assert token not in text, \
                "%s: foreign meaning %r" % (name, token)


def test_reason_codes_implemented_in_rust_module():
    with open(RUST_MODULE, encoding="utf-8") as handle:
        module = handle.read()
    for reason in REASONS:
        assert '"%s"' % reason in module, \
            "rust module never emits reason %s" % reason


def test_rust_suite_covers_every_fixture():
    with open(RUST_TEST, encoding="utf-8") as handle:
        suite = handle.read()
    for name in all_fixtures():
        case = load_fixture(name)["case"]
        assert case in suite, \
            "rust suite never mentions case %s" % case
    assert "exposure_census" in suite, \
        "rust suite never binds the census module"


# Per-class refusal reasons in predicate order. The
# order test walks adjacent pairs through the oracle,
# and the module-order test requires the Rust module
# to list this same sequence.
CHECK_ORDER = (
    "class-missing",
    "unit-unknown",
    "unit-mismatch",
    "scope-unknown",
    "scope-mismatch",
    "profile-mismatch",
    "workload-mismatch",
    "epoch-mismatch",
    "device-binding-mismatch",
    "coverage-mismatch",
    "atomicity-unknown",
    "atomicity-mismatch",
    "clock-unknown",
    "clock-mismatch",
    "window-mismatch",
    "journal-scope-mismatch",
    "partial-journal",
)


def base_pair():
    """Two fully compatible snapshots with one count."""
    def side(evidence):
        return {
            "atomicity": {"mode": "atomic",
                         "races_observed": False},
            "counts": [{
                "class_id": "x",
                "unit": "unknown",
                "value": "1",
            }],
            "coverage": ["census-sweep"],
            "epoch": "41",
            "evidence_id": evidence,
            "journal": {"complete": True,
                       "scope_id": "journal-main"},
            "platform_cell": "ordinary-guest-01",
            "profile_id": "linux-x86_64-7.0-reference",
            "scope": "guest-view",
            "window": {"clock_domain": "guest_monotonic_active",
                       "end": "2000", "start": "1000"},
            "workload": "idle-snapshot",
        }

    left = side("snap-left-order")
    right = side("snap-right-order")
    right["counts"][0]["value"] = "9"
    return left, right


def break_check(reason, left, right):
    """Fail exactly one compatibility check on the pair."""
    count = right["counts"][0]
    if reason == "class-missing":
        right["counts"] = []
    elif reason == "unit-unknown":
        left["counts"][0]["unit"] = ""
    elif reason == "unit-mismatch":
        count["unit"] = "bytes"
    elif reason == "scope-unknown":
        left["scope"] = ""
    elif reason == "scope-mismatch":
        right["scope"] = "guest-view-narrow"
    elif reason == "profile-mismatch":
        right["profile_id"] = "linux-x86_64-7.0-hardened"
    elif reason == "workload-mismatch":
        right["workload"] = "io-batch"
    elif reason == "epoch-mismatch":
        right["epoch"] = "42"
    elif reason == "device-binding-mismatch":
        right["platform_cell"] = "ordinary-guest-02"
    elif reason == "coverage-mismatch":
        right["coverage"] = ["census-sweep", "census-resweep"]
    elif reason == "atomicity-unknown":
        left["atomicity"]["mode"] = "unknown"
    elif reason == "atomicity-mismatch":
        right["atomicity"]["mode"] = "interval"
    elif reason == "clock-unknown":
        left["window"]["clock_domain"] = ""
    elif reason == "clock-mismatch":
        right["window"]["clock_domain"] = "guest_boottime_elapsed"
    elif reason == "window-mismatch":
        right["window"]["end"] = "3000"
    elif reason == "journal-scope-mismatch":
        right["journal"]["scope_id"] = "journal-retry"
    elif reason == "partial-journal":
        right["journal"]["complete"] = False
    else:  # pragma: no cover
        raise AssertionError("no breaker for %s" % reason)


def test_checks_run_in_documented_order():
    for index in range(len(CHECK_ORDER) - 1):
        earlier = CHECK_ORDER[index]
        later = CHECK_ORDER[index + 1]
        if earlier == "class-missing":
            continue  # absence preempts every check; see below
        left, right = base_pair()
        break_check(earlier, left, right)
        break_check(later, left, right)
        assert validate_snapshot(left) is None
        assert validate_snapshot(right) is None
        compatibility, reason, _delta = expect_row(
            "order", left, right, "x")
        assert compatibility == "incompatible", (earlier, later)
        assert reason == earlier, \
            "want %s before %s, got %s" % (earlier, later, reason)
    # A missing class preempts every later check at once.
    left, right = base_pair()
    for reason in CHECK_ORDER:
        if reason != "class-missing":
            break_check(reason, left, right)
    break_check("class-missing", left, right)
    compatibility, reason, _delta = expect_row(
        "order", left, right, "x")
    assert (compatibility, reason) == ("unavailable", "class-missing")
    # The last check beats the delta stage: a partial
    # journal with an unknown value still refuses.
    left, right = base_pair()
    break_check("partial-journal", left, right)
    left["counts"][0]["value"] = None
    left["counts"][0]["value_reason"] = "source-unavailable"
    compatibility, reason, _delta = expect_row(
        "order", left, right, "x")
    assert (compatibility, reason) == ("incompatible", "partial-journal")
    # Validation order mirrors the product: duplicates beat
    # a backward window, and the left snapshot goes first.
    left, right = base_pair()
    left["counts"].append(dict(left["counts"][0]))
    left["window"]["start"] = "3000"
    left["window"]["end"] = "2000"
    assert validate_snapshot(left) == "duplicate-class"
    left, right = base_pair()
    left["counts"][0]["value"] = None
    right["counts"].append(dict(right["counts"][0]))
    assert validate_snapshot(left) == "invalid-count"
    assert validate_snapshot(right) == "duplicate-class"
    assert (validate_snapshot(left) or validate_snapshot(right)) \
        == "invalid-count"
    # Malformed content refuses after the pairing rules: a
    # bad count beats a bad scope, which beats a bad clock,
    # and the left snapshot still goes first.
    left, right = base_pair()
    left["counts"][0]["value"] = None
    left["counts"][0]["value_reason"] = None
    left["scope"] = "\x1c"
    assert validate_snapshot(left) == "invalid-count"
    left, right = base_pair()
    left["scope"] = "\x1c"
    left["window"]["clock_domain"] = "\x1c"
    assert validate_snapshot(left) == "invalid-scope"
    left, right = base_pair()
    left["window"]["clock_domain"] = "\x1c"
    right["scope"] = "\x1c"
    assert validate_snapshot(left) == "invalid-clock"
    assert validate_snapshot(right) == "invalid-scope"
    assert (validate_snapshot(left) or validate_snapshot(right)) \
        == "invalid-clock"


def test_rust_module_follows_check_order():
    with open(RUST_MODULE, encoding="utf-8") as handle:
        module = handle.read()
    positions = [module.index('"%s"' % reason)
                 for reason in CHECK_ORDER]
    assert positions == sorted(positions), \
        "rust module lists checks out of order"
    assert len(set(positions)) == len(positions)


def test_blank_scopes_are_unknown():
    # A blank scope records no scope: empty or
    # whitespace-only on either side, or both, refuses
    # the class as unknown with no delta. Two blanks
    # are not equal; blank against changed is unknown,
    # never a change.
    cases = [
        ("", ""),
        ("", "guest-view"),
        ("guest-view", ""),
        ("   ", "guest-view"),
        ("guest-view", "   "),
        ("", "guest-view-narrow"),
    ]
    for left_blank, right_blank in cases:
        left, right = base_pair()
        left["scope"] = left_blank
        right["scope"] = right_blank
        assert validate_snapshot(left) is None
        assert validate_snapshot(right) is None
        assert expect_row("blank", left, right, "x") == (
            "incompatible", "scope-unknown", "absent"), \
            (left_blank, right_blank)
