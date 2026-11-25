# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent oracle for authored exposure fixture ledgers.

This module compares hand-authored before/after ledgers and fixture
control flows. It is deliberately independent of the collector: it
reads only the fixture manifest, the per-scenario case files and the
frozen read-only capability catalog. Fixture tokens are session-local
labels, never addresses, and fixture data must never be fed into
collector observations.

Vacuity rule: comparing against an empty expected ledger always
raises :class:`LedgerMismatch`, so a dropped expectation cannot pass
silently. Fixture structure problems raise :class:`FixtureError`.
"""
import json
import re
from pathlib import Path

MANIFEST_FORMAT = "exposure-fixture-manifest/0.1.0"
CASE_FORMAT = "exposure-fixture-case/0.1.0"
CATALOG_VERSION = "0.1.0"

# Lifecycle states shared with the frozen capability catalog.
LIFECYCLE_STATUSES = ("created", "live", "released", "quarantined", "unknown")

# Session-local token spelling: short lowercase labels. Anything that
# looks like an address or a format string is rejected outright.
TOKEN_RE = re.compile(r"[a-z][a-z0-9-]{0,63}\Z")
ADDRESS_RE = re.compile(r"0[xX][0-9a-fA-F]+|%p|pfn\s*=")

# Canonical u64 decimal strings: no signs, leading zeros, fractions or
# scientific notation; range checked against 2**64 - 1.
U64_RE = re.compile(r"(0|[1-9][0-9]{0,19})\Z")
U64_MAX = 18446744073709551615

# Fixture page counts stay exact and small; the test-only oracle
# module refuses anything above this ceiling.
MAX_FIXTURE_PAGES = 256
SMALL_FIXTURE_PAGES = 8

LEDGER_KEYS = ("object_token", "generation", "pages", "status")
STEP_KEYS = ("ordinal", "operation", "object", "pages", "native_result", "action")


class FixtureError(ValueError):
    """A fixture file is malformed."""


class LedgerMismatch(ValueError):
    """Two ledgers disagree, or a comparison is vacuous."""


def is_canonical_u64(text):
    """Return True only for canonical u64 decimal strings."""
    return (isinstance(text, str) and U64_RE.match(text) is not None
            and int(text) <= U64_MAX)


def check_token(token, what):
    """Validate a session-local token; reject anything address-like."""
    if not isinstance(token, str) or TOKEN_RE.match(token) is None:
        raise FixtureError(f"{what}: malformed token {token!r}")
    if ADDRESS_RE.search(token):
        raise FixtureError(f"{what}: address-like token {token!r}")
    return token


def scan_no_addresses(value, what):
    """Reject address-like or format-string content anywhere nested."""
    if isinstance(value, str):
        if ADDRESS_RE.search(value):
            raise FixtureError(f"{what}: forbidden address-like content {value!r}")
    elif isinstance(value, dict):
        for key, item in value.items():
            scan_no_addresses(key, what)
            scan_no_addresses(item, what)
    elif isinstance(value, (list, tuple)):
        for item in value:
            scan_no_addresses(item, what)
    return value


def check_pages(pages, what):
    """Validate an exact fixture page count."""
    if not is_canonical_u64(pages):
        raise FixtureError(f"{what}: pages must be a canonical u64 string, got {pages!r}")
    count = int(pages)
    if not 1 <= count <= MAX_FIXTURE_PAGES:
        raise FixtureError(f"{what}: pages out of range 1..{MAX_FIXTURE_PAGES}: {pages!r}")
    return count


def _load_json(path):
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise FixtureError(f"missing fixture file: {path}")
    except (OSError, UnicodeDecodeError) as exc:
        raise FixtureError(f"unreadable fixture file {path}: {exc}")
    except json.JSONDecodeError as exc:
        raise FixtureError(f"invalid JSON in {path}: {exc}")


def load_manifest(path):
    """Load and strictly validate the fixture manifest."""
    data = _load_json(path)
    if not isinstance(data, dict):
        raise FixtureError("manifest must be a JSON object")
    if data.get("format") != MANIFEST_FORMAT:
        raise FixtureError(f"manifest format must be {MANIFEST_FORMAT!r}")
    if data.get("catalog_version") != CATALOG_VERSION:
        raise FixtureError(f"manifest must pin catalog {CATALOG_VERSION!r}")
    scenarios = data.get("spec_scenarios")
    cases = data.get("cases")
    if not isinstance(scenarios, list) or not scenarios:
        raise FixtureError("manifest needs a non-empty spec_scenarios list")
    if not isinstance(cases, list) or not cases:
        raise FixtureError("manifest needs a non-empty cases list")
    seen_specs, seen_cases = set(), set()
    for entry in scenarios:
        if not isinstance(entry, dict):
            raise FixtureError("spec scenario entries must be objects")
        spec = entry.get("id")
        check_token(spec, "spec scenario id")
        if spec in seen_specs:
            raise FixtureError(f"duplicate spec scenario id {spec!r}")
        seen_specs.add(spec)
        if not isinstance(entry.get("title"), str) or not entry["title"]:
            raise FixtureError(f"spec scenario {spec!r} needs a non-empty title")
        mapped = entry.get("cases")
        if not isinstance(mapped, list) or not mapped:
            raise FixtureError(f"spec scenario {spec!r} needs a non-empty cases list")
        for case_id in mapped:
            check_token(case_id, f"spec scenario {spec!r} mapping")
    for entry in cases:
        if not isinstance(entry, dict):
            raise FixtureError("case entries must be objects")
        case_id = entry.get("id")
        check_token(case_id, "case id")
        if case_id in seen_cases:
            raise FixtureError(f"duplicate case id {case_id!r}")
        seen_cases.add(case_id)
        if not isinstance(entry.get("file"), str) or not entry["file"]:
            raise FixtureError(f"case {case_id!r} needs a file path")
    scan_no_addresses(data, "manifest")
    return data


def _check_ledger(entries, what):
    if not isinstance(entries, list):
        raise FixtureError(f"{what}: ledger must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) or tuple(entry) != LEDGER_KEYS:
            raise FixtureError(f"{what}: entries need exactly keys {list(LEDGER_KEYS)}")
        token = check_token(entry["object_token"], f"{what} entry")
        if token in seen:
            raise FixtureError(f"{what}: duplicate ledger token {token!r}")
        seen.add(token)
        if not is_canonical_u64(entry["generation"]):
            raise FixtureError(f"{what}: token {token!r} needs a canonical u64 generation")
        check_pages(entry["pages"], f"{what}: token {token!r}")
        if entry["status"] not in LIFECYCLE_STATUSES:
            raise FixtureError(f"{what}: token {token!r} has unknown status {entry['status']!r}")
    return {entry["object_token"]: entry for entry in entries}


def load_case(path):
    """Load and strictly validate one authored scenario case file."""
    data = _load_json(path)
    what = f"case {Path(path).name}"
    if not isinstance(data, dict):
        raise FixtureError(f"{what}: must be a JSON object")
    for key in ("format", "provenance", "scenario", "family", "namespace",
                "control_flow", "before_ledger", "after_ledger", "expectation"):
        if key not in data:
            raise FixtureError(f"{what}: missing required key {key!r}")
    if data["format"] != CASE_FORMAT:
        raise FixtureError(f"{what}: format must be {CASE_FORMAT!r}")
    if not isinstance(data["provenance"], str) or "authored" not in data["provenance"]:
        raise FixtureError(f"{what}: provenance must state independent authorship")
    scenario = check_token(data["scenario"], f"{what} scenario")
    if not isinstance(data["family"], str) or not data["family"]:
        raise FixtureError(f"{what}: family must be a non-empty string")
    if not isinstance(data["namespace"], str) or not data["namespace"]:
        raise FixtureError(f"{what}: namespace must be a non-empty string")
    steps = data["control_flow"]
    if not isinstance(steps, list) or not steps:
        raise FixtureError(f"{what}: control_flow must be a non-empty list")
    for position, step in enumerate(steps, start=1):
        if not isinstance(step, dict) or tuple(step) != STEP_KEYS:
            raise FixtureError(f"{what}: steps need exactly keys {list(STEP_KEYS)}")
        if step["ordinal"] != str(position):
            raise FixtureError(f"{what}: step ordinals must run 1..{len(steps)} in order")
        check_token(step["operation"], f"{what} step {position} operation")
        if step["object"] != "none":
            check_token(step["object"], f"{what} step {position} object")
        check_pages(step["pages"], f"{what} step {position}")
        if not isinstance(step["native_result"], int) or isinstance(step["native_result"], bool):
            raise FixtureError(f"{what} step {position}: native_result must be an integer")
        if not isinstance(step["action"], str) or not step["action"]:
            raise FixtureError(f"{what} step {position}: action must be a non-empty string")
    before = _check_ledger(data["before_ledger"], f"{what} before_ledger")
    after = _check_ledger(data["after_ledger"], f"{what} after_ledger")
    expectation = data["expectation"]
    if not isinstance(expectation, dict):
        raise FixtureError(f"{what}: expectation must be an object")
    try:
        groups = {name: list(expectation[name])
                  for name in ("conserved", "transitioned", "added", "removed")}
    except (KeyError, TypeError):
        raise FixtureError(f"{what}: expectation needs conserved/transitioned/added/removed lists")
    for name, tokens in groups.items():
        for token in tokens:
            check_token(token, f"{what} expectation {name}")
    flat = [token for tokens in groups.values() for token in tokens]
    if len(set(flat)) != len(flat):
        raise FixtureError(f"{what}: expectation groups must be disjoint")
    if set(before) != set(groups["conserved"] + groups["transitioned"] + groups["removed"]):
        raise FixtureError(f"{what}: expectation groups must partition the before ledger")
    if set(after) != set(groups["conserved"] + groups["transitioned"] + groups["added"]):
        raise FixtureError(f"{what}: expectation groups must partition the after ledger")
    for token in groups["conserved"]:
        if before[token] != after[token]:
            raise FixtureError(f"{what}: conserved token {token!r} changed between ledgers")
    for token in groups["transitioned"]:
        if before[token] == after[token]:
            raise FixtureError(f"{what}: transitioned token {token!r} is unchanged")
    scan_no_addresses(data, what)
    data["_validated_scenario"] = scenario
    return data


def derive_events(case):
    """Derive the ordered expected event list from fixture control flow."""
    return [{"ordinal": step["ordinal"], "operation_token": step["operation"],
             "object_token": step["object"], "pages": step["pages"],
             "native_result": step["native_result"]} for step in case["control_flow"]]


def compare_entries(expected, actual, what):
    """Strictly compare two ordered entry lists.

    Wrong, missing, duplicate or reordered entries raise
    :class:`LedgerMismatch`. An empty expected list always raises so a
    dropped expectation can never pass vacuously. Returns the number
    of matched entries.
    """
    if not isinstance(expected, list) or not expected:
        raise LedgerMismatch(f"{what}: refusing to compare against an empty expected ledger")
    if not isinstance(actual, list) or not actual:
        raise LedgerMismatch(f"{what}: actual ledger is empty, expected {len(expected)} entries")
    if len(actual) != len(expected):
        raise LedgerMismatch(f"{what}: entry count {len(actual)} != expected {len(expected)}")
    for position, (want, got) in enumerate(zip(expected, actual), start=1):
        if want != got:
            raise LedgerMismatch(f"{what}: entry {position} differs: {got!r} != {want!r}")
    return len(expected)


def verify_case(case):
    """Run the positive self-check for one validated case.

    Confirms the control flow derives the authored event count, every
    control object is accounted for in the ledgers with matching exact
    page counts, and every page count stays small. Returns a summary
    dict.
    """
    what = f"case {case.get('scenario')}"
    events = derive_events(case)
    if not events:
        raise FixtureError(f"{what}: control flow derives no events")
    ledger_tokens = {entry["object_token"] for entry in case["before_ledger"]}
    ledger_tokens.update(entry["object_token"] for entry in case["after_ledger"])
    ledger_pages = {}
    for entry in case["before_ledger"] + case["after_ledger"]:
        token = entry["object_token"]
        if token in ledger_pages and ledger_pages[token] != entry["pages"]:
            raise FixtureError(f"{what}: token {token!r} changes page count between ledgers")
        ledger_pages[token] = entry["pages"]
    for event in events:
        if event["object_token"] == "none":
            continue
        if event["object_token"] not in ledger_tokens:
            raise FixtureError(f"{what}: event object {event['object_token']!r} "
                               "is in no ledger")
        if event["pages"] != ledger_pages[event["object_token"]]:
            raise FixtureError(f"{what}: event {event['ordinal']} page count differs "
                               f"from the ledger for {event['object_token']!r}")
    small = SMALL_FIXTURE_PAGES
    for entry in case["before_ledger"] + case["after_ledger"]:
        if int(entry["pages"]) > small:
            raise FixtureError(f"{what}: token {entry['object_token']!r} exceeds "
                               f"the small-fixture bound of {small} pages")
    for event in events:
        if int(event["pages"]) > small:
            raise FixtureError(f"{what}: event {event['ordinal']} exceeds "
                               f"the small-fixture bound of {small} pages")
    return {"scenario": case.get("scenario"), "events": len(events),
            "before": len(case["before_ledger"]), "after": len(case["after_ledger"])}
