#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lease-free self-tests for authored exposure fixture ledgers.

These tests exercise only the independent fixture oracle under
``tests/exposure/`` and the authored per-scenario case files. They never
touch the collector, never load a kernel module, and never require a
guest lease. Expected ledgers are authored by hand; nothing here is
derived from collector output. The frozen capability catalog is read
only to cross-check scenario identities.

Vacuity rule: an empty expected ledger never compares equal, so a
missing or dropped expectation cannot pass silently.
"""
import copy
import json
import re
import sys
import tempfile
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
EXPOSURE_DIR = ROOT / "tests" / "exposure"
CATALOG = ROOT / "profiles" / "exposure" / "catalog.json"
sys.path.insert(0, str(ROOT))

from tests.exposure.oracle import (  # noqa: E402
    CATALOG_VERSION,
    FixtureError,
    LedgerMismatch,
    compare_entries,
    derive_events,
    load_case,
    load_manifest,
    verify_case,
)

GOOD = [
    {"object_token": "buf-a-1", "generation": "1", "pages": "2", "status": "live"},
    {"object_token": "buf-a-2", "generation": "1", "pages": "1", "status": "live"},
]

ADDRESS_RE = re.compile(r"0[xX][0-9a-fA-F]{2,}|%p|pfn\s*=")


class VacuitySelfTests(unittest.TestCase):
    def test_matching_ledgers_compare_equal(self):
        self.assertEqual(compare_entries(GOOD, GOOD, "vacuity"), 2)

    def test_wrong_token_fails(self):
        bad = [dict(GOOD[0], object_token="buf-a-9"), GOOD[1]]
        with self.assertRaises(LedgerMismatch):
            compare_entries(GOOD, bad, "vacuity")

    def test_missing_token_fails(self):
        with self.assertRaises(LedgerMismatch):
            compare_entries(GOOD, GOOD[:1], "vacuity")

    def test_duplicate_token_fails(self):
        with self.assertRaises(LedgerMismatch):
            compare_entries(GOOD, GOOD + GOOD[:1], "vacuity")

    def test_reordered_entries_fail(self):
        with self.assertRaises(LedgerMismatch):
            compare_entries(GOOD, list(reversed(GOOD)), "vacuity")

    def test_empty_ledgers_never_compare_equal(self):
        for expected, actual in (([], []), (GOOD, []), ([], GOOD)):
            with self.subTest(expected=expected, actual=actual):
                with self.assertRaises(LedgerMismatch):
                    compare_entries(expected, actual, "vacuity")

    def test_fixture_errors_are_distinct_from_mismatches(self):
        self.assertTrue(issubclass(FixtureError, ValueError))
        self.assertTrue(issubclass(LedgerMismatch, ValueError))
        self.assertIsNot(FixtureError, LedgerMismatch)


def load_manifest_once():
    return load_manifest(EXPOSURE_DIR / "cases.json")


class ManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest_once()
        cls.catalog = json.loads(CATALOG.read_text(encoding="utf-8"))

    def test_ten_spec_scenarios(self):
        specs = self.manifest["spec_scenarios"]
        self.assertEqual(len(specs), 10)
        self.assertEqual([entry["id"] for entry in specs],
                         [f"spec-{number:02d}" for number in range(1, 11)])

    def test_every_spec_scenario_maps_to_at_least_one_case(self):
        for entry in self.manifest["spec_scenarios"]:
            with self.subTest(spec=entry["id"]):
                self.assertTrue(entry["cases"])

    def test_every_case_is_mapped_by_some_spec_scenario(self):
        mapped = {case_id for entry in self.manifest["spec_scenarios"]
                  for case_id in entry["cases"]}
        for entry in self.manifest["cases"]:
            with self.subTest(case=entry["id"]):
                self.assertIn(entry["id"], mapped)

    def test_case_files_exist_and_match_manifest(self):
        for entry in self.manifest["cases"]:
            with self.subTest(case=entry["id"]):
                path = EXPOSURE_DIR / entry["file"]
                self.assertTrue(path.is_file(), path)
                case = load_case(path)
                self.assertEqual(case["scenario"], entry["id"])

    def test_catalog_cross_check_is_exact_and_read_only(self):
        catalog_ids = {scenario["id"] for scenario in self.catalog["scenarios"]}
        manifest_ids = {entry["id"] for entry in self.manifest["cases"]}
        self.assertEqual(manifest_ids, catalog_ids)
        self.assertEqual(self.catalog["exposure_catalog_version"], CATALOG_VERSION)
        for entry in self.manifest["cases"]:
            with self.subTest(case=entry["id"]):
                case = load_case(EXPOSURE_DIR / entry["file"])
                catalog_entry = next(item for item in self.catalog["scenarios"]
                                     if item["id"] == entry["id"])
                self.assertEqual(case["family"], catalog_entry["family"])
                self.assertEqual(case["namespace"], catalog_entry["namespace"])


def mutate(path, change):
    """Return the path of a temp copy of a case file with one change applied."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    change(data)
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8")
    with handle:
        json.dump(data, handle)
    return handle.name


class ScenarioTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest_once()
        cls.files = {entry["id"]: EXPOSURE_DIR / entry["file"]
                     for entry in cls.manifest["cases"]}
        cls.cases = {case_id: load_case(path) for case_id, path in cls.files.items()}

    def assert_rejected(self, path, change, label):
        tmp = mutate(path, change)
        try:
            try:
                case = load_case(tmp)
            except FixtureError:
                return
            with self.assertRaises(FixtureError, msg=label):
                verify_case(case)
        finally:
            Path(tmp).unlink()

    def test_positive_all_ten_spec_scenarios(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                with self.subTest(spec=entry["id"], case=case_id):
                    case = self.cases[case_id]
                    summary = verify_case(case)
                    self.assertEqual(summary["scenario"], case_id)
                    events = derive_events(case)
                    self.assertEqual(summary["events"], len(events))
                    self.assertGreater(len(events), 0)
                    self.assertEqual(compare_entries(events, events, case_id),
                                     len(events))

    def test_negative_wrong_missing_duplicate_tokens(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                path = self.files[case_id]
                if not self.cases[case_id]["after_ledger"]:
                    continue
                with self.subTest(spec=entry["id"], case=case_id, mutation="wrong"):
                    self.assert_rejected(
                        path,
                        lambda data: data["after_ledger"][0].update(
                            object_token="buf-foreign-1"),
                        "wrong token must fail")
                with self.subTest(spec=entry["id"], case=case_id, mutation="missing"):
                    self.assert_rejected(
                        path,
                        lambda data: data["after_ledger"].pop(),
                        "missing token must fail")
                with self.subTest(spec=entry["id"], case=case_id, mutation="duplicate"):
                    self.assert_rejected(
                        path,
                        lambda data: data["after_ledger"].append(
                            copy.deepcopy(data["after_ledger"][0])),
                        "duplicate token must fail")

    def test_negative_wrong_counts_and_reordered_events(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                path = self.files[case_id]
                case = self.cases[case_id]
                with self.subTest(spec=entry["id"], case=case_id, mutation="pages"):
                    if case["after_ledger"]:
                        self.assert_rejected(
                            path,
                            lambda data: data["after_ledger"][0].update(pages="7"),
                            "wrong page count must fail")
                    else:
                        self.assert_rejected(
                            path,
                            lambda data: data["control_flow"][0].update(pages="9"),
                            "page count above the small bound must fail")
                with self.subTest(spec=entry["id"], case=case_id, mutation="non-canonical"):
                    target = ("after_ledger" if case["after_ledger"] else "control_flow")
                    self.assert_rejected(
                        path,
                        lambda data: data[target][0].update(pages="03"),
                        "non-canonical count must fail")
                with self.subTest(spec=entry["id"], case=case_id, mutation="dropped-step"):
                    self.assert_rejected(
                        path,
                        lambda data: data["control_flow"].pop(0),
                        "dropped control step must fail")
                with self.subTest(spec=entry["id"], case=case_id, mutation="reorder"):
                    events = derive_events(case)
                    self.assertGreater(len(events), 1)
                    with self.assertRaises(LedgerMismatch):
                        compare_entries(events, list(reversed(events)), case_id)

    def test_negative_address_like_and_unknown_tokens(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                path = self.files[case_id]
                with self.subTest(spec=entry["id"], case=case_id):
                    self.assert_rejected(
                        path,
                        lambda data: data["control_flow"][0].update(
                            operation="op-0x1234"),
                        "address-like token must fail")

    def test_vacuity_empty_control_flow_rejected(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                with self.subTest(spec=entry["id"], case=case_id):
                    self.assert_rejected(
                        self.files[case_id],
                        lambda data: data.update(control_flow=[]),
                        "empty control flow must fail")

    def test_vacuity_empty_actual_ledger_rejected(self):
        for entry in self.manifest["spec_scenarios"]:
            for case_id in entry["cases"]:
                case = self.cases[case_id]
                if not case["after_ledger"]:
                    continue
                with self.subTest(spec=entry["id"], case=case_id):
                    with self.assertRaises(LedgerMismatch):
                        compare_entries(case["after_ledger"], [], case_id)

    def test_vacuity_zero_conversion_case_still_observes(self):
        case = self.cases["conversion-request-result"]
        summary = verify_case(case)
        self.assertEqual((summary["before"], summary["after"]), (0, 0))
        self.assertGreater(summary["events"], 0)
        with self.assertRaises(LedgerMismatch):
            compare_entries(case["after_ledger"], case["after_ledger"],
                            "conversion-request-result")


class PrivacyTests(unittest.TestCase):
    def test_no_address_like_content_in_fixtures(self):
        files = [EXPOSURE_DIR / "cases.json"]
        files += sorted((EXPOSURE_DIR / "cases").glob("*.json"))
        self.assertGreater(len(files), 15)
        for path in files:
            with self.subTest(file=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertIsNone(ADDRESS_RE.search(text), text)
                self.assertNotIn("0x", text)

    def test_every_case_states_independent_authorship(self):
        manifest = load_manifest_once()
        for entry in manifest["cases"]:
            with self.subTest(case=entry["id"]):
                case = load_case(EXPOSURE_DIR / entry["file"])
                self.assertIn("authored", case["provenance"])


if __name__ == "__main__":
    unittest.main()
