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


class DistinguishingContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = load_manifest_once()
        cls.files = {entry["id"]: EXPOSURE_DIR / entry["file"]
                     for entry in cls.manifest["cases"]}
        cls.cases = {case_id: load_case(path) for case_id, path in cls.files.items()}
        cls.specs = {entry["id"]: entry["cases"]
                     for entry in cls.manifest["spec_scenarios"]}

    def spec_cases(self, spec):
        return [(case_id, self.cases[case_id]) for case_id in self.specs[spec]]

    def test_spec_03_models_quarantine_and_incomplete_cleanup(self):
        quarantined, incomplete = [], []
        for case_id, case in self.spec_cases("spec-03"):
            after = {entry["object_token"]: entry for entry in case["after_ledger"]}
            failed = {step["object"] for step in case["control_flow"]
                      if step["native_result"] != 0}
            quarantined += [(case_id, token) for token, entry in after.items()
                            if entry["status"] == "quarantined" and token in failed]
            incomplete += [(case_id, token) for token in failed
                           if token != "none" and after.get(token, {}).get("status") == "live"]
        self.assertTrue(quarantined,
                        "spec-03 needs an object quarantined after failed restoration")
        self.assertTrue(incomplete,
                        "spec-03 needs an object retained live after a failed cleanup step")

    def test_spec_04_models_concurrent_object_reuse(self):
        reused = []
        for case_id, case in self.spec_cases("spec-04"):
            before = {entry["object_token"]: entry for entry in case["before_ledger"]}
            after = {entry["object_token"]: entry for entry in case["after_ledger"]}
            reused += [(case_id, token) for token in before
                       if token in after
                       and before[token]["generation"] != after[token]["generation"]]
        self.assertTrue(reused, "spec-04 needs a token reused under a new generation")
        for case_id, token in reused:
            steps = [step for step in self.cases[case_id]["control_flow"]
                     if step["object"] == token]
            text = " ".join(f'{step["action"]} {step["operation"]}'
                            for step in steps)
            for marker in ("teardown", "reoffer", "overlap"):
                self.assertIn(
                    marker, text,
                    f"spec-04 needs a {marker} step for reused token "
                    f"{token} in {case_id}, not just a generation change")
            reoffers = [step for step in steps if "reoffer" in step["action"]]
            self.assertTrue(reoffers,
                            f"spec-04 needs a reoffer action for reused token "
                            f"{token} in {case_id}, not just a marker substring")
            for step in reoffers:
                self.assertEqual(
                    step["native_result"], 0,
                    f"spec-04 reoffer must succeed for reused token {token} "
                    f"in {case_id} before the new generation can go live")

    def test_spec_06_pairs_equal_metadata_with_different_protection(self):
        case = self.cases["mapping-dax-inventory"]
        after = case["after_ledger"]
        pairs = []
        for index, left in enumerate(after):
            for right in after[index + 1:]:
                if (left["pages"] == right["pages"]
                        and left["generation"] == right["generation"]
                        and left["status"] != right["status"]):
                    pairs.append((left["object_token"], right["object_token"]))
        self.assertTrue(pairs, "spec-06 needs a pair with equal pages and generation "
                               "but different protection outcomes")
        metadata = [step for step in case["control_flow"]
                    if "metadata" in step["action"]]
        self.assertTrue(metadata, "spec-06 needs metadata read steps establishing "
                                  "the pair, not just ledger entries")
        for step in metadata:
            self.assertEqual(step["native_result"], 0,
                             "metadata reads must succeed to establish equal metadata")
        observed = {step["object"] for step in metadata}
        observed_pairs = [(left, right) for left, right in pairs
                          if left in observed and right in observed]
        self.assertTrue(observed_pairs,
                        "spec-06 needs the differing pair to be established by "
                        "metadata reads, not reconstructed from ledger statuses alone")
        pages_by_object = {}
        for step in metadata:
            pages_by_object.setdefault(step["object"], []).append(step["pages"])
        equal_observed = []
        for left, right in observed_pairs:
            seen = set(pages_by_object.get(left, [])
                       + pages_by_object.get(right, []))
            if len(seen) == 1:
                equal_observed.append((left, right))
        self.assertTrue(equal_observed,
                        "spec-06 needs the observed metadata reads to report "
                        "equal page counts for the differing pair")
        protection = [step for step in case["control_flow"]
                      if "protection" in step["action"]]
        self.assertTrue(protection, "spec-06 needs a protection step establishing "
                                    "the pair difference, not just different "
                                    "lifecycle statuses")
        for step in protection:
            self.assertNotEqual(step["native_result"], 0,
                                "the protection step must record a refusal result")
        protected = {step["object"] for step in protection}
        self.assertTrue(any(left in protected or right in protected
                            for left, right in equal_observed),
                        "the differing pair must be the subject of the "
                        "protection step")
        for step in case["control_flow"]:
            self.assertNotIn("payload", step["action"])

    def test_spec_08_pairs_traces_with_and_without_modeled_host_read(self):
        case = self.cases["egress-control-facts"]
        modeled = [step for step in case["control_flow"]
                   if "model-host-read" in step["action"]]
        self.assertTrue(modeled, "spec-08 needs a modeled host-read step")
        self.assertTrue(all(step["object"] == "none" for step in modeled),
                        "the modeled host read itself observes no object")
        after = {entry["object_token"]: entry for entry in case["after_ledger"]}
        observed = {}
        for step in case["control_flow"]:
            if step["object"] != "none":
                observed.setdefault(step["object"], []).append(step)
        pairs = 0
        for token, entry in after.items():
            if not token.endswith("-1"):
                continue
            sibling = token[:-1] + "2"
            self.assertIn(sibling, after,
                          f"spec-08 needs a with/without host-read pair for {token}")
            twin = dict(after[sibling])
            want = dict(entry)
            del twin["object_token"], want["object_token"]
            self.assertEqual(twin, want,
                             f"paired traces must stay indistinguishable for {token}")
            self.assertIn(token, observed,
                          f"spec-08 needs a trace observation for {token}")
            self.assertIn(sibling, observed,
                          f"spec-08 needs a trace observation for {sibling}")
            first = [(step["native_result"], step["pages"])
                     for step in observed[token]]
            second = [(step["native_result"], step["pages"])
                      for step in observed[sibling]]
            self.assertEqual(first, second,
                             f"paired trace observations must agree for {token}, "
                             "not just the final ledger entries")
            pairs += 1
        self.assertGreater(pairs, 0, "spec-08 needs at least one with/without pair")
        positions = {id(step): index for index, step in enumerate(case["control_flow"])}
        modeled_index = min(positions[id(step)] for step in modeled)
        first_trace = [step for step in case["control_flow"]
                       if step["object"].endswith("-1")]
        second_trace = [step for step in case["control_flow"]
                        if step["object"].endswith("-2")]
        self.assertTrue(first_trace and second_trace,
                        "spec-08 needs ordered observations for both traces")
        self.assertEqual(len(first_trace), len(second_trace),
                         "paired traces must observe the same number of steps")
        self.assertTrue(all(positions[id(step)] < modeled_index
                            for step in first_trace),
                        "the first trace must precede the modeled host read")
        self.assertTrue(all(positions[id(step)] > modeled_index
                            for step in second_trace),
                        "the second trace must follow the modeled host read")

        def normalized(step):
            base = step["object"][:-2]
            action = step["action"]
            if action.startswith("reread-"):
                action = action[len("re"):]
            return (base, action, step["native_result"], step["pages"])

        self.assertEqual([normalized(step) for step in first_trace],
                         [normalized(step) for step in second_trace],
                         "paired traces must observe the same sequence in order, "
                         "not just the same grouped observations")

    def test_spec_10_models_reordered_rules_conflicts_and_empty_scope(self):
        case = self.cases["before-after-delta"]
        steps = case["control_flow"]
        applies = [step["object"] for step in steps
                   if step["action"] == "apply-rule-in-order"]
        reordered = [step["object"] for step in steps
                     if step["action"] == "reapply-rule-reordered"]
        self.assertGreaterEqual(len(applies), 2, "spec-10 needs ordered rule steps")
        self.assertEqual(reordered, list(reversed(applies)),
                         "spec-10 needs the same rules reapplied in reverse order")
        before = {entry["object_token"]: entry for entry in case["before_ledger"]}
        after = {entry["object_token"]: entry for entry in case["after_ledger"]}
        for token in applies:
            self.assertEqual(before[token], after[token],
                             "reordered rule evaluation must agree with ordered evaluation")
        ordered = {}
        reordered_results = {}
        for step in steps:
            if step["action"] == "apply-rule-in-order":
                ordered.setdefault(step["object"], []).append(step["native_result"])
            elif step["action"] == "reapply-rule-reordered":
                reordered_results.setdefault(step["object"], []).append(
                    step["native_result"])
        self.assertEqual(set(ordered), set(reordered_results),
                         "every ordered rule needs a reordered result")
        for token in ordered:
            self.assertEqual(ordered[token], reordered_results[token],
                             f"rule {token} must evaluate the same sequence under "
                             "reordered application, not just agree in the object "
                             "ledger")
        conflicts = [step for step in steps if "conflict" in step["action"]]
        self.assertTrue(conflicts, "spec-10 needs a conflicting-rules step")
        scopes = [step for step in steps if "empty-scope" in step["action"]]
        self.assertTrue(scopes, "spec-10 needs an empty-scope step")
        for step in conflicts + scopes:
            self.assertEqual(step["object"], "none", "refused rules record no object")
            self.assertNotEqual(step["native_result"], 0,
                                "refused rules carry a failure result")

    def test_spec_10_rejects_malicious_rule_and_scope_strings(self):
        operations = ["rule-%p", "op-0xdead", "../scope", "scope;drop",
                      "rule %n", "RULE-1", ""]
        actions = ["apply-%p", "read-0x1234", "pfn=7-leak", ""]
        for case_id in self.specs["spec-10"]:
            path = self.files[case_id]
            for operation in operations:
                with self.subTest(case=case_id, field="operation", value=operation):
                    tmp = mutate(path, lambda data, value=operation:
                                 data["control_flow"][0].update(operation=value))
                    try:
                        with self.assertRaises(FixtureError):
                            load_case(tmp)
                    finally:
                        Path(tmp).unlink()
            for action in actions:
                with self.subTest(case=case_id, field="action", value=action):
                    tmp = mutate(path, lambda data, value=action:
                                 data["control_flow"][0].update(action=value))
                    try:
                        with self.assertRaises(FixtureError):
                            load_case(tmp)
                    finally:
                        Path(tmp).unlink()


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
