#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Lease-free self-tests for authored exposure fixture ledgers.

These tests exercise only the independent fixture oracle under
``tests/exposure/`` and the authored per-scenario case files. They never
touch the collector, never load a kernel module, and never require a
guest lease. Expected ledgers are authored by hand; nothing here is
derived from collector output.

Vacuity rule: an empty expected ledger never compares equal, so a
missing or dropped expectation cannot pass silently.
"""
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from tests.exposure.oracle import (  # noqa: E402
    FixtureError,
    LedgerMismatch,
    compare_entries,
)

GOOD = [
    {"object_token": "buf-a-1", "generation": "1", "pages": "2", "status": "live"},
    {"object_token": "buf-a-2", "generation": "1", "pages": "1", "status": "live"},
]


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

    def test_empty_ledgers_never_compare_equal(self):
        for expected, actual in (([], []), (GOOD, []), ([], GOOD)):
            with self.subTest(expected=expected, actual=actual):
                with self.assertRaises(LedgerMismatch):
                    compare_entries(expected, actual, "vacuity")

    def test_fixture_errors_are_distinct_from_mismatches(self):
        self.assertTrue(issubclass(FixtureError, ValueError))
        self.assertTrue(issubclass(LedgerMismatch, ValueError))
        self.assertIsNot(FixtureError, LedgerMismatch)


if __name__ == "__main__":
    unittest.main()
