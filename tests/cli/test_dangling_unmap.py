#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""A dropped map's release exits degraded, or refuses under complete."""

import json
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "build/memveil"
OK = "tests/fixtures/reader/f2-dangling-split-mapping-ok"
DENY = "tests/fixtures/reader/f2-dangling-split-mapping-deny"


def mapping_status(fixture):
    session = json.loads((ROOT / fixture / "session.json").read_text())
    return session["quality"]["correlation"]["relations"][
        "mapping_release"]["status"]


class DanglingUnmapExit(unittest.TestCase):
    def report(self, fixture):
        return subprocess.run([BIN, "report", ROOT / fixture],
                              capture_output=True, text=True)

    def test_release_exit_follows_mapping_class(self):
        # Same dropped-map stream; only the mapping class differs.
        self.assertEqual((ROOT / OK / "events.ndjson").read_bytes(),
                         (ROOT / DENY / "events.ndjson").read_bytes())
        self.assertEqual(mapping_status(OK), "partial")
        self.assertEqual(mapping_status(DENY), "complete_for_scope")
        with self.subTest(mapping_release="partial"):
            proc = self.report(OK)
            self.assertEqual(proc.returncode, 4, proc.stderr)
            self.assertNotEqual(proc.stdout, "")
        with self.subTest(mapping_release="complete_for_scope"):
            proc = self.report(DENY)
            self.assertEqual(proc.returncode, 2, proc.stderr)
            self.assertEqual(proc.stdout, "")
            self.assertIn("unknown mapping", proc.stderr)


if __name__ == "__main__":
    unittest.main()
