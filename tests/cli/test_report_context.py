#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Human reports preserve captured context without admitting the reader host."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BIN = ROOT / "build/memveil"
SOURCES = ("kernel.release", "profile.decision", "measurement_scope")


class ReportContext(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="memveil-context-")
        self.addCleanup(self.tmp.cleanup)
        self.cap = Path(self.tmp.name)
        self.session = json.loads((ROOT / "tests/fixtures/attempts/session.json").read_text())
        (self.cap / "events.ndjson").write_bytes(
            (ROOT / "tests/fixtures/attempts/events.ndjson").read_bytes())

    def write(self, values):
        self.session["environment"]["evidence"] = [
            {"type": "provenance", "source": source, "interpretation": value}
            for source, value in values]
        (self.cap / "session.json").write_text(json.dumps(self.session))

    def report(self, fmt):
        proc = subprocess.run([BIN, "report", "--format", fmt, self.cap],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stderr, "")
        return proc.stdout

    def test_missing_is_explicit_and_synthetic_stays_visible(self):
        self.write([])
        for fmt in ("text", "markdown"):
            with self.subTest(fmt=fmt):
                out = self.report(fmt)
                for source in SOURCES:
                    label = source.replace("_", "\\_") if fmt == "markdown" else source
                    self.assertIn("recorded " + label + ": unavailable (no captured provenance)", out)
                self.assertIn("synthetic", out)
                self.assertIn("duration: 3.000000000 s (3000000000 ns)", out)

    def test_agreeing_duplicates_preserve_unbound_and_json(self):
        values = [("kernel.release", "7.0.0-captured"),
                  ("profile.decision", "unbound: no admitted profile"),
                  ("measurement_scope", "attempts in recorded window")]
        self.write(values + values)
        doc = json.loads(self.report("json"))
        self.assertEqual(len(doc["environment"]["evidence"]), 6)
        self.assertEqual([m["value"] for m in doc["metrics"] if m["name"] == "bounce_attempts"], ["3", "3"])
        for fmt in ("text", "markdown"):
            with self.subTest(fmt=fmt):
                out = self.report(fmt)
                self.assertIn("recorded kernel.release: 7.0.0-captured", out)
                self.assertIn("recorded profile.decision: unbound: no admitted profile", out)
                self.assertNotIn("validated", out)
                self.assertNotIn("conflicting captured values", out)
                self.assertEqual(out.count("7.0.0-captured"), 1)

    def test_conflicting_values_are_all_visible_without_a_selected_winner(self):
        self.write([(source, value) for source in SOURCES
                    for value in ("first-captured", "second-captured", "first-captured")])
        for fmt in ("text", "markdown"):
            with self.subTest(fmt=fmt):
                out = self.report(fmt)
                self.assertEqual(out.count("conflicting captured values: first-captured; second-captured"), 3)

    def test_hostile_values_use_each_renderers_escaping(self):
        self.write([(source, "captured\n\t\x1b[2J|*_<script>" ) for source in SOURCES])
        for fmt in ("text", "markdown"):
            with self.subTest(fmt=fmt):
                out = self.report(fmt)
                self.assertNotIn("\x1b", out)
                self.assertNotIn("captured\n", out)
                want = ("captured\\n\\t\ufffd[2J|*_<script>" if fmt == "text" else
                        "captured\\\\n\\\\t\ufffd\\[2J\\|\\*\\_&lt;script&gt;")
                self.assertEqual(out.count(want), 3)

    def test_nonprovenance_records_cannot_supply_recorded_context(self):
        self.write([])
        self.session["environment"]["evidence"] = [
            {"type": "sysfs", "source": "kernel.release", "interpretation": "not-provenance"}]
        (self.cap / "session.json").write_text(json.dumps(self.session))
        for fmt in ("text", "markdown"):
            with self.subTest(fmt=fmt):
                self.assertIn("recorded kernel.release: unavailable (no captured provenance)", self.report(fmt))

    def test_integer_duration_zero_fraction_and_u64_max(self):
        (self.cap / "events.ndjson").write_bytes(b"")
        for start, end, want in (("0", "0", "0.000000000 s (0 ns)"),
                                 ("9007199254740993", "9007199254741000", "0.000000007 s (7 ns)"),
                                 ("0", "18446744073709551615", "18446744073.709551615 s (18446744073709551615 ns)")):
            self.session["capture"]["window"] = {"start_ns": start, "end_ns": end}
            self.write([])
            for fmt in ("text", "markdown"):
                with self.subTest(start=start, end=end, fmt=fmt):
                    self.assertIn("duration: " + want, self.report(fmt))

    def test_top_duration_tracks_each_replay_prefix(self):
        cap = ROOT / "tests/fixtures/lifecycle/lifecycle-nested"
        proc = subprocess.run([BIN, "top", "--interval", "1s", cap],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        blocks = [b for b in proc.stdout.split("--- refresh ") if b.strip()]
        self.assertEqual(len(blocks), 2)
        self.assertIn("duration: 1.000000000 s (1000000000 ns)", blocks[0])
        self.assertIn("duration: 1.500000000 s (1500000000 ns)", blocks[1])


if __name__ == "__main__":
    unittest.main()
