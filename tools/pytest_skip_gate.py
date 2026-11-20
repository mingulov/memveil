#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Fail on any pytest skip outside the checked-in allowlist.

Reads one pytest -rs report (short summary lines) and the
expected-skips allowlist, and compares the multisets of
(file, reason) pairs: -rs locations collapse line numbers
(they churn on every edit and pytest versions disagree on
their presence) while per-pair counts stay exact. Any
unlisted skip fails; any stale allowlist entry fails too,
so the one place stays truthful. Usage:
pytest_skip_gate.py ALLOWLIST REPORT.
"""
import json
import re
import sys
from collections import Counter

SCHEMA = "memveil-pytest-ci-expected-skips/1"
LINE = re.compile(r"^SKIPPED \[\d+\] (\S+?)(?::\d+)?: (.*)$")


def parse_rs(text):
    """Multiset of (file, reason) over -rs summary lines."""
    found = Counter()
    for line in text.splitlines():
        match = LINE.match(line)
        if match:
            found[(match[1], match[2])] += 1
    return found


def load_allowlist(path):
    """Expected (file, reason) multiset; fail closed on shape."""
    with open(path, encoding="utf-8") as stream:
        doc = json.load(stream)
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise ValueError("unsupported expected-skips allowlist")
    skips = doc.get("skips")
    if not isinstance(skips, list):
        raise ValueError("expected-skips allowlist needs a skips list")
    expected = Counter()
    for entry in skips:
        if not isinstance(entry, dict) \
                or set(entry) != {"id", "reason", "count"}:
            raise ValueError("expected-skips entry shape differs")
        if not isinstance(entry["id"], str) or not entry["id"].strip() \
                or any(char.isspace() for char in entry["id"]):
            raise ValueError("expected-skips id differs")
        if not isinstance(entry["reason"], str) \
                or not entry["reason"].strip():
            raise ValueError("expected-skips reason differs")
        if type(entry["count"]) is not int or entry["count"] < 1:
            raise ValueError("expected-skips count differs")
        expected[(entry["id"], entry["reason"])] += entry["count"]
    return expected


def main(argv):
    if len(argv) != 3:
        print("usage: pytest_skip_gate.py ALLOWLIST REPORT",
              file=sys.stderr)
        return 2
    try:
        expected = load_allowlist(argv[1])
        with open(argv[2], encoding="utf-8") as stream:
            found = parse_rs(stream.read())
    except (OSError, ValueError) as exc:
        print("skip gate: " + str(exc), file=sys.stderr)
        return 1
    failed = False
    for pair in sorted(set(found) - set(expected)):
        print("skip gate: unlisted skip: %s: %s" % pair,
              file=sys.stderr)
        failed = True
    for pair in sorted(set(expected) - set(found)):
        print("skip gate: stale allowlist entry: %s: %s" % pair,
              file=sys.stderr)
        failed = True
    for pair in sorted(set(found) & set(expected)):
        if found[pair] != expected[pair]:
            print("skip gate: skip count differs for %s: "
                  "report has %d, allowlist has %d"
                  % (pair[0] + ": " + pair[1],
                     found[pair], expected[pair]),
                  file=sys.stderr)
            failed = True
    if not failed:
        print("skip gate: %d skips, all listed"
              % sum(found.values()))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
