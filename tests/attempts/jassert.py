#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent JSON oracle for the collector matrix (test tool).

Reads producer/report JSON with stock python (no project
code) and asserts one expectation per call. Exit 0 on
match, 1 with a diagnostic otherwise.

Usage:
  jassert.py field FILE A.B.C EXPECTED
      dotted object path equals EXPECTED ("null" for JSON null)
  jassert.py metric FILE NAME EXPECTED
      metrics[] entry NAME has value EXPECTED
  jassert.py evidence FILE SOURCE EXPECTED
      environment.evidence[] entry SOURCE has
      interpretation EXPECTED ("absent" asserts missing)
  jassert.py events DIR K1,K2,...
      events.ndjson holds exactly the kind sequence,
      seqs dense from 0, session ids all equal the
      session.json session_id
  jassert.py nofile PATH
      PATH must not exist
  jassert.py nometric FILE NAME
      metrics[] holds no entry NAME
  jassert.py eventfield FILE INDEX A.B EXPECTED
      events.ndjson line INDEX dotted path equals EXPECTED
"""

import json
import sys


def fail(msg):
    print("jassert: " + msg, file=sys.stderr)
    return 1


def load(path):
    with open(path) as handle:
        return json.load(handle)


def want(text, value):
    if text == "null":
        return value is None
    return value == text


def cmd_field(path, dotted, expected):
    try:
        node = load(path)
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return fail("%s: no path %s" % (path, dotted))
        node = node[part]
    if not want(expected, node):
        return fail("%s: %s is %r, want %s" % (path, dotted, node, expected))
    return 0


def cmd_metric(path, name, expected):
    try:
        doc = load(path)
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    for metric in doc.get("metrics", []):
        if metric.get("name") == name:
            if not want(expected, metric.get("value")):
                return fail(
                    "%s: metric %s is %r, want %s"
                    % (path, name, metric.get("value"), expected)
                )
            return 0
    return fail("%s: no metric %s" % (path, name))


def cmd_evidence(path, source, expected):
    try:
        doc = load(path)
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    found = None
    for item in doc.get("environment", {}).get("evidence", []):
        if item.get("source") == source:
            found = item.get("interpretation")
    if expected == "absent":
        if found is not None:
            return fail("%s: evidence %s present, want absent" % (path, source))
        return 0
    if found is None:
        return fail("%s: no evidence %s" % (path, source))
    if found != expected:
        return fail(
            "%s: evidence %s is %r, want %r" % (path, source, found, expected)
        )
    return 0


def cmd_events(path, kinds):
    import os

    want_kinds = kinds.split(",") if kinds else []
    session_path = os.path.join(os.path.dirname(path), "session.json")
    try:
        sid = load(session_path)["session_id"]
    except Exception as exc:
        return fail("%s: %s" % (session_path, exc))
    try:
        with open(path) as handle:
            lines = [line for line in handle if line.strip()]
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    if len(lines) != len(want_kinds):
        return fail(
            "%s: %d events, want %d" % (path, len(lines), len(want_kinds))
        )
    for pos, line in enumerate(lines):
        try:
            event = json.loads(line)
        except Exception as exc:
            return fail("%s line %d: %s" % (path, pos, exc))
        if event.get("kind") != want_kinds[pos]:
            return fail(
                "%s line %d: kind %r, want %r"
                % (path, pos, event.get("kind"), want_kinds[pos])
            )
        if event.get("seq") != str(pos):
            return fail(
                "%s line %d: seq %r, want %r"
                % (path, pos, event.get("seq"), str(pos))
            )
        if event.get("session_id") != sid:
            return fail("%s line %d: session mismatch" % (path, pos))
    return 0


def cmd_nofile(path):
    import os

    if os.path.exists(path):
        return fail("%s exists, want absent" % path)
    return 0


def cmd_nometric(path, name):
    try:
        doc = load(path)
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    for metric in doc.get("metrics", []):
        if metric.get("name") == name:
            return fail("%s: metric %s present, want absent" % (path, name))
    return 0


def cmd_eventfield(path, index, dotted, expected):
    try:
        with open(path) as handle:
            lines = [line for line in handle if line.strip()]
    except Exception as exc:
        return fail("%s: %s" % (path, exc))
    try:
        event = json.loads(lines[int(index)])
    except (IndexError, ValueError) as exc:
        return fail("%s line %s: %s" % (path, index, exc))
    node = event
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return fail("%s line %s: no path %s" % (path, index, dotted))
        node = node[part]
    if not want(expected, node):
        return fail(
            "%s line %s: %s is %r, want %s"
            % (path, index, dotted, node, expected)
        )
    return 0


def main(argv):
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    mode = argv[1]
    if mode == "field" and len(argv) == 5:
        return cmd_field(argv[2], argv[3], argv[4])
    if mode == "metric" and len(argv) == 5:
        return cmd_metric(argv[2], argv[3], argv[4])
    if mode == "evidence" and len(argv) == 5:
        return cmd_evidence(argv[2], argv[3], argv[4])
    if mode == "events" and len(argv) == 4:
        return cmd_events(argv[2], argv[3])
    if mode == "nofile" and len(argv) == 3:
        return cmd_nofile(argv[2])
    if mode == "nometric" and len(argv) == 4:
        return cmd_nometric(argv[2], argv[3])
    if mode == "eventfield" and len(argv) == 6:
        return cmd_eventfield(argv[2], argv[3], argv[4], argv[5])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
