#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Independent test oracle for the exact committed event-file record."""

import collections
import hashlib
import json
import pathlib
import sys

KINDS = ("bounce_attempt", "map_result", "unmap", "copy", "sync_request",
         "transition_result", "pool_sample", "gap", "marker", "counter_snapshot")


def recount(data):
    lines = data.splitlines(keepends=True)
    counts = collections.Counter()
    for seq, line in enumerate(lines):
        if not line.endswith(b"\n") or len(line) > 65536:
            raise ValueError("event framing")
        event = json.loads(line)
        if event["seq"] != str(seq):
            raise ValueError("event sequence")
        if event["kind"] not in KINDS:
            raise ValueError("event kind")
        counts[event["kind"]] += 1
    return {"algorithm": "sha256", "events_bytes": str(len(data)),
            "line_count": str(len(lines)),
            "first_seq": "0" if lines else None,
            "last_seq": str(len(lines) - 1) if lines else None,
            "events_sha256": hashlib.sha256(data).hexdigest(),
            "kinds": {kind: str(counts[kind]) for kind in KINDS}}


def check(directory):
    directory = pathlib.Path(directory)
    session = json.loads((directory / "session.json").read_bytes())
    if session["schema_version"] != "0.1.4":
        raise ValueError("oracle requires integrity session 0.1.4")
    data = (directory / "events.ndjson").read_bytes()
    actual = session["capture"]["integrity"]
    expected = recount(data)
    if actual != expected:
        fields = [key for key in expected if expected[key] != actual.get(key)]
        raise ValueError("integrity mismatch: " + ", ".join(fields))
    return len(data), int(expected["line_count"])


def selftest():
    data = b'{"seq":"0","kind":"marker"}\n'
    expected = recount(data)
    assert expected["events_bytes"] == str(len(data))
    assert expected["line_count"] == "1"
    assert expected["kinds"]["marker"] == "1"
    for invalid in (data[:-1], data.replace(b'"0"', b'"1"'),
                    data.replace(b'marker', b'foreign')):
        try:
            recount(invalid)
        except ValueError:
            pass
        else:
            raise AssertionError("negative control accepted")
    assert recount(b"")["events_sha256"] == hashlib.sha256(b"").hexdigest()


def main():
    if sys.argv[1:] == ["--selftest"]:
        selftest()
        print("integrity oracle: negative controls passed")
        return
    if not sys.argv[1:]:
        raise ValueError("usage: check_integrity.py CAPTURE... | --selftest")
    for directory in sys.argv[1:]:
        size, count = check(directory)
        print(f"integrity oracle: {directory}: {size} bytes, {count} events")


if __name__ == "__main__":
    main()
