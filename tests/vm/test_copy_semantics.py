#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Copy semantics in the disposable VM.

Verifies request-vs-copy accounting on live traffic: sync
requests alone add no copy bytes, nested copies before a map
result stay counted, and copies under a failed mapping survive
while the failure creates no mapping.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_oracle_script,
                     compare_scripted, parse_consume_file,
                     parse_oracle_log)
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module, require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports


def check_nested_copies(lc_events, cp_events, tag):
    """Every map keeps exactly one preceding TO bounce.

    The map-time bounce executes inside the mapping call, so
    its ktime precedes the fexit map result; scripted sizes
    are unique per op, so the pairing is unambiguous. Sync
    bounces land after their map and never count here.
    """
    bad = []
    maps = {}
    for event in lc_events:
        if event["kind"] == 1:
            if event["size"] in maps:
                bad.append("%s: map size %d repeats, pairing lost"
                           % (tag, event["size"]))
            maps[event["size"]] = event["ktime"]
    for size, map_ktime in sorted(maps.items()):
        preceding = [e for e in cp_events
                     if e["kind"] == 2 and e["todev"] == 1
                     and e["req"] == size and e["ktime"] <= map_ktime]
        if len(preceding) != 1:
            bad.append("%s: size %d has %d preceding TO bounces"
                       % (tag, size, len(preceding)))
    return bad


def check_window(got, tag, fail_op):
    lc, lc_sum = parse_consume_file(str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_script(ops_log, releases, complete, 4,
                               fail_op, tag)
    bad += compare_scripted(lc, cp, 4, fail_op, tag)
    bad += check_nested_copies(lc, cp, tag)
    if fail_op >= 0:
        entry = ops_log[fail_op]
        if entry.get("success") is not False:
            bad.append("%s: fail op unexpectedly succeeded" % tag)
        if fail_op in releases:
            bad.append("%s: fail op released a mapping" % tag)
        size = entry["requested"]
        survivors = [e for e in cp if e["kind"] == 2
                     and e["req"] == size]
        if not survivors:
            bad.append("%s: no surviving copy under failure" % tag)
    assert not bad, "\n".join(bad)
    print("%s: %d lc + %d cp exact, nested ok"
          % (tag, len(lc), len(cp)))


def test_copy_semantics():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    tmp, proc = run_guest("copy")
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(tmp, "copy",
                             ["identity.json", "a-lc.txt",
                              "a-cp.txt", "a-oracle.log",
                              "b-lc.txt", "b-cp.txt",
                              "b-oracle.log"])
        check_window(got, "a", -1)
        check_window(got, "b", 2)
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
