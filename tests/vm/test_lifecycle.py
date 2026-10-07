#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Low-rate lifecycle matrix in the disposable VM.

Loads the oracle module at stepped rates (1, 10, 100 maps/s),
captures with the lifecycle probes, and compares every report
against the oracle ledger with zero tolerated mismatches. Also
checks the effective-copy equality at each step.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_oracle_script,
                     compare_scripted, parse_consume_file,
                     parse_oracle_log)
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module, require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports

STEPS = (1000, 100, 10)


def expected_effective(ops_log):
    """Executed bytes derived from the oracle log by rule.

    Map-time TO bounce per successful op, sync_for_device
    bounce per TO sync, release bounce per FROM unmap. Never
    read from probe output.
    """
    total = 0
    for i in sorted(ops_log):
        entry = ops_log[i]
        if entry.get("success") is not True:
            continue
        size = entry["mapped"]
        total += size
        direction = entry["syncs"][0]["dir"] if entry["syncs"] else None
        for sync in entry["syncs"]:
            assert sync["dir"] == direction, (i, entry["syncs"])
            assert sync["len"] == size, (i, entry["syncs"])
            if direction == 1:
                total += size
        if direction == 2:
            total += size
    return total


def check_step(got, delay_ms):
    tag = "s%d" % delay_ms
    lc, lc_sum = parse_consume_file(
        str(got["%s-lc.txt" % tag]))
    cp, cp_sum = parse_consume_file(
        str(got["%s-cp.txt" % tag]))
    bad = check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(got["%s-oracle.log" % tag]))
    bad += check_oracle_script(ops_log, releases, complete, 4, -1,
                               tag)
    bad += compare_scripted(lc, cp, 4, -1, tag)
    maps = sorted(e["ktime"] for e in lc if e["kind"] == 1)
    assert len(maps) == 4, (tag, len(maps))
    floor_ns = int(delay_ms * 1e6 * 0.8)
    for first, second in zip(maps, maps[1:]):
        if second - first < floor_ns:
            bad.append("%s: map gap %d ns below floor %d"
                       % (tag, second - first, floor_ns))
    want_eff = expected_effective(ops_log)
    got_eff = sum(e["eff"] for e in cp if e["kind"] == 2)
    if got_eff != want_eff:
        bad.append("%s: effective %d != oracle %d"
                   % (tag, got_eff, want_eff))
    assert not bad, "\n".join(bad)
    print("%s: 8 lc + 17 cp exact, eff=%d, gaps>=%.1fms ok"
          % (tag, got_eff, floor_ns / 1e6))


def test_low_rate_matrix():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    tmp, proc = run_guest("matrix")
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        names = ["identity.json"]
        for delay_ms in STEPS:
            tag = "s%d" % delay_ms
            names += ["%s-lc.txt" % tag, "%s-cp.txt" % tag,
                      "%s-oracle.log" % tag]
        got = verify_exports(tmp, "matrix", names)
        ident = json.loads(got["identity.json"].read_text())
        assert ident["release"] == "7.0.0-34-generic", ident
        for delay_ms in STEPS:
            check_step(got, delay_ms)
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
