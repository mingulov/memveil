#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Real block/vnet I/O slice in the disposable VM.

Runs real block and vnet I/O through the swiotlb path with the
lifecycle probes attached and checks that captures stay
internally consistent (no orphan releases, live bytes
reconcilable, completed lifetimes sane). No fixture traffic:
the workload is ordinary guest I/O.
"""

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import check_conservation, parse_consume_file
from lifecycle_env import (CONSUMER, COPY_PROBE, LIFECYCLE_PROBE,
                           ensure_oracle_module, require_lifecycle_env)
from vm_boot import cleanup, run_guest, verify_exports


def check_consistency(lc_events, cp_events, workload):
    """Internal-consistency rules for unattributed live traffic.

    No orphan releases (per size/dir class, unmaps never exceed
    maps), live bytes non-negative, used slabs return to the
    pre-workload floor, completed lifetimes non-negative and
    inside the window. Pairing is FIFO within a size/dir
    class: a gate heuristic, explicitly not product
    correlation.
    """
    bad = []
    maps = Counter()
    unmaps = Counter()
    for event in lc_events:
        key = (event["size"], event["dir"])
        if event["kind"] == 1:
            maps[key] += 1
        elif event["kind"] == 2:
            unmaps[key] += 1
        else:
            bad.append("stray lc kind %d" % event["kind"])
    for key in sorted(set(maps) | set(unmaps)):
        if unmaps[key] > maps[key]:
            bad.append("orphan releases %r: %d unmaps > %d maps"
                       % (key, unmaps[key], maps[key]))
    live_bytes = (sum(e["size"] for e in lc_events if e["kind"] == 1)
                  - sum(e["size"] for e in lc_events if e["kind"] == 2))
    if live_bytes < 0:
        bad.append("negative live bytes %d" % live_bytes)
    if min(workload["used_after"]) != min(workload["used_before"]):
        bad.append("used slabs %r -> %r, floor moved"
                   % (workload["used_before"], workload["used_after"]))
    pending = {}
    worst = 0
    span = workload["end_ns"] - workload["start_ns"]
    for event in sorted(lc_events, key=lambda e: e["ktime"]):
        key = (event["size"], event["dir"])
        if event["kind"] == 1:
            pending.setdefault(key, []).append(event["ktime"])
        else:
            queue = pending.get(key, [])
            if not queue:
                continue
            lifetime = event["ktime"] - queue.pop(0)
            if lifetime < 0:
                bad.append("negative lifetime %r" % key)
            worst = max(worst, lifetime)
    if worst > span + 10_000_000_000:
        bad.append("lifetime %d exceeds window %d" % (worst, span))
    for event in cp_events:
        if event["kind"] == 1:
            if (event["known"], event["reason"], event["eff"]) != (0, 4, 0):
                bad.append("sync carries bytes %r" % event)
        elif event["kind"] == 2:
            if (event["known"], event["reason"]) != (1, 0):
                bad.append("bounce unknown %r" % event)
            if not 0 <= event["eff"] <= event["req"]:
                bad.append("bounce eff out of range %r" % event)
        else:
            bad.append("stray cp kind %d" % event["kind"])
    return bad, live_bytes


def test_real_io_slice():
    require_lifecycle_env(LIFECYCLE_PROBE, COPY_PROBE, CONSUMER)
    ensure_oracle_module()
    tmp, proc = run_guest("realio", network=True)
    try:
        assert proc.returncode == 0, \
            "guest failed: %s" % proc.stderr[-2000:]
        got = verify_exports(tmp, "realio",
                             ["identity.json", "io-lc.txt",
                              "io-cp.txt", "workload.json"])
        workload = json.loads(got["workload.json"].read_text())
        assert workload["ping_tx"] == 2000, workload
        assert workload["ping_rx"] == 2000, workload
        assert workload["disk_bytes"] == 2 * 256 * 65536, workload
        assert workload["end_ns"] < workload["detach_ns"], workload
        lc, lc_sum = parse_consume_file(str(got["io-lc.txt"]))
        cp, cp_sum = parse_consume_file(str(got["io-cp.txt"]))
        assert lc, "no lifecycle events under real I/O"
        assert cp, "no copy events under real I/O"
        bad = check_conservation(lc, lc_sum, "io-lc")
        bad += check_conservation(cp, cp_sum, "io-cp")
        consistent, live_bytes = check_consistency(lc, cp, workload)
        bad += consistent
        assert not bad, "\n".join(bad)
        print("realio: %d lc + %d cp, live=%d, floor=%d ok"
              % (len(lc), len(cp), live_bytes,
                 min(workload["used_before"])))
    except Exception:
        print(f"gate artifacts kept at {tmp}")
        raise
    else:
        cleanup(tmp)
