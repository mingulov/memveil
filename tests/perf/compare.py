#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Paired workload comparison: correctness before ratios.

Each PerformanceRun carries its own validity verdict. compare()
excludes invalid runs by name first, requires at least five
interleaved baseline/observer pairs per workload, then reports
per-pair ratios with median and spread. Invalid runs are never
silently included and thresholds are never loosened after a
failure; a workload with too few samples leaves its latency
claim unqualified.
"""

import statistics
import math


def validate(runs):
    """Split runs into (valid, [(index, reason)]) by validity."""
    good, bad = [], []
    for i, run in enumerate(runs):
        if run.get("valid") is True and run.get("counts_ok") is True:
            good.append(run)
        else:
            bad.append((i, run.get("invalid_reason", "unverified run")))
    return good, bad


def _ratio(observer, baseline, field):
    base = baseline.get(field)
    obs = observer.get(field)
    if type(base) not in (int, float) or type(obs) not in (int, float) or not math.isfinite(base) or not math.isfinite(obs) or base <= 0 or obs <= 0:
        return None
    return obs / base


def compare(workload, baselines, observers, fields=("throughput", "p99")):
    """Compare interleaved pairs; return the verdict mapping."""
    # Preserve original pair identities; independent filtering would re-pair
    # a failed baseline with a different observer and fabricate valid pairs.
    aligned = []
    excluded = []
    for i in range(max(len(baselines), len(observers))):
        good = True
        for label, runs in (("baseline", baselines), ("observer", observers)):
            if i >= len(runs):
                excluded.append("%s#%d: missing paired leg" % (label, i))
                good = False
            elif not validate([runs[i]])[0]:
                excluded.append("%s#%d: %s" % (label, i, runs[i].get("invalid_reason", "unverified run")))
                good = False
        if good:
            aligned.append((baselines[i], observers[i]))
    pairs = len(aligned)
    verdict = {"workload": workload, "pairs": pairs,
               "excluded": excluded, "qualified": pairs >= 5,
               "fields": {}}
    if pairs < 5:
        verdict["reason"] = ("only %d valid pairs; latency claim "
                             "unqualified" % pairs)
        return verdict
    for field in fields:
        ratios = []
        for i in range(pairs):
            ratio = _ratio(aligned[i][1], aligned[i][0], field)
            if ratio is not None:
                ratios.append(ratio)
        if not ratios:
            verdict["fields"][field] = {"samples": 0,
                                        "qualified": False}
            continue
        verdict["fields"][field] = {
            "samples": len(ratios),
            "median": statistics.median(ratios),
            "min": min(ratios),
            "max": max(ratios),
            "qualified": len(ratios) >= 5,
        }
    return verdict


def assess(verdict, throughput_floor=0.95, p99_ceiling=1.10):
    """Assess summary-mode targets; correctness gates everything."""
    if not verdict["qualified"]:
        return ("UNQUALIFIED",
                verdict.get("reason", "too few valid pairs"))
    if any(not field.get("qualified") for field in verdict["fields"].values()):
        return ("UNQUALIFIED", "required metric lacks five valid paired samples")
    notes = []
    ok = True
    thr = verdict["fields"].get("throughput", {})
    if thr.get("qualified"):
        if thr["median"] < throughput_floor:
            ok = False
            notes.append("throughput ratio %.3f below %.2f"
                         % (thr["median"], throughput_floor))
    p99 = verdict["fields"].get("p99", {})
    if p99.get("qualified"):
        if p99["median"] > p99_ceiling:
            ok = False
            notes.append("p99 ratio %.3f above %.2f"
                         % (p99["median"], p99_ceiling))
    if ok:
        return ("PASS", "within targets")
    return ("FAIL", "; ".join(notes))
