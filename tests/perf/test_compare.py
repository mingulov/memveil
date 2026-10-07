# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline tests for the paired-comparison math."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from compare import assess, compare, validate


def run(throughput, p99, valid=True, reason=""):
    return {"valid": valid, "counts_ok": valid,
            "invalid_reason": reason, "throughput": throughput,
            "p99": p99}


def test_validate_excludes_by_name():
    good, bad = validate([run(100, 10), run(0, 0, False, "counts bad")])
    assert len(good) == 1
    assert bad == [(1, "counts bad")]


def test_too_few_pairs_unqualified():
    verdict = compare("w", [run(100, 10)] * 2, [run(99, 11)] * 2)
    assert verdict["qualified"] is False
    assert verdict["pairs"] == 2
    status, _ = assess(verdict)
    assert status == "UNQUALIFIED"


def test_pass_within_targets():
    base = [run(100, 10)] * 5
    obs = [run(98, 10.5)] * 5
    verdict = compare("w", base, obs)
    assert verdict["qualified"] is True
    assert verdict["fields"]["throughput"]["median"] == 0.98
    status, _ = assess(verdict)
    assert status == "PASS"


def test_throughput_breach_fails():
    base = [run(100, 10)] * 5
    obs = [run(90, 10)] * 5
    status, reason = assess(compare("w", base, obs))
    assert status == "FAIL"
    assert "throughput" in reason


def test_p99_breach_fails():
    base = [run(100, 10)] * 5
    obs = [run(100, 12)] * 5
    status, reason = assess(compare("w", base, obs))
    assert status == "FAIL"
    assert "p99" in reason


def test_invalid_runs_never_silent():
    base = [run(100, 10)] * 5 + [run(0, 0, False, "env drift")]
    obs = [run(99, 10.5)] * 5
    verdict = compare("w", base, obs)
    assert verdict["qualified"] is True
    assert verdict["excluded"] == ["baseline#5: env drift"]
