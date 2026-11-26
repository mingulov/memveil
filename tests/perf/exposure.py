#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline bound assertions for the exposure self-tests.

Pure standard-library helpers only: every offline adversarial
and acceptance check wraps its work in :func:`run_bounded`,
which fails the check when it exceeds an explicit wall-clock
or process-growth budget. These helpers never boot a
workload, never measure product throughput or latency, and
never prove any live performance claim; live measurement
belongs to the controller-owned live suites.
"""

import resource
import sys
import time

# Explicit per-check offline budgets. Fixture corpora are a few
# kilobytes, so a healthy check finishes in milliseconds with no
# measurable process growth; the caps only catch runaway work.
TIME_BUDGET_MS = 10000
RSS_GROWTH_BUDGET_KB = 131072


class BoundExceeded(AssertionError):
    """A check exceeded its explicit time or growth budget."""


def current_rss_kb():
    """Return the current peak process size in KiB (standard library)."""
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        return peak // 1024
    return peak


def check_bounds(label, elapsed_ms, growth_kb,
                 time_ms=TIME_BUDGET_MS, rss_kb=RSS_GROWTH_BUDGET_KB):
    """Fail when observed cost exceeds the explicit budgets."""
    if elapsed_ms > time_ms:
        raise BoundExceeded(
            "%s: wall time %.1f ms exceeds the %d ms offline budget"
            % (label, elapsed_ms, time_ms))
    if growth_kb > rss_kb:
        raise BoundExceeded(
            "%s: process growth %d KiB exceeds the %d KiB offline budget"
            % (label, growth_kb, rss_kb))
    return {"label": label, "elapsed_ms": elapsed_ms,
            "growth_kb": growth_kb, "time_ms": time_ms, "rss_kb": rss_kb}


def run_bounded(label, func, *args, **kwargs):
    """Run ``func`` and fail when it exceeds the offline budgets.

    Extra keyword arguments ``time_ms`` and ``rss_kb`` override
    the default budgets for one call; remaining arguments go to
    ``func``. Returns a dict with the observed cost on success.
    """
    time_ms = kwargs.pop("time_ms", TIME_BUDGET_MS)
    rss_kb = kwargs.pop("rss_kb", RSS_GROWTH_BUDGET_KB)
    before_kb = current_rss_kb()
    start = time.monotonic()
    func(*args, **kwargs)
    elapsed_ms = (time.monotonic() - start) * 1000.0
    growth_kb = current_rss_kb() - before_kb
    return check_bounds(label, elapsed_ms, growth_kb,
                        time_ms=time_ms, rss_kb=rss_kb)


if __name__ == "__main__":
    receipt = run_bounded("self-check", lambda: None)
    print("offline bounds helper OK: %(label)s in %(elapsed_ms).1f ms, "
          "+%(growth_kb)d KiB" % receipt)
