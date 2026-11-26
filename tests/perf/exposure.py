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

import ctypes
import resource
import sys
import threading
import time
import tracemalloc

# Explicit per-check offline budgets. Fixture corpora are a few
# kilobytes, so a healthy check finishes in milliseconds with no
# measurable process growth; the caps only catch runaway work.
TIME_BUDGET_MS = 10000
RSS_GROWTH_BUDGET_KB = 131072


class BoundExceeded(AssertionError):
    """A check exceeded its explicit time or growth budget."""


class WorkerTimeout(BaseException):
    """Internal termination request for a worker past its budget.

    A BaseException (like KeyboardInterrupt) so blanket
    ``except Exception`` handlers inside the timed-out work
    cannot swallow the termination request.
    """


# Workers that outlived their time budget and were asked to
# stop. A worker that is still alive here at the next bounded
# call is refused loudly: timed-out work may never continue
# unobserved.
_timed_out_lock = threading.Lock()
_timed_out_workers = []


def _set_async_exc(thread_id, exc):
    """Deliver ``exc`` to another thread, best effort.

    Returns True when the interpreter accepted the request
    for exactly one thread. A missing API (non-CPython) or
    a vanished thread reports False without raising.
    """
    setter = getattr(ctypes.pythonapi, "PyThreadState_SetAsyncExc", None)
    if setter is None:
        return False
    setter.argtypes = (ctypes.c_ulong, ctypes.py_object)
    setter.restype = ctypes.c_int
    try:
        affected = setter(ctypes.c_ulong(thread_id), exc)
    except (ctypes.ArgumentError, SystemError, ValueError):
        return False
    if affected == 0:
        return False
    if affected != 1:
        try:
            setter(ctypes.c_ulong(thread_id), None)
        except (ctypes.ArgumentError, SystemError, ValueError):
            pass
        return False
    return True


def _terminate_worker(worker, label):
    """Stop a worker that outlived its time budget.

    The timeout alone only releases the waiter; without
    termination the worker would keep running unobserved.
    The pending request fires as soon as the worker resumes
    Python execution, so no further step of the timed-out
    work can run. A worker that still will not stop is
    recorded so the next bounded call refuses to proceed.
    """
    ident = worker.ident
    if ident is not None and worker.is_alive():
        _set_async_exc(ident, ctypes.py_object(WorkerTimeout(
            "%s: stopping work past its time budget" % label)))
    if worker.is_alive():
        with _timed_out_lock:
            _timed_out_workers.append(worker)


def _refuse_lingering_workers(label):
    """Fail when earlier timed-out work is still running."""
    with _timed_out_lock:
        _timed_out_workers[:] = [worker for worker in _timed_out_workers
                                 if worker.is_alive()]
        if _timed_out_workers:
            raise BoundExceeded(
                "%s: earlier timed-out work is still running; "
                "refusing to continue unobserved" % (label,))


def current_rss_kb():
    """Return the current resident process size in KiB.

    Per-check accounting reads the current resident set, never
    the process lifetime peak: retained bytes must count against
    the calling check even when an earlier peak was larger.
    """
    try:
        with open("/proc/self/statm", encoding="utf-8") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * resource.getpagesize() // 1024
    except (OSError, ValueError, IndexError):
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

    The time budget is enforced while ``func`` runs: a call
    that is still running past ``time_ms`` fails promptly,
    the worker is asked to stop so its work cannot continue
    unobserved, and any later bounded call refuses to proceed
    while that worker is still alive. Growth is the larger
    of the resident-set delta across this call and the
    allocation peak reached within it, so a transient spike
    that is freed before return still fails its limit.
    """
    time_ms = kwargs.pop("time_ms", TIME_BUDGET_MS)
    rss_kb = kwargs.pop("rss_kb", RSS_GROWTH_BUDGET_KB)
    _refuse_lingering_workers(label)
    before_kb = current_rss_kb()
    start = time.monotonic()
    outcome = {}
    started_tracing = False
    if not tracemalloc.is_tracing():
        tracemalloc.start()
        started_tracing = True
    tracemalloc.reset_peak()
    traced_before, _ = tracemalloc.get_traced_memory()
    try:
        def run():
            try:
                func(*args, **kwargs)
            except BaseException as error:
                # BaseException, not Exception: worker failures
                # that bypass Exception (such as the test
                # runner's failure outcomes) must still fail the
                # check instead of dying in the thread unobserved.
                outcome["error"] = error

        worker = threading.Thread(target=run, daemon=True)
        worker.start()
        worker.join(time_ms / 1000.0)
        if worker.is_alive():
            _terminate_worker(worker, label)
            raise BoundExceeded(
                "%s: still running past the %d ms offline budget"
                % (label, time_ms))
        if "error" in outcome:
            raise outcome["error"]
        elapsed_ms = (time.monotonic() - start) * 1000.0
        _, traced_peak = tracemalloc.get_traced_memory()
        # Resident counters only offer lifetime high-water
        # marks, so a transient spike freed before return is
        # invisible to an end-delta read; the traced peak
        # within this call bounds that transient growth
        # deterministically instead.
        traced_growth_kb = max(0, (traced_peak - traced_before) // 1024)
        growth_kb = max(current_rss_kb() - before_kb, traced_growth_kb)
        return check_bounds(label, elapsed_ms, growth_kb,
                            time_ms=time_ms, rss_kb=rss_kb)
    finally:
        if started_tracing:
            tracemalloc.stop()


if __name__ == "__main__":
    receipt = run_bounded("self-check", lambda: None)
    print("offline bounds helper OK: %(label)s in %(elapsed_ms).1f ms, "
          "+%(growth_kb)d KiB" % receipt)
