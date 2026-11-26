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

import multiprocessing
# Eager worker-process imports: the first bounded call must not
# be charged for lazily loading these (plus their transitive
# dependencies) as process growth.
import multiprocessing.connection
import multiprocessing.popen_fork
import multiprocessing.resource_tracker
import multiprocessing.util
import resource
import sys
import threading
import time

# Explicit per-check offline budgets. Fixture corpora are a few
# kilobytes, so a healthy check finishes in milliseconds with no
# measurable process growth; the caps only catch runaway work.
TIME_BUDGET_MS = 10000
RSS_GROWTH_BUDGET_KB = 131072

# Poll quantum for the timeout watch and the resident-set
# sampler. A few milliseconds: prompt budget enforcement
# without busy-waiting.
_POLL_QUANTUM_S = 0.002
# Grace for a terminated worker to exit before the backstop
# signal. Termination is prompt (the default disposition ends
# the worker at once, even one blocked in native code); the
# backstop only covers a worker that catches the first signal.
_TERMINATE_GRACE_S = 0.1


class BoundExceeded(AssertionError):
    """A check exceeded its explicit time or growth budget."""


class WorkerFailed(AssertionError):
    """A bounded check failed inside its worker.

    The worker runs in a separate process, so a failure
    whose type cannot be raised again here (or a worker that
    ends without any result) is carried by this failure with
    the original failure type and message instead of passing
    silently. Failures with plain built-in types are raised
    again as their own type with the same message.
    """


# Workers that outlived their time budget. Every entry was
# terminated and reaped before the budget failure was raised,
# so no entry here is ever alive. A worker that is somehow
# still alive refuses the next bounded call loudly instead of
# letting timed-out work continue unobserved.
_timed_out_lock = threading.Lock()
_timed_out_workers = []


def _fork_context():
    """Return the fork worker-process context.

    The worker must start from the caller's exact in-memory
    state (fixture readers, proof switches, in-memory test
    doubles), so it is forked, never spawned: neither the
    target nor its arguments are serialized.
    """
    return multiprocessing.get_context("fork")


def _reap_worker(worker):
    """Reap a worker, stopping it first when still running.

    Idempotent: a worker that already exited is only joined.
    A worker that survives the terminate signal past a short
    grace gets the backstop signal, so this always returns
    with the worker reaped and never alive.
    """
    if worker.is_alive():
        try:
            worker.terminate()
        except (OSError, ValueError):
            pass
        worker.join(_TERMINATE_GRACE_S)
    if worker.is_alive():
        try:
            worker.kill()
        except (OSError, ValueError):
            pass
        worker.join(_TERMINATE_GRACE_S)
    else:
        worker.join()


def _terminate_worker(worker, label):
    """Stop a worker that outlived its time budget, then record it.

    Termination is enforced, not requested: the worker is
    signalled, reaped on every path, and only then recorded.
    The timeout alone only releases the waiter; without
    termination the worker would keep running unobserved. A
    blocked worker cannot be stopped from inside this process
    (it only resumes when its own blocker releases), which is
    why the check runs in a separate process that the timeout
    can always end and reap.
    """
    _reap_worker(worker)
    with _timed_out_lock:
        _timed_out_workers.append(worker)


def _refuse_lingering_workers(label):
    """Fail when earlier timed-out work is still running.

    Timed-out workers are terminated and reaped before the
    budget failure is raised, so this list only ever holds
    reaped workers; the refusal stays as a backstop against
    timed-out work continuing unobserved.
    """
    with _timed_out_lock:
        lingering = list(_timed_out_workers)
    for worker in lingering:
        if not worker.is_alive():
            worker.join()
    with _timed_out_lock:
        _timed_out_workers[:] = [worker for worker in _timed_out_workers
                                 if worker.is_alive()]
        if _timed_out_workers:
            raise BoundExceeded(
                "%s: earlier timed-out work is still running; "
                "refusing to continue unobserved" % (label,))


def _rss_of_pid(pid):
    """Return one process's current resident size in KiB, best effort.

    None when the process is unreadable, for example after it
    already exited.
    """
    try:
        with open("/proc/%d/statm" % (pid,), encoding="utf-8") as handle:
            resident_pages = int(handle.read().split()[1])
        return resident_pages * resource.getpagesize() // 1024
    except (OSError, ValueError, IndexError):
        return None


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


def _describe_error(error):
    """Describe a worker failure with plain serializable values."""
    error_type = type(error)
    try:
        message = str(error)
    except Exception:
        message = "<unprintable %s>" % (
            getattr(error_type, "__name__", "error"),)
    return {"type_module": getattr(error_type, "__module__", ""),
            "type_name": getattr(error_type, "__name__", "error"),
            "message": message}


def _rebuild_error(description):
    """Raise a worker failure described by :func:`_describe_error`.

    Failures whose type resolves in this process (plain
    built-in failures such as assertion outcomes) are raised
    again as their own type with the same message; anything
    else is carried by :class:`WorkerFailed` so the check
    still fails instead of passing on an unresolvable type.
    """
    import builtins

    module_name = description.get("type_module", "")
    type_name = description.get("type_name", "error")
    message = description.get("message", "")
    if module_name in ("builtins", "exceptions"):
        candidate = getattr(builtins, type_name, None)
        if isinstance(candidate, type) \
                and issubclass(candidate, BaseException):
            try:
                rebuilt = candidate(message)
            except Exception:
                rebuilt = None
            if rebuilt is not None:
                raise rebuilt
    if message:
        raise WorkerFailed("%s: %s" % (type_name, message))
    raise WorkerFailed("%s" % (type_name,))


def _child_main(write_conn, func, args, kwargs):
    """Run one bounded check in the worker process.

    Reports the resident peak reached while the check ran
    (the kernel high-water mark, so a transient spike freed
    before return still counts) plus the check outcome. The
    parent reads the single report from the pipe.
    """
    # The forked worker inherits its parent's lifetime peak,
    # so the baseline is the entry peak, not the entry current
    # size: only growth reached within this call counts, never
    # resident history from before the fork.
    before_kb = current_rss_kb()
    entry_peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        entry_peak_kb = entry_peak_kb // 1024
    baseline_kb = max(before_kb, entry_peak_kb)
    outcome = {"ok": True, "error": None}
    try:
        func(*args, **kwargs)
    except BaseException as error:
        # BaseException, not Exception: worker failures
        # that bypass Exception (such as the test
        # runner's failure outcomes) must still fail the
        # check instead of dying in the worker unobserved.
        outcome = {"ok": False, "error": _describe_error(error)}
    peak_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    if sys.platform == "darwin":
        peak_kb = peak_kb // 1024
    try:
        write_conn.send({"before_kb": baseline_kb,
                         "peak_kb": peak_kb,
                         "outcome": outcome})
    finally:
        try:
            write_conn.close()
        except (OSError, EOFError):
            pass
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except (OSError, ValueError):
                pass


def _flush_stdio():
    """Flush standard streams before forking the worker.

    Buffered parent output must reach its destination once:
    the forked worker inherits the same file offsets, so
    unflushed output would appear twice when the worker
    flushes on its way out.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError):
            pass


def run_bounded(label, func, *args, **kwargs):
    """Run ``func`` and fail when it exceeds the offline budgets.

    Extra keyword arguments ``time_ms`` and ``rss_kb`` override
    the default budgets for one call; remaining arguments go to
    ``func``. Returns a dict with the observed cost on success.

    The check runs in a forked worker process started from
    the caller's exact in-memory state. The time budget is
    enforced while it runs: a worker that is still running
    past ``time_ms`` is terminated and reaped before the
    budget failure is raised, so timed-out work can never
    continue unobserved. Growth is the resident peak reached
    within the call -- the worker's own high-water mark plus
    resident samples taken while it runs -- so a transient
    spike that is freed before return still fails its limit.
    """
    time_ms = kwargs.pop("time_ms", TIME_BUDGET_MS)
    rss_kb = kwargs.pop("rss_kb", RSS_GROWTH_BUDGET_KB)
    _refuse_lingering_workers(label)
    before_kb = current_rss_kb()
    start = time.monotonic()
    deadline = start + time_ms / 1000.0
    context = _fork_context()
    read_conn, write_conn = context.Pipe(duplex=False)
    _flush_stdio()
    worker = context.Process(target=_child_main,
                             args=(write_conn, func, args, kwargs),
                             name="exposure-bounded-%s" % (label,),
                             daemon=True)
    worker.start()
    worker_pid = worker.pid
    try:
        write_conn.close()
    except (OSError, EOFError):
        pass
    sampled_peak_kb = 0
    report = None
    try:
        while True:
            if read_conn.poll(_POLL_QUANTUM_S):
                try:
                    report = read_conn.recv()
                except EOFError:
                    report = None
                break
            if worker_pid is not None:
                sample = _rss_of_pid(worker_pid)
                if sample is not None and sample > sampled_peak_kb:
                    sampled_peak_kb = sample
            if not worker.is_alive():
                # Ended without sending a report (crashed or
                # exited early): reap it and fail closed below.
                worker.join()
                break
            if time.monotonic() >= deadline:
                _terminate_worker(worker, label)
                raise BoundExceeded(
                    "%s: still running past the %d ms offline budget "
                    "(worker pid %s terminated and reaped)"
                    % (label, time_ms, worker_pid))
        if report is None:
            _reap_worker(worker)
            raise WorkerFailed(
                "%s: check worker ended without a result (exit %r)"
                % (label, worker.exitcode))
        _reap_worker(worker)
        if not report["outcome"]["ok"]:
            _rebuild_error(report["outcome"]["error"])
        elapsed_ms = (time.monotonic() - start) * 1000.0
        baseline_kb = report["before_kb"]
        sampled_growth_kb = sampled_peak_kb - baseline_kb \
            if sampled_peak_kb else 0
        growth_kb = max(0,
                        current_rss_kb() - before_kb,
                        report["peak_kb"] - baseline_kb,
                        sampled_growth_kb)
        return check_bounds(label, elapsed_ms, growth_kb,
                            time_ms=time_ms, rss_kb=rss_kb)
    finally:
        # Never leave the worker behind: reap it on every
        # path, including a parent-side interruption, then
        # release the pipe.
        _reap_worker(worker)
        try:
            read_conn.close()
        except (OSError, EOFError):
            pass


if __name__ == "__main__":
    receipt = run_bounded("self-check", lambda: None)
    print("offline bounds helper OK: %(label)s in %(elapsed_ms).1f ms, "
          "+%(growth_kb)d KiB" % receipt)
