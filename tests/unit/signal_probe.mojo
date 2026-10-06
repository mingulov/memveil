# SPDX-License-Identifier: GPL-3.0-or-later

"""Live signal probe (signals lane tool, not shipped).

Usage: signal_probe <mode> [args...]

Runs the REAL collector with scripted kernel/clock/writer
sources and the LIVE signalfd source, or exercises the
live source alone. Prints machine-readable result lines;
the lane asserts the lines, the session bytes, and (for
sigterm_run) the single-thread /proc task count.

Modes:
  none                    setup, check twice, teardown, proofs
  repeat                  two distinct signals, three checks
  latch <signo> <dir>     signal during polling latches
  inhand <signo> <dir>    signal with a record in hand
  setup_fail <which> <dir>  mask|signalfd setup failure
  sigterm_run <dir>       long run for external SIGTERM
"""

from std.ffi import external_call
from std.os import listdir
from std.sys import argv, exit

from memveil.capture.collector import (
    Collector,
    RunResult,
)
from memveil.platform.reader import read_host_file
from memveil.platform.signal import (
    LiveSignalSource,
    _has_sigblk_sentinel,
    ensure_inherited_signal_block,
)

from collector_probe import (
    _base_config,
    _cuts,
    _record_batch,
    _timeout,
    _zeros,
)
from scripted import (
    ScriptClock,
    ScriptKernel,
    ScriptWriter,
    snap_ok,
    stats_ok,
)


def _sigblk_of(raw: List[UInt8]) -> String:
    """SigBlk hex token from one /proc status body ("?" if absent)."""
    var want = String("SigBlk:").as_bytes()
    var at = -1
    var i = 0
    var last = len(raw) - len(want)
    while i <= last:
        var j = 0
        while j < len(want):
            if raw[i + j] != want[j]:
                break
            j += 1
        if j == len(want):
            at = i
            break
        i += 1
    if at < 0:
        return String("?")
    var k = at + len(want)
    while True:
        if k >= len(raw):
            break
        var c = raw[k]
        if c != UInt8(0x20) and c != UInt8(0x09):
            break
        k += 1
    var tok = List[UInt8]()
    while True:
        if k >= len(raw):
            break
        if raw[k] == UInt8(0x0A):
            break
        tok.append(raw[k])
        k += 1
    try:
        return String(from_utf8=Span(tok))
    except:
        return String("?")


def _sigblk() raises -> String:
    """Current SigBlk hex mask from /proc/self/status."""
    var raw = read_host_file(
        String("/proc/self/status"), String("sigblk"), 65536
    )
    return _sigblk_of(raw)


def _mode_threads(arglist: List[String]) raises:
    """Prove the re-exec: sentinel set, every thread blocked.

    Prints sentinel_before (1 in the re-execed child),
    the thread count, and one sigblk line per thread.
    The lane asserts bits 0x4002 (SIGINT+SIGTERM) on
    every line: no worker may receive a stop signal.
    """
    var pre = _has_sigblk_sentinel()
    var note = ensure_inherited_signal_block(arglist)
    if note != String(""):
        print(String("reexec_refused=") + note)
        exit(3)
    print(
        String("sentinel_before=")
        + (String("1") if pre else String("0"))
    )
    var tids = listdir(String("/proc/self/task"))
    print(String("threads=") + String(len(tids)))
    for i in range(len(tids)):
        var raw = read_host_file(
            String("/proc/self/task/") + tids[i] + String("/status"),
            String("thread status"),
            65536,
        )
        print(
            String("sigblk[")
            + tids[i]
            + String("]=")
            + _sigblk_of(raw)
        )


def _raise(signo: Int):
    _ = external_call["raise", Int32](Int32(signo))


def _mode_none() raises:
    var initial = _sigblk()
    print(String("sigblk_initial=") + initial)
    var src = LiveSignalSource()
    var setup = src.setup()
    print(String("setup=") + (String("ok") if setup.ok else String("fail")))
    var first = src.check()
    var second = src.check()
    print(String("check1=") + first.state)
    print(String("check2=") + second.state)
    print(String("sigblk_armed=") + _sigblk())
    src.teardown()
    print(String("sigblk_restored=") + _sigblk())
    var after = src.check()
    print(String("post_teardown=") + after.state)


def _mode_repeat():
    var src = LiveSignalSource()
    var setup = src.setup()
    if not setup.ok:
        print(String("setup=fail"))
        return
    print(String("setup=ok"))
    _raise(15)
    _raise(2)
    var first = src.check()
    var second = src.check()
    var third = src.check()
    print(String("check1=") + first.state)
    print(String("check2=") + second.state)
    print(String("check3=") + third.state)
    src.teardown()


def _report(res: RunResult):
    print(String("exit=") + String(res.exit_code))
    print(String("end=") + res.end_reason)
    print(String("outcome=") + res.outcome)
    if res.diagnostic != String(""):
        print(String("diag=") + res.diagnostic)


def _lclock(iters: Int) -> ScriptClock:
    var clock = ScriptClock()
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    for i in range(iters):
        clock.add(base + UInt64(4 + i))
    var latch = base + UInt64(61000000001)
    clock.add(latch)
    for i in range(7):
        clock.add(latch + UInt64(1 + i))
    return clock^


def _mode_latch(signo: Int, dir: String):
    var kernel = ScriptKernel()
    kernel.raise_on_poll = 3
    kernel.raise_signo = Int32(signo)
    kernel.add_poll(_timeout(), 105)
    _zeros(kernel, 5, 4)
    var clock = _lclock(3)
    var signal = LiveSignalSource()
    var writer = ScriptWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    signal.teardown()
    _report(res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _mode_inhand(signo: Int, dir: String):
    var kernel = ScriptKernel()
    kernel.raise_on_poll = 1
    kernel.raise_signo = Int32(signo)
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    ))
    for _ in range(4):
        kernel.add_stats(stats_ok(
            UInt64(1), UInt64(1), UInt64(0), UInt64(0), UInt64(0)
        ))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _lclock(1)
    var signal = LiveSignalSource()
    var writer = ScriptWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    signal.teardown()
    _report(res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _mode_setup_fail(which: String, dir: String) raises:
    var initial = _sigblk()
    var kernel = ScriptKernel()
    var clock = _lclock(0)
    var signal = LiveSignalSource()
    signal.test_fail_setup_at = which.copy()
    var writer = ScriptWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    signal.teardown()
    _report(res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("sigblk_initial=") + initial)
    print(String("sigblk_restored=") + _sigblk())


def _mode_sigterm_run(dir: String):
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 4000000000000)
    var zstats = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    for _ in range(5):
        kernel.add_stats(zstats.copy())
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(4):
        kernel.add_snap(zsnap.copy())
    var clock = ScriptClock()
    clock.step = UInt64(0)
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    var signal = LiveSignalSource()
    var writer = ScriptWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    signal.teardown()
    _report(res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def main() raises:
    var args = argv()
    if len(args) < 2:
        print(String("usage: signal_probe <mode> [args...]"))
        exit(2)
    var arglist = List[String]()
    for i in range(len(args)):
        arglist.append(String(args[i]))
    if args[1] == String("none"):
        _mode_none()
    elif args[1] == String("threads") and len(args) == 2:
        _mode_threads(arglist)
    elif args[1] == String("repeat"):
        _mode_repeat()
    elif args[1] == String("latch") and len(args) == 4:
        var note = ensure_inherited_signal_block(arglist)
        if note != String(""):
            print(String("reexec_refused=") + note)
            exit(3)
        var signo = 0
        for b in args[2].as_bytes():
            signo = signo * 10 + Int(b) - Int(UInt8(0x30))
        _mode_latch(signo, args[3])
    elif args[1] == String("inhand") and len(args) == 4:
        var note = ensure_inherited_signal_block(arglist)
        if note != String(""):
            print(String("reexec_refused=") + note)
            exit(3)
        var signo = 0
        for b in args[2].as_bytes():
            signo = signo * 10 + Int(b) - Int(UInt8(0x30))
        _mode_inhand(signo, args[3])
    elif args[1] == String("setup_fail") and len(args) == 4:
        var note = ensure_inherited_signal_block(arglist)
        if note != String(""):
            print(String("reexec_refused=") + note)
            exit(3)
        _mode_setup_fail(args[2], args[3])
    elif args[1] == String("sigterm_run") and len(args) == 3:
        var note = ensure_inherited_signal_block(arglist)
        if note != String(""):
            print(String("reexec_refused=") + note)
            exit(3)
        _mode_sigterm_run(args[2])
    else:
        print(String("usage: signal_probe <mode> [args...]"))
        exit(2)
