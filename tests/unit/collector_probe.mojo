# SPDX-License-Identifier: GPL-3.0-or-later

"""Collector close-out probe (attempts lane tool, not shipped).

Usage: collector_probe <script> <dir>

Runs the REAL collector with scripted sources and a real
(or null) writer into <dir>, prints machine-readable
result lines, and leaves a replayable capture behind.
The lane asserts the lines, the session bytes, and the
replayed report metric values.
"""

from std.sys import argv, exit

from memveil.capture.collector import (
    Collector,
    CollectorConfig,
    OpOut,
    PollOut,
    RunResult,
    StatsOut,
)
from memveil.capture.kernel import LmbKernel
from memveil.capture.live import LiveWriter
from memveil.model.session import EvidenceItem

from scripted import (
    AppendFault,
    DropWriter,
    NullWriter,
    ScriptClock,
    ScriptKernel,
    ScriptSignal,
    ScriptWriter,
    snap_err,
    snap_ok,
    stats_ok,
)


def _le16(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    out.append(UInt8(v & 0xFF))
    out.append(UInt8((v >> 8) & 0xFF))
    return out^


def _le32(v: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for i in range(4):
        out.append(UInt8((v >> (i * 8)) & 0xFF))
    return out^


def _le64(v: UInt64) -> List[UInt8]:
    var out = List[UInt8]()
    var x = v
    for _ in range(8):
        out.append(UInt8(x & UInt64(0xFF)))
        x >>= UInt64(8)
    return out^


def _payload(seq: UInt64, ktime: UInt64, size: UInt64, name: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in _le32(0x3741564D):
        out.append(b)
    for b in _le16(1):
        out.append(b)
    for b in _le16(0):
        out.append(b)
    for b in _le64(seq):
        out.append(b)
    for b in _le64(ktime):
        out.append(b)
    for b in _le64(size):
        out.append(b)
    var raw = name.as_bytes()
    var nlen = len(raw)
    if nlen > 63:
        nlen = 63
    for b in _le16(nlen):
        out.append(b)
    for i in range(nlen):
        out.append(raw[i])
    for _ in range(63 - nlen):
        out.append(UInt8(0))
    out.append(UInt8(0))
    return out^


def _frame(payload: List[UInt8]) -> List[UInt8]:
    var out = List[UInt8]()
    for b in _le32(len(payload)):
        out.append(b)
    for b in _le16(1):
        out.append(b)
    for b in _le16(0):
        out.append(b)
    for b in payload:
        out.append(b)
    return out^


def _batch(payload: List[UInt8]) -> PollOut:
    return PollOut(String("batch"), _frame(payload), UInt32(0), String(""))


def _timeout() -> PollOut:
    return PollOut(String("timeout"), List[UInt8](), UInt32(0), String(""))


def _base_config(dir: String, budget: Int = 134217728) -> CollectorConfig:
    var cfg = CollectorConfig()
    cfg.duration_s = UInt64(60)
    cfg.max_events_bytes = budget
    cfg.output = dir
    cfg.profile_id = String("probe")
    cfg.pid = 4242
    cfg.has_boot_id = True
    cfg.boot_id = String("probe-boot")
    var item = EvidenceItem()
    item.item_type = String("provenance")
    item.source = String("probe")
    item.interpretation = String("scripted run")
    cfg.evidence.append(item^)
    return cfg^


def _report(prefix: String, res: RunResult):
    print(prefix + String("exit=") + String(res.exit_code))
    print(prefix + String("end=") + res.end_reason)
    print(prefix + String("outcome=") + res.outcome)
    if res.diagnostic != String(""):
        print(prefix + String("diag=") + res.diagnostic)


def _clock(pre: Int) -> ScriptClock:
    """Standard clock: start/stable/attach, `pre` sub-deadline
    nows (main-loop + admit reads), the latch jump, tail."""
    var clock = ScriptClock()
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    for i in range(pre):
        clock.add(base + UInt64(4 + i))
    var latch = base + UInt64(61000000001)
    clock.add(latch)
    for i in range(7):
        clock.add(latch + UInt64(1 + i))
    return clock^


def _run(
    dir: String,
    mut kernel: ScriptKernel,
    mut clock: ScriptClock,
    mut signal: ScriptSignal,
    mut writer: ScriptWriter,
    budget: Int = 134217728,
):
    var coll = Collector(_base_config(dir, budget))
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _run_dur(
    dir: String,
    mut kernel: ScriptKernel,
    mut clock: ScriptClock,
    mut signal: ScriptSignal,
    mut writer: ScriptWriter,
    dur_s: UInt64,
):
    var cfg = _base_config(dir)
    cfg.duration_s = dur_s
    var coll = Collector(cfg^)
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _run_null(
    dir: String,
    mut kernel: ScriptKernel,
    mut clock: ScriptClock,
    mut signal: ScriptSignal,
    mut writer: DropWriter,
):
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("appends=") + String(writer.appends))
    print(String("committed=") + String(writer.committed_len()))


def _zeros(mut kernel: ScriptKernel, nstats: Int, nsnaps: Int):
    var zstats = stats_ok(
        UInt64(0), UInt64(0), UInt64(0), UInt64(0), UInt64(0)
    )
    for _ in range(nstats):
        kernel.add_stats(zstats.copy())
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(nsnaps):
        kernel.add_snap(zsnap.copy())


def _record_batch(seq: UInt64, ktime: UInt64, size: UInt64) -> PollOut:
    return _batch(_payload(seq, ktime, size, String("sda")))


def _flow_stats(
    received: UInt64, delivered: UInt64
) -> StatsOut:
    return stats_ok(
        received, delivered, UInt64(0), UInt64(0), UInt64(0)
    )


def _err_flow(mut kernel: ScriptKernel, r: UInt64, d: UInt64):
    """Baseline + error-path final (no drain/confirm stats)."""
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(r, d))


def _err_poll() -> PollOut:
    return PollOut(
        String("error"),
        List[UInt8](),
        UInt32(0),
        String("scripted hard poll error"),
    )


def _short_frame_batch() -> PollOut:
    var raw = List[UInt8]()
    raw.append(UInt8(1))
    raw.append(UInt8(2))
    raw.append(UInt8(3))
    return PollOut(String("batch"), raw^, UInt32(0), String(""))


def _bad_utf8_batch(seq: UInt64, ktime: UInt64, size: UInt64) -> PollOut:
    """Structurally valid payload, non-UTF8 name (non-fatal)."""
    var raw = _payload(seq, ktime, size, String("sda"))
    raw[34] = UInt8(0xFF)
    raw[35] = UInt8(0xFE)
    return _batch(raw)


def _cuts(
    mut kernel: ScriptKernel,
    o: UInt64,
    ob: UInt64,
    e: UInt64,
    eb: UInt64,
    s: UInt64,
    f: UInt64,
):
    """Zero start pair + stable end cut."""
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    var cut = snap_ok(o, ob, e, eb, s, f)
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())


def _steady_flow(mut kernel: ScriptKernel, r: UInt64, d: UInt64):
    """Zero baseline + steady post-start flow (drain/end/final)."""
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    for _ in range(4):
        kernel.add_stats(_flow_stats(r, d))


def _steady_flow_md(
    mut kernel: ScriptKernel,
    r: UInt64,
    d: UInt64,
    m: UInt64,
    dr: UInt64,
):
    """Steady flow with malformed/dropped components."""
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    for _ in range(4):
        kernel.add_stats(stats_ok(r, d, UInt64(0), m, dr))


def _script_attachwin(dir: String):
    """Attach-anchored window: a 20s init/attach gap must not
    burn the 2s duration budget or backdate the window."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 4)
    var clock = ScriptClock()
    clock.add(UInt64(1000))
    clock.add(UInt64(1001))
    clock.add(UInt64(1002))
    clock.add(UInt64(20000000000))
    clock.add(UInt64(20000000001))
    clock.add(UInt64(20000000002))
    clock.add(UInt64(22000000001))
    for i in range(7):
        clock.add(UInt64(22000000002) + UInt64(i))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run_dur(dir, kernel, clock, signal, writer, UInt64(2))


def _script_canary(dir: String):
    """Hostile device names: only PCI scope persists verbatim."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _batch(_payload(
            UInt64(0), base + UInt64(10), UInt64(64),
            String("0000:00:0c.0"),
        )), 1,
    )
    kernel.add_poll(
        _batch(_payload(
            UInt64(1), base + UInt64(11), UInt64(64),
            String("ffff888012345000"),
        )), 1,
    )
    kernel.add_poll(
        _batch(_payload(
            UInt64(2), base + UInt64(12), UInt64(64),
            String("../../home/canary-alice/x"),
        )), 1,
    )
    var long_name = String("")
    for _ in range(70):
        long_name += String("A")
    kernel.add_poll(
        _batch(_payload(
            UInt64(3), base + UInt64(13), UInt64(64), long_name^
        )), 1,
    )
    kernel.add_poll(
        _batch(_payload(
            UInt64(4), base + UInt64(14), UInt64(64),
            String("eth0"),
        )), 1,
    )
    kernel.add_poll(_timeout(), 110)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    for _ in range(4):
        kernel.add_stats(_flow_stats(UInt64(5), UInt64(5)))
    _cuts(
        kernel,
        UInt64(5),
        UInt64(320),
        UInt64(5),
        UInt64(320),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(12)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_zero(dir: String):
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 4)
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _run_pool(
    dir: String,
    mut kernel: ScriptKernel,
    mut clock: ScriptClock,
    mut signal: ScriptSignal,
    mut writer: ScriptWriter,
    root: String,
):
    var cfg = _base_config(dir)
    cfg.has_pool_sample = True
    cfg.pool_root = root
    var coll = Collector(cfg^)
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _script_pool(dir: String):
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 4)
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run_pool(
        dir, kernel, clock, signal, writer,
        String("tests/fixtures/pools/debugfs-ok"),
    )


def _script_poolcap(dir: String):
    """Nine thousand seconds of capture time stop periodic pool
    sampling at 4096 with an explicit session note. The scripted
    clock steps one second per read past the four startup
    values, so every iteration fires (deadline read plus
    sample-timestamp read: two seconds per fire) until the cap
    latches, then the remaining iterations drain the clock to
    the deadline without sampling."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 10000)
    _zeros(kernel, 5, 4)
    var clock = ScriptClock()
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    clock.step = UInt64(1000000000)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    var cfg = _base_config(dir)
    cfg.duration_s = UInt64(9000)
    cfg.has_pool_sample = True
    cfg.pool_root = String("tests/fixtures/pools/debugfs-ok")
    var coll = Collector(cfg^)
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)
    print(String("polls=") + String(kernel.polls_done))
    print(String("stats=") + String(kernel.stats_done))
    print(String("snaps=") + String(kernel.snaps_done))
    print(String("reads=") + String(clock.reads))
    print(String("committed=") + String(writer.committed_len()))


def _script_detfail(dir: String):
    var kernel = ScriptKernel()
    kernel.detach_out = OpOut(False, String("scripted detach failure"))
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 4)
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_stablen(dir: String):
    """End cut stabilizes on the second pair; values used."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(
        snap_ok(
            UInt64(1),
            UInt64(64),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
        )
    )
    var cut = snap_ok(
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_neverstable(dir: String):
    """End reads never agree: unresolved, unknown, exit 4."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 2)
    var flip = True
    for _ in range(20):
        if flip:
            kernel.add_snap(
                snap_ok(
                    UInt64(1),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                )
            )
        else:
            kernel.add_snap(
                snap_ok(
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                )
            )
        flip = not flip
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_tornretry(dir: String):
    """End first read fails, retry pair agrees; values used."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(snap_err())
    var cut = snap_ok(
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_recvgt(dir: String):
    """Bridge received exceeds kernel emitted: unknown."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(
        _record_batch(UInt64(1), base + UInt64(11), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(2), UInt64(2)))
    kernel.add_stats(_flow_stats(UInt64(2), UInt64(2)))
    kernel.add_stats(_flow_stats(UInt64(2), UInt64(2)))
    kernel.add_stats(_flow_stats(UInt64(2), UInt64(2)))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    var cut = snap_ok(
        UInt64(2),
        UInt64(128),
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(4)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_confirmact(dir: String):
    """Confirm drain consumes a straggler: unknown."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(_timeout(), 4)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 99)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    var cut = snap_ok(
        UInt64(1),
        UInt64(0),
        UInt64(1),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_drainbudget(dir: String):
    """Drain clock jumps past budget: exhausted, unknown."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 101)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    _zeros(kernel, 0, 4)
    var clock = ScriptClock()
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    clock.add(base + UInt64(4))
    var latch = base + UInt64(61000000001)
    clock.add(latch)
    clock.add(latch + UInt64(1))
    clock.add(latch + UInt64(2))
    clock.add(latch + UInt64(31000000002))
    clock.add(latch + UInt64(31000000003))
    clock.add(latch + UInt64(31000000004))
    clock.add(latch + UInt64(31000000005))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_delaysubmit(dir: String):
    """Submit-fail increment lands mid-protocol; cut exact."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(
        snap_ok(
            UInt64(1),
            UInt64(64),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
        )
    )
    var cut = snap_ok(
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
        UInt64(1),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_latesubmit(dir: String):
    """Submit increment lands after the cut: identity breaks."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(2),
        UInt64(128),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_lateemit(dir: String):
    """Emit increment lands after the cut: identity breaks."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(
        _record_batch(UInt64(1), base + UInt64(11), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(2), UInt64(2))
    _cuts(
        kernel,
        UInt64(3),
        UInt64(192),
        UInt64(2),
        UInt64(128),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(4)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_wrapobs(dir: String):
    """OBSERVED_WRAP seeded: epoch invalid, detail unknown."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(6),
        UInt64(320),
        UInt64(0),
        UInt64(0),
        UInt64(1),
        UInt64(1),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_wrapemit(dir: String):
    """EMITTED_WRAP seeded: epoch invalid, detail unknown."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(9),
        UInt64(64),
        UInt64(1),
        UInt64(4),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_wrapsubmit(dir: String):
    """SUBMIT_WRAP seeded: submit_fail renders unavailable."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
        UInt64(13),
        UInt64(16),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_wrapobsbytes(dir: String):
    """OBSERVED_BYTES_WRAP: bytes invalid, detail stays exact."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(500),
        UInt64(0),
        UInt64(0),
        UInt64(1),
        UInt64(2),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_wrapemitbytes(dir: String):
    """EMITTED_BYTES_WRAP: bytes invalid, detail stays exact."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(400),
        UInt64(1),
        UInt64(8),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_bytecov(dir: String):
    """BYTE_COVERAGE seeded: aggregate unavailable, no gap."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(41),
        UInt64(0),
        UInt64(0),
        UInt64(1),
        UInt64(32),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_recoverable(dir: String):
    """Known combo: malformed + dropped + omitted + rejected."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(
        _bad_utf8_batch(UInt64(1), base + UInt64(11), UInt64(32)), 1
    )
    kernel.add_poll(_timeout(), 1)
    kernel.add_poll(
        _record_batch(UInt64(99), base + UInt64(12), UInt64(48)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow_md(
        kernel,
        UInt64(5),
        UInt64(3),
        UInt64(1),
        UInt64(1),
    )
    _cuts(
        kernel,
        UInt64(5),
        UInt64(144),
        UInt64(5),
        UInt64(144),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(5)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_appendfail0(dir: String):
    """First attempt append fails: error path, exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    _err_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    writer.append_faults.append(AppendFault(1, String("error")))
    _run(dir, kernel, clock, signal, writer)


def _script_appendtorn(dir: String):
    """Second append fails: retained prefix + gap, exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(
        _record_batch(UInt64(1), base + UInt64(11), UInt64(64)), 1
    )
    _err_flow(kernel, UInt64(2), UInt64(2))
    _cuts(
        kernel,
        UInt64(2),
        UInt64(128),
        UInt64(2),
        UInt64(128),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(4)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    writer.append_faults.append(AppendFault(2, String("error")))
    _run(dir, kernel, clock, signal, writer)


def _script_catalogfull(dir: String):
    """4097th distinct device: exhaustion, error path."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    for i in range(4097):
        var raw = _payload(
            UInt64(i), base + UInt64(10), UInt64(64),
            String(t"dev{i}"),
        )
        kernel.add_poll(_batch(raw^), 1)
    _err_flow(kernel, UInt64(4097), UInt64(4097))
    _cuts(
        kernel,
        UInt64(4097),
        UInt64(262208),
        UInt64(4097),
        UInt64(262208),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(8194)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_hardpoll(dir: String):
    """Hard poll error with staged=1 observed, exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_err_poll(), 1)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(
        stats_ok(
            UInt64(2),
            UInt64(1),
            UInt64(1),
            UInt64(0),
            UInt64(0),
        )
    )
    _cuts(
        kernel,
        UInt64(2),
        UInt64(128),
        UInt64(2),
        UInt64(128),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(3)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_structfault(dir: String):
    """Short frame: structure fault, error path, exit 1."""
    var kernel = ScriptKernel()
    kernel.add_poll(_short_frame_batch(), 1)
    _err_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(1)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_structfaultq(dir: String):
    """Fault first, good record queued: never polled."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(_short_frame_batch(), 1)
    kernel.add_poll(
        _record_batch(UInt64(1), base + UInt64(11), UInt64(64)), 1
    )
    _err_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(1)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_durhard(dir: String):
    """Duration latch, then drain hard error: exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(_timeout(), 2)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_err_poll(), 1)
    kernel.add_poll(_timeout(), 100)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(0),
        UInt64(1),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_sigclose(dir: String):
    """Signal latch, then drain hard error: exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_err_poll(), 1)
    kernel.add_poll(_timeout(), 100)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    kernel.add_stats(_flow_stats(UInt64(1), UInt64(1)))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(0),
        UInt64(1),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(0)
    var signal = ScriptSignal()
    signal.add(String("pending"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_errdetfail(dir: String):
    """Collection error + detach failure: detach primary."""
    var kernel = ScriptKernel()
    kernel.detach_out = OpOut(False, String("scripted detach failure"))
    kernel.add_poll(_short_frame_batch(), 1)
    _err_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(1)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_combinederr(dir: String):
    """Error + detach failure + unresolved snap: R6D5."""
    var kernel = ScriptKernel()
    kernel.detach_out = OpOut(False, String("scripted detach failure"))
    kernel.add_poll(_short_frame_batch(), 1)
    _err_flow(kernel, UInt64(1), UInt64(1))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    var flip = True
    for _ in range(20):
        if flip:
            kernel.add_snap(
                snap_ok(
                    UInt64(1),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                )
            )
        else:
            kernel.add_snap(zsnap.copy())
        flip = not flip
    var clock = _clock(1)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_siginhand(dir: String):
    """Signal trips with a record in hand: omitted, exit 4."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    signal.add(String("none"))
    signal.add(String("pending"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_sigreaderr(dir: String):
    """Signal read error in hand: error state, exit 1."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(1),
        UInt64(64),
        UInt64(1),
        UInt64(64),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    signal.add(String("none"))
    signal.add_error(String("scripted EIO"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_sigreaderr0(dir: String):
    """Signal read error before any poll: exit 1, no gap."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(0)
    var signal = ScriptSignal()
    signal.add_error(String("scripted EIO"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_sigsetupfail(dir: String):
    """Signal setup fails: refusal, exit 3, no output."""
    var kernel = ScriptKernel()
    var clock = _clock(0)
    var signal = ScriptSignal()
    signal.setup_out = OpOut(False, String("scripted mask failure"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_sigsetuprollback(dir: String):
    """Setup fails and close fails: residual, exit 1."""
    var kernel = ScriptKernel()
    kernel.close_out = OpOut(False, String("scripted close failure"))
    var clock = _clock(0)
    var signal = ScriptSignal()
    signal.setup_out = OpOut(False, String("scripted mask failure"))
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_attachfail(dir: String):
    """Attach fails: refusal, exit 3, dir gone."""
    var kernel = ScriptKernel()
    kernel.attach_out = OpOut(False, String("scripted attach failure"))
    _zeros(kernel, 1, 2)
    var clock = _clock(0)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_rollbackfail(dir: String):
    """Attach fails and close fails: residual, exit 1."""
    var kernel = ScriptKernel()
    kernel.attach_out = OpOut(False, String("scripted attach failure"))
    kernel.close_out = OpOut(False, String("scripted close failure"))
    _zeros(kernel, 1, 2)
    var clock = _clock(0)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_nonzerostart(dir: String):
    """Stable but nonzero start: refusal, exit 3."""
    var kernel = ScriptKernel()
    var cut = snap_ok(
        UInt64(1),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(cut.copy())
    kernel.add_snap(cut.copy())
    var clock = _clock(0)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_clockseam(dir: String):
    """End-pair timestamp jump: end_ns derives past it."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    var zsnap = snap_ok(
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    kernel.add_snap(zsnap.copy())
    var clock = ScriptClock()
    var base = UInt64(1000000000)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    clock.add(base + UInt64(4))
    clock.add(base + UInt64(5))
    var latch = base + UInt64(61000000001)
    clock.add(latch)
    clock.add(latch + UInt64(1))
    clock.add(latch + UInt64(2))
    clock.add(latch + UInt64(3))
    clock.add(latch + UInt64(4))
    clock.add(latch + UInt64(5))
    clock.add(latch + UInt64(5000000000))
    clock.add(latch + UInt64(6))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_ooo100(dir: String):
    """Out-of-order stamps past the cut: advance succeeds."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    var latch = base + UInt64(61000000001)
    var bent = latch + UInt64(5) + UInt64(1) + UInt64(100000000)
    kernel.add_poll(
        _record_batch(UInt64(0), bent + UInt64(50), UInt64(64)), 1
    )
    kernel.add_poll(
        _record_batch(UInt64(1), bent + UInt64(10), UInt64(64)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(2), UInt64(2))
    _cuts(
        kernel,
        UInt64(2),
        UInt64(128),
        UInt64(2),
        UInt64(128),
        UInt64(0),
        UInt64(0),
    )
    var clock = ScriptClock()
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    clock.add(base + UInt64(4))
    clock.add(base + UInt64(5))
    clock.add(base + UInt64(6))
    clock.add(base + UInt64(7))
    clock.add(latch)
    var tail = latch + UInt64(5)
    clock.add(latch + UInt64(1))
    clock.add(latch + UInt64(2))
    clock.add(latch + UInt64(3))
    clock.add(latch + UInt64(4))
    clock.add(tail)
    clock.add(tail + UInt64(1))
    clock.add(tail + UInt64(2))
    clock.add(tail + UInt64(60))
    clock.add(tail + UInt64(61))
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_opcount(dir: String):
    """Cross the 4194304 op cap: size latch, exact session.

    Null writer: event bytes are dropped (a true
    crossing needs 1.4 GiB of events, past the frozen
    256 MiB reader cap, so no full replay here); every
    line still passes the shape gate, and the spilled
    session.json carries the exact boundary proof. Full
    replay of a size latch is covered by sizerefused.
    """
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(1), UInt64(64)),
        4194305,
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    var flow = stats_ok(
        UInt64(4194305),
        UInt64(4194305),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(4):
        kernel.add_stats(flow.copy())
    _cuts(
        kernel,
        UInt64(4194305),
        UInt64(268435520),
        UInt64(4194305),
        UInt64(268435520),
        UInt64(0),
        UInt64(0),
    )
    var clock = ScriptClock()
    clock.step = UInt64(0)
    clock.add(base)
    clock.add(base + UInt64(1))
    clock.add(base + UInt64(2))
    clock.add(base + UInt64(3))
    var signal = ScriptSignal()
    var writer = DropWriter()
    _run_null(dir, kernel, clock, signal, writer)


def _script_live_refuse(dir: String):
    """Live-adapter startup refusal stays a clean refusal.

    REAL LmbKernel (unloadable bridge) plus a REAL fresh
    LiveWriter: open fails before any resource exists, so
    rollback must report no residuals and the run must end
    refused (exit 3), not refusal-rollback-failed (exit 1).
    Guards the live/scripted cleanup contract match.
    """
    var elf = List[UInt8]()
    var kernel = LmbKernel(
        elf^,
        String("mv_attempts"),
        String("/nonexistent-bridge-dir/nolib.so"),
        String("mv_attempt_trace"),
        String("swiotlb"),
        String("swiotlb_bounced"),
    )
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = LiveWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)


def _script_live_create_residual(dir: String):
    """Stuck construction unwind ends refusal-rollback-failed.

    Scripted kernel (all-ok) plus a REAL LiveWriter under
    fstat/unlink faults: create fails AND its unwind sticks,
    so abandon reports construction residuals and the run
    must end refusal-rollback-failed (exit 1), never a
    clean refusal. Run under LD_PRELOAD faults by the lane.
    """
    var kernel = ScriptKernel()
    _zeros(kernel, 1, 2)
    var clock = ScriptClock()
    var signal = ScriptSignal()
    var writer = LiveWriter()
    var coll = Collector(_base_config(dir))
    var res = coll.run(kernel, clock, signal, writer)
    _report(String(""), res)


def _script_sizerefused(dir: String):
    """Budget refusal trips the size latch; capture replays."""
    var kernel = ScriptKernel()
    kernel.seq_patch = True
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(64)),
        190,
    )
    kernel.add_poll(_timeout(), 102)
    kernel.add_stats(_flow_stats(UInt64(0), UInt64(0)))
    var flow = stats_ok(
        UInt64(190),
        UInt64(190),
        UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    for _ in range(4):
        kernel.add_stats(flow.copy())
    _cuts(
        kernel,
        UInt64(190),
        UInt64(12160),
        UInt64(190),
        UInt64(12160),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(380)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer, 131072)


def _script_pausedbytes(dir: String):
    """Paused-before-byte-update cut: identity breaks (R5D2)."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), UInt64(6)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(1), UInt64(1))
    _cuts(
        kernel,
        UInt64(2),
        UInt64(10),
        UInt64(1),
        UInt64(6),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_u64sum(dir: String):
    """MAX then 1 byte: sum guard omits + latches (R5D4)."""
    var kernel = ScriptKernel()
    var base = UInt64(1000000000)
    kernel.add_poll(
        _record_batch(UInt64(0), base + UInt64(10), ~UInt64(0)), 1
    )
    kernel.add_poll(
        _record_batch(UInt64(1), base + UInt64(11), UInt64(1)), 1
    )
    kernel.add_poll(_timeout(), 102)
    _steady_flow(kernel, UInt64(2), UInt64(2))
    _cuts(
        kernel,
        UInt64(2),
        ~UInt64(0),
        UInt64(2),
        ~UInt64(0),
        UInt64(0),
        UInt64(0),
    )
    var clock = _clock(4)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_flowinject(dir: String):
    """C-simulator cut O=2,S=2,E=0+BYTE_COVERAGE (R6D4).

    Values mirror the counter-flow simulator's
    injected-fail/normal-firing schedule exactly; the
    simulator test pins the producer side of the pact.
    """
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _steady_flow(kernel, UInt64(0), UInt64(0))
    _cuts(
        kernel,
        UInt64(2),
        UInt64(0),
        UInt64(0),
        UInt64(0),
        UInt64(2),
        UInt64(32),
    )
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    _run(dir, kernel, clock, signal, writer)


def _script_unsynced(dir: String):
    """Finalize reports present_unsynced: exit 1, files kept."""
    var kernel = ScriptKernel()
    kernel.add_poll(_timeout(), 104)
    _zeros(kernel, 5, 4)
    var clock = _clock(2)
    var signal = ScriptSignal()
    var writer = ScriptWriter()
    writer.finalize_status = String("present_unsynced")
    _run(dir, kernel, clock, signal, writer)


def main() raises:
    var args = argv()
    if len(args) != 3:
        print(String("usage: collector_probe <script> <dir>"))
        exit(2)
    if args[1] == String("canary"):
        _script_canary(args[2])
    elif args[1] == String("attachwin"):
        _script_attachwin(args[2])
    elif args[1] == String("zero"):
        _script_zero(args[2])
    elif args[1] == String("pool"):
        _script_pool(args[2])
    elif args[1] == String("poolcap"):
        _script_poolcap(args[2])
    elif args[1] == String("detfail"):
        _script_detfail(args[2])
    elif args[1] == String("stablen"):
        _script_stablen(args[2])
    elif args[1] == String("neverstable"):
        _script_neverstable(args[2])
    elif args[1] == String("tornretry"):
        _script_tornretry(args[2])
    elif args[1] == String("recvgt"):
        _script_recvgt(args[2])
    elif args[1] == String("confirmact"):
        _script_confirmact(args[2])
    elif args[1] == String("drainbudget"):
        _script_drainbudget(args[2])
    elif args[1] == String("delaysubmit"):
        _script_delaysubmit(args[2])
    elif args[1] == String("latesubmit"):
        _script_latesubmit(args[2])
    elif args[1] == String("lateemit"):
        _script_lateemit(args[2])
    elif args[1] == String("wrapobs"):
        _script_wrapobs(args[2])
    elif args[1] == String("wrapemit"):
        _script_wrapemit(args[2])
    elif args[1] == String("wrapsubmit"):
        _script_wrapsubmit(args[2])
    elif args[1] == String("wrapobsbytes"):
        _script_wrapobsbytes(args[2])
    elif args[1] == String("wrapemitbytes"):
        _script_wrapemitbytes(args[2])
    elif args[1] == String("bytecov"):
        _script_bytecov(args[2])
    elif args[1] == String("recoverable"):
        _script_recoverable(args[2])
    elif args[1] == String("appendfail0"):
        _script_appendfail0(args[2])
    elif args[1] == String("appendtorn"):
        _script_appendtorn(args[2])
    elif args[1] == String("catalogfull"):
        _script_catalogfull(args[2])
    elif args[1] == String("hardpoll"):
        _script_hardpoll(args[2])
    elif args[1] == String("structfault"):
        _script_structfault(args[2])
    elif args[1] == String("structfaultq"):
        _script_structfaultq(args[2])
    elif args[1] == String("durhard"):
        _script_durhard(args[2])
    elif args[1] == String("sigclose"):
        _script_sigclose(args[2])
    elif args[1] == String("errdetfail"):
        _script_errdetfail(args[2])
    elif args[1] == String("combinederr"):
        _script_combinederr(args[2])
    elif args[1] == String("siginhand"):
        _script_siginhand(args[2])
    elif args[1] == String("sigreaderr"):
        _script_sigreaderr(args[2])
    elif args[1] == String("sigreaderr0"):
        _script_sigreaderr0(args[2])
    elif args[1] == String("sigsetupfail"):
        _script_sigsetupfail(args[2])
    elif args[1] == String("sigsetuprollback"):
        _script_sigsetuprollback(args[2])
    elif args[1] == String("attachfail"):
        _script_attachfail(args[2])
    elif args[1] == String("rollbackfail"):
        _script_rollbackfail(args[2])
    elif args[1] == String("nonzerostart"):
        _script_nonzerostart(args[2])
    elif args[1] == String("clockseam"):
        _script_clockseam(args[2])
    elif args[1] == String("ooo100"):
        _script_ooo100(args[2])
    elif args[1] == String("opcount"):
        _script_opcount(args[2])
    elif args[1] == String("live-refuse"):
        _script_live_refuse(args[2])
    elif args[1] == String("live-create-residual"):
        _script_live_create_residual(args[2])
    elif args[1] == String("sizerefused"):
        _script_sizerefused(args[2])
    elif args[1] == String("pausedbytes"):
        _script_pausedbytes(args[2])
    elif args[1] == String("u64sum"):
        _script_u64sum(args[2])
    elif args[1] == String("flowinject"):
        _script_flowinject(args[2])
    elif args[1] == String("unsynced"):
        _script_unsynced(args[2])
    else:
        print(String("unknown script"))
        exit(2)
