# SPDX-License-Identifier: GPL-3.0-or-later

"""Scripted collector sources for the close-out matrix.

Test-only: deterministic poll/stats/snapshot/clock/signal
scripts plus a real-writer adapter with scripted faults
and an in-memory null writer. The probe owns the
sources across run() for post-run assertions.
"""

from std.ffi import external_call

from memveil.capture.collector import (
    AppendOut,
    ClockSource,
    CreateOut,
    FinalOut,
    GeomOut,
    GroupOut,
    KernelSource,
    OpOut,
    PollOut,
    SignalOut,
    SignalSource,
    SnapOut,
    StatsOut,
    WriterSource,
)
from memveil.capture.writer import EventWriter


comptime _D_O_WRONLY = 1
comptime _D_O_CREAT = 64
comptime _D_O_EXCL = 128
comptime _D_AT_FDCWD = -100
comptime _D_EEXIST = 17


@fieldwise_init
struct ScriptPollItem(Copyable, Movable):
    """One poll script entry with run-length repeats."""

    var out: PollOut
    var repeat: Int


struct ScriptKernel(KernelSource):
    var open_out: OpOut
    var load_out: OpOut
    var counts_geom: GeomOut
    var ring_geom: GeomOut
    var ring_geom1: GeomOut
    var ring_geom2: GeomOut
    var attach_out: OpOut
    var detach_out: OpOut
    var close_out: OpOut
    var channels: Int
    var polls: List[ScriptPollItem]
    var poll_idx: Int
    var poll_left: Int
    var stats_q: List[StatsOut]
    var stats_idx: Int
    var stats_q1: List[StatsOut]
    var stats_idx1: Int
    var stats_q2: List[StatsOut]
    var stats_idx2: Int
    var snaps: List[SnapOut]
    var snap_idx: Int
    var snaps1: List[SnapOut]
    var snap_idx1: Int
    var snaps2: List[SnapOut]
    var snap_idx2: Int
    var poll_timeouts: List[Int]
    var poll_caps: List[UInt32]
    var polls_done: Int
    var stats_done: Int
    var snaps_done: Int
    var closes_done: Int
    var seq_patch: Bool
    var seq_next: UInt64
    var raise_on_poll: Int
    var raise_signo: Int32

    def __init__(out self):
        var ok = OpOut(True, String(""))
        self.open_out = ok.copy()
        self.load_out = ok.copy()
        self.counts_geom = GeomOut(
            True, UInt32(2), UInt32(4), UInt32(8), UInt32(6), String("")
        )
        self.ring_geom = GeomOut(
            True, UInt32(27), UInt32(0), UInt32(0), UInt32(8388608),
            String(""),
        )
        self.ring_geom1 = GeomOut(
            True, UInt32(27), UInt32(0), UInt32(0), UInt32(8388608),
            String(""),
        )
        self.ring_geom2 = GeomOut(
            True, UInt32(27), UInt32(0), UInt32(0), UInt32(8388608),
            String(""),
        )
        self.attach_out = ok.copy()
        self.detach_out = ok.copy()
        self.close_out = ok.copy()
        self.channels = 1
        self.polls = List[ScriptPollItem]()
        self.poll_idx = 0
        self.poll_left = 0
        self.stats_q = List[StatsOut]()
        self.stats_idx = 0
        self.stats_q1 = List[StatsOut]()
        self.stats_idx1 = 0
        self.stats_q2 = List[StatsOut]()
        self.stats_idx2 = 0
        self.snaps = List[SnapOut]()
        self.snap_idx = 0
        self.snaps1 = List[SnapOut]()
        self.snap_idx1 = 0
        self.snaps2 = List[SnapOut]()
        self.snap_idx2 = 0
        self.poll_timeouts = List[Int]()
        self.poll_caps = List[UInt32]()
        self.polls_done = 0
        self.stats_done = 0
        self.snaps_done = 0
        self.closes_done = 0
        self.seq_patch = False
        self.seq_next = UInt64(0)
        self.raise_on_poll = -1
        self.raise_signo = Int32(15)

    def open_session(mut self) -> OpOut:
        return self.open_out.copy()

    def load(mut self) -> OpOut:
        return self.load_out.copy()

    def map_info(mut self, name: String) -> GeomOut:
        if name == String("mv_counts"):
            return self.counts_geom.copy()
        return self.ring_geom.copy()

    def map_info_at(mut self, channel: Int, name: String) -> GeomOut:
        if channel < 0 or channel >= self.channels:
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                String("bad channel"),
            )
        if name == String("mv_counts"):
            return self.counts_geom.copy()
        if channel == 1:
            return self.ring_geom1.copy()
        if channel == 2:
            return self.ring_geom2.copy()
        return self.ring_geom.copy()

    def channel_count(self) -> Int:
        return self.channels

    def attach(mut self) -> OpOut:
        return self.attach_out.copy()

    def add_poll(mut self, item: PollOut, repeat: Int):
        self.polls.append(ScriptPollItem(item.copy(), repeat))

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        self.poll_timeouts.append(timeout_ms)
        self.poll_caps.append(capacity)
        self.polls_done += 1
        if self.polls_done == self.raise_on_poll:
            _ = external_call["raise", Int32](self.raise_signo)
        while True:
            if self.poll_idx >= len(self.polls):
                return PollOut(
                    String("error"), List[UInt8](), UInt32(0),
                    String("script exhausted: poll"),
                )
            var item = self.polls[self.poll_idx].copy()
            if self.poll_left <= 0:
                self.poll_left = item.repeat
            if self.poll_left <= 0:
                self.poll_idx += 1
                continue
            self.poll_left -= 1
            var out = item.out.copy()
            if self.seq_patch and out.kind == String("batch"):
                if len(out.frame) >= 24:
                    var v = self.seq_next
                    for i in range(8):
                        out.frame[16 + i] = UInt8(
                            v & UInt64(0xFF)
                        )
                        v >>= UInt64(8)
                    self.seq_next += UInt64(1)
            if self.poll_left <= 0:
                self.poll_idx += 1
            return out^

    def add_stats(mut self, item: StatsOut):
        self.stats_q.append(item.copy())

    def add_stats_at(mut self, channel: Int, item: StatsOut):
        if channel == 1:
            self.stats_q1.append(item.copy())
        elif channel == 2:
            self.stats_q2.append(item.copy())
        else:
            self.stats_q.append(item.copy())

    def stats(mut self) -> StatsOut:
        self.stats_done += 1
        if self.stats_idx >= len(self.stats_q):
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                String("script exhausted: stats"),
            )
        var out = self.stats_q[self.stats_idx].copy()
        self.stats_idx += 1
        return out^

    def stats_at(mut self, channel: Int) -> StatsOut:
        if channel == 0 or channel < 0 or channel >= self.channels:
            if channel < 0 or channel >= self.channels:
                return StatsOut(
                    False,
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    String("bad channel"),
                )
            return self.stats()
        self.stats_done += 1
        if channel == 1:
            if self.stats_idx1 >= len(self.stats_q1):
                return StatsOut(
                    False,
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    String("script exhausted: stats1"),
                )
            var out = self.stats_q1[self.stats_idx1].copy()
            self.stats_idx1 += 1
            return out^
        if channel == 2:
            if self.stats_idx2 >= len(self.stats_q2):
                return StatsOut(
                    False,
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    String("script exhausted: stats2"),
                )
            var out = self.stats_q2[self.stats_idx2].copy()
            self.stats_idx2 += 1
            return out^
        return self.stats()

    def add_snap(mut self, item: SnapOut):
        self.snaps.append(item.copy())

    def add_snap_at(mut self, channel: Int, item: SnapOut):
        if channel == 1:
            self.snaps1.append(item.copy())
        elif channel == 2:
            self.snaps2.append(item.copy())
        else:
            self.snaps.append(item.copy())

    def read_full(mut self) -> SnapOut:
        self.snaps_done += 1
        if self.snap_idx >= len(self.snaps):
            return SnapOut(
                False, List[UInt64](), String("script exhausted: snap")
            )
        var out = self.snaps[self.snap_idx].copy()
        self.snap_idx += 1
        return out^

    def read_full_at(mut self, channel: Int) -> SnapOut:
        if channel == 0 or channel < 0 or channel >= self.channels:
            if channel < 0 or channel >= self.channels:
                return SnapOut(
                    False, List[UInt64](), String("bad channel")
                )
            return self.read_full()
        self.snaps_done += 1
        if channel == 1:
            if self.snap_idx1 >= len(self.snaps1):
                return SnapOut(
                    False, List[UInt64](),
                    String("script exhausted: snap1"),
                )
            var out = self.snaps1[self.snap_idx1].copy()
            self.snap_idx1 += 1
            return out^
        if channel == 2:
            if self.snap_idx2 >= len(self.snaps2):
                return SnapOut(
                    False, List[UInt64](),
                    String("script exhausted: snap2"),
                )
            var out = self.snaps2[self.snap_idx2].copy()
            self.snap_idx2 += 1
            return out^
        return self.read_full()

    def detach(mut self) -> OpOut:
        return self.detach_out.copy()

    def close(mut self) -> OpOut:
        self.closes_done += 1
        return self.close_out.copy()


struct ScriptClock(ClockSource):
    var vals: List[UInt64]
    var idx: Int
    var step: UInt64
    var offset: UInt64
    var sleeps: List[Int]
    var reads: Int

    def __init__(out self):
        self.vals = List[UInt64]()
        self.idx = 0
        self.step = UInt64(1000000)
        self.offset = UInt64(0)
        self.sleeps = List[Int]()
        self.reads = 0

    def add(mut self, v: UInt64):
        self.vals.append(v)

    def now(mut self) -> UInt64:
        self.reads += 1
        var top = ~UInt64(0)
        var base = UInt64(0)
        if self.idx < len(self.vals):
            base = self.vals[self.idx]
        elif len(self.vals) > 0:
            var last = self.vals[len(self.vals) - 1]
            var k = UInt64(self.idx - len(self.vals) + 1)
            base = top
            if self.step == UInt64(0) or k <= top // self.step:
                var add = self.step * k
                if add <= top - last:
                    base = last + add
        self.idx += 1
        if base > top - self.offset:
            return top
        return base + self.offset

    def sleep_ms(mut self, ms: Int):
        self.sleeps.append(ms)
        var add = UInt64(ms) * UInt64(1000000)
        if add > ~UInt64(0) - self.offset:
            self.offset = ~UInt64(0)
        else:
            self.offset += add


struct ScriptSignal(SignalSource):
    var setup_out: OpOut
    var states: List[SignalOut]
    var idx: Int
    var checks: Int
    var setups: Int

    def __init__(out self):
        self.setup_out = OpOut(True, String(""))
        self.states = List[SignalOut]()
        self.idx = 0
        self.checks = 0
        self.setups = 0

    def setup(mut self) -> OpOut:
        self.setups += 1
        return self.setup_out.copy()

    def add(mut self, state: String):
        self.states.append(SignalOut(state, String("")))

    def add_error(mut self, message: String):
        self.states.append(SignalOut(String("error"), message))

    def check(mut self) -> SignalOut:
        self.checks += 1
        if self.idx >= len(self.states):
            return SignalOut(String("none"), String(""))
        var out = self.states[self.idx].copy()
        self.idx += 1
        return out^


@fieldwise_init
struct AppendFault(Copyable, Movable):
    """Fail the Nth append (1-based) with kind."""

    var at: Int
    var kind: String


struct ScriptWriter(WriterSource):
    """Real EventWriter (lazy) with scripted fault injection."""

    var slots: List[EventWriter]
    var append_faults: List[AppendFault]
    var abort_fault: Bool
    var finalize_status: String
    var appends: Int
    var creates: Int
    var discards: Int

    def __init__(out self):
        self.slots = List[EventWriter]()
        self.append_faults = List[AppendFault]()
        self.abort_fault = False
        self.finalize_status = String("")
        self.appends = 0
        self.creates = 0
        self.discards = 0

    def create(mut self, path: String, budget: Int) -> CreateOut:
        self.creates += 1
        try:
            self.slots.append(EventWriter(path, budget))
        except e:
            return CreateOut(False, e.kind, e.message)
        return CreateOut(True, String(""), String(""))

    def append(mut self, line: List[UInt8]) -> AppendOut:
        self.appends += 1
        for i in range(len(self.append_faults)):
            if self.append_faults[i].at == self.appends:
                return AppendOut(
                    False, self.append_faults[i].kind,
                    String("scripted fault"),
                )
        try:
            self.slots[0].append(line)
        except e:
            return AppendOut(False, e.kind, e.message)
        return AppendOut(True, String(""), String(""))

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        self.appends += 1
        for i in range(len(self.append_faults)):
            if self.append_faults[i].at == self.appends:
                return AppendOut(
                    False, self.append_faults[i].kind,
                    String("scripted fault"),
                )
        try:
            self.slots[0].append_closing(line)
        except e:
            return AppendOut(False, e.kind, e.message)
        return AppendOut(True, String(""), String(""))

    def group_begin(mut self) -> GroupOut:
        try:
            var mark = self.slots[0].group_begin()
            return GroupOut(True, mark, String(""))
        except e:
            return GroupOut(False, 0, e.kind)

    def group_abort(mut self, mark: Int) -> AppendOut:
        if self.abort_fault:
            return AppendOut(False, String("fatal"), String("scripted"))
        try:
            self.slots[0].group_abort(mark)
        except e:
            return AppendOut(False, e.kind, e.message)
        return AppendOut(True, String(""), String(""))

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        try:
            var outcome = self.slots[0].finalize(session)
            if self.finalize_status != String(""):
                return FinalOut(self.finalize_status, outcome.message)
            return FinalOut(outcome.status, outcome.message)
        except e:
            return FinalOut(String("misuse"), e.message)

    def abandon(mut self) -> String:
        if len(self.slots) == 0:
            return String("")
        return self.slots[0].abandon()

    def discard(mut self):
        self.discards += 1
        if len(self.slots) > 0:
            self.slots[0].discard()

    def committed_len(self) -> Int:
        if len(self.slots) == 0:
            return 0
        return self.slots[0].committed_len()


struct NullWriter(WriterSource):
    """In-memory recording writer for the op-count case."""

    var created: Bool
    var lines: List[List[UInt8]]
    var lens: List[Int]
    var session_bytes: List[UInt8]
    var committed: Int
    var appends: Int
    var finalized: Bool

    def __init__(out self):
        self.created = False
        self.lines = List[List[UInt8]]()
        self.lens = List[Int]()
        self.session_bytes = List[UInt8]()
        self.committed = 0
        self.appends = 0
        self.finalized = False

    def create(mut self, path: String, budget: Int) -> CreateOut:
        self.created = True
        return CreateOut(True, String(""), String(""))

    def append(mut self, line: List[UInt8]) -> AppendOut:
        self.appends += 1
        self.committed += len(line)
        self.lens.append(len(line))
        self.lines.append(line.copy())
        return AppendOut(True, String(""), String(""))

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        return self.append(line)

    def group_begin(mut self) -> GroupOut:
        return GroupOut(True, self.committed, String(""))

    def group_abort(mut self, mark: Int) -> AppendOut:
        if mark < 0 or mark > self.committed:
            return AppendOut(False, String("misuse"), String("bad mark"))
        while self.committed > mark:
            var n = self.lens.pop()
            self.committed -= n
            _ = self.lines.pop()
        return AppendOut(True, String(""), String(""))

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        self.session_bytes = session.copy()
        self.finalized = True
        return FinalOut(String("finalized"), String(""))

    def abandon(mut self) -> String:
        self.lines = List[List[UInt8]]()
        self.lens = List[Int]()
        self.session_bytes = List[UInt8]()
        self.committed = 0
        return String("")

    def discard(mut self):
        pass

    def committed_len(self) -> Int:
        return self.committed


def _d_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _d_errno() -> Int:
    var p = external_call[
        "__errno_location", Pointer[Int32, MutAnyOrigin]
    ]()
    return Int(p.unsafe_load())


def _d_line_ok(line: List[UInt8]) -> Bool:
    """Cheap shape gate: schema head + newline tail."""
    var head = String("{\"schema_version\":\"0.1.1\"")
    var raw = head.as_bytes()
    if len(line) < len(raw) + 1:
        return False
    for i in range(len(raw)):
        if line[i] != raw[i]:
            return False
    return line[len(line) - 1] == UInt8(0x0A)


struct DropWriter(WriterSource):
    """Null writer: counts + shape-checks lines, spills session.

    Event bytes are dropped (the op-count crossing would
    otherwise need 1.4 GiB of events); every line still
    passes a schema-head/newline-tail gate, and finalize
    writes a real session.json into the created dir. No
    fsync: the spill is read back on the same machine.
    """

    var dir_path: String
    var created: Bool
    var appends: Int
    var bytes: Int
    var mark_appends: Int
    var mark_bytes: Int
    var finalized: Bool

    def __init__(out self):
        self.dir_path = String("")
        self.created = False
        self.appends = 0
        self.bytes = 0
        self.mark_appends = 0
        self.mark_bytes = 0
        self.finalized = False

    def create(mut self, path: String, budget: Int) -> CreateOut:
        var cstr = _d_cstr(path)
        var made = external_call["mkdir", Int32](
            Span(cstr).unsafe_ptr(), 0o700
        )
        if Int(made) != 0:
            if _d_errno() == _D_EEXIST:
                return CreateOut(
                    False, String("exists"),
                    String("output exists"),
                )
            return CreateOut(
                False, String("io"), String("mkdir failed")
            )
        self.dir_path = path.copy()
        self.created = True
        return CreateOut(True, String(""), String(""))

    def append(mut self, line: List[UInt8]) -> AppendOut:
        if not _d_line_ok(line):
            return AppendOut(
                False, String("fatal"), String("misshapen line")
            )
        self.appends += 1
        self.bytes += len(line)
        return AppendOut(True, String(""), String(""))

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        return self.append(line)

    def group_begin(mut self) -> GroupOut:
        self.mark_appends = self.appends
        self.mark_bytes = self.bytes
        return GroupOut(True, self.bytes, String(""))

    def group_abort(mut self, mark: Int) -> AppendOut:
        if mark != self.mark_bytes:
            return AppendOut(
                False, String("misuse"), String("bad mark")
            )
        self.appends = self.mark_appends
        self.bytes = self.mark_bytes
        return AppendOut(True, String(""), String(""))

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        var cstr = _d_cstr(self.dir_path + String("/session.json"))
        var fd = external_call["openat", Int32](
            Int32(_D_AT_FDCWD),
            Span(cstr).unsafe_ptr(),
            Int32(_D_O_WRONLY | _D_O_CREAT | _D_O_EXCL),
            UInt32(0o600),
        )
        if fd < Int32(0):
            return FinalOut(
                String("unfinalized"), String("session create failed")
            )
        var off = 0
        var ok = True
        while off < len(session):
            var n = external_call["pwrite", Int64](
                fd,
                Span(session).unsafe_ptr().unsafe_offset(off),
                Int64(len(session) - off),
                Int64(off),
            )
            if Int(n) <= 0:
                ok = False
                break
            off += Int(n)
        _ = external_call["close", Int32](fd)
        if not ok:
            return FinalOut(
                String("unfinalized"), String("session write failed")
            )
        self.finalized = True
        return FinalOut(String("finalized"), String(""))

    def abandon(mut self) -> String:
        var cstr = _d_cstr(self.dir_path)
        var r = external_call["rmdir", Int32](Span(cstr).unsafe_ptr())
        if Int(r) != 0:
            return String("rmdir failed")
        self.created = False
        return String("")

    def discard(mut self):
        pass

    def committed_len(self) -> Int:
        return self.bytes


def stats_ok(
    received: UInt64, delivered: UInt64, staged: UInt64,
    malformed: UInt64, dropped: UInt64,
) -> StatsOut:
    return StatsOut(
        True, received, delivered, staged, malformed, dropped,
        String(""),
    )


def snap_ok(
    observed: UInt64, observed_bytes: UInt64, emitted: UInt64,
    emitted_bytes: UInt64, submit_fail: UInt64, flags: UInt64,
) -> SnapOut:
    var vals = List[UInt64]()
    vals.append(observed)
    vals.append(observed_bytes)
    vals.append(emitted)
    vals.append(emitted_bytes)
    vals.append(submit_fail)
    vals.append(flags)
    return SnapOut(True, vals^, String(""))


def snap_err() -> SnapOut:
    return SnapOut(False, List[UInt64](), String("scripted read error"))
