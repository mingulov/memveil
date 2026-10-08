# SPDX-License-Identifier: GPL-3.0-or-later

"""Live kernel source: KernelSource over libbpf-mojo sessions.

Thin ownership adapter, no policy: every trait method
takes the session out of its slot, runs one bridge
call, and puts the session back (close drops it on
success so __deinit__ has nothing to retry). Bridge
failures surface as OpOut/GeomOut/PollOut/StatsOut/
SnapOut with structured op/domain/code detail; calls
before open (or after close) report "session not open",
except close, which is idempotent and succeeds.

Channels share one open state: open_session opens every
present channel or none (rollback on failure), attach
attaches every present channel or none (explicit detach
rollback), and close releases everything. Channel 0 is
the attempt tracepoint object; channel 1 the lifecycle
tracing object; channel 2 the copy tracing object.
Attach sites are frozen per channel; record selects
which channels exist by passing their object bytes.

Poll rotates across present channels (sticky on short:
a short pins the next poll to the channel holding the
retained record). Stats sum across present channels;
per-channel counters stay available through stats_at
and read_full_at.
"""

from libbpf_mojo.batch import (
    POLL_BATCH,
    POLL_ERROR,
    POLL_SHORT,
    POLL_TIMEOUT,
)
from libbpf_mojo.error import EINTR, LmbError
from libbpf_mojo.session import AttachSpec, Session

from memveil.capture.collector import (
    GeomOut,
    KernelSource,
    OpOut,
    PollOut,
    SnapOut,
    StatsOut,
)

# abi-v1 frozen values (libbpf-mojo 0.1.0): tracepoint
# and tracing attach kinds, and the retained-record
# ceiling. Raw records are at most 98 bytes; 4096
# accepts everything any probe can emit while bounding
# the staging slot.
comptime _ATTACH_TRACEPOINT = UInt32(1)
comptime _ATTACH_TRACING = UInt32(2)
comptime _MAX_RAW_BYTES = UInt32(4096)
comptime _COUNTS_MAP = "mv_counts"
comptime _COUNT_KEYS = 6
comptime _RING_ATTEMPT = "mv_attempts"
comptime _RING_LIFECYCLE = "mv_lifecycle"
comptime _RING_COPY = "mv_copies"


def poll_outcome(kind: UInt32, code: Int32) -> String:
    """Map one bridge poll result to a collector poll kind.

    An interrupted wait (-EINTR) delivered nothing and is
    indistinguishable from a timeout to the loop, which
    re-checks signals and the deadline before re-polling;
    every other error stays fatal. The saturation gate
    covers this: SIGSTOP/SIGCONT deterministically
    interrupts the ring wait.
    """
    if kind == POLL_BATCH:
        return String("batch")
    if kind == POLL_TIMEOUT:
        return String("timeout")
    if kind == POLL_SHORT:
        return String("short")
    if kind == POLL_ERROR and code == EINTR:
        return String("timeout")
    return String("error")


def _lmb_message(e: LmbError) -> String:
    return (
        String("op=")
        + String(e.operation)
        + String(" domain=")
        + String(e.domain)
        + String(" code=")
        + String(e.code)
        + String(": ")
        + e.message
    )


def _channel_tag(channel: Int) -> String:
    return String("ch") + String(channel) + String(" ")


def poll_advance(order_len: Int, start: Int, k: Int) -> Int:
    """Next poll position after a batch found at probe k.

    Advances by order position, never by channel id, so a
    sparse order like [0, 2] rotates instead of reselecting
    a busy high channel and starving attempt.
    """
    return (start + k + 1) % order_len


def join_op_message(acc: String, channel: Int, message: String) -> String:
    """Accumulate one channel failure into a combined message.

    Teardown attempts every owned channel and reports all
    failures; the first error never silences the rest.
    """
    var piece = _channel_tag(channel) + message
    if acc == String(""):
        return piece
    return acc + String("; ") + piece


def _attempt_specs(
    program: String, tp_system: String, tp_event: String
) -> List[AttachSpec]:
    var out = List[AttachSpec]()
    out.append(
        AttachSpec(
            program, _ATTACH_TRACEPOINT, tp_system, tp_event
        )
    )
    return out^


def _lifecycle_specs() -> List[AttachSpec]:
    var out = List[AttachSpec]()
    out.append(
        AttachSpec(
            String("mv_map_result"),
            _ATTACH_TRACING,
            String("swiotlb_tbl_map_single"),
            String(""),
        )
    )
    out.append(
        AttachSpec(
            String("mv_unmap"),
            _ATTACH_TRACING,
            String("__swiotlb_tbl_unmap_single"),
            String(""),
        )
    )
    return out^


def _copy_specs() -> List[AttachSpec]:
    var out = List[AttachSpec]()
    out.append(
        AttachSpec(
            String("mv_sync_device"),
            _ATTACH_TRACING,
            String("__swiotlb_sync_single_for_device"),
            String(""),
        )
    )
    out.append(
        AttachSpec(
            String("mv_sync_cpu"),
            _ATTACH_TRACING,
            String("__swiotlb_sync_single_for_cpu"),
            String(""),
        )
    )
    out.append(
        AttachSpec(
            String("mv_bounce"),
            _ATTACH_TRACING,
            String("swiotlb_bounce"),
            String(""),
        )
    )
    return out^


struct _Channel(Movable):
    """One object's session slot: elf, ring, sites, session."""

    var elf: List[UInt8]
    var ring: String
    var specs: List[AttachSpec]
    var sess: Optional[Session]
    var poll_buf: List[UInt8]
    var present: Bool

    def __init__(out self):
        self.elf = List[UInt8]()
        self.ring = String("")
        self.specs = List[AttachSpec]()
        self.sess = None
        self.poll_buf = List[UInt8]()
        self.present = False

    def setup(
        mut self, elf: List[UInt8], ring: String,
        specs: List[AttachSpec],
    ):
        self.elf = elf.copy()
        self.ring = ring
        self.specs = specs.copy()
        self.present = True

    def is_open(self) -> Bool:
        if self.sess:
            return True
        return False

    def open_session(mut self, lib_path: String) -> OpOut:
        if self.is_open():
            return OpOut(False, String("session already open"))
        try:
            var s = Session.open_with_lib(
                Span(self.elf),
                self.ring,
                _MAX_RAW_BYTES,
                lib_path,
            )
            self.sess = Optional(s^)
        except e:
            return OpOut(False, _lmb_message(e.copy()))
        return OpOut(True, String(""))

    def load(mut self) -> OpOut:
        if not self.is_open():
            return OpOut(False, String("session not open"))
        var s = self.sess.take()
        try:
            s.load()
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self.sess = Optional(s^)
        return OpOut(True, String(""))

    def map_info(mut self, name: String) -> GeomOut:
        if not self.is_open():
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                String("session not open"),
            )
        var s = self.sess.take()
        try:
            var info = s.map_info(name)
            self.sess = Optional(s^)
            return GeomOut(
                True,
                info.map_type,
                info.key_size,
                info.value_size,
                info.max_entries,
                String(""),
            )
        except e:
            self.sess = Optional(s^)
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                _lmb_message(e.copy()),
            )

    def attach(mut self) -> OpOut:
        if not self.is_open():
            return OpOut(False, String("session not open"))
        var s = self.sess.take()
        try:
            s.attach(self.specs.copy())
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self.sess = Optional(s^)
        return OpOut(True, String(""))

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        if not self.is_open():
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("session not open"),
            )
        while len(self.poll_buf) < Int(capacity):
            self.poll_buf.append(UInt8(0))
        var s = self.sess.take()
        var res = s.poll(
            self.poll_buf, 0, capacity, Int32(timeout_ms)
        )
        self.sess = Optional(s^)
        var kind = poll_outcome(res.kind, res.error.code)
        if kind == String("batch"):
            var frame = List[UInt8]()
            for i in range(Int(res.written)):
                frame.append(self.poll_buf[i])
            return PollOut(
                String("batch"), frame^, UInt32(0), String("")
            )
        if kind == String("timeout"):
            return PollOut(
                String("timeout"), List[UInt8](), UInt32(0),
                String(""),
            )
        if kind == String("short"):
            return PollOut(
                String("short"), List[UInt8](), res.required,
                String(""),
            )
        return PollOut(
            String("error"),
            List[UInt8](),
            UInt32(0),
            _lmb_message(res.error.copy()),
        )

    def stats(mut self) -> StatsOut:
        if not self.is_open():
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                String("session not open"),
            )
        var s = self.sess.take()
        try:
            var st = s.stats()
            self.sess = Optional(s^)
            return StatsOut(
                True,
                st.received,
                st.delivered,
                st.staged,
                st.malformed,
                st.dropped,
                String(""),
            )
        except e:
            self.sess = Optional(s^)
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                _lmb_message(e.copy()),
            )

    def read_full(mut self) -> SnapOut:
        if not self.is_open():
            return SnapOut(
                False, List[UInt64](), String("session not open")
            )
        var s = self.sess.take()
        var vals = List[UInt64]()
        try:
            for key in range(_COUNT_KEYS):
                var key_bytes = List[UInt8]()
                for i in range(4):
                    key_bytes.append(
                        UInt8((UInt32(key) >> UInt32(8 * i)) & UInt32(0xFF))
                    )
                var got = s.map_read(
                    String(_COUNTS_MAP),
                    Span(key_bytes),
                    UInt32(8),
                )
                if got.is_short() or len(got.data) != 8:
                    self.sess = Optional(s^)
                    return SnapOut(
                        False,
                        List[UInt64](),
                        String("short counter read"),
                    )
                var v = UInt64(0)
                for i in range(8):
                    v |= UInt64(got.data[i]) << UInt64(8 * i)
                vals.append(v)
        except e:
            self.sess = Optional(s^)
            return SnapOut(
                False, List[UInt64](), _lmb_message(e.copy())
            )
        self.sess = Optional(s^)
        return SnapOut(True, vals^, String(""))

    def detach(mut self) -> OpOut:
        if not self.is_open():
            return OpOut(False, String("session not open"))
        var s = self.sess.take()
        try:
            s.detach()
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self.sess = Optional(s^)
        return OpOut(True, String(""))

    def close(mut self) -> OpOut:
        # Idempotent cleanup: closing a never-opened (or
        # already closed) session succeeds, so unconditional
        # rollback after a pre-open startup failure stays a
        # clean refusal instead of a rollback failure.
        if not self.is_open():
            return OpOut(True, String(""))
        var s = self.sess.take()
        try:
            s.close()
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self.sess = None
        return OpOut(True, String(""))


struct LmbKernel(KernelSource):
    """KernelSource backed by up to three libbpf-mojo sessions."""

    var _lib_path: String
    var _ch0: _Channel
    var _ch1: _Channel
    var _ch2: _Channel
    var _poll_next: Int
    var _short_ch: Int

    def __init__(
        out self,
        elf: List[UInt8],
        ring: String,
        lib_path: String,
        program: String,
        tp_system: String,
        tp_event: String,
    ):
        self._lib_path = lib_path
        self._ch0 = _Channel()
        self._ch1 = _Channel()
        self._ch2 = _Channel()
        self._poll_next = 0
        self._short_ch = -1
        self._ch0.setup(
            elf, ring,
            _attempt_specs(program, tp_system, tp_event),
        )

    @staticmethod
    def with_channels(
        elf_attempt: List[UInt8],
        tp_system: String,
        tp_event: String,
        elf_lc: List[UInt8],
        has_lc: Bool,
        elf_cp: List[UInt8],
        has_cp: Bool,
        lib_path: String,
    ) -> Self:
        """Attempt kernel with optional lifecycle/copy channels.

        Rings, programs, and tracing targets are frozen per
        channel; only the tracepoint site comes from the
        profile. Object bytes for a disabled channel are
        ignored.
        """
        var out = Self(
            elf_attempt,
            String(_RING_ATTEMPT),
            lib_path,
            String("mv_swiotlb_attempt"),
            tp_system,
            tp_event,
        )
        if has_lc:
            out._ch1.setup(
                elf_lc, String(_RING_LIFECYCLE),
                _lifecycle_specs(),
            )
        if has_cp:
            out._ch2.setup(
                elf_cp, String(_RING_COPY), _copy_specs()
            )
        return out^

    def channel_count(self) -> Int:
        var n = 1
        if self._ch1.present:
            n += 1
        if self._ch2.present:
            n += 1
        return n

    def _present(self, channel: Int) -> Bool:
        if channel == 0:
            return True
        if channel == 1:
            return self._ch1.present
        if channel == 2:
            return self._ch2.present
        return False

    def _any_open(self) -> Bool:
        if self._ch0.is_open():
            return True
        if self._ch1.present and self._ch1.is_open():
            return True
        if self._ch2.present and self._ch2.is_open():
            return True
        return False

    def open_session(mut self) -> OpOut:
        if self._any_open():
            return OpOut(False, String("session already open"))
        var first = self._ch0.open_session(self._lib_path)
        if not first.ok:
            return OpOut(
                False, _channel_tag(0) + first.message
            )
        if self._ch1.present:
            var second = self._ch1.open_session(self._lib_path)
            if not second.ok:
                _ = self._ch0.close()
                return OpOut(
                    False, _channel_tag(1) + second.message
                )
        if self._ch2.present:
            var third = self._ch2.open_session(self._lib_path)
            if not third.ok:
                _ = self._ch0.close()
                if self._ch1.present:
                    _ = self._ch1.close()
                return OpOut(
                    False, _channel_tag(2) + third.message
                )
        return OpOut(True, String(""))

    def load(mut self) -> OpOut:
        if not self._any_open():
            return OpOut(False, String("session not open"))
        var first = self._ch0.load()
        if not first.ok:
            return OpOut(
                False, _channel_tag(0) + first.message
            )
        if self._ch1.present:
            var second = self._ch1.load()
            if not second.ok:
                return OpOut(
                    False, _channel_tag(1) + second.message
                )
        if self._ch2.present:
            var third = self._ch2.load()
            if not third.ok:
                return OpOut(
                    False, _channel_tag(2) + third.message
                )
        return OpOut(True, String(""))

    def map_info(mut self, name: String) -> GeomOut:
        return self._ch0.map_info(name)

    def map_info_at(mut self, channel: Int, name: String) -> GeomOut:
        if not self._present(channel):
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                String("bad channel"),
            )
        if channel == 1:
            return self._ch1.map_info(name)
        if channel == 2:
            return self._ch2.map_info(name)
        return self._ch0.map_info(name)

    def attach(mut self) -> OpOut:
        if not self._any_open():
            return OpOut(False, String("session not open"))
        var first = self._ch0.attach()
        if not first.ok:
            return OpOut(
                False, _channel_tag(0) + first.message
            )
        if self._ch1.present:
            var second = self._ch1.attach()
            if not second.ok:
                var back = self._ch0.detach()
                var msg = _channel_tag(1) + second.message
                if not back.ok:
                    msg += (
                        String("; rollback ch0: ") + back.message
                    )
                return OpOut(False, msg)
        if self._ch2.present:
            var third = self._ch2.attach()
            if not third.ok:
                var back0 = self._ch0.detach()
                var msg = _channel_tag(2) + third.message
                if not back0.ok:
                    msg += (
                        String("; rollback ch0: ")
                        + back0.message
                    )
                if self._ch1.present:
                    var back1 = self._ch1.detach()
                    if not back1.ok:
                        msg += (
                            String("; rollback ch1: ")
                            + back1.message
                        )
                return OpOut(False, msg)
        return OpOut(True, String(""))

    def _poll_channel(
        mut self, channel: Int, timeout_ms: Int, capacity: UInt32
    ) -> PollOut:
        if channel == 1:
            return self._ch1.poll(timeout_ms, capacity)
        if channel == 2:
            return self._ch2.poll(timeout_ms, capacity)
        return self._ch0.poll(timeout_ms, capacity)

    def _order(self) -> List[Int]:
        var out = List[Int]()
        out.append(0)
        if self._ch1.present:
            out.append(1)
        if self._ch2.present:
            out.append(2)
        return out^

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        if not self._any_open():
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("session not open"),
            )
        if self._short_ch >= 0:
            var ch = self._short_ch
            var retry = self._poll_channel(ch, timeout_ms, capacity)
            if retry.kind != String("short"):
                self._short_ch = -1
            if retry.kind == String("error"):
                retry.message = (
                    _channel_tag(ch) + retry.message
                )
            return retry^
        var order = self._order()
        var start = self._poll_next % len(order)
        for k in range(len(order)):
            var ch = order[(start + k) % len(order)]
            var wait = timeout_ms
            if k > 0:
                wait = 0
            var out = self._poll_channel(ch, wait, capacity)
            if out.kind == String("batch"):
                self._poll_next = poll_advance(
                    len(order), start, k
                )
                return out^
            if out.kind == String("short"):
                self._short_ch = ch
                return out^
            if out.kind == String("error"):
                out.message = _channel_tag(ch) + out.message
                return out^
        self._poll_next = (start + 1) % len(order)
        return PollOut(
            String("timeout"), List[UInt8](), UInt32(0),
            String(""),
        )

    def stats(mut self) -> StatsOut:
        if not self._any_open():
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                String("session not open"),
            )
        # Cross-channel sums; any wrap breaks the collector
        # identities and fails the run closed, never silently.
        var received = UInt64(0)
        var delivered = UInt64(0)
        var staged = UInt64(0)
        var malformed = UInt64(0)
        var dropped = UInt64(0)
        var order = self._order()
        for k in range(len(order)):
            var st = self.stats_at(order[k])
            if not st.ok:
                return StatsOut(
                    False,
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    UInt64(0),
                    _channel_tag(order[k]) + st.message,
                )
            received += st.received
            delivered += st.delivered
            staged += st.staged
            malformed += st.malformed
            dropped += st.dropped
        return StatsOut(
            True, received, delivered, staged, malformed,
            dropped, String(""),
        )

    def stats_at(mut self, channel: Int) -> StatsOut:
        if not self._present(channel):
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                String("bad channel"),
            )
        if channel == 1:
            return self._ch1.stats()
        if channel == 2:
            return self._ch2.stats()
        return self._ch0.stats()

    def read_full(mut self) -> SnapOut:
        return self._ch0.read_full()

    def read_full_at(mut self, channel: Int) -> SnapOut:
        if not self._present(channel):
            return SnapOut(
                False, List[UInt64](), String("bad channel")
            )
        if channel == 1:
            return self._ch1.read_full()
        if channel == 2:
            return self._ch2.read_full()
        return self._ch0.read_full()

    def detach(mut self) -> OpOut:
        if not self._any_open():
            return OpOut(False, String("session not open"))
        var order = self._order()
        var failed = False
        var msg = String("")
        for k in range(len(order)):
            var ch = order[k]
            var out: OpOut
            if ch == 1:
                out = self._ch1.detach()
            elif ch == 2:
                out = self._ch2.detach()
            else:
                out = self._ch0.detach()
            if not out.ok:
                failed = True
                msg = join_op_message(msg, ch, out.message)
        if failed:
            return OpOut(False, msg^)
        return OpOut(True, String(""))

    def close(mut self) -> OpOut:
        # Idempotent cleanup: closing a never-opened (or
        # already closed) session succeeds on every channel,
        # so unconditional rollback after a pre-open startup
        # failure stays a clean refusal instead of a
        # rollback failure.
        var order = self._order()
        var failed = False
        var msg = String("")
        for k in range(len(order)):
            var ch = order[k]
            var out: OpOut
            if ch == 1:
                out = self._ch1.close()
            elif ch == 2:
                out = self._ch2.close()
            else:
                out = self._ch0.close()
            if not out.ok:
                failed = True
                msg = join_op_message(msg, ch, out.message)
        self._short_ch = -1
        if failed:
            return OpOut(False, msg^)
        return OpOut(True, String(""))
