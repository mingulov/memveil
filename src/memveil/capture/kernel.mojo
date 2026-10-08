# SPDX-License-Identifier: GPL-3.0-or-later

"""Live kernel source: KernelSource over a libbpf-mojo Session.

Thin ownership adapter, no policy: every trait method
takes the session out of its slot, runs one bridge
call, and puts the session back (close drops it on
success so __deinit__ has nothing to retry). Bridge
failures surface as OpOut/GeomOut/PollOut/StatsOut/
SnapOut with structured op/domain/code detail; calls
before open (or after close) report "session not open",
except close, which is idempotent and succeeds.
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

# abi-v1 frozen values (libbpf-mojo 0.2.0, unchanged in
# 0.2.1, 0.2.2): tracepoint
# attach kind, and the retained-record ceiling. Raw
# attempt records are 91 bytes; 4096 accepts everything
# the probe can emit while bounding the staging slot.
comptime _ATTACH_TRACEPOINT = UInt32(1)
comptime _MAX_RAW_BYTES = UInt32(4096)
comptime _COUNTS_MAP = "mv_counts"
comptime _COUNT_KEYS = 6


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


struct LmbKernel(KernelSource):
    """KernelSource backed by one libbpf-mojo session."""

    var _elf: List[UInt8]
    var _ring: String
    var _lib_path: String
    var _program: String
    var _tp_system: String
    var _tp_event: String
    var _sess: Optional[Session]
    var _poll_buf: List[UInt8]

    def __init__(
        out self,
        elf: List[UInt8],
        ring: String,
        lib_path: String,
        program: String,
        tp_system: String,
        tp_event: String,
    ):
        self._elf = elf.copy()
        self._ring = ring
        self._lib_path = lib_path
        self._program = program
        self._tp_system = tp_system
        self._tp_event = tp_event
        self._sess = None
        self._poll_buf = List[UInt8]()

    def open_session(mut self) -> OpOut:
        if self._sess:
            return OpOut(False, String("session already open"))
        try:
            var s = Session.open_with_lib(
                Span(self._elf),
                self._ring,
                _MAX_RAW_BYTES,
                self._lib_path,
            )
            self._sess = Optional(s^)
        except e:
            return OpOut(False, _lmb_message(e.copy()))
        return OpOut(True, String(""))

    def load(mut self) -> OpOut:
        if not self._sess:
            return OpOut(False, String("session not open"))
        var s = self._sess.take()
        try:
            s.load()
        except e:
            self._sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self._sess = Optional(s^)
        return OpOut(True, String(""))

    def map_info(mut self, name: String) -> GeomOut:
        if not self._sess:
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                String("session not open"),
            )
        var s = self._sess.take()
        try:
            var info = s.map_info(name)
            self._sess = Optional(s^)
            return GeomOut(
                True,
                info.map_type,
                info.key_size,
                info.value_size,
                info.max_entries,
                String(""),
            )
        except e:
            self._sess = Optional(s^)
            return GeomOut(
                False,
                UInt32(0),
                UInt32(0),
                UInt32(0),
                UInt32(0),
                _lmb_message(e.copy()),
            )

    def attach(mut self) -> OpOut:
        if not self._sess:
            return OpOut(False, String("session not open"))
        var specs = List[AttachSpec]()
        specs.append(
            AttachSpec(
                self._program,
                _ATTACH_TRACEPOINT,
                self._tp_system,
                self._tp_event,
            )
        )
        var s = self._sess.take()
        try:
            s.attach(specs^)
        except e:
            self._sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self._sess = Optional(s^)
        return OpOut(True, String(""))

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        if not self._sess:
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("session not open"),
            )
        while len(self._poll_buf) < Int(capacity):
            self._poll_buf.append(UInt8(0))
        var s = self._sess.take()
        var res = s.poll(
            self._poll_buf, 0, capacity, Int32(timeout_ms)
        )
        self._sess = Optional(s^)
        var kind = poll_outcome(res.kind, res.error.code)
        if kind == String("batch"):
            var frame = List[UInt8]()
            for i in range(Int(res.written)):
                frame.append(self._poll_buf[i])
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
        if not self._sess:
            return StatsOut(
                False,
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                UInt64(0),
                String("session not open"),
            )
        var s = self._sess.take()
        try:
            var st = s.stats()
            self._sess = Optional(s^)
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
            self._sess = Optional(s^)
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
        if not self._sess:
            return SnapOut(
                False, List[UInt64](), String("session not open")
            )
        var s = self._sess.take()
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
                    self._sess = Optional(s^)
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
            self._sess = Optional(s^)
            return SnapOut(
                False, List[UInt64](), _lmb_message(e.copy())
            )
        self._sess = Optional(s^)
        return SnapOut(True, vals^, String(""))

    def detach(mut self) -> OpOut:
        if not self._sess:
            return OpOut(False, String("session not open"))
        var s = self._sess.take()
        try:
            s.detach()
        except e:
            self._sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self._sess = Optional(s^)
        return OpOut(True, String(""))

    def close(mut self) -> OpOut:
        # Idempotent cleanup: closing a never-opened (or
        # already closed) session succeeds, so unconditional
        # rollback after a pre-open startup failure stays a
        # clean refusal instead of a rollback failure.
        if not self._sess:
            return OpOut(True, String(""))
        var s = self._sess.take()
        try:
            s.close()
        except e:
            self._sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self._sess = None
        return OpOut(True, String(""))
