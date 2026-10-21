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

Each channel remembers the program fds its load created
(diffed from /proc/self/fdinfo, no bridge call needed).
Without copy, recursion_misses sums the per-program
counters; with copy, it identifies each tracing program
by kernel name and reads the fallback counters, so the
collector can charge exact copy loss.

Poll rotates across present channels (sticky on short:
a short pins the next poll to the channel holding the
retained record) and waits only when every channel is
empty. Stats sum across present channels;
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
from std.ffi import external_call
from std.os import listdir

from memveil.capture.collector import (
    GeomOut,
    KernelSource,
    MissOut,
    OpOut,
    PollOut,
    SnapOut,
    StatsOut,
)
from memveil.platform.narrow import (
    MV_OFFSETS_TABLE_LEN,
    MV_OFF_TABLE_MAGIC,
)
from memveil.platform.reader import bytes_to_text, read_host_file

# abi-v1 frozen values (libbpf-mojo 0.2.0): tracepoint
# and tracing attach kinds, and the retained-record
# ceiling. Raw records are at most 98 bytes; 4096
# accepts everything any probe can emit while bounding
# the staging slot.
comptime _ATTACH_TRACEPOINT = UInt32(1)
comptime _ATTACH_TRACING = UInt32(2)
comptime _MAX_RAW_BYTES = UInt32(4096)
comptime _COUNTS_MAP = "mv_counts"
comptime _OFFSETS_MAP = "mv_offsets"
comptime _COUNT_KEYS = 6
comptime _RING_ATTEMPT = "mv_attempts"
comptime _RING_LIFECYCLE = "mv_lifecycle"
comptime _RING_COPY = "mv_copies"
comptime _FDINFO_DIR = "/proc/self/fdinfo"
comptime _FDINFO_CAP = 4096
comptime _FB_MAP = "mv_copy_fb"
comptime _FB_KEYS = 3
comptime _FB_ARMED_KEY = 3
comptime _SYS_BPF = 321
comptime _BPF_OBJ_GET_INFO = 15
comptime _PROG_INFO_SIZE = 232
comptime _PROG_NAME_OFF = 64
comptime _PROG_NAME_LEN = 16
comptime _PROG_REC_OFF = 208


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


trait ChannelPoller:
    """One bounded poll on one channel; rotate_poll owns policy."""

    def poll_channel(
        mut self, channel: Int, timeout_ms: Int, capacity: UInt32
    ) -> PollOut:
        ...


@fieldwise_init
struct PollRotation(Copyable, Movable):
    """Rotation state: next order position, pinned short channel."""

    var next: Int
    var short_ch: Int


def rotate_poll[P: ChannelPoller](
    mut poller: P, mut rot: PollRotation, order: List[Int],
    timeout_ms: Int, capacity: UInt32,
) -> PollOut:
    """One multi-channel poll over order (sticky on short).

    Every channel is probed without waiting first; only when
    all are empty does the start channel wait timeout_ms, so
    a quiet ring never holds the wait while another ring has
    records queued. Data arriving on a non-waited channel is
    picked up by the next call, at most one finite wait later.
    An empty order is an error, never a division by zero.
    """
    if rot.short_ch >= 0:
        var ch = rot.short_ch
        var retry = poller.poll_channel(ch, timeout_ms, capacity)
        if retry.kind != String("short"):
            rot.short_ch = -1
        if retry.kind == String("error"):
            retry.message = _channel_tag(ch) + retry.message
        return retry^
    var n = len(order)
    if n == 0:
        return PollOut(
            String("error"), List[UInt8](), UInt32(0),
            String("no channels to poll"),
        )
    var start = rot.next % n
    var probes = n
    if timeout_ms != 0:
        probes = n + 1
    for k in range(probes):
        var pos = k % n
        var ch = order[(start + pos) % n]
        var wait = 0
        if k == n:
            wait = timeout_ms
        var out = poller.poll_channel(ch, wait, capacity)
        if out.kind == String("batch"):
            rot.next = poll_advance(n, start, pos)
            return out^
        if out.kind == String("short"):
            rot.short_ch = ch
            return out^
        if out.kind == String("error"):
            out.message = _channel_tag(ch) + out.message
            return out^
    rot.next = (start + 1) % n
    return PollOut(
        String("timeout"), List[UInt8](), UInt32(0), String("")
    )


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
    # Entry attaches first; the gate plus this order make recoveries exact.
    out.append(
        AttachSpec(
            String("mv_bounce"),
            _ATTACH_TRACING,
            String("swiotlb_bounce"),
            String(""),
        )
    )
    out.append(
        AttachSpec(
            String("mv_bounce_exit"),
            _ATTACH_TRACING,
            String("swiotlb_bounce"),
            String(""),
        )
    )
    return out^


def fdinfo_u64(text: String, key: String) -> Optional[UInt64]:
    """Decimal value of the `key:` line of one fdinfo text, if any."""
    var b = text.as_bytes()
    var k = key.as_bytes()
    var n = len(b)
    var i = 0
    while i < n:
        var j = 0
        while j < len(k) and i + j < n and b[i + j] == k[j]:
            j += 1
        if j == len(k) and i + j < n and b[i + j] == UInt8(58):
            var p = i + j + 1
            while p < n and (b[p] == UInt8(9) or b[p] == UInt8(32)):
                p += 1
            var v = UInt64(0)
            var digits = 0
            while p < n and b[p] >= UInt8(48) and b[p] <= UInt8(57):
                var d = UInt64(b[p] - UInt8(48))
                if v > (UInt64(0xFFFFFFFFFFFFFFFF) - d) // UInt64(10):
                    return None
                v = v * UInt64(10) + d
                digits += 1
                p += 1
            if digits == 0 or (p < n and b[p] != UInt8(10)):
                return None
            return v
        while i < n and b[i] != UInt8(10):
            i += 1
        i += 1
    return None


def _fd_number(name: String) -> Int:
    """Decimal fd from a /proc/self/fdinfo entry name, or -1."""
    var b = name.as_bytes()
    if len(b) == 0 or len(b) > 9:
        return -1
    var v = 0
    for i in range(len(b)):
        if b[i] < UInt8(48) or b[i] > UInt8(57):
            return -1
        v = v * 10 + Int(b[i] - UInt8(48))
    return v


def _fdinfo_text(fd: Int) raises -> String:
    var path = String(_FDINFO_DIR) + String("/") + String(fd)
    try:
        return bytes_to_text(
            read_host_file(path, String("fdinfo"), _FDINFO_CAP)
        )
    except e:
        raise Error(e.message)


def prog_fds() -> Optional[List[Int]]:
    """This process's open BPF program fds; None if unlistable."""
    var names: List[String]
    try:
        names = listdir(String(_FDINFO_DIR))
    except:
        return None
    var out = List[Int]()
    for k in range(len(names)):
        var fd = _fd_number(names[k])
        if fd < 0:
            continue
        # Fds closed since the listing (its own dir fd) are skipped.
        try:
            if fdinfo_u64(_fdinfo_text(fd), String("prog_type")):
                out.append(fd)
        except:
            continue
    return out^


def added_fds(before: List[Int], after: List[Int]) -> List[Int]:
    """Fds in after that before lacks, in after's order."""
    var out = List[Int]()
    for i in range(len(after)):
        var seen = False
        for j in range(len(before)):
            if before[j] == after[i]:
                seen = True
                break
        if not seen:
            out.append(after[i])
    return out^


def parse_prog_name(info: Span[UInt8, _]) -> Optional[String]:
    """Program name from a bpf_prog_info image, if readable."""
    if len(info) < _PROG_NAME_OFF + _PROG_NAME_LEN:
        return None
    var raw = List[UInt8]()
    for i in range(_PROG_NAME_LEN):
        var b = info[_PROG_NAME_OFF + i]
        if b == UInt8(0):
            break
        raw.append(b)
    if len(raw) == 0:
        return None
    for i in range(len(raw)):
        var b = raw[i]
        var ok = (
            (b >= UInt8(0x41) and b <= UInt8(0x5A))
            or (b >= UInt8(0x61) and b <= UInt8(0x7A))
            or (b >= UInt8(0x30) and b <= UInt8(0x39))
            or b == UInt8(0x5F)
        )
        if not ok:
            return None
    try:
        return String(from_utf8=Span(raw))
    except:
        return None


def parse_prog_misses(info: Span[UInt8, _]) -> UInt64:
    """Recursion misses from a bpf_prog_info image, else 0."""
    if len(info) < _PROG_REC_OFF + 8:
        return UInt64(0)
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(info[_PROG_REC_OFF + i]) << UInt64(8 * i)
    return v


@fieldwise_init
struct CopyProgs(Copyable, Movable):
    """One copy-channel identification (misses valid when ok)."""

    var ok: Bool
    var message: String
    var bounce: UInt64
    var exit_misses: UInt64
    var sync_device: UInt64
    var sync_cpu: UInt64


def identify_copy_progs(
    names: List[String], misses: List[UInt64]
) -> CopyProgs:
    """Match the four frozen copy programs by kernel name."""
    if len(names) != 4 or len(misses) != 4:
        return CopyProgs(
            False, String("copy program count"), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0),
        )
    var bounce = UInt64(0)
    var exit_misses = UInt64(0)
    var sync_device = UInt64(0)
    var sync_cpu = UInt64(0)
    var seen_bounce = False
    var seen_exit = False
    var seen_dev = False
    var seen_cpu = False
    for i in range(4):
        var n = names[i]
        if n == String("mv_bounce"):
            if seen_bounce:
                return CopyProgs(
                    False, String("copy program ambiguous"),
                    UInt64(0), UInt64(0), UInt64(0), UInt64(0),
                )
            seen_bounce = True
            bounce = misses[i]
        elif n == String("mv_bounce_exit"):
            if seen_exit:
                return CopyProgs(
                    False, String("copy program ambiguous"),
                    UInt64(0), UInt64(0), UInt64(0), UInt64(0),
                )
            seen_exit = True
            exit_misses = misses[i]
        elif n == String("mv_sync_device"):
            if seen_dev:
                return CopyProgs(
                    False, String("copy program ambiguous"),
                    UInt64(0), UInt64(0), UInt64(0), UInt64(0),
                )
            seen_dev = True
            sync_device = misses[i]
        elif n == String("mv_sync_cpu"):
            if seen_cpu:
                return CopyProgs(
                    False, String("copy program ambiguous"),
                    UInt64(0), UInt64(0), UInt64(0), UInt64(0),
                )
            seen_cpu = True
            sync_cpu = misses[i]
        else:
            return CopyProgs(
                False, String("copy program unexpected"),
                UInt64(0), UInt64(0), UInt64(0), UInt64(0),
            )
    if not (seen_bounce and seen_exit and seen_dev and seen_cpu):
        return CopyProgs(
            False, String("copy program missing"), UInt64(0),
            UInt64(0), UInt64(0), UInt64(0),
        )
    return CopyProgs(
        True, String(""), bounce, exit_misses, sync_device,
        sync_cpu,
    )


@fieldwise_init
struct LifecycleProgs(Copyable, Movable):
    """One lifecycle-channel identification (valid when ok)."""

    var ok: Bool
    var message: String
    var map_misses: UInt64
    var unmap_misses: UInt64


def identify_lifecycle_progs(
    names: List[String], misses: List[UInt64]
) -> LifecycleProgs:
    """Match the two frozen lifecycle programs by kernel name."""
    if len(names) != 2 or len(misses) != 2:
        return LifecycleProgs(
            False, String("lifecycle program count"), UInt64(0),
            UInt64(0),
        )
    var map_misses = UInt64(0)
    var unmap_misses = UInt64(0)
    var seen_map = False
    var seen_unmap = False
    for i in range(2):
        var n = names[i]
        if n == String("mv_map_result"):
            if seen_map:
                return LifecycleProgs(
                    False, String("lifecycle program ambiguous"),
                    UInt64(0), UInt64(0),
                )
            seen_map = True
            map_misses = misses[i]
        elif n == String("mv_unmap"):
            if seen_unmap:
                return LifecycleProgs(
                    False, String("lifecycle program ambiguous"),
                    UInt64(0), UInt64(0),
                )
            seen_unmap = True
            unmap_misses = misses[i]
        else:
            return LifecycleProgs(
                False, String("lifecycle program unexpected"),
                UInt64(0), UInt64(0),
            )
    if not (seen_map and seen_unmap):
        return LifecycleProgs(
            False, String("lifecycle program missing"), UInt64(0),
            UInt64(0),
        )
    return LifecycleProgs(True, String(""), map_misses, unmap_misses)


@fieldwise_init
struct ProgInfo(Copyable, Movable):
    """One program identity read (name/misses valid when ok)."""

    var ok: Bool
    var message: String
    var name: String
    var misses: UInt64


def prog_info(fd: Int) -> ProgInfo:
    """Kernel name and misses for one program fd, via info call."""
    var info = List[UInt8]()
    for _ in range(_PROG_INFO_SIZE):
        info.append(UInt8(0))
    var attr = List[UInt8]()
    for _ in range(16):
        attr.append(UInt8(0))
    var fdu = UInt32(fd)
    for i in range(4):
        attr[i] = UInt8((fdu >> UInt32(8 * i)) & UInt32(0xFF))
    var info_len = UInt32(_PROG_INFO_SIZE)
    for i in range(4):
        attr[4 + i] = UInt8(
            (info_len >> UInt32(8 * i)) & UInt32(0xFF)
        )
    var ptr = UInt64(Span(info).unsafe_ptr())
    for i in range(8):
        attr[8 + i] = UInt8((ptr >> UInt64(8 * i)) & UInt64(0xFF))
    var rc: Int64
    try:
        rc = external_call["syscall", Int64](
            Int64(_SYS_BPF), Int64(_BPF_OBJ_GET_INFO),
            Span(attr).unsafe_ptr(), Int64(16),
        )
    except:
        return ProgInfo(
            False, String("prog info syscall failed"), String(""),
            UInt64(0),
        )
    if rc != Int64(0):
        return ProgInfo(
            False,
            String("prog info unreadable for fd ") + String(fd),
            String(""), UInt64(0),
        )
    var name = parse_prog_name(Span(info))
    if not name:
        return ProgInfo(
            False,
            String("program identity unreadable for fd ")
            + String(fd),
            String(""), UInt64(0),
        )
    return ProgInfo(True, String(""), name.value(), parse_prog_misses(Span(info)))


struct _Channel(Movable):
    """One object's session slot: elf, ring, sites, session."""

    var elf: List[UInt8]
    var ring: String
    var specs: List[AttachSpec]
    var sess: Optional[Session]
    var poll_buf: List[UInt8]
    var present: Bool
    var progs: List[Int]
    var progs_known: Bool

    def __init__(out self):
        self.elf = List[UInt8]()
        self.ring = String("")
        self.specs = List[AttachSpec]()
        self.sess = None
        self.poll_buf = List[UInt8]()
        self.present = False
        self.progs = List[Int]()
        self.progs_known = False

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
        var before = prog_fds()
        var s = self.sess.take()
        try:
            s.load()
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        self.sess = Optional(s^)
        var after = prog_fds()
        if Bool(before) and Bool(after):
            self.progs = added_fds(before.value(), after.value())
            self.progs_known = len(self.progs) > 0
        return OpOut(True, String(""))

    def misses(mut self) -> MissOut:
        if not self.is_open():
            return MissOut(False, UInt64(0), String("session not open"))
        if not self.progs_known:
            return MissOut(
                False, UInt64(0), String("program fds unknown")
            )
        var total = UInt64(0)
        for k in range(len(self.progs)):
            var fd = self.progs[k]
            var got: Optional[UInt64]
            try:
                got = fdinfo_u64(
                    _fdinfo_text(fd), String("recursion_misses")
                )
            except e:
                return MissOut(
                    False, UInt64(0),
                    String("fdinfo ") + String(fd) + String(": ")
                    + String(e),
                )
            if not got:
                return MissOut(
                    False, UInt64(0),
                    String("fdinfo ") + String(fd)
                    + String(": no recursion_misses"),
                )
            var m = got.value()
            if total > UInt64(0xFFFFFFFFFFFFFFFF) - m:
                return MissOut(
                    False, UInt64(0), String("recursion misses wrap")
                )
            total += m
        return MissOut(True, total, String(""))

    def prog_names_misses(mut self) -> Tuple[Bool, String, List[String], List[UInt64]]:
        """Kernel names and misses for every program fd, in order."""
        var names = List[String]()
        var misses = List[UInt64]()
        if not self.is_open():
            return (False, String("session not open"), names^, misses^)
        if not self.progs_known:
            return (False, String("program fds unknown"), names^, misses^)
        for k in range(len(self.progs)):
            var got = prog_info(self.progs[k])
            if not got.ok:
                var nn = List[String]()
                var mm = List[UInt64]()
                return (False, got.message, nn^, mm^)
            names.append(got.name)
            misses.append(got.misses)
        return (True, String(""), names^, misses^)

    def misses_lifecycle(mut self) -> LifecycleProgs:
        var r = self.prog_names_misses()
        if not r[0]:
            return LifecycleProgs(False, r[1], UInt64(0), UInt64(0))
        return identify_lifecycle_progs(r[2].copy(), r[3].copy())

    def misses_copy(mut self) -> CopyProgs:
        var r = self.prog_names_misses()
        if not r[0]:
            return CopyProgs(
                False, r[1], UInt64(0), UInt64(0), UInt64(0),
                UInt64(0),
            )
        return identify_copy_progs(r[2].copy(), r[3].copy())

    def read_fb(mut self) -> SnapOut:
        if not self.is_open():
            return SnapOut(
                False, List[UInt64](), String("session not open")
            )
        var s = self.sess.take()
        var vals = List[UInt64]()
        try:
            for key in range(_FB_KEYS):
                var key_bytes = List[UInt8]()
                for i in range(4):
                    key_bytes.append(
                        UInt8((UInt32(key) >> UInt32(8 * i)) & UInt32(0xFF))
                    )
                var got = s.map_read(
                    String(_FB_MAP),
                    Span(key_bytes),
                    UInt32(8),
                )
                if got.is_short() or len(got.data) != 8:
                    self.sess = Optional(s^)
                    return SnapOut(
                        False,
                        List[UInt64](),
                        String("short fallback read"),
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

    def set_fb_armed(mut self, armed: Bool) -> OpOut:
        """Write the fallback armed slot; exactly 1 arms the exit."""
        if not self.is_open():
            return OpOut(False, String("session not open"))
        var key_bytes = List[UInt8]()
        for i in range(4):
            key_bytes.append(
                UInt8(
                    (UInt32(_FB_ARMED_KEY) >> UInt32(8 * i))
                    & UInt32(0xFF)
                )
            )
        var val_bytes = List[UInt8]()
        var v = UInt64(1) if armed else UInt64(0)
        for i in range(8):
            val_bytes.append(
                UInt8((v >> UInt64(8 * i)) & UInt64(0xFF))
            )
        var s = self.sess.take()
        try:
            s.map_write(
                String(_FB_MAP), Span(key_bytes), Span(val_bytes)
            )
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

    def install_offsets(mut self, table: List[UInt8]) -> OpOut:
        """Write the offset table, then read it back and compare.

        A short write, a short read-back, or any byte
        difference refuses: the program must never run on
        a mis-installed table.
        """
        if not self.is_open():
            return OpOut(False, String("session not open"))
        if len(table) != MV_OFFSETS_TABLE_LEN:
            return OpOut(False, String("bad offsets table"))
        var magic = Int(0)
        for i in range(4):
            magic |= Int(table[i]) << (8 * i)
        if magic != MV_OFF_TABLE_MAGIC:
            return OpOut(False, String("bad offsets table"))
        var key_bytes = List[UInt8]()
        for _ in range(4):
            key_bytes.append(UInt8(0))
        var s = self.sess.take()
        try:
            s.map_write(
                String(_OFFSETS_MAP), Span(key_bytes), Span(table)
            )
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        try:
            var got = s.map_read(
                String(_OFFSETS_MAP),
                Span(key_bytes),
                UInt32(MV_OFFSETS_TABLE_LEN),
            )
            self.sess = Optional(s^)
            if got.is_short() or len(got.data) != MV_OFFSETS_TABLE_LEN:
                return OpOut(False, String("offsets verify short"))
            for i in range(MV_OFFSETS_TABLE_LEN):
                if got.data[i] != table[i]:
                    return OpOut(
                        False, String("offsets verify mismatch")
                    )
        except e:
            self.sess = Optional(s^)
            return OpOut(False, _lmb_message(e.copy()))
        return OpOut(True, String(""))

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
        self.progs = List[Int]()
        self.progs_known = False
        return OpOut(True, String(""))


def fb_valid(vals: List[UInt64]) -> Bool:
    """Fallback reads are usable only with three slots and no flags."""
    if len(vals) != _FB_KEYS:
        return False
    return vals[2] == UInt64(0)


def fb_flag_reason(flags: UInt64) -> String:
    """Name for nonzero fallback flags; empty when clean."""
    if flags == UInt64(0):
        return String("")
    # Bits 0-1 are counter wraps, bit 2 a lost frame.
    var out = String("")
    if (flags & UInt64(3)) != UInt64(0):
        out = String("fallback counters wrapped")
    if (flags & UInt64(4)) != UInt64(0):
        if out != String(""):
            out += String("; ")
        out += String("fallback frame lost")
    if (flags & ~UInt64(7)) != UInt64(0):
        if out != String(""):
            out += String("; ")
        out += String("fallback flags invalid")
    return out^


struct LmbKernel(ChannelPoller, KernelSource):
    """KernelSource backed by up to three libbpf-mojo sessions."""

    var _lib_path: String
    var _ch0: _Channel
    var _ch1: _Channel
    var _ch2: _Channel
    var _rot: PollRotation

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
        self._rot = PollRotation(0, -1)
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

    def install_offsets(mut self, table: List[UInt8]) -> OpOut:
        if not self._any_open():
            return OpOut(False, String("session not open"))
        return self._ch0.install_offsets(table.copy())

    def set_copy_armed(mut self, armed: Bool) -> OpOut:
        """Write the copy fallback armed slot (copy channel only)."""
        if not self._any_open():
            return OpOut(False, String("session not open"))
        if not self._ch2.present:
            return OpOut(False, String("copy channel absent"))
        return self._ch2.set_fb_armed(armed)

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

    def poll_channel(
        mut self, channel: Int, timeout_ms: Int, capacity: UInt32
    ) -> PollOut:
        """Raw one-channel poll for rotate_poll; skips the short pin."""
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
        var rot = self._rot.copy()
        var out = rotate_poll(
            self, rot, self._order(), timeout_ms, capacity
        )
        self._rot = rot^
        return out^

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

    def recursion_misses(mut self) -> MissOut:
        if not self._any_open():
            return MissOut(False, UInt64(0), String("session not open"))
        var ch0 = self._ch0.misses()
        if not ch0.ok:
            return MissOut(
                False, UInt64(0),
                _channel_tag(0) + ch0.message,
            )
        if not self._ch2.present:
            var total = ch0.count
            var attempt = ch0.count
            if self._ch1.present:
                var lc = self._ch1.misses()
                if not lc.ok:
                    var out = MissOut(
                        True, UInt64(0), String(""), ch0.count)
                    out.detail_error = _channel_tag(1) + lc.message
                    return out^
                if total > UInt64(0xFFFFFFFFFFFFFFFF) - lc.count:
                    return MissOut(
                        False, UInt64(0),
                        String("recursion misses wrap"),
                    )
                total += lc.count
            return MissOut(True, total, String(""), attempt)
        var lc_map = UInt64(0)
        var lc_unmap = UInt64(0)
        if self._ch1.present:
            var lc = self._ch1.misses_lifecycle()
            if not lc.ok:
                var out = MissOut(
                    True, UInt64(0), String(""), ch0.count)
                out.detail_error = _channel_tag(1) + lc.message
                return out^
            lc_map = lc.map_misses
            lc_unmap = lc.unmap_misses
        var cp = self._ch2.misses_copy()
        if not cp.ok:
            var out = MissOut(
                True, UInt64(0), String(""), ch0.count)
            out.detail_error = _channel_tag(2) + cp.message
            return out^
        var fb = self._ch2.read_fb()
        if not fb.ok:
            var out = MissOut(
                True, UInt64(0), String(""), ch0.count)
            out.detail_error = (
                _channel_tag(2) + String("fallback: ") + fb.message
            )
            return out^
        if not fb_valid(fb.vals):
            var out = MissOut(
                True, UInt64(0), String(""), ch0.count)
            if len(fb.vals) != _FB_KEYS:
                out.detail_error = (
                    _channel_tag(2) + String("fallback flags invalid")
                )
            else:
                out.detail_error = (
                    _channel_tag(2) + fb_flag_reason(fb.vals[2])
                )
            return out^
        return MissOut(
            True, UInt64(0), String(""), ch0.count, True,
            cp.bounce, cp.exit_misses, cp.sync_device,
            cp.sync_cpu, lc_map, lc_unmap, fb.vals[0],
            fb.vals[1],
        )

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
        self._rot.short_ch = -1
        if failed:
            return OpOut(False, msg^)
        return OpOut(True, String(""))
