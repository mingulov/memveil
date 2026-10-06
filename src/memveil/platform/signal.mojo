# SPDX-License-Identifier: GPL-3.0-or-later

"""Live signal source: signalfd(2) behind SignalSource.

Setup blocks SIGINT/SIGTERM in the calling thread and
opens a nonblocking signalfd; check() reports none,
pending, or error. Masks are restored when signalfd
creation fails and at teardown. Read diagnostics carry
the errno number only (R7D1 sanitized form).
"""

from std.ffi import external_call
from std.os import getenv

from memveil.capture.collector import OpOut, SignalOut, SignalSource


comptime _SIG_BLOCK = 0
comptime _SIG_SETMASK = 2
comptime _SIGINT_NO = 2
comptime _SIGTERM_NO = 15
comptime _SFD_CLOEXEC = 524288
comptime _SFD_NONBLOCK = 2048
comptime _EAGAIN_NO = 11
comptime _EINTR_NO = 4
comptime _SIGSET_BYTES = 128
comptime _SIGINFO_BYTES = 128

comptime READ_NONE = 0
comptime READ_PENDING = 1
comptime READ_RETRY = 2
comptime READ_ERROR = 3

comptime _SIGBLK_SENTINEL = "MEMVEIL_SIGBLK"


def _sig_errno() -> Int:
    var p = external_call[
        "__errno_location", Pointer[Int32, MutAnyOrigin]
    ]()
    return Int(p.unsafe_load())


def classify_signal_read(n: Int, errno_no: Int) -> Int:
    """Pure read disposition: EAGAIN rests, EINTR retries."""
    if n > 0:
        return READ_PENDING
    if n == 0:
        return READ_ERROR
    if errno_no == _EAGAIN_NO:
        return READ_NONE
    if errno_no == _EINTR_NO:
        return READ_RETRY
    return READ_ERROR


def blocked_mask() -> List[UInt8]:
    """128-byte sigset with SIGINT (bit 1) + SIGTERM (bit 14)."""
    var mask = List[UInt8]()
    for _ in range(_SIGSET_BYTES):
        mask.append(UInt8(0))
    mask[0] = UInt8(0x02)
    mask[1] = UInt8(0x40)
    return mask^


def _cstr_bytes(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _has_sigblk_sentinel() -> Bool:
    """True when MEMVEIL_SIGBLK=1 is set (exact lookup).

    Uses getenv, not a capped /proc/self/environ scan: a
    read-cap failure would report a set sentinel as absent
    and loop the re-exec forever on large environments.
    """
    return getenv(String("MEMVEIL_SIGBLK")) == String("1")


def ensure_inherited_signal_block(args: List[String]) -> String:
    """Re-exec once so runtime threads inherit blocked signals.

    Every Mojo 1.1.0 binary spawns runtime worker threads
    before main with the parent's (unblocked) mask; a
    process-directed SIGINT/SIGTERM would land in a
    worker and never reach signalfd. Blocking here and
    re-executing makes the runtime init inherit the
    block, so NO thread is eligible and every stop
    signal stays pending for signalfd. Masks survive
    exec, so the child skips the re-exec via the
    MEMVEIL_SIGBLK=1 sentinel. The sentinel is verified,
    not trusted: a pre-set variable without the mask
    refuses instead of running unprotected (re-execing
    would loop, since the child would inherit the same
    unblocked mask plus the same sentinel).

    Returns "" when the caller may proceed (already
    inherited), else a refusal note (re-exec failed or
    impossible). A successful re-exec never returns.
    """
    var sentinel = _cstr_bytes(_SIGBLK_SENTINEL)
    if _has_sigblk_sentinel():
        var probe_mask = blocked_mask()
        var old = List[UInt8]()
        for _ in range(_SIGSET_BYTES):
            old.append(UInt8(0))
        var probed = external_call["sigprocmask", Int32](
            Int32(_SIG_BLOCK),
            Span(probe_mask).unsafe_ptr(),
            Span(old).unsafe_ptr(),
        )
        if Int(probed) != 0:
            return String("cannot verify inherited signal mask")
        var need0 = UInt8(0x02)
        var need1 = UInt8(0x40)
        if (old[0] & need0) != need0 or (old[1] & need1) != need1:
            return String(
                "signal mask not inherited (MEMVEIL_SIGBLK set,"
                " SIGINT/SIGTERM unblocked); refusing"
            )
        return String("")
    var mask = blocked_mask()
    var old = List[UInt8]()
    for _ in range(_SIGSET_BYTES):
        old.append(UInt8(0))
    var blocked = external_call["sigprocmask", Int32](
        Int32(_SIG_BLOCK),
        Span(mask).unsafe_ptr(),
        Span(old).unsafe_ptr(),
    )
    if Int(blocked) != 0:
        return String("cannot block signals for re-exec")
    var one = _cstr_bytes(String("1"))
    var marked = external_call["setenv", Int32](
        Span(sentinel).unsafe_ptr(),
        Span(one).unsafe_ptr(),
        Int32(1),
    )
    if Int(marked) != 0:
        return String("cannot mark signal re-exec")
    var exe_link = _cstr_bytes(String("/proc/self/exe"))
    var exe_buf = List[UInt8]()
    for _ in range(4096):
        exe_buf.append(UInt8(0))
    var n = external_call["readlink", Int64](
        Span(exe_link).unsafe_ptr(),
        Span(exe_buf).unsafe_ptr(),
        UInt64(4095),
    )
    if Int(n) <= 0:
        return String("cannot resolve self path for re-exec")
    # One backing block so every argv pointer shares
    # a single origin (origins have no nameable common
    # spelling; the element type comes from type_of).
    # argv[0] is the resolved path; readlink wrote Int(n)
    # bytes and never NUL-terminates, so terminate here.
    var block = List[UInt8]()
    var offs = List[Int]()
    offs.append(0)
    for i in range(Int(n)):
        block.append(exe_buf[i])
    block.append(UInt8(0))
    for i in range(1, len(args)):
        offs.append(len(block))
        var cstr = _cstr_bytes(args[i])
        for j in range(len(cstr)):
            block.append(cstr[j])
    var base = Span(block).unsafe_ptr()
    var argv_ptrs = List[Optional[type_of(base)]]()
    for i in range(len(offs)):
        argv_ptrs.append(base.unsafe_offset(offs[i]))
    argv_ptrs.append(None)
    # Path via exe_buf (disjoint from block): two
    # mutable pointers into one buffer would alias.
    _ = external_call["execv", Int32](
        Span(exe_buf).unsafe_ptr(),
        Span(argv_ptrs).unsafe_ptr(),
    )
    return String("signal re-exec failed: errno ") + String(_sig_errno())


struct LiveSignalSource(SignalSource):
    """signalfd SIGINT/SIGTERM source for one thread.

    Single-threaded use only: sigprocmask covers the
    calling thread, and record spawns no threads.
    `test_fail_setup_at` ("mask"/"signalfd") is a
    test-only fault point for the two setup failures;
    production leaves it "".
    """

    var fd: Int32
    var old_mask: List[UInt8]
    var armed: Bool
    var test_fail_setup_at: String

    def __init__(out self):
        self.fd = Int32(-1)
        self.old_mask = List[UInt8]()
        self.armed = False
        self.test_fail_setup_at = String("")

    def __deinit__(deinit self):
        self.teardown()

    def setup(mut self) -> OpOut:
        if self.test_fail_setup_at == String("mask"):
            return OpOut(False, String("test mask failure"))
        var mask = blocked_mask()
        var old = List[UInt8]()
        var scratch = List[UInt8]()
        for _ in range(_SIGSET_BYTES):
            old.append(UInt8(0))
            scratch.append(UInt8(0))
        var blocked = external_call["sigprocmask", Int32](
            Int32(_SIG_BLOCK),
            Span(mask).unsafe_ptr(),
            Span(old).unsafe_ptr(),
        )
        if Int(blocked) != 0:
            return OpOut(
                False,
                String("mask install failed: errno ")
                + String(_sig_errno()),
            )
        if self.test_fail_setup_at == String("signalfd"):
            _ = external_call["sigprocmask", Int32](
                Int32(_SIG_SETMASK),
                Span(old).unsafe_ptr(),
                Span(scratch).unsafe_ptr(),
            )
            return OpOut(False, String("test signalfd failure"))
        var fd = external_call["signalfd", Int32](
            Int32(-1),
            Span(mask).unsafe_ptr(),
            Int32(_SFD_CLOEXEC | _SFD_NONBLOCK),
        )
        if fd < Int32(0):
            var no = _sig_errno()
            _ = external_call["sigprocmask", Int32](
                Int32(_SIG_SETMASK),
                Span(old).unsafe_ptr(),
                Span(scratch).unsafe_ptr(),
            )
            return OpOut(
                False,
                String("signalfd failed: errno ") + String(no),
            )
        self.fd = fd
        self.old_mask = old^
        self.armed = True
        return OpOut(True, String(""))

    def check(mut self) -> SignalOut:
        var buf = List[UInt8]()
        for _ in range(_SIGINFO_BYTES):
            buf.append(UInt8(0))
        while True:
            var n = external_call["read", Int64](
                self.fd,
                Span(buf).unsafe_ptr(),
                UInt64(_SIGINFO_BYTES),
            )
            var no = 0
            if Int(n) < 0:
                no = _sig_errno()
            var code = classify_signal_read(Int(n), no)
            if code == READ_PENDING:
                return SignalOut(String("pending"), String(""))
            if code == READ_NONE:
                return SignalOut(String("none"), String(""))
            if code == READ_ERROR:
                if Int(n) == 0:
                    return SignalOut(
                        String("error"), String("signal read: short")
                    )
                return SignalOut(
                    String("error"),
                    String("signal read: errno ") + String(no),
                )

    def teardown(mut self):
        """Restore the mask and close the fd (idempotent)."""
        if not self.armed:
            return
        _ = external_call["close", Int32](self.fd)
        var scratch = List[UInt8]()
        for _ in range(_SIGSET_BYTES):
            scratch.append(UInt8(0))
        _ = external_call["sigprocmask", Int32](
            Int32(_SIG_SETMASK),
            Span(self.old_mask).unsafe_ptr(),
            Span(scratch).unsafe_ptr(),
        )
        self.fd = Int32(-1)
        self.armed = False
