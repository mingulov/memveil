# SPDX-License-Identifier: GPL-3.0-or-later

"""Checked standard-output writer: short writes fail loudly.

The language print path and file writes swallow output errors
(/dev/full exits 0), so every product stdout write goes
through here instead: raw write(2) on fd 1 with an EINTR
retry loop and an exact byte count. A short write or an
error raises StdoutError carrying the errno, and the caller
maps it to exit 1 with a stderr reason. Nothing on stdout is
buffered here, and no other product code writes fd 1, so
bytes land in call order.
"""

from std.ffi import external_call

comptime _EINTR = 4


@fieldwise_init
struct StdoutError(Copyable, Writable):
    """One standard-output failure: errno attached, never silent."""

    var message: String


def _errno_now() -> Int:
    var p = external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()
    return Int(p.unsafe_load())


def write_stdout(text: String) raises:
    """Write every byte of text to fd 1 or raise StdoutError."""
    var raw = text.as_bytes()
    var total = len(raw)
    var off = 0
    while off < total:
        var n = external_call["write", Int](
            1, Span(raw).unsafe_ptr().unsafe_offset(off), total - off
        )
        if n < 0:
            var no = _errno_now()
            if no == _EINTR:
                continue
            raise StdoutError("stdout write failed: errno " + String(no))
        if n == 0:
            raise StdoutError("stdout write returned 0")
        off += n
