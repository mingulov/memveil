# SPDX-License-Identifier: GPL-3.0-or-later

"""Load diagnostics: errno names, verifier tails, load replay.

``errno_name``/``errno_cause`` name the small errno set a BPF
load can return; ``verifier_tail`` keeps the last lines of a
program log; ``diagnose_load`` replays one object load with
log-on-failure to recover those lines. Nothing here attaches.
"""

from libbpf_mojo._ffi import LOG_ON_FAILURE
from libbpf_mojo.object import Object, ObjectOptions
from memveil.platform.reader import bytes_to_text

comptime _DIAG_LOG_CAP = 65536
comptime _TAIL_LINES = 4
comptime _TAIL_LINE_CAP = 256


def errno_name(code: Int32) -> String:
    """Short name for one load errno, else ``errno <n>``."""
    if code == Int32(-1):
        return String("EPERM")
    if code == Int32(-2):
        return String("ENOENT")
    if code == Int32(-7):
        return String("E2BIG")
    if code == Int32(-12):
        return String("ENOMEM")
    if code == Int32(-13):
        return String("EACCES")
    if code == Int32(-16):
        return String("EBUSY")
    if code == Int32(-22):
        return String("EINVAL")
    if code == Int32(-28):
        return String("ENOSPC")
    if code == Int32(-38):
        return String("ENOSYS")
    if code == Int32(-95):
        return String("EOPNOTSUPP")
    if code == Int32(-524):
        return String("ENOTSUPP")
    return String("errno ") + String(code)


def errno_cause(code: Int32) -> String:
    """One-line cause for a load errno, else ``""``."""
    if code == Int32(-1):
        return String("needs CAP_BPF and CAP_PERFMON")
    if code == Int32(-12):
        return String("memcg or memlock limit")
    if code == Int32(-13) or code == Int32(-22):
        return String("verifier rejected, see log")
    if code == Int32(-7):
        return String("program too large")
    return String("")


def _escape_line(s: String) -> String:
    """Escape one line: backslash n/t/r, U+FFFD for C0/DEL.

    Same byte rules as render/text escape_text, kept local
    so capture never imports render.
    """
    var raw = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(raw)):
        var b = raw[i]
        if b == UInt8(0x0A):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x6E))
        elif b == UInt8(0x09):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x74))
        elif b == UInt8(0x0D):
            out.append(UInt8(0x5C))
            out.append(UInt8(0x72))
        elif b < UInt8(0x20) or b == UInt8(0x7F):
            out.append(UInt8(0xEF))
            out.append(UInt8(0xBF))
            out.append(UInt8(0xBD))
        else:
            out.append(b)
    try:
        return String(from_utf8=Span(out))
    except:
        return bytes_to_text(out^)


def _clip_line(s: String, cap: Int) -> String:
    """Clip one line to cap bytes at a UTF-8 edge."""
    var b = s.as_bytes()
    if len(b) <= cap:
        return s.copy()
    var n = cap
    while n > 0 and b[n] >= UInt8(0x80) and b[n] < UInt8(0xC0):
        n -= 1
    var cut = List[UInt8]()
    for i in range(n):
        cut.append(b[i])
    try:
        return String(from_utf8=Span(cut))
    except:
        return bytes_to_text(cut^)


def _clean_verifier_line(raw: List[UInt8]) -> String:
    """Sanitize one verifier line, then cap at 256 bytes."""
    return _clip_line(_escape_line(bytes_to_text(raw)), _TAIL_LINE_CAP)


def verifier_tail(log: List[UInt8], truncated: Bool) -> List[String]:
    """Last 4 non-empty verifier lines, sanitized, capped.

    A truncated log gains the fixed first line naming the
    64 KiB cut; each kept line holds at most 256 bytes.
    """
    var lines = List[String]()
    var cur = List[UInt8]()
    for i in range(len(log)):
        var b = log[i]
        if b == UInt8(0x0A):
            if len(cur) > 0:
                lines.append(_clean_verifier_line(cur))
                cur = List[UInt8]()
        else:
            cur.append(b)
    if len(cur) > 0:
        lines.append(_clean_verifier_line(cur))
    var out = List[String]()
    if truncated:
        out.append(
            String("verifier log truncated at 65536 bytes")
        )
    var start = 0
    if len(lines) > _TAIL_LINES:
        start = len(lines) - _TAIL_LINES
    for i in range(start, len(lines)):
        out.append(lines[i].copy())
    return out^


struct LoadDiag(Copyable):
    """One load replay: errno name plus verifier tail lines."""

    var errno: String
    var lines: List[String]

    def __init__(out self):
        self.errno = String("")
        self.lines = List[String]()


def diagnose_load(
    elf: Span[UInt8, _], lib_path: String, programs: List[String]
) -> LoadDiag:
    """Reload one object for its verifier log; never attaches.

    Opens the object with log-on-failure and loads it; on
    failure tails the first non-empty program log. Every
    path releases the object; nothing attaches.
    """
    var out = LoadDiag()
    var opts = ObjectOptions(
        String("mv-diagnose"),
        List[UInt8](),
        LOG_ON_FAILURE,
        UInt64(_DIAG_LOG_CAP),
    )
    try:
        var obj = Object.open_with_lib(elf, lib_path, opts^)
        try:
            obj.load()
        except e:
            out.errno = errno_name(e.code)
            for i in range(len(programs)):
                var mlog = List[UInt8]()
                var mtrunc = False
                var meta_ok = False
                try:
                    var view = obj.program(programs[i])
                    try:
                        var meta = view.info(_DIAG_LOG_CAP)
                        mlog = meta.log.copy()
                        mtrunc = meta.log_truncated
                        meta_ok = True
                    except:
                        pass
                    view.close()
                except:
                    pass
                if meta_ok and len(mlog) > 0:
                    out.lines = verifier_tail(mlog^, mtrunc)
                    break
        obj.release()
    except e:
        out.errno = errno_name(e.code)
    return out^
