# SPDX-License-Identifier: GPL-3.0-or-later

"""Kernel gate probes: tracefs root, hook identity, ftrace state.

The tracefs root follows libbpf's probe order (debugfs
first, sys second), so admission and the loader agree on
which tree they read. Hook identity counts exact
first-token matches in available_filter_functions;
dotted clones and longer names never count. Denied
evidence is never absence: every probe reports unknown
when the kernel hides the fact.
"""

from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    EvidenceReader,
    bytes_to_text,
    exists_f_ok,
    file_state,
    read_evidence,
)


comptime TRACEFS_DEBUG = "/sys/kernel/debug/tracing"
comptime TRACEFS_SYS = "/sys/kernel/tracing"
comptime MAX_FILTER_FUNCS_BYTES = 8388608
comptime HOOK_STATE_UNREADABLE = 3

comptime _MOUNTS_CAP = 1048576
comptime _FTRACE_CAP = 1024
comptime _FTRACE_TEXT_KEEP = 64


struct TracefsProbe(Copyable):
    """One tracefs location probe: root, events state, mount word."""

    var root: String
    var has_root: Bool
    var events: Int
    var mounted: String

    def __init__(out self):
        self.root = String("")
        self.has_root = False
        self.events = EVIDENCE_ABSENT
        self.mounted = String("unknown")


def probe_tracefs(reader: EvidenceReader) -> TracefsProbe:
    """Locate the tracefs root in libbpf's probe order.

    The debugfs tree wins when it exists, else the sys
    tree; the events state and the mount word (yes, no,
    or unknown) come from the live tree and /proc/mounts.
    """
    var out = TracefsProbe()
    if exists_f_ok(reader, TRACEFS_DEBUG):
        out.root = TRACEFS_DEBUG
        out.has_root = True
    elif exists_f_ok(reader, TRACEFS_SYS):
        out.root = TRACEFS_SYS
        out.has_root = True
    if out.has_root:
        out.events = file_state(reader, out.root + String("/events"))
    var mounts = List[UInt8]()
    try:
        mounts = read_evidence(reader, String("/proc/mounts"), _MOUNTS_CAP)
    except:
        out.mounted = String("unknown")
        return out^
    var text = bytes_to_text(mounts^)
    var lines = text.split(String("\n"))
    var yes = False
    for i in range(len(lines)):
        var fields = String(lines[i]).split(String(" "))
        if len(fields) < 3:
            continue
        var where = String(fields[1])
        var fstype = String(fields[2])
        if out.has_root and where == out.root and fstype == String(
            "tracefs"
        ):
            yes = True
            break
        if (
            out.has_root
            and out.root == TRACEFS_DEBUG
            and where == String("/sys/kernel/debug")
            and fstype == String("debugfs")
        ):
            yes = True
            break
    if yes:
        out.mounted = String("yes")
    else:
        out.mounted = String("no")
    return out^


def tracefs_translate(probe: TracefsProbe, path: String) -> String:
    """Map a /sys/kernel/tracing profile path onto the live root.

    Paths outside the sys tracefs prefix, and every path
    without a probed root, pass through unchanged.
    """
    if not probe.has_root:
        return path
    if path == TRACEFS_SYS:
        return probe.root.copy()
    var prefix = String(TRACEFS_SYS) + String("/")
    if not path.startswith(prefix):
        return path
    var pb = path.as_bytes()
    var rest = String("")
    try:
        rest = String(from_utf8=pb[prefix.byte_length() : len(pb)])
    except:
        return path
    return probe.root + String("/") + rest


struct HookCount(Copyable):
    """One filter-file hook count: state plus matches."""

    var state: Int
    var count: Int
    var clones: Int

    def __init__(out self):
        self.state = EVIDENCE_ABSENT
        self.count = 0
        self.clones = 0


def _first_token(line: String) -> String:
    """The line up to its first space, or the whole line."""
    var b = line.as_bytes()
    for i in range(len(b)):
        if b[i] == UInt8(0x20):
            try:
                return String(from_utf8=b[0:i])
            except:
                return String("")
    return line


def filter_line_counts(line: String, function: String) -> Bool:
    """True when the line's first token equals the function.

    Module suffixes ("fn [mod]") still count; dotted
    clones ("fn.isra.0") and longer names never do.
    """
    return _first_token(line) == function


def _filter_line_is_clone(line: String, function: String) -> Bool:
    """True when the first token is a dotted clone of function."""
    var tok = _first_token(line)
    if tok == function:
        return False
    return tok.startswith(function + String("."))


def count_filter_function(
    reader: EvidenceReader, probe: TracefsProbe, function: String
) -> HookCount:
    """Count one function in available_filter_functions.

    The file is read under the probed root; state carries
    absent, denied, or unreadable without counting, and
    clones count separately, never as matches.
    """
    var out = HookCount()
    var fpath = tracefs_translate(
        probe, String(TRACEFS_SYS) + String("/available_filter_functions")
    )
    var st = file_state(reader, fpath)
    if st != EVIDENCE_OK:
        out.state = st
        return out^
    var raw = List[UInt8]()
    try:
        raw = read_evidence(reader, fpath, MAX_FILTER_FUNCS_BYTES)
    except:
        out.state = HOOK_STATE_UNREADABLE
        return out^
    var text = bytes_to_text(raw^)
    var lines = text.split(String("\n"))
    for i in range(len(lines)):
        var l = String(lines[i])
        if filter_line_counts(l.copy(), function):
            out.count += 1
        elif _filter_line_is_clone(l, function):
            out.clones += 1
    out.state = EVIDENCE_OK
    return out^


struct FtraceState(Copyable):
    """One ftrace_enabled read: 1, 0, absent, denied, malformed."""

    var value: String

    def __init__(out self):
        self.value = String("malformed")


def read_ftrace_enabled(reader: EvidenceReader) -> FtraceState:
    """Read the kernel.ftrace_enabled sysctl state word."""
    var out = FtraceState()
    var st = file_state(reader, String("/proc/sys/kernel/ftrace_enabled"))
    if st == EVIDENCE_ABSENT:
        out.value = String("absent")
        return out^
    if st == EVIDENCE_DENIED:
        out.value = String("denied")
        return out^
    var raw = List[UInt8]()
    try:
        raw = read_evidence(
            reader, String("/proc/sys/kernel/ftrace_enabled"), _FTRACE_CAP
        )
    except:
        out.value = String("malformed")
        return out^
    var text = bytes_to_text(raw^)
    var b = text.as_bytes()
    var end = len(b)
    if end > 0 and b[end - 1] == UInt8(0x0A):
        end -= 1
    var word = String("")
    try:
        word = String(from_utf8=b[0:end])
    except:
        out.value = String("malformed")
        return out^
    if word == String("1") or word == String("0"):
        out.value = word.copy()
    else:
        out.value = String("malformed")
    return out^


def read_ftrace_text(reader: EvidenceReader) -> String:
    """Raw ftrace_enabled content for messages, "" when unreadable."""
    var raw = List[UInt8]()
    try:
        raw = read_evidence(
            reader, String("/proc/sys/kernel/ftrace_enabled"), _FTRACE_CAP
        )
    except:
        return String("")
    var text = bytes_to_text(raw^)
    var b = text.as_bytes()
    var end = len(b)
    if end > 0 and b[end - 1] == UInt8(0x0A):
        end -= 1
    if end > _FTRACE_TEXT_KEEP:
        end = _FTRACE_TEXT_KEEP
    try:
        return String(from_utf8=b[0:end])
    except:
        return String("")
