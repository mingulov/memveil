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

from memveil.platform.narrow import read_live_config_text
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
comptime _LOCKDOWN_CAP = 4096
comptime _CMDLINE_CAP = 65536


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


def _mounts_state(
    reader: EvidenceReader, where: String, fstype: String
) -> String:
    """Mount word for one path: yes, no, or unknown.

    Unknown covers unreadable, absent, and denied mount
    tables: mounting is never disproven from them.
    """
    try:
        var mounts = read_evidence(
            reader, String("/proc/mounts"), _MOUNTS_CAP
        )
        var text = bytes_to_text(mounts^)
        var lines = text.split(String("\n"))
        for i in range(len(lines)):
            var fields = String(lines[i]).split(String(" "))
            if len(fields) < 3:
                continue
            if String(fields[1]) == where and String(fields[2]) == fstype:
                return String("yes")
        return String("no")
    except:
        return String("unknown")


struct LockdownState(Copyable):
    """One kernel lockdown read: mode, source, and detail."""

    var mode: String
    var src: String
    var detail: String

    def __init__(out self):
        self.mode = String("unknown")
        self.src = String("none")
        self.detail = String("")


def _lockdown_bracketed(text: String) -> List[String]:
    """Every [token] in one lockdown file body, in order."""
    var out = List[String]()
    var b = text.as_bytes()
    var i = 0
    while i < len(b):
        if b[i] != UInt8(0x5B):
            i += 1
            continue
        var j = i + 1
        while j < len(b) and b[j] != UInt8(0x5D):
            j += 1
        if j < len(b):
            try:
                out.append(String(from_utf8=b[i + 1 : j]))
            except:
                pass
            i = j + 1
        else:
            i += 1
    return out^


def _lockdown_mode(level: Int) -> String:
    """Mode word for one parsed level: 2, 1, or 0."""
    if level >= 2:
        return String("confidentiality")
    if level == 1:
        return String("integrity")
    return String("none")


def read_lockdown(
    reader: EvidenceReader, release: String, zlib: String
) -> LockdownState:
    """Read the kernel lockdown level with fallbacks.

    The securityfs file wins when it parses under a
    mounted securityfs; otherwise the cmdline level and
    the config level combine by taking the higher one
    (an absent lockdown LSM still forces none), and
    silence everywhere reports unknown. Never mounts.
    """
    var out = LockdownState()
    var notes = List[String]()
    var secfs = _mounts_state(
        reader, String("/sys/kernel/security"), String("securityfs")
    )
    var st = file_state(reader, String("/sys/kernel/security/lockdown"))
    if st == EVIDENCE_OK and secfs != String("no"):
        try:
            var lraw = read_evidence(
                reader,
                String("/sys/kernel/security/lockdown"),
                _LOCKDOWN_CAP,
            )
            var toks = _lockdown_bracketed(bytes_to_text(lraw^))
            if len(toks) == 1 and (
                toks[0] == String("none")
                or toks[0] == String("integrity")
                or toks[0] == String("confidentiality")
            ):
                out.mode = toks[0].copy()
                out.src = String("securityfs")
                return out^
            notes.append(String("lockdown file malformed"))
        except:
            pass
    var cmd_level = 0
    if file_state(reader, String("/proc/cmdline")) == EVIDENCE_OK:
        try:
            var craw = read_evidence(
                reader, String("/proc/cmdline"), _CMDLINE_CAP
            )
            var ctext = bytes_to_text(craw^)
            var cb = ctext.as_bytes()
            if len(cb) > 0 and cb[len(cb) - 1] == UInt8(0x0A):
                try:
                    ctext = String(from_utf8=cb[0 : len(cb) - 1])
                except:
                    pass
            var words = ctext.split(String(" "))
            for i in range(len(words)):
                var tok = String(words[i])
                if tok == String("--"):
                    break
                if tok.startswith(String("lockdown=")):
                    var tb = tok.as_bytes()
                    var val = String("")
                    try:
                        val = String(from_utf8=tb[9 : len(tb)])
                    except:
                        val = String("")
                    if val == String("integrity"):
                        if cmd_level < 1:
                            cmd_level = 1
                    elif val == String("confidentiality"):
                        cmd_level = 2
                    else:
                        notes.append(
                            String("lockdown=")
                            + val
                            + String(" ignored")
                        )
        except:
            pass
    var force_level = 0
    var force_none = False
    var lsm_absent = False
    var cfg = read_live_config_text(reader, release, zlib)
    if cfg.state == String("text"):
        var lines = cfg.text.split(String("\n"))
        for i in range(len(lines)):
            var ln = String(lines[i])
            if (
                ln
                == String(
                    "CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY=y"
                )
            ):
                force_level = 2
            elif ln == String("CONFIG_LOCK_DOWN_KERNEL_FORCE_INTEGRITY=y"):
                if force_level < 1:
                    force_level = 1
            elif ln == String("CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y"):
                force_none = True
            elif (
                ln
                == String("# CONFIG_SECURITY_LOCKDOWN_LSM is not set")
            ):
                lsm_absent = True
    if lsm_absent:
        out.mode = String("none")
        out.src = String("config")
    elif cmd_level > 0 or force_level > 0:
        if cmd_level >= force_level:
            out.mode = _lockdown_mode(cmd_level)
            out.src = String("cmdline")
        else:
            out.mode = _lockdown_mode(force_level)
            out.src = String("config")
    elif force_none:
        out.mode = String("none")
        out.src = String("config")
    if len(notes) > 0:
        out.detail = notes[0].copy()
        for i in range(1, len(notes)):
            out.detail += String("; ") + notes[i]
    return out^
