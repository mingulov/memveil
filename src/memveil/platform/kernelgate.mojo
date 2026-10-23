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

from memveil.platform.btf import MAX_KERNEL_BTF_BYTES, check_btf_health
from memveil.platform.narrow import read_live_config_text
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    E_TOO_BIG,
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
    (an absent lockdown LSM still forces none).
    CONFIG_FORCE_NONE without securityfs reports
    unknown: root may have raised the level since boot.
    Silence everywhere reports unknown. Never mounts.
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
        # Forced none is only the boot default; without
        # the securityfs file the runtime level is open.
        out.mode = String("unknown")
        out.src = String("config")
    if len(notes) > 0:
        out.detail = notes[0].copy()
        for i in range(1, len(notes)):
            out.detail += String("; ") + notes[i]
    return out^


def remedy_for(code: String) -> String:
    """One fixed remedy text per reason code, else "".

    Families share a text; anything outside the table
    (profile refusals, unknown codes) carries no line.
    """
    if code == String("lockdown-confidentiality"):
        return String(
            "boot without lockdown=confidentiality or use a kernel"
            " without CONFIG_LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY;"
            " integrity mode is fine"
        )
    if code == String("no-bpf-tracing"):
        return String(
            "kernel has no BPF tracing support: use a kernel built"
            " with CONFIG_FTRACE=y and CONFIG_BPF_EVENTS=y"
        )
    if code == String("tracefs-not-mounted"):
        return String(
            "mount tracefs: mount -t tracefs nodev /sys/kernel/tracing"
        )
    if code == String("tracefs-hidden"):
        return String(
            "check the lockdown state (cat /sys/kernel/security/lockdown)"
            " and that tracefs is mounted"
        )
    if (
        code == String("tracefs-denied")
        or code == String("btf-denied")
        or code == String("no-bpf-privilege")
        or code == String("load-eperm")
    ):
        return String(
            "run as root, or grant CAP_BPF and CAP_PERFMON"
            " (or CAP_SYS_ADMIN) and read access to tracefs"
            " and /sys/kernel/btf/vmlinux"
        )
    if (
        code == String("btf-absent-config")
        or code == String("btf-absent-unknown")
        or code == String("btf-malformed")
        or code == String("btf-truncated")
        or code == String("btf-too-large")
        or code == String("btf-split")
        or code == String("btf-unreadable")
        or code == String("btf-hook-not-in-btf")
        or code == String("btf-hook-missing")
    ):
        return String(
            "use a kernel built with CONFIG_DEBUG_INFO_BTF=y;"
            " memveil qualify cannot help"
        )
    if code == String("btf-not-visible"):
        return String(
            "run with the host /sys: this view hides /sys/kernel/btf/vmlinux"
        )
    if (
        code == String("btf-hook-absent")
        or code == String("hook-ambiguous")
        or code == String("hook-not-traceable")
    ):
        return String(
            "this kernel does not expose the hook function for tracing;"
            " this capability cannot run here"
        )
    if code == String("ftrace-disabled"):
        return String(
            "enable function tracing: sysctl kernel.ftrace_enabled=1"
        )
    if code == String("ftrace-unknown"):
        return String(
            "check that /proc/sys/kernel/ftrace_enabled is readable"
            " and holds 1"
        )
    if (
        code == String("layout-missing")
        or code == String("layout-kind")
        or code == String("layout-size")
        or code == String("layout-bitfield")
        or code == String("layout-ambiguous")
    ):
        return String(
            "this kernel's struct layout differs from what the objects"
            " were built for; this capability cannot run here"
        )
    if code == String("signature-mismatch") or code == String(
        "signature-width"
    ):
        return String(
            "refresh the profile's recorded signatures from this kernel,"
            " then re-prove with memveil qualify"
            " (see memveil qualify --help)"
        )
    if code == String("memcg-headroom") or code == String("load-enomem"):
        return String(
            "raise the cgroup memory limit (memory.max) or RLIMIT_MEMLOCK"
        )
    if code == String("object-missing"):
        return String(
            "install the memveil BPF objects or pass --object,"
            " --lc-object, --cp-object"
        )
    if code == String("verifier-rejected"):
        return String(
            "the kernel verifier rejected the object;"
            " see the verifier lines above"
        )
    if code == String("bridge-unchecked"):
        return String(
            "run memveil doctor --load-check or memveil record"
            " to check the bridge"
        )
    return String("")


struct BtfFacts(Copyable):
    """One kernel BTF fact set: state, bytes, config words."""

    var state: String
    var bytes: Int
    var has_bytes: Bool
    var config_btf: String
    var config_src: String

    def __init__(out self):
        self.state = String("unreadable")
        self.bytes = 0
        self.has_bytes = False
        self.config_btf = String("unknown")
        self.config_src = String("none")


struct GateVerdict(Copyable):
    """One shared kernel gate verdict with evidence facts."""

    var ok: Bool
    var unknown: Bool
    var code: String
    var reason: String
    var remedy: String
    var btf: BtfFacts
    var lockdown: LockdownState
    var tracefs: TracefsProbe

    def __init__(out self):
        self.ok = False
        self.unknown = False
        self.code = String("")
        self.reason = String("")
        self.remedy = String("")
        self.btf = BtfFacts()
        self.lockdown = LockdownState()
        self.tracefs = TracefsProbe()


def _config_has_line(text: String, line: String) -> Bool:
    """True when one exact config line is present."""
    var lines = text.split(String("\n"))
    for i in range(len(lines)):
        if String(lines[i]) == line:
            return True
    return False


def kernel_gate(
    reader: EvidenceReader,
    release: String,
    zlib: String,
    caps: List[String],
) -> GateVerdict:
    """Admit capabilities through the shared kernel checks.

    Lockdown, tracing support, tracefs, and (for the BTF
    channels) BTF presence decide in that order; the
    first match wins and the facts always fill in for
    doctor. Unhealthy BTF bytes are recorded, never
    refused here: the live path reports them.
    """
    var out = GateVerdict()
    out.lockdown = read_lockdown(reader, release, zlib)
    out.tracefs = probe_tracefs(reader)
    var cfg = read_live_config_text(reader, release, zlib)
    var cfg_text = String("")
    if cfg.state == String("text"):
        cfg_text = cfg.text.copy()
    var facts = BtfFacts()
    if cfg.state == String("text"):
        if cfg.src == String("gz"):
            facts.config_src = String("proc")
        elif cfg.src == String("file"):
            facts.config_src = String("boot")
        if _config_has_line(
            cfg_text, String("CONFIG_DEBUG_INFO_BTF=y")
        ):
            facts.config_btf = String("y")
        elif _config_has_line(
            cfg_text, String("# CONFIG_DEBUG_INFO_BTF is not set")
        ):
            facts.config_btf = String("n")
    var btf_st = file_state(reader, String("/sys/kernel/btf/vmlinux"))
    var btf_too_big = False
    var btf_read_ok = False
    var btf_err = String("")
    if btf_st == EVIDENCE_OK:
        try:
            var btf_bytes = read_evidence(
                reader,
                String("/sys/kernel/btf/vmlinux"),
                MAX_KERNEL_BTF_BYTES,
            )
            var health = check_btf_health(Span(btf_bytes))
            facts.bytes = len(btf_bytes)
            facts.has_bytes = True
            btf_read_ok = True
            if health.ok:
                facts.state = String("present")
            else:
                facts.state = String("malformed")
        except e:
            btf_err = String(e)
            if e.code == E_TOO_BIG:
                btf_too_big = True
    if btf_st == EVIDENCE_DENIED:
        facts.state = String("denied")
    elif btf_st == EVIDENCE_ABSENT:
        facts.state = String("absent")
        if facts.config_btf == String("y"):
            facts.state = String("not-visible")
    elif not btf_read_ok:
        facts.state = String("unreadable")
    out.btf = facts^
    var want_btf = False
    for i in range(len(caps)):
        if caps[i] == String("mapping-lifecycle") or caps[i] == String(
            "copy-actual"
        ):
            want_btf = True
            break
    var code = String("")
    var reason = String("")
    var unknown = False
    var refused = False
    var troot = out.tracefs.root.copy()
    if out.lockdown.mode == String("confidentiality"):
        var lsrc = out.lockdown.src.copy()
        code = String("lockdown-confidentiality")
        reason = String(
            t"kernel lockdown is confidentiality ({lsrc}): tracefs"
        ) + String(" is hidden and bpf_probe_read_kernel is denied")
        refused = True
    elif _config_has_line(cfg_text, String("# CONFIG_FTRACE is not set")):
        code = String("no-bpf-tracing")
        reason = String(
            "kernel has no BPF tracing support"
            " (config has # CONFIG_FTRACE is not set)"
        )
        refused = True
    elif _config_has_line(
        cfg_text, String("CONFIG_FTRACE=y")
    ) and not _config_has_line(
        cfg_text, String("CONFIG_BPF_EVENTS=y")
    ):
        code = String("no-bpf-tracing")
        reason = String(
            "kernel has no BPF tracing support"
            " (config has CONFIG_FTRACE=y without CONFIG_BPF_EVENTS=y)"
        )
        refused = True
    elif (
        out.tracefs.mounted == String("yes")
        and out.tracefs.events == EVIDENCE_ABSENT
        and out.lockdown.mode != String("unknown")
    ):
        code = String("no-bpf-tracing")
        reason = (
            String("kernel has no BPF tracing support (tracefs mounted at ")
            + troot.copy()
            + String(" but has no events/)")
        )
        refused = True
    elif not out.tracefs.has_root:
        code = String("tracefs-not-mounted")
        reason = String(
            "tracefs not found: neither /sys/kernel/debug/tracing"
            " nor /sys/kernel/tracing exists"
        )
        refused = True
    elif out.tracefs.events == EVIDENCE_DENIED:
        code = String("tracefs-denied")
        reason = (
            String("tracefs denied (privilege): ")
            + troot.copy()
            + String("/events")
        )
        unknown = True
        refused = True
    elif (
        out.tracefs.events == EVIDENCE_ABSENT
        and out.tracefs.mounted == String("no")
    ):
        code = String("tracefs-not-mounted")
        reason = (
            String("tracefs not mounted at ")
            + troot.copy()
            + String(" (no tracefs entry in /proc/mounts)")
        )
        refused = True
    elif (
        out.tracefs.events == EVIDENCE_ABSENT
        and out.lockdown.mode == String("unknown")
    ):
        code = String("tracefs-hidden")
        reason = String(
            "tracepoint absent or tracefs hidden by lockdown"
            " (lockdown state unknown)"
        )
        unknown = True
        refused = True
    elif out.tracefs.events == EVIDENCE_ABSENT:
        code = String("tracefs-not-mounted")
        reason = (
            troot.copy()
            + String(
                "/events absent (tracefs not mounted"
                " or mount state unreadable)"
            )
        )
        unknown = True
        refused = True
    elif want_btf and btf_st == EVIDENCE_DENIED:
        code = String("btf-denied")
        reason = String("BTF denied (privilege)")
        unknown = True
        refused = True
    elif (
        want_btf
        and btf_st == EVIDENCE_ABSENT
        and out.btf.config_btf == String("n")
        and exists_f_ok(reader, String("/sys/kernel/notes"))
    ):
        code = String("btf-absent-config")
        reason = String("BTF absent (kernel built without BTF)")
        refused = True
    elif (
        want_btf
        and btf_st == EVIDENCE_ABSENT
        and out.btf.config_btf == String("y")
    ):
        code = String("btf-not-visible")
        reason = String(
            "BTF not visible (config has CONFIG_DEBUG_INFO_BTF=y"
            " but /sys/kernel/btf/vmlinux is missing)"
        )
        unknown = True
        refused = True
    elif want_btf and btf_st == EVIDENCE_ABSENT:
        code = String("btf-absent-unknown")
        reason = String(
            "BTF absent (not exposed: kernel built without BTF,"
            " or /sys/kernel/btf hidden)"
        )
        refused = True
    elif want_btf and btf_too_big:
        var cap = MAX_KERNEL_BTF_BYTES
        code = String("btf-too-large")
        reason = String(t"BTF too large (over {cap} bytes)")
        unknown = True
        refused = True
    elif want_btf and not btf_read_ok:
        code = String("btf-unreadable")
        reason = String("BTF unreadable: ") + btf_err
        unknown = True
        refused = True
    if refused:
        out.code = code.copy()
        out.reason = reason.copy()
        out.unknown = unknown
        out.remedy = remedy_for(code)
        return out^
    out.ok = True
    return out^
