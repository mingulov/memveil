# SPDX-License-Identifier: GPL-3.0-or-later

"""Zero-config runtime discovery for the bridge and BPF objects.

Collection verbs resolve the native bridge and per-channel BPF
objects through this module instead of requiring flags or
environment setup. Bridge order: explicit ``--bridge``
verbatim, ``LMB_NATIVE_LIB`` when unprivileged, the
executable-relative bundle path, then the system path.
Objects resolve per channel the same way without an env step:
explicit verbatim, bundle path, then the system path.

Explicit values are authoritative user input and are returned
unprobed; every other candidate must exist and be readable.
Discovery never loads anything: no dlopen here, only
``access(R_OK)`` probes. Callers inject the env value and the
kernel-resolved executable path (``getenv`` /
``readlink_self``), keeping this module free of ambient reads.
"""

from std.ffi import external_call

from memveil.platform.reader import _geteuid_live, _getuid_live


comptime _SYSTEM_BRIDGE = "/usr/lib/memveil/libbpf_mojo.so.1"
# BPF objects ship beside the bridge under /usr/lib: arch-dependent
# ELF under /usr/share is a packaging error, so the installed
# objects live here and discovery probes this directory.
comptime _SYSTEM_BPF_DIR = "/usr/lib/memveil"
comptime _MODE_R_OK = 4


@fieldwise_init
struct UidPair(Copyable, Movable):
    """Real and effective uids sampled together."""

    var ruid: Int
    var euid: Int


def live_uids() -> UidPair:
    """Sample the live real and effective uids."""
    return UidPair(_getuid_live(), _geteuid_live())


def is_privileged(ids: UidPair) -> Bool:
    """True for root or shifted-identity execution.

    euid 0 covers sudo and root; euid != ruid covers setuid
    and capability-shaped identity shifts. No setuid ships
    with MemVeil; the second arm is defense in depth.
    """
    return ids.euid == 0 or ids.euid != ids.ruid


def _to_cstr(text: String) -> List[UInt8]:
    """Copy text into a fresh NUL-terminated byte buffer."""
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _is_readable(path: String) -> Bool:
    """True when path exists and the caller may read it.

    One ``access(R_OK)`` probe: no open file description,
    never a load. Empty paths are never readable.
    """
    if path == String(""):
        return False
    var cpath = _to_cstr(path)
    var r = external_call["access", Int32](
        Span(cpath).unsafe_ptr(), _MODE_R_OK
    )
    return Int(r) == 0


def _dirname(path: String) -> String:
    """Lexical parent: "/a/b" -> "/a", "a/b" -> "a".

    Paths without "/" have no directory part (""); "/x" has
    parent "/".
    """
    var parts = path.split(String("/"))
    if len(parts) < 2:
        return String("")
    var out = String(parts[0])
    for i in range(1, len(parts) - 1):
        out += String("/") + String(parts[i])
    if out == String(""):
        return String("/")
    return out^


def exe_root(exe_path: String) -> String:
    """Tree root above the executable.

    Packaged layout keeps the binary one directory below the
    tree root (``<root>/bin/memveil``), so the root is the
    parent-of-parent. "" when no parent-of-parent exists (a
    bare name or a shallow relative path cannot name a tree);
    callers then skip the executable-relative candidate.
    """
    var parent = _dirname(exe_path)
    if parent == String(""):
        return String("")
    return _dirname(parent)


def _under(root: String, rest: String) -> String:
    """Join root and rest with exactly one separator."""
    if root == String("/"):
        return root + rest
    return root + String("/") + rest


def discover_bridge(
    explicit: String,
    has_explicit: Bool,
    env_value: String,
    ids: UidPair,
    exe_path: String,
) -> String:
    """Resolve the native bridge path, or "" when none applies.

    Order: explicit verbatim, the ``LMB_NATIVE_LIB`` value
    when unprivileged, the executable-relative bundle path,
    then the system path. Only non-explicit candidates are
    probed; nothing is ever loaded here.
    """
    if has_explicit:
        return explicit
    if not is_privileged(ids):
        if env_value != String("") and _is_readable(env_value):
            return env_value
    var root = exe_root(exe_path)
    if root != String(""):
        var bundled = _under(root, String("lib/libbpf_mojo.so.1"))
        if _is_readable(bundled):
            return bundled^
    if _is_readable(String(_SYSTEM_BRIDGE)):
        return String(_SYSTEM_BRIDGE)
    return String("")


def _object_file(kind: String) -> String:
    """BPF object filename for a channel, or "" when unknown."""
    if kind == String("attempt"):
        return String("swiotlb_attempt.bpf.o")
    if kind == String("lifecycle"):
        return String("swiotlb_lifecycle.bpf.o")
    if kind == String("copy"):
        return String("swiotlb_copy.bpf.o")
    return String("")


def discover_object(
    kind: String, explicit: String, has_explicit: Bool, exe_path: String
) -> String:
    """Resolve one channel's BPF object path, or "" when none.

    Order: explicit verbatim, the executable-relative bundle
    path, then the system path. Unknown kinds have no derived
    candidates. Probes existence/readability only; never loads.
    """
    if has_explicit:
        return explicit
    var file = _object_file(kind)
    if file == String(""):
        return String("")
    var root = exe_root(exe_path)
    if root != String(""):
        var bundled = _under(root, String("bpf/") + file)
        if _is_readable(bundled):
            return bundled^
    var system = String(_SYSTEM_BPF_DIR) + String("/") + file
    if _is_readable(system):
        return system^
    return String("")
