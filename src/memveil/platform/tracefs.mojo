# SPDX-License-Identifier: GPL-3.0-or-later

"""Tracefs root probe: locate the tree, translate paths onto it.

The root follows libbpf's probe order (debugfs first,
sys second), so admission and the loader agree on which
tree they read. A leaf module: only the evidence reader
below it, so narrow and the gate can both use it without
a cycle.
"""

from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EvidenceReader,
    bytes_to_text,
    exists_f_ok,
    file_state,
    read_evidence,
)


comptime TRACEFS_DEBUG = "/sys/kernel/debug/tracing"
comptime TRACEFS_SYS = "/sys/kernel/tracing"
comptime _MOUNTS_CAP = 1048576


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
