# SPDX-License-Identifier: GPL-3.0-or-later

"""Passive pre-checks: privilege, memcg headroom, BPF sysctl.

Each check reads procfs/sysfs evidence without loading
anything: fail means the capability cannot run, unknown
leaves it load-unchecked with the check line as evidence.
"""

from memveil.model.validate import format_u64
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EvidenceReader,
    bytes_to_text,
    file_state,
    read_evidence,
)

comptime P_STATUS = "/proc/self/status"
comptime P_CGROUP_SELF = "/proc/self/cgroup"
comptime P_CGROUP_ROOT = "/sys/fs/cgroup"
comptime P_UID_MAP = "/proc/self/uid_map"
comptime P_UNPRIV_BPF = "/proc/sys/kernel/unprivileged_bpf_disabled"
comptime _STATUS_CAP = 65536
comptime _CGROUP_CAP = 65536
comptime _MEMCG_CAP = 4096
comptime _UIDMAP_CAP = 4096
comptime _UNPRIV_CAP = 4096


@fieldwise_init
struct PreCheck(Copyable):
    """One passive pre-check: id, state, reason, code."""

    var id: String
    var state: String
    var reason: String
    var code: String


def _is_hex(b: UInt8) -> Bool:
    return (
        (b >= UInt8(0x30) and b <= UInt8(0x39))
        or (b >= UInt8(0x61) and b <= UInt8(0x66))
        or (b >= UInt8(0x41) and b <= UInt8(0x46))
    )


def _hex_val(b: UInt8) -> UInt64:
    if b >= UInt8(0x61):
        return UInt64(Int(b) - 0x61 + 10)
    if b >= UInt8(0x41):
        return UInt64(Int(b) - 0x41 + 10)
    return UInt64(Int(b) - 0x30)


def _is_blank(b: UInt8) -> Bool:
    return (
        b == UInt8(0x20)
        or b == UInt8(0x09)
        or b == UInt8(0x0A)
        or b == UInt8(0x0D)
    )


def _strip_token(raw: List[UInt8]) -> List[UInt8]:
    """Core bytes between leading and trailing blanks."""
    var out = List[UInt8]()
    var s = 0
    while s < len(raw) and _is_blank(raw[s]):
        s += 1
    var e = len(raw)
    while e > s and _is_blank(raw[e - 1]):
        e -= 1
    for k in range(s, e):
        out.append(raw[k])
    return out^


def _is_init_uidmap(raw: List[UInt8]) -> Bool:
    """True when raw holds exactly 0, 0, 4294967295 as tokens."""
    var toks = List[String]()
    var cur = List[UInt8]()
    for b in raw:
        if _is_blank(b):
            if len(cur) > 0:
                toks.append(bytes_to_text(cur^))
                cur = List[UInt8]()
            continue
        cur.append(b)
    if len(cur) > 0:
        toks.append(bytes_to_text(cur^))
    if len(toks) != 3:
        return False
    return (
        toks[0] == String("0")
        and toks[1] == String("0")
        and toks[2] == String("4294967295")
    )


def check_privilege(reader: EvidenceReader) -> PreCheck:
    """Pass iff init-namespace CapEff grants BPF or sysadmin.

    capable() checks the init user namespace, so a
    namespaced CapEff cannot pass. An absent uid_map
    means the kernel has no user namespaces at all.
    """
    var st = file_state(reader, String(P_STATUS))
    if st == EVIDENCE_ABSENT:
        return PreCheck(
            String("privilege"),
            String("unknown"),
            String("CapEff unreadable: absent"),
            String(""),
        )
    if st == EVIDENCE_DENIED:
        return PreCheck(
            String("privilege"),
            String("unknown"),
            String("CapEff unreadable: denied"),
            String(""),
        )
    var ust = file_state(reader, String(P_UID_MAP))
    if ust == EVIDENCE_DENIED:
        return PreCheck(
            String("privilege"),
            String("unknown"),
            String("user namespace unreadable: denied"),
            String(""),
        )
    if ust != EVIDENCE_ABSENT:
        var umap = List[UInt8]()
        try:
            umap = read_evidence(reader, String(P_UID_MAP), _UIDMAP_CAP)
        except e:
            return PreCheck(
                String("privilege"),
                String("unknown"),
                String("user namespace unreadable: ") + e.message,
                String(""),
            )
        if not _is_init_uidmap(umap^):
            return PreCheck(
                String("privilege"),
                String("unknown"),
                String("non-init user namespace: CapEff is namespaced"),
                String(""),
            )
    var text = String("")
    try:
        text = bytes_to_text(
            read_evidence(reader, String(P_STATUS), _STATUS_CAP)
        )
    except e:
        return PreCheck(
            String("privilege"),
            String("unknown"),
            String("CapEff unreadable: ") + e.message,
            String(""),
        )
    var seen = False
    var bad = True
    var cap = UInt64(0)
    var shown = String("")
    for line in text.split(String("\n")):
        if not line.startswith(String("CapEff:")):
            continue
        if seen:
            break
        seen = True
        var lb = line.as_bytes()
        var vstart = 7
        while vstart < len(lb) and _is_blank(lb[vstart]):
            vstart += 1
        var vend = vstart
        while vend < len(lb) and not _is_blank(lb[vend]):
            vend += 1
        var rest = vend
        while rest < len(lb) and _is_blank(lb[rest]):
            rest += 1
        if rest != len(lb) or vend - vstart != 16:
            break
        var digits = List[UInt8]()
        var v = UInt64(0)
        var ok = True
        for k in range(vstart, vend):
            if not _is_hex(lb[k]):
                ok = False
                break
            digits.append(lb[k])
            v = v * UInt64(16) + _hex_val(lb[k])
        if not ok:
            break
        shown = bytes_to_text(digits^)
        cap = v
        bad = False
        break
    if bad:
        return PreCheck(
            String("privilege"),
            String("unknown"),
            String("CapEff unreadable: malformed"),
            String(""),
        )
    var bpf = ((cap >> UInt64(39)) & UInt64(1)) == UInt64(1)
    var perfmon = ((cap >> UInt64(38)) & UInt64(1)) == UInt64(1)
    var admin = ((cap >> UInt64(21)) & UInt64(1)) == UInt64(1)
    if (bpf and perfmon) or admin:
        var grant = String("CAP_BPF+CAP_PERFMON")
        if not (bpf and perfmon):
            grant = String("CAP_SYS_ADMIN")
        return PreCheck(
            String("privilege"),
            String("pass"),
            String("CapEff ") + shown + String(" has ") + grant,
            String(""),
        )
    return PreCheck(
        String("privilege"),
        String("fail"),
        String("CapEff ")
        + shown
        + String(" lacks CAP_BPF+CAP_PERFMON and CAP_SYS_ADMIN"),
        String("no-bpf-privilege"),
    )


struct _MemVal(ImplicitlyCopyable):
    """One memcg file: unlimited, value, or unknown with why."""

    var unlimited: Bool
    var known: Bool
    var value: UInt64
    var why: String

    def __init__(out self):
        self.unlimited = False
        self.known = False
        self.value = UInt64(0)
        self.why = String("")


def _read_mem_val(
    reader: EvidenceReader, path: String, allow_max: Bool
) -> _MemVal:
    """Read one memcg limit/usage file with strict digits."""
    var out = _MemVal()
    var st = file_state(reader, path)
    if st == EVIDENCE_ABSENT:
        out.unlimited = True
        return out^
    if st == EVIDENCE_DENIED:
        out.why = path + String(" unreadable: denied")
        return out^
    var raw = List[UInt8]()
    try:
        raw = read_evidence(reader, path, _MEMCG_CAP)
    except e:
        out.why = path + String(" unreadable: ") + e.message
        return out^
    var tok = _strip_token(raw^)
    if allow_max and len(tok) == 3:
        if (
            tok[0] == UInt8(0x6D)
            and tok[1] == UInt8(0x61)
            and tok[2] == UInt8(0x78)
        ):
            out.unlimited = True
            return out^
    if len(tok) == 0 or len(tok) > 20:
        out.why = path + String(" malformed")
        return out^
    var v = UInt64(0)
    for b in tok:
        if b < UInt8(0x30) or b > UInt8(0x39):
            out.why = path + String(" malformed")
            return out^
        var d = UInt64(Int(b) - 48)
        if v > (UInt64(0xFFFFFFFFFFFFFFFF) - d) // UInt64(10):
            v = UInt64(0xFFFFFFFFFFFFFFFF)
        else:
            v = v * UInt64(10) + d
    out.known = True
    out.value = v
    return out^


def check_memcg(reader: EvidenceReader, need: Int) -> PreCheck:
    """Pass iff every ancestor cgroup fits need bytes.

    A shortfall is unknown, not fail: memory.current
    counts reclaimable page cache and map allocation
    reclaims. A root path is unknown too: it may be a
    cgroup-namespace root with invisible outer limits.
    """
    var st = file_state(reader, String(P_CGROUP_SELF))
    if st == EVIDENCE_ABSENT:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String("cgroup unreadable: absent"),
            String(""),
        )
    if st == EVIDENCE_DENIED:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String("cgroup unreadable: denied"),
            String(""),
        )
    var text = String("")
    try:
        text = bytes_to_text(
            read_evidence(reader, String(P_CGROUP_SELF), _CGROUP_CAP)
        )
    except e:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String("cgroup unreadable: ") + e.message,
            String(""),
        )
    var cgpath = String("")
    var found = False
    for line in text.split(String("\n")):
        if not line.startswith(String("0::")):
            continue
        var lb = line.as_bytes()
        var tail = List[UInt8]()
        for k in range(3, len(lb)):
            tail.append(lb[k])
        var stripped = _strip_token(tail^)
        for b in stripped:
            if _is_blank(b):
                return PreCheck(
                    String("memcg"),
                    String("unknown"),
                    String("malformed cgroup path"),
                    String(""),
                )
        cgpath = bytes_to_text(stripped^)
        found = True
        break
    if not found:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String("no 0:: cgroup line"),
            String(""),
        )
    var comps = List[String]()
    var cur = List[UInt8]()
    var pb = cgpath.as_bytes()
    for b in pb:
        if b == UInt8(0x2F):
            if len(cur) > 0:
                comps.append(bytes_to_text(cur^))
                cur = List[UInt8]()
        else:
            cur.append(b)
    if len(cur) > 0:
        comps.append(bytes_to_text(cur^))
    if len(comps) == 0:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String(
                "cgroup at /: possible cgroup namespace,"
                " outer limits unknown"
            ),
            String(""),
        )
    for c in comps:
        if c == String(".") or c == String(".."):
            return PreCheck(
                String("memcg"),
                String("unknown"),
                String("malformed cgroup path"),
                String(""),
            )
    var want = UInt64(0)
    if need > 0:
        want = UInt64(need)
    var best = UInt64(0xFFFFFFFFFFFFFFFF)
    var best_path = String("/")
    var constrained = False
    var prefix = String("")
    for c in comps:
        prefix += String("/") + c
        var dir = String(P_CGROUP_ROOT) + prefix
        var maxv = _read_mem_val(
            reader, dir + String("/memory.max"), True
        )
        if maxv.why.byte_length() != 0:
            return PreCheck(
                String("memcg"), String("unknown"), maxv.why, String("")
            )
        if maxv.unlimited:
            continue
        var curv = _read_mem_val(
            reader, dir + String("/memory.current"), False
        )
        if curv.why.byte_length() != 0:
            return PreCheck(
                String("memcg"), String("unknown"), curv.why, String("")
            )
        if curv.unlimited:
            return PreCheck(
                String("memcg"),
                String("unknown"),
                dir + String("/memory.current unreadable: absent"),
                String(""),
            )
        var headroom = UInt64(0)
        if maxv.value >= curv.value:
            headroom = maxv.value - curv.value
        if not constrained or headroom < best:
            best = headroom
            best_path = prefix.copy()
            constrained = True
    var disp = cgpath.copy()
    if disp == String(""):
        disp = String("/")
    if not constrained:
        return PreCheck(
            String("memcg"),
            String("pass"),
            String("memcg headroom unlimited (") + disp + String(")"),
            String(""),
        )
    if best < want:
        return PreCheck(
            String("memcg"),
            String("unknown"),
            String("memcg headroom ")
            + format_u64(best)
            + String(" bytes below the objects' ")
            + String(need)
            + String(" bytes (at ")
            + best_path
            + String(")"),
            String("memcg-headroom"),
        )
    return PreCheck(
        String("memcg"),
        String("pass"),
        String("memcg headroom ")
        + format_u64(best)
        + String(" bytes covers the objects' ")
        + String(need)
        + String(" bytes (at ")
        + best_path
        + String(")"),
        String(""),
    )


def check_unprivileged_bpf(reader: EvidenceReader) -> PreCheck:
    """Report the unprivileged-BPF sysctl; never fails."""
    var st = file_state(reader, String(P_UNPRIV_BPF))
    if st == EVIDENCE_ABSENT:
        return PreCheck(
            String("unprivileged-bpf"),
            String("unknown"),
            String("unprivileged_bpf_disabled unreadable: absent"),
            String(""),
        )
    if st == EVIDENCE_DENIED:
        return PreCheck(
            String("unprivileged-bpf"),
            String("unknown"),
            String("unprivileged_bpf_disabled unreadable: denied"),
            String(""),
        )
    var raw = List[UInt8]()
    try:
        raw = read_evidence(reader, String(P_UNPRIV_BPF), _UNPRIV_CAP)
    except e:
        return PreCheck(
            String("unprivileged-bpf"),
            String("unknown"),
            String("unprivileged_bpf_disabled unreadable: ") + e.message,
            String(""),
        )
    var tok = _strip_token(raw^)
    if len(tok) != 1:
        return PreCheck(
            String("unprivileged-bpf"),
            String("unknown"),
            String("unprivileged_bpf_disabled malformed"),
            String(""),
        )
    var v = tok[0]
    if v != UInt8(0x30) and v != UInt8(0x31) and v != UInt8(0x32):
        return PreCheck(
            String("unprivileged-bpf"),
            String("unknown"),
            String("unprivileged_bpf_disabled malformed"),
            String(""),
        )
    var one = List[UInt8]()
    one.append(v)
    return PreCheck(
        String("unprivileged-bpf"),
        String("pass"),
        String("unprivileged_bpf_disabled=") + bytes_to_text(one^),
        String(""),
    )
