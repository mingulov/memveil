"""Host identity and guest-technology evidence for the passive doctor.

``detect_environment`` gathers every profile-independent fact the
doctor needs: kernel release/arch and floor eligibility, the
guest-technology verdict, BTF/config states, and the
privilege-denied path list. Scanning is byte-level over capped reads.

The function is total: unreadable evidence degrades to explicit
unknown/conflict signals, never to an exception. Only structural
failures (a bad fixture header) raise, and those surface when the
reader is opened, before this module runs.

Guest-technology rules are conservative, and every verdict names its
sources in ``signals``:

- ``sev-guest`` and ``tdx-guest`` nodes both readable: unknown plus
  a conflict. The nodes contradict each other.
- One node readable: the matching cpu flag corroborates it
  (``sev_snp`` for snp, ``sev`` without ``sev_snp`` for sev-classic,
  ``tdx_guest`` for tdx). A flag token for the *other* technology
  contradicts the node and means unknown plus a conflict, as do
  readable flags that lack the node's own token. Unreadable flags
  mean unknown with an unavailable note.
- No nodes: readable flags mean ordinary, recorded explicitly as an
  absence-of-node inference; unreadable flags mean unknown. Stray
  technology tokens without any node do not contradict the
  absence inference: CPUID feature bits are leakable by the
  hypervisor, so flags alone never assert.
- Denied nodes or cpuinfo mean unknown, and the path lands in
  ``denied_paths`` so a privilege restriction reads differently
  from an absent kernel feature.
- A fixture-only user assertion breaks an unknown tie or agrees
  with the evidence verdict; when it contradicts the evidence the
  verdict is unknown plus a conflict. Live runs never assert.
- CPU vendor/model/family lines are never verdict sources. Only
  the three corroborating flag tokens are read, and only from
  ``flags`` lines.
"""

from memveil.model.common import MaybeString
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    EvidenceReader,
    bytes_to_text,
    file_state,
    read_evidence,
)


comptime P_CPUINFO = "/proc/cpuinfo"
comptime P_OS_RELEASE = "/etc/os-release"
comptime P_BTF = "/sys/kernel/btf/vmlinux"
comptime P_CONFIG_GZ = "/proc/config.gz"
comptime P_SEV_NODE = "/dev/sev-guest"
comptime P_TDX_NODE = "/dev/tdx_guest"
comptime P_BOOT_CONFIG_PREFIX = "/boot/config-"

comptime _CPUINFO_CAP = 1048576
comptime _OS_RELEASE_CAP = 65536
comptime _BTF_CAP = 33554432
comptime _TRIPLE_BOUND = 2147483647
comptime _OS_VALUE_KEEP = 64


@fieldwise_init
struct KernelTriple(ImplicitlyCopyable):
    """A parsed kernel release triple. ``ok`` is False when unparseable."""

    var ok: Bool
    var major: Int
    var minor: Int
    var patch: Int


@fieldwise_init
struct KernelInfo(Copyable):
    """Kernel identity plus the 7.0 eligibility floor check."""

    var release: String
    var arch: String
    var eligible_floor: Bool
    var floor_reason: String


@fieldwise_init
struct GuestInfo(Copyable):
    """Guest-technology verdict.

    ``tech`` is one of ``ordinary``, ``snp``, ``tdx``,
    ``sev-classic``, ``unknown``. ``signals`` names every evidence
    source behind the verdict (``info:``-prefixed entries are
    environment context, not verdict sources). ``asserted`` is True
    when a fixture-only user assertion contributed.
    ``conflict`` is ``""`` when nothing contradicts.
    """

    var tech: String
    var signals: List[String]
    var asserted: Bool
    var conflict: String


@fieldwise_init
struct EnvironmentEvidence(Copyable):
    """All profile-independent doctor evidence for one reader."""

    var kernel: KernelInfo
    var guest: GuestInfo
    var btf_state: Int
    var btf_bytes: Int
    var config_gz_state: Int
    var os_id: String
    var os_version: String
    var denied: List[String]


def parse_kernel_triple(release: String) -> KernelTriple:
    """Parse ``major[.minor[.patch]]`` from a release string.

    Leading digits are the major (required); an optional dotted
    minor and patch default to 0. Anything after the parsed triple
    (``-34-generic``, ``.0-...``) is ignored. No leading digits
    means ``ok`` is False. Components are bounded; overflow makes
    the release unparseable rather than wrapping.
    """
    var parts = List[Int]()
    var acc = 0
    var have_digit = False
    var bad = False
    for b in release.as_bytes():
        if b >= UInt8(0x30) and b <= UInt8(0x39):
            var digit = Int(b) - 0x30
            if acc > (_TRIPLE_BOUND - digit) // 10:
                bad = True
                break
            acc = acc * 10 + digit
            have_digit = True
        elif b == UInt8(0x2E) and len(parts) < 2:
            if not have_digit:
                bad = True
                break
            parts.append(acc)
            acc = 0
            have_digit = False
        else:
            break
    if bad or not have_digit:
        return KernelTriple(False, 0, 0, 0)
    parts.append(acc)
    var major = parts[0]
    var minor = 0
    var patch = 0
    if len(parts) > 1:
        minor = parts[1]
    if len(parts) > 2:
        patch = parts[2]
    return KernelTriple(True, major, minor, patch)


def _check_floor(release: String, arch: String) -> KernelInfo:
    """Check one release/arch pair against the 7.0 floor."""
    var triple = parse_kernel_triple(release)
    if not triple.ok:
        return KernelInfo(
            release,
            arch,
            False,
            "release " + release + " is unparseable; floor unknown",
        )
    if triple.major >= 7:
        return KernelInfo(
            release,
            arch,
            True,
            "release " + release + " meets the 7.0 floor",
        )
    return KernelInfo(
        release, arch, False, "release " + release + " is below the 7.0 floor"
    )


@fieldwise_init
struct _FlagHits(ImplicitlyCopyable):
    """Which corroborating tokens one cpuinfo scan found."""

    var sev: Bool
    var snp: Bool
    var tdx: Bool


def _scan_flags(view: Span[UInt8, ...]) -> _FlagHits:
    """Scan cpuinfo ``flags`` lines for sev/sev_snp/tdx_guest.

    Only lines starting with ``flags`` followed by blanks and a
    colon are scanned; tokens split on blanks. Matches are whole
    tokens only: ``sev`` never matches inside ``sev_snp``. One
    pass serves all three tokens.
    """
    var label = String("flags")
    var sev_t = String("sev")
    var snp_t = String("sev_snp")
    var tdx_t = String("tdx_guest")
    var want = label.as_bytes()
    var b_sev = sev_t.as_bytes()
    var b_snp = snp_t.as_bytes()
    var b_tdx = tdx_t.as_bytes()
    var hit_sev = False
    var hit_snp = False
    var hit_tdx = False
    var i = 0
    var n = len(view)
    while i < n:
        var line_end = i
        while line_end < n and view[line_end] != UInt8(0x0A):
            line_end += 1
        var is_flags = line_end - i >= len(want)
        if is_flags:
            for k in range(len(want)):
                if view[i + k] != want[k]:
                    is_flags = False
                    break
        if is_flags:
            var j = i + len(want)
            while j < line_end and (
                view[j] == UInt8(0x20) or view[j] == UInt8(0x09)
            ):
                j += 1
            if j < line_end and view[j] == UInt8(0x3A):
                var t = j + 1
                while t <= line_end:
                    var tend = t
                    while tend < line_end and (
                        view[tend] != UInt8(0x20)
                        and view[tend] != UInt8(0x09)
                    ):
                        tend += 1
                    if tend > t:
                        var tlen = tend - t
                        if tlen == len(b_sev):
                            var same = True
                            for k in range(tlen):
                                if view[t + k] != b_sev[k]:
                                    same = False
                                    break
                            if same:
                                hit_sev = True
                        if tlen == len(b_snp):
                            var same = True
                            for k in range(tlen):
                                if view[t + k] != b_snp[k]:
                                    same = False
                                    break
                            if same:
                                hit_snp = True
                        if tlen == len(b_tdx):
                            var same = True
                            for k in range(tlen):
                                if view[t + k] != b_tdx[k]:
                                    same = False
                                    break
                            if same:
                                hit_tdx = True
                    t = tend + 1
        i = line_end + 1
    return _FlagHits(hit_sev, hit_snp, hit_tdx)


@fieldwise_init
struct _OsVals(ImplicitlyCopyable):
    """ID and VERSION_ID read from os-release bytes."""

    var os_id: String
    var os_version: String


def _line_value(
    view: Span[UInt8, ...], start: Int, end: Int, key: String
) -> MaybeString:
    """Read ``key=value`` from one os-release line span.

    Returns ``has`` False unless the span starts with ``key=``.
    One pair of surrounding double quotes is stripped; values
    keep raw bytes up to 64 of them; decoding is lossy downstream.
    """
    var out = MaybeString()
    var kbytes = key.as_bytes()
    if end - start <= len(kbytes):
        return out^
    for k in range(len(kbytes)):
        if view[start + k] != kbytes[k]:
            return out^
    if view[start + len(kbytes)] != UInt8(0x3D):
        return out^
    var vstart = start + len(kbytes) + 1
    var vend = end
    if (
        vend - vstart >= 2
        and view[vstart] == UInt8(0x22)
        and view[vend - 1] == UInt8(0x22)
    ):
        vstart += 1
        vend -= 1
    if vend - vstart > _OS_VALUE_KEEP:
        vend = vstart + _OS_VALUE_KEEP
    if vend > vstart and view[vend - 1] == UInt8(0x0D):
        vend -= 1
    var raw = List[UInt8]()
    for p in range(vstart, vend):
        raw.append(view[p])
    out.has = True
    out.value = bytes_to_text(raw^)
    return out^


def _os_release_values(view: Span[UInt8, ...]) -> _OsVals:
    """Read ID and VERSION_ID from os-release bytes.

    The first ``ID=`` and ``VERSION_ID=`` lines win. Missing keys
    read as "".
    """
    var os_id = String("")
    var os_version = String("")
    var got_id = False
    var got_ver = False
    var i = 0
    var n = len(view)
    while i < n:
        var line_end = i
        while line_end < n and view[line_end] != UInt8(0x0A):
            line_end += 1
        if not got_id:
            var id_hit = _line_value(view, i, line_end, String("ID"))
            if id_hit.has:
                os_id = id_hit.value
                got_id = True
        if not got_ver:
            var ver_hit = _line_value(
                view, i, line_end, String("VERSION_ID")
            )
            if ver_hit.has:
                os_version = ver_hit.value
                got_ver = True
        i = line_end + 1
    return _OsVals(os_id, os_version)


def _release_path_safe(release: String) -> Bool:
    """True when the release is safe to interpolate into a path.

    Live uname releases always pass. A fixture release holding
    ``/`` or ``..`` would escape the fixture root, so the boot
    config probe is skipped for it instead.
    """
    var prev_dot = False
    for b in release.as_bytes():
        if b == UInt8(0x2F):
            return False
        if b == UInt8(0x2E) and prev_dot:
            return False
        prev_dot = b == UInt8(0x2E)
    return True


def _detect_guest(reader: EvidenceReader) -> GuestInfo:
    """Decide the guest technology from nodes, flags, and assertion.

    Never raises: every unreadable input becomes an explicit
    unknown or conflict outcome. Denied paths are re-derived from
    the verdict signals by the caller.
    """
    var signals = List[String]()
    var asserted = reader.asserted_guest_tech
    var sev = file_state(reader, P_SEV_NODE)
    var tdx = file_state(reader, P_TDX_NODE)
    if sev == EVIDENCE_OK:
        signals.append(String("sev-node:present"))
    elif sev == EVIDENCE_DENIED:
        signals.append(String("sev-node:denied"))
    else:
        signals.append(String("sev-node:absent"))
    if tdx == EVIDENCE_OK:
        signals.append(String("tdx-node:present"))
    elif tdx == EVIDENCE_DENIED:
        signals.append(String("tdx-node:denied"))
    else:
        signals.append(String("tdx-node:absent"))
    var cpu = file_state(reader, P_CPUINFO)
    var flags_ok = False
    var has_sev = False
    var has_snp = False
    var has_tdx = False
    if cpu == EVIDENCE_DENIED:
        signals.append(String("cpu-flags:denied"))
    elif cpu == EVIDENCE_ABSENT:
        signals.append(String("cpu-flags:absent"))
    else:
        try:
            var data = read_evidence(reader, P_CPUINFO, _CPUINFO_CAP)
            var hits = _scan_flags(Span(data))
            has_sev = hits.sev
            has_snp = hits.snp
            has_tdx = hits.tdx
            flags_ok = True
            var summary = String("cpu-flags:ok:")
            var first = True
            if has_sev:
                summary += "sev"
                first = False
            if has_snp:
                if not first:
                    summary += "+"
                summary += "sev_snp"
                first = False
            if has_tdx:
                if not first:
                    summary += "+"
                summary += "tdx_guest"
                first = False
            if first:
                summary += "none"
            signals.append(summary)
        except:
            signals.append(String("cpu-flags:read-error"))
    var tech = String("unknown")
    var conflict = String("")
    if sev == EVIDENCE_OK and tdx == EVIDENCE_OK:
        conflict = "sev-guest and tdx-guest nodes both present"
    elif sev == EVIDENCE_DENIED or tdx == EVIDENCE_DENIED:
        conflict = ""
    elif sev == EVIDENCE_OK:
        if not flags_ok:
            conflict = ""
        elif has_tdx:
            conflict = "sev-guest node present with tdx_guest cpu flag"
        elif has_snp:
            tech = "snp"
        elif has_sev:
            tech = "sev-classic"
        else:
            conflict = "sev-guest node present but cpu flags lack sev"
    elif tdx == EVIDENCE_OK:
        if not flags_ok:
            conflict = ""
        elif has_sev or has_snp:
            conflict = "tdx-guest node present with sev cpu flags"
        elif has_tdx:
            tech = "tdx"
        else:
            conflict = (
                "tdx-guest node present but cpu flags lack tdx_guest"
            )
    else:
        if flags_ok:
            tech = "ordinary"
            signals.append(String("ordinary:absent-nodes-inference"))
    var used_assertion = False
    if asserted.byte_length() != 0:
        signals.append("asserted:" + asserted)
        if conflict == "" and (tech == "unknown" or tech == asserted):
            tech = asserted
            used_assertion = True
        elif conflict == "":
            conflict = "evidence says " + tech + ", asserted " + asserted
            tech = "unknown"
            used_assertion = True
        else:
            conflict = conflict + "; asserted " + asserted + " unresolved"
            used_assertion = True
    return GuestInfo(tech, signals^, used_assertion, conflict)


def detect_environment(reader: EvidenceReader) -> EnvironmentEvidence:
    """Gather all profile-independent doctor evidence. Never raises."""
    var kernel = _check_floor(reader.release, reader.arch)
    var guest = _detect_guest(reader)
    var denied = List[String]()
    for i in range(len(guest.signals)):
        var s = guest.signals[i]
        if (
            s == "sev-node:denied"
            or s == "tdx-node:denied"
            or s == "cpu-flags:denied"
        ):
            if s == "sev-node:denied":
                denied.append(P_SEV_NODE)
            elif s == "tdx-node:denied":
                denied.append(P_TDX_NODE)
            else:
                denied.append(P_CPUINFO)
    var info = List[String]()
    var btf = file_state(reader, P_BTF)
    var btf_bytes = 0
    if btf == EVIDENCE_OK:
        try:
            var data = read_evidence(reader, P_BTF, _BTF_CAP)
            btf_bytes = len(data)
            info.append("info:btf:present:" + String(btf_bytes) + "B")
        except:
            info.append(String("info:btf:read-error"))
    elif btf == EVIDENCE_DENIED:
        info.append(String("info:btf:denied"))
        denied.append(P_BTF)
    else:
        info.append(String("info:btf:absent"))
    var cfg = file_state(reader, P_CONFIG_GZ)
    if cfg == EVIDENCE_OK:
        info.append(String("info:config-gz:present"))
    elif cfg == EVIDENCE_DENIED:
        info.append(String("info:config-gz:denied"))
        denied.append(P_CONFIG_GZ)
    else:
        info.append(String("info:config-gz:absent"))
    var os_id = String("")
    var os_version = String("")
    var osst = file_state(reader, P_OS_RELEASE)
    if osst == EVIDENCE_OK:
        try:
            var osdata = read_evidence(reader, P_OS_RELEASE, _OS_RELEASE_CAP)
            var vals = _os_release_values(Span(osdata))
            os_id = vals.os_id
            os_version = vals.os_version
            info.append("info:os:" + os_id + ":" + os_version)
        except:
            info.append(String("info:os:read-error"))
    elif osst == EVIDENCE_DENIED:
        info.append(String("info:os:denied"))
        denied.append(P_OS_RELEASE)
    else:
        info.append(String("info:os:absent"))
    if _release_path_safe(reader.release):
        var boot = P_BOOT_CONFIG_PREFIX + reader.release
        var bst = file_state(reader, boot)
        if bst == EVIDENCE_OK:
            info.append(String("info:boot-config:present"))
        elif bst == EVIDENCE_DENIED:
            info.append(String("info:boot-config:denied"))
            denied.append(boot)
        else:
            info.append(String("info:boot-config:absent"))
    else:
        info.append(String("info:boot-config:skipped-unsafe-release"))
    var merged = List[String]()
    for i in range(len(guest.signals)):
        merged.append(guest.signals[i])
    for i in range(len(info)):
        merged.append(info[i])
    guest.signals = merged^
    return EnvironmentEvidence(
        kernel^, guest^, btf, btf_bytes, cfg, os_id, os_version, denied^
    )
