# SPDX-License-Identifier: GPL-3.0-or-later

"""memveil record: admitted attempt capture, optional channels.

``run_record`` implements ``record --duration SEC --max-events-bytes
N --output DIR [--object PATH] [--bridge PATH] [--profile ID]
[--capability IDS] [--lc-object PATH] [--cp-object PATH]`` against
the live host. ``run_record_with`` is the same flow against an
explicit evidence root and profiles directory, so tests drive
fixtures through the identical code path. ``decide_record`` is the
testable admission decision (profile scan, capability selection,
object statics, hook layout, narrow binding) without clocks or BPF.

Exit codes: 4 = finalized (NORMAL including zero-event runs,
signal stops, and known-loss runs); 3 = cannot start
(diagnostic, no residual directory); 2 = usage (fixable via
argv); 1 = error or unfinalizable. Only a broken standard
error raises.
"""

from std.ffi import external_call
from std.os import getenv

from memveil.capture.collector import (
    EXIT_ERROR,
    EXIT_INVALID,
    EXIT_REFUSAL,
    Collector,
    CollectorConfig,
    RunResult,
    WriterSource,
)
from memveil.capture.kernel import LmbKernel
from memveil.capture.live import LiveWriter
from memveil.cli.doctor import resolve_profiles_dir
from memveil.cli.report import (
    EXIT_OK,
    CliError,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.model.session import EvidenceItem
from memveil.model.validate import check_opaque_id
from memveil.platform.stdout import write_stdout
from memveil.platform.btf import read_btf_maps, read_btf_maps_ring
from memveil.platform.clock import (
    MonoClock,
    check_timens_live,
)
from memveil.platform.evidence import (
    KernelInfo,
    detect_environment,
)
from memveil.platform.hash import sha256_hex
from memveil.platform.narrow import (
    MAX_NARROW_BTF_BYTES,
    MAX_NARROW_FORMAT_BYTES,
    MAX_NARROW_IMAGE_BYTES,
    MAX_NARROW_OBJECT_BYTES,
    MAX_NARROW_RING_BYTES,
    LiveValue,
    NarrowLive,
    check_narrow,
    check_narrow_extra,
    check_trace_layout,
    parse_narrow_note,
    read_live_bid,
    read_live_bytes,
    read_live_config,
    verify_object,
    verify_object_program,
)
from memveil.platform.profiles import (
    Profile,
    ProfileHook,
    load_profiles,
    parse_profile_bytes,
    select_attempt_hook,
    select_profile,
    tracing_gap,
    verify_qualification_receipt,
)
from memveil.platform.reader import (
    EvidenceReader,
    _geteuid_live,
    open_evidence_reader,
    read_host_file,
    readlink_self,
)
from memveil.platform.runtime import (
    discover_bridge,
    discover_object,
    is_privileged,
    live_uids,
)
from memveil.platform.signal import LiveSignalSource

comptime DEFAULT_DURATION_S = UInt64(60)
comptime DEFAULT_MAX_EVENTS_BYTES = 1073741824
comptime MIN_RECORD_BYTES = 131072
comptime MAX_RECORD_BYTES = 4294967296
comptime MAX_PROFILE_DOC_BYTES = 1048576
comptime _ZLIB = "libz.so.1"
comptime _RING_MAP = "mv_attempts"
comptime _PROGRAM = "mv_swiotlb_attempt"
comptime _ATTEMPT_CAP = "attempt-trace"
comptime _LIFECYCLE_CAP = "mapping-lifecycle"
comptime _COPY_CAP = "copy-actual"
comptime _CONVERT_CAP = "conversion-observe"
comptime _RING_LC_MAP = "mv_lifecycle"
comptime _RING_CP_MAP = "mv_copies"


struct RecordOptions:
    """Parsed record arguments."""

    var duration_s: UInt64
    var max_events_bytes: Int
    var output: String
    var object: String
    var bridge: String
    var has_bridge: Bool
    var profile: String
    var has_profile: Bool
    var profiles_dir: String
    var has_profiles_dir: Bool
    var lc_object: String
    var cp_object: String
    var capabilities: String

    def __init__(out self):
        self.duration_s = DEFAULT_DURATION_S
        self.max_events_bytes = DEFAULT_MAX_EVENTS_BYTES
        self.output = String("")
        self.object = String("")
        self.bridge = String("")
        self.has_bridge = False
        self.profile = String("")
        self.has_profile = False
        self.profiles_dir = String("")
        self.has_profiles_dir = False
        self.lc_object = String("")
        self.cp_object = String("")
        self.capabilities = String("")


def record_usage() -> String:
    """Usage text for the record verb."""
    return (
        "usage: memveil record --output DIR [--object PATH]\n"
        "       [--duration SEC] [--max-events-bytes N]\n"
        "       [--bridge PATH] [--profile ID|PATH]\n"
        "       [--profiles-dir DIR] [--capability IDS]\n"
        "       [--lc-object PATH] [--cp-object PATH]\n"
        "\n"
        "Capture swiotlb bounce attempts into DIR. SEC defaults\n"
        "to 60; N defaults to 1073741824 (1 GiB) and must lie\n"
        "in 131072..4294967296. Without --bridge, the native\n"
        "bridge is discovered: LMB_NATIVE_LIB when unprivileged,\n"
        "then beside the executable, then the system path.\n"
        "Without --object, --lc-object, or --cp-object, each\n"
        "BPF object is discovered beside the executable or\n"
        "under the system directory, else the run refuses.\n"
        "Without --profile, the first validated profile passing\n"
        "full identity binding wins, else the first covering\n"
        "profile runs\n"
        "partial; an explicit --profile that fails binding\n"
        "refuses. Diagnostics go to stderr.\n"
        "\n"
        "--capability selects extra channels as a comma-separated\n"
        "list without spaces (default: attempt-trace, which is\n"
        "always required). mapping-lifecycle uses --lc-object\n"
        "and copy-actual uses --cp-object when given, else the\n"
        "discovered object for that channel; the winning profile\n"
        "must declare each requested capability supported and\n"
        "bind the matching object bytes, else the run refuses\n"
        "naming the capability. Extra channels never run\n"
        "partial: without full narrow binding the run refuses.\n"
        "\n"
        "Exit 4 for a finalized capture (including zero-event\n"
        "and signal stops), 3 when the run cannot start, 2 on\n"
        "usage errors, 1 on error or unfinalizable output.\n"
    )


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def _parse_decimal_u64(text: String) raises CliError -> UInt64:
    """Strict decimal: no leading zeros, 1..2^64-1."""
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 20:
        raise CliError("bad decimal: " + text)
    if raw[0] < UInt8(0x31) or raw[0] > UInt8(0x39):
        raise CliError("bad decimal: " + text)
    var v = UInt64(0)
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise CliError("bad decimal: " + text)
        var d = UInt64(Int(b) - 0x30)
        if v > (UInt64(0xFFFFFFFFFFFFFFFF) - d) // UInt64(10):
            raise CliError("bad decimal: " + text)
        v = v * UInt64(10) + d
    return v


def parse_record_args(args: List[String]) raises CliError -> RecordOptions:
    """Parse record arguments without the leading verb."""
    var opts = RecordOptions()
    var i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--duration":
            if i + 1 >= len(args):
                raise CliError("--duration needs a value")
            opts.duration_s = _parse_decimal_u64(args[i + 1])
            i += 2
        elif tok == "--max-events-bytes":
            if i + 1 >= len(args):
                raise CliError("--max-events-bytes needs a value")
            var v = _parse_decimal_u64(args[i + 1])
            if v > UInt64(0x7FFFFFFFFFFFFFFF):
                raise CliError("--max-events-bytes too large")
            opts.max_events_bytes = Int(v)
            i += 2
        elif tok == "--output":
            if i + 1 >= len(args):
                raise CliError("--output needs a value")
            if args[i + 1] == "":
                raise CliError("--output needs a value")
            opts.output = args[i + 1]
            i += 2
        elif tok == "--object":
            if i + 1 >= len(args):
                raise CliError("--object needs a value")
            if args[i + 1] == "":
                raise CliError("--object needs a value")
            opts.object = args[i + 1]
            i += 2
        elif tok == "--bridge":
            if i + 1 >= len(args):
                raise CliError("--bridge needs a value")
            if args[i + 1] == "":
                raise CliError("--bridge needs a value")
            opts.bridge = args[i + 1]
            opts.has_bridge = True
            i += 2
        elif tok == "--profile":
            if i + 1 >= len(args):
                raise CliError("--profile needs a value")
            if args[i + 1] == "":
                raise CliError("--profile needs a value")
            opts.profile = args[i + 1]
            opts.has_profile = True
            i += 2
        elif tok == "--profiles-dir":
            if i + 1 >= len(args):
                raise CliError("--profiles-dir needs a value")
            if args[i + 1] == "":
                raise CliError("--profiles-dir needs a value")
            opts.profiles_dir = args[i + 1]
            opts.has_profiles_dir = True
            i += 2
        elif tok == "--lc-object":
            if i + 1 >= len(args):
                raise CliError("--lc-object needs a value")
            if args[i + 1] == "":
                raise CliError("--lc-object needs a value")
            opts.lc_object = args[i + 1]
            i += 2
        elif tok == "--cp-object":
            if i + 1 >= len(args):
                raise CliError("--cp-object needs a value")
            if args[i + 1] == "":
                raise CliError("--cp-object needs a value")
            opts.cp_object = args[i + 1]
            i += 2
        elif tok == "--capability":
            if i + 1 >= len(args):
                raise CliError("--capability needs a value")
            if args[i + 1] == "":
                raise CliError("--capability needs a value")
            opts.capabilities = args[i + 1]
            i += 2
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            raise CliError("unexpected argument: " + tok)
    if opts.output == "":
        raise CliError("missing --output")
    return opts^


struct ScanDecision(Copyable):
    """One admission decision: mode, hook, identity, bytes.

    ``ok`` False carries an exit-3 ``refusal``; otherwise
    ``kind`` is validated, local-auto, candidate, or partial, ``hook``
    is the selected tracepoint hook with a verified live
    layout, and ``elf`` is the verified object bytes (read
    once, hashed and handed to the session unchanged).
    Bound decisions also carry the measured narrow
    identities (config/src, btf, format, image, image
    build-id); partial decisions leave them empty so the
    capture marks each one unavailable. ``selected_caps``
    names the requested capabilities in order; a selected
    extra channel carries its verified object bytes, hash,
    and bound ring size, and never runs partial.
    """

    var ok: Bool
    var refusal: String
    var kind: String
    var profile: Profile
    var hook: ProfileHook
    var reason: String
    var object_sha: String
    var ring_bytes: Int
    var elf: List[UInt8]
    var tp_system: String
    var tp_event: String
    var measured_config: LiveValue
    var measured_config_src: String
    var measured_btf: LiveValue
    var measured_format: LiveValue
    var measured_image: LiveValue
    var measured_image_bid: LiveValue
    var selected_caps: String
    var has_lifecycle: Bool
    var has_copy: Bool
    var lc_elf: List[UInt8]
    var cp_elf: List[UInt8]
    var lc_ring_bytes: Int
    var cp_ring_bytes: Int
    var lc_object_sha: String
    var cp_object_sha: String

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.kind = String("")
        self.profile = Profile()
        self.hook = ProfileHook()
        self.reason = String("")
        self.object_sha = String("")
        self.ring_bytes = 0
        self.elf = List[UInt8]()
        self.tp_system = String("")
        self.tp_event = String("")
        self.measured_config = LiveValue()
        self.measured_config_src = String("")
        self.measured_btf = LiveValue()
        self.measured_format = LiveValue()
        self.measured_image = LiveValue()
        self.measured_image_bid = LiveValue()
        self.selected_caps = String("")
        self.has_lifecycle = False
        self.has_copy = False
        self.lc_elf = List[UInt8]()
        self.cp_elf = List[UInt8]()
        self.lc_ring_bytes = 0
        self.cp_ring_bytes = 0
        self.lc_object_sha = String("")
        self.cp_object_sha = String("")


def _refuse_scan(reason: String) -> ScanDecision:
    var out = ScanDecision()
    out.ok = False
    out.refusal = reason
    return out^


struct CapsOut(Copyable):
    """Parsed capability request: caps in order, or err."""

    var ok: Bool
    var caps: List[String]
    var err: String

    def __init__(out self):
        self.ok = False
        self.caps = List[String]()
        self.err = String("")


def _split_caps(text: String) -> List[String]:
    """Split a comma capability list (strict, no spaces)."""
    var out = List[String]()
    var raw = text.as_bytes()
    var cur = List[UInt8]()
    for i in range(len(raw)):
        if raw[i] == UInt8(0x2C):
            try:
                out.append(String(from_utf8=Span(cur)))
            except:
                out.append(String(""))
            cur = List[UInt8]()
        else:
            cur.append(raw[i])
    try:
        out.append(String(from_utf8=Span(cur)))
    except:
        out.append(String(""))
    return out^


def parse_requested_caps(want: String) -> CapsOut:
    """Parse requested capabilities in order, deduplicated.

    Empty means attempt-trace alone. Unknown ids, empty
    items, and requests without attempt-trace refuse: the
    attempt channel is the mandatory base channel.
    """
    var out = CapsOut()
    var items = List[String]()
    if want == String(""):
        items.append(String(_ATTEMPT_CAP))
    else:
        items = _split_caps(want)
    for i in range(len(items)):
        var item = items[i].copy()
        if item == String(""):
            out.err = String("bad capability list")
            return out^
        if (
            item != String(_ATTEMPT_CAP)
            and item != String(_LIFECYCLE_CAP)
            and item != String(_COPY_CAP)
            and item != String(_CONVERT_CAP)
        ):
            out.err = String("unknown capability: ") + item
            return out^
        var seen = False
        for j in range(len(out.caps)):
            if out.caps[j] == item:
                seen = True
                break
        if not seen:
            out.caps.append(item.copy())
    var has_attempt = False
    for i in range(len(out.caps)):
        if out.caps[i] == String(_ATTEMPT_CAP):
            has_attempt = True
            break
    if not has_attempt:
        out.err = String("attempt-trace is required")
        return out^
    out.ok = True
    return out^


def _cap_selectable(doc: Profile, cap: String) -> Bool:
    """True when the doc admits the capability for capture.

    Both supported and candidate declarations select;
    the decision kind already tells them apart. Only
    unsupported or missing declarations refuse.
    """
    for i in range(len(doc.caps)):
        if doc.caps[i].id == cap:
            return (
                doc.caps[i].status == String("supported")
                or doc.caps[i].status == String("candidate")
            )
    return False


def _cap_unknown_hook(doc: Profile, cap: String) -> String:
    """First hook a requested cap names that the doc lacks."""
    for i in range(len(doc.caps)):
        if doc.caps[i].id == cap:
            for j in range(len(doc.caps[i].hooks)):
                var want = doc.caps[i].hooks[j].copy()
                var found = False
                for k in range(len(doc.hooks)):
                    if doc.hooks[k].name == want:
                        found = True
                        break
                if not found:
                    return want.copy()
            return String("")
    return String("")


struct _ProgWant(Copyable):
    var name: String
    var section: String

    def __init__(out self, name: String, section: String):
        self.name = name
        self.section = section


def _lc_progs() -> List[_ProgWant]:
    """Frozen lifecycle programs; mirrors the attach specs."""
    var out = List[_ProgWant]()
    out.append(_ProgWant(String("mv_map_result"), String("fexit/")))
    out.append(_ProgWant(String("mv_unmap"), String("fentry/")))
    return out^


def _cp_progs() -> List[_ProgWant]:
    """Frozen copy programs; mirrors the attach specs."""
    var out = List[_ProgWant]()
    out.append(_ProgWant(String("mv_sync_device"), String("fentry/")))
    out.append(_ProgWant(String("mv_sync_cpu"), String("fentry/")))
    out.append(_ProgWant(String("mv_bounce"), String("fentry/")))
    return out^


struct _ExtraOut(Copyable):
    var ok: Bool
    var refusal: String
    var elf: List[UInt8]
    var sha: String
    var ring: Int

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.elf = List[UInt8]()
        self.sha = String("")
        self.ring = 0


def _verify_extra_object(
    path: String,
    word: String,
    ring_var: String,
    ring_word: String,
    wants: List[_ProgWant],
) -> _ExtraOut:
    """Static admission for one extra channel object.

    Reads the object once, verifies every frozen tracing
    program in its section kind, and reads the channel
    ring size from BTF. Refusals name the channel word.
    """
    var out = _ExtraOut()
    var elf: List[UInt8]
    try:
        elf = read_host_file(
            path,
            word + String(" object"),
            MAX_NARROW_OBJECT_BYTES,
        )
    except:
        out.refusal = word + String(" object unreadable")
        return out^
    for i in range(len(wants)):
        var chk = verify_object_program(
            Span(elf), wants[i].name, wants[i].section
        )
        if not chk.ok:
            out.refusal = (
                word + String(" object refused: ") + chk.message
            )
            return out^
    var maps = read_btf_maps_ring(Span(elf), ring_var, ring_word)
    if not maps.ok:
        out.refusal = (
            word + String(" object refused: ") + maps.message
        )
        return out^
    if maps.ring_bytes > MAX_NARROW_RING_BYTES:
        out.refusal = word + String(" object ring too large")
        return out^
    out.ok = True
    out.elf = elf.copy()
    out.sha = sha256_hex(Span(elf))
    out.ring = maps.ring_bytes
    return out^


def _split_site(name: String, mut sys: String, mut evt: String) -> Bool:
    """Split a `system:event` hook name into C identifiers."""
    var raw = name.as_bytes()
    var cut = -1
    for i in range(len(raw)):
        if raw[i] == UInt8(0x3A):
            if cut >= 0:
                return False
            cut = i
    if cut <= 0 or cut + 1 >= len(raw):
        return False
    for i in range(len(raw)):
        if i == cut:
            continue
        var b = raw[i]
        var ok = (
            (b >= UInt8(0x41) and b <= UInt8(0x5A))
            or (b >= UInt8(0x61) and b <= UInt8(0x7A))
            or (b >= UInt8(0x30) and b <= UInt8(0x39))
            or b == UInt8(0x5F)
        )
        if not ok:
            return False
    var sbytes = List[UInt8]()
    for i in range(cut):
        sbytes.append(raw[i])
    var ebytes = List[UInt8]()
    for i in range(cut + 1, len(raw)):
        ebytes.append(raw[i])
    try:
        sys = String(from_utf8=Span(sbytes))
    except:
        return False
    try:
        evt = String(from_utf8=Span(ebytes))
    except:
        return False
    return True


def _join(root: String, path: String) -> String:
    if root == String("/") or root == String(""):
        return path
    return root + path


struct _BindingOut(ImplicitlyCopyable):
    var ok: Bool
    var reason: String
    var config: LiveValue
    var config_src: String
    var btf: LiveValue
    var format: LiveValue
    var image: LiveValue
    var image_bid: LiveValue

    def __init__(out self):
        self.ok = False
        self.reason = String("")
        self.config = LiveValue()
        self.config_src = String("")
        self.btf = LiveValue()
        self.format = LiveValue()
        self.image = LiveValue()
        self.image_bid = LiveValue()


def _check_binding(
    root: String,
    release: String,
    doc: Profile,
    hook: ProfileHook,
    object_sha: String,
    ring_bytes: Int,
    format_bytes: Span[UInt8, _],
    lc_sha: String,
    lc_ring: Int,
    cp_sha: String,
    cp_ring: Int,
    want_lc: Bool,
    want_cp: Bool,
) -> _BindingOut:
    """Full narrow binding of one doc against live identity.

    Release must equal the recorded revision, the note
    must parse, every live source must match, requested
    extra channels must bind their object bytes and ring
    sizes, and the live format bytes must equal the
    embedded text.
    """
    var out = _BindingOut()
    if release != doc.identity.source.revision:
        out.reason = String("release != revision")
        return out^
    var parsed = parse_narrow_note(doc.identity.source.note)
    if not parsed.ok:
        out.reason = parsed.message.copy()
        return out^
    var bind = parsed.bindings
    var live = NarrowLive()
    var cfg = read_live_config(root, release, String(_ZLIB))
    live.config = cfg.value
    live.config_src = cfg.src
    live.btf = read_live_bytes(
        root,
        String("/sys/kernel/btf/vmlinux"),
        String("btf"),
        MAX_NARROW_BTF_BYTES,
    )
    live.format.state = String("value")
    live.format.value = sha256_hex(format_bytes)
    live.object.state = String("value")
    live.object.value = object_sha
    live.image = read_live_bytes(
        root,
        String("/boot/vmlinuz-") + release,
        String("image"),
        MAX_NARROW_IMAGE_BYTES,
    )
    live.image_bid = read_live_bid(root)
    live.ring.state = String("value")
    live.ring.value = String(ring_bytes)
    out.config = live.config.copy()
    out.config_src = live.config_src.copy()
    out.btf = live.btf.copy()
    out.format = live.format.copy()
    out.image = live.image.copy()
    out.image_bid = live.image_bid.copy()
    var verdict = check_narrow(bind, live)
    if verdict.state != String("bound"):
        out.reason = verdict.state + String(" ") + verdict.key
        return out^
    live.lc_object.state = String("value")
    live.lc_object.value = lc_sha.copy()
    live.lc_ring.state = String("value")
    live.lc_ring.value = String(lc_ring)
    live.cp_object.state = String("value")
    live.cp_object.value = cp_sha.copy()
    live.cp_ring.state = String("value")
    live.cp_ring.value = String(cp_ring)
    var extra = check_narrow_extra(bind, live, want_lc, want_cp)
    if extra.state != String("bound"):
        out.reason = extra.state + String(" ") + extra.key
        return out^
    if not hook.format_has:
        out.reason = String("uncheckable format_text")
        return out^
    var want = hook.format_text.as_bytes()
    if len(want) != len(format_bytes):
        out.reason = String("mismatch format_text")
        return out^
    for i in range(len(want)):
        if want[i] != format_bytes[i]:
            out.reason = String("mismatch format_text")
            return out^
    out.ok = True
    out.reason = String("")
    return out^


def _covers(kernel: KernelInfo, doc: Profile) -> Bool:
    var one = List[Profile]()
    one.append(doc.copy())
    return select_profile(kernel, one^).has_profile


def _receipt_covers(
    doc: Profile,
    kernel: KernelInfo,
    want: List[String],
    pdir: String,
    bridge_sha: String,
    mut bridge_mismatch: Bool,
) -> Bool:
    """True when a verifying receipt covers every wanted cap.

    The receipt at <pdir>/receipts/<id>.json must verify
    against the doc, the live kernel, and the resolved
    bridge hash, and qualify each requested capability.
    An empty pdir, a missing file, or any verify failure
    yields False: scan falls through to the next
    candidate. ``bridge_mismatch`` reports True when the
    receipt was otherwise valid but named another
    bridge, so the fallback reason can name it. Never
    raises.
    """
    bridge_mismatch = False
    if pdir == String(""):
        return False
    var path = (
        pdir
        + String("/receipts/")
        + doc.profile_id
        + String(".json")
    )
    var raw = List[UInt8]()
    try:
        raw = read_host_file(
            path, String("receipt"), MAX_PROFILE_DOC_BYTES
        )
    except:
        return False
    var v = verify_qualification_receipt(
        Span(raw), doc, kernel, bridge_sha
    )
    if not v.ok:
        bridge_mismatch = v.bridge_mismatch
        return False
    for i in range(len(want)):
        var found = False
        for j in range(len(v.caps)):
            if v.caps[j] == want[i]:
                found = True
                break
        if not found:
            return False
    return True


def _read_format(
    root: String, hook: ProfileHook, mut raw: List[UInt8]
) -> String:
    """Read hook format bytes; "" when readable."""
    try:
        raw = read_host_file(
            _join(root, hook.format_path),
            String("format"),
            MAX_NARROW_FORMAT_BYTES,
        )
    except:
        return String("format unreadable")
    return String("")


def _admit_hook(
    root: String,
    doc: Profile,
    mut hook: ProfileHook,
    mut raw: List[UInt8],
    mut sys: String,
    mut evt: String,
) -> String:
    """Select, read, and verify one doc's hook; "" when admitted."""
    var sel = select_attempt_hook(doc)
    if not sel.ok:
        return sel.refusal.copy()
    hook = sel.hook.copy()
    var err = _read_format(root, hook.copy(), raw)
    if err != String(""):
        return err
    var layout = check_trace_layout(Span(raw))
    if not layout.ok:
        return String("layout: ") + layout.message
    if not _split_site(hook.name, sys, evt):
        return String("bad hook site")
    return String("")


def _selection_gap(doc: Profile, caps: List[String]) -> String:
    """First reason a doc cannot satisfy the request, else "".

    Every requested extra capability needs a supported
    or candidate declaration whose named hooks all
    exist in the doc; the message names the capability
    and the document. The attempt channel keeps its
    legacy hook selection and refusals below.
    """
    for i in range(len(caps)):
        if caps[i] == String(_ATTEMPT_CAP):
            continue
        if not _cap_selectable(doc, caps[i]):
            return (
                String("capability ")
                + caps[i]
                + String(" unsupported by ")
                + doc.profile_id
            )
        var missing = _cap_unknown_hook(doc, caps[i])
        if missing != String(""):
            return (
                String("capability ")
                + caps[i]
                + String(" names unknown hook ")
                + missing
            )
    return String("")


def decide_record(
    root: String,
    kernel: KernelInfo,
    profiles: List[Profile],
    explicit: String,
    has_explicit: Bool,
    object_path: String,
    lc_object: String,
    cp_object: String,
    want_caps: String,
    profiles_dir: String,
    bridge_sha: String,
) -> ScanDecision:
    """Decide admission: scan, object statics, hook, binding.

    Explicit mode resolves one doc (file first, then id)
    and enforces full binding when bindings exist. Scan
    mode tries each covering validated doc in order, then
    each covering reference doc whose receipt under
    <profiles_dir>/receipts/ verifies (against the doc,
    the live kernel, and ``bridge_sha``, the bare hex
    sha256 of the resolved bridge) and covers the
    requested capabilities ("\" disables receipts), and
    falls back to the first covering doc as partial. A
    receipt blocked only by the bridge falls through to
    partial with a reason naming the bridge mismatch,
    never local-auto. Static object failures refuse
    everywhere; identity failures fall through in scan
    mode only. Requested extra capabilities need a
    supported declaration, a resolvable object path, and
    full extended binding; they never fall back to
    partial.
    """
    var out = ScanDecision()
    var ask = parse_requested_caps(want_caps)
    if not ask.ok:
        return _refuse_scan(ask.err.copy())
    var want_lc = False
    var want_cp = False
    for i in range(len(ask.caps)):
        if ask.caps[i] == String(_LIFECYCLE_CAP):
            want_lc = True
        if ask.caps[i] == String(_COPY_CAP):
            want_cp = True
        if ask.caps[i] == String(_CONVERT_CAP):
            return _refuse_scan(
                String(
                    "capability conversion-observe has no record channel"
                )
            )
    var want_extra = want_lc or want_cp
    var selected = ask.caps[0].copy()
    for i in range(1, len(ask.caps)):
        selected = selected + String(",") + ask.caps[i]
    var candidates = List[Profile]()
    var want_explicit = has_explicit
    if want_explicit:
        var doc_bytes = List[UInt8]()
        var is_path: Bool
        try:
            doc_bytes = read_host_file(
                explicit, String("profile"), MAX_PROFILE_DOC_BYTES
            )
            is_path = True
        except:
            is_path = False
        if is_path:
            try:
                var doc = parse_profile_bytes(doc_bytes^)
                candidates.append(doc^)
            except e:
                return _refuse_scan(
                    String("cannot parse --profile: ") + String(e)
                )
        else:
            var found = False
            for i in range(len(profiles)):
                if profiles[i].profile_id == explicit:
                    candidates.append(profiles[i].copy())
                    found = True
                    break
            if not found:
                return _refuse_scan(
                    String("unknown --profile: ") + explicit
                )
        if not _covers(kernel, candidates[0]):
            return _refuse_scan(
                String("profile does not cover this kernel")
            )
    else:
        for i in range(len(profiles)):
            if _covers(kernel, profiles[i]):
                candidates.append(profiles[i].copy())
        if len(candidates) == 0:
            return _refuse_scan(String("no profile covers this kernel"))
    if want_lc and lc_object == String(""):
        return _refuse_scan(
            String("no object: pass --lc-object PATH")
        )
    if want_cp and cp_object == String(""):
        return _refuse_scan(
            String("no object: pass --cp-object PATH")
        )
    var elf: List[UInt8]
    try:
        elf = read_host_file(
            object_path, String("object"), MAX_NARROW_OBJECT_BYTES
        )
    except:
        return _refuse_scan(String("object unreadable"))
    var accuse = verify_object(Span(elf), String(_PROGRAM))
    if not accuse.ok:
        return _refuse_scan(
            String("object refused: ") + accuse.message
        )
    var maps = read_btf_maps(Span(elf))
    if not maps.ok:
        return _refuse_scan(String("object refused: ") + maps.message)
    var ring = maps.ring_bytes
    var sha = sha256_hex(Span(elf))
    if ring > MAX_NARROW_RING_BYTES:
        return _refuse_scan(String("object ring too large"))
    var lc = _ExtraOut()
    if want_lc:
        lc = _verify_extra_object(
            lc_object,
            String("lc"),
            String(_RING_LC_MAP),
            String("lifecycle"),
            _lc_progs(),
        )
        if not lc.ok:
            return _refuse_scan(lc.refusal.copy())
    var cp = _ExtraOut()
    if want_cp:
        cp = _verify_extra_object(
            cp_object,
            String("cp"),
            String(_RING_CP_MAP),
            String("copy"),
            _cp_progs(),
        )
        if not cp.ok:
            return _refuse_scan(cp.refusal.copy())
    var order = List[Int]()
    var order_receipt = List[Bool]()
    var saw_bridge_mismatch = False
    if want_explicit:
        order.append(0)
        order_receipt.append(False)
    else:
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                order.append(i)
                order_receipt.append(False)
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                continue
            var mism = False
            if _receipt_covers(
                candidates[i],
                kernel,
                ask.caps,
                profiles_dir,
                bridge_sha,
                mism,
            ):
                order.append(i)
                order_receipt.append(True)
            elif mism:
                saw_bridge_mismatch = True
    var skip_reason = String("")
    for oi in range(len(order)):
        var doc = candidates[order[oi]].copy()
        var gap = _selection_gap(doc, ask.caps)
        if gap != String(""):
            if want_explicit:
                return _refuse_scan(gap)
            skip_reason = gap.copy()
            continue
        var tgap = tracing_gap(doc, ask.caps)
        if tgap != String(""):
            if want_explicit:
                return _refuse_scan(tgap)
            skip_reason = tgap.copy()
            continue
        var hook = ProfileHook()
        var raw = List[UInt8]()
        var sys = String("")
        var evt = String("")
        var herr = _admit_hook(root, doc.copy(), hook, raw, sys, evt)
        if herr != String(""):
            if want_explicit:
                return _refuse_scan(herr)
            skip_reason = herr.copy()
            continue
        var parsed = parse_narrow_note(doc.identity.source.note)
        if not parsed.ok:
            if want_explicit:
                if want_extra:
                    return _refuse_scan(
                        String("binding failed: ") + parsed.message
                    )
                # Unparseable bindings are never validated,
                # whatever the document status claims: without
                # a parsed note no identity check ran. Both
                # statuses proceed as unbound partials with
                # wording that reserves "validated" for
                # successful binding checks.
                out.ok = True
                out.kind = String("partial")
                if doc.status == String("validated"):
                    out.reason = String("explicit ") + doc.profile_id.copy() + String(" (unbound, no bindings)")
                else:
                    out.reason = String("explicit ") + doc.profile_id.copy() + String(" (reference, no bindings)")
                out.profile = doc.copy()
                out.hook = hook.copy()
                out.object_sha = sha.copy()
                out.ring_bytes = ring
                out.elf = elf.copy()
                out.tp_system = sys.copy()
                out.tp_event = evt.copy()
                out.selected_caps = selected.copy()
                return out^
            skip_reason = String("binding failed: ") + parsed.message
            continue
        var bound = _check_binding(
            root,
            kernel.release,
            doc.copy(),
            hook.copy(),
            sha,
            ring,
            Span(raw),
            lc.sha,
            lc.ring,
            cp.sha,
            cp.ring,
            want_lc,
            want_cp,
        )
        if not bound.ok:
            if want_explicit:
                return _refuse_scan(
                    String("binding failed: ") + bound.reason
                )
            skip_reason = String("binding failed: ") + bound.reason
            continue
        out.ok = True
        if doc.status == String("validated"):
            out.kind = String("validated")
            out.reason = (
                String("validated ")
                + doc.profile_id.copy()
                + String(": bindings hold")
            )
        elif order_receipt[oi]:
            out.kind = String("local-auto")
            out.reason = (
                String("local-auto ")
                + doc.profile_id.copy()
                + String(": receipt verified, bindings hold")
            )
        else:
            out.kind = String("candidate")
            out.reason = (
                String("candidate ")
                + doc.profile_id.copy()
                + String(": bindings hold (profile unvalidated)")
            )
        out.profile = doc.copy()
        out.hook = hook.copy()
        out.object_sha = sha.copy()
        out.ring_bytes = ring
        out.elf = elf.copy()
        out.tp_system = sys.copy()
        out.tp_event = evt.copy()
        out.measured_config = bound.config.copy()
        out.measured_config_src = bound.config_src.copy()
        out.measured_btf = bound.btf.copy()
        out.measured_format = bound.format.copy()
        out.measured_image = bound.image.copy()
        out.measured_image_bid = bound.image_bid.copy()
        out.selected_caps = selected.copy()
        out.has_lifecycle = want_lc
        out.has_copy = want_cp
        if want_lc:
            out.lc_elf = lc.elf.copy()
            out.lc_object_sha = lc.sha.copy()
            out.lc_ring_bytes = lc.ring
        if want_cp:
            out.cp_elf = cp.elf.copy()
            out.cp_object_sha = cp.sha.copy()
            out.cp_ring_bytes = cp.ring
        return out^
    # Scan mode only: explicit always returns inside the loop.
    if want_extra:
        if skip_reason == String(""):
            return _refuse_scan(
                String("no profile satisfies requested capabilities")
            )
        return _refuse_scan(skip_reason.copy())
    var first = candidates[0].copy()
    var phook = ProfileHook()
    var praw = List[UInt8]()
    var psys = String("")
    var pevt = String("")
    var perr = _admit_hook(root, first.copy(), phook, praw, psys, pevt)
    if perr != String(""):
        return _refuse_scan(perr)
    out.ok = True
    out.kind = String("partial")
    var had_validated = False
    for i in range(len(candidates)):
        if candidates[i].status == String("validated"):
            had_validated = True
            break
    if saw_bridge_mismatch:
        out.reason = (
            String("partial ")
            + first.profile_id.copy()
            + String(": receipt bridge mismatch")
        )
    elif had_validated:
        out.reason = (
            String("partial ")
            + first.profile_id.copy()
            + String(": narrow identity unverified")
        )
    else:
        out.reason = (
            String("partial ")
            + first.profile_id.copy()
            + String(": no validated profile")
        )
    out.profile = first.copy()
    out.hook = phook.copy()
    out.object_sha = sha.copy()
    out.ring_bytes = ring
    out.elf = elf.copy()
    out.tp_system = psys.copy()
    out.tp_event = pevt.copy()
    out.selected_caps = selected.copy()
    return out^


def _record_failed(detail: String) raises -> Int:
    """Report one cannot-start failure; return EXIT_REFUSAL."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_REFUSAL


def _record_misused(detail: String) raises -> Int:
    """Report one usage failure; return EXIT_INVALID."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID


def resolve_bridge(bridge: String, has_bridge: Bool) -> String:
    """Explicit --bridge verbatim, else zero-config discovery.

    Thin delegate over discover_bridge: the ambient env
    value, live uids, and kernel-resolved executable path
    feed the pure order (env when unprivileged, bundle,
    system). Never argv[0], PATH, or the working directory.
    """
    var exe_path = String("")
    try:
        exe_path = readlink_self()
    except:
        exe_path = String("")
    return discover_bridge(
        bridge,
        has_bridge,
        getenv("LMB_NATIVE_LIB"),
        live_uids(),
        exe_path,
    )


def resolve_object(
    kind: String, explicit: String, exe_path: String
) -> String:
    """Explicit object path verbatim, else discovery.

    ``kind`` is attempt, lifecycle, or copy. An explicit
    path wins unprobed; otherwise the executable-relative
    bundle path and the system path are probed in order.
    Callers pass the kernel-resolved executable path
    (readlink_self), never argv[0] or the working
    directory, so tests pin discovery with fixture trees.
    "" when nothing applies.
    """
    var has_explicit = explicit != String("")
    return discover_object(kind, explicit, has_explicit, exe_path)


comptime _SNAP_AT_FDCWD = -100
comptime _SNAP_O_RDONLY = 0


struct BridgeSnapshot(Movable):
    """One pinned bridge file: the hashed bytes are the loaded bytes.

    The resolved pathname opens once with O_RDONLY and
    stays open; the loader and the admission hash both
    name that same open file description through
    /proc/self/fd/N, so a pathname swap after
    resolution changes neither. The pin defeats
    rename and symlink swaps, not in-place writes to
    the pinned inode itself; the threat assumption is
    unchanged. ``sha`` is the bare hex sha256 of the
    pinned bytes, "" when the bridge is uncheckable;
    ``load_path`` is the fd alias when pinned, else
    the plain pathname for the loader's own failure.
    Hold the snapshot until the load it guards
    completes; dropping it closes the fd.
    """

    var fd: Int32
    var load_path: String
    var sha: String

    def __init__(out self):
        self.fd = Int32(-1)
        self.load_path = String("")
        self.sha = String("")

    def __deinit__(deinit self):
        if self.fd >= Int32(0):
            _ = external_call["close", Int32](self.fd)


def open_bridge_snapshot(path: String) -> BridgeSnapshot:
    """Pin one bridge file for hashing and loading.

    Opens path O_RDONLY (following a final symlink
    once, at open) and hashes the open description
    through its /proc/self/fd/N alias; the loader
    receives the same alias. When the open or the
    alias read fails, the snapshot degrades to the
    plain pathname with an empty hash: admission
    cannot bind and the loader reports its own
    failure, exactly as before. Never raises.
    """
    var snap = BridgeSnapshot()
    if path == String(""):
        return snap^
    var cpath = _to_cstr(path)
    var fd = external_call["openat", Int32](
        Int32(_SNAP_AT_FDCWD),
        Span(cpath).unsafe_ptr(),
        Int32(_SNAP_O_RDONLY),
        UInt32(0),
    )
    if fd < Int32(0):
        snap.load_path = path.copy()
        return snap^
    var alias = String("/proc/self/fd/") + String(Int(fd))
    try:
        var raw = read_host_file(
            alias, String("bridge"), MAX_NARROW_OBJECT_BYTES
        )
        snap.sha = sha256_hex(Span(raw))
        snap.fd = fd
        snap.load_path = alias.copy()
    except:
        _ = external_call["close", Int32](fd)
        snap.load_path = path.copy()
    return snap^


def open_object_snapshot(path: String) -> BridgeSnapshot:
    """Pin one BPF object file for smoke input and minting.

    The same mechanism as open_bridge_snapshot: one
    O_RDONLY open, hashed and read through its
    /proc/self/fd/N alias, degrading to the plain
    pathname with an empty hash when uncheckable.
    Qualify snapshots each object before the smoke,
    feeds the alias to the smoke as its load input,
    and mints from the snapshot hash, so the receipt
    binds the exercised bytes. Never raises.
    """
    var snap = open_bridge_snapshot(path)
    return snap^


def _parse_sudo_id(text: String) -> Int:
    """Parse a SUDO_UID/SUDO_GID value, or -1 when insane.

    Strict ASCII decimal fitting uid_t
    (0..4294967295); empty, non-digit, and
    overflowing values refuse. -1 never collides:
    it lies outside the uid_t range.
    """
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 10:
        return -1
    var v = UInt64(0)
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            return -1
        var d = UInt64(Int(b) - 0x30)
        if v > (UInt64(0xFFFFFFFF) - d) // UInt64(10):
            return -1
        v = v * UInt64(10) + d
    return Int(v)


def _to_cstr(text: String) -> List[UInt8]:
    """Copy text into a fresh NUL-terminated byte buffer."""
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


comptime _OWN_AT_FDCWD = -100
comptime _OWN_O_RDONLY = 0
comptime _OWN_O_DIRECTORY = 65536
comptime _OWN_O_NOFOLLOW = 131072
comptime _OWN_STAT_SIZE = 144
comptime _OWN_S_IFMT = 0o170000
comptime _OWN_S_IFREG = 0o100000
comptime _OWN_S_IFDIR = 0o040000


def _own_le32(buf: List[UInt8], off: Int) -> UInt32:
    var v = UInt32(0)
    for i in range(4):
        v |= UInt32(buf[off + i]) << UInt32(8 * i)
    return v


def _own_le64(buf: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(buf[off + i]) << UInt64(8 * i)
    return v


def _own_fstat_ids(fd: Int32) raises -> List[UInt64]:
    """[mode, uid, nlink] for an open fd (x86-64 stat layout)."""
    var buf = List[UInt8]()
    for _ in range(_OWN_STAT_SIZE):
        buf.append(UInt8(0))
    var r = external_call["fstat", Int32](
        fd, Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("ownership fstat failed")
    var out = List[UInt64]()
    out.append(UInt64(_own_le32(buf, 24)))
    out.append(UInt64(_own_le32(buf, 28)))
    out.append(_own_le64(buf, 16))
    return out^


def _own_close_quiet(fd: Int32):
    if fd >= Int32(0):
        _ = external_call["close", Int32](fd)


def _own_open_dir(path: String) -> Int32:
    """Open the directory itself, never a symlink; -1 on failure."""
    var cpath = _to_cstr(path)
    return external_call["openat", Int32](
        Int32(_OWN_AT_FDCWD),
        Span(cpath).unsafe_ptr(),
        Int32(_OWN_O_RDONLY | _OWN_O_DIRECTORY | _OWN_O_NOFOLLOW),
        UInt32(0),
    )


def _own_open_child(dir_fd: Int32, name: String) -> Int32:
    """Open one child by name, never a symlink; -1 on failure."""
    var cname = _to_cstr(name)
    return external_call["openat", Int32](
        dir_fd,
        Span(cname).unsafe_ptr(),
        Int32(_OWN_O_RDONLY | _OWN_O_NOFOLLOW),
        UInt32(0),
    )


def _own_child_ok(fd: Int32) -> Bool:
    """True when an open child is a single-link regular file.

    Symlinks never reach here (O_NOFOLLOW refuses them
    at open). This rejects directories, fifos, sockets,
    and files with extra hard links. Ownership is
    checked separately by the caller. Never raises.
    """
    try:
        var ids = _own_fstat_ids(fd)
        return (
            ids[0] & UInt64(_OWN_S_IFMT) == UInt64(_OWN_S_IFREG)
            and ids[2] == UInt64(1)
        )
    except:
        return False


def _own_fd_uid(fd: Int32) -> Int:
    """Owner uid of an open fd, or -1 on failure.

    Under sudo every true capture file is
    root-created, so any other owner proves a planted
    replacement. Never raises.
    """
    try:
        var ids = _own_fstat_ids(fd)
        return Int(ids[1])
    except:
        return -1


def _own_fchown(fd: Int32, uid: UInt32, gid: UInt32) -> Bool:
    """True when one fchown call reports success."""
    var r = external_call["fchown", Int32](fd, uid, gid)
    return Int(r) == 0


def _own_repair_child(
    dir_fd: Int32, name: String, uid: UInt32, gid: UInt32
) -> Bool:
    """Hand one expected child to the invoking user.

    The child opens through the retained directory
    descriptor and every later step (identity check,
    ownership transfer) acts on that same open file
    description, so a mid-repair replacement cannot
    redirect the chown. Only a root-owned single-link
    regular file transfers; anything else is rejected
    untouched. False when the child is missing,
    rejected, or unchownable. Never raises.
    """
    var fd = _own_open_child(dir_fd, name)
    if fd < Int32(0):
        return False
    var ok = _own_child_ok(fd) and _own_fd_uid(fd) == 0
    if ok:
        ok = _own_fchown(fd, uid, gid)
    _own_close_quiet(fd)
    return ok


def _restore_sudo_ownership(output: String):
    """Best-effort capture ownership repair; never raises.

    Under sudo the capture lands root-owned (mkdir
    0700), locking out the invoking user's replay.
    When both SUDO_UID and SUDO_GID parse as uid_t
    values and this process runs as root (a non-root
    run already owns its files, so there is nothing
    to restore), hand the capture to the invoking
    user through retained descriptors: the directory
    opens with O_DIRECTORY|O_NOFOLLOW and must itself
    be the root-created capture dir (a swapped-in
    user-owned dir aborts the repair before anything
    is touched); each expected flat file
    (events.ndjson, session.json) opens through that
    descriptor, proves a root-owned single-link
    regular file, and transfers via fchown; anything
    else in the directory is foreign and stays
    root-owned. The directory transfers LAST, so the
    invoking user gains no write access until every
    child is already handed back and nothing can be
    planted mid-repair. Any failure warns once on
    stderr; the capture itself stands.
    """
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid < 0 or gid < 0:
        return
    if _geteuid_live() != 0:
        return
    var ok = True
    var dir_fd = _own_open_dir(output)
    if dir_fd < Int32(0):
        ok = False
    else:
        var dir_ok = False
        try:
            var ids = _own_fstat_ids(dir_fd)
            dir_ok = (
                ids[0] & UInt64(_OWN_S_IFMT)
                == UInt64(_OWN_S_IFDIR)
                and ids[1] == UInt64(0)
            )
        except:
            dir_ok = False
        if dir_ok:
            if not _own_repair_child(
                dir_fd,
                String("events.ndjson"),
                UInt32(uid),
                UInt32(gid),
            ):
                ok = False
            if not _own_repair_child(
                dir_fd,
                String("session.json"),
                UInt32(uid),
                UInt32(gid),
            ):
                ok = False
            if not _own_fchown(dir_fd, UInt32(uid), UInt32(gid)):
                ok = False
        else:
            ok = False
        _own_close_quiet(dir_fd)
    if not ok:
        try:
            write_stderr(
                String("memveil record: warning: cannot restore ")
                + String("capture ownership to ")
                + String(uid)
                + String(":")
                + String(gid)
                + String("\n")
            )
        except:
            pass


def _read_boot_id(root: String, mut boot_id: String) -> Bool:
    """Live boot id when present and well-formed, else False."""
    var raw: List[UInt8]
    try:
        raw = read_host_file(
            _join(root, String("/proc/sys/kernel/random/boot_id")),
            String("boot_id"),
            4096,
        )
    except:
        return False
    while len(raw) > 0 and raw[len(raw) - 1] == UInt8(0x0A):
        _ = raw.pop()
    if len(raw) == 0:
        return False
    var text: String
    try:
        text = String(from_utf8=Span(raw))
    except:
        return False
    try:
        check_opaque_id(text)
    except:
        return False
    boot_id = text.copy()
    return True


def _decision_item(reason: String) -> EvidenceItem:
    var item = EvidenceItem()
    item.item_type = String("provenance")
    item.source = String("profile.decision")
    item.interpretation = reason
    return item^


def _value_item(source: String, value: String) -> EvidenceItem:
    var item = EvidenceItem()
    item.item_type = String("provenance")
    item.source = source
    item.interpretation = value
    return item^


def render_provenance(source: String, v: LiveValue) -> EvidenceItem:
    """One provenance item from a measured live identity.

    Valued reads render their bare hex; anything else is
    an explicit unavailable marker, never empty or zero.
    Empty states mean no binding ran (partial decisions);
    other states carry the read failure reason.
    """
    var item = EvidenceItem()
    item.item_type = String("provenance")
    item.source = source
    if v.state == String("value"):
        item.interpretation = v.value.copy()
    elif v.state == String(""):
        item.interpretation = String(
            "unavailable: narrow identity unverified"
        )
    elif v.detail == String(""):
        item.interpretation = String("unavailable: ") + v.state
    else:
        item.interpretation = (
            String("unavailable: ")
            + v.state
            + String(": ")
            + v.detail
        )
    return item^


def run_collector_with[W: WriterSource](
    root: String, profiles_dir: String, opts: RecordOptions,
    mut writer: W,
) raises -> RunResult:
    """Run admission plus collection; return the raw outcome.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. Absent bridge
    and object paths are discovered (explicit user input
    wins verbatim and is never root-joined). Pre-run
    refusals return exit 3 with an empty end reason and
    the diagnostic unprefixed; the caller adds its verb
    prefix. The collector runs only on approval, so
    refusals create no BPF or output resource.
    """
    if opts.max_events_bytes < MIN_RECORD_BYTES:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String(t"budget {opts.max_events_bytes} below 131072"),
        )
    if opts.max_events_bytes > MAX_RECORD_BYTES:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String(t"budget {opts.max_events_bytes} above 4294967296"),
        )
    var bridge = resolve_bridge(opts.bridge, opts.has_bridge)
    if bridge == String(""):
        # Privileged runs ignore LMB_NATIVE_LIB, so the
        # refusal must not recommend it: only an
        # unprivileged caller can use the env step.
        var hint = String(
            "no bridge: pass --bridge or set LMB_NATIVE_LIB"
        )
        if is_privileged(live_uids()):
            hint = String(
                "no bridge: restore the bundled bridge"
                " or pass --bridge PATH"
            )
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            hint,
        )
    # One resolution, pinned once: the snapshot's open
    # file description feeds the admission hash, the
    # provenance below, and the loader, so no pathname
    # swap can slip a different bridge between the
    # receipt check and the load. An unreadable bridge
    # hashes to "": receipts cannot admit local-auto, and
    # provenance marks the identity uncheckable. The
    # snapshot lives in this scope, so its fd covers the
    # load inside the collector run below.
    var snap = open_bridge_snapshot(bridge)
    var bridge_sha = snap.sha.copy()
    var bridge_v = LiveValue()
    if bridge_sha != String(""):
        bridge_v.state = String("value")
        bridge_v.value = bridge_sha.copy()
    else:
        bridge_v.state = String("uncheckable")
        bridge_v.detail = String("bridge unreadable")
    var exe_path = String("")
    try:
        exe_path = readlink_self()
    except:
        exe_path = String("")
    var object_path = resolve_object(
        String("attempt"), opts.object, exe_path
    )
    if object_path == String(""):
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("no object: pass --object PATH"),
        )
    var lc_object = resolve_object(
        String("lifecycle"), opts.lc_object, exe_path
    )
    var cp_object = resolve_object(
        String("copy"), opts.cp_object, exe_path
    )
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(root)
    except e:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("cannot open evidence: ") + String(e),
        )
    var env = detect_environment(reader)
    if not env.kernel.eligible_floor:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("kernel ")
            + env.kernel.release
            + String(" below floor 7.0"),
        )
    var profiles: List[Profile]
    try:
        profiles = load_profiles(profiles_dir)
    except e:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("cannot load profiles: ") + String(e),
        )
    var decision = decide_record(
        root,
        env.kernel,
        profiles^,
        opts.profile,
        opts.has_profile,
        object_path,
        lc_object,
        cp_object,
        opts.capabilities,
        profiles_dir,
        bridge_sha,
    )
    if not decision.ok:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            decision.refusal.copy(),
        )
    var timens = check_timens_live()
    if not timens.ok:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("time namespace unverifiable"),
        )
    if timens.offset:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("time namespace offset present"),
        )
    var cfg = CollectorConfig()
    cfg.duration_s = opts.duration_s
    cfg.max_events_bytes = opts.max_events_bytes
    cfg.output = opts.output
    cfg.profile_id = decision.profile.profile_id.copy()
    cfg.grade = decision.kind.copy()
    # Live captures sample the default SWIOTLB pool counters at
    # start, periodically, and close; unreadable counters stay
    # in the samples as unavailable halves, never as failed runs.
    cfg.has_pool_sample = True
    cfg.pid = Int(external_call["getpid", Int32]())
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(decision.ring_bytes)
    cfg.has_lifecycle = decision.has_lifecycle
    cfg.lifecycle_ring_bytes = UInt32(decision.lc_ring_bytes)
    cfg.has_copy = decision.has_copy
    cfg.copy_ring_bytes = UInt32(decision.cp_ring_bytes)
    var boot_id = String("")
    if _read_boot_id(root, boot_id):
        cfg.has_boot_id = True
        cfg.boot_id = boot_id.copy()
    cfg.guest = env.guest.copy()
    cfg.evidence.append(_decision_item(decision.reason.copy()))
    cfg.evidence.append(
        _value_item(
            String("object.sha256"), decision.object_sha.copy()
        )
    )
    cfg.evidence.append(
        _value_item(
            String("ring.bytes"), String(decision.ring_bytes)
        )
    )
    cfg.evidence.append(
        _value_item(
            String("capabilities.selected"),
            decision.selected_caps.copy(),
        )
    )
    if decision.has_lifecycle:
        cfg.evidence.append(
            _value_item(
                String("lc.object.sha256"),
                decision.lc_object_sha.copy(),
            )
        )
        cfg.evidence.append(
            _value_item(
                String("lc.ring.bytes"),
                String(decision.lc_ring_bytes),
            )
        )
    if decision.has_copy:
        cfg.evidence.append(
            _value_item(
                String("cp.object.sha256"),
                decision.cp_object_sha.copy(),
            )
        )
        cfg.evidence.append(
            _value_item(
                String("cp.ring.bytes"),
                String(decision.cp_ring_bytes),
            )
        )
    if env.kernel.release == String(""):
        cfg.evidence.append(
            _value_item(
                String("kernel.release"),
                String("unavailable: release unknown"),
            )
        )
    else:
        cfg.evidence.append(
            _value_item(
                String("kernel.release"), env.kernel.release.copy()
            )
        )
    cfg.evidence.append(
        render_provenance(
            String("kernel.build_id"), decision.measured_image_bid
        )
    )
    cfg.evidence.append(
        render_provenance(
            String("config.sha256"), decision.measured_config
        )
    )
    var config_src = LiveValue()
    if decision.measured_config_src != String(""):
        config_src.state = String("value")
        config_src.value = decision.measured_config_src.copy()
    cfg.evidence.append(
        render_provenance(String("config.src"), config_src)
    )
    cfg.evidence.append(
        render_provenance(
            String("btf.sha256"), decision.measured_btf
        )
    )
    cfg.evidence.append(
        render_provenance(
            String("format.sha256"), decision.measured_format
        )
    )
    cfg.evidence.append(
        render_provenance(
            String("image.sha256"), decision.measured_image
        )
    )
    cfg.evidence.append(
        render_provenance(String("bridge.sha256"), bridge_v)
    )
    cfg.evidence.append(
        _value_item(
            String("bridge.abi"), String("abi-v1 (required)")
        )
    )
    var kernel = LmbKernel.with_channels(
        decision.elf.copy(),
        decision.tp_system.copy(),
        decision.tp_event.copy(),
        decision.lc_elf.copy(),
        decision.has_lifecycle,
        decision.cp_elf.copy(),
        decision.has_copy,
        snap.load_path,
    )
    var clock = MonoClock()
    var signal = LiveSignalSource()
    var collector = Collector(cfg^)
    var out = collector.run(kernel, clock, signal, writer)
    if out.outcome == String("finalized"):
        # A published capture lands root-owned under sudo;
        # hand it to the invoking user. Warn-only: the
        # capture stands whatever ownership repair does.
        _restore_sudo_ownership(opts.output)
    return out^


def run_record_with(
    root: String, profiles_dir: String, opts: RecordOptions
) raises -> Int:
    """Run the record flow against explicit roots; return exit code.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. Absent bridge
    and object paths are discovered (explicit user input
    wins verbatim and is never root-joined). Refusals print
    one diagnostic and exit 3 before any BPF or output
    resource exists.
    """
    var writer = LiveWriter()
    var result = run_collector_with(
        root, profiles_dir, opts, writer
    )
    if result.exit_code == EXIT_ERROR or result.exit_code == EXIT_REFUSAL:
        try:
            write_stderr(
                String("memveil record: ")
                + sanitize_diagnostic(result.diagnostic)
                + String("\n")
            )
        except:
            pass
    if result.end_reason == String(""):
        return result.exit_code
    var done = String(
        t"record: end={result.end_reason} outcome={result.outcome} exit={result.exit_code}"
    )
    try:
        write_stdout(done + String("\n"))
    except:
        try:
            write_stderr("memveil record: cannot write stdout\n")
        except:
            pass
        return EXIT_ERROR
    return result.exit_code


def run_record(args: List[String]) raises -> Int:
    """Run the record verb; return the process exit code.

    args excludes the program name and the record word.
    Profiles resolve from the kernel-resolved binary path,
    never from argv[0] or the working directory.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(record_usage())
            except:
                try:
                    write_stderr("memveil record: cannot write stdout\n")
                except:
                    pass
                return EXIT_ERROR
            return EXIT_OK
        i += 1
    var opts: RecordOptions
    try:
        opts = parse_record_args(args)
    except e:
        return _record_misused(e.message)
    var profiles_dir = opts.profiles_dir
    if not opts.has_profiles_dir:
        try:
            profiles_dir = resolve_profiles_dir()
        except e:
            return _record_failed(
                String("cannot resolve profiles location: ") + e.message
            )
    return run_record_with(String(""), profiles_dir, opts^)
