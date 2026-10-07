# SPDX-License-Identifier: GPL-3.0-or-later

"""memveil record: admitted attempt capture.

``run_record`` implements ``record --duration SEC --max-events-bytes
N --output DIR --object PATH --bridge PATH [--profile ID]`` against
the live host. ``run_record_with`` is the same flow against an
explicit evidence root and profiles directory, so tests drive
fixtures through the identical code path. ``decide_record`` is the
testable admission decision (profile scan, object statics, hook
layout, narrow binding) without clocks or BPF.

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
from memveil.platform.btf import read_btf_maps
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
    check_trace_layout,
    parse_narrow_note,
    read_live_bid,
    read_live_bytes,
    read_live_config,
    verify_object,
)
from memveil.platform.profiles import (
    Profile,
    ProfileHook,
    load_profiles,
    parse_profile_bytes,
    select_profile,
)
from memveil.platform.reader import (
    EvidenceReader,
    open_evidence_reader,
    read_host_file,
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

    def __init__(out self):
        self.duration_s = DEFAULT_DURATION_S
        self.max_events_bytes = DEFAULT_MAX_EVENTS_BYTES
        self.output = String("")
        self.object = String("")
        self.bridge = String("")
        self.has_bridge = False
        self.profile = String("")
        self.has_profile = False


def record_usage() -> String:
    """Usage text for the record verb."""
    return (
        "usage: memveil record --output DIR --object PATH\n"
        "       [--duration SEC] [--max-events-bytes N]\n"
        "       [--bridge PATH] [--profile ID|PATH]\n"
        "\n"
        "Capture swiotlb bounce attempts into DIR. SEC defaults\n"
        "to 60; N defaults to 1073741824 (1 GiB) and must lie\n"
        "in 131072..4294967296. --bridge defaults to the\n"
        "LMB_NATIVE_LIB environment path. Without --profile,\n"
        "the first validated profile passing full identity\n"
        "binding wins, else the first covering profile runs\n"
        "partial; an explicit --profile that fails binding\n"
        "refuses. Diagnostics go to stderr.\n"
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
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            raise CliError("unexpected argument: " + tok)
    if opts.output == "":
        raise CliError("missing --output")
    if opts.object == "":
        raise CliError("missing --object")
    return opts^


struct ScanDecision(Copyable):
    """One admission decision: mode, hook, identity, bytes.

    ``ok`` False carries an exit-3 ``refusal``; otherwise
    ``kind`` is validated, candidate, or partial, ``hook``
    is the selected tracepoint hook with a verified live
    layout, and ``elf`` is the verified object bytes (read
    once, hashed and handed to the session unchanged).
    Bound decisions also carry the measured narrow
    identities (config/src, btf, format, image, image
    build-id); partial decisions leave them empty so the
    capture marks each one unavailable.
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


def _refuse_scan(reason: String) -> ScanDecision:
    var out = ScanDecision()
    out.ok = False
    out.refusal = reason
    return out^


struct _HookOut(Copyable):
    var ok: Bool
    var refusal: String
    var hook: ProfileHook

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.hook = ProfileHook()


def _select_hook(profile: Profile) -> _HookOut:
    """Select the attempt-trace hook of one profile.

    The hook named by the attempt-trace capability wins;
    otherwise the first tracepoint hook. Anything else
    refuses: capture needs exactly one tracepoint site.
    """
    var out = _HookOut()
    var want = String("")
    for i in range(len(profile.caps)):
        if profile.caps[i].id == _ATTEMPT_CAP:
            if len(profile.caps[i].hooks) > 0:
                want = profile.caps[i].hooks[0]
            break
    if want != String(""):
        for i in range(len(profile.hooks)):
            if profile.hooks[i].name == want:
                if profile.hooks[i].kind != String("tracepoint"):
                    out.refusal = String(
                        "attempt-trace hook is not a tracepoint"
                    )
                    return out^
                out.ok = True
                out.hook = profile.hooks[i].copy()
                return out^
        out.refusal = String("attempt-trace hook missing")
        return out^
    for i in range(len(profile.hooks)):
        if profile.hooks[i].kind == String("tracepoint"):
            out.ok = True
            out.hook = profile.hooks[i].copy()
            return out^
    out.refusal = String("no tracepoint hook")
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
) -> _BindingOut:
    """Full narrow binding of one doc against live identity.

    Release must equal the recorded revision, the note
    must parse, every live source must match, and the
    live format bytes must equal the embedded text.
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
    var sel = _select_hook(doc)
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


def decide_record(
    root: String,
    kernel: KernelInfo,
    profiles: List[Profile],
    explicit: String,
    has_explicit: Bool,
    object_path: String,
) -> ScanDecision:
    """Decide admission: scan, object statics, hook, binding.

    Explicit mode resolves one doc (file first, then id)
    and enforces full binding when bindings exist. Scan
    mode tries each covering validated doc in order and
    falls back to the first covering doc as partial.
    Static object failures refuse everywhere; identity
    failures fall through in scan mode only.
    """
    var out = ScanDecision()
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
    var order = List[Int]()
    if want_explicit:
        order.append(0)
    else:
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                order.append(i)
    for oi in range(len(order)):
        var doc = candidates[order[oi]].copy()
        var hook = ProfileHook()
        var raw = List[UInt8]()
        var sys = String("")
        var evt = String("")
        var herr = _admit_hook(root, doc.copy(), hook, raw, sys, evt)
        if herr != String(""):
            if want_explicit:
                return _refuse_scan(herr)
            continue
        var parsed = parse_narrow_note(doc.identity.source.note)
        if not parsed.ok:
            if want_explicit:
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
                return out^
            continue
        var bound = _check_binding(
            root,
            kernel.release,
            doc.copy(),
            hook.copy(),
            sha,
            ring,
            Span(raw),
        )
        if not bound.ok:
            if want_explicit:
                return _refuse_scan(
                    String("binding failed: ") + bound.reason
                )
            continue
        out.ok = True
        if doc.status == String("validated"):
            out.kind = String("validated")
            out.reason = (
                String("validated ")
                + doc.profile_id.copy()
                + String(": bindings hold")
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
        return out^
    # Scan mode only: explicit always returns inside the loop.
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
    if had_validated:
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
    return out^


def _record_failed(detail: String) raises -> Int:
    """Report one cannot-start failure; return EXIT_REFUSAL."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_REFUSAL


def _record_misused(detail: String) raises -> Int:
    """Report one usage failure; return EXIT_INVALID."""
    write_stderr("memveil record: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID


def _resolve_bridge(bridge: String, has_bridge: Bool) -> String:
    """Explicit --bridge, else LMB_NATIVE_LIB, else ""."""
    if has_bridge:
        return bridge
    var path = getenv("LMB_NATIVE_LIB")
    if path == "":
        return String("")
    return path


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


def run_record_with(
    root: String, profiles_dir: String, opts: RecordOptions
) raises -> Int:
    """Run the record flow against explicit roots; return exit code.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. The object path
    stays exactly as given (explicit user input, never
    root-joined). Refusals print one diagnostic and exit 3
    before any BPF or output resource exists.
    """
    if opts.max_events_bytes < MIN_RECORD_BYTES:
        return _record_failed(
            String(t"budget {opts.max_events_bytes} below 131072")
        )
    if opts.max_events_bytes > MAX_RECORD_BYTES:
        return _record_failed(
            String(t"budget {opts.max_events_bytes} above 4294967296")
        )
    var bridge = _resolve_bridge(opts.bridge, opts.has_bridge)
    if bridge == String(""):
        return _record_failed(
            String("no bridge: pass --bridge or set LMB_NATIVE_LIB")
        )
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(root)
    except e:
        return _record_failed(
            String("cannot open evidence: ") + String(e)
        )
    var env = detect_environment(reader)
    if not env.kernel.eligible_floor:
        return _record_failed(
            String("kernel ") + env.kernel.release + String(" below floor 7.0")
        )
    var profiles: List[Profile]
    try:
        profiles = load_profiles(profiles_dir)
    except e:
        return _record_failed(
            String("cannot load profiles: ") + String(e)
        )
    var decision = decide_record(
        root,
        env.kernel,
        profiles^,
        opts.profile,
        opts.has_profile,
        opts.object,
    )
    if not decision.ok:
        return _record_failed(decision.refusal.copy())
    var timens = check_timens_live()
    if not timens.ok:
        return _record_failed(String("time namespace unverifiable"))
    if timens.offset:
        return _record_failed(String("time namespace offset present"))
    var cfg = CollectorConfig()
    cfg.duration_s = opts.duration_s
    cfg.max_events_bytes = opts.max_events_bytes
    cfg.output = opts.output
    cfg.profile_id = decision.profile.profile_id.copy()
    cfg.pid = Int(external_call["getpid", Int32]())
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(decision.ring_bytes)
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
    var bridge_v = LiveValue()
    try:
        var braw = read_host_file(
            bridge, String("bridge"), MAX_NARROW_OBJECT_BYTES
        )
        bridge_v.state = String("value")
        bridge_v.value = sha256_hex(Span(braw))
    except:
        bridge_v.state = String("uncheckable")
        bridge_v.detail = String("bridge unreadable")
    cfg.evidence.append(
        render_provenance(String("bridge.sha256"), bridge_v)
    )
    cfg.evidence.append(
        _value_item(
            String("bridge.abi"), String("abi-v1 (required)")
        )
    )
    var kernel = LmbKernel(
        decision.elf.copy(),
        String(_RING_MAP),
        bridge,
        String(_PROGRAM),
        decision.tp_system.copy(),
        decision.tp_event.copy(),
    )
    var clock = MonoClock()
    var signal = LiveSignalSource()
    var writer = LiveWriter()
    var collector = Collector(cfg^)
    var result = collector.run(kernel, clock, signal, writer)
    if result.exit_code == EXIT_ERROR or result.exit_code == EXIT_REFUSAL:
        try:
            write_stderr(
                String("memveil record: ")
                + sanitize_diagnostic(result.diagnostic)
                + String("\n")
            )
        except:
            pass
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
    var profiles_dir: String
    try:
        profiles_dir = resolve_profiles_dir()
    except e:
        return _record_failed(
            String("cannot resolve profiles location: ") + e.message
        )
    return run_record_with(String(""), profiles_dir, opts^)
