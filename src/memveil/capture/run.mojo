# SPDX-License-Identifier: GPL-3.0-or-later

"""Shared collection service: admission plus the collector run.

The record verb, live top, and the qualify smoke share this one
narrow boundary: run options with fixed defaults, capability
parsing, profile admission (``decide_record``), artifact
discovery, and ``run_collector_with``, which runs admission
plus collection and returns the raw outcome. Pre-run refusals
return exit 3 with an unprefixed diagnostic and create no BPF
or output resource; each command adds its own verb prefix and
renders its own output. Ownership repair of a finalized
capture stays shared through ``repair_warning_for`` (pure: it
returns the warn-once line, else ""), while writing that line
stays with the calling command. Argument parsing and
presentation stay in the commands.
"""

from std.ffi import external_call
from std.os import getenv

from memveil.capture.collector import (
    EXIT_REFUSAL,
    Collector,
    CollectorConfig,
    RunResult,
    WriterSource,
)
from memveil.capture.loadcheck import (
    LoadDiag,
    diagnose_load,
    load_refusal_code,
)
from memveil.capture.kernel import LmbKernel
from memveil.capture.reader import (
    DEFAULT_MAX_EVENTS_BYTES as REPLAY_MAX_EVENTS_BYTES,
)
from memveil.model.session import EvidenceItem
from memveil.model.validate import check_opaque_id
from memveil.platform.artifact_files import (
    join_root,
    open_bridge_snapshot,
    restore_capture_ownership,
)
from memveil.platform.btf import (
    read_btf_copy_fb,
    read_btf_maps,
    read_btf_maps_ring,
)
from memveil.platform.capabilities import (
    attempt_loss_exact,
    cap_floor_ok,
    cap_floor_refusal,
)
from memveil.platform.clock import (
    MonoClock,
    check_timens_live,
)
from memveil.platform.evidence import (
    KernelInfo,
    detect_environment,
)
from memveil.platform.hash import sha256_hex
from memveil.platform.kernelgate import (
    GateVerdict,
    kernel_gate,
    remedy_for,
)
from memveil.platform.narrow import (
    MAX_NARROW_BTF_BYTES,
    MAX_NARROW_FORMAT_BYTES,
    MAX_NARROW_IMAGE_BYTES,
    MAX_NARROW_OBJECT_BYTES,
    MAX_NARROW_RING_BYTES,
    LiveValue,
    NarrowLive,
    OffsetProbe,
    check_narrow,
    check_narrow_extra,
    parse_narrow_note,
    probe_trace_offsets,
    read_live_bid,
    read_live_bytes,
    read_live_config,
    verify_object,
    verify_object_program,
)
from memveil.platform.profiles import (
    Profile,
    ProfileHook,
    default_receipts_dir,
    load_profiles,
    parse_profile_bytes,
    select_attempt_hook,
    select_profile,
    tracing_gap,
    verify_live_interfaces,
    verify_live_receipt,
    verify_qualification_receipt,
)
from memveil.platform.reader import (
    EvidenceReader,
    host_file_denied,
    open_evidence_reader,
    read_evidence,
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
from memveil.platform.tracefs import probe_tracefs, tracefs_translate

comptime DEFAULT_DURATION_S = UInt64(60)
# A default capture always replays under the default report cap.
comptime DEFAULT_MAX_EVENTS_BYTES = REPLAY_MAX_EVENTS_BYTES
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
    var device: String
    var has_device: Bool

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
        self.device = String("")
        self.has_device = False


struct ExtraChannel(Copyable):
    """One admitted extra channel: verified bytes, hash, ring.

    Lifecycle and copy channels admit identically shaped
    artifacts (verified object bytes, sha256, bound ring
    size) through the same static checks; the struct
    keeps that accounting grouped while each channel's
    programs, ring map, and event semantics stay
    explicit at its own call site. ``present`` False
    carries empty artifacts.
    """

    var present: Bool
    var elf: List[UInt8]
    var ring_bytes: Int
    var object_sha: String

    def __init__(out self):
        self.present = False
        self.elf = List[UInt8]()
        self.ring_bytes = 0
        self.object_sha = String("")


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
    and bound ring size in ``lc``/``cp``, and never runs
    partial. ``layout_evidence`` carries one line per
    checked 0.1.2 layout item. Admitted decisions carry
    the probed
    load-time table offsets (``off_*``, -1 when never
    probed). Refusals carry a machine ``refusal_code``
    (``profile`` for selection refusals), whether the
    evidence was ``refusal_unknown``, and a user ``fix``
    line ("" when none applies).
    """

    var ok: Bool
    var refusal: String
    var refusal_code: String
    var refusal_unknown: Bool
    var fix: String
    var kind: String
    var profile: Profile
    var hook: ProfileHook
    var reason: String
    var object_sha: String
    var ring_bytes: Int
    var off_loc: Int
    var off_size: Int
    var off_force: Int
    var off_fixed_end: Int
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
    var layout_evidence: List[String]
    var lc: ExtraChannel
    var cp: ExtraChannel

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.refusal_code = String("")
        self.refusal_unknown = False
        self.fix = String("")
        self.kind = String("")
        self.profile = Profile()
        self.hook = ProfileHook()
        self.reason = String("")
        self.object_sha = String("")
        self.ring_bytes = 0
        self.off_loc = -1
        self.off_size = -1
        self.off_force = -1
        self.off_fixed_end = -1
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
        self.layout_evidence = List[String]()
        self.lc = ExtraChannel()
        self.cp = ExtraChannel()


def _refuse_scan(reason: String) -> ScanDecision:
    var out = ScanDecision()
    out.ok = False
    out.refusal = reason
    out.refusal_code = String("profile")
    return out^


def _refuse_scan_gate(gate: GateVerdict) -> ScanDecision:
    """One kernel-gate refusal: reason, code, unknown flag, fix."""
    var out = ScanDecision()
    out.ok = False
    out.refusal = gate.reason.copy()
    out.refusal_code = gate.code.copy()
    out.refusal_unknown = gate.unknown
    out.fix = gate.remedy.copy()
    return out^


def _live_skip_code(code: String) -> String:
    """One live refusal code, defaulting to the selection class."""
    if code == String(""):
        return String("profile")
    return code.copy()


def _refuse_scan_live(
    reason: String, code: String, unknown: Bool
) -> ScanDecision:
    """One live-check refusal: reason, code, unknown flag, fix."""
    var out = ScanDecision()
    out.ok = False
    out.refusal = reason
    out.refusal_code = _live_skip_code(code.copy())
    out.refusal_unknown = unknown
    out.fix = remedy_for(out.refusal_code.copy())
    return out^


def _refusal_basename(path: String) -> String:
    """Last path component: refusal reasons leak no layout."""
    var b = path.as_bytes()
    var cut = 0
    for i in range(len(b)):
        if b[i] == UInt8(0x2F):
            cut = i + 1
    if cut >= len(b):
        return path
    try:
        return String(from_utf8=b[cut : len(b)])
    except:
        return path


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

    Empty means attempt-trace alone; the sole item "all"
    expands to the three record channels. Unknown ids,
    empty items, and requests without attempt-trace
    refuse: the attempt channel is the mandatory base
    channel.
    """
    var out = CapsOut()
    if want == String("all"):
        out.caps.append(String(_ATTEMPT_CAP))
        out.caps.append(String(_LIFECYCLE_CAP))
        out.caps.append(String(_COPY_CAP))
        out.ok = True
        return out^
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
    out.append(_ProgWant(String("mv_bounce_exit"), String("fexit/")))
    return out^


def attempt_program_names() -> List[String]:
    """Attempt program names for load diagnostics."""
    var out = List[String]()
    out.append(String(_PROGRAM))
    return out^


def lifecycle_program_names() -> List[String]:
    """Lifecycle program names for load diagnostics."""
    var wants = _lc_progs()
    var out = List[String]()
    for i in range(len(wants)):
        out.append(wants[i].name.copy())
    return out^


def copy_program_names() -> List[String]:
    """Copy program names for load diagnostics."""
    var wants = _cp_progs()
    var out = List[String]()
    for i in range(len(wants)):
        out.append(wants[i].name.copy())
    return out^


def _is_load_errno_failure(diagnostic: String) -> Bool:
    """True when a diagnostic names an EINVAL/EACCES load errno."""
    if diagnostic.find(String("code=-22")) != -1:
        return True
    return diagnostic.find(String("code=-13")) != -1


def _has_channel(diagnostic: String, channel: Int) -> Bool:
    """True when the diagnostic tags one load channel."""
    var tag = String("ch") + String(channel) + String(" ")
    if diagnostic.startswith(tag.copy()):
        return True
    var joined = String("; ") + tag
    return diagnostic.find(joined^) != -1


def _load_fail_channel(diagnostic: String) -> Int:
    """0/1/2 for the load channel a diagnostic blames, else 0.

    Session and load errors carry a ch0/ch1/ch2 tag from
    the kernel layer; the verifier replay diagnoses the
    blamed object's load. Untagged diagnostics replay
    the attempt object.
    """
    if _has_channel(diagnostic.copy(), 1):
        return 1
    if _has_channel(diagnostic, 2):
        return 2
    return 0


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
    if word == String("cp"):
        var fb = read_btf_copy_fb(Span(elf))
        if not fb.ok:
            out.refusal = (
                word + String(" object refused: ") + fb.message
            )
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


def _measure_binding(
    root: String,
    release: String,
    hook: ProfileHook,
    format_bytes: Span[UInt8, _],
) -> _BindingOut:
    """Measure live narrow identities without comparing.

    Reads the same live sources ``_check_binding``
    hashes (config plus source, btf, format, image,
    image build-id) for live-path candidates, which
    carry no parsed note to compare against. The hook
    rides along for the call shape only; no format
    text comparison runs here.
    """
    var out = _BindingOut()
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
    live.image = read_live_bytes(
        root,
        String("/boot/vmlinuz-") + release,
        String("image"),
        MAX_NARROW_IMAGE_BYTES,
    )
    live.image_bid = read_live_bid(root)
    out.config = live.config.copy()
    out.config_src = live.config_src.copy()
    out.btf = live.btf.copy()
    out.format = live.format.copy()
    out.image = live.image.copy()
    out.image_bid = live.image_bid.copy()
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
    root: String,
    obj_attempt: String,
    obj_lc: String,
    obj_cp: String,
) -> Bool:
    """True when a verifying receipt covers every wanted cap.

    The receipt at <receipts-dir>/<id>.json must verify
    against the doc, the live kernel, and the resolved
    bridge hash, and qualify each requested capability.
    Docs with a parseable narrow note verify exactly;
    docs with no usable note verify against fresh live
    measurements plus the given live-resolved object
    shas. An empty pdir, a missing file, or any verify
    failure yields False: scan falls through to the next
    candidate. ``bridge_mismatch`` reports True when the
    receipt was otherwise valid but named another
    bridge, so the fallback reason can name it. Never
    raises.
    """
    bridge_mismatch = False
    if pdir == String(""):
        return False
    var path = (
        default_receipts_dir(pdir)
        + String("/")
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
    var noted = doc.identity.source.has_note and parse_narrow_note(
        doc.identity.source.note
    ).ok
    var hit_caps = List[String]()
    if noted:
        var v = verify_qualification_receipt(
            Span(raw), doc, kernel, bridge_sha
        )
        if not v.ok:
            bridge_mismatch = v.bridge_mismatch
            return False
        hit_caps = v.caps.copy()
    else:
        var v = verify_live_receipt(
            Span(raw),
            doc,
            kernel,
            bridge_sha,
            root,
            String(_ZLIB),
            obj_attempt,
            obj_lc,
            obj_cp,
        )
        if not v.ok:
            bridge_mismatch = v.bridge_mismatch
            return False
        hit_caps = v.caps.copy()
    for i in range(len(want)):
        var found = False
        for j in range(len(hit_caps)):
            if hit_caps[j] == want[i]:
                found = True
                break
        if not found:
            return False
    return True


def _read_format(
    root: String, hook: ProfileHook, mut raw: List[UInt8]
) -> String:
    """Read hook format bytes; "" when readable.

    Failures name the translated path and the evidence
    error, keeping the `format unreadable` prefix the
    release gate matches.
    """
    try:
        var treader = open_evidence_reader(root)
        var fpath = tracefs_translate(
            probe_tracefs(treader), hook.format_path
        )
        try:
            raw = read_evidence(
                treader, fpath, MAX_NARROW_FORMAT_BYTES
            )
        except e:
            return (
                String("format unreadable: ")
                + fpath
                + String(": ")
                + e.message
            )
        return String("")
    except e:
        return (
            String("format unreadable: ")
            + hook.format_path
            + String(": ")
            + e.message
        )


def _admit_hook(
    root: String,
    doc: Profile,
    mut hook: ProfileHook,
    mut raw: List[UInt8],
    mut sys: String,
    mut evt: String,
    mut probe: OffsetProbe,
) -> String:
    """Select, read, verify, and probe one doc's hook.

    "" when admitted, with the table offsets probed from
    the same raw buffer the format binding hashes, so the
    offsets inherit that binding.
    """
    var sel = select_attempt_hook(doc)
    if not sel.ok:
        return sel.refusal.copy()
    hook = sel.hook.copy()
    var err = _read_format(root, hook.copy(), raw)
    if err != String(""):
        return err
    probe = probe_trace_offsets(Span(raw))
    if not probe.ok:
        return String("layout: ") + probe.message.copy()
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


def _static_gap(doc: Profile, caps: List[String]) -> String:
    """First privilege-independent selection gap, else ""."""
    var gap = _selection_gap(doc, caps)
    if gap != String(""):
        return gap
    return tracing_gap(doc, caps)


def _noted_doc(doc: Profile) -> Bool:
    """True when the doc carries a parseable narrow note."""
    if not doc.identity.source.has_note:
        return False
    var parsed = parse_narrow_note(doc.identity.source.note)
    return parsed.ok


def _static_receipt_ok(
    doc: Profile,
    kernel: KernelInfo,
    want: List[String],
    pdir: String,
    bridge_sha: String,
    mut denied_drop: Bool,
    mut bridge_drop: Bool,
) -> Bool:
    """True when a noted-doc receipt routes without privilege.

    Reuses receipt coverage for noted docs only; callers
    must never pass a live doc here, whose receipt check
    reads fresh live measurements behind the gate. Sets
    denied_drop when the receipt file itself is denied,
    bridge_drop when the receipt is blocked only by the
    bridge.
    """
    denied_drop = False
    bridge_drop = False
    var mism = False
    if _receipt_covers(
        doc, kernel, want, pdir, bridge_sha, mism,
        String(""), String(""), String(""), String(""),
    ):
        return True
    bridge_drop = mism
    if pdir != String(""):
        var path = (
            default_receipts_dir(pdir)
            + String("/")
            + doc.profile_id
            + String(".json")
        )
        if host_file_denied(path):
            denied_drop = True
    return False


def _refuse_gate_unreadable(detail: String) -> ScanDecision:
    """One unreadable-gate refusal: unknown, never admitted."""
    var out = _refuse_scan(
        String("kernel gate unreadable: ") + detail
    )
    out.refusal_unknown = True
    return out^


def _live_doc(doc: Profile) -> Bool:
    """True when the doc can only take the live path.

    Reference docs (any status but validated) whose
    narrow note is unusable - the source carries no
    note or the note fails to parse - never bind
    exactly; they verify live interfaces instead.
    Docs with a parseable note never take the live
    path.
    """
    if doc.status == String("validated"):
        return False
    if not doc.identity.source.has_note:
        return True
    return not parse_narrow_note(doc.identity.source.note).ok


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
    the receipts dir for the profiles dir verifies
    (against the doc, the live kernel, and
    ``bridge_sha``, the bare hex sha256 of the
    resolved bridge) and covers the
    requested capabilities ("\" disables receipts), and
    falls back to the first covering doc as partial. A
    receipt blocked only by the bridge falls through to
    partial with a reason naming the bridge mismatch,
    never local-auto; requested extras with an unchecked
    bridge ("") refuse unknown as bridge-unchecked
    instead. Static object failures refuse
    everywhere; identity failures fall through in scan
    mode only. Requested extra capabilities need a
    supported declaration, a resolvable object path, and
    full extended binding; they never fall back to
    partial. Reference docs without a usable narrow
    note take the live path instead: their tracing
    interfaces verify against the live host, and
    success admits a candidate carrying measured
    identities without exact binding.
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
    for i in range(len(ask.caps)):
        if not cap_floor_ok(ask.caps[i], kernel.release):
            return _refuse_scan(
                cap_floor_refusal(ask.caps[i], kernel.release)
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
                    String("unknown --profile: ")
                    + _refusal_basename(explicit.copy())
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
    var gate_reader: EvidenceReader
    try:
        gate_reader = open_evidence_reader(root)
    except e:
        return _refuse_gate_unreadable(String(e))
    # Privilege-independent selection refuses before the
    # kernel gate. Receipt checks against fresh live
    # measurements, hook format reads, live checks, and
    # bindings all run after it.
    if want_explicit:
        var egap = _static_gap(candidates[0], ask.caps)
        if egap != String(""):
            return _refuse_scan(egap)
    elif want_extra:
        var pool = List[Int]()
        var denied_drop = False
        var bridge_drop = False
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                pool.append(i)
            elif _live_doc(candidates[i]):
                pool.append(i)
            elif _noted_doc(candidates[i]):
                var dd = False
                var bd = False
                var ok_static = _static_receipt_ok(
                    candidates[i], kernel, ask.caps, profiles_dir,
                    bridge_sha, dd, bd,
                )
                if ok_static:
                    pool.append(i)
                elif dd:
                    denied_drop = True
                elif bd:
                    bridge_drop = True
        var bridge_open = bridge_drop and bridge_sha == String("")
        if len(pool) > 0:
            var last_gap = String("")
            var all_gapped = True
            for r in range(len(pool)):
                var g = _static_gap(
                    candidates[pool[r]], ask.caps
                )
                if g == String(""):
                    all_gapped = False
                    break
                last_gap = g.copy()
            if all_gapped:
                if bridge_open:
                    return _refuse_scan_live(
                        String(
                            "bridge unchecked: cannot verify receipts"
                        ),
                        String("bridge-unchecked"),
                        True,
                    )
                return _refuse_scan(last_gap)
        elif not denied_drop:
            if bridge_open:
                return _refuse_scan_live(
                    String("bridge unchecked: cannot verify receipts"),
                    String("bridge-unchecked"),
                    True,
                )
            return _refuse_scan(
                String("no profile satisfies requested capabilities")
            )
    try:
        var gated = kernel_gate(
            gate_reader,
            kernel.release.copy(),
            String(_ZLIB),
            ask.caps.copy(),
        )
        if not gated.ok:
            return _refuse_scan_gate(gated)
    except e:
        return _refuse_gate_unreadable(String(e))
    var order = List[Int]()
    var order_receipt = List[Bool]()
    var order_live = List[Bool]()
    var saw_bridge_mismatch = False
    var saw_noted_bridge_mismatch = False
    if want_explicit:
        order.append(0)
        order_receipt.append(False)
        order_live.append(_live_doc(candidates[0]))
    else:
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                order.append(i)
                order_receipt.append(False)
                order_live.append(False)
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
                root,
                sha,
                lc.sha,
                cp.sha,
            ):
                order.append(i)
                order_receipt.append(True)
                order_live.append(False)
            elif mism:
                saw_bridge_mismatch = True
                if not _live_doc(candidates[i]):
                    saw_noted_bridge_mismatch = True
        for i in range(len(candidates)):
            if candidates[i].status == String("validated"):
                continue
            if _live_doc(candidates[i]):
                order.append(i)
                order_receipt.append(False)
                order_live.append(True)
    var skip_reason = String("")
    var skip_code = String("profile")
    var skip_unknown = False
    for oi in range(len(order)):
        var doc = candidates[order[oi]].copy()
        var gap = _selection_gap(doc, ask.caps)
        if gap != String(""):
            if want_explicit:
                return _refuse_scan(gap)
            skip_reason = gap.copy()
            skip_code = String("profile")
            skip_unknown = False
            continue
        var tgap = tracing_gap(doc, ask.caps)
        if tgap != String(""):
            if want_explicit:
                return _refuse_scan(tgap)
            skip_reason = tgap.copy()
            skip_code = String("profile")
            skip_unknown = False
            continue
        var hook = ProfileHook()
        var raw = List[UInt8]()
        var sys = String("")
        var evt = String("")
        var probe = OffsetProbe()
        var herr = _admit_hook(
            root, doc.copy(), hook, raw, sys, evt, probe
        )
        if herr != String(""):
            if want_explicit:
                return _refuse_scan(herr)
            skip_reason = herr.copy()
            skip_code = String("profile")
            skip_unknown = False
            continue
        if order_live[oi]:
            var live = verify_live_interfaces(
                root, doc.copy(), ask.caps.copy()
            )
            if not live.ok:
                if want_explicit:
                    if want_extra:
                        return _refuse_scan_live(
                            String("live check failed: ") + live.reason,
                            live.code.copy(),
                            live.unknown,
                        )
                    out.ok = True
                    out.kind = String("partial")
                    out.reason = (
                        String("explicit ")
                        + doc.profile_id.copy()
                        + String(" (reference, live check failed: ")
                        + live.reason
                        + String(")")
                    )
                    out.profile = doc.copy()
                    out.hook = hook.copy()
                    out.object_sha = sha.copy()
                    out.ring_bytes = ring
                    out.off_loc = probe.loc_off
                    out.off_size = probe.size_off
                    out.off_force = probe.force_off
                    out.off_fixed_end = probe.fixed_end
                    out.elf = elf.copy()
                    out.tp_system = sys.copy()
                    out.tp_event = evt.copy()
                    out.selected_caps = selected.copy()
                    return out^
                skip_reason = (
                    String("live check failed: ") + live.reason
                )
                skip_code = _live_skip_code(live.code.copy())
                skip_unknown = live.unknown
                continue
            out.layout_evidence = live.evidence.copy()
            var measured = _measure_binding(
                root, kernel.release, hook.copy(), Span(raw)
            )
            out.ok = True
            out.kind = String("candidate")
            out.reason = (
                String("candidate ")
                + doc.profile_id.copy()
                + String(": live interfaces verified (profile unvalidated)")
            )
            out.profile = doc.copy()
            out.hook = hook.copy()
            out.object_sha = sha.copy()
            out.ring_bytes = ring
            out.off_loc = probe.loc_off
            out.off_size = probe.size_off
            out.off_force = probe.force_off
            out.off_fixed_end = probe.fixed_end
            out.elf = elf.copy()
            out.tp_system = sys.copy()
            out.tp_event = evt.copy()
            out.measured_config = measured.config.copy()
            out.measured_config_src = measured.config_src.copy()
            out.measured_btf = measured.btf.copy()
            out.measured_format = measured.format.copy()
            out.measured_image = measured.image.copy()
            out.measured_image_bid = measured.image_bid.copy()
            out.selected_caps = selected.copy()
            out.lc.present = want_lc
            out.cp.present = want_cp
            if want_lc:
                out.lc.elf = lc.elf.copy()
                out.lc.object_sha = lc.sha.copy()
                out.lc.ring_bytes = lc.ring
            if want_cp:
                out.cp.elf = cp.elf.copy()
                out.cp.object_sha = cp.sha.copy()
                out.cp.ring_bytes = cp.ring
            return out^
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
                out.off_loc = probe.loc_off
                out.off_size = probe.size_off
                out.off_force = probe.force_off
                out.off_fixed_end = probe.fixed_end
                out.elf = elf.copy()
                out.tp_system = sys.copy()
                out.tp_event = evt.copy()
                out.selected_caps = selected.copy()
                return out^
            skip_reason = String("binding failed: ") + parsed.message
            skip_code = String("profile")
            skip_unknown = False
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
            skip_code = String("profile")
            skip_unknown = False
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
        out.off_loc = probe.loc_off
        out.off_size = probe.size_off
        out.off_force = probe.force_off
        out.off_fixed_end = probe.fixed_end
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
        out.lc.present = want_lc
        out.cp.present = want_cp
        if want_lc:
            out.lc.elf = lc.elf.copy()
            out.lc.object_sha = lc.sha.copy()
            out.lc.ring_bytes = lc.ring
        if want_cp:
            out.cp.elf = cp.elf.copy()
            out.cp.object_sha = cp.sha.copy()
            out.cp.ring_bytes = cp.ring
        return out^
    # Scan mode only: explicit always returns inside the loop.
    if want_extra:
        if bridge_sha == String("") and saw_noted_bridge_mismatch:
            return _refuse_scan_live(
                String("bridge unchecked: cannot verify receipts"),
                String("bridge-unchecked"),
                True,
            )
        if skip_reason == String(""):
            return _refuse_scan(
                String("no profile satisfies requested capabilities")
            )
        return _refuse_scan_live(
            skip_reason.copy(), skip_code.copy(), skip_unknown
        )
    var first = candidates[0].copy()
    var phook = ProfileHook()
    var praw = List[UInt8]()
    var psys = String("")
    var pevt = String("")
    var pprobe = OffsetProbe()
    var perr = _admit_hook(
        root, first.copy(), phook, praw, psys, pevt, pprobe
    )
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
    out.off_loc = pprobe.loc_off
    out.off_size = pprobe.size_off
    out.off_force = pprobe.force_off
    out.off_fixed_end = pprobe.fixed_end
    out.elf = elf.copy()
    out.tp_system = psys.copy()
    out.tp_event = pevt.copy()
    out.selected_caps = selected.copy()
    return out^


def loadcheck_bridge_sha(bridge: String, has_bridge: Bool) -> String:
    """Sha256 of the resolved bridge, else "" when unreadable.

    Load-check admission binds receipts to the resolved
    bridge bytes; an unresolvable bridge leaves every
    receipt unchecked.
    """
    var path = resolve_bridge(bridge, has_bridge)
    var snap = open_bridge_snapshot(path)
    return snap.sha.copy()


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


def _read_boot_id(root: String, mut boot_id: String) -> Bool:
    """Live boot id when present and well-formed, else False."""
    var raw: List[UInt8]
    try:
        raw = read_host_file(
            join_root(root, String("/proc/sys/kernel/random/boot_id")),
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


def attempt_loss_evidence(release: String) -> List[EvidenceItem]:
    """Attempt-loss bound item on kernels before 6.7, else empty."""
    var out = List[EvidenceItem]()
    if attempt_loss_exact(release):
        return out^
    var item = EvidenceItem()
    item.item_type = String("attempt-loss-bound")
    item.source = String("kernel ") + release
    item.interpretation = String(
        "attempt loss counts are a lower bound before 6.7:"
        " trace_call_bpf skipped programs without counting them"
    )
    out.append(item^)
    return out^


def _append_channel_evidence(
    mut evidence: List[EvidenceItem], name: String, channel: ExtraChannel
):
    """Append one present channel's hash and ring provenance.

    Lifecycle and copy channels report the identical pair
    (``<name>.object.sha256``, ``<name>.ring.bytes``);
    absent channels append nothing.
    """
    if not channel.present:
        return
    evidence.append(
        _value_item(
            name + String(".object.sha256"),
            channel.object_sha.copy(),
        )
    )
    evidence.append(
        _value_item(
            name + String(".ring.bytes"),
            String(channel.ring_bytes),
        )
    )


def _append_layout_evidence(
    mut evidence: List[EvidenceItem], lines: List[String]
):
    """Append one layout item per checked CO-RE layout line.

    Each line was verified against kernel BTF by the live
    layout check; the item names that source.
    """
    for i in range(len(lines)):
        var item = EvidenceItem()
        item.item_type = String("layout")
        item.source = String("kernel BTF")
        item.interpretation = lines[i].copy()
        evidence.append(item^)


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
            String(""),
            String(""),
            False,
            True,
        )
    if opts.max_events_bytes > MAX_RECORD_BYTES:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String(t"budget {opts.max_events_bytes} above 4294967296"),
            String(""),
            String(""),
            False,
            True,
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
            String(""),
            String(""),
            False,
            True,
        )
    # One resolution, pinned once: the snapshot's open
    # file description feeds the admission hash, the
    # provenance below, and the loader, so no pathname
    # swap can slip a different bridge between the
    # receipt check and the load. An unreadable bridge
    # hashes to "": receipts cannot admit local-auto, and
    # provenance marks the identity uncheckable. The
    # keep-alive touch after the collector run below
    # holds the fd through every open_session; scope
    # alone does not (Mojo destroys after its last use).
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
            String(""),
            String(""),
            False,
            True,
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
            String(""),
            String(""),
            False,
            False,
        )
    var env = detect_environment(reader)
    if not env.kernel.eligible_floor:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("kernel ")
            + env.kernel.release
            + String(" below floor 6.0"),
            String(""),
            String(""),
            False,
            True,
        )
    var profiles: List[Profile]
    try:
        profiles = load_profiles(profiles_dir)
    except e:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("cannot load profiles: ") + String(e),
            String(""),
            String(""),
            False,
            False,
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
            decision.fix.copy(),
            decision.refusal_code.copy(),
            decision.refusal_unknown,
            True,
        )
    var timens = check_timens_live()
    if not timens.ok:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("time namespace unverifiable"),
            String(""),
            String(""),
            False,
            True,
        )
    if timens.offset:
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("time namespace offset present"),
            String(""),
            String(""),
            False,
            True,
        )
    if (
        decision.off_loc < 0
        or decision.off_size < 0
        or decision.off_force < 0
        or decision.off_fixed_end < 0
    ):
        return RunResult(
            EXIT_REFUSAL, String(""), String(""),
            String("admission did not probe offsets"),
            String(""),
            String(""),
            False,
            True,
        )
    var cfg = CollectorConfig()
    cfg.duration_s = opts.duration_s
    cfg.max_events_bytes = opts.max_events_bytes
    cfg.output = opts.output
    cfg.profile_id = decision.profile.profile_id.copy()
    cfg.grade = decision.kind.copy()
    cfg.off_loc = decision.off_loc
    cfg.off_size = decision.off_size
    cfg.off_force = decision.off_force
    cfg.off_fixed_end = decision.off_fixed_end
    # Live captures sample the default SWIOTLB pool counters at
    # start, periodically, and close; unreadable counters stay
    # in the samples as unavailable halves, never as failed runs.
    cfg.has_pool_sample = True
    cfg.pid = Int(external_call["getpid", Int32]())
    cfg.has_ring_bytes = True
    cfg.ring_bytes = UInt32(decision.ring_bytes)
    cfg.has_lifecycle = decision.lc.present
    cfg.lifecycle_ring_bytes = UInt32(decision.lc.ring_bytes)
    cfg.has_copy = decision.cp.present
    cfg.copy_ring_bytes = UInt32(decision.cp.ring_bytes)
    cfg.has_device_filter = opts.has_device
    cfg.device_filter = opts.device
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
    var loss_bound = attempt_loss_evidence(env.kernel.release)
    for i in range(len(loss_bound)):
        cfg.evidence.append(loss_bound[i].copy())
    cfg.attempt_loss_lower_bound = not attempt_loss_exact(
        env.kernel.release
    )
    _append_channel_evidence(
        cfg.evidence, String("lc"), decision.lc
    )
    _append_channel_evidence(
        cfg.evidence, String("cp"), decision.cp
    )
    _append_layout_evidence(cfg.evidence, decision.layout_evidence)
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
        decision.lc.elf.copy(),
        decision.lc.present,
        decision.cp.elf.copy(),
        decision.cp.present,
        snap.load_path,
    )
    var clock = MonoClock()
    var signal = LiveSignalSource()
    var collector = Collector(cfg^)
    var out = collector.run(kernel, clock, signal, writer)
    # Retain the bridge pin through every open_session
    # inside the run above and the load replay below:
    # this explicit use keeps the fd open while the
    # loader dlopens the alias.
    _ = snap.fd
    if _is_load_errno_failure(out.diagnostic):
        var fail_ch = _load_fail_channel(out.diagnostic)
        var diag: LoadDiag
        if fail_ch == 1:
            diag = diagnose_load(
                Span(decision.lc.elf),
                snap.load_path,
                lifecycle_program_names(),
            )
        elif fail_ch == 2:
            diag = diagnose_load(
                Span(decision.cp.elf),
                snap.load_path,
                copy_program_names(),
            )
        else:
            diag = diagnose_load(
                Span(decision.elf),
                snap.load_path,
                attempt_program_names(),
            )
        for i in range(len(diag.lines)):
            out.diagnostic += String("\n") + diag.lines[i]
    if out.exit_code == EXIT_REFUSAL and out.code == String(""):
        var lcode = load_refusal_code(out.diagnostic)
        if lcode != String(""):
            out.code = lcode^
            out.fix = remedy_for(out.code.copy())
    return out^


def ownership_warning(uid: Int, gid: Int) -> String:
    """Warn-once line for a failed ownership repair, with newline.

    The record-flow wording stays fixed across callers:
    live top and the qualify smoke reuse the record
    flow, so their repair warnings keep the record
    prefix, as before.
    """
    return (
        String("memveil record: warning: cannot restore ")
        + String("capture ownership to ")
        + String(uid)
        + String(":")
        + String(gid)
        + String("\n")
    )


def repair_warning_for[W: WriterSource](
    output: String, writer: W
) -> String:
    """Restore a finalized capture's ownership; warn, or "".

    Best-effort hand-back of a root-made capture to the
    invoking user through the writer's finalize pin
    (dev/inode continuity; only the recorded dir and
    files transfer). Returns the warn-once line when an
    attempted repair did not hold, else "": the capture
    stands either way. Call only for a finalized
    outcome; never raises.
    """
    var repair = restore_capture_ownership(
        output, writer.finalized_identity()
    )
    if repair.attempted and not repair.repaired:
        return ownership_warning(repair.uid, repair.gid)
    return String("")
