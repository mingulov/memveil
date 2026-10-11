# SPDX-License-Identifier: GPL-3.0-or-later

"""Semantic profiles: exact-identity collection manifests.

``parse_profile_bytes`` validates one profile JSON document against
the profile-v0.1.1 rules. Parsing is strict: unknown keys,
duplicates, overlong text, bad enums, and capability hook names
that resolve to nothing are all rejected.

``load_profiles`` reads ``<dir>/manifest.txt`` (one filename per
line, strict grammar, no path separators) and parses each profile
in order. Only manifest-listed profiles are admitted.

``select_profile`` matches kernel identity against profiles in
manifest order: ``arch`` must equal and the release triple must
reach ``min_kernel``. ``matched`` is True only for validated
profiles; a covering reference-unvalidated profile yields
``matched`` False with a reason that says so. An unparseable
release covers nothing.
"""

from memveil.jsonscan import Scanner
from memveil.model.common import (
    MaybeString,
    array_is_empty,
    array_next,
    expect_colon,
    object_is_empty,
    object_next,
    parse_maybe_string,
)
from memveil.model.validate import ValidationError, check_bounded_text
from memveil.platform.btf import read_btf_func_proto
from memveil.platform.evidence import KernelInfo, parse_kernel_triple
from memveil.platform.narrow import (
    NarrowBindings,
    check_identity_bindings,
    is_sha256_value,
    parse_narrow_note,
)
from memveil.platform.reader import bytes_to_text, read_host_file
from memveil.render.json import escape_json


comptime PROFILE_SCHEMA_VERSION = "0.1.1"
comptime MAX_PROFILE_HOOKS = 32
comptime MAX_PROFILE_CAPS = 16
comptime MAX_PROFILE_NOTES = 32
comptime MAX_CAP_HOOKS = 32
comptime _MANIFEST_CAP = 65536
comptime _PROFILE_CAP = 1048576
comptime _INSTALLED_PROFILES_DIR = "/usr/share/memveil/profiles"
comptime _INSTALLED_RECEIPTS_DIR = "/var/lib/memveil/receipts"


struct ProfileHook(Copyable):
    """One hook named by a profile: tracepoint paths or tracing binding.

    Tracepoint hooks carry id/format paths plus optional layout
    text; tracing hooks carry the frozen function identity
    (function, attach, signature) instead. Each kind forbids
    the other's fields.
    """

    var name: String
    var kind: String
    var id_path: String
    var format_path: String
    var format_has: Bool
    var format_text: String
    var function: String
    var attach: String
    var signature: String
    var has_note: Bool
    var note: String

    def __init__(out self):
        self.name = String("")
        self.kind = String("")
        self.id_path = String("")
        self.format_path = String("")
        self.format_has = False
        self.format_text = String("")
        self.function = String("")
        self.attach = String("")
        self.signature = String("")
        self.has_note = False
        self.note = String("")


struct ProfileCapability(Copyable):
    """One capability declaration: support level plus hook refs."""

    var id: String
    var status: String
    var hooks: List[String]
    var reason: String

    def __init__(out self):
        self.id = String("")
        self.status = String("")
        self.hooks = List[String]()
        self.reason = String("")


struct ProfileSource(Copyable):
    """The source identity a profile claims (origin plus revision)."""

    var origin: String
    var revision: String
    var has_note: Bool
    var note: String

    def __init__(out self):
        self.origin = String("")
        self.revision = String("")
        self.has_note = False
        self.note = String("")


struct ProfileIdentity(Copyable):
    """Kernel identity a profile covers: arch plus kernel floor."""

    var arch: String
    var min_kernel: String
    var min_major: Int
    var min_minor: Int
    var min_patch: Int
    var source: ProfileSource
    var has_note: Bool
    var note: String

    def __init__(out self):
        self.arch = String("")
        self.min_kernel = String("")
        self.min_major = 0
        self.min_minor = 0
        self.min_patch = 0
        self.source = ProfileSource()
        self.has_note = False
        self.note = String("")


struct Profile(Copyable):
    """One validated profile manifest."""

    var profile_id: String
    var status: String
    var identity: ProfileIdentity
    var hooks: List[ProfileHook]
    var caps: List[ProfileCapability]
    var notes: List[String]

    def __init__(out self):
        self.profile_id = String("")
        self.status = String("")
        self.identity = ProfileIdentity()
        self.hooks = List[ProfileHook]()
        self.caps = List[ProfileCapability]()
        self.notes = List[String]()


struct ProfileDecision(Copyable):
    """The outcome of matching kernel identity against profiles.

    ``matched`` is True only when a validated profile binds or
    a reference profile matches with a verifying receipt.
    ``has_profile`` is True whenever any profile (even a
    reference one) covers the identity; then ``profile`` is
    that manifest in full. ``reason`` always explains the
    outcome. ``grade`` is "validated", "local-auto", or ""
    when unmatched; ``receipt_caps`` lists the receipt's
    qualified ids on a local-auto match and stays empty
    otherwise.
    """

    var matched: Bool
    var has_profile: Bool
    var profile: Profile
    var reason: String
    var grade: String
    var receipt_caps: List[String]

    def __init__(
        out self,
        matched: Bool,
        has_profile: Bool,
        profile: Profile,
        reason: String,
        grade: String,
        receipt_caps: List[String],
    ):
        self.matched = matched
        self.has_profile = has_profile
        self.profile = profile.copy()
        self.reason = reason.copy()
        self.grade = grade.copy()
        self.receipt_caps = receipt_caps.copy()


struct SigVerdict(Copyable):
    """Frozen-vs-live signature verdict for one tracing hook.

    ``ok`` is True only when the frozen signature normalizes
    and spells exactly the live BTF prototype. ``live`` holds
    the live canonical spelling ("" when BTF is unreadable)
    so callers can show both sides of a mismatch.
    """

    var hook: String
    var ok: Bool
    var reason: String
    var live: String

    def __init__(out self):
        self.hook = String("")
        self.ok = False
        self.reason = String("")
        self.live = String("")


def _check_profile_id(v: String) raises:
    """Check a profile_id against ^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$."""
    try:
        check_bounded_text(v, 1, 128, "profile_id")
    except e:
        raise ValidationError("profile_id", String(e))
    var first = True
    for b in v.as_bytes():
        var ok = (b >= UInt8(0x41) and b <= UInt8(0x5A)) or (
            b >= UInt8(0x61) and b <= UInt8(0x7A)
        ) or (b >= UInt8(0x30) and b <= UInt8(0x39)) or b == UInt8(
            0x5F
        ) or (not first and (b == UInt8(0x2E) or b == UInt8(0x2D)))
        if not ok:
            raise ValidationError("profile_id", "bad charset")
        first = False


def _parse_min_kernel(v: String) raises -> ProfileIdentity:
    """Parse ``major.minor[.patch]`` and stash it on a blank identity.

    The whole string must match: leading digits, one dot, digits,
    an optional second dot plus digits, then the end. Anything
    else (empty parts, extra dots, trailing text) is rejected.
    """
    var parts = List[Int]()
    var acc = 0
    var have_digit = False
    for b in v.as_bytes():
        if b >= UInt8(0x30) and b <= UInt8(0x39):
            var digit = Int(b) - 0x30
            if acc > (2147483647 - digit) // 10:
                raise ValidationError("min_kernel", "component too large")
            acc = acc * 10 + digit
            have_digit = True
        elif b == UInt8(0x2E):
            if not have_digit or len(parts) >= 2:
                raise ValidationError("min_kernel", "bad shape")
            parts.append(acc)
            acc = 0
            have_digit = False
        else:
            raise ValidationError("min_kernel", "bad charset")
    if not have_digit:
        raise ValidationError("min_kernel", "bad shape")
    parts.append(acc)
    if len(parts) < 2 or len(parts) > 3:
        raise ValidationError("min_kernel", "bad shape")
    var out = ProfileIdentity()
    out.min_kernel = v
    out.min_major = parts[0]
    out.min_minor = parts[1]
    if len(parts) > 2:
        out.min_patch = parts[2]
    return out^


def _check_hook_path(v: String, what: String) raises:
    """Check an absolute hook path: rooted, canonical segments.

    Must start with ``/``; every ``/``-separated segment must be
    non-empty and neither ``.`` nor ``..``, so profile paths
    cannot escape the evidence root they resolve against. NUL
    bytes are rejected outright: libc truncates paths at NUL, so
    a NUL would smuggle a different path past validation.
    """
    for b in v.as_bytes():
        if b == UInt8(0):
            raise ValidationError(what, "nul byte")
    var parts = v.split(String("/"))
    if len(parts) < 2:
        raise ValidationError(what, "not absolute")
    if String(parts[0]).byte_length() != 0:
        raise ValidationError(what, "not absolute")
    for i in range(1, len(parts)):
        var seg = String(parts[i])
        if seg.byte_length() == 0:
            raise ValidationError(what, "empty segment")
        if seg == "." or seg == "..":
            raise ValidationError(what, "dot segment")


def _check_function(v: String) raises:
    """Check a tracing function name: C identifier, 1..128 chars."""
    try:
        check_bounded_text(v, 1, 128, "hook.function")
    except e:
        raise ValidationError("hook.function", String(e))
    var first = True
    for b in v.as_bytes():
        var ok = (
            (b >= UInt8(0x41) and b <= UInt8(0x5A))
            or (b >= UInt8(0x61) and b <= UInt8(0x7A))
            or b == UInt8(0x5F)
            or (not first and b >= UInt8(0x30) and b <= UInt8(0x39))
        )
        if not ok:
            raise ValidationError("hook.function", "bad charset")
        first = False


def _parse_source(mut scan: Scanner) raises -> ProfileSource:
    """Parse the identity.source object: origin, revision, note?."""
    scan.begin_object()
    var out = ProfileSource()
    var has_origin = False
    var has_revision = False
    var has_note = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "source")
            if key == "origin":
                if has_origin:
                    raise ValidationError("source.origin", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 64, "source.origin")
                except e:
                    raise ValidationError("source.origin", String(e))
                out.origin = v
                has_origin = True
            elif key == "revision":
                if has_revision:
                    raise ValidationError("source.revision", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 128, "source.revision")
                except e:
                    raise ValidationError("source.revision", String(e))
                out.revision = v
                has_revision = True
            elif key == "note":
                if has_note:
                    raise ValidationError("source.note", "duplicate")
                var v = scan.parse_string()
                try:
                    # Twelve-field narrow notes need ~700
                    # chars; 8-field notes stay valid.
                    check_bounded_text(v, 0, 1024, "source.note")
                except e:
                    raise ValidationError("source.note", String(e))
                out.note = v
                out.has_note = True
                has_note = True
            else:
                raise ValidationError("source", "unknown source field")
            if not object_next(scan, "source"):
                break
    scan.end_object()
    if not has_origin or not has_revision:
        raise ValidationError("source", "missing field")
    return out^


def _parse_identity(mut scan: Scanner) raises -> ProfileIdentity:
    """Parse the identity object: arch, min_kernel, source, note?."""
    scan.begin_object()
    var out = ProfileIdentity()
    var has_arch = False
    var has_min = False
    var has_source = False
    var has_note = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "identity")
            if key == "arch":
                if has_arch:
                    raise ValidationError("identity.arch", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 32, "identity.arch")
                except e:
                    raise ValidationError("identity.arch", String(e))
                out.arch = v
                has_arch = True
            elif key == "min_kernel":
                if has_min:
                    raise ValidationError("identity.min_kernel", "duplicate")
                var v = scan.parse_string()
                var parsed = _parse_min_kernel(v)
                out.min_kernel = parsed.min_kernel
                out.min_major = parsed.min_major
                out.min_minor = parsed.min_minor
                out.min_patch = parsed.min_patch
                has_min = True
            elif key == "source":
                if has_source:
                    raise ValidationError("identity.source", "duplicate")
                out.source = _parse_source(scan)
                has_source = True
            elif key == "note":
                if has_note:
                    raise ValidationError("identity.note", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 0, 512, "identity.note")
                except e:
                    raise ValidationError("identity.note", String(e))
                out.note = v
                out.has_note = True
                has_note = True
            else:
                raise ValidationError("identity", "unknown identity field")
            if not object_next(scan, "identity"):
                break
    scan.end_object()
    if not has_arch or not has_min or not has_source:
        raise ValidationError("identity", "missing field")
    return out^


def _parse_hook(mut scan: Scanner) raises -> ProfileHook:
    """Parse one hooks[] item: name, kind, kind-shaped fields, note?.

    Tracepoint hooks need id/format paths with optional
    layout text; tracing hooks need the frozen function
    identity (function, attach, signature). Each kind
    forbids the other's fields.
    """
    scan.begin_object()
    var out = ProfileHook()
    var has_name = False
    var has_kind = False
    var has_id = False
    var has_format = False
    var has_text = False
    var has_function = False
    var has_attach = False
    var has_signature = False
    var has_note = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "hook")
            if key == "name":
                if has_name:
                    raise ValidationError("hook.name", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 128, "hook.name")
                except e:
                    raise ValidationError("hook.name", String(e))
                out.name = v
                has_name = True
            elif key == "kind":
                if has_kind:
                    raise ValidationError("hook.kind", "duplicate")
                var v = scan.parse_string()
                if v != "tracepoint" and v != "tracing":
                    raise ValidationError("hook.kind", "bad const")
                out.kind = v
                has_kind = True
            elif key == "id_path":
                if has_id:
                    raise ValidationError("hook.id_path", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 256, "hook.id_path")
                except e:
                    raise ValidationError("hook.id_path", String(e))
                _check_hook_path(v, "hook.id_path")
                out.id_path = v
                has_id = True
            elif key == "format_path":
                if has_format:
                    raise ValidationError("hook.format_path", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 256, "hook.format_path")
                except e:
                    raise ValidationError("hook.format_path", String(e))
                _check_hook_path(v, "hook.format_path")
                out.format_path = v
                has_format = True
            elif key == "format_text":
                if has_text:
                    raise ValidationError("hook.format_text", "duplicate")
                var m = parse_maybe_string(scan)
                if m.has:
                    try:
                        check_bounded_text(
                            m.value, 0, 65536, "hook.format_text"
                        )
                    except e:
                        raise ValidationError(
                            "hook.format_text", String(e)
                        )
                    out.format_text = m.value
                    out.format_has = True
                has_text = True
            elif key == "function":
                if has_function:
                    raise ValidationError("hook.function", "duplicate")
                var v = scan.parse_string()
                _check_function(v)
                out.function = v
                has_function = True
            elif key == "attach":
                if has_attach:
                    raise ValidationError("hook.attach", "duplicate")
                var v = scan.parse_string()
                if v != "fentry" and v != "fexit":
                    raise ValidationError("hook.attach", "bad const")
                out.attach = v
                has_attach = True
            elif key == "signature":
                if has_signature:
                    raise ValidationError("hook.signature", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 1024, "hook.signature")
                except e:
                    raise ValidationError("hook.signature", String(e))
                out.signature = v
                has_signature = True
            elif key == "note":
                if has_note:
                    raise ValidationError("hook.note", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 0, 512, "hook.note")
                except e:
                    raise ValidationError("hook.note", String(e))
                out.note = v
                out.has_note = True
                has_note = True
            else:
                raise ValidationError("hook", "unknown hook field")
            if not object_next(scan, "hook"):
                break
    scan.end_object()
    if not has_name or not has_kind:
        raise ValidationError("hook", "missing field")
    if out.kind == String("tracing"):
        if has_id or has_format or has_text:
            raise ValidationError("hook", "tracepoint field on tracing")
        if not has_function or not has_attach or not has_signature:
            raise ValidationError("hook", "missing field")
    else:
        if has_function or has_attach or has_signature:
            raise ValidationError("hook", "tracing field on tracepoint")
        if not has_id or not has_format:
            raise ValidationError("hook", "missing field")
    return out^


def _parse_capability(mut scan: Scanner) raises -> ProfileCapability:
    """Parse one capabilities[] item: id, status, hooks, reason."""
    scan.begin_object()
    var out = ProfileCapability()
    var has_id = False
    var has_status = False
    var has_hooks = False
    var has_reason = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "capability")
            if key == "id":
                if has_id:
                    raise ValidationError("capability.id", "duplicate")
                var v = scan.parse_string()
                if (
                    v != "attempt-trace"
                    and v != "mapping-lifecycle"
                    and v != "copy-actual"
                    and v != "conversion-observe"
                ):
                    raise ValidationError("capability.id", "bad enum")
                out.id = v
                has_id = True
            elif key == "status":
                if has_status:
                    raise ValidationError("capability.status", "duplicate")
                var v = scan.parse_string()
                if (
                    v != "candidate"
                    and v != "supported"
                    and v != "unsupported"
                ):
                    raise ValidationError("capability.status", "bad enum")
                out.status = v
                has_status = True
            elif key == "hooks":
                if has_hooks:
                    raise ValidationError("capability.hooks", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        var v = scan.parse_string()
                        try:
                            check_bounded_text(
                                v, 1, 128, "capability.hooks[]"
                            )
                        except e:
                            raise ValidationError(
                                "capability.hooks[]", String(e)
                            )
                        out.hooks.append(v)
                        if len(out.hooks) > MAX_CAP_HOOKS:
                            raise ValidationError(
                                "capability.hooks", "too many items"
                            )
                        if not array_next(scan, "capability.hooks"):
                            break
                scan.end_array()
                has_hooks = True
            elif key == "reason":
                if has_reason:
                    raise ValidationError("capability.reason", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 0, 512, "capability.reason")
                except e:
                    raise ValidationError("capability.reason", String(e))
                out.reason = v
                has_reason = True
            else:
                raise ValidationError(
                    "capability", "unknown capability field"
                )
            if not object_next(scan, "capability"):
                break
    scan.end_object()
    if not has_id or not has_status or not has_hooks or not has_reason:
        raise ValidationError("capability", "missing field")
    return out^


def parse_profile_bytes(data: List[UInt8]) raises -> Profile:
    """Parse and validate one profile JSON document."""
    var scan = Scanner(data)
    scan.skip_ws()
    scan.begin_object()
    var out = Profile()
    var has_version = False
    var has_id = False
    var has_status = False
    var has_identity = False
    var has_hooks = False
    var has_caps = False
    var has_notes = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "profile")
            if key == "schema_version":
                if has_version:
                    raise ValidationError("schema_version", "duplicate")
                var v = scan.parse_string()
                if v != PROFILE_SCHEMA_VERSION:
                    raise ValidationError("schema_version", "bad const")
                has_version = True
            elif key == "profile_id":
                if has_id:
                    raise ValidationError("profile_id", "duplicate")
                var v = scan.parse_string()
                _check_profile_id(v)
                out.profile_id = v
                has_id = True
            elif key == "status":
                if has_status:
                    raise ValidationError("status", "duplicate")
                var v = scan.parse_string()
                if v != "validated" and v != "reference-unvalidated":
                    raise ValidationError("status", "bad enum")
                out.status = v
                has_status = True
            elif key == "identity":
                if has_identity:
                    raise ValidationError("identity", "duplicate")
                out.identity = _parse_identity(scan)
                has_identity = True
            elif key == "hooks":
                if has_hooks:
                    raise ValidationError("hooks", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        var h = _parse_hook(scan)
                        for i in range(len(out.hooks)):
                            if out.hooks[i].name == h.name:
                                raise ValidationError(
                                    "hooks", "duplicate hook name"
                                )
                        out.hooks.append(h^)
                        if len(out.hooks) > MAX_PROFILE_HOOKS:
                            raise ValidationError(
                                "hooks", "too many items"
                            )
                        if not array_next(scan, "hooks"):
                            break
                scan.end_array()
                has_hooks = True
            elif key == "capabilities":
                if has_caps:
                    raise ValidationError("capabilities", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        var c = _parse_capability(scan)
                        for i in range(len(out.caps)):
                            if out.caps[i].id == c.id:
                                raise ValidationError(
                                    "capabilities", "duplicate capability id"
                                )
                        out.caps.append(c^)
                        if len(out.caps) > MAX_PROFILE_CAPS:
                            raise ValidationError(
                                "capabilities", "too many items"
                            )
                        if not array_next(scan, "capabilities"):
                            break
                scan.end_array()
                has_caps = True
            elif key == "notes":
                if has_notes:
                    raise ValidationError("notes", "duplicate")
                scan.begin_array()
                if not array_is_empty(scan):
                    while True:
                        scan.skip_ws()
                        var v = scan.parse_string()
                        try:
                            check_bounded_text(v, 0, 512, "notes[]")
                        except e:
                            raise ValidationError("notes[]", String(e))
                        out.notes.append(v)
                        if len(out.notes) > MAX_PROFILE_NOTES:
                            raise ValidationError(
                                "notes", "too many items"
                            )
                        if not array_next(scan, "notes"):
                            break
                scan.end_array()
                has_notes = True
            else:
                raise ValidationError("profile", "unknown profile field")
            if not object_next(scan, "profile"):
                break
    scan.end_object()
    if (
        not has_version
        or not has_id
        or not has_status
        or not has_identity
        or not has_hooks
        or not has_caps
    ):
        raise ValidationError("profile", "missing field")
    for i in range(len(out.caps)):
        for j in range(len(out.caps[i].hooks)):
            var need = out.caps[i].hooks[j]
            var known = False
            for k in range(len(out.hooks)):
                if out.hooks[k].name == need:
                    known = True
                    break
            if not known:
                raise ValidationError(
                    "capability.hooks", "unknown hook reference"
                )
    scan.skip_ws()
    if not scan.at_end():
        raise ValidationError("profile", "trailing data")
    return out^


def _check_manifest_name(name: String) raises:
    """Check one manifest filename: plain name, no path escape.

    Accepts ``[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`` with no leading
    dot, so ``/``, ``..``, and hidden files are all rejected and
    the name always resolves directly under the profiles dir.
    """
    try:
        check_bounded_text(name, 1, 128, "manifest")
    except e:
        raise ValidationError("manifest", String(e))
    var first = True
    for b in name.as_bytes():
        var ok = (b >= UInt8(0x41) and b <= UInt8(0x5A)) or (
            b >= UInt8(0x61) and b <= UInt8(0x7A)
        ) or (b >= UInt8(0x30) and b <= UInt8(0x39)) or b == UInt8(
            0x5F
        ) or (not first and (b == UInt8(0x2E) or b == UInt8(0x2D)))
        if not ok:
            raise ValidationError("manifest", "bad filename")
        first = False


struct NamedProfiles(Copyable, Movable):
    """Profiles plus their manifest entries, index-aligned.

    One manifest read produces both lists, so ``names[i]``
    is always the file ``profiles[i]`` was parsed from.
    Callers that re-resolve a planned document (the qualify
    smoke) use the entry to preserve document identity
    instead of resolving a bare id again.
    """

    var names: List[String]
    var profiles: List[Profile]

    def __init__(out self):
        self.names = List[String]()
        self.profiles = List[Profile]()


def load_profiles_named(dir: String) raises -> NamedProfiles:
    """Load every manifest-admitted profile with its entry.

    ``<dir>/manifest.txt`` holds one filename per line: no blank
    lines or padding (a single trailing newline is allowed), no
    duplicates. An empty manifest admits nothing, which the
    doctor reports as unknown coverage downstream.
    """
    var raw = read_host_file(
        dir + "/manifest.txt", "manifest.txt", _MANIFEST_CAP
    )
    var text = bytes_to_text(raw^)
    var names = List[String]()
    var lines = text.split(String("\n"))
    for i in range(len(lines)):
        var line = String(lines[i])
        if i == len(lines) - 1 and line.byte_length() == 0:
            break
        if line.byte_length() == 0:
            raise ValidationError("manifest", "blank line")
        _check_manifest_name(line)
        for j in range(len(names)):
            if names[j] == line:
                raise ValidationError("manifest", "duplicate entry")
        names.append(line)
    var out = NamedProfiles()
    for i in range(len(names)):
        var path = dir + "/" + names[i]
        var data = read_host_file(path, names[i], _PROFILE_CAP)
        try:
            var prof = parse_profile_bytes(data^)
            out.profiles.append(prof^)
        except e:
            raise ValidationError("profile " + names[i], String(e))
    out.names = names^
    return out^


def load_profiles(dir: String) raises -> List[Profile]:
    """Load every manifest-admitted profile under dir, in order.

    ``<dir>/manifest.txt`` holds one filename per line: no blank
    lines or padding (a single trailing newline is allowed), no
    duplicates. An empty manifest admits nothing, which the
    doctor reports as unknown coverage downstream.
    """
    var named = load_profiles_named(dir)
    var out = named.profiles.copy()
    return out^


def _triple_ge(
    major: Int, minor: Int, patch: Int,
    want_major: Int, want_minor: Int, want_patch: Int
) -> Bool:
    """True when (major, minor, patch) reaches the wanted triple."""
    if major != want_major:
        return major > want_major
    if minor != want_minor:
        return minor > want_minor
    return patch >= want_patch


def select_profile(
    kernel: KernelInfo, profiles: List[Profile]
) -> ProfileDecision:
    """Match kernel identity against profiles in manifest order.

    The first covering profile wins: ``arch`` must equal and the
    release triple must reach ``min_kernel``. ``matched`` is True
    only for validated profiles. Never raises: an unparseable
    release simply covers nothing.
    """
    if len(profiles) == 0:
        return ProfileDecision(
            False,
            False,
            Profile(),
            String("no profiles admitted"),
            String(""),
            List[String](),
        )
    var triple = parse_kernel_triple(kernel.release)
    if not triple.ok:
        return ProfileDecision(
            False,
            False,
            Profile(),
            "release " + kernel.release + " is unparseable; no coverage",
            String(""),
            List[String](),
        )
    for i in range(len(profiles)):
        var covered = profiles[i].identity.arch == kernel.arch
        if covered:
            covered = _triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                profiles[i].identity.min_major,
                profiles[i].identity.min_minor,
                profiles[i].identity.min_patch
            )
        if covered:
            if profiles[i].status == "validated":
                return ProfileDecision(
                    True,
                    True,
                    profiles[i].copy(),
                    "profile "
                    + profiles[i].profile_id
                    + " matched (validated)",
                    String("validated"),
                    List[String](),
                )
            return ProfileDecision(
                False,
                True,
                profiles[i].copy(),
                "profile "
                + profiles[i].profile_id
                + " covers this identity but is reference-unvalidated",
                String(""),
                List[String](),
            )
    return ProfileDecision(
        False,
        False,
        Profile(),
        "no profile covers arch "
        + kernel.arch
        + " release "
        + kernel.release,
        String(""),
        List[String](),
    )


comptime ATTEMPT_TRACE_ID = "attempt-trace"
comptime LIFECYCLE_CAP_ID = "mapping-lifecycle"
comptime COPY_CAP_ID = "copy-actual"


struct TraceWant(Copyable):
    """One frozen tracing hook: name plus exact signature."""

    var name: String
    var function: String
    var attach: String
    var signature: String

    def __init__(
        out self, name: String, function: String, attach: String,
        signature: String,
    ):
        self.name = name
        self.function = function
        self.attach = attach
        self.signature = signature


def lc_trace() -> List[TraceWant]:
    """Frozen lifecycle tracing hooks; mirrors the hook freeze."""
    var out = List[TraceWant]()
    out.append(
        TraceWant(
            String("fexit:swiotlb_tbl_map_single"),
            String("swiotlb_tbl_map_single"),
            String("fexit"),
            String(
                "phys_addr_t swiotlb_tbl_map_single(struct device *dev,"
                " phys_addr_t orig_addr, size_t mapping_size,"
                " unsigned int alloc_align_mask,"
                " enum dma_data_direction dir, unsigned long attrs)"
            ),
        )
    )
    out.append(
        TraceWant(
            String("fentry:__swiotlb_tbl_unmap_single"),
            String("__swiotlb_tbl_unmap_single"),
            String("fentry"),
            String(
                "void __swiotlb_tbl_unmap_single(struct device *dev,"
                " phys_addr_t tlb_addr, size_t mapping_size,"
                " enum dma_data_direction dir, unsigned long attrs,"
                " struct io_tlb_pool *pool)"
            ),
        )
    )
    return out^


def cp_trace() -> List[TraceWant]:
    """Frozen copy tracing hooks; mirrors the hook freeze."""
    var out = List[TraceWant]()
    out.append(
        TraceWant(
            String("fentry:__swiotlb_sync_single_for_device"),
            String("__swiotlb_sync_single_for_device"),
            String("fentry"),
            String(
                "void __swiotlb_sync_single_for_device(struct device *dev,"
                " phys_addr_t tlb_addr, size_t size,"
                " enum dma_data_direction dir, struct io_tlb_pool *pool)"
            ),
        )
    )
    out.append(
        TraceWant(
            String("fentry:__swiotlb_sync_single_for_cpu"),
            String("__swiotlb_sync_single_for_cpu"),
            String("fentry"),
            String(
                "void __swiotlb_sync_single_for_cpu(struct device *dev,"
                " phys_addr_t tlb_addr, size_t size,"
                " enum dma_data_direction dir, struct io_tlb_pool *pool)"
            ),
        )
    )
    out.append(
        TraceWant(
            String("fentry:swiotlb_bounce"),
            String("swiotlb_bounce"),
            String("fentry"),
            String(
                "void swiotlb_bounce(struct device *dev,"
                " phys_addr_t tlb_addr, size_t size,"
                " enum dma_data_direction dir, struct io_tlb_pool *mem)"
            ),
        )
    )
    return out^


def tracing_gap(doc: Profile, caps: List[String]) -> String:
    """First reason the doc's tracing bindings fail, else "".

    Every hook named by a requested extra capability must
    be a tracing hook whose (function, attach) pair is a
    frozen member of that capability with the exact frozen
    signature text, and every frozen member must be named:
    no vacuous, partial, or substituted bindings. Live
    signature identity rides the whole-BTF binding checked
    later; this gate pins the document side exactly.
    Record admission and doctor availability share this
    one predicate so the two verbs cannot disagree about
    a document's tracing bindings.
    """
    for i in range(len(caps)):
        if caps[i] == String(ATTEMPT_TRACE_ID):
            continue
        var wants = cp_trace()
        if caps[i] == String(LIFECYCLE_CAP_ID):
            wants = lc_trace()
        var named = List[String]()
        for j in range(len(doc.caps)):
            if doc.caps[j].id == caps[i]:
                named = doc.caps[j].hooks.copy()
                break
        var seen = List[Bool]()
        for j in range(len(wants)):
            seen.append(False)
        for j in range(len(named)):
            var hook = ProfileHook()
            var found = False
            for k in range(len(doc.hooks)):
                if doc.hooks[k].name == named[j]:
                    hook = doc.hooks[k].copy()
                    found = True
                    break
            if not found:
                return (
                    String("capability ")
                    + caps[i]
                    + String(" names unknown hook ")
                    + named[j]
                )
            if hook.kind != String("tracing"):
                return (
                    String("capability ")
                    + caps[i]
                    + String(" hook ")
                    + named[j]
                    + String(" is not a tracing hook")
                )
            var member = -1
            for k in range(len(wants)):
                if (
                    wants[k].function == hook.function
                    and wants[k].attach == hook.attach
                ):
                    member = k
                    break
            if member < 0:
                return (
                    String("capability ")
                    + caps[i]
                    + String(" hook ")
                    + named[j]
                    + String(" binds no frozen ")
                    + caps[i]
                    + String(" hook")
                )
            if hook.signature != wants[member].signature:
                return (
                    String("capability ")
                    + caps[i]
                    + String(" hook ")
                    + named[j]
                    + String(" signature mismatch")
                )
            seen[member] = True
        for j in range(len(wants)):
            if not seen[j]:
                return (
                    String("capability ")
                    + caps[i]
                    + String(" missing frozen hook ")
                    + wants[j].name
                )
    return String("")


struct HookSelection(Copyable):
    """Attempt-hook selection: ok plus hook, else refusal."""

    var ok: Bool
    var refusal: String
    var hook: ProfileHook

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.hook = ProfileHook()


def select_attempt_hook(profile: Profile) -> HookSelection:
    """Select the attempt-trace hook of one profile.

    The hook named by the attempt-trace capability wins;
    otherwise the first tracepoint hook. Anything else
    refuses: capture needs exactly one tracepoint site.
    Shared by record admission and binding-aware selection
    so both judge the same hook; refusal strings are pinned
    by the scan suite.
    """
    var out = HookSelection()
    var want = String("")
    for i in range(len(profile.caps)):
        if profile.caps[i].id == String(ATTEMPT_TRACE_ID):
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


def _normalize_frozen_signature(
    frozen: String, function: String
) -> MaybeString:
    """Strip the function name from a frozen signature.

    Frozen form is "<ret> <name>(<params>)"; the normalized
    form "<ret> (<params>)" compares directly with the BTF
    canonical spelling. Anything else (no paren, name not
    immediately before it, empty return type, trailing
    bytes) yields no value: the frozen text is malformed.
    """
    var out = MaybeString()
    var fb = frozen.as_bytes()
    var nb = function.as_bytes()
    if len(fb) == 0 or len(nb) == 0:
        return out^
    var open = -1
    for i in range(len(fb)):
        if fb[i] == UInt8(0x28):
            open = i
            break
    if open < 0 or fb[len(fb) - 1] != UInt8(0x29):
        return out^
    var need = len(nb) + 1
    if open < need + 1:
        return out^
    if fb[open - need] != UInt8(0x20):
        return out^
    for i in range(len(nb)):
        if fb[open - len(nb) + i] != nb[i]:
            return out^
    try:
        var ret = String(from_utf8=fb[0 : open - need])
        var tail = String(from_utf8=fb[open + 1 : len(fb)])
        out.value = ret + String(" (") + tail
        out.has = True
    except:
        pass
    return out^


def verify_hook_signatures(
    profile: Profile, btf: Span[UInt8, _]
) -> List[SigVerdict]:
    """Compare frozen tracing signatures against live BTF bytes.

    One verdict per tracing hook in profile order; tracepoint
    hooks are skipped (their tracefs layout is checked
    separately). A verdict is ok only when the frozen
    signature normalizes and spells exactly the live BTF
    prototype; every refusal names the hook and the cause.
    """
    var out = List[SigVerdict]()
    for i in range(len(profile.hooks)):
        var h = profile.hooks[i].copy()
        if h.kind != String("tracing"):
            continue
        var v = SigVerdict()
        v.hook = h.name.copy()
        var norm = _normalize_frozen_signature(h.signature, h.function)
        if not norm.has:
            v.reason = String(t"{h.name}: frozen signature malformed")
            out.append(v.copy())
            continue
        var live = read_btf_func_proto(btf, h.function)
        if not live.ok:
            v.reason = String(t"{h.name}: {live.message}")
            out.append(v.copy())
            continue
        v.live = live.canonical.copy()
        if live.canonical != norm.value:
            v.reason = String(t"{h.name}: signature mismatch")
            out.append(v.copy())
            continue
        v.ok = True
        out.append(v.copy())
    return out^


struct _ReceiptHit(Copyable, Movable):
    """One receipt check: note plus qualified caps on a hit.

    ``note`` is "" when the receipt verifies and the doc's
    identity bindings hold; "absent" when no receipt file
    exists; else "<id> " plus the verify or identity cause.
    ``caps`` carries the receipt's qualified ids on a hit
    and stays empty otherwise.
    """

    var note: String
    var caps: List[String]

    def __init__(out self):
        self.note = String("")
        self.caps = List[String]()


def _installed_profiles_key(profiles_dir: String) -> String:
    """Comparison key for a profiles dir, or "" when unusable.

    Collapses redundant separators and drops ``.``
    components throughout (interior, trailing, and
    combined, so ``share//memveil/./profiles/`` maps),
    matching how the kernel normalizes the path. Used
    only to recognize spellings of the installed
    profiles dir; anything else keeps its byte-identical
    ``<profiles-dir>/receipts`` fallback. Never resolves
    ``..``: ``profiles/..`` names the parent of the
    installed dir, not the dir itself.
    """
    var raw = List[UInt8]()
    for b in profiles_dir.as_bytes():
        raw.append(b)
    var absolute = len(raw) > 0 and raw[0] == UInt8(0x2F)
    var flat = List[UInt8]()
    var first = True
    var idx = 0
    while idx < len(raw):
        while idx < len(raw) and raw[idx] == UInt8(0x2F):
            idx += 1
        var start = idx
        while idx < len(raw) and raw[idx] != UInt8(0x2F):
            idx += 1
        if idx == start:
            break
        var is_dot = (idx - start == 1) and raw[start] == UInt8(
            0x2E
        )
        if is_dot:
            continue
        if first:
            first = False
            if absolute:
                flat.append(UInt8(0x2F))
        else:
            flat.append(UInt8(0x2F))
        var j = start
        while j < idx:
            flat.append(raw[j])
            j += 1
    try:
        return String(from_utf8=Span(flat))
    except:
        return String("")


def default_receipts_dir(profiles_dir: String) -> String:
    """Receipts dir for a profiles dir.

    The installed profiles dir keeps its receipts in
    the writable state dir instead of beside the
    read-only profiles; every other layout (bundle,
    checkout, explicit override) keeps receipts under
    ``<profiles-dir>/receipts`` exactly as before. The
    comparison normalizes redundant separators and ``.``
    components throughout, so shell-completed or dotted
    spellings of the installed dir cannot misplace a
    receipt.
    """
    if _installed_profiles_key(profiles_dir) == String(
        _INSTALLED_PROFILES_DIR
    ):
        return String(_INSTALLED_RECEIPTS_DIR)
    return profiles_dir + String("/receipts")


def _check_receipt(
    doc: Profile,
    kernel: KernelInfo,
    root: String,
    zlib: String,
    pdir: String,
    bridge_sha: String,
) -> _ReceiptHit:
    """Receipt verdict for one covering reference doc.

    A hit (empty note) means the receipt under the
    receipts dir for pdir verifies against the doc,
    the live kernel, and the resolved bridge hash, and
    the doc's identity bindings hold; the caller
    matches local-auto and keeps the qualified caps
    for per-capability judging. An empty
    ``bridge_sha`` means no bridge binding was
    performed (the passive path never touches the
    bridge): receipts then report an explicit
    unchecked note instead of a mismatch, so the
    caller never implies a binding that did not
    happen. Never raises: unreadable files read as
    absent, and the profile_id grammar admits no path
    separators so the join cannot escape the dir.
    """
    var out = _ReceiptHit()
    if pdir == String(""):
        out.note = String("absent")
        return out^
    var path = (
        default_receipts_dir(pdir)
        + String("/")
        + doc.profile_id
        + String(".json")
    )
    var raw = List[UInt8]()
    try:
        raw = read_host_file(path, String("receipt"), _PROFILE_CAP)
    except:
        out.note = String("absent")
        return out^
    var v = verify_qualification_receipt(
        Span(raw), doc, kernel, bridge_sha
    )
    if not v.ok:
        if v.bridge_mismatch and bridge_sha == String(""):
            out.note = (
                doc.profile_id
                + String(
                    " receipt bridge unchecked:"
                    " no binding performed on this path"
                )
            )
            return out^
        out.note = doc.profile_id + String(" ") + v.message
        return out^
    var sel = select_attempt_hook(doc)
    if not sel.ok:
        out.note = doc.profile_id + String(" receipt hook unusable")
        return out^
    var b = check_identity_bindings(
        root,
        kernel.release,
        doc.identity.source.note,
        zlib,
        sel.hook.format_path,
    )
    if b.state != String("bound"):
        out.note = (
            doc.profile_id
            + String(" receipt identity ")
            + b.state
            + String(": ")
            + b.key
        )
        return out^
    out.caps = v.caps.copy()
    return out^


def select_profile_bound(
    kernel: KernelInfo,
    profiles: List[Profile],
    root: String,
    zlib: String,
    pdir: String,
    bridge_sha: String,
) -> ProfileDecision:
    """Match kernel identity, preferring a doc that binds.

    Scans covering validated docs in manifest order and returns
    the first whose recorded revision equals the running release
    and whose identity bindings hold against the evidence tree
    under root. Object and ring bindings stay record-time
    checks. Otherwise every covering reference doc is tried
    for a receipt under the receipts dir for pdir
    verifying against the resolved bridge hash whose
    identity bindings hold, first hit matching with
    grade local-auto. An empty
    bridge hash performs no binding: receipts then carry
    an explicit unchecked note. With no
    receipt hit it falls back to the
    first covering doc of any status: a non-binding
    validated doc reports its own failing key; other
    reference cover names its receipt state plus the first
    validated near-miss (if any) so callers can quote the
    cause. Never raises: an unparseable release simply
    covers nothing.
    """
    if len(profiles) == 0:
        return ProfileDecision(
            False,
            False,
            Profile(),
            String("no profiles admitted"),
            String(""),
            List[String](),
        )
    var triple = parse_kernel_triple(kernel.release)
    if not triple.ok:
        return ProfileDecision(
            False,
            False,
            Profile(),
            "release " + kernel.release + " is unparseable; no coverage",
            String(""),
            List[String](),
        )
    var near_id = String("")
    var near_state = String("")
    var near_key = String("")
    for i in range(len(profiles)):
        if profiles[i].status != String("validated"):
            continue
        var covered = profiles[i].identity.arch == kernel.arch
        if covered:
            covered = _triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                profiles[i].identity.min_major,
                profiles[i].identity.min_minor,
                profiles[i].identity.min_patch,
            )
        if not covered:
            continue
        var state = String("")
        var key = String("")
        if kernel.release != profiles[i].identity.source.revision:
            state = String("mismatch")
            key = String("revision")
        else:
            var sel = select_attempt_hook(profiles[i])
            if not sel.ok:
                state = String("uncheckable")
                key = String("hook")
            else:
                var v = check_identity_bindings(
                    root,
                    kernel.release,
                    profiles[i].identity.source.note,
                    zlib,
                    sel.hook.format_path,
                )
                state = v.state
                key = v.key
        if state == String("bound"):
            return ProfileDecision(
                True,
                True,
                profiles[i].copy(),
                "profile "
                + profiles[i].profile_id
                + " matched (validated)",
                String("validated"),
                List[String](),
            )
        if near_id == String(""):
            near_id = profiles[i].profile_id
            near_state = state
            near_key = key
    var first_cover = -1
    for i in range(len(profiles)):
        var covered = profiles[i].identity.arch == kernel.arch
        if covered:
            covered = _triple_ge(
                triple.major,
                triple.minor,
                triple.patch,
                profiles[i].identity.min_major,
                profiles[i].identity.min_minor,
                profiles[i].identity.min_patch,
            )
        if not covered:
            continue
        if first_cover < 0:
            first_cover = i
        if profiles[i].status == String("validated"):
            continue
        var hit = _check_receipt(
            profiles[i], kernel, root, zlib, pdir, bridge_sha
        )
        if hit.note == String(""):
            return ProfileDecision(
                True,
                True,
                profiles[i].copy(),
                "profile "
                + profiles[i].profile_id
                + " matched (local-auto)",
                String("local-auto"),
                hit.caps,
            )
    if first_cover < 0:
        return ProfileDecision(
            False,
            False,
            Profile(),
            "no profile covers arch "
            + kernel.arch
            + " release "
            + kernel.release,
            String(""),
            List[String](),
        )
    var first = profiles[first_cover].copy()
    if first.status == String("validated"):
        return ProfileDecision(
            False,
            True,
            first.copy(),
            "profile "
            + first.profile_id
            + " covers this identity but identity "
            + near_state
            + ": "
            + near_key,
            String(""),
            List[String](),
        )
    var receipt_hit = _check_receipt(
        first, kernel, root, zlib, pdir, bridge_sha
    )
    var receipt_note = receipt_hit.note
    var reason = (
        String("profile ")
        + first.profile_id
        + String(" covers this identity but is reference-unvalidated")
    )
    if receipt_note != String("absent"):
        reason += String("; ") + receipt_note
    if near_id != String(""):
        reason += (
            String("; ")
            + near_id
            + String(" identity ")
            + near_state
            + String(": ")
            + near_key
        )
    return ProfileDecision(
        False, True, first.copy(), reason, String(""), List[String]()
    )


struct CapQualification(ImplicitlyCopyable):
    """One capability result feeding a minted receipt."""

    var id: String
    var detail: String

    def __init__(out self):
        self.id = String("")
        self.detail = String("")

    def __init__(out self, cid: String, detail: String):
        self.id = cid
        self.detail = detail


struct ReceiptVerdict(Copyable, Movable):
    """Receipt verification: ok plus empty message, else cause.

    ``caps`` lists the qualified capability ids in receipt
    order on success and stays empty on any refusal.
    ``bridge_mismatch`` is True only when every other check
    passed and the receipt's bridge hash differs from the
    resolved bridge, so callers can name the stale bridge
    in their fallback reason.
    """

    var ok: Bool
    var message: String
    var caps: List[String]
    var bridge_mismatch: Bool

    def __init__(out self):
        self.ok = False
        self.message = String("")
        self.caps = List[String]()
        self.bridge_mismatch = False


def mint_qualification_receipt(
    profile_id: String,
    kernel: KernelInfo,
    bind: NarrowBindings,
    created_ns: UInt64,
    caps: List[CapQualification],
    memveil: String,
    bridge: String,
    obj_attempt: String,
    obj_lc: String,
    obj_cp: String,
    duration_s: UInt64,
    note: String,
) raises -> String:
    """Render a local-auto qualification receipt (schema 0.1.0).

    Pure rendering: every input is caller-verified, so minting
    itself cannot fail except on undecodable text. Empty
    lifecycle/copy object hashes omit those keys.
    """
    var out = String("{\n")
    out += String('"schema_version": "0.1.0",\n')
    out += String('"kind": "memveil-qualification-receipt",\n')
    out += String('"profile_id": ') + escape_json(profile_id) + String(",\n")
    out += String('"grade": "local-auto",\n')
    out += String('"created_ns": "') + String(created_ns) + String('",\n')
    out += String('"kernel": {"arch": ') + escape_json(kernel.arch)
    out += String(', "release": ') + escape_json(kernel.release)
    out += String("},\n")
    out += String('"bindings": {"config": ')
    out += escape_json(String("sha256:") + bind.config)
    out += String(', "config_src": ') + escape_json(bind.config_src)
    out += String(', "btf": ')
    out += escape_json(String("sha256:") + bind.btf)
    out += String(', "format": ')
    out += escape_json(String("sha256:") + bind.format)
    out += String(', "image": ')
    out += escape_json(String("sha256:") + bind.image)
    out += String(', "image_bid": ') + escape_json(bind.image_bid)
    out += String("},\n")
    out += String('"capabilities": {')
    for i in range(len(caps)):
        if i > 0:
            out += String(", ")
        out += escape_json(caps[i].id)
        out += String(': {"status": "qualified", "detail": ')
        out += escape_json(caps[i].detail)
        out += String("}")
    out += String("},\n")
    out += String('"artifacts": {"memveil": ') + escape_json(memveil)
    out += String(', "bridge": ') + escape_json(bridge)
    out += String(', "objects": {"attempt": ') + escape_json(obj_attempt)
    if obj_lc != String(""):
        out += String(', "lifecycle": ') + escape_json(obj_lc)
    if obj_cp != String(""):
        out += String(', "copy": ') + escape_json(obj_cp)
    out += String("}},\n")
    out += String('"workload": {"kind": "smoke", "duration_s": "')
    out += String(duration_s) + String('", "traffic_required": false')
    out += String(', "note": ') + escape_json(note)
    out += String("}\n}\n")
    return out^


struct _ReceiptData(Copyable, Movable):
    """Parsed receipt fields (valid only past the const checks)."""

    var profile_id: String
    var arch: String
    var release: String
    var config: String
    var config_src: String
    var btf: String
    var format: String
    var image: String
    var image_bid: String
    var cap_count: Int
    var cap_ids: List[String]
    var bridge: String
    var obj_attempt: String
    var obj_lc: String
    var obj_cp: String

    def __init__(out self):
        self.profile_id = String("")
        self.arch = String("")
        self.release = String("")
        self.config = String("")
        self.config_src = String("")
        self.btf = String("")
        self.format = String("")
        self.image = String("")
        self.image_bid = String("")
        self.cap_count = 0
        self.cap_ids = List[String]()
        self.bridge = String("")
        self.obj_attempt = String("")
        self.obj_lc = String("")
        self.obj_cp = String("")


def _check_u64_dec(v: String, what: String) raises:
    """Check ^(0|[1-9][0-9]{0,19})$ decimal shape."""
    var raw = v.as_bytes()
    if len(raw) == 0 or len(raw) > 20:
        raise ValidationError(what, "bad decimal")
    if raw[0] == UInt8(0x30):
        if len(raw) != 1:
            raise ValidationError(what, "leading zero")
        return
    for i in range(len(raw)):
        if raw[i] < UInt8(0x30) or raw[i] > UInt8(0x39):
            raise ValidationError(what, "bad decimal")


def _parse_receipt_kernel(mut scan: Scanner, mut rec: _ReceiptData) raises:
    """Parse receipt.kernel: arch, release."""
    scan.begin_object()
    var has_arch = False
    var has_release = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "receipt.kernel")
            if key == "arch":
                if has_arch:
                    raise ValidationError("receipt.kernel", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 32, "receipt.kernel.arch")
                except e:
                    raise ValidationError("receipt.kernel.arch", String(e))
                rec.arch = v
                has_arch = True
            elif key == "release":
                if has_release:
                    raise ValidationError("receipt.kernel", "duplicate")
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 128, "receipt.kernel.release")
                except e:
                    raise ValidationError(
                        "receipt.kernel.release", String(e)
                    )
                rec.release = v
                has_release = True
            else:
                raise ValidationError("receipt.kernel", "unknown field")
            if not object_next(scan, "receipt.kernel"):
                break
    scan.end_object()
    if not has_arch or not has_release:
        raise ValidationError("receipt.kernel", "missing field")


def _strip_sha256(v: String, what: String) raises -> String:
    """Strip a sha256: scheme, requiring 64 following bytes."""
    var raw = v.as_bytes()
    if len(raw) != 71:
        raise ValidationError(what, "bad sha256 value")
    var want = String("sha256:")
    var prefix = want.as_bytes()
    for i in range(7):
        if raw[i] != prefix[i]:
            raise ValidationError(what, "bad sha256 value")
    var rest = List[UInt8]()
    for i in range(7, len(raw)):
        rest.append(raw[i])
    return bytes_to_text(rest^)


def _parse_receipt_bindings(
    mut scan: Scanner, mut rec: _ReceiptData
) raises:
    """Parse receipt.bindings: six identity values."""
    scan.begin_object()
    var seen = List[Bool]()
    for _ in range(6):
        seen.append(False)
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "receipt.bindings")
            var idx = -1
            if key == "config":
                idx = 0
            elif key == "config_src":
                idx = 1
            elif key == "btf":
                idx = 2
            elif key == "format":
                idx = 3
            elif key == "image":
                idx = 4
            elif key == "image_bid":
                idx = 5
            else:
                raise ValidationError("receipt.bindings", "unknown field")
            if seen[idx]:
                raise ValidationError("receipt.bindings", "duplicate")
            var v = scan.parse_string()
            var bound = 71
            if idx == 1:
                bound = 4
            elif idx == 5:
                bound = 64
            try:
                check_bounded_text(v, 1, bound, "receipt.bindings")
            except e:
                raise ValidationError("receipt.bindings", String(e))
            # Hash bindings carry the sha256: scheme on the
            # wire; the note grammar stores bare hex, so strip
            # before comparing.
            if idx == 0:
                rec.config = _strip_sha256(v, String("receipt.bindings"))
            elif idx == 1:
                rec.config_src = v
            elif idx == 2:
                rec.btf = _strip_sha256(v, String("receipt.bindings"))
            elif idx == 3:
                rec.format = _strip_sha256(v, String("receipt.bindings"))
            elif idx == 4:
                rec.image = _strip_sha256(v, String("receipt.bindings"))
            else:
                rec.image_bid = v
            seen[idx] = True
            if not object_next(scan, "receipt.bindings"):
                break
    scan.end_object()
    for i in range(6):
        if not seen[i]:
            raise ValidationError("receipt.bindings", "missing field")


def _parse_receipt_capabilities(
    mut scan: Scanner, mut rec: _ReceiptData
) raises:
    """Parse receipt.capabilities: at least one qualified entry."""
    scan.begin_object()
    var count = 0
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var cid = scan.parse_string()
            try:
                check_bounded_text(cid, 1, 64, "receipt.capabilities")
            except e:
                raise ValidationError("receipt.capabilities", String(e))
            if count >= MAX_PROFILE_CAPS:
                raise ValidationError("receipt.capabilities", "too many")
            expect_colon(scan, "receipt.capabilities")
            scan.begin_object()
            var has_status = False
            var has_detail = False
            if not object_is_empty(scan):
                while True:
                    scan.skip_ws()
                    var key = scan.parse_string()
                    expect_colon(scan, "receipt.capability")
                    if key == "status":
                        if has_status:
                            raise ValidationError(
                                "receipt.capability", "duplicate"
                            )
                        var v = scan.parse_string()
                        if v != String("qualified"):
                            raise ValidationError(
                                "receipt.capability",
                                "status is not qualified",
                            )
                        has_status = True
                    elif key == "detail":
                        if has_detail:
                            raise ValidationError(
                                "receipt.capability", "duplicate"
                            )
                        var v = scan.parse_string()
                        try:
                            check_bounded_text(
                                v, 1, 1024, "receipt.capability.detail"
                            )
                        except e:
                            raise ValidationError(
                                "receipt.capability.detail", String(e)
                            )
                        has_detail = True
                    else:
                        raise ValidationError(
                            "receipt.capability", "unknown field"
                        )
                    if not object_next(scan, "receipt.capability"):
                        break
            scan.end_object()
            if not has_status or not has_detail:
                raise ValidationError("receipt.capability", "missing field")
            rec.cap_ids.append(cid.copy())
            count += 1
            if not object_next(scan, "receipt.capabilities"):
                break
    scan.end_object()
    if count == 0:
        raise ValidationError("receipt.capabilities", "empty")
    rec.cap_count = count


def _parse_receipt_const_str(
    mut scan: Scanner, want: String, what: String
) raises:
    """Parse one string field that must equal want exactly."""
    var v = scan.parse_string()
    if v != want:
        raise ValidationError(what, "unexpected value")


def _parse_receipt_objects(
    mut scan: Scanner, mut rec: _ReceiptData
) raises:
    """Parse receipt.artifacts.objects: attempt plus extras."""
    scan.begin_object()
    var has_attempt = False
    var has_lc = False
    var has_cp = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "receipt.artifacts.objects")
            if key == "attempt":
                if has_attempt:
                    raise ValidationError(
                        "receipt.artifacts.objects", "duplicate"
                    )
                var v = scan.parse_string()
                if not is_sha256_value(v):
                    raise ValidationError(
                        "receipt.artifacts.objects", "bad sha256 value"
                    )
                rec.obj_attempt = _strip_sha256(
                    v, String("receipt.artifacts.objects")
                )
                has_attempt = True
            elif key == "lifecycle":
                if has_lc:
                    raise ValidationError(
                        "receipt.artifacts.objects", "duplicate"
                    )
                var v = scan.parse_string()
                if not is_sha256_value(v):
                    raise ValidationError(
                        "receipt.artifacts.objects", "bad sha256 value"
                    )
                rec.obj_lc = _strip_sha256(
                    v, String("receipt.artifacts.objects")
                )
                has_lc = True
            elif key == "copy":
                if has_cp:
                    raise ValidationError(
                        "receipt.artifacts.objects", "duplicate"
                    )
                var v = scan.parse_string()
                if not is_sha256_value(v):
                    raise ValidationError(
                        "receipt.artifacts.objects", "bad sha256 value"
                    )
                rec.obj_cp = _strip_sha256(
                    v, String("receipt.artifacts.objects")
                )
                has_cp = True
            else:
                raise ValidationError(
                    "receipt.artifacts.objects", "unknown field"
                )
            if not object_next(scan, "receipt.artifacts.objects"):
                break
    scan.end_object()
    if not has_attempt:
        raise ValidationError(
            "receipt.artifacts.objects", "missing field"
        )


def _parse_receipt_artifacts(
    mut scan: Scanner, mut rec: _ReceiptData
) raises:
    """Parse receipt.artifacts: version, bridge, object hashes."""
    scan.begin_object()
    var has_memveil = False
    var has_bridge = False
    var has_objects = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "receipt.artifacts")
            if key == "memveil":
                if has_memveil:
                    raise ValidationError(
                        "receipt.artifacts", "duplicate"
                    )
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 64, "receipt.artifacts.memveil")
                except e:
                    raise ValidationError(
                        "receipt.artifacts.memveil", String(e)
                    )
                has_memveil = True
            elif key == "bridge":
                if has_bridge:
                    raise ValidationError(
                        "receipt.artifacts", "duplicate"
                    )
                var v = scan.parse_string()
                if not is_sha256_value(v):
                    raise ValidationError(
                        "receipt.artifacts", "bad sha256 value"
                    )
                rec.bridge = _strip_sha256(
                    v, String("receipt.artifacts")
                )
                has_bridge = True
            elif key == "objects":
                if has_objects:
                    raise ValidationError(
                        "receipt.artifacts", "duplicate"
                    )
                _parse_receipt_objects(scan, rec)
                has_objects = True
            else:
                raise ValidationError("receipt.artifacts", "unknown field")
            if not object_next(scan, "receipt.artifacts"):
                break
    scan.end_object()
    if not has_memveil or not has_bridge or not has_objects:
        raise ValidationError("receipt.artifacts", "missing field")


def _parse_receipt_workload(mut scan: Scanner) raises:
    """Parse receipt.workload: the smoke that minted this."""
    scan.begin_object()
    var has_kind = False
    var has_duration = False
    var has_traffic = False
    var has_note = False
    if not object_is_empty(scan):
        while True:
            scan.skip_ws()
            var key = scan.parse_string()
            expect_colon(scan, "receipt.workload")
            if key == "kind":
                if has_kind:
                    raise ValidationError(
                        "receipt.workload", "duplicate"
                    )
                _parse_receipt_const_str(
                    scan, String("smoke"), "receipt.workload.kind"
                )
                has_kind = True
            elif key == "duration_s":
                if has_duration:
                    raise ValidationError(
                        "receipt.workload", "duplicate"
                    )
                _check_u64_dec(
                    scan.parse_string(), "receipt.workload.duration_s"
                )
                has_duration = True
            elif key == "traffic_required":
                if has_traffic:
                    raise ValidationError(
                        "receipt.workload", "duplicate"
                    )
                if scan.parse_bool():
                    raise ValidationError(
                        "receipt.workload.traffic_required",
                        "must be false",
                    )
                has_traffic = True
            elif key == "note":
                if has_note:
                    raise ValidationError(
                        "receipt.workload", "duplicate"
                    )
                var v = scan.parse_string()
                try:
                    check_bounded_text(v, 1, 512, "receipt.workload.note")
                except e:
                    raise ValidationError(
                        "receipt.workload.note", String(e)
                    )
                has_note = True
            else:
                raise ValidationError("receipt.workload", "unknown field")
            if not object_next(scan, "receipt.workload"):
                break
    scan.end_object()
    if not has_kind or not has_duration or not has_traffic or not has_note:
        raise ValidationError("receipt.workload", "missing field")


def verify_qualification_receipt(
    data: Span[UInt8, _],
    doc: Profile,
    kernel: KernelInfo,
    bridge_sha: String,
) -> ReceiptVerdict:
    """Verify a receipt against its document and the live kernel.

    The receipt must parse with no trailing data, carry
    schema 0.1.0 and grade local-auto for this document,
    name this kernel, and repeat the document note's
    identity bindings exactly. The kernel must also equal
    the document revision, and every object hash the
    receipt claims must equal the note's binding, so an
    updated document or object cannot inherit an old
    receipt. ``bridge_sha`` is the bare hex sha256 of the
    currently-resolved bridge ("" when unresolvable);
    the receipt's bridge hash must equal it, so a receipt
    minted for one bridge cannot admit another. The
    bridge compares last, after document and object
    drift, so a pure bridge rotation names the bridge.
    At least one capability must qualify; the workload
    is shape-checked audit context. Never raises.
    """
    var out = ReceiptVerdict()
    var text = String("")
    try:
        var raw = List[UInt8]()
        for i in range(len(data)):
            raw.append(data[i])
        text = bytes_to_text(raw^)
        var scan = Scanner(text, 64)
        scan.begin_object()
        var rec = _ReceiptData()
        var seen = List[Bool]()
        for _ in range(10):
            seen.append(False)
        if not object_is_empty(scan):
            while True:
                scan.skip_ws()
                var key = scan.parse_string()
                expect_colon(scan, "receipt")
                if key == "schema_version":
                    if seen[0]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_const_str(
                        scan, String("0.1.0"), "receipt.schema_version"
                    )
                    seen[0] = True
                elif key == "kind":
                    if seen[1]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_const_str(
                        scan, String("memveil-qualification-receipt"),
                        "receipt.kind",
                    )
                    seen[1] = True
                elif key == "profile_id":
                    if seen[2]:
                        raise ValidationError("receipt", "duplicate")
                    var v = scan.parse_string()
                    try:
                        check_bounded_text(v, 1, 128, "receipt.profile_id")
                    except e:
                        raise ValidationError(
                            "receipt.profile_id", String(e)
                        )
                    rec.profile_id = v
                    seen[2] = True
                elif key == "grade":
                    if seen[3]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_const_str(
                        scan, String("local-auto"), "receipt.grade"
                    )
                    seen[3] = True
                elif key == "created_ns":
                    if seen[4]:
                        raise ValidationError("receipt", "duplicate")
                    _check_u64_dec(
                        scan.parse_string(), "receipt.created_ns"
                    )
                    seen[4] = True
                elif key == "kernel":
                    if seen[5]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_kernel(scan, rec)
                    seen[5] = True
                elif key == "bindings":
                    if seen[6]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_bindings(scan, rec)
                    seen[6] = True
                elif key == "capabilities":
                    if seen[7]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_capabilities(scan, rec)
                    seen[7] = True
                elif key == "artifacts":
                    if seen[8]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_artifacts(scan, rec)
                    seen[8] = True
                elif key == "workload":
                    if seen[9]:
                        raise ValidationError("receipt", "duplicate")
                    _parse_receipt_workload(scan)
                    seen[9] = True
                else:
                    raise ValidationError("receipt", "unknown field")
                if not object_next(scan, "receipt"):
                    break
        scan.end_object()
        for i in range(10):
            if not seen[i]:
                raise ValidationError("receipt", "missing field")
        if rec.profile_id != doc.profile_id:
            out.message = String("receipt names another profile")
            return out^
        if rec.arch != kernel.arch or rec.release != kernel.release:
            out.message = String("receipt names another kernel")
            return out^
        if doc.identity.source.revision != kernel.release:
            out.message = String(
                "receipt kernel differs from profile revision"
            )
            return out^
        var parsed = parse_narrow_note(doc.identity.source.note)
        if not parsed.ok:
            out.message = String("profile note unparseable")
            return out^
        var bind = parsed.bindings
        if (
            rec.config != bind.config
            or rec.config_src != bind.config_src
            or rec.btf != bind.btf
            or rec.format != bind.format
            or rec.image != bind.image
            or rec.image_bid != bind.image_bid
        ):
            out.message = String("receipt bindings differ from note")
            return out^
        if rec.obj_attempt != bind.object:
            out.message = String("receipt artifacts differ from note")
            return out^
        # Every qualified channel needs its own artifact
        # hash present and matching: a lifecycle-qualified
        # receipt without one would let a changed
        # lifecycle object inherit qualification. Hashes
        # for unqualified channels still compare when
        # present, so a stray wrong hash never verifies.
        var qualifies_lc = False
        var qualifies_cp = False
        for i in range(len(rec.cap_ids)):
            if rec.cap_ids[i] == String(LIFECYCLE_CAP_ID):
                qualifies_lc = True
            if rec.cap_ids[i] == String(COPY_CAP_ID):
                qualifies_cp = True
        if qualifies_lc and rec.obj_lc == String(""):
            out.message = String(
                "receipt lacks lifecycle hash for qualified"
                " mapping-lifecycle"
            )
            return out^
        if qualifies_cp and rec.obj_cp == String(""):
            out.message = String(
                "receipt lacks copy hash for qualified copy-actual"
            )
            return out^
        if (
            (rec.obj_lc != String("") and rec.obj_lc != bind.lc_object)
            or (rec.obj_cp != String("") and rec.obj_cp != bind.cp_object)
        ):
            out.message = String("receipt artifacts differ from note")
            return out^
        scan.skip_ws()
        if not scan.at_end():
            raise ValidationError("receipt", "trailing data")
        if rec.bridge != bridge_sha:
            out.message = String(
                "receipt bridge differs from resolved bridge"
            )
            out.bridge_mismatch = True
            return out^
        out.caps = rec.cap_ids.copy()
    except e:
        out.message = String("receipt unparseable: ") + String(e)
        return out^
    out.ok = True
    out.message = String("")
    return out^
