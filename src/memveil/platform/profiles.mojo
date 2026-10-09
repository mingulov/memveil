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
from memveil.platform.evidence import KernelInfo, parse_kernel_triple
from memveil.platform.reader import bytes_to_text, read_host_file


comptime PROFILE_SCHEMA_VERSION = "0.1.1"
comptime MAX_PROFILE_HOOKS = 32
comptime MAX_PROFILE_CAPS = 16
comptime MAX_PROFILE_NOTES = 32
comptime MAX_CAP_HOOKS = 32
comptime _MANIFEST_CAP = 65536
comptime _PROFILE_CAP = 1048576


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


@fieldwise_init
struct ProfileDecision(Copyable):
    """The outcome of matching kernel identity against profiles.

    ``matched`` is True only when a validated profile covers the
    identity. ``has_profile`` is True whenever any profile (even a
    reference one) covers it; then ``profile`` is that manifest in
    full. ``reason`` always explains the outcome.
    """

    var matched: Bool
    var has_profile: Bool
    var profile: Profile
    var reason: String


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


def load_profiles(dir: String) raises -> List[Profile]:
    """Load every manifest-admitted profile under dir, in order.

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
    var out = List[Profile]()
    for i in range(len(names)):
        var path = dir + "/" + names[i]
        var data = read_host_file(path, names[i], _PROFILE_CAP)
        try:
            var prof = parse_profile_bytes(data^)
            out.append(prof^)
        except e:
            raise ValidationError("profile " + names[i], String(e))
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
            False, False, Profile(), String("no profiles admitted")
        )
    var triple = parse_kernel_triple(kernel.release)
    if not triple.ok:
        return ProfileDecision(
            False,
            False,
            Profile(),
            "release " + kernel.release + " is unparseable; no coverage",
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
                )
            return ProfileDecision(
                False,
                True,
                profiles[i].copy(),
                "profile "
                + profiles[i].profile_id
                + " covers this identity but is reference-unvalidated",
            )
    return ProfileDecision(
        False,
        False,
        Profile(),
        "no profile covers arch "
        + kernel.arch
        + " release "
        + kernel.release,
    )
