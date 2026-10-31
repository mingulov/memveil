# Copyright (c) 2026 Denis Mingulov
# SPDX-License-Identifier: GPL-3.0-or-later
"""Mint a bound profile document from live evidence (bind-profile verb)."""

from memveil.capture.collector import EXIT_REFUSAL
from memveil.capture.run import (
    MAX_PROFILE_DOC_BYTES,
    parse_requested_caps,
    resolve_object,
)
from memveil.cli.doctor import resolve_profiles_dir
from memveil.cli.qualify import publish_receipt
from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    CliError,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.platform.artifact_files import join_root
from memveil.platform.evidence import (
    KernelInfo,
    detect_environment,
    parse_kernel_triple,
)
from memveil.platform.narrow import (
    MAX_NARROW_FORMAT_BYTES,
    NarrowBindings,
    format_narrow_note,
    measure_live_bindings,
    read_live_object,
    tracefs_format_path,
)
from memveil.platform.profiles import (
    NamedProfiles,
    Profile,
    ProfileHook,
    load_profiles,
    load_profiles_named,
    parse_profile_bytes,
    select_profile,
)
from memveil.platform.reader import (
    EvidenceReader,
    open_evidence_reader,
    read_host_file,
    readlink_self,
)
from memveil.platform.stdout import write_stdout
from memveil.render.json import escape_json

comptime _ATTEMPT = "attempt-trace"
comptime _LIFECYCLE = "mapping-lifecycle"
comptime _COPY = "copy-actual"
comptime _CONVERT = "conversion-observe"
comptime _ZLIB = "libz.so.1"
comptime _RING_ATTEMPT = "8388608"
comptime _RING_EXTRA = "33554432"
comptime _MAX_FORMAT_TEXT = 65536
comptime _MAX_NOTE = 1024
comptime _CAP_REASON = "Candidate collection source; availability is checked passively, semantics are unproven until qualify."
comptime _IDENTITY_NOTE = "Narrow identity for this host; bindings refuse every other identity."
comptime _HOOK_NOTE = "Hook definition copied from the covering reference; admission checks it live."


struct BindOptions:
    """Parsed bind-profile arguments."""

    var output: String
    var object: String
    var profile: String
    var has_profile: Bool
    var profiles_dir: String
    var has_profiles_dir: Bool
    var lc_object: String
    var cp_object: String
    var capabilities: String
    var profile_id: String
    var has_profile_id: Bool

    def __init__(out self):
        self.output = String("")
        self.object = String("")
        self.profile = String("")
        self.has_profile = False
        self.profiles_dir = String("")
        self.has_profiles_dir = False
        self.lc_object = String("")
        self.cp_object = String("")
        self.capabilities = String("")
        self.profile_id = String("")
        self.has_profile_id = False


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def parse_bind_args(args: List[String]) raises CliError -> BindOptions:
    """Parse bind-profile arguments without the leading verb."""
    var opts = BindOptions()
    var i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--output":
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
        elif tok == "--profile-id":
            if i + 1 >= len(args):
                raise CliError("--profile-id needs a value")
            if args[i + 1] == "":
                raise CliError("--profile-id needs a value")
            opts.profile_id = args[i + 1]
            opts.has_profile_id = True
            i += 2
        elif _is_option(tok):
            raise CliError("unknown option: " + tok)
        else:
            raise CliError("unexpected argument: " + tok)
    if opts.output == "":
        raise CliError("missing --output")
    return opts^


def bind_usage() -> String:
    """Usage text for the bind-profile verb."""
    return (
        "usage: memveil bind-profile --output PATH [--profile ID|PATH]\n"
        "       [--profiles-dir DIR] [--object PATH] [--lc-object PATH]\n"
        "       [--cp-object PATH] [--capability LIST] [--profile-id ID]\n"
        "\n"
        "Mint a bound reference-unvalidated profile document for\n"
        "this host: hook definitions come from the covering\n"
        "reference, identity bindings and tracepoint format text\n"
        "are measured live. Register the minted file first in\n"
        "the profiles manifest, then run qualify against it.\n"
        "Format text and the kernel image need root reads; run\n"
        "under sudo when they deny the current user.\n"
        "Attempt-trace is the mandatory base channel; extra\n"
        "channels bind together (both objects required) with\n"
        "the canonical ring sizes, verified live at qualify.\n"
        "Minted documents carry no BTF layouts: signature and\n"
        "smoke checks still apply, layout pins do not.\n"
        "The BPF object is discovered beside the executable or\n"
        "under the system path unless --object overrides it.\n"
    )


def _bind_failed(detail: String) raises -> Int:
    """Report one cannot-mint outcome; return EXIT_REFUSAL."""
    write_stderr(
        String("memveil bind-profile: ")
        + sanitize_diagnostic(detail)
        + String("\n")
    )
    return EXIT_REFUSAL


def _bind_misused(detail: String) raises -> Int:
    """Report one usage failure; return EXIT_INVALID."""
    write_stderr(
        String("memveil bind-profile: ")
        + sanitize_diagnostic(detail)
        + String("\n")
    )
    return EXIT_INVALID


def _bind_broken(detail: String) raises -> Int:
    """Report one internal failure; return EXIT_INTERNAL."""
    try:
        write_stderr(
            String("memveil bind-profile: ")
            + sanitize_diagnostic(detail)
            + String("\n")
        )
    except:
        pass
    return EXIT_INTERNAL


def _is_id_start(b: UInt8) -> Bool:
    return (
        (b >= UInt8(0x41) and b <= UInt8(0x5A))
        or (b >= UInt8(0x61) and b <= UInt8(0x7A))
        or (b >= UInt8(0x30) and b <= UInt8(0x39))
        or b == UInt8(0x5F)
    )


def _is_id_rest(b: UInt8) -> Bool:
    return (
        _is_id_start(b)
        or b == UInt8(0x2E)
        or b == UInt8(0x2D)
    )


def valid_profile_id(text: String) -> Bool:
    """True for the profile_id schema pattern (1..128 chars)."""
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 128:
        return False
    if not _is_id_start(raw[0]):
        return False
    for i in range(1, len(raw)):
        if not _is_id_rest(raw[i]):
            return False
    return True


def default_profile_id(release: String) -> String:
    """Derive local-<release> with unpatterned bytes dashed."""
    var out = String("local-")
    var raw = release.as_bytes()
    for i in range(len(raw)):
        var b = raw[i]
        if _is_id_rest(b):
            try:
                out += String(from_utf8=Span(raw[i : i + 1]))
            except:
                out += String("-")
        else:
            out += String("-")
    var clipped = out.as_bytes()
    if len(clipped) > 128:
        var keep = List[UInt8]()
        for i in range(128):
            keep.append(clipped[i])
        try:
            return String(from_utf8=Span(keep))
        except:
            return String("local-host")
    return out^


def min_kernel_for(release: String) -> String:
    """Major.minor cover floor for a release, or ""."""
    var triple = parse_kernel_triple(release)
    if not triple.ok:
        return String("")
    return String(triple.major) + String(".") + String(triple.minor)


def _resolve_base(
    explicit: String,
    has_explicit: Bool,
    profiles_dir: String,
    kernel: KernelInfo,
    mut base: Profile,
) -> String:
    """Resolve the base document; "" when resolved.

    An explicit --profile wins by file then id; otherwise
    the first covering manifest document wins, exactly
    like record admission.
    """
    if has_explicit:
        var named: NamedProfiles
        try:
            named = load_profiles_named(profiles_dir)
        except e:
            return String("cannot load profiles: ") + String(e)
        var raw = List[UInt8]()
        var is_path = False
        try:
            raw = read_host_file(
                explicit, String("profile"), MAX_PROFILE_DOC_BYTES
            )
            is_path = True
        except:
            pass
        if is_path:
            try:
                base = parse_profile_bytes(raw^)
            except e:
                return String("cannot parse --profile: ") + String(e)
            return String("")
        for i in range(len(named.profiles)):
            if named.profiles[i].profile_id == explicit:
                base = named.profiles[i].copy()
                return String("")
        return String("unknown --profile: ") + explicit
    var docs: List[Profile]
    try:
        docs = load_profiles(profiles_dir)
    except e:
        return String("cannot load profiles: ") + String(e)
    var decision = select_profile(kernel, docs^)
    if not decision.has_profile:
        return String("no covering profile: ") + decision.reason
    base = decision.profile.copy()
    return String("")


def _base_hooks_for(
    base: Profile, cap: String, mut names: List[String]
) -> Bool:
    """Collect the base capability's hook names; False when none."""
    for i in range(len(base.caps)):
        if base.caps[i].id == cap:
            for h in range(len(base.caps[i].hooks)):
                names.append(base.caps[i].hooks[h].copy())
            return len(names) > 0
    return False


def _find_hook(base: Profile, name: String) -> ProfileHook:
    var out = ProfileHook()
    for i in range(len(base.hooks)):
        if base.hooks[i].name == name:
            return base.hooks[i].copy()
    return out^


def _read_format_text(root: String, hook: ProfileHook) raises -> String:
    """Live tracepoint format bytes, translated onto the root."""
    var path = tracefs_format_path(root, hook.format_path)
    var raw: List[UInt8]
    try:
        raw = read_host_file(
            join_root(root, path),
            String("format"),
            MAX_NARROW_FORMAT_BYTES,
        )
    except:
        raise Error("format text unreadable: " + hook.format_path)
    if len(raw) > _MAX_FORMAT_TEXT:
        raise Error("format text exceeds 65536 bytes")
    try:
        return String(from_utf8=Span(raw))
    except:
        raise Error("format text is not UTF-8")


def _hook_json(
    hook: ProfileHook, format_text: String, has_format: Bool
) raises -> String:
    """Render one hook object; tracing keeps its signature."""
    var out = String("    {\n")
    out += String('      "name": ') + escape_json(hook.name) + String(",\n")
    out += String('      "kind": ') + escape_json(hook.kind) + String(",\n")
    if hook.kind == String("tracepoint"):
        out += (
            String('      "id_path": ')
            + escape_json(hook.id_path)
            + String(",\n")
        )
        out += (
            String('      "format_path": ')
            + escape_json(hook.format_path)
            + String(",\n")
        )
        if has_format:
            out += (
                String('      "format_text": ')
                + escape_json(format_text)
                + String(",\n")
            )
    else:
        out += (
            String('      "function": ')
            + escape_json(hook.function)
            + String(",\n")
        )
        out += (
            String('      "attach": ')
            + escape_json(hook.attach)
            + String(",\n")
        )
        out += (
            String('      "signature": ')
            + escape_json(hook.signature)
            + String(",\n")
        )
        if len(hook.signature_alt) > 0:
            out += String('      "signature_alt": [')
            for i in range(len(hook.signature_alt)):
                if i > 0:
                    out += String(", ")
                out += escape_json(hook.signature_alt[i])
            out += String("],\n")
    if hook.has_note:
        out += String('      "note": ') + escape_json(hook.note) + String("\n")
    else:
        out += (
            String('      "note": ')
            + escape_json(String(_HOOK_NOTE))
            + String("\n")
        )
    out += String("    }")
    return out^


def _cap_json(cap: String, hooks: List[String]) raises -> String:
    """Render one candidate capability object."""
    var out = String("    {\n")
    out += String('      "id": ') + escape_json(cap) + String(",\n")
    out += String('      "status": "candidate",\n')
    out += String('      "hooks": [')
    for i in range(len(hooks)):
        if i > 0:
            out += String(", ")
        out += escape_json(hooks[i])
    out += String("],\n")
    out += (
        String('      "reason": ')
        + escape_json(String(_CAP_REASON))
        + String("\n")
    )
    out += String("    }")
    return out^


def render_bound_profile(
    profile_id: String,
    arch: String,
    min_kernel: String,
    release: String,
    note: String,
    mut hooks: List[ProfileHook],
    mut formats: List[String],
    mut has_formats: List[Bool],
    mut caps: List[String],
    mut cap_hooks: List[List[String]],
) raises -> String:
    """Render the minted 0.1.1 document text."""
    var out = String("{\n")
    out += String('  "schema_version": "0.1.1",\n')
    out += (
        String('  "profile_id": ') + escape_json(profile_id) + String(",\n")
    )
    out += String('  "status": "reference-unvalidated",\n')
    out += String('  "identity": {\n')
    out += String('    "arch": ') + escape_json(arch) + String(",\n")
    out += (
        String('    "min_kernel": ')
        + escape_json(min_kernel)
        + String(",\n")
    )
    out += String('    "source": {\n')
    out += String('      "origin": "distro",\n')
    out += (
        String('      "revision": ')
        + escape_json(release)
        + String(",\n")
    )
    out += (
        String('      "note": ') + escape_json(note) + String("\n")
    )
    out += String("    },\n")
    out += (
        String('    "note": ')
        + escape_json(String(_IDENTITY_NOTE))
        + String("\n")
    )
    out += String("  },\n")
    out += String('  "hooks": [\n')
    for i in range(len(hooks)):
        if i > 0:
            out += String(",\n")
        out += _hook_json(hooks[i].copy(), formats[i], has_formats[i])
    out += String("\n  ],\n")
    out += String('  "capabilities": [\n')
    for i in range(len(caps)):
        if i > 0:
            out += String(",\n")
        out += _cap_json(caps[i], cap_hooks[i])
    out += String("\n  ],\n")
    var minted = (
        String("Minted from live ")
        + release
        + String(" evidence by memveil bind-profile; inspection is not qualification evidence.")
    )
    out += String('  "notes": [') + escape_json(minted) + String("]\n")
    out += String("}\n")
    return out^


struct MintOut(Copyable):
    """One mint attempt: doc text, or err with refusal text."""

    var ok: Bool
    var text: String
    var err: String

    def __init__(out self):
        self.ok = False
        self.text = String("")
        self.err = String("")


def mint_bound_profile(
    root: String,
    exe_path: String,
    base: Profile,
    mut caps: List[String],
    obj: String,
    lc_obj: String,
    cp_obj: String,
    profile_id: String,
    release: String,
    arch: String,
) -> MintOut:
    """Measure live bindings and render the bound document.

    Never raises: every failure returns err text naming the
    exact unmeasurable binding, missing hook, or unresolved
    object. Object paths resolve like record admission
    (explicit, bundle, system); rings are the canonical
    sizes, verified live again at qualify.
    """
    var out = MintOut()
    var want_extra = False
    for i in range(len(caps)):
        if caps[i] == String(_LIFECYCLE) or caps[i] == String(_COPY):
            want_extra = True
    var emit_hooks = List[ProfileHook]()
    var emit_names = List[String]()
    var cap_hooks = List[List[String]]()
    for i in range(len(caps)):
        var names = List[String]()
        if not _base_hooks_for(base, caps[i], names):
            out.err = (
                String("base profile has no hooks for ") + caps[i]
            )
            return out^
        var one = List[String]()
        for h in range(len(names)):
            var hook = _find_hook(base, names[h])
            if hook.name == String(""):
                out.err = (
                    String("base profile lacks hook ") + names[h]
                )
                return out^
            one.append(names[h].copy())
            var seen = False
            for e in range(len(emit_names)):
                if emit_names[e] == names[h]:
                    seen = True
            if not seen:
                emit_names.append(names[h].copy())
                emit_hooks.append(hook.copy())
        cap_hooks.append(one^)
    var attempt_hook = ProfileHook()
    for i in range(len(emit_hooks)):
        if emit_hooks[i].kind == String("tracepoint"):
            attempt_hook = emit_hooks[i].copy()
            break
    if attempt_hook.name == String(""):
        out.err = String("no tracepoint hook to bind")
        return out^
    var bindings = NarrowBindings()
    var measure_err = measure_live_bindings(
        root, release, _ZLIB, attempt_hook.format_path, bindings
    )
    if measure_err != String(""):
        out.err = measure_err.copy()
        return out^
    var obj_path = resolve_object(String("attempt"), obj, exe_path)
    if obj_path == String(""):
        out.err = String("no object: pass --object PATH")
        return out^
    var obj_live = read_live_object(obj_path)
    if obj_live.state != String("value"):
        out.err = String("attempt object unreadable: ") + obj_path
        return out^
    bindings.object = obj_live.value.copy()
    bindings.ring = String(_RING_ATTEMPT)
    if want_extra:
        var lc_path = resolve_object(String("lifecycle"), lc_obj, exe_path)
        if lc_path == String(""):
            out.err = String("no lifecycle object: pass --lc-object PATH")
            return out^
        var lc_live = read_live_object(lc_path)
        if lc_live.state != String("value"):
            out.err = String("lifecycle object unreadable: ") + lc_path
            return out^
        var cp_path = resolve_object(String("copy"), cp_obj, exe_path)
        if cp_path == String(""):
            out.err = String("no copy object: pass --cp-object PATH")
            return out^
        var cp_live = read_live_object(cp_path)
        if cp_live.state != String("value"):
            out.err = String("copy object unreadable: ") + cp_path
            return out^
        bindings.lc_object = lc_live.value.copy()
        bindings.lc_ring = String(_RING_EXTRA)
        bindings.cp_object = cp_live.value.copy()
        bindings.cp_ring = String(_RING_EXTRA)
    var formats = List[String]()
    var has_formats = List[Bool]()
    for i in range(len(emit_hooks)):
        var hook = emit_hooks[i].copy()
        if hook.kind == String("tracepoint"):
            try:
                formats.append(_read_format_text(root, hook))
            except e:
                out.err = String(e)
                return out^
            has_formats.append(True)
        else:
            formats.append(String(""))
            has_formats.append(False)
    var note = String("")
    try:
        note = format_narrow_note(bindings, want_extra)
    except e:
        out.err = String("cannot assemble note: ") + String(e)
        return out^
    if len(note.as_bytes()) > _MAX_NOTE:
        out.err = String("assembled note exceeds 1024 bytes")
        return out^
    var floor = min_kernel_for(release)
    if floor == String(""):
        out.err = String("release ") + release + String(" is unparseable")
        return out^
    try:
        out.text = render_bound_profile(
            profile_id,
            arch,
            floor,
            release,
            note,
            emit_hooks,
            formats,
            has_formats,
            caps,
            cap_hooks,
        )
    except e:
        out.err = String("cannot render document: ") + String(e)
        return out^
    out.ok = True
    return out^


def run_bind_with(
    root: String, exe_path: String, profiles_dir: String, opts: BindOptions
) raises -> Int:
    """Run the bind flow against explicit roots; exit code.

    ``root`` is the evidence root ("" for the live host);
    ``exe_path`` anchors object discovery. Publishes the
    minted document at opts.output, atomically.
    """
    var ask = parse_requested_caps(opts.capabilities)
    if not ask.ok:
        return _bind_failed(ask.err.copy())
    for i in range(len(ask.caps)):
        if ask.caps[i] == String(_CONVERT):
            return _bind_failed(
                String(
                    "capability conversion-observe has no record channel"
                )
            )
    if opts.has_profile_id and not valid_profile_id(opts.profile_id):
        return _bind_misused(
            String("bad --profile-id: ") + opts.profile_id
        )
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(root)
    except e:
        return _bind_failed(String("cannot open evidence: ") + String(e))
    var env = detect_environment(reader)
    if not env.kernel.eligible_floor:
        return _bind_failed(env.kernel.floor_reason.copy())
    var pid = opts.profile_id
    if not opts.has_profile_id:
        pid = default_profile_id(env.kernel.release)
    var base = Profile()
    var base_err = _resolve_base(
        opts.profile,
        opts.has_profile,
        profiles_dir,
        env.kernel,
        base,
    )
    if base_err != String(""):
        return _bind_failed(base_err.copy())
    var caps = ask.caps.copy()
    var minted = mint_bound_profile(
        root,
        exe_path,
        base,
        caps,
        opts.object,
        opts.lc_object,
        opts.cp_object,
        pid,
        env.kernel.release,
        env.kernel.arch,
    )
    if not minted.ok:
        return _bind_failed(minted.err.copy())
    try:
        publish_receipt(opts.output, minted.text)
    except e:
        return _bind_broken(
            String("cannot publish document: ") + String(e)
        )
    var listed = String("")
    for i in range(len(ask.caps)):
        if i > 0:
            listed += String(",")
        listed += ask.caps[i]
    try:
        write_stdout(
            String("bind-profile: ")
            + pid
            + String(" caps=")
            + listed
            + String(" path=")
            + opts.output
            + String("\n")
        )
    except:
        return _bind_broken(String("cannot write stdout"))
    return EXIT_OK


def run_bind(args: List[String]) raises -> Int:
    """Run the bind-profile verb; return the process exit code.

    args excludes the program name and the bind-profile word.
    Profiles resolve from --profiles-dir or the
    kernel-resolved binary path, never from argv[0] or
    the working directory.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(bind_usage())
            except:
                return _bind_broken(String("cannot write stdout"))
            return EXIT_OK
        i += 1
    var opts: BindOptions
    try:
        opts = parse_bind_args(args)
    except e:
        return _bind_misused(e.message)
    var profiles_dir = opts.profiles_dir
    if not opts.has_profiles_dir:
        try:
            profiles_dir = resolve_profiles_dir()
        except e:
            return _bind_failed(
                String("cannot resolve profiles location: ") + e.message
            )
    var exe_path = String("")
    try:
        exe_path = readlink_self()
    except e:
        return _bind_broken(
            String("cannot resolve executable path: ") + String(e)
        )
    return run_bind_with(String(""), exe_path, profiles_dir, opts^)
