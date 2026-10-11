# SPDX-License-Identifier: GPL-3.0-or-later

"""Local-auto qualification: prove this host, mint a receipt.

`memveil qualify` runs a short smoke capture (attach, poll,
detach; an idle ring is honest success) against one
covering profile and, when the smoke proves the requested
channels, publishes a machine-local receipt under
<profiles-dir>/receipts/. Later `record` runs re-verify
the receipt at collection start and admit grade local-auto.
Qualify never mints grade validated and never rewrites the
shipped profiles: selection, binding, signature, smoke,
mint, publish — any refusal names its exact cause.
"""

from std.ffi import external_call

from memveil.capture.collector import EXIT_REFUSAL
from memveil.capture.live import LiveWriter
from memveil.cli.doctor import resolve_profiles_dir
from memveil.cli.record import (
    BridgeSnapshot,
    MAX_PROFILE_DOC_BYTES,
    RecordOptions,
    open_bridge_snapshot,
    open_object_snapshot,
    parse_requested_caps,
    resolve_bridge,
    resolve_object,
    run_collector_with,
)
from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    CliError,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.model.report import ENGINE_VERSION
from memveil.model.session import parse_session
from memveil.platform.clock import wall_ns
from memveil.platform.evidence import KernelInfo, detect_environment
from memveil.platform.hash import sha256_hex
from memveil.platform.narrow import (
    MAX_NARROW_BTF_BYTES,
    MAX_NARROW_OBJECT_BYTES,
    NarrowBindings,
    check_identity_bindings,
    parse_narrow_note,
)
from memveil.platform.profiles import (
    CapQualification,
    NamedProfiles,
    Profile,
    SigVerdict,
    load_profiles_named,
    mint_qualification_receipt,
    parse_profile_bytes,
    select_attempt_hook,
    select_profile,
    verify_hook_signatures,
)
from memveil.platform.reader import (
    EvidenceReader,
    open_evidence_reader,
    read_host_file,
    readlink_self,
)
from memveil.platform.stdout import write_stdout

comptime _ZLIB = "libz.so.1"
comptime _BTF_PATH = "/sys/kernel/btf/vmlinux"
comptime _SMOKE_DURATION_S = UInt64(3)
comptime _SMOKE_NOTE = "smoke: attach/poll/detach, no traffic required"
comptime _ATTEMPT = "attempt-trace"
comptime _CONVERT = "conversion-observe"
comptime _LIFECYCLE = "mapping-lifecycle"
comptime _COPY = "copy-actual"

comptime _O_WRONLY = 1
comptime _O_CREAT = 64
comptime _O_EXCL = 128
comptime _O_DIRECTORY = 65536
comptime _O_NOFOLLOW = 131072
comptime _AT_FDCWD = -100
comptime _EINTR = 4
comptime _EEXIST = 17


struct QualifyOptions:
    """Parsed qualify arguments."""

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


def _is_option(text: String) -> Bool:
    var raw = text.as_bytes()
    return len(raw) > 0 and raw[0] == UInt8(0x2D)


def parse_qualify_args(args: List[String]) raises CliError -> QualifyOptions:
    """Parse qualify arguments without the leading verb."""
    var opts = QualifyOptions()
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


def qualify_usage() -> String:
    """Usage text for the qualify verb."""
    return (
        "usage: memveil qualify --output DIR [--object PATH]\n"
        "       [--bridge PATH] [--profile ID|PATH]\n"
        "       [--profiles-dir DIR] [--capability IDS]\n"
        "       [--lc-object PATH] [--cp-object PATH]\n"
        "\n"
        "Run a short smoke capture into DIR and, when it\n"
        "proves the requested channels, publish a\n"
        "machine-local local-auto receipt under\n"
        "<profiles-dir>/receipts. Without --bridge, the native\n"
        "bridge is discovered: LMB_NATIVE_LIB when unprivileged,\n"
        "then beside the executable, then the system path.\n"
        "Without --object, --lc-object, or --cp-object, each\n"
        "BPF object is discovered beside the executable or\n"
        "under the system directory, else the run refuses.\n"
        "The smoke attaches, polls, and detaches once; an\n"
        "idle ring is honest success and still qualifies.\n"
        "Receipts never claim\n"
        "validated. Diagnostics go to stderr.\n"
        "\n"
        "--capability selects channels as a comma-separated\n"
        "list without spaces (default: attempt-trace, which\n"
        "is always required). mapping-lifecycle uses\n"
        "--lc-object and copy-actual uses --cp-object when\n"
        "given, else the discovered object for that channel.\n"
    )


struct QualPlan(Copyable, Movable):
    """One qualification plan: doc, kernel, bindings, caps.

    ``ok`` False carries an exit-3 ``refusal``; otherwise
    the doc covers this kernel, its identity bindings
    hold, every tracing-hook signature matches live BTF,
    and ``caps`` names the requested capabilities in
    order. ``signatures`` holds the per-hook verdicts
    (all ok) for receipt detail and auditors.
    ``doc_source`` is the exact file the smoke must
    resolve: the explicit path verbatim, else the planned
    manifest entry under the profiles dir. The smoke
    never re-resolves a bare id, so a same-named
    working-directory file cannot substitute the doc.
    """

    var ok: Bool
    var refusal: String
    var doc: Profile
    var doc_source: String
    var kernel: KernelInfo
    var bindings: NarrowBindings
    var caps: List[String]
    var signatures: List[SigVerdict]

    def __init__(out self):
        self.ok = False
        self.refusal = String("")
        self.doc = Profile()
        self.doc_source = String("")
        self.kernel = KernelInfo(String(""), String(""), False, String(""))
        self.bindings = NarrowBindings()
        self.caps = List[String]()
        self.signatures = List[SigVerdict]()


def _refuse_plan(reason: String) -> QualPlan:
    var out = QualPlan()
    out.refusal = reason
    return out^


def _join(root: String, path: String) -> String:
    if root == String("/") or root == String(""):
        return path
    return root + path


def _covers(kernel: KernelInfo, doc: Profile) -> Bool:
    var one = List[Profile]()
    one.append(doc.copy())
    return select_profile(kernel, one^).has_profile


def _explicit_doc(
    explicit: String,
    named: NamedProfiles,
    profiles_dir: String,
    mut doc: Profile,
    mut source: String,
) -> String:
    """Resolve --profile by file then id; "" when resolved.

    ``source`` reports the exact file the smoke must
    resolve: the explicit path verbatim for the file
    branch, else the matched manifest entry.
    """
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
            doc = parse_profile_bytes(doc_bytes^)
        except e:
            return String("cannot parse --profile: ") + String(e)
        source = explicit.copy()
        return String("")
    for i in range(len(named.profiles)):
        if named.profiles[i].profile_id == explicit:
            doc = named.profiles[i].copy()
            source = profiles_dir + String("/") + named.names[i]
            return String("")
    return String("unknown --profile: ") + explicit


def plan_qualification(
    root: String, profiles_dir: String, opts: QualifyOptions
) -> QualPlan:
    """Select one doc and prove it statically; never raises.

    The capability request must parse and name a record
    channel, the evidence root must open above the 7.0
    floor, and one covering doc must exist (explicit or
    first in manifest order). The doc's identity
    bindings must parse and hold against the live tree,
    and every tracing-hook signature must match live
    BTF. Any failure refuses with its exact cause; the
    smoke runs only on an ok plan.
    """
    var ask = parse_requested_caps(opts.capabilities)
    if not ask.ok:
        return _refuse_plan(ask.err.copy())
    for i in range(len(ask.caps)):
        if ask.caps[i] == String(_CONVERT):
            return _refuse_plan(
                String(
                    "capability conversion-observe has no record channel"
                )
            )
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(root)
    except e:
        return _refuse_plan(
            String("cannot open evidence: ") + String(e)
        )
    var env = detect_environment(reader)
    if not env.kernel.eligible_floor:
        return _refuse_plan(
            String("kernel ")
            + env.kernel.release
            + String(" below floor 7.0")
        )
    var named: NamedProfiles
    try:
        named = load_profiles_named(profiles_dir)
    except e:
        return _refuse_plan(
            String("cannot load profiles: ") + String(e)
        )
    var doc = Profile()
    var source = String("")
    if opts.has_profile:
        var err = _explicit_doc(
            opts.profile, named, profiles_dir, doc, source
        )
        if err != String(""):
            return _refuse_plan(err)
        if not _covers(env.kernel, doc):
            return _refuse_plan(
                String("profile does not cover this kernel")
            )
    else:
        var found = False
        for i in range(len(named.profiles)):
            if _covers(env.kernel, named.profiles[i]):
                doc = named.profiles[i].copy()
                source = (
                    profiles_dir + String("/") + named.names[i]
                )
                found = True
                break
        if not found:
            return _refuse_plan(
                String("no profile covers this kernel")
            )
    var parsed = parse_narrow_note(doc.identity.source.note)
    if not parsed.ok:
        return _refuse_plan(
            String("profile ")
            + doc.profile_id
            + String(" bindings unparseable: ")
            + parsed.message
        )
    var sel = select_attempt_hook(doc)
    if not sel.ok:
        return _refuse_plan(sel.refusal.copy())
    var bound = check_identity_bindings(
        root,
        env.kernel.release,
        doc.identity.source.note,
        String(_ZLIB),
        sel.hook.format_path,
    )
    if bound.state != String("bound"):
        return _refuse_plan(
            String("binding failed: ") + bound.key + String(" ") + bound.state
        )
    var btf: List[UInt8]
    try:
        btf = read_host_file(
            _join(root, String(_BTF_PATH)),
            String("btf"),
            MAX_NARROW_BTF_BYTES,
        )
    except e:
        # Binding just hashed this file, so only a
        # concurrent disappearance lands here.
        return _refuse_plan(String("BTF unreadable: ") + String(e))
    var sigs = verify_hook_signatures(doc, Span(btf))
    for i in range(len(sigs)):
        if not sigs[i].ok:
            return _refuse_plan(sigs[i].reason.copy())
    var out = QualPlan()
    out.ok = True
    out.doc = doc.copy()
    out.doc_source = source.copy()
    out.kernel = env.kernel.copy()
    out.bindings = parsed.bindings.copy()
    out.caps = ask.caps.copy()
    out.signatures = sigs.copy()
    return out^


@fieldwise_init
struct PublishError(Copyable, Writable):
    """One receipt-publication failure: cause attached."""

    var message: String


def _errno_now() -> Int:
    var p = external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()
    return Int(p.unsafe_load())


def _cstr(text: String) raises PublishError -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        if raw[i] == UInt8(0):
            raise PublishError("NUL byte in path")
        out.append(raw[i])
    out.append(UInt8(0))
    return out^


def _close_quiet(fd: Int32):
    _ = external_call["close", Int32](fd)


def _write_all(fd: Int32, raw: Span[UInt8, _]) raises PublishError:
    var total = len(raw)
    var off = 0
    while off < total:
        var n = external_call["write", Int](
            Int(fd),
            Span(raw).unsafe_ptr().unsafe_offset(off),
            total - off,
        )
        if n < 0:
            var no = _errno_now()
            if no == _EINTR:
                continue
            raise PublishError(
                String("receipt write failed: errno ") + String(no)
            )
        if n == 0:
            raise PublishError("receipt write returned 0")
        off += n


def _unlink_at_quiet(dir_fd: Int32, name: List[UInt8]):
    _ = external_call["unlinkat", Int32](
        dir_fd, Span(name).unsafe_ptr(), Int32(0)
    )


def _open_tmp(dir_fd: Int32, name: List[UInt8]) -> Int32:
    return external_call["openat", Int32](
        dir_fd,
        Span(name).unsafe_ptr(),
        Int32(_O_WRONLY | _O_CREAT | _O_EXCL | _O_NOFOLLOW),
        UInt32(0o644),
    )


def publish_receipt(path: String, text: String) raises:
    """Atomically publish receipt text at path.

    The parent directory is created when missing, then
    pinned with O_DIRECTORY|O_NOFOLLOW before any byte
    is written; every later step runs descriptor-
    relative, so a swapped parent or link cannot
    redirect the write. The tmp file is created
    O_EXCL (a stale or planted name is unlinked once
    and retried once, then refuses), written, synced,
    and renamed over the final name, and the pinned
    directory is synced last. A crash leaves the old
    receipt or nothing, never a half-written file.
    Raises PublishError with the errno on any failure.
    """
    var raw = path.as_bytes()
    var slash = -1
    for i in range(len(raw)):
        if raw[i] == UInt8(0x2F):
            slash = i
    if slash <= 0 or slash + 1 >= len(raw):
        raise PublishError("receipt path has no directory")
    var parent: String
    var final: String
    try:
        parent = String(from_utf8=raw[0:slash])
        final = String(from_utf8=raw[slash + 1 : len(raw)])
    except:
        raise PublishError("receipt path undecodable")
    var parent_cstr = _cstr(parent)
    _ = external_call["mkdirat", Int32](
        Int32(_AT_FDCWD), Span(parent_cstr).unsafe_ptr(), 0o755
    )
    var dir_fd = external_call["openat", Int32](
        Int32(_AT_FDCWD),
        Span(parent_cstr).unsafe_ptr(),
        Int32(_O_DIRECTORY | _O_NOFOLLOW),
        UInt32(0),
    )
    if dir_fd < Int32(0):
        raise PublishError(
            String("receipt dir unavailable: errno ")
            + String(_errno_now())
        )
    var pid = Int(external_call["getpid", Int32]())
    var tmp_cstr = _cstr(final + String(".tmp.") + String(pid))
    var fd = _open_tmp(dir_fd, tmp_cstr)
    if fd < Int32(0) and _errno_now() == _EEXIST:
        _unlink_at_quiet(dir_fd, tmp_cstr)
        fd = _open_tmp(dir_fd, tmp_cstr)
    if fd < Int32(0):
        var no = _errno_now()
        _close_quiet(dir_fd)
        raise PublishError(
            String("receipt create failed: errno ") + String(no)
        )
    try:
        _write_all(fd, text.as_bytes())
        if Int(external_call["fsync", Int32](fd)) != 0:
            raise PublishError(
                String("receipt fsync failed: errno ")
                + String(_errno_now())
            )
    except e:
        _close_quiet(fd)
        _unlink_at_quiet(dir_fd, tmp_cstr)
        _close_quiet(dir_fd)
        raise PublishError(String(e))
    _close_quiet(fd)
    var final_cstr = _cstr(final)
    # Plain renameat intentionally replaces: re-qualify
    # must overwrite an expired receipt, and concurrent
    # same-operator qualifies resolve atomic
    # last-writer-wins with whole files. NOREPLACE would
    # break renewal for no safety gain.
    var rn = external_call["renameat", Int32](
        dir_fd,
        Span(tmp_cstr).unsafe_ptr(),
        dir_fd,
        Span(final_cstr).unsafe_ptr(),
    )
    if Int(rn) != 0:
        var no = _errno_now()
        _unlink_at_quiet(dir_fd, tmp_cstr)
        _close_quiet(dir_fd)
        raise PublishError(
            String("receipt rename failed: errno ") + String(no)
        )
    if Int(external_call["fsync", Int32](dir_fd)) != 0:
        var no = _errno_now()
        _close_quiet(dir_fd)
        raise PublishError(
            String("receipt dir fsync failed: errno ") + String(no)
        )
    _close_quiet(dir_fd)


def _qualify_failed(detail: String) raises -> Int:
    """Report one cannot-qualify outcome; return EXIT_REFUSAL."""
    write_stderr(
        String("memveil qualify: ")
        + sanitize_diagnostic(detail)
        + String("\n")
    )
    return EXIT_REFUSAL


def _qualify_misused(detail: String) raises -> Int:
    """Report one usage failure; return EXIT_INVALID."""
    write_stderr(
        String("memveil qualify: ")
        + sanitize_diagnostic(detail)
        + String("\n")
    )
    return EXIT_INVALID


def _qualify_broken(detail: String) raises -> Int:
    """Report one internal failure; return EXIT_INTERNAL."""
    try:
        write_stderr(
            String("memveil qualify: ")
            + sanitize_diagnostic(detail)
            + String("\n")
        )
    except:
        pass
    return EXIT_INTERNAL


def smoke_shutdown_ok(output: String) -> Bool:
    """Session-file proof the smoke shut down cleanly.

    RunResult alone cannot tell failed-detach (dirty
    teardown, hooks possibly still armed) from an idle
    ring (honest quiet): both end duration/finalized
    with a nonzero exit. Only the written session.json
    records stop.admission_closed, so qualify mints only
    when the smoke's own session file says the collector
    closed admission. Any read or parse failure refuses.
    The file is the collector's own just-written output
    in this run's directory, not cross-principal input:
    the operator qualifies their own machine.
    """
    var raw = List[UInt8]()
    try:
        raw = read_host_file(
            output + String("/session.json"),
            String("session"),
            8388608,
        )
    except:
        return False
    try:
        var session = parse_session(raw^)
        return session.stop.admission_closed
    except:
        return False


def _hash_object(path: String) raises -> String:
    """sha256: hex of one object file, or raise."""
    var elf = read_host_file(
        path, String("object"), MAX_NARROW_OBJECT_BYTES
    )
    return String("sha256:") + sha256_hex(Span(elf))


def _smoke_bridge_hash(snap: BridgeSnapshot) raises -> String:
    """sha256: hash of the smoke's exercised bridge bytes, or raise.

    The receipt binds the snapshot taken before the
    smoke, never a post-smoke pathname re-read: a swap
    after the smoke cannot mint a receipt for bytes the
    smoke never exercised. An unbound snapshot (empty
    hash) refuses instead of hashing a pathname.
    """
    if snap.sha == String(""):
        raise Error("bridge identity unbound for this smoke")
    return String("sha256:") + snap.sha


def _smoke_object_hash(snap: BridgeSnapshot) raises -> String:
    """sha256: hash of the smoke's exercised object bytes, or raise.

    The receipt binds the snapshot taken before the
    smoke, never a post-smoke pathname re-read: a swap
    after the smoke cannot mint a receipt for bytes the
    smoke never exercised. An unbound snapshot (empty
    hash) refuses instead of hashing a pathname.
    """
    if snap.sha == String(""):
        raise Error("object identity unbound for this smoke")
    return String("sha256:") + snap.sha


def run_qualify_with(
    root: String, profiles_dir: String, opts: QualifyOptions
) raises -> Int:
    """Run the qualify flow against explicit roots; exit code.

    ``root`` is the evidence root ("" for the live host)
    and ``profiles_dir`` holds ``manifest.txt`` plus the
    ``receipts/`` cache. The smoke runs the collector in
    explicit mode against the planned doc; only a
    finalized duration-ended smoke whose session file
    proves stop.admission_closed mints, and minting
    publishes exactly one local-auto receipt. Refusals
    print one diagnostic and exit 3 before any receipt
    exists.
    """
    var output = opts.output.copy()
    var bridge = resolve_bridge(opts.bridge, opts.has_bridge)
    # Pin the bridge before the smoke: the smoke loads
    # through the snapshot's fd alias and the receipt
    # binds the snapshot hash, so a pathname swap on
    # either side of the smoke binds nothing new. The
    # snapshot lives in this scope, covering the smoke.
    var snap = open_bridge_snapshot(bridge)
    var exe_path = String("")
    try:
        exe_path = readlink_self()
    except:
        exe_path = String("")
    var object_path = resolve_object(
        String("attempt"), opts.object, exe_path
    )
    if object_path == String(""):
        return _qualify_failed(
            String("no object: pass --object PATH")
        )
    # Pin the objects before the smoke, like the
    # bridge: the smoke reads through the snapshot
    # aliases and the receipt binds the snapshot
    # hashes, so a pathname swap on either side of
    # the smoke binds nothing new. The snapshots
    # live in this scope, covering the smoke.
    var obj_snap = open_object_snapshot(object_path)
    var lc_object = opts.lc_object.copy()
    var cp_object = opts.cp_object.copy()
    var want_caps = opts.capabilities.copy()
    var plan = plan_qualification(root, profiles_dir, opts)
    if not plan.ok:
        return _qualify_failed(plan.refusal.copy())
    var want_lc = False
    var want_cp = False
    for i in range(len(plan.caps)):
        if plan.caps[i] == String(_LIFECYCLE):
            want_lc = True
        if plan.caps[i] == String(_COPY):
            want_cp = True
    if lc_object == String("") and want_lc:
        lc_object = resolve_object(
            String("lifecycle"), String(""), exe_path
        )
    if cp_object == String("") and want_cp:
        cp_object = resolve_object(
            String("copy"), String(""), exe_path
        )
    var lc_snap = open_object_snapshot(lc_object)
    var cp_snap = open_object_snapshot(cp_object)
    var ropts = RecordOptions()
    ropts.output = output.copy()
    ropts.object = obj_snap.load_path.copy()
    ropts.bridge = snap.load_path.copy()
    ropts.has_bridge = snap.load_path != String("")
    # The smoke resolves the planned source path, never a
    # bare id: plan.doc_source is the explicit file verbatim
    # or the planned manifest entry, so a same-named file in
    # the working directory cannot substitute the document
    # through record's file-first resolver.
    ropts.profile = plan.doc_source.copy()
    ropts.has_profile = True
    ropts.lc_object = lc_snap.load_path.copy()
    ropts.cp_object = cp_snap.load_path.copy()
    ropts.capabilities = want_caps.copy()
    ropts.duration_s = _SMOKE_DURATION_S
    var writer = LiveWriter()
    var result = run_collector_with(
        root, profiles_dir, ropts^, writer
    )
    if (
        result.outcome != String("finalized")
        or result.end_reason != String("duration")
    ):
        var detail = (
            String("smoke ")
            + result.end_reason
            + String("/")
            + result.outcome
        )
        if result.diagnostic != String(""):
            detail += String(": ") + result.diagnostic
        return _qualify_failed(detail)
    if not smoke_shutdown_ok(output):
        return _qualify_failed(
            String(
                "smoke shutdown unproven: session"
                " stop.admission_closed is false or"
                " unreadable"
            )
        )
    var created = wall_ns()
    if created == UInt64(0):
        return _qualify_broken(String("wall clock unreadable"))
    var smoke = (
        String("smoke end=duration outcome=finalized exit=")
        + String(result.exit_code)
    )
    var caps = List[CapQualification]()
    for i in range(len(plan.caps)):
        if plan.caps[i] == String(_ATTEMPT):
            caps.append(
                CapQualification(
                    plan.caps[i].copy(),
                    String("layout holds; ") + smoke,
                )
            )
        else:
            caps.append(
                CapQualification(
                    plan.caps[i].copy(),
                    String("signatures hold; ") + smoke,
                )
            )
    var obj_attempt = String("")
    var obj_lc = String("")
    var obj_cp = String("")
    try:
        obj_attempt = _smoke_object_hash(obj_snap)
        if lc_object != String(""):
            obj_lc = _smoke_object_hash(lc_snap)
        if cp_object != String(""):
            obj_cp = _smoke_object_hash(cp_snap)
    except e:
        return _qualify_broken(
            String("smoke objects unbound: ") + String(e)
        )
    try:
        bridge = _smoke_bridge_hash(snap)
    except e:
        return _qualify_broken(
            String("smoke bridge unbound: ") + String(e)
        )
    var receipt = String("")
    try:
        receipt = mint_qualification_receipt(
            plan.doc.profile_id,
            plan.kernel,
            plan.bindings,
            created,
            caps^,
            String(ENGINE_VERSION),
            bridge,
            obj_attempt,
            obj_lc,
            obj_cp,
            _SMOKE_DURATION_S,
            String(_SMOKE_NOTE),
        )
    except e:
        return _qualify_broken(
            String("cannot mint receipt: ") + String(e)
        )
    var pid = plan.doc.profile_id.copy()
    var path = profiles_dir + String("/receipts/") + pid + String(".json")
    try:
        publish_receipt(path, receipt)
    except e:
        return _qualify_broken(
            String("cannot publish receipt: ") + String(e)
        )
    var listed = String("")
    for i in range(len(plan.caps)):
        if i > 0:
            listed += String(",")
        listed += plan.caps[i]
    try:
        write_stdout(
            String("qualify: local-auto ")
            + pid
            + String(" caps=")
            + listed
            + String(" receipt=")
            + path
            + String("\n")
        )
    except:
        return _qualify_broken(String("cannot write stdout"))
    return EXIT_OK


def run_qualify(args: List[String]) raises -> Int:
    """Run the qualify verb; return the process exit code.

    args excludes the program name and the qualify word.
    Profiles resolve from --profiles-dir or the
    kernel-resolved binary path, never from argv[0] or
    the working directory.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(qualify_usage())
            except:
                return _qualify_broken(String("cannot write stdout"))
            return EXIT_OK
        i += 1
    var opts: QualifyOptions
    try:
        opts = parse_qualify_args(args)
    except e:
        return _qualify_misused(e.message)
    var profiles_dir = opts.profiles_dir
    if not opts.has_profiles_dir:
        try:
            profiles_dir = resolve_profiles_dir()
        except e:
            return _qualify_failed(
                String("cannot resolve profiles location: ") + e.message
            )
    return run_qualify_with(String(""), profiles_dir, opts^)
