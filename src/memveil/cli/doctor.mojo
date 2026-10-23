# SPDX-License-Identifier: GPL-3.0-or-later

"""memveil doctor: passive environment and capability report.

``run_doctor`` implements the ``doctor`` verb against the
live host and ``profiles/``. ``run_doctor_with`` is the same flow
against an explicit evidence root and profiles directory, so tests
drive fixtures through the identical code path.

Exit codes: 0 when attempt-trace is available (ready), 3 when the
requested collection is unavailable or unknown, 2 on usage or
internal errors (bad fixture header, unreadable profiles). The
rendered report goes to stdout and nothing else does; every
diagnostic goes to stderr. Only a broken standard error raises.

Text and ``--json`` render the same DoctorReport2; the JSON matches
the doctor-v0.1.1 schema exactly. Every interpolated evidence
fragment is sanitized for its sink.
"""

from memveil.capture.loadcheck import (
    LoadResult,
    LoadTarget,
    load_check,
)
from memveil.capture.run import (
    attempt_program_names,
    copy_program_names,
    decide_record,
    lifecycle_program_names,
    loadcheck_bridge_sha,
    parse_requested_caps,
    resolve_bridge,
    resolve_object,
)
from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.platform.btf import read_object_map_bytes
from memveil.platform.stdout import write_stdout
from memveil.platform.capabilities import attempt_loss_exact
from memveil.platform.evidence import (
    EnvironmentEvidence,
    GuestInfo,
    KernelInfo,
    detect_environment,
)
from memveil.platform.kernelgate import (
    BtfFacts,
    LockdownState,
    kernel_gate,
    remedy_for,
)
from memveil.platform.prechecks import (
    PreCheck,
    check_memcg,
    check_privilege,
    check_unprivileged_bpf,
)
from memveil.platform.profiles import (
    Profile,
    ProfileDecision,
    load_profiles,
    select_profile_bound,
)
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_OK,
    EvidenceError,
    EvidenceReader,
    bytes_to_text,
    file_state,
    open_evidence_reader,
    read_evidence,
    read_host_file,
    readlink_self,
)
from memveil.platform.runtime import is_privileged, live_uids
from memveil.render.json import escape_json


comptime EXIT_UNAVAILABLE = 3
comptime _ZLIB = "libz.so.1"
comptime _OBJECT_BYTES_CAP = 67108864
comptime _CMDLINE_CAP = 65536
comptime _NSLABS_CAP = 64
comptime _MAX_NEED = 9223372036854775807




def doctor_usage() -> String:
    """Usage text for the doctor verb."""
    return (
        "usage: memveil doctor [--json] [--profiles-dir DIR]"
        " [--capability LIST] [--object PATH] [--lc-object PATH]"
        " [--cp-object PATH] [--bridge PATH] [--load-check]\n"
        "\n"
        "Judge every requested capability through record admission\n"
        "and print one environment and capability report on stdout.\n"
        "Diagnostics go to stderr. Exit 0 when the requested\n"
        "capabilities are available, 3 when requested collection\n"
        "is unavailable or unknown, 2 on usage or internal errors.\n"
        "Profiles resolve from the executable location, never from\n"
        "the caller's working directory.\n"
        "Passive by default: no BPF load, no bridge access;\n"
        "--load-check loads every requested object without attaching.\n"
        "\n"
        "  --json            print the doctor-v0.1.1 JSON report.\n"
        "  --profiles-dir DIR  profiles directory"
        " (default: executable-relative).\n"
        "  --capability LIST   comma-separated capability ids,"
        " or all (default all).\n"
        "  --object PATH       attempt channel object"
        " (default: discovered).\n"
        "  --lc-object PATH    lifecycle channel object"
        " (default: discovered).\n"
        "  --cp-object PATH    copy channel object"
        " (default: discovered).\n"
        "  --bridge PATH       bridge library"
        " (used only with --load-check).\n"
        "  --load-check        load every requested object"
        " without attaching.\n"
    )


def default_profiles_dir(prog: String) -> String:
    """Locate the profiles dir from the program path.

    Layout contract: the executable lives one directory below
    the tree root (``<root>/build/memveil`` in a checkout,
    ``<root>/bin/memveil`` packaged), with profiles at
    ``<root>/profiles``. An executable installed at
    ``/usr/bin`` instead reads the FHS profiles dir. A bare
    program name (PATH lookup) falls back to ``./profiles``.
    """
    var parts = prog.split(String("/"))
    if len(parts) < 2:
        return String("profiles")
    var out = String("")
    for i in range(len(parts) - 1):
        if i != 0:
            out += "/"
        out += String(parts[i])
    if out.byte_length() == 0:
        out = String("/")
    if out == "/":
        return String("/../profiles")
    if out == String("/usr/bin"):
        return String("/usr/share/memveil/profiles")
    return out + String("/../profiles")


def resolve_profiles_dir() raises EvidenceError -> String:
    """Locate the profiles dir from the kernel-resolved binary path.

    There is deliberately no argv[0] fallback: when /proc/self/exe
    cannot be resolved, guessing from argv[0] or the working
    directory could load a planted tree's profiles, so resolution
    failure is an explicit error instead.
    """
    var exe = readlink_self()
    return default_profiles_dir(exe)


def _doctor_failed(detail: String) raises -> Int:
    """Report one doctor failure on stderr; return EXIT_INVALID."""
    write_stderr("memveil doctor: " + sanitize_diagnostic(detail) + "\n")
    return EXIT_INVALID








def run_doctor_with(
    root: String, profiles_dir: String, as_json: Bool
) raises -> Int:
    """Run the doctor flow against explicit roots; return exit code.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. Wrapper over the
    admission-judging pipeline with discovery for every
    object and capabilities ``all``. Doctor is
    bridge-independent: it never discovers, opens, or
    hashes the bridge or any environment-selected
    stream, so receipt checks run with an unchecked
    bridge identity and report it as such; bridge
    admission checks belong on collection paths. The
    report goes to stdout; failures go to stderr with
    exit 2.
    """
    var opts = DoctorOptions()
    opts.root = root
    opts.profiles_dir = profiles_dir
    opts.as_json = as_json
    return run_doctor_opts(opts^)


def run_doctor(args: List[String]) raises -> Int:
    """Run the doctor verb; return the process exit code.

    args excludes the program name and the doctor word. Only
    the usage flags are accepted; anything else is a usage
    error. Without the flag, profiles resolve from the
    kernel-resolved binary path, never from argv[0] or the
    working directory.
    """
    var i = 0
    while i < len(args):
        if args[i] == "--help" or args[i] == "-h":
            try:
                write_stdout(doctor_usage())
            except:
                write_stderr("memveil doctor: cannot write stdout\n")
                return EXIT_INTERNAL
            return EXIT_OK
        i += 1
    var as_json = False
    var profiles_dir = String("")
    var has_profiles_dir = False
    var capabilities = String("all")
    var object = String("")
    var lc_object = String("")
    var cp_object = String("")
    var bridge = String("")
    var has_bridge = False
    var load_check = False
    i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--json":
            as_json = True
            i += 1
        elif tok == "--load-check":
            load_check = True
            i += 1
        elif tok == "--profiles-dir":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--profiles-dir needs a value")
            profiles_dir = args[i + 1]
            has_profiles_dir = True
            i += 2
        elif tok == "--capability":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--capability needs a value")
            capabilities = args[i + 1]
            i += 2
        elif tok == "--object":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--object needs a value")
            object = args[i + 1]
            i += 2
        elif tok == "--lc-object":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--lc-object needs a value")
            lc_object = args[i + 1]
            i += 2
        elif tok == "--cp-object":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--cp-object needs a value")
            cp_object = args[i + 1]
            i += 2
        elif tok == "--bridge":
            if i + 1 >= len(args) or args[i + 1] == "":
                return _doctor_failed("--bridge needs a value")
            bridge = args[i + 1]
            has_bridge = True
            i += 2
        else:
            return _doctor_failed("unknown option: " + tok)
    if not has_profiles_dir:
        try:
            profiles_dir = resolve_profiles_dir()
        except e:
            return _doctor_failed(
                "cannot resolve profiles location: " + e.message
            )
    var opts = DoctorOptions()
    opts.root = String("")
    opts.profiles_dir = profiles_dir
    opts.as_json = as_json
    opts.capabilities = capabilities
    opts.object = object
    opts.lc_object = lc_object
    opts.cp_object = cp_object
    opts.bridge = bridge
    opts.has_bridge = has_bridge
    opts.load_check = load_check
    return run_doctor_opts(opts^)


struct DoctorCap(Copyable):
    """One judged capability: status, reason, code, evidence."""

    var id: String
    var status: String
    var reason: String
    var remedy: String
    var reason_code: String
    var evidence: List[String]

    def __init__(out self):
        self.id = String("")
        self.status = String("unknown")
        self.reason = String("")
        self.remedy = String("")
        self.reason_code = String("")
        self.evidence = List[String]()


struct DoctorOptions(Copyable):
    """Doctor inputs: roots, requested set, objects, load flag."""

    var root: String
    var profiles_dir: String
    var as_json: Bool
    var capabilities: String
    var object: String
    var lc_object: String
    var cp_object: String
    var bridge: String
    var has_bridge: Bool
    var load_check: Bool

    def __init__(out self):
        self.root = String("")
        self.profiles_dir = String("")
        self.as_json = False
        self.capabilities = String("all")
        self.object = String("")
        self.lc_object = String("")
        self.cp_object = String("")
        self.bridge = String("")
        self.has_bridge = False
        self.load_check = False


struct DoctorReport2(Copyable):
    """One admission-judged doctor report, ready to render.

    The 0.1.0 fields keep their meaning; ``mode`` names the
    run kind, ``btf``/``lockdown`` carry the kernel gate
    facts, ``requested``/``prechecks``/``load``/``notes``
    record the judgment inputs, and every capability gains
    a machine ``reason_code`` plus evidence lines.
    """

    var origin: String
    var kernel: KernelInfo
    var guest: GuestInfo
    var matched: Bool
    var has_profile: Bool
    var profile_id: String
    var profile_status: String
    var profile_reason: String
    var caps: List[DoctorCap]
    var euid: Int
    var denied: List[String]
    var verdict: String
    var summary: String
    var mode: String
    var btf: BtfFacts
    var lockdown: LockdownState
    var requested: List[String]
    var prechecks: List[PreCheck]
    var load: List[LoadResult]
    var notes: List[String]

    def __init__(out self):
        self.origin = String("fixture")
        self.kernel = KernelInfo(
            String(""), String(""), False, String("")
        )
        self.guest = GuestInfo(
            String("unknown"), List[String](), False, String("")
        )
        self.matched = False
        self.has_profile = False
        self.profile_id = String("")
        self.profile_status = String("")
        self.profile_reason = String("")
        self.caps = List[DoctorCap]()
        self.euid = 0
        self.denied = List[String]()
        self.verdict = String("unavailable")
        self.summary = String("")
        self.mode = String("passive")
        self.btf = BtfFacts()
        self.lockdown = LockdownState()
        self.requested = List[String]()
        self.prechecks = List[PreCheck]()
        self.load = List[LoadResult]()
        self.notes = List[String]()


def _clip_n(text: String, cap: Int) -> String:
    """Clip text to cap bytes at a UTF-8 edge, else verbatim."""
    if cap <= 0:
        return String("")
    var b = text.as_bytes()
    if len(b) <= cap:
        return text.copy()
    var n = cap
    while n > 0 and b[n] >= UInt8(0x80) and b[n] < UInt8(0xC0):
        n -= 1
    var cut = List[UInt8]()
    for i in range(n):
        cut.append(b[i])
    try:
        return String(from_utf8=Span(cut))
    except:
        return String("")


def _has_token(cmdline: String, token: String) -> Bool:
    """True when one blank-separated token matches exactly."""
    var norm = cmdline.replace(String("\x00"), String(" "))
    norm = norm.replace(String("\t"), String(" "))
    norm = norm.replace(String("\n"), String(" "))
    norm = norm.replace(String("\r"), String(" "))
    var parts = norm.split(String(" "))
    for i in range(len(parts)):
        if String(parts[i]) == token:
            return True
    return False


def _ascii_is_zero(raw: List[UInt8]) -> Bool:
    """True when raw is blank-padded ASCII digits of value 0."""
    var started = False
    var nonzero = False
    var trailing = False
    for i in range(len(raw)):
        var c = raw[i]
        if (
            c == UInt8(0x20)
            or c == UInt8(0x09)
            or c == UInt8(0x0A)
            or c == UInt8(0x0D)
        ):
            if started:
                trailing = True
            continue
        if trailing:
            return False
        if c < UInt8(0x30) or c > UInt8(0x39):
            return False
        started = True
        if c != UInt8(0x30):
            nonzero = True
    return started and not nonzero


def _swiotlb_pool_inactive(reader: EvidenceReader) -> Bool:
    """True when debugfs shows a swiotlb dir with no slabs.

    The kernel always creates the swiotlb directory and
    skips its files when the slab count is zero, so an
    absent directory proves nothing about the pool.
    """
    if (
        file_state(reader, String("/sys/kernel/debug/swiotlb"))
        != EVIDENCE_OK
    ):
        return False
    var npath = String("/sys/kernel/debug/swiotlb/io_tlb_nslabs")
    var st = file_state(reader, npath.copy())
    if st == EVIDENCE_ABSENT:
        return True
    if st != EVIDENCE_OK:
        return False
    try:
        var raw = read_evidence(reader, npath, _NSLABS_CAP)
        return _ascii_is_zero(raw^)
    except:
        return False


def _is_object_refusal(refusal: String) -> Bool:
    """True when record refused over a channel object."""
    if refusal.startswith(String("no object:")):
        return True
    if refusal == String("object unreadable"):
        return True
    if refusal.startswith(String("object refused")):
        return True
    if refusal.startswith(String("object ring too large")):
        return True
    if refusal.find(String(" object unreadable")) != -1:
        return True
    if refusal.find(String(" object refused")) != -1:
        return True
    return refusal.find(String(" object ring too large")) != -1


def _is_floor_refusal(refusal: String) -> Bool:
    """True when record refused over the kernel floor."""
    if refusal.find(String(" is unparseable; floor unknown")) != -1:
        return True
    return (
        refusal.find(String(" needs kernel ")) != -1
        and refusal.find(String("(this kernel: ")) != -1
    )


def _is_unsupported_declaration(
    refusal: String, cap: String
) -> Bool:
    """True for 'capability <cap> unsupported by <doc>'."""
    var head = (
        String("capability ") + cap + String(" unsupported by ")
    )
    if len(refusal.as_bytes()) < len(head.as_bytes()):
        return False
    return refusal.startswith(head)


def _reason_code_for(refusal: String, code: String) -> String:
    """One machine code for a record refusal.

    Gate codes pass through; selection refusals decode to
    the object, floor, or profile code from their text.
    """
    if code != String("profile"):
        return code.copy()
    if _is_object_refusal(refusal):
        return String("object-missing")
    if _is_floor_refusal(refusal):
        return String("floor")
    return String("profile")


def _precheck_line(pc: PreCheck) -> String:
    """One evidence line for a non-pass pre-check."""
    return (
        pc.id + String(": ") + pc.state + String(": ") + pc.reason
    )


def _load_kind(cap_id: String) -> String:
    """Channel kind for one capability, else ``""``."""
    if cap_id == String("attempt-trace"):
        return String("attempt")
    if cap_id == String("mapping-lifecycle"):
        return String("lifecycle")
    if cap_id == String("copy-actual"):
        return String("copy")
    return String("")


def _load_code_for(errno: String) -> String:
    """One machine code for a load errno name."""
    if errno == String("EPERM"):
        return String("load-eperm")
    if errno == String("ENOMEM"):
        return String("load-enomem")
    if errno == String("EINVAL") or errno == String("EACCES"):
        return String("verifier-rejected")
    return String("load-failed")


def _no_bridge_detail() -> String:
    """Missing-bridge detail, matching the record refusal."""
    if is_privileged(live_uids()):
        return String(
            "no bridge: restore the bundled bridge or pass --bridge PATH"
        )
    return String("no bridge: pass --bridge or set LMB_NATIVE_LIB")


def _result_for_cap(
    ti: Int,
    results: List[LoadResult],
    synth_caps: List[Int],
    synth_res: List[LoadResult],
    ci: Int,
    cap_id: String,
) -> LoadResult:
    """One load entry: attempted result, race synthetic, or skipped."""
    if ti >= 0:
        return results[ti].copy()
    for s in range(len(synth_caps)):
        if synth_caps[s] == ci:
            return synth_res[s].copy()
    var sk = LoadResult()
    var kind = _load_kind(cap_id)
    if kind == String(""):
        sk.object = cap_id.copy()
    else:
        sk.object = kind.copy()
    sk.state = String("skipped")
    sk.detail = String("passive checks did not pass")
    return sk^


def assess_doctor(opts: DoctorOptions) -> DoctorReport2:
    """Judge every requested capability through record admission.

    Passive: no BPF load, no attach, no bridge access. Each
    of the three record capabilities runs ``decide_record``
    over its own set for its display row, and the verdict
    judges the requested set through one more call;
    conversion-observe has no record channel. A failed
    passive pre-check demotes an admitted capability to
    unavailable with that check's code. Bad roots,
    profiles, or capability lists yield an unavailable
    report naming the failure; the exit-code mapping lives
    in ``run_doctor_opts``. Under ``--load-check`` on the
    live host, every admitted object loads without
    attaching: loaded objects read ``available`` and the
    verdict is ``ready`` only when every requested object
    loaded.
    """
    var out = DoctorReport2()
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(opts.root)
    except e:
        out.summary = (
            String("unavailable: cannot open evidence: ") + String(e)
        )
        return out^
    if reader.root == String(""):
        out.origin = String("live")
    var env = detect_environment(reader)
    out.kernel = env.kernel.copy()
    out.guest = env.guest.copy()
    out.euid = reader.euid
    for i in range(len(env.denied)):
        out.denied.append(env.denied[i])
    var profiles: List[Profile]
    try:
        profiles = load_profiles(opts.profiles_dir)
    except e:
        out.summary = (
            String("unavailable: cannot load profiles: ")
            + String(e)
        )
        return out^
    var sel = List[Profile]()
    for i in range(len(profiles)):
        sel.append(profiles[i].copy())
    var decision = select_profile_bound(
        env.kernel,
        sel^,
        opts.root,
        String(_ZLIB),
        opts.profiles_dir,
        String(""),
    )
    out.matched = decision.matched
    out.has_profile = decision.has_profile
    if decision.has_profile:
        out.profile_id = decision.profile.profile_id
        out.profile_status = decision.profile.status
    out.profile_reason = decision.reason
    var ask = parse_requested_caps(opts.capabilities)
    if not ask.ok:
        out.summary = String("unavailable: ") + ask.err
        return out^
    for i in range(len(ask.caps)):
        out.requested.append(ask.caps[i])
    var gated = kernel_gate(
        reader, env.kernel.release, String(_ZLIB), ask.caps
    )
    out.btf = gated.btf.copy()
    out.lockdown = gated.lockdown.copy()
    var exe = String("")
    try:
        exe = readlink_self()
    except:
        pass
    var object_path = resolve_object(
        String("attempt"), opts.object, exe
    )
    var lc_path = resolve_object(
        String("lifecycle"), opts.lc_object, exe
    )
    var cp_path = resolve_object(String("copy"), opts.cp_object, exe)
    var need = 0
    for i in range(len(ask.caps)):
        var p = object_path.copy()
        if ask.caps[i] == String("mapping-lifecycle"):
            p = lc_path.copy()
        elif ask.caps[i] == String("copy-actual"):
            p = cp_path.copy()
        elif ask.caps[i] != String("attempt-trace"):
            continue
        if p == String(""):
            continue
        var elf: List[UInt8]
        try:
            elf = read_host_file(p, String("object"), _OBJECT_BYTES_CAP)
        except:
            continue
        var mb = read_object_map_bytes(Span(elf))
        if not mb.ok or mb.bytes <= 0:
            continue
        if need <= _MAX_NEED - mb.bytes:
            need += mb.bytes
        else:
            need = _MAX_NEED
    var priv = check_privilege(reader)
    var mem = check_memcg(reader, need)
    var unp = check_unprivileged_bpf(reader)
    out.prechecks.append(priv.copy())
    out.prechecks.append(mem.copy())
    out.prechecks.append(unp.copy())
    var fail_code = String("")
    var fail_reason = String("")
    if priv.state == String("fail"):
        fail_code = priv.code.copy()
        fail_reason = priv.reason.copy()
    elif mem.state == String("fail"):
        fail_code = mem.code.copy()
        fail_reason = mem.reason.copy()
    var loading = opts.load_check and opts.root == String("")
    var bridge = String("")
    var bridge_sha = String("")
    if loading:
        bridge = resolve_bridge(opts.bridge, opts.has_bridge)
        bridge_sha = loadcheck_bridge_sha(
            opts.bridge, opts.has_bridge
        )
    var plines = List[String]()
    if priv.state != String("pass") and len(plines) < 64:
        plines.append(_clip_n(_precheck_line(priv), 512))
    if mem.state != String("pass") and len(plines) < 64:
        plines.append(_clip_n(_precheck_line(mem), 512))
    if unp.state != String("pass") and len(plines) < 64:
        plines.append(_clip_n(_precheck_line(unp), 512))
    for i in range(len(ask.caps)):
        var cap = ask.caps[i].copy()
        var entry = DoctorCap()
        entry.id = cap.copy()
        if cap == String("conversion-observe"):
            entry.status = String("unsupported")
            entry.reason = String(
                "capability conversion-observe has no record channel"
            )
            entry.reason_code = String("unsupported")
            out.caps.append(entry^)
            continue
        var want = String("attempt-trace")
        if cap != String("attempt-trace"):
            want = String("attempt-trace,") + cap
        var pick = decide_record(
            opts.root,
            env.kernel,
            profiles,
            String(""),
            False,
            object_path,
            lc_path,
            cp_path,
            want,
            opts.profiles_dir,
            bridge_sha,
        )
        if not pick.ok:
            if _is_unsupported_declaration(pick.refusal, cap):
                entry.status = String("unsupported")
                entry.reason_code = String("unsupported")
            elif pick.refusal_unknown:
                entry.status = String("unknown")
                entry.reason_code = _reason_code_for(
                    pick.refusal, pick.refusal_code
                )
            else:
                entry.status = String("unavailable")
                entry.reason_code = _reason_code_for(
                    pick.refusal, pick.refusal_code
                )
            entry.reason = _clip_n(pick.refusal, 512)
            if pick.fix != String(""):
                entry.remedy = _clip_n(pick.fix, 512)
            else:
                entry.remedy = _clip_n(
                    remedy_for(entry.reason_code), 512
                )
            out.caps.append(entry^)
            continue
        if fail_code != String(""):
            entry.status = String("unavailable")
            entry.reason = _clip_n(fail_reason, 512)
            entry.reason_code = fail_code.copy()
            entry.remedy = _clip_n(remedy_for(fail_code), 512)
        else:
            entry.status = String("available-load-unchecked")
            entry.reason = _clip_n(pick.reason, 512)
            entry.reason_code = String("available")
            entry.remedy = String("")
        for j in range(len(plines)):
            if len(entry.evidence) < 64:
                entry.evidence.append(plines[j])
        if (
            entry.id == String("attempt-trace")
            and entry.status == String("available-load-unchecked")
            and not attempt_loss_exact(env.kernel.release)
            and len(entry.evidence) < 64
        ):
            entry.evidence.append(
                String(
                    "attempt loss counts are a lower bound before 6.7:"
                    " trace_call_bpf skipped programs without counting"
                    " them"
                )
            )
        out.caps.append(entry^)
    # The verdict judges the requested set as one record
    # admission; per-capability rows are display only.
    var whole_want = String("")
    for i in range(len(ask.caps)):
        if i != 0:
            whole_want += String(",")
        whole_want += ask.caps[i]
    var whole = decide_record(
        opts.root,
        env.kernel,
        profiles,
        String(""),
        False,
        object_path,
        lc_path,
        cp_path,
        whole_want,
        opts.profiles_dir,
        bridge_sha,
    )
    if loading:
        out.mode = String("load-check")
        var targets = List[LoadTarget]()
        var target_for_cap = List[Int]()
        for _ in range(len(out.caps)):
            target_for_cap.append(-1)
        var synth_caps = List[Int]()
        var synth_res = List[LoadResult]()
        for i in range(len(out.caps)):
            var kind = _load_kind(out.caps[i].id)
            if kind == String(""):
                continue
            if out.caps[i].status != String("available-load-unchecked"):
                continue
            var path = object_path.copy()
            if kind == String("lifecycle"):
                path = lc_path.copy()
            elif kind == String("copy"):
                path = cp_path.copy()
            var elf: List[UInt8]
            try:
                elf = read_host_file(
                    path, String("object"), _OBJECT_BYTES_CAP
                )
            except:
                var res = LoadResult()
                res.object = kind.copy()
                res.state = String("failed")
                res.detail = String("object unreadable at load")
                synth_caps.append(i)
                synth_res.append(res^)
                continue
            var target = LoadTarget()
            target.kind = kind.copy()
            target.elf = elf^
            if kind == String("attempt"):
                target.programs = attempt_program_names()
            elif kind == String("lifecycle"):
                target.programs = lifecycle_program_names()
            else:
                target.programs = copy_program_names()
            target_for_cap[i] = len(targets)
            targets.append(target^)
        var results = List[LoadResult]()
        if bridge == String(""):
            for t in range(len(targets)):
                var res = LoadResult()
                res.object = targets[t].kind.copy()
                res.state = String("failed")
                res.detail = _no_bridge_detail()
                results.append(res^)
        elif len(targets) > 0:
            results = load_check(targets^, bridge)
        for i in range(len(out.caps)):
            var res = _result_for_cap(
                target_for_cap[i],
                results,
                synth_caps,
                synth_res,
                i,
                out.caps[i].id,
            )
            if res.state == String("loaded"):
                out.caps[i].status = String("available")
            elif res.state == String("failed"):
                out.caps[i].status = String("unavailable")
                if res.errno == String(""):
                    out.caps[i].reason = _clip_n(res.detail, 512)
                else:
                    out.caps[i].reason = _clip_n(
                        String("load ")
                        + res.errno
                        + String(": ")
                        + res.detail,
                        512,
                    )
                out.caps[i].reason_code = _load_code_for(res.errno)
                var rcode = out.caps[i].reason_code.copy()
                out.caps[i].remedy = _clip_n(remedy_for(rcode), 512)
                for l in range(len(res.lines)):
                    if len(out.caps[i].evidence) < 64:
                        out.caps[i].evidence.append(res.lines[l])
            out.load.append(res^)
    var want = String("available-load-unchecked")
    if loading:
        want = String("available")
    var all_ok = True
    var first_refusal = String("")
    for i in range(len(out.caps)):
        if out.caps[i].status != want:
            all_ok = False
            if first_refusal == String(""):
                first_refusal = out.caps[i].reason.copy()
    var names = String("")
    for k in range(len(out.requested)):
        if k != 0:
            names += String(", ")
        names += out.requested[k]
    if not whole.ok:
        out.verdict = String("unavailable")
        out.summary = _clip_n(
            String("unavailable: ") + whole.refusal, 1024
        )
    elif all_ok and loading:
        out.verdict = String("ready")
        out.summary = String("ready: ") + names + String(" available")
        if out.has_profile:
            out.summary += String(" under ") + out.profile_id
    elif all_ok:
        out.verdict = String("ready-load-unchecked")
        out.summary = (
            String("ready (load not checked): ")
            + names
            + String(" available")
        )
        if out.has_profile:
            out.summary += String(" under ") + out.profile_id
    else:
        out.verdict = String("unavailable")
        out.summary = _clip_n(
            String("unavailable: ") + first_refusal, 1024
        )
    var cmdline = String("")
    var cmd_ok = False
    try:
        cmdline = bytes_to_text(
            read_evidence(
                reader, String("/proc/cmdline"), _CMDLINE_CAP
            )
        )
        cmd_ok = True
    except:
        pass
    if cmd_ok and _has_token(cmdline, String("swiotlb=noforce")):
        out.notes.append(
            String("no swiotlb pool active: attempts will be 0")
        )
    elif _swiotlb_pool_inactive(reader):
        out.notes.append(
            String("no swiotlb pool active: attempts will be 0")
        )
    if unp.state == String("pass"):
        out.notes.append(unp.reason.copy())
    return out^


def render_doctor_json2(rep: DoctorReport2) raises -> String:
    """Render one DoctorReport2 as doctor-v0.1.1 JSON."""
    var out = String("{\n")
    out += '  "schema_version": "0.1.1",\n'
    out += '  "mode": ' + escape_json(rep.mode) + ",\n"
    out += '  "provenance": {"origin": ' + escape_json(rep.origin) + "},\n"
    out += '  "kernel": {\n'
    out += '    "release": ' + escape_json(rep.kernel.release) + ",\n"
    out += '    "arch": ' + escape_json(rep.kernel.arch) + ",\n"
    if rep.kernel.eligible_floor:
        out += '    "eligible_floor": true,\n'
    else:
        out += '    "eligible_floor": false,\n'
    out += '    "floor_reason": ' + escape_json(
        rep.kernel.floor_reason
    ) + ",\n"
    out += '    "btf": {"state": ' + escape_json(rep.btf.state)
    out += ', "bytes": '
    if rep.btf.has_bytes:
        out += escape_json(String(rep.btf.bytes))
    else:
        out += "null"
    out += ', "config_btf": ' + escape_json(rep.btf.config_btf)
    out += ', "config_src": ' + escape_json(rep.btf.config_src)
    out += "},\n"
    out += '    "lockdown": {"mode": ' + escape_json(
        rep.lockdown.mode
    ) + ', "src": ' + escape_json(rep.lockdown.src) + "}\n"
    out += "  },\n"
    out += '  "guest": {\n'
    out += '    "tech": ' + escape_json(rep.guest.tech) + ",\n"
    out += '    "signals": ['
    for i in range(len(rep.guest.signals)):
        if i != 0:
            out += ", "
        out += escape_json(rep.guest.signals[i])
    out += "],\n"
    if rep.guest.asserted:
        out += '    "asserted": true,\n'
    else:
        out += '    "asserted": false,\n'
    out += '    "conflict": ' + escape_json(rep.guest.conflict) + "\n"
    out += "  },\n"
    out += '  "profile": {\n'
    if rep.matched:
        out += '    "matched": true,\n'
    else:
        out += '    "matched": false,\n'
    if rep.has_profile:
        out += '    "profile_id": ' + escape_json(
            rep.profile_id
        ) + ",\n"
        out += '    "status": ' + escape_json(
            rep.profile_status
        ) + ",\n"
    else:
        out += '    "profile_id": null,\n'
        out += '    "status": null,\n'
    out += '    "reason": ' + escape_json(rep.profile_reason) + "\n"
    out += "  },\n"
    out += '  "capabilities": ['
    for i in range(len(rep.caps)):
        if i != 0:
            out += ", "
        out += '{"id": ' + escape_json(rep.caps[i].id)
        out += ', "status": ' + escape_json(rep.caps[i].status)
        out += ', "reason": ' + escape_json(rep.caps[i].reason)
        out += ', "remedy": ' + escape_json(rep.caps[i].remedy)
        out += ', "reason_code": ' + escape_json(rep.caps[i].reason_code)
        out += ', "evidence": ['
        for j in range(len(rep.caps[i].evidence)):
            if j != 0:
                out += ", "
            out += escape_json(rep.caps[i].evidence[j])
        out += "]}"
    out += "],\n"
    out += '  "privilege": {\n'
    out += '    "euid": ' + String(rep.euid) + ",\n"
    out += '    "denied_paths": ['
    for i in range(len(rep.denied)):
        if i != 0:
            out += ", "
        out += escape_json(rep.denied[i])
    out += "]\n"
    out += "  },\n"
    out += '  "requested": ['
    for i in range(len(rep.requested)):
        if i != 0:
            out += ", "
        out += escape_json(rep.requested[i])
    out += "],\n"
    out += '  "prechecks": ['
    for i in range(len(rep.prechecks)):
        if i != 0:
            out += ", "
        out += '{"id": ' + escape_json(rep.prechecks[i].id)
        out += ', "state": ' + escape_json(rep.prechecks[i].state)
        out += ', "reason": ' + escape_json(rep.prechecks[i].reason)
        out += "}"
    out += "],\n"
    out += '  "load": ['
    for i in range(len(rep.load)):
        if i != 0:
            out += ", "
        out += '{"object": ' + escape_json(rep.load[i].object)
        out += ', "state": ' + escape_json(rep.load[i].state)
        out += ', "errno": '
        if rep.load[i].errno == String(""):
            out += "null"
        else:
            out += escape_json(rep.load[i].errno)
        out += ', "detail": ' + escape_json(rep.load[i].detail) + "}"
    out += "],\n"
    out += '  "notes": ['
    for i in range(len(rep.notes)):
        if i != 0:
            out += ", "
        out += escape_json(rep.notes[i])
    out += "],\n"
    out += '  "verdict": ' + escape_json(rep.verdict) + ",\n"
    out += '  "summary": ' + escape_json(rep.summary) + "\n"
    out += "}\n"
    return out


def _doctor2_status_text(status: String) -> String:
    """Text spelling of one capability status."""
    if status == String("available-load-unchecked"):
        return String("available (load not checked)")
    return status.copy()


def render_doctor_text2(rep: DoctorReport2) raises -> String:
    """Render one DoctorReport2 as human-readable text.

    Same shape as the 0.1.0 text, plus one ``note:`` line
    per note; load-unchecked statuses print in words.
    Every interpolated evidence fragment passes through
    the single-line diagnostic sanitizer.
    """
    var out = String(
        "memveil doctor ("
        + rep.mode
        + ", "
        + rep.origin
        + " evidence)\n"
    )
    out += (
        "kernel: "
        + sanitize_diagnostic(rep.kernel.release)
        + " "
        + sanitize_diagnostic(rep.kernel.arch)
        + " (floor 6.0: "
    )
    if rep.kernel.eligible_floor:
        out += "yes"
    else:
        out += "no"
    out += ")\n"
    out += "floor: " + sanitize_diagnostic(rep.kernel.floor_reason) + "\n"
    out += "guest: " + sanitize_diagnostic(rep.guest.tech)
    if rep.guest.asserted:
        out += " (user-asserted)"
    out += "\n"
    for i in range(len(rep.guest.signals)):
        out += "  signal: " + sanitize_diagnostic(
            rep.guest.signals[i]
        ) + "\n"
    if rep.guest.conflict.byte_length() != 0:
        out += (
            "  conflict: " + sanitize_diagnostic(rep.guest.conflict) + "\n"
        )
    if rep.has_profile:
        out += (
            "profile: "
            + sanitize_diagnostic(rep.profile_id)
            + " ("
            + sanitize_diagnostic(rep.profile_status)
            + ")\n"
        )
    else:
        out += "profile: none\n"
    out += (
        "profile-detail: " + sanitize_diagnostic(rep.profile_reason) + "\n"
    )
    out += "capabilities:\n"
    for i in range(len(rep.caps)):
        out += (
            "  "
            + sanitize_diagnostic(rep.caps[i].id)
            + ": "
            + sanitize_diagnostic(_doctor2_status_text(rep.caps[i].status))
            + " - "
            + sanitize_diagnostic(rep.caps[i].reason)
            + "\n"
        )
        if rep.caps[i].remedy != String(""):
            out += (
                "    fix: "
                + sanitize_diagnostic(rep.caps[i].remedy)
                + "\n"
            )
    for i in range(len(rep.notes)):
        out += "note: " + sanitize_diagnostic(rep.notes[i]) + "\n"
    out += "privilege: euid " + String(rep.euid)
    if len(rep.denied) != 0:
        out += ", denied:"
        for i in range(len(rep.denied)):
            out += " " + sanitize_diagnostic(rep.denied[i])
    out += "\n"
    out += "verdict: " + sanitize_diagnostic(rep.verdict) + "\n"
    out += "summary: " + sanitize_diagnostic(rep.summary) + "\n"
    return out


def run_doctor_opts(opts: DoctorOptions) raises -> Int:
    """Run the admission-judging doctor flow; return exit code.

    Bad roots, profiles, or capability lists fail with
    exit 2; a load check against a fixture root is
    rejected the same way. Otherwise the report goes to
    stdout with exit 0 when the requested set is ready
    and 3 when it is unavailable. Passive runs never
    touch the bridge.
    """
    if opts.load_check and opts.root != String(""):
        return _doctor_failed("--load-check needs the live host")
    try:
        _ = open_evidence_reader(opts.root)
    except e:
        return _doctor_failed("cannot open evidence: " + String(e))
    try:
        _ = load_profiles(opts.profiles_dir)
    except e:
        return _doctor_failed("cannot load profiles: " + String(e))
    var ask = parse_requested_caps(opts.capabilities)
    if not ask.ok:
        return _doctor_failed(ask.err.copy())
    var drep = assess_doctor(opts)
    var ready = (
        drep.verdict == String("ready")
        or drep.verdict == String("ready-load-unchecked")
    )
    try:
        if opts.as_json:
            write_stdout(render_doctor_json2(drep^))
        else:
            write_stdout(render_doctor_text2(drep^))
    except:
        write_stderr("memveil doctor: cannot write stdout\n")
        return EXIT_INTERNAL
    if ready:
        return EXIT_OK
    return EXIT_UNAVAILABLE
