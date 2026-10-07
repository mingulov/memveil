# SPDX-License-Identifier: GPL-3.0-or-later

"""memveil doctor: passive environment and capability report.

``run_doctor`` implements the ``doctor [--json]`` verb against the
live host and ``profiles/``. ``run_doctor_with`` is the same flow
against an explicit evidence root and profiles directory, so tests
drive fixtures through the identical code path.

Exit codes: 0 when attempt-trace is available (ready), 3 when the
requested collection is unavailable or unknown, 2 on usage or
internal errors (bad fixture header, unreadable profiles). The
rendered report goes to stdout and nothing else does; every
diagnostic goes to stderr. Only a broken standard error raises.

Text and ``--json`` render the same DoctorReport; the JSON matches
the doctor-v0.1.0 schema exactly. Every interpolated evidence
fragment is sanitized for its sink.
"""

from memveil.cli.report import (
    EXIT_INTERNAL,
    EXIT_INVALID,
    EXIT_OK,
    sanitize_diagnostic,
    write_stderr,
)
from memveil.platform.stdout import write_stdout
from memveil.platform.capabilities import (
    CapEntry,
    CapabilityReport,
    discover_capabilities,
)
from memveil.platform.evidence import (
    EnvironmentEvidence,
    GuestInfo,
    KernelInfo,
    detect_environment,
)
from memveil.platform.profiles import (
    Profile,
    ProfileDecision,
    load_profiles,
    select_profile,
)
from memveil.platform.reader import (
    EvidenceError,
    EvidenceReader,
    open_evidence_reader,
    readlink_self,
)
from memveil.render.json import escape_json


comptime EXIT_UNAVAILABLE = 3
comptime DOCTOR_SCHEMA_VERSION = "0.1.0"


struct DoctorReport(Copyable):
    """One assembled doctor report, ready to render.

    ``origin`` is ``live`` only for the live host reader;
    every fixture root renders ``fixture``.
    """

    var origin: String
    var kernel: KernelInfo
    var guest: GuestInfo
    var matched: Bool
    var has_profile: Bool
    var profile_id: String
    var profile_status: String
    var profile_reason: String
    var caps: List[CapEntry]
    var euid: Int
    var denied: List[String]
    var verdict: String
    var summary: String

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
        self.caps = List[CapEntry]()
        self.euid = 0
        self.denied = List[String]()
        self.verdict = String("unavailable")
        self.summary = String("")


def doctor_usage() -> String:
    """Usage text for the doctor verb."""
    return (
        "usage: memveil doctor [--json]\n"
        "\n"
        "Inspect the host passively (no BPF load, no system change)\n"
        "and print one environment and capability report on stdout.\n"
        "Diagnostics go to stderr. Exit 0 when attempt-trace is\n"
        "available, 3 when requested collection is unavailable or\n"
        "unknown, 2 on usage or internal errors.\n"
        "Profiles resolve from the executable location, never from\n"
        "the caller's working directory.\n"
        "\n"
        "  --json   print the doctor-v0.1.0 JSON report.\n"
    )


def default_profiles_dir(prog: String) -> String:
    """Locate the profiles dir from the program path.

    Layout contract: the executable lives one directory below
    the tree root (``<root>/build/memveil`` in a checkout,
    ``<root>/bin/memveil`` packaged), with profiles at
    ``<root>/profiles``. A bare program name (PATH lookup) falls
    back to ``./profiles``.
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


def build_doctor_report(
    reader: EvidenceReader,
    env: EnvironmentEvidence,
    decision: ProfileDecision,
    report: CapabilityReport,
) -> DoctorReport:
    """Assemble one DoctorReport from the pipeline stages.

    The verdict is ready only when the attempt-trace entry is
    available; any other outcome, including unknown, reads
    unavailable. Denied paths merge environment and hook denials.
    Origin derives from the reader root: only the live host ("")
    renders ``live``.
    """
    var out = DoctorReport()
    if reader.root == "":
        out.origin = String("live")
    out.kernel = env.kernel.copy()
    out.guest = env.guest.copy()
    out.matched = decision.matched
    out.has_profile = decision.has_profile
    if decision.has_profile:
        out.profile_id = decision.profile.profile_id
        out.profile_status = decision.profile.status
    out.profile_reason = decision.reason
    out.caps = List[CapEntry]()
    for i in range(len(report.entries)):
        out.caps.append(report.entries[i].copy())
    out.euid = reader.euid
    out.denied = List[String]()
    for i in range(len(env.denied)):
        out.denied.append(env.denied[i])
    for i in range(len(report.denied)):
        var seen = False
        for j in range(len(out.denied)):
            if out.denied[j] == report.denied[i]:
                seen = True
                break
        if not seen:
            out.denied.append(report.denied[i])
    var attempt_status = String("unknown")
    var attempt_reason = String("attempt-trace was not judged")
    for i in range(len(out.caps)):
        if out.caps[i].id == "attempt-trace":
            attempt_status = out.caps[i].status
            attempt_reason = out.caps[i].reason
            break
    if attempt_status == "available":
        out.verdict = String("ready")
        out.summary = (
            "ready: attempt-trace available under " + out.profile_id
        )
    else:
        out.verdict = String("unavailable")
        out.summary = "unavailable: " + attempt_reason
    return out^


def render_doctor_json(rep: DoctorReport) raises -> String:
    """Render one DoctorReport as doctor-v0.1.0 JSON."""
    var out = String("{\n")
    out += '  "schema_version": "0.1.0",\n'
    out += '  "mode": "passive",\n'
    out += '  "provenance": {"origin": ' + escape_json(rep.origin) + "},\n"
    out += '  "kernel": {\n'
    out += '    "release": ' + escape_json(rep.kernel.release) + ",\n"
    out += '    "arch": ' + escape_json(rep.kernel.arch) + ",\n"
    if rep.kernel.eligible_floor:
        out += '    "eligible_floor": true,\n'
    else:
        out += '    "eligible_floor": false,\n'
    out += '    "floor_reason": ' + escape_json(rep.kernel.floor_reason) + "\n"
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
        out += '    "profile_id": ' + escape_json(rep.profile_id) + ",\n"
        out += '    "status": ' + escape_json(rep.profile_status) + ",\n"
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
        out += ', "reason": ' + escape_json(rep.caps[i].reason) + "}"
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
    out += '  "verdict": ' + escape_json(rep.verdict) + ",\n"
    out += '  "summary": ' + escape_json(rep.summary) + "\n"
    out += "}\n"
    return out


def render_doctor_text(rep: DoctorReport) raises -> String:
    """Render one DoctorReport as human-readable text.

    Every interpolated evidence fragment passes through the
    single-line diagnostic sanitizer, so hostile fixture bytes
    can neither split lines nor smuggle terminal sequences.
    """
    var out = String(
        "memveil doctor (passive, " + rep.origin + " evidence)\n"
    )
    out += (
        "kernel: "
        + sanitize_diagnostic(rep.kernel.release)
        + " "
        + sanitize_diagnostic(rep.kernel.arch)
        + " (floor 7.0: "
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
        out += "  signal: " + sanitize_diagnostic(rep.guest.signals[i]) + "\n"
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
            + sanitize_diagnostic(rep.caps[i].status)
            + " - "
            + sanitize_diagnostic(rep.caps[i].reason)
            + "\n"
        )
    out += "privilege: euid " + String(rep.euid)
    if len(rep.denied) != 0:
        out += ", denied:"
        for i in range(len(rep.denied)):
            out += " " + sanitize_diagnostic(rep.denied[i])
    out += "\n"
    out += "verdict: " + sanitize_diagnostic(rep.verdict) + "\n"
    out += "summary: " + sanitize_diagnostic(rep.summary) + "\n"
    return out


def run_doctor_with(
    root: String, profiles_dir: String, as_json: Bool
) raises -> Int:
    """Run the doctor flow against explicit roots; return exit code.

    ``root`` is the evidence root ("" for the live host) and
    ``profiles_dir`` holds ``manifest.txt``. The report goes to
    stdout; failures go to stderr with exit 2.
    """
    var reader: EvidenceReader
    try:
        reader = open_evidence_reader(root)
    except e:
        return _doctor_failed("cannot open evidence: " + String(e))
    var env = detect_environment(reader)
    var profiles: List[Profile]
    try:
        profiles = load_profiles(profiles_dir)
    except e:
        return _doctor_failed("cannot load profiles: " + String(e))
    var decision = select_profile(env.kernel, profiles^)
    var report = discover_capabilities(reader, decision)
    var drep = build_doctor_report(reader, env, decision^, report^)
    var ready = drep.verdict == "ready"
    try:
        if as_json:
            write_stdout(render_doctor_json(drep^))
        else:
            write_stdout(render_doctor_text(drep^))
    except:
        write_stderr("memveil doctor: cannot write stdout\n")
        return EXIT_INTERNAL
    if ready:
        return EXIT_OK
    return EXIT_UNAVAILABLE


def run_doctor(args: List[String]) raises -> Int:
    """Run the doctor verb; return the process exit code.

    args excludes the program name and the doctor word. Only
    ``--json`` is accepted; anything else is a usage error.
    Profiles resolve from the kernel-resolved binary path,
    never from argv[0] or the working directory.
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
    i = 0
    while i < len(args):
        var tok = args[i]
        if tok == "--json":
            as_json = True
            i += 1
        else:
            return _doctor_failed("unknown option: " + tok)
    var profiles_dir: String
    try:
        profiles_dir = resolve_profiles_dir()
    except e:
        return _doctor_failed(
            "cannot resolve profiles location: " + e.message
        )
    return run_doctor_with(String(""), profiles_dir, as_json)
