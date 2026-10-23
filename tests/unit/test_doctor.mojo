# SPDX-License-Identifier: GPL-3.0-or-later

"""Doctor unit tests: report assembly, rendering, and exit codes.

Assembly tests pin verdicts, summaries, and denied-path merges per
fixture. One exact-JSON test pins the doctor-v0.1.0 wire shape; the
reports lane revalidates live output against the schema oracle.
Sanitizer tests prove hostile fixture bytes cannot escape either
sink raw. Exit tests drive run_doctor_with through fixtures.
"""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.capture.run import decide_record
from memveil.cli.doctor import (
    EXIT_UNAVAILABLE,
    DoctorCap,
    DoctorOptions,
    DoctorReport,
    DoctorReport2,
    assess_doctor,
    build_doctor_report,
    default_profiles_dir,
    doctor_usage,
    render_doctor_json,
    render_doctor_json2,
    render_doctor_text,
    resolve_profiles_dir,
    run_doctor,
    run_doctor_opts,
    run_doctor_with,
)
from memveil.cli.report import EXIT_INVALID, EXIT_OK
from memveil.jsonscan import Scanner
from memveil.platform.capabilities import discover_capabilities
from memveil.platform.evidence import detect_environment
from memveil.platform.kernelgate import remedy_for
from memveil.platform.profiles import load_profiles, select_profile
from memveil.platform.reader import open_evidence_reader


def fx(name: String) -> String:
    """Fixture directory path for one capabilities fixture name."""
    return "tests/fixtures/capabilities/" + name


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def parsed(doc: String) raises -> String:
    """Parse one JSON string literal into its decoded value."""
    var s = Scanner(doc)
    return s.parse_string()


def drep_for(fxname: String, profdir: String) raises -> DoctorReport:
    """Assemble a DoctorReport for one fixture plus profiles dir."""
    var r = open_evidence_reader(fx(fxname))
    var env = detect_environment(r)
    var ps = load_profiles(profdir)
    var d = select_profile(env.kernel, ps^)
    var rep = discover_capabilities(r, d^)
    return build_doctor_report(r, env, d, rep)


def test_build_ordinary() raises:
    var drep = drep_for(String("ordinary-7.0"), String("profiles"))
    assert_equal(drep.origin, String("fixture"))
    assert_equal(drep.verdict, String("unavailable"))
    assert_equal(
        drep.summary,
        String("unavailable: layout: missing field common_type"),
    )
    assert_equal(drep.euid, 1001)
    assert_equal(len(drep.denied), 0)
    assert_equal(len(drep.caps), 3)
    assert_true(not drep.matched)
    assert_true(drep.has_profile)
    assert_equal(drep.profile_id, String("linux-x86_64-7.0-reference"))
    assert_equal(drep.profile_status, String("reference-unvalidated"))


def test_build_ready() raises:
    var drep = drep_for(String("ready-validated"), fx("profiles-test"))
    assert_equal(drep.origin, String("fixture"))
    assert_equal(drep.verdict, String("ready"))
    assert_equal(
        drep.summary,
        String("ready: attempt-trace available under test-validated"),
    )
    assert_true(drep.matched)


def _attempt_reason(drep: DoctorReport) -> String:
    for i in range(len(drep.caps)):
        if drep.caps[i].id == String("attempt-trace"):
            return drep.caps[i].reason.copy()
    return String("")


def test_doctor_changed_names_drift_class() raises:
    # A changed format stays unavailable, but the reason
    # names the drift class: offset-only drift may admit
    # after re-qualifying, anything else cannot.
    var moved = drep_for(String("changed-moved"), fx("profiles-moved"))
    assert_equal(moved.verdict, String("unavailable"))
    assert_true(
        contains(
            _attempt_reason(moved),
            String("; drift: offset-only (re-qualify may admit)"),
        )
    )
    var trivial = drep_for(
        String("changed-trivial"), fx("profiles-moved")
    )
    assert_equal(trivial.verdict, String("unavailable"))
    assert_true(
        contains(
            _attempt_reason(trivial),
            String("; drift: none (layout pinned)"),
        )
    )
    var sig = drep_for(
        String("changed-signature"), fx("profiles-test")
    )
    assert_equal(sig.verdict, String("unavailable"))
    assert_true(
        contains(
            _attempt_reason(sig),
            String("; drift: missing field common_type"),
        )
    )


def test_build_denied_merge() raises:
    var drep = drep_for(String("denied-tracepoint"), String("profiles"))
    assert_equal(drep.verdict, String("unavailable"))
    assert_equal(len(drep.denied), 1)
    assert_equal(
        drep.denied[0],
        String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"),
    )


def test_build_env_denied() raises:
    var drep = drep_for(String("denied-guest-node"), String("profiles"))
    assert_equal(len(drep.denied), 1)
    assert_equal(drep.denied[0], String("/dev/sev-guest"))


def test_json_ordinary_exact() raises:
    # Stand-in BTF is corrupt evidence: lifecycle and copy
    # report unknown (with the unknown-status remedy), only
    # the proven layout gap stays unavailable.
    var drep = drep_for(String("ordinary-7.0"), String("profiles"))
    var js = render_doctor_json(drep)
    var want = String(
        '{\n'
        '  "schema_version": "0.1.0",\n'
        '  "mode": "passive",\n'
        '  "provenance": {"origin": "fixture"},\n'
        '  "kernel": {\n'
        '    "release": "7.0.0-34-generic",\n'
        '    "arch": "x86_64",\n'
        '    "eligible_floor": true,\n'
        '    "floor_reason":'
        ' "release 7.0.0-34-generic meets the 6.0 floor"\n'
        "  },\n"
        '  "guest": {\n'
        '    "tech": "ordinary",\n'
        '    "signals": ["sev-node:absent", "tdx-node:absent",'
        ' "cpu-flags:ok:none", "ordinary:absent-nodes-inference",'
        ' "info:btf:present:24B", "info:config-gz:absent",'
        ' "info:os:ubuntu:24.04", "info:boot-config:absent"],\n'
        '    "asserted": false,\n'
        '    "conflict": ""\n'
        "  },\n"
        '  "profile": {\n'
        '    "matched": false,\n'
        '    "profile_id": "linux-x86_64-7.0-reference",\n'
        '    "status": "reference-unvalidated",\n'
        '    "reason": "profile linux-x86_64-7.0-reference covers'
        " this identity but is reference-unvalidated\"\n"
        "  },\n"
        '  "capabilities": [{"id": "attempt-trace", "status": "unavailable",'
        ' "reason": "layout: missing field common_type",'
        ' "remedy": "refresh the profile\'s recorded signatures from'
        ' this kernel, then re-prove with memveil qualify'
        ' (see memveil qualify --help)"},'
        ' {"id": "mapping-lifecycle", "status": "unknown",'
        ' "reason": "bad BTF header",'
        ' "remedy": "run memveil qualify for local-auto,'
        ' or await validated evidence"},'
        ' {"id": "copy-actual", "status": "unknown",'
        ' "reason": "bad BTF header",'
        ' "remedy": "run memveil qualify for local-auto,'
        ' or await validated evidence"}],\n'
        '  "privilege": {\n'
        '    "euid": 1001,\n'
        '    "denied_paths": []\n'
        "  },\n"
        '  "verdict": "unavailable",\n'
        '  "summary": "unavailable: layout: missing field common_type"\n'
        "}\n"
    )
    assert_equal(js, want)


def test_text_fix_lines() raises:
    var drep = drep_for(String("ordinary-7.0"), String("profiles"))
    var text = render_doctor_text(drep)
    # The live judgment proves the stand-in format
    # unusable, so the attempt reason names the layout
    # gap instead of asking for a recorded format.
    assert_true(
        contains(text, String("layout: missing field common_type"))
    )
    assert_true(
        text.find(
            String(
                "    fix: refresh the profile's recorded signatures"
                " from this kernel, then re-prove with memveil"
                " qualify (see memveil qualify --help)\n"
            )
        )
        != -1
    )


def test_json_ready_verdict() raises:
    var drep = drep_for(String("ready-validated"), fx("profiles-test"))
    var js = render_doctor_json(drep)
    assert_true(contains(js, String('"verdict": "ready"')))
    assert_true(contains(js, String('"matched": true')))


def test_json_null_profile() raises:
    var drep = drep_for(String("arch-mismatch"), String("profiles"))
    var js = render_doctor_json(drep)
    assert_true(contains(js, String('"profile_id": null')))
    assert_true(contains(js, String('"status": null')))
    assert_true(contains(js, String('"matched": false')))


def test_json_escapes_hostile() raises:
    var drep = drep_for(String("meta-release-hostile"), String("profiles"))
    var js = render_doctor_json(drep)
    assert_true(contains(js, String("\\u001b")))
    var esc = parsed(String('"\\u001b"'))
    assert_equal(len(js.split(esc)), 1)


def test_build_live_origin() raises:
    var r = open_evidence_reader(String(""))
    var env = detect_environment(r)
    var ps = load_profiles(String("profiles"))
    var d = select_profile(env.kernel, ps^)
    var rep = discover_capabilities(r, d^)
    var drep = build_doctor_report(r, env, d, rep)
    assert_equal(drep.origin, String("live"))


def test_text_key_lines() raises:
    var drep = drep_for(String("ordinary-7.0"), String("profiles"))
    var tx = render_doctor_text(drep)
    assert_true(
        contains(tx, String("memveil doctor (passive, fixture evidence)"))
    )
    assert_true(contains(tx, String("guest: ordinary")))
    assert_true(
        contains(
            tx,
            String(
                "profile: linux-x86_64-7.0-reference"
                " (reference-unvalidated)"
            ),
        )
    )
    assert_true(contains(tx, String("privilege: euid 1001")))
    assert_true(contains(tx, String("verdict: unavailable")))


def test_text_conflict_line() raises:
    var drep = drep_for(String("conflicting-evidence"), String("profiles"))
    var tx = render_doctor_text(drep)
    assert_true(
        contains(
            tx,
            String("conflict: sev-guest and tdx-guest nodes both present"),
        )
    )


def test_text_asserted_mark() raises:
    var drep = drep_for(String("user-asserted-snp"), String("profiles"))
    var tx = render_doctor_text(drep)
    assert_true(contains(tx, String("guest: snp (user-asserted)")))


def test_text_denied_lists() raises:
    var drep = drep_for(String("denied-tracepoint"), String("profiles"))
    var tx = render_doctor_text(drep)
    assert_true(
        contains(
            tx,
            String(
                "denied:"
                " /sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"
            ),
        )
    )


def test_text_sanitizes_hostile() raises:
    var drep = drep_for(String("meta-release-hostile"), String("profiles"))
    var tx = render_doctor_text(drep)
    var esc = parsed(String('"\\u001b"'))
    assert_equal(len(tx.split(esc)), 1)
    assert_true(contains(tx, String("7.0/evil")))


def test_exit_ready() raises:
    # D10 (T2): doctor judges through record admission, so
    # undiscoverable objects under mojo run read unavailable
    # even on the ready-validated fixture (D13 approved).
    var code = run_doctor_with(
        fx("ready-validated"), fx("profiles-test"), True
    )
    assert_equal(code, EXIT_UNAVAILABLE)


def test_exit_unavailable() raises:
    var code = run_doctor_with(fx("ordinary-7.0"), String("profiles"), False)
    assert_equal(code, EXIT_UNAVAILABLE)


def test_exit_bad_root() raises:
    var code = run_doctor_with(
        String("no-such-dir"), String("profiles"), False
    )
    assert_equal(code, EXIT_INVALID)


def test_exit_bad_profiles() raises:
    var code = run_doctor_with(
        fx("ordinary-7.0"), String("no-such-profiles"), False
    )
    assert_equal(code, EXIT_INVALID)


def test_exit_unknown_option() raises:
    var args = List[String]()
    args.append(String("--bogus"))
    var code = run_doctor(args^)
    assert_equal(code, EXIT_INVALID)


def test_exit_profiles_dir_missing_value() raises:
    var args = List[String]()
    args.append(String("--profiles-dir"))
    var code = run_doctor(args^)
    assert_equal(code, EXIT_INVALID)


def test_exit_profiles_dir_bad_path() raises:
    var args = List[String]()
    args.append(String("--profiles-dir"))
    args.append(String("tests/fixtures/capabilities/nonexistent-xyz"))
    var code = run_doctor(args^)
    assert_equal(code, EXIT_INVALID)


def test_exit_profiles_dir_valid_dir() raises:
    var args = List[String]()
    args.append(String("--profiles-dir"))
    args.append(fx(String("profiles-test")))
    var code = run_doctor(args^)
    assert_true(code != EXIT_INVALID)


def test_resolve_shape() raises:
    var got = resolve_profiles_dir()
    var tail = got.split(String("/../profiles"))
    assert_equal(len(tail), 2)
    assert_equal(String(tail[1]), String(""))
    var head = got.split(String("/"))
    assert_equal(String(head[0]), String(""))


def test_profiles_dir() raises:
    assert_equal(
        default_profiles_dir(String("build/memveil")),
        String("build/../profiles"),
    )
    assert_equal(
        default_profiles_dir(String("/opt/mv/bin/memveil")),
        String("/opt/mv/bin/../profiles"),
    )
    assert_equal(
        default_profiles_dir(String("/usr/bin/memveil")),
        String("/usr/share/memveil/profiles"),
    )
    assert_equal(
        default_profiles_dir(String("memveil")), String("profiles")
    )
    assert_equal(
        default_profiles_dir(String("/memveil")), String("/../profiles")
    )


def test_usage() raises:
    assert_true(contains(doctor_usage(), String("doctor [--json]")))


def gate(name: String) -> String:
    """Fixture directory path for one gate fixture name."""
    return "tests/fixtures/gate/" + name


def _doctor2_opts(
    root: String,
    profiles_dir: String,
    capabilities: String,
    obj_path: String,
    lc_object: String,
    cp_object: String,
) -> DoctorOptions:
    """One DoctorOptions with explicit objects and no bridge."""
    var opts = DoctorOptions()
    opts.root = root
    opts.profiles_dir = profiles_dir
    opts.capabilities = capabilities
    opts.object = obj_path
    opts.lc_object = lc_object
    opts.cp_object = cp_object
    return opts^


def _live38_opts() -> DoctorOptions:
    """gate/base against profiles-live with every object."""
    return _doctor2_opts(
        gate(String("base")),
        String("tests/fixtures/scan/profiles-live"),
        String("all"),
        String("tests/fixtures/elf/ok.o"),
        String("tests/fixtures/elf/lc-ok.o"),
        String("tests/fixtures/elf/cp-ok.o"),
    )


def test_doctor2_validated_attempt() raises:
    var opts = _doctor2_opts(
        String("tests/fixtures/scan/ok"),
        String("tests/fixtures/scan/profiles"),
        String("attempt-trace"),
        String("tests/fixtures/elf/ok.o"),
        String(""),
        String(""),
    )
    var drep = assess_doctor(opts)
    assert_equal(drep.verdict, String("ready-load-unchecked"))
    assert_equal(len(drep.caps), 1)
    assert_equal(drep.caps[0].id, String("attempt-trace"))
    assert_equal(
        drep.caps[0].status, String("available-load-unchecked")
    )
    var code = run_doctor_opts(opts)
    assert_equal(code, EXIT_OK)


def test_doctor2_all_on_live38() raises:
    var opts = _live38_opts()
    var drep = assess_doctor(opts)
    assert_equal(len(drep.caps), 3)
    for i in range(len(drep.caps)):
        assert_equal(
            drep.caps[i].status, String("available-load-unchecked")
        )
    assert_equal(len(drep.requested), 3)
    assert_equal(drep.requested[0], String("attempt-trace"))
    assert_equal(drep.requested[1], String("mapping-lifecycle"))
    assert_equal(drep.requested[2], String("copy-actual"))
    assert_equal(len(drep.load), 0)
    var js = render_doctor_json2(drep)
    assert_true(contains(js, String('"mode": "passive"')))
    assert_true(
        contains(
            js,
            String(
                '"lockdown": {"mode": "none", "src": "securityfs"}'
            ),
        )
    )
    assert_true(
        contains(
            js,
            String(
                '"btf": {"state": "present", "bytes": "1063",'
                ' "config_btf": "unknown", "config_src": "proc"}'
            ),
        )
    )


def test_doctor2_agrees_with_record() raises:
    var variants = List[String]()
    variants.append(String("base"))
    variants.append(String("btf-absent-config"))
    variants.append(String("btf-absent-unknown"))
    variants.append(String("btf-denied"))
    variants.append(String("btf-not-visible"))
    variants.append(String("container-view"))
    variants.append(String("denied-all"))
    variants.append(String("events-denied"))
    variants.append(String("hook-absent"))
    variants.append(String("hook-clone"))
    variants.append(String("hook-nokallsyms"))
    variants.append(String("hook-not-in-btf"))
    variants.append(String("lockdown-conf"))
    variants.append(String("notracing-bpfevents"))
    variants.append(String("notracing-config"))
    variants.append(String("tracefs-gone"))
    variants.append(String("tracefs-hidden"))
    variants.append(String("tracefs-noevents"))
    variants.append(String("tracefs-unmounted"))
    var profiles_dir = String("tests/fixtures/scan/profiles-live")
    var ok_o = String("tests/fixtures/elf/ok.o")
    var lc_o = String("tests/fixtures/elf/lc-ok.o")
    var cp_o = String("tests/fixtures/elf/cp-ok.o")
    for i in range(len(variants)):
        var root = gate(variants[i].copy())
        var r = open_evidence_reader(root.copy())
        var env = detect_environment(r)
        var ps = load_profiles(profiles_dir.copy())
        var decision = decide_record(
            root.copy(),
            env.kernel,
            ps^,
            String(""),
            False,
            ok_o.copy(),
            lc_o.copy(),
            cp_o.copy(),
            String("all"),
            profiles_dir.copy(),
            String(""),
        )
        var opts = _doctor2_opts(
            root,
            profiles_dir.copy(),
            String("all"),
            ok_o.copy(),
            lc_o.copy(),
            cp_o.copy(),
        )
        var drep = assess_doctor(opts)
        assert_true(
            (drep.verdict == String("unavailable"))
            == (not decision.ok)
        )
        if not decision.ok:
            assert_equal(
                drep.summary,
                String("unavailable: ") + decision.refusal,
            )


def _live_cap(fxname: String, cap_id: String) raises -> DoctorCap:
    """Judge one capability on one gate fixture, all objects."""
    var opts = _doctor2_opts(
        gate(fxname),
        String("tests/fixtures/scan/profiles-live"),
        String("all"),
        String("tests/fixtures/elf/ok.o"),
        String("tests/fixtures/elf/lc-ok.o"),
        String("tests/fixtures/elf/cp-ok.o"),
    )
    var drep = assess_doctor(opts)
    for i in range(len(drep.caps)):
        if drep.caps[i].id == cap_id:
            return drep.caps[i].copy()
    return DoctorCap()


def test_doctor2_live_btf_truncated_unknown() raises:
    var lc = _live_cap(String("btf-truncated"), String("mapping-lifecycle"))
    assert_equal(lc.status, String("unknown"))
    assert_equal(lc.reason_code, String("btf-truncated"))
    assert_equal(lc.remedy, remedy_for(String("btf-truncated")))
    var at = _live_cap(String("btf-truncated"), String("attempt-trace"))
    assert_equal(at.status, String("available-load-unchecked"))


def test_doctor2_live_ftrace_disabled_fix() raises:
    var lc = _live_cap(String("ftrace-off"), String("mapping-lifecycle"))
    assert_equal(lc.status, String("unavailable"))
    assert_equal(lc.reason_code, String("ftrace-disabled"))
    assert_equal(lc.remedy, remedy_for(String("ftrace-disabled")))


def test_doctor2_live_hook_ambiguous_code() raises:
    var lc = _live_cap(String("aff-dup"), String("mapping-lifecycle"))
    assert_equal(lc.status, String("unavailable"))
    assert_equal(lc.reason_code, String("hook-ambiguous"))
    assert_equal(lc.remedy, remedy_for(String("hook-ambiguous")))


def test_doctor2_live_hook_absent_code() raises:
    var lc = _live_cap(String("hook-absent"), String("mapping-lifecycle"))
    assert_equal(lc.status, String("unavailable"))
    assert_equal(lc.reason_code, String("btf-hook-absent"))
    assert_equal(lc.remedy, remedy_for(String("btf-hook-absent")))


def test_doctor2_no_object() raises:
    var opts = _doctor2_opts(
        gate(String("base")),
        String("tests/fixtures/scan/profiles-live"),
        String("all"),
        String(""),
        String(""),
        String(""),
    )
    var drep = assess_doctor(opts)
    assert_equal(len(drep.caps), 3)
    assert_equal(drep.caps[0].id, String("attempt-trace"))
    assert_equal(drep.caps[0].status, String("unavailable"))
    assert_equal(drep.caps[0].reason_code, String("object-missing"))
    assert_equal(
        drep.caps[0].remedy,
        String(
            "install the memveil BPF objects or pass --object,"
            " --lc-object, --cp-object"
        ),
    )
    var code = run_doctor_opts(opts)
    assert_equal(code, EXIT_UNAVAILABLE)


def test_doctor2_precheck_fail() raises:
    var profiles_dir = String("tests/fixtures/scan/profiles-live")
    var ok_o = String("tests/fixtures/elf/ok.o")
    var lc_o = String("tests/fixtures/elf/lc-ok.o")
    var cp_o = String("tests/fixtures/elf/cp-ok.o")
    var opts = _doctor2_opts(
        gate(String("caps-none")),
        profiles_dir.copy(),
        String("all"),
        ok_o.copy(),
        lc_o.copy(),
        cp_o.copy(),
    )
    var drep = assess_doctor(opts)
    assert_equal(len(drep.caps), 3)
    for i in range(len(drep.caps)):
        assert_equal(drep.caps[i].status, String("unavailable"))
        assert_equal(
            drep.caps[i].reason_code, String("no-bpf-privilege")
        )
    var mopts = _doctor2_opts(
        gate(String("memcg-v1")),
        profiles_dir,
        String("all"),
        ok_o,
        lc_o,
        cp_o,
    )
    var mdrep = assess_doctor(mopts)
    assert_equal(len(mdrep.caps), 3)
    for i in range(len(mdrep.caps)):
        assert_equal(
            mdrep.caps[i].status, String("available-load-unchecked")
        )
        var seen = False
        for j in range(len(mdrep.caps[i].evidence)):
            if mdrep.caps[i].evidence[j].startswith(
                String("memcg: unknown")
            ):
                seen = True
                break
        assert_true(seen)


def test_doctor2_notes() raises:
    var profiles_dir = String("tests/fixtures/scan/profiles-live")
    var ok_o = String("tests/fixtures/elf/ok.o")
    var lc_o = String("tests/fixtures/elf/lc-ok.o")
    var cp_o = String("tests/fixtures/elf/cp-ok.o")
    var want = String("no swiotlb pool active: attempts will be 0")
    var names = List[String]()
    names.append(String("swiotlb-noforce"))
    names.append(String("swiotlb-inactive"))
    for i in range(len(names)):
        var opts = _doctor2_opts(
            gate(names[i].copy()),
            profiles_dir.copy(),
            String("all"),
            ok_o.copy(),
            lc_o.copy(),
            cp_o.copy(),
        )
        var drep = assess_doctor(opts)
        var seen = False
        for j in range(len(drep.notes)):
            if drep.notes[j] == want:
                seen = True
                break
        assert_true(seen)
    var bopts = _doctor2_opts(
        gate(String("base")),
        profiles_dir,
        String("all"),
        ok_o,
        lc_o,
        cp_o,
    )
    var bdrep = assess_doctor(bopts)
    for j in range(len(bdrep.notes)):
        assert_true(bdrep.notes[j] != want)


def test_doctor2_flags() raises:
    var bad = List[String]()
    bad.append(String("--capability"))
    bad.append(String("attempt-trace,nope"))
    assert_equal(run_doctor(bad^), EXIT_INVALID)
    var missing = List[String]()
    missing.append(String("--capability"))
    assert_equal(run_doctor(missing^), EXIT_INVALID)
    assert_true(
        contains(doctor_usage(), String("--load-check"))
    )
    var live = List[String]()
    live.append(String("--load-check"))
    live.append(String("--profiles-dir"))
    live.append(String("profiles"))
    assert_true(run_doctor(live^) != EXIT_INVALID)


def _cstr_local(s: String) -> List[UInt8]:
    """One NUL-terminated copy of a path or mode string."""
    var b = s.as_bytes()
    var out = List[UInt8]()
    for i in range(len(b)):
        out.append(b[i])
    out.append(UInt8(0))
    return out^


def _write_doctor2_json(text: String) raises:
    """Write the doctor-v0.1.1 JSON under build/test-tmp."""
    var parent = _cstr_local(String("build/test-tmp"))
    _ = external_call["mkdir", Int32](
        Span(parent).unsafe_ptr(), 0o755
    )
    var cpath = _cstr_local(String("build/test-tmp/doctor2.json"))
    var cmode = _cstr_local(String("w"))
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(cmode).unsafe_ptr()
    )
    if fp == 0:
        raise Error(String("cannot write doctor2.json"))
    var body = text.as_bytes()
    var n = external_call["fwrite", Int64](
        body.unsafe_ptr(), 1, len(body), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(body):
        raise Error(String("short write doctor2.json"))


def test_doctor2_json_schema() raises:
    var drep = assess_doctor(_live38_opts())
    var js = render_doctor_json2(drep)
    assert_true(contains(js, String('"schema_version": "0.1.1"')))
    _write_doctor2_json(js)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_build_ordinary]()
    suite.test[test_build_ready]()
    suite.test[test_doctor_changed_names_drift_class]()
    suite.test[test_build_live_origin]()
    suite.test[test_build_denied_merge]()
    suite.test[test_build_env_denied]()
    suite.test[test_json_ordinary_exact]()
    suite.test[test_text_fix_lines]()
    suite.test[test_json_ready_verdict]()
    suite.test[test_json_null_profile]()
    suite.test[test_json_escapes_hostile]()
    suite.test[test_text_key_lines]()
    suite.test[test_text_conflict_line]()
    suite.test[test_text_asserted_mark]()
    suite.test[test_text_denied_lists]()
    suite.test[test_text_sanitizes_hostile]()
    suite.test[test_exit_ready]()
    suite.test[test_exit_unavailable]()
    suite.test[test_exit_bad_root]()
    suite.test[test_exit_bad_profiles]()
    suite.test[test_exit_unknown_option]()
    suite.test[test_exit_profiles_dir_missing_value]()
    suite.test[test_exit_profiles_dir_bad_path]()
    suite.test[test_exit_profiles_dir_valid_dir]()
    suite.test[test_profiles_dir]()
    suite.test[test_resolve_shape]()
    suite.test[test_usage]()
    suite.test[test_doctor2_validated_attempt]()
    suite.test[test_doctor2_all_on_live38]()
    suite.test[test_doctor2_agrees_with_record]()
    suite.test[test_doctor2_live_btf_truncated_unknown]()
    suite.test[test_doctor2_live_ftrace_disabled_fix]()
    suite.test[test_doctor2_live_hook_ambiguous_code]()
    suite.test[test_doctor2_live_hook_absent_code]()
    suite.test[test_doctor2_no_object]()
    suite.test[test_doctor2_precheck_fail]()
    suite.test[test_doctor2_notes]()
    suite.test[test_doctor2_flags]()
    suite.test[test_doctor2_json_schema]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
