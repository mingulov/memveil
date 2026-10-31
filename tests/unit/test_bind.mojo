# SPDX-License-Identifier: GPL-3.0-or-later

"""Bind-profile argument parsing, minting, and exit codes."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import _stop_mkdtemp
from memveil.cli.bind import (
    BindOptions,
    default_profile_id,
    min_kernel_for,
    mint_bound_profile,
    parse_bind_args,
    run_bind_with,
    valid_profile_id,
)
from memveil.cli.report import EXIT_INVALID, EXIT_OK
from memveil.capture.collector import EXIT_REFUSAL
from memveil.platform.narrow import parse_narrow_note, read_live_object
from memveil.platform.profiles import (
    Profile,
    parse_profile_bytes,
)
from memveil.platform.reader import bytes_to_text, read_host_file

comptime _HOST = "tests/fixtures/qualify/host"
comptime _PDIR = "tests/fixtures/qualify/profiles"
comptime _REF = "tests/fixtures/qualify/profiles/qual-ref.json"
comptime _OBJ = "tests/fixtures/elf/ok.o"
comptime _LC_OBJ = "tests/fixtures/elf/lc-ok.o"
comptime _CP_OBJ = "tests/fixtures/elf/cp-ok.o"


def _args(items: List[String]) -> List[String]:
    var out = List[String]()
    for i in range(len(items)):
        out.append(items[i].copy())
    return out^


def _base() raises -> Profile:
    var raw = read_host_file(String(_REF), String("profile"), 1048576)
    return parse_profile_bytes(raw^)


def _ref_note() raises -> String:
    return _base().identity.source.note.copy()


def test_bind_args_missing_output() raises:
    var raised = False
    try:
        _ = parse_bind_args(_args(List[String]()))
    except:
        raised = True
    assert_true(raised)


def test_bind_args_full() raises:
    var items = List[String]()
    items.append(String("--output"))
    items.append(String("/tmp/x.json"))
    items.append(String("--profile"))
    items.append(String("my-host"))
    items.append(String("--profiles-dir"))
    items.append(String("pd"))
    items.append(String("--object"))
    items.append(String("o"))
    items.append(String("--lc-object"))
    items.append(String("l"))
    items.append(String("--cp-object"))
    items.append(String("c"))
    items.append(String("--capability"))
    items.append(String("attempt-trace"))
    items.append(String("--profile-id"))
    items.append(String("pid"))
    var opts = parse_bind_args(_args(items))
    assert_equal(opts.output, String("/tmp/x.json"))
    assert_equal(opts.profile, String("my-host"))
    assert_true(opts.has_profile)
    assert_equal(opts.profiles_dir, String("pd"))
    assert_true(opts.has_profiles_dir)
    assert_equal(opts.object, String("o"))
    assert_equal(opts.lc_object, String("l"))
    assert_equal(opts.cp_object, String("c"))
    assert_equal(opts.capabilities, String("attempt-trace"))
    assert_equal(opts.profile_id, String("pid"))
    assert_true(opts.has_profile_id)


def test_bind_args_rejections() raises:
    var cases = List[List[String]]()
    var a = List[String]()
    a.append(String("--output"))
    cases.append(a.copy())
    var b = List[String]()
    b.append(String("--output"))
    b.append(String("x"))
    b.append(String("--bogus"))
    cases.append(b.copy())
    var c = List[String]()
    c.append(String("--output"))
    c.append(String("x"))
    c.append(String("stray"))
    cases.append(c.copy())
    var d = List[String]()
    d.append(String("--output"))
    d.append(String("x"))
    d.append(String("--profile-id"))
    cases.append(d.copy())
    for i in range(len(cases)):
        var raised = False
        try:
            _ = parse_bind_args(cases[i])
        except:
            raised = True
        assert_true(raised)


def test_profile_id_rules() raises:
    assert_true(valid_profile_id(String("my-host")))
    assert_true(valid_profile_id(String("local-7.0.0-test")))
    assert_true(not valid_profile_id(String("")))
    assert_true(not valid_profile_id(String("-lead-dash")))
    assert_true(not valid_profile_id(String("has space")))
    assert_true(not valid_profile_id(String("has/slash")))
    assert_equal(
        default_profile_id(String("7.0.0-test")), String("local-7.0.0-test")
    )
    assert_equal(
        default_profile_id(String("7.0 foo!")), String("local-7.0-foo-")
    )
    assert_equal(min_kernel_for(String("7.0.0-test")), String("7.0"))
    assert_equal(min_kernel_for(String("6.12.1")), String("6.12"))
    assert_equal(min_kernel_for(String("bogus")), String(""))


def test_mint_reproduces_reference_note() raises:
    # The helper measures the same six files plus the
    # discovered object the recipe hashes by hand: minted
    # bindings equal the checked-in reference note exactly.
    var caps = List[String]()
    caps.append(String("attempt-trace"))
    var minted = mint_bound_profile(
        String(_HOST),
        String(""),
        _base(),
        caps,
        String(_OBJ),
        String(""),
        String(""),
        String("test-bind"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(minted.ok, minted.err)
    var mbytes = List[UInt8]()
    for b in minted.text.as_bytes():
        mbytes.append(b)
    var doc = parse_profile_bytes(mbytes^)
    assert_equal(doc.profile_id, String("test-bind"))
    assert_equal(doc.status, String("reference-unvalidated"))
    assert_equal(doc.schema_version, String("0.1.1"))
    assert_equal(doc.identity.min_kernel, String("7.0"))
    assert_equal(doc.identity.source.note, _ref_note())
    assert_equal(len(doc.caps), 1)
    assert_equal(doc.caps[0].id, String("attempt-trace"))
    assert_equal(doc.caps[0].status, String("candidate"))
    var hook_text = String("")
    for i in range(len(doc.hooks)):
        if doc.hooks[i].kind == String("tracepoint"):
            assert_true(doc.hooks[i].format_has)
            hook_text = doc.hooks[i].format_text.copy()
    var raw = read_host_file(
        String(_HOST)
        + String("/sys/kernel/tracing/events/swiotlb/swiotlb_bounced/format"),
        String("format"),
        1048576,
    )
    assert_equal(hook_text, bytes_to_text(raw^))


def test_mint_extra_binds_twelve_fields() raises:
    # Any extra channel binds the full 12-field note: both
    # extended objects are required together.
    var caps = List[String]()
    caps.append(String("attempt-trace"))
    caps.append(String("mapping-lifecycle"))
    var minted = mint_bound_profile(
        String(_HOST),
        String(""),
        _base(),
        caps,
        String(_OBJ),
        String(_LC_OBJ),
        String(_CP_OBJ),
        String("test-bind-extra"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(minted.ok, minted.err)
    var mbytes = List[UInt8]()
    for b in minted.text.as_bytes():
        mbytes.append(b)
    var doc = parse_profile_bytes(mbytes^)
    var parsed = parse_narrow_note(doc.identity.source.note)
    assert_true(parsed.ok, parsed.message)
    var lc = read_live_object(String(_LC_OBJ))
    var cp = read_live_object(String(_CP_OBJ))
    assert_true(lc.state == String("value"))
    assert_true(cp.state == String("value"))
    assert_equal(parsed.bindings.lc_object, lc.value)
    assert_equal(parsed.bindings.lc_ring, String("33554432"))
    assert_equal(parsed.bindings.cp_object, cp.value)
    assert_equal(parsed.bindings.cp_ring, String("33554432"))
    assert_equal(len(doc.caps), 2)


def test_mint_refusals_name_cause() raises:
    var caps = List[String]()
    caps.append(String("attempt-trace"))
    var bad_root = mint_bound_profile(
        String("no-such-root"),
        String(""),
        _base(),
        caps,
        String(_OBJ),
        String(""),
        String(""),
        String("x"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(not bad_root.ok)
    assert_true(bad_root.err.find(String("config")) != -1, bad_root.err)
    var caps2 = List[String]()
    caps2.append(String("attempt-trace"))
    var no_obj = mint_bound_profile(
        String(_HOST),
        String(""),
        _base(),
        caps2,
        String(""),
        String(""),
        String(""),
        String("x"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(not no_obj.ok)
    assert_true(no_obj.err.find(String("no object")) != -1, no_obj.err)
    var caps3 = List[String]()
    caps3.append(String("attempt-trace"))
    caps3.append(String("mapping-lifecycle"))
    var no_lc = mint_bound_profile(
        String(_HOST),
        String(""),
        _base(),
        caps3,
        String(_OBJ),
        String(""),
        String(_CP_OBJ),
        String("x"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(not no_lc.ok)
    assert_true(
        no_lc.err.find(String("lifecycle object")) != -1, no_lc.err
    )
    var caps4 = List[String]()
    caps4.append(String("copy-actual"))
    var no_hooks = mint_bound_profile(
        String(_HOST),
        String(""),
        _base(),
        caps4,
        String(_OBJ),
        String(""),
        String(""),
        String("x"),
        String("7.0.0-test"),
        String("x86_64"),
    )
    assert_true(not no_hooks.ok)
    assert_true(no_hooks.err.find(String("no hooks")) != -1, no_hooks.err)


def _bind_opts(output: String) -> BindOptions:
    var opts = BindOptions()
    opts.output = output.copy()
    opts.object = String(_OBJ)
    return opts^


def test_run_bind_publishes() raises:
    var base = _stop_mkdtemp()
    var out = base + String("/minted.json")
    var opts = _bind_opts(out)
    var code = run_bind_with(String(_HOST), String(""), String(_PDIR), opts)
    assert_equal(code, EXIT_OK)
    var raw = read_host_file(out, String("minted"), 1048576)
    var doc = parse_profile_bytes(raw^)
    assert_equal(doc.profile_id, String("local-7.0.0-test"))
    assert_equal(doc.identity.source.note, _ref_note())


def test_run_bind_exits() raises:
    var base = _stop_mkdtemp()
    var opts = _bind_opts(base + String("/x.json"))
    var code = run_bind_with(
        String("no-such-root"), String(""), String(_PDIR), opts
    )
    assert_equal(code, EXIT_REFUSAL)
    var opts2 = _bind_opts(base + String("/y.json"))
    opts2.profile = String("no-such-profile")
    opts2.has_profile = True
    var code2 = run_bind_with(
        String(_HOST), String(""), String(_PDIR), opts2
    )
    assert_equal(code2, EXIT_REFUSAL)
    var opts3 = _bind_opts(base + String("/z.json"))
    opts3.profile_id = String("bad id")
    opts3.has_profile_id = True
    var code3 = run_bind_with(
        String(_HOST), String(""), String(_PDIR), opts3
    )
    assert_equal(code3, EXIT_INVALID)
    var opts4 = _bind_opts(base + String("/w.json"))
    opts4.capabilities = String("bogus-cap")
    var code4 = run_bind_with(
        String(_HOST), String(""), String(_PDIR), opts4
    )
    assert_equal(code4, EXIT_REFUSAL)
    var opts5 = _bind_opts(base + String("/v.json"))
    opts5.capabilities = String("conversion-observe")
    var code5 = run_bind_with(
        String(_HOST), String(""), String(_PDIR), opts5
    )
    assert_equal(code5, EXIT_REFUSAL)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_bind_args_missing_output]()
    suite.test[test_bind_args_full]()
    suite.test[test_bind_args_rejections]()
    suite.test[test_profile_id_rules]()
    suite.test[test_mint_reproduces_reference_note]()
    suite.test[test_mint_extra_binds_twelve_fields]()
    suite.test[test_mint_refusals_name_cause]()
    suite.test[test_run_bind_publishes]()
    suite.test[test_run_bind_exits]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
