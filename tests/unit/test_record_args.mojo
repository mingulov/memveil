# SPDX-License-Identifier: GPL-3.0-or-later

"""record CLI flag parsing: channel selection options."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.cli.record import (
    parse_record_args,
    record_usage,
    resolve_bridge,
    resolve_object,
)
from memveil.platform.reader import read_host_file

comptime _EXE = "tests/fixtures/runtime/bin/memveil"
comptime _SYSTEM_BPF = "/usr/share/memveil/bpf"


def contains(hay: String, needle: String) -> Bool:
    """True when needle occurs in hay at least once."""
    return len(hay.split(String(needle))) > 1


def _system_object_expected(file: String) -> String:
    """System object path when readable, else "".

    Independent fopen-based oracle: discovery probes
    with access(R_OK), so a readable-here file must
    resolve and an unreadable one must fall through.
    """
    var path = String(_SYSTEM_BPF) + String("/") + file
    try:
        _ = read_host_file(
            path, String("system object probe"), 67108864
        )
    except:
        return String("")
    return path^


def _args(first: String, second: String) -> List[String]:
    var out = List[String]()
    out.append(String("--output"))
    out.append(String("out"))
    out.append(String("--object"))
    out.append(String("obj.o"))
    if first != String(""):
        out.append(first.copy())
        out.append(second.copy())
    return out^


def test_record_args_defaults() raises:
    var opts = parse_record_args(_args(String(""), String("")))
    assert_equal(opts.output, String("out"))
    assert_equal(opts.object, String("obj.o"))
    assert_equal(opts.lc_object, String(""))
    assert_equal(opts.cp_object, String(""))
    assert_equal(opts.capabilities, String(""))
    assert_equal(opts.profiles_dir, String(""))
    assert_true(not opts.has_profiles_dir)


def test_record_args_profiles_dir() raises:
    var opts = parse_record_args(_args(String("--profiles-dir"), String("qd")))
    assert_equal(opts.profiles_dir, String("qd"))
    assert_true(opts.has_profiles_dir)


def test_record_args_profiles_dir_needs_value() raises:
    var raised = False
    try:
        _ = parse_record_args(_args(String("--profiles-dir"), String("")))
    except e:
        raised = True
        assert_equal(e.message, String("--profiles-dir needs a value"))
    assert_true(raised)


def test_record_args_channels() raises:
    var args = _args(String("--lc-object"), String("lc.o"))
    args.append(String("--cp-object"))
    args.append(String("cp.o"))
    args.append(String("--capability"))
    args.append(
        String("attempt-trace,mapping-lifecycle,copy-actual")
    )
    var opts = parse_record_args(args^)
    assert_equal(opts.lc_object, String("lc.o"))
    assert_equal(opts.cp_object, String("cp.o"))
    assert_equal(
        opts.capabilities,
        String("attempt-trace,mapping-lifecycle,copy-actual"),
    )


def test_record_args_lc_needs_value() raises:
    var raised = False
    try:
        _ = parse_record_args(_args(String("--lc-object"), String("")))
    except e:
        raised = True
        assert_equal(e.message, String("--lc-object needs a value"))
    assert_true(raised)


def test_record_args_cp_needs_value() raises:
    var raised = False
    try:
        _ = parse_record_args(_args(String("--cp-object"), String("")))
    except e:
        raised = True
        assert_equal(e.message, String("--cp-object needs a value"))
    assert_true(raised)


def test_record_args_capability_needs_value() raises:
    var raised = False
    try:
        _ = parse_record_args(_args(String("--capability"), String("")))
    except e:
        raised = True
        assert_equal(e.message, String("--capability needs a value"))
    assert_true(raised)


def test_record_args_object_optional() raises:
    # --object is discovered when absent, so parsing
    # without it succeeds and leaves the path empty.
    var args = List[String]()
    args.append(String("--output"))
    args.append(String("out"))
    var opts = parse_record_args(args^)
    assert_equal(opts.output, String("out"))
    assert_equal(opts.object, String(""))


def test_resolve_bridge_explicit_verbatim() raises:
    assert_equal(
        resolve_bridge(String("br.so"), True), String("br.so")
    )


def test_resolve_object_explicit_verbatim() raises:
    assert_equal(
        resolve_object(String("attempt"), String("o.o"), String("")),
        String("o.o"),
    )


def test_resolve_object_exe_relative() raises:
    assert_equal(
        resolve_object(String("attempt"), String(""), String(_EXE)),
        String("tests/fixtures/runtime/bpf/swiotlb_attempt.bpf.o"),
    )
    assert_equal(
        resolve_object(String("lifecycle"), String(""), String(_EXE)),
        String("tests/fixtures/runtime/bpf/swiotlb_lifecycle.bpf.o"),
    )
    assert_equal(
        resolve_object(String("copy"), String(""), String(_EXE)),
        String("tests/fixtures/runtime/bpf/swiotlb_copy.bpf.o"),
    )


def test_resolve_object_nothing_discovered() raises:
    # An executable tree without a bundle falls through
    # to the system path (oracle) or "" when absent too.
    var got = resolve_object(
        String("attempt"),
        String(""),
        String("build/nobundle-xyz/bin/memveil"),
    )
    assert_equal(
        got, _system_object_expected(String("swiotlb_attempt.bpf.o"))
    )


def test_record_usage_discovery() raises:
    var text = record_usage()
    assert_true(contains(text, String("[--object PATH]")))
    assert_true(contains(text, String("discover")))
    assert_true(contains(text, String("LMB_NATIVE_LIB")))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_record_args_defaults]()
    suite.test[test_record_args_channels]()
    suite.test[test_record_args_profiles_dir]()
    suite.test[test_record_args_profiles_dir_needs_value]()
    suite.test[test_record_args_lc_needs_value]()
    suite.test[test_record_args_cp_needs_value]()
    suite.test[test_record_args_capability_needs_value]()
    suite.test[test_record_args_object_optional]()
    suite.test[test_resolve_bridge_explicit_verbatim]()
    suite.test[test_resolve_object_explicit_verbatim]()
    suite.test[test_resolve_object_exe_relative]()
    suite.test[test_resolve_object_nothing_discovered]()
    suite.test[test_record_usage_discovery]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
