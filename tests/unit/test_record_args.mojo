# SPDX-License-Identifier: GPL-3.0-or-later

"""record CLI flag parsing: channel selection options."""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.cli.record import parse_record_args


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


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_record_args_defaults]()
    suite.test[test_record_args_channels]()
    suite.test[test_record_args_lc_needs_value]()
    suite.test[test_record_args_cp_needs_value]()
    suite.test[test_record_args_capability_needs_value]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
