# SPDX-License-Identifier: GPL-3.0-or-later

"""Collection service boundary: options, admission, run refusals.

The record, live top, and qualify flows share one narrow
collection service: run options with fixed defaults, capability
parsing, admission decisions, and the collector run itself.
These tests pin that boundary through its own import path:
default option values, capability acceptance and refusal
wording, pre-run refusal exits and diagnostics (which create
no output resource), and the grouped extra-channel records
each admitted decision carries.
"""

from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import ScriptWriter, _stop_mkdtemp

from memveil.capture.run import (
    RecordOptions,
    decide_record,
    ownership_warning,
    parse_requested_caps,
    resolve_bridge,
    run_collector_with,
)
from memveil.platform.evidence import KernelInfo
from memveil.platform.profiles import Profile, load_profiles
from memveil.platform.reader import read_host_file

comptime _OK = "tests/fixtures/scan/ok"
comptime _PROFILES = "tests/fixtures/scan/profiles"
comptime _HOST_OLD = "tests/fixtures/qualify/host-old"
comptime _ELF_OK = "tests/fixtures/elf/ok.o"
comptime _ELF_LC = "tests/fixtures/elf/lc-ok.o"
comptime _ELF_CP = "tests/fixtures/elf/cp-ok.o"


def _svc_contains(hay: String, needle: String) -> Bool:
    return len(hay.split(String(needle))) > 1


def _svc_opts(output: String) -> RecordOptions:
    var opts = RecordOptions()
    opts.output = output
    opts.object = String(_ELF_OK)
    opts.bridge = String("test-bridge")
    opts.has_bridge = True
    return opts^


def _svc_kernel() -> KernelInfo:
    return KernelInfo(
        String("7.0.0-test"), String("x86_64"), True, String("")
    )


def _svc_absent(path: String) -> Bool:
    try:
        _ = read_host_file(path, String("probe"), 16)
    except:
        return True
    return False


def test_service_options_defaults() raises:
    var opts = RecordOptions()
    assert_equal(opts.duration_s, UInt64(60))
    assert_equal(opts.max_events_bytes, 1073741824)
    assert_equal(opts.output, String(""))
    assert_equal(opts.object, String(""))
    assert_equal(opts.bridge, String(""))
    assert_true(not opts.has_bridge)
    assert_true(not opts.has_profile)
    assert_true(not opts.has_profiles_dir)
    assert_equal(opts.lc_object, String(""))
    assert_equal(opts.cp_object, String(""))
    assert_equal(opts.capabilities, String(""))
    assert_equal(opts.device, String(""))
    assert_true(not opts.has_device)


def test_service_caps_default_attempt() raises:
    var ask = parse_requested_caps(String(""))
    assert_true(ask.ok)
    assert_equal(len(ask.caps), 1)
    assert_equal(ask.caps[0], String("attempt-trace"))


def test_service_caps_reject_unknown() raises:
    var ask = parse_requested_caps(
        String("attempt-trace,nope")
    )
    assert_true(not ask.ok)
    assert_equal(ask.err, String("unknown capability: nope"))


def test_service_caps_require_attempt() raises:
    var ask = parse_requested_caps(String("mapping-lifecycle"))
    assert_true(not ask.ok)
    assert_equal(ask.err, String("attempt-trace is required"))


def test_service_run_budget_low_refuses() raises:
    var base = _stop_mkdtemp()
    var out = base + String("/cap")
    var opts = _svc_opts(out)
    opts.max_events_bytes = 131071
    var writer = ScriptWriter()
    var result = run_collector_with(
        String(_OK), String(_PROFILES), opts^, writer
    )
    assert_equal(result.exit_code, 3)
    assert_equal(
        result.diagnostic, String("budget 131071 below 131072")
    )
    assert_true(_svc_absent(out + String("/session.json")))


def test_service_run_budget_high_refuses() raises:
    var base = _stop_mkdtemp()
    var out = base + String("/cap")
    var opts = _svc_opts(out)
    opts.max_events_bytes = 4294967297
    var writer = ScriptWriter()
    var result = run_collector_with(
        String(_OK), String(_PROFILES), opts^, writer
    )
    assert_equal(result.exit_code, 3)
    assert_equal(
        result.diagnostic,
        String("budget 4294967297 above 4294967296"),
    )
    assert_true(_svc_absent(out + String("/session.json")))


def test_service_run_no_bridge_refuses() raises:
    if resolve_bridge(String(""), False) != String(""):
        print(
            String("SKIP test_service_run_no_bridge_refuses: ")
            + String("bridge discoverable on this host")
        )
        return
    var base = _stop_mkdtemp()
    var out = base + String("/cap")
    var opts = _svc_opts(out)
    opts.bridge = String("")
    opts.has_bridge = False
    var writer = ScriptWriter()
    var result = run_collector_with(
        String(_OK), String(_PROFILES), opts^, writer
    )
    assert_equal(result.exit_code, 3)
    assert_true(_svc_contains(result.diagnostic, String("no bridge")))
    assert_true(_svc_absent(out + String("/session.json")))


def test_service_run_below_floor_refuses() raises:
    var base = _stop_mkdtemp()
    var out = base + String("/cap")
    var opts = _svc_opts(out)
    var writer = ScriptWriter()
    var result = run_collector_with(
        String(_HOST_OLD), String(_PROFILES), opts^, writer
    )
    assert_equal(result.exit_code, 3)
    assert_equal(
        result.diagnostic,
        String("kernel 6.8.0-test below floor 7.0"),
    )
    assert_true(_svc_absent(out + String("/session.json")))


def test_service_run_profiles_unloadable_refuses() raises:
    var base = _stop_mkdtemp()
    var out = base + String("/cap")
    var opts = _svc_opts(out)
    var writer = ScriptWriter()
    var result = run_collector_with(
        String(_OK), base + String("/no-such-dir"), opts^, writer
    )
    assert_equal(result.exit_code, 3)
    assert_true(
        _svc_contains(result.diagnostic, String("cannot load profiles: "))
    )
    assert_true(_svc_absent(out + String("/session.json")))


def test_service_ownership_warning_text() raises:
    assert_equal(
        ownership_warning(1001, 1002),
        String(
            "memveil record: warning: cannot restore capture"
            " ownership to 1001:1002\n"
        ),
    )


def test_service_extra_channels_grouped() raises:
    var profiles = load_profiles(String(_PROFILES))
    var d = decide_record(
        String(_OK),
        _svc_kernel(),
        profiles^,
        String(_PROFILES) + String("/valid-lc.json"),
        True,
        String(_ELF_OK),
        String(_ELF_LC),
        String(_ELF_CP),
        String("attempt-trace,mapping-lifecycle,copy-actual"),
        String(""),
        String(""),
    )
    assert_true(d.ok)
    assert_equal(d.kind, String("validated"))
    assert_true(d.lc.present)
    assert_true(d.cp.present)
    assert_true(len(d.lc.elf) > 0)
    assert_true(len(d.cp.elf) > 0)
    assert_equal(d.lc.ring_bytes, 8388608)
    assert_equal(d.cp.ring_bytes, 8388608)
    assert_true(d.lc.object_sha != String(""))
    assert_true(d.cp.object_sha != String(""))


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_service_options_defaults]()
    suite.test[test_service_caps_default_attempt]()
    suite.test[test_service_caps_reject_unknown]()
    suite.test[test_service_caps_require_attempt]()
    suite.test[test_service_run_budget_low_refuses]()
    suite.test[test_service_run_budget_high_refuses]()
    suite.test[test_service_run_no_bridge_refuses]()
    suite.test[test_service_run_below_floor_refuses]()
    suite.test[test_service_run_profiles_unloadable_refuses]()
    suite.test[test_service_ownership_warning_text]()
    suite.test[test_service_extra_channels_grouped]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
