# SPDX-License-Identifier: GPL-3.0-or-later

"""Runtime discovery: bridge/object resolution and privilege policy."""

from std.ffi import external_call
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from memveil.platform.reader import read_host_file
from memveil.platform.runtime import (
    UidPair,
    discover_bridge,
    discover_object,
    exe_root,
    is_privileged,
    live_uids,
)

comptime _EXE = "tests/fixtures/runtime/bin/memveil"
comptime _BUNDLED_BRIDGE = "tests/fixtures/runtime/lib/libbpf_mojo.so.1"
comptime _ENV_BRIDGE = "tests/fixtures/runtime/env-bridge.so"
comptime _ABSENT = "tests/fixtures/runtime/lib/absent.so"
comptime _SYSTEM_BRIDGE = "/usr/lib/memveil/libbpf_mojo.so.1"
comptime _SYSTEM_BPF = "/usr/share/memveil/bpf"


def _system_bridge_expected() -> String:
    """System bridge path when readable, else "".

    Independent fopen-based oracle: the discovery probe uses
    access(R_OK), so a readable-here file must resolve and an
    unreadable one must fall through to "".
    """
    try:
        _ = read_host_file(
            String(_SYSTEM_BRIDGE),
            String("system bridge probe"),
            67108864,
        )
    except:
        return String("")
    return String(_SYSTEM_BRIDGE)


def _system_object_expected(kind: String, file: String) -> String:
    """System object path for kind when readable, else ""."""
    var path = String(_SYSTEM_BPF) + String("/") + file
    try:
        _ = read_host_file(
            path, String("system object probe"), 67108864
        )
    except:
        return String("")
    return path^


def _user() -> UidPair:
    return UidPair(1001, 1001)


def test_bridge_explicit_wins_verbatim() raises:
    # Explicit wins even when the path does not exist: it is
    # returned verbatim, never probed, ahead of a live env and
    # bundle candidate.
    var got = discover_bridge(
        String(_ABSENT), True, String(_ENV_BRIDGE), _user(),
        String(_EXE),
    )
    assert_equal(got, String(_ABSENT))


def test_bridge_explicit_empty() raises:
    var got = discover_bridge(
        String(""), True, String(_BUNDLED_BRIDGE), _user(),
        String(_EXE),
    )
    assert_equal(got, String(""))


def test_bridge_env_honored_unprivileged() raises:
    # Env beats the bundled candidate when unprivileged. The env
    # path differs from the bundle path so the test can tell which
    # step matched.
    var got = discover_bridge(
        String(""), False, String(_ENV_BRIDGE), _user(),
        String(_EXE),
    )
    assert_equal(got, String(_ENV_BRIDGE))


def test_bridge_env_ignored_privileged() raises:
    var root = UidPair(0, 0)
    var setuid = UidPair(1001, 0)
    var want = String(_BUNDLED_BRIDGE)
    var got_root = discover_bridge(
        String(""), False, String(_ENV_BRIDGE), root, String(_EXE)
    )
    assert_equal(got_root, want)
    var got_setuid = discover_bridge(
        String(""), False, String(_ENV_BRIDGE), setuid, String(_EXE)
    )
    assert_equal(got_setuid, want)


def test_bridge_env_missing_falls_through() raises:
    # A set-but-unreadable env value is skipped, not returned.
    var got = discover_bridge(
        String(""), False, String(_ABSENT), _user(), String(_EXE)
    )
    assert_equal(got, String(_BUNDLED_BRIDGE))


def test_bridge_exe_relative() raises:
    var got = discover_bridge(
        String(""), False, String(""), _user(), String(_EXE)
    )
    assert_equal(got, String(_BUNDLED_BRIDGE))


def test_bridge_without_bundle() raises:
    # No explicit, no env, no bundle: system path iff readable.
    var want = _system_bridge_expected()
    var got = discover_bridge(
        String(""), False, String(""), _user(),
        String("tests/fixtures/runtime-missing/bin/memveil"),
    )
    assert_equal(got, want)


def test_bridge_empty_exe_path() raises:
    var got = discover_bridge(
        String(""), False, String(""), _user(), String("")
    )
    assert_equal(got, _system_bridge_expected())


def test_bridge_bare_exe_name() raises:
    var got = discover_bridge(
        String(""), False, String(""), _user(), String("memveil")
    )
    assert_equal(got, _system_bridge_expected())


def test_object_explicit_wins_verbatim() raises:
    var missing = String("tests/fixtures/runtime/bpf/absent.bpf.o")
    var got = discover_object(
        String("attempt"), missing, True, String(_EXE)
    )
    assert_equal(got, missing)


def test_object_kinds() raises:
    var attempt = discover_object(
        String("attempt"), String(""), False, String(_EXE)
    )
    assert_equal(
        attempt,
        String("tests/fixtures/runtime/bpf/swiotlb_attempt.bpf.o"),
    )
    var lifecycle = discover_object(
        String("lifecycle"), String(""), False, String(_EXE)
    )
    assert_equal(
        lifecycle,
        String("tests/fixtures/runtime/bpf/swiotlb_lifecycle.bpf.o"),
    )
    var copy = discover_object(
        String("copy"), String(""), False, String(_EXE)
    )
    assert_equal(
        copy, String("tests/fixtures/runtime/bpf/swiotlb_copy.bpf.o")
    )


def test_object_without_bundle() raises:
    var exe = String("tests/fixtures/runtime-missing/bin/memveil")
    var attempt = discover_object(
        String("attempt"), String(""), False, exe
    )
    assert_equal(
        attempt,
        _system_object_expected(
            String("attempt"), String("swiotlb_attempt.bpf.o")
        ),
    )


def test_object_unknown_kind() raises:
    var got = discover_object(
        String("bogus"), String(""), False, String(_EXE)
    )
    assert_equal(got, String(""))


def test_object_unknown_kind_explicit_wins() raises:
    var missing = String("tests/fixtures/runtime/bpf/absent.bpf.o")
    var got = discover_object(
        String("bogus"), missing, True, String(_EXE)
    )
    assert_equal(got, missing)


def test_exe_root() raises:
    assert_equal(
        exe_root(String(_EXE)), String("tests/fixtures/runtime")
    )
    assert_equal(exe_root(String("/root/bin/memveil")), String("/root"))
    assert_equal(exe_root(String("/usr/bin/memveil")), String("/usr"))
    assert_equal(exe_root(String("/memveil")), String("/"))
    assert_equal(exe_root(String("bin/memveil")), String(""))
    assert_equal(exe_root(String("memveil")), String(""))
    assert_equal(exe_root(String("")), String(""))


def test_is_privileged() raises:
    assert_true(not is_privileged(UidPair(1001, 1001)))
    assert_true(is_privileged(UidPair(0, 0)))
    assert_true(is_privileged(UidPair(1001, 0)))
    assert_true(is_privileged(UidPair(0, 1001)))


def test_live_uids() raises:
    var ids = live_uids()
    assert_true(ids.ruid >= 0)
    assert_true(ids.euid >= 0)
    assert_equal(ids.ruid, Int(external_call["getuid", UInt32]()))
    assert_equal(ids.euid, Int(external_call["geteuid", UInt32]()))
    assert_equal(
        is_privileged(ids), ids.euid == 0 or ids.euid != ids.ruid
    )


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_bridge_explicit_wins_verbatim]()
    suite.test[test_bridge_explicit_empty]()
    suite.test[test_bridge_env_honored_unprivileged]()
    suite.test[test_bridge_env_ignored_privileged]()
    suite.test[test_bridge_env_missing_falls_through]()
    suite.test[test_bridge_exe_relative]()
    suite.test[test_bridge_without_bundle]()
    suite.test[test_bridge_empty_exe_path]()
    suite.test[test_bridge_bare_exe_name]()
    suite.test[test_object_explicit_wins_verbatim]()
    suite.test[test_object_kinds]()
    suite.test[test_object_without_bundle]()
    suite.test[test_object_unknown_kind]()
    suite.test[test_object_unknown_kind_explicit_wins]()
    suite.test[test_exe_root]()
    suite.test[test_is_privileged]()
    suite.test[test_live_uids]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
