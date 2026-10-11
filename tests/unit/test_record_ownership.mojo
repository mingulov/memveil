# SPDX-License-Identifier: GPL-3.0-or-later

"""Ownership hand-back: symlink-swap rejection and warn-only repair.

Under sudo the capture lands root-owned; record hands it back to
the invoking user. The repair must never let the invoking user
redirect root chown operations outside the capture: swapped-in
symlinks are rejected and no outside path is chowned.

The adversarial test needs root and a real invoking user (run the
file under sudo: SUDO_UID/SUDO_GID come from sudo itself); without
root it returns early and the file still pins the non-root
validation helpers below.
"""

from std.ffi import external_call
from std.os import getenv
from std.sys import exit
from std.testing import TestSuite, assert_equal, assert_true

from scripted import _stop_mkdtemp

from memveil.cli.record import (
    _own_child_ok,
    _own_close_quiet,
    _own_fd_uid,
    _own_open_child,
    _own_open_dir,
    _own_repair_child,
    _parse_sudo_id,
    _restore_sudo_ownership,
)
from memveil.platform.reader import (
    _geteuid_live,
    read_host_file,
)


comptime _SWAP = "tests/fixtures/ownership/swap"


def _t_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _t_lstat_uid(path: String) raises -> Int:
    """Owner uid of path itself (no symlink follow), or raise."""
    var buf = List[UInt8]()
    for _ in range(144):
        buf.append(UInt8(0))
    var cpath = _t_cstr(path)
    var r = external_call["lstat", Int32](
        Span(cpath).unsafe_ptr(), Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("lstat failed for " + path)
    var uid = UInt32(0)
    for i in range(4):
        uid |= UInt32(buf[28 + i]) << UInt32(8 * i)
    return Int(uid)


def _t_lstat_gid(path: String) raises -> Int:
    """Owner gid of path itself (no symlink follow), or raise."""
    var buf = List[UInt8]()
    for _ in range(144):
        buf.append(UInt8(0))
    var cpath = _t_cstr(path)
    var r = external_call["lstat", Int32](
        Span(cpath).unsafe_ptr(), Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("lstat failed for " + path)
    var gid = UInt32(0)
    for i in range(4):
        gid |= UInt32(buf[32 + i]) << UInt32(8 * i)
    return Int(gid)


def _t_write(path: String, text: String) raises:
    var cpath = _t_cstr(path)
    var mode = _t_cstr("w")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == UInt64(0):
        raise Error("fopen failed for " + path)
    var raw = text.as_bytes()
    var n = external_call["fwrite", Int64](
        Span(raw).unsafe_ptr(), Int64(1), Int64(len(raw)), fp
    )
    _ = external_call["fclose", Int32](fp)
    if Int(n) != len(raw):
        raise Error("short write for " + path)


def _t_mkdir(path: String) raises:
    var cpath = _t_cstr(path)
    var r = external_call["mkdirat", Int32](
        Int32(-100), Span(cpath).unsafe_ptr(), 0o700
    )
    if Int(r) != 0:
        raise Error("mkdir failed for " + path)


def _t_symlink(target: String, link: String) raises:
    var ct = _t_cstr(target)
    var cl = _t_cstr(link)
    var r = external_call["symlink", Int32](
        Span(ct).unsafe_ptr(), Span(cl).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("symlink failed for " + link)


def test_restore_rejects_symlink_swap() raises:
    # Root-only adversarial probe: a capture dir whose
    # session.json is a symlink to an outside victim must be
    # repaired without chowning the victim. Without root (or
    # without a sudo invoking user) this returns early.
    if _geteuid_live() != 0:
        return
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid <= 0 or gid < 0:
        return
    var base = _stop_mkdtemp()
    var cap = base + String("/cap")
    var victim = base + String("/victim.txt")
    _t_mkdir(cap)
    _t_write(cap + String("/events.ndjson"), String("EVENTS\n"))
    _t_write(victim, String("VICTIM\n"))
    _t_symlink(victim, cap + String("/session.json"))
    _restore_sudo_ownership(cap)
    assert_equal(_t_lstat_uid(victim), 0)
    assert_equal(_t_lstat_uid(cap + String("/events.ndjson")), uid)
    assert_equal(_t_lstat_uid(cap), uid)


def test_open_child_rejects_symlink() raises:
    # No privilege needed: the swapped session.json
    # symlink must refuse O_NOFOLLOW open, and the link
    # target stays intact.
    var dir_fd = _own_open_dir(String(_SWAP))
    assert_true(dir_fd >= Int32(0))
    assert_true(_own_open_child(dir_fd, String("session.json")) < Int32(0))
    _own_close_quiet(dir_fd)
    var raw = read_host_file(
        String(_SWAP) + String("/victim.txt"), String("victim"), 64
    )
    assert_equal(len(raw), 7)


def test_child_ok_accepts_regular() raises:
    var dir_fd = _own_open_dir(String(_SWAP))
    assert_true(dir_fd >= Int32(0))
    var fd = _own_open_child(dir_fd, String("events.ndjson"))
    assert_true(fd >= Int32(0))
    assert_true(_own_child_ok(fd))
    assert_equal(_own_fd_uid(fd), _t_lstat_uid(String(_SWAP)))
    _own_close_quiet(fd)
    _own_close_quiet(dir_fd)


def test_child_ok_rejects_dir() raises:
    var dir_fd = _own_open_dir(String(_SWAP))
    assert_true(dir_fd >= Int32(0))
    var fd = _own_open_child(dir_fd, String("subdir"))
    assert_true(fd >= Int32(0))
    assert_true(not _own_child_ok(fd))
    _own_close_quiet(fd)
    _own_close_quiet(dir_fd)


def test_child_ok_rejects_hardlink() raises:
    # No privilege needed: a second link to a regular
    # file must fail the single-link check.
    var base = _stop_mkdtemp()
    var one = base + String("/one.txt")
    var two = base + String("/two.txt")
    _t_write(one, String("LINKED\n"))
    var c1 = _t_cstr(one)
    var c2 = _t_cstr(two)
    var r = external_call["link", Int32](
        Span(c1).unsafe_ptr(), Span(c2).unsafe_ptr()
    )
    assert_equal(Int(r), 0)
    var dir_fd = _own_open_dir(base)
    assert_true(dir_fd >= Int32(0))
    var fd = _own_open_child(dir_fd, String("one.txt"))
    assert_true(fd >= Int32(0))
    assert_true(not _own_child_ok(fd))
    _own_close_quiet(fd)
    _own_close_quiet(dir_fd)


def test_repair_child_owner_arms_need_root() raises:
    # Root-only: a root-owned regular child transfers
    # while a user-owned one (planted replacement) is
    # rejected untouched.
    if _geteuid_live() != 0:
        return
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid <= 0 or gid < 0:
        return
    var base = _stop_mkdtemp()
    var mine = base + String("/events.ndjson")
    var planted = base + String("/session.json")
    _t_write(mine, String("EVENTS\n"))
    _t_write(planted, String("PLANTED\n"))
    # Planted files carry the user's uid but a foreign
    # gid, so a wrongful transfer would visibly change
    # the gid while rejection leaves it alone.
    var cp = _t_cstr(planted)
    var r = external_call["chown", Int32](
        Span(cp).unsafe_ptr(), UInt32(uid), UInt32(0)
    )
    assert_equal(Int(r), 0)
    var dir_fd = _own_open_dir(base)
    assert_true(dir_fd >= Int32(0))
    assert_true(
        _own_repair_child(
            dir_fd, String("events.ndjson"), UInt32(uid), UInt32(gid)
        )
    )
    assert_true(
        not _own_repair_child(
            dir_fd, String("session.json"), UInt32(uid), UInt32(gid)
        )
    )
    _own_close_quiet(dir_fd)
    assert_equal(_t_lstat_uid(mine), uid)
    assert_equal(_t_lstat_uid(planted), uid)
    assert_equal(_t_lstat_gid(planted), 0)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_restore_rejects_symlink_swap]()
    suite.test[test_open_child_rejects_symlink]()
    suite.test[test_child_ok_accepts_regular]()
    suite.test[test_child_ok_rejects_dir]()
    suite.test[test_child_ok_rejects_hardlink]()
    suite.test[test_repair_child_owner_arms_need_root]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
