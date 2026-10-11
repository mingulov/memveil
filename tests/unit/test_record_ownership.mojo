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

from memveil.capture.writer import EventWriter
from memveil.cli.record import (
    _own_child_ok,
    _own_close_quiet,
    _own_fd_uid,
    _own_fstat_devino,
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


def _t_pin_one(fd: Int32) raises -> List[UInt64]:
    return _own_fstat_devino(fd)


def _t_want_for(
    dir_path: String, ev_name: String, sess_dummy: Bool
) raises -> List[UInt64]:
    """Record [dir, ev, sess] dev/inode for a manual capture dir.

    Session is dummy zeros when it cannot open (symlink
    probe); the repair fails that child at open before
    any identity compare, as before.
    """
    var want = List[UInt64]()
    var dir_fd = _own_open_dir(dir_path)
    if dir_fd < Int32(0):
        raise Error("want: cannot open dir " + dir_path)
    var dids = _t_pin_one(dir_fd)
    want.append(dids[0])
    want.append(dids[1])
    var ev_fd = _own_open_child(dir_fd, ev_name)
    if ev_fd < Int32(0):
        _own_close_quiet(dir_fd)
        raise Error("want: cannot open " + ev_name)
    var eids = _t_pin_one(ev_fd)
    _own_close_quiet(ev_fd)
    want.append(eids[0])
    want.append(eids[1])
    if sess_dummy:
        want.append(UInt64(0))
        want.append(UInt64(0))
    else:
        var s_fd = _own_open_child(dir_fd, String("session.json"))
        if s_fd < Int32(0):
            _own_close_quiet(dir_fd)
            raise Error("want: cannot open session.json")
        var sids = _t_pin_one(s_fd)
        _own_close_quiet(s_fd)
        want.append(sids[0])
        want.append(sids[1])
    _own_close_quiet(dir_fd)
    return want^


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
    var want = _t_want_for(cap, String("events.ndjson"), True)
    _restore_sudo_ownership(cap, want^)
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
    var mine_fd = _own_open_child(dir_fd, String("events.ndjson"))
    assert_true(mine_fd >= Int32(0))
    var mine_ids = _own_fstat_devino(mine_fd)
    _own_close_quiet(mine_fd)
    var planted_fd = _own_open_child(dir_fd, String("session.json"))
    assert_true(planted_fd >= Int32(0))
    var planted_ids = _own_fstat_devino(planted_fd)
    _own_close_quiet(planted_fd)
    assert_true(
        _own_repair_child(
            dir_fd, String("events.ndjson"), UInt32(uid), UInt32(gid),
            mine_ids[0], mine_ids[1],
        )
    )
    assert_true(
        not _own_repair_child(
            dir_fd, String("session.json"), UInt32(uid), UInt32(gid),
            planted_ids[0], planted_ids[1],
        )
    )
    _own_close_quiet(dir_fd)
    assert_equal(_t_lstat_uid(mine), uid)
    assert_equal(_t_lstat_uid(planted), uid)
    assert_equal(_t_lstat_gid(planted), 0)


def _t_rename(old: String, new: String) raises:
    var co = _t_cstr(old)
    var cn = _t_cstr(new)
    var r = external_call["rename", Int32](
        Span(co).unsafe_ptr(), Span(cn).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("rename failed: " + old + " -> " + new)


def _t_finalize_cap(path: String) raises -> List[UInt64]:
    """Create + finalize one capture; return its recorded identity.

    Uses the production EventWriter so the identity pins
    the same dev/inode the repair must compare against.
    """
    var w = EventWriter(path, 131072)
    var sess = List[UInt8]()
    for b in String('{"dummy":1}\n').as_bytes():
        sess.append(b)
    var out = w.finalize(sess^)
    assert_equal(out.status, String("finalized"))
    return w.finalized_identity()


def test_restore_rejects_dir_replacement() raises:
    # Root-only directory-replacement probe: a substituted
    # root-owned dir with root-owned single-link children
    # must be rejected (no transfer), while the original
    # dir repairs. Without dev/inode continuity the
    # substitute passes mode/uid/nlink and transfers.
    if _geteuid_live() != 0:
        return
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid <= 0 or gid < 0:
        return
    var base = _stop_mkdtemp()
    var cap1 = base + String("/cap1")
    var cap2 = base + String("/cap2")
    var sub = base + String("/sub")
    var want1 = _t_finalize_cap(cap1)
    var want2 = _t_finalize_cap(cap2)
    _t_mkdir(sub)
    _t_write(sub + String("/events.ndjson"), String("FOREIGN-EVENTS\n"))
    _t_write(sub + String("/session.json"), String("FOREIGN-SESSION\n"))
    # Replace cap1 with the substitute (parent-rename,
    # as in a user-writable parent).
    _t_rename(cap1, base + String("/cap1.orig"))
    _t_rename(sub, cap1)
    _restore_sudo_ownership(cap1, want1)
    assert_equal(_t_lstat_uid(cap1), 0)
    assert_equal(_t_lstat_uid(cap1 + String("/events.ndjson")), 0)
    assert_equal(_t_lstat_uid(cap1 + String("/session.json")), 0)
    # Positive control: the original dir repairs.
    _restore_sudo_ownership(cap2, want2)
    assert_equal(_t_lstat_uid(cap2), uid)
    assert_equal(_t_lstat_uid(cap2 + String("/events.ndjson")), uid)
    assert_equal(_t_lstat_uid(cap2 + String("/session.json")), uid)


def test_restore_refuses_foreign_entries() raises:
    # Root-only foreign-entry probe: a capture dir
    # holding an extra planted file must not transfer at
    # all (neither children nor the dir itself), while a
    # clean capture repairs. Without the entry check the
    # dir hands back out from under the foreign file.
    if _geteuid_live() != 0:
        return
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid <= 0 or gid < 0:
        return
    var base = _stop_mkdtemp()
    var cap1 = base + String("/cap1")
    var cap2 = base + String("/cap2")
    var want1 = _t_finalize_cap(cap1)
    var want2 = _t_finalize_cap(cap2)
    _t_write(cap1 + String("/stowaway.txt"), String("FOREIGN\n"))
    _restore_sudo_ownership(cap1, want1)
    assert_equal(_t_lstat_uid(cap1), 0)
    assert_equal(_t_lstat_uid(cap1 + String("/events.ndjson")), 0)
    assert_equal(_t_lstat_uid(cap1 + String("/session.json")), 0)
    assert_equal(_t_lstat_uid(cap1 + String("/stowaway.txt")), 0)
    # Positive control: the clean dir repairs.
    _restore_sudo_ownership(cap2, want2)
    assert_equal(_t_lstat_uid(cap2), uid)
    assert_equal(_t_lstat_uid(cap2 + String("/events.ndjson")), uid)
    assert_equal(_t_lstat_uid(cap2 + String("/session.json")), uid)


def run() raises -> Int:
    var suite = TestSuite()
    suite.test[test_restore_rejects_symlink_swap]()
    suite.test[test_open_child_rejects_symlink]()
    suite.test[test_child_ok_accepts_regular]()
    suite.test[test_child_ok_rejects_dir]()
    suite.test[test_child_ok_rejects_hardlink]()
    suite.test[test_repair_child_owner_arms_need_root]()
    suite.test[test_restore_rejects_dir_replacement]()
    suite.test[test_restore_refuses_foreign_entries]()
    suite^.run()
    return 0


def main() raises:
    var code = run()
    if code != 0:
        exit(code)
