# SPDX-License-Identifier: GPL-3.0-or-later

"""Pinned artifact files: snapshots, root joining, ownership repair.

Collection resolves bridge and BPF object pathnames once, pins
each behind one open file description, and hashes and loads
through the pin's /proc/self/fd/N alias, so a pathname swap
after resolution changes neither the hashed nor the loaded
bytes. Captures finalized by a root run are handed back to the
invoking user through retained descriptors with dev/inode
continuity. Helpers return explicit owned results and never
write diagnostics; callers render those.
"""

from std.ffi import external_call
from std.os import getenv

from memveil.platform.hash import sha256_hex
from memveil.platform.narrow import MAX_NARROW_OBJECT_BYTES
from memveil.platform.reader import _geteuid_live, read_host_file


def join_root(root: String, path: String) -> String:
    """Join an evidence root with an absolute member path."""
    if root == String("/") or root == String(""):
        return path
    return root + path


comptime _SNAP_AT_FDCWD = -100
comptime _SNAP_O_RDONLY = 0


struct BridgeSnapshot(Movable):
    """One pinned bridge file: the hashed bytes are the loaded bytes.

    The resolved pathname opens once with O_RDONLY and
    stays open; the loader and the admission hash both
    name that same open file description through
    /proc/self/fd/N, so a pathname swap after
    resolution changes neither. The pin defeats
    rename and symlink swaps, not in-place writes to
    the pinned inode itself; the threat assumption is
    unchanged. ``sha`` is the bare hex sha256 of the
    pinned bytes, "" when the bridge is uncheckable;
    ``load_path`` is the fd alias when pinned, else
    the plain pathname for the loader's own failure.
    Hold the snapshot until the load it guards
    completes; dropping it closes the fd.
    """

    var fd: Int32
    var load_path: String
    var sha: String

    def __init__(out self):
        self.fd = Int32(-1)
        self.load_path = String("")
        self.sha = String("")

    def __deinit__(deinit self):
        if self.fd >= Int32(0):
            _ = external_call["close", Int32](self.fd)


def open_bridge_snapshot(path: String) -> BridgeSnapshot:
    """Pin one bridge file for hashing and loading.

    Opens path O_RDONLY (following a final symlink
    once, at open) and hashes the open description
    through its /proc/self/fd/N alias; the loader
    receives the same alias. When the open or the
    alias read fails, the snapshot degrades to the
    plain pathname with an empty hash: admission
    cannot bind and the loader reports its own
    failure, exactly as before. Never raises.
    """
    var snap = BridgeSnapshot()
    if path == String(""):
        return snap^
    var cpath = _to_cstr(path)
    var fd = external_call["openat", Int32](
        Int32(_SNAP_AT_FDCWD),
        Span(cpath).unsafe_ptr(),
        Int32(_SNAP_O_RDONLY),
        UInt32(0),
    )
    if fd < Int32(0):
        snap.load_path = path.copy()
        return snap^
    var alias = String("/proc/self/fd/") + String(Int(fd))
    try:
        var raw = read_host_file(
            alias, String("bridge"), MAX_NARROW_OBJECT_BYTES
        )
        snap.sha = sha256_hex(Span(raw))
        snap.fd = fd
        snap.load_path = alias.copy()
    except:
        _ = external_call["close", Int32](fd)
        snap.load_path = path.copy()
    return snap^


def open_object_snapshot(path: String) -> BridgeSnapshot:
    """Pin one BPF object file for smoke input and minting.

    The same mechanism as open_bridge_snapshot: one
    O_RDONLY open, hashed and read through its
    /proc/self/fd/N alias, degrading to the plain
    pathname with an empty hash when uncheckable.
    Qualify snapshots each object before the smoke,
    feeds the alias to the smoke as its load input,
    and mints from the snapshot hash, so the receipt
    binds the exercised bytes. Never raises.
    """
    var snap = open_bridge_snapshot(path)
    return snap^


def _parse_sudo_id(text: String) -> Int:
    """Parse a SUDO_UID/SUDO_GID value, or -1 when insane.

    Strict ASCII decimal fitting uid_t
    (0..4294967295); empty, non-digit, and
    overflowing values refuse. -1 never collides:
    it lies outside the uid_t range.
    """
    var raw = text.as_bytes()
    if len(raw) == 0 or len(raw) > 10:
        return -1
    var v = UInt64(0)
    for i in range(len(raw)):
        var b = raw[i]
        if b < UInt8(0x30) or b > UInt8(0x39):
            return -1
        var d = UInt64(Int(b) - 0x30)
        if v > (UInt64(0xFFFFFFFF) - d) // UInt64(10):
            return -1
        v = v * UInt64(10) + d
    return Int(v)


def _to_cstr(text: String) -> List[UInt8]:
    """Copy text into a fresh NUL-terminated byte buffer."""
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


comptime _OWN_AT_FDCWD = -100
comptime _OWN_O_RDONLY = 0
comptime _OWN_O_DIRECTORY = 65536
comptime _OWN_O_NOFOLLOW = 131072
comptime _OWN_STAT_SIZE = 144
comptime _OWN_S_IFMT = 0o170000
comptime _OWN_S_IFREG = 0o100000
comptime _OWN_S_IFDIR = 0o040000
comptime _OWN_DIRENT_NAME_OFF = 19
comptime _OWN_DIRENT_BUF_SIZE = 8192


def _own_name_is(
    buf: List[UInt8], base: Int, nlen: Int, text: String
) -> Bool:
    """True when the NUL-bounded name equals text, byte-wise."""
    var i = 0
    for b in text.as_bytes():
        if i >= nlen:
            return False
        if buf[base + i] != b:
            return False
        i += 1
    return i == nlen


def _own_le32(buf: List[UInt8], off: Int) -> UInt32:
    var v = UInt32(0)
    for i in range(4):
        v |= UInt32(buf[off + i]) << UInt32(8 * i)
    return v


def _own_le64(buf: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(buf[off + i]) << UInt64(8 * i)
    return v


def _own_fstat_ids(fd: Int32) raises -> List[UInt64]:
    """[mode, uid, nlink] for an open fd (x86-64 stat layout)."""
    var buf = List[UInt8]()
    for _ in range(_OWN_STAT_SIZE):
        buf.append(UInt8(0))
    var r = external_call["fstat", Int32](
        fd, Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("ownership fstat failed")
    var out = List[UInt64]()
    out.append(UInt64(_own_le32(buf, 24)))
    out.append(UInt64(_own_le32(buf, 28)))
    out.append(_own_le64(buf, 16))
    return out^


def _own_fstat_devino(fd: Int32) raises -> List[UInt64]:
    """[st_dev, st_ino] for an open fd (x86-64 stat layout)."""
    var buf = List[UInt8]()
    for _ in range(_OWN_STAT_SIZE):
        buf.append(UInt8(0))
    var r = external_call["fstat", Int32](
        fd, Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise Error("ownership fstat failed")
    var out = List[UInt64]()
    out.append(_own_le64(buf, 0))
    out.append(_own_le64(buf, 8))
    return out^


def _own_close_quiet(fd: Int32):
    if fd >= Int32(0):
        _ = external_call["close", Int32](fd)


def _own_errno_now() -> Int:
    var p = external_call[
        "__errno_location", Pointer[Int32, MutAnyOrigin]
    ]()
    return Int(p.unsafe_load())


def _own_dir_has_foreign(dir_fd: Int32) -> Bool:
    """True when dir holds entries besides the capture files.

    A finalized capture holds exactly events.ndjson and
    session.json; any other entry proves a planted or
    swapped-in foreign file, and the repair must not
    transfer the directory out from under it. Listing
    failures also refuse (fail closed). Lists entries
    with getdents64 straight off the held fd (no
    DIR stream, so no libc symbols the stdlib also
    declares): getdents64 advances the directory
    offset, so the caller must pass a fresh
    descriptor it never lists twice (as the repair
    path does). Never raises.
    """
    var buf = List[UInt8]()
    for _ in range(_OWN_DIRENT_BUF_SIZE):
        buf.append(UInt8(0))
    var foreign = False
    var failed = False
    while True:
        var n = external_call["getdents64", Int64](
            dir_fd, Span(buf).unsafe_ptr(), UInt64(len(buf))
        )
        if n < Int64(0):
            failed = True
            break
        if n == Int64(0):
            break
        var total = Int(n)
        var off = 0
        while off < total:
            var nbase = off + _OWN_DIRENT_NAME_OFF
            if nbase > total:
                failed = True
                break
            var reclen = Int(buf[off + 16]) | (
                Int(buf[off + 17]) << 8
            )
            if reclen < 20 or off + reclen > total:
                failed = True
                break
            # d_name sits at byte 19 of the x86-64
            # Linux dirent (ino 8, off 8, reclen 2,
            # type 1); match the capture files
            # byte-wise, anything else is foreign.
            var nlen = 0
            while _OWN_DIRENT_NAME_OFF + nlen < reclen:
                if buf[nbase + nlen] == UInt8(0):
                    break
                nlen += 1
            var known = _own_name_is(
                buf, nbase, nlen, String(".")
            )
            known = known or _own_name_is(
                buf, nbase, nlen, String("..")
            )
            known = known or _own_name_is(
                buf, nbase, nlen, String("events.ndjson")
            )
            known = known or _own_name_is(
                buf, nbase, nlen, String("session.json")
            )
            if not known:
                foreign = True
                break
            off += reclen
        if foreign or failed:
            break
    return foreign or failed


def _own_open_dir(path: String) -> Int32:
    """Open the directory itself, never a symlink; -1 on failure."""
    var cpath = _to_cstr(path)
    return external_call["openat", Int32](
        Int32(_OWN_AT_FDCWD),
        Span(cpath).unsafe_ptr(),
        Int32(_OWN_O_RDONLY | _OWN_O_DIRECTORY | _OWN_O_NOFOLLOW),
        UInt32(0),
    )


def _own_open_child(dir_fd: Int32, name: String) -> Int32:
    """Open one child by name, never a symlink; -1 on failure."""
    var cname = _to_cstr(name)
    return external_call["openat", Int32](
        dir_fd,
        Span(cname).unsafe_ptr(),
        Int32(_OWN_O_RDONLY | _OWN_O_NOFOLLOW),
        UInt32(0),
    )


def _own_child_ok(fd: Int32) -> Bool:
    """True when an open child is a single-link regular file.

    Symlinks never reach here (O_NOFOLLOW refuses them
    at open). This rejects directories, fifos, sockets,
    and files with extra hard links. Ownership is
    checked separately by the caller. Never raises.
    """
    try:
        var ids = _own_fstat_ids(fd)
        return (
            ids[0] & UInt64(_OWN_S_IFMT) == UInt64(_OWN_S_IFREG)
            and ids[2] == UInt64(1)
        )
    except:
        return False


def _own_fd_uid(fd: Int32) -> Int:
    """Owner uid of an open fd, or -1 on failure.

    Under sudo every true capture file is
    root-created, so any other owner proves a planted
    replacement. Never raises.
    """
    try:
        var ids = _own_fstat_ids(fd)
        return Int(ids[1])
    except:
        return -1


def _own_fd_matches(
    fd: Int32, want_dev: UInt64, want_ino: UInt64
) -> Bool:
    """True when an open fd names the recorded identity.

    Mode/uid/nlink alone cannot tell a substituted
    root-owned file from the capture's own; dev/inode
    continuity can. Never raises.
    """
    try:
        var ids = _own_fstat_devino(fd)
        return ids[0] == want_dev and ids[1] == want_ino
    except:
        return False


def _own_fchown(fd: Int32, uid: UInt32, gid: UInt32) -> Bool:
    """True when one fchown call reports success."""
    var r = external_call["fchown", Int32](fd, uid, gid)
    return Int(r) == 0


def _own_repair_child(
    dir_fd: Int32, name: String, uid: UInt32, gid: UInt32,
    want_dev: UInt64, want_ino: UInt64,
) -> Bool:
    """Hand one expected child to the invoking user.

    The child opens through the retained directory
    descriptor and every later step (identity check,
    ownership transfer) acts on that same open file
    description, so a mid-repair replacement cannot
    redirect the chown. Only the recorded capture file
    transfers: a root-owned single-link regular file
    whose dev/inode matches the finalize pin, compared
    before any fchown. Anything else is rejected
    untouched. False when the child is missing,
    rejected, or unchownable. Never raises.
    """
    var fd = _own_open_child(dir_fd, name)
    if fd < Int32(0):
        return False
    var ok = (
        _own_child_ok(fd)
        and _own_fd_uid(fd) == 0
        and _own_fd_matches(fd, want_dev, want_ino)
    )
    if ok:
        ok = _own_fchown(fd, uid, gid)
    _own_close_quiet(fd)
    return ok


struct OwnershipRepair(Copyable, Movable):
    """One capture ownership repair: attempted, and whether it held.

    ``attempted`` is True only for a root run under sudo
    with sane invoking ids; anything else is a silent
    no-op. ``repaired`` is True only when every expected
    transfer succeeded. ``uid``/``gid`` name the invoking
    user for the caller's warning; they are -1 when the
    repair never attempted.
    """

    var attempted: Bool
    var repaired: Bool
    var uid: Int
    var gid: Int

    def __init__(out self):
        self.attempted = False
        self.repaired = False
        self.uid = -1
        self.gid = -1


def restore_capture_ownership(
    output: String, want: List[UInt64]
) -> OwnershipRepair:
    """Best-effort capture ownership repair; never raises.

    Under sudo the capture lands root-owned (mkdir
    0700), locking out the invoking user's replay.
    When both SUDO_UID and SUDO_GID parse as uid_t
    values and this process runs as root (a non-root
    run already owns its files, so there is nothing
    to restore), hand the capture to the invoking
    user through retained descriptors: the directory
    opens with O_DIRECTORY|O_NOFOLLOW and must itself
    be the recorded capture dir (dev/inode continuity
    against the finalize pin, compared before any
    fchown; a substituted dir aborts the repair before
    anything is touched); each expected flat file
    (events.ndjson, session.json) opens through that
    descriptor, proves the recorded root-owned
    single-link regular file, and transfers via
    fchown, and only when the directory holds exactly
    those two files; any foreign entry aborts the repair
    before anything is touched. ``want`` is the writer's
    [dir_dev, dir_ino, ev_dev, ev_ino, sess_dev,
    sess_ino] pin; any other shape aborts touching
    nothing. The directory transfers LAST, so the
    invoking user gains no write access until every
    child is already handed back and nothing can be
    planted mid-repair. The result reports the repair;
    the caller warns once on stderr for an attempted
    repair that did not hold, and the capture itself
    stands either way.
    """
    var repair = OwnershipRepair()
    var uid = _parse_sudo_id(getenv("SUDO_UID"))
    var gid = _parse_sudo_id(getenv("SUDO_GID"))
    if uid < 0 or gid < 0:
        return repair^
    if _geteuid_live() != 0:
        return repair^
    repair.attempted = True
    repair.uid = uid
    repair.gid = gid
    var ok = True
    if len(want) != 6:
        return repair^
    var dir_fd = _own_open_dir(output)
    if dir_fd < Int32(0):
        ok = False
    else:
        var dir_ok = False
        try:
            var ids = _own_fstat_ids(dir_fd)
            dir_ok = (
                ids[0] & UInt64(_OWN_S_IFMT)
                == UInt64(_OWN_S_IFDIR)
                and ids[1] == UInt64(0)
                and _own_fd_matches(dir_fd, want[0], want[1])
            )
        except:
            dir_ok = False
        if dir_ok and _own_dir_has_foreign(dir_fd):
            dir_ok = False
        if dir_ok:
            if not _own_repair_child(
                dir_fd,
                String("events.ndjson"),
                UInt32(uid),
                UInt32(gid),
                want[2],
                want[3],
            ):
                ok = False
            if not _own_repair_child(
                dir_fd,
                String("session.json"),
                UInt32(uid),
                UInt32(gid),
                want[4],
                want[5],
            ):
                ok = False
            if not _own_fchown(dir_fd, UInt32(uid), UInt32(gid)):
                ok = False
        else:
            ok = False
        _own_close_quiet(dir_fd)
    repair.repaired = ok
    return repair^
