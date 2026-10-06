# SPDX-License-Identifier: GPL-3.0-or-later

"""Writer fault-injection probe (writer lane tool, not shipped).

Usage:
  shim_probe script <dir>        fixed op sequence, one line per op
  shim_probe createonly <path>   create + one append + finalize, one line
  shim_probe rename_events <dir> rename events away + fresh file, finalize
  shim_probe rename_dir <dir>    rename the output dir away, finalize
  shim_probe live-create <dir>   LiveWriter create + abandon, two lines

Every op catches WriteError, prints a machine-readable line,
and continues the script, so the lane can assert exact
traces under each MVSHIM mode. Exit 0 always on the scripted
path; an unexpected escape (traceback) fails the lane.
"""

from std.ffi import external_call
from std.sys import argv, exit

from memveil.capture.live import LiveWriter
from memveil.capture.writer import (
    MIN_EVENTS_BUDGET,
    EventWriter,
)
from memveil.platform.reader import read_host_file


comptime _P_AT_FDCWD = -100
comptime _P_O_DIRECTORY = 65536
comptime _P_O_WRONLY = 1
comptime _P_O_CREAT = 64
comptime _P_O_EXCL = 128
comptime _P_RENAME_NOREPLACE = 1


def _p_cstr(text: String) -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _p_close_quiet(fd: Int32):
    if fd >= Int32(0):
        _ = external_call["close", Int32](fd)


def _line(byte: UInt8, n: Int) -> List[UInt8]:
    var out = List[UInt8]()
    for _ in range(n - 1):
        out.append(byte)
    out.append(UInt8(0x0A))
    return out^


def _script_ops(mut w: EventWriter, dir: String):
    try:
        w.append(_line(UInt8(0x41), 100))
        print(
            String("append1 ok committed=") + String(w.committed_len())
        )
    except e:
        print(
            String("append1 error kind=")
            + e.kind
        )
    try:
        w.append(_line(UInt8(0x42), 100))
        print(
            String("append2 ok committed=") + String(w.committed_len())
        )
    except e:
        print(
            String("append2 error kind=")
            + e.kind
        )
    var stage = String("begin")
    try:
        var mark = w.group_begin()
        stage = String("gc")
        w.append(_line(UInt8(0x43), 100))
        stage = String("gd")
        w.append(_line(UInt8(0x44), 100))
        stage = String("abort")
        w.group_abort(mark)
        print(
            String("group ok mark=")
            + String(mark)
            + String(" committed=")
            + String(w.committed_len())
        )
    except e:
        print(
            String("group error op=")
            + stage
            + String(" kind=")
            + e.kind
        )
    try:
        w.append(_line(UInt8(0x45), 100))
        print(
            String("append3 ok committed=") + String(w.committed_len())
        )
    except e:
        print(
            String("append3 error kind=")
            + e.kind
        )
    try:
        var outcome = w.finalize(_line(UInt8(0x7B), 50))
        print(
            String("finalize status=")
            + outcome.status
            + String(" note=")
            + outcome.message
        )
    except e:
        print(
            String("finalize error kind=")
            + e.kind
        )
    try:
        var ev = read_host_file(
            dir + String("/events.ndjson"), "probe events", 8388608
        )
        print(String("events_len=") + String(len(ev)))
    except:
        print(String("events MISSING"))
    try:
        var se = read_host_file(
            dir + String("/session.json"), "probe session", 8388608
        )
        print(String("session_len=") + String(len(se)))
    except:
        print(String("session MISSING"))


def _script(dir: String) raises:
    try:
        var w = EventWriter(dir, MIN_EVENTS_BUDGET)
        print(String("create ok"))
        _script_ops(w, dir)
    except e:
        print(
            String("create error kind=")
            + e.kind
        )
        print(String("events MISSING"))
        print(String("session MISSING"))


def _createonly(path: String) raises:
    try:
        var w = EventWriter(path, MIN_EVENTS_BUDGET)
        w.append(_line(UInt8(0x78), 2))
        var outcome = w.finalize(_line(UInt8(0x7B), 10))
        print(
            String("createonly ok status=")
            + outcome.status
            + String(" committed=")
            + String(w.committed_len())
        )
    except e:
        print(
            String("createonly error kind=")
            + e.kind
        )


def _rename_events(dir: String) raises:
    """Swap the visible events file mid-run, then finalize."""
    try:
        var w = EventWriter(dir, MIN_EVENTS_BUDGET)
        w.append(_line(UInt8(0x41), 100))
        var dir_cstr = _p_cstr(dir)
        var dirfd = external_call["openat", Int32](
            Int32(_P_AT_FDCWD),
            Span(dir_cstr).unsafe_ptr(),
            Int32(_P_O_DIRECTORY),
            UInt32(0),
        )
        if dirfd < Int32(0):
            print(String("mutate error kind=io"))
            return
        var old_name = _p_cstr("events.ndjson")
        var bak_name = _p_cstr("events.ndjson.bak")
        var rn = external_call["renameat2", Int32](
            dirfd,
            Span(old_name).unsafe_ptr(),
            dirfd,
            Span(bak_name).unsafe_ptr(),
            UInt32(_P_RENAME_NOREPLACE),
        )
        if Int(rn) != 0:
            print(String("mutate error kind=io"))
            _p_close_quiet(dirfd)
            return
        var fresh = external_call["openat", Int32](
            dirfd,
            Span(old_name).unsafe_ptr(),
            Int32(_P_O_WRONLY | _P_O_CREAT | _P_O_EXCL),
            UInt32(0o600),
        )
        if fresh < Int32(0):
            print(String("mutate error kind=io"))
            _p_close_quiet(dirfd)
            return
        var junk = _line(UInt8(0x4A), 11)
        var n = external_call["pwrite", Int64](
            fresh,
            Span(junk).unsafe_ptr(),
            Int64(len(junk)),
            Int64(0),
        )
        _p_close_quiet(fresh)
        _p_close_quiet(dirfd)
        if Int(n) != len(junk):
            print(String("mutate error kind=io"))
            return
        print(String("mutate ok"))
        try:
            var outcome = w.finalize(_line(UInt8(0x7B), 50))
            print(
                String("finalize status=")
                + outcome.status
                + String(" note=")
                + outcome.message
            )
        except e:
            print(String("finalize error kind=") + e.kind)
    except e:
        print(String("setup error kind=") + e.kind)


def _live_create(dir: String):
    """LiveWriter create, then abandon; print both outcomes."""
    var w = LiveWriter()
    var made = w.create(dir, MIN_EVENTS_BUDGET)
    if made.ok:
        print(String("live-create ok"))
    else:
        print(
            String("live-create error kind=")
            + made.kind
            + String(" message=")
            + made.message
        )
    print(String("live-create abandon=") + w.abandon())
    print(String("live-create abandon2=") + w.abandon())


def _rename_dir(dir: String) raises:
    """Rename the output dir away mid-run, then finalize."""
    try:
        var w = EventWriter(dir, MIN_EVENTS_BUDGET)
        w.append(_line(UInt8(0x41), 100))
        var old_cstr = _p_cstr(dir)
        var new_cstr = _p_cstr(dir + String(".bak"))
        var rn = external_call["renameat2", Int32](
            Int32(_P_AT_FDCWD),
            Span(old_cstr).unsafe_ptr(),
            Int32(_P_AT_FDCWD),
            Span(new_cstr).unsafe_ptr(),
            UInt32(_P_RENAME_NOREPLACE),
        )
        if Int(rn) != 0:
            print(String("mutate error kind=io"))
            return
        print(String("mutate ok"))
        try:
            var outcome = w.finalize(_line(UInt8(0x7B), 50))
            print(
                String("finalize status=")
                + outcome.status
                + String(" note=")
                + outcome.message
            )
        except e:
            print(String("finalize error kind=") + e.kind)
    except e:
        print(String("setup error kind=") + e.kind)


def main() raises:
    var args = argv()
    if len(args) != 3:
        print(String("usage: shim_probe {script|createonly} <path>"))
        exit(2)
    if args[1] == String("script"):
        _script(args[2])
    elif args[1] == String("createonly"):
        _createonly(args[2])
    elif args[1] == String("rename_events"):
        _rename_events(args[2])
    elif args[1] == String("rename_dir"):
        _rename_dir(args[2])
    elif args[1] == String("live-create"):
        _live_create(args[2])
    else:
        print(String("usage: shim_probe {script|createonly} <path>"))
        exit(2)
