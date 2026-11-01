# SPDX-License-Identifier: GPL-3.0-or-later

"""Descriptor-based recovery reads with directory locking and identity checks."""
from std.ffi import external_call


def cstr(text: String) raises -> List[UInt8]:
    var out = List[UInt8]()
    for b in text.as_bytes():
        if b == 0:
            raise Error("NUL in capture path")
        out.append(b)
    out.append(UInt8(0))
    return out^


def close_fd(fd: Int32):
    if fd >= 0:
        _ = external_call["close", Int32](fd)


def file_stat(fd: Int32) raises -> List[UInt64]:
    # Linux x86-64 stat layout is checked by the native layout test.
    var raw = List[UInt8](length=144, fill=UInt8(0))
    if external_call["fstat", Int32](fd, Span(raw).unsafe_ptr()) != 0:
        raise Error("capture stat failed")
    var out = List[UInt64]()
    for off in [0, 8, 16, 24, 28, 48, 64]:
        var value = UInt64(0)
        var width = 4 if off == 24 or off == 28 else 8
        for i in range(width):
            value |= UInt64(raw[off + i]) << UInt64(i * 8)
        out.append(value)
    return out^


def open_directory(path: String) raises -> Int32:
    var root = cstr("/" if path.startswith("/") else ".")
    var fd = external_call["openat", Int32](Int32(-100), Span(root).unsafe_ptr(), Int32(65536 | 524288), UInt32(0))
    if fd < 0:
        raise Error("cannot open capture parent")
    var parts = path.split(String("/"))
    for part in parts:
        if part == "" or part == ".":
            continue
        var name = cstr(String(part))
        var next_fd = external_call["openat", Int32](fd, Span(name).unsafe_ptr(), Int32(65536 | 131072 | 524288), UInt32(0))
        close_fd(fd)
        if next_fd < 0:
            raise Error("capture directory is inaccessible or a symlink")
        fd = next_fd
    return fd


struct RecoveryFiles(Movable):
    var directory: Int32
    var events: Int32
    var checkpoint: Int32
    var path: String
    var directory_ids: List[UInt64]
    var events_ids: List[UInt64]
    var checkpoint_ids: List[UInt64]

    def __init__(out self):
        self.directory = Int32(-1)
        self.events = Int32(-1)
        self.checkpoint = Int32(-1)
        self.path = String("")
        self.directory_ids = List[UInt64]()
        self.events_ids = List[UInt64]()
        self.checkpoint_ids = List[UInt64]()

    def __deinit__(deinit self):
        close_fd(self.events)
        close_fd(self.checkpoint)
        close_fd(self.directory)

    def open_regular(self, name: String) raises -> Int32:
        var key = cstr(name)
        var fd = external_call["openat", Int32](self.directory, Span(key).unsafe_ptr(), Int32(131072 | 524288 | 2048), UInt32(0))
        if fd < 0:
            raise Error(name + ": cannot open regular capture file")
        try:
            var ids = file_stat(fd)
            if ids[3] & UInt64(0o170000) != UInt64(0o100000) or ids[2] != UInt64(1):
                raise Error(name + ": not a singly linked regular file")
            if ids[4] != UInt64(external_call["geteuid", UInt32]()):
                raise Error(name + ": not owned by reader")
        except e:
            close_fd(fd)
            raise e^
        return fd

    def open(mut self, path: String) raises:
        self.path = path
        self.directory = open_directory(path)
        if external_call["flock", Int32](self.directory, Int32(1 | 4)) != 0:
            raise Error("active writer or unavailable capture lock")
        self.directory_ids = file_stat(self.directory)
        if self.directory_ids[4] != UInt64(external_call["geteuid", UInt32]()):
            raise Error("capture directory not owned by reader")
        self.checkpoint = self.open_regular("checkpoint.json")
        self.events = self.open_regular("events.ndjson")
        self.checkpoint_ids = file_stat(self.checkpoint)
        self.events_ids = file_stat(self.events)
        self.verify()

    def verify(self) raises:
        var current = open_directory(self.path)
        var ids: List[UInt64]
        try:
            ids = file_stat(current)
        except e:
            close_fd(current)
            raise e^
        close_fd(current)
        if ids[0] != self.directory_ids[0] or ids[1] != self.directory_ids[1]:
            raise Error("capture directory replaced during recovery")
        for name in [String("checkpoint.json"), String("events.ndjson")]:
            var fd = self.open_regular(String(name))
            var now: List[UInt64]
            try:
                now = file_stat(fd)
            except e:
                close_fd(fd)
                raise e^
            close_fd(fd)
            var want = self.checkpoint_ids.copy() if name == "checkpoint.json" else self.events_ids.copy()
            if now[0] != want[0] or now[1] != want[1] or now[5] != want[5]:
                raise Error(String(name) + ": replaced or resized during recovery")
        var final_name = cstr("session.json")
        var present = external_call["openat", Int32](self.directory, Span(final_name).unsafe_ptr(), Int32(2097152 | 131072 | 524288), UInt32(0))
        if present >= 0:
            close_fd(present)
            raise Error("final session appeared during recovery; retry finalized capture")
        var errno_ptr = external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()
        if errno_ptr.unsafe_load() != 2:
            raise Error("cannot establish absence of final session")

    def read_checkpoint(self, cap: Int) raises -> List[UInt8]:
        if self.checkpoint_ids[5] > UInt64(cap):
            raise Error("checkpoint.json too large")
        var raw = List[UInt8](length=Int(self.checkpoint_ids[5]), fill=UInt8(0))
        var done = 0
        while done < len(raw):
            var n = external_call["pread", Int64](self.checkpoint, Span(raw).unsafe_ptr().unsafe_offset(done), Int64(len(raw) - done), Int64(done))
            if n <= 0:
                raise Error("checkpoint.json: cannot read")
            done += Int(n)
        return raw^
