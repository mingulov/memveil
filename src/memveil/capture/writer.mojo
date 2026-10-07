# SPDX-License-Identifier: GPL-3.0-or-later

"""Capture file writer: exclusive creation, explicit-offset appends.

mkdir-0700 output,
O_EXCL events file, pwrite-throughout appends with a size
gate, ftruncate recovery, snapshot rollback groups, and a
fsync/renameat2-NOREPLACE/dir-fsync publication protocol.

The writer reports mechanism outcomes (WriteError kinds and
FinalOutcome); the collector maps them to dispositions,
result_state, and exits. Disposition buckets live in the
collector, never here.
"""

from std.ffi import external_call


comptime MIN_EVENTS_BUDGET = 131072
comptime MAX_EVENTS_BUDGET = 4294967296
comptime CLOSING_RESERVE = 65536

comptime _O_WRONLY = 1
comptime _O_CREAT = 64
comptime _O_EXCL = 128
comptime _O_DIRECTORY = 65536
comptime _O_NOFOLLOW = 131072
comptime _O_PATH = 2097152
comptime _AT_FDCWD = -100
comptime _AT_REMOVEDIR = 512
comptime _RENAME_NOREPLACE = 1
comptime _STAT_SIZE = 144

comptime _EINTR = 4
comptime _ENOENT = 2
comptime _EEXIST = 17


@fieldwise_init
struct WriteError(Copyable, Writable):
    """One writer failure: kind routes the collector decision.

    Kinds: exists (output present), budget (range), io
    (create/stat failure), refused (size gate, no write
    attempted), append_failed (attempted append failed;
    prefix recovered), fatal (unrecoverable mid-append),
    misuse (use after finalize/close).
    """

    var kind: String
    var message: String


@fieldwise_init
struct FinalOutcome(Copyable, Writable):
    """One publication result.

    Status: finalized (session published + synced),
    present_unsynced (rename ok, dir or parent fsync
    failed), unfinalized (no session.json).
    """

    var status: String
    var message: String


def _errno_now() -> Int:
    var p = external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()
    return Int(p.unsafe_load())


def _cstr(text: String) raises WriteError -> List[UInt8]:
    var out = List[UInt8]()
    var raw = text.as_bytes()
    for i in range(len(raw)):
        if raw[i] == UInt8(0):
            raise WriteError("io", "NUL byte in path")
        out.append(raw[i])
    out.append(UInt8(0))
    return out^


def _le64(buf: List[UInt8], off: Int) -> UInt64:
    var v = UInt64(0)
    for i in range(8):
        v |= UInt64(buf[off + i]) << UInt64(8 * i)
    return v


def _fstat_ids(fd: Int32) raises WriteError -> List[UInt64]:
    """Return [st_dev, st_ino, st_nlink] for an open fd (x86-64)."""
    var buf = List[UInt8]()
    for _ in range(_STAT_SIZE):
        buf.append(UInt8(0))
    var r = external_call["fstat", Int32](
        fd, Span(buf).unsafe_ptr()
    )
    if Int(r) != 0:
        raise WriteError(
            "io", "fstat failed: errno " + String(_errno_now())
        )
    var ids = List[UInt64]()
    ids.append(_le64(buf, 0))
    ids.append(_le64(buf, 8))
    ids.append(_le64(buf, 16))
    return ids^


def _close_quiet(fd: Int32):
    if fd >= Int32(0):
        _ = external_call["close", Int32](fd)


def _name_matches(
    dir_fd: Int32, name: String, want: List[UInt64]
) -> Bool:
    """True when name under dir_fd resolves to want.

    O_PATH|O_NOFOLLOW probe plus dev/ino compare; False
    on any failure (missing, replaced, symlink, bad fd).
    """
    try:
        var cname = _cstr(name)
        var probe = external_call["openat", Int32](
            dir_fd,
            Span(cname).unsafe_ptr(),
            Int32(_O_PATH | _O_NOFOLLOW),
            UInt32(0),
        )
        if probe < Int32(0):
            return False
        var ids = _fstat_ids(probe)
        _close_quiet(probe)
        return ids[0] == want[0] and ids[1] == want[1]
    except:
        return False


def _name_exists(dir_fd: Int32, name: String) -> Bool:
    """True when name under dir_fd opens (no symlink follow)."""
    try:
        var cname = _cstr(name)
        var probe = external_call["openat", Int32](
            dir_fd,
            Span(cname).unsafe_ptr(),
            Int32(_O_PATH | _O_NOFOLLOW),
            UInt32(0),
        )
        if probe < Int32(0):
            return False
        _close_quiet(probe)
        return True
    except:
        return False


def _split_parent(path: String) raises WriteError -> List[String]:
    """Split an output path into [parent, base] (no libc)."""
    var raw = path.as_bytes()
    var end = len(raw)
    while end > 1 and raw[end - 1] == UInt8(0x2F):
        end -= 1
    var cut = -1
    var i = end - 1
    while i >= 0:
        if raw[i] == UInt8(0x2F):
            cut = i
            break
        i -= 1
    var parent = List[UInt8]()
    var base = List[UInt8]()
    if cut < 0:
        for b in String(".").as_bytes():
            parent.append(b)
        for j in range(end):
            base.append(raw[j])
    elif cut == 0:
        for b in String("/").as_bytes():
            parent.append(b)
        for j in range(1, end):
            base.append(raw[j])
    else:
        for j in range(cut):
            parent.append(raw[j])
        for j in range(cut + 1, end):
            base.append(raw[j])
    var out = List[String]()
    try:
        out.append(String(from_utf8=Span(parent)))
        out.append(String(from_utf8=Span(base)))
    except:
        raise WriteError("io", "output path not UTF-8")
    return out^


struct EventWriter(Movable):
    """One capture's events file, from mkdir through finalize.

    All-or-nothing creation: a failed __init__ leaves no
    residuals (only owned artifacts are removed). Use
    abandon() for pre-readiness collector rollback.
    """

    var _dir_path: String
    var _parent_path: String
    var _base_name: String
    var _parent_fd: Int32
    var _dir_fd: Int32
    var _ev_fd: Int32
    var _dir_ids: List[UInt64]
    var _ev_ids: List[UInt64]
    var _committed: Int
    var _max: Int
    var _finalized: Bool
    var _closed: Bool

    def __init__(
        out self, dir_path: String, max_events_bytes: Int
    ) raises WriteError:
        if (
            max_events_bytes < MIN_EVENTS_BUDGET
            or max_events_bytes > MAX_EVENTS_BUDGET
        ):
            raise WriteError(
                "budget",
                "events budget "
                + String(max_events_bytes)
                + " outside 128 KiB..4 GiB",
            )
        var parts = _split_parent(dir_path)
        var parent_path = parts[0]
        var base_name = parts[1]
        var parent_cstr = _cstr(parent_path)
        var parent_fd = external_call["openat", Int32](
            Int32(_AT_FDCWD),
            Span(parent_cstr).unsafe_ptr(),
            Int32(_O_DIRECTORY | _O_NOFOLLOW),
            UInt32(0),
        )
        if parent_fd < Int32(0):
            raise WriteError(
                "io",
                "parent open failed: errno " + String(_errno_now()),
            )
        var base_cstr = _cstr(base_name)
        # NOTE: mode as Int (not UInt32) to match the stdlib's own C
        # "mkdirat" declaration exactly; a differing signature fails
        # lowering with "existing function with conflicting signature".
        var made = external_call["mkdirat", Int32](
            parent_fd, Span(base_cstr).unsafe_ptr(), 0o700
        )
        if Int(made) != 0:
            var no = _errno_now()
            _close_quiet(parent_fd)
            if no == _EEXIST:
                raise WriteError("exists", "output exists")
            raise WriteError(
                "io",
                "mkdir failed: errno " + String(no),
            )
        var dir_fd = external_call["openat", Int32](
            parent_fd,
            Span(base_cstr).unsafe_ptr(),
            Int32(_O_DIRECTORY | _O_NOFOLLOW),
            UInt32(0),
        )
        if dir_fd < Int32(0):
            var no = _errno_now()
            _ = external_call["unlinkat", Int32](
                parent_fd,
                Span(base_cstr).unsafe_ptr(),
                Int32(_AT_REMOVEDIR),
            )
            _close_quiet(parent_fd)
            raise WriteError("io", "dir open failed: errno " + String(no))
        var ev_name = _cstr("events.ndjson")
        var ev_fd = external_call["openat", Int32](
            dir_fd,
            Span(ev_name).unsafe_ptr(),
            Int32(_O_WRONLY | _O_CREAT | _O_EXCL | _O_NOFOLLOW),
            UInt32(0o600),
        )
        if ev_fd < Int32(0):
            var no = _errno_now()
            _close_quiet(dir_fd)
            _ = external_call["unlinkat", Int32](
                parent_fd,
                Span(base_cstr).unsafe_ptr(),
                Int32(_AT_REMOVEDIR),
            )
            _close_quiet(parent_fd)
            raise WriteError(
                "io", "events create failed: errno " + String(no)
            )
        var dir_ids: List[UInt64]
        var ev_ids: List[UInt64]
        try:
            dir_ids = _fstat_ids(dir_fd)
            ev_ids = _fstat_ids(ev_fd)
        except e:
            # Construction never published: unwind the owned
            # events file and dir before closing, so a pin
            # failure leaves no orphaned artifacts. No pins
            # exist yet to compare against, so the window is
            # the microseconds since O_EXCL creation. Unwind
            # failures ride along in the raised error: no
            # writer exists to carry residuals.
            var stuck = String("")
            try:
                var ev_name = _cstr("events.ndjson")
                var r = external_call["unlinkat", Int32](
                    dir_fd,
                    Span(ev_name).unsafe_ptr(),
                    Int32(0),
                )
                if Int(r) != 0 and _errno_now() != _ENOENT:
                    stuck = String("events")
            except:
                stuck = String("events")
            try:
                var r = external_call["unlinkat", Int32](
                    parent_fd,
                    Span(base_cstr).unsafe_ptr(),
                    Int32(_AT_REMOVEDIR),
                )
                if Int(r) != 0 and _errno_now() != _ENOENT:
                    if stuck != String(""):
                        stuck = stuck + String(",")
                    stuck = stuck + String("dir")
            except:
                if stuck != String(""):
                    stuck = stuck + String(",")
                stuck = stuck + String("dir")
            _close_quiet(ev_fd)
            _close_quiet(dir_fd)
            _close_quiet(parent_fd)
            if stuck != String(""):
                raise WriteError(
                    e.kind.copy(),
                    e.message.copy()
                    + String("; residuals: ")
                    + stuck,
                )
            raise e^
        self._dir_path = dir_path.copy()
        self._parent_path = parent_path.copy()
        self._base_name = base_name.copy()
        self._parent_fd = parent_fd
        self._dir_fd = dir_fd
        self._ev_fd = ev_fd
        self._dir_ids = dir_ids^
        self._ev_ids = ev_ids^
        self._committed = 0
        self._max = max_events_bytes
        self._finalized = False
        self._closed = False

    def __deinit__(deinit self):
        _close_quiet(self._ev_fd)
        _close_quiet(self._dir_fd)
        _close_quiet(self._parent_fd)

    def committed_len(self) -> Int:
        return self._committed

    def _check_open(self) raises WriteError:
        if self._closed or self._finalized:
            raise WriteError("misuse", "writer not open")

    def append(mut self, line: List[UInt8]) raises WriteError:
        """Append one attempt line or raise.

        refused: attempt gate (nothing written). append_failed:
        attempted write failed, prefix recovered via
        ftruncate (zero-byte failures need no truncate).
        fatal: recovery itself failed.
        """
        self._check_open()
        if self._committed + len(line) > self._max - CLOSING_RESERVE:
            raise WriteError(
                "refused",
                "size gate: "
                + String(self._committed + len(line))
                + " over attempt budget",
            )
        self._write_line(line)

    def append_closing(mut self, line: List[UInt8]) raises WriteError:
        """Append one closing line (snapshot/gap) or raise.

        Closing lines use the 64 KiB reserve: gated at the
        full budget, not the attempt gate. A refusal here
        means the reserve itself is exhausted (closing
        records are bounded small, so this needs a
        pathological budget or prefix, never normal flow).
        """
        self._check_open()
        if self._committed + len(line) > self._max:
            raise WriteError(
                "refused",
                "size gate: "
                + String(self._committed + len(line))
                + " over closing budget",
            )
        self._write_line(line)

    def _write_line(mut self, line: List[UInt8]) raises WriteError:
        var done = 0
        var total = len(line)
        var failed = False
        var no = 0
        while done < total:
            var base = Span(line).unsafe_ptr()
            var n = external_call["pwrite", Int64](
                self._ev_fd,
                base.unsafe_offset(done),
                Int64(total - done),
                Int64(self._committed + done),
            )
            if Int(n) < 0:
                no = _errno_now()
                if no == _EINTR:
                    continue
                failed = True
                break
            if Int(n) == 0:
                no = 0
                failed = True
                break
            done += Int(n)
        if not failed:
            self._committed += total
            return
        if done == 0:
            raise WriteError(
                "append_failed",
                "zero-byte append failed: errno " + String(no),
            )
        var trunc = external_call["ftruncate", Int32](
            self._ev_fd, Int64(self._committed)
        )
        if Int(trunc) != 0:
            # Unrecoverable: the file holds bytes past
            # _committed that no offset can resync. Close so
            # no session can ever publish this prefix.
            self._close_all()
            raise WriteError(
                "fatal",
                "torn append unrecoverable: errno " + String(_errno_now()),
            )
        raise WriteError(
            "append_failed",
            "torn append recovered: errno " + String(no),
        )

    def group_begin(mut self) raises WriteError -> Int:
        """Mark the pre-group offset for rollback."""
        self._check_open()
        return self._committed

    def group_abort(mut self, mark: Int) raises WriteError:
        """Roll back to a group mark, erasing partial lines.

        Rollback failure closes the writer: the caller
        asked for atomicity and did not get it, so no
        session may publish this prefix (unfinalizable).
        """
        self._check_open()
        if mark < 0 or mark > self._committed:
            raise WriteError("misuse", "bad group mark")
        var trunc = external_call["ftruncate", Int32](
            self._ev_fd, Int64(mark)
        )
        if Int(trunc) != 0:
            self._close_all()
            raise WriteError(
                "fatal",
                "group rollback failed: errno " + String(_errno_now()),
            )
        self._committed = mark

    def _identity_ok(mut self) -> Bool:
        """Re-verify both fds still name the created files.

        dev/ino pins catch replacement; nlink pins catch
        mid-run unlinking (events file unlinked, or dir
        emptied and removed): either refuses publication.
        """
        try:
            var dir_ids = _fstat_ids(self._dir_fd)
            var ev_ids = _fstat_ids(self._ev_fd)
            return (
                dir_ids[0] == self._dir_ids[0]
                and dir_ids[1] == self._dir_ids[1]
                and dir_ids[2] == self._dir_ids[2]
                and ev_ids[0] == self._ev_ids[0]
                and ev_ids[1] == self._ev_ids[1]
                and ev_ids[2] == self._ev_ids[2]
            )
        except:
            return False

    def _namespace_ok(mut self) -> String:
        """Compare the live namespace against held descriptors.

        Returns "" when the basename lookup through the
        held parent fd resolves to the held dir AND the
        events.ndjson lookup through the held dir fd
        resolves to the held events file (both without
        following symlinks); else a mismatch note. Catches
        rename-and-replace, which preserves the held fds'
        dev/ino/nlink. Proves integrity AT CHECK TIME
        against a quiescent mutator only.
        """
        try:
            var base = _cstr(self._base_name)
            var dir_probe = external_call["openat", Int32](
                self._parent_fd,
                Span(base).unsafe_ptr(),
                Int32(_O_PATH | _O_NOFOLLOW | _O_DIRECTORY),
                UInt32(0),
            )
            if dir_probe < Int32(0):
                return String("namespace: output dir lookup failed")
            var dir_ids = _fstat_ids(dir_probe)
            _close_quiet(dir_probe)
            if (
                dir_ids[0] != self._dir_ids[0]
                or dir_ids[1] != self._dir_ids[1]
            ):
                return String("namespace: output dir replaced")
            var ev_name = _cstr("events.ndjson")
            var ev_probe = external_call["openat", Int32](
                self._dir_fd,
                Span(ev_name).unsafe_ptr(),
                Int32(_O_PATH | _O_NOFOLLOW),
                UInt32(0),
            )
            if ev_probe < Int32(0):
                return String("namespace: events file lookup failed")
            var ev_ids = _fstat_ids(ev_probe)
            _close_quiet(ev_probe)
            if (
                ev_ids[0] != self._ev_ids[0]
                or ev_ids[1] != self._ev_ids[1]
            ):
                return String("namespace: events file replaced")
            return String("")
        except:
            return String("namespace: check failed")

    def _remove_tmp_if_owned(
        mut self, name: String, want: List[UInt64]
    ) -> Bool:
        """Unlink a tmp name only if it still resolves to want.

        Returns True when the name is gone (unlinked or
        already absent), False when a replacement was
        preserved. Never raises.
        """
        if not _name_matches(self._dir_fd, name, want):
            return False
        try:
            var cname = _cstr(name)
            var r = external_call["unlinkat", Int32](
                self._dir_fd, Span(cname).unsafe_ptr(), Int32(0)
            )
            return Int(r) == 0 or _errno_now() == _ENOENT
        except:
            return False

    def _write_tmp(
        mut self, name: String, data: List[UInt8]
    ) raises WriteError -> Int32:
        """Create + fill + fsync a tmp file; errno read before cleanup.

        Own-failure cleanup: write/sync failures remove the
        just-created tmp only when the name still resolves
        to it (dev/ino); replacements are preserved and
        reported in the raised error. Create failures never
        unlink: a pre-existing name is foreign.
        """
        var cname = _cstr(name)
        var fd = external_call["openat", Int32](
            self._dir_fd,
            Span(cname).unsafe_ptr(),
            Int32(_O_WRONLY | _O_CREAT | _O_EXCL | _O_NOFOLLOW),
            UInt32(0o600),
        )
        if fd < Int32(0):
            raise WriteError(
                "io",
                "tmp create failed: errno " + String(_errno_now()),
            )
        var ids: List[UInt64]
        try:
            ids = _fstat_ids(fd)
        except:
            _close_quiet(fd)
            raise WriteError(
                "io", "tmp pin failed; tmp left in place"
            )
        var done = 0
        var total = len(data)
        while done < total:
            var base = Span(data).unsafe_ptr()
            var n = external_call["pwrite", Int64](
                fd, base.unsafe_offset(done),
                Int64(total - done), Int64(done),
            )
            if Int(n) < 0:
                var no = _errno_now()
                if no == _EINTR:
                    continue
                var gone = self._remove_tmp_if_owned(name, ids)
                _close_quiet(fd)
                var msg = (
                    String("tmp write failed: errno ") + String(no)
                )
                if not gone:
                    msg = (
                        msg
                        + String("; tmp replacement left in place")
                    )
                raise WriteError("io", msg)
            if Int(n) == 0:
                var gone = self._remove_tmp_if_owned(name, ids)
                _close_quiet(fd)
                var msg = String("tmp write stalled")
                if not gone:
                    msg = (
                        msg
                        + String("; tmp replacement left in place")
                    )
                raise WriteError("io", msg)
            done += Int(n)
        if Int(external_call["fsync", Int32](fd)) != 0:
            var no = _errno_now()
            var gone = self._remove_tmp_if_owned(name, ids)
            _close_quiet(fd)
            var msg = (
                String("tmp fsync failed: errno ") + String(no)
            )
            if not gone:
                msg = msg + String("; tmp replacement left in place")
            raise WriteError("io", msg)
        return fd

    def finalize(mut self, session: List[UInt8]) raises WriteError -> FinalOutcome:
        """Publish session.json; single-shot, closes the writer."""
        self._check_open()
        self._finalized = True
        if not self._identity_ok():
            self._close_all()
            return FinalOutcome(
                "unfinalized", "identity changed or unlinked"
            )
        var ns_note = self._namespace_ok()
        if ns_note != String(""):
            self._close_all()
            return FinalOutcome("unfinalized", ns_note)
        if Int(external_call["fsync", Int32](self._ev_fd)) != 0:
            var no = _errno_now()
            self._close_all()
            return FinalOutcome(
                "unfinalized", "events fsync: errno " + String(no)
            )
        var tmp: Int32
        try:
            tmp = self._write_tmp("session.json.tmp", session)
        except e:
            # _write_tmp cleans its own tmp on write/sync
            # failures and never unlinks on create failure
            # (a pre-existing name is foreign).
            self._close_all()
            return FinalOutcome("unfinalized", e.message)
        var tmp_ids = List[UInt64]()
        var have_pin = True
        try:
            tmp_ids = _fstat_ids(tmp)
        except:
            have_pin = False
        _close_quiet(tmp)
        var old_name = _cstr("session.json.tmp")
        var new_name = _cstr("session.json")
        var rn = external_call["renameat2", Int32](
            self._dir_fd,
            Span(old_name).unsafe_ptr(),
            self._dir_fd,
            Span(new_name).unsafe_ptr(),
            UInt32(_RENAME_NOREPLACE),
        )
        if Int(rn) != 0:
            var no = _errno_now()
            var msg = (
                String("rename failed: errno ") + String(no)
            )
            if have_pin:
                if not self._remove_tmp_if_owned(
                    String("session.json.tmp"), tmp_ids
                ):
                    msg = (
                        msg
                        + String("; tmp replacement left in place")
                    )
            else:
                msg = msg + String("; tmp left in place (unpinned)")
            self._close_all()
            return FinalOutcome("unfinalized", msg)
        if Int(external_call["fsync", Int32](self._dir_fd)) != 0:
            var no = _errno_now()
            self._close_all()
            return FinalOutcome(
                "present_unsynced", "dir fsync: errno " + String(no)
            )
        if Int(external_call["fsync", Int32](self._parent_fd)) != 0:
            var no = _errno_now()
            self._close_all()
            return FinalOutcome(
                "present_unsynced",
                "parent fsync: "
                + self._parent_path
                + ": errno "
                + String(no),
            )
        self._close_all()
        return FinalOutcome("finalized", "")

    def _close_all(mut self):
        _close_quiet(self._ev_fd)
        _close_quiet(self._dir_fd)
        _close_quiet(self._parent_fd)
        self._ev_fd = Int32(-1)
        self._dir_fd = Int32(-1)
        self._parent_fd = Int32(-1)
        self._closed = True

    def discard(mut self):
        """Close without publishing: events kept for forensics.

        Best-effort fsyncs the events file, then closes.
        No session.json is written. Idempotent.
        """
        if not self._closed:
            _ = external_call["fsync", Int32](self._ev_fd)
        self._close_all()

    def abandon(mut self) -> String:
        """Pre-readiness rollback: remove owned files, close up.

        Identity-gated: a name is removed only when it
        still resolves to the created file or dir (dev/ino
        via O_PATH|O_NOFOLLOW probes). Replacements and
        foreign files are preserved and reported. The tmp
        name is never removed here: finalize creates it and
        cleans its own tmp on every path, so any tmp seen
        at rollback is foreign. Returns "" when nothing is
        left behind, else a residual diagnostic. Never
        touches pre-existing paths: only the created dir
        and its events file.
        """
        if not _name_matches(
            self._parent_fd, self._base_name, self._dir_ids
        ):
            self._close_all()
            return String(
                "output dir replaced or missing; left in place"
            )
        var leftovers = String("")
        if _name_matches(
            self._dir_fd, String("events.ndjson"), self._ev_ids
        ):
            try:
                var ev_name = _cstr("events.ndjson")
                _ = external_call["unlinkat", Int32](
                    self._dir_fd,
                    Span(ev_name).unsafe_ptr(),
                    Int32(0),
                )
            except:
                pass
        else:
            leftovers = String(
                "events file replaced or missing; left in place"
            )
        if _name_exists(self._dir_fd, String("session.json.tmp")):
            if leftovers != String(""):
                leftovers = leftovers + String("; ")
            leftovers = (
                leftovers
                + String("foreign session.json.tmp left in place")
            )
        try:
            var base = _cstr(self._base_name)
            var r = external_call["unlinkat", Int32](
                self._parent_fd,
                Span(base).unsafe_ptr(),
                Int32(_AT_REMOVEDIR),
            )
            if Int(r) != 0 and _errno_now() != _ENOENT:
                if leftovers != String(""):
                    leftovers = leftovers + String("; ")
                leftovers = (
                    leftovers
                    + String("rmdir ")
                    + self._dir_path
                    + String(" failed")
                )
        except:
            if leftovers != String(""):
                leftovers = leftovers + String("; ")
            leftovers = (
                leftovers
                + String("rmdir ")
                + self._dir_path
                + String(" failed")
            )
        self._close_all()
        return leftovers^
