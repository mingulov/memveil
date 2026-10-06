"""Passive evidence reader: live host or recorded fixture.

A06: the doctor never loads BPF, never writes the system, and never
executes helpers. All platform evidence comes through this reader, which
either probes the live host (stdlib FFI against libc: uname, geteuid,
access, fread) or replays a recorded fixture tree created by
``tools/probe-inventory --emit-fixture``.

A fixture directory maps host paths to relative ones::

    <fixture>/meta.txt                    key=value inventory header
                                     (arch/release/euid required)
    <fixture>/sys/kernel/tracing/...     evidence trees as found
    <fixture>/sys/kernel/mm/...          SEV nodes, when present
    <fixture>/sys/devices/virtual/...    TDX node, when present
    <fixture>/proc/...                   proc evidence, when held

Live mode (``root == ""``) never consults ``meta.txt`` and never reports
asserted guest tech. Fixture mode requires ``meta.txt``; a fixture
without it is rejected rather than half-read.

Reads are capped; unreadable evidence is distinguished as absent (path
missing) versus denied (permission refused), never silently skipped.
"""

from std.ffi import external_call
from std.memory import Pointer


comptime EVIDENCE_OK = 0
comptime EVIDENCE_ABSENT = 1
comptime EVIDENCE_DENIED = 2

comptime E_META_MISSING = UInt32(1)
comptime E_META_BAD = UInt32(2)
comptime E_ABSENT = UInt32(3)
comptime E_DENIED = UInt32(4)
comptime E_TOO_BIG = UInt32(5)
comptime E_IO = UInt32(6)
comptime E_UNAME = UInt32(7)

comptime _MODE_F_OK = 0
comptime _MODE_R_OK = 4
comptime _ENOENT = 2
comptime _CHUNK_BYTES = 65536
comptime _UTS_FIELDS = 6
comptime _UTS_FIELD_LEN = 65
comptime _UTS_MACHINE_OFF = 260
comptime _UTS_RELEASE_OFF = 130
comptime _MAX_EUID = 2147483647


@fieldwise_init
struct EvidenceError(Copyable, Writable):
    """One evidence failure. Callers match on code, never text."""

    var code: UInt32
    var message: String


@fieldwise_init
struct EvidenceReader(Copyable):
    """One evidence source: live host or one fixture directory.

    ``root`` is ``""`` for the live host, else the fixture directory
    path. ``arch``/``release``/``euid`` come from uname/geteuid live,
    or from ``meta.txt`` in a fixture. ``denied`` holds
    fixture-declared unreadable paths (always empty live).
    ``asserted_guest_tech`` is non-empty only when a fixture author
    recorded an out-of-band guest-tech note using the doctor
    vocabulary (``snp``, ``sev-classic``, ``tdx``); live runs never
    assert.
    """

    var root: String
    var arch: String
    var release: String
    var euid: Int
    var denied: List[String]
    var asserted_guest_tech: String


def _to_cstr_local(text: String) -> List[UInt8]:
    """Copy text into a fresh NUL-terminated byte buffer.

    Small duplicate of the capture reader's helper: the platform
    layer must not reach into capture internals.
    """
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


def _errno_now() -> Int:
    """Read the calling thread's libc errno value."""
    var p = external_call["__errno_location", Pointer[Int32, MutAnyOrigin]]()
    return Int(p.unsafe_load())


def is_valid_utf8(data: List[UInt8]) -> Bool:
    """True when the bytes are strict RFC 3629 UTF-8.

    Rejects overlongs, surrogates, code points past U+10FFFF,
    and truncated sequences. Paths that fail this check are
    never lossy-decoded into a lookup: decoding substitutes
    U+FFFD, which could resolve a different tree than the
    kernel named.
    """
    var i = 0
    var n = len(data)
    while i < n:
        var b0 = data[i]
        if b0 < UInt8(0x80):
            i += 1
            continue
        var need: Int
        var lo = 0x80
        var hi = 0xBF
        if b0 >= UInt8(0xC2) and b0 <= UInt8(0xDF):
            need = 1
        elif b0 >= UInt8(0xE0) and b0 <= UInt8(0xEF):
            need = 2
            if b0 == UInt8(0xE0):
                lo = 0xA0
            if b0 == UInt8(0xED):
                hi = 0x9F
        elif b0 >= UInt8(0xF0) and b0 <= UInt8(0xF4):
            need = 3
            if b0 == UInt8(0xF0):
                lo = 0x90
            if b0 == UInt8(0xF4):
                hi = 0x8F
        else:
            return False
        if i + need >= n:
            return False
        for k in range(1, need + 1):
            var bc = data[i + k]
            if k == 1:
                if Int(bc) < lo or Int(bc) > hi:
                    return False
            elif bc < UInt8(0x80) or bc > UInt8(0xBF):
                return False
        i += need + 1
    return True


def readlink_self() raises EvidenceError -> String:
    """Resolve the running executable via /proc/self/exe.

    Unlike argv[0] this cannot be a bare PATH name or a spoofed
    string: the kernel reports the true binary path. Linux-only,
    matching the supported collection target. Raises E_IO when
    the link cannot be read, overruns the 4 KiB buffer, or is
    not valid UTF-8 (a lossy substitute could resolve a
    different tree than the kernel named).
    """
    var link = _to_cstr_local("/proc/self/exe")
    var buf = List[UInt8]()
    for _ in range(4096):
        buf.append(UInt8(0))
    var n = external_call["readlink", Int64](
        Span(link).unsafe_ptr(), Span(buf).unsafe_ptr(), 4096
    )
    if Int(n) <= 0 or Int(n) >= 4096:
        raise EvidenceError(E_IO, "cannot resolve executable path")
    var raw = List[UInt8]()
    for i in range(Int(n)):
        raw.append(buf[i])
    if not is_valid_utf8(raw):
        raise EvidenceError(E_IO, "executable path not UTF-8")
    return bytes_to_text(raw^)


def _uname_field(buf: List[UInt8], off: Int, what: String) raises EvidenceError -> String:
    """Decode one NUL-terminated utsname field at byte offset off."""
    var end = off
    var stop = off + _UTS_FIELD_LEN
    while end < stop and buf[end] != UInt8(0):
        end += 1
    var raw = List[UInt8]()
    for i in range(off, end):
        raw.append(buf[i])
    if len(raw) == 0:
        raise EvidenceError(E_UNAME, "uname " + what + " empty")
    return bytes_to_text(raw^)


def _uname_machine() raises EvidenceError -> String:
    """Return the live machine field from uname(2), e.g. x86_64."""
    var buf = List[UInt8]()
    for _ in range(_UTS_FIELDS * _UTS_FIELD_LEN):
        buf.append(UInt8(0))
    var r = external_call["uname", Int32](Span(buf).unsafe_ptr())
    if Int(r) != 0:
        raise EvidenceError(E_UNAME, "uname failed")
    return _uname_field(buf^, _UTS_MACHINE_OFF, "machine")


def _uname_release() raises EvidenceError -> String:
    """Return the live release field from uname(2)."""
    var buf = List[UInt8]()
    for _ in range(_UTS_FIELDS * _UTS_FIELD_LEN):
        buf.append(UInt8(0))
    var r = external_call["uname", Int32](Span(buf).unsafe_ptr())
    if Int(r) != 0:
        raise EvidenceError(E_UNAME, "uname failed")
    return _uname_field(buf^, _UTS_RELEASE_OFF, "release")


def _geteuid_live() -> Int:
    """Return the live effective uid."""
    return Int(external_call["geteuid", UInt32]())


def _parse_euid(text: String) raises EvidenceError -> Int:
    """Parse a meta.txt euid: decimal digits, 0..2**31-1."""
    if text.byte_length() == 0:
        raise EvidenceError(E_META_BAD, "meta euid empty")
    var acc = 0
    for b in text.as_bytes():
        if b < UInt8(0x30) or b > UInt8(0x39):
            raise EvidenceError(E_META_BAD, "meta euid not decimal")
        var digit = Int(b) - 0x30
        if acc > (_MAX_EUID - digit) // 10:
            raise EvidenceError(E_META_BAD, "meta euid too large")
        acc = acc * 10 + digit
    return acc


def _is_absolute(path: String) -> Bool:
    """True when the path's first byte is /. Empty is not absolute."""
    for b in path.as_bytes():
        return b == UInt8(0x2F)
    return False


def _parse_denied(text: String) raises EvidenceError -> List[String]:
    """Parse a meta.txt denied list: comma-separated absolute paths."""
    var out = List[String]()
    if text.byte_length() == 0:
        return out^
    var parts = text.split(String(","))
    for i in range(len(parts)):
        var cur = String(parts[i])
        if cur.byte_length() == 0 or not _is_absolute(cur):
            raise EvidenceError(
                E_META_BAD, "meta denied entry not absolute"
            )
        if cur.byte_length() > 256:
            raise EvidenceError(E_META_BAD, "meta denied entry too long")
        out.append(cur)
    return out^


def _parse_meta(text: String) raises EvidenceError -> EvidenceReader:
    """Parse meta.txt into a fixture reader skeleton (root unset).

    Grammar: one ``key=value`` per line, LF-terminated, no comments,
    no blank padding, no duplicate or unknown keys, no ``=`` inside
    values, no NUL byte in any value (libc truncates paths at NUL,
    so a NUL would smuggle a different path past validation).
    Known keys: ``arch``, ``release``, ``euid``, ``denied``,
    ``asserted_guest_tech``. ``arch``, ``release``, and ``euid`` are
    required; the others default to empty. Length bounds keep every
    derived report field inside the doctor schema: ``arch`` 1..32
    bytes, ``release`` 1..128 bytes, each ``denied`` entry 1..256
    bytes.
    """
    var arch = String("")
    var release = String("")
    var euid_text = String("")
    var denied_text = String("")
    var asserted = String("")
    var seen_arch = False
    var seen_release = False
    var seen_euid = False
    var seen_denied = False
    var seen_asserted = False
    var lines = text.split(String("\n"))
    for i in range(len(lines)):
        var line = String(lines[i])
        var last = i == len(lines) - 1
        if last and line.byte_length() == 0:
            break
        if line.byte_length() == 0:
            raise EvidenceError(E_META_BAD, "meta blank line")
        var kv = line.split(String("="))
        if len(kv) != 2:
            raise EvidenceError(E_META_BAD, "meta line without one =")
        var key = String(kv[0])
        var val = String(kv[1])
        for b in val.as_bytes():
            if b == UInt8(0):
                raise EvidenceError(E_META_BAD, "meta NUL byte")
        if key == "arch":
            if seen_arch:
                raise EvidenceError(E_META_BAD, "meta duplicate arch")
            seen_arch = True
            arch = val
        elif key == "release":
            if seen_release:
                raise EvidenceError(E_META_BAD, "meta duplicate release")
            seen_release = True
            release = val
        elif key == "euid":
            if seen_euid:
                raise EvidenceError(E_META_BAD, "meta duplicate euid")
            seen_euid = True
            euid_text = val
        elif key == "denied":
            if seen_denied:
                raise EvidenceError(E_META_BAD, "meta duplicate denied")
            seen_denied = True
            denied_text = val
        elif key == "asserted_guest_tech":
            if seen_asserted:
                raise EvidenceError(
                    E_META_BAD, "meta duplicate asserted_guest_tech"
                )
            seen_asserted = True
            asserted = val
        else:
            raise EvidenceError(E_META_BAD, "meta unknown key")
    if not seen_arch or not seen_release or not seen_euid:
        raise EvidenceError(
            E_META_BAD, "meta missing arch, release, or euid"
        )
    if arch.byte_length() == 0:
        raise EvidenceError(E_META_BAD, "meta arch empty")
    if arch.byte_length() > 32:
        raise EvidenceError(E_META_BAD, "meta arch too long")
    if release.byte_length() == 0:
        raise EvidenceError(E_META_BAD, "meta release empty")
    if release.byte_length() > 128:
        raise EvidenceError(E_META_BAD, "meta release too long")
    if (
        asserted.byte_length() != 0
        and asserted != "snp"
        and asserted != "sev-classic"
        and asserted != "tdx"
    ):
        raise EvidenceError(E_META_BAD, "meta unknown guest tech")
    var euid = _parse_euid(euid_text)
    var denied = _parse_denied(denied_text)
    return EvidenceReader(
        String(""), arch, release, euid, denied^, asserted
    )


def _read_bounded_local(path: String, what: String, cap: Int) raises EvidenceError -> List[UInt8]:
    """Read a small evidence file without over-allocating past cap.

    Same chunked pattern as the capture reader: a fixed 64 KiB
    buffer streams through, and the running total is checked before
    each chunk lands, so an oversized file is rejected after one
    chunk over the bound instead of being read fully.
    """
    var cpath = _to_cstr_local(path)
    var mode = _to_cstr_local("rb")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == 0:
        raise EvidenceError(E_IO, what + ": cannot open")
    var chunk = List[UInt8]()
    for _ in range(_CHUNK_BYTES):
        chunk.append(UInt8(0))
    var out = List[UInt8]()
    while True:
        var got = external_call["fread", Int64](
            Span(chunk).unsafe_ptr(), 1, _CHUNK_BYTES, fp
        )
        if got == 0:
            var ferr = external_call["ferror", Int32](fp)
            _ = external_call["fclose", Int32](fp)
            if ferr != 0:
                raise EvidenceError(E_IO, what + ": cannot read")
            return out^
        var n = Int(got)
        if len(out) + n > cap:
            _ = external_call["fclose", Int32](fp)
            raise EvidenceError(E_TOO_BIG, what + " too large")
        for i in range(n):
            out.append(chunk[i])


def open_evidence_reader(root: String) raises EvidenceError -> EvidenceReader:
    """Open the live host (root == "") or one fixture directory.

    Fixture mode requires ``<root>/meta.txt`` and rejects the
    fixture when it is missing or malformed.
    """
    if root == "":
        return EvidenceReader(
            String(""), _uname_machine(), _uname_release(),
            _geteuid_live(), List[String](), String("")
        )
    var meta_path = root + "/meta.txt"
    var raw: List[UInt8]
    try:
        raw = _read_bounded_local(meta_path, "meta.txt", _CHUNK_BYTES)
    except e:
        raise EvidenceError(E_META_MISSING, String(e))
    if not is_valid_utf8(raw):
        raise EvidenceError(E_META_BAD, "meta not UTF-8")
    var text = bytes_to_text(raw^)
    var reader = _parse_meta(text)
    reader.root = root
    return reader^


def evidence_path(reader: EvidenceReader, path: String) -> String:
    """Map a host-absolute evidence path into the reader's root."""
    if reader.root == "":
        return path
    return reader.root + path


def is_denied(reader: EvidenceReader, path: String) -> Bool:
    """True when a fixture declares path unreadable. Always False live."""
    for i in range(len(reader.denied)):
        if reader.denied[i] == path:
            return True
    return False


def file_state(reader: EvidenceReader, path: String) -> Int:
    """Classify one evidence path: OK, ABSENT, or DENIED.

    Fixture-declared denied paths report DENIED even when the
    fixture holds their content, so a fixture can model a live
    refusal. Otherwise access() decides, with errno telling
    absence from refusal: only ENOENT is ABSENT. Any other
    failure (EACCES on the path or a parent, ELOOP, exotic
    errors) is DENIED, since absence is unproven. Present and
    readable is OK.
    """
    if is_denied(reader, path):
        return EVIDENCE_DENIED
    var mapped = evidence_path(reader, path)
    var cpath = _to_cstr_local(mapped)
    var r = external_call["access", Int32](
        Span(cpath).unsafe_ptr(), _MODE_F_OK
    )
    if Int(r) == 0:
        var cpath2 = _to_cstr_local(mapped)
        var r2 = external_call["access", Int32](
            Span(cpath2).unsafe_ptr(), _MODE_R_OK
        )
        if Int(r2) == 0:
            return EVIDENCE_OK
        return EVIDENCE_DENIED
    if _errno_now() == _ENOENT:
        return EVIDENCE_ABSENT
    return EVIDENCE_DENIED


def read_evidence(
    reader: EvidenceReader, path: String, cap: Int
) raises EvidenceError -> List[UInt8]:
    """Read one evidence file, capped at cap bytes.

    Raises E_ABSENT when the path is missing, E_DENIED when it is
    unreadable, E_TOO_BIG past the cap, E_IO on open/read failure.
    Bytes are returned raw; text decoding is the caller's choice.
    """
    var st = file_state(reader, path)
    if st == EVIDENCE_ABSENT:
        raise EvidenceError(E_ABSENT, path + ": absent")
    if st == EVIDENCE_DENIED:
        raise EvidenceError(E_DENIED, path + ": denied")
    return _read_bounded_local(evidence_path(reader, path), path, cap)


def read_host_file(path: String, what: String, cap: Int) raises EvidenceError -> List[UInt8]:
    """Read one small host file (profile, manifest), capped at cap bytes.

    Unlike ``read_evidence`` this never maps a fixture root: profile
    and manifest paths are taken literally. Raises E_IO on open/read
    failure and E_TOO_BIG past the cap.
    """
    return _read_bounded_local(path, what, cap)


def bytes_to_text(data: List[UInt8]) -> String:
    """Decode evidence bytes as UTF-8, replacing invalid sequences.

    Evidence text (cpuinfo, release files, meta) is kernel or
    distro ASCII in practice; lossy decoding keeps the doctor total
    over hostile fixtures. Byte-exact comparisons (tracepoint
    format signatures) never pass through here.
    """
    return String(from_utf8_lossy=Span(data))
