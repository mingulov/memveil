# SPDX-License-Identifier: GPL-3.0-or-later

"""Streaming bounded capture reader: session.json plus events.ndjson.

A capture directory holds session.json and events.ndjson. The reader
enforces byte limits while parsing: the session document is read whole
(16 MiB bound), while events stream through libc in 64 KiB chunks, so
resident memory stays O(chunk + longest line) no matter how large the
file is. Line splitting and both byte bounds match the schema
validator's line iterator exactly: a line's content plus its newline
terminator must fit max_line_bytes, and total consumed bytes
(including terminators) must fit max_events_bytes.

Lines parse lazily in order; every event must match the session ID,
carry a strictly increasing sequence number, and land inside the
half-open session window.

Only an explicit allow_partial recovers a truncated tail, and only
for the final record when the file lacks a trailing newline: a tail
that is a clean truncation (the classifier says incomplete) is
dropped, reported via partial, and never silently repaired. A final
record that parses but lacks its trailing newline is a framing error
in both modes, and so is an unterminated tail that is corrupt rather
than truncated. Interior corruption is always an error, as is a
terminated final line that fails to parse.

A bare carriage return before a newline is tolerated because it is
JSON whitespace; anything else strict fails.

The open FILE* closes when the stream exhausts, when the tail is
recovered, or when the reader is destroyed, so every path — including
error paths — releases the descriptor.
"""

from std.ffi import external_call
from std.pathlib import Path

from memveil.jsonscan import TAIL_INCOMPLETE, classify_tail
from memveil.model.event import Event, parse_event, partial_record_definitive
from memveil.model.session import Session, parse_session
from memveil.model.validate import checked_add

comptime READ_IO = UInt32(1)
comptime READ_TOO_BIG = UInt32(2)
comptime READ_PARSE = UInt32(3)
comptime READ_INVALID = UInt32(4)

comptime DEFAULT_MAX_SESSION_BYTES = 16777216
comptime DEFAULT_MAX_LINE_BYTES = 65536
comptime DEFAULT_MAX_EVENTS_BYTES = 268435456

comptime _CHUNK_BYTES = 65536

comptime _MAX_TRACKED_IDS = 4194304


@fieldwise_init
struct ReadError(Copyable, Writable):
    """One capture-read failure. Callers match on code, never text."""

    var code: UInt32
    var line_no: Int
    var message: String


@fieldwise_init
struct ReaderLimits(Copyable):
    """Byte limits for one read_capture call."""

    var max_session_bytes: Int
    var max_line_bytes: Int
    var max_events_bytes: Int


def default_limits() -> ReaderLimits:
    """Return the default reader limits."""
    return ReaderLimits(
        DEFAULT_MAX_SESSION_BYTES,
        DEFAULT_MAX_LINE_BYTES,
        DEFAULT_MAX_EVENTS_BYTES,
    )


def _to_cstr(text: String) -> List[UInt8]:
    """Copy text into a fresh NUL-terminated byte buffer."""
    var out = List[UInt8]()
    for b in text.as_bytes():
        out.append(b)
    out.append(UInt8(0))
    return out^


struct CaptureReader:
    """One open capture: validated session plus lazy event stream."""

    var session: Session
    var partial: Bool
    var _fp: UInt64
    var _chunk: List[UInt8]
    var _pos: Int
    var _end: Int
    var _pending: List[UInt8]
    var _total: Int
    var _lineno: Int
    var _staged: Bool
    var _staged_final: Bool
    var _exhausted: Bool
    var _stream_eof: Bool
    var _allow_partial: Bool
    var _limits: ReaderLimits
    var _has_prev: Bool
    var _prev_seq: UInt64
    var _devices: Dict[String, Bool]
    var _ops: Dict[String, Bool]
    var _maps: Dict[String, Bool]
    var _dead: Dict[String, Bool]
    var _ref_ids: List[String]
    var _ref_lines: List[Int]
    var _req_total: UInt64
    var _req_dev: Dict[String, UInt64]

    def __init__(out self):
        self.session = Session()
        self.partial = False
        self._fp = UInt64(0)
        self._chunk = List[UInt8]()
        self._pos = 0
        self._end = 0
        self._pending = List[UInt8]()
        self._total = 0
        self._lineno = 0
        self._staged = False
        self._staged_final = False
        self._exhausted = False
        self._stream_eof = False
        self._allow_partial = False
        self._limits = default_limits()
        self._has_prev = False
        self._prev_seq = UInt64(0)
        self._devices = Dict[String, Bool]()
        self._ops = Dict[String, Bool]()
        self._maps = Dict[String, Bool]()
        self._dead = Dict[String, Bool]()
        self._ref_ids = List[String]()
        self._ref_lines = List[Int]()
        self._req_total = UInt64(0)
        self._req_dev = Dict[String, UInt64]()

    def __deinit__(deinit self):
        if self._fp != 0:
            _ = external_call["fclose", Int32](self._fp)

    def has_more(mut self) raises ReadError -> Bool:
        """True when another event awaits.

        With allow_partial, a final unterminated record that is a
        clean truncation (the classifier says incomplete) is dropped
        here: partial is set and iteration ends. A final record that
        parses but lacks its trailing newline is a framing error in
        both modes, and an unterminated record that is corrupt rather
        than truncated always raises.
        """
        self._ensure_staged()
        if not self._staged:
            return False
        if self._staged_final:
            return self._probe_tail()
        return True

    def next_event(mut self) raises ReadError -> Event:
        """Parse, check, and return the next event in order."""
        self._ensure_staged()
        if not self._staged:
            raise ReadError(READ_INVALID, 0, "no more events")
        var lineno = self._lineno
        var was_final = self._staged_final
        self._staged = False
        var ev: Event
        try:
            ev = parse_event(self._pending)
        except e:
            raise ReadError(
                READ_PARSE, lineno, "line " + String(lineno) + ": " + String(e)
            )
        self._check(ev, lineno)
        if was_final:
            raise ReadError(
                READ_PARSE,
                lineno,
                "line "
                + String(lineno)
                + ": final record lacks trailing newline",
            )
        self._prev_seq = ev.seq
        self._has_prev = True
        self._pending = List[UInt8]()
        return ev^

    def _probe_tail(mut self) raises ReadError -> Bool:
        """Decide the final unterminated line: recover, or raise.

        Recovery is only for clean truncation: an incomplete tail
        whose complete bytes already prove the record invalid is a
        definitive error, not a cut-off write, and raises in both
        modes.
        """
        var lineno = self._lineno
        var verdict = classify_tail(self._pending)
        var probe: Event
        try:
            probe = parse_event(self._pending)
        except:
            if self._allow_partial and verdict == TAIL_INCOMPLETE:
                if partial_record_definitive(
                    self._pending, self.session.session_id
                ):
                    raise ReadError(
                        READ_PARSE,
                        lineno,
                        "line "
                        + String(lineno)
                        + ": definitive error in final record",
                    )
                self.partial = True
                self._staged = False
                self._exhausted = True
                self._close_now()
                self._finish_checks()
                return False
            raise ReadError(
                READ_PARSE,
                lineno,
                "line "
                + String(lineno)
                + ": corrupt final record (not truncation)",
            )
        self._check(probe, lineno)
        raise ReadError(
            READ_PARSE,
            lineno,
            "line " + String(lineno) + ": final record lacks trailing newline",
        )

    def _ensure_staged(mut self) raises ReadError:
        """Stage the next line unless the stream already ended."""
        if self._staged or self._exhausted:
            return
        if self._fill_line():
            self._staged = True
            return
        self._exhausted = True
        self._close_now()
        self._finish_checks()

    def _fill_line(mut self) raises ReadError -> Bool:
        """Accumulate one line into _pending.

        Returns True with _lineno advanced when a line (terminated
        or a final unterminated tail) is staged; False at clean EOF
        when no bytes remain. Byte bounds match the schema
        validator's line iterator exactly.
        """
        self._pending = List[UInt8]()
        self._staged_final = False
        while True:
            if self._pos >= self._end:
                if self._stream_eof:
                    if len(self._pending) == 0:
                        return False
                    self._lineno += 1
                    self._staged_final = True
                    return True
                self._refill()
                continue
            var b = self._chunk[self._pos]
            self._pos += 1
            self._total += 1
            if self._total > self._limits.max_events_bytes:
                raise ReadError(READ_TOO_BIG, 0, "events.ndjson too large")
            if b == UInt8(0x0A):
                if len(self._pending) + 1 > self._limits.max_line_bytes:
                    raise ReadError(
                        READ_TOO_BIG, self._lineno + 1, "line too large"
                    )
                self._lineno += 1
                return True
            self._pending.append(b)
            if len(self._pending) > self._limits.max_line_bytes:
                raise ReadError(
                    READ_TOO_BIG, self._lineno + 1, "line too large"
                )

    def _refill(mut self) raises ReadError:
        """Read the next chunk; set _stream_eof at clean EOF."""
        var got = external_call["fread", Int64](
            Span(self._chunk).unsafe_ptr(), 1, _CHUNK_BYTES, self._fp
        )
        if got == 0:
            var ferr = external_call["ferror", Int32](self._fp)
            if ferr != 0:
                raise ReadError(READ_IO, 0, "cannot read events.ndjson")
            self._stream_eof = True
            self._pos = 0
            self._end = 0
            return
        self._pos = 0
        self._end = Int(got)

    def _close_now(mut self):
        """Close the stream exactly once; safe to repeat."""
        if self._fp != 0:
            _ = external_call["fclose", Int32](self._fp)
            self._fp = 0

    def _check(mut self, ev: Event, lineno: Int) raises ReadError:
        if ev.session_id != self.session.session_id:
            raise ReadError(
                READ_INVALID, lineno, "line " + String(lineno) + ": session id"
            )
        if self._has_prev and ev.seq <= self._prev_seq:
            raise ReadError(
                READ_INVALID, lineno, "line " + String(lineno) + ": seq order"
            )
        if ev.ts_ns < self.session.window_start_ns:
            raise ReadError(
                READ_INVALID, lineno, "line " + String(lineno) + ": ts before"
            )
        if ev.ts_ns >= self.session.window_end_ns:
            raise ReadError(
                READ_INVALID, lineno, "line " + String(lineno) + ": ts after"
            )
        self._check_identities(ev, lineno)
        var tracked = len(self._ops) + len(self._maps)
        if tracked > _MAX_TRACKED_IDS:
            raise ReadError(
                READ_TOO_BIG, lineno, "too many tracked identities"
            )

    def _check_identities(
        mut self, ev: Event, lineno: Int
    ) raises ReadError:
        """Enforce cross-record identity rules for one event.

        Device membership, per-(kind, operation) uniqueness, mapping
        creation/release pairing, and deferred copy/sync references
        match the schema validator exactly: unmap needs a prior live
        creation, while copy/sync references resolve when the stream
        ends so forward references stay valid.
        """
        var tag = "line " + String(lineno) + ": "
        if ev.kind == "bounce_attempt":
            if ev.bounce.device_id not in self._devices:
                raise ReadError(READ_INVALID, lineno, tag + "unknown device")
            self._note_op(ev.kind, ev.bounce.operation_id, tag, lineno)
            try:
                self._req_total = checked_add(
                    self._req_total, ev.bounce.requested_bytes
                )
            except:
                raise ReadError(
                    READ_INVALID, lineno, tag + "requested bytes overflow"
                )
            # The per-device arm mirrors the validator's second sum.
            # The total is checked first and always dominates it, so
            # this arm is unreachable; it stands as a parity guard.
            var prior: UInt64
            try:
                prior = self._req_dev[ev.bounce.device_id]
            except:
                prior = UInt64(0)
            try:
                self._req_dev[ev.bounce.device_id] = checked_add(
                    prior, ev.bounce.requested_bytes
                )
            except:
                raise ReadError(
                    READ_INVALID, lineno, tag + "per-device bytes overflow"
                )
        elif ev.kind == "map_result":
            self._note_op(ev.kind, ev.map_result.operation_id, tag, lineno)
            if ev.map_result.success:
                var mid = ev.map_result.mapping_id
                if mid in self._maps:
                    raise ReadError(
                        READ_INVALID, lineno, tag + "duplicate mapping"
                    )
                self._maps[mid] = True
        elif ev.kind == "unmap":
            if ev.unmap.has_mapping_id:
                var target = ev.unmap.mapping_id
                if target in self._dead:
                    raise ReadError(
                        READ_INVALID, lineno, tag + "mapping released twice"
                    )
                if target not in self._maps:
                    raise ReadError(
                        READ_INVALID, lineno, tag + "unknown mapping"
                    )
                self._dead[target] = True
        elif ev.kind == "copy":
            # Copies repeat freely under one operation (nested,
            # per-sync, and completion copies share it); only
            # attempts and map results claim an operation once.
            if ev.copy.has_mapping_id:
                self._ref_ids.append(ev.copy.mapping_id)
                self._ref_lines.append(lineno)
        elif ev.kind == "sync_request":
            # Syncs repeat freely under one operation for the
            # same reason as copies.
            if ev.sync.has_mapping_id:
                self._ref_ids.append(ev.sync.mapping_id)
                self._ref_lines.append(lineno)
        elif ev.kind == "counter_snapshot":
            if ev.snapshot.has_scope_device:
                if ev.snapshot.scope_device_id not in self._devices:
                    raise ReadError(
                        READ_INVALID, lineno, tag + "unknown device"
                    )

    def _note_op(
        mut self, kind: String, op: String, tag: String, lineno: Int
    ) raises ReadError:
        """Record one (kind, operation) pair; reject repeats.

        The key embeds the operation byte length between separators,
        so splitting at the first two separators recovers the kind
        and operation uniquely no matter what the id contains.
        """
        var key = (
            kind
            + "#"
            + String(op.byte_length())
            + "#"
            + op
        )
        if key in self._ops:
            raise ReadError(
                READ_INVALID, lineno, tag + "duplicate operation"
            )
        self._ops[key] = True

    def _finish_checks(self) raises ReadError:
        """Resolve deferred copy/sync mapping references at end."""
        for i in range(len(self._ref_ids)):
            if self._ref_ids[i] not in self._maps:
                var lineno = self._ref_lines[i]
                raise ReadError(
                    READ_INVALID,
                    lineno,
                    "line " + String(lineno) + ": unknown mapping",
                )


def _read_bounded(
    path: String, what: String, limit: Int
) raises ReadError -> List[UInt8]:
    """Read a small file without ever over-allocating past limit.

    Chunks stream through a fixed 64 KiB buffer; the running total
    is checked before each chunk lands, so a huge file is rejected
    after one chunk over the bound instead of being read fully.
    """
    var cpath = _to_cstr(path)
    var mode = _to_cstr("rb")
    var fp = external_call["fopen", UInt64](
        Span(cpath).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == 0:
        raise ReadError(READ_IO, 0, what + ": cannot open")
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
                raise ReadError(READ_IO, 0, what + ": cannot read")
            return out^
        var n = Int(got)
        if len(out) + n > limit:
            _ = external_call["fclose", Int32](fp)
            raise ReadError(READ_TOO_BIG, 0, what + " too large")
        for i in range(n):
            out.append(chunk[i])


def read_capture(
    dir: String, allow_partial: Bool, limits: ReaderLimits
) raises ReadError -> CaptureReader:
    """Open the capture in dir: validate session, stream events."""
    var session_bytes = _read_bounded(
        dir + "/session.json", "session.json", limits.max_session_bytes
    )
    var session: Session
    try:
        session = parse_session(session_bytes^)
    except e:
        raise ReadError(READ_PARSE, 0, "session.json: " + String(e))
    var out = CaptureReader()
    out.session = session^
    out._allow_partial = allow_partial
    out._limits = limits.copy()
    for i in range(len(out.session.devices)):
        out._devices[out.session.devices[i].device_id] = True
    for _ in range(_CHUNK_BYTES):
        out._chunk.append(UInt8(0))
    var path = _to_cstr(dir + "/events.ndjson")
    var mode = _to_cstr("rb")
    var fp = external_call["fopen", UInt64](
        Span(path).unsafe_ptr(), Span(mode).unsafe_ptr()
    )
    if fp == 0:
        raise ReadError(READ_IO, 0, "cannot open events.ndjson")
    out._fp = fp
    return out^
