# SPDX-License-Identifier: GPL-3.0-or-later

"""Tee writer source: persist every line, fold a live analyzer.

A WriterSource that forwards every call to an owned LiveWriter
and, on success only, decodes the same bytes and feeds the
shared composed analyzer. Persist and fold are atomic: when
the fold fails, the line is rolled back and the analyzer is
rewound to the retained prefix, so live input stays
byte-identical to what replay will read. A decode failure is
an internal error, never a silent skip.

The analyzer runs under a provisional session stamped from the
template: the window starts at the first folded event, ends at
the event-time horizon, and never claims finalization. Refresh
timing is event time, not wall time: a refresh emits when the
running maximum event timestamp reaches the interval past the
last emission, so quiet periods structurally print nothing and
disordered events fold forward without moving the horizon.

Printed refreshes are never revised. A group abort rewinds the
retained prefix, so the tee rebuilds the analyzer by
streaming the retained event bytes in fixed chunks (aborts
only happen on the failing closing path, so the rebuild cost
never touches clean runs) while the already printed prefix
refreshes stand. Emission cadence continues past the abort:
horizons already shown are not shown again.

The tee never emits a final block: the caller replays the
retained capture for the final answer, which keeps the final
live block equal to a replay of that capture by construction.
"""

from memveil.analysis.engine import Analyzer
from memveil.capture.collector import (
    AppendOut,
    CreateOut,
    FinalOut,
    GroupOut,
    WriterSource,
)
from memveil.capture.live import LiveWriter
from memveil.model.event import Event, parse_event
from memveil.model.report import Report
from memveil.model.session import Session
from memveil.platform.reader import LineSink, stream_host_lines


trait RefreshSink:
    """One live refresh consumer: report plus event-time horizon.

    The report moves into the sink: the sink is its final
    consumer and may diagnose it in place.
    """

    def emit(mut self, var rep: Report, horizon_ns: UInt64) -> Bool:
        ...


def _strip_newline(line: List[UInt8]) -> List[UInt8]:
    """Copy line minus one trailing newline, matching the reader."""
    var out = List[UInt8]()
    var n = len(line)
    if n > 0 and line[n - 1] == UInt8(0x0A):
        n -= 1
    for i in range(n):
        out.append(line[i])
    return out^


struct _FloorScan(LineSink):
    """First rebuild pass: retained minimum, maximum, line count."""

    var floor_ns: UInt64
    var horizon_ns: UInt64
    var lines: Int
    var failure: String

    def __init__(out self):
        self.floor_ns = ~UInt64(0)
        self.horizon_ns = UInt64(0)
        self.lines = 0
        self.failure = String("")

    def feed(mut self, line: List[UInt8]) -> String:
        var ev: Event
        try:
            ev = parse_event(line)
        except e:
            self.failure = String(e)
            return self.failure
        if ev.ts_ns < self.floor_ns:
            self.floor_ns = ev.ts_ns
        if ev.ts_ns > self.horizon_ns:
            self.horizon_ns = ev.ts_ns
        self.lines += 1
        return String("")


struct _Refold(LineSink):
    """Second rebuild pass: fold the prefix into a fresh analyzer."""

    var _template: Session
    var _floor_ns: UInt64
    var _analyzer: Optional[Analyzer]
    var failure: String

    def __init__(out self, template: Session, floor_ns: UInt64):
        self._template = template.copy()
        self._floor_ns = floor_ns
        self._analyzer = None
        self.failure = String("")

    def feed(mut self, line: List[UInt8]) -> String:
        var ev: Event
        try:
            ev = parse_event(line)
        except e:
            self.failure = String(e)
            return self.failure
        if not self._analyzer:
            var stamped = self._template.copy()
            stamped.window_start_ns = self._floor_ns
            stamped.window_end_ns = ~UInt64(0)
            var first = Analyzer(stamped)
            self._analyzer = Optional(first^)
        var work = self._analyzer.take()
        try:
            work.consume(ev)
        except e:
            self._analyzer = Optional(work^)
            self.failure = String(e)
            return self.failure
        self._analyzer = Optional(work^)
        return String("")

    def drain(mut self) -> Analyzer:
        return self._analyzer.take()


struct TeeWriter[S: RefreshSink & Movable & Deinitable](WriterSource):
    """WriterSource that persists lines and folds live refreshes."""

    var _inner: LiveWriter
    var _sink: Self.S
    var _template: Session
    var _interval_ns: UInt64
    var _path: String
    var _created: Bool
    var _analyzer: Optional[Analyzer]
    var _horizon_ns: UInt64
    var _floor_ns: UInt64
    var _last_emit_ns: UInt64
    var _emissions: Int

    def __init__(
        out self,
        template: Session,
        interval_ns: UInt64,
        var sink: Self.S,
    ):
        self._inner = LiveWriter()
        self._sink = sink^
        self._template = template.copy()
        self._interval_ns = interval_ns
        self._path = String("")
        self._created = False
        self._analyzer = None
        self._horizon_ns = UInt64(0)
        self._floor_ns = UInt64(0)
        self._last_emit_ns = UInt64(0)
        self._emissions = 0

    def create(mut self, path: String, budget: Int) -> CreateOut:
        var out = self._inner.create(path, budget)
        if out.ok:
            self._path = path.copy()
            self._created = True
        return out^

    def append(mut self, line: List[UInt8]) -> AppendOut:
        var mark = self._inner.committed_len()
        var out = self._inner.append(line)
        if not out.ok:
            return out^
        var folded = self._fold(line)
        if folded.ok:
            return folded^
        return self._undo_append(mark, folded^)

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        var mark = self._inner.committed_len()
        var out = self._inner.append_closing(line)
        if not out.ok:
            return out^
        var folded = self._fold(line)
        if folded.ok:
            return folded^
        return self._undo_append(mark, folded^)

    def _undo_append(
        mut self, mark: Int, var err: AppendOut
    ) -> AppendOut:
        """Roll back one persisted line, rewind the analyzer.

        A failed fold must not leave persisted-but-unfolded
        bytes: the collector keeps appending closing records
        after a failure, and every later refresh must match
        a replay of the retained file. The inner mark is a
        plain offset, so this nests safely inside a caller
        group. The original fold error is preserved; only a
        dead writer or a failed rewind supersedes it.
        """
        var rolled = self._inner.group_abort(mark)
        if not rolled.ok:
            return rolled^
        var rewound = self._rebuild()
        if not rewound.ok:
            return rewound^
        return err^

    def group_begin(mut self) -> GroupOut:
        return self._inner.group_begin()

    def group_abort(mut self, mark: Int) -> AppendOut:
        var out = self._inner.group_abort(mark)
        if not out.ok:
            return out^
        return self._rebuild()

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        return self._inner.finalize(session)

    def abandon(mut self) -> String:
        return self._inner.abandon()

    def discard(mut self):
        self._inner.discard()

    def committed_len(self) -> Int:
        return self._inner.committed_len()

    def emission_count(self) -> Int:
        """Refreshes the sink accepted so far."""
        return self._emissions

    def _fold(mut self, line: List[UInt8]) -> AppendOut:
        """Decode one persisted line, fold it, maybe refresh.

        A refresh at horizon H covers [floor, H): the event
        at H folds after the snapshot, matching replay. The
        first event only establishes the window; horizons at
        or below the last emission never re-emit, so a
        rewound horizon cannot wrap the unsigned gap.
        """
        var body = _strip_newline(line)
        var ev: Event
        try:
            ev = parse_event(body)
        except e:
            return AppendOut(False, String("internal"), String(e))
        if not self._analyzer:
            var stamped = self._template.copy()
            stamped.window_start_ns = ev.ts_ns
            stamped.window_end_ns = ~UInt64(0)
            var fresh = Analyzer(stamped)
            self._analyzer = Optional(fresh^)
            self._floor_ns = ev.ts_ns
            self._horizon_ns = ev.ts_ns
            self._last_emit_ns = ev.ts_ns
            var work = self._analyzer.take()
            try:
                work.consume(ev)
            except e:
                self._analyzer = Optional(work^)
                return AppendOut(False, String("internal"), String(e))
            self._analyzer = Optional(work^)
            return AppendOut(True, String(""), String(""))
        var horizon = self._horizon_ns
        if ev.ts_ns > horizon:
            horizon = ev.ts_ns
        if (
            horizon > self._last_emit_ns
            and horizon - self._last_emit_ns >= self._interval_ns
        ):
            var shown = self._analyzer.take()
            var snap: Report
            try:
                snap = shown.snapshot(horizon, False)
            except e:
                self._analyzer = Optional(shown^)
                return AppendOut(False, String("internal"), String(e))
            self._analyzer = Optional(shown^)
            if not self._sink.emit(snap^, horizon):
                return AppendOut(
                    False,
                    String("internal"),
                    String("refresh sink refused"),
                )
            self._last_emit_ns = horizon
            self._emissions += 1
        self._horizon_ns = horizon
        if ev.ts_ns < self._floor_ns:
            # Below the stamped floor: refold the retained
            # prefix with the floor lowered to the retained
            # minimum, so nothing counts below the window.
            return self._rebuild()
        var work = self._analyzer.take()
        try:
            work.consume(ev)
        except e:
            self._analyzer = Optional(work^)
            return AppendOut(False, String("internal"), String(e))
        self._analyzer = Optional(work^)
        return AppendOut(True, String(""), String(""))

    def _rebuild(mut self) -> AppendOut:
        """Refold the retained prefix after a group abort.

        Streams the event file the inner writer owns in fixed
        64 KiB chunks, twice: once for the retained minimum
        and maximum, once to fold the prefix into a fresh
        analyzer. The file is never held whole, so a large
        retained capture cannot exhaust memory on the abort
        path. The window floor is the retained minimum, never
        the first arrival. The emission cadence keeps its
        place: shown horizons stand.
        """
        if not self._created or self._inner.committed_len() == 0:
            self._analyzer = None
            self._horizon_ns = UInt64(0)
            self._floor_ns = UInt64(0)
            return AppendOut(True, String(""), String(""))
        var events_path = self._path + String("/events.ndjson")
        var bound = self._inner.committed_len()
        var scan = _FloorScan()
        try:
            stream_host_lines(
                events_path, String("events"), bound, scan
            )
        except e:
            return AppendOut(False, String("internal"), String(e))
        if scan.failure != "":
            return AppendOut(
                False, String("internal"), scan.failure
            )
        if scan.lines == 0:
            self._analyzer = None
            self._horizon_ns = UInt64(0)
            self._floor_ns = UInt64(0)
            return AppendOut(True, String(""), String(""))
        var refold = _Refold(self._template.copy(), scan.floor_ns)
        try:
            stream_host_lines(
                events_path, String("events"), bound, refold
            )
        except e:
            return AppendOut(False, String("internal"), String(e))
        if refold.failure != "":
            return AppendOut(
                False, String("internal"), refold.failure
            )
        var rebuilt = refold.drain()
        self._analyzer = Optional(rebuilt^)
        self._horizon_ns = scan.horizon_ns
        self._floor_ns = scan.floor_ns
        return AppendOut(True, String(""), String(""))
