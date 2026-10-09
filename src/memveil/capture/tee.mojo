# SPDX-License-Identifier: GPL-3.0-or-later

"""Tee writer source: persist every line, fold a live analyzer.

A WriterSource that forwards every call to an owned LiveWriter
and, on success only, decodes the same bytes and feeds the
shared composed analyzer. Live input is byte-identical to what
replay will read: a decode failure is an internal error, never
a silent skip.

The analyzer runs under a provisional session stamped from the
template: the window starts at the first folded event, ends at
the event-time horizon, and never claims finalization. Refresh
timing is event time, not wall time: a refresh emits when the
running maximum event timestamp reaches the interval past the
last emission, so quiet periods structurally print nothing and
disordered events fold forward without moving the horizon.

Printed refreshes are never revised. A group abort rewinds the
retained prefix, so the tee rebuilds the analyzer from the
retained event bytes (aborts only happen on the failing
closing path, so the rebuild cost never touches clean runs)
while the already printed prefix refreshes stand. Emission
cadence continues past the abort: horizons already shown are
not shown again.

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
from memveil.platform.reader import read_host_file


trait RefreshSink:
    """One live refresh consumer: report plus event-time horizon."""

    def emit(mut self, rep: Report, horizon_ns: UInt64) -> Bool:
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
    var _last_emit_ns: UInt64

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
        self._last_emit_ns = UInt64(0)

    def create(mut self, path: String, budget: Int) -> CreateOut:
        var out = self._inner.create(path, budget)
        if out.ok:
            self._path = path.copy()
            self._created = True
        return out^

    def append(mut self, line: List[UInt8]) -> AppendOut:
        var out = self._inner.append(line)
        if not out.ok:
            return out^
        return self._fold(line)

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        var out = self._inner.append_closing(line)
        if not out.ok:
            return out^
        return self._fold(line)

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

    def _fold(mut self, line: List[UInt8]) -> AppendOut:
        """Decode one persisted line, fold it, maybe refresh."""
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
        var work = self._analyzer.take()
        try:
            work.consume(ev)
        except e:
            self._analyzer = Optional(work^)
            return AppendOut(False, String("internal"), String(e))
        self._analyzer = Optional(work^)
        if ev.ts_ns > self._horizon_ns:
            self._horizon_ns = ev.ts_ns
        if self._horizon_ns - self._last_emit_ns < self._interval_ns:
            return AppendOut(True, String(""), String(""))
        var shown = self._analyzer.take()
        var snap: Report
        try:
            snap = shown.snapshot(self._horizon_ns, False)
        except e:
            self._analyzer = Optional(shown^)
            return AppendOut(False, String("internal"), String(e))
        self._analyzer = Optional(shown^)
        if not self._sink.emit(snap, self._horizon_ns):
            return AppendOut(
                False, String("internal"), String("refresh sink refused")
            )
        self._last_emit_ns = self._horizon_ns
        return AppendOut(True, String(""), String(""))

    def _rebuild(mut self) -> AppendOut:
        """Refold the retained prefix after a group abort.

        Reads back the event file the inner writer owns, so the
        analyzer again matches exactly the persisted bytes. The
        emission cadence keeps its place: shown horizons stand.
        """
        if not self._created or self._inner.committed_len() == 0:
            self._analyzer = None
            self._horizon_ns = UInt64(0)
            return AppendOut(True, String(""), String(""))
        var raw: List[UInt8]
        try:
            raw = read_host_file(
                self._path + String("/events.ndjson"),
                String("events"),
                self._inner.committed_len(),
            )
        except e:
            return AppendOut(False, String("internal"), String(e))
        var fresh: Optional[Analyzer] = None
        var horizon = UInt64(0)
        var start = 0
        var i = 0
        while True:
            if i >= len(raw) or raw[i] == UInt8(0x0A):
                if i > start:
                    var body = List[UInt8]()
                    for j in range(start, i):
                        body.append(raw[j])
                    var ev: Event
                    try:
                        ev = parse_event(body)
                    except e:
                        return AppendOut(
                            False, String("internal"), String(e)
                        )
                    if not fresh:
                        var stamped = self._template.copy()
                        stamped.window_start_ns = ev.ts_ns
                        stamped.window_end_ns = ~UInt64(0)
                        var first = Analyzer(stamped)
                        fresh = Optional(first^)
                    var work = fresh.take()
                    try:
                        work.consume(ev)
                    except e:
                        return AppendOut(
                            False, String("internal"), String(e)
                        )
                    fresh = Optional(work^)
                    if ev.ts_ns > horizon:
                        horizon = ev.ts_ns
                if i >= len(raw):
                    break
                start = i + 1
            i += 1
        self._analyzer = fresh^
        self._horizon_ns = horizon
        return AppendOut(True, String(""), String(""))
