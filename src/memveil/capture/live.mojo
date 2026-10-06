# SPDX-License-Identifier: GPL-3.0-or-later

"""Live writer source: WriterSource over an EventWriter.

Thin ownership adapter, no policy: create() opens the
EventWriter in its slot; every later method takes the
writer out, runs one call, and puts it back (finalize
and discard consume it: the slot empties, later calls
report misuse). Calls before create report misuse too.
"""

from memveil.capture.collector import (
    AppendOut,
    CreateOut,
    FinalOut,
    GroupOut,
    WriterSource,
)
from memveil.capture.writer import EventWriter, WriteError


def _writer_message(e: WriteError) -> String:
    return e.kind + String(": ") + e.message


def _residual_mark_at(message: String) -> Int:
    """Byte index of '; residuals: ', or -1 when absent."""
    var mark = String("; residuals: ").as_bytes()
    var body = message.as_bytes()
    var i = 0
    while i + len(mark) <= len(body):
        var j = 0
        while j < len(mark):
            if body[i + j] != mark[j]:
                break
            j += 1
        if j == len(mark):
            return i
        i += 1
    return -1


def _residual_tail(message: String) -> String:
    """Text after '; residuals: ', or '' when absent.

    The construction unwind reports stuck artifacts in the
    raised error; this lifts the stuck list so a failed
    create still leaves a rollback account behind.
    """
    var at = _residual_mark_at(message)
    if at < 0:
        return String("")
    try:
        var tail = List[UInt8]()
        var body = message.as_bytes()
        var k = at + len(String("; residuals: ").as_bytes())
        while k < len(body):
            tail.append(body[k])
            k += 1
        return String(from_utf8=Span(tail))
    except:
        return String("unparseable")


def _strip_residual_tail(message: String) -> String:
    """Head before '; residuals: '; full message when absent.

    The adapter boundary reports stuck construction
    artifacts exactly once, via abandon(): the creation
    error keeps the failure cause, never the residual
    suffix, so rollback cannot repeat the list.
    """
    var at = _residual_mark_at(message)
    if at < 0:
        return message.copy()
    try:
        var head = List[UInt8]()
        var body = message.as_bytes()
        var k = 0
        while k < at:
            head.append(body[k])
            k += 1
        return String(from_utf8=Span(head))
    except:
        return message.copy()


struct LiveWriter(WriterSource):
    """WriterSource backed by one EventWriter."""

    var _writer: Optional[EventWriter]
    var _construction_residual: String

    def __init__(out self):
        self._writer = None
        self._construction_residual = String("")

    def create(mut self, path: String, budget: Int) -> CreateOut:
        if self._writer:
            return CreateOut(False, String("misuse"), String("create twice"))
        try:
            var w = EventWriter(path, budget)
            self._writer = Optional(w^)
        except e:
            var stuck = _residual_tail(e.message)
            if stuck != String(""):
                self._construction_residual = stuck
                return CreateOut(
                    False,
                    e.kind.copy(),
                    _strip_residual_tail(e.message),
                )
            return CreateOut(False, e.kind.copy(), e.message.copy())
        return CreateOut(True, String(""), String(""))

    def append(mut self, line: List[UInt8]) -> AppendOut:
        if not self._writer:
            return AppendOut(
                False, String("misuse"), String("append before create")
            )
        var w = self._writer.take()
        try:
            w.append(line.copy())
        except e:
            self._writer = Optional(w^)
            return AppendOut(False, e.kind.copy(), e.message.copy())
        self._writer = Optional(w^)
        return AppendOut(True, String(""), String(""))

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        if not self._writer:
            return AppendOut(
                False, String("misuse"), String("append before create")
            )
        var w = self._writer.take()
        try:
            w.append_closing(line.copy())
        except e:
            self._writer = Optional(w^)
            return AppendOut(False, e.kind.copy(), e.message.copy())
        self._writer = Optional(w^)
        return AppendOut(True, String(""), String(""))

    def group_begin(mut self) -> GroupOut:
        if not self._writer:
            return GroupOut(False, 0, String("misuse"))
        var w = self._writer.take()
        try:
            var mark = w.group_begin()
            self._writer = Optional(w^)
            return GroupOut(True, mark, String(""))
        except e:
            self._writer = Optional(w^)
            return GroupOut(False, 0, e.kind.copy())

    def group_abort(mut self, mark: Int) -> AppendOut:
        if not self._writer:
            return AppendOut(
                False, String("misuse"), String("abort before create")
            )
        var w = self._writer.take()
        try:
            w.group_abort(mark)
        except e:
            self._writer = Optional(w^)
            return AppendOut(False, e.kind.copy(), e.message.copy())
        self._writer = Optional(w^)
        return AppendOut(True, String(""), String(""))

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        if not self._writer:
            return FinalOut(
                String("unfinalized"), String("finalize before create")
            )
        var w = self._writer.take()
        try:
            var outcome = w.finalize(session.copy())
            return FinalOut(outcome.status.copy(), outcome.message.copy())
        except e:
            self._writer = Optional(w^)
            return FinalOut(String("unfinalized"), _writer_message(e.copy()))

    def abandon(mut self) -> String:
        # Idempotent cleanup: nothing created means nothing
        # to roll back (same contract as discard, and as the
        # scripted writers). A missing writer here is the
        # normal pre-create startup-refusal path, not misuse.
        # Exception: a failed create that left artifacts
        # behind reports them once, so the refusal becomes a
        # rollback failure instead of a clean refusal.
        if not self._writer:
            if self._construction_residual != String(""):
                var stuck = self._construction_residual.copy()
                self._construction_residual = String("")
                return String("construction residuals: ") + stuck
            return String("")
        var w = self._writer.take()
        return w.abandon()

    def discard(mut self):
        if not self._writer:
            return
        var w = self._writer.take()
        w.discard()

    def committed_len(self) -> Int:
        if not self._writer:
            return 0
        return self._writer.value().committed_len()
