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
from memveil.capture.writer import (
    EventWriter,
    WriteError,
    residual_text,
)


def _writer_message(e: WriteError) -> String:
    return e.kind + String(": ") + e.message


def _construction_note(residuals: UInt8) -> String:
    """Display text for stuck construction artifacts, or '' when none.

    Rendered from the typed residual bits alone. The
    adapter boundary reports them exactly once, via
    abandon(): the creation error keeps the failure
    cause, never a residual suffix, so rollback cannot
    repeat the list. Error message text is never parsed.
    """
    var tail = residual_text(residuals)
    if tail == String(""):
        return String("")
    return String("construction residuals: ") + tail


struct LiveWriter(WriterSource):
    """WriterSource backed by one EventWriter."""

    var _writer: Optional[EventWriter]
    var _construction_residuals: UInt8
    var _final_ids: List[UInt64]

    def __init__(out self):
        self._writer = None
        self._construction_residuals = UInt8(0)
        self._final_ids = List[UInt64]()

    def create(mut self, path: String, budget: Int) -> CreateOut:
        if self._writer:
            return CreateOut(False, String("misuse"), String("create twice"))
        try:
            var w = EventWriter(path, budget)
            self._writer = Optional(w^)
        except e:
            if e.residuals != UInt8(0):
                self._construction_residuals = e.residuals
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
            if outcome.status == String("finalized"):
                self._final_ids = w.finalized_identity()
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
            if self._construction_residuals != UInt8(0):
                var bits = self._construction_residuals
                self._construction_residuals = UInt8(0)
                return _construction_note(bits)
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

    def finalized_identity(self) -> List[UInt64]:
        return self._final_ids.copy()
