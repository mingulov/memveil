# SPDX-License-Identifier: GPL-3.0-or-later
"""Owned tracing transport. Native diagnostics never export verifier contents."""
from libbpf_mojo.session import Session, AttachSpec
from libbpf_mojo.batch import decode_frame, POLL_BATCH, POLL_TIMEOUT, POLL_SHORT
from memveil.capture.conversions import decode_journal_counters, JOURNAL_NATIVE_COUNTERS
from memveil.platform.outcome import OpOut
from memveil.platform.reader import read_host_file
from memveil.capture.journal_callers import resolve_caller_ranges, encode_caller_range, CallerRange


@fieldwise_init
struct JournalPoll(Copyable):
    var ok: Bool
    var data: List[UInt8]


@fieldwise_init
struct JournalCounters(Copyable):
    var ok: Bool
    var values: List[UInt64]


trait JournalSource(Movable):
    def prepare(mut self, control: List[UInt8]) -> OpOut:
        ...
    def attach(mut self) -> OpOut:
        ...
    def control(mut self, value: List[UInt8]) -> OpOut:
        ...
    def poll(mut self, timeout_ms: Int) -> JournalPoll:
        ...
    def counters(mut self) -> JournalCounters:
        ...
    def detach(mut self) -> OpOut:
        ...
    def close(mut self) -> OpOut:
        ...


def journal_attach_specs() -> List[AttachSpec]:
    var out = List[AttachSpec]()
    for name in [String("mv_jr_dec_exit"), String("mv_jr_enc_exit"), String("mv_jr_dec_enter"), String("mv_jr_enc_enter")]:
        out.append(AttachSpec(name, UInt32(2), String(""), String("")))
    return out^


struct JournalKernel(JournalSource):
    var elf: List[UInt8]
    var bridge: String
    var session: Optional[Session]
    var stable_owned_module: Bool

    def __init__(out self):
        self.elf = List[UInt8]()
        self.bridge = String("")
        self.session = None
        self.stable_owned_module = False

    def setup(mut self, elf: List[UInt8], bridge: String, stable_owned_module: Bool = False):
        self.elf = elf.copy()
        self.bridge = bridge
        self.stable_owned_module = stable_owned_module

    def prepare(mut self, control: List[UInt8]) -> OpOut:
        if self.session:
            return OpOut(False, String("journal already open"))
        try:
            var s = Session.open_with_lib(Span(self.elf), String("mv_journal"), UInt32(72), self.bridge)
            s.load()
            for name, kind, key_bytes, value_bytes, capacity in [
                (String("mv_jr_control"), 2, 4, 48, 1),
                (String("mv_jr_counts"), 2, 4, 8, 15),
                (String("mv_jr_sequence"), 6, 4, 8, 1),
                (String("mv_jr_tasks"), 1, 32, 16, 4096),
                (String("mv_jr_ops"), 1, 32, 24, 4096),
                (String("mv_jr_symbols"), 2, 4, 24, 10),
                (String("mv_journal"), 27, 0, 0, 8388608),
            ]:
                var geom = s.map_info(name)
                if geom.map_type != UInt32(kind) or geom.key_size != UInt32(key_bytes) or geom.value_size != UInt32(value_bytes) or geom.max_entries != UInt32(capacity):
                    return OpOut(False, String("journal map geometry"))
            self.session = Optional(s^)
        except:
            return OpOut(False, String("journal open/load unavailable"))
        var counters = self.counters()
        if not counters.ok:
            _ = self.close()
            return OpOut(False, String("journal initial counters unavailable"))
        for value in counters.values:
            if value != 0:
                _ = self.close()
                return OpOut(False, String("journal initial counters nonzero"))
        if len(control) == 48 and control[40] != 0:
            if not self.install_callers():
                _ = self.close()
                return OpOut(False, String("journal caller map unavailable"))
        return self.control(control)

    def install_callers(mut self) -> Bool:
        if not self.session:
            return True
        var data = List[UInt8]()
        try:
            data = read_host_file(String("/proc/kallsyms"), String("caller symbol source"), 16777216)
        except:
            return True
        var ranges: List[CallerRange]
        try:
            ranges = resolve_caller_ranges(String(from_utf8=Span(data)), self.stable_owned_module)
        except:
            return True
        var s = self.session.take()
        var ok = True
        try:
            for i in range(10):
                var key = List[UInt8](length=4, fill=UInt8(0))
                key[0] = UInt8(i)
                var value = encode_caller_range(ranges[i])
                s.map_write(String("mv_jr_symbols"), Span(key), Span(value))
        except:
            ok = False
        self.session = Optional(s^)
        return ok

    def attach(mut self) -> OpOut:
        if not self.session:
            return OpOut(False, String("journal not open"))
        var s = self.session.take()
        var ok = True
        try:
            s.attach(journal_attach_specs())
        except:
            ok = False
        self.session = Optional(s^)
        return OpOut(ok, String("") if ok else String("journal attach failed"))

    def control(mut self, value: List[UInt8]) -> OpOut:
        if not self.session or len(value) != 48:
            return OpOut(False, String("journal control unavailable"))
        var s = self.session.take()
        var key = List[UInt8](length=4, fill=UInt8(0))
        var ok = True
        try:
            s.map_write(String("mv_jr_control"), Span(key), Span(value))
            var actual = s.map_read(String("mv_jr_control"), Span(key), UInt32(48))
            if actual.required != 0 or actual.data != value:
                ok = False
        except:
            ok = False
        self.session = Optional(s^)
        return OpOut(ok, String("") if ok else String("journal control write/readback failed"))

    def poll(mut self, timeout_ms: Int) -> JournalPoll:
        var data = List[UInt8]()
        if not self.session:
            return JournalPoll(False, data^)
        var s = self.session.take()
        var buf = List[UInt8](length=4096, fill=UInt8(0))
        var ok = True
        try:
            var result = s.poll(buf, 0, UInt32(4096), Int32(timeout_ms))
            if result.kind == POLL_SHORT:
                if result.required == 0 or result.required > 4096:
                    ok = False
                else:
                    result = s.poll(buf, 0, UInt32(4096), Int32(0))
                    if result.kind != POLL_BATCH:
                        ok = False
            if result.kind == POLL_BATCH and ok:
                var frame = decode_frame(Span(buf), 0, result.written)
                data = frame.payload.copy()
            elif result.kind != POLL_TIMEOUT:
                ok = False
        except:
            ok = False
        self.session = Optional(s^)
        return JournalPoll(ok, data^)

    def counters(mut self) -> JournalCounters:
        var raw = List[UInt8]()
        var values = List[UInt64]()
        if not self.session:
            return JournalCounters(False, values^)
        var s = self.session.take()
        var ok = True
        try:
            for index in range(JOURNAL_NATIVE_COUNTERS):
                var key = List[UInt8](length=4, fill=UInt8(0))
                key[0] = UInt8(index)
                var got = s.map_read(String("mv_jr_counts"), Span(key), UInt32(8))
                if got.required != 0 or len(got.data) != 8:
                    ok = False
                    break
                raw.extend(Span(got.data))
        except:
            ok = False
        if ok:
            try:
                values = decode_journal_counters(raw)
            except:
                ok = False
        self.session = Optional(s^)
        return JournalCounters(ok, values^)

    def detach(mut self) -> OpOut:
        if not self.session:
            return OpOut(True, String(""))
        var s = self.session.take()
        var ok = True
        try:
            s.detach()
        except:
            ok = False
        self.session = Optional(s^)
        return OpOut(ok, String("") if ok else String("journal detach failed"))

    def close(mut self) -> OpOut:
        if not self.session:
            return OpOut(True, String(""))
        var s = self.session.take()
        try:
            s.close()
        except:
            self.session = Optional(s^)
            return OpOut(False, String("journal close failed"))
        return OpOut(True, String(""))
