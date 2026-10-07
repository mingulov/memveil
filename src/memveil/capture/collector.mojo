# SPDX-License-Identifier: GPL-3.0-or-later

"""Attempt collector: kernel records to finalized capture.

Implements design sections 2-4: transactional start,
precedence-ordered poll loop with admission latches, the
normal and error close-out machines, loss accounting
identities, closing serialization, and session assembly.
The core is generic over four source traits, so the
scripted matrix drives the REAL close-out, writer, and
session bytes without a kernel; live adapters wrap
libbpf-mojo Session/bridge calls.
"""

from libbpf_mojo.batch import decode_frame
from libbpf_mojo.error import LmbError
from memveil.capture.normalize import (
    CatalogEntry,
    DecodedAttempt,
    DeviceTable,
    NormalizedAttempt,
    NormalizeError,
    decode_payload,
    normalize_attempt,
)
from memveil.capture.pools import (
    POOL_SWIOTLB_ALLOCATOR,
    POOL_SWIOTLB_POOL_ID,
    POOL_SWIOTLB_UNIT,
    NormalizedPoolSample,
    sample_default_pool,
)
from memveil.model.encode import (
    EncodeError,
    encode_event_line,
    encode_session,
)
from memveil.model.event import (
    BounceAttempt,
    CounterSnapshot,
    Event,
    Gap,
    PoolSample,
)
from memveil.model.report import ENGINE_VERSION
from memveil.model.session import (
    Capability,
    Channel,
    DeviceEntry,
    EvidenceItem,
    Session,
)
from memveil.model.validate import format_u64
from memveil.platform.evidence import GuestInfo
from memveil.platform.outcome import OpOut
from memveil.platform.reader import (
    EvidenceReader,
    fs_type_name,
    open_evidence_reader,
)
from memveil.platform.signal import SignalOut, SignalSource

comptime EXIT_ERROR = 1
comptime EXIT_INVALID = 2
comptime EXIT_REFUSAL = 3
comptime EXIT_PARTIAL = 4

comptime MAX_OPS = 4194304
comptime DRAIN_MAX_POLLS = 100000
comptime DRAIN_MAX_S = 30
comptime CONFIRM_POLLS = 100
comptime STABLE_PAIRS = 10
comptime ADVANCE_MAX = 1000
comptime POLL_QUANTUM_MS = 100
comptime SETTLE_MS = 100

comptime CNT_OBSERVED = 0
comptime CNT_OBSERVED_BYTES = 1
comptime CNT_EMITTED = 2
comptime CNT_EMITTED_BYTES = 3
comptime CNT_SUBMIT_FAIL = 4
comptime CNT_FLAGS = 5

comptime FLAG_OBSERVED_WRAP = UInt64(1)
comptime FLAG_OBSERVED_BYTES_WRAP = UInt64(2)
comptime FLAG_EMITTED_WRAP = UInt64(4)
comptime FLAG_EMITTED_BYTES_WRAP = UInt64(8)
comptime FLAG_SUBMIT_WRAP = UInt64(16)
comptime FLAG_BYTE_COVERAGE = UInt64(32)

comptime MAP_TYPE_ARRAY = 2
comptime MAP_TYPE_RINGBUF = 27


@fieldwise_init
struct GeomOut(Copyable, Movable):
    """One map geometry answer (valid only when ok)."""

    var ok: Bool
    var map_type: UInt32
    var key_size: UInt32
    var value_size: UInt32
    var max_entries: UInt32
    var message: String


@fieldwise_init
struct PollOut(Copyable, Movable):
    """One poll outcome: timeout, batch, short, or error.

    kind in {"timeout", "batch", "short", "error"}.
    batch carries raw FRAME bytes (header + payload) for
    collector-side decode_frame; short carries required.
    """

    var kind: String
    var frame: List[UInt8]
    var required: UInt32
    var message: String


@fieldwise_init
struct StatsOut(Copyable, Movable):
    """One bridge-stats read (counters valid only when ok)."""

    var ok: Bool
    var received: UInt64
    var delivered: UInt64
    var staged: UInt64
    var malformed: UInt64
    var dropped: UInt64
    var message: String


@fieldwise_init
struct SnapOut(Copyable, Movable):
    """One full 6-entry counter read (vals valid when ok)."""

    var ok: Bool
    var vals: List[UInt64]
    var message: String


@fieldwise_init
struct CreateOut(Copyable, Movable):
    """One writer-create outcome (kind valid when not ok)."""

    var ok: Bool
    var kind: String
    var message: String


@fieldwise_init
struct AppendOut(Copyable, Movable):
    """One writer-append outcome (kind valid when not ok)."""

    var ok: Bool
    var kind: String
    var message: String


@fieldwise_init
struct GroupOut(Copyable, Movable):
    """One group-begin outcome (mark valid when ok)."""

    var ok: Bool
    var mark: Int
    var kind: String


@fieldwise_init
struct FinalOut(Copyable, Movable):
    """One finalize outcome: status + note, or misuse."""

    var status: String
    var note: String


trait KernelSource:
    """Libbpf-mojo session surface behind scriptable outcomes."""

    def open_session(mut self) -> OpOut:
        ...

    def load(mut self) -> OpOut:
        ...

    def map_info(mut self, name: String) -> GeomOut:
        ...

    def attach(mut self) -> OpOut:
        ...

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        ...

    def stats(mut self) -> StatsOut:
        ...

    def read_full(mut self) -> SnapOut:
        ...

    def detach(mut self) -> OpOut:
        ...

    def close(mut self) -> OpOut:
        ...


trait ClockSource:
    """Monotonic nanoseconds plus settle sleeps."""

    def now(mut self) -> UInt64:
        ...

    def sleep_ms(mut self, ms: Int):
        ...


trait WriterSource:
    """Capture file surface behind scriptable outcomes."""

    def create(mut self, path: String, budget: Int) -> CreateOut:
        ...

    def append(mut self, line: List[UInt8]) -> AppendOut:
        ...

    def append_closing(mut self, line: List[UInt8]) -> AppendOut:
        ...

    def group_begin(mut self) -> GroupOut:
        ...

    def group_abort(mut self, mark: Int) -> AppendOut:
        ...

    def finalize(mut self, session: List[UInt8]) -> FinalOut:
        ...

    def abandon(mut self) -> String:
        ...

    def discard(mut self):
        """Close without publishing: events kept, no session."""
        ...

    def committed_len(self) -> Int:
        ...


struct CollectorConfig(Copyable, Movable):
    """Everything run() needs beyond the sources."""

    var duration_s: UInt64
    var max_events_bytes: Int
    var output: String
    var profile_id: String
    var pid: Int
    var has_ring_bytes: Bool
    var ring_bytes: UInt32
    var has_boot_id: Bool
    var boot_id: String
    var guest: GuestInfo
    var evidence: List[EvidenceItem]
    var has_pool_sample: Bool
    var pool_root: String

    def __init__(out self):
        self.duration_s = UInt64(60)
        self.max_events_bytes = 1073741824
        self.output = String("")
        self.profile_id = String("")
        self.pid = 0
        self.has_ring_bytes = False
        self.ring_bytes = UInt32(0)
        self.has_boot_id = False
        self.boot_id = String("")
        self.guest = GuestInfo(
            String("unknown"), List[String](), False, String("")
        )
        self.evidence = List[EvidenceItem]()
        self.has_pool_sample = False
        self.pool_root = String("")


@fieldwise_init
struct RunResult(Copyable, Movable):
    """One collector run: exit code + session routing."""

    var exit_code: Int
    var end_reason: String
    var outcome: String
    var diagnostic: String


def u64_max() -> UInt64:
    return ~UInt64(0)


def op_limited(persisted: UInt64) -> Bool:
    """True once the 4194304-attempt cap is reached."""
    return persisted >= UInt64(MAX_OPS)


def checked_add(a: UInt64, b: UInt64) -> UInt64:
    """Saturating add: overflow pins at MAX (deadline math)."""
    if b > u64_max() - a:
        return u64_max()
    return a + b


def _cut_utf8(raw: Span[UInt8, ...], limit: Int) -> List[UInt8]:
    """Truncate bytes to limit without splitting a codepoint."""
    var n = len(raw)
    if n > limit:
        n = limit
    while n > 0 and (raw[n - 1] & UInt8(0xC0)) == UInt8(0x80):
        n -= 1
    var out = List[UInt8]()
    for i in range(n):
        out.append(raw[i])
    return out^


def truncate_text(text: String, limit: Int) -> String:
    """Bound evidence text; invalid UTF-8 becomes empty."""
    var cut = _cut_utf8(text.as_bytes(), limit)
    try:
        return String(from_utf8=Span(cut))
    except:
        return String("")


def stable_cut(
    first: List[UInt64], second: List[UInt64]
) -> Bool:
    """True when two consecutive full reads agree exactly."""
    if len(first) != 6 or len(second) != 6:
        return False
    for i in range(6):
        if first[i] != second[i]:
            return False
    return True


def count_identity(vals: List[UInt64]) -> Bool:
    """observed == emitted + submit_fail without wraparound."""
    if len(vals) != 6:
        return False
    var observed = vals[CNT_OBSERVED]
    var emitted = vals[CNT_EMITTED]
    var failed = vals[CNT_SUBMIT_FAIL]
    if emitted > u64_max() - failed:
        return False
    return observed == emitted + failed


def byte_identity(vals: List[UInt64]) -> Bool:
    """observed_bytes covers emitted_bytes (no silent loss)."""
    if len(vals) != 6:
        return False
    return vals[CNT_OBSERVED_BYTES] >= vals[CNT_EMITTED_BYTES]


def counters_valid(vals: List[UInt64]) -> Bool:
    """All five availability rows valid (section 1.2 matrix)."""
    if len(vals) != 6:
        return False
    var flags = vals[CNT_FLAGS]
    if flags & FLAG_OBSERVED_WRAP != UInt64(0):
        return False
    if flags & FLAG_OBSERVED_BYTES_WRAP != UInt64(0):
        return False
    if flags & FLAG_EMITTED_WRAP != UInt64(0):
        return False
    if flags & FLAG_EMITTED_BYTES_WRAP != UInt64(0):
        return False
    if flags & FLAG_SUBMIT_WRAP != UInt64(0):
        return False
    return True


def byte_coverage_valid(vals: List[UInt64]) -> Bool:
    """Byte aggregate coverable: flags fully clear + identity."""
    if len(vals) != 6:
        return False
    if vals[CNT_FLAGS] != UInt64(0):
        return False
    return byte_identity(vals)


def submit_valid(vals: List[UInt64]) -> Bool:
    if len(vals) != 6:
        return False
    return vals[CNT_FLAGS] & FLAG_SUBMIT_WRAP == UInt64(0)


def all_zero(vals: List[UInt64]) -> Bool:
    if len(vals) != 6:
        return False
    for i in range(6):
        if vals[i] != UInt64(0):
            return False
    return True


def _pair(name: String, value: String) -> String:
    return name + String("=(") + value + String(")")


def detail_reason_known(
    submit_fail: UInt64,
    malformed: UInt64,
    dropped: UInt64,
    size_omitted: UInt64,
    duration_omitted: UInt64,
    signal_omitted: UInt64,
    rejected: UInt64,
    write_failed: UInt64,
) -> String:
    """Strict `detail loss <N> (<8 pairs>)` grammar."""
    var total = (
        submit_fail
        + malformed
        + dropped
        + size_omitted
        + duration_omitted
        + signal_omitted
        + rejected
        + write_failed
    )
    var pairs = _pair(String("submit_fail"), format_u64(submit_fail))
    pairs += String(" ") + _pair(String("malformed"), format_u64(malformed))
    pairs += String(" ") + _pair(String("dropped"), format_u64(dropped))
    pairs += String(" ") + _pair(
        String("size_omitted"), format_u64(size_omitted)
    )
    pairs += String(" ") + _pair(
        String("duration_omitted"), format_u64(duration_omitted)
    )
    pairs += String(" ") + _pair(
        String("signal_omitted"), format_u64(signal_omitted)
    )
    pairs += String(" ") + _pair(String("rejected"), format_u64(rejected))
    pairs += String(" ") + _pair(
        String("write_failed"), format_u64(write_failed)
    )
    return (
        String("detail loss ")
        + format_u64(total)
        + String(" (")
        + pairs
        + String(")")
    )


def detail_reason_unknown(
    cause: String,
    submit_fail: String,
    malformed: String,
    dropped: String,
    size_omitted: UInt64,
    duration_omitted: UInt64,
    signal_omitted: UInt64,
    rejected: UInt64,
    write_failed: UInt64,
) -> String:
    """Strict `detail loss unknown (<cause>; known: ...)` grammar."""
    var pairs = _pair(String("submit_fail"), submit_fail)
    pairs += String(" ") + _pair(String("malformed"), malformed)
    pairs += String(" ") + _pair(String("dropped"), dropped)
    pairs += String(" ") + _pair(
        String("size_omitted"), format_u64(size_omitted)
    )
    pairs += String(" ") + _pair(
        String("duration_omitted"), format_u64(duration_omitted)
    )
    pairs += String(" ") + _pair(
        String("signal_omitted"), format_u64(signal_omitted)
    )
    pairs += String(" ") + _pair(String("rejected"), format_u64(rejected))
    pairs += String(" ") + _pair(
        String("write_failed"), format_u64(write_failed)
    )
    return (
        String("detail loss unknown (")
        + cause
        + String("; known: ")
        + pairs
        + String(")")
    )


def aggregate_reason(present: Bool, cause: String) -> String:
    if present:
        return String(
            "counter snapshots present "
            "(valid cut, identity holds, coverage valid)"
        )
    return String("counter snapshots absent (") + cause + String(")")


def env_mode_for(guest: GuestInfo) -> String:
    if guest.tech == String("snp"):
        return String("sev_snp")
    if guest.tech == String("tdx"):
        return String("tdx")
    if guest.tech == String("sev-classic"):
        return String("sev")
    if guest.tech == String("ordinary"):
        return String("none")
    return String("unknown")


def detection_for(guest: GuestInfo) -> String:
    if guest.conflict != String(""):
        return String("conflicting")
    if guest.tech == String("unknown"):
        return String("unverified")
    return String("kernel_reported")


struct Collector:
    """One capture run: state machine over injected sources.

    Sources arrive per call (never stored), so scripted
    harnesses keep ownership for post-run assertions.
    Buckets are exact u64 tallies; the latch and result
    state follow the section 2 rules.
    """

    var cfg: CollectorConfig
    var stop_reason: String
    var result_state: String
    var unknown_cause: String
    var persisted: UInt64
    var persisted_sum: UInt64
    var size_omitted: UInt64
    var duration_omitted: UInt64
    var signal_omitted: UInt64
    var rejected: UInt64
    var write_failed: UInt64
    var max_persisted_ts: UInt64
    var start_ns: UInt64
    var max_snap_ts: UInt64
    var next_seq: UInt64
    var table: DeviceTable
    var session_id: String
    var t_close: UInt64
    var end_ns: UInt64
    var start_vals: List[UInt64]
    var end_vals: List[UInt64]
    var has_end_cut: Bool
    var start_pair_ts: UInt64
    var end_pair_ts: UInt64
    var stats_start: StatsOut
    var stats_drain: StatsOut
    var stats_final: StatsOut
    var has_final_stats: Bool
    var closing_error: Bool
    var snapshots_present: Bool
    var attach_ns: UInt64
    var detach_ns: UInt64
    var secondary_causes: List[String]
    var signal_error: String
    var output_fs: String
    var pool_baseline: NormalizedPoolSample
    var pool_baseline_ts: UInt64
    var pool_has_baseline: Bool
    var pool_final: NormalizedPoolSample
    var pool_final_ts: UInt64
    var pool_has_final: Bool
    var pool_ok: Bool
    var pool_reason: String

    def __init__(out self, cfg: CollectorConfig):
        self.cfg = cfg.copy()
        self.stop_reason = String("")
        self.result_state = String("ok")
        self.unknown_cause = String("")
        self.persisted = UInt64(0)
        self.persisted_sum = UInt64(0)
        self.size_omitted = UInt64(0)
        self.duration_omitted = UInt64(0)
        self.signal_omitted = UInt64(0)
        self.rejected = UInt64(0)
        self.write_failed = UInt64(0)
        self.max_persisted_ts = UInt64(0)
        self.start_ns = UInt64(0)
        self.max_snap_ts = UInt64(0)
        self.next_seq = UInt64(0)
        self.table = DeviceTable()
        self.session_id = String("")
        self.t_close = UInt64(0)
        self.end_ns = UInt64(0)
        self.start_vals = List[UInt64]()
        self.end_vals = List[UInt64]()
        self.has_end_cut = False
        self.start_pair_ts = UInt64(0)
        self.end_pair_ts = UInt64(0)
        self.stats_start = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_drain = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_final = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.has_final_stats = False
        self.closing_error = False
        self.snapshots_present = False
        self.attach_ns = UInt64(0)
        self.detach_ns = UInt64(0)
        self.secondary_causes = List[String]()
        self.signal_error = String("")
        self.output_fs = String("")
        self.pool_baseline = NormalizedPoolSample()
        self.pool_baseline_ts = UInt64(0)
        self.pool_has_baseline = False
        self.pool_final = NormalizedPoolSample()
        self.pool_final_ts = UInt64(0)
        self.pool_has_final = False
        self.pool_ok = False
        self.pool_reason = String("")

    def note_unknown(mut self, cause: String):
        """First deviation wins; later ones are retained."""
        if self.unknown_cause == String(""):
            self.unknown_cause = cause
            return
        if cause == self.unknown_cause:
            return
        if len(self.secondary_causes) > 0:
            if cause == self.secondary_causes[len(self.secondary_causes) - 1]:
                return
        self.secondary_causes.append(cause)

    def latch(mut self, reason: String):
        """Immutable first trigger; empty latches once."""
        if self.stop_reason == String(""):
            self.stop_reason = reason

    def fail(mut self, reason: String):
        """Error trigger: immutable latch + monotonic error."""
        self.latch(reason)
        self.result_state = String("error")

    def omit_for_latch(mut self):
        """Count one crossed/drained record to the latch."""
        if self.stop_reason == String("duration"):
            self.duration_omitted += UInt64(1)
        elif self.stop_reason == String("size_limit"):
            self.size_omitted += UInt64(1)
        elif self.stop_reason == String("signal"):
            self.signal_omitted += UInt64(1)

    def stable_pair[
        K: KernelSource, C: ClockSource
    ](mut self, mut kernel: K, mut clock: C) -> Bool:
        """Run the stable protocol; on success store the cut.

        Reads full 6-entry vectors until two consecutive
        agree (bounded pairs) or any read fails over. The
        second read's timestamp stamps the pair; every
        reading's timestamp feeds max_snap_ts.
        """
        for _ in range(STABLE_PAIRS):
            var first = kernel.read_full()
            if not first.ok:
                continue
            var ts_first = clock.now()
            if ts_first > self.max_snap_ts:
                self.max_snap_ts = ts_first
            var second = kernel.read_full()
            if not second.ok:
                continue
            var ts_second = clock.now()
            if ts_second > self.max_snap_ts:
                self.max_snap_ts = ts_second
            if stable_cut(first.vals, second.vals):
                self.end_vals = second.vals.copy()
                self.end_pair_ts = ts_second
                self.has_end_cut = True
                return True
        return False

    def run[K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource](
        mut self, mut kernel: K, mut clock: C, mut signal: G,
        mut writer: W,
    ) -> RunResult:
        """Full run: start, collect, close, finalize."""
        var refusal = self.startup(kernel, clock, signal, writer)
        if refusal != String(""):
            return self.refuse(kernel, writer, refusal)
        var stop = self.poll_loop(kernel, clock, signal, writer)
        if stop == String("error-path"):
            return self.error_close(kernel, clock, writer)
        if stop == String("unfinalizable"):
            return self.drop_unfinalizable(writer)
        self.normal_close(kernel, clock, writer)
        if self.result_state == String("unfinalizable"):
            return self.drop_unfinalizable(writer)
        return self.finish(clock, writer)

    def refuse[
        K: KernelSource, W: WriterSource
    ](mut self, mut kernel: K, mut writer: W, reason: String) -> RunResult:
        """Clean rollback after a pre-readiness failure."""
        var residual = writer.abandon()
        var closed = kernel.close()
        if residual != String("") or not closed.ok:
            var diag = reason
            if residual != String(""):
                diag += String("; writer residual: ") + residual
            if not closed.ok:
                diag += String("; close: ") + closed.message
            return RunResult(EXIT_ERROR, String("unknown"), String("refusal-rollback-failed"), diag)
        return RunResult(EXIT_REFUSAL, String("unknown"), String("refused"), reason)

    def startup[
        K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, mut kernel: K, mut clock: C, mut signal: G,
        mut writer: W,
    ) -> String:
        """Transactional start; "" means ready, else the reason."""
        var sig_ready = signal.setup()
        if not sig_ready.ok:
            return String("signal setup: ") + sig_ready.message
        self.start_ns = clock.now()
        self.max_persisted_ts = self.start_ns
        self.session_id = (
            String("cap-")
            + format_u64(self.start_ns)
            + String("-")
            + String(self.cfg.pid)
        )
        var opened = kernel.open_session()
        if not opened.ok:
            return String("open: ") + opened.message
        var loaded = kernel.load()
        if not loaded.ok:
            return String("load: ") + loaded.message
        var counts = kernel.map_info(String("mv_counts"))
        if not counts.ok:
            return String("map mv_counts: ") + counts.message
        if (
            counts.map_type != UInt32(MAP_TYPE_ARRAY)
            or counts.key_size != UInt32(4)
            or counts.value_size != UInt32(8)
            or counts.max_entries != UInt32(6)
        ):
            return String("map mv_counts geometry")
        var ring = kernel.map_info(String("mv_attempts"))
        if not ring.ok:
            return String("map mv_attempts: ") + ring.message
        if ring.map_type != UInt32(MAP_TYPE_RINGBUF):
            return String("map mv_attempts geometry")
        if self.cfg.has_ring_bytes and ring.max_entries != self.cfg.ring_bytes:
            return String("map mv_attempts ring size")
        if not self.stable_pair(kernel, clock):
            return String("start snapshot unresolved")
        self.start_vals = self.end_vals.copy()
        self.start_pair_ts = self.end_pair_ts
        self.has_end_cut = False
        if not all_zero(self.start_vals):
            return String("start snapshot nonzero")
        var baseline = kernel.stats()
        if not baseline.ok:
            return String("start stats: ") + baseline.message
        self.stats_start = baseline.copy()
        var made = writer.create(self.cfg.output, self.cfg.max_events_bytes)
        if not made.ok:
            return String("output ") + made.kind + String(": ") + made.message
        self.output_fs = fs_type_name(self.cfg.output)
        var attached = kernel.attach()
        if not attached.ok:
            return String("attach: ") + attached.message
        self.attach_ns = clock.now()
        if self.cfg.has_pool_sample:
            # Baseline pool sample, held for the closing path:
            # pool samples are not bridge-delivered, so they
            # persist as closing records, never as poll output.
            var base = self._sample_pool_now(clock)
            self.pool_baseline = base[0]
            self.pool_baseline_ts = base[1]
            self.pool_has_baseline = True
        print(
            String("ready session=")
            + self.session_id
            + String(" start_ns=")
            + format_u64(self.start_ns)
        )
        return String("")

    def poll_one[K: KernelSource](
        mut self, mut kernel: K, timeout_ms: Int
    ) -> PollOut:
        """One resolved poll: shorts retried once at size.

        Returns timeout, batch, or error. A second short,
        a zero required size, or a timeout after a short
        (retained record lost) is a transport violation.
        """
        var out = kernel.poll(timeout_ms, UInt32(65536))
        if out.kind != String("short"):
            return out^
        if out.required == UInt32(0):
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("short without size"),
            )
        var retry = kernel.poll(0, out.required)
        if retry.kind == String("batch"):
            return retry^
        if retry.kind == String("timeout"):
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("retained record lost"),
            )
        if retry.kind == String("short"):
            return PollOut(
                String("error"), List[UInt8](), UInt32(0),
                String("repeated short"),
            )
        return retry^

    def poll_loop[
        K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, mut kernel: K, mut clock: C, mut signal: G,
        mut writer: W,
    ) -> String:
        """Collect until a latch; error-path/unfinalizable/closed."""
        var dur_ns = u64_max()
        if self.cfg.duration_s <= u64_max() // UInt64(1000000000):
            dur_ns = self.cfg.duration_s * UInt64(1000000000)
        # The duration budget starts at readiness (attach),
        # not at pre-init: init latency must not burn it.
        var deadline = checked_add(self.attach_ns, dur_ns)
        while True:
            var sig = signal.check()
            if sig.state == String("pending"):
                self.latch(String("signal"))
                return String("closed")
            if sig.state == String("error"):
                self.latch(String("signal"))
                self.result_state = String("error")
                self.signal_error = sig.message
                return String("closed")
            var now = clock.now()
            if now >= deadline:
                self.latch(String("duration"))
                return String("closed")
            var remaining_ms = (deadline - now) // UInt64(1000000)
            var wait = POLL_QUANTUM_MS
            if remaining_ms < UInt64(wait):
                wait = Int(remaining_ms)
            var out = self.poll_one(kernel, wait)
            if out.kind == String("timeout"):
                continue
            if out.kind == String("error"):
                self.fail(String("error"))
                return String("error-path")
            var verdict = self.admit(
                out.frame, kernel, clock, signal, writer, deadline
            )
            if verdict != String(""):
                return verdict

    def admit[
        K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, frame: List[UInt8], mut kernel: K, mut clock: C,
        mut signal: G, mut writer: W, deadline: UInt64,
    ) -> String:
        """Dispose one delivered batch; "" continues the loop."""
        var payload: List[UInt8]
        try:
            var decoded_frame = decode_frame(Span(frame), 0, UInt32(len(frame)))
            payload = decoded_frame.payload.copy()
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var attempt: DecodedAttempt
        try:
            attempt = decode_payload(payload)
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var sig = signal.check()
        if sig.state == String("pending"):
            self.latch(String("signal"))
            self.omit_for_latch()
            return String("closed")
        if sig.state == String("error"):
            self.latch(String("signal"))
            self.result_state = String("error")
            self.signal_error = sig.message
            self.omit_for_latch()
            return String("closed")
        var now = clock.now()
        if now >= deadline:
            self.latch(String("duration"))
            self.omit_for_latch()
            return String("closed")
        if op_limited(self.persisted):
            self.latch(String("size_limit"))
            self.omit_for_latch()
            return String("closed")
        var normalized: NormalizedAttempt
        try:
            normalized = normalize_attempt(attempt, self.table)
        except e:
            if e.reason == String("UTF8") and not e.fatal:
                self.rejected += UInt64(1)
                return String("")
            self.rejected += UInt64(1)
            if e.reason == String("INTERNAL"):
                self.result_state = String("unfinalizable")
                return String("unfinalizable")
            self.fail(String("error"))
            return String("error-path")
        if normalized.requested_bytes > u64_max() - self.persisted_sum:
            self.latch(String("size_limit"))
            self.omit_for_latch()
            return String("closed")
        var line: List[UInt8]
        try:
            line = self.encode_attempt(normalized)
        except:
            self.result_state = String("unfinalizable")
            return String("unfinalizable")
        var wrote = writer.append(line)
        if wrote.ok:
            self.persisted += UInt64(1)
            self.persisted_sum += normalized.requested_bytes
            if normalized.ts_ns > self.max_persisted_ts:
                self.max_persisted_ts = normalized.ts_ns
            return String("")
        if wrote.kind == String("refused"):
            self.next_seq -= UInt64(1)
            self.latch(String("size_limit"))
            self.omit_for_latch()
            return String("closed")
        self.next_seq -= UInt64(1)
        self.write_failed += UInt64(1)
        if wrote.kind == String("fatal") or wrote.kind == String("misuse"):
            self.result_state = String("unfinalizable")
            return String("unfinalizable")
        self.fail(String("error"))
        return String("error-path")

    def normal_close[K: KernelSource, C: ClockSource, W: WriterSource](
        mut self, mut kernel: K, mut clock: C, mut writer: W
    ):
        """DETACHING -> SETTLE -> DRAINING -> STATS -> CONFIRM."""
        var detached = kernel.detach()
        self.detach_ns = clock.now()
        if not detached.ok:
            self.note_unknown(String("detach failed; shutdown evidence unresolved"))
        clock.sleep_ms(SETTLE_MS)
        self.drain(kernel, clock)
        if not self.stable_pair(kernel, clock):
            self.note_unknown(String("snapshot unresolved"))
            self.has_end_cut = False
        else:
            var guard = 0
            var last_ts = self.end_pair_ts
            while last_ts <= self.max_persisted_ts and guard < ADVANCE_MAX:
                last_ts = clock.now()
                guard += 1
        var drain_stats = kernel.stats()
        if drain_stats.ok:
            self.stats_drain = drain_stats.copy()
        else:
            self.note_unknown(String("error shutdown"))
        self.confirm(kernel)
        if self.cfg.has_pool_sample:
            # Final pool sample, held for the closing path with
            # its true timestamp (always before t_close, so the
            # window end covers it).
            var fin = self._sample_pool_now(clock)
            self.pool_final = fin[0]
            self.pool_final_ts = fin[1]
            self.pool_has_final = True

    def drain[K: KernelSource, C: ClockSource](
        mut self, mut kernel: K, mut clock: C
    ):
        """Bounded consume-and-count; every record omitted."""
        var start = clock.now()
        var budget_s = checked_add(start, UInt64(DRAIN_MAX_S) * UInt64(1000000000))
        var prev_received = u64_max()
        var prev_malformed = u64_max()
        var have_prev = False
        for _ in range(DRAIN_MAX_POLLS):
            var now = clock.now()
            if now >= budget_s:
                self.note_unknown(String("drain budget exhausted"))
                return
            var out = self.poll_one(kernel, 0)
            if out.kind == String("batch"):
                self.omit_for_latch()
                continue
            if out.kind != String("timeout"):
                self.note_unknown(String("error shutdown"))
                self.result_state = String("error")
                return
            var stats = kernel.stats()
            if not stats.ok:
                self.note_unknown(String("error shutdown"))
                return
            if have_prev and stats.staged == UInt64(0):
                if (
                    stats.received == prev_received
                    and stats.malformed == prev_malformed
                ):
                    return
            prev_received = stats.received
            prev_malformed = stats.malformed
            have_prev = True
        self.note_unknown(String("drain budget exhausted"))

    def confirm[K: KernelSource](mut self, mut kernel: K):
        """Bounded confirmation drain after the end snapshot."""
        for _ in range(CONFIRM_POLLS):
            var out = self.poll_one(kernel, 0)
            if out.kind == String("batch"):
                self.omit_for_latch()
                self.note_unknown(String("post-snapshot activity"))
            elif out.kind != String("timeout"):
                self.note_unknown(String("error shutdown"))
                self.result_state = String("error")
                return
        var final = kernel.stats()
        if not final.ok:
            self.note_unknown(String("error shutdown"))
            return
        self.stats_final = final.copy()
        self.has_final_stats = True
        if self.stats_drain.ok:
            if (
                final.received != self.stats_drain.received
                or final.malformed != self.stats_drain.malformed
            ):
                self.note_unknown(String("post-snapshot activity"))

    def error_close[K: KernelSource, C: ClockSource, W: WriterSource](
        mut self, mut kernel: K, mut clock: C, mut writer: W
    ) -> RunResult:
        """ERROR_DETACH -> ERROR_STATS -> FINALIZING; no drain."""
        var detached = kernel.detach()
        self.detach_ns = clock.now()
        if not detached.ok:
            self.note_unknown(String("detach failed; shutdown evidence unresolved"))
        var final = kernel.stats()
        if final.ok:
            self.stats_final = final.copy()
            self.has_final_stats = True
        if not self.stable_pair(kernel, clock):
            self.note_unknown(String("snapshot unresolved"))
            self.has_end_cut = False
        if self.cfg.has_pool_sample:
            var fin = self._sample_pool_now(clock)
            self.pool_final = fin[0]
            self.pool_final_ts = fin[1]
            self.pool_has_final = True
        if self.unknown_cause == String(""):
            self.note_unknown(String("error shutdown"))
        return self.finish(clock, writer)

    def fill_source(mut self, mut ev: Event):
        """Stamp the explicit source block on one event."""
        ev.session_id = self.session_id
        ev.seq = self.next_seq
        self.next_seq += UInt64(1)
        ev.source_hook = String("swiotlb:swiotlb_bounced")
        ev.source_backend = String("tracepoint")
        ev.source_profile_id = self.cfg.profile_id
        ev.source_measurement = String("observed")
        ev.source_correlation = String("direct")

    def encode_attempt(
        mut self, normalized: NormalizedAttempt
    ) raises EncodeError -> List[UInt8]:
        var ev = Event()
        self.fill_source(ev)
        ev.ts_ns = normalized.ts_ns
        ev.kind = String("bounce_attempt")
        ev.bounce = BounceAttempt()
        ev.bounce.device_id = normalized.device_id
        ev.bounce.requested_bytes = normalized.requested_bytes
        ev.bounce.forced = normalized.forced
        ev.bounce.operation_id = normalized.operation_id
        return encode_event_line(ev)

    def _sample_pool_now[C: ClockSource](
        self, mut clock: C
    ) -> Tuple[NormalizedPoolSample, UInt64]:
        """Sample the default pool now; failures stay in the sample.

        The evidence reader opens the configured root (live host
        when empty, one fixture in tests). An unreadable reader
        yields an unavailable sample, never a failed run.
        """
        var ts = clock.now()
        var sample: NormalizedPoolSample
        try:
            var reader = open_evidence_reader(self.cfg.pool_root)
            sample = sample_default_pool(
                reader,
                POOL_SWIOTLB_POOL_ID,
                UInt64(POOL_SWIOTLB_UNIT),
            )
        except:
            sample = NormalizedPoolSample()
            sample.pool_id = POOL_SWIOTLB_POOL_ID
            sample.allocator = POOL_SWIOTLB_ALLOCATOR
            sample.reason = String("denied")
            sample.notes = String("evidence reader unavailable")
        return (sample, ts)

    def pool_sample_event(
        mut self, sample: NormalizedPoolSample, ts_ns: UInt64
    ) raises EncodeError -> List[UInt8]:
        var ev = Event()
        ev.session_id = self.session_id
        ev.seq = self.next_seq
        self.next_seq += UInt64(1)
        ev.source_hook = String("swiotlb:debugfs")
        ev.source_backend = String("debugfs")
        ev.source_profile_id = self.cfg.profile_id
        ev.source_measurement = String("observed")
        ev.source_correlation = String("direct")
        ev.ts_ns = ts_ns
        ev.kind = String("pool_sample")
        ev.pool = PoolSample()
        ev.pool.pool_id = sample.pool_id
        ev.pool.has_used = sample.has_used_bytes
        ev.pool.used_bytes = sample.used_bytes
        ev.pool.has_capacity = sample.has_capacity_bytes
        ev.pool.capacity_bytes = sample.capacity_bytes
        ev.pool.unit = sample.unit
        ev.pool.allocator = sample.allocator
        ev.pool.has_unit_bytes = sample.has_unit_bytes
        ev.pool.unit_bytes = sample.unit_bytes
        ev.pool.has_hiwater = sample.has_hiwater_bytes
        ev.pool.hiwater_bytes = sample.hiwater_bytes
        ev.pool.reason = sample.reason
        return encode_event_line(ev)

    def snapshot_event(
        mut self, counter_id: String, value: UInt64, unit: String,
        ts_ns: UInt64,
    ) raises EncodeError -> List[UInt8]:
        var ev = Event()
        self.fill_source(ev)
        ev.ts_ns = ts_ns
        ev.kind = String("counter_snapshot")
        ev.snapshot = CounterSnapshot()
        ev.snapshot.counter_id = counter_id
        ev.snapshot.epoch = UInt64(0)
        ev.snapshot.has_scope_device = False
        ev.snapshot.scope_profile_id = self.cfg.profile_id
        ev.snapshot.value = value
        ev.snapshot.unit = unit
        return encode_event_line(ev)

    def gap_event(mut self) raises EncodeError -> List[UInt8]:
        var ev = Event()
        self.fill_source(ev)
        ev.ts_ns = self.t_close
        ev.kind = String("gap")
        ev.gap = Gap()
        ev.gap.channel = String("detail")
        ev.gap.has_lost_count = False
        ev.gap.lost_count = UInt64(0)
        ev.gap.reason = (
            String("detail closure unproven: ") + self.unknown_cause
        )
        ev.gap.window_start_ns = self.attach_ns
        ev.gap.window_end_ns = self.end_ns
        return encode_event_line(ev)

    def snapshots_eligible(self) -> Bool:
        """The three section 4.1 emission gates."""
        if not self.has_end_cut:
            return False
        if not all_zero(self.start_vals):
            return False
        if not counters_valid(self.end_vals):
            return False
        if not count_identity(self.end_vals):
            return False
        return byte_coverage_valid(self.end_vals)

    def snapshot_gate_cause(self) -> String:
        """First failing gate, for the aggregate reason."""
        if not self.has_end_cut:
            return String("no stable cut")
        if not counters_valid(self.end_vals):
            return String("invalid epoch")
        if not count_identity(self.end_vals):
            return String("count identity unproven")
        return String("byte coverage invalid")

    def persist_pool_sample[W: WriterSource](
        mut self, mut writer: W, sample: NormalizedPoolSample,
        ts_ns: UInt64,
    ):
        """Append one pool sample as a closing record.

        Pool samples are not bridge-delivered, so they never
        touch poll/attempt counters; only the persisted-ts
        maximum moves, honestly covering them. A failed sample
        degrades the run to error state like a failed gap,
        since the closing record set is incomplete.
        """
        var line: List[UInt8]
        try:
            line = self.pool_sample_event(sample, ts_ns)
        except:
            self.next_seq -= UInt64(1)
            self.closing_error = True
            self.result_state = String("error")
            return
        var wrote = writer.append_closing(line)
        if wrote.ok:
            if sample.has_used_bytes or sample.has_capacity_bytes:
                self.pool_ok = True
            if ts_ns > self.max_persisted_ts:
                self.max_persisted_ts = ts_ns
            if self.pool_reason == String(""):
                if sample.reason != String(""):
                    self.pool_reason = sample.reason
            return
        self.next_seq -= UInt64(1)
        self.closing_error = True
        self.result_state = String("error")

    def closing_records[W: WriterSource](mut self, mut writer: W) -> String:
        """Append snapshots (rollback group) + pool + gap; "" or fatal."""
        if self.snapshots_eligible():
            var begun = writer.group_begin()
            if not begun.ok:
                self.result_state = String("unfinalizable")
                return String("unfinalizable")
            var mark = begun.mark
            var seq_mark = self.next_seq
            var failed = False
            try:
                var lines = List[List[UInt8]]()
                lines.append(
                    self.snapshot_event(
                        String("swiotlb.bounce_attempts"),
                        self.start_vals[CNT_OBSERVED],
                        String("count"),
                        self.start_pair_ts,
                    )
                )
                lines.append(
                    self.snapshot_event(
                        String("swiotlb.requested_bytes"),
                        self.start_vals[CNT_OBSERVED_BYTES],
                        String("bytes"),
                        self.start_pair_ts,
                    )
                )
                lines.append(
                    self.snapshot_event(
                        String("swiotlb.bounce_attempts"),
                        self.end_vals[CNT_OBSERVED],
                        String("count"),
                        self.end_pair_ts,
                    )
                )
                lines.append(
                    self.snapshot_event(
                        String("swiotlb.requested_bytes"),
                        self.end_vals[CNT_OBSERVED_BYTES],
                        String("bytes"),
                        self.end_pair_ts,
                    )
                )
                for i in range(4):
                    var wrote = writer.append_closing(lines[i])
                    if not wrote.ok:
                        failed = True
                        break
            except:
                failed = True
            if failed:
                var back = writer.group_abort(mark)
                if not back.ok:
                    self.result_state = String("unfinalizable")
                    return String("unfinalizable")
                self.next_seq = seq_mark
                self.snapshots_present = False
                self.closing_error = True
                self.result_state = String("error")
            else:
                self.snapshots_present = True
        if self.pool_has_baseline:
            var base = self.pool_baseline
            var base_ts = self.pool_baseline_ts
            self.persist_pool_sample(writer, base, base_ts)
        if self.pool_has_final:
            var fin = self.pool_final
            var fin_ts = self.pool_final_ts
            self.persist_pool_sample(writer, fin, fin_ts)
        if self.unknown_cause != String(""):
            try:
                var gap = self.gap_event()
                var wrote = writer.append_closing(gap)
                if not wrote.ok:
                    self.next_seq -= UInt64(1)
                    self.closing_error = True
                    self.result_state = String("error")
            except:
                self.next_seq -= UInt64(1)
                self.closing_error = True
                self.result_state = String("error")
        return String("")

    def evaluate(mut self) -> String:
        """Check identities; "" continues, else unfinalizable."""
        if self.has_final_stats:
            var start = self.stats_start.copy()
            var final = self.stats_final.copy()
            if start.staged != UInt64(0):
                return String("unfinalizable")
            if (
                final.received < start.received
                or final.delivered < start.delivered
                or final.malformed < start.malformed
                or final.dropped < start.dropped
            ):
                return String("unfinalizable")
            var received_d = final.received - start.received
            var delivered_d = final.delivered - start.delivered
            var malformed_d = final.malformed - start.malformed
            var dropped_d = final.dropped - start.dropped
            var app_total = (
                self.persisted
                + self.size_omitted
                + self.duration_omitted
                + self.signal_omitted
                + self.rejected
                + self.write_failed
            )
            if delivered_d != app_total:
                return String("unfinalizable")
            var bridge_total = delivered_d + final.staged
            if bridge_total < delivered_d:
                return String("unfinalizable")
            bridge_total += malformed_d
            if bridge_total < malformed_d:
                return String("unfinalizable")
            bridge_total += dropped_d
            if bridge_total < dropped_d:
                return String("unfinalizable")
            if received_d != bridge_total:
                return String("unfinalizable")
            if self.unknown_cause == String("") and final.staged != UInt64(0):
                self.note_unknown(String("error shutdown"))
        if self.has_end_cut:
            var vals = self.end_vals.copy()
            var epoch_ok = (
                vals[CNT_FLAGS] & FLAG_OBSERVED_WRAP == UInt64(0)
                and vals[CNT_FLAGS] & FLAG_EMITTED_WRAP == UInt64(0)
                and vals[CNT_FLAGS] & FLAG_SUBMIT_WRAP == UInt64(0)
            )
            if not epoch_ok:
                self.note_unknown(String("invalid epoch"))
            elif not count_identity(vals):
                self.note_unknown(String("kernel identity unproven"))
            elif self.has_final_stats:
                var emitted = vals[CNT_EMITTED]
                var received_d = (
                    self.stats_final.received - self.stats_start.received
                )
                if received_d != emitted:
                    self.note_unknown(String("ring count unproven"))
        return String("")

    def diagnostic(self, note: String) -> String:
        """Merge the retained signal error with a close note."""
        if self.signal_error == String(""):
            return note
        if note == String(""):
            return String("signal: ") + self.signal_error
        return String("signal: ") + self.signal_error + String("; ") + note

    def drop_unfinalizable[W: WriterSource](mut self, mut writer: W) -> RunResult:
        """Keep the events file for forensics; no session."""
        writer.discard()
        return RunResult(
            EXIT_ERROR, String("error"), String("unfinalizable"),
            self.diagnostic(
                String("local accounting unusable; events kept, no session")
            ),
        )

    def finish[C: ClockSource, W: WriterSource](
        mut self, mut clock: C, mut writer: W
    ) -> RunResult:
        """FINALIZING: stamps, closing, assembly, publication."""
        self.t_close = clock.now()
        var probe = List[UInt64]()
        probe.append(self.t_close)
        probe.append(self.max_snap_ts)
        probe.append(self.max_persisted_ts)
        probe.append(self.start_ns)
        var top = UInt64(0)
        for i in range(len(probe)):
            if probe[i] > top:
                top = probe[i]
        if top == u64_max():
            return self.drop_unfinalizable(writer)
        self.end_ns = top + UInt64(1)
        if self.evaluate() != String(""):
            return self.drop_unfinalizable(writer)
        if self.closing_records(writer) != String(""):
            return self.drop_unfinalizable(writer)
        if not self.contained():
            return self.drop_unfinalizable(writer)
        var session_text: String
        try:
            var session = self.assemble()
            session_text = encode_session(session)
        except:
            return self.drop_unfinalizable(writer)
        var raw = List[UInt8]()
        for b in session_text.as_bytes():
            raw.append(b)
        var done = writer.finalize(raw)
        var reason = self.stop_reason
        if self.result_state == String("error"):
            reason = String("error")
        if done.status == String("finalized"):
            if self.result_state == String("error"):
                return RunResult(
                    EXIT_ERROR, reason, String("error"),
                    self.diagnostic(done.note),
                )
            return RunResult(
                EXIT_PARTIAL, reason, String("finalized"),
                self.diagnostic(String("")),
            )
        if done.status == String("present_unsynced"):
            return RunResult(
                EXIT_ERROR, reason, String("present_unsynced"),
                self.diagnostic(done.note),
            )
        if done.status == String("misuse"):
            return RunResult(
                EXIT_ERROR, reason, String("unfinalizable"),
                self.diagnostic(String("finalize after close")),
            )
        return RunResult(
            EXIT_ERROR, reason, String("unfinalized"),
            self.diagnostic(done.note),
        )

    def contained(self) -> Bool:
        """Every persisted closing stamp lies in [start, end)."""
        if self.snapshots_present:
            if self.start_pair_ts < self.start_ns:
                return False
            if self.start_pair_ts >= self.end_ns:
                return False
            if self.end_pair_ts < self.start_ns:
                return False
            if self.end_pair_ts >= self.end_ns:
                return False
        if self.unknown_cause != String(""):
            if self.t_close < self.start_ns:
                return False
            if self.t_close >= self.end_ns:
                return False
        return True

    def loss_pairs(self) -> List[String]:
        """Kernel/bridge components as decimal-or-unavailable."""
        var submit = String("unavailable")
        var malformed = String("unavailable")
        var dropped = String("unavailable")
        if self.has_end_cut and submit_valid(self.end_vals):
            submit = format_u64(self.end_vals[CNT_SUBMIT_FAIL])
        if self.has_final_stats:
            malformed = format_u64(
                self.stats_final.malformed - self.stats_start.malformed
            )
            dropped = format_u64(
                self.stats_final.dropped - self.stats_start.dropped
            )
        var out = List[String]()
        out.append(submit)
        out.append(malformed)
        out.append(dropped)
        return out^

    def loss_known(self) -> Bool:
        """Proven closure with every component exact."""
        if self.unknown_cause != String(""):
            return False
        if not self.has_end_cut or not self.has_final_stats:
            return False
        if not submit_valid(self.end_vals):
            return False
        return True

    def assemble(mut self) raises EncodeError -> Session:
        """Build the session header for the closed capture."""
        var out = Session()
        out.session_id = self.session_id
        out.has_boot_id = self.cfg.has_boot_id
        out.boot_id = self.cfg.boot_id
        out.synthetic = False
        out.product_name = String("memveil")
        out.product_version = String(ENGINE_VERSION)
        out.has_build = False
        out.env_mode = env_mode_for(self.cfg.guest)
        out.env_detection = detection_for(self.cfg.guest)
        out.has_asserted_mode = False
        out.asserted_mode_present = False
        out.env_attestation = String("not_performed")
        out.capture_mode = String("live")
        out.window_start_ns = self.attach_ns
        out.window_end_ns = self.end_ns
        out.has_baseline_start_ns = True
        out.baseline_start_ns = self.start_pair_ts
        out.has_filter_device = False
        out.finalized = True
        out.has_end_reason = True
        out.end_reason = self.stop_reason
        if self.result_state == String("error"):
            out.end_reason = String("error")
        try:
            var catalog = self.table.entries()
            for i in range(len(catalog)):
                var entry = DeviceEntry()
                entry.device_id = catalog[i].device_id
                entry.name = catalog[i].name
                entry.has_driver = False
                entry.driver_present = True
                entry.identity_status = String("unresolved")
                out.devices.append(entry^)
        except:
            raise EncodeError(
                String("device_catalog"), String("catalog unusable")
            )
        out.baseline_complete = False
        out.baseline_region_count = 0
        var cap = Capability()
        cap.status = String("partial")
        cap.reason = (
            String("capture ")
            + self.result_state
            + String(", ")
            + format_u64(self.persisted)
            + String(" attempts persisted; admitted under ")
            + self.cfg.profile_id
            + String("; device detail grouped by observed name scope")
        )
        cap.hooks.append(String("swiotlb:swiotlb_bounced"))
        cap.has_profile_id = True
        cap.profile_id = self.cfg.profile_id
        out.cap_bounce_attempts = cap^
        self.unavailable_cap(
            out.cap_mapping_lifecycle,
            String("No map_result source in this capture."),
        )
        self.unavailable_cap(
            out.cap_copy_bytes,
            String("No copy source in this capture."),
        )
        self.unavailable_cap(
            out.cap_sync_requests,
            String("No sync source in this capture."),
        )
        self.unavailable_cap(
            out.cap_conversion_results,
            String("No conversion source in this capture."),
        )
        self.unavailable_cap(
            out.cap_region_state,
            String("No region source in this capture."),
        )
        if self.pool_ok:
            var pcap = Capability()
            pcap.status = String("partial")
            pcap.reason = String(
                "default-pool debugfs samples at capture start"
                " and close; no continuous occupancy"
            )
            pcap.hooks.append(String("swiotlb:debugfs"))
            pcap.has_profile_id = True
            pcap.profile_id = self.cfg.profile_id
            out.cap_pool_stats = pcap^
        elif self.cfg.has_pool_sample:
            var why = self.pool_reason
            if why == String(""):
                why = String("unreadable")
            self.unavailable_cap(
                out.cap_pool_stats,
                String("pool counters unreadable: ") + why,
            )
        else:
            self.unavailable_cap(
                out.cap_pool_stats,
                String("No pool source in this capture."),
            )
        self.unavailable_cap(
            out.cap_task_context,
            String("No observer context in this capture."),
        )
        var pairs = self.loss_pairs()
        var scope = (
            format_u64(self.persisted) + String(" bounce_attempt events")
        )
        if self.loss_known():
            var total = (
                self.end_vals[CNT_SUBMIT_FAIL]
                + (self.stats_final.malformed - self.stats_start.malformed)
                + (self.stats_final.dropped - self.stats_start.dropped)
                + self.size_omitted
                + self.duration_omitted
                + self.signal_omitted
                + self.rejected
                + self.write_failed
            )
            if total == UInt64(0):
                out.q_detail.status = String("complete_for_scope")
            else:
                out.q_detail.status = String("partial")
            out.q_detail.has_loss_count = True
            out.q_detail.loss_count = total
            out.q_detail.reason = detail_reason_known(
                self.end_vals[CNT_SUBMIT_FAIL],
                self.stats_final.malformed - self.stats_start.malformed,
                self.stats_final.dropped - self.stats_start.dropped,
                self.size_omitted,
                self.duration_omitted,
                self.signal_omitted,
                self.rejected,
                self.write_failed,
            )
        else:
            out.q_detail.status = String("partial")
            out.q_detail.has_loss_count = False
            out.q_detail.reason = detail_reason_unknown(
                self.unknown_cause,
                pairs[0],
                pairs[1],
                pairs[2],
                self.size_omitted,
                self.duration_omitted,
                self.signal_omitted,
                self.rejected,
                self.write_failed,
            )
        out.q_detail.scope = scope
        if self.snapshots_present:
            out.q_aggregate.status = String("complete_for_scope")
            out.q_aggregate.has_loss_count = True
            out.q_aggregate.loss_count = UInt64(0)
            out.q_aggregate.reason = aggregate_reason(True, String(""))
        else:
            out.q_aggregate.status = String("unavailable")
            out.q_aggregate.has_loss_count = False
            out.q_aggregate.reason = aggregate_reason(
                False, self.snapshot_gate_cause()
            )
        out.q_aggregate.scope = String("counter snapshots")
        out.q_correlation.status = String("not_applicable")
        out.q_correlation.has_loss_count = False
        out.q_correlation.scope = String("attempt counting")
        out.q_correlation.reason = String(
            "Attempt counting needs no cross-event correlation."
        )
        out.q_baseline.status = String("not_applicable")
        out.q_baseline.has_loss_count = False
        out.q_baseline.scope = String("attempt metrics")
        out.q_baseline.reason = String("Attempt metrics need no baseline.")
        out.q_terminal.status = String("partial")
        out.q_terminal.has_loss_count = False
        out.q_terminal.scope = String("capture finalization")
        out.q_terminal.reason = String(
            "terminal settlement unproven; stop protocol not yet proven"
        )
        for i in range(len(self.cfg.evidence)):
            var item = self.cfg.evidence[i]
            var kept = EvidenceItem()
            kept.item_type = String("provenance")
            kept.source = truncate_text(item.source, 128)
            if kept.source == String(""):
                kept.source = String("undecodable")
            kept.interpretation = truncate_text(item.interpretation, 512)
            out.evidence.append(kept^)
        self.provenance(
            out,
            String("attach_ns"),
            format_u64(self.attach_ns),
        )
        self.provenance(
            out,
            String("detach_ns"),
            format_u64(self.detach_ns),
        )
        if self.unknown_cause == String(""):
            self.provenance(
                out, String("drain_closure"), String("proven")
            )
        else:
            self.provenance(
                out,
                String("drain_closure"),
                String("unknown: ") + self.unknown_cause,
            )
        self.provenance(
            out,
            String("measurement_scope"),
            String("ordinals below observed at the end cut"),
        )
        if self.output_fs == String(""):
            self.provenance(
                out,
                String("output.fs"),
                String("unavailable: filesystem unmeasured"),
            )
        else:
            var fstype = self.output_fs
            self.provenance(out, String("output.fs"), fstype)
        if self.signal_error != String(""):
            var sig_err = self.signal_error
            self.provenance(out, String("signal.error"), sig_err)
        if len(self.secondary_causes) > 0:
            var joined = self.secondary_causes[0]
            for i in range(1, len(self.secondary_causes)):
                joined += String("; ") + self.secondary_causes[i]
            self.provenance(
                out, String("shutdown.secondary_causes"), joined
            )
        while len(out.evidence) > 64:
            _ = out.evidence.pop()
        return out^

    def unavailable_cap(mut self, mut cap: Capability, reason: String):
        cap.status = String("unavailable")
        cap.reason = reason
        cap.has_profile_id = False

    def provenance(mut self, mut out: Session, key: String, value: String):
        var item = EvidenceItem()
        item.item_type = String("provenance")
        item.source = key
        if item.source == String(""):
            item.source = String("undecodable")
        item.interpretation = truncate_text(value, 512)
        out.evidence.append(item^)
