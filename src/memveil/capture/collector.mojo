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
from memveil.capture.correlation import CorrelationRegistry
from memveil.capture.lifecycle import (
    CP_LEN,
    HOOK_BOUNCE,
    HOOK_MAP_RESULT,
    HOOK_SYNC_CPU,
    HOOK_SYNC_DEVICE,
    HOOK_UNMAP,
    LC_LEN,
    DecodedCopy,
    DecodedLifecycle,
    decode_copy,
    decode_lifecycle,
    normalize_copy_event,
    normalize_lifecycle_event,
)
from memveil.capture.normalize import (
    PAYLOAD_LEN,
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
from memveil.capture.stop import (
    STOP_BUDGET_MS,
    StopController,
    StopEvidence,
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

comptime EXIT_OK = 0
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
comptime POOL_SAMPLE_INTERVAL_NS = UInt64(1000000000)
comptime POOL_PERIODIC_MAX = 4096

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
    """Libbpf-mojo session surface behind scriptable outcomes.

    Channel 0 is the attempt object; channels 1 and 2 are
    the lifecycle and copy objects when present. The
    unindexed map_info/read_full address channel 0; stats
    sums across present channels on the live path (scripted
    kernels return their script) while the _at variants
    read one channel exactly.
    """

    def open_session(mut self) -> OpOut:
        ...

    def load(mut self) -> OpOut:
        ...

    def map_info(mut self, name: String) -> GeomOut:
        ...

    def map_info_at(
        mut self, channel: Int, name: String
    ) -> GeomOut:
        ...

    def attach(mut self) -> OpOut:
        ...

    def poll(mut self, timeout_ms: Int, capacity: UInt32) -> PollOut:
        ...

    def stats(mut self) -> StatsOut:
        ...

    def stats_at(mut self, channel: Int) -> StatsOut:
        ...

    def read_full(mut self) -> SnapOut:
        ...

    def read_full_at(mut self, channel: Int) -> SnapOut:
        ...

    def channel_count(self) -> Int:
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
    var has_lifecycle: Bool
    var lifecycle_ring_bytes: UInt32
    var has_copy: Bool
    var copy_ring_bytes: UInt32

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
        self.has_lifecycle = False
        self.lifecycle_ring_bytes = UInt32(0)
        self.has_copy = False
        self.copy_ring_bytes = UInt32(0)


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


def epoch_flags_clear(vals: List[UInt64]) -> Bool:
    """No count-channel wrap flags (byte coverage is separate)."""
    if len(vals) != 6:
        return False
    var flags = vals[CNT_FLAGS]
    if flags & FLAG_OBSERVED_WRAP != UInt64(0):
        return False
    if flags & FLAG_EMITTED_WRAP != UInt64(0):
        return False
    if flags & FLAG_SUBMIT_WRAP != UInt64(0):
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
    var persisted_attempt: UInt64
    var persisted_map: UInt64
    var persisted_map_ok: UInt64
    var persisted_unmap: UInt64
    var persisted_copy: UInt64
    var persisted_sync: UInt64
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
    var start_vals_lc: List[UInt64]
    var end_vals_lc: List[UInt64]
    var has_end_cut_lc: Bool
    var start_vals_cp: List[UInt64]
    var end_vals_cp: List[UInt64]
    var has_end_cut_cp: Bool
    var start_pair_ts: UInt64
    var end_pair_ts: UInt64
    var stats_start: StatsOut
    var stats_drain: StatsOut
    var stats_final: StatsOut
    var has_final_stats: Bool
    var stats_start_ch0: StatsOut
    var stats_final_ch0: StatsOut
    var stats_start_lc: StatsOut
    var stats_final_lc: StatsOut
    var stats_start_cp: StatsOut
    var stats_final_cp: StatsOut
    var registry: CorrelationRegistry[]
    var closing_error: Bool
    var snapshots_present: Bool
    var attach_ns: UInt64
    var detach_ns: UInt64
    var secondary_causes: List[String]
    var signal_error: String
    var output_fs: String
    var pool_final: NormalizedPoolSample
    var pool_final_ts: UInt64
    var pool_has_final: Bool
    var pool_ok: Bool
    var pool_reason: String
    var pool_next_ts: UInt64
    var pool_periodic: Int
    var pool_periodic_capped: Bool
    var stop_ctl: StopController
    var stop_drained: Int
    var stop_drain_busy: Bool
    var stop_misuse: Bool
    var stop_evidence: StopEvidence
    var has_stop_evidence: Bool

    def __init__(out self, cfg: CollectorConfig):
        self.cfg = cfg.copy()
        self.stop_reason = String("")
        self.result_state = String("ok")
        self.unknown_cause = String("")
        self.persisted = UInt64(0)
        self.persisted_attempt = UInt64(0)
        self.persisted_map = UInt64(0)
        self.persisted_map_ok = UInt64(0)
        self.persisted_unmap = UInt64(0)
        self.persisted_copy = UInt64(0)
        self.persisted_sync = UInt64(0)
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
        self.start_vals_lc = List[UInt64]()
        self.end_vals_lc = List[UInt64]()
        self.has_end_cut_lc = False
        self.start_vals_cp = List[UInt64]()
        self.end_vals_cp = List[UInt64]()
        self.has_end_cut_cp = False
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
        self.stats_start_ch0 = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_final_ch0 = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_start_lc = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_final_lc = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_start_cp = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.stats_final_cp = StatsOut(
            False,
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            UInt64(0),
            String(""),
        )
        self.registry = CorrelationRegistry()
        self.closing_error = False
        self.snapshots_present = False
        self.attach_ns = UInt64(0)
        self.detach_ns = UInt64(0)
        self.secondary_causes = List[String]()
        self.signal_error = String("")
        self.output_fs = String("")
        self.pool_final = NormalizedPoolSample()
        self.pool_final_ts = UInt64(0)
        self.pool_has_final = False
        self.pool_ok = False
        self.pool_reason = String("")
        self.pool_next_ts = UInt64(0)
        self.pool_periodic = 0
        self.pool_periodic_capped = False
        self.stop_ctl = StopController()
        self.stop_drained = 0
        self.stop_drain_busy = False
        self.stop_misuse = False
        self.stop_evidence = StopEvidence(
            String("partial"),
            String("stop evidence missing"),
            STOP_BUDGET_MS,
            0,
            False,
            False,
            0,
            0,
            0,
            0,
            False,
            False,
            0,
        )
        self.has_stop_evidence = False

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

    def _stop_close(mut self, detached_ok: Bool):
        """Record the detach outcome as admission close/fail.

        Misuse is impossible by construction (ready runs
        close exactly once); the fallback keeps evidence
        total and loud if it ever happens.
        """
        try:
            if detached_ok:
                self.stop_ctl.close_admission()
            else:
                self.stop_ctl.fail_close()
        except:
            self.stop_misuse = True
            self.result_state = String("error")
            self.note_unknown(String("stop protocol misuse"))

    def _stop_record_drain(mut self, records: Int, busy: Bool):
        try:
            self.stop_ctl.drain(records, busy)
        except:
            self.stop_misuse = True
            self.result_state = String("error")
            self.note_unknown(String("stop protocol misuse"))

    def _stop_counters_valid(self) -> Bool:
        """End cuts present and usable, mirroring evaluate."""
        if not self.has_end_cut:
            return False
        if not epoch_flags_clear(self.end_vals):
            return False
        if not count_identity(self.end_vals):
            return False
        if self.cfg.has_lifecycle:
            if not self.has_end_cut_lc:
                return False
            if not epoch_flags_clear(self.end_vals_lc):
                return False
            if not count_identity(self.end_vals_lc):
                return False
        if self.cfg.has_copy:
            if not self.has_end_cut_cp:
                return False
            if not epoch_flags_clear(self.end_vals_cp):
                return False
            if not count_identity(self.end_vals_cp):
                return False
        return True

    def _stop_complete(self) -> Bool:
        """True only on present complete stop evidence."""
        return (
            self.has_stop_evidence
            and self.stop_evidence.outcome == String("complete")
        )

    def _final_exit_code(self, session: Session) -> Int:
        """Exit 0 needs settled termination and sufficient detail.

        Complete stop evidence alone is not enough: a
        partial or unavailable detail channel keeps exit 4.
        Aggregate-only gaps keep the sufficient exit, as in
        replay.
        """
        if self._stop_complete() and (
            session.q_detail.status == String("complete_for_scope")
        ):
            return EXIT_OK
        return EXIT_PARTIAL

    def _stop_open_mappings(self) -> Int:
        var open = UInt64(0)
        if self.persisted_map_ok > self.persisted_unmap:
            open = self.persisted_map_ok - self.persisted_unmap
        if open > UInt64(9223372036854775807):
            return 9223372036854775807
        return Int(open)

    def _stop_finalize(mut self, t1_ns: UInt64):
        """Finalize stop evidence over the close-out window.

        Elapsed runs detach to the finalize stamp (one
        clock read per run), which precedes the normal
        path's final pool sample and session publication.
        Milliseconds round up so a budget overrun can
        never truncate into the budget. A regressing
        stamp notes a clock failure; elapsed then stays
        zero beside that cause. Quiescence is never
        observed here: without the kernel-side protocol no
        consumer signal proves admitted writers settled,
        so live evidence always carries quiescence
        unproven.
        """
        var elapsed = UInt64(0)
        if t1_ns >= self.detach_ns:
            var delta = t1_ns - self.detach_ns
            elapsed = delta // UInt64(1000000)
            if delta % UInt64(1000000) != UInt64(0):
                elapsed += UInt64(1)
        else:
            self.note_unknown(String("stop clock regressed"))
        if elapsed > UInt64(9223372036854775807):
            elapsed = UInt64(9223372036854775807)
        var ms = Int(elapsed)
        if self.stop_misuse:
            self.stop_evidence = StopEvidence(
                String("partial"),
                String("stop protocol misuse"),
                STOP_BUDGET_MS,
                ms,
                False,
                False,
                0,
                0,
                0,
                0,
                False,
                False,
                0,
            )
        else:
            try:
                self.stop_evidence = (
                    self.stop_ctl.finalize_over_budget(
                        ms, self._stop_open_mappings()
                    )
                )
            except:
                self.stop_misuse = True
                self.result_state = String("error")
                self.note_unknown(String("stop protocol misuse"))
                self.stop_evidence = StopEvidence(
                    String("partial"),
                    String("stop protocol misuse"),
                    STOP_BUDGET_MS,
                    ms,
                    False,
                    False,
                    0,
                    0,
                    0,
                    0,
                    False,
                    False,
                    0,
                )
        self.has_stop_evidence = True

    def omit_for_latch(mut self):
        """Count one crossed/drained record to the latch."""
        if self.stop_reason == String("duration"):
            self.duration_omitted += UInt64(1)
        elif self.stop_reason == String("size_limit"):
            self.size_omitted += UInt64(1)
        elif self.stop_reason == String("signal"):
            self.signal_omitted += UInt64(1)

    def stable_pair_at[
        K: KernelSource, C: ClockSource
    ](mut self, mut kernel: K, mut clock: C, channel: Int) -> Bool:
        """Run the stable protocol on one channel; store the cut.

        Reads full 6-entry vectors until two consecutive
        agree (bounded pairs) or any read fails over. The
        second read's timestamp stamps the pair (channel 0
        only; extra channels archive no snapshots); every
        reading's timestamp feeds max_snap_ts.
        """
        for _ in range(STABLE_PAIRS):
            var first = kernel.read_full_at(channel)
            if not first.ok:
                continue
            var ts_first = clock.now()
            if ts_first > self.max_snap_ts:
                self.max_snap_ts = ts_first
            var second = kernel.read_full_at(channel)
            if not second.ok:
                continue
            var ts_second = clock.now()
            if ts_second > self.max_snap_ts:
                self.max_snap_ts = ts_second
            if stable_cut(first.vals, second.vals):
                self._store_cut(channel, second.vals, ts_second)
                return True
        return False

    def _store_cut(
        mut self, channel: Int, vals: List[UInt64], ts: UInt64
    ):
        """Store one channel's stable cut."""
        if channel == 1:
            self.end_vals_lc = vals.copy()
            self.has_end_cut_lc = True
        elif channel == 2:
            self.end_vals_cp = vals.copy()
            self.has_end_cut_cp = True
        else:
            self.end_vals = vals.copy()
            self.end_pair_ts = ts
            self.has_end_cut = True

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

    def _extra_channels(self) -> Bool:
        return self.cfg.has_lifecycle or self.cfg.has_copy

    def _check_channel_maps[
        K: KernelSource
    ](
        mut self, mut kernel: K, channel: Int, tag: String,
        ring_map: String, ring_bytes: UInt32,
    ) -> String:
        """Verify one extra channel's mv_counts + ring; "" ok."""
        var counts = kernel.map_info_at(channel, String("mv_counts"))
        if not counts.ok:
            return (
                String("map ")
                + tag
                + String(" mv_counts: ")
                + counts.message
            )
        if (
            counts.map_type != UInt32(MAP_TYPE_ARRAY)
            or counts.key_size != UInt32(4)
            or counts.value_size != UInt32(8)
            or counts.max_entries != UInt32(6)
        ):
            return String("map ") + tag + String(" mv_counts geometry")
        var ring = kernel.map_info_at(channel, ring_map)
        if not ring.ok:
            return (
                String("map ")
                + tag
                + String(" ")
                + ring_map
                + String(": ")
                + ring.message
            )
        if ring.map_type != UInt32(MAP_TYPE_RINGBUF):
            return (
                String("map ")
                + tag
                + String(" ")
                + ring_map
                + String(" geometry")
            )
        if ring.max_entries != ring_bytes:
            return (
                String("map ")
                + tag
                + String(" ")
                + ring_map
                + String(" ring size")
            )
        return String("")

    def _admit_channel_hooks(mut self) -> String:
        """Admit enabled hooks to the registry; "" ok else reason.

        Admission (which hooks) follows record's
        capability selection; the namespace is a frozen
        semantic property (swiotlb hooks observe physical
        tlb-pool addresses, not IOVAs). Events from
        unadmitted hooks stay unpaired; a registry
        rejection here refuses before any probe attaches.
        """
        try:
            if self.cfg.has_lifecycle:
                self.registry.admit_hook(
                    String(HOOK_MAP_RESULT), String("tlb-phys")
                )
                self.registry.admit_hook(
                    String(HOOK_UNMAP), String("tlb-phys")
                )
            if self.cfg.has_copy:
                self.registry.admit_hook(
                    String(HOOK_SYNC_DEVICE), String("tlb-phys")
                )
                self.registry.admit_hook(
                    String(HOOK_SYNC_CPU), String("tlb-phys")
                )
                self.registry.admit_hook(
                    String(HOOK_BOUNCE), String("tlb-phys")
                )
        except:
            return String("hook admission failed")
        return String("")

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
        if self.cfg.has_lifecycle:
            var lc_maps = self._check_channel_maps(
                kernel, 1, String("lc"), String("mv_lifecycle"),
                self.cfg.lifecycle_ring_bytes,
            )
            if lc_maps != String(""):
                return lc_maps
        if self.cfg.has_copy:
            var cp_maps = self._check_channel_maps(
                kernel, 2, String("cp"), String("mv_copies"),
                self.cfg.copy_ring_bytes,
            )
            if cp_maps != String(""):
                return cp_maps
        if not self.stable_pair_at(kernel, clock, 0):
            return String("start snapshot unresolved")
        self.start_vals = self.end_vals.copy()
        self.start_pair_ts = self.end_pair_ts
        self.has_end_cut = False
        if not all_zero(self.start_vals):
            return String("start snapshot nonzero")
        if self.cfg.has_lifecycle:
            if not self.stable_pair_at(kernel, clock, 1):
                return String("start lc snapshot unresolved")
            self.start_vals_lc = self.end_vals_lc.copy()
            self.has_end_cut_lc = False
            if not all_zero(self.start_vals_lc):
                return String("start lc snapshot nonzero")
        if self.cfg.has_copy:
            if not self.stable_pair_at(kernel, clock, 2):
                return String("start cp snapshot unresolved")
            self.start_vals_cp = self.end_vals_cp.copy()
            self.has_end_cut_cp = False
            if not all_zero(self.start_vals_cp):
                return String("start cp snapshot nonzero")
        var baseline = kernel.stats()
        if not baseline.ok:
            return String("start stats: ") + baseline.message
        self.stats_start = baseline.copy()
        if self._extra_channels():
            var ch0 = kernel.stats_at(0)
            if not ch0.ok:
                return String("start ch0 stats: ") + ch0.message
            self.stats_start_ch0 = ch0.copy()
            if self.cfg.has_lifecycle:
                var blc = kernel.stats_at(1)
                if not blc.ok:
                    return String("start lc stats: ") + blc.message
                self.stats_start_lc = blc.copy()
            if self.cfg.has_copy:
                var bcp = kernel.stats_at(2)
                if not bcp.ok:
                    return String("start cp stats: ") + bcp.message
                self.stats_start_cp = bcp.copy()
        var made = writer.create(self.cfg.output, self.cfg.max_events_bytes)
        if not made.ok:
            return String("output ") + made.kind + String(": ") + made.message
        self.output_fs = fs_type_name(self.cfg.output)
        if self._extra_channels():
            var admitted = self._admit_channel_hooks()
            if admitted != String(""):
                return admitted
        # The window floor is read BEFORE activation: a firing
        # between link activation and a post-attach timestamp
        # would persist below the declared window and the reader
        # would reject the capture. Nothing can fire before the
        # links exist, so a pre-attach floor stays tight without
        # backdating across the init gap.
        self.attach_ns = clock.now()
        var attached = kernel.attach()
        if not attached.ok:
            return String("attach: ") + attached.message
        if self.cfg.has_pool_sample:
            # Baseline pool sample, persisted first: the file
            # stays chronological (baseline, periodic, final)
            # so order-based reducers cannot misread a held
            # baseline as a late sample. Pool samples are not
            # bridge-delivered, so only the persisted-ts
            # maximum moves.
            var base = self._sample_pool_now(clock)
            var line: List[UInt8]
            try:
                line = self.pool_sample_event(base[0], base[1])
            except:
                self.next_seq -= UInt64(1)
                return String("output pool baseline unencodable")
            var wrote = writer.append(line)
            if not wrote.ok:
                self.next_seq -= UInt64(1)
                return (
                    String("output pool baseline ")
                    + wrote.kind
                    + String(": ")
                    + wrote.message
                )
            if base[0].has_used_bytes or base[0].has_capacity_bytes:
                self.pool_ok = True
            if base[1] > self.max_persisted_ts:
                self.max_persisted_ts = base[1]
            if base[0].reason != String(""):
                self.pool_reason = base[0].reason
        self.pool_next_ts = checked_add(
            self.attach_ns, POOL_SAMPLE_INTERVAL_NS
        )
        print(
            String("ready session=")
            + self.session_id
            + String(" start_ns=")
            + format_u64(self.start_ns)
        )
        self.stop_ctl.mark_ready()
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
            var ptick = self.maybe_sample_pool(clock, writer, now)
            if ptick != String(""):
                return ptick
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
        if len(payload) == PAYLOAD_LEN:
            return self._admit_attempt(
                payload, clock, signal, writer, deadline
            )
        if len(payload) == LC_LEN:
            return self._admit_lifecycle(
                payload, clock, signal, writer, deadline
            )
        if len(payload) == CP_LEN:
            return self._admit_copy(
                payload, clock, signal, writer, deadline
            )
        self.rejected += UInt64(1)
        self.fail(String("error"))
        return String("error-path")

    def _gate[C: ClockSource, G: SignalSource](
        mut self, mut clock: C, mut signal: G, deadline: UInt64
    ) -> String:
        """Pre-normalize latch gate; "" admits, else closed."""
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
        return String("")

    def _persist_line[W: WriterSource](
        mut self, mut writer: W, line: List[UInt8], byte_count: UInt64,
        ts_ns: UInt64, kind: String,
    ) -> String:
        """Append one encoded event; "" persisted, else closed/error."""
        var wrote = writer.append(line)
        if wrote.ok:
            self.persisted += UInt64(1)
            self.persisted_sum += byte_count
            if ts_ns > self.max_persisted_ts:
                self.max_persisted_ts = ts_ns
            if kind == String("bounce_attempt"):
                self.persisted_attempt += UInt64(1)
            elif kind == String("map_result"):
                self.persisted_map += UInt64(1)
            elif kind == String("unmap"):
                self.persisted_unmap += UInt64(1)
            elif kind == String("copy"):
                self.persisted_copy += UInt64(1)
            elif kind == String("sync_request"):
                self.persisted_sync += UInt64(1)
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

    def _admit_attempt[
        C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, payload: List[UInt8], mut clock: C, mut signal: G,
        mut writer: W, deadline: UInt64,
    ) -> String:
        var attempt: DecodedAttempt
        try:
            attempt = decode_payload(payload)
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var gate = self._gate(clock, signal, deadline)
        if gate != String(""):
            return gate
        var normalized: NormalizedAttempt
        try:
            normalized = normalize_attempt(attempt, self.table)
        except e:
            if not e.fatal:
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
        return self._persist_line(
            writer, line^, normalized.requested_bytes,
            normalized.ts_ns, String("bounce_attempt"),
        )

    def _admit_lifecycle[
        C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, payload: List[UInt8], mut clock: C, mut signal: G,
        mut writer: W, deadline: UInt64,
    ) -> String:
        var decoded: DecodedLifecycle
        try:
            decoded = decode_lifecycle(payload)
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var gate = self._gate(clock, signal, deadline)
        if gate != String(""):
            return gate
        var ev = normalize_lifecycle_event(decoded)
        if decoded.size > u64_max() - self.persisted_sum:
            self.latch(String("size_limit"))
            self.omit_for_latch()
            return String("closed")
        self.fill_source_hook(ev)
        try:
            ev = self.registry.normalize(ev^, String("capture"))
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var line: List[UInt8]
        try:
            line = encode_event_line(ev)
        except:
            self.result_state = String("unfinalizable")
            return String("unfinalizable")
        var ok_map = (
            ev.kind == String("map_result") and ev.map_result.success
        )
        var res = self._persist_line(
            writer, line^, decoded.size, decoded.ktime, ev.kind
        )
        if res == String("") and ok_map:
            self.persisted_map_ok += UInt64(1)
        return res

    def _admit_copy[
        C: ClockSource, G: SignalSource, W: WriterSource
    ](
        mut self, payload: List[UInt8], mut clock: C, mut signal: G,
        mut writer: W, deadline: UInt64,
    ) -> String:
        var decoded: DecodedCopy
        try:
            decoded = decode_copy(payload)
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var gate = self._gate(clock, signal, deadline)
        if gate != String(""):
            return gate
        var ev: Event
        try:
            ev = normalize_copy_event(decoded)
        except e:
            if not e.fatal:
                self.rejected += UInt64(1)
                return String("")
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var byte_count = decoded.requested
        if ev.kind == String("copy"):
            byte_count = decoded.effective
        if byte_count > u64_max() - self.persisted_sum:
            self.latch(String("size_limit"))
            self.omit_for_latch()
            return String("closed")
        self.fill_source_hook(ev)
        try:
            ev = self.registry.normalize(ev^, String("capture"))
        except:
            self.rejected += UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var line: List[UInt8]
        try:
            line = encode_event_line(ev)
        except:
            self.result_state = String("unfinalizable")
            return String("unfinalizable")
        return self._persist_line(
            writer, line^, byte_count, decoded.ktime, ev.kind
        )

    def normal_close[K: KernelSource, C: ClockSource, W: WriterSource](
        mut self, mut kernel: K, mut clock: C, mut writer: W
    ):
        """DETACHING -> SETTLE -> DRAINING -> STATS -> CONFIRM."""
        var detached = kernel.detach()
        self.detach_ns = clock.now()
        self._stop_close(detached.ok)
        if not detached.ok:
            self.note_unknown(String("detach failed; shutdown evidence unresolved"))
        clock.sleep_ms(SETTLE_MS)
        self.drain(kernel, clock)
        if not self.stable_pair_at(kernel, clock, 0):
            self.note_unknown(String("snapshot unresolved"))
            self.has_end_cut = False
        else:
            if self.cfg.has_lifecycle:
                if not self.stable_pair_at(kernel, clock, 1):
                    self.note_unknown(String("lc snapshot unresolved"))
                    self.has_end_cut_lc = False
            if self.cfg.has_copy:
                if not self.stable_pair_at(kernel, clock, 2):
                    self.note_unknown(String("cp snapshot unresolved"))
                    self.has_end_cut_cp = False
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
        var drain_busy = (
            self.stop_drain_busy
            or not drain_stats.ok
            or drain_stats.staged != UInt64(0)
        )
        self._stop_record_drain(self.stop_drained, drain_busy)
        # The sample must follow the last drain: a new
        # boundary claim invalidates any earlier sample.
        self.stop_ctl.sample_counters(self._stop_counters_valid())
        self._stop_finalize(clock.now())
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
        """Bounded consume-and-count; every record omitted.

        Consumed batches feed the stop drain count; any
        unsettled exit (budget, error, unreadable stats)
        marks the drain busy. Confirm-phase batches stay
        out: they arrive after the end cut and note their
        own deviation.
        """
        var start = clock.now()
        var budget_s = checked_add(start, UInt64(DRAIN_MAX_S) * UInt64(1000000000))
        var prev_received = u64_max()
        var prev_malformed = u64_max()
        var have_prev = False
        for _ in range(DRAIN_MAX_POLLS):
            var now = clock.now()
            if now >= budget_s:
                self.note_unknown(String("drain budget exhausted"))
                self.stop_drain_busy = True
                return
            var out = self.poll_one(kernel, 0)
            if out.kind == String("batch"):
                self.stop_drained += 1
                self.omit_for_latch()
                continue
            if out.kind != String("timeout"):
                self.note_unknown(String("error shutdown"))
                self.result_state = String("error")
                self.stop_drain_busy = True
                return
            var stats = kernel.stats()
            if not stats.ok:
                self.note_unknown(String("error shutdown"))
                self.stop_drain_busy = True
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
        self.stop_drain_busy = True

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
        if self._extra_channels():
            self._read_channel_finals(kernel)
        if self.stats_drain.ok:
            if (
                final.received != self.stats_drain.received
                or final.malformed != self.stats_drain.malformed
            ):
                self.note_unknown(String("post-snapshot activity"))

    def _read_channel_finals[K: KernelSource](mut self, mut kernel: K):
        """Read per-channel final transport stats; failures close."""
        var ch0 = kernel.stats_at(0)
        if not ch0.ok:
            self.note_unknown(String("error shutdown"))
            return
        self.stats_final_ch0 = ch0.copy()
        if self.cfg.has_lifecycle:
            var lc = kernel.stats_at(1)
            if not lc.ok:
                self.note_unknown(String("error shutdown"))
                return
            self.stats_final_lc = lc.copy()
        if self.cfg.has_copy:
            var cp = kernel.stats_at(2)
            if not cp.ok:
                self.note_unknown(String("error shutdown"))
                return
            self.stats_final_cp = cp.copy()

    def error_close[K: KernelSource, C: ClockSource, W: WriterSource](
        mut self, mut kernel: K, mut clock: C, mut writer: W
    ) -> RunResult:
        """ERROR_DETACH -> ERROR_STATS -> FINALIZING; no drain."""
        var detached = kernel.detach()
        self.detach_ns = clock.now()
        self._stop_close(detached.ok)
        if not detached.ok:
            self.note_unknown(String("detach failed; shutdown evidence unresolved"))
        var final = kernel.stats()
        if final.ok:
            self.stats_final = final.copy()
            self.has_final_stats = True
        if self._extra_channels():
            self._read_channel_finals(kernel)
        if not self.stable_pair_at(kernel, clock, 0):
            self.note_unknown(String("snapshot unresolved"))
            self.has_end_cut = False
        else:
            if self.cfg.has_lifecycle:
                if not self.stable_pair_at(kernel, clock, 1):
                    self.note_unknown(String("lc snapshot unresolved"))
                    self.has_end_cut_lc = False
            if self.cfg.has_copy:
                if not self.stable_pair_at(kernel, clock, 2):
                    self.note_unknown(String("cp snapshot unresolved"))
                    self.has_end_cut_cp = False
        if self.cfg.has_pool_sample:
            var fin = self._sample_pool_now(clock)
            self.pool_final = fin[0]
            self.pool_final_ts = fin[1]
            self.pool_has_final = True
        self.stop_ctl.sample_counters(self._stop_counters_valid())
        self._stop_finalize(clock.now())
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

    def fill_source_hook(mut self, mut ev: Event):
        """Stamp capture fields; keep probe hook/backend/correlation.

        Lifecycle/copy normalizers set the per-probe hook
        and backend; the registry sets correlation after
        this stamp, so evidence refs carry real seqs.
        """
        ev.session_id = self.session_id
        ev.seq = self.next_seq
        self.next_seq += UInt64(1)
        ev.source_profile_id = self.cfg.profile_id
        ev.source_measurement = String("observed")

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

    def maybe_sample_pool[C: ClockSource, W: WriterSource](
        mut self, mut clock: C, mut writer: W, now: UInt64
    ) -> String:
        """Persist one periodic pool sample when due; "" otherwise.

        Fires at most once per loop iteration on the 1s
        cadence and stops at 4096 samples with a session
        note; the resync skips missed ticks without
        backfill bursts. Unavailable reads persist as
        unavailable samples, never as failed runs.
        """
        if not self.cfg.has_pool_sample:
            return String("")
        if self.pool_periodic_capped:
            return String("")
        if now < self.pool_next_ts:
            return String("")
        self.pool_next_ts = checked_add(now, POOL_SAMPLE_INTERVAL_NS)
        if self.pool_periodic >= POOL_PERIODIC_MAX:
            self.pool_periodic_capped = True
            return String("")
        var fired = self._sample_pool_now(clock)
        var line: List[UInt8]
        try:
            line = self.pool_sample_event(fired[0], fired[1])
        except:
            self.next_seq -= UInt64(1)
            self.fail(String("error"))
            return String("error-path")
        var verdict = self._persist_pool_mid(writer, line, fired[1])
        if verdict != String(""):
            return verdict
        var sample = fired[0]
        if sample.has_used_bytes or sample.has_capacity_bytes:
            self.pool_ok = True
        if self.pool_reason == String(""):
            if sample.reason != String(""):
                self.pool_reason = sample.reason
        self.pool_periodic += 1
        return String("")

    def _persist_pool_mid[W: WriterSource](
        mut self, mut writer: W, line: List[UInt8], ts_ns: UInt64
    ) -> String:
        """Append one periodic pool sample; "" persisted, else verdict.

        Pool samples are not bridge-delivered, so they stay
        out of the delivery identity: no persisted, omitted,
        or write-failed counting, only the persisted-ts
        maximum moves, honestly covering them. The attempt
        gate still bounds their bytes, and the failure
        mapping mirrors the attempt path.
        """
        var wrote = writer.append(line)
        if wrote.ok:
            if ts_ns > self.max_persisted_ts:
                self.max_persisted_ts = ts_ns
            return String("")
        if wrote.kind == String("refused"):
            self.next_seq -= UInt64(1)
            self.latch(String("size_limit"))
            return String("closed")
        self.next_seq -= UInt64(1)
        if wrote.kind == String("fatal") or wrote.kind == String("misuse"):
            self.result_state = String("unfinalizable")
            return String("unfinalizable")
        self.fail(String("error"))
        return String("error-path")

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
            if not epoch_flags_clear(vals):
                self.note_unknown(String("invalid epoch"))
            elif not count_identity(vals):
                self.note_unknown(String("kernel identity unproven"))
            elif self.has_final_stats:
                var emitted = vals[CNT_EMITTED]
                var received_d: UInt64
                if self._extra_channels():
                    if not self.stats_final_ch0.ok:
                        self.note_unknown(String("error shutdown"))
                        return String("")
                    received_d = (
                        self.stats_final_ch0.received
                        - self.stats_start_ch0.received
                    )
                else:
                    received_d = (
                        self.stats_final.received
                        - self.stats_start.received
                    )
                if received_d != emitted:
                    self.note_unknown(String("ring count unproven"))
        if self.cfg.has_lifecycle:
            var lc_vals = self.end_vals_lc.copy()
            var lc_start = self.stats_start_lc.copy()
            var lc_final = self.stats_final_lc.copy()
            if self._evaluate_channel(
                lc_vals, self.has_end_cut_lc,
                lc_start, lc_final, String("lifecycle"),
            ) != String(""):
                return String("unfinalizable")
        if self.cfg.has_copy:
            var cp_vals = self.end_vals_cp.copy()
            var cp_start = self.stats_start_cp.copy()
            var cp_final = self.stats_final_cp.copy()
            if self._evaluate_channel(
                cp_vals, self.has_end_cut_cp,
                cp_start, cp_final, String("copy"),
            ) != String(""):
                return String("unfinalizable")
        return String("")

    def _evaluate_channel(
        mut self, vals_in: List[UInt64], has_cut: Bool,
        start: StatsOut, final: StatsOut, tag: String,
    ) -> String:
        """Close verification for one extra channel's cut."""
        if not has_cut:
            return String("")
        var vals = vals_in.copy()
        if not epoch_flags_clear(vals):
            self.note_unknown(tag + String(" invalid epoch"))
            return String("")
        if not count_identity(vals):
            self.note_unknown(tag + String(" kernel identity unproven"))
            return String("")
        if not final.ok:
            return String("")
        if (
            final.received < start.received
            or final.delivered < start.delivered
            or final.malformed < start.malformed
            or final.dropped < start.dropped
        ):
            return String("unfinalizable")
        var received_d = final.received - start.received
        if received_d != vals[CNT_EMITTED]:
            self.note_unknown(tag + String(" ring count unproven"))
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
        var assembled = Session()
        try:
            assembled = self.assemble()
            session_text = encode_session(assembled)
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
            var code = self._final_exit_code(assembled)
            return RunResult(
                code, reason, String("finalized"),
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

    def _submit_valid_all(self) -> Bool:
        """Every enabled channel's submit_fail is readable."""
        if not self.has_end_cut or not submit_valid(self.end_vals):
            return False
        if self.cfg.has_lifecycle and (
            not self.has_end_cut_lc
            or not submit_valid(self.end_vals_lc)
        ):
            return False
        if self.cfg.has_copy and (
            not self.has_end_cut_cp
            or not submit_valid(self.end_vals_cp)
        ):
            return False
        return True

    def _submit_fail_total(self) -> UInt64:
        """Summed submit_fail over enabled channels' end cuts."""
        var total = UInt64(0)
        if self.has_end_cut:
            total += self.end_vals[CNT_SUBMIT_FAIL]
        if self.cfg.has_lifecycle and self.has_end_cut_lc:
            total += self.end_vals_lc[CNT_SUBMIT_FAIL]
        if self.cfg.has_copy and self.has_end_cut_cp:
            total += self.end_vals_cp[CNT_SUBMIT_FAIL]
        return total

    def loss_pairs(self) -> List[String]:
        """Kernel/bridge components as decimal-or-unavailable."""
        var submit = String("unavailable")
        var malformed = String("unavailable")
        var dropped = String("unavailable")
        if self._submit_valid_all():
            submit = format_u64(self._submit_fail_total())
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
        if not self._submit_valid_all():
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
            + format_u64(self.persisted_attempt)
            + String(" attempts persisted; admitted under ")
            + self.cfg.profile_id
            + String("; device detail grouped by observed name scope")
        )
        cap.hooks.append(String("swiotlb:swiotlb_bounced"))
        cap.has_profile_id = True
        cap.profile_id = self.cfg.profile_id
        out.cap_bounce_attempts = cap^
        if self.cfg.has_lifecycle:
            var lc_cap = Capability()
            lc_cap.status = String("partial")
            lc_cap.reason = (
                String("capture ")
                + self.result_state
                + String(", ")
                + format_u64(
                    self.persisted_map + self.persisted_unmap
                )
                + String(
                    " map_result/unmap events persisted; admitted"
                    " under "
                )
                + self.cfg.profile_id
                + String(
                    "; v2 wire reports opaque mapping generations"
                    " when observed"
                )
            )
            lc_cap.hooks.append(String(HOOK_MAP_RESULT))
            lc_cap.hooks.append(String(HOOK_UNMAP))
            lc_cap.has_profile_id = True
            lc_cap.profile_id = self.cfg.profile_id
            out.cap_mapping_lifecycle = lc_cap^
        else:
            self.unavailable_cap(
                out.cap_mapping_lifecycle,
                String("No map_result source in this capture."),
            )
        if self.cfg.has_copy:
            var cp_cap = Capability()
            cp_cap.status = String("partial")
            cp_cap.reason = (
                String("capture ")
                + self.result_state
                + String(", ")
                + format_u64(self.persisted_copy)
                + String(" copy events persisted; admitted under ")
                + self.cfg.profile_id
                + String("; v1 copy wire carries no mapping identity")
            )
            cp_cap.hooks.append(String(HOOK_BOUNCE))
            cp_cap.has_profile_id = True
            cp_cap.profile_id = self.cfg.profile_id
            out.cap_copy_bytes = cp_cap^
            var sy_cap = Capability()
            sy_cap.status = String("partial")
            sy_cap.reason = (
                String("capture ")
                + self.result_state
                + String(", ")
                + format_u64(self.persisted_sync)
                + String(
                    " sync_request events persisted; admitted"
                    " under "
                )
                + self.cfg.profile_id
                + String("; v1 copy wire carries no mapping identity")
            )
            sy_cap.hooks.append(String(HOOK_SYNC_DEVICE))
            sy_cap.hooks.append(String(HOOK_SYNC_CPU))
            sy_cap.has_profile_id = True
            sy_cap.profile_id = self.cfg.profile_id
            out.cap_sync_requests = sy_cap^
        else:
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
            var cadence = (
                String("default-pool debugfs samples at capture")
                + String(" start and close plus ")
                + format_u64(UInt64(self.pool_periodic))
                + String(" periodic samples (")
                + format_u64(
                    POOL_SAMPLE_INTERVAL_NS // UInt64(1000000000)
                )
                + String("s cadence)")
            )
            if self.pool_periodic_capped:
                cadence += (
                    String("; periodic sampling stopped at ")
                    + format_u64(UInt64(POOL_PERIODIC_MAX))
                    + String(" (count cap)")
                )
            if self.pool_reason != String(""):
                cadence += (
                    String("; first read failure: ") + self.pool_reason
                )
            pcap.reason = cadence
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
            format_u64(self.persisted_attempt)
            + String(" bounce_attempt")
        )
        if self.cfg.has_lifecycle:
            scope += (
                String(" + ")
                + format_u64(self.persisted_map + self.persisted_unmap)
                + String(" map_result/unmap")
            )
        if self.cfg.has_copy:
            scope += (
                String(" + ")
                + format_u64(
                    self.persisted_copy + self.persisted_sync
                )
                + String(" copy/sync_request")
            )
        scope += String(" events")
        if self.loss_known():
            var submit_fail = self._submit_fail_total()
            var total = (
                submit_fail
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
                submit_fail,
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
        if self._extra_channels():
            # Lifecycle/copy counter cuts are verified at
            # close and feed q_detail loss, but only the
            # attempt channel archives counter snapshots.
            out.q_aggregate.scope = String(
                "counter snapshots (attempt channel)"
            )
        else:
            out.q_aggregate.scope = String("counter snapshots")
        if self._extra_channels():
            var health = self.registry.health()
            out.q_correlation.status = health.status
            out.q_correlation.has_loss_count = health.has_loss_count
            out.q_correlation.loss_count = health.loss_count
            out.q_correlation.scope = health.scope
            out.q_correlation.reason = health.reason
            out.q_correlation.evidence_refs = (
                health.evidence_refs.copy()
            )
        else:
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
        var stop = self.stop_evidence
        out.stop.outcome = stop.outcome
        out.stop.reason = stop.reason
        out.stop.budget_ms = UInt64(stop.stop_budget_ms)
        out.stop.elapsed_ms = UInt64(stop.elapsed_ms)
        out.stop.admission_closed = stop.admission_closed
        out.stop.quiescence_observed = stop.quiescence_observed
        out.stop.writers_settled = UInt64(stop.writers_settled)
        out.stop.in_flight_at_close = UInt64(stop.in_flight_at_close)
        out.stop.late_submits_drained = UInt64(stop.late_submits_drained)
        out.stop.drained_records = UInt64(stop.drained_records)
        out.stop.busy_at_drain = stop.busy_at_drain
        out.stop.counters_valid = stop.counters_valid
        out.stop.open_mappings = UInt64(stop.open_mappings)
        if self._stop_complete():
            out.q_terminal.status = String("complete_for_scope")
            out.q_terminal.has_loss_count = False
            out.q_terminal.scope = String("capture finalization")
            out.q_terminal.reason = String(
                "stop complete: all stages proved"
            )
        else:
            out.q_terminal.status = String("partial")
            out.q_terminal.has_loss_count = False
            out.q_terminal.scope = String("capture finalization")
            out.q_terminal.reason = (
                String("stop ")
                + stop.outcome
                + String(": ")
                + stop.reason
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
