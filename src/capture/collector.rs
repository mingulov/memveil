// SPDX-License-Identifier: GPL-3.0-or-later
//! Attempt collector: kernel records to finalized capture.
//!
//! Transactional start, precedence-ordered poll loop with
//! admission latches, the normal and error close-out machines,
//! loss accounting identities, closing serialization, and
//! session assembly. The core is generic over four source
//! traits, so the scripted matrix drives the real close-out,
//! writer, and session bytes without a kernel; live adapters
//! wrap the statically linked loader sessions.
//!
//! This module owns the `KernelSource`, `ClockSource`, and
//! `SignalSource` traits plus the platform `impl` blocks. The
//! writer surface (`WriterSource` and its outcome shapes) lives
//! in the live writer module and is reused here, not redefined.
//! Poll batches carry raw payload bytes: the ring yields items
//! directly, so there is no bridge frame header to decode.
//!
//! Post-release follow-up: split the scripted test harness out
//! of this module. The file mirrors the Mojo source 1:1 today,
//! which keeps the port reviewable; the split must preserve
//! behavior and the scripted matrix exactly.

use super::correlation::CorrelationRegistry;
use super::journal_capture::{JournalCapture, JournalKernel, encode_journal_control};
use super::journal_kernel::JournalKernel as NativeJournalKernel;
use super::lifecycle::{
    CP_KIND_COPY, CP_LEN, CP_REASON_BOUNDS, CP_REASON_LAYOUT, CP_REASON_MASK_READ, CP_REASON_SHIFT,
    CP_REASON_SLOT_READ, DecodedCopy, DecodedLifecycle, HOOK_BOUNCE, HOOK_MAP_RESULT,
    HOOK_SYNC_CPU, HOOK_SYNC_DEVICE, HOOK_UNMAP, LC_LEN, copy_unknown_reason_name, decode_copy,
    decode_lifecycle, normalize_copy_event, normalize_lifecycle_event,
};
use super::live::WriterSource;
use super::liveness::{
    LIVENESS_GUARD_NS, LivenessLoss, LivenessTally, LivenessVerdict, evaluate_liveness, sat_add_u64,
};
use super::normalize::{
    DecodedAttempt, DeviceTable, NormalizedAttempt, PAYLOAD_LEN, decode_payload, normalize_attempt,
    selection_matches,
};
use super::pools::{
    NormalizedPoolSample, POOL_SWIOTLB_ALLOCATOR, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT,
    pool_sample_pressured, sample_default_pool,
};
use super::stop::{STOP_BUDGET_MS, StopController, StopEvidence};
use super::writer::CommittedStream;
use crate::model::encode::{EncodeError, encode_event_line, encode_session};
use crate::model::event::{BounceAttempt, CounterSnapshot, Event, Gap, PoolSample};
use crate::model::report::verdict_for_session;
use crate::model::session::{Capability, Channel, DeviceEntry, EvidenceItem, Session};
use crate::model::validate::format_u64;
use crate::platform::clock::MonoClock;
use crate::platform::evidence::GuestInfo;
use crate::platform::narrow::{encode_offsets_table, validate_table_extents};
use crate::platform::outcome::OpOut;
use crate::platform::reader::{fs_type_name, is_valid_utf8, open_evidence_reader};
use crate::platform::signal::{LiveSignalSource, SignalOut};

/// Clean finalized exit.
pub const EXIT_OK: i64 = 0;
/// Error exit.
pub const EXIT_ERROR: i64 = 1;
/// Invalid-input exit.
pub const EXIT_INVALID: i64 = 2;
/// Refusal exit.
pub const EXIT_REFUSAL: i64 = 3;
/// Partial (strict) exit.
pub const EXIT_PARTIAL: i64 = 4;

/// Identity budget shared with the reader's tracked-id cap:
/// the writer stops while the next record still fits, so
/// finalized captures always pass admission.
pub const MAX_OPS: u64 = 4194304;
/// Close-out drain poll bound.
pub const DRAIN_MAX_POLLS: i64 = 100000;
/// Close-out drain time bound in seconds.
pub const DRAIN_MAX_S: i64 = 30;
/// Confirm-phase poll bound.
pub const CONFIRM_POLLS: i64 = 100;
/// Stable-pair attempts per cut.
pub const STABLE_PAIRS: i64 = 10;
/// End-pair advance attempts.
pub const ADVANCE_MAX: i64 = 1000;
/// Poll quantum in milliseconds.
pub const POLL_QUANTUM_MS: i64 = 100;
/// Settle sleep in milliseconds.
pub const SETTLE_MS: i64 = 100;
/// Pool sample cadence in nanoseconds.
pub const POOL_SAMPLE_INTERVAL_NS: u64 = 1000000000;
/// Routine periodic pool sample cap.
pub const POOL_PERIODIC_MAX: i64 = 4096;
/// Post-cap pressurized pool sample cap.
pub const POOL_POSTCAP_MAX: i64 = 64;

/// Counter slot: observed records.
pub const CNT_OBSERVED: usize = 0;
/// Counter slot: observed bytes.
pub const CNT_OBSERVED_BYTES: usize = 1;
/// Counter slot: emitted records.
pub const CNT_EMITTED: usize = 2;
/// Counter slot: emitted bytes.
pub const CNT_EMITTED_BYTES: usize = 3;
/// Counter slot: submit failures.
pub const CNT_SUBMIT_FAIL: usize = 4;
/// Counter slot: wrap/coverage flags.
pub const CNT_FLAGS: usize = 5;

/// Flag: observed count wrapped.
pub const FLAG_OBSERVED_WRAP: u64 = 1;
/// Flag: observed bytes wrapped.
pub const FLAG_OBSERVED_BYTES_WRAP: u64 = 2;
/// Flag: emitted count wrapped.
pub const FLAG_EMITTED_WRAP: u64 = 4;
/// Flag: emitted bytes wrapped.
pub const FLAG_EMITTED_BYTES_WRAP: u64 = 8;
/// Flag: submit-fail count wrapped.
pub const FLAG_SUBMIT_WRAP: u64 = 16;
/// Flag: byte coverage void.
pub const FLAG_BYTE_COVERAGE: u64 = 32;
/// Flag: argument count mismatch.
pub const FLAG_ARGCNT: u64 = 64;

/// BPF map type array.
pub const MAP_TYPE_ARRAY: u32 = 2;
/// BPF map type ringbuf.
pub const MAP_TYPE_RINGBUF: u32 = 27;
/// Detail scope text cap in code points.
pub const DETAIL_SCOPE_MAX: usize = 256;

/// Mapping-release relation scope text.
const CORR_SCOPE_MAPPING: &str = "mapping and release pairing";
/// Copy-attribution relation scope text.
const CORR_SCOPE_COPY: &str = "copy attribution";
/// Sync-attribution relation scope text.
const CORR_SCOPE_SYNC: &str = "sync attribution";
/// Poll staging capacity in bytes.
const POLL_CAPACITY: u32 = 65536;

/// One map geometry answer (valid only when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeomOut {
    /// True when the geometry read.
    pub ok: bool,
    /// BPF map type.
    pub map_type: u32,
    /// Key size in bytes.
    pub key_size: u32,
    /// Value size in bytes.
    pub value_size: u32,
    /// Entry count (ring bytes for ring buffers).
    pub max_entries: u32,
    /// Failure detail; empty on success.
    pub message: String,
}

/// One poll outcome: timeout, batch, short, or error.
///
/// kind in {"timeout", "batch", "short", "error"}.
/// batch carries raw payload bytes; short carries required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PollOut {
    /// Outcome kind.
    pub kind: String,
    /// Raw payload bytes on batch.
    pub frame: Vec<u8>,
    /// Required capacity on short.
    pub required: u32,
    /// Failure detail; empty unless error.
    pub message: String,
}

/// One stats read (counters valid only when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsOut {
    /// True when the stats read.
    pub ok: bool,
    /// Ring items consumed.
    pub received: u64,
    /// Decoded frames handed out.
    pub delivered: u64,
    /// Staged-but-undecoded items.
    pub staged: u64,
    /// Consumed items the decoder rejected.
    pub malformed: u64,
    /// Kernel-side drops observed.
    pub dropped: u64,
    /// Failure detail; empty on success.
    pub message: String,
}

/// One full 6-entry counter read (vals valid when ok).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapOut {
    /// True when the counters read.
    pub ok: bool,
    /// Six counter values in slot order.
    pub vals: Vec<u64>,
    /// Failure detail; empty on success.
    pub message: String,
}

/// Summed program recursion misses (counts valid when ok).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MissOut {
    /// True when the misses read.
    pub ok: bool,
    /// Summed misses.
    pub count: u64,
    /// Failure detail; empty on success.
    pub message: String,
    /// Subset of count skipped by the attempt (channel 0) programs.
    pub attempt: u64,
    /// True when the exact copy detail below is valid.
    pub has_copy_detail: bool,
    /// Bounce-entry misses.
    pub bounce: u64,
    /// Bounce-exit misses.
    pub exit_misses: u64,
    /// Sync-device misses.
    pub sync_device: u64,
    /// Sync-cpu misses.
    pub sync_cpu: u64,
    /// Map-result misses.
    pub lc_map: u64,
    /// Unmap misses.
    pub lc_unmap: u64,
    /// Deferred copies.
    pub deferred: u64,
    /// Recovered copies.
    pub recovered: u64,
    /// Copy-detail failure with attempt still valid; empty when none.
    pub detail_error: String,
}

/// Loader session surface behind scriptable outcomes.
///
/// Channel 0 is the attempt object; channels 1 and 2 are
/// the lifecycle and copy objects when present. The
/// unindexed map_info/read_full address channel 0; stats
/// sums across present channels on the live path (scripted
/// kernels return their script) while the _at variants
/// read one channel exactly.
pub trait KernelSource {
    /// Open every present channel or none.
    fn open_session(&mut self) -> OpOut;
    /// Load every present channel.
    fn load(&mut self) -> OpOut;
    /// Channel-0 geometry of one map.
    fn map_info(&mut self, name: &str) -> GeomOut;
    /// One channel's geometry of one map.
    fn map_info_at(&mut self, channel: i64, name: &str) -> GeomOut;
    /// Write the channel-0 offset table with read-back verify.
    fn install_offsets(&mut self, table: &[u8]) -> OpOut;
    /// Attach every present channel or none.
    fn attach(&mut self) -> OpOut;
    /// Write the copy fallback armed slot (copy channel only).
    fn set_copy_armed(&mut self, armed: bool) -> OpOut;
    /// Poll one batch with a staging capacity.
    fn poll(&mut self, timeout_ms: i64, capacity: u32) -> PollOut;
    /// Summed stats across present channels.
    fn stats(&mut self) -> StatsOut;
    /// One channel's stats.
    fn stats_at(&mut self, channel: i64) -> StatsOut;
    /// Channel-0 full counter read.
    fn read_full(&mut self) -> SnapOut;
    /// One channel's full counter read.
    fn read_full_at(&mut self, channel: i64) -> SnapOut;
    /// Present channel count.
    fn channel_count(&self) -> i64;
    /// Detach every present channel.
    fn detach(&mut self) -> OpOut;
    /// Runs the kernel skipped (trampoline recursion), summed.
    fn recursion_misses(&mut self) -> MissOut;
    /// Release everything; idempotent.
    fn close(&mut self) -> OpOut;
}

/// Monotonic nanoseconds plus settle sleeps.
pub trait ClockSource {
    /// Monotonic now in nanoseconds.
    fn now(&mut self) -> u64;
    /// Sleep `ms` milliseconds.
    fn sleep_ms(&mut self, ms: i64);
}

impl ClockSource for MonoClock {
    fn now(&mut self) -> u64 {
        MonoClock::now(self)
    }

    fn sleep_ms(&mut self, ms: i64) {
        MonoClock::sleep_ms(self, ms)
    }
}

/// Stop-signal source: setup plus none/pending/error checks.
pub trait SignalSource {
    /// Install the source; out.ok false refuses the run.
    fn setup(&mut self) -> OpOut;
    /// Check for a pending stop signal.
    fn check(&mut self) -> SignalOut;
}

impl SignalSource for LiveSignalSource {
    fn setup(&mut self) -> OpOut {
        LiveSignalSource::setup(self)
    }

    fn check(&mut self) -> SignalOut {
        LiveSignalSource::check(self)
    }
}

/// Everything run() needs beyond the sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollectorConfig {
    /// Capture duration in seconds.
    pub duration_s: u64,
    /// Events budget in bytes.
    pub max_events_bytes: u64,
    /// Output capture directory.
    pub output: String,
    /// Admitted profile id.
    pub profile_id: String,
    /// Admission grade.
    pub grade: String,
    /// Producer pid.
    pub pid: i64,
    /// Probed dev_name offset.
    pub off_loc: i64,
    /// Probed size offset.
    pub off_size: i64,
    /// Probed force offset.
    pub off_force: i64,
    /// Probed dynamic-data floor.
    pub off_fixed_end: i64,
    /// True when the attempt ring size binds.
    pub has_ring_bytes: bool,
    /// Bound attempt ring size.
    pub ring_bytes: u32,
    /// True when a boot id was reported.
    pub has_boot_id: bool,
    /// Boot identity.
    pub boot_id: String,
    /// Guest evidence.
    pub guest: GuestInfo,
    /// Admission evidence items.
    pub evidence: Vec<EvidenceItem>,
    /// True when pool sampling runs.
    pub has_pool_sample: bool,
    /// Evidence root for pool counters.
    pub pool_root: String,
    /// True when the lifecycle channel runs.
    pub has_lifecycle: bool,
    /// Bound lifecycle ring size.
    pub lifecycle_ring_bytes: u32,
    /// True when the copy channel runs.
    pub has_copy: bool,
    /// Bound copy ring size.
    pub copy_ring_bytes: u32,
    /// True when the conversion journal channel runs.
    pub has_journal: bool,
    /// True when the journal is the only channel (no attempt source).
    pub journal_only: bool,
    /// True when bounded journal caller processing runs.
    pub journal_callers: bool,
    /// Journal source profile identity.
    pub journal_profile: String,
    /// True when a device filter selects.
    pub has_device_filter: bool,
    /// Device selector.
    pub device_filter: String,
    /// True when attempt loss counts are a lower bound
    /// (kernels before 6.7 skip uncounted programs).
    pub attempt_loss_lower_bound: bool,
    /// True when the run must exit 4 unless the record
    /// verdict is complete (--strict).
    pub strict: bool,
}

impl Default for CollectorConfig {
    fn default() -> Self {
        Self {
            duration_s: 60,
            max_events_bytes: 1073741824,
            output: String::new(),
            profile_id: String::new(),
            grade: String::new(),
            pid: 0,
            off_loc: 8,
            off_size: 32,
            off_force: 40,
            off_fixed_end: 41,
            has_ring_bytes: false,
            ring_bytes: 0,
            has_boot_id: false,
            boot_id: String::new(),
            guest: GuestInfo {
                tech: "unknown".to_string(),
                signals: Vec::new(),
                asserted: false,
                conflict: String::new(),
            },
            evidence: Vec::new(),
            has_pool_sample: false,
            pool_root: String::new(),
            has_lifecycle: false,
            lifecycle_ring_bytes: 0,
            has_copy: false,
            copy_ring_bytes: 0,
            has_journal: false,
            journal_only: false,
            journal_callers: false,
            journal_profile: String::new(),
            has_device_filter: false,
            device_filter: String::new(),
            attempt_loss_lower_bound: false,
            strict: false,
        }
    }
}

/// One collector run: exit code + session routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunResult {
    /// Process exit code.
    pub exit_code: i64,
    /// End reason enum.
    pub end_reason: String,
    /// Outcome enum.
    pub outcome: String,
    /// Human diagnostic.
    pub diagnostic: String,
    /// User fix line.
    pub fix: String,
    /// Machine reason code.
    pub code: String,
    /// True when the refusal is uncertainty.
    pub unknown: bool,
    /// True when the failure is trusted evidence.
    pub trusted: bool,
}

/// Upper bound on the reader's tracked identities.
///
/// The reader counts distinct operation, mapping, excused,
/// and copy/sync reference ids; every counted id first
/// appears in one of these persisted events (copies and
/// syncs reference already-seen operations by construction
/// of the reader's checks), and each map contributes at most
/// its operation plus its mapping. Repeats only lower the
/// true count, so this sum never under-counts. Counters stop
/// growing once the gate latches, so the sum cannot overflow.
pub fn identity_estimate(
    persisted_attempt: u64,
    persisted_map: u64,
    persisted_map_ok: u64,
    persisted_unmap: u64,
    persisted_copy: u64,
    persisted_sync: u64,
) -> u64 {
    persisted_attempt
        + persisted_map
        + persisted_map_ok
        + persisted_unmap
        + persisted_copy
        + persisted_sync
}

/// True once the 4194304 identity budget is reached.
///
/// The argument is the estimate plus headroom for the next
/// record; the budget mirrors the reader's tracked-identity
/// cap, so a capture the writer finalizes is one the reader
/// accepts.
pub fn op_limited(identity_room: u64) -> bool {
    identity_room >= MAX_OPS
}

/// Saturating add: overflow pins at MAX (deadline math).
pub fn checked_add(a: u64, b: u64) -> u64 {
    a.saturating_add(b)
}

/// Truncate bytes to limit without splitting a codepoint.
fn cut_utf8(raw: &[u8], limit: usize) -> Vec<u8> {
    let mut n = raw.len().min(limit);
    while n > 0 && (raw[n - 1] & 0xC0) == 0x80 {
        n -= 1;
    }
    raw[..n].to_vec()
}

/// Bound evidence text; invalid UTF-8 becomes empty.
pub fn truncate_text(text: &str, limit: usize) -> String {
    let cut = cut_utf8(text.as_bytes(), limit);
    String::from_utf8(cut).unwrap_or_default()
}

/// True when two consecutive full reads agree exactly.
pub fn stable_cut(first: &[u64], second: &[u64]) -> bool {
    if first.len() != 6 || second.len() != 6 {
        return false;
    }
    for i in 0..6 {
        if first[i] != second[i] {
            return false;
        }
    }
    true
}

/// No count-channel wrap flags (byte coverage is separate).
pub fn epoch_flags_clear(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    let flags = vals[CNT_FLAGS];
    if flags & FLAG_OBSERVED_WRAP != 0 {
        return false;
    }
    if flags & FLAG_EMITTED_WRAP != 0 {
        return false;
    }
    if flags & FLAG_SUBMIT_WRAP != 0 {
        return false;
    }
    true
}

/// observed == emitted + submit_fail without wraparound.
pub fn count_identity(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    let observed = vals[CNT_OBSERVED];
    let emitted = vals[CNT_EMITTED];
    let failed = vals[CNT_SUBMIT_FAIL];
    if emitted > u64::MAX - failed {
        return false;
    }
    observed == emitted + failed
}

/// observed_bytes covers emitted_bytes (no silent loss).
pub fn byte_identity(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    vals[CNT_OBSERVED_BYTES] >= vals[CNT_EMITTED_BYTES]
}

/// All five availability rows valid (section 1.2 matrix).
pub fn counters_valid(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    let flags = vals[CNT_FLAGS];
    if flags & FLAG_OBSERVED_WRAP != 0 {
        return false;
    }
    if flags & FLAG_OBSERVED_BYTES_WRAP != 0 {
        return false;
    }
    if flags & FLAG_EMITTED_WRAP != 0 {
        return false;
    }
    if flags & FLAG_EMITTED_BYTES_WRAP != 0 {
        return false;
    }
    if flags & FLAG_SUBMIT_WRAP != 0 {
        return false;
    }
    true
}

/// Byte aggregate coverable: flags fully clear + identity.
pub fn byte_coverage_valid(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    if vals[CNT_FLAGS] != 0 {
        return false;
    }
    byte_identity(vals)
}

/// True when submit_fail is readable (no submit wrap).
pub fn submit_valid(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    vals[CNT_FLAGS] & FLAG_SUBMIT_WRAP == 0
}

/// True when all six slots are zero.
pub fn all_zero(vals: &[u64]) -> bool {
    if vals.len() != 6 {
        return false;
    }
    for v in vals {
        if *v != 0 {
            return false;
        }
    }
    true
}

fn pair(name: &str, value: &str) -> String {
    format!("{name}=({value})")
}

/// Strict `detail loss <N> (<9 pairs>)` grammar.
#[allow(clippy::too_many_arguments)]
pub fn detail_reason_known(
    submit_fail: u64,
    malformed: u64,
    dropped: u64,
    recursion_missed: u64,
    size_omitted: u64,
    duration_omitted: u64,
    signal_omitted: u64,
    rejected: u64,
    write_failed: u64,
) -> String {
    let total = submit_fail
        + malformed
        + dropped
        + recursion_missed
        + size_omitted
        + duration_omitted
        + signal_omitted
        + rejected
        + write_failed;
    let mut pairs = pair("submit_fail", &format_u64(submit_fail));
    pairs += &format!(" {}", pair("malformed", &format_u64(malformed)));
    pairs += &format!(" {}", pair("dropped", &format_u64(dropped)));
    pairs += &format!(
        " {}",
        pair("recursion_missed", &format_u64(recursion_missed))
    );
    pairs += &format!(" {}", pair("size_omitted", &format_u64(size_omitted)));
    pairs += &format!(
        " {}",
        pair("duration_omitted", &format_u64(duration_omitted))
    );
    pairs += &format!(" {}", pair("signal_omitted", &format_u64(signal_omitted)));
    pairs += &format!(" {}", pair("rejected", &format_u64(rejected)));
    pairs += &format!(" {}", pair("write_failed", &format_u64(write_failed)));
    format!("detail loss {} ({pairs})", format_u64(total))
}

/// Strict `detail loss unknown (<cause>; known: ...)` grammar.
#[allow(clippy::too_many_arguments)]
pub fn detail_reason_unknown(
    cause: &str,
    submit_fail: &str,
    malformed: &str,
    dropped: &str,
    recursion_missed: &str,
    size_omitted: u64,
    duration_omitted: u64,
    signal_omitted: u64,
    rejected: u64,
    write_failed: u64,
) -> String {
    let mut pairs = pair("submit_fail", submit_fail);
    pairs += &format!(" {}", pair("malformed", malformed));
    pairs += &format!(" {}", pair("dropped", dropped));
    pairs += &format!(" {}", pair("recursion_missed", recursion_missed));
    pairs += &format!(" {}", pair("size_omitted", &format_u64(size_omitted)));
    pairs += &format!(
        " {}",
        pair("duration_omitted", &format_u64(duration_omitted))
    );
    pairs += &format!(" {}", pair("signal_omitted", &format_u64(signal_omitted)));
    pairs += &format!(" {}", pair("rejected", &format_u64(rejected)));
    pairs += &format!(" {}", pair("write_failed", &format_u64(write_failed)));
    format!("detail loss unknown ({cause}; known: {pairs})")
}

/// Aggregate reason: present or absent with cause.
pub fn aggregate_reason(present: bool, cause: &str) -> String {
    if present {
        return "counter snapshots present (valid cut, identity holds, coverage valid)".to_string();
    }
    format!("counter snapshots absent ({cause})")
}

/// Environment mode enum for guest evidence.
pub fn env_mode_for(guest: &GuestInfo) -> String {
    if guest.tech == "snp" {
        return "sev_snp".to_string();
    }
    if guest.tech == "tdx" {
        return "tdx".to_string();
    }
    if guest.tech == "sev-classic" {
        return "sev".to_string();
    }
    if guest.tech == "ordinary" {
        return "none".to_string();
    }
    "unknown".to_string()
}

/// Detection enum for guest evidence.
pub fn detection_for(guest: &GuestInfo) -> String {
    if !guest.conflict.is_empty() {
        return "conflicting".to_string();
    }
    if guest.tech == "unknown" {
        return "unverified".to_string();
    }
    "kernel_reported".to_string()
}

/// One capture run: state machine over injected sources.
///
/// Sources arrive per call (never stored), so scripted
/// harnesses keep ownership for post-run assertions.
/// Buckets are exact u64 tallies; the latch and result
/// state follow the section 2 rules.
pub struct Collector {
    cfg: CollectorConfig,
    stop_reason: String,
    result_state: String,
    unknown_cause: String,
    persisted: u64,
    persisted_attempt: u64,
    persisted_map: u64,
    persisted_map_ok: u64,
    persisted_unmap: u64,
    persisted_copy: u64,
    persisted_sync: u64,
    persisted_sum: u64,
    size_omitted: u64,
    duration_omitted: u64,
    signal_omitted: u64,
    rejected: u64,
    unknown_copy_first: String,
    unknown_copy_slot_read: u64,
    unknown_copy_mask_read: u64,
    unknown_copy_bounds: u64,
    unknown_copy_layout: u64,
    unknown_copy_shift: u64,
    filtered: u64,
    write_failed: u64,
    max_persisted_ts: u64,
    start_ns: u64,
    max_snap_ts: u64,
    next_seq: u64,
    checkpoint_generation: u64,
    checkpoint_failures: u64,
    checkpoint_next_ns: u64,
    checkpoint_next_seq: u64,
    committed_stream: CommittedStream,
    table: DeviceTable,
    session_id: String,
    t_close: u64,
    end_ns: u64,
    start_vals: Vec<u64>,
    end_vals: Vec<u64>,
    has_end_cut: bool,
    start_vals_lc: Vec<u64>,
    end_vals_lc: Vec<u64>,
    has_end_cut_lc: bool,
    start_vals_cp: Vec<u64>,
    end_vals_cp: Vec<u64>,
    has_end_cut_cp: bool,
    start_pair_ts: u64,
    end_pair_ts: u64,
    stats_start: StatsOut,
    stats_drain: StatsOut,
    stats_final: StatsOut,
    has_final_stats: bool,
    recursion_missed: u64,
    attempt_missed: u64,
    attempt_known: bool,
    attempt_post_snapshot: bool,
    attempt_void_cause: String,
    has_recursion: bool,
    rec_has_detail: bool,
    rec_bounce: u64,
    rec_exit: u64,
    rec_sync_device: u64,
    rec_sync_cpu: u64,
    rec_lc_map: u64,
    rec_lc_unmap: u64,
    rec_deferred: u64,
    rec_recovered: u64,
    stats_start_ch0: StatsOut,
    stats_final_ch0: StatsOut,
    stats_start_lc: StatsOut,
    stats_final_lc: StatsOut,
    stats_start_cp: StatsOut,
    stats_final_cp: StatsOut,
    registry: CorrelationRegistry,
    closing_error: bool,
    snapshots_present: bool,
    attach_ns: u64,
    detach_ns: u64,
    ready_ns: u64,
    detach_begin_ns: u64,
    attempt_attach_done_ns: u64,
    attempt_detach_begin_ns: u64,
    secondary_causes: Vec<String>,
    signal_error: String,
    output_fs: String,
    pool_final: NormalizedPoolSample,
    pool_final_ts: u64,
    pool_has_final: bool,
    pool_ok: bool,
    pool_reason: String,
    pool_next_ts: u64,
    pool_periodic: i64,
    pool_periodic_capped: bool,
    pool_postcap: i64,
    pool_postcap_capped: bool,
    stop_ctl: StopController,
    stop_drained: i64,
    stop_drain_busy: bool,
    stop_misuse: bool,
    stop_evidence: StopEvidence,
    has_stop_evidence: bool,
    live: LivenessTally,
    journal_data: JournalCapture,
    journal_counts: Vec<u64>,
    journal_readable: bool,
    journal_done: bool,
}

/// Bounded admission-close drain budget in nanoseconds.
const JOURNAL_STOP_NS: u64 = 5000000000;

fn stats_out_blank(ok: bool) -> StatsOut {
    StatsOut {
        ok,
        received: 0,
        delivered: 0,
        staged: 0,
        malformed: 0,
        dropped: 0,
        message: String::new(),
    }
}

impl Collector {
    /// A fresh collector over one config.
    pub fn new(cfg: CollectorConfig) -> Self {
        Self {
            cfg,
            stop_reason: String::new(),
            result_state: "ok".to_string(),
            unknown_cause: String::new(),
            persisted: 0,
            persisted_attempt: 0,
            persisted_map: 0,
            persisted_map_ok: 0,
            persisted_unmap: 0,
            persisted_copy: 0,
            persisted_sync: 0,
            persisted_sum: 0,
            size_omitted: 0,
            duration_omitted: 0,
            signal_omitted: 0,
            rejected: 0,
            unknown_copy_first: String::new(),
            unknown_copy_slot_read: 0,
            unknown_copy_mask_read: 0,
            unknown_copy_bounds: 0,
            unknown_copy_layout: 0,
            unknown_copy_shift: 0,
            filtered: 0,
            write_failed: 0,
            max_persisted_ts: 0,
            start_ns: 0,
            max_snap_ts: 0,
            next_seq: 0,
            checkpoint_generation: 0,
            checkpoint_failures: 0,
            checkpoint_next_ns: 0,
            checkpoint_next_seq: 0,
            committed_stream: CommittedStream::new(),
            table: DeviceTable::new(),
            session_id: String::new(),
            t_close: 0,
            end_ns: 0,
            start_vals: Vec::new(),
            end_vals: Vec::new(),
            has_end_cut: false,
            start_vals_lc: Vec::new(),
            end_vals_lc: Vec::new(),
            has_end_cut_lc: false,
            start_vals_cp: Vec::new(),
            end_vals_cp: Vec::new(),
            has_end_cut_cp: false,
            start_pair_ts: 0,
            end_pair_ts: 0,
            stats_start: stats_out_blank(false),
            stats_drain: stats_out_blank(false),
            stats_final: stats_out_blank(false),
            has_final_stats: false,
            recursion_missed: 0,
            attempt_missed: 0,
            attempt_known: false,
            attempt_post_snapshot: false,
            attempt_void_cause: String::new(),
            has_recursion: false,
            rec_has_detail: false,
            rec_bounce: 0,
            rec_exit: 0,
            rec_sync_device: 0,
            rec_sync_cpu: 0,
            rec_lc_map: 0,
            rec_lc_unmap: 0,
            rec_deferred: 0,
            rec_recovered: 0,
            stats_start_ch0: stats_out_blank(false),
            stats_final_ch0: stats_out_blank(false),
            stats_start_lc: stats_out_blank(false),
            stats_final_lc: stats_out_blank(false),
            stats_start_cp: stats_out_blank(false),
            stats_final_cp: stats_out_blank(false),
            registry: CorrelationRegistry::new(),
            closing_error: false,
            snapshots_present: false,
            attach_ns: 0,
            detach_ns: 0,
            ready_ns: 0,
            detach_begin_ns: 0,
            attempt_attach_done_ns: 0,
            attempt_detach_begin_ns: 0,
            secondary_causes: Vec::new(),
            signal_error: String::new(),
            output_fs: String::new(),
            pool_final: NormalizedPoolSample::default(),
            pool_final_ts: 0,
            pool_has_final: false,
            pool_ok: false,
            pool_reason: String::new(),
            pool_next_ts: 0,
            pool_periodic: 0,
            pool_periodic_capped: false,
            pool_postcap: 0,
            pool_postcap_capped: false,
            stop_ctl: StopController::new(),
            stop_drained: 0,
            stop_drain_busy: false,
            stop_misuse: false,
            stop_evidence: StopEvidence {
                outcome: "partial".to_string(),
                reason: "stop evidence missing".to_string(),
                stop_budget_ms: STOP_BUDGET_MS,
                elapsed_ms: 0,
                admission_closed: false,
                quiescence_observed: false,
                writers_settled: 0,
                in_flight_at_close: 0,
                late_submits_drained: 0,
                drained_records: 0,
                has_drained: false,
                submit_after_drain: false,
                busy_at_drain: false,
                counters_valid: false,
                open_mappings: 0,
            },
            has_stop_evidence: false,
            live: LivenessTally::new(),
            journal_data: JournalCapture {
                session: crate::model::journal_session::JournalSession::default(),
                capture_start: 0,
                invalid_records: 0,
                sequence_gaps: 0,
                sequences: std::collections::HashMap::new(),
                last_result: 0,
            },
            journal_counts: Vec::new(),
            journal_readable: false,
            journal_done: false,
        }
    }

    /// First deviation wins; later ones are retained.
    fn note_unknown(&mut self, cause: String) {
        if self.unknown_cause.is_empty() {
            self.unknown_cause = cause;
            return;
        }
        if cause == self.unknown_cause {
            return;
        }
        if self
            .secondary_causes
            .last()
            .is_some_and(|last| cause == *last)
        {
            return;
        }
        self.secondary_causes.push(cause);
    }

    /// Immutable first trigger; empty latches once.
    fn latch(&mut self, reason: String) {
        if self.stop_reason.is_empty() {
            self.stop_reason = reason;
        }
    }

    /// Error trigger: immutable latch + monotonic error.
    fn fail(&mut self, reason: String) {
        self.latch(reason);
        self.result_state = "error".to_string();
    }

    /// Record the detach outcome as admission close/fail.
    ///
    /// Misuse is impossible by construction (ready runs
    /// close exactly once); the fallback keeps evidence
    /// total and loud if it ever happens.
    fn stop_close(&mut self, detached_ok: bool) {
        let res = if detached_ok {
            self.stop_ctl.close_admission()
        } else {
            self.stop_ctl.fail_close()
        };
        if res.is_err() {
            self.stop_misuse = true;
            self.result_state = "error".to_string();
            self.note_unknown("stop protocol misuse".to_string());
        }
    }

    fn stop_record_drain(&mut self, records: i64, busy: bool) {
        if self.stop_ctl.drain(records, busy).is_err() {
            self.stop_misuse = true;
            self.result_state = "error".to_string();
            self.note_unknown("stop protocol misuse".to_string());
        }
    }

    /// End cuts present and usable, mirroring evaluate.
    fn stop_counters_valid(&self) -> bool {
        if !self.has_end_cut {
            return false;
        }
        if !epoch_flags_clear(&self.end_vals) {
            return false;
        }
        if !count_identity(&self.end_vals) {
            return false;
        }
        if self.cfg.has_lifecycle {
            if !self.has_end_cut_lc {
                return false;
            }
            if !epoch_flags_clear(&self.end_vals_lc) {
                return false;
            }
            if !count_identity(&self.end_vals_lc) {
                return false;
            }
        }
        if self.cfg.has_copy {
            if !self.has_end_cut_cp {
                return false;
            }
            if !epoch_flags_clear(&self.end_vals_cp) {
                return false;
            }
            if !count_identity(&self.end_vals_cp) {
                return false;
            }
        }
        true
    }

    /// True only on present complete stop evidence.
    fn stop_complete(&self) -> bool {
        self.has_stop_evidence && self.stop_evidence.outcome == "complete"
    }

    /// Exit 0 for a finalized capture; strict needs completeness.
    ///
    /// A finalized session is valid no matter what it records, so
    /// the normal exit is 0 and completeness rides in the session
    /// verdict. Under --strict only a complete record verdict keeps
    /// 0; anything else exits 4.
    fn final_exit_code(&self, session: &Session) -> i64 {
        if !self.cfg.strict {
            return EXIT_OK;
        }
        let verdict = verdict_for_session(session, self.persisted_attempt);
        if verdict.name == "complete" {
            return EXIT_OK;
        }
        EXIT_PARTIAL
    }

    fn stop_open_mappings(&self) -> i64 {
        let mut open = 0u64;
        if self.persisted_map_ok > self.persisted_unmap {
            open = self.persisted_map_ok - self.persisted_unmap;
        }
        if open > i64::MAX as u64 {
            return i64::MAX;
        }
        open as i64
    }

    /// Finalize stop evidence over the close-out window.
    ///
    /// Elapsed runs detach to the finalize stamp (one
    /// clock read per run), which precedes the normal
    /// path's final pool sample and session publication.
    /// Milliseconds round up so a budget overrun can
    /// never truncate into the budget. A regressing
    /// stamp notes a clock failure; elapsed then stays
    /// zero beside that cause. Quiescence is never
    /// observed here: without the kernel-side protocol no
    /// consumer signal proves admitted writers settled,
    /// so live evidence always carries quiescence
    /// unproven.
    fn stop_finalize(&mut self, t1_ns: u64) {
        let mut elapsed = 0u64;
        if t1_ns >= self.detach_ns {
            let delta = t1_ns - self.detach_ns;
            elapsed = delta / 1000000;
            if !delta.is_multiple_of(1000000) {
                elapsed += 1;
            }
        } else {
            self.note_unknown("stop clock regressed".to_string());
        }
        if elapsed > i64::MAX as u64 {
            elapsed = i64::MAX as u64;
        }
        let ms = elapsed as i64;
        if self.stop_misuse {
            self.stop_evidence = StopEvidence {
                outcome: "partial".to_string(),
                reason: "stop protocol misuse".to_string(),
                stop_budget_ms: STOP_BUDGET_MS,
                elapsed_ms: ms,
                admission_closed: false,
                quiescence_observed: false,
                writers_settled: 0,
                in_flight_at_close: 0,
                late_submits_drained: 0,
                drained_records: 0,
                has_drained: false,
                submit_after_drain: false,
                busy_at_drain: false,
                counters_valid: false,
                open_mappings: 0,
            };
        } else {
            let open = self.stop_open_mappings();
            match self.stop_ctl.finalize_over_budget(ms, open) {
                Ok(ev) => {
                    self.stop_evidence = ev;
                }
                Err(_) => {
                    self.stop_misuse = true;
                    self.result_state = "error".to_string();
                    self.note_unknown("stop protocol misuse".to_string());
                    self.stop_evidence = StopEvidence {
                        outcome: "partial".to_string(),
                        reason: "stop protocol misuse".to_string(),
                        stop_budget_ms: STOP_BUDGET_MS,
                        elapsed_ms: ms,
                        admission_closed: false,
                        quiescence_observed: false,
                        writers_settled: 0,
                        in_flight_at_close: 0,
                        late_submits_drained: 0,
                        drained_records: 0,
                        has_drained: false,
                        submit_after_drain: false,
                        busy_at_drain: false,
                        counters_valid: false,
                        open_mappings: 0,
                    };
                }
            }
        }
        self.has_stop_evidence = true;
    }

    /// Count one crossed/drained record to the latch.
    fn omit_for_latch(&mut self) {
        if self.stop_reason == "duration" {
            self.duration_omitted += 1;
        } else if self.stop_reason == "size_limit" {
            self.size_omitted += 1;
        } else if self.stop_reason == "signal" {
            self.signal_omitted += 1;
        }
    }

    /// Run the stable protocol on one channel; store the cut.
    ///
    /// Reads full 6-entry vectors until two consecutive
    /// agree (bounded pairs) or any read fails over. The
    /// second read's timestamp stamps the pair (channel 0
    /// only; extra channels archive no snapshots); every
    /// reading's timestamp feeds max_snap_ts.
    fn stable_pair_at<K: KernelSource, C: ClockSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        channel: i64,
    ) -> bool {
        for _ in 0..STABLE_PAIRS {
            let first = kernel.read_full_at(channel);
            if !first.ok {
                continue;
            }
            let ts_first = clock.now();
            if ts_first > self.max_snap_ts {
                self.max_snap_ts = ts_first;
            }
            let second = kernel.read_full_at(channel);
            if !second.ok {
                continue;
            }
            let ts_second = clock.now();
            if ts_second > self.max_snap_ts {
                self.max_snap_ts = ts_second;
            }
            if stable_cut(&first.vals, &second.vals) {
                self.store_cut(channel, second.vals, ts_second);
                return true;
            }
        }
        false
    }

    /// Store one channel's stable cut.
    fn store_cut(&mut self, channel: i64, vals: Vec<u64>, ts: u64) {
        if channel == 1 {
            self.end_vals_lc = vals;
            self.has_end_cut_lc = true;
        } else if channel == 2 {
            self.end_vals_cp = vals;
            self.has_end_cut_cp = true;
        } else {
            self.end_vals = vals;
            self.end_pair_ts = ts;
            self.has_end_cut = true;
        }
    }
}

impl Collector {
    /// Full run: start, collect, close, finalize.
    pub fn run<K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> RunResult {
        let mut journal = NativeJournalKernel::new();
        self.run_with_journal(kernel, &mut journal, clock, signal, writer)
    }

    /// Full run with an explicit journal source.
    pub fn run_with_journal<
        K: KernelSource,
        J: JournalKernel,
        C: ClockSource,
        G: SignalSource,
        W: WriterSource,
    >(
        &mut self,
        kernel: &mut K,
        journal: &mut J,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> RunResult {
        let refusal = self.startup_with_journal(kernel, journal, clock, signal, writer);
        if !refusal.is_empty() {
            if self.cfg.has_journal {
                let _ = journal.close();
            }
            if self.cfg.journal_only {
                let residual = writer.abandon();
                return RunResult {
                    exit_code: if residual.is_empty() {
                        EXIT_REFUSAL
                    } else {
                        EXIT_ERROR
                    },
                    end_reason: "unknown".to_string(),
                    outcome: "refused".to_string(),
                    diagnostic: refusal,
                    fix: String::new(),
                    code: String::new(),
                    unknown: false,
                    trusted: false,
                };
            }
            return self.refuse(kernel, writer, refusal);
        }
        let stop = self.poll_loop_with_journal(kernel, journal, clock, signal, writer);
        if self.cfg.has_journal {
            self.close_journal(journal, clock, writer);
        }
        if stop == "unfinalizable"
            || (self.cfg.journal_only && self.result_state == "unfinalizable")
        {
            return self.drop_unfinalizable(writer);
        }
        if self.cfg.journal_only {
            return self.finish(clock, writer);
        }
        if stop == "error-path" {
            return self.error_close(kernel, clock, writer);
        }
        self.normal_close(kernel, clock, writer);
        if self.result_state == "unfinalizable" {
            return self.drop_unfinalizable(writer);
        }
        self.finish(clock, writer)
    }

    /// Poll one journal record into the capture; "" continues.
    fn journal_poll<J: JournalKernel, C: ClockSource, W: WriterSource>(
        &mut self,
        journal: &mut J,
        clock: &mut C,
        writer: &mut W,
        wait_ms: i64,
    ) -> String {
        let polled = journal.poll(wait_ms);
        if !polled.ok {
            self.fail("error".to_string());
            return "error-path".to_string();
        }
        if polled.data.is_empty() {
            return String::new();
        }
        let now = clock.now();
        if now == u64::MAX {
            self.fail("error".to_string());
            return "error-path".to_string();
        }
        let mut event = match self
            .journal_data
            .consume(&polled.data, &self.session_id, now + 1)
        {
            Ok(event) => event,
            Err(_) => {
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        event.seq = self.next_seq;
        let line = match encode_event_line(&event) {
            Ok(line) => line,
            Err(_) => {
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let wrote = writer.append(&line);
        if !wrote.ok {
            if wrote.kind == "refused" {
                self.latch("size_limit".to_string());
                return "closed".to_string();
            }
            if wrote.kind == "fatal" || wrote.kind == "misuse" {
                self.result_state = "unfinalizable".to_string();
                return "unfinalizable".to_string();
            }
            self.fail("error".to_string());
            return "error-path".to_string();
        }
        self.next_seq += 1;
        self.account_line(&line, "transition_result");
        if event.ts_ns > self.max_persisted_ts {
            self.max_persisted_ts = event.ts_ns;
        }
        String::new()
    }

    /// Bounded admission close: close admission, drain, detach, snapshot.
    fn close_journal<J: JournalKernel, C: ClockSource, W: WriterSource>(
        &mut self,
        journal: &mut J,
        clock: &mut C,
        writer: &mut W,
    ) {
        let close_ns = clock.now();
        let start = self.journal_data.session.admission_start_ns.value;
        let epoch = self.journal_data.session.epoch;
        let control = encode_journal_control(
            epoch,
            start,
            close_ns,
            false,
            true,
            self.cfg.journal_callers,
        );
        let closed = journal.control(&control);
        // Bound admitted callbacks by the completed write/readback, not by
        // the earlier request instant: callbacks can race the map update.
        let close_ns = clock.now();
        if self.journal_data.closed(close_ns, closed.ok).is_err() {
            self.fail("error".to_string());
        }
        let deadline = sat_add_u64(close_ns, JOURNAL_STOP_NS).0;
        for _ in 0..10000 {
            if clock.now() >= deadline {
                break;
            }
            let result = self.journal_poll(journal, clock, writer, 10);
            if !result.is_empty() {
                break;
            }
            let counters = journal.counters();
            if counters.ok && counters.values.len() == 15 && counters.values[12] == 0 {
                break;
            }
        }
        let disabled = journal.control(&encode_journal_control(
            epoch,
            start,
            close_ns,
            false,
            false,
            self.cfg.journal_callers,
        ));
        let detached = journal.detach();
        // Detached/quiet is only a bounded observation cut, never closure proof.
        for _ in 0..10000 {
            if clock.now() >= deadline {
                break;
            }
            let polled = journal.poll(0);
            if !polled.ok || polled.data.is_empty() {
                break;
            }
            let event = match self
                .journal_data
                .consume(&polled.data, &self.session_id, clock.now())
            {
                Ok(event) => event,
                Err(_) => {
                    self.fail("error".to_string());
                    break;
                }
            };
            let mut event = event;
            event.seq = self.next_seq;
            let line = match encode_event_line(&event) {
                Ok(line) => line,
                Err(_) => {
                    self.fail("error".to_string());
                    break;
                }
            };
            let wrote = writer.append(&line);
            if !wrote.ok {
                if wrote.kind == "fatal" || wrote.kind == "misuse" {
                    self.result_state = "unfinalizable".to_string();
                } else if wrote.kind == "refused" {
                    self.latch("size_limit".to_string());
                } else {
                    self.fail("error".to_string());
                }
                break;
            }
            self.next_seq += 1;
            self.account_line(&line, "transition_result");
            if event.ts_ns > self.max_persisted_ts {
                self.max_persisted_ts = event.ts_ns;
            }
        }
        let final_counters = journal.counters();
        self.journal_counts = final_counters.values.clone();
        self.journal_readable = final_counters.ok && disabled.ok && detached.ok;
        self.journal_done = true;
        if !journal.close().ok {
            self.fail("error".to_string());
        }
    }

    /// Open journal admission at readiness.
    fn open_journal<J: JournalKernel, C: ClockSource>(
        &mut self,
        journal: &mut J,
        clock: &mut C,
    ) -> String {
        let start = clock.now();
        let control = encode_journal_control(
            self.journal_data.session.epoch,
            start,
            0,
            true,
            true,
            self.cfg.journal_callers,
        );
        if !journal.control(&control).ok {
            return "journal readiness control failed".to_string();
        }
        if self.journal_data.opened(start).is_err() {
            return "journal readiness clock invalid".to_string();
        }
        String::new()
    }

    /// Clean rollback after a pre-readiness failure.
    fn refuse<K: KernelSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        writer: &mut W,
        reason: String,
    ) -> RunResult {
        let residual = writer.abandon();
        let closed = kernel.close();
        if !residual.is_empty() || !closed.ok {
            let mut diag = reason;
            if !residual.is_empty() {
                diag += &format!("; writer residual: {residual}");
            }
            if !closed.ok {
                diag += &format!("; close: {}", closed.message);
            }
            return RunResult {
                exit_code: EXIT_ERROR,
                end_reason: "unknown".to_string(),
                outcome: "refusal-rollback-failed".to_string(),
                diagnostic: diag,
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
        RunResult {
            exit_code: EXIT_REFUSAL,
            end_reason: "unknown".to_string(),
            outcome: "refused".to_string(),
            diagnostic: reason,
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        }
    }

    fn extra_channels(&self) -> bool {
        self.cfg.has_lifecycle || self.cfg.has_copy
    }

    /// Verify one extra channel's mv_counts + ring; "" ok.
    fn check_channel_maps<K: KernelSource>(
        &mut self,
        kernel: &mut K,
        channel: i64,
        tag: &str,
        ring_map: &str,
        ring_bytes: u32,
    ) -> String {
        let counts = kernel.map_info_at(channel, "mv_counts");
        if !counts.ok {
            return format!("map {tag} mv_counts: {}", counts.message);
        }
        if counts.map_type != MAP_TYPE_ARRAY
            || counts.key_size != 4
            || counts.value_size != 8
            || counts.max_entries != 6
        {
            return format!("map {tag} mv_counts geometry");
        }
        let ring = kernel.map_info_at(channel, ring_map);
        if !ring.ok {
            return format!("map {tag} {ring_map}: {}", ring.message);
        }
        if ring.map_type != MAP_TYPE_RINGBUF {
            return format!("map {tag} {ring_map} geometry");
        }
        if ring.max_entries != ring_bytes {
            return format!("map {tag} {ring_map} ring size");
        }
        String::new()
    }

    /// Admit enabled hooks to the registry; "" ok else reason.
    ///
    /// Admission (which hooks) follows record's
    /// capability selection; the namespace is a frozen
    /// semantic property (swiotlb hooks observe physical
    /// tlb-pool addresses, not IOVAs). Events from
    /// unadmitted hooks stay unpaired; a registry
    /// rejection here refuses before any probe attaches.
    fn admit_channel_hooks(&mut self) -> String {
        let mut res: Result<(), _> = Ok(());
        if self.cfg.has_lifecycle {
            res = self
                .registry
                .admit_hook(HOOK_MAP_RESULT, "tlb-phys")
                .and_then(|()| self.registry.admit_hook(HOOK_UNMAP, "tlb-phys"));
        }
        if res.is_ok() && self.cfg.has_copy {
            res = self
                .registry
                .admit_hook(HOOK_SYNC_DEVICE, "tlb-phys")
                .and_then(|()| self.registry.admit_hook(HOOK_SYNC_CPU, "tlb-phys"))
                .and_then(|()| self.registry.admit_hook(HOOK_BOUNCE, "tlb-phys"));
        }
        if res.is_err() {
            return "hook admission failed".to_string();
        }
        String::new()
    }

    /// Transactional start; "" means ready, else the reason.
    pub fn startup<K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> String {
        let mut journal = NativeJournalKernel::new();
        self.startup_with_journal(kernel, &mut journal, clock, signal, writer)
    }

    /// Transactional start with an explicit journal source.
    pub fn startup_with_journal<
        K: KernelSource,
        J: JournalKernel,
        C: ClockSource,
        G: SignalSource,
        W: WriterSource,
    >(
        &mut self,
        kernel: &mut K,
        journal: &mut J,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> String {
        let sig_ready = signal.setup();
        if !sig_ready.ok {
            return format!("signal setup: {}", sig_ready.message);
        }
        self.start_ns = clock.now();
        self.max_persisted_ts = self.start_ns;
        self.session_id = format!("cap-{}-{}", format_u64(self.start_ns), self.cfg.pid);
        if self.cfg.has_journal {
            self.journal_data = JournalCapture::new(
                self.start_ns.max(1),
                self.start_ns,
                self.cfg.journal_profile.clone(),
                self.cfg.journal_callers,
            );
            let prepared = journal.prepare(&encode_journal_control(
                self.journal_data.session.epoch,
                0,
                0,
                false,
                false,
                self.cfg.journal_callers,
            ));
            if !prepared.ok {
                return prepared.message;
            }
            if self.cfg.journal_only {
                let made = writer.create(&self.cfg.output, self.cfg.max_events_bytes);
                if !made.ok {
                    return "journal output create failed".to_string();
                }
                self.attach_ns = clock.now();
                self.journal_data.capture_start = self.attach_ns;
                if !journal.attach().ok {
                    return "journal attach failed".to_string();
                }
                self.ready_ns = clock.now();
                let checkpoint_note = self.checkpoint(writer, self.ready_ns);
                if !checkpoint_note.is_empty() {
                    return checkpoint_note;
                }
                return self.open_journal(journal, clock);
            }
        }
        let opened = kernel.open_session();
        if !opened.ok {
            return format!("open: {}", opened.message);
        }
        let loaded = kernel.load();
        if !loaded.ok {
            return format!("load: {}", loaded.message);
        }
        let counts = kernel.map_info("mv_counts");
        if !counts.ok {
            return format!("map mv_counts: {}", counts.message);
        }
        if counts.map_type != MAP_TYPE_ARRAY
            || counts.key_size != 4
            || counts.value_size != 8
            || counts.max_entries != 6
        {
            return "map mv_counts geometry".to_string();
        }
        let ring = kernel.map_info("mv_attempts");
        if !ring.ok {
            return format!("map mv_attempts: {}", ring.message);
        }
        if ring.map_type != MAP_TYPE_RINGBUF {
            return "map mv_attempts geometry".to_string();
        }
        if self.cfg.has_ring_bytes && ring.max_entries != self.cfg.ring_bytes {
            return "map mv_attempts ring size".to_string();
        }
        // The load-time offset table installs between load
        // and attach: the program reads every attempt field
        // through it, so a bad install refuses here, before
        // any firing can misread.
        let offgeom = kernel.map_info("mv_offsets");
        if !offgeom.ok {
            return format!("map mv_offsets: {}", offgeom.message);
        }
        let offsets_len = crate::platform::narrow::MV_OFFSETS_TABLE_LEN as u32;
        if offgeom.map_type != MAP_TYPE_ARRAY
            || offgeom.key_size != 4
            || offgeom.value_size != offsets_len
            || offgeom.max_entries != 1
        {
            return "map mv_offsets geometry".to_string();
        }
        let bad = validate_table_extents(
            self.cfg.off_loc,
            self.cfg.off_size,
            self.cfg.off_force,
            self.cfg.off_fixed_end,
        );
        if !bad.is_empty() {
            return format!("install offsets: {bad}");
        }
        let table = encode_offsets_table(
            self.cfg.off_loc,
            self.cfg.off_size,
            self.cfg.off_force,
            self.cfg.off_fixed_end,
        );
        let installed = kernel.install_offsets(&table);
        if !installed.ok {
            return format!("install offsets: {}", installed.message);
        }
        if self.cfg.has_lifecycle {
            let lc_maps = self.check_channel_maps(
                kernel,
                1,
                "lc",
                "mv_lifecycle",
                self.cfg.lifecycle_ring_bytes,
            );
            if !lc_maps.is_empty() {
                return lc_maps;
            }
        }
        if self.cfg.has_copy {
            let cp_maps =
                self.check_channel_maps(kernel, 2, "cp", "mv_copies", self.cfg.copy_ring_bytes);
            if !cp_maps.is_empty() {
                return cp_maps;
            }
            let fb = kernel.map_info_at(2, "mv_copy_fb");
            if !fb.ok {
                return format!("map cp mv_copy_fb: {}", fb.message);
            }
            if fb.map_type != MAP_TYPE_ARRAY
                || fb.key_size != 4
                || fb.value_size != 8
                || fb.max_entries != 4
            {
                return "map cp mv_copy_fb geometry".to_string();
            }
            let claims = kernel.map_info_at(2, "mv_claims");
            if !claims.ok {
                return format!("map cp mv_claims: {}", claims.message);
            }
            if claims.map_type != MAP_TYPE_ARRAY
                || claims.key_size != 4
                || claims.value_size != 16
                || claims.max_entries != 4096
            {
                return "map cp mv_claims geometry".to_string();
            }
        }
        if !self.stable_pair_at(kernel, clock, 0) {
            return "start snapshot unresolved".to_string();
        }
        self.start_vals = self.end_vals.clone();
        self.start_pair_ts = self.end_pair_ts;
        self.has_end_cut = false;
        if !all_zero(&self.start_vals) {
            return "start snapshot nonzero".to_string();
        }
        if self.cfg.has_lifecycle {
            if !self.stable_pair_at(kernel, clock, 1) {
                return "start lc snapshot unresolved".to_string();
            }
            self.start_vals_lc = self.end_vals_lc.clone();
            self.has_end_cut_lc = false;
            if !all_zero(&self.start_vals_lc) {
                return "start lc snapshot nonzero".to_string();
            }
        }
        if self.cfg.has_copy {
            if !self.stable_pair_at(kernel, clock, 2) {
                return "start cp snapshot unresolved".to_string();
            }
            self.start_vals_cp = self.end_vals_cp.clone();
            self.has_end_cut_cp = false;
            if !all_zero(&self.start_vals_cp) {
                return "start cp snapshot nonzero".to_string();
            }
        }
        let baseline = kernel.stats();
        if !baseline.ok {
            return format!("start stats: {}", baseline.message);
        }
        self.stats_start = baseline;
        if self.extra_channels() {
            let ch0 = kernel.stats_at(0);
            if !ch0.ok {
                return format!("start ch0 stats: {}", ch0.message);
            }
            self.stats_start_ch0 = ch0;
            if self.cfg.has_lifecycle {
                let blc = kernel.stats_at(1);
                if !blc.ok {
                    return format!("start lc stats: {}", blc.message);
                }
                self.stats_start_lc = blc;
            }
            if self.cfg.has_copy {
                let bcp = kernel.stats_at(2);
                if !bcp.ok {
                    return format!("start cp stats: {}", bcp.message);
                }
                self.stats_start_cp = bcp;
            }
        }
        let made = writer.create(&self.cfg.output, self.cfg.max_events_bytes);
        if !made.ok {
            return format!("output {}: {}", made.kind, made.message);
        }
        self.output_fs = fs_type_name(&self.cfg.output);
        if self.extra_channels() {
            let admitted = self.admit_channel_hooks();
            if !admitted.is_empty() {
                return admitted;
            }
        }
        // The window floor is read BEFORE activation: a firing
        // between link activation and a post-attach timestamp
        // would persist below the declared window and the reader
        // would reject the capture. Nothing can fire before the
        // links exist, so a pre-attach floor stays tight without
        // backdating across the init gap.
        self.attach_ns = clock.now();
        let attached = kernel.attach();
        if !attached.ok {
            return format!("attach: {}", attached.message);
        }
        // Attempt attaches last, so attach completion bounds
        // the attempt hook's live interval from below on the
        // same clock as the window.
        self.attempt_attach_done_ns = clock.now();
        if self.cfg.has_copy {
            // Arm only after every copy link exists, so no bare exit inflates recoveries.
            let armed = kernel.set_copy_armed(true);
            if !armed.ok {
                return format!("arm copy: {}", armed.message);
            }
        }
        // Ready means firing is live; R starts a guard later, past in-flight maps.
        self.ready_ns = clock.now();
        let t_r = sat_add_u64(self.ready_ns, LIVENESS_GUARD_NS).0;
        self.live.retarget(self.attach_ns, t_r);
        if self.cfg.has_journal {
            self.journal_data.capture_start = self.attach_ns;
            if !journal.attach().ok {
                return "journal attach failed".to_string();
            }
        }
        let checkpoint_note = self.checkpoint(writer, self.ready_ns);
        if !checkpoint_note.is_empty() {
            return format!("output readiness checkpoint: {checkpoint_note}");
        }
        if self.cfg.has_journal {
            let note = self.open_journal(journal, clock);
            if !note.is_empty() {
                return note;
            }
        }
        if self.cfg.has_pool_sample {
            // Baseline pool sample, persisted first: the file
            // stays chronological (baseline, periodic, final)
            // so order-based reducers cannot misread a held
            // baseline as a late sample. Pool samples are not
            // bridge-delivered, so only the persisted-ts
            // maximum moves.
            let base = self.sample_pool_now(clock);
            let line = match self.pool_sample_event(&base.0, base.1) {
                Ok(line) => line,
                Err(_) => {
                    self.next_seq -= 1;
                    return "output pool baseline unencodable".to_string();
                }
            };
            let wrote = writer.append(&line);
            if !wrote.ok {
                self.next_seq -= 1;
                return format!("output pool baseline {}: {}", wrote.kind, wrote.message);
            }
            self.account_line(&line, "pool_sample");
            if base.0.has_used_bytes || base.0.has_capacity_bytes {
                self.pool_ok = true;
            }
            if base.1 > self.max_persisted_ts {
                self.max_persisted_ts = base.1;
            }
            if !base.0.reason.is_empty() {
                self.pool_reason = base.0.reason.clone();
            }
        }
        self.pool_next_ts = checked_add(self.attach_ns, POOL_SAMPLE_INTERVAL_NS);
        println!(
            "ready session={} start_ns={}",
            self.session_id,
            format_u64(self.start_ns)
        );
        self.stop_ctl.mark_ready();
        String::new()
    }
}

impl Collector {
    /// Snapshot committed metadata without claiming terminal settlement.
    fn checkpoint<W: WriterSource>(&mut self, writer: &mut W, now: u64) -> String {
        self.checkpoint_next_ns = sat_add_u64(now, 10000000000).0;
        self.checkpoint_next_seq = sat_add_u64(self.next_seq, 1000).0;
        if self.checkpoint_generation == u64::MAX {
            self.checkpoint_failures = sat_add_u64(self.checkpoint_failures, 1).0;
            return "checkpoint generation exhausted".to_string();
        }
        self.checkpoint_generation += 1;
        let mut note = String::new();
        let snap: Result<Session, EncodeError> = (|| {
            let mut snapshot = self.assemble()?;
            snapshot.finalized = false;
            snapshot.end_reason = "checkpoint".to_string();
            snapshot.has_end_reason = true;
            snapshot.has_checkpoint_generation = true;
            snapshot.checkpoint_generation = self.checkpoint_generation;
            let horizon = now.max(self.max_persisted_ts);
            if horizon == u64::MAX {
                return Err(EncodeError::new("checkpoint", "window end overflow"));
            }
            snapshot.window_end_ns = horizon + 1;
            if self.cfg.has_journal {
                match self.journal_data.snapshot(
                    snapshot.window_end_ns,
                    false,
                    &self.journal_counts,
                    self.journal_readable,
                ) {
                    Ok(journal) => {
                        snapshot.journal = journal;
                        snapshot.has_journal = true;
                    }
                    Err(_) => {
                        return Err(EncodeError::new("journal", "checkpoint snapshot invalid"));
                    }
                }
            }
            snapshot.has_integrity = true;
            snapshot.integrity = self.committed_stream.snapshot();
            if snapshot.integrity.events_bytes != writer.committed_len()
                || snapshot.integrity.line_count != self.next_seq
            {
                return Err(EncodeError::new("checkpoint", "committed prefix mismatch"));
            }
            snapshot.stop.outcome = "partial".to_string();
            snapshot.stop.reason = "checkpoint: measurement window remains open".to_string();
            snapshot.stop.admission_closed = false;
            snapshot.stop.quiescence_observed = false;
            snapshot.stop.drain_completed = false;
            snapshot.stop.counters_valid = false;
            snapshot.q_terminal.status = "partial".to_string();
            snapshot.q_terminal.reason = snapshot.stop.reason.clone();
            snapshot.q_detail.status = "partial".to_string();
            snapshot.q_detail.has_loss_count = false;
            snapshot.q_detail.reason = snapshot.stop.reason.clone();
            snapshot.has_verdict = false;
            let text = encode_session(&snapshot)?;
            let result = writer.checkpoint(text.as_bytes());
            if result.ok {
                return Ok(snapshot);
            }
            note = result.message;
            Err(EncodeError::new("checkpoint", "unreachable"))
        })();
        if snap.is_ok() {
            return String::new();
        }
        if note.is_empty()
            && let Err(e) = snap
        {
            note = e.to_string();
        }
        self.checkpoint_failures = sat_add_u64(self.checkpoint_failures, 1).0;
        note
    }

    /// One resolved poll: shorts retried once at size.
    ///
    /// Returns timeout, batch, or error. A second short,
    /// a zero required size, or a timeout after a short
    /// (retained record lost) is a transport violation.
    fn poll_one<K: KernelSource>(&mut self, kernel: &mut K, timeout_ms: i64) -> PollOut {
        let out = kernel.poll(timeout_ms, POLL_CAPACITY);
        if out.kind != "short" {
            return out;
        }
        if out.required == 0 {
            return PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: "short without size".to_string(),
            };
        }
        let retry = kernel.poll(0, out.required);
        if retry.kind == "batch" {
            return retry;
        }
        if retry.kind == "timeout" {
            return PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: "retained record lost".to_string(),
            };
        }
        if retry.kind == "short" {
            return PollOut {
                kind: "error".to_string(),
                frame: Vec::new(),
                required: 0,
                message: "repeated short".to_string(),
            };
        }
        retry
    }

    /// Collect until a latch; error-path/unfinalizable/closed.
    pub fn poll_loop<K: KernelSource, C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> String {
        let mut journal = NativeJournalKernel::new();
        self.poll_loop_with_journal(kernel, &mut journal, clock, signal, writer)
    }

    /// Collect with an explicit journal source.
    pub fn poll_loop_with_journal<
        K: KernelSource,
        J: JournalKernel,
        C: ClockSource,
        G: SignalSource,
        W: WriterSource,
    >(
        &mut self,
        kernel: &mut K,
        journal: &mut J,
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
    ) -> String {
        let mut dur_ns = u64::MAX;
        if self.cfg.duration_s <= u64::MAX / 1000000000 {
            dur_ns = self.cfg.duration_s * 1000000000;
        }
        // The duration budget starts at readiness (attach),
        // not at pre-init: init latency must not burn it.
        let deadline = checked_add(self.attach_ns, dur_ns);
        // After an admitted frame its gate has just checked signals.
        let mut gated = false;
        loop {
            if !gated {
                let sig = signal.check();
                if sig.state == "pending" {
                    self.latch("signal".to_string());
                    return "closed".to_string();
                }
                if sig.state == "error" {
                    self.latch("signal".to_string());
                    self.result_state = "error".to_string();
                    self.signal_error = sig.message;
                    return "closed".to_string();
                }
            }
            gated = false;
            let now = clock.now();
            if now >= deadline {
                self.latch("duration".to_string());
                return "closed".to_string();
            }
            if now >= self.checkpoint_next_ns || self.next_seq >= self.checkpoint_next_seq {
                let _ = self.checkpoint(writer, now);
            }
            if self.cfg.has_journal {
                let journal_tick = self.journal_poll(
                    journal,
                    clock,
                    writer,
                    if self.cfg.journal_only { 10 } else { 0 },
                );
                if !journal_tick.is_empty() {
                    return journal_tick;
                }
                if self.cfg.journal_only {
                    continue;
                }
            }
            let ptick = self.maybe_sample_pool(clock, writer, now);
            if !ptick.is_empty() {
                return ptick;
            }
            let remaining_ms = (deadline - now) / 1000000;
            let mut wait = POLL_QUANTUM_MS;
            if remaining_ms < wait as u64 {
                wait = remaining_ms as i64;
            }
            let out = self.poll_one(kernel, wait);
            if out.kind == "timeout" {
                continue;
            }
            if out.kind == "error" {
                self.fail("error".to_string());
                return "error-path".to_string();
            }
            let verdict = self.admit(&out.frame, clock, signal, writer, deadline);
            if !verdict.is_empty() {
                return verdict;
            }
            gated = true;
        }
    }

    /// Dispose one delivered batch; "" continues the loop.
    fn admit<C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        payload: &[u8],
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
        deadline: u64,
    ) -> String {
        if payload.len() == PAYLOAD_LEN {
            return self.admit_attempt(payload, clock, signal, writer, deadline);
        }
        if payload.len() == LC_LEN {
            return self.admit_lifecycle(payload, clock, signal, writer, deadline);
        }
        if payload.len() == CP_LEN {
            return self.admit_copy(payload, clock, signal, writer, deadline);
        }
        self.rejected += 1;
        self.fail("error".to_string());
        "error-path".to_string()
    }

    /// Pre-normalize latch gate; "" admits, else closed.
    fn gate<C: ClockSource, G: SignalSource>(
        &mut self,
        clock: &mut C,
        signal: &mut G,
        deadline: u64,
    ) -> String {
        let sig = signal.check();
        if sig.state == "pending" {
            self.latch("signal".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        if sig.state == "error" {
            self.latch("signal".to_string());
            self.result_state = "error".to_string();
            self.signal_error = sig.message;
            self.omit_for_latch();
            return "closed".to_string();
        }
        let now = clock.now();
        if now >= deadline {
            self.latch("duration".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        // Identity budget, aligned with the reader's tracked-id
        // cap: stop while the costliest next record (a map plus
        // its mapping) still fits, so the finalized capture is
        // one the reader accepts. Counter events add no ids.
        let room = identity_estimate(
            self.persisted_attempt,
            self.persisted_map,
            self.persisted_map_ok,
            self.persisted_unmap,
            self.persisted_copy,
            self.persisted_sync,
        );
        if op_limited(room + 2) {
            self.latch("size_limit".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        String::new()
    }

    fn account_line(&mut self, line: &[u8], kind: &str) {
        if self.committed_stream.commit(line, kind).is_err() {
            // Internal accounting failure cannot authorize a final session.
            self.result_state = "unfinalizable".to_string();
        }
    }

    /// Append one encoded event; "" persisted, else closed/error.
    fn persist_line<W: WriterSource>(
        &mut self,
        writer: &mut W,
        line: Vec<u8>,
        byte_count: u64,
        ts_ns: u64,
        kind: &str,
    ) -> String {
        let wrote = writer.append(&line);
        if wrote.ok {
            self.account_line(&line, kind);
            self.persisted += 1;
            self.persisted_sum += byte_count;
            if ts_ns > self.max_persisted_ts {
                self.max_persisted_ts = ts_ns;
            }
            if kind == "bounce_attempt" {
                self.persisted_attempt += 1;
            } else if kind == "map_result" {
                self.persisted_map += 1;
            } else if kind == "unmap" {
                self.persisted_unmap += 1;
            } else if kind == "copy" {
                self.persisted_copy += 1;
            } else if kind == "sync_request" {
                self.persisted_sync += 1;
            }
            return String::new();
        }
        if wrote.kind == "refused" {
            self.next_seq -= 1;
            self.latch("size_limit".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        self.next_seq -= 1;
        self.write_failed += 1;
        if wrote.kind == "fatal" || wrote.kind == "misuse" {
            self.result_state = "unfinalizable".to_string();
            return "unfinalizable".to_string();
        }
        self.fail("error".to_string());
        "error-path".to_string()
    }

    fn admit_attempt<C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        payload: &[u8],
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
        deadline: u64,
    ) -> String {
        let attempt: DecodedAttempt = match decode_payload(payload) {
            Ok(a) => a,
            Err(_) => {
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let gate = self.gate(clock, signal, deadline);
        if !gate.is_empty() {
            return gate;
        }
        // Malformed names stay malformed under a filter;
        // selection runs on valid names before interning so
        // dropped devices consume no catalog ids.
        if !is_valid_utf8(&attempt.name) {
            self.rejected += 1;
            return String::new();
        }
        if self.cfg.has_device_filter && !selection_matches(&attempt.name, &self.cfg.device_filter)
        {
            self.filtered += 1;
            return String::new();
        }
        let normalized: NormalizedAttempt = match normalize_attempt(&attempt, &mut self.table) {
            Ok(n) => n,
            Err(e) => {
                if !e.fatal {
                    self.rejected += 1;
                    return String::new();
                }
                self.rejected += 1;
                if e.reason == "INTERNAL" {
                    self.result_state = "unfinalizable".to_string();
                    return "unfinalizable".to_string();
                }
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        self.live.note_attempt(attempt.ktime);
        if normalized.requested_bytes > u64::MAX - self.persisted_sum {
            self.latch("size_limit".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        let line = match self.encode_attempt(&normalized) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.result_state = "unfinalizable".to_string();
                return "unfinalizable".to_string();
            }
        };
        let requested = normalized.requested_bytes;
        let ts = normalized.ts_ns;
        self.persist_line(writer, line, requested, ts, "bounce_attempt")
    }

    fn admit_lifecycle<C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        payload: &[u8],
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
        deadline: u64,
    ) -> String {
        let decoded: DecodedLifecycle = match decode_lifecycle(payload) {
            Ok(d) => d,
            Err(_) => {
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let gate = self.gate(clock, signal, deadline);
        if !gate.is_empty() {
            return gate;
        }
        let mut ev = normalize_lifecycle_event(&decoded);
        if ev.kind == "map_result" {
            self.live.note_map(decoded.ktime, decoded.ok);
        } else if ev.kind == "unmap" {
            self.live
                .note_unmap(decoded.ktime, decoded.dir, decoded.skip_sync);
        }
        if decoded.size > u64::MAX - self.persisted_sum {
            self.latch("size_limit".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        self.fill_source_hook(&mut ev);
        ev = match self.registry.normalize(ev, "capture") {
            Ok(ev) => ev,
            Err(_) => {
                self.next_seq -= 1;
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let line = match encode_event_line(&ev) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.result_state = "unfinalizable".to_string();
                return "unfinalizable".to_string();
            }
        };
        let ok_map = ev.kind == "map_result" && ev.map_result.success;
        let kind = ev.kind.clone();
        let res = self.persist_line(writer, line, decoded.size, decoded.ktime, &kind);
        if res.is_empty() && ok_map {
            self.persisted_map_ok += 1;
        }
        res
    }

    /// Unknown copies charge their wire reason; the first names the detail.
    fn note_unknown_copy(&mut self, decoded: &DecodedCopy) {
        if decoded.kind != CP_KIND_COPY || decoded.known {
            return;
        }
        if decoded.reason == CP_REASON_SLOT_READ {
            self.unknown_copy_slot_read += 1;
        } else if decoded.reason == CP_REASON_MASK_READ {
            self.unknown_copy_mask_read += 1;
        } else if decoded.reason == CP_REASON_BOUNDS {
            self.unknown_copy_bounds += 1;
        } else if decoded.reason == CP_REASON_LAYOUT {
            self.unknown_copy_layout += 1;
        } else if decoded.reason == CP_REASON_SHIFT {
            self.unknown_copy_shift += 1;
        } else {
            return;
        }
        if self.unknown_copy_first.is_empty() {
            self.unknown_copy_first = copy_unknown_reason_name(decoded.reason);
        }
    }

    fn admit_copy<C: ClockSource, G: SignalSource, W: WriterSource>(
        &mut self,
        payload: &[u8],
        clock: &mut C,
        signal: &mut G,
        writer: &mut W,
        deadline: u64,
    ) -> String {
        let decoded: DecodedCopy = match decode_copy(payload) {
            Ok(d) => d,
            Err(_) => {
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let gate = self.gate(clock, signal, deadline);
        if !gate.is_empty() {
            return gate;
        }
        let mut ev: Event = match normalize_copy_event(&decoded) {
            Ok(ev) => ev,
            Err(e) => {
                if !e.fatal {
                    self.rejected += 1;
                    self.note_unknown_copy(&decoded);
                    return String::new();
                }
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        if ev.kind == "sync_request" {
            self.live
                .note_sync(decoded.ktime, decoded.to_device, decoded.dir);
        } else if ev.kind == "copy" {
            self.live.note_copy(decoded.ktime, decoded.dir);
        }
        let mut byte_count = decoded.requested;
        if ev.kind == "copy" {
            byte_count = decoded.effective;
        }
        if byte_count > u64::MAX - self.persisted_sum {
            self.latch("size_limit".to_string());
            self.omit_for_latch();
            return "closed".to_string();
        }
        self.fill_source_hook(&mut ev);
        ev = match self.registry.normalize(ev, "capture") {
            Ok(ev) => ev,
            Err(_) => {
                self.next_seq -= 1;
                self.rejected += 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let line = match encode_event_line(&ev) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.result_state = "unfinalizable".to_string();
                return "unfinalizable".to_string();
            }
        };
        let kind = ev.kind.clone();
        self.persist_line(writer, line, byte_count, decoded.ktime, &kind)
    }
}

impl Collector {
    fn mark_detach_begin<C: ClockSource>(&mut self, clock: &mut C) {
        // The stop edge stamps once here, before the first detach call.
        // Attempt detaches first, so the same read bounds the
        // attempt hook's live interval from above.
        self.detach_begin_ns = clock.now();
        self.attempt_detach_begin_ns = self.detach_begin_ns;
    }

    /// DETACHING -> SETTLE -> DRAINING -> STATS -> CONFIRM.
    pub fn normal_close<K: KernelSource, C: ClockSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        _writer: &mut W,
    ) {
        self.mark_detach_begin(clock);
        if self.cfg.has_copy {
            // Disarm before detach, so no late exit recovers after the end cut.
            let disarmed = kernel.set_copy_armed(false);
            if !disarmed.ok {
                self.note_unknown(format!("copy disarm failed: {}", disarmed.message));
            }
        }
        let detached = kernel.detach();
        self.detach_ns = clock.now();
        self.stop_close(detached.ok);
        if !detached.ok {
            self.note_unknown("detach failed; shutdown evidence unresolved".to_string());
        }
        self.read_misses(kernel);
        clock.sleep_ms(SETTLE_MS);
        self.drain(kernel, clock);
        if !self.stable_pair_at(kernel, clock, 0) {
            self.note_unknown("snapshot unresolved".to_string());
            self.has_end_cut = false;
        } else {
            if self.cfg.has_lifecycle && !self.stable_pair_at(kernel, clock, 1) {
                self.note_unknown("lc snapshot unresolved".to_string());
                self.has_end_cut_lc = false;
            }
            if self.cfg.has_copy && !self.stable_pair_at(kernel, clock, 2) {
                self.note_unknown("cp snapshot unresolved".to_string());
                self.has_end_cut_cp = false;
            }
            let mut guard = 0;
            let mut last_ts = self.end_pair_ts;
            while last_ts <= self.max_persisted_ts && guard < ADVANCE_MAX {
                last_ts = clock.now();
                guard += 1;
            }
        }
        let drain_stats = kernel.stats();
        if drain_stats.ok {
            self.stats_drain = drain_stats;
        } else {
            self.note_unknown("error shutdown".to_string());
        }
        self.confirm(kernel);
        let drain_busy =
            self.stop_drain_busy || !self.stats_drain.ok || self.stats_drain.staged != 0;
        self.stop_record_drain(self.stop_drained, drain_busy);
        // The sample must follow the last drain: a new
        // boundary claim invalidates any earlier sample.
        let valid = self.stop_counters_valid();
        self.stop_ctl.sample_counters(valid);
        let t1 = clock.now();
        self.stop_finalize(t1);
        if self.cfg.has_pool_sample {
            // Final pool sample, held for the closing path with
            // its true timestamp (always before t_close, so the
            // window end covers it).
            let fin = self.sample_pool_now(clock);
            self.pool_final = fin.0;
            self.pool_final_ts = fin.1;
            self.pool_has_final = true;
        }
    }

    /// Bounded consume-and-count; every record omitted.
    ///
    /// Consumed batches feed the stop drain count; any
    /// unsettled exit (budget, error, unreadable stats)
    /// marks the drain busy. Confirm-phase batches stay
    /// out: they arrive after the end cut and note their
    /// own deviation.
    fn drain<K: KernelSource, C: ClockSource>(&mut self, kernel: &mut K, clock: &mut C) {
        let start = clock.now();
        let budget_s = checked_add(start, DRAIN_MAX_S as u64 * 1000000000);
        let mut prev_received = u64::MAX;
        let mut prev_malformed = u64::MAX;
        let mut have_prev = false;
        for _ in 0..DRAIN_MAX_POLLS {
            let now = clock.now();
            if now >= budget_s {
                self.note_unknown("drain budget exhausted".to_string());
                self.stop_drain_busy = true;
                return;
            }
            let out = self.poll_one(kernel, 0);
            if out.kind == "batch" {
                self.stop_drained += 1;
                self.omit_for_latch();
                continue;
            }
            if out.kind != "timeout" {
                self.note_unknown("error shutdown".to_string());
                self.result_state = "error".to_string();
                self.stop_drain_busy = true;
                return;
            }
            let stats = kernel.stats();
            if !stats.ok {
                self.note_unknown("error shutdown".to_string());
                self.stop_drain_busy = true;
                return;
            }
            if have_prev
                && stats.staged == 0
                && stats.received == prev_received
                && stats.malformed == prev_malformed
            {
                return;
            }
            prev_received = stats.received;
            prev_malformed = stats.malformed;
            have_prev = true;
        }
        self.note_unknown("drain budget exhausted".to_string());
        self.stop_drain_busy = true;
    }

    /// Read skipped program runs once the probes are detached.
    fn read_misses<K: KernelSource>(&mut self, kernel: &mut K) {
        let m = kernel.recursion_misses();
        if !m.ok {
            self.note_unknown(format!("recursion misses unreadable: {}", m.message));
            return;
        }
        if !m.detail_error.is_empty() {
            self.attempt_missed = m.attempt;
            self.attempt_known = true;
            let label = if self.cfg.has_copy {
                "copy detail unreadable: "
            } else {
                "lifecycle detail unreadable: "
            };
            self.note_unknown(format!("{label}{}", m.detail_error));
            return;
        }
        self.attempt_missed = m.attempt;
        self.attempt_known = true;
        if !m.has_copy_detail {
            self.recursion_missed = m.count;
            self.has_recursion = true;
            self.rec_deferred = m.deferred;
            self.rec_recovered = m.recovered;
            return;
        }
        self.rec_has_detail = true;
        self.rec_bounce = m.bounce;
        self.rec_exit = m.exit_misses;
        self.rec_sync_device = m.sync_device;
        self.rec_sync_cpu = m.sync_cpu;
        self.rec_lc_map = m.lc_map;
        self.rec_lc_unmap = m.lc_unmap;
        self.rec_deferred = m.deferred;
        self.rec_recovered = m.recovered;
        let top = u64::MAX;
        if m.bounce > top - m.deferred {
            self.note_unknown("copy recursion counters overflow".to_string());
            return;
        }
        let have = m.bounce + m.deferred;
        if have < m.recovered {
            self.note_unknown(format!(
                "copy recursion counters contradict: E={} D={} R={}",
                format_u64(m.bounce),
                format_u64(m.deferred),
                format_u64(m.recovered)
            ));
            return;
        }
        let loss_cp = have - m.recovered;
        let mut others = m.attempt;
        let parts = [m.lc_map, m.lc_unmap, m.sync_device, m.sync_cpu];
        for part in parts {
            if others > top - part {
                self.note_unknown("copy recursion counters overflow".to_string());
                return;
            }
            others += part;
        }
        if others > top - loss_cp {
            self.note_unknown("copy recursion counters overflow".to_string());
            return;
        }
        self.recursion_missed = others + loss_cp;
        self.has_recursion = true;
    }

    /// Void exact attempt loss; the cause names move or gap.
    fn void_attempt_aggregate(&mut self, cause: String) {
        self.attempt_post_snapshot = true;
        self.attempt_void_cause = cause;
    }

    /// Re-read miss counters; any move past the first read is unknown.
    fn verify_misses_stable<K: KernelSource>(&mut self, kernel: &mut K) {
        if !self.attempt_known {
            return;
        }
        let m = kernel.recursion_misses();
        if !m.ok {
            self.void_attempt_aggregate("recursion misses unreadable after settle".to_string());
            self.note_unknown(format!(
                "recursion misses unreadable after settle: {}",
                m.message
            ));
            return;
        }
        if !m.detail_error.is_empty() {
            if m.attempt != self.attempt_missed {
                self.void_attempt_aggregate("post-snapshot activity".to_string());
            }
            self.note_unknown(format!(
                "recursion misses unreadable after settle: {}",
                m.detail_error
            ));
            return;
        }
        let attempt_moved = m.attempt != self.attempt_missed;
        if attempt_moved {
            self.void_attempt_aggregate("post-snapshot activity".to_string());
        }
        if self.rec_has_detail != m.has_copy_detail {
            self.note_unknown("post-snapshot activity".to_string());
            return;
        }
        if self.rec_has_detail {
            if attempt_moved
                || m.bounce != self.rec_bounce
                || m.exit_misses != self.rec_exit
                || m.sync_device != self.rec_sync_device
                || m.sync_cpu != self.rec_sync_cpu
                || m.lc_map != self.rec_lc_map
                || m.lc_unmap != self.rec_lc_unmap
                || m.deferred != self.rec_deferred
                || m.recovered != self.rec_recovered
            {
                self.note_unknown("post-snapshot activity".to_string());
            }
            return;
        }
        if attempt_moved || m.count != self.recursion_missed {
            self.note_unknown("post-snapshot activity".to_string());
        }
    }

    /// Bounded confirmation drain after the end snapshot.
    fn confirm<K: KernelSource>(&mut self, kernel: &mut K) {
        for _ in 0..CONFIRM_POLLS {
            let out = self.poll_one(kernel, 0);
            if out.kind == "batch" {
                self.omit_for_latch();
                self.note_unknown("post-snapshot activity".to_string());
            } else if out.kind != "timeout" {
                self.note_unknown("error shutdown".to_string());
                self.result_state = "error".to_string();
                self.void_attempt_aggregate("re-read skipped".to_string());
                return;
            }
        }
        let final_stats = kernel.stats();
        if !final_stats.ok {
            self.note_unknown("error shutdown".to_string());
            self.void_attempt_aggregate("re-read skipped".to_string());
            return;
        }
        self.stats_final = final_stats;
        self.has_final_stats = true;
        if self.extra_channels() {
            self.read_channel_finals(kernel);
        }
        if self.stats_drain.ok
            && (self.stats_final.received != self.stats_drain.received
                || self.stats_final.malformed != self.stats_drain.malformed)
        {
            self.note_unknown("post-snapshot activity".to_string());
        }
        self.verify_misses_stable(kernel);
    }

    /// Read per-channel final transport stats; failures close.
    fn read_channel_finals<K: KernelSource>(&mut self, kernel: &mut K) {
        let ch0 = kernel.stats_at(0);
        if !ch0.ok {
            self.note_unknown("error shutdown".to_string());
            return;
        }
        self.stats_final_ch0 = ch0;
        if self.cfg.has_lifecycle {
            let lc = kernel.stats_at(1);
            if !lc.ok {
                self.note_unknown("error shutdown".to_string());
                return;
            }
            self.stats_final_lc = lc;
        }
        if self.cfg.has_copy {
            let cp = kernel.stats_at(2);
            if !cp.ok {
                self.note_unknown("error shutdown".to_string());
                return;
            }
            self.stats_final_cp = cp;
        }
    }

    /// ERROR_DETACH -> ERROR_STATS -> FINALIZING; no drain.
    pub fn error_close<K: KernelSource, C: ClockSource, W: WriterSource>(
        &mut self,
        kernel: &mut K,
        clock: &mut C,
        writer: &mut W,
    ) -> RunResult {
        self.mark_detach_begin(clock);
        if self.cfg.has_copy {
            // Disarm before detach, so no late exit recovers after the end cut.
            let disarmed = kernel.set_copy_armed(false);
            if !disarmed.ok {
                self.note_unknown(format!("copy disarm failed: {}", disarmed.message));
            }
        }
        let detached = kernel.detach();
        self.detach_ns = clock.now();
        self.stop_close(detached.ok);
        if !detached.ok {
            self.note_unknown("detach failed; shutdown evidence unresolved".to_string());
        }
        self.read_misses(kernel);
        let final_stats = kernel.stats();
        if final_stats.ok {
            self.stats_final = final_stats;
            self.has_final_stats = true;
        }
        if self.extra_channels() {
            self.read_channel_finals(kernel);
        }
        if !self.stable_pair_at(kernel, clock, 0) {
            self.note_unknown("snapshot unresolved".to_string());
            self.has_end_cut = false;
        } else {
            if self.cfg.has_lifecycle && !self.stable_pair_at(kernel, clock, 1) {
                self.note_unknown("lc snapshot unresolved".to_string());
                self.has_end_cut_lc = false;
            }
            if self.cfg.has_copy && !self.stable_pair_at(kernel, clock, 2) {
                self.note_unknown("cp snapshot unresolved".to_string());
                self.has_end_cut_cp = false;
            }
        }
        self.verify_misses_stable(kernel);
        if self.cfg.has_pool_sample {
            let fin = self.sample_pool_now(clock);
            self.pool_final = fin.0;
            self.pool_final_ts = fin.1;
            self.pool_has_final = true;
        }
        let valid = self.stop_counters_valid();
        self.stop_ctl.sample_counters(valid);
        let t1 = clock.now();
        self.stop_finalize(t1);
        if self.unknown_cause.is_empty() {
            self.note_unknown("error shutdown".to_string());
        }
        self.finish(clock, writer)
    }
}

impl Collector {
    /// Stamp the explicit source block on one event.
    fn fill_source(&mut self, ev: &mut Event) {
        ev.journal_version = self.cfg.has_journal;
        ev.session_id = self.session_id.clone();
        ev.seq = self.next_seq;
        self.next_seq += 1;
        ev.source_hook = "swiotlb:swiotlb_bounced".to_string();
        ev.source_backend = "tracepoint".to_string();
        ev.source_profile_id = self.cfg.profile_id.clone();
        ev.source_measurement = "observed".to_string();
        ev.source_correlation = "direct".to_string();
    }

    /// Stamp capture fields; keep probe hook/backend/correlation.
    ///
    /// Lifecycle/copy normalizers set the per-probe hook
    /// and backend; the registry sets correlation after
    /// this stamp, so evidence refs carry real seqs.
    fn fill_source_hook(&mut self, ev: &mut Event) {
        ev.journal_version = self.cfg.has_journal;
        ev.session_id = self.session_id.clone();
        ev.seq = self.next_seq;
        self.next_seq += 1;
        ev.source_profile_id = self.cfg.profile_id.clone();
        ev.source_measurement = "observed".to_string();
    }

    fn encode_attempt(&mut self, normalized: &NormalizedAttempt) -> Result<Vec<u8>, EncodeError> {
        let mut ev = Event::default();
        self.fill_source(&mut ev);
        ev.ts_ns = normalized.ts_ns;
        ev.kind = "bounce_attempt".to_string();
        ev.bounce = BounceAttempt {
            device_id: normalized.device_id.clone(),
            requested_bytes: normalized.requested_bytes,
            forced: normalized.forced,
            operation_id: normalized.operation_id.clone(),
        };
        encode_event_line(&ev)
    }

    /// Sample the default pool now; failures stay in the sample.
    ///
    /// The evidence reader opens the configured root (live host
    /// when empty, one fixture in tests). An unreadable reader
    /// yields an unavailable sample, never a failed run.
    fn sample_pool_now<C: ClockSource>(&self, clock: &mut C) -> (NormalizedPoolSample, u64) {
        let ts = clock.now();
        let sample = match open_evidence_reader(&self.cfg.pool_root) {
            Ok(reader) => sample_default_pool(&reader, POOL_SWIOTLB_POOL_ID, POOL_SWIOTLB_UNIT),
            Err(_) => NormalizedPoolSample {
                pool_id: POOL_SWIOTLB_POOL_ID.to_string(),
                allocator: POOL_SWIOTLB_ALLOCATOR.to_string(),
                reason: "denied".to_string(),
                notes: "evidence reader unavailable".to_string(),
                ..Default::default()
            },
        };
        (sample, ts)
    }

    fn pool_sample_event(
        &mut self,
        sample: &NormalizedPoolSample,
        ts_ns: u64,
    ) -> Result<Vec<u8>, EncodeError> {
        let seq = self.next_seq;
        self.next_seq += 1;
        let mut ev = Event {
            session_id: self.session_id.clone(),
            seq,
            journal_version: self.cfg.has_journal,
            source_hook: "swiotlb:debugfs".to_string(),
            source_backend: "debugfs".to_string(),
            source_profile_id: self.cfg.profile_id.clone(),
            source_measurement: "observed".to_string(),
            source_correlation: "direct".to_string(),
            ts_ns,
            kind: "pool_sample".to_string(),
            ..Default::default()
        };
        ev.pool = PoolSample {
            pool_id: sample.pool_id.clone(),
            has_used: sample.has_used_bytes,
            used_bytes: sample.used_bytes,
            has_capacity: sample.has_capacity_bytes,
            capacity_bytes: sample.capacity_bytes,
            unit: sample.unit.clone(),
            allocator: sample.allocator.clone(),
            has_unit_bytes: sample.has_unit_bytes,
            unit_bytes: sample.unit_bytes,
            has_hiwater: sample.has_hiwater_bytes,
            hiwater_bytes: sample.hiwater_bytes,
            reason: sample.reason.clone(),
        };
        encode_event_line(&ev)
    }

    fn snapshot_event(
        &mut self,
        counter_id: &str,
        value: u64,
        unit: &str,
        ts_ns: u64,
    ) -> Result<Vec<u8>, EncodeError> {
        let mut ev = Event::default();
        self.fill_source(&mut ev);
        ev.ts_ns = ts_ns;
        ev.kind = "counter_snapshot".to_string();
        ev.snapshot = CounterSnapshot {
            counter_id: counter_id.to_string(),
            epoch: 0,
            has_scope_device: false,
            scope_device_id: String::new(),
            scope_profile_id: self.cfg.profile_id.clone(),
            value,
            unit: unit.to_string(),
        };
        encode_event_line(&ev)
    }

    fn gap_event(&mut self) -> Result<Vec<u8>, EncodeError> {
        let mut ev = Event::default();
        self.fill_source(&mut ev);
        ev.ts_ns = self.t_close;
        ev.kind = "gap".to_string();
        ev.gap = Gap {
            channel: "detail".to_string(),
            has_lost_count: false,
            lost_count: 0,
            reason: format!("detail closure unproven: {}", self.unknown_cause),
            window_start_ns: self.attach_ns,
            window_end_ns: self.end_ns,
        };
        encode_event_line(&ev)
    }

    /// The three section 4.1 emission gates.
    fn snapshots_eligible(&self) -> bool {
        if !self.has_end_cut {
            return false;
        }
        if !all_zero(&self.start_vals) {
            return false;
        }
        if !counters_valid(&self.end_vals) {
            return false;
        }
        if !count_identity(&self.end_vals) {
            return false;
        }
        byte_coverage_valid(&self.end_vals)
    }

    /// First failing gate, for the aggregate reason.
    fn snapshot_gate_cause(&self) -> String {
        if !self.has_end_cut {
            return "no stable cut".to_string();
        }
        if !counters_valid(&self.end_vals) {
            return "invalid epoch".to_string();
        }
        if !count_identity(&self.end_vals) {
            return "count identity unproven".to_string();
        }
        "byte coverage invalid".to_string()
    }

    /// Both attached-interval stamps present and ordered.
    fn attempt_interval_known(&self) -> bool {
        if self.attempt_attach_done_ns == 0 {
            return false;
        }
        if self.attempt_detach_begin_ns == 0 {
            return false;
        }
        self.attempt_attach_done_ns < self.attempt_detach_begin_ns
    }

    /// Counter scope, claimed over the attached interval.
    fn aggregate_scope(&self) -> String {
        let mut base = "counter snapshots".to_string();
        if self.extra_channels() {
            base = "counter snapshots (attempt channel)".to_string();
        }
        if !self.attempt_interval_known() {
            return base;
        }
        format!(
            "{base} attached [{},{})",
            format_u64(self.attempt_attach_done_ns),
            format_u64(self.attempt_detach_begin_ns),
        )
    }
}

impl Collector {
    /// Persist one periodic pool sample when due; "" otherwise.
    ///
    /// Fires at most once per loop iteration on the 1s
    /// cadence; the resync skips missed ticks without
    /// backfill bursts. Unavailable reads persist as
    /// unavailable samples, never as failed runs. Past
    /// 4096 routine samples the cadence keeps reading
    /// but persists pressurized samples only (up to 64),
    /// with a session note naming the thinning.
    fn maybe_sample_pool<C: ClockSource, W: WriterSource>(
        &mut self,
        clock: &mut C,
        writer: &mut W,
        now: u64,
    ) -> String {
        if !self.cfg.has_pool_sample {
            return String::new();
        }
        if now < self.pool_next_ts {
            return String::new();
        }
        self.pool_next_ts = checked_add(now, POOL_SAMPLE_INTERVAL_NS);
        if self.pool_periodic >= POOL_PERIODIC_MAX {
            self.pool_periodic_capped = true;
            return self.maybe_sample_pool_postcap(clock, writer);
        }
        let fired = self.sample_pool_now(clock);
        let line = match self.pool_sample_event(&fired.0, fired.1) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let verdict = self.persist_pool_mid(writer, line, fired.1);
        if !verdict.is_empty() {
            return verdict;
        }
        if fired.0.has_used_bytes || fired.0.has_capacity_bytes {
            self.pool_ok = true;
        }
        if self.pool_reason.is_empty() && !fired.0.reason.is_empty() {
            self.pool_reason = fired.0.reason.clone();
        }
        self.pool_periodic += 1;
        String::new()
    }

    /// Persist one pressurized sample past the routine cap.
    ///
    /// Past 4096 routine samples the cadence keeps reading
    /// but persists only pressurized samples (the same 90%
    /// predicate the analysis streak uses), up to 64, so a
    /// pressure finding can still form on long captures
    /// while the capture stays bounded. Quiet ticks persist
    /// nothing; the session note names the thinning.
    fn maybe_sample_pool_postcap<C: ClockSource, W: WriterSource>(
        &mut self,
        clock: &mut C,
        writer: &mut W,
    ) -> String {
        let fired = self.sample_pool_now(clock);
        if !pool_sample_pressured(&fired.0) {
            return String::new();
        }
        if self.pool_postcap >= POOL_POSTCAP_MAX {
            self.pool_postcap_capped = true;
            return String::new();
        }
        let line = match self.pool_sample_event(&fired.0, fired.1) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.fail("error".to_string());
                return "error-path".to_string();
            }
        };
        let verdict = self.persist_pool_mid(writer, line, fired.1);
        if !verdict.is_empty() {
            return verdict;
        }
        if fired.0.has_used_bytes || fired.0.has_capacity_bytes {
            self.pool_ok = true;
        }
        if self.pool_reason.is_empty() && !fired.0.reason.is_empty() {
            self.pool_reason = fired.0.reason.clone();
        }
        self.pool_postcap += 1;
        String::new()
    }

    /// Append one periodic pool sample; "" persisted, else verdict.
    ///
    /// Pool samples are not bridge-delivered, so they stay
    /// out of the delivery identity: no persisted, omitted,
    /// or write-failed counting, only the persisted-ts
    /// maximum moves, honestly covering them. The attempt
    /// gate still bounds their bytes, and the failure
    /// mapping mirrors the attempt path.
    fn persist_pool_mid<W: WriterSource>(
        &mut self,
        writer: &mut W,
        line: Vec<u8>,
        ts_ns: u64,
    ) -> String {
        let wrote = writer.append(&line);
        if wrote.ok {
            self.account_line(&line, "pool_sample");
            if ts_ns > self.max_persisted_ts {
                self.max_persisted_ts = ts_ns;
            }
            return String::new();
        }
        if wrote.kind == "refused" {
            self.next_seq -= 1;
            self.latch("size_limit".to_string());
            return "closed".to_string();
        }
        self.next_seq -= 1;
        if wrote.kind == "fatal" || wrote.kind == "misuse" {
            self.result_state = "unfinalizable".to_string();
            return "unfinalizable".to_string();
        }
        self.fail("error".to_string());
        "error-path".to_string()
    }

    /// Append one pool sample as a closing record.
    ///
    /// Pool samples are not bridge-delivered, so they never
    /// touch poll/attempt counters; only the persisted-ts
    /// maximum moves, honestly covering them. A failed sample
    /// degrades the run to error state like a failed gap,
    /// since the closing record set is incomplete.
    fn persist_pool_sample<W: WriterSource>(
        &mut self,
        writer: &mut W,
        sample: &NormalizedPoolSample,
        ts_ns: u64,
    ) {
        let line = match self.pool_sample_event(sample, ts_ns) {
            Ok(line) => line,
            Err(_) => {
                self.next_seq -= 1;
                self.closing_error = true;
                self.result_state = "error".to_string();
                return;
            }
        };
        let wrote = writer.append_closing(&line);
        if wrote.ok {
            self.account_line(&line, "pool_sample");
            if sample.has_used_bytes || sample.has_capacity_bytes {
                self.pool_ok = true;
            }
            if ts_ns > self.max_persisted_ts {
                self.max_persisted_ts = ts_ns;
            }
            if self.pool_reason.is_empty() && !sample.reason.is_empty() {
                self.pool_reason = sample.reason.clone();
            }
            return;
        }
        self.next_seq -= 1;
        self.closing_error = true;
        self.result_state = "error".to_string();
        if wrote.kind == "fatal" || wrote.kind == "misuse" {
            self.result_state = "unfinalizable".to_string();
        }
    }

    /// Append snapshots (rollback group) + pool + gap; "" or fatal.
    fn closing_records<W: WriterSource>(&mut self, writer: &mut W) -> String {
        if self.snapshots_eligible() {
            let begun = writer.group_begin();
            if !begun.ok {
                self.result_state = "unfinalizable".to_string();
                return "unfinalizable".to_string();
            }
            let mark = begun.mark;
            let seq_mark = self.next_seq;
            let stream_mark = self.committed_stream.clone();
            let mut failed = false;
            let lines: Result<Vec<Vec<u8>>, EncodeError> = (|| {
                Ok(vec![
                    self.snapshot_event(
                        "swiotlb.bounce_attempts",
                        self.start_vals[CNT_OBSERVED],
                        "count",
                        self.start_pair_ts,
                    )?,
                    self.snapshot_event(
                        "swiotlb.requested_bytes",
                        self.start_vals[CNT_OBSERVED_BYTES],
                        "bytes",
                        self.start_pair_ts,
                    )?,
                    self.snapshot_event(
                        "swiotlb.bounce_attempts",
                        self.end_vals[CNT_OBSERVED],
                        "count",
                        self.end_pair_ts,
                    )?,
                    self.snapshot_event(
                        "swiotlb.requested_bytes",
                        self.end_vals[CNT_OBSERVED_BYTES],
                        "bytes",
                        self.end_pair_ts,
                    )?,
                ])
            })();
            match lines {
                Ok(lines) => {
                    for line in &lines {
                        let wrote = writer.append_closing(line);
                        if !wrote.ok {
                            if wrote.kind == "fatal" || wrote.kind == "misuse" {
                                self.result_state = "unfinalizable".to_string();
                                return "unfinalizable".to_string();
                            }
                            failed = true;
                            break;
                        }
                        self.account_line(line, "counter_snapshot");
                    }
                }
                Err(_) => {
                    failed = true;
                }
            }
            if failed {
                let back = writer.group_abort(mark);
                if !back.ok {
                    self.result_state = "unfinalizable".to_string();
                    return "unfinalizable".to_string();
                }
                self.next_seq = seq_mark;
                self.committed_stream = stream_mark;
                self.snapshots_present = false;
                self.closing_error = true;
                self.result_state = "error".to_string();
            } else {
                self.snapshots_present = true;
            }
        }
        if self.pool_has_final {
            let fin = self.pool_final.clone();
            let fin_ts = self.pool_final_ts;
            self.persist_pool_sample(writer, &fin, fin_ts);
            if self.result_state == "unfinalizable" {
                return "unfinalizable".to_string();
            }
        }
        if !self.unknown_cause.is_empty() {
            match self.gap_event() {
                Ok(gap) => {
                    let wrote = writer.append_closing(&gap);
                    if wrote.ok {
                        self.account_line(&gap, "gap");
                    }
                    if !wrote.ok {
                        self.next_seq -= 1;
                        self.closing_error = true;
                        self.result_state = "error".to_string();
                        if wrote.kind == "fatal" || wrote.kind == "misuse" {
                            self.result_state = "unfinalizable".to_string();
                            return "unfinalizable".to_string();
                        }
                    }
                }
                Err(_) => {
                    self.next_seq -= 1;
                    self.closing_error = true;
                    self.result_state = "error".to_string();
                }
            }
        }
        String::new()
    }

    /// Check identities; "" continues, else unfinalizable.
    fn evaluate(&mut self) -> String {
        if self.has_final_stats {
            let start = self.stats_start.clone();
            let final_stats = self.stats_final.clone();
            if start.staged != 0 {
                return "unfinalizable".to_string();
            }
            if final_stats.received < start.received
                || final_stats.delivered < start.delivered
                || final_stats.malformed < start.malformed
                || final_stats.dropped < start.dropped
            {
                return "unfinalizable".to_string();
            }
            let received_d = final_stats.received - start.received;
            let delivered_d = final_stats.delivered - start.delivered;
            let malformed_d = final_stats.malformed - start.malformed;
            let dropped_d = final_stats.dropped - start.dropped;
            // Selection drops are bridge-delivered payloads
            // with a known disposition, so they belong in
            // the delivery identity (never in loss totals).
            let app_total = self.persisted
                + self.size_omitted
                + self.duration_omitted
                + self.signal_omitted
                + self.rejected
                + self.write_failed
                + self.filtered;
            if delivered_d != app_total {
                return "unfinalizable".to_string();
            }
            // Checked sums fail the run closed on overflow instead of trapping:
            // unreachable in practice, loud if it ever happens.
            let mut bridge_total = match delivered_d.checked_add(final_stats.staged) {
                Some(v) => v,
                None => return "unfinalizable".to_string(),
            };
            bridge_total = match bridge_total.checked_add(malformed_d) {
                Some(v) => v,
                None => return "unfinalizable".to_string(),
            };
            bridge_total = match bridge_total.checked_add(dropped_d) {
                Some(v) => v,
                None => return "unfinalizable".to_string(),
            };
            if received_d != bridge_total {
                return "unfinalizable".to_string();
            }
            if self.unknown_cause.is_empty() && final_stats.staged != 0 {
                self.note_unknown("error shutdown".to_string());
            }
        }
        if self.has_end_cut {
            let vals = self.end_vals.clone();
            if !epoch_flags_clear(&vals) {
                self.note_unknown("invalid epoch".to_string());
            } else if !count_identity(&vals) {
                self.note_unknown("kernel identity unproven".to_string());
            } else if self.has_final_stats {
                let emitted = vals[CNT_EMITTED];
                if self.extra_channels() && !self.stats_final_ch0.ok {
                    self.note_unknown("error shutdown".to_string());
                    return String::new();
                }
                let received_d: u64 = if self.extra_channels() {
                    self.stats_final_ch0.received - self.stats_start_ch0.received
                } else {
                    self.stats_final.received - self.stats_start.received
                };
                if received_d != emitted {
                    self.note_unknown("ring count unproven".to_string());
                }
            }
        }
        if self.cfg.has_lifecycle {
            let lc_vals = self.end_vals_lc.clone();
            let lc_start = self.stats_start_lc.clone();
            let lc_final = self.stats_final_lc.clone();
            if !self
                .evaluate_channel(
                    &lc_vals,
                    self.has_end_cut_lc,
                    &lc_start,
                    &lc_final,
                    "lifecycle",
                )
                .is_empty()
            {
                return "unfinalizable".to_string();
            }
        }
        if self.cfg.has_copy {
            let cp_vals = self.end_vals_cp.clone();
            let cp_start = self.stats_start_cp.clone();
            let cp_final = self.stats_final_cp.clone();
            if !self
                .evaluate_channel(&cp_vals, self.has_end_cut_cp, &cp_start, &cp_final, "copy")
                .is_empty()
            {
                return "unfinalizable".to_string();
            }
        }
        String::new()
    }

    /// Close verification for one extra channel's cut.
    fn evaluate_channel(
        &mut self,
        vals_in: &[u64],
        has_cut: bool,
        start: &StatsOut,
        final_stats: &StatsOut,
        tag: &str,
    ) -> String {
        if !has_cut {
            return String::new();
        }
        let vals = vals_in.to_vec();
        if vals.len() == 6 && vals[CNT_FLAGS] & FLAG_ARGCNT != 0 {
            self.note_unknown(format!("{tag} argument count mismatch"));
            return String::new();
        }
        if !epoch_flags_clear(&vals) {
            self.note_unknown(format!("{tag} invalid epoch"));
            return String::new();
        }
        if !count_identity(&vals) {
            self.note_unknown(format!("{tag} kernel identity unproven"));
            return String::new();
        }
        if !final_stats.ok {
            return String::new();
        }
        if final_stats.received < start.received
            || final_stats.delivered < start.delivered
            || final_stats.malformed < start.malformed
            || final_stats.dropped < start.dropped
        {
            return "unfinalizable".to_string();
        }
        let received_d = final_stats.received - start.received;
        if received_d != vals[CNT_EMITTED] {
            self.note_unknown(format!("{tag} ring count unproven"));
        }
        String::new()
    }

    /// Merge the retained signal error with a close note.
    fn diagnostic(&self, note: &str) -> String {
        if self.signal_error.is_empty() {
            return note.to_string();
        }
        if note.is_empty() {
            return format!("signal: {}", self.signal_error);
        }
        format!("signal: {}; {note}", self.signal_error)
    }

    /// Keep the events file for forensics; no session.
    fn drop_unfinalizable<W: WriterSource>(&mut self, writer: &mut W) -> RunResult {
        writer.discard();
        RunResult {
            exit_code: EXIT_ERROR,
            end_reason: "error".to_string(),
            outcome: "unfinalizable".to_string(),
            diagnostic: self.diagnostic("local accounting unusable; events kept, no session"),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        }
    }

    /// FINALIZING: stamps, closing, assembly, publication.
    fn finish<C: ClockSource, W: WriterSource>(
        &mut self,
        clock: &mut C,
        writer: &mut W,
    ) -> RunResult {
        self.t_close = clock.now();
        let probe = [
            self.t_close,
            self.max_snap_ts,
            self.max_persisted_ts,
            self.start_ns,
        ];
        let mut top = 0u64;
        for v in probe {
            if v > top {
                top = v;
            }
        }
        if top == u64::MAX {
            return self.drop_unfinalizable(writer);
        }
        self.end_ns = top + 1;
        if !self.cfg.journal_only && !self.evaluate().is_empty() {
            return self.drop_unfinalizable(writer);
        }
        if !self.cfg.journal_only && !self.closing_records(writer).is_empty() {
            return self.drop_unfinalizable(writer);
        }
        if !self.contained() {
            return self.drop_unfinalizable(writer);
        }
        let integrity = self.committed_stream.snapshot();
        if integrity.events_bytes != writer.committed_len() || integrity.line_count != self.next_seq
        {
            return self.drop_unfinalizable(writer);
        }
        let assembled: Session = match self.assemble() {
            Ok(mut assembled) => {
                assembled.has_integrity = true;
                assembled.integrity = integrity;
                assembled
            }
            Err(_) => return self.drop_unfinalizable(writer),
        };
        let session_text = match encode_session(&assembled) {
            Ok(text) => text,
            Err(_) => return self.drop_unfinalizable(writer),
        };
        let done = writer.finalize(session_text.as_bytes());
        let mut reason = self.stop_reason.clone();
        if self.result_state == "error" {
            reason = "error".to_string();
        }
        if done.status == "finalized" {
            if self.result_state == "error" {
                return RunResult {
                    exit_code: EXIT_ERROR,
                    end_reason: reason,
                    outcome: "error".to_string(),
                    diagnostic: self.diagnostic(&done.note),
                    fix: String::new(),
                    code: String::new(),
                    unknown: false,
                    trusted: false,
                };
            }
            let code = self.final_exit_code(&assembled);
            return RunResult {
                exit_code: code,
                end_reason: reason,
                outcome: "finalized".to_string(),
                diagnostic: self.diagnostic(""),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
        if done.status == "present_unsynced" {
            return RunResult {
                exit_code: EXIT_ERROR,
                end_reason: reason,
                outcome: "present_unsynced".to_string(),
                diagnostic: self.diagnostic(&done.note),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
        if done.status == "misuse" {
            return RunResult {
                exit_code: EXIT_ERROR,
                end_reason: reason,
                outcome: "unfinalizable".to_string(),
                diagnostic: self.diagnostic("finalize after close"),
                fix: String::new(),
                code: String::new(),
                unknown: false,
                trusted: false,
            };
        }
        RunResult {
            exit_code: EXIT_ERROR,
            end_reason: reason,
            outcome: "unfinalized".to_string(),
            diagnostic: self.diagnostic(&done.note),
            fix: String::new(),
            code: String::new(),
            unknown: false,
            trusted: false,
        }
    }

    /// Every enabled channel's submit_fail is readable.
    fn submit_valid_all(&self) -> bool {
        if !self.has_end_cut || !submit_valid(&self.end_vals) {
            return false;
        }
        if self.cfg.has_lifecycle && (!self.has_end_cut_lc || !submit_valid(&self.end_vals_lc)) {
            return false;
        }
        if self.cfg.has_copy && (!self.has_end_cut_cp || !submit_valid(&self.end_vals_cp)) {
            return false;
        }
        true
    }

    /// Summed submit_fail over enabled channels' end cuts, or
    /// `None` on overflow. Mojo traps on this sum; a wrapped
    /// release total would be silently wrong, so callers void to
    /// unknown instead.
    fn submit_fail_total(&self) -> Option<u64> {
        let mut total = 0u64;
        if self.has_end_cut {
            total = total.checked_add(self.end_vals[CNT_SUBMIT_FAIL])?;
        }
        if self.cfg.has_lifecycle && self.has_end_cut_lc {
            total = total.checked_add(self.end_vals_lc[CNT_SUBMIT_FAIL])?;
        }
        if self.cfg.has_copy && self.has_end_cut_cp {
            total = total.checked_add(self.end_vals_cp[CNT_SUBMIT_FAIL])?;
        }
        Some(total)
    }

    /// Known-loss detail total with checked arithmetic: `None` when
    /// any leg overflows (Mojo traps here; the caller voids the
    /// closure to unknown rather than reporting a wrapped count).
    fn checked_detail_loss(&self) -> Option<(u64, u64)> {
        let submit_fail = self.submit_fail_total()?;
        let mut total = submit_fail;
        for part in [
            self.stats_final.malformed - self.stats_start.malformed,
            self.stats_final.dropped - self.stats_start.dropped,
            self.recursion_missed,
            self.size_omitted,
            self.duration_omitted,
            self.signal_omitted,
            self.rejected,
            self.write_failed,
        ] {
            total = total.checked_add(part)?;
        }
        Some((submit_fail, total))
    }

    /// Per-channel program misses; unknown unless exactly provable.
    fn liveness_misses(&self, is_copy: bool) -> (u64, bool) {
        let top = u64::MAX;
        if self.rec_has_detail {
            let mut parts: Vec<u64> = Vec::new();
            if is_copy {
                // Entry misses and deferrals lose a record unless the exit recovered it.
                if self.rec_bounce > top - self.rec_deferred {
                    return (0, false);
                }
                let have = self.rec_bounce + self.rec_deferred;
                if self.rec_recovered > have {
                    return (0, false);
                }
                parts.push(have - self.rec_recovered);
                parts.push(self.rec_sync_device);
                parts.push(self.rec_sync_cpu);
            } else {
                parts.push(self.rec_lc_map);
                parts.push(self.rec_lc_unmap);
            }
            let mut total = 0u64;
            for part in parts {
                if total > top - part {
                    return (0, false);
                }
                total += part;
            }
            return (total, true);
        }
        if !self.has_recursion || !self.attempt_known {
            return (0, false);
        }
        if self.attempt_missed > self.recursion_missed {
            return (0, false);
        }
        if !self.cfg.has_copy {
            // Lifecycle-only runs split the aggregate exactly: total minus attempt.
            if is_copy {
                return (0, false);
            }
            return (self.recursion_missed - self.attempt_missed, true);
        }
        // An aggregate sum of zero proves every channel missed nothing.
        if self.recursion_missed == 0 {
            return (0, true);
        }
        (0, false)
    }

    /// Observed-minus-read plus channel misses, with validity.
    ///
    /// The xcounter pair must be complete and trustworthy
    /// (identity holds, no wrap or argument-count flags);
    /// more read than observed contradicts the counters and
    /// voids the loss. Drain-stranded and rejected records
    /// stay inside the observed term by construction: they
    /// were observed but never tallied. Skipped program runs
    /// never observe, so per-channel misses join the loss;
    /// the copy channel nets entry misses plus deferrals
    /// minus exit recoveries, which neither path observed.
    fn liveness_channel_loss(
        &self,
        start: &[u64],
        end: &[u64],
        has_cut: bool,
        seen: u64,
        is_copy: bool,
    ) -> (u64, bool) {
        if !has_cut {
            return (0, false);
        }
        if start.len() != 6 || end.len() != 6 {
            return (0, false);
        }
        if !count_identity(start) || !epoch_flags_clear(start) {
            return (0, false);
        }
        if !count_identity(end) || !epoch_flags_clear(end) {
            return (0, false);
        }
        if end[CNT_FLAGS] & FLAG_ARGCNT != 0 {
            return (0, false);
        }
        if start[CNT_FLAGS] & FLAG_ARGCNT != 0 {
            return (0, false);
        }
        if end[CNT_EMITTED] < start[CNT_EMITTED] {
            return (0, false);
        }
        if end[CNT_OBSERVED] < start[CNT_OBSERVED] {
            return (0, false);
        }
        let delta = end[CNT_OBSERVED] - start[CNT_OBSERVED];
        if seen > delta {
            return (0, false);
        }
        let misses = self.liveness_misses(is_copy);
        if !misses.1 {
            return (0, false);
        }
        let top = u64::MAX;
        let base = delta - seen;
        if base > top - misses.0 {
            return (0, false);
        }
        (base + misses.0, true)
    }

    /// Judge hook liveness from the tally and end cuts.
    fn liveness_verdict(&self) -> LivenessVerdict {
        let mut loss_lc = (0u64, true);
        let mut loss_cp = (0u64, true);
        if self.cfg.has_lifecycle {
            loss_lc = self.liveness_channel_loss(
                &self.start_vals_lc,
                &self.end_vals_lc,
                self.has_end_cut_lc,
                self.live.seen_lc,
                false,
            );
        }
        if self.cfg.has_copy {
            loss_cp = self.liveness_channel_loss(
                &self.start_vals_cp,
                &self.end_vals_cp,
                self.has_end_cut_cp,
                self.live.seen_cp,
                true,
            );
        }
        let loss = LivenessLoss {
            lc: loss_lc.0,
            cp: loss_cp.0,
            known_lc: loss_lc.1,
            known_cp: loss_cp.1,
        };
        evaluate_liveness(
            &self.live,
            self.detach_begin_ns,
            true,
            self.cfg.has_lifecycle,
            self.cfg.has_copy,
            &loss,
        )
    }

    /// One channel's transport triple, decimal-or-unavailable.
    fn channel_triple(
        &self,
        has_cut: bool,
        end_vals: &[u64],
        stats_start: &StatsOut,
        stats_final: &StatsOut,
    ) -> String {
        let mut submit = "unavailable".to_string();
        let mut malformed = "unavailable".to_string();
        let mut dropped = "unavailable".to_string();
        if has_cut && submit_valid(end_vals) {
            submit = format_u64(end_vals[CNT_SUBMIT_FAIL]);
        }
        if stats_start.ok && stats_final.ok {
            malformed = format_u64(stats_final.malformed - stats_start.malformed);
            dropped = format_u64(stats_final.dropped - stats_start.dropped);
        }
        format!("submit_fail={submit} malformed={malformed} dropped={dropped}")
    }

    /// Per-channel transport breakdown for multi-channel runs.
    ///
    /// The pooled pairs stay first; this suffix names which
    /// ring lost what. Attempt-only captures keep byte-identical
    /// reasons. A channel whose evidence is invalid reports
    /// unavailable per component, mirroring loss_pairs.
    fn channel_loss_suffix(&self) -> String {
        if !self.extra_channels() {
            return String::new();
        }
        let mut out = "; channels attempt:(".to_string();
        out += &self.channel_triple(
            self.has_end_cut,
            &self.end_vals,
            &self.stats_start_ch0,
            &self.stats_final_ch0,
        );
        out += ")";
        if self.cfg.has_lifecycle {
            out += " lifecycle:(";
            out += &self.channel_triple(
                self.has_end_cut_lc,
                &self.end_vals_lc,
                &self.stats_start_lc,
                &self.stats_final_lc,
            );
            out += ")";
        }
        if self.cfg.has_copy {
            out += " copy:(";
            out += &self.channel_triple(
                self.has_end_cut_cp,
                &self.end_vals_cp,
                &self.stats_start_cp,
                &self.stats_final_cp,
            );
            out += ")";
        }
        out
    }

    /// Kernel/bridge components as decimal-or-unavailable.
    fn loss_pairs(&self) -> Vec<String> {
        let mut submit = "unavailable".to_string();
        let mut malformed = "unavailable".to_string();
        let mut dropped = "unavailable".to_string();
        let mut missed = "unavailable".to_string();
        if self.has_recursion {
            missed = format_u64(self.recursion_missed);
        }
        if self.submit_valid_all()
            && let Some(failed) = self.submit_fail_total()
        {
            submit = format_u64(failed);
        }
        if self.has_final_stats {
            malformed = format_u64(self.stats_final.malformed - self.stats_start.malformed);
            dropped = format_u64(self.stats_final.dropped - self.stats_start.dropped);
        }
        vec![submit, malformed, dropped, missed]
    }

    /// Build the session header for the closed capture.
    //
    // Sequential field writes mirror the behavior source
    // line-for-line for auditability; a single literal
    // would bury the conditional channel logic.
    #[allow(clippy::field_reassign_with_default)]
    fn assemble(&mut self) -> Result<Session, EncodeError> {
        let mut out = Session::default();
        out.session_id = self.session_id.clone();
        out.has_boot_id = self.cfg.has_boot_id;
        out.boot_id = self.cfg.boot_id.clone();
        out.synthetic = false;
        out.product_name = "memveil".to_string();
        out.product_version = crate::ENGINE_VERSION.to_string();
        out.has_build = false;
        out.env_mode = env_mode_for(&self.cfg.guest);
        out.env_detection = detection_for(&self.cfg.guest);
        out.has_asserted_mode = false;
        out.asserted_mode_present = false;
        out.env_attestation = "not_performed".to_string();
        out.capture_mode = "live".to_string();
        out.window_start_ns = self.attach_ns;
        out.window_end_ns = self.end_ns;
        out.has_baseline_start_ns = true;
        out.baseline_start_ns = self.start_pair_ts;
        out.has_filter_device = self.cfg.has_device_filter;
        if self.cfg.has_device_filter {
            out.filter_device = self.cfg.device_filter.clone();
        }
        out.finalized = true;
        out.has_end_reason = true;
        out.end_reason = self.stop_reason.clone();
        if self.result_state == "error" {
            out.end_reason = "error".to_string();
        }
        let catalog = match self.table.entries() {
            Ok(catalog) => catalog,
            Err(_) => {
                return Err(EncodeError::new("device_catalog", "catalog unusable"));
            }
        };
        for entry in &catalog {
            out.devices.push(DeviceEntry {
                device_id: entry.device_id.clone(),
                name: entry.name.clone(),
                has_driver: false,
                driver: String::new(),
                driver_present: true,
                identity_status: "unresolved".to_string(),
            });
        }
        out.baseline_complete = false;
        out.baseline_region_count = 0;
        // Error paths never judge liveness: the windows never closed cleanly.
        let mut verdict = LivenessVerdict {
            state: "not_exercised".to_string(),
            equation: String::new(),
            detail: String::new(),
            lc: "not_exercised".to_string(),
            cp: "not_exercised".to_string(),
        };
        if self.result_state != "error" {
            verdict = self.liveness_verdict();
        }
        let mut cap = Capability {
            status: "partial".to_string(),
            reason: format!(
                "capture {}, {} attempts persisted; admitted under {}; device detail grouped by observed name scope",
                self.result_state,
                format_u64(self.persisted_attempt),
                self.cfg.profile_id,
            ),
            has_profile_id: true,
            profile_id: self.cfg.profile_id.clone(),
            ..Default::default()
        };
        cap.hooks.push("swiotlb:swiotlb_bounced".to_string());
        if !self.cfg.grade.is_empty() {
            cap.has_grade = true;
            cap.grade = self.cfg.grade.clone();
        }
        out.cap_bounce_attempts = cap;
        if self.cfg.has_lifecycle {
            let mut lc_cap = Capability {
                status: "partial".to_string(),
                reason: format!(
                    "capture {}, {} map_result/unmap events persisted; admitted under {}; v2 wire reports opaque mapping generations when observed",
                    self.result_state,
                    format_u64(self.persisted_map + self.persisted_unmap),
                    self.cfg.profile_id,
                ),
                has_profile_id: true,
                profile_id: self.cfg.profile_id.clone(),
                ..Default::default()
            };
            lc_cap.hooks.push(HOOK_MAP_RESULT.to_string());
            lc_cap.hooks.push(HOOK_UNMAP.to_string());
            if !self.cfg.grade.is_empty() {
                lc_cap.has_grade = true;
                lc_cap.grade = self.cfg.grade.clone();
            }
            out.cap_mapping_lifecycle = lc_cap;
        } else {
            Self::unavailable_cap(
                &mut out.cap_mapping_lifecycle,
                "No map_result source in this capture.",
            );
        }
        if self.cfg.has_copy {
            let mut cp_cap = Capability {
                status: "partial".to_string(),
                reason: format!(
                    "capture {}, {} copy events persisted; admitted under {}; v1 copy wire carries no mapping identity",
                    self.result_state,
                    format_u64(self.persisted_copy),
                    self.cfg.profile_id,
                ),
                has_profile_id: true,
                profile_id: self.cfg.profile_id.clone(),
                ..Default::default()
            };
            cp_cap.hooks.push(HOOK_BOUNCE.to_string());
            if !self.cfg.grade.is_empty() {
                cp_cap.has_grade = true;
                cp_cap.grade = self.cfg.grade.clone();
            }
            out.cap_copy_bytes = cp_cap;
            let mut sy_cap = Capability {
                status: "partial".to_string(),
                reason: format!(
                    "capture {}, {} sync_request events persisted; admitted under {}; v1 copy wire carries no mapping identity",
                    self.result_state,
                    format_u64(self.persisted_sync),
                    self.cfg.profile_id,
                ),
                has_profile_id: true,
                profile_id: self.cfg.profile_id.clone(),
                ..Default::default()
            };
            sy_cap.hooks.push(HOOK_SYNC_DEVICE.to_string());
            sy_cap.hooks.push(HOOK_SYNC_CPU.to_string());
            if !self.cfg.grade.is_empty() {
                sy_cap.has_grade = true;
                sy_cap.grade = self.cfg.grade.clone();
            }
            out.cap_sync_requests = sy_cap;
        } else {
            Self::unavailable_cap(&mut out.cap_copy_bytes, "No copy source in this capture.");
            Self::unavailable_cap(
                &mut out.cap_sync_requests,
                "No sync source in this capture.",
            );
        }
        // Each suffix names only what its own channel proved or lost.
        if self.cfg.has_lifecycle {
            if verdict.lc == "verified" {
                out.cap_mapping_lifecycle.reason += "; liveness verified";
            } else if verdict.lc == "hooks_silent" {
                out.cap_mapping_lifecycle.reason += "; liveness hooks silent";
            }
        }
        if self.cfg.has_copy {
            if verdict.cp == "verified" {
                out.cap_copy_bytes.reason += "; liveness verified";
                out.cap_sync_requests.reason += "; liveness verified";
            } else if verdict.cp == "hooks_silent" {
                out.cap_copy_bytes.reason += "; liveness hooks silent";
                out.cap_sync_requests.reason += "; liveness hooks silent";
            }
        }
        Self::unavailable_cap(
            &mut out.cap_conversion_results,
            "No conversion source in this capture.",
        );
        Self::unavailable_cap(
            &mut out.cap_region_state,
            "No region source in this capture.",
        );
        if self.pool_ok {
            let mut pcap = Capability {
                status: "partial".to_string(),
                ..Default::default()
            };
            let mut cadence = format!(
                "default-pool debugfs samples at capture start and close plus {} periodic samples ({}s cadence)",
                format_u64(self.pool_periodic as u64),
                format_u64(POOL_SAMPLE_INTERVAL_NS / 1000000000),
            );
            if self.pool_periodic_capped {
                cadence += &format!(
                    "; routine sampling stopped at {} (count cap)",
                    format_u64(POOL_PERIODIC_MAX as u64),
                );
                if self.pool_postcap > 0 {
                    cadence += &format!(
                        "; {} pressurized samples persisted past the cap",
                        format_u64(self.pool_postcap as u64),
                    );
                } else {
                    cadence += "; quiet ticks past the cap persist nothing";
                }
                if self.pool_postcap_capped {
                    cadence += "; post-cap budget exhausted";
                }
            }
            if !self.pool_reason.is_empty() {
                cadence += &format!("; first read failure: {}", self.pool_reason);
            }
            pcap.reason = cadence;
            pcap.hooks.push("swiotlb:debugfs".to_string());
            pcap.has_profile_id = true;
            pcap.profile_id = self.cfg.profile_id.clone();
            out.cap_pool_stats = pcap;
        } else if self.cfg.has_pool_sample {
            let mut why = self.pool_reason.clone();
            if why.is_empty() {
                why = "unreadable".to_string();
            }
            Self::unavailable_cap(
                &mut out.cap_pool_stats,
                &format!("pool counters unreadable: {why}"),
            );
        } else {
            Self::unavailable_cap(&mut out.cap_pool_stats, "No pool source in this capture.");
        }
        Self::unavailable_cap(
            &mut out.cap_task_context,
            "No observer context in this capture.",
        );
        let pairs = self.loss_pairs();
        let mut scope = format!("{} bounce_attempt", format_u64(self.persisted_attempt));
        if self.cfg.has_lifecycle {
            scope += &format!(
                " + {} map_result/unmap",
                format_u64(self.persisted_map + self.persisted_unmap),
            );
        }
        if self.cfg.has_copy {
            scope += &format!(
                " + {} copy/sync_request",
                format_u64(self.persisted_copy + self.persisted_sync),
            );
        }
        scope += " events";
        if self.cfg.has_device_filter {
            // Deliberate narrowing is recorded scope, never
            // loss: the dropped count stays out of the loss
            // total below.
            let phrase = format!(
                "; device selection {} dropped {} non-matching attempts",
                self.cfg.device_filter,
                format_u64(self.filtered),
            );
            // The selector alone may span the whole scope
            // bound, so it is named only when the phrase
            // fits: the exact selector always stays in
            // capture.filters.device, and the elided form
            // still records the dropped count.
            let candidate = scope.clone() + &phrase;
            if candidate.chars().count() <= DETAIL_SCOPE_MAX {
                scope = candidate;
            } else {
                scope += &format!(
                    "; device selection dropped {} non-matching attempts",
                    format_u64(self.filtered),
                );
            }
        }
        // The checked detail total voids a provable closure to
        // unknown on overflow (Mojo traps on these same sums, so a
        // wrapped total would be silently wrong): resolve it before
        // branching so the overflow cause lands in the unknown
        // reason below.
        let mut overflowed = false;
        let known_loss = if self.loss_known() {
            match self.checked_detail_loss() {
                Some(pair) => Some(pair),
                None => {
                    overflowed = true;
                    None
                }
            }
        } else {
            None
        };
        if overflowed {
            self.note_unknown("loss counters overflow".to_string());
        }
        if let Some((submit_fail, total)) = known_loss {
            if total == 0 {
                out.q_detail.status = "complete_for_scope".to_string();
            } else {
                out.q_detail.status = "partial".to_string();
            }
            out.q_detail.has_loss_count = true;
            out.q_detail.loss_count = total;
            out.q_detail.reason = detail_reason_known(
                submit_fail,
                self.stats_final.malformed - self.stats_start.malformed,
                self.stats_final.dropped - self.stats_start.dropped,
                self.recursion_missed,
                self.size_omitted,
                self.duration_omitted,
                self.signal_omitted,
                self.rejected,
                self.write_failed,
            );
        } else {
            out.q_detail.status = "partial".to_string();
            out.q_detail.has_loss_count = false;
            out.q_detail.reason = detail_reason_unknown(
                &self.unknown_cause,
                &pairs[0],
                &pairs[1],
                &pairs[2],
                &pairs[3],
                self.size_omitted,
                self.duration_omitted,
                self.signal_omitted,
                self.rejected,
                self.write_failed,
            );
        }
        out.q_detail.reason += &self.channel_loss_suffix();
        if !self.unknown_copy_first.is_empty() {
            out.q_detail.reason += &format!("; first unknown copy: {}", self.unknown_copy_first);
        }
        if verdict.state == "hooks_silent" {
            out.q_detail.status = "partial".to_string();
            out.q_detail.has_loss_count = false;
            out.q_detail.reason +=
                &format!("; hooks silent: {} ({})", verdict.equation, verdict.detail);
        } else if verdict.state == "unverified" {
            out.q_detail.status = "partial".to_string();
            if verdict.equation == "copy liveness needs lifecycle" {
                // Bounce hooks fire inside map/sync/unmap paths, so lone copies stay unattributable.
                out.q_detail.has_loss_count = false;
                out.q_detail.reason += "; copy liveness unverified: lifecycle not captured";
            } else {
                out.q_detail.reason += &format!(
                    "; {} liveness unverified ({})",
                    verdict.equation, verdict.detail
                );
            }
        }
        if self.cfg.attempt_loss_lower_bound {
            // A claimed count below 6.7 is a lower bound:
            // trace_call_bpf skipped programs uncounted, so
            // detail never claims complete there either.
            out.q_detail.status = "partial".to_string();
            out.q_detail.reason += "; attempt loss counts are a lower bound before 6.7";
        }
        out.q_detail.scope = scope;
        if self.snapshots_present && !self.attempt_interval_known() {
            // Both attached-interval stamps must be present and ordered.
            out.q_aggregate.status = "partial".to_string();
            out.q_aggregate.has_loss_count = false;
            out.q_aggregate.reason = aggregate_reason(true, "");
            if self.attempt_attach_done_ns == 0 || self.attempt_detach_begin_ns == 0 {
                out.q_aggregate.reason += "; attempt attached interval unknown (stamp missing)";
            } else {
                out.q_aggregate.reason +=
                    "; attempt attached interval unknown (stamps not increasing)";
            }
        } else if self.snapshots_present && !self.attempt_known {
            // Skipped attempt runs never advance the counters.
            out.q_aggregate.status = "partial".to_string();
            out.q_aggregate.has_loss_count = false;
            out.q_aggregate.reason = aggregate_reason(true, "");
            out.q_aggregate.reason +=
                "; attempt program skips unknown (recursion misses unreadable)";
        } else if self.snapshots_present && self.attempt_post_snapshot {
            // A moved or unchecked attempt count voids exact loss.
            out.q_aggregate.status = "partial".to_string();
            out.q_aggregate.has_loss_count = false;
            out.q_aggregate.reason = aggregate_reason(true, "");
            out.q_aggregate.reason += &format!(
                "; attempt program skips unknown ({})",
                self.attempt_void_cause
            );
        } else if self.snapshots_present && self.attempt_missed > 0 {
            out.q_aggregate.status = "partial".to_string();
            out.q_aggregate.has_loss_count = true;
            out.q_aggregate.loss_count = self.attempt_missed;
            out.q_aggregate.reason = aggregate_reason(true, "");
            out.q_aggregate.reason += &format!(
                "; attempt program runs skipped {} (recursion)",
                format_u64(self.attempt_missed)
            );
        } else if self.snapshots_present {
            out.q_aggregate.status = "complete_for_scope".to_string();
            out.q_aggregate.has_loss_count = true;
            out.q_aggregate.loss_count = 0;
            out.q_aggregate.reason = aggregate_reason(true, "");
        } else {
            out.q_aggregate.status = "unavailable".to_string();
            out.q_aggregate.has_loss_count = false;
            out.q_aggregate.reason = aggregate_reason(false, &self.snapshot_gate_cause());
        }
        if self.cfg.attempt_loss_lower_bound && out.q_aggregate.has_loss_count {
            // A claimed count below 6.7 is a lower bound:
            // trace_call_bpf skipped programs uncounted, so
            // the aggregate never claims complete there.
            out.q_aggregate.status = "partial".to_string();
            out.q_aggregate.reason += "; attempt loss counts are a lower bound before 6.7";
        }
        // Lifecycle/copy counter cuts are verified at
        // close and feed q_detail loss, but only the
        // attempt channel archives counter snapshots.
        out.q_aggregate.scope = self.aggregate_scope();
        if self.extra_channels() {
            let health = self.registry.health_full();
            out.q_correlation.status = health.aggregate.status.clone();
            out.q_correlation.has_loss_count = health.aggregate.has_loss_count;
            out.q_correlation.loss_count = health.aggregate.loss_count;
            out.q_correlation.scope = health.aggregate.scope.clone();
            out.q_correlation.reason = health.aggregate.reason.clone();
            out.q_correlation.evidence_refs = health.aggregate.evidence_refs.clone();
            out.has_corr_relations = true;
            out.q_corr_mapping = health.mapping_release;
            out.q_corr_copy = health.copy_attribution;
            out.q_corr_sync = health.sync_attribution;
        } else {
            out.q_correlation.status = "not_applicable".to_string();
            out.q_correlation.has_loss_count = false;
            out.q_correlation.scope = "attempt counting".to_string();
            out.q_correlation.reason =
                "Attempt counting needs no cross-event correlation.".to_string();
            out.has_corr_relations = true;
            out.q_corr_mapping = Channel {
                status: "not_applicable".to_string(),
                scope: CORR_SCOPE_MAPPING.to_string(),
                reason: "Attempt counting needs no cross-event correlation.".to_string(),
                ..Default::default()
            };
            out.q_corr_copy = Channel {
                status: "not_applicable".to_string(),
                scope: CORR_SCOPE_COPY.to_string(),
                reason: "Attempt counting needs no cross-event correlation.".to_string(),
                ..Default::default()
            };
            out.q_corr_sync = Channel {
                status: "not_applicable".to_string(),
                scope: CORR_SCOPE_SYNC.to_string(),
                reason: "Attempt counting needs no cross-event correlation.".to_string(),
                ..Default::default()
            };
        }
        out.q_baseline.status = "not_applicable".to_string();
        out.q_baseline.has_loss_count = false;
        out.q_baseline.scope = "attempt metrics".to_string();
        out.q_baseline.reason = "Attempt metrics need no baseline.".to_string();
        let stop = self.stop_evidence.clone();
        out.stop.has_checkpoint_failures = true;
        out.stop.checkpoint_failures = self.checkpoint_failures;
        out.stop.outcome = stop.outcome.clone();
        out.stop.reason = stop.reason.clone();
        out.stop.budget_ms = stop.stop_budget_ms as u64;
        out.stop.elapsed_ms = stop.elapsed_ms as u64;
        out.stop.admission_closed = stop.admission_closed;
        out.stop.quiescence_observed = stop.quiescence_observed;
        out.stop.writers_settled = stop.writers_settled as u64;
        out.stop.in_flight_at_close = stop.in_flight_at_close as u64;
        out.stop.late_submits_drained = stop.late_submits_drained as u64;
        out.stop.drained_records = stop.drained_records as u64;
        out.stop.drain_completed = stop.has_drained;
        out.stop.submit_after_drain = stop.submit_after_drain;
        out.stop.has_drain_completed = true;
        out.stop.has_submit_after_drain = true;
        out.stop.busy_at_drain = stop.busy_at_drain;
        out.stop.counters_valid = stop.counters_valid;
        out.stop.open_mappings = stop.open_mappings as u64;
        if self.stop_complete() {
            out.q_terminal.status = "complete_for_scope".to_string();
            out.q_terminal.has_loss_count = false;
            out.q_terminal.scope = "capture finalization".to_string();
            out.q_terminal.reason = "stop complete: all stages proved".to_string();
        } else {
            out.q_terminal.status = "partial".to_string();
            out.q_terminal.has_loss_count = false;
            out.q_terminal.scope = "capture finalization".to_string();
            out.q_terminal.reason = format!("stop {}: {}", stop.outcome, stop.reason);
        }
        let record_verdict = verdict_for_session(&out, self.persisted_attempt);
        out.has_verdict = true;
        out.verdict_name = record_verdict.name;
        out.verdict_loss_bps = record_verdict.loss_ratio_bps;
        out.verdict_delivered = self.persisted_attempt;
        for item in &self.cfg.evidence {
            let mut source = truncate_text(&item.source, 128);
            if source.is_empty() {
                source = "undecodable".to_string();
            }
            out.evidence.push(EvidenceItem {
                item_type: "provenance".to_string(),
                source,
                interpretation: truncate_text(&item.interpretation, 512),
            });
        }
        Self::provenance(&mut out, "attach_ns", &format_u64(self.attach_ns));
        Self::provenance(&mut out, "detach_ns", &format_u64(self.detach_ns));
        if self.unknown_cause.is_empty() {
            Self::provenance(&mut out, "drain_closure", "proven");
        } else {
            Self::provenance(
                &mut out,
                "drain_closure",
                &format!("unknown: {}", self.unknown_cause),
            );
        }
        Self::provenance(
            &mut out,
            "measurement_scope",
            "ordinals below observed at the end cut",
        );
        if self.output_fs.is_empty() {
            Self::provenance(&mut out, "output.fs", "unavailable: filesystem unmeasured");
        } else {
            let fstype = self.output_fs.clone();
            Self::provenance(&mut out, "output.fs", &fstype);
        }
        if !self.signal_error.is_empty() {
            let sig_err = self.signal_error.clone();
            Self::provenance(&mut out, "signal.error", &sig_err);
        }
        if !self.secondary_causes.is_empty() {
            let mut joined = self.secondary_causes[0].clone();
            for cause in self.secondary_causes.iter().skip(1) {
                joined += "; ";
                joined += cause;
            }
            Self::provenance(&mut out, "shutdown.secondary_causes", &joined);
        }
        if self.rec_has_detail {
            Self::provenance(
                &mut out,
                "copy.mv_bounce_misses",
                &format_u64(self.rec_bounce),
            );
            Self::provenance(
                &mut out,
                "copy.mv_bounce_exit_misses",
                &format_u64(self.rec_exit),
            );
            Self::provenance(
                &mut out,
                "copy.mv_sync_device_misses",
                &format_u64(self.rec_sync_device),
            );
            Self::provenance(
                &mut out,
                "copy.mv_sync_cpu_misses",
                &format_u64(self.rec_sync_cpu),
            );
            Self::provenance(
                &mut out,
                "lifecycle.mv_map_result_misses",
                &format_u64(self.rec_lc_map),
            );
            Self::provenance(
                &mut out,
                "lifecycle.mv_unmap_misses",
                &format_u64(self.rec_lc_unmap),
            );
            Self::provenance(&mut out, "copy.deferred", &format_u64(self.rec_deferred));
            Self::provenance(&mut out, "copy.recovered", &format_u64(self.rec_recovered));
        }
        if self.unknown_copy_slot_read != 0 {
            Self::provenance(
                &mut out,
                "copy.unknown_slot_read",
                &format_u64(self.unknown_copy_slot_read),
            );
        }
        if self.unknown_copy_mask_read != 0 {
            Self::provenance(
                &mut out,
                "copy.unknown_mask_read",
                &format_u64(self.unknown_copy_mask_read),
            );
        }
        if self.unknown_copy_bounds != 0 {
            Self::provenance(
                &mut out,
                "copy.unknown_bounds",
                &format_u64(self.unknown_copy_bounds),
            );
        }
        if self.unknown_copy_layout != 0 {
            Self::provenance(
                &mut out,
                "copy.unknown_layout",
                &format_u64(self.unknown_copy_layout),
            );
        }
        if self.unknown_copy_shift != 0 {
            Self::provenance(
                &mut out,
                "copy.unknown_shift",
                &format_u64(self.unknown_copy_shift),
            );
        }
        if self.cfg.has_journal {
            out.has_journal = true;
            out.finalized = self.journal_done;
            let cut = self
                .end_ns
                .max(self.attach_ns.max(self.max_persisted_ts).saturating_add(1));
            out.window_end_ns = cut;
            out.journal = match self.journal_data.snapshot(
                cut,
                self.journal_done,
                &self.journal_counts,
                self.journal_readable,
            ) {
                Ok(journal) => journal,
                Err(_) => return Err(EncodeError::new("journal", "snapshot invalid")),
            };
            out.cap_conversion_results.status = "partial".to_string();
            out.cap_conversion_results.reason =
                "Native wrapper requests/results; callback completeness unproved.".to_string();
            out.cap_conversion_results.profile_id = self.cfg.journal_profile.clone();
            out.cap_conversion_results.has_profile_id = true;
            out.cap_conversion_results.hooks = vec![
                "set_memory_decrypted".to_string(),
                "set_memory_encrypted".to_string(),
            ];
            out.q_terminal.status = "partial".to_string();
            out.q_terminal.reason =
                "Journal closure unproved; quiet transport is not synchronization.".to_string();
            out.q_terminal.has_loss_count = false;
            out.stop.outcome = "partial".to_string();
            out.stop.reason = out.q_terminal.reason.clone();
            out.stop.admission_closed = out.journal.admission_end_ns.has;
            out.stop.quiescence_observed = false;
            out.has_verdict = false;
            if self.cfg.journal_only {
                Self::unavailable_cap(&mut out.cap_bounce_attempts, "Attempt source not selected.");
                out.has_baseline_start_ns = false;
                out.q_detail.status = "partial".to_string();
                out.q_detail.reason =
                    "Journal observed results; missed callbacks not observable.".to_string();
                out.q_detail.scope = "conversion journal".to_string();
                out.q_detail.has_loss_count = false;
                out.q_aggregate.status = "partial".to_string();
                out.q_aggregate.scope = "journal counters".to_string();
                out.q_aggregate.reason =
                    "Non-atomic snapshots; counter and detail alternatives are separate."
                        .to_string();
                out.q_aggregate.has_loss_count = false;
                out.q_correlation.status = "unavailable".to_string();
                out.q_correlation.scope = "journal operation membership".to_string();
                out.q_correlation.reason =
                    "Matching tokens do not prove callback completeness.".to_string();
                out.q_correlation.has_loss_count = false;
                out.q_baseline.status = "unavailable".to_string();
                out.q_baseline.scope = "journal baseline".to_string();
                out.q_baseline.reason =
                    "Boot/pre-attach, MMIO, kexec/accept and unobserved paths excluded."
                        .to_string();
                out.q_baseline.has_loss_count = false;
            }
        }
        while out.evidence.len() > 64 {
            out.evidence.pop();
        }
        Ok(out)
    }

    fn unavailable_cap(cap: &mut Capability, reason: &str) {
        cap.status = "unavailable".to_string();
        cap.reason = reason.to_string();
        cap.has_profile_id = false;
    }

    fn provenance(out: &mut Session, key: &str, value: &str) {
        let mut source = key.to_string();
        if source.is_empty() {
            source = "undecodable".to_string();
        }
        out.evidence.push(EvidenceItem {
            item_type: "provenance".to_string(),
            source,
            interpretation: truncate_text(value, 512),
        });
    }

    /// Proven closure with every component exact.
    fn loss_known(&self) -> bool {
        if !self.unknown_cause.is_empty() {
            return false;
        }
        if !self.has_end_cut || !self.has_final_stats {
            return false;
        }
        if !self.has_recursion {
            return false;
        }
        if !self.submit_valid_all() {
            return false;
        }
        true
    }

    /// Every persisted closing stamp lies in [start, end).
    fn contained(&self) -> bool {
        if self.snapshots_present {
            if self.start_pair_ts < self.start_ns {
                return false;
            }
            if self.start_pair_ts >= self.end_ns {
                return false;
            }
            if self.end_pair_ts < self.start_ns {
                return false;
            }
            if self.end_pair_ts >= self.end_ns {
                return false;
            }
        }
        if !self.unknown_cause.is_empty() {
            if self.t_close < self.start_ns {
                return false;
            }
            if self.t_close >= self.end_ns {
                return false;
            }
        }
        true
    }
}

/// Scripted collector sources for the close-out matrix.
///
/// Test-only: deterministic poll/stats/snapshot/clock/signal
/// scripts plus a real-writer adapter with scripted faults
/// and in-memory null writers. Tests own the sources across
/// run() for post-run assertions. Shared by the collector,
/// stop, pool, and kernel test suites in this module family.
#[cfg(test)]
pub(crate) mod script {
    use super::{ClockSource, GeomOut, KernelSource, MissOut, PollOut, SignalSource, SnapOut};
    use super::{StatsOut, WriterSource};
    use crate::capture::live::{AppendOut, CreateOut, FinalOut, GroupOut};
    use crate::capture::writer::EventWriter;
    use crate::platform::outcome::OpOut;
    use crate::platform::signal::SignalOut;

    /// One poll script entry with run-length repeats.
    #[derive(Debug, Clone)]
    pub(crate) struct ScriptPollItem {
        /// Scripted outcome.
        pub(crate) out: PollOut,
        /// Repeat count.
        pub(crate) repeat: i64,
    }

    /// Scripted kernel: geometries, outcomes, scripts, counters.
    pub(crate) struct ScriptKernel {
        /// open_session outcome.
        pub(crate) open_out: OpOut,
        /// load outcome.
        pub(crate) load_out: OpOut,
        /// mv_counts geometry.
        pub(crate) counts_geom: GeomOut,
        /// Channel-0 ring geometry.
        pub(crate) ring_geom: GeomOut,
        /// Channel-1 ring geometry.
        pub(crate) ring_geom1: GeomOut,
        /// Channel-2 ring geometry.
        pub(crate) ring_geom2: GeomOut,
        /// mv_offsets geometry.
        pub(crate) offsets_geom: GeomOut,
        /// mv_copy_fb geometry.
        pub(crate) fb_geom: GeomOut,
        /// mv_claims geometry.
        pub(crate) claims_geom: GeomOut,
        /// install_offsets outcome.
        pub(crate) install_out: OpOut,
        /// Last installed table.
        pub(crate) installed: Vec<u8>,
        /// install_offsets call count.
        pub(crate) install_calls: i64,
        /// attach outcome.
        pub(crate) attach_out: OpOut,
        /// attach call count.
        pub(crate) attach_calls: i64,
        /// arm outcome.
        pub(crate) arm_out: OpOut,
        /// disarm outcome.
        pub(crate) disarm_out: OpOut,
        /// Call log (attach/arm/disarm/detach).
        pub(crate) calls: Vec<String>,
        /// detach outcome.
        pub(crate) detach_out: OpOut,
        /// close outcome.
        pub(crate) close_out: OpOut,
        /// First misses read.
        pub(crate) misses_out: MissOut,
        /// Later misses reads when armed.
        pub(crate) misses_out2: MissOut,
        /// True to serve misses_out2 past the first read.
        pub(crate) use_misses2: bool,
        /// misses read count.
        pub(crate) misses_reads: i64,
        /// Present channel count.
        pub(crate) channels: i64,
        polls: Vec<ScriptPollItem>,
        poll_idx: usize,
        poll_left: i64,
        stats_q: Vec<StatsOut>,
        stats_idx: usize,
        stats_q1: Vec<StatsOut>,
        stats_idx1: usize,
        stats_q2: Vec<StatsOut>,
        stats_idx2: usize,
        snaps: Vec<SnapOut>,
        snap_idx: usize,
        snaps1: Vec<SnapOut>,
        snap_idx1: usize,
        snaps2: Vec<SnapOut>,
        snap_idx2: usize,
        /// Observed poll timeouts in order.
        pub(crate) poll_timeouts: Vec<i64>,
        /// Observed poll capacities in order.
        pub(crate) poll_caps: Vec<u32>,
        /// poll call count.
        pub(crate) polls_done: i64,
        /// stats call count.
        pub(crate) stats_done: i64,
        /// snap call count.
        pub(crate) snaps_done: i64,
        /// close call count.
        pub(crate) closes_done: i64,
        /// True to patch wire seqs on batches.
        pub(crate) seq_patch: bool,
        /// Next patched wire seq.
        pub(crate) seq_next: u64,
    }

    fn ok_geom(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> GeomOut {
        GeomOut {
            ok: true,
            map_type,
            key_size,
            value_size,
            max_entries,
            message: String::new(),
        }
    }

    impl ScriptKernel {
        /// An all-ok scripted kernel.
        pub(crate) fn new() -> Self {
            let ok = OpOut {
                ok: true,
                message: String::new(),
            };
            Self {
                open_out: ok.clone(),
                load_out: ok.clone(),
                counts_geom: ok_geom(2, 4, 8, 6),
                ring_geom: ok_geom(27, 0, 0, 8388608),
                ring_geom1: ok_geom(27, 0, 0, 8388608),
                ring_geom2: ok_geom(27, 0, 0, 8388608),
                offsets_geom: ok_geom(2, 4, 24, 1),
                fb_geom: ok_geom(2, 4, 8, 4),
                claims_geom: ok_geom(2, 4, 16, 4096),
                install_out: ok.clone(),
                installed: Vec::new(),
                install_calls: 0,
                attach_out: ok.clone(),
                attach_calls: 0,
                arm_out: ok.clone(),
                disarm_out: ok.clone(),
                calls: Vec::new(),
                detach_out: ok.clone(),
                close_out: ok,
                misses_out: MissOut {
                    ok: true,
                    ..Default::default()
                },
                misses_out2: MissOut {
                    ok: true,
                    ..Default::default()
                },
                use_misses2: false,
                misses_reads: 0,
                channels: 1,
                polls: Vec::new(),
                poll_idx: 0,
                poll_left: 0,
                stats_q: Vec::new(),
                stats_idx: 0,
                stats_q1: Vec::new(),
                stats_idx1: 0,
                stats_q2: Vec::new(),
                stats_idx2: 0,
                snaps: Vec::new(),
                snap_idx: 0,
                snaps1: Vec::new(),
                snap_idx1: 0,
                snaps2: Vec::new(),
                snap_idx2: 0,
                poll_timeouts: Vec::new(),
                poll_caps: Vec::new(),
                polls_done: 0,
                stats_done: 0,
                snaps_done: 0,
                closes_done: 0,
                seq_patch: false,
                seq_next: 0,
            }
        }

        /// Append one poll script entry.
        pub(crate) fn add_poll(&mut self, item: PollOut, repeat: i64) {
            self.polls.push(ScriptPollItem { out: item, repeat });
        }

        /// Append one pooled stats entry.
        pub(crate) fn add_stats(&mut self, item: StatsOut) {
            self.stats_q.push(item);
        }

        /// Append one per-channel stats entry.
        pub(crate) fn add_stats_at(&mut self, channel: i64, item: StatsOut) {
            if channel == 1 {
                self.stats_q1.push(item);
            } else if channel == 2 {
                self.stats_q2.push(item);
            } else {
                self.stats_q.push(item);
            }
        }

        /// Append one pooled snapshot entry.
        pub(crate) fn add_snap(&mut self, item: SnapOut) {
            self.snaps.push(item);
        }

        /// Append one per-channel snapshot entry.
        pub(crate) fn add_snap_at(&mut self, channel: i64, item: SnapOut) {
            if channel == 1 {
                self.snaps1.push(item);
            } else if channel == 2 {
                self.snaps2.push(item);
            } else {
                self.snaps.push(item);
            }
        }
    }

    impl Default for ScriptKernel {
        fn default() -> Self {
            Self::new()
        }
    }

    fn bad_channel_geom() -> GeomOut {
        GeomOut {
            ok: false,
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            message: "bad channel".to_string(),
        }
    }

    fn bad_channel_stats() -> StatsOut {
        StatsOut {
            ok: false,
            received: 0,
            delivered: 0,
            staged: 0,
            malformed: 0,
            dropped: 0,
            message: "bad channel".to_string(),
        }
    }

    fn bad_channel_snap() -> SnapOut {
        SnapOut {
            ok: false,
            vals: Vec::new(),
            message: "bad channel".to_string(),
        }
    }

    impl KernelSource for ScriptKernel {
        fn open_session(&mut self) -> OpOut {
            self.open_out.clone()
        }

        fn load(&mut self) -> OpOut {
            self.load_out.clone()
        }

        fn map_info(&mut self, name: &str) -> GeomOut {
            if name == "mv_counts" {
                return self.counts_geom.clone();
            }
            if name == "mv_offsets" {
                return self.offsets_geom.clone();
            }
            self.ring_geom.clone()
        }

        fn map_info_at(&mut self, channel: i64, name: &str) -> GeomOut {
            if channel < 0 || channel >= self.channels {
                return bad_channel_geom();
            }
            if name == "mv_counts" {
                return self.counts_geom.clone();
            }
            if name == "mv_copy_fb" {
                return self.fb_geom.clone();
            }
            if name == "mv_claims" {
                return self.claims_geom.clone();
            }
            if channel == 1 {
                return self.ring_geom1.clone();
            }
            if channel == 2 {
                return self.ring_geom2.clone();
            }
            self.ring_geom.clone()
        }

        fn channel_count(&self) -> i64 {
            self.channels
        }

        fn install_offsets(&mut self, table: &[u8]) -> OpOut {
            self.install_calls += 1;
            self.installed = table.to_vec();
            self.install_out.clone()
        }

        fn attach(&mut self) -> OpOut {
            self.attach_calls += 1;
            self.calls.push("attach".to_string());
            self.attach_out.clone()
        }

        fn set_copy_armed(&mut self, armed: bool) -> OpOut {
            if armed {
                self.calls.push("arm".to_string());
                return self.arm_out.clone();
            }
            self.calls.push("disarm".to_string());
            self.disarm_out.clone()
        }

        fn poll(&mut self, timeout_ms: i64, capacity: u32) -> PollOut {
            self.poll_timeouts.push(timeout_ms);
            self.poll_caps.push(capacity);
            self.polls_done += 1;
            loop {
                if self.poll_idx >= self.polls.len() {
                    return PollOut {
                        kind: "error".to_string(),
                        frame: Vec::new(),
                        required: 0,
                        message: "script exhausted: poll".to_string(),
                    };
                }
                let item = self.polls[self.poll_idx].clone();
                if self.poll_left <= 0 {
                    self.poll_left = item.repeat;
                }
                if self.poll_left <= 0 {
                    self.poll_idx += 1;
                    continue;
                }
                self.poll_left -= 1;
                let mut out = item.out;
                if self.seq_patch && out.kind == "batch" && out.frame.len() >= 16 {
                    // Raw payload: the wire seq sits at offset 8.
                    let mut v = self.seq_next;
                    for i in 0..8 {
                        out.frame[8 + i] = (v & 0xFF) as u8;
                        v >>= 8;
                    }
                    self.seq_next += 1;
                }
                if self.poll_left <= 0 {
                    self.poll_idx += 1;
                }
                return out;
            }
        }

        fn stats(&mut self) -> StatsOut {
            self.stats_done += 1;
            if self.stats_idx >= self.stats_q.len() {
                return StatsOut {
                    ok: false,
                    received: 0,
                    delivered: 0,
                    staged: 0,
                    malformed: 0,
                    dropped: 0,
                    message: "script exhausted: stats".to_string(),
                };
            }
            let out = self.stats_q[self.stats_idx].clone();
            self.stats_idx += 1;
            out
        }

        fn stats_at(&mut self, channel: i64) -> StatsOut {
            if channel < 0 || channel >= self.channels {
                return bad_channel_stats();
            }
            if channel == 0 {
                return self.stats();
            }
            self.stats_done += 1;
            if channel == 1 {
                if self.stats_idx1 >= self.stats_q1.len() {
                    let mut out = bad_channel_stats();
                    out.message = "script exhausted: stats1".to_string();
                    return out;
                }
                let out = self.stats_q1[self.stats_idx1].clone();
                self.stats_idx1 += 1;
                return out;
            }
            if channel == 2 {
                if self.stats_idx2 >= self.stats_q2.len() {
                    let mut out = bad_channel_stats();
                    out.message = "script exhausted: stats2".to_string();
                    return out;
                }
                let out = self.stats_q2[self.stats_idx2].clone();
                self.stats_idx2 += 1;
                return out;
            }
            self.stats()
        }

        fn read_full(&mut self) -> SnapOut {
            self.snaps_done += 1;
            if self.snap_idx >= self.snaps.len() {
                return SnapOut {
                    ok: false,
                    vals: Vec::new(),
                    message: "script exhausted: snap".to_string(),
                };
            }
            let out = self.snaps[self.snap_idx].clone();
            self.snap_idx += 1;
            out
        }

        fn read_full_at(&mut self, channel: i64) -> SnapOut {
            if channel < 0 || channel >= self.channels {
                return bad_channel_snap();
            }
            if channel == 0 {
                return self.read_full();
            }
            self.snaps_done += 1;
            if channel == 1 {
                if self.snap_idx1 >= self.snaps1.len() {
                    return SnapOut {
                        ok: false,
                        vals: Vec::new(),
                        message: "script exhausted: snap1".to_string(),
                    };
                }
                let out = self.snaps1[self.snap_idx1].clone();
                self.snap_idx1 += 1;
                return out;
            }
            if channel == 2 {
                if self.snap_idx2 >= self.snaps2.len() {
                    return SnapOut {
                        ok: false,
                        vals: Vec::new(),
                        message: "script exhausted: snap2".to_string(),
                    };
                }
                let out = self.snaps2[self.snap_idx2].clone();
                self.snap_idx2 += 1;
                return out;
            }
            self.read_full()
        }

        fn detach(&mut self) -> OpOut {
            self.calls.push("detach".to_string());
            self.detach_out.clone()
        }

        fn recursion_misses(&mut self) -> MissOut {
            self.misses_reads += 1;
            if self.use_misses2 && self.misses_reads > 1 {
                return self.misses_out2.clone();
            }
            self.misses_out.clone()
        }

        fn close(&mut self) -> OpOut {
            self.closes_done += 1;
            self.close_out.clone()
        }
    }

    /// Scripted clock: explicit values, then a stepped tail.
    pub(crate) struct ScriptClock {
        vals: Vec<u64>,
        idx: usize,
        /// Tail step; 0 freezes the tail.
        pub(crate) step: u64,
        offset: u64,
        /// Observed sleeps in order.
        pub(crate) sleeps: Vec<i64>,
        /// now() call count.
        pub(crate) reads: i64,
    }

    impl ScriptClock {
        /// A clock with a 1ms stepped tail.
        pub(crate) fn new() -> Self {
            Self {
                vals: Vec::new(),
                idx: 0,
                step: 1000000,
                offset: 0,
                sleeps: Vec::new(),
                reads: 0,
            }
        }

        /// Append one explicit value.
        pub(crate) fn add(&mut self, v: u64) {
            self.vals.push(v);
        }
    }

    impl Default for ScriptClock {
        fn default() -> Self {
            Self::new()
        }
    }

    impl ClockSource for ScriptClock {
        fn now(&mut self) -> u64 {
            self.reads += 1;
            let top = u64::MAX;
            let mut base = 0u64;
            if self.idx < self.vals.len() {
                base = self.vals[self.idx];
            } else if !self.vals.is_empty() {
                let last = self.vals[self.vals.len() - 1];
                let k = (self.idx - self.vals.len() + 1) as u64;
                base = top;
                if self.step == 0 || k <= top / self.step {
                    let add = self.step.wrapping_mul(k);
                    if add <= top - last {
                        base = last + add;
                    }
                }
            }
            self.idx += 1;
            if base > top - self.offset {
                return top;
            }
            base + self.offset
        }

        fn sleep_ms(&mut self, ms: i64) {
            self.sleeps.push(ms);
            let add = (ms as u64).wrapping_mul(1000000);
            if add > u64::MAX - self.offset {
                self.offset = u64::MAX;
            } else {
                self.offset += add;
            }
        }
    }

    /// Scripted signals: setup outcome plus check states.
    pub(crate) struct ScriptSignal {
        /// setup outcome.
        pub(crate) setup_out: OpOut,
        states: Vec<SignalOut>,
        /// Consumed state count.
        pub(crate) idx: usize,
        /// check call count.
        pub(crate) checks: i64,
        /// setup call count.
        pub(crate) setups: i64,
    }

    impl ScriptSignal {
        /// A quiet scripted source.
        pub(crate) fn new() -> Self {
            Self {
                setup_out: OpOut {
                    ok: true,
                    message: String::new(),
                },
                states: Vec::new(),
                idx: 0,
                checks: 0,
                setups: 0,
            }
        }

        /// Append one state.
        pub(crate) fn add(&mut self, state: &str) {
            self.states.push(SignalOut {
                state: state.to_string(),
                message: String::new(),
            });
        }

        /// Append one error state.
        pub(crate) fn add_error(&mut self, message: &str) {
            self.states.push(SignalOut {
                state: "error".to_string(),
                message: message.to_string(),
            });
        }
    }

    impl Default for ScriptSignal {
        fn default() -> Self {
            Self::new()
        }
    }

    impl SignalSource for ScriptSignal {
        fn setup(&mut self) -> OpOut {
            self.setups += 1;
            self.setup_out.clone()
        }

        fn check(&mut self) -> SignalOut {
            self.checks += 1;
            if self.idx >= self.states.len() {
                return SignalOut {
                    state: "none".to_string(),
                    message: String::new(),
                };
            }
            let out = self.states[self.idx].clone();
            self.idx += 1;
            out
        }
    }

    /// Fail the Nth append (1-based) with kind.
    #[derive(Debug, Clone)]
    pub(crate) struct AppendFault {
        /// 1-based append index.
        pub(crate) at: i64,
        /// Failure kind.
        pub(crate) kind: String,
    }

    /// Real EventWriter with scripted fault injection.
    pub(crate) struct ScriptWriter {
        slot: Option<EventWriter>,
        /// Append faults in append order.
        pub(crate) append_faults: Vec<AppendFault>,
        /// True to fail the next group abort.
        pub(crate) abort_fault: bool,
        /// Forced finalize status; empty for the real one.
        pub(crate) finalize_status: String,
        /// checkpoint call count.
        pub(crate) checkpoint_calls: i64,
        /// 1-based checkpoint call to fail; 0 never fails.
        pub(crate) checkpoint_fail_at: i64,
        /// First checkpoint bytes.
        pub(crate) first_checkpoint: Vec<u8>,
        /// Last checkpoint bytes.
        pub(crate) last_checkpoint: Vec<u8>,
        /// append call count.
        pub(crate) appends: i64,
        /// create call count.
        pub(crate) creates: i64,
        /// discard call count.
        pub(crate) discards: i64,
    }

    impl ScriptWriter {
        /// A fresh scripted writer.
        pub(crate) fn new() -> Self {
            Self {
                slot: None,
                append_faults: Vec::new(),
                abort_fault: false,
                finalize_status: String::new(),
                checkpoint_calls: 0,
                checkpoint_fail_at: 0,
                first_checkpoint: Vec::new(),
                last_checkpoint: Vec::new(),
                appends: 0,
                creates: 0,
                discards: 0,
            }
        }
    }

    impl Default for ScriptWriter {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WriterSource for ScriptWriter {
        fn create(&mut self, path: &str, budget: u64) -> CreateOut {
            self.creates += 1;
            match EventWriter::new(path, budget) {
                Ok(mut w) => {
                    if let Err(e) = w.prepare() {
                        self.slot = Some(w);
                        return CreateOut {
                            ok: false,
                            kind: e.kind,
                            message: e.message,
                        };
                    }
                    self.slot = Some(w);
                }
                Err(e) => {
                    return CreateOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    };
                }
            }
            CreateOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }

        fn append(&mut self, line: &[u8]) -> AppendOut {
            self.appends += 1;
            for fault in &self.append_faults {
                if fault.at == self.appends {
                    return AppendOut {
                        ok: false,
                        kind: fault.kind.clone(),
                        message: "scripted fault".to_string(),
                    };
                }
            }
            match self.slot.as_mut() {
                Some(w) => match w.append(line) {
                    Ok(()) => AppendOut {
                        ok: true,
                        kind: String::new(),
                        message: String::new(),
                    },
                    Err(e) => AppendOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    },
                },
                None => AppendOut {
                    ok: false,
                    kind: "misuse".to_string(),
                    message: "append before create".to_string(),
                },
            }
        }

        fn append_closing(&mut self, line: &[u8]) -> AppendOut {
            self.appends += 1;
            for fault in &self.append_faults {
                if fault.at == self.appends {
                    return AppendOut {
                        ok: false,
                        kind: fault.kind.clone(),
                        message: "scripted fault".to_string(),
                    };
                }
            }
            match self.slot.as_mut() {
                Some(w) => match w.append_closing(line) {
                    Ok(()) => AppendOut {
                        ok: true,
                        kind: String::new(),
                        message: String::new(),
                    },
                    Err(e) => AppendOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    },
                },
                None => AppendOut {
                    ok: false,
                    kind: "misuse".to_string(),
                    message: "append before create".to_string(),
                },
            }
        }

        fn group_begin(&mut self) -> GroupOut {
            match self.slot.as_mut() {
                Some(w) => match w.group_begin() {
                    Ok(mark) => GroupOut {
                        ok: true,
                        mark,
                        kind: String::new(),
                    },
                    Err(e) => GroupOut {
                        ok: false,
                        mark: 0,
                        kind: e.kind,
                    },
                },
                None => GroupOut {
                    ok: false,
                    mark: 0,
                    kind: "misuse".to_string(),
                },
            }
        }

        fn group_abort(&mut self, mark: u64) -> AppendOut {
            if self.abort_fault {
                return AppendOut {
                    ok: false,
                    kind: "fatal".to_string(),
                    message: "scripted".to_string(),
                };
            }
            match self.slot.as_mut() {
                Some(w) => match w.group_abort(mark) {
                    Ok(()) => AppendOut {
                        ok: true,
                        kind: String::new(),
                        message: String::new(),
                    },
                    Err(e) => AppendOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    },
                },
                None => AppendOut {
                    ok: false,
                    kind: "misuse".to_string(),
                    message: "abort before create".to_string(),
                },
            }
        }

        fn checkpoint(&mut self, session: &[u8]) -> AppendOut {
            self.checkpoint_calls += 1;
            if self.checkpoint_calls == 1 {
                self.first_checkpoint = session.to_vec();
            }
            if self.checkpoint_calls == self.checkpoint_fail_at {
                return AppendOut {
                    ok: false,
                    kind: "io".to_string(),
                    message: "scripted checkpoint failure".to_string(),
                };
            }
            self.last_checkpoint = session.to_vec();
            match self.slot.as_mut() {
                Some(w) => match w.checkpoint(session) {
                    Ok(()) => AppendOut {
                        ok: true,
                        kind: String::new(),
                        message: String::new(),
                    },
                    Err(e) => AppendOut {
                        ok: false,
                        kind: e.kind,
                        message: e.message,
                    },
                },
                None => AppendOut {
                    ok: false,
                    kind: "misuse".to_string(),
                    message: "checkpoint before create".to_string(),
                },
            }
        }

        fn finalize(&mut self, session: &[u8]) -> FinalOut {
            match self.slot.as_mut() {
                Some(w) => match w.finalize(session) {
                    Ok(outcome) => {
                        if !self.finalize_status.is_empty() {
                            return FinalOut {
                                status: self.finalize_status.clone(),
                                note: outcome.message,
                            };
                        }
                        FinalOut {
                            status: outcome.status,
                            note: outcome.message,
                        }
                    }
                    Err(e) => FinalOut {
                        status: "misuse".to_string(),
                        note: e.message,
                    },
                },
                None => FinalOut {
                    status: "misuse".to_string(),
                    note: "finalize before create".to_string(),
                },
            }
        }

        fn abandon(&mut self) -> String {
            match self.slot.as_mut() {
                Some(w) => w.abandon(),
                None => String::new(),
            }
        }

        fn discard(&mut self) {
            self.discards += 1;
            if let Some(w) = self.slot.as_mut() {
                w.discard();
            }
        }

        fn committed_len(&self) -> u64 {
            match self.slot.as_ref() {
                Some(w) => w.committed_len(),
                None => 0,
            }
        }

        fn finalized_identity(&self) -> Vec<u64> {
            match self.slot.as_ref() {
                Some(w) => w.finalized_identity(),
                None => Vec::new(),
            }
        }
    }

    /// Cheap shape gate: schema head + newline tail.
    fn drop_line_ok(line: &[u8]) -> bool {
        let head = b"{\"schema_version\":\"0.1.1\"";
        if line.len() < head.len() + 1 {
            return false;
        }
        if &line[..head.len()] != head {
            return false;
        }
        line[line.len() - 1] == 0x0A
    }

    /// Null writer: counts + shape-checks lines, spills session.
    ///
    /// Event bytes are dropped (the op-count crossing would
    /// otherwise need 1.4 GiB of events); every line still
    /// passes a schema-head/newline-tail gate, and finalize
    /// writes a real session.json into the created dir. No
    /// fsync: the spill is read back on the same machine.
    pub(crate) struct DropWriter {
        dir_path: String,
        /// True once created.
        pub(crate) created: bool,
        /// append call count.
        pub(crate) appends: i64,
        bytes: u64,
        mark_appends: i64,
        mark_bytes: u64,
        /// True once finalized.
        pub(crate) finalized: bool,
    }

    impl DropWriter {
        /// A fresh null writer.
        pub(crate) fn new() -> Self {
            Self {
                dir_path: String::new(),
                created: false,
                appends: 0,
                bytes: 0,
                mark_appends: 0,
                mark_bytes: 0,
                finalized: false,
            }
        }
    }

    impl Default for DropWriter {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WriterSource for DropWriter {
        fn create(&mut self, path: &str, _budget: u64) -> CreateOut {
            use std::os::unix::fs::PermissionsExt;
            match std::fs::create_dir(path) {
                Ok(()) => {
                    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                    return CreateOut {
                        ok: false,
                        kind: "exists".to_string(),
                        message: "output exists".to_string(),
                    };
                }
                Err(_) => {
                    return CreateOut {
                        ok: false,
                        kind: "io".to_string(),
                        message: "mkdir failed".to_string(),
                    };
                }
            }
            self.dir_path = path.to_string();
            self.created = true;
            CreateOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }

        fn append(&mut self, line: &[u8]) -> AppendOut {
            if !drop_line_ok(line) {
                return AppendOut {
                    ok: false,
                    kind: "fatal".to_string(),
                    message: "misshapen line".to_string(),
                };
            }
            self.appends += 1;
            self.bytes += line.len() as u64;
            AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }

        fn append_closing(&mut self, line: &[u8]) -> AppendOut {
            self.append(line)
        }

        fn group_begin(&mut self) -> GroupOut {
            self.mark_appends = self.appends;
            self.mark_bytes = self.bytes;
            GroupOut {
                ok: true,
                mark: self.bytes,
                kind: String::new(),
            }
        }

        fn group_abort(&mut self, mark: u64) -> AppendOut {
            if mark != self.mark_bytes {
                return AppendOut {
                    ok: false,
                    kind: "misuse".to_string(),
                    message: "bad mark".to_string(),
                };
            }
            self.appends = self.mark_appends;
            self.bytes = self.mark_bytes;
            AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }

        fn checkpoint(&mut self, _session: &[u8]) -> AppendOut {
            AppendOut {
                ok: true,
                kind: String::new(),
                message: String::new(),
            }
        }

        fn finalize(&mut self, session: &[u8]) -> FinalOut {
            use std::os::unix::fs::OpenOptionsExt;
            let path = format!("{}/session.json", self.dir_path);
            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            let mut file = match opts.open(&path) {
                Ok(file) => file,
                Err(_) => {
                    return FinalOut {
                        status: "unfinalized".to_string(),
                        note: "session create failed".to_string(),
                    };
                }
            };
            use std::io::Write;
            if file.write_all(session).is_err() {
                return FinalOut {
                    status: "unfinalized".to_string(),
                    note: "session write failed".to_string(),
                };
            }
            self.finalized = true;
            FinalOut {
                status: "finalized".to_string(),
                note: String::new(),
            }
        }

        fn abandon(&mut self) -> String {
            if std::fs::remove_dir(&self.dir_path).is_err() {
                return "rmdir failed".to_string();
            }
            self.created = false;
            String::new()
        }

        fn discard(&mut self) {}

        fn committed_len(&self) -> u64 {
            self.bytes
        }

        fn finalized_identity(&self) -> Vec<u64> {
            Vec::new()
        }
    }

    /// One ok stats script entry.
    pub(crate) fn stats_ok(
        received: u64,
        delivered: u64,
        staged: u64,
        malformed: u64,
        dropped: u64,
    ) -> StatsOut {
        StatsOut {
            ok: true,
            received,
            delivered,
            staged,
            malformed,
            dropped,
            message: String::new(),
        }
    }

    /// One ok snapshot script entry.
    pub(crate) fn snap_ok(
        observed: u64,
        observed_bytes: u64,
        emitted: u64,
        emitted_bytes: u64,
        submit_fail: u64,
        flags: u64,
    ) -> SnapOut {
        SnapOut {
            ok: true,
            vals: vec![
                observed,
                observed_bytes,
                emitted,
                emitted_bytes,
                submit_fail,
                flags,
            ],
            message: String::new(),
        }
    }

    /// One failed snapshot script entry.
    pub(crate) fn snap_err() -> SnapOut {
        SnapOut {
            ok: false,
            vals: Vec::new(),
            message: "scripted read error".to_string(),
        }
    }

    /// One timeout poll.
    pub(crate) fn timeout_poll() -> PollOut {
        PollOut {
            kind: "timeout".to_string(),
            frame: Vec::new(),
            required: 0,
            message: String::new(),
        }
    }

    /// One batch poll over raw payload bytes.
    pub(crate) fn batch_poll(payload: Vec<u8>) -> PollOut {
        PollOut {
            kind: "batch".to_string(),
            frame: payload,
            required: 0,
            message: String::new(),
        }
    }

    fn le16(v: u64) -> [u8; 2] {
        [v as u8, (v >> 8) as u8]
    }

    fn le32(v: u64) -> [u8; 4] {
        [v as u8, (v >> 8) as u8, (v >> 16) as u8, (v >> 24) as u8]
    }

    fn le64(v: u64) -> [u8; 8] {
        v.to_le_bytes()
    }

    /// One 98-byte attempt payload.
    pub(crate) fn attempt_payload(seq: u64, ktime: u64, size: u64, name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&le32(0x3741564D));
        out.extend_from_slice(&le16(1));
        out.extend_from_slice(&le16(0));
        out.extend_from_slice(&le64(seq));
        out.extend_from_slice(&le64(ktime));
        out.extend_from_slice(&le64(size));
        let raw = name.as_bytes();
        let nlen = raw.len().min(63);
        out.extend_from_slice(&le16(nlen as u64));
        out.extend_from_slice(&raw[..nlen]);
        out.resize(out.len() + (64 - nlen), 0);
        out
    }

    /// One 44-byte lifecycle payload.
    pub(crate) fn lc_raw(
        kind: u64,
        flags: u64,
        dir: u64,
        seq: u64,
        ktime: u64,
        size: u64,
        generation: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&le32(0x434C564D));
        out.extend_from_slice(&le16(2));
        out.extend_from_slice(&le16(kind));
        out.extend_from_slice(&le16(flags));
        out.extend_from_slice(&le16(dir));
        out.extend_from_slice(&le64(seq));
        out.extend_from_slice(&le64(ktime));
        out.extend_from_slice(&le64(size));
        out.extend_from_slice(&le64(generation));
        out
    }

    /// One 48-byte copy payload.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn cp_raw(
        kind: u64,
        flags: u64,
        dir: u64,
        seq: u64,
        ktime: u64,
        requested: u64,
        effective: u64,
        reason: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&le32(0x5043564D));
        out.extend_from_slice(&le16(1));
        out.extend_from_slice(&le16(kind));
        out.extend_from_slice(&le16(flags));
        out.extend_from_slice(&le16(dir));
        out.extend_from_slice(&le64(seq));
        out.extend_from_slice(&le64(ktime));
        out.extend_from_slice(&le64(requested));
        out.extend_from_slice(&le64(effective));
        out.extend_from_slice(&le16(reason));
        out.push(0);
        out.push(0);
        out
    }

    /// One attempt batch on device sda.
    pub(crate) fn record_batch(seq: u64, ktime: u64, size: u64) -> PollOut {
        batch_poll(attempt_payload(seq, ktime, size, "sda"))
    }

    /// One hard poll error.
    pub(crate) fn err_poll() -> PollOut {
        PollOut {
            kind: "error".to_string(),
            frame: Vec::new(),
            required: 0,
            message: "scripted hard poll error".to_string(),
        }
    }

    /// One structurally short batch.
    pub(crate) fn short_frame_batch() -> PollOut {
        batch_poll(vec![1, 2, 3])
    }

    /// Structurally valid payload, non-UTF8 name (non-fatal).
    pub(crate) fn bad_utf8_batch(seq: u64, ktime: u64, size: u64) -> PollOut {
        let mut raw = attempt_payload(seq, ktime, size, "sda");
        raw[34] = 0xFF;
        raw[35] = 0xFE;
        batch_poll(raw)
    }

    /// Zero baseline + steady post-start flow (drain/end/final).
    pub(crate) fn steady_flow(kernel: &mut ScriptKernel, r: u64, d: u64) {
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(r, d, 0, 0, 0));
        }
    }

    /// Steady flow with malformed/dropped components.
    pub(crate) fn steady_flow_md(kernel: &mut ScriptKernel, r: u64, d: u64, m: u64, dr: u64) {
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(r, d, 0, m, dr));
        }
    }

    /// Baseline + error-path final (no drain/confirm stats).
    pub(crate) fn err_flow(kernel: &mut ScriptKernel, r: u64, d: u64) {
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(r, d, 0, 0, 0));
    }

    /// Zero start pair + stable end cut.
    pub(crate) fn cuts(
        kernel: &mut ScriptKernel,
        o: u64,
        ob: u64,
        e: u64,
        eb: u64,
        s: u64,
        f: u64,
    ) {
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zsnap.clone());
        kernel.add_snap(zsnap);
        let cut = snap_ok(o, ob, e, eb, s, f);
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut);
    }

    /// Zero stats + zero snaps.
    pub(crate) fn zeros(kernel: &mut ScriptKernel, nstats: i64, nsnaps: i64) {
        let zstats = stats_ok(0, 0, 0, 0, 0);
        for _ in 0..nstats {
            kernel.add_stats(zstats.clone());
        }
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        for _ in 0..nsnaps {
            kernel.add_snap(zsnap.clone());
        }
    }

    /// Standard clock: start/stable/attach/ready, `pre`
    /// sub-deadline nows, the latch jump, tail. The duplicated
    /// base+4 feeds the attach-completion and readiness stamps
    /// so the `pre` schedule stays aligned.
    pub(crate) fn std_clock(pre: i64) -> ScriptClock {
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 4);
        clock.add(base + 4);
        for i in 0..pre {
            clock.add(base + (4 + i) as u64);
        }
        let latch = base + 61000000001;
        clock.add(latch);
        for i in 0..7 {
            clock.add(latch + (1 + i) as u64);
        }
        clock
    }

    /// The close-out drain discards payloads without
    /// decoding, so any frame bytes drain-count.
    pub(crate) fn stop_batch() -> PollOut {
        batch_poll(vec![0u8; 64])
    }

    /// Standard probe config over one output dir.
    pub(crate) fn base_config(dir: &str, budget: u64) -> super::CollectorConfig {
        use crate::model::session::EvidenceItem;
        let mut cfg = super::CollectorConfig {
            duration_s: 60,
            max_events_bytes: budget,
            output: dir.to_string(),
            profile_id: "probe".to_string(),
            pid: 4242,
            has_boot_id: true,
            boot_id: "probe-boot".to_string(),
            ..Default::default()
        };
        cfg.evidence.push(EvidenceItem {
            item_type: "provenance".to_string(),
            source: "probe".to_string(),
            interpretation: "scripted run".to_string(),
        });
        cfg
    }

    /// One scripted run: result plus both output files as text.
    pub(crate) struct CaseOut {
        /// Process exit code.
        pub(crate) exit_code: i64,
        /// End reason enum.
        pub(crate) end_reason: String,
        /// Outcome enum.
        pub(crate) outcome: String,
        /// Human diagnostic.
        pub(crate) diagnostic: String,
        /// events.ndjson text.
        pub(crate) events: String,
        /// session.json text.
        pub(crate) session: String,
        /// signal check count.
        pub(crate) signal_checks: i64,
        /// Loop (nonzero-timeout) poll count.
        pub(crate) loop_polls: i64,
        /// Kernel call log.
        pub(crate) calls: Vec<String>,
    }

    /// Options for [`run_case`].
    pub(crate) struct RunOpts {
        /// Admission grade.
        pub(crate) grade: String,
        /// First misses read.
        pub(crate) misses: MissOut,
        /// Later misses reads when armed.
        pub(crate) misses2: MissOut,
        /// True to serve misses2 past the first read.
        pub(crate) use_misses2: bool,
        /// arm outcome.
        pub(crate) arm_out: OpOut,
        /// disarm outcome.
        pub(crate) disarm_out: OpOut,
        /// Present channel count (1/2/3).
        pub(crate) channels: i64,
        /// Trailing timeout count.
        pub(crate) timeouts: i64,
        /// True to append one confirm error poll.
        pub(crate) confirm_poll_err: bool,
        /// True to break the confirm final stats.
        pub(crate) fail_confirm_stats: bool,
        /// True for the pre-6.7 lower bound.
        pub(crate) lower_bound: bool,
        /// Lifecycle malformed/dropped deltas.
        pub(crate) ch1mal: u64,
        /// Lifecycle dropped delta.
        pub(crate) ch1drop: u64,
        /// Copy malformed delta.
        pub(crate) ch2mal: u64,
        /// Copy dropped delta.
        pub(crate) ch2drop: u64,
        /// Strict exit mode.
        pub(crate) strict: bool,
        pub(crate) read_files: bool,
    }

    impl Default for RunOpts {
        fn default() -> Self {
            let ok = OpOut {
                ok: true,
                message: String::new(),
            };
            Self {
                grade: String::new(),
                misses: MissOut {
                    ok: true,
                    ..Default::default()
                },
                misses2: MissOut {
                    ok: true,
                    ..Default::default()
                },
                use_misses2: false,
                arm_out: ok.clone(),
                disarm_out: ok,
                channels: 3,
                timeouts: 103,
                confirm_poll_err: false,
                fail_confirm_stats: false,
                lower_bound: false,
                ch1mal: 0,
                ch1drop: 0,
                ch2mal: 0,
                ch2drop: 0,
                strict: false,
                read_files: true,
            }
        }
    }

    /// Read one output file as text.
    pub(crate) fn read_text(path: &str) -> String {
        let raw = std::fs::read(path).expect("read output file");
        String::from_utf8(raw).expect("output is UTF-8")
    }

    /// Non-overlapping substring occurrences.
    pub(crate) fn count_occurrences(hay: &str, needle: &str) -> usize {
        if needle.is_empty() {
            return 0;
        }
        let mut n = 0;
        let mut rest = hay;
        while let Some(at) = rest.find(needle) {
            n += 1;
            rest = &rest[at + needle.len()..];
        }
        n
    }

    /// Verify session integrity metadata against event bytes.
    pub(crate) fn check_integrity(events: &str, session: &str) {
        use crate::model::event::parse_event;
        use crate::model::integrity::{INTEGRITY_KIND_COUNT, integrity_kind_index};
        use crate::model::session::parse_session;
        use crate::platform::hash::sha256_hex;
        if session.is_empty() {
            return;
        }
        let s = parse_session(session.as_bytes()).expect("parse session");
        assert!(s.has_integrity);
        assert_eq!(s.integrity.events_bytes, events.len() as u64);
        assert_eq!(s.integrity.events_sha256, sha256_hex(events.as_bytes()));
        let lines: Vec<&str> = events.lines().collect();
        assert_eq!(s.integrity.line_count, lines.len() as u64);
        let mut counts = [0u64; INTEGRITY_KIND_COUNT];
        for (i, line) in lines.iter().enumerate() {
            let event = parse_event(line.as_bytes()).expect("parse event");
            assert_eq!(event.seq, i as u64);
            let idx = integrity_kind_index(&event.kind).expect("known kind");
            counts[idx] += 1;
        }
        for i in 0..INTEGRITY_KIND_COUNT {
            assert_eq!(s.integrity.kinds[i], counts[i]);
        }
    }

    /// Run one scripted multi-channel capture; return its outputs.
    ///
    /// Channels selects attempt-only (1), lifecycle (2),
    /// or copy (3); enabled channels use 8 MiB rings;
    /// end0/end1/end2 are the 6-word end cuts and rx1/rx2
    /// the lifecycle/copy received/delivered counts
    /// (attempt traffic is the remainder). Signals stop
    /// the run after the last batch.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_case(
        tmp: &str,
        payloads: Vec<Vec<u8>>,
        end0: Vec<u64>,
        end1: Vec<u64>,
        rx1: u64,
        end2: Vec<u64>,
        rx2: u64,
        opts: &RunOpts,
    ) -> CaseOut {
        let cfg = super::CollectorConfig {
            duration_s: 60,
            max_events_bytes: 1073741824,
            output: format!("{tmp}/cap"),
            profile_id: "test-profile-1".to_string(),
            grade: opts.grade.clone(),
            pid: 7,
            has_ring_bytes: true,
            ring_bytes: 8388608,
            has_lifecycle: opts.channels >= 2,
            lifecycle_ring_bytes: 8388608,
            has_copy: opts.channels >= 3,
            copy_ring_bytes: 8388608,
            attempt_loss_lower_bound: opts.lower_bound,
            strict: opts.strict,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.channels = opts.channels;
        kernel.misses_out = opts.misses.clone();
        kernel.misses_out2 = opts.misses2.clone();
        kernel.use_misses2 = opts.use_misses2;
        kernel.arm_out = opts.arm_out.clone();
        kernel.disarm_out = opts.disarm_out.clone();
        let zero_snap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zero_snap.clone());
        kernel.add_snap(zero_snap.clone());
        if opts.channels >= 2 {
            kernel.add_snap_at(1, zero_snap.clone());
            kernel.add_snap_at(1, zero_snap.clone());
        }
        if opts.channels >= 3 {
            kernel.add_snap_at(2, zero_snap.clone());
            kernel.add_snap_at(2, zero_snap);
        }
        let end0snap = SnapOut {
            ok: true,
            vals: end0,
            message: String::new(),
        };
        kernel.add_snap(end0snap.clone());
        kernel.add_snap(end0snap);
        if opts.channels >= 2 {
            let end1snap = SnapOut {
                ok: true,
                vals: end1,
                message: String::new(),
            };
            kernel.add_snap_at(1, end1snap.clone());
            kernel.add_snap_at(1, end1snap);
        }
        if opts.channels >= 3 {
            let end2snap = SnapOut {
                ok: true,
                vals: end2,
                message: String::new(),
            };
            kernel.add_snap_at(2, end2snap.clone());
            kernel.add_snap_at(2, end2snap);
        }
        let n = payloads.len() as u64;
        // Shared stats queue in read order: sum baseline, ch0
        // baseline, drain pair, drain cut, final sum, ch0 final.
        // Attempt-only skips both ch0 entries (no _at reads).
        // The pooled final carries the per-channel loss sums, so
        // pooled pairs and the channel breakdown agree. Received
        // covers delivered plus malformed plus dropped on every
        // ring (the close-out bridge identity).
        let total = stats_ok(
            n + opts.ch1mal + opts.ch2mal + opts.ch1drop + opts.ch2drop,
            n,
            0,
            opts.ch1mal + opts.ch2mal,
            opts.ch1drop + opts.ch2drop,
        );
        let ch0n = stats_ok(n - rx1 - rx2, n - rx1 - rx2, 0, 0, 0);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        if opts.channels >= 2 {
            kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        }
        kernel.add_stats(total.clone());
        kernel.add_stats(total.clone());
        kernel.add_stats(total.clone());
        if opts.fail_confirm_stats {
            kernel.add_stats(StatsOut {
                ok: false,
                received: 0,
                delivered: 0,
                staged: 0,
                malformed: 0,
                dropped: 0,
                message: "confirm stats lost".to_string(),
            });
        } else {
            kernel.add_stats(total.clone());
        }
        if opts.channels >= 2 {
            kernel.add_stats(ch0n);
            kernel.add_stats_at(1, stats_ok(0, 0, 0, 0, 0));
            kernel.add_stats_at(
                1,
                stats_ok(
                    rx1 + opts.ch1mal + opts.ch1drop,
                    rx1,
                    0,
                    opts.ch1mal,
                    opts.ch1drop,
                ),
            );
        }
        if opts.channels >= 3 {
            kernel.add_stats_at(2, stats_ok(0, 0, 0, 0, 0));
            kernel.add_stats_at(
                2,
                stats_ok(
                    rx2 + opts.ch2mal + opts.ch2drop,
                    rx2,
                    0,
                    opts.ch2mal,
                    opts.ch2drop,
                ),
            );
        }
        for payload in &payloads {
            kernel.add_poll(batch_poll(payload.clone()), 1);
        }
        kernel.add_poll(timeout_poll(), opts.timeouts);
        if opts.confirm_poll_err {
            kernel.add_poll(
                PollOut {
                    kind: "error".to_string(),
                    frame: Vec::new(),
                    required: 0,
                    message: "confirm poll failed".to_string(),
                },
                1,
            );
        }
        // One head check plus one gate per frame; the next head check latches.
        let mut signal = ScriptSignal::new();
        for _ in 0..payloads.len() + 1 {
            signal.add("none");
        }
        signal.add("pending");
        let mut clock = ScriptClock::new();
        clock.add(0);
        let mut writer = ScriptWriter::new();
        let mut collector = super::Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        let out_dir = format!("{tmp}/cap");
        let mut events = String::new();
        let mut session = String::new();
        if opts.read_files {
            events = read_text(&format!("{out_dir}/events.ndjson"));
            session = read_text(&format!("{out_dir}/session.json"));
        }
        // Close-out drains poll with timeout 0; the loop never does.
        let mut loop_polls = 0;
        for t in &kernel.poll_timeouts {
            if *t != 0 {
                loop_polls += 1;
            }
        }
        check_integrity(&events, &session);
        CaseOut {
            exit_code: result.exit_code,
            end_reason: result.end_reason,
            outcome: result.outcome,
            diagnostic: result.diagnostic,
            events,
            session,
            signal_checks: signal.checks,
            loop_polls,
            calls: kernel.calls.clone(),
        }
    }

    /// Options for [`run_live_case`].
    pub(crate) struct LiveOpts {
        /// True when the lifecycle channel runs.
        pub(crate) has_lifecycle: bool,
        /// True when the copy channel runs.
        pub(crate) has_copy: bool,
        /// Capture duration in seconds.
        pub(crate) duration_s: u64,
        /// Events budget in bytes.
        pub(crate) max_events_bytes: u64,
        /// Trailing timeout count.
        pub(crate) timeouts: i64,
        /// First misses read.
        pub(crate) misses: MissOut,
        /// Later misses reads when armed.
        pub(crate) misses2: MissOut,
        /// True to serve misses2 past the first read.
        pub(crate) use_misses2: bool,
    }

    impl Default for LiveOpts {
        fn default() -> Self {
            Self {
                has_lifecycle: true,
                has_copy: true,
                duration_s: 60,
                max_events_bytes: 1073741824,
                timeouts: 103,
                misses: MissOut {
                    ok: true,
                    ..Default::default()
                },
                misses2: MissOut {
                    ok: true,
                    ..Default::default()
                },
                use_misses2: false,
            }
        }
    }

    /// Explicit startup reads through the ready stamp.
    pub(crate) fn live_clock_values(base: u64, has_lifecycle: bool, has_copy: bool) -> Vec<u64> {
        let mut nch = 1;
        if has_lifecycle {
            nch += 1;
        }
        if has_copy {
            nch += 1;
        }
        let mut out = Vec::new();
        for i in 0..1 + 2 * nch + 1 {
            out.push(base + i as u64);
        }
        out
    }

    /// Attach read of an explicit startup script (no pool).
    pub(crate) fn live_attach(clock_values: &[u64], has_lifecycle: bool, has_copy: bool) -> u64 {
        let mut nch = 1;
        if has_lifecycle {
            nch += 1;
        }
        if has_copy {
            nch += 1;
        }
        clock_values[1 + 2 * nch]
    }

    /// `run_case` with an explicit clock script and channel flags.
    ///
    /// Record ktimes are absolute; tests place them with
    /// `live_attach` plus an offset. The scripted tail steps
    /// 100ms per read.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn run_live_case(
        tmp: &str,
        payloads: Vec<Vec<u8>>,
        clock_values: Vec<u64>,
        end0: Vec<u64>,
        end1: Vec<u64>,
        rx1: u64,
        end2: Vec<u64>,
        rx2: u64,
        opts: &LiveOpts,
    ) -> CaseOut {
        let out_dir = format!("{tmp}/cap");
        let cfg = super::CollectorConfig {
            duration_s: opts.duration_s,
            max_events_bytes: opts.max_events_bytes,
            output: out_dir.clone(),
            profile_id: "test-profile-1".to_string(),
            pid: 7,
            has_ring_bytes: true,
            ring_bytes: 8388608,
            has_lifecycle: opts.has_lifecycle,
            lifecycle_ring_bytes: 8388608,
            has_copy: opts.has_copy,
            copy_ring_bytes: 8388608,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        if opts.has_copy {
            kernel.channels = 3;
        } else if opts.has_lifecycle {
            kernel.channels = 2;
        }
        kernel.misses_out = opts.misses.clone();
        kernel.misses_out2 = opts.misses2.clone();
        kernel.use_misses2 = opts.use_misses2;
        let zero_snap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zero_snap.clone());
        kernel.add_snap(zero_snap.clone());
        if opts.has_lifecycle {
            kernel.add_snap_at(1, zero_snap.clone());
            kernel.add_snap_at(1, zero_snap.clone());
        }
        if opts.has_copy {
            kernel.add_snap_at(2, zero_snap.clone());
            kernel.add_snap_at(2, zero_snap);
        }
        let end0snap = SnapOut {
            ok: true,
            vals: end0,
            message: String::new(),
        };
        kernel.add_snap(end0snap.clone());
        kernel.add_snap(end0snap);
        if opts.has_lifecycle {
            let end1snap = SnapOut {
                ok: true,
                vals: end1,
                message: String::new(),
            };
            kernel.add_snap_at(1, end1snap.clone());
            kernel.add_snap_at(1, end1snap);
        }
        if opts.has_copy {
            let end2snap = SnapOut {
                ok: true,
                vals: end2,
                message: String::new(),
            };
            kernel.add_snap_at(2, end2snap.clone());
            kernel.add_snap_at(2, end2snap);
        }
        let n = payloads.len() as u64;
        let total = stats_ok(n, n, 0, 0, 0);
        let ch0n = stats_ok(n - rx1 - rx2, n - rx1 - rx2, 0, 0, 0);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        let mut nch = 1;
        if opts.has_lifecycle {
            nch += 1;
        }
        if opts.has_copy {
            nch += 1;
        }
        if nch >= 2 {
            kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        }
        kernel.add_stats(total.clone());
        kernel.add_stats(total.clone());
        kernel.add_stats(total.clone());
        kernel.add_stats(total.clone());
        if nch >= 2 {
            kernel.add_stats(ch0n);
        }
        if opts.has_lifecycle {
            kernel.add_stats_at(1, stats_ok(0, 0, 0, 0, 0));
            kernel.add_stats_at(1, stats_ok(rx1, rx1, 0, 0, 0));
        }
        if opts.has_copy {
            kernel.add_stats_at(2, stats_ok(0, 0, 0, 0, 0));
            kernel.add_stats_at(2, stats_ok(rx2, rx2, 0, 0, 0));
        }
        for payload in &payloads {
            kernel.add_poll(batch_poll(payload.clone()), 1);
        }
        kernel.add_poll(timeout_poll(), opts.timeouts);
        let mut signal = ScriptSignal::new();
        for _ in 0..payloads.len() + 1 {
            signal.add("none");
        }
        signal.add("pending");
        let mut clock = ScriptClock::new();
        clock.step = 100000000;
        for v in clock_values {
            clock.add(v);
        }
        let mut writer = ScriptWriter::new();
        let mut collector = super::Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        let events = read_text(&format!("{out_dir}/events.ndjson"));
        let session = read_text(&format!("{out_dir}/session.json"));
        let mut loop_polls = 0;
        for t in &kernel.poll_timeouts {
            if *t != 0 {
                loop_polls += 1;
            }
        }
        check_integrity(&events, &session);
        CaseOut {
            exit_code: result.exit_code,
            end_reason: result.end_reason,
            outcome: result.outcome,
            diagnostic: result.diagnostic,
            events,
            session,
            signal_checks: signal.checks,
            loop_polls,
            calls: kernel.calls.clone(),
        }
    }

    /// Zero 6-word cut.
    pub(crate) fn zero_cut() -> Vec<u64> {
        vec![0, 0, 0, 0, 0, 0]
    }

    /// 6-word cut with zero submit_fail and flags.
    pub(crate) fn cut(o: u64, ob: u64, e: u64, eb: u64) -> Vec<u64> {
        vec![o, ob, e, eb, 0, 0]
    }

    pub(crate) fn cut5(o: u64, ob: u64, e: u64, eb: u64, s: u64) -> Vec<u64> {
        vec![o, ob, e, eb, s, 0]
    }

    /// Mask the host filesystem in session provenance.
    pub(crate) fn mask_output_fs(session: &str) -> String {
        let key = "\"source\":\"output.fs\",\"interpretation\":\"";
        let b = session.as_bytes();
        let kb = key.as_bytes();
        let mut i = 0;
        while i + kb.len() <= b.len() {
            if &b[i..i + kb.len()] == kb {
                let mut end = i + kb.len();
                while end < b.len() && b[end] != 0x22 {
                    end += 1;
                }
                return session[..i + kb.len()].to_string() + "FS" + &session[end..];
            }
            i += 1;
        }
        panic!("session has no output.fs provenance");
    }
}

#[cfg(test)]
mod tests {
    use super::script::{
        AppendFault, DropWriter, RunOpts, ScriptClock, ScriptKernel, ScriptSignal, ScriptWriter,
        attempt_payload, bad_utf8_batch, base_config, batch_poll, check_integrity,
        count_occurrences, cp_raw, cut, cut5, cuts, err_flow, err_poll, lc_raw, mask_output_fs,
        read_text, record_batch, run_case, short_frame_batch, snap_err, snap_ok, stats_ok,
        std_clock, steady_flow, steady_flow_md, stop_batch, timeout_poll, zero_cut, zeros,
    };
    use super::{
        CNT_EMITTED, CNT_FLAGS, Collector, CollectorConfig, EXIT_ERROR, EXIT_OK, EXIT_PARTIAL,
        EXIT_REFUSAL, FLAG_ARGCNT, MissOut, StatsOut, aggregate_reason, all_zero,
        byte_coverage_valid, byte_identity, checked_add, count_identity, counters_valid,
        detail_reason_known, detail_reason_unknown, detection_for, env_mode_for, identity_estimate,
        op_limited, stable_cut, submit_valid,
    };
    use crate::capture::live::WriterSource;
    use crate::model::session::{Session, parse_session};
    use crate::platform::outcome::OpOut;
    use crate::platform::test_support::TestDir;

    fn stop_session(cap: &str) -> Session {
        let raw = std::fs::read(format!("{cap}/session.json")).expect("read session");
        parse_session(&raw).expect("parse session")
    }

    #[test]
    fn op_guard_boundary() {
        assert!(!op_limited(0));
        assert!(!op_limited(4194303));
        assert!(op_limited(4194304));
        assert!(op_limited(4194305));
        assert!(op_limited(u64::MAX));
    }

    #[test]
    fn identity_estimate_sums_kinds() {
        // Every persisted map contributes its operation plus,
        // when successful, its mapping; repeats never add.
        assert_eq!(identity_estimate(10, 5, 3, 2, 1, 1), 22);
        assert_eq!(identity_estimate(0, 0, 0, 0, 0, 0), 0);
        // A capture of pure maps costs two identities per map:
        // the old event-count budget would have admitted twice
        // the reader's cap.
        assert_eq!(identity_estimate(0, 2097152, 2097152, 0, 0, 0), 4194304);
    }

    #[test]
    fn detail_known_grammar() {
        let got = detail_reason_known(1, 2, 0, 3, 0, 4, 0, 1, 0);
        assert_eq!(
            got,
            "detail loss 11 (submit_fail=(1) malformed=(2) dropped=(0) recursion_missed=(3) size_omitted=(0) duration_omitted=(4) signal_omitted=(0) rejected=(1) write_failed=(0))"
        );
    }

    #[test]
    fn detail_unknown_grammar() {
        let got = detail_reason_unknown(
            "drain budget exhausted",
            "unavailable",
            "3",
            "0",
            "unavailable",
            0,
            9,
            0,
            0,
            0,
        );
        assert_eq!(
            got,
            "detail loss unknown (drain budget exhausted; known: submit_fail=(unavailable) malformed=(3) dropped=(0) recursion_missed=(unavailable) size_omitted=(0) duration_omitted=(9) signal_omitted=(0) rejected=(0) write_failed=(0))"
        );
    }

    #[test]
    fn aggregate_grammar() {
        assert_eq!(
            aggregate_reason(true, ""),
            "counter snapshots present (valid cut, identity holds, coverage valid)"
        );
        assert_eq!(
            aggregate_reason(false, "no stable cut"),
            "counter snapshots absent (no stable cut)"
        );
    }

    #[test]
    fn cut_and_identities() {
        let zeros = vec![0u64; 6];
        let ones = vec![1u64; 6];
        assert!(stable_cut(&zeros, &zeros));
        assert!(!stable_cut(&zeros, &ones));
        assert!(!stable_cut(&zeros, &[0]));
        assert!(all_zero(&zeros));
        assert!(!all_zero(&ones));
        // O=2 E=1 S=1: identity holds.
        let good = vec![2, 10, 1, 6, 1, 0];
        assert!(count_identity(&good));
        assert!(counters_valid(&good));
        assert!(byte_coverage_valid(&good));
        assert!(submit_valid(&good));
        assert!(byte_identity(&good));
        // Paused-before-byte-update: O=2 E=1 S=0 breaks it.
        let paused = vec![2, 10, 1, 6, 0, 0];
        assert!(!count_identity(&paused));
        assert!(counters_valid(&paused));
        assert!(byte_coverage_valid(&paused));
        // Submit wrap poisons the count epoch only.
        let wrapped = vec![7, 70, 5, 50, 2, 16];
        assert!(count_identity(&wrapped));
        assert!(!counters_valid(&wrapped));
        assert!(!byte_coverage_valid(&wrapped));
        assert!(!submit_valid(&wrapped));
        // Byte coverage bit poisons bytes, not counts.
        let covered = vec![2, 0, 0, 0, 2, 32];
        assert!(count_identity(&covered));
        assert!(counters_valid(&covered));
        assert!(!byte_coverage_valid(&covered));
        assert!(submit_valid(&covered));
        // Observed bytes below emitted bytes is incoherent.
        let incoherent = vec![3, 4, 3, 9, 0, 0];
        assert!(!byte_identity(&incoherent));
        assert!(!byte_coverage_valid(&incoherent));
    }

    #[test]
    fn table_bad_cut_has_no_byte_coverage() {
        // One table-bad firing (unknown size): counts stay
        // coherent, but no requested-byte snapshot is
        // covered.
        let cut = vec![1, 0, 0, 0, 1, 32];
        assert!(count_identity(&cut));
        assert!(counters_valid(&cut));
        assert!(!byte_coverage_valid(&cut));
        assert!(submit_valid(&cut));
    }

    #[test]
    fn checked_add_saturates() {
        let top = u64::MAX;
        assert_eq!(checked_add(2, 3), 5);
        assert_eq!(checked_add(top, 1), top);
        assert_eq!(checked_add(top, top), top);
        assert_eq!(checked_add(0, 0), 0);
    }

    #[test]
    fn env_mapping() {
        use crate::platform::evidence::GuestInfo;
        let snp = GuestInfo {
            tech: "snp".to_string(),
            signals: vec!["sev_snp:cc_blob".to_string()],
            asserted: false,
            conflict: String::new(),
        };
        assert_eq!(env_mode_for(&snp), "sev_snp");
        assert_eq!(detection_for(&snp), "kernel_reported");
        let ordinary = GuestInfo {
            tech: "ordinary".to_string(),
            signals: Vec::new(),
            asserted: false,
            conflict: String::new(),
        };
        assert_eq!(env_mode_for(&ordinary), "none");
        assert_eq!(detection_for(&ordinary), "kernel_reported");
        let unknown = GuestInfo {
            tech: "unknown".to_string(),
            signals: Vec::new(),
            asserted: false,
            conflict: String::new(),
        };
        assert_eq!(env_mode_for(&unknown), "unknown");
        assert_eq!(detection_for(&unknown), "unverified");
        let conflicted = GuestInfo {
            tech: "tdx".to_string(),
            signals: Vec::new(),
            asserted: false,
            conflict: "dmi vs msr".to_string(),
        };
        assert_eq!(env_mode_for(&conflicted), "tdx");
        assert_eq!(detection_for(&conflicted), "conflicting");
    }

    fn argcnt_vals(flags: u64) -> Vec<u64> {
        vec![10, 100, 9, 90, 1, flags]
    }

    fn argcnt_start() -> StatsOut {
        stats_ok(0, 0, 0, 0, 0)
    }

    fn argcnt_final() -> StatsOut {
        stats_ok(9, 9, 0, 0, 0)
    }

    #[test]
    fn evaluate_channel_argcnt_noted() {
        let mut collector = Collector::new(CollectorConfig::default());
        let vals = argcnt_vals(FLAG_ARGCNT);
        assert_eq!(vals[CNT_FLAGS], FLAG_ARGCNT);
        let out = collector.evaluate_channel(&vals, true, &argcnt_start(), &argcnt_final(), "lc");
        assert_eq!(out, "");
        assert_eq!(collector.unknown_cause, "lc argument count mismatch");
    }

    #[test]
    fn evaluate_channel_argcnt_precedes_identity() {
        let mut collector = Collector::new(CollectorConfig::default());
        let mut vals = argcnt_vals(FLAG_ARGCNT);
        vals[CNT_EMITTED] = 5;
        let out = collector.evaluate_channel(&vals, true, &argcnt_start(), &argcnt_final(), "lc");
        assert_eq!(out, "");
        assert_eq!(collector.unknown_cause, "lc argument count mismatch");
        let mut plain = Collector::new(CollectorConfig::default());
        let mut vals2 = argcnt_vals(0);
        vals2[CNT_EMITTED] = 5;
        let out2 = plain.evaluate_channel(&vals2, true, &argcnt_start(), &argcnt_final(), "lc");
        assert_eq!(out2, "");
        assert_eq!(plain.unknown_cause, "lc kernel identity unproven");
    }

    fn zero_snaps(kernel: &mut ScriptKernel, channel: i64) {
        let z = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap_at(channel, z.clone());
        kernel.add_snap_at(channel, z);
    }

    fn zero_stats(kernel: &mut ScriptKernel) {
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
    }

    #[test]
    fn ready_after_arm() {
        // Readiness lands after the copy arm: attach_ns < ready_ns over strictly increasing scripted clock reads.
        let tmp = TestDir::create("memveil-collector-ts").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            max_events_bytes: 134217728,
            profile_id: "ts-probe".to_string(),
            pid: 4242,
            has_copy: true,
            copy_ring_bytes: 8388608,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.channels = 3;
        zero_snaps(&mut kernel, 0);
        zero_snaps(&mut kernel, 2);
        zero_stats(&mut kernel);
        let s = stats_ok(0, 0, 0, 0, 0);
        kernel.add_stats_at(0, s.clone());
        kernel.add_stats_at(2, s);
        let mut clock = ScriptClock::new();
        clock.step = 1000;
        clock.add(1000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let refusal = collector.startup(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(refusal, "");
        assert!(collector.attach_ns < collector.ready_ns);
        assert_eq!(collector.attach_ns, 6000);
        assert_eq!(collector.attempt_attach_done_ns, 7000);
        assert_eq!(collector.ready_ns, 8000);
    }

    #[test]
    fn detach_begin_before_detach() {
        // The close-out window opens before it ends: detach_begin_ns is the shutdown's first clock read and detach_ns a later one.
        let tmp = TestDir::create("memveil-collector-ts").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            max_events_bytes: 134217728,
            profile_id: "ts-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        zero_snaps(&mut kernel, 0);
        zero_stats(&mut kernel);
        let mut clock = ScriptClock::new();
        clock.step = 1000;
        clock.add(1000);
        let mut writer = ScriptWriter::new();
        let made = writer.create(&format!("{}/cap", tmp.as_str()), 134217728);
        assert!(made.ok);
        let mut collector = Collector::new(cfg);
        collector.stop_ctl.mark_ready();
        let result = collector.error_close(&mut kernel, &mut clock, &mut writer);
        assert!(collector.detach_begin_ns <= collector.detach_ns);
        assert_eq!(collector.detach_begin_ns, 1000);
        assert_eq!(collector.detach_ns, 2000);
        // An error shutdown that still finalizes a valid session
        // exits 0; the unknown cause rides in the session verdict.
        assert_eq!(result.exit_code, 0);
    }

    #[test]
    fn attached_interval_reason_distinguishes_missing_and_unordered() {
        let mut collector = Collector::new(CollectorConfig::default());
        collector.snapshots_present = true;
        let missing = collector.assemble().expect("assemble");
        assert!(missing.q_aggregate.reason.contains("stamp missing"));
        for end in [10u64, 9u64] {
            collector.attempt_attach_done_ns = 10;
            collector.attempt_detach_begin_ns = end;
            let unordered = collector.assemble().expect("assemble");
            assert!(
                unordered
                    .q_aggregate
                    .reason
                    .contains("stamps not increasing")
            );
            assert!(!unordered.q_aggregate.reason.contains("stamp missing"));
            assert_eq!(unordered.q_aggregate.status, missing.q_aggregate.status);
            assert_eq!(unordered.q_aggregate.scope, missing.q_aggregate.scope);
            assert_eq!(
                unordered.q_aggregate.has_loss_count,
                missing.q_aggregate.has_loss_count
            );
            assert_eq!(unordered.q_detail.status, missing.q_detail.status);
            assert_eq!(
                unordered.integrity.events_bytes,
                missing.integrity.events_bytes
            );
            assert_eq!(unordered.integrity.line_count, missing.integrity.line_count);
        }
    }

    #[test]
    fn stop_complete_gate() {
        // The complete gate opens only on present complete
        // evidence: missing evidence or a partial outcome keep
        // exit 4 and the partial terminal channel.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            ..Default::default()
        };
        let mut collector = Collector::new(cfg);
        collector.stop_evidence.outcome = "complete".to_string();
        assert!(!collector.stop_complete());
        collector.has_stop_evidence = true;
        collector.stop_evidence.outcome = "partial".to_string();
        assert!(!collector.stop_complete());
        collector.stop_evidence.outcome = "complete".to_string();
        assert!(collector.stop_complete());
    }

    #[test]
    fn final_exit_normal_zero_strict_verdict() {
        // A finalized session exits 0 no matter what it
        // records; strict exits 4 unless the record verdict computed
        // from the assembled session is complete.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            ..Default::default()
        };
        let collector = Collector::new(cfg);
        let mut s = Session::default();
        s.q_detail.status = "partial".to_string();
        assert_eq!(collector.final_exit_code(&s), EXIT_OK);
        s.q_detail.status = "unavailable".to_string();
        assert_eq!(collector.final_exit_code(&s), EXIT_OK);
        s.q_detail.status = "complete_for_scope".to_string();
        assert_eq!(collector.final_exit_code(&s), EXIT_OK);
        let scfg = CollectorConfig {
            output: format!("{}/cap-strict", tmp.as_str()),
            strict: true,
            ..Default::default()
        };
        let strict_collector = Collector::new(scfg);
        let mut clean = Session::default();
        clean.q_detail.status = "complete_for_scope".to_string();
        clean.q_detail.has_loss_count = true;
        clean.q_detail.loss_count = 0;
        clean.q_terminal.status = "complete_for_scope".to_string();
        clean.stop.outcome = "complete".to_string();
        assert_eq!(strict_collector.final_exit_code(&clean), EXIT_OK);
        clean.q_detail.status = "partial".to_string();
        assert_eq!(strict_collector.final_exit_code(&clean), EXIT_PARTIAL);
    }

    #[test]
    fn stop_counters_require_usable_cuts() {
        // counters_valid mirrors the run's own epoch verdict:
        // a stable cut with wrap flags (evaluate's invalid
        // epoch) or a broken count identity is not valid.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            ..Default::default()
        };
        let mut collector = Collector::new(cfg);
        assert!(!collector.stop_counters_valid());
        collector.end_vals = vec![0u64; 6];
        collector.has_end_cut = true;
        assert!(collector.stop_counters_valid());
        collector.end_vals[CNT_FLAGS] = super::FLAG_OBSERVED_WRAP;
        assert!(!collector.stop_counters_valid());
    }

    #[test]
    fn stop_finalize_elapsed_honest() {
        // Elapsed milliseconds round up: 5000.9 ms of
        // close-out exceeds the 5000 ms budget instead of
        // truncating into it. A regressing finalize stamp
        // notes a clock failure instead of silently
        // serializing zero.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/cap", tmp.as_str()),
            ..Default::default()
        };
        let mut collector = Collector::new(cfg);
        collector.stop_ctl.mark_ready();
        collector.stop_ctl.close_admission().expect("close");
        collector.stop_ctl.observe_quiescence().expect("quiesce");
        collector.stop_ctl.drain(0, false).expect("drain");
        collector.stop_ctl.sample_counters(true);
        collector.detach_ns = 1000000000;
        collector.stop_finalize(6000900000);
        assert_eq!(collector.stop_evidence.elapsed_ms, 5001);
        assert_eq!(collector.stop_evidence.reason, "stop budget exhausted");
        let cfg2 = CollectorConfig {
            output: format!("{}/cap2", tmp.as_str()),
            ..Default::default()
        };
        let mut reg = Collector::new(cfg2);
        reg.stop_ctl.mark_ready();
        reg.stop_ctl.close_admission().expect("close");
        reg.stop_ctl.observe_quiescence().expect("quiesce");
        reg.stop_ctl.drain(0, false).expect("drain");
        reg.stop_ctl.sample_counters(true);
        reg.detach_ns = 1000000000;
        reg.stop_finalize(7);
        assert_eq!(reg.stop_evidence.elapsed_ms, 0);
        assert_eq!(reg.unknown_cause, "stop clock regressed");
    }

    fn stop_run_evidence(strict: bool) -> (i64, TestDir) {
        // The scripted quiescence-unproven run: admission closed,
        // quiescence unproven (no kernel protocol observes it),
        // three drained batches, valid end counters.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 0,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "stop-evidence-probe".to_string(),
            pid: 4242,
            strict,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(stop_batch(), 3);
        kernel.add_poll(timeout_poll(), 300);
        // Stats order: startup, two drain reads, drain
        // snapshot, confirm final. The final carries the
        // three drained batches (received = delivered, none
        // staged) so loss closure holds.
        zeros(&mut kernel, 4, 4);
        kernel.add_stats(stats_ok(3, 3, 0, 0, 0));
        zeros(&mut kernel, 3, 0);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.end_reason, "duration");
        (result.exit_code, tmp)
    }

    #[test]
    fn closeout_records_stop_evidence() {
        // A scripted full run records exact terminal stop
        // evidence: admission closed, quiescence unproven (no
        // kernel protocol observes it), three drained batches,
        // valid end counters. A finalized capture exits
        // 0; completeness rides in the session verdict.
        let (exit_code, tmp) = stop_run_evidence(false);
        assert_eq!(exit_code, 0);
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.stop.outcome, "partial");
        assert_eq!(s.stop.reason, "quiescence unproven");
        assert_eq!(s.stop.budget_ms, 5000);
        assert!(s.stop.elapsed_ms <= 5000);
        assert!(s.stop.admission_closed);
        assert!(!s.stop.quiescence_observed);
        assert_eq!(s.stop.writers_settled, 0);
        assert_eq!(s.stop.in_flight_at_close, 0);
        assert_eq!(s.stop.late_submits_drained, 0);
        assert_eq!(s.stop.drained_records, 3);
        assert!(!s.stop.busy_at_drain);
        assert!(s.stop.counters_valid);
        assert_eq!(s.stop.open_mappings, 0);
    }

    #[test]
    fn closeout_strict_partial() {
        // The same quiescence-unproven run under --strict exits 4:
        // the record verdict is not complete.
        let (exit_code, _tmp) = stop_run_evidence(true);
        assert_eq!(exit_code, 4);
    }

    #[test]
    fn closeout_detach_failure_partial() {
        // A failed detach finalizes partial with the admission
        // reason; the close is not claimed.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 0,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "stop-detach-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.detach_out = OpOut {
            ok: false,
            message: "boom".to_string(),
        };
        kernel.add_poll(timeout_poll(), 300);
        zeros(&mut kernel, 8, 4);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        // Finalized exits 0.
        assert_eq!(result.exit_code, 0);
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.stop.outcome, "partial");
        assert_eq!(s.stop.reason, "admission close failed");
        assert!(!s.stop.admission_closed);
    }

    #[test]
    fn signal_storm_first_latch_stands() {
        // A storm of pending signals latches once on the
        // first: the immutable stop reason stands, the
        // close-out completes, and terminal evidence stays
        // honest. Ten pendings arrive; exactly one is
        // observed (three quiet checks, then the latch).
        // The close-out reads no signal state, so the
        // storm's tail can neither disturb nor extend it.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "stop-storm-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 300);
        zeros(&mut kernel, 8, 4);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        for _ in 0..3 {
            signal.add("none");
        }
        for _ in 0..10 {
            signal.add("pending");
        }
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        // Finalized exits 0.
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.end_reason, "signal");
        assert_eq!(signal.checks, 4);
        assert_eq!(signal.idx, 4);
        assert_eq!(kernel.closes_done, 0);
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.end_reason, "signal");
        assert_eq!(s.stop.outcome, "partial");
        assert_eq!(s.stop.reason, "quiescence unproven");
        assert_eq!(s.stop.budget_ms, 5000);
        assert!(s.stop.elapsed_ms <= 5000);
        assert!(s.stop.admission_closed);
        assert!(!s.stop.quiescence_observed);
        assert!(!s.stop.busy_at_drain);
        assert!(s.stop.counters_valid);
    }

    #[test]
    fn refusal_closes_session_once() {
        // A pre-readiness refusal releases the owned
        // session exactly once: the rollback accounts for
        // the resource instead of leaking it or closing
        // twice.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "stop-refuse-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.attach_out = OpOut {
            ok: false,
            message: "scripted attach failure".to_string(),
        };
        zeros(&mut kernel, 2, 2);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.end_reason, "unknown");
        assert_eq!(result.outcome, "refused");
        assert_eq!(kernel.closes_done, 1);
    }

    #[test]
    fn closing_snapshot_fault_keeps_readable_session() {
        // Blocked output during close-out: the first
        // closing snapshot append fails, the rollback
        // group aborts, and the run degrades to error
        // state. The session still finalizes readably
        // (end reason error, stop evidence present) with
        // zero committed closing bytes; the failure is
        // loud, never a silent complete.
        let tmp = TestDir::create("memveil-stop").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 0,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "stop-closing-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 300);
        zeros(&mut kernel, 8, 4);
        let mut clock = ScriptClock::new();
        clock.add(1000000000);
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        writer.append_faults.push(AppendFault {
            at: 1,
            kind: "io".to_string(),
        });
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.end_reason, "error");
        assert_eq!(result.outcome, "error");
        assert_eq!(writer.appends, 1);
        assert_eq!(writer.committed_len(), 0);
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.end_reason, "error");
        assert!(s.cap_bounce_attempts.reason.contains("capture error"));
        assert_eq!(s.stop.outcome, "partial");
        assert_eq!(s.stop.reason, "quiescence unproven");
        assert!(s.stop.admission_closed);
        assert!(!s.stop.busy_at_drain);
    }

    fn pool_fixture(name: &str) -> String {
        crate::platform::test_support::repo_root()
            .join("tests/fixtures/pools")
            .join(name)
            .to_str()
            .expect("fixture path must be UTF-8")
            .to_string()
    }

    fn line_kind(line: &str) -> String {
        let tag = "\"kind\":\"";
        if let Some(at) = line.find(tag) {
            let rest = &line[at + tag.len()..];
            if let Some(end) = rest.find('"') {
                return rest[..end].to_string();
            }
        }
        String::new()
    }

    fn kinds(events: &str) -> Vec<String> {
        events
            .lines()
            .filter_map(|line| {
                let k = line_kind(line);
                if k.is_empty() { None } else { Some(k) }
            })
            .collect()
    }

    /// Startup reads, interleaved dwell/ts pairs, latch, tail.
    ///
    /// Every dwell iteration fires, so each dwell timestamp
    /// appears twice: once for the loop's deadline read and
    /// once for the sample's own timestamp read. The fifth
    /// startup value feeds the attach-completion stamp and
    /// the sixth the readiness stamp; without them the
    /// dwell pairs would shift by one.
    fn clock_vals(dwells: &[u64]) -> Vec<u64> {
        let base = 1000000000u64;
        let mut out = vec![base, base + 1, base + 2, base + 3, base + 4, base + 4];
        for dwell in dwells {
            out.push(*dwell);
            out.push(*dwell);
        }
        let latch = base + 61000000001;
        out.push(latch);
        for i in 0..7 {
            out.push(latch + 1 + i);
        }
        out
    }

    struct TimerCase {
        exit_code: i64,
        end_reason: String,
        events: String,
        session: String,
    }

    fn run_timer_case(
        tmp: &TestDir,
        pool_root: &str,
        has_pool: bool,
        vals: Vec<u64>,
        step: u64,
        duration_s: u64,
        timeouts: i64,
    ) -> TimerCase {
        let cfg = CollectorConfig {
            duration_s,
            max_events_bytes: 134217728,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "pool-timer-probe".to_string(),
            pid: 4242,
            has_pool_sample: has_pool,
            pool_root: pool_root.to_string(),
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), timeouts);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        clock.step = step;
        for v in vals {
            clock.add(v);
        }
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        TimerCase {
            exit_code: result.exit_code,
            end_reason: result.end_reason,
            events: read_text(&format!("{}/cap/events.ndjson", tmp.as_str())),
            session: read_text(&format!("{}/cap/session.json", tmp.as_str())),
        }
    }

    #[test]
    fn periodic_cadence() {
        // The baseline persists at startup, then three dwell
        // iterations past the 1s cadence persist three
        // mid-stream samples ahead of the closing set: the file
        // stays chronological (baseline, periodic, final).
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let base = 1000000000u64;
        let dwells = vec![base + 1500000000, base + 2500000000, base + 3500000000];
        let c = run_timer_case(
            &tmp,
            &pool_fixture("debugfs-ok"),
            true,
            clock_vals(&dwells),
            1000000,
            60,
            120,
        );
        assert_eq!(c.exit_code, 0);
        assert_eq!(c.end_reason, "duration");
        let want = vec![
            "pool_sample",
            "pool_sample",
            "pool_sample",
            "pool_sample",
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
            "pool_sample",
        ];
        let got = kinds(&c.events);
        assert_eq!(got, want);
        // Fixture halves land on every sample, baseline first.
        assert_eq!(count_occurrences(&c.events, "\"used_bytes\":\"24576\""), 5);
        assert_eq!(
            count_occurrences(&c.events, "\"capacity_bytes\":\"67108864\""),
            5
        );
        assert_eq!(
            count_occurrences(&c.events, "\"pool_id\":\"swiotlb-default\""),
            5
        );
        // Periodic samples carry their scripted fire times.
        assert_eq!(count_occurrences(&c.events, "\"ts_ns\":\"2500000000\""), 1);
        assert_eq!(count_occurrences(&c.events, "\"ts_ns\":\"3500000000\""), 1);
        assert_eq!(count_occurrences(&c.events, "\"ts_ns\":\"4500000000\""), 1);
        assert!(c.session.contains("3 periodic samples"));
    }

    #[test]
    fn no_dwell_no_periodic() {
        // Without dwell the cadence never fires: the startup
        // baseline plus the closing final stand alone and the
        // session says zero.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let c = run_timer_case(
            &tmp,
            &pool_fixture("debugfs-ok"),
            true,
            clock_vals(&[]),
            1000000,
            60,
            120,
        );
        assert_eq!(c.exit_code, 0);
        assert_eq!(c.end_reason, "duration");
        let want = vec![
            "pool_sample",
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
            "pool_sample",
        ];
        assert_eq!(kinds(&c.events), want);
        assert!(c.session.contains("0 periodic samples"));
    }

    #[test]
    fn denied_periodic_unavailable() {
        // A denied used counter persists a null used half beside
        // live capacity mid-stream too; the run still succeeds,
        // stays partial, and names the first read failure.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let base = 1000000000u64;
        let dwells = vec![base + 1500000000, base + 2500000000];
        let c = run_timer_case(
            &tmp,
            &pool_fixture("debugfs-denied"),
            true,
            clock_vals(&dwells),
            1000000,
            60,
            120,
        );
        assert_eq!(c.exit_code, 0);
        assert_eq!(c.end_reason, "duration");
        assert_eq!(count_occurrences(&c.events, "\"kind\":\"pool_sample\""), 4);
        assert_eq!(count_occurrences(&c.events, "\"used_bytes\":null"), 4);
        assert_eq!(
            count_occurrences(&c.events, "\"capacity_bytes\":\"67108864\""),
            4
        );
        assert!(c.session.contains("2 periodic samples"));
        assert!(c.session.contains("first read failure: denied"));
    }

    #[test]
    fn no_pool_config_no_timer() {
        // Dwell without pool configuration samples nothing.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let base = 1000000000u64;
        let dwells = vec![base + 1500000000, base + 2500000000, base + 3500000000];
        let c = run_timer_case(
            &tmp,
            &pool_fixture("debugfs-ok"),
            false,
            clock_vals(&dwells),
            1000000,
            60,
            120,
        );
        assert_eq!(c.exit_code, 0);
        assert_eq!(c.end_reason, "duration");
        let want = vec![
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
            "counter_snapshot",
        ];
        assert_eq!(kinds(&c.events), want);
        assert!(c.session.contains("No pool source in this capture"));
    }

    fn capped_collector(pool_root: &str) -> Collector {
        let cfg = CollectorConfig {
            has_pool_sample: true,
            pool_root: pool_root.to_string(),
            ..Default::default()
        };
        let mut coll = Collector::new(cfg);
        coll.pool_periodic = 4096;
        coll.pool_periodic_capped = true;
        coll.pool_next_ts = 1000000000;
        coll
    }

    fn drive_tick(coll: &mut Collector, writer: &mut ScriptWriter, now: u64) -> String {
        let mut clock = ScriptClock::new();
        clock.add(now);
        coll.maybe_sample_pool(&mut clock, writer, now)
    }

    fn pool_writer(tmp: &TestDir) -> ScriptWriter {
        let mut writer = ScriptWriter::new();
        let created = writer.create(&format!("{}/events.ndjson", tmp.as_str()), 134217728);
        assert!(created.ok);
        writer
    }

    #[test]
    fn postcap_quiet_persists_nothing() {
        // Past the routine cap, quiet ticks keep reading on
        // the cadence but persist nothing: no post-cap count,
        // no appends, timer still advancing.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let mut coll = capped_collector(&pool_fixture("debugfs-ok"));
        let mut writer = pool_writer(&tmp);
        for i in 0..3 {
            let verdict = drive_tick(&mut coll, &mut writer, 1000000000 + i * 1000000000);
            assert_eq!(verdict, "");
        }
        assert_eq!(coll.pool_postcap, 0);
        assert_eq!(writer.appends, 0);
        assert_eq!(coll.pool_next_ts, 4000000000);
    }

    #[test]
    fn postcap_pressure_persists() {
        // Past the routine cap, pressurized ticks persist so
        // a pressure streak can still form on long captures.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let mut coll = capped_collector(&pool_fixture("debugfs-pressure"));
        let mut writer = pool_writer(&tmp);
        for i in 0..3 {
            let verdict = drive_tick(&mut coll, &mut writer, 1000000000 + i * 1000000000);
            assert_eq!(verdict, "");
        }
        assert_eq!(coll.pool_postcap, 3);
        assert_eq!(writer.appends, 3);
        assert!(!coll.pool_postcap_capped);
    }

    #[test]
    fn postcap_budget_exhausts() {
        // The post-cap budget is hard: a pressurized tick past
        // 64 latches exhaustion and persists nothing.
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let mut coll = capped_collector(&pool_fixture("debugfs-pressure"));
        coll.pool_postcap = 64;
        let mut writer = pool_writer(&tmp);
        let verdict = drive_tick(&mut coll, &mut writer, 1000000000);
        assert_eq!(verdict, "");
        assert_eq!(coll.pool_postcap, 64);
        assert_eq!(writer.appends, 0);
        assert!(coll.pool_postcap_capped);
    }

    #[test]
    fn postcap_session_note() {
        // The session reason names the thinning: routine stop,
        // post-cap count, exhaustion.
        let mut coll = capped_collector(&pool_fixture("debugfs-ok"));
        coll.pool_postcap = 2;
        coll.pool_ok = true;
        let session = coll.assemble().expect("assemble");
        let reason = session.cap_pool_stats.reason.clone();
        assert!(
            reason.contains("routine sampling stopped at 4096"),
            "{reason}"
        );
        assert!(
            reason.contains("2 pressurized samples persisted past the cap"),
            "{reason}"
        );
        coll.pool_postcap_capped = true;
        let session2 = coll.assemble().expect("assemble");
        assert!(
            session2
                .cap_pool_stats
                .reason
                .contains("post-cap budget exhausted"),
            "{}",
            session2.cap_pool_stats.reason
        );
    }

    #[test]
    fn checkpoint_after_one_thousand_committed_events() {
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let cfg = CollectorConfig {
            output: format!("{}/checkpoint-count", tmp.as_str()),
            profile_id: "checkpoint-count-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        for i in 0..1000 {
            kernel.add_poll(record_batch((i + 1) as u64, base + 4, 64), 1);
        }
        kernel.add_poll(err_poll(), 1);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        for offset in [0, 1, 2, 3, 4, 4] {
            clock.add(base + offset);
        }
        clock.step = 1;
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        assert_eq!(
            collector.startup(&mut kernel, &mut clock, &mut signal, &mut writer),
            ""
        );
        assert_eq!(
            collector.poll_loop(&mut kernel, &mut clock, &mut signal, &mut writer),
            "error-path"
        );
        assert_eq!(writer.checkpoint_calls, 2);
        let first = parse_session(&writer.first_checkpoint).expect("first");
        let last = parse_session(&writer.last_checkpoint).expect("last");
        assert_eq!(first.integrity.line_count, 0);
        assert_eq!(last.integrity.line_count, 1000);
        assert_eq!(last.checkpoint_generation, 2);
        assert!(last.window_end_ns - first.window_end_ns < 10000000000);
        assert_eq!(
            read_text(&format!("{}/checkpoint-count/events.ndjson", tmp.as_str()))
                .matches('\n')
                .count(),
            1000
        );
        assert_eq!(last.integrity.events_bytes, writer.committed_len());
        assert_eq!(writer.abandon(), "");
    }

    #[test]
    fn checkpoint_cadence_and_failure_counter() {
        let tmp = TestDir::create("memveil-pool-timer").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 35,
            output: format!("{}/checkpoint-cadence", tmp.as_str()),
            profile_id: "checkpoint-timer-probe".to_string(),
            pid: 4242,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        // 34 collecting polls, two draining polls, and 100 confirmation polls.
        kernel.add_poll(timeout_poll(), 136);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        for offset in [0, 1, 2, 3, 4, 4] {
            clock.add(base + offset);
        }
        for tick in 1..36 {
            clock.add(base + 4 + tick * 1000000000);
        }
        clock.step = 1;
        let mut signal = ScriptSignal::new();
        let mut writer = ScriptWriter::new();
        writer.checkpoint_fail_at = 2;
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.outcome, "finalized");
        assert_eq!(writer.checkpoint_calls, 4);
        let first = parse_session(&writer.first_checkpoint).expect("first");
        let last = parse_session(&writer.last_checkpoint).expect("last");
        assert_eq!(first.integrity.line_count, 0);
        assert_eq!(first.checkpoint_generation, 1);
        assert_eq!(last.checkpoint_generation, 4);
        assert_eq!(last.window_end_ns - first.window_end_ns, 30000000000);
        assert_eq!(last.stop.checkpoint_failures, 1);
        let final_text = read_text(&format!("{}/checkpoint-cadence/session.json", tmp.as_str()));
        let final_parsed = parse_session(final_text.as_bytes()).expect("final");
        assert_eq!(final_parsed.stop.checkpoint_failures, 1);
    }

    #[test]
    fn checkpoint_generation_exhaustion_refuses() {
        // A checkpoint at generation u64::MAX refuses without
        // touching the writer and counts one failure.
        let mut collector = Collector::new(CollectorConfig::default());
        collector.checkpoint_generation = u64::MAX;
        let mut writer = ScriptWriter::new();
        let note = collector.checkpoint(&mut writer, 1000000000);
        assert_eq!(note, "checkpoint generation exhausted");
        assert_eq!(collector.checkpoint_failures, 1);
        assert_eq!(collector.checkpoint_generation, u64::MAX);
        assert_eq!(writer.checkpoint_calls, 0);
    }

    #[test]
    fn evaluate_bridge_overflow_unfinalizable() {
        // A delivered-plus-staged sum past u64::MAX fails the
        // run closed ("unfinalizable") instead of trapping.
        let mut collector = Collector::new(CollectorConfig::default());
        collector.has_final_stats = true;
        collector.stats_start = stats_ok(0, 0, 0, 0, 0);
        collector.stats_final = stats_ok(u64::MAX, u64::MAX, 1, 0, 0);
        collector.persisted = u64::MAX;
        assert_eq!(collector.evaluate(), "unfinalizable");
    }

    #[test]
    fn submit_fail_total_checked() {
        // The cross-channel submit_fail sum refuses to wrap:
        // None on overflow (Mojo traps here), Some otherwise.
        let mut collector = Collector::new(CollectorConfig::default());
        collector.cfg.has_lifecycle = true;
        collector.has_end_cut = true;
        collector.has_end_cut_lc = true;
        collector.end_vals = cut5(u64::MAX, 0, 0, 0, u64::MAX);
        collector.end_vals_lc = cut5(u64::MAX, 0, 0, 0, u64::MAX);
        assert_eq!(collector.submit_fail_total(), None);
        collector.end_vals_lc = zero_cut();
        assert_eq!(collector.submit_fail_total(), Some(u64::MAX));
        collector.end_vals = zero_cut();
        assert_eq!(collector.submit_fail_total(), Some(0));
    }

    #[test]
    fn checked_detail_loss_overflows() {
        // The detail loss total is checked leg by leg: a
        // recursion count that overflows the submit sum voids
        // the total instead of wrapping it.
        let mut collector = Collector::new(CollectorConfig::default());
        collector.has_end_cut = true;
        collector.end_vals = cut5(1, 0, 0, 0, 1);
        collector.has_final_stats = true;
        collector.stats_start = stats_ok(0, 0, 0, 0, 0);
        collector.stats_final = stats_ok(0, 0, 0, 0, 0);
        collector.recursion_missed = u64::MAX;
        assert_eq!(collector.checked_detail_loss(), None);
        collector.recursion_missed = 41;
        assert_eq!(collector.checked_detail_loss(), Some((1, 42)));
    }

    #[test]
    fn submit_fail_overflow_voids_detail_loss() {
        // End to end: two saturated submit_fail legs keep every
        // other closure proof intact, so only the overflow voids
        // detail loss to unknown (pre-fix the sum wrapped to a
        // wrong-but-finite count).
        let tmp = TestDir::create("memveil-submit-overflow").expect("mkdtemp");
        let max = u64::MAX;
        let saturated = cut5(max, 0, 0, 0, max);
        let opts = RunOpts {
            channels: 2,
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            vec![],
            saturated.clone(),
            saturated,
            0,
            zero_cut(),
            0,
            &opts,
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("loss counters overflow"));
    }

    #[test]
    fn detail_leg_overflow_voids_detail_loss() {
        // End to end: a saturated recursion leg overflows an
        // otherwise exact detail total the same way.
        let tmp = TestDir::create("memveil-leg-overflow").expect("mkdtemp");
        let opts = RunOpts {
            channels: 1,
            misses: MissOut {
                ok: true,
                count: u64::MAX,
                ..Default::default()
            },
            misses2: MissOut {
                ok: true,
                count: u64::MAX,
                ..Default::default()
            },
            use_misses2: true,
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            vec![],
            cut5(1, 0, 0, 0, 1),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("loss counters overflow"));
    }

    struct ProbeOut {
        exit_code: i64,
        end_reason: String,
        outcome: String,
        diagnostic: String,
        events: String,
        session: String,
        polls_done: i64,
    }

    fn run_probe(
        tmp: &TestDir,
        kernel: &mut ScriptKernel,
        clock: ScriptClock,
        signal: ScriptSignal,
        budget: u64,
    ) -> ProbeOut {
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, budget));
        let mut clock = clock;
        let mut signal = signal;
        let result = collector.run(kernel, &mut clock, &mut signal, &mut writer);
        ProbeOut {
            exit_code: result.exit_code,
            end_reason: result.end_reason,
            outcome: result.outcome,
            diagnostic: result.diagnostic,
            events: read_text(&format!("{dir}/events.ndjson")),
            session: read_text(&format!("{dir}/session.json")),
            polls_done: kernel.polls_done,
        }
    }

    fn run_probe_dur(
        tmp: &TestDir,
        kernel: &mut ScriptKernel,
        clock: ScriptClock,
        signal: ScriptSignal,
        dur_s: u64,
    ) -> ProbeOut {
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut cfg = base_config(&dir, 134217728);
        cfg.duration_s = dur_s;
        let mut collector = Collector::new(cfg);
        let mut clock = clock;
        let mut signal = signal;
        let result = collector.run(kernel, &mut clock, &mut signal, &mut writer);
        ProbeOut {
            exit_code: result.exit_code,
            end_reason: result.end_reason,
            outcome: result.outcome,
            diagnostic: result.diagnostic,
            events: read_text(&format!("{dir}/events.ndjson")),
            session: read_text(&format!("{dir}/session.json")),
            polls_done: kernel.polls_done,
        }
    }

    #[test]
    fn probe_zero() {
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        zeros(&mut kernel, 5, 4);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.end_reason, "duration");
        assert_eq!(p.outcome, "finalized");
        assert_eq!(kinds(&p.events), vec!["counter_snapshot"; 4]);
        assert!(
            p.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\"")
        );
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\"")
        );
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_canary() {
        // Hostile device names: only PCI scope persists verbatim.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(
            batch_poll(attempt_payload(0, base + 10, 64, "0000:00:0c.0")),
            1,
        );
        kernel.add_poll(
            batch_poll(attempt_payload(1, base + 11, 64, "ffff888012345000")),
            1,
        );
        kernel.add_poll(
            batch_poll(attempt_payload(
                2,
                base + 12,
                64,
                "../../home/canary-alice/x",
            )),
            1,
        );
        let long_name = "A".repeat(70);
        kernel.add_poll(batch_poll(attempt_payload(3, base + 13, 64, &long_name)), 1);
        kernel.add_poll(batch_poll(attempt_payload(4, base + 14, 64, "eth0")), 1);
        kernel.add_poll(timeout_poll(), 110);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(5, 5, 0, 0, 0));
        }
        cuts(&mut kernel, 5, 320, 5, 320, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(12),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert_eq!(
            count_occurrences(&p.events, "\"kind\":\"bounce_attempt\""),
            5
        );
        // Only PCI scope persists verbatim in the catalog; nothing escapes.
        assert!(p.session.contains("\"name\":\"0000:00:0c.0\""));
        assert!(!p.events.contains("canary-alice"));
        assert!(!p.session.contains("canary-alice"));
        assert!(!p.events.contains("ffff888012345000"));
        assert!(!p.session.contains("ffff888012345000"));
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_attachwin() {
        // Attach-anchored window: a 20s init/attach gap must not
        // burn the 2s duration budget or backdate the window.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        clock.add(1000);
        clock.add(1001);
        clock.add(1002);
        clock.add(20000000000);
        clock.add(20000000000);
        clock.add(20000000000);
        clock.add(20000000001);
        clock.add(20000000002);
        clock.add(22000000001);
        for i in 0..7 {
            clock.add(22000000002 + i);
        }
        let p = run_probe_dur(&tmp, &mut kernel, clock, ScriptSignal::new(), 2);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.end_reason, "duration");
        assert!(p.session.contains("\"start_ns\":\"20000000000\""));
    }

    #[test]
    fn probe_stablen() {
        // End cut stabilizes on the second pair; values used.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        }
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zsnap.clone());
        kernel.add_snap(zsnap);
        kernel.add_snap(snap_ok(1, 64, 0, 0, 0, 0));
        let cut = snap_ok(1, 64, 1, 64, 0, 0);
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        // The stable end values archive, not the torn first read.
        assert_eq!(count_occurrences(&p.events, "\"value\":\"1\""), 1);
        assert_eq!(count_occurrences(&p.events, "\"value\":\"64\""), 1);
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_neverstable() {
        // End reads never agree: unresolved, unknown, exit 0.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        zeros(&mut kernel, 5, 2);
        let mut flip = true;
        for _ in 0..20 {
            if flip {
                kernel.add_snap(snap_ok(1, 0, 0, 0, 0, 0));
            } else {
                kernel.add_snap(snap_ok(0, 0, 0, 0, 0, 0));
            }
            flip = !flip;
        }
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("snapshot unresolved"));
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"unavailable\"")
        );
        assert!(p.session.contains("no stable cut"));
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 1);
    }

    #[test]
    fn probe_tornretry() {
        // End first read fails, retry pair agrees; values used.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        }
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zsnap.clone());
        kernel.add_snap(zsnap);
        kernel.add_snap(snap_err());
        let cut = snap_ok(1, 64, 1, 64, 0, 0);
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert_eq!(
            count_occurrences(&p.events, "\"kind\":\"counter_snapshot\""),
            4
        );
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_recvgt() {
        // Bridge received exceeds kernel emitted: unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(record_batch(1, base + 11, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..4 {
            kernel.add_stats(stats_ok(2, 2, 0, 0, 0));
        }
        cuts(&mut kernel, 2, 128, 1, 64, 1, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(4),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("ring count unproven"));
    }

    #[test]
    fn probe_confirmact() {
        // Confirm drain consumes a straggler: unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(timeout_poll(), 4);
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 99);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        for _ in 0..3 {
            kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        }
        kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        cuts(&mut kernel, 1, 0, 1, 0, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("post-snapshot activity"));
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 1);
    }

    #[test]
    fn probe_drainbudget() {
        // Drain clock jumps past budget: exhausted, unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 101);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        zeros(&mut kernel, 0, 4);
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 4);
        let latch = base + 61000000001;
        clock.add(latch);
        clock.add(latch + 1);
        clock.add(latch + 1);
        clock.add(latch + 2);
        clock.add(latch + 31000000002);
        clock.add(latch + 31000000003);
        clock.add(latch + 31000000004);
        clock.add(latch + 31000000005);
        let p = run_probe(&tmp, &mut kernel, clock, ScriptSignal::new(), 134217728);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("drain budget exhausted"));
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert!(s.stop.busy_at_drain);
    }

    #[test]
    fn probe_stopbudget() {
        // Close-out overruns the 5000 ms total: honest partial.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 200);
        let zstats = stats_ok(0, 0, 0, 0, 0);
        for _ in 0..5 {
            kernel.add_stats(zstats.clone());
        }
        zeros(&mut kernel, 0, 4);
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 4);
        let latch = base + 61000000001;
        clock.add(latch);
        clock.add(latch + 1);
        clock.add(latch + 1);
        clock.add(latch + 2);
        clock.add(latch + 6000000003);
        clock.add(latch + 6000000004);
        clock.add(latch + 6000000005);
        clock.add(latch + 6000000006);
        let p = run_probe(&tmp, &mut kernel, clock, ScriptSignal::new(), 134217728);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.stop.outcome, "partial");
        // Quiescence precedes the budget in finalize order; the
        // measured overrun rides beside the budget in elapsed_ms.
        assert_eq!(s.stop.reason, "quiescence unproven");
        assert!(s.stop.elapsed_ms > 5000);
        assert!(!s.stop.busy_at_drain);
    }

    #[test]
    fn probe_stuckdrain() {
        // Producer never stops: 100000-poll bound, busy, unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 100000);
        kernel.add_poll(timeout_poll(), 100);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        let flow = stats_ok(100000, 100000, 0, 0, 0);
        kernel.add_stats(flow.clone());
        kernel.add_stats(flow);
        cuts(&mut kernel, 100000, 0, 100000, 0, 0, 0);
        let mut clock = ScriptClock::new();
        clock.step = 0;
        for i in 0..4 {
            clock.add(base + i);
        }
        clock.add(base + 4);
        clock.add(base + 4);
        for i in 4..8 {
            clock.add(base + i);
        }
        let p = run_probe_dur(&tmp, &mut kernel, clock, ScriptSignal::new(), 0);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("drain budget exhausted"));
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.stop.drained_records, 100000);
        assert!(s.stop.busy_at_drain);
    }

    #[test]
    fn probe_stageddrain() {
        // Five records stuck staged at final: busy, error shutdown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 200);
        let zstats = stats_ok(0, 0, 0, 0, 0);
        for _ in 0..3 {
            kernel.add_stats(zstats.clone());
        }
        let stuck = stats_ok(5, 0, 5, 0, 0);
        kernel.add_stats(stuck.clone());
        kernel.add_stats(stuck);
        cuts(&mut kernel, 0, 0, 0, 0, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert!(s.stop.busy_at_drain);
        assert!(p.session.contains("error shutdown"));
    }

    #[test]
    fn probe_delaysubmit() {
        // Submit-fail increment lands mid-protocol; cut exact.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zsnap.clone());
        kernel.add_snap(zsnap);
        kernel.add_snap(snap_ok(1, 64, 0, 0, 0, 0));
        let cut = snap_ok(1, 64, 0, 0, 1, 0);
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("detail loss 1 (submit_fail=(1)"));
    }

    #[test]
    fn probe_latesubmit() {
        // Submit increment lands after the cut: identity breaks.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 2, 128, 1, 64, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("kernel identity unproven"));
    }

    #[test]
    fn probe_lateemit() {
        // Emit increment lands after the cut: identity breaks.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(record_batch(1, base + 11, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 2, 2);
        cuts(&mut kernel, 3, 192, 2, 128, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(4),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("kernel identity unproven"));
    }

    #[test]
    fn probe_wrapobs() {
        // OBSERVED_WRAP seeded: epoch invalid, detail unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 6, 320, 0, 0, 1, 1);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("invalid epoch"));
    }

    #[test]
    fn probe_wrapemit() {
        // EMITTED_WRAP seeded: epoch invalid, detail unknown.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 1, 64, 9, 64, 1, 4);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("invalid epoch"));
    }

    #[test]
    fn probe_wrapsubmit() {
        // SUBMIT_WRAP seeded: submit_fail renders unavailable.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 1, 64, 0, 0, 13, 16);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("invalid epoch"));
        assert!(p.session.contains("submit_fail=(unavailable)"));
    }

    #[test]
    fn probe_wrapobsbytes() {
        // OBSERVED_BYTES_WRAP: bytes invalid, detail stays exact.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 1, 500, 0, 0, 1, 2);
        // OBSERVED_BYTES_WRAP: exact (known) detail with the submit-fail counted.
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("detail loss 1 (submit_fail=(1)"));
        assert!(
            p.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"1\",")
        );
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"unavailable\"")
        );
    }

    #[test]
    fn probe_wrapemitbytes() {
        // EMITTED_BYTES_WRAP: bytes invalid, detail stays exact.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 1, 64, 0, 400, 1, 8);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(
            p.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"1\",")
        );
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"unavailable\"")
        );
    }

    #[test]
    fn probe_bytecov() {
        // BYTE_COVERAGE seeded: aggregate unavailable, no gap.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 1, 41, 0, 0, 1, 32);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("detail loss 1 (submit_fail=(1)"));
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"unavailable\"")
        );
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 0);
    }

    #[test]
    fn probe_recoverable() {
        // Known combo: malformed + dropped + omitted + rejected.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(bad_utf8_batch(1, base + 11, 32), 1);
        kernel.add_poll(timeout_poll(), 1);
        kernel.add_poll(record_batch(99, base + 12, 48), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow_md(&mut kernel, 5, 3, 1, 1);
        cuts(&mut kernel, 5, 144, 5, 144, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(5),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        // The third batch arrives after the duration latch and
        // drains as omitted: 1 malformed + 1 dropped + 1 omitted
        // + 1 rejected.
        assert!(p.session.contains("detail loss 4 (submit_fail=(0)"));
        assert!(p.session.contains("malformed=(1)"));
        assert!(p.session.contains("dropped=(1)"));
        assert!(p.session.contains("duration_omitted=(1)"));
        assert!(p.session.contains("rejected=(1)"));
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_appendfail0() {
        // First attempt append fails: error path, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        err_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        writer.append_faults.push(AppendFault {
            at: 1,
            kind: "error".to_string(),
        });
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(2);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.end_reason, "error");
        assert_eq!(result.outcome, "error");
    }

    #[test]
    fn probe_appendtorn() {
        // Second append fails: retained prefix + gap, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(record_batch(1, base + 11, 64), 1);
        err_flow(&mut kernel, 2, 2);
        cuts(&mut kernel, 2, 128, 2, 128, 0, 0);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        writer.append_faults.push(AppendFault {
            at: 2,
            kind: "error".to_string(),
        });
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(4);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.end_reason, "error");
        let events = read_text(&format!("{dir}/events.ndjson"));
        assert_eq!(count_occurrences(&events, "\"kind\":\"bounce_attempt\""), 1);
        assert_eq!(count_occurrences(&events, "\"kind\":\"gap\""), 1);
    }

    #[test]
    fn probe_catalogfull() {
        // 4097th distinct device: exhaustion, error path.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        for i in 0..4097 {
            kernel.add_poll(
                batch_poll(attempt_payload(i as u64, base + 10, 64, &format!("dev{i}"))),
                1,
            );
        }
        err_flow(&mut kernel, 4097, 4097);
        cuts(&mut kernel, 4097, 262208, 4097, 262208, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(8194),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
        assert_eq!(p.outcome, "error");
    }

    #[test]
    fn probe_hardpoll() {
        // Hard poll error with staged=1 observed, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(err_poll(), 1);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(2, 1, 1, 0, 0));
        cuts(&mut kernel, 2, 128, 2, 128, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(3),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 1);
    }

    #[test]
    fn probe_structfault() {
        // Short frame: structure fault, error path, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(short_frame_batch(), 1);
        err_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(1),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
    }

    #[test]
    fn probe_structfaultq() {
        // Fault first, good record queued: never polled.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(short_frame_batch(), 1);
        kernel.add_poll(record_batch(1, base + 11, 64), 1);
        err_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(1),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.polls_done, 1);
    }

    #[test]
    fn probe_durhard() {
        // Duration latch, then drain hard error: exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(timeout_poll(), 2);
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(err_poll(), 1);
        kernel.add_poll(timeout_poll(), 100);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        cuts(&mut kernel, 1, 0, 1, 0, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
        assert_eq!(p.outcome, "error");
    }

    #[test]
    fn probe_sigclose() {
        // Signal latch, then drain hard error: exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(err_poll(), 1);
        kernel.add_poll(timeout_poll(), 100);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        kernel.add_stats(stats_ok(1, 1, 0, 0, 0));
        cuts(&mut kernel, 1, 0, 1, 0, 0, 0);
        let mut signal = ScriptSignal::new();
        signal.add("pending");
        let p = run_probe(&tmp, &mut kernel, std_clock(0), signal, 134217728);
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
    }

    #[test]
    fn probe_errdetfail() {
        // Collection error + detach failure: detach primary.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.detach_out = OpOut {
            ok: false,
            message: "scripted detach failure".to_string(),
        };
        kernel.add_poll(short_frame_batch(), 1);
        err_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(1),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert!(
            p.session
                .contains("detach failed; shutdown evidence unresolved")
        );
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert_eq!(s.stop.reason, "admission close failed");
    }

    #[test]
    fn probe_combinederr() {
        // Error + detach failure + unresolved snap.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.detach_out = OpOut {
            ok: false,
            message: "scripted detach failure".to_string(),
        };
        kernel.add_poll(short_frame_batch(), 1);
        err_flow(&mut kernel, 1, 1);
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        kernel.add_snap(zsnap.clone());
        kernel.add_snap(zsnap.clone());
        let mut flip = true;
        for _ in 0..20 {
            if flip {
                kernel.add_snap(snap_ok(1, 0, 0, 0, 0, 0));
            } else {
                kernel.add_snap(zsnap.clone());
            }
            flip = !flip;
        }
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(1),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, EXIT_ERROR);
        // First deviation wins; the unresolved snap is retained beside it.
        assert!(
            p.session
                .contains("detach failed; shutdown evidence unresolved")
        );
        assert!(p.session.contains("snapshot unresolved"));
    }

    #[test]
    fn probe_siginhand() {
        // Signal trips with a record in hand: omitted, exit 0.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let mut signal = ScriptSignal::new();
        signal.add("none");
        signal.add("pending");
        let p = run_probe(&tmp, &mut kernel, std_clock(2), signal, 134217728);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.end_reason, "signal");
        assert_eq!(p.outcome, "finalized");
        assert!(p.session.contains("signal_omitted=(1)"));
    }

    #[test]
    fn probe_sigreaderr() {
        // Signal read error in hand: error state, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 1, 64, 1, 64, 0, 0);
        let mut signal = ScriptSignal::new();
        signal.add("none");
        signal.add_error("scripted EIO");
        let p = run_probe(&tmp, &mut kernel, std_clock(2), signal, 134217728);
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(p.end_reason, "error");
        assert!(p.diagnostic.contains("scripted EIO"));
    }

    #[test]
    fn probe_sigreaderr0() {
        // Signal read error before any poll: exit 1, no gap.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 0, 0, 0, 0, 0, 0);
        let mut signal = ScriptSignal::new();
        signal.add_error("scripted EIO");
        let p = run_probe(&tmp, &mut kernel, std_clock(0), signal, 134217728);
        assert_eq!(p.exit_code, EXIT_ERROR);
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 0);
    }

    #[test]
    fn probe_sigsetupfail() {
        // Signal setup fails: refusal, exit 3, no output.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let mut signal = ScriptSignal::new();
        signal.setup_out = OpOut {
            ok: false,
            message: "scripted mask failure".to_string(),
        };
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(0);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.outcome, "refused");
        assert!(result.diagnostic.contains("signal setup"));
        assert!(!std::path::Path::new(&dir).exists());
    }

    #[test]
    fn probe_sigsetuprollback() {
        // Setup fails and close fails: residual, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.close_out = OpOut {
            ok: false,
            message: "scripted close failure".to_string(),
        };
        let mut signal = ScriptSignal::new();
        signal.setup_out = OpOut {
            ok: false,
            message: "scripted mask failure".to_string(),
        };
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(0);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.outcome, "refusal-rollback-failed");
        assert!(result.diagnostic.contains("scripted close failure"));
    }

    #[test]
    fn probe_attachfail() {
        // Attach fails: refusal, exit 3, dir gone.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.attach_out = OpOut {
            ok: false,
            message: "scripted attach failure".to_string(),
        };
        zeros(&mut kernel, 1, 2);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(0);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.outcome, "refused");
        assert!(!std::path::Path::new(&dir).exists());
    }

    #[test]
    fn probe_rollbackfail() {
        // Attach fails and close fails: residual, exit 1.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.attach_out = OpOut {
            ok: false,
            message: "scripted attach failure".to_string(),
        };
        kernel.close_out = OpOut {
            ok: false,
            message: "scripted close failure".to_string(),
        };
        zeros(&mut kernel, 1, 2);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(0);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.outcome, "refusal-rollback-failed");
    }

    #[test]
    fn probe_nonzerostart() {
        // Stable but nonzero start: refusal, exit 3.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let cut = snap_ok(1, 0, 0, 0, 0, 0);
        kernel.add_snap(cut.clone());
        kernel.add_snap(cut);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(0);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("start snapshot nonzero"));
    }

    #[test]
    fn probe_clockseam() {
        // End-pair timestamp jump: end_ns derives past it.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        let zsnap = snap_ok(0, 0, 0, 0, 0, 0);
        for _ in 0..4 {
            kernel.add_snap(zsnap.clone());
        }
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 5);
        let latch = base + 61000000001;
        clock.add(latch);
        clock.add(latch + 1);
        clock.add(latch + 1);
        clock.add(latch + 2);
        clock.add(latch + 3);
        clock.add(latch + 4);
        clock.add(latch + 5);
        clock.add(latch + 5000000000);
        clock.add(latch + 6);
        let p = run_probe(&tmp, &mut kernel, clock, ScriptSignal::new(), 134217728);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        let s = stop_session(&format!("{}/cap", tmp.as_str()));
        assert!(s.window_end_ns > latch + 5000000000);
    }

    #[test]
    fn probe_ooo100() {
        // Out-of-order stamps past the cut: advance succeeds.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        let latch = base + 61000000001;
        let bent = latch + 5 + 1 + 100000000;
        kernel.add_poll(record_batch(0, bent + 50, 64), 1);
        kernel.add_poll(record_batch(1, bent + 10, 64), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 2, 2);
        cuts(&mut kernel, 2, 128, 2, 128, 0, 0);
        let mut clock = ScriptClock::new();
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 4);
        clock.add(base + 5);
        clock.add(base + 6);
        clock.add(base + 7);
        clock.add(latch);
        let tail = latch + 5;
        clock.add(latch + 1);
        clock.add(latch + 1);
        clock.add(latch + 2);
        clock.add(latch + 3);
        clock.add(latch + 4);
        clock.add(tail);
        clock.add(tail + 1);
        clock.add(tail + 2);
        clock.add(tail + 60);
        clock.add(tail + 61);
        let p = run_probe(&tmp, &mut kernel, clock, ScriptSignal::new(), 134217728);
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.outcome, "finalized");
        check_integrity(&p.events, &p.session);
    }

    #[test]
    fn probe_sizerefused() {
        // Budget refusal trips the size latch; capture replays.
        use crate::capture::reader::{default_limits, read_capture};
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.seq_patch = true;
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 64), 190);
        kernel.add_poll(timeout_poll(), 102);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        let flow = stats_ok(190, 190, 0, 0, 0);
        for _ in 0..4 {
            kernel.add_stats(flow.clone());
        }
        cuts(&mut kernel, 190, 12160, 190, 12160, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(380),
            ScriptSignal::new(),
            131072,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.end_reason, "size_limit");
        assert_eq!(p.outcome, "finalized");
        let dir = format!("{}/cap", tmp.as_str());
        let replay = read_capture(&dir, false, default_limits());
        assert!(replay.is_ok());
    }

    #[test]
    fn probe_pausedbytes() {
        // Paused-before-byte-update cut: identity breaks.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, 6), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 1, 1);
        cuts(&mut kernel, 2, 10, 1, 6, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("kernel identity unproven"));
    }

    #[test]
    fn probe_u64sum() {
        // MAX then 1 byte: sum guard omits + latches.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 10, u64::MAX), 1);
        kernel.add_poll(record_batch(1, base + 11, 1), 1);
        kernel.add_poll(timeout_poll(), 102);
        steady_flow(&mut kernel, 2, 2);
        cuts(&mut kernel, 2, u64::MAX, 2, u64::MAX, 0, 0);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(4),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert_eq!(p.end_reason, "size_limit");
        assert_eq!(
            count_occurrences(&p.events, "\"kind\":\"bounce_attempt\""),
            1
        );
    }

    #[test]
    fn probe_flowinject() {
        // Counter-flow simulator cut O=2,S=2,E=0+BYTE_COVERAGE.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        steady_flow(&mut kernel, 0, 0);
        cuts(&mut kernel, 2, 0, 0, 0, 2, 32);
        let p = run_probe(
            &tmp,
            &mut kernel,
            std_clock(2),
            ScriptSignal::new(),
            134217728,
        );
        assert_eq!(p.exit_code, 0);
        assert!(p.session.contains("detail loss 2 (submit_fail=(2)"));
        assert!(
            p.session
                .contains("\"aggregate\":{\"status\":\"unavailable\"")
        );
        assert_eq!(count_occurrences(&p.events, "\"kind\":\"gap\""), 0);
    }

    #[test]
    fn probe_unsynced() {
        // Finalize reports present_unsynced: exit 1, files kept.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        zeros(&mut kernel, 5, 4);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        writer.finalize_status = "present_unsynced".to_string();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut clock = std_clock(2);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_ERROR);
        assert_eq!(result.outcome, "present_unsynced");
        assert!(std::path::Path::new(&format!("{dir}/events.ndjson")).exists());
    }

    #[test]
    fn probe_pool() {
        // Pool baseline + final around a quiet capture.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 104);
        zeros(&mut kernel, 5, 4);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut cfg = base_config(&dir, 134217728);
        cfg.has_pool_sample = true;
        cfg.pool_root = pool_fixture("debugfs-ok");
        let mut collector = Collector::new(cfg);
        let mut clock = std_clock(2);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, 0);
        let events = read_text(&format!("{dir}/events.ndjson"));
        assert_eq!(count_occurrences(&events, "\"kind\":\"pool_sample\""), 2);
    }

    #[test]
    fn probe_poolcap() {
        // Long capture stops routine sampling at 4096 with a note.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 10000);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 3);
        clock.add(base + 3);
        clock.step = 1000000000;
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut cfg = base_config(&dir, 134217728);
        cfg.duration_s = 9000;
        cfg.has_pool_sample = true;
        cfg.pool_root = pool_fixture("debugfs-ok");
        let mut collector = Collector::new(cfg);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, 0);
        let session = read_text(&format!("{dir}/session.json"));
        assert!(session.contains("routine sampling stopped at 4096"));
        assert!(session.contains("quiet ticks past the cap persist nothing"));
        let events = read_text(&format!("{dir}/events.ndjson"));
        assert_eq!(events.lines().count(), 1 + 4096 + 4 + 1);
    }

    #[test]
    fn probe_poolpressure() {
        // Pressurized ticks persist past the cap to the 64 budget.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        kernel.add_poll(timeout_poll(), 10000);
        zeros(&mut kernel, 5, 4);
        let mut clock = ScriptClock::new();
        let base = 1000000000u64;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        clock.add(base + 3);
        clock.add(base + 3);
        clock.step = 1000000000;
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = ScriptWriter::new();
        let mut cfg = base_config(&dir, 134217728);
        cfg.duration_s = 9000;
        cfg.has_pool_sample = true;
        cfg.pool_root = pool_fixture("debugfs-pressure");
        let mut collector = Collector::new(cfg);
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, 0);
        let session = read_text(&format!("{dir}/session.json"));
        assert!(session.contains("routine sampling stopped at 4096"));
        assert!(session.contains("64 pressurized samples persisted past the cap"));
        assert!(session.contains("post-cap budget exhausted"));
        let events = read_text(&format!("{dir}/events.ndjson"));
        assert_eq!(events.lines().count(), 1 + 4096 + 64 + 4 + 1);
    }
    fn misses_of(count: u64, attempt: u64) -> MissOut {
        MissOut {
            ok: true,
            count,
            attempt,
            ..Default::default()
        }
    }

    fn misses_err(message: &str) -> MissOut {
        MissOut {
            ok: false,
            message: message.to_string(),
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn detail_misses8(
        bounce: u64,
        exit_misses: u64,
        sync_device: u64,
        sync_cpu: u64,
        lc_map: u64,
        lc_unmap: u64,
        deferred: u64,
        recovered: u64,
        attempt: u64,
    ) -> MissOut {
        MissOut {
            ok: true,
            count: 0,
            attempt,
            has_copy_detail: true,
            bounce,
            exit_misses,
            sync_device,
            sync_cpu,
            lc_map,
            lc_unmap,
            deferred,
            recovered,
            ..Default::default()
        }
    }

    fn detail_misses3(bounce: u64, deferred: u64, recovered: u64) -> MissOut {
        detail_misses8(bounce, 0, 0, 0, 0, 0, deferred, recovered, 0)
    }

    fn stable_detail() -> MissOut {
        detail_misses8(100, 3, 0, 0, 0, 0, 10, 110, 0)
    }

    fn detail_failed(attempt: u64, reason: &str) -> MissOut {
        MissOut {
            ok: true,
            attempt,
            detail_error: reason.to_string(),
            ..Default::default()
        }
    }

    fn bad37() -> Vec<u8> {
        vec![0u8; 37]
    }

    fn one_copy_run(tmp: &TestDir, misses: MissOut) -> super::script::CaseOut {
        one_copy_run_opts(tmp, misses, MissOut::default(), false, &RunOpts::default())
    }

    fn one_copy_run_opts(
        tmp: &TestDir,
        misses: MissOut,
        misses2: MissOut,
        use_misses2: bool,
        base: &RunOpts,
    ) -> super::script::CaseOut {
        let opts = RunOpts {
            misses,
            misses2,
            use_misses2,
            timeouts: base.timeouts,
            confirm_poll_err: base.confirm_poll_err,
            fail_confirm_stats: base.fail_confirm_stats,
            lower_bound: base.lower_bound,
            strict: base.strict,
            grade: base.grade.clone(),
            ..RunOpts::default()
        };
        run_case(
            tmp.as_str(),
            vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)],
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &opts,
        )
    }

    fn error_copy_run(tmp: &TestDir, misses: MissOut) -> super::script::CaseOut {
        error_copy_run_opts(tmp, misses, MissOut::default(), false)
    }

    fn error_copy_run_opts(
        tmp: &TestDir,
        misses: MissOut,
        misses2: MissOut,
        use_misses2: bool,
    ) -> super::script::CaseOut {
        let opts = RunOpts {
            misses,
            misses2,
            use_misses2,
            ..RunOpts::default()
        };
        run_case(
            tmp.as_str(),
            vec![bad37()],
            cut(1, 37, 1, 37),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        )
    }

    fn one_attempt_run_opts(
        tmp: &TestDir,
        misses: MissOut,
        misses2: MissOut,
        use_misses2: bool,
    ) -> super::script::CaseOut {
        let opts = RunOpts {
            misses,
            misses2,
            use_misses2,
            channels: 1,
            ..RunOpts::default()
        };
        run_case(
            tmp.as_str(),
            vec![],
            zero_cut(),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        )
    }

    fn one_lc_run(tmp: &TestDir, misses: MissOut) -> super::script::CaseOut {
        one_lc_run_opts(tmp, misses, MissOut::default(), false)
    }

    fn one_lc_run_opts(
        tmp: &TestDir,
        misses: MissOut,
        misses2: MissOut,
        use_misses2: bool,
    ) -> super::script::CaseOut {
        let opts = RunOpts {
            misses,
            misses2,
            use_misses2,
            channels: 2,
            ..RunOpts::default()
        };
        run_case(
            tmp.as_str(),
            vec![lc_raw(1, 1, 1, 121, 1021, 4096, 41)],
            zero_cut(),
            cut(1, 4096, 1, 4096),
            1,
            zero_cut(),
            0,
            &opts,
        )
    }

    fn error_lc_run(tmp: &TestDir, misses: MissOut) -> super::script::CaseOut {
        error_lc_run_opts(tmp, misses, MissOut::default(), false)
    }

    fn error_lc_run_opts(
        tmp: &TestDir,
        misses: MissOut,
        misses2: MissOut,
        use_misses2: bool,
    ) -> super::script::CaseOut {
        let opts = RunOpts {
            misses,
            misses2,
            use_misses2,
            channels: 2,
            ..RunOpts::default()
        };
        run_case(
            tmp.as_str(),
            vec![bad37()],
            cut(1, 37, 1, 37),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        )
    }

    fn run_copy_liveness(
        tmp: &TestDir,
        n_cp: i64,
        cut_cp: u64,
        misses: MissOut,
    ) -> super::script::CaseOut {
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..100 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                9100 + i,
                attach + i * 30000000,
                4096,
                9100 + i,
            ));
        }
        for i in 0..n_cp {
            payloads.push(cp_raw(
                2,
                3,
                1,
                9300 + i as u64,
                attach + i as u64 * 30000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses,
            ..LiveOpts::default()
        };
        run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut(cut_cp, cut_cp * 4096, cut_cp, cut_cp * 4096),
            cut_cp,
            &opts,
        )
    }

    #[test]
    fn nested_copies() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0),
            cp_raw(2, 3, 1, 102, 1002, 1024, 1024, 0),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(2, 5120, 2, 5120),
            2,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.end_reason, "signal");
        assert_eq!(c.outcome, "finalized");
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("\"kind\":\"copy\""));
        assert!(lines[0].contains("\"operation_id\":\"lc-101\""));
        assert!(lines[1].contains("\"operation_id\":\"lc-102\""));
    }

    #[test]
    fn admitted_caps_carry_grade() {
        // The admission grade lands on every qualified
        // channel (bounce, lifecycle, copy, sync) and on no
        // auxiliary one (pool, conversion, region, task).
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(1, 1, 1, 201, 2001, 4096, 0, 4)];
        let opts = RunOpts {
            grade: "local-auto".to_string(),
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &opts,
        );
        let s = parse_session(c.session.as_bytes()).expect("parse");
        assert!(s.cap_bounce_attempts.has_grade);
        assert_eq!(s.cap_bounce_attempts.grade, "local-auto");
        assert!(s.cap_mapping_lifecycle.has_grade);
        assert_eq!(s.cap_mapping_lifecycle.grade, "local-auto");
        assert!(s.cap_copy_bytes.has_grade);
        assert_eq!(s.cap_copy_bytes.grade, "local-auto");
        assert!(s.cap_sync_requests.has_grade);
        assert_eq!(s.cap_sync_requests.grade, "local-auto");
        assert!(!s.cap_pool_stats.has_grade);
        assert!(!s.cap_conversion_results.has_grade);
        assert!(!s.cap_region_state.has_grade);
        assert!(!s.cap_task_context.has_grade);
    }

    #[test]
    fn clamped_copy_keeps_effective() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(2, 7, 1, 211, 2011, 4096, 1024, 0)];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 5);
        // Requested bytes stay in the aggregate counters only;
        // the event carries the executed 1024.
        assert!(lines[0].contains("\"bytes\":\"1024\""));
        assert!(!lines[0].contains("4096"));
    }

    #[test]
    fn early_zero_persists_proved_zero() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(2, 10, 2, 221, 2021, 512, 0, 0)];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 512, 1, 512),
            1,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 5);
        assert!(lines[0].contains("\"kind\":\"copy\""));
        assert!(lines[0].contains("\"bytes\":\"0\""));
        assert!(lines[0].contains("\"direction\":\"bounce_to_original\""));
    }

    #[test]
    fn reuse_reports_distinct_ids() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            lc_raw(1, 1, 1, 121, 1021, 4096, 41),
            lc_raw(1, 1, 1, 122, 1022, 4096, 42),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            cut(2, 8192, 2, 8192),
            2,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 6);
        assert!(lines[0].contains("\"mapping_id\":\"gen-41\""));
        assert!(lines[1].contains("\"mapping_id\":\"gen-42\""));
        assert!(lines[0].contains("\"correlation\":\"direct\""));
        assert!(lines[1].contains("\"correlation\":\"direct\""));
    }

    #[test]
    fn unknown_copy_drops_as_rejected() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(2, 0, 1, 231, 2031, 4096, 0, 1)];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &RunOpts::default(),
        );
        // Known loss: the delivered record is counted, never
        // persisted, and the capture still finalizes.
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.outcome, "finalized");
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(!c.events.contains("\"kind\":\"copy\""));
        assert!(c.session.contains("detail loss 1 (submit_fail=(0)"));
        assert!(c.session.contains("rejected=(1)"));
        assert!(c.session.contains("first unknown copy: SLOT_READ"));
    }

    #[test]
    fn unknown_copies_counted_per_reason() {
        // Each unknown copy charges its wire reason; the detail names the first.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let reasons = [5u64, 6, 5, 1, 2, 3];
        let mut payloads = Vec::new();
        for (i, reason) in reasons.iter().enumerate() {
            payloads.push(cp_raw(
                2,
                0,
                2,
                240 + i as u64,
                2040 + i as u64,
                4096,
                0,
                *reason,
            ));
        }
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(6, 24576, 6, 24576),
            6,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert!(!c.events.contains("\"kind\":\"copy\""));
        assert!(c.session.contains("detail loss 6 (submit_fail=(0)"));
        assert!(c.session.contains("rejected=(6)"));
        assert!(c.session.contains("first unknown copy: LAYOUT"));
        assert!(
            c.session
                .contains("\"source\":\"copy.unknown_layout\",\"interpretation\":\"2\"")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.unknown_shift\",\"interpretation\":\"1\"")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.unknown_slot_read\",\"interpretation\":\"1\"")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.unknown_mask_read\",\"interpretation\":\"1\"")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.unknown_bounds\",\"interpretation\":\"1\"")
        );
    }

    #[test]
    fn recursion_misses_are_detail_loss() {
        // Kernel-skipped program runs never reach a ring; they
        // are loss, so a clean ring with misses is not complete.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(5, 0));
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 5 (submit_fail=(0)"));
        assert!(c.session.contains("recursion_missed=(5)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"5\",")
        );
        assert!(
            c.session
                .contains("channels attempt:(submit_fail=0 malformed=0 dropped=0)")
        );
    }

    #[test]
    fn detail_loss_names_its_channel() {
        // Per-channel transport loss rides in a channels suffix
        // after the pooled pairs; the pooled totals stay first.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)];
        let opts = RunOpts {
            ch2mal: 1,
            ch2drop: 2,
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut5(7, 28672, 4, 16384, 3),
            1,
            &opts,
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 6 (submit_fail=(3)"));
        assert!(c.session.contains("malformed=(1)"));
        assert!(c.session.contains("dropped=(2)"));
        assert!(
            c.session
                .contains("copy:(submit_fail=3 malformed=1 dropped=2)")
        );
    }

    #[test]
    fn strict_close_out_exits_partial() {
        // Finalized partial verdicts exit 0 normally; strict
        // restores exit 4 for the same close-out.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mk = || vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)];
        let plain = run_case(
            tmp.as_str(),
            mk(),
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &RunOpts::default(),
        );
        assert_eq!(plain.exit_code, EXIT_OK);
        let tmp2 = TestDir::create("memveil-lc").expect("mkdtemp");
        let opts = RunOpts {
            strict: true,
            ..RunOpts::default()
        };
        let strict = run_case(
            tmp2.as_str(),
            mk(),
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &opts,
        );
        assert_eq!(strict.exit_code, EXIT_PARTIAL);
    }

    #[test]
    fn identity_budget_latches_gate() {
        // The gate stops while the costliest next record (a map
        // plus its mapping, cost 2) still fits under the
        // reader-mirroring identity budget.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 1073741824,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "test-profile-1".to_string(),
            pid: 7,
            ..Default::default()
        };
        let mut collector = Collector::new(cfg.clone());
        collector.persisted_attempt = 4194302;
        let mut clock = ScriptClock::new();
        clock.add(0);
        let mut signal = ScriptSignal::new();
        signal.add("none");
        assert_eq!(
            collector.gate(&mut clock, &mut signal, 60000000000),
            "closed"
        );
        assert_eq!(collector.stop_reason, "size_limit");
        let mut collector2 = Collector::new(cfg);
        collector2.persisted_map = 2097150;
        collector2.persisted_map_ok = 2097150;
        let mut clock2 = ScriptClock::new();
        clock2.add(0);
        let mut signal2 = ScriptSignal::new();
        signal2.add("none");
        assert_eq!(collector2.gate(&mut clock2, &mut signal2, 60000000000), "");
    }

    #[test]
    fn zero_recursion_misses_stay_complete() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(0, 0));
        assert!(c.session.contains("detail loss 0 (submit_fail=(0)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
    }

    #[test]
    fn unreadable_recursion_misses_make_loss_unknown() {
        // An unreadable count can never be reported as zero.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_err("fdinfo gone"));
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("detail loss unknown (recursion misses unreadable: fdinfo gone")
        );
        assert!(c.session.contains("recursion_missed=(unavailable)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn attempt_misses_make_aggregate_partial() {
        // Skipped attempt runs never advance the aggregate counters.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(5, 3));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("attempt program runs skipped 3 (recursion)")
        );
    }

    #[test]
    fn attempt_loss_lower_bound_labels_aggregate() {
        // Kernels before 6.7 skip programs in trace_call_bpf
        // without counting them: a claimed aggregate count is
        // a lower bound there and the reason says so.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mk = || vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)];
        let c = run_case(
            tmp.as_str(),
            mk(),
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &RunOpts {
                misses: misses_of(5, 3),
                lower_bound: true,
                ..RunOpts::default()
            },
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("attempt loss counts are a lower bound before 6.7")
        );
        let tmp2 = TestDir::create("memveil-lc").expect("mkdtemp");
        let zero = run_case(
            tmp2.as_str(),
            mk(),
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &RunOpts {
                misses: misses_of(5, 0),
                lower_bound: true,
                ..RunOpts::default()
            },
        );
        assert!(
            zero.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"0\",")
        );
        assert!(
            zero.session
                .contains("attempt loss counts are a lower bound before 6.7")
        );
        let tmp3 = TestDir::create("memveil-lc").expect("mkdtemp");
        let plain = one_copy_run(&tmp3, misses_of(5, 3));
        assert!(
            !plain
                .session
                .contains("attempt loss counts are a lower bound before 6.7")
        );
    }

    #[test]
    fn copy_only_misses_keep_aggregate_complete() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(5, 0));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
    }

    #[test]
    fn admitted_frame_skips_only_its_own_signal_check() {
        // Head check, frame, gate check, timeout, head check latches.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(0, 0));
        assert_eq!(c.end_reason, "signal");
        assert_eq!(c.signal_checks, 3);
        assert_eq!(c.loop_polls, 2);
    }

    #[test]
    fn foreign_payload_aborts() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = run_case(
            tmp.as_str(),
            vec![bad37()],
            cut(1, 37, 1, 37),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert!(
            c.session
                .contains("\"integrity\":{\"algorithm\":\"sha256\"")
        );
        assert_eq!(c.exit_code, EXIT_ERROR);
        assert_eq!(c.end_reason, "error");
        assert_eq!(c.outcome, "error");
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 5);
        for line in lines.iter().take(4) {
            assert!(line.contains("\"kind\":\"counter_snapshot\""));
        }
        assert!(lines[4].contains("\"kind\":\"gap\""));
        assert!(lines[4].contains("\"reason\":\"detail closure unproven: error shutdown\""));
    }

    #[test]
    fn lifecycle_geometry_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 1073741824,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "test-profile-1".to_string(),
            pid: 7,
            has_ring_bytes: true,
            ring_bytes: 8388608,
            has_lifecycle: true,
            lifecycle_ring_bytes: 8388608,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.channels = 3;
        kernel.ring_geom1.map_type = 2;
        let mut signal = ScriptSignal::new();
        let mut clock = ScriptClock::new();
        clock.add(0);
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert_eq!(result.outcome, "refused");
        assert!(result.diagnostic.contains("map lc mv_lifecycle geometry"));
        assert!(!std::path::Path::new(&format!("{}/cap/events.ndjson", tmp.as_str())).exists());
    }

    #[test]
    fn stop_open_mappings_exact() {
        // Two successful maps, one unmap, one failed map:
        // the stop wire reports exactly one open mapping
        // (failed maps never count as opened).
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            lc_raw(1, 1, 1, 121, 1021, 4096, 41),
            lc_raw(1, 1, 1, 122, 1022, 4096, 42),
            lc_raw(2, 3, 2, 123, 1023, 4096, 41),
            lc_raw(1, 0, 1, 124, 1024, 4096, 0),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            cut(4, 16384, 4, 16384),
            4,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("\"open_mappings\":\"1\""));
        assert!(c.session.contains("\"outcome\":\"partial\""));
    }

    #[test]
    fn stop_open_mappings_saturate() {
        // A failed map plus an unpaired unmap: unmaps outrun
        // successful maps, so open mappings saturate at zero
        // instead of wrapping.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            lc_raw(1, 0, 1, 131, 1031, 4096, 0),
            lc_raw(2, 3, 2, 132, 1032, 4096, 9),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            cut(2, 8192, 2, 8192),
            2,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("\"open_mappings\":\"0\""));
    }

    #[test]
    fn stop_open_mappings_balance_limit() {
        // The wire count is a persisted-event balance, not an
        // inventory: an unpaired unmap masks a still-open map
        // made after it.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            lc_raw(2, 3, 2, 141, 1041, 4096, 9),
            lc_raw(1, 1, 1, 142, 1042, 4096, 41),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            cut(2, 8192, 2, 8192),
            2,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("\"open_mappings\":\"0\""));
    }

    #[test]
    fn stop_open_mappings_churn() {
        // 500 map/unmap cycles persist as 1000 paired records
        // plus 4 snapshots; the balance closes at zero.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut payloads = Vec::new();
        for i in 0..500 {
            let generation = 100 + i as u64;
            let seq = 1000 + 2 * i as u64;
            let ktime = 5000 + 2 * i as u64;
            payloads.push(lc_raw(1, 1, 1, seq, ktime, 4096, generation));
            payloads.push(lc_raw(2, 3, 2, seq + 1, ktime + 1, 4096, generation));
        }
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            cut(1000, 4096000, 1000, 4096000),
            1000,
            zero_cut(),
            0,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.outcome, "finalized");
        let lines: Vec<&str> = c.events.lines().collect();
        assert_eq!(lines.len(), 1004);
        assert!(lines[0].contains("\"mapping_id\":\"gen-100\""));
        assert!(lines[1].contains("\"mapping_id\":\"gen-100\""));
        assert!(c.session.contains("\"open_mappings\":\"0\""));
    }

    #[test]
    fn exact_copy_loss_zero_stays_complete() {
        // E=100, D=10, R=110: every skipped or deferred copy
        // recovered, so busy capture stays complete.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(100, 3, 0, 0, 0, 0, 10, 110, 0));
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 0 (submit_fail=(0)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(c.session.contains("copy.mv_bounce_misses"));
        assert!(c.session.contains("copy.deferred"));
        assert!(c.session.contains("copy.recovered"));
    }

    #[test]
    fn exact_copy_loss_positive_is_partial() {
        // Others=3, E=10, D=2, R=5: loss is 3+7=10.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(10, 4, 1, 0, 1, 1, 2, 5, 0));
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 10 (submit_fail=(0)"));
        assert!(c.session.contains("recursion_missed=(10)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"10\",")
        );
    }

    #[test]
    fn exact_copy_loss_negative_is_unknown() {
        // R exceeds E+D: counters contradict, loss unknown.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(5, 0, 0, 0, 0, 0, 0, 10, 0));
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("contradict"));
        assert!(c.session.contains("copy.mv_bounce_misses"));
    }

    #[test]
    fn exact_copy_loss_counts_attempt_misses() {
        // Attempt misses charge both detail and the aggregate.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(10, 4, 1, 0, 1, 1, 2, 5, 3));
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 13 (submit_fail=(0)"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("attempt program runs skipped 3 (recursion)")
        );
    }

    #[test]
    fn copy_contradiction_keeps_aggregate_complete() {
        // A copy-counter contradiction poisons detail, not a clean aggregate.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(5, 0, 0, 0, 0, 0, 0, 10, 0));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
    }

    #[test]
    fn copy_contradiction_keeps_attempt_loss() {
        // Attempt skips still charge the aggregate under a contradiction.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(5, 0, 0, 0, 0, 0, 0, 10, 2));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"2\",")
        );
        assert!(
            c.session
                .contains("attempt program runs skipped 2 (recursion)")
        );
    }

    #[test]
    fn copy_overflow_keeps_aggregate_complete() {
        // A copy-counter overflow poisons detail, not a clean aggregate.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_misses8(u64::MAX, 0, 0, 0, 0, 0, 1, 0, 0));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("copy recursion counters overflow"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
    }

    fn run_geom(tmp: &TestDir, fb: super::GeomOut, claims: super::GeomOut) -> super::RunResult {
        let cfg = CollectorConfig {
            duration_s: 60,
            max_events_bytes: 1073741824,
            output: format!("{}/cap", tmp.as_str()),
            profile_id: "test-profile-1".to_string(),
            pid: 7,
            has_ring_bytes: true,
            ring_bytes: 8388608,
            has_copy: true,
            copy_ring_bytes: 8388608,
            ..Default::default()
        };
        let mut kernel = ScriptKernel::new();
        kernel.channels = 3;
        kernel.fb_geom = fb;
        kernel.claims_geom = claims;
        let mut signal = ScriptSignal::new();
        let mut clock = ScriptClock::new();
        clock.add(0);
        let mut writer = ScriptWriter::new();
        let mut collector = Collector::new(cfg);
        collector.run(&mut kernel, &mut clock, &mut signal, &mut writer)
    }

    fn good_fb() -> super::GeomOut {
        super::GeomOut {
            ok: true,
            map_type: 2,
            key_size: 4,
            value_size: 8,
            max_entries: 4,
            message: String::new(),
        }
    }

    fn good_claims() -> super::GeomOut {
        super::GeomOut {
            ok: true,
            map_type: 2,
            key_size: 4,
            value_size: 16,
            max_entries: 4096,
            message: String::new(),
        }
    }

    #[test]
    fn copy_fb_geometry_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let fb = super::GeomOut {
            ok: false,
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            message: "scripted fb failure".to_string(),
        };
        let result = run_geom(&tmp, fb, good_claims());
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_copy_fb:"));
    }

    #[test]
    fn copy_fb_wrong_type_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut fb = good_fb();
        fb.map_type = 1;
        let result = run_geom(&tmp, fb, good_claims());
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_copy_fb geometry"));
    }

    #[test]
    fn copy_fb_wrong_key_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut fb = good_fb();
        fb.key_size = 8;
        let result = run_geom(&tmp, fb, good_claims());
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_copy_fb geometry"));
    }

    #[test]
    fn copy_fb_wrong_value_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut fb = good_fb();
        fb.value_size = 4;
        let result = run_geom(&tmp, fb, good_claims());
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_copy_fb geometry"));
    }

    #[test]
    fn copy_claims_wrong_type_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut claims = good_claims();
        claims.map_type = 1;
        let result = run_geom(&tmp, good_fb(), claims);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_claims geometry"));
    }

    #[test]
    fn copy_claims_wrong_key_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut claims = good_claims();
        claims.key_size = 8;
        let result = run_geom(&tmp, good_fb(), claims);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_claims geometry"));
    }

    #[test]
    fn copy_claims_wrong_value_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut claims = good_claims();
        claims.value_size = 8;
        let result = run_geom(&tmp, good_fb(), claims);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_claims geometry"));
    }

    #[test]
    fn copy_claims_wrong_max_refuses() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let mut claims = good_claims();
        claims.max_entries = 1024;
        let result = run_geom(&tmp, good_fb(), claims);
        assert_eq!(result.exit_code, EXIT_REFUSAL);
        assert!(result.diagnostic.contains("map cp mv_claims geometry"));
    }

    #[test]
    fn copy_arm_failure_refuses_start() {
        // A failed arm write fails the capture closed, never unarmed.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let opts = RunOpts {
            arm_out: OpOut {
                ok: false,
                message: "map write denied".to_string(),
            },
            read_files: false,
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            vec![],
            zero_cut(),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, EXIT_REFUSAL);
        assert_eq!(c.outcome, "refused");
        assert!(c.diagnostic.contains("arm copy"));
        assert_eq!(c.calls.len(), 2);
        assert_eq!(c.calls[0], "attach");
        assert_eq!(c.calls[1], "arm");
    }

    #[test]
    fn copy_disarm_failure_makes_detail_unknown() {
        // A failed disarm write leaves copy detail unknown, never complete.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)];
        let opts = RunOpts {
            disarm_out: OpOut {
                ok: false,
                message: "map write denied".to_string(),
            },
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &opts,
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("copy disarm"));
    }

    #[test]
    fn copy_arm_disarm_bracket_the_capture() {
        // The arm write lands after attach, the disarm before detach.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, misses_of(0, 0));
        assert_eq!(c.calls.len(), 4);
        assert_eq!(c.calls[0], "attach");
        assert_eq!(c.calls[1], "arm");
        assert_eq!(c.calls[2], "disarm");
        assert_eq!(c.calls[3], "detach");
    }

    #[test]
    fn copy_disarm_precedes_detach_on_error_close() {
        // The error path disarms before detach like the normal close.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = error_copy_run(&tmp, misses_of(0, 0));
        assert_eq!(c.outcome, "error");
        assert_eq!(c.calls.len(), 4);
        assert_eq!(c.calls[0], "attach");
        assert_eq!(c.calls[1], "arm");
        assert_eq!(c.calls[2], "disarm");
        assert_eq!(c.calls[3], "detach");
    }
    #[test]
    fn stable_second_miss_read_keeps_exact_loss() {
        // Unchanged counters after settle and drain keep exact loss.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            stable_detail(),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("detail loss 0 (submit_fail=(0)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn grown_entry_misses_after_detach_make_loss_unknown() {
        // E grows after the first read: detail loss unknown, first kept.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(101, 3, 0, 0, 0, 0, 10, 110, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.mv_bounce_misses\",\"interpretation\":\"100\"")
        );
    }

    #[test]
    fn grown_deferred_after_detach_make_loss_unknown() {
        // D grows after the first read: detail loss unknown, first kept.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 3, 0, 0, 0, 0, 11, 110, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.deferred\",\"interpretation\":\"10\"")
        );
    }

    #[test]
    fn grown_recovered_after_detach_make_loss_unknown() {
        // R grows after the first read: detail loss unknown, first kept.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 3, 0, 0, 0, 0, 10, 111, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.recovered\",\"interpretation\":\"110\"")
        );
    }

    #[test]
    fn unreadable_second_miss_read_makes_loss_unknown() {
        // An unreadable second read cannot prove a quiet stop.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            misses_err("fdinfo gone"),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("recursion misses unreadable after settle")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn error_close_stable_read_keeps_error_cause() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = error_copy_run_opts(&tmp, stable_detail(), stable_detail(), true);
        assert_eq!(c.outcome, "error");
        assert!(c.session.contains("error shutdown"));
        assert!(!c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn error_close_grown_entry_misses_note_post_snapshot() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = error_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(101, 3, 0, 0, 0, 0, 10, 110, 0),
            true,
        );
        assert_eq!(c.outcome, "error");
        assert!(c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn unreadable_second_read_keeps_its_diagnostic() {
        // A failed re-read keeps the kernel diagnostic in its reason.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            misses_err("fdinfo gone"),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("recursion misses unreadable after settle: fdinfo gone")
        );
    }

    #[test]
    fn failed_second_detail_read_keeps_its_diagnostic() {
        // A failed detail re-read keeps its diagnostic in its reason.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_failed(0, "ch2 fallback counters wrapped"),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session.contains(
                "recursion misses unreadable after settle: ch2 fallback counters wrapped"
            )
        );
    }

    #[test]
    fn attempt_only_stable_second_read_keeps_exact_loss() {
        // Unchanged attempt counters keep exact loss without extras.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_attempt_run_opts(&tmp, misses_of(0, 0), misses_of(0, 0), true);
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("post-snapshot activity"));
        assert!(
            !c.session
                .contains("recursion misses unreadable after settle")
        );
    }

    #[test]
    fn lifecycle_only_stable_second_read_keeps_exact_loss() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_lc_run_opts(&tmp, misses_of(0, 0), misses_of(0, 0), true);
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn attempt_only_unreadable_second_read_goes_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_attempt_run_opts(&tmp, misses_of(0, 0), misses_err("fdinfo gone"), true);
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("recursion misses unreadable after settle")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn lifecycle_only_failed_second_read_goes_unknown() {
        // A failed ch1 re-read fails closed with a stable attempt.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_lc_run_opts(
            &tmp,
            misses_of(0, 0),
            detail_failed(0, "ch1 lifecycle program count"),
            true,
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("recursion misses unreadable after settle")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn copy_failed_second_detail_read_goes_unknown() {
        // A failed copy-detail re-read fails closed, first kept.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_failed(0, "ch2 fallback counters wrapped"),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("recursion misses unreadable after settle")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("\"source\":\"copy.mv_bounce_misses\",\"interpretation\":\"100\"")
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn attempt_growth_after_detach_leaves_aggregate_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 3, 0, 0, 0, 0, 10, 110, 1),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("attempt program skips unknown (post-snapshot activity)")
        );
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn unreadable_second_read_leaves_aggregate_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            misses_err("gone"),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session.contains(
                "attempt program skips unknown (recursion misses unreadable after settle)"
            )
        );
    }

    #[test]
    fn confirm_poll_error_leaves_aggregate_unknown() {
        // A confirm poll failure skips the re-read; no exact loss.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let base = RunOpts {
            timeouts: 3,
            confirm_poll_err: true,
            ..RunOpts::default()
        };
        let c = one_copy_run_opts(&tmp, stable_detail(), stable_detail(), false, &base);
        assert_eq!(c.outcome, "error");
        assert!(c.session.contains("error shutdown"));
        assert!(
            c.session
                .contains("attempt program skips unknown (re-read skipped)")
        );
    }

    #[test]
    fn confirm_stats_error_leaves_aggregate_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let base = RunOpts {
            fail_confirm_stats: true,
            ..RunOpts::default()
        };
        let c = one_copy_run_opts(&tmp, misses_of(0, 0), misses_of(0, 0), false, &base);
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("attempt program skips unknown (re-read skipped)")
        );
    }

    #[test]
    fn grown_exit_misses_after_detach_make_loss_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 4, 0, 0, 0, 0, 10, 110, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn grown_sync_device_misses_after_detach_make_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 3, 1, 0, 0, 0, 10, 110, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn grown_lc_map_misses_after_detach_make_unknown() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            detail_misses8(100, 3, 0, 0, 1, 0, 10, 110, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn detail_shape_flip_after_detach_makes_loss_unknown() {
        // Detail first, aggregate second: shapes disagree.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            stable_detail(),
            misses_of(0, 0),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn count_shape_flip_after_detach_makes_loss_unknown() {
        // Aggregate first, detail second: shapes disagree.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run_opts(
            &tmp,
            misses_of(0, 0),
            stable_detail(),
            true,
            &RunOpts::default(),
        );
        assert_eq!(c.outcome, "finalized");
        assert!(c.session.contains("post-snapshot activity"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn error_close_detail_shape_flip_notes_post_snapshot() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = error_copy_run_opts(&tmp, stable_detail(), misses_of(0, 0), true);
        assert_eq!(c.outcome, "error");
        assert!(c.session.contains("post-snapshot activity"));
    }

    #[test]
    fn lifecycle_only_detail_failure_names_lifecycle_channel() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_lc_run(&tmp, detail_failed(0, "ch1 lifecycle program count"));
        assert_eq!(c.outcome, "finalized");
        assert!(
            c.session
                .contains("lifecycle detail unreadable: ch1 lifecycle program count")
        );
        assert!(!c.session.contains("copy detail unreadable"));
    }

    #[test]
    fn error_close_lifecycle_only_detail_failure_names_channel() {
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = error_lc_run(&tmp, detail_failed(0, "ch1 lifecycle program count"));
        assert_eq!(c.outcome, "error");
        assert!(
            c.session
                .contains("lifecycle detail unreadable: ch1 lifecycle program count")
        );
    }

    #[test]
    fn wrapped_fallback_keeps_attempt_count() {
        // Wrapped fallback counters poison detail, not a read attempt count.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_failed(3, "ch2 fallback counters wrapped"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("attempt program runs skipped 3 (recursion)")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("copy detail unreadable: ch2 fallback counters wrapped")
        );
    }

    #[test]
    fn frame_lost_fallback_keeps_attempt_count() {
        // A lost frame names itself, never a counter wrap.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_failed(3, "ch2 fallback frame lost"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("copy detail unreadable: ch2 fallback frame lost")
        );
    }

    #[test]
    fn unreadable_fallback_keeps_attempt_count() {
        // An unreadable fallback map poisons detail, not the attempt count.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_failed(3, "ch2 fallback: short fallback read"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("copy detail unreadable: ch2 fallback: short fallback read")
        );
    }

    #[test]
    fn unreadable_lifecycle_misses_keep_attempt_count() {
        // Unreadable lifecycle misses poison detail, not the attempt count.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_failed(3, "ch1 lifecycle program count"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("copy detail unreadable: ch1 lifecycle program count")
        );
    }

    #[test]
    fn unreadable_copy_misses_keep_attempt_count() {
        // Unreadable copy misses poison detail, not the attempt count.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = one_copy_run(&tmp, detail_failed(3, "ch2 copy program count"));
        assert!(
            c.session
                .contains("\"aggregate\":{\"status\":\"partial\",\"loss_count\":\"3\",")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(
            c.session
                .contains("copy detail unreadable: ch2 copy program count")
        );
    }

    #[test]
    fn collector_liveness_dead_copy_silent() {
        // 200 maps over 3s with no copies: the session ends partial naming map->copy as silent.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..200 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                1000 + i,
                attach + i * 15000000,
                4096,
                1000 + i,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(200, 819200, 200, 819200),
            200,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(c.session.contains("hooks silent: map->copy"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
        assert!(c.session.contains("liveness hooks silent"));
    }

    #[test]
    fn collector_liveness_healthy_verified() {
        // Matched copies verify with zero loss.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..200 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                1000 + i,
                attach + i * 15000000,
                4096,
                1000 + i,
            ));
        }
        for i in 0..200 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                2000 + i,
                attach + i * 15000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(200, 819200, 200, 819200),
            200,
            cut(200, 819200, 200, 819200),
            200,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(c.session.contains("; liveness verified"));
    }

    #[test]
    fn copy_only_session_partial() {
        // A copy-only session is never complete: lone copies stay unverified.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, false, true);
        let attach = live_attach(&vals, false, true);
        let mut payloads = Vec::new();
        for i in 0..50 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                3000 + i,
                attach + i * 20000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            has_lifecycle: false,
            has_copy: true,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            zero_cut(),
            0,
            cut(50, 204800, 50, 204800),
            50,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("copy liveness unverified: lifecycle not captured")
        );
    }

    #[test]
    fn copy_only_zero_records_unverified() {
        // No records at all still leaves the copy hooks unattributable.
        use super::script::{LiveOpts, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, false, true);
        let opts = LiveOpts {
            has_lifecycle: false,
            has_copy: true,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            vec![],
            vals,
            zero_cut(),
            zero_cut(),
            0,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("copy liveness unverified: lifecycle not captured")
        );
    }

    #[test]
    fn copy_only_syncs_without_copies_silent() {
        // Syncs with no copies prove the bounce hook dead, no lifecycle needed.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, false, true);
        let attach = live_attach(&vals, false, true);
        let mut payloads = Vec::new();
        for i in 0..30 {
            payloads.push(cp_raw(1, 1, 1, 3100 + i, attach + i * 20000000, 4096, 0, 4));
        }
        let opts = LiveOpts {
            has_lifecycle: false,
            has_copy: true,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            zero_cut(),
            0,
            cut(30, 122880, 30, 122880),
            30,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(c.session.contains("hooks silent: map->copy"));
    }

    #[test]
    fn collector_liveness_submit_fail_absorbs_gap() {
        // Ring-full drops never emit, so they join the copy loss, never silence.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..100 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                7000 + i,
                attach + i * 30000000,
                4096,
                7000 + i,
            ));
        }
        for i in 0..60 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                7100 + i,
                attach + i * 50000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut5(100, 409600, 60, 245760, 40),
            60,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("; liveness verified"));
    }

    #[test]
    fn collector_liveness_recursion_misses_absorb_gap() {
        // Skipped bounce runs never observe, so they join the copy loss too.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..100 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                7200 + i,
                attach + i * 30000000,
                4096,
                7200 + i,
            ));
        }
        for i in 0..90 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                7300 + i,
                attach + i * 33000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses: detail_misses3(10, 0, 0),
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut(90, 368640, 90, 368640),
            90,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("; liveness verified"));
    }

    #[test]
    fn collector_liveness_deferred_absorbs_gap() {
        // Deferred-but-unrecovered entries never observe, so they join the loss.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..100 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                7400 + i,
                attach + i * 30000000,
                4096,
                7400 + i,
            ));
        }
        for i in 0..90 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                7500 + i,
                attach + i * 33000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses: detail_misses3(0, 10, 0),
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut(90, 368640, 90, 368640),
            90,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("; liveness verified"));
    }

    #[test]
    fn collector_liveness_fallback_exact() {
        // Recovered entries never inflate the loss; over-recovery voids it.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..100 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                7600 + i,
                attach + i * 30000000,
                4096,
                7600 + i,
            ));
        }
        for i in 0..90 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                7700 + i,
                attach + i * 33000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses: detail_misses3(0, 10, 10),
            ..LiveOpts::default()
        };
        let even = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut(90, 368640, 90, 368640),
            90,
            &opts,
        );
        assert_eq!(even.exit_code, 0);
        assert!(even.session.contains("hooks silent: map->copy"));
        let tmp2 = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals2 = live_clock_values(1000000000, true, true);
        let attach2 = live_attach(&vals2, true, true);
        let mut payloads2 = Vec::new();
        for i in 0..100 {
            payloads2.push(lc_raw(
                1,
                1,
                1,
                7800 + i,
                attach2 + i * 30000000,
                4096,
                7800 + i,
            ));
        }
        for i in 0..90 {
            payloads2.push(cp_raw(
                2,
                3,
                1,
                7900 + i,
                attach2 + i * 33000000,
                4096,
                4096,
                0,
            ));
        }
        let opts2 = LiveOpts {
            duration_s: 3600,
            misses: detail_misses3(0, 0, 5),
            ..LiveOpts::default()
        };
        let contradict = run_live_case(
            tmp2.as_str(),
            payloads2,
            vals2,
            zero_cut(),
            cut(100, 409600, 100, 409600),
            100,
            cut(90, 368640, 90, 368640),
            90,
            &opts2,
        );
        assert_eq!(contradict.exit_code, 0);
        assert!(!contradict.session.contains("hooks silent"));
    }

    #[test]
    fn collector_liveness_exit_recovered_misses_verify() {
        // E=10 D=0 R=10 with every copy emitted: the exit recovered
        // the entry-probe misses, so the copy loss is provably zero.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = run_copy_liveness(&tmp, 100, 100, detail_misses3(10, 0, 10));
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(c.session.contains("; liveness verified"));
        assert!(!c.session.contains("liveness unverified"));
        assert!(!c.session.contains("hooks silent"));
    }

    #[test]
    fn collector_liveness_exit_recovered_misses_expose_gap() {
        // E=10 D=0 R=10 with 20 copies missing: the counters explain
        // nothing, so map->copy reads hooks silent with unknown loss.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = run_copy_liveness(&tmp, 80, 80, detail_misses3(10, 0, 10));
        assert_eq!(c.exit_code, 0);
        assert!(c.session.contains("hooks silent: map->copy (100 > 80)"));
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":null,")
        );
    }

    #[test]
    fn collector_liveness_partial_exit_recovery_charges_loss() {
        // E=10 D=0 R=6: four copies truly lost, charged as known loss.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let c = run_copy_liveness(&tmp, 96, 96, detail_misses3(10, 0, 6));
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"partial\",\"loss_count\":\"4\",")
        );
        assert!(c.session.contains("recursion_missed=(4)"));
        assert!(c.session.contains("; liveness verified"));
        assert!(!c.session.contains("liveness unverified"));
    }

    #[test]
    fn collector_liveness_unreadable_misses_unverified() {
        // Without the miss counters the gap is unprovable: unverified, not silent.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..200 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                8000 + i,
                attach + i * 15000000,
                4096,
                8000 + i,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses: misses_err("fdinfo gone"),
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(200, 819200, 200, 819200),
            200,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("liveness unverified"));
    }

    #[test]
    fn collector_liveness_detail_error_unverified() {
        // A partial miss read splits no channel, so the gap stays unverified too.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..200 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                8100 + i,
                attach + i * 15000000,
                4096,
                8100 + i,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            misses: detail_failed(0, "ch2 copy program count"),
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(200, 819200, 200, 819200),
            200,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("liveness unverified"));
    }

    #[test]
    fn collector_liveness_forward_only_suffixes_copy() {
        // Copies outside R verify only the copy channel; lifecycle stays bare.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let ready = attach + 100000000;
        let detach_begin = 21400000007u64;
        let mut payloads = Vec::new();
        for i in 0..50 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                9400 + i,
                attach + 2000000000 + i * 40000000,
                4096,
                9400 + i,
            ));
        }
        for i in 0..25 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                9500 + i,
                ready + 25000000 + i * 35000000,
                4096,
                4096,
                0,
            ));
        }
        for i in 0..25 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                9600 + i,
                detach_begin - 25000000 - i * 35000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(50, 204800, 50, 204800),
            50,
            cut(50, 204800, 50, 204800),
            50,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("\"source\":\"detach_ns\",\"interpretation\":\"21500000007\"")
        );
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("liveness verified"));
    }

    #[test]
    fn collector_liveness_skipped_on_error_path() {
        // A torn run judges nothing: exercised windows stay out of the verdict.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..10 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                9700 + i,
                attach + i * 10000000,
                4096,
                9700 + i,
            ));
        }
        payloads.push(bad37());
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(10, 40960, 10, 40960),
            10,
            zero_cut(),
            0,
            &opts,
        );
        assert_eq!(c.exit_code, EXIT_ERROR);
        assert_eq!(c.end_reason, "error");
        assert_eq!(c.outcome, "error");
        assert!(!c.session.contains("hooks silent"));
        assert!(!c.session.contains("liveness"));
    }

    #[test]
    fn collector_liveness_busy_edges_clean() {
        // Guard-edge copies stay out of R while matched middle traffic verifies.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let ready = attach + 100000000;
        let detach_begin = 18000000007u64;
        let mut payloads = Vec::new();
        for i in 0..20 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                4000 + i,
                attach + 2000000000 + i * 100000000,
                4096,
                4000 + i,
            ));
        }
        for i in 0..20 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                4100 + i,
                attach + 2000000000 + i * 100000000,
                4096,
                4096,
                0,
            ));
        }
        for i in 0..20 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                4200 + i,
                ready + 25000000 + i * 50000000,
                4096,
                4096,
                0,
            ));
        }
        for i in 0..23 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                4300 + i,
                detach_begin - 25000000 - i * 42000000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(20, 81920, 20, 81920),
            20,
            cut(63, 257856, 63, 257856),
            63,
            &opts,
        );
        assert_eq!(c.exit_code, 0);
        assert!(
            c.session
                .contains("\"source\":\"detach_ns\",\"interpretation\":\"18100000007\"")
        );
        assert!(
            c.session
                .contains("\"detail\":{\"status\":\"complete_for_scope\",\"loss_count\":\"0\",")
        );
        assert!(!c.session.contains("hooks silent"));
        assert!(c.session.contains("; liveness verified"));
    }

    #[test]
    fn collector_liveness_size_limit_latch() {
        // Budget latch with room to drain; stranded batches stay inside the loss.
        use super::script::{LiveOpts, live_attach, live_clock_values, run_live_case};
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let vals = live_clock_values(1000000000, true, true);
        let attach = live_attach(&vals, true, true);
        let mut payloads = Vec::new();
        for i in 0..200 {
            payloads.push(lc_raw(
                1,
                1,
                1,
                5000 + i,
                attach + i * 2500000,
                4096,
                5000 + i,
            ));
        }
        for i in 0..200 {
            payloads.push(cp_raw(
                2,
                3,
                1,
                6000 + i,
                attach + 1000000000 + i * 2500000,
                4096,
                4096,
                0,
            ));
        }
        let opts = LiveOpts {
            duration_s: 3600,
            max_events_bytes: 131072,
            ..LiveOpts::default()
        };
        let c = run_live_case(
            tmp.as_str(),
            payloads,
            vals,
            zero_cut(),
            cut(200, 819200, 200, 819200),
            200,
            cut(200, 819200, 200, 819200),
            200,
            &opts,
        );
        assert_eq!(c.end_reason, "size_limit");
        assert_eq!(c.exit_code, 0);
        assert!(!c.session.contains("hooks silent"));
    }

    #[test]
    fn attempt_loss_lower_bound_caps_detail_partial() {
        // On a pre-6.7 kernel the detail claim is capped at
        // partial with the lower-bound label; the known count
        // stays as the lower bound, and the aggregate matches.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let opts = RunOpts {
            misses: misses_of(0, 0),
            lower_bound: true,
            ..RunOpts::default()
        };
        let c = run_case(
            tmp.as_str(),
            vec![cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0)],
            zero_cut(),
            zero_cut(),
            0,
            cut(1, 4096, 1, 4096),
            1,
            &opts,
        );
        let s = parse_session(c.session.as_bytes()).expect("parse");
        assert_eq!(s.q_detail.status, "partial");
        assert!(s.q_detail.has_loss_count);
        assert_eq!(s.q_detail.loss_count, 0);
        assert!(
            s.q_detail
                .reason
                .contains("attempt loss counts are a lower bound before 6.7")
        );
        assert_eq!(s.q_aggregate.status, "partial");
        assert!(s.q_aggregate.has_loss_count);
        assert_eq!(s.q_aggregate.loss_count, 0);
        assert!(
            s.q_aggregate
                .reason
                .contains("attempt loss counts are a lower bound before 6.7")
        );
    }

    #[test]
    fn aggregate_missing_stamp_yields_partial() {
        // Without both attached-interval stamps the aggregate
        // is partial, never complete_for_scope.
        let cfg = CollectorConfig {
            profile_id: "test-profile-1".to_string(),
            pid: 7,
            ..Default::default()
        };
        let mut collector = Collector::new(cfg);
        collector.snapshots_present = true;
        collector.attempt_known = true;
        let s = collector.assemble().expect("assemble");
        assert_eq!(s.q_aggregate.status, "partial");
        assert!(!s.q_aggregate.has_loss_count);
        assert!(s.q_aggregate.reason.contains("attached interval"));
        // Positive control: ordered stamps restore complete.
        collector.attempt_attach_done_ns = 100;
        collector.attempt_detach_begin_ns = 200;
        let s2 = collector.assemble().expect("assemble");
        assert_eq!(s2.q_aggregate.status, "complete_for_scope");
        assert!(s2.q_aggregate.has_loss_count);
        assert_eq!(s2.q_aggregate.loss_count, 0);
        assert!(s2.q_aggregate.scope.contains("attached [100,200)"));
    }
    #[test]
    fn scripted_old_ktimes_byte_identical() {
        // Pre-attach ktimes never enter a window: this nested-copy scenario
        // replays byte-identical with liveness on. The golden bytes below are
        // the Mojo-recorded sealed outputs for this exact script.
        let tmp = TestDir::create("memveil-lc").expect("mkdtemp");
        let payloads = vec![
            cp_raw(2, 3, 1, 101, 1001, 4096, 4096, 0),
            cp_raw(2, 3, 1, 102, 1002, 1024, 1024, 0),
        ];
        let c = run_case(
            tmp.as_str(),
            payloads,
            zero_cut(),
            zero_cut(),
            0,
            cut(2, 5120, 2, 5120),
            2,
            &RunOpts::default(),
        );
        assert_eq!(c.exit_code, EXIT_OK);
        assert_eq!(c.end_reason, "signal");
        assert_eq!(c.events, GOLDEN_EVENTS);
        assert!(c.session.contains(GOLDEN_INTEGRITY));
        assert!(c.session.contains(r#""schema_version":"0.1.4""#));
        // This scripted run has no checkpoint failures; prove that new field
        // before removing only its exact encoding for the legacy comparison.
        let legacy = without_zero_checkpoint_failures(&c.session);
        let legacy = legacy.replace(GOLDEN_INTEGRITY, "");
        let legacy = legacy.replace(
            r#""schema_version":"0.1.4","#,
            r#""schema_version":"0.1.3","#,
        );
        let golden = GOLDEN_SESSION.replace("memveil-0.1.1", crate::ENGINE_VERSION);
        assert_eq!(mask_output_fs(&legacy), mask_output_fs(&golden));
    }

    fn without_zero_checkpoint_failures(session: &str) -> String {
        let parsed = parse_session(session.as_bytes()).expect("parse");
        assert!(parsed.stop.has_checkpoint_failures);
        assert_eq!(parsed.stop.checkpoint_failures, 0);
        let field = r#""stop":{"checkpoint_failures":"0","#;
        assert!(session.contains(field));
        session.replace(field, r#""stop":{"#)
    }

    const GOLDEN_EVENTS: &str = r#"{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"0","ts_ns":"1001","kind":"copy","source":{"hook":"fentry:swiotlb_bounce","backend":"tracing","profile_id":"test-profile-1","measurement":"observed","correlation":"unpaired"},"data":{"operation_id":"lc-101","mapping_id":null,"direction":"original_to_bounce","bytes":"4096"}}
{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"1","ts_ns":"1002","kind":"copy","source":{"hook":"fentry:swiotlb_bounce","backend":"tracing","profile_id":"test-profile-1","measurement":"observed","correlation":"unpaired"},"data":{"operation_id":"lc-102","mapping_id":null,"direction":"original_to_bounce","bytes":"1024"}}
{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"2","ts_ns":"2000000","kind":"counter_snapshot","source":{"hook":"swiotlb:swiotlb_bounced","backend":"tracepoint","profile_id":"test-profile-1","measurement":"observed","correlation":"direct"},"data":{"counter_id":"swiotlb.bounce_attempts","epoch":"0","scope":{"profile_id":"test-profile-1"},"value":"0","unit":"count"}}
{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"3","ts_ns":"2000000","kind":"counter_snapshot","source":{"hook":"swiotlb:swiotlb_bounced","backend":"tracepoint","profile_id":"test-profile-1","measurement":"observed","correlation":"direct"},"data":{"counter_id":"swiotlb.requested_bytes","epoch":"0","scope":{"profile_id":"test-profile-1"},"value":"0","unit":"bytes"}}
{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"4","ts_ns":"121000000","kind":"counter_snapshot","source":{"hook":"swiotlb:swiotlb_bounced","backend":"tracepoint","profile_id":"test-profile-1","measurement":"observed","correlation":"direct"},"data":{"counter_id":"swiotlb.bounce_attempts","epoch":"0","scope":{"profile_id":"test-profile-1"},"value":"0","unit":"count"}}
{"schema_version":"0.1.1","session_id":"cap-0-7","seq":"5","ts_ns":"121000000","kind":"counter_snapshot","source":{"hook":"swiotlb:swiotlb_bounced","backend":"tracepoint","profile_id":"test-profile-1","measurement":"observed","correlation":"direct"},"data":{"counter_id":"swiotlb.requested_bytes","epoch":"0","scope":{"profile_id":"test-profile-1"},"value":"0","unit":"bytes"}}
"#;
    const GOLDEN_INTEGRITY: &str = r#","integrity":{"algorithm":"sha256","events_bytes":"2168","line_count":"6","first_seq":"0","last_seq":"5","events_sha256":"7e4f612a4f54e91938d3e5850d243a8ab40945a88ab0deb283b82c8257d3a24e","kinds":{"bounce_attempt":"0","map_result":"0","unmap":"0","copy":"2","sync_request":"0","transition_result":"0","pool_sample":"0","gap":"0","marker":"0","counter_snapshot":"4"}}"#;
    const GOLDEN_SESSION: &str = r#"{"schema_version":"0.1.3","session_id":"cap-0-7","synthetic":false,"product":{"name":"memveil","version":"memveil-0.1.1"},"environment":{"mode":"unknown","detection":"unverified","attestation":"not_performed","evidence":[{"type":"provenance","source":"attach_ns","interpretation":"7000000"},{"type":"provenance","source":"detach_ns","interpretation":"16000000"},{"type":"provenance","source":"drain_closure","interpretation":"proven"},{"type":"provenance","source":"measurement_scope","interpretation":"ordinals below observed at the end cut"},{"type":"provenance","source":"output.fs","interpretation":"btrfs"}]},"capture":{"mode":"live","window":{"start_ns":"7000000","end_ns":"127000001","baseline_start_ns":"2000000"},"filters":{},"finalized":true,"end_reason":"signal"},"device_catalog":{"devices":[]},"baseline":{"complete":false,"region_observations":[]},"capabilities":{"bounce_attempts":{"status":"partial","reason":"capture ok, 0 attempts persisted; admitted under test-profile-1; device detail grouped by observed name scope","hooks":["swiotlb:swiotlb_bounced"],"profile_id":"test-profile-1"},"mapping_lifecycle":{"status":"partial","reason":"capture ok, 0 map_result/unmap events persisted; admitted under test-profile-1; v2 wire reports opaque mapping generations when observed","hooks":["fexit:swiotlb_tbl_map_single","fentry:__swiotlb_tbl_unmap_single"],"profile_id":"test-profile-1"},"copy_bytes":{"status":"partial","reason":"capture ok, 2 copy events persisted; admitted under test-profile-1; v1 copy wire carries no mapping identity","hooks":["fentry:swiotlb_bounce"],"profile_id":"test-profile-1"},"sync_requests":{"status":"partial","reason":"capture ok, 0 sync_request events persisted; admitted under test-profile-1; v1 copy wire carries no mapping identity","hooks":["fentry:__swiotlb_sync_single_for_device","fentry:__swiotlb_sync_single_for_cpu"],"profile_id":"test-profile-1"},"conversion_results":{"status":"unavailable","reason":"No conversion source in this capture.","hooks":[]},"region_state":{"status":"unavailable","reason":"No region source in this capture.","hooks":[]},"pool_stats":{"status":"unavailable","reason":"No pool source in this capture.","hooks":[]},"task_context":{"status":"unavailable","reason":"No observer context in this capture.","hooks":[]}},"quality":{"detail":{"status":"complete_for_scope","loss_count":"0","scope":"0 bounce_attempt + 0 map_result/unmap + 2 copy/sync_request events","reason":"detail loss 0 (submit_fail=(0) malformed=(0) dropped=(0) recursion_missed=(0) size_omitted=(0) duration_omitted=(0) signal_omitted=(0) rejected=(0) write_failed=(0)); channels attempt:(submit_fail=0 malformed=0 dropped=0) lifecycle:(submit_fail=0 malformed=0 dropped=0) copy:(submit_fail=0 malformed=0 dropped=0)","evidence_refs":[]},"aggregate":{"status":"complete_for_scope","loss_count":"0","scope":"counter snapshots (attempt channel) attached [8000000,15000000)","reason":"counter snapshots present (valid cut, identity holds, coverage valid)","evidence_refs":[]},"correlation":{"status":"partial","loss_count":null,"scope":"correlated lifecycle events","reason":"copy_attribution partial (copy without pending operation)","evidence_refs":["capture:seq=0","capture:seq=1"],"relations":{"mapping_release":{"status":"complete_for_scope","loss_count":"0","scope":"mapping and release pairing","reason":"all mapping and release relationships paired","evidence_refs":[]},"copy_attribution":{"status":"partial","loss_count":null,"scope":"copy attribution","reason":"copy without pending operation","evidence_refs":["capture:seq=0","capture:seq=1"]},"sync_attribution":{"status":"complete_for_scope","loss_count":"0","scope":"sync attribution","reason":"all sync attribution relationships paired","evidence_refs":[]}}},"baseline":{"status":"not_applicable","loss_count":null,"scope":"attempt metrics","reason":"Attempt metrics need no baseline.","evidence_refs":[]},"terminal":{"status":"partial","loss_count":null,"scope":"capture finalization","reason":"stop partial: quiescence unproven","evidence_refs":[]}},"stop":{"outcome":"partial","reason":"quiescence unproven","budget_ms":"5000","elapsed_ms":"110","admission_closed":true,"quiescence_observed":false,"writers_settled":"0","in_flight_at_close":"0","late_submits_drained":"0","drained_records":"0","drain_completed":true,"submit_after_drain":false,"busy_at_drain":false,"counters_valid":true,"open_mappings":"0"},"verdict":{"name":"partial_known_loss","loss_ratio_bps":"0","delivered":"0"}}"#;
    // Slow identity-budget crossing (~3 min in debug builds): run explicitly with
    // -- --ignored. The boundary is proven; the cost is per-line SHA-256 + encode.
    #[test]
    #[ignore]
    fn probe_opcount() {
        // Cross the identity budget: size latch, exact session.
        let tmp = TestDir::create("memveil-probe").expect("mkdtemp");
        let mut kernel = ScriptKernel::new();
        let base = 1000000000u64;
        kernel.add_poll(record_batch(0, base + 1, 64), 4194305);
        kernel.add_poll(timeout_poll(), 102);
        kernel.add_stats(stats_ok(0, 0, 0, 0, 0));
        let flow = stats_ok(4194305, 4194305, 0, 0, 0);
        for _ in 0..4 {
            kernel.add_stats(flow.clone());
        }
        cuts(&mut kernel, 4194305, 268435520, 4194305, 268435520, 0, 0);
        let mut clock = ScriptClock::new();
        clock.step = 0;
        clock.add(base);
        clock.add(base + 1);
        clock.add(base + 2);
        clock.add(base + 3);
        let dir = format!("{}/cap", tmp.as_str());
        let mut writer = DropWriter::new();
        let mut collector = Collector::new(base_config(&dir, 134217728));
        let mut signal = ScriptSignal::new();
        let result = collector.run(&mut kernel, &mut clock, &mut signal, &mut writer);
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.end_reason, "size_limit");
        assert_eq!(result.outcome, "finalized");
        // 4194302 persisted + 4 snapshots; 3 omitted (1 gate + 2 drain).
        assert_eq!(writer.appends, 4194302 + 4);
        let session = read_text(&format!("{dir}/session.json"));
        assert!(session.contains("size_omitted=(3)"));
    }
}
