# SPDX-License-Identifier: GPL-3.0-or-later

"""Derived report document (report v0.1.4 shape).

The analyzer builds this from one session plus its event stream;
renderers serialize it. Environment and device catalog echo the
session claims verbatim so provenance survives every export.
"""

from memveil.model.metric import Finding, Metric
from memveil.model.session import (
    Channel,
    DeviceEntry,
    EvidenceItem,
    Session,
    terminal_loss_leg,
)

comptime ENGINE_VERSION = "memveil-0.1.0"


struct ReportEnv:
    """Echoed session environment."""

    var mode: String
    var detection: String
    var has_asserted_mode: Bool
    var asserted_mode: String
    var asserted_mode_present: Bool
    var attestation: String
    var evidence: List[EvidenceItem]

    def __init__(out self):
        self.mode = String("")
        self.detection = String("")
        self.has_asserted_mode = False
        self.asserted_mode = String("")
        self.asserted_mode_present = False
        self.attestation = String("")
        self.evidence = List[EvidenceItem]()


struct ReportCap(Copyable):
    """One echoed session capability claim: name plus grade."""

    var name: String
    var status: String
    var has_grade: Bool
    var grade: String
    var reason: String

    def __init__(out self):
        self.name = String("")
        self.status = String("")
        self.has_grade = False
        self.grade = String("")
        self.reason = String("")


struct Report:
    """One deterministic offline analysis result."""

    var integrity_context: String
    var integrity_status: String
    var verified_bytes: UInt64
    var verified_events: UInt64
    var session_id: String
    var synthetic: Bool
    var engine_version: String
    var window_start_ns: UInt64
    var window_end_ns: UInt64
    var env: ReportEnv
    var devices: List[DeviceEntry]
    var caps: List[ReportCap]
    var q_detail: Channel
    var q_aggregate: Channel
    var q_correlation: Channel
    var has_corr_relations: Bool
    var q_corr_mapping: Channel
    var q_corr_copy: Channel
    var q_corr_sync: Channel
    var q_baseline: Channel
    var q_terminal: Channel
    var metrics: List[Metric]
    var findings: List[Finding]
    var limitations: List[String]
    var counter_disagreement: Bool
    var detail_delivered: UInt64
    var verdict: Verdict

    def __init__(out self):
        self.integrity_context = String("capture")
        self.integrity_status = String("legacy_unverified")
        self.verified_bytes = UInt64(0)
        self.verified_events = UInt64(0)
        self.session_id = String("")
        self.synthetic = False
        self.engine_version = String(ENGINE_VERSION)
        self.window_start_ns = UInt64(0)
        self.window_end_ns = UInt64(0)
        self.env = ReportEnv()
        self.devices = List[DeviceEntry]()
        self.caps = List[ReportCap]()
        self.q_detail = Channel()
        self.q_aggregate = Channel()
        self.q_correlation = Channel()
        self.has_corr_relations = False
        self.q_corr_mapping = Channel()
        self.q_corr_copy = Channel()
        self.q_corr_sync = Channel()
        self.q_baseline = Channel()
        self.q_terminal = Channel()
        self.metrics = List[Metric]()
        self.findings = List[Finding]()
        self.limitations = List[String]()
        self.counter_disagreement = False
        self.detail_delivered = UInt64(0)
        self.verdict = Verdict()


struct Verdict(Copyable):
    """Measurement verdict: agreed counters plus bounded loss.

    The name is one of complete, partial_known_loss, or
    partial_unknown_loss. The ratio counts known lost records over
    known lost plus delivered records in basis points (0..10000),
    truncated; it is exact when every leg is known and a lower bound
    otherwise, so partial_unknown_loss with ratio 0 means "no known
    loss, more may hide", never "nothing lost".
    """

    var name: String
    var loss_ratio_bps: Int

    def __init__(out self):
        self.name = String("")
        self.loss_ratio_bps = 0


def _loss_ratio_bps(known_lost: UInt64, delivered: UInt64) -> Int:
    """Known-loss ratio in basis points, truncated toward zero.

    Division-first form: the exact floor without multiplying the
    full count by 10000. Counts are event counts bounded by capture
    bytes on disk, so u64 wrap (past ~1.8e19 events) is unreachable.
    """
    var total = known_lost + delivered
    if total == UInt64(0):
        return 0
    var head = Int(known_lost // total) * 10000
    var rem = known_lost % total
    var tail = Int((rem * UInt64(10000)) // total)
    return head + tail


def verdict_for_counts(
    counters_agree: Bool,
    detail_loss_known: Bool,
    detail_lost: UInt64,
    detail_partial: Bool,
    terminal_partial: Bool,
    terminal_loss_known: Bool,
    terminal_lost: UInt64,
    delivered: UInt64,
) -> Verdict:
    """Assemble a verdict from counters agreement plus loss legs.

    Only legs flagged known feed the ratio; unknown legs keep their
    counts out of the numerator. Complete needs agreed counters,
    every leg known, zero known loss, and no partial leg: a partial
    leg with bounded loss (gap markers claiming zero, quiescence-only
    spillover verified) stays partial_known_loss, never complete.
    """
    var known_lost = UInt64(0)
    if detail_loss_known:
        known_lost += detail_lost
    if terminal_loss_known:
        known_lost += terminal_lost
    var all_known = detail_loss_known and terminal_loss_known
    var any_partial = detail_partial or terminal_partial
    var out = Verdict()
    out.loss_ratio_bps = _loss_ratio_bps(known_lost, delivered)
    if counters_agree and all_known and known_lost == 0 and not any_partial:
        out.name = String("complete")
    elif counters_agree and all_known:
        out.name = String("partial_known_loss")
    else:
        out.name = String("partial_unknown_loss")
    return out^


def verdict_for_session(session: Session, delivered: UInt64) -> Verdict:
    """Record-time verdict from session channels plus stop evidence.

    The record side performs no counter comparison (the stream is not
    read back), so the counters leg is vacuously agreed: the analysis
    cross-check can only add unknown, never remove it. The detail leg
    comes from the producer channel, the terminal leg from the shared
    stop predicate, and delivered counts bounce_attempt records. The
    report verdict is never better than this record verdict; the two
    agree on intact gap-free loads.
    """
    var term = terminal_loss_leg(session.q_terminal.status, session.stop)
    return verdict_for_counts(
        True,
        session.q_detail.has_loss_count,
        session.q_detail.loss_count,
        session.q_detail.status != String("complete_for_scope"),
        term[0],
        term[1],
        term[2],
        delivered,
    )


def incomplete_finding_severity(
    verdict_name: String, loss_ratio_bps: Int
) -> String:
    """Severity for the aggregate incompleteness finding.

    The finding demotes to informational only when the verdict
    proves the incompleteness fully bounded with zero loss
    (partial channels, nothing missing). Unknown loss, real
    loss, and complete-with-correlation-caveats stay warning:
    attribution gaps are not bounded by the detail verdict.
    """
    if (
        verdict_name == String("partial_known_loss")
        and loss_ratio_bps == 0
    ):
        return String("informational")
    return String("warning")


def _unverified_channel(mut channel: Channel):
    if channel.status == "complete_for_scope":
        channel.status = String("partial")
    var note = String("Capture integrity unverified; ")
    var reason = channel.reason
    channel.reason = note
    var count = note.count_codepoints()
    for cp in reason.codepoint_slices():
        if count >= 1024:
            break
        channel.reason += String(cp)
        count += 1


def apply_integrity(mut rep: Report, verified: Bool, bytes: UInt64, events: UInt64):
    """Bind file verification after reduction without changing its arithmetic."""
    if verified:
        rep.integrity_status = String("verified")
        rep.verified_bytes = bytes
        rep.verified_events = events
        return
    rep.integrity_status = String("legacy_unverified")
    rep.verified_bytes = UInt64(0)
    rep.verified_events = UInt64(0)
    _unverified_channel(rep.q_detail)
    _unverified_channel(rep.q_aggregate)
    _unverified_channel(rep.q_correlation)
    _unverified_channel(rep.q_corr_mapping)
    _unverified_channel(rep.q_corr_copy)
    _unverified_channel(rep.q_corr_sync)
    _unverified_channel(rep.q_baseline)
    _unverified_channel(rep.q_terminal)
    rep.verdict.name = String("partial_unknown_loss")
    for i in range(len(rep.metrics)):
        if rep.metrics[i].coverage == "complete_for_scope":
            rep.metrics[i].coverage = String("partial")
