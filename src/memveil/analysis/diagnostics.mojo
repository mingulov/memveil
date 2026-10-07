# SPDX-License-Identifier: GPL-3.0-or-later

"""Evidence-linked diagnosis over finished reports.

The engine reads quality channels and metric rows and emits
findings with stable codes, each referencing the evidence it
explains. It never duplicates a code the report already
carries, never scores security, and never turns an open
allocation into a leak verdict: the long-lived policy is
informational and disabled unless configured.
"""

from memveil.analysis.attempts import window_label
from memveil.model.metric import Finding, Metric
from memveil.model.report import Report
from memveil.model.validate import format_u64


struct DiagnosticPolicy:
    """Diagnosis inputs: long-lived threshold plus requested scope."""

    var has_long_lived_after: Bool
    var long_lived_after_ns: UInt64
    var requested: List[String]

    def __init__(out self):
        self.has_long_lived_after = False
        self.long_lived_after_ns = UInt64(0)
        self.requested = List[String]()


def _has_code(findings: List[Finding], code: String) -> Bool:
    for i in range(len(findings)):
        if findings[i].code == code:
            return True
    return False


def _valued_metric(
    metrics: List[Metric], name: String, pool: String
) -> Metric:
    var blank = Metric()
    for i in range(len(metrics)):
        var m = metrics[i]
        if m.name != name or not m.has_value:
            continue
        if pool == "" and not m.has_pool_id:
            return m
        if pool != "" and m.has_pool_id and m.pool_id == pool:
            return m
    return blank^


def _any_valued(metrics: List[Metric], name: String) -> Bool:
    for i in range(len(metrics)):
        if metrics[i].name == name and metrics[i].has_value:
            return True
    return False


def diagnose_report(
    mut rep: Report,
    has_long_lived_after: Bool,
    long_lived_after_ns: UInt64,
):
    """Append derived findings to a finished report."""
    var policy = DiagnosticPolicy()
    if has_long_lived_after:
        policy.has_long_lived_after = True
        policy.long_lived_after_ns = long_lived_after_ns
    var eng = DiagnosisEngine()
    var extra = eng.evaluate(rep, policy)
    # Findings are move-only: pop them out in reverse, then pop
    # them back in order. Subscript moves out of a list do not
    # carry an origin in this toolchain.
    var staged = List[Finding]()
    while len(extra) > 0:
        staged.append(extra.pop())
    while len(staged) > 0:
        rep.findings.append(staged.pop())


struct DiagnosisEngine:
    """Stateless finding derivation over one report."""

    def __init__(out self):
        pass

    def evaluate(
        self, report: Report, policy: DiagnosticPolicy
    ) -> List[Finding]:
        """Derive findings; never duplicate existing codes."""
        var out = List[Finding]()
        var window = window_label(
            report.window_start_ns, report.window_end_ns
        )
        if not _has_code(report.findings, String("PROBE_UNAVAILABLE")):
            self._probe(report, window, out)
        if not _has_code(report.findings, String("UNPAIRED_LIFECYCLE")):
            self._unpaired(report, window, out)
        if not _has_code(report.findings, String("CONVERSION_FAILED")):
            self._conversion(report, window, out)
        if not _has_code(report.findings, String("POOL_PRESSURE")):
            self._pressure(report, window, out)
        if not _has_code(
            report.findings, String("LONG_LIVED_ALLOCATION")
        ):
            self._long_lived(report, policy, window, out)
        if not _has_code(report.findings, String("PROBE_UNAVAILABLE")):
            self._requested(report, policy, window, out)
        return out^

    def _probe(
        self, report: Report, window: String, mut out: List[Finding]
    ):
        # Only the detail channel reflects the event probe. The
        # aggregate channel is an optional counter cross-check:
        # its absence never constitutes a probe outage.
        if report.q_detail.status != "unavailable":
            return
        var expl = (
            String("Detail probe unavailable: ")
            + report.q_detail.reason
        )
        var tail = expl.as_bytes()
        if len(tail) == 0 or tail[len(tail) - 1] != UInt8(0x2E):
            expl += "."
        var f = Finding()
        f.code = String("PROBE_UNAVAILABLE")
        f.severity = String("warning")
        f.explanation = expl
        for i in range(len(report.q_detail.evidence_refs)):
            if len(f.evidence_refs) < 32:
                f.evidence_refs.append(
                    report.q_detail.evidence_refs[i]
                )
        f.scope = window
        f.limitations = String(
            "The detail channel carries no measurements; rerun"
            " with the probe attached."
        )
        out.append(f^)

    def _unpaired(
        self, report: Report, window: String, mut out: List[Finding]
    ):
        # The finding derives from the observed unpaired-event
        # row, never from channel loss: producer-claimed or
        # gap-derived correlation loss without pairing evidence
        # must not invent lifecycle exclusions.
        var row = _valued_metric(
            report.metrics,
            String("unpaired_lifecycle_events"),
            String(""),
        )
        if not row.has_value or row.value == UInt64(0):
            return
        var f = Finding()
        f.code = String("UNPAIRED_LIFECYCLE")
        f.severity = String("warning")
        f.explanation = (
            format_u64(row.value)
            + " lifecycle events could not be paired and were"
            " excluded from lifecycle totals."
        )
        f.evidence_refs.append(
            String("metric:unpaired_lifecycle_events")
        )
        f.scope = window
        f.limitations = String(
            "Affected totals degrade; raw pairing detail stays"
            " out of the report."
        )
        out.append(f^)

    def _conversion(
        self, report: Report, window: String, mut out: List[Finding]
    ):
        var row = _valued_metric(
            report.metrics, String("conversion_failures"), String("")
        )
        if not row.has_value or row.value == UInt64(0):
            return
        var f = Finding()
        f.code = String("CONVERSION_FAILED")
        f.severity = String("warning")
        f.explanation = (
            format_u64(row.value)
            + " observed conversion requests failed; affected"
            " region state is invalid."
        )
        f.evidence_refs.append(String("metric:conversion_failures"))
        f.scope = window
        f.limitations = String(
            "Failures invalidate state; they prove nothing about"
            " other regions."
        )
        out.append(f^)

    def _pressure(
        self, report: Report, window: String, mut out: List[Finding]
    ):
        for i in range(len(report.metrics)):
            var m = report.metrics[i]
            if m.name != "pool_pressure_samples" or not m.has_value:
                continue
            if m.value < UInt64(3) or not m.has_pool_id:
                continue
            var f = Finding()
            f.code = String("POOL_PRESSURE")
            f.severity = String("warning")
            f.explanation = (
                String("Pool ")
                + m.pool_id
                + String(" at or above 90% for ")
                + format_u64(m.value)
                + String(" consecutive valid samples.")
            )
            f.evidence_refs.append(
                String("metric:pool_pressure_samples")
            )
            f.evidence_refs.append("pool:" + m.pool_id)
            f.scope = window + "; pool " + m.pool_id
            f.limitations = String(
                "Pressure is a measured allocator state, not a"
                " defect verdict."
            )
            out.append(f^)

    def _long_lived(
        self,
        report: Report,
        policy: DiagnosticPolicy,
        window: String,
        mut out: List[Finding],
    ):
        if not policy.has_long_lived_after:
            return
        var row = _valued_metric(
            report.metrics,
            String("oldest_open_mapping_age_ns"),
            String(""),
        )
        if not row.has_value:
            return
        if row.value < policy.long_lived_after_ns:
            return
        var f = Finding()
        f.code = String("LONG_LIVED_ALLOCATION")
        f.severity = String("informational")
        f.explanation = (
            String("Oldest open mapping is ")
            + format_u64(row.value)
            + String(" ns old, past the configured ")
            + format_u64(policy.long_lived_after_ns)
            + String(" ns threshold.")
        )
        f.evidence_refs.append(
            String("metric:oldest_open_mapping_age_ns")
        )
        f.scope = window
        f.limitations = String(
            "Open is not a leak; the mapping may still be in"
            " legitimate use."
        )
        out.append(f^)

    def _requested(
        self,
        report: Report,
        policy: DiagnosticPolicy,
        window: String,
        mut out: List[Finding],
    ):
        for i in range(len(policy.requested)):
            var want = policy.requested[i]
            if want == "lifecycle":
                if not _any_valued(
                    report.metrics, String("successful_allocations")
                ):
                    self._requested_finding(
                        "lifecycle", window, out
                    )
            elif want == "pools":
                if not _any_valued(
                    report.metrics, String("pool_used_bytes")
                ):
                    self._requested_finding("pools", window, out)
            if _has_code(out, "PROBE_UNAVAILABLE"):
                return

    def _requested_finding(
        self, scope: String, window: String, mut out: List[Finding]
    ):
        var f = Finding()
        f.code = String("PROBE_UNAVAILABLE")
        f.severity = String("warning")
        f.explanation = (
            String("Requested ")
            + scope
            + String(" scope has no evidence in this capture.")
        )
        f.scope = window
        f.limitations = String(
            "Rerun with the requested scope observable."
        )
        out.append(f^)
