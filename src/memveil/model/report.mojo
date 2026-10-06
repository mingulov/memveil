"""Derived report document (report v0.1.0 shape).

The analyzer builds this from one session plus its event stream;
renderers serialize it. Environment and device catalog echo the
session claims verbatim so provenance survives every export.
"""

from memveil.model.metric import Finding, Metric
from memveil.model.session import Channel, DeviceEntry, EvidenceItem

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


struct Report:
    """One deterministic offline analysis result."""

    var session_id: String
    var synthetic: Bool
    var engine_version: String
    var window_start_ns: UInt64
    var window_end_ns: UInt64
    var env: ReportEnv
    var devices: List[DeviceEntry]
    var q_detail: Channel
    var q_aggregate: Channel
    var q_correlation: Channel
    var q_baseline: Channel
    var q_terminal: Channel
    var metrics: List[Metric]
    var findings: List[Finding]
    var limitations: List[String]
    var counter_disagreement: Bool

    def __init__(out self):
        self.session_id = String("")
        self.synthetic = False
        self.engine_version = String(ENGINE_VERSION)
        self.window_start_ns = UInt64(0)
        self.window_end_ns = UInt64(0)
        self.env = ReportEnv()
        self.devices = List[DeviceEntry]()
        self.q_detail = Channel()
        self.q_aggregate = Channel()
        self.q_correlation = Channel()
        self.q_baseline = Channel()
        self.q_terminal = Channel()
        self.metrics = List[Metric]()
        self.findings = List[Finding]()
        self.limitations = List[String]()
        self.counter_disagreement = False
