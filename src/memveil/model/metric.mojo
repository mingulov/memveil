# SPDX-License-Identifier: GPL-3.0-or-later

"""Report metric and finding rows (report v0.1.0 shapes).

Values stay numeric until rendering; the renderers format them with
format_u64 so the JSON output carries canonical decimal strings.
"""

struct Metric(ImplicitlyCopyable):
    """One derived metric row."""

    var name: String
    var has_value: Bool
    var value: UInt64
    var unit: String
    var measurement: String
    var coverage: String
    var has_aggregation: Bool
    var aggregation: String
    var has_sample_count: Bool
    var sample_count: UInt64
    var has_device_id: Bool
    var device_id: String
    var has_pool_id: Bool
    var pool_id: String
    var scope: String
    var notes: String

    def __init__(out self):
        self.name = String("")
        self.has_value = False
        self.value = UInt64(0)
        self.unit = String("")
        self.measurement = String("unavailable")
        self.coverage = String("unavailable")
        self.has_aggregation = False
        self.aggregation = String("")
        self.has_sample_count = False
        self.sample_count = UInt64(0)
        self.has_device_id = False
        self.device_id = String("")
        self.has_pool_id = False
        self.pool_id = String("")
        self.scope = String("")
        self.notes = String("")


struct Finding:
    """One evidence-linked observation."""

    var code: String
    var severity: String
    var explanation: String
    var evidence_refs: List[String]
    var scope: String
    var limitations: String

    def __init__(out self):
        self.code = String("")
        self.severity = String("informational")
        self.explanation = String("")
        self.evidence_refs = List[String]()
        self.scope = String("")
        self.limitations = String("")
