# SPDX-License-Identifier: GPL-3.0-or-later
"""Deferred qualification suites: explicit skips with recorded reasons.

A candidate run fails on any skip not on this list and
passes (a skip, with its reason recorded) for listed ones.
Each entry names the dispatched suite and the exact skip
reason. The dispatch de-route consults the suite name; the
candidate pytest hooks exempt only reports whose node ID is
listed verbatim on an entry with a matching reason, so a
node that merely shares the reason text stays failing.
Entries with no nodes exempt no pytest report: the suite
de-route still applies.
"""


DEFERRED = [
    {"suite": "perf-workload",
     "reason": "sealed candidate carries no retired "
               "perf-workload guest inputs (mv_consume "
               "consumer, libbpf_mojo bridge, oracle ko)",
     "nodes": []},
]


def validate(entries=None):
    """Refuse a malformed deferral list.

    Every entry carries exactly suite, reason, and nodes:
    suite and reason are non-empty strings, nodes is a
    list of exact pytest node IDs (non-empty unique
    strings, possibly empty); suites are unique. Raises
    ValueError.
    """
    if entries is None:
        entries = DEFERRED
    if not isinstance(entries, list):
        raise ValueError("deferral list must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) \
                or set(entry) != {"suite", "reason",
                                  "nodes"}:
            raise ValueError(
                "deferral entry needs exactly suite, "
                "reason, nodes: %r" % (entry,))
        for key in ("suite", "reason"):
            if not isinstance(entry[key], str) \
                    or not entry[key].strip():
                raise ValueError(
                    "deferral %s must be a non-empty "
                    "string" % key)
        nodes = entry["nodes"]
        if not isinstance(nodes, list) \
                or any(not isinstance(node, str)
                       or not node for node in nodes) \
                or len(set(nodes)) != len(nodes):
            raise ValueError(
                "deferral nodes must be unique non-empty "
                "strings: %r" % (nodes,))
        if entry["suite"] in seen:
            raise ValueError(
                "deferral suite listed twice: "
                + entry["suite"])
        seen.add(entry["suite"])


validate()


def lookup(suite):
    """Deferral entry for one dispatched suite, or None."""
    for entry in DEFERRED:
        if entry["suite"] == suite:
            return entry
    return None


def skip_reason(report):
    """Recorded reason of one pytest skip report, or None.

    Pytest stores skips as (file, line, "Skipped:
    <reason>"); a bare "Skipped" carries no reason and
    never matches the list.
    """
    longrepr = getattr(report, "longrepr", None)
    if not isinstance(longrepr, tuple) or len(longrepr) != 3:
        return None
    text = longrepr[2]
    if not isinstance(text, str):
        return None
    if text.startswith("Skipped: "):
        return text[len("Skipped: "):]
    return None


def exempted(report, entries=None):
    """True when one skip report is deferred verbatim.

    The report's node ID must be listed exactly on an
    entry whose reason equals the recorded reason; either
    half failing keeps the skip unlisted.
    """
    if entries is None:
        entries = DEFERRED
    nodeid = getattr(report, "nodeid", None)
    reason = skip_reason(report)
    return any(nodeid in entry["nodes"]
               and reason == entry["reason"]
               for entry in entries)


def unlisted_skips(reports, entries=None):
    """Describe skipped reports no entry exempts."""
    if entries is None:
        entries = DEFERRED
    found = []
    for report in reports or []:
        if not exempted(report, entries):
            found.append("%s: %s" % (
                getattr(report, "nodeid", "?"),
                skip_reason(report)))
    return found
