# SPDX-License-Identifier: GPL-3.0-or-later
"""Deferred qualification suites: explicit skips with owning cards.

A candidate run fails on any skip not on this list and passes
(a skip, with its reason recorded) for listed ones. Each entry
names the dispatched suite, the exact skip reason, and the card
that owns the sealed rederivation. The dispatch de-route and
the candidate conftest hooks consult this one list.
"""
import re

CARD_RE = r"MV[0-9]+-[0-9]+"

DEFERRED = [
    {"suite": "perf-workload",
     "reason": "sealed candidate carries no retired "
               "perf-workload guest inputs (mv_consume "
               "consumer, libbpf_mojo bridge, oracle ko)",
     "owning-card": "MV31-12"},
]


def validate(entries=None):
    """Refuse a malformed deferral list.

    Every entry carries exactly suite, reason, and
    owning-card, all non-empty strings; suites are unique
    and cards match MV<plan>-<card>. Raises ValueError.
    """
    if entries is None:
        entries = DEFERRED
    if not isinstance(entries, list):
        raise ValueError("deferral list must be a list")
    seen = set()
    for entry in entries:
        if not isinstance(entry, dict) \
                or set(entry) != {"suite", "reason",
                                  "owning-card"}:
            raise ValueError(
                "deferral entry needs exactly suite, "
                "reason, owning-card: %r" % (entry,))
        for key in ("suite", "reason", "owning-card"):
            if not isinstance(entry[key], str) \
                    or not entry[key].strip():
                raise ValueError(
                    "deferral %s must be a non-empty "
                    "string" % key)
        if entry["suite"] in seen:
            raise ValueError(
                "deferral suite listed twice: "
                + entry["suite"])
        seen.add(entry["suite"])
        if not re.fullmatch(CARD_RE, entry["owning-card"]):
            raise ValueError(
                "deferral card is not MV<plan>-<card>: "
                + entry["owning-card"])


validate()


def lookup(suite):
    """Deferral entry for one dispatched suite, or None."""
    for entry in DEFERRED:
        if entry["suite"] == suite:
            return entry
    return None


def listed_reason(reason):
    """True when one skip reason is deferred verbatim."""
    return any(entry["reason"] == reason for entry in DEFERRED)


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


def unlisted_skips(reports):
    """Describe skipped reports whose reason is not deferred."""
    found = []
    for report in reports or []:
        reason = skip_reason(report)
        if reason is None or not listed_reason(reason):
            found.append("%s: %s" % (
                getattr(report, "nodeid", "?"), reason))
    return found
