#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Hook-definition admission comparator (offline rules).

Each lifecycle or copy adapter needs an admitted hook
definition before it may attach: a present adapter, a
non-inlined available target, a signature matching the
recorded kernel source, a matching BTF anchor, a proven
authority, an effective adapter length within budget, and a
proven hook kind. Anything else refuses with a reason.

The comparator is pure: the VM harness feeds it definitions
extracted from kernel source and BTF, and these same rules
decide. Default deny: a definition that is missing any field
refuses.
"""

MAX_ADAPTER_BYTES = 2048
PROVEN_KINDS = ("tracepoint", "fentry")
PROVEN_AUTHORITIES = ("kernel-source", "btf")


def effective_length(source):
    """Adapter bytes minus blank and full-line comment lines.

    Compiler flags, trailing comments, and line-length
    exclusions never change this number: only full blank and
    full-line (# or //) comment lines are dropped.
    """
    total = 0
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("//"):
            continue
        total += len(line.encode("utf-8")) + 1
    return total


def _need(defn, field, reasons):
    if field not in defn or defn[field] is None:
        reasons.append("missing field: " + field)
        return None
    return defn[field]


def admit(defn, recorded):
    """Admit one hook definition. Returns (ok, reason)."""
    reasons = []
    hook = _need(defn, "hook", reasons)
    kind = _need(defn, "kind", reasons)
    target = _need(defn, "target", reasons)
    signature = _need(defn, "signature", reasons)
    anchor = _need(defn, "btf_anchor", reasons)
    authority = _need(defn, "authority", reasons)
    adapter_len = _need(defn, "adapter_len", reasons)
    _need(defn, "inlined", reasons)
    _need(defn, "available", reasons)
    if reasons:
        return False, "; ".join(reasons)
    if not isinstance(adapter_len, int) or adapter_len <= 0:
        return False, "missing adapter for %s" % hook
    if adapter_len > MAX_ADAPTER_BYTES:
        return False, ("adapter too long for %s: %d > %d"
                       % (hook, adapter_len, MAX_ADAPTER_BYTES))
    if defn["inlined"]:
        return False, "inlined target %s" % target
    if not defn["available"]:
        return False, "unavailable target %s" % target
    if kind not in PROVEN_KINDS:
        return False, "unproven hook kind %s" % kind
    if authority not in PROVEN_AUTHORITIES:
        return False, "unproven authority %s" % authority
    want_sig = recorded.get("signature")
    if signature != want_sig:
        return False, ("signature drift for %s: recorded %r, "
                       "definition %r" % (target, want_sig, signature))
    want_anchor = recorded.get("btf_anchor")
    if anchor != want_anchor:
        return False, ("BTF anchor mismatch for %s: recorded %r, "
                       "definition %r" % (target, want_anchor, anchor))
    return True, "admitted %s via %s" % (hook, authority)
