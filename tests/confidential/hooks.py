# SPDX-License-Identifier: GPL-3.0-or-later
"""Candidate conversion-API symbol evidence (pure parsing).

`parse_kallsyms` extracts text-symbol kinds for exactly the two
candidate conversion APIs. `collect_evidence` bundles one verdict:
name presence is recorded as data, and hook admission is always
refused, because a kallsyms name proves nothing about signature
stability, return-code meaning, inlining, or rollback behavior.
Admission needs per-hook kernel-source inspection plus a
return/rollback proof; collecting evidence never performs it.
"""

CANDIDATE_APIS = ("set_memory_encrypted", "set_memory_decrypted")

_REFUSAL = ("symbol names are not semantic admission; hook-body "
            "kernel-source inspection plus return/rollback proof "
            "are missing")


def parse_kallsyms(text):
    """Map candidate API names to global-text or local-text.

    Only exact-name text symbols (T/t) count; __pfx_ aliases,
    data symbols, and malformed lines are ignored. Addresses are
    never read: zeroed (unprivileged) maps work the same.
    """
    found = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3:
            continue
        _address, kind, name = parts
        if name not in CANDIDATE_APIS:
            continue
        if kind == "T":
            found[name] = "global-text"
        elif kind == "t":
            found[name] = "local-text"
    return found


def collect_evidence(symbols, btf_present, kernel_release,
                     kallsyms_readable=True):
    """Build one evidence verdict; admission is always refused."""
    entries = {}
    for name in CANDIDATE_APIS:
        kind = symbols.get(name)
        entries[name] = {"present": kind is not None, "kind": kind}
    return {"kernel_release": kernel_release,
            "btf_present": bool(btf_present),
            "kallsyms_readable": bool(kallsyms_readable),
            "symbols": entries,
            "admission": "refused",
            "reason": _REFUSAL}
