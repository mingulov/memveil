# SPDX-License-Identifier: GPL-3.0-or-later

"""Kernel-floor helpers shared by admission and reporting.

Capability floors (6.0 for attempt-trace, 6.11 for the
tracing capabilities) and the 6.7 attempt-loss exactness
cutover live here so every verb judges them identically.
"""

from memveil.platform.evidence import parse_kernel_triple, triple_ge


def cap_floor_need(cap_id: String) -> String:
    """Lowest ``major.minor`` serving one capability id.

    Attempt-trace rides the tracepoint that is stable from
    6.0 on; lifecycle and copy need the tracing interfaces
    verified from 6.11 on. Unknown ids need nothing because
    no gate admits them.
    """
    if cap_id == String("attempt-trace"):
        return String("6.0")
    if cap_id == String("mapping-lifecycle"):
        return String("6.11")
    if cap_id == String("copy-actual"):
        return String("6.11")
    return String("")


def cap_floor_ok(cap_id: String, release: String) -> Bool:
    """True when a release reaches one capability's floor."""
    var need = cap_floor_need(cap_id)
    if need == String(""):
        return False
    var triple = parse_kernel_triple(release)
    if need == String("6.0"):
        return triple_ge(triple, 6, 0)
    return triple_ge(triple, 6, 11)


def cap_floor_refusal(cap_id: String, release: String) -> String:
    """Refusal naming the floor one capability needs.

    An unparseable release cannot reach any floor, so it
    refuses as unknown rather than naming a version it
    might already satisfy.
    """
    var triple = parse_kernel_triple(release)
    if not triple.ok:
        return (
            String("release ")
            + release
            + String(" is unparseable; floor unknown")
        )
    return (
        String("capability ")
        + cap_id
        + String(" needs kernel ")
        + cap_floor_need(cap_id)
        + String("+ (this kernel: ")
        + release
        + String(")")
    )


def attempt_loss_exact(release: String) -> Bool:
    """True when attempt loss counts are exact on this release.

    Kernels before 6.7 skipped programs in trace_call_bpf
    without counting them, so loss counts there are a
    lower bound. Unparsable releases are not exact.
    """
    var triple = parse_kernel_triple(release)
    if not triple.ok:
        return False
    return triple_ge(triple, 6, 7)
