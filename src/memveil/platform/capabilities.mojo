# SPDX-License-Identifier: GPL-3.0-or-later

"""Passive capability discovery: profile declarations vs live evidence.

``discover_capabilities`` judges each known capability without
loading BPF or attaching anything:

- the kernel floor fails: ``attempt-trace`` is unavailable, and
  any other available judgment is demoted to unavailable with the
  floor reason. Below the floor no support claim of any kind is
  valid. Eligibility stays separate from source support and
  attachment.
- no covering profile: every capability is unknown.
- declared ``unsupported``: stays unsupported with the profile's
  reason verbatim.
- declared ``candidate`` with every hook present and readable:
  unknown. Hooks present, semantics unproven.
- declared ``supported`` with every hook verified byte for byte:
  available, but only under a validated (matched) profile. The
  same evidence under a reference profile stays unknown.
- a hook id/format file absent: unavailable, naming the path.
- a hook id/format file denied: unknown, naming the path as a
  privilege restriction; the path joins ``denied``.
- a hook format file that probes readable but fails to read
  (over the cap, TOCTOU): unknown, naming it unreadable. This is
  not a privilege fact, so the path stays out of ``denied``.
- a recorded format that differs byte for byte: unavailable
  (changed signature).
- a hook with no recorded format: unknown (nothing to verify
  against), even under a validated profile.

Hook failures combine by severity: any absent beats any changed
signature beats any unreadable read beats any denial beats any
unrecorded format. Reasons name the first failing hook in
declaration order.

The function is total: late read failures degrade to explicit
unknown reasons, never to an exception.
"""

from memveil.platform.evidence import parse_kernel_triple
from memveil.platform.profiles import ProfileDecision
from memveil.platform.reader import (
    EVIDENCE_ABSENT,
    EVIDENCE_DENIED,
    EVIDENCE_OK,
    EvidenceReader,
    file_state,
    read_evidence,
)


comptime _FORMAT_CAP = 131072


@fieldwise_init
struct CapEntry(Copyable):
    """One judged capability: id, status, and reason.

    ``status`` is one of ``available``, ``unavailable``,
    ``unknown``, ``unsupported``.
    """

    var id: String
    var status: String
    var reason: String


@fieldwise_init
struct CapabilityReport(Copyable):
    """Judged capabilities plus hook paths refused by privilege."""

    var entries: List[CapEntry]
    var denied: List[String]


@fieldwise_init
struct _HookMarks(ImplicitlyCopyable):
    """Combined per-hook probe outcome for one capability."""

    var absent_path: String
    var absent_which: String
    var absent_hook: String
    var has_absent: Bool
    var denied_path: String
    var denied_which: String
    var denied_hook: String
    var has_denied: Bool
    var changed_hook: String
    var has_changed: Bool
    var unread_hook: String
    var has_unread: Bool
    var bare_hook: String
    var has_bare: Bool


def _bytes_equal_text(data: List[UInt8], text: String) -> Bool:
    """True when data equals the text's UTF-8 bytes exactly."""
    var tbytes = text.as_bytes()
    if len(data) != len(tbytes):
        return False
    for i in range(len(data)):
        if data[i] != tbytes[i]:
            return False
    return True


def _probe_hooks(
    reader: EvidenceReader,
    decision: ProfileDecision,
    cap_index: Int,
    mut denied: List[String],
) -> _HookMarks:
    """Probe every hook a capability references, in order.

    Appends denied hook paths to ``denied``. Late read failures
    degrade to unreadable marks, which are not privilege facts.
    """
    var marks = _HookMarks(
        String(""), String(""), String(""), False,
        String(""), String(""), String(""), False,
        String(""), False, String(""), False,
        String(""), False,
    )
    var n = len(decision.profile.caps[cap_index].hooks)
    for r in range(n):
        var want = decision.profile.caps[cap_index].hooks[r]
        var found = -1
        for h in range(len(decision.profile.hooks)):
            if decision.profile.hooks[h].name == want:
                found = h
                break
        if found < 0:
            # Unreachable via load_profiles (the parser rejects
            # dangling refs). Fail closed as unverifiable rather
            # than skipping the reference silently.
            if not marks.has_bare:
                marks.has_bare = True
                marks.bare_hook = want
            continue
        var hname = decision.profile.hooks[found].name
        var id_path = decision.profile.hooks[found].id_path
        var fmt_path = decision.profile.hooks[found].format_path
        var id_st = file_state(reader, id_path)
        if id_st == EVIDENCE_ABSENT and not marks.has_absent:
            marks.has_absent = True
            marks.absent_hook = hname
            marks.absent_which = String("id")
            marks.absent_path = id_path
        elif id_st == EVIDENCE_DENIED:
            denied.append(id_path)
            if not marks.has_denied:
                marks.has_denied = True
                marks.denied_hook = hname
                marks.denied_which = String("id")
                marks.denied_path = id_path
        var fmt_st = file_state(reader, fmt_path)
        if fmt_st == EVIDENCE_ABSENT and not marks.has_absent:
            marks.has_absent = True
            marks.absent_hook = hname
            marks.absent_which = String("format")
            marks.absent_path = fmt_path
        elif fmt_st == EVIDENCE_DENIED:
            denied.append(fmt_path)
            if not marks.has_denied:
                marks.has_denied = True
                marks.denied_hook = hname
                marks.denied_which = String("format")
                marks.denied_path = fmt_path
        # The format comparison depends only on the format file
        # itself: a denied or absent id must not hide a readable
        # signature change. Severity combination stays in
        # _judge_declared (absent beats changed beats the rest).
        if fmt_st != EVIDENCE_OK:
            continue
        if not decision.profile.hooks[found].format_has:
            if not marks.has_bare:
                marks.has_bare = True
                marks.bare_hook = hname
            continue
        try:
            var got = read_evidence(reader, fmt_path, _FORMAT_CAP)
            var want_text = decision.profile.hooks[found].format_text
            if not _bytes_equal_text(got^, want_text):
                if not marks.has_changed:
                    marks.has_changed = True
                    marks.changed_hook = hname
        except:
            if not marks.has_unread:
                marks.has_unread = True
                marks.unread_hook = hname
    return marks^


def _judge_declared(
    reader: EvidenceReader,
    decision: ProfileDecision,
    cap_index: Int,
    mut denied: List[String],
) -> CapEntry:
    """Judge one declared capability from its hook probes."""
    var cap_id = decision.profile.caps[cap_index].id
    var declared = decision.profile.caps[cap_index].status
    var profile_id = decision.profile.profile_id
    if declared == "unsupported":
        return CapEntry(
            cap_id,
            String("unsupported"),
            decision.profile.caps[cap_index].reason,
        )
    var marks = _probe_hooks(reader, decision, cap_index, denied)
    if marks.has_absent:
        return CapEntry(
            cap_id,
            String("unavailable"),
            "hook "
            + marks.absent_hook
            + " "
            + marks.absent_which
            + " "
            + marks.absent_path
            + " absent",
        )
    if marks.has_changed:
        return CapEntry(
            cap_id,
            String("unavailable"),
            "hook "
            + marks.changed_hook
            + " format differs from profile "
            + profile_id
            + " signature",
        )
    if marks.has_unread:
        return CapEntry(
            cap_id,
            String("unknown"),
            "hook " + marks.unread_hook + " format unreadable after probe",
        )
    if marks.has_denied:
        return CapEntry(
            cap_id,
            String("unknown"),
            "hook "
            + marks.denied_hook
            + " "
            + marks.denied_which
            + " "
            + marks.denied_path
            + " denied (privilege)",
        )
    if marks.has_bare:
        return CapEntry(
            cap_id,
            String("unknown"),
            "hook "
            + marks.bare_hook
            + " has no recorded format in profile "
            + profile_id,
        )
    if declared == "candidate":
        if decision.matched:
            return CapEntry(
                cap_id,
                String("unknown"),
                "candidate under validated profile "
                + profile_id
                + ": hooks present, support unproven",
            )
        return CapEntry(
            cap_id,
            String("unknown"),
            "candidate under reference-unvalidated profile "
            + profile_id
            + ": hooks present, semantics unproven",
        )
    if decision.matched:
        return CapEntry(
            cap_id,
            String("available"),
            "verified under validated profile " + profile_id,
        )
    return CapEntry(
        cap_id,
        String("unknown"),
        "supported hooks present but profile "
        + profile_id
        + " is not validated",
    )


def _judge_one(
    reader: EvidenceReader,
    decision: ProfileDecision,
    cap_id: String,
    mut denied: List[String],
) -> CapEntry:
    """Judge one known capability id against the covering profile."""
    if not decision.has_profile:
        return CapEntry(
            cap_id, String("unknown"), String("no profile covers this identity")
        )
    var at = -1
    for c in range(len(decision.profile.caps)):
        if decision.profile.caps[c].id == cap_id:
            at = c
            break
    if at < 0:
        return CapEntry(
            cap_id,
            String("unknown"),
            "profile "
            + decision.profile.profile_id
            + " does not declare "
            + cap_id,
        )
    return _judge_declared(reader, decision, at, denied)


def discover_capabilities(
    reader: EvidenceReader, decision: ProfileDecision
) -> CapabilityReport:
    """Judge the known capabilities. Never raises.

    The known universe is the schema's three ids; a profile that
    omits one leaves it unknown. When the kernel floor fails,
    ``attempt-trace`` demotes to unavailable with the floor reason
    and any other available judgment demotes the same way; other
    unknown and unsupported judgments stand.
    """
    var denied = List[String]()
    var entries = List[CapEntry]()
    var triple = parse_kernel_triple(reader.release)
    var floor_ok = triple.ok and triple.major >= 7
    var ids = List[String]()
    ids.append(String("attempt-trace"))
    ids.append(String("mapping-lifecycle"))
    ids.append(String("copy-actual"))
    for k in range(len(ids)):
        var entry = _judge_one(reader, decision, ids[k], denied)
        if not floor_ok:
            if not triple.ok and entry.id == "attempt-trace":
                entry = CapEntry(
                    entry.id,
                    String("unknown"),
                    "release "
                    + reader.release
                    + " is unparseable; floor unknown",
                )
            elif (
                triple.ok
                and entry.status != "unsupported"
                and (
                    entry.id == "attempt-trace"
                    or entry.status == "available"
                )
            ):
                entry = CapEntry(
                    entry.id,
                    String("unavailable"),
                    "kernel "
                    + reader.release
                    + " is below the 7.0 floor",
                )
        entries.append(entry^)
    return CapabilityReport(entries^, denied^)
