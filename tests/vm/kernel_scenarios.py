#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Detection scenario table and pure predicates.

Pure offline logic for the tools/kernel-matrix scenario
mode. No boot, no network, no privileged reads.
"""

import json
import re

from kernel_matrix import CAPS, record_code

SCENARIO_ORDER = (
    "base",
    "neg-renamed",
    "neg-layout",
    "neg-shift",
    "neg-argcnt",
    "nonroot",
    "nocaps",
    "ftrace-off",
    "tracefs-unmounted",
    "btf-empty",
    "btf-truncated",
    "memcg",
)

REFUSED_STATUSES = ("unavailable", "unknown")

EXECUTED_BYTE_METRICS = (
    "copy_original_to_bounce_bytes",
    "copy_bounce_to_original_bytes",
    "copy_private_pool_bytes",
)

ALLOWED_PAIRS = {
    "nocaps": frozenset({("no-bpf-privilege", "load-eperm")}),
    "memcg": frozenset({("available", "load-enomem")}),
    "neg-renamed": frozenset({("available",
                               "verifier-rejected")}),
}

_MIB = 1048576


def _alu():
    return ("available-load-unchecked", "available")


def _avail(reason_route="available"):
    return ("available", reason_route)


SCENARIOS = {
    "base": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"all": _avail()},
        "load_verdict": "ready",
        "record": {"finalize": True},
        "exits": ("0", "0", "4"),
        "workload": True,
        "capture": "base",
    },
    "neg-renamed": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"caps": {
            "attempt-trace": _avail(),
            "mapping-lifecycle": _avail(),
            "copy-actual": ("unavailable",
                            "verifier-rejected")}},
        "load_verdict": "unavailable",
        "record": {"refuse": "verifier-rejected"},
        "exits": ("0", "3", "3"),
        "workload": False,
        "capture": None,
        "negative": "renamed_field",
    },
    "neg-layout": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"all": _avail()},
        "load_verdict": "ready",
        "record": {"finalize": True},
        "exits": ("0", "0", "4"),
        "workload": True,
        "capture": "neg-layout",
        "cause": "LAYOUT",
        "unknown_key": "copy.unknown_layout",
        "negative": "widened_layout",
    },
    "neg-shift": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"all": _avail()},
        "load_verdict": "ready",
        "record": {"finalize": True},
        "exits": ("0", "0", "4"),
        "workload": True,
        "capture": "neg-shift",
        "cause": "SHIFT",
        "unknown_key": "copy.unknown_shift",
        "negative": "wrong_shift",
    },
    "neg-argcnt": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"all": _avail()},
        "load_verdict": "ready",
        "record": {"finalize": True},
        "exits": ("0", "0", "4"),
        "workload": True,
        "capture": "neg-argcnt",
        "cause": "argument count mismatch",
        "unknown_key": None,
        "negative": "wrong_argcnt",
    },
    "nonroot": {
        "passive": {"all": ("unknown", "tracefs-denied")},
        "passive_verdict": "unavailable",
        "load": {"all": ("unknown", "tracefs-denied")},
        "load_verdict": "unavailable",
        "record": {"refuse": "tracefs-denied"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "nocaps": {
        "passive": {"all": ("unavailable",
                            "no-bpf-privilege")},
        "passive_verdict": "unavailable",
        "load": {"all": ("unavailable", "load-eperm")},
        "load_verdict": "unavailable",
        "record": {"refuse": "load-eperm"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "ftrace-off": {
        "passive": {"caps": {
            "attempt-trace": _alu(),
            "mapping-lifecycle": (None, "ftrace-disabled"),
            "copy-actual": (None, "ftrace-disabled")}},
        "passive_verdict": "unavailable",
        "load": {"caps": {
            "attempt-trace": _avail(),
            "mapping-lifecycle": (None, "ftrace-disabled"),
            "copy-actual": (None, "ftrace-disabled")}},
        "load_verdict": "unavailable",
        "record": {"refuse": "ftrace-disabled"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "tracefs-unmounted": {
        "passive": {"all": (None, "tracefs-not-mounted")},
        "passive_verdict": "unavailable",
        "load": {"all": (None, "tracefs-not-mounted")},
        "load_verdict": "unavailable",
        "record": {"refuse": "tracefs-not-mounted"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "btf-empty": {
        "passive": {"caps": {
            "attempt-trace": _alu(),
            "mapping-lifecycle": ("unknown",
                                  "btf-truncated"),
            "copy-actual": ("unknown", "btf-truncated")}},
        "passive_verdict": "unavailable",
        "load": {"caps": {
            "attempt-trace": _avail(),
            "mapping-lifecycle": ("unknown",
                                  "btf-truncated"),
            "copy-actual": ("unknown", "btf-truncated")}},
        "load_verdict": "unavailable",
        "record": {"refuse": "btf-truncated"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "btf-truncated": {
        "passive": {"caps": {
            "attempt-trace": _alu(),
            "mapping-lifecycle": ("unknown",
                                  "btf-truncated"),
            "copy-actual": ("unknown", "btf-truncated")}},
        "passive_verdict": "unavailable",
        "load": {"caps": {
            "attempt-trace": _avail(),
            "mapping-lifecycle": ("unknown",
                                  "btf-truncated"),
            "copy-actual": ("unknown", "btf-truncated")}},
        "load_verdict": "unavailable",
        "record": {"refuse": "btf-truncated"},
        "exits": ("3", "3", "3"),
        "workload": False,
        "capture": None,
    },
    "memcg": {
        "passive": {"all": _alu()},
        "passive_verdict": "ready-load-unchecked",
        "load": {"any_enomem": True},
        "load_verdict": "unavailable",
        "record": {"refuse": "load-enomem"},
        "exits": ("0", "3", "3"),
        "workload": False,
        "capture": None,
    },
}


def scenarios_row_admitted(entry):
    """True only when all three capabilities are admitted."""
    try:
        expected = entry["expected"]
    except (KeyError, TypeError):
        return False
    for cap in CAPS:
        want = expected.get(cap, {})
        if want.get("verdict") != "admitted":
            return False
    return True


def check_expectation_table():
    """Table faults: every scenario needs P, L, record, exits."""
    fails = []
    for name in SCENARIO_ORDER:
        spec = SCENARIOS.get(name)
        if spec is None:
            fails.append("%s: missing from SCENARIOS" % name)
            continue
        for key in ("passive", "load", "record", "exits",
                    "passive_verdict", "load_verdict"):
            if key not in spec:
                fails.append("%s: missing %s" % (name, key))
        for side in ("passive", "load"):
            exp = spec.get(side, {})
            if "all" in exp:
                continue
            if side == "load" and exp.get("any_enomem"):
                continue
            caps = exp.get("caps", {})
            for cap in CAPS:
                if cap not in caps:
                    fails.append("%s: %s lacks %s"
                                 % (name, side, cap))
        rec = spec.get("record", {})
        if ("refuse" in rec) == ("finalize" in rec):
            fails.append("%s: record needs refuse xor finalize"
                         % name)
        exits = spec.get("exits", ())
        if len(exits) != 3 \
                or any(e not in ("0", "3", "4")
                       for e in exits):
            fails.append("%s: bad exits %r" % (name, exits))
    for name in SCENARIOS:
        if name not in SCENARIO_ORDER:
            fails.append("%s: missing from SCENARIO_ORDER"
                         % name)
    return fails


def _caps_of(doc):
    caps = {}
    for cap in doc.get("capabilities", []):
        if isinstance(cap, dict) and cap.get("id") in CAPS:
            caps[cap["id"]] = cap
    return caps


def check_doctor_caps(doc, expectation, mode, verdict,
                      precheck=None):
    """One doctor document matches its scenario expectation.

    A None status accepts any refused status; codes are
    always exact.
    """
    if not isinstance(doc, dict):
        return False, "doctor is not an object"
    if doc.get("mode") != mode:
        return False, "mode %r want %s" % (doc.get("mode"),
                                           mode)
    if doc.get("verdict") != verdict:
        return False, "verdict %r want %s" % (
            doc.get("verdict"), verdict)
    got = _caps_of(doc)
    if "all" in expectation:
        want = {cap: expectation["all"] for cap in CAPS}
    else:
        want = expectation.get("caps", {})
    for cap in CAPS:
        if cap not in got:
            return False, "%s missing from doctor" % cap
        if cap not in want:
            return False, "no expectation for %s" % cap
        status, code = want[cap]
        if status is None:
            if got[cap].get("status") not in REFUSED_STATUSES:
                return False, "%s status %r want refused" % (
                    cap, got[cap].get("status"))
        elif got[cap].get("status") != status:
            return False, "%s status %r want %s" % (
                cap, got[cap].get("status"), status)
        if got[cap].get("reason_code") != code:
            return False, "%s code %r want %s" % (
                cap, got[cap].get("reason_code"), code)
    if precheck is not None:
        want_id, want_state, want_code = precheck
        for entry in doc.get("prechecks", []):
            if not isinstance(entry, dict):
                continue
            if entry.get("id") != want_id:
                continue
            if entry.get("state") != want_state \
                    or entry.get("code") != want_code:
                return False, "precheck %s is %s/%s" % (
                    want_id, entry.get("state"),
                    entry.get("code"))
            break
        else:
            return False, "precheck %s missing" % want_id
    return True, "doctor matches"


def check_memcg_load(doc, verdict):
    """Load-check under a memory limit: ENOMEM somewhere.

    At least one component refuses load-enomem; every
    other component is either available or refuses the
    same way. Any other code is not the memcg effect.
    """
    if not isinstance(doc, dict):
        return False, "doctor is not an object"
    if doc.get("mode") != "load-check":
        return False, "mode %r want load-check" % (
            doc.get("mode"),)
    if doc.get("verdict") != verdict:
        return False, "verdict %r want %s" % (
            doc.get("verdict"), verdict)
    got = _caps_of(doc)
    refused = 0
    for cap in CAPS:
        if cap not in got:
            return False, "%s missing from doctor" % cap
        status = got[cap].get("status")
        code = got[cap].get("reason_code")
        if status == "available" and code == "available":
            continue
        if status in REFUSED_STATUSES \
                and code == "load-enomem":
            refused += 1
            continue
        return False, "%s is %s/%s, want available or " \
            "load-enomem" % (cap, status, code)
    if refused < 1:
        return False, "no component refuses load-enomem"
    return True, "load refuses load-enomem (%d of %d)" % (
        refused, len(CAPS))


def first_refused_code(load_doc):
    """Load-check code of the first refused cap, or None."""
    got = _caps_of(load_doc)
    for cap in CAPS:
        entry = got.get(cap)
        if entry is None:
            return None
        if entry.get("status") != "available":
            return entry.get("reason_code")
    return None


def check_agreement(scenario, passive_doc, load_doc,
                    record_out):
    """Passive/load codes agree; record follows the first refusal.

    Equal codes always agree; differing pairs must be
    allowlisted for the scenario. A refused record carries
    the load-check code of the first refused capability in
    record order; a finalized record prints no code line.
    """
    spec = SCENARIOS.get(scenario)
    if spec is None:
        return False, "unknown scenario %s" % scenario
    allowed = ALLOWED_PAIRS.get(scenario, frozenset())
    pgot = _caps_of(passive_doc)
    lgot = _caps_of(load_doc)
    for cap in CAPS:
        pentry = pgot.get(cap)
        lentry = lgot.get(cap)
        if pentry is None or lentry is None:
            return False, "%s missing from a doctor" % cap
        pcode = pentry.get("reason_code")
        lcode = lentry.get("reason_code")
        if pcode != lcode and (pcode, lcode) not in allowed:
            return False, "%s pair (%r, %r) not allowed" % (
                cap, pcode, lcode)
    try:
        rcode = record_code(record_out)
    except ValueError as exc:
        return False, "record code: %s" % exc
    if "finalize" in spec["record"]:
        if rcode is not None:
            return False, "finalized record prints code %r" \
                % (rcode,)
        return True, "codes agree, no record code line"
    want = first_refused_code(load_doc)
    if want is None:
        return False, "record refused but load admits all"
    if rcode != want:
        return False, "record code %r want %r (first " \
            "refused)" % (rcode, want)
    return True, "record code follows first refusal"


def check_record_refusal(record, want_code):
    """One refusal: exit 3, exact code line, no output dir."""
    if (record.get("exit") or "").strip() != "3":
        return False, "exit %r want 3" % (
            record.get("exit") or "",)
    try:
        got = record_code(record.get("out"))
    except ValueError as exc:
        return False, "record code: %s" % exc
    if got != want_code:
        return False, "record code %r want %r" % (got,
                                                 want_code)
    if (record.get("exists") or "").strip() != "no":
        return False, "left partial capture"
    return True, "refused exit 3 (%s)" % want_code


def check_record_finalized(record, want_exit="4"):
    """One capture: exact exit, output dir present."""
    if (record.get("exit") or "").strip() != want_exit:
        return False, "exit %r want %s" % (
            record.get("exit") or "", want_exit)
    if (record.get("exists") or "").strip() != "yes":
        return False, "capture dir missing"
    return True, "finalized exit %s" % want_exit


def _count_kinds(events_text):
    """Kind counts over events lines, None when corrupt."""
    counts = {}
    for line in (events_text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            return None
        if not isinstance(doc, dict):
            return None
        kind = doc.get("kind")
        counts[kind] = counts.get(kind, 0) + 1
    return counts


def _evidence_map(session):
    out = {}
    evidence = session.get("environment", {}).get(
        "evidence", [])
    for item in evidence:
        if isinstance(item, dict) and "source" in item:
            out[item["source"]] = item.get("interpretation")
    return out


def _workload_ok(cap):
    if (cap.get("workload_exit") or "").strip() != "0":
        return False
    out = cap.get("workload_out") or ""
    return "phase scn " in out and "buf scn " in out


_METRIC_LINE = re.compile(
    r"^  ([A-Za-z0-9_]+)(?:\[[^\]]*\])? = (\S+)")


def check_capture(scenario, cap):
    """Base and negative capture rules over raw evidence."""
    spec = SCENARIOS.get(scenario) or {}
    kind = spec.get("capture")
    if kind is None:
        return False, "scenario %s has no capture rule" % (
            scenario,)
    try:
        session = json.loads(cap.get("session_text") or "")
    except ValueError:
        return False, "session.json bad"
    if not isinstance(session, dict):
        return False, "session.json is not an object"
    counts = _count_kinds(cap.get("events_text"))
    if counts is None:
        return False, "events.ndjson corrupt"
    if cap.get("validate_rc") != 0:
        return False, "capture invalid (rc=%r)" % (
            cap.get("validate_rc"),)
    if kind == "base":
        if counts.get("bounce_attempt", 0) <= 0:
            return False, "no attempt records"
        if counts.get("copy", 0) <= 0:
            return False, "no copy records"
        return True, "base capture holds attempts and copies"
    if counts.get("copy", 0) != 0:
        return False, "%d copy records persisted" % (
            counts.get("copy", 0),)
    try:
        copy_cap = session["capabilities"]["copy_bytes"]
        detail = session["quality"]["detail"]
    except (KeyError, TypeError):
        return False, "session lacks copy_bytes or detail"
    if not isinstance(copy_cap, dict) \
            or not isinstance(detail, dict):
        return False, "session lacks copy_bytes or detail"
    if copy_cap.get("status") == "complete":
        return False, "copy_bytes reads complete"
    cause = spec.get("cause", "")
    if cause not in (detail.get("reason") or ""):
        return False, "detail reason lacks %r" % (cause,)
    evidence = _evidence_map(session)
    unknown_key = spec.get("unknown_key")
    if unknown_key is not None:
        try:
            unknown = int(evidence.get(unknown_key))
        except (TypeError, ValueError):
            return False, "%s missing" % unknown_key
        if unknown <= 0:
            return False, "%s is 0" % unknown_key
    elif detail.get("loss_count") is not None:
        return False, "copy loss claimed known"
    if counts.get("map_result", 0) <= 0:
        return False, "no lifecycle maps (workload never ran)"
    if not _workload_ok(cap):
        return False, "workload evidence missing"
    if evidence.get("cp.object.sha256") != cap.get(
            "object_sha"):
        return False, "copy object sha mismatch"
    try:
        report = json.loads(cap.get("report_json_text") or "")
    except ValueError:
        return False, "report.json bad"
    if not isinstance(report, dict):
        return False, "report.json is not an object"
    for metric in report.get("metrics", []):
        if not isinstance(metric, dict):
            continue
        if metric.get("name") not in EXECUTED_BYTE_METRICS:
            continue
        if metric.get("value") is not None:
            return False, "report %s = %r" % (
                metric.get("name"), metric.get("value"))
        if metric.get("measurement") != "unavailable":
            return False, "report %s measurement %r" % (
                metric.get("name"),
                metric.get("measurement"))
    for line in (cap.get("report_text") or "").splitlines():
        hit = _METRIC_LINE.match(line)
        if hit and hit.group(1) in EXECUTED_BYTE_METRICS \
                and hit.group(2) != "unavailable":
            return False, "text presents %s" % line.strip()
        if re.search(r"\d+ copy bytes lack device "
                     r"attribution", line):
            return False, "unattributed copy bytes line " \
                "present"
    return True, "negative capture degrades honestly"


def memcg_limit(p0, r0, p1):
    """Calibrated memcg limit: midpoint rounded down to a page.

    The kernel stores memory.max page-aligned, so the
    written limit is already a whole number of pages and
    reads back exactly.
    """
    return ((max(p0, r0) + p1) // 2) // 4096 * 4096


def _memcg_attempt_ok(pre):
    """Calibrated memcg attempt facts, or (None, detail)."""
    attempt = pre.get("attempt")
    if not isinstance(attempt, dict):
        return None, "memcg attempt missing"
    try:
        p0 = int(attempt["p0"])
        p1 = int(attempt["p1"])
        r0 = int(attempt["r0"])
        limit = int(attempt["limit"])
    except (KeyError, TypeError, ValueError):
        return None, "memcg calibration not integers"
    if p1 - p0 < 8 * _MIB:
        return None, "memcg calibration spans %d bytes" % (
            p1 - p0,)
    if not r0 < p1:
        return None, "memcg record peak over load peak"
    if not r0 < limit:
        return None, "memcg record peak over limit"
    if limit != memcg_limit(p0, r0, p1):
        return None, "memcg limit is not the midpoint"
    if "mvt_small" not in (attempt.get("cgroup") or ""):
        return None, "cgroup does not name mvt_small"
    if (attempt.get("memory_max") or "").strip() != str(
            limit):
        return None, "memory.max does not read back"
    return attempt, "memcg calibrated"


def _memcg_invalid(attempt):
    """Invalidity evidence for one attempt, else None."""
    try:
        before = int(attempt["oom_before"])
        after = int(attempt["oom_after"])
    except (KeyError, TypeError, ValueError):
        return "oom counters missing"
    if after - before > 0:
        return "oom_kill delta %d" % (after - before,)
    for exit_text in attempt.get("exits", []):
        if (exit_text or "").strip().startswith("-"):
            return "signal exit %s" % exit_text.strip()
    return None


def check_precondition(scenario, pre, job=None):
    """Setup proof for one scenario."""
    if not isinstance(pre, dict):
        return False, "precondition missing"
    if scenario == "base":
        if pre.get("verdict") != "ready-load-unchecked":
            return False, "base verdict %r" % (
                pre.get("verdict"),)
        return True, "base positive control ready"
    if scenario.startswith("neg-"):
        spec = SCENARIOS.get(scenario) or {}
        want = (job or {}).get(spec.get("negative"))
        if not want:
            return False, "job carries no %s sha" % (
                spec.get("negative"),)
        if pre.get("object_sha") != want:
            return False, "object sha does not match the job"
        return True, "negative object matches job"
    if scenario == "nonroot":
        if pre.get("uid") != 65534:
            return False, "uid %r" % (pre.get("uid"),)
        if pre.get("root") not in ("debug", "sys"):
            return False, "no tracefs root to deny"
        if pre.get("events_readable") is not False:
            return False, "events readable as nobody"
        return True, "nobody denied tracefs events"
    if scenario == "nocaps":
        try:
            eff = int((pre.get("capeff") or "").strip(), 16)
        except ValueError:
            return False, "CapEff %r unparseable" % (
                pre.get("capeff"),)
        if eff != 0:
            return False, "CapEff %s, want 0" % (
                (pre.get("capeff") or "").strip(),)
        return True, "CapEff 0 in the dropped child"
    if scenario == "ftrace-off":
        if (pre.get("ftrace_enabled") or "").strip() != "0":
            return False, "ftrace_enabled %r" % (
                pre.get("ftrace_enabled"),)
        return True, "tracing disabled"
    if scenario == "tracefs-unmounted":
        mounts = pre.get("mounts") or ""
        for line in mounts.splitlines():
            fields = line.split()
            if len(fields) >= 3 and fields[2] in (
                    "tracefs", "debugfs"):
                return False, "still mounted: %s" % line
        if pre.get("events_present") is not False:
            return False, "events still present"
        return True, "no tracefs or debugfs mount"
    if scenario == "btf-empty":
        if pre.get("size") != 0:
            return False, "btf size %r" % (pre.get("size"),)
        return True, "btf reads empty"
    if scenario == "btf-truncated":
        try:
            size = int(pre.get("size"))
            orig = int(pre.get("orig_size"))
        except (TypeError, ValueError):
            return False, "btf sizes not integers"
        if orig < 2 or size != orig // 2:
            return False, "btf size %r is not half of %r" % (
                size, orig)
        if pre.get("head_equal") is not True:
            return False, "btf head differs"
        return True, "btf reads a truncated half"
    if scenario == "memcg":
        attempt, detail = _memcg_attempt_ok(pre)
        if attempt is None:
            return False, detail
        return True, detail
    return False, "unknown scenario %s" % scenario


def check_teardown(teardown, base_verdict):
    """Post-teardown passive verdict equals the base verdict."""
    if not isinstance(teardown, dict):
        return False, "teardown missing"
    if teardown.get("verdict") != base_verdict:
        return False, "verdict %r want base %r" % (
            teardown.get("verdict"), base_verdict)
    return True, "teardown restores base verdict"


def _memcg_not_proven(memcg):
    """Not-proven verification over recorded attempts."""
    if not isinstance(memcg, dict):
        return False, "memcg evidence missing"
    if memcg.get("status") != "not_proven":
        return False, "memcg claims %r" % (
            memcg.get("status"),)
    attempts = memcg.get("attempts")
    if not isinstance(attempts, list) or len(attempts) < 2:
        return False, "not_proven needs two attempts"
    for attempt in attempts:
        cal, detail = _memcg_attempt_ok(
            {"attempt": attempt})
        if cal is None:
            return False, "attempt uncalibrated: %s" % detail
        invalid = _memcg_invalid(attempt)
        exits = attempt.get("exits") or []
        if len(exits) > 2 and isinstance(exits[2], str):
            record_exit = exits[2].strip()
        else:
            record_exit = None
        if record_exit is None:
            return False, "record exit missing"
        if invalid is None and record_exit == "3":
            return False, "attempt valid and refused, " \
                "not_proven void"
    return True, "two calibrated runs, none valid and refused"


def _nocaps_not_proven(pre):
    """Not-proven verification over the drop proof."""
    if not isinstance(pre, dict):
        return False, "precondition missing"
    if (pre.get("probe_exit") or "").strip() != "0":
        return False, "drop probe exit %r" % (
            pre.get("probe_exit"),)
    try:
        eff = int((pre.get("capeff") or "").strip(), 16)
    except ValueError:
        return False, "CapEff %r unparseable" % (
            pre.get("capeff"),)
    if eff == 0:
        return False, "CapEff 0, not_proven void"
    return True, "CapEff %s, want 0" % (
        (pre.get("capeff") or "").strip(),)


def evaluate_scenario(name, ev):
    """Judge one scenario; return a status record.

    Status is ok, fail, or (memcg/nocaps) not_proven.
    Checks are precondition, doctor_passive,
    doctor_passive_exit, doctor_load, doctor_load_exit,
    record, agreement, capture, teardown; capture runs
    only where the table gives a capture rule.
    """
    spec = SCENARIOS.get(name)
    checks = []

    def add(check_name, ok, detail, skipped=False):
        checks.append({"name": check_name, "ok": bool(ok),
                       "detail": detail, "skipped": bool(
                           skipped)})

    if spec is None:
        add("precondition", False, "unknown scenario %s"
            % name)
        return {"name": name, "ok": False, "status": "fail",
                "checks": checks}
    if name == "memcg" and isinstance(ev.get("memcg"), dict) \
            and ev["memcg"].get("status") == "not_proven":
        ok, detail = _memcg_not_proven(ev["memcg"])
        add("precondition", ok, detail)
        for check_name in ("doctor_passive",
                           "doctor_passive_exit",
                           "doctor_load", "doctor_load_exit",
                           "record", "agreement", "capture",
                           "teardown"):
            add(check_name, ok, detail,
                skipped=True)
        return {"name": name, "ok": False,
                "status": "not_proven" if ok else "fail",
                "checks": checks}
    if name == "nocaps":
        pre_ok, _ = check_precondition(
            name, ev.get("precondition"),
            ev.get("job_negatives"))
        if not pre_ok:
            ok, detail = _nocaps_not_proven(
                ev.get("precondition"))
            add("precondition", ok, detail)
            for check_name in ("doctor_passive",
                               "doctor_passive_exit",
                               "doctor_load",
                               "doctor_load_exit",
                               "record", "agreement",
                               "capture", "teardown"):
                add(check_name, ok, detail,
                    skipped=True)
            return {"name": name, "ok": False,
                    "status": "not_proven" if ok else "fail",
                    "checks": checks}
    ok, detail = check_precondition(
        name, ev.get("precondition"), ev.get("job_negatives"))
    add("precondition", ok, detail)
    try:
        passive = json.loads(ev["passive"]["text"])
    except (KeyError, TypeError, ValueError):
        passive = None
    if passive is None:
        add("doctor_passive", False, "passive doctor bad")
    else:
        ok, detail = check_doctor_caps(
            passive, spec["passive"], "passive",
            spec["passive_verdict"],
            spec.get("passive_precheck"))
        if ok and not ev.get("passive_schema"):
            ok, detail = False, "passive doctor fails schema"
        add("doctor_passive", ok, detail)
    want_passive_exit = spec["exits"][0]
    passive_exit = (ev.get("passive") or {}).get("exit", "")
    passive_exit = (passive_exit or "").strip()
    add("doctor_passive_exit",
        passive_exit == want_passive_exit,
        "passive doctor exit %s want %s" % (
            passive_exit, want_passive_exit))
    try:
        load = json.loads(ev["load"]["text"])
    except (KeyError, TypeError, ValueError):
        load = None
    if load is None:
        add("doctor_load", False, "load doctor bad")
    elif spec["load"].get("any_enomem"):
        ok, detail = check_memcg_load(load,
                                      spec["load_verdict"])
        if ok and not ev.get("load_schema"):
            ok, detail = False, "load doctor fails schema"
        add("doctor_load", ok, detail)
    else:
        ok, detail = check_doctor_caps(
            load, spec["load"], "load-check",
            spec["load_verdict"])
        if ok and not ev.get("load_schema"):
            ok, detail = False, "load doctor fails schema"
        add("doctor_load", ok, detail)
    want_load_exit = spec["exits"][1]
    load_exit = (ev.get("load") or {}).get("exit", "")
    load_exit = (load_exit or "").strip()
    add("doctor_load_exit", load_exit == want_load_exit,
        "load doctor exit %s want %s" % (load_exit,
                                         want_load_exit))
    record = ev.get("record") or {}
    if "refuse" in spec["record"]:
        ok, detail = check_record_refusal(
            record, spec["record"]["refuse"])
    else:
        ok, detail = check_record_finalized(
            record, spec["exits"][2])
    add("record", ok, detail)
    if passive is None or load is None:
        add("agreement", False, "a doctor document is bad")
    else:
        ok, detail = check_agreement(
            name, passive, load, record.get("out"))
        add("agreement", ok, detail)
    if spec.get("capture") is None:
        add("capture", True, "scenario refuses, no capture",
            skipped=True)
    elif ev.get("capture") is None:
        add("capture", False, "capture evidence missing")
    else:
        ok, detail = check_capture(name, ev["capture"])
        add("capture", ok, detail)
    ok, detail = check_teardown(ev.get("teardown"),
                                ev.get("base_verdict"))
    add("teardown", ok, detail)
    if name == "memcg":
        picked = None
        memcg = ev.get("memcg")
        if isinstance(memcg, dict):
            attempts = memcg.get("attempts")
            chosen = memcg.get("chosen")
            if isinstance(attempts, list) \
                    and isinstance(chosen, int) \
                    and 0 <= chosen < len(attempts) \
                    and isinstance(attempts[chosen], dict):
                picked = attempts[chosen]
        if picked is None:
            invalid = "chosen attempt missing"
        else:
            invalid = _memcg_invalid(picked)
        if invalid is not None:
            for check in checks:
                if check["name"] == "record":
                    check["ok"] = False
                    check["detail"] = "run invalid " \
                        "(%s)" % (invalid,)
    good = all(check["ok"] for check in checks)
    return {"name": name, "ok": good,
            "status": "ok" if good else "fail",
            "checks": checks}


def evaluate_run(named):
    """Apply run cascades over evaluated scenarios.

    A broken base control fails every scenario; a failed
    teardown fails its scenario and every later one. The
    cascade lands as an explicit control check.
    """
    out = []
    base_ok = bool(named) and named[0][0] == "base" and \
        named[0][1]["ok"]
    poisoned = not base_ok
    for name, rec in named:
        checks = [dict(check) for check in rec["checks"]]
        status = rec["status"]
        if name != "base" and not base_ok:
            checks.append({"name": "control", "ok": False,
                           "detail": "base control failed",
                           "skipped": False})
            status = "fail"
        elif poisoned and name != "base":
            checks.append({"name": "control", "ok": False,
                           "detail": "earlier teardown not "
                                     "restored",
                           "skipped": False})
            status = "fail"
        if status == "fail" and any(
                check["name"] == "teardown"
                and not check["ok"] for check in checks):
            poisoned = True
        out.append({"name": name,
                    "ok": status == "ok", "status": status,
                    "checks": checks})
    return out


def scenarios_verdict(results):
    """Row verdict over scenario statuses.

    A row passes only with zero failures and zero
    not-proven scenarios; not_proven never passes.
    """
    ok_count = sum(1 for res in results
                   if res.get("status") == "ok")
    np_count = sum(1 for res in results
                   if res.get("status") == "not_proven")
    fail_count = sum(1 for res in results
                     if res.get("status") == "fail")
    ok = fail_count == 0 and np_count == 0
    return ok, "scenarios ok=%d fail=%d not_proven=%d" % (
        ok_count, fail_count, np_count)
