#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Scenario-battery runner for the blocked legs, case-selectable.

Unarmed (default) the runner self-tests offline: pinned-seal
verification, consumer build plus decoder vectors, C9
layouts, wrong-pair and malformed-wire refusals, manifest
checks, per-leg judge preservation on synthetic logs built
through the real consumer replay path, and refusal paths
for every selection and input error. No boot, no
privileges. Standalone:
`python3 tests/vm/test_battery.py [--self-test]`.

Armed (MEMVEIL_VM_BATTERY=1 with --case/--out, requiring a
live-VM lease) the runner boots the pinned guest once per
case, runs that case's choreography, re-derives every
verdict host-side from the exported observations, and
writes stamped receipts. --bundle/--candidate name the
retained seal explicitly and are required for every armed
run; --expect-release refuses when it conflicts with the
pinned guest release. The `saturation` case refuses until
the 4 KiB test objects plus the loader test layout land.
The guest command line carries only the staged inputs
filename: the full inputs doc travels through the shared
export dir, and any guest argv projecting past the kernel
command-line budget refuses before booting. Every boot
captures the guest console to the case transcript.
"""

import argparse
import ast
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))
import battery_core as core
import battery_guest
import guest_oracle
import stress_core as score
from consume import (parse_consume_file, parse_oracle_log,
                     scripted_expectation)
from test_canonical import (check_clamp_extras,
                            check_early_extras, check_window)
from test_copy_semantics import check_window as check_copy_window
from test_faults import judge_faults_capture
from test_lifecycle import check_step, expected_effective
from test_record3 import (_events, check_record3_capture)
from test_saturation import judge_saturation_flood
from test_stop_races import judge_stop_cycles

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "battery_guest.py"
ARM_ENV = "MEMVEIL_VM_BATTERY"
SPEC = REPO / "tests" / "vm" / "fixtures" / "canonical-expectations.json"

# The guest owns the canonical per-case inventory; the host
# judges exactly that list, never a private copy.
EXPORT_NAMES = {case: battery_guest.export_names_for_case(case)
                for case in core.CASES}

# Guest command-line budget. vng base64-encodes the whole
# --exec payload into virtme.exec= on the guest kernel
# command line, so the projected total is the fixed vng
# overhead plus 4*ceil(exec_chars/3), bounded by the x86
# COMMAND_LINE_SIZE of 2048. Past that the kernel
# truncates the exec and the guest hangs silently, so the
# runner refuses pre-boot instead. Dry-run measurements
# (vng 1.41, pinned guest row, --rwdir export shape) put
# the fixed overhead at 654 chars on microvm and 694 on
# the full-machine faults shape without verbose console
# capture, 626 and 666 with it; the constant below covers
# the worst measured shape plus host-path variance (the
# fixed part embeds host paths, so it shifts with the
# user and install locations). The exec budget is the
# largest payload with 768 + 4*ceil(n/3) <= 2048.
COMMAND_LINE_SIZE = 2048
VNG_CMDLINE_OVERHEAD = 768
GUEST_EXEC_BUDGET = 960
# Real-case guest argvs must project this far under the
# ceiling, so ordinary argv growth trips the offline test
# before it trips the kernel.
CMDLINE_HEADROOM = 400


def project_cmdline_total(exec_chars):
    """Projected kernel cmdline chars for an --exec payload.

    exec_chars is the length of the joined --exec string;
    vng base64-encodes those exact bytes into virtme.exec=.
    """
    return VNG_CMDLINE_OVERHEAD + 4 * ((exec_chars + 2) // 3)


def cmdline_over_budget(exec_chars):
    """True when a payload length must refuse pre-boot."""
    return project_cmdline_total(exec_chars) > COMMAND_LINE_SIZE


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def check(name, cond, detail=""):
    print("%s %s %s" % ("ok" if cond else "FAIL", name,
                        detail if not cond else ""))
    return bool(cond)


def consumer_run(args, timeout=120):
    return subprocess.run([score.CONSUMER_RELEASE] + args,
                          capture_output=True, text=True,
                          timeout=timeout)


# -- Synthetic windows (real consumer replay) ----------------

SIZES = (512, 1024, 2048, 4096)


def replay_consumer(tmp, tag, ring, wire, counts):
    """Decode synthetic wire through the real consumer."""
    wire_path = os.path.join(tmp, "%s.wire" % tag)
    with open(wire_path, "wb") as handle:
        handle.write(wire)
    out = os.path.join(tmp, "%s.txt" % tag)
    proc = consumer_run(["--replay", wire_path, ring, out,
                         "--counts", ",".join(
                             str(v) for v in counts)])
    if proc.returncode != 0:
        raise ValueError("replay %s failed: %s"
                         % (tag, proc.stdout.strip()[-200:]))
    return out


def scripted_wire(ops=4, fail_op=-1, drop_lc=(), drop_cp=(),
                  ktime_base=1000000, ktime_step=1000000,
                  skip_flip=()):
    """Scripted probe wire plus counts, with induced loss.

    Builds the exact 4-op scripted traffic the oracle
    module emits (map-time bounce before each map result,
    sync bounces after, releases paired by nonzero
    generation), dropping the named ordinals to model ring
    loss. drop_lc/drop_cp name lc/cp ordinal positions to
    omit; skip_flip names unmap ordinals whose skip bit
    clears. Returns (lc_wire, lc_counts, cp_wire,
    cp_counts).
    """
    lc_recs = []
    cp_recs = []
    gen = [0]

    def lc(kind, ok, skip, dirc, size, gen_v):
        gen[0] += 1
        ktime = ktime_base + gen[0] * ktime_step
        return (score.encode_lc(kind, ok, skip, dirc,
                                len(lc_recs), ktime, size,
                                gen_v), size)

    def cp(kind, todev, known, clamp, ezero, dirc, reason,
           req, eff):
        gen[0] += 1
        ktime = ktime_base + gen[0] * ktime_step
        return (score.encode_cp(kind, todev, known, clamp,
                                ezero, dirc, reason,
                                len(cp_recs), ktime, req,
                                eff), req)

    for i in range(ops):
        size = SIZES[i % len(SIZES)]
        direction = 2 if i % 2 else 1
        gen_v = i + 1
        if i != fail_op:
            cp_recs.append(cp(2, 1, True, False, False, 1,
                              0, size, size))
        else:
            # The fail probe's inner success still bounces.
            cp_recs.append(cp(2, 1, True, False, False, 1,
                              0, size, size))
        lc_recs.append(lc(1, True, False, direction, size,
                          gen_v))
        if i == fail_op:
            lc_recs.append(lc(2, True, True, direction,
                              size, gen_v))
            continue
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            # Sync todev follows for-device/for-cpu, not the
            # mapping direction: every for-device sync lands
            # in syncs_dev whatever its dir.
            cp_recs.append(cp(1, 1, False, False, False,
                              direction, 4, size, 0))
            if direction == 1:
                cp_recs.append(cp(2, 1, True, False, False,
                                  1, 0, size, size))
        cp_recs.append(cp(1, 0, False, False, False,
                          direction, 4, size, 0))
        if direction == 2:
            cp_recs.append(cp(2, 0, True, False, False, 2,
                              0, size, size))
        flip = len(lc_recs) in skip_flip
        lc_recs.append(lc(2, True, not flip, direction,
                          size, gen_v))

    def pack(recs, dropped, kind):
        kept = [rec for n, rec in enumerate(recs)
                if n not in dropped]
        # Ordinals are dense positions: dropped records
        # leave holes, so re-encode kept records with
        # their original ordinals.
        wire = b""
        total = 0
        for n, (blob, size) in enumerate(recs):
            if n in dropped:
                continue
            wire += blob
            total += size
        obs = len(recs)
        emit = len(kept)
        obsb = sum(size for _, size in recs)
        return wire, [obs, obsb, emit, total,
                      obs - emit, 0]

    lc_wire, lc_counts = pack(lc_recs, set(drop_lc), "lc")
    cp_wire, cp_counts = pack(cp_recs, set(drop_cp), "cp")
    return lc_wire, lc_counts, cp_wire, cp_counts


def oracle_script_log(ops=4, fail_op=-1, witness=False):
    """Synthetic mv-oracle: log for one scripted window."""
    lines = []
    for i in range(ops):
        size = SIZES[i % len(SIZES)]
        direction = 2 if i % 2 else 1
        lines.append("op=%d attempt requested=%d forced=0"
                     % (i, size))
        if i == fail_op:
            lines.append("op=%d outcome=failure rc=-EIO" % i)
            continue
        lines.append("op=%d outcome=success mapping=%d "
                     "mapped=%d" % (i, i, size))
        if witness:
            lines.append("op=%d mapping=%d witness copy=map "
                         "copied=%d verified=%d"
                         % (i, i, size, size))
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            lines.append("op=%d mapping=%d sync dir=%d "
                         "len=%d for=device"
                         % (i, i, direction, size))
            if witness and direction == 1:
                lines.append("op=%d mapping=%d witness "
                             "copy=sync copied=%d verified=%d"
                             % (i, i, size, size))
        if witness and direction == 2:
            lines.append("op=%d mapping=%d witness "
                         "copy=release copied=%d verified=%d"
                         % (i, i, size, size))
        lines.append("mapping=%d release lifetime_ns=%d"
                     % (i, 1000 + i))
    lines.append("script complete ops=%d" % ops)
    return "".join("[0.0] mv-oracle: %s\n" % line
                   for line in lines)


def oracle_canonical_log(spec):
    """Synthetic oracle log from one frozen canonical spec."""
    lines = []
    for key in sorted(spec["per_op"], key=int):
        i = int(key)
        want = spec["per_op"][key]
        lines.append("op=%d attempt requested=%d forced=0"
                     % (i, want["requested"]))
        lines.append("op=%d outcome=success mapping=%d "
                     "mapped=%d" % (i, i, want["requested"]))
        for copy, copied, verified in want["witness"]:
            extra = ""
            if copy == "clamped":
                extra = " pre=%d post=%d" % (verified,
                                             verified)
            if copy == "early":
                extra = " stale=%d" % copied
            lines.append("op=%d mapping=%d witness copy=%s "
                         "copied=%d verified=%d%s"
                         % (i, i, copy, copied, verified,
                            extra))
        stale = any(kind == "early" for kind, _, _
                      in want["witness"])
        for dirc, length in want["syncs"]:
            lines.append("op=%d mapping=%d sync dir=%d "
                         "len=%d for=device%s"
                         % (i, i, dirc, length,
                            " stale=1" if stale else ""))
        lines.append("mapping=%d release lifetime_ns=%d"
                     % (i, 1000 + i))
    lines.append("script complete ops=%d" % spec["ops"])
    return "".join("[0.0] mv-oracle: %s\n" % line
                   for line in lines)


def canonical_wire(spec, clamped=None, early=False,
                   ktime_base=1000000):
    """Synthetic probe wire from one frozen spec's multisets."""
    probes = spec["probes"]
    lc_recs = []
    cp_recs = []
    tick = [0]

    def ktime():
        tick[0] += 1
        return ktime_base + tick[0] * 1000000

    gen = [0]
    for size, dirc, ok in probes["maps"]:
        gen[0] += 1
        lc_recs.append((score.encode_lc(
            1, True, False, dirc, len(lc_recs),
            ktime(), size, gen[0]), size))
    for size, dirc, skip in probes["unmaps"]:
        lc_recs.append((score.encode_lc(
            2, True, bool(skip), dirc, len(lc_recs),
            ktime(), size, gen[0]), size))
    for req, dirc in probes["syncs_dev"]:
        cp_recs.append((score.encode_cp(
            1, 1, False, False, False, dirc, 4,
            len(cp_recs), ktime(), req, 0), req))
    for req, dirc in probes["syncs_cpu"]:
        cp_recs.append((score.encode_cp(
            1, 0, False, False, False, dirc, 4,
            len(cp_recs), ktime(), req, 0), req))
    early_left = 1 if early else 0
    for todev, req, dirc in probes["bounces"]:
        is_clamp = clamped is not None and req == clamped[0] \
            and todev == 1
        # The early window carries two identical bounce
        # tuples; exactly one is the early-zero copy.
        is_early = early_left > 0 and req == 2048 \
            and todev == 1
        if is_early:
            early_left -= 1
        eff = req
        clamp = 0
        ezero = 0
        if is_clamp:
            eff = clamped[1]
            clamp = 1
        if is_early:
            eff = 0
            ezero = 1
        cp_recs.append((score.encode_cp(
            2, todev, True, bool(clamp), bool(ezero),
            dirc, 0, len(cp_recs), ktime(), req, eff),
            req))

    def pack(recs):
        wire = b"".join(blob for blob, _ in recs)
        total = sum(size for _, size in recs)
        return wire, [len(recs), total, len(recs), total,
                      0, 0]

    return pack(lc_recs) + pack(cp_recs)


def synth_session(session_id="cap-synth-1", start_ns=1000000,
                  span_ns=30000000000, end_reason="duration",
                  detail_status="complete_for_scope",
                  loss_count="0", detail_reason=None,
                  aggregate_status="complete_for_scope",
                  aggregate_loss="0",
                  correlation="partial", terminal="partial",
                  decision=None):
    """Synthetic capture session with strict quality shapes."""
    if detail_reason is None:
        detail_reason = "detail loss 0 (submit_fail=(0) " \
            "malformed=(0) dropped=(0) " \
            "recursion_missed=(0) size_omitted=(0) " \
            "duration_omitted=(0) signal_omitted=(0) " \
            "rejected=(0) write_failed=(0))"
    corr_reason = "copy without pending operation; sync " \
        "references unknown mapping"
    if correlation == "not_applicable":
        corr_reason = "attempt counting needs no " \
            "cross-event correlation"
    return {
        "session_id": session_id,
        "capture": {
            "finalized": True,
            "end_reason": end_reason,
            "window": {"start_ns": str(start_ns),
                       "end_ns": str(start_ns + span_ns)},
        },
        "quality": {
            "detail": {"status": detail_status,
                       "loss_count": loss_count,
                       "reason": detail_reason},
            "aggregate": {"status": aggregate_status,
                          "loss_count": aggregate_loss,
                          "reason": "counter snapshots present "
                                    "(valid cut, identity holds, "
                                    "coverage valid)"},
            "correlation": {"status": correlation,
                            "reason": corr_reason},
            "terminal": {"status": terminal, "reason": ""},
        },
        "environment": {
            "evidence": [
                {"source": "profile.decision",
                 "interpretation": decision or
                 core.PROFILE_DECISION},
            ],
        },
    }


def synth_event(session_id, seq, ts_ns, kind, data):
    """Synthetic capture event with correlation source."""
    return {"session_id": session_id, "seq": seq,
            "ts_ns": ts_ns, "kind": kind, "data": data,
            "source": {"correlation": "paired"}}


def write_events(path, events):
    with open(path, "w") as handle:
        for event in events:
            handle.write(json.dumps(event,
                                    sort_keys=True) + "\n")


# -- Host judgment (one case from verified exports) ----------

def judge_identity(ident, manifest, case):
    """Recheck the exported guest identity host-side.

    Returns a reason list (empty ok): the booted release
    and the live BTF bytes must equal the pinned
    expectations, and every measured input digest must
    equal the manifest-bound bytes, independent of the
    guest's own gate. The saturation case measures the
    bound test objects instead of the sealed pair.
    """
    bad = []
    if ident.get("release") != core.EXPECT_RELEASE:
        bad.append("guest booted release %r, expected %r"
                   % (ident.get("release"),
                      core.EXPECT_RELEASE))
    if ident.get("btf_sha256") != \
            guest_oracle.GUEST_BTF_SHA256:
        bad.append("guest live BTF differs from the pinned "
                   "bytes")
    digests = ident.get("digests", {})
    oracle = manifest.get("oracle", {})
    if digests.get("ko") != oracle.get("ko_sha256"):
        bad.append("guest measured oracle bytes differ from "
                   "the pinned fixture")
    if case == "saturation":
        test_objects = manifest.get("test_objects", {})
        for channel in ("lc", "cp"):
            if digests.get("test-%s" % channel) != \
                    test_objects.get(channel, {}).get(
                        "sha256"):
                bad.append("guest measured %s test bytes "
                           "differ from the binding"
                           % channel)
        return bad
    objects = manifest.get("objects", {})
    for channel in ("lc", "cp"):
        if digests.get(channel) != objects.get(
                channel, {}).get("sha256"):
            bad.append("guest measured %s bytes differ from "
                       "the seal" % channel)
    return bad


def judge_record_identity(ident, manifest, files):
    """Identity plus record-leg input checks; reason list."""
    bad = judge_identity(ident, manifest, "record3")
    digests = ident.get("digests", {})
    if digests.get("attempt") != manifest.get(
            "objects", {}).get("attempt", {}).get("sha256"):
        bad.append("guest measured attempt bytes differ "
                   "from the seal")
    if digests.get("binary") != manifest.get(
            "binary", {}).get("sha256"):
        bad.append("guest measured binary bytes differ from "
                   "the seal")
    profile = manifest.get("profile", {})
    if digests.get("profile") != profile.get("sha256"):
        bad.append("guest measured profile bytes differ "
                   "from the bound profile")
    try:
        exported = json.loads(
            files["profile.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return bad + ["profile export unreadable: %s" % exc]
    if exported.get("profile_id") != core.PROFILE_ID:
        bad.append("exported profile id %r" %
                   exported.get("profile_id"))
    try:
        if sha_file(str(files["profile.json"])) != \
                profile.get("sha256"):
            bad.append("exported profile bytes differ from "
                       "the bound profile")
    except OSError as exc:
        bad.append("exported profile unreadable: %s" % exc)
    return bad


def judge_case(files, case, manifest):
    """Host re-derivation of one case; (reasons, metrics).

    Every verdict is re-derived here from the exported
    observations through the shared battery judges; the
    guest exports carry no verdicts.
    """
    try:
        ident = json.loads(
            files["identity.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return (["%s: identity unreadable: %s" % (case, exc)],
                {})
    if case in ("faults", "record3"):
        bad = judge_record_identity(ident, manifest, files)
    else:
        bad = judge_identity(ident, manifest, case)
    metrics = {}
    try:
        if case == "matrix":
            for delay_ms in (1000, 100, 10):
                try:
                    check_step(files, delay_ms)
                except AssertionError as exc:
                    bad.append(str(exc))
        elif case == "copy":
            for tag, fail_op in (("a", -1), ("b", 2)):
                try:
                    check_copy_window(files, tag, fail_op)
                except AssertionError as exc:
                    bad.append(str(exc))
        elif case in ("canonical-c", "canonical-e"):
            frozen = json.loads(SPEC.read_text())
            if frozen["frozen_for_module"] != "0.4.0":
                return (bad + ["%s: canonical spec drift"
                               % case], metrics)
            tag = "c" if case == "canonical-c" else "e"
            spec = frozen[tag]
            if tag == "c":
                reasons, _, _, ops, _ = check_window(
                    files, tag, spec, clamped=(4096, 1024))
                reasons += check_clamp_extras(ops, tag)
            else:
                reasons, _, _, ops, _ = check_window(
                    files, tag, spec, early=True)
                reasons += check_early_extras(ops, tag)
            bad += reasons
        elif case == "saturation":
            bad += judge_saturation_flood(files)
        elif case == "stop":
            ledger = json.loads(
                files["ledger.json"].read_text())
            bad += judge_stop_cycles(files, ledger)
        elif case == "faults":
            try:
                bad += judge_faults_capture(
                    files,
                    expect_decision=core.PROFILE_DECISION)
            except AssertionError as exc:
                bad.append(str(exc))
            bad += judge_faults_channels(files)
        elif case == "record3":
            bad += judge_record3_capture(files)
        elif case == "skipsync":
            bad += core.judge_skipsync(
                str(files["w-lc.txt"]), str(files["w-cp.txt"]),
                str(files["w-oracle.log"]), "w")
        else:
            bad.append("bad case %r" % (case,))
    except (ValueError, OSError, KeyError) as exc:
        bad.append("%s: case files unreadable: %s"
                   % (case, exc))
    return sorted(bad), metrics


def judge_record3_capture(files):
    """Record3 judgment: shared capture checks plus oracle ties."""
    bad = []
    try:
        record = json.loads(
            files["record.json"].read_text())
        session = json.loads(
            files["cap-session.json"].read_text())
        events = _events(str(files["cap-events.ndjson"]))
        ops_log, _, complete = parse_oracle_log(
            str(files["r3-oracle.log"]))
    except (ValueError, OSError, KeyError) as exc:
        return ["r3: capture files unreadable: %s" % exc]
    if not complete:
        bad.append("r3: oracle scenario 1 incomplete")
    if len(ops_log) != 2:
        bad.append("r3: oracle ops %r" % sorted(ops_log))
    if sorted(entry["requested"] for entry in
              ops_log.values()) != [1024, 4096]:
        bad.append("r3: oracle sizes %r" % (ops_log,))
    bad += check_record3_capture(
        events, session, record, "r3",
        expect_decision=core.PROFILE_DECISION)
    try:
        frozen = json.loads(SPEC.read_text())
        witnessed = frozen["n"]["witnessed_total"]
    except (ValueError, OSError, KeyError) as exc:
        return bad + ["r3: canonical spec unreadable: %s"
                      % exc]
    eff = sum(int(e["data"]["bytes"]) for e in events
              if e["kind"] == "copy")
    if eff != witnessed:
        bad.append("r3: copy bytes %d != witnessed %d"
                   % (eff, witnessed))
    return sorted(bad)


def _faults_caps(files):
    """Load every faults capture; raises on unreadable files."""
    caps = {}
    for tag in ("f3a", "f3b", "f5a", "f5b", "f5c", "f6"):
        record = json.loads(
            files["%s-record.json" % tag].read_text())
        session = json.loads(
            files["%s-session.json" % tag].read_text())
        events = _events(
            str(files["%s-events.ndjson" % tag]))
        ops, _, _ = parse_oracle_log(
            str(files["%s-oracle.log" % tag]))
        caps[tag] = (record, session, events, ops)
    return caps


def judge_faults_channels(files):
    """Per-channel loss reconcile for the faults floods.

    Strengthens the shared pooled checks: every flood
    channel reconciles its recorded plus omitted records
    against its own prediction, so one channel
    over-counting while another under-counts cannot pass.
    """
    bad = []
    try:
        caps = _faults_caps(files)
        ledger = {row["scenario"]: row for row in json.loads(
            files["faults.json"].read_text())}
    except (ValueError, OSError, KeyError) as exc:
        return ["ft: capture files unreadable: %s" % exc]
    want = scripted_expectation(300, -1)
    want_channels = {
        "attempt": len(want["maps"]),
        "lifecycle": len(want["maps"]) + len(want["unmaps"]),
        "copy": len(want["syncs_dev"]) + len(want["syncs_cpu"])
                + len(want["bounces"]),
    }
    for tag in ("f3a", "f3b"):
        _, session, events, _ = caps[tag]
        try:
            cut, _, _ = parse_oracle_log(
                str(files["%s-cut-oracle.log" % tag]))
        except (ValueError, OSError) as exc:
            bad.append("ft-%s: cut log unreadable: %s"
                       % (tag, exc))
            continue
        window = ledger[tag]["window"]
        sl = [e for e in events
              if window[0] <= int(e["ts_ns"]) <= window[1]]
        prefix = core.scripted_prefix_expectation(set(cut))
        bad += core.check_per_channel_loss(
            sl, session, prefix, "ft-%s" % tag,
            strict_total=False)
    for tag in ("f5a", "f5b"):
        _, session, events, _ = caps[tag]
        window = ledger[tag]["window"]
        sl = [e for e in events
              if window[0] <= int(e["ts_ns"]) <= window[1]]
        if tag == "f5a":
            kinds = {e["kind"] for e in sl}
            if kinds - {"bounce_attempt", "counter_snapshot",
                        "pool_sample"}:
                bad.append("ft-f5a: 1ch slice carries %r"
                           % (kinds,))
            bad += core.check_per_channel_loss(
                [e for e in sl
                 if e["kind"] == "bounce_attempt"],
                session,
                {"attempt": want_channels["attempt"],
                 "lifecycle": 0, "copy": 0},
                "ft-f5a")
        else:
            bad += core.check_per_channel_loss(
                sl, session, want_channels, "ft-f5b")
    _, session, events, _ = caps["f5c"]
    window = ledger["f5c"]["window"]
    sl = [e for e in events
          if window[0] <= int(e["ts_ns"]) <= window[1]]
    bad += core.check_per_channel_loss(
        sl, session, want_channels, "ft-f5c")
    return sorted(bad)


# -- Unarmed self-test: pins --------------------------------

def self_test_pins():
    """Every pinned byte still matches its source."""
    ok = True
    for rel, want in [
            ("tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o",
             score.C9_LC_SHA),
            ("tests/vm/fixtures/aya/swiotlb_copy.bpf.o",
             score.C9_CP_SHA),
            ("tests/vm/fixtures/aya/swiotlb_attempt.bpf.o",
             score.C9_ATTEMPT_SHA)]:
        got = sha_file(str(REPO / rel))
        ok = check("pins-%s" % rel.rsplit("/", 1)[1].split(
            ".")[0], got == want, got[:16]) and ok
    try:
        oracle = score.oracle_digest(str(REPO))
        ok = check("pins-oracle",
                   len(oracle["memveil_dma_oracle.c"]) == 64
                   and len(oracle["Makefile"]) == 64) and ok
    except (ValueError, OSError, KeyError) as exc:
        ok = check("pins-oracle", False, str(exc)) and ok
    try:
        guest_oracle.verify_fixture()
        ok = check("pins-oracle-fixture", True) and ok
    except (ValueError, OSError) as exc:
        ok = check("pins-oracle-fixture", False,
                   str(exc)[:200]) and ok
    try:
        pins = core.profile_pins(str(REPO))
        ok = check("pins-profile",
                   pins["sha256"] == core.PROFILE_SHA256
                   and pins["profile_id"] == core.PROFILE_ID,
                   pins["sha256"][:16]) and ok
    except (ValueError, OSError) as exc:
        ok = check("pins-profile", False, str(exc)) and ok
    seal = [REPO / "dist" / "candidate.json",
            REPO / "dist" / "bundle.tar.gz"]
    if not all(p.is_file() for p in seal):
        print("ok pins-candidate SKIP (no dist/ seal in tree)")
    else:
        try:
            binding = score.load_candidate_binding(str(REPO))
            ok = check(
                "pins-candidate",
                binding["bundle"]["sha256"]
                == score.C9_BUNDLE_SHA
                and binding["source"]["commit"]
                == score.C9_SOURCE_COMMIT
                and binding["source"]["tree"]
                == score.C9_SOURCE_TREE) and ok
        except (ValueError, OSError, KeyError) as exc:
            ok = check("pins-candidate", False,
                       str(exc)) and ok
    return ok


def self_test_gate_constants():
    """Mirrored battery constants still equal their sources."""
    ok = True
    try:
        tree = ast.parse((REPO / "tests" / "vm"
                          / "guest_lifecycle.py").read_text())
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) \
                    and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                key = node.targets[0].id
                if key in ("LC_SITES", "CP_SITES"):
                    try:
                        found[key] = ast.literal_eval(
                            node.value)
                    except ValueError:
                        pass
        ok = check("const-sites-lc",
                   found.get("LC_SITES") == core.LC_SITES,
                   "%r" % (found.get("LC_SITES"),)) and ok
        ok = check("const-sites-cp",
                   found.get("CP_SITES") == core.CP_SITES,
                   "%r" % (found.get("CP_SITES"),)) and ok
    except OSError as exc:
        ok = check("const-sites", False, str(exc)) and ok
    ok = check("const-release",
               core.EXPECT_RELEASE
               == battery_guest.EXPECT_RELEASE
               == guest_oracle.GUEST_RELEASE,
               "%r" % (core.EXPECT_RELEASE,)) and ok
    try:
        entry = core.pinned_guest_entry(str(REPO))
        source = entry.get("source", {})
        ok = check("const-vng-tag",
                   source.get("vng_version") == core.VNG_TAG
                   and entry.get("release")
                   == core.EXPECT_RELEASE) and ok
        ok = check("const-vmlinuz",
                   source.get("vmlinuz_sha256")
                   == core.VMLINUZ_SHA256) and ok
        ok = check("const-modules",
                   source.get("modules_manifest_sha256")
                   == core.MODULES_MANIFEST_SHA256) and ok
        try:
            binding = core.guest_binding(str(REPO))
            ok = check("const-guest-binding",
                       binding["vng_tag"] == core.VNG_TAG
                       and binding["release"]
                       == core.EXPECT_RELEASE) and ok
        except ValueError as exc:
            ok = check("const-guest-binding", False,
                       str(exc)) and ok
    except ValueError as exc:
        ok = check("const-guest-lock", False, str(exc)) and ok
    try:
        run_rs = (REPO / "src" / "capture"
                  / "run.rs").read_text()
        ok = check(
            "const-decision-phrase",
            "candidate {}: live interfaces verified "
            "(profile unvalidated)" in run_rs) and ok
        ok = check(
            "const-decision-shape",
            core.PROFILE_DECISION
            == "candidate %s: live interfaces verified "
               "(profile unvalidated)" % core.PROFILE_ID) \
            and ok
    except OSError as exc:
        ok = check("const-decision", False, str(exc)) and ok
    try:
        text = (REPO / "src" / "capture"
                / "collector.rs").read_text()
        ok = check("const-loss-grammar",
                   "detail loss {} ({pairs})" in text
                   and "; channels attempt:(" in text) and ok
    except OSError as exc:
        ok = check("const-loss-grammar", False,
                   str(exc)) and ok
    try:
        text = (REPO / "src" / "capture"
                / "writer.rs").read_text()
        ok = check("const-reserve",
                   "FINALIZE_RESERVE_BYTES: u64 = "
                   "17 * 1024 * 1024" in text
                   and battery_guest.FINALIZE_RESERVE_BYTES
                   == 17 * 1024 * 1024) and ok
        ok = check("const-reserve-prepare",
                   "pub fn prepare(" in text
                   and "reserve allocation failed: errno "
                   in text) and ok
    except OSError as exc:
        ok = check("const-reserve", False, str(exc)) and ok
    try:
        text = (REPO / "src" / "capture"
                / "collector.rs").read_text()
        ok = check("const-refusal-exit",
                   "pub const EXIT_REFUSAL: i64 = 3;"
                   in text
                   and battery_guest.EXIT_REFUSAL == 3) \
            and ok
    except OSError as exc:
        ok = check("const-refusal-exit", False,
                   str(exc)) and ok
    try:
        text = (REPO / "src" / "capture"
                / "live.rs").read_text()
        made = text.index("fn create(")
        ok = check("const-reserve-before-ready",
                   made < text.index("w.prepare()",
                                     made)) and ok
    except (OSError, ValueError) as exc:
        ok = check("const-reserve-before-ready", False,
                   str(exc)[:80]) and ok
    ok = check("const-cases",
               set(core.CASES) == set(EXPORT_NAMES)
               and len(core.CASES) == 9) and ok
    for case in core.CASES:
        try:
            names = battery_guest.export_names_for_case(case)
        except ValueError as exc:
            ok = check("const-inventory-%s" % case, False,
                       str(exc)) and ok
            continue
        ok = check("const-inventory-%s" % case,
                   names == EXPORT_NAMES[case]
                   and len(names) == len(set(names))
                   and "identity.json" in names
                   and "input-verify.json" in names,
                   "%d names" % len(names)) and ok
    try:
        battery_guest.export_names_for_case("bogus")
        ok = check("const-inventory-bogus", False,
                   "accepted") and ok
    except ValueError:
        ok = check("const-inventory-bogus", True) and ok
    return ok


# -- Unarmed self-test: consumer build + layouts ----------------

def self_test_consumer_build():
    """Release consumer builds pinned; its self-check is green."""
    try:
        built = score.build_consumer()
    except ValueError as exc:
        return check("build-consumer", False, str(exc)[:300])
    ok = True
    ok = check("build-consumer",
               os.path.isfile(built["path"])) and ok
    ok = check("build-aya-pin",
               built["build"]["locked"].get("aya") == "0.14.0"
               and built["build"]["locked"].get("aya-obj")
               == "0.3.0",
               "%r" % (built["build"]["locked"],)) and ok
    proc = consumer_run(["--self-check"])
    ok = check("build-self-check",
               proc.returncode == 0 and "ok" in proc.stdout,
               (proc.stdout + proc.stderr).strip()[-200:]) \
        and ok
    digest_proc = consumer_run([
        "--verify-layout",
        str(REPO / "tests/vm/fixtures/aya/"
                   "swiotlb_lifecycle.bpf.o"),
        "mv_lifecycle"])
    parsed = score.parse_verify_layout(digest_proc.stdout)
    ok = check("build-sha-agrees",
               parsed["sha256"] == sha_file(
                   str(REPO / "tests/vm/fixtures/aya/"
                             "swiotlb_lifecycle.bpf.o"))
               == score.C9_LC_SHA) and ok
    return ok


LAYOUT_WANT = {
    ("c9", "lc"): {
        "family": "aya", "core": "no",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8,
                          "entries": 6},
            "mv_lifecycle": {"type": 27, "key": 0, "value": 0,
                             "entries": 33554432},
            "mv_gen_table": {"type": 1, "key": 16, "value": 8,
                             "entries": 32768},
            "mv_gen_next": {"type": 2, "key": 4, "value": 8,
                            "entries": 1},
        },
        "programs": {"mv_map_result": "fexit",
                     "mv_unmap": "fentry"},
    },
    ("c9", "cp"): {
        "family": "aya", "core": "no",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8,
                          "entries": 6},
            "mv_claims": {"type": 2, "key": 4, "value": 16,
                          "entries": 4096},
            "mv_copy_fb": {"type": 2, "key": 4, "value": 8,
                           "entries": 4},
            "mv_copies": {"type": 27, "key": 0, "value": 0,
                          "entries": 33554432},
            "mv_copy_offs": {"type": 2, "key": 4, "value": 112,
                             "entries": 1},
        },
        "programs": {"mv_bounce": "fentry",
                     "mv_bounce_exit": "fexit",
                     "mv_sync_device": "fentry",
                     "mv_sync_cpu": "fentry"},
    },
}


def self_test_layouts(tmp, pairs):
    """C9 layouts verified against pinned bytes, offline."""
    rings = {"lc": "mv_lifecycle", "cp": "mv_copies"}
    ok = True
    for (name, channel), want in sorted(LAYOUT_WANT.items()):
        proc = consumer_run(["--verify-layout",
                             pairs[name][channel]["path"],
                             rings[channel]])
        parsed = score.parse_verify_layout(proc.stdout)
        tag = "layout-%s-%s" % (name, channel)
        good = proc.returncode == 0 \
            and parsed["verdict"] == "PASS"
        ok = check(tag, good, proc.stdout.strip().split(
            "\n")[-1] if not good else "") and ok
        ok = check(tag + "-family",
                   parsed["family"] == want["family"]
                   and parsed["core_relocations"]
                   == want["core"],
                   "%r" % parsed) and ok
        ok = check(tag + "-maps",
                   parsed["maps"] == want["maps"],
                   "%r" % (parsed["maps"],)) and ok
        kinds = {key: row["kind"] for key, row in
                 parsed["programs"].items()}
        sleepable = any(row["sleepable"] for row in
                        parsed["programs"].values())
        ok = check(tag + "-progs",
                   kinds == want["programs"]
                   and not sleepable,
                   "%r" % (parsed["programs"],)) and ok
        ok = check(tag + "-sha",
                   parsed["sha256"]
                   == pairs[name][channel]["sha256"]) and ok
    proc = consumer_run(["--verify-layout",
                         pairs["c9"]["cp"]["path"],
                         "mv_lifecycle"])
    ok = check("layout-cross-channel",
               proc.returncode == 1
               and "neither family" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    return ok


def self_test_wrong_pair(pairs):
    """Wrong-pair refusals through the real consume entrypoint.

    The digest and family gates fire before any privilege or
    BTF need, so these run fully offline with no boot.
    """
    ok = True
    c9_lc = pairs["c9"]["lc"]["path"]
    never = os.path.join(tempfile.gettempdir(),
                         "battery-never-written")
    cases = [
        ("family-swap",
         ["--expect-family", "c", c9_lc, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "family mismatch"),
        ("digest-wrong",
         ["--expect-sha256", "0" * 64, c9_lc, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "digest mismatch"),
        ("sites-short",
         [c9_lc, "mv_lifecycle", "mv_map_result:x",
          "1", never],
         "exactly the mv_lifecycle program set"),
    ]
    for name, argv, want in cases:
        proc = consumer_run(argv)
        ok = check("refuse-%s" % name,
                   proc.returncode == 1
                   and want in proc.stdout,
                   "exit=%d %s" % (proc.returncode,
                                   proc.stdout.strip()[
                                       -160:])) and ok
    return ok


def self_test_prefix_rule():
    """Prefix expectations match the scripted rule exactly."""
    ok = True
    for ops in (1, 2, 3, 4, 5, 8, 300):
        want = scripted_expectation(ops, -1)
        channels = {
            "attempt": len(want["maps"]),
            "lifecycle": len(want["maps"])
                         + len(want["unmaps"]),
            "copy": len(want["syncs_dev"])
                    + len(want["syncs_cpu"])
                    + len(want["bounces"]),
        }
        got = core.scripted_prefix_expectation(set(range(ops)))
        ok = check("prefix-%d" % ops, got == channels,
                   "%r vs %r" % (got, channels)) and ok
    return ok


# -- Unarmed self-test: judge preservation --------------------

def synth_manifest():
    """Self-consistent manifest for synthetic judgments."""
    manifest = {
        "oracle": {"ko_sha256": guest_oracle.KO_SHA256},
        "objects": {
            "lc": {"sha256": score.C9_LC_SHA},
            "cp": {"sha256": score.C9_CP_SHA},
            "attempt": {"sha256": score.C9_ATTEMPT_SHA},
        },
        "binary": {"sha256": "syn-binary"},
        "profile": {"sha256": core.PROFILE_SHA256,
                    "profile_id": core.PROFILE_ID},
        "test_objects": {"bound": False},
    }
    return manifest


def synth_identity(record=False):
    """Self-consistent guest identity for synthetic judgments."""
    digests = {"ko": guest_oracle.KO_SHA256,
               "lc": score.C9_LC_SHA,
               "cp": score.C9_CP_SHA}
    if record:
        digests["attempt"] = score.C9_ATTEMPT_SHA
        digests["binary"] = "syn-binary"
        digests["profile"] = core.PROFILE_SHA256
    return {"release": core.EXPECT_RELEASE,
            "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
            "digests": digests}


def synth_window_files(tmp, tag, lc_wire, lc_counts, cp_wire,
                       cp_counts, oracle_text):
    """Replay one synthetic window; return {name: Path}."""
    out = {}
    lc_path = replay_consumer(tmp, "%s-lc" % tag,
                              "mv_lifecycle", lc_wire,
                              lc_counts)
    cp_path = replay_consumer(tmp, "%s-cp" % tag, "mv_copies",
                              cp_wire, cp_counts)
    oracle_path = os.path.join(tmp, "%s-oracle.log" % tag)
    with open(oracle_path, "w") as handle:
        handle.write(oracle_text)
    out["%s-lc.txt" % tag] = Path(lc_path)
    out["%s-cp.txt" % tag] = Path(cp_path)
    out["%s-oracle.log" % tag] = Path(oracle_path)
    return out


def synth_case_files(tmp, windows):
    """Full synthetic export set for one consumer case."""
    files = {}
    ident_path = os.path.join(tmp, "identity.json")
    with open(ident_path, "w") as handle:
        handle.write(json.dumps(synth_identity(),
                                sort_keys=True))
    files["identity.json"] = Path(ident_path)
    for tag, lc_wire, lc_counts, cp_wire, cp_counts, \
            oracle_text in windows:
        files.update(synth_window_files(
            tmp, tag, lc_wire, lc_counts, cp_wire,
            cp_counts, oracle_text))
    return files


def self_test_matrix(tmp):
    """Matrix leg preserved: rates, multisets, bytes, pacing."""
    ok = True
    windows = []
    for delay_ms, step in ((1000, 1000000000), (100, 100000000),
                           (10, 10000000)):
        lc_wire, lc_counts, cp_wire, cp_counts = \
            scripted_wire(ktime_step=step)
        windows.append(("s%d" % delay_ms, lc_wire, lc_counts,
                        cp_wire, cp_counts,
                        oracle_script_log()))
    files = synth_case_files(tmp, windows)
    bad, _ = judge_case(files, "matrix", synth_manifest())
    ok = check("judge-matrix", bad == [],
               "; ".join(bad[:3])) and ok
    # Effective bytes derive from the oracle log by rule,
    # never from probe output.
    ops_log = parse_oracle_log(
        str(files["s1000-oracle.log"]))[0]
    want_eff = expected_effective(ops_log)
    got_eff = sum(e["eff"] for e in
                  parse_consume_file(
                      str(files["s1000-cp.txt"]))[0]
                  if e["kind"] == 2)
    ok = check("judge-matrix-bytes", got_eff == want_eff,
               "%d vs %d" % (got_eff, want_eff)) and ok
    return ok


def self_test_copy(tmp):
    """Copy leg preserved: nested order, failed-outer survival."""
    ok = True
    lc_a, lc_ac, cp_a, cp_ac = scripted_wire()
    lc_b, lc_bc, cp_b, cp_bc = scripted_wire(fail_op=2)
    files = synth_case_files(tmp, [
        ("a", lc_a, lc_ac, cp_a, cp_ac,
         oracle_script_log()),
        ("b", lc_b, lc_bc, cp_b, cp_bc,
         oracle_script_log(fail_op=2)),
    ])
    bad, _ = judge_case(files, "copy", synth_manifest())
    ok = check("judge-copy", bad == [],
               "; ".join(bad[:3])) and ok
    # The failed outer op keeps no successful outer map or
    # release while its inner copy survives.
    ops_log = parse_oracle_log(
        str(files["b-oracle.log"]))[0]
    releases = parse_oracle_log(
        str(files["b-oracle.log"]))[1]
    entry = ops_log[2]
    cp = parse_consume_file(str(files["b-cp.txt"]))[0]
    survivors = [e for e in cp if e["kind"] == 2
                 and e["req"] == entry["requested"]]
    ok = check("judge-copy-failouter",
               entry.get("success") is False
               and 2 not in releases and survivors,
               "%r" % (entry,)) and ok
    # The failed-outer proof is load-bearing: a release for
    # the failed op fails the window.
    text = oracle_script_log(fail_op=2)
    text += "[0.0] mv-oracle: mapping=2 release " \
        "lifetime_ns=999\n"
    files = synth_case_files(tmp, [
        ("b", lc_b, lc_bc, cp_b, cp_bc, text),
    ])
    try:
        check_copy_window(files, "b", 2)
        ok = check("judge-copy-failouter-rel", False,
                   "failed-op release passed") and ok
    except AssertionError:
        ok = check("judge-copy-failouter-rel", True) and ok
    return ok


def self_test_canonical(tmp):
    """Canonical legs preserved: clamp + early, selectable."""
    ok = True
    frozen = json.loads(SPEC.read_text())
    lc_wire, lc_counts, cp_wire, cp_counts = \
        canonical_wire(frozen["c"], clamped=(4096, 1024))
    files = synth_case_files(tmp, [
        ("c", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_canonical_log(frozen["c"])),
    ])
    bad, _ = judge_case(files, "canonical-c",
                        synth_manifest())
    ok = check("judge-canonical-c", bad == [],
               "; ".join(bad[:3])) and ok
    lc_wire, lc_counts, cp_wire, cp_counts = \
        canonical_wire(frozen["e"], early=True)
    files = synth_case_files(tmp, [
        ("e", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_canonical_log(frozen["e"])),
    ])
    bad, _ = judge_case(files, "canonical-e",
                        synth_manifest())
    ok = check("judge-canonical-e", bad == [],
               "; ".join(bad[:3])) and ok
    return ok


def self_test_stop(tmp):
    """Stop leg preserved: 5 cycles, victim, quiet, short."""
    ok = True
    lc_full, lc_full_c, cp_full, cp_full_c = scripted_wire()
    # Short window: op-3's unmap (lc ordinal 7), cpu-sync
    # (cp ordinal 15), and release bounce (cp ordinal 16)
    # never persist; the held mapping's release triple is
    # absent while everything else stays exact.
    short_lc, short_lc_c, short_cp, short_cp_c = \
        scripted_wire(drop_lc=(7,), drop_cp=(15, 16))
    quiet = (b"", [0, 0, 0, 0, 0, 0],
             b"", [0, 0, 0, 0, 0, 0])
    oracle = oracle_script_log()
    windows = [
        ("c0", lc_full, lc_full_c, cp_full, cp_full_c,
         oracle),
        ("c3", lc_full, lc_full_c, cp_full, cp_full_c,
         oracle),
        ("c2", quiet[0], quiet[1], quiet[2], quiet[3], ""),
        ("c4", short_lc, short_lc_c, short_cp, short_cp_c,
         oracle),
    ]
    files = synth_case_files(tmp, windows)
    # Victim cycle: survivor lc plus oracle only; the cp
    # file never landed.
    solo = synth_window_files(tmp, "c1x", lc_full, lc_full_c,
                              cp_full, cp_full_c, oracle)
    files["c1-lc.txt"] = solo["c1x-lc.txt"]
    files["c1-oracle.log"] = solo["c1x-oracle.log"]
    ledger = [
        {"cycle": 0, "mode": "stop-both", "lc_exit": 0,
         "cp_exit": 0},
        {"cycle": 1, "mode": "term-cp", "lc_exit": 0,
         "cp_exit": -15, "victim_alive": True,
         "victim_rc": -15, "victim_signal": 15,
         "victim_signal_ns": 12345, "victim_file": False},
        {"cycle": 2, "mode": "quiet", "lc_exit": 0,
         "cp_exit": 0},
        {"cycle": 3, "mode": "stop-lc", "lc_exit": 0,
         "cp_exit": 0},
        {"cycle": 4, "mode": "short", "lc_exit": 0,
         "cp_exit": 0},
    ]
    ledger_path = os.path.join(tmp, "ledger.json")
    with open(ledger_path, "w") as handle:
        handle.write(json.dumps(ledger, sort_keys=True))
    files["ledger.json"] = Path(ledger_path)
    bad, _ = judge_case(files, "stop", synth_manifest())
    ok = check("judge-stop", bad == [],
               "; ".join(bad[:3])) and ok
    # A victim file with a final summary fails; an absent
    # victim file with the death receipt passes.
    victim_path = os.path.join(tmp, "c1-cp.txt")
    with open(victim_path, "w") as handle:
        handle.write("summary observed=0 badframe=0 badrec=0 "
                     "cnt_obs=0 cnt_obsb=0 cnt_emit=0 "
                     "cnt_emitb=0 cnt_fail=0 cnt_flags=0 "
                     "rx=0 dlv=0 mal=0 drop=0\n")
    files["c1-cp.txt"] = Path(victim_path)
    bad, _ = judge_case(files, "stop", synth_manifest())
    ok = check("judge-stop-victim-summary",
               any("summary" in reason for reason in bad),
               "; ".join(bad[:2])) and ok
    return ok


def self_test_saturation(tmp):
    """Saturation judge preserved on a synthetic loss flood."""
    ok = True
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire(
        drop_lc=(6, 7), drop_cp=(0, 3))
    files = synth_case_files(tmp, [
        ("flood", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_script_log()),
    ])
    reasons = judge_saturation_flood(files, ops=4)
    ok = check("judge-saturation", reasons == [],
               "; ".join(reasons[:3])) and ok
    # No induced loss fails the flood judgment.
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    files = synth_case_files(tmp, [
        ("flood", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_script_log()),
    ])
    reasons = judge_saturation_flood(files, ops=4)
    ok = check("judge-saturation-noloss",
               any("no loss induced" in reason
                   for reason in reasons),
               "; ".join(reasons[:2])) and ok
    return ok


def self_test_skipsync(tmp):
    """Skip-sync judge: pass plus the three refusal shapes."""
    ok = True
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    files = synth_case_files(tmp, [
        ("w", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_script_log(witness=True)),
    ])
    bad, _ = judge_case(files, "skipsync", synth_manifest())
    ok = check("judge-skipsync", bad == [],
               "; ".join(bad[:3])) and ok
    # Empty window fails.
    files = synth_case_files(tmp, [
        ("w", b"", [0, 0, 0, 0, 0, 0],
         b"", [0, 0, 0, 0, 0, 0], ""),
    ])
    bad, _ = judge_case(files, "skipsync", synth_manifest())
    ok = check("judge-skipsync-empty",
               any("empty window" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    # Flipped skip flag fails.
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire(
        skip_flip=(3,))
    files = synth_case_files(tmp, [
        ("w", lc_wire, lc_counts, cp_wire, cp_counts,
         oracle_script_log(witness=True)),
    ])
    bad, _ = judge_case(files, "skipsync", synth_manifest())
    ok = check("judge-skipsync-flip",
               any("skip" in reason for reason in bad),
               "; ".join(bad[:2])) and ok
    # Missing release fails.
    text = oracle_script_log(witness=True)
    kept = [line for line in text.split("\n")
            if "mapping=1 release" not in line]
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    files = synth_case_files(tmp, [
        ("w", lc_wire, lc_counts, cp_wire, cp_counts,
         "\n".join(kept)),
    ])
    bad, _ = judge_case(files, "skipsync", synth_manifest())
    ok = check("judge-skipsync-norel",
               any("release" in reason for reason in bad),
               "; ".join(bad[:2])) and ok
    # Skip-path purity: a release copy on a TO op fails.
    text = oracle_script_log(witness=True)
    text += "[0.0] mv-oracle: op=0 mapping=0 witness " \
        "copy=release copied=512 verified=512\n"
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    files = synth_case_files(tmp, [
        ("w", lc_wire, lc_counts, cp_wire, cp_counts, text),
    ])
    bad, _ = judge_case(files, "skipsync", synth_manifest())
    ok = check("judge-skipsync-torel",
               any("skip path" in reason for reason in bad),
               "; ".join(bad[:2])) and ok
    return ok


# -- Unarmed self-test: loss grammar + record legs ------------

def loss_session(loss_count, buckets, channels=None):
    """Synthetic session carrying one Detail reason."""
    pairs = " ".join("%s=(%d)" % (name, buckets[name])
                     for name in core.LOSS_BUCKETS)
    reason = "detail loss %d (%s)" % (loss_count, pairs)
    if channels is not None:
        parts = []
        for name in ("attempt", "lifecycle", "copy"):
            if name not in channels:
                continue
            triple = channels[name]
            parts.append(
                "%s:(submit_fail=%s malformed=%s dropped=%s)"
                % (name, triple[0], triple[1], triple[2]))
        reason += "; channels " + " ".join(parts)
    return synth_session(loss_count=str(loss_count),
                         detail_reason=reason,
                         detail_status="partial"
                         if loss_count else "complete_for_scope")


def loss_events(session_id, start, attempt=0, lifecycle=0,
                copy=0, gen_base=1):
    """Synthetic detail events with paired generations."""
    events = []
    seq = [0]
    ts = [start]

    def nxt():
        seq[0] += 1
        ts[0] += 1000
        return seq[0] - 1, ts[0]

    for i in range(attempt):
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "bounce_attempt",
            {"requested_bytes": "512"}))
    maps = lifecycle // 2
    for i in range(maps):
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "map_result",
            {"mapped_bytes": "512", "success": True,
             "wire_generation": str(gen_base + i)}))
    for i in range(lifecycle - maps):
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "unmap",
            {"wire_generation": str(gen_base + i)}))
    for i in range(copy):
        seq_v, ts_v = nxt()
        kind = "sync_request" if i % 2 else "copy"
        data = {"length": "512", "offset_known": False,
                "offset": None} if kind == "sync_request" \
            else {"bytes": "512",
                  "direction": "original_to_bounce"}
        events.append(synth_event(session_id, seq_v, ts_v,
                                  kind, data))
    return events


def self_test_loss_grammar():
    """Strict loss parsing plus per-channel reconcile."""
    ok = True
    zero = dict((name, 0) for name in core.LOSS_BUCKETS)
    session = loss_session(0, zero)
    try:
        loss = core.parse_detail_loss(session)
        ok = check("loss-exact-zero",
                   loss["loss_count"] == 0
                   and loss["channels"] is None
                   and not loss["unknown"]) and ok
    except ValueError as exc:
        ok = check("loss-exact-zero", False, str(exc)) and ok
    buckets = dict(zero, duration_omitted=10)
    session = loss_session(
        10, buckets,
        {"attempt": (0, 0, 0), "lifecycle": (0, 0, 0),
         "copy": (0, 0, 0)})
    try:
        loss = core.parse_detail_loss(session)
        ok = check("loss-channels",
                   loss["buckets"]["duration_omitted"] == 10
                   and loss["channels"]["copy"] ==
                   {"submit_fail": 0, "malformed": 0,
                    "dropped": 0}) and ok
    except ValueError as exc:
        ok = check("loss-channels", False, str(exc)) and ok
    session = loss_session(9, buckets)
    try:
        core.parse_detail_loss(session)
        ok = check("loss-head-mismatch", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("loss-head-mismatch",
                   "bucket sum" in str(exc),
                   str(exc)[:120]) and ok
    session = synth_session(
        loss_count="0",
        detail_reason="detail loss unknown (drain budget "
                      "exhausted; known: submit_fail=(3) "
                      "malformed=(0) dropped=(0) "
                      "recursion_missed=(0) size_omitted=(0) "
                      "duration_omitted=(0) signal_omitted=(0) "
                      "rejected=(0) write_failed=(0))",
        detail_status="partial")
    try:
        loss = core.parse_detail_loss(session)
        ok = check("loss-unknown",
                   loss["unknown"]
                   and loss["cause"] == "drain budget "
                                        "exhausted") and ok
    except ValueError as exc:
        ok = check("loss-unknown", False, str(exc)) and ok
    session = synth_session(loss_count="0",
                            detail_reason="detail loss 0 (submit_fail=(0))")
    try:
        core.parse_detail_loss(session)
        ok = check("loss-drift", False, "accepted") and ok
    except ValueError as exc:
        ok = check("loss-drift",
                   "grammar drift" in str(exc),
                   str(exc)[:120]) and ok
    # Per-channel reconcile: exact, over-count, pooled
    # disagreement, unknown.
    events = loss_events("s", 1000, attempt=10, lifecycle=20,
                         copy=30)
    want = {"attempt": 10, "lifecycle": 20, "copy": 30}
    session = loss_session(0, zero)
    ok = check("channels-exact",
               core.check_per_channel_loss(
                   events, session, want, "t") == []) and ok
    events = loss_events("s", 1000, attempt=11, lifecycle=20,
                         copy=29)
    bad = core.check_per_channel_loss(events, session, want,
                                      "t")
    ok = check("channels-overcount",
               any("over predicted" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    buckets = dict(zero, submit_fail=2)
    session = loss_session(
        2, buckets,
        {"attempt": (1, 0, 0), "lifecycle": (0, 0, 0),
         "copy": (0, 0, 0)})
    events = loss_events("s", 1000, attempt=8, lifecycle=20,
                         copy=30)
    bad = core.check_per_channel_loss(events, session, want,
                                      "t")
    ok = check("channels-disagree",
               any("sums 1 != pooled 2" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    buckets = dict(zero, submit_fail=2)
    session = loss_session(
        2, buckets,
        {"attempt": (2, 0, 0), "lifecycle": (0, 0, 0),
         "copy": (0, 0, 0)})
    bad = core.check_per_channel_loss(events, session, want,
                                      "t")
    ok = check("channels-exact-loss", bad == [],
               "; ".join(bad[:2])) and ok
    session = synth_session(
        loss_count="5",
        detail_reason="detail loss unknown (cut; known: "
                      "submit_fail=(5) malformed=(0) "
                      "dropped=(0) recursion_missed=(0) "
                      "size_omitted=(0) duration_omitted=(0) "
                      "signal_omitted=(0) rejected=(0) "
                      "write_failed=(0))",
        detail_status="partial")
    bad = core.check_per_channel_loss(events, session, want,
                                      "t")
    ok = check("channels-unknown",
               any("unreconciled" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    # The product's own golden reasons parse: the strict
    # grammar is anchored to formatter outputs, not to
    # remembered strings.
    try:
        goldens = re.findall(
            r"detail loss \d+ \([a-z_]+=\(\d+\)"
            r"(?: [a-z_]+=\(\d+\))*\)"
            r"(?:; channels (?:attempt|lifecycle|copy):"
            r"\([^)]*\)"
            r"(?: (?:attempt|lifecycle|copy):\([^)]*\))*)?",
            (REPO / "src" / "capture"
             / "collector.rs").read_text())
    except OSError as exc:
        return check("loss-golden", False, str(exc)) and ok
    parsed = 0
    for reason in goldens:
        head = int(reason.split(" ", 2)[2].split(" ", 1)[0])
        session = synth_session(
            loss_count=str(head), detail_reason=reason,
            detail_status="partial" if head
            else "complete_for_scope")
        try:
            loss = core.parse_detail_loss(session)
            assert loss["loss_count"] == head
            parsed += 1
        except (ValueError, AssertionError) as exc:
            ok = check("loss-golden", False,
                       "%s: %s" % (reason[:60], exc)) and ok
    ok = check("loss-golden", parsed >= 2 and parsed
               == len(goldens),
               "%d/%d parsed" % (parsed, len(goldens))) and ok
    return ok


def scenario1_events(session_id, start, gens=("11", "12")):
    """Synthetic nested scenario-1 detail events."""
    events = []
    ts = [start]
    seq = [0]

    def nxt():
        out = (seq[0], ts[0])
        seq[0] += 1
        ts[0] += 1000000
        return out

    sizes = (("4096", gens[0]), ("1024", gens[1]))
    for size, gen in sizes:
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "bounce_attempt",
            {"requested_bytes": size}))
    for size, gen in sizes:
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "map_result",
            {"mapped_bytes": size, "success": True,
             "wire_generation": gen}))
    for size, _ in sizes:
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "sync_request",
            {"length": size, "offset_known": False,
             "offset": None}))
    for size, _ in sizes:
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "copy",
            {"bytes": size,
             "direction": "original_to_bounce"}))
    for size, gen in sizes:
        seq_v, ts_v = nxt()
        events.append(synth_event(
            session_id, seq_v, ts_v, "unmap",
            {"wire_generation": gen}))
    return events


def flood_events(session_id, start, ops=300, drop=(),
                 gen_base=1):
    """Synthetic scripted-flood detail events with drops.

    drop names (kind, index) detail records to omit,
    where index counts that kind's emission order.
    """
    from consume import LC_SIZES
    events = []
    ts = [start]
    seq = [0]
    omitted = {"bounce_attempt": 0, "map_result": 0,
               "unmap": 0, "sync_request": 0, "copy": 0}

    def nxt():
        out = (seq[0], ts[0])
        seq[0] += 1
        ts[0] += 1000
        return out

    def emit(kind, data):
        seq_v, ts_v = nxt()
        events.append(synth_event(session_id, seq_v, ts_v,
                                  kind, data))

    def maybe(kind, data):
        if (kind, omitted[kind]) in drop:
            omitted[kind] += 1
            return
        omitted[kind] += 1
        emit(kind, data)

    gen = gen_base
    for i in range(ops):
        size = LC_SIZES[i % len(LC_SIZES)]
        direction = 2 if i % 2 else 1
        maybe("bounce_attempt",
              {"requested_bytes": str(size)})
        maybe("map_result",
              {"mapped_bytes": str(size), "success": True,
               "wire_generation": str(gen)})
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            maybe("sync_request",
                  {"length": str(size), "offset_known": False,
                   "offset": None})
        maybe("sync_request",
              {"length": str(size), "offset_known": False,
               "offset": None})
        maybe("copy", {"bytes": str(size),
                       "direction": "original_to_bounce"})
        if direction == 1:
            for _ in range(syncs):
                maybe("copy",
                      {"bytes": str(size),
                       "direction": "original_to_bounce"})
        else:
            maybe("copy", {"bytes": str(size),
                           "direction":
                           "bounce_to_original"})
        maybe("unmap", {"wire_generation": str(gen)})
        gen += 1
    return events


def counter_events(session_id, seq_start, ts, pairs):
    """Synthetic counter snapshots for exact counter pairs."""
    events = []
    seq = seq_start
    for counter_id, values in pairs:
        for value in values:
            events.append(synth_event(
                session_id, seq, ts, "counter_snapshot",
                {"counter_id": counter_id,
                 "value": value}))
            seq += 1
    return events


def pool_events(session_id, seq_start, ts, count,
                used="100", baseline="100"):
    """Synthetic pool samples with a closing baseline pair."""
    events = []
    seq = seq_start
    for _ in range(count):
        events.append(synth_event(
            session_id, seq, ts, "pool_sample",
            {"used_bytes": used}))
        seq += 1
    for tail in (baseline, used):
        events.append(synth_event(
            session_id, seq, ts, "pool_sample",
            {"used_bytes": tail}))
        seq += 1
    return events


def self_test_record3(tmp):
    """Record3 leg preserved on a synthetic scenario-1 capture."""
    ok = True
    session_id = "cap-synth-r3"
    start = 5000000
    events = scenario1_events(session_id, start)
    seq = len(events)
    events += counter_events(
        session_id, seq, start + 100,
        [("swiotlb.bounce_attempts", ("0", "2")),
         ("swiotlb.requested_bytes", ("0", "5120"))])
    events += pool_events(session_id, len(events),
                          start + 200, 12)
    session = synth_session(session_id=session_id,
                            start_ns=1000000,
                            span_ns=30000000000)
    record = {"exit": 0, "ready": "ready session=r3"}
    oracle = ("[0.0] mv-oracle: op=0 attempt requested=4096 "
              "forced=0\n"
              "[0.0] mv-oracle: op=0 outcome=success "
              "mapping=0 mapped=4096\n"
              "[0.0] mv-oracle: mapping=0 release "
              "lifetime_ns=10\n"
              "[0.0] mv-oracle: op=1 attempt requested=1024 "
              "forced=0\n"
              "[0.0] mv-oracle: op=1 outcome=success "
              "mapping=1 mapped=1024\n"
              "[0.0] mv-oracle: mapping=1 release "
              "lifetime_ns=11\n"
              "[0.0] mv-oracle: script complete ops=2\n")
    files = {"identity.json": None}
    ident_path = os.path.join(tmp, "r3-identity.json")
    with open(ident_path, "w") as handle:
        handle.write(json.dumps(synth_identity(record=True),
                                sort_keys=True))
    files = {"identity.json": Path(ident_path)}
    for name, doc in (("record.json", record),
                      ("cap-session.json", session)):
        path = os.path.join(tmp, "r3-%s" % name)
        with open(path, "w") as handle:
            handle.write(json.dumps(doc, sort_keys=True))
        files[name] = Path(path)
    events_path = os.path.join(tmp, "r3-cap-events.ndjson")
    write_events(events_path, events)
    files["cap-events.ndjson"] = Path(events_path)
    oracle_path = os.path.join(tmp, "r3-oracle.log")
    with open(oracle_path, "w") as handle:
        handle.write(oracle)
    files["r3-oracle.log"] = Path(oracle_path)
    prof_path = os.path.join(tmp, "r3-profile.json")
    shutil.copyfile(str(REPO / core.PROFILE_REL), prof_path)
    files["profile.json"] = Path(prof_path)
    bad, _ = judge_case(files, "record3", synth_manifest())
    ok = check("judge-record3", bad == [],
               "; ".join(bad[:3])) and ok
    # The retired mint decision no longer admits: the
    # rebound leg pins the reference decision exactly.
    stale = dict(session)
    stale["environment"] = {"evidence": [
        {"source": "profile.decision",
         "interpretation": "candidate record3-ephemeral: "
                           "bindings hold (profile "
                           "unvalidated)"}]}
    stale_path = os.path.join(tmp, "r3-stale-session.json")
    with open(stale_path, "w") as handle:
        handle.write(json.dumps(stale, sort_keys=True))
    files["cap-session.json"] = Path(stale_path)
    bad, _ = judge_case(files, "record3", synth_manifest())
    ok = check("judge-record3-decision",
               any("profile decision" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    return ok


def synth_faults_files(tmp):
    """Full synthetic faults export set, self-consistent."""
    from consume import LC_SIZES
    files = {}
    ident_path = os.path.join(tmp, "ft-identity.json")
    with open(ident_path, "w") as handle:
        handle.write(json.dumps(synth_identity(record=True),
                                sort_keys=True))
    files["identity.json"] = Path(ident_path)
    prof_path = os.path.join(tmp, "ft-profile.json")
    shutil.copyfile(str(REPO / core.PROFILE_REL), prof_path)
    files["profile.json"] = Path(prof_path)
    ledger = []
    base = [100000000]

    def window_for(span):
        start = base[0]
        base[0] += span + 100000000
        return [start - 1000, start + span]

    def put(tag, record, session, events, oracle_text):
        for name, doc in (("%s-record.json" % tag, record),
                          ("%s-session.json" % tag, session)):
            path = os.path.join(tmp, "ft-%s" % name)
            with open(path, "w") as handle:
                handle.write(json.dumps(doc, sort_keys=True))
            files[name] = Path(path)
        events_path = os.path.join(
            tmp, "ft-%s-events.ndjson" % tag)
        write_events(events_path, events)
        files["%s-events.ndjson" % tag] = Path(events_path)
        oracle_path = os.path.join(tmp, "ft-%s-oracle.log"
                                   % tag)
        with open(oracle_path, "w") as handle:
            handle.write(oracle_text)
        files["%s-oracle.log" % tag] = Path(oracle_path)

    def ledger_row(scenario, window=None, exit=0, stderr="",
                   cap=True):
        row = {"scenario": scenario, "exit": exit,
               "stderr": stderr, "progs_before": 5,
               "progs_after": 5, "maps_before": 7,
               "maps_after": 7, "settle_s": 1.0, "cap": cap}
        if window is not None:
            row["window"] = window
        ledger.append(row)

    for tag in ("f1", "f2"):
        ledger_row(tag, exit=3, stderr="refused", cap=False)
    zero = dict((name, 0) for name in core.LOSS_BUCKETS)
    suffix3 = "; channels attempt:(submit_fail=0 " \
        "malformed=0 dropped=0) lifecycle:(submit_fail=0 " \
        "malformed=0 dropped=0) copy:(submit_fail=0 " \
        "malformed=0 dropped=0)"

    def zero_reason(channels=False):
        pairs = " ".join("%s=(0)" % name
                         for name in core.LOSS_BUCKETS)
        reason = "detail loss 0 (%s)" % pairs
        return reason + (suffix3 if channels else "")

    # Signal cuts: 150-op cut logs, partial event prefixes.
    for tag, paired in (("f3a", False), ("f3b", True)):
        window = window_for(200000000)
        session_id = "cap-synth-%s" % tag
        start = window[0] + 1000
        events = []
        seq = [0]

        def nxt():
            out = seq[0]
            seq[0] += 1
            return out
        ts = [start]

        def tick():
            ts[0] += 1000
            return ts[0]
        for i in range(100):
            size = LC_SIZES[i % len(LC_SIZES)]
            events.append(synth_event(
                session_id, nxt(), tick(), "bounce_attempt",
                {"requested_bytes": str(size)}))
        if paired:
            for i in range(60):
                size = LC_SIZES[i % len(LC_SIZES)]
                events.append(synth_event(
                    session_id, nxt(), tick(), "map_result",
                    {"mapped_bytes": str(size),
                     "success": True,
                     "wire_generation": str(i + 1)}))
            for i in range(60):
                events.append(synth_event(
                    session_id, nxt(), tick(), "unmap",
                    {"wire_generation": str(i + 1)}))
            for i in range(40):
                size = LC_SIZES[i % len(LC_SIZES)]
                events.append(synth_event(
                    session_id, nxt(), tick(), "sync_request",
                    {"length": str(size),
                     "offset_known": False, "offset": None}))
            for i in range(40):
                size = LC_SIZES[i % len(LC_SIZES)]
                events.append(synth_event(
                    session_id, nxt(), tick(), "copy",
                    {"bytes": str(size),
                     "direction": "original_to_bounce"}))
            events.append(synth_event(
                session_id, nxt(), tick(), "pool_sample",
                {"used_bytes": "100"}))
            events.append(synth_event(
                session_id, nxt(), tick(), "pool_sample",
                {"used_bytes": "120"}))
        session = synth_session(
            session_id=session_id, start_ns=start - 5000000,
            span_ns=10000000000, end_reason="signal",
            detail_reason=zero_reason(paired),
            correlation="partial" if paired
            else "not_applicable")
        put(tag, {"exit": 0, "ready": "ready session=%s" % tag},
            session, events, oracle_script_log(ops=300))
        cut_path = os.path.join(tmp, "ft-%s-cut-oracle.log"
                                % tag)
        with open(cut_path, "w") as handle:
            handle.write(oracle_script_log(ops=150))
        files["%s-cut-oracle.log" % tag] = Path(cut_path)
        ledger_row(tag, window)
    # Signal-cut report over the f3b capture.
    f3b_events = _events(str(files["f3b-events.ndjson"]))
    kinds = {}
    for event in f3b_events:
        kinds.setdefault(event["kind"], []).append(event)
    attempts = kinds.get("bounce_attempt", [])
    maps = kinds.get("map_result", [])
    copies = kinds.get("copy", [])
    syncs = kinds.get("sync_request", [])
    unmaps = kinds.get("unmap", [])
    ok_maps = [e for e in maps if e["data"]["success"]]
    born = {e["data"]["wire_generation"] for e in ok_maps
            if e["data"]["wire_generation"]
            not in (None, "0")}
    paired = [e for e in unmaps
              if e["data"]["wire_generation"] in born]
    samples = kinds.get("pool_sample", [])
    todev = sum(int(e["data"]["bytes"]) for e in copies
                if e["data"]["direction"]
                == "original_to_bounce")
    tocpu = sum(int(e["data"]["bytes"]) for e in copies
                if e["data"]["direction"]
                == "bounce_to_original")
    unpaired = sum(1 for e in maps + copies + syncs + unmaps
                   if e["source"]["correlation"]
                   == "unpaired")
    report = {
        "metrics": [
            {"name": "bounce_attempts", "value": str(
                len(attempts)), "scope": "all devices",
             "coverage": "complete"},
            {"name": "requested_bounce_bytes", "value": str(
                sum(int(e["data"]["requested_bytes"])
                    for e in attempts)),
             "scope": "all devices", "coverage": "complete"},
            {"name": "successful_allocations",
             "value": str(len(ok_maps)), "scope": "all",
             "coverage": "complete"},
            {"name": "mapped_bytes_total", "value": str(
                sum(int(e["data"]["mapped_bytes"])
                    for e in ok_maps)), "scope": "all",
             "coverage": "complete"},
            {"name": "copy_original_to_bounce_bytes",
             "value": str(todev), "scope": "all",
             "coverage": "partial"},
            {"name": "copy_bounce_to_original_bytes",
             "value": str(tocpu), "scope": "all",
             "coverage": "partial"},
            {"name": "unpaired_lifecycle_events",
             "value": str(unpaired), "scope": "all",
             "coverage": "complete"},
            {"name": "sync_requests",
             "value": str(len(syncs)), "scope": "all",
             "coverage": "complete"},
            {"name": "completed_lifetime_count",
             "value": str(len(paired)), "scope": "all",
             "coverage": "complete"},
            {"name": "pool_used_bytes",
             "value": samples[-1]["data"]["used_bytes"],
             "scope": "all", "coverage": "complete"},
        ],
        "findings": [{"code": "UNPAIRED_LIFECYCLE"}],
    }
    report_path = os.path.join(tmp, "ft-f3b-report.json")
    with open(report_path, "w") as handle:
        handle.write(json.dumps(report, sort_keys=True))
    files["f3b-report.json"] = Path(report_path)
    ledger_row("f3b-report", exit=0)
    # Full-filesystem honesty: oracle facts only.
    f4_path = os.path.join(tmp, "ft-f4-oracle.log")
    with open(f4_path, "w") as handle:
        handle.write(oracle_script_log(ops=2))
    files["f4-oracle.log"] = Path(f4_path)
    ledger_row("f4", exit=1, stderr="enospc", cap=False)
    ledger[-1]["events_kept"] = True
    ledger[-1]["ready"] = "ready session=f4"
    # Paced floods: 1ch attempts plus exact 3ch multisets.
    window = window_for(600000000)
    session_id = "cap-synth-f5a"
    start = window[0] + 1000
    events = []
    for i in range(300):
        size = LC_SIZES[i % len(LC_SIZES)]
        events.append(synth_event(
            session_id, i, start + i * 1000,
            "bounce_attempt",
            {"requested_bytes": str(size)}))
    session = synth_session(
        session_id=session_id, start_ns=start - 5000000,
        span_ns=120000000000,
        detail_reason=zero_reason(False),
        correlation="not_applicable")
    put("f5a", {"exit": 0, "ready": "ready session=f5a"},
        session, events, oracle_script_log(ops=300))
    ledger_row("f5a", window)
    window = window_for(600000000)
    session_id = "cap-synth-f5b"
    start = window[0] + 1000
    events = flood_events(session_id, start)
    session = synth_session(
        session_id=session_id, start_ns=start - 5000000,
        span_ns=120000000000,
        detail_reason=zero_reason(True))
    put("f5b", {"exit": 0, "ready": "ready session=f5b"},
        session, events, oracle_script_log(ops=300))
    ledger_row("f5b", window)
    # Burst flood: 10 omitted records reconciled exactly.
    window = window_for(600000000)
    session_id = "cap-synth-f5c"
    start = window[0] + 1000
    drop = tuple([("map_result", i) for i in range(290, 294)]
                 + [("unmap", i) for i in range(290, 294)]
                 + [("copy", 0), ("copy", 1)])
    events = flood_events(session_id, start, drop=drop)
    buckets = dict(zero, duration_omitted=10)
    pairs = " ".join("%s=(%d)" % (name, buckets[name])
                     for name in core.LOSS_BUCKETS)
    reason = "detail loss 10 (%s)%s" % (pairs, suffix3)
    session = synth_session(
        session_id=session_id, start_ns=start - 5000000,
        span_ns=120000000000, detail_status="partial",
        loss_count="10", detail_reason=reason)
    put("f5c", {"exit": 0, "ready": "ready session=f5c"},
        session, events, oracle_script_log(ops=300))
    ledger_row("f5c", window)
    # Attach race: scenario-1 slice exact, nothing early.
    window = window_for(200000000)
    session_id = "cap-synth-f6"
    start = window[0] + 1000
    events = scenario1_events(session_id, start)
    session = synth_session(
        session_id=session_id, start_ns=start - 5000000,
        span_ns=60000000000,
        detail_reason=zero_reason(True))
    oracle = ("[0.0] mv-oracle: op=0 attempt requested=4096 "
              "forced=0\n"
              "[0.0] mv-oracle: op=0 outcome=success "
              "mapping=0 mapped=4096\n"
              "[0.0] mv-oracle: mapping=0 release "
              "lifetime_ns=10\n"
              "[0.0] mv-oracle: op=1 attempt requested=1024 "
              "forced=0\n"
              "[0.0] mv-oracle: op=1 outcome=success "
              "mapping=1 mapped=1024\n"
              "[0.0] mv-oracle: mapping=1 release "
              "lifetime_ns=11\n"
              "[0.0] mv-oracle: script complete ops=2\n")
    put("f6", {"exit": 0, "ready": "ready session=f6"},
        session, events, oracle)
    ledger_row("f6", window)
    ledger_path = os.path.join(tmp, "ft-faults.json")
    with open(ledger_path, "w") as handle:
        handle.write(json.dumps(ledger, sort_keys=True))
    files["faults.json"] = Path(ledger_path)
    return files


def self_test_faults(tmp):
    """Faults leg preserved on a synthetic seven-scenario boot."""
    ok = True
    files = synth_faults_files(tmp)
    bad, _ = judge_case(files, "faults", synth_manifest())
    ok = check("judge-faults", bad == [],
               "; ".join(bad[:3])) and ok
    # f3a/f3b alone leave the leg open: dropping the burst
    # flood's reconcile fails the judgment.
    files = synth_faults_files(tmp)
    events = _events(str(files["f5c-events.ndjson"]))
    extra = dict(events[0])
    extra["seq"] = max(e["seq"] for e in events) + 1
    events.append(extra)
    write_events(str(files["f5c-events.ndjson"]), events)
    bad, _ = judge_case(files, "faults", synth_manifest())
    ok = check("judge-faults-burst",
               bad != [], "burst drift passed") and ok
    # Unknown loss fails closed: the burst reconcile never
    # passes undeclared gaps.
    files = synth_faults_files(tmp)
    session = json.loads(
        files["f5c-session.json"].read_text())
    session["quality"]["detail"]["reason"] = \
        "detail loss unknown (cut; known: submit_fail=(10) " \
        "malformed=(0) dropped=(0) recursion_missed=(0) " \
        "size_omitted=(0) duration_omitted=(0) " \
        "signal_omitted=(0) rejected=(0) write_failed=(0))"
    files["f5c-session.json"].write_text(json.dumps(session))
    bad, _ = judge_case(files, "faults", synth_manifest())
    ok = check("judge-faults-unknown",
               any("unreconciled" in reason
                   for reason in bad),
               "; ".join(bad[:2])) and ok
    return ok


def _f4_calls_in_order(node):
    """Call nodes under node in execution order (post-order walk)."""
    found = []
    for child in ast.iter_child_nodes(node):
        found.extend(_f4_calls_in_order(child))
    if isinstance(node, ast.Call):
        found.append(node)
    return found


class _FakeRec:
    """Minimal Popen stand-in for readiness tests."""
    def __init__(self, stdout_fh, exits):
        self.stdout = stdout_fh
        self._exits = list(exits)
        self.returncode = None
        self.killed = False

    def poll(self):
        if self._exits:
            self.returncode = self._exits.pop(0)
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9


class _BoundedFile:
    """Fake bounded-filesystem file: N writes, then err."""
    def __init__(self, budget, err=None):
        import errno as errno_mod
        self.left = budget
        self.writes = 0
        self.errno = err if err is not None \
            else errno_mod.ENOSPC

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def write(self, chunk):
        if self.left <= 0:
            raise OSError(self.errno, "injected")
        self.left -= 1
        self.writes += 1
        return len(chunk)


class _ZeroFile:
    """Fake file whose writes report zero without error."""
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def write(self, chunk):
        return 0


def self_test_f4_staging(tmp):
    """f4 admits the reserve, then fills; await classified."""
    from unittest import mock
    import errno as errno_mod
    import io
    ok = True
    reserve = battery_guest.FINALIZE_RESERVE_BYTES
    headroom = battery_guest.F4_HEADROOM_BYTES
    size = battery_guest.f4_fs_bytes()
    # Admission on mocked filesystem sizes: the new
    # staging admits the reserve plus headroom, the
    # old 64k staging (and its ~8k free) cannot.
    ok = check("f4-admits",
               size == reserve + headroom
               and battery_guest.f4_admits_start(size)) \
        and ok
    ok = check("f4-rejects-starved",
               not battery_guest.f4_admits_start(65536)
               and not battery_guest.f4_admits_start(8192)) \
        and ok
    # Reserve boundary: the bare reserve with zero
    # headroom is rejected (prepare needs staging and
    # baseline bytes past the fallocate), the staged
    # size is admitted with margin.
    ok = check("f4-boundary",
               not battery_guest.f4_admits_start(reserve - 1)
               and not battery_guest.f4_admits_start(reserve)
               and battery_guest.f4_admits_start(size)) and ok
    # Headroom covers the modeled pre-fill need (a 4 KiB
    # baseline line plus 64 one-KiB slow-guest events,
    # two orders past any millisecond-scale
    # ready-to-fill window); the mount arg stays KiB-exact.
    ok = check("f4-headroom",
               headroom >= 4096 + 64 * 1024
               and size % 1024 == 0) and ok
    # Fill-after-start, pinned structurally: in
    # run_faults the f4 fill runs strictly after the f4
    # readiness wait, the mount precedes both, and the
    # starved pre-start staging is gone.
    try:
        tree = ast.parse(GUEST.read_text())
    except OSError as exc:
        return check("f4-order", False, str(exc)) and ok
    faults = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) \
                and node.name == "run_faults":
            faults = node
            break

    def kind(call):
        func = call.func
        if isinstance(func, ast.Name):
            if func.id == "sh" and call.args \
                    and isinstance(call.args[0], ast.List) \
                    and call.args[0].elts \
                    and isinstance(call.args[0].elts[0],
                                   ast.Constant) \
                    and call.args[0].elts[0].value == "mount":
                return "mount"
            if func.id == "await_record_ready":
                for arg in call.args:
                    if isinstance(arg, ast.Constant) \
                            and arg.value == "f4-record.stderr":
                        return "await-f4"
                return "await"
            if func.id == "fill_to_full":
                return "fill"
        elif isinstance(func, ast.Attribute) \
                and func.attr == "Popen":
            return "popen"
        return ""
    calls = _f4_calls_in_order(faults) \
        if faults is not None else []
    kinds = [kind(call) for call in calls]

    def pos(want):
        return [i for i, got in enumerate(kinds)
                if got == want]
    mounts, awaits, fills = \
        pos("mount"), pos("await-f4"), pos("fill")
    order = (faults is not None and len(mounts) == 1
             and len(awaits) == 1 and len(fills) == 1
             and mounts[0] < awaits[0] < fills[0])
    ok = check("f4-order", order,
               "%d mount %d await-f4 %d fill"
               % (len(mounts), len(awaits), len(fills))) \
        and ok
    denied = False
    if len(awaits) == 1:
        for word in calls[awaits[0]].keywords:
            if word.arg == "allow_refusal" \
                    and isinstance(word.value, ast.Constant):
                denied = word.value.value is False
    ok = check("f4-requires-ready", denied) and ok
    dump = ast.dump(faults) if faults is not None else ""
    ok = check("f4-no-starved-staging",
               "size=64k" not in dump
               and "57344" not in dump) and ok
    # Mocked growth: the filler stops quietly at ENOSPC
    # and fails loudly on anything else.
    seen = {}
    fake_file = []

    def fake_open(path, mode="r", buffering=-1, **kw):
        seen["mode"] = mode
        seen["buffering"] = buffering
        return fake_file[0]

    def fails_quietly(fn):
        """Run fn; return its FAIL text, else None."""
        with mock.patch.object(sys, "stderr",
                               io.StringIO()) as err:
            try:
                fn()
            except SystemExit:
                return err.getvalue()
        return None
    fake_file.append(_BoundedFile(3))
    with mock.patch("builtins.open", fake_open):
        battery_guest.fill_to_full("filler")
    ok = check("f4-fill-stops",
               fake_file[0].writes == 3
               and seen.get("buffering") == 0
               and seen.get("mode") == "ab") and ok
    fake_file[0] = _BoundedFile(0)
    with mock.patch("builtins.open", fake_open):
        battery_guest.fill_to_full("filler")
    ok = check("f4-fill-full-now",
               fake_file[0].writes == 0) and ok
    fake_file[0] = _BoundedFile(3, errno_mod.EIO)
    with mock.patch("builtins.open", fake_open):
        text = fails_quietly(
            lambda: battery_guest.fill_to_full("filler"))
    ok = check("f4-fill-other-errno",
               text is not None
               and "filler failed" in text,
               (text or "")[:80]) and ok
    fake_file[0] = _ZeroFile()
    with mock.patch("builtins.open", fake_open):
        text = fails_quietly(
            lambda: battery_guest.fill_to_full("filler"))
    ok = check("f4-fill-zero",
               text is not None
               and "zero bytes" in text,
               (text or "")[:80]) and ok
    # ENOSPC on open means already full (quiet); any
    # other open errno fails loudly.
    def raise_open(path, mode="r", buffering=-1, **kw):
        raise OSError(open_errno[0], "injected")
    open_errno = [errno_mod.ENOSPC]
    with mock.patch("builtins.open", raise_open):
        text = fails_quietly(
            lambda: battery_guest.fill_to_full("filler"))
    ok = check("f4-fill-open-full", text is None) and ok
    open_errno[0] = errno_mod.EACCES
    with mock.patch("builtins.open", raise_open):
        text = fails_quietly(
            lambda: battery_guest.fill_to_full("filler"))
    ok = check("f4-fill-open-other",
               text is not None
               and "filler failed" in text,
               (text or "")[:80]) and ok

    # Readiness branches: success, expected refusal,
    # and every unexpected death shape.
    def pipe_with(text):
        """Pipe read end serving text, write end closed (EOF)."""
        rd, wr = os.pipe()
        if text:
            os.write(wr, text.encode())
        os.close(wr)
        return os.fdopen(rd, "r", buffering=1)
    work = os.path.join(tmp, "f4-await")
    os.makedirs(work)
    errname = "t-record.stderr"
    with open(os.path.join(work, errname), "wb") as handle:
        handle.write(b"tail-bytes")
    stdout = pipe_with("noise\nready session=t start_ns=1\n")
    try:
        ready, tail = battery_guest.await_record_ready(
            _FakeRec(stdout, []), work, errname)
    finally:
        stdout.close()
    ok = check("await-ready",
               ready == "ready session=t start_ns=1"
               and tail() == "tail-bytes") and ok
    stdout = pipe_with("")
    try:
        state = battery_guest.await_record_ready(
            _FakeRec(stdout, [3]), work, errname,
            allow_refusal=True)
    finally:
        stdout.close()
    ok = check("await-refused-allowed",
               state[0] is None
               and state[1]() == "tail-bytes") and ok
    for tag, exits, allow, want in (
            ("denied", [3], False,
             "refused pre-readiness"),
            ("died", [1], False,
             "died pre-readiness (exit 1)"),
            ("signal", [-15], False,
             "died pre-readiness (signal 15)")):
        stdout = pipe_with("")
        try:
            text = fails_quietly(
                lambda: battery_guest.await_record_ready(
                    _FakeRec(stdout, exits), work, errname,
                    allow_refusal=allow))
        finally:
            stdout.close()
        ok = check("await-%s" % tag,
                   text is not None and want in text,
                   (text or "")[:80]) and ok
    # Timeout without waiting: the clock jumps past the
    # deadline while the process stays alive.
    stdout = pipe_with("")
    rec = _FakeRec(stdout, [])
    try:
        with mock.patch("time.monotonic",
                        side_effect=[100.0, 161.0]):
            text = fails_quietly(
                lambda: battery_guest.await_record_ready(
                    rec, work, errname))
    finally:
        stdout.close()
    ok = check("await-timeout",
               text is not None
               and "never reached readiness" in text
               and rec.killed,
               (text or "")[:80]) and ok
    return ok


# -- Unarmed self-test: manifest + selection ------------------

def self_test_manifest(tmp):
    """Input manifest round-trip plus tamper refusals."""
    seal = [REPO / "dist" / "candidate.json",
            REPO / "dist" / "bundle.tar.gz"]
    if not all(p.is_file() for p in seal):
        print("ok manifest SKIP (no dist/ seal in tree)")
        return True
    ok = True
    try:
        inputs = core.materialize(
            str(REPO), os.path.join(tmp, "inputs"),
            str(seal[0]), str(seal[1]))
    except (ValueError, OSError) as exc:
        return check("manifest-materialize", False,
                     str(exc)[:200])
    ok = check("manifest-materialize",
               inputs["binary"]["sha256"]
               == inputs["candidate"]["files"][
                   "bin/memveil"]) and ok
    prof_dir = os.path.dirname(inputs["profile"]["path"])
    try:
        listed = open(os.path.join(
            prof_dir, "manifest.txt")).read().split()
        ok = check("manifest-profiles-dir",
                   listed == ["battery-profile.json"]
                   and sha_file(
                       inputs["profile"]["path"])
                   == core.PROFILE_SHA256) and ok
    except OSError as exc:
        ok = check("manifest-profiles-dir", False,
                   str(exc)) and ok
    try:
        built = score.build_consumer()
    except ValueError as exc:
        return check("manifest-consumer", False,
                     str(exc)[:200])
    commit = core.git_head(str(REPO))
    cases = [c for c in core.CASES if c != "saturation"]
    try:
        staged = write_guest_inputs_docs(
            tmp, cases, os.path.join(tmp, "inputs.json"),
            built, inputs, None, "")
    except (ValueError, OSError) as exc:
        return check("manifest-inputs-stage", False,
                     str(exc)[:200])
    manifest = core.write_input_manifest(
        os.path.join(tmp, "inputs.json"), inputs,
        {"sha256": built["sha256"], "build": built["build"]},
        cases, ["test_battery", "--case", "matrix"], commit,
        guest_inputs=staged)
    ok = check("manifest-verify",
               core.verify_input_manifest(
                   manifest, built["path"]) == [],
               "; ".join(core.verify_input_manifest(
                   manifest, built["path"])[:2])) and ok
    ok = check("manifest-guest-inputs",
               sorted(manifest["guest_inputs"])
               == sorted(cases)
               and manifest["guest_inputs"][
                   "matrix"]["file"]
               == core.GUEST_INPUTS_FILE) and ok
    ok = check("manifest-cases",
               manifest["cases"] == cases
               and manifest["schema"] == core.SCHEMA
               and manifest["runner_commit"] == commit) \
        and ok
    ok = check("manifest-oracle",
               manifest["oracle"]["ko_sha256"]
               == guest_oracle.KO_SHA256
               and manifest["oracle"]["guest_release"]
               == core.EXPECT_RELEASE) and ok
    # Every tamper refuses with its own reason.
    tampers = []

    def tampered(path, value):
        import copy
        other = copy.deepcopy(manifest)
        node = other
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value
        return other
    tampers.append(("schema",
                    tampered(["schema"], "bogus/0")))
    tampers.append(("cases",
                    tampered(["cases"], ["matrix",
                                         "bogus"])))
    tampers.append(("consumer",
                    tampered(["consumer", "binary_sha256"],
                             "0" * 64)))
    tampers.append(("binary",
                    tampered(["binary", "sha256"], "0" * 64)))
    tampers.append(("lc-bytes",
                    tampered(["objects", "lc", "sha256"],
                             "0" * 64)))
    tampers.append(("profile",
                    tampered(["profile", "sha256"], "0" * 64)))
    tampers.append(("oracle",
                    tampered(["oracle", "ko_sha256"],
                             "0" * 64)))
    tampers.append(("guest",
                    tampered(["guest", "vmlinuz_sha256"],
                             "0" * 64)))
    tampers.append(("candidate",
                    tampered(["candidate", "source",
                              "commit"], "0" * 64)))
    tampers.append(("guest-inputs",
                    tampered(["guest_inputs", "matrix",
                              "sha256"], "0" * 64)))
    for name, other in tampers:
        reasons = core.verify_input_manifest(
            other, built["path"])
        ok = check("manifest-tamper-%s" % name,
                   reasons != [],
                   "tamper passed") and ok
    # Saturation without bound test objects refuses.
    sat = tampered(["cases"],
                   ["matrix", "saturation"])
    reasons = core.verify_input_manifest(sat, built["path"])
    ok = check("manifest-saturation-unbound",
               any("test objects" in reason
                   for reason in reasons),
               "; ".join(reasons[:2])) and ok
    # Malformed shapes refuse instead of crashing.
    nulls = tampered(["objects"], None)
    reasons = core.verify_input_manifest(nulls, built["path"])
    ok = check("manifest-null-objects",
               any("not a mapping" in reason
                   for reason in reasons),
               "; ".join(reasons[:2])) and ok
    # Bound test objects round-trip structurally. The C9
    # bytes stand in for the future small-ring objects to
    # prove the plumbing only; live flood accounting still
    # needs the real objects (the loader's exact layout
    # allowlist plus the induced-loss judgment refuse
    # anything else).
    sat_pair = {"bound": True,
                "lc": {"path": inputs["lc"]["path"],
                       "sha256": inputs["lc"]["sha256"]},
                "cp": {"path": inputs["cp"]["path"],
                       "sha256": inputs["cp"]["sha256"]}}
    try:
        sat_staged = write_guest_inputs_docs(
            tmp, ["saturation"],
            os.path.join(tmp, "inputs-bound.json"), built,
            inputs, sat_pair, "")
    except (ValueError, OSError) as exc:
        return check("manifest-saturation-stage", False,
                     str(exc)[:200])
    bound = core.write_input_manifest(
        os.path.join(tmp, "inputs-bound.json"), inputs,
        {"sha256": built["sha256"], "build": built["build"]},
        ["saturation"], ["test_battery", "--case",
                         "saturation"], commit,
        test_objects={
            "lc": {"path": inputs["lc"]["path"]},
            "cp": {"path": inputs["cp"]["path"]}},
        guest_inputs=sat_staged)
    reasons = core.verify_input_manifest(bound, built["path"])
    ok = check("manifest-saturation-bound",
               reasons == [], "; ".join(reasons[:2])) and ok
    ok = check("manifest-bound-stamps",
               bound["test_objects"]["bound"] is True
               and bound["test_objects"]["lc"]["sha256"]
               == inputs["lc"]["sha256"]) and ok
    # A wrong consumer binary refuses against the manifest.
    other = os.path.join(tmp, "other-consumer")
    with open(other, "wb") as handle:
        handle.write(b"not the consumer")
    reasons = core.verify_input_manifest(manifest, other)
    ok = check("manifest-consumer-drift",
               any("consumer digest" in reason
                   for reason in reasons),
               "; ".join(reasons[:2])) and ok
    return ok


def parse_cases(values):
    """Parse --case values into an ordered unique case list.

    Refuses unknown names and repeats: a repeated case
    would boot twice for one receipt row.
    """
    cases = []
    for value in values:
        for name in value.split(","):
            name = name.strip()
            if not name:
                continue
            if name not in core.CASES:
                raise ValueError(
                    "bad --case %r: want one of %s"
                    % (name, ", ".join(core.CASES)))
            if name in cases:
                raise ValueError("duplicate --case %s"
                                 % name)
            cases.append(name)
    if not cases:
        raise ValueError("no --case selected")
    return cases


def self_test_selection():
    """Case selection: valid sets pass, bad input refuses."""
    ok = True
    try:
        cases = parse_cases(["matrix,copy",
                             "canonical-c"])
        ok = check("select-split",
                   cases == ["matrix", "copy",
                             "canonical-c"],
                   "%r" % (cases,)) and ok
    except ValueError as exc:
        ok = check("select-split", False, str(exc)) and ok
    for name, values in (("unknown", ["bogus"]),
                         ("dup", ["matrix,matrix"]),
                         ("empty", [""]),
                         ("none", [])):
        try:
            parse_cases(values)
            ok = check("select-%s" % name, False,
                       "accepted") and ok
        except ValueError:
            ok = check("select-%s" % name, True) and ok
    return ok


def build_guest_inputs(case, manifest_path, built, inputs,
                       test_objects, expect_release):
    """Staged inputs doc bytes for one case (host-tested).

    Carries every path and digest the guest flow verifies;
    the host writes these exact bytes to the shared export
    dir and binds their digest in the run manifest, while
    the guest command line carries only the pointer
    filename. Refuses the saturation case until its test
    objects bind. test_objects is the manifest test-object
    entry (or None when unbound).
    """
    if case not in core.CASES:
        raise ValueError("bad case %r" % (case,))
    if case == "saturation":
        if not test_objects or not test_objects.get("bound"):
            raise ValueError(
                "saturation needs bound 4 KiB test objects")
        test_lc = {"path": test_objects["lc"]["path"],
                   "sha256": test_objects["lc"]["sha256"]}
        test_cp = {"path": test_objects["cp"]["path"],
                   "sha256": test_objects["cp"]["sha256"]}
    else:
        test_lc = {"path": "", "sha256": ""}
        test_cp = {"path": "", "sha256": ""}
    doc = {
        "schema": core.GUEST_INPUTS_SCHEMA,
        "case": case,
        "expect_release": expect_release,
        "manifest": str(manifest_path),
        "consumer": {"path": built["path"],
                     "sha256": built["sha256"]},
        "ko": {"path": guest_oracle.FIXTURE_KO,
               "sha256": guest_oracle.KO_SHA256},
        "lc": {"path": inputs["lc"]["path"],
               "sha256": inputs["lc"]["sha256"]},
        "cp": {"path": inputs["cp"]["path"],
               "sha256": inputs["cp"]["sha256"]},
        "attempt": {"path": inputs["attempt"]["path"],
                    "sha256": inputs["attempt"]["sha256"]},
        "binary": {"path": inputs["binary"]["path"],
                   "sha256": inputs["binary"]["sha256"]},
        "profile": {"path": inputs["profile"]["path"],
                    "sha256": inputs["profile"]["sha256"]},
        "profiles_dir": os.path.dirname(
            inputs["profile"]["path"]),
        "test_lc": test_lc,
        "test_cp": test_cp,
    }
    return (json.dumps(doc, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def write_guest_inputs_docs(work, cases, manifest_path, built,
                            inputs, test_objects,
                            expect_release):
    """Stage one inputs doc per case; return {case: path}."""
    staged = {}
    for case in cases:
        blob = build_guest_inputs(
            case, manifest_path, built, inputs,
            test_objects, expect_release)
        doc_path = os.path.join(work, "guest-inputs-%s.json"
                                % case)
        with open(doc_path, "wb") as handle:
            handle.write(blob)
        staged[case] = doc_path
    return staged


def build_guest_argv(case):
    """Guest command line for one case (host-tested wiring).

    Carries only the staged inputs filename: the full
    inputs doc travels through the shared export dir, so
    the joined payload stays far under GUEST_EXEC_BUDGET
    however long the host paths grow.
    """
    if case not in core.CASES:
        raise ValueError("bad case %r" % (case,))
    return [sys.executable, str(GUEST), "/tmp/vmgate-work",
            "/tmp/export",
            "--inputs", core.GUEST_INPUTS_FILE]


def self_test_guest_argv(tmp):
    """Guest argv carries only the staged inputs pointer."""
    ok = True
    try:
        argv = build_guest_argv("matrix")
        joined = " ".join(argv)
        ok = check("argv-pointer",
                   argv[-2:] == ["--inputs",
                                core.GUEST_INPUTS_FILE]
                   and "--bridge" not in joined
                   and not re.search(r"[0-9a-f]{64}",
                                     joined),
                   joined[-160:]) and ok
    except ValueError as exc:
        ok = check("argv-pointer", False, str(exc)) and ok
    try:
        argv = build_guest_argv("saturation")
        ok = check("argv-saturation-shape",
                   argv[-2:] == ["--inputs",
                                core.GUEST_INPUTS_FILE],
                   " ".join(argv)[-160:]) and ok
    except ValueError as exc:
        ok = check("argv-saturation-shape", False,
                   str(exc)) and ok
    try:
        build_guest_argv("bogus")
        ok = check("argv-bogus", False, "accepted") and ok
    except ValueError:
        ok = check("argv-bogus", True) and ok
    return ok


def synth_inputs():
    """Self-consistent inputs dict for offline doc tests."""
    return {
        "lc": {"path": "/w/lc.o", "sha256": score.C9_LC_SHA},
        "cp": {"path": "/w/cp.o", "sha256": score.C9_CP_SHA},
        "attempt": {"path": "/w/at.o",
                    "sha256": score.C9_ATTEMPT_SHA},
        "binary": {"path": "/w/memveil", "sha256": "b" * 64},
        "profile": {"path": "/w/prof.json",
                    "sha256": core.PROFILE_SHA256},
    }


def self_test_cmdline_budget(tmp):
    """Cmdline projection refuses over budget, frees real argvs."""
    ok = True
    ok = check("budget-arithmetic",
               project_cmdline_total(GUEST_EXEC_BUDGET)
               == COMMAND_LINE_SIZE
               and project_cmdline_total(
                   GUEST_EXEC_BUDGET + 1)
               == COMMAND_LINE_SIZE + 4) and ok
    for length, want in ((0, False),
                         (GUEST_EXEC_BUDGET - 1, False),
                         (GUEST_EXEC_BUDGET, False),
                         (GUEST_EXEC_BUDGET + 1, True),
                         (1939, True)):
        try:
            over = cmdline_over_budget(length)
            ok = check("budget-%d" % length, over == want,
                       "over=%s want=%s" % (over, want)) \
                and ok
        except ValueError as exc:
            ok = check("budget-%d" % length, False,
                       str(exc)) and ok
    worst = 0
    worst_case = ""
    all_ok = True
    for case in core.CASES:
        argv = build_guest_argv(case)
        total = project_cmdline_total(
            len(shlex.join(argv)))
        if total > worst:
            worst = total
            worst_case = case
        if total > COMMAND_LINE_SIZE - CMDLINE_HEADROOM:
            all_ok = False
    ok = check("budget-real-argvs", all_ok,
               "worst %s projects %d (ceiling %d, "
               "headroom floor %d)"
               % (worst_case, worst, COMMAND_LINE_SIZE,
                  COMMAND_LINE_SIZE - CMDLINE_HEADROOM)) \
        and ok
    return ok


def self_test_guest_inputs(tmp):
    """Inputs docs stage, parse, bind, and refuse tampering."""
    ok = True
    built = {"path": "/w/stress-consume",
             "sha256": "c" * 64}
    inputs = synth_inputs()
    try:
        staged = write_guest_inputs_docs(
            tmp, ["matrix", "record3"], "/w/inputs.json",
            built, inputs, None, "")
    except (ValueError, OSError) as exc:
        return check("inputs-stage", False, str(exc)[:160])
    ok = check("inputs-stage",
               sorted(staged) == ["matrix", "record3"],
               "%r" % (sorted(staged),)) and ok
    try:
        blob = open(staged["matrix"], "rb").read()
        doc = json.loads(blob.decode("utf-8"))
        ok = check("inputs-doc",
                   doc["schema"]
                   == core.GUEST_INPUTS_SCHEMA
                   and doc["case"] == "matrix"
                   and doc["lc"]["sha256"]
                   == score.C9_LC_SHA
                   and doc["ko"]["sha256"]
                   == guest_oracle.KO_SHA256
                   and doc["test_lc"] == {"path": "",
                                          "sha256": ""},
                   blob[:120].decode("utf-8",
                                     "replace")) and ok
    except (OSError, ValueError) as exc:
        ok = check("inputs-doc", False, str(exc)[:160]) \
            and ok
    try:
        build_guest_inputs("saturation", "/w/inputs.json",
                           built, inputs, None, "")
        ok = check("inputs-saturation-unbound", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("inputs-saturation-unbound",
                   "test objects" in str(exc),
                   str(exc)[:160]) and ok
    bound = {"bound": True,
             "lc": {"path": "/w/tlc.o", "sha256": "d" * 64},
             "cp": {"path": "/w/tcp.o", "sha256": "e" * 64}}
    try:
        blob = build_guest_inputs(
            "saturation", "/w/inputs.json", built, inputs,
            bound, "")
        doc = json.loads(blob.decode("utf-8"))
        ok = check("inputs-saturation-bound",
                   doc["test_lc"]["path"] == "/w/tlc.o"
                   and doc["test_cp"]["sha256"]
                   == "e" * 64,
                   blob[:120].decode("utf-8",
                                     "replace")) and ok
    except ValueError as exc:
        ok = check("inputs-saturation-bound", False,
                   str(exc)[:160]) and ok
    export = os.path.join(tmp, "export")
    os.makedirs(export, exist_ok=True)
    staged_copy = os.path.join(export, core.GUEST_INPUTS_FILE)
    shutil.copyfile(staged["matrix"], staged_copy)
    manifest_path = os.path.join(tmp, "manifest.json")
    with open(staged_copy, "r+b") as handle:
        raw = handle.read().replace(b"/w/inputs.json",
                                    manifest_path.encode())
        handle.seek(0)
        handle.write(raw)
        handle.truncate()
    with open(manifest_path, "w") as handle:
        handle.write(json.dumps({
            "guest_inputs": {
                "matrix": {
                    "file": core.GUEST_INPUTS_FILE,
                    "sha256": sha_file(staged_copy),
                },
            },
        }))
    try:
        fields, observed = battery_guest.parse_guest_inputs(
            export, core.GUEST_INPUTS_FILE)
        ok = check("inputs-parse",
                   fields["case"] == "matrix"
                   and fields["lc_sha"] == score.C9_LC_SHA
                   and fields["manifest"] == manifest_path
                   and observed == sha_file(staged_copy),
                   observed[:16]) and ok
    except ValueError as exc:
        ok = check("inputs-parse", False,
                   str(exc)[:160]) and ok
    with open(staged_copy, "ab") as handle:
        handle.write(b" ")
    try:
        battery_guest.parse_guest_inputs(
            export, core.GUEST_INPUTS_FILE)
        ok = check("inputs-tamper", False, "accepted") \
            and ok
    except ValueError as exc:
        ok = check("inputs-tamper",
                   "differ from the manifest binding"
                   in str(exc),
                   str(exc)[:160]) and ok
    for label, name in (("absolute", "/etc/hostname"),
                        ("escape", "../inputs.json"),
                        ("empty", "")):
        try:
            battery_guest.parse_guest_inputs(export, name)
            ok = check("inputs-pointer-%s" % label, False,
                       "accepted") and ok
        except ValueError as exc:
            ok = check("inputs-pointer-%s" % label,
                       "bare filename" in str(exc),
                       str(exc)[:160]) and ok
    return ok


def self_test_identity():
    """Identity re-checks pass clean and catch every drift."""
    ok = True
    manifest = synth_manifest()
    ident = synth_identity()
    ok = check("identity-consumer",
               judge_identity(ident, manifest, "matrix")
               == []) and ok
    ident = synth_identity(record=True)
    files = {"profile.json": REPO / core.PROFILE_REL}
    ok = check("identity-record",
               judge_record_identity(ident, manifest, files)
               == []) and ok
    drifts = [
        ("release", {"release": "bogus"}, "matrix"),
        ("btf", {"btf_sha256": "0" * 64}, "matrix"),
        ("ko", {"digests": {"ko": "0" * 64}}, "matrix"),
        ("lc", {"digests": {"lc": "0" * 64}}, "matrix"),
    ]
    for name, patch, case in drifts:
        ident = synth_identity()
        for key, value in patch.items():
            if key == "digests":
                ident["digests"].update(value)
            else:
                ident[key] = value
        bad = judge_identity(ident, manifest, case)
        ok = check("identity-drift-%s" % name, bad != [],
                   "drift passed") and ok
    ident = synth_identity(record=True)
    ident["digests"]["profile"] = "0" * 64
    bad = judge_record_identity(ident, manifest, files)
    ok = check("identity-drift-profile", bad != [],
               "drift passed") and ok
    return ok


def self_test_inputs_binding(tmp):
    """Guest-observed inputs digest must match the binding."""
    ok = True
    export = os.path.join(tmp, "bound-export")
    os.makedirs(export, exist_ok=True)
    staged = os.path.join(export, core.GUEST_INPUTS_FILE)
    with open(staged, "wb") as handle:
        handle.write(b'{"case": "matrix"}\n')
    digest = sha_file(staged)
    manifest = {"guest_inputs": {
        "matrix": {"file": core.GUEST_INPUTS_FILE,
                   "sha256": digest}}}
    verify_path = os.path.join(tmp, "input-verify.json")

    def files_for(doc):
        with open(verify_path, "w") as handle:
            handle.write(json.dumps(doc))
        return {"input-verify.json": Path(verify_path)}

    good = {"case": "matrix",
            "guest_inputs_file": core.GUEST_INPUTS_FILE,
            "guest_inputs_sha256": digest}
    ok = check("binding-clean",
               check_guest_inputs_binding(
                   files_for(good), "matrix", manifest,
                   export) == []) and ok
    drifted = dict(good, guest_inputs_sha256="0" * 64)
    ok = check("binding-drift",
               check_guest_inputs_binding(
                   files_for(drifted), "matrix", manifest,
                   export) != [],
               "drift passed") and ok
    renamed = dict(good, case="copy")
    ok = check("binding-case",
               check_guest_inputs_binding(
                   files_for(renamed), "matrix", manifest,
                   export) != [],
               "case swap passed") and ok
    with open(staged, "ab") as handle:
        handle.write(b" ")
    ok = check("binding-staged",
               check_guest_inputs_binding(
                   files_for(good), "matrix", manifest,
                   export) != [],
               "staged tamper passed") and ok
    os.unlink(verify_path)
    ok = check("binding-missing",
               check_guest_inputs_binding(
                   {}, "matrix", manifest, export) != [],
               "missing verify passed") and ok
    return ok


def self_test_inputs_manifest(tmp):
    """Manifest guest-inputs round-trip without the dist seal."""
    ok = True
    consumer_path = os.path.join(tmp, "consumer")
    with open(consumer_path, "wb") as handle:
        handle.write(b"synthetic consumer")
    consumer_sha = sha_file(consumer_path)
    binary_path = os.path.join(tmp, "memveil")
    with open(binary_path, "wb") as handle:
        handle.write(b"synthetic binary")
    binary_sha = sha_file(binary_path)
    aya = REPO / "tests" / "vm" / "fixtures" / "aya"
    inputs = {
        "binary": {"path": binary_path,
                   "sha256": binary_sha},
        "attempt": {"path": str(
            aya / "swiotlb_attempt.bpf.o"),
            "sha256": score.C9_ATTEMPT_SHA},
        "lc": {"path": str(
            aya / "swiotlb_lifecycle.bpf.o"),
            "sha256": score.C9_LC_SHA},
        "cp": {"path": str(
            aya / "swiotlb_copy.bpf.o"),
            "sha256": score.C9_CP_SHA},
        "profile": {"path": str(REPO / core.PROFILE_REL),
                    "sha256": core.PROFILE_SHA256,
                    "profile_id": core.PROFILE_ID},
        "candidate": {
            "source": {"commit": score.C9_SOURCE_COMMIT},
            "bundle_manifest_sha256":
                score.C9_BUNDLE_MANIFEST_SHA,
            "bundle": {"sha256": score.C9_BUNDLE_SHA},
            "files": {
                "bin/memveil": binary_sha,
                "bpf/swiotlb_attempt.bpf.o":
                    score.C9_ATTEMPT_SHA,
                "bpf/swiotlb_lifecycle.bpf.o":
                    score.C9_LC_SHA,
                "bpf/swiotlb_copy.bpf.o": score.C9_CP_SHA,
            },
        },
        "oracle": {
            "ko": guest_oracle.FIXTURE_KO,
            "ko_sha256": guest_oracle.KO_SHA256,
            "ko_vermagic": guest_oracle.GUEST_VERMAGIC,
            "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
            "guest_release": guest_oracle.GUEST_RELEASE,
        },
        "guest": {
            "row": "7.0",
            "vng_tag": core.VNG_TAG,
            "release": core.EXPECT_RELEASE,
            "vmlinuz_sha256": core.VMLINUZ_SHA256,
            "modules_manifest_sha256":
                core.MODULES_MANIFEST_SHA256,
        },
    }
    built = {"path": consumer_path, "sha256": consumer_sha,
             "build": "synthetic"}
    cases = ["matrix", "record3"]
    try:
        staged = write_guest_inputs_docs(
            tmp, cases, os.path.join(tmp, "syn-inputs.json"),
            built, inputs, None, "")
    except (ValueError, OSError) as exc:
        return check("syn-inputs-stage", False,
                     str(exc)[:160])
    try:
        manifest = core.write_input_manifest(
            os.path.join(tmp, "syn-inputs.json"), inputs,
            {"sha256": consumer_sha, "build": "synthetic"},
            cases, ["synthetic"], "syn-commit",
            guest_inputs=staged)
    except (ValueError, OSError) as exc:
        return check("syn-inputs-write", False,
                     str(exc)[:160])
    reasons = core.verify_input_manifest(
        manifest, consumer_path)
    ok = check("syn-inputs-verify", reasons == [],
               "; ".join(reasons[:2])) and ok
    import copy
    drifted = copy.deepcopy(manifest)
    drifted["guest_inputs"]["matrix"]["sha256"] = "0" * 64
    ok = check("syn-inputs-tamper",
               core.verify_input_manifest(
                   drifted, consumer_path) != [],
               "tamper passed") and ok
    dropped = copy.deepcopy(manifest)
    del dropped["guest_inputs"]["record3"]
    ok = check("syn-inputs-dropped",
               any("record3" in reason for reason in
                   core.verify_input_manifest(
                       dropped, consumer_path)),
               "dropped entry passed") and ok
    with open(staged["matrix"], "ab") as handle:
        handle.write(b" ")
    ok = check("syn-inputs-bytes",
               any("bytes differ" in reason
                   for reason in core.verify_input_manifest(
                       manifest, consumer_path)),
               "rewritten bytes passed") and ok
    return ok


def self_test_console_capture(tmp):
    """Boots stay verbose and transcripts land in receipts."""
    ok = True
    flight = {"prefix": ["vng"], "harness": {}}
    micro = build_vng_argv("matrix", flight, "/tmp/x",
                           "exec payload")
    full = build_vng_argv("faults", flight, "/tmp/x",
                          "exec payload")
    ok = check("console-verbose",
               "--verbose" in micro and "--verbose" in full
               and micro[-2:] == ["--exec", "exec payload"]
               and "--disable-microvm" not in micro
               and "--disable-microvm" in full,
               " ".join(micro[-6:])) and ok
    boot = os.path.join(tmp, "mock-boot")
    export = os.path.join(boot, "export")
    os.makedirs(export, exist_ok=True)
    transcript = ("[boot] console line\n"
                  "battery-guest: matrix exported\n")
    for name, blob in (
            ("boot.json", b'{"case": "matrix"}\n'),
            ("guest.stdout", b"guest out\n"),
            ("guest.stderr", transcript.encode()),
            ("guest.exit", b"0")):
        with open(os.path.join(boot, name), "wb") as handle:
            handle.write(blob)
    staged = b'{"case": "matrix"}\n'
    with open(os.path.join(export, core.GUEST_INPUTS_FILE),
              "wb") as handle:
        handle.write(staged)
    name = "identity.json"
    with open(os.path.join(export, name), "wb") as handle:
        handle.write(b"{}\n")
    digest = sha_file(os.path.join(export, name))
    with open(os.path.join(export, name + ".sha256"),
              "w") as handle:
        handle.write("%s  %s\n" % (digest, name))
    manifest_path = os.path.join(tmp, "mock-inputs.json")
    with open(manifest_path, "w") as handle:
        handle.write("{}\n")
    manifest = {"runner_commit": "mock",
                "consumer": {}, "candidate": {},
                "oracle": {}, "guest": {}, "profile": {}}
    out = Path(tmp) / "receipt" / "matrix"
    try:
        save_case_receipts(
            out, "matrix", Path(boot), Path(export),
            {name: Path(export) / name}, [name],
            manifest_path, manifest, [], {})
    except OSError as exc:
        return check("console-receipt", False,
                     str(exc)[:160])
    try:
        kept = (out / "host-guest.stderr").read_text()
        verdict = json.loads(
            (out / "host-verdict.json").read_text())
        pinned = (out / "host-guest-inputs.json"
                  ).read_bytes()
        ok = check("console-receipt",
                   kept == transcript
                   and verdict["console_transcript"]
                   == "host-guest.stderr"
                   and pinned == staged,
                   kept[:80]) and ok
    except (OSError, ValueError) as exc:
        ok = check("console-receipt", False,
                   str(exc)[:160]) and ok
    return ok


def run_self_test(work=None):
    """Full offline suite: proofs plus unarmed checks. No boot."""
    print("battery self-test (unarmed, offline)")
    tmp = work or tempfile.mkdtemp(prefix="vmgate-battery-")
    os.makedirs(tmp, exist_ok=True)
    keep = work is not None
    ok = True
    try:
        ok = self_test_pins() and ok
        ok = self_test_gate_constants() and ok
        ok = self_test_consumer_build() and ok
        pairs = {"c9": {
            "lc": {"path": str(
                REPO / "tests/vm/fixtures/aya/"
                       "swiotlb_lifecycle.bpf.o"),
                "sha256": score.C9_LC_SHA},
            "cp": {"path": str(
                REPO / "tests/vm/fixtures/aya/"
                       "swiotlb_copy.bpf.o"),
                "sha256": score.C9_CP_SHA}}}
        ok = self_test_layouts(tmp, pairs) and ok
        ok = self_test_wrong_pair(pairs) and ok
        ok = self_test_prefix_rule() and ok
        ok = self_test_matrix(tmp) and ok
        ok = self_test_copy(tmp) and ok
        ok = self_test_canonical(tmp) and ok
        ok = self_test_stop(tmp) and ok
        ok = self_test_saturation(tmp) and ok
        ok = self_test_skipsync(tmp) and ok
        ok = self_test_loss_grammar() and ok
        ok = self_test_record3(tmp) and ok
        ok = self_test_faults(tmp) and ok
        ok = self_test_f4_staging(tmp) and ok
        ok = self_test_manifest(tmp) and ok
        ok = self_test_selection() and ok
        ok = self_test_guest_argv(tmp) and ok
        ok = self_test_cmdline_budget(tmp) and ok
        ok = self_test_guest_inputs(tmp) and ok
        ok = self_test_inputs_binding(tmp) and ok
        ok = self_test_inputs_manifest(tmp) and ok
        ok = self_test_console_capture(tmp) and ok
        ok = self_test_identity() and ok
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print("battery self-test: %s" % ("PASS" if ok else "FAIL"))
    return ok


# -- Armed run (prepared; needs the live-VM lease) ---------------

def armed_preflight():
    """Resolve vng + harness versions; armed failures are fatal."""
    from test_attempt_capture import find_vng, gate_prefix
    from harness_env import check_harness_versions
    vng = find_vng()
    if not vng:
        print("FAIL vm-battery: armed but vng missing")
        return None
    try:
        harness = check_harness_versions(vng)
    except ValueError as exc:
        print("FAIL vm-battery: armed but %s" % (exc,))
        return None
    try:
        prefix, _env = gate_prefix()
    except Exception as exc:  # pytest.skip/fail raise here
        print("FAIL vm-battery: armed but %s" % (exc,))
        return None
    return {"vng": vng, "harness": harness, "prefix": prefix}


def verify_guest_cache():
    """Verify the pinned guest kernel cache against the lock.

    Returns (ok, detail, kernel_ref): nothing is fetched
    here; a missing cache names the tool that fills it.
    """
    from kernel_matrix import verify_entry_cache
    try:
        entry = core.pinned_guest_entry(str(REPO))
    except ValueError as exc:
        return False, str(exc), None
    home = os.path.expanduser("~")
    try:
        ok, why, ref = verify_entry_cache(home, entry)
    except Exception as exc:
        return False, "cache verify failed: %s" % exc, None
    return ok, why, ref


def verify_exports(export, case):
    """Exact inventory + sidecar check; returns {ok, files, reasons}.

    The host-staged inputs doc shares the export dir but
    is not guest output: the binding check verifies it
    separately, so the guest inventory excludes it here.
    """
    names = EXPORT_NAMES[case]
    result = {"ok": False, "files": {}, "reasons": []}
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        result["reasons"].append("export unreadable: %s" % (exc,))
        return result
    have.discard(core.GUEST_INPUTS_FILE)
    want = set(names) | {"%s.sha256" % n for n in names}
    if have != want:
        result["reasons"].append(
            "export inventory drift: %s" % sorted(have ^ want))
        return result
    for name in names:
        path = export / name
        sidecar = export / ("%s.sha256" % name)
        try:
            digest = sha_file(path)
            text = sidecar.read_text().strip()
        except OSError as exc:
            result["reasons"].append("%s unreadable: %s" % (name, exc))
            return result
        if text != "%s  %s" % (digest, name):
            result["reasons"].append("%s sidecar mismatch" % name)
            return result
        result["files"][name] = path
    result["ok"] = True
    return result


def build_vng_argv(case, flight, export, exec_str):
    """vng command for one case (host-tested wiring).

    Always verbose: that routes the guest console to the
    captured stderr instead of /dev/null, so a boot that
    never reaches the guest flow still leaves a console
    transcript in the case's host-guest.stderr.
    """
    cmd = flight["prefix"] + ["--run", core.VNG_TAG, "-m",
                              "6G", "--append",
                              "swiotlb=force", "--verbose"]
    if core.CASE_NETWORK[case]:
        cmd += ["--disable-microvm", "--network", "user",
                "--qemu-opts=-cpu host",
                "--qemu-opts=-device pcnet,netdev=pcnet0"
                " -netdev user,id=pcnet0,net=10.0.3.0/24"]
    cmd += ["--rwdir=/tmp/export=%s" % (export,),
            "--exec", exec_str]
    return cmd


def check_guest_inputs_binding(files, case, manifest, export):
    """Refuse unless the guest saw the exact staged bytes.

    Returns a reason list (empty ok): the guest-observed
    digest exported in input-verify.json must equal the
    manifest-bound digest for this case, and the staged
    copy still in the export dir must hash the same.
    """
    try:
        observed = json.loads(
            files["input-verify.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return ["%s: input-verify unreadable: %s"
                % (case, exc)]
    bad = []
    if observed.get("case") != case:
        bad.append("%s: input-verify names case %r"
                   % (case, observed.get("case")))
    entry = manifest.get("guest_inputs", {}).get(case, {})
    if observed.get("guest_inputs_file") != entry.get("file"):
        bad.append("%s: guest saw inputs file %r, bound %r"
                   % (case, observed.get("guest_inputs_file"),
                      entry.get("file")))
    if observed.get("guest_inputs_sha256") \
            != entry.get("sha256"):
        bad.append("%s: guest-observed inputs digest "
                   "differs from the manifest binding"
                   % case)
    try:
        staged = sha_file(str(Path(export)
                              / core.GUEST_INPUTS_FILE))
    except OSError as exc:
        return sorted(bad + ["%s: staged inputs "
                             "unreadable: %s" % (case, exc)])
    if staged != entry.get("sha256"):
        bad.append("%s: staged inputs bytes differ from "
                   "the manifest binding" % case)
    return sorted(bad)


def save_case_receipts(out, case, tmp, export, files, names,
                       manifest_path, manifest, bad, metrics):
    """Copy one case receipt set; raises OSError on failure.

    The boot console transcript lands in the receipt as
    host-guest.stderr (the verbose boot routes the guest
    console to the captured stderr);
    host-guest-inputs.json pins the staged inputs bytes
    the guest had to see.
    """
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(files[name], out / name)
        shutil.copy2(export / ("%s.sha256" % name),
                     out / ("%s.sha256" % name))
    shutil.copy2(manifest_path, out / "inputs.json")
    shutil.copy2(export / core.GUEST_INPUTS_FILE,
                 out / "host-guest-inputs.json")
    for name in ("boot.json", "guest.stdout",
                 "guest.stderr", "guest.exit"):
        shutil.copy2(tmp / name, out / ("host-%s" % name))
    (out / "host-verdict.json").write_text(json.dumps(
        {"verdict": "PASS" if not bad else "FAIL",
         "case": case, "reasons": bad, "metrics": metrics,
         "console_transcript": "host-guest.stderr",
         "runner_commit": manifest["runner_commit"],
         "consumer": manifest["consumer"],
         "candidate": manifest["candidate"],
         "oracle": manifest["oracle"],
         "guest": manifest["guest"],
         "profile": manifest["profile"]},
        indent=2, sort_keys=True) + "\n")


def armed_boot_case(case, args, manifest_path, manifest,
                    staged_inputs, flight):
    """Boot once, run one case in-guest, judge host-side."""
    from vm_process import run_owned_guest
    names = EXPORT_NAMES[case]
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-battery-boot-"))
    export = tmp / "export"
    export.mkdir()
    guest_argv = build_guest_argv(case)
    exec_str = shlex.join(guest_argv)
    projected = project_cmdline_total(len(exec_str))
    if cmdline_over_budget(len(exec_str)):
        (tmp / "boot.json").write_text(json.dumps(
            {"case": case, "refused": "cmdline budget",
             "exec_chars": len(exec_str),
             "projected_cmdline": projected,
             "cmdline_ceiling": COMMAND_LINE_SIZE,
             "exec_budget": GUEST_EXEC_BUDGET},
            indent=2, sort_keys=True) + "\n")
        print("FAIL vm-battery %s: guest argv projects to "
              "%d cmdline chars (exec %d chars, budget %d "
              "total / %d exec); refusing boot, artifacts "
              "kept at %s"
              % (case, projected, len(exec_str),
                 COMMAND_LINE_SIZE, GUEST_EXEC_BUDGET, tmp))
        return 2
    try:
        shutil.copyfile(staged_inputs,
                        export / core.GUEST_INPUTS_FILE)
        copied = sha_file(export / core.GUEST_INPUTS_FILE)
    except OSError as exc:
        print("FAIL vm-battery %s: staged inputs copy "
              "failed (%s); artifacts kept at %s"
              % (case, exc, tmp))
        return 1
    bound = manifest.get("guest_inputs", {}).get(case, {})
    if copied != bound.get("sha256"):
        print("FAIL vm-battery %s: staged inputs copy "
              "differs from the manifest binding; "
              "artifacts kept at %s" % (case, tmp))
        return 1
    cmd = build_vng_argv(case, flight, export, exec_str)
    (tmp / "boot.json").write_text(json.dumps(
        {"case": case, "cmd": cmd, "manifest": manifest,
         "harness": flight["harness"],
         "exec_chars": len(exec_str),
         "projected_cmdline": projected,
         "cmdline_ceiling": COMMAND_LINE_SIZE,
         "exec_budget": GUEST_EXEC_BUDGET,
         "guest_inputs_sha256": copied},
        indent=2, sort_keys=True) + "\n")
    timeout = core.CASE_TIMEOUTS[case]
    try:
        proc = run_owned_guest(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        (tmp / "guest.stdout").write_text(exc.stdout or "")
        (tmp / "guest.stderr").write_text(exc.stderr or "")
        (tmp / "guest.exit").write_text("timeout")
        print("FAIL vm-battery %s: guest timed out after %ds; "
              "artifacts kept at %s" % (case, timeout, tmp))
        # A hung boot aborts the remaining cases: judge
        # failures continue, but a hang is near-certainly
        # environmental and would burn every later timeout.
        return 2
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        print("FAIL vm-battery %s: guest exit %d; artifacts "
              "kept at %s" % (case, proc.returncode, tmp))
        return 1
    verified = verify_exports(export, case)
    if not verified["ok"]:
        print("FAIL vm-battery %s: %s; artifacts kept at %s"
              % (case, "; ".join(verified["reasons"]), tmp))
        return 1
    bad, metrics = judge_case(verified["files"], case, manifest)
    bad = sorted(bad + check_guest_inputs_binding(
        verified["files"], case, manifest, export))
    out = Path(args.out) / case
    try:
        save_case_receipts(out, case, tmp, export,
                           verified["files"], names,
                           manifest_path, manifest, bad,
                           metrics)
    except OSError as exc:
        print("FAIL vm-battery %s: receipt failed (%s); "
              "artifacts kept at %s" % (case, exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-battery %s: guest tmp kept at %s" % (case, tmp))
    if bad:
        print("FAIL vm-battery %s: %s"
              % (case, "; ".join(bad)))
        return 1
    print("ok vm-battery %s PASS (%s)" % (case, out))
    return 0


def armed_run(args):
    """Armed battery: one pinned boot per selected case."""
    if os.environ.get(ARM_ENV) != "1":
        print("FAIL vm-battery: armed run needs %s=1" % ARM_ENV)
        return 2
    if not args.out:
        print("FAIL vm-battery: armed needs --out")
        return 2
    if not getattr(args, "bundle", "") or not getattr(
            args, "candidate", ""):
        print("FAIL vm-battery: armed needs --bundle and "
              "--candidate")
        return 2
    if getattr(args, "expect_release", "") not in (
            "", core.EXPECT_RELEASE):
        print("FAIL vm-battery: conflicting --expect-release %r"
              % (args.expect_release,))
        return 2
    try:
        cases = parse_cases(args.case)
    except ValueError as exc:
        print("FAIL vm-battery: %s" % exc)
        return 2
    flight = armed_preflight()
    if flight is None:
        return 1
    cache_ok, cache_why, _ = verify_guest_cache()
    if not cache_ok:
        print("FAIL vm-battery: pinned guest cache refused: %s"
              % (cache_why,))
        return 1
    lock_dir = REPO / "build" / "vm"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("FAIL vm-battery: lock dir failed: %s" % (exc,))
        return 1
    # The run work dir lives under the repo build tree so
    # the guest resolves every input path identically; the
    # guest /tmp is a private overlay.
    work = Path(tempfile.mkdtemp(prefix="battery-",
                                 dir=str(lock_dir)))
    try:
        inputs = core.materialize(
            str(REPO), str(work / "inputs"), args.candidate,
            args.bundle)
        built = score.build_consumer()
        commit = core.git_head(str(REPO))
    except (ValueError, OSError) as exc:
        print("FAIL vm-battery: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    manifest_path = work / "inputs.json"
    # No test-object inputs exist yet, so saturation stays
    # unbound here; the writer already takes the bound pair
    # once the small-ring objects land.
    try:
        staged = write_guest_inputs_docs(
            str(work), cases, manifest_path, built, inputs,
            None, args.expect_release)
    except (ValueError, OSError) as exc:
        print("FAIL vm-battery: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    manifest = core.write_input_manifest(
        str(manifest_path), inputs,
        {"sha256": built["sha256"], "build": built["build"]},
        cases, sys.argv, commit,
        guest_inputs=staged)
    reasons = core.verify_input_manifest(manifest,
                                         built["path"])
    if reasons:
        print("FAIL vm-battery: %s" % "; ".join(reasons))
        shutil.rmtree(work, ignore_errors=True)
        return 1
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        print("FAIL vm-battery: VM suite lease already owned; "
              "one live executor at a time")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    rc = 0
    try:
        try:
            guest_oracle.verify_fixture()
        except (ValueError, OSError) as exc:
            print("FAIL vm-battery: oracle fixture refused: %s"
                  % (exc,))
            return 1
        for case in cases:
            step = armed_boot_case(case, args, manifest_path,
                                   manifest, staged[case],
                                   flight)
            if step == 2:
                rc = step
                break
            if step != 0:
                rc = step
    except Exception as exc:
        print("FAIL vm-battery: armed but %s" % (exc,))
        return 1
    finally:
        lease.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("vm-battery: work kept at %s" % (work,))
    return rc


# -- pytest entry points ------------------------------------------

def test_self_test_unarmed(tmp_path):
    assert run_self_test(work=str(tmp_path / "self"))


def test_armed_battery():
    import pytest
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip("battery armed run needs %s=1" % ARM_ENV)

    class Args:
        pass
    args = Args()
    raw = os.environ.get("MV_BATTERY_CASE", "")
    args.case = [item for item in raw.split(";") if item]
    args.out = os.environ.get(
        "MV_BATTERY_OUT",
        str(REPO / "build" / "vm" / "battery"))
    args.keep = os.environ.get("MV_BATTERY_KEEP", "") == "1"
    args.bundle = os.environ.get("MV_BATTERY_BUNDLE", "")
    args.candidate = os.environ.get("MV_BATTERY_CANDIDATE", "")
    args.expect_release = os.environ.get(
        "MV_BATTERY_EXPECT_RELEASE", "")
    assert armed_run(args) == 0


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--case", action="append", default=[])
    parser.add_argument("--out", default="")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--bundle", default="",
                        help="retained bundle.tar.gz path "
                             "(required when armed)")
    parser.add_argument("--candidate", default="",
                        help="retained candidate.json path "
                             "(required when armed)")
    parser.add_argument("--expect-release", default="",
                        help="refuse unless the guest release "
                             "matches (must equal the pin)")
    args = parser.parse_args(argv)
    if args.self_test or (not args.case and not args.out):
        return 0 if run_self_test() else 1
    return armed_run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
