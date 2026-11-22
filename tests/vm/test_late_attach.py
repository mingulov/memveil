#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Late-attach VM gate: a held mapping across attach, plus control.

SUPERSEDED by tests/vm/test_lateattach.py (ported late-attach
gate on the sealed consumer inputs). The judges below stay the
verdict source of record and are imported verbatim by the port;
only the retired armed path (token-less boot, --bridge guest
contract) is superseded.

Standalone runner (no lane wiring). Unarmed, it self-tests the
harness logic against mock fixtures: a good late-attach pair
must pass and five targeted mutations (missed held release,
dangling generation, control with dropped traffic, control
with a miss, violated attach ordering) must each fail. Armed
with MEMVEIL_VM_LATE_ATTACH=1 and qualified probes, it boots
one guest, runs the two-phase late-attach flow, and judges the
exports with the same functions the self-test exercises.

Phase A (late attach): scripted traffic runs BEFORE the
consumers attach, so every map, sync, and unmap completes
pre-attach except the script's final held-open mapping. The
consumers then attach and the module unloads, so the held
mapping's release is the only phase-A traffic the probes can
observe: one unmap with generation 0 (an explicit miss: the
map never reached the ring, so the probe honestly reports the
release as untracked) plus its release bounce. The pre-attach
oracle snapshot proves the maps completed before attachment;
the post snapshot proves the release landed after it.

Phase B (positive control): fresh consumers attach first,
then a full scripted run executes entirely post-attach and
must be observed exactly, with no misses. The control proves
attached observation works, so phase A's absent pre-attach
traffic is a genuine miss pattern and a missed held release
would fail the gate.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from consume import (check_conservation, check_identity_closure,
                     check_oracle_script, check_record_flags,
                     compare_multisets, compare_scripted,
                     parse_consume_file, parse_oracle_log)

SUB = "lateattach"
OPS = 4
HELD_OP = OPS - 1
HELD_SIZE = 4096
HELD_DIR = 2
EXPORT_NAMES = ["identity.json", "a-pre-oracle.log",
                "a-lc.txt", "a-cp.txt", "a-oracle.log",
                "b-lc.txt", "b-cp.txt", "b-oracle.log",
                "attach.json"]

# The only phase-A traffic the probes can observe: the held
# mapping's exit release (unmap triple) and its release bounce
# (FROM direction copies back at release). Every map, sync,
# and other unmap completed pre-attach.
HELD_WANT = {
    "maps": [],
    "unmaps": [(HELD_SIZE, HELD_DIR, 1)],
    "syncs_dev": [],
    "syncs_cpu": [],
    "bounces": [(0, HELD_SIZE, HELD_DIR)],
}


def judge_attach_doc(doc, tag="attach"):
    """Strict attach-ordering evidence: shape plus inequalities."""
    bad = []
    if type(doc) is not dict:
        return [tag + ": attach doc is not an object"]
    if doc.get("ops") != OPS or doc.get("held_op") != HELD_OP:
        bad.append("%s: ops/held_op %r want %d/%d"
                   % (tag, (doc.get("ops"), doc.get("held_op")),
                      OPS, HELD_OP))
    for phase in ("phase_a", "phase_b"):
        row = doc.get(phase)
        if type(row) is not dict:
            bad.append("%s: %s missing" % (tag, phase))
            continue
        for key in ("attach_ns", "mapped_ns", "released_ns",
                    "lc_exit", "cp_exit"):
            if type(row.get(key)) is not int:
                bad.append("%s: %s.%s not an integer"
                           % (tag, phase, key))
        if row.get("lc_exit") != 0 or row.get("cp_exit") != 0:
            bad.append("%s: %s consumer exit %r"
                       % (tag, phase,
                          (row.get("lc_exit"), row.get("cp_exit"))))
    a = doc.get("phase_a")
    if type(a) is dict and all(
            type(a.get(k)) is int for k in
            ("mapped_ns", "attach_ns", "released_ns")):
        if not (a["mapped_ns"] < a["attach_ns"]
                < a["released_ns"]):
            bad.append("%s: phase_a order is not "
                       "mapped < attach < released" % tag)
    b = doc.get("phase_b")
    if type(b) is dict and all(
            type(b.get(k)) is int for k in
            ("attach_ns", "mapped_ns", "released_ns")):
        if not (b["attach_ns"] < b["mapped_ns"]
                < b["released_ns"]):
            bad.append("%s: phase_b order is not "
                       "attach < mapped < released" % tag)
    return sorted(bad)


def judge_pre_attach(pre_text, ops_log, releases, complete_ops,
                     tag):
    """Pre-attach snapshot: script done, held mapping still open."""
    bad = []
    if complete_ops != OPS:
        bad.append("%s: pre-attach complete ops=%r want %d"
                   % (tag, complete_ops, OPS))
    if sorted(releases) != [0, 1, 2]:
        bad.append("%s: pre-attach released %r want [0, 1, 2]"
                   % (tag, sorted(releases)))
    if "held-open" not in pre_text:
        bad.append("%s: pre-attach held-open missing" % tag)
    if "exit-release" in pre_text:
        bad.append("%s: pre-attach already released" % tag)
    if "mapping=%d release" % HELD_OP in pre_text:
        bad.append("%s: held mapping released pre-attach" % tag)
    if sorted(ops_log) != list(range(OPS)):
        bad.append("%s: pre-attach op coverage %r"
                   % (tag, sorted(ops_log)))
    return sorted(bad)


def judge_phase_a(got, tag="lateattach-a"):
    """Late attach: only the held release observed, as a miss."""
    bad = []
    lc, lc_sum = parse_consume_file(str(got["a-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(got["a-cp.txt"]))
    bad += check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    if lc_sum["cnt_fail"] != 0 or cp_sum["cnt_fail"] != 0:
        bad.append("%s: loss in a two-event window is "
                   "unexpected" % tag)
    ops_log, releases, complete = parse_oracle_log(
        str(got["a-oracle.log"]))
    bad += check_oracle_script(ops_log, releases, complete,
                               OPS, -1, tag)
    post_text = got["a-oracle.log"].read_text()
    if "exit-release" not in post_text:
        bad.append("%s: post-attach exit-release missing" % tag)
    pre_text = got["a-pre-oracle.log"].read_text()
    pre_ops, pre_rel, pre_complete = parse_oracle_log(
        str(got["a-pre-oracle.log"]))
    bad += judge_pre_attach(pre_text, pre_ops, pre_rel,
                            pre_complete, tag)
    bad += compare_multisets(lc, cp, HELD_WANT, tag)
    bad += check_record_flags(lc, cp, tag)
    bad += check_identity_closure(lc, tag + "-lc")
    if len(lc) != 1 or lc[0]["kind"] != 2:
        bad.append("%s: want exactly the held unmap, got %d "
                   "lc events" % (tag, len(lc)))
    elif lc[0]["gen"] != 0:
        bad.append("%s: held unmap claims gen %d with no "
                   "persisted map; want an explicit miss "
                   "(gen 0)" % (tag, lc[0]["gen"]))
    return sorted(bad)


def judge_phase_b(got, tag="lateattach-b"):
    """Positive control: full post-attach traffic, exact, no miss."""
    bad = []
    lc, lc_sum = parse_consume_file(str(got["b-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(got["b-cp.txt"]))
    bad += check_conservation(lc, lc_sum, tag + "-lc")
    bad += check_conservation(cp, cp_sum, tag + "-cp")
    if lc_sum["cnt_fail"] != 0 or cp_sum["cnt_fail"] != 0:
        bad.append("%s: loss in the control window is "
                   "unexpected" % tag)
    ops_log, releases, complete = parse_oracle_log(
        str(got["b-oracle.log"]))
    bad += check_oracle_script(ops_log, releases, complete,
                               OPS, -1, tag)
    bad += compare_scripted(lc, cp, OPS, -1, tag)
    bad += check_identity_closure(lc, tag + "-lc")
    missed = [e["seq"] for e in lc if e["gen"] == 0]
    if missed:
        bad.append("%s: control has %d miss(es); attached "
                   "observation must be exact" % (tag,
                                                 len(missed)))
    return sorted(bad)


# --- Unarmed self-test: mock fixtures through the same judges ---

MOCK_SIZES = (512, 1024, 2048, 4096)
MOCK_DIRS = (1, 2, 1, 2)


def mock_oracle_bodies(lifetime_base=1000):
    """Scripted oracle bodies: (pre_lines, post_lines).

    Replicates the module script order for four ops: attempt,
    outcome, syncs, then release, except the last op, which
    stays held-open until the exit release.
    """
    pre = []
    for i in range(OPS):
        size = MOCK_SIZES[i]
        direction = MOCK_DIRS[i]
        pre.append("op=%d attempt requested=%d forced=0"
                   % (i, size))
        pre.append("op=%d outcome=success mapping=%d mapped=%d"
                   % (i, i, size))
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            pre.append("op=%d mapping=%d sync dir=%d len=%d "
                       "for=device" % (i, i, direction, size))
        if i == HELD_OP:
            pre.append("op=%d mapping=%d held-open" % (i, i))
        else:
            pre.append("mapping=%d release lifetime_ns=%d"
                       % (i, lifetime_base + i))
    pre.append("script complete ops=%d" % OPS)
    post = list(pre) + [
        "op=%d mapping=%d exit-release" % (HELD_OP, HELD_OP),
        "mapping=%d release lifetime_ns=%d"
        % (HELD_OP, lifetime_base + 99),
        "unloaded",
    ]
    return pre, post


def mock_oracle_text(bodies):
    lines = ["[%10.6f] mv-oracle: %s" % (1.0 + n * 0.001, body)
             for n, body in enumerate(bodies)]
    return "\n".join(lines) + "\n"


def mock_summary(count, byte_sum):
    return ("summary observed=%d badframe=0 badrec=0 "
            "cnt_obs=%d cnt_obsb=%d cnt_emit=%d cnt_emitb=%d "
            "cnt_fail=0 cnt_flags=0 rx=%d dlv=%d mal=0 drop=0"
            % (count, count, byte_sum, count, byte_sum,
               count, count))


def mock_lc_line(kind, direction, seq, ktime, size, gen):
    if kind == 1:
        return ("lc kind=1 ok=1 skip=0 dir=%d seq=%d "
                "ktime=%d size=%d gen=%d"
                % (direction, seq, ktime, size, gen))
    return ("lc kind=2 ok=1 skip=1 dir=%d seq=%d ktime=%d "
            "size=%d gen=%d" % (direction, seq, ktime, size,
                                gen))


def mock_cp_sync(todev, direction, seq, ktime, req):
    return ("cp kind=1 todev=%d known=0 clamp=0 ezero=0 "
            "dir=%d reason=4 seq=%d ktime=%d req=%d eff=0"
            % (todev, direction, seq, ktime, req))


def mock_cp_bounce(todev, direction, seq, ktime, req):
    return ("cp kind=2 todev=%d known=1 clamp=0 ezero=0 "
            "dir=%d reason=0 seq=%d ktime=%d req=%d eff=%d"
            % (todev, direction, seq, ktime, req, req))


def mock_phase_a_files(tmp):
    """Held release only: one gen-0 unmap plus its bounce."""
    pre, post = mock_oracle_bodies()
    (tmp / "a-pre-oracle.log").write_text(
        mock_oracle_text(pre))
    (tmp / "a-oracle.log").write_text(mock_oracle_text(post))
    lc = [mock_lc_line(2, HELD_DIR, 0, 2000000000,
                       HELD_SIZE, 0)]
    (tmp / "a-lc.txt").write_text(
        "\n".join(lc + [mock_summary(1, HELD_SIZE)]) + "\n")
    cp = [mock_cp_bounce(0, HELD_DIR, 0, 2000000001,
                         HELD_SIZE)]
    (tmp / "a-cp.txt").write_text(
        "\n".join(cp + [mock_summary(1, HELD_SIZE)]) + "\n")


def mock_phase_b_files(tmp):
    """Full post-attach scripted traffic, exact, no misses."""
    _, post = mock_oracle_bodies(lifetime_base=5000)
    (tmp / "b-oracle.log").write_text(mock_oracle_text(post))
    lc, ktime = [], 3000000000
    for i in range(OPS):
        size = MOCK_SIZES[i]
        direction = MOCK_DIRS[i]
        gen = 101 + i
        lc.append(mock_lc_line(1, direction, len(lc), ktime,
                               size, gen))
        ktime += 1
        lc.append(mock_lc_line(2, direction, len(lc), ktime,
                               size, gen))
        ktime += 1
    (tmp / "b-lc.txt").write_text(
        "\n".join(lc + [mock_summary(len(lc), 15360)]) + "\n")
    cp = []
    for i in range(OPS):
        size = MOCK_SIZES[i]
        direction = MOCK_DIRS[i]
        cp.append(mock_cp_bounce(1, 1, len(cp), ktime, size))
        ktime += 1
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            cp.append(mock_cp_sync(1, direction, len(cp),
                                   ktime, size))
            ktime += 1
            if direction == 1:
                cp.append(mock_cp_bounce(1, direction,
                                         len(cp), ktime,
                                         size))
                ktime += 1
        cp.append(mock_cp_sync(0, direction, len(cp), ktime,
                               size))
        ktime += 1
    for i in range(OPS):
        if MOCK_DIRS[i] == 2:
            cp.append(mock_cp_bounce(0, 2, len(cp), ktime,
                                     MOCK_SIZES[i]))
            ktime += 1
    (tmp / "b-cp.txt").write_text(
        "\n".join(cp + [mock_summary(len(cp), 31744)]) + "\n")


def mock_attach_doc():
    return {
        "ops": OPS,
        "held_op": HELD_OP,
        "phase_a": {"mapped_ns": 100, "attach_ns": 200,
                    "released_ns": 300, "lc_exit": 0,
                    "cp_exit": 0},
        "phase_b": {"attach_ns": 400, "mapped_ns": 500,
                    "released_ns": 600, "lc_exit": 0,
                    "cp_exit": 0},
    }


def check_mock_pins(tmp):
    """Pin the mock generator to independently counted numbers."""
    bad = []
    lc, lc_sum = parse_consume_file(str(tmp / "b-lc.txt"))
    cp, cp_sum = parse_consume_file(str(tmp / "b-cp.txt"))
    if len(lc) != 8:
        bad.append("mock: b-lc has %d lines, want 8" % len(lc))
    if len(cp) != 17:
        bad.append("mock: b-cp has %d lines, want 17" % len(cp))
    if lc_sum["cnt_obsb"] != 15360:
        bad.append("mock: b-lc bytes %d, want 15360"
                   % lc_sum["cnt_obsb"])
    if cp_sum["cnt_obsb"] != 31744:
        bad.append("mock: b-cp bytes %d, want 31744"
                   % cp_sum["cnt_obsb"])
    return bad


def selftest_case(tmp, name, mutate, judge, want_fail):
    """One mock case: mutate a good copy, judge, check the verdict."""
    import copy
    case = tmp / name
    case.mkdir()
    for src in tmp.glob("*.txt"):
        shutil.copyfile(src, case / src.name)
    for src in tmp.glob("*.log"):
        shutil.copyfile(src, case / src.name)
    doc = copy.deepcopy(mock_attach_doc())
    mutate(case, doc)
    (case / "attach.json").write_text(json.dumps(doc) + "\n")
    got = {path.name: path for path in case.iterdir()
           if path.suffix in (".txt", ".log")}
    found = judge(got) if judge is not None else []
    found += judge_attach_doc(doc, tag=name)
    failed = bool(found)
    if failed != want_fail:
        return ["selftest %s: judged %s, want %s (%s)"
                % (name, "FAIL" if failed else "PASS",
                   "FAIL" if want_fail else "PASS",
                   "; ".join(found[:3]))]
    print("lateattach selftest %s: judged %s as expected"
          % (name, "FAIL" if failed else "PASS"))
    return []


def drop_lc_seq(path, victim):
    """Remove one lc line and renumber seqs with a fixed summary."""
    kept = []
    for line in path.read_text().splitlines():
        if line.startswith("summary "):
            continue
        fields = dict(part.split("=", 1) for part in
                      line.split()[1:])
        if int(fields["seq"]) != victim:
            kept.append((line, fields))
    out = []
    for seq, (line, fields) in enumerate(kept):
        out.append(re.sub(r" seq=\d+", " seq=%d" % seq, line,
                          count=1))
    byte_sum = sum(int(dict(part.split("=", 1) for part in
                             line.split()[1:])["size"])
                   for line in out)
    out.append(mock_summary(len(out), byte_sum))
    path.write_text("\n".join(out) + "\n")


def selftest_boot_tmpdir_guard(tmp):
    """Boot assembly refuses rewritten TMPDIR before spawning."""
    from unittest import mock
    bad = []
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    hostile = tmp / 't"mp'
    hostile.mkdir()
    with mock.patch.object(sys.modules[__name__], 'REPO',
                           str(tmp)), \
         mock.patch('test_attempt_capture.gate_prefix',
                    return_value=(['vng'], {})), \
         mock.patch('harness_env.check_harness_versions',
                    return_value={}), \
         mock.patch('lifecycle_env.ensure_oracle_module',
                    return_value=None), \
         mock.patch('support.candidate_input.load',
                    return_value=None):
        with mock.patch('vm_process.run_owned_guest') as spawned, \
             mock.patch.dict(os.environ,
                             {'TMPDIR': str(hostile)}), \
             mock.patch.object(tempfile, 'tempdir', None):
            try:
                boot_lateattach()
                bad.append('tmpdir guard accepted rewritten TMPDIR')
            except ValueError as exc:
                if 'launcher shell' not in str(exc):
                    bad.append('tmpdir guard wrong refusal: %s'
                               % exc)
                elif spawned.call_count != 0:
                    bad.append('tmpdir guard spawned before refusing')
        with mock.patch('vm_process.run_owned_guest') as spawned:
            spawned.side_effect = ValueError('sentinel-reached-boot')
            try:
                boot_lateattach()
                bad.append('tmpdir guard blocked honest TMPDIR')
            except ValueError as exc:
                if str(exc) != 'sentinel-reached-boot':
                    bad.append('tmpdir guard wrong honest error: %s'
                               % exc)
                elif spawned.call_count != 1:
                    bad.append('tmpdir guard honest spawned %d'
                               % spawned.call_count)
    return bad


def run_selftest():
    """Unarmed proof: good mocks pass, five mutations fail."""
    bad = []
    with tempfile.TemporaryDirectory(
            prefix="lateattach-selftest-") as raw:
        tmp = Path(raw)
        mock_phase_a_files(tmp)
        mock_phase_b_files(tmp)
        bad += check_mock_pins(tmp)

        def nomatch(case, doc):
            return None

        bad += selftest_case(tmp, "good", nomatch,
                             lambda got: judge_phase_a(got)
                             + judge_phase_b(got), False)

        def miss_held(case, doc):
            (case / "a-lc.txt").write_text(
                mock_summary(0, 0) + "\n")
            (case / "a-cp.txt").write_text(
                mock_summary(0, 0) + "\n")

        bad += selftest_case(tmp, "neg-missed-release",
                             miss_held, judge_phase_a, True)

        def dangling(case, doc):
            body = (case / "a-lc.txt").read_text()
            (case / "a-lc.txt").write_text(
                body.replace("gen=0", "gen=7"))

        bad += selftest_case(tmp, "neg-dangling-gen",
                             dangling, judge_phase_a, True)

        def drop_control(case, doc):
            drop_lc_seq(case / "b-lc.txt", 4)

        bad += selftest_case(tmp, "neg-control-drop",
                             drop_control, judge_phase_b, True)

        def miss_control(case, doc):
            body = (case / "b-lc.txt").read_text()
            (case / "b-lc.txt").write_text(
                body.replace("gen=101", "gen=0", 1))

        bad += selftest_case(tmp, "neg-control-miss",
                             miss_control, judge_phase_b, True)

        def swap_order(case, doc):
            row = doc["phase_a"]
            row["attach_ns"], row["released_ns"] = (
                row["released_ns"], row["attach_ns"])

        bad += selftest_case(tmp, "neg-order-swap",
                             swap_order, None, True)
        bad += selftest_boot_tmpdir_guard(tmp)
    if bad:
        print("FAIL lateattach selftest:")
        for line in bad:
            print("  " + line)
        return 1
    print("lateattach selftest: PASS: good pair accepted, "
          "5 mutations rejected")
    return 0


# --- Armed run: one guest boot, same judges ---

GUEST_FLOW = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "late_attach_guest.py")


def need(path, what):
    if not os.path.isfile(path):
        print(f"FAIL vm-lateattach: armed but {what} missing: "
              f"{path}")
        return False
    return True


def armed_preflight():
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_lifecycle.bpf.o"),
              "lifecycle probes")
    ok = need(os.path.join(REPO, "build", "bpf",
                           "swiotlb_copy.bpf.o"),
              "copy probes") and ok
    ok = need(os.path.join(REPO, "build", "vm", "mv_consume"),
              "consumer") and ok
    if not shutil.which("vng"):
        print("FAIL vm-lateattach: armed but vng not available")
        return False
    if not shutil.which("qemu-system-x86_64"):
        print("FAIL vm-lateattach: armed but qemu not available")
        return False
    if not os.path.exists("/dev/kvm"):
        print("FAIL vm-lateattach: armed but /dev/kvm missing")
        return False
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    if probe.returncode != 0:
        print("FAIL vm-lateattach: armed but no passwordless "
              "sudo")
        return False
    return ok


def guest_exec_command(work, repo, selected=None):
    guest = ["python3", GUEST_FLOW, SUB, work, "/tmp/export",
             str(repo)]
    if selected is None:
        return " ".join(guest)
    import shlex
    return shlex.join(
        ["env",
         "MV_CANDIDATE_MANIFEST=" + str(selected.manifest_path),
         "MV_BUNDLE_TARBALL=" + str(selected.bundle),
         "MV_CANDIDATE_DIGEST=" + selected.digest,
         *guest])


def boot_lateattach(timeout=900):
    """Boot one guest and run the late-attach flow."""
    import fcntl
    sys.path.insert(0, ROOT)
    from support.candidate_input import load
    from test_attempt_capture import gate_prefix
    from lifecycle_env import (ensure_oracle_module,
                               sealed_profiles_dir)
    from harness_env import check_harness_versions
    from vm_process import run_owned_guest
    selected = load()
    prefix, _env = gate_prefix()
    harness = check_harness_versions(prefix[-1])
    repo = Path(REPO)
    lock_dir = repo / "build" / "vm"
    lock_dir.mkdir(parents=True, exist_ok=True)
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        raise ValueError("VM suite lease already owned")
    try:
        if selected is None:
            ensure_oracle_module()
        else:
            ensure_oracle_module(
                profiles=sealed_profiles_dir(selected))
    except BaseException:
        lease.close()
        raise
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-lateattach-"))
    export = tmp / "export"
    export.mkdir()
    from capture_durability import check_shell_inert_path
    # The export reaches the launcher command raw, so its
    # spelling is gated before the boot is assembled.
    check_shell_inert_path(export, "export path")
    cmd = prefix + [
        "--run", "-m", "6G",
        "--append", "swiotlb=force",
        "--rwdir=/tmp/export=%s" % export,
        "--exec",
        guest_exec_command("/tmp/vmgate-work", repo,
                           selected),
    ]
    try:
        proc = run_owned_guest(cmd, timeout=timeout)
        (tmp / "harness.json").write_text(
            json.dumps(harness, sort_keys=True) + "\n")
    except subprocess.TimeoutExpired:
        (tmp / "timeout.json").write_text(json.dumps(
            dict(timeout=timeout, status="FAIL")) + "\n")
        print(f"timed-out gate artifacts kept at {tmp}")
        raise
    finally:
        lease.close()
    return tmp, proc


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1048576), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_lateattach_exports(tmp):
    """Exact inventory, sidecar hashes, and leaf validation."""
    from export_validation import identity as check_identity
    from evidence_retention import (VerifiedExports,
                                    snapshot_exports)
    export = tmp / "export"
    got, verified = snapshot_exports(tmp, SUB, EXPORT_NAMES)
    want_files = {"%s-%s" % (SUB, n) for n in EXPORT_NAMES}
    want_files |= {"%s-%s.sha256" % (SUB, n)
                   for n in EXPORT_NAMES}
    have = {p.name for p in export.iterdir()}
    assert have == want_files, \
        f"export inventory drift: {have ^ want_files}"
    check_identity(json.loads(
        got["identity.json"].read_text()))
    for name in ("a-lc.txt", "a-cp.txt", "b-lc.txt",
                 "b-cp.txt"):
        parse_consume_file(str(got[name]))
    for name in ("a-pre-oracle.log", "a-oracle.log",
                 "b-oracle.log"):
        # Same line grammar the lifecycle export validator
        # enforces: oracle bodies plus a dmesg prefix only.
        for line in got[name].read_text().splitlines():
            if not re.fullmatch(
                    r"(?:\[\s*\d+\.\d+\]\s*)?mv-oracle: "
                    r"[A-Za-z0-9_ =-]+", line):
                raise ValueError(
                    "unexpected oracle export line")
        parse_oracle_log(str(got[name]))
    attach = json.loads(got["attach.json"].read_text())
    found = judge_attach_doc(attach)
    assert not found, "; ".join(found)
    sys.path.insert(0, ROOT)
    from support.candidate_input import load
    from lifecycle_env import (ORACLE_KO, module_build_identity,
                               sealed_profiles_dir)
    from vm_boot import guest_artifact_paths
    selected = load()
    if selected is None:
        expected = module_build_identity()
    else:
        expected = module_build_identity(
            profiles_dir=sealed_profiles_dir(selected))
    identity = json.loads(got["identity.json"].read_text())
    for key in ("release", "config_sha", "btf_sha"):
        assert identity[key] == expected[key], \
            "guest kernel identity drift: " + key
    paths = guest_artifact_paths(SUB, REPO, selected)
    checks = dict(paths)
    checks["ko_sha"] = Path(ORACLE_KO)
    for key, path in checks.items():
        assert identity[key] == sha_file(path), \
            "guest artifact mismatch: " + key
    return VerifiedExports(got, verified)


def run_flow():
    from evidence_retention import (expected_from_verified,
                                    retain_failure)
    from test_attempt_capture import cleanup
    tmp = None
    try:
        tmp, proc = boot_lateattach()
        if proc.returncode != 0:
            print("FAIL vm-lateattach: guest failed: %s"
                  % proc.stderr[-2000:])
            retain_failure(tmp, "lateattach")
            print(f"gate artifacts kept at {tmp}")
            return 1
        got = verify_lateattach_exports(tmp)
        expected = expected_from_verified(got, SUB)
        bad = judge_phase_a(got)
        bad += judge_phase_b(got)
        if bad:
            print("FAIL vm-lateattach:")
            for line in bad:
                print("  " + line)
            retain_failure(tmp, "lateattach")
            print(f"gate artifacts kept at {tmp}")
            return 1
        print("vm-lateattach: PASS: held release observed "
              "post-attach as a miss; control exact")
    except Exception as exc:
        print(f"FAIL vm-lateattach: {exc}")
        if tmp is not None:
            retain_failure(tmp, "lateattach")
            print(f"gate artifacts kept at {tmp}")
        return 1
    else:
        cleanup(tmp, "lateattach", expected=expected)
        return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if "--self-test" in argv:
        return run_selftest()
    if os.environ.get("MEMVEIL_VM_LATE_ATTACH", "0") != "1":
        return run_selftest()
    if not armed_preflight():
        return 1
    return run_flow()


if __name__ == "__main__":
    sys.exit(main())

