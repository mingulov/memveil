#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Stress-pair runner: baseline vs candidate identity comparison.

Unarmed (default) the runner self-tests offline: pinned-byte
verification of both object pairs, consumer build plus decoder
vectors, both layouts against their exact map allowlists,
wrong-pair and malformed-wire refusals, replay determinism,
judge and comparison unit cases on synthetic logs, and input
manifest checks. No boot, no privileges. Standalone:
`python3 tests/vm/test_stress_consumer.py [--self-test]`.

Armed (MEMVEIL_VM_STRESS=1 with --inputs/--out, prepared but
requiring a live-VM lease) the runner boots one pinned guest,
runs the baseline pair then the candidate pair through
identity controls, a quiet phase, and a paced overlap phase,
re-derives every verdict host-side from the exported
observations, and writes stamped receipts. The --inputs
surface is stress-only: it resolves the two named
lifecycle/copy pairs and passes those paths to the same
consumer; bytes must equal the pinned pairs either way.
--bundle/--candidate name the retained seal explicitly and
are required for every armed run; --expect-release refuses
when it conflicts with the pinned guest release; --mode q3
runs the adapter gate only (candidate then baseline,
controls plus the quiet phase, no comparison).
"""

import ast
import fcntl
import hashlib
import io
import json
import os
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))
import stress_core as core
import stress_guest
import guest_oracle
from consume import (check_conservation, check_identity_closure,
                     check_oracle_script, compare_scripted,
                     parse_consume_file, parse_oracle_log)

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "stress-consumer" / "stress_guest.py"
ARM_ENV = "MEMVEIL_VM_STRESS"

# The guest owns the canonical per-mode inventory; the host
# judges exactly that list, never a private copy.
EXPORT_NAMES = stress_guest.export_names_for_mode("full")
EXPORT_NAMES_Q3 = stress_guest.export_names_for_mode("q3")


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
    return core.run([core.CONSUMER_RELEASE] + args,
                    timeout=timeout)


# -- Unarmed self-test: pins ------------------------------------

def self_test_pins():
    """Every pinned byte still matches its source."""
    ok = True
    parent = core.run(
        ["git", "-C", str(REPO), "rev-parse",
         "%s^" % core.BASELINE_CUTOVER],
        timeout=30)
    ok = check("pins-cutover-parent",
               parent.returncode == 0
               and parent.stdout.strip() == core.BASELINE_COMMIT,
               parent.stdout.strip()) and ok
    for rel, blob_id, want in [
            (core.BASELINE_LC_BLOB, core.BASELINE_LC_BLOB_ID,
             core.BASELINE_LC_SHA),
            (core.BASELINE_CP_BLOB, core.BASELINE_CP_BLOB_ID,
             core.BASELINE_CP_SHA)]:
        ident = core.run(
            ["git", "-C", str(REPO), "rev-parse",
             "%s:%s" % (core.BASELINE_COMMIT, rel)],
            timeout=30)
        raw = core.run(
            ["git", "-C", str(REPO), "cat-file", "-p",
             "%s:%s" % (core.BASELINE_COMMIT, rel)],
            timeout=30, text=False)
        got = hashlib.sha256(raw.stdout).hexdigest()
        ok = check("pins-%s" % rel.rsplit("/", 1)[1],
                   ident.returncode == 0
                   and ident.stdout.strip() == blob_id
                   and got == want, got[:16]) and ok
    for rel, want in [
            ("tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o",
             core.C9_LC_SHA),
            ("tests/vm/fixtures/aya/swiotlb_copy.bpf.o", core.C9_CP_SHA),
            ("tests/vm/fixtures/aya/swiotlb_attempt.bpf.o",
             core.C9_ATTEMPT_SHA)]:
        got = sha_file(str(REPO / rel))
        ok = check("pins-%s" % rel.rsplit("/", 1)[1].split(".")[0],
                   got == want, got[:16]) and ok
    seal = [REPO / "dist" / "candidate.json",
            REPO / "dist" / "bundle.tar.gz"]
    if not all(p.is_file() for p in seal):
        print("ok pins-candidate SKIP (no dist/ seal in tree; "
              "explicit-path seals covered by candidate-flags-*)")
    else:
        try:
            binding = core.load_candidate_binding(str(REPO))
            ok = check("pins-candidate",
                       binding["bundle"]["sha256"] == core.C9_BUNDLE_SHA
                       and binding["source"]["commit"]
                       == core.C9_SOURCE_COMMIT
                       and binding["source"]["tree"]
                       == core.C9_SOURCE_TREE) and ok
        except (ValueError, OSError, KeyError) as exc:
            ok = check("pins-candidate", False, str(exc)) and ok
    try:
        oracle = core.oracle_digest(str(REPO))
        ok = check("pins-oracle",
                   len(oracle["memveil_dma_oracle.c"]) == 64
                   and len(oracle["Makefile"]) == 64) and ok
    except (ValueError, OSError, KeyError) as exc:
        ok = check("pins-oracle", False, str(exc)) and ok
    return ok


def self_test_gate_constants():
    """Mirrored gate constants still equal their sources."""
    files = {
        "test_identity_races.py": {
            "P1_OPS": core.P1_OPS, "P2_OPS": core.P2_OPS,
            "COUNT_SLACK": core.COUNT_SLACK,
            "MISS_CEILING": core.MISS_CEILING,
        },
        "guest_lifecycle.py": {
            "LC_SITES": core.LC_SITES, "CP_SITES": core.CP_SITES,
        },
    }
    ok = True
    for name, want in files.items():
        try:
            tree = ast.parse((REPO / "tests" / "vm" / name).read_text())
        except OSError as exc:
            ok = check("const-%s" % name, False, str(exc)) and ok
            continue
        found = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and len(node.targets) == 1 \
                    and isinstance(node.targets[0], ast.Name):
                key = node.targets[0].id
                if key in want:
                    try:
                        found[key] = ast.literal_eval(node.value)
                    except ValueError:
                        pass
        for key, value in want.items():
            ok = check("const-%s" % key, found.get(key) == value,
                       "%r" % (found.get(key),)) and ok
    return ok


# -- Unarmed self-test: consumer build + layouts ----------------

def self_test_consumer_build():
    """Release consumer builds pinned; its self-check is green."""
    try:
        built = core.build_consumer()
    except ValueError as exc:
        return check("build-consumer", False, str(exc)[:300])
    ok = True
    ok = check("build-consumer", os.path.isfile(built["path"])) and ok
    ok = check("build-aya-pin",
               built["build"]["locked"].get("aya") == "0.14.0"
               and built["build"]["locked"].get("aya-obj") == "0.3.0",
               "%r" % (built["build"]["locked"],)) and ok
    proc = consumer_run(["--self-check"])
    ok = check("build-self-check",
               proc.returncode == 0 and "ok" in proc.stdout,
               (proc.stdout + proc.stderr).strip()[-200:]) and ok
    # The consumer's digest must agree with hashlib exactly.
    digest_proc = consumer_run(
        ["--verify-layout",
         str(REPO / "tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o"),
         "mv_lifecycle"])
    parsed = core.parse_verify_layout(digest_proc.stdout)
    ok = check("build-sha-agrees",
               parsed["sha256"] == sha_file(
                   str(REPO / "tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o"))
               == core.C9_LC_SHA) and ok
    return ok


LAYOUT_WANT = {
    ("c9", "lc"): {
        "family": "aya", "core": "no",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8, "entries": 6},
            "mv_lifecycle": {"type": 27, "key": 0, "value": 0,
                             "entries": 33554432},
            "mv_gen_table": {"type": 1, "key": 16, "value": 8,
                             "entries": 32768},
            "mv_gen_next": {"type": 2, "key": 4, "value": 8, "entries": 1},
        },
        "programs": {"mv_map_result": "fexit", "mv_unmap": "fentry"},
    },
    ("c9", "cp"): {
        "family": "aya", "core": "no",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8, "entries": 6},
            "mv_claims": {"type": 2, "key": 4, "value": 16,
                          "entries": 4096},
            "mv_copy_fb": {"type": 2, "key": 4, "value": 8, "entries": 4},
            "mv_copies": {"type": 27, "key": 0, "value": 0,
                          "entries": 33554432},
            "mv_copy_offs": {"type": 2, "key": 4, "value": 112,
                             "entries": 1},
        },
        "programs": {"mv_bounce": "fentry", "mv_bounce_exit": "fexit",
                     "mv_sync_device": "fentry", "mv_sync_cpu": "fentry"},
    },
    ("baseline", "lc"): {
        "family": "c", "core": "yes",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8, "entries": 6},
            "mv_lifecycle": {"type": 27, "key": 0, "value": 0,
                             "entries": 33554432},
            "mv_gen_table": {"type": 1, "key": 16, "value": 8,
                             "entries": 32768},
            "mv_gen_next": {"type": 2, "key": 4, "value": 8, "entries": 1},
            "mv_gen_quarantine": {"type": 1, "key": 16, "value": 1,
                                  "entries": 1024},
            "mv_gen_dark": {"type": 2, "key": 4, "value": 1, "entries": 1},
        },
        "programs": {"mv_map_result": "fexit", "mv_unmap": "fentry"},
    },
    ("baseline", "cp"): {
        "family": "c", "core": "yes",
        "maps": {
            "mv_counts": {"type": 2, "key": 4, "value": 8, "entries": 6},
            "mv_claims": {"type": 2, "key": 4, "value": 16,
                          "entries": 4096},
            "mv_copy_fb": {"type": 2, "key": 4, "value": 8, "entries": 4},
            "mv_copies": {"type": 27, "key": 0, "value": 0,
                          "entries": 33554432},
        },
        "programs": {"mv_bounce": "fentry", "mv_bounce_exit": "fexit",
                     "mv_sync_device": "fentry", "mv_sync_cpu": "fentry"},
    },
}


def self_test_layouts(tmp, pairs):
    """Both layouts verified against pinned bytes, offline."""
    rings = {"lc": "mv_lifecycle", "cp": "mv_copies"}
    ok = True
    for (name, channel), want in sorted(LAYOUT_WANT.items()):
        proc = consumer_run(["--verify-layout",
                             pairs[name][channel]["path"],
                             rings[channel]])
        parsed = core.parse_verify_layout(proc.stdout)
        tag = "layout-%s-%s" % (name, channel)
        good = proc.returncode == 0 and parsed["verdict"] == "PASS"
        ok = check(tag, good, proc.stdout.strip().split("\n")[-1]
                   if not good else "") and ok
        ok = check(tag + "-family",
                   parsed["family"] == want["family"]
                   and parsed["core_relocations"] == want["core"],
                   "%r" % parsed) and ok
        ok = check(tag + "-maps", parsed["maps"] == want["maps"],
                   "%r" % (parsed["maps"],)) and ok
        kinds = {key: row["kind"] for key, row in parsed["programs"].items()}
        sleepable = any(row["sleepable"]
                        for row in parsed["programs"].values())
        ok = check(tag + "-progs",
                   kinds == want["programs"] and not sleepable,
                   "%r" % (parsed["programs"],)) and ok
        ok = check(tag + "-sha",
                   parsed["sha256"] == pairs[name][channel]["sha256"]) and ok
    return ok


# -- Unarmed self-test: refusals --------------------------------

def self_test_wrong_pair(pairs):
    """Wrong-pair refusals through the real consume entrypoint.

    The digest and family gates fire before any privilege or
    BTF need, so these run fully offline with no boot.
    """
    ok = True
    base_lc = pairs["baseline"]["lc"]["path"]
    c9_lc = pairs["c9"]["lc"]["path"]
    sites = core.LC_SITES
    cases = [
        ("family-swap-aya",
         ["--expect-family", "aya", base_lc, "mv_lifecycle",
          sites, "1", os.path.join(tempfile.gettempdir(),
                                   "stress-never-written")],
         "family mismatch"),
        ("family-swap-c",
         ["--expect-family", "c", c9_lc, "mv_lifecycle",
          sites, "1", os.path.join(tempfile.gettempdir(),
                                   "stress-never-written")],
         "family mismatch"),
        ("digest-wrong",
         ["--expect-sha256", "0" * 64, c9_lc, "mv_lifecycle",
          sites, "1", os.path.join(tempfile.gettempdir(),
                                   "stress-never-written")],
         "digest mismatch"),
        ("sites-short",
         [c9_lc, "mv_lifecycle", "mv_map_result:x",
          "1", os.path.join(tempfile.gettempdir(),
                            "stress-never-written")],
         "exactly the mv_lifecycle program set"),
    ]
    for name, argv, want in cases:
        proc = consumer_run(argv)
        ok = check("refuse-%s" % name,
                   proc.returncode == 1 and want in proc.stdout,
                   "exit=%d %s" % (proc.returncode,
                                   proc.stdout.strip()[-160:])) and ok
    proc = consumer_run(["--verify-layout",
                         pairs["c9"]["cp"]["path"], "mv_lifecycle"])
    ok = check("refuse-cross-channel",
               proc.returncode == 1
               and "neither family" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    proc = consumer_run(["--verify-layout",
                         pairs["baseline"]["lc"]["path"], "mv_copies"])
    ok = check("refuse-cross-channel-legacy",
               proc.returncode == 1
               and "neither family" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    return ok


# -- Unarmed self-test: replay ----------------------------------

SIZES = (512, 1024, 2048, 4096)


def lc_window():
    """One coherent 16-record lifecycle window: 8 maps + 8 unmaps."""
    wire = b""
    sizes = []
    for i in range(8):
        size = SIZES[i % 4]
        sizes.append(size)
        wire += core.encode_lc(core.LC_KIND_MAP, True, False, 1,
                               i, 1000 + i, size, i + 1)
    for i in range(8):
        wire += core.encode_lc(core.LC_KIND_UNMAP, True, True, 1,
                               8 + i, 2000 + i, sizes[i], i + 1)
    counts = [16, sum(sizes) * 2, 16, sum(sizes) * 2, 0, 0]
    return wire, counts, sizes


def cp_window():
    """One coherent copy window: 4 syncs then 4 known copies."""
    wire = b""
    req_total = 0
    for i in range(4):
        wire += core.encode_cp(core.CP_KIND_SYNC, 0, False, False,
                               False, 1, 4, i, 1000 + i, 512, 0)
        req_total += 512
    for i in range(4):
        wire += core.encode_cp(core.CP_KIND_COPY, 1, True, False,
                               False, 1, 0, 4 + i, 2000 + i,
                               1024, 1024)
        req_total += 1024
    counts = [8, req_total, 8, req_total, 0, 0]
    return wire, counts


def self_test_replay(tmp):
    """Replay determinism + gate-shape checks on synthetic logs."""
    ok = True
    wire, counts, _sizes = lc_window()
    wire_path = os.path.join(tmp, "lc.wire")
    open(wire_path, "wb").write(wire)
    counts_text = ",".join(str(v) for v in counts)
    outs = []
    for i in range(2):
        out = os.path.join(tmp, "lc%d.txt" % i)
        proc = consumer_run(["--replay", wire_path, "mv_lifecycle",
                             out, "--counts", counts_text])
        outs.append(out)
        ok = check("replay-lc-exit-%d" % i, proc.returncode == 0,
                   proc.stdout.strip()[-200:]) and ok
    ok = check("replay-lc-deterministic",
               open(outs[0], "rb").read() == open(outs[1], "rb").read()) and ok
    events, summary = parse_consume_file(outs[0])
    ok = check("replay-lc-conservation",
               check_conservation(events, summary, "syn-lc") == [],
               "; ".join(check_conservation(events, summary, "syn-lc"))) and ok
    ok = check("replay-lc-closure",
               check_identity_closure(events, "syn-lc") == []) and ok
    mix = core.retained_breakdown(events)
    ok = check("replay-lc-mix",
               mix["D"] == 16 and mix["M"] == 0
               and mix["maps_ok_assigned"] == 8
               and mix["unmaps_known"] == 8, "%r" % mix) and ok
    wire, counts = cp_window()
    wire_path = os.path.join(tmp, "cp.wire")
    open(wire_path, "wb").write(wire)
    counts_text = ",".join(str(v) for v in counts)
    outs = []
    for i in range(2):
        out = os.path.join(tmp, "cp%d.txt" % i)
        proc = consumer_run(["--replay", wire_path, "mv_copies",
                             out, "--counts", counts_text])
        outs.append(out)
        ok = check("replay-cp-exit-%d" % i, proc.returncode == 0,
                   proc.stdout.strip()[-200:]) and ok
    ok = check("replay-cp-deterministic",
               open(outs[0], "rb").read() == open(outs[1], "rb").read()) and ok
    events, summary = parse_consume_file(outs[0])
    ok = check("replay-cp-conservation",
               check_conservation(events, summary, "syn-cp") == [],
               "; ".join(check_conservation(events, summary, "syn-cp"))) and ok
    return ok


def self_test_malformed(tmp):
    """Malformed-wire refusals: exit 1 with a retained summary."""
    ok = True
    base_wire, _, _ = lc_window()
    cases = []
    cases.append(("truncated", base_wire + b"\0" * 10, "mv_lifecycle",
                  "badframe=1"))
    bad = bytearray(core.encode_lc(1, True, False, 1, 0, 0, 512, 1))
    bad[0] = 0
    cases.append(("bad-magic", bytes(bad), "mv_lifecycle", "badrec=1"))
    # Unmap without ok: the wire shape passes, semantics refuse.
    cases.append(("unmap-no-ok",
                  core.encode_lc(2, False, False, 1, 0, 0, 512, 5),
                  "mv_lifecycle", "badrec=1"))
    # Known copy with effective past requested: semantic refusal.
    cases.append(("cp-overflow",
                  core.encode_cp(2, 1, True, False, False, 1, 0,
                                 0, 0, 1024, 1281),
                  "mv_copies", "badrec=1"))
    # Known sync with zero bytes: invalid for a request.
    cases.append(("cp-sync-known",
                  core.encode_cp(1, 0, True, False, False, 1, 0,
                                 0, 0, 512, 0),
                  "mv_copies", "badrec=1"))
    for name, wire, ring, marker in cases:
        wire_path = os.path.join(tmp, "bad-%s.wire" % name)
        open(wire_path, "wb").write(wire)
        out = os.path.join(tmp, "bad-%s.txt" % name)
        proc = consumer_run(["--replay", wire_path, ring, out,
                             "--counts", "1,512,1,512,0,0"])
        text = open(out).read() if os.path.isfile(out) else ""
        ok = check("malformed-%s" % name,
                   proc.returncode == 1 and marker in text
                   and "unhealthy" in proc.stdout,
                   "exit=%d %s" % (proc.returncode,
                                   proc.stdout.strip()[-120:])) and ok
    return ok


def self_test_cargo_unit():
    """The consumer's own unit tests (decoders, gates, BTF)."""
    proc = core.run(
        ["cargo", "test", "--locked", "--offline"], cwd=core.CONSUMER_DIR,
        timeout=600, env=core.cargo_env())
    tail = (proc.stdout + proc.stderr).strip().split("\n")[-1]
    return check("cargo-unit", proc.returncode == 0, tail[-200:])


def self_test_host_btf():
    """Resolver proof on live host BTF bytes (unprivileged read)."""
    path = "/sys/kernel/btf/vmlinux"
    if not os.access(path, os.R_OK):
        print("ok host-btf SKIP (no readable host BTF)")
        return True
    proc = consumer_run(["--resolve-copy-table"])
    lines = proc.stdout.strip().split("\n")
    fields = [line for line in lines if line.startswith("fields: ")]
    dirs = [line for line in lines if line.startswith("dirs: ")]
    ok = check("host-btf-resolve", proc.returncode == 0
               and len(fields) == 1 and len(dirs) == 1,
               proc.stdout.strip()[-200:])
    if ok:
        ok = check("host-btf-dirs", dirs[0] == "dirs: bidi=0 to=1 from=2",
                   dirs[0] if dirs else "") and ok
    return ok


# -- Unarmed self-test: judge + comparison ----------------------

def synth_leg(miss_maps=0, miss_unmaps=0):
    """One synthetic coherent leg: 100 maps + 100 unmaps + copies.

    miss_maps unassigned successful maps and miss_unmaps missed
    unmaps; everything else resolves with identity closure.
    """
    lc = []
    for i in range(100):
        gen = 0 if i < miss_maps else i + 1
        lc.append({"ring": "lc", "kind": 1, "ok": 1, "skip": 0,
                   "dir": 1, "seq": i, "ktime": 1000 + i,
                   "size": 512, "gen": gen})
    for i in range(100):
        if i < miss_unmaps:
            gen = 0
        elif i < miss_maps:
            gen = 0
        else:
            gen = i + 1
        lc.append({"ring": "lc", "kind": 2, "ok": 1, "skip": 1,
                   "dir": 1, "seq": 100 + i, "ktime": 2000 + i,
                   "size": 512, "gen": gen})
    lc_sum = {"observed": 200, "badframe": 0, "badrec": 0,
              "cnt_obs": 200, "cnt_obsb": 200 * 512,
              "cnt_emit": 200, "cnt_emitb": 200 * 512,
              "cnt_fail": 0, "cnt_flags": 0,
              "rx": 200, "dlv": 200, "mal": 0, "drop": 0}
    cp = []
    for i in range(50):
        cp.append({"ring": "cp", "kind": 1, "todev": 1, "known": 0,
                   "clamp": 0, "ezero": 0, "dir": 1, "reason": 4,
                   "seq": i, "ktime": 1000 + i, "req": 512, "eff": 0})
    for i in range(50):
        cp.append({"ring": "cp", "kind": 2, "todev": 1, "known": 1,
                   "clamp": 0, "ezero": 0, "dir": 1, "reason": 0,
                   "seq": 50 + i, "ktime": 2000 + i,
                   "req": 1024, "eff": 1024})
    cp_sum = {"observed": 100, "badframe": 0, "badrec": 0,
              "cnt_obs": 100, "cnt_obsb": 50 * 512 + 50 * 1024,
              "cnt_emit": 100, "cnt_emitb": 50 * 512 + 50 * 1024,
              "cnt_fail": 0, "cnt_flags": 0,
              "rx": 100, "dlv": 100, "mal": 0, "drop": 0}
    bpf = {"maps": 100, "unmaps": 100, "bounces": 50}
    stats = {"before": {"read_ios": 10}, "after": {"read_ios": 60}}
    return lc, lc_sum, cp, cp_sum, bpf, stats


def self_test_judge():
    """Judge shapes on synthetic legs: pass plus every tripwire."""
    ok = True
    good = synth_leg()
    bad, metrics = core.judge_phase2(*good, "syn")
    ok = check("judge-pass", bad == [], "; ".join(bad)) and ok
    ok = check("judge-metrics",
               metrics["M"] == 0 and metrics["D"] == 200
               and metrics["miss"] == 0.0, "%r" % metrics) and ok
    cases = []
    # Probe vs bpftrace slack: 64 passes, 65 trips.
    slack = synth_leg()
    slack[4]["maps"] = 100 + 64
    cases.append(("slack-edge", slack, True))
    over = synth_leg()
    over[4]["maps"] = 100 + 65
    cases.append(("slack-over", over, False))
    # No block reads: the flood never flowed.
    norio = synth_leg()
    norio[5]["after"]["read_ios"] = 10
    cases.append(("no-block-reads", norio, False))
    # Copy double-record tripwire: 70 valid copy records
    # against zero bounce calls (conservation still holds).
    double = synth_leg()
    for i in range(20):
        double[2].append({"ring": "cp", "kind": 2, "todev": 1,
                          "known": 1, "clamp": 0, "ezero": 0,
                          "dir": 1, "reason": 0, "seq": 100 + i,
                          "ktime": 3000 + i, "req": 1024,
                          "eff": 1024})
    double[3]["observed"] = 120
    double[3]["cnt_obs"] = 120
    double[3]["cnt_obsb"] += 20 * 1024
    double[3]["cnt_emit"] = 120
    double[3]["cnt_emitb"] += 20 * 1024
    double[3]["rx"] = 120
    double[3]["dlv"] = 120
    double[4]["bounces"] = 0
    cases.append(("double-record", double, False))
    # Copy silent-drop tripwire.
    drop = synth_leg()
    drop[4]["bounces"] = 50 + 65
    cases.append(("silent-drop", drop, False))
    # Drop covered by submit failures stays honest.
    covered = synth_leg()
    covered[4]["bounces"] = 50 + 64
    covered[3]["cnt_fail"] = 64
    covered[3]["cnt_obs"] = 164
    covered[3]["cnt_obsb"] = 50 * 512 + 50 * 1024 + 64 * 1024
    cases.append(("drop-covered", covered, True))
    # Miss ceiling: exactly half passes, over trips.
    half = synth_leg(miss_maps=50, miss_unmaps=50)
    cases.append(("miss-half", half, True))
    over_miss = synth_leg(miss_maps=51, miss_unmaps=50)
    cases.append(("miss-over", over_miss, False))
    # Dangling identity trips closure.
    dangling = synth_leg()
    dangling[0][100]["gen"] = 9999
    cases.append(("dangling", dangling, False))
    for name, leg, want_pass in cases:
        reasons, _ = core.judge_phase2(*leg, "syn-%s" % name)
        ok = check("judge-%s" % name, (reasons == []) == want_pass,
                   "; ".join(reasons)) and ok
    # Outcome mix splits the miss classes exactly.
    leg = synth_leg(miss_maps=3, miss_unmaps=5)
    mix = core.retained_breakdown(leg[0])
    ok = check("judge-mix",
               mix["M"] == 8 and mix["D"] == 200
               and mix["maps_unassigned"] == 3
               and mix["unmaps_missed"] == 5
               and mix["maps_failed"] == 0
               and mix["maps_ok_assigned"] == 97
               and mix["unmaps_known"] == 95, "%r" % mix) and ok
    return ok


def self_test_compare():
    """Comparison logic on synthetic pairs."""
    ok = True
    verdict, reasons, detail = core.compare_pairs(
        {"M": 10, "D": 200, "complete": True},
        {"M": 5, "D": 200, "complete": True}, "syn")
    ok = check("compare-pass", verdict == "PASS"
               and detail["c9_ratio"] == "5/200", verdict) and ok
    verdict, reasons, _ = core.compare_pairs(
        {"M": 5, "D": 200, "complete": True},
        {"M": 10, "D": 200, "complete": True}, "syn")
    ok = check("compare-regression", verdict == "REGRESSION"
               and reasons, verdict) and ok
    # A higher candidate ratio regresses even under the ceiling.
    verdict, _, _ = core.compare_pairs(
        {"M": 1, "D": 200, "complete": True},
        {"M": 2, "D": 200, "complete": True}, "syn")
    ok = check("compare-under-ceiling", verdict == "REGRESSION",
               verdict) and ok
    verdict, _, _ = core.compare_pairs(
        {"M": 0, "D": 0, "complete": True},
        {"M": 0, "D": 200, "complete": True}, "syn")
    ok = check("compare-empty-blocked", verdict == "BLOCKED",
               verdict) and ok
    verdict, _, _ = core.compare_pairs(
        {"M": 5, "D": 200, "complete": True},
        {"M": 5, "D": 200, "complete": False}, "syn")
    ok = check("compare-incomplete-blocked", verdict == "BLOCKED",
               verdict) and ok
    verdict, _, detail = core.compare_pairs(
        {"M": 5, "D": 200, "complete": True},
        {"M": 5, "D": 200, "complete": True}, "syn")
    ok = check("compare-equal-pass", verdict == "PASS", verdict) and ok
    return ok


# -- Unarmed self-test: manifest --------------------------------

def self_test_manifest(tmp, pairs):
    """Input manifest checks: exact bytes bind, tamper refuses."""
    ok = True
    try:
        candidate = core.load_candidate_binding(str(REPO))
    except (ValueError, OSError) as exc:
        print("ok manifest-verify SKIP (no dist/ seal in tree: %s)"
              % str(exc)[:120])
        return True
    consumer = {"sha256": sha_file(core.CONSUMER_RELEASE),
                "build": {"profile": "release"}}
    try:
        oracle = core.oracle_run_binding(str(REPO))
    except (ValueError, OSError) as exc:
        return check("manifest-verify", False, str(exc))
    commit = core.git_head(str(REPO))
    path = os.path.join(tmp, "inputs.json")
    manifest = core.write_input_manifest(
        path, pairs, candidate, consumer, oracle,
        ["test_stress_consumer.py", "--self-test"], commit)
    ok = check("manifest-verify",
               core.verify_input_manifest(manifest,
                                          core.CONSUMER_RELEASE) == []) and ok
    ok = check("manifest-stamps",
               manifest["runner_commit"] == commit
               and manifest["runner_argv"][0].endswith(".py")
               and manifest["consumer"]["binary_sha256"]
               == sha_file(core.CONSUMER_RELEASE)
               and "memveil_dma_oracle.c" in manifest["oracle"]) and ok
    tampered = json.loads(open(path).read())
    tampered["pairs"]["c9"]["lc"]["sha256"] = "0" * 64
    ok = check("manifest-tamper",
               core.verify_input_manifest(tampered) != []) and ok
    renamed = json.loads(open(path).read())
    renamed["pairs"]["other"] = renamed["pairs"].pop("c9")
    ok = check("manifest-names",
               core.verify_input_manifest(renamed) != []) and ok
    ko_tampered = json.loads(open(path).read())
    ko_tampered["oracle"]["ko_sha256"] = "0" * 64
    ok = check("manifest-ko-tamper",
               core.verify_input_manifest(ko_tampered) != []) and ok
    btf_dropped = json.loads(open(path).read())
    del btf_dropped["oracle"]["btf_sha256"]
    ok = check("manifest-btf-drop",
               core.verify_input_manifest(btf_dropped) != []) and ok
    return ok


# -- Unarmed self-test: guest oracle --------------------------

def self_test_guest_oracle(tmp, pairs):
    """Guest-targeted oracle fixture: pinned bytes bind, drift refuses."""
    ok = True
    try:
        receipt = guest_oracle.verify_fixture()
        ok = check("oracle-fixture",
                   receipt["ko_sha256"] == guest_oracle.KO_SHA256
                   and receipt["target_release"]
                   == guest_oracle.GUEST_RELEASE
                   and receipt["vermagic"]
                   == guest_oracle.GUEST_VERMAGIC) and ok
    except (ValueError, OSError) as exc:
        ok = check("oracle-fixture", False, str(exc)) and ok
    magic = None
    try:
        magic = guest_oracle.vermagic_from_bytes(guest_oracle.FIXTURE_KO)
        ok = check("oracle-vermagic",
                   magic == guest_oracle.GUEST_VERMAGIC,
                   "%r" % magic) and ok
    except ValueError as exc:
        ok = check("oracle-vermagic", False, str(exc)) and ok
    modinfo = shutil.which("modinfo")
    if modinfo is None:
        print("ok oracle-modinfo-agrees SKIP (no modinfo)")
    elif magic is None:
        ok = check("oracle-modinfo-agrees", False,
                   "no parsed vermagic") and ok
    else:
        proc = core.run(
            [modinfo, "-F", "vermagic", guest_oracle.FIXTURE_KO],
            timeout=30)
        ok = check("oracle-modinfo-agrees",
                   proc.returncode == 0
                   and proc.stdout.strip() == magic.strip(),
                   proc.stdout.strip()[-120:]) and ok
    # A flipped byte refuses at the digest gate.
    blob = bytearray(open(guest_oracle.FIXTURE_KO, "rb").read())
    blob[1000] ^= 1
    bad_ko = os.path.join(tmp, "bad.ko")
    open(bad_ko, "wb").write(bytes(blob))
    try:
        guest_oracle.verify_fixture(ko_path=bad_ko)
        ok = check("oracle-tamper", False, "accepted") and ok
    except ValueError:
        ok = check("oracle-tamper", True) and ok
    # Non-ELF and truncated bytes refuse the vermagic parse.
    bad_elf = os.path.join(tmp, "bad.elf")
    open(bad_elf, "wb").write(b"not an elf object")
    try:
        guest_oracle.vermagic_from_bytes(bad_elf)
        ok = check("oracle-vermagic-nonelf", False, "accepted") and ok
    except ValueError:
        ok = check("oracle-vermagic-nonelf", True) and ok
    trunc = os.path.join(tmp, "trunc.ko")
    open(trunc, "wb").write(open(guest_oracle.FIXTURE_KO, "rb").read()[:40])
    try:
        guest_oracle.vermagic_from_bytes(trunc)
        ok = check("oracle-vermagic-trunc", False, "accepted") and ok
    except ValueError:
        ok = check("oracle-vermagic-trunc", True) and ok
    # The manifest binds the fixture digest; drift refuses.
    candidate = {"schema": "memveil-candidate/2",
                 "source": {"commit": core.C9_SOURCE_COMMIT,
                            "tree": core.C9_SOURCE_TREE},
                 "bundle_manifest_sha256": core.C9_BUNDLE_MANIFEST_SHA,
                 "files": {
                     "bpf/swiotlb_lifecycle.bpf.o": core.C9_LC_SHA,
                     "bpf/swiotlb_copy.bpf.o": core.C9_CP_SHA,
                     "bpf/swiotlb_attempt.bpf.o": core.C9_ATTEMPT_SHA},
                 "bundle": {"sha256": core.C9_BUNDLE_SHA,
                            "size": core.C9_BUNDLE_SIZE}}
    consumer = {"sha256": sha_file(core.CONSUMER_RELEASE),
                "build": {"profile": "release"}}
    try:
        oracle = core.oracle_run_binding(str(REPO))
    except (ValueError, OSError) as exc:
        return check("oracle-manifest-bind", False, str(exc)) and ok
    commit = core.git_head(str(REPO))
    manifest = core.write_input_manifest(
        os.path.join(tmp, "oracle-inputs.json"), pairs, candidate,
        consumer, oracle, ["self-test"], commit)
    ok = check("oracle-manifest-bind",
               core.verify_input_manifest(
                   manifest, core.CONSUMER_RELEASE) == []
               and manifest["oracle"]["ko_sha256"]
               == guest_oracle.KO_SHA256) and ok
    # Rebuild audit: byte-equality with the fixture when the
    # headers cache is present, honest skip otherwise.
    tree = os.path.join(guest_oracle.kbuild_root(), "tree", "usr",
                        "src", "linux-headers-7.0.14-070014-generic",
                        "Makefile")
    if not os.path.isfile(tree):
        print("ok oracle-rebuild SKIP (no headers cache)")
        return ok
    try:
        made = guest_oracle.rebuild_from_kbuild(
            os.path.join(tmp, "rebuild"))
        same = open(made, "rb").read() == open(
            guest_oracle.FIXTURE_KO, "rb").read()
        ok = check("oracle-rebuild", same,
                   "rebuilt bytes differ") and ok
    except ValueError as exc:
        ok = check("oracle-rebuild", False, str(exc)[:200]) and ok
    return ok


# -- Unarmed self-test: forensics -----------------------------

def self_test_forensics(tmp):
    """Fault injection: stalls leave markers, partials, no strays."""
    import contextlib
    import signal

    class ProbeGate(stress_guest.Gate):
        def __init__(self, work, export):
            self.work = work
            self.export_dir = export
            self.consumers = []
            self.transients = []
            self.oracle_loaded = False

    ok = True
    work = os.path.join(tmp, "fwork")
    export = os.path.join(tmp, "fexport")
    os.makedirs(work)
    os.makedirs(export)
    gate = ProbeGate(work, export)
    # A stalled step fails with its last marker, the timeout
    # status, and the partial output mirrored to the export.
    try:
        with gate.step("probe-stall"):
            stress_guest.sh(["sleep", "30"], timeout=1)
        ok = check("forensics-stall-fails", False, "no failure") and ok
    except SystemExit:
        ok = check("forensics-stall-fails", True) and ok
    marks = [json.loads(line)
             for line in open(os.path.join(work, "progress.log"))]
    kinds = [(m["step"], m["status"]) for m in marks]
    ok = check("forensics-markers",
               kinds == [("probe-stall", "start"),
                         ("probe-stall", "timeout")],
               "%r" % (kinds,)) and ok
    mirrored = open(os.path.join(export, "progress.log")).read()
    ok = check("forensics-mirror",
               '"status": "timeout"' in mirrored
               and '"step": "probe-stall"' in mirrored) and ok
    partial = os.path.join(work, "probe-stall-timeout.txt")
    ok = check("forensics-partial",
               os.path.isfile(partial)
               and "timeout: 1s" in open(partial).read()
               and os.path.isfile(os.path.join(
                   export, "probe-stall-timeout.txt"))) and ok
    # The owned guest wrapper preserves the partial console
    # capture on timeout and reaps the owned process group.
    from vm_process import run_owned_guest
    marker = os.path.join(tmp, "child.pid")
    script = ("import subprocess,time,pathlib,sys;"
              "print('hello-partial',flush=True);"
              "p=subprocess.Popen(['sleep','30']);"
              "pathlib.Path(%r).write_text(str(p.pid));"
              "time.sleep(30)" % marker)
    try:
        run_owned_guest([sys.executable, "-c", script], timeout=2)
        ok = check("forensics-owned-timeout", False, "no timeout") and ok
    except subprocess.TimeoutExpired as exc:
        ok = check("forensics-owned-timeout",
                   "hello-partial" in (exc.stdout or ""),
                   "%r" % (exc.stdout,)) and ok
    pid = int(open(marker).read())
    deadline = time.monotonic() + 5
    alive = True
    while time.monotonic() < deadline:
        try:
            with open("/proc/%d/stat" % pid) as handle:
                state = handle.read().split()[2]
            if state == "Z":
                alive = False
                break
        except (FileNotFoundError, ProcessLookupError):
            alive = False
            break
        time.sleep(0.1)
    ok = check("forensics-owned-reaped", not alive,
               "stray pid %d" % pid) and ok
    # Readiness: only a complete newline-terminated
    # line for the consumer's own ring accepts. A full
    # ack prefix without its newline then silence must
    # fail at the deadline, not accept immediately.
    stall = subprocess.Popen(
        [sys.executable, "-c",
         "import sys,time;"
         "sys.stdout.write('ready ring=mv_lifecycle');"
         "sys.stdout.flush();time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    stall.gate_ring = "mv_lifecycle"
    start = time.monotonic()
    try:
        gate.wait_ready([stall], timeout=2)
        elapsed = time.monotonic() - start
        ok = check("forensics-ready-newline-less", False,
                   "accepted") and ok
    except SystemExit:
        elapsed = time.monotonic() - start
        ok = check("forensics-ready-newline-less",
                   1.9 <= elapsed < 10, "%.1fs" % elapsed) and ok
    finally:
        stall.kill()
        try:
            stall.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # A complete line for another ring refuses too.
    wrong = subprocess.Popen(
        [sys.executable, "-c",
         "print('ready ring=mv_copies',flush=True);"
         "import time;time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    wrong.gate_ring = "mv_lifecycle"
    start = time.monotonic()
    try:
        gate.wait_ready([wrong], timeout=2)
        elapsed = time.monotonic() - start
        ok = check("forensics-ready-wrong-ring", False,
                   "accepted") and ok
    except SystemExit:
        elapsed = time.monotonic() - start
        ok = check("forensics-ready-wrong-ring",
                   1.9 <= elapsed < 10, "%.1fs" % elapsed) and ok
    finally:
        wrong.kill()
        try:
            wrong.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # A proper ack is still accepted, with its prefix kept
    # for the later readiness cross-check.
    good = subprocess.Popen(
        [sys.executable, "-c",
         "print('ready ring=mv_lifecycle',flush=True)"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    good.gate_ring = "mv_lifecycle"
    try:
        gate.wait_ready([good], timeout=5)
        gate.wait_consumer(good, "forensics-ready", timeout=5)
        ok = check("forensics-ready-accept",
                   getattr(good, "gate_ready", False)
                   and "ready ring=mv_lifecycle\n" in getattr(
                       good, "gate_prefix", "")) and ok
    except SystemExit as exc:
        ok = check("forensics-ready-accept", False, str(exc)) and ok
    # A descendant holding stdout past the child's exit
    # delays the verdict by its own lifetime, never by
    # failing: the drain completes and the full output
    # is preserved.
    holder_pid = os.path.join(tmp, "fast-holder.pid")
    held = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,pathlib;"
         "print('ready ring=mv_lifecycle',flush=True);"
         "print('holder-output-marker',flush=True);"
         "p=subprocess.Popen(['sleep','3']);"
         "pathlib.Path(%r).write_text(str(p.pid))" % holder_pid],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    held.gate_ring = "mv_lifecycle"
    start = time.monotonic()
    try:
        gate.wait_ready([held], timeout=5)
        out = gate.wait_consumer(held, "forensics-held",
                                 timeout=2)
        elapsed = time.monotonic() - start
        seen = getattr(held, "gate_prefix", "") + (out or "")
        ok = check("forensics-consumer-holder-returns",
                   "holder-output-marker" in seen
                   and 2.0 <= elapsed < 5.5,
                   "%.1fs %r" % (elapsed, seen[-80:])) and ok
    except SystemExit as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-consumer-holder-returns", False,
                   "%.1fs %s" % (elapsed, exc)) and ok
    finally:
        try:
            os.kill(int(open(holder_pid).read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
        try:
            held.kill()
        except OSError:
            pass
        try:
            held.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # A holder that never leaves fails bounded instead:
    # the drain grace plus truncation, never a hang and
    # never a silent discard.
    stuck_pid = os.path.join(tmp, "stuck-holder.pid")
    stuck = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,pathlib;"
         "print('ready ring=mv_lifecycle',flush=True);"
         "print('stuck-output-marker',flush=True);"
         "p=subprocess.Popen(['sleep','30']);"
         "pathlib.Path(%r).write_text(str(p.pid))" % stuck_pid],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    stuck.gate_ring = "mv_lifecycle"
    start = time.monotonic()
    diag = io.StringIO()
    try:
        gate.wait_ready([stuck], timeout=5)
        with contextlib.redirect_stderr(diag):
            gate.wait_consumer(stuck, "forensics-stuck",
                               timeout=1)
        elapsed = time.monotonic() - start
        ok = check("forensics-consumer-holder-truncated", False,
                   "returned") and ok
    except SystemExit:
        elapsed = time.monotonic() - start
        ok = check("forensics-consumer-holder-truncated",
                   4.5 <= elapsed < 10
                   and "truncated" in diag.getvalue()
                   and "stuck-output-marker" in diag.getvalue(),
                   "%.1fs %r" % (elapsed,
                                 diag.getvalue()[-120:])) and ok
    finally:
        try:
            os.kill(int(open(stuck_pid).read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
        try:
            stuck.kill()
        except OSError:
            pass
        try:
            stuck.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # Abort tails reach the shared export, not just guest
    # work storage, with sidecars and a record entry.
    gate.mode = "full"
    noisy = subprocess.Popen(
        [sys.executable, "-c",
         "print('abort-tail-marker',flush=True);"
         "import time;time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    gate.consumers.append(noisy)
    try:
        time.sleep(0.5)
        gate.abort("probe abort")
        tail = open(os.path.join(
            export, "abort-consumer-0.txt")).read()
        record = json.loads(open(os.path.join(
            export, "abort.json")).read())
        ok = check("forensics-abort-exports-tails",
                   "abort-tail-marker" in tail
                   and os.path.isfile(os.path.join(
                       export, "abort-consumer-0.txt.sha256"))
                   and record.get("tails")
                   == ["abort-consumer-0.txt"]
                   and record.get("unreaped") == 0
                   and record.get("reason") == "probe abort",
                   "%r" % (record,)) and ok
    except (SystemExit, OSError, ValueError) as exc:
        ok = check("forensics-abort-exports-tails", False,
                   str(exc)) and ok
    finally:
        gate.consumers.remove(noisy)
        try:
            noisy.kill()
        except OSError:
            pass
        try:
            noisy.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # An abort tail held open still exports bounded,
    # marked truncated instead of hanging the abort.
    gate.consumers.clear()
    tail_pid = os.path.join(tmp, "tail-holder.pid")
    lingering = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,pathlib;"
         "print('lingering-tail-marker',flush=True);"
         "p=subprocess.Popen(['sleep','30']);"
         "pathlib.Path(%r).write_text(str(p.pid))" % tail_pid],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    gate.consumers.append(lingering)
    start = time.monotonic()
    try:
        lingering.wait(timeout=5)
        gate.abort("probe lingering abort")
        elapsed = time.monotonic() - start
        tail = open(os.path.join(
            export, "abort-consumer-0.txt")).read()
        record = json.loads(open(os.path.join(
            export, "abort.json")).read())
        ok = check("forensics-abort-tail-truncated",
                   4.5 <= elapsed < 12
                   and "lingering-tail-marker" in tail
                   and "truncated" in tail
                   and record.get("tails")
                   == ["abort-consumer-0.txt"],
                   "%.1fs %r" % (elapsed, tail[-120:])) and ok
    except (SystemExit, OSError, ValueError,
            subprocess.TimeoutExpired) as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-abort-tail-truncated", False,
                   "%.1fs %s" % (elapsed, exc)) and ok
    finally:
        gate.consumers.remove(lingering)
        try:
            os.kill(int(open(tail_pid).read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
        try:
            lingering.kill()
        except OSError:
            pass
        try:
            lingering.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    # A host child in a separate session holding stdout
    # cannot push past timeout + grace + the short final
    # drain; the pipe-buffered capture is preserved and
    # the cut is marked, not silent.
    outer_pid = os.path.join(tmp, "outer-holder.pid")
    script = ("import subprocess,sys,time,pathlib;"
              "print('separate-session-marker',flush=True);"
              "p=subprocess.Popen([sys.executable,'-c',"
              "'import os,time;os.setsid();time.sleep(30)']);"
              "pathlib.Path(%r).write_text(str(p.pid));"
              "time.sleep(30)" % outer_pid)
    start = time.monotonic()
    try:
        run_owned_guest([sys.executable, "-c", script],
                        timeout=0.2)
        elapsed = time.monotonic() - start
        ok = check("forensics-owned-separate-session", False,
                   "no timeout") and ok
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-owned-separate-session",
                   10 <= elapsed < 14
                   and "separate-session-marker" in (exc.stdout or "")
                   and "truncated" in (exc.stdout or "")
                   and "truncated" in (exc.stderr or ""),
                   "%.1fs %r" % (elapsed, exc.stdout)) and ok
    finally:
        try:
            os.kill(int(open(outer_pid).read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    # A child that outlives SIGKILL must not hang the
    # guest command helper: the post-kill reap has a
    # deadline, and the timeout carries the partials.
    from unittest import mock

    class StuckPopen:
        """A child that never dies within a deadline.

        communicate() always raises TimeoutExpired with
        byte partials (like POSIX _communicate); wait()
        honors its deadline like the kernel, then raises.
        """

        def __init__(self, *args, **kwargs):
            self.args = args[0] if args else None

        def communicate(self, *args, **kwargs):
            raise subprocess.TimeoutExpired(
                self.args, 1, output=b"partial-out",
                stderr=b"partial-err")

        def kill(self):
            pass

        def wait(self, timeout=None):
            if timeout is not None:
                time.sleep(timeout)
            else:
                time.sleep(3600)
            raise subprocess.TimeoutExpired(self.args,
                                            timeout)

        def poll(self):
            return None

    start = time.monotonic()
    try:
        with mock.patch.object(stress_guest.subprocess,
                               "Popen", StuckPopen):
            stress_guest.sh(["sleep", "30"], timeout=1)
        elapsed = time.monotonic() - start
        ok = check("forensics-sh-kill-bounded", False,
                   "returned") and ok
    except stress_guest.StepTimeout as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-sh-kill-bounded",
                   4.5 <= elapsed < 10
                   and "partial-out" in exc.out
                   and "partial-err" in exc.err
                   and "unreaped" in exc.err,
                   "%.1fs %r %r" % (elapsed, exc.out,
                                    exc.err)) and ok
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-sh-kill-bounded", False,
                   "%.1fs bare %s" % (elapsed, exc)) and ok
    # The shared host runner bounds the same way: the
    # same TimeoutExpired type, carrying decoded partials.
    start = time.monotonic()
    try:
        with mock.patch.object(core.subprocess, "Popen",
                               StuckPopen):
            core.run(["sleep", "30"], timeout=1)
        elapsed = time.monotonic() - start
        ok = check("forensics-run-kill-bounded", False,
                   "returned") and ok
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-run-kill-bounded",
                   4.5 <= elapsed < 10
                   and "partial-out" in (exc.output or "")
                   and "partial-err" in (exc.stderr or ""),
                   "%.1fs %r" % (elapsed,
                                 exc.output)) and ok
    # Undecodable tail bytes on the timeout path must not
    # cost the receipt either stream: both arrive, with
    # the replacement shown honestly on the stream that
    # needed it.
    bad_pid = os.path.join(tmp, "bad-holder.pid")
    bad_script = ("import subprocess,sys,time,pathlib;"
                  "print('badbytes-marker',flush=True);"
                  "sys.stderr.buffer.write(b'\\xe2\\x82');"
                  "sys.stderr.buffer.flush();"
                  "p=subprocess.Popen([sys.executable,'-c',"
                  "'import os,time;os.setsid();time.sleep(30)']);"
                  "pathlib.Path(%r).write_text(str(p.pid));"
                  "time.sleep(30)" % bad_pid)
    start = time.monotonic()
    try:
        run_owned_guest([sys.executable, "-c", bad_script],
                        timeout=0.2)
        elapsed = time.monotonic() - start
        ok = check("forensics-owned-undecodable", False,
                   "no timeout") and ok
    except subprocess.TimeoutExpired as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-owned-undecodable",
                   10 <= elapsed < 14
                   and "badbytes-marker"
                   in (exc.stdout or "")
                   and "truncated" in (exc.stdout or "")
                   and "truncated" in (exc.stderr or "")
                   and "\ufffd" in (exc.stderr or "")
                   and "undecodable" in (exc.stderr or "")
                   and "undecodable"
                   not in (exc.stdout or ""),
                   "%.1fs %r %r" % (elapsed, exc.stdout,
                                    exc.stderr)) and ok
    except UnicodeDecodeError as exc:
        elapsed = time.monotonic() - start
        ok = check("forensics-owned-undecodable", False,
                   "%.1fs %s" % (elapsed, exc)) and ok
    finally:
        try:
            os.kill(int(open(bad_pid).read()), signal.SIGKILL)
        except (OSError, ValueError):
            pass
    # Same undecodable bytes on the success path return a
    # receipt instead of raising: lossy, total, marked.
    try:
        proc = run_owned_guest(
            [sys.executable, "-c",
             "import sys;"
             "sys.stderr.buffer.write(b'\\xe2\\x82')"],
            timeout=10)
        ok = check("forensics-owned-undecodable-success",
                   proc.returncode == 0
                   and "\ufffd" in proc.stderr
                   and "undecodable" in proc.stderr
                   and "undecodable" not in proc.stdout,
                   "%r" % (proc.stderr,)) and ok
    except UnicodeDecodeError as exc:
        ok = check("forensics-owned-undecodable-success",
                   False, str(exc)) and ok
    # A diagnostic consumed before a readiness failure
    # still exports its tail: save-then-timeout, not
    # save-only-on-ack.
    gate.consumers.clear()
    diag = subprocess.Popen(
        [sys.executable, "-c",
         "print('verifier: BTF knob missing',flush=True);"
         "import time;time.sleep(30)"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, bufsize=1, start_new_session=True)
    diag.gate_ring = "mv_lifecycle"
    gate.consumers.append(diag)
    try:
        try:
            gate.wait_ready([diag], timeout=2)
            ok = check("forensics-ready-diagnostic", False,
                       "accepted") and ok
        except SystemExit:
            gate.abort("probe diagnostic abort")
            tail = open(os.path.join(
                export, "abort-consumer-0.txt")).read()
            record = json.loads(open(os.path.join(
                export, "abort.json")).read())
            ok = check(
                "forensics-ready-diagnostic",
                "verifier: BTF knob missing" in getattr(
                    diag, "gate_prefix", "")
                and record.get("tails")
                == ["abort-consumer-0.txt"]
                and "verifier: BTF knob missing" in tail,
                "%r" % (record,)) and ok
    except (OSError, ValueError) as exc:
        ok = check("forensics-ready-diagnostic", False,
                   str(exc)) and ok
    finally:
        gate.consumers.remove(diag)
        try:
            diag.kill()
        except OSError:
            pass
        try:
            diag.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    class ScriptedTracer:
        """A tracer with scripted wait/poll behavior."""

        def __init__(self, waits, poll_result):
            self._waits = list(waits)
            self._poll = poll_result
            self.killed = False

        def send_signal(self, sig):
            pass

        def wait(self, timeout=None):
            outcome = self._waits.pop(0)
            if outcome == "timeout":
                raise subprocess.TimeoutExpired(
                    ["bpftrace"], timeout)
            return outcome

        def kill(self):
            self.killed = True

        def poll(self):
            return self._poll

    def unreaped_marks():
        marks = open(os.path.join(
            work, "progress.log")).read()
        return marks.count('"status": "unreaped"')

    # A tracer unreaped on both waits fails closed: the
    # proc stays owned for the abort backstop, an
    # explicit marker records the tracer state, and the
    # raise lands before any checkpoint may run.
    stuck_tracer = ScriptedTracer(["timeout", "timeout"],
                                  None)
    gate.transients.append(stuck_tracer)
    base_marks = unreaped_marks()
    try:
        gate.stop_tracer(stuck_tracer)
        ok = check("forensics-tracer-unreaped", False,
                   "returned") and ok
    except SystemExit:
        ok = check("forensics-tracer-unreaped",
                   stuck_tracer in gate.transients
                   and stuck_tracer.killed
                   and unreaped_marks() == base_marks + 1,
                   "owned=%s killed=%s marks=%d"
                   % (stuck_tracer in gate.transients,
                      stuck_tracer.killed,
                      unreaped_marks())) and ok
    finally:
        gate.transients.remove(stuck_tracer)
    # A tracer that reports on SIGINT stops quietly: no
    # kill, no unreaped marker.
    before = unreaped_marks()
    quick = ScriptedTracer([0], 0)
    try:
        gate.stop_tracer(quick)
        ok = check("forensics-tracer-reaps",
                   not quick.killed
                   and unreaped_marks() == before) and ok
    except SystemExit as exc:
        ok = check("forensics-tracer-reaps", False,
                   str(exc)) and ok
    # A tracer that needs SIGKILL still stops quietly
    # once the reap lands.
    mid = unreaped_marks()
    slow = ScriptedTracer(["timeout", 0], 0)
    try:
        gate.stop_tracer(slow)
        ok = check("forensics-tracer-kill-reaps",
                   slow.killed
                   and unreaped_marks() == mid) and ok
    except SystemExit as exc:
        ok = check("forensics-tracer-kill-reaps", False,
                   str(exc)) and ok
    return ok


# -- Unarmed self-test: explicit seals ------------------------

def build_fixture_seal(root, name, payload):
    """Write one synthetic seal; returns (candidate, bundle, pins)."""
    os.makedirs(root, exist_ok=True)
    members = {
        "bundle/MANIFEST.json": b'{"seal": "%s"}' % name.encode(),
        "bundle/bpf/swiotlb_lifecycle.bpf.o": b"LC:" + payload,
        "bundle/bpf/swiotlb_copy.bpf.o": b"CP:" + payload,
        "bundle/bpf/swiotlb_attempt.bpf.o": b"AT:" + payload,
    }
    bundle_path = os.path.join(root, "bundle.tar.gz")
    with tarfile.open(bundle_path, "w:gz") as archive:
        for mname in sorted(members):
            info = tarfile.TarInfo(mname)
            info.size = len(members[mname])
            info.mtime = 0
            archive.addfile(info, io.BytesIO(members[mname]))
    inner = hashlib.sha256(members["bundle/MANIFEST.json"]).hexdigest()
    files = {"bpf/swiotlb_lifecycle.bpf.o": hashlib.sha256(
                 members["bundle/bpf/swiotlb_lifecycle.bpf.o"]).hexdigest(),
             "bpf/swiotlb_copy.bpf.o": hashlib.sha256(
                 members["bundle/bpf/swiotlb_copy.bpf.o"]).hexdigest(),
             "bpf/swiotlb_attempt.bpf.o": hashlib.sha256(
                 members["bundle/bpf/swiotlb_attempt.bpf.o"]).hexdigest()}
    manifest = {
        "schema": "memveil-candidate/2",
        "source": {"commit": "c" * 40, "tree": "t" * 40},
        "bundle_manifest_sha256": inner,
        "files": files,
        "artifacts": [{"name": "bundle.tar.gz",
                       "sha256": sha_file(bundle_path),
                       "size": os.path.getsize(bundle_path)}],
    }
    candidate_path = os.path.join(root, "candidate.json")
    with open(candidate_path, "w") as handle:
        handle.write(json.dumps(manifest, indent=2,
                                sort_keys=True) + "\n")
    pins = {"candidate_sha256": sha_file(candidate_path),
            "schema": "memveil-candidate/2",
            "source_commit": "c" * 40,
            "source_tree": "t" * 40,
            "bundle_manifest_sha256": inner,
            "files": files,
            "bundle_sha256": sha_file(bundle_path),
            "bundle_size": os.path.getsize(bundle_path)}
    return candidate_path, bundle_path, pins


def self_test_candidate_flags(tmp, pairs):
    """Explicit seals: full verify passes, every mix refuses."""
    ok = True
    cand_a, bundle_a, pins_a = build_fixture_seal(
        os.path.join(tmp, "seal-a"), "a", b"A" * 64)
    cand_b, bundle_b, _pins_b = build_fixture_seal(
        os.path.join(tmp, "seal-b"), "b", b"B" * 64)
    try:
        binding = core.verify_candidate_binding(
            cand_a, bundle_a, pins_a)
        ok = check("candidate-flags-accept",
                   binding["files"] == pins_a["files"]
                   and binding["bundle"]["sha256"]
                   == pins_a["bundle_sha256"]) and ok
    except ValueError as exc:
        ok = check("candidate-flags-accept", False, str(exc)) and ok
    cases = []
    # Missing inputs refuse.
    cases.append(("missing-candidate",
                  os.path.join(tmp, "absent.json"), bundle_a, pins_a))
    cases.append(("missing-bundle",
                  cand_a, os.path.join(tmp, "absent.tar.gz"), pins_a))
    # Altered bytes refuse (flipped copies).
    alt_cand = os.path.join(tmp, "alt-candidate.json")
    blob = bytearray(open(cand_a, "rb").read())
    blob[20] ^= 1
    open(alt_cand, "wb").write(bytes(blob))
    cases.append(("altered-candidate", alt_cand, bundle_a, pins_a))
    alt_bundle = os.path.join(tmp, "alt-bundle.tar.gz")
    blob = bytearray(open(bundle_a, "rb").read())
    blob[40] ^= 1
    open(alt_bundle, "wb").write(bytes(blob))
    cases.append(("altered-bundle", cand_a, alt_bundle, pins_a))
    # Mixed seals refuse: B's candidate names B's bundle,
    # never A's.
    cases.append(("mixed-manifest", cand_b, bundle_a, pins_a))
    cases.append(("mixed-bundle", cand_a, bundle_b, pins_a))
    for case, cand, bundle, pins in cases:
        try:
            core.verify_candidate_binding(cand, bundle, pins)
            ok = check("candidate-flags-%s" % case, False,
                       "accepted") and ok
        except ValueError:
            ok = check("candidate-flags-%s" % case, True) and ok
    # Inner gates fire on their own layer: the manifest
    # claims disagree with the tarball content while every
    # outer check still passes.
    skew = json.loads(open(cand_a).read())
    skew["files"]["bpf/swiotlb_copy.bpf.o"] = "1" * 64
    skew_cand = os.path.join(tmp, "skew-candidate.json")
    with open(skew_cand, "w") as handle:
        handle.write(json.dumps(skew, indent=2, sort_keys=True) + "\n")
    skew_pins = dict(pins_a)
    skew_pins["candidate_sha256"] = sha_file(skew_cand)
    skew_pins["files"] = dict(pins_a["files"])
    skew_pins["files"]["bpf/swiotlb_copy.bpf.o"] = "1" * 64
    try:
        core.verify_candidate_binding(skew_cand, bundle_a, skew_pins)
        ok = check("candidate-flags-inner-member", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("candidate-flags-inner-member",
                   "bundle member drift" in str(exc), str(exc)) and ok
    skew_inner = json.loads(open(cand_a).read())
    skew_inner["bundle_manifest_sha256"] = "1" * 64
    skew_inner_cand = os.path.join(tmp, "skew-inner-candidate.json")
    with open(skew_inner_cand, "w") as handle:
        handle.write(json.dumps(skew_inner, indent=2,
                                sort_keys=True) + "\n")
    skew_inner_pins = dict(pins_a)
    skew_inner_pins["candidate_sha256"] = sha_file(skew_inner_cand)
    skew_inner_pins["bundle_manifest_sha256"] = "1" * 64
    try:
        core.verify_candidate_binding(skew_inner_cand, bundle_a,
                                      skew_inner_pins)
        ok = check("candidate-flags-inner-manifest", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("candidate-flags-inner-manifest",
                   "inner manifest drift" in str(exc), str(exc)) and ok
    unpars = os.path.join(tmp, "unparsable.json")
    open(unpars, "w").write("{oops")
    unpars_pins = dict(pins_a)
    unpars_pins["candidate_sha256"] = sha_file(unpars)
    try:
        core.verify_candidate_binding(unpars, bundle_a, unpars_pins)
        ok = check("candidate-flags-unparsable", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("candidate-flags-unparsable",
                   "unparsable" in str(exc), str(exc)) and ok
    # Wrong-pair --inputs refuse at the manifest gate: the
    # copy bytes presented as the lifecycle pair are not
    # the pinned pair bytes.
    candidate = {"schema": "memveil-candidate/2",
                 "source": {"commit": core.C9_SOURCE_COMMIT,
                            "tree": core.C9_SOURCE_TREE},
                 "bundle_manifest_sha256": core.C9_BUNDLE_MANIFEST_SHA,
                 "files": {
                     "bpf/swiotlb_lifecycle.bpf.o": core.C9_LC_SHA,
                     "bpf/swiotlb_copy.bpf.o": core.C9_CP_SHA,
                     "bpf/swiotlb_attempt.bpf.o": core.C9_ATTEMPT_SHA},
                 "bundle": {"sha256": core.C9_BUNDLE_SHA,
                            "size": core.C9_BUNDLE_SIZE}}
    consumer = {"sha256": sha_file(core.CONSUMER_RELEASE),
                "build": {"profile": "release"}}
    oracle = core.oracle_run_binding(str(REPO))
    commit = core.git_head(str(REPO))
    swapped = {"baseline": pairs["baseline"],
               "c9": {"lc": pairs["c9"]["cp"],
                      "cp": pairs["c9"]["lc"]}}
    manifest = core.write_input_manifest(
        os.path.join(tmp, "swapped-inputs.json"), swapped, candidate,
        consumer, oracle, ["self-test"], commit)
    reasons = core.verify_input_manifest(manifest)
    ok = check("candidate-flags-wrong-pair",
               any("not the pinned pair bytes" in r for r in reasons),
               "%r" % (reasons,)) and ok
    # Armed entry without the explicit seal refuses before
    # anything boots; a conflicting release refuses too.
    from types import SimpleNamespace
    saved = os.environ.get(ARM_ENV)
    os.environ[ARM_ENV] = "1"
    try:
        out_dir = os.path.join(tmp, "never-booted")
        args = SimpleNamespace(inputs=[], out=out_dir, kver="",
                               timeout=5, keep=False, bundle="",
                               candidate="", expect_release="",
                               mode="full")
        rc = armed_run(args)
        ok = check("candidate-flags-armed-refuses",
                   rc == 2 and not os.path.exists(out_dir),
                   "exit=%r" % rc) and ok
        args = SimpleNamespace(inputs=[], out=out_dir, kver="",
                               timeout=5, keep=False,
                               bundle=cand_a, candidate=cand_a,
                               expect_release="1.2.3-nope",
                               mode="full")
        ok = check("candidate-flags-release-refuses",
                   armed_run(args) == 2) and ok
        args = SimpleNamespace(inputs=[], out=out_dir, kver="",
                               timeout=5, keep=False,
                               bundle=cand_a, candidate=cand_a,
                               expect_release="", mode="q9")
        ok = check("candidate-flags-mode-refuses",
                   armed_run(args) == 2) and ok
    finally:
        if saved is None:
            os.environ.pop(ARM_ENV, None)
        else:
            os.environ[ARM_ENV] = saved
    return ok


# -- Unarmed self-test: identity ------------------------------

def self_test_identity():
    """Release + BTF identity: exact pins accept, drift refuses."""
    ok = True
    ok = check("identity-pins-agree",
               stress_guest.EXPECT_RELEASE == core.EXPECT_RELEASE
               == guest_oracle.GUEST_RELEASE,
               "%r" % (core.EXPECT_RELEASE,)) and ok
    oracle = {"ko_sha256": guest_oracle.KO_SHA256,
              "btf_sha256": guest_oracle.GUEST_BTF_SHA256}
    ident = {"release": core.EXPECT_RELEASE,
             "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
             "digests": {"ko": guest_oracle.KO_SHA256}}
    try:
        stress_guest.check_identity(ident, guest_oracle.KO_SHA256,
                                    oracle, core.EXPECT_RELEASE)
        ok = check("identity-accept", True) and ok
    except ValueError as exc:
        ok = check("identity-accept", False, str(exc)) and ok
    cases = [
        ("release", {"release": "7.2.13-200.fc44.x86_64",
                     "btf_sha256": guest_oracle.GUEST_BTF_SHA256},
         guest_oracle.KO_SHA256, oracle),
        ("btf", {"release": core.EXPECT_RELEASE,
                 "btf_sha256": "0" * 64},
         guest_oracle.KO_SHA256, oracle),
        ("ko", ident, "0" * 64, oracle),
        ("pins-missing", ident, guest_oracle.KO_SHA256, {}),
    ]
    for case, who, ko, pins in cases:
        try:
            stress_guest.check_identity(who, ko, pins,
                                        core.EXPECT_RELEASE)
            ok = check("identity-refuse-%s" % case, False,
                       "accepted") and ok
        except ValueError:
            ok = check("identity-refuse-%s" % case, True) and ok
    ok = check("identity-host-accept",
               check_host_identity(ident) == []) and ok
    ok = check("identity-host-release",
               check_host_identity({"release": "other",
                                    "btf_sha256": ident["btf_sha256"],
                                    "digests": ident["digests"]})
               != []) and ok
    ok = check("identity-host-btf",
               check_host_identity({"release": ident["release"],
                                    "btf_sha256": "0" * 64,
                                    "digests": ident["digests"]})
               != []) and ok
    ok = check("identity-host-ko",
               check_host_identity({"release": ident["release"],
                                    "btf_sha256": ident["btf_sha256"],
                                    "digests": {"ko": "0" * 64}})
               != []) and ok
    # Guest init order: the release gate fires before the
    # manifest is even read (no traceback on any host).
    probe = core.run(
        [sys.executable, str(GUEST), "/tmp/sg-work", "/tmp/sg-export",
         "--manifest", "/tmp/sg-absent-manifest.json",
         "--consumer", "/tmp/sg-c", "--consumer-sha", "0" * 64,
         "--ko", "/tmp/sg-k", "--ko-sha", "0" * 64,
         "--mode", "q3", "--expect-release", "9.9.9-nope",
         "--baseline-lc", "/tmp/a", "--baseline-cp", "/tmp/b",
         "--baseline-lc-sha", "0" * 64, "--baseline-cp-sha", "0" * 64,
         "--c9-lc", "/tmp/c", "--c9-cp", "/tmp/d",
         "--c9-lc-sha", "0" * 64, "--c9-cp-sha", "0" * 64],
        timeout=30)
    ok = check("identity-guest-order",
               probe.returncode == 1
               and "FAIL" in probe.stderr
               and "Traceback" not in probe.stderr,
               probe.stderr.strip()[-160:]) and ok
    # The exec-entry marker lands before the manifest
    # read: a stall there still leaves one marker, while
    # the release gate above still fires first (the order
    # probe above pins that side).
    import contextlib
    import threading
    from types import SimpleNamespace
    from unittest import mock
    gated = SimpleNamespace(release=stress_guest.EXPECT_RELEASE)
    args = SimpleNamespace(
        consumer="/tmp/sg-c", consumer_sha="0" * 64,
        ko="/tmp/sg-k", ko_sha="0" * 64, mode="q3",
        expect_release="", manifest="/tmp/sg-absent-manifest.json",
        baseline_lc="/tmp/a", baseline_cp="/tmp/b",
        baseline_lc_sha="0" * 64, baseline_cp_sha="0" * 64,
        c9_lc="/tmp/c", c9_cp="/tmp/d",
        c9_lc_sha="0" * 64, c9_cp_sha="0" * 64)
    tmpdir = tempfile.mkdtemp(prefix="vmgate-exec-")
    try:
        logged = io.StringIO()
        with mock.patch.object(stress_guest.os, "uname",
                               return_value=gated):
            with contextlib.redirect_stderr(logged):
                try:
                    stress_guest.Gate(os.path.join(tmpdir, "work"),
                                      os.path.join(tmpdir, "export"),
                                      args)
                except SystemExit as exited:
                    code = exited.code
                else:
                    code = 0
        try:
            marks = [json.loads(line) for line in open(
                os.path.join(tmpdir, "work", "progress.log"))]
            mirrored = open(os.path.join(
                tmpdir, "export", "progress.log")).read()
        except OSError:
            marks, mirrored = [], ""
        ok = check("identity-exec-marker-before-manifest",
                   code == 1
                   and "cannot read run manifest" in logged.getvalue()
                   and marks
                   and marks[0]["step"] == "exec"
                   and marks[0]["status"] == "start"
                   and '"step": "exec"' in mirrored,
                   "%r %r" % (code, marks)) and ok
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    # A manifest read that blocks (a FIFO with no writer
    # yet) still leaves the marker while blocked.
    tmpdir = tempfile.mkdtemp(prefix="vmgate-stall-")
    fifo = os.path.join(tmpdir, "manifest.fifo")
    os.mkfifo(fifo)
    stalled = SimpleNamespace(**vars(args))
    stalled.manifest = fifo
    outcome = {}
    logged = io.StringIO()

    def construct():
        with contextlib.redirect_stderr(logged):
            try:
                stress_guest.Gate(os.path.join(tmpdir, "work"),
                                  os.path.join(tmpdir, "export"),
                                  stalled)
            except SystemExit as exited:
                outcome["code"] = exited.code
            except BaseException as exc:
                outcome["error"] = repr(exc)

    worker = threading.Thread(target=construct, daemon=True)
    with mock.patch.object(stress_guest.os, "uname",
                           return_value=gated):
        worker.start()
        deadline = time.monotonic() + 3
        marks = []
        while time.monotonic() < deadline:
            try:
                marks = [json.loads(line) for line in open(
                    os.path.join(tmpdir, "work", "progress.log"))]
            except (OSError, ValueError):
                marks = []
            if marks:
                break
            time.sleep(0.05)
        marker_while_blocked = (
            marks and marks[0]["step"] == "exec"
            and worker.is_alive())
        writer = os.open(fifo, os.O_WRONLY)
        try:
            os.write(writer, b"{")
        finally:
            os.close(writer)
        worker.join(timeout=5)
    shutil.rmtree(tmpdir, ignore_errors=True)
    ok = check("identity-exec-marker-stall",
               marker_while_blocked
               and not worker.is_alive()
               and outcome.get("code") == 1
               and "cannot read run manifest" in logged.getvalue()
               and "error" not in outcome,
               "%r %r" % (marks, outcome)) and ok
    return ok


# -- Unarmed self-test: q3 mode --------------------------------

def replay_window(tmp, tag, wire, ring, total, total_bytes):
    """Replay one wire window through the real consumer."""
    wire_path = os.path.join(tmp, "%s.wire" % tag)
    open(wire_path, "wb").write(wire)
    out = os.path.join(tmp, "%s.txt" % tag)
    proc = consumer_run(["--replay", wire_path, ring, out,
                         "--counts", "%d,%d,%d,%d,0,0"
                         % (total, total_bytes, total,
                            total_bytes)])
    if proc.returncode != 0:
        raise ValueError("replay %s failed: %s"
                         % (tag, proc.stdout.strip()[-200:]))
    return out


def skew_loss(src, dst):
    """Add one balanced submit loss to a window file."""
    order = ("observed", "badframe", "badrec", "cnt_obs",
             "cnt_obsb", "cnt_emit", "cnt_emitb", "cnt_fail",
             "cnt_flags", "rx", "dlv", "mal", "drop")
    skewed = []
    for line in open(src).read().split("\n"):
        if line.startswith("summary "):
            fields = dict(token.split("=", 1)
                          for token in line.split()[1:])
            fields["cnt_obs"] = str(int(fields["cnt_obs"]) + 1)
            fields["cnt_fail"] = str(int(fields["cnt_fail"]) + 1)
            line = "summary " + " ".join(
                "%s=%s" % (key, fields[key]) for key in order)
        skewed.append(line)
    open(dst, "w").write("\n".join(skewed))


def skew_release(src, dst, size, direction):
    """Rewrite kind=2 record size/dir; rebalance bytes.

    Generation and counters stay coherent: delivered
    bytes still equal the emitted aggregate, so only
    the release match key can refuse the skewed window.
    """
    lines = open(src).read().split("\n")
    delta = 0
    skewed = []
    for line in lines:
        if line.startswith("lc ") and "kind=2" in line:
            fixed = []
            for tok in line.split():
                if tok.startswith("size="):
                    delta += size - int(
                        tok.partition("=")[2])
                    tok = "size=%d" % size
                elif tok.startswith("dir="):
                    tok = "dir=%d" % direction
                fixed.append(tok)
            line = " ".join(fixed)
        skewed.append(line)
    out = []
    for line in skewed:
        if line.startswith("summary "):
            fixed = []
            for tok in line.split():
                key, _, val = tok.partition("=")
                if key in ("cnt_obsb", "cnt_emitb"):
                    tok = "%s=%d" % (key,
                                     int(val) + delta)
                fixed.append(tok)
            line = " ".join(fixed)
        out.append(line)
    open(dst, "w").write("\n".join(out))


def write_oracle_log(path, ops):
    """Write one scripted oracle dmesg log with ops ops.

    Module order: every op attempts once with its cycled
    size, succeeds, and syncs (op 1 twice); every mapping
    releases once; the completion line closes the script.
    A realistic dmesg prefix: the parser tolerates it.
    """
    from consume import LC_SIZES
    lines = []
    for i in range(ops):
        size = LC_SIZES[i % len(LC_SIZES)]
        direction = 2 if i % 2 else 1
        lines.append("mv-oracle: op=%d attempt requested=%d forced=0"
                     % (i, size))
        lines.append("mv-oracle: op=%d outcome=success mapping=%d "
                     "mapped=%d" % (i, i, size))
        syncs = 2 if i == 1 else 1
        for _ in range(syncs):
            lines.append("mv-oracle: op=%d mapping=%d sync dir=%d "
                         "len=%d for=device" % (i, i, direction,
                                                size))
    for i in range(ops):
        lines.append("mv-oracle: mapping=%d release "
                     "lifetime_ns=%d" % (i, 5000 + i))
    lines.append("mv-oracle: script complete ops=%d" % ops)
    with open(path, "w") as handle:
        for line in lines:
            handle.write("[    5.123456] %s\n" % line)


def synth_q3_leg(tmp, name, miss_unmaps=0):
    """One coherent synthetic q3 leg, replay-generated.

    miss_unmaps releases report gen 0 (misses): closure,
    conservation, and the scripted multisets still hold,
    so the leg passes with M == miss_unmaps.
    """
    from consume import scripted_expectation
    ops = core.P1_OPS
    want = scripted_expectation(ops, -1)
    # Multiset order for the wire (matches the
    # expectation exactly); op order for the log.
    sizes = [size for size, _dir, _ok in want["maps"]]
    dirs = [direction for _size, direction, _ok in want["maps"]]
    wire = b""
    seq = 0
    for i in range(ops):
        wire += core.encode_lc(core.LC_KIND_MAP, True, False,
                               dirs[i], seq, 1000 + seq,
                               sizes[i], i + 1)
        seq += 1
    for i in range(ops):
        gen = 0 if i < miss_unmaps else i + 1
        wire += core.encode_lc(2, True, True, dirs[i], seq,
                               3000 + seq, sizes[i], gen,
                               miss=(gen == 0))
        seq += 1
    lc_bytes = 2 * sum(sizes)
    lc = replay_window(tmp, "%s-p1-lc" % name, wire,
                       "mv_lifecycle", 2 * ops, lc_bytes)
    wire = b""
    seq = 0
    cp_bytes = 0
    for req, direction in want["syncs_dev"]:
        wire += core.encode_cp(1, 1, False, False, False,
                               direction, 4, seq, 1000 + seq,
                               req, 0)
        cp_bytes += req
        seq += 1
    for req, direction in want["syncs_cpu"]:
        wire += core.encode_cp(1, 0, False, False, False,
                               direction, 4, seq, 1000 + seq,
                               req, 0)
        cp_bytes += req
        seq += 1
    for todev, req, direction in want["bounces"]:
        wire += core.encode_cp(2, todev, True, False, False,
                               direction, 0, seq, 1000 + seq,
                               req, req)
        cp_bytes += req
        seq += 1
    cp = replay_window(tmp, "%s-p1-cp" % name, wire, "mv_copies",
                       seq, cp_bytes)
    oracle = os.path.join(tmp, "%s-p1-oracle.log" % name)
    write_oracle_log(oracle, ops)
    c0a = replay_window(
        tmp, "%s-c0a-lc" % name,
        core.encode_lc(1, True, False, 1, 0, 100, 512, 7)
        + core.encode_lc(2, True, True, 1, 1, 200, 512, 7),
        "mv_lifecycle", 2, 1024)
    # The held release is op 1's (size 1024, dir 2): the
    # unmap probe emits the call's direction on every
    # unmap record, including gen-0 misses, so an honest
    # held-across-attach release carries dir 2, not 1.
    c0b = replay_window(
        tmp, "%s-c0b-lc" % name,
        core.encode_lc(2, True, True, 2, 0, 100, 1024, 0,
                       miss=True),
        "mv_lifecycle", 1, 1024)
    # The 2-op control script, in module order: op 0 runs
    # and releases, op 1 syncs twice and stays held-open
    # until the rmmod exit-release, then the completion
    # and unload notes the parser tolerates.
    c0_lines = [
        "mv-oracle: op=0 attempt requested=512 forced=0",
        "mv-oracle: op=0 outcome=success mapping=0 mapped=512",
        "mv-oracle: op=0 mapping=0 sync dir=1 len=512 for=device",
        "mv-oracle: mapping=0 release lifetime_ns=5000",
        "mv-oracle: op=1 attempt requested=1024 forced=0",
        "mv-oracle: op=1 outcome=success mapping=1 mapped=1024",
        "mv-oracle: op=1 mapping=1 sync dir=2 len=1024 for=device",
        "mv-oracle: op=1 mapping=1 sync dir=2 len=1024 for=device",
        "mv-oracle: op=1 mapping=1 held-open",
        "mv-oracle: script complete ops=2",
        "mv-oracle: op=1 mapping=1 exit-release",
        "mv-oracle: mapping=1 release lifetime_ns=5001",
        "mv-oracle: unloaded",
    ]
    c0_log = os.path.join(tmp, "%s-c0-oracle.log" % name)
    with open(c0_log, "w") as handle:
        for line in c0_lines:
            handle.write("[    5.123456] %s\n" % line)
    controls = os.path.join(tmp, "%s-controls.json" % name)
    with open(controls, "w") as handle:
        handle.write(json.dumps({"op0_gen": 7, "held_gen_first": 0,
                                 "held_releases": 1}) + "\n")
    return {"%s-controls.json" % name: Path(controls),
            "%s-c0a-lc.txt" % name: Path(c0a),
            "%s-c0b-lc.txt" % name: Path(c0b),
            "%s-c0-oracle.log" % name: Path(c0_log),
            "%s-p1-lc.txt" % name: Path(lc),
            "%s-p1-cp.txt" % name: Path(cp),
            "%s-p1-oracle.log" % name: Path(oracle)}


def synth_full_leg(tmp, name):
    """One coherent synthetic full leg, replay-generated.

    Controls plus the quiet phase come from the q3 leg;
    the overlap phase is a small honest window: 100 maps
    plus 100 resolving unmaps against matching bpftrace
    counts, 50 syncs plus 50 bounces, a 2000-op oracle
    script, and sidecars proving the flood flowed inside
    the oracle window.
    """
    files = synth_q3_leg(tmp, name)
    wire = b""
    seq = 0
    for i in range(100):
        wire += core.encode_lc(core.LC_KIND_MAP, True, False,
                               1, seq, 1000 + seq, 512, i + 1)
        seq += 1
    for i in range(100):
        wire += core.encode_lc(2, True, True, 1, seq,
                               3000 + seq, 512, i + 1)
        seq += 1
    lc2 = replay_window(tmp, "%s-p2-lc" % name, wire,
                        "mv_lifecycle", 200, 200 * 512)
    wire = b""
    seq = 0
    cp_bytes = 0
    for _ in range(50):
        wire += core.encode_cp(1, 1, False, False, False,
                               1, 4, seq, 1000 + seq, 512, 0)
        cp_bytes += 512
        seq += 1
    for _ in range(50):
        wire += core.encode_cp(2, 1, True, False, False,
                               1, 0, seq, 1000 + seq,
                               1024, 1024)
        cp_bytes += 1024
        seq += 1
    cp2 = replay_window(tmp, "%s-p2-cp" % name, wire,
                        "mv_copies", seq, cp_bytes)
    oracle2 = os.path.join(tmp, "%s-p2-oracle.log" % name)
    write_oracle_log(oracle2, core.P2_OPS)
    bpf = os.path.join(tmp, "%s-bpftrace.txt" % name)
    with open(bpf, "w") as handle:
        handle.write("@maps: 100\n@unmaps: 100\n@bounces: 50\n")
    stats = os.path.join(tmp, "%s-blockstats.json" % name)
    with open(stats, "w") as handle:
        handle.write(json.dumps({"before": {"read_ios": 10},
                                 "after": {"read_ios": 60}})
                     + "\n")
    dd = os.path.join(tmp, "%s-dd.json" % name)
    with open(dd, "w") as handle:
        handle.write(json.dumps(
            {"cpu0": {"bytes": 128 * 16 * 65536,
                      "seconds": 0.1,
                      "start_ns": 100, "finish_ns": 200}})
                     + "\n")
    window = os.path.join(tmp, "%s-window.json" % name)
    with open(window, "w") as handle:
        handle.write(json.dumps({"start_ns": 150,
                                 "finish_ns": 250}) + "\n")
    files.update({
        "%s-p2-lc.txt" % name: Path(lc2),
        "%s-p2-cp.txt" % name: Path(cp2),
        "%s-p2-oracle.log" % name: Path(oracle2),
        "%s-bpftrace.txt" % name: Path(bpf),
        "%s-blockstats.json" % name: Path(stats),
        "%s-dd.json" % name: Path(dd),
        "%s-window.json" % name: Path(window)})
    return files


def self_test_q3_mode(tmp, pairs):
    """Q3 selection: legs judge without p2 files or comparison."""
    from types import SimpleNamespace
    ok = True
    argv = build_guest_argv(
        os.path.join(tmp, "inputs.json"),
        {"path": core.CONSUMER_RELEASE,
         "sha256": sha_file(core.CONSUMER_RELEASE)},
        pairs, "q3", core.EXPECT_RELEASE)
    flags = dict(zip(argv[4::2], argv[5::2]))
    ok = check("q3-guest-argv",
               flags.get("--mode") == "q3"
               and flags.get("--ko-sha") == guest_oracle.KO_SHA256
               and flags.get("--ko") == guest_oracle.FIXTURE_KO
               and flags.get("--expect-release") == core.EXPECT_RELEASE
               and flags.get("--c9-lc-sha") == core.C9_LC_SHA) and ok
    full = set(EXPORT_NAMES)
    q3 = set(EXPORT_NAMES_Q3)
    ok = check("q3-inventory", q3 < full
               and len(EXPORT_NAMES_Q3) == 17
               and "progress.log" in q3
               and not any("-p2-" in n or "bpftrace" in n
                           or n.endswith(("-dd.json", "-window.json",
                                          "-blockstats.json"))
                           for n in q3)) and ok
    ok = check("q3-full-untouched", len(EXPORT_NAMES) == 33
               and "progress.log" in full) and ok
    base = synth_q3_leg(tmp, "baseline")
    c9 = synth_q3_leg(tmp, "c9", miss_unmaps=50)
    bad, metrics = judge_q3_leg(base, "baseline", "syn-base")
    ok = check("q3-leg-pass", bad == []
               and metrics == {"M": 0, "D": 400},
               "; ".join(bad)) and ok
    bad, metrics = judge_q3_leg(c9, "c9", "syn-c9")
    ok = check("q3-leg-miss-pass", bad == []
               and metrics == {"M": 50, "D": 400},
               "; ".join(bad)) and ok
    # No p2 files exist anywhere above: touching the
    # overlap phase would raise KeyError, failing loudly.
    broken = dict(base)
    corrupt = os.path.join(tmp, "baseline-p1-oracle-broken.log")
    lines = open(str(base["baseline-p1-oracle.log"])).read().split(
        "\n")
    open(corrupt, "w").write("\n".join(
        line for line in lines if "script complete" not in line))
    broken["baseline-p1-oracle.log"] = Path(corrupt)
    bad, _ = judge_q3_leg(broken, "baseline", "syn-broken")
    ok = check("q3-oracle-tripwire",
               any("script complete" in r for r in bad),
               "; ".join(bad)) and ok
    garbage = dict(base)
    trash = os.path.join(tmp, "baseline-c0b-trash.txt")
    open(trash, "w").write("not a consume window\n")
    garbage["baseline-c0b-lc.txt"] = Path(trash)
    bad, _ = judge_q3_leg(garbage, "baseline", "syn-trash")
    ok = check("q3-controls-tripwire", bad != [],
               "; ".join(bad)) and ok
    # A balanced loss in the second control window still
    # conserves, so only the loss-free rule refuses it.
    lossy = dict(base)
    c0b_loss = os.path.join(tmp, "baseline-c0b-lossy.txt")
    skew_loss(str(base["baseline-c0b-lc.txt"]), c0b_loss)
    lossy["baseline-c0b-lc.txt"] = Path(c0b_loss)
    events, summary = parse_consume_file(c0b_loss)
    bad, _ = judge_q3_leg(lossy, "baseline", "syn-c0-loss")
    ok = check("q3-controls-loss-refuses",
               check_conservation(events, summary,
                                  "skew-c0b") == []
               and any("cnt_fail" in reason for reason in bad),
               "; ".join(bad)) and ok
    # Same for a balanced loss in the quiet copy window.
    quiet_lossy = dict(base)
    cp_loss = os.path.join(tmp, "baseline-p1-cp-lossy.txt")
    skew_loss(str(base["baseline-p1-cp.txt"]), cp_loss)
    quiet_lossy["baseline-p1-cp.txt"] = Path(cp_loss)
    events, summary = parse_consume_file(cp_loss)
    bad, _ = judge_q3_leg(quiet_lossy, "baseline",
                           "syn-quiet-loss")
    ok = check("q3-quiet-loss-refuses",
               check_conservation(events, summary,
                                  "skew-quiet") == []
               and any("cnt_fail" in reason for reason in bad),
               "; ".join(bad)) and ok
    # A blanked control oracle log refuses: the control
    # record is mandatory evidence, not optional.
    blanked = dict(base)
    c0_blank = os.path.join(tmp, "baseline-c0-blank.log")
    open(c0_blank, "w").write("")
    blanked["baseline-c0-oracle.log"] = Path(c0_blank)
    bad, _ = judge_q3_leg(blanked, "baseline", "syn-blank")
    ok = check("q3-blanked-control-log-refuses",
               any("script complete" in reason
                   for reason in bad),
               "; ".join(bad)) and ok
    # The q3 receipt passes despite a higher candidate
    # ratio (50/400 vs 0/400): no comparison runs.
    export = Path(tmp) / "q3-export"
    export.mkdir()
    files = {}
    files.update(base)
    files.update(c9)
    ident = {"release": core.EXPECT_RELEASE,
             "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
             "digests": {"ko": guest_oracle.KO_SHA256}}
    for name, doc in (("identity.json", ident),
                      ("input-verify.json", {"digests": {}})):
        path = Path(tmp) / ("q3-%s" % name)
        path.write_text(json.dumps(doc) + "\n")
        files[name] = path
    progress = Path(tmp) / "q3-progress.log"
    progress.write_text('{"step": "boot", "status": "ok"}\n')
    files["progress.log"] = progress
    for name in EXPORT_NAMES_Q3:
        shutil.copy2(str(files[name]), export / name)
        digest = sha_file(export / name)
        (export / ("%s.sha256" % name)).write_text(
            "%s  %s\n" % (digest, name))
    verified = {"files": {name: export / name
                          for name in EXPORT_NAMES_Q3}}
    manifest = {"runner_commit": "self-test",
                "consumer": {"binary_sha256": "self-test"},
                "oracle": {"ko_sha256": guest_oracle.KO_SHA256}}
    manifest_path = Path(tmp) / "q3-inputs.json"
    manifest_path.write_text(json.dumps(manifest) + "\n")
    boot_tmp = Path(tmp) / "q3-boot"
    boot_tmp.mkdir()
    for name in ("boot.json", "guest.stdout", "guest.stderr",
                 "guest.exit"):
        (boot_tmp / name).write_text("self-test\n")
    args = SimpleNamespace(out=str(Path(tmp) / "q3-out"),
                           keep=False)
    rc = judge_q3_receipt(args, manifest_path, manifest,
                          verified, ident, EXPORT_NAMES_Q3,
                          export, boot_tmp)
    receipt = json.loads(
        (Path(tmp) / "q3-out" / "host-verdict.json").read_text())
    ok = check("q3-receipt-no-compare",
               rc == 0 and receipt["verdict"] == "PASS"
               and receipt["mode"] == "q3"
               and receipt["comparison"]["verdict"] == "NOT_RUN"
               and receipt["c9"]["metrics"] == {"M": 50, "D": 400},
               "%r" % (receipt,)) and ok
    # A release that keeps its generation but mutates
    # size and direction, with rebalanced counters, must
    # refuse: generation alone never binds a release.
    skew = dict(base)
    c0a_skew = os.path.join(tmp, "baseline-c0a-skew.txt")
    skew_release(str(base["baseline-c0a-lc.txt"]), c0a_skew,
                 1024, 2)
    skew["baseline-c0a-lc.txt"] = Path(c0a_skew)
    events, summary = parse_consume_file(c0a_skew)
    bad, _ = judge_q3_leg(skew, "baseline", "syn-c0-skew")
    ok = check("q3-release-skew-refuses",
               check_conservation(events, summary,
                                  "skew-c0a") == []
               and any("contradicts" in reason
                       for reason in bad),
               "; ".join(bad)) and ok
    # Each mutated field refuses on its own: size-only
    # with rebalanced bytes, and direction-only with
    # counters untouched.
    size_only = dict(base)
    c0a_size = os.path.join(tmp, "baseline-c0a-size.txt")
    skew_release(str(base["baseline-c0a-lc.txt"]), c0a_size,
                 1024, 1)
    size_only["baseline-c0a-lc.txt"] = Path(c0a_size)
    events, summary = parse_consume_file(c0a_size)
    bad, _ = judge_q3_leg(size_only, "baseline",
                           "syn-c0-size")
    ok = check("q3-release-size-only-refuses",
               check_conservation(events, summary,
                                  "skew-c0a-size") == []
               and any("contradicts" in reason
                       for reason in bad),
               "; ".join(bad)) and ok
    dir_only = dict(base)
    c0a_dir = os.path.join(tmp, "baseline-c0a-dir.txt")
    skew_release(str(base["baseline-c0a-lc.txt"]), c0a_dir,
                 512, 2)
    dir_only["baseline-c0a-lc.txt"] = Path(c0a_dir)
    events, summary = parse_consume_file(c0a_dir)
    bad, _ = judge_q3_leg(dir_only, "baseline",
                           "syn-c0-dir")
    ok = check("q3-release-dir-only-refuses",
               check_conservation(events, summary,
                                  "skew-c0a-dir") == []
               and any("contradicts" in reason
                       for reason in bad),
               "; ".join(bad)) and ok
    # The held release binds its direction too: op 1's
    # release with any other direction is not op 1's.
    held_skew = dict(base)
    c0b_skew = os.path.join(tmp, "baseline-c0b-skew.txt")
    skew_release(str(base["baseline-c0b-lc.txt"]), c0b_skew,
                 1024, 1)
    held_skew["baseline-c0b-lc.txt"] = Path(c0b_skew)
    events, summary = parse_consume_file(c0b_skew)
    bad, _ = judge_q3_leg(held_skew, "baseline",
                           "syn-c0-held")
    ok = check("q3-held-dir-refuses",
               check_conservation(events, summary,
                                  "skew-c0b") == []
               and any("no held op-1" in reason
                       for reason in bad),
               "; ".join(bad)) and ok
    # The shared release key, pinned directly: honest
    # pairs pass with the op-0 gen, each mutation refuses.
    first = [{"kind": 1, "size": 512, "dir": 1, "gen": 7},
             {"kind": 2, "size": 512, "dir": 1, "gen": 7}]
    second = [{"kind": 2, "size": 1024, "dir": 2, "gen": 0}]
    rel_bad, gen0 = check_control_releases(
        first, second, "unit")
    unit_ok = rel_bad == [] and gen0 == 7
    rel_bad, _ = check_control_releases(
        [{"kind": 1, "size": 512, "dir": 1, "gen": 7},
         {"kind": 2, "size": 1024, "dir": 2, "gen": 7}],
        second, "unit")
    unit_ok = unit_ok and any("contradicts" in reason
                              for reason in rel_bad)
    rel_bad, _ = check_control_releases(
        first, [{"kind": 2, "size": 1024, "dir": 1,
                 "gen": 0}], "unit")
    unit_ok = unit_ok and any("no held op-1" in reason
                              for reason in rel_bad)
    ok = check("q3-control-releases-unit", unit_ok) and ok
    return ok


def self_test_full_mode(tmp):
    """Full-mode judge: honest legs pass, lossy legs refuse."""
    ok = True
    base = synth_full_leg(tmp, "baseline")
    bad, metrics = judge_leg(base, "baseline", "syn-full")
    ok = check("full-leg-pass", bad == []
               and metrics["M"] == 0 and metrics["D"] == 200,
               "; ".join(bad)) and ok
    # A balanced loss in the second control window still
    # conserves, so only the loss-free rule refuses it.
    lossy = dict(base)
    c0b_loss = os.path.join(tmp, "baseline-c0b-lossy.txt")
    skew_loss(str(base["baseline-c0b-lc.txt"]), c0b_loss)
    lossy["baseline-c0b-lc.txt"] = Path(c0b_loss)
    events, summary = parse_consume_file(c0b_loss)
    bad, _ = judge_leg(lossy, "baseline", "syn-full-c0-loss")
    ok = check("full-controls-loss-refuses",
               check_conservation(events, summary,
                                  "skew-full-c0b") == []
               and any("cnt_fail" in reason for reason in bad),
               "; ".join(bad)) and ok
    # Same for a balanced loss in the quiet copy window.
    quiet_lossy = dict(base)
    cp_loss = os.path.join(tmp, "baseline-p1-cp-lossy.txt")
    skew_loss(str(base["baseline-p1-cp.txt"]), cp_loss)
    quiet_lossy["baseline-p1-cp.txt"] = Path(cp_loss)
    events, summary = parse_consume_file(cp_loss)
    bad, _ = judge_leg(quiet_lossy, "baseline",
                        "syn-full-quiet-loss")
    ok = check("full-quiet-loss-refuses",
               check_conservation(events, summary,
                                  "skew-full-quiet") == []
               and any("cnt_fail" in reason for reason in bad),
               "; ".join(bad)) and ok
    # A blanked control oracle log refuses: the control
    # record is mandatory evidence, not optional.
    blanked = dict(base)
    c0_blank = os.path.join(tmp, "baseline-c0-blank.log")
    open(c0_blank, "w").write("")
    blanked["baseline-c0-oracle.log"] = Path(c0_blank)
    bad, _ = judge_leg(blanked, "baseline", "syn-full-blank")
    ok = check("full-blanked-control-log-refuses",
               any("script complete" in reason
                   for reason in bad),
               "; ".join(bad)) and ok
    # Same release-mutation class through the full-mode
    # judge: the shared key refuses there too.
    skew = dict(base)
    c0a_skew = os.path.join(tmp, "full-c0a-skew.txt")
    skew_release(str(base["baseline-c0a-lc.txt"]), c0a_skew,
                 1024, 2)
    skew["baseline-c0a-lc.txt"] = Path(c0a_skew)
    bad, _ = judge_leg(skew, "baseline", "syn-full-skew")
    ok = check("full-release-skew-refuses",
               any("contradicts" in reason
                   for reason in bad),
               "; ".join(bad)) and ok
    return ok


def run_self_test(work=None):
    """Full offline suite: proofs plus unarmed checks. No boot."""
    print("stress-consumer self-test (unarmed, offline)")
    tmp = work or tempfile.mkdtemp(prefix="vmgate-stress-")
    os.makedirs(tmp, exist_ok=True)
    keep = work is not None
    ok = True
    try:
        ok = self_test_pins() and ok
        ok = self_test_gate_constants() and ok
        ok = self_test_consumer_build() and ok
        try:
            pairs = core.materialize(
                str(REPO), os.path.join(tmp, "pairs"))
        except ValueError as exc:
            ok = check("materialize", False, str(exc)) and ok
            pairs = None
        if pairs is not None:
            ok = self_test_layouts(tmp, pairs) and ok
            ok = self_test_wrong_pair(pairs) and ok
            ok = self_test_manifest(tmp, pairs) and ok
            ok = self_test_guest_oracle(tmp, pairs) and ok
            ok = self_test_candidate_flags(tmp, pairs) and ok
        ok = self_test_replay(tmp) and ok
        ok = self_test_malformed(tmp) and ok
        ok = self_test_cargo_unit() and ok
        ok = self_test_host_btf() and ok
        ok = self_test_judge() and ok
        ok = self_test_compare() and ok
        ok = self_test_forensics(tmp) and ok
        ok = self_test_identity() and ok
        if pairs is not None:
            ok = self_test_q3_mode(tmp, pairs) and ok
        ok = self_test_full_mode(tmp) and ok
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print("stress-consumer self-test: %s" % ("PASS" if ok else "FAIL"))
    return ok


# -- Armed run (prepared; needs the live-VM lease) ---------------

def parse_inputs(values):
    """Parse --inputs NAME=LC,CP into {name: (lc, cp)}.

    Only the two pinned names resolve; anything else refuses.
    Byte identity is verified against the pins separately, so a
    path rebind can never smuggle different bytes.
    """
    pairs = {}
    for value in values:
        name, sep, rest = value.partition("=")
        if not sep or name not in ("baseline", "c9"):
            raise ValueError("bad --inputs %r: want NAME=LC,CP "
                             "with NAME baseline or c9" % value)
        if name in pairs:
            raise ValueError("duplicate --inputs %s" % name)
        lc, comma, cp = rest.partition(",")
        if not comma or not lc or not cp or "," in cp:
            raise ValueError("bad --inputs %r: want NAME=LC,CP" % value)
        pairs[name] = (lc, cp)
    return pairs


def armed_preflight():
    """Resolve vng + harness versions; armed failures are fatal."""
    from test_attempt_capture import find_vng, gate_prefix
    from harness_env import check_harness_versions
    vng = find_vng()
    if not vng:
        print("FAIL vm-stress: armed but vng missing")
        return None
    try:
        harness = check_harness_versions(vng)
    except ValueError as exc:
        print("FAIL vm-stress: armed but %s" % (exc,))
        return None
    try:
        prefix, _env = gate_prefix()
    except Exception as exc:  # pytest.skip/fail raise here
        print("FAIL vm-stress: armed but %s" % (exc,))
        return None
    return {"vng": vng, "harness": harness, "prefix": prefix}


def verify_exports(export, names=None):
    """Exact inventory + sidecar check; returns {ok, files, reasons}."""
    names = EXPORT_NAMES if names is None else names
    result = {"ok": False, "files": {}, "reasons": []}
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        result["reasons"].append("export unreadable: %s" % (exc,))
        return result
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


def parse_bpftrace(text):
    """Parse the three attach-point counters, all mandatory."""
    import re
    out = {}
    for name in ("maps", "unmaps", "bounces"):
        match = re.search(r"@%s:\s+(\d+)" % name, text)
        if not match:
            raise ValueError("bpftrace count %r missing" % name)
        out[name] = int(match.group(1))
    return out


def check_loss_free(summary, tag):
    """Control/quiet windows must be loss-free.

    Conservation tolerates a balanced submit loss (the
    books still add up); the adapter gate does not: any
    reported loss refuses the window, balanced or not.
    """
    if summary.get("cnt_fail"):
        return ["%s: submit loss cnt_fail=%d"
                % (tag, summary["cnt_fail"])]
    return []


def check_control_releases(first, second, tag):
    """Match control releases by generation, size, dir.

    The control script is fully pinned: op 0 (size 512,
    dir 1) maps and releases under the first consumer,
    op 1 (size 1024, dir 2) maps there, stays held, and
    releases under the second. Generation alone cannot
    bind a release: a mutated size or direction with
    rebalanced counters would still pass. The op-0
    release must therefore repeat its map's full record
    (generation, size, direction), and the held release
    must repeat the scripted op-1 record with gen 0
    (the second consumer never saw the map, so any
    known gen there would be fabricated; the unmap
    probe emits the call's direction on every unmap,
    misses included). Returns (reasons, op0_gen).
    """
    bad = []
    known = [e for e in first if e["kind"] == 1
             and e["size"] == 512 and e["dir"] == 1
             and e["gen"] != 0]
    if not known:
        bad.append("%s: no post-attach known map" % tag)
        gen0 = None
    else:
        gen0 = known[0]["gen"]
        same_gen = [e for e in first if e["kind"] == 2
                    and e["gen"] == gen0]
        if not same_gen:
            bad.append("%s: post-attach release lost gen %d"
                       % (tag, gen0))
        elif not any(e["size"] == 512 and e["dir"] == 1
                     for e in same_gen):
            bad.append("%s: post-attach release gen %d "
                       "contradicts op 0 size/dir"
                       % (tag, gen0))
    held = [e for e in second if e["kind"] == 2
            and e["size"] == 1024 and e["dir"] == 2]
    if not held:
        bad.append("%s: no held op-1 release (size/dir)"
                   % tag)
    elif not any(e["gen"] == 0 for e in held):
        bad.append("%s: held-across-attach release not gen 0"
                   % tag)
    return sorted(bad), gen0


def judge_controls(files, name, tag):
    """Host re-derivation of one leg's controls.

    Re-derived from the raw control windows; guest-side
    JSON is cross-checked, never trusted. Both control
    windows must conserve and be loss-free, and the
    2-op control oracle record is mandatory evidence: a
    blanked or short control log refuses the leg.
    """
    bad = []
    try:
        first, first_sum = parse_consume_file(
            str(files["%s-c0a-lc.txt" % name]))
        second, second_sum = parse_consume_file(
            str(files["%s-c0b-lc.txt" % name]))
        ops_log, releases, complete = parse_oracle_log(
            str(files["%s-c0-oracle.log" % name]))
    except ValueError as exc:
        return (["%s: control files unparsable: %s" % (tag, exc)], {})
    bad += check_conservation(first, first_sum, tag + "-c0a")
    bad += check_conservation(second, second_sum, tag + "-c0b")
    bad += check_loss_free(first_sum, tag + "-c0a")
    bad += check_loss_free(second_sum, tag + "-c0b")
    bad += check_oracle_script(ops_log, releases, complete,
                               2, -1, tag + "-c0")
    rel_bad, op0_gen = check_control_releases(first, second, tag)
    bad += rel_bad
    controls = json.loads(files["%s-controls.json" % name].read_text())
    if controls.get("op0_gen") != op0_gen:
        bad.append("%s: guest controls.json disagrees" % tag)
    return sorted(bad), {}


def judge_quiet(files, name, tag):
    """Host re-derivation of one leg's quiet phase.

    Exact scripted expectations over the 200-op oracle log
    plus the lifecycle/copy multisets; returns
    (reasons, metrics) with the retained M/D mix.
    """
    bad = []
    try:
        lc, lc_sum = parse_consume_file(
            str(files["%s-p1-lc.txt" % name]))
        cp, cp_sum = parse_consume_file(
            str(files["%s-p1-cp.txt" % name]))
        ops_log, releases, complete = parse_oracle_log(
            str(files["%s-p1-oracle.log" % name]))
    except ValueError as exc:
        return (["%s: p1 files unparsable: %s" % (tag, exc)], {})
    bad += check_conservation(lc, lc_sum, tag + "-p1-lc")
    bad += check_conservation(cp, cp_sum, tag + "-p1-cp")
    bad += check_loss_free(lc_sum, tag + "-p1-lc")
    bad += check_loss_free(cp_sum, tag + "-p1-cp")
    bad += check_identity_closure(lc, tag + "-p1-lc")
    bad += check_oracle_script(ops_log, releases, complete,
                               core.P1_OPS, -1, tag + "-p1")
    bad += compare_scripted(lc, cp, core.P1_OPS, -1, tag + "-p1")
    mix = core.retained_breakdown(lc)
    return sorted(bad), {"M": mix["M"], "D": mix["D"]}


def judge_q3_leg(files, name, tag):
    """Host re-derivation of one adapter-gate leg.

    Controls plus the quiet phase only; the overlap
    phase and the pair comparison stay out.
    """
    bad, _ = judge_controls(files, name, tag)
    quiet_bad, metrics = judge_quiet(files, name, tag)
    return sorted(bad + quiet_bad), metrics


def judge_leg(files, name, tag):
    """Host re-derivation of one leg; returns (reasons, metrics).

    Controls, quiet phase, and overlap phase are all re-judged
    here from the exported observations; guest-side JSON is
    cross-checked, never trusted.
    """
    bad = []
    # Controls: re-derive from the raw control windows.
    try:
        first, first_sum = parse_consume_file(
            str(files["%s-c0a-lc.txt" % name]))
        second, second_sum = parse_consume_file(
            str(files["%s-c0b-lc.txt" % name]))
        ops_log, releases, complete = parse_oracle_log(
            str(files["%s-c0-oracle.log" % name]))
    except ValueError as exc:
        return (["%s: control files unparsable: %s" % (tag, exc)], {})
    bad += check_conservation(first, first_sum, tag + "-c0a")
    bad += check_conservation(second, second_sum, tag + "-c0b")
    bad += check_loss_free(first_sum, tag + "-c0a")
    bad += check_loss_free(second_sum, tag + "-c0b")
    bad += check_oracle_script(ops_log, releases, complete,
                               2, -1, tag + "-c0")
    rel_bad, op0_gen = check_control_releases(first, second, tag)
    bad += rel_bad
    controls = json.loads(files["%s-controls.json" % name].read_text())
    if controls.get("op0_gen") != op0_gen:
        bad.append("%s: guest controls.json disagrees" % tag)
    # Quiet phase: exact scripted expectations.
    try:
        lc, lc_sum = parse_consume_file(
            str(files["%s-p1-lc.txt" % name]))
        cp, cp_sum = parse_consume_file(
            str(files["%s-p1-cp.txt" % name]))
        ops_log, releases, complete = parse_oracle_log(
            str(files["%s-p1-oracle.log" % name]))
    except ValueError as exc:
        return (sorted(bad + ["%s: p1 files unparsable: %s" % (tag, exc)]),
                {})
    bad += check_conservation(lc, lc_sum, tag + "-p1-lc")
    bad += check_conservation(cp, cp_sum, tag + "-p1-cp")
    bad += check_loss_free(lc_sum, tag + "-p1-lc")
    bad += check_loss_free(cp_sum, tag + "-p1-cp")
    bad += check_identity_closure(lc, tag + "-p1-lc")
    bad += check_oracle_script(ops_log, releases, complete,
                               core.P1_OPS, -1, tag + "-p1")
    bad += compare_scripted(lc, cp, core.P1_OPS, -1, tag + "-p1")
    # Overlap phase: judge shapes plus oracle + overlap proof.
    try:
        lc2, lc2_sum = parse_consume_file(
            str(files["%s-p2-lc.txt" % name]))
        cp2, cp2_sum = parse_consume_file(
            str(files["%s-p2-cp.txt" % name]))
        ops2, releases2, complete2 = parse_oracle_log(
            str(files["%s-p2-oracle.log" % name]))
    except ValueError as exc:
        return (sorted(bad + ["%s: p2 files unparsable: %s" % (tag, exc)]),
                {})
    stats = json.loads(files["%s-blockstats.json" % name].read_text())
    try:
        bpf = parse_bpftrace(files["%s-bpftrace.txt" % name].read_text())
    except ValueError as exc:
        return (sorted(bad + ["%s: %s" % (tag, exc)]), {})
    reasons2, metrics = core.judge_phase2(
        lc2, lc2_sum, cp2, cp2_sum, bpf, stats, tag + "-p2")
    bad += reasons2
    bad += check_oracle_script(ops2, releases2, complete2,
                               core.P2_OPS, -1, tag + "-p2")
    legs = json.loads(files["%s-dd.json" % name].read_text())
    window = json.loads(files["%s-window.json" % name].read_text())
    want_bytes = 128 * 16 * 65536
    for leg_name, leg in sorted(legs.items()):
        if leg.get("bytes") != want_bytes:
            bad.append("%s: %s completed %r bytes, want %d"
                       % (tag, leg_name, leg.get("bytes"), want_bytes))
        if not (leg["start_ns"] < window["finish_ns"]
                and window["start_ns"] < leg["finish_ns"]):
            bad.append("%s: %s never overlapped oracle traffic"
                       % (tag, leg_name))
    return sorted(bad), metrics


def check_host_identity(ident):
    """Recheck the exported guest identity host-side.

    Returns a reason list (empty ok): the booted release
    and the live BTF bytes must equal the pinned
    expectations, independent of the guest's own gate.
    """
    bad = []
    if ident.get("release") != core.EXPECT_RELEASE:
        bad.append("guest booted release %r, expected %r"
                   % (ident.get("release"), core.EXPECT_RELEASE))
    if ident.get("btf_sha256") != guest_oracle.GUEST_BTF_SHA256:
        bad.append("guest live BTF differs from the pinned bytes")
    if ident.get("digests", {}).get("ko") != guest_oracle.KO_SHA256:
        bad.append("guest measured oracle bytes differ from "
                   "the pinned fixture")
    return bad


def armed_run(args):
    """Armed stress pair: one pinned boot, baseline then c9."""
    if os.environ.get(ARM_ENV) != "1":
        print("FAIL vm-stress: armed run needs %s=1" % ARM_ENV)
        return 2
    if not args.out:
        print("FAIL vm-stress: armed needs --out")
        return 2
    if not getattr(args, "bundle", "") or not getattr(args, "candidate", ""):
        print("FAIL vm-stress: armed needs --bundle and --candidate")
        return 2
    if getattr(args, "expect_release", "") not in (
            "", core.EXPECT_RELEASE):
        print("FAIL vm-stress: conflicting --expect-release %r" % (
            args.expect_release,))
        return 2
    if getattr(args, "mode", "full") not in ("full", "q3"):
        print("FAIL vm-stress: bad --mode %r (want full or q3)" % (
            args.mode,))
        return 2
    try:
        rebind = parse_inputs(args.inputs)
    except ValueError as exc:
        print("FAIL vm-stress: %s" % exc)
        return 2
    flight = armed_preflight()
    if flight is None:
        return 1
    work = Path(tempfile.mkdtemp(prefix="vmgate-stress-"))
    try:
        pairs = core.materialize(str(REPO), str(work / "pairs"))
        for name, (lc, cp) in rebind.items():
            pairs[name] = {"lc": {"path": lc,
                                  "sha256": sha_file(lc)},
                           "cp": {"path": cp,
                                  "sha256": sha_file(cp)}}
    except (ValueError, OSError) as exc:
        print("FAIL vm-stress: inputs refused: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    try:
        candidate = core.load_candidate_binding(
            str(REPO), args.candidate, args.bundle)
        built = core.build_consumer()
        oracle = core.oracle_run_binding(str(REPO))
        commit = core.git_head(str(REPO))
    except (ValueError, OSError) as exc:
        print("FAIL vm-stress: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    manifest_path = work / "inputs.json"
    manifest = core.write_input_manifest(
        str(manifest_path), pairs, candidate,
        {"sha256": built["sha256"], "build": built["build"]},
        oracle, sys.argv, commit)
    reasons = core.verify_input_manifest(manifest, built["path"])
    if reasons:
        print("FAIL vm-stress: %s" % "; ".join(reasons))
        shutil.rmtree(work, ignore_errors=True)
        return 1
    lock_dir = REPO / "build" / "vm"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("FAIL vm-stress: lock dir failed: %s" % (exc,))
        shutil.rmtree(work, ignore_errors=True)
        return 1
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        print("FAIL vm-stress: VM suite lease already owned; "
              "one live executor at a time")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    try:
        # The guest-targeted fixture is already verified by
        # the run binding above; no host-kernel build runs.
        guest_oracle.verify_fixture()
    except (ValueError, OSError) as exc:
        print("FAIL vm-stress: oracle fixture refused: %s" % (exc,))
        return 1
    try:
        return armed_boot(args, pairs, manifest_path, manifest,
                          built, flight, work)
    except Exception as exc:
        print("FAIL vm-stress: armed but %s" % (exc,))
        return 1
    finally:
        lease.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("vm-stress: work kept at %s" % (work,))


def snapshot_partial_export(export, tmp):
    """Copy whatever the guest checkpointed before dying.

    Progress markers, phase checkpoints, abort records,
    and timeout partials survive here even when the boot
    never completes; an empty export snapshots empty.
    """
    dst = tmp / "partial-export"
    dst.mkdir(exist_ok=True)
    try:
        names = sorted(p.name for p in export.iterdir())
    except OSError:
        names = []
    for name in names:
        try:
            shutil.copy2(export / name, dst / name)
        except OSError:
            pass
    return names


def build_guest_argv(manifest_path, built, pairs, mode,
                     expect_release):
    """Guest command line for one boot (host-tested wiring)."""
    return [sys.executable, str(GUEST), "/tmp/vmgate-work",
            "/tmp/export",
            "--manifest", str(manifest_path),
            "--consumer", built["path"],
            "--consumer-sha", built["sha256"],
            "--ko", guest_oracle.FIXTURE_KO,
            "--ko-sha", guest_oracle.KO_SHA256,
            "--mode", mode,
            "--expect-release", expect_release,
            "--baseline-lc", pairs["baseline"]["lc"]["path"],
            "--baseline-cp", pairs["baseline"]["cp"]["path"],
            "--baseline-lc-sha",
            pairs["baseline"]["lc"]["sha256"],
            "--baseline-cp-sha",
            pairs["baseline"]["cp"]["sha256"],
            "--c9-lc", pairs["c9"]["lc"]["path"],
            "--c9-cp", pairs["c9"]["cp"]["path"],
            "--c9-lc-sha", pairs["c9"]["lc"]["sha256"],
            "--c9-cp-sha", pairs["c9"]["cp"]["sha256"]]


def armed_boot(args, pairs, manifest_path, manifest, built,
               flight, work):
    """Boot once, run both legs in-guest, judge host-side."""
    from vm_process import run_owned_guest
    mode = getattr(args, "mode", "full")
    names = EXPORT_NAMES_Q3 if mode == "q3" else EXPORT_NAMES
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-stress-boot-"))
    export = tmp / "export"
    export.mkdir()
    guest_argv = build_guest_argv(
        manifest_path, built, pairs, mode,
        getattr(args, "expect_release", ""))
    cmd = flight["prefix"] + ["--run"]
    if args.kver:
        cmd += [args.kver]
    cmd += ["-m", "6G",
            "--append", "swiotlb=force",
            "--rwdir=/tmp/export=%s" % (export,),
            "--exec", shlex.join(guest_argv)]
    (tmp / "boot.json").write_text(json.dumps(
        {"cmd": cmd, "manifest": manifest,
         "harness": flight["harness"]},
        indent=2, sort_keys=True) + "\n")
    try:
        proc = run_owned_guest(cmd, timeout=args.timeout)
    except subprocess.TimeoutExpired as exc:
        (tmp / "guest.stdout").write_text(exc.stdout or "")
        (tmp / "guest.stderr").write_text(exc.stderr or "")
        (tmp / "guest.exit").write_text("timeout")
        kept = snapshot_partial_export(export, tmp)
        (tmp / "timeout.json").write_text(json.dumps(
            {"status": "timeout", "after_s": args.timeout,
             "cleanup": "owned process group terminated",
             "partial_export": kept},
            indent=2, sort_keys=True) + "\n")
        print("FAIL vm-stress: guest timed out after %ds; "
              "artifacts kept at %s" % (args.timeout, tmp))
        return 1
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        snapshot_partial_export(export, tmp)
        print("FAIL vm-stress: guest exit %d; artifacts kept at %s"
              % (proc.returncode, tmp))
        return 1
    verified = verify_exports(export, names)
    if not verified["ok"]:
        snapshot_partial_export(export, tmp)
        print("FAIL vm-stress: %s; artifacts kept at %s"
              % ("; ".join(verified["reasons"]), tmp))
        return 1
    ident = json.loads(verified["files"]["identity.json"].read_text())
    ident_bad = check_host_identity(ident)
    if ident_bad:
        print("FAIL vm-stress: %s; artifacts kept at %s"
              % ("; ".join(ident_bad), tmp))
        return 1
    if mode == "q3":
        return judge_q3_receipt(args, manifest_path, manifest,
                                verified, ident, names, export, tmp)
    base_bad, base_metrics = judge_leg(verified["files"], "baseline",
                                       "stress-base")
    c9_bad, c9_metrics = judge_leg(verified["files"], "c9", "stress-c9")
    base = {"M": base_metrics.get("M", 0), "D": base_metrics.get("D", 0),
            "complete": not base_bad}
    c9 = {"M": c9_metrics.get("M", 0), "D": c9_metrics.get("D", 0),
          "complete": not c9_bad}
    verdict, cmp_reasons, detail = core.compare_pairs(base, c9,
                                                      "stress-compare")
    reasons = (["baseline: %s" % r for r in base_bad]
               + ["c9: %s" % r for r in c9_bad]
               + cmp_reasons)
    host_verdict = "PASS" if verdict == "PASS" and not reasons else (
        "BLOCKED" if verdict == "BLOCKED" else "FAIL")
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        for name in EXPORT_NAMES:
            shutil.copy2(verified["files"][name], out / name)
            shutil.copy2(export / ("%s.sha256" % name),
                         out / ("%s.sha256" % name))
        shutil.copy2(manifest_path, out / "inputs.json")
        for name in ("boot.json", "guest.stdout",
                     "guest.stderr", "guest.exit"):
            shutil.copy2(tmp / name, out / ("host-%s" % name))
        (out / "host-verdict.json").write_text(json.dumps(
            {"verdict": host_verdict, "reasons": reasons,
             "mode": mode,
             "comparison": {"verdict": verdict, "detail": detail},
             "baseline": {"reasons": base_bad,
                          "metrics": base_metrics},
             "c9": {"reasons": c9_bad, "metrics": c9_metrics},
             "identity": ident,
             "runner_commit": manifest["runner_commit"],
             "consumer": manifest["consumer"],
             "oracle": manifest["oracle"]},
            indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        print("FAIL vm-stress: receipt failed (%s); artifacts kept "
              "at %s" % (exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-stress: guest tmp kept at %s" % (tmp,))
    if host_verdict != "PASS":
        print("FAIL vm-stress %s: %s"
              % (host_verdict, "; ".join(reasons)))
        return 1
    print("ok vm-stress PASS (%s)" % (out,))
    print("ok vm-stress base M/D=%d/%d c9 M/D=%d/%d" % (
        base["M"], base["D"], c9["M"], c9["D"]))
    return 0


def judge_q3_receipt(args, manifest_path, manifest, verified,
                     ident, names, export, tmp):
    """Judge the adapter gate: both legs, no comparison."""
    base_bad, base_metrics = judge_q3_leg(
        verified["files"], "baseline", "stress-base")
    c9_bad, c9_metrics = judge_q3_leg(
        verified["files"], "c9", "stress-c9")
    reasons = (["baseline: %s" % r for r in base_bad]
               + ["c9: %s" % r for r in c9_bad])
    host_verdict = "PASS" if not reasons else "FAIL"
    out = Path(args.out)
    try:
        out.mkdir(parents=True, exist_ok=True)
        for name in names:
            shutil.copy2(verified["files"][name], out / name)
            shutil.copy2(export / ("%s.sha256" % name),
                         out / ("%s.sha256" % name))
        shutil.copy2(manifest_path, out / "inputs.json")
        for name in ("boot.json", "guest.stdout",
                     "guest.stderr", "guest.exit"):
            shutil.copy2(tmp / name, out / ("host-%s" % name))
        (out / "host-verdict.json").write_text(json.dumps(
            {"verdict": host_verdict, "reasons": reasons,
             "mode": "q3",
             "comparison": {"verdict": "NOT_RUN",
                            "reason": "q3 mode judges legs only; "
                                      "the pair comparison is "
                                      "separately scheduled"},
             "baseline": {"reasons": base_bad,
                          "metrics": base_metrics},
             "c9": {"reasons": c9_bad, "metrics": c9_metrics},
             "identity": ident,
             "runner_commit": manifest["runner_commit"],
             "consumer": manifest["consumer"],
             "oracle": manifest["oracle"]},
            indent=2, sort_keys=True) + "\n")
    except OSError as exc:
        print("FAIL vm-stress: receipt failed (%s); artifacts kept "
              "at %s" % (exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-stress: guest tmp kept at %s" % (tmp,))
    if host_verdict != "PASS":
        print("FAIL vm-stress %s: %s"
              % (host_verdict, "; ".join(reasons)))
        return 1
    print("ok vm-stress Q3 PASS (%s)" % (out,))
    print("ok vm-stress base M/D=%d/%d c9 M/D=%d/%d" % (
        base_metrics.get("M", 0), base_metrics.get("D", 0),
        c9_metrics.get("M", 0), c9_metrics.get("D", 0)))
    return 0


# -- pytest entry points ------------------------------------------

def test_self_test_unarmed(tmp_path):
    assert run_self_test(work=str(tmp_path / "self"))


def test_armed_stress_pair():
    import pytest
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip("stress armed run needs %s=1" % ARM_ENV)

    class Args:
        pass
    args = Args()
    raw = os.environ.get("MV_STRESS_INPUTS", "")
    args.inputs = [item for item in raw.split(";") if item]
    args.out = os.environ.get(
        "MV_STRESS_OUT",
        str(REPO / "build" / "vm" / "stress"))
    args.kver = os.environ.get("MV_STRESS_KVER", "")
    args.timeout = int(os.environ.get("MV_STRESS_TIMEOUT", "1800"))
    args.keep = os.environ.get("MV_STRESS_KEEP", "") == "1"
    args.bundle = os.environ.get("MV_STRESS_BUNDLE", "")
    args.candidate = os.environ.get("MV_STRESS_CANDIDATE", "")
    args.expect_release = os.environ.get("MV_STRESS_EXPECT_RELEASE", "")
    args.mode = os.environ.get("MV_STRESS_MODE", "full")
    assert armed_run(args) == 0


def main(argv):
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--inputs", action="append", default=[])
    parser.add_argument("--out", default="")
    parser.add_argument("--kver", default="")
    parser.add_argument("--timeout", type=int, default=1800)
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
    parser.add_argument("--mode", default="full",
                        choices=("full", "q3"),
                        help="full runs controls+quiet+overlap "
                             "with comparison; q3 runs the "
                             "adapter gate only")
    args = parser.parse_args(argv)
    if args.self_test or (not args.inputs and not args.out):
        return 0 if run_self_test() else 1
    return armed_run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

