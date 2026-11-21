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
"""

import ast
import fcntl
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))
import stress_core as core
from consume import (check_conservation, check_identity_closure,
                     check_oracle_script, compare_scripted,
                     parse_consume_file, parse_oracle_log)

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "stress-consumer" / "stress_guest.py"
ARM_ENV = "MEMVEIL_VM_STRESS"

EXPORT_NAMES = ["identity.json", "input-verify.json"]
for _leg in ("baseline", "c9"):
    EXPORT_NAMES += ["%s-controls.json" % _leg, "%s-c0a-lc.txt" % _leg,
                     "%s-c0b-lc.txt" % _leg, "%s-c0-oracle.log" % _leg,
                     "%s-p1-lc.txt" % _leg, "%s-p1-cp.txt" % _leg,
                     "%s-p1-oracle.log" % _leg, "%s-p2-lc.txt" % _leg,
                     "%s-p2-cp.txt" % _leg, "%s-p2-oracle.log" % _leg,
                     "%s-bpftrace.txt" % _leg, "%s-bpftrace.stderr" % _leg,
                     "%s-dd.json" % _leg, "%s-window.json" % _leg,
                     "%s-blockstats.json" % _leg]


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
    return subprocess.run([core.CONSUMER_RELEASE] + args,
                          capture_output=True, text=True, timeout=timeout)


# -- Unarmed self-test: pins ------------------------------------

def self_test_pins():
    """Every pinned byte still matches its source."""
    ok = True
    parent = subprocess.run(
        ["git", "-C", str(REPO), "rev-parse",
         "%s^" % core.BASELINE_CUTOVER],
        capture_output=True, text=True, timeout=30)
    ok = check("pins-cutover-parent",
               parent.returncode == 0
               and parent.stdout.strip() == core.BASELINE_COMMIT,
               parent.stdout.strip()) and ok
    for rel, blob_id, want in [
            (core.BASELINE_LC_BLOB, core.BASELINE_LC_BLOB_ID,
             core.BASELINE_LC_SHA),
            (core.BASELINE_CP_BLOB, core.BASELINE_CP_BLOB_ID,
             core.BASELINE_CP_SHA)]:
        ident = subprocess.run(
            ["git", "-C", str(REPO), "rev-parse",
             "%s:%s" % (core.BASELINE_COMMIT, rel)],
            capture_output=True, text=True, timeout=30)
        raw = subprocess.run(
            ["git", "-C", str(REPO), "cat-file", "-p",
             "%s:%s" % (core.BASELINE_COMMIT, rel)],
            capture_output=True, timeout=30)
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
    try:
        binding = core.load_candidate_binding(str(REPO))
        ok = check("pins-candidate",
                   binding["bundle"]["sha256"] == core.C9_BUNDLE_SHA
                   and binding["source"]["commit"] == core.C9_SOURCE_COMMIT
                   and binding["source"]["tree"] == core.C9_SOURCE_TREE) and ok
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
    proc = subprocess.run(
        ["cargo", "test", "--locked", "--offline"], cwd=core.CONSUMER_DIR,
        capture_output=True, text=True, timeout=600, env=core.cargo_env())
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
    candidate = core.load_candidate_binding(str(REPO))
    consumer = {"sha256": sha_file(core.CONSUMER_RELEASE),
                "build": {"profile": "release"}}
    oracle = core.oracle_digest(str(REPO))
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
        ok = self_test_replay(tmp) and ok
        ok = self_test_malformed(tmp) and ok
        ok = self_test_cargo_unit() and ok
        ok = self_test_host_btf() and ok
        ok = self_test_judge() and ok
        ok = self_test_compare() and ok
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


def verify_exports(export):
    """Exact inventory + sidecar check; returns {ok, files, reasons}."""
    result = {"ok": False, "files": {}, "reasons": []}
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        result["reasons"].append("export unreadable: %s" % (exc,))
        return result
    want = set(EXPORT_NAMES) | {"%s.sha256" % n for n in EXPORT_NAMES}
    if have != want:
        result["reasons"].append(
            "export inventory drift: %s" % sorted(have ^ want))
        return result
    for name in EXPORT_NAMES:
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
        second, _ = parse_consume_file(
            str(files["%s-c0b-lc.txt" % name]))
    except ValueError as exc:
        return (["%s: control files unparsable: %s" % (tag, exc)], {})
    bad += check_conservation(first, first_sum, tag + "-c0a")
    known = [e for e in first if e["kind"] == 1 and e["size"] == 512
             and e["gen"] != 0]
    if not known:
        bad.append("%s: no post-attach known map" % tag)
    elif not any(e["kind"] == 2 and e["gen"] == known[0]["gen"]
                 for e in first):
        bad.append("%s: post-attach release lost gen %d"
                   % (tag, known[0]["gen"]))
    held = [e for e in second if e["kind"] == 2 and e["size"] == 1024]
    if not any(e["gen"] == 0 for e in held):
        bad.append("%s: held-across-attach release not gen 0" % tag)
    controls = json.loads(files["%s-controls.json" % name].read_text())
    if controls.get("op0_gen") != (known[0]["gen"] if known else None):
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


def armed_run(args):
    """Armed stress pair: one pinned boot, baseline then c9."""
    if os.environ.get(ARM_ENV) != "1":
        print("FAIL vm-stress: armed run needs %s=1" % ARM_ENV)
        return 2
    if not args.out:
        print("FAIL vm-stress: armed needs --out")
        return 2
    try:
        rebind = parse_inputs(args.inputs)
    except ValueError as exc:
        print("FAIL vm-stress: %s" % exc)
        return 2
    flight = armed_preflight()
    if flight is None:
        return 1
    from lifecycle_env import ensure_oracle_module
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
        candidate = core.load_candidate_binding(str(REPO))
        built = core.build_consumer()
        oracle = core.oracle_digest(str(REPO))
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
        ensure_oracle_module()
        return armed_boot(args, pairs, manifest_path, manifest,
                          built, flight, work)
    except Exception as exc:  # pytest.fail raises here
        print("FAIL vm-stress: armed but %s" % (exc,))
        return 1
    finally:
        lease.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("vm-stress: work kept at %s" % (work,))


def armed_boot(args, pairs, manifest_path, manifest, built,
               flight, work):
    """Boot once, run both legs in-guest, judge host-side."""
    from vm_process import run_owned_guest
    from lifecycle_env import ORACLE_KO
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-stress-boot-"))
    export = tmp / "export"
    export.mkdir()
    guest_argv = [sys.executable, str(GUEST), "/tmp/vmgate-work",
                  "/tmp/export",
                  "--manifest", str(manifest_path),
                  "--consumer", built["path"],
                  "--consumer-sha", built["sha256"],
                  "--ko", ORACLE_KO,
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
    except subprocess.TimeoutExpired:
        print("FAIL vm-stress: guest timed out; artifacts kept "
              "at %s" % (tmp,))
        return 1
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        print("FAIL vm-stress: guest exit %d; artifacts kept at %s"
              % (proc.returncode, tmp))
        return 1
    verified = verify_exports(export)
    if not verified["ok"]:
        print("FAIL vm-stress: %s; artifacts kept at %s"
              % ("; ".join(verified["reasons"]), tmp))
        return 1
    ident = json.loads(verified["files"]["identity.json"].read_text())
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
    args = parser.parse_args(argv)
    if args.self_test or (not args.inputs and not args.out):
        return 0 if run_self_test() else 1
    return armed_run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

