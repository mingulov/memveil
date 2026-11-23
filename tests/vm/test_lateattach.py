#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Ported late-attach gate on the sealed consumer inputs.

The retired late-attach harness (tests/vm/test_late_attach.py)
drove a consumer contract with no surviving producer
(--bridge argv the sealed consumer rejects, an ASCII bridge
fixture, unstaged build inputs) and booted the host kernel
instead of the pinned guest. This runner ports the gate to
the battery precedent: a new guest flow
(tests/vm/lateattach_guest.py) drives the test-only Rust
consumer with its real CLI (--expect-family aya plus the
pinned digest, no bridge) over digest-pinned sealed
objects, the oracle fixture supplies the scripted
traffic, and the boot pins the locked 7.0.14 row through
the vng version token with cache verification.

Unarmed (default, no lease): the offline self-test —
pinned-byte verification, consumer build, both candidate layouts,
wrong-pair refusals, the kept judges over the retired mock
pair plus its five mutations, manifest round-trips, and
the staged-inputs wiring. Armed
(MEMVEIL_VM_LATEATTACH=1 with --bundle/--candidate/--out
plus the live-VM lease): one pinned boot runs both phases
in-guest, and the host re-derives the verdict from the
exports through the kept judges.

The kept judges (judge_phase_a/judge_phase_b plus the
attach-ordering and pre-attach predicates) are imported
verbatim from the retired runner; this file adds only the
new evidence identity (input manifest, staged inputs,
host-verdict receipt) around them.
"""

import argparse
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

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
sys.path.insert(0, os.path.join(_HERE, "stress-consumer"))

import candidate_pins as pins  # noqa: E402
import guest_oracle  # noqa: E402
import lateattach_core as core  # noqa: E402
import lateattach_guest  # noqa: E402
import stress_core as score  # noqa: E402
from capture_durability import check_shell_inert_path  # noqa: E402
from test_battery import (COMMAND_LINE_SIZE,  # noqa: E402
                          CMDLINE_HEADROOM, GUEST_EXEC_BUDGET,
                          cmdline_over_budget,
                          project_cmdline_total)
from test_late_attach import (  # noqa: E402
    HELD_OP, OPS, check_mock_pins, drop_lc_seq,
    judge_attach_doc, judge_phase_a, judge_phase_b,
    mock_attach_doc, mock_phase_a_files, mock_phase_b_files,
    mock_summary)
from test_late_attach import EXPORT_NAMES as RETIRED_EXPORTS

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "lateattach_guest.py"
ARM_ENV = "MEMVEIL_VM_LATEATTACH"
EXPORT_NAMES = {"lateattach": lateattach_guest.export_names()}


def sha_file(path):
    """SHA-256 of a file, streamed."""
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


# -- Host judges (kept verdicts plus the new identity) ----

def judge_identity(ident, manifest):
    """Recheck the exported guest identity host-side.

    Returns a reason list (empty ok): the booted release
    and the live BTF bytes must equal the pinned
    expectations, and every measured input digest must
    equal the manifest-bound bytes, independent of the
    guest's own gate.
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
    objects = manifest.get("objects", {})
    for channel in ("lc", "cp"):
        if digests.get(channel) != objects.get(
                channel, {}).get("sha256"):
            bad.append("guest measured %s bytes differ from "
                       "the seal" % channel)
    return bad


def judge_lateattach(files, manifest):
    """Host re-derivation of the gate; (reasons, metrics).

    Every verdict is re-derived here from the exported
    observations through the kept late-attach judges; the
    guest exports carry no verdicts.
    """
    try:
        ident = json.loads(
            files["identity.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return (["lateattach: identity unreadable: %s"
                 % (exc,)], {})
    bad = judge_identity(ident, manifest)
    try:
        attach = json.loads(
            files["attach.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return (sorted(bad + ["lateattach: attach doc "
                              "unreadable: %s" % (exc,)]),
                {})
    bad += judge_attach_doc(attach)
    metrics = {}
    try:
        bad += judge_phase_a(files)
        bad += judge_phase_b(files)
    except (ValueError, OSError, KeyError) as exc:
        bad.append("lateattach: case files unreadable: %s"
                   % (exc,))
    return sorted(bad), metrics


def synth_manifest():
    """Self-consistent manifest for synthetic judgments."""
    manifest = {
        "schema": core.SCHEMA,
        "runner_commit": "self-test",
        "objects": {
            "lc": {"sha256": pins.LC_SHA256},
            "cp": {"sha256": pins.CP_SHA256},
        },
        "oracle": {
            "ko_sha256": guest_oracle.KO_SHA256,
        },
    }
    return manifest


def synth_identity():
    """Self-consistent guest identity for judgments."""
    return {
        "release": core.EXPECT_RELEASE,
        "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
        "digests": {
            "consumer": "c" * 64,
            "lc": pins.LC_SHA256,
            "cp": pins.CP_SHA256,
            "ko": guest_oracle.KO_SHA256,
        },
    }


def synth_inputs():
    """Self-consistent inputs dict for offline doc tests."""
    return {
        "binary": {"path": "/w/memveil",
                   "sha256": "b" * 64},
        "attempt": {"path": "/w/attempt.bpf.o",
                    "sha256": pins.ATTEMPT_SHA256},
        "lc": {"path": "/w/lifecycle.bpf.o",
               "sha256": pins.LC_SHA256},
        "cp": {"path": "/w/copy.bpf.o",
               "sha256": pins.CP_SHA256},
        "profile": {"path": "/w/profiles/lateattach.json",
                    "sha256": "9" * 64,
                    "profile_id": "synth"},
    }


# -- Unarmed self-test: pins and gate constants -------------

def self_test_pins():
    """Every pinned byte still matches its source."""
    ok = True
    for rel, want in [
            ("tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o",
             pins.LC_SHA256),
            ("tests/vm/fixtures/aya/swiotlb_copy.bpf.o",
             pins.CP_SHA256),
            ("tests/vm/fixtures/aya/swiotlb_attempt.bpf.o",
             pins.ATTEMPT_SHA256)]:
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
        prof = core.profile_pins(str(REPO))
        import battery_core as bcore
        ok = check("pins-profile",
                   prof["sha256"] == bcore.PROFILE_SHA256
                   and prof["profile_id"]
                   == bcore.PROFILE_ID,
                   prof["sha256"][:16]) and ok
    except (ValueError, OSError) as exc:
        ok = check("pins-profile", False, str(exc)) and ok
    seal = [REPO / "dist" / "candidate.json",
            Path(pins.dist_bundle_tarball(REPO))]
    if not all(p.is_file() for p in seal):
        print("ok pins-candidate SKIP (no dist/ seal in tree)")
    else:
        try:
            binding = score.load_candidate_binding(str(REPO))
            ok = check(
                "pins-candidate",
                binding["bundle"]["sha256"]
                == pins.BUNDLE_SHA256
                and binding["source"]["commit"]
                == pins.SOURCE_COMMIT
                and binding["source"]["tree"]
                == pins.SOURCE_TREE) and ok
        except (ValueError, OSError, KeyError) as exc:
            ok = check("pins-candidate", False,
                       str(exc)) and ok
    return ok


def self_test_gate_constants():
    """Mirrored gate constants still equal their sources."""
    import ast
    import battery_core as bcore
    import battery_guest
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
                   found.get("LC_SITES") == core.LC_SITES
                   == battery_guest.LC_SITES,
                   "%r" % (found.get("LC_SITES"),)) and ok
        ok = check("const-sites-cp",
                   found.get("CP_SITES") == core.CP_SITES
                   == battery_guest.CP_SITES,
                   "%r" % (found.get("CP_SITES"),)) and ok
    except OSError as exc:
        ok = check("const-sites", False, str(exc)) and ok
    ok = check("const-release",
               core.EXPECT_RELEASE
               == lateattach_guest.EXPECT_RELEASE
               == battery_guest.EXPECT_RELEASE
               == guest_oracle.GUEST_RELEASE,
               "%r" % (core.EXPECT_RELEASE,)) and ok
    try:
        entry = core.pinned_guest_entry(str(REPO))
        source = entry.get("source", {})
        ok = check("const-vng-tag",
                   source.get("vng_version") == core.VNG_TAG
                   == bcore.VNG_TAG
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
                       binding["row"] == "7.0"
                       and binding["vng_tag"] == core.VNG_TAG
                       and binding["release"]
                       == core.EXPECT_RELEASE) and ok
        except ValueError as exc:
            ok = check("const-guest-binding", False,
                       str(exc)) and ok
    except ValueError as exc:
        ok = check("const-guest-lock", False, str(exc)) and ok
    try:
        import late_attach_guest as retired_guest
        ok = check("const-choreography",
                   lateattach_guest.OPS
                   == retired_guest.OPS == OPS == 4
                   and lateattach_guest.HELD_OP
                   == retired_guest.HELD_OP == HELD_OP == 3
                   and lateattach_guest.CONSUMER_SECONDS
                   == retired_guest.CONSUMER_SECONDS == 30,
                   "ops/held/seconds drift") and ok
    except (OSError, AttributeError) as exc:
        ok = check("const-choreography", False,
                   str(exc)[:160]) and ok
    ok = check("const-cases",
               core.CASES == ("lateattach",)
               and set(core.CASES) == set(EXPORT_NAMES)) \
        and ok
    names = EXPORT_NAMES["lateattach"]
    ok = check("const-inventory",
               sorted(names)
               == sorted(RETIRED_EXPORTS
                         + ["input-verify.json"])
               and len(names) == len(set(names))
               and "identity.json" in names
               and "input-verify.json" in names
               and "attach.json" in names,
               "%d names" % len(names)) and ok
    return ok


# -- Unarmed self-test: kept judges, verbatim --------------

def self_test_judges(tmp):
    """Kept judges over the retired mocks, verbatim."""
    import inspect
    import test_late_attach as retired
    ok = True
    here = os.path.dirname(os.path.abspath(__file__))
    for name in ("judge_phase_a", "judge_phase_b",
                 "judge_attach_doc"):
        try:
            same = inspect.getsourcefile(
                globals()[name]) == os.path.join(
                    here, "test_late_attach.py")
        except (KeyError, TypeError):
            same = False
        ok = check("judges-import-%s" % name, same) and ok
    try:
        rc = retired.run_selftest()
    except Exception as exc:
        return check("judges-retired-selftest", False,
                     str(exc)[:200]) and ok
    ok = check("judges-retired-selftest", rc == 0,
               "exit=%r" % (rc,)) and ok
    work = os.path.join(tmp, "judges")
    os.makedirs(work, exist_ok=True)
    mock_phase_a_files(Path(work))
    mock_phase_b_files(Path(work))
    bad = check_mock_pins(Path(work))
    ok = check("judges-mock-pins", bad == [],
               "; ".join(bad[:2])) and ok

    def judged(mutate):
        import copy
        case = os.path.join(work, mutate.__name__)
        os.makedirs(case, exist_ok=True)
        for name in os.listdir(work):
            src = os.path.join(work, name)
            if os.path.isfile(src):
                shutil.copyfile(
                    src, os.path.join(case, name))
        doc = copy.deepcopy(mock_attach_doc())
        mutate(Path(case), doc)
        with open(os.path.join(case,
                               "attach.json"), "w") as handle:
            handle.write(json.dumps(doc) + "\n")
        ident = synth_identity()
        with open(os.path.join(case,
                               "identity.json"), "w") as handle:
            handle.write(json.dumps(ident) + "\n")
        files = {name: Path(case) / name
                 for name in os.listdir(case)}
        reasons, _ = judge_lateattach(files,
                                      synth_manifest())
        return reasons

    def good(case, doc):
        return None

    def miss_held(case, doc):
        (case / "a-lc.txt").write_text(
            mock_summary(0, 0) + "\n")
        (case / "a-cp.txt").write_text(
            mock_summary(0, 0) + "\n")

    def dangling(case, doc):
        body = (case / "a-lc.txt").read_text()
        (case / "a-lc.txt").write_text(
            body.replace("gen=0", "gen=7"))

    def drop_control(case, doc):
        drop_lc_seq(case / "b-lc.txt", 4)

    def miss_control(case, doc):
        body = (case / "b-lc.txt").read_text()
        (case / "b-lc.txt").write_text(
            body.replace("gen=101", "gen=0", 1))

    def swap_order(case, doc):
        row = doc["phase_a"]
        row["attach_ns"], row["released_ns"] = (
            row["released_ns"], row["attach_ns"])

    def drop_bounce(case, doc):
        (case / "a-cp.txt").write_text(
            mock_summary(0, 0) + "\n")

    cases = [(good, False), (miss_held, True),
             (dangling, True), (drop_control, True),
             (miss_control, True), (swap_order, True),
             (drop_bounce, True)]
    for mutate, want_fail in cases:
        try:
            reasons = judged(mutate)
        except Exception as exc:
            ok = check("judges-%s" % mutate.__name__,
                       False, str(exc)[:200]) and ok
            continue
        ok = check("judges-%s" % mutate.__name__,
                   bool(reasons) == want_fail,
                   "; ".join(reasons[:2])) and ok
    # Missing evidence refuses cleanly instead of crashing.
    good_files = {name: Path(work) / "good" / name
                  for name in os.listdir(
                      os.path.join(work, "good"))}
    for drop in ("identity.json", "attach.json",
                 "a-lc.txt"):
        files = {name: path for name, path in
                 good_files.items() if name != drop}
        try:
            reasons, _ = judge_lateattach(
                files, synth_manifest())
        except Exception as exc:
            ok = check("judges-missing-%s" % drop, False,
                       "crashed: %s" % exc) and ok
            continue
        ok = check("judges-missing-%s" % drop,
                   reasons != [],
                   "missing file passed") and ok
    return ok


# -- Unarmed self-test: consumer build + layouts ------------

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
               == pins.LC_SHA256) and ok
    # The retired --bridge contract stays refused: the Gate
    # argv shape exits 2 with the usage text, exactly the
    # blocker the port removes from the guest path.
    bridge_proc = consumer_run([
        "--bridge", "bridge", "obj", "ring", "sites", "1",
        "out"])
    ok = check("build-bridge-refused",
               bridge_proc.returncode == 2
               and "usage:" in bridge_proc.stdout,
               "exit=%d" % bridge_proc.returncode) and ok
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
    """Candidate layouts verified against pinned bytes, offline."""
    from test_battery import LAYOUT_WANT as battery_layouts
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
        ok = check(tag + "-battery-agrees",
                   battery_layouts[(name, channel)]
                   == want) and ok
    proc = consumer_run(["--verify-layout",
                         pairs["c9"]["cp"]["path"],
                         "mv_lifecycle"])
    ok = check("layout-cross-channel",
               proc.returncode == 1
               and "neither family" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    trunc = os.path.join(tmp, "trunc-lc.o")
    with open(pairs["c9"]["lc"]["path"], "rb") as handle:
        head = handle.read(4096)
    with open(trunc, "wb") as handle:
        handle.write(head)
    proc = consumer_run(["--verify-layout", trunc,
                         "mv_lifecycle"])
    ok = check("layout-truncated",
               proc.returncode == 1
               and "ELF parse failed" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    return ok


def self_test_wrong_pair(pairs):
    """Wrong-pair refusals through the real consume entrypoint.

    The digest and family gates fire before any privilege or
    BTF need, so these run fully offline with no boot.
    """
    ok = True
    c9_lc = pairs["c9"]["lc"]["path"]
    c9_cp = pairs["c9"]["cp"]["path"]
    never = os.path.join(tempfile.gettempdir(),
                         "lateattach-never-written")
    cases = [
        ("family-swap",
         ["--expect-family", "c", c9_lc, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "family mismatch"),
        ("digest-wrong",
         ["--expect-sha256", "0" * 64, c9_lc, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "digest mismatch"),
        ("digest-swapped-channels",
         ["--expect-sha256", pins.LC_SHA256, c9_cp,
          "mv_copies", core.CP_SITES, "1", never],
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


def self_test_stage(tmp):
    """Consumer staging lands verified bytes at the old path."""
    ok = True
    try:
        built = score.build_consumer()
    except ValueError as exc:
        return check("stage-consumer", False,
                     str(exc)[:200])
    root = os.path.join(tmp, "stage-root")
    try:
        staged = core.stage_consumer(root, built)
    except (ValueError, OSError) as exc:
        return check("stage-consumer", False,
                     str(exc)[:200])
    want = os.path.join(root, "build", "vm", "mv_consume")
    ok = check("stage-path", staged["path"] == want,
               staged["path"]) and ok
    try:
        ok = check("stage-sha",
                   sha_file(want) == built["sha256"]
                   == staged["sha256"]) and ok
    except OSError as exc:
        ok = check("stage-sha", False, str(exc)[:160]) \
            and ok
    ok = check("stage-build",
               staged["build"] == built["build"]) and ok
    # Staging foreign bytes under a clean digest refuses:
    # the post-copy hash must catch the swap.
    evil = os.path.join(tmp, "evil-consumer")
    with open(evil, "wb") as handle:
        handle.write(b"not the consumer")
    try:
        core.stage_consumer(
            root, {"path": evil,
                   "sha256": built["sha256"],
                   "build": built["build"]})
        ok = check("stage-tamper", False, "accepted") and ok
    except ValueError as exc:
        ok = check("stage-tamper", "drift" in str(exc),
                   str(exc)[:160]) and ok
    return ok


# -- Guest-inputs wiring (host-tested) ----------------------

def build_guest_inputs(manifest_path, staged, inputs,
                       expect_release):
    """Staged inputs doc bytes (host-tested).

    Carries every path and digest the guest flow verifies;
    the host writes these exact bytes to the shared export
    dir and binds their digest in the run manifest, while
    the guest command line carries only the pointer
    filename. staged is the staged-consumer entry ({path,
    sha256}); the guest executes the staged bytes at the
    retired prerequisite path.
    """
    doc = {
        "schema": core.GUEST_INPUTS_SCHEMA,
        "case": "lateattach",
        "expect_release": expect_release,
        "manifest": str(manifest_path),
        "consumer": {"path": staged["path"],
                     "sha256": staged["sha256"]},
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
    }
    return (json.dumps(doc, indent=2, sort_keys=True)
            + "\n").encode("utf-8")


def write_guest_inputs_doc(work, manifest_path, staged,
                           inputs, expect_release):
    """Stage the inputs doc; return its path."""
    blob = build_guest_inputs(manifest_path, staged, inputs,
                              expect_release)
    doc_path = os.path.join(work, "guest-inputs.json")
    with open(doc_path, "wb") as handle:
        handle.write(blob)
    return doc_path


def build_guest_argv():
    """Guest command line (host-tested wiring).

    Carries only the staged inputs filename: the full
    inputs doc travels through the shared export dir, so
    the joined payload stays far under GUEST_EXEC_BUDGET
    however long the host paths grow.
    """
    return [sys.executable, str(GUEST), "/tmp/vmgate-work",
            "/tmp/export",
            "--inputs", core.GUEST_INPUTS_FILE]


# -- Unarmed self-test: manifest and wiring -----------------

def sealed_inputs_for_manifest(tmp):
    """Inputs dict over committed candidate bytes (no dist/ seal).

    The committed Aya fixtures ARE the sealed candidate object
    bytes, the bound profile is committed, and the oracle
    fixture carries its own binding: only the sealed binary
    has no committed bytes, so a scratch stand-in fills its
    slot with its measured digest. The writer/verifier
    round-trip below therefore runs identically with and
    without a dist/ seal in the tree.
    """
    binary = os.path.join(tmp, "standin-memveil")
    with open(binary, "wb") as handle:
        handle.write(b"lateattach stand-in binary\n")
    os.chmod(binary, 0o755)
    prof = core.profile_pins(str(REPO))
    prof_dir = os.path.join(tmp, "profiles")
    os.makedirs(prof_dir, exist_ok=True)
    prof_dst = os.path.join(prof_dir, "lateattach.json")
    shutil.copyfile(prof["path"], prof_dst)
    with open(os.path.join(prof_dir, "manifest.txt"),
              "w") as handle:
        handle.write("lateattach.json\n")
    return {
        "binary": {"path": binary, "sha256": sha_file(binary)},
        "attempt": {
            "path": str(REPO / "tests/vm/fixtures/aya/"
                              "swiotlb_attempt.bpf.o"),
            "sha256": pins.ATTEMPT_SHA256},
        "lc": {"path": str(REPO / "tests/vm/fixtures/aya/"
                                   "swiotlb_lifecycle.bpf.o"),
               "sha256": pins.LC_SHA256},
        "cp": {"path": str(REPO / "tests/vm/fixtures/aya/"
                                  "swiotlb_copy.bpf.o"),
               "sha256": pins.CP_SHA256},
        "profile": {"path": prof_dst,
                    "sha256": prof["sha256"],
                    "profile_id": prof["profile_id"]},
        "candidate": {
            "schema": "memveil-candidate/2",
            "source": {"commit": pins.SOURCE_COMMIT,
                       "tree": pins.SOURCE_TREE},
            "bundle_manifest_sha256":
                pins.BUNDLE_MANIFEST_SHA256,
            "files": {
                "bin/memveil": sha_file(binary),
                "bpf/swiotlb_attempt.bpf.o":
                    pins.ATTEMPT_SHA256,
                "bpf/swiotlb_lifecycle.bpf.o":
                    pins.LC_SHA256,
                "bpf/swiotlb_copy.bpf.o": pins.CP_SHA256,
            },
            "bundle": {"sha256": pins.BUNDLE_SHA256,
                       "size": pins.BUNDLE_SIZE},
        },
        "oracle": {
            "ko": guest_oracle.FIXTURE_KO,
            "ko_sha256": guest_oracle.KO_SHA256,
            "ko_vermagic": guest_oracle.GUEST_VERMAGIC,
            "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
            "guest_release": guest_oracle.GUEST_RELEASE,
        },
        "guest": core.guest_binding(str(REPO)),
    }


def self_test_manifest(tmp):
    """Input manifest round-trip plus tamper refusals."""
    ok = True
    try:
        built = score.build_consumer()
    except ValueError as exc:
        return check("manifest-consumer", False,
                     str(exc)[:200])
    try:
        staged = core.stage_consumer(
            os.path.join(tmp, "seal-stage"), built)
    except (ValueError, OSError) as exc:
        return check("manifest-stage", False,
                     str(exc)[:200])
    inputs = sealed_inputs_for_manifest(tmp)
    commit = core.git_head(str(REPO))
    manifest_path = os.path.join(tmp, "inputs.json")
    try:
        doc_path = write_guest_inputs_doc(
            tmp, manifest_path, staged, inputs, "")
    except (ValueError, OSError) as exc:
        return check("manifest-inputs-stage", False,
                     str(exc)[:200])
    manifest = core.write_input_manifest(
        manifest_path, inputs,
        {"sha256": staged["sha256"],
         "build": staged["build"]},
        ["lateattach"], ["test_lateattach", "--out", "x"],
        commit, guest_inputs={"lateattach": doc_path})
    ok = check("manifest-verify",
               core.verify_input_manifest(
                   manifest, staged["path"]) == [],
               "; ".join(core.verify_input_manifest(
                   manifest, staged["path"])[:2])) and ok
    ok = check("manifest-guest-inputs",
               sorted(manifest["guest_inputs"])
               == ["lateattach"]
               and manifest["guest_inputs"][
                   "lateattach"]["file"]
               == core.GUEST_INPUTS_FILE) and ok
    ok = check("manifest-cases",
               manifest["cases"] == ["lateattach"]
               and manifest["schema"] == core.SCHEMA
               and manifest["runner_commit"] == commit) \
        and ok
    ok = check("manifest-oracle",
               manifest["oracle"]["ko_sha256"]
               == guest_oracle.KO_SHA256
               and manifest["oracle"]["guest_release"]
               == core.EXPECT_RELEASE) and ok
    ok = check("manifest-staged-consumer",
               manifest["consumer"]["binary_sha256"]
               == built["sha256"]
               == sha_file(staged["path"])) and ok
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
                    tampered(["cases"], ["lateattach",
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
                    tampered(["guest_inputs", "lateattach",
                              "sha256"], "0" * 64)))
    for name, other in tampers:
        reasons = core.verify_input_manifest(
            other, staged["path"])
        ok = check("manifest-tamper-%s" % name,
                   reasons != [],
                   "tamper passed") and ok
    # Malformed shapes refuse instead of crashing.
    nulls = tampered(["objects"], None)
    reasons = core.verify_input_manifest(nulls, staged["path"])
    ok = check("manifest-null-objects",
               any("not a mapping" in reason
                   for reason in reasons),
               "; ".join(reasons[:2])) and ok
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


def self_test_manifest_seal(tmp):
    """Full seal materialize when a dist/ seal is present."""
    seal = [REPO / "dist" / "candidate.json",
            Path(pins.dist_bundle_tarball(REPO))]
    if not all(p.is_file() for p in seal):
        print("ok manifest-seal SKIP (no dist/ seal in tree)")
        return True
    ok = True
    try:
        inputs = core.materialize(
            str(REPO), os.path.join(tmp, "seal-inputs"),
            str(seal[0]), str(seal[1]))
    except (ValueError, OSError) as exc:
        return check("manifest-seal-materialize", False,
                     str(exc)[:200])
    ok = check("manifest-seal-materialize",
               inputs["binary"]["sha256"]
               == inputs["candidate"]["files"][
                   "bin/memveil"]
               and inputs["lc"]["sha256"] == pins.LC_SHA256
               and inputs["cp"]["sha256"] == pins.CP_SHA256
               and inputs["attempt"]["sha256"]
               == pins.ATTEMPT_SHA256) and ok
    return ok


def self_test_guest_argv(tmp):
    """Guest argv carries only the staged inputs pointer."""
    ok = True
    try:
        argv = build_guest_argv()
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
    return ok


def self_test_cmdline_budget(tmp):
    """Cmdline projection refuses over budget, frees the argv."""
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
    argv = build_guest_argv()
    total = project_cmdline_total(len(shlex.join(argv)))
    ok = check("budget-real-argv",
               total <= COMMAND_LINE_SIZE - CMDLINE_HEADROOM,
               "projects %d (ceiling %d, headroom floor %d)"
               % (total, COMMAND_LINE_SIZE,
                  COMMAND_LINE_SIZE - CMDLINE_HEADROOM)) \
        and ok
    return ok


def self_test_guest_inputs(tmp):
    """Inputs doc stages, parses, binds, and refuses tampering."""
    ok = True
    staged = {"path": "/w/build/vm/mv_consume",
              "sha256": "c" * 64}
    inputs = synth_inputs()
    try:
        doc_path = write_guest_inputs_doc(
            tmp, "/w/inputs.json", staged, inputs, "")
    except (ValueError, OSError) as exc:
        return check("inputs-stage", False, str(exc)[:160])
    ok = check("inputs-stage", os.path.isfile(doc_path),
               doc_path) and ok
    try:
        blob = open(doc_path, "rb").read()
        doc = json.loads(blob.decode("utf-8"))
        ok = check("inputs-doc",
                   doc["schema"]
                   == core.GUEST_INPUTS_SCHEMA
                   == lateattach_guest.GUEST_INPUTS_SCHEMA
                   and doc["case"] == "lateattach"
                   and doc["consumer"]["path"]
                   == "/w/build/vm/mv_consume"
                   and doc["lc"]["sha256"]
                   == pins.LC_SHA256
                   and doc["ko"]["sha256"]
                   == guest_oracle.KO_SHA256,
                   blob[:120].decode("utf-8",
                                     "replace")) and ok
    except (OSError, ValueError) as exc:
        ok = check("inputs-doc", False, str(exc)[:160]) \
            and ok
    export = os.path.join(tmp, "export")
    os.makedirs(export, exist_ok=True)
    staged_copy = os.path.join(export, core.GUEST_INPUTS_FILE)
    shutil.copyfile(doc_path, staged_copy)
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
                "lateattach": {
                    "file": core.GUEST_INPUTS_FILE,
                    "sha256": sha_file(staged_copy),
                },
            },
        }))
    try:
        fields, observed = \
            lateattach_guest.parse_guest_inputs(
                export, core.GUEST_INPUTS_FILE)
        ok = check("inputs-parse",
                   fields["case"] == "lateattach"
                   and fields["lc_sha"] == pins.LC_SHA256
                   and fields["consumer"]
                   == "/w/build/vm/mv_consume"
                   and fields["manifest"] == manifest_path
                   and observed == sha_file(staged_copy),
                   observed[:16]) and ok
    except ValueError as exc:
        ok = check("inputs-parse", False,
                   str(exc)[:160]) and ok
    with open(staged_copy, "ab") as handle:
        handle.write(b" ")
    try:
        lateattach_guest.parse_guest_inputs(
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
            lateattach_guest.parse_guest_inputs(export, name)
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
               judge_identity(ident, manifest)
               == []) and ok
    drifts = [
        ("release", {"release": "bogus"}),
        ("btf", {"btf_sha256": "0" * 64}),
        ("ko", {"digests": {"ko": "0" * 64}}),
        ("lc", {"digests": {"lc": "0" * 64}}),
        ("cp", {"digests": {"cp": "0" * 64}}),
    ]
    for name, patch in drifts:
        ident = synth_identity()
        for key, value in patch.items():
            if key == "digests":
                ident["digests"].update(value)
            else:
                ident[key] = value
        bad = judge_identity(ident, manifest)
        ok = check("identity-drift-%s" % name, bad != [],
                   "drift passed") and ok
    return ok


def self_test_inputs_binding(tmp):
    """Guest-observed inputs digest must match the binding."""
    ok = True
    export = os.path.join(tmp, "bound-export")
    os.makedirs(export, exist_ok=True)
    staged = os.path.join(export, core.GUEST_INPUTS_FILE)
    with open(staged, "wb") as handle:
        handle.write(b'{"case": "lateattach"}\n')
    digest = sha_file(staged)
    manifest = {"guest_inputs": {
        "lateattach": {"file": core.GUEST_INPUTS_FILE,
                       "sha256": digest}}}
    verify_path = os.path.join(tmp, "input-verify.json")

    def files_for(doc):
        with open(verify_path, "w") as handle:
            handle.write(json.dumps(doc))
        return {"input-verify.json": Path(verify_path)}

    good = {"case": "lateattach",
            "guest_inputs_file": core.GUEST_INPUTS_FILE,
            "guest_inputs_sha256": digest}
    ok = check("binding-clean",
               check_guest_inputs_binding(
                   files_for(good), manifest,
                   export) == []) and ok
    drifted = dict(good, guest_inputs_sha256="0" * 64)
    ok = check("binding-drift",
               check_guest_inputs_binding(
                   files_for(drifted), manifest,
                   export) != [],
               "drift passed") and ok
    renamed = dict(good, case="matrix")
    ok = check("binding-case",
               check_guest_inputs_binding(
                   files_for(renamed), manifest,
                   export) != [],
               "case swap passed") and ok
    with open(staged, "ab") as handle:
        handle.write(b" ")
    ok = check("binding-staged",
               check_guest_inputs_binding(
                   files_for(good), manifest,
                   export) != [],
               "staged tamper passed") and ok
    os.unlink(verify_path)
    ok = check("binding-missing",
               check_guest_inputs_binding(
                   {}, manifest, export) != [],
               "missing verify passed") and ok
    return ok


def self_test_verify_exports(tmp):
    """Export inventory check passes clean, refuses drift."""
    ok = True
    export = Path(tmp) / "verify-export"
    export.mkdir(exist_ok=True)
    names = EXPORT_NAMES["lateattach"]
    for name in names:
        (export / name).write_text("payload %s\n" % name)
        digest = sha_file(export / name)
        (export / ("%s.sha256" % name)).write_text(
            "%s  %s\n" % (digest, name))
    # The staged inputs doc shares the dir but is not
    # guest output: inventory must ignore it.
    (export / core.GUEST_INPUTS_FILE).write_text("{}\n")
    good = verify_exports(export)
    ok = check("exports-clean",
               good["ok"] is True
               and sorted(good["files"]) == sorted(names),
               "; ".join(good["reasons"][:2])) and ok
    (export / "stowaway.txt").write_text("x\n")
    drifted = verify_exports(export)
    ok = check("exports-extra",
               drifted["ok"] is False
               and any("inventory drift" in reason
                       for reason in drifted["reasons"]),
               "extra file passed") and ok
    (export / "stowaway.txt").unlink()
    (export / ("a-lc.txt.sha256")).write_text(
        "%s  a-lc.txt\n" % ("0" * 64))
    tampered = verify_exports(export)
    ok = check("exports-sidecar",
               tampered["ok"] is False
               and any("sidecar mismatch" in reason
                       for reason in tampered["reasons"]),
               "sidecar tamper passed") and ok
    (export / "b-cp.txt").unlink()
    missing = verify_exports(export)
    ok = check("exports-missing",
               missing["ok"] is False
               and any("inventory drift" in reason
                       for reason in missing["reasons"]),
               "missing file passed") and ok
    return ok


def self_test_receipt_drift(tmp):
    """Receipt-time manifest must still equal the judged snapshot."""
    ok = True
    manifest = {
        "runner_commit": "self-test",
        "consumer": {"binary_sha256": "self-test"},
        "oracle": {"ko_sha256": guest_oracle.KO_SHA256},
        "guest_inputs": {
            "lateattach": {"file": core.GUEST_INPUTS_FILE,
                           "sha256": "a" * 64},
        },
    }
    manifest_path = os.path.join(tmp, "drift-inputs.json")

    def rewrite(doc):
        with open(manifest_path, "w") as handle:
            handle.write(json.dumps(doc, indent=2,
                                    sort_keys=True) + "\n")

    rewrite(manifest)
    retained = {}
    ok = check("receipt-drift-clean",
               check_manifest_receipt_drift(
                   manifest_path, manifest,
                   retained=retained)
               == []
               and retained.get("raw") == open(
                   manifest_path, "rb").read()) and ok
    # A post-judgment mutation of the bound digest refuses
    # and names the drifted fields.
    mutated = json.loads(json.dumps(manifest))
    mutated["guest_inputs"]["lateattach"]["sha256"] = \
        "0" * 64
    rewrite(mutated)
    bad = check_manifest_receipt_drift(
        manifest_path, manifest)
    ok = check("receipt-drift-digest",
               len(bad) == 1 and "drifted" in bad[0]
               and "guest_inputs" in bad[0],
               "; ".join(bad)) and ok
    # A repeated member refuses instead of silently
    # keeping one value.
    with open(manifest_path, "w") as handle:
        handle.write('{"runner_commit": "a", '
                     '"runner_commit": "b"}\n')
    bad = check_manifest_receipt_drift(
        manifest_path, manifest)
    ok = check("receipt-drift-dupe",
               len(bad) == 1 and "duplicate" in bad[0],
               "; ".join(bad)) and ok
    os.unlink(manifest_path)
    bad = check_manifest_receipt_drift(
        manifest_path, manifest)
    ok = check("receipt-drift-missing",
               bad != [], "missing manifest passed") and ok
    return ok


def self_test_vng_argv(tmp):
    """vng argv pins the guest row and gates the export spelling."""
    ok = True
    export = os.path.join(tmp, "vng-export")
    os.makedirs(export, exist_ok=True)
    flight = {"prefix": ["vng"], "harness": {},
              "vng": "vng"}
    try:
        cmd = build_vng_argv(flight, export, "exec-str")
    except ValueError as exc:
        return check("vng-argv", False, str(exc)[:160])
    try:
        at = cmd.index("--run")
    except ValueError:
        return check("vng-argv-token", False,
                     "no --run in %r" % (cmd,))
    ok = check("vng-argv-token", cmd[at + 1] == core.VNG_TAG,
               "%r" % (cmd,)) and ok
    ok = check("vng-argv-microvm",
               "--disable-microvm" not in cmd
               and "--network" not in cmd) and ok
    ok = check("vng-argv-verbose", "--verbose" in cmd) and ok
    hostile = os.path.join(tmp, 't"mp')
    os.makedirs(hostile, exist_ok=True)
    try:
        build_vng_argv(flight, hostile, "exec-str")
        ok = check("vng-argv-hostile-export", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("vng-argv-hostile-export",
                   "launcher shell" in str(exc),
                   str(exc)[:160]) and ok
    return ok


def self_test_boot_tmpdir_guard(tmp):
    """Boot assembly refuses rewritten TMPDIR before spawning."""
    from unittest import mock
    ok = True
    hostile = Path(tmp) / 't"mp'
    hostile.mkdir(exist_ok=True)
    flight = {"prefix": ["vng"], "harness": {},
              "vng": "vng"}
    with mock.patch.dict(os.environ,
                         {'TMPDIR': str(hostile)}), \
         mock.patch.object(tempfile, 'tempdir', None):
        try:
            assemble_boot(flight)
            ok = check("tmpdir-guard", False,
                       "accepted") and ok
        except ValueError as exc:
            ok = check("tmpdir-guard",
                       'launcher shell' in str(exc),
                       str(exc)[:160]) and ok
    # An honest TMPDIR assembles without spawning:
    # assembly returns parts, the caller spawns later.
    with mock.patch("vm_process.run_owned_guest") as spawned:
        try:
            parts = assemble_boot(flight)
        except ValueError as exc:
            return check("tmpdir-guard-honest", False,
                         str(exc)[:160]) and ok
        shutil.rmtree(str(parts[0]), ignore_errors=True)
        ok = check("tmpdir-guard-honest",
                   len(parts) == 5
                   and spawned.call_count == 0) and ok
    return ok


def self_test_guest_completion_wait(tmp):
    """Phase-A completion wait over scripted dmesg streams.

    No guest: the wait's dmesg reads are scripted, so a
    late completion marker proves the new code waits
    while the old snapshot-first order fails on the
    same stream's first frame.
    """
    import contextlib
    import inspect
    import io
    import lateattach_guest as guest
    ok = True

    class _R:
        def __init__(self, out):
            self.returncode = 0
            self.stdout = out

    early = "[2.0] mv-oracle: op=0 mapping=0 held-open\n"
    full = early + \
        "[2.0] mv-oracle: script complete ops=4\n"
    wrong = early + \
        "[2.0] mv-oracle: script complete ops=3\n"
    real_sh = guest.sh

    def run_wait(outputs, timeout):
        calls = []
        stream = list(outputs)

        def fake(args, timeout=30, **kw):
            calls.append(list(args))
            if len(calls) <= len(stream):
                return _R(stream[len(calls) - 1])
            return _R(stream[-1])

        guest.sh = fake
        err = io.StringIO()
        code = None
        try:
            with contextlib.redirect_stderr(err):
                guest.Gate.wait_oracle_complete(
                    object(), timeout=timeout,
                    interval=0.001)
        except SystemExit as exc:
            code = exc.code
        finally:
            guest.sh = real_sh
        return code, err.getvalue(), len(calls)

    code, _, calls = run_wait([full], 60)
    ok = check("wait-immediate",
               code is None and calls == 1,
               "code=%r calls=%d" % (code, calls)) and ok
    code, _, calls = run_wait([early, early, full], 60)
    ok = check("wait-late",
               code is None and calls == 3,
               "code=%r calls=%d" % (code, calls)) and ok
    code, msg, _ = run_wait([early], 0)
    ok = check("wait-timeout",
               code == 1 and "never completed" in msg
               and "pre-attach script incomplete"
               not in msg,
               msg.strip()[-120:]) and ok
    code, msg, _ = run_wait([wrong], 60)
    ok = check("wait-badops",
               code == 1 and "bad ops" in msg,
               msg.strip()[-120:]) and ok

    # RED: the old order (snapshot first, no wait) fails
    # on the late stream's first frame with the
    # misleading message; the completed frame passes.
    pre = os.path.join(tmp, "wait-pre.log")
    with open(pre, "w") as handle:
        handle.write(early)
    err = io.StringIO()
    code = None
    try:
        with contextlib.redirect_stderr(err):
            guest.check_pre_attach(pre)
    except SystemExit as exc:
        code = exc.code
    ok = check("wait-red-oldcode",
               code == 1
               and "pre-attach script incomplete"
               in err.getvalue(),
               "code=%r" % (code,)) and ok
    with open(pre, "w") as handle:
        handle.write(full)
    try:
        guest.check_pre_attach(pre)
        ok = check("wait-red-complete", True) and ok
    except SystemExit as exc:
        ok = check("wait-red-complete", False,
                   "code=%r" % (exc.code,)) and ok

    # The phase-A source itself orders the wait between
    # insmod and the snapshot, with the mapped stamp
    # taken only once completion is observed.
    src = inspect.getsource(guest.run_phase_a)
    insmod_at = src.index("gate.insmod(")
    wait_at = src.index("gate.wait_oracle_complete(")
    snap_at = src.index('gate.oracle_log("a-pre-oracle.log")')
    stamp_at = src.index("mapped_ns = mono_ns()")
    ok = check("wait-wired",
               insmod_at < wait_at < snap_at
               and wait_at < stamp_at < snap_at) and ok
    ok = check("wait-bounds",
               30 <= guest.TIMEOUT_ORACLE_COMPLETE <= 60
               and guest.ORACLE_POLL_INTERVAL >= 0.05,
               "timeout=%r interval=%r"
               % (guest.TIMEOUT_ORACLE_COMPLETE,
                  guest.ORACLE_POLL_INTERVAL)) and ok

    # Post-insmod publication trigger: the pinned guest holds
    # the last committed record from readers until a later
    # record commits (proven live), so phase A writes one
    # marker record after insmod, before the wait polls.
    import builtins
    real_open = builtins.open

    class _Handle:
        def __init__(self, store):
            self.store = store

        def write(self, text):
            self.store.append(text)

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    writes = []

    def fake_kmsg_open(path, mode="r", *args, **kw):
        if str(path) == "/dev/kmsg" and "w" in mode:
            return _Handle(writes)
        return real_open(path, mode, *args, **kw)

    builtins.open = fake_kmsg_open
    try:
        guest.Gate.mark_dmesg(object())
        ok = check("mark-writes",
                   writes == ["<6>" + guest.PHASE_A_TRIGGER + "\n"],
                   repr(writes)[:120]) and ok
    except SystemExit as exc:
        ok = check("mark-writes", False,
                   "code=%r" % (exc.code,)) and ok
    finally:
        builtins.open = real_open

    def failing_open(path, mode="r", *args, **kw):
        if str(path) == "/dev/kmsg":
            raise OSError("read-only")
        return real_open(path, mode, *args, **kw)

    builtins.open = failing_open
    err = io.StringIO()
    code = None
    try:
        with contextlib.redirect_stderr(err):
            guest.Gate.mark_dmesg(object())
    except SystemExit as exc:
        code = exc.code
    finally:
        builtins.open = real_open
    ok = check("mark-fails-loud",
               code == 1 and "cannot mark dmesg" in err.getvalue(),
               "code=%r %s" % (code, err.getvalue().strip()[-80:])) \
        and ok

    tag = guest.PHASE_A_TRIGGER
    ok = check("mark-clean",
               "mv-oracle:" not in tag
               and "script complete" not in tag
               and "held-open" not in tag
               and "exit-release" not in tag
               and "ops=" not in tag,
               repr(tag)) and ok

    insmod_at = src.find("gate.insmod(")
    mark_at = src.find("gate.mark_dmesg(")
    ok = check("mark-wired",
               0 <= insmod_at < mark_at < wait_at,
               "insmod=%d mark=%d wait=%d"
               % (insmod_at, mark_at, wait_at)) and ok

    # RED/GREEN over the proven mechanism: pre-trigger dmesg
    # frames omit the trailing completion record (as live);
    # the mark publishes it, so later frames carry it. The
    # old wait-without-mark order times out on the stuck
    # stream; mark-then-wait passes on the same stream.
    published = []

    def stuck_open(path, mode="r", *args, **kw):
        if str(path) == "/dev/kmsg" and "w" in mode:
            published.append(True)
            return _Handle([])
        return real_open(path, mode, *args, **kw)

    def stuck_sh(args, timeout=30, **kw):
        if published:
            return _R(full)
        return _R(early)

    builtins.open = stuck_open
    guest.sh = stuck_sh
    err = io.StringIO()
    code = None
    try:
        with contextlib.redirect_stderr(err):
            guest.Gate.wait_oracle_complete(
                object(), timeout=0.02, interval=0.001)
    except SystemExit as exc:
        code = exc.code
    finally:
        guest.sh = real_sh
        builtins.open = real_open
    ok = check("mark-red-stuck",
               code == 1 and "never completed" in err.getvalue(),
               "code=%r" % (code,)) and ok

    builtins.open = stuck_open
    guest.sh = stuck_sh
    code = None
    try:
        guest.Gate.mark_dmesg(object())
        guest.Gate.wait_oracle_complete(
            object(), timeout=60, interval=0.001)
        ok = check("mark-green-published", True) and ok
    except SystemExit as exc:
        ok = check("mark-green-published", False,
                   "code=%r" % (exc.code,)) and ok
    finally:
        guest.sh = real_sh
        builtins.open = real_open
    return ok


def run_self_test(work=None):
    """Full offline suite: proofs plus unarmed checks. No boot."""
    print("lateattach self-test (unarmed, offline)")
    tmp = work or tempfile.mkdtemp(prefix="vmgate-lateattach-")
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
                "sha256": pins.LC_SHA256},
            "cp": {"path": str(
                REPO / "tests/vm/fixtures/aya/"
                       "swiotlb_copy.bpf.o"),
                "sha256": pins.CP_SHA256}}}
        ok = self_test_layouts(tmp, pairs) and ok
        ok = self_test_wrong_pair(pairs) and ok
        ok = self_test_stage(tmp) and ok
        ok = self_test_judges(tmp) and ok
        ok = self_test_manifest(tmp) and ok
        ok = self_test_manifest_seal(tmp) and ok
        ok = self_test_guest_argv(tmp) and ok
        ok = self_test_cmdline_budget(tmp) and ok
        ok = self_test_guest_inputs(tmp) and ok
        ok = self_test_identity() and ok
        ok = self_test_inputs_binding(tmp) and ok
        ok = self_test_verify_exports(tmp) and ok
        ok = self_test_receipt_drift(tmp) and ok
        ok = self_test_vng_argv(tmp) and ok
        ok = self_test_boot_tmpdir_guard(tmp) and ok
        ok = self_test_guest_completion_wait(tmp) and ok
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print("lateattach self-test: %s" % ("PASS" if ok else "FAIL"))
    return ok


# -- Armed run: one pinned boot, same kept judges ----------

def armed_preflight():
    """Resolve vng + harness versions; armed failures are fatal."""
    from test_attempt_capture import find_vng, gate_prefix
    from harness_env import check_harness_versions
    vng = find_vng()
    if not vng:
        print("FAIL vm-lateattach: armed but vng missing")
        return None
    try:
        harness = check_harness_versions(vng)
    except ValueError as exc:
        print("FAIL vm-lateattach: armed but %s" % (exc,))
        return None
    try:
        prefix, _env = gate_prefix()
    except Exception as exc:  # pytest.skip/fail raise here
        print("FAIL vm-lateattach: armed but %s" % (exc,))
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


def verify_exports(export):
    """Exact inventory + sidecar check; returns {ok, files, reasons}.

    The host-staged inputs doc shares the export dir but
    is not guest output: the binding check verifies it
    separately, so the guest inventory excludes it here.
    """
    names = EXPORT_NAMES["lateattach"]
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


def build_vng_argv(flight, export, exec_str):
    """vng command for the gate (host-tested wiring).

    Always verbose: that routes the guest console to the
    captured stderr instead of /dev/null, so a boot that
    never reaches the guest flow still leaves a console
    transcript in the host-guest.stderr.

    The --run version token pins the locked 7.0.14 row: a
    token-less --run would resolve the host kernel instead.

    The export reaches the launcher command raw, so its
    spelling is gated first.
    """
    check_shell_inert_path(export, "export path")
    cmd = flight["prefix"] + ["--run", core.VNG_TAG, "-m",
                              "6G", "--append",
                              "swiotlb=force", "--verbose"]
    cmd += ["--rwdir=/tmp/export=%s" % (export,),
            "--exec", exec_str]
    return cmd


def check_guest_inputs_binding(files, manifest, export):
    """Refuse unless the guest saw the exact staged bytes.

    Returns a reason list (empty ok): the guest-observed
    digest exported in input-verify.json must equal the
    manifest-bound digest, and the staged copy still in
    the export dir must hash the same.
    """
    try:
        observed = json.loads(
            files["input-verify.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return ["lateattach: input-verify unreadable: %s"
                % (exc,)]
    bad = []
    if observed.get("case") != "lateattach":
        bad.append("lateattach: input-verify names case %r"
                   % (observed.get("case"),))
    entry = manifest.get("guest_inputs", {}).get("lateattach",
                                                 {})
    if observed.get("guest_inputs_file") != entry.get("file"):
        bad.append("lateattach: guest saw inputs file %r, bound %r"
                   % (observed.get("guest_inputs_file"),
                      entry.get("file")))
    if observed.get("guest_inputs_sha256") \
            != entry.get("sha256"):
        bad.append("lateattach: guest-observed inputs digest "
                   "differs from the manifest binding")
    try:
        staged = sha_file(str(Path(export)
                              / core.GUEST_INPUTS_FILE))
    except OSError as exc:
        return sorted(bad + ["lateattach: staged inputs "
                             "unreadable: %s" % (exc,)])
    if staged != entry.get("sha256"):
        bad.append("lateattach: staged inputs bytes differ from "
                   "the manifest binding")
    return sorted(bad)


class _DuplicateMember(ValueError):
    """A manifest object repeated a member name."""


def _object_no_dupes(pairs):
    """Build a mapping, refusing repeated member names.

    The receipt retains the source manifest bytes, so a
    repeated member would stamp two values under one
    name; fail closed instead of silently keeping one.
    """
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateMember(
                "duplicate member %r" % (key,))
        obj[key] = value
    return obj


def check_manifest_receipt_drift(manifest_path, manifest,
                                 retained=None):
    """Refuse when the on-disk manifest drifts from the judged one.

    Returns a reason list (empty ok): the receipt path
    retains the on-disk manifest bytes, so a post-judgment
    mutation would stamp evidence the host never judged.
    The re-read must match the in-memory snapshot exactly,
    with no repeated member at any level. On success the
    exact validated bytes are stored as retained["raw"]
    when retained is not None, so the saver writes the
    judged bytes without re-reading the live path.
    """
    try:
        with open(manifest_path, "rb") as handle:
            raw = handle.read()
    except OSError as exc:
        return ["lateattach: receipt manifest unreadable: %s"
                % (exc,)]
    try:
        disk = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_object_no_dupes)
    except _DuplicateMember as exc:
        return ["lateattach: receipt manifest refused: %s"
                % (exc,)]
    except ValueError as exc:
        return ["lateattach: receipt manifest unreadable: %s"
                % (exc,)]
    if isinstance(disk, dict) and disk == manifest:
        if retained is not None:
            retained["raw"] = raw
        return []
    if isinstance(disk, dict):
        keys = sorted(key for key in set(disk) | set(manifest)
                      if disk.get(key) != manifest.get(key))
        detail = "fields %s" % (", ".join(keys),)
    else:
        detail = "top level is not a mapping"
    return ["lateattach: on-disk inputs manifest drifted from the "
            "judged snapshot (%s)" % (detail,)]


def save_case_receipts(out, tmp, export, files, names,
                       manifest, bad, metrics,
                       manifest_bytes):
    """Copy the receipt set; raises OSError on failure.

    The boot console transcript lands in the receipt as
    host-guest.stderr (the verbose boot routes the guest
    console to the captured stderr);
    host-guest-inputs.json pins the staged inputs bytes
    the guest had to see. manifest_bytes must be the
    validated judged bytes from check_manifest_receipt_drift,
    so the receipt keeps the judged bytes; the live
    manifest path is never re-read on the save path.
    """
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(files[name], out / name)
        shutil.copy2(export / ("%s.sha256" % name),
                     out / ("%s.sha256" % name))
    (out / "inputs.json").write_bytes(manifest_bytes)
    shutil.copy2(export / core.GUEST_INPUTS_FILE,
                 out / "host-guest-inputs.json")
    for name in ("boot.json", "guest.stdout",
                 "guest.stderr", "guest.exit"):
        shutil.copy2(tmp / name, out / ("host-%s" % name))
    (out / "host-verdict.json").write_text(json.dumps(
        {"verdict": "PASS" if not bad else "FAIL",
         "case": "lateattach", "reasons": bad,
         "metrics": metrics,
         "console_transcript": "host-guest.stderr",
         "runner_commit": manifest["runner_commit"],
         "consumer": manifest["consumer"],
         "candidate": manifest["candidate"],
         "oracle": manifest["oracle"],
         "guest": manifest["guest"],
         "profile": manifest["profile"]},
        indent=2, sort_keys=True) + "\n")


def assemble_boot(flight):
    """Assemble the one pinned guest boot; return parts.

    Returns (tmp, export, cmd, exec_str, projected): the
    caller stages the inputs doc into export, verifies the
    copy against the manifest binding, and only then runs
    cmd. Raises ValueError before anything spawns when the
    export spelling or the cmdline budget refuses.
    """
    guest_argv = build_guest_argv()
    exec_str = shlex.join(guest_argv)
    projected = project_cmdline_total(len(exec_str))
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-lateattach-boot-"))
    export = tmp / "export"
    export.mkdir()
    # The export reaches the launcher command raw, so its
    # spelling is gated before the boot is assembled.
    check_shell_inert_path(export, "export path")
    if cmdline_over_budget(len(exec_str)):
        (tmp / "boot.json").write_text(json.dumps(
            {"case": "lateattach", "refused": "cmdline budget",
             "exec_chars": len(exec_str),
             "projected_cmdline": projected,
             "cmdline_ceiling": COMMAND_LINE_SIZE,
             "exec_budget": GUEST_EXEC_BUDGET},
            indent=2, sort_keys=True) + "\n")
        raise ValueError(
            "guest argv projects to %d cmdline chars "
            "(exec %d chars, budget %d total / %d exec); "
            "refusal artifacts kept at %s"
            % (projected, len(exec_str), COMMAND_LINE_SIZE,
               GUEST_EXEC_BUDGET, tmp))
    cmd = build_vng_argv(flight, export, exec_str)
    return tmp, export, cmd, exec_str, projected


def armed_boot_case(args, manifest_path, manifest,
                    staged_inputs, flight):
    """Boot once, run both phases in-guest, judge host-side."""
    from vm_process import run_owned_guest
    names = EXPORT_NAMES["lateattach"]
    try:
        tmp, export, cmd, exec_str, projected = \
            assemble_boot(flight)
    except ValueError as exc:
        print("FAIL vm-lateattach: %s" % (exc,))
        return 1
    try:
        shutil.copyfile(staged_inputs,
                        export / core.GUEST_INPUTS_FILE)
        copied = sha_file(export / core.GUEST_INPUTS_FILE)
    except OSError as exc:
        print("FAIL vm-lateattach: staged inputs copy "
              "failed (%s); artifacts kept at %s"
              % (exc, tmp))
        return 1
    bound = manifest.get("guest_inputs", {}).get("lateattach",
                                                 {})
    if copied != bound.get("sha256"):
        print("FAIL vm-lateattach: staged inputs copy "
              "differs from the manifest binding; "
              "artifacts kept at %s" % (tmp,))
        return 1
    (tmp / "boot.json").write_text(json.dumps(
        {"case": "lateattach", "cmd": cmd, "manifest": manifest,
         "harness": flight["harness"],
         "exec_chars": len(exec_str),
         "projected_cmdline": projected,
         "cmdline_ceiling": COMMAND_LINE_SIZE,
         "exec_budget": GUEST_EXEC_BUDGET,
         "guest_inputs_sha256": copied},
        indent=2, sort_keys=True) + "\n")
    timeout = core.CASE_TIMEOUTS["lateattach"]
    try:
        proc = run_owned_guest(cmd, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        (tmp / "guest.stdout").write_text(exc.stdout or "")
        (tmp / "guest.stderr").write_text(exc.stderr or "")
        (tmp / "guest.exit").write_text("timeout")
        print("FAIL vm-lateattach: guest timed out after %ds; "
              "artifacts kept at %s" % (timeout, tmp))
        return 2
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        print("FAIL vm-lateattach: guest exit %d; artifacts "
              "kept at %s" % (proc.returncode, tmp))
        return 1
    verified = verify_exports(export)
    if not verified["ok"]:
        print("FAIL vm-lateattach: %s; artifacts kept at %s"
              % ("; ".join(verified["reasons"]), tmp))
        return 1
    bad, metrics = judge_lateattach(verified["files"],
                                    manifest)
    bad = sorted(bad + check_guest_inputs_binding(
        verified["files"], manifest, export))
    retained = {}
    drift_bad = check_manifest_receipt_drift(
        manifest_path, manifest, retained)
    if drift_bad:
        print("FAIL vm-lateattach: %s; artifacts kept at %s"
              % ("; ".join(drift_bad), tmp))
        return 1
    out = Path(args.out) / "lateattach"
    try:
        save_case_receipts(out, tmp, export,
                           verified["files"], names,
                           manifest, bad, metrics,
                           retained["raw"])
    except OSError as exc:
        print("FAIL vm-lateattach: receipt failed (%s); "
              "artifacts kept at %s" % (exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-lateattach: guest tmp kept at %s" % (tmp,))
    if bad:
        print("FAIL vm-lateattach: %s" % ("; ".join(bad),))
        return 1
    print("ok vm-lateattach PASS (%s)" % (out,))
    return 0


def armed_run(args):
    """Armed late-attach: one pinned boot, both phases."""
    if os.environ.get(ARM_ENV) != "1":
        print("FAIL vm-lateattach: armed run needs %s=1"
              % ARM_ENV)
        return 2
    if not args.out:
        print("FAIL vm-lateattach: armed needs --out")
        return 2
    if not getattr(args, "bundle", "") or not getattr(
            args, "candidate", ""):
        print("FAIL vm-lateattach: armed needs --bundle and "
              "--candidate")
        return 2
    if getattr(args, "expect_release", "") not in (
            "", core.EXPECT_RELEASE):
        print("FAIL vm-lateattach: conflicting --expect-release %r"
              % (args.expect_release,))
        return 2
    flight = armed_preflight()
    if flight is None:
        return 1
    cache_ok, cache_why, _ = verify_guest_cache()
    if not cache_ok:
        print("FAIL vm-lateattach: pinned guest cache refused: %s"
              % (cache_why,))
        return 1
    lock_dir = REPO / "build" / "vm"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("FAIL vm-lateattach: lock dir failed: %s" % (exc,))
        return 1
    # The run work dir lives under the repo build tree so
    # the guest resolves every input path identically; the
    # guest /tmp is a private overlay.
    work = Path(tempfile.mkdtemp(prefix="lateattach-",
                                 dir=str(lock_dir)))
    try:
        inputs = core.materialize(
            str(REPO), str(work / "inputs"), args.candidate,
            args.bundle)
        built = score.build_consumer()
        commit = core.git_head(str(REPO))
    except (ValueError, OSError) as exc:
        print("FAIL vm-lateattach: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        print("FAIL vm-lateattach: VM suite lease already owned; "
              "one live executor at a time")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    rc = 0
    try:
        try:
            guest_oracle.verify_fixture()
        except (ValueError, OSError) as exc:
            print("FAIL vm-lateattach: oracle fixture refused: %s"
                  % (exc,))
            return 1
        try:
            staged = core.stage_consumer(str(REPO), built)
        except (ValueError, OSError) as exc:
            print("FAIL vm-lateattach: %s" % exc)
            return 1
        manifest_path = work / "inputs.json"
        try:
            doc_path = write_guest_inputs_doc(
                str(work), manifest_path, staged, inputs,
                args.expect_release)
        except (ValueError, OSError) as exc:
            print("FAIL vm-lateattach: %s" % exc)
            return 1
        manifest = core.write_input_manifest(
            str(manifest_path), inputs,
            {"sha256": staged["sha256"],
             "build": staged["build"]},
            ["lateattach"], sys.argv, commit,
            guest_inputs={"lateattach": doc_path})
        reasons = core.verify_input_manifest(
            manifest, staged["path"])
        if reasons:
            print("FAIL vm-lateattach: %s" % "; ".join(reasons))
            shutil.rmtree(work, ignore_errors=True)
            return 1
        rc = armed_boot_case(args, manifest_path, manifest,
                             doc_path, flight)
    except Exception as exc:
        print("FAIL vm-lateattach: armed but %s" % (exc,))
        return 1
    finally:
        lease.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("vm-lateattach: work kept at %s" % (work,))
    return rc


# -- pytest entry points ------------------------------------------

def test_self_test_unarmed(tmp_path):
    assert run_self_test(work=str(tmp_path / "self"))


def test_armed_lateattach():
    import pytest
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip(
            "lateattach armed run needs MEMVEIL_VM_LATEATTACH=1")

    class Args:
        pass
    args = Args()
    args.out = os.environ.get(
        "MV_LATEATTACH_OUT",
        str(REPO / "build" / "vm" / "lateattach"))
    args.keep = os.environ.get("MV_LATEATTACH_KEEP", "") == "1"
    args.bundle = os.environ.get("MV_LATEATTACH_BUNDLE", "")
    args.candidate = os.environ.get(
        "MV_LATEATTACH_CANDIDATE", "")
    args.expect_release = os.environ.get(
        "MV_LATEATTACH_EXPECT_RELEASE", "")
    assert armed_run(args) == 0


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--out", default="")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--bundle", default="",
                        help="retained bundle tarball path "
                             "(required when armed)")
    parser.add_argument("--candidate", default="",
                        help="retained candidate.json path "
                             "(required when armed)")
    parser.add_argument("--expect-release", default="",
                        help="refuse unless the guest release "
                             "matches (must equal the pin)")
    args = parser.parse_args(argv)
    if args.self_test or not args.out:
        return 0 if run_self_test() else 1
    return armed_run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
