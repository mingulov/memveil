#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""L6 held-open runner: the live held-open leg on the battery shape.

Unarmed (default) the runner self-tests offline: seal-pin
derivation, the consumer build plus layout and gate
vectors, the retired-shape RED refusals (the --bridge
usage exit, build-tree inputs absent with no producer,
the fixture unreferenced by the old oracle sub, the
token-less boot), the ported GREEN wiring (the real CLI
shape, the staged-input manifest round-trip plus tampers,
the fixture feed, the pinned kernel selector), the
held-open choreography sequence, and judge preservation
on synthetic windows built through the real consumer
replay path. No boot, no privileges. Standalone:
`python3 tests/vm/test_heldopen.py [--self-test]`.

Probe-seal (--probe-seal with --bundle/--candidate)
re-runs the seal-dependent checks against explicit seal
bytes with no boot: full materialize, the manifest
round-trip, the complete preserved judge with the staged
sealed executable, and the kernel-selector dry-run
comparison.

Armed (MEMVEIL_VM_HELDOPEN=1 with --out, requiring a
live-VM lease) the runner boots the pinned guest once,
runs the held-open choreography, re-derives the verdict
host-side from the exported observations, and writes a
stamped receipt. --bundle/--candidate name the retained
seal explicitly and are required for every armed run;
--expect-release refuses when it conflicts with the pinned
guest release.
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
import battery_core as battery  # noqa: E402
import guest_oracle  # noqa: E402
import heldopen_core as core  # noqa: E402
import heldopen_guest  # noqa: E402
import heldopen_seal as seal  # noqa: E402
import stress_core as score  # noqa: E402
from capture_durability import check_shell_inert_path  # noqa: E402
from consume import (check_conservation, check_oracle_script,  # noqa: E402
                     compare_scripted, parse_consume_file,
                     parse_oracle_log)
from test_battery import (LAYOUT_WANT, oracle_script_log,  # noqa: E402
                          replay_consumer, scripted_wire)
from test_oracle_live import judge_oracle_comparison  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent
GUEST = REPO / "tests" / "vm" / "heldopen_guest.py"
ARM_ENV = "MEMVEIL_VM_HELDOPEN"

# The guest owns the canonical export inventory; the host
# judges exactly that list, never a private copy.
EXPORT_NAMES = heldopen_guest.export_names_for_case(core.CASE)

# Guest command-line budget, same derivation as the
# battery runner (vng base64-encodes the whole --exec
# payload into virtme.exec= on the guest kernel command
# line, bounded by the x86 COMMAND_LINE_SIZE of 2048).
COMMAND_LINE_SIZE = 2048
VNG_CMDLINE_OVERHEAD = 768
GUEST_EXEC_BUDGET = 960
# The real guest argv must project this far under the
# ceiling, so ordinary argv growth trips the offline test
# before it trips the kernel.
CMDLINE_HEADROOM = 400


def project_cmdline_total(exec_chars):
    """Projected kernel cmdline chars for an --exec payload."""
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


def heldopen_oracle_log(ops=4):
    """Synthetic oracle log with the real held-open shape.

    The scripted window plus the held-open note the last
    op logs at map time and the exit-release plus unloaded
    notes the unload path logs: exactly the shapes the
    live guest snapshot carries and the parser skips.
    """
    text = oracle_script_log(ops=ops)
    held = "[0.0] mv-oracle: op=%d mapping=%d held-open\n" \
        % (ops - 1, ops - 1)
    text = text.replace("[0.0] mv-oracle: script complete",
                        held + "[0.0] mv-oracle: script complete")
    text += "[0.0] mv-oracle: op=%d mapping=%d exit-release\n" \
        % (ops - 1, ops - 1)
    text += "[0.0] mv-oracle: unloaded\n"
    return text


# -- Host judges --------------------------------------------

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


def judge_case(files, manifest, work_dir):
    """Host re-derivation of the held-open leg; (reasons, metrics).

    The verdict is re-derived here from the exported
    observations through the preserved held-open judge;
    the guest exports carry no verdicts.
    """
    try:
        ident = json.loads(
            files["identity.json"].read_text())
    except (KeyError, ValueError, OSError) as exc:
        return (["heldopen: identity unreadable: %s" % exc],
                {})
    bad = judge_identity(ident, manifest)
    metrics = {}
    try:
        bad += judge_oracle_comparison(
            files, work_dir,
            manifest["binary"]["path"],
            manifest["profile"]["profile_id"])
    except (ValueError, OSError, KeyError) as exc:
        bad.append("heldopen: case files unreadable: %s"
                   % (exc,))
    return sorted(bad), metrics


# -- Offline self-test --------------------------------------

def self_test_seal_pins():
    """Seal pins are well-shaped; logic never branches on them."""
    ok = True
    pins = seal.candidate_pins()
    ok = check("pins-keys",
               sorted(pins) == ["bundle_manifest_sha256",
                                "bundle_sha256", "bundle_size",
                                "candidate_sha256", "files",
                                "schema", "source_commit",
                                "source_tree"],
               "%r" % (sorted(pins),)) and ok
    sha256 = [pins["candidate_sha256"],
              pins["bundle_manifest_sha256"],
              pins["bundle_sha256"]]
    sha256 += [pins["files"][member] for member in (
        "bpf/swiotlb_lifecycle.bpf.o",
        "bpf/swiotlb_copy.bpf.o",
        "bpf/swiotlb_attempt.bpf.o")]
    sha1 = [pins["source_commit"], pins["source_tree"]]

    def hexed(digests, size):
        return all(len(digest) == size and all(
            char in "0123456789abcdef" for char in digest)
            for digest in digests)
    ok = check("pins-hex",
               hexed(sha256, 64) and hexed(sha1, 40)) and ok
    ok = check("pins-size",
               type(pins["bundle_size"]) is int
               and pins["bundle_size"] > 0,
               "%r" % (pins["bundle_size"],)) and ok
    ok = check("pins-label",
               isinstance(seal.SEAL_LABEL, str)
               and seal.SEAL_LABEL.strip()
               == seal.SEAL_LABEL != "",
               "%r" % (seal.SEAL_LABEL,)) and ok
    return ok


def self_test_derived_pins():
    """Guest/oracle pins derive from their owners, not copies."""
    ok = True
    ok = check("derived-vng",
               core.VNG_TAG is battery.VNG_TAG
               and core.VNG_TAG == "v7.0.14",
               "%r" % (core.VNG_TAG,)) and ok
    ok = check("derived-vmlinuz",
               core.VMLINUZ_SHA256
               is battery.VMLINUZ_SHA256) and ok
    ok = check("derived-modules",
               core.MODULES_MANIFEST_SHA256
               is battery.MODULES_MANIFEST_SHA256) and ok
    ok = check("derived-release",
               core.EXPECT_RELEASE
               == battery.EXPECT_RELEASE
               == heldopen_guest.EXPECT_RELEASE
               == "7.0.14-070014-generic",
               "%r" % (core.EXPECT_RELEASE,)) and ok
    ok = check("derived-sites",
               core.LC_SITES == battery.LC_SITES
               and core.CP_SITES == battery.CP_SITES,
               "attach grammar drift") and ok
    ok = check("derived-guest-schema",
               core.GUEST_INPUTS_SCHEMA
               is heldopen_guest.GUEST_INPUTS_SCHEMA) and ok
    text = (REPO / "tests" / "vm" / "heldopen_core.py"
            ).read_text()
    ok = check("derived-oracle-refs",
               "guest_oracle.KO_SHA256" in text
               and "guest_oracle.GUEST_VERMAGIC" in text
               and "guest_oracle.GUEST_BTF_SHA256" in text
               and "guest_oracle.GUEST_RELEASE" in text,
               "oracle pins copied, not referenced") and ok
    ok = check("derived-seal-refs",
               "seal.candidate_pins()" in text
               and "seal.LC_SHA256" in text
               and "seal.CP_SHA256" in text,
               "seal pins copied, not referenced") and ok
    return ok


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
    fixture = str(REPO / "tests" / "vm" / "fixtures" / "aya" /
                  "swiotlb_lifecycle.bpf.o")
    proc = consumer_run(["--verify-layout", fixture,
                         "mv_lifecycle"])
    parsed = score.parse_verify_layout(proc.stdout)
    ok = check("build-sha-agrees",
               parsed["sha256"] == sha_file(fixture)
               == seal.LC_SHA256,
               "%r" % (parsed.get("sha256"),)) and ok
    return ok


def self_test_layouts():
    """Sealed-pair layouts verified against pinned bytes, offline."""
    rings = {"lc": "mv_lifecycle", "cp": "mv_copies"}
    paths = {
        "lc": str(REPO / "tests" / "vm" / "fixtures" / "aya" /
                  "swiotlb_lifecycle.bpf.o"),
        "cp": str(REPO / "tests" / "vm" / "fixtures" / "aya" /
                  "swiotlb_copy.bpf.o"),
    }
    ok = True
    for channel, want in (("lc", LAYOUT_WANT[("c9", "lc")]),
                          ("cp", LAYOUT_WANT[("c9", "cp")])):
        proc = consumer_run(["--verify-layout",
                             paths[channel],
                             rings[channel]])
        parsed = score.parse_verify_layout(proc.stdout)
        tag = "layout-sealed-%s" % channel
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
                   == sha_file(paths[channel])
                   == {"lc": seal.LC_SHA256,
                       "cp": seal.CP_SHA256}[channel]) and ok
    proc = consumer_run(["--verify-layout", paths["cp"],
                         "mv_lifecycle"])
    ok = check("layout-cross-channel",
               proc.returncode == 1
               and "neither family" in proc.stdout,
               "exit=%d" % proc.returncode) and ok
    return ok


def self_test_red_bridge():
    """RED: the retired --bridge shape exits 2 on the consumer."""
    ok = True
    retired = (REPO / "tests" / "vm" / "guest_lifecycle.py"
               ).read_text()
    start = retired.find("def start_consumer")
    block = retired[start:retired.find("\n    def ", start)]
    ok = check("red-bridge-retired-shape",
               '"--bridge"' in block,
               "retired shape moved") and ok
    obj = str(REPO / "tests" / "vm" / "fixtures" / "aya" /
              "swiotlb_lifecycle.bpf.o")
    proc = consumer_run(["--bridge", "bridge", obj,
                         "mv_lifecycle", core.LC_SITES,
                         "1", os.path.join(
                             tempfile.gettempdir(),
                             "heldopen-never-written")])
    ok = check("red-bridge-exit2",
               proc.returncode == 2,
               "exit=%d %s" % (proc.returncode,
                               proc.stdout.strip()[-120:])) \
        and ok
    ported = (REPO / "tests" / "vm" / "heldopen_guest.py"
              ).read_text()
    ok = check("red-bridge-absent-ported",
               "--bridge" not in ported,
               "bridge survives in the port") and ok
    return ok


def self_test_green_cli():
    """GREEN: the ported argv uses the real CLI, gates fire first."""
    ok = True
    text = (REPO / "tests" / "vm" / "heldopen_guest.py"
            ).read_text()
    markers = ['"--expect-family", "aya"',
               '"--expect-sha256", expect_sha',
               "obj, ring,", "sites, str(seconds), out"]
    at = []
    pos = text.find("def start_consumer")
    for marker in markers:
        pos = text.find(marker, pos + 1)
        at.append(pos)
    ok = check("green-cli-shape",
               all(pos >= 0 for pos in at),
               "%r" % (at,)) and ok
    obj = str(REPO / "tests" / "vm" / "fixtures" / "aya" /
              "swiotlb_lifecycle.bpf.o")
    never = os.path.join(tempfile.gettempdir(),
                         "heldopen-never-written")
    cases = [
        ("family-swap",
         ["--expect-family", "c", obj, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "family mismatch"),
        ("digest-wrong",
         ["--expect-sha256", "0" * 64, obj, "mv_lifecycle",
          core.LC_SITES, "1", never],
         "digest mismatch"),
        ("sites-short",
         [obj, "mv_lifecycle", "mv_map_result:x",
          "1", never],
         "exactly the mv_lifecycle program set"),
    ]
    for name, argv, want in cases:
        proc = consumer_run(argv)
        ok = check("green-gate-%s" % name,
                   proc.returncode == 1
                   and want in proc.stdout,
                   "exit=%d %s" % (proc.returncode,
                                   proc.stdout.strip()[
                                       -160:])) and ok
    return ok


def self_test_red_buildtree():
    """RED: old build-tree inputs absent with no producer."""
    ok = True
    ok = check("red-noprog",
               not os.path.isdir(str(
                   REPO / "bpf" / "programs")),
               "bpf/programs exists") and ok
    sys.path.insert(0, str(REPO / "tests" / "vm"))
    import lifecycle_env
    for label, path in (
            ("lifecycle", lifecycle_env.LIFECYCLE_PROBE),
            ("copy", lifecycle_env.COPY_PROBE),
            ("consumer", lifecycle_env.CONSUMER)):
        ok = check("red-absent-%s" % label,
                   not os.path.isfile(path),
                   "staged at %s" % path) and ok
    retired = (REPO / "tests" / "vm" / "test_oracle_live.py"
               ).read_text()
    ok = check("red-refusal-kept",
               "armed but missing" in retired,
               "retired refusal moved") and ok
    for name in ("heldopen_guest.py", "heldopen_core.py",
                 "heldopen_seal.py"):
        text = (REPO / "tests" / "vm" / name).read_text()
        ok = check("green-nobuild-%s" % name,
                   "build/" not in text,
                   "build-tree reference") and ok
    # The RED checks above necessarily name the retired
    # paths, so this runner is excluded here; the port's
    # freedom from them is proven behaviorally (every GREEN
    # check passes with the retired paths absent).
    for name in ("heldopen_guest.py", "heldopen_core.py",
                 "heldopen_seal.py"):
        text = (REPO / "tests" / "vm" / name).read_text()
        ok = check("green-noretired-inputs-%s" % name,
                   "LIFECYCLE_PROBE" not in text
                   and "COPY_PROBE" not in text
                   and "mv_consume" not in text
                   and "build/memveil" not in text,
                   "retired input reference") and ok
    return ok


def self_test_red_localko():
    """RED: the fixture feeds no old oracle-sub path."""
    ok = True
    for name in ("test_oracle_live.py", "vm_boot.py",
                 "lifecycle_env.py"):
        text = (REPO / "tests" / "vm" / name).read_text()
        ok = check("red-unreferenced-%s" % name,
                   "fixtures/ko" not in text,
                   "oracle-fixture reference appeared") and ok
    retired = (REPO / "tests" / "vm" / "guest_lifecycle.py"
               ).read_text()
    ok = check("red-localko-default",
               '"build", "vm", "oracle"' in retired,
               "retired ko path moved") and ok
    return ok


def self_test_green_fixture():
    """GREEN: the fixture verifies and feeds the port."""
    ok = True
    try:
        receipt = guest_oracle.verify_fixture()
    except (ValueError, OSError) as exc:
        return check("green-fixture-verify", False,
                     str(exc)[:160])
    ok = check("green-fixture-verify",
               receipt.get("target_release")
               == guest_oracle.GUEST_RELEASE) and ok
    try:
        magic = guest_oracle.vermagic_from_bytes(
            guest_oracle.FIXTURE_KO)
    except ValueError as exc:
        return check("green-fixture-vermagic", False,
                     str(exc)[:160])
    ok = check("green-fixture-vermagic",
               magic == guest_oracle.GUEST_VERMAGIC,
               "%r" % (magic,)) and ok
    with open(guest_oracle.FIXTURE_KO, "rb") as handle:
        blob = handle.read()
    for needle in (b"held-open", b"exit-release",
                   b"mv_oracle_arm", b"mv_oracle_delay_ms"):
        ok = check("green-fixture-%s" % needle.decode(),
                   needle in blob, "missing") and ok
    source_sha = sha_file(str(
        REPO / "tests" / "kernel" / "memveil_dma_oracle.c"))
    ok = check("green-fixture-source",
               receipt.get("oracle_source_sha256")
               == source_sha,
               "fixture predates the source") and ok
    doc = build_guest_inputs(
        "/w/inputs.json",
        {"path": "/w/stress-consume", "sha256": "c" * 64},
        synth_inputs(), "")
    ok = check("green-fixture-feed",
               doc["ko"]["path"] == guest_oracle.FIXTURE_KO
               and doc["ko"]["sha256"]
               == guest_oracle.KO_SHA256,
               "%r" % (doc.get("ko"),)) and ok
    return ok


def self_test_red_tokenless():
    """RED: the old boot assembles a token-less --run."""
    ok = True
    text = (REPO / "tests" / "vm" / "vm_boot.py").read_text()
    ok = check("red-tokenless-shape",
               '"--run", "-m"' in text,
               "old boot shape moved") and ok
    return ok


# -- Guest wiring (host-tested) -------------------------------

def build_guest_inputs(manifest_path, built, inputs,
                       expect_release):
    """Staged inputs doc for the held-open leg (host-tested).

    Carries every path and digest the guest flow verifies;
    the host writes these exact bytes to the shared export
    dir and binds their digest in the run manifest, while
    the guest command line carries only the pointer
    filename.
    """
    return {
        "schema": core.GUEST_INPUTS_SCHEMA,
        "case": core.CASE,
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
    }


def write_guest_inputs_doc(work, manifest_path, built, inputs,
                           expect_release):
    """Stage the inputs doc; return its path."""
    blob = (json.dumps(build_guest_inputs(
        manifest_path, built, inputs, expect_release),
        indent=2, sort_keys=True) + "\n").encode("utf-8")
    doc_path = os.path.join(work, "guest-inputs-%s.json"
                            % core.CASE)
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


def build_vng_argv(flight, export, exec_str):
    """vng command for the held-open leg (host-tested wiring).

    Always verbose: that routes the guest console to the
    captured stderr instead of /dev/null, so a boot that
    never reaches the guest flow still leaves a console
    transcript in the host-guest.stderr.

    The kernel selector is pinned: only the battery's vng
    tag boots, validated as a plain release token first.
    The export reaches the launcher command raw, so its
    spelling is gated first.
    """
    from kernel_matrix import validate_vng_token
    check_shell_inert_path(export, "export path")
    validate_vng_token(core.VNG_TAG, "kernel selector")
    return flight["prefix"] + ["--run", core.VNG_TAG, "-m",
                               "6G", "--append",
                               "swiotlb=force", "--verbose",
                               "--rwdir=/tmp/export=%s"
                               % (export,),
                               "--exec", exec_str]


def synth_inputs():
    """Self-consistent inputs dict for offline doc tests."""
    return {
        "lc": {"path": "/w/lc.o",
               "sha256": seal.LC_SHA256},
        "cp": {"path": "/w/cp.o",
               "sha256": seal.CP_SHA256},
    }


def self_test_green_selector():
    """GREEN: the boot carries the pinned kernel selector."""
    ok = True
    flight = {"prefix": ["vng"], "harness": {}}
    try:
        argv = build_vng_argv(flight, "/tmp/x",
                             "exec payload")
    except ValueError as exc:
        return check("selector-shape", False, str(exc)[:160])
    at = argv.index("--run")
    ok = check("selector-pinned",
               argv[at + 1] == "v7.0.14"
               == core.VNG_TAG,
               " ".join(argv)) and ok
    ok = check("selector-microvm",
               "--disable-microvm" not in argv
               and "--network" not in argv
               and "--verbose" in argv,
               " ".join(argv)) and ok
    ok = check("selector-rwdir",
               "--rwdir=/tmp/export=/tmp/x" in argv
               and argv[-2:] == ["--exec", "exec payload"],
               " ".join(argv[-2:])) and ok
    for num, evil in enumerate(('/tmp/x"y', "/tmp/has space",
                                "/tmp/o$(touch_x)",
                                "/tmp/a;b")):
        try:
            build_vng_argv(flight, evil, "exec payload")
            ok = check("selector-spelling-%d" % num, False,
                       "accepted %r" % evil) and ok
        except ValueError:
            ok = check("selector-spelling-%d" % num, True) \
                and ok
    return ok


class _FakeProc:
    """Recording stand-in for a started consumer."""

    def __init__(self, tag):
        self.tag = tag


class _FakeGate:
    """Recording stand-in proving the choreography order."""

    def __init__(self):
        self.calls = []
        self.work = "/w"
        self.lc_obj = "/w/lc.o"
        self.cp_obj = "/w/cp.o"
        self.lc_sha = seal.LC_SHA256
        self.cp_sha = seal.CP_SHA256

    def write_json(self, name, doc):
        self.calls.append(("write_json", name))

    def identity(self):
        return {"release": "fake"}

    def clear_dmesg(self):
        self.calls.append(("clear_dmesg",))

    def start_consumer(self, obj, ring, sites, seconds,
                       out, expect_sha):
        self.calls.append(("start_consumer", obj, ring,
                           sites, seconds, out,
                           expect_sha))
        return _FakeProc(out)

    def wait_ready(self, procs):
        self.calls.append(("wait_ready",
                           [proc.tag for proc in procs]))

    def insmod(self, params):
        self.calls.append(("insmod", list(params)))

    def rmmod(self):
        self.calls.append(("rmmod",))

    def wait_consumer(self, proc, tag):
        self.calls.append(("wait_consumer", proc.tag, tag))

    def oracle_log(self, name):
        self.calls.append(("oracle_log", name))

    def export(self, names):
        self.calls.append(("export", list(names)))


def _choreography_statements():
    """Callee sequence of run_heldopen, plus sleep/insmod args."""
    text = (REPO / "tests" / "vm" / "heldopen_guest.py"
            ).read_text()
    module = ast.parse(text)
    func = next(node for node in ast.walk(module)
                if isinstance(node, ast.FunctionDef)
                and node.name == "run_heldopen")
    names = []
    detail = {}
    for stmt in func.body:
        call = stmt.value if isinstance(
            stmt, ast.Assign) else stmt.value if isinstance(
                stmt, ast.Expr) else None
        if isinstance(call, ast.Constant):
            names.append("doc")
            continue
        if not isinstance(call, ast.Call):
            names.append("?")
            continue
        target = call.func
        if isinstance(target, ast.Attribute):
            names.append(target.attr)
        elif isinstance(target, ast.Name):
            names.append(target.id)
        else:
            names.append("?")
        if names[-1] == "sleep":
            detail["sleep"] = [ast.literal_eval(arg)
                               for arg in call.args]
        if names[-1] == "insmod":
            detail["insmod"] = [ast.literal_eval(arg)
                                for arg in call.args]
        if names[-1] == "print":
            detail["print"] = True
    return names, detail


def self_test_choreography():
    """Held-open steps run in order with the retired timings."""
    ok = True
    gate = _FakeGate()
    heldopen_guest.run_heldopen(gate)
    names = [call[0] for call in gate.calls]
    ok = check("choreo-order",
               names == ["write_json", "clear_dmesg",
                         "start_consumer", "start_consumer",
                         "wait_ready", "insmod", "rmmod",
                         "wait_consumer", "wait_consumer",
                         "oracle_log", "export"],
               "%r" % (names,)) and ok
    starts = [call for call in gate.calls
              if call[0] == "start_consumer"]
    ok = check("choreo-consumers",
               starts[0][1:] == ("/w/lc.o", "mv_lifecycle",
                                 core.LC_SITES, 25,
                                 "/w/cmp-lc.txt",
                                 seal.LC_SHA256)
               and starts[1][1:] == (
                   "/w/cp.o", "mv_copies", core.CP_SITES,
                   25, "/w/cmp-cp.txt", seal.CP_SHA256),
               "%r" % (starts,)) and ok
    ok = check("choreo-insmod",
               ("insmod", ["mv_oracle_delay_ms=100"])
               in gate.calls,
               "%r" % (gate.calls,)) and ok
    waits = [call for call in gate.calls
             if call[0] == "wait_consumer"]
    ok = check("choreo-waits",
               [call[2] for call in waits] == [
                   "heldopen-cmp-lc", "heldopen-cmp-cp"],
               "%r" % (waits,)) and ok
    ok = check("choreo-exports",
               ("export", EXPORT_NAMES) in gate.calls
               and EXPORT_NAMES == [
                   "identity.json", "input-verify.json",
                   "cmp-lc.txt", "cmp-cp.txt",
                   "cmp-oracle.log"],
               "%r" % (EXPORT_NAMES,)) and ok
    names, detail = _choreography_statements()
    ok = check("choreo-static-order",
               names == ["doc", "write_json", "clear_dmesg",
                         "join", "join",
                         "start_consumer", "start_consumer",
                         "wait_ready", "insmod", "sleep",
                         "rmmod", "wait_consumer",
                         "wait_consumer", "oracle_log",
                         "export", "print"],
               "%r" % (names,)) and ok
    ok = check("choreo-hold",
               detail.get("sleep") == [5]
               and detail.get("insmod")
               == [["mv_oracle_delay_ms=100"]],
               "%r" % (detail,)) and ok
    try:
        heldopen_guest.export_names_for_case("bogus")
        ok = check("choreo-bogus", False, "accepted") and ok
    except ValueError:
        ok = check("choreo-bogus", True) and ok
    return ok


def self_test_guest_argv():
    """Guest argv carries only the staged inputs pointer."""
    ok = True
    argv = build_guest_argv()
    joined = " ".join(argv)
    ok = check("argv-pointer",
               argv[-2:] == ["--inputs",
                            core.GUEST_INPUTS_FILE]
               and "--bridge" not in joined
               and not re.search(r"[0-9a-f]{64}", joined),
               joined[-160:]) and ok
    total = project_cmdline_total(len(shlex.join(argv)))
    ok = check("argv-budget",
               total <= COMMAND_LINE_SIZE - CMDLINE_HEADROOM,
               "projects %d (ceiling %d)" % (
                   total, COMMAND_LINE_SIZE)) and ok
    ok = check("budget-arithmetic",
               project_cmdline_total(GUEST_EXEC_BUDGET)
               == COMMAND_LINE_SIZE
               and project_cmdline_total(
                   GUEST_EXEC_BUDGET + 1)
               == COMMAND_LINE_SIZE + 4) and ok
    for length, want in ((0, False),
                         (GUEST_EXEC_BUDGET - 1, False),
                         (GUEST_EXEC_BUDGET, False),
                         (GUEST_EXEC_BUDGET + 1, True)):
        try:
            over = cmdline_over_budget(length)
            ok = check("budget-%d" % length, over == want,
                       "over=%s want=%s" % (over, want)) \
                and ok
        except ValueError as exc:
            ok = check("budget-%d" % length, False,
                       str(exc)[:160]) and ok
    return ok


def self_test_guest_inputs(tmp):
    """Inputs docs stage, parse, bind, and refuse tampering."""
    ok = True
    built = {"path": "/w/stress-consume",
             "sha256": "c" * 64}
    inputs = synth_inputs()
    doc = build_guest_inputs("/w/inputs.json", built, inputs,
                             "")
    ok = check("inputs-doc",
               doc["schema"] == core.GUEST_INPUTS_SCHEMA
               and doc["case"] == core.CASE
               and doc["lc"]["sha256"] == seal.LC_SHA256
               and doc["cp"]["sha256"] == seal.CP_SHA256
               and doc["ko"]["sha256"]
               == guest_oracle.KO_SHA256
               and doc["consumer"]["sha256"] == "c" * 64,
               "%r" % (sorted(doc),)) and ok
    try:
        staged = write_guest_inputs_doc(
            tmp, "/w/inputs.json", built, inputs, "")
    except (ValueError, OSError) as exc:
        return check("inputs-stage", False, str(exc)[:160])
    ok = check("inputs-stage", os.path.isfile(staged)) and ok
    export = os.path.join(tmp, "export")
    os.makedirs(export, exist_ok=True)
    staged_copy = os.path.join(export, core.GUEST_INPUTS_FILE)
    shutil.copyfile(staged, staged_copy)
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
                core.CASE: {
                    "file": core.GUEST_INPUTS_FILE,
                    "sha256": sha_file(staged_copy),
                },
            },
        }))
    try:
        fields, observed = heldopen_guest.parse_guest_inputs(
            export, core.GUEST_INPUTS_FILE)
        ok = check("inputs-parse",
                   fields["case"] == core.CASE
                   and fields["lc_sha"] == seal.LC_SHA256
                   and fields["manifest"] == manifest_path
                   and observed == sha_file(staged_copy),
                   observed[:16]) and ok
    except ValueError as exc:
        ok = check("inputs-parse", False,
                   str(exc)[:160]) and ok
    with open(staged_copy, "ab") as handle:
        handle.write(b" ")
    try:
        heldopen_guest.parse_guest_inputs(
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
            heldopen_guest.parse_guest_inputs(export, name)
            ok = check("inputs-pointer-%s" % label, False,
                       "accepted") and ok
        except ValueError as exc:
            ok = check("inputs-pointer-%s" % label,
                       "bare filename" in str(exc),
                       str(exc)[:160]) and ok
    # A manifest binding a different filename refuses: the
    # guest must see exactly the staged doc, not a swapped
    # pointer to another file.
    export2 = os.path.join(tmp, "export2")
    os.makedirs(export2, exist_ok=True)
    shutil.copyfile(staged, os.path.join(
        export2, core.GUEST_INPUTS_FILE))
    manifest2_path = os.path.join(tmp, "manifest2.json")
    with open(os.path.join(export2,
                           core.GUEST_INPUTS_FILE), "r+b") \
            as handle:
        raw = handle.read().replace(
            b"/w/inputs.json", manifest2_path.encode())
        handle.seek(0)
        handle.write(raw)
        handle.truncate()
    with open(manifest2_path, "w") as handle:
        handle.write(json.dumps({
            "guest_inputs": {
                core.CASE: {
                    "file": "other-inputs.json",
                    "sha256": sha_file(os.path.join(
                        export2, core.GUEST_INPUTS_FILE)),
                },
            },
        }))
    try:
        heldopen_guest.parse_guest_inputs(
            export2, core.GUEST_INPUTS_FILE)
        ok = check("inputs-file-mismatch", False,
                   "accepted") and ok
    except ValueError as exc:
        ok = check("inputs-file-mismatch",
                   "not the bound doc" in str(exc),
                   str(exc)[:160]) and ok
    return ok


def synth_full_inputs(tmp):
    """Hermetic inputs binding real tree bytes, no seal needed.

    The lifecycle/copy objects are the committed Aya
    fixtures (which hash to the seal pins); the binary and
    profile are synthetic temp files whose measured shas
    the synthetic candidate binding carries. Everything
    the manifest binds is re-hashed from these bytes, so
    the round-trip and the tamper matrix run fully
    offline, including in CI.
    """
    binary_path = os.path.join(tmp, "syn-memveil")
    with open(binary_path, "wb") as handle:
        handle.write(b"heldopen-synth-binary")
    os.chmod(binary_path, 0o755)
    profile_path = os.path.join(tmp, "syn-profile.json")
    with open(profile_path, "w") as handle:
        handle.write(json.dumps(
            {"profile_id": "syn-profile"}) + "\n")
    candidate = {
        "schema": seal.CANDIDATE_SCHEMA,
        "source": {"commit": seal.SOURCE_COMMIT,
                   "tree": seal.SOURCE_TREE},
        "bundle_manifest_sha256":
            seal.BUNDLE_MANIFEST_SHA256,
        "files": {
            "bpf/swiotlb_lifecycle.bpf.o": seal.LC_SHA256,
            "bpf/swiotlb_copy.bpf.o": seal.CP_SHA256,
            "bpf/swiotlb_attempt.bpf.o":
                seal.ATTEMPT_SHA256,
            seal.BINARY_MEMBER: sha_file(binary_path),
            seal.PROFILE_MEMBER: sha_file(profile_path),
        },
        "bundle": {"sha256": seal.BUNDLE_SHA256,
                   "size": seal.BUNDLE_SIZE},
    }
    return {
        "binary": {"path": binary_path,
                   "sha256": sha_file(binary_path)},
        "lc": {"path": str(REPO / "tests" / "vm"
                            / "fixtures" / "aya"
                            / "swiotlb_lifecycle.bpf.o"),
               "sha256": seal.LC_SHA256},
        "cp": {"path": str(REPO / "tests" / "vm"
                            / "fixtures" / "aya"
                            / "swiotlb_copy.bpf.o"),
               "sha256": seal.CP_SHA256},
        "profile": {"path": profile_path,
                    "sha256": sha_file(profile_path),
                    "profile_id": "syn-profile"},
        "candidate": candidate,
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
        inputs = synth_full_inputs(tmp)
    except (ValueError, OSError) as exc:
        return check("manifest-inputs", False,
                     str(exc)[:200])
    ok = check("manifest-inputs",
               inputs["oracle"]["ko_sha256"]
               == guest_oracle.KO_SHA256
               and inputs["guest"]["vng_tag"]
               == core.VNG_TAG) and ok
    commit = core.git_head(str(REPO))
    try:
        staged = write_guest_inputs_doc(
            tmp, os.path.join(tmp, "inputs.json"), built,
            inputs, "")
    except (ValueError, OSError) as exc:
        return check("manifest-inputs-stage", False,
                     str(exc)[:200])
    manifest = core.write_input_manifest(
        os.path.join(tmp, "inputs.json"), inputs,
        {"sha256": built["sha256"], "build": built["build"]},
        ["test_heldopen", "--self-test"], commit,
        guest_inputs={core.CASE: staged})
    reasons = core.verify_input_manifest(manifest,
                                         built["path"])
    ok = check("manifest-verify", reasons == [],
               "; ".join(reasons[:2])) and ok
    ok = check("manifest-identity",
               manifest["schema"] == core.SCHEMA
               and manifest["seal"] == seal.SEAL_LABEL
               and manifest["cases"] == [core.CASE]
               and manifest["runner_commit"] == commit
               and manifest["guest_inputs"][core.CASE][
                   "file"] == core.GUEST_INPUTS_FILE) and ok
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
    tampers.append(("seal",
                    tampered(["seal"], "bogus")))
    tampers.append(("schema",
                    tampered(["schema"], "bogus/0")))
    tampers.append(("cases",
                    tampered(["cases"], ["bogus"])))
    tampers.append(("consumer",
                    tampered(["consumer", "binary_sha256"],
                             "0" * 64)))
    tampers.append(("binary",
                    tampered(["binary", "sha256"], "0" * 64)))
    tampers.append(("lc-bytes",
                    tampered(["objects", "lc", "sha256"],
                             "0" * 64)))
    tampers.append(("cp-bytes",
                    tampered(["objects", "cp", "sha256"],
                             "0" * 64)))
    tampers.append(("profile",
                    tampered(["profile", "sha256"], "0" * 64)))
    tampers.append(("profile-id",
                    tampered(["profile", "profile_id"], "")))
    tampers.append(("oracle",
                    tampered(["oracle", "ko_sha256"],
                             "0" * 64)))
    tampers.append(("guest",
                    tampered(["guest", "vmlinuz_sha256"],
                             "0" * 64)))
    tampers.append(("candidate-source",
                    tampered(["candidate", "source",
                              "commit"], "0" * 64)))
    tampers.append(("candidate-tree",
                    tampered(["candidate", "source",
                              "tree"], "0" * 40)))
    tampers.append(("bundle-manifest",
                    tampered(["candidate",
                              "bundle_manifest_sha256"],
                             "0" * 64)))
    tampers.append(("bundle",
                    tampered(["candidate", "bundle",
                              "sha256"], "0" * 64)))
    tampers.append(("bundle-size",
                    tampered(["candidate", "bundle",
                              "size"], 1)))
    tampers.append(("guest-inputs",
                    tampered(["guest_inputs", core.CASE,
                              "sha256"], "0" * 64)))
    for name, other in tampers:
        reasons = core.verify_input_manifest(
            other, built["path"])
        ok = check("manifest-tamper-%s" % name,
                   reasons != [],
                   "tamper passed") and ok
    # Malformed shapes refuse instead of crashing.
    nulls = tampered(["objects"], None)
    reasons = core.verify_input_manifest(nulls, built["path"])
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


def synth_manifest():
    """Self-consistent manifest for synthetic judgments."""
    return {
        "oracle": {"ko_sha256": guest_oracle.KO_SHA256},
        "objects": {
            "lc": {"sha256": seal.LC_SHA256},
            "cp": {"sha256": seal.CP_SHA256},
        },
    }


def synth_identity():
    """Self-consistent guest identity for synthetic judgments."""
    return {"release": core.EXPECT_RELEASE,
            "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
            "digests": {"ko": guest_oracle.KO_SHA256,
                        "lc": seal.LC_SHA256,
                        "cp": seal.CP_SHA256}}


def self_test_guest_identity_gate():
    """Guest-side identity gate passes clean, refuses drift."""
    ok = True
    ident = synth_identity()
    oracle = {"ko_sha256": guest_oracle.KO_SHA256,
              "btf_sha256": guest_oracle.GUEST_BTF_SHA256}
    try:
        heldopen_guest.check_identity(
            ident, guest_oracle.KO_SHA256, oracle)
        ok = check("guest-gate-clean", True) and ok
    except ValueError as exc:
        ok = check("guest-gate-clean", False,
                   str(exc)[:160]) and ok
    cases = [
        ("release", dict(ident, release="bogus"),
         guest_oracle.KO_SHA256, oracle),
        ("btf", dict(ident, btf_sha256="0" * 64),
         guest_oracle.KO_SHA256, oracle),
        ("ko", ident, "0" * 64, oracle),
        ("pins", ident, guest_oracle.KO_SHA256, {}),
    ]
    for name, doc, ko, pins in cases:
        try:
            heldopen_guest.check_identity(doc, ko, pins)
            ok = check("guest-gate-%s" % name, False,
                       "drift passed") and ok
        except ValueError:
            ok = check("guest-gate-%s" % name, True) and ok
    return ok


def self_test_identity():
    """Identity re-checks pass clean and catch every drift."""
    ok = True
    ok = check("identity-clean",
               judge_identity(synth_identity(),
                              synth_manifest()) == []) and ok
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
        bad = judge_identity(ident, synth_manifest())
        ok = check("identity-drift-%s" % name, bad != [],
                   "drift passed") and ok
    return ok


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


def window_reasons(files):
    """Preserved window checks without the report step."""
    lc, lc_sum = parse_consume_file(str(files["cmp-lc.txt"]))
    cp, cp_sum = parse_consume_file(str(files["cmp-cp.txt"]))
    bad = check_conservation(lc, lc_sum, "cmp-lc")
    bad += check_conservation(cp, cp_sum, "cmp-cp")
    ops_log, releases, complete = parse_oracle_log(
        str(files["cmp-oracle.log"]))
    bad += check_oracle_script(ops_log, releases, complete,
                               4, -1, "cmp")
    bad += compare_scripted(lc, cp, 4, -1, "cmp")
    return sorted(bad)


def self_test_judge_window(tmp):
    """Window half of the preserved judge, plus negatives."""
    ok = True
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    files = synth_window_files(tmp, "cmp", lc_wire,
                               lc_counts, cp_wire, cp_counts,
                               heldopen_oracle_log())
    bad = window_reasons(files)
    ok = check("judge-window", bad == [],
               "; ".join(bad[:3])) and ok
    # The held-open/exit-release/unloaded notes the live
    # guest carries parse cleanly.
    ops_log, releases, complete = parse_oracle_log(
        str(files["cmp-oracle.log"]))
    ok = check("judge-window-heldopen",
               complete == 4 and sorted(releases)
               == [0, 1, 2, 3],
               "%r %r" % (complete,
                           sorted(releases))) and ok
    # Dropped probe records fail the window.
    lc_d, lc_dc, cp_d, cp_dc = scripted_wire(drop_lc=(0,))
    files = synth_window_files(tmp, "cmp", lc_d, lc_dc,
                               cp_d, cp_dc,
                               heldopen_oracle_log())
    ok = check("judge-window-drop",
               window_reasons(files) != [],
               "loss passed") and ok
    # A cleared skip bit fails the flag rules.
    lc_f, lc_fc, cp_f, cp_fc = scripted_wire(skip_flip=(1,))
    files = synth_window_files(tmp, "cmp", lc_f, lc_fc,
                               cp_f, cp_fc,
                               heldopen_oracle_log())
    ok = check("judge-window-skip",
               window_reasons(files) != [],
               "flag flip passed") and ok
    # A missing release fails the script check.
    text = heldopen_oracle_log().replace(
        "[0.0] mv-oracle: mapping=3 release "
        "lifetime_ns=1003\n", "")
    files = synth_window_files(tmp, "cmp", lc_wire,
                               lc_counts, cp_wire, cp_counts,
                               text)
    ok = check("judge-window-release",
               window_reasons(files) != [],
               "missing release passed") and ok
    return ok


def _judge_calls():
    """Call-arg facts of the extracted preserved judge."""
    text = (REPO / "tests" / "vm" / "test_oracle_live.py"
            ).read_text()
    module = ast.parse(text)
    func = next(node for node in ast.walk(module)
                if isinstance(node, ast.FunctionDef)
                and node.name == "judge_oracle_comparison")
    calls = {}
    for node in ast.walk(func):
        if not isinstance(node, ast.Call):
            continue
        target = node.func
        name = target.id if isinstance(target, ast.Name) \
            else None
        if name in ("check_oracle_script", "compare_scripted",
                    "translate_session",
                    "author_reducer_fixture", "compare_live",
                    "check_lifetime_ordering",
                    "replay_oracle_ledger",
                    "check_conservation",
                    "parse_consume_file", "parse_oracle_log"):
            calls.setdefault(name, []).append(node)
    return func, calls


def self_test_judge_preserved():
    """The port judges through the extracted retired block."""
    ok = True
    text = (REPO / "tests" / "vm" / "test_oracle_live.py"
            ).read_text()
    start = text.find("def test_guest_comparison")
    body = text[start:]
    ok = check("judge-retired-calls",
               "judge_oracle_comparison(" in body
               and "MEMVEIL_BIN" in body
               and "selected_profile_id()" in body,
               "retired entry drifted") and ok
    func, calls = _judge_calls()
    try:
        script = calls["check_oracle_script"][0]
        args = [ast.literal_eval(arg)
                for arg in script.args[-3:]]
        multi = calls["compare_scripted"][0]
        margs = [ast.literal_eval(arg)
                 for arg in multi.args[-3:]]
        ok = check("judge-call-args",
                   args == [4, -1, "cmp"]
                   and margs == [4, -1, "cmp"],
                   "%r %r" % (args, margs)) and ok
    except (KeyError, IndexError, ValueError) as exc:
        ok = check("judge-call-args", False,
                   str(exc)[:160]) and ok
    try:
        session = calls["translate_session"][0]
        session_id = ast.literal_eval(session.args[-2])
        profile_arg = session.args[-1]
        ok = check("judge-session-id",
                   session_id == "oracle-live-session"
                   and isinstance(profile_arg, ast.Name)
                   and profile_arg.id == "profile_id",
                   "%r" % (session_id,)) and ok
    except (KeyError, IndexError, ValueError) as exc:
        ok = check("judge-session-id", False,
                   str(exc)[:160]) and ok
    dump = ast.dump(func)
    ok = check("judge-report-argv",
               "'report'" in dump and "'--format'" in dump
               and "'json'" in dump and "300" in dump
               and "report exit" in dump,
               "report step drifted") and ok
    params = [arg.arg for arg in func.args.args]
    ok = check("judge-params",
               params == ["got", "work_dir", "memveil_bin",
                          "profile_id"],
               "%r" % (params,)) and ok
    return ok


def self_test_judge_report(tmp):
    """Full judge with a real binary when one is staged.

    The report-vs-ledger leg needs an executable: the
    probe-seal mode runs it with the staged sealed binary,
    while the self-test runs it with the built binary when
    CI has one and skips loudly otherwise.
    """
    binary = str(REPO / "build" / "memveil")
    if not (os.path.isfile(binary)
            and os.access(binary, os.X_OK)):
        print("ok judge-report SKIP (no build/memveil in tree)")
        return True
    lc_wire, lc_counts, cp_wire, cp_counts = scripted_wire()
    text = heldopen_oracle_log()
    for i in range(4):
        text = text.replace(
            "mapping=%d release lifetime_ns=%d" % (i, 1000 + i),
            "mapping=%d release lifetime_ns=%d"
            % (i, 10 ** 12 + i))
    files = synth_window_files(tmp, "cmp", lc_wire,
                               lc_counts, cp_wire, cp_counts,
                               text)
    try:
        bad = judge_oracle_comparison(
            files, os.path.join(tmp, "judge-work"), binary,
            "linux-x86_64-7.0-reference")
    except (ValueError, OSError) as exc:
        return check("judge-report", False, str(exc)[:300])
    return check("judge-report", bad == [],
                 "; ".join(str(reason)[:200]
                           for reason in bad[:3]))


def self_test_boot_budget(tmp):
    """An over-budget guest argv refuses before any boot."""
    ok = True
    real_argv = build_guest_argv

    def huge_argv():
        return ["python3", "guest.py"] + ["x" * 400] * 4

    self_mod = sys.modules[__name__]
    self_mod.build_guest_argv = huge_argv
    try:

        class Args:
            out = os.path.join(tmp, "out")
            keep = True

        staged = os.path.join(tmp, "inputs-doc.json")
        with open(staged, "w") as handle:
            handle.write("{}\n")
        manifest = {"guest_inputs": {
            core.CASE: {"file": core.GUEST_INPUTS_FILE,
                        "sha256": sha_file(staged)}}}
        flight = {"prefix": ["vng"], "harness": {}}
        import contextlib
        import io
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            rc = armed_boot_case(Args(), os.path.join(
                tmp, "inputs.json"), manifest, staged,
                flight)
        ok = check("boot-budget-refuses",
                   rc == 2
                   and "refusing boot" in captured.getvalue(),
                   "rc=%r" % (rc,)) and ok
    finally:
        self_mod.build_guest_argv = real_argv
    return ok


def self_test_receipt_drift(tmp):
    """Receipt drift refusals: clean, tampered, dup member."""
    ok = True
    manifest_path = os.path.join(tmp, "receipt-inputs.json")
    manifest = {"schema": core.SCHEMA, "cases": [core.CASE]}
    with open(manifest_path, "w") as handle:
        handle.write(json.dumps(manifest, indent=2,
                                sort_keys=True) + "\n")
    retained = {}
    ok = check("receipt-clean",
               check_manifest_receipt_drift(
                   manifest_path, manifest, retained)
               == []
               and retained.get("raw") is not None) and ok
    with open(manifest_path, "w") as handle:
        handle.write(json.dumps({"schema": core.SCHEMA,
                                 "cases": ["bogus"]},
                                indent=2, sort_keys=True)
                     + "\n")
    ok = check("receipt-tamper",
               check_manifest_receipt_drift(
                   manifest_path, manifest) != [],
               "drift passed") and ok
    with open(manifest_path, "w") as handle:
        handle.write('{"cases": ["%s"], "cases": ["%s"]}'
                     % (core.CASE, core.CASE))
    ok = check("receipt-dup",
               check_manifest_receipt_drift(
                   manifest_path, manifest) != [],
               "dup member passed") and ok
    return ok


def run_self_test(work=None):
    """Full offline suite: proofs plus unarmed checks. No boot."""
    print("heldopen self-test (unarmed, offline)")
    tmp = work or tempfile.mkdtemp(prefix="vmgate-heldopen-")
    os.makedirs(tmp, exist_ok=True)
    keep = work is not None
    ok = True
    try:
        ok = self_test_seal_pins() and ok
        ok = self_test_derived_pins() and ok
        ok = self_test_consumer_build() and ok
        ok = self_test_layouts() and ok
        ok = self_test_red_bridge() and ok
        ok = self_test_green_cli() and ok
        ok = self_test_red_buildtree() and ok
        ok = self_test_red_localko() and ok
        ok = self_test_green_fixture() and ok
        ok = self_test_red_tokenless() and ok
        ok = self_test_green_selector() and ok
        ok = self_test_choreography() and ok
        ok = self_test_guest_argv() and ok
        ok = self_test_guest_inputs(tmp) and ok
        ok = self_test_manifest(tmp) and ok
        ok = self_test_guest_identity_gate() and ok
        ok = self_test_identity() and ok
        ok = self_test_judge_window(tmp) and ok
        ok = self_test_judge_preserved() and ok
        ok = self_test_judge_report(tmp) and ok
        ok = self_test_boot_budget(tmp) and ok
        ok = self_test_receipt_drift(tmp) and ok
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
    print("heldopen self-test: %s" % ("PASS" if ok else "FAIL"))
    return ok


# -- Armed run (prepared; needs the live-VM lease) ---------------

def armed_preflight():
    """Resolve vng + harness versions; armed failures are fatal."""
    from test_attempt_capture import find_vng, gate_prefix
    from harness_env import check_harness_versions
    vng = find_vng()
    if not vng:
        print("FAIL vm-heldopen: armed but vng missing")
        return None
    try:
        harness = check_harness_versions(vng)
    except ValueError as exc:
        print("FAIL vm-heldopen: armed but %s" % (exc,))
        return None
    try:
        prefix, _env = gate_prefix()
    except Exception as exc:  # pytest.skip/fail raise here
        print("FAIL vm-heldopen: armed but %s" % (exc,))
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
    result = {"ok": False, "files": {}, "reasons": []}
    try:
        have = {p.name for p in export.iterdir()}
    except OSError as exc:
        result["reasons"].append("export unreadable: %s" % (exc,))
        return result
    have.discard(core.GUEST_INPUTS_FILE)
    want = set(EXPORT_NAMES) | {"%s.sha256" % n
                               for n in EXPORT_NAMES}
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
        return ["heldopen: input-verify unreadable: %s"
                % (exc,)]
    bad = []
    if observed.get("case") != core.CASE:
        bad.append("heldopen: input-verify names case %r"
                   % (observed.get("case"),))
    entry = manifest.get("guest_inputs", {}).get(core.CASE, {})
    if observed.get("guest_inputs_file") != entry.get("file"):
        bad.append("heldopen: guest saw inputs file %r, bound %r"
                   % (observed.get("guest_inputs_file"),
                      entry.get("file")))
    if observed.get("guest_inputs_sha256") \
            != entry.get("sha256"):
        bad.append("heldopen: guest-observed inputs digest "
                   "differs from the manifest binding")
    try:
        staged = sha_file(str(Path(export)
                              / core.GUEST_INPUTS_FILE))
    except OSError as exc:
        return sorted(bad + ["heldopen: staged inputs "
                             "unreadable: %s" % (exc,)])
    if staged != entry.get("sha256"):
        bad.append("heldopen: staged inputs bytes differ from "
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
        return ["heldopen: receipt manifest unreadable: %s"
                % (exc,)]
    try:
        disk = json.loads(raw.decode("utf-8"),
                          object_pairs_hook=_object_no_dupes)
    except _DuplicateMember as exc:
        return ["heldopen: receipt manifest refused: %s"
                % (exc,)]
    except ValueError as exc:
        return ["heldopen: receipt manifest unreadable: %s"
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
    return ["heldopen: on-disk inputs manifest drifted from the "
            "judged snapshot (%s)" % (detail,)]


def save_case_receipts(out, tmp, export, files, names,
                       manifest_path, manifest, bad, metrics,
                       manifest_bytes=None):
    """Copy one receipt set; raises OSError on failure.

    The boot console transcript lands in the receipt as
    host-guest.stderr (the verbose boot routes the guest
    console to the captured stderr);
    host-guest-inputs.json pins the staged inputs bytes
    the guest had to see. Production callers must check
    first via check_manifest_receipt_drift and pass the
    validated bytes as manifest_bytes, so the receipt
    keeps the judged bytes; the live manifest path is
    never re-read on the save path. Without them the
    manifest path is copied (offline probes only).
    """
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        shutil.copy2(files[name], out / name)
        shutil.copy2(export / ("%s.sha256" % name),
                     out / ("%s.sha256" % name))
    if manifest_bytes is None:
        shutil.copy2(manifest_path, out / "inputs.json")
    else:
        (out / "inputs.json").write_bytes(manifest_bytes)
    shutil.copy2(export / core.GUEST_INPUTS_FILE,
                 out / "host-guest-inputs.json")
    for name in ("boot.json", "guest.stdout",
                 "guest.stderr", "guest.exit"):
        shutil.copy2(tmp / name, out / ("host-%s" % name))
    (out / "host-verdict.json").write_text(json.dumps(
        {"verdict": "PASS" if not bad else "FAIL",
         "case": core.CASE, "reasons": bad, "metrics": metrics,
         "console_transcript": "host-guest.stderr",
         "seal": manifest["seal"],
         "runner_commit": manifest["runner_commit"],
         "consumer": manifest["consumer"],
         "candidate": manifest["candidate"],
         "oracle": manifest["oracle"],
         "guest": manifest["guest"],
         "profile": manifest["profile"]},
        indent=2, sort_keys=True) + "\n")


def armed_boot_case(args, manifest_path, manifest,
                    staged_inputs, flight):
    """Boot once, run the held-open leg in-guest, judge host-side."""
    from vm_process import run_owned_guest
    tmp = Path(tempfile.mkdtemp(prefix="vmgate-heldopen-boot-"))
    export = tmp / "export"
    export.mkdir()
    guest_argv = build_guest_argv()
    exec_str = shlex.join(guest_argv)
    projected = project_cmdline_total(len(exec_str))
    if cmdline_over_budget(len(exec_str)):
        (tmp / "boot.json").write_text(json.dumps(
            {"case": core.CASE, "refused": "cmdline budget",
             "exec_chars": len(exec_str),
             "projected_cmdline": projected,
             "cmdline_ceiling": COMMAND_LINE_SIZE,
             "exec_budget": GUEST_EXEC_BUDGET},
            indent=2, sort_keys=True) + "\n")
        print("FAIL vm-heldopen: guest argv projects to "
              "%d cmdline chars (exec %d chars, budget %d "
              "total / %d exec); refusing boot, artifacts "
              "kept at %s"
              % (projected, len(exec_str),
                 COMMAND_LINE_SIZE, GUEST_EXEC_BUDGET, tmp))
        return 2
    try:
        shutil.copyfile(staged_inputs,
                        export / core.GUEST_INPUTS_FILE)
        copied = sha_file(export / core.GUEST_INPUTS_FILE)
    except OSError as exc:
        print("FAIL vm-heldopen: staged inputs copy "
              "failed (%s); artifacts kept at %s"
              % (exc, tmp))
        return 1
    bound = manifest.get("guest_inputs", {}).get(core.CASE, {})
    if copied != bound.get("sha256"):
        print("FAIL vm-heldopen: staged inputs copy "
              "differs from the manifest binding; "
              "artifacts kept at %s" % (tmp,))
        return 1
    cmd = build_vng_argv(flight, export, exec_str)
    (tmp / "boot.json").write_text(json.dumps(
        {"case": core.CASE, "cmd": cmd, "manifest": manifest,
         "harness": flight["harness"],
         "exec_chars": len(exec_str),
         "projected_cmdline": projected,
         "cmdline_ceiling": COMMAND_LINE_SIZE,
         "exec_budget": GUEST_EXEC_BUDGET,
         "guest_inputs_sha256": copied},
        indent=2, sort_keys=True) + "\n")
    try:
        proc = run_owned_guest(cmd, timeout=core.CASE_TIMEOUT)
    except subprocess.TimeoutExpired as exc:
        (tmp / "guest.stdout").write_text(exc.stdout or "")
        (tmp / "guest.stderr").write_text(exc.stderr or "")
        (tmp / "guest.exit").write_text("timeout")
        print("FAIL vm-heldopen: guest timed out after %ds; "
              "artifacts kept at %s" % (core.CASE_TIMEOUT, tmp))
        return 2
    (tmp / "guest.stdout").write_text(proc.stdout or "")
    (tmp / "guest.stderr").write_text(proc.stderr or "")
    (tmp / "guest.exit").write_text(str(proc.returncode))
    if proc.returncode != 0:
        print("FAIL vm-heldopen: guest exit %d; artifacts "
              "kept at %s" % (proc.returncode, tmp))
        return 1
    verified = verify_exports(export)
    if not verified["ok"]:
        print("FAIL vm-heldopen: %s; artifacts kept at %s"
              % ("; ".join(verified["reasons"]), tmp))
        return 1
    judge_work = tmp / "judge"
    judge_work.mkdir()
    bad, metrics = judge_case(verified["files"], manifest,
                              str(judge_work))
    bad = sorted(bad + check_guest_inputs_binding(
        verified["files"], manifest, export))
    retained = {}
    drift_bad = check_manifest_receipt_drift(
        manifest_path, manifest, retained)
    if drift_bad:
        print("FAIL vm-heldopen: %s; artifacts kept at %s"
              % ("; ".join(drift_bad), tmp))
        return 1
    out = Path(args.out) / core.CASE
    try:
        save_case_receipts(out, tmp, export,
                           verified["files"], EXPORT_NAMES,
                           manifest_path, manifest, bad,
                           metrics, retained["raw"])
    except OSError as exc:
        print("FAIL vm-heldopen: receipt failed (%s); "
              "artifacts kept at %s" % (exc, tmp))
        return 1
    if not args.keep:
        shutil.rmtree(tmp, ignore_errors=True)
    else:
        print("vm-heldopen: guest tmp kept at %s" % (tmp,))
    if bad:
        print("FAIL vm-heldopen: %s" % ("; ".join(bad),))
        return 1
    print("ok vm-heldopen PASS (%s)" % (out,))
    return 0


def armed_run(args):
    """Armed held-open leg: one pinned boot, judged host-side."""
    if os.environ.get(ARM_ENV) != "1":
        print("FAIL vm-heldopen: armed run needs %s=1" % ARM_ENV)
        return 2
    if not args.out:
        print("FAIL vm-heldopen: armed needs --out")
        return 2
    if not getattr(args, "bundle", "") or not getattr(
            args, "candidate", ""):
        print("FAIL vm-heldopen: armed needs --bundle and "
              "--candidate")
        return 2
    if getattr(args, "expect_release", "") not in (
            "", core.EXPECT_RELEASE):
        print("FAIL vm-heldopen: conflicting --expect-release %r"
              % (args.expect_release,))
        return 2
    flight = armed_preflight()
    if flight is None:
        return 1
    cache_ok, cache_why, _ = verify_guest_cache()
    if not cache_ok:
        print("FAIL vm-heldopen: pinned guest cache refused: %s"
              % (cache_why,))
        return 1
    lock_dir = REPO / "build" / "vm"
    try:
        lock_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        print("FAIL vm-heldopen: lock dir failed: %s" % (exc,))
        return 1
    # The run work dir lives under the repo build tree so
    # the guest resolves every input path identically; the
    # guest /tmp is a private overlay.
    work = Path(tempfile.mkdtemp(prefix="heldopen-",
                                 dir=str(lock_dir)))
    try:
        inputs = core.materialize(
            str(REPO), str(work / "inputs"), args.candidate,
            args.bundle)
        built = score.build_consumer()
        commit = core.git_head(str(REPO))
    except (ValueError, OSError) as exc:
        print("FAIL vm-heldopen: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    manifest_path = work / "inputs.json"
    try:
        staged = write_guest_inputs_doc(
            str(work), manifest_path, built, inputs,
            args.expect_release)
    except (ValueError, OSError) as exc:
        print("FAIL vm-heldopen: %s" % exc)
        shutil.rmtree(work, ignore_errors=True)
        return 1
    manifest = core.write_input_manifest(
        str(manifest_path), inputs,
        {"sha256": built["sha256"], "build": built["build"]},
        sys.argv, commit,
        guest_inputs={core.CASE: staged})
    reasons = core.verify_input_manifest(manifest,
                                         built["path"])
    if reasons:
        print("FAIL vm-heldopen: %s" % "; ".join(reasons))
        shutil.rmtree(work, ignore_errors=True)
        return 1
    lease = (lock_dir / "suite.lock").open("a+")
    try:
        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        lease.close()
        print("FAIL vm-heldopen: VM suite lease already owned; "
              "one live executor at a time")
        shutil.rmtree(work, ignore_errors=True)
        return 1
    try:
        try:
            guest_oracle.verify_fixture()
        except (ValueError, OSError) as exc:
            print("FAIL vm-heldopen: oracle fixture refused: %s"
                  % (exc,))
            return 1
        return armed_boot_case(args, manifest_path, manifest,
                               staged, flight)
    except Exception as exc:
        print("FAIL vm-heldopen: armed but %s" % (exc,))
        return 1
    finally:
        lease.close()
        if not args.keep:
            shutil.rmtree(work, ignore_errors=True)
        else:
            print("vm-heldopen: work kept at %s" % (work,))


# -- Offline seal probe (no boot) -------------------------------

def probe_seal(args):
    """Offline proof against explicit seal bytes. No boot, no root."""
    if not getattr(args, "bundle", "") or not getattr(
            args, "candidate", ""):
        print("FAIL vm-heldopen probe: needs --bundle and "
              "--candidate")
        return 2
    work = Path(tempfile.mkdtemp(prefix="heldopen-probe-"))
    try:
        try:
            inputs = core.materialize(
                str(REPO), str(work / "inputs"),
                args.candidate, args.bundle)
            built = score.build_consumer()
            commit = core.git_head(str(REPO))
        except (ValueError, OSError) as exc:
            print("FAIL vm-heldopen probe: %s" % exc)
            return 1
        print("probe seal %s binary %s" % (
            seal.SEAL_LABEL, inputs["binary"]["sha256"][:16]))
        print("probe objects lc %s cp %s" % (
            inputs["lc"]["sha256"][:16],
            inputs["cp"]["sha256"][:16]))
        print("probe profile %s %s" % (
            inputs["profile"]["profile_id"],
            inputs["profile"]["sha256"][:16]))
        print("probe consumer %s" % built["sha256"][:16])
        manifest_path = work / "inputs.json"
        try:
            staged = write_guest_inputs_doc(
                str(work), manifest_path, built, inputs, "")
        except (ValueError, OSError) as exc:
            print("FAIL vm-heldopen probe: %s" % exc)
            return 1
        manifest = core.write_input_manifest(
            str(manifest_path), inputs,
            {"sha256": built["sha256"],
             "build": built["build"]},
            sys.argv, commit,
            guest_inputs={core.CASE: staged})
        reasons = core.verify_input_manifest(
            manifest, built["path"])
        if reasons:
            print("FAIL vm-heldopen probe: %s"
                  % "; ".join(reasons))
            return 1
        print("probe manifest verifies []")
        # The complete preserved judge on a synthetic
        # held-open window through the real consumer
        # replay path, rendered by the staged sealed
        # executable.
        lc_wire, lc_counts, cp_wire, cp_counts = \
            scripted_wire()
        text = heldopen_oracle_log()
        for i in range(4):
            text = text.replace(
                "mapping=%d release lifetime_ns=%d"
                % (i, 1000 + i),
                "mapping=%d release lifetime_ns=%d"
                % (i, 10 ** 12 + i))
        files = synth_window_files(
            str(work), "cmp", lc_wire, lc_counts, cp_wire,
            cp_counts, text)
        ident_path = work / "identity.json"
        ident_path.write_text(json.dumps(
            {"release": core.EXPECT_RELEASE,
             "btf_sha256": guest_oracle.GUEST_BTF_SHA256,
             "digests": {"ko": manifest["oracle"]["ko_sha256"],
                         "lc": manifest["objects"]["lc"][
                             "sha256"],
                         "cp": manifest["objects"]["cp"][
                             "sha256"]}},
            sort_keys=True))
        files["identity.json"] = ident_path
        judge_work = work / "judge"
        judge_work.mkdir()
        try:
            bad, _ = judge_case(files, manifest,
                                str(judge_work))
        except (ValueError, OSError) as exc:
            print("FAIL vm-heldopen probe: judge error: %s"
                  % exc)
            return 1
        if bad:
            print("FAIL vm-heldopen probe: judge: %s"
                  % "; ".join(bad))
            return 1
        print("probe judge PASS with staged sealed binary "
              "%s" % inputs["binary"]["sha256"][:16])
        # A wrong seal member refuses: the staged binary
        # swapped for foreign bytes fails the manifest.
        import copy
        other = copy.deepcopy(manifest)
        other["binary"]["sha256"] = "0" * 64
        if not core.verify_input_manifest(other,
                                         built["path"]):
            print("FAIL vm-heldopen probe: binary tamper "
                  "passed")
            return 1
        print("probe binary tamper refused")
        # The staged sealed objects load under the ported
        # CLI shape; the retired shape still exits 2.
        for channel, ring in (("lc", "mv_lifecycle"),
                              ("cp", "mv_copies")):
            proc = consumer_run(
                ["--verify-layout",
                 inputs[channel]["path"], ring])
            parsed = score.parse_verify_layout(proc.stdout)
            if proc.returncode != 0 \
                    or parsed["verdict"] != "PASS" \
                    or parsed["sha256"] != inputs[channel][
                        "sha256"]:
                print("FAIL vm-heldopen probe: staged %s "
                      "refused" % channel)
                return 1
        print("probe staged objects load (family aya)")
        proc = consumer_run(["--bridge", "bridge",
                             inputs["lc"]["path"],
                             "mv_lifecycle", core.LC_SITES,
                             "1", str(work / "never")])
        if proc.returncode != 2:
            print("FAIL vm-heldopen probe: --bridge exited %d"
                  % proc.returncode)
            return 1
        print("probe retired --bridge shape exits 2")
        # Kernel selector: token-less dry-run resolves the
        # host kernel; the pinned selector resolves the
        # locked guest kernel. Dry runs only, never a boot.
        from test_attempt_capture import find_vng
        vng = find_vng()
        if not vng:
            print("FAIL vm-heldopen probe: vng not available")
            return 1
        bare = subprocess.run(
            [vng, "--run", "--dry-run"], capture_output=True,
            text=True, timeout=120)
        pinned = subprocess.run(
            [vng, "--run", core.VNG_TAG, "--dry-run"],
            capture_output=True, text=True, timeout=120)
        if bare.returncode != 0 or pinned.returncode != 0:
            print("FAIL vm-heldopen probe: vng dry-run "
                  "failed")
            return 1
        if core.EXPECT_RELEASE in bare.stdout \
                or "-kernel" not in bare.stdout:
            print("FAIL vm-heldopen probe: token-less "
                  "dry-run did not resolve away from %s"
                  % core.EXPECT_RELEASE)
            return 1
        if core.EXPECT_RELEASE not in pinned.stdout \
                or core.VNG_TAG not in pinned.stdout:
            print("FAIL vm-heldopen probe: pinned dry-run "
                  "missed %s" % core.EXPECT_RELEASE)
            return 1
        print("probe selector: token-less -> host kernel, "
              "--run %s -> %s"
              % (core.VNG_TAG, core.EXPECT_RELEASE))
        cache_ok, cache_why, _ = verify_guest_cache()
        if not cache_ok:
            print("FAIL vm-heldopen probe: pinned guest "
                  "cache refused: %s" % (cache_why,))
            return 1
        print("probe guest cache holds (%s)" % cache_why)
    finally:
        if getattr(args, "keep", False):
            print("vm-heldopen probe: work kept at %s"
                  % (work,))
        else:
            shutil.rmtree(work, ignore_errors=True)
    print("ok vm-heldopen probe PASS (offline, no boot)")
    return 0


# -- pytest entry points ------------------------------------------

def test_self_test_unarmed(tmp_path):
    assert run_self_test(work=str(tmp_path / "self"))


def test_armed_heldopen():
    import pytest
    if os.environ.get(ARM_ENV) != "1":
        pytest.skip(
            "heldopen armed run needs MEMVEIL_VM_HELDOPEN=1")

    class Args:
        pass
    args = Args()
    args.out = os.environ.get(
        "MV_HELDOPEN_OUT",
        str(REPO / "build" / "vm" / "heldopen"))
    args.keep = os.environ.get("MV_HELDOPEN_KEEP", "") == "1"
    args.bundle = os.environ.get("MV_HELDOPEN_BUNDLE", "")
    args.candidate = os.environ.get("MV_HELDOPEN_CANDIDATE", "")
    args.expect_release = os.environ.get(
        "MV_HELDOPEN_EXPECT_RELEASE", "")
    assert armed_run(args) == 0


def main(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--probe-seal", action="store_true",
                        help="offline proof against explicit "
                             "seal bytes (needs --bundle and "
                             "--candidate; no boot)")
    parser.add_argument("--out", default="")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--bundle", default="",
                        help="retained bundle.tar.gz path "
                             "(required when armed or probing)")
    parser.add_argument("--candidate", default="",
                        help="retained candidate.json path "
                             "(required when armed or probing)")
    parser.add_argument("--expect-release", default="",
                        help="refuse unless the guest release "
                             "matches (must equal the pin)")
    args = parser.parse_args(argv)
    if args.self_test or (not args.probe_seal and not args.out):
        return 0 if run_self_test() else 1
    if args.probe_seal:
        return probe_seal(args)
    return armed_run(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
