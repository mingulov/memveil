#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Unarmed proofs for the sealed faults gate.

No boot, no privileges: pin cross-checks against committed
sources, the consumer/bridge removal proof from the guest
flow, binding accept/refuse per field on synthetic and
retained pairs, oracle digest/vermagic gates, kernel-lock
gates, identity rechecks, the f3a/f3b judge on synthetic
logs, and the full host flow against a mocked guest export
tree. Tests needing the retained dist/ seal skip cleanly
when it is absent; every other proof runs anywhere.
"""

import ast
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "stress-consumer"))

from consume import parse_oracle_log  # noqa: E402
import guest_lifecycle  # noqa: E402
import guest_oracle  # noqa: E402
import test_battery as battery_tests  # noqa: E402
import test_faults as faults  # noqa: E402
from test_record3 import _events  # noqa: E402

REPO = faults.REPO
DIST_MANIFEST = os.path.join(REPO, "dist", "candidate.json")
DIST_BUNDLE = os.path.join(REPO, "dist", "bundle.tar.gz")
SEAL_FILES = ("bin/memveil", "bpf/swiotlb_attempt.bpf.o",
              "bpf/swiotlb_copy.bpf.o", "bpf/swiotlb_lifecycle.bpf.o",
              "profiles/linux-x86_64-7.0-reference.json")

needs_seal = pytest.mark.skipif(
    not (os.path.isfile(DIST_MANIFEST)
         and os.path.isfile(DIST_BUNDLE)),
    reason="no dist/ seal in tree")


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


# -- Pins vs committed sources ------------------------------

def test_seal_objects_match_committed_fixtures():
    for rel, key in (
            ("tests/vm/fixtures/aya/swiotlb_attempt.bpf.o",
             "bpf/swiotlb_attempt.bpf.o"),
            ("tests/vm/fixtures/aya/swiotlb_copy.bpf.o",
             "bpf/swiotlb_copy.bpf.o"),
            ("tests/vm/fixtures/aya/swiotlb_lifecycle.bpf.o",
             "bpf/swiotlb_lifecycle.bpf.o")):
        assert faults.sha_file(os.path.join(REPO, rel)) == \
            faults.SEAL_MEMBERS[key], rel


def test_profile_pin_matches_checkout_doc():
    doc_path = os.path.join(REPO, faults.PROFILE_REL)
    with open(doc_path) as handle:
        doc = json.load(handle)
    assert doc["profile_id"] == faults.PROFILE_ID
    assert faults.sha_file(doc_path) == faults.PROFILE_SHA256


def test_kernel_lock_pins_match():
    lock = json.loads(Path(
        REPO, "tests", "vm", "kernels.lock.json").read_text())
    rows = [k for k in lock["kernels"] if k.get("id") == "7.0"]
    assert len(rows) == 1
    row = rows[0]
    assert row["release"] == faults.EXPECT_RELEASE
    assert row["source"]["vng_version"] == faults.VNG_TAG
    assert row["source"]["vmlinuz_sha256"] == faults.VMLINUZ_SHA256
    assert row["source"]["modules_manifest_sha256"] == \
        faults.MODULES_MANIFEST_SHA256
    binding = faults.verify_kernel_lock(REPO)
    assert binding["release"] == faults.EXPECT_RELEASE
    assert binding["vng_tag"] == faults.VNG_TAG


def test_guest_pins_match_host_pins():
    assert guest_lifecycle.FAULTS_RELEASE == faults.EXPECT_RELEASE
    assert guest_lifecycle.FAULTS_KO_SHA256 == \
        guest_oracle.KO_SHA256
    assert guest_lifecycle.FAULTS_BTF_SHA256 == \
        guest_oracle.GUEST_BTF_SHA256
    assert guest_lifecycle.FAULTS_PROFILE_MEMBER == \
        "profiles/linux-x86_64-7.0-reference.json"
    fixture = os.path.join(
        REPO, *guest_lifecycle.FAULTS_KO_FIXTURE)
    assert fixture == guest_oracle.FIXTURE_KO
    assert os.path.isfile(fixture)


def test_release_single_sourced_across_runners():
    assert faults.EXPECT_RELEASE == guest_oracle.GUEST_RELEASE
    assert faults.EXPECT_RELEASE == \
        battery_tests.core.EXPECT_RELEASE
    assert faults.PROFILE_ID == battery_tests.core.PROFILE_ID
    assert faults.PROFILE_SHA256 == \
        battery_tests.core.PROFILE_SHA256
    assert faults.PROFILE_DECISION == \
        battery_tests.core.PROFILE_DECISION
    assert faults.VNG_TAG == battery_tests.core.VNG_TAG
    assert faults.VMLINUZ_SHA256 == \
        battery_tests.core.VMLINUZ_SHA256
    assert faults.MODULES_MANIFEST_SHA256 == \
        battery_tests.core.MODULES_MANIFEST_SHA256
    assert faults.SEAL_MEMBERS["bpf/swiotlb_lifecycle.bpf.o"] == \
        battery_tests.score.C9_LC_SHA
    assert faults.SEAL_MEMBERS["bpf/swiotlb_copy.bpf.o"] == \
        battery_tests.score.C9_CP_SHA
    assert faults.SEAL_MEMBERS["bpf/swiotlb_attempt.bpf.o"] == \
        battery_tests.score.C9_ATTEMPT_SHA
    assert faults.SEAL_CANDIDATE_SHA == \
        battery_tests.score.C9_CANDIDATE_SHA


def test_decision_shape_matches_product():
    assert faults.PROFILE_DECISION == \
        "candidate %s: live interfaces verified " \
        "(profile unvalidated)" % faults.PROFILE_ID
    run_rs = Path(REPO, "src", "capture", "run.rs").read_text()
    assert "candidate {}: live interfaces verified " \
        "(profile unvalidated)" in run_rs


def test_static_loader_phrase_in_record_source():
    record_rs = Path(REPO, "src", "cli", "record.rs").read_text()
    assert "Without --bridge, the statically linked loader runs" \
        in record_rs


# -- Consumer/bridge removal proof --------------------------

def _guest_function(name):
    source = Path(guest_lifecycle.__file__).read_text()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return node, source
    raise AssertionError("guest lacks %s" % name)


def test_faults_flow_invokes_record_directly():
    """The faults guest never touches consumer or bridge.

    run_faults drives the record binary through Popen/sh
    plus the shared oracle/BPF helpers; it reaches no
    consumer entry point, and no bridge path or flag
    survives on its record command lines.
    """
    node, source = _guest_function("run_faults")
    attrs, calls, consts = set(), set(), []
    for child in ast.walk(node):
        if isinstance(child, ast.Attribute):
            attrs.add(child.attr)
        if isinstance(child, ast.Call) and isinstance(
                child.func, ast.Attribute):
            calls.add(child.func.attr)
        if isinstance(child, ast.Constant) and isinstance(
                child.value, str):
            consts.append(child.value)
    assert "start_consumer" not in calls
    assert "consume" not in attrs
    assert "bridge" not in attrs
    assert "--bridge" not in consts
    assert "--force" not in consts
    assert "record" in consts
    init, _ = _guest_function("__init__")
    setup = ast.get_source_segment(source, init)
    assert 'sub in ("bundle", "faults")' in setup
    assert 'None if sub == "faults"' in setup
    insmod, _ = _guest_function("insmod")
    assert "--force" not in ast.get_source_segment(source, insmod)


def test_seal_members_carry_no_bridge():
    for name in faults.SEAL_MEMBERS:
        assert "mojo" not in name, name
        assert not name.endswith(".so"), name
        assert ".so." not in name, name


@needs_seal
def test_retained_closure_carries_no_bridge():
    with open(DIST_MANIFEST) as handle:
        manifest = json.load(handle)
    shared = [name for name in manifest["files"]
              if name.endswith(".so") or ".so." in name
              or "mojo" in name.lower()]
    assert shared == ["lib/memveil/libgcc_s.so.1"], shared


@needs_seal
def test_shipped_binary_needs_no_bridge_lib(tmp_path):
    """The sealed binary loads with no bridge library.

    Its bytes never name one (a dynamic dependency would
    embed the name verbatim), and its own record help
    declares the statically linked loader for bridgeless
    runs.
    """
    root = tmp_path / "seal"
    with tarfile.open(DIST_BUNDLE, "r:gz") as archive:
        for member in ("bundle/bin/memveil",
                       "bundle/lib/memveil/libgcc_s.so.1"):
            archive.extract(member, path=root)
    binary = root / "bundle" / "bin" / "memveil"
    assert b"libbpf_mojo" not in binary.read_bytes()
    proc = subprocess.run(
        [str(binary), "record", "--help"],
        capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr[-500:]
    assert "Without --bridge, the statically linked loader runs" \
        in proc.stdout


# -- Synthetic seal pairs -----------------------------------

SYNTH_MEMBERS = {
    "bin/memveil": b"synthetic-record-binary",
    "bpf/swiotlb_attempt.bpf.o": b"synthetic-attempt-object",
    "bpf/swiotlb_copy.bpf.o": b"synthetic-copy-object",
    "bpf/swiotlb_lifecycle.bpf.o": b"synthetic-lifecycle-object",
    "profiles/linux-x86_64-7.0-reference.json":
        b'{"profile_id": "linux-x86_64-7.0-reference"}',
}
SYNTH_INNER = b'{"bundle": "synthetic"}'


def make_seal_pair(tmp, tag="pair", member_over=None, omit=(),
                   inner=SYNTH_INNER, manifest_files=None,
                   manifest_over=None, bundle_sha=None,
                   bundle_size=None, raw_manifest=None):
    """Craft a seal pair plus pins for the pristine bytes.

    Pins always describe the unflawed pair, so each flaw
    refuses at its own check with its own reason; the
    manifest digest pin follows the crafted manifest bytes
    so manifest-level flaws reach their own checks instead
    of stopping at the digest.
    """
    members = dict(SYNTH_MEMBERS)
    if member_over:
        members.update(member_over)
    for gone in omit:
        members.pop(gone, None)
    bundle_path = os.path.join(tmp, "%s-bundle.tar.gz" % tag)
    with tarfile.open(bundle_path, "w:gz") as archive:
        if inner is not None:
            info = tarfile.TarInfo("bundle/MANIFEST.json")
            info.size = len(inner)
            archive.addfile(info, io.BytesIO(inner))
        for name in sorted(members):
            info = tarfile.TarInfo("bundle/" + name)
            info.size = len(members[name])
            archive.addfile(info, io.BytesIO(members[name]))
    manifest_path = os.path.join(tmp, "%s-candidate.json" % tag)
    if raw_manifest is not None:
        with open(manifest_path, "wb") as handle:
            handle.write(raw_manifest)
    else:
        files = manifest_files if manifest_files is not None \
            else {name: sha_bytes(data)
                  for name, data in members.items()}
        manifest = {
            "schema": "memveil-candidate/2",
            "source": {"commit": "c" * 40, "tree": "t" * 40},
            "bundle_manifest_sha256": sha_bytes(inner)
            if inner is not None else "0" * 64,
            "files": files,
            "artifacts": [{"name": "bundle.tar.gz",
                           "sha256": bundle_sha or faults.sha_file(
                               bundle_path),
                           "size": bundle_size if bundle_size
                           is not None else os.path.getsize(
                               bundle_path)}],
        }
        if manifest_over:
            manifest.update(manifest_over)
        with open(manifest_path, "w") as handle:
            json.dump(manifest, handle, sort_keys=True)
    pins = {
        "candidate_sha256": faults.sha_file(manifest_path),
        "schema": "memveil-candidate/2",
        "source_commit": "c" * 40,
        "source_tree": "t" * 40,
        "bundle_manifest_sha256": sha_bytes(SYNTH_INNER),
        "files": {name: sha_bytes(data)
                  for name, data in SYNTH_MEMBERS.items()},
        "bundle_sha256": faults.sha_file(bundle_path),
        "bundle_size": os.path.getsize(bundle_path),
    }
    return manifest_path, bundle_path, pins


@needs_seal
def test_seal_accepts_retained_pair():
    binding = faults.verify_seal(DIST_MANIFEST, DIST_BUNDLE)
    assert binding["files"] == faults.SEAL_MEMBERS
    assert binding["bundle"]["sha256"] == faults.SEAL_BUNDLE_SHA
    assert binding["source"]["commit"] == faults.SEAL_SOURCE_COMMIT


def test_seal_accepts_synthetic_pair(tmp_path):
    manifest_path, bundle_path, pins = make_seal_pair(
        str(tmp_path))
    binding = faults.verify_seal(
        manifest_path, bundle_path, pins)
    assert binding["files"] == pins["files"]


def test_seal_refuses_manifest_flaws(tmp_path):
    tmp = str(tmp_path)
    manifest_path, bundle_path, pins = make_seal_pair(
        tmp, tag="clean")
    with pytest.raises(ValueError, match="manifest missing"):
        faults.verify_seal(
            os.path.join(tmp, "absent.json"), bundle_path, pins)
    with open(manifest_path, "ab") as handle:
        handle.write(b" ")
    with pytest.raises(ValueError, match="manifest digest drift"):
        faults.verify_seal(manifest_path, bundle_path, pins)
    raw, _, pins = make_seal_pair(
        tmp, tag="raw", raw_manifest=b"{nope")
    with pytest.raises(ValueError, match="unparsable"):
        faults.verify_seal(raw, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="schema", manifest_over={"schema": "bogus"})
    with pytest.raises(ValueError, match="schema drift"):
        faults.verify_seal(flawed, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="commit",
        manifest_over={"source": {"commit": "x" * 40,
                                  "tree": "t" * 40}})
    with pytest.raises(ValueError, match="source drift"):
        faults.verify_seal(flawed, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="tree",
        manifest_over={"source": {"commit": "c" * 40,
                                  "tree": "x" * 40}})
    with pytest.raises(ValueError, match="source drift"):
        faults.verify_seal(flawed, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="innerpin",
        manifest_over={"bundle_manifest_sha256": "0" * 64})
    with pytest.raises(ValueError,
                       match="bundle manifest drift"):
        faults.verify_seal(flawed, bundle_path, pins)


def test_seal_refuses_file_entry_flaws(tmp_path):
    tmp = str(tmp_path)
    _, bundle_path, _ = make_seal_pair(tmp, tag="clean")
    for nth, name in enumerate(SEAL_FILES):
        files = {key: sha_bytes(data)
                 for key, data in SYNTH_MEMBERS.items()}
        files[name] = "0" * 64
        flawed, _, pins = make_seal_pair(
            tmp, tag="file%d" % nth, manifest_files=files)
        with pytest.raises(ValueError, match="file drift"):
            faults.verify_seal(flawed, bundle_path, pins)
    gone = {key: sha_bytes(data)
            for key, data in SYNTH_MEMBERS.items()
            if key != "bin/memveil"}
    flawed, _, pins = make_seal_pair(
        tmp, tag="nobin", manifest_files=gone)
    with pytest.raises(ValueError, match="file drift"):
        faults.verify_seal(flawed, bundle_path, pins)


def test_seal_refuses_bundle_entry_flaws(tmp_path):
    tmp = str(tmp_path)
    _, bundle_path, _ = make_seal_pair(tmp, tag="clean")
    flawed, _, pins = make_seal_pair(
        tmp, tag="noentry", manifest_over={"artifacts": []})
    with pytest.raises(ValueError, match="bundle entry missing"):
        faults.verify_seal(flawed, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="entrysha", bundle_sha="0" * 64)
    with pytest.raises(ValueError, match="bundle entry drift"):
        faults.verify_seal(flawed, bundle_path, pins)
    flawed, _, pins = make_seal_pair(
        tmp, tag="entrysize", bundle_size=-1)
    with pytest.raises(ValueError, match="bundle entry drift"):
        faults.verify_seal(flawed, bundle_path, pins)


def test_seal_refuses_bundle_byte_flaws(tmp_path):
    tmp = str(tmp_path)
    manifest_path, bundle_path, pins = make_seal_pair(
        tmp, tag="clean")
    with pytest.raises(ValueError, match="bundle missing"):
        faults.verify_seal(
            manifest_path, os.path.join(tmp, "absent.tgz"), pins)
    with open(bundle_path, "r+b") as handle:
        handle.seek(10)
        byte = handle.read(1)
        handle.seek(10)
        handle.write(bytes([byte[0] ^ 0xff]))
    with pytest.raises(ValueError, match="bundle bytes drift"):
        faults.verify_seal(manifest_path, bundle_path, pins)
    manifest_path, bundle_path, pins = make_seal_pair(
        tmp, tag="size")
    size = os.path.getsize(bundle_path)
    with open(manifest_path) as handle:
        grown_manifest = json.load(handle)
    grown_manifest["artifacts"][0]["size"] = size + 1
    with open(manifest_path, "w") as handle:
        json.dump(grown_manifest, handle, sort_keys=True)
    grown = dict(pins, bundle_size=size + 1,
                 candidate_sha256=faults.sha_file(manifest_path))
    with pytest.raises(ValueError, match="bundle size drift"):
        faults.verify_seal(manifest_path, bundle_path, grown)
    garbage = os.path.join(tmp, "garbage.tgz")
    with open(garbage, "wb") as handle:
        handle.write(b"not a tarball")
    pins = dict(pins, bundle_sha256=faults.sha_file(garbage),
                bundle_size=os.path.getsize(garbage))
    manifest = {
        "schema": "memveil-candidate/2",
        "source": {"commit": "c" * 40, "tree": "t" * 40},
        "bundle_manifest_sha256": sha_bytes(SYNTH_INNER),
        "files": {name: sha_bytes(data)
                  for name, data in SYNTH_MEMBERS.items()},
        "artifacts": [{"name": "bundle.tar.gz",
                       "sha256": pins["bundle_sha256"],
                       "size": pins["bundle_size"]}],
    }
    manifest_copy = os.path.join(tmp, "garbage.json")
    with open(manifest_copy, "w") as handle:
        json.dump(manifest, handle, sort_keys=True)
    pins = dict(pins,
                candidate_sha256=faults.sha_file(manifest_copy))
    with pytest.raises(ValueError, match="bundle unreadable"):
        faults.verify_seal(manifest_copy, garbage, pins)


def test_seal_refuses_member_flaws(tmp_path):
    tmp = str(tmp_path)
    pristine_files = {name: sha_bytes(data)
                     for name, data in SYNTH_MEMBERS.items()}
    flawed, flawed_bundle, pins = make_seal_pair(
        tmp, tag="noinner", inner=None,
        manifest_over={
            "bundle_manifest_sha256": sha_bytes(SYNTH_INNER)})
    with pytest.raises(ValueError, match="lacks inner manifest"):
        faults.verify_seal(flawed, flawed_bundle, pins)
    flawed, flawed_bundle, pins = make_seal_pair(
        tmp, tag="innerdrift", inner=b"tampered-inner",
        manifest_over={
            "bundle_manifest_sha256": sha_bytes(SYNTH_INNER)})
    with pytest.raises(ValueError,
                       match="inner manifest drift"):
        faults.verify_seal(flawed, flawed_bundle, pins)
    for nth, name in enumerate(SEAL_FILES):
        flawed, flawed_bundle, pins = make_seal_pair(
            tmp, tag="drift%d" % nth,
            member_over={name: b"tampered-member-bytes"},
            manifest_files=dict(pristine_files))
        with pytest.raises(ValueError, match="member drift"):
            faults.verify_seal(flawed, flawed_bundle, pins)
        flawed, flawed_bundle, pins = make_seal_pair(
            tmp, tag="omit%d" % nth, omit=(name,),
            manifest_files=dict(pristine_files))
        with pytest.raises(ValueError,
                           match="bundle lacks"):
            faults.verify_seal(flawed, flawed_bundle, pins)


# -- Bound profile --------------------------------------------

@needs_seal
def test_profile_member_matches_reviewed_doc():
    binding = faults.verify_profile(REPO, DIST_BUNDLE)
    assert binding == {"sha256": faults.PROFILE_SHA256,
                       "profile_id": faults.PROFILE_ID}


def _profile_tarball(tmp, tag, member_bytes):
    members = dict(SYNTH_MEMBERS)
    members["profiles/linux-x86_64-7.0-reference.json"] = \
        member_bytes
    path = os.path.join(tmp, "%s-prof.tar.gz" % tag)
    with tarfile.open(path, "w:gz") as archive:
        for name in sorted(members):
            info = tarfile.TarInfo("bundle/" + name)
            info.size = len(members[name])
            archive.addfile(info, io.BytesIO(members[name]))
    return path


def test_profile_refuses_member_flaws(tmp_path):
    tmp = str(tmp_path)
    other = _profile_tarball(tmp, "other", b'{"profile_id": "x"}')
    with pytest.raises(ValueError, match="member id drift"):
        faults.verify_profile(REPO, other)
    broken = _profile_tarball(tmp, "broken", b"{nope")
    with pytest.raises(ValueError, match="member unparsable"):
        faults.verify_profile(REPO, broken)
    renamed = dict(SYNTH_MEMBERS)
    renamed["profiles/linux-x86_64-7.0-reference.json"] = \
        b'{"profile_id": "linux-x86_64-7.0-reference", "x": 1}'
    coherent = _profile_tarball(
        tmp, "coherent",
        renamed["profiles/linux-x86_64-7.0-reference.json"])
    with pytest.raises(ValueError, match="differs from the reviewed"):
        faults.verify_profile(REPO, coherent)


# -- Pinned-guest oracle --------------------------------------

def test_oracle_fixture_accepts():
    binding = faults.verify_oracle()
    assert binding["ko_sha256"] == guest_oracle.KO_SHA256
    assert binding["ko_vermagic"] == guest_oracle.GUEST_VERMAGIC
    assert binding["btf_sha256"] == guest_oracle.GUEST_BTF_SHA256
    assert binding["guest_release"] == guest_oracle.GUEST_RELEASE
    assert len(binding["ko_provenance_sha256"]) == 64


def test_oracle_refuses_tampered_bytes(tmp_path):
    tmp = str(tmp_path)
    ko_copy = os.path.join(tmp, "oracle.ko")
    prov_copy = os.path.join(tmp, "oracle.ko.provenance.json")
    shutil.copyfile(guest_oracle.FIXTURE_KO, ko_copy)
    shutil.copyfile(guest_oracle.FIXTURE_PROVENANCE, prov_copy)
    with open(ko_copy, "r+b") as handle:
        handle.seek(100)
        byte = handle.read(1)
        handle.seek(100)
        handle.write(bytes([byte[0] ^ 0xff]))
    with pytest.raises(ValueError, match="digest drift"):
        faults.verify_oracle(ko_copy, prov_copy)
    with open(prov_copy) as handle:
        receipt = json.load(handle)
    receipt["ko_sha256"] = "0" * 64
    with open(prov_copy, "w") as handle:
        json.dump(receipt, handle)
    shutil.copyfile(guest_oracle.FIXTURE_KO, ko_copy)
    with pytest.raises(ValueError, match="receipt digest drift"):
        faults.verify_oracle(ko_copy, prov_copy)
    receipt["ko_sha256"] = guest_oracle.KO_SHA256
    receipt["target_release"] = "bogus"
    with open(prov_copy, "w") as handle:
        json.dump(receipt, handle)
    with pytest.raises(ValueError, match="receipt release drift"):
        faults.verify_oracle(ko_copy, prov_copy)
    with pytest.raises(ValueError, match="provenance missing"):
        faults.verify_oracle(
            ko_copy, os.path.join(tmp, "absent.json"))
    with pytest.raises(ValueError, match="fixture missing"):
        faults.verify_oracle(
            os.path.join(tmp, "absent.ko"), prov_copy)


def test_oracle_vermagic_parsed_from_bytes(tmp_path):
    tmp = str(tmp_path)
    assert guest_oracle.vermagic_from_bytes(
        guest_oracle.FIXTURE_KO) == guest_oracle.GUEST_VERMAGIC
    blob = Path(guest_oracle.FIXTURE_KO).read_bytes()
    needle = b"7.0.14-070014-generic"
    assert blob.count(needle) >= 1
    forged = os.path.join(tmp, "forged.ko")
    with open(forged, "wb") as handle:
        handle.write(blob.replace(needle, b"7.0.14-070014-generiX"))
    assert guest_oracle.vermagic_from_bytes(forged) != \
        guest_oracle.GUEST_VERMAGIC
    bad_elf = os.path.join(tmp, "bad.ko")
    with open(bad_elf, "wb") as handle:
        handle.write(b"not an elf object")
    with pytest.raises(ValueError, match="ELF"):
        guest_oracle.vermagic_from_bytes(bad_elf)
    trunc = os.path.join(tmp, "trunc.ko")
    with open(trunc, "wb") as handle:
        handle.write(blob[:100])
    with pytest.raises(ValueError):
        guest_oracle.vermagic_from_bytes(trunc)


# -- Locked guest kernel --------------------------------------

def _fake_repo(tmp, tag, mut=None, raw=None):
    root = os.path.join(tmp, "repo-%s" % tag)
    os.makedirs(os.path.join(root, "tests", "vm"))
    with open(os.path.join(
            REPO, "tests", "vm", "kernels.lock.json")) as handle:
        lock = json.load(handle)
    if mut is not None:
        for entry in lock["kernels"]:
            if entry.get("id") == "7.0":
                mut(entry)
    if raw == "norow":
        lock["kernels"] = [entry for entry in lock["kernels"]
                           if entry.get("id") != "7.0"]
    path = os.path.join(root, "tests", "vm", "kernels.lock.json")
    with open(path, "w") as handle:
        json.dump(lock, handle)
    return root


def test_kernel_lock_refuses_per_field(tmp_path):
    tmp = str(tmp_path)

    def release(entry):
        entry["release"] = "bogus"

    def vng(entry):
        entry["source"]["vng_version"] = "bogus"

    def vmlinuz(entry):
        entry["source"]["vmlinuz_sha256"] = "0" * 64

    def modules(entry):
        entry["source"]["modules_manifest_sha256"] = "0" * 64

    for nth, (mut, reason) in enumerate(
            ((release, "release drift"), (vng, "vng tag drift"),
             (vmlinuz, "vmlinuz pin drift"),
             (modules, "modules pin drift"))):
        with pytest.raises(ValueError, match=reason):
            faults.verify_kernel_lock(_fake_repo(tmp, "k%d" % nth,
                                                 mut))
    with pytest.raises(ValueError, match="lacks row"):
        faults.verify_kernel_lock(_fake_repo(tmp, "norow",
                                             raw="norow"))
    with pytest.raises(ValueError, match="unreadable"):
        faults.verify_kernel_lock(os.path.join(tmp, "absent"))


# -- Guest identity recheck -----------------------------------

def real_binding():
    """Binding from the pins, without the dist/ seal."""
    files = faults.SEAL_MEMBERS
    return {
        "objects": {
            "lc": {"sha256": files[
                "bpf/swiotlb_lifecycle.bpf.o"]},
            "cp": {"sha256": files[
                "bpf/swiotlb_copy.bpf.o"]},
            "attempt": {"sha256": files[
                "bpf/swiotlb_attempt.bpf.o"]},
        },
        "binary": {"sha256": files["bin/memveil"]},
        "profile": {"sha256": faults.PROFILE_SHA256,
                    "profile_id": faults.PROFILE_ID},
        "oracle": {"ko_sha256": guest_oracle.KO_SHA256,
                   "btf_sha256": guest_oracle.GUEST_BTF_SHA256},
        "guest": {"release": faults.EXPECT_RELEASE},
    }


def matching_identity(binding):
    return {
        "release": binding["guest"]["release"],
        "btf_sha256": binding["oracle"]["btf_sha256"],
        "digests": {
            "ko": binding["oracle"]["ko_sha256"],
            "lc": binding["objects"]["lc"]["sha256"],
            "cp": binding["objects"]["cp"]["sha256"],
            "attempt": binding["objects"]["attempt"]["sha256"],
            "binary": binding["binary"]["sha256"],
            "profile": binding["profile"]["sha256"],
        },
    }


def test_identity_accepts_bound_measurements(tmp_path):
    binding = real_binding()
    profile_path = tmp_path / "profile.json"
    shutil.copyfile(os.path.join(REPO, faults.PROFILE_REL),
                    profile_path)
    assert faults.check_faults_identity(
        matching_identity(binding), binding,
        {"profile.json": profile_path}) == []


def test_identity_refuses_per_field(tmp_path):
    binding = real_binding()
    profile_path = tmp_path / "profile.json"
    shutil.copyfile(os.path.join(REPO, faults.PROFILE_REL),
                    profile_path)
    files = {"profile.json": profile_path}
    ident = matching_identity(binding)
    ident["release"] = "bogus"
    assert any("release" in reason for reason in
               faults.check_faults_identity(ident, binding, files))
    ident = matching_identity(binding)
    ident["btf_sha256"] = "0" * 64
    assert any("BTF" in reason for reason in
               faults.check_faults_identity(ident, binding, files))
    for channel in ("ko", "lc", "cp", "attempt", "binary",
                    "profile"):
        ident = matching_identity(binding)
        ident["digests"][channel] = "0" * 64
        assert faults.check_faults_identity(
            ident, binding, files) != [], channel
    profile_path.write_text(json.dumps({"profile_id": "bogus"}))
    assert any("profile id" in reason for reason in
               faults.check_faults_identity(
                   matching_identity(binding), binding, files))
    profile_path.write_text(json.dumps(
        {"profile_id": faults.PROFILE_ID}))
    assert any("profile bytes" in reason for reason in
               faults.check_faults_identity(
                   matching_identity(binding), binding, files))
    assert any("unreadable" in reason for reason in
               faults.check_faults_identity(
                   matching_identity(binding), binding, {}))


# -- f3a/f3b judge on synthetic logs --------------------------

def synth_files(tmp):
    dest = os.path.join(tmp, "synth")
    os.makedirs(dest, exist_ok=True)
    return battery_tests.synth_faults_files(dest)


def rewrite_json(path, mut):
    with open(path) as handle:
        doc = json.load(handle)
    mut(doc)
    with open(path, "w") as handle:
        handle.write(json.dumps(doc, sort_keys=True))


def test_judge_accepts_synthetic_faults(tmp_path):
    files = synth_files(str(tmp_path))
    assert faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION) == []


def test_judge_catches_f3_signal_regressions(tmp_path):
    tmp = str(tmp_path)
    files = synth_files(tmp)
    rewrite_json(str(files["f3a-session.json"]),
                 lambda doc: doc["capture"].update(
                     end_reason="duration"))
    bad = faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION)
    assert any("end_reason" in reason for reason in bad), bad
    files = synth_files(tmp)
    rewrite_json(str(files["f3b-record.json"]),
                 lambda doc: doc.update(exit=1))
    bad = faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION)
    assert any("record exit" in reason for reason in bad), bad
    files = synth_files(tmp)

    def stretch(doc):
        window = doc["capture"]["window"]
        window["end_ns"] = str(int(window["start_ns"])
                               + 1000000000000)
    rewrite_json(str(files["f3a-session.json"]), stretch)
    bad = faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION)
    assert any("window span" in reason for reason in bad), bad
    files = synth_files(tmp)

    def drift(doc):
        doc["environment"]["evidence"][0][
            "interpretation"] = "bogus"
    rewrite_json(str(files["f3b-session.json"]), drift)
    bad = faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION)
    assert any("profile decision" in reason
               for reason in bad), bad
    files = synth_files(tmp)
    ledger = {row["scenario"]: row for row in json.loads(
        files["faults.json"].read_text())}
    window = ledger["f3a"]["window"]
    events = _events(str(files["f3a-events.ndjson"]))
    cut, _, _ = parse_oracle_log(str(files["f3a-cut-oracle.log"]))
    windowed = [event for event in events
                if event["kind"] == "bounce_attempt"
                and window[0] <= int(event["ts_ns"]) <= window[1]]
    assert 0 < len(windowed) <= len(cut)
    first = windowed[0]
    seq = max(event["seq"] for event in events) + 1
    for _ in range(len(cut) - len(windowed) + 1):
        extra = dict(first)
        extra["seq"] = seq
        seq += 1
        extra["ts_ns"] = window[0] + 1
        events.append(extra)
    battery_tests.write_events(
        str(files["f3a-events.ndjson"]), events)
    bad = faults.judge_faults_capture(
        files, expect_decision=faults.PROFILE_DECISION)
    assert any("attempts" in reason and "logged" in reason
               for reason in bad), bad


def test_judge_rejects_bad_f3_cuts(tmp_path):
    tmp = str(tmp_path)
    files = synth_files(tmp)
    with open(files["f3a-cut-oracle.log"], "w") as handle:
        handle.write("[0.0] mv-oracle: script complete ops=0\n")
    with pytest.raises(AssertionError):
        faults.judge_faults_capture(
            files, expect_decision=faults.PROFILE_DECISION)
    files = synth_files(tmp)
    with open(files["f3b-cut-oracle.log"], "w") as handle:
        handle.write(battery_tests.oracle_script_log(ops=300))
    with pytest.raises(AssertionError):
        faults.judge_faults_capture(
            files, expect_decision=faults.PROFILE_DECISION)
    files = synth_files(tmp)
    with open(files["f3a-oracle.log"], "w") as handle:
        handle.write(battery_tests.oracle_script_log(ops=150))
    with pytest.raises(AssertionError):
        faults.judge_faults_capture(
            files, expect_decision=faults.PROFILE_DECISION)


# -- Full host flow against a mocked guest -------------------

def stage_mock_guest(work, files, corrupt=None):
    """Stage a mocked guest export tree with sidecars."""
    export = Path(work) / "export"
    export.mkdir(parents=True)
    for name in sorted(files):
        data = Path(files[name]).read_bytes()
        if name == corrupt:
            data += b"GARBAGE LINE\n"
        dest = export / ("faults-%s" % name)
        dest.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        (export / ("faults-%s.sha256" % name)).write_text(
            "%s  faults-%s\n" % (digest, name))
    return work


def synth_binding():
    """Binding matching the synthetic guest measurements."""
    manifest = battery_tests.synth_manifest()
    return {
        "guest": {"release": faults.EXPECT_RELEASE},
        "oracle": {"ko_sha256": manifest["oracle"]["ko_sha256"],
                   "btf_sha256": guest_oracle.GUEST_BTF_SHA256},
        "objects": manifest["objects"],
        "binary": manifest["binary"],
        "profile": manifest["profile"],
    }


def test_verifier_wiring_with_mocked_guest(tmp_path):
    """Snapshot, identity, and judge agree on one staged boot."""
    work = str(tmp_path / "mock")
    files = synth_files(work)
    names = sorted(files)
    stage_mock_guest(work, files)
    got, verified = faults.snapshot_faults_exports(work, names)
    assert len(verified) == len(names)
    binding = synth_binding()
    ident = json.loads(got["identity.json"].read_text())
    assert faults.check_faults_identity(
        ident, binding, got) == []
    assert faults.judge_faults_capture(
        got, expect_decision=faults.PROFILE_DECISION) == []


def test_verifier_inventory_gates(tmp_path):
    work = str(tmp_path / "mock")
    files = synth_files(work)
    names = sorted(files)
    stage_mock_guest(work, files)
    with pytest.raises(AssertionError, match="inventory drift"):
        faults.snapshot_faults_exports(work, names[:-1])
    extra = Path(work) / "export" / "faults-stowaway"
    extra.write_text("x")
    with pytest.raises(AssertionError, match="inventory drift"):
        faults.snapshot_faults_exports(work, names)
    extra.unlink()
    victim = Path(work) / "export" / "faults-faults.json"
    with open(victim, "ab") as handle:
        handle.write(b"x")
    with pytest.raises(AssertionError, match="hash mismatch"):
        faults.snapshot_faults_exports(work, names)


def test_verifier_schema_gate_wired(tmp_path):
    work = str(tmp_path / "mock")
    files = synth_files(work)
    names = ["identity.json", "profile.json", "f4-oracle.log"]
    stage_mock_guest(
        work, {name: files[name] for name in names},
        corrupt="f4-oracle.log")
    with pytest.raises(ValueError,
                       match="unexpected oracle export line"):
        faults.verify_faults_exports(work, names, synth_binding())
