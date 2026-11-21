#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Scenario runner flag + staging substitution offline tests.

No boot, no mount, no network, no privileged calls. The guest spawn
is always stopped before exec (a mocked build_vng_cmd raises, or a
mocked run_owned_guest records the call); mount/umount helpers run
only against bogus inputs whose failure is the assertion. Every case
runs from controlled fixture bytes.
"""

import hashlib
import importlib.util
import inspect
import json
import os
import subprocess
import sys
import types
from importlib.machinery import SourceFileLoader
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_matrix as km

TOOL = Path(os.path.dirname(os.path.abspath(__file__))) \
    .parent.parent / "tools" / "kernel-matrix"


def _load_tool():
    loader = SourceFileLoader("scenario_runner_tool",
                              str(TOOL))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


kmt = _load_tool()

# Documented 4-way equality bytes (deb, manifest, sealed fixture,
# release set) for the sealed source.
SEALED_COMMIT = "1af6cc9a912a38c8b2cb61da14749fbf1f628659"
SEALED_ATTEMPT = "ded931289c83713f62cdb5479fbf8aab03fe344d91a91" \
    "bdeeee7e76f106979eb"
SEALED_LIFECYCLE = "32f6a353779778981e727f311fe5d1b2c21fc92ae" \
    "9918765f86bc4f81f58df34"
SEALED_COPY = "526a6726e24f7725a0e88e28d6994f0475a1589c3de10" \
    "c7ebef703a03dfa73e8"

NEG_SHAS = {"renamed_field": "11" * 32,
            "widened_layout": "22" * 32,
            "wrong_shift": "33" * 32,
            "wrong_argcnt": "44" * 32}


def _sha(data):
    return hashlib.sha256(data).hexdigest()


# --- flag parsing ---

def test_parser_defaults_none():
    args = kmt.build_parser().parse_args(
        ["--out", "o", "--kernel", "7.0"])
    assert args.scenarios is False
    assert args.scenario_rootfs is None
    assert args.scenario_rootfs_sha256 is None
    assert args.scenario_bpf_set is None


def test_parser_scenario_flags():
    args = kmt.build_parser().parse_args(
        ["--out", "o", "--kernels", "7.0", "--scenarios",
         "--deb", "d.deb", "--scenario-rootfs", "r.img",
         "--scenario-rootfs-sha256", "ab" * 32,
         "--scenario-bpf-set", "bpf"])
    assert args.scenarios is True
    assert args.scenario_rootfs == "r.img"
    assert args.scenario_rootfs_sha256 == "ab" * 32
    assert args.scenario_bpf_set == "bpf"


def _cli_args(scenarios, rootfs=None, sha=None, bpf_set=None):
    return types.SimpleNamespace(
        scenarios=scenarios, scenario_rootfs=rootfs,
        scenario_rootfs_sha256=sha, scenario_bpf_set=bpf_set)


def test_cli_matrix_ignores_all_scenario_flags():
    state = kmt.scenario_cli_state(_cli_args(
        False, rootfs="r.img", sha="ab" * 32, bpf_set="bpf"))
    assert state is None


def test_cli_scenario_without_flags():
    state = kmt.scenario_cli_state(_cli_args(True))
    assert state == {"rootfs_image": None,
                     "rootfs_sha256": None, "bpf_set": None}


def test_cli_scenario_full_state():
    state = kmt.scenario_cli_state(_cli_args(
        True, rootfs="r.img", sha="ab" * 32, bpf_set="bpf"))
    assert state == {"rootfs_image": "r.img",
                     "rootfs_sha256": "ab" * 32,
                     "bpf_set": "bpf"}


def test_cli_half_pair_refuses():
    with pytest.raises(ValueError):
        kmt.scenario_cli_state(_cli_args(
            True, rootfs="r.img"))
    with pytest.raises(ValueError):
        kmt.scenario_cli_state(_cli_args(
            True, sha="ab" * 32))


# --- rootfs image verification (mounts nothing) ---

def test_verify_accept(tmp_path):
    img = tmp_path / "r.img"
    img.write_bytes(b"rootfs-bytes")
    got = kmt.verify_scenario_rootfs(str(img),
                                     _sha(b"rootfs-bytes"))
    assert got == {"image": os.path.abspath(str(img)),
                   "sha256": _sha(b"rootfs-bytes")}


def test_verify_accept_upper_hex(tmp_path):
    img = tmp_path / "r.img"
    img.write_bytes(b"rootfs-bytes")
    got = kmt.verify_scenario_rootfs(
        str(img), _sha(b"rootfs-bytes").upper())
    assert got["sha256"] == _sha(b"rootfs-bytes")


def test_verify_missing_refuses(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        kmt.verify_scenario_rootfs(
            str(tmp_path / "absent.img"), "ab" * 32)


def test_verify_directory_refuses(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        kmt.verify_scenario_rootfs(str(tmp_path), "ab" * 32)


def test_verify_malformed_digest_refuses(tmp_path):
    img = tmp_path / "r.img"
    img.write_bytes(b"rootfs-bytes")
    for bad in ("xyz", "ab" * 31, "ab" * 33, "zz" * 32, "",
                None):
        with pytest.raises(ValueError, match="64 hex"):
            kmt.verify_scenario_rootfs(str(img), bad)


def test_verify_mismatch_refuses(tmp_path):
    img = tmp_path / "r.img"
    img.write_bytes(b"rootfs-bytes")
    with pytest.raises(ValueError, match="mismatch"):
        kmt.verify_scenario_rootfs(str(img), "ab" * 32)


# --- guest command + vng argv builders ---

def test_scenario_guest_cmd_exact():
    assert kmt.scenario_guest_cmd() == \
        "python3 /mv/repo/tests/vm/kernel_scenarios_guest.py " \
        "/tmp/export /mv/repo"


def test_rootfs_vng_args_exact(tmp_path):
    mount = str(tmp_path / "mnt")
    stage = str(tmp_path / "out" / "7.0" / "ro-deb")
    assert kmt.scenario_rootfs_vng_args(mount, stage) == [
        "--root", mount,
        "--cwd", mount,
        "--rodir=/mv/repo=%s" % kmt.ROOT,
        "--rodir=/mv/deb=%s" % stage]


# --- mount/umount helpers (failures only; never mount live) ---

def test_mount_refuses_crowded_point(tmp_path):
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    (mnt / "stray").write_text("x")
    with pytest.raises(ValueError, match="not empty"):
        kmt.mount_scenario_rootfs("img", str(mnt), False)


def test_mount_failure_refuses(tmp_path):
    mnt = tmp_path / "mnt"
    bogus = tmp_path / "bogus.img"
    bogus.write_bytes(b"not-a-filesystem")
    with pytest.raises(ValueError, match="mount"):
        kmt.mount_scenario_rootfs(str(bogus), str(mnt),
                                  False)


def test_umount_failure_returns_text(tmp_path):
    note = kmt.umount_scenario_rootfs(
        str(tmp_path / "nomnt"), False)
    assert isinstance(note, str) and note


def test_umount_never_raises():
    assert isinstance(
        kmt.umount_scenario_rootfs("", False), str)
    assert isinstance(
        kmt.umount_scenario_rootfs("", True), str)


# --- release-output sets (complete-set + divergence) ---

def _write_set(base, name, blobs):
    out = Path(base) / name / "out"
    out.mkdir(parents=True)
    for channel, data in blobs.items():
        (out / ("memveil-ebpf-" + channel)).write_bytes(data)
    return out


BLOBS = {"attempt": b"attempt-bytes",
         "lifecycle": b"lifecycle-bytes",
         "copy": b"copy-bytes"}
BLOB_SHAS = {channel: _sha(data)
             for channel, data in BLOBS.items()}


def test_set_single_accept(tmp_path):
    _write_set(tmp_path, "aaa", BLOBS)
    assert kmt.release_set_shas(str(tmp_path)) == BLOB_SHAS


def test_set_two_agreeing_accept(tmp_path):
    first = _write_set(tmp_path, "aaa", BLOBS)
    second = _write_set(tmp_path, "bbb", BLOBS)
    os.utime(str(second / "memveil-ebpf-attempt"),
             (1, 2000000000))
    os.utime(str(first / "memveil-ebpf-attempt"),
             (1, 1000000000))
    assert kmt.release_set_shas(str(tmp_path)) == BLOB_SHAS


def test_set_diverged_refuses(tmp_path):
    _write_set(tmp_path, "aaa", BLOBS)
    other = dict(BLOBS)
    other["copy"] = b"other-copy-bytes"
    _write_set(tmp_path, "bbb", other)
    with pytest.raises(ValueError, match="divergent"):
        kmt.release_set_shas(str(tmp_path))


def test_set_incomplete_refuses(tmp_path):
    out = Path(tmp_path) / "aaa" / "out"
    out.mkdir(parents=True)
    (out / "memveil-ebpf-attempt").write_bytes(b"x")
    (out / "memveil-ebpf-lifecycle").write_bytes(b"y")
    with pytest.raises(ValueError, match="no complete"):
        kmt.release_set_shas(str(tmp_path))


def test_set_missing_refuses(tmp_path):
    with pytest.raises(ValueError, match="missing"):
        kmt.release_set_shas(str(tmp_path / "absent"))


def test_set_empty_refuses(tmp_path):
    with pytest.raises(ValueError, match="no complete"):
        kmt.release_set_shas(str(tmp_path))


# --- candidate manifest + sealed fixture ---

def _mint_manifest(path, bpf_shas, commit=SEALED_COMMIT):
    sys.path.insert(0, str(kmt.ROOT / "tools"))
    import candidate
    files = {"bin/memveil": "aa" * 32,
             "lib/memveil/libmemveil.so.1": "bb" * 32,
             "profiles/p.json": "cc" * 32}
    for channel, digest in bpf_shas.items():
        files["bpf/swiotlb_%s.bpf.o" % channel] = digest
    doc = {
        "schema": "memveil-candidate/2",
        "origin": "local-build",
        "source": {"commit": commit, "tree": "12" * 20,
                   "inventory_sha256": "dd" * 32},
        "toolchain": {
            "cargo_lock_sha256": "ee" * 32,
            "ebpf_lock_sha256": "ff" * 32,
            "tools": {"cargo": "1.2.3", "rustc": "1.2.3",
                      "bpf_linker": "0.1.2"}},
        "build_receipt_sha256": "01" * 32,
        "bundle_manifest_sha256": "02" * 32,
        "policy_sha256": "03" * 32,
        "files": files,
        "artifacts": [
            {"role": role, "name": role + ".bin",
             "size": "1", "sha256": "04" * 32}
            for role in ("bundle", "deb", "rpm", "source",
                         "sbom", "provenance")],
    }
    return candidate.seal_manifest(doc, str(path))


def _sealed_bpf_shas():
    return {"attempt": SEALED_ATTEMPT,
            "lifecycle": SEALED_LIFECYCLE,
            "copy": SEALED_COPY}


def test_manifest_needs_env(monkeypatch):
    monkeypatch.delenv("MV_CANDIDATE_MANIFEST",
                       raising=False)
    with pytest.raises(ValueError,
                       match="MV_CANDIDATE_MANIFEST"):
        kmt.scenario_manifest()


def test_manifest_refuses_garbage(tmp_path, monkeypatch):
    bad = tmp_path / "candidate.json"
    bad.write_text("{nope")
    monkeypatch.setenv("MV_CANDIDATE_MANIFEST", str(bad))
    with pytest.raises(ValueError, match="refused"):
        kmt.scenario_manifest()


def test_manifest_accepts_minted(tmp_path, monkeypatch):
    path = tmp_path / "candidate.json"
    _mint_manifest(path, _sealed_bpf_shas())
    monkeypatch.setenv("MV_CANDIDATE_MANIFEST", str(path))
    manifest = kmt.scenario_manifest()
    assert manifest["source"]["commit"] == SEALED_COMMIT
    assert kmt.manifest_bpf_sha(manifest, "copy") == \
        SEALED_COPY


def test_manifest_bpf_missing_refuses():
    with pytest.raises(ValueError, match="bpf copy"):
        kmt.manifest_bpf_sha({}, "copy")
    with pytest.raises(ValueError, match="bpf copy"):
        kmt.manifest_bpf_sha({"files": {}}, "copy")


def test_sealed_fixture_real_copy():
    assert kmt.sealed_fixture_sha(SEALED_COMMIT, "copy") == \
        SEALED_COPY


def test_sealed_fixture_bogus_refuses():
    with pytest.raises(ValueError, match="unreadable"):
        kmt.sealed_fixture_sha("f" * 40, "copy")
    with pytest.raises(ValueError, match="unreadable"):
        kmt.sealed_fixture_sha(SEALED_COMMIT, "nope")


def test_old_target_authority_gone():
    assert not hasattr(kmt, "rust_copy_object_sha")


# --- staging substitution ---

def _stage_env(tmp_path, monkeypatch, bpf_shas=None,
               commit=SEALED_COMMIT, deb_sha=SEALED_COPY):
    path = tmp_path / "candidate.json"
    _mint_manifest(path, _sealed_bpf_shas()
                   if bpf_shas is None else bpf_shas,
                   commit=commit)
    monkeypatch.setenv("MV_CANDIDATE_MANIFEST", str(path))
    monkeypatch.setattr(kmt, "scenario_negatives",
                        lambda: dict(NEG_SHAS))
    monkeypatch.setattr(kmt, "deb_copy_object_sha",
                        lambda deb: deb_sha)


def test_staging_fixture_accept_4way(tmp_path, monkeypatch):
    _stage_env(tmp_path, monkeypatch)
    shas, staging = kmt.check_scenario_inputs("d.deb")
    assert shas == NEG_SHAS
    assert staging["reference"] == "sealed-fixture"
    assert staging["manifest_commit"] == SEALED_COMMIT
    assert staging["copy_sha256"] == SEALED_COPY
    assert staging["bpf_set"] is None
    assert len(staging["manifest_digest"]) == 64


def test_staging_needs_manifest(monkeypatch):
    monkeypatch.delenv("MV_CANDIDATE_MANIFEST",
                       raising=False)
    monkeypatch.setattr(kmt, "scenario_negatives",
                        lambda: dict(NEG_SHAS))
    with pytest.raises(ValueError,
                       match="MV_CANDIDATE_MANIFEST"):
        kmt.check_scenario_inputs("d.deb")


def test_staging_diverged_deb_refuses(tmp_path, monkeypatch):
    _stage_env(tmp_path, monkeypatch, deb_sha="00" * 32)
    with pytest.raises(ValueError, match="deb copy object"):
        kmt.check_scenario_inputs("d.deb")


def test_staging_diverged_fixture_refuses(tmp_path,
                                          monkeypatch):
    _stage_env(tmp_path, monkeypatch)
    monkeypatch.setattr(kmt, "sealed_fixture_sha",
                        lambda commit, channel: "00" * 32)
    with pytest.raises(ValueError, match="fixture blob"):
        kmt.check_scenario_inputs("d.deb")


def test_staging_unpinned_manifest_refuses(tmp_path,
                                           monkeypatch):
    _stage_env(tmp_path, monkeypatch)
    monkeypatch.setattr(kmt, "scenario_manifest",
                        lambda: {"source": {
                            "commit": SEALED_COMMIT},
                            "files": {}})
    with pytest.raises(ValueError, match="bpf copy"):
        kmt.check_scenario_inputs("d.deb")
    monkeypatch.setattr(kmt, "scenario_manifest",
                        lambda: {"files": {
                            "bpf/swiotlb_copy.bpf.o":
                                SEALED_COPY}})
    with pytest.raises(ValueError, match="sealed source"):
        kmt.check_scenario_inputs("d.deb")


def test_staging_bpf_set_accept(tmp_path, monkeypatch):
    _write_set(tmp_path / "bpf", "aaa", BLOBS)
    _stage_env(tmp_path, monkeypatch, bpf_shas=BLOB_SHAS,
               deb_sha=BLOB_SHAS["copy"])
    shas, staging = kmt.check_scenario_inputs(
        "d.deb", bpf_set=str(tmp_path / "bpf"))
    assert shas == NEG_SHAS
    assert staging["reference"] == "bpf-set"
    assert staging["copy_sha256"] == BLOB_SHAS["copy"]
    assert staging["bpf_set"] == os.path.realpath(
        str(tmp_path / "bpf"))


def test_staging_bpf_set_diverged_refuses(tmp_path,
                                          monkeypatch):
    other = dict(BLOBS)
    other["copy"] = b"other-copy-bytes"
    _write_set(tmp_path / "bpf", "aaa", other)
    _stage_env(tmp_path, monkeypatch, bpf_shas=BLOB_SHAS,
               deb_sha=BLOB_SHAS["copy"])
    with pytest.raises(ValueError, match="copy channel"):
        kmt.check_scenario_inputs(
            "d.deb", bpf_set=str(tmp_path / "bpf"))


def test_staging_bpf_set_incomplete_refuses(tmp_path,
                                            monkeypatch):
    out = tmp_path / "bpf" / "aaa" / "out"
    out.mkdir(parents=True)
    (out / "memveil-ebpf-copy").write_bytes(BLOBS["copy"])
    _stage_env(tmp_path, monkeypatch, bpf_shas=BLOB_SHAS,
               deb_sha=BLOB_SHAS["copy"])
    with pytest.raises(ValueError, match="no complete"):
        kmt.check_scenario_inputs(
            "d.deb", bpf_set=str(tmp_path / "bpf"))


def test_staging_bpf_set_inside_tree_refuses(tmp_path,
                                             monkeypatch):
    _stage_env(tmp_path, monkeypatch)
    for inside in (str(kmt.ROOT),
                   str(kmt.ROOT / "tests")):
        with pytest.raises(ValueError, match="inside"):
            kmt.check_scenario_inputs("d.deb",
                                      bpf_set=inside)


# --- deb staging into the export ---

def _fake_root(tmp_path, monkeypatch):
    root = tmp_path / "root"
    neg = root / "build" / "bpf-negative"
    neg.mkdir(parents=True)
    for name in kmt.NEGATIVE_NAMES:
        (neg / ("swiotlb_copy-%s.bpf.o" % name)).write_bytes(
            b"neg-" + name.encode())
    monkeypatch.setattr(kmt, "ROOT", root)
    return root


def _rootfs(mnt="m"):
    return {"image": "r.img", "sha256": "ab" * 32,
            "mount": mnt, "privilege": "direct",
            "runner_commit": "c" * 40, "runner_dirty": False}


_STAGING = {"reference": "sealed-fixture",
            "manifest_digest": "dd" * 32,
            "manifest_commit": SEALED_COMMIT,
            "copy_sha256": SEALED_COPY, "bpf_set": None}


def test_stage_legacy(tmp_path, monkeypatch):
    _fake_root(tmp_path, monkeypatch)
    export = str(tmp_path / "7.0")
    os.makedirs(export)
    job = {"deb": "host.deb"}
    kmt.stage_scenario_files(export, job, NEG_SHAS,
                             staging=_STAGING)
    assert job["negatives"] == NEG_SHAS
    assert job["staging"] == _STAGING
    assert job["deb"] == "host.deb"
    assert "rootfs" not in job
    assert not os.path.exists(os.path.join(export, "ro-deb"))
    for name in kmt.NEGATIVE_NAMES:
        assert os.path.isfile(os.path.join(
            export, "neg", "swiotlb_copy-%s.bpf.o" % name))


def test_stage_rootfs(tmp_path, monkeypatch):
    _fake_root(tmp_path, monkeypatch)
    deb = tmp_path / "memveil-test.deb"
    deb.write_bytes(b"deb-bytes")
    export = str(tmp_path / "7.0")
    os.makedirs(export)
    job = {"deb": str(deb)}
    rootfs = _rootfs(mnt=str(tmp_path / "mnt"))
    kmt.stage_scenario_files(export, job, NEG_SHAS,
                             deb=str(deb), rootfs=rootfs,
                             staging=_STAGING)
    staged = os.path.join(export, "ro-deb",
                          "memveil-test.deb")
    assert Path(staged).read_bytes() == b"deb-bytes"
    assert job["deb"] == "/mv/deb/memveil-test.deb"
    assert job["deb_host"] == str(deb)
    assert job["rootfs"] == {"image": "r.img",
                             "sha256": "ab" * 32,
                             "mount": str(tmp_path / "mnt")}
    record = json.loads(Path(
        export, "rootfs.json").read_text())
    assert record["image"] == "r.img"
    assert record["sha256"] == "ab" * 32
    assert record["privilege"] == "direct"
    assert record["runner_commit"] == "c" * 40
    assert record["runner_dirty"] is False
    assert record["staging"] == _STAGING


def test_stage_rootfs_needs_deb(tmp_path, monkeypatch):
    _fake_root(tmp_path, monkeypatch)
    export = str(tmp_path / "7.0")
    os.makedirs(export)
    with pytest.raises(ValueError, match="deb path"):
        kmt.stage_scenario_files(export, {}, NEG_SHAS,
                                 rootfs=_rootfs())


def test_stage_rootfs_copy_corrupt_refuses(tmp_path,
                                           monkeypatch):
    _fake_root(tmp_path, monkeypatch)
    deb = tmp_path / "memveil-test.deb"
    deb.write_bytes(b"deb-bytes")
    export = str(tmp_path / "7.0")
    os.makedirs(export)
    calls = iter(["aa" * 32, "bb" * 32])
    monkeypatch.setattr(km, "sha_file",
                        lambda path: next(calls))
    with pytest.raises(ValueError, match="staged deb copy"):
        kmt.stage_scenario_files(export, {}, NEG_SHAS,
                                 deb=str(deb),
                                 rootfs=_rootfs())


# --- run_one argv + cwd (spawn always mocked; never boots) ---

def _run_args(out, scenarios=False):
    return types.SimpleNamespace(
        out=str(out), duration=60, dd_count=128,
        timeout=900, cpus=4, scenarios=scenarios,
        scenario_rootfs=None, scenario_rootfs_sha256=None,
        scenario_bpf_set=None)


def _run_entry():
    return {
        "id": "7.0",
        "release": "7.0.14-test",
        "source": {"kind": "archive",
                   "vng_version": "v7.0.14"},
        "expected": {
            cap: {"verdict": "refused",
                  "reason_class": "floor-6.0"}
            for cap in km.CAPS},
    }


def _receipt_base():
    return {"mode": "matrix", "kind": "bundle",
            "source_sha256": "ss" * 32,
            "kernel_selector": "--kernel 7.0",
            "duration_s": 60, "dd_count": 128,
            "timeout_s": 900, "cpus": 4, "timeout": False,
            "source": ("archive", "v7.0.14", "x"),
            "toolchain": {}, "lock_tools": {},
            "shipped_profile_id": None}


def _mock_pre_spawn(monkeypatch, tmp_path, captured,
                    stop=True):
    import shutil
    monkeypatch.setattr(
        shutil, "which",
        lambda tool: "/usr/bin/" + tool)
    monkeypatch.setattr(
        kmt, "verify_cache",
        lambda entry: (True, "cached", str(tmp_path),
                       "v7.0.14"))
    monkeypatch.setattr(
        kmt, "ensure_scratch",
        lambda disk_img, ident: str(tmp_path / "scr.img"))
    monkeypatch.setattr(kmt, "shipped_id",
                        lambda entry: None)
    monkeypatch.setattr(km, "write_row_receipt",
                        lambda *args: None)

    def fake_build(prefix, cpus, home, vng_args):
        captured["prefix"] = list(prefix)
        captured["vng_args"] = list(vng_args)
        if stop:
            raise ValueError("stop-before-boot")
        return ["/abs/vng"] + list(vng_args)

    monkeypatch.setattr(km, "build_vng_cmd", fake_build)


def _legacy_guest_cmd(script):
    return "python3 %s /tmp/export %s" % (script, kmt.ROOT)


def _expect_base(export, disk, scratch, guest_cmd):
    return ["--run", "v7.0.14",
            "--cpus", "4",
            "-m", "4G",
            "--append", "swiotlb=131072,force tsc=nowatchdog",
            "--overlay-rwdir=/usr", "--overlay-rwdir=/etc",
            "--overlay-rwdir=/var",
            "--rwdir=/tmp/export=%s" % export,
            "--qemu-opts=-cpu host %s %s" % (
                km.qemu_drive_opt(disk),
                km.qemu_drive_opt(scratch, drive_id="d1",
                                  serial="mv1",
                                  readonly=False)),
            "--exec", guest_cmd]


def test_run_one_signature_defaults_rootfs_none():
    param = inspect.signature(
        kmt.run_one).parameters["rootfs"]
    assert param.default is None


def test_matrix_argv_exact(tmp_path, monkeypatch):
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    out = tmp_path / "out"
    disk = str(tmp_path / "disk.img")
    args = _run_args(out)
    kmt.run_one(_run_entry(), args, "bundle", "b",
                disk, {}, "t", ["/abs/vng"], _receipt_base())
    export = os.path.join(str(out), "7.0")
    script = str(kmt.ROOT / "tests" / "vm"
                 / "kernel_matrix_guest.py")
    assert captured["vng_args"] == _expect_base(
        export, disk, str(tmp_path / "scr.img"),
        _legacy_guest_cmd(script))


def test_matrix_ignores_scenario_flags(tmp_path, monkeypatch):
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    out = tmp_path / "out"
    disk = str(tmp_path / "disk.img")
    args = _run_args(out)
    args.scenario_rootfs = "r.img"
    args.scenario_rootfs_sha256 = "ab" * 32
    args.scenario_bpf_set = "bpf"
    kmt.run_one(_run_entry(), args, "bundle", "b",
                disk, {}, "t", ["/abs/vng"], _receipt_base())
    export = os.path.join(str(out), "7.0")
    script = str(kmt.ROOT / "tests" / "vm"
                 / "kernel_matrix_guest.py")
    assert captured["vng_args"] == _expect_base(
        export, disk, str(tmp_path / "scr.img"),
        _legacy_guest_cmd(script))


def test_scenario_legacy_argv(tmp_path, monkeypatch):
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    out = tmp_path / "out"
    disk = str(tmp_path / "disk.img")
    args = _run_args(out, scenarios=True)
    staged = {}
    kmt.run_one(_run_entry(), args, "deb", "d.deb",
                disk, {}, "t", ["/abs/vng"], _receipt_base(),
                guest_script=str(
                    kmt.ROOT / "tests" / "vm"
                    / "kernel_scenarios_guest.py"),
                collect=kmt.collect_scenarios,
                stage=lambda export, job: staged.update(job))
    export = os.path.join(str(out), "7.0")
    script = str(kmt.ROOT / "tests" / "vm"
                 / "kernel_scenarios_guest.py")
    assert captured["vng_args"] == _expect_base(
        export, disk, str(tmp_path / "scr.img"),
        _legacy_guest_cmd(script))
    assert "--root" not in captured["vng_args"]


def test_scenario_rootfs_argv(tmp_path, monkeypatch):
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    monkeypatch.chdir(tmp_path)
    out = Path("rel")
    disk = "disk.img"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    args = _run_args(out, scenarios=True)
    kmt.run_one(_run_entry(), args, "deb", "d.deb",
                disk, {}, "t", ["/abs/vng"], _receipt_base(),
                guest_script="unused",
                collect=kmt.collect_scenarios,
                stage=lambda export, job: None,
                rootfs=_rootfs(mnt=str(mnt)))
    export = os.path.abspath(os.path.join(str(out), "7.0"))
    disk_abs = os.path.abspath(disk)
    base = _expect_base(export, disk_abs,
                        str(tmp_path / "scr.img"),
                        kmt.scenario_guest_cmd())
    extras = kmt.scenario_rootfs_vng_args(
        str(mnt), os.path.join(export, "ro-deb"))
    assert captured["vng_args"] == \
        base[:-2] + extras + base[-2:]
    assert captured["vng_args"].count("--root") == 1


def _mock_full_run(monkeypatch, tmp_path, captured, seen):
    _mock_pre_spawn(monkeypatch, tmp_path, captured,
                    stop=False)
    import vm_process

    def fake_spawn(cmd, timeout):
        seen["cmd"] = list(cmd)
        seen["cwd"] = os.getcwd()
        return subprocess.CompletedProcess(cmd, 0, "out",
                                           "")

    monkeypatch.setattr(vm_process, "run_owned_guest",
                        fake_spawn)


def test_matrix_never_chdirs(tmp_path, monkeypatch):
    captured, seen = {}, {}
    _mock_full_run(monkeypatch, tmp_path, captured, seen)
    before = os.getcwd()
    out = tmp_path / "out"
    rec = kmt.run_one(
        _run_entry(), _run_args(out), "bundle", "b",
        str(tmp_path / "disk.img"), {}, "t",
        ["/abs/vng"], _receipt_base(),
        collect=lambda *args: {"id": "7.0", "ok": True,
                               "detail": "mocked",
                               "elapsed": 0.1,
                               "run_id": "t"})
    assert seen["cwd"] == before
    assert os.getcwd() == before
    assert rec["ok"]
    assert seen["cmd"][0] == "/abs/vng"
    assert "--root" not in seen["cmd"]


def test_rootfs_spawns_inside_mount_and_restores(
        tmp_path, monkeypatch):
    captured, seen = {}, {}
    _mock_full_run(monkeypatch, tmp_path, captured, seen)
    before = os.getcwd()
    out = tmp_path / "out"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    rec = kmt.run_one(
        _run_entry(), _run_args(out, scenarios=True),
        "deb", "d.deb", str(tmp_path / "disk.img"), {},
        "t", ["/abs/vng"], _receipt_base(),
        guest_script="unused",
        collect=lambda *args: {"id": "7.0", "ok": True,
                               "detail": "mocked",
                               "elapsed": 0.1,
                               "run_id": "t"},
        stage=lambda export, job: None,
        rootfs=_rootfs(mnt=str(mnt)))
    assert seen["cwd"] == str(mnt)
    assert os.getcwd() == before
    assert rec["ok"]
    export = os.path.abspath(os.path.join(str(out), "7.0"))
    assert Path(export, "vng-cmd.txt").read_text() == \
        " ".join(seen["cmd"]) + "\n"
    assert Path(export, "vng.exit").read_text() == "0"
    assert "--root" in seen["cmd"]
    assert str(mnt) in seen["cmd"]


def test_rootfs_chdir_failure_refuses(tmp_path, monkeypatch):
    captured, seen = {}, {}
    _mock_full_run(monkeypatch, tmp_path, captured, seen)
    before = os.getcwd()
    out = tmp_path / "out"
    rec = kmt.run_one(
        _run_entry(), _run_args(out, scenarios=True),
        "deb", "d.deb", str(tmp_path / "disk.img"), {},
        "t", ["/abs/vng"], _receipt_base(),
        guest_script="unused",
        collect=kmt.collect_scenarios,
        stage=lambda export, job: None,
        rootfs=_rootfs(mnt=str(tmp_path / "nomnt")))
    assert not rec["ok"]
    assert rec["checks"][0]["name"] == "rootfs"
    assert rec["checks"][0]["detail"] == \
        "rootfs-chdir-failed"
    assert os.getcwd() == before
    assert "cmd" not in seen


def test_rootfs_relative_vng_resolved(tmp_path, monkeypatch):
    import shutil
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    monkeypatch.setattr(
        shutil, "which",
        lambda tool: "/usr/bin/" + tool
        if tool in ("bpftrace", "bpftool")
        else "rel/dir/vng")
    out = tmp_path / "out"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    kmt.run_one(_run_entry(), _run_args(out, scenarios=True),
                "deb", "d.deb", str(tmp_path / "disk.img"),
                {}, "t", ["relvng"], _receipt_base(),
                guest_script="unused",
                collect=kmt.collect_scenarios,
                stage=lambda export, job: None,
                rootfs=_rootfs(mnt=str(mnt)))
    assert captured["prefix"] == [
        os.path.abspath("rel/dir/vng")]


def test_rootfs_relative_vng_unresolved(tmp_path,
                                        monkeypatch):
    import shutil
    captured = {}
    _mock_pre_spawn(monkeypatch, tmp_path, captured)
    monkeypatch.setattr(
        shutil, "which",
        lambda tool: "/usr/bin/" + tool
        if tool in ("bpftrace", "bpftool") else None)
    monkeypatch.setattr(
        km, "build_vng_cmd",
        lambda *args: (_ for _ in ()).throw(
            AssertionError("must not build")))
    out = tmp_path / "out"
    mnt = tmp_path / "mnt"
    mnt.mkdir()
    rec = kmt.run_one(
        _run_entry(), _run_args(out, scenarios=True),
        "deb", "d.deb", str(tmp_path / "disk.img"), {},
        "t", ["relvng"], _receipt_base(),
        guest_script="unused",
        collect=kmt.collect_scenarios,
        stage=lambda export, job: None,
        rootfs=_rootfs(mnt=str(mnt)))
    assert not rec["ok"]
    assert rec["checks"][0]["name"] == "vng_cmd"
    assert rec["checks"][0]["detail"] == "vng-unresolved"
