# SPDX-License-Identifier: GPL-3.0-or-later

"""SBOM tests: SPDX content comes from recorded inputs only.

tools/sbom emits SPDX 2.3 JSON whose every hash is traceable:
payload file hashes equal tools/payload-gate --collect over
the same three packages, the bridge pin and toolchain
versions equal the repository lock, and the container
hashes equal the shipped files. Two runs differ only in the
creation timestamp; a bundle whose MANIFEST disagrees with
the lock fails instead of emitting.

Environment: MV_BUNDLE_TARBALL, MV_DEB, MV_RPM (required,
the three release packages), MV_REPO (optional, defaults to
this checkout).
"""

import hashlib
import json
import os
import subprocess
import tarfile

import pytest

BUNDLE = os.environ.get("MV_BUNDLE_TARBALL", "")
DEB = os.environ.get("MV_DEB", "")
RPM = os.environ.get("MV_RPM", "")
REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))

SBOM = os.path.join(REPO, "tools", "sbom")
GATE = os.path.join(REPO, "tools", "payload-gate")
LOCK = os.path.join(REPO, "toolchain.lock.json")

needs_packages = pytest.mark.skipif(
    not (BUNDLE and DEB and RPM),
    reason="MV_BUNDLE_TARBALL/MV_DEB/MV_RPM are not set "
           "(run tools/test sbom)")


def run_sbom(*args):
    return subprocess.run(
        ["python3", SBOM] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def emit(tmp_path, name="memveil.spdx.json", bundle=None,
         lock=None):
    out = str(tmp_path / name)
    proc = run_sbom("--bundle", bundle or BUNDLE,
                    "--deb", DEB, "--rpm", RPM,
                    "--lock", lock or LOCK, "--out", out)
    assert proc.returncode == 0, proc.stderr.decode()
    with open(out, encoding="utf-8") as handle:
        return json.load(handle)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_payload(tmp_path):
    out = str(tmp_path / "PACKAGED-SHA256.txt")
    proc = subprocess.run(
        ["python3", GATE, "--collect", "--deb", DEB,
         "--rpm", RPM, "--bundle", BUNDLE, "--out", out],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr.decode()
    entries = {}
    with open(out, encoding="utf-8") as handle:
        for line in handle.read().splitlines():
            if line.strip():
                parts = line.split()
                entries[parts[1]] = parts[0]
    return entries


def files_by_name(doc):
    return {entry["fileName"]: entry for entry in doc["files"]}


def packages_by_name(doc):
    found = {}
    for entry in doc["packages"]:
        found.setdefault(entry["name"], []).append(entry)
    return found


@needs_packages
def test_spdx_envelope(tmp_path):
    doc = emit(tmp_path)
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["name"].startswith("memveil-")
    assert doc["documentNamespace"].startswith("urn:memveil:")
    assert doc["creationInfo"]["created"].endswith("Z")
    describes = [rel for rel in doc["relationships"]
                 if rel["relationshipType"] == "DESCRIBES"]
    assert len(describes) == 1
    root = [pkg for pkg in doc["packages"]
            if pkg["name"] == "memveil"]
    assert len(root) == 1
    assert describes[0]["relatedSpdxElement"] == root[0]["SPDXID"]


@needs_packages
def test_payload_hashes_match_collect(tmp_path):
    doc = emit(tmp_path)
    payload = collect_payload(tmp_path)
    assert len(payload) == 15
    files = files_by_name(doc)
    for logical, digest in payload.items():
        entry = files.get("payload/%s" % logical)
        assert entry is not None, logical
        assert entry["checksums"] == [
            {"algorithm": "SHA256", "checksumValue": digest}]


@needs_packages
def test_bridge_and_toolchain_match_lock(tmp_path):
    doc = emit(tmp_path)
    with open(LOCK, encoding="utf-8") as handle:
        lock = json.load(handle)
    pkgs = packages_by_name(doc)
    bridge = pkgs["libbpf-mojo"][0]
    want_bridge = lock["dependencies"]["libbpf-mojo"]
    assert bridge["versionInfo"] == want_bridge["version"]
    assert bridge["checksums"] == [
        {"algorithm": "SHA256",
         "checksumValue": want_bridge["tarball_sha256"]}]
    assert pkgs["mojo"][0]["versionInfo"] == \
        lock["toolchain"]["mojo"]["version"]
    assert pkgs["pixi"][0]["versionInfo"] == \
        lock["toolchain"]["pixi"]["version"]


@needs_packages
def test_container_hashes_match_shipped_files(tmp_path):
    doc = emit(tmp_path)
    pkgs = packages_by_name(doc)
    for path in (BUNDLE, DEB, RPM):
        entries = pkgs.get(os.path.basename(path))
        assert entries is not None, path
        assert entries[0]["checksums"] == [
            {"algorithm": "SHA256",
             "checksumValue": sha256_of(path)}]


@needs_packages
def test_deterministic_except_created(tmp_path):
    first = emit(tmp_path, "first.spdx.json")
    second = emit(tmp_path, "second.spdx.json")
    first["creationInfo"]["created"] = "STAMP"
    second["creationInfo"]["created"] = "STAMP"
    assert first == second


@needs_packages
def test_bridge_disagreement_fails(tmp_path):
    with open(LOCK, encoding="utf-8") as handle:
        lock = json.load(handle)
    lock["dependencies"]["libbpf-mojo"]["tarball_sha256"] = \
        "1" * 64
    bad_lock = str(tmp_path / "bad-lock.json")
    with open(bad_lock, "w", encoding="utf-8") as handle:
        json.dump(lock, handle)
    out = str(tmp_path / "disagree.spdx.json")
    proc = run_sbom("--bundle", BUNDLE, "--deb", DEB,
                    "--rpm", RPM, "--lock", bad_lock,
                    "--out", out)
    assert proc.returncode == 1
    assert "disagreement" in proc.stderr.decode()
    assert not os.path.exists(out)


@needs_packages
def test_bundle_without_manifest_fails(tmp_path):
    work = tmp_path / "nomanifest"
    (work / "memveil-0.0.0").mkdir(parents=True)
    (work / "memveil-0.0.0" / "stray.txt").write_text("x")
    hollow = str(work / "hollow.tar.gz")
    with tarfile.open(hollow, "w:gz") as archive:
        archive.add(str(work / "memveil-0.0.0"),
                    arcname="memveil-0.0.0")
    out = str(tmp_path / "hollow.spdx.json")
    proc = run_sbom("--bundle", hollow, "--deb", DEB,
                    "--rpm", RPM, "--lock", LOCK, "--out", out)
    assert proc.returncode == 2
    assert "MANIFEST" in proc.stderr.decode()


def test_usage_errors_exit_2(tmp_path):
    proc = run_sbom("--bundle", BUNDLE)
    assert proc.returncode == 2
    proc = run_sbom("--bundle", str(tmp_path / "nope.tar.gz"),
                    "--deb", DEB, "--rpm", RPM,
                    "--lock", LOCK,
                    "--out", str(tmp_path / "nope.spdx.json"))
    assert proc.returncode == 2
