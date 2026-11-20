# SPDX-License-Identifier: GPL-3.0-or-later
"""Synthetic sealed candidates for the installed-mapping tests.

Wraps the seal fixture in test_candidate.py: one process-wide
workshop plus per-test fresh copies, sealed through the real
candidate protocol. Callers get a manifest plus a bundle
tarball and a .deb/.rpm pair whose names they choose, so the
installed runners can prove they consumed exactly those sealed
paths and no build outputs.

Requires git, dpkg-deb, rpmbuild, cargo, and bpf-linker on
PATH; missing tools fail closed (install them, do not skip:
skips would mask the mapping proof).
"""

import atexit
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests"))
from test_candidate import (FIXED_EPOCH, Workshop,
                            deterministic_tar_gz)
import candidate as protocol

REQUIRED_TOOLS = ("git", "dpkg-deb", "rpmbuild", "cargo",
                  "bpf-linker", "python3")

_workshop = None


def require_tool(name):
    if not shutil.which(name):
        pytest.fail("sealed fixture requires %s on PATH" % name)


def workshop():
    """Process-wide seal workshop (built once, read-only after)."""
    global _workshop
    if _workshop is not None:
        return _workshop
    for name in REQUIRED_TOOLS:
        require_tool(name)
    base = Path(tempfile.mkdtemp(prefix="memveil-seal-base-"))
    atexit.register(shutil.rmtree, base, True)
    _workshop = Workshop(base)
    return _workshop


def _git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True).stdout.strip()


def _regenerate_seal_bindings(fix, harness_bin):
    """Rebind the SBOM and provenance to the present artifacts.

    Both documents bind artifact names and digests, so the
    fixture copies are re-emitted after any rename or re-tar
    before the seal. Shapes mirror the workshop build.
    """
    artifacts = fix["artifacts"]
    manifest_bytes = (
        fix["bundle_dir"] / "MANIFEST.json").read_bytes()
    roles = protocol.discover_artifacts(
        artifacts, manifest_bytes)
    sbom_out = roles["sbom"]
    sbom_out.unlink()
    proc = subprocess.run(
        [harness_bin, "sbom-emit",
         "--manifest",
         str(fix["bundle_dir"] / "MANIFEST.json"),
         "--bundle", str(roles["bundle"]),
         "--deb", str(roles["deb"]),
         "--rpm", str(roles["rpm"]),
         "--lock", str(fix["root"] / "Cargo.lock"),
         "--ebpf-lock",
         str(fix["root"] / "crates" / "ebpf" / "Cargo.lock"),
         "--created", str(FIXED_EPOCH),
         "--out", str(sbom_out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, proc.stderr[-3000:]
    root = fix["root"]
    commit = _git(root, "rev-parse", "HEAD")
    _entries, inventory = protocol.git_inventory(root, commit)
    lock = (root / "Cargo.lock").read_bytes()
    ebpf_lock = (root / "crates" / "ebpf"
                 / "Cargo.lock").read_bytes()
    tools = dict(workshop().tools())
    receipt = json.loads(
        (fix["bundle_dir"] / "MANIFEST.json").read_text())[
            "build_receipt"]
    provenance_leaf = roles["provenance"].name
    subjects = {}
    for path in sorted(artifacts.iterdir()):
        if path.name == provenance_leaf:
            continue
        subjects[path.name] = hashlib.sha256(
            path.read_bytes()).hexdigest()
    provenance = {
        "schema": "memveil-local-build/2",
        "origin": "local-build",
        "source": {"commit": commit,
                   "tree": _git(root, "rev-parse",
                                "HEAD^{tree}"),
                   "inventory_sha256": inventory},
        "toolchain": {
            "cargo_lock_sha256": hashlib.sha256(
                lock).hexdigest(),
            "ebpf_lock_sha256": hashlib.sha256(
                ebpf_lock).hexdigest(),
            "tools": tools},
        "build_receipt": receipt,
        "subjects": subjects,
    }
    roles["provenance"].write_bytes(
        protocol.canonical(provenance))


def _make_executable_bundle(fix):
    """Rebuild the bundle tarball with an executable engine.

    The loader requires an executable bin/memveil; the
    workshop payload stages it mode-blind, so set 0755 and
    re-tar deterministically before the seal binds the bytes.
    """
    engine = fix["bundle_dir"] / "bin" / "memveil"
    engine.chmod(0o755)
    manifest_bytes = (
        fix["bundle_dir"] / "MANIFEST.json").read_bytes()
    roles = protocol.discover_artifacts(
        fix["artifacts"], manifest_bytes)
    with tarfile.open(roles["bundle"], "r:gz") as tar:
        arcname = tar.getnames()[0].split("/")[0]
    deterministic_tar_gz(fix["bundle_dir"], arcname,
                         roles["bundle"])


def seal_candidate(tmp_path, name, deb_name=None,
                   rpm_name=None):
    """Seal one synthetic candidate; return its paths and manifest.

    deb_name/rpm_name rename the sealed pair (extensions must
    stay .deb/.rpm); the SBOM and provenance are re-emitted to
    bind the new names before the seal.
    """
    shop = workshop()
    fix = shop.fresh(Path(tmp_path) / name)
    artifacts = fix["artifacts"]
    if deb_name is not None:
        assert deb_name.endswith(".deb"), deb_name
        originals = list(artifacts.glob("*.deb"))
        assert len(originals) == 1, originals
        originals[0].rename(artifacts / deb_name)
    if rpm_name is not None:
        assert rpm_name.endswith(".rpm"), rpm_name
        originals = list(artifacts.glob("*.rpm"))
        assert len(originals) == 1, originals
        originals[0].rename(artifacts / rpm_name)
    _make_executable_bundle(fix)
    _regenerate_seal_bindings(fix, shop.harness_bin())
    manifest = protocol.create_manifest(
        fix["bundle_dir"], artifacts, fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": shop.harness_bin()})
    # The loader resolves artifacts beside the manifest, so
    # the seal lives in the artifacts dir, not above it.
    out = artifacts / "candidate.json"
    protocol.seal_manifest(manifest, out)
    roles = {entry["role"]: artifacts / entry["name"]
             for entry in manifest["artifacts"]}
    assert roles["deb"].is_file() and roles["rpm"].is_file()
    assert roles["bundle"].is_file()
    return {"dir": Path(tmp_path) / name,
            "manifest_path": out, "manifest": manifest,
            "bundle": roles["bundle"], "deb": roles["deb"],
            "rpm": roles["rpm"],
            "bundle_dir": fix["bundle_dir"],
            "root": fix["root"]}


def candidate_env(sealed):
    """Loader env dict pointing at one sealed candidate."""
    return {"MV_BUNDLE_TARBALL": str(sealed["bundle"]),
            "MV_CANDIDATE_MANIFEST":
            str(sealed["manifest_path"])}


def dev_tarball():
    """Dev bundle tarball: named, else the newest built one.

    MV_BUNDLE_TARBALL wins when set (the candidate tarball in
    qualification runs); otherwise the newest tarball the
    packaging suites built. Fails closed with the remedy when
    neither exists.
    """
    named = os.environ.get("MV_BUNDLE_TARBALL", "")
    if named:
        assert os.path.isfile(named), \
            "MV_BUNDLE_TARBALL is not a file: %s" % named
        return Path(named)
    haystack = ROOT / "target" / "package-test" / "tarball"
    found = sorted(haystack.glob("memveil-*.tar.gz"),
                   key=lambda path: path.stat().st_mtime) \
        if haystack.is_dir() else []
    assert found, \
        "no dev bundle tarball: run cargo test --locked " \
        "--test package_tarball first"
    return found[-1]
