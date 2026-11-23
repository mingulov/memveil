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
skips would mask the mapping proof). Shaped seals also
require rustc, readelf, rpm, rpm2cpio, and cpio.
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

# Extra tools the shaped seal needs over the minimal one:
# rustc compiles the stub engine/lib, readelf derives the
# control floor, and rpm/rpm2cpio/cpio verify the rebuilt
# pair.
SHAPED_TOOLS = ("rustc", "readelf", "rpm", "rpm2cpio",
                "cpio")

# Engine version the stub sources implement; the shaped seal
# refuses a workshop bundle that drifts from it.
STUB_VERSION = "0.2.0"

# Full-shape bundle members the shaped seal adds over the
# workshop payload: exact names the real packagers and the
# fixed file pins require, synthetic bytes (every consumer
# hashes them post-build, so bytes never matter, names do).
SHAPED_EXTRA_FILES = {
    "examples/real-capture/README.md":
    b"synthetic example\n",
    "examples/real-capture/events.ndjson":
    b"synthetic example\n",
    "examples/real-capture/session.json":
    b"synthetic example\n",
    "examples/lifecycle-copy/README.md":
    b"synthetic example\n",
    "examples/lifecycle-copy/events.ndjson":
    b"synthetic example\n",
    "examples/lifecycle-copy/session.json":
    b"synthetic example\n",
    "examples/lifecycle-copy/oracle-phase.log":
    b"synthetic example\n",
    "examples/lifecycle-copy/fail-phase.log":
    b"synthetic example\n",
    "LICENSES/GPL-2.0-or-later.txt":
    b"synthetic license\n",
    "LICENSES/GPL-2.0.txt":
    b"synthetic license\n",
    "licenses/RUNTIME.LIBRARY.EXCEPTION":
    b"synthetic exception\n",
}

_workshop = None
_stub_binaries = None


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


def _sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def _stub_build_env():
    return {key: value for key, value in os.environ.items()
            if key != "RUSTUP_TOOLCHAIN"}


def _build_stub_binaries(dest):
    """Compile the stub engine + closure lib once per process.

    Direct rustc, no cargo project (the stubs need no
    dependencies and must not touch the workspace lock):
    the engine answers the packager-observed surface
    (`version`, top and per-verb `--help`), the cdylib is a
    well-formed ELF .so. Returns (engine_bytes, lib_bytes).
    """
    global _stub_binaries
    if _stub_binaries is not None:
        return _stub_binaries
    require_tool("rustc")
    env = _stub_build_env()
    out = Path(dest) / "stub-build"
    out.mkdir(parents=True, exist_ok=True)
    engine = out / "stub-engine"
    proc = subprocess.run(
        ["rustc", "--edition=2021", "-O",
         "tests/package/stub_engine.rs",
         "-o", str(engine)],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    lib = out / "libstub.so"
    proc = subprocess.run(
        ["rustc", "--edition=2021", "-O",
         "--crate-type=cdylib",
         "tests/package/stub_lib.rs",
         "-o", str(lib)],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    proc = subprocess.run(
        [str(engine), "version"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0 and proc.stdout.strip() == \
        "memveil-" + STUB_VERSION, proc.stderr[-1000:]
    proc = subprocess.run(
        [str(engine), "--help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0 and proc.stdout.strip(), \
        "stub engine --help failed"
    proc = subprocess.run(
        ["readelf", "-V", str(lib)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, \
        "stub lib is not well-formed ELF"
    _stub_binaries = (engine.read_bytes(), lib.read_bytes())
    return _stub_binaries


def _bundle_tarball(artifacts):
    """Locate the bundle tarball structurally (pre-rebind).

    Name- and bytes-blind: the .tar.gz carrying a top-level
    MANIFEST.json is the bundle (the source archive is a bare
    git export). Used when the manifest was just rewritten
    and digest matching cannot work yet.
    """
    found = []
    for tarball in sorted(artifacts.glob("*.tar.gz")):
        try:
            with tarfile.open(tarball, "r:gz") as tar:
                names = tar.getnames()
        except (tarfile.TarError, OSError):
            continue
        if not names:
            continue
        top = names[0].split("/")[0]
        if top + "/MANIFEST.json" in names:
            found.append((tarball, top))
    assert len(found) == 1, \
        "want exactly one bundle tarball in %s" % artifacts
    return found[0]


def _shape_bundle(fix, dest):
    """Upgrade a fresh fixture to real package shape.

    The workshop's minimal payload (synthetic engine text,
    hand-staged pair) cannot satisfy the re-homed control,
    file-list, or installed-man assertions. The shaped seal
    instead stages a full-shape bundle -- stub engine and
    closure lib plus the exact example/license names the
    fixed pins require -- and rebuilds the .deb/.rpm pair
    through the real packaging scripts, so control fields,
    generated pages, and the sealed file sets are all
    script-shaped with synthetic bytes. The BPF copies stay
    synthetic (only ever equality-compared) and the fixture
    source root stays untouched (the seal still binds it).
    """
    for name in SHAPED_TOOLS:
        require_tool(name)
    Path(dest).mkdir(parents=True, exist_ok=True)
    bundle = fix["bundle_dir"]
    manifest_path = bundle / "MANIFEST.json"
    manifest = json.loads(manifest_path.read_text())
    assert manifest["engine_version"] == STUB_VERSION, \
        "stub sources implement %s, bundle says %s" % (
            STUB_VERSION, manifest["engine_version"])
    engine_bytes, lib_bytes = _build_stub_binaries(dest)
    files = dict(manifest["files"])
    engine = bundle / "bin" / "memveil"
    engine.write_bytes(engine_bytes)
    # The packagers execute the staged engine (the `version`
    # rerun, man generation); the workshop stages mode-blind.
    engine.chmod(0o755)
    files["bin/memveil"] = _sha_bytes(engine_bytes)
    # The synthetic-text lib cannot survive the packagers'
    # readelf derivation; the stub .so takes its name slot.
    (bundle / "lib" / "memveil"
     / "libfixture.so.1").unlink()
    del files["lib/memveil/libfixture.so.1"]
    (bundle / "lib" / "memveil"
     / "libgcc_s.so.1").write_bytes(lib_bytes)
    files["lib/memveil/libgcc_s.so.1"] = _sha_bytes(lib_bytes)
    for rel, data in SHAPED_EXTRA_FILES.items():
        assert rel not in files, rel
        path = bundle / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        files[rel] = _sha_bytes(data)
    # The workshop's demo example has no FHS destination in
    # the real packagers (they stage only the two worked
    # examples), so it leaves the shaped closure.
    demo = bundle / "examples" / "demo" / "fixture.txt"
    demo.unlink()
    del files["examples/demo/fixture.txt"]
    manifest["files"] = files
    manifest["build_receipt"]["outputs"]["engine_sha256"] = \
        files["bin/memveil"]
    # The .deb transcribes the patchelf record into
    # X-Memveil-Build-Tools; the fixture runs no patchelf.
    manifest["packaging_tools"] = {
        "patchelf": {"version": "0.0.0"}}
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    epoch_env = dict(os.environ)
    epoch_env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
    deb_out = Path(dest) / "shaped-deb"
    deb_out.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "package-deb.py"),
         "--bundle", str(bundle), "--out", str(deb_out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=epoch_env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    debs = list(deb_out.glob("*.deb"))
    assert len(debs) == 1, debs
    for old in fix["artifacts"].glob("*.deb"):
        old.unlink()
    shutil.copy2(debs[0], fix["artifacts"] / debs[0].name)
    rpm_work = Path(dest) / "shaped-rpm-work"
    rpm_out = Path(dest) / "shaped-rpm"
    rpm_out.mkdir(exist_ok=True)
    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "package-rpm.py"),
         "--bundle", str(bundle), "--root", str(fix["root"]),
         "--work", str(rpm_work), "--out", str(rpm_out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env=epoch_env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    rpms = list(rpm_out.glob("*.rpm"))
    assert len(rpms) == 1, rpms
    for old in fix["artifacts"].glob("*.rpm"):
        old.unlink()
    shutil.copy2(rpms[0], fix["artifacts"] / rpms[0].name)
    # Re-tar so the bundle artifact matches the upgraded
    # manifest before the seal binds the bytes.
    tarball, arcname = _bundle_tarball(fix["artifacts"])
    deterministic_tar_gz(bundle, arcname, tarball)


def seal_candidate(tmp_path, name, deb_name=None,
                   rpm_name=None, shaped=False):
    """Seal one synthetic candidate; return its paths and manifest.

    deb_name/rpm_name rename the sealed pair (extensions must
    stay .deb/.rpm); the SBOM and provenance are re-emitted to
    bind the new names before the seal. shaped=True rebuilds
    the pair through the real packaging scripts from a
    full-shape bundle, for legs that assert re-homed
    control/file-list/installed-man behavior.
    """
    shop = workshop()
    fix = shop.fresh(Path(tmp_path) / name)
    artifacts = fix["artifacts"]
    if shaped:
        _shape_bundle(fix, Path(tmp_path) / (name + "-shape"))
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
