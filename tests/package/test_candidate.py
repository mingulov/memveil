# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal tests for memveil-candidate/2 manifests.

Synthetic custody fixtures never qualify a product artifact: every
bundle, archive, and receipt below is assembled in a temporary
directory, and only the verification logic under test is real.
"""

import base64
import copy
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests" / "vm"))
import kernel_matrix as km
import candidate_custody as cc
from test_kernel_matrix import (_admitted_entry, _ev_pass, _row_ctx,
                                _row_job)


def api():
    assert importlib.util.find_spec("candidate"), \
        "candidate protocol is missing"
    import candidate
    return candidate


def sha(data):
    return hashlib.sha256(data).hexdigest()


FIXED_EPOCH = 1763596800
FIXED_DATE = "%d +0000" % FIXED_EPOCH


def git(root, *args, **kw):
    env = dict(os.environ)
    env["GIT_AUTHOR_DATE"] = FIXED_DATE
    env["GIT_COMMITTER_DATE"] = FIXED_DATE
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True, env=env, **kw).stdout.strip()


def deterministic_tar_gz(tree, arcname, dest):
    """Bundle tarball with pinned members, order, and stamps.

    Members sort, carry the fixed epoch with zeroed
    ownership, and the gzip header stamps the same epoch,
    so two builds of one tree hash identically.
    """
    tree = Path(tree)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as stream:
        for base, dirs, files in os.walk(tree):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(base, name)
                rel = os.path.relpath(full, tree)
                arc = arcname + "/" + rel.replace(os.sep, "/")
                info = stream.gettarinfo(full, arc)
                info.mtime = FIXED_EPOCH
                info.uid = info.gid = 0
                info.uname = info.gname = ""
                with open(full, "rb") as handle:
                    stream.addfile(info, handle)
    Path(dest).write_bytes(
        gzip.compress(buf.getvalue(), mtime=FIXED_EPOCH))


def _clamp_tree(tree):
    """Pin every mtime under tree to the fixed epoch."""
    for base, dirs, files in os.walk(tree):
        for name in dirs + files:
            os.utime(os.path.join(base, name),
                     (FIXED_EPOCH, FIXED_EPOCH))


def cargo_build_harness():
    """Build the release-entry harness once; return its binary path."""
    env = {k: v for k, v in os.environ.items()
           if k != "RUSTUP_TOOLCHAIN"}
    proc = subprocess.run(
        ["cargo", "build", "-p", "memveil-release-entry",
         "--locked", "--offline"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    target = os.environ.get("CARGO_TARGET_DIR")
    binary = Path(target) / "debug" / "memveil-release-entry" \
        if target else ROOT / "target" / "debug" / "memveil-release-entry"
    assert binary.is_file(), "harness binary missing: %s" % binary
    return str(binary)


def probe_tools():
    """Ambient build-tool versions under the repository pin."""
    env = {k: v for k, v in os.environ.items()
           if k != "RUSTUP_TOOLCHAIN"}
    out = {}
    for name, argv in (("cargo", ["cargo", "--version"]),
                      ("rustc", ["rustc", "--version"]),
                      ("bpf_linker", ["bpf-linker", "--version"])):
        proc = subprocess.run(argv, cwd=str(ROOT),
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True, env=env)
        assert proc.returncode == 0, "%s --version failed" % name
        token = proc.stdout.split()[1]
        out[name] = token[1:] if token.startswith("v") else token
    return out


class Workshop:
    """Lazily built seal fixtures over one synthetic source commit.

    Everything builds on first use (after the test imports the
    candidate module), so a missing implementation fails the suite
    at the import instead of inside fixture setup.
    """

    def __init__(self, base):
        self.base = Path(base)
        self._harness = None
        self._tools = None
        self._built = False

    def harness_bin(self):
        if self._harness is None:
            self._harness = cargo_build_harness()
        return self._harness

    def tools(self):
        if self._tools is None:
            self._tools = probe_tools()
        return self._tools

    def fresh(self, tmp_path):
        """Copy the pristine fixture set into tmp_path; return paths."""
        if not self._built:
            self._build()
        dest = Path(tmp_path) / "seal"
        shutil.copytree(self.base, dest, symlinks=True)
        return {
            "root": dest / "root",
            "bundle_dir": dest / "bundle",
            "artifacts": dest / "artifacts",
            "policy": dest / "root" / "packaging"
            / "candidate-policy.json",
        }

    def _build(self):
        m = api()
        tools = self.tools()
        root = self.base / "root"
        (root / "crates" / "ebpf").mkdir(parents=True)
        (root / "packaging").mkdir(parents=True)
        (root / "src").mkdir(parents=True)
        lock = ('version = 3\n\n[[package]]\nname = "fixture-crate"\n'
                'version = "0.1.0"\nsource = "registry+https://x.invalid/index"\n'
                'checksum = "%s"\n' % ("ab" * 32))
        (root / "Cargo.lock").write_text(lock)
        ebpf_lock = lock.replace("fixture-crate", "fixture-ebpf-crate")
        (root / "crates" / "ebpf" / "Cargo.lock").write_text(ebpf_lock)
        (root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "%s"\n' % tools["cargo"])
        (root / "packaging" / "candidate-policy.json").write_text(
            '{"schema":"fixture-policy/1"}\n')
        (root / "src" / "engine.txt").write_text("synthetic engine\n")
        os.symlink("engine.txt", root / "src" / "engine-link.txt")
        (root / "tests" / "vm").mkdir(parents=True)
        (root / "tests" / "vm" / "kernels.lock.json").write_bytes(
            m.canonical(_matrix_lock(_admitted_entry())))
        git(root, "init", "-q")
        git(root, "add", ".")
        git(root, "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "Fixture C")
        commit = git(root, "rev-parse", "HEAD")
        entries, inventory = m.git_inventory(root, commit)
        assert entries, "empty fixture inventory"

        bundle = self.base / "bundle"
        payload = {
            "bin/memveil": b"synthetic-engine\n",
            "lib/memveil/libfixture.so.1": b"synthetic-lib\n",
            "bpf/swiotlb_attempt.bpf.o": b"synthetic-bpf-attempt\n",
            "bpf/swiotlb_lifecycle.bpf.o": b"synthetic-bpf-lifecycle\n",
            "bpf/swiotlb_copy.bpf.o": b"synthetic-bpf-copy\n",
            "profiles/manifest.txt": b"p.json\n",
            "profiles/p.json": b"{}\n",
            "docs/quickstart.md": b"# fixture\n",
            "examples/demo/fixture.txt": b"fixture\n",
            "LICENSE": b"fixture license\n",
            "THIRD-PARTY-NOTICES.md": b"fixture notices\n",
            "LICENSES/GPL-2.0-only.txt": b"fixture gpl\n",
            "licenses/GPL-3.0.txt": b"fixture gpl3\n",
            "licenses/crates/demo/LICENSE": b"fixture crate\n",
        }
        for rel, data in payload.items():
            path = bundle / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        files = {rel: sha(data) for rel, data in payload.items()}
        # The build-time receipt the packager records in MANIFEST.json
        # in candidate mode: source C + tree inventory, probed tool
        # versions, the engine/BPF output digests, and the in-flow
        # build flag. The honest provenance below repeats it
        # verbatim; the seal requires the two to match.
        receipt = {
            "source_commit": commit,
            "inventory_sha256": inventory,
            "tools": dict(tools),
            "outputs": {
                "engine_sha256": files["bin/memveil"],
                "bpf": {name: files["bpf/" + name] for name in
                        ("swiotlb_attempt.bpf.o",
                         "swiotlb_lifecycle.bpf.o",
                         "swiotlb_copy.bpf.o")},
            },
            "clean_tree": True,
            "built_from_source": True,
        }
        manifest = {
            "bundle": "memveil-fixture",
            "build_receipt": receipt,
            "engine_version": "0.1.0",
            "memveil_revision": commit,
            "toolchain": {
                "cargo": {"version": tools["cargo"]},
                "rustc": {"version": tools["rustc"]},
            },
            "cargo": {
                "lock_sha256": sha(lock.encode()),
                "ebpf_lock_sha256": sha(ebpf_lock.encode()),
                "crates": [{"name": "fixture-crate", "version": "0.1.0",
                            "license": "MIT",
                            "source": "registry+https://x.invalid/index"}],
                "ebpf_crates": [{"name": "fixture-ebpf-crate",
                                 "version": "0.1.0", "license": "MIT",
                                 "source":
                                 "registry+https://x.invalid/index"}],
            },
            "embedded_bpf": {
                name: files["bpf/" + name] for name in
                ("swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
                 "swiotlb_copy.bpf.o")},
            "files": files,
        }
        (bundle / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n")

        artifacts = self.base / "artifacts"
        artifacts.mkdir(parents=True)
        deterministic_tar_gz(
            bundle, "memveil-fixture",
            artifacts / "memveil-fixture.tar.gz")
        epoch_env = dict(os.environ)
        epoch_env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
        staged = self.base / "staged"
        for rel in files:
            target = staged / m.installed_file_path(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundle / rel, target)
        deb_stage = self.base / "deb-stage"
        shutil.copytree(staged, deb_stage / "payload")
        (deb_stage / "payload" / "DEBIAN").mkdir(parents=True)
        (deb_stage / "payload" / "DEBIAN" / "control").write_text(
            "Package: memveil-fixture\nVersion: 0.1.0\n"
            "Architecture: amd64\nMaintainer: Fixture\n"
            "Description: synthetic seal fixture\n")
        _clamp_tree(deb_stage / "payload")
        proc = subprocess.run(
            ["dpkg-deb", "-b", str(deb_stage / "payload"),
             str(artifacts / "memveil-fixture_0.1.0_amd64.deb")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=epoch_env)
        assert proc.returncode == 0, proc.stderr
        rpm_top = self.base / "rpm-top"
        for leaf in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (rpm_top / leaf).mkdir(parents=True)
        spec = self.base / "fixture.spec"
        spec.write_text(
            "Name: memveil-fixture\nVersion: 0.1.0\nRelease: 1\n"
            "Summary: synthetic seal fixture\n"
            "License: GPL-3.0-or-later\n\n"
            "%description\nsynthetic seal fixture\n\n"
            "%install\ncp -r %{payload}/* %{buildroot}/\n\n"
            "%files\n" + "".join(
                '/%s\n' % m.installed_file_path(rel)
                for rel in sorted(files)) + "\n"
            "%changelog\n* Thu Nov 19 2026 Fixture - 0.1.0-1\n- fixture\n")
        proc = subprocess.run(
            ["rpmbuild", "-bb", "--define", "_topdir %s" % rpm_top,
             "--define", "payload %s" % staged,
             "--define",
             "use_source_date_epoch_as_buildtime 1",
             str(spec)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=epoch_env)
        assert proc.returncode == 0, proc.stderr[-3000:]
        rpms = list((rpm_top / "RPMS").rglob("*.rpm"))
        assert len(rpms) == 1, rpms
        shutil.copy2(rpms[0], artifacts / rpms[0].name)
        proc = subprocess.run(
            ["git", "-C", str(root), "archive", "HEAD"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        (artifacts / "memveil-fixture-source.tar.gz").write_bytes(
            gzip.compress(proc.stdout, mtime=0))
        sbom_out = artifacts / "memveil-fixture.spdx.json"
        proc = subprocess.run(
            [self.harness_bin(), "sbom-emit",
             "--manifest", str(bundle / "MANIFEST.json"),
             "--bundle",
             str(artifacts / "memveil-fixture.tar.gz"),
             "--deb", str(next(artifacts.glob("*.deb"))),
             "--rpm", str(next(artifacts.glob("*.rpm"))),
             "--lock", str(root / "Cargo.lock"),
             "--ebpf-lock",
             str(root / "crates" / "ebpf" / "Cargo.lock"),
             "--created", str(FIXED_EPOCH),
             "--out", str(sbom_out)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 0, proc.stderr
        subjects = {}
        for path in sorted(artifacts.iterdir()):
            subjects[path.name] = sha(path.read_bytes())
        provenance = {
            "schema": "memveil-local-build/2",
            "origin": "local-build",
            "source": {"commit": commit,
                       "tree": git(root, "rev-parse",
                                   "HEAD^{tree}"),
                       "inventory_sha256": inventory},
            "toolchain": {"cargo_lock_sha256": sha(lock.encode()),
                          "ebpf_lock_sha256": sha(ebpf_lock.encode()),
                          "tools": dict(tools)},
            "build_receipt": receipt,
            "subjects": subjects,
        }
        (artifacts / "memveil-fixture.provenance.json").write_text(
            m.canonical(provenance).decode())
        self._built = True


@pytest.fixture(scope="session")
def workshop(tmp_path_factory):
    return Workshop(tmp_path_factory.mktemp("seal-base"))


def seal_paths(workshop, tmp_path):
    m = api()
    fix = workshop.fresh(tmp_path)
    return m, fix


def test_seal_binds_source_toolchain_artifacts(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    out = Path(tmp_path) / "candidate.json"
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})
    assert manifest["schema"] == "memveil-candidate/2"
    assert manifest["origin"] == "local-build"
    root = fix["root"]
    assert manifest["source"] == {
        "commit": git(root, "rev-parse", "HEAD"),
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "inventory_sha256": m.git_inventory(
            root, git(root, "rev-parse", "HEAD"))[1]}
    assert manifest["toolchain"] == {
        "cargo_lock_sha256": sha((root / "Cargo.lock").read_bytes()),
        "ebpf_lock_sha256": sha(
            (root / "crates" / "ebpf" / "Cargo.lock").read_bytes()),
        "tools": workshop.tools()}
    roles = {}
    for entry in manifest["artifacts"]:
        assert set(entry) == {"role", "name", "size", "sha256"}
        assert entry["role"] not in roles
        roles[entry["role"]] = entry
        path = fix["artifacts"] / entry["name"]
        assert path.is_file() and not path.is_symlink()
        assert entry["size"] == str(path.stat().st_size)
        assert entry["sha256"] == sha(path.read_bytes())
    assert set(roles) == {"bundle", "deb", "rpm", "source",
                          "sbom", "provenance"}
    assert manifest["policy_sha256"] == sha(
        fix["policy"].read_bytes())
    assert manifest["bundle_manifest_sha256"] == sha(
        (fix["bundle_dir"] / "MANIFEST.json").read_bytes())
    assert manifest["files"] == json.loads(
        (fix["bundle_dir"] / "MANIFEST.json").read_text())["files"]
    candidate_id = m.seal_manifest(manifest, out)
    assert candidate_id == m.digest_canonical(manifest)
    assert candidate_id == sha(out.read_bytes())
    assert out.read_bytes() == m.canonical(manifest)
    assert m.load_manifest(out, candidate_id) == manifest
    with pytest.raises(FileExistsError):
        m.seal_manifest(manifest, out)


def test_seal_cli_reports_candidate_id(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    out = Path(tmp_path) / "candidate.json"
    proc = subprocess.run(
        [str(ROOT / "tools" / "candidate"), "seal",
         "--bundle-dir", str(fix["bundle_dir"]),
         "--artifacts-dir", str(fix["artifacts"]),
         "--policy", str(fix["policy"]),
         "--source-root", str(fix["root"]),
         "--harness-bin", workshop.harness_bin(),
         "--out", str(out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha(out.read_bytes())
    assert m.load_manifest(out)["schema"] == "memveil-candidate/2"
    rerun = subprocess.run(
        [str(ROOT / "tools" / "candidate"), "seal",
         "--bundle-dir", str(fix["bundle_dir"]),
         "--artifacts-dir", str(fix["artifacts"]),
         "--policy", str(fix["policy"]),
         "--source-root", str(fix["root"]),
         "--harness-bin", workshop.harness_bin(),
         "--out", str(out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert rerun.returncode == 1
    assert rerun.stderr.strip(), "silent seal failure"


def test_seal_rejects_stale_engine(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    presented = fix["bundle_dir"] / "bpf" / "swiotlb_attempt.bpf.o"
    presented.write_bytes(b"synthetic-bpf-attempt-rebuilt\n")
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    doc["files"]["bpf/swiotlb_attempt.bpf.o"] = sha(
        presented.read_bytes())
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Ee]mbedded|[Bb][Pp][Ff]"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_duplicate_keys(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    path = Path(tmp_path) / "candidate.json"
    path.write_text('{"schema":"memveil-candidate/2",'
                    '"schema":"memveil-candidate/2"}\n')
    with pytest.raises(ValueError, match="duplicate"):
        m.load_manifest(path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    text = manifest_path.read_text().replace(
        '"bundle": "memveil-fixture"',
        '"bundle": "memveil-fixture", "bundle": "memveil-fixture"',
        1)
    manifest_path.write_text(text)
    with pytest.raises(ValueError, match="duplicate"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_v1_manifest(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})
    manifest["schema"] = "memveil-candidate/1"
    with pytest.raises(ValueError, match="[Ss]chema"):
        m.validate_manifest(manifest)
    path = Path(tmp_path) / "v1.json"
    path.write_bytes(m.canonical(manifest))
    with pytest.raises(ValueError, match="[Ss]chema"):
        m.load_manifest(path)


def rewrite_provenance(m, fix, mutate):
    path = next(fix["artifacts"].glob("*.provenance.json"))
    doc = json.loads(path.read_text())
    mutate(doc)
    path.write_bytes(m.canonical(doc))


def rebuild_bundle_tarball(fix):
    """Re-tar the bundle directory over the bundle tarball artifact."""
    tars = sorted(fix["artifacts"].glob("*.tar.gz"))
    target = next(path for path in tars
                  if not path.name.endswith("source.tar.gz"))
    target.unlink()
    with tarfile.open(target, "w:gz") as stream:
        stream.add(fix["bundle_dir"], arcname="memveil-fixture")


def test_seal_rejects_receipt_output_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    rewrite_provenance(
        m, fix,
        lambda doc: doc["build_receipt"]["outputs"].update(
            {"engine_sha256": "9" * 64}))
    with pytest.raises(ValueError, match="[Rr]eceipt|[Ee]ngine"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_receipt_source_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    rewrite_provenance(
        m, fix,
        lambda doc: doc["build_receipt"].update(
            {"source_commit": "9" * 40}))
    with pytest.raises(ValueError, match="[Rr]eceipt|[Ss]ource"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_receipt_stripped_bundle(workshop,
                                              tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    del doc["build_receipt"]
    manifest_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Bb]uild receipt"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_requires_clean_tree_receipt(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    assert doc["build_receipt"]["clean_tree"] is True
    doc["build_receipt"]["clean_tree"] = False
    manifest_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Dd]irty worktree"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})
    del doc["build_receipt"]["clean_tree"]
    manifest_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Bb]uild receipt"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_prebuilt_receipt(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    # Codex's miss, replayed: stale prebuilt bytes repackaged at
    # C carry a fresh, self-consistent receipt naming C and the
    # staged bytes — but the packager recorded it outside
    # candidate mode, so the seal must still refuse.
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    assert doc["build_receipt"]["built_from_source"] is True
    doc["build_receipt"]["built_from_source"] = False
    manifest_path.write_text(
        json.dumps(doc, indent=2, sort_keys=True))
    rebuild_bundle_tarball(fix)
    rewrite_provenance(
        m, fix,
        lambda doc: doc["build_receipt"].update(
            {"built_from_source": False}))
    _rebind_provenance_subjects(m, fix)
    with pytest.raises(ValueError, match="[Cc]andidate mode"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})
    with pytest.raises(ValueError, match="[Cc]andidate mode"):
        m.emit_provenance(
            fix["bundle_dir"], _emit_source_info(fix),
            tmp_path / "prebuilt.provenance.json")


def test_candidate_mode_requires_in_flow_build():
    packager = _packager_module()
    # Only --candidate with --build from the root and no
    # prebuilt overrides records a sealable receipt.
    assert packager.candidate_built_from_source(
        True, True, None, None) is True
    # Development runs (plain --build or --binary) record a
    # receipt the seal refuses.
    assert packager.candidate_built_from_source(
        False, True, None, None) is False
    assert packager.candidate_built_from_source(
        False, False, "/prebuilt/memveil", None) is False
    assert packager.candidate_built_from_source(
        False, False, None, "/prebuilt/bpf") is False
    # Candidate mode without the in-flow build, or mixed with
    # prebuilt inputs, fails instead of recording.
    with pytest.raises(SystemExit):
        packager.candidate_built_from_source(
            True, False, None, None)
    with pytest.raises(SystemExit):
        packager.candidate_built_from_source(
            True, True, "/prebuilt/memveil", None)
    with pytest.raises(SystemExit):
        packager.candidate_built_from_source(
            True, True, None, "/prebuilt/bpf")


def test_candidate_packager_cli_validates_before_build():
    packager = str(ROOT / "scripts" / "package-tarball.py")
    proc = subprocess.run(
        [sys.executable, packager, "--candidate", "--tag", "t"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 1
    assert "requires --build" in proc.stderr
    proc = subprocess.run(
        [sys.executable, packager, "--candidate", "--build",
         "--binary", "/prebuilt/memveil", "--tag", "t"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 1
    assert "forbids" in proc.stderr


def test_select_built_binary_parses_cargo_json(tmp_path):
    packager = _packager_module()
    target = Path(tmp_path) / "target"
    release = target / "release"
    release.mkdir(parents=True)
    binary = release / "memveil"
    binary.write_bytes(b"fresh\n")
    line = json.dumps({"reason": "compiler-artifact",
                       "target": {"name": "memveil",
                                  "kind": ["bin"]},
                       "executable": str(binary),
                       "filenames": [str(binary)]})
    noise = "\n".join([
        json.dumps({"reason": "compiler-artifact",
                    "target": {"name": "memveil",
                               "kind": ["lib"]},
                    "filenames": [str(release / "libmemveil.rlib")]}),
        json.dumps({"reason": "build-finished", "success": True}),
        "not json at all"])
    assert packager.select_built_binary(
        noise + "\n" + line + "\n", "memveil",
        str(target)) == str(binary)
    # The same path repeated is one binary; two distinct
    # paths are ambiguous and fail closed.
    assert packager.select_built_binary(
        line + "\n" + line, "memveil",
        str(target)) == str(binary)
    with pytest.raises(SystemExit):
        packager.select_built_binary(noise, "memveil",
                                     str(target))
    other = release / "memveil-alt"
    other.write_bytes(b"fresh\n")
    alt = json.dumps({"reason": "compiler-artifact",
                      "target": {"name": "memveil",
                                 "kind": ["bin"]},
                      "executable": str(other),
                      "filenames": [str(other)]})
    with pytest.raises(SystemExit):
        packager.select_built_binary(line + "\n" + alt,
                                     "memveil", str(target))
    outside = Path(tmp_path) / "shadow" / "memveil"
    outside.parent.mkdir(parents=True)
    outside.write_bytes(b"stale\n")
    escaped = json.dumps(
        {"reason": "compiler-artifact",
         "target": {"name": "memveil", "kind": ["bin"]},
         "executable": str(outside),
         "filenames": [str(outside)]})
    with pytest.raises(SystemExit):
        packager.select_built_binary(escaped, "memveil",
                                     str(target))


def _redirect_probe_crate(path):
    """Tiny crate with a build script emitting an OUT_DIR marker."""
    path = Path(path)
    (path / "src").mkdir(parents=True)
    (path / ".cargo").mkdir(parents=True)
    (path / "Cargo.toml").write_text(
        "[package]\nname = \"redirprobe\"\nversion = \"0.1.0\"\n"
        "edition = \"2021\"\n")
    (path / "src" / "main.rs").write_text(
        "fn main() { println!(\"fresh\"); }\n")
    (path / "build.rs").write_text(
        "use std::env;\nuse std::fs;\n"
        "fn main() {\n"
        "    let out = env::var(\"OUT_DIR\").unwrap();\n"
        "    fs::write(out + \"/probe-marker.txt\",\n"
        "              \"fresh-marker\\n\").unwrap();\n"
        "}\n")
    env = dict(os.environ)
    env.pop("RUSTUP_TOOLCHAIN", None)
    proc = subprocess.run(
        ["cargo", "generate-lockfile", "--offline"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, cwd=str(path), env=env)
    assert proc.returncode == 0, proc.stderr
    return path


def test_in_flow_build_ignores_redirects(tmp_path, monkeypatch):
    packager = _packager_module()
    proj = _redirect_probe_crate(tmp_path / "proj")
    shadow = Path(tmp_path) / "shadow"
    cfg_shadow = Path(tmp_path) / "cfgshadow"
    cfg_build = Path(tmp_path) / "cfgbuild"
    env_build = Path(tmp_path) / "envbuild"
    for path in (shadow, cfg_shadow, cfg_build, env_build):
        path.mkdir(parents=True)
    # Stale bytes planted where the redirects point: a
    # full shadow release tree plus config-redirected
    # target and intermediates dirs.
    (shadow / "release").mkdir(parents=True)
    stale = shadow / "release" / "redirprobe"
    stale.write_bytes(b"stale-binary\n")
    (shadow / "release" / "build").mkdir(parents=True)
    (cfg_shadow / "sentinel.txt").write_text("stale\n")
    (proj / ".cargo" / "config.toml").write_text(
        "[build]\n"
        "target-dir = %s\n" % json.dumps(str(cfg_shadow))
        + "build-dir = %s\n" % json.dumps(str(cfg_build)))
    monkeypatch.setenv("CARGO_TARGET_DIR", str(shadow))
    monkeypatch.setenv("CARGO_BUILD_BUILD_DIR", str(env_build))
    monkeypatch.setenv("CARGO_BUILD_TARGET_DIR", str(shadow))
    target = proj / "target"
    binary = packager.build_release_binary(
        str(proj), str(target), bin_name="redirprobe")
    # The fresh in-flow bytes are packaged: cargo's own
    # reported path under the pinned dir, and its bytes
    # differ from the planted stale shadow.
    assert binary == str(target / "release" / "redirprobe")
    assert Path(binary).read_bytes() != b"stale-binary\n"
    assert stale.read_bytes() == b"stale-binary\n"
    # Every redirect stayed empty of fresh outputs: the
    # config-redirected dirs hold only the planted stale
    # bytes, and the env-redirected intermediates dir is
    # untouched, while the pinned tree carries the fresh
    # build-script marker.
    assert (cfg_shadow / "sentinel.txt").read_text() == "stale\n"
    assert sorted(path.name for path in cfg_shadow.iterdir()) == \
        ["sentinel.txt"]
    assert list(cfg_build.iterdir()) == []
    assert list(env_build.iterdir()) == []
    assert sorted(path.name
                  for path in (shadow / "release").iterdir()) == \
        ["build", "redirprobe"]
    markers = sorted(target.rglob("probe-marker.txt"))
    assert markers, "no fresh build-script marker under the pin"
    assert all(marker.read_text() == "fresh-marker\n"
               for marker in markers)


def test_in_flow_build_uses_fresh_ephemeral_target_dir(tmp_path):
    packager = _packager_module()
    proj = _redirect_probe_crate(tmp_path / "proj")
    # Decoy reusable dir with stale bytes plus stale cache
    # markers, as a pre-existing root/target would hold
    # after a linker swap cargo cannot see.
    decoy = proj / "target"
    (decoy / "release").mkdir(parents=True)
    stale = decoy / "release" / "redirprobe"
    stale.write_bytes(b"stale-binary\n")
    cached = decoy / "release" / "build" / "redirprobe-stale" \
        / "out"
    cached.mkdir(parents=True)
    (cached / "probe-marker.txt").write_text("stale-marker\n")
    before = sorted(path.relative_to(decoy).as_posix()
                    for path in decoy.rglob("*"))
    fresh = packager.fresh_target_dir()
    try:
        assert Path(fresh).is_dir()
        assert Path(fresh) != decoy
        binary = packager.resolve_binary(
            str(proj), None, True, fresh,
            bin_name="redirprobe")
        # Cargo's own reported path under the fresh dir, and
        # the fresh build-script marker: only this
        # invocation's bytes are consumed.
        assert binary == str(
            Path(fresh) / "release" / "redirprobe")
        assert Path(binary).read_bytes() != b"stale-binary\n"
        markers = sorted(Path(fresh).rglob("probe-marker.txt"))
        assert markers, "no fresh marker under the fresh dir"
        assert all(marker.read_text() == "fresh-marker\n"
                   for marker in markers)
        # The decoy reusable dir is byte-identical: no
        # fresh outputs landed there and the stale bytes
        # were never packaged.
        assert stale.read_bytes() == b"stale-binary\n"
        assert sorted(path.relative_to(decoy).as_posix()
                      for path in decoy.rglob("*")) == before
    finally:
        packager.drop_target_dir(fresh)
    assert not Path(fresh).exists()
    # Dropping twice, or dropping nothing, never fails.
    packager.drop_target_dir(fresh)
    packager.drop_target_dir(None)


def test_seal_rejects_smuggled_deb_payload(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    path = next(fix["artifacts"].glob("*.deb"))
    stage = Path(tmp_path) / "deb-rescue"
    for args in (["dpkg-deb", "-x", str(path), str(stage)],
                 ["dpkg-deb", "-e", str(path),
                  str(stage / "DEBIAN")]):
        proc = subprocess.run(
            args, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 0, proc.stderr
    smuggled = stage / "usr" / "lib" / "memveil" \
        / "libevil.so.1"
    smuggled.write_bytes(b"smuggled runtime\n")
    repacked = Path(tmp_path) / path.name
    proc = subprocess.run(
        ["dpkg-deb", "-b", str(stage), str(repacked)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, proc.stderr
    path.unlink()
    shutil.move(str(repacked), str(path))
    with pytest.raises(ValueError, match="unmapped"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_tampered_source_archive(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    path = next(fix["artifacts"].glob("*source.tar.gz"))
    raw = bytearray(gzip.decompress(path.read_bytes()))
    raw[2000:2008] = b"tampered"
    path.write_bytes(gzip.compress(bytes(raw), mtime=0))
    with pytest.raises(ValueError):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def _retar_source_archive(path, tree):
    """Re-tar an extracted source tree over the source artifact."""
    path.unlink()
    with tarfile.open(path, "w:gz") as stream:
        for base, dirs, files in os.walk(tree):
            dirs.sort()
            for name in sorted(files):
                full = os.path.join(base, name)
                stream.add(
                    full, arcname=os.path.relpath(full, tree))


def _rebind_provenance_subjects(m, fix):
    """Point fixture provenance subjects at the staged bytes."""
    path = next(fix["artifacts"].glob("*.provenance.json"))
    doc = json.loads(path.read_text())
    doc["subjects"] = {
        entry.name: sha(entry.read_bytes())
        for entry in sorted(fix["artifacts"].iterdir())
        if entry.name != path.name}
    path.write_bytes(m.canonical(doc))


def test_seal_rejects_source_mode_flip(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    path = next(fix["artifacts"].glob("*source.tar.gz"))
    tree = Path(tmp_path) / "resrc"
    m.safe_extract(path, tree, False, True)
    seal = {"root": str(fix["root"]),
            "harness_bin": workshop.harness_bin()}
    # Control: a faithful re-tar still seals.
    _retar_source_archive(path, tree)
    _rebind_provenance_subjects(m, fix)
    m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        seal)
    # A 644 -> 755 flip on one archived file refuses.
    target = tree / "src" / "engine.txt"
    assert not target.stat().st_mode & 0o100
    target.chmod(0o755)
    _retar_source_archive(path, tree)
    _rebind_provenance_subjects(m, fix)
    with pytest.raises(ValueError, match="[Mm]odes"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            seal)


def test_seal_rejects_lock_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    doc["cargo"]["lock_sha256"] = "8" * 64
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    rebuild_bundle_tarball(fix)
    with pytest.raises(ValueError, match="[Ll]ock"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_toolchain_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    doc["toolchain"]["cargo"]["version"] = "0.0.0"
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Tt]oolchain|[Cc]argo"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_sbom_closure_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    path = next(fix["artifacts"].glob("*.spdx.json"))
    doc = json.loads(path.read_text())
    target = next(item for item in doc["files"]
                  if item["fileName"] == "payload/bundle/bin/memveil")
    target["checksums"][0]["checksumValue"] = "7" * 64
    path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="[Ss][Bb][Oo][Mm]|[Pp]ayload"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def _sbom_emit_argv(workshop, fix, out, created=True):
    argv = [workshop.harness_bin(), "sbom-emit",
           "--manifest",
           str(fix["bundle_dir"] / "MANIFEST.json"),
           "--bundle",
           str(next(fix["artifacts"].glob(
               "memveil-fixture.tar.gz"))),
           "--deb", str(next(fix["artifacts"].glob("*.deb"))),
           "--rpm", str(next(fix["artifacts"].glob("*.rpm"))),
           "--lock", str(fix["root"] / "Cargo.lock"),
           "--ebpf-lock",
           str(fix["root"] / "crates" / "ebpf"
               / "Cargo.lock")]
    if created:
        argv += ["--created", str(FIXED_EPOCH)]
    return argv + ["--out", str(out)]


def _want_created():
    from datetime import datetime, timezone
    return datetime.fromtimestamp(
        FIXED_EPOCH, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ")


def test_sbom_emit_is_deterministic(workshop, tmp_path):
    _m, fix = seal_paths(workshop, tmp_path)
    first = Path(tmp_path) / "first.spdx.json"
    second = Path(tmp_path) / "second.spdx.json"
    for out in (first, second):
        proc = subprocess.run(
            _sbom_emit_argv(workshop, fix, out),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True)
        assert proc.returncode == 0, proc.stderr
    assert first.read_bytes() == second.read_bytes()
    doc = json.loads(first.read_bytes())
    assert doc["creationInfo"]["created"] == _want_created()


def test_sbom_emit_refuses_missing_stamp(workshop, tmp_path,
                                         monkeypatch):
    _m, fix = seal_paths(workshop, tmp_path)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    proc = subprocess.run(
        _sbom_emit_argv(workshop, fix,
                        Path(tmp_path) / "nostamp.spdx.json",
                        created=False),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 1
    assert "creation time" in proc.stderr


def test_sbom_emit_honors_source_date_epoch(workshop,
                                            tmp_path,
                                            monkeypatch):
    _m, fix = seal_paths(workshop, tmp_path)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", str(FIXED_EPOCH))
    out = Path(tmp_path) / "env.spdx.json"
    proc = subprocess.run(
        _sbom_emit_argv(workshop, fix, out, created=False),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(out.read_bytes())
    assert doc["creationInfo"]["created"] == _want_created()


def test_seal_is_deterministic(tmp_path):
    m = api()
    harness = cargo_build_harness()
    ids = []
    sets = []
    for leaf in ("det-a", "det-b"):
        shop = Workshop(tmp_path / leaf)
        fix = shop.fresh(tmp_path / (leaf + "-use"))
        manifest = m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": harness})
        out = tmp_path / (leaf + ".json")
        ids.append(m.seal_manifest(manifest, out))
        sets.append({path.name: path.read_bytes()
                     for path in sorted(
                         fix["artifacts"].iterdir())})
    assert sets[0].keys() == sets[1].keys()
    for name in sets[0]:
        assert sets[0][name] == sets[1][name], name
    assert ids[0] == ids[1]


def test_seal_rejects_provenance_subject_mismatch(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    rewrite_provenance(
        m, fix,
        lambda doc: doc["subjects"].update(
            {next(iter(doc["subjects"])): "6" * 64}))
    with pytest.raises(ValueError, match="[Ss]ubject|[Pp]rovenance"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_rejects_incomplete_package(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    missing = fix["bundle_dir"] / "bpf" / "swiotlb_copy.bpf.o"
    missing.unlink()
    with pytest.raises(ValueError):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def test_seal_requires_clean_source(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    (fix["root"] / "src" / "uncommitted.txt").write_text("dirty\n")
    with pytest.raises(ValueError, match="[Cc]lean"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def sealed_manifest(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    return m, m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})


@pytest.mark.parametrize("damage", [
    "placeholder", "missing", "extra", "size", "path", "origin",
    "toolchain", "role", "runtime",
])
def test_manifest_rejects_damaged_bindings(workshop, tmp_path, damage):
    m, manifest = sealed_manifest(workshop, tmp_path)
    if damage == "placeholder":
        manifest["source"]["commit"] = "0" * 40
    if damage == "missing":
        del manifest["files"]["bin/memveil"]
    if damage == "extra":
        manifest["artifacts"][0]["unknown"] = True
    if damage == "size":
        manifest["artifacts"][0]["size"] = 1
    if damage == "path":
        manifest["artifacts"][0]["name"] = "../escape"
    if damage == "origin":
        manifest["origin"] = "github-build"
    if damage == "toolchain":
        del manifest["toolchain"]["tools"]["bpf_linker"]
    if damage == "role":
        manifest["artifacts"][0]["role"] = "sbom"
    if damage == "runtime":
        manifest["files"] = {"LICENSE": "3" * 64}
    with pytest.raises(ValueError):
        m.validate_manifest(manifest)


def test_runtime_closure_requires_shared_object(workshop,
                                                tmp_path):
    m, manifest = sealed_manifest(workshop, tmp_path)
    lib = "lib/memveil/libfixture.so.1"
    # A lib/memveil/ entry with no .so member must not satisfy
    # the runtime closure requirement, in the manifest or the
    # bundle directory it seals.
    doctored = json.loads(json.dumps(manifest))
    doctored["files"]["lib/memveil/README"] = \
        doctored["files"].pop(lib)
    with pytest.raises(ValueError, match="runtime component"):
        m.validate_manifest(doctored)
    m, fix = seal_paths(workshop, tmp_path / "bundle")
    bundle_manifest = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(bundle_manifest.read_text())
    doc["files"]["lib/memveil/README"] = doc["files"].pop(lib)
    (fix["bundle_dir"] / lib).unlink()
    (fix["bundle_dir"] / "lib/memveil/README").write_bytes(
        b"synthetic-lib\n")
    bundle_manifest.write_text(
        json.dumps(doc, indent=2, sort_keys=True))
    with pytest.raises(ValueError, match="runtime closure"):
        m.verify_bundle_dir(fix["bundle_dir"])


def test_expected_payload_covers_full_closure(workshop, tmp_path):
    m, manifest = sealed_manifest(workshop, tmp_path)
    expected = m.expected_payload(manifest)
    assert len(expected) == 3 * len(manifest["files"])
    assert expected["bundle/bin/memveil"] == \
        manifest["files"]["bin/memveil"]
    assert expected["deb/usr/bin/memveil"] == \
        manifest["files"]["bin/memveil"]
    assert expected["rpm/usr/lib/memveil/swiotlb_copy.bpf.o"] == \
        manifest["files"]["bpf/swiotlb_copy.bpf.o"]
    assert expected["deb/usr/share/doc/memveil/LICENSE"] == \
        manifest["files"]["LICENSE"]


def test_installed_paths_match_packagers():
    m = api()
    assert m.installed_file_path("bin/memveil") == "usr/bin/memveil"
    assert m.installed_file_path("lib/memveil/libx.so.1") == \
        "usr/lib/memveil/libx.so.1"
    assert m.installed_file_path("bpf/swiotlb_attempt.bpf.o") == \
        "usr/lib/memveil/swiotlb_attempt.bpf.o"
    assert m.installed_file_path("profiles/p.json") == \
        "usr/share/memveil/profiles/p.json"
    assert m.installed_file_path("docs/quickstart.md") == \
        "usr/share/memveil/docs/quickstart.md"
    assert m.installed_file_path("examples/demo/f.txt") == \
        "usr/share/memveil/docs/examples/demo/f.txt"
    assert m.installed_file_path("LICENSE") == \
        "usr/share/doc/memveil/LICENSE"
    assert m.installed_file_path("licenses/GPL-3.0.txt") == \
        "usr/share/doc/memveil/licenses/GPL-3.0.txt"
    with pytest.raises(ValueError):
        m.installed_file_path("MANIFEST.json")
    with pytest.raises(ValueError):
        m.installed_file_path("../escape")


@pytest.mark.parametrize("line", [
    'channel = "1.100.0"',
    "channel = '1.100.0'",
    'channel = "1.100.0"  # pinned toolchain',
    "channel = '1.100.0'  # pinned toolchain",
    'channel="1.100.0"',
])
def test_toolchain_channel_parses_quoting_and_comments(
        tmp_path, line):
    m = api()
    (Path(tmp_path) / "rust-toolchain.toml").write_text(
        "[toolchain]\n" + line + "\n")
    assert m.toolchain_channel(tmp_path) == "1.100.0"


def test_toolchain_channel_rejects_missing_or_invalid(
        tmp_path):
    m = api()
    with pytest.raises(ValueError, match="[Tt]oolchain"):
        m.toolchain_channel(tmp_path)
    (Path(tmp_path) / "rust-toolchain.toml").write_text(
        "[toolchain]\n# no channel here\n")
    with pytest.raises(ValueError, match="[Cc]hannel"):
        m.toolchain_channel(tmp_path)
    (Path(tmp_path) / "rust-toolchain.toml").write_text(
        "channel = \n")
    with pytest.raises(ValueError, match="[Tt]oolchain"):
        m.toolchain_channel(tmp_path)


def test_write_once_refuses_overwrite(tmp_path):
    m = api()
    path = Path(tmp_path) / "once.bin"
    m.write_once(path, b"first\n")
    assert path.read_bytes() == b"first\n"
    with pytest.raises(FileExistsError):
        m.write_once(path, b"second\n")
    assert path.read_bytes() == b"first\n"


def test_cli_help_is_available():
    for args in ([], ["seal"]):
        proc = subprocess.run(
            [str(ROOT / "tools" / "candidate"), *args, "--help"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 0, proc.stderr


def test_noncanonical_sealed_bytes_rejected(workshop, tmp_path):
    m, manifest = sealed_manifest(workshop, tmp_path)
    path = Path(tmp_path) / "candidate.json"
    path.write_text(json.dumps(manifest, indent=2))
    with pytest.raises(ValueError, match="[Cc]anonical"):
        m.load_manifest(path)


@pytest.mark.parametrize("link_first", [True, False])
def test_safe_extract_rejects_symlink_prefix_attack(tmp_path,
                                                    link_first):
    m = api()
    archive = Path(tmp_path) / "evil.tar.gz"
    outside = Path(tmp_path) / "outside"
    outside.mkdir()
    sentinel = outside / "pwned"
    link = tarfile.TarInfo("evil")
    link.type = tarfile.SYMTYPE
    link.linkname = str(outside)
    data = b"pwned\n"
    member = tarfile.TarInfo("evil/pwned")
    member.size = len(data)
    ordered = [(link, None), (member, io.BytesIO(data))]
    if not link_first:
        ordered.reverse()
    with tarfile.open(archive, "w:gz") as stream:
        for info, payload in ordered:
            stream.addfile(info, payload)
    with pytest.raises(ValueError, match="[Ss]ymlink"):
        m.safe_extract(archive, Path(tmp_path) / "dest", False, True)
    assert not sentinel.exists(), "extraction escaped the scratch dir"


def test_safe_extract_returns_the_inner_root(tmp_path):
    m = api()
    archive = Path(tmp_path) / "single.tar.gz"
    with tarfile.open(archive, "w:gz") as stream:
        data = b"inner\n"
        member = tarfile.TarInfo("evidence/kept.txt")
        member.size = len(data)
        stream.addfile(member, io.BytesIO(data))
    dest = Path(tmp_path) / "dest"
    inner = m.safe_extract(archive, dest, True, False)
    assert inner == dest / "evidence"
    assert (inner / "kept.txt").read_bytes() == b"inner\n"
    assert not (dest / "kept.txt").exists()


def test_payload_closure_defaults_to_cargo_run(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    artifacts = fix["artifacts"]
    debs = sorted(artifacts.glob("*.deb"))
    rpms = sorted(artifacts.glob("*.rpm"))
    assert len(debs) == 1 and len(rpms) == 1
    bundle = artifacts / "memveil-fixture.tar.gz"
    assert bundle.is_file()
    fallback = m.collect_payload_closure(
        ROOT, None, bundle, debs[0], rpms[0])
    explicit = m.collect_payload_closure(
        ROOT, workshop.harness_bin(), bundle, debs[0], rpms[0])
    assert fallback == explicit
    assert fallback, "empty payload closure"


def _role_archives(fix):
    """The bundle/deb/rpm paths the seal discovers in the fixture."""
    artifacts = fix["artifacts"]
    debs = sorted(artifacts.glob("*.deb"))
    rpms = sorted(artifacts.glob("*.rpm"))
    assert len(debs) == 1 and len(rpms) == 1
    bundle = artifacts / "memveil-fixture.tar.gz"
    assert bundle.is_file()
    return bundle, debs[0], rpms[0]


def _expected_default_harness_argv(m, fix):
    """Exact `cargo run` fallback argv against the sealed root."""
    bundle, deb, rpm = _role_archives(fix)
    return ["cargo", "run", "--manifest-path",
            str(Path(fix["root"]) / "Cargo.toml"),
            "-p", m.HARNESS_PACKAGE,
            "--locked", "--offline", "--", "payload-closure",
            "--bundle", str(bundle), "--deb", str(deb),
            "--rpm", str(rpm)]


def test_create_manifest_default_harness_uses_locked_offline_run(
        workshop, tmp_path, monkeypatch):
    m, fix = seal_paths(workshop, tmp_path)
    monkeypatch.setenv("RUSTUP_TOOLCHAIN", "seal-default-probe")
    real_run = subprocess.run
    calls = []

    def fake_run(argv, **kw):
        if isinstance(argv, list) and argv[:2] == ["cargo", "run"]:
            env = kw.get("env")
            calls.append({"argv": list(argv),
                          "env": dict(env) if env is not None
                          else None})
            tail = argv[argv.index("--") + 1:]
            args = dict(kw)
            args["env"] = None
            return real_run(
                [workshop.harness_bin(), *tail], **args)
        return real_run(argv, **kw)

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"])})
    assert manifest["schema"] == "memveil-candidate/2"
    assert len(calls) == 1, calls
    assert calls[0]["argv"] == _expected_default_harness_argv(m, fix)
    assert "--locked" in calls[0]["argv"]
    assert "--offline" in calls[0]["argv"]
    assert calls[0]["env"] is not None, \
        "default path must pass an explicit environment"
    assert "RUSTUP_TOOLCHAIN" not in calls[0]["env"]
    assert calls[0]["env"] == {
        key: value for key, value in os.environ.items()
        if key != "RUSTUP_TOOLCHAIN"}


def test_cli_default_harness_failure_propagates(
        workshop, tmp_path, monkeypatch, capsys):
    m, fix = seal_paths(workshop, tmp_path)
    monkeypatch.setenv("RUSTUP_TOOLCHAIN", "seal-default-probe")
    real_run = subprocess.run
    calls = []

    def fake_run(argv, **kw):
        if isinstance(argv, list) and argv[:2] == ["cargo", "run"]:
            env = kw.get("env")
            calls.append({"argv": list(argv),
                          "env": dict(env) if env is not None
                          else None})
            return subprocess.CompletedProcess(
                argv, 1, stdout="", stderr="cargo run boom\n")
        return real_run(argv, **kw)

    monkeypatch.setattr(m.subprocess, "run", fake_run)
    out = Path(tmp_path) / "candidate.json"
    with pytest.raises(SystemExit) as failure:
        m.main(["seal",
                "--bundle-dir", str(fix["bundle_dir"]),
                "--artifacts-dir", str(fix["artifacts"]),
                "--policy", str(fix["policy"]),
                "--source-root", str(fix["root"]),
                "--out", str(out)])
    assert failure.value.code == 1
    assert "payload closure failed" in capsys.readouterr().err
    assert not out.exists(), "failed seal must not write a manifest"
    assert len(calls) == 1, calls
    assert calls[0]["argv"] == _expected_default_harness_argv(m, fix)
    assert "RUSTUP_TOOLCHAIN" not in calls[0]["env"]


def _emit_source_info(fix):
    """Explicit emitter inputs: source root + one path per role."""
    artifacts = fix["artifacts"]
    deb = sorted(artifacts.glob("*.deb"))
    rpm = sorted(artifacts.glob("*.rpm"))
    sbom = sorted(artifacts.glob("*.spdx.json"))
    tars = sorted(artifacts.glob("*.tar.gz"))
    assert len(deb) == 1 and len(rpm) == 1 and len(sbom) == 1
    assert len(tars) == 2
    bundle = next(path for path in tars
                  if not path.name.endswith("source.tar.gz"))
    source = next(path for path in tars
                  if path.name.endswith("source.tar.gz"))
    return {"root": str(fix["root"]), "bundle": str(bundle),
            "deb": str(deb[0]), "rpm": str(rpm[0]),
            "source": str(source), "sbom": str(sbom[0])}


def _present_subjects(fix):
    """True {name: sha256} of the five non-provenance artifacts."""
    return {path.name: sha(path.read_bytes())
            for path in sorted(fix["artifacts"].iterdir())
            if not path.name.endswith(".provenance.json")}


def _reemit_sbom(workshop, fix):
    """Fresh harness SBOM over the current bundle and packages."""
    info = _emit_source_info(fix)
    sbom_out = Path(info["sbom"])
    sbom_out.unlink()
    proc = subprocess.run(
        [workshop.harness_bin(), "sbom-emit",
         "--manifest", str(fix["bundle_dir"] / "MANIFEST.json"),
         "--bundle", info["bundle"],
         "--deb", info["deb"],
         "--rpm", info["rpm"],
         "--lock", str(fix["root"] / "Cargo.lock"),
         "--ebpf-lock",
         str(fix["root"] / "crates" / "ebpf" / "Cargo.lock"),
         "--created", str(FIXED_EPOCH),
         "--out", str(sbom_out)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr


def _archive_source(root, dest):
    """Genuine `git archive HEAD` of root, gzip-normalized like builds."""
    proc = subprocess.run(
        ["git", "-C", str(root), "archive", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    Path(dest).write_bytes(gzip.compress(proc.stdout, mtime=0))


def _packager_module():
    """Load scripts/package-tarball.py as a module (no main run)."""
    path = ROOT / "scripts" / "package-tarball.py"
    spec = importlib.util.spec_from_file_location(
        "package_tarball_receipt", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_provenance_emitter_binds_recorded_receipt(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    # The packager's tree-inventory construction must match the
    # seal's exactly: the recorded inventory digest is derived
    # from the same git tree on both sides.
    packager = _packager_module()
    pack_entries, pack_digest = packager.git_tree_inventory(
        str(root), commit)
    seal_entries, seal_digest = m.git_inventory(root, commit)
    assert pack_entries == seal_entries
    assert pack_digest == seal_digest
    recorded = json.loads(
        (fix["bundle_dir"] / "MANIFEST.json").read_text())[
            "build_receipt"]
    assert recorded["inventory_sha256"] == seal_digest
    assert recorded["source_commit"] == commit
    # The real emission flow: provenance does not exist yet, so
    # remove the fixture copy, emit from the recorded receipt,
    # and stage the emitted bytes as the sixth artifact.
    next(fix["artifacts"].glob("*.provenance.json")).unlink()
    out = fix["artifacts"] / "memveil-fixture.provenance.json"
    emitted_digest = m.emit_provenance(
        fix["bundle_dir"], _emit_source_info(fix), out)
    raw = out.read_bytes()
    emitted = json.loads(raw)
    assert raw == m.canonical(emitted)
    assert emitted_digest == m.digest_canonical(emitted) == sha(raw)
    assert emitted["schema"] == "memveil-local-build/2"
    assert emitted["origin"] == "local-build"
    assert emitted["build_receipt"] == recorded
    assert emitted["subjects"] == _present_subjects(fix)
    assert emitted["source"] == {
        "commit": commit,
        "tree": git(root, "rev-parse", "HEAD^{tree}"),
        "inventory_sha256": seal_digest}
    assert emitted["toolchain"] == {
        "cargo_lock_sha256": sha((root / "Cargo.lock").read_bytes()),
        "ebpf_lock_sha256": sha(
            (root / "crates" / "ebpf" / "Cargo.lock").read_bytes()),
        "tools": workshop.tools()}
    with pytest.raises(FileExistsError):
        m.emit_provenance(
            fix["bundle_dir"], _emit_source_info(fix), out)
    assert out.read_bytes() == raw, "refused emit must not touch bytes"
    # The CLI emits the same bytes elsewhere and refuses overwrite.
    cli_out = Path(tmp_path) / "cli.provenance.json"
    info = _emit_source_info(fix)
    argv = [str(ROOT / "tools" / "candidate"), "provenance",
           "--bundle-dir", str(fix["bundle_dir"]),
           "--bundle", info["bundle"], "--deb", info["deb"],
           "--rpm", info["rpm"], "--source", info["source"],
           "--sbom", info["sbom"],
           "--source-root", str(fix["root"]),
           "--out", str(cli_out)]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha(cli_out.read_bytes())
    assert cli_out.read_bytes() == raw
    rerun = subprocess.run(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
    assert rerun.returncode == 1
    assert rerun.stderr.strip(), "silent provenance failure"
    # A real seal runs end-to-end on the emitted provenance.
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], fix["policy"],
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})
    assert manifest["schema"] == "memveil-candidate/2"
    assert manifest["build_receipt_sha256"] == m.digest_canonical(
        recorded)


@pytest.mark.parametrize("edge", ["missing-role", "symlink-subject",
                                  "duplicate-basenames",
                                  "dirty-root"])
def test_provenance_emitter_rejects_bad_inputs(workshop,
                                               tmp_path, edge):
    m, fix = seal_paths(workshop, tmp_path)
    info = _emit_source_info(fix)
    out = Path(tmp_path) / ("emitter-%s.provenance.json" % edge)
    if edge == "missing-role":
        del info["sbom"]
    elif edge == "symlink-subject":
        link = Path(tmp_path) / "linked.deb"
        os.symlink(info["deb"], link)
        info["deb"] = str(link)
    elif edge == "duplicate-basenames":
        twin = Path(tmp_path) / "twin"
        twin.mkdir()
        same = twin / Path(info["deb"]).name
        shutil.copy2(info["deb"], same)
        info["rpm"] = str(same)
    elif edge == "dirty-root":
        (fix["root"] / "src" / "uncommitted.txt").write_text(
            "dirty\n")
    with pytest.raises(ValueError):
        m.emit_provenance(fix["bundle_dir"], info, out)
    assert not out.exists(), "refused emit must not write bytes"


def _advance_fixture_to_c1(fix):
    """Commit an unrelated file in the fixture root; return C1 facts."""
    m = api()
    root = fix["root"]
    (root / "src" / "c1-note.txt").write_text("second commit\n")
    git(root, "add", "src/c1-note.txt")
    git(root, "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "Fixture C1")
    commit = git(root, "rev-parse", "HEAD")
    tree = git(root, "rev-parse", "HEAD^{tree}")
    return {"commit": commit, "tree": tree,
            "inventory": m.git_inventory(root, commit)[1]}


def _reclaim_bundle_as(fix, commit):
    """Rewrite the bundle revision claim and re-tar the bundle."""
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    doc["memveil_revision"] = commit
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    rebuild_bundle_tarball(fix)


def test_seal_rejects_deep_stale_prebuilt(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    # (a) A self-consistent C' build (engine, BPF, receipt recorded
    # at C') presented as C1: the source archive, SBOM, tarball, and
    # revision claim are all genuinely C1, but the build-time receipt
    # still binds C'. The honest staleness already fails; the receipt
    # forgery below must fail through the recorded receipt alone.
    first = _advance_fixture_to_c1(fix)
    _reclaim_bundle_as(fix, first["commit"])
    info = _emit_source_info(fix)
    Path(info["source"]).unlink()
    _archive_source(fix["root"], info["source"])
    _reemit_sbom(workshop, fix)
    subjects = _present_subjects(fix)
    rewrite_provenance(
        m, fix,
        lambda doc: doc.update(
            {"source": {"commit": first["commit"],
                        "tree": first["tree"],
                        "inventory_sha256": first["inventory"]},
             "subjects": dict(subjects)}))
    with pytest.raises(ValueError, match="[Rr]eceipt|[Ss]ource"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})
    rewrite_provenance(
        m, fix,
        lambda doc: doc["build_receipt"].update(
            {"source_commit": first["commit"],
             "inventory_sha256": first["inventory"]}))
    with pytest.raises(ValueError, match="[Rr]ecorded|[Rr]eceipt"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})

    # (b) The receipt was recorded at C but the engine was swapped
    # afterwards; the files map, tarball, and provenance
    # outputs/subjects were consistently re-pointed at the swapped
    # bytes. Only the recorded receipt names the build outputs, so
    # both the seal and a re-emit must refuse through it (the seal's
    # recorded-receipt gate fires before the stale SBOM/packages).
    m, fix = seal_paths(workshop, tmp_path / "swapped")
    engine = fix["bundle_dir"] / "bin" / "memveil"
    engine.write_bytes(b"synthetic-engine-rebuilt\n")
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    doc = json.loads(manifest_path.read_text())
    doc["files"]["bin/memveil"] = sha(engine.read_bytes())
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    rebuild_bundle_tarball(fix)
    subjects = _present_subjects(fix)
    swapped = sha(engine.read_bytes())

    def forge_outputs(doc):
        doc["build_receipt"]["outputs"].update(
            {"engine_sha256": swapped})
        doc.update({"subjects": dict(subjects)})

    rewrite_provenance(m, fix, forge_outputs)
    with pytest.raises(ValueError, match="[Rr]eceipt"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})
    with pytest.raises(ValueError, match="[Rr]eceipt"):
        m.emit_provenance(
            fix["bundle_dir"], _emit_source_info(fix),
            tmp_path / "swapped.provenance.json")


MATRIX_GATE = "kernel-matrix/2"
MATRIX_ROW = _admitted_entry()["id"]
NONMATRIX_GATE = "synthetic-counts/1"


def _matrix_lock(entry):
    return {"schema": km.SCHEMA, "recorded_on": "2026-11-19",
            "archive": "https://kernel.ubuntu.com/mainline",
            "archive_queried": "2026-11-19",
            "tools": {"bpftrace": "bpftrace v0.25.0",
                      "bpftool": "bpftool v7.7.0"},
            "kernels": [entry]}


def _spread_bytes(total, count):
    """Exact integer split of total bytes over count lines."""
    base, rem = divmod(total, count)
    return [base + 1 if idx < rem else base
            for idx in range(count)]


def _emit_matrix_events(ev):
    """events.ndjson lines re-deriving the cached derivations.

    Emits one line per persisted event with byte fields that
    sum exactly to the cached byte sums, mapping IDs that
    pair every successful map with an unmap, and counter
    snapshots that delta exactly to the cached counters.
    """
    lines = []
    for size in _spread_bytes(
            ev["persisted_bytes"]["requested"],
            ev["persisted"]["bounce_attempt"]):
        lines.append({"kind": "bounce_attempt",
                      "data": {"requested_bytes": size}})
    for idx, size in enumerate(_spread_bytes(
            ev["persisted_bytes"]["mapped"],
            ev["persisted"]["map_result"])):
        lines.append({"kind": "map_result",
                      "data": {"success": True,
                             "mapping_id": "m%d" % idx,
                             "mapped_bytes": size}})
    for idx in range(ev["persisted"]["unmap"]):
        if idx < ev["persisted"]["map_result"]:
            ident = "m%d" % idx
        else:
            ident = "stray%d" % idx
        lines.append({"kind": "unmap",
                      "data": {"mapping_id": ident}})
    copied = ev["persisted_bytes"]["copy"]
    for direction in ("original_to_bounce",
                      "bounce_to_original"):
        for size in _spread_bytes(
                copied[direction],
                ev["persisted_copy_dirs"][direction]):
            lines.append({"kind": "copy",
                          "data": {"direction": direction,
                                 "bytes": size}})
    for size in _spread_bytes(ev["persisted_bytes"]["sync"],
                              ev["persisted"]["sync_request"]):
        lines.append({"kind": "sync_request",
                      "data": {"length": size}})
    for ident in sorted(ev["counters"]):
        for value in (0, ev["counters"][ident]):
            lines.append({"kind": "counter_snapshot",
                          "data": {"counter_id": ident,
                                 "epoch": 0, "value": value}})
    return "".join(json.dumps(line, sort_keys=True) + "\n"
                   for line in lines)


def _write_real_matrix_row(m, matrix_dir, doc):
    """Honest matrix row bound to a sealed manifest.

    Builds a passing admitted row from the shared matrix
    fixtures, binds its receipt to the manifest (source,
    toolchain, executable, BPF, closure, candidate ID), and
    writes the row directory plus the <id>.json rec and
    summary.json beside it. Every predicate-consumed cached
    value is backed by retained bytes: exit/status files,
    the oracle mode, program snapshots, a generated events
    file re-deriving the cached counts, the busy shrink
    summary, validate records, and an honestly scanned
    redaction outcome. Returns (ev, rec, receipt, row).
    """
    ev = _ev_pass()
    ev["duration"] = 60
    hooks = json.loads(ev["hooks_text"])
    hooks["btf"] = True
    ev["hooks_text"] = json.dumps(hooks)
    for field in ("miss_snaps", "busy_miss_snaps"):
        ev[field] = [[nsecs, text]
                     for nsecs, text in ev[field]]
    ev["candidate_sha256"] = m.digest_bytes(m.canonical(doc))
    ev["candidate_files"] = copy.deepcopy(doc["files"])
    measured = json.loads(ev["artifacts_text"])
    measured["binary"]["sha256"] = doc["files"]["bin/memveil"]
    for channel in ("attempt", "lifecycle", "copy"):
        measured["bpf"][channel] = \
            doc["files"]["bpf/swiotlb_%s.bpf.o" % channel]
    ev["artifacts_text"] = json.dumps(measured)
    ev["persisted"]["counter_snapshot"] = \
        2 * len(ev["counters"])
    ev["oracle_mode"] = "full"
    ev["unpaired_count"] = 0
    ev["unpaired_bytes"] = 0
    ev["unpaired_error"] = None
    ev["busy_events_bytes"] = 1048576
    matrix_dir = Path(matrix_dir)
    row = matrix_dir / ev["entry"]["id"]
    row.mkdir(parents=True)
    job = _row_job()
    job.update(id=ev["entry"]["id"],
               release=ev["entry"]["release"],
               run_id="20261101T000000Z")
    files = {"job.json": json.dumps(job),
             "vng.exit": ev["vng_exit"],
             # Local-only host command line with an
             # address-like payload: the collector writes
             # it, but receipts, the signed inventory,
             # replays, and shipped archives must all
             # ignore it.
             "vng-cmd.txt":
             "sudo -n vng --run 0x7f8a1b2c3d4e "
             "--rwdir=/tmp/export=/work/0123456789abcdef\n",
             "artifacts.json": ev["artifacts_text"],
             "uname.txt": ev["uname_text"],
             "mods.txt": ev["mods_text"],
             "hooks.json": ev["hooks_text"],
             "btf-sha.txt": "2" * 64,
             "oracle.txt": ev["oracle_text"],
             "oracle.stderr": ev["oracle_stderr"],
             "oracle.mode": "full",
             "doctor.json": ev["doctor_text"],
             "doctor.exit": ev["doctor_exit"],
             "doctor-passive.json": ev["doctor_passive_text"],
             "doctor-passive.exit":
             ev["doctor_passive_exit"],
             "sev-sysfs.txt": ev["sev_sysfs_text"],
             "dmesg.txt": ev["dmesg_text"],
             "dmesg_scan.json": ev["dmesg_scan_text"],
             "cap/session.json": ev["session_text"],
             "record.exit": ev["record_exit"],
             "report.exit": ev["report_exit"],
             "report-json.exit": ev["report_json_exit"],
             "workload.txt": ev["workload_text"],
             "blockstat.json": ev["blockstat_text"],
             "udev.exit": ev["udev_exit"],
             "udev.out": ev["udev_out"],
             "busy/record.exit": ev["busy_record_exit"],
             "busy/end_reason.txt": ev["busy_end_reason"],
             "busy/report.exit": ev["busy_report_exit"],
             "busy/report-json.exit":
             ev["busy_report_json_exit"],
             "busy/times.json": ev["busy_times_text"],
             "busy/busy.out": ev["busy_out_text"],
             "busy/cap/session.json": ev["busy_session_text"]}
    for name, value in files.items():
        target = row / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)
    (row / "cap" / "events.ndjson").write_text(
        _emit_matrix_events(ev))
    for field, subdir, count in (("miss_snaps", "", 4),
                                 ("busy_miss_snaps", "busy",
                                  3)):
        snaps = ev[field]
        base = row / subdir if subdir else row
        (base / "progs_times.json").write_text(json.dumps(
            {str(idx): snaps[idx][0]
             for idx in range(count)}))
        for idx in range(count):
            (base / ("progs%d.json" % idx)).write_text(
                snaps[idx][1])
    summary = {"sha256": sha(b"fixture-busy-events"),
               "bytes": ev["busy_events_bytes"],
               "counts": ev["busy_persisted"],
               "counters": ev["busy_counters"],
               "counters_error": ev["busy_counters_error"]}
    (row / "busy" / "events_summary.json").write_text(
        json.dumps(summary))
    (row / "validate.json").write_text(json.dumps(
        {"rc": ev["validate_rc"],
         "out": ev["validate_out"]}) + "\n")
    (row / "busy" / "validate.json").write_text(json.dumps(
        {"rc": ev["busy_validate_rc"],
         "out": ev["busy_validate_out"]}) + "\n")
    ev["export_redact_error"] = km.scan_export_redaction(
        row, skip={"receipt.json", "oracle-inputs.json"}
        | km.REDACT_SKIP_LOCAL)
    rec = km.evaluate_row(ev)
    assert rec["ok"], rec
    rec.update(run_id="20261101T000000Z", elapsed=1.0,
               timeout=False, release=ev["entry"]["release"])
    job.update(run_id=rec["run_id"])
    (row / "job.json").write_text(json.dumps(job))
    (row / "oracle-inputs.json").write_text(json.dumps(ev))
    ctx = _row_ctx(
        kernel_selector="--kernel " + ev["entry"]["id"],
        source_sha256=m.artifact(doc, "deb")["sha256"])
    ctx["source"]["memveil"] = {"commit": doc["source"]["commit"],
                                "dirty": False}
    ctx["toolchain"]["lock_sha256"] = \
        doc["toolchain"]["cargo_lock_sha256"]
    receipt = km.write_row_receipt(row, rec, ev["entry"], ctx)
    (matrix_dir / (ev["entry"]["id"] + ".json")).write_text(
        json.dumps(rec))
    (matrix_dir / "summary.json").write_text(json.dumps([rec]))
    return ev, rec, receipt, row


def _ephemeral_key(target):
    """Fresh Ed25519 signing key; returns (private, public)."""
    target = Path(target)
    subprocess.run(
        ["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
         "-f", str(target)],
        check=True, capture_output=True)
    return target, Path(str(target) + ".pub")


def _sign(key, subject):
    """Sign subject with ssh-keygen -Y; return the signature path."""
    stale = Path(str(subject) + ".sig")
    # ssh-keygen prompts instead of overwriting a stale
    # signature, so remove it first; the signer always writes
    # fresh bytes for the current subject.
    if stale.exists():
        stale.unlink()
    subprocess.run(
        ["ssh-keygen", "-Y", "sign", "-f", str(key),
         "-n", "memveil-candidate", str(subject)],
        check=True, capture_output=True)
    return Path(str(subject) + ".sig")


def _write_policy(m, path, required_gates, trusted):
    policy = {"schema": "memveil-candidate-policy/1",
              "claim": "ordinary-preview",
              "retention_days": "90",
              "trusted_keys": list(trusted),
              "required_gates": required_gates}
    Path(path).write_bytes(m.canonical(policy))
    return policy


def _sealed_for_qualify(workshop, tmp_path, required_gates):
    """Seal a manifest bound to a real policy and ephemeral trust.

    The policy lives outside the sealed root (the seal only binds
    its digest), so the fixture root stays clean.
    """
    m, fix = seal_paths(workshop, tmp_path)
    private, public = _ephemeral_key(Path(tmp_path) / "key")
    policy_path = Path(tmp_path) / "policy.json"
    _write_policy(m, policy_path, required_gates,
                  [sha(public.read_bytes())])
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], policy_path,
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})
    manifest_path = Path(tmp_path) / "candidate.json"
    candidate_id = m.seal_manifest(manifest, manifest_path)
    return m, {"root": fix["root"], "manifest": manifest,
               "manifest_path": manifest_path,
               "candidate_id": candidate_id,
               "policy_path": policy_path,
               "artifacts": fix["artifacts"],
               "key": private, "pub": public}


def _signed_gate(m, ctx, evidence, gate, inputs_name,
                 receipt_name, inputs):
    """Write inputs + gate receipt, sign it, stage the pubkey."""
    evidence = Path(evidence)
    inputs_path = evidence / inputs_name
    inputs_path.write_bytes(m.canonical(inputs))
    receipt = {"schema": "memveil-gate-receipt/1", "gate": gate,
               "candidate_sha256": ctx["candidate_id"],
               "source_commit":
               ctx["manifest"]["source"]["commit"],
               "inputs": inputs_name,
               "inputs_sha256": sha(inputs_path.read_bytes())}
    receipt_path = evidence / receipt_name
    receipt_path.write_bytes(m.canonical(receipt))
    sig = _sign(ctx["key"], receipt_path)
    shutil.copy2(ctx["pub"], evidence / "signer.pub")
    return {"receipt": receipt_name,
            "receipt_sha256": sha(receipt_path.read_bytes()),
            "signature": sig.name, "public_key": "signer.pub"}


def _write_qualification(m, ctx, path, gates):
    doc = {"schema": "memveil-qualification/1",
           "candidate_sha256": ctx["candidate_id"],
           "source_commit":
           ctx["manifest"]["source"]["commit"],
           "claim": "ordinary-preview",
           "evidence_archive":
           {"name": "qualification-evidence.tar.gz",
            "size": "1", "sha256": "5" * 64},
           "gates": gates}
    Path(path).write_bytes(m.canonical(doc))
    return doc


def _matrix_required_gates():
    return {MATRIX_GATE:
            {"environment": "ordinary-linux",
             "predicates": {"required_rows": "equal",
                            "failed_rows": "zero",
                            "skipped_rows": "zero"}}}


def _write_matrix_evidence(m, ctx, evidence):
    """One honest matrix row bound to the sealed manifest."""
    matrix = Path(evidence) / "matrix"
    matrix.mkdir(parents=True)
    _ev, _rec, _receipt, row = _write_real_matrix_row(
        m, matrix, ctx["manifest"])
    assert row.name == MATRIX_ROW, row.name
    return matrix


def _matrix_inputs(m, evidence):
    inventory = m.build_evidence_inventory(evidence, "matrix")
    assert inventory, "empty matrix inventory"
    return {"schema": "memveil-matrix-input/2",
            "matrix_directory": "matrix",
            "evidence_inventory_sha256":
            m.digest_canonical(inventory)}


def _matrix_qualified(workshop, tmp_path):
    """Honest signed matrix gate; returns (m, ctx, evidence, q)."""
    m, ctx = _sealed_for_qualify(workshop, tmp_path,
                                 _matrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    evidence.mkdir()
    _write_matrix_evidence(m, ctx, evidence)
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           _matrix_inputs(m, evidence))
    q_path = Path(tmp_path) / "qualification.json"
    doc = _write_qualification(m, ctx, q_path,
                               {MATRIX_GATE: binding})
    return m, ctx, evidence, q_path, doc


def test_matrix_inputs_require_signed_inventory(workshop,
                                                tmp_path):
    m, ctx = _sealed_for_qualify(workshop, tmp_path,
                                 _matrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    evidence.mkdir()
    _write_matrix_evidence(m, ctx, evidence)
    # /1 inputs fail closed even with a valid signature on them.
    legacy = {"schema": "memveil-matrix-input/1",
              "matrix_directory": "matrix",
              "lock_sha256": "1" * 64}
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           legacy)
    q_path = Path(tmp_path) / "qualification.json"
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})
    with pytest.raises(ValueError,
                       match="invalid fields|[Ff]ail closed"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    # A /2-shaped doc with a /1 schema gets the explicit blame.
    flipped = _matrix_inputs(m, evidence)
    flipped["schema"] = "memveil-matrix-input/1"
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           flipped)
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})
    with pytest.raises(ValueError, match="[Ff]ail closed"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    # /2 inputs without the inventory digest fail closed too.
    naked = {"schema": "memveil-matrix-input/2",
             "matrix_directory": "matrix"}
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           naked)
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})
    with pytest.raises(ValueError, match="invalid fields"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_inventory_rejects_altered_row_receipt(workshop,
                                               tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"])) == {"ok": True, "gates": [MATRIX_GATE],
                      "trusted_keys": [sha(
                          ctx["pub"].read_bytes())],
                      "claim": "ordinary-preview"}
    receipt_path = evidence / "matrix" / MATRIX_ROW \
        / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["files"][0]["sha256"] = "7" * 64
    receipt_path.write_bytes(m.canonical(receipt))
    with pytest.raises(ValueError, match="inventory differs"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    # The inventory error fires before signature verification:
    # breaking the signature as well must not change the blame.
    (evidence / "receipt.json.sig").write_bytes(b"invalid\n")
    with pytest.raises(ValueError, match="inventory differs"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_inventory_rejects_missing_oracle_inputs(workshop,
                                                 tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    (evidence / "matrix" / MATRIX_ROW
     / "oracle-inputs.json").unlink()
    with pytest.raises(ValueError, match="missing"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_inventory_rejects_extra_file(workshop, tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    (row / "extra.bin").write_bytes(b"unretained\n")
    with pytest.raises(ValueError,
                       match="unknown|extra|refuses"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    (row / "extra.bin").unlink()
    (evidence / "matrix" / "extra.json").write_text("{}\n")
    with pytest.raises(ValueError, match="extra"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_inventory_rejects_symlinked_row_directory(workshop,
                                                   tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    (row / "real.d").mkdir()
    (row / "real.d" / "kept.txt").write_text("kept\n")
    os.symlink("real.d", row / "linked.d")
    with pytest.raises(ValueError, match="symlink"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_inventory_accepts_runner_harness_and_summary(
        workshop, tmp_path):
    m, ctx = _sealed_for_qualify(workshop, tmp_path,
                                 _matrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    evidence.mkdir()
    _write_matrix_evidence(m, ctx, evidence)
    matrix = evidence / "matrix"
    harness = {"vng": "vng test", "qemu": "qemu test",
               "bpftrace": "bpftrace test",
               "bpftool": "bpftool test",
               "run_id": "20261101T000000Z",
               "deb_sha256": "d" * 64,
               "harness_commit": "c" * 40,
               "harness_dirty": False}
    (matrix / "harness.json").write_bytes(m.canonical(harness))
    (matrix / "summary.txt").write_text(
        "kernel vng doctor record report channels "
        "detail/aggregate verdict run\n"
        + MATRIX_ROW + " vng PASS run=20261101T000000Z\n")
    inventory = m.build_evidence_inventory(evidence, "matrix")
    assert inventory["harness.json"] == sha(
        (matrix / "harness.json").read_bytes())
    assert inventory["summary.txt"] == sha(
        (matrix / "summary.txt").read_bytes())
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           _matrix_inputs(m, evidence))
    q_path = Path(tmp_path) / "qualification.json"
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"]))["ok"] is True
    archive = Path(tmp_path) / "qualification-evidence.tar.gz"
    excluded = m.build_evidence_archive(evidence, archive)
    assert "matrix/harness.json" not in excluded
    assert "matrix/summary.txt" not in excluded
    with tarfile.open(archive, "r:gz") as stream:
        names = stream.getnames()
    assert "evidence/matrix/harness.json" in names
    assert "evidence/matrix/summary.txt" in names


@pytest.mark.parametrize("name", ["harness.json", "summary.txt"])
def test_inventory_admits_each_runner_output(tmp_path, name):
    m = api()
    assert set(m.MATRIX_RUNNER_FILES) == {"harness.json",
                                          "summary.txt"}
    matrix = Path(tmp_path) / "matrix"
    row = matrix / "row-a"
    row.mkdir(parents=True)
    (row / "receipt.json").write_text("{}\n")
    (row / "oracle-inputs.json").write_text("{}\n")
    (matrix / "summary.json").write_text("[]\n")
    (matrix / name).write_text("runner output\n")
    inventory = m.build_evidence_inventory(tmp_path, "matrix")
    assert inventory[name] == sha(b"runner output\n")
    assert inventory["summary.json"] == sha(b"[]\n")
    assert inventory["row-a/receipt.json"] == sha(b"{}\n")


@pytest.mark.parametrize("name", ["Harness.json",
                                  "harness.json.sig",
                                  "summary.txt~",
                                  "summary.json.bak"])
def test_inventory_still_rejects_runner_lookalikes(tmp_path,
                                                   name):
    m = api()
    matrix = Path(tmp_path) / "matrix"
    row = matrix / "row-a"
    row.mkdir(parents=True)
    (row / "receipt.json").write_text("{}\n")
    (row / "oracle-inputs.json").write_text("{}\n")
    (matrix / "summary.json").write_text("[]\n")
    (matrix / name).write_text("runner output\n")
    with pytest.raises(ValueError, match="extra"):
        m.build_evidence_inventory(tmp_path, "matrix")


def test_redaction_replay_ignores_local_vng_cmd(workshop,
                                                  tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    # The fixture row carries a local-only host command
    # line with an address-like payload. The payload is
    # meaningful: an unskipped scan names it.
    raw = (row / "vng-cmd.txt").read_text()
    assert "0x" in raw
    assert km.scan_export_redaction(
        row, skip={"receipt.json",
                   "oracle-inputs.json"}) == \
        "vng-cmd.txt: redacted text keeps 0x address"
    # The pinned skip set ignores it, and the row receipt
    # still excludes its raw bytes.
    assert km.REDACT_SKIP_LOCAL == frozenset({"vng-cmd.txt"})
    assert km.scan_export_redaction(
        row, skip={"receipt.json", "oracle-inputs.json"}
        | km.REDACT_SKIP_LOCAL) is None
    receipt = json.loads((row / "receipt.json").read_text())
    assert "vng-cmd.txt" not in [
        entry["name"] for entry in receipt["files"]]
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"]))["ok"] is True
    # Rewriting the local-only bytes after signing changes
    # no verdict: the signed inventory never bound them and
    # the replay never reads them.
    (row / "vng-cmd.txt").write_text(
        "vng --run 0xaaaaaaaaaaaaaaaa --rwdir=/tmp/x\n")
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"]))["ok"] is True


def test_evidence_archive_excludes_local_vng_cmd(workshop,
                                                 tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    assert (row / "vng-cmd.txt").is_file()
    archive = Path(tmp_path) / "qualification-evidence.tar.gz"
    excluded = m.build_evidence_archive(evidence, archive)
    assert excluded == ["matrix/" + MATRIX_ROW + "/vng-cmd.txt"]
    with tarfile.open(archive, "r:gz") as stream:
        names = stream.getnames()
    assert names[0] == "evidence"
    assert "evidence/matrix/" + MATRIX_ROW + "/vng-cmd.txt" \
        not in names
    assert not any(Path(name).name == "vng-cmd.txt"
                   for name in names)
    assert "evidence/matrix/" + MATRIX_ROW + "/oracle.txt" \
        in names
    # The packed archive still extracts and verifies: the
    # exclusion drops only the local-only bytes.
    inner = m.safe_extract(archive, Path(tmp_path) / "packed",
                           True, False)
    assert not (inner / "matrix" / MATRIX_ROW
                / "vng-cmd.txt").exists()
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        inner, source_tree=str(ctx["root"]))["ok"] is True
    # Builder edges fail closed: symlinks never pack, and
    # the destination is never overwritten.
    (row / "linked.txt").symlink_to(row / "oracle.txt")
    with pytest.raises(ValueError, match="symlink"):
        m.build_evidence_archive(
            evidence, Path(tmp_path) / "linked.tar.gz")
    (row / "linked.txt").unlink()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        m.build_evidence_archive(evidence, archive)


def test_pack_evidence_cli_reports_digest(workshop, tmp_path):
    m, ctx, evidence, _q_path, _doc = _matrix_qualified(
        workshop, tmp_path)
    archive = Path(tmp_path) / "cli-evidence.tar.gz"
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "candidate.py"),
         "pack-evidence", "--evidence-dir", str(evidence),
         "--out", str(archive)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines() == [
        sha(archive.read_bytes())]
    assert "excluded local-only: matrix/" + MATRIX_ROW \
        + "/vng-cmd.txt" in proc.stderr


def test_qualification_inside_evidence_is_refused(workshop,
                                                 tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    # The old self-referential layout: the digest record
    # consumed from inside its own evidence dir.
    inner = evidence / "qualification.json"
    inner.write_bytes(q_path.read_bytes())
    with pytest.raises(ValueError, match="beside the evidence"):
        m.verify_qualification(ctx["manifest_path"], inner,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    # The external layout verifies over the same bytes; the
    # unread inner copy is ignored, never trusted.
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"]))["ok"] is True


def test_evidence_archive_refuses_inner_qualification(
        workshop, tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    (evidence / "qualification.json").write_bytes(
        q_path.read_bytes())
    with pytest.raises(ValueError, match="never inside"):
        m.build_evidence_archive(
            evidence, Path(tmp_path) / "inner.tar.gz")


def test_original_signature_rejects_mutated_evidence(workshop,
                                                     tmp_path):
    m, ctx, evidence, q_path, doc = _matrix_qualified(
        workshop, tmp_path)
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"])) == {"ok": True, "gates": [MATRIX_GATE],
                      "trusted_keys": [sha(
                          ctx["pub"].read_bytes())],
                      "claim": "ordinary-preview"}
    signed = {name: sha((evidence / name).read_bytes())
              for name in ("receipt.json", "receipt.json.sig",
                           "inputs.json")}
    # The attack: retained oracle counts change, every unsigned
    # hash is refreshed (row transcription plus the outer
    # evidence-archive hash), the cached inputs stay behind.
    row = evidence / "matrix" / MATRIX_ROW
    oracle = row / "oracle.txt"
    original = oracle.read_text()
    altered = original.replace("13000", "999999")
    assert original != altered
    oracle.write_text(altered)
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["oracle"]["text_sha256"] = sha(
        oracle.read_bytes())
    receipt["files"] = km.row_receipt_files(row)
    receipt_path.write_bytes(m.canonical(receipt))
    doc["evidence_archive"]["sha256"] = "6" * 64
    q_path.write_bytes(m.canonical(doc))
    assert signed == {name: sha((evidence / name).read_bytes())
                      for name in signed}, \
        "the signed bytes must be untouched"
    with pytest.raises(ValueError, match="inventory differs"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))
    # The original signature itself still verifies standalone:
    # only the signed inventory catches the substitution.
    m.verify_signature(evidence / "receipt.json",
                       evidence / "receipt.json.sig",
                       evidence / "signer.pub",
                       [sha((evidence / "signer.pub")
                            .read_bytes())])


def _resign_matrix_inputs(m, ctx, evidence, q_path):
    """Rebuild the matrix inputs and re-sign them over evidence."""
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           _matrix_inputs(m, evidence))
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})


def test_qualify_rejects_failing_row_predicates(workshop,
                                                tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    # The attack: the oracle counts change identically in the
    # retained raw file and the cached transcription, with
    # every unsigned hash refreshed, so only the re-derived
    # predicates (persisted counts above the oracle bounds)
    # can refuse.
    oracle = row / "oracle.txt"
    altered = oracle.read_text().replace("13000", "12000")
    assert altered != oracle.read_text()
    oracle.write_text(altered)
    cached_path = row / "oracle-inputs.json"
    ev = json.loads(cached_path.read_text())
    ev["oracle_text"] = altered
    cached_path.write_text(json.dumps(ev))
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["oracle"]["text_sha256"] = sha(
        oracle.read_bytes())
    receipt["files"] = km.row_receipt_files(row)
    receipt_path.write_bytes(m.canonical(receipt))
    _resign_matrix_inputs(m, ctx, evidence, q_path)
    with pytest.raises(ValueError, match="[Pp]redicates"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_qualify_rejects_mismatched_recorded_checks(workshop,
                                                    tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    # The attack: the recorded checks no longer match what the
    # predicates re-derive from the cached inputs. The shared
    # receipt re-derivation refuses first (the row no longer
    # re-derives PASS), exactly as the tested export always
    # did; the predicate path stays covered by the
    # failing-predicates test above.
    receipt["actual"]["checks"][0]["ok"] = \
        not receipt["actual"]["checks"][0]["ok"]
    receipt_path.write_bytes(m.canonical(receipt))
    _resign_matrix_inputs(m, ctx, evidence, q_path)
    with pytest.raises(ValueError,
                       match="required matrix rows did not pass"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


def test_qualify_rejects_receipt_files_drift(workshop,
                                             tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    # The attack: the receipt's files[] inventory no longer
    # matches the retained row bytes (one hash rewritten)
    # while every predicate input and recorded check stays
    # honest, so only receipt-internal consistency can refuse.
    assert receipt["files"][0]["sha256"] != "0" * 64
    receipt["files"][0]["sha256"] = "0" * 64
    receipt_path.write_bytes(m.canonical(receipt))
    _resign_matrix_inputs(m, ctx, evidence, q_path)
    with pytest.raises(ValueError,
                       match="required matrix rows did not pass"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


@pytest.mark.parametrize(
    "damage,blame",
    [("engine", "matrix executable differs"),
     ("bpf", "matrix BPF object differs"),
     ("smoke", "smoke-only"),
     ("package", "matrix selected artifact differs"),
     ("source", "matrix product source differs"),
     ("toolchain", "matrix toolchain differs"),
     ("entry", "pinned lock"),
     ("closure", "runtime/profile closure differs")])
def test_qualify_refuses_foreign_tested_bytes(
        workshop, tmp_path, damage, blame):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    cached_path = row / "oracle-inputs.json"
    ev = json.loads(cached_path.read_text())
    if damage in ("engine", "bpf"):
        # The attack: the row tested different bytes, kept
        # consistent across the retained artifacts file, the
        # cached transcription, and the receipt, so only the
        # row-to-candidate binding can refuse.
        measured = json.loads((row / "artifacts.json")
                              .read_text())
        if damage == "engine":
            measured["binary"]["sha256"] = "9" * 64
            receipt["artifacts"]["binary_sha256"] = "9" * 64
        else:
            measured["bpf"]["attempt"] = "9" * 64
            receipt["artifacts"]["bpf"]["attempt"] = "9" * 64
        (row / "artifacts.json").write_text(
            json.dumps(measured))
        ev["artifacts_text"] = json.dumps(measured)
        cached_path.write_text(json.dumps(ev))
        receipt["files"] = km.row_receipt_files(row)
    elif damage == "smoke":
        # A short smoke run, consistently relabelled in the
        # job transcript and the receipt workload, still
        # refuses: qualification needs full-run rows.
        job = json.loads((row / "job.json").read_text())
        job["duration"] = 61
        (row / "job.json").write_text(json.dumps(job))
        receipt["command"]["duration_s"] = 61
        receipt["workload"]["duration_s"] = 61
        receipt["smoke"] = True
        receipt["files"] = km.row_receipt_files(row)
    elif damage == "package":
        receipt["command"]["source_sha256"] = "9" * 64
    elif damage == "source":
        receipt["source"]["memveil"]["commit"] = "9" * 40
    elif damage == "toolchain":
        receipt["toolchain"]["lock_sha256"] = "9" * 64
    elif damage == "entry":
        # A predicate-neutral lock field: the oracle verdicts
        # re-derive identically, only the pinned-entry binding
        # can refuse.
        assert ev["entry"]["upstream"] != "9.9.99"
        ev["entry"]["upstream"] = "9.9.99"
        cached_path.write_text(json.dumps(ev))
        receipt["files"] = km.row_receipt_files(row)
    else:
        assert ev["candidate_files"]["bin/memveil"] != "9" * 64
        ev["candidate_files"]["bin/memveil"] = "9" * 64
        cached_path.write_text(json.dumps(ev))
        receipt["files"] = km.row_receipt_files(row)
    receipt_path.write_bytes(m.canonical(receipt))
    _resign_matrix_inputs(m, ctx, evidence, q_path)
    with pytest.raises(ValueError, match=blame):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence,
                               source_tree=str(ctx["root"]))


@pytest.mark.parametrize("damage", ["bad-schema", "missing-schema"])
def test_qualify_refuses_malformed_lock_schema(workshop,
                                               tmp_path, damage):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    # The attack: C carries a lock whose schema field is
    # damaged but whose JSON stays valid and whose row set
    # stays intact, so a row-set-only check would accept it.
    lock_path = root / "tests" / "vm" / "kernels.lock.json"
    lock = json.loads(lock_path.read_bytes())
    if damage == "bad-schema":
        lock["schema"] = "bogus-schema/9"
    else:
        del lock["schema"]
    assert [entry["id"] for entry in lock["kernels"]] == \
        [MATRIX_ROW]
    lock_path.write_bytes(m.canonical(lock))
    git(root, "add", "tests/vm/kernels.lock.json")
    git(root, "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", "Fixture C with damaged lock schema")
    commit = git(root, "rev-parse", "HEAD")
    _entries, inventory = m.git_inventory(root, commit)
    # Rebind every C-pinned byte to the damaged commit: the
    # seal pins bytes, not lock grammar, so it must still
    # accept and only the shared grammar validation refuses.
    staged = json.loads(
        (fix["bundle_dir"] / "MANIFEST.json").read_text())
    staged["memveil_revision"] = commit
    staged["build_receipt"]["source_commit"] = commit
    staged["build_receipt"]["inventory_sha256"] = inventory
    (fix["bundle_dir"] / "MANIFEST.json").write_text(
        json.dumps(staged, indent=2, sort_keys=True) + "\n")
    bundle_tar = next(fix["artifacts"].glob(
        "memveil-fixture.tar.gz"))
    bundle_tar.unlink()
    deterministic_tar_gz(fix["bundle_dir"], "memveil-fixture",
                         bundle_tar)
    proc = subprocess.run(
        ["git", "-C", str(root), "archive", "HEAD"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=True)
    source_tar = next(fix["artifacts"].glob("*source.tar.gz"))
    source_tar.write_bytes(gzip.compress(proc.stdout, mtime=0))
    sbom_path = next(fix["artifacts"].glob("*.spdx.json"))
    sbom_path.unlink()
    proc = subprocess.run(
        _sbom_emit_argv(workshop, fix, sbom_path),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True)
    assert proc.returncode == 0, proc.stderr
    provenance_path = next(fix["artifacts"].glob(
        "*.provenance.json"))
    provenance_path.unlink()
    m.emit_provenance(fix["bundle_dir"], _emit_source_info(fix),
                      provenance_path)
    # Seal and qualify honestly over the damaged C: the
    # shared full-grammar validation must refuse.
    private, public = _ephemeral_key(Path(tmp_path) / "key")
    policy_path = Path(tmp_path) / "policy.json"
    _write_policy(m, policy_path, _matrix_required_gates(),
                  [sha(public.read_bytes())])
    manifest = m.create_manifest(
        fix["bundle_dir"], fix["artifacts"], policy_path,
        {"root": str(fix["root"]),
         "harness_bin": workshop.harness_bin()})
    manifest_path = Path(tmp_path) / "candidate.json"
    candidate_id = m.seal_manifest(manifest, manifest_path)
    ctx = {"manifest": manifest, "candidate_id": candidate_id,
           "key": private, "pub": public}
    evidence = Path(tmp_path) / "evidence"
    evidence.mkdir()
    _write_matrix_evidence(m, ctx, evidence)
    binding = _signed_gate(m, ctx, evidence, MATRIX_GATE,
                           "inputs.json", "receipt.json",
                           _matrix_inputs(m, evidence))
    q_path = Path(tmp_path) / "qualification.json"
    _write_qualification(m, ctx, q_path,
                         {MATRIX_GATE: binding})
    with pytest.raises(ValueError, match="bad schema"):
        m.verify_qualification(manifest_path, q_path,
                               policy_path, evidence,
                               source_tree=str(root))


def _nonmatrix_required_gates():
    return {NONMATRIX_GATE:
            {"environment": "offline",
             "predicates": {"events": "equal",
                            "losses": "zero"}}}


def _write_nonmatrix_evidence(m, ctx, evidence):
    """Golden non-matrix gate: fixed counts over retained raws."""
    evidence = Path(evidence)
    evidence.mkdir(exist_ok=True)
    inputs = {"schema": "memveil-gate-input/1",
              "environment": "offline",
              "product": {"events": "12", "losses": "0"},
              "oracle": {"events": "12", "losses": "0"}}
    inputs["sources"] = {}
    for side in ("product", "oracle"):
        raw = evidence / (side + ".json")
        raw.write_bytes(m.canonical(inputs[side]))
        inputs["sources"][side] = {
            name: {"file": raw.name,
                   "sha256": sha(raw.read_bytes()),
                   "path": [name], "encoding": "u64"}
            for name in inputs[side]}
    binding = _signed_gate(m, ctx, evidence, NONMATRIX_GATE,
                           "input.json", "receipt.json",
                           inputs)
    return binding


def test_nonmatrix_gate_chain_unchanged(workshop, tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _nonmatrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    binding = _write_nonmatrix_evidence(m, ctx, evidence)
    q_path = Path(tmp_path) / "qualification.json"
    _write_qualification(m, ctx, q_path,
                         {NONMATRIX_GATE: binding})
    expected = {"ok": True, "gates": [NONMATRIX_GATE],
                "trusted_keys": [sha(ctx["pub"].read_bytes())],
                "claim": "ordinary-preview"}
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"])) == expected
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"])) == expected


def _write_signed_checksums(m, ctx, evidence):
    """Signed SHA256SUMS over the sealed artifacts in evidence."""
    evidence = Path(evidence)
    text = "".join(entry["sha256"] + "  " + entry["name"]
                   + "\n" for entry in sorted(
                       ctx["manifest"]["artifacts"],
                       key=lambda entry: entry["name"]))
    (evidence / "SHA256SUMS.txt").write_text(text)
    _sign(ctx["key"], evidence / "SHA256SUMS.txt")


def test_qualify_cli_rederives_signed_gates(workshop,
                                            tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _nonmatrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    binding = _write_nonmatrix_evidence(m, ctx, evidence)
    q_path = Path(tmp_path) / "qualification.json"
    _write_qualification(m, ctx, q_path,
                         {NONMATRIX_GATE: binding})
    _write_signed_checksums(m, ctx, evidence)
    argv = [str(ROOT / "tools" / "candidate"), "qualify",
           "--manifest", str(ctx["manifest_path"]),
           "--qualification", str(q_path),
           "--policy", str(ctx["policy_path"]),
           "--evidence-dir", str(evidence),
           "--source-tree", str(ctx["root"])]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "re-derived" in proc.stdout
    (evidence / "product.json").write_bytes(b'{"x": 1}\n')
    rerun = subprocess.run(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
    assert rerun.returncode == 1
    assert rerun.stderr.strip(), "silent qualify failure"


def test_qualify_cli_evaluates_matrix_rows(workshop,
                                           tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    _write_signed_checksums(m, ctx, evidence)
    argv = [str(ROOT / "tools" / "candidate"), "qualify",
           "--manifest", str(ctx["manifest_path"]),
           "--qualification", str(q_path),
           "--policy", str(ctx["policy_path"]),
           "--evidence-dir", str(evidence),
           "--source-tree", str(ctx["root"])]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "re-derived" in proc.stdout
    # Without the source tree the lock cannot load, so the
    # same evidence refuses instead of skipping predicates.
    bare = [entry for entry in argv
            if entry != "--source-tree"
            and entry != str(ctx["root"])]
    rerun = subprocess.run(bare, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True,
                           cwd=str(tmp_path))
    assert rerun.returncode == 1
    assert rerun.stderr.strip(), "silent qualify failure"


def test_verify_q_diff_accepts_evidence_only(workshop, tmp_path,
                                             monkeypatch):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    (root / "packaging" / "qualifications").mkdir(
        parents=True)
    (root / "packaging" / "qualifications"
     / "candidate.json").write_text("{}\n")
    (root / "packaging" / "tested-payload.sha256").write_text(
        "0" * 64 + "  bundle/LICENSE\n")
    first = _commit_as(root, "Q evidence",
                       "packaging/qualifications/candidate.json",
                       "packaging/tested-payload.sha256")
    (root / "packaging" / "qualifications"
     / "remote.json").write_text("{}\n")
    second = _commit_as(root, "Q remote checks",
                        "packaging/qualifications/remote.json")
    monkeypatch.chdir(root)
    assert m.verify_q_diff(commit, first) is None
    assert m.verify_q_diff(commit, second) is None
    assert m.verify_q_diff(commit, commit) is None


def _commit_as(root, message, *paths):
    git(root, "add", *paths)
    git(root, "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid",
        "commit", "-qm", message)
    return git(root, "rev-parse", "HEAD")


def test_verify_q_diff_rejects_non_evidence(workshop, tmp_path,
                                            monkeypatch):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    (root / "src" / "evil.txt").write_text("source edit\n")
    bad = _commit_as(root, "Q source edit", "src/evil.txt")
    monkeypatch.chdir(root)
    with pytest.raises(ValueError, match="evidence-only"):
        m.verify_q_diff(commit, bad)
    with pytest.raises(ValueError):
        m.verify_q_diff(bad, commit)
    # A merge of two evidence-only sides still fails, in a fresh
    # checkout whose history holds no other violation.
    other = workshop.fresh(tmp_path / "merge")["root"]
    base = git(other, "rev-parse", "HEAD")
    branch = git(other, "rev-parse", "--abbrev-ref", "HEAD")
    (other / "packaging" / "qualifications").mkdir(
        parents=True)
    (other / "packaging" / "qualifications"
     / "side.json").write_text("{}\n")
    git(other, "checkout", "-qb", "side")
    _commit_as(other, "Q side evidence",
               "packaging/qualifications/side.json")
    git(other, "checkout", "-q", branch)
    (other / "packaging" / "qualifications").mkdir(
        parents=True, exist_ok=True)
    (other / "packaging" / "qualifications"
     / "main.json").write_text("{}\n")
    _commit_as(other, "Q main evidence",
               "packaging/qualifications/main.json")
    git(other, "-c", "user.name=Fixture",
        "-c", "user.email=fixture@example.invalid",
        "merge", "--no-ff", "-q", "side", "-m", "Q merge")
    merged = git(other, "rev-parse", "HEAD")
    monkeypatch.chdir(other)
    with pytest.raises(ValueError, match="merge"):
        m.verify_q_diff(base, merged)


def test_verify_q_diff_rejects_source_to_evidence_rename(
        workshop, tmp_path, monkeypatch):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    (root / "packaging" / "qualifications").mkdir(
        parents=True)
    # A rename out of the source tree reads as one evidence
    # path under rename detection; the deleted source side
    # must still fail the evidence-only rule.
    git(root, "mv", "src/engine.txt",
        "packaging/qualifications/renamed.json")
    renamed = _commit_as(
        root, "Q rename",
        "packaging/qualifications/renamed.json")
    monkeypatch.chdir(root)
    with pytest.raises(ValueError, match="evidence-only"):
        m.verify_q_diff(commit, renamed)


def _q_bound_repo(workshop, tmp_path):
    """Source repo at C with an evidence-only Q child on top."""
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    (root / "packaging" / "qualifications").mkdir(
        parents=True)
    (root / "packaging" / "qualifications"
     / "candidate.json").write_text("{}\n")
    first = _commit_as(
        root, "Q evidence",
        "packaging/qualifications/candidate.json")
    return m, root, commit, first


def test_verify_q_bound_accepts_honest_triple(workshop,
                                              tmp_path):
    m, root, commit, first = _q_bound_repo(workshop,
                                           tmp_path)
    manifest = {"source": {"commit": commit}}
    assert m.verify_q_bound(manifest, commit, first,
                            str(root)) is None


def test_verify_q_bound_refuses_wrong_c(workshop, tmp_path):
    m, root, commit, first = _q_bound_repo(workshop,
                                           tmp_path)
    manifest = {"source": {"commit": "1" * 40}}
    assert manifest["source"]["commit"] != commit
    with pytest.raises(ValueError, match="dispatched"):
        m.verify_q_bound(manifest, commit, first,
                         str(root))
    with pytest.raises(ValueError, match="dispatched"):
        m.verify_q_bound({}, commit, first, str(root))


def test_verify_q_bound_refuses_non_evidence_q(workshop,
                                               tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    root = fix["root"]
    commit = git(root, "rev-parse", "HEAD")
    (root / "src" / "evil.txt").write_text("source edit\n")
    bad = _commit_as(root, "Q source edit", "src/evil.txt")
    manifest = {"source": {"commit": commit}}
    with pytest.raises(ValueError, match="evidence-only"):
        m.verify_q_bound(manifest, commit, bad, str(root))


def test_tested_payload_matches_candidate_closure(workshop,
                                                  tmp_path):
    m, manifest = sealed_manifest(workshop, tmp_path)
    expected = m.expected_payload(manifest)
    path = Path(tmp_path) / "tested.txt"
    path.write_text("".join(
        value + "  " + name + "\n"
        for name, value in sorted(expected.items())))
    assert m.verify_tested_payload(manifest, path) == expected
    entries = dict(expected)
    entries.pop("bundle/LICENSE")
    path.write_text("".join(
        value + "  " + name + "\n"
        for name, value in sorted(entries.items())))
    with pytest.raises(ValueError):
        m.verify_tested_payload(manifest, path)
    path.write_text("bogus line\n")
    with pytest.raises(ValueError):
        m.verify_tested_payload(manifest, path)


def test_qualify_candidate_exports_tested_payload(workshop,
                                                  tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _nonmatrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    binding = _write_nonmatrix_evidence(m, ctx, evidence)
    _write_signed_checksums(m, ctx, evidence)
    archive = Path(tmp_path) / "evidence.tar.gz"
    assert m.build_evidence_archive(evidence, archive) == []
    root = ctx["root"]
    qualifications = root / "packaging" / "qualifications"
    qualifications.mkdir(parents=True)
    q_repo = qualifications / "qualification.json"
    doc = _write_qualification(m, ctx, q_repo,
                               {NONMATRIX_GATE: binding})
    doc["evidence_archive"] = {
        "name": archive.name, "size": str(archive.stat()
                                          .st_size),
        "sha256": sha(archive.read_bytes())}
    q_repo.write_bytes(m.canonical(doc))
    expected = m.expected_payload(ctx["manifest"])
    rendered = "".join(value + "  " + name + "\n"
                       for name, value in sorted(
                           expected.items()))
    (root / "packaging" / "tested-payload.sha256").write_text(
        rendered)
    _commit_as(root, "Q evidence",
               "packaging/qualifications",
               "packaging/tested-payload.sha256")
    out = Path(tmp_path) / "tested.txt"
    assert m.qualify_candidate(
        str(root), ctx["manifest_path"], q_repo,
        ctx["policy_path"], archive, out) == expected
    assert out.read_bytes() == (
        root / "packaging" / "tested-payload.sha256"
    ).read_bytes()
    # A staged rename out of the source tree reads as one
    # evidence path under rename detection; the worktree
    # check must still see the moved source side.
    git(root, "mv", "src/engine.txt",
        "packaging/qualifications/staged.json")
    with pytest.raises(ValueError, match="non-evidence"):
        m.qualify_candidate(
            str(root), ctx["manifest_path"], q_repo,
            ctx["policy_path"], archive,
            Path(tmp_path) / "tested-renamed.txt")
    git(root, "mv", "packaging/qualifications/staged.json",
        "src/engine.txt")
    (root / "src" / "dirty.txt").write_text("dirty\n")
    with pytest.raises(ValueError, match="non-evidence"):
        m.qualify_candidate(
            str(root), ctx["manifest_path"], q_repo,
            ctx["policy_path"], archive,
            Path(tmp_path) / "tested-dirty.txt")


def test_seal_cross_checks_bpf_linker(workshop, tmp_path):
    m, fix = seal_paths(workshop, tmp_path)
    manifest_path = fix["bundle_dir"] / "MANIFEST.json"
    # A recorded bpf-linker that disagrees with the probed
    # toolchain fails even when every other record is honest.
    doc = json.loads(manifest_path.read_text())
    assert doc["build_receipt"]["tools"]["bpf_linker"] != "9.9.9"
    doc["build_receipt"]["tools"]["bpf_linker"] = "9.9.9"
    manifest_path.write_text(json.dumps(doc, indent=2, sort_keys=True))
    rebuild_bundle_tarball(fix)
    with pytest.raises(ValueError, match="[Rr]ecorded|[Bb]pf"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})
    # The same holds when the provenance receipt is forged to
    # match the recorded lie: the probed toolchain still differs.
    rewrite_provenance(
        m, fix,
        lambda doc: doc["build_receipt"]["tools"].update(
            {"bpf_linker": "9.9.9"}))
    with pytest.raises(ValueError, match="[Rr]ecorded|[Bb]pf"):
        m.create_manifest(
            fix["bundle_dir"], fix["artifacts"], fix["policy"],
            {"root": str(fix["root"]),
             "harness_bin": workshop.harness_bin()})


def _sign_checksums_fixture(tmp_path):
    """Three fixed artifacts (created out of order) plus a key."""
    staged = Path(tmp_path) / "staged"
    staged.mkdir()
    bodies = {"b.dat": b"b-body\n", "a.dat": b"a-body\n",
              "c.dat": b"c-body\n"}
    for name, body in bodies.items():
        (staged / name).write_bytes(body)
    private, public = _ephemeral_key(Path(tmp_path) / "key")
    return staged, private, public


def test_sign_checksums_golden_content(tmp_path):
    m = api()
    staged, private, public = _sign_checksums_fixture(tmp_path)
    out = Path(tmp_path) / "signed"
    argv = [str(ROOT / "tools" / "candidate"), "sign-checksums",
           "--artifacts-dir", str(staged),
           "--key", str(private),
           "--out-dir", str(out)]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    names = sorted(path.name for path in staged.iterdir())
    golden = "".join(
        sha((staged / name).read_bytes()) + "  " + name + "\n"
        for name in names)
    sums = out / "SHA256SUMS.txt"
    assert sums.read_text() == golden
    assert proc.stdout.strip() == sha(sums.read_bytes())
    derived = subprocess.run(
        ["ssh-keygen", "-y", "-f", str(private)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True).stdout.strip()
    assert derived.startswith("ssh-ed25519 ")
    assert (out / "signer.pub").read_bytes() == \
        (derived + "\n").encode()
    trusted = [sha((out / "signer.pub").read_bytes())]
    assert m.verify_signature(
        sums, out / "SHA256SUMS.txt.sig",
        out / "signer.pub", trusted) is None
    assert m.verify_artifact_checksums(staged, sums) == golden
    rerun = subprocess.run(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
    assert rerun.returncode == 1
    assert rerun.stderr.strip(), "silent sign-checksums failure"


def test_sign_checksums_tampered_artifact_refuses_to_verify(
        tmp_path):
    m = api()
    staged, private, public = _sign_checksums_fixture(tmp_path)
    out = Path(tmp_path) / "signed"
    assert m.sign_checksums(staged, private, out) == sha(
        (out / "SHA256SUMS.txt").read_bytes())
    m.verify_artifact_checksums(staged, out / "SHA256SUMS.txt")
    target = staged / "b.dat"
    with open(target, "ab") as stream:
        stream.write(b"tampered")
    with pytest.raises(ValueError, match="differ"):
        m.verify_artifact_checksums(
            staged, out / "SHA256SUMS.txt")
    # The signed bytes themselves still verify standalone:
    # only the re-derived binding catches the substitution.
    m.verify_signature(out / "SHA256SUMS.txt",
                       out / "SHA256SUMS.txt.sig",
                       out / "signer.pub",
                       [sha((out / "signer.pub")
                            .read_bytes())])


def test_sign_checksums_cleans_partial_signature_on_failure(
        tmp_path, monkeypatch):
    m = api()
    staged, private, public = _sign_checksums_fixture(tmp_path)
    out = Path(tmp_path) / "signed"
    real_run = subprocess.run

    def failing_sign(argv, **kw):
        if argv[:3] == ["ssh-keygen", "-Y", "sign"]:
            # The signer wrote a partial .sig, then failed.
            Path(str(argv[-1]) + ".sig").write_bytes(
                b"partial\n")
            return subprocess.CompletedProcess(
                argv, 1, "", "boom")
        return real_run(argv, **kw)

    monkeypatch.setattr(m.subprocess, "run", failing_sign)
    with pytest.raises(ValueError, match="signing failed"):
        m.sign_checksums(staged, private, out)
    assert list(out.iterdir()) == [], \
        "failed sign must leave no partial triple"


# Authoring CLIs: gate receipts, qualifications, remote custody.
#
# The verify side (qualify, custody promote) re-derives every gate
# from retained evidence; these CLIs author the signed records an
# honest qualifier writes after running the gates. Tests use
# ephemeral ssh-keygen keys and synthetic seals only.


def _write_gate_inputs(m, evidence, inputs_name, counts=None):
    """Gate inputs plus retained raw bindings over evidence raws."""
    evidence = Path(evidence)
    evidence.mkdir(exist_ok=True)
    counts = {"events": "12", "losses": "0"} \
        if counts is None else dict(counts)
    inputs = {"schema": "memveil-gate-input/1",
              "environment": "offline",
              "product": dict(counts), "oracle": dict(counts)}
    inputs["sources"] = {}
    for side in ("product", "oracle"):
        raw = evidence / (side + ".json")
        raw.write_bytes(m.canonical(inputs[side]))
        inputs["sources"][side] = {
            name: {"file": raw.name,
                   "sha256": sha(raw.read_bytes()),
                   "path": [name], "encoding": "u64"}
            for name in inputs[side]}
    path = evidence / inputs_name
    path.write_bytes(m.canonical(inputs))
    return path


def _two_gate_policy():
    req = {"environment": "offline",
           "predicates": {"events": "equal", "losses": "zero"}}
    return {"synthetic-counts/1": copy.deepcopy(req),
            "synthetic-counts/2": copy.deepcopy(req)}


def _receipt_cli(ctx, gate, inputs_path, out_path):
    return [str(ROOT / "tools" / "candidate"),
            "write-gate-receipt",
            "--gate", gate,
            "--candidate", str(ctx["manifest_path"]),
            "--inputs", str(inputs_path),
            "--key", str(ctx["key"]),
            "--out", str(out_path)]


def _run_cli(argv):
    return subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)


def test_write_gate_receipt_roundtrip(workshop, tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _nonmatrix_required_gates())
    staged = Path(tmp_path) / "staged"
    inputs_path = _write_gate_inputs(m, staged, "inputs.json")
    out = Path(tmp_path) / "receipt.json"
    proc = _run_cli(_receipt_cli(ctx, NONMATRIX_GATE,
                                 inputs_path, out))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha(out.read_bytes())
    record = m.read_json(out, sealed=True)
    assert record == {
        "schema": "memveil-gate-receipt/1", "gate": NONMATRIX_GATE,
        "candidate_sha256": ctx["candidate_id"],
        "source_commit": ctx["manifest"]["source"]["commit"],
        "inputs": "inputs.json",
        "inputs_sha256": sha(inputs_path.read_bytes())}
    sig = Path(str(out) + ".sig")
    pub = out.parent / "signer.pub"
    assert sig.is_file() and pub.is_file()
    assert pub.read_bytes() == ctx["pub"].read_bytes()
    trusted = [sha(pub.read_bytes())]
    m.verify_signature(out, sig, pub, trusted)
    tampered = bytearray(out.read_bytes())
    tampered[-20] ^= 1
    out.write_bytes(bytes(tampered))
    with pytest.raises(ValueError):
        m.verify_signature(out, sig, pub, trusted)
    # The receipt binds the inputs bytes: re-emitting over
    # changed inputs records a different digest.
    _write_gate_inputs(m, staged, "inputs.json",
                       {"events": "13", "losses": "0"})
    out2 = Path(tmp_path) / "receipt2.json"
    proc = _run_cli(_receipt_cli(ctx, NONMATRIX_GATE,
                                 inputs_path, out2))
    assert proc.returncode == 0, proc.stderr
    assert m.read_json(out2, sealed=True)["inputs_sha256"] \
        != record["inputs_sha256"]


def _qualification_cli(ctx, gates, evidence, out_path):
    return [str(ROOT / "tools" / "candidate"),
            "write-qualification",
            "--manifest", str(ctx["manifest_path"]),
            "--policy", str(ctx["policy_path"]),
            "--gates", *[str(gate) for gate in gates],
            "--evidence-dir", str(evidence),
            "--out", str(out_path)]


def test_write_qualification_refuses_inconsistent(workshop,
                                                  tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _two_gate_policy())
    evidence = Path(tmp_path) / "evidence"
    inputs1 = _write_gate_inputs(m, evidence, "inputs-1.json")
    inputs2 = _write_gate_inputs(m, evidence, "inputs-2.json")
    first = evidence / "receipt-1.json"
    second = evidence / "receipt-2.json"
    for gate, inputs_path, out in (
            ("synthetic-counts/1", inputs1, first),
            ("synthetic-counts/2", inputs2, second)):
        proc = _run_cli(_receipt_cli(ctx, gate, inputs_path,
                                     out))
        assert proc.returncode == 0, proc.stderr
    # Positive control: the exact set assembles, binds the
    # packed archive beside the qualification, and re-derives
    # through the real verifier.
    q_path = Path(tmp_path) / "qualification.json"
    proc = _run_cli(_qualification_cli(
        ctx, [first, second], evidence, q_path))
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha(q_path.read_bytes())
    doc = m.read_json(q_path, sealed=True)
    assert set(doc["gates"]) == {"synthetic-counts/1",
                                 "synthetic-counts/2"}
    archive = Path(tmp_path) / "qualification-evidence.tar.gz"
    assert archive.is_file()
    assert doc["evidence_archive"] == {
        "name": "qualification-evidence.tar.gz",
        "size": str(archive.stat().st_size),
        "sha256": sha(archive.read_bytes())}
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"])) == {
            "ok": True,
            "gates": ["synthetic-counts/1",
                      "synthetic-counts/2"],
            "trusted_keys": [sha(ctx["pub"].read_bytes())],
            "claim": "ordinary-preview"}
    refusals = []
    # Unknown gate: honestly signed but outside the policy.
    ninth = evidence / "receipt-9.json"
    proc = _run_cli(_receipt_cli(ctx, "synthetic-counts/9",
                                 inputs1, ninth))
    assert proc.returncode == 0, proc.stderr
    refusals.append([first, second, ninth])
    refusals.append([first])
    refusals.append([first, first])
    for rank, gates in enumerate(refusals):
        proc = _run_cli(_qualification_cli(
            ctx, gates, evidence,
            Path(tmp_path) / ("q-%d.json" % rank)))
        assert proc.returncode == 1, gates
        assert proc.stderr.strip(), \
            "silent qualification refusal: %r" % (gates,)
    # Corrupted signature over an otherwise honest receipt.
    forged = evidence / "receipt-forged.json"
    forged_sig = Path(str(forged) + ".sig")
    shutil.copy2(first, forged)
    shutil.copy2(str(first) + ".sig", forged_sig)
    damaged = bytearray(forged_sig.read_bytes())
    damaged[-20] ^= 1
    forged_sig.write_bytes(bytes(damaged))
    proc = _run_cli(_qualification_cli(
        ctx, [forged, second], evidence,
        Path(tmp_path) / "q-forged.json"))
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent signature refusal"
    # The qualification lives beside the evidence, never in it.
    proc = _run_cli(_qualification_cli(
        ctx, [first, second], evidence,
        evidence / "qualification.json"))
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent nesting refusal"
    # Inputs rewritten after signing no longer match the receipt.
    _write_gate_inputs(m, evidence, "inputs-1.json",
                       {"events": "13", "losses": "0"})
    proc = _run_cli(_qualification_cli(
        ctx, [first, second], evidence,
        Path(tmp_path) / "q-drifted.json"))
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent drift refusal"


def test_write_qualification_assembles_matrix_gate(workshop,
                                                   tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _matrix_required_gates())
    evidence = Path(tmp_path) / "evidence"
    evidence.mkdir()
    _write_matrix_evidence(m, ctx, evidence)
    inputs_path = evidence / "inputs.json"
    inputs_path.write_bytes(
        m.canonical(_matrix_inputs(m, evidence)))
    receipt_path = evidence / "receipt.json"
    proc = _run_cli(_receipt_cli(ctx, MATRIX_GATE, inputs_path,
                                 receipt_path))
    assert proc.returncode == 0, proc.stderr
    q_path = Path(tmp_path) / "qualification.json"
    proc = _run_cli(_qualification_cli(
        ctx, [receipt_path], evidence, q_path))
    assert proc.returncode == 0, proc.stderr
    qualified = m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence, source_tree=str(ctx["root"]))
    assert qualified == {
        "ok": True, "gates": [MATRIX_GATE],
        "trusted_keys": [sha(ctx["pub"].read_bytes())],
        "claim": "ordinary-preview"}


class _DraftApi:
    """Minimal holding-draft stub serving the sealed bytes."""

    def __init__(self, repo, release_id, tag, artifacts,
                 manifest):
        self.repo = repo
        self.release_id = release_id
        self.tag = tag
        self.blobs = {}
        self.records = []
        self.asset_ids = {}
        entries = sorted(manifest["artifacts"],
                         key=lambda entry: entry["name"])
        for rank, entry in enumerate(entries, 101):
            ident = str(rank)
            self.blobs[ident] = artifacts / entry["name"]
            self.asset_ids[entry["name"]] = ident
            self.records.append({
                "name": entry["name"], "id": rank,
                "url": "https://api.github.com/repos/" + repo
                + "/releases/assets/" + ident,
                "state": "uploaded",
                "size": int(entry["size"]),
                "digest": "sha256:" + entry["sha256"]})

    def json(self, path):
        assert path == "repos/%s/releases/%s" % (
            self.repo, self.release_id), path
        return {"id": int(self.release_id), "draft": True,
                "tag_name": self.tag,
                "assets": [dict(record)
                           for record in self.records]}

    def download(self, path, destination):
        ident = path.rsplit("/", 1)[1]
        Path(destination).write_bytes(
            self.blobs[ident].read_bytes())


def _import_custody(ctx, tmp_path):
    """Honest import record via the real import_assets flow."""
    m = api()
    repo = "example/project"
    draft = _DraftApi(repo, "1", "candidate-fixture",
                      ctx["artifacts"], ctx["manifest"])
    custody = cc.import_assets(
        draft, repo, "1", draft.asset_ids, ctx["manifest"],
        Path(tmp_path) / "stored")
    path = Path(tmp_path) / "custody.json"
    path.write_bytes(m.canonical(custody))
    return path, custody


def _check_binding(ctx, workdir, rank, ident, measurement,
                   head, candidate_override=None):
    """One signed remote-gate binding over offline counts."""
    m = api()
    counts = {measurement: "2", "failures": "0"}
    inputs = {"schema": "memveil-gate-input/1",
              "environment": "offline",
              "product": dict(counts), "oracle": dict(counts)}
    receipt = {"schema": "memveil-remote-gate/1",
               "gate": ident,
               "candidate_sha256": ctx["candidate_id"],
               "source_commit":
               ctx["manifest"]["source"]["commit"],
               "inputs_sha256": sha(m.canonical(inputs))}
    if candidate_override is not None:
        receipt["candidate_sha256"] = candidate_override
    subject = Path(workdir) / ("remote-%d.receipt" % rank)
    subject.write_bytes(m.canonical(receipt))
    sig = _sign(ctx["key"], subject)
    binding = {
        "check_id": str(rank), "run_id": "9",
        "head_sha": head, "receipt": receipt,
        "inputs": inputs,
        "signature_base64": base64.b64encode(
            sig.read_bytes()).decode(),
        "public_key": ctx["pub"].read_text()}
    subject.unlink()
    sig.unlink()
    return binding


def _write_check_file(m, path, envelope, binding):
    doc = {"schema": "memveil-remote-check/1",
           "import_run": dict(envelope), "check": binding}
    Path(path).write_bytes(m.canonical(doc))
    return doc


def test_write_remote_binds_import(workshop, tmp_path):
    m, ctx = _sealed_for_qualify(
        workshop, tmp_path, _nonmatrix_required_gates())
    custody_path, _ = _import_custody(ctx, tmp_path)
    head = ctx["manifest"]["source"]["commit"]
    envelope = {"repository_id": "9", "run_id": "8",
                "artifact_id": "7",
                "artifact_sha256": sha(b"fixture-stored-zip"),
                "signer_commit": head}
    workdir = Path(tmp_path) / "checks-work"
    workdir.mkdir()
    paths = []
    for rank, (ident, measurement) in enumerate(
            sorted(cc.REMOTE_CHECKS.items()), 1):
        binding = _check_binding(ctx, workdir, rank, ident,
                                 measurement, head)
        path = Path(tmp_path) / ("check-%d.json" % rank)
        _write_check_file(m, path, envelope, binding)
        paths.append(path)
    out = Path(tmp_path) / "remote.json"
    proc = _run_cli(
        [str(ROOT / "tools" / "candidate"), "write-remote",
         "--import", str(custody_path),
         "--checks", *[str(path) for path in paths],
         "--out", str(out)])
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == sha(out.read_bytes())
    doc = m.read_json(out, sealed=True)
    assert doc["schema"] == "memveil-remote-custody/1"
    assert doc["candidate_sha256"] == ctx["candidate_id"]
    assert doc["source_commit"] == head
    assert doc["repository"] == "example/project"
    assert doc["repository_id"] == "9"
    assert doc["run_id"] == "8"
    assert doc["artifact_id"] == "7"
    assert doc["artifact_sha256"] == envelope["artifact_sha256"]
    assert doc["signer_commit"] == head
    assert doc["custody_sha256"] == sha(
        custody_path.read_bytes())
    assert set(doc["checks"]) == set(cc.REMOTE_CHECKS)
    assert doc["checks"]["no-overwrite/1"]["inputs"] == {
        "schema": "memveil-gate-input/1",
        "environment": "offline",
        "product": {"preserved_assets": "2", "failures": "0"},
        "oracle": {"preserved_assets": "2", "failures": "0"}}
    # Wrong candidate in one receipt: the signature is valid
    # over those bytes, so only the import binding refuses.
    stray = _check_binding(
        ctx, workdir, 1, "independent-attestation/1",
        cc.REMOTE_CHECKS["independent-attestation/1"], head,
        candidate_override="f" * 64)
    stray_path = Path(tmp_path) / "check-stray.json"
    _write_check_file(m, stray_path, envelope, stray)
    proc = _run_cli(
        [str(ROOT / "tools" / "candidate"), "write-remote",
         "--import", str(custody_path), "--checks",
         str(stray_path), *[str(path) for path in paths[1:]],
         "--out", str(Path(tmp_path) / "remote-stray.json")])
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent import-binding refusal"
    # Disagreeing import-run envelope across the check files.
    other = dict(envelope, artifact_sha256="e" * 64)
    forked = Path(tmp_path) / "check-forked.json"
    _write_check_file(
        m, forked, other, _check_binding(
            ctx, workdir, 2, "no-overwrite/1",
            cc.REMOTE_CHECKS["no-overwrite/1"], head))
    proc = _run_cli(
        [str(ROOT / "tools" / "candidate"), "write-remote",
         "--import", str(custody_path), "--checks",
         str(paths[0]), str(forked),
         *[str(path) for path in paths[2:]],
         "--out", str(Path(tmp_path) / "remote-forked.json")])
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent envelope refusal"
    # An incomplete check set assembles nothing.
    proc = _run_cli(
        [str(ROOT / "tools" / "candidate"), "write-remote",
         "--import", str(custody_path), "--checks",
         *[str(path) for path in paths[:4]],
         "--out", str(Path(tmp_path) / "remote-short.json")])
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent incomplete refusal"
    # A foreign public key breaks the check signature.
    _, foreign = _ephemeral_key(Path(tmp_path) / "foreign")
    tampered = _check_binding(
        ctx, workdir, 3, "promotion-dry-run/1",
        cc.REMOTE_CHECKS["promotion-dry-run/1"], head)
    tampered["public_key"] = foreign.read_text()
    tampered_path = Path(tmp_path) / "check-tampered.json"
    _write_check_file(m, tampered_path, envelope, tampered)
    proc = _run_cli(
        [str(ROOT / "tools" / "candidate"), "write-remote",
         "--import", str(custody_path), "--checks",
         *[str(path) for path in paths[:2]],
         str(tampered_path),
         *[str(path) for path in paths[3:]],
         "--out", str(Path(tmp_path) / "remote-tampered.json")])
    assert proc.returncode == 1
    assert proc.stderr.strip(), "silent signature refusal"


def test_remote_checks_mirror_custody():
    m = api()
    assert m.REMOTE_CHECKS == cc.REMOTE_CHECKS


CI_SELECTION = ROOT / "tests" / "pytest-ci-selection.json"
CI_SELECTION_SCHEMA = "memveil-pytest-ci-selection/1"
# MEMVEIL_* names that never arm privileged behavior: evidence
# paths, measurement parameters, and harness controls. Every
# other MEMVEIL_* name fails the CI unarmed guard closed as
# potentially arming, including future unknown names.
CI_UNARMED_ALLOW_EXACT = frozenset({
    "MEMVEIL_EVIDENCE_DIR", "MEMVEIL_OWNED_EVIDENCE",
    "MEMVEIL_ORACLE_KVER", "MEMVEIL_SOAK_MINUTES",
    "MEMVEIL_PACED_SECONDS", "MEMVEIL_PACED_FILE",
    "MEMVEIL_PACED_RECEIPT", "MEMVEIL_PACED_LINES",
    "MEMVEIL_PACED_NS", "MEMVEIL_FUZZ_SEEDS", "MEMVEIL_SIGBLK"})
CI_UNARMED_ALLOW_PREFIXES = ("MEMVEIL_TEST_",)


def _ci_selection():
    return json.loads(CI_SELECTION.read_text())


def _rust_workflow():
    import yaml
    path = ROOT / ".github" / "workflows" / "rust.yml"
    return yaml.safe_load(path.read_text())


def test_ci_selection_audited():
    sel = _ci_selection()
    assert set(sel) == {"schema", "run", "exclude",
                        "unarmed_allow_env"}
    assert sel["schema"] == CI_SELECTION_SCHEMA
    run = sel["run"]
    assert run == sorted(set(run)), \
        "run list must be sorted unique"
    exclude = sel["exclude"]
    assert isinstance(exclude, dict) and exclude
    assert list(exclude) == sorted(exclude), \
        "exclude map must be sorted"
    for path, reason in exclude.items():
        assert isinstance(reason, str) and reason.strip(), \
            path
    assert not (set(run) & set(exclude)), "listed twice"
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = sorted(
            name for name in dirnames
            if name not in (".git", ".pixi", "target",
                            "__pycache__", "node_modules",
                            ".venv"))
        for name in sorted(filenames):
            if name.startswith("test_") \
                    and name.endswith(".py"):
                found.append(Path(dirpath, name)
                             .relative_to(ROOT).as_posix())
    found = sorted(found)
    assert found, "no pytest files found"
    assert [path for path in found
            if not path.startswith("tests/")] == [], \
        "pytest files must live under tests/"
    assert set(found) == set(run) | set(exclude), \
        "unaudited pytest files: %s" % sorted(
            set(found) - set(run) - set(exclude))
    runner = (ROOT / "tools" / "test").read_text()
    for path, reason in sorted(exclude.items()):
        text = (ROOT / path).read_text()
        if "collects no tests" in reason:
            assert not re.search(
                r"(?m)^\s*(async\s+)?def test", text), path
        for token in re.findall(r"MEMVEIL_[A-Z0-9_]+",
                                reason):
            assert token in text, (path, token)
        if "tools/test" in reason:
            assert path in runner, path
    allow = sel["unarmed_allow_env"]
    assert set(allow) == {"exact", "prefixes"}
    assert set(allow["exact"]) == set(CI_UNARMED_ALLOW_EXACT)
    assert allow["exact"] == sorted(allow["exact"])
    assert list(allow["prefixes"]) == \
        list(CI_UNARMED_ALLOW_PREFIXES)
    doc = _rust_workflow()
    assert set(doc["jobs"]) == {"deny", "rust-test", "pytest"}
    job = doc["jobs"]["pytest"]
    assert job["runs-on"] == "ubuntu-26.04"
    assert job["permissions"] == {"contents": "read"}
    steps = job["steps"]
    checkouts = [step for step in steps
                 if str(step.get("uses", "")).startswith(
                     "actions/checkout@")]
    assert len(checkouts) == 1
    deny_checkout = next(
        step["uses"] for step in doc["jobs"]["deny"]["steps"]
        if str(step.get("uses", "")).startswith(
            "actions/checkout@"))
    assert checkouts[0]["uses"] == deny_checkout, \
        "checkout pin drift"
    assert (checkouts[0].get("with") or {}).get(
        "persist-credentials") is False
    runs = {str(step.get("name", "")): str(step.get("run", ""))
            for step in steps if "run" in step}
    guard = next(run for name, run in runs.items()
                 if "guard" in name.lower())
    assert "pytest-ci-selection.json" in guard
    assert "unarmed_allow_env" in guard
    assert "MEMVEIL_" in guard
    assert "sys.exit(1)" in guard
    apt = next(run for run in runs.values()
               if "apt-get install" in run)
    installed = set(re.findall(r"[a-z0-9][a-z0-9+.-]*", apt))
    for package in ("binutils", "bpftrace", "bpftool",
                    "cpio", "python3-pytest", "python3-yaml",
                    "rpm", "rpm2cpio", "strace"):
        assert package in installed, package
    whole = json.dumps(job)
    assert "import yaml" in whole
    assert "pytest --version" in whole
    assert "cargo build" in whole and "--release" in whole
    assert "build/memveil" in whole
    assert "cargo test --locked --test package_tarball" \
        in whole
    selected = next(
        run for run in runs.values()
        if "-m pytest" in run
        and "pytest-ci-selection.json" in run)
    assert "FILES" in selected
    for name, run in sorted(runs.items()):
        proc = subprocess.run(
            ["bash", "-n"], input=run, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        assert proc.returncode == 0, (name, proc.stderr)
