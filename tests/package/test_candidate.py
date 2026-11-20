# SPDX-License-Identifier: GPL-3.0-or-later
"""Seal tests for memveil-candidate/2 manifests.

Synthetic custody fixtures never qualify a product artifact: every
bundle, archive, and receipt below is assembled in a temporary
directory, and only the verification logic under test is real.
"""

import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))


def api():
    assert importlib.util.find_spec("candidate"), \
        "candidate protocol is missing"
    import candidate
    return candidate


def sha(data):
    return hashlib.sha256(data).hexdigest()


def git(root, *args, **kw):
    return subprocess.run(
        ["git", "-C", str(root), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, check=True, **kw).stdout.strip()


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
        # The build-time receipt the packager records in MANIFEST.json:
        # source C + tree inventory, probed tool versions, and the
        # engine/BPF output digests. The honest provenance below
        # repeats it verbatim; the seal requires the two to match.
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
        with tarfile.open(artifacts / "memveil-fixture.tar.gz",
                          "w:gz") as stream:
            stream.add(bundle, arcname="memveil-fixture")
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
        proc = subprocess.run(
            ["dpkg-deb", "-b", str(deb_stage / "payload"),
             str(artifacts / "memveil-fixture_0.1.0_amd64.deb")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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
             "--define", "payload %s" % staged, str(spec)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
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


def _transcribe(row):
    """Unsigned row transcription hashes, as the runner records."""
    found = []
    for path in sorted(Path(row).iterdir()):
        if path.name == "receipt.json" or not path.is_file() \
                or path.is_symlink():
            continue
        found.append({"name": path.name,
                      "sha256": sha(path.read_bytes()),
                      "bytes": path.stat().st_size})
    return found


MATRIX_GATE = "kernel-matrix/2"
MATRIX_ROW = "row1"
NONMATRIX_GATE = "synthetic-counts/1"


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


def _write_matrix_evidence(m, evidence):
    """One honest matrix row: receipt, cached inputs, raw, summary."""
    matrix = Path(evidence) / "matrix"
    row = matrix / MATRIX_ROW
    row.mkdir(parents=True)
    oracle = row / "oracle.txt"
    oracle.write_text("oracle events: 13000\noracle losses: 0\n")
    cached = {"row": MATRIX_ROW, "oracle_events": "13000",
              "oracle_losses": "0"}
    (row / "oracle-inputs.json").write_bytes(m.canonical(cached))
    files = _transcribe(row)
    assert {entry["name"] for entry in files} == {
        "oracle.txt", "oracle-inputs.json"}
    receipt = {"row": MATRIX_ROW,
               "oracle": {"text_sha256":
                          sha(oracle.read_bytes())},
               "files": files}
    (row / "receipt.json").write_bytes(m.canonical(receipt))
    summary = [{"id": MATRIX_ROW, "status": "pass"}]
    (matrix / "summary.json").write_bytes(m.canonical(summary))
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
    _write_matrix_evidence(m, evidence)
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
    _write_matrix_evidence(m, evidence)
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
                               ctx["policy_path"], evidence)
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
                               ctx["policy_path"], evidence)
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
                               ctx["policy_path"], evidence)


def test_inventory_rejects_altered_row_receipt(workshop,
                                               tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence) == {"ok": True, "gates": [MATRIX_GATE],
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
                               ctx["policy_path"], evidence)
    # The inventory error fires before signature verification:
    # breaking the signature as well must not change the blame.
    (evidence / "receipt.json.sig").write_bytes(b"invalid\n")
    with pytest.raises(ValueError, match="inventory differs"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence)


def test_inventory_rejects_missing_oracle_inputs(workshop,
                                                 tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    (evidence / "matrix" / MATRIX_ROW
     / "oracle-inputs.json").unlink()
    with pytest.raises(ValueError, match="missing"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence)


def test_inventory_rejects_extra_file(workshop, tmp_path):
    m, ctx, evidence, q_path, _ = _matrix_qualified(
        workshop, tmp_path)
    row = evidence / "matrix" / MATRIX_ROW
    (row / "extra.bin").write_bytes(b"unretained\n")
    with pytest.raises(ValueError,
                       match="unknown|extra|refuses"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence)
    (row / "extra.bin").unlink()
    (evidence / "matrix" / "extra.json").write_text("{}\n")
    with pytest.raises(ValueError, match="extra"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence)


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
                               ctx["policy_path"], evidence)


def test_original_signature_rejects_mutated_evidence(workshop,
                                                     tmp_path):
    m, ctx, evidence, q_path, doc = _matrix_qualified(
        workshop, tmp_path)
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence) == {"ok": True, "gates": [MATRIX_GATE],
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
    receipt["files"] = _transcribe(row)
    receipt_path.write_bytes(m.canonical(receipt))
    doc["evidence_archive"]["sha256"] = "6" * 64
    q_path.write_bytes(m.canonical(doc))
    assert signed == {name: sha((evidence / name).read_bytes())
                      for name in signed}, \
        "the signed bytes must be untouched"
    with pytest.raises(ValueError, match="inventory differs"):
        m.verify_qualification(ctx["manifest_path"], q_path,
                               ctx["policy_path"], evidence)
    # The original signature itself still verifies standalone:
    # only the signed inventory catches the substitution.
    m.verify_signature(evidence / "receipt.json",
                       evidence / "receipt.json.sig",
                       evidence / "signer.pub",
                       [sha((evidence / "signer.pub")
                            .read_bytes())])


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
        evidence) == expected
    assert m.verify_qualification(
        ctx["manifest_path"], q_path, ctx["policy_path"],
        evidence) == expected


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
           "--evidence-dir", str(evidence)]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "re-derived" in proc.stdout
    (evidence / "product.json").write_bytes(b'{"x": 1}\n')
    rerun = subprocess.run(argv, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
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
    with tarfile.open(archive, "w:gz") as stream:
        stream.add(evidence, arcname="evidence")
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
