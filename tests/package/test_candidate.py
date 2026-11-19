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
        manifest = {
            "bundle": "memveil-fixture",
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
        entries, inventory = m.git_inventory(root, commit)
        assert entries, "empty fixture inventory"
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
        }
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
