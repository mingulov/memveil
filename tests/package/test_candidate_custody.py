# SPDX-License-Identifier: GPL-3.0-or-later
"""Import/promote/dry-run custody over local git and stubbed remotes.

Every flow runs against a synthetic source checkout plus fake
release/artifact/check-run records: no network, no credentials, no
real tags or releases outside the fixture. The `gh` binary is a
logging stub on PATH that never touches the network.
"""
import base64
import copy
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "tests/package"))
sys.path.insert(0, str(ROOT / "tests" / "vm"))
import candidate as c
import kernel_matrix as km
from test_kernel_matrix import _admitted_entry
from test_candidate import (
    cargo_build_harness, git, probe_tools, sha, _commit_as,
    _ephemeral_key, _sign, _write_policy,
    _write_nonmatrix_evidence, _write_signed_checksums,
    _nonmatrix_required_gates, NONMATRIX_GATE,
    _matrix_lock, _matrix_inputs, _matrix_required_gates,
    _write_real_matrix_row, _signed_gate, MATRIX_GATE,
    FIXED_EPOCH, deterministic_tar_gz, _clamp_tree)


def api():
    assert importlib.util.find_spec("candidate_custody"), \
        "custody protocol is missing"
    import candidate_custody
    return candidate_custody


REPO = "example/project"
VERSION = "0.1.1"
TAG = "v" + VERSION
ARCHIVE = "qualification-evidence.tar.gz"


class CustodyBase:
    """Lazily built custody fixtures over one synthetic source commit.

    The base holds a source checkout at C (with a Cargo version, a
    real candidate policy, locks, and release notes), a sealed
    candidate over honest artifacts, and signed qualification
    evidence. Tests copy the base, commit Q on top, and run the
    custody flows with stubbed remotes.
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
        dest = Path(tmp_path) / "custody"
        shutil.copytree(self.base, dest, symlinks=True)
        manifest = json.loads(
            (dest / "candidate.json").read_bytes())
        qualification = json.loads(
            (dest / "qualification.json").read_bytes())
        return {
            "root": dest / "root",
            "artifacts": dest / "artifacts",
            "manifest": manifest,
            "candidate_id": sha(
                (dest / "candidate.json").read_bytes()),
            "candidate_bytes":
                (dest / "candidate.json").read_bytes(),
            "qualification": qualification,
            "qualification_bytes":
                (dest / "qualification.json").read_bytes(),
            "tested_bytes":
                (dest / "tested-payload.sha256").read_bytes(),
            "archive_bytes": (dest / (ARCHIVE + ".bytes"))
            .read_bytes(),
            "key": dest / "key",
            "pub": dest / "key.pub",
        }

    def _build(self):
        tools = self.tools()
        private, public = _ephemeral_key(self.base / "key")
        trusted = [sha(public.read_bytes())]
        root = self.base / "root"
        (root / "crates" / "ebpf").mkdir(parents=True)
        (root / "packaging").mkdir(parents=True)
        (root / "src").mkdir(parents=True)
        (root / "docs").mkdir(parents=True)
        (root / "Cargo.toml").write_text(
            '[package]\nname = "memveil"\nversion = "%s"\n'
            % VERSION)
        lock = ('version = 3\n\n[[package]]\n'
                'name = "fixture-crate"\nversion = "0.1.0"\n'
                'source = "registry+https://x.invalid/index"\n'
                'checksum = "%s"\n' % ("ab" * 32))
        (root / "Cargo.lock").write_text(lock)
        ebpf_lock = lock.replace("fixture-crate", "fixture-ebpf-crate")
        (root / "crates" / "ebpf" / "Cargo.lock").write_text(
            ebpf_lock)
        (root / "rust-toolchain.toml").write_text(
            '[toolchain]\nchannel = "%s"\n' % tools["cargo"])
        _write_policy(c, root / "packaging"
                      / "candidate-policy.json",
                      {**_nonmatrix_required_gates(),
                       **_matrix_required_gates()},
                      trusted)
        (root / "src" / "engine.txt").write_text(
            "synthetic engine\n")
        os.symlink("engine.txt", root / "src" / "engine-link.txt")
        (root / "docs" / "release-notes.md").write_text(
            "# %s\n\nTest release notes.\n" % VERSION)
        (root / "tests" / "vm").mkdir(parents=True)
        (root / "tests" / "vm" / "kernels.lock.json").write_bytes(
            c.canonical(_matrix_lock(_admitted_entry())))
        git(root, "init", "-q")
        git(root, "add", ".")
        git(root, "-c", "user.name=Fixture",
            "-c", "user.email=fixture@example.invalid",
            "commit", "-qm", "Custody C")
        commit = git(root, "rev-parse", "HEAD")
        entries, inventory = c.git_inventory(root, commit)
        assert entries, "empty fixture inventory"

        bundle = self.base / "bundle"
        payload = {
            "bin/memveil": b"synthetic-engine\n",
            "lib/memveil/libfixture.so.1": b"synthetic-lib\n",
            "bpf/swiotlb_attempt.bpf.o": b"synthetic-bpf-attempt\n",
            "bpf/swiotlb_lifecycle.bpf.o":
                b"synthetic-bpf-lifecycle\n",
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
        bundled = {
            "bundle": "memveil-custody",
            "build_receipt": receipt,
            "engine_version": VERSION,
            "memveil_revision": commit,
            "toolchain": {
                "cargo": {"version": tools["cargo"]},
                "rustc": {"version": tools["rustc"]},
            },
            "cargo": {
                "lock_sha256": sha(lock.encode()),
                "ebpf_lock_sha256": sha(ebpf_lock.encode()),
                "crates": [{"name": "fixture-crate",
                            "version": "0.1.0",
                            "license": "MIT",
                            "source":
                            "registry+https://x.invalid/index"}],
                "ebpf_crates": [{"name": "fixture-ebpf-crate",
                                 "version": "0.1.0",
                                 "license": "MIT",
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
            json.dumps(bundled, indent=2, sort_keys=True) + "\n")

        artifacts = self.base / "artifacts"
        artifacts.mkdir(parents=True)
        bundle_tar = artifacts / "memveil-custody.tar.gz"
        deterministic_tar_gz(bundle, "memveil-custody",
                             bundle_tar)
        epoch_env = dict(os.environ)
        epoch_env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
        staged = self.base / "staged"
        for rel in files:
            target = staged / c.installed_file_path(rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(bundle / rel, target)
        deb_stage = self.base / "deb-stage"
        shutil.copytree(staged, deb_stage / "payload")
        (deb_stage / "payload" / "DEBIAN").mkdir(parents=True)
        (deb_stage / "payload" / "DEBIAN" / "control").write_text(
            "Package: memveil-custody\nVersion: %s\n"
            "Architecture: amd64\nMaintainer: Fixture\n"
            "Description: synthetic custody fixture\n" % VERSION)
        _clamp_tree(deb_stage / "payload")
        proc = subprocess.run(
            ["dpkg-deb", "-b", str(deb_stage / "payload"),
             str(artifacts
                 / ("memveil-custody_%s_amd64.deb" % VERSION))],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=epoch_env)
        assert proc.returncode == 0, proc.stderr
        rpm_top = self.base / "rpm-top"
        for leaf in ("BUILD", "RPMS", "SOURCES", "SPECS", "SRPMS"):
            (rpm_top / leaf).mkdir(parents=True)
        spec = self.base / "fixture.spec"
        spec.write_text(
            "Name: memveil-custody\nVersion: %s\nRelease: 1\n"
            "Summary: synthetic custody fixture\n"
            "License: GPL-3.0-or-later\n\n"
            "%%description\nsynthetic custody fixture\n\n"
            "%%install\ncp -r %%{payload}/* %%{buildroot}/\n\n"
            "%%files\n" % VERSION + "".join(
                '/%s\n' % c.installed_file_path(rel)
                for rel in sorted(files)) + "\n"
            "%%changelog\n* Thu Nov 19 2026 Fixture - %s-1\n"
            "- fixture\n" % VERSION)
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
        source_tar = artifacts / "memveil-custody-source.tar.gz"
        source_tar.write_bytes(gzip.compress(proc.stdout, mtime=0))
        sbom_out = artifacts / "memveil-custody.spdx.json"
        proc = subprocess.run(
            [self.harness_bin(), "sbom-emit",
             "--manifest", str(bundle / "MANIFEST.json"),
             "--bundle", str(bundle_tar),
             "--deb", str(next(artifacts.glob("*.deb"))),
             "--rpm", str(next(artifacts.glob("*.rpm"))),
             "--lock", str(root / "Cargo.lock"),
             "--ebpf-lock",
             str(root / "crates" / "ebpf" / "Cargo.lock"),
             "--created", str(FIXED_EPOCH),
             "--out", str(sbom_out)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert proc.returncode == 0, proc.stderr
        provenance_out = artifacts / "memveil-custody.provenance.json"
        c.emit_provenance(
            bundle, {"root": str(root),
                     "bundle": str(bundle_tar),
                     "deb": str(next(artifacts.glob("*.deb"))),
                     "rpm": str(next(artifacts.glob("*.rpm"))),
                     "source": str(source_tar),
                     "sbom": str(sbom_out)},
            provenance_out)

        manifest = c.create_manifest(
            bundle, artifacts,
            root / "packaging" / "candidate-policy.json",
            {"root": str(root),
             "harness_bin": self.harness_bin()})
        candidate_path = self.base / "candidate.json"
        candidate_id = c.seal_manifest(manifest, candidate_path)

        ctx = {"manifest": manifest, "candidate_id": candidate_id,
               "key": private, "pub": public}
        evidence = self.base / "evidence"
        binding = _write_nonmatrix_evidence(c, ctx, evidence)
        _write_real_matrix_row(c, evidence / "matrix", manifest)
        matrix_binding = _signed_gate(
            c, ctx, evidence, MATRIX_GATE, "matrix-inputs.json",
            "matrix-receipt.json",
            _matrix_inputs(c, evidence))
        _write_signed_checksums(c, ctx, evidence)
        archive_path = self.base / (ARCHIVE + ".bytes")
        assert c.build_evidence_archive(
            evidence, archive_path) == [
                "matrix/" + _admitted_entry()["id"]
                + "/vng-cmd.txt"]
        archive_entry = {
            "name": ARCHIVE,
            "size": str(archive_path.stat().st_size),
            "sha256": sha(archive_path.read_bytes())}
        doc = {"schema": "memveil-qualification/1",
               "candidate_sha256": candidate_id,
               "source_commit": commit,
               "claim": "ordinary-preview",
               "evidence_archive": archive_entry,
               "gates": {NONMATRIX_GATE: binding,
                         MATRIX_GATE: matrix_binding}}
        (self.base / "qualification.json").write_bytes(
            c.canonical(doc))
        expected = c.expected_payload(manifest)
        (self.base / "tested-payload.sha256").write_text("".join(
            value + "  " + name + "\n"
            for name, value in sorted(expected.items())))
        self._built = True


@pytest.fixture(scope="session")
def custody_base(tmp_path_factory):
    return CustodyBase(tmp_path_factory.mktemp("custody-base"))


def fresh(base, tmp_path):
    return base.fresh(tmp_path)


def commit_q(root, entries):
    """Commit Q files; return the new commit."""
    for rel, data in entries.items():
        path = Path(root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return _commit_as(root, "Q evidence", *entries)


def q1_entries(fix):
    return {
        "packaging/qualifications/candidate.json":
            fix["candidate_bytes"],
        "packaging/tested-payload.sha256": fix["tested_bytes"],
        "packaging/qualifications/qualification.json":
            fix["qualification_bytes"],
    }


def armed(monkeypatch, root, mode, head):
    monkeypatch.setenv("CUSTODY_ARM", "ARM-" + mode.upper())
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_REPOSITORY", REPO)
    monkeypatch.setenv("GITHUB_SHA", head)
    monkeypatch.chdir(root)


class FakeRelease:
    """Stub release endpoint serving the sealed bytes."""

    def __init__(self, fix):
        self.calls = []
        self.data = {}
        self.ids = {}
        records = list(fix["manifest"]["artifacts"]) + [{
            "name": ARCHIVE,
            "size": str(len(fix["archive_bytes"])),
            "sha256": sha(fix["archive_bytes"])}, {
            "name": "qualification.json",
            "size": str(len(fix["qualification_bytes"])),
            "sha256": sha(fix["qualification_bytes"])}]
        assets = []
        for rank, entry in enumerate(records, 100):
            ident = str(rank)
            self.ids[entry["name"]] = ident
            if entry["name"] == ARCHIVE:
                self.data[entry["name"]] = fix["archive_bytes"]
            elif entry["name"] == "qualification.json":
                self.data[entry["name"]] = \
                    fix["qualification_bytes"]
            else:
                self.data[entry["name"]] = (
                    fix["artifacts"] / entry["name"]).read_bytes()
            assets.append({
                "id": rank, "name": entry["name"],
                "size": int(entry["size"]), "state": "uploaded",
                "digest": "sha256:" + entry["sha256"],
                "url": "https://api.github.com/repos/" + REPO
                + "/releases/assets/" + ident})
        self.release = {"id": 1, "draft": True,
                        "tag_name": "candidate-fixture",
                        "assets": assets}

    def json(self, path):
        self.calls.append(("GET", path))
        assert path == "repos/" + REPO + "/releases/1", path
        return copy.deepcopy(self.release)

    def download(self, path, destination):
        self.calls.append(("DOWNLOAD", path))
        name = next(key for key, ident in self.ids.items()
                    if path == "repos/" + REPO
                    + "/releases/assets/" + ident)
        Path(destination).write_bytes(self.data[name])


class FakeList:
    """Stub list-releases endpoint serving one listing."""

    def __init__(self, releases):
        self.calls = []
        self.releases = copy.deepcopy(releases)

    def json(self, path):
        self.calls.append(("GET", path))
        assert path == "repos/" + REPO \
            + "/releases?per_page=100", path
        return copy.deepcopy(self.releases)

    def download(self, path, destination):
        self.calls.append(("DOWNLOAD", path))
        ident = path.rsplit("/", 1)[1]
        Path(destination).write_bytes(
            ("asset-bytes:%s\n" % ident).encode())


def _draft_listing(tag):
    return [
        {"id": 7, "draft": False, "tag_name": "v0.1.0",
         "assets": []},
        {"id": 9, "draft": True, "tag_name": tag,
         "assets": [
             {"id": 101,
              "name": "qualification-evidence.tar.gz",
              "state": "uploaded"},
             {"id": 102, "name": "candidate.json",
              "state": "uploaded"}]},
        {"id": 11, "draft": False, "tag_name": "v0.1.1",
         "assets": []},
    ]


def test_find_holding_draft_selects_draft_only():
    m = api()
    tag = "candidate-" + "1" * 64
    found = m.find_holding_draft(
        FakeList(_draft_listing(tag)), REPO, tag)
    assert found["id"] == 9
    assert found["draft"] is True


def test_find_holding_draft_rejects_absent_tag():
    m = api()
    with pytest.raises(ValueError, match="missing or ambiguous"):
        m.find_holding_draft(
            FakeList(_draft_listing("candidate-" + "1" * 64)),
            REPO, "candidate-" + "2" * 64)


def test_find_holding_draft_ignores_published_same_tag():
    m = api()
    tag = "candidate-" + "1" * 64
    listing = [{"id": 7, "draft": False, "tag_name": tag,
                "assets": []}]
    with pytest.raises(ValueError, match="missing or ambiguous"):
        m.find_holding_draft(FakeList(listing), REPO, tag)


def test_download_draft_asset_uses_asset_id(tmp_path):
    m = api()
    tag = "candidate-" + "1" * 64
    listing = FakeList(_draft_listing(tag))
    release = m.find_holding_draft(listing, REPO, tag)
    dest = Path(tmp_path) / "evidence.tar.gz"
    asset = m.download_draft_asset(
        listing, REPO, release, "qualification-evidence.tar.gz",
        dest)
    assert asset["id"] == 101
    assert ("DOWNLOAD",
            "repos/" + REPO + "/releases/assets/101") \
        in listing.calls
    assert dest.read_bytes() == b"asset-bytes:101\n"
    with pytest.raises(ValueError, match="missing or ambiguous"):
        m.download_draft_asset(listing, REPO, release,
                               "absent.bin", dest)


def test_download_draft_asset_refuses_unuploaded(tmp_path):
    m = api()
    release = {"id": 9, "draft": True, "tag_name": "t",
               "assets": [{"id": 103, "name": "half.bin",
                           "state": "open"}]}
    with pytest.raises(ValueError, match="not uploaded"):
        m.download_draft_asset(FakeList([]), REPO, release,
                               "half.bin", tmp_path / "half.bin")


def custody_statement(fix, ids):
    return {
        "schema": "memveil-candidate-import/1",
        "operation": "import", "build_origin": "local-build",
        "repository": REPO, "release_id": "1", "assets": ids,
        "candidate_sha256": fix["candidate_id"],
        "source_commit": fix["manifest"]["source"]["commit"]}


def stored_zip(fix, custody):
    """Flat ZIP of the retained bytes plus the custody statement."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w",
                         zipfile.ZIP_DEFLATED) as stream:
        for entry in fix["manifest"]["artifacts"]:
            stream.writestr(
                entry["name"],
                (fix["artifacts"] / entry["name"]).read_bytes())
        stream.writestr(ARCHIVE, fix["archive_bytes"])
        stream.writestr("qualification.json",
                        fix["qualification_bytes"])
        stream.writestr("custody.json", c.canonical(custody))
    return buffer.getvalue()


def remote_checks(fix, head):
    """Five signed fixed-gate bindings over offline counts."""
    m = api()
    checks = {}
    for rank, (ident, measurement) in enumerate(
            sorted(m.REMOTE_CHECKS.items()), 1):
        inputs = {"schema": "memveil-gate-input/1",
                  "environment": "offline",
                  "product": {measurement: "2", "failures": "0"},
                  "oracle": {measurement: "2", "failures": "0"}}
        receipt = {"schema": "memveil-remote-gate/1",
                   "gate": ident,
                   "candidate_sha256": fix["candidate_id"],
                   "source_commit":
                   fix["manifest"]["source"]["commit"],
                   "inputs_sha256": sha(c.canonical(inputs))}
        subject = fix["root"] / ("remote-%d.receipt" % rank)
        subject.write_bytes(c.canonical(receipt))
        sig = _sign(fix["key"], subject)
        checks[ident] = {
            "check_id": str(rank), "run_id": "9",
            "head_sha": head, "receipt": receipt,
            "inputs": inputs,
            "signature_base64": base64.b64encode(
                sig.read_bytes()).decode(),
            "public_key": fix["pub"].read_text()}
        subject.unlink()
        sig.unlink()
    return checks


def remote_receipt(fix, signer, zip_bytes, custody_sha, checks):
    return {
        "schema": "memveil-remote-custody/1",
        "candidate_sha256": fix["candidate_id"],
        "source_commit": fix["manifest"]["source"]["commit"],
        "repository": REPO, "repository_id": "9", "run_id": "8",
        "artifact_id": "7", "artifact_sha256": sha(zip_bytes),
        "signer_commit": signer, "custody_sha256": custody_sha,
        "checks": checks}


class FakeRemote:
    """Stub artifacts/runs/check-runs/releases endpoints."""

    def __init__(self, fix, remote, zip_bytes, listing=None,
                 artifact=None, run=None):
        self.calls = []
        self.fix = fix
        self.remote = copy.deepcopy(remote)
        self.zip_bytes = zip_bytes
        self.listing = listing if listing is not None else []
        self.artifact_record = artifact
        self.run_record = run

    def json(self, path):
        self.calls.append(("GET", path))
        if path == "repos/" + REPO + "/actions/artifacts/7":
            if self.artifact_record is not None:
                return copy.deepcopy(self.artifact_record)
            return {
                "id": 7, "expired": False,
                "name": "candidate-" + self.fix["candidate_id"],
                "digest": "sha256:" + sha(self.zip_bytes),
                "expires_at": "2099-01-01T00:00:00Z",
                "workflow_run": {
                    "id": 8, "repository_id": 9,
                    "head_repository_id": 9,
                    "head_sha": self.remote["signer_commit"]}}
        if path == "repos/" + REPO + "/actions/runs/8":
            if self.run_record is not None:
                return copy.deepcopy(self.run_record)
            return {
                "status": "completed", "conclusion": "success",
                "event": "workflow_dispatch",
                "path": ".github/workflows/release.yml",
                "head_sha": self.remote["signer_commit"],
                "repository": {"id": 9}}
        if path.startswith("repos/" + REPO + "/check-runs/"):
            ident = sorted(self.remote["checks"])[
                int(path.rsplit("/", 1)[1]) - 1]
            binding = self.remote["checks"][ident]
            return {
                "name": ident, "status": "completed",
                "conclusion": "success",
                "head_sha": binding["head_sha"],
                "app": {"slug": "github-actions"},
                "details_url": "https://github.com/" + REPO
                + "/actions/runs/9/job/123"}
        assert path == "repos/" + REPO + "/releases?per_page=100", \
            path
        return copy.deepcopy(self.listing)

    def download(self, path, destination):
        self.calls.append(("DOWNLOAD", path))
        assert path == "repos/" + REPO \
            + "/actions/artifacts/7/zip", path
        Path(destination).write_bytes(self.zip_bytes)


def fake_gh(monkeypatch, tmp_path, attest_exit="0"):
    """Logging `gh` stub; attestation exit is configurable."""
    bindir = Path(tmp_path) / "fakebin"
    bindir.mkdir(exist_ok=True)
    log = Path(tmp_path) / "gh.log"
    log.write_text("")
    script = bindir / "gh"
    script.write_text(
        "#!/bin/sh\n"
        'echo "$@" >> "%s"\n'
        'if [ "$1 $2" = "attestation verify" ]; then\n'
        '  exit %s\n'
        "fi\n"
        'if [ "$1" = "release" ]; then\n'
        "  exit 0\n"
        "fi\n"
        'echo "unexpected gh call" >&2\n'
        "exit 1\n" % (log, attest_exit))
    script.chmod(0o755)
    monkeypatch.setenv(
        "PATH", str(bindir) + os.pathsep + os.environ["PATH"])
    return log


def import_request(fix, q1, ids):
    return {"repository": REPO,
            "source_commit": fix["manifest"]["source"]["commit"],
            "qualification_commit": q1,
            "candidate_sha256": fix["candidate_id"],
            "release_id": "1", "asset_ids": ids}


def stored_request(fix, q2, with_tag=True):
    request = {
        "repository": REPO,
        "source_commit": fix["manifest"]["source"]["commit"],
        "qualification_commit": q2,
        "candidate_sha256": fix["candidate_id"],
        "run_id": "8", "artifact_id": "7"}
    if with_tag:
        request["tag"] = TAG
    return request


def qualify_two(fix):
    """Commit Q1 evidence plus Q2 remote receipt; return (q1, q2)."""
    q1 = commit_q(fix["root"], q1_entries(fix))
    checks = remote_checks(fix, q1)
    custody = custody_statement(
        fix, {entry["name"]: str(rank) for rank, entry in
              enumerate(fix["manifest"]["artifacts"], 100)})
    archive = stored_zip(fix, custody)
    remote = remote_receipt(fix, q1, archive,
                            sha(c.canonical(custody)), checks)
    q2 = commit_q(fix["root"], {
        "packaging/qualifications/remote.json":
            c.canonical(remote)})
    return q1, q2, remote, archive


def test_import_accepts_exact_draft(custody_base, tmp_path,
                                    monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    q1 = commit_q(fix["root"], q1_entries(fix))
    armed(monkeypatch, fix["root"], "import", q1)
    release = FakeRelease(fix)
    monkeypatch.setattr(m, "GitHub", lambda: release)
    out = Path(tmp_path) / "out"
    assert m.run("import", import_request(fix, q1, release.ids),
                 out, custody_base.harness_bin()) is None
    stored = out / "stored"
    names = {entry["name"]
             for entry in fix["manifest"]["artifacts"]}
    assert {path.name for path in stored.iterdir()} == names | {
        ARCHIVE, "qualification.json", "custody.json"}
    # The external digest record pinned the draft copy to
    # the Q-committed bytes.
    assert (stored / "qualification.json").read_bytes() == \
        fix["qualification_bytes"]
    custody = json.loads((stored / "custody.json").read_bytes())
    assert custody == custody_statement(fix, release.ids)
    subjects = (out / "SUBJECTS.txt").read_text().splitlines()
    assert subjects[-1] == sha((stored / "custody.json")
                               .read_bytes()) + "  custody.json"
    assert len(subjects) == len(names) + 1
    assert ("GET", "repos/" + REPO + "/releases/1") in release.calls
    assert sum(1 for call in release.calls
               if call[0] == "DOWNLOAD") == len(names) + 2


@pytest.mark.parametrize("damage", ["not-draft", "extra",
                                    "wrong-digest", "substitute",
                                    "wrong-id"])
def test_import_rejects_conflicting_assets(
        custody_base, tmp_path, monkeypatch, damage):
    m = api()
    fix = fresh(custody_base, tmp_path)
    q1 = commit_q(fix["root"], q1_entries(fix))
    armed(monkeypatch, fix["root"], "import", q1)
    release = FakeRelease(fix)
    ids = dict(release.ids)
    if damage == "not-draft":
        release.release["draft"] = False
    elif damage == "extra":
        release.release["assets"].append(
            dict(release.release["assets"][0], id=999,
                 name="extra"))
    elif damage == "wrong-digest":
        release.release["assets"][0]["digest"] = "sha256:" \
            + "0" * 64
    elif damage == "substitute":
        first = next(iter(release.data))
        release.data[first] = b"substituted bytes\n"
    elif damage == "wrong-id":
        first = next(iter(ids))
        ids[first] = "999"
    monkeypatch.setattr(m, "GitHub", lambda: release)
    with pytest.raises(ValueError):
        m.run("import", import_request(fix, q1, ids),
              Path(tmp_path) / "out", custody_base.harness_bin())


def test_import_rejects_foreign_build_origin(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    foreign = json.loads(
        (fix["artifacts"] / next(
            entry["name"] for entry in
            fix["manifest"]["artifacts"]
            if entry["role"] == "provenance")).read_bytes())
    foreign["origin"] = "foreign-build"
    foreign_bytes = c.canonical(foreign)
    patched = copy.deepcopy(fix["manifest"])
    for entry in patched["artifacts"]:
        if entry["role"] == "provenance":
            entry["size"] = str(len(foreign_bytes))
            entry["sha256"] = sha(foreign_bytes)
    assert c.validate_manifest(patched) == patched
    patched_id = sha(c.canonical(patched))
    ctx = {"manifest": patched, "candidate_id": patched_id,
           "key": fix["key"], "pub": fix["pub"]}
    evidence = Path(tmp_path) / "evidence-foreign"
    binding = _write_nonmatrix_evidence(c, ctx, evidence)
    _write_real_matrix_row(c, evidence / "matrix", patched)
    matrix_binding = _signed_gate(
        c, ctx, evidence, MATRIX_GATE, "matrix-inputs.json",
        "matrix-receipt.json", _matrix_inputs(c, evidence))
    _write_signed_checksums(c, ctx, evidence)
    archive_path = Path(tmp_path) / "foreign.tar.gz"
    assert c.build_evidence_archive(
        evidence, archive_path) == [
            "matrix/" + _admitted_entry()["id"]
            + "/vng-cmd.txt"]
    archive_bytes = archive_path.read_bytes()
    doc = {"schema": "memveil-qualification/1",
           "candidate_sha256": patched_id,
           "source_commit": patched["source"]["commit"],
           "claim": "ordinary-preview",
           "evidence_archive": {
               "name": ARCHIVE,
               "size": str(len(archive_bytes)),
               "sha256": sha(archive_bytes)},
           "gates": {NONMATRIX_GATE: binding,
                     MATRIX_GATE: matrix_binding}}
    patched_fix = dict(fix, manifest=patched,
                       candidate_id=patched_id,
                       candidate_bytes=c.canonical(patched),
                       qualification_bytes=c.canonical(doc),
                       archive_bytes=archive_bytes)
    q1 = commit_q(fix["root"], q1_entries(patched_fix))
    release = FakeRelease(patched_fix)
    release.data[next(
        entry["name"] for entry in patched["artifacts"]
        if entry["role"] == "provenance")] = foreign_bytes
    armed(monkeypatch, fix["root"], "import", q1)
    monkeypatch.setattr(m, "GitHub", lambda: release)
    with pytest.raises(ValueError, match="origin"):
        m.run("import",
              import_request(patched_fix, q1, release.ids),
              Path(tmp_path) / "out", custody_base.harness_bin())


def test_import_rejects_failing_row_predicates(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    # The attack: the oracle counts change identically in the
    # retained raw file and the cached transcription, with
    # every unsigned hash refreshed, so only the re-derived
    # row predicates can refuse.
    evidence = Path(tmp_path) / "evidence-tampered"
    with tarfile.open(fileobj=io.BytesIO(
            fix["archive_bytes"]), mode="r:gz") as stream:
        stream.extractall(evidence)
    inner = evidence / "evidence"
    row = next(path for path in (inner / "matrix").iterdir()
               if path.is_dir())
    oracle = row / "oracle.txt"
    altered = oracle.read_text().replace("13000", "12000")
    assert altered != oracle.read_text()
    oracle.write_text(altered)
    cached_path = row / "oracle-inputs.json"
    cached = json.loads(cached_path.read_text())
    cached["oracle_text"] = altered
    cached_path.write_text(json.dumps(cached))
    receipt_path = row / "receipt.json"
    receipt = json.loads(receipt_path.read_text())
    receipt["oracle"]["text_sha256"] = sha(
        oracle.read_bytes())
    receipt["files"] = km.row_receipt_files(row)
    receipt_path.write_bytes(c.canonical(receipt))
    ctx = {"manifest": fix["manifest"],
           "candidate_id": fix["candidate_id"],
           "key": fix["key"], "pub": fix["pub"]}
    matrix_binding = _signed_gate(
        c, ctx, inner, MATRIX_GATE, "matrix-inputs.json",
        "matrix-receipt.json", _matrix_inputs(c, inner))
    doc = copy.deepcopy(fix["qualification"])
    doc["gates"][MATRIX_GATE] = matrix_binding
    archive_path = Path(tmp_path) / "tampered.tar.gz"
    # The inner tree was extracted from a packed archive,
    # so the local-only command line is already gone and
    # the repack excludes nothing.
    assert c.build_evidence_archive(inner, archive_path) == []
    archive_bytes = archive_path.read_bytes()
    doc["evidence_archive"] = {
        "name": ARCHIVE, "size": str(len(archive_bytes)),
        "sha256": sha(archive_bytes)}
    tampered_fix = dict(
        fix, qualification_bytes=c.canonical(doc),
        archive_bytes=archive_bytes)
    q1 = commit_q(fix["root"], q1_entries(tampered_fix))
    release = FakeRelease(tampered_fix)
    armed(monkeypatch, fix["root"], "import", q1)
    monkeypatch.setattr(m, "GitHub", lambda: release)
    with pytest.raises(ValueError, match="[Pp]redicates"):
        m.run("import",
              import_request(tampered_fix, q1, release.ids),
              Path(tmp_path) / "out", custody_base.harness_bin())


def test_dryrun_validates_proposed_tag_without_mutation(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    _q1, q2, remote, archive = qualify_two(fix)
    armed(monkeypatch, fix["root"], "dry-run", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    log = fake_gh(monkeypatch, tmp_path)
    out = Path(tmp_path) / "out"
    assert m.run("dry-run", stored_request(fix, q2),
                 out, custody_base.harness_bin()) is None
    assert (out / "stored" / "custody.json").is_file()
    assert not (out / "SUBJECTS.txt").exists()
    lines = log.read_text().splitlines()
    assert any("attestation verify" in line for line in lines)
    assert not any(line.startswith("release ") for line in lines), \
        "dry-run must not publish: %r" % lines


@pytest.mark.parametrize("at", ["source", "qualified"])
def test_dryrun_requires_no_tag_yet(
        custody_base, tmp_path, monkeypatch, at):
    m = api()
    fix = fresh(custody_base, tmp_path)
    _q1, q2, remote, archive = qualify_two(fix)
    head = fix["manifest"]["source"]["commit"] \
        if at == "source" else q2
    git(fix["root"], "tag", TAG, head)
    armed(monkeypatch, fix["root"], "dry-run", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    fake_gh(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="already exists"):
        m.run("dry-run", stored_request(fix, q2),
              Path(tmp_path) / "out", custody_base.harness_bin())


@pytest.mark.parametrize("field,forged", [("run_id", "9"),
                                          ("artifact_id", "6")])
def test_consumer_refuses_import_ids_differing_from_Q(
        custody_base, tmp_path, monkeypatch, field, forged):
    m = api()
    fix = fresh(custody_base, tmp_path)
    _q1, q2, remote, archive = qualify_two(fix)
    armed(monkeypatch, fix["root"], "dry-run", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    fake_gh(monkeypatch, tmp_path)
    request = stored_request(fix, q2)
    assert request[field] != forged
    request[field] = forged
    with pytest.raises(ValueError, match="immutable IDs differ"):
        m.run("dry-run", request, Path(tmp_path) / "out",
              custody_base.harness_bin())


def test_promote_requires_tag_resolving_to_C(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    source = fix["manifest"]["source"]["commit"]
    _q1, q2, remote, archive = qualify_two(fix)
    armed(monkeypatch, fix["root"], "promote", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    log = fake_gh(monkeypatch, tmp_path)
    with pytest.raises(ValueError, match="final tag"):
        m.run("promote", stored_request(fix, q2),
              Path(tmp_path) / "absent", custody_base.harness_bin())
    git(fix["root"], "tag", TAG, q2)
    with pytest.raises(ValueError, match="final tag"):
        m.run("promote", stored_request(fix, q2),
              Path(tmp_path) / "drifted", custody_base.harness_bin())
    git(fix["root"], "tag", "-d", TAG)
    git(fix["root"], "tag", TAG, source)
    out = Path(tmp_path) / "out"
    assert m.run("promote", stored_request(fix, q2),
                 out, custody_base.harness_bin()) is None
    lines = log.read_text().splitlines()
    assert any(line.startswith("release create ") for line in lines)
    assert any(line.startswith("release upload ") for line in lines)
    assert any(line.startswith("release edit ") for line in lines)


def test_promote_reads_policy_once(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    source = fix["manifest"]["source"]["commit"]
    _q1, q2, remote, archive = qualify_two(fix)
    git(fix["root"], "tag", TAG, source)
    armed(monkeypatch, fix["root"], "promote", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    fake_gh(monkeypatch, tmp_path)
    out = Path(tmp_path) / "out"
    policy_path = out / "policy.json"
    reads = []
    real_read_regular = c.read_regular

    def counting_read_regular(path, *args, **kwargs):
        if Path(str(path)) == policy_path:
            reads.append(path)
            if len(reads) > 1:
                raise ValueError("policy re-read")
        return real_read_regular(path, *args, **kwargs)

    real_read_json = c.read_json

    def refusing_read_json(path, *args, **kwargs):
        if Path(str(path)) == policy_path:
            raise ValueError(
                "policy must not load via read_json")
        return real_read_json(path, *args, **kwargs)

    monkeypatch.setattr(c, "read_regular", counting_read_regular)
    monkeypatch.setattr(c, "read_json", refusing_read_json)
    assert m.run("promote", stored_request(fix, q2),
                 out, custody_base.harness_bin()) is None
    assert len(reads) == 1


@pytest.mark.parametrize("damage", ["flag", "timestamp", "fork"])
def test_promote_rejects_expired_artifact(
        custody_base, tmp_path, monkeypatch, damage):
    m = api()
    fix = fresh(custody_base, tmp_path)
    source = fix["manifest"]["source"]["commit"]
    _q1, q2, remote, archive = qualify_two(fix)
    git(fix["root"], "tag", TAG, source)
    record = {
        "id": 7, "expired": damage == "flag",
        "name": "candidate-" + fix["candidate_id"],
        "digest": "sha256:" + sha(archive),
        "expires_at": "2000-01-01T00:00:00Z"
        if damage == "timestamp" else "2099-01-01T00:00:00Z",
        "workflow_run": {
            "id": 8, "repository_id": 9,
            "head_repository_id": 10 if damage == "fork" else 9,
            "head_sha": remote["signer_commit"]}}
    armed(monkeypatch, fix["root"], "promote", q2)
    stub = FakeRemote(fix, remote, archive, artifact=record)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    log = fake_gh(monkeypatch, tmp_path)
    with pytest.raises(ValueError):
        m.run("promote", stored_request(fix, q2),
              Path(tmp_path) / "out", custody_base.harness_bin())
    assert "release create" not in log.read_text()


def test_promote_rejects_untrusted_attestation(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    source = fix["manifest"]["source"]["commit"]
    _q1, q2, remote, archive = qualify_two(fix)
    git(fix["root"], "tag", TAG, source)
    armed(monkeypatch, fix["root"], "promote", q2)
    stub = FakeRemote(fix, remote, archive)
    monkeypatch.setattr(m, "GitHub", lambda: stub)
    log = fake_gh(monkeypatch, tmp_path, attest_exit="1")
    with pytest.raises(subprocess.CalledProcessError):
        m.run("promote", stored_request(fix, q2),
              Path(tmp_path) / "out", custody_base.harness_bin())
    assert "release create" not in log.read_text()


def test_remote_checks_verify_offline(tmp_path):
    m = api()
    assert set(m.REMOTE_CHECKS) == {
        "tampered-payload/1", "promotion-dry-run/1",
        "independent-attestation/1", "required-checks/1",
        "no-overwrite/1"}
    private, public = _ephemeral_key(Path(tmp_path) / "key")
    policy = {"trusted_keys": [sha(public.read_bytes())]}
    checks = {}
    for rank, (ident, measurement) in enumerate(
            sorted(m.REMOTE_CHECKS.items()), 1):
        inputs = {"schema": "memveil-gate-input/1",
                  "environment": "offline",
                  "product": {measurement: "2", "failures": "0"},
                  "oracle": {measurement: "2", "failures": "0"}}
        receipt = {"schema": "memveil-remote-gate/1",
                   "gate": ident,
                   "candidate_sha256": "a" * 64,
                   "source_commit": "b" * 40,
                   "inputs_sha256": sha(c.canonical(inputs))}
        subject = Path(tmp_path) / ("receipt-%d" % rank)
        subject.write_bytes(c.canonical(receipt))
        sig = _sign(private, subject)
        checks[ident] = {
            "check_id": str(rank), "run_id": "9",
            "head_sha": "b" * 40, "receipt": receipt,
            "inputs": inputs,
            "signature_base64": base64.b64encode(
                sig.read_bytes()).decode(),
            "public_key": public.read_text()}

    class FakeChecks:
        def json(self, path):
            rank = int(path.rsplit("/", 1)[1])
            ident = sorted(checks)[rank - 1]
            return {
                "name": ident, "status": "completed",
                "conclusion": "success", "head_sha": "b" * 40,
                "app": {"slug": "github-actions"},
                "details_url": "https://github.com/" + REPO
                + "/actions/runs/9/job/123"}

    assert m.verify_remote_checks(
        checks, FakeChecks(), REPO, "b" * 40, "a" * 64,
        policy) is None
    changed = copy.deepcopy(checks)
    changed["tampered-payload/1"]["inputs"]["product"][
        "refusals"] = "0"
    with pytest.raises(ValueError, match="inputs differ"):
        m.verify_remote_checks(changed, FakeChecks(), REPO,
                               "b" * 40, "a" * 64, policy)
    with pytest.raises(ValueError, match="untrusted"):
        m.verify_remote_checks(checks, FakeChecks(), REPO,
                               "b" * 40, "a" * 64,
                               {"trusted_keys": []})


def test_unarmed_custody_has_no_side_effects(
        custody_base, tmp_path, monkeypatch):
    m = api()
    fix = fresh(custody_base, tmp_path)
    monkeypatch.delenv("CUSTODY_ARM", raising=False)
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.chdir(fix["root"])
    out = Path(tmp_path) / "out"
    with pytest.raises(ValueError, match="arming"):
        m.run("import", {}, out, custody_base.harness_bin())
    assert not out.exists()
    monkeypatch.setenv("CUSTODY_ARM", "ARM-IMPORT")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    with pytest.raises(ValueError, match="dispatch"):
        m.run("import", {}, out, custody_base.harness_bin())
    assert not out.exists()


def test_cli_import_accepts_exact_draft(
        custody_base, tmp_path, monkeypatch):
    fix = fresh(custody_base, tmp_path)
    q1 = commit_q(fix["root"], q1_entries(fix))
    release = FakeRelease(fix)
    request_path = Path(tmp_path) / "request.json"
    request_path.write_bytes(
        c.canonical(import_request(fix, q1, release.ids)))
    served = Path(tmp_path) / "served"
    (served / "by-id").mkdir(parents=True)
    (served / "release.json").write_text(
        json.dumps(release.release))
    for name, ident in release.ids.items():
        (served / "by-id" / ident).write_bytes(
            release.data[name])
    bindir = Path(tmp_path) / "apibin"
    bindir.mkdir()
    script = bindir / "gh"
    script.write_text(
        "#!/bin/sh\n"
        "if [ \"$1\" != \"api\" ]; then\n"
        '  echo "unexpected gh call" >&2\n'
        "  exit 1\n"
        "fi\n"
        "for last in \"$@\"; do :; done\n"
        'case "$*" in\n'
        "  *application/octet-stream*)\n"
        '    cat "$GH_CUSTODY_SERVED/by-id/${last##*/}";;\n'
        "  *)\n"
        '    cat "$GH_CUSTODY_SERVED/release.json";;\n'
        "esac\n")
    script.chmod(0o755)
    out = Path(tmp_path) / "out"
    env = dict(os.environ)
    env.update({"CUSTODY_ARM": "ARM-IMPORT",
                "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_REPOSITORY": REPO, "GITHUB_SHA": q1,
                "GH_CUSTODY_SERVED": str(served),
                "PATH": str(bindir) + os.pathsep
                + os.environ["PATH"]})
    wrapper = ROOT / "tools" / "candidate-custody"
    assert os.access(wrapper, os.X_OK), "CLI wrapper is missing"
    proc = subprocess.run(
        [str(wrapper), "import", "--request", str(request_path),
         "--out", str(out), "--harness-bin",
         custody_base.harness_bin()],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=str(fix["root"]), env=env)
    assert proc.returncode == 0, proc.stderr
    assert (out / "SUBJECTS.txt").is_file()
    rerun = subprocess.run(
        [str(wrapper), "import", "--request", str(request_path),
         "--out", str(out), "--harness-bin",
         custody_base.harness_bin()],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        cwd=str(fix["root"]), env=env)
    assert rerun.returncode == 1
    assert "candidate-custody" in rerun.stderr


def _release_workflow():
    yaml = pytest.importorskip("yaml")
    path = ROOT / ".github" / "workflows" / "release.yml"
    return yaml.safe_load(path.read_text())


def test_release_workflow_parses_and_shells_check():
    doc = _release_workflow()
    assert {"seal", "qualify", "sign", "import", "dry-run",
            "promote"} <= set(doc["jobs"])
    for job, spec in sorted(doc["jobs"].items()):
        for step in spec.get("steps", []):
            if "run" not in step:
                continue
            proc = subprocess.run(
                ["bash", "-n"], input=step["run"], text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE)
            assert proc.returncode == 0, "%s: %s" % (
                job, proc.stderr)


def test_release_checkouts_use_no_input_ref():
    doc = _release_workflow()
    for job, spec in sorted(doc["jobs"].items()):
        for step in spec.get("steps", []):
            if not str(step.get("uses", "")).startswith(
                    "actions/checkout@"):
                continue
            ref = (step.get("with") or {}).get("ref", "")
            assert "${{ inputs" not in str(ref), job


def test_release_sign_job_has_no_source_checkout():
    doc = _release_workflow()
    text = json.dumps(doc["jobs"]["sign"])
    assert "source_commit" not in text
    assert "SOURCE_COMMIT" not in text
    assert "candidate-src" not in text


def test_release_seal_job_holds_no_secrets():
    doc = _release_workflow()
    text = json.dumps(doc["jobs"]["seal"])
    assert "secrets." not in text
    assert "QUALIFIER_SIGNING_KEY" not in text
    assert "GH_TOKEN" not in text


def test_release_checkouts_persist_no_credentials():
    doc = _release_workflow()
    seen = 0
    for job, spec in sorted(doc["jobs"].items()):
        for step in spec.get("steps", []):
            if not str(step.get("uses", "")).startswith(
                    "actions/checkout@"):
                continue
            seen += 1
            assert (step.get("with") or {}).get(
                "persist-credentials") is False, job
    assert seen == 6, seen


def test_release_seal_permissions_are_minimal():
    doc = _release_workflow()
    assert doc["jobs"]["seal"]["permissions"] == {
        "contents": "read", "actions": "write"}


def test_release_custody_runs_no_sealed_harness():
    doc = _release_workflow()
    whole = json.dumps(doc["jobs"])
    assert "sealed/memveil-release-entry" not in whole
    assert "sealed-unsigned/memveil-release-entry" not in whole
    assert "QUALIFIER_SIGNING_KEY" in whole
    keyed = [job for job, spec in doc["jobs"].items()
             if "QUALIFIER_SIGNING_KEY" in json.dumps(spec)]
    assert keyed == ["sign"], keyed
    for job in ("import", "dry-run", "promote"):
        text = json.dumps(doc["jobs"][job])
        assert "cargo build -p memveil-release-entry" in text, job
        assert "cargo fetch --locked" in text, job
        found = [line.strip() for step in doc["jobs"][job]["steps"]
                 for line in str(step.get("run", "")).splitlines()
                 if "--harness-bin" in line]
        assert found, job
        for line in found:
            assert "sealed" not in line, (job, line)
            assert "target/debug/memveil-release-entry" in line, \
                (job, line)
    assert "--harness-bin" not in json.dumps(
        doc["jobs"]["qualify"])


def test_release_qualify_extracts_to_fresh_path():
    doc = _release_workflow()
    steps = doc["jobs"]["qualify"]["steps"]
    collect = next(step for step in steps
                   if "campaign evidence" in step.get("name", ""))
    for line in collect["run"].splitlines():
        words = line.strip().split()
        if not words or words[0] != "mkdir":
            continue
        targets = [word for word in words[1:]
                   if not word.startswith("-")]
        assert "evidence" not in targets, line


def test_release_qualify_uses_the_returned_inner_root():
    doc = _release_workflow()
    steps = doc["jobs"]["qualify"]["steps"]
    collect = next(step for step in steps
                   if "campaign evidence" in step.get("name", ""))
    assert "inner = candidate.safe_extract(" in collect["run"]
    assert "EVIDENCE_DIR=$(python3" in collect["run"]
    assert "GITHUB_ENV" in collect["run"]
    assert '"$EVIDENCE_DIR"/' in collect["run"]
    export = next(step for step in steps
                  if "tested payload" in step.get("name", ""))
    assert '"$EVIDENCE_DIR"' in export["run"]
    assert "--evidence-dir evidence" not in export["run"]
    assert '"evidence/' not in export["run"]
    assert "evidence/qualification.json" not in export["run"]


def test_release_import_attests_stored_subjects():
    m = api()
    doc = _release_workflow()
    job = doc["jobs"]["import"]
    assert job["permissions"].get("attestations") == "write"
    steps = [step for step in job["steps"]
             if "attest" in str(step.get("uses", "")).lower()]
    assert steps, "import job attests nothing"
    text = json.dumps(steps)
    assert m.PREDICATE in text
    assert "custody-out/stored" in text


def test_release_dryrun_stands_alone():
    doc = _release_workflow()
    assert doc["jobs"]["dry-run"]["if"] == \
        "inputs.mode == 'dry-run'"


def test_release_modes_gate_each_stage():
    doc = _release_workflow()
    trigger = doc.get("on", doc.get(True))
    modes = trigger["workflow_dispatch"]["inputs"]["mode"][
        "options"]
    assert modes == ["seal", "import", "dry-run", "promote"]
    assert doc["jobs"]["seal"]["if"] == "inputs.mode == 'seal'"
    assert doc["jobs"]["sign"]["if"] == "inputs.mode == 'seal'"
    assert doc["jobs"]["qualify"]["if"] == \
        "inputs.mode == 'seal'"
    assert doc["jobs"]["import"]["if"] == \
        "inputs.mode == 'import'"
    assert "promote_authorization" in doc["jobs"]["promote"][
        "if"]
    for job in ("import", "dry-run", "promote"):
        assert "needs" not in doc["jobs"][job], job


def test_release_draft_lookups_list_and_filter():
    doc = _release_workflow()
    whole = json.dumps(doc["jobs"])
    assert "releases/tags/" not in whole
    assert "gh release download" not in whole
    for job in ("qualify", "import"):
        text = json.dumps(doc["jobs"][job])
        assert "find_holding_draft" in text, job
    assert "download_draft_asset" in json.dumps(
        doc["jobs"]["qualify"])


def test_release_qualify_reads_qualification_beside_evidence():
    doc = _release_workflow()
    steps = doc["jobs"]["qualify"]["steps"]
    collect = next(step for step in steps
                   if "campaign evidence" in step.get("name", ""))
    assert "evidence-dl/qualification.json" in collect["run"]
    export = next(step for step in steps
                  if "tested payload" in step.get("name", ""))
    assert export["run"].count(
        "--qualification evidence-dl/qualification.json") == 2
    assert '"$EVIDENCE_DIR"/qualification.json' not in export[
        "run"]


def test_release_qualify_consumes_same_run_seal():
    doc = _release_workflow()
    qualify = doc["jobs"]["qualify"]
    needs = qualify.get("needs", [])
    if isinstance(needs, str):
        needs = [needs]
    assert "seal" in needs and "sign" in needs
    # The sealed bytes come from this run's own artifact,
    # never from a second dispatch's rebuild.
    collect = next(
        step for step in qualify["steps"]
        if "campaign evidence" in step.get("name", ""))
    assert 'gh run download "$GITHUB_RUN_ID"' in collect["run"]
    assert '-n "sealed-$CANDIDATE_SHA256"' in collect["run"]
    # No second-dispatch machinery remains: no
    # draft-presence output gates the job, and no step
    # triggers another workflow run.
    assert "outputs" not in doc["jobs"]["sign"]
    whole = json.dumps(doc["jobs"])
    assert "needs.sign.outputs.present" not in whole
    assert "steps.draft.outputs" not in whole
    for job, spec in sorted(doc["jobs"].items()):
        for step in spec.get("steps", []):
            run = str(step.get("run", ""))
            assert "gh workflow run" not in run, job
            assert "/dispatches" not in run, job


def test_release_custody_stages_never_rebuild():
    doc = _release_workflow()
    forbidden = ("package-tarball", "package-deb",
                 "package-rpm", "sbom-emit", "candidate seal",
                 "candidate provenance", "sign-checksums",
                 "bpf-linker", "nightly-", "--release",
                 "candidate-src")
    for job in ("import", "dry-run", "promote"):
        text = json.dumps(doc["jobs"][job])
        for marker in forbidden:
            assert marker not in text, (job, marker)


def test_release_promote_needs_no_dryrun():
    doc = _release_workflow()
    needs = doc["jobs"]["promote"].get("needs", [])
    if isinstance(needs, str):
        needs = [needs]
    assert "dry-run" not in needs


def test_release_consumers_take_recorded_import_ids():
    doc = _release_workflow()
    trigger = doc.get("on", doc.get(True))
    inputs = trigger["workflow_dispatch"]["inputs"]
    assert "import_run_id" in inputs
    assert "import_artifact_id" in inputs
    for job in ("dry-run", "promote"):
        text = json.dumps(doc["jobs"][job])
        assert "IMPORT_RUN_ID" in text, job
        assert "IMPORT_ARTIFACT_ID" in text, job
        assert "packaging/qualifications/remote.json" not in text, \
            job


def test_release_consumers_never_import_or_attest():
    doc = _release_workflow()
    for job in ("dry-run", "promote"):
        spec = doc["jobs"][job]
        for step in spec.get("steps", []):
            uses = str(step.get("uses", ""))
            assert "actions/upload-artifact" not in uses, job
            assert "actions/attest" not in uses, job
            run = str(step.get("run", ""))
            assert "gh release upload" not in run, job
            assert "candidate-custody import" not in run, job
        text = json.dumps(spec)
        assert "attestations: write" not in text, job
        assert "actions: write" not in text, job


def test_release_digest_never_in_shell():
    doc = _release_workflow()
    for job, spec in sorted(doc["jobs"].items()):
        for step in spec.get("steps", []):
            if "run" not in step:
                continue
            assert "${{ inputs.candidate_sha256 }}" \
                not in step["run"], job
            assert "${{ inputs.source_commit }}" \
                not in step["run"], job


def test_release_version_binding():
    m = api()
    for version, claim in [("0.1.1", "ordinary-preview"),
                           ("0.2.0", "snp-journal"),
                           ("0.3.0", "security-workflow")]:
        assert m.verify_release_version(
            "v" + version, version, version, claim) is None
    for tag, binary, source, claim in [
            ("v0.1.1", "0.1.0", "0.1.0", "ordinary-preview"),
            ("v0.2.0", "0.2.0", "0.2.0", "ordinary-preview"),
            ("v0.3.0", "0.3.0", "0.3.0", "snp-journal"),
            ("v0.1.1", "0.1.1", "0.1.0", "ordinary-preview"),
            ("v0.4.0", "0.4.0", "0.4.0", "security-workflow")]:
        with pytest.raises(ValueError):
            m.verify_release_version(tag, binary, source, claim)
