# SPDX-License-Identifier: GPL-3.0-or-later

"""Clean-room consumer test for the MemVeil owner bundle.

Extracts the tarball built by tools/package into a fresh directory
and proves, from outside the source checkout, that:

- every payload file matches its MANIFEST.json hash;
- help/version/doctor run with exit/verdict consistency;
- text/JSON/Markdown reports reproduce the worked example's
  recorded numbers (exit codes asserted together with fields);
- replay needs no Pixi, no environment, no working directory,
  no BTF, no libbpf, and no network (pixi libs hidden, scrubbed
  env, strace syscall audit);
- a valid-empty capture replays with zero metrics, visibly
  distinct from unavailable ones;
- denied recordings (bad object, missing bridge, unprivileged
  live attempt) exit 3 and create no capture directory.

Environment: MV_BUNDLE_TARBALL (required), MV_REPO (required,
to locate the pixi libs to hide), MV_VALID_EMPTY (required,
valid-empty fixture dir).

Requires strace on PATH for the syscall audit; fails otherwise
(the audit is the proof, not an optional extra).
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile

import pytest

from cleanroom import audit_trace, check_manifest

TARBALL = os.environ.get("MV_BUNDLE_TARBALL", "")
REPO = os.environ.get("MV_REPO", "")
VALID_EMPTY = os.environ.get("MV_VALID_EMPTY", "")

REQUIRED = (
    "bin/memveil",
    "lib/libbpf_mojo.so.1",
    "bpf/swiotlb_attempt.bpf.o",
    "profiles/manifest.txt",
    "docs/quickstart.md",
    "docs/support.md",
    "docs/privacy.md",
    "docs/troubleshooting.md",
    "docs/performance.md",
    "docs/resource-limits.md",
    "docs/permissions.md",
    "docs/oracles.md",
    "examples/real-capture/events.ndjson",
    "examples/real-capture/session.json",
    "LICENSE",
    "LICENSES/GPL-2.0-only.txt",
    "LICENSES/GPL-2.0-or-later.txt",
    "THIRD-PARTY-NOTICES.md",
    "THIRD-PARTY-NOTICES.libbpf-mojo.md",
    "licenses/GPL-3.0.txt",
    "licenses/LICENSE.BSD-2-Clause.libbpf",
    "licenses/LICENSE.mojo-compiler",
    "licenses/LICENSE.zlib",
    "licenses/NOTICE.mojo-runtime.md",
    "licenses/RUNTIME.LIBRARY.EXCEPTION",
    "licenses/Third-Party-Notices.mojo-compiler",
    "licenses/libbpf-mojo-LICENSE",
    "licenses/libbpf-mojo-LICENSES/GPL-2.0-only.txt",
    "licenses/libbpf-mojo-LICENSES/LLVM-exception.txt",
    "MANIFEST.json",
)

# Mojo runtime NEEDED names the bundle binary resolves from its
# own lib/ dir once the pixi copies are hidden.
HIDE_LIBS = (
    "libKGENCompilerRTShared.so",
    "libMSupportGlobals.so",
    "libAsyncRTRuntimeGlobals.so",
    "libstdc++.so.6",
    "libgcc_s.so.1",
)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    assert TARBALL and os.path.isfile(TARBALL), \
        "MV_BUNDLE_TARBALL must name the built tarball"
    assert REPO and os.path.isdir(REPO), "MV_REPO must name the checkout"
    assert VALID_EMPTY and os.path.isdir(VALID_EMPTY), \
        "MV_VALID_EMPTY must name the valid-empty fixture"
    dest = tmp_path_factory.mktemp("bundle")
    with tarfile.open(TARBALL, "r:gz") as tar:
        members = tar.getnames()
        assert len(members) > 10, "tarball looks empty"
        top = members[0].split("/")[0]
        assert all(m == top or m.startswith(top + "/")
                   for m in members), "tarball must hold one top dir"
        tar.extractall(dest)
    root = dest / top
    for rel in REQUIRED:
        assert (root / rel).exists(), "bundle lacks %s" % rel
    manifest = json.loads((root / "MANIFEST.json").read_text())
    return root, manifest


def run(*argv, **kwargs):
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, timeout=120, **kwargs,
    )


def test_manifest_hashes(bundle):
    root, manifest = bundle
    assert manifest["bundle"] == root.name
    assert manifest["engine_version"]
    assert manifest["memveil_revision"]
    assert manifest["libbpf_mojo"]["tarball_used_sha256"] == \
        manifest["libbpf_mojo"]["tarball_sha256"]
    problems = check_manifest(str(root), manifest)
    assert problems == [], problems
    for rel in REQUIRED:
        if rel != "MANIFEST.json":
            assert rel in manifest["files"], \
                "manifest omits required %s" % rel
    for rel, want in sorted(manifest["files"].items()):
        assert sha_file(root / rel) == want, \
            "hash mismatch on %s" % rel


def test_license_texts_and_first_party(bundle):
    root, manifest = bundle
    first = manifest.get("first_party", {})
    assert first.get("license_default") == "GPL-3.0-or-later"
    assert first["licenses"]["GPL-3.0-or-later"] == "LICENSE"
    assert first["paths"]["bpf/swiotlb_attempt.bpf.o"] == \
        "GPL-2.0-only"
    for rel in first["licenses"].values():
        assert (root / rel).is_file(), "staged text lacks %s" % rel
        assert (root / rel).stat().st_size > 1000, \
            "staged text too small: %s" % rel
    own = (root / "THIRD-PARTY-NOTICES.md").read_text()
    assert manifest["libbpf_mojo"]["version"] in own
    assert manifest["libbpf_mojo"]["source_commit"] in own
    assert "licenses/LICENSE.mojo-compiler" in own
    assert "not shipped in `lib/`" in own
    lmb = (root / "THIRD-PARTY-NOTICES.libbpf-mojo.md").read_text()
    assert "BSD 2-Clause" in lmb


def test_shipped_manuals_resolve(bundle):
    import re
    root, _ = bundle
    missing = []
    for rel in ("docs/quickstart.md", "docs/support.md"):
        text = (root / rel).read_text()
        refs = set(re.findall(r"\(([\w./-]+\.md)(?:#[\w-]+)?\)", text))
        refs |= set(re.findall(r"`([\w./-]+\.md)`", text))
        for ref in sorted(refs):
            if ref.startswith("examples/"):
                target = root / ref
            else:
                target = root / "docs" / ref
            if not target.is_file():
                missing.append("%s -> %s" % (rel, ref))
    assert missing == [], missing


def test_help_version(bundle):
    root, manifest = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "help")
    assert proc.returncode == 0, proc.stderr
    assert "usage: memveil <record|report|top|doctor|help|version>" in proc.stdout
    proc = run(binary, "version")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == \
        "memveil-" + manifest["engine_version"]


def test_doctor_exit_verdict_consistent(bundle):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "doctor")
    assert proc.returncode in (0, 3), proc.stderr
    if proc.returncode == 0:
        assert "verdict: ready" in proc.stdout
    else:
        assert "verdict: unavailable" in proc.stdout
    assert "summary: " in proc.stdout
    proc = run(binary, "doctor", "--bogus")
    assert proc.returncode == 2


def metric(report, name):
    hits = [m for m in report["metrics"] if m["name"] == name]
    assert hits, "metric %s missing" % name
    return hits[0]


def test_report_example_all_formats(bundle):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    cap = str(root / "examples" / "real-capture")
    text = run(binary, "report", "--format", "text", cap)
    js = run(binary, "report", "--format", "json", cap)
    md = run(binary, "report", "--format", "markdown", cap)
    assert text.returncode == 4, text.stderr
    assert js.returncode == 4, js.stderr
    assert md.returncode == 4, md.stderr
    report = json.loads(js.stdout)
    assert report["quality"]["detail"]["status"] == "complete_for_scope"
    assert report["quality"]["detail"]["loss_count"] == "0"
    assert report["quality"]["terminal"]["status"] == "partial"
    assert metric(report, "bounce_attempts")["value"] == "30"
    assert "bounce_attempts = 30" in text.stdout
    assert "loss=0" in text.stdout
    assert "| detail | complete_for_scope | 0 |" in md.stdout


def test_valid_empty_replays_zero(bundle):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "report", "--format", "json", VALID_EMPTY)
    assert proc.returncode == 4, proc.stderr
    report = json.loads(proc.stdout)
    assert report["quality"]["detail"]["status"] == \
        "complete_for_scope"
    assert report["quality"]["detail"]["loss_count"] == "0"
    assert metric(report, "bounce_attempts")["value"] == "0"
    assert metric(report, "counter_bounce_attempts")["value"] == "0"
    # Known-empty is zeros; unproven stays null, never zero.
    assert metric(report, "successful_allocations")["value"] is None


class TestCleanRoom:
    @pytest.fixture()
    def hidden_pixi(self, tmp_path):
        hide = tmp_path / "hide"
        hide.mkdir()
        libdir = os.path.join(REPO, ".pixi", "envs", "default", "lib")
        missing = [n for n in HIDE_LIBS
                   if not os.path.isfile(os.path.join(libdir, n))]
        assert not missing, "pixi libs missing: %s" % missing
        moved = []
        try:
            for name in HIDE_LIBS:
                shutil.move(os.path.join(libdir, name),
                            str(hide / name))
                moved.append(name)
            yield
        finally:
            errors = []
            for name in moved:
                try:
                    shutil.move(str(hide / name),
                                os.path.join(libdir, name))
                except OSError as err:
                    errors.append("%s: %s" % (name, err))
            assert not errors, \
                "pixi restore failed: %s" % errors

    def test_replay_without_pixi_env_cwd(self, bundle, hidden_pixi,
                                         tmp_path):
        if not shutil.which("strace"):
            pytest.fail("strace is required for the syscall audit")
        root, _ = bundle
        binary = str(root / "bin" / "memveil")
        cap = str(root / "examples" / "real-capture")
        trace = str(tmp_path / "trace.log")
        env = {"PATH": "/usr/bin:/bin"}
        # ldd must resolve every Mojo runtime lib from the bundle.
        proc = run("ldd", binary, env=env, cwd="/")
        assert proc.returncode == 0, proc.stderr
        for name in HIDE_LIBS:
            hits = [ln for ln in proc.stdout.splitlines()
                    if name in ln]
            assert len(hits) == 1, (name, proc.stdout)
            assert "/bin/../lib/" in hits[0], hits[0]
            assert ".pixi" not in hits[0], hits[0]
        # Replay under the audit: scrubbed env, foreign cwd.
        proc = run("strace", "-f", "-o", trace, "-e",
                   "trace=openat,open,openat2,socket,connect,"
                   "sendto,bpf,execve,chdir,fchdir",
                   binary, "report", "--format", "json", cap,
                   env=env, cwd="/")
        assert proc.returncode == 4, proc.stderr
        report = json.loads(proc.stdout)
        assert metric(report, "bounce_attempts")["value"] == "30"
        text = open(trace, encoding="utf-8",
                    errors="replace").read()
        violations = audit_trace(
            text, "/", os.path.realpath(REPO))
        assert violations == [], violations


# Exact refusal diagnostics for the deterministic denials (any
# user, any host): the object bytes and the bridge lookup do not
# depend on privilege or kernel identity.
BAD_OBJECT_DIAG = "memveil record: object refused: object too small\n"
NO_BRIDGE_DIAG = \
    "memveil record: no bridge: pass --bridge or set LMB_NATIVE_LIB\n"


def test_denied_bad_object(bundle, tmp_path):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    junk = tmp_path / "junk.o"
    junk.write_bytes(b"not an elf object")
    out = tmp_path / "cap-badobj"
    proc = run(binary, "record", "--output", str(out),
               "--object", str(junk),
               "--bridge", str(root / "lib" / "libbpf_mojo.so.1"),
               "--duration", "2",
               env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert proc.stderr == BAD_OBJECT_DIAG, proc.stderr
    assert not out.exists(), "denied run must create no capture"


def test_denied_missing_bridge(bundle, tmp_path):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    out = tmp_path / "cap-nobridge"
    env = {"PATH": "/usr/bin:/bin"}
    proc = run(binary, "record", "--output", str(out),
               "--object",
               str(root / "bpf" / "swiotlb_attempt.bpf.o"),
               "--duration", "2", env=env)
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert proc.stderr == NO_BRIDGE_DIAG, proc.stderr
    assert not out.exists(), "denied run must create no capture"


def test_denied_unprivileged_live(bundle, tmp_path):
    if os.geteuid() == 0:
        pytest.skip("live denial needs an unprivileged caller")
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    out = tmp_path / "cap-live"
    proc = run(binary, "record", "--output", str(out),
               "--object",
               str(root / "bpf" / "swiotlb_attempt.bpf.o"),
               "--bridge", str(root / "lib" / "libbpf_mojo.so.1"),
               "--duration", "2",
               env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    # The live reason is host-dependent (hook denial, unreadable
    # format, unbound profile), so it is pinned by exclusion: a
    # non-empty refusal naming neither deterministic boundary.
    assert proc.stderr.startswith("memveil record: "), proc.stderr
    reason = proc.stderr[len("memveil record: "):].strip()
    assert reason, "empty refusal reason"
    assert proc.stderr not in (BAD_OBJECT_DIAG, NO_BRIDGE_DIAG), \
        "live attempt hit a static boundary: %s" % proc.stderr
    assert not out.exists(), "denied run must create no capture"


if __name__ == "__main__":
    sys.exit("run via: python3 -m pytest tests/package/")
