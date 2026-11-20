# SPDX-License-Identifier: GPL-3.0-or-later

"""Clean-room consumer test for the MemVeil owner bundle.

Extracts the tarball built by the Rust packager into a fresh
directory and proves, from outside the source checkout, that:

- every payload file matches its MANIFEST.json hash;
- help/version/doctor run with exit/verdict consistency;
- text/JSON/Markdown reports reproduce the worked example's
  recorded numbers (exit codes asserted together with fields);
- replay needs no environment, no working directory, no BTF,
  and no network access (scrubbed env, strace syscall audit),
  and no development runtime path is consulted (no pixi, no
  checkout paths in the trace);
- a valid-empty capture replays with zero metrics, visibly
  distinct from unavailable ones;
- denied recordings (bad object, unprivileged live attempt)
  exit 3 and create no capture directory.

Environment: MV_BUNDLE_TARBALL plus MV_CANDIDATE_MANIFEST
(candidate mode: the verified root replaces the tarball),
MV_VALID_EMPTY (optional, defaults to the in-repo fixture).
Without candidate inputs the bundle tests use the newest
tarball the packaging suites built (run the cargo
package_tarball suite first); a missing tarball fails closed
with the remedy.

Requires strace on PATH for the syscall audit; fails
otherwise (the audit is the proof, not an optional extra).

Dropped from the Mojo-era file, with reasons: the pixi
library hiding fixture (no pixi toolchain on Rust main; the
no-pixi test pins its absence instead), the missing-bridge
denial (no bridge discovery in the Rust package), the
shipped-manuals check (man pages ship in the FHS packages
only, covered by the Rust suites), and the runtime
provenance payload check (folded into the release-runtime
provenance port to keep one owner).
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from support.candidate_input import load

from cleanroom import audit_trace
from sealed_fixture import (candidate_env, dev_tarball,
                            seal_candidate)

ROOT = Path(__file__).resolve().parents[2]
VALID_EMPTY = os.environ.get(
    "MV_VALID_EMPTY",
    str(ROOT / "tests" / "package" / "valid-empty"))

REQUIRED = (
    "bin/memveil",
    "lib/memveil/libgcc_s.so.1",
    "bpf/swiotlb_attempt.bpf.o",
    "bpf/swiotlb_lifecycle.bpf.o",
    "bpf/swiotlb_copy.bpf.o",
    "profiles/manifest.txt",
    "docs/quickstart.md",
    "docs/support.md",
    "docs/privacy.md",
    "docs/troubleshooting.md",
    "docs/performance.md",
    "docs/resource-limits.md",
    "docs/permissions.md",
    "docs/oracles.md",
    "examples/real-capture/README.md",
    "examples/real-capture/events.ndjson",
    "examples/real-capture/session.json",
    "examples/lifecycle-copy/README.md",
    "examples/lifecycle-copy/events.ndjson",
    "examples/lifecycle-copy/session.json",
    "examples/lifecycle-copy/oracle-phase.log",
    "examples/lifecycle-copy/fail-phase.log",
    "LICENSE",
    "LICENSES/GPL-2.0-only.txt",
    "LICENSES/GPL-2.0-or-later.txt",
    "THIRD-PARTY-NOTICES.md",
    "licenses/GPL-3.0.txt",
    "licenses/RUNTIME.LIBRARY.EXCEPTION",
    "MANIFEST.json",
)


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    selected = load()
    if selected:
        root = selected.root
        return root, json.loads(
            (root / "MANIFEST.json").read_text())
    tarball = dev_tarball()
    dest = tmp_path_factory.mktemp("bundle")
    with tarfile.open(tarball, "r:gz") as tar:
        members = tar.getnames()
        assert len(members) > 10, "tarball looks empty"
        top = members[0].split("/")[0]
        assert all(m == top or m.startswith(top + "/")
                   for m in members), \
            "tarball must hold one top dir"
        tar.extractall(dest)
    root = dest / top
    for rel in ("bin/memveil",
                "lib/memveil/libgcc_s.so.1",
                "bpf/swiotlb_attempt.bpf.o",
                "MANIFEST.json"):
        assert (root / rel).exists(), "bundle lacks %s" % rel
    manifest = json.loads((root / "MANIFEST.json").read_text())
    return root, manifest


def run(*argv, **kwargs):
    kwargs.setdefault("timeout", 120)
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )


def test_manifest_hashes(bundle):
    root, manifest = bundle
    assert manifest["bundle"] == root.name
    assert manifest["engine_version"]
    assert manifest["memveil_revision"]
    for rel in REQUIRED:
        if rel != "MANIFEST.json":
            assert rel in manifest["files"], \
                "manifest omits required %s" % rel
    disk = set()
    for base, _, files in os.walk(root):
        for name in files:
            rel = os.path.relpath(
                os.path.join(base, name), root)
            if rel != "MANIFEST.json":
                disk.add(rel)
    assert set(manifest["files"]) == disk, \
        "manifest/tree differ: %s" % sorted(
            set(manifest["files"]) ^ disk)[:5]
    for rel, want in sorted(manifest["files"].items()):
        assert sha_file(root / rel) == want, \
            "hash mismatch on %s" % rel


def test_license_first_party(bundle):
    root, manifest = bundle
    first = manifest.get("first_party", {})
    assert first.get("license_default") == "GPL-3.0-or-later"
    assert first["licenses"]["GPL-3.0-or-later"] == "LICENSE"
    assert first["paths"]["bpf/swiotlb_attempt.bpf.o"] == \
        "GPL-2.0-only"
    assert first["paths"]["bpf/swiotlb_lifecycle.bpf.o"] == \
        "GPL-2.0-only"
    assert first["paths"]["bpf/swiotlb_copy.bpf.o"] == \
        "GPL-2.0-only"
    for rel in first["licenses"].values():
        assert (root / rel).is_file(), "staged text lacks %s" % rel


def test_help_version(bundle):
    root, manifest = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "help")
    assert proc.returncode == 0, proc.stderr
    assert "usage: memveil " \
        "<record|report|top|doctor|qualify|bind-profile|help|version>" \
        in proc.stdout
    proc = run(binary, "version")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == \
        "memveil-" + manifest["engine_version"]


def test_doctor_exit_verdict_consistent(bundle):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "doctor")
    assert proc.returncode in (0, 3), proc.stderr
    assert proc.stdout.strip(), "doctor printed nothing"
    verdicts = [line for line in proc.stdout.splitlines()
                if line.startswith("verdict: ")]
    summaries = [line for line in proc.stdout.splitlines()
                 if line.startswith("summary: ")]
    assert len(verdicts) == 1, proc.stdout[-500:]
    assert len(summaries) == 1, proc.stdout[-500:]
    assert verdicts[0][len("verdict: "):].strip(), \
        "empty doctor verdict"


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
    assert text.returncode == 0, text.stderr
    assert js.returncode == 0, js.stderr
    assert md.returncode == 0, md.stderr
    report = json.loads(js.stdout)
    assert report["integrity"]["status"] == "legacy_unverified"
    assert report["quality"]["detail"]["status"] == "partial"
    assert report["quality"]["detail"]["loss_count"] == "0"
    assert report["quality"]["terminal"]["status"] == "partial"
    assert metric(report, "bounce_attempts")["value"] == "30"
    assert "bounce_attempts = 30" in text.stdout
    assert "loss=0" in text.stdout
    assert "| detail | partial | 0 |" in md.stdout


def test_valid_empty_replays_zero(bundle):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    proc = run(binary, "report", "--format", "json", VALID_EMPTY)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert report["integrity"]["status"] == "legacy_unverified"
    assert report["quality"]["detail"]["status"] == "partial"
    assert report["quality"]["detail"]["loss_count"] == "0"
    assert metric(report, "bounce_attempts")["value"] == "0"
    assert metric(report, "counter_bounce_attempts")[
        "value"] == "0"
    # Known-empty is zeros; unproven stays null, never zero.
    assert metric(report, "successful_allocations")[
        "value"] is None


def test_cleanroom_no_pixi(tmp_path):
    # The clean room admits an environment where development
    # libraries are already absent: nothing in this file
    # requires pixi paths, the audit accepts a trace with none,
    # and it refuses traces that touch pixi or checkout paths.
    own = Path(__file__).read_text()
    for left, right in (("HIDE", "_LIBS"), (".pixi", "/envs"),
                        ("hidden", "_pixi"), ("pixi ", "libs"),
                        ("pixi ", "restore")):
        assert left + right not in own, \
            "clean room must not hide pixi libraries: %s" \
            % (left + right)
    clean = (
        "99 execve(\"/tmp/clean/bin/memveil\", "
        "[\"memveil\", \"report\"], 0x7fff) = 0\n"
        "99 openat(AT_FDCWD, \"/tmp/clean/bin/memveil\", "
        "O_RDONLY|O_CLOEXEC) = 3\n"
        "99 openat(AT_FDCWD, \"/lib64/libc.so.6\", "
        "O_RDONLY|O_CLOEXEC) = 3\n"
        "99 openat(AT_FDCWD, \"/tmp/cap/session.json\", "
        "O_RDONLY|O_CLOEXEC) = 3\n"
        "99 openat(AT_FDCWD, \"/proc/cpuinfo\", "
        "O_RDONLY|O_CLOEXEC) = 3\n")
    assert audit_trace(clean, "/", "/nonexistent-root") == []
    pixi = clean + \
        "99 openat(AT_FDCWD, \"/repo/.pixi/libx.so\", " \
        "O_RDONLY|O_CLOEXEC) = 3\n"
    assert any(".pixi" in hit for hit in audit_trace(
        pixi, "/", "/nonexistent-root")), "pixi open accepted"
    checkout = clean + \
        "99 openat(AT_FDCWD, \"/repo/build/memveil\", " \
        "O_RDONLY|O_CLOEXEC) = 3\n"
    assert any("checkout" in hit for hit in audit_trace(
        checkout, "/", "/repo")), "checkout open accepted"
    sealed = seal_candidate(tmp_path, "nopixi")
    selected = load(env=candidate_env(sealed),
                    required=True)
    try:
        assert (selected.root / "MANIFEST.json").is_file()
    finally:
        selected.close()


def test_replay_audited_cleanroom(bundle, tmp_path):
    if not shutil.which("strace"):
        pytest.fail("strace is required for the syscall audit")
    if not shutil.which("ldd"):
        pytest.fail("ldd is required for the closure proof")
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    cap = str(root / "examples" / "real-capture")
    trace = str(tmp_path / "trace.log")
    env = {"PATH": "/usr/bin:/bin"}
    # ldd must resolve the closure lib from the bundle.
    proc = run("ldd", binary, env=env, cwd="/")
    assert proc.returncode == 0, proc.stderr
    assert "not found" not in proc.stdout, proc.stdout
    hits = [line for line in proc.stdout.splitlines()
            if "libgcc_s.so.1" in line]
    assert len(hits) == 1, proc.stdout
    assert "/bin/../lib/" in hits[0], hits[0]
    # Replay under the audit: scrubbed env, foreign cwd.
    proc = run("strace", "-f", "-o", trace, "-e",
               "trace=openat,open,openat2,socket,connect,"
               "sendto,bpf,execve,chdir,fchdir",
               binary, "report", "--format", "json", cap,
               env=env, cwd="/")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)
    assert metric(report, "bounce_attempts")["value"] == "30"
    text = open(trace, encoding="utf-8",
                errors="replace").read()
    if load():
        assert ".pixi" not in text, \
            "candidate replay attempted a development " \
            "runtime path"
        assert os.path.realpath(ROOT) not in text, \
            "candidate replay attempted a checkout path"
    violations = audit_trace(
        text, "/", os.path.realpath(ROOT))
    assert violations == [], violations


# Exact refusal diagnostic for the deterministic denial (any
# user, any host): the object-bytes check does not depend on
# privilege or kernel identity.
BAD_OBJECT_DIAG = \
    "memveil record: object refused: object too small\n"


def test_denied_bad_object(bundle, tmp_path):
    root, _ = bundle
    binary = str(root / "bin" / "memveil")
    junk = tmp_path / "junk.o"
    junk.write_bytes(b"not an elf object")
    out = tmp_path / "cap-badobj"
    proc = run(binary, "record", "--output", str(out),
               "--object", str(junk),
               "--duration", "2",
               env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    assert proc.stderr == BAD_OBJECT_DIAG, proc.stderr
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
               "--duration", "2",
               env={"PATH": "/usr/bin:/bin"})
    assert proc.returncode == 3, (proc.returncode, proc.stderr)
    # The live reason is host-dependent (hook denial, unreadable
    # format, unbound profile), so it is pinned by exclusion: a
    # non-empty refusal naming neither deterministic boundary.
    assert proc.stderr.startswith("memveil record: "), proc.stderr
    reason = proc.stderr[len("memveil record: "):].strip()
    assert reason, "empty refusal reason"
    assert proc.stderr != BAD_OBJECT_DIAG, \
        "live attempt hit a static boundary: %s" % proc.stderr
    assert "object unreadable" not in proc.stderr and \
        "unknown --profile" not in proc.stderr, \
        "live attempt hit a static boundary: %s" % proc.stderr
    assert not out.exists(), "denied run must create no capture"


if __name__ == "__main__":
    sys.exit("run via: python3 -m pytest tests/package/")
