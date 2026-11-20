# SPDX-License-Identifier: GPL-3.0-or-later

"""Release-runtime gate: the extracted candidate fails closed.

Gap cases beyond the clean-room replay lane, all against the
extracted owner bundle: an absent BPF object and an unknown
--profile each refuse with exit 3 and no capture directory;
top replays offline; and the bundle's loader layout,
provenance, licenses, permissions, and tarball modes match the
manifest plus the packager's system allowlist.

Installed mapping: the sealed .deb/.rpm pair install exactly
the candidate files closure (extra/missing/tampered members
refuse), the packaging journeys consume the sealed paths and
never rebuild, and candidate mode needs no build outputs.

Environment: MV_BUNDLE_TARBALL plus MV_CANDIDATE_MANIFEST
(candidate mode: the verified root replaces the tarball),
MV_VALID_EMPTY (optional, defaults to the in-repo fixture).
Without candidate inputs the behavioral tests use the newest
tarball the packaging suites built (run the cargo
package_tarball suite first); a missing tarball fails closed
with the remedy. The sealed-input tests build synthetic
candidates in tmp and need git, dpkg-deb, rpmbuild, cargo,
and bpf-linker on PATH.

Dropped from the Mojo-era file, with reasons: the replaced
bridge refusal (the Rust package has no dlopen bridge), the
runpath_abspaths unit (tools/package is gone; the Rust
loader_closure suite owns the guard), and the pixi-lock
provenance cross-check (no pixi lock on Rust main).
"""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from support.candidate_input import load

sys.path.insert(0, str(Path(__file__).resolve().parents[2]
                       / "tools"))
import candidate as protocol

from sealed_fixture import (candidate_env, dev_tarball,
                            seal_candidate)

ROOT = Path(__file__).resolve().parents[2]
VALID_EMPTY = os.environ.get(
    "MV_VALID_EMPTY",
    str(ROOT / "tests" / "package" / "valid-empty"))

BPF_OBJECTS = ("swiotlb_attempt.bpf.o", "swiotlb_lifecycle.bpf.o",
               "swiotlb_copy.bpf.o")

REQUIRED_MEMBERS = ("bin/memveil",
                    "lib/memveil/libgcc_s.so.1",
                    "bpf/swiotlb_attempt.bpf.o",
                    "MANIFEST.json")


def load_tarball_tool():
    path = ROOT / "scripts" / "package-tarball.py"
    loader = importlib.util.spec_from_file_location(
        "mvpacktarball", path)
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    return module


def load_deb_tool():
    path = ROOT / "scripts" / "package-deb.py"
    loader = importlib.util.spec_from_file_location(
        "mvpackdeb", path)
    module = importlib.util.module_from_spec(loader)
    loader.loader.exec_module(module)
    return module


PKG = load_tarball_tool()
DEBPKG = load_deb_tool()


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    selected = load()
    if selected:
        root = selected.root
        return root, json.loads(
            (root / "MANIFEST.json").read_text())
    tarball = dev_tarball()
    dest = tmp_path_factory.mktemp("release")
    with tarfile.open(tarball, "r:gz") as tar:
        members = tar.getnames()
        assert len(members) > 10, "tarball looks empty"
        top = members[0].split("/")[0]
        assert all(m == top or m.startswith(top + "/")
                   for m in members), \
            "tarball must hold one top dir"
        tar.extractall(dest)
    root = dest / top
    for rel in REQUIRED_MEMBERS:
        assert (root / rel).exists(), "bundle lacks %s" % rel
    manifest = json.loads((root / "MANIFEST.json").read_text())
    return root, manifest


def run(*argv, **kwargs):
    kwargs.setdefault("timeout", 120)
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )


def sha_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def test_absent_bpf_object_refused(bundle, tmp_path):
    root, _ = bundle
    trial = tmp_path / "noobj"
    shutil.copytree(root, trial)
    missing = trial / "bpf" / "swiotlb_attempt.bpf.o"
    missing.unlink()
    cap = tmp_path / "cap"
    proc = run(str(trial / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--object", str(missing),
               "--duration", "1", cwd=str(tmp_path))
    assert proc.returncode == 3, proc.stderr
    assert "object unreadable" in proc.stderr, proc.stderr
    assert not cap.exists(), "refused record left a capture dir"


def test_unknown_profile_refused(bundle, tmp_path):
    root, _ = bundle
    cap = tmp_path / "cap"
    proc = run(str(root / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--object",
               str(root / "bpf" / "swiotlb_attempt.bpf.o"),
               "--profile", "release-runtime-bogus-0",
               "--duration", "1", cwd=str(tmp_path))
    assert proc.returncode == 3, proc.stderr
    assert "unknown --profile" in proc.stderr, proc.stderr
    assert not cap.exists(), "refused record left a capture dir"


def test_top_replays_valid_empty(bundle):
    root, _ = bundle
    proc = run(str(root / "bin" / "memveil"), "top",
               "--interval", "1s", VALID_EMPTY)
    assert proc.returncode == 0, proc.stderr
    assert "--- refresh" in proc.stdout
    assert "bounce_attempts = 0" in proc.stdout


def needed(path):
    proc = run("readelf", "-d", str(path))
    assert proc.returncode == 0, proc.stderr
    names = []
    for line in proc.stdout.splitlines():
        if "(NEEDED)" in line and "[" in line:
            names.append(line.split("[")[1].split("]")[0])
    return names


def dynamic_strings(path):
    proc = run("readelf", "-d", str(path))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def test_loader_layout(bundle):
    root, manifest = bundle
    binary = root / "bin" / "memveil"
    dyn = dynamic_strings(binary)
    assert "$ORIGIN/../lib/memveil" in dyn, dyn
    assert "Library runpath:" in dyn or \
        "Library rpath:" not in dyn, dyn
    for line in dyn.splitlines():
        if "Library runpath:" in line or \
                "Library rpath:" in line:
            segment = line.split("[", 1)[1].split("]", 1)[0]
            assert all(not entry or
                       entry.startswith("$ORIGIN")
                       for entry in segment.split(":")), dyn
    proc = run("readelf", "-h", str(binary))
    assert proc.returncode == 0
    assert "X86-64" in proc.stdout, proc.stdout
    shipped = {path.split("/")[-1]
               for path in manifest["files"]
               if path.startswith("lib/")}
    allow = set(PKG.SYSTEM_ALLOW)
    targets = [binary] + sorted(
        (root / "lib" / "memveil").glob("*.so*"))
    assert len(targets) > 1, "bundle ships no closure lib"
    for target in targets:
        for name in needed(target):
            assert name in shipped or name in allow, \
                "%s needs %s: outside closure" % (
                    target.name, name)


def test_runtime_provenance_pinned(bundle):
    root, manifest = bundle
    prov = manifest["runtime_provenance"]
    libs = sorted(
        "lib/memveil/%s" % path.name
        for path in (root / "lib" / "memveil").glob("*.so*"))
    assert libs, "bundle lib/ holds no closure library"
    assert sorted(prov) == libs, prov
    for rel in libs:
        record = prov[rel]
        digest = sha_file(root / rel)
        assert digest == record["staged_sha256"], rel
        assert digest == record["member_sha256"], rel
        assert digest == \
            record["pre_normalization_sha256"], rel
        assert digest == manifest["files"][rel], rel
        assert record["member"].startswith("usr/lib/"), rel
        assert record["provider"], rel
        assert record["provider_version"], rel
        assert record["license"], rel


def test_runtime_licenses_match(bundle):
    root, manifest = bundle
    texts = manifest["runtime_licenses"]
    assert sorted(texts) == [
        "licenses/GPL-3.0.txt",
        "licenses/RUNTIME.LIBRARY.EXCEPTION",
    ], texts
    for rel, record in texts.items():
        digest = sha_file(root / rel)
        assert digest == record["sha256"], rel
        assert digest == manifest["files"][rel], rel


def test_permissions(bundle):
    root, _ = bundle
    binary = root / "bin" / "memveil"
    mode = os.stat(binary).st_mode
    assert mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH), \
        "bin/memveil is not executable"
    bad = []
    for base, _, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            mode = os.stat(full).st_mode
            if mode & stat.S_IWOTH or mode & (
                    stat.S_ISUID | stat.S_ISGID):
                bad.append(os.path.relpath(full, root))
    assert not bad, "; ".join(bad[:5])


def test_tar_members_normalized_modes():
    # The tarball carries explicit directory members (0755) and
    # normalized file modes (0644, executable bit kept), never
    # raw build-tree modes. Read the members themselves: the
    # extracted tree may mask modes through the umask.
    with tarfile.open(dev_tarball(), "r:gz") as tar:
        members = tar.getmembers()
    assert members, "tarball has no members"
    top = members[0].name.split("/")[0]
    dirs = [m for m in members if m.isdir()]
    assert dirs, "tarball must carry explicit directory members"
    assert any(m.name == top for m in dirs), \
        "tarball lacks top dir member %s" % top
    for member in dirs:
        assert stat.S_IMODE(member.mode) == 0o755, \
            "%s mode %o, want 755" % (member.name, member.mode)
    files = [m for m in members if m.isfile()]
    assert files, "tarball has no file members"
    binary = top + "/bin/memveil"
    assert any(m.name == binary for m in files), \
        "tarball lacks %s" % binary
    for member in files:
        mode = stat.S_IMODE(member.mode)
        if member.name == binary:
            assert mode == 0o755, \
                "%s mode %o, want 755" % (member.name, mode)
        else:
            assert mode in (0o644, 0o755), \
                "%s mode %o, want 644 or 755" % (
                    member.name, mode)


def test_bare_env_record_fails_past_discovery(bundle, tmp_path):
    # Zero-config: bundled record with an empty environment and
    # no --object must resolve the bundled objects. It then
    # refuses at a later gate (this host lacks readable
    # tracefs) or, on a qualified host, captures; it must never
    # fail discovery itself. Exit/capture accounting matches the
    # install-journey record probe exactly.
    root, _ = bundle
    cap = tmp_path / "cap"
    proc = run(str(root / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--duration", "1", cwd=str(tmp_path), env={})
    for missing in ("no bridge", "no object", "missing --object",
                    "cannot load profiles",
                    "cannot resolve profiles"):
        assert missing not in proc.stderr, proc.stderr
    assert proc.returncode in (0, 3, 4), proc.stderr
    if proc.returncode == 3:
        assert proc.stderr.strip(), \
            "refusal needs a diagnostic"
        assert not cap.exists(), \
            "refused record left a capture dir"
    else:
        assert cap.exists(), \
            "exit %d left no capture dir" % proc.returncode


def _extract_deb(deb, dest):
    assert shutil.which("dpkg-deb"), \
        "installed mapping requires dpkg-deb on PATH"
    proc = run("dpkg-deb", "-x", str(deb), str(dest))
    assert proc.returncode == 0, proc.stderr
    return dest


def _extract_rpm(rpm, dest):
    assert shutil.which("rpm2cpio"), \
        "installed mapping requires rpm2cpio on PATH"
    assert shutil.which("cpio"), \
        "installed mapping requires cpio on PATH"
    dump = subprocess.run(
        ["rpm2cpio", str(rpm)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert dump.returncode == 0, dump.stderr.decode()
    proc = subprocess.run(
        ["cpio", "-idm", "--quiet"], input=dump.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        cwd=str(dest))
    assert proc.returncode == 0, proc.stderr.decode()
    return dest


def _installed_set(root):
    found = set()
    for base, _, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            if os.path.islink(full):
                continue
            found.add(os.path.relpath(full, root).replace(
                os.sep, "/"))
    return found


def test_installed_closure_matches_candidate(tmp_path):
    # The sealed .deb/.rpm pair installs exactly the candidate
    # files closure: every manifest member lands at its mapped
    # FHS path with equal bytes, nothing is missing, and
    # nothing extra ships besides the generated deb files.
    sealed = seal_candidate(tmp_path, "closure")
    manifest = sealed["manifest"]
    selected = load(env=candidate_env(sealed))
    try:
        assert selected is not None
        assert selected.manifest == manifest
    finally:
        selected.close()
    expected = {protocol.installed_file_path(name)
                for name in manifest["files"]}
    generated = {"usr/share/doc/memveil/copyright",
                 "usr/share/doc/memveil/changelog.Debian.gz"}
    for role, extract in (("deb", _extract_deb),
                          ("rpm", _extract_rpm)):
        dest = tmp_path / ("installed-" + role)
        dest.mkdir()
        extract(sealed[role], dest)
        DEBPKG.verify_installed(str(dest), manifest)
        have = _installed_set(str(dest))
        assert expected <= have, \
            "%s lacks %s" % (role,
                             sorted(expected - have)[:3])
        assert have - expected <= generated, \
            "%s ships extra %s" % (
                role, sorted(have - expected)[:3])
    # Negative controls against the deb tree: a missing
    # member, tampered bytes, an extra docs file, and an
    # aliased member each refuse.
    dest = tmp_path / "installed-neg"
    dest.mkdir()
    _extract_deb(sealed["deb"], dest)
    victim = dest / "usr" / "bin" / "memveil"
    saved = victim.read_bytes()
    victim.unlink()
    with pytest.raises(ValueError):
        DEBPKG.verify_installed(str(dest), manifest)
    victim.write_bytes(b"tampered-by-test")
    with pytest.raises(ValueError):
        DEBPKG.verify_installed(str(dest), manifest)
    victim.write_bytes(saved)
    DEBPKG.verify_installed(str(dest), manifest)
    extra = dest / "usr" / "share" / "doc" / "memveil" \
        / "smuggled.txt"
    extra.write_text("not in the closure\n")
    with pytest.raises(ValueError):
        DEBPKG.verify_installed(str(dest), manifest)
    extra.unlink()
    alias = dest / "usr" / "bin" / "memveil"
    alias.unlink()
    alias.symlink_to("nowhere-alias-target")
    with pytest.raises(ValueError):
        DEBPKG.verify_installed(str(dest), manifest)


_binaries = {}


def _test_binary(name):
    found = _binaries.get(name)
    if found is not None and found.is_file():
        return found
    env = {key: value for key, value in os.environ.items()
           if key != "RUSTUP_TOOLCHAIN"}
    proc = subprocess.run(
        ["cargo", "test", "--locked", "--no-run",
         "--test", name],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    marker = "Executable tests/%s.rs (" % name
    for line in proc.stdout.splitlines() + \
            proc.stderr.splitlines():
        line = line.strip()
        if line.startswith(marker) and line.endswith(")"):
            found = Path(line[len(marker):-1])
            if not found.is_absolute():
                found = ROOT / found
            assert found.is_file(), \
                "cargo named a missing test binary: %s" % found
            _binaries[name] = found
            return found
    raise AssertionError(
        "cargo named no test binary for %s" % name)


def _run_sealed_suite(sealed, suite, target_dir, extra=None):
    binary = _test_binary(suite)
    assert binary is not None, suite
    env = {"PATH": os.environ.get("PATH", ""),
           "CARGO_TARGET_DIR": str(target_dir),
           "MV_RUSTPKG_REBUILD": "1"}
    env.update(candidate_env(sealed))
    if extra:
        env.update(extra)
    return subprocess.run(
        [str(binary), "sealed_inputs_used", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)


def test_sealed_inputs_used(tmp_path):
    # The install journeys consume the sealed .deb/.rpm paths
    # from the candidate manifest and never rebuild: the seal
    # carries a marker-named pair, rebuilds are requested, and
    # the helpers must still resolve exactly the sealed paths.
    sealed = seal_candidate(
        tmp_path, "markers", deb_name="sealed-marker.deb",
        rpm_name="sealed-marker.rpm")
    assert sealed["deb"].name == "sealed-marker.deb"
    assert sealed["rpm"].name == "sealed-marker.rpm"
    target_dir = tmp_path / "sealed-target"
    target_dir.mkdir()
    for suite, marker in (("package_deb", "sealed-marker.deb"),
                          ("package_rpm", "sealed-marker.rpm")):
        proc = _run_sealed_suite(sealed, suite, target_dir)
        assert proc.returncode == 0, proc.stderr[-3000:]
        combined = proc.stdout + proc.stderr
        assert "1 passed" in combined, \
            "%s ran no sealed-input test" % suite
        assert marker in combined, \
            "%s never consumed %s" % (suite, marker)
    # The cargo-driven shape dispatch uses must work too:
    # cargo injects LD_LIBRARY_PATH into the test binary, which
    # the loader forbids, so the helpers scrub it for the
    # loader probe. This leg fails if the scrub regresses.
    env = {key: value for key, value in os.environ.items()
           if key != "RUSTUP_TOOLCHAIN"}
    env.update(candidate_env(sealed))
    proc = subprocess.run(
        ["cargo", "test", "--locked", "--test", "package_deb",
         "sealed_inputs_used", "--", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-3000:]
    combined = proc.stdout + proc.stderr
    assert "1 passed" in combined, combined[-2000:]
    assert "sealed-marker.deb" in combined, \
        "cargo-driven run never consumed the sealed .deb"
    # Even with rebuilds requested, candidate mode must not
    # build any package output under the target dir.
    leftovers = sorted(
        path.relative_to(target_dir).as_posix()
        for base, _, files in os.walk(target_dir)
        for path in (Path(base) / name for name in files)
        if path.suffix in (".deb", ".rpm"))
    assert leftovers == [], leftovers
    # Partial candidate inputs fail closed, never silently
    # fall back to building.
    env = {"PATH": os.environ.get("PATH", ""),
           "CARGO_TARGET_DIR": str(target_dir),
           "MV_BUNDLE_TARBALL":
           str(sealed["bundle"])}
    binary = _test_binary("package_deb")
    proc = subprocess.run(
        [str(binary), "sealed_inputs_used", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode != 0, \
        "partial candidate inputs silently accepted"
    assert "both" in proc.stderr + proc.stdout, \
        "partial-input refusal must name both inputs"


def test_no_build_outputs_needed(tmp_path):
    # Candidate mode consults no build outputs: the sealed
    # resolution runs under a fresh empty target dir (no
    # release binary, no BPF outputs, no prior packages), the
    # installed BPF bytes are compared against the verified
    # candidate root even though the development BPF bytes
    # differ, and the candidate-mode code never names a build
    # output path at all.
    sealed = seal_candidate(tmp_path, "nobuild")
    target_dir = tmp_path / "empty-target"
    target_dir.mkdir()
    for suite in ("package_deb", "package_rpm"):
        proc = _run_sealed_suite(sealed, suite, target_dir)
        assert proc.returncode == 0, proc.stderr[-3000:]
        assert "1 passed" in proc.stdout + proc.stderr, \
            "%s ran no sealed-input test" % suite
    built = sorted(
        path.relative_to(target_dir).as_posix()
        for base, _, files in os.walk(target_dir)
        for path in (Path(base) / name for name in files)
        if path.suffix in (".deb", ".rpm")
        or path.name == "memveil"
        or path.name.startswith("memveil-ebpf-"))
    assert built == [], built
    selected = load(env=candidate_env(sealed))
    try:
        staged = tmp_path / "bpf-staged"
        staged.mkdir()
        _extract_deb(sealed["deb"], staged)
        for name in BPF_OBJECTS:
            installed = staged / "usr" / "lib" / "memveil" \
                / name
            assert installed.is_file(), name
            assert installed.read_bytes() == \
                selected.path("bpf/" + name).read_bytes(), \
                name
    finally:
        selected.close()
    outs = sorted(
        path for path in
        (ROOT / "target" / "release" / "build" / "memveil").glob(
            "*/out")
        if (path / "memveil-ebpf-attempt").is_file())
    if outs:
        dev_bytes = (outs[0]
                     / "memveil-ebpf-attempt").read_bytes()
        candidate_bytes = (
            sealed["bundle_dir"] / "bpf"
            / "swiotlb_attempt.bpf.o").read_bytes()
        assert dev_bytes != candidate_bytes, \
            "test setup: development BPF must differ from " \
            "the candidate bytes to prove they are unused"
    needle = "build" + "/"
    for rel in ("tests/package_helpers/mod.rs",
                "tests/package_helpers/journey.rs",
                "tests/package/test_release_runtime.py"):
        text = (ROOT / rel).read_text()
        hits = [line.strip() for line in text.splitlines()
                if needle in line]
        assert hits == [], "%s references %s" % (rel, hits)


if __name__ == "__main__":
    sys.exit("run via: python3 -m pytest tests/package/")
