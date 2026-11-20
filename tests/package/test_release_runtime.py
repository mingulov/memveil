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
refuse), every re-homed packaging leg consumes the sealed
paths and never rebuilds, candidate mode needs no build
outputs, and foreign loader overrides refuse pre-exec while
every candidate spawn runs scrubbed. All candidate legs
build and run inside one audited target dir.

Environment: MV_BUNDLE_TARBALL plus MV_CANDIDATE_MANIFEST
(candidate mode: the verified root replaces the tarball),
MV_VALID_EMPTY (optional, defaults to the in-repo fixture).
Without candidate inputs the behavioral tests use the newest
tarball the packaging suites built (run the cargo
package_tarball suite first); a missing tarball fails closed
with the remedy. The sealed-input tests build synthetic
candidates in tmp and need git, dpkg-deb, rpmbuild, cargo,
and bpf-linker on PATH. Under dispatched candidate inputs
those legs return early: they prove dev-only machinery,
while dispatched runs prove the bundle()-consuming legs
against the real seal.

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
from support.candidate_input import load, requested

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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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


@pytest.mark.qualification
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
    # Symlinks enumerate first-class as "path -> target"
    # (never skipped): any alias outside the expected set
    # shows up in the set difference.
    found = set()
    for base, dirs, files in os.walk(root):
        for name in files:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, root).replace(
                os.sep, "/")
            if os.path.islink(full):
                found.add(rel + " -> " + os.readlink(full))
            else:
                found.add(rel)
        for name in dirs:
            full = os.path.join(base, name)
            if os.path.islink(full):
                found.add(os.path.relpath(
                    full, root).replace(os.sep, "/")
                    + " -> " + os.readlink(full))
    return found


def _dev_only_seal_leg():
    """True when a synthetic-seal leg must return early.

    Dispatched runs consume the real seal through bundle();
    sealing synthetic inputs there would prove machinery,
    not the candidate. The early return keeps the conftest
    fail-on-skip guard intact: these legs are dev-only by
    design, not deferred, so they record no skip.
    """
    if requested():
        print("release-runtime: synthetic-seal leg is dev-only; "
              "dispatched runs prove the bundle()-consuming legs")
        return True
    return False


@pytest.mark.dev_fixture
def test_installed_closure_matches_candidate(tmp_path):
    # The sealed .deb/.rpm pair installs exactly the candidate
    # files closure: every manifest member lands at its mapped
    # FHS path with equal bytes, nothing is missing, and
    # nothing extra ships besides the generated deb files.
    if _dev_only_seal_leg():
        return
    sealed = seal_candidate(tmp_path, "closure")
    manifest = sealed["manifest"]
    selected = load(env=candidate_env(sealed),
                    required=True)
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
    alias.unlink()
    alias.write_bytes(saved)
    DEBPKG.verify_installed(str(dest), manifest)
    # An extra member under the lib prefix refuses, as does
    # an extra alias: both name their path, the alias also
    # its target, and the installed set carries the link.
    smuggled = dest / "usr" / "lib" / "memveil" / "smuggled.so"
    smuggled.write_bytes(b"not in the closure\n")
    with pytest.raises(ValueError, match="smuggled"):
        DEBPKG.verify_installed(str(dest), manifest)
    smuggled.unlink()
    link = dest / "usr" / "lib" / "memveil" / "alias.so"
    link.symlink_to("nowhere-link-target")
    with pytest.raises(ValueError, match="alias"):
        DEBPKG.verify_installed(str(dest), manifest)
    with pytest.raises(ValueError, match="nowhere-link-target"):
        DEBPKG.verify_installed(str(dest), manifest)
    assert "usr/lib/memveil/alias.so -> nowhere-link-target" \
        in _installed_set(str(dest))
    link.unlink()
    DEBPKG.verify_installed(str(dest), manifest)


@pytest.mark.qualification
def test_installed_closure_live_scopes_owned_paths(tmp_path):
    # Live installs share /usr/bin with the system: an
    # unrelated binary beside the package accepts under
    # live scoping, while added files and aliases under
    # owned paths refuse. Staging keeps refusing the
    # unrelated binary, proving the flag.
    members = {
        "bin/memveil": b"live binary\n",
        "lib/memveil/libx.so.1": b"live lib\n",
        "bpf/o.bpf.o": b"live object\n",
        "profiles/p.json": b"{}\n",
        "docs/d.md": b"# live\n",
    }
    manifest = {"files": {
        name: hashlib.sha256(data).hexdigest()
        for name, data in members.items()}}
    root = tmp_path / "live-root"
    for name, data in members.items():
        dest = root / DEBPKG.installed_file_path(name)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    (root / "usr/bin/unrelated-system-binary").write_bytes(
        b"not ours\n")
    DEBPKG.verify_installed(str(root), manifest, live=True)
    alias = root / "usr/lib/memveil/alias.so"
    alias.symlink_to("nowhere-live-target")
    with pytest.raises(ValueError, match="alias.so"):
        DEBPKG.verify_installed(str(root), manifest, live=True)
    with pytest.raises(ValueError,
                       match="nowhere-live-target"):
        DEBPKG.verify_installed(str(root), manifest, live=True)
    alias.unlink()
    DEBPKG.verify_installed(str(root), manifest, live=True)
    smuggled = root / "usr/share/memveil/profiles/smuggled.json"
    smuggled.write_text("{}\n")
    with pytest.raises(ValueError, match="smuggled"):
        DEBPKG.verify_installed(str(root), manifest, live=True)
    smuggled.unlink()
    with pytest.raises(
            ValueError, match="unrelated-system-binary"):
        DEBPKG.verify_installed(str(root), manifest)


# Re-homed tests the candidate legs execute per suite:
# every test with a candidate branch plus the structural
# pins that prove the seal is real-shaped. Excluded with
# reasons: the floor/BPF/stripped/loader pins need real
# bytes the synthetic seal never carries, lintian_gate is
# host-tool dependent, the pure spec lints are dev-owned,
# and the privileged/container journeys need a full engine
# (the real-seal journey pass owns them).
CANDIDATE_DEB_TESTS = (
    "sealed_inputs_used",
    "control_fields",
    "file_list_exact",
    "staged_payload_matches_bundle",
    "bpf_objects_match_build",
    "installed_man_matches_current_help",
    "docs_mirror_repo_and_links_resolve",
    "lintian_overrides_exact",
    "changelog_debian",
    "installed_closure_wiring",
    "installed_closure_live_scopes_owned_paths",
    "no_maintainer_scripts",
    "receipts_state_dir_staged",
    "md5sums_match_payload",
    "modes_owners_no_privilege_bits",
    "man_and_completions_present",
    "copyright_points_at_texts",
    "no_elf_under_usr_share",
)

CANDIDATE_RPM_TESTS = (
    "sealed_inputs_used",
    "installed_closure_live_scopes_owned_paths",
    "rpm_header",
    "rpm_manual_deps_only",
    "rpm_file_list_exact",
    "rpm_modes_owners",
    "rpm_payload_mirrors_repo",
    "rpmspec_parse",
    "spec_version_matches_engine",
)

CANDIDATE_SUITES = (("package_deb", CANDIDATE_DEB_TESTS),
                    ("package_rpm", CANDIDATE_RPM_TESTS))


@pytest.fixture(scope="module")
def audited_target_dir(tmp_path_factory):
    """One audited cargo target dir for the candidate legs.

    Every leg builds and runs inside this dir, so the
    no-outputs assertions audit exactly the tree cargo used:
    nothing lands in the ambient target dir unaudited.
    """
    return tmp_path_factory.mktemp("audited-target")


_binaries = {}


def _test_binary(name, target_dir):
    key = (name, str(target_dir))
    found = _binaries.get(key)
    if found is not None and found.is_file():
        return found
    env = {item: value for item, value in os.environ.items()
           if item != "RUSTUP_TOOLCHAIN"}
    env["CARGO_TARGET_DIR"] = str(target_dir)
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
            try:
                found.relative_to(target_dir)
            except ValueError:
                raise AssertionError(
                    "test binary escaped the audited "
                    "target dir: %s" % found)
            _binaries[key] = found
            return found
    raise AssertionError(
        "cargo named no test binary for %s" % name)


def _run_sealed_suite(sealed, suite, target_dir, tests,
                      extra=None):
    binary = _test_binary(suite, target_dir)
    assert binary is not None, suite
    ran = {}
    for name in tests:
        env = {"PATH": os.environ.get("PATH", ""),
               "CARGO_TARGET_DIR": str(target_dir),
               "MV_RUSTPKG_REBUILD": "1"}
        env.update(candidate_env(sealed))
        if extra:
            env.update(extra)
        proc = subprocess.run(
            [str(binary), name, "--nocapture"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, \
            "%s %s failed: %s" % (
                suite, name, proc.stderr[-3000:])
        assert "1 passed" in combined, \
            "%s ran no %s" % (suite, name)
        ran[name] = combined
    return ran


def _cargo_suite_env(sealed, target_dir):
    # The cargo-driven development shape, audited: the
    # ambient target dir and rebuild request never leak in
    # (both are set explicitly below), the repo pin wins.
    env = {key: value for key, value in os.environ.items()
           if key not in ("RUSTUP_TOOLCHAIN",
                          "CARGO_TARGET_DIR",
                          "MV_RUSTPKG_REBUILD")}
    env["CARGO_TARGET_DIR"] = str(target_dir)
    env["MV_RUSTPKG_REBUILD"] = "1"
    env.update(candidate_env(sealed))
    return env


def _run_cargo_suite(sealed, suite, target_dir, tests):
    env = _cargo_suite_env(sealed, target_dir)
    ran = {}
    for name in tests:
        proc = subprocess.run(
            ["cargo", "test", "--locked", "--test", suite,
             name, "--", "--nocapture"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        combined = proc.stdout + proc.stderr
        assert proc.returncode == 0, \
            "cargo %s %s failed: %s" % (
                suite, name, proc.stderr[-3000:])
        assert "1 passed" in combined, \
            "cargo %s ran no %s: %s" % (
                suite, name, combined[-2000:])
        ran[name] = combined
    return ran


def _assert_binaries_built_here(target_dir):
    # The cargo-driven legs must compile inside the audited
    # dir: each suite leaves its test binary there.
    for suite, _ in CANDIDATE_SUITES:
        found = [path for path in target_dir.rglob(
            suite + "-*")
            if path.is_file()
            and os.access(path, os.X_OK)]
        assert found, \
            "cargo left no %s test binary in %s" % (
                suite, target_dir)


def _package_outputs(target_dir):
    # Package outputs the helpers could emit under the
    # candidate-writable work subtree (every ensure_* writes
    # beneath it, rebuild-scoped or not).
    work = target_dir / "package-test"
    if not work.is_dir():
        return []
    return sorted(
        path.relative_to(target_dir).as_posix()
        for base, _, files in os.walk(work)
        for path in (Path(base) / name for name in files)
        if path.suffix in (".deb", ".rpm"))


@pytest.mark.dev_fixture
def test_sealed_inputs_used(tmp_path, audited_target_dir):
    # The install journeys consume the sealed .deb/.rpm paths
    # from the candidate manifest and never rebuild: the seal
    # carries a marker-named pair, rebuilds are requested,
    # and every re-homed leg must still resolve exactly the
    # sealed paths -- not only the sealed-input threading
    # test, but the control, file-list, staging,
    # engine-version, installed-man, docs, and closure legs
    # that execute ensure_deb/ensure_rpm in candidate mode.
    if _dev_only_seal_leg():
        return
    sealed = seal_candidate(
        tmp_path, "markers", deb_name="sealed-marker.deb",
        rpm_name="sealed-marker.rpm", shaped=True)
    assert sealed["deb"].name == "sealed-marker.deb"
    assert sealed["rpm"].name == "sealed-marker.rpm"
    target_dir = audited_target_dir
    markers = {"package_deb": "sealed-marker.deb",
               "package_rpm": "sealed-marker.rpm"}
    for suite, tests in CANDIDATE_SUITES:
        ran = _run_sealed_suite(sealed, suite, target_dir,
                                tests)
        assert markers[suite] in \
            ran["sealed_inputs_used"], \
            "%s never consumed %s" % (
                suite, markers[suite])
    # The cargo-driven development shape must work too:
    # dispatch itself launches prebuilt executables directly
    # (see the launcher tests in tests/support), but a manual
    # cargo run with candidate inputs still injects
    # LD_LIBRARY_PATH into the test binary, which the entry
    # check recognizes (cargo-only passes) while every
    # candidate spawn still runs scrubbed. This leg fails if
    # recognition or the scrub regresses.
    for suite, tests in CANDIDATE_SUITES:
        ran = _run_cargo_suite(sealed, suite, target_dir,
                               tests)
        assert markers[suite] in \
            ran["sealed_inputs_used"], \
            "cargo-driven %s never consumed %s" % (
                suite, markers[suite])
    _assert_binaries_built_here(target_dir)
    # Even with rebuilds requested, candidate mode must not
    # build any package output under the audited dir.
    leftovers = _package_outputs(target_dir)
    assert leftovers == [], leftovers
    # Partial candidate inputs fail closed, never silently
    # fall back to building.
    env = {"PATH": os.environ.get("PATH", ""),
           "CARGO_TARGET_DIR": str(target_dir),
           "MV_BUNDLE_TARBALL":
           str(sealed["bundle"])}
    binary = _test_binary("package_deb", target_dir)
    proc = subprocess.run(
        [str(binary), "sealed_inputs_used", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode != 0, \
        "partial candidate inputs silently accepted"
    assert "both" in proc.stderr + proc.stdout, \
        "partial-input refusal must name both inputs"


@pytest.mark.dev_fixture
def test_candidate_inputs_set_but_empty_refuse(audited_target_dir):
    # Set-but-empty is invalid input, never dev mode: one
    # empty plus one set fails, both empty fails, and both
    # unset stays dev (the leg skips cleanly). The refusal
    # fires before any input is read, so the set side needs
    # no valid seal here.
    target_dir = audited_target_dir
    binary = _test_binary("package_deb", target_dir)
    for key in ("MV_BUNDLE_TARBALL", "MV_CANDIDATE_MANIFEST"):
        env = {"PATH": os.environ.get("PATH", ""),
               "CARGO_TARGET_DIR": str(target_dir),
               "MV_BUNDLE_TARBALL": "dispatched",
               "MV_CANDIDATE_MANIFEST": "dispatched"}
        env[key] = ""
        proc = subprocess.run(
            [str(binary), "sealed_inputs_used", "--nocapture"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        assert proc.returncode != 0, \
            "empty %s silently accepted" % key
        assert "invalid" in proc.stderr + proc.stdout, \
            "empty-input refusal must say invalid"
        assert key in proc.stderr + proc.stdout, \
            "empty-input refusal must name the variable"
    env = {"PATH": os.environ.get("PATH", ""),
           "CARGO_TARGET_DIR": str(target_dir),
           "MV_BUNDLE_TARBALL": "",
           "MV_CANDIDATE_MANIFEST": ""}
    proc = subprocess.run(
        [str(binary), "sealed_inputs_used", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode != 0, \
        "both-empty candidate inputs silently accepted"
    assert "invalid" in proc.stderr + proc.stdout, \
        "both-empty refusal must say invalid"
    env = {"PATH": os.environ.get("PATH", ""),
           "CARGO_TARGET_DIR": str(target_dir)}
    proc = subprocess.run(
        [str(binary), "sealed_inputs_used", "--nocapture"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env)
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "1 passed" in proc.stdout + proc.stderr, \
        "unset inputs must stay dev"


@pytest.mark.dev_fixture
def test_candidate_loader_env_operator_refused(
        tmp_path, audited_target_dir):
    # An operator loader override refuses pre-exec in
    # candidate mode: the bare value, the cargo-shaped value
    # with an operator suffix appended, and the present-but-
    # empty value each fail closed naming the variable. The
    # inputs are valid; only the env is tainted.
    if _dev_only_seal_leg():
        return
    sealed = seal_candidate(tmp_path, "refused")
    target_dir = audited_target_dir
    binary = _test_binary("package_deb", target_dir)
    cases = {"/tmp/memveil-operator-taint": "bare",
             str(target_dir / "debug")
             + ":/tmp/memveil-operator-taint": "suffixed",
             "": "empty"}
    for tainted, label in cases.items():
        env = {"PATH": os.environ.get("PATH", ""),
               "CARGO_TARGET_DIR": str(target_dir),
               "MV_RUSTPKG_REBUILD": "1",
               "LD_LIBRARY_PATH": tainted}
        env.update(candidate_env(sealed))
        proc = subprocess.run(
            [str(binary), "sealed_inputs_used",
             "--nocapture"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        combined = proc.stdout + proc.stderr
        assert proc.returncode != 0, \
            "%s override silently accepted" % label
        assert "LD_LIBRARY_PATH" in combined, \
            "%s refusal must name the variable" % label


@pytest.mark.dev_fixture
def test_candidate_loader_env_cargo_only_proceeds(
        tmp_path, audited_target_dir):
    # A cargo-shaped loader value proceeds: the entry check
    # recognizes cargo's own injection (here spelled
    # explicitly, no cargo involved) while the suite still
    # consumes the sealed inputs.
    if _dev_only_seal_leg():
        return
    sealed = seal_candidate(tmp_path, "cargoonly")
    target_dir = audited_target_dir
    ran = _run_sealed_suite(
        sealed, "package_deb", target_dir,
        ("sealed_inputs_used",),
        extra={"LD_LIBRARY_PATH":
               str(target_dir / "debug")})
    assert sealed["deb"].name in \
        ran["sealed_inputs_used"]


@pytest.mark.dev_fixture
def test_no_build_outputs_needed(tmp_path, audited_target_dir):
    # Candidate mode consults no build outputs: every
    # re-homed leg runs against the sealed pair with
    # rebuilds requested, yet no package output appears
    # under the audited dir, no release tree is emitted
    # there at all, the installed BPF bytes are compared
    # against the verified candidate root even though the
    # development BPF bytes differ, and the
    # candidate-mode code never names a build output path
    # at all.
    if _dev_only_seal_leg():
        return
    sealed = seal_candidate(tmp_path, "nobuild", shaped=True)
    target_dir = audited_target_dir
    for suite, tests in CANDIDATE_SUITES:
        _run_sealed_suite(sealed, suite, target_dir, tests)
    built = _package_outputs(target_dir)
    assert built == [], built
    assert not (target_dir / "release").exists(), \
        "candidate mode emitted a release tree"
    selected = load(env=candidate_env(sealed),
                    required=True)
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


@pytest.mark.dev_fixture
def test_dispatched_env_returns_synthetic_seal_legs_early(
        tmp_path, audited_target_dir, monkeypatch, capsys):
    # Under dispatched candidate inputs every synthetic-seal
    # leg returns before sealing anything: the seal-machinery
    # spy must never fire. In dev the guard stays quiet.
    monkeypatch.setenv("MV_BUNDLE_TARBALL", "dispatched")
    monkeypatch.setenv("MV_CANDIDATE_MANIFEST", "dispatched")
    assert requested()
    this = sys.modules[__name__]
    def fail(*args, **kwargs):
        raise AssertionError(
            "synthetic seal machinery ran under dispatch")
    monkeypatch.setattr(this, "seal_candidate", fail)
    test_installed_closure_matches_candidate(tmp_path)
    test_sealed_inputs_used(tmp_path, audited_target_dir)
    test_candidate_loader_env_operator_refused(
        tmp_path, audited_target_dir)
    test_candidate_loader_env_cargo_only_proceeds(
        tmp_path, audited_target_dir)
    test_no_build_outputs_needed(tmp_path, audited_target_dir)
    assert "dev-only" in capsys.readouterr().out
    monkeypatch.delenv("MV_BUNDLE_TARBALL")
    monkeypatch.delenv("MV_CANDIDATE_MANIFEST")
    assert _dev_only_seal_leg() is False


def _selection_marks(path):
    """{test name: {markers}} for one dispatched file (AST)."""
    import ast
    found = {}
    tree = ast.parse(path.read_text())
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef) \
                or not node.name.startswith("test_"):
            continue
        marks = set()
        for decorator in node.decorator_list:
            value = decorator
            while isinstance(value, ast.Call):
                value = value.func
            if isinstance(value, ast.Attribute) \
                    and value.attr in ("qualification",
                                       "dev_fixture") \
                    and isinstance(value.value, ast.Attribute) \
                    and value.value.attr == "mark":
                marks.add(value.attr)
        found[node.name] = marks
    return found


@pytest.mark.qualification
def test_selection_markers_cover_every_test():
    # Every test in a dispatched file carries exactly one
    # selection marker: an unmarked fixture test would
    # silently rejoin qualification and build there.
    sys.path.insert(0, str(ROOT / "tests"))
    from support import candidate_suite as dispatch_mod
    files = set()
    for names in dispatch_mod.PYTEST_SELECTIONS.values():
        files.update(names)
    assert files == {
        "tests/package/test_release_runtime.py",
        "tests/package/test_clean_runtime.py"}, files
    for name in sorted(files):
        for test, marks in sorted(
                _selection_marks(ROOT / name).items()):
            assert marks in ({"qualification"},
                             {"dev_fixture"}), \
                "%s:%s carries %s" % (name, test, marks)


@pytest.mark.qualification
def test_dispatched_selection_collects_only_qualification():
    # The real dispatch argv, collected without running:
    # every qualification test is collected and no
    # development fixture test is.
    sys.path.insert(0, str(ROOT / "tests"))
    from support import candidate_suite as dispatch_mod
    for suite, files in sorted(
            dispatch_mod.PYTEST_SELECTIONS.items()):
        argv = dispatch_mod.pytest_dispatch_argv(*files)
        assert argv[:2] == ["-m", "pytest"], argv
        assert argv[-2:] == ["-m", "qualification"], argv
        env = {key: value for key, value in os.environ.items()
               if key not in ("MV_BUNDLE_TARBALL",
                              "MV_CANDIDATE_MANIFEST",
                              "MV_CANDIDATE_DIGEST")}
        proc = subprocess.run(
            [sys.executable, *argv, "--collect-only",
             "-p", "no:cacheprovider"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)
        assert proc.returncode == 0, proc.stderr[-2000:]
        collected = {line.split("::")[0]
                     + "::" + line.split("::")[1].split()[0]
                     for line in proc.stdout.splitlines()
                     if "::" in line}
        assert collected, "dispatch collects no %s" % suite
        for path in files:
            for test, marks in _selection_marks(
                    ROOT / path).items():
                node = "%s::%s" % (path, test)
                if marks == {"qualification"}:
                    assert node in collected, \
                        "%s drops %s" % (suite, node)
                else:
                    assert node not in collected, \
                        "%s keeps fixture %s" % (suite, node)


@pytest.mark.dev_fixture
def test_dispatched_selection_builds_nothing(tmp_path):
    # The dispatched qualification selection runs green
    # with cargo shadowed: no collected test may invoke a
    # build. Runs against the dev tarball (the selection,
    # not the bundle source, is under test); the cargo
    # stub fails loudly and leaves a sentinel.
    sys.path.insert(0, str(ROOT / "tests"))
    from support import candidate_suite as dispatch_mod
    bindir = tmp_path / "shadowbin"
    bindir.mkdir()
    sentinel = tmp_path / "cargo-invoked"
    stub = bindir / "cargo"
    stub.write_text(
        '#!/bin/sh\necho CARGO-SHADOWED-STUB >&2\n'
        'touch "%s"\nexit 99\n' % sentinel)
    stub.chmod(0o755)
    env = {key: value for key, value in os.environ.items()
           if key not in ("MV_BUNDLE_TARBALL",
                          "MV_CANDIDATE_MANIFEST",
                          "MV_CANDIDATE_DIGEST")}
    env["PATH"] = str(bindir) + ":/usr/bin:/bin"
    argv = dispatch_mod.pytest_dispatch_argv(
        *dispatch_mod.PYTEST_SELECTIONS["package"])
    result = subprocess.run(
        [sys.executable, *argv, "-p", "no:cacheprovider"],
        cwd=str(ROOT), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, env=env,
        timeout=900)
    combined = result.stdout + result.stderr
    assert result.returncode == 0, combined[-3000:]
    assert "passed" in combined, combined[-1000:]
    assert "CARGO-SHADOWED-STUB" not in combined, combined
    assert not sentinel.exists(), \
        "dispatched selection invoked cargo"


@pytest.mark.dev_fixture
def test_fedora_journey_candidate_without_docker_fails(
        tmp_path, audited_target_dir):
    # The Fedora dependency-resolution journey cannot be
    # skipped in candidate mode: with docker faked absent
    # the lane fails, while dev still skips. The bogus
    # candidate pair proves the gate fires before any seal
    # read; the sealed pair proves it under valid inputs.
    # rpm tooling must exist (the lane returns before the
    # gate without it, in both modes).
    assert shutil.which("rpm") is not None, \
        "fedora gate test needs rpm on PATH"
    target_dir = audited_target_dir
    binary = _test_binary("package_rpm", target_dir)
    bindir = tmp_path / "nodocker"
    bindir.mkdir()
    stub = bindir / "docker"
    stub.write_text("#!/bin/sh\necho nodocker-stub >&2\nexit 1\n")
    stub.chmod(0o755)
    path = str(bindir) + os.pathsep + os.environ.get(
        "PATH", "")

    def journey(env):
        return subprocess.run(
            [str(binary), "rpm_fedora_journey", "--nocapture"],
            cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=env)

    dev = {"PATH": path, "CARGO_TARGET_DIR": str(target_dir)}
    proc = journey(dev)
    combined = proc.stdout + proc.stderr
    assert proc.returncode == 0, combined[-2000:]
    assert "1 passed" in combined, combined[-2000:]
    assert "docker unusable" in combined, combined[-2000:]
    bogus = dict(dev, MV_BUNDLE_TARBALL="dispatched",
                 MV_CANDIDATE_MANIFEST="dispatched")
    proc = journey(bogus)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined[-2000:]
    assert "candidate Fedora journey refused" in combined, \
        combined[-2000:]
    sealed = seal_candidate(tmp_path, "fedora")
    candidate = dict(dev, **candidate_env(sealed))
    proc = journey(candidate)
    combined = proc.stdout + proc.stderr
    assert proc.returncode != 0, combined[-2000:]
    assert "candidate Fedora journey refused" in combined, \
        combined[-2000:]


if __name__ == "__main__":
    sys.exit("run via: python3 -m pytest tests/package/")
