# SPDX-License-Identifier: GPL-3.0-or-later

"""RPM gate: the rpmbuild-built .rpm carries the FHS payload and journeys.

The .rpm built from packaging/rpm/memveil.spec (via the
rpm-journey lane, which runs real `rpmbuild -bb`) must carry
the same installed payload the .deb pins: /usr/bin/memveil,
the bridge plus the BPF objects under /usr/lib/memveil,
profiles and manuals under /usr/share/memveil, generated man
pages, static completions, license texts, and the empty
state dir /var/lib/memveil/receipts. Its dependency set must
stay manual (libelf, zlib, plus the versioned glibc floor
the staged ELF files require): the private bundled libs
must neither leak into Requires nor satisfy other packages
via Provides.

The Fedora journey then installs the .rpm with dnf inside a
Fedora container (proving Requires resolve on the target
distro) and drives the installed tree like the .deb journey:
rpm verify, version, receipts-dir state, bridge LOAD proof,
generalized RUNPATH check, BPF placement, zero-flag doctor,
zero-env record probe, privileged qualify, uninstall, and
residue check. See tests/package/rpm_journey.sh for the
in-container steps.

Environment: MV_RPM (required, the built .rpm), MV_REPO
(optional, defaults to this checkout). Without docker the
journey test skips loudly and docs/install.md carries the
exact manual gate instead.
"""

import os
import re
import shutil
import subprocess

import pytest

RPM = os.environ.get("MV_RPM", "")
REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))

needs_rpm = pytest.mark.skipif(
    not RPM, reason="MV_RPM is not set (run tools/test rpm-journey)")

FEDORA_IMAGE = "fedora:41"

# The pinned payload, an independent literal mirroring the
# .deb FIXED_FILES: a new installed path fails here until
# both formats (and both pins) are updated together.
FIXED_FILES = {
    "/usr/bin/memveil",
    "/usr/lib/memveil/libbpf_mojo.so.1",
    "/usr/lib/memveil/swiotlb_attempt.bpf.o",
    "/usr/lib/memveil/swiotlb_lifecycle.bpf.o",
    "/usr/lib/memveil/swiotlb_copy.bpf.o",
    "/usr/share/doc/memveil/copyright",
    "/usr/share/doc/memveil/LICENSE",
    "/usr/share/doc/memveil/THIRD-PARTY-NOTICES.md",
    "/usr/share/doc/memveil/THIRD-PARTY-NOTICES.libbpf-mojo.md",
    "/usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt",
    "/usr/share/doc/memveil/LICENSES/GPL-2.0-or-later.txt",
    "/usr/share/doc/memveil/licenses/GPL-3.0.txt",
    "/usr/share/doc/memveil/licenses/LICENSE.BSD-2-Clause.libbpf",
    "/usr/share/doc/memveil/licenses/LICENSE.mojo-compiler",
    "/usr/share/doc/memveil/licenses/LICENSE.zlib",
    "/usr/share/doc/memveil/licenses/NOTICE.mojo-runtime.md",
    "/usr/share/doc/memveil/licenses/RUNTIME.LIBRARY.EXCEPTION",
    "/usr/share/doc/memveil/licenses/Third-Party-Notices.mojo-compiler",
    "/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSE",
    "/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/GPL-2.0-only.txt",
    "/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/LLVM-exception.txt",
    "/usr/share/memveil/docs/examples/real-capture/README.md",
    "/usr/share/memveil/docs/examples/real-capture/events.ndjson",
    "/usr/share/memveil/docs/examples/real-capture/session.json",
    "/usr/share/man/man1/memveil.1",
    "/usr/share/man/man1/memveil-record.1",
    "/usr/share/man/man1/memveil-report.1",
    "/usr/share/man/man1/memveil-top.1",
    "/usr/share/man/man1/memveil-doctor.1",
    "/usr/share/man/man1/memveil-qualify.1",
    "/usr/share/bash-completion/completions/memveil",
    "/usr/share/zsh/vendor-completions/_memveil",
}

# The only %dir-owned directories: every other parent
# belongs to the base system (filesystem, man-db). The
# license subdirs are %dir-owned too, so removal leaves no
# directory residue behind.
OWNED_DIRS = {
    "/usr/lib/memveil",
    "/usr/share/memveil",
    "/usr/share/doc/memveil",
    "/usr/share/doc/memveil/LICENSES",
    "/usr/share/doc/memveil/licenses",
    "/usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES",
    "/var/lib/memveil",
    "/var/lib/memveil/receipts",
}

BPF_OBJECTS = (
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
)

# Host-side rpm queries never touch the system rpm db: every
# query passes a scratch --dbpath so the lock error a db-less
# host prints never pollutes stderr.
JOURNEY_STEPS = (
    "dnf-install",
    "rpm-verify",
    "version",
    "receipts-dir",
    "bridge-load",
    "runpath",
    "bpf",
    "no-elf-share",
    "man-completions",
    "doctor",
    "record-probe",
    "uninstall-clean",
)


def run(*argv, **kwargs):
    kwargs.setdefault("timeout", 300)
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )


def rpm_query(*args, dbpath):
    return run("rpm", "--dbpath", dbpath, *args)


@pytest.fixture(scope="module")
def dbpath(tmp_path_factory):
    dest = tmp_path_factory.mktemp("rpmdb")
    return str(dest)


@pytest.fixture(scope="module")
def listing(dbpath):
    assert RPM and os.path.isfile(RPM), \
        "MV_RPM must name the built .rpm"
    proc = rpm_query("-qlp", RPM, dbpath=dbpath)
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr == "", proc.stderr
    return [line.strip() for line in proc.stdout.splitlines()
            if line.strip()]


def repo_tree_files(subdir, suffix):
    """Repo source files under subdir with suffix, as rpm paths."""
    base = os.path.join(REPO, subdir)
    found = set()
    for root, _, names in os.walk(base):
        for name in sorted(names):
            if not name.endswith(suffix):
                continue
            full = os.path.join(root, name)
            rel = os.path.relpath(full, base)
            found.add(rel)
    return found


@needs_rpm
def test_rpm_header(dbpath):
    if shutil.which("rpm") is None:
        pytest.skip("rpm absent on this host: header pins need "
                    "`rpm -qp`; rerun where rpmbuild ran")
    assert RPM and os.path.isfile(RPM)
    proc = rpm_query("-qp", "--queryformat",
                     "%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n",
                     RPM, dbpath=dbpath)
    assert proc.returncode == 0, proc.stderr
    name, version, release, arch = proc.stdout.strip().split()
    assert name == "memveil", proc.stdout
    assert arch == "x86_64", proc.stdout
    assert re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", version), version
    src = open(os.path.join(
        REPO, "src", "memveil", "model", "report.mojo")).read()
    engine = re.search(r'ENGINE_VERSION = "memveil-([^"]+)"', src)
    assert engine, "ENGINE_VERSION moved; update the drift guard"
    assert version == engine.group(1), \
        "rpm Version %s vs engine %s" % (version, engine.group(1))
    assert os.path.basename(RPM) == \
        "memveil-%s-%s.%s.rpm" % (version, release, arch), RPM


@needs_rpm
def test_rpm_manual_deps_only(dbpath):
    # The private bundled libs must stay out of both sets:
    # no auto Requires on the closure, no Provides that
    # could satisfy another package. rpmlib() boilerplate
    # is the only generated entry allowed.
    if shutil.which("rpm") is None:
        pytest.skip("rpm absent on this host: dependency pins "
                    "need `rpm -qp`; rerun where rpmbuild ran")
    assert RPM and os.path.isfile(RPM)
    proc = rpm_query("-qp", "--requires", RPM, dbpath=dbpath)
    assert proc.returncode == 0, proc.stderr
    requires = [line.strip() for line in proc.stdout.splitlines()
                if line.strip()]
    assert "libelf.so.1()(64bit)" in requires, requires
    assert "libz.so.1()(64bit)" in requires, requires
    assert "glibc >= 2.38" in requires, requires
    for token in ("libbpf_mojo", "libAsync", "libKGEN",
                  "libMSupport", "libstdc++", "libgcc_s",
                  "libc.so", "libm.so", "ld-linux"):
        assert not [line for line in requires if token in line], \
            "auto-Requires leaked %s: %s" % (token, requires)
    assert all(line.startswith("rpmlib(") or line in (
        "libelf.so.1()(64bit)", "libz.so.1()(64bit)",
        "glibc >= 2.38")
        for line in requires), requires
    proc = rpm_query("-qp", "--provides", RPM, dbpath=dbpath)
    assert proc.returncode == 0, proc.stderr
    provides = [line.strip() for line in proc.stdout.splitlines()
                if line.strip()]
    assert [line for line in provides
            if line.startswith("memveil = ")], provides
    for token in ("libbpf_mojo", "libAsync", "libKGEN",
                  "libMSupport", ".so("):
        assert not [line for line in provides if token in line], \
            "private Provides leaked %s: %s" % (token, provides)


@needs_rpm
def test_rpm_file_list_exact(listing):
    if shutil.which("rpm") is None:
        pytest.skip("rpm absent on this host: file-list pins "
                    "need `rpm -qlp`; rerun where rpmbuild ran")
    libs = {p for p in listing if p.startswith("/usr/lib/memveil/")}
    libs.discard("/usr/lib/memveil")
    assert "/usr/lib/memveil/libbpf_mojo.so.1" in libs
    assert {p for p in libs if p.endswith(".bpf.o")} == {
        "/usr/lib/memveil/" + name for name in BPF_OBJECTS}
    rest = {p for p in libs if not p.endswith(".bpf.o")}
    assert rest, "no shared libraries shipped"
    assert all(re.fullmatch(r"/usr/lib/memveil/[^/]+\.so(\..*)?",
                            p) for p in rest), rest
    profiles = {"/usr/share/memveil/profiles/" + rel
                for rel in repo_tree_files("profiles", ".json")}
    profiles.add("/usr/share/memveil/profiles/manifest.txt")
    docs = {"/usr/share/memveil/docs/" + rel
            for rel in repo_tree_files("docs", ".md")}
    # The spec ships whole trees (`dir/` trailing slash),
    # so rpm lists their intermediate directories too.
    tree_dirs = set()
    for path in profiles | docs | set(FIXED_FILES):
        parent = os.path.dirname(path)
        while parent.startswith("/usr/share/memveil/"):
            tree_dirs.add(parent)
            parent = os.path.dirname(parent)
    want = set(FIXED_FILES) | profiles | docs | libs \
        | OWNED_DIRS | tree_dirs
    assert set(listing) == want, \
        "extra: %s; missing: %s" % (
            sorted(set(listing) - want), sorted(want - set(listing)))


@needs_rpm
def test_rpm_modes_owners(listing, dbpath):
    if shutil.which("rpm") is None:
        pytest.skip("rpm absent on this host: mode pins need "
                    "`rpm -qlpv`; rerun where rpmbuild ran")
    assert RPM and os.path.isfile(RPM)
    proc = rpm_query("-qlpv", RPM, dbpath=dbpath)
    assert proc.returncode == 0, proc.stderr
    entries = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        assert len(parts) >= 9, line
        mode, owner = parts[0], parts[2] + "/" + parts[3]
        entries[parts[-1]] = (mode, owner)
    assert set(entries) == set(listing)
    for path, (mode, owner) in sorted(entries.items()):
        assert owner == "root/root", (path, owner)
        if mode.startswith("d"):
            assert mode == "drwxr-xr-x", (path, mode)
        else:
            assert mode[0] == "-", (path, mode)
            assert "s" not in mode and "t" not in mode, (path, mode)
            assert mode[8] != "w", (path, mode)
            if path == "/usr/bin/memveil":
                assert mode == "-rwxr-xr-x", (path, mode)
            else:
                assert mode == "-rw-r--r--", (path, mode)


@needs_rpm
def test_rpm_payload_mirrors_repo(tmp_path):
    # Profiles and manuals ship the whole source trees:
    # extracted bytes must equal the repo bytes.
    if shutil.which("rpm2cpio") is None \
            or shutil.which("cpio") is None:
        pytest.skip("rpm2cpio/cpio absent: cannot extract the "
                    "payload for the byte mirror")
    assert RPM and os.path.isfile(RPM)
    dest = tmp_path / "rpmroot"
    dest.mkdir()
    cpio = subprocess.run(
        "rpm2cpio %s | cpio -idm --quiet" % RPM, shell=True,
        cwd=str(dest), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, text=True, timeout=300)
    assert cpio.returncode == 0, cpio.stderr
    for subdir, suffix, inst in (
            ("profiles", ".json", "usr/share/memveil/profiles"),
            ("docs", ".md", "usr/share/memveil/docs")):
        base = os.path.join(REPO, subdir)
        for root, _, names in os.walk(base):
            for name in names:
                if not name.endswith(suffix):
                    continue
                rel = os.path.relpath(os.path.join(root, name),
                                      base)
                installed = dest / inst / rel
                assert installed.is_file(), rel
                assert installed.read_bytes() == open(
                    os.path.join(root, name), "rb").read(), rel
    manifest = dest / "usr/share/memveil/profiles/manifest.txt"
    assert manifest.is_file(), "profiles/manifest.txt missing"


def docker_usable():
    if shutil.which("docker") is None:
        return False
    proc = run("docker", "info", timeout=60)
    return proc.returncode == 0


def fedora_image_ready():
    proc = run("docker", "image", "inspect", FEDORA_IMAGE,
               timeout=60)
    if proc.returncode == 0:
        return True
    proc = run("docker", "pull", FEDORA_IMAGE, timeout=600)
    return proc.returncode == 0


@needs_rpm
def test_rpm_fedora_journey():
    if not docker_usable():
        pytest.skip(
            "docker unusable on this host: the Fedora journey "
            "cannot run here; docs/install.md carries the exact "
            "manual gate (build via rpmbuild, install, doctor, "
            "uninstall) with expected outputs instead")
    if not fedora_image_ready():
        pytest.skip(
            "fedora:41 image unavailable (offline?): the "
            "container journey needs it; docs/install.md "
            "carries the manual gate instead")
    script = os.path.join(REPO, "tests", "package",
                          "rpm_journey.sh")
    assert os.path.isfile(script), "missing rpm_journey.sh"
    proc = run("docker", "run", "--rm",
               "-v", "%s:/mnt/m.rpm:ro" % os.path.abspath(RPM),
               "-v", "%s:/mnt/journey.sh:ro" % script,
               FEDORA_IMAGE, "bash", "/mnt/journey.sh",
               "/mnt/m.rpm", timeout=600)
    print(proc.stdout)
    print(proc.stderr)
    assert proc.returncode == 0, \
        "fedora journey failed (see log above)"
    for step in JOURNEY_STEPS:
        assert "journey-ok: %s" % step in proc.stdout, \
            "journey skipped %s" % step
    assert "journey qualify receipt: qualify: local-auto" in \
        proc.stdout or "journey qualify refusal: " in proc.stdout, \
        "journey never qualified"
    assert "journey: all steps passed" in proc.stdout


def _write_executable(path, body):
    path.write_text(body)
    path.chmod(0o755)


def test_rpm_journey_refuses_retained_receipts(tmp_path):
    # Retained receipts must block the rpm journey before
    # installation: no dnf install attempt, no deletion,
    # and the survivor stays byte-identical (the .deb
    # `_preflight_fresh_state` semantics). Needs no
    # .rpm/docker: the journey script runs against a staged
    # receipts dir (MV_RECEIPTS_DIR) with dnf stubbed to
    # log every call and rpm stubbed to fail. Pre-gate the
    # script installs first, so the no-install assertion
    # fails there (RED).
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    sentinel = receipts / "pre-existing-receipt.json"
    sentinel.write_bytes(
        b'{"profile_id": "linux-x86_64-7.0.0-99-test"}\n')
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "dnf-calls.log"
    _write_executable(
        bindir / "dnf",
        "#!/bin/sh\necho \"$@\" >>\"%s\"\nexit 0\n" % calls)
    _write_executable(bindir / "rpm", "#!/bin/sh\nexit 1\n")
    env = dict(os.environ)
    env["PATH"] = "%s:%s" % (bindir, env.get("PATH", ""))
    env["MV_RECEIPTS_DIR"] = str(receipts)
    script = os.path.join(REPO, "tests", "package",
                           "rpm_journey.sh")
    proc = run("bash", script, str(tmp_path / "dummy.rpm"),
               env=env, timeout=120)
    assert proc.returncode != 0, proc.stdout
    assert not calls.exists(), \
        "install attempted despite retained receipts"
    assert "refusing install" in proc.stderr, proc.stderr
    assert "pre-existing-receipt.json" in proc.stderr, \
        proc.stderr
    assert sentinel.read_bytes() == \
        b'{"profile_id": "linux-x86_64-7.0.0-99-test"}\n'


def test_rpm_journey_preflight_fresh_proceeds_to_install(tmp_path):
    # Positive control for the gate above: with a fresh
    # (empty) staged receipts dir the journey must reach
    # dnf install. The stubbed install succeeds and the run
    # then dies at the stubbed `rpm -V`; the dnf call log
    # proves the gate passed and the harness detects
    # install attempts.
    receipts = tmp_path / "receipts"
    receipts.mkdir()
    bindir = tmp_path / "bin"
    bindir.mkdir()
    calls = tmp_path / "dnf-calls.log"
    _write_executable(
        bindir / "dnf",
        "#!/bin/sh\necho \"$@\" >>\"%s\"\nexit 0\n" % calls)
    _write_executable(bindir / "rpm", "#!/bin/sh\nexit 1\n")
    env = dict(os.environ)
    env["PATH"] = "%s:%s" % (bindir, env.get("PATH", ""))
    env["MV_RECEIPTS_DIR"] = str(receipts)
    script = os.path.join(REPO, "tests", "package",
                           "rpm_journey.sh")
    proc = run("bash", script, str(tmp_path / "dummy.rpm"),
               env=env, timeout=120)
    assert proc.returncode != 0, proc.stdout
    assert "retained receipts" not in proc.stderr, proc.stderr
    assert calls.exists(), "fresh run never reached dnf"
    assert "dummy.rpm" in calls.read_text(), \
        calls.read_text()
