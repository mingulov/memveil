# SPDX-License-Identifier: GPL-3.0-or-later

"""Debian package gate: file list, control fields, lintian, install smoke.

The .deb built by tools/package-deb carries the FHS layout the
Phase A discovery constants resolve without flags or
environment: /usr/bin/memveil, the bridge plus the BPF
objects under /usr/lib/memveil (BPF ELF must not sit under
/usr/share), profiles and manuals under /usr/share/memveil,
and the state dir /var/lib/memveil/receipts. Control pins
the manual dependency set; there are no maintainer scripts,
no setuid/capabilities bits, and (Task 7 owns them) no man
pages or completions.

The lib/*.so* member names are the pixi toolchain closure and
vary with the lockfile, so they are pinned structurally
(ELF shared objects, bridge present, NEEDED closure holds)
rather than by name; every other member is pinned exactly,
and profiles/docs must mirror the repo source trees.

Environment: MV_DEB (required, the built .deb), MV_REPO
(optional, defaults to this checkout).
"""

import json
import os
import re
import shutil
import stat
import subprocess

import pytest

DEB = os.environ.get("MV_DEB", "")
REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))

pytestmark = pytest.mark.skipif(
    not DEB, reason="MV_DEB is not set (run tools/test deb)")

# Every member outside lib/ and the docs mirror, pinned literally.
FIXED_FILES = {
    "usr/bin/memveil",
    "usr/lib/memveil/libbpf_mojo.so.1",
    "usr/lib/memveil/swiotlb_attempt.bpf.o",
    "usr/lib/memveil/swiotlb_lifecycle.bpf.o",
    "usr/lib/memveil/swiotlb_copy.bpf.o",
    "usr/share/doc/memveil/copyright",
    "usr/share/doc/memveil/LICENSE",
    "usr/share/doc/memveil/THIRD-PARTY-NOTICES.md",
    "usr/share/doc/memveil/THIRD-PARTY-NOTICES.libbpf-mojo.md",
    "usr/share/doc/memveil/LICENSES/GPL-2.0-only.txt",
    "usr/share/doc/memveil/LICENSES/GPL-2.0-or-later.txt",
    "usr/share/doc/memveil/licenses/GPL-3.0.txt",
    "usr/share/doc/memveil/licenses/LICENSE.BSD-2-Clause.libbpf",
    "usr/share/doc/memveil/licenses/LICENSE.mojo-compiler",
    "usr/share/doc/memveil/licenses/LICENSE.zlib",
    "usr/share/doc/memveil/licenses/NOTICE.mojo-runtime.md",
    "usr/share/doc/memveil/licenses/RUNTIME.LIBRARY.EXCEPTION",
    "usr/share/doc/memveil/licenses/Third-Party-Notices.mojo-compiler",
    "usr/share/doc/memveil/licenses/libbpf-mojo-LICENSE",
    "usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/GPL-2.0-only.txt",
    "usr/share/doc/memveil/licenses/libbpf-mojo-LICENSES/LLVM-exception.txt",
    "usr/share/memveil/docs/examples/real-capture/README.md",
    "usr/share/memveil/docs/examples/real-capture/events.ndjson",
    "usr/share/memveil/docs/examples/real-capture/session.json",
}

BPF_OBJECTS = (
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
)

SHORT_DESC = "swiotlb bounce-attempt capture and offline replay on x86-64 Linux"

# dpkg's t64 transition renamed libelf1 to libelf1t64 with no
# libelf1 candidate left (verified on Ubuntu 26.04: libelf1 has
# no install candidate). The alternation keeps the package
# installable on pre-t64 (libelf1) and current (libelf1t64)
# systems while staying a manual Depends (no dh_shlibs).
EXPECTED_DEPENDS = "libelf1t64 | libelf1, zlib1g"


def run(*argv, **kwargs):
    kwargs.setdefault("timeout", 300)
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )


@pytest.fixture(scope="module")
def listing():
    assert DEB and os.path.isfile(DEB), \
        "MV_DEB must name the built .deb"
    proc = run("dpkg-deb", "-c", DEB)
    assert proc.returncode == 0, proc.stderr
    files = {}
    dirs = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        assert len(parts) >= 6, line
        mode, owner = parts[0], parts[1]
        path = parts[-1]
        assert path.startswith("./"), line
        path = path[2:]
        if mode.startswith("d"):
            dirs[path.rstrip("/")] = (mode, owner)
        else:
            assert not path.endswith("/"), line
            files[path] = (mode, owner)
    assert files, "empty .deb"
    assert "" not in files and "./" not in files
    return files, dirs


@pytest.fixture(scope="module")
def extracted(tmp_path_factory):
    assert DEB and os.path.isfile(DEB), \
        "MV_DEB must name the built .deb"
    dest = tmp_path_factory.mktemp("debroot")
    proc = run("dpkg-deb", "-x", DEB, str(dest))
    assert proc.returncode == 0, proc.stderr
    return dest


@pytest.fixture(scope="module")
def engine_version(extracted):
    binary = extracted / "usr" / "bin" / "memveil"
    proc = run(str(binary), "version")
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.startswith("memveil-"), proc.stdout
    return proc.stdout.strip().split("-", 1)[1]


def deb_field(name):
    proc = run("dpkg-deb", "-f", DEB, name)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


def repo_tree_files(subdir, suffix):
    """Repo source files under subdir with suffix, as deb paths."""
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


def test_control_fields(engine_version):
    assert deb_field("Package").strip() == "memveil"
    assert deb_field("Version").strip() == engine_version + "-1"
    assert deb_field("Architecture").strip() == "amd64"
    assert deb_field("Depends").strip() == EXPECTED_DEPENDS
    assert deb_field("Section").strip() == "utils"
    assert deb_field("Priority").strip() == "optional"
    assert deb_field("Maintainer").strip() != ""
    desc = deb_field("Description")
    assert desc.splitlines()[0].strip() == SHORT_DESC, desc
    assert len(desc.splitlines()) > 1, "long description missing"
    rev = deb_field("X-Memveil-Revision").strip()
    assert rev == "export" or re.fullmatch(r"[0-9a-f]{40}", rev), rev
    lmb = deb_field("X-LMB-Tarball-SHA256").strip()
    lock = json.load(open(os.path.join(
        REPO, "toolchain.lock.json")))
    assert lmb == lock["dependencies"]["libbpf-mojo"]["tarball_sha256"]
    want_name = "memveil_%s-1_amd64.deb" % engine_version
    assert os.path.basename(DEB) == want_name, DEB


def test_file_list_exact(listing):
    files, _ = listing
    # Profiles and manuals ship the whole source trees: the
    # installed set must equal the repo set in both directions.
    profiles = {"usr/share/memveil/profiles/" + rel
                for rel in repo_tree_files("profiles", ".json")}
    profiles.add("usr/share/memveil/profiles/manifest.txt")
    docs = {"usr/share/memveil/docs/" + rel
            for rel in repo_tree_files("docs", ".md")}
    libs = {p for p in files if p.startswith("usr/lib/memveil/")}
    assert "usr/lib/memveil/libbpf_mojo.so.1" in libs
    assert {p for p in libs if p.endswith(".bpf.o")} == {
        "usr/lib/memveil/" + name for name in BPF_OBJECTS}
    rest = {p for p in libs
            if not p.endswith(".bpf.o")}
    assert rest, "no shared libraries shipped"
    assert all(re.fullmatch(r"usr/lib/memveil/[^/]+\.so(\..*)?",
                            p) for p in rest), rest - FIXED_FILES
    for path in rest:
        assert "%" not in path and " " not in path, path
    want = set(FIXED_FILES) | profiles | docs | libs
    assert set(files) == want, \
        "extra: %s; missing: %s" % (
            sorted(set(files) - want), sorted(want - set(files)))


def test_modes_owners_no_privilege_bits(listing):
    files, dirs = listing
    for path, (mode, owner) in sorted(dirs.items()):
        assert owner == "root/root", (path, owner)
        assert mode == "drwxr-xr-x", (path, mode)
    for path, (mode, owner) in sorted(files.items()):
        assert owner == "root/root", (path, owner)
        assert mode[0] == "-", (path, mode)
        assert "s" not in mode and "t" not in mode, (path, mode)
        assert mode[8] != "w", (path, mode)
        if path == "usr/bin/memveil":
            assert mode == "-rwxr-xr-x", (path, mode)
        else:
            assert mode == "-rw-r--r--", (path, mode)


def test_no_maintainer_scripts():
    ctrl = subprocess.run(
        ["dpkg-deb", "--ctrl-tarfile", DEB],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    assert ctrl.returncode == 0, ctrl.stderr
    out = subprocess.run(
        ["tar", "-t"], input=ctrl.stdout,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=300)
    assert out.returncode == 0, out.stderr
    members = {line.strip().lstrip("./") for line in
               out.stdout.decode().splitlines() if line.strip()}
    members.discard("")
    assert members == {"control", "md5sums"}, members


def test_md5sums_match_payload(extracted, tmp_path):
    import hashlib

    ctrl = tmp_path / "control"
    ctrl.mkdir()
    proc = run("dpkg-deb", "-e", DEB, str(ctrl))
    assert proc.returncode == 0, proc.stderr
    listed = {}
    for line in (ctrl / "md5sums").read_text().splitlines():
        digest, path = line.split("  ", 1)
        listed[path] = digest
    actual = {}
    for base, _, names in os.walk(extracted):
        for name in names:
            full = os.path.join(base, name)
            rel = os.path.relpath(full, extracted)
            actual[rel] = hashlib.md5(
                open(full, "rb").read()).hexdigest()
    assert listed == actual


def test_bpf_objects_unstripped(extracted):
    # dh_strip exclusion, proven directly: the installed BPF
    # objects keep machine EM_BPF and their symbol table.
    for name in BPF_OBJECTS:
        obj = extracted / "usr" / "lib" / "memveil" / name
        header = obj.read_bytes()[:20]
        assert header[:4] == b"\x7fELF", name
        machine = int.from_bytes(header[18:20], "little")
        assert machine == 247, (name, machine)
        proc = run("readelf", "-S", str(obj))
        assert proc.returncode == 0, proc.stderr
        assert "] .symtab" in proc.stdout, (name, proc.stdout)


def test_bpf_objects_match_build(extracted):
    import hashlib

    for name in BPF_OBJECTS:
        staged = os.path.join(REPO, "build", "bpf", name)
        if not os.path.isfile(staged):
            pytest.skip("build/bpf/%s absent: rerun with a built tree "
                        "to prove installed bytes equal built bytes"
                        % name)
    for name in BPF_OBJECTS:
        staged = os.path.join(REPO, "build", "bpf", name)
        installed = extracted / "usr" / "lib" / "memveil" / name
        assert (hashlib.sha256(installed.read_bytes()).hexdigest()
                == hashlib.sha256(
                    open(staged, "rb").read()).hexdigest()), name


def test_no_elf_under_usr_share(extracted):
    # Arch-dependent ELF under /usr/share is a lintian error;
    # the bridge and BPF objects live under /usr/lib instead.
    bad = []
    for base, _, names in os.walk(extracted / "usr" / "share"):
        for name in names:
            full = os.path.join(base, name)
            with open(full, "rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    bad.append(os.path.relpath(full, extracted))
    assert not bad, bad


def test_copyright_points_at_texts(extracted):
    copyright = (extracted / "usr" / "share" / "doc" / "memveil"
                 / "copyright")
    text = copyright.read_text()
    assert "GPL-3.0-or-later" in text, text
    assert "THIRD-PARTY-NOTICES" in text, text
    assert "GPL-2.0-only" in text, text


def test_no_man_no_completions(listing):
    # Task 7 owns man pages and completions: no half-done files.
    files, _ = listing
    bad = [p for p in files if "/man/" in p
           or "completion" in p]
    assert not bad, bad


def needed(path):
    proc = run("readelf", "-d", str(path))
    assert proc.returncode == 0, proc.stderr
    return [line.split("[")[1].split("]")[0]
            for line in proc.stdout.splitlines()
            if "(NEEDED)" in line and "[" in line]


def test_loader_closure(extracted):
    import importlib.util
    from importlib.machinery import SourceFileLoader

    binary = extracted / "usr" / "bin" / "memveil"
    proc = run("readelf", "-d", str(binary))
    assert proc.returncode == 0, proc.stderr
    assert "$ORIGIN/../lib/memveil" in proc.stdout, proc.stdout
    assert "/home/" not in proc.stdout \
        and "/work/" not in proc.stdout, proc.stdout
    proc = run("readelf", "-h", str(binary))
    assert proc.returncode == 0
    assert "X86-64" in proc.stdout, proc.stdout
    loader = SourceFileLoader(
        "mvpackage", os.path.join(REPO, "tools", "package"))
    spec = importlib.util.spec_from_loader("mvpackage", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    allow = set(module.SYSTEM_ALLOW)
    libs = sorted((extracted / "usr" / "lib" / "memveil").glob("*.so*"))
    assert libs, "no shared libraries extracted"
    shipped = {path.name for path in libs}
    for target in [binary] + libs:
        for name in needed(target):
            assert name in shipped or name in allow, \
                "%s needs %s: outside closure" % (target.name, name)


def test_docs_mirror_repo_and_links_resolve(extracted):
    docs = extracted / "usr" / "share" / "memveil" / "docs"
    base = os.path.join(REPO, "docs")
    for root, _, names in os.walk(base):
        for name in names:
            if not name.endswith(".md"):
                continue
            rel = os.path.relpath(os.path.join(root, name), base)
            installed = docs / rel
            assert installed.is_file(), rel
            assert installed.read_bytes() == open(
                os.path.join(root, name), "rb").read(), rel
    link = re.compile(r"\]\(([^)#]+)(#[^)]*)?\)")
    for root, _, names in os.walk(docs):
        for name in names:
            if not name.endswith(".md"):
                continue
            text = open(os.path.join(root, name),
                        encoding="utf-8").read()
            for target in link.findall(text):
                ref = target[0]
                if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:",
                            ref) or ref.startswith("/"):
                    continue
                dest = os.path.normpath(
                    os.path.join(root, ref))
                assert os.path.isfile(dest), \
                    "%s links missing %s" % (name, ref)


def test_receipts_state_dir_staged(listing):
    _, dirs = listing
    assert "var/lib/memveil/receipts" in dirs, sorted(dirs)
    assert "var/lib/memveil" in dirs
    files, _ = listing
    assert not [p for p in files
                if p.startswith("var/lib/memveil/")], \
        "state dir must ship empty"


def test_lintian_gate():
    if shutil.which("lintian") is None:
        pytest.skip(
            "lintian absent on this host "
            "(verified: only dpkg-deb/dpkg present): "
            "BPF-under-/usr/lib, no-ELF-under-/usr/share, "
            "no-maintainer-script, and control-field pins are "
            "asserted directly instead; rerun tools/test deb on "
            "a lintian-bearing host for the full gate")
    proc = run("lintian", DEB)
    print(proc.stdout)
    print(proc.stderr)
    errors = [line for line in
              (proc.stdout + proc.stderr).splitlines()
              if line.startswith("E:")]
    assert not errors, errors


def have_passwordless_sudo():
    proc = run("sudo", "-n", "true")
    return proc.returncode == 0


def test_install_doctor_uninstall_smoke(engine_version, tmp_path):
    if shutil.which("dpkg") is None or not have_passwordless_sudo():
        pytest.skip("install smoke needs dpkg plus passwordless "
                    "sudo; this host lacks one of them")
    probe = run("dpkg", "-s", "memveil")
    assert probe.returncode != 0, \
        "memveil is already installed (stale residue?): " \
        "remove it with `sudo dpkg -r memveil` and rerun"
    proc = run("sudo", "-n", "dpkg", "-i", DEB)
    assert proc.returncode == 0, proc.stderr
    try:
        try:
            status = run("dpkg", "-s", "memveil")
            assert status.returncode == 0, status.stderr
            assert "Status: install ok installed" in status.stdout
            verify = run("dpkg", "--verify", "memveil")
            assert verify.returncode == 0, verify.stderr
            assert verify.stdout == "", verify.stdout
            receipts = "/var/lib/memveil/receipts"
            assert os.path.isdir(receipts), "receipts dir missing"
            info = os.stat(receipts)
            assert stat.S_IMODE(info.st_mode) == 0o755, \
                oct(stat.S_IMODE(info.st_mode))
            assert info.st_uid == 0 and info.st_gid == 0
            doctor = run("/usr/bin/memveil", "doctor",
                         "--profiles-dir",
                         "/usr/share/memveil/profiles")
            assert doctor.returncode in (0, 3), doctor.stderr
            assert doctor.stdout.strip(), "doctor printed nothing"
            version = run("/usr/bin/memveil", "version")
            assert version.returncode == 0, version.stderr
            assert version.stdout.strip() == \
                "memveil-" + engine_version, version.stdout
            # Installed discovery with zero env/flags: record
            # must resolve the system bridge and objects, then
            # refuse at a later gate (or capture on a qualified
            # host) — never fail discovery itself.
            cap = tmp_path / "cap"
            record = run("/usr/bin/memveil", "record",
                         "--output", str(cap),
                         "--duration", "1",
                         cwd=str(tmp_path), env={})
            for missing in ("no bridge", "no object",
                            "missing --object"):
                assert missing not in record.stderr, record.stderr
            assert record.returncode in (0, 3, 4), record.stderr
            if record.returncode == 3:
                assert record.stderr.strip()
                assert not cap.exists(), \
                    "refused record left a capture dir"
            else:
                assert cap.exists(), \
                    "exit %d left no capture dir" \
                    % record.returncode
        finally:
            uninst = run("sudo", "-n", "dpkg", "-r", "memveil")
            assert uninst.returncode == 0, uninst.stderr
    except BaseException:
        run("sudo", "-n", "dpkg", "-r", "memveil")
        raise
    assert run("dpkg", "-s", "memveil").returncode != 0
    for path in ("/usr/lib/memveil", "/usr/share/memveil",
                 "/var/lib/memveil"):
        assert not os.path.exists(path), "residue: %s" % path
