# SPDX-License-Identifier: GPL-3.0-or-later

"""Debian package gate plus the rpm/man/completions contract.

The .deb built by tools/package-deb carries the FHS layout the
Phase A discovery constants resolve without flags or
environment: /usr/bin/memveil, the bridge plus the BPF
objects under /usr/lib/memveil (BPF ELF must not sit under
/usr/share), profiles and manuals under /usr/share/memveil,
generated man pages under /usr/share/man/man1, static shell
completions, and the state dir /var/lib/memveil/receipts.
Control pins the manual dependency set; there are no
maintainer scripts and no setuid/capabilities bits.

The lib/*.so* member names are the pixi toolchain closure and
vary with the lockfile, so they are pinned structurally
(ELF shared objects, bridge present, NEEDED closure holds)
rather than by name; every other member is pinned exactly,
and profiles/docs must mirror the repo source trees.

This file also pins the Task 7 generator contract, which
needs no .deb: tools/gen-man renders man pages from the live
`--help` texts (CLI help is the single source of truth),
tools/gen-completions renders static completions from the
frozen verb/flag sets below, and packaging/rpm/memveil.spec
carries the same FHS layout via %files. The frozen pins are
independent literals: a new verb, flag, or --format value
fails naming the exact token until the generator AND these
pins are updated together. The suite never regenerates
inside the test.

Environment: MV_DEB (required for the install-layout tests,
the built .deb), MV_REPO (optional, defaults to this
checkout). The generator/spec tests need only a built tree
(build/memveil) and run with MV_DEB unset.
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

needs_deb = pytest.mark.skipif(
    not DEB, reason="MV_DEB is not set (run tools/test deb)")

BIN = os.path.join(REPO, "build", "memveil")
needs_bin = pytest.mark.skipif(
    not os.path.isfile(BIN),
    reason="build/memveil is absent (run tools/build first)")

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

MAN_FILES = {
    "usr/share/man/man1/memveil.1",
    "usr/share/man/man1/memveil-record.1",
    "usr/share/man/man1/memveil-report.1",
    "usr/share/man/man1/memveil-top.1",
    "usr/share/man/man1/memveil-doctor.1",
    "usr/share/man/man1/memveil-qualify.1",
}

COMPLETION_FILES = {
    "usr/share/bash-completion/completions/memveil",
    "usr/share/zsh/vendor-completions/_memveil",
}

FIXED_FILES |= MAN_FILES | COMPLETION_FILES

BPF_OBJECTS = (
    "swiotlb_attempt.bpf.o",
    "swiotlb_lifecycle.bpf.o",
    "swiotlb_copy.bpf.o",
)

# Frozen completion source, pinned independently of the
# generator. Long flags only: the -h alias works on every
# verb but is intentionally omitted from completions (it
# appears in no --help text, so no drift guard can bind it).
FROZEN_VERBS = ("record", "report", "top", "doctor", "qualify",
                "help", "version")
FROZEN_TOP_FLAGS = ("--help", "--version")
FROZEN_FLAGS = {
    "record": ("--bridge", "--capability", "--cp-object",
               "--duration", "--help", "--lc-object",
               "--max-events-bytes", "--object", "--output",
               "--profile", "--profiles-dir"),
    "report": ("--allow-partial", "--format", "--help",
               "--long-lived-after", "--max-events-bytes",
               "--max-line-bytes", "--max-session-bytes"),
    "top": ("--bridge", "--capability", "--cp-object",
            "--device", "--duration", "--help", "--interval",
            "--lc-object", "--long-lived-after",
            "--max-events-bytes", "--max-line-bytes",
            "--max-session-bytes", "--object", "--output",
            "--profile"),
    "doctor": ("--help", "--json", "--profiles-dir"),
    "qualify": ("--bridge", "--capability", "--cp-object",
                "--help", "--lc-object", "--object",
                "--output", "--profile", "--profiles-dir"),
}
# --format's enum is closed in the parser (report.mojo);
# capabilities stay free text because the accepted set is
# profile-dependent, not statically closed.
FROZEN_FORMAT_VALUES = ("text", "json", "markdown")
FROZEN_NOVALUE_FLAGS = ("--help", "--allow-partial", "--json")

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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
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


@needs_deb
def test_copyright_points_at_texts(extracted):
    copyright = (extracted / "usr" / "share" / "doc" / "memveil"
                 / "copyright")
    text = copyright.read_text()
    assert "GPL-3.0-or-later" in text, text
    assert "THIRD-PARTY-NOTICES" in text, text
    assert "GPL-2.0-only" in text, text


@needs_deb
def test_man_and_completions_present(listing, extracted):
    files, dirs = listing
    for path in sorted(MAN_FILES | COMPLETION_FILES):
        assert path in files, "missing %s" % path
    assert "usr/share/man/man1" in dirs
    assert "usr/share/bash-completion/completions" in dirs
    assert "usr/share/zsh/vendor-completions" in dirs
    for path in sorted(MAN_FILES):
        text = (extracted / path).read_text()
        assert text.startswith(".TH MEMVEIL"), path
        assert "Generated by tools/gen-man" in text, path
        assert len(text.splitlines()) > 5, path
    bash = (extracted / "usr/share/bash-completion/completions"
            / "memveil").read_text()
    assert "generated by tools/gen-completions" in bash, bash[:200]
    assert "complete -F _memveil" in bash
    for verb in FROZEN_VERBS:
        assert verb in bash, "bash completions lack %s" % verb
    zsh = (extracted / "usr/share/zsh/vendor-completions"
           / "_memveil").read_text()
    assert zsh.startswith("#compdef memveil"), zsh[:200]
    for verb in FROZEN_VERBS:
        assert verb in zsh, "zsh completions lack %s" % verb


@needs_deb
@needs_bin
def test_installed_man_matches_current_help(extracted):
    # The .deb embeds man generated during its own build from
    # the same tree, so every current --help line must be in
    # the installed page: generated output never drifts.
    pages = {"": "memveil.1"}
    for verb in FROZEN_FLAGS:
        pages[verb] = "memveil-%s.1" % verb
    for verb, name in sorted(pages.items()):
        argv = [BIN] if verb == "" else [BIN, verb]
        proc = run(*(argv + ["--help"]))
        assert proc.returncode == 0, (verb, proc.stderr)
        text = (extracted / "usr/share/man/man1"
                / name).read_text()
        for line in proc.stdout.splitlines():
            assert _roff(line) in text, \
                "%s: installed man lacks help line %r" % (name, line)


def needed(path):
    proc = run("readelf", "-d", str(path))
    assert proc.returncode == 0, proc.stderr
    return [line.split("[")[1].split("]")[0]
            for line in proc.stdout.splitlines()
            if "(NEEDED)" in line and "[" in line]


@needs_deb
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


@needs_deb
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


@needs_deb
def test_receipts_state_dir_staged(listing):
    _, dirs = listing
    assert "var/lib/memveil/receipts" in dirs, sorted(dirs)
    assert "var/lib/memveil" in dirs
    files, _ = listing
    assert not [p for p in files
                if p.startswith("var/lib/memveil/")], \
        "state dir must ship empty"


@needs_deb
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


@needs_deb
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


# --- Generator and spec contract (no .deb needed) ---

GEN_MAN = os.path.join(REPO, "tools", "gen-man")
GEN_COMPLETIONS = os.path.join(REPO, "tools", "gen-completions")
SPEC = os.path.join(REPO, "packaging", "rpm", "memveil.spec")


def _roff(line):
    """The escaping contract tools/gen-man implements."""
    out = line.replace("\\", "\\(rs")
    if out.startswith(".") or out.startswith("'"):
        out = "\\&" + out
    return out


def _load_tool(name, path):
    import importlib.util
    from importlib.machinery import SourceFileLoader

    assert os.path.isfile(path), "missing %s" % path
    loader = SourceFileLoader(name, path)
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _help(verb):
    argv = [BIN] if verb == "" else [BIN, verb]
    proc = run(*(argv + ["--help"]))
    assert proc.returncode == 0, (verb, proc.stderr)
    assert proc.stdout.strip(), "empty --help for %r" % verb
    return proc.stdout


@needs_bin
def test_frozen_verbs_match_top_help():
    text = _help("")
    match = re.search(r"usage: memveil <([^>]+)>", text)
    assert match, text.splitlines()[0]
    live = set(match.group(1).split("|"))
    assert live == set(FROZEN_VERBS), \
        "new/renamed verb: live %s vs frozen %s" % (
            sorted(live), sorted(FROZEN_VERBS))
    for flag in FROZEN_TOP_FLAGS:
        proc = run(BIN, flag)
        assert proc.returncode == 0, \
            "top-level %s stopped working" % flag


@needs_bin
def test_frozen_flags_match_verb_help():
    for verb in sorted(FROZEN_FLAGS):
        text = _help(verb)
        live = set(re.findall(r"--[a-z][a-z-]*", text))
        want = set(FROZEN_FLAGS[verb]) - {"--help"}
        assert live == want, \
            "memveil %s: --help names %s vs frozen %s" % (
                verb, sorted(live), sorted(want))


@needs_bin
def test_frozen_value_arity_matches_synopsis():
    # Every value-taking flag shows a metavariable in the
    # synopsis brackets ([--output DIR]); the novalue pins
    # stand bare ([--json]). A flag that gains or loses its
    # value fails naming the verb and flag.
    for verb in sorted(FROZEN_FLAGS):
        text = _help(verb)
        para = text.split("\n\n")[0].replace("\n", " ")
        assert "usage:" in para, "no synopsis for %s" % verb
        takes_value = set()
        bare = set()
        for match in re.finditer(r"--[a-z][a-z-]*(?=[\s\]]|$)",
                                   para):
            rest = para[match.end():].split()
            if rest and not rest[0].startswith(("-", "[", "]")):
                takes_value.add(match.group(0))
            else:
                bare.add(match.group(0))
        for flag in sorted(set(FROZEN_FLAGS[verb]) - {"--help"}):
            if flag in FROZEN_NOVALUE_FLAGS:
                assert flag in bare, \
                    "memveil %s: frozen-novalue %s shows a value" % (
                        verb, flag)
            else:
                assert flag in takes_value, \
                    "memveil %s: %s lost its synopsis value" % (
                        verb, flag)


@needs_bin
def test_frozen_format_values_named_in_help():
    text = _help("report")
    for value in FROZEN_FORMAT_VALUES:
        assert value in text, \
            "--format value %r vanished from report --help" % value


def test_generator_frozen_matches_pins():
    module = _load_tool("mvgencomp", GEN_COMPLETIONS)
    assert tuple(module.FROZEN_VERBS) == FROZEN_VERBS, \
        "gen-completions verbs drifted from test pins"
    assert tuple(module.FROZEN_TOP_FLAGS) == FROZEN_TOP_FLAGS
    assert set(module.FROZEN_FLAGS) == set(FROZEN_FLAGS), \
        "gen-completions verbs %s vs pins %s" % (
            sorted(module.FROZEN_FLAGS), sorted(FROZEN_FLAGS))
    for verb in sorted(FROZEN_FLAGS):
        assert tuple(module.FROZEN_FLAGS[verb]) == \
            FROZEN_FLAGS[verb], \
            "gen-completions flags for %s drifted: %s" % (
                verb, module.FROZEN_FLAGS[verb])
    assert tuple(module.FROZEN_FORMAT_VALUES) == \
        FROZEN_FORMAT_VALUES
    assert set(module.FROZEN_NOVALUE_FLAGS) == \
        set(FROZEN_NOVALUE_FLAGS)


@needs_bin
def test_gen_man_embeds_current_help(tmp_path):
    assert os.path.isfile(GEN_MAN), "missing tools/gen-man"
    out = tmp_path / "man"
    proc = run(GEN_MAN, "--binary", BIN, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    version = run(BIN, "version")
    assert version.returncode == 0
    pages = {"": "memveil.1"}
    for verb in FROZEN_FLAGS:
        pages[verb] = "memveil-%s.1" % verb
    assert sorted(p.name for p in out.iterdir()) == \
        sorted(pages.values()), \
        "gen-man wrote %s" % sorted(p.name for p in out.iterdir())
    for verb, name in sorted(pages.items()):
        text = (out / name).read_text()
        title = "MEMVEIL" if verb == "" else \
            "MEMVEIL-" + verb.upper()
        assert text.startswith(".TH %s 1 " % title), name
        assert version.stdout.strip() in text, name
        assert "Generated by tools/gen-man" in text, name
        for line in _help(verb).splitlines():
            assert _roff(line) in text, \
                "%s drifts from --help at %r" % (name, line)


@needs_bin
def test_gen_man_deterministic(tmp_path):
    assert os.path.isfile(GEN_MAN), "missing tools/gen-man"
    first = tmp_path / "a"
    second = tmp_path / "b"
    for target in (first, second):
        proc = run(GEN_MAN, "--binary", BIN, "--out", str(target))
        assert proc.returncode == 0, proc.stderr
    names = sorted(p.name for p in first.iterdir())
    assert names, "gen-man wrote nothing"
    for name in names:
        assert (first / name).read_bytes() == \
            (second / name).read_bytes(), \
            "gen-man output for %s is not deterministic" % name


def test_gen_completions_covers_frozen(tmp_path):
    assert os.path.isfile(GEN_COMPLETIONS), \
        "missing tools/gen-completions"
    out = tmp_path / "comp"
    proc = run(GEN_COMPLETIONS, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    assert sorted(p.name for p in out.iterdir()) == \
        ["_memveil", "memveil"], \
        "gen-completions wrote %s" % sorted(
            p.name for p in out.iterdir())
    bash = (out / "memveil").read_text()
    assert "generated by tools/gen-completions" in bash
    assert "complete -F _memveil" in bash
    zsh = (out / "_memveil").read_text()
    assert zsh.startswith("#compdef memveil"), zsh[:200]
    for verb in FROZEN_VERBS:
        assert verb in bash, "bash lacks verb %s" % verb
        assert verb in zsh, "zsh lacks verb %s" % verb
    for flag in FROZEN_TOP_FLAGS:
        assert flag in bash, "bash lacks %s" % flag
        assert flag in zsh, "zsh lacks %s" % flag
    for verb in sorted(FROZEN_FLAGS):
        for flag in FROZEN_FLAGS[verb]:
            assert flag in bash, \
                "bash lacks memveil %s %s" % (verb, flag)
            assert flag in zsh, \
                "zsh lacks memveil %s %s" % (verb, flag)
    for value in FROZEN_FORMAT_VALUES:
        assert value in bash, "bash lacks --format %s" % value
        assert value in zsh, "zsh lacks --format %s" % value
    if shutil.which("bash") is None:
        pytest.skip("bash absent: cannot syntax-check completions")
    proc = run("bash", "-n", str(out / "memveil"))
    assert proc.returncode == 0, proc.stderr


def test_gen_completions_bash_functional(tmp_path):
    # Drive the generated _memveil function directly: stub
    # out `complete`, set COMP_WORDS/COMP_CWORD, read back
    # COMPREPLY. Proves the completion table, not just that
    # the tokens appear in the file.
    if shutil.which("bash") is None:
        pytest.skip("bash absent: cannot drive completions")
    assert os.path.isfile(GEN_COMPLETIONS), \
        "missing tools/gen-completions"
    out = tmp_path / "comp"
    proc = run(GEN_COMPLETIONS, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    driver = tmp_path / "drive.sh"
    driver.write_text(
        "complete() { :; }\n"
        "source \"$1\"\n"
        "shift\n"
        "cword=\"$1\"\n"
        "shift\n"
        "COMP_WORDS=(\"$@\")\n"
        "COMP_CWORD=\"$cword\"\n"
        "COMPREPLY=()\n"
        "_memveil\n"
        "printf '%s\\n' \"${COMPREPLY[@]}\"\n"
    )

    def complete(words, cword):
        proc = run("bash", str(driver), str(out / "memveil"),
                   str(cword), *words)
        assert proc.returncode == 0, proc.stderr
        return sorted(line for line in
                      proc.stdout.splitlines() if line)

    assert complete(["memveil", ""], 1) == sorted(FROZEN_VERBS)
    assert complete(["memveil", "--"], 1) == sorted(FROZEN_TOP_FLAGS)
    assert complete(["memveil", "record", "--"], 2) == \
        sorted(FROZEN_FLAGS["record"])
    assert complete(["memveil", "report", "--for"], 2) == ["--format"]
    assert complete(["memveil", "report", "--format", ""], 3) == \
        sorted(FROZEN_FORMAT_VALUES)
    assert complete(["memveil", "record", "--output", ""], 3) == []
    assert complete(["memveil", "bogus", "--"], 2) == []


def test_gen_completions_zsh_syntax(tmp_path):
    if shutil.which("zsh") is None:
        pytest.skip("zsh absent on this host: the _memveil file "
                    "is pinned by content (test_gen_completions_"
                    "covers_frozen) instead; rerun on a zsh host "
                    "for the syntax gate")
    assert os.path.isfile(GEN_COMPLETIONS), \
        "missing tools/gen-completions"
    out = tmp_path / "comp"
    proc = run(GEN_COMPLETIONS, "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    proc = run("zsh", "-n", str(out / "_memveil"))
    assert proc.returncode == 0, proc.stderr


def _spec_text():
    assert os.path.isfile(SPEC), \
        "missing packaging/rpm/memveil.spec"
    return open(SPEC).read()


_HEADERS = ("description|prep|build|install|files|clean|pre|"
              "post|preun|postun|pretrans|posttrans|trigger|"
              "changelog|package")


def _spec_section(text, name):
    match = re.search(r"^%%%s\n(.*?)(?=^%%(?:%s)\b|\Z)" % (
        name, _HEADERS), text, re.M | re.S)
    assert match, "spec has no %%%s section" % name
    return match.group(1)


def test_spec_version_matches_engine():
    text = _spec_text()
    match = re.search(r"^Version:\s*(\S+)\s*$", text, re.M)
    assert match, "spec has no Version tag"
    src = open(os.path.join(
        REPO, "src", "memveil", "model", "report.mojo")).read()
    engine = re.search(r'ENGINE_VERSION = "memveil-([^"]+)"', src)
    assert engine, "ENGINE_VERSION moved; update the drift guard"
    assert match.group(1) == engine.group(1), \
        "spec Version %s vs engine %s: bump together" % (
            match.group(1), engine.group(1))


def test_spec_files_cover_fhs():
    # The %files layout must equal the .deb payload: same FHS
    # paths for bin/lib/profiles/docs/man/completions, the
    # license texts by name, the state dir shipped empty.
    text = _spec_text()
    entries = [line.strip() for line in
               _spec_section(text, "files").splitlines()
               if line.strip() and
               not line.strip().startswith("#")]
    licenses = {
        "/usr/share/doc/memveil/" + rel
        for rel in ("copyright", "LICENSE",
                    "THIRD-PARTY-NOTICES.md",
                    "THIRD-PARTY-NOTICES.libbpf-mojo.md",
                    "LICENSES/GPL-2.0-only.txt",
                    "LICENSES/GPL-2.0-or-later.txt",
                    "licenses/GPL-3.0.txt",
                    "licenses/LICENSE.BSD-2-Clause.libbpf",
                    "licenses/LICENSE.mojo-compiler",
                    "licenses/LICENSE.zlib",
                    "licenses/NOTICE.mojo-runtime.md",
                    "licenses/RUNTIME.LIBRARY.EXCEPTION",
                    "licenses/Third-Party-Notices.mojo-compiler",
                    "licenses/libbpf-mojo-LICENSE",
                    "licenses/libbpf-mojo-LICENSES/GPL-2.0-only.txt")}
    man = {"/usr/share/man/man1/" + name for name in (
        "memveil.1", "memveil-record.1", "memveil-report.1",
        "memveil-top.1", "memveil-doctor.1",
        "memveil-qualify.1")}
    want = {
        "%defattr(-,root,root,-)",
        "/usr/bin/memveil",
        "%dir /usr/lib/memveil",
        "/usr/lib/memveil/*.so*",
        "/usr/lib/memveil/*.bpf.o",
        "%dir /usr/share/memveil",
        "/usr/share/memveil/profiles/",
        "/usr/share/memveil/docs/",
        "%dir /usr/share/doc/memveil",
        "/usr/share/bash-completion/completions/memveil",
        "/usr/share/zsh/vendor-completions/_memveil",
        "%dir /var/lib/memveil",
        "%dir /var/lib/memveil/receipts",
    } | licenses | man
    assert set(entries) == want, \
        "extra: %s; missing: %s" % (
            sorted(set(entries) - want), sorted(want - set(entries)))


def test_spec_no_scriptlets_or_privilege():
    text = _spec_text()
    for macro in ("%pre", "%post", "%preun", "%postun",
                  "%pretrans", "%posttrans", "%trigger"):
        assert not re.search(r"^%s\b" % macro, text, re.M), \
            "spec must ship no maintainer scriptlets (%s)" % macro
    assert "setcap" not in text, "file capabilities are forbidden"
    assert "setuid" not in text.lower(), "setuid is forbidden"
    assert not re.search(r"%attr\([^)]*[47][0-7]{3}", text), \
        "privilege bits in %attr are forbidden"
    assert re.search(r"^ExclusiveArch:\s*x86_64\s*$", text, re.M), \
        "collection targets x86-64 only"
    match = re.search(r"^Requires:\s*(.+)$", text, re.M)
    assert match, "manual Requires missing (no auto-deps)"
    for soname in ("libelf.so.1()(64bit)", "libz.so.1()(64bit)"):
        assert soname in match.group(1), \
            "Requires lacks %s" % soname


def test_spec_private_lib_pinning():
    # bundled()-style private lib: the Mojo closure and the
    # bridge ship under /usr/lib/memveil for the RUNPATH only
    # and must never satisfy other packages' deps.
    text = _spec_text()
    assert "bundled" in text.lower(), \
        "private-lib note must name the bundled() convention"
    assert re.search(r"^%global\s+__find_provides\s+%\{nil\}",
                     text, re.M), "__find_provides must be off"
    assert re.search(r"^%global\s+__find_requires\s+%\{nil\}",
                     text, re.M), "__find_requires must be off"
    assert re.search(r"^%global\s+__os_install_post\s+%\{nil\}",
                     text, re.M), \
        "brp-strip would strip the BPF symtabs; post must be off"


def test_spec_build_spells_pinned_inputs():
    text = _spec_text()
    assert re.search(r"^Source0:\s*memveil-%\{version\}\.tar\.gz",
                     text, re.M), "Source0 must be the source export"
    assert "libbpf-mojo" in text, "bridge tarball source missing"
    body = _spec_section(text, "build")
    assert "tools/package" in body, \
        "%build never runs tools/package"
    body = _spec_section(text, "install")
    for token in ("tools/gen-man", "tools/gen-completions",
                  "patchelf", "libbpf_mojo.so.1"):
        assert token in body, \
            "%%install never references %s" % token
    for name in BPF_OBJECTS:
        assert name in body, \
            "%%install never stages %s" % name
    assert text.count("%{") == len(
        re.findall(r"%\{[^}]*\}", text)), "unbalanced %{ macros"


def test_rpmspec_parse():
    _spec_text()
    if shutil.which("rpmspec") is None:
        pytest.skip(
            "rpmspec absent on this host "
            "(verified: rpmbuild/rpmspec not installed): "
            "the %files-coverage, scriptlet, macro-balance, and "
            "version pins above assert the spec contract "
            "instead; rerun on an rpm-bearing host for "
            "`rpmspec -P`, and no .rpm was built here")
    proc = run("rpmspec", "-P", SPEC)
    assert proc.returncode == 0, proc.stderr
