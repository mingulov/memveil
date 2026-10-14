# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for packaging validators, source identity and trace audit.

No builds or bundle: tools/package validators
are imported from the wrapper, and cleanroom helpers run over
synthetic fixtures, including the reviewer's interleaved
success/failure counterexamples.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from importlib.machinery import SourceFileLoader

import pytest

from cleanroom import audit_trace, check_manifest, reassemble

REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))


def load_package_tool():
    path = os.path.join(REPO, "tools", "package")
    loader = SourceFileLoader("mvpackage", path)
    spec = importlib.util.spec_from_loader("mvpackage", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


PKG = load_package_tool()


def _git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args],
                                   stderr=subprocess.DEVNULL, text=True).strip()


def _checkout(root):
    root.mkdir()
    _git(root, "init", "-q")
    (root / ".gitignore").write_text("exports/\n")
    _git(root, "add", ".gitignore")
    _git(root, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
         "commit", "-qm", "initial")


def test_export_identity_ignores_unrelated_parent(tmp_path):
    parent = tmp_path / "parent"
    _checkout(parent)
    export = parent / "exports" / "source"
    export.mkdir(parents=True)
    for dirty in (False, True):
        if dirty:
            (parent / "unrelated.txt").write_text("dirty\n")
        assert PKG.git_rev_or_none(str(export)) is None
        # An export has no owning worktree whose cleanliness can be used.
        with pytest.raises(SystemExit):
            PKG.git_clean(str(export))


def test_checkout_and_git_file_worktree_keep_identity(tmp_path):
    parent = tmp_path / "parent"
    _checkout(parent)
    head = _git(parent, "rev-parse", "HEAD")
    linked = tmp_path / "linked"
    _git(parent, "worktree", "add", "--detach", str(linked), "HEAD")
    assert (linked / ".git").is_file()
    for root in (parent, linked):
        assert PKG.git_rev_or_none(str(root)) == head
        assert PKG.git_clean(str(root))
        (root / "new.txt").write_text("dirty\n")
        assert not PKG.git_clean(str(root))


def test_tag_accepts_plain_names():
    assert PKG.validate_tag("memveil-0.1.0") == "memveil-0.1.0"
    assert PKG.validate_tag("a") == "a"


def test_tag_rejects_traversal_and_flags():
    for bad in ("", ".", "..", "../src", "a/b", "a\\b", "/abs",
                "-tag", "x\x00y"):
        with pytest.raises(ValueError):
            PKG.validate_tag(bad)


def test_lib_name_accepts_bare_names():
    assert PKG.validate_lib_name("libc.so.6", "x") == "libc.so.6"
    assert PKG.validate_lib_name("libbpf_mojo.so.1", "x") == \
        "libbpf_mojo.so.1"


def test_lib_name_rejects_escapes():
    for bad in ("", ".", "..", "../escape.so", "/abs.so",
                "sub/lib.so", "a\\b.so", "x\x00.so"):
        with pytest.raises(ValueError):
            PKG.validate_lib_name(bad, "probe")


def test_contained(tmp_path):
    base = tmp_path / "lib"
    base.mkdir()
    assert PKG.contained(str(base / "x.so"), str(base))
    assert not PKG.contained(str(tmp_path / "escape.so"),
                             str(base))
    assert not PKG.contained(
        str(base / ".." / "escape.so"), str(base))


def test_package_help_entry_point():
    proc = subprocess.run(
        [sys.executable, os.path.join(REPO, "tools", "package"),
         "--help"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    assert proc.returncode == 0
    assert "Usage: tools/package" in proc.stdout


def load_deb_tool():
    path = os.path.join(REPO, "tools", "package-deb")
    loader = SourceFileLoader("mvpackagedeb", path)
    spec = importlib.util.spec_from_loader("mvpackagedeb", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


DEB_PKG = load_deb_tool()

READELF_VERSION_NEEDS = """\
Version needs section '.gnu.version_r' contains 2 entries:
  000000: Version: 1  File: libc.so.6  Cnt: 3
  0x0010:   Name: GLIBC_2.17  Flags: none  Version: 4
  0x0020:   Name: GLIBC_2.34  Flags: none  Version: 5
  0x0030:   Name: GLIBC_2.38  Flags: none  Version: 7
  0x0040: Version: 1  File: libelf.so.1  Cnt: 1
  0x0050:   Name: ELFUTILS_1.0  Flags: none  Version: 3
"""


def test_glibc_floor_parses_max_need():
    assert DEB_PKG.parse_glibc_floor(
        READELF_VERSION_NEEDS) == (2, 38)


def test_glibc_floor_ignores_non_glibc():
    assert DEB_PKG.parse_glibc_floor(
        "Name: ELFUTILS_1.0\nName: GCC_3.0\n") is None
    assert DEB_PKG.parse_glibc_floor("") is None


CLEAN_TRACE = """\
100 execve("/b/bin/memveil", ["report"], 0x7f) = 0
100 openat(AT_FDCWD, "/b/lib/libK.so", O_RDONLY) = -1 ENOENT (No such file)
100 openat(AT_FDCWD, "/b/bin/../lib/libK.so", O_RDONLY) = 3
100 openat(AT_FDCWD, "/sys/devices/system/cpu/possible", O_RDONLY) = 4
100 openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY) = 5
100 openat(AT_FDCWD, "/cap/events.ndjson", O_RDONLY) = 6
"""

SPLIT_SUCCESS_BTF = """\
200 openat(AT_FDCWD, "/sys/kernel/btf/vmlinux", O_RDONLY <unfinished ...>
201 openat(AT_FDCWD, "/cap/events.ndjson", O_RDONLY) = 6
200 <... openat resumed> ) = 3
"""

SPLIT_SUCCESS_CONNECT = """\
300 socket(AF_UNIX, SOCK_STREAM, 0) = 7
300 connect(7, {sa_family=AF_UNIX, sun_path="/run/x"}, 110 <unfinished ...>
301 openat(AT_FDCWD, "/proc/cpuinfo", O_RDONLY) = 5
300 <... connect resumed> ) = 0
"""

SPLIT_FAILED_BTF = """\
400 openat(AT_FDCWD, "/sys/kernel/btf/vmlinux", O_RDONLY <unfinished ...>
400 <... openat resumed> ) = -1 ENOENT (No such file or directory)
"""

TRUNCATED_TRACE = """\
500 openat(AT_FDCWD, "/sys/kernel/btf/vmlinux", O_RDONLY <unfinished ...>
"""

ORPHAN_RESUME = """\
600 <... openat resumed> ) = 3
"""


def test_reassemble_joins_split_calls():
    completed, problems = reassemble(
        SPLIT_SUCCESS_BTF.splitlines())
    assert problems == [], problems
    assert len(completed) == 2
    assert ") = 3" in completed[0] or ") = 3" in completed[1]


def test_reassemble_flags_truncation_and_orphans():
    _, problems = reassemble(TRUNCATED_TRACE.splitlines())
    assert len(problems) == 1 and "truncated" in problems[0]
    _, problems = reassemble(ORPHAN_RESUME.splitlines())
    assert len(problems) == 1 and "orphan" in problems[0]


def test_audit_clean_trace_passes():
    assert audit_trace(CLEAN_TRACE, "/", "/repo") == []


def test_audit_catches_split_btf_success():
    violations = audit_trace(SPLIT_SUCCESS_BTF, "/", "/repo")
    assert len(violations) == 1
    assert "/sys/kernel/" in violations[0]


def test_audit_catches_split_connect_success():
    violations = audit_trace(SPLIT_SUCCESS_CONNECT, "/", "/repo")
    assert violations, "split connect success must flag"


def test_audit_ignores_split_failure():
    assert audit_trace(SPLIT_FAILED_BTF, "/", "/repo") == []


def test_audit_catches_bpf_and_socket():
    trace = ('700 bpf(BPF_PROG_LOAD, {prog_name="x"}, 128) = 8\n'
             '701 socket(AF_NETLINK, SOCK_RAW, 0) = 9\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 2


def test_audit_catches_dirfd_relative_and_chdir():
    trace = ('800 open(3, "rel/x", O_RDONLY) = 9\n'
             '801 openat(9, "rel/y", O_RDONLY) = 10\n'
             '802 chdir("/tmp") = 0\n')
    violations = audit_trace(trace, "/", "/repo")
    assert any("dirfd-relative" in v for v in violations), violations
    assert any(v.startswith("chdir:") for v in violations), violations


def test_audit_resolves_checkout_from_repo():
    trace = '900 openat(AT_FDCWD, "/elsewhere/x", O_RDONLY) = 3\n'
    assert audit_trace(trace, "/", "/elsewhere") != []
    assert audit_trace(trace, "/", "/repo") == []


def test_audit_catches_bpf_object_and_libbpf():
    trace = ('901 openat(AT_FDCWD, "/b/bpf/x.bpf.o", O_RDONLY) = 3\n'
             '902 openat(AT_FDCWD, "/usr/lib/libbpf.so.1", O_RDONLY) = 4\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 2, violations


def test_audit_normalizes_alias_paths():
    trace = ('910 openat(AT_FDCWD, "./proc/1/status", O_RDONLY) = 3\n'
             '911 openat(AT_FDCWD, "/proc/self/../1/status", O_RDONLY) = 4\n'
             '912 openat(AT_FDCWD, "/repo/./sub/data", O_RDONLY) = 5\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 3, violations
    assert any("proc:" in v for v in violations)
    assert any("checkout:" in v for v in violations)


def test_audit_ignores_near_miss_prefixes():
    trace = ('913 openat(AT_FDCWD, "/repo-sibling/x", O_RDONLY) = 3\n'
             '914 openat(AT_FDCWD, "/sys/kernell/x", O_RDONLY) = 4\n')
    assert audit_trace(trace, "/", "/repo") == []


def test_audit_parses_return_outside_quotes():
    trace = ('915 openat(AT_FDCWD, "/sys/kernel/) = -1", O_RDONLY) = 3\n'
             '916 openat(AT_FDCWD, "/tmp/) = 3", O_RDONLY)'
             ' = -1 ENOENT (No such file)\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 1, violations
    assert "/sys/kernel" in violations[0]


def test_audit_rejects_indeterminate_returns():
    trace = ('917 openat(AT_FDCWD, "/x", O_RDONLY) =\n'
             '918 connect(3, {...}, 16) = ?\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 2, violations
    assert all("indeterminate" in v for v in violations)


def test_audit_collapses_double_slash_aliases():
    trace = ('920 openat(AT_FDCWD, "//proc/1/status", O_RDONLY) = 3\n'
             '921 openat(AT_FDCWD, "//sys/kernel/btf/vmlinux", O_RDONLY) = 4\n'
             '922 openat(AT_FDCWD, "//repo/data", O_RDONLY) = 5\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 3, violations


def test_audit_quoted_marker_with_truncation():
    trace = ('923 openat(AT_FDCWD, "/sys/kernel/) = -1", O_RDONLY) =\n'
             '924 openat(AT_FDCWD, "/x", O_RDONLY) = \n'
             '\n'
             '925 openat(AT_FDCWD, "/ok", O_RDONLY) = 3\n')
    violations = audit_trace(trace, "/", "/repo")
    assert len(violations) == 2, violations
    assert all("indeterminate" in v for v in violations)


def _tree(tmp_path, names):
    for rel in names:
        full = tmp_path / rel
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_bytes(b"x")
    return str(tmp_path)


def test_manifest_exact_match_passes(tmp_path):
    names = ("bin/memveil", "lib/libbpf_mojo.so.1",
             "bpf/swiotlb_attempt.bpf.o",
             "bpf/swiotlb_lifecycle.bpf.o",
             "bpf/swiotlb_copy.bpf.o", "profiles/manifest.txt",
             "docs/quickstart.md", "LICENSE",
             "THIRD-PARTY-NOTICES.md")
    root = _tree(tmp_path, names + ("MANIFEST.json",))
    manifest = {"files": {n: "h" for n in names}}
    assert check_manifest(root, manifest) == []


def test_manifest_flags_omitted_critical_and_extras(tmp_path):
    names = ("bin/memveil", "lib/libbpf_mojo.so.1",
             "bpf/swiotlb_attempt.bpf.o",
             "bpf/swiotlb_lifecycle.bpf.o",
             "bpf/swiotlb_copy.bpf.o", "profiles/manifest.txt",
             "LICENSE", "THIRD-PARTY-NOTICES.md")
    root = _tree(tmp_path, names + ("stowaway", "MANIFEST.json"))
    manifest = {"files": {"lib/libbpf_mojo.so.1": "h",
                          "bpf/swiotlb_attempt.bpf.o": "h",
                          "bpf/swiotlb_lifecycle.bpf.o": "h",
                          "bpf/swiotlb_copy.bpf.o": "h",
                          "profiles/manifest.txt": "h",
                          "LICENSE": "h",
                          "THIRD-PARTY-NOTICES.md": "h",
                          "ghost": "h"}}
    problems = check_manifest(root, manifest)
    assert any("critical bin/memveil" in p for p in problems), \
        problems
    assert any("missing ghost" in p for p in problems), problems
    assert any("unlisted payload file stowaway" in p for p in problems), \
        problems


def load_tool_module(name):
    path = os.path.join(REPO, "tools", name + ".py")
    loader = importlib.machinery.SourceFileLoader(
        "mv%s" % name, path)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[loader.name] = module
    loader.exec_module(module)
    return module


def _write(path, data=b"x"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _admitted_tree(root):
    _write(root / "src" / "memveil" / "main.mojo", b"def main():\n")
    _write(root / "bpf" / "probe.c", b"int x;\n")
    _write(root / "profiles" / "manifest.txt", b"p\n")
    _write(root / "docs" / "note.md", b"# n\n")
    _write(root / "schemas" / "s.json", b"{}\n")
    _write(root / "examples" / "real-capture" / "events.ndjson",
           b"{}\n")
    _write(root / "tests" / "native" / "t.c", b"int y;\n")
    _write(root / "tests" / "shim" / "s.c", b"int z;\n")
    _write(root / "tests" / "vm" / "v.mojo", b"def v():\n")
    _write(root / "third_party" / "vendored.tgz", b"tgz")
    _write(root / "tools" / "build", b"#!/bin/sh\n")
    _write(root / "LICENSES" / "l.txt", b"l\n")
    _write(root / "toolchain.lock.json", b'{"a": 1}\n')
    _write(root / "pixi.toml", b"[x]\n")
    _write(root / "pixi.lock", b"l\n")
    _write(root / "LICENSE", b"L\n")
    _write(root / "THIRD-PARTY-NOTICES.md", b"T\n")
    return root


class TestSourceInventory:
    @pytest.fixture(scope="class")
    def inventory(self):
        return load_tool_module("source_inventory")

    def test_deterministic_digest(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        first = inventory.take_inventory(str(tmp_path))
        second = inventory.take_inventory(str(tmp_path))
        assert first == second
        assert first["format"] == "memveil-source-inventory"
        assert first["version"] == 1
        assert len(first["digest"]) == 64
        paths = [entry["path"] for entry in first["files"]]
        assert paths == sorted(paths)
        assert "src/memveil/main.mojo" in paths
        assert "toolchain.lock.json" in paths

    def test_records_mode_symlink_and_dir(self, inventory, tmp_path):
        target = _write(tmp_path / "src" / "real.mojo", b"r\n")
        target.chmod(0o640)
        os.symlink("real.mojo", tmp_path / "src" / "link.mojo")
        files = {entry["path"]: entry for entry in
                 inventory.take_inventory(str(tmp_path))["files"]}
        assert files["src"]["kind"] == "dir"
        assert files["src/real.mojo"]["kind"] == "file"
        assert files["src/real.mojo"]["mode"] == "0o640"
        assert files["src/link.mojo"]["kind"] == "symlink"
        assert files["src/link.mojo"]["target"] == "real.mojo"

    def test_excludes_generated(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        _write(tmp_path / "src" / "__pycache__" / "a.pyc", b"p")
        _write(tmp_path / "src" / "stray.pyc", b"p")
        _write(tmp_path / "build" / "memveil", b"b")
        _write(tmp_path / "dist" / "t.tar.gz", b"d")
        _write(tmp_path / ".pixi" / "envs" / "e", b"e")
        _write(tmp_path / ".git" / "HEAD", b"h")
        paths = [entry["path"] for entry in
                 inventory.take_inventory(str(tmp_path))["files"]]
        assert not [p for p in paths if "__pycache__" in p
                    or p.endswith(".pyc") or p.startswith("build/")
                    or p.startswith("dist/") or p.startswith(".pixi/")
                    or p.startswith(".git/")]

    def test_digest_ignores_timestamps(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        before = inventory.take_inventory(str(tmp_path))
        path = tmp_path / "docs" / "note.md"
        info = path.stat()
        os.utime(path, ns=(info.st_atime_ns + 10**9,
                           info.st_mtime_ns + 10**9))
        after = inventory.take_inventory(str(tmp_path))
        assert after["digest"] == before["digest"]
        assert inventory.compare(before, after) != []

    def test_compare_detects(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        before = inventory.take_inventory(str(tmp_path))
        (tmp_path / "src" / "memveil" / "main.mojo").write_bytes(
            b"changed\n")
        problems = inventory.compare(
            before, inventory.take_inventory(str(tmp_path)))
        assert problems == [
            "content changed: src/memveil/main.mojo"], problems
        (tmp_path / "bpf" / "probe.c").chmod(0o600)
        problems = inventory.compare(
            before, inventory.take_inventory(str(tmp_path)))
        assert any("mode changed: bpf/probe.c" in p
                   for p in problems), problems
        _write(tmp_path / "docs" / "added.md", b"a\n")
        (tmp_path / "schemas" / "s.json").unlink()
        problems = inventory.compare(
            before, inventory.take_inventory(str(tmp_path)))
        assert "added input: docs/added.md" in problems, problems
        assert "removed input: schemas/s.json" in problems, problems

    def test_compare_flags_restore(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        path = tmp_path / "docs" / "note.md"
        original = path.read_bytes()
        before = inventory.take_inventory(str(tmp_path))
        path.write_bytes(b"tampered\n")
        path.write_bytes(original)
        problems = inventory.compare(
            before, inventory.take_inventory(str(tmp_path)))
        assert problems == [
            "touched without content change: docs/note.md"], \
            problems

    def test_build_tool_is_inventoried(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        paths = [entry["path"] for entry in
                 inventory.take_inventory(str(tmp_path))["files"]]
        assert "tools/build" in paths

    def test_real_tree_build_tools_inventoried(self, inventory):
        paths = {entry["path"] for entry in
                 inventory.take_inventory(REPO)["files"]}
        for rel in ("tools/build", "tools/package",
                    "tools/source_inventory.py",
                    "tools/build_receipt.py"):
            assert rel in paths, rel

    def test_compare_flags_mtime_restore(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        path = tmp_path / "docs" / "note.md"
        original = path.read_bytes()
        before = inventory.take_inventory(str(tmp_path))
        (entry,) = [entry for entry in before["files"]
                    if entry["path"] == "docs/note.md"]
        path.write_bytes(b"tampered\n")
        path.write_bytes(original)
        info = path.stat()
        os.utime(path, ns=(info.st_atime_ns, entry["mtime_ns"]))
        problems = inventory.compare(
            before, inventory.take_inventory(str(tmp_path)))
        assert problems == [
            "touched without content change: docs/note.md"], \
            problems

    def test_symlink_inputs_trip(self, inventory, tmp_path):
        _admitted_tree(tmp_path)
        os.symlink("real.mojo",
                   tmp_path / "src" / "memveil" / "link.mojo")
        os.makedirs(tmp_path / "elsewhere", exist_ok=True)
        os.symlink("../elsewhere", tmp_path / "src" / "linkdir")
        sealed = inventory.take_inventory(str(tmp_path))
        kinds = {entry["path"]: entry["kind"]
                 for entry in sealed["files"]}
        assert kinds.get("src/memveil/link.mojo") == "symlink"
        assert kinds.get("src/linkdir") == "symlink"
        problems = inventory.compare(sealed, sealed)
        assert "symlink inputs unsupported: src/linkdir" in \
            problems, problems
        assert "symlink inputs unsupported: src/memveil/link.mojo" \
            in problems, problems

    def test_real_tree_has_no_symlink_inputs(self, inventory):
        kinds = [entry["kind"] for entry in
                 inventory.take_inventory(REPO)["files"]]
        assert "symlink" not in kinds

    def test_cli_out_and_help(self, inventory, tmp_path, capsys):
        _admitted_tree(tmp_path)
        out = tmp_path / "inv.json"
        assert inventory.main(
            [str(tmp_path), "--out", str(out)]) == 0
        assert json.loads(out.read_text())["format"] == \
            "memveil-source-inventory"
        assert inventory.main(["--bogus"]) == 2
        assert inventory.main(["--help"]) == 0


def _receipt_tree(root):
    _admitted_tree(root)
    (root / "toolchain.lock.json").write_text(json.dumps({
        "dependencies": {
            "libbpf-mojo": {"tarball_sha256": "lmb"}},
        "toolchain": {
            "libbpf_source": {"tarball_sha256": "libbpf"}}}))
    build = root / "build"
    _write(build / "memveil", b"binary")
    _write(build / "bpf" / "x.bpf.o", b"object")
    _write(build / "deps" / "lmb" / "lib" / "bridge.so", b"so")
    _write(build / "deps" / "include" / "bpf" / "h.h", b"h")
    _write(build / "deps" / "lmb-package.tgz", b"tgz")
    return root


class TestBuildReceipt:
    @pytest.fixture(scope="class")
    def receipt(self):
        return load_tool_module("build_receipt")

    @pytest.fixture()
    def probes(self, receipt, monkeypatch):
        monkeypatch.setattr(
            receipt, "PROBES",
            [("echo", ["echo", "probe-tool 1.0"])])
        return receipt.PROBES

    def _sealed(self, receipt, probes, root):
        pre = root / "pre.json"
        assert receipt.cmd_seal(
            str(root), str(pre)) == 0
        assert receipt.cmd_finalize(
            str(root), "build", str(pre), probes) == 0
        return root / "build" / "build-receipt.json"

    def test_finalize_writes_versioned_receipt(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        path = self._sealed(receipt, probes, tmp_path)
        data = json.loads(path.read_text())
        assert data["format"] == "memveil-build-receipt"
        assert data["version"] == 1
        assert data["toolchain_observed"] == \
            {"echo": "probe-tool 1.0"}
        assert data["dependencies"]["libbpf-mojo_tarball_sha256"] \
            == "lmb"
        assert "lmb-package.tgz_sha256" in data["dependencies"]
        assert data["outputs"]["memveil"]["size"] == 6
        assert "bpf/x.bpf.o" in data["outputs"]
        assert data["inventory"]["digest"]
        assert receipt.cmd_verify(
            str(tmp_path), str(path), "build") == 0

    def test_finalize_refuses_changed_input(
            self, receipt, probes, tmp_path, capsys):
        _receipt_tree(tmp_path)
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        (tmp_path / "docs" / "note.md").write_bytes(b"mutated\n")
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(pre), probes) == 1
        assert "changed during the build" in capsys.readouterr().err

    def test_finalize_refuses_restore(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        path = tmp_path / "docs" / "note.md"
        original = path.read_bytes()
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        path.write_bytes(b"tampered\n")
        path.write_bytes(original)
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(pre), probes) == 1

    def test_seal_records_resolved_deps(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        sealed = json.loads(pre.read_text())
        assert sealed["format"] == "memveil-build-seal"
        assert sealed["version"] == 1
        dep_paths = [entry["path"]
                     for entry in sealed["deps"]["files"]]
        assert "lmb/lib/bridge.so" in dep_paths
        assert "include/bpf/h.h" in dep_paths
        assert "lmb-package.tgz" in dep_paths

    def test_finalize_refuses_changed_dep(
            self, receipt, probes, tmp_path, capsys):
        _receipt_tree(tmp_path)
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        (tmp_path / "build" / "deps" / "lmb" / "lib"
         / "bridge.so").write_bytes(b"tampered\n")
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(pre), probes) == 1
        assert "resolved dependencies changed" in \
            capsys.readouterr().err

    def test_finalize_refuses_dep_restore(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        path = tmp_path / "build" / "deps" / "include" / "bpf" / "h.h"
        original = path.read_bytes()
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        path.write_bytes(b"tampered\n")
        path.write_bytes(original)
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(pre), probes) == 1

    def test_verify_loaded_ignores_receipt_path(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        path = self._sealed(receipt, probes, tmp_path)
        loaded = json.loads(path.read_text())
        path.write_text("garbage, not json")
        assert receipt.cmd_verify(
            str(tmp_path), str(path), "build") == 1
        assert receipt.verify_loaded(
            loaded, str(tmp_path), "build") == []

    def test_verify_flags_drift(
            self, receipt, probes, tmp_path, capsys):
        _receipt_tree(tmp_path)
        path = self._sealed(receipt, probes, tmp_path)
        (tmp_path / "profiles" / "manifest.txt").write_bytes(
            b"mutated\n")
        assert receipt.cmd_verify(
            str(tmp_path), str(path), "build") == 1
        assert "content changed: profiles/manifest.txt" in \
            capsys.readouterr().err

    def test_verify_flags_output_tamper(
            self, receipt, probes, tmp_path, capsys):
        _receipt_tree(tmp_path)
        path = self._sealed(receipt, probes, tmp_path)
        (tmp_path / "build" / "bpf" / "x.bpf.o").write_bytes(
            b"tampered-object-bytes!!")
        assert receipt.cmd_verify(
            str(tmp_path), str(path), "build") == 1
        assert "build output changed: bpf/x.bpf.o" in \
            capsys.readouterr().err

    def test_verify_flags_missing_output(
            self, receipt, probes, tmp_path):
        _receipt_tree(tmp_path)
        path = self._sealed(receipt, probes, tmp_path)
        (tmp_path / "build" / "bpf" / "x.bpf.o").unlink()
        assert receipt.cmd_verify(
            str(tmp_path), str(path), "build") == 1

    def test_rejects_bad_inputs(
            self, receipt, probes, tmp_path, capsys):
        _receipt_tree(tmp_path)
        assert receipt.cmd_verify(
            str(tmp_path), str(tmp_path / "absent.json"),
            "build") == 1
        garbage = tmp_path / "garbage.json"
        garbage.write_text("not json")
        assert receipt.cmd_verify(
            str(tmp_path), str(garbage), "build") == 1
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(garbage), probes) == 1
        assert receipt.cmd_finalize(
            str(tmp_path), "absent-dir",
            str(tmp_path / "pre.json"), probes) == 1
        assert receipt.main([]) == 0
        assert receipt.main(["bogus"]) == 2
        assert receipt.main(["verify"]) == 2

    def test_toolchain_failure(
            self, receipt, tmp_path, monkeypatch):
        monkeypatch.setattr(
            receipt, "PROBES", [("false", ["false"])])
        _receipt_tree(tmp_path)
        pre = tmp_path / "pre.json"
        assert receipt.cmd_seal(str(tmp_path), str(pre)) == 0
        assert receipt.cmd_finalize(
            str(tmp_path), "build", str(pre),
            receipt.PROBES) == 1


def _probe_copy(root, dest):
    skip = {".git", ".pixi", "build", "dist", "__pycache__",
            ".pytest_cache", ".mypy_cache", "fixtures"}

    def ignore(path, names):
        return [name for name in names
                if name in skip or name.endswith(".pyc")]

    shutil.copytree(root, dest, ignore=ignore,
                    ignore_dangling_symlinks=True)
    return dest


def _probe_build(root, dest):
    for rel in ("memveil", "bpf", os.path.join("deps", "lmb")):
        full = os.path.join(root, "build", rel)
        target = os.path.join(dest, "build", rel)
        if os.path.isdir(full) and not os.path.islink(full):
            shutil.copytree(full, target)
        elif os.path.isfile(full):
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(full, target)


class TestPackagingSeal:
    """End-to-end seal probes with substituted compilers.

    Only compiler/build actions are substituted (tools/build
    exits 0 over copied real artifacts; the relocatable link
    copies the real binary). Staging, hashing, closure walk,
    patchelf, version execution, manifest, and tarball run for
    real against a scratch tree, with deterministic mutation
    hooks at link time (post-seal, pre-verify) and version
    time (pre-verify).
    """

    @pytest.fixture(scope="class")
    def package(self):
        return load_package_tool()

    @pytest.fixture(scope="class")
    def receipt(self):
        return load_tool_module("build_receipt")

    @pytest.fixture(scope="class")
    def inventory(self):
        return load_tool_module("source_inventory")

    @pytest.fixture()
    def probe(self, tmp_path, monkeypatch):
        sentinels = (
            "build/memveil",
            "build/bpf/swiotlb_attempt.bpf.o",
            "build/deps/lmb/lib/libbpf_mojo.so.1",
            "build/deps/lmb/THIRD-PARTY-NOTICES.md",
            "third_party/libbpf-mojo-0.2.0.tar.gz",
        )
        missing = [rel for rel in sentinels
                   if not os.path.isfile(os.path.join(REPO, rel))]
        if missing:
            pytest.skip("needs built tree: %s" % ", ".join(missing))
        root = os.path.join(str(tmp_path), "probe")
        _probe_copy(REPO, root)
        _probe_build(REPO, root)
        return root

    def _commit(self, root):
        env = dict(os.environ,
                   GIT_CONFIG_NOSYSTEM="1",
                   HOME=os.path.expanduser("~"))
        base = ["git", "-C", root, "-c", "user.email=t@t",
                "-c", "user.name=t", "-c", "commit.gpgsign=false"]
        subprocess.run(["git", "init", "-q", root], check=True,
                       env=env)
        subprocess.run(base + ["add", "-A"], check=True, env=env,
                       stdout=subprocess.DEVNULL)
        subprocess.run(base + ["commit", "-qm", "probe"], check=True,
                       env=env, stdout=subprocess.DEVNULL)
        head = subprocess.run(
            base + ["rev-parse", "HEAD"], check=True, env=env,
            stdout=subprocess.PIPE, text=True).stdout.strip()
        return head

    def _seal(self, receipt, root, monkeypatch):
        monkeypatch.setattr(
            receipt, "PROBES", [("echo", ["echo", "probe"])])
        pre = os.path.join(root, "build", "sources-pre.json")
        assert receipt.cmd_seal(root, pre) == 0
        assert receipt.cmd_finalize(
            root, "build", pre, receipt.PROBES) == 0

    def _run(self, package, root, monkeypatch, link_hook=None,
             version_hook=None, argv=None, lmb="default"):
        real_run = package.run

        def fake_run(cmd, **kwargs):
            if cmd[:4] == ["pixi", "run", "--frozen", "mojo"] \
                    and "build" in cmd:
                dest = cmd[cmd.index("-o") + 1]
                shutil.copy2(os.path.join(root, "build", "memveil"),
                             dest)
                if link_hook is not None:
                    link_hook()
                return real_run(["true"])
            if len(cmd) == 2 and cmd[1] == "version":
                if version_hook is not None:
                    version_hook()
                return real_run(cmd, **kwargs)
            if cmd == [os.path.join(root, "tools", "build")]:
                return real_run(["true"])
            return real_run(cmd, **kwargs)

        monkeypatch.setattr(package, "ROOT", root)
        monkeypatch.setattr(
            package, "RUNTIME_LIB_DIR",
            os.path.join(REPO, ".pixi", "envs", "default", "lib"))
        monkeypatch.setattr(package, "run", fake_run)
        if lmb == "default":
            monkeypatch.setenv(
                "LMB_PACKAGE",
                os.path.join(
                    REPO, "third_party", "libbpf-mojo-0.2.0.tar.gz"))
        elif lmb == "unset":
            monkeypatch.delenv("LMB_PACKAGE", raising=False)
        else:
            monkeypatch.setenv("LMB_PACKAGE", lmb)
        out = os.path.join(root, "dist-seal")
        args = ["--out", out] + list(argv or [])
        return package.main(args), out

    def _manifest(self, out, tag=None):
        if tag is None:
            names = [name for name in os.listdir(out)
                     if name.endswith(".tar.gz")]
            assert len(names) == 1, names
            tag = names[0][:-len(".tar.gz")]
        path = os.path.join(out, tag, "MANIFEST.json")
        with open(path, "r", encoding="utf-8") as handle:
            return tag, json.load(handle)

    def test_quiet_git_packages(
            self, package, receipt, inventory, probe, monkeypatch):
        head = self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        assert self._run(package, probe, monkeypatch)[0] == 0
        tag, manifest = self._manifest(
            os.path.join(probe, "dist-seal"))
        assert manifest["memveil_revision"] == head
        sealed = inventory.take_inventory(probe)
        assert manifest["source_inventory_digest"] == \
            sealed["digest"]
        assert manifest["source_inventory"] == sealed["files"]

    def test_quiet_export_packages(
            self, package, receipt, probe, monkeypatch):
        self._seal(receipt, probe, monkeypatch)
        assert self._run(package, probe, monkeypatch)[0] == 0
        _, manifest = self._manifest(
            os.path.join(probe, "dist-seal"))
        assert manifest["memveil_revision"] == "export"

    def _refused(self, package, receipt, probe, monkeypatch,
                 capsys, link_hook=None, version_hook=None,
                 verify_hook=None, post_verify_hook=None,
                 expect=None):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        if verify_hook is not None or post_verify_hook is not None:
            real_verify = package.verify_staged_tree

            def hooked(staged, inv, outs, *extra):
                if verify_hook is not None:
                    verify_hook(staged)
                result = real_verify(staged, inv, outs, *extra)
                if post_verify_hook is not None:
                    post_verify_hook(staged)
                return result

            monkeypatch.setattr(package, "verify_staged_tree",
                                hooked)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       link_hook=link_hook,
                       version_hook=version_hook)
        assert exc.value.code == 1
        out = os.path.join(probe, "dist-seal")
        err = capsys.readouterr().err
        assert "seal" in err
        if expect is not None:
            assert expect in err, err
        leftovers = os.listdir(out) if os.path.isdir(out) else []
        assert leftovers == [], leftovers

    def _mutate(self, root, rel, data=b"tampered\n"):
        path = os.path.join(root, rel)
        with open(path, "ab") as handle:
            handle.write(data)

    def _mutate_lock_valid(self, root):
        path = os.path.join(root, "toolchain.lock.json")
        with open(path, "r", encoding="utf-8") as handle:
            lock = json.load(handle)
        lock["dependencies"]["libbpf-mojo"]["source_commit"] = \
            "tampered"
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(lock, handle, indent=2, sort_keys=True)
            handle.write("\n")

    def test_changed_mojo_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: self._mutate(
                probe, "src/memveil/main.mojo"))

    def test_changed_doc_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: self._mutate(
                probe, "docs/privacy.md"))

    def test_changed_profile_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: self._mutate(
                probe, "profiles/manifest.txt"))

    def test_changed_lock_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: self._mutate_lock_valid(probe),
            expect="toolchain.lock.json")

    def test_added_input_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        target = os.path.join(probe, "docs", "planted.md")

        def plant():
            with open(target, "wb") as handle:
                handle.write(b"p\n")

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=plant)

    def test_removed_input_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        target = os.path.join(probe, "profiles", "manifest.txt")
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: os.remove(target))

    def test_mode_change_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        target = os.path.join(probe, "docs", "privacy.md")
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: os.chmod(target, 0o600))

    def test_modify_restore_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        target = os.path.join(probe, "docs", "privacy.md")
        with open(target, "rb") as handle:
            original = handle.read()

        def mutate():
            with open(target, "wb") as handle:
                handle.write(b"tampered\n")

        def restore():
            with open(target, "wb") as handle:
                handle.write(original)

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=mutate, version_hook=restore)

    def test_stale_build_output_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        path = os.path.join(
            probe, "build", "bpf", "swiotlb_attempt.bpf.o")
        with open(path, "r+b") as handle:
            handle.seek(16)
            handle.write(b"STALE")
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch)
        assert exc.value.code == 1
        assert "seal" in capsys.readouterr().err

    def test_staged_tamper_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def tamper(staged):
            path = os.path.join(staged, "docs", "support.md")
            with open(path, "ab") as handle:
                handle.write(b"torn\n")

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=tamper)

    def test_staged_doc_deletion_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def delete(staged):
            os.remove(os.path.join(
                staged, "docs", "troubleshooting.md"))

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=delete, expect="troubleshooting.md")

    def test_staged_profile_deletion_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def delete(staged):
            os.remove(os.path.join(
                staged, "profiles", "manifest.txt"))

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=delete, expect="profiles/manifest.txt")

    def test_staged_output_deletion_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def delete(staged):
            os.remove(os.path.join(
                staged, "bpf", "swiotlb_copy.bpf.o"))

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=delete, expect="swiotlb_copy.bpf.o")

    def test_staged_mode_change_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def chmod(staged):
            os.chmod(os.path.join(
                staged, "docs", "support.md"), 0o600)

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=chmod, expect="docs/support.md")

    def test_lock_mutated_under_staging_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def mutate(staged):
            del staged
            self._mutate_lock_valid(probe)

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=mutate, expect="toolchain.lock.json")

    def test_packaging_pins_receipt_baseline(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with open(os.path.join(
                probe, "build", "build-receipt.json"),
                "rb") as handle:
            pinned = handle.read()
        want = hashlib.sha256(pinned).hexdigest()

        def rewrite():
            with open(os.path.join(
                    probe, "build", "build-receipt.json"),
                    "w", encoding="utf-8") as handle:
                handle.write("garbage, not a receipt")

        code, out = self._run(
            package, probe, monkeypatch, version_hook=rewrite)
        assert code == 0
        _, manifest = self._manifest(out)
        assert manifest["build_receipt_sha256"] == want

    def test_archive_failure_publishes_nothing(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)

        def boom(*args, **kwargs):
            raise OSError("injected archive failure")

        monkeypatch.setattr(package.tarfile, "open", boom)
        out = os.path.join(probe, "dist-seal")
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert os.listdir(out) == [], os.listdir(out)
        assert not os.path.exists(
            os.path.join(out, "probe-tag"))
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))

    def test_staged_mutation_after_verify_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def mutate(staged):
            with open(os.path.join(
                    staged, "bpf", "swiotlb_attempt.bpf.o"),
                    "ab") as handle:
                handle.write(b"torn\n")

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            post_verify_hook=mutate,
            expect="swiotlb_attempt.bpf.o")

    def test_staged_dir_symlink_refused(
            self, package, receipt, probe, monkeypatch, capsys):
        def linkdir(staged):
            shutil.rmtree(os.path.join(staged, "bpf"))
            os.symlink(os.path.join(probe, "build", "bpf"),
                       os.path.join(staged, "bpf"))

        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            verify_hook=linkdir, expect="staged directory")

    def test_rename_failure_publishes_nothing(
            self, package, receipt, probe, monkeypatch):
        out = os.path.join(probe, "dist-seal")
        os.makedirs(out, exist_ok=True)
        blocker = os.path.join(out, "probe-tag")
        with open(blocker, "wb") as handle:
            handle.write(b"alien\n")
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))
        assert not os.path.isdir(
            os.path.join(out, ".stage"))
        with open(blocker, "rb") as handle:
            assert handle.read() == b"alien\n"

    def _flaky_sha(self, package, monkeypatch, out, fail_on):
        real_sha = package.sha256_file
        tarball = os.path.join(out, "probe-tag.tar.gz")
        calls = []

        def flaky(path):
            if os.path.realpath(path) == os.path.realpath(tarball) \
                    if os.path.exists(tarball) \
                    else path == tarball:
                calls.append(path)
            if len(calls) >= fail_on:
                raise OSError("injected hash failure")
            return real_sha(path)

        monkeypatch.setattr(package, "sha256_file", flaky)
        return tarball

    def test_hash_failure_before_publish_removes_tarball(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        out = os.path.join(probe, "dist-seal")
        self._flaky_sha(package, monkeypatch, out, 1)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))
        assert not os.path.exists(
            os.path.join(out, "probe-tag"))
        assert not os.path.isdir(
            os.path.join(out, ".stage"))

    def test_hash_failure_after_publish_removes_bundle(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        out = os.path.join(probe, "dist-seal")
        self._flaky_sha(package, monkeypatch, out, 2)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))
        assert not os.path.exists(
            os.path.join(out, "probe-tag"))
        assert not os.path.isdir(
            os.path.join(out, ".stage"))

    def test_hash_mismatch_after_publish_removes_bundle(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        out = os.path.join(probe, "dist-seal")
        real_sha = package.sha256_file
        tarball = os.path.join(out, "probe-tag.tar.gz")
        calls = []

        def swapped(path):
            if path == tarball:
                calls.append(path)
                if len(calls) > 1:
                    return "0" * 64
            return real_sha(path)

        monkeypatch.setattr(package, "sha256_file", swapped)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))
        assert not os.path.exists(
            os.path.join(out, "probe-tag"))
        assert not os.path.isdir(
            os.path.join(out, ".stage"))

    def test_staging_setup_failure_refused(
            self, package, receipt, probe, monkeypatch):
        out = os.path.join(probe, "dist-seal")
        os.makedirs(out, exist_ok=True)
        with open(os.path.join(out, ".stage"), "wb") as handle:
            handle.write(b"alien\n")
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch)
        assert exc.value.code == 1
        assert not os.path.isdir(os.path.join(out, ".stage"))

    def test_early_refusal_drops_matching_candidates(
            self, package, receipt, probe, monkeypatch, capsys):
        proc = subprocess.run(
            [os.path.join(probe, "build", "memveil"), "version"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, cwd=probe)
        assert proc.returncode == 0, proc.stderr
        tag = "memveil-" + proc.stdout.strip().split("-", 1)[1]
        out = os.path.join(probe, "dist-seal")
        os.makedirs(os.path.join(out, tag))
        with open(os.path.join(out, tag + ".tar.gz"),
                  "wb") as handle:
            handle.write(b"stale\n")
        self._refused(
            package, receipt, probe, monkeypatch, capsys,
            link_hook=lambda: self._mutate(
                probe, "docs/privacy.md"))

    def test_invalid_tag_deletes_nothing(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        out = os.path.join(probe, "dist-seal")
        nested = os.path.join(out, "keep", "subdir")
        os.makedirs(nested)
        sentinel = os.path.join(nested, "sentinel.txt")
        with open(sentinel, "wb") as handle:
            handle.write(b"keep\n")
        seeded_tarball = os.path.join(out, "keep", "subdir.tar.gz")
        with open(seeded_tarball, "wb") as handle:
            handle.write(b"keep\n")
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "keep/subdir"])
        assert exc.value.code == 1
        with open(sentinel, "rb") as handle:
            assert handle.read() == b"keep\n"
        with open(seeded_tarball, "rb") as handle:
            assert handle.read() == b"keep\n"

    def test_tarball_swap_before_hash_refused(
            self, package, receipt, probe, monkeypatch):
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        out = os.path.join(probe, "dist-seal")
        real_sha = package.sha256_file
        tarball = os.path.join(out, "probe-tag.tar.gz")
        swapped = []

        def swapping(path):
            if path == tarball and not swapped:
                swapped.append(path)
                with open(tarball, "wb") as handle:
                    handle.write(b"forged-tarball-bytes")
            return real_sha(path)

        monkeypatch.setattr(package, "sha256_file", swapping)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"])
        assert exc.value.code == 1
        assert swapped == [tarball]
        assert not os.path.exists(
            os.path.join(out, "probe-tag.tar.gz"))
        assert not os.path.exists(
            os.path.join(out, "probe-tag"))
        assert not os.path.isdir(
            os.path.join(out, ".stage"))

    def test_missing_bridge_drops_matching_candidates(
            self, package, receipt, probe, monkeypatch):
        out = os.path.join(probe, "dist-seal")
        os.makedirs(os.path.join(out, "probe-tag"))
        with open(os.path.join(out, "probe-tag.tar.gz"),
                  "wb") as handle:
            handle.write(b"stale\n")
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"], lmb="unset")
        assert exc.value.code == 1
        assert os.listdir(out) == [], os.listdir(out)

    def test_nonfile_bridge_drops_matching_candidates(
            self, package, receipt, probe, monkeypatch):
        out = os.path.join(probe, "dist-seal")
        os.makedirs(os.path.join(out, "probe-tag"))
        with open(os.path.join(out, "probe-tag.tar.gz"),
                  "wb") as handle:
            handle.write(b"stale\n")
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       argv=["--tag", "probe-tag"],
                       lmb=os.path.join(probe, "no-such.tgz"))
        assert exc.value.code == 1
        assert os.listdir(out) == [], os.listdir(out)

    def test_failed_run_preserves_other_bundles(
            self, package, receipt, probe, monkeypatch, capsys):
        out = os.path.join(probe, "dist-seal")
        os.makedirs(os.path.join(out, "other-tag"))
        sentinel = os.path.join(out, "sentinel.txt")
        with open(sentinel, "wb") as handle:
            handle.write(b"keep\n")
        self._commit(probe)
        self._seal(receipt, probe, monkeypatch)
        with pytest.raises(SystemExit) as exc:
            self._run(package, probe, monkeypatch,
                       link_hook=lambda: self._mutate(
                           probe, "docs/privacy.md"))
        assert exc.value.code == 1
        assert "seal" in capsys.readouterr().err
        assert sorted(os.listdir(out)) == [
            "other-tag", "sentinel.txt"], os.listdir(out)
        with open(sentinel, "rb") as handle:
            assert handle.read() == b"keep\n"
