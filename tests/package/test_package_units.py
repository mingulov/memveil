# SPDX-License-Identifier: GPL-3.0-or-later

"""Unit tests for packaging validators, source identity and trace audit.

No builds or bundle: tools/package validators
are imported from the wrapper, and cleanroom helpers run over
synthetic fixtures, including the reviewer's interleaved
success/failure counterexamples.
"""

import importlib.util
import os
import subprocess
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
