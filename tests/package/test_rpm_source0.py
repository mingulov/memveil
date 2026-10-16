# SPDX-License-Identifier: GPL-3.0-or-later

"""Source0 selection: the rpm Source0 tarball owns its file set.

tools/rpm-source0 builds the rpm-journey Source0 tarball from
the tree's own files only: inside an owning checkout it takes
exactly the tracked plus unignored-untracked set; under an
unrelated parent repository, or outside any repository, it
tars the tree minus generated directories instead of
inheriting the parent's file set. Git repository, index,
and configuration overrides from the environment can
neither relocate the ownership check nor shrink the
selected file set.
"""

import os
import subprocess
import tarfile

import pytest

REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))
SCRIPT = os.path.join(REPO, "tools", "rpm-source0")

VERSION = "0.1.0"


def run_git(args, cwd, env=None):
    base = {"GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull}
    if env:
        base.update(env)
    merged = dict(os.environ)
    merged.update(base)
    return subprocess.run(
        ["git", "-c", "init.defaultBranch=main",
         "-c", "user.email=source0@example.invalid",
         "-c", "user.name=source0"] + args,
        cwd=cwd, env=merged, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True)


def init_repo(path, tracked=(), untracked=(), ignored=()):
    os.makedirs(path, exist_ok=True)
    assert run_git(["init"], cwd=path).returncode == 0
    for rel in tracked:
        full = os.path.join(path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write("tracked %s\n" % rel)
    if ignored:
        with open(os.path.join(path, ".gitignore"), "w",
                  encoding="utf-8") as handle:
            handle.write("\n".join(ignored) + "\n")
        tracked = tuple(tracked) + (".gitignore",)
    assert run_git(["add"] + list(tracked),
                   cwd=path).returncode == 0
    assert run_git(["commit", "-m", "fixture"],
                   cwd=path).returncode == 0
    for rel in untracked:
        full = os.path.join(path, rel)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as handle:
            handle.write("untracked %s\n" % rel)
    return path


def run_source0(root, out, version=VERSION, env=None):
    merged = dict(os.environ) if env is None else env
    return subprocess.run(
        [SCRIPT, "--root", root, "--version", version,
         "--out", out],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, env=merged)


def members(out):
    with tarfile.open(out, "r:gz") as tar:
        return sorted(tar.getnames())


def test_usage_errors(tmp_path):
    proc = subprocess.run(
        [SCRIPT], stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True)
    assert proc.returncode == 2, proc.stdout
    proc = run_source0(str(tmp_path), str(tmp_path / "o.tar.gz"),
                       version="1.0/evil")
    assert proc.returncode == 2, proc.stdout
    proc = run_source0(str(tmp_path / "no-such-root"),
                       str(tmp_path / "o.tar.gz"))
    assert proc.returncode == 2, proc.stdout


def test_owning_checkout_selects_tracked_and_unignored(tmp_path):
    root = init_repo(str(tmp_path / "own"),
                     tracked=("a.txt", "sub/b.txt"),
                     untracked=("c.txt",),
                     ignored=("build/",))
    os.makedirs(os.path.join(root, "build"), exist_ok=True)
    with open(os.path.join(root, "build", "x.o"), "w",
              encoding="utf-8") as handle:
        handle.write("residue\n")
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(root, out)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    assert "memveil-%s/a.txt" % VERSION in got, got
    assert "memveil-%s/sub/b.txt" % VERSION in got, got
    assert "memveil-%s/c.txt" % VERSION in got, got
    assert not any(name.endswith("build/x.o") for name in got), got
    assert not any("/.git/" in name or name.endswith("/.git")
                   for name in got), got


def test_nested_owning_checkout_ignores_parent(tmp_path):
    parent = init_repo(str(tmp_path / "parent"),
                       tracked=("parent.txt",))
    child = init_repo(os.path.join(parent, "child"),
                      tracked=("child.txt",),
                      untracked=("child-new.txt",))
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(child, out)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    assert "memveil-%s/child.txt" % VERSION in got, got
    assert "memveil-%s/child-new.txt" % VERSION in got, got
    assert not any("parent.txt" in name for name in got), got


def test_plain_tree_under_parent_repo_tars_own_files(tmp_path):
    parent = init_repo(str(tmp_path / "parent"),
                       tracked=("parent.txt",))
    child = os.path.join(parent, "plain")
    os.makedirs(os.path.join(child, "build"), exist_ok=True)
    with open(os.path.join(child, "own.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("own\n")
    with open(os.path.join(child, "build", "x.o"), "w",
              encoding="utf-8") as handle:
        handle.write("residue\n")
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(child, out)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    assert "memveil-%s/own.txt" % VERSION in got, got
    assert not any("parent.txt" in name for name in got), got
    assert not any(name.endswith("build/x.o") for name in got), got


def test_outside_any_repo_tars_tree_minus_generated(tmp_path):
    root = os.path.join(str(tmp_path), "export")
    os.makedirs(os.path.join(root, "dist"), exist_ok=True)
    os.makedirs(os.path.join(root, "pkg", "__pycache__"),
                exist_ok=True)
    with open(os.path.join(root, "own.txt"), "w",
              encoding="utf-8") as handle:
        handle.write("own\n")
    with open(os.path.join(root, "dist", "x.tar.gz"), "w",
              encoding="utf-8") as handle:
        handle.write("residue\n")
    with open(os.path.join(root, "pkg", "__pycache__", "x.pyc"),
              "w", encoding="utf-8") as handle:
        handle.write("residue\n")
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(root, out)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    assert "memveil-%s/own.txt" % VERSION in got, got
    assert not any("dist/x.tar.gz" in name for name in got), got
    assert not any("__pycache__" in name for name in got), got


def test_git_env_override_cannot_relocate_ownership(tmp_path):
    root = init_repo(str(tmp_path / "own"),
                     tracked=("own.txt",))
    foreign = init_repo(str(tmp_path / "foreign"),
                        tracked=("foreign.txt",))
    env = dict(os.environ)
    env["GIT_DIR"] = os.path.join(foreign, ".git")
    env["GIT_WORK_TREE"] = foreign
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(root, out, env=env)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    assert "memveil-%s/own.txt" % VERSION in got, got
    assert not any("foreign.txt" in name for name in got), got


def test_git_config_excludes_cannot_shrink_selection(tmp_path):
    root = init_repo(str(tmp_path / "own"),
                     tracked=("keep.txt",),
                     untracked=("new-a.txt", "new-b.txt",
                                "helper-a.sh", "helper-b.sh"))
    excludes = tmp_path / "excludes"
    excludes.write_text("new-*\nhelper-*\n", encoding="utf-8")
    env = dict(os.environ)
    env["GIT_CONFIG_COUNT"] = "1"
    env["GIT_CONFIG_KEY_0"] = "core.excludesFile"
    env["GIT_CONFIG_VALUE_0"] = str(excludes)
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(root, out, env=env)
    assert proc.returncode == 0, proc.stdout
    got = members(out)
    for rel in ("keep.txt", "new-a.txt", "new-b.txt",
                "helper-a.sh", "helper-b.sh"):
        assert "memveil-%s/%s" % (VERSION, rel) in got, got


def test_empty_selection_refuses(tmp_path):
    root = os.path.join(str(tmp_path), "empty")
    os.makedirs(root, exist_ok=True)
    assert run_git(["init"], cwd=root).returncode == 0
    out = str(tmp_path / "source0.tar.gz")
    proc = run_source0(root, out)
    assert proc.returncode == 1, proc.stdout
