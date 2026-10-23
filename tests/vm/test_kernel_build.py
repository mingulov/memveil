#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Reproducible kernel build tests: fragments, gates, link cleanup.

No build, no boot, no network. Every case runs from
controlled fixture bytes.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import kernel_matrix as km


def _tool_module():
    import importlib.machinery
    import importlib.util
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "..", "..", "tools", "kernel-build")
    loader = importlib.machinery.SourceFileLoader(
        "build_tool", path)
    spec = importlib.util.spec_from_loader("build_tool", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_fragment_lines_y_n_string():
    text = ("# comment\n\nCONFIG_A=y\n"
            "# CONFIG_B is not set\n"
            "CONFIG_C=\"hi\"\nCONFIG_D=m\n")
    assert km.fragment_lines(text) == [
        ("CONFIG_A", "y"), ("CONFIG_B", "n"),
        ("CONFIG_C", '"hi"'), ("CONFIG_D", "m")]


def test_merge_fragments_last_wins():
    merged = km.merge_fragments(["CONFIG_A=y\nCONFIG_B=y\n",
                                 "CONFIG_A=n\n"])
    assert merged == {"CONFIG_A": "n", "CONFIG_B": "y"}


def test_dropped_fragment_line_named():
    merged = {"CONFIG_PREEMPT_RT": "y", "CONFIG_EXPERT": "y"}
    final = "CONFIG_EXPERT=y\n"
    assert km.dropped_fragment_lines(merged, final) == [
        "CONFIG_PREEMPT_RT=y"]


def test_n_satisfied_by_not_set_or_absent():
    merged = {"CONFIG_FOO": "n"}
    assert km.dropped_fragment_lines(
        merged, "# CONFIG_FOO is not set\n") == []
    assert km.dropped_fragment_lines(merged, "CONFIG_X=y\n") == []
    assert km.dropped_fragment_lines(
        merged, "CONFIG_FOO=y\n") == ["CONFIG_FOO=n"]


def test_build_refuses_toolchain_drift_names_tool():
    tool = _tool_module()
    want = {"gcc": "gcc line", "ld": "ld line",
            "pahole": "pahole line"}
    tool.check_toolchain(want, dict(want))
    got = dict(want)
    got["ld"] = "other ld line"
    with pytest.raises(tool.BuildError) as err:
        tool.check_toolchain(want, got)
    assert "ld" in str(err.value)
    assert "gcc" not in str(err.value)


class _Vfs:
    def __init__(self, avail, size):
        self.f_bavail = avail
        self.f_frsize = size


def test_build_refuses_low_disk():
    tool = _tool_module()
    low = lambda path: _Vfs(24 * 1024 ** 3 // 4096, 4096)
    with pytest.raises(tool.BuildError):
        tool.check_free_space("/var/tmp", statvfs=low)
    room = lambda path: _Vfs(26 * 1024 ** 3 // 4096, 4096)
    tool.check_free_space("/var/tmp", statvfs=room)


def test_kernel_build_refuses_non_default_root(capsys):
    tool = _tool_module()
    code = tool.main(["--id", "no-such-row", "--root",
                      "/tmp/other-root"])
    assert code == 2
    assert "root" in capsys.readouterr().err


def test_kernel_build_allows_default_root_and_print_hashes(
        capsys):
    tool = _tool_module()
    code = tool.main(["--id", "no-such-row", "--root",
                      tool.BUILD_ROOT])
    assert code == 2
    assert "unknown row" in capsys.readouterr().err
    code = tool.main(["--id", "no-such-row", "--root",
                      "/tmp/other-root", "--print-hashes"])
    assert code == 2
    assert "unknown row" in capsys.readouterr().err


def test_build_env_refuses_unpinned_influencers(monkeypatch):
    tool = _tool_module()
    for var in ("LLVM", "KCFLAGS", "KAFLAGS",
                "CROSS_COMPILE", "CC", "HOSTCC", "ARCH"):
        monkeypatch.setenv(var, "x")
        with pytest.raises(tool.BuildError):
            tool.build_env()
        monkeypatch.delenv(var)
    env = tool.build_env()
    assert env["KBUILD_BUILD_USER"] == "memveil"


def test_build_links_removed_before_hash(tmp_path):
    tool = _tool_module()
    mods = tmp_path / "lib" / "modules" / "6.12.114-test"
    mods.mkdir(parents=True)
    (mods / "mod.ko").write_bytes(b"x")
    os.symlink("/nonexistent/tree", str(mods / "build"))
    os.symlink("/nonexistent/tree", str(mods / "source"))
    tool.remove_build_links(str(mods))
    assert not os.path.lexists(str(mods / "build"))
    assert not os.path.lexists(str(mods / "source"))
    assert (mods / "mod.ko").is_file()
    _, count = km.modules_manifest_sha(str(mods))
    assert count == 1
    tool.remove_build_links(str(mods))
    real = tmp_path / "real"
    (real / "build").mkdir(parents=True)
    with pytest.raises(tool.BuildError):
        tool.remove_build_links(str(real))
    assert (real / "build").is_dir()
