# SPDX-License-Identifier: GPL-3.0-or-later

"""Remap helpers preserve Cargo's flag selection.

Both release-build funnels (the tarball packager's in-flow
build and the docs driver's --build) add a home/checkout
path-remap pair to the cargo invocation. The pair must
extend the flag set Cargo itself would use -- the encoded
spelling when set, else RUSTFLAGS when set, else the config
layer carried forward -- exactly once, leaving through the
encoded channel alone: merging channels fabricates
conflicting flags Cargo would never pass, and exporting
remaps alone shadows config-sourced flags.

Every test runs against both helpers; each builds a fully
synthetic environment plus tmp config files, so no ambient
cargo configuration can leak in.
"""

import importlib.util
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name, leaf):
    path = ROOT / "scripts" / leaf
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PACKAGER = _load("mv_remap_packager", "package-tarball.py")
DOCS = _load("mv_remap_gendocs", "gen-docs.py")

HELPERS = pytest.mark.parametrize(
    "module", [PACKAGER, DOCS], ids=["packager", "docs"])


@pytest.fixture()
def isolated(tmp_path, monkeypatch):
    """Synthetic build tree with no ambient cargo config."""
    home = tmp_path / "home"
    home.mkdir()
    cargo_home = tmp_path / "cargo-home"
    cargo_home.mkdir()
    build = tmp_path / "build"
    build.mkdir()
    env = {"HOME": str(home), "CARGO_HOME": str(cargo_home),
           "PATH": os.environ.get("PATH", "")}
    monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    return env, build


def _remap(module, env, build):
    if module is PACKAGER:
        module.remap_build_paths(env, str(build))
    else:
        module.remap_build_paths(env)
    assert "RUSTFLAGS" not in env
    return env["CARGO_ENCODED_RUSTFLAGS"].split("\x1f")


def _pair(env, build):
    home = env["HOME"]
    return ["--remap-path-prefix=%s=/build-prefix" % home,
            "--remap-path-prefix=%s=/build-root"
            % os.path.abspath(build)]


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@HELPERS
def test_conflicting_channels_export_encoded_only(
        module, isolated):
    """Both channels set: the encoded set wins whole, once."""
    env, build = isolated
    env["CARGO_ENCODED_RUSTFLAGS"] = "-Copt-level=3"
    env["RUSTFLAGS"] = "-Copt-level=0"
    assert _remap(module, env, build) == \
        ["-Copt-level=3"] + _pair(env, build)


@HELPERS
def test_rustflags_channel_moves_to_encoded(module, isolated):
    env, build = isolated
    env["RUSTFLAGS"] = "-C opt-level=0"
    assert _remap(module, env, build) == \
        ["-C", "opt-level=0"] + _pair(env, build)


@HELPERS
def test_rustflags_channel_shadows_config(module, isolated):
    """A set channel wins over config files, like Cargo."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = ["-C", "opt-level=1"]\n')
    env["RUSTFLAGS"] = "-C opt-level=0"
    assert _remap(module, env, build) == \
        ["-C", "opt-level=0"] + _pair(env, build)


@HELPERS
def test_channel_set_ignores_broken_config(module, isolated):
    """A set channel never even reads the config layer."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml", "not = [valid\n")
    env["RUSTFLAGS"] = "-C opt-level=0"
    assert _remap(module, env, build) == \
        ["-C", "opt-level=0"] + _pair(env, build)


@HELPERS
def test_empty_encoded_shadows_rustflags(module, isolated):
    """Presence selects the channel, not non-emptiness."""
    env, build = isolated
    env["CARGO_ENCODED_RUSTFLAGS"] = ""
    env["RUSTFLAGS"] = "-C opt-level=0"
    assert _remap(module, env, build) == _pair(env, build)


@HELPERS
def test_empty_rustflags_shadows_config(module, isolated):
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = ["-C", "opt-level=1"]\n')
    env["RUSTFLAGS"] = ""
    assert _remap(module, env, build) == _pair(env, build)


@HELPERS
def test_encoded_empty_segments_preserved(module, isolated):
    """Cargo passes empty segments through; so must we."""
    env, build = isolated
    env["CARGO_ENCODED_RUSTFLAGS"] = "-C\x1f\x1f-X"
    assert _remap(module, env, build) == \
        ["-C", "", "-X"] + _pair(env, build)


@HELPERS
def test_rustflags_quoted_flag_keeps_quotes(module, isolated):
    """Quotes ride through untouched: words break on spaces alone."""
    env, build = isolated
    env["RUSTFLAGS"] = '--cfg mv_cfg="quoted"'
    assert _remap(module, env, build) == \
        ["--cfg", 'mv_cfg="quoted"'] + _pair(env, build)


@HELPERS
@pytest.mark.parametrize("text,want", [
    ('--cfg mv="a b"', ["--cfg", 'mv="a', 'b"']),
    ("--cfg 'a b'", ["--cfg", "'a", "b'"]),
    ('"a b" c', ['"a', 'b"', "c"]),
    ('a"b c"d', ['a"b', 'c"d']),
    ("a'b c'd", ["a'b", "c'd"]),
    ("a\\ b", ["a\\", "b"]),
    ("a\\", ["a\\"]),
    ("\\", ["\\"]),
    ('"a', ['"a']),
    ("'a", ["'a"]),
    ('""', ['""']),
    ("''", ["''"]),
    ('"', ['"']),
    ('foo"bar', ['foo"bar']),
    ("a\tb", ["a\tb"]),
    ("a\nb", ["a\nb"]),
    ("a\rb", ["a\rb"]),
    ("a\x0bb", ["a\x0bb"]),
    ("a\x0cb", ["a\x0cb"]),
    ("a\xa0", ["a\xa0"]),
    ("a\xa0b", ["a\xa0b"]),
    ("a  b", ["a", "b"]),
    ("  a  ", ["a"]),
    ("", []),
    ("   ", []),
    ("#foo", ["#foo"]),
])
def test_rustflags_words_break_on_spaces_alone(
        module, isolated, text, want):
    """Only spaces split; quotes, backslashes, and other blanks stay literal."""
    env, build = isolated
    env["RUSTFLAGS"] = text
    assert _remap(module, env, build) == want + _pair(env, build)


@HELPERS
def test_config_file_array_survives(module, isolated):
    """Config-sourced flags ride along with the remaps."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = ["-C", "opt-level=1"]\n')
    assert _remap(module, env, build) == \
        ["-C", "opt-level=1"] + _pair(env, build)


@HELPERS
def test_config_file_string_splits_on_whitespace(
        module, isolated):
    """String values split on whitespace; quotes stay literal."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = "--cfg foo=\\"a b\\""\n')
    assert _remap(module, env, build) == \
        ["--cfg", 'foo="a', 'b"'] + _pair(env, build)


@HELPERS
def test_config_join_order(module, isolated, tmp_path,
                           monkeypatch):
    """Home, then ancestors down, then the dotted spelling."""
    env, build = isolated
    parent = tmp_path / "outer"
    parent.mkdir()
    build = parent / "inner"
    build.mkdir()
    if module is DOCS:
        monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    _write(Path(env["CARGO_HOME"]) / "config.toml",
           '[build]\nrustflags = ["--cfg", "home"]\n')
    _write(parent / ".cargo" / "config.toml",
           '[build]\nrustflags = ["--cfg", "parent"]\n')
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = ["--cfg", "child"]\n')
    env["CARGO_BUILD_RUSTFLAGS"] = "--cfg dotted"
    assert _remap(module, env, build) == [
        "--cfg", "home", "--cfg", "parent", "--cfg", "child",
        "--cfg", "dotted"] + _pair(env, build)


@HELPERS
def test_extensionless_config_wins_same_level(
        module, isolated):
    env, build = isolated
    cargo_dir = build / ".cargo"
    _write(cargo_dir / "config.toml",
           '[build]\nrustflags = ["--cfg", "dotted"]\n')
    _write(cargo_dir / "config",
           '[build]\nrustflags = ["--cfg", "plain"]\n')
    assert _remap(module, env, build) == \
        ["--cfg", "plain"] + _pair(env, build)


@HELPERS
def test_extensionless_without_flags_suppresses_toml(
        module, isolated):
    """The winner suppresses the loser wholesale, even flagless."""
    env, build = isolated
    cargo_dir = build / ".cargo"
    _write(cargo_dir / "config", "[build]\njobs = 2\n")
    _write(cargo_dir / "config.toml",
           '[build]\nrustflags = ["--cfg", "ignored"]\n')
    assert _remap(module, env, build) == _pair(env, build)


@HELPERS
def test_broken_losing_leaf_ignored(module, isolated):
    """A broken config.toml stays unread where config wins."""
    env, build = isolated
    cargo_dir = build / ".cargo"
    _write(cargo_dir / "config",
           '[build]\nrustflags = ["--cfg", "plain"]\n')
    _write(cargo_dir / "config.toml", "not = [valid\n")
    assert _remap(module, env, build) == \
        ["--cfg", "plain"] + _pair(env, build)


@HELPERS
def test_broken_symlink_counts_as_absent(module, isolated):
    """A broken link is no leaf: the dotted file serves."""
    env, build = isolated
    cargo_dir = build / ".cargo"
    cargo_dir.mkdir(parents=True)
    os.symlink(str(build / "nowhere"), str(cargo_dir / "config"))
    _write(cargo_dir / "config.toml",
           '[build]\nrustflags = ["--cfg", "dotted"]\n')
    assert _remap(module, env, build) == \
        ["--cfg", "dotted"] + _pair(env, build)


@HELPERS
def test_directory_leaf_refuses(module, isolated):
    """An extensionless directory refuses instead of falling through."""
    env, build = isolated
    cargo_dir = build / ".cargo"
    (cargo_dir / "config").mkdir(parents=True)
    _write(cargo_dir / "config.toml",
           '[build]\nrustflags = ["--cfg", "dotted"]\n')
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
def test_layered_strings_replace(
        module, isolated, tmp_path, monkeypatch):
    """A nearer string replaces the ancestor string outright."""
    env, _build = isolated
    parent = tmp_path / "outer"
    parent.mkdir()
    build = parent / "inner"
    build.mkdir()
    if module is DOCS:
        monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    _write(parent / ".cargo" / "config.toml",
           '[build]\nrustflags = "--cfg old"\n')
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = "--cfg new"\n')
    assert _remap(module, env, build) == \
        ["--cfg", "new"] + _pair(env, build)


@HELPERS
@pytest.mark.parametrize("outer,inner", [
    ('[build]\nrustflags = "--cfg old"\n',
     '[build]\nrustflags = ["--cfg", "new"]\n'),
    ('[build]\nrustflags = ["--cfg", "old"]\n',
     '[build]\nrustflags = "--cfg new"\n'),
])
def test_mixed_string_array_refuses(
        module, isolated, tmp_path, monkeypatch, outer, inner):
    """A string meeting an array across files refuses, either way round."""
    env, _build = isolated
    parent = tmp_path / "outer"
    parent.mkdir()
    build = parent / "inner"
    build.mkdir()
    if module is DOCS:
        monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    _write(parent / ".cargo" / "config.toml", outer)
    _write(build / ".cargo" / "config.toml", inner)
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
def test_home_ancestor_overlap_loads_once(
        module, isolated, tmp_path, monkeypatch):
    """A home overlapping an ancestor loads once, at the ancestor."""
    env, _build = isolated
    parent = tmp_path / "outer"
    build = parent / "inner"
    build.mkdir(parents=True)
    if module is DOCS:
        monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    env["CARGO_HOME"] = str(parent / ".cargo")
    _write(parent / ".cargo" / "config.toml",
           '[build]\nrustflags = ["--cfg", "dup"]\n')
    _write(build / ".cargo" / "config.toml",
           '[build]\nrustflags = ["--cfg", "child"]\n')
    flags = _remap(module, env, build)
    assert flags == ["--cfg", "dup", "--cfg", "child"] \
        + _pair(env, build)
    assert flags.count("dup") == 1


@HELPERS
def test_home_ancestor_overlap_symlink_loads_once(
        module, isolated, tmp_path, monkeypatch):
    """Overlap through a symlinked spelling loads once too."""
    env, _build = isolated
    parent = tmp_path / "outer"
    build = parent / "inner"
    build.mkdir(parents=True)
    if module is DOCS:
        monkeypatch.setattr(DOCS, "ROOT_DIR", str(build))
    (parent / ".cargo").mkdir(parents=True)
    link = tmp_path / "cargo-link"
    os.symlink(str(parent / ".cargo"), str(link))
    env["CARGO_HOME"] = str(link)
    _write(parent / ".cargo" / "config.toml",
           '[build]\nrustflags = ["--cfg", "dup"]\n')
    flags = _remap(module, env, build)
    assert flags == ["--cfg", "dup"] + _pair(env, build)
    assert flags.count("dup") == 1


@HELPERS
@pytest.mark.parametrize("leaf", ["config", "config.toml"])
@pytest.mark.parametrize("dotted,want", [
    ("--cfg dotted", ["--cfg", "file", "--cfg", "dotted"]),
    ("", ["--cfg", "file"]),
])
def test_dotted_env_appends_after_file_string(
        module, isolated, leaf, dotted, want):
    """The dotted spelling appends after a file string.

    An empty value leaves the file flags standing; both
    config leaves behave alike.
    """
    env, build = isolated
    _write(build / ".cargo" / leaf,
           '[build]\nrustflags = "--cfg file"\n')
    env["CARGO_BUILD_RUSTFLAGS"] = dotted
    assert _remap(module, env, build) == want + _pair(env, build)


@HELPERS
def test_unrelated_config_keys_ignored(module, isolated):
    """Non-flag settings never trip the reader."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[build]\njobs = 4\n'
           '[target.x86_64-unknown-linux-gnu]\n'
           'linker = "cc"\n')
    env["CARGO_TARGET_DIR"] = str(build / "target")
    env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"] = "cc"
    assert _remap(module, env, build) == _pair(env, build)


@HELPERS
def test_dotted_env_only(module, isolated):
    env, build = isolated
    env["CARGO_BUILD_RUSTFLAGS"] = "-C opt-level=2"
    assert _remap(module, env, build) == \
        ["-C", "opt-level=2"] + _pair(env, build)


@HELPERS
def test_ambient_empty_exports_remaps_only(module, isolated):
    """No channels, no configs: exactly the remap pair."""
    env, build = isolated
    assert _remap(module, env, build) == _pair(env, build)


@HELPERS
def test_remap_pair_present_exactly_once(module, isolated):
    env, build = isolated
    env["RUSTFLAGS"] = "--cfg ambient"
    flags = _remap(module, env, build)
    pair = _pair(env, build)
    assert flags[:2] == ["--cfg", "ambient"]
    assert flags[2:] == pair
    assert flags.count(pair[0]) == 1
    assert flags.count(pair[1]) == 1


@HELPERS
def test_missing_home_skips_home_remap(module, isolated):
    env, build = isolated
    env["HOME"] = ""
    flags = _remap(module, env, build)
    assert flags == [pair for pair in _pair(env, build)
                     if pair.endswith("=/build-root")]
    assert len(flags) == 1


@HELPERS
def test_target_rustflags_refuse(module, isolated):
    """Target entries shadow the build key: never guess."""
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           '[target.x86_64-unknown-linux-gnu]\n'
           'rustflags = ["-C", "opt-level=2"]\n')
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
def test_target_env_rustflags_refuse(module, isolated):
    env, build = isolated
    env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS"] = \
        "-C opt-level=2"
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
def test_include_refuses(module, isolated):
    env, build = isolated
    _write(build / ".cargo" / "config.toml",
           'include = ["extra.toml"]\n')
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
def test_invalid_toml_refuses(module, isolated):
    env, build = isolated
    _write(build / ".cargo" / "config.toml", "not = [valid\n")
    with pytest.raises(SystemExit):
        _remap(module, env, build)


@HELPERS
@pytest.mark.parametrize("body", [
    '[build]\nrustflags = 42\n',
    '[build]\nrustflags = ["-C", 42]\n',
    'build = "nope"\n',
    'target = "nope"\n',
])
def test_mistyped_config_refuses(module, isolated, body):
    env, build = isolated
    _write(build / ".cargo" / "config.toml", body)
    with pytest.raises(SystemExit):
        _remap(module, env, build)


def _pinned_channel():
    """Repository toolchain pin: the channel the repo builds under."""
    text = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("channel"):
            _, _, value = line.partition("=")
            value = value.strip().strip('"')
            assert value, "pin names a channel"
            return value
    raise AssertionError("pin names no channel")


_QUOTED_MAIN_RS = '''#[cfg(not(mv_cfg = "quoted"))]
compile_error!("quoted flag did not reach rustc");
fn main() {}
'''


def _scratch_crate(path, channel):
    """Scratch crate refusing to compile without the exact quoted flag."""
    (path / "src").mkdir(parents=True)
    (path / "Cargo.toml").write_text(
        '[package]\nname = "quoted"\nversion = "0.1.0"\n'
        'edition = "2021"\n', encoding="utf-8")
    (path / "src" / "main.rs").write_text(
        _QUOTED_MAIN_RS, encoding="utf-8")
    (path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "%s"\n' % channel,
        encoding="utf-8")


def _cargo_env(cargo_home, target):
    """Hermetic cargo environment: no ambient flags, home, or target.

    The ambient home stays: the toolchain resolver reads it,
    while cargo itself writes only to the scratch home and
    target given here.
    """
    env = {key: value for key, value in os.environ.items()
           if key not in (
               "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS",
               "CARGO_BUILD_RUSTFLAGS", "RUSTUP_TOOLCHAIN",
               "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
               "RUSTC", "CARGO_HOME", "CARGO_TARGET_DIR",
               "CARGO_NET_OFFLINE")}
    env.update(CARGO_HOME=str(cargo_home),
               CARGO_TARGET_DIR=str(target),
               CARGO_NET_OFFLINE="true")
    return env


def _assert_pinned(proj, env, channel):
    """The cargo under test proves it is the repository pin."""
    probe = subprocess.run(
        ["cargo", "--version"], capture_output=True, text=True,
        cwd=proj, env=env, timeout=120)
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.startswith("cargo %s " % channel), \
        probe.stdout


def test_quoted_flag_accepted_by_pinned_cargo(
        isolated, tmp_path):
    """Both helpers' quoted output survives a real pinned build.

    Each helper words the quoted flag with its quotes intact;
    the shared encoded output then drives a pinned cargo build
    of a crate that refuses to compile without the exact flag.
    """
    env, build = isolated
    channel = _pinned_channel()
    seen = set()
    for module in (PACKAGER, DOCS):
        probe = dict(env)
        probe["RUSTFLAGS"] = '--cfg mv_cfg="quoted"'
        flags = _remap(module, probe, build)
        assert flags[:2] == ["--cfg", 'mv_cfg="quoted"']
        seen.add(probe["CARGO_ENCODED_RUSTFLAGS"])
    assert len(seen) == 1
    proj = tmp_path / "proj"
    _scratch_crate(proj, channel)
    cargo_env = _cargo_env(
        env["CARGO_HOME"], tmp_path / "target")
    _assert_pinned(proj, cargo_env, channel)
    built = subprocess.run(
        ["cargo", "build", "--offline"], capture_output=True,
        text=True, cwd=proj, timeout=300,
        env={**cargo_env,
             "CARGO_ENCODED_RUSTFLAGS": seen.pop()})
    assert built.returncode == 0, built.stderr[-2000:]


def test_unquoted_flag_rejected_by_pinned_cargo(
        isolated, tmp_path):
    """The end-to-end harness discriminates: stripped quotes fail."""
    env, _build = isolated
    channel = _pinned_channel()
    proj = tmp_path / "proj"
    _scratch_crate(proj, channel)
    cargo_env = _cargo_env(
        env["CARGO_HOME"], tmp_path / "target")
    _assert_pinned(proj, cargo_env, channel)
    built = subprocess.run(
        ["cargo", "build", "--offline"], capture_output=True,
        text=True, cwd=proj, timeout=300,
        env={**cargo_env, "CARGO_ENCODED_RUSTFLAGS":
             "\x1f".join(["--cfg", "mv_cfg=quoted"])})
    assert built.returncode != 0
    assert "invalid" in built.stderr, built.stderr[-2000:]


_WRAPPER_SH = (
    "#!/bin/sh\n"
    "rustc=\"$1\"\n"
    "shift\n"
    "printf '%s\\n' \"$*\" >> \"$MEMVEIL_RUSTC_ARGV_LOG\"\n"
    "exec \"$rustc\" \"$@\"\n"
)


def _scratch_probe(path, channel, leaf, body):
    """Scratch crate carrying one config leaf with the given body."""
    (path / "src").mkdir(parents=True)
    (path / "Cargo.toml").write_text(
        '[package]\nname = "flagprobe"\nversion = "0.1.0"\n'
        'edition = "2021"\n', encoding="utf-8")
    (path / "src" / "main.rs").write_text(
        "fn main() {}\n", encoding="utf-8")
    (path / "rust-toolchain.toml").write_text(
        '[toolchain]\nchannel = "%s"\n' % channel,
        encoding="utf-8")
    cargo_dir = path / ".cargo"
    cargo_dir.mkdir()
    (cargo_dir / leaf).write_text(body, encoding="utf-8")


def _wrapper_argv_log(proj, cargo_home, target, channel,
                      dotted):
    """Compiler-argument log from a real pinned build of `proj`.

    A wrapper script sits between cargo and the compiler:
    it appends each compiler argument vector to the log,
    then runs the compiler it was given, so the log holds
    exactly what the compiler saw. The dotted spelling is
    set to `dotted` (even when empty) for the build.
    """
    wrapper = proj.parent / ("wrapper-%s.sh" % proj.name)
    wrapper.write_text(_WRAPPER_SH, encoding="utf-8")
    wrapper.chmod(0o755)
    log = proj.parent / ("argv-%s.log" % proj.name)
    cargo_env = _cargo_env(cargo_home, target)
    _assert_pinned(proj, cargo_env, channel)
    built = subprocess.run(
        ["cargo", "build", "--offline"], capture_output=True,
        text=True, cwd=proj, timeout=300,
        env={**cargo_env,
             "CARGO_BUILD_RUSTFLAGS": dotted,
             "RUSTC_WRAPPER": str(wrapper),
             "MEMVEIL_RUSTC_ARGV_LOG": str(log)})
    assert built.returncode == 0, built.stderr[-2000:]
    return log.read_text(encoding="utf-8")


@pytest.mark.parametrize("leaf", ["config", "config.toml"])
def test_dotted_env_matches_compiler_invocation(
        isolated, tmp_path, leaf):
    """The dotted spelling appends after file flags on the real line.

    A wrapper between pinned cargo and the compiler logs
    exactly what the compiler saw: file flags first, then
    the dotted flags; an empty dotted value leaves the file
    flags standing. Both helpers agree with the log flag
    for flag, and both config leaves behave alike.
    """
    env, build = isolated
    channel = _pinned_channel()
    body = '[build]\nrustflags = "--cfg file"\n'
    _write(build / ".cargo" / leaf, body)
    for tag, dotted, want in [
            ("append", "--cfg dotted",
             ["--cfg", "file", "--cfg", "dotted"]),
            ("empty", "", ["--cfg", "file"])]:
        for module in (PACKAGER, DOCS):
            probe = dict(env)
            probe["CARGO_BUILD_RUSTFLAGS"] = dotted
            assert _remap(module, probe, build) == \
                want + _pair(probe, build)
        proj = tmp_path / ("probe-%s-%s" % (leaf, tag))
        _scratch_probe(proj, channel, leaf, body)
        log = _wrapper_argv_log(
            proj, env["CARGO_HOME"],
            tmp_path / ("target-%s" % proj.name),
            channel, dotted)
        lines = log.splitlines()
        if tag == "append":
            seen = [line for line in lines
                    if "--cfg file" in line]
            assert seen, log[-2000:]
            assert any("--cfg dotted" in line
                       for line in seen), log[-2000:]
            for line in seen:
                if "--cfg dotted" in line:
                    assert line.index("--cfg file") < \
                        line.index("--cfg dotted"), line
        else:
            assert any("--cfg file" in line
                       for line in lines), log[-2000:]
            assert not any("--cfg dotted" in line
                           for line in lines), log[-2000:]
