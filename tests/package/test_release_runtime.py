# SPDX-License-Identifier: GPL-3.0-or-later

"""Release-runtime gate: the extracted candidate fails closed.

Gap cases beyond the clean-room replay lane, all against the
extracted owner bundle: a present-but-incompatible bridge, an
absent BPF object, and an unknown --profile each refuse with
exit 3 and no capture directory; top replays offline with the
same quality exit as report; and the bundle's loader layout,
permissions, and NEEDED closure match the manifest plus the
packager's system allowlist.

Environment: MV_BUNDLE_TARBALL (required), MV_VALID_EMPTY
(required, valid-empty fixture dir), MV_REPO (optional,
defaults to this checkout, to import tools/package).
"""

import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
from importlib.machinery import SourceFileLoader

import pytest

TARBALL = os.environ.get("MV_BUNDLE_TARBALL", "")
VALID_EMPTY = os.environ.get("MV_VALID_EMPTY", "")
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


@pytest.fixture(scope="module")
def bundle(tmp_path_factory):
    assert TARBALL and os.path.isfile(TARBALL), \
        "MV_BUNDLE_TARBALL must name the built tarball"
    assert VALID_EMPTY and os.path.isdir(VALID_EMPTY), \
        "MV_VALID_EMPTY must name the valid-empty fixture"
    dest = tmp_path_factory.mktemp("release")
    with tarfile.open(TARBALL, "r:gz") as tar:
        members = tar.getnames()
        assert len(members) > 10, "tarball looks empty"
        top = members[0].split("/")[0]
        assert all(m == top or m.startswith(top + "/")
                   for m in members), "tarball must hold one top dir"
        tar.extractall(dest)
    root = dest / top
    for rel in ("bin/memveil", "lib/libbpf_mojo.so.1",
                "bpf/swiotlb_attempt.bpf.o", "MANIFEST.json"):
        assert (root / rel).exists(), "bundle lacks %s" % rel
    manifest = json.loads((root / "MANIFEST.json").read_text())
    return root, manifest


def run(*argv, **kwargs):
    kwargs.setdefault("timeout", 120)
    return subprocess.run(
        argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, **kwargs,
    )


def test_replaced_bridge_reaches_named_refusal_boundary(bundle, tmp_path):
    # record validates in gate order (object, profile, hook
    # format, binding) before the bridge loads, so on a host
    # without readable tracefs this fails at the format gate,
    # not at bridge load. The stable contract is fail-closed:
    # exit 3, a stderr reason, no capture directory. Exact
    # per-gate messages stay in the record lane.
    root, _ = bundle
    trial = tmp_path / "wrongabi"
    shutil.copytree(root, trial)
    libs = sorted((trial / "lib").glob("*.so*"))
    donor = next((p for p in libs
                  if p.name != "libbpf_mojo.so.1"), None)
    assert donor is not None, "bundle lib/ has no second library"
    bridge = trial / "lib" / "libbpf_mojo.so.1"
    shutil.copyfile(donor, bridge)
    cap = tmp_path / "cap"
    proc = run(str(trial / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--object", str(trial / "bpf" / "swiotlb_attempt.bpf.o"),
               "--bridge", str(bridge),
               "--duration", "1", cwd=str(tmp_path))
    assert proc.returncode == 3, proc.stderr
    # This lane names the gate it actually reached. ABI rejection itself
    # requires a qualified live environment that passes all preceding gates.
    boundaries = ("requires x86_64", "requires Linux", "below floor 7.0", "format unreadable",
                  "binding failed", "setup failed", "bridge", "time namespace")
    assert any(reason in proc.stderr for reason in boundaries), proc.stderr
    print("replaced-bridge refusal boundary: " + proc.stderr.strip())
    assert not cap.exists(), "refused record left a capture dir"


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
               "--bridge", str(trial / "lib" / "libbpf_mojo.so.1"),
               "--duration", "1", cwd=str(tmp_path))
    assert proc.returncode == 3, proc.stderr
    assert "object unreadable" in proc.stderr, proc.stderr
    assert not cap.exists(), "refused record left a capture dir"


def test_unknown_profile_refused(bundle, tmp_path):
    root, _ = bundle
    cap = tmp_path / "cap"
    proc = run(str(root / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--object", str(root / "bpf" / "swiotlb_attempt.bpf.o"),
               "--bridge", str(root / "lib" / "libbpf_mojo.so.1"),
               "--profile", "release-runtime-bogus-0",
               "--duration", "1", cwd=str(tmp_path))
    assert proc.returncode == 3, proc.stderr
    assert "unknown --profile" in proc.stderr, proc.stderr
    assert not cap.exists(), "refused record left a capture dir"


def test_top_replays_valid_empty(bundle):
    root, _ = bundle
    proc = run(str(root / "bin" / "memveil"), "top",
               "--interval", "1s", VALID_EMPTY)
    assert proc.returncode == 4, proc.stderr
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


def runpath_abspaths(dyn):
    """Non-$ORIGIN RUNPATH/RPATH entries in a dynamic section.

    Parses the bracketed `Library runpath:`/`Library rpath:`
    values and returns every colon-separated entry that is
    not $ORIGIN-relative: any absolute build-host path, not
    just known prefixes. [] means fully relocatable.
    """
    found = []
    for line in dyn.splitlines():
        match = re.search(r"Library (?:runpath|rpath): \[(.*)\]",
                          line)
        if not match:
            continue
        for entry in match.group(1).split(":"):
            if entry and not entry.startswith("$ORIGIN"):
                found.append(entry)
    return found


def test_runpath_abspaths_flags_hidden_absolute():
    # The RUNPATH guard must parse the bracketed runpath,
    # not match known prefixes: a /tmp RPATH passes the old
    # substring forms (no /home/, no /work/, no " /") yet is
    # still an absolute build-host path. Needs no bundle.
    clean = (" 0x000000000000001d (RUNPATH)"
             " Library runpath: [$ORIGIN/../lib]")
    assert runpath_abspaths(clean) == []
    hidden = (" 0x000000000000001d (RUNPATH)"
              " Library runpath: [/tmp/stage/lib]")
    assert "/home/" not in hidden and "/work/" not in hidden
    assert " /" not in hidden.replace("$ORIGIN", "")
    assert runpath_abspaths(hidden) == ["/tmp/stage/lib"]


def test_loader_layout(bundle):
    root, manifest = bundle
    binary = root / "bin" / "memveil"
    dyn = dynamic_strings(binary)
    assert "$ORIGIN/../lib" in dyn, dyn
    assert runpath_abspaths(dyn) == [], dyn
    proc = run("readelf", "-h", str(binary))
    assert proc.returncode == 0
    assert "X86-64" in proc.stdout, proc.stdout
    shipped = {path.split("/")[-1]
               for path in manifest["files"] if path.startswith("lib/")}
    allow = set(PKG.SYSTEM_ALLOW)
    for target in [binary] + sorted((root / "lib").glob("*.so*")):
        for name in needed(target):
            assert name in shipped or name in allow, \
                "%s needs %s: outside closure" % (target.name, name)


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
    assert TARBALL and os.path.isfile(TARBALL), \
        "MV_BUNDLE_TARBALL must name the built tarball"
    with tarfile.open(TARBALL, "r:gz") as tar:
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
    # no --bridge/--object must resolve the bundled bridge and
    # objects. It then refuses at a later gate (this host lacks
    # readable tracefs) or, on a qualified host, captures; it
    # must never fail discovery itself.
    root, _ = bundle
    cap = tmp_path / "cap"
    proc = run(str(root / "bin" / "memveil"), "record",
               "--output", str(cap),
               "--duration", "1", cwd=str(tmp_path), env={})
    for missing in ("no bridge", "no object", "missing --object"):
        assert missing not in proc.stderr, proc.stderr
    assert proc.returncode in (0, 3, 4), proc.stderr
    if proc.returncode == 3:
        assert proc.stderr.strip(), "refusal needs a diagnostic"
        assert not cap.exists(), "refused record left a capture dir"
    else:
        # A produced capture proves discovery resolved the bundled
        # bridge and objects: exit 0 is a sufficient qualified-host
        # capture (complete stop with complete_for_scope detail),
        # exit 4 a materially incomplete one.
        assert cap.exists(), \
            "exit %d left no capture dir" % proc.returncode
