#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Oracle module kernel targeting: build for the guest kernel.

The VM harness boots guests that may run an older admitted
kernel than the host (the guest kernel is selected through
the VNG path). The oracle module must then be built for the
guest kernel: a host-built module fails insmod on vermagic.
MEMVEIL_ORACLE_KVER names the target kernel release. Without
it, the identity measures the running host kernel exactly as
before. With it (and different from the running kernel), the
release, config, and image come from the target kernel's
installed files, and the BTF expectation comes from the
shipped validated profile for that release; the in-guest
drift check then verifies the live guest BTF against the pin.
A same-release override measures live bytes exactly like no
override.

All tests here use controlled fixture bytes except the one
explicitly armed host check (MEMVEIL_HOST_IDENTITY=1), which
is the only test allowed to read live host kernel files.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import lifecycle_env as env

REPO = Path(__file__).resolve().parent.parent.parent
NARROW_PROFILES = REPO / "tests" / "fixtures" / "capabilities" \
    / "profiles-narrow-test"
NARROW_DOC = NARROW_PROFILES / "test-narrow-validated.json"
TARGET = "7.0.0-34-generic"
HOST_LABEL = "0.0.0-test-host"
SAME_LABEL = "0.0.0-test-same"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def uses_sudo():
    probe = subprocess.run(["sudo", "-n", "true"],
                           capture_output=True)
    return probe.returncode == 0


def make_kernel_tree(root, release, config=b"fixture-config\n",
                     image=b"fixture-image\n", btf=b"fixture-btf\n"):
    """Write a controlled kernel file tree; return roots + digests."""
    modules = root / "modules"
    boot = root / "boot"
    (modules / release / "build").mkdir(parents=True)
    boot.mkdir(parents=True, exist_ok=True)
    (modules / release / "build" / ".config").write_bytes(config)
    (boot / ("vmlinuz-" + release)).write_bytes(image)
    btf_file = root / ("btf-" + release)
    btf_file.write_bytes(btf)
    return dict(modules_root=str(modules), boot_root=str(boot),
                btf_path=str(btf_file), config_sha=sha_bytes(config),
                kernel_sha=sha_bytes(image), btf_sha=sha_bytes(btf))


def refuse_subprocess(monkeypatch):
    """Fail any subprocess call: offline tests never invoke sudo."""
    def nope(*args, **kwargs):
        raise AssertionError(
            "offline identity test invoked %r" % (args[0],))
    monkeypatch.setattr(subprocess, "run", nope)


def pinned_btf():
    doc = json.loads(NARROW_DOC.read_text())
    note = doc["identity"]["source"]["note"]
    for field in note.split():
        if field.startswith("btf=sha256:"):
            return field[len("btf=sha256:"):]
    raise AssertionError("narrow doc carries no btf pin")


def test_no_override_measures_named_kernel(monkeypatch, tmp_path):
    tree = make_kernel_tree(tmp_path, HOST_LABEL)
    monkeypatch.delenv("MEMVEIL_ORACLE_KVER", raising=False)
    refuse_subprocess(monkeypatch)
    ident = env.module_build_identity(
        host_release=HOST_LABEL, modules_root=tree["modules_root"],
        boot_root=tree["boot_root"], btf_path=tree["btf_path"])
    assert ident["release"] == HOST_LABEL
    assert ident["config_sha"] == tree["config_sha"]
    assert ident["kernel_sha"] == tree["kernel_sha"]
    assert ident["btf_sha"] == tree["btf_sha"]
    assert ident["btf_provenance"] == "live-bytes"


def test_override_same_release_measures_live_bytes(monkeypatch,
                                                   tmp_path):
    tree = make_kernel_tree(tmp_path, SAME_LABEL)
    assert tree["btf_sha"] != pinned_btf()
    monkeypatch.setenv("MEMVEIL_ORACLE_KVER", SAME_LABEL)
    refuse_subprocess(monkeypatch)
    ident = env.module_build_identity(
        host_release=SAME_LABEL, modules_root=tree["modules_root"],
        boot_root=tree["boot_root"], btf_path=tree["btf_path"])
    assert ident["release"] == SAME_LABEL
    assert ident["config_sha"] == tree["config_sha"]
    assert ident["kernel_sha"] == tree["kernel_sha"]
    assert ident["btf_sha"] == tree["btf_sha"]
    assert ident["btf_provenance"] == "live-bytes"


def test_override_same_admitted_release_measures_live_bytes(
        monkeypatch, tmp_path):
    tree = make_kernel_tree(tmp_path, TARGET)
    assert tree["btf_sha"] != pinned_btf()
    monkeypatch.setenv("MEMVEIL_ORACLE_KVER", TARGET)
    refuse_subprocess(monkeypatch)
    ident = env.module_build_identity(
        host_release=TARGET, modules_root=tree["modules_root"],
        boot_root=tree["boot_root"], btf_path=tree["btf_path"])
    assert ident["release"] == TARGET
    assert ident["btf_sha"] == tree["btf_sha"]
    assert ident["btf_provenance"] == "live-bytes"


def test_override_different_release_uses_profile_pin(monkeypatch,
                                                     tmp_path):
    tree = make_kernel_tree(tmp_path, TARGET)
    assert tree["btf_sha"] != pinned_btf()
    monkeypatch.setenv("MEMVEIL_ORACLE_KVER", TARGET)
    refuse_subprocess(monkeypatch)
    ident = env.module_build_identity(
        host_release=HOST_LABEL, modules_root=tree["modules_root"],
        boot_root=tree["boot_root"], btf_path=tree["btf_path"],
        profiles_dir=str(NARROW_PROFILES))
    assert ident["release"] == TARGET
    assert ident["config_sha"] == tree["config_sha"]
    assert ident["kernel_sha"] == tree["kernel_sha"]
    assert ident["btf_sha"] == pinned_btf()
    assert ident["btf_provenance"] == "profile-pinned"


def test_override_rejects_unknown_release(monkeypatch, tmp_path):
    tree = make_kernel_tree(tmp_path, HOST_LABEL)
    monkeypatch.setenv("MEMVEIL_ORACLE_KVER", "9.9.9-no-such-kernel")
    refuse_subprocess(monkeypatch)
    with pytest.raises(pytest.fail.Exception):
        env.module_build_identity(
            host_release=HOST_LABEL,
            modules_root=tree["modules_root"],
            boot_root=tree["boot_root"], btf_path=tree["btf_path"])


def test_override_rejects_unvalidated_doc(monkeypatch, tmp_path):
    tree = make_kernel_tree(tmp_path, HOST_LABEL)
    ref = json.loads((REPO / "profiles"
                      / "linux-x86_64-7.0-reference.json").read_text())
    assert ref["status"] != "validated"
    monkeypatch.setenv("MEMVEIL_ORACLE_KVER",
                       ref["identity"]["source"]["revision"])
    refuse_subprocess(monkeypatch)
    with pytest.raises(pytest.fail.Exception):
        env.module_build_identity(
            host_release=HOST_LABEL,
            modules_root=tree["modules_root"],
            boot_root=tree["boot_root"], btf_path=tree["btf_path"])


def test_pin_parser_accepts_and_rejects():
    good = ("config=sha256:%s config_src=file btf=sha256:%s "
            "format=sha256:%s" % ("a" * 64, "b" * 64, "c" * 64))
    assert env.profile_btf_pin(good) == "b" * 64
    assert env.profile_btf_pin("config=sha256:%s" % ("a" * 64)) is None
    assert env.profile_btf_pin("btf=sha256:xyz") is None
    assert env.profile_btf_pin("") is None


def test_image_hash_reads_unreadable_file(tmp_path):
    probe = tmp_path / "opaque"
    probe.write_bytes(b"opaque-bytes")
    probe.chmod(0)
    try:
        if os.access(probe, os.R_OK):
            pytest.skip("tmp file still readable (running as root?)")
        if not uses_sudo():
            pytest.skip("needs passwordless sudo for the fallback")
        assert env.sha_file_maybe_sudo(str(probe)) == hashlib.sha256(
            b"opaque-bytes").hexdigest()
    finally:
        probe.chmod(0o600)


def test_host_identity_measures_running_kernel(monkeypatch):
    if os.environ.get("MEMVEIL_HOST_IDENTITY") != "1":
        pytest.skip("host identity check needs MEMVEIL_HOST_IDENTITY=1")
    monkeypatch.delenv("MEMVEIL_ORACLE_KVER", raising=False)
    try:
        ident = env.module_build_identity()
    except OSError as exc:
        pytest.fail("armed but host identity unavailable: %s" % exc)
    release = os.uname().release
    assert ident["release"] == release
    assert ident["config_sha"] == sha(
        Path("/lib/modules") / release / "build" / ".config")
    assert ident["btf_sha"] == sha("/sys/kernel/btf/vmlinux")
    assert ident["btf_provenance"] == "live-bytes"
