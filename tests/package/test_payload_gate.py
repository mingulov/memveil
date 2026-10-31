# SPDX-License-Identifier: GPL-3.0-or-later

"""Payload-gate tests: collect and check over the release set.

tools/payload-gate --collect hashes the engine binary, the
libbpf-mojo bridge, and the three BPF objects out of each of
the three release packages; --check compares that manifest
against the committed packaging/tested-payload.sha256 and
fails closed on a placeholder, a missing or extra entry, or
a hash mismatch. A tampered package (one flipped payload
byte, repacked) must fail the check against the untampered
manifest.

Environment: MV_BUNDLE_TARBALL, MV_DEB, MV_RPM (required,
the three release packages), MV_REPO (optional, defaults to
this checkout).
"""

import os
import re
import subprocess
import tarfile

import pytest

BUNDLE = os.environ.get("MV_BUNDLE_TARBALL", "")
DEB = os.environ.get("MV_DEB", "")
RPM = os.environ.get("MV_RPM", "")
REPO = os.environ.get("MV_REPO", os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", ".."))

GATE = os.path.join(REPO, "tools", "payload-gate")
TESTED = os.path.join(REPO, "packaging", "tested-payload.sha256")

needs_packages = pytest.mark.skipif(
    not (BUNDLE and DEB and RPM),
    reason="MV_BUNDLE_TARBALL/MV_DEB/MV_RPM are not set "
           "(run tools/test payload-gate)")

HEX64 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED = sorted([
    "deb/usr/bin/memveil",
    "deb/usr/lib/memveil/libbpf_mojo.so.1",
    "deb/usr/lib/memveil/swiotlb_attempt.bpf.o",
    "deb/usr/lib/memveil/swiotlb_copy.bpf.o",
    "deb/usr/lib/memveil/swiotlb_lifecycle.bpf.o",
    "rpm/usr/bin/memveil",
    "rpm/usr/lib/memveil/libbpf_mojo.so.1",
    "rpm/usr/lib/memveil/swiotlb_attempt.bpf.o",
    "rpm/usr/lib/memveil/swiotlb_copy.bpf.o",
    "rpm/usr/lib/memveil/swiotlb_lifecycle.bpf.o",
    "bundle/bin/memveil",
    "bundle/lib/libbpf_mojo.so.1",
    "bundle/bpf/swiotlb_attempt.bpf.o",
    "bundle/bpf/swiotlb_copy.bpf.o",
    "bundle/bpf/swiotlb_lifecycle.bpf.o",
])


def run_gate(*args):
    return subprocess.run(
        ["python3", GATE] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def collect(tmp_path):
    out = str(tmp_path / "PACKAGED-SHA256.txt")
    proc = run_gate("--collect", "--deb", DEB, "--rpm", RPM,
                    "--bundle", BUNDLE, "--out", out)
    assert proc.returncode == 0, proc.stderr.decode()
    with open(out, encoding="utf-8") as handle:
        lines = [line for line in handle.read().splitlines()
                 if line.strip()]
    return out, lines


def parse(lines):
    entries = {}
    for line in lines:
        parts = line.split()
        entries[parts[1]] = parts[0]
    return entries


def write_manifest(tmp_path, name, entries):
    path = str(tmp_path / name)
    with open(path, "w", encoding="utf-8") as handle:
        for logical in sorted(entries):
            handle.write("%s  %s\n" % (entries[logical], logical))
    return path


@needs_packages
def test_collect_covers_fifteen_payload_files(tmp_path):
    _, lines = collect(tmp_path)
    entries = parse(lines)
    assert sorted(entries) == EXPECTED
    for logical, digest in entries.items():
        assert HEX64.match(digest), logical
        assert digest != "0" * 64, logical


@needs_packages
def test_collect_is_deterministic(tmp_path):
    _, first = collect(tmp_path)
    second_path = str(tmp_path / "second.txt")
    proc = run_gate("--collect", "--deb", DEB, "--rpm", RPM,
                    "--bundle", BUNDLE, "--out", second_path)
    assert proc.returncode == 0, proc.stderr.decode()
    with open(second_path, encoding="utf-8") as handle:
        second = [line for line in handle.read().splitlines()
                  if line.strip()]
    assert second == first


@needs_packages
def test_check_self_passes(tmp_path):
    manifest, _ = collect(tmp_path)
    proc = run_gate("--check", "--packaged", manifest,
                    "--tested", manifest)
    assert proc.returncode == 0, proc.stderr.decode()


@needs_packages
def test_check_flipped_hash_fails(tmp_path):
    manifest, lines = collect(tmp_path)
    entries = parse(lines)
    entries["deb/usr/bin/memveil"] = \
        "1" + entries["deb/usr/bin/memveil"][1:]
    flipped = write_manifest(tmp_path, "flipped.txt", entries)
    proc = run_gate("--check", "--packaged", flipped,
                    "--tested", manifest)
    assert proc.returncode == 1
    assert "deb/usr/bin/memveil mismatch" in \
        proc.stderr.decode()


@needs_packages
def test_check_zero_hash_fails(tmp_path):
    manifest, lines = collect(tmp_path)
    entries = parse(lines)
    entries["rpm/usr/bin/memveil"] = "0" * 64
    zeros = write_manifest(tmp_path, "zeros.txt", entries)
    proc = run_gate("--check", "--packaged", manifest,
                    "--tested", zeros)
    assert proc.returncode == 1
    assert "placeholder" in proc.stderr.decode()


@needs_packages
def test_check_missing_entry_fails(tmp_path):
    manifest, lines = collect(tmp_path)
    entries = parse(lines)
    del entries["bundle/bin/memveil"]
    short = write_manifest(tmp_path, "short.txt", entries)
    proc = run_gate("--check", "--packaged", short,
                    "--tested", manifest)
    assert proc.returncode == 1
    assert "bundle/bin/memveil" in proc.stderr.decode()


@needs_packages
def test_check_extra_entry_fails(tmp_path):
    manifest, lines = collect(tmp_path)
    entries = parse(lines)
    entries["deb/usr/bin/evil"] = "1" * 64
    extra = write_manifest(tmp_path, "extra.txt", entries)
    proc = run_gate("--check", "--packaged", extra,
                    "--tested", manifest)
    assert proc.returncode == 1
    assert "unexpected entry" in proc.stderr.decode()


@needs_packages
def test_check_malformed_line_fails(tmp_path):
    manifest, _ = collect(tmp_path)
    bad = str(tmp_path / "bad.txt")
    with open(bad, "w", encoding="utf-8") as handle:
        handle.write("not-a-manifest-line\n")
    proc = run_gate("--check", "--packaged", bad,
                    "--tested", manifest)
    assert proc.returncode == 2
    assert "malformed" in proc.stderr.decode()


@needs_packages
def test_check_missing_file_fails(tmp_path):
    manifest, _ = collect(tmp_path)
    proc = run_gate("--check", "--packaged", manifest,
                    "--tested", str(tmp_path / "nope.txt"))
    assert proc.returncode == 2


def test_committed_tested_manifest_is_wellformed():
    with open(TESTED, encoding="utf-8") as handle:
        lines = [line for line in handle.read().splitlines()
                 if line.strip() and not line.startswith("#")]
    entries = parse(lines)
    assert sorted(entries) == EXPECTED
    for digest in entries.values():
        assert HEX64.match(digest)


@needs_packages
def test_tampered_deb_fails_against_untampered(tmp_path):
    manifest, _ = collect(tmp_path)
    work = str(tmp_path / "tamper")
    os.makedirs(work)
    proc = subprocess.run(
        ["dpkg-deb", "-R", DEB, os.path.join(work, "root")],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr.decode()
    target = os.path.join(work, "root", "usr", "bin", "memveil")
    with open(target, "r+b") as handle:
        first = handle.read(1)
        handle.seek(0)
        handle.write(bytes([first[0] ^ 1]))
    tampered = os.path.join(work, "tampered.deb")
    proc = subprocess.run(
        ["dpkg-deb", "-b", os.path.join(work, "root"), tampered],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    assert proc.returncode == 0, proc.stderr.decode()
    tainted = str(tmp_path / "tainted.txt")
    proc = run_gate("--collect", "--deb", tampered, "--rpm", RPM,
                    "--bundle", BUNDLE, "--out", tainted)
    assert proc.returncode == 0, proc.stderr.decode()
    proc = run_gate("--check", "--packaged", tainted,
                    "--tested", manifest)
    assert proc.returncode == 1
    assert "deb/usr/bin/memveil mismatch" in proc.stderr.decode()


@needs_packages
def test_bundle_missing_member_fails_collect(tmp_path):
    work = str(tmp_path / "hollow")
    os.makedirs(os.path.join(work, "memveil-0.0.0"))
    hollow = os.path.join(work, "hollow.tar.gz")
    with tarfile.open(hollow, "w:gz") as archive:
        archive.add(os.path.join(work, "memveil-0.0.0"),
                    arcname="memveil-0.0.0")
    out = str(tmp_path / "hollow.txt")
    proc = run_gate("--collect", "--deb", DEB, "--rpm", RPM,
                    "--bundle", hollow, "--out", out)
    assert proc.returncode == 2
    assert "lacks payload member" in proc.stderr.decode()


def test_usage_errors_exit_2():
    proc = run_gate("--check", "--packaged", "/nonexistent")
    assert proc.returncode == 2
    proc = run_gate("--bogus")
    assert proc.returncode == 2
